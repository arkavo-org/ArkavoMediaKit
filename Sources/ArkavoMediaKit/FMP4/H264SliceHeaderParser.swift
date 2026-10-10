import Foundation

/// Measures H.264 slice headers, so `cbcs` protection can start on the first byte after one.
///
/// ISO/IEC 23001-7 `cbcs` (as CMAF requires it) leaves each video slice NAL unit's header and slice header clear:
/// "BytesOfProtectedData SHALL start on the first byte of video data following the slice header". A player parses the
/// slice header before it decrypts, so a protected range that starts inside it is unplayable.
///
/// The parameter sets are the stream's SPS and PPS NAL units (header byte included), as an `avcC` carries them.
/// Only what a slice header's length depends on is read. Anything this profile does not need (slice groups, data
/// partitioning, MVC and SVC slices, SP and SI slices) is refused rather than guessed.
public struct H264SliceHeaderParser: Sendable {
    public enum Failure: Error, Equatable {
        /// The bytes end or break the syntax before the header does.
        case malformed
        /// Valid H.264 this parser does not measure.
        case unsupported(String)
        /// A slice names a PPS, or a PPS an SPS, that the stream did not carry.
        case unknownParameterSet
    }

    struct SequenceParameterSet: Sendable {
        var chromaArrayType = 1
        var separateColourPlane = false
        var log2MaxFrameNum = 0
        var picOrderCntType = 0
        var log2MaxPicOrderCntLsb = 0
        var deltaPicOrderAlwaysZero = false
        var frameMbsOnly = true
    }

    struct PictureParameterSet: Sendable {
        var spsID = 0
        var entropyCodingMode = false
        var bottomFieldPicOrderInFramePresent = false
        var numRefIdxL0DefaultActiveMinus1 = 0
        var numRefIdxL1DefaultActiveMinus1 = 0
        var weightedPred = false
        var weightedBipredIdc = 0
        var deblockingFilterControlPresent = false
        var redundantPicCntPresent = false
    }

    private var sequenceParameterSets: [Int: SequenceParameterSet] = [:]
    private var pictureParameterSets: [Int: PictureParameterSet] = [:]

    public init(sps: [Data], pps: [Data]) throws {
        for nal in sps {
            var reader = try Self.payloadReader(nal, expecting: 7)
            let (id, set) = try Self.parseSPS(&reader)
            sequenceParameterSets[id] = set
        }
        for nal in pps {
            var reader = try Self.payloadReader(nal, expecting: 8)
            let (id, set) = try Self.parsePPS(&reader)
            guard sequenceParameterSets[set.spsID] != nil else { throw Failure.unknownParameterSet }
            pictureParameterSets[id] = set
        }
    }

    /// The bytes of `nal` (a NAL unit without its length prefix) up to the end of its slice header: the NAL header
    /// byte and the slice header, emulation prevention bytes included, rounded up to a whole byte.
    public func headerSize(ofSlice nal: Data) throws -> Int {
        1 + (try sliceHeaderBits(ofSlice: nal) + 7) / 8
    }

    /// The bits of `nal`'s slice header, from the byte after the NAL header, emulation prevention bytes included.
    func sliceHeaderBits(ofSlice nal: Data) throws -> Int {
        guard let header = nal.first else { throw Failure.malformed }
        let nalType = Int(header & 0x1F), nalRefIdc = Int(header >> 5) & 0x3
        guard nalType == 1 || nalType == 5 else { throw Failure.unsupported("slice NAL unit type \(nalType)") }
        let isIDR = nalType == 5
        var reader = RBSPReader(Array(nal.dropFirst()))

        _ = try reader.ue()                                      // first_mb_in_slice
        let sliceType = try reader.ue()
        guard sliceType < 10 else { throw Failure.malformed }
        let isP = sliceType % 5 == 0, isB = sliceType % 5 == 1, isI = sliceType % 5 == 2
        // Switching slices are Extended profile only, which no encoder this packages for writes.
        guard sliceType % 5 < 3 else { throw Failure.unsupported("SP and SI slices") }
        guard let pps = pictureParameterSets[try reader.ue()],
              let sps = sequenceParameterSets[pps.spsID] else { throw Failure.unknownParameterSet }

        if sps.separateColourPlane { _ = try reader.bits(2) }  // colour_plane_id
        _ = try reader.bits(sps.log2MaxFrameNum)                 // frame_num
        var fieldPic = false
        if !sps.frameMbsOnly {
            fieldPic = try reader.bit() == 1
            if fieldPic { _ = try reader.bit() }                 // bottom_field_flag
        }
        if isIDR { _ = try reader.ue() }                         // idr_pic_id
        if sps.picOrderCntType == 0 {
            _ = try reader.bits(sps.log2MaxPicOrderCntLsb)       // pic_order_cnt_lsb
            if pps.bottomFieldPicOrderInFramePresent && !fieldPic { _ = try reader.se() }
        }
        if sps.picOrderCntType == 1 && !sps.deltaPicOrderAlwaysZero {
            _ = try reader.se()                                  // delta_pic_order_cnt[0]
            if pps.bottomFieldPicOrderInFramePresent && !fieldPic { _ = try reader.se() }
        }
        if pps.redundantPicCntPresent { _ = try reader.ue() }
        if isB { _ = try reader.bit() }                          // direct_spatial_mv_pred_flag

        var refsL0 = pps.numRefIdxL0DefaultActiveMinus1 + 1, refsL1 = pps.numRefIdxL1DefaultActiveMinus1 + 1
        if isP || isB, try reader.bit() == 1 {           // num_ref_idx_active_override_flag
            refsL0 = try reader.ue() + 1
            if isB { refsL1 = try reader.ue() + 1 }
        }
        guard refsL0 <= 32, refsL1 <= 32 else { throw Failure.malformed }

        // ref_pic_list_modification()
        for list in 0 ..< (isB ? 2 : 1) where !isI || list > 0 {
            guard try reader.bit() == 1 else { continue }
            while true {
                let idc = try reader.ue()
                if idc == 3 { break }
                guard idc < 3 else { throw Failure.malformed }
                _ = try reader.ue()                              // abs_diff_pic_num_minus1 or long_term_pic_num
            }
        }

        if (pps.weightedPred && isP) || (pps.weightedBipredIdc == 1 && isB) {
            // pred_weight_table()
            _ = try reader.ue()                                  // luma_log2_weight_denom
            if sps.chromaArrayType != 0 { _ = try reader.ue() }  // chroma_log2_weight_denom
            for references in isB ? [refsL0, refsL1] : [refsL0] {
                for _ in 0 ..< references {
                    if try reader.bit() == 1 { _ = try reader.se(); _ = try reader.se() }
                    if sps.chromaArrayType != 0, try reader.bit() == 1 {
                        for _ in 0 ..< 4 { _ = try reader.se() }
                    }
                }
            }
        }

        if nalRefIdc != 0 {
            // dec_ref_pic_marking()
            if isIDR {
                _ = try reader.bits(2)                           // no_output_of_prior_pics, long_term_reference
            } else if try reader.bit() == 1 {                    // adaptive_ref_pic_marking_mode_flag
                while true {
                    let operation = try reader.ue()
                    if operation == 0 { break }
                    guard operation <= 6 else { throw Failure.malformed }
                    if operation == 1 || operation == 3 { _ = try reader.ue() }
                    if operation == 2 { _ = try reader.ue() }
                    if operation == 3 || operation == 6 { _ = try reader.ue() }
                    if operation == 4 { _ = try reader.ue() }
                }
            }
        }

        if pps.entropyCodingMode && !isI { _ = try reader.ue() }  // cabac_init_idc
        _ = try reader.se()                                      // slice_qp_delta
        if pps.deblockingFilterControlPresent, try reader.ue() != 1 {
            _ = try reader.se()                                  // slice_alpha_c0_offset_div2
            _ = try reader.se()                                  // slice_beta_offset_div2
        }

        return reader.rawBitsRead
    }

    private static func payloadReader(_ nal: Data, expecting type: UInt8) throws -> RBSPReader {
        guard let header = nal.first, header & 0x1F == type else { throw Failure.malformed }
        return RBSPReader(Array(nal.dropFirst()))
    }

    /// The profiles whose SPS carries chroma format, bit depths and scaling lists.
    private static let highProfiles: Set<Int> = [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135]

    private static func parseSPS(_ reader: inout RBSPReader) throws -> (Int, SequenceParameterSet) {
        var set = SequenceParameterSet()
        let profile = try reader.bits(8)
        _ = try reader.bits(16)                                  // constraint flags, level_idc
        let id = try reader.ue()
        guard id < 32 else { throw Failure.malformed }
        if highProfiles.contains(profile) {
            let chromaFormat = try reader.ue()
            guard chromaFormat <= 3 else { throw Failure.malformed }
            if chromaFormat == 3 { set.separateColourPlane = try reader.bit() == 1 }
            set.chromaArrayType = set.separateColourPlane ? 0 : chromaFormat
            _ = try reader.ue()                                  // bit_depth_luma_minus8
            _ = try reader.ue()                                  // bit_depth_chroma_minus8
            _ = try reader.bit()                                 // qpprime_y_zero_transform_bypass_flag
            if try reader.bit() == 1 {                           // seq_scaling_matrix_present_flag
                for list in 0 ..< (chromaFormat != 3 ? 8 : 12) where try reader.bit() == 1 {
                    try skipScalingList(&reader, size: list < 6 ? 16 : 64)
                }
            }
        }
        set.log2MaxFrameNum = try reader.ue() + 4
        set.picOrderCntType = try reader.ue()
        guard set.log2MaxFrameNum <= 16, set.picOrderCntType <= 2 else { throw Failure.malformed }
        if set.picOrderCntType == 0 {
            set.log2MaxPicOrderCntLsb = try reader.ue() + 4
            guard set.log2MaxPicOrderCntLsb <= 16 else { throw Failure.malformed }
        } else if set.picOrderCntType == 1 {
            set.deltaPicOrderAlwaysZero = try reader.bit() == 1
            _ = try reader.se()                                  // offset_for_non_ref_pic
            _ = try reader.se()                                  // offset_for_top_to_bottom_field
            let cycle = try reader.ue()
            guard cycle < 256 else { throw Failure.malformed }
            for _ in 0 ..< cycle { _ = try reader.se() }         // offset_for_ref_frame
        }
        _ = try reader.ue()                                      // max_num_ref_frames
        _ = try reader.bit()                                     // gaps_in_frame_num_value_allowed_flag
        _ = try reader.ue()                                      // pic_width_in_mbs_minus1
        _ = try reader.ue()                                      // pic_height_in_map_units_minus1
        set.frameMbsOnly = try reader.bit() == 1
        return (id, set)
    }

    private static func skipScalingList(_ reader: inout RBSPReader, size: Int) throws {
        var last = 8, next = 8
        for _ in 0 ..< size {
            if next != 0 {
                let delta = try reader.se()
                guard (-128 ... 127).contains(delta) else { throw Failure.malformed }
                next = (last + delta + 256) % 256
            }
            last = next == 0 ? last : next
        }
    }

    private static func parsePPS(_ reader: inout RBSPReader) throws -> (Int, PictureParameterSet) {
        var set = PictureParameterSet()
        let id = try reader.ue()
        set.spsID = try reader.ue()
        guard id < 256, set.spsID < 32 else { throw Failure.malformed }
        set.entropyCodingMode = try reader.bit() == 1
        set.bottomFieldPicOrderInFramePresent = try reader.bit() == 1
        guard try reader.ue() == 0 else { throw Failure.unsupported("slice groups") }
        set.numRefIdxL0DefaultActiveMinus1 = try reader.ue()
        set.numRefIdxL1DefaultActiveMinus1 = try reader.ue()
        guard set.numRefIdxL0DefaultActiveMinus1 < 32, set.numRefIdxL1DefaultActiveMinus1 < 32 else {
            throw Failure.malformed
        }
        set.weightedPred = try reader.bit() == 1
        set.weightedBipredIdc = try reader.bits(2)
        _ = try reader.se()                                      // pic_init_qp_minus26
        _ = try reader.se()                                      // pic_init_qs_minus26
        _ = try reader.se()                                      // chroma_qp_index_offset
        set.deblockingFilterControlPresent = try reader.bit() == 1
        _ = try reader.bit()                                     // constrained_intra_pred_flag
        set.redundantPicCntPresent = try reader.bit() == 1
        return (id, set)
    }
}

/// Reads an H.264 RBSP from the escaped NAL bytes: it drops each emulation prevention byte (the 0x03 of 0x000003)
/// but counts it in `rawBitsRead`, so a position maps back to the NAL unit's bytes.
struct RBSPReader {
    private let bytes: [UInt8]
    private var index = 0          // next raw byte to load
    private var current: UInt8 = 0
    private var bitsLeft = 0       // unread bits of `current`
    private var zeros = 0          // consecutive 0x00 bytes loaded

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    /// Raw bytes loaded, emulation prevention bytes included, as bits, less the unread bits of the current byte.
    var rawBitsRead: Int { index * 8 - bitsLeft }

    mutating func bit() throws -> Int {
        if bitsLeft == 0 {
            guard index < bytes.count else { throw H264SliceHeaderParser.Failure.malformed }
            if zeros >= 2 && bytes[index] == 0x03 {
                // An emulation prevention byte: not RBSP data, but one of the NAL unit's bytes.
                index += 1
                zeros = 0
                guard index < bytes.count else { throw H264SliceHeaderParser.Failure.malformed }
            }
            current = bytes[index]
            zeros = current == 0 ? zeros + 1 : 0
            index += 1
            bitsLeft = 8
        }
        bitsLeft -= 1
        return Int(current >> UInt8(bitsLeft)) & 1
    }

    mutating func bits(_ count: Int) throws -> Int {
        var value = 0
        for _ in 0 ..< count { value = value << 1 | (try bit()) }
        return value
    }

    /// An unsigned Exp-Golomb code, ue(v).
    mutating func ue() throws -> Int {
        var leadingZeros = 0
        while try bit() == 0 {
            leadingZeros += 1
            guard leadingZeros < 32 else { throw H264SliceHeaderParser.Failure.malformed }
        }
        return (1 << leadingZeros) - 1 + (try bits(leadingZeros))
    }

    /// A signed Exp-Golomb code, se(v).
    mutating func se() throws -> Int {
        let code = try ue()
        return code % 2 == 1 ? (code + 1) / 2 : -(code / 2)
    }
}

extension H264SliceHeaderParser.Failure: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformed: "An H.264 slice header in the video could not be read."
        case .unknownParameterSet: "An H.264 slice in the video names a parameter set the video does not carry."
        case let .unsupported(feature): "The video uses H.264 \(feature), which FairPlay protection does not support."
        }
    }
}
