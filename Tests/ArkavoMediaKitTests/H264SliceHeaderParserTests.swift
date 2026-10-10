import Foundation
import Testing
@testable import ArkavoMediaKit

@Suite("H.264 slice header length")
struct H264SliceHeaderParserTests {
    @Test("Each fixture slice's header length matches ffmpeg's trace", arguments: H264SliceHeaderFixtures.all)
    func fixtureStreams(name: String, stream: H264SliceHeaderFixtures.Stream) throws {
        let parser = try H264SliceHeaderParser(sps: [Data(hex: stream.sps)], pps: [Data(hex: stream.pps)])
        for (index, slice) in stream.slices.enumerated() {
            #expect(try parser.headerSize(ofSlice: Data(hex: slice.nal)) == slice.headerSize,
                    "\(name) slice \(index)")
        }
    }

    @Test("The reader drops an emulation prevention byte but counts it")
    func emulationPrevention() throws {
        var reader = RBSPReader([0x00, 0x00, 0x03, 0x01, 0xFF])
        #expect(try reader.bits(24) == 0x000001)
        #expect(reader.rawBitsRead == 32)
    }

    @Test("Exp-Golomb codes read as H.264 defines them")
    func expGolomb() throws {
        // ue: 1 → 0, 010 → 1, 011 → 2, 00100 → 3; se: 010 → 1, 011 → -1, 00100 → 2.
        var reader = RBSPReader([0b1010_0110, 0b0100_0100, 0b1100_1000])
        #expect(try reader.ue() == 0)
        #expect(try reader.ue() == 1)
        #expect(try reader.ue() == 2)
        #expect(try reader.ue() == 3)
        #expect(try reader.se() == 1)
        #expect(try reader.se() == -1)
        #expect(try reader.se() == 2)
    }

    /// An SPS with scaling lists and picture order count type 1, a PPS with redundant picture counts, and a P slice
    /// whose header holds an emulation prevention byte: syntax the encoder fixtures do not reach.
    @Test("A hand-built stream with scaling lists, POC type 1 and an escaped header")
    func handBuilt() throws {
        var sps = BitWriter()
        sps.u(100, 8); sps.u(0, 8); sps.u(30, 8); sps.ue(0)        // profile High, constraints, level, sps id
        sps.ue(1); sps.ue(0); sps.ue(0); sps.u(0, 1)                 // 4:2:0, 8-bit luma and chroma, qpprime
        sps.u(1, 1)                                                  // seq_scaling_matrix_present_flag
        for list in 0 ..< 8 {
            sps.u(list % 3 == 0 ? 1 : 0, 1)                          // seq_scaling_list_present_flag
            if list == 0 {
                // nextScale 8 → 9 → 10 → 11, then a delta of -11 makes it 0, which ends the list early.
                sps.se(1); sps.se(1); sps.se(1); sps.se(-11)
            } else if list % 3 == 0 {
                for _ in 0 ..< (list < 6 ? 16 : 64) { sps.se(1) }  // a whole 4x4 list, then a whole 8x8 list
            }
        }
        sps.ue(3)                                                    // log2_max_frame_num_minus4: 7-bit frame_num
        sps.ue(1); sps.u(0, 1); sps.se(-2); sps.se(3); sps.ue(2); sps.se(1); sps.se(-1)  // POC type 1, cycle of 2
        sps.ue(4); sps.u(0, 1); sps.ue(19); sps.ue(10); sps.u(1, 1)  // refs, gaps, size, frame_mbs_only_flag
        sps.u(1, 1); sps.u(0, 1); sps.u(0, 1); sps.u(0, 1)           // direct_8x8, cropping, VUI, stop bit
        var pps = BitWriter()
        pps.ue(0); pps.ue(0); pps.u(1, 1); pps.u(1, 1); pps.ue(0)    // ids, CABAC, bottom field POC, no slice groups
        pps.ue(2); pps.ue(0); pps.u(0, 1); pps.u(0, 2)               // default refs, no weighted prediction
        pps.se(0); pps.se(0); pps.se(0); pps.u(1, 1); pps.u(0, 1); pps.u(1, 1)  // qp, deblocking, redundant_pic_cnt
        var slice = BitWriter()
        slice.ue(4_194_303)          // first_mb_in_slice: 22 leading zero bits, so the payload starts 0x0000 0x02…
        slice.ue(5); slice.ue(0); slice.u(93, 7)                     // P, pps id, frame_num
        slice.se(-3); slice.se(4)                                    // delta_pic_order_cnt[0], [1]
        slice.ue(1_000)                                              // redundant_pic_cnt
        slice.u(1, 1); slice.ue(1)                                   // num_ref_idx override: two references
        slice.u(1, 1); slice.ue(0); slice.ue(2); slice.ue(2); slice.ue(5); slice.ue(3)  // list modification
        slice.ue(1); slice.se(-2)                                    // cabac_init_idc, slice_qp_delta
        slice.ue(0); slice.se(1); slice.se(-1)                       // deblocking idc 0 with offsets
        let headerBits = slice.count
        slice.u(1, 1); slice.alignWithOnes(); slice.bytes(0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55)

        let parser = try H264SliceHeaderParser(sps: [sps.nal(header: 0x67)], pps: [pps.nal(header: 0x68)])
        let nal = slice.nal(header: 0x01)
        #expect(nal.count > slice.byteCount + 1, "the slice header carries an emulation prevention byte")
        #expect(try parser.headerSize(ofSlice: nal) == slice.escapedSize(forBits: headerBits) + 1)
        let escapes = slice.escapedSize(forBits: headerBits) - (headerBits + 7) / 8
        #expect(escapes == 2)
        #expect(try parser.sliceHeaderBits(ofSlice: nal) == headerBits + 8 * escapes)
    }

    @Test("A slice naming a PPS the stream did not carry is refused")
    func unknownPPS() throws {
        let stream = H264SliceHeaderFixtures.high
        let parser = try H264SliceHeaderParser(sps: [Data(hex: stream.sps)], pps: [Data(hex: stream.pps)])
        var slice = BitWriter()
        slice.ue(0); slice.ue(7); slice.ue(5); slice.bytes(0xFF, 0xFF, 0xFF, 0xFF)  // I slice, pps id 5
        #expect(throws: H264SliceHeaderParser.Failure.unknownParameterSet) {
            try parser.headerSize(ofSlice: slice.nal(header: 0x65))
        }
    }

    @Test("Slice NAL units outside types 1 and 5 are refused", arguments: [UInt8(2), 3, 4, 19, 20])
    func otherSliceTypes(type: UInt8) throws {
        let stream = H264SliceHeaderFixtures.high
        let parser = try H264SliceHeaderParser(sps: [Data(hex: stream.sps)], pps: [Data(hex: stream.pps)])
        #expect(throws: H264SliceHeaderParser.Failure.unsupported("slice NAL unit type \(type)")) {
            try parser.headerSize(ofSlice: Data([0x60 | type, 0x88, 0x84, 0x00, 0xFF]))
        }
    }

    @Test("SP and SI slices (Extended profile) are refused", arguments: [3, 4, 8, 9])
    func switchingSlices(sliceType: Int) throws {
        let stream = H264SliceHeaderFixtures.baseline
        let parser = try H264SliceHeaderParser(sps: [Data(hex: stream.sps)], pps: [Data(hex: stream.pps)])
        var slice = BitWriter()
        slice.ue(0); slice.ue(sliceType); slice.ue(0); slice.bytes(0xFF, 0xFF, 0xFF, 0xFF)
        #expect(throws: H264SliceHeaderParser.Failure.unsupported("SP and SI slices")) {
            try parser.headerSize(ofSlice: slice.nal(header: 0x41))
        }
    }

    @Test("A header cut short is malformed")
    func truncated() throws {
        let stream = H264SliceHeaderFixtures.high
        let parser = try H264SliceHeaderParser(sps: [Data(hex: stream.sps)], pps: [Data(hex: stream.pps)])
        let slice = Data(hex: stream.slices[4].nal)  // a P slice whose header runs to 23 bytes
        #expect(throws: H264SliceHeaderParser.Failure.malformed) {
            try parser.headerSize(ofSlice: slice.prefix(10))
        }
    }

    @Test("A PPS with slice groups is refused")
    func sliceGroups() throws {
        let stream = H264SliceHeaderFixtures.baseline
        var pps = BitWriter()
        pps.ue(0); pps.ue(0); pps.u(0, 1); pps.u(0, 1); pps.ue(1)   // num_slice_groups_minus1 1
        pps.ue(0); pps.bytes(0xFF, 0xFF)
        #expect(throws: H264SliceHeaderParser.Failure.unsupported("slice groups")) {
            try H264SliceHeaderParser(sps: [Data(hex: stream.sps)], pps: [pps.nal(header: 0x68)])
        }
    }
}

/// Writes RBSP bits, then escapes them into a NAL unit the way an encoder does.
struct BitWriter {
    private(set) var bits: [UInt8] = []

    var count: Int { bits.count }
    var byteCount: Int { (bits.count + 7) / 8 }

    mutating func u(_ value: Int, _ width: Int) {
        for shift in stride(from: width - 1, through: 0, by: -1) { bits.append(UInt8((value >> shift) & 1)) }
    }

    mutating func ue(_ value: Int) {
        let coded = value + 1
        let width = Int.bitWidth - coded.leadingZeroBitCount
        u(0, width - 1)
        u(coded, width)
    }

    mutating func se(_ value: Int) { ue(value > 0 ? 2 * value - 1 : -2 * value) }

    mutating func alignWithOnes() { while bits.count % 8 != 0 { bits.append(1) } }

    mutating func bytes(_ values: UInt8...) { for value in values { u(Int(value), 8) } }

    private var rbsp: [UInt8] {
        var padded = bits
        while padded.count % 8 != 0 { padded.append(0) }
        return stride(from: 0, to: padded.count, by: 8).map { start in
            padded[start ..< start + 8].reduce(0) { $0 << 1 | $1 }
        }
    }

    /// The NAL unit: `header`, then the RBSP with an emulation prevention byte after each 0x0000 that precedes a
    /// byte of at most 0x03.
    func nal(header: UInt8) -> Data {
        Data([header] + Self.escape(rbsp))
    }

    /// Escaped bytes covering the first `bitCount` RBSP bits, rounded up.
    func escapedSize(forBits bitCount: Int) -> Int {
        Self.escape(Array(rbsp.prefix((bitCount + 7) / 8))).count
    }

    private static func escape(_ bytes: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        var zeros = 0
        for byte in bytes {
            if zeros >= 2, byte <= 3 { out.append(3); zeros = 0 }
            out.append(byte)
            zeros = byte == 0 ? zeros + 1 : 0
        }
        return out
    }
}

/// A protect that fails on the video shows `localizedDescription` (Creator's "Protection Error" alert), so each
/// failure says what it was.
@Suite("Video protection failure descriptions")
struct VideoProtectionFailureDescriptionTests {
    @Test("Slice header failures describe themselves")
    func sliceHeaderFailures() {
        #expect(H264SliceHeaderParser.Failure.malformed.localizedDescription
                    == "An H.264 slice header in the video could not be read.")
        #expect(H264SliceHeaderParser.Failure.unknownParameterSet.localizedDescription
                    == "An H.264 slice in the video names a parameter set the video does not carry.")
        #expect(H264SliceHeaderParser.Failure.unsupported("slice groups").localizedDescription
                    == "The video uses H.264 slice groups, which FairPlay protection does not support.")
    }

    @Test("A malformed sample describes itself")
    func malformedSample() {
        #expect(CBCSEncryptor.Failure.malformedSample.localizedDescription
                    == "A video sample's NAL unit lengths do not match its size.")
    }
}
