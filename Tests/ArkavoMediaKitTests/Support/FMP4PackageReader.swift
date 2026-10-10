import Foundation
@testable import ArkavoMediaKit

/// One ISO BMFF box: its type, where it starts and its payload (after the size and type, and for a full box before
/// version and flags).
struct MP4Box {
    let type: String
    let start: Int
    let payload: Range<Int>

    var end: Int { payload.upperBound }
}

/// A protected fMP4 presentation read the way a player reads it, every sample decrypted with
/// `CBCSReferenceDecryptor`: the init segment's tracks and protection, then each media segment's fragments.
struct FMP4PackageReader {
    enum Failure: Error { case malformed(String) }

    struct Track {
        let trackID: UInt32
        let handler: String
        let sampleEntry: String
        let originalFormat: String
        let tencVersion: UInt8
        let cryptBlocks: Int
        let skipBlocks: Int
        let constantIV: Data
        /// The `esds` AudioSpecificConfig's audio object type, for an audio track.
        let audioObjectType: Int?
    }

    struct Fragment {
        let trackID: UInt32
        let baseDecodeTime: UInt64
        let durations: [UInt32]
        /// The fragment's `traf` children other than `tfhd`, `tfdt` and `trun`.
        let auxiliaryBoxes: [String]
        /// The `senc` flags, when there is a `senc`.
        let sencFlags: UInt32?
    }

    private(set) var tracks: [UInt32: Track] = [:]
    /// The fragments of each media segment, in order.
    private(set) var segments: [[Fragment]] = []
    /// Every track's samples, decrypted, in decode order.
    private(set) var samples: [UInt32: [Data]] = [:]

    init(initSegment: Data, segments mediaSegments: [Data], key: Data) throws {
        let bytes = [UInt8](initSegment)
        guard let moov = Self.boxes(bytes, in: 0 ..< bytes.count).first(where: { $0.type == "moov" }) else {
            throw Failure.malformed("no moov")
        }
        for trak in Self.boxes(bytes, in: moov.payload) where trak.type == "trak" {
            let track = try Self.track(bytes, trak)
            tracks[track.trackID] = track
        }
        for segment in mediaSegments {
            segments.append(try read(segment, key: key))
        }
    }

    // MARK: - Init segment

    private static func track(_ bytes: [UInt8], _ trak: MP4Box) throws -> Track {
        let tkhd = try only("tkhd", in: trak, bytes)
        let tkhdVersion = bytes[tkhd.payload.lowerBound]
        let trackID = be32(bytes, tkhd.payload.lowerBound + 4 + (tkhdVersion == 1 ? 16 : 8))
        let mdia = try only("mdia", in: trak, bytes)
        let hdlr = try only("hdlr", in: mdia, bytes)
        let handler = fourCC(bytes, hdlr.payload.lowerBound + 8)
        let stsd = try only("stbl", in: only("minf", in: mdia, bytes), bytes)
        let stsdBox = try only("stsd", in: stsd, bytes)
        // stsd: version and flags, entry count, then the entries.
        guard let entry = boxes(bytes, in: stsdBox.payload.lowerBound + 8 ..< stsdBox.end).first else {
            throw Failure.malformed("no sample entry")
        }
        let fields = handler == "vide" ? 78 : 28
        let children = boxes(bytes, in: entry.payload.lowerBound + fields ..< entry.end)
        guard let sinf = children.first(where: { $0.type == "sinf" }) else { throw Failure.malformed("no sinf") }
        let frma = try only("frma", in: sinf, bytes)
        let tenc = try only("tenc", in: only("schi", in: sinf, bytes), bytes)
        let start = tenc.payload.lowerBound
        let ivSize = Int(bytes[start + 24])
        var objectType: Int?
        if let esds = children.first(where: { $0.type == "esds" }) {
            // The DecoderSpecificInfo (tag 5) is the AudioSpecificConfig, whose first 5 bits are the object type.
            let body = Array(bytes[esds.payload])
            if let tag = body.firstIndex(of: 0x05), tag + 2 < body.count { objectType = Int(body[tag + 2] >> 3) }
        }
        return Track(trackID: trackID, handler: handler, sampleEntry: entry.type,
                     originalFormat: fourCC(bytes, frma.payload.lowerBound), tencVersion: bytes[start],
                     cryptBlocks: Int(bytes[start + 5] >> 4), skipBlocks: Int(bytes[start + 5] & 0x0F),
                     constantIV: Data(bytes[start + 25 ..< start + 25 + ivSize]), audioObjectType: objectType)
    }

    // MARK: - Media segments

    private mutating func read(_ segment: Data, key: Data) throws -> [Fragment] {
        let bytes = [UInt8](segment)
        var fragments: [Fragment] = []
        for moof in Self.boxes(bytes, in: 0 ..< bytes.count) where moof.type == "moof" {
            for traf in Self.boxes(bytes, in: moof.payload) where traf.type == "traf" {
                fragments.append(try read(traf, of: moof, in: bytes, key: key))
            }
        }
        return fragments
    }

    private mutating func read(_ traf: MP4Box, of moof: MP4Box, in bytes: [UInt8], key: Data) throws -> Fragment {
        let children = Self.boxes(bytes, in: traf.payload)
        let tfhd = try Self.only("tfhd", in: traf, bytes)
        let trackID = Self.be32(bytes, tfhd.payload.lowerBound + 4)
        guard Self.be32(bytes, tfhd.payload.lowerBound) & 0x02_0000 != 0 else {
            throw Failure.malformed("tfhd without default-base-is-moof")
        }
        guard let track = tracks[trackID] else { throw Failure.malformed("traf for unknown track \(trackID)") }
        let tfdt = try Self.only("tfdt", in: traf, bytes)
        let baseDecodeTime = bytes[tfdt.payload.lowerBound] == 1
            ? UInt64(Self.be32(bytes, tfdt.payload.lowerBound + 4)) << 32 | UInt64(Self.be32(bytes, tfdt.payload.lowerBound + 8))
            : UInt64(Self.be32(bytes, tfdt.payload.lowerBound + 4))

        // trun: per-sample durations and sizes, and where the samples start relative to the moof.
        let trun = try Self.only("trun", in: traf, bytes)
        let flags = Self.be32(bytes, trun.payload.lowerBound) & 0xFF_FFFF
        let count = Int(Self.be32(bytes, trun.payload.lowerBound + 4))
        var cursor = trun.payload.lowerBound + 8
        guard flags & 0x01 != 0 else { throw Failure.malformed("trun without data_offset") }
        var dataStart = moof.start + Int(Int32(bitPattern: Self.be32(bytes, cursor)))
        cursor += 4
        if flags & 0x04 != 0 { cursor += 4 }
        var durations: [UInt32] = [], sizes: [Int] = []
        for _ in 0 ..< count {
            if flags & 0x100 != 0 { durations.append(Self.be32(bytes, cursor)); cursor += 4 }
            guard flags & 0x200 != 0 else { throw Failure.malformed("trun without sample sizes") }
            sizes.append(Int(Self.be32(bytes, cursor))); cursor += 4
            if flags & 0x400 != 0 { cursor += 4 }
            if flags & 0x800 != 0 { cursor += 4 }
        }

        // senc: subsamples when flag 2 is set; with a constant IV there are no per-sample IVs.
        var subsamples: [[SubsampleEntry]?] = Array(repeating: nil, count: count)
        var sencFlags: UInt32?
        if let senc = children.first(where: { $0.type == "senc" }) {
            let flags = Self.be32(bytes, senc.payload.lowerBound) & 0xFF_FFFF
            sencFlags = flags
            guard Int(Self.be32(bytes, senc.payload.lowerBound + 4)) == count else {
                throw Failure.malformed("senc and trun disagree on the sample count")
            }
            if flags & 0x02 != 0 {
                var position = senc.payload.lowerBound + 8
                for index in 0 ..< count {
                    let entries = Int(Self.be16(bytes, position))
                    position += 2
                    subsamples[index] = (0 ..< entries).map { entry in
                        let at = position + entry * 6
                        return SubsampleEntry(bytesOfClearData: Self.be16(bytes, at),
                                              bytesOfProtectedData: Self.be32(bytes, at + 2))
                    }
                    position += entries * 6
                }
                // saio points at the first sample's auxiliary information: the senc's first entry.
                let saio = try Self.only("saio", in: traf, bytes)
                let saioHasType = Self.be32(bytes, saio.payload.lowerBound) & 0x01 != 0
                let offset = Int(Self.be32(bytes, saio.payload.lowerBound + (saioHasType ? 16 : 8)))
                guard moof.start + offset == senc.payload.lowerBound + 8 else {
                    throw Failure.malformed("saio does not point at the senc entries")
                }
            }
        }

        let key = key
        for index in 0 ..< count {
            let sample = Data(bytes[dataStart ..< dataStart + sizes[index]])
            dataStart += sizes[index]
            samples[trackID, default: []].append(CBCSReferenceDecryptor.decrypt(
                sample, subsamples: subsamples[index], key: key, iv: track.constantIV,
                cryptBlocks: track.cryptBlocks, skipBlocks: track.skipBlocks))
        }
        let auxiliary = children.map(\.type).filter { !["tfhd", "tfdt", "trun"].contains($0) }
        return Fragment(trackID: trackID, baseDecodeTime: baseDecodeTime, durations: durations,
                        auxiliaryBoxes: auxiliary, sencFlags: sencFlags)
    }

    // MARK: - Boxes

    static func boxes(_ bytes: [UInt8], in range: Range<Int>) -> [MP4Box] {
        var out: [MP4Box] = []
        var offset = range.lowerBound
        while offset + 8 <= range.upperBound {
            var size = Int(be32(bytes, offset))
            var header = 8
            if size == 1 {
                size = Int(UInt64(be32(bytes, offset + 8)) << 32 | UInt64(be32(bytes, offset + 12)))
                header = 16
            } else if size == 0 {
                size = range.upperBound - offset
            }
            guard size >= header, offset + size <= range.upperBound else { break }
            let type = fourCC(bytes, offset + 4)
            // Full boxes this reader walks into keep version and flags in the payload; `stsd` is read by hand.
            out.append(MP4Box(type: type, start: offset, payload: offset + header ..< offset + size))
            offset += size
        }
        return out
    }

    static func only(_ type: String, in parent: MP4Box, _ bytes: [UInt8]) throws -> MP4Box {
        let matches = boxes(bytes, in: parent.payload).filter { $0.type == type }
        guard matches.count == 1 else { throw Failure.malformed("\(matches.count) \(type) in \(parent.type)") }
        return matches[0]
    }

    static func be16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    static func be32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        (0 ..< 4).reduce(UInt32(0)) { $0 << 8 | UInt32(bytes[offset + $1]) }
    }

    static func fourCC(_ bytes: [UInt8], _ offset: Int) -> String {
        String(decoding: bytes[offset ..< offset + 4], as: UTF8.self)
    }
}
