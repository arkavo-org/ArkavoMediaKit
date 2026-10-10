import Foundation
@testable import ArkavoMediaKit

/// Real H.264 slices for tests that build samples by hand: the parameter sets and slice headers of
/// `H264SliceHeaderFixtures.high`, followed by filler.
///
/// `CBCSEncryptor` measures each slice header from the stream's parameter sets, so a slice NAL unit of a header byte
/// and filler is not a slice it can protect.
enum H264TestStream {
    static let sps = Data(hex: H264SliceHeaderFixtures.high.sps)
    static let pps = Data(hex: H264SliceHeaderFixtures.high.pps)

    /// Measures the slice headers of `slice(isIDR:count:filler:)`.
    static func sliceHeaders() throws -> H264SliceHeaderParser {
        try H264SliceHeaderParser(sps: [sps], pps: [pps])
    }

    /// A slice NAL unit (no length prefix) of `count` bytes: a real IDR or P slice header, then `filler`.
    static func slice(isIDR: Bool, count: Int, filler: UInt8 = 0xCC) -> Data {
        let size = headerSize(isIDR: isIDR)
        precondition(count >= size, "A \(count)-byte slice cannot hold its \(size)-byte header")
        return Data(Data(hex: fixture(isIDR: isIDR).nal).prefix(size)) + Data(repeating: filler, count: count - size)
    }

    /// Its slice header length, NAL header included (the fixture's `headerSize`).
    static func headerSize(isIDR: Bool) -> Int {
        fixture(isIDR: isIDR).headerSize
    }

    /// Slice 0 of `high` is an IDR slice (NAL unit type 5), slice 2 a P slice (type 1).
    private static func fixture(isIDR: Bool) -> (nal: String, headerSize: Int) {
        H264SliceHeaderFixtures.high.slices[isIDR ? 0 : 2]
    }
}
