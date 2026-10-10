import Foundation
import Testing
@testable import ArkavoMediaKit

/// `CBCSEncryptor` output decrypted by an independent reference `cbcs` decryptor, as a player decrypts it.
@Suite("cbcs round trip")
struct CBCSRoundTripTests {
    let key = Data((0 ..< 16).map { UInt8($0 &* 7 &+ 3) })
    let iv = Data((0 ..< 16).map { UInt8(0xF0 &- $0 &* 5) })

    /// A length-prefixed slice NAL unit: a real slice header from `H264SliceHeaderFixtures.high`, then
    /// `payloadCount` bytes that vary with `seed`.
    private func slice(_ index: Int, payloadCount: Int, seed: UInt8) -> (nal: Data, headerSize: Int) {
        let fixture = H264SliceHeaderFixtures.high.slices[index]
        let header = Data(hex: fixture.nal).prefix(fixture.headerSize)
        let body = header + (0 ..< payloadCount).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) }
        return (Data(withUnsafeBytes(of: UInt32(body.count).bigEndian, Array.init)) + body, fixture.headerSize)
    }

    private var sliceHeaders: H264SliceHeaderParser {
        get throws {
            try H264SliceHeaderParser(sps: [Data(hex: H264SliceHeaderFixtures.high.sps)],
                                      pps: [Data(hex: H264SliceHeaderFixtures.high.pps)])
        }
    }

    @Test("A sample of two slice NAL units decrypts back to the plaintext")
    func twoSliceNALUnits() throws {
        // Two slices of one picture, with headers of over 20 bytes, each long enough for three encrypted blocks, so
        // the chain within a subsample matters and so does restarting from the IV at each subsample.
        let first = slice(4, payloadCount: 600, seed: 1), second = slice(5, payloadCount: 520, seed: 9)
        let sample = first.nal + second.nal
        let encryptor = CBCSEncryptor(key: key, iv: iv)

        let result = try encryptor.encryptVideoSample(sample, nalLengthSize: 4, sliceHeaders: sliceHeaders)

        #expect(result.encryptedData != sample)
        let decrypted = CBCSReferenceDecryptor.decrypt(result.encryptedData, subsamples: result.subsamples,
                                                       key: key, iv: iv, cryptBlocks: 1, skipBlocks: 9)
        #expect(decrypted == sample)
    }

    @Test("Protection starts on the first byte after each slice header")
    func clearThroughSliceHeader() throws {
        let first = slice(4, payloadCount: 600, seed: 1), second = slice(5, payloadCount: 520, seed: 9)
        let encryptor = CBCSEncryptor(key: key, iv: iv)

        let result = try encryptor.encryptVideoSample(first.nal + second.nal, nalLengthSize: 4,
                                                      sliceHeaders: sliceHeaders)

        #expect(result.subsamples.map(\.bytesOfClearData) == [UInt16(4 + first.headerSize),
                                                              UInt16(4 + second.headerSize)])
        #expect(result.subsamples.map(\.bytesOfProtectedData) == [UInt32(first.nal.count - 4 - first.headerSize),
                                                                  UInt32(second.nal.count - 4 - second.headerSize)])
    }

    @Test("A slice whose header cannot be measured is refused, not protected from a guess")
    func unmeasurableSlice() throws {
        // Data partitioning (NAL unit type 2) is not measured.
        let sample = Data([0, 0, 0, 40, 0x62]) + Data(repeating: 0x5A, count: 39)
        let encryptor = CBCSEncryptor(key: key, iv: iv)

        #expect(throws: H264SliceHeaderParser.Failure.self) {
            try encryptor.encryptVideoSample(sample, nalLengthSize: 4, sliceHeaders: sliceHeaders)
        }
    }

    @Test("A sample its NAL unit lengths do not cover exactly is refused, not truncated",
          arguments: [1, 3, 7])
    func trailingBytes(extra: Int) throws {
        let sample = slice(4, payloadCount: 200, seed: 3).nal + Data(repeating: 0, count: extra)
        let encryptor = CBCSEncryptor(key: key, iv: iv)

        #expect(throws: CBCSEncryptor.Failure.malformedSample) {
            try encryptor.encryptVideoSample(sample, nalLengthSize: 4, sliceHeaders: sliceHeaders)
        }
    }

    @Test("An audio sample decrypts back to the plaintext as one full-sample chain")
    func audioFullSample() {
        // Six complete blocks and a trailing partial block, which stays clear.
        let sample = Data((0 ..< 100).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ 5) })
        let encryptor = CBCSEncryptor(key: key, iv: iv)

        let result = encryptor.encryptAudioSample(sample)

        #expect(result.encryptedData.prefix(96) != sample.prefix(96))
        #expect(result.encryptedData.suffix(4) == sample.suffix(4))
        let decrypted = CBCSReferenceDecryptor.decrypt(result.encryptedData, subsamples: nil,
                                                       key: key, iv: iv, cryptBlocks: 0, skipBlocks: 0)
        #expect(decrypted == sample)
    }
}
