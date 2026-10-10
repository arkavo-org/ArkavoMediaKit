import Foundation
import Testing
@testable import ArkavoMediaKit

/// `CBCSEncryptor` output decrypted by an independent reference `cbcs` decryptor, as a player decrypts it.
@Suite("cbcs round trip")
struct CBCSRoundTripTests {
    let key = Data((0 ..< 16).map { UInt8($0 &* 7 &+ 3) })
    let iv = Data((0 ..< 16).map { UInt8(0xF0 &- $0 &* 5) })

    /// A length-prefixed NAL unit: a 4-byte length, the header byte, then `payloadCount` bytes that vary with `seed`.
    private func nal(header: UInt8, payloadCount: Int, seed: UInt8) -> Data {
        let body = [header] + (0 ..< payloadCount).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) }
        return Data(withUnsafeBytes(of: UInt32(body.count).bigEndian, Array.init) + body)
    }

    @Test("A sample of two slice NAL units decrypts back to the plaintext")
    func twoSliceNALUnits() {
        // Long enough for three encrypted blocks per NAL unit, so the chain within each subsample matters, and two
        // NAL units, so restarting from the IV at each subsample (not once per sample) matters.
        let sample = nal(header: 0x65, payloadCount: 600, seed: 1) + nal(header: 0x65, payloadCount: 520, seed: 9)
        let encryptor = CBCSEncryptor(key: key, iv: iv)

        let result = encryptor.encryptVideoSample(sample, nalLengthSize: 4)

        #expect(result.subsamples.count == 2)
        #expect(result.encryptedData != sample)
        let decrypted = CBCSReferenceDecryptor.decrypt(result.encryptedData, subsamples: result.subsamples,
                                                       key: key, iv: iv, cryptBlocks: 1, skipBlocks: 9)
        #expect(decrypted == sample)
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
