import CommonCrypto
import Foundation
@testable import ArkavoMediaKit

/// A reference `cbcs` decryptor (ISO/IEC 23001-7 pattern encryption), written apart from `CBCSEncryptor` and the way a
/// player decrypts (it follows ffmpeg's mov demuxer):
/// - With subsamples, each subsample's protected bytes start again from the constant IV. Within them, the pattern's
///   encrypted 16-byte blocks form one CBC chain; the skipped blocks and a trailing partial block are clear.
/// - Without subsamples, the whole sample is one chain over every complete block, with a trailing partial block clear.
enum CBCSReferenceDecryptor {
    static func decrypt(_ sample: Data, subsamples: [SubsampleEntry]?, key: Data, iv: Data,
                        cryptBlocks: Int, skipBlocks: Int) -> Data {
        var bytes = [UInt8](sample)
        guard let subsamples, !subsamples.isEmpty else {
            let blocks = (0 ..< bytes.count / 16).map { $0 * 16 }
            decryptChain(&bytes, blockOffsets: blocks, key: key, iv: iv)
            return Data(bytes)
        }
        var offset = 0
        for subsample in subsamples {
            offset += Int(subsample.bytesOfClearData)
            let protected = Int(subsample.bytesOfProtectedData)
            let period = cryptBlocks + skipBlocks
            let blocks = (0 ..< protected / 16)
                .filter { period == 0 || $0 % period < cryptBlocks }
                .map { offset + $0 * 16 }
            decryptChain(&bytes, blockOffsets: blocks, key: key, iv: iv)
            offset += protected
        }
        return Data(bytes)
    }

    /// Decrypts the blocks at `blockOffsets` as one AES-128-CBC chain from `iv`, in place.
    private static func decryptChain(_ bytes: inout [UInt8], blockOffsets: [Int], key: Data, iv: Data) {
        guard !blockOffsets.isEmpty else { return }
        let cipher = blockOffsets.flatMap { bytes[$0 ..< $0 + 16] }
        var plain = [UInt8](repeating: 0, count: cipher.count)
        var moved = 0
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                        keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                        cipher, cipher.count, &plain, plain.count, &moved)
            }
        }
        precondition(status == kCCSuccess && moved == cipher.count, "reference decrypt failed: \(status)")
        for (index, offset) in blockOffsets.enumerated() {
            bytes.replaceSubrange(offset ..< offset + 16, with: plain[index * 16 ..< index * 16 + 16])
        }
    }
}
