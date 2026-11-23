import CommonCrypto
import CryptoKit
import Foundation
import Synchronization

// MARK: - CBCS Debug Configuration

/// Global configuration for CBCS encryption debugging
public enum CBCSDebugConfig {
    #if DEBUG
    private static let verboseLoggingStorage = Mutex(true)
    #else
    private static let verboseLoggingStorage = Mutex(false)
    #endif

    /// Enable verbose debug logging (set to false for production)
    public static var isVerboseLoggingEnabled: Bool {
        get { verboseLoggingStorage.withLock { $0 } }
        set { verboseLoggingStorage.withLock { $0 = newValue } }
    }
}

// MARK: - CBCS Encryptor

/// CBCS (Common Encryption Scheme - CBC mode with Subsample encryption) encryptor
/// Implements pattern-based encryption for FairPlay Streaming
public final class CBCSEncryptor: Sendable {
    // MARK: - Types

    public enum Failure: Error, Equatable, Sendable {
        /// The sample's NAL unit lengths do not cover it exactly.
        case malformedSample
        /// The system's random source failed, with this status: there is no key.
        case randomBytesUnavailable(OSStatus)
        /// The CBCS pattern (`cryptBlocks:skipBlocks`) is outside ISO/IEC 23001-7 limits
        /// (`0...15` each, and `cryptBlocks == 0` is only valid with `skipBlocks == 0`).
        case invalidPattern(cryptBlocks: Int, skipBlocks: Int)
    }

    /// Encryption result with subsample map
    public struct EncryptionResult: Sendable {
        public let encryptedData: Data
        public let subsamples: [SubsampleEntry]
    }

    /// NAL unit information for subsample mapping
    public struct NALUnit: Sendable {
        public let type: UInt8
        public let offset: Int
        public let length: Int
        public let isSlice: Bool // True for VCL NAL units (actual video data)
    }

    // MARK: - Properties

    private let key: Data      // 16 bytes AES-128 key
    private let iv: Data       // 16 bytes initialization vector
    private let cryptBlocks: Int
    private let skipBlocks: Int

    // MARK: - Initialization

    /// Initialize CBCS encryptor with key and IV
    /// - Parameters:
    ///   - key: 16-byte AES-128 encryption key
    ///   - iv: 16-byte initialization vector (constant for CBCS)
    ///   - cryptBlocks: Number of blocks to encrypt in pattern (default 1; 0:0 means full-sample whole-block encryption)
    ///   - skipBlocks: Number of blocks to skip in pattern (default 9)
    public init(key: Data, iv: Data, cryptBlocks: Int = 1, skipBlocks: Int = 9) {
        precondition(key.count == 16, "Key must be 16 bytes for AES-128")
        precondition(iv.count == 16, "IV must be 16 bytes")

        // Normalize into fresh contiguous zero-based Data so slices with non-zero startIndex are safe
        self.key = Data(key)
        self.iv = Data(iv)
        self.cryptBlocks = cryptBlocks
        self.skipBlocks = skipBlocks
    }

    /// Validates that the configured CBCS pattern fits in ISO/IEC 23001-7 4-bit `tenc` fields
    /// and is not an unencrypted `0:N` (`N > 0`) pattern.
    private func validatePattern() throws {
        guard (0 ... 15).contains(cryptBlocks),
              (0 ... 15).contains(skipBlocks),
              cryptBlocks > 0 || skipBlocks == 0
        else {
            throw Failure.invalidPattern(cryptBlocks: cryptBlocks, skipBlocks: skipBlocks)
        }
    }

    // MARK: - Video Encryption (H.264)

    /// Encrypt video sample with NAL unit awareness
    ///
    /// Each slice NAL unit is one subsample whose clear bytes are its length prefix, NAL header and slice header,
    /// so protection starts on the first byte after the slice header (ISO/IEC 23001-7 `cbcs`, as CMAF requires).
    /// Every other NAL unit is clear (split into <= 65,535-byte subsample entries if larger than `UInt16.max`).
    /// - Parameters:
    ///   - sample: Raw video sample data (with length-prefixed NAL units)
    ///   - nalLengthSize: Size of NAL unit length field (must be 1, 2, or 4; typically 4)
    ///   - sliceHeaders: Measures slice headers, from the stream's parameter sets
    /// - Returns: Encrypted data and subsample map
    /// - Throws: `Failure.invalidPattern`, `Failure.malformedSample`, or `H264SliceHeaderParser.Failure`
    public func encryptVideoSample(_ sample: Data, nalLengthSize: Int = 4,
                                   sliceHeaders: H264SliceHeaderParser) throws -> EncryptionResult {
        try validatePattern()
        let bytes = [UInt8](sample)
        let nalUnits = try parseNALUnits(bytes, lengthSize: nalLengthSize)

        var encryptedData = Data()
        encryptedData.reserveCapacity(bytes.count)
        var subsamples: [SubsampleEntry] = []

        // Debug: Log NAL structure for first few samples
        if CBCSDebugConfig.isVerboseLoggingEnabled && nalUnits.count > 1 {
            let nalTypes = nalUnits.map { "NAL\($0.type)(\($0.isSlice ? "slice" : "non-slice"):\($0.length)B)" }
            print("🔍 [CBCS] Sample \(bytes.count)B has \(nalUnits.count) NALs: \(nalTypes.joined(separator: ", "))")
        }

        for nal in nalUnits {
            let nalData = Data(bytes[nal.offset ..< (nal.offset + nal.length)])

            if nal.isSlice {
                // Encrypt slice NAL units
                let (encrypted, nalSubsamples) = try encryptNALUnit(nalData, lengthSize: nalLengthSize,
                                                                    sliceHeaders: sliceHeaders)
                encryptedData.append(encrypted)
                subsamples.append(contentsOf: nalSubsamples)
            } else {
                // Non-slice NAL units (SPS, PPS, SEI, etc.) are kept clear; split if > UInt16.max
                encryptedData.append(nalData)
                Self.appendClearSubsamples(byteCount: nal.length, into: &subsamples)
            }
        }

        // Verify total bytes match
        let totalClear = subsamples.reduce(0) { $0 + Int($1.bytesOfClearData) }
        let totalProtected = subsamples.reduce(0) { $0 + Int($1.bytesOfProtectedData) }
        let totalSubsampleBytes = totalClear + totalProtected
        if totalSubsampleBytes != encryptedData.count && CBCSDebugConfig.isVerboseLoggingEnabled {
            print("⚠️ [CBCS] Subsample mismatch: clear=\(totalClear) + protected=\(totalProtected) = \(totalSubsampleBytes), but data=\(encryptedData.count)")
        }

        // Debug: Log subsample structure
        if CBCSDebugConfig.isVerboseLoggingEnabled {
            let subsampleDesc = subsamples.map { "[\($0.bytesOfClearData)c/\($0.bytesOfProtectedData)p]" }.joined(separator: " ")
            print("🔍 [CBCS] Sample \(encryptedData.count)B → \(subsamples.count) subsamples: \(subsampleDesc)")
        }

        return EncryptionResult(encryptedData: encryptedData, subsamples: subsamples)
    }

    /// Splits a clear-only byte run into one or more `SubsampleEntry` items so `bytesOfClearData` never overflows `UInt16`.
    private static func appendClearSubsamples(byteCount: Int, into subsamples: inout [SubsampleEntry]) {
        var remaining = byteCount
        let maxClear = Int(UInt16.max)
        while remaining > maxClear {
            subsamples.append(SubsampleEntry(bytesOfClearData: UInt16.max, bytesOfProtectedData: 0))
            remaining -= maxClear
        }
        subsamples.append(SubsampleEntry(bytesOfClearData: UInt16(remaining), bytesOfProtectedData: 0))
    }

    /// Encrypt a single slice NAL unit using CBCS pattern, from the first byte after its slice header
    private func encryptNALUnit(_ nalData: Data, lengthSize: Int,
                                sliceHeaders: H264SliceHeaderParser) throws -> (Data, [SubsampleEntry]) {
        // Length prefix, NAL header and slice header stay clear.
        let clearBytes = lengthSize + (try sliceHeaders.headerSize(ofSlice: nalData.dropFirst(lengthSize)))
        guard clearBytes <= nalData.count else {
            throw Failure.malformedSample
        }

        // Keep NAL header + slice header clear
        let clearPart = nalData.prefix(clearBytes)

        // Payload to encrypt (everything after clear bytes)
        let payload = nalData.dropFirst(clearBytes)

        if payload.isEmpty {
            var entries: [SubsampleEntry] = []
            Self.appendClearSubsamples(byteCount: nalData.count, into: &entries)
            return (nalData, entries)
        }

        // Apply pattern encryption to payload
        let encryptedPayload = encryptWithPattern(Data(payload))
        guard let protectedCount = UInt32(exactly: encryptedPayload.count) else {
            throw Failure.malformedSample
        }

        // Debug: Verify encryption actually modified data
        if CBCSDebugConfig.isVerboseLoggingEnabled && payload.count >= 16 {
            let originalFirst16 = Array(payload.prefix(16))
            let encryptedFirst16 = Array(encryptedPayload.prefix(16))
            let modified = originalFirst16 != encryptedFirst16
            if !modified {
                print("⚠️ [CBCS] WARNING: First 16 bytes NOT modified by encryption!")
            }
        }

        var result = Data()
        result.reserveCapacity(nalData.count)
        result.append(clearPart)
        result.append(encryptedPayload)

        var entries: [SubsampleEntry] = []
        var remainingClear = clearBytes
        let maxClear = Int(UInt16.max)
        while remainingClear > maxClear {
            entries.append(SubsampleEntry(bytesOfClearData: UInt16.max, bytesOfProtectedData: 0))
            remainingClear -= maxClear
        }
        entries.append(SubsampleEntry(
            bytesOfClearData: UInt16(remainingClear),
            bytesOfProtectedData: protectedCount
        ))

        return (result, entries)
    }

    /// Apply CBCS pattern encryption (encrypt N blocks, skip M blocks) to one subsample's protected bytes.
    ///
    /// Per ISO/IEC 23001-7 `cbcs`, pattern `0:0` encrypts every complete 16-byte block (full-sample whole-block).
    /// Otherwise encrypted blocks form one CBC chain starting from the constant IV across skipped blocks.
    private func encryptWithPattern(_ data: Data) -> Data {
        let blockCount = data.count / 16
        guard blockCount > 0 else { return data }
        if cryptBlocks == 0 && skipBlocks == 0 {
            return encryptChain(data, blocks: Array(0 ..< blockCount))
        }
        let patternLength = cryptBlocks + skipBlocks
        let blocks = (0 ..< blockCount).filter { $0 % patternLength < cryptBlocks }
        return encryptChain(data, blocks: blocks)
    }

    /// Encrypts the 16-byte blocks at `blocks` (indexes into `data`) as one AES-128-CBC chain from the constant IV,
    /// leaving every other byte as it is.
    private func encryptChain(_ data: Data, blocks: [Int]) -> Data {
        guard !blocks.isEmpty else { return data }
        var bytes = [UInt8](data)
        let plain = blocks.flatMap { bytes[$0 * 16 ..< $0 * 16 + 16] }
        var cipher = [UInt8](repeating: 0, count: plain.count)
        var moved = 0
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(0),
                        keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                        plain, plain.count, &cipher, cipher.count, &moved)
            }
        }
        // Never fall back to the clear bytes: they would be written as protected.
        precondition(status == kCCSuccess && moved == plain.count, "AES-128-CBC encryption failed: \(status)")
        for (index, block) in blocks.enumerated() {
            bytes.replaceSubrange(block * 16 ..< block * 16 + 16, with: cipher[index * 16 ..< index * 16 + 16])
        }
        return Data(bytes)
    }

    // MARK: - Audio Encryption

    /// Encrypt audio sample (whole-block full-sample encryption, no pattern)
    ///
    /// ISO/IEC 23001-7 `cbcs` protects tracks other than video this way, so the sample has no subsamples: a player
    /// decrypts every complete block of it as one chain.
    /// - Parameter sample: Raw audio sample data
    /// - Returns: Encrypted data, and no subsamples
    public func encryptAudioSample(_ sample: Data) -> EncryptionResult {
        EncryptionResult(encryptedData: encryptFullSample(sample), subsamples: [])
    }

    /// Encrypt entire sample with AES-128-CBC (for audio): every complete block, one chain from the constant IV.
    /// A trailing partial block stays clear (CBCS doesn't pad).
    private func encryptFullSample(_ data: Data) -> Data {
        encryptChain(data, blocks: Array(0 ..< data.count / 16))
    }

    // MARK: - NAL Parsing

    /// Parse NAL units from length-prefixed sample (ISO/IEC 14496-15 supports 1, 2, or 4 byte lengths).
    /// - Throws: `Failure.malformedSample` for invalid `lengthSize`, 0-length NALs, or truncated/trailing bytes.
    private func parseNALUnits(_ bytes: [UInt8], lengthSize: Int) throws -> [NALUnit] {
        guard lengthSize == 1 || lengthSize == 2 || lengthSize == 4 else {
            throw Failure.malformedSample
        }

        var nalUnits: [NALUnit] = []
        var offset = 0

        while offset < bytes.count {
            guard offset + lengthSize <= bytes.count else {
                throw Failure.malformedSample
            }

            let length: Int
            switch lengthSize {
            case 1:
                length = Int(bytes[offset])
            case 2:
                length = (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
            case 4:
                let raw = (UInt32(bytes[offset]) << 24)
                    | (UInt32(bytes[offset + 1]) << 16)
                    | (UInt32(bytes[offset + 2]) << 8)
                    | UInt32(bytes[offset + 3])
                guard let exact = Int(exactly: raw) else {
                    throw Failure.malformedSample
                }
                length = exact
            default:
                throw Failure.malformedSample
            }

            // A valid NAL unit must contain at least its 1-byte NAL header
            guard length > 0, length <= bytes.count - (offset + lengthSize) else {
                throw Failure.malformedSample
            }

            let totalLength = lengthSize + length
            let nalHeaderOffset = offset + lengthSize
            let nalType = parseNALType(bytes[nalHeaderOffset])

            nalUnits.append(NALUnit(
                type: nalType,
                offset: offset,
                length: totalLength,
                isSlice: isSliceNAL(nalType)
            ))

            offset += totalLength
        }

        guard offset == bytes.count else { throw Failure.malformedSample }
        return nalUnits
    }

    /// Parse H.264 NAL unit type
    private func parseNALType(_ header: UInt8) -> UInt8 {
        header & 0x1F // Lower 5 bits for H.264
    }

    /// Check if NAL unit is a slice (VCL NAL)
    private func isSliceNAL(_ type: UInt8) -> Bool {
        // H.264 slice NAL types: 1-5
        switch type {
        case 1...5: return true  // H.264 coded slice
        case 19: return true     // H.264 coded slice of IDR
        case 20: return true     // H.264 coded slice extension
        default: return false
        }
    }
}

// MARK: - Key Derivation

extension CBCSEncryptor {
    /// Derive a 16-byte AES-128 content key from `keyID` and `masterKey` using HKDF-SHA256.
    public static func deriveKey(from keyID: Data, using masterKey: Data) -> Data {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(masterKey)),
            salt: Data(keyID),
            info: Data("arkavo-cbcs-key-v1".utf8),
            outputByteCount: 16
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    /// A 16-byte AES-128 content key from the system's cryptographically secure random source.
    /// - Throws: `Failure.randomBytesUnavailable` when the source fails, rather than return a key it did not fill.
    public static func generateContentKey() throws -> Data {
        try generateContentKey { count, bytes in SecRandomCopyBytes(kSecRandomDefault, count, bytes) }
    }

    /// A content key from `random`, which fills its count of bytes and returns a status (`errSecSuccess` on success).
    static func generateContentKey(random: (Int, UnsafeMutableRawPointer) -> OSStatus) throws -> Data {
        try randomBytes(16, from: random)
    }

    /// The package's constant IV: 16 bytes from the system's random source. Every sample's CBC chain starts from it.
    /// - Throws: `Failure.randomBytesUnavailable` when the random source fails: there is no IV, never an unfilled one.
    static func generateConstantIV() throws -> Data {
        try generateConstantIV { count, bytes in SecRandomCopyBytes(kSecRandomDefault, count, bytes) }
    }

    /// A constant IV from `random`, which fills its count of bytes and returns a status (`errSecSuccess` on success).
    static func generateConstantIV(random: (Int, UnsafeMutableRawPointer) -> OSStatus) throws -> Data {
        try randomBytes(16, from: random)
    }

    /// `count` bytes from `random`, or `Failure.randomBytesUnavailable` with its status.
    private static func randomBytes(_ count: Int, from random: (Int, UnsafeMutableRawPointer) -> OSStatus) throws
        -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { random($0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw Failure.randomBytesUnavailable(status) }
        return bytes
    }

    /// Generate random key ID (fails closed via precondition if the CSPRNG fails).
    public static func generateKeyID() -> Data {
        var keyID = Data(count: 16)
        let status = keyID.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed while generating key ID: \(status)")
        return keyID
    }

    /// Generate random IV (fails closed via precondition if the CSPRNG fails).
    /// `FMP4RecordingProtectionService` uses the throwing `generateConstantIV()`.
    public static func generateIV() -> Data {
        var iv = Data(count: 16)
        let status = iv.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed while generating IV: \(status)")
        return iv
    }
}

extension CBCSEncryptor.Failure: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformedSample:
            "A video sample's NAL unit lengths do not match its size."
        case let .randomBytesUnavailable(status):
            "The system's random source failed (status \(status))."
        case let .invalidPattern(cryptBlocks, skipBlocks):
            "Invalid CBCS pattern \(cryptBlocks):\(skipBlocks) (expected 0...15 each, and cryptBlocks=0 only with skipBlocks=0)."
        }
    }
}
