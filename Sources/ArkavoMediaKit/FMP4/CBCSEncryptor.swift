import CommonCrypto
import Foundation

// MARK: - CBCS Debug Configuration

/// Global configuration for CBCS encryption debugging
public enum CBCSDebugConfig {
    /// Enable verbose debug logging (set to false for production)
    #if DEBUG
    public nonisolated(unsafe) static var isVerboseLoggingEnabled = true
    #else
    public nonisolated(unsafe) static var isVerboseLoggingEnabled = false
    #endif
}

// MARK: - CBCS Encryptor

/// CBCS (Common Encryption Scheme - CBC mode with Subsample encryption) encryptor
/// Implements pattern-based encryption for FairPlay Streaming
public final class CBCSEncryptor {
    // MARK: - Types

    /// Encryption result with subsample map
    public struct EncryptionResult {
        public let encryptedData: Data
        public let subsamples: [SubsampleEntry]
    }

    /// NAL unit information for subsample mapping
    public struct NALUnit {
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
    ///   - cryptBlocks: Number of blocks to encrypt in pattern (default 1)
    ///   - skipBlocks: Number of blocks to skip in pattern (default 9)
    public init(key: Data, iv: Data, cryptBlocks: Int = 1, skipBlocks: Int = 9) {
        precondition(key.count == 16, "Key must be 16 bytes for AES-128")
        precondition(iv.count == 16, "IV must be 16 bytes")

        self.key = key
        self.iv = iv
        self.cryptBlocks = cryptBlocks
        self.skipBlocks = skipBlocks

        // Debug: Log encryption key for verification
        if CBCSDebugConfig.isVerboseLoggingEnabled {
            print("🔐 CBCSEncryptor initialized with key (hex): \(key.map { String(format: "%02x", $0) }.joined())")
            print("🔐 CBCSEncryptor IV (hex): \(iv.map { String(format: "%02x", $0) }.joined())")
        }
    }

    // MARK: - Video Encryption (H.264/H.265)

    /// Encrypt video sample with NAL unit awareness
    /// - Parameters:
    ///   - sample: Raw video sample data (with length-prefixed NAL units)
    ///   - nalLengthSize: Size of NAL unit length field (typically 4)
    /// - Returns: Encrypted data and subsample map
    public func encryptVideoSample(_ sample: Data, nalLengthSize: Int = 4) -> EncryptionResult {
        let nalUnits = parseNALUnits(sample, lengthSize: nalLengthSize)

        var encryptedData = Data()
        var subsamples: [SubsampleEntry] = []

        // Debug: Log NAL structure for first few samples
        if CBCSDebugConfig.isVerboseLoggingEnabled && nalUnits.count > 1 {
            let nalTypes = nalUnits.map { "NAL\($0.type)(\($0.isSlice ? "slice" : "non-slice"):\($0.length)B)" }
            print("🔍 [CBCS] Sample \(sample.count)B has \(nalUnits.count) NALs: \(nalTypes.joined(separator: ", "))")
        }

        for nal in nalUnits {
            let nalData = sample.subdata(in: nal.offset..<(nal.offset + nal.length))

            if nal.isSlice {
                // Encrypt slice NAL units
                let (encrypted, subsample) = encryptNALUnit(nalData, lengthSize: nalLengthSize)
                encryptedData.append(encrypted)
                subsamples.append(subsample)
            } else {
                // Non-slice NAL units (SPS, PPS, SEI, etc.) are kept clear
                encryptedData.append(nalData)
                subsamples.append(SubsampleEntry(
                    bytesOfClearData: UInt16(nal.length),
                    bytesOfProtectedData: 0
                ))
            }
        }

        // Verify total bytes match
        let totalClear = subsamples.reduce(0) { $0 + Int($1.bytesOfClearData) }
        let totalProtected = subsamples.reduce(0) { $0 + Int($1.bytesOfProtectedData) }
        let totalSubsampleBytes = totalClear + totalProtected
        if totalSubsampleBytes != encryptedData.count && CBCSDebugConfig.isVerboseLoggingEnabled {
            print("⚠️ [CBCS] Subsample mismatch: clear=\(totalClear) + protected=\(totalProtected) = \(totalSubsampleBytes), but data=\(encryptedData.count)")
        }

        // NOTE: Do NOT merge subsamples for FairPlay CBCS!
        // FairPlay/CBCS requires each NAL unit to have its own subsample entry.
        // The decoder uses these entries to know exactly which bytes are clear vs encrypted.
        // Reference content (Apple FairPlay SDK) uses 8 subsamples per sample (50 bytes = 2 + 8*6).
        //
        // Merging would create: [164 clear, 99836 protected] - WRONG for FairPlay!
        // Correct is: [28c,0p] [8c,0p] [128c,99836p] etc. - separate entry per NAL

        // Debug: Log subsample structure
        if CBCSDebugConfig.isVerboseLoggingEnabled {
            let subsampleDesc = subsamples.map { "[\($0.bytesOfClearData)c/\($0.bytesOfProtectedData)p]" }.joined(separator: " ")
            print("🔍 [CBCS] Sample \(encryptedData.count)B → \(subsamples.count) subsamples: \(subsampleDesc)")
        }

        return EncryptionResult(encryptedData: encryptedData, subsamples: subsamples)
    }

    /// Encrypt a single NAL unit using CBCS pattern
    private func encryptNALUnit(_ nalData: Data, lengthSize: Int) -> (Data, SubsampleEntry) {
        guard nalData.count > lengthSize else {
            return (nalData, SubsampleEntry(bytesOfClearData: UInt16(nalData.count), bytesOfProtectedData: 0))
        }

        // For CBCS, keep NAL header clear. The slice header can be encrypted.
        // Apple FairPlay reference content uses ~12 bytes clear per NAL:
        // - Length prefix (4 bytes)
        // - NAL unit header (1-2 bytes)
        // - Small safety margin
        let minimumClearBytes = 12

        // NAL header is: length prefix + NAL header byte(s)
        let nalHeaderSize = lengthSize + 1 // For H.264. H.265 uses 2 bytes

        // Use the larger of nalHeaderSize or minimumClearBytes for slice NAL units
        // If the NAL unit is smaller than minimumClearBytes, keep it all clear
        let clearBytes = min(max(nalHeaderSize, minimumClearBytes), nalData.count)

        // Keep NAL header + slice header clear
        let clearPart = nalData.prefix(clearBytes)

        // Payload to encrypt (everything after clear bytes)
        let payload = nalData.dropFirst(clearBytes)

        if payload.isEmpty {
            return (nalData, SubsampleEntry(bytesOfClearData: UInt16(nalData.count), bytesOfProtectedData: 0))
        }

        // Apply pattern encryption to payload
        let encryptedPayload = encryptWithPattern(Data(payload))

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
        result.append(clearPart)
        result.append(encryptedPayload)

        let subsample = SubsampleEntry(
            bytesOfClearData: UInt16(clearBytes),
            bytesOfProtectedData: UInt32(encryptedPayload.count)
        )

        return (result, subsample)
    }

    /// Apply CBCS pattern encryption (encrypt N blocks, skip M blocks)
    private func encryptWithPattern(_ data: Data) -> Data {
        let blockSize = 16
        var result = Data()
        var offset = 0
        let patternLength = cryptBlocks + skipBlocks

        while offset < data.count {
            // Determine position in pattern
            let blockIndex = offset / blockSize
            let patternPosition = blockIndex % patternLength

            let remaining = data.count - offset
            let chunkSize = min(blockSize, remaining)
            let chunk = data.subdata(in: offset..<(offset + chunkSize))

            if patternPosition < cryptBlocks && chunkSize == blockSize {
                // Encrypt this block
                let encrypted = encryptBlock(chunk)
                result.append(encrypted)
            } else {
                // Keep clear (skip block or partial block)
                result.append(chunk)
            }

            offset += chunkSize
        }

        return result
    }

    /// Encrypt a single 16-byte block with AES-128-CBC
    private func encryptBlock(_ block: Data) -> Data {
        precondition(block.count == 16, "Block must be 16 bytes")

        var encrypted = Data(count: 16)
        var numBytesEncrypted: size_t = 0

        let status = encrypted.withUnsafeMutableBytes { encryptedPtr in
            block.withUnsafeBytes { blockPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0), // No padding for single block
                            keyPtr.baseAddress, 16,
                            ivPtr.baseAddress,
                            blockPtr.baseAddress, 16,
                            encryptedPtr.baseAddress, 16,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            // Return original block on error
            return block
        }

        return encrypted
    }

    // MARK: - Audio Encryption

    /// Encrypt audio sample (full encryption, no pattern)
    /// - Parameter sample: Raw audio sample data
    /// - Returns: Encrypted data and subsample map
    public func encryptAudioSample(_ sample: Data) -> EncryptionResult {
        // Audio uses full encryption (all blocks encrypted)
        let encrypted = encryptFullSample(sample)

        let subsample = SubsampleEntry(
            bytesOfClearData: 0,
            bytesOfProtectedData: UInt32(encrypted.count)
        )

        return EncryptionResult(encryptedData: encrypted, subsamples: [subsample])
    }

    /// Encrypt entire sample with AES-128-CBC (for audio)
    private func encryptFullSample(_ data: Data) -> Data {
        let blockSize = 16
        var result = Data()
        var offset = 0

        while offset < data.count {
            let remaining = data.count - offset
            let chunkSize = min(blockSize, remaining)
            let chunk = data.subdata(in: offset..<(offset + chunkSize))

            if chunkSize == blockSize {
                result.append(encryptBlock(chunk))
            } else {
                // Partial block at end - keep clear (CBCS doesn't pad)
                result.append(chunk)
            }

            offset += chunkSize
        }

        return result
    }

    // MARK: - NAL Parsing

    /// Parse NAL units from length-prefixed sample
    private func parseNALUnits(_ data: Data, lengthSize: Int) -> [NALUnit] {
        var nalUnits: [NALUnit] = []
        var offset = 0

        while offset + lengthSize < data.count {
            // Read NAL unit length
            let lengthData = data.subdata(in: offset..<(offset + lengthSize))
            let length: Int
            switch lengthSize {
            case 1: length = Int(lengthData[0])
            case 2: length = Int(UInt16(bigEndianData: lengthData))
            case 4: length = Int(UInt32(bigEndianData: lengthData))
            default: length = Int(UInt32(bigEndianData: lengthData))
            }

            let totalLength = lengthSize + length
            guard offset + totalLength <= data.count else { break }

            // Determine NAL type
            let nalHeaderOffset = offset + lengthSize
            let nalType = parseNALType(data[nalHeaderOffset])

            nalUnits.append(NALUnit(
                type: nalType,
                offset: offset,
                length: totalLength,
                isSlice: isSliceNAL(nalType)
            ))

            offset += totalLength
        }

        return nalUnits
    }

    /// Parse H.264 NAL unit type
    private func parseNALType(_ header: UInt8) -> UInt8 {
        header & 0x1F // Lower 5 bits for H.264
    }

    /// Check if NAL unit is a slice (VCL NAL)
    private func isSliceNAL(_ type: UInt8) -> Bool {
        // H.264 slice NAL types: 1-5
        // H.265 slice NAL types: 0-31 (simplified)
        switch type {
        case 1...5: return true  // H.264 coded slice
        case 19: return true     // H.264 coded slice of IDR
        case 20: return true     // H.264 coded slice extension
        default: return false
        }
    }

    /// Merge consecutive subsamples
    private func mergeSubsamples(_ subsamples: [SubsampleEntry]) -> [SubsampleEntry] {
        guard !subsamples.isEmpty else { return [] }

        var merged: [SubsampleEntry] = []
        var currentClear: UInt16 = 0
        var currentProtected: UInt32 = 0

        for subsample in subsamples {
            if subsample.bytesOfProtectedData == 0 {
                // All clear - accumulate
                currentClear += subsample.bytesOfClearData
            } else if currentProtected == 0 {
                // Starting new protected region
                currentClear += subsample.bytesOfClearData
                currentProtected = subsample.bytesOfProtectedData
            } else {
                // Already have protected - emit current and start new
                merged.append(SubsampleEntry(
                    bytesOfClearData: currentClear,
                    bytesOfProtectedData: currentProtected
                ))
                currentClear = subsample.bytesOfClearData
                currentProtected = subsample.bytesOfProtectedData
            }
        }

        // Emit final subsample
        if currentClear > 0 || currentProtected > 0 {
            merged.append(SubsampleEntry(
                bytesOfClearData: currentClear,
                bytesOfProtectedData: currentProtected
            ))
        }

        return merged
    }
}

// MARK: - Key Derivation

extension CBCSEncryptor {
    /// Derive content key from key ID using HKDF (for testing)
    public static func deriveKey(from keyID: Data, using masterKey: Data) -> Data {
        // Simplified key derivation - in production use proper HKDF
        var derived = Data(count: 16)

        for i in 0..<16 {
            let masterByte: UInt8 = i < masterKey.count ? masterKey[i] : 0
            let keyIDByte: UInt8 = i < keyID.count ? keyID[i] : 0
            derived[i] = masterByte ^ keyIDByte
        }

        return derived
    }

    /// Generate random key ID
    public static func generateKeyID() -> Data {
        var keyID = Data(count: 16)
        _ = keyID.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
        }
        return keyID
    }

    /// Generate random IV
    public static func generateIV() -> Data {
        var iv = Data(count: 16)
        _ = iv.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
        }
        return iv
    }
}
