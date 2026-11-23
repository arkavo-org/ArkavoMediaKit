import CryptoKit
import Foundation
import OpenTDFKit

/// Standard TDF encryption for HLS video segments
///
/// Uses OpenTDFKit's TDFCrypto for large video segments (2-10MB).
/// Standard TDF is the correct format for HLS segments, providing:
/// - ZIP-based container with manifest.json + encrypted payload
/// - RSA-2048+ key wrapping (vs EC for NanoTDF)
/// - ~1.1KB overhead (negligible for multi-MB segments)
/// - Industry-standard format with cross-platform compatibility
///
/// Supports both GCM (authenticated, default) and CBC (FairPlay compatible) modes.
public actor StandardTDFSegmentCrypto {
    private let kasInfo: TDFKasInfo
    private let policy: TDFPolicy
    private let mimeType: String
    private let keySize: TDFKeySize
    private let mode: TDFEncryptionMode

    /// Initialize with KAS configuration and policy
    ///
    /// - Parameters:
    ///   - kasURL: KAS server URL for key wrapping/rewrap
    ///   - kasPublicKeyPEM: RSA public key (minimum 2048-bit)
    ///   - policyJSON: Standard TDF policy JSON with uuid and body
    ///   - mimeType: MIME type for segments (default: video/mp2t for MPEG-TS)
    ///   - keySize: Key size (default: .bits256 for AES-256)
    ///   - mode: Encryption mode (default: .gcm for authenticated encryption)
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String,
        policyJSON: Data,
        mimeType: String = "video/mp2t",
        keySize: TDFKeySize = .bits256,
        mode: TDFEncryptionMode = .gcm
    ) throws {
        kasInfo = TDFKasInfo(url: kasURL, publicKeyPEM: kasPublicKeyPEM)
        policy = try TDFPolicy(json: policyJSON)
        self.mimeType = mimeType
        self.keySize = keySize
        self.mode = mode
    }

    /// Encrypt a video segment to Standard TDF format
    ///
    /// Creates a .tdf ZIP archive containing:
    /// - 0.manifest.json: Wrapped DEK, policy, KAS info
    /// - 0.payload: Encrypted segment data (GCM or CBC based on mode)
    ///
    /// - Parameters:
    ///   - segmentData: Raw video segment data (2-10MB typical)
    ///   - segmentIndex: Segment index for tracking
    ///   - assetID: Asset identifier for policy binding
    /// - Returns: TDF archive data and symmetric key (for optional offline playback)
    /// - Throws: StandardTDFEncryptionError if encryption fails
    public func encryptSegment(
        segmentData: Data,
        segmentIndex: Int,
        assetID: String
    ) async throws -> (tdfData: Data, symmetricKey: SymmetricKey) {
        // Validate inputs
        try InputValidator.validateAssetID(assetID)

        // Generate symmetric key for segment with configured key size
        let symmetricKey = try TDFCrypto.generateSymmetricKey(size: keySize)

        // Encrypt payload based on mode
        let iv: Data
        let encryptedPayload: Data
        let segmentSignatureBytes: Data

        switch mode {
        case .gcm:
            let result = try TDFCrypto.encryptPayload(
                plaintext: segmentData,
                symmetricKey: symmetricKey
            )
            iv = result.iv
            // Append the 16-byte GCM authentication tag to ciphertext in a fresh 0-indexed Data buffer
            // (AES.GCM.SealedBox.ciphertext is a Data slice with non-zero startIndex, which would trap in TDFArchiveWriter)
            var combined = Data(capacity: result.cipherText.count + result.authenticationTag.count)
            combined.append(result.cipherText)
            combined.append(result.authenticationTag)
            encryptedPayload = combined
            segmentSignatureBytes = result.authenticationTag
        case .cbc:
            let result = try TDFCrypto.encryptPayloadCBC(
                plaintext: segmentData,
                symmetricKey: symmetricKey
            )
            iv = result.iv
            encryptedPayload = result.cipherText
            segmentSignatureBytes = TDFCrypto.segmentSignature(
                segmentCiphertext: encryptedPayload,
                symmetricKey: symmetricKey
            )
        }

        // Wrap symmetric key with KAS RSA public key
        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: kasInfo.publicKeyPEM,
            symmetricKey: symmetricKey
        )

        // Create policy binding (HMAC-SHA256 of policy with symmetric key)
        let policyBinding = TDFCrypto.policyBinding(
            policy: policy.json,
            symmetricKey: symmetricKey
        )

        // Build manifest with authentic segment & root integrity metadata
        let manifest = try buildManifest(
            wrappedKey: wrappedKey,
            symmetricKey: symmetricKey,
            iv: iv,
            segmentSignature: segmentSignatureBytes,
            policyBinding: policyBinding,
            plaintextSize: segmentData.count,
            encryptedPayloadSize: encryptedPayload.count,
            assetID: assetID,
            segmentIndex: segmentIndex
        )

        // Create TDF archive (ZIP)
        let tdfData = try createTDFArchive(
            manifest: manifest,
            encryptedPayload: encryptedPayload
        )

        return (tdfData, symmetricKey)
    }

    /// Decrypt a Standard TDF segment
    ///
    /// - Parameters:
    ///   - tdfData: Standard TDF archive data
    ///   - symmetricKey: Symmetric key for decryption (from KAS or offline cache)
    /// - Returns: Decrypted segment data
    /// - Throws: StandardTDFSegmentError if decryption, policy binding, or integrity verification fails
    public func decryptSegment(
        tdfData: Data,
        symmetricKey: SymmetricKey
    ) async throws -> Data {
        // Parse TDF archive
        let reader = try TDFArchiveReader(data: tdfData)
        let manifest = try reader.manifest()

        // Extract payload
        let encryptedPayload = try reader.payloadData()

        // Get encryption info from manifest
        let encInfo = manifest.encryptionInformation
        let method = encInfo.method
        let algorithm = method.algorithm

        // Always require and verify policy binding against the symmetric key (fail closed if policy is stripped).
        // Accepts both the OpenTDF 5.0 spec form Base64(raw 32B HMAC) and the legacy hex form Base64(utf8(hex(HMAC))).
        guard !encInfo.policy.isEmpty,
              let keyAccess = encInfo.keyAccess.first,
              keyAccess.policyBinding.alg == "HS256",
              let actualBinding = Data(base64Encoded: keyAccess.policyBinding.hash),
              Self.verifyPolicyBinding(
                  actual: actualBinding,
                  policyBase64: encInfo.policy,
                  symmetricKey: symmetricKey
              )
        else {
            throw StandardTDFSegmentError.integrityVerificationFailed
        }

        // Strict algorithm allowlist; refuse downgrade from configured GCM mode to unauthenticated CBC
        let isGCM: Bool
        switch algorithm {
        case "AES-128-GCM", "AES-256-GCM":
            isGCM = true
        case "AES-128-CBC", "AES-256-CBC":
            guard mode == .cbc else {
                throw StandardTDFSegmentError.unsupportedEncryptionMethod
            }
            isGCM = false
        default:
            throw StandardTDFSegmentError.unsupportedEncryptionMethod
        }

        // Extract IV from manifest method
        guard let iv = Data(base64Encoded: method.iv) else {
            throw StandardTDFSegmentError.missingEncryptionParameters
        }

        // Decrypt based on verified algorithm
        if isGCM {
            guard iv.count == 12 else {
                throw StandardTDFSegmentError.missingEncryptionParameters
            }
            // GCM mode - tag is appended to ciphertext (last 16 bytes)
            let tagLength = 16
            guard encryptedPayload.count >= tagLength else {
                throw StandardTDFSegmentError.invalidPayloadSize
            }

            let ciphertext = Data(encryptedPayload.dropLast(tagLength))
            let tag = Data(encryptedPayload.suffix(tagLength))

            // Verify integrity metadata when present
            if let integrity = encInfo.integrityInformation, !integrity.segments.isEmpty {
                try Self.verifyIntegrity(
                    integrity: integrity,
                    segmentSignature: tag,
                    encryptedSize: encryptedPayload.count,
                    symmetricKey: symmetricKey
                )
            }

            return try TDFCrypto.decryptPayload(
                ciphertext: ciphertext,
                iv: iv,
                tag: tag,
                symmetricKey: symmetricKey
            )
        } else {
            guard iv.count == 16 else {
                throw StandardTDFSegmentError.missingEncryptionParameters
            }
            // CBC mode is unauthenticated at the cipher layer: require authentic integrity metadata (fail closed if stripped)
            guard let integrity = encInfo.integrityInformation, !integrity.segments.isEmpty else {
                throw StandardTDFSegmentError.integrityVerificationFailed
            }
            let computedSig = TDFCrypto.segmentSignature(
                segmentCiphertext: encryptedPayload,
                symmetricKey: symmetricKey
            )
            try Self.verifyIntegrity(
                integrity: integrity,
                segmentSignature: computedSig,
                encryptedSize: encryptedPayload.count,
                symmetricKey: symmetricKey
            )

            // CBC mode - no tag, ciphertext is the entire payload
            return try TDFCrypto.decryptPayloadCBC(
                ciphertext: encryptedPayload,
                iv: iv,
                symmetricKey: symmetricKey
            )
        }
    }

    // MARK: - Private Helpers

    private static func verifyIntegrity(
        integrity: TDFIntegrityInformation,
        segmentSignature: Data,
        encryptedSize: Int,
        symmetricKey: SymmetricKey
    ) throws {
        guard integrity.segments.count == 1,
              let segment = integrity.segments.first,
              let expectedSegmentHash = Data(base64Encoded: segment.hash),
              constantTimeEquals(expectedSegmentHash, segmentSignature)
        else {
            throw StandardTDFSegmentError.integrityVerificationFailed
        }
        if let declaredEncryptedSize = segment.encryptedSegmentSize,
           declaredEncryptedSize != Int64(encryptedSize)
        {
            throw StandardTDFSegmentError.integrityVerificationFailed
        }
        guard integrity.rootSignature.alg == "HS256",
              let actualRootSig = Data(base64Encoded: integrity.rootSignature.sig)
        else {
            throw StandardTDFSegmentError.integrityVerificationFailed
        }
        let expectedRootSig = Data(HMAC<SHA256>.authenticationCode(
            for: segmentSignature,
            using: symmetricKey
        ))
        guard constantTimeEquals(actualRootSig, expectedRootSig) else {
            throw StandardTDFSegmentError.integrityVerificationFailed
        }
    }

    static func verifyPolicyBinding(
        actual: Data,
        policyBase64: String,
        symmetricKey: SymmetricKey
    ) -> Bool {
        let rawDigest = Data(HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8),
            using: symmetricKey
        ))
        if constantTimeEquals(actual, rawDigest) {
            return true
        }
        // Legacy Go/OpenTDFKit <= 4 form: base64(utf8(lowercase hex(digest)))
        let hexDigest = Data(rawDigest.map { String(format: "%02x", $0) }.joined().utf8)
        return constantTimeEquals(actual, hexDigest)
    }

    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    private func buildManifest(
        wrappedKey: String,
        symmetricKey: SymmetricKey,
        iv: Data,
        segmentSignature: Data,
        policyBinding: TDFPolicyBinding,
        plaintextSize: Int,
        encryptedPayloadSize: Int,
        assetID: String,
        segmentIndex: Int
    ) throws -> TDFManifest {
        // Create key access object
        let keyAccess = TDFKeyAccessObject(
            type: .wrapped,
            url: kasInfo.url.absoluteString,
            protocolValue: .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: try buildEncryptedMetadata(assetID: assetID, segmentIndex: segmentIndex),
            kid: nil,
            sid: nil,
            schemaVersion: nil,
            ephemeralPublicKey: nil
        )

        // Create encryption method with algorithm based on key size and mode
        let algorithmString = keySize.algorithm(mode: mode)
        let method = TDFMethodDescriptor(
            algorithm: algorithmString,
            iv: iv.base64EncodedString(),
            isStreamable: true
        )

        // Create authentic OpenTDF integrity information:
        // segment hash = raw GMAC (GCM tag) or HS256 digest; rootSignature = HMAC-SHA256(DEK, segmentHash)
        let rootSigBase64 = TDFCrypto.rootSignatureBase64(
            rawSegmentSignatures: [segmentSignature],
            symmetricKey: symmetricKey
        )
        let rootSignature = TDFRootSignature(
            alg: "HS256",
            sig: rootSigBase64
        )
        let segmentHashAlg = mode == .gcm ? "GMAC" : "HS256"
        let segment = TDFSegment(
            hash: segmentSignature.base64EncodedString(),
            segmentSize: Int64(plaintextSize),
            encryptedSegmentSize: Int64(encryptedPayloadSize)
        )
        let integrityInfo = TDFIntegrityInformation(
            rootSignature: rootSignature,
            segmentHashAlg: segmentHashAlg,
            segmentSizeDefault: Int64(plaintextSize),
            encryptedSegmentSizeDefault: Int64(encryptedPayloadSize),
            segments: [segment]
        )

        // Create encryption information
        let encInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [keyAccess],
            method: method,
            integrityInformation: integrityInfo,
            policy: policy.base64String
        )

        // Create payload descriptor
        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: mimeType
        )

        return TDFManifest(
            schemaVersion: "1.0.0",
            payload: payloadDescriptor,
            encryptionInformation: encInfo,
            assertions: nil
        )
    }

    private func buildEncryptedMetadata(assetID: String, segmentIndex: Int) throws -> String {
        // Metadata contains segment-specific info
        let metadata: [String: Any] = [
            "asset_id": assetID,
            "segment_index": segmentIndex,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: metadata)
        return jsonData.base64EncodedString()
    }

    private func createTDFArchive(
        manifest: TDFManifest,
        encryptedPayload: Data
    ) throws -> Data {
        // Normalize slice startIndex to 0 before handing to OpenTDFKit's TDFArchiveWriter
        let payload = encryptedPayload.startIndex == 0 ? encryptedPayload : Data(encryptedPayload)
        // Create ZIP archive with manifest and payload using OpenTDFKit's writer
        let writer = TDFArchiveWriter(compressionMethod: .deflate)
        return try writer.buildArchive(manifest: manifest, payload: payload)
    }
}

/// Standard TDF segment errors
public enum StandardTDFSegmentError: Error, LocalizedError, Equatable, Sendable {
    case unsupportedEncryptionMethod
    case missingEncryptionParameters
    case invalidPayloadSize
    case integrityVerificationFailed
    case manifestCreationFailed
    case archiveCreationFailed

    public var errorDescription: String? {
        switch self {
        case .unsupportedEncryptionMethod:
            "Unsupported encryption method (supported: AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC)"
        case .missingEncryptionParameters:
            "Missing IV in manifest"
        case .invalidPayloadSize:
            "Payload too small to contain authentication tag"
        case .integrityVerificationFailed:
            "Segment integrity or policy binding verification failed"
        case .manifestCreationFailed:
            "Failed to create TDF manifest"
        case .archiveCreationFailed:
            "Failed to create ZIP archive"
        }
    }
}
