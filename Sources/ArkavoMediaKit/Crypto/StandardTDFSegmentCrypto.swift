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
        let ciphertext: Data
        let tag: Data?

        switch mode {
        case .gcm:
            let result = try TDFCrypto.encryptPayload(
                plaintext: segmentData,
                symmetricKey: symmetricKey
            )
            iv = result.iv
            ciphertext = result.cipherText
            tag = result.authenticationTag
        case .cbc:
            let result = try TDFCrypto.encryptPayloadCBC(
                plaintext: segmentData,
                symmetricKey: symmetricKey
            )
            iv = result.iv
            ciphertext = result.cipherText
            tag = nil // CBC doesn't produce an authentication tag
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

        // Build manifest with algorithm based on key size and mode
        let manifest = try buildManifest(
            wrappedKey: wrappedKey,
            iv: iv,
            tag: tag,
            policyBinding: policyBinding,
            payloadSize: ciphertext.count,
            assetID: assetID,
            segmentIndex: segmentIndex
        )

        // Create TDF archive (ZIP)
        let tdfData = try createTDFArchive(
            manifest: manifest,
            encryptedPayload: ciphertext
        )

        return (tdfData, symmetricKey)
    }

    /// Decrypt a Standard TDF segment
    ///
    /// - Parameters:
    ///   - tdfData: Standard TDF archive data
    ///   - symmetricKey: Symmetric key for decryption (from KAS or offline cache)
    /// - Returns: Decrypted segment data
    /// - Throws: StandardTDFDecryptionError if decryption fails
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

        // Extract IV from manifest method
        guard let iv = Data(base64Encoded: method.iv) else {
            throw StandardTDFSegmentError.missingEncryptionParameters
        }

        // Decrypt based on algorithm
        if algorithm.contains("GCM") {
            // GCM mode - tag is appended to ciphertext (last 16 bytes)
            let tagLength = 16
            guard encryptedPayload.count >= tagLength else {
                throw StandardTDFSegmentError.invalidPayloadSize
            }

            let ciphertext = encryptedPayload.dropLast(tagLength)
            let tag = encryptedPayload.suffix(tagLength)

            return try TDFCrypto.decryptPayload(
                ciphertext: Data(ciphertext),
                iv: iv,
                tag: Data(tag),
                symmetricKey: symmetricKey
            )
        } else if algorithm.contains("CBC") {
            // CBC mode - no tag, ciphertext is the entire payload
            return try TDFCrypto.decryptPayloadCBC(
                ciphertext: encryptedPayload,
                iv: iv,
                symmetricKey: symmetricKey
            )
        } else {
            throw StandardTDFSegmentError.unsupportedEncryptionMethod
        }
    }

    // MARK: - Private Helpers

    private func buildManifest(
        wrappedKey: String,
        iv: Data,
        tag: Data?,
        policyBinding: TDFPolicyBinding,
        payloadSize: Int,
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

        // Create integrity information
        // For GCM, include tag size in segment size; for CBC, no tag
        let tagSize = tag?.count ?? 0
        let rootSignature = TDFRootSignature(
            alg: "HS256",
            sig: iv.base64EncodedString() // Store IV here for segment decryption
        )
        let segmentHashAlg = mode == .gcm ? "GMAC" : "HS256"
        let integrityInfo = TDFIntegrityInformation(
            rootSignature: rootSignature,
            segmentHashAlg: segmentHashAlg,
            segmentSizeDefault: Int64(payloadSize + tagSize),
            encryptedSegmentSizeDefault: Int64(payloadSize + tagSize),
            segments: []
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
        // Create ZIP archive with manifest and payload using OpenTDFKit's writer
        let writer = TDFArchiveWriter(compressionMethod: .deflate)
        return try writer.buildArchive(manifest: manifest, payload: encryptedPayload)
    }
}

/// Standard TDF segment errors
public enum StandardTDFSegmentError: Error, LocalizedError {
    case unsupportedEncryptionMethod
    case missingEncryptionParameters
    case invalidPayloadSize
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
        case .manifestCreationFailed:
            "Failed to create TDF manifest"
        case .archiveCreationFailed:
            "Failed to create ZIP archive"
        }
    }
}
