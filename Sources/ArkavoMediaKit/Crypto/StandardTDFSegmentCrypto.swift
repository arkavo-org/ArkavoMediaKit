import CryptoKit
import Foundation
import OpenTDFKit

/// Standard TDF encryption for HLS video segments
///
/// Uses OpenTDFKit's StandardTDFEncryptor/Decryptor for large video segments (2-10MB).
/// Standard TDF is the correct format for HLS segments, providing:
/// - ZIP-based container with manifest.json + encrypted payload
/// - RSA-2048+ key wrapping (vs EC for NanoTDF)
/// - ~1.1KB overhead (negligible for multi-MB segments)
/// - Industry-standard format with cross-platform compatibility
public actor StandardTDFSegmentCrypto {
    private let kasInfo: StandardTDFKasInfo
    private let policy: StandardTDFPolicy
    private let mimeType: String

    /// Initialize with KAS configuration and policy
    ///
    /// - Parameters:
    ///   - kasURL: KAS server URL for key wrapping/rewrap
    ///   - kasPublicKeyPEM: RSA public key (minimum 2048-bit)
    ///   - policyJSON: Standard TDF policy JSON with uuid and body
    ///   - mimeType: MIME type for segments (default: video/mp2t for MPEG-TS)
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String,
        policyJSON: Data,
        mimeType: String = "video/mp2t"
    ) throws {
        kasInfo = StandardTDFKasInfo(url: kasURL, publicKeyPEM: kasPublicKeyPEM)
        policy = try StandardTDFPolicy(json: policyJSON)
        self.mimeType = mimeType
    }

    /// Encrypt a video segment to Standard TDF format
    ///
    /// Creates a .tdf ZIP archive containing:
    /// - 0.manifest.json: Wrapped DEK, policy, KAS info
    /// - 0.payload: AES-256-GCM encrypted segment data
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

        // Generate symmetric key for segment
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()

        // Encrypt payload
        let (iv, ciphertext, tag) = try StandardTDFCrypto.encryptPayload(
            plaintext: segmentData,
            symmetricKey: symmetricKey
        )

        // Wrap symmetric key with KAS RSA public key
        let wrappedKey = try StandardTDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: kasInfo.publicKeyPEM,
            symmetricKey: symmetricKey
        )

        // Create policy binding (HMAC-SHA256 of policy with symmetric key)
        let policyBinding = StandardTDFCrypto.policyBinding(
            policy: policy.json,
            symmetricKey: symmetricKey
        )

        // Build manifest
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

        // Get encryption info from manifest (these are non-optional in OpenTDFKit)
        let encInfo = manifest.encryptionInformation
        let method = encInfo.method

        guard method.algorithm == "AES-256-GCM" else {
            throw StandardTDFSegmentError.unsupportedEncryptionMethod
        }

        // Extract IV from manifest method
        guard let iv = Data(base64Encoded: method.iv) else {
            throw StandardTDFSegmentError.missingEncryptionParameters
        }

        // Tag is appended to ciphertext (last 16 bytes for AES-GCM-128)
        let tagLength = 16
        guard encryptedPayload.count >= tagLength else {
            throw StandardTDFSegmentError.invalidPayloadSize
        }

        let ciphertext = encryptedPayload.dropLast(tagLength)
        let tag = encryptedPayload.suffix(tagLength)

        // Decrypt payload
        return try StandardTDFCrypto.decryptPayload(
            ciphertext: Data(ciphertext),
            iv: iv,
            tag: Data(tag),
            symmetricKey: symmetricKey
        )
    }

    // MARK: - Private Helpers

    private func buildManifest(
        wrappedKey: String,
        iv: Data,
        tag: Data,
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

        // Create encryption method
        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: iv.base64EncodedString(),
            isStreamable: true
        )

        // Create integrity information (store IV in rootSignature for retrieval)
        let rootSignature = TDFRootSignature(
            alg: "HS256",
            sig: iv.base64EncodedString() // Store IV here for segment decryption
        )
        let integrityInfo = TDFIntegrityInformation(
            rootSignature: rootSignature,
            segmentHashAlg: "GMAC",
            segmentSizeDefault: Int64(payloadSize + tag.count),
            encryptedSegmentSizeDefault: Int64(payloadSize + tag.count),
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
            "Unsupported encryption method (only AES-256-GCM supported)"
        case .missingEncryptionParameters:
            "Missing IV or tag in manifest"
        case .invalidPayloadSize:
            "Payload too small to contain tag"
        case .manifestCreationFailed:
            "Failed to create TDF manifest"
        case .archiveCreationFailed:
            "Failed to create ZIP archive"
        }
    }
}
