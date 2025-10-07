import CryptoKit
import Foundation
import OpenTDFKit

/// Provides Standard TDF-wrapped keys for media segments
///
/// Manages RSA key pairs and handles key wrapping/unwrapping for HLS segments.
/// Integrates with KAS for policy-based key access via RSA rewrap protocol.
public actor StandardTDFKeyProvider {
    private let kasURL: URL
    private let kasPublicKeyPEM: String
    private let sessionManager: TDF3MediaSession
    private let rsaPrivateKeyPEM: String?

    /// Initialize with KAS configuration
    ///
    /// - Parameters:
    ///   - kasURL: KAS server URL for rewrap requests
    ///   - kasPublicKeyPEM: KAS RSA public key (2048+ bit) for key wrapping
    ///   - sessionManager: Session manager for tracking playback sessions
    ///   - rsaPrivateKeyPEM: Optional RSA private key for offline decryption
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String,
        sessionManager: TDF3MediaSession,
        rsaPrivateKeyPEM: String? = nil
    ) {
        self.kasURL = kasURL
        self.kasPublicKeyPEM = kasPublicKeyPEM
        self.sessionManager = sessionManager
        self.rsaPrivateKeyPEM = rsaPrivateKeyPEM
    }

    /// Request a key for a specific segment from KAS
    ///
    /// Sends the Standard TDF manifest to KAS for policy validation and DEK unwrapping.
    /// KAS validates the policy and returns the wrapped DEK.
    ///
    /// - Parameters:
    ///   - request: Key access request with manifest and session info
    ///   - policy: Media DRM policy to validate
    ///   - deviceInfo: Device security information
    /// - Returns: Key access response with wrapped DEK
    /// - Throws: KeyProviderError if validation or unwrapping fails
    public func requestKey(
        request: KeyAccessRequest,
        policy: MediaDRMPolicy,
        deviceInfo: DeviceInfo
    ) async throws -> KeyAccessResponse {
        let startTime = Date()

        // Validate session exists and is active
        let session = try await sessionManager.getSession(sessionID: request.sessionID)

        // Get current active stream count for concurrency check
        let activeStreams = await sessionManager.getActiveStreamCount(userID: request.userID)

        // Validate policy
        try policy.validate(
            session: session,
            firstPlayTimestamp: session.firstPlayTimestamp,
            currentActiveStreams: activeStreams,
            deviceInfo: deviceInfo
        )

        // Parse TDF manifest from request
        guard let manifestData = Data(base64Encoded: request.tdfManifest) else {
            throw KeyProviderError.invalidTDFManifest
        }

        let manifest = try JSONDecoder().decode(TDFManifest.self, from: manifestData)

        // Extract wrapped key from manifest (encryptionInformation is non-optional)
        let encInfo = manifest.encryptionInformation
        guard let keyAccess = encInfo.keyAccess.first else {
            throw KeyProviderError.missingWrappedKey
        }
        let wrappedKey = keyAccess.wrappedKey

        // For now, return the wrapped key as-is
        // In production, would send to KAS for rewrap with user's ephemeral public key
        // KAS flow: manifest + ephemeral_pubkey → KAS validates policy → rewraps DEK → returns
        let wrappedKeyData = Data(wrappedKey.utf8).base64EncodedString()

        // Calculate latency
        let latencyMS = Int(Date().timeIntervalSince(startTime) * 1000)

        // Update session heartbeat
        try await sessionManager.updateHeartbeat(
            sessionID: request.sessionID,
            state: .playing
        )

        return KeyAccessResponse(
            wrappedKey: wrappedKeyData,
            metadata: .init(
                segmentIndex: request.segmentIndex,
                expiresAt: nil,
                latencyMS: latencyMS
            )
        )
    }

    /// Generate and wrap a new segment key
    ///
    /// Creates a symmetric key and wraps it with KAS RSA public key.
    ///
    /// - Parameters:
    ///   - assetID: Asset identifier
    ///   - segmentIndex: Segment index
    ///   - policy: Media DRM policy
    ///   - policyJSON: Standard TDF policy JSON
    /// - Returns: TDF archive data and symmetric key
    /// - Throws: KeyProviderError if wrapping fails
    public func generateWrappedSegmentKey(
        assetID: String,
        segmentIndex: Int,
        policy: MediaDRMPolicy,
        policyJSON: Data
    ) async throws -> (tdfArchive: Data, symmetricKey: SymmetricKey) {
        // Validate asset ID
        try InputValidator.validateAssetID(assetID)

        // Generate symmetric key for manifest
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()

        // Wrap the key
        let wrappedKey = try StandardTDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: kasPublicKeyPEM,
            symmetricKey: symmetricKey
        )

        // Create minimal TDF manifest with wrapped key
        let policyBinding = StandardTDFCrypto.policyBinding(
            policy: policyJSON,
            symmetricKey: symmetricKey
        )

        let keyAccessObj = TDFKeyAccessObject(
            type: .wrapped,
            url: kasURL.absoluteString,
            protocolValue: .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: try buildMetadata(assetID: assetID, segmentIndex: segmentIndex),
            kid: nil,
            sid: nil,
            schemaVersion: nil,
            ephemeralPublicKey: nil
        )

        // Create minimal integrity information
        let rootSig = TDFRootSignature(alg: "HS256", sig: "")
        let integrityInfo = TDFIntegrityInformation(
            rootSignature: rootSig,
            segmentHashAlg: "GMAC",
            segmentSizeDefault: 0,
            encryptedSegmentSizeDefault: nil,
            segments: []
        )

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: Data(count: 12).base64EncodedString(), // Placeholder IV
            isStreamable: true
        )

        let encInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [keyAccessObj],
            method: method,
            integrityInformation: integrityInfo,
            policy: try StandardTDFPolicy(json: policyJSON).base64String
        )

        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: "video/mp2t"
        )

        let manifest = TDFManifest(
            schemaVersion: "1.0.0",
            payload: payloadDescriptor,
            encryptionInformation: encInfo,
            assertions: nil
        )

        let manifestData = try JSONEncoder().encode(manifest)

        return (manifestData, symmetricKey)
    }

    /// Unwrap a segment key from Standard TDF manifest
    ///
    /// Unwraps the DEK using either RSA private key (offline) or KAS rewrap (online).
    ///
    /// - Parameters:
    ///   - tdfData: Standard TDF archive data
    ///   - useKASRewrap: Whether to use KAS rewrap (true) or local RSA key (false)
    /// - Returns: Unwrapped symmetric key
    /// - Throws: KeyProviderError if unwrapping fails
    public func unwrapSegmentKey(
        tdfData: Data,
        useKASRewrap: Bool = true
    ) async throws -> SymmetricKey {
        // Parse TDF archive
        let reader = try TDFArchiveReader(data: tdfData)
        let manifest = try reader.manifest()

        // Extract wrapped key (encryptionInformation is non-optional)
        let encInfo = manifest.encryptionInformation
        guard let keyAccess = encInfo.keyAccess.first else {
            throw KeyProviderError.missingWrappedKey
        }
        let wrappedKey = keyAccess.wrappedKey

        if useKASRewrap {
            // TODO: Implement KAS rewrap protocol
            // 1. Generate ephemeral RSA key pair
            // 2. Send manifest + ephemeral public key to KAS
            // 3. KAS validates policy and rewraps DEK with ephemeral key
            // 4. Decrypt rewrapped DEK with ephemeral private key
            throw KeyProviderError.kasRewrapNotImplemented
        } else {
            // Offline decryption with local RSA private key
            guard let privateKeyPEM = rsaPrivateKeyPEM else {
                throw KeyProviderError.noPrivateKey
            }

            return try StandardTDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: privateKeyPEM,
                wrappedKey: wrappedKey
            )
        }
    }

    // MARK: - Private Helpers

    private func buildMetadata(assetID: String, segmentIndex: Int) throws -> String {
        let metadata: [String: Any] = [
            "asset_id": assetID,
            "segment_index": segmentIndex,
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: metadata)
        return jsonData.base64EncodedString()
    }
}

/// Key provider errors
public enum KeyProviderError: Error, LocalizedError {
    case invalidTDFManifest
    case missingWrappedKey
    case keyDerivationFailed
    case policyValidationFailed(String)
    case sessionInvalid
    case kasRewrapNotImplemented
    case noPrivateKey

    public var errorDescription: String? {
        switch self {
        case .invalidTDFManifest:
            "Invalid Standard TDF manifest"
        case .missingWrappedKey:
            "Wrapped key not found in manifest"
        case .keyDerivationFailed:
            "Failed to derive segment key"
        case let .policyValidationFailed(reason):
            "Policy validation failed: \(reason)"
        case .sessionInvalid:
            "Invalid or expired session"
        case .kasRewrapNotImplemented:
            "KAS rewrap protocol not yet implemented - use offline decryption"
        case .noPrivateKey:
            "No RSA private key available for offline decryption"
        }
    }
}
