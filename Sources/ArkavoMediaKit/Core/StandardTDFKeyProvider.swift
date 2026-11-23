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
    private let authTokenProvider: (@Sendable () async -> String?)?
    private let kasKeyClient: StandardTDFKASKeyClient

    /// Initialize with KAS configuration
    ///
    /// - Parameters:
    ///   - kasURL: KAS server URL for rewrap requests
    ///   - kasPublicKeyPEM: KAS RSA public key (2048+ bit) for key wrapping
    ///   - sessionManager: Session manager for tracking playback sessions
    ///   - rsaPrivateKeyPEM: Optional RSA private key for offline decryption
    ///   - authTokenProvider: Supplies the bearer token sent to the KAS on
    ///     rewrap. Required for `unwrapSegmentKey(useKASRewrap: true)`; a nil
    ///     provider or a nil token throws `KeyProviderError.notAuthenticated`.
    ///   - kasKeyClient: Performs the KAS rewrap; inject one with a stubbed
    ///     `URLSession` in tests.
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String,
        sessionManager: TDF3MediaSession,
        rsaPrivateKeyPEM: String? = nil,
        authTokenProvider: (@Sendable () async -> String?)? = nil,
        kasKeyClient: StandardTDFKASKeyClient? = nil
    ) {
        self.kasURL = kasURL
        self.kasPublicKeyPEM = kasPublicKeyPEM
        self.sessionManager = sessionManager
        self.rsaPrivateKeyPEM = rsaPrivateKeyPEM
        self.authTokenProvider = authTokenProvider
        self.kasKeyClient = kasKeyClient ?? StandardTDFKASKeyClient(allowedKASOrigins: [kasURL.absoluteString])
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

        // Validate session exists, is active, and belongs to this user and asset
        let session = try await sessionManager.getSession(sessionID: request.sessionID)
        guard session.userID == request.userID, session.assetID == request.assetID else {
            throw KeyProviderError.sessionInvalid
        }

        // Get current active stream count for concurrency check
        let activeStreams = await sessionManager.getActiveStreamCount(userID: session.userID)

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
        guard let decodedWrappedKey = Data(base64Encoded: wrappedKey), !decodedWrappedKey.isEmpty else {
            throw KeyProviderError.invalidTDFManifest
        }

        // Calculate latency
        let latencyMS = Int(Date().timeIntervalSince(startTime) * 1000)

        // Update session heartbeat
        try await sessionManager.updateHeartbeat(
            sessionID: request.sessionID,
            state: .playing
        )

        return KeyAccessResponse(
            wrappedKey: wrappedKey,
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
        let symmetricKey = try TDFCrypto.generateSymmetricKey()

        // Wrap the key
        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: kasPublicKeyPEM,
            symmetricKey: symmetricKey
        )

        // Create minimal TDF manifest with wrapped key
        let policyBinding = TDFCrypto.policyBinding(
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

        let randomIV = try TDFCrypto.randomBytes(count: 12)
        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: randomIV.base64EncodedString(),
            isStreamable: true
        )

        let encInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [keyAccessObj],
            method: method,
            integrityInformation: integrityInfo,
            policy: try TDFPolicy(json: policyJSON).base64String
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
    /// - Throws: `KeyProviderError.notAuthenticated` when KAS rewrap is requested
    ///   without a bearer token; `StandardTDFKASKeyClientError`, `KASRewrapError`
    ///   and `KASDiscoveryError` from the rewrap; `KeyProviderError` otherwise.
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
            // Prevent SSRF and OAuth token exfiltration via an untrusted manifest keyAccess.url
            try validateKasURL(keyAccess.url)
            guard let manifestKASURL = URL(string: keyAccess.url),
                  let manifestOrigin = StandardTDFKASKeyClient.origin(of: manifestKASURL),
                  let configuredOrigin = StandardTDFKASKeyClient.origin(of: kasURL),
                  manifestOrigin == configuredOrigin
            else {
                throw StandardTDFKASKeyClientError.untrustedKASOrigin(keyAccess.url)
            }
            guard let authToken = await authTokenProvider?(), !authToken.isEmpty else {
                throw KeyProviderError.notAuthenticated
            }
            return try await kasKeyClient.unwrapKey(manifest: manifest, authToken: authToken)
        } else {
            // Offline decryption with local RSA private key
            guard let privateKeyPEM = rsaPrivateKeyPEM else {
                throw KeyProviderError.noPrivateKey
            }

            let dek = try TDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: privateKeyPEM,
                wrappedKey: wrappedKey
            )

            // Always require and verify policyBinding against the unwrapped DEK to prevent policy substitution/stripping.
            guard !encInfo.policy.isEmpty else {
                throw KeyProviderError.policyValidationFailed("Missing manifest policy")
            }
            guard keyAccess.policyBinding.alg == "HS256" else {
                throw KeyProviderError.policyValidationFailed("Unsupported policyBinding algorithm")
            }
            guard let actual = Data(base64Encoded: keyAccess.policyBinding.hash),
                  StandardTDFSegmentCrypto.verifyPolicyBinding(
                      actual: actual,
                      policyBase64: encInfo.policy,
                      symmetricKey: dek
                  )
            else {
                throw KeyProviderError.policyValidationFailed("Policy binding verification failed")
            }

            return dek
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
public enum KeyProviderError: Error, LocalizedError, Equatable {
    case invalidTDFManifest
    case missingWrappedKey
    case keyDerivationFailed
    case policyValidationFailed(String)
    case sessionInvalid
    /// KAS rewrap was requested but no bearer token is available.
    case notAuthenticated
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
        case .notAuthenticated:
            "Not authenticated - a bearer token is required for KAS rewrap"
        case .noPrivateKey:
            "No RSA private key available for offline decryption"
        }
    }
}
