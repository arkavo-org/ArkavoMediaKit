import Foundation

/// Request for accessing a segment decryption key
///
/// Sent to KAS with the Standard TDF manifest to request key unwrapping.
public struct KeyAccessRequest: Sendable {
    /// Session identifier
    public let sessionID: UUID

    /// User identifier
    public let userID: String

    /// Asset identifier
    public let assetID: String

    /// Segment index
    public let segmentIndex: Int

    /// Standard TDF manifest (base64-encoded JSON)
    ///
    /// Contains the wrapped DEK, policy, and encryption parameters.
    /// KAS validates the policy and unwraps the DEK for authorized requests.
    public let tdfManifest: String

    /// Request timestamp
    public let timestamp: Date

    /// Client context (optional metadata)
    public let context: [String: String]

    public init(
        sessionID: UUID,
        userID: String,
        assetID: String,
        segmentIndex: Int,
        tdfManifest: String,
        context: [String: String] = [:]
    ) {
        self.sessionID = sessionID
        self.userID = userID
        self.assetID = assetID
        self.segmentIndex = segmentIndex
        self.tdfManifest = tdfManifest
        self.timestamp = Date()
        self.context = context
    }
}

/// Response containing the wrapped decryption key
public struct KeyAccessResponse: Sendable {
    /// Wrapped symmetric key (base64 encoded)
    ///
    /// For Standard TDF, this is the RSA-wrapped DEK that can be unwrapped
    /// with the client's private key (offline) or via KAS rewrap (online).
    public let wrappedKey: String

    /// Key metadata
    public let metadata: KeyMetadata

    public struct KeyMetadata: Sendable, Codable {
        public let segmentIndex: Int
        public let expiresAt: Date?
        public let latencyMS: Int?

        public init(segmentIndex: Int, expiresAt: Date? = nil, latencyMS: Int? = nil) {
            self.segmentIndex = segmentIndex
            self.expiresAt = expiresAt
            self.latencyMS = latencyMS
        }
    }

    public init(wrappedKey: String, metadata: KeyMetadata) {
        self.wrappedKey = wrappedKey
        self.metadata = metadata
    }
}

extension KeyAccessRequest: Codable {}
extension KeyAccessResponse: Codable {}
