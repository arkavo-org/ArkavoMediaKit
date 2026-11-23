import Foundation
import Security
import Synchronization

// MARK: - TDF Manifest Builder

/// Builds OpenTDF Standard TDF manifests for FairPlay key delivery
public final class TDFManifestBuilder: Sendable {
    /// Maximum allowed response size for KAS public key fetch (64 KiB)
    private static let maxPublicKeyResponseBytes = 64 * 1024

    // MARK: - Types

    /// TDF Manifest structure matching OpenTDF Standard TDF specification
    public struct Manifest: Codable, Sendable {
        public let encryptionInformation: EncryptionInformation
        public let payload: Payload?

        public init(encryptionInformation: EncryptionInformation, payload: Payload? = nil) {
            self.encryptionInformation = encryptionInformation
            self.payload = payload
        }
    }

    public struct EncryptionInformation: Codable, Sendable {
        public let type: String
        public let keyAccess: [KeyAccess]
        public let method: EncryptionMethod
        public let integrityInformation: IntegrityInformation?
        public let policy: String?

        public init(keyAccess: [KeyAccess],
                    method: EncryptionMethod,
                    integrityInformation: IntegrityInformation? = nil,
                    policy: String? = nil) {
            self.type = "split"
            self.keyAccess = keyAccess
            self.method = method
            self.integrityInformation = integrityInformation
            self.policy = policy
        }
    }

    public struct KeyAccess: Codable, Sendable {
        public let type: String
        public let url: String
        public let `protocol`: String
        public let wrappedKey: String
        public let policyBinding: PolicyBinding?
        public let encryptedMetadata: String?

        public init(url: String,
                    wrappedKey: String,
                    policyBinding: PolicyBinding? = nil,
                    encryptedMetadata: String? = nil) {
            self.type = "wrapped"
            self.url = url
            self.protocol = "kas"
            self.wrappedKey = wrappedKey
            self.policyBinding = policyBinding
            self.encryptedMetadata = encryptedMetadata
        }
    }

    public struct PolicyBinding: Codable, Sendable {
        public let alg: String
        public let hash: String

        public init(alg: String = "HS256", hash: String) {
            self.alg = alg
            self.hash = hash
        }
    }

    public struct EncryptionMethod: Codable, Sendable {
        public let algorithm: String
        public let iv: String
        public let isStreamable: Bool?

        public init(algorithm: String, iv: String, isStreamable: Bool? = nil) {
            self.algorithm = algorithm
            self.iv = iv
            self.isStreamable = isStreamable
        }

        /// AES-128-CBC for FairPlay
        public static func aes128CBC(iv: Data) -> EncryptionMethod {
            EncryptionMethod(
                algorithm: "AES-128-CBC",
                iv: iv.base64EncodedString(),
                isStreamable: true
            )
        }

        /// AES-256-GCM
        public static func aes256GCM(iv: Data) -> EncryptionMethod {
            EncryptionMethod(
                algorithm: "AES-256-GCM",
                iv: iv.base64EncodedString(),
                isStreamable: true
            )
        }
    }

    public struct IntegrityInformation: Codable, Sendable {
        public let rootSignature: RootSignature
        public let segmentHashAlg: String
        public let segments: [Segment]?
        public let encryptedSegmentSizeDefault: Int?

        public init(rootSignature: RootSignature,
                    segmentHashAlg: String = "GMAC",
                    segments: [Segment]? = nil) {
            self.rootSignature = rootSignature
            self.segmentHashAlg = segmentHashAlg
            self.segments = segments
            self.encryptedSegmentSizeDefault = nil
        }
    }

    public struct RootSignature: Codable, Sendable {
        public let alg: String
        public let sig: String

        public init(alg: String = "HS256", sig: String) {
            self.alg = alg
            self.sig = sig
        }
    }

    public struct Segment: Codable, Sendable {
        public let hash: String
        public let segmentSize: Int?
        public let encryptedSegmentSize: Int?
    }

    public struct Payload: Codable, Sendable {
        public let type: String
        public let url: String?
        public let `protocol`: String
        public let mimeType: String?
        public let isEncrypted: Bool

        public init(type: String = "reference",
                    url: String? = nil,
                    mimeType: String? = nil,
                    isEncrypted: Bool = true) {
            self.type = type
            self.url = url
            self.protocol = "zip"
            self.mimeType = mimeType
            self.isEncrypted = isEncrypted
        }
    }

    // MARK: - Properties

    private struct KeyCacheBox: @unchecked Sendable {
        var key: SecKey?
    }

    private let kasURL: URL
    private let urlSession: URLSession?
    private let keyCache = Mutex(KeyCacheBox())

    // MARK: - Initialization

    /// Initialize with KAS URL
    public init(kasURL: URL) {
        self.kasURL = kasURL
        self.urlSession = nil
    }

    /// Internal initializer allowing custom URLSession injection in tests
    init(kasURL: URL, urlSession: URLSession) {
        self.kasURL = kasURL
        self.urlSession = urlSession
    }

    // MARK: - Public Key Fetching

    /// Fetch KAS RSA public key from server (requires HTTPS, refuses redirects)
    public func fetchKASPublicKey() async throws -> SecKey {
        if let existing = keyCache.withLock({ $0.key }) {
            return existing
        }

        guard InputValidator.isAllowedHTTPSOrLoopbackHTTP(kasURL) else {
            throw TDFError.publicKeyFetchFailed
        }

        let url = kasURL.appendingPathComponent("kas/v2/kas_public_key")
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw TDFError.publicKeyFetchFailed
        }
        components.queryItems = [URLQueryItem(name: "algorithm", value: "rsa:2048")]
        guard let requestURL = components.url else {
            throw TDFError.publicKeyFetchFailed
        }

        var request = URLRequest(url: requestURL)
        // KAS advertises `alt-svc: h3`; opt the first hop into HTTP/3 (falls back to HTTP/2).
        request.assumesHTTP3Capable = true
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let session = urlSession ?? URLSession.shared
        let (data, response) = try await session.data(for: request, delegate: RedirectRefusal())

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw TDFError.publicKeyFetchFailed
        }
        guard data.count <= Self.maxPublicKeyResponseBytes else {
            throw TDFError.invalidPublicKeyFormat
        }

        // Parse response - expects PEM or JSON with public key
        let key = try parsePublicKeyResponse(data)
        keyCache.withLock { $0.key = key }
        return key
    }

    private func parsePublicKeyResponse(_ data: Data) throws -> SecKey {
        // Try JSON format first
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let publicKeyPEM = json["public_key"] as? String {
            return try pemToSecKey(publicKeyPEM)
        }

        // Try raw PEM
        if let pemString = String(data: data, encoding: .utf8) {
            return try pemToSecKey(pemString)
        }

        throw TDFError.invalidPublicKeyFormat
    }

    private func pemToSecKey(_ pem: String) throws -> SecKey {
        guard let keyData = Data(base64Encoded: Self.pemBody(pem), options: .ignoreUnknownCharacters) else {
            throw TDFError.invalidPublicKeyFormat
        }

        // Create SecKey from DER data (SPKI or PKCS#1)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            _ = error?.takeRetainedValue()
            throw TDFError.invalidPublicKeyFormat
        }

        // SecKeyCreateWithData takes the size from the key, whatever the attributes say.
        let bits = (SecKeyCopyAttributes(secKey) as? [String: Any])?[kSecAttrKeySizeInBits as String] as? Int
            ?? SecKeyGetBlockSize(secKey) * 8
        guard bits >= 2048 else {
            throw TDFError.weakPublicKey(bits: bits)
        }

        return secKey
    }

    /// The base64 between a `PUBLIC KEY` or `RSA PUBLIC KEY` BEGIN line and its
    /// END line (or the end of the text, when the END line is missing). RFC 7468
    /// lets text surround the block and whitespace sit in the body. Text with
    /// no BEGIN line is taken as bare base64.
    static func pemBody(_ pem: String) -> String {
        guard let begin = pem.range(of: "-----BEGIN ") else { return pem }
        guard let labelEnd = pem.range(of: "-----", range: begin.upperBound ..< pem.endIndex),
              ["PUBLIC KEY", "RSA PUBLIC KEY"].contains(pem[begin.upperBound ..< labelEnd.lowerBound])
        else { return "" }
        let end = pem.range(of: "-----END ", range: labelEnd.upperBound ..< pem.endIndex)?.lowerBound ?? pem.endIndex
        return String(pem[labelEnd.upperBound ..< end])
    }

    /// Parse a KAS RSA public key from PEM (`PUBLIC KEY` or `RSA PUBLIC KEY` armor).
    public func publicKey(fromPEM pem: String) throws -> SecKey {
        try pemToSecKey(pem)
    }

    // MARK: - Key Wrapping

    /// Wrap content key with RSA-OAEP using KAS public key
    public func wrapKey(_ contentKey: Data, with publicKey: SecKey) throws -> Data {
        guard contentKey.count == 16 || contentKey.count == 32 else {
            throw TDFError.invalidKeySize
        }

        // RSA-OAEP with SHA-1 (OpenTDF Standard TDF specification)
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA1

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw TDFError.unsupportedAlgorithm
        }

        var error: Unmanaged<CFError>?
        guard let wrappedData = SecKeyCreateEncryptedData(publicKey, algorithm, contentKey as CFData, &error) else {
            _ = error?.takeRetainedValue()
            throw TDFError.keyWrappingFailed
        }

        return wrappedData as Data
    }

    /// Wrap content key after fetching public key from server
    public func wrapKey(_ contentKey: Data) async throws -> Data {
        let publicKey = try await fetchKASPublicKey()
        return try wrapKey(contentKey, with: publicKey)
    }

    // MARK: - Manifest Building

    /// Build TDF manifest for FairPlay content key delivery
    @available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
    public func buildManifest(contentKey: Data, iv: Data, assetID: String) async throws -> Manifest {
        let wrappedKey = try await wrapKey(contentKey)

        let keyAccess = KeyAccess(
            url: kasURL.absoluteString,
            wrappedKey: wrappedKey.base64EncodedString()
        )

        let method = EncryptionMethod.aes128CBC(iv: iv)

        let encryptionInfo = EncryptionInformation(
            keyAccess: [keyAccess],
            method: method
        )

        return Manifest(encryptionInformation: encryptionInfo)
    }

    /// Build TDF manifest with pre-wrapped key
    @available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
    public func buildManifest(wrappedKey: Data, iv: Data) -> Manifest {
        let keyAccess = KeyAccess(
            url: kasURL.absoluteString,
            wrappedKey: wrappedKey.base64EncodedString()
        )

        let method = EncryptionMethod.aes128CBC(iv: iv)

        let encryptionInfo = EncryptionInformation(
            keyAccess: [keyAccess],
            method: method
        )

        return Manifest(encryptionInformation: encryptionInfo)
    }

    /// Build a FairPlay TDF manifest that the arks license service accepts:
    /// one wrapped key (RSA-OAEP-SHA1) for this KAS, `policy` = base64(policyJSON),
    /// and the spec binding `base64(HMAC-SHA256(DEK, utf8(policy)))`.
    public func buildManifest(
        contentKey: Data,
        iv: Data,
        policyJSON: Data,
        publicKey: SecKey
    ) throws -> Manifest {
        guard iv.count == 16 else {
            throw TDFError.invalidIVSize
        }
        try FairPlayPolicy.validateJSONStructure(policyJSON)
        let wrappedKey = try wrapKey(contentKey, with: publicKey)
        let policyBase64 = policyJSON.base64EncodedString()
        let keyAccess = KeyAccess(
            url: kasURL.absoluteString,
            wrappedKey: wrappedKey.base64EncodedString(),
            policyBinding: PolicyBinding(
                hash: FairPlayPolicy.binding(policyBase64: policyBase64, dek: contentKey))
        )
        let encryptionInfo = EncryptionInformation(
            keyAccess: [keyAccess],
            method: .aes128CBC(iv: iv),
            policy: policyBase64
        )
        return Manifest(encryptionInformation: encryptionInfo)
    }

    /// Build a FairPlay package profile v2 manifest (ADR-0055 §3 in arkavo-ios): the policy with the component list
    /// inserted, and one key access object per component, in component order. Each wraps its own key for this KAS
    /// (RSA-OAEP-SHA1) and carries its own binding of the policy, `base64(HMAC-SHA256(key, utf8(policy)))`.
    public func buildManifest(
        componentKeys: [FairPlayComponentKey],
        iv: Data,
        policyJSON: Data,
        publicKey: SecKey
    ) throws -> Manifest {
        guard iv.count == 16 else {
            throw TDFError.invalidIVSize
        }
        let policyBase64 = try FairPlayComponents.insert(componentKeys, intoPolicyJSON: policyJSON).base64EncodedString()
        let keyAccess = try componentKeys.map { componentKey in
            KeyAccess(
                url: kasURL.absoluteString,
                wrappedKey: try wrapKey(componentKey.key, with: publicKey).base64EncodedString(),
                policyBinding: PolicyBinding(
                    hash: FairPlayPolicy.binding(policyBase64: policyBase64, dek: componentKey.key))
            )
        }
        let encryptionInfo = EncryptionInformation(
            keyAccess: keyAccess,
            method: .aes128CBC(iv: iv),
            policy: policyBase64
        )
        return Manifest(encryptionInformation: encryptionInfo)
    }

    /// Serialize manifest to JSON data
    public func serializeManifest(_ manifest: Manifest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(manifest)
    }

    // MARK: - Errors

    public enum TDFError: Error, LocalizedError, Equatable, Sendable {
        case publicKeyFetchFailed
        case invalidPublicKeyFormat
        case invalidKeySize
        case invalidIVSize
        case unsupportedAlgorithm
        case keyWrappingFailed
        case manifestSerializationFailed
        case weakPublicKey(bits: Int)

        public var errorDescription: String? {
            switch self {
            case .publicKeyFetchFailed:
                return "Failed to fetch KAS public key"
            case .invalidPublicKeyFormat:
                return "Invalid public key format"
            case .invalidKeySize:
                return "Content key must be 16 or 32 bytes"
            case .invalidIVSize:
                return "Initialization vector must be 16 bytes"
            case .unsupportedAlgorithm:
                return "RSA-OAEP algorithm not supported"
            case .keyWrappingFailed:
                return "Failed to wrap content key"
            case .manifestSerializationFailed:
                return "Failed to serialize TDF manifest"
            case let .weakPublicKey(bits):
                return "KAS RSA public key is \(bits) bits; at least 2048 required"
            }
        }
    }
}

// MARK: - FairPlay Integration

extension TDFManifestBuilder {
    /// Build TDF manifest for FairPlay key request
    /// - Parameters:
    ///   - contentKey: 16-byte AES-128 content encryption key
    ///   - iv: 16-byte initialization vector
    ///   - assetID: Unused; the manifest carries no policy and so no key id
    /// - Returns: JSON data ready to send to /media/v1/key-request
    @available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
    public func buildFairPlayKeyRequest(
        contentKey: Data,
        iv: Data,
        assetID: String
    ) async throws -> Data {
        let manifest = try await buildManifest(contentKey: contentKey, iv: iv, assetID: assetID)
        return try serializeManifest(manifest)
    }

    /// Create manifest data from wrapped key (when key is already wrapped)
    @available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
    public func buildFairPlayKeyRequestFromWrappedKey(
        wrappedKey: Data,
        iv: Data
    ) throws -> Data {
        let manifest = buildManifest(wrappedKey: wrappedKey, iv: iv)
        return try serializeManifest(manifest)
    }
}
