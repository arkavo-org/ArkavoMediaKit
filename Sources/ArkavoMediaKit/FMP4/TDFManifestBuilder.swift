import Foundation
import Security

// MARK: - TDF Manifest Builder

/// Builds OpenTDF Standard TDF manifests for FairPlay key delivery
public final class TDFManifestBuilder {
    // MARK: - Types

    /// TDF Manifest structure matching OpenTDF Standard TDF specification
    public struct Manifest: Codable {
        public let encryptionInformation: EncryptionInformation
        public let payload: Payload?

        public init(encryptionInformation: EncryptionInformation, payload: Payload? = nil) {
            self.encryptionInformation = encryptionInformation
            self.payload = payload
        }
    }

    public struct EncryptionInformation: Codable {
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

    public struct KeyAccess: Codable {
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

    public struct PolicyBinding: Codable {
        public let alg: String
        public let hash: String

        public init(alg: String = "HS256", hash: String) {
            self.alg = alg
            self.hash = hash
        }
    }

    public struct EncryptionMethod: Codable {
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

    public struct IntegrityInformation: Codable {
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

    public struct RootSignature: Codable {
        public let alg: String
        public let sig: String

        public init(alg: String = "HS256", sig: String) {
            self.alg = alg
            self.sig = sig
        }
    }

    public struct Segment: Codable {
        public let hash: String
        public let segmentSize: Int?
        public let encryptedSegmentSize: Int?
    }

    public struct Payload: Codable {
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

    private let kasURL: URL
    private var kasPublicKey: SecKey?

    // MARK: - Initialization

    /// Initialize with KAS URL
    public init(kasURL: URL) {
        self.kasURL = kasURL
    }

    // MARK: - Public Key Fetching

    /// Fetch KAS RSA public key from server
    public func fetchKASPublicKey() async throws -> SecKey {
        if let existing = kasPublicKey {
            return existing
        }

        let url = kasURL.appendingPathComponent("kas/v2/kas_public_key")
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "algorithm", value: "rsa:2048")]

        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw TDFError.publicKeyFetchFailed
        }

        // Parse response - expects PEM or JSON with public key
        let key = try parsePublicKeyResponse(data)
        kasPublicKey = key
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
        // Remove PEM headers
        let keyString = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespaces)

        guard let keyData = Data(base64Encoded: keyString) else {
            throw TDFError.invalidPublicKeyFormat
        }

        // Create SecKey from DER data
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            throw TDFError.invalidPublicKeyFormat
        }

        return secKey
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

    /// Serialize manifest to JSON data
    public func serializeManifest(_ manifest: Manifest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(manifest)
    }

    // MARK: - Errors

    public enum TDFError: Error, LocalizedError {
        case publicKeyFetchFailed
        case invalidPublicKeyFormat
        case invalidKeySize
        case unsupportedAlgorithm
        case keyWrappingFailed
        case manifestSerializationFailed

        public var errorDescription: String? {
            switch self {
            case .publicKeyFetchFailed:
                return "Failed to fetch KAS public key"
            case .invalidPublicKeyFormat:
                return "Invalid public key format"
            case .invalidKeySize:
                return "Content key must be 16 or 32 bytes"
            case .unsupportedAlgorithm:
                return "RSA-OAEP algorithm not supported"
            case .keyWrappingFailed:
                return "Failed to wrap content key"
            case .manifestSerializationFailed:
                return "Failed to serialize TDF manifest"
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
    ///   - assetID: Asset identifier (used in skd:// URI)
    /// - Returns: JSON data ready to send to /media/v1/key-request
    public func buildFairPlayKeyRequest(
        contentKey: Data,
        iv: Data,
        assetID: String
    ) async throws -> Data {
        let manifest = try await buildManifest(contentKey: contentKey, iv: iv, assetID: assetID)
        return try serializeManifest(manifest)
    }

    /// Create manifest data from wrapped key (when key is already wrapped)
    public func buildFairPlayKeyRequestFromWrappedKey(
        wrappedKey: Data,
        iv: Data
    ) throws -> Data {
        let manifest = buildManifest(wrappedKey: wrappedKey, iv: iv)
        return try serializeManifest(manifest)
    }
}
