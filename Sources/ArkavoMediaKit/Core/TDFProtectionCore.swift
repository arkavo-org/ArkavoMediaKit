import CommonCrypto
import Foundation

// MARK: - TDF Protection Core

/// Shared cryptographic operations for TDF content protection
/// Used by TDFProtectionService, RecordingProtectionService, and VideoProtectionService
public enum TDFProtectionCore {
    // MARK: - Key Generation

    /// Generate 16-byte DEK for AES-128 encryption
    public static func generateDEK() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw TDFProtectionCoreError.keyGenerationFailed
        }
        return Data(bytes)
    }

    /// Generate 16-byte initialization vector
    public static func generateIV() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw TDFProtectionCoreError.ivGenerationFailed
        }
        return Data(bytes)
    }

    // MARK: - AES-128-CBC Encryption

    /// Encrypt data with AES-128-CBC using PKCS7 padding
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - key: 16-byte AES-128 key
    ///   - iv: 16-byte initialization vector
    /// - Returns: Encrypted ciphertext
    public static func encryptCBC(plaintext: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES128 else {
            throw TDFProtectionCoreError.invalidKeySize
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw TDFProtectionCoreError.invalidIVSize
        }

        let bufferSize = plaintext.count + kCCBlockSizeAES128
        var ciphertext = Data(count: bufferSize)
        var numBytesEncrypted = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                plaintext.withUnsafeBytes { plaintextBytes in
                    ciphertext.withUnsafeMutableBytes { ciphertextBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            kCCKeySizeAES128,
                            ivBytes.baseAddress,
                            plaintextBytes.baseAddress,
                            plaintext.count,
                            ciphertextBytes.baseAddress,
                            bufferSize,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw TDFProtectionCoreError.encryptionFailed(status: status)
        }

        ciphertext.removeSubrange(numBytesEncrypted...)
        return ciphertext
    }

    // MARK: - RSA Key Operations

    /// Load RSA public key from PEM format
    /// - Parameter pem: PEM-encoded RSA public key
    /// - Returns: SecKey for encryption operations
    public static func loadRSAPublicKey(fromPEM pem: String) throws -> SecKey {
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = Data(base64Encoded: stripped) else {
            throw TDFProtectionCoreError.invalidPEM
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw TDFProtectionCoreError.invalidKeyData(error?.takeRetainedValue())
        }

        // Validate minimum RSA key size (2048 bits)
        guard let attrs = SecKeyCopyAttributes(key) as? [String: Any],
              let keySize = attrs[kSecAttrKeySizeInBits as String] as? Int,
              keySize >= 2048
        else {
            throw TDFProtectionCoreError.weakRSAKey
        }

        return key
    }

    /// Wrap DEK with RSA-2048 OAEP using SHA-1 (per OpenTDF spec)
    /// - Parameters:
    ///   - dek: 16-byte data encryption key
    ///   - publicKeyPEM: PEM-encoded RSA public key
    /// - Returns: Base64-encoded wrapped key
    public static func wrapDEKWithRSA(dek: Data, publicKeyPEM: String) throws -> String {
        let publicKey = try loadRSAPublicKey(fromPEM: publicKeyPEM)

        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA1,
            dek as CFData,
            &error
        ) as Data? else {
            throw TDFProtectionCoreError.keyWrapFailed(error?.takeRetainedValue())
        }

        // Verify wrapped key size (256 bytes for RSA-2048)
        guard encrypted.count == 256 else {
            throw TDFProtectionCoreError.invalidWrappedKeySize
        }

        return encrypted.base64EncodedString()
    }

    // MARK: - KAS Integration

    /// Fetch RSA public key from KAS server
    /// - Parameters:
    ///   - kasURL: Base KAS server URL
    ///   - algorithm: Algorithm query parameter (default: "rsa")
    /// - Returns: PEM-encoded RSA public key
    public static func fetchKASRSAPublicKey(kasURL: URL, algorithm: String = "rsa") async throws -> String {
        var components = URLComponents(url: kasURL, resolvingAgainstBaseURL: true)!
        components.path = "/kas/v2/kas_public_key"
        components.queryItems = [URLQueryItem(name: "algorithm", value: algorithm)]

        guard let url = components.url else {
            throw TDFProtectionCoreError.invalidKASURL
        }

        let (data, response) = try await URLSession.shared.data(from: url)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200
        else {
            throw TDFProtectionCoreError.kasKeyFetchFailed
        }

        // Try both common key names in response
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let publicKey = json["public_key"] as? String ?? json["publicKey"] as? String
        else {
            throw TDFProtectionCoreError.invalidKASResponse
        }

        return publicKey
    }

    // MARK: - Manifest Building

    /// Build Standard TDF manifest.json
    /// - Parameters:
    ///   - kasURL: KAS server URL for key access
    ///   - wrappedKey: Base64-encoded wrapped DEK
    ///   - iv: Initialization vector
    ///   - assetID: Optional asset identifier
    ///   - mimeType: Content MIME type
    ///   - includeMetadata: Whether to include meta section with assetId and protectedAt
    /// - Returns: JSON-encoded manifest data
    public static func buildManifest(
        kasURL: URL,
        wrappedKey: String,
        iv: Data,
        assetID: String? = nil,
        mimeType: String = "video/mp4",
        includeMetadata: Bool = true
    ) throws -> Data {
        var manifest: [String: Any] = [
            "encryptionInformation": [
                "type": "split",
                "keyAccess": [[
                    "type": "wrapped",
                    "url": kasURL.absoluteString,
                    "protocol": "kas",
                    "wrappedKey": wrappedKey,
                ]],
                "method": [
                    "algorithm": "AES-128-CBC",
                    "iv": iv.base64EncodedString(),
                ],
            ],
            "payload": [
                "type": "reference",
                "url": "0.payload",
                "mimeType": mimeType,
            ],
        ]

        if includeMetadata, let assetID {
            manifest["meta"] = [
                "assetId": assetID,
                "protectedAt": ISO8601DateFormatter().string(from: Date()),
            ]
        }

        return try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .prettyPrinted])
    }

    /// Build manifest with custom KAS URL (allows appending /kas path if needed)
    public static func buildManifestWithKASPath(
        kasURL: URL,
        appendKASPath: Bool,
        wrappedKey: String,
        iv: Data,
        assetID: String,
        mimeType: String = "video/quicktime"
    ) throws -> Data {
        let kasRewrapURL: String
        if appendKASPath, !kasURL.path.contains("/kas") {
            kasRewrapURL = kasURL.appendingPathComponent("kas").absoluteString
        } else {
            kasRewrapURL = kasURL.absoluteString
        }

        let manifest: [String: Any] = [
            "encryptionInformation": [
                "type": "split",
                "keyAccess": [[
                    "type": "wrapped",
                    "url": kasRewrapURL,
                    "protocol": "kas",
                    "wrappedKey": wrappedKey,
                ]],
                "method": [
                    "algorithm": "AES-128-CBC",
                    "iv": iv.base64EncodedString(),
                ],
            ],
            "payload": [
                "type": "reference",
                "url": "0.payload",
                "mimeType": mimeType,
            ],
            "meta": [
                "assetId": assetID,
                "protectedAt": ISO8601DateFormatter().string(from: Date()),
            ],
        ]

        return try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .prettyPrinted])
    }
}

// MARK: - TDF Protection Core Error

/// Errors from TDF protection core operations
public enum TDFProtectionCoreError: Error, LocalizedError, Sendable {
    case keyGenerationFailed
    case ivGenerationFailed
    case invalidKeySize
    case invalidIVSize
    case encryptionFailed(status: CCCryptorStatus)
    case invalidKASURL
    case kasKeyFetchFailed
    case invalidKASResponse
    case invalidPEM
    case invalidKeyData(CFError?)
    case keyWrapFailed(CFError?)
    case invalidWrappedKeySize
    case weakRSAKey

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed:
            "Failed to generate content encryption key"
        case .ivGenerationFailed:
            "Failed to generate initialization vector"
        case .invalidKeySize:
            "Invalid AES-128 key size (expected 16 bytes)"
        case .invalidIVSize:
            "Invalid IV size (expected 16 bytes)"
        case let .encryptionFailed(status):
            "AES-CBC encryption failed with status \(status)"
        case .invalidKASURL:
            "Invalid KAS URL"
        case .kasKeyFetchFailed:
            "Failed to fetch RSA public key from KAS"
        case .invalidKASResponse:
            "Invalid response from KAS key endpoint"
        case .invalidPEM:
            "Invalid PEM format for RSA public key"
        case let .invalidKeyData(error):
            "Invalid RSA key data: \(error?.localizedDescription ?? "unknown")"
        case let .keyWrapFailed(error):
            "RSA key wrapping failed: \(error?.localizedDescription ?? "unknown")"
        case .invalidWrappedKeySize:
            "Invalid wrapped key size (expected 256 bytes for RSA-2048)"
        case .weakRSAKey:
            "RSA key too weak (minimum 2048 bits required)"
        }
    }
}
