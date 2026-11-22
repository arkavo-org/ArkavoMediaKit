import Foundation

/// Validation errors for input sanitization
public enum ValidationError: Error, LocalizedError, Sendable {
    case invalidAssetID(String)
    case invalidUserID(String)
    case invalidSessionID
    case invalidURL(String)
    case invalidRegionCode(String)
    case invalidPolicyAttribute(String)
    case inputTooLong(field: String, maxLength: Int)
    case inputEmpty(field: String)
    case invalidCharacters(field: String)

    // FairPlay-specific errors
    case missingContentKeyIdentifier
    case invalidContentKeyIdentifier(String)
    case contentKeyRequestFailed(Error)
    case persistableKeyNotSupported

    public var errorDescription: String? {
        switch self {
        case let .invalidAssetID(id):
            "Invalid asset ID: \(id)"
        case let .invalidUserID(id):
            "Invalid user ID: \(id)"
        case .invalidSessionID:
            "Invalid session ID"
        case let .invalidURL(url):
            "Invalid URL: \(url)"
        case let .invalidRegionCode(code):
            "Invalid region code: \(code)"
        case let .invalidPolicyAttribute(attr):
            "Invalid policy attribute: \(attr)"
        case let .inputTooLong(field, maxLength):
            "\(field) exceeds maximum length of \(maxLength) characters"
        case let .inputEmpty(field):
            "\(field) cannot be empty"
        case let .invalidCharacters(field):
            "\(field) contains invalid characters"
        case .missingContentKeyIdentifier:
            "Content key identifier is missing"
        case let .invalidContentKeyIdentifier(identifier):
            "Invalid content key identifier: \(identifier)"
        case let .contentKeyRequestFailed(error):
            "Content key request failed: \(error.localizedDescription)"
        case .persistableKeyNotSupported:
            "Persistable content keys are not supported on this platform"
        }
    }
}

/// Input validator for public APIs
public enum InputValidator {
    /// Maximum lengths for various fields
    public enum Limits {
        public static let assetIDMaxLength = 256
        public static let userIDMaxLength = 256
        public static let sessionIDMaxLength = 128
        public static let regionCodeLength = 2
        public static let policyAttributeMaxLength = 512
    }

    /// Strict RFC 3986 unreserved characters for percent-encoding query parameter values
    private static let queryValueAllowed = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )

    /// Validate session ID (prevents URL path traversal / endpoint injection)
    /// - Parameter sessionID: Session identifier
    /// - Throws: ValidationError.invalidSessionID if invalid
    public static func validateSessionID(_ sessionID: String) throws {
        guard !sessionID.isEmpty,
              sessionID.utf8.count <= Limits.sessionIDMaxLength
        else {
            throw ValidationError.invalidSessionID
        }

        let isValid = sessionID.utf8.allSatisfy { byte in
            (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
                || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                || byte == UInt8(ascii: "-")
                || byte == UInt8(ascii: "_")
        }

        guard isValid else {
            throw ValidationError.invalidSessionID
        }
    }

    /// Validate asset ID
    /// - Parameter assetID: Asset identifier
    /// - Throws: ValidationError if invalid
    public static func validateAssetID(_ assetID: String) throws {
        guard !assetID.isEmpty else {
            throw ValidationError.inputEmpty(field: "assetID")
        }

        guard assetID.count <= Limits.assetIDMaxLength else {
            throw ValidationError.inputTooLong(
                field: "assetID",
                maxLength: Limits.assetIDMaxLength
            )
        }

        // Allow alphanumeric, hyphens, underscores
        let allowedCharacters = CharacterSet.alphanumerics
            .union(CharacterSet(charactersIn: "-_"))

        guard assetID.unicodeScalars.allSatisfy({ allowedCharacters.contains($0) }) else {
            throw ValidationError.invalidCharacters(field: "assetID")
        }
    }

    /// Validate user ID
    /// - Parameter userID: User identifier
    /// - Throws: ValidationError if invalid
    public static func validateUserID(_ userID: String) throws {
        guard !userID.isEmpty else {
            throw ValidationError.inputEmpty(field: "userID")
        }

        guard userID.count <= Limits.userIDMaxLength else {
            throw ValidationError.inputTooLong(
                field: "userID",
                maxLength: Limits.userIDMaxLength
            )
        }

        // Allow alphanumeric, hyphens, underscores, @ for email-like IDs
        let allowedCharacters = CharacterSet.alphanumerics
            .union(CharacterSet(charactersIn: "-_@."))

        guard userID.unicodeScalars.allSatisfy({ allowedCharacters.contains($0) }) else {
            throw ValidationError.invalidCharacters(field: "userID")
        }
    }

    /// Validate region code (ISO 3166-1 alpha-2)
    /// - Parameter regionCode: Two-letter ASCII uppercase region code
    /// - Throws: ValidationError if invalid
    public static func validateRegionCode(_ regionCode: String) throws {
        guard regionCode.utf8.count == Limits.regionCodeLength else {
            throw ValidationError.invalidRegionCode(regionCode)
        }

        guard regionCode.utf8.allSatisfy({ $0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "Z") }) else {
            throw ValidationError.invalidRegionCode(regionCode)
        }
    }

    /// Validate and sanitize policy attribute
    /// - Parameter attribute: Policy attribute string
    /// - Returns: Sanitized attribute safe for query parameter transmission
    /// - Throws: ValidationError if invalid
    public static func validatePolicyAttribute(_ attribute: String) throws -> String {
        guard !attribute.isEmpty else {
            throw ValidationError.inputEmpty(field: "policyAttribute")
        }

        guard attribute.count <= Limits.policyAttributeMaxLength else {
            throw ValidationError.inputTooLong(
                field: "policyAttribute",
                maxLength: Limits.policyAttributeMaxLength
            )
        }

        // Percent-encode all non-unreserved characters so query delimiters (&, =, +, ;, ?, #) cannot inject params
        guard let encoded = attribute.addingPercentEncoding(
            withAllowedCharacters: queryValueAllowed
        ) else {
            throw ValidationError.invalidPolicyAttribute(attribute)
        }

        return encoded
    }

    /// Validate URL
    /// - Parameter urlString: URL string (requires https or tdf3 with a non-empty host; http only for loopback)
    /// - Throws: ValidationError if invalid
    public static func validateURL(_ urlString: String) throws -> URL {
        guard let url = URL(string: urlString),
              let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased(),
              !host.isEmpty
        else {
            throw ValidationError.invalidURL(urlString)
        }

        switch scheme {
        case "https", "tdf3":
            return url
        case "http":
            let normalizedHost = host.hasSuffix(".") ? String(host.dropLast()) : host
            guard normalizedHost == "localhost" || normalizedHost == "127.0.0.1" || normalizedHost == "::1" else {
                throw ValidationError.invalidURL(urlString)
            }
            return url
        default:
            throw ValidationError.invalidURL(urlString)
        }
    }
}
