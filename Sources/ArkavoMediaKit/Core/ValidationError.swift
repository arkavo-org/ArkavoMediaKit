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
        }
    }
}

/// Input validator for public APIs
public enum InputValidator {
    /// Maximum lengths for various fields
    public enum Limits {
        public static let assetIDMaxLength = 256
        public static let userIDMaxLength = 256
        public static let regionCodeLength = 2
        public static let policyAttributeMaxLength = 512
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
    /// - Parameter regionCode: Two-letter region code
    /// - Throws: ValidationError if invalid
    public static func validateRegionCode(_ regionCode: String) throws {
        guard regionCode.count == Limits.regionCodeLength else {
            throw ValidationError.invalidRegionCode(regionCode)
        }

        guard regionCode.unicodeScalars.allSatisfy({ CharacterSet.uppercaseLetters.contains($0) }) else {
            throw ValidationError.invalidRegionCode(regionCode)
        }
    }

    /// Validate and sanitize policy attribute
    /// - Parameter attribute: Policy attribute string
    /// - Returns: Sanitized attribute
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

        // URL-encode for safe transmission
        guard let encoded = attribute.addingPercentEncoding(
            withAllowedCharacters: .urlQueryAllowed
        ) else {
            throw ValidationError.invalidPolicyAttribute(attribute)
        }

        return encoded
    }

    /// Validate URL
    /// - Parameter urlString: URL string
    /// - Throws: ValidationError if invalid
    public static func validateURL(_ urlString: String) throws -> URL {
        guard let url = URL(string: urlString),
              let scheme = url.scheme,
              ["http", "https", "tdf3"].contains(scheme) else {
            throw ValidationError.invalidURL(urlString)
        }

        return url
    }
}
