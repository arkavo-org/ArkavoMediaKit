import Foundation

/// Configuration for DRM media server and FairPlay Streaming
public struct DRMConfiguration: Sendable {
    /// Media server base URL
    public let serverURL: URL

    /// FairPlay Streaming application certificate data
    public let fpsCertificate: Data

    /// Session heartbeat interval (seconds)
    public let heartbeatInterval: TimeInterval

    /// Session timeout (seconds)
    public let sessionTimeout: TimeInterval

    /// Initialize with required parameters
    /// - Parameters:
    ///   - serverURL: Media server base URL (must use HTTPS)
    ///   - fpsCertificateData: FPS certificate data (required - obtain from Apple Developer Portal)
    ///   - heartbeatInterval: How often to send heartbeat (default: 30s)
    ///   - sessionTimeout: Session expiration time (default: 300s)
    /// - Throws: DRMConfigurationError if certificate is invalid or URL is not HTTPS
    public init(
        serverURL: URL,
        fpsCertificateData: Data,
        heartbeatInterval: TimeInterval = 30,
        sessionTimeout: TimeInterval = 300
    ) throws {
        // Validate HTTPS requirement
        guard serverURL.scheme == "https" else {
            throw DRMConfigurationError.invalidServerURL
        }

        // Validate certificate data
        guard !fpsCertificateData.isEmpty else {
            throw DRMConfigurationError.certificateEmpty
        }

        self.serverURL = serverURL
        self.fpsCertificate = fpsCertificateData
        self.heartbeatInterval = heartbeatInterval
        self.sessionTimeout = sessionTimeout
    }
}

/// DRM configuration errors
public enum DRMConfigurationError: Error, LocalizedError {
    case certificateNotFound
    case certificateEmpty
    case certificateLoadFailed(Error)
    case invalidServerURL

    public var errorDescription: String? {
        switch self {
        case .certificateNotFound:
            "FairPlay Streaming certificate not found in bundle"
        case .certificateEmpty:
            "FairPlay Streaming certificate is empty"
        case .certificateLoadFailed(let error):
            "Failed to load FairPlay Streaming certificate: \(error.localizedDescription)"
        case .invalidServerURL:
            "Invalid media server URL"
        }
    }
}
