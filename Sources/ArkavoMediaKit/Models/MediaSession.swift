import Foundation

/// Represents a media streaming session with TDF3 protection
public struct MediaSession: Sendable {
    /// Unique session identifier
    public let sessionID: UUID

    /// User identifier
    public let userID: String

    /// Asset/content identifier
    public let assetID: String

    /// Client IP address
    public let clientIP: String?

    /// Geographic region code (ISO 3166-1 alpha-2)
    public let geoRegion: String?

    /// Session creation timestamp
    public let createdAt: Date

    /// Last heartbeat timestamp
    public private(set) var lastHeartbeat: Date

    /// Current playback state
    public private(set) var state: PlaybackState

    /// First play timestamp (for rental window tracking)
    public private(set) var firstPlayTimestamp: Date?

    /// Session metadata
    public var metadata: [String: String]

    public enum PlaybackState: String, Sendable, Codable {
        case idle
        case playing
        case paused
        case buffering
        case ended
    }

    public init(
        sessionID: UUID = UUID(),
        userID: String,
        assetID: String,
        clientIP: String? = nil,
        geoRegion: String? = nil,
        metadata: [String: String] = [:]
    ) {
        self.sessionID = sessionID
        self.userID = userID
        self.assetID = assetID
        self.clientIP = clientIP
        self.geoRegion = geoRegion
        self.createdAt = Date()
        self.lastHeartbeat = Date()
        self.state = .idle
        self.metadata = metadata
    }

    /// Update heartbeat timestamp
    public mutating func updateHeartbeat(state: PlaybackState) {
        self.lastHeartbeat = Date()
        self.state = state

        // Record first play timestamp
        if state == .playing && firstPlayTimestamp == nil {
            firstPlayTimestamp = Date()
        }
    }
}

extension MediaSession: Codable {}
extension MediaSession: Identifiable {
    public var id: UUID { sessionID }
}
