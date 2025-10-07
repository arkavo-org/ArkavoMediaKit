import Foundation

/// Manages TDF3 media streaming sessions
public actor TDF3MediaSession {
    /// Active sessions keyed by session ID
    private var sessions: [UUID: MediaSession] = [:]

    /// Active streams per user for concurrency tracking
    private var activeStreamsPerUser: [String: Set<UUID>] = [:]

    /// Session heartbeat timeout (seconds)
    private let heartbeatTimeout: TimeInterval

    public init(heartbeatTimeout: TimeInterval = 300) {
        self.heartbeatTimeout = heartbeatTimeout
    }

    /// Start a new media session
    public func startSession(
        userID: String,
        assetID: String,
        clientIP: String? = nil,
        geoRegion: String? = nil,
        policy: MediaDRMPolicy? = nil,
        metadata: [String: String] = [:]
    ) throws -> MediaSession {
        // Validate inputs
        try InputValidator.validateUserID(userID)
        try InputValidator.validateAssetID(assetID)

        if let region = geoRegion {
            try InputValidator.validateRegionCode(region)
        }

        // Check concurrency limit if policy specifies
        if let maxStreams = policy?.maxConcurrentStreams {
            let currentStreams = activeStreamsPerUser[userID]?.count ?? 0
            if currentStreams >= maxStreams {
                throw SessionError.concurrencyLimitExceeded(current: currentStreams, max: maxStreams)
            }
        }

        // Create new session
        let session = MediaSession(
            userID: userID,
            assetID: assetID,
            clientIP: clientIP,
            geoRegion: geoRegion,
            metadata: metadata
        )

        // Store session
        sessions[session.sessionID] = session

        // Track user's active streams (using dictionary default to avoid race condition)
        activeStreamsPerUser[userID, default: Set()].insert(session.sessionID)

        return session
    }

    /// Update session heartbeat
    public func updateHeartbeat(
        sessionID: UUID,
        state: MediaSession.PlaybackState
    ) throws {
        guard var session = sessions[sessionID] else {
            throw SessionError.sessionNotFound(sessionID: sessionID)
        }

        session.updateHeartbeat(state: state)
        sessions[sessionID] = session
    }

    /// Get session by ID
    public func getSession(sessionID: UUID) throws -> MediaSession {
        guard let session = sessions[sessionID] else {
            throw SessionError.sessionNotFound(sessionID: sessionID)
        }

        // Check if session expired
        let elapsed = Date().timeIntervalSince(session.lastHeartbeat)
        if elapsed > heartbeatTimeout {
            try endSession(sessionID: sessionID)
            throw SessionError.sessionExpired(sessionID: sessionID)
        }

        return session
    }

    /// End a session
    public func endSession(sessionID: UUID) throws {
        guard let session = sessions.removeValue(forKey: sessionID) else {
            throw SessionError.sessionNotFound(sessionID: sessionID)
        }

        // Remove from active streams
        activeStreamsPerUser[session.userID]?.remove(sessionID)
        if activeStreamsPerUser[session.userID]?.isEmpty == true {
            activeStreamsPerUser.removeValue(forKey: session.userID)
        }
    }

    /// Get active stream count for a user
    public func getActiveStreamCount(userID: String) -> Int {
        activeStreamsPerUser[userID]?.count ?? 0
    }

    /// Clean up expired sessions
    public func cleanupExpiredSessions() -> Int {
        let now = Date()
        var cleanedCount = 0

        let expiredSessionIDs = sessions.filter { _, session in
            now.timeIntervalSince(session.lastHeartbeat) > heartbeatTimeout
        }.map(\.key)

        for sessionID in expiredSessionIDs {
            try? endSession(sessionID: sessionID)
            cleanedCount += 1
        }

        return cleanedCount
    }

    /// Get all active sessions for a user
    public func getUserSessions(userID: String) -> [MediaSession] {
        guard let sessionIDs = activeStreamsPerUser[userID] else {
            return []
        }

        return sessionIDs.compactMap { sessions[$0] }
    }
}

/// Session-related errors
public enum SessionError: Error, LocalizedError {
    case sessionNotFound(sessionID: UUID)
    case sessionExpired(sessionID: UUID)
    case concurrencyLimitExceeded(current: Int, max: Int)
    case invalidSession

    public var errorDescription: String? {
        switch self {
        case let .sessionNotFound(sessionID):
            "Session not found: \(sessionID)"
        case let .sessionExpired(sessionID):
            "Session expired: \(sessionID)"
        case let .concurrencyLimitExceeded(current, max):
            "Concurrency limit exceeded: \(current)/\(max) streams active"
        case .invalidSession:
            "Invalid session"
        }
    }
}
