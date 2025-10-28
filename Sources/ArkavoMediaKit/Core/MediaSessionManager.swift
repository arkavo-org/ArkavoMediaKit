import Foundation
import os.log

/// Manages media playback sessions with automatic heartbeat
public actor MediaSessionManager {
    private let client: MediaServerClient
    private let configuration: DRMConfiguration

    /// Active sessions mapped by server-assigned sessionId
    private var activeSessions: [String: ActiveSession] = [:]

    /// Heartbeat task for periodic updates
    private var heartbeatTask: Task<Void, Never>?

    /// Logger for session management
    private let logger = Logger(subsystem: "com.arkavo.mediakit", category: "session")

    /// Optional callback for heartbeat failures
    public var onHeartbeatFailure: (@Sendable (String, Error) -> Void)?

    public struct ActiveSession: Sendable {
        let sessionId: String
        let userID: String
        let assetID: String
        var state: PlaybackState
        var lastHeartbeat: Date
        var position: Double?
        var failedHeartbeatCount: Int = 0
        var lastHeartbeatError: Error?

        public enum PlaybackState: String, Sendable {
            case idle
            case playing
            case paused
            case buffering
            case ended
        }
    }

    public init(configuration: DRMConfiguration) {
        self.configuration = configuration
        self.client = MediaServerClient(configuration: configuration)
    }

    /// Start a new playback session
    /// - Parameters:
    ///   - userID: User identifier
    ///   - assetID: Asset identifier
    ///   - clientIP: Optional client IP
    ///   - geoRegion: Optional geo region
    /// - Returns: Server-assigned session ID
    public func startSession(
        userID: String,
        assetID: String,
        clientIP: String? = nil,
        geoRegion: String? = nil
    ) async throws -> String {
        // Validate inputs
        try InputValidator.validateUserID(userID)
        try InputValidator.validateAssetID(assetID)

        if let region = geoRegion {
            try InputValidator.validateRegionCode(region)
        }

        // Call server to start session
        let response = try await client.startSession(
            userID: userID,
            assetID: assetID,
            clientIP: clientIP,
            geoRegion: geoRegion
        )

        // Store active session
        let session = ActiveSession(
            sessionId: response.sessionId,
            userID: userID,
            assetID: assetID,
            state: .idle,
            lastHeartbeat: Date(),
            position: nil
        )

        activeSessions[response.sessionId] = session

        // Start heartbeat task if not already running
        startHeartbeatIfNeeded()

        return response.sessionId
    }

    /// Update session playback state
    /// - Parameters:
    ///   - sessionId: Session identifier
    ///   - state: New playback state
    ///   - position: Optional playback position
    public func updateState(
        sessionId: String,
        state: ActiveSession.PlaybackState,
        position: Double? = nil
    ) {
        guard var session = activeSessions[sessionId] else {
            return
        }

        session.state = state
        session.position = position
        activeSessions[sessionId] = session
    }

    /// End a session
    /// - Parameter sessionId: Session identifier
    public func endSession(sessionId: String) async throws {
        guard activeSessions[sessionId] != nil else {
            throw SessionError.sessionNotFound(sessionID: UUID())
        }

        // Notify server
        try await client.endSession(sessionId: sessionId)

        // Remove from active sessions
        activeSessions.removeValue(forKey: sessionId)

        // Stop heartbeat if no more sessions
        if activeSessions.isEmpty {
            stopHeartbeat()
        }
    }

    /// End all active sessions
    public func endAllSessions() async {
        let sessionIds = Array(activeSessions.keys)

        for sessionId in sessionIds {
            try? await endSession(sessionId: sessionId)
        }

        stopHeartbeat()
    }

    /// Get active session count
    public var activeSessionCount: Int {
        activeSessions.count
    }

    // MARK: - Heartbeat Management

    private func startHeartbeatIfNeeded() {
        guard heartbeatTask == nil else {
            return
        }

        heartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }

                // Wait for heartbeat interval
                let interval = configuration.heartbeatInterval
                try? await Task.sleep(for: .seconds(interval))

                // Send heartbeats for all active sessions
                await self.sendHeartbeats()
            }
        }
    }

    private func stopHeartbeat() {
        heartbeatTask?.cancel()
        heartbeatTask = nil
    }

    private func sendHeartbeats() async {
        let now = Date()
        let maxRetries = 3

        for (sessionId, session) in activeSessions {
            do {
                try await client.sendHeartbeat(
                    sessionId: sessionId,
                    state: session.state.rawValue,
                    position: session.position
                )

                // Success - reset failure count and update last heartbeat time
                var updatedSession = session
                updatedSession.lastHeartbeat = now
                updatedSession.failedHeartbeatCount = 0
                updatedSession.lastHeartbeatError = nil
                activeSessions[sessionId] = updatedSession

            } catch {
                // Log error but continue with other sessions
                logger.error("Failed to send heartbeat for session \(sessionId): \(error.localizedDescription)")

                // Increment failure count
                var updatedSession = session
                updatedSession.failedHeartbeatCount += 1
                updatedSession.lastHeartbeatError = error
                activeSessions[sessionId] = updatedSession

                // Notify callback
                onHeartbeatFailure?(sessionId, error)

                // Only remove session after max retries or timeout
                // This allows for transient network failures
                if updatedSession.failedHeartbeatCount >= maxRetries {
                    logger.warning("Session \(sessionId) exceeded max heartbeat failures (\(maxRetries)), removing session")
                    activeSessions.removeValue(forKey: sessionId)
                } else {
                    // Check if session expired (no successful heartbeat for timeout period)
                    let elapsed = now.timeIntervalSince(session.lastHeartbeat)
                    if elapsed > configuration.sessionTimeout {
                        logger.warning("Session \(sessionId) timed out after \(elapsed)s, removing session")
                        activeSessions.removeValue(forKey: sessionId)
                    } else {
                        logger.info("Session \(sessionId) heartbeat failed (\(updatedSession.failedHeartbeatCount)/\(maxRetries)), will retry")
                    }
                }
            }
        }

        // Stop heartbeat if all sessions expired
        if activeSessions.isEmpty {
            stopHeartbeat()
        }
    }

    deinit {
        heartbeatTask?.cancel()
    }
}
