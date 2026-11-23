import Foundation
import os.log

/// Manages media playback sessions with automatic heartbeat
public actor MediaSessionManager {
    private let client: MediaServerClient
    private let configuration: DRMConfiguration

    /// Active sessions mapped by server-assigned sessionId
    private var activeSessions: [String: ActiveSession] = [:]

    /// Sessions already removed locally whose server-side end notification failed and can be retried
    private var pendingServerEnd: Set<String> = []

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

    /// Internal initializer allowing custom MediaServerClient injection in tests
    init(configuration: DRMConfiguration, client: MediaServerClient) {
        self.configuration = configuration
        self.client = client
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

        pendingServerEnd.remove(response.sessionId)
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
        let removedActive = activeSessions.removeValue(forKey: sessionId) != nil
        let isPendingRetry = pendingServerEnd.contains(sessionId)

        guard removedActive || isPendingRetry else {
            if let uuid = UUID(uuidString: sessionId) {
                throw SessionError.sessionNotFound(sessionID: uuid)
            }
            throw SessionError.sessionNotFoundWithID(sessionId)
        }

        // Keep session eligible for server-side cleanup retries until DELETE succeeds
        pendingServerEnd.insert(sessionId)

        // Stop heartbeat immediately if no active sessions remain so a failed server
        // notification cannot leak the local session or let heartbeats resurrect it.
        if activeSessions.isEmpty {
            stopHeartbeat()
        }

        // Notify server; leave in pendingServerEnd on failure so callers can retry
        try await client.endSession(sessionId: sessionId)
        pendingServerEnd.remove(sessionId)
    }

    /// End all active sessions (and retry any pending server-side cleanups)
    public func endAllSessions() async {
        let sessionIds = Array(Set(activeSessions.keys).union(pendingServerEnd))

        for sessionId in sessionIds {
            try? await endSession(sessionId: sessionId)
        }

        // Only stop the heartbeat if no new session was started concurrently while ending prior sessions.
        if activeSessions.isEmpty {
            stopHeartbeat()
        }
    }

    /// Get active session count
    public var activeSessionCount: Int {
        activeSessions.count
    }

    /// Read current session snapshot (internal for testing)
    func session(for sessionId: String) -> ActiveSession? {
        activeSessions[sessionId]
    }

    // MARK: - Heartbeat Management

    private func startHeartbeatIfNeeded() {
        guard heartbeatTask == nil else {
            return
        }

        heartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }

                // Wait for heartbeat interval; stop immediately on cancellation without firing an extra heartbeat
                let interval = configuration.heartbeatInterval
                do {
                    try await Task.sleep(for: .seconds(interval))
                } catch {
                    return
                }
                guard !Task.isCancelled else { return }

                // Send heartbeats for all active sessions
                await self.sendHeartbeats()
            }
        }
    }

    private func stopHeartbeat() {
        heartbeatTask?.cancel()
        heartbeatTask = nil
    }

    func sendHeartbeats() async {
        let maxRetries = 3
        // Snapshot keys/state before suspension points
        let snapshots = Array(activeSessions.values)

        for snapshot in snapshots {
            let sessionId = snapshot.sessionId
            // Re-check before sending in case a previous iteration's await allowed endSession
            guard let currentBeforeSend = activeSessions[sessionId] else { continue }
            do {
                try await client.sendHeartbeat(
                    sessionId: sessionId,
                    state: currentBeforeSend.state.rawValue,
                    position: currentBeforeSend.position
                )

                // Re-fetch after suspension: never resurrect ended sessions or clobber concurrent state updates
                guard var current = activeSessions[sessionId] else { continue }
                current.lastHeartbeat = Date()
                current.failedHeartbeatCount = 0
                current.lastHeartbeatError = nil
                activeSessions[sessionId] = current

            } catch {
                // Log error but continue with other sessions
                logger.error("Failed to send heartbeat for session \(sessionId): \(error.localizedDescription)")

                // Re-fetch after suspension: if the session was ended while in flight, do not resurrect it
                guard var current = activeSessions[sessionId] else { continue }
                current.failedHeartbeatCount += 1
                current.lastHeartbeatError = error
                activeSessions[sessionId] = current

                // Notify callback
                onHeartbeatFailure?(sessionId, error)

                // Only remove session after max retries or timeout
                if current.failedHeartbeatCount >= maxRetries {
                    logger.warning("Session \(sessionId) exceeded max heartbeat failures (\(maxRetries)), removing session")
                    activeSessions.removeValue(forKey: sessionId)
                } else {
                    let elapsed = Date().timeIntervalSince(current.lastHeartbeat)
                    if elapsed > configuration.sessionTimeout {
                        logger.warning("Session \(sessionId) timed out after \(elapsed)s, removing session")
                        activeSessions.removeValue(forKey: sessionId)
                    } else {
                        logger.info("Session \(sessionId) heartbeat failed (\(current.failedHeartbeatCount)/\(maxRetries)), will retry")
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
