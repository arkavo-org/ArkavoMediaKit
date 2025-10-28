import AVFoundation
import Foundation
import Observation

/// High-level DRM-protected media player with FairPlay Streaming support
@Observable
public final class DRMMediaPlayer {
    // MARK: - Public Properties

    /// Current player instance
    public private(set) var player: AVPlayer?

    /// Current playback state
    public private(set) var state: PlaybackState = .idle

    /// Current error if any
    public private(set) var error: Error?

    /// Current session ID
    public private(set) var sessionId: String?

    // MARK: - Private Properties

    private let configuration: DRMConfiguration
    private let sessionManager: MediaSessionManager
    private let serverClient: MediaServerClient

    private var contentKeySession: AVContentKeySession?
    private var contentKeyDelegate: FairPlayContentKeyDelegate?

    // MARK: - Initialization

    /// Initialize with required configuration
    /// - Parameter configuration: DRM configuration with server URL and FairPlay certificate
    public init(configuration: DRMConfiguration) {
        self.configuration = configuration
        self.sessionManager = MediaSessionManager(configuration: configuration)
        self.serverClient = MediaServerClient(configuration: configuration)
    }

    // MARK: - Session Management

    /// Start a new playback session
    /// - Parameters:
    ///   - userID: User identifier
    ///   - assetID: Asset identifier
    ///   - clientIP: Optional client IP
    ///   - geoRegion: Optional geo region
    /// - Returns: Session ID
    @discardableResult
    public func startSession(
        userID: String,
        assetID: String,
        clientIP: String? = nil,
        geoRegion: String? = nil
    ) async throws -> String {
        // End previous session if exists
        if sessionId != nil {
            try? await endSession()
        }

        // Start new session
        let newSessionId = try await sessionManager.startSession(
            userID: userID,
            assetID: assetID,
            clientIP: clientIP,
            geoRegion: geoRegion
        )

        self.sessionId = newSessionId

        // Setup content key session for FairPlay
        setupContentKeySession(sessionId: newSessionId)

        return newSessionId
    }

    /// End current session
    public func endSession() async throws {
        guard let sessionId else {
            return
        }

        // Stop playback
        stop()

        // End session on server
        try await sessionManager.endSession(sessionId: sessionId)

        // Cleanup - clear delegate reference first to break retain cycle
        contentKeySession?.setDelegate(nil, queue: nil)
        contentKeySession?.invalidateAllPersistableContentKeys(
            forApp: configuration.fpsCertificate,
            options: nil
        ) { _, _ in }
        contentKeySession = nil
        contentKeyDelegate = nil
        self.sessionId = nil
    }

    // MARK: - Playback Control

    /// Play DRM-protected HLS stream
    /// - Parameter url: HLS master playlist URL
    public func play(url: URL) async throws {
        guard sessionId != nil else {
            throw DRMPlayerError.noActiveSession
        }

        // Validate URL scheme (only secure protocols allowed)
        guard let scheme = url.scheme,
              ["https", "skd", "tdf3"].contains(scheme) else {
            throw DRMPlayerError.invalidURL
        }

        // Create player if needed
        if player == nil {
            player = AVPlayer()
        }

        // Create player item with asset
        let asset = AVURLAsset(url: url)

        // Associate asset with content key session
        contentKeySession?.addContentKeyRecipient(asset)

        let playerItem = AVPlayerItem(asset: asset)

        // Set up player item
        player?.replaceCurrentItem(with: playerItem)

        // Update state
        state = .playing
        await updateSessionState(.playing)

        // Start playback
        player?.play()
    }

    /// Pause playback
    public func pause() async {
        player?.pause()
        state = .paused
        await updateSessionState(.paused)
    }

    /// Resume playback
    public func resume() async {
        player?.play()
        state = .playing
        await updateSessionState(.playing)
    }

    /// Stop playback
    public func stop() {
        player?.pause()
        player?.replaceCurrentItem(with: nil)
        state = .idle
    }

    /// Seek to position
    /// - Parameter time: Target time
    public func seek(to time: CMTime) async {
        await player?.seek(to: time)
        if let position = player?.currentTime().seconds {
            await updateSessionState(.playing, position: position)
        }
    }

    // MARK: - Offline Support (iOS only)

    #if os(iOS)
        /// Request persistable key for offline playback
        /// - Parameter assetID: Asset identifier
        public func requestPersistableKey(for assetID: String) {
            contentKeyDelegate?.requestPersistableKey(for: assetID)
        }
    #endif

    // MARK: - Private Methods

    private func setupContentKeySession(sessionId: String) {
        // Create content key session for FairPlay
        let keySession = AVContentKeySession(keySystem: .fairPlayStreaming)

        // Create delegate
        let delegate = FairPlayContentKeyDelegate(
            configuration: configuration,
            serverClient: serverClient,
            sessionId: sessionId
        )

        // Set delegate
        let delegateQueue = DispatchQueue(label: "com.arkavo.mediakit.contentkey")
        keySession.setDelegate(delegate, queue: delegateQueue)

        self.contentKeySession = keySession
        self.contentKeyDelegate = delegate
    }

    private func updateSessionState(
        _ state: MediaSessionManager.ActiveSession.PlaybackState,
        position: Double? = nil
    ) async {
        guard let sessionId else { return }

        await sessionManager.updateState(
            sessionId: sessionId,
            state: state,
            position: position
        )
    }

    // MARK: - Cleanup

    deinit {
        // Ensure delegate is cleared to prevent retain cycles
        contentKeySession?.setDelegate(nil, queue: nil)
        contentKeyDelegate = nil
        contentKeySession = nil
    }

    // MARK: - Playback State

    public enum PlaybackState: Sendable, Equatable {
        case idle
        case loading
        case playing
        case paused
        case buffering
        case ended
        case error(Error)

        public static func == (lhs: PlaybackState, rhs: PlaybackState) -> Bool {
            switch (lhs, rhs) {
            case (.idle, .idle), (.loading, .loading), (.playing, .playing),
                 (.paused, .paused), (.buffering, .buffering), (.ended, .ended):
                return true
            case (.error, .error):
                return true
            default:
                return false
            }
        }
    }
}

/// DRM player errors
public enum DRMPlayerError: Error, LocalizedError {
    case noActiveSession
    case invalidURL
    case playbackFailed(Error)

    public var errorDescription: String? {
        switch self {
        case .noActiveSession:
            "No active playback session. Call startSession() first."
        case .invalidURL:
            "Invalid media URL. Only HTTPS, SKD, and TDF3 schemes are allowed."
        case let .playbackFailed(error):
            "Playback failed: \(error.localizedDescription)"
        }
    }
}
