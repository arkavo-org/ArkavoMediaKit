import AVFoundation
import Combine
import Foundation
import OpenTDFKit

#if canImport(UIKit) || canImport(AppKit)

/// AVPlayer wrapper for TDF3-protected HLS streams
@available(iOS 18.0, macOS 15.0, tvOS 18.0, *)
@MainActor
public class TDF3StreamingPlayer: ObservableObject {
    /// The underlying AVPlayer
    public let player: AVPlayer

    /// Content key session for handling Standard TDF keys
    private let contentKeySession: AVContentKeySession

    /// Content key delegate
    private let contentKeyDelegate: StandardTDFContentKeyDelegate

    /// Current playback session
    @Published public private(set) var session: MediaSession?

    /// Player status
    @Published public private(set) var status: PlayerStatus = .idle

    /// Current time
    @Published public private(set) var currentTime: TimeInterval = 0

    /// Duration
    @Published public private(set) var duration: TimeInterval = 0

    private var timeObserver: Any?
    private var cancellables = Set<AnyCancellable>()

    public enum PlayerStatus: Sendable {
        case idle
        case loading
        case ready
        case playing
        case paused
        case failed(Error)
    }

    public init(
        keyProvider: StandardTDFKeyProvider,
        policy: MediaDRMPolicy,
        deviceInfo: DeviceInfo,
        sessionID: UUID
    ) {
        player = AVPlayer()

        // Create content key session
        contentKeySession = AVContentKeySession(keySystem: .fairPlayStreaming)

        // Create delegate
        contentKeyDelegate = StandardTDFContentKeyDelegate(
            keyProvider: keyProvider,
            policy: policy,
            deviceInfo: deviceInfo,
            sessionID: sessionID
        )

        // Set delegate
        let delegateQueue = DispatchQueue(label: "com.arkavo.mediakit.contentkey")
        contentKeySession.setDelegate(contentKeyDelegate, queue: delegateQueue)

        setupObservers()
    }

    // Note: Removed deinit due to Swift 6 Sendable constraints
    // The timeObserver is automatically cleaned up when the player is deallocated

    /// Load and play TDF3-protected HLS stream
    public func loadStream(
        url: URL,
        session: MediaSession
    ) async throws {
        self.session = session
        status = .loading

        // Create player item
        let asset = AVURLAsset(url: url)

        // Associate asset with content key session
        contentKeySession.addContentKeyRecipient(asset)

        let playerItem = AVPlayerItem(asset: asset)

        // Replace current item
        player.replaceCurrentItem(with: playerItem)

        // Wait for ready to play
        try await waitForReadyToPlay(playerItem: playerItem)

        status = .ready
    }

    /// Play the current stream
    public func play() {
        player.play()
        status = .playing
    }

    /// Pause playback
    public func pause() {
        player.pause()
        status = .paused
    }

    /// Seek to time
    public func seek(to time: TimeInterval) async {
        let cmTime = CMTime(seconds: time, preferredTimescale: 600)
        await player.seek(to: cmTime)
    }

    /// Stop playback and clean up
    public func stop() {
        player.pause()
        player.replaceCurrentItem(with: nil)
        session = nil
        status = .idle
    }

    // MARK: - Private

    private func setupObservers() {
        // Observe time
        let interval = CMTime(seconds: 0.5, preferredTimescale: 600)
        timeObserver = player.addPeriodicTimeObserver(
            forInterval: interval,
            queue: .main
        ) { [weak self] time in
            self?.currentTime = time.seconds
        }

        // Observe status
        player.publisher(for: \.currentItem?.status)
            .sink { [weak self] status in
                guard let status else { return }
                switch status {
                case .failed:
                    if let error = self?.player.currentItem?.error {
                        self?.status = .failed(error)
                    }
                default:
                    break
                }
            }
            .store(in: &cancellables)

        // Observe duration
        player.publisher(for: \.currentItem?.duration)
            .sink { [weak self] duration in
                guard let duration, duration.isNumeric else { return }
                self?.duration = duration.seconds
            }
            .store(in: &cancellables)
    }

    private func waitForReadyToPlay(playerItem: AVPlayerItem) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            var observer: NSKeyValueObservation?
            observer = playerItem.observe(\.status, options: [.new]) { item, _ in
                switch item.status {
                case .readyToPlay:
                    observer?.invalidate()
                    continuation.resume()
                case .failed:
                    observer?.invalidate()
                    if let error = item.error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(throwing: PlayerError.loadFailed)
                    }
                default:
                    break
                }
            }
        }
    }
}

/// Player errors
public enum PlayerError: Error, LocalizedError {
    case loadFailed
    case invalidURL
    case noSession

    public var errorDescription: String? {
        switch self {
        case .loadFailed: "Failed to load stream"
        case .invalidURL: "Invalid stream URL"
        case .noSession: "No active session"
        }
    }
}

#endif
