import AVFoundation
import Combine
import CryptoKit
import Foundation
import OpenTDFKit
import Synchronization

#if canImport(UIKit) || canImport(AppKit)

/// AVPlayer wrapper for TDF3-protected HLS streams
@available(iOS 18.0, macOS 15.0, tvOS 18.0, *)
@MainActor
public class TDF3StreamingPlayer: ObservableObject {
    /// Default KAS server URL used when callers omit `kasURL`
    private static let defaultKASURL = URL(string: "https://100.arkavo.net")!

    private final class CleanupResources: @unchecked Sendable {
        let player: AVPlayer
        var timeObserver: Any?
        var tempDirectory: URL?

        init(player: AVPlayer) {
            self.player = player
        }

        func cleanup() {
            if let observer = timeObserver {
                player.removeTimeObserver(observer)
                timeObserver = nil
            }
            if let dir = tempDirectory {
                try? FileManager.default.removeItem(at: dir)
                tempDirectory = nil
            }
        }
    }

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

    private let cleanupResources: Mutex<CleanupResources>
    private var cancellables = Set<AnyCancellable>()
    private var loadGeneration: UInt64 = 0
    private var pendingReadyWait: (id: UUID, cancel: () -> Void)?

    /// Resource loader delegate for TDF-packaged HLS
    private var resourceLoaderDelegate: HLSResourceLoaderDelegate?

    /// Extracted local HLS asset
    private var localAsset: LocalHLSAsset?

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
        let avPlayer = AVPlayer()
        player = avPlayer
        cleanupResources = Mutex(CleanupResources(player: avPlayer))

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

    deinit {
        cleanupResources.withLock { $0.cleanup() }
    }

    /// Load and play TDF3-protected HLS stream
    public func loadStream(
        url: URL,
        session: MediaSession
    ) async throws {
        loadGeneration &+= 1
        let myGeneration = loadGeneration
        cancelCurrentReadyWait()
        cleanupLocalAsset()

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
        guard loadGeneration == myGeneration else {
            throw CancellationError()
        }

        status = .ready
    }

    /// Load TDF-packaged HLS stream for local playback
    ///
    /// Extracts HLS content from TDF archive and plays using custom resource loader.
    /// This enables offline playback of TDF-protected video.
    ///
    /// - Parameters:
    ///   - tdfData: TDF archive containing HLS content
    ///   - session: Media session for playback
    ///   - kasURL: Trusted KAS URL for manifest validation (defaults to `https://100.arkavo.net`)
    ///   - extractionLimits: Size and entry caps for archive extraction (defaults to `.default`)
    ///   - keyProvider: Callback to obtain decryption key from KAS
    public func loadFromTDF(
        tdfData: Data,
        session: MediaSession,
        kasURL: URL? = nil,
        extractionLimits: HLSTDFExtractor.ExtractionLimits = .default,
        keyProvider: @escaping (HLSManifest) async throws -> SymmetricKey
    ) async throws {
        loadGeneration &+= 1
        let myGeneration = loadGeneration
        cancelCurrentReadyWait()
        cleanupLocalAsset()

        self.session = session
        status = .loading

        // Create temp directory for extracted content
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tdf-hls-\(UUID().uuidString)")

        do {
            // Extract HLS from TDF
            let extractor = HLSTDFExtractor(kasURL: kasURL ?? Self.defaultKASURL, limits: extractionLimits)
            let localAsset = try await extractor.extract(
                tdfData: tdfData,
                outputDirectory: tempDir
            )

            // If another load or stop() superseded us while extracting, clean up our tempDir and abort
            guard loadGeneration == myGeneration else {
                try? FileManager.default.removeItem(at: tempDir)
                throw CancellationError()
            }

            self.localAsset = localAsset
            cleanupResources.withLock { $0.tempDirectory = localAsset.outputDirectory }

            // Create asset with custom resource loader (explicit host + path)
            let playlistURL = URL(string: "\(tdfHLSScheme)://local/playlist.m3u8")!
            let asset = AVURLAsset(url: playlistURL)

            // Create and configure resource loader delegate
            let delegate = HLSResourceLoaderDelegate(
                localAsset: localAsset,
                extractor: extractor
            )
            delegate.onKeyRequest = keyProvider
            self.resourceLoaderDelegate = delegate

            // Set delegate on resource loader
            let loaderQueue = DispatchQueue(label: "com.arkavo.hlsResourceLoader.player")
            asset.resourceLoader.setDelegate(delegate, queue: loaderQueue)

            // Create player item
            let playerItem = AVPlayerItem(asset: asset)

            // Replace current item
            player.replaceCurrentItem(with: playerItem)

            // Wait for ready to play
            try await waitForReadyToPlay(playerItem: playerItem)
            guard loadGeneration == myGeneration else {
                throw CancellationError()
            }

            status = .ready
        } catch {
            // Clean up extracted temp directory if extraction or player readiness fails
            try? FileManager.default.removeItem(at: tempDir)
            if self.localAsset?.outputDirectory == tempDir {
                self.localAsset = nil
                cleanupResources.withLock { $0.tempDirectory = nil }
            }
            throw error
        }
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
        loadGeneration &+= 1
        cancelCurrentReadyWait()
        player.pause()
        player.replaceCurrentItem(with: nil)
        session = nil
        status = .idle

        cleanupLocalAsset()
        resourceLoaderDelegate = nil
    }

    // MARK: - Private

    private func cancelCurrentReadyWait() {
        let pending = pendingReadyWait
        pendingReadyWait = nil
        pending?.cancel()
    }

    private func cleanupLocalAsset() {
        if let localAsset {
            try? FileManager.default.removeItem(at: localAsset.outputDirectory)
            self.localAsset = nil
            cleanupResources.withLock { $0.tempDirectory = nil }
        }
    }

    private func setupObservers() {
        // Observe time on main queue
        let interval = CMTime(seconds: 0.5, preferredTimescale: 600)
        let observer = player.addPeriodicTimeObserver(
            forInterval: interval,
            queue: .main
        ) { [weak self] time in
            MainActor.assumeIsolated {
                self?.currentTime = time.seconds
            }
        }
        cleanupResources.withLock { $0.timeObserver = observer }

        // Observe status on main queue so @MainActor @Published mutations are never off-thread
        player.publisher(for: \.currentItem?.status)
            .receive(on: DispatchQueue.main)
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

        // Observe duration on main queue
        player.publisher(for: \.currentItem?.duration)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] duration in
                guard let duration, duration.isNumeric else { return }
                self?.duration = duration.seconds
            }
            .store(in: &cancellables)
    }

    /// Synchronized, cancellation-safe KVO readiness waiter with `.initial` inspection and guaranteed one-shot resume.
    private final class ReadyWaitBox: @unchecked Sendable {
        var continuation: CheckedContinuation<Void, Error>?
        var observer: NSKeyValueObservation?
        var finished = false
        var pendingResult: Result<Void, Error>?
    }

    private func waitForReadyToPlay(playerItem: AVPlayerItem) async throws {
        let waitToken = UUID()
        defer {
            // Clear only if this waiter still owns the cancellation slot (never clobber a replacement load)
            if pendingReadyWait?.id == waitToken {
                pendingReadyWait = nil
            }
        }
        try await Self.waitForReadyToPlay(playerItem: playerItem) { [weak self] cancel in
            self?.pendingReadyWait = (id: waitToken, cancel: cancel)
        }
    }

    /// Internal testable helper for waiting on `AVPlayerItem.status` with `.initial` + `.new`,
    /// synchronized one-shot resume, no retain cycles, and task/item-replacement cancellation.
    static func waitForReadyToPlay(
        playerItem: AVPlayerItem,
        registerCancel: ((@escaping () -> Void) -> Void)? = nil
    ) async throws {
        let state = Mutex(ReadyWaitBox())

        let finish: @Sendable (Result<Void, Error>) -> Void = { result in
            let continuationToResume: CheckedContinuation<Void, Error>? = state.withLock { box in
                guard !box.finished else { return nil }
                box.finished = true
                box.observer?.invalidate()
                box.observer = nil
                if let continuation = box.continuation {
                    box.continuation = nil
                    return continuation
                } else {
                    // Resolved synchronously (e.g. .initial KVO or immediate cancellation) before continuation stored
                    box.pendingResult = result
                    return nil
                }
            }
            continuationToResume?.resume(with: result)
        }

        registerCancel?({ finish(.failure(CancellationError())) })

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let immediateResult: Result<Void, Error>? = state.withLock { box in
                    if let pending = box.pendingResult {
                        box.pendingResult = nil
                        return pending
                    }
                    if box.finished {
                        return .failure(CancellationError())
                    }
                    box.continuation = continuation
                    return nil
                }

                if let immediateResult {
                    continuation.resume(with: immediateResult)
                    return
                }

                if Task.isCancelled {
                    finish(.failure(CancellationError()))
                    return
                }

                // Observe with `.initial` and `.new` so an already-ready or already-failed item never hangs.
                // Captures only `finish` (no strong capture of `observer` -> zero retain cycle).
                let observation = playerItem.observe(\.status, options: [.initial, .new]) { item, _ in
                    switch item.status {
                    case .readyToPlay:
                        finish(.success(()))
                    case .failed:
                        finish(.failure(item.error ?? PlayerError.loadFailed))
                    default:
                        break
                    }
                }

                let shouldInvalidate = state.withLock { box -> Bool in
                    if box.finished {
                        return true
                    }
                    box.observer = observation
                    return false
                }
                if shouldInvalidate {
                    observation.invalidate()
                }
            }
        } onCancel: {
            finish(.failure(CancellationError()))
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
