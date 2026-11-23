import AVFoundation
import CryptoKit
import Foundation
import OpenTDFKit
import Synchronization

/// Custom URL scheme for TDF-protected HLS content
public let tdfHLSScheme = "tdf-hls"

/// AVAssetResourceLoaderDelegate for serving TDF-protected HLS content
///
/// Intercepts requests for:
/// - `tdf-hls://local/playlist.m3u8` (or `tdf-hls://playlist.m3u8`) - Returns the local playlist
/// - `tdf-hls://local/segments/N.enc` (or `tdf-hls://segments/N.enc`) - Decrypts and returns segment data
public final class HLSResourceLoaderDelegate: NSObject, AVAssetResourceLoaderDelegate, Sendable {
    enum ResourceRoute: Equatable, Sendable {
        case playlist
        case segment(Int)
    }

    private struct KeyCallbackBox: @unchecked Sendable {
        let handler: (HLSManifest) async throws -> SymmetricKey
    }

    private struct InFlightSlot: Sendable {
        var task: Task<Void, Never>?
        var cancelled = false
    }

    private struct State: Sendable {
        var symmetricKey: SymmetricKey?
        var onKeyRequest: KeyCallbackBox?
        var inFlightTasks: [ObjectIdentifier: InFlightSlot] = [:]
    }

    private let localAsset: LocalHLSAsset
    private let extractor: HLSTDFExtractor
    private let state = Mutex(State())
    private let responseQueue = DispatchQueue(label: "com.arkavo.hlsResourceLoader")

    /// Callback for key requests - implement for KAS/FairPlay key retrieval
    public var onKeyRequest: ((HLSManifest) async throws -> SymmetricKey)? {
        get { state.withLock { $0.onKeyRequest?.handler } }
        set {
            let boxed = newValue.map(KeyCallbackBox.init(handler:))
            state.withLock { $0.onKeyRequest = boxed }
        }
    }

    /// Initialize with extracted local HLS asset
    ///
    /// - Parameters:
    ///   - localAsset: Extracted HLS content from TDF
    ///   - extractor: HLSTDFExtractor for segment decryption
    public init(
        localAsset: LocalHLSAsset,
        extractor: HLSTDFExtractor
    ) {
        self.localAsset = localAsset
        self.extractor = extractor
        super.init()
    }

    /// Set the symmetric key for segment decryption
    ///
    /// Call this after obtaining the key from KAS or FairPlay
    public func setSymmetricKey(_ key: SymmetricKey) {
        state.withLock { $0.symmetricKey = key }
    }

    // MARK: - URL Routing & Range Helpers

    /// Parses a `tdf-hls://` URL, supporting both authority-host form (`tdf-hls://playlist.m3u8`,
    /// `tdf-hls://segments/0.enc`) and host+path form (`tdf-hls://local/playlist.m3u8`,
    /// `tdf-hls://local/segments/0.enc`). Rejects negative indices, traversal, and raw key routes.
    static func route(for url: URL) -> ResourceRoute? {
        guard url.scheme?.lowercased() == tdfHLSScheme else {
            return nil
        }

        // Build normalized path components from host (unless placeholder host "local") and path
        var components: [String] = []
        if let host = url.host, !host.isEmpty, host.lowercased() != "local" {
            components.append(host)
        }
        let pathParts = url.path.split(separator: "/").map(String.init)
        components.append(contentsOf: pathParts)

        if components == ["playlist.m3u8"] {
            return .playlist
        }

        if components.count == 2,
           components[0] == "segments",
           components[1].hasSuffix(".enc")
        {
            let digits = String(components[1].dropLast(4))
            guard !digits.isEmpty,
                  digits.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let index = Int(digits),
                  index >= 0
            else {
                return nil
            }
            return .segment(index)
        }

        return nil
    }

    /// Safely computes a byte-range slice without negative-index or integer-overflow crashes.
    /// Returns `nil` when `requestedOffset < 0`, `requestedLength < 0`, or `dataCount < 0`.
    static func safeByteRange(requestedOffset: Int64, requestedLength: Int, dataCount: Int) -> Range<Int>? {
        guard requestedOffset >= 0, requestedLength >= 0, dataCount >= 0 else {
            return nil
        }
        guard requestedOffset < Int64(dataCount) else {
            return dataCount ..< dataCount
        }
        let start = Int(requestedOffset)
        let (rawEnd, overflow) = start.addingReportingOverflow(requestedLength)
        let end = overflow ? dataCount : min(rawEnd, dataCount)
        return start ..< end
    }

    /// Rewrites relative segment URIs line-by-line (never global `replacingOccurrences`) and strips
    /// `#EXT-X-KEY` tags so AVPlayer does not double-decrypt segments decrypted locally by the delegate.
    static func rewritePlaylistURLs(_ playlist: String) -> String {
        let normalized = playlist.replacingOccurrences(of: "\r\n", with: "\n")
        let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false)
        var rewritten: [String] = []
        rewritten.reserveCapacity(lines.count)

        for rawLine in lines {
            let line = String(rawLine)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#EXT-X-KEY:") {
                // Segments are decrypted locally in handleSegmentRequest; strip AES-128 key tag
                // to avoid AVPlayer double-decryption and raw key exposure.
                continue
            }
            if trimmed.hasPrefix("segments/"),
               trimmed.hasSuffix(".enc"),
               !trimmed.contains("..")
            {
                rewritten.append("\(tdfHLSScheme)://local/\(trimmed)")
            } else {
                rewritten.append(line)
            }
        }

        return rewritten.joined(separator: "\n")
    }

    // MARK: - AVAssetResourceLoaderDelegate

    public func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
    ) -> Bool {
        guard let url = loadingRequest.request.url,
              let route = Self.route(for: url)
        else {
            return false
        }

        switch route {
        case .playlist:
            return handlePlaylistRequest(loadingRequest)
        case let .segment(segmentIndex):
            return handleSegmentRequest(loadingRequest, segmentIndex: segmentIndex)
        }
    }

    public func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        didCancel loadingRequest: AVAssetResourceLoadingRequest
    ) {
        let id = ObjectIdentifier(loadingRequest)
        let task: Task<Void, Never>? = state.withLock { state in
            if var slot = state.inFlightTasks[id] {
                slot.cancelled = true
                let existingTask = slot.task
                state.inFlightTasks.removeValue(forKey: id)
                return existingTask
            }
            return nil
        }
        task?.cancel()
    }

    // MARK: - Request Handlers

    private func handlePlaylistRequest(_ loadingRequest: AVAssetResourceLoadingRequest) -> Bool {
        let requestBox = LoadingRequestBox(loadingRequest)
        responseQueue.async { [weak self] in
            guard let self else { return }
            let req = requestBox.request
            guard !req.isCancelled else { return }

            do {
                let rawPlaylist = try String(contentsOf: localAsset.playlistURL, encoding: .utf8)
                let playlistContent = Self.rewritePlaylistURLs(rawPlaylist)

                guard let data = playlistContent.data(using: .utf8) else {
                    req.finishLoading(with: HLSResourceLoaderError.playlistEncodingFailed)
                    return
                }

                req.contentInformationRequest?.contentType = "application/x-mpegURL"
                req.contentInformationRequest?.contentLength = Int64(data.count)
                req.contentInformationRequest?.isByteRangeAccessSupported = false

                req.dataRequest?.respond(with: data)
                req.finishLoading()
            } catch {
                req.finishLoading(with: error)
            }
        }
        return true
    }

    private func handleSegmentRequest(_ loadingRequest: AVAssetResourceLoadingRequest, segmentIndex: Int) -> Bool {
        let requestBox = LoadingRequestBox(loadingRequest)
        let requestID = ObjectIdentifier(loadingRequest)

        // Reserve slot before launching Task so a fast-finishing task or immediate didCancel cannot race/leak
        state.withLock { $0.inFlightTasks[requestID] = InFlightSlot() }

        let task = Task { [weak self] in
            guard let self else { return }
            defer {
                _ = self.state.withLock { $0.inFlightTasks.removeValue(forKey: requestID) }
            }

            do {
                try Task.checkCancellation()

                guard segmentIndex >= 0, segmentIndex < localAsset.segmentURLs.count else {
                    finishOnQueue(requestBox, error: HLSResourceLoaderError.invalidSegmentPath)
                    return
                }

                // Obtain the symmetric key without blocking a dispatch queue
                let (cachedKey, keyCallback) = state.withLock { ($0.symmetricKey, $0.onKeyRequest) }
                let symmetricKey: SymmetricKey
                if let cachedKey {
                    symmetricKey = cachedKey
                } else if let keyCallback {
                    let fetched = try await keyCallback.handler(localAsset.manifest)
                    try Task.checkCancellation()
                    setSymmetricKey(fetched)
                    symmetricKey = fetched
                } else {
                    finishOnQueue(requestBox, error: HLSResourceLoaderError.keyNotAvailable)
                    return
                }

                // Read and decrypt segment
                let segmentURL = localAsset.segmentURLs[segmentIndex]
                let encryptedData = try Data(contentsOf: segmentURL)
                try Task.checkCancellation()

                let decryptedData = try await extractor.decryptSegment(
                    segmentData: encryptedData,
                    segmentIndex: segmentIndex,
                    symmetricKey: symmetricKey,
                    manifest: localAsset.manifest
                )
                try Task.checkCancellation()

                responseQueue.async {
                    let req = requestBox.request
                    guard !req.isCancelled else { return }

                    req.contentInformationRequest?.contentType = "video/MP2T"
                    req.contentInformationRequest?.contentLength = Int64(decryptedData.count)
                    req.contentInformationRequest?.isByteRangeAccessSupported = true

                    if let dataRequest = req.dataRequest {
                        guard let range = Self.safeByteRange(
                            requestedOffset: dataRequest.requestedOffset,
                            requestedLength: dataRequest.requestedLength,
                            dataCount: decryptedData.count
                        ) else {
                            req.finishLoading(with: HLSResourceLoaderError.invalidByteRange)
                            return
                        }
                        let availableData = range.isEmpty ? Data() : decryptedData.subdata(in: range)
                        dataRequest.respond(with: availableData)
                    }

                    req.finishLoading()
                }
            } catch is CancellationError {
                return
            } catch {
                finishOnQueue(requestBox, error: error)
            }
        }

        // Attach the task only if the slot is still live (neither finished nor cancelled before registration)
        let shouldCancel = state.withLock { state -> Bool in
            guard var slot = state.inFlightTasks[requestID], !slot.cancelled else {
                return true
            }
            slot.task = task
            state.inFlightTasks[requestID] = slot
            return false
        }
        if shouldCancel {
            task.cancel()
        }
        return true
    }

    private func finishOnQueue(_ requestBox: LoadingRequestBox, error: Error) {
        responseQueue.async {
            let req = requestBox.request
            guard !req.isCancelled else { return }
            req.finishLoading(with: error)
        }
    }

    private struct LoadingRequestBox: @unchecked Sendable {
        let request: AVAssetResourceLoadingRequest
        init(_ request: AVAssetResourceLoadingRequest) {
            self.request = request
        }
    }
}

/// Create an AVURLAsset configured for TDF-protected HLS playback
///
/// - Parameters:
///   - localAsset: Extracted HLS content
///   - extractor: HLSTDFExtractor for decryption
///   - keyProvider: Callback to obtain decryption key
/// - Returns: Configured AVURLAsset and resource loader delegate
public func createTDFHLSAsset(
    localAsset: LocalHLSAsset,
    extractor: HLSTDFExtractor,
    keyProvider: @escaping (HLSManifest) async throws -> SymmetricKey
) -> (asset: AVURLAsset, delegate: HLSResourceLoaderDelegate) {
    // Create URL with our custom scheme using an explicit host and path
    let playlistURL = URL(string: "\(tdfHLSScheme)://local/playlist.m3u8")!

    // Create asset
    let asset = AVURLAsset(url: playlistURL)

    // Create and configure delegate
    let delegate = HLSResourceLoaderDelegate(
        localAsset: localAsset,
        extractor: extractor
    )
    delegate.onKeyRequest = keyProvider

    // Set delegate on resource loader
    let loaderQueue = DispatchQueue(label: "com.arkavo.hlsResourceLoader.asset")
    asset.resourceLoader.setDelegate(delegate, queue: loaderQueue)

    return (asset, delegate)
}

/// Errors that can occur during HLS resource loading
public enum HLSResourceLoaderError: Error, LocalizedError, Equatable, Sendable {
    case playlistEncodingFailed
    case invalidSegmentPath
    case invalidByteRange
    case keyNotAvailable
    case decryptionFailed

    public var errorDescription: String? {
        switch self {
        case .playlistEncodingFailed:
            "Failed to encode playlist as UTF-8"
        case .invalidSegmentPath:
            "Invalid segment path in request"
        case .invalidByteRange:
            "Invalid byte range in request"
        case .keyNotAvailable:
            "Decryption key not available"
        case .decryptionFailed:
            "Segment decryption failed"
        }
    }
}
