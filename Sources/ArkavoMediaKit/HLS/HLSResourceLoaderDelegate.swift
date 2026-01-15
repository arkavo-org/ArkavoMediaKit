import AVFoundation
import CryptoKit
import Foundation
import OpenTDFKit

/// Custom URL scheme for TDF-protected HLS content
public let tdfHLSScheme = "tdf-hls"

/// AVAssetResourceLoaderDelegate for serving TDF-protected HLS content
///
/// Intercepts requests for:
/// - `tdf-hls://playlist.m3u8` - Returns the local playlist
/// - `tdf-hls://segments/N.enc` - Decrypts and returns segment data
/// - `tdf-hls://key` - Triggers key request via FairPlay or returns cached key
public class HLSResourceLoaderDelegate: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    private let localAsset: LocalHLSAsset
    private let extractor: HLSTDFExtractor
    private var symmetricKey: SymmetricKey?
    private let queue = DispatchQueue(label: "com.arkavo.hlsResourceLoader")

    /// Callback for key requests - implement for FairPlay integration
    public var onKeyRequest: ((HLSManifest) async throws -> SymmetricKey)?

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
        queue.sync {
            self.symmetricKey = key
        }
    }

    // MARK: - AVAssetResourceLoaderDelegate

    public func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
    ) -> Bool {
        guard let url = loadingRequest.request.url,
              url.scheme == tdfHLSScheme
        else {
            return false
        }

        // Handle different resource types
        let path = url.path
        if path.hasSuffix(".m3u8") {
            return handlePlaylistRequest(loadingRequest)
        } else if path.contains("/segments/") && path.hasSuffix(".enc") {
            return handleSegmentRequest(loadingRequest, path: path)
        } else if path == "/key" {
            return handleKeyRequest(loadingRequest)
        }

        return false
    }

    public func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        didCancel loadingRequest: AVAssetResourceLoadingRequest
    ) {
        // Handle cancellation if needed
    }

    // MARK: - Request Handlers

    private func handlePlaylistRequest(_ loadingRequest: AVAssetResourceLoadingRequest) -> Bool {
        queue.async { [weak self] in
            guard let self else { return }

            do {
                // Read and modify playlist to use our custom scheme
                var playlistContent = try String(contentsOf: localAsset.playlistURL, encoding: .utf8)

                // Replace segment paths with our custom scheme
                playlistContent = self.rewritePlaylistURLs(playlistContent)

                // Add key URI for FairPlay
                if !playlistContent.contains("#EXT-X-KEY:") {
                    // Insert key tag before first segment
                    let keyTag = "#EXT-X-KEY:METHOD=AES-128,URI=\"\(tdfHLSScheme)://key\"\n"
                    if let range = playlistContent.range(of: "#EXTINF:") {
                        playlistContent.insert(contentsOf: keyTag, at: range.lowerBound)
                    }
                }

                guard let data = playlistContent.data(using: .utf8) else {
                    loadingRequest.finishLoading(with: HLSResourceLoaderError.playlistEncodingFailed)
                    return
                }

                loadingRequest.contentInformationRequest?.contentType = "application/x-mpegURL"
                loadingRequest.contentInformationRequest?.contentLength = Int64(data.count)
                loadingRequest.contentInformationRequest?.isByteRangeAccessSupported = false

                loadingRequest.dataRequest?.respond(with: data)
                loadingRequest.finishLoading()
            } catch {
                loadingRequest.finishLoading(with: error)
            }
        }
        return true
    }

    private func handleSegmentRequest(_ loadingRequest: AVAssetResourceLoadingRequest, path: String) -> Bool {
        Task { [weak self] in
            guard let self else { return }

            do {
                // Extract segment index from path (e.g., "/segments/0.enc" -> 0)
                guard let indexString = path.components(separatedBy: "/").last?
                    .replacingOccurrences(of: ".enc", with: ""),
                    let segmentIndex = Int(indexString),
                    segmentIndex < localAsset.segmentURLs.count
                else {
                    loadingRequest.finishLoading(with: HLSResourceLoaderError.invalidSegmentPath)
                    return
                }

                // Get the symmetric key
                var key = queue.sync { self.symmetricKey }
                if key == nil {
                    // Key not yet available - need to request it
                    if let onKeyRequest = self.onKeyRequest {
                        key = try await onKeyRequest(self.localAsset.manifest)
                        self.setSymmetricKey(key!)
                    } else {
                        loadingRequest.finishLoading(with: HLSResourceLoaderError.keyNotAvailable)
                        return
                    }
                }

                guard let symmetricKey = key else {
                    loadingRequest.finishLoading(with: HLSResourceLoaderError.keyNotAvailable)
                    return
                }

                // Read encrypted segment
                let segmentURL = localAsset.segmentURLs[segmentIndex]
                let encryptedData = try Data(contentsOf: segmentURL)

                // Decrypt segment (async call to actor)
                let decryptedData = try await self.extractor.decryptSegment(
                    segmentData: encryptedData,
                    segmentIndex: segmentIndex,
                    symmetricKey: symmetricKey,
                    manifest: localAsset.manifest
                )

                // Return decrypted data
                loadingRequest.contentInformationRequest?.contentType = "video/MP2T"
                loadingRequest.contentInformationRequest?.contentLength = Int64(decryptedData.count)
                loadingRequest.contentInformationRequest?.isByteRangeAccessSupported = true

                if let dataRequest = loadingRequest.dataRequest {
                    let requestedOffset = Int(dataRequest.requestedOffset)
                    let requestedLength = dataRequest.requestedLength

                    let availableData: Data
                    if requestedOffset < decryptedData.count {
                        let endOffset = min(requestedOffset + requestedLength, decryptedData.count)
                        availableData = decryptedData.subdata(in: requestedOffset..<endOffset)
                    } else {
                        availableData = Data()
                    }

                    dataRequest.respond(with: availableData)
                }

                loadingRequest.finishLoading()
            } catch {
                loadingRequest.finishLoading(with: error)
            }
        }
        return true
    }

    private func handleKeyRequest(_ loadingRequest: AVAssetResourceLoadingRequest) -> Bool {
        queue.async { [weak self] in
            guard let self else { return }

            // If we have a key, return it as raw bytes for AES-128
            if let key = self.symmetricKey {
                let keyData = key.withUnsafeBytes { Data($0) }

                loadingRequest.contentInformationRequest?.contentType = "application/octet-stream"
                loadingRequest.contentInformationRequest?.contentLength = Int64(keyData.count)

                loadingRequest.dataRequest?.respond(with: keyData)
                loadingRequest.finishLoading()
                return
            }

            // Request key via callback
            if let onKeyRequest = self.onKeyRequest {
                Task {
                    do {
                        let key = try await onKeyRequest(self.localAsset.manifest)
                        self.setSymmetricKey(key)

                        let keyData = key.withUnsafeBytes { Data($0) }
                        loadingRequest.contentInformationRequest?.contentType = "application/octet-stream"
                        loadingRequest.contentInformationRequest?.contentLength = Int64(keyData.count)
                        loadingRequest.dataRequest?.respond(with: keyData)
                        loadingRequest.finishLoading()
                    } catch {
                        loadingRequest.finishLoading(with: error)
                    }
                }
            } else {
                loadingRequest.finishLoading(with: HLSResourceLoaderError.keyNotAvailable)
            }
        }
        return true
    }

    // MARK: - Helpers

    private func rewritePlaylistURLs(_ playlist: String) -> String {
        var result = playlist
        // Replace segment references with our custom scheme
        // Original: segments/0.enc
        // New: tdf-hls://segments/0.enc
        let lines = playlist.components(separatedBy: "\n")
        for line in lines {
            if line.hasPrefix("segments/") {
                let newLine = "\(tdfHLSScheme)://\(line)"
                result = result.replacingOccurrences(of: line, with: newLine)
            }
        }
        return result
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
    // Create URL with our custom scheme
    let playlistURL = URL(string: "\(tdfHLSScheme)://playlist.m3u8")!

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
public enum HLSResourceLoaderError: Error, LocalizedError {
    case playlistEncodingFailed
    case invalidSegmentPath
    case keyNotAvailable
    case decryptionFailed

    public var errorDescription: String? {
        switch self {
        case .playlistEncodingFailed:
            "Failed to encode playlist as UTF-8"
        case .invalidSegmentPath:
            "Invalid segment path in request"
        case .keyNotAvailable:
            "Decryption key not available"
        case .decryptionFailed:
            "Segment decryption failed"
        }
    }
}
