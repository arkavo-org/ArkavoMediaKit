import AVFoundation
import CryptoKit
import Foundation
import OpenTDFKit
import Synchronization

#if canImport(UIKit) || canImport(AppKit)

/// AVContentKeySessionDelegate implementation for Standard TDF-protected media
///
/// Handles key requests from AVPlayer for .tdf segment files.
/// Downloads the .tdf archive, extracts the manifest, requests key unwrapping from KAS,
/// and provides the DEK to AVPlayer for decryption.
@available(iOS 18.0, macOS 15.0, tvOS 18.0, *)
public final class StandardTDFContentKeyDelegate: NSObject, AVContentKeySessionDelegate, Sendable {
    private struct CacheKey: Hashable, Sendable {
        let assetID: String
        let segmentIndex: Int
    }

    private let keyProvider: StandardTDFKeyProvider
    private let policy: MediaDRMPolicy
    private let deviceInfo: DeviceInfo
    private let sessionID: UUID

    /// Cache of unwrapped DEKs keyed by (assetID, segmentIndex) to avoid cross-asset collisions
    private let dekCache = Mutex<[CacheKey: SymmetricKey]>([:])

    private static let downloadSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        return URLSession(configuration: config, delegate: RedirectRefusal(), delegateQueue: nil)
    }()

    public init(
        keyProvider: StandardTDFKeyProvider,
        policy: MediaDRMPolicy,
        deviceInfo: DeviceInfo,
        sessionID: UUID
    ) {
        self.keyProvider = keyProvider
        self.policy = policy
        self.deviceInfo = deviceInfo
        self.sessionID = sessionID
        super.init()
    }

    // MARK: - AVContentKeySessionDelegate

    public func contentKeySession(
        _ session: AVContentKeySession,
        didProvide keyRequest: AVContentKeyRequest
    ) {
        Task {
            do {
                try await handleKeyRequest(keyRequest, isRenewal: false)
            } catch {
                keyRequest.processContentKeyResponseError(error)
            }
        }
    }

    public func contentKeySession(
        _ session: AVContentKeySession,
        didProvideRenewingContentKeyRequest keyRequest: AVContentKeyRequest
    ) {
        Task {
            do {
                try await handleKeyRequest(keyRequest, isRenewal: true)
            } catch {
                keyRequest.processContentKeyResponseError(error)
            }
        }
    }

    public func contentKeySession(
        _ session: AVContentKeySession,
        contentKeyRequest keyRequest: AVContentKeyRequest,
        didFailWithError err: Error
    ) {
        print("Content key request failed: \(err.localizedDescription)")
    }

    // MARK: - Key Request Handling

    struct ParsedKeyRequest: Equatable, Sendable {
        let assetID: String
        let segmentIndex: Int
        let userID: String?
    }

    /// Parses a `tdf3://.../key?asset=ID&segment=N[&user=UID]` key URI.
    /// `user` is optional because `HLSPlaylistGenerator` omits PII from playlists.
    static func parseKeyRequestURI(_ identifier: String) throws -> ParsedKeyRequest {
        guard let url = URL(string: identifier),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let segmentParam = components.queryItems?.first(where: { $0.name == "segment" }),
              let segmentIndexString = segmentParam.value,
              let segmentIndex = Int(segmentIndexString),
              segmentIndex >= 0,
              let assetParam = components.queryItems?.first(where: { $0.name == "asset" }),
              let assetID = assetParam.value
        else {
            throw ContentKeyError.invalidURL
        }

        try InputValidator.validateAssetID(assetID)
        let userID = components.queryItems?.first(where: { $0.name == "user" })?.value
        if let userID {
            try InputValidator.validateUserID(userID)
        }
        return ParsedKeyRequest(assetID: assetID, segmentIndex: segmentIndex, userID: userID)
    }

    private func handleKeyRequest(_ keyRequest: AVContentKeyRequest, isRenewal: Bool) async throws {
        // Extract and validate segment information from the key request identifier
        guard let identifier = keyRequest.identifier as? String else {
            throw ContentKeyError.invalidIdentifier
        }
        let parsed = try Self.parseKeyRequestURI(identifier)
        _ = (parsed, isRenewal)

        // Fail immediately before performing network fetches: FairPlay requires a KSM-signed CKC
        // generated from the player's SPC, and raw symmetric DEKs must never be passed as a CKC.
        throw ContentKeyError.notImplemented(
            "FairPlay CKC exchange is required; use TDFContentKeyDelegate for FairPlay playback."
        )
    }

    /// Fetch the .tdf segment URL
    ///
    /// ⚠️ **IMPLEMENTATION REQUIRED**
    ///
    /// This method must be implemented to retrieve the .tdf segment URL.
    ///
    /// ## Implementation Options:
    ///
    /// ### Option 1: Parse from HLS Manifest
    /// The segment URL is already in the HLS playlist, extract it from there:
    /// ```swift
    /// // Store playlist segments during loadStream()
    /// private var segmentURLs: [Int: URL] = [:]
    /// return segmentURLs[segmentIndex]
    /// ```
    ///
    /// ### Option 2: Construct from CDN Pattern
    /// Build the URL using a known pattern:
    /// ```swift
    /// return URL(string: "https://cdn.arkavo.net/\(assetID)/segment_\(segmentIndex).tdf")
    /// ```
    ///
    /// ### Option 3: Fetch from Metadata Service
    /// Query a service for the segment URL:
    /// ```swift
    /// let url = URL(string: "https://api.arkavo.net/assets/\(assetID)/segments/\(segmentIndex)")!
    /// let (data, _) = try await URLSession.shared.data(from: url)
    /// let response = try JSONDecoder().decode(SegmentURLResponse.self, from: data)
    /// return response.tdfURL
    /// ```
    private func fetchSegmentURL(assetID: String, segmentIndex: Int) async throws -> URL? {
        // TODO: CRITICAL - Implement segment URL fetching before production use
        throw ContentKeyError.notImplemented(
            "fetchSegmentURL() requires implementation. " +
            "See method documentation for integration options."
        )
    }
}

/// Content key errors
public enum ContentKeyError: Error, LocalizedError, Sendable {
    case invalidIdentifier
    case invalidURL
    case segmentNotFound
    case keyProcessingFailed
    case notImplemented(String)

    public var errorDescription: String? {
        switch self {
        case .invalidIdentifier:
            "Invalid content key identifier"
        case .invalidURL:
            "Invalid segment URL format"
        case .segmentNotFound:
            "TDF segment not found"
        case .keyProcessingFailed:
            "Failed to process content key"
        case let .notImplemented(message):
            "Not implemented: \(message)"
        }
    }
}

#endif
