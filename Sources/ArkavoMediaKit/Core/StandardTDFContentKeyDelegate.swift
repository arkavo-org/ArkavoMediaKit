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

    private func handleKeyRequest(_ keyRequest: AVContentKeyRequest, isRenewal: Bool) async throws {
        // Extract segment information from the key request identifier
        guard let identifier = keyRequest.identifier as? String,
              let url = URL(string: identifier)
        else {
            throw ContentKeyError.invalidIdentifier
        }

        // Parse segment index from URL
        // Expected format: tdf3://kas.arkavo.net/key?segment=N&asset=ID&user=UID
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let segmentParam = components.queryItems?.first(where: { $0.name == "segment" }),
              let segmentIndexString = segmentParam.value,
              let segmentIndex = Int(segmentIndexString),
              segmentIndex >= 0,
              let assetParam = components.queryItems?.first(where: { $0.name == "asset" }),
              let assetID = assetParam.value,
              let userParam = components.queryItems?.first(where: { $0.name == "user" }),
              let userID = userParam.value
        else {
            throw ContentKeyError.invalidURL
        }

        try InputValidator.validateAssetID(assetID)
        try InputValidator.validateUserID(userID)

        let cacheKey = CacheKey(assetID: assetID, segmentIndex: segmentIndex)

        // Renewals must always re-validate policy and never short-circuit on cached DEKs.
        if isRenewal {
            dekCache.withLock { _ = $0.removeValue(forKey: cacheKey) }
        }

        // Download the .tdf segment file over HTTPS without following redirects
        guard let tdfURL = try await fetchSegmentURL(assetID: assetID, segmentIndex: segmentIndex) else {
            throw ContentKeyError.segmentNotFound
        }
        guard tdfURL.scheme?.lowercased() == "https",
              let host = tdfURL.host, !host.isEmpty
        else {
            throw ContentKeyError.invalidURL
        }

        let (tdfData, response) = try await Self.downloadSession.data(from: tdfURL)
        guard let http = response as? HTTPURLResponse, (200 ... 299).contains(http.statusCode) else {
            throw ContentKeyError.segmentNotFound
        }

        // Parse TDF archive to extract manifest
        let reader = try TDFArchiveReader(data: tdfData)
        let manifest = try reader.manifest()

        // Encode manifest as base64 for key request
        let manifestData = try JSONEncoder().encode(manifest)
        let manifestBase64 = manifestData.base64EncodedString()

        // Always enforce session and policy checks before releasing any key
        let accessRequest = KeyAccessRequest(
            sessionID: sessionID,
            userID: userID,
            assetID: assetID,
            segmentIndex: segmentIndex,
            tdfManifest: manifestBase64
        )
        _ = try await keyProvider.requestKey(
            request: accessRequest,
            policy: policy,
            deviceInfo: deviceInfo
        )

        let dek: SymmetricKey
        if !isRenewal, let cachedDEK = dekCache.withLock({ $0[cacheKey] }) {
            dek = cachedDEK
        } else {
            dek = try await keyProvider.unwrapSegmentKey(
                tdfData: tdfData,
                useKASRewrap: false
            )
            dekCache.withLock { $0[cacheKey] = dek }
        }

        // Provide key to AVPlayer
        try provideKey(dek, to: keyRequest)
    }

    private func provideKey(_ key: SymmetricKey, to keyRequest: AVContentKeyRequest) throws {
        // FairPlay requires a KSM-signed CKC generated from the player's SPC; raw symmetric DEKs
        // must never be passed to AVContentKeyResponse(fairPlayStreamingKeyResponseData:).
        _ = key
        _ = keyRequest
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
