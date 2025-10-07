import AVFoundation
import CryptoKit
import Foundation
import OpenTDFKit

#if canImport(UIKit) || canImport(AppKit)

/// AVContentKeySessionDelegate implementation for Standard TDF-protected media
///
/// Handles key requests from AVPlayer for .tdf segment files.
/// Downloads the .tdf archive, extracts the manifest, requests key unwrapping from KAS,
/// and provides the DEK to AVPlayer for decryption.
@available(iOS 18.0, macOS 15.0, tvOS 18.0, *)
public class StandardTDFContentKeyDelegate: NSObject, AVContentKeySessionDelegate, @unchecked Sendable {
    private let keyProvider: StandardTDFKeyProvider
    private let policy: MediaDRMPolicy
    private let deviceInfo: DeviceInfo
    private let sessionID: UUID

    /// Cache of unwrapped DEKs by segment index to avoid re-parsing .tdf files
    private var dekCache: [Int: SymmetricKey] = [:]
    private let cacheQueue = DispatchQueue(label: "com.arkavo.mediakit.dekcache")

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
                try await handleKeyRequest(keyRequest)
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
                try await handleKeyRequest(keyRequest)
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

    private func handleKeyRequest(_ keyRequest: AVContentKeyRequest) async throws {
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
              let assetParam = components.queryItems?.first(where: { $0.name == "asset" }),
              let assetID = assetParam.value,
              let userParam = components.queryItems?.first(where: { $0.name == "user" }),
              let userID = userParam.value
        else {
            throw ContentKeyError.invalidURL
        }

        // Check DEK cache first
        if let cachedDEK = cacheQueue.sync(execute: { dekCache[segmentIndex] }) {
            try provideKey(cachedDEK, to: keyRequest)
            return
        }

        // Download the .tdf segment file
        guard let tdfURL = try await fetchSegmentURL(assetID: assetID, segmentIndex: segmentIndex) else {
            throw ContentKeyError.segmentNotFound
        }

        let (tdfData, _) = try await URLSession.shared.data(from: tdfURL)

        // Parse TDF archive to extract manifest
        let reader = try TDFArchiveReader(data: tdfData)
        let manifest = try reader.manifest()

        // Encode manifest as base64 for key request
        let manifestData = try JSONEncoder().encode(manifest)
        let manifestBase64 = manifestData.base64EncodedString()

        // Create key access request
        let accessRequest = KeyAccessRequest(
            sessionID: sessionID,
            userID: userID,
            assetID: assetID,
            segmentIndex: segmentIndex,
            tdfManifest: manifestBase64
        )

        // Request key from provider (calls KAS or uses offline key)
        let response = try await keyProvider.requestKey(
            request: accessRequest,
            policy: policy,
            deviceInfo: deviceInfo
        )

        // Unwrap the DEK from the .tdf archive
        let dek = try await keyProvider.unwrapSegmentKey(
            tdfData: tdfData,
            useKASRewrap: false // Use offline unwrapping for now
        )

        // Cache the DEK
        cacheQueue.sync {
            dekCache[segmentIndex] = dek
        }

        // Provide key to AVPlayer
        try provideKey(dek, to: keyRequest)
    }

    private func provideKey(_ key: SymmetricKey, to keyRequest: AVContentKeyRequest) throws {
        // Extract key data
        let keyData = key.withUnsafeBytes { Data($0) }

        // Create content key response
        let keyResponse = AVContentKeyResponse(fairPlayStreamingKeyResponseData: keyData)
        keyRequest.processContentKeyResponse(keyResponse)
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
