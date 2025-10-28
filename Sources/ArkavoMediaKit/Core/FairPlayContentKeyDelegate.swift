import AVFoundation
import Foundation
import os.log

/// FairPlay Streaming content key delegate
/// Implements AVContentKeySessionDelegate to handle key requests from AVPlayer
public final class FairPlayContentKeyDelegate: NSObject, AVContentKeySessionDelegate, @unchecked Sendable {
    private let configuration: DRMConfiguration
    private let serverClient: MediaServerClient
    private let sessionId: String

    /// Logger for DRM operations
    private let logger = Logger(subsystem: "com.arkavo.mediakit", category: "drm")

    /// Thread-safe cache for decryption keys (DEK)
    private let cacheQueue = DispatchQueue(label: "com.arkavo.mediakit.keycache")
    private var dekCache: [String: Data] = [:]
    private var cacheAccessOrder: [String] = []
    private let maxCacheSize = 50

    /// Directory for storing persistable content keys (iOS only)
    #if os(iOS)
        private lazy var persistableKeyDirectory: URL = {
            let documentsPath = NSSearchPathForDirectoriesInDomains(
                .documentDirectory,
                .userDomainMask,
                true
            ).first!
            let documentsURL = URL(fileURLWithPath: documentsPath)
            let keyDirectory = documentsURL.appendingPathComponent(".fairplay_keys", isDirectory: true)

            if !FileManager.default.fileExists(atPath: keyDirectory.path) {
                try? FileManager.default.createDirectory(
                    at: keyDirectory,
                    withIntermediateDirectories: false,
                    attributes: nil
                )
            }

            return keyDirectory
        }()

        /// Set of pending persistable key identifiers
        private var pendingPersistableKeys = Set<String>()
    #endif

    /// Initialize delegate
    /// - Parameters:
    ///   - configuration: DRM configuration
    ///   - serverClient: Media server client
    ///   - sessionId: Server-assigned session ID
    public init(
        configuration: DRMConfiguration,
        serverClient: MediaServerClient,
        sessionId: String
    ) {
        self.configuration = configuration
        self.serverClient = serverClient
        self.sessionId = sessionId
        super.init()
    }

    // MARK: - AVContentKeySessionDelegate

    /// Handle content key request from AVPlayer
    public func contentKeySession(
        _ session: AVContentKeySession,
        didProvide keyRequest: AVContentKeyRequest
    ) {
        Task {
            await handleStreamingKeyRequest(keyRequest)
        }
    }

    /// Handle renewing content key request
    public func contentKeySession(
        _ session: AVContentKeySession,
        didProvideRenewingContentKeyRequest keyRequest: AVContentKeyRequest
    ) {
        Task {
            await handleStreamingKeyRequest(keyRequest)
        }
    }

    /// Decide whether to retry failed key request
    public func contentKeySession(
        _ session: AVContentKeySession,
        shouldRetry keyRequest: AVContentKeyRequest,
        reason retryReason: AVContentKeyRequest.RetryReason
    ) -> Bool {
        switch retryReason {
        case .timedOut, .receivedResponseWithExpiredLease, .receivedObsoleteContentKey:
            return true
        default:
            return false
        }
    }

    /// Handle key request failure
    public func contentKeySession(
        _ session: AVContentKeySession,
        contentKeyRequest keyRequest: AVContentKeyRequest,
        didFailWithError err: Error
    ) {
        logger.error("Content key request failed: \(err.localizedDescription)")
    }

    #if os(iOS)
        /// Handle persistable content key request (iOS only)
        public func contentKeySession(
            _ session: AVContentKeySession,
            didProvide keyRequest: AVPersistableContentKeyRequest
        ) {
            Task {
                await handlePersistableKeyRequest(keyRequest)
            }
        }
    #endif

    // MARK: - Key Request Handling

    private func handleStreamingKeyRequest(_ keyRequest: AVContentKeyRequest) async {
        // Extract asset ID from key request identifier
        guard let assetID = extractAssetID(from: keyRequest) else {
            keyRequest.processContentKeyResponseError(
                ValidationError.missingContentKeyIdentifier
            )
            return
        }

        // Check cache first
        if let cachedKey = getCachedKey(for: assetID) {
            let keyResponse = AVContentKeyResponse(fairPlayStreamingKeyResponseData: cachedKey)
            keyRequest.processContentKeyResponse(keyResponse)
            return
        }

        #if os(iOS)
            // Check if we should request persistable key
            if shouldRequestPersistableKey(for: assetID) {
                do {
                    try keyRequest.respondByRequestingPersistableContentKeyRequestAndReturnError()
                    return
                } catch {
                    // Fall through to online key request
                    logger.warning("Persistable key request failed, falling back to online: \(error.localizedDescription)")
                }
            }
        #endif

        // Request online key
        await requestOnlineKey(keyRequest: keyRequest, assetID: assetID)
    }

    private func requestOnlineKey(keyRequest: AVContentKeyRequest, assetID: String) async {
        do {
            // Generate SPC and request CKC from server
            let (spcData, ckcData) = try await generateSPCAndRequestCKC(
                keyRequest: keyRequest,
                assetID: assetID
            )

            // Cache the key
            cacheKey(ckcData, for: assetID)

            // Provide key to AVPlayer
            let keyResponse = AVContentKeyResponse(fairPlayStreamingKeyResponseData: ckcData)
            keyRequest.processContentKeyResponse(keyResponse)

        } catch {
            keyRequest.processContentKeyResponseError(error)
        }
    }

    /// Generate SPC and request CKC from server
    /// - Parameters:
    ///   - keyRequest: Content key request from AVFoundation
    ///   - assetID: Asset identifier
    /// - Returns: Tuple of (SPC data, CKC data)
    private func generateSPCAndRequestCKC(
        keyRequest: AVContentKeyRequest,
        assetID: String
    ) async throws -> (Data, Data) {
        // Get FPS certificate
        let certificate = configuration.fpsCertificate

        // Prepare asset identifier data
        guard let assetIDData = assetID.data(using: .utf8) else {
            throw ValidationError.invalidContentKeyIdentifier(assetID)
        }

        // Generate SPC (Server Playback Context)
        let spcData = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            keyRequest.makeStreamingContentKeyRequestData(
                forApp: certificate,
                contentIdentifier: assetIDData,
                options: [AVContentKeyRequestProtocolVersionsKey: [1]]
            ) { spcData, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let spcData {
                    continuation.resume(returning: spcData)
                } else {
                    continuation.resume(throwing: KeyRequestError.invalidSPCData)
                }
            }
        }

        // Request CKC from server
        let response = try await serverClient.requestKey(
            sessionId: sessionId,
            spcData: spcData,
            assetId: assetID
        )

        // Decode CKC
        let ckcData = try response.decodedCKC()

        return (spcData, ckcData)
    }

    #if os(iOS)
        private func handlePersistableKeyRequest(_ keyRequest: AVPersistableContentKeyRequest) async {
            guard let assetID = extractAssetID(from: keyRequest) else {
                keyRequest.processContentKeyResponseError(
                    ValidationError.missingContentKeyIdentifier
                )
                return
            }

            do {
                // Check if key already persisted
                if let persistedKey = loadPersistedKey(for: assetID) {
                    let keyResponse = AVContentKeyResponse(fairPlayStreamingKeyResponseData: persistedKey)
                    keyRequest.processContentKeyResponse(keyResponse)
                    return
                }

                // Generate SPC and request CKC from server (reuse common method)
                let (_, ckcData) = try await generateSPCAndRequestCKC(
                    keyRequest: keyRequest,
                    assetID: assetID
                )

                // Create persistable key
                let persistableData = try keyRequest.persistableContentKey(fromKeyVendorResponse: ckcData)

                // Save to disk
                try savePersistedKey(persistableData, for: assetID)

                // Provide key to AVPlayer
                let keyResponse = AVContentKeyResponse(fairPlayStreamingKeyResponseData: ckcData)
                keyRequest.processContentKeyResponse(keyResponse)

                // Remove from pending (thread-safe)
                cacheQueue.sync {
                    pendingPersistableKeys.remove(assetID)
                }

            } catch {
                keyRequest.processContentKeyResponseError(error)
            }
        }
    #endif

    // MARK: - Helper Methods

    private func extractAssetID(from keyRequest: AVContentKeyRequest) -> String? {
        guard let identifier = keyRequest.identifier as? String else {
            return nil
        }

        // Support URL-based identifiers: skd://assetID or tdf3://assetID
        if let url = URL(string: identifier), let host = url.host {
            return host
        }

        // Fallback to raw identifier
        return identifier
    }

    private func getCachedKey(for assetID: String) -> Data? {
        cacheQueue.sync {
            // Update access order for LRU
            if let index = cacheAccessOrder.firstIndex(of: assetID) {
                cacheAccessOrder.remove(at: index)
                cacheAccessOrder.append(assetID)
            }
            return dekCache[assetID]
        }
    }

    private func cacheKey(_ keyData: Data, for assetID: String) {
        cacheQueue.sync {
            dekCache[assetID] = keyData

            // Update LRU access order
            cacheAccessOrder.removeAll { $0 == assetID }
            cacheAccessOrder.append(assetID)

            // Evict oldest if over limit
            while dekCache.count > maxCacheSize {
                if let oldest = cacheAccessOrder.first {
                    dekCache.removeValue(forKey: oldest)
                    cacheAccessOrder.removeFirst()
                }
            }
        }
    }

    #if os(iOS)
        private func shouldRequestPersistableKey(for assetID: String) -> Bool {
            cacheQueue.sync {
                pendingPersistableKeys.contains(assetID)
            } || loadPersistedKey(for: assetID) != nil
        }

        private func loadPersistedKey(for assetID: String) -> Data? {
            let keyURL = persistableKeyDirectory.appendingPathComponent(assetID)
            return try? Data(contentsOf: keyURL)
        }

        private func savePersistedKey(_ keyData: Data, for assetID: String) throws {
            let keyURL = persistableKeyDirectory.appendingPathComponent(assetID)
            try keyData.write(to: keyURL, options: .atomic)
        }

        /// Request persistable key for offline playback
        /// - Parameter assetID: Asset identifier
        public func requestPersistableKey(for assetID: String) {
            cacheQueue.sync {
                pendingPersistableKeys.insert(assetID)
            }
        }
    #endif
}
