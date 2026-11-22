import AVFoundation
import Foundation
import Synchronization

// MARK: - FairPlay Key Client

/// Client for FairPlay key delivery with TDF integration
public final class FairPlayKeyClient: Sendable {
    /// Maximum allowed response body sizes
    private static let maxCertificateBytes = 64 * 1024
    private static let maxJSONResponseBytes = 1 * 1024 * 1024

    /// Dedicated ephemeral, redirect-refusing session shared across default clients
    private static let defaultSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        return URLSession(configuration: config, delegate: RedirectRefusal(), delegateQueue: nil)
    }()

    // MARK: - Types

    /// Session information
    public struct Session: Sendable {
        public let sessionId: String
        public let userId: String
        public let assetId: String
        public let createdAt: Date

        public init(sessionId: String, userId: String, assetId: String) {
            self.sessionId = sessionId
            self.userId = userId
            self.assetId = assetId
            self.createdAt = Date()
        }
    }

    /// Key request configuration
    @available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
    public struct KeyRequestConfig: Sendable {
        public let contentKey: Data      // 16-byte AES-128 key
        public let contentIV: Data       // 16-byte IV
        public let assetId: String
        public let userId: String

        public init(contentKey: Data, contentIV: Data, assetId: String, userId: String) {
            self.contentKey = contentKey
            self.contentIV = contentIV
            self.assetId = assetId
            self.userId = userId
        }
    }

    // MARK: - Properties

    private struct State: Sendable {
        var currentSession: Session?
        var certificate: Data?
    }

    private let serverURL: URL
    private let authToken: String?
    private let manifestBuilder: TDFManifestBuilder
    private let urlSession: URLSession
    private let state = Mutex(State())

    // MARK: - Initialization

    /// Initialize FairPlay key client
    /// - Parameters:
    ///   - serverURL: Base URL of the media server (must use HTTPS, e.g., https://100.arkavo.net)
    ///   - authToken: Optional Bearer token for authenticated requests
    public init(serverURL: URL, authToken: String? = nil) {
        self.serverURL = serverURL
        self.authToken = authToken
        self.manifestBuilder = TDFManifestBuilder(kasURL: serverURL)
        self.urlSession = Self.defaultSession
    }

    /// Internal initializer allowing custom URLSession injection in tests
    init(serverURL: URL, authToken: String? = nil, urlSession: URLSession) {
        self.serverURL = serverURL
        self.authToken = authToken
        self.manifestBuilder = TDFManifestBuilder(kasURL: serverURL, urlSession: urlSession)
        self.urlSession = urlSession
    }

    /// Read current session snapshot (internal for testing)
    var activeSession: Session? {
        state.withLock { $0.currentSession }
    }

    private func validateHTTPSServerURL() throws {
        guard serverURL.scheme?.lowercased() == "https",
              let host = serverURL.host, !host.isEmpty
        else {
            throw FairPlayKeyError.insecureServerURL
        }
    }

    private func sessionEndpointURL(sessionId: String, trailingComponent: String? = nil) throws -> URL {
        try validateHTTPSServerURL()
        do {
            try InputValidator.validateSessionID(sessionId)
        } catch {
            throw FairPlayKeyError.invalidSessionResponse
        }
        var url = serverURL
            .appendingPathComponent("media")
            .appendingPathComponent("v1")
            .appendingPathComponent("session")
            .appendingPathComponent(sessionId)
        if let trailingComponent {
            url = url.appendingPathComponent(trailingComponent)
        }
        return url
    }

    /// Prepare a request for the KAS/media server: opt into HTTP/3, set timeouts, disable caching, and add auth.
    private func prepareRequest(_ request: inout URLRequest) {
        request.assumesHTTP3Capable = true
        request.timeoutInterval = 30
        request.cachePolicy = .reloadIgnoringLocalCacheData
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    // MARK: - Certificate

    /// Fetch FairPlay application certificate from server
    public func fetchCertificate() async throws -> Data {
        try validateHTTPSServerURL()
        if let existing = state.withLock({ $0.certificate }) {
            return existing
        }

        let url = serverURL.appendingPathComponent("media/v1/certificate")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        prepareRequest(&request)

        let (data, response) = try await urlSession.data(for: request, delegate: RedirectRefusal())

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw FairPlayKeyError.certificateFetchFailed
        }
        guard !data.isEmpty, data.count <= Self.maxCertificateBytes else {
            throw FairPlayKeyError.certificateFetchFailed
        }

        state.withLock { $0.certificate = data }
        return data
    }

    // MARK: - Session Management

    /// Start a new playback session
    public func startSession(userId: String, assetId: String) async throws -> Session {
        try validateHTTPSServerURL()
        let url = serverURL.appendingPathComponent("media/v1/session/start")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        prepareRequest(&request)

        let body: [String: Any] = [
            "userId": userId,
            "assetId": assetId,
            "protocol": "fairplay"
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await urlSession.data(for: request, delegate: RedirectRefusal())

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw FairPlayKeyError.sessionStartFailed("HTTP \(statusCode)")
        }
        guard data.count <= Self.maxJSONResponseBytes else {
            throw FairPlayKeyError.invalidSessionResponse
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sessionId = json["sessionId"] as? String,
              (try? InputValidator.validateSessionID(sessionId)) != nil
        else {
            throw FairPlayKeyError.invalidSessionResponse
        }

        let session = Session(sessionId: sessionId, userId: userId, assetId: assetId)
        state.withLock { $0.currentSession = session }
        return session
    }

    /// Send session heartbeat
    public func sendHeartbeat() async throws {
        guard let session = state.withLock({ $0.currentSession }) else {
            throw FairPlayKeyError.noActiveSession
        }

        let url = try sessionEndpointURL(sessionId: session.sessionId, trailingComponent: "heartbeat")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        prepareRequest(&request)

        let body: [String: Any] = [
            "userId": session.userId,
            "currentTime": Date().timeIntervalSince1970
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (_, response) = try await urlSession.data(for: request, delegate: RedirectRefusal())

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw FairPlayKeyError.heartbeatFailed
        }
    }

    /// End the current session (never clears a newer session started concurrently during the network call)
    public func endSession() async throws {
        guard let session = state.withLock({ $0.currentSession }) else {
            return
        }

        let url = try sessionEndpointURL(sessionId: session.sessionId)
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        prepareRequest(&request)

        let body: [String: Any] = ["userId": session.userId]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (_, response) = try await urlSession.data(for: request, delegate: RedirectRefusal())

        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw FairPlayKeyError.sessionEndFailed
        }

        // Only clear if the session has not been replaced by a newer startSession() while awaiting
        state.withLock { s in
            if s.currentSession?.sessionId == session.sessionId {
                s.currentSession = nil
            }
        }
    }

    // MARK: - Key Request

    /// Request CKC from server with TDF-wrapped content key
    /// - Parameters:
    ///   - spcData: Server Playback Context from AVContentKeyRequest
    ///   - config: Key request configuration with content key and IV
    /// - Returns: Content Key Context (CKC) data for AVContentKeyResponse
    @available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
    public func requestCKC(spcData: Data, config: KeyRequestConfig) async throws -> Data {
        try validateHTTPSServerURL()

        // Ensure we have a session
        let session: Session
        if let existing = state.withLock({ $0.currentSession }), existing.assetId == config.assetId {
            session = existing
        } else {
            session = try await startSession(userId: config.userId, assetId: config.assetId)
        }

        // Build TDF manifest with wrapped key
        let manifestData = try await manifestBuilder.buildFairPlayKeyRequest(
            contentKey: config.contentKey,
            iv: config.contentIV,
            assetID: config.assetId
        )

        // Request CKC
        let url = serverURL.appendingPathComponent("media/v1/key-request")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        prepareRequest(&request)

        let body: [String: Any] = [
            "sessionId": session.sessionId,
            "userId": session.userId,
            "assetId": config.assetId,
            "spcData": spcData.base64EncodedString(),
            "tdfManifest": manifestData.base64EncodedString()
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await urlSession.data(for: request, delegate: RedirectRefusal())

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw FairPlayKeyError.ckcRequestFailed("HTTP \(statusCode)")
        }
        guard data.count <= Self.maxJSONResponseBytes else {
            throw FairPlayKeyError.invalidCKCResponse
        }

        // Parse CKC response (reject empty CKC)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ckcBase64 = json["wrappedKey"] as? String,
              let ckcData = Data(base64Encoded: ckcBase64),
              !ckcData.isEmpty
        else {
            throw FairPlayKeyError.invalidCKCResponse
        }

        return ckcData
    }

    /// Request CKC with pre-wrapped key data (when TDF manifest is provided)
    public func requestCKC(spcData: Data, tdfManifest: Data) async throws -> Data {
        try validateHTTPSServerURL()
        guard let session = state.withLock({ $0.currentSession }) else {
            throw FairPlayKeyError.noActiveSession
        }

        let url = serverURL.appendingPathComponent("media/v1/key-request")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        prepareRequest(&request)

        let body: [String: Any] = [
            "sessionId": session.sessionId,
            "userId": session.userId,
            "assetId": session.assetId,
            "spcData": spcData.base64EncodedString(),
            "tdfManifest": tdfManifest.base64EncodedString()
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await urlSession.data(for: request, delegate: RedirectRefusal())

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw FairPlayKeyError.ckcRequestFailed("HTTP \(statusCode)")
        }
        guard data.count <= Self.maxJSONResponseBytes else {
            throw FairPlayKeyError.invalidCKCResponse
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ckcBase64 = json["wrappedKey"] as? String,
              let ckcData = Data(base64Encoded: ckcBase64),
              !ckcData.isEmpty
        else {
            throw FairPlayKeyError.invalidCKCResponse
        }

        return ckcData
    }

    // MARK: - Errors

    public enum FairPlayKeyError: Error, LocalizedError, Equatable, Sendable {
        case insecureServerURL
        case certificateFetchFailed
        case sessionStartFailed(String)
        case invalidSessionResponse
        case noActiveSession
        case heartbeatFailed
        case sessionEndFailed
        case ckcRequestFailed(String)
        case invalidCKCResponse

        public var errorDescription: String? {
            switch self {
            case .insecureServerURL:
                return "FairPlay server URL must use HTTPS"
            case .certificateFetchFailed:
                return "Failed to fetch FairPlay certificate"
            case .sessionStartFailed(let error):
                return "Failed to start session: \(error)"
            case .invalidSessionResponse:
                return "Invalid session response from server"
            case .noActiveSession:
                return "No active playback session"
            case .heartbeatFailed:
                return "Session heartbeat failed"
            case .sessionEndFailed:
                return "Failed to end session"
            case .ckcRequestFailed(let error):
                return "CKC request failed: \(error)"
            case .invalidCKCResponse:
                return "Invalid CKC response from server"
            }
        }
    }
}

// MARK: - AVContentKeySession Integration

extension FairPlayKeyClient {
    /// Create AVContentKeySession delegate for FairPlay playback
    @available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
    public func createContentKeyDelegate() -> FMP4ContentKeyDelegate {
        FMP4ContentKeyDelegate(keyClient: self)
    }
}

// MARK: - FMP4 Content Key Delegate

/// AVContentKeySessionDelegate implementation for fMP4 FairPlay playback
@available(*, deprecated, message: "Sends a manifest with no policy, which arks refuses since PR #75. Package with FMP4RecordingProtectionService and play with TDFContentKeyDelegate given the archive manifest.")
public final class FMP4ContentKeyDelegate: NSObject, AVContentKeySessionDelegate, Sendable {
    private let keyClient: FairPlayKeyClient
    private let keyConfigStorage = Mutex<FairPlayKeyClient.KeyRequestConfig?>(nil)

    public init(keyClient: FairPlayKeyClient) {
        self.keyClient = keyClient
        super.init()
    }

    /// Set the key configuration for upcoming key requests
    public func setKeyConfig(_ config: FairPlayKeyClient.KeyRequestConfig) {
        keyConfigStorage.withLock { $0 = config }
    }

    /// Read the key configuration (internal for testing)
    var currentKeyConfig: FairPlayKeyClient.KeyRequestConfig? {
        keyConfigStorage.withLock { $0 }
    }

    // MARK: - AVContentKeySessionDelegate

    public func contentKeySession(_ session: AVContentKeySession,
                                   didProvide keyRequest: AVContentKeyRequest) {
        Task {
            await handleKeyRequest(keyRequest)
        }
    }

    public func contentKeySession(_ session: AVContentKeySession,
                                   didProvideRenewingContentKeyRequest keyRequest: AVContentKeyRequest) {
        Task {
            await handleKeyRequest(keyRequest)
        }
    }

    public func contentKeySession(_ session: AVContentKeySession,
                                   shouldRetry keyRequest: AVContentKeyRequest,
                                   reason: AVContentKeyRequest.RetryReason) -> Bool {
        return reason == .timedOut || reason == .receivedResponseWithExpiredLease
    }

    public func contentKeySession(_ session: AVContentKeySession,
                                   contentKeyRequest keyRequest: AVContentKeyRequest,
                                   didFailWithError error: Error) {
        print("FMP4ContentKeyDelegate: Key request failed - \(error.localizedDescription)")
    }

    // MARK: - Key Request Handling

    private func handleKeyRequest(_ keyRequest: AVContentKeyRequest) async {
        guard let config = keyConfigStorage.withLock({ $0 }) else {
            let error = NSError(domain: "FMP4ContentKeyDelegate", code: 1,
                               userInfo: [NSLocalizedDescriptionKey: "No key configuration set"])
            keyRequest.processContentKeyResponseError(error)
            return
        }

        do {
            // Fetch certificate
            let certificate = try await keyClient.fetchCertificate()

            // Generate SPC
            let contentIdData = config.assetId.data(using: .utf8) ?? Data()
            let spcData = try await keyRequest.makeStreamingContentKeyRequestData(
                forApp: certificate,
                contentIdentifier: contentIdData
            )

            // Request CKC from server
            let ckcData = try await keyClient.requestCKC(spcData: spcData, config: config)

            // Deliver key to player
            let response = AVContentKeyResponse(fairPlayStreamingKeyResponseData: ckcData)
            keyRequest.processContentKeyResponse(response)

        } catch {
            keyRequest.processContentKeyResponseError(error)
        }
    }
}
