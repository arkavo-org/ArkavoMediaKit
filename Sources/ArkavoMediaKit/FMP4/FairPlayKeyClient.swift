import AVFoundation
import Foundation

// MARK: - FairPlay Key Client

/// Client for FairPlay key delivery with TDF integration
public final class FairPlayKeyClient {
    // MARK: - Types

    /// Session information
    public struct Session {
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
    public struct KeyRequestConfig {
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

    private let serverURL: URL
    private let authToken: String?
    private let manifestBuilder: TDFManifestBuilder
    private var currentSession: Session?
    private var certificate: Data?

    // MARK: - Initialization

    /// Initialize FairPlay key client
    /// - Parameters:
    ///   - serverURL: Base URL of the media server (e.g., https://100.arkavo.net)
    ///   - authToken: Optional Bearer token for authenticated requests
    public init(serverURL: URL, authToken: String? = nil) {
        self.serverURL = serverURL
        self.authToken = authToken
        self.manifestBuilder = TDFManifestBuilder(kasURL: serverURL)
    }

    /// Add authorization header to request if auth token is available
    private func addAuthHeader(to request: inout URLRequest) {
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    // MARK: - Certificate

    /// Fetch FairPlay application certificate from server
    public func fetchCertificate() async throws -> Data {
        if let existing = certificate {
            return existing
        }

        let url = serverURL.appendingPathComponent("media/v1/certificate")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        addAuthHeader(to: &request)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw FairPlayKeyError.certificateFetchFailed
        }

        certificate = data
        return data
    }

    // MARK: - Session Management

    /// Start a new playback session
    public func startSession(userId: String, assetId: String) async throws -> Session {
        let url = serverURL.appendingPathComponent("media/v1/session/start")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        addAuthHeader(to: &request)

        let body: [String: Any] = [
            "userId": userId,
            "assetId": assetId,
            "protocol": "fairplay"
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let errorBody = String(data: data, encoding: .utf8) ?? ""
            throw FairPlayKeyError.sessionStartFailed(errorBody)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sessionId = json["sessionId"] as? String else {
            throw FairPlayKeyError.invalidSessionResponse
        }

        let session = Session(sessionId: sessionId, userId: userId, assetId: assetId)
        currentSession = session
        return session
    }

    /// Send session heartbeat
    public func sendHeartbeat() async throws {
        guard let session = currentSession else {
            throw FairPlayKeyError.noActiveSession
        }

        let url = serverURL.appendingPathComponent("media/v1/session/\(session.sessionId)/heartbeat")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        addAuthHeader(to: &request)

        let body: [String: Any] = [
            "userId": session.userId,
            "currentTime": Date().timeIntervalSince1970
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (_, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw FairPlayKeyError.heartbeatFailed
        }
    }

    /// End the current session
    public func endSession() async throws {
        guard let session = currentSession else {
            return
        }

        let url = serverURL.appendingPathComponent("media/v1/session/\(session.sessionId)")
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        addAuthHeader(to: &request)

        let body: [String: Any] = ["userId": session.userId]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (_, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw FairPlayKeyError.sessionEndFailed
        }

        currentSession = nil
    }

    // MARK: - Key Request

    /// Request CKC from server with TDF-wrapped content key
    /// - Parameters:
    ///   - spcData: Server Playback Context from AVContentKeyRequest
    ///   - config: Key request configuration with content key and IV
    /// - Returns: Content Key Context (CKC) data for AVContentKeyResponse
    public func requestCKC(spcData: Data, config: KeyRequestConfig) async throws -> Data {
        // Ensure we have a session
        let session: Session
        if let existing = currentSession, existing.assetId == config.assetId {
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
        addAuthHeader(to: &request)

        let body: [String: Any] = [
            "sessionId": session.sessionId,
            "userId": session.userId,
            "assetId": config.assetId,
            "spcData": spcData.base64EncodedString(),
            "tdfManifest": manifestData.base64EncodedString()
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let errorBody = String(data: data, encoding: .utf8) ?? ""
            throw FairPlayKeyError.ckcRequestFailed(errorBody)
        }

        // Parse CKC response
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ckcBase64 = json["wrappedKey"] as? String,
              let ckcData = Data(base64Encoded: ckcBase64) else {
            throw FairPlayKeyError.invalidCKCResponse
        }

        return ckcData
    }

    /// Request CKC with pre-wrapped key data (when TDF manifest is provided)
    public func requestCKC(spcData: Data, tdfManifest: Data) async throws -> Data {
        guard let session = currentSession else {
            throw FairPlayKeyError.noActiveSession
        }

        let url = serverURL.appendingPathComponent("media/v1/key-request")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        addAuthHeader(to: &request)

        let body: [String: Any] = [
            "sessionId": session.sessionId,
            "userId": session.userId,
            "assetId": session.assetId,
            "spcData": spcData.base64EncodedString(),
            "tdfManifest": tdfManifest.base64EncodedString()
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let errorBody = String(data: data, encoding: .utf8) ?? ""
            throw FairPlayKeyError.ckcRequestFailed(errorBody)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ckcBase64 = json["wrappedKey"] as? String,
              let ckcData = Data(base64Encoded: ckcBase64) else {
            throw FairPlayKeyError.invalidCKCResponse
        }

        return ckcData
    }

    // MARK: - Errors

    public enum FairPlayKeyError: Error, LocalizedError {
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
    public func createContentKeyDelegate() -> FMP4ContentKeyDelegate {
        FMP4ContentKeyDelegate(keyClient: self)
    }
}

// MARK: - FMP4 Content Key Delegate

/// AVContentKeySessionDelegate implementation for fMP4 FairPlay playback
public final class FMP4ContentKeyDelegate: NSObject, AVContentKeySessionDelegate {
    private let keyClient: FairPlayKeyClient
    private var keyConfig: FairPlayKeyClient.KeyRequestConfig?

    public init(keyClient: FairPlayKeyClient) {
        self.keyClient = keyClient
        super.init()
    }

    /// Set the key configuration for upcoming key requests
    public func setKeyConfig(_ config: FairPlayKeyClient.KeyRequestConfig) {
        self.keyConfig = config
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
        guard let config = keyConfig else {
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
