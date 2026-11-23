import Foundation
import os.log

/// HTTP client for media server API endpoints
public actor MediaServerClient {
    /// Maximum allowed response size for media server API calls (1 MiB)
    private static let maxResponseBytes = 1 * 1024 * 1024

    private let baseURL: URL
    private let session: URLSession
    private let ownsSession: Bool
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    private let logger = Logger(subsystem: "com.arkavo.mediakit", category: "network")

    /// Initialize with configuration
    /// - Parameter configuration: DRM configuration
    public init(configuration: DRMConfiguration) {
        self.baseURL = configuration.serverURL

        // Ephemeral URLSession with explicit timeouts, no disk caching, and redirect refusal
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = 30
        sessionConfig.timeoutIntervalForResource = 60
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalCacheData
        sessionConfig.urlCache = nil
        self.session = URLSession(configuration: sessionConfig, delegate: RedirectRefusal(), delegateQueue: nil)
        self.ownsSession = true

        // JSON encoder/decoder
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
    }

    /// Internal initializer allowing custom URLSession injection in tests
    init(configuration: DRMConfiguration, session: URLSession) {
        self.baseURL = configuration.serverURL
        self.session = session
        self.ownsSession = false
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
    }

    deinit {
        if ownsSession {
            session.finishTasksAndInvalidate()
        }
    }

    private func sessionURL(_ sessionId: String, trailingComponent: String? = nil) throws -> URL {
        try InputValidator.validateSessionID(sessionId)
        var url = baseURL
            .appendingPathComponent("media")
            .appendingPathComponent("v1")
            .appendingPathComponent("session")
            .appendingPathComponent(sessionId)
        if let trailingComponent {
            url = url.appendingPathComponent(trailingComponent)
        }
        return url
    }

    private func boundedRequest(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.boundedData(
                for: request,
                maxBytes: Self.maxResponseBytes,
                delegate: RedirectRefusal()
            )
        } catch BoundedResponseError.responseTooLarge {
            throw MediaServerError.invalidResponse
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw MediaServerError.invalidResponse
        }

        guard (200 ... 299).contains(httpResponse.statusCode) else {
            throw MediaServerError.httpError(statusCode: httpResponse.statusCode)
        }

        return (data, httpResponse)
    }

    /// Start a new playback session
    /// - Parameters:
    ///   - userID: User identifier
    ///   - assetID: Asset identifier
    ///   - clientIP: Optional client IP address
    ///   - geoRegion: Optional geo region code
    /// - Returns: Session start response with sessionId
    public func startSession(
        userID: String,
        assetID: String,
        clientIP: String? = nil,
        geoRegion: String? = nil
    ) async throws -> SessionStartResponse {
        let url = baseURL
            .appendingPathComponent("media")
            .appendingPathComponent("v1")
            .appendingPathComponent("session")
            .appendingPathComponent("start")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        // Build request body
        var body: [String: Any] = [
            "userID": userID,
            "assetID": assetID,
        ]
        if let ip = clientIP {
            body["clientIP"] = ip
        }
        if let region = geoRegion {
            body["geoRegion"] = region
        }

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, _) = try await boundedRequest(request)

        let decoded = try decoder.decode(SessionStartResponse.self, from: data)
        try InputValidator.validateSessionID(decoded.sessionId)
        return decoded
    }

    /// Request content decryption key (FairPlay CKC)
    /// - Parameters:
    ///   - sessionId: Session identifier from startSession
    ///   - spcData: FairPlay SPC data
    ///   - assetId: Asset identifier
    /// - Returns: Key response with CKC data
    public func requestKey(
        sessionId: String,
        spcData: Data,
        assetId: String
    ) async throws -> KeyRequestResponse {
        try InputValidator.validateSessionID(sessionId)
        let url = baseURL
            .appendingPathComponent("media")
            .appendingPathComponent("v1")
            .appendingPathComponent("key-request")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = KeyRequestBody(
            sessionId: sessionId,
            spcData: spcData,
            assetId: assetId
        )

        request.httpBody = try encoder.encode(body)

        let (data, _) = try await boundedRequest(request)

        return try decoder.decode(KeyRequestResponse.self, from: data)
    }

    /// Send session heartbeat
    /// - Parameters:
    ///   - sessionId: Session identifier
    ///   - state: Current playback state
    ///   - position: Optional playback position in seconds
    public func sendHeartbeat(
        sessionId: String,
        state: String,
        position: Double? = nil
    ) async throws {
        let url = try sessionURL(sessionId, trailingComponent: "heartbeat")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = HeartbeatRequest(state: state, position: position)
        request.httpBody = try encoder.encode(body)

        _ = try await boundedRequest(request)
    }

    /// End playback session
    /// - Parameter sessionId: Session identifier
    public func endSession(sessionId: String) async throws {
        let url = try sessionURL(sessionId)

        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"

        _ = try await boundedRequest(request)
    }
}

/// Media server communication errors
public enum MediaServerError: Error, LocalizedError {
    case invalidResponse
    case httpError(statusCode: Int)
    case networkError(Error)
    case decodingError(Error)

    public var errorDescription: String? {
        switch self {
        case .invalidResponse:
            "Invalid response from media server"
        case let .httpError(statusCode):
            "HTTP error: \(statusCode)"
        case let .networkError(error):
            "Network error: \(error.localizedDescription)"
        case let .decodingError(error):
            "Failed to decode response: \(error.localizedDescription)"
        }
    }
}
