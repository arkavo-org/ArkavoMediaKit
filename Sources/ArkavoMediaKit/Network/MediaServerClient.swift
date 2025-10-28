import Foundation
import os.log

/// HTTP client for media server API endpoints
public actor MediaServerClient {
    private let baseURL: URL
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    /// API endpoint paths
    private enum Endpoint {
        static let sessionStart = "/media/v1/session/start"
        static let keyRequest = "/media/v1/key-request"

        static func sessionHeartbeat(_ sessionId: String) -> String {
            "/media/v1/session/\(sessionId)/heartbeat"
        }

        static func sessionEnd(_ sessionId: String) -> String {
            "/media/v1/session/\(sessionId)"
        }
    }

    private let logger = Logger(subsystem: "com.arkavo.mediakit", category: "network")

    /// Initialize with configuration
    /// - Parameter configuration: DRM configuration
    public init(configuration: DRMConfiguration) {
        self.baseURL = configuration.serverURL

        // Configure URLSession with timeout
        let sessionConfig = URLSessionConfiguration.default
        sessionConfig.timeoutIntervalForRequest = 30
        sessionConfig.timeoutIntervalForResource = 60
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(configuration: sessionConfig)

        // JSON encoder/decoder
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
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
        let url = baseURL.appendingPathComponent(Endpoint.sessionStart)

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

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw MediaServerError.invalidResponse
        }

        guard (200 ... 299).contains(httpResponse.statusCode) else {
            throw MediaServerError.httpError(statusCode: httpResponse.statusCode)
        }

        return try decoder.decode(SessionStartResponse.self, from: data)
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
        let url = baseURL.appendingPathComponent(Endpoint.keyRequest)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = KeyRequestBody(
            sessionId: sessionId,
            spcData: spcData,
            assetId: assetId
        )

        request.httpBody = try encoder.encode(body)

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw MediaServerError.invalidResponse
        }

        guard (200 ... 299).contains(httpResponse.statusCode) else {
            throw MediaServerError.httpError(statusCode: httpResponse.statusCode)
        }

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
        let url = baseURL.appendingPathComponent(Endpoint.sessionHeartbeat(sessionId))

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = HeartbeatRequest(state: state, position: position)
        request.httpBody = try encoder.encode(body)

        let (_, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw MediaServerError.invalidResponse
        }

        guard (200 ... 299).contains(httpResponse.statusCode) else {
            throw MediaServerError.httpError(statusCode: httpResponse.statusCode)
        }
    }

    /// End playback session
    /// - Parameter sessionId: Session identifier
    public func endSession(sessionId: String) async throws {
        let url = baseURL.appendingPathComponent(Endpoint.sessionEnd(sessionId))

        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"

        let (_, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw MediaServerError.invalidResponse
        }

        guard (200 ... 299).contains(httpResponse.statusCode) else {
            throw MediaServerError.httpError(statusCode: httpResponse.statusCode)
        }
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
