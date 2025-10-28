import Foundation

/// Response from POST /media/v1/session/start
public struct SessionStartResponse: Sendable, Codable {
    /// Server-assigned session identifier
    public let sessionId: String

    /// Session status
    public let status: String

    /// Optional session metadata
    public let metadata: [String: String]?

    enum CodingKeys: String, CodingKey {
        case sessionId = "sessionId"
        case status
        case metadata
    }

    public init(sessionId: String, status: String, metadata: [String: String]? = nil) {
        self.sessionId = sessionId
        self.status = status
        self.metadata = metadata
    }
}
