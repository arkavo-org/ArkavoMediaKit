import AVFoundation
import Foundation
import os.log

// MARK: - FairPlay Debug Configuration

/// Global configuration for FairPlay debugging
public enum FairPlayDebugConfig {
    /// Enable verbose debug logging (set to false for production)
    #if DEBUG
        public nonisolated(unsafe) static var isVerboseLoggingEnabled = true
    #else
        public nonisolated(unsafe) static var isVerboseLoggingEnabled = false
    #endif
}

// MARK: - FairPlay Debug Logger

private let fairPlayLog = OSLog(subsystem: "com.arkavo.mediakit", category: "FairPlay")

/// Debug logger for FairPlay key exchange
enum FairPlayDebug {
    static func log(_ message: String, type: OSLogType = .debug) {
        guard FairPlayDebugConfig.isVerboseLoggingEnabled else { return }
        os_log("%{public}@", log: fairPlayLog, type: type, message)
        print("🎬 [FairPlay] \(message)")
    }

    static func logData(_ label: String, data: Data, maxBytes: Int = 64) {
        guard FairPlayDebugConfig.isVerboseLoggingEnabled else { return }
        let hex = data.prefix(maxBytes).map { String(format: "%02x", $0) }.joined(separator: " ")
        let truncated = data.count > maxBytes ? "... (\(data.count) bytes total)" : ""
        log("\(label): \(hex)\(truncated)")
    }

    static func logRequest(_ method: String, url: URL, body: Data?) {
        guard FairPlayDebugConfig.isVerboseLoggingEnabled else { return }
        log("→ \(method) \(url.absoluteString)")
        if let body = body, let json = try? JSONSerialization.jsonObject(with: body),
           let pretty = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted),
           let str = String(data: pretty, encoding: .utf8)
        {
            // Truncate long values like wrappedKey and spcData
            let truncated = str.replacingOccurrences(
                of: #""[A-Za-z0-9+/=]{100,}""#,
                with: "\"<base64 truncated>\"",
                options: .regularExpression
            )
            log("   Body: \(truncated)")
        }
    }

    static func logResponse(_ statusCode: Int, data: Data) {
        guard FairPlayDebugConfig.isVerboseLoggingEnabled else { return }
        if let str = String(data: data, encoding: .utf8) {
            log("← HTTP \(statusCode): \(str.prefix(500))")
        } else {
            log("← HTTP \(statusCode): \(data.count) bytes (binary)")
        }
    }
}

// MARK: - FairPlay Errors

/// Errors that can occur during FairPlay key exchange
public enum FairPlayError: Error, LocalizedError, Sendable {
    case sessionStartFailed(String)
    case certificateFetchFailed(String)
    case spcGenerationFailed(String)
    case ckcRequestFailed(String)
    case invalidCKCResponse(String)
    case manifestEncodingFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .sessionStartFailed(reason):
            "Failed to start FairPlay session: \(reason)"
        case let .certificateFetchFailed(reason):
            "Failed to fetch FairPlay certificate: \(reason)"
        case let .spcGenerationFailed(reason):
            "Failed to generate SPC: \(reason)"
        case let .ckcRequestFailed(reason):
            "Failed to request CKC: \(reason)"
        case let .invalidCKCResponse(reason):
            "Invalid CKC response: \(reason)"
        case let .manifestEncodingFailed(reason):
            "Failed to encode TDF manifest: \(reason)"
        }
    }
}

// MARK: - FairPlay Manifest Protocol

/// Protocol for manifest types that can be used with FairPlay key exchange
public protocol FairPlayManifestProtocol: Sendable {
    var assetID: String { get }
    var kasURL: String { get }
    var wrappedKey: String { get }
    var algorithm: String { get }
    var iv: String { get }
}

// MARK: - Default FairPlay Manifest Implementation

/// Default manifest implementation for FairPlay key exchange
public struct FairPlayManifest: FairPlayManifestProtocol, Sendable {
    public let assetID: String
    public let kasURL: String
    public let wrappedKey: String
    public let algorithm: String
    public let iv: String

    public init(
        assetID: String,
        kasURL: String,
        wrappedKey: String,
        algorithm: String,
        iv: String
    ) {
        self.assetID = assetID
        self.kasURL = kasURL
        self.wrappedKey = wrappedKey
        self.algorithm = algorithm
        self.iv = iv
    }
}

// MARK: - State Actor for Thread Safety

/// Actor to manage FairPlay session state
private actor FairPlayState {
    var sessionId: String?
    var fairPlayCertificate: Data?

    func setSessionId(_ id: String) {
        sessionId = id
    }

    func setCertificate(_ cert: Data) {
        fairPlayCertificate = cert
    }
}

// MARK: - TDFContentKeyDelegate

/// AVContentKeySessionDelegate for FairPlay DRM with TDF content
///
/// Handles the FairPlay key exchange process:
/// 1. Receives key request from AVPlayer
/// 2. Generates SPC (Server Playback Context)
/// 3. Posts SPC + TDF manifest to server
/// 4. Receives CKC (Content Key Context) from server
/// 5. Provides CKC to AVPlayer for hardware decryption
///
/// The TDF manifest contains the RSA-wrapped DEK. The server:
/// - Unwraps DEK using its RSA private key
/// - Re-wraps DEK using FairPlay SDK
/// - Returns CKC for Secure Enclave decryption
public final class TDFContentKeyDelegate<Manifest: FairPlayManifestProtocol>: NSObject, AVContentKeySessionDelegate,
    @unchecked Sendable
{
    private let manifest: Manifest
    private let serverURL: URL
    private let userId: String
    private let authToken: String?
    private let state = FairPlayState()

    /// Callback invoked when content key is successfully delivered
    public var onKeyDelivered: (@Sendable () -> Void)?

    /// Callback invoked when content key delivery fails
    public var onKeyFailed: (@Sendable (Error) -> Void)?

    /// Initialize with TDF manifest and authentication
    /// - Parameters:
    ///   - manifest: The TDF manifest containing encryption info
    ///   - authToken: Optional authentication token for server requests
    ///   - userId: User identifier for session (defaults to "anonymous")
    ///   - serverURL: FairPlay server URL (defaults to 100.arkavo.net)
    public init(
        manifest: Manifest,
        authToken: String? = nil,
        userId: String = "anonymous",
        serverURL: URL = URL(string: "https://100.arkavo.net")!
    ) {
        self.manifest = manifest
        self.authToken = authToken
        self.userId = userId
        self.serverURL = serverURL
        super.init()

        FairPlayDebug.log("══════════════════════════════════════════════════════")
        FairPlayDebug.log("TDFContentKeyDelegate initialized")
        FairPlayDebug.log("  Server URL: \(serverURL.absoluteString)")
        FairPlayDebug.log("  Asset ID: \(manifest.assetID)")
        FairPlayDebug.log("  KAS URL: \(manifest.kasURL)")
        FairPlayDebug.log("  Algorithm: \(manifest.algorithm)")
        FairPlayDebug.log("  Auth: \(authToken != nil ? "provided" : "none")")
        if let ivData = Data(base64Encoded: manifest.iv) {
            FairPlayDebug.log("  IV (hex): \(ivData.map { String(format: "%02x", $0) }.joined())")
        }
        FairPlayDebug.log("══════════════════════════════════════════════════════")
    }

    // MARK: - AVContentKeySessionDelegate

    public func contentKeySession(
        _: AVContentKeySession,
        didProvide keyRequest: AVContentKeyRequest
    ) {
        FairPlayDebug.log("──────────────────────────────────────────────────────")
        FairPlayDebug.log("📥 contentKeySession(didProvide:) called")
        FairPlayDebug.log("  Request identifier: \(keyRequest.identifier ?? "nil")")
        FairPlayDebug.log("  Request status: \(keyRequest.status.rawValue)")
        handleKeyRequest(keyRequest)
    }

    public func contentKeySession(
        _: AVContentKeySession,
        didProvideRenewingContentKeyRequest keyRequest: AVContentKeyRequest
    ) {
        FairPlayDebug.log("──────────────────────────────────────────────────────")
        FairPlayDebug.log("🔄 contentKeySession(didProvideRenewingContentKeyRequest:)")
        handleKeyRequest(keyRequest)
    }

    public func contentKeySession(
        _: AVContentKeySession,
        shouldRetry _: AVContentKeyRequest,
        reason retryReason: AVContentKeyRequest.RetryReason
    ) -> Bool {
        FairPlayDebug.log("⚠️ contentKeySession(shouldRetry:) - reason: \(retryReason.rawValue)")
        switch retryReason {
        case .timedOut:
            FairPlayDebug.log("  → Will retry (timed out)")
            return true
        case .receivedResponseWithExpiredLease:
            FairPlayDebug.log("  → Will retry (expired lease)")
            return true
        default:
            FairPlayDebug.log("  → Will NOT retry")
            return false
        }
    }

    public func contentKeySession(
        _: AVContentKeySession,
        contentKeyRequest _: AVContentKeyRequest,
        didFailWithError error: Error
    ) {
        FairPlayDebug.log("❌ contentKeySession(didFailWithError:)", type: .error)
        FairPlayDebug.log("  Error: \(error.localizedDescription)", type: .error)
        if let nsError = error as NSError? {
            FairPlayDebug.log("  Domain: \(nsError.domain)", type: .error)
            FairPlayDebug.log("  Code: \(nsError.code)", type: .error)
            if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? Error {
                FairPlayDebug.log("  Underlying: \(underlying)", type: .error)
            }
        }
    }

    public func contentKeySessionDidGenerateExpiredSessionReport(_: AVContentKeySession) {
        FairPlayDebug.log("📋 contentKeySessionDidGenerateExpiredSessionReport")
    }

    public func contentKeySession(_: AVContentKeySession, contentKeyRequestDidSucceed _: AVContentKeyRequest) {
        FairPlayDebug.log("✅ contentKeyRequestDidSucceed!")
    }

    // MARK: - Key Request Handling

    private func handleKeyRequest(_ keyRequest: AVContentKeyRequest) {
        let startTime = CFAbsoluteTimeGetCurrent()
        FairPlayDebug.log("🚀 handleKeyRequest started")

        Task {
            do {
                // 1. Start session if needed
                FairPlayDebug.log("Step 1: Check/start session...")
                var currentSessionId = await state.sessionId
                if currentSessionId == nil {
                    FairPlayDebug.log("  No existing session, starting new one...")
                    let newSessionId = try await startSession()
                    await state.setSessionId(newSessionId)
                    currentSessionId = newSessionId
                } else {
                    FairPlayDebug.log("  Using existing session: \(currentSessionId!)")
                }

                // 2. Get FairPlay certificate (cached after first fetch)
                FairPlayDebug.log("Step 2: Get FairPlay certificate...")
                var certificate = await state.fairPlayCertificate
                if certificate == nil {
                    FairPlayDebug.log("  No cached certificate, fetching...")
                    certificate = try await fetchCertificate()
                    if let cert = certificate {
                        await state.setCertificate(cert)
                    }
                } else {
                    FairPlayDebug.log("  Using cached certificate (\(certificate!.count) bytes)")
                }

                guard let cert = certificate else {
                    throw FairPlayError.certificateFetchFailed("Certificate is nil")
                }

                // 3. Generate SPC with content identifier
                FairPlayDebug.log("Step 3: Generate SPC...")
                let contentId = manifest.assetID.data(using: .utf8) ?? Data()
                FairPlayDebug.log("  Content ID: \(manifest.assetID)")
                FairPlayDebug.logData("  Content ID bytes", data: contentId)

                let spcStartTime = CFAbsoluteTimeGetCurrent()
                let spcData = try await keyRequest.makeStreamingContentKeyRequestData(
                    forApp: cert,
                    contentIdentifier: contentId
                )
                let spcDuration = CFAbsoluteTimeGetCurrent() - spcStartTime
                FairPlayDebug.log("  ✅ SPC generated in \(String(format: "%.3f", spcDuration))s")
                FairPlayDebug.log("  SPC size: \(spcData.count) bytes")
                FairPlayDebug.logData("  SPC header", data: spcData, maxBytes: 32)

                // 4. Request CKC from server
                FairPlayDebug.log("Step 4: Request CKC from server...")
                guard let activeSessionId = currentSessionId else {
                    throw FairPlayError.sessionStartFailed("Session ID not available")
                }

                let ckcStartTime = CFAbsoluteTimeGetCurrent()
                let ckcData = try await requestCKC(
                    spcData: spcData,
                    sessionId: activeSessionId
                )
                let ckcDuration = CFAbsoluteTimeGetCurrent() - ckcStartTime
                FairPlayDebug.log("  ✅ CKC received in \(String(format: "%.3f", ckcDuration))s")
                FairPlayDebug.log("  CKC size: \(ckcData.count) bytes")
                FairPlayDebug.logData("  CKC header", data: ckcData, maxBytes: 32)

                // 5. Provide CKC to AVPlayer
                FairPlayDebug.log("Step 5: Deliver CKC to AVPlayer...")
                let keyResponse = AVContentKeyResponse(
                    fairPlayStreamingKeyResponseData: ckcData
                )
                keyRequest.processContentKeyResponse(keyResponse)

                let totalDuration = CFAbsoluteTimeGetCurrent() - startTime
                FairPlayDebug.log("══════════════════════════════════════════════════════")
                FairPlayDebug.log("✅ FairPlay key exchange COMPLETE")
                FairPlayDebug.log("  Total time: \(String(format: "%.3f", totalDuration))s")
                FairPlayDebug.log("══════════════════════════════════════════════════════")

                // Notify caller that key is ready
                if let callback = onKeyDelivered {
                    DispatchQueue.main.async {
                        callback()
                    }
                }

            } catch {
                let totalDuration = CFAbsoluteTimeGetCurrent() - startTime
                FairPlayDebug.log("══════════════════════════════════════════════════════", type: .error)
                FairPlayDebug
                    .log(
                        "❌ FairPlay key exchange FAILED after \(String(format: "%.3f", totalDuration))s",
                        type: .error
                    )
                FairPlayDebug.log("  Error: \(error)", type: .error)
                if let localizedError = error as? LocalizedError {
                    FairPlayDebug.log("  Description: \(localizedError.errorDescription ?? "none")", type: .error)
                }
                FairPlayDebug.log("══════════════════════════════════════════════════════", type: .error)
                keyRequest.processContentKeyResponseError(error)

                // Notify caller that key failed
                if let callback = onKeyFailed {
                    let capturedError = error
                    DispatchQueue.main.async {
                        callback(capturedError)
                    }
                }
            }
        }
    }

    // MARK: - Server Communication

    /// Start a FairPlay playback session
    private func startSession() async throws -> String {
        let url = serverURL.appendingPathComponent("media/v1/session/start")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let body: [String: Any] = [
            "userId": userId,
            "assetId": manifest.assetID,
            "protocol": "fairplay",
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        FairPlayDebug.logRequest("POST", url: url, body: request.httpBody)

        let (data, response) = try await URLSession.shared.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        FairPlayDebug.logResponse(statusCode, data: data)

        guard let httpResponse = response as? HTTPURLResponse,
              (200 ... 299).contains(httpResponse.statusCode)
        else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw FairPlayError.sessionStartFailed("HTTP \(statusCode): \(body)")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sessionId = json["sessionId"] as? String
        else {
            throw FairPlayError.sessionStartFailed("Invalid session response")
        }

        FairPlayDebug.log("  ✅ Session ID: \(sessionId)")
        return sessionId
    }

    /// Fetch FairPlay certificate from server
    private func fetchCertificate() async throws -> Data {
        let url = serverURL.appendingPathComponent("media/v1/certificate")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        FairPlayDebug.logRequest("GET", url: url, body: nil)

        let (data, response) = try await URLSession.shared.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        FairPlayDebug.log("← HTTP \(statusCode): \(data.count) bytes (certificate binary)")

        guard let httpResponse = response as? HTTPURLResponse,
              (200 ... 299).contains(httpResponse.statusCode)
        else {
            throw FairPlayError.certificateFetchFailed("HTTP \(statusCode)")
        }

        guard !data.isEmpty else {
            throw FairPlayError.certificateFetchFailed("Empty certificate data")
        }

        FairPlayDebug.log("  ✅ Certificate fetched: \(data.count) bytes")
        FairPlayDebug.logData("  Certificate header", data: data, maxBytes: 32)
        return data
    }

    /// Request CKC from server with SPC and TDF manifest
    private func requestCKC(spcData: Data, sessionId: String) async throws -> Data {
        let url = serverURL.appendingPathComponent("media/v1/key-request")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        // Encode manifest as base64 JSON
        let manifestJSON: [String: Any] = [
            "encryptionInformation": [
                "type": "split",
                "keyAccess": [[
                    "type": "wrapped",
                    "url": manifest.kasURL,
                    "protocol": "kas",
                    "wrappedKey": manifest.wrappedKey,
                ]],
                "method": [
                    "algorithm": manifest.algorithm,
                    "iv": manifest.iv,
                ],
            ],
        ]

        guard let manifestData = try? JSONSerialization.data(withJSONObject: manifestJSON) else {
            throw FairPlayError.manifestEncodingFailed("Failed to serialize manifest")
        }
        let manifestBase64 = manifestData.base64EncodedString()

        FairPlayDebug.log("  Building key-request payload:")
        FairPlayDebug.log("    Session ID: \(sessionId)")
        FairPlayDebug.log("    User ID: \(userId)")
        FairPlayDebug.log("    Asset ID: \(manifest.assetID)")
        FairPlayDebug.log("    SPC size: \(spcData.count) bytes")
        FairPlayDebug.log("    TDF manifest size: \(manifestData.count) bytes")

        let body: [String: Any] = [
            "sessionId": sessionId,
            "userId": userId,
            "assetId": manifest.assetID,
            "spcData": spcData.base64EncodedString(),
            "tdfManifest": manifestBase64,
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        FairPlayDebug.logRequest("POST", url: url, body: request.httpBody)

        let (data, response) = try await URLSession.shared.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        FairPlayDebug.logResponse(statusCode, data: data)

        guard let httpResponse = response as? HTTPURLResponse,
              (200 ... 299).contains(httpResponse.statusCode)
        else {
            let body = String(data: data, encoding: .utf8) ?? ""
            FairPlayDebug.log("  ❌ Server error response: \(body)", type: .error)
            throw FairPlayError.ckcRequestFailed("HTTP \(statusCode): \(body)")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            FairPlayDebug.log("  ❌ Failed to parse response as JSON", type: .error)
            throw FairPlayError.invalidCKCResponse("Response is not valid JSON")
        }

        // Check for error response
        if let error = json["error"] as? String {
            let message = json["message"] as? String ?? "Unknown error"
            FairPlayDebug.log("  ❌ Server returned error: \(error) - \(message)", type: .error)
            throw FairPlayError.ckcRequestFailed("\(error): \(message)")
        }

        guard let ckcBase64 = json["wrappedKey"] as? String else {
            FairPlayDebug.log("  ❌ Missing 'wrappedKey' in response", type: .error)
            FairPlayDebug.log("  Response keys: \(json.keys.joined(separator: ", "))", type: .error)
            throw FairPlayError.invalidCKCResponse("Missing wrappedKey in response")
        }

        guard let ckcData = Data(base64Encoded: ckcBase64) else {
            FairPlayDebug.log("  ❌ Failed to decode wrappedKey as base64", type: .error)
            throw FairPlayError.invalidCKCResponse("Invalid base64 in wrappedKey")
        }

        FairPlayDebug.log("  ✅ CKC decoded: \(ckcData.count) bytes")
        return ckcData
    }
}

// MARK: - Type Alias for Convenience

/// Type alias for TDFContentKeyDelegate with default FairPlayManifest type
public typealias DefaultTDFContentKeyDelegate = TDFContentKeyDelegate<FairPlayManifest>
