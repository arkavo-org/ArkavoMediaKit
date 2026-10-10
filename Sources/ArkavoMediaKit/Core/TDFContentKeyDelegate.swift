import AVFoundation
import Foundation
import os.log
import Synchronization

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
    /// A key request for a key the package's playlists do not ask for, refused without any request.
    case unknownKeyIdentifier

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
        case .unknownKeyIdentifier:
            "The key request is for a key this recording does not have"
        }
    }
}

// MARK: - FairPlay Manifest Protocol

/// Protocol for manifest types that can be used with FairPlay key exchange
public protocol FairPlayManifestProtocol: Sendable {
    /// The SPC content id when `tdfManifestJSON` is nil or its policy has no
    /// uuid; otherwise the policy uuid is used.
    var assetID: String { get }
    var kasURL: String { get }
    var wrappedKey: String { get }
    var algorithm: String { get }
    var iv: String { get }
    /// The archive's own `manifest.json` bytes. When present they are sent as
    /// the key request's `tdfManifest`, less `meta` and `encryptedMetadata`, so
    /// the policy and its binding reach the license service (required by arks
    /// after PR #75), and its policy uuid is the SPC content id.
    var tdfManifestJSON: Data? { get }
}

public extension FairPlayManifestProtocol {
    var tdfManifestJSON: Data? { nil }
}

// MARK: - Default FairPlay Manifest Implementation

/// Default manifest implementation for FairPlay key exchange
public struct FairPlayManifest: FairPlayManifestProtocol, Sendable {
    public let assetID: String
    public let kasURL: String
    public let wrappedKey: String
    public let algorithm: String
    public let iv: String
    public let tdfManifestJSON: Data?

    public init(
        assetID: String,
        kasURL: String,
        wrappedKey: String,
        algorithm: String,
        iv: String,
        tdfManifestJSON: Data? = nil
    ) {
        self.assetID = assetID
        self.kasURL = kasURL
        self.wrappedKey = wrappedKey
        self.algorithm = algorithm
        self.iv = iv
        self.tdfManifestJSON = tdfManifestJSON
    }
}

// MARK: - State Actor for Thread Safety

/// The delegate's shared state: the certificate fetch, the keys delivered, and whether the outcome has been reported.
private actor FairPlayState {
    private var certificateFetch: Task<Data, Error>?
    private var delivered: Set<String> = []
    private var settled = false

    /// The FairPlay certificate, fetched once for every request. After a failed fetch, the next request tries again.
    /// The check and the set happen with no suspension between them, so requests asking at once share one fetch.
    func certificate(_ fetch: @escaping @Sendable () async throws -> Data) async throws -> Data {
        let fetching = certificateFetch ?? Task { try await fetch() }
        certificateFetch = fetching
        do {
            return try await fetching.value
        } catch {
            if certificateFetch == fetching { certificateFetch = nil }
            throw error
        }
    }

    /// True once: when `uri`'s delivery completes `expected`, before any failure.
    func deliver(_ uri: String, expected: Set<String>) -> Bool {
        guard !settled else { return false }
        delivered.insert(uri)
        guard delivered.isSuperset(of: expected) else { return false }
        settled = true
        return true
    }

    /// True once: for the first failure before every key was delivered.
    func fail() -> Bool {
        guard !settled else { return false }
        settled = true
        return true
    }
}

// MARK: - TDFContentKeyDelegate

/// AVContentKeySessionDelegate for FairPlay DRM with TDF content
///
/// Answers every key a package's playlists ask for (`keyIdentifiers`):
/// - FairPlay package profile v2: `skd://<policy uuid>/<id>` for each component in the policy's `arkavo:components`
///   (ADR-0055 in arkavo-ios);
/// - profile v1: `skd://<policy uuid>`.
///
/// Each request, a renewal included, is its own license request (ADR-0046 §8):
/// 1. the FairPlay certificate, fetched once and shared;
/// 2. the SPC, whose content identifier is `<policy uuid>/<id>` (profile v1: the uuid);
/// 3. a session for the policy uuid, the key request, and the session's end. The key request carries the SPC, the
///    archive manifest and, for a component, `component`;
/// 4. the CKC, given to AVFoundation.
///
/// A request for any other key is refused without a request. So is every request when the archive manifest's
/// `arkavo:components` is malformed (`FairPlayComponents.Error.malformedComponents`): such a package has no keys.
///
/// The outcome is reported at most once, on the main queue:
/// - `onKeyDelivered`, once every one of `keyIdentifiers` has had its first key given to AVFoundation; or
/// - `onKeyFailed`, at the first failure before that: a refused, unknown or failed key request, or AVFoundation's own
///   failure of a key request (`contentKeySession(_:contentKeyRequest:didFailWithError:)`).
///
/// Never both, and neither twice, whatever the number, order or outcome of the requests, so a caller can resume one
/// continuation from either. A renewal never reports: it is answered, or its failure goes to AVFoundation alone. Nor
/// does anything after the outcome: a later key is still answered, and a later failure goes to AVFoundation alone.
///
/// If AVFoundation asks for fewer keys than the package has, neither callback is ever called: a caller that waits for
/// the outcome needs its own timeout. Set both callbacks before giving the delegate to a session: an outcome reached
/// while a callback is unset is not reported later.
///
/// Sendable without `@unchecked`: every stored property is an immutable Sendable value, the callbacks sit behind a
/// mutex, and the certificate fetch and outcome sit in an actor. Each license request has its own session, so no
/// session id is shared between requests.
public final class TDFContentKeyDelegate<Manifest: FairPlayManifestProtocol>: NSObject, AVContentKeySessionDelegate,
    Sendable
{
    private struct Callbacks: Sendable {
        var delivered: (@Sendable () -> Void)?
        var failed: (@Sendable (Error) -> Void)?
    }

    private let manifest: Manifest
    /// The package's keys, or why it has none.
    private let targets: Result<[FairPlayKeyTarget], any Error>
    private let serverURL: URL
    private let userId: String
    private let authToken: String?
    private let http: any FairPlayHTTP
    private let state = FairPlayState()
    private let callbacks = Mutex(Callbacks())

    /// Called at most once, on the main queue, when every key the package's playlists ask for has been delivered.
    public var onKeyDelivered: (@Sendable () -> Void)? {
        get { callbacks.withLock { $0.delivered } }
        set { callbacks.withLock { $0.delivered = newValue } }
    }

    /// Called at most once, on the main queue, at the first failure before every key was delivered.
    public var onKeyFailed: (@Sendable (Error) -> Void)? {
        get { callbacks.withLock { $0.failed } }
        set { callbacks.withLock { $0.failed = newValue } }
    }

    /// The `skd://` URIs this delegate answers, in component order; empty when the package's component list is
    /// malformed.
    public var keyIdentifiers: [String] { ((try? targets.get()) ?? []).map(\.uri) }

    /// Initialize with TDF manifest and authentication
    /// - Parameters:
    ///   - manifest: The TDF manifest containing encryption info
    ///   - authToken: Optional authentication token for server requests
    ///   - userId: User identifier for session (defaults to "anonymous")
    ///   - serverURL: FairPlay server URL (defaults to 100.arkavo.net)
    public convenience init(
        manifest: Manifest,
        authToken: String? = nil,
        userId: String = "anonymous",
        serverURL: URL = URL(string: "https://100.arkavo.net")!
    ) {
        self.init(manifest: manifest, authToken: authToken, userId: userId, serverURL: serverURL,
                  http: URLSessionFairPlayHTTP())
    }

    init(manifest: Manifest, authToken: String?, userId: String, serverURL: URL, http: any FairPlayHTTP) {
        self.manifest = manifest
        self.targets = Result { try FairPlayKeyTarget.targets(for: manifest) }
        self.authToken = authToken
        self.userId = userId
        self.serverURL = serverURL
        self.http = http
        super.init()

        FairPlayDebug.log("══════════════════════════════════════════════════════")
        FairPlayDebug.log("TDFContentKeyDelegate initialized")
        FairPlayDebug.log("  Server URL: \(serverURL.absoluteString)")
        if case .failure = targets {
            FairPlayDebug.log("  Keys: none, the recording's component list is malformed", type: .error)
        } else {
            FairPlayDebug.log("  Keys: \(keyIdentifiers.joined(separator: ", "))")
        }
        FairPlayDebug.log("  Auth: \(authToken != nil ? "provided" : "none")")
        FairPlayDebug.log("══════════════════════════════════════════════════════")
    }

    // MARK: - AVContentKeySessionDelegate

    public func contentKeySession(
        _: AVContentKeySession,
        didProvide keyRequest: AVContentKeyRequest
    ) {
        let request = AVFoundationKeyRequest(request: keyRequest)
        FairPlayDebug.log("📥 contentKeySession(didProvide:) for \(request.keyIdentifier ?? "no identifier")")
        Task { await self.handle(request) }
    }

    public func contentKeySession(
        _: AVContentKeySession,
        didProvideRenewingContentKeyRequest keyRequest: AVContentKeyRequest
    ) {
        let request = AVFoundationKeyRequest(request: keyRequest)
        FairPlayDebug.log("🔄 contentKeySession(didProvideRenewingContentKeyRequest:) for \(request.keyIdentifier ?? "no identifier")")
        Task { await self.handle(request, renewal: true) }
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
        contentKeyRequest keyRequest: AVContentKeyRequest,
        didFailWithError error: Error
    ) {
        let renewal = keyRequest.renewsExpiringResponseData
        FairPlayDebug.log("❌ contentKeySession(didFailWithError:)\(renewal ? " renewal" : ""): \(error.localizedDescription)",
                          type: .error)
        Task { await self.keyRequestFailed(error, renewal: renewal) }
    }

    public func contentKeySessionDidGenerateExpiredSessionReport(_: AVContentKeySession) {
        FairPlayDebug.log("📋 contentKeySessionDidGenerateExpiredSessionReport")
    }

    public func contentKeySession(_: AVContentKeySession, contentKeyRequestDidSucceed _: AVContentKeyRequest) {
        FairPlayDebug.log("✅ contentKeyRequestDidSucceed!")
    }

    // MARK: - Key Request Handling

    /// Answers one key request, a first request or a renewal, as its own license request (ADR-0046 §8). A renewal never
    /// reports an outcome.
    func handle(_ request: some FairPlayKeyRequesting, renewal: Bool = false) async {
        let target: FairPlayKeyTarget
        switch targets {
        case let .failure(error):
            // The component list is malformed: no key is ever asked for (ADR-0055 §7).
            FairPlayDebug.log("❌ Refused a key request: the recording's component list is malformed", type: .error)
            await fail(request, error, renewal: renewal)
            return
        case let .success(targets):
            guard let identifier = request.keyIdentifier, let found = targets.first(where: { $0.uri == identifier })
            else {
                // Not a key this package's playlists ask for: refused without any request (ADR-0055 §7).
                FairPlayDebug.log("❌ Refused a key request for a key this recording does not have", type: .error)
                await fail(request, FairPlayError.unknownKeyIdentifier, renewal: renewal)
                return
            }
            target = found
        }
        do {
            let certificate = try await state.certificate { try await self.fetchCertificate() }
            let spc = try await request.makeServerPlaybackContext(
                certificate: certificate, contentIdentifier: Data(target.contentIdentifier.utf8))
            let session = try await startSession(assetID: target.policyUUID)
            let ckc: Data
            do {
                ckc = try await requestCKC(spcData: spc, sessionId: session, target: target)
            } catch {
                await endSession(session)
                throw error
            }
            request.process(ckc: ckc)
            FairPlayDebug.log("✅ Key delivered: \(target.uri)\(renewal ? " (renewal)" : "")")
            if !renewal, await state.deliver(target.uri, expected: Set(keyIdentifiers)), let callback = onKeyDelivered {
                DispatchQueue.main.async { callback() }
            }
            await endSession(session)
        } catch {
            FairPlayDebug.log("❌ Key exchange failed for \(target.uri): \(error.localizedDescription)", type: .error)
            await fail(request, error, renewal: renewal)
        }
    }

    /// A key request that failed, here or in AVFoundation: reported when it is the first failure before every key was
    /// delivered, and never for a renewal.
    func keyRequestFailed(_ error: Error, renewal: Bool = false) async {
        guard !renewal else { return }
        if await state.fail(), let callback = onKeyFailed {
            DispatchQueue.main.async { callback(error) }
        }
    }

    private func fail(_ request: some FairPlayKeyRequesting, _ error: Error, renewal: Bool) async {
        request.fail(error)
        await keyRequestFailed(error, renewal: renewal)
    }

    // MARK: - Server Communication

    /// Prepare a request for the KAS/media server: opt into HTTP/3 and add auth.
    ///
    /// The KAS advertises `alt-svc: h3`; `assumesHTTP3Capable` lets the first hop
    /// negotiate HTTP/3, falling back to HTTP/2 automatically for non-h3 servers.
    private func prepareRequest(_ request: inout URLRequest) {
        request.assumesHTTP3Capable = true
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    /// Start a FairPlay playback session for the policy uuid: one per license request. Neither the body nor the answer
    /// is printed.
    private func startSession(assetID: String) async throws -> String {
        let url = serverURL.appendingPathComponent("media/v1/session/start")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        prepareRequest(&request)
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "userId": userId,
            "assetId": assetID,
            "protocol": "fairplay",
        ])

        FairPlayDebug.logRequest("POST", url: url, body: nil)

        let (data, response) = try await http.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        FairPlayDebug.log("← HTTP \(statusCode): \(data.count) bytes")

        guard (200 ... 299).contains(statusCode) else {
            throw FairPlayError.sessionStartFailed("HTTP \(statusCode): \(String(data: data, encoding: .utf8) ?? "")")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sessionId = json["sessionId"] as? String, !sessionId.isEmpty
        else {
            throw FairPlayError.sessionStartFailed("Invalid session response")
        }
        return sessionId
    }

    /// End a session, best effort: a failure is logged and never fails the key.
    private func endSession(_ sessionId: String) async {
        let url = serverURL.appendingPathComponent("media/v1/session").appendingPathComponent(sessionId)
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        prepareRequest(&request)
        let status = ((try? await http.data(for: request))?.1 as? HTTPURLResponse)?.statusCode ?? 0
        FairPlayDebug.log("← session end HTTP \(status)")
    }

    /// Fetch FairPlay certificate from server
    private func fetchCertificate() async throws -> Data {
        let url = serverURL.appendingPathComponent("media/v1/certificate")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        prepareRequest(&request)

        FairPlayDebug.logRequest("GET", url: url, body: nil)

        let (data, response) = try await http.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        FairPlayDebug.log("← HTTP \(statusCode): \(data.count) bytes (certificate binary)")

        guard (200 ... 299).contains(statusCode) else {
            throw FairPlayError.certificateFetchFailed("HTTP \(statusCode)")
        }
        guard !data.isEmpty else {
            throw FairPlayError.certificateFetchFailed("Empty certificate data")
        }
        return data
    }

    /// The CKC for `target`'s SPC. The body names the policy uuid as `assetId`, and the component for a profile v2 key
    /// (ADR-0055 §7). Neither the body nor the answer is printed: they carry the SPC, the manifest and the CKC.
    private func requestCKC(spcData: Data, sessionId: String, target: FairPlayKeyTarget) async throws -> Data {
        let url = serverURL.appendingPathComponent("media/v1/key-request")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        prepareRequest(&request)

        var body: [String: Any] = [
            "sessionId": sessionId,
            "userId": userId,
            "assetId": target.policyUUID,
            "spcData": spcData.base64EncodedString(),
            "tdfManifest": try Self.keyRequestManifestData(for: manifest).base64EncodedString(),
        ]
        if let component = target.component { body["component"] = component }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        FairPlayDebug.log("→ POST \(url.absoluteString) for \(target.uri): SPC \(spcData.count) bytes")

        let (data, response) = try await http.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        FairPlayDebug.log("← HTTP \(statusCode): \(data.count) bytes")

        guard (200 ... 299).contains(statusCode) else {
            // A refusal carries an error and a message, never a CKC.
            throw FairPlayError.ckcRequestFailed("HTTP \(statusCode): \(String(data: data, encoding: .utf8) ?? "")")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw FairPlayError.invalidCKCResponse("Response is not valid JSON")
        }
        if let error = json["error"] as? String {
            throw FairPlayError.ckcRequestFailed("\(error): \(json["message"] as? String ?? "Unknown error")")
        }
        guard let ckcBase64 = json["wrappedKey"] as? String else {
            throw FairPlayError.invalidCKCResponse("Missing wrappedKey in response")
        }
        guard let ckcData = Data(base64Encoded: ckcBase64), !ckcData.isEmpty else {
            throw FairPlayError.invalidCKCResponse("Invalid base64 in wrappedKey")
        }
        return ckcData
    }

    /// The SPC content id and the requests' `assetId`: the uuid of the policy
    /// in the archive manifest when there is one, since arks matches the SPC
    /// against the policy it is sent, else `manifest.assetID`.
    static func contentID(for manifest: Manifest) -> String {
        manifest.tdfManifestJSON.flatMap(FairPlayPolicy.uuid(ofManifestJSON:)) ?? manifest.assetID
    }

    /// The `tdfManifest` sent with a key request: the archive's own manifest
    /// when the caller supplied it, else the legacy reconstruction (no policy,
    /// which the post-#75 license service refuses).
    static func keyRequestManifestData(for manifest: Manifest) throws -> Data {
        if let raw = manifest.tdfManifestJSON { return trimmedForKeyRequest(raw) }
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
        guard let data = try? JSONSerialization.data(withJSONObject: manifestJSON) else {
            throw FairPlayError.manifestEncodingFailed("Failed to serialize manifest")
        }
        return data
    }

    /// The archive manifest without what no license service reads: top-level
    /// `meta` and each key access object's `encryptedMetadata` (in archives
    /// before 0.1.7, the fMP4 per-segment file list, ~32 B a segment). The policy, wrapped key and
    /// binding strings are carried over unchanged. Bytes that are not a JSON
    /// object, or that JSONSerialization could not write back, are returned as
    /// they are.
    private static func trimmedForKeyRequest(_ raw: Data) -> Data {
        guard var json = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] else { return raw }
        json["meta"] = nil
        if var info = json["encryptionInformation"] as? [String: Any],
           let keyAccess = info["keyAccess"] as? [[String: Any]] {
            info["keyAccess"] = keyAccess.map { $0.filter { $0.key != "encryptedMetadata" } }
            json["encryptionInformation"] = info
        }
        // Writing a non-finite number (-1e400 parses as -inf) raises an exception `try?` cannot catch.
        guard JSONSerialization.isValidJSONObject(json) else { return raw }
        return (try? JSONSerialization.data(withJSONObject: json, options: [.withoutEscapingSlashes])) ?? raw
    }
}

// MARK: - Type Alias for Convenience

/// Type alias for TDFContentKeyDelegate with default FairPlayManifest type
public typealias DefaultTDFContentKeyDelegate = TDFContentKeyDelegate<FairPlayManifest>
