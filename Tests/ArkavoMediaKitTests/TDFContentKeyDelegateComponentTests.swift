import Foundation
import Synchronization
import Testing
@testable import ArkavoMediaKit

/// The delegate's outcomes, in order, once the main queue has run them.
final class Outcomes: Sendable {
    private let events = Mutex<[String]>([])

    func record(_ event: String) { events.withLock { $0.append(event) } }

    /// Waits for every callback already queued on the main queue, then returns what has been reported.
    func reported() async -> [String] {
        await MainActor.run {}
        return events.withLock { $0 }
    }
}

/// The media service, answering by route. It serves a certificate and starts a new session for each start. It answers
/// each key request with a CKC, or refuses one component's, and ends any session.
actor FakeMediaService: FairPlayHTTP {
    struct Call: Sendable {
        /// The method and the path after `/media/v1/`.
        let route: String
        /// The JSON body's string values.
        let body: [String: String]
    }

    /// How a refusal answers: its status and its body.
    struct Refusal: Sendable {
        let status: Int
        let body: Data

        static let forbidden = Refusal(status: 403,
                                       body: Data(#"{"error":"forbidden","message":"manifest refused"}"#.utf8))
    }

    private(set) var calls: [Call] = []
    private var sessions = 0
    private var refused: String?
    private let refusal: Refusal
    private let sessionPrefix: String
    private let sessionStartRefusal: Refusal?
    private let redirectedRoute: String?

    /// - Parameters:
    ///   - component: Refuses that component's key requests with `refusal`.
    ///   - sessionPrefix: Each session id is this and the session's number.
    ///   - sessionStartRefusal: Refuses every session start with this, when set.
    ///   - redirectedRoute: Answers this route (`"GET certificate"`, …) with a 307 to another host, when set.
    init(refusing component: String? = nil, refusal: Refusal = .forbidden, sessionPrefix: String = "session-",
         sessionStartRefusal: Refusal? = nil, redirecting redirectedRoute: String? = nil) {
        refused = component
        self.refusal = refusal
        self.sessionPrefix = sessionPrefix
        self.sessionStartRefusal = sessionStartRefusal
        self.redirectedRoute = redirectedRoute
    }

    /// From now on, refuses `component`'s key requests (nil: none).
    func refuse(_ component: String?) { refused = component }

    static func ckc(for component: String) -> Data {
        Data((0 ..< 300).map { UInt8(255 - $0 % 256) }) + Data(component.utf8)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        let path = (request.url?.path ?? "").replacingOccurrences(of: "/media/v1/", with: "")
        let route = (request.httpMethod ?? "GET") + " " + path
        let object = request.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        let body = object.compactMapValues { $0 as? String }
        calls.append(Call(route: route, body: body))
        if route == redirectedRoute {
            return respond(request, 307, Data(), headers: ["Location": "https://elsewhere.example/media/v1/\(path)"])
        }
        switch route {
        case "GET certificate":
            return respond(request, 200, Data(repeating: 0x30, count: 64))
        case "POST session/start":
            if let sessionStartRefusal { return respond(request, sessionStartRefusal.status, sessionStartRefusal.body) }
            sessions += 1
            return respond(request, 200,
                           Data(#"{"sessionId":"\#(sessionPrefix)\#(sessions)","status":"started"}"#.utf8))
        case "POST key-request" where body["component"] != nil && body["component"] == refused:
            return respond(request, refusal.status, refusal.body)
        case "POST key-request":
            let ckc = Self.ckc(for: body["component"] ?? "v1").base64EncodedString()
            return respond(request, 200, Data(#"{"status":"success","wrappedKey":"\#(ckc)"}"#.utf8))
        default:
            return respond(request, route.hasPrefix("DELETE session/") ? 200 : 404, Data())
        }
    }

    private func respond(_ request: URLRequest, _ status: Int, _ body: Data,
                         headers: [String: String]? = nil) -> (Data, URLResponse) {
        (body, HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!)
    }
}

/// A key request for `keyIdentifier` that records what the delegate does with it.
final class FakeKeyRequest: FairPlayKeyRequesting {
    struct Log: Sendable {
        var contentIdentifiers: [String] = []
        var ckcs: [Data] = []
        var errors: [any Error] = []
    }

    let keyIdentifier: String?
    private let log = Mutex(Log())
    /// Run when the delegate fails the request, before `fail(_:)` returns: as AVFoundation reports its own failure of
    /// a request the delegate failed.
    private let onFail: (@Sendable (Error) -> Void)?

    init(_ keyIdentifier: String?, onFail: (@Sendable (Error) -> Void)? = nil) {
        self.keyIdentifier = keyIdentifier
        self.onFail = onFail
    }

    /// A long SPC whose base64 holds `/` and `+`, which JSONSerialization escapes and the log truncation missed.
    static func spc(for contentIdentifier: String) -> Data {
        Data((0 ..< 600).map { UInt8($0 % 256) }) + Data(contentIdentifier.utf8)
    }

    var contentIdentifiers: [String] { log.withLock { $0.contentIdentifiers } }
    var ckcs: [Data] { log.withLock { $0.ckcs } }
    var failures: Int { log.withLock { $0.errors.count } }
    var errors: [any Error] { log.withLock { $0.errors } }

    func makeServerPlaybackContext(certificate: Data, contentIdentifier: Data) async throws -> Data {
        let identifier = String(decoding: contentIdentifier, as: UTF8.self)
        log.withLock { $0.contentIdentifiers.append(identifier) }
        return Self.spc(for: identifier)
    }

    func process(ckc: Data) { log.withLock { $0.ckcs.append(ckc) } }

    func fail(_ error: Error) {
        log.withLock { $0.errors.append(error) }
        onFail?(error)
    }
}

/// `TDFContentKeyDelegate` answers every key a profile v2 package's playlists ask for, each as its own license request,
/// and reports the outcome at most once (ADR-0055 §7 in arkavo-ios).
@Suite("TDFContentKeyDelegate components")
struct TDFContentKeyDelegateComponentTests {
    static let uuid = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"
    static let iv = Data((0xF0 ... 0xFF).map { UInt8($0) })
    /// A wrapped key long enough to recognise in a log, its base64 holding `/` and `+`.
    static let wrappedKey = Data((0 ..< 256).map { UInt8(($0 * 37 + 11) % 256) })
    static let video = "skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b/video"
    static let audio = "skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b/audio"

    /// A manifest whose policy lists `components`; nil is profile v1. Only the policy matters to the delegate, which
    /// sends the rest of the manifest as it is.
    static func manifest(components: [FairPlayComponent]?, uuid: String = TDFContentKeyDelegateComponentTests.uuid) throws -> FairPlayManifest {
        var policy = Data(#"{"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"\#(uuid)"}"#.utf8)
        if let components {
            policy = try FairPlayComponents.insert(
                components.enumerated().map { index, component in
                    FairPlayComponentKey(component: component, key: Data(repeating: UInt8(index + 1), count: 16))
                },
                intoPolicyJSON: policy)
        }
        return try manifest(policy: policy, accesses: components?.count ?? 1)
    }

    /// A manifest with `policy` as it is, and `accesses` key access objects.
    static func manifest(policy: Data, accesses: Int = 2) throws -> FairPlayManifest {
        let access: [String: Any] = [
            "type": "wrapped", "url": "https://platform.arkavo.net", "wrappedKey": wrappedKey.base64EncodedString(),
        ]
        let information: [String: Any] = [
            "type": "split", "policy": policy.base64EncodedString(), "keyAccess": Array(repeating: access, count: accesses),
            "method": ["algorithm": "AES-128-CBC", "iv": iv.base64EncodedString()] as [String: Any],
        ]
        let json = try JSONSerialization.data(withJSONObject: ["encryptionInformation": information])
        return FairPlayManifest(assetID: "recording-1", kasURL: "https://platform.arkavo.net",
                                wrappedKey: wrappedKey.base64EncodedString(), algorithm: "AES-128-CBC",
                                iv: iv.base64EncodedString(), tdfManifestJSON: json)
    }

    static func delegate(_ components: [FairPlayComponent]? = [.video, .audio], service: FakeMediaService) throws
        -> (TDFContentKeyDelegate<FairPlayManifest>, Outcomes) {
        try delegate(manifest: manifest(components: components), service: service)
    }

    static func delegate(manifest: FairPlayManifest, service: FakeMediaService, authToken: String = "token")
        -> (TDFContentKeyDelegate<FairPlayManifest>, Outcomes) {
        let delegate = TDFContentKeyDelegate(
            manifest: manifest, authToken: authToken, serverURL: URL(string: "https://platform.arkavo.net")!,
            http: service)
        let outcomes = Outcomes()
        delegate.onKeyDelivered = { outcomes.record("ready") }
        delegate.onKeyFailed = { _ in outcomes.record("failed") }
        return (delegate, outcomes)
    }

    /// Answers each request, then has AVFoundation accept each one's key, in order.
    static func answerAndAccept(_ delegate: TDFContentKeyDelegate<FairPlayManifest>, _ requests: FakeKeyRequest...)
        async {
        for request in requests { await delegate.handle(request) }
        for request in requests { await delegate.keyRequestSucceeded(request.keyIdentifier) }
    }

    @Test("A package's keys are its components' skd:// URIs, in order; profile v1 has the uuid's alone")
    func keyIdentifiers() throws {
        #expect(try Self.delegate(service: FakeMediaService()).0.keyIdentifiers == [Self.video, Self.audio])
        #expect(try Self.delegate([.video], service: FakeMediaService()).0.keyIdentifiers == [Self.video])
        #expect(try Self.delegate(nil, service: FakeMediaService()).0.keyIdentifiers == ["skd://\(Self.uuid)"])
    }

    @Test("Each component's key is its own license request, and ready is reported once, after the last key is accepted")
    func everyKeyThenReady() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)
        let video = FakeKeyRequest(Self.video), audio = FakeKeyRequest(Self.audio)

        await delegate.handle(video)
        await delegate.keyRequestSucceeded(Self.video)
        #expect(await outcomes.reported() == [])
        await delegate.handle(audio)
        await delegate.keyRequestSucceeded(Self.audio)
        #expect(await outcomes.reported() == ["ready"])

        #expect(video.contentIdentifiers == ["\(Self.uuid)/video"])
        #expect(audio.contentIdentifiers == ["\(Self.uuid)/audio"])
        #expect(video.ckcs == [FakeMediaService.ckc(for: "video")])
        #expect(audio.ckcs == [FakeMediaService.ckc(for: "audio")])
        let calls = await service.calls
        #expect(calls.map(\.route) == [
            "GET certificate",
            "POST session/start", "POST key-request", "DELETE session/session-1",
            "POST session/start", "POST key-request", "DELETE session/session-2",
        ])
        // Exactly these members: never `userId` (ADR-0046 §4's never-sent list, kept by ADR-0055 §7).
        let starts = calls.filter { $0.route == "POST session/start" }
        let startBody: [String: String] = ["assetId": Self.uuid, "protocol": "fairplay"]
        #expect(starts.map(\.body) == [startBody, startBody])
        let keyRequests = calls.filter { $0.route == "POST key-request" }
        let keyRequestMembers: Set<String> = ["sessionId", "assetId", "spcData", "tdfManifest", "component"]
        #expect(keyRequests.allSatisfy { Set($0.body.keys) == keyRequestMembers })
        #expect(keyRequests.map { $0.body["component"] } == ["video", "audio"])
        #expect(keyRequests.map { $0.body["assetId"] } == [Self.uuid, Self.uuid])
        #expect(keyRequests.map { $0.body["sessionId"] } == ["session-1", "session-2"])
    }

    @Test("A CKC handed to AVFoundation is not a key accepted: nothing is reported until AVFoundation accepts each")
    func handOffIsNotAcceptance() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService())
        let video = FakeKeyRequest(Self.video), audio = FakeKeyRequest(Self.audio)

        await delegate.handle(video)
        await delegate.handle(audio)

        #expect(video.ckcs.count == 1 && audio.ckcs.count == 1)
        #expect(await outcomes.reported() == [])
    }

    @Test("Every key accepted reports ready once; a renewal's or an unknown key's acceptance never counts")
    func allAcceptedReadyOnce() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService())
        await delegate.handle(FakeKeyRequest(Self.video))
        await delegate.handle(FakeKeyRequest(Self.audio))

        await delegate.keyRequestSucceeded(Self.video)
        await delegate.keyRequestSucceeded(Self.audio, renewal: true)
        await delegate.keyRequestSucceeded("skd://\(Self.uuid)/subtitles")
        await delegate.keyRequestSucceeded(nil)
        #expect(await outcomes.reported() == [])

        await delegate.keyRequestSucceeded(Self.audio)
        #expect(await outcomes.reported() == ["ready"])

        await delegate.keyRequestSucceeded(Self.audio)
        await delegate.keyRequestSucceeded(Self.video)
        await delegate.keyRequestFailed(FairPlayError.invalidCKCResponse("late"))
        #expect(await outcomes.reported() == ["ready"])
    }

    @Test("CKCs handed off, then one rejected by AVFoundation: failed, never ready")
    func handedOffThenRejected() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService())
        await delegate.handle(FakeKeyRequest(Self.video))
        await delegate.handle(FakeKeyRequest(Self.audio))
        await delegate.keyRequestSucceeded(Self.video)

        // AVFoundation rejects the audio CKC it was given.
        await delegate.keyRequestFailed(FairPlayError.invalidCKCResponse("rejected"))
        #expect(await outcomes.reported() == ["failed"])

        await delegate.keyRequestSucceeded(Self.audio)
        #expect(await outcomes.reported() == ["failed"])
    }

    @Test("Keys answered and accepted in either order report ready once, after the last")
    func outOfOrder() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService())
        await Self.answerAndAccept(delegate, FakeKeyRequest(Self.audio))
        #expect(await outcomes.reported() == [])
        await Self.answerAndAccept(delegate, FakeKeyRequest(Self.video))
        #expect(await outcomes.reported() == ["ready"])
    }

    @Test("Keys asked for at once share one certificate fetch and have a session each")
    func concurrent() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)
        async let first: Void = Self.answerAndAccept(delegate, FakeKeyRequest(Self.video))
        async let second: Void = Self.answerAndAccept(delegate, FakeKeyRequest(Self.audio))
        _ = await (first, second)

        #expect(await outcomes.reported() == ["ready"])
        let calls = await service.calls
        #expect(calls.filter { $0.route == "GET certificate" }.count == 1)
        #expect(Set(calls.filter { $0.route == "POST key-request" }.compactMap { $0.body["sessionId"] }).count == 2)
        #expect(calls.filter { $0.route.hasPrefix("DELETE session/") }.count == 2)
    }

    @Test("A refused second key reports one failure and never ready, and its session still ends")
    func refusedSecondKey() async throws {
        let service = FakeMediaService(refusing: "audio")
        let (delegate, outcomes) = try Self.delegate(service: service)
        let video = FakeKeyRequest(Self.video), audio = FakeKeyRequest(Self.audio)

        await Self.answerAndAccept(delegate, video)
        await delegate.handle(audio)

        #expect(await outcomes.reported() == ["failed"])
        #expect(video.ckcs.count == 1)
        #expect(audio.ckcs.isEmpty && audio.failures == 1)
        #expect(audio.errors.first.map { "\($0)" } == "\(FairPlayError.ckcRequestFailed("HTTP 403"))")
        #expect(await service.calls.filter { $0.route.hasPrefix("DELETE session/") }.count == 2)
    }

    @Test("A refused key reports the delegate's own error, even when AVFoundation's report of the failure comes first")
    func ownErrorWins() async throws {
        let (delegate, _) = try Self.delegate(service: FakeMediaService(refusing: "video"))
        let reported = Mutex<[String]>([])
        delegate.onKeyFailed = { error in reported.withLock { $0.append("\(error)") } }
        struct Echo: Error {}
        // AVFoundation answers `processContentKeyResponseError` with `didFailWithError`: here, before `fail` returns.
        let echoed = DispatchSemaphore(value: 0)
        let request = FakeKeyRequest(Self.video) { _ in
            Task.detached {
                await delegate.keyRequestFailed(Echo())
                echoed.signal()
            }
            _ = echoed.wait(timeout: .now() + 5)
        }

        await delegate.handle(request)
        await MainActor.run {}

        #expect(reported.withLock { $0 } == ["\(FairPlayError.ckcRequestFailed("HTTP 403"))"])
    }

    @Test("After a failure, a later key is still answered but reports nothing")
    func failureThenKey() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService(refusing: "video"))
        let video = FakeKeyRequest(Self.video), audio = FakeKeyRequest(Self.audio)

        await delegate.handle(video)
        #expect(await outcomes.reported() == ["failed"])
        await Self.answerAndAccept(delegate, audio)

        #expect(audio.ckcs.count == 1)
        #expect(await outcomes.reported() == ["failed"])
    }

    @Test("A renewal after ready is its own license request and reports nothing more")
    func renewalAfterReady() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)

        await Self.answerAndAccept(delegate, FakeKeyRequest(Self.video), FakeKeyRequest(Self.audio))
        let renewal = FakeKeyRequest(Self.video)
        await delegate.handle(renewal, renewal: true)
        await delegate.keyRequestSucceeded(Self.video, renewal: true)

        #expect(await outcomes.reported() == ["ready"])
        #expect(renewal.ckcs.count == 1)
        let calls = await service.calls
        #expect(calls.filter { $0.route == "POST key-request" }.map { $0.body["component"] } == ["video", "audio", "video"])
        #expect(calls.filter { $0.route == "POST session/start" }.count == 3)
        #expect(calls.filter { $0.route == "GET certificate" }.count == 1)
    }

    @Test("A renewal never reports, even refused before ready: the outcome is the first keys'")
    func renewalBeforeReady() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)

        await Self.answerAndAccept(delegate, FakeKeyRequest(Self.video))
        await service.refuse("video")
        let renewal = FakeKeyRequest(Self.video)
        await delegate.handle(renewal, renewal: true)
        #expect(renewal.ckcs.isEmpty && renewal.failures == 1)
        await delegate.keyRequestFailed(FairPlayError.invalidCKCResponse("renewal"), renewal: true)
        #expect(await outcomes.reported() == [])

        await Self.answerAndAccept(delegate, FakeKeyRequest(Self.audio))
        #expect(await outcomes.reported() == ["ready"])
    }

    @Test("A refused session start fails the key with its status alone, and asks for no key")
    func sessionStartRefused() async throws {
        let service = FakeMediaService(sessionStartRefusal: FakeMediaService.Refusal(
            status: 500, body: Data(#"{"error":"internal","message":"session store said: secret-detail-4b2f"}"#.utf8)))
        let (delegate, outcomes) = try Self.delegate(service: service)
        let request = FakeKeyRequest(Self.video)

        await delegate.handle(request)

        #expect(await outcomes.reported() == ["failed"])
        #expect(request.ckcs.isEmpty && request.failures == 1)
        let error = try #require(request.errors.first)
        #expect("\(error)" == "\(FairPlayError.sessionStartFailed("HTTP 500"))")
        #expect(!error.localizedDescription.contains("secret-detail"))
        #expect(await service.calls.map(\.route) == ["GET certificate", "POST session/start"])
    }

    @Test("A credential-bearing request answered with a redirect fails, and the redirect is not followed",
          arguments: ["GET certificate", "POST session/start", "POST key-request"])
    func redirectRefused(route: String) async throws {
        let service = FakeMediaService(redirecting: route)
        let (delegate, outcomes) = try Self.delegate(service: service)
        let request = FakeKeyRequest(Self.video)

        await delegate.handle(request)

        #expect(await outcomes.reported() == ["failed"])
        #expect(request.ckcs.isEmpty && request.failures == 1)
        let calls = await service.calls
        #expect(calls.filter { $0.route == route }.count == 1)
        #expect(calls.last.map { $0.route == route || $0.route.hasPrefix("DELETE session/") } == true)
    }

    @Test("A key the package does not ask for is refused without any request", arguments: [
        "skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b/subtitles",
        "skd://6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d/video",
        "skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b",
        "skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b/video/x",
        "",
    ])
    func foreignIdentifier(_ identifier: String) async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)
        let request = FakeKeyRequest(identifier)

        await delegate.handle(request)

        #expect(request.failures == 1 && request.contentIdentifiers.isEmpty)
        #expect(await service.calls.isEmpty)
        #expect(await outcomes.reported() == ["failed"])
    }

    @Test("A key request without an identifier is refused without any request")
    func noIdentifier() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)
        let request = FakeKeyRequest(nil)

        await delegate.handle(request)

        #expect(request.failures == 1)
        #expect(await service.calls.isEmpty)
        #expect(await outcomes.reported() == ["failed"])
    }

    @Test("A package whose component list is malformed has no keys and refuses every request without any request",
          arguments: [
              // A repeated member: JSONSerialization reads the first list, the key service the last.
              "{\"arkavo:components\":[\(FairPlayComponentsTests.videoEntry)],\"arkavo:components\":[\(FairPlayComponentsTests.videoEntry),\(FairPlayComponentsTests.audioEntry)],\"uuid\":\"\(TDFContentKeyDelegateComponentTests.uuid)\"}",
              "{\"arkavo:components\":[],\"uuid\":\"\(TDFContentKeyDelegateComponentTests.uuid)\"}",
              "{\"arkavo:components\":[\(FairPlayComponentsTests.audioEntry)],\"uuid\":\"\(TDFContentKeyDelegateComponentTests.uuid)\"}",
          ])
    func malformedComponents(_ policy: String) async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = Self.delegate(manifest: try Self.manifest(policy: Data(policy.utf8)), service: service)
        #expect(delegate.keyIdentifiers.isEmpty)

        let requests = [Self.video, Self.audio, "skd://\(Self.uuid)"].map { FakeKeyRequest($0) }
        for request in requests { await delegate.handle(request) }

        for request in requests {
            #expect(request.failures == 1 && request.contentIdentifiers.isEmpty)
            #expect(request.errors.first as? FairPlayComponents.Error == .malformedComponents)
        }
        #expect(await service.calls.isEmpty)
        #expect(await outcomes.reported() == ["failed"])
    }

    @Test("A profile v1 package asks for one key, its content identifier the uuid, without a component")
    func profileV1() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(nil, service: service)
        let request = FakeKeyRequest("skd://\(Self.uuid)")

        await Self.answerAndAccept(delegate, request)

        #expect(await outcomes.reported() == ["ready"])
        #expect(request.contentIdentifiers == [Self.uuid])
        let keyRequest = try #require(await service.calls.first { $0.route == "POST key-request" })
        #expect(keyRequest.body["component"] == nil)
        #expect(keyRequest.body["assetId"] == Self.uuid)
        #expect(Set(keyRequest.body.keys) == ["sessionId", "assetId", "spcData", "tdfManifest"])
    }

    @Test("AVFoundation's key failure before ready reports one failure; after ready, nothing")
    func avFoundationFailure() async throws {
        let (failing, failingOutcomes) = try Self.delegate(service: FakeMediaService())
        await failing.keyRequestFailed(FairPlayError.invalidCKCResponse("rejected"))
        await failing.keyRequestFailed(FairPlayError.invalidCKCResponse("again"))
        #expect(await failingOutcomes.reported() == ["failed"])

        let (ready, readyOutcomes) = try Self.delegate(service: FakeMediaService())
        await Self.answerAndAccept(ready, FakeKeyRequest(Self.video), FakeKeyRequest(Self.audio))
        await ready.keyRequestFailed(FairPlayError.invalidCKCResponse("late"))
        #expect(await readyOutcomes.reported() == ["ready"])
    }

    @Test("Callbacks set while keys are answered never race the answers")
    func callbacksSetConcurrently() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService())
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await Self.answerAndAccept(delegate, FakeKeyRequest(Self.video)) }
            group.addTask { await Self.answerAndAccept(delegate, FakeKeyRequest(Self.audio)) }
            for _ in 0 ..< 100 {
                group.addTask { delegate.onKeyDelivered = { outcomes.record("ready") } }
                group.addTask { delegate.onKeyFailed = { _ in outcomes.record("failed") } }
            }
        }
        #expect(await outcomes.reported() == ["ready"])
    }
}

extension FairPlayVerboseLoggingTests {
    /// The FairPlay exchange's verbose log (ArkavoMediaKit 0.3.1 printed SPC and CKC header bytes, the IV, and 500 characters of
    /// the key request's answer).
    @Suite("TDFContentKeyDelegate key material")
    struct DelegateKeyMaterialTests {
        @Test("The exchange prints no SPC, CKC, wrapped key, IV, token or session id, however formatted, nor any refusal's text")
        func printsNoKeyMaterial() async throws {
            let original = FairPlayDebugConfig.isVerboseLoggingEnabled
            FairPlayDebugConfig.isVerboseLoggingEnabled = true
            defer { FairPlayDebugConfig.isVerboseLoggingEnabled = original }
            // A uuid of this test's own, so the positive control below cannot see another test's exchange.
            let uuid = UUID().uuidString.lowercased()
            let manifest = try TDFContentKeyDelegateComponentTests.manifest(components: [.video, .audio], uuid: uuid)
            let token = "bearer-marker-\(UUID().uuidString)"
            let sessionPrefix = "session-marker-\(UUID().uuidString)-"
            let secrets = [
                FakeKeyRequest.spc(for: "\(uuid)/video"), FakeKeyRequest.spc(for: "\(uuid)/audio"),
                FakeMediaService.ckc(for: "video"), FakeMediaService.ckc(for: "audio"),
                TDFContentKeyDelegateComponentTests.wrappedKey, TDFContentKeyDelegateComponentTests.iv,
            ]
            // A refusal that echoes everything a key service could: the SPC, a CKC, the wrapped key, the IV, the
            // bearer token and the session id.
            let echoed = "spc=\(secrets[0].base64EncodedString()) ckc=\(secrets[2].base64EncodedString()) "
                + "wrappedKey=\(secrets[4].base64EncodedString()) iv=\(secrets[5].base64EncodedString()) "
                + "bearer=\(token) session=\(sessionPrefix)1"
            let refusals = [
                FakeMediaService(refusing: "video", refusal: .init(
                    status: 403, body: Data(#"{"error":"forbidden","message":"\#(echoed)"}"#.utf8)),
                    sessionPrefix: sessionPrefix),
                FakeMediaService(refusing: "video", refusal: .init(
                    status: 200, body: Data(#"{"error":"\#(echoed)","message":"\#(echoed)"}"#.utf8)),
                    sessionPrefix: sessionPrefix),
                FakeMediaService(sessionPrefix: sessionPrefix, sessionStartRefusal: .init(
                    status: 500, body: Data(#"{"error":"\#(echoed)","message":"\#(echoed)"}"#.utf8))),
            ]
            let errors = Mutex<[any Error]>([])
            let (_, output) = try await StdoutCapture.capture {
                let (delegate, _) = TDFContentKeyDelegateComponentTests.delegate(
                    manifest: manifest, service: FakeMediaService(sessionPrefix: sessionPrefix), authToken: token)
                await TDFContentKeyDelegateComponentTests.answerAndAccept(
                    delegate, FakeKeyRequest("skd://\(uuid)/video"), FakeKeyRequest("skd://\(uuid)/audio"))
                for service in refusals {
                    let (refusing, _) = TDFContentKeyDelegateComponentTests.delegate(
                        manifest: manifest, service: service, authToken: token)
                    refusing.onKeyFailed = { error in errors.withLock { $0.append(error) } }
                    let request = FakeKeyRequest("skd://\(uuid)/video")
                    await refusing.handle(request)
                    errors.withLock { $0 += request.errors }
                }
                await MainActor.run {}
            }
            // The positive control: the capture saw this exchange's log, so the absences below are not vacuous.
            #expect(output.contains("Key delivered: skd://\(uuid)/video"))
            #expect(output.contains("Key delivered: skd://\(uuid)/audio"))
            #expect(output.components(separatedBy: "Key exchange failed for skd://\(uuid)/video").count == 4)
            let descriptions = errors.withLock { $0 }.flatMap { ["\($0)", $0.localizedDescription] }
            #expect(descriptions.count == 12)

            var texts = [token, sessionPrefix, "forbidden"]
            for secret in secrets {
                let base64 = secret.base64EncodedString()
                let hex = secret.map { String(format: "%02x", $0) }.joined()
                let spacedHex = secret.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
                texts += [base64, base64.replacingOccurrences(of: "/", with: #"\/"#), hex, hex.uppercased(),
                          String(hex.prefix(32)), String(base64.prefix(40)), spacedHex]
            }
            for text in texts {
                #expect(!output.contains(text), "printed: \(text.prefix(24))")
                #expect(!descriptions.contains { $0.contains(text) }, "in an error: \(text.prefix(24))")
            }
        }
    }
}

/// Answers a request to `platform.example` with a 307 to `elsewhere.example`, and any other request with 200, recording
/// every URL it is asked for.
final class RedirectingURLProtocol: URLProtocol {
    private static let seen = Mutex<[URL]>([])

    /// The URLs asked for whose path holds `marker`.
    static func seen(_ marker: String) -> [URL] { seen.withLock { $0.filter { $0.path.contains(marker) } } }

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else { return }
        Self.seen.withLock { $0.append(url) }
        if url.host == "platform.example" {
            let target = URL(string: "https://elsewhere.example\(url.path)")!
            let response = HTTPURLResponse(url: url, statusCode: 307, httpVersion: "HTTP/1.1",
                                           headerFields: ["Location": target.absoluteString])!
            var redirect = request
            redirect.url = target
            client?.urlProtocol(self, wasRedirectedTo: redirect, redirectResponse: response)
            // Refused, the redirect is the answer.
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
        } else {
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data("collected".utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {}
}

/// The delegate's requests carry the bearer token, the SPC and the manifest: a redirect must never re-send them.
@Suite("FairPlay HTTP redirects")
struct FairPlayHTTPRedirectTests {
    @Test("A FairPlay request answered with a redirect is not redirected: the 3xx is the answer",
          arguments: ["GET certificate", "POST session/start", "POST key-request", "DELETE session/s-1"])
    func notFollowed(route: String) async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RedirectingURLProtocol.self]
        let http = URLSessionFairPlayHTTP(configuration: configuration)
        let parts = route.split(separator: " ")
        let marker = UUID().uuidString
        var request = URLRequest(url: URL(string: "https://platform.example/\(marker)/media/v1/\(parts[1])")!)
        request.httpMethod = String(parts[0])
        request.setValue("Bearer redirect-test-token", forHTTPHeaderField: "Authorization")
        if request.httpMethod == "POST" { request.httpBody = Data(#"{"spcData":"AAAA"}"#.utf8) }

        let (_, response) = try await http.data(for: request)

        #expect((response as? HTTPURLResponse)?.statusCode == 307)
        #expect(RedirectingURLProtocol.seen(marker).map(\.host) == ["platform.example"])
    }
}
