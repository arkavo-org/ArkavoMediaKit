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

    private(set) var calls: [Call] = []
    private var sessions = 0
    private var refused: String?

    init(refusing component: String? = nil) { refused = component }

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
        switch route {
        case "GET certificate":
            return respond(request, 200, Data(repeating: 0x30, count: 64))
        case "POST session/start":
            sessions += 1
            return respond(request, 200, Data(#"{"sessionId":"session-\#(sessions)","status":"started"}"#.utf8))
        case "POST key-request" where body["component"] != nil && body["component"] == refused:
            return respond(request, 403, Data(#"{"error":"forbidden","message":"manifest refused"}"#.utf8))
        case "POST key-request":
            let ckc = Self.ckc(for: body["component"] ?? "v1").base64EncodedString()
            return respond(request, 200, Data(#"{"status":"success","wrappedKey":"\#(ckc)"}"#.utf8))
        default:
            return respond(request, route.hasPrefix("DELETE session/") ? 200 : 404, Data())
        }
    }

    private func respond(_ request: URLRequest, _ status: Int, _ body: Data) -> (Data, URLResponse) {
        (body, HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!)
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

    init(_ keyIdentifier: String?) { self.keyIdentifier = keyIdentifier }

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

    func fail(_ error: Error) { log.withLock { $0.errors.append(error) } }
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

    static func delegate(manifest: FairPlayManifest, service: FakeMediaService)
        -> (TDFContentKeyDelegate<FairPlayManifest>, Outcomes) {
        let delegate = TDFContentKeyDelegate(
            manifest: manifest, authToken: "token", userId: "viewer",
            serverURL: URL(string: "https://platform.arkavo.net")!, http: service)
        let outcomes = Outcomes()
        delegate.onKeyDelivered = { outcomes.record("ready") }
        delegate.onKeyFailed = { _ in outcomes.record("failed") }
        return (delegate, outcomes)
    }

    @Test("A package's keys are its components' skd:// URIs, in order; profile v1 has the uuid's alone")
    func keyIdentifiers() throws {
        #expect(try Self.delegate(service: FakeMediaService()).0.keyIdentifiers == [Self.video, Self.audio])
        #expect(try Self.delegate([.video], service: FakeMediaService()).0.keyIdentifiers == [Self.video])
        #expect(try Self.delegate(nil, service: FakeMediaService()).0.keyIdentifiers == ["skd://\(Self.uuid)"])
    }

    @Test("Each component's key is its own license request, and ready is reported once, after the last key")
    func everyKeyThenReady() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)
        let video = FakeKeyRequest(Self.video), audio = FakeKeyRequest(Self.audio)

        await delegate.handle(video)
        #expect(await outcomes.reported() == [])
        await delegate.handle(audio)
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
        let starts = calls.filter { $0.route == "POST session/start" }
        #expect(starts.map { $0.body["assetId"] } == [Self.uuid, Self.uuid])
        let keyRequests = calls.filter { $0.route == "POST key-request" }
        #expect(keyRequests.map { $0.body["component"] } == ["video", "audio"])
        #expect(keyRequests.map { $0.body["assetId"] } == [Self.uuid, Self.uuid])
        #expect(keyRequests.map { $0.body["sessionId"] } == ["session-1", "session-2"])
        #expect(keyRequests.allSatisfy { $0.body["spcData"] != nil && $0.body["tdfManifest"] != nil })
    }

    @Test("Keys answered in either order report ready once, after the last")
    func outOfOrder() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService())
        await delegate.handle(FakeKeyRequest(Self.audio))
        #expect(await outcomes.reported() == [])
        await delegate.handle(FakeKeyRequest(Self.video))
        #expect(await outcomes.reported() == ["ready"])
    }

    @Test("Keys asked for at once share one certificate fetch and have a session each")
    func concurrent() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)
        async let first: Void = delegate.handle(FakeKeyRequest(Self.video))
        async let second: Void = delegate.handle(FakeKeyRequest(Self.audio))
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

        await delegate.handle(video)
        await delegate.handle(audio)

        #expect(await outcomes.reported() == ["failed"])
        #expect(video.ckcs.count == 1)
        #expect(audio.ckcs.isEmpty && audio.failures == 1)
        #expect(await service.calls.filter { $0.route.hasPrefix("DELETE session/") }.count == 2)
    }

    @Test("After a failure, a later key is still answered but reports nothing")
    func failureThenKey() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService(refusing: "video"))
        let video = FakeKeyRequest(Self.video), audio = FakeKeyRequest(Self.audio)

        await delegate.handle(video)
        #expect(await outcomes.reported() == ["failed"])
        await delegate.handle(audio)

        #expect(audio.ckcs.count == 1)
        #expect(await outcomes.reported() == ["failed"])
    }

    @Test("A renewal after ready is its own license request and reports nothing more")
    func renewalAfterReady() async throws {
        let service = FakeMediaService()
        let (delegate, outcomes) = try Self.delegate(service: service)

        await delegate.handle(FakeKeyRequest(Self.video))
        await delegate.handle(FakeKeyRequest(Self.audio))
        let renewal = FakeKeyRequest(Self.video)
        await delegate.handle(renewal, renewal: true)

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

        await delegate.handle(FakeKeyRequest(Self.video))
        await service.refuse("video")
        let renewal = FakeKeyRequest(Self.video)
        await delegate.handle(renewal, renewal: true)
        #expect(renewal.ckcs.isEmpty && renewal.failures == 1)
        await delegate.keyRequestFailed(FairPlayError.invalidCKCResponse("renewal"), renewal: true)
        #expect(await outcomes.reported() == [])

        await delegate.handle(FakeKeyRequest(Self.audio))
        #expect(await outcomes.reported() == ["ready"])
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

        await delegate.handle(request)

        #expect(await outcomes.reported() == ["ready"])
        #expect(request.contentIdentifiers == [Self.uuid])
        let keyRequest = try #require(await service.calls.first { $0.route == "POST key-request" })
        #expect(keyRequest.body["component"] == nil)
        #expect(keyRequest.body["assetId"] == Self.uuid)
    }

    @Test("AVFoundation's key failure before ready reports one failure; after ready, nothing")
    func avFoundationFailure() async throws {
        let (failing, failingOutcomes) = try Self.delegate(service: FakeMediaService())
        await failing.keyRequestFailed(FairPlayError.invalidCKCResponse("rejected"))
        await failing.keyRequestFailed(FairPlayError.invalidCKCResponse("again"))
        #expect(await failingOutcomes.reported() == ["failed"])

        let (ready, readyOutcomes) = try Self.delegate(service: FakeMediaService())
        await ready.handle(FakeKeyRequest(Self.video))
        await ready.handle(FakeKeyRequest(Self.audio))
        await ready.keyRequestFailed(FairPlayError.invalidCKCResponse("late"))
        #expect(await readyOutcomes.reported() == ["ready"])
    }

    @Test("Callbacks set while keys are answered never race the answers")
    func callbacksSetConcurrently() async throws {
        let (delegate, outcomes) = try Self.delegate(service: FakeMediaService())
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await delegate.handle(FakeKeyRequest(Self.video)) }
            group.addTask { await delegate.handle(FakeKeyRequest(Self.audio)) }
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
        @Test("The exchange prints no SPC, CKC, wrapped key or IV, however formatted")
        func printsNoKeyMaterial() async throws {
            let original = FairPlayDebugConfig.isVerboseLoggingEnabled
            FairPlayDebugConfig.isVerboseLoggingEnabled = true
            defer { FairPlayDebugConfig.isVerboseLoggingEnabled = original }
            // A uuid of this test's own, so the positive control below cannot see another test's exchange.
            let uuid = UUID().uuidString.lowercased()
            let manifest = try TDFContentKeyDelegateComponentTests.manifest(components: [.video, .audio], uuid: uuid)
            let (_, output) = try await StdoutCapture.capture {
                let (delegate, _) = TDFContentKeyDelegateComponentTests.delegate(
                    manifest: manifest, service: FakeMediaService())
                await delegate.handle(FakeKeyRequest("skd://\(uuid)/video"))
                await delegate.handle(FakeKeyRequest("skd://\(uuid)/audio"))
            }
            // The positive control: the capture saw this exchange's log, so the absences below are not vacuous.
            #expect(output.contains("Key delivered: skd://\(uuid)/video"))
            #expect(output.contains("Key delivered: skd://\(uuid)/audio"))

            let secrets = [
                FakeKeyRequest.spc(for: "\(uuid)/video"), FakeKeyRequest.spc(for: "\(uuid)/audio"),
                FakeMediaService.ckc(for: "video"), FakeMediaService.ckc(for: "audio"),
                TDFContentKeyDelegateComponentTests.wrappedKey, TDFContentKeyDelegateComponentTests.iv,
            ]
            for secret in secrets {
                let base64 = secret.base64EncodedString()
                let hex = secret.map { String(format: "%02x", $0) }.joined()
                let spacedHex = secret.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
                for text in [base64, base64.replacingOccurrences(of: "/", with: #"\/"#), hex, hex.uppercased(),
                             String(hex.prefix(32)), String(base64.prefix(40)), spacedHex] {
                    #expect(!output.contains(text))
                }
            }
        }
    }
}
