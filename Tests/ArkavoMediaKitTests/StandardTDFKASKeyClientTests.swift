import CryptoKit
import Foundation
import OpenTDFKit
import Synchronization
import Testing
@testable import ArkavoMediaKit

// MARK: - URLProtocol stub

/// Intercepts every request on a session built with `session()` and hands it
/// to `handler`. Plays both the platform well-known document and the KAS
/// rewrap endpoint so `StandardTDFKASKeyClient` can be exercised offline.
///
/// Apple's URL loading system delivers a POST body to a `URLProtocol` as
/// `httpBodyStream`, not `httpBody`; `body(of:)` drains whichever is set.
final class KASStubURLProtocol: URLProtocol {
    typealias Handler = @Sendable (URLRequest, Data?) throws -> (HTTPURLResponse, Data)

    nonisolated(unsafe) static var handler: Handler?

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        do {
            let (response, data) = try handler(request, Self.body(of: request))
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    static func body(of request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let bufferSize = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [KASStubURLProtocol.self]
        return URLSession(configuration: configuration)
    }
}

// MARK: - Fake KAS

/// The KAS side of a standard-TDF rewrap, reproduced from the standard rather
/// than from OpenTDFKit: ECDH with the client's ephemeral P-256 key, HKDF-SHA256
/// with the given salt and empty info, AES-GCM `nonce || ciphertext || tag`.
/// The DEK is never RSA-unwrapped here; the fake simply returns `dek`.
final class FakeKAS: Sendable {
    /// Standard TDF session salt: SHA256("TDF"), as the Go SDK's `tdfSalt()`.
    static let standardTDFSalt = Data(SHA256.hash(data: Data("TDF".utf8)))

    /// NanoTDF v1.2 salt: SHA256(magic "L1" + version byte 0x4C). This is the
    /// library default for `KASRewrapClient.unwrapKey` and is wrong for HLS.
    static let nanoTDFSalt = Data(SHA256.hash(data: Data([0x4C, 0x31, 0x4C])))

    enum WellKnown: Sendable {
        case connect
        case restOnly
        case noKASBlock
        case unreachable
    }

    let platformBase = "https://platform.example.com"
    let dek: SymmetricKey
    let salt: Data
    let wellKnown: WellKnown
    let expectedBearer: String

    /// Every URL the client hit, in order.
    let requestedURLs = Mutex<[URL]>([])
    /// The unsigned rewrap request body (the JWT's `requestBody` JSON), if any.
    let rewrapRequestJSON = Mutex<Data?>(nil)

    init(dek: SymmetricKey = SymmetricKey(size: .bits128),
         salt: Data = FakeKAS.standardTDFSalt,
         wellKnown: WellKnown = .connect,
         expectedBearer: String = "test-session-token")
    {
        self.dek = dek
        self.salt = salt
        self.wellKnown = wellKnown
        self.expectedBearer = expectedBearer
    }

    var connectRewrapURL: String { "\(platformBase)/kas.AccessService/Rewrap" }
    var legacyRewrapURL: String { "\(platformBase)/kas/v2/rewrap" }

    var dekBytes: Data { dek.withUnsafeBytes { Data($0) } }

    /// Installs this fake as the stub handler and returns a session routed to it.
    func install() -> URLSession {
        KASStubURLProtocol.handler = { [self] request, body in try self.handle(request, body: body) }
        return KASStubURLProtocol.session()
    }

    private func handle(_ request: URLRequest, body: Data?) throws -> (HTTPURLResponse, Data) {
        let url = try #require(request.url)
        requestedURLs.withLock { $0.append(url) }

        switch url.absoluteString {
        case "\(platformBase)/.well-known/opentdf-configuration":
            return try wellKnownResponse(url)
        case connectRewrapURL:
            return try rewrap(request, url: url, body: body)
        case legacyRewrapURL:
            // arkavo-rs serves /kas/v2/rewrap locally for NanoTDF only; a
            // standard TDF request is refused before the policy is looked at.
            return (http(url, 400), Data(#"{"error":"missing field `header`"}"#.utf8))
        default:
            return (http(url, 404), Data())
        }
    }

    private func wellKnownResponse(_ url: URL) throws -> (HTTPURLResponse, Data) {
        var kas: [String: Any]?
        switch wellKnown {
        case .connect:
            kas = [
                "uri": platformBase,
                "algorithms": ["rsa:2048"],
                "connect_public_key_url": "\(platformBase)/kas.AccessService/PublicKey",
                "connect_rewrap_url": connectRewrapURL,
            ]
        case .restOnly:
            kas = [
                "uri": platformBase,
                "algorithms": ["rsa:2048"],
                "public_key_url": "\(platformBase)/kas/v2/kas_public_key",
                "rewrap_url": legacyRewrapURL,
            ]
        case .noKASBlock:
            kas = nil
        case .unreachable:
            return (http(url, 404), Data("not found".utf8))
        }
        var document: [String: Any] = ["platform_issuer": "https://idp.example.com"]
        if let kas { document["kas"] = kas }
        return (http(url, 200), try JSONSerialization.data(withJSONObject: document))
    }

    private func rewrap(_ request: URLRequest, url: URL, body: Data?) throws -> (HTTPURLResponse, Data) {
        guard request.value(forHTTPHeaderField: "Authorization") == "Bearer \(expectedBearer)" else {
            return (http(url, 401), Data(#"{"code":"unauthenticated","message":"unauthenticated"}"#.utf8))
        }
        let unsignedJSON = try Self.unsignedRequestJSON(fromSignedBody: try #require(body))
        rewrapRequestJSON.withLock { $0 = unsignedJSON }
        let unsigned = try #require(try JSONSerialization.jsonObject(with: unsignedJSON) as? [String: Any])
        let clientPEM = try #require(unsigned["clientPublicKey"] as? String)
        let clientPublicKey = try P256.KeyAgreement.PublicKey(pemRepresentation: clientPEM)

        let sessionKey = P256.KeyAgreement.PrivateKey()
        let shared = try sessionKey.sharedSecretFromKeyAgreement(with: clientPublicKey)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32
        )
        let box = try AES.GCM.seal(dekBytes, using: kek)
        let wrapped = try #require(box.combined)

        let response: [String: Any] = [
            "responses": [[
                "policyId": "policy",
                "results": [[
                    "keyAccessObjectId": "kao-0",
                    "status": "permit",
                    "kasWrappedKey": wrapped.base64EncodedString(),
                ]],
            ]],
            "sessionPublicKey": sessionKey.publicKey.pemRepresentation,
        ]
        return (http(url, 200), try JSONSerialization.data(withJSONObject: response))
    }

    /// `{"signed_request_token": "<ES256 JWT>"}` → JWT claims → `requestBody`
    /// (a JSON string) → the unsigned rewrap request as JSON bytes.
    static func unsignedRequestJSON(fromSignedBody body: Data) throws -> Data {
        let signed = try JSONDecoder().decode([String: String].self, from: body)
        let token = try #require(signed["signed_request_token"])
        let parts = token.split(separator: ".")
        #expect(parts.count == 3, "expected a compact JWT, got \(parts.count) parts")
        let claims = try #require(
            try JSONSerialization.jsonObject(with: base64URLDecode(String(parts[1]))) as? [String: Any]
        )
        let requestBody = try #require(claims["requestBody"] as? String)
        return Data(requestBody.utf8)
    }

    private static func base64URLDecode(_ s: String) throws -> Data {
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        return try #require(Data(base64Encoded: b64))
    }

    private func http(_ url: URL, _ status: Int) -> HTTPURLResponse {
        HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1",
                        headerFields: ["Content-Type": "application/json"])!
    }
}

// MARK: - Fixtures

private enum Fixture {
    static let kasURL = URL(string: "https://platform.example.com/kas")!
    static let policyJSON = #"{"uuid":"asset-kas-001","body":{"dataAttributes":["https://example.com/attr/tier/value/premium"],"dissem":[]}}"#
    static var policyBase64: String { Data(policyJSON.utf8).base64EncodedString() }
    static let wrappedKey = Data(repeating: 0x5A, count: 256).base64EncodedString()
    static let iv = Data(repeating: 0x01, count: 16).base64EncodedString()

    /// The binding the packager would have written (HMAC over the base64
    /// policy string, base64) for some DEK; the fake KAS never checks it,
    /// the tests only assert it reaches the wire unchanged.
    static var policyBinding: TDFPolicyBinding {
        TDFCrypto.policyBinding(policy: Data(policyJSON.utf8), symmetricKey: SymmetricKey(data: Data(repeating: 0xAB, count: 16)))
    }

    static func hlsManifest(policy: String? = policyBase64,
                            bindingAlg: String? = policyBinding.alg,
                            bindingHash: String? = policyBinding.hash) -> HLSManifest
    {
        HLSManifest(
            assetID: "asset-kas-001",
            wrappedKey: wrappedKey,
            algorithm: "AES-128-CBC",
            segmentIVs: [iv],
            segmentCount: 1,
            totalDuration: 6.0,
            encryptionMode: "CBC",
            kasURL: kasURL,
            policy: policy,
            policyBindingAlg: bindingAlg,
            policyBindingHash: bindingHash
        )
    }

    /// A standard TDF archive (`0.manifest.json` + `0.payload`) whose manifest
    /// points at the fake KAS.
    static func tdfArchive() throws -> Data {
        let manifest = OpenTDFKit.TDFManifestBuilder().buildStandardManifest(
            wrappedKey: wrappedKey,
            kasURL: kasURL,
            policy: policyBase64,
            iv: iv,
            policyBinding: policyBinding
        )
        return try TDFArchiveWriter().buildArchive(manifest: manifest, payload: Data(repeating: 0x33, count: 64))
    }
}

// MARK: - Route policy (pure)

@Suite("StandardTDFKASKeyClient route policy")
struct StandardTDFKASKeyClientRoutePolicyTests {
    private let platformBase = "https://platform.example.com"

    private func document(uri: String = "https://kas.example.com", rest: Bool, connect: Bool) -> OpenTDFConfiguration {
        OpenTDFConfiguration(
            kas: KasConfig(
                uri: uri,
                algorithms: ["rsa:2048"],
                publicKeyURL: rest ? "\(uri)/kas/v2/kas_public_key" : nil,
                rewrapURL: rest ? "\(uri)/kas/v2/rewrap" : nil,
                connectPublicKeyURL: connect ? "\(uri)/kas.AccessService/PublicKey" : nil,
                connectRewrapURL: connect ? "\(uri)/kas.AccessService/Rewrap" : nil
            ),
            idp: nil,
            platformIssuer: nil
        )
    }

    @Test("advertised Connect pair is used as-is")
    func advertisedConnectPairIsUsedAsIs() throws {
        let resolved = StandardTDFKASKeyClient.resolveKASConfiguration(
            platformBase: platformBase,
            discovered: .success(document(rest: true, connect: true))
        )
        let endpoints = try KasEndpoints.from(resolved)
        #expect(endpoints.transport == .connect)
        #expect(endpoints.rewrapURL == "https://kas.example.com/kas.AccessService/Rewrap")
    }

    @Test("REST-only document falls back to Connect defaults, never legacy REST")
    func restOnlyDocumentFallsBackToConnectDefaults() throws {
        let resolved = StandardTDFKASKeyClient.resolveKASConfiguration(
            platformBase: platformBase,
            discovered: .success(document(rest: true, connect: false))
        )
        let endpoints = try KasEndpoints.from(resolved)
        #expect(endpoints.transport == .connect, "a REST-only document must not route to /kas/v2/rewrap")
        #expect(endpoints.rewrapURL == "\(platformBase)/kas.AccessService/Rewrap")
    }

    @Test("document with no kas block or empty uri falls back without throwing")
    func documentWithoutUsableKASBlockFallsBack() throws {
        let noBlock = OpenTDFConfiguration(kas: nil, idp: nil, platformIssuer: nil)
        let emptyURI = document(uri: "", rest: false, connect: false)
        for doc in [noBlock, emptyURI] {
            let resolved = StandardTDFKASKeyClient.resolveKASConfiguration(platformBase: platformBase, discovered: .success(doc))
            let endpoints = try KasEndpoints.from(resolved)
            #expect(endpoints.transport == .connect)
            #expect(endpoints.rewrapURL == "\(platformBase)/kas.AccessService/Rewrap")
        }
    }

    @Test("unreachable document falls back to Connect defaults")
    func unreachableDocumentFallsBack() throws {
        let resolved = StandardTDFKASKeyClient.resolveKASConfiguration(
            platformBase: platformBase,
            discovered: .failure(URLError(.notConnectedToInternet))
        )
        let endpoints = try KasEndpoints.from(resolved)
        #expect(endpoints.transport == .connect)
        #expect(endpoints.rewrapURL == "\(platformBase)/kas.AccessService/Rewrap")
    }
}

// MARK: - Against the stub

/// Serialized (recursively): `KASStubURLProtocol.handler` is process-global,
/// so every test that installs a `FakeKAS` must run alone.
@Suite("StandardTDFKASKeyClient against a stub KAS", .serialized)
enum StandardTDFKASKeyClientStubTests {

@Suite("StandardTDFKASKeyClient rewrap")
struct RewrapTests {
    @Test("HLS manifest unwraps to the DEK when the KAS wraps with the standard salt")
    func hlsManifestUnwrapsWithStandardSalt() async throws {
        let kas = FakeKAS(salt: FakeKAS.standardTDFSalt)
        let client = StandardTDFKASKeyClient(urlSession: kas.install())

        let key = try await client.unwrapKey(manifest: Fixture.hlsManifest(), authToken: kas.expectedBearer)

        #expect(key.withUnsafeBytes { Data($0) } == kas.dekBytes)
        let urls = kas.requestedURLs.withLock { $0 }.map(\.absoluteString)
        #expect(urls == ["\(kas.platformBase)/.well-known/opentdf-configuration", kas.connectRewrapURL])
    }

    @Test("rewrap request carries the manifest policy and key access object the KAS verifies")
    func rewrapRequestCarriesPolicyAndKeyAccess() async throws {
        let kas = FakeKAS()
        let client = StandardTDFKASKeyClient(urlSession: kas.install())

        _ = try await client.unwrapKey(manifest: Fixture.hlsManifest(), authToken: kas.expectedBearer)

        let json = try #require(kas.rewrapRequestJSON.withLock { $0 })
        let request = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        let requests = try #require(request["requests"] as? [[String: Any]])
        let first = try #require(requests.first)
        let policy = try #require(first["policy"] as? [String: Any])
        #expect(policy["body"] as? String == Fixture.policyBase64)
        #expect(first["algorithm"] as? String == "rsa:2048")

        let kaos = try #require(first["keyAccessObjects"] as? [[String: Any]])
        let kao = try #require(kaos.first?["keyAccessObject"] as? [String: Any])
        #expect(kao["url"] as? String == Fixture.kasURL.absoluteString)
        #expect(kao["type"] as? String == "wrapped")
        #expect(kao["protocol"] as? String == "kas")
        #expect(kao["wrappedKey"] as? String == Fixture.wrappedKey)
        let binding = try #require(kao["policyBinding"] as? [String: Any])
        #expect(binding["alg"] as? String == Fixture.policyBinding.alg)
        #expect(binding["hash"] as? String == Fixture.policyBinding.hash)
    }

    @Test("unwrap fails when the KAS wraps with the NanoTDF salt")
    func unwrapFailsWithNanoTDFSalt() async throws {
        let kas = FakeKAS(salt: FakeKAS.nanoTDFSalt)
        let client = StandardTDFKASKeyClient(urlSession: kas.install())

        await #expect(throws: (any Error).self, "a DEK wrapped with the NanoTDF salt must not unwrap on the standard-TDF path") {
            _ = try await client.unwrapKey(manifest: Fixture.hlsManifest(), authToken: kas.expectedBearer)
        }
    }

    @Test("REST-only well-known still rewraps on the Connect route")
    func restOnlyWellKnownRewrapsOnConnect() async throws {
        let kas = FakeKAS(wellKnown: .restOnly)
        let client = StandardTDFKASKeyClient(urlSession: kas.install())

        let key = try await client.unwrapKey(manifest: Fixture.hlsManifest(), authToken: kas.expectedBearer)

        #expect(key.withUnsafeBytes { Data($0) } == kas.dekBytes)
        let urls = kas.requestedURLs.withLock { $0 }.map(\.absoluteString)
        #expect(urls.contains(kas.connectRewrapURL))
        #expect(!urls.contains(kas.legacyRewrapURL))
    }

    @Test("unreachable well-known falls back to the Connect route under the platform base")
    func unreachableWellKnownRewrapsOnConnect() async throws {
        let kas = FakeKAS(wellKnown: .unreachable)
        let client = StandardTDFKASKeyClient(urlSession: kas.install())

        let key = try await client.unwrapKey(manifest: Fixture.hlsManifest(), authToken: kas.expectedBearer)

        #expect(key.withUnsafeBytes { Data($0) } == kas.dekBytes)
        let urls = kas.requestedURLs.withLock { $0 }.map(\.absoluteString)
        #expect(urls.last == kas.connectRewrapURL)
    }

    @Test("KAS errors propagate unchanged")
    func kasErrorsPropagate() async throws {
        let kas = FakeKAS(expectedBearer: "someone-else")
        let client = StandardTDFKASKeyClient(urlSession: kas.install())

        await #expect(throws: KASRewrapError.self) {
            _ = try await client.unwrapKey(manifest: Fixture.hlsManifest(), authToken: "stale-token")
        }
    }

    @Test("HLS manifest without policy data throws missingPolicyData before any request")
    func missingPolicyDataThrows() async throws {
        let kas = FakeKAS()
        let client = StandardTDFKASKeyClient(urlSession: kas.install())

        for manifest in [
            Fixture.hlsManifest(policy: nil),
            Fixture.hlsManifest(bindingAlg: nil),
            Fixture.hlsManifest(bindingHash: nil),
        ] {
            await #expect(throws: StandardTDFKASKeyClientError.missingPolicyData) {
                _ = try await client.unwrapKey(manifest: manifest, authToken: kas.expectedBearer)
            }
        }
        #expect(kas.requestedURLs.withLock { $0 }.isEmpty)
    }
}

// MARK: - StandardTDFKeyProvider wiring

@Suite("StandardTDFKeyProvider KAS rewrap")
struct KeyProviderTests {
    @Test("useKASRewrap without a token provider throws notAuthenticated")
    func noTokenProviderThrowsNotAuthenticated() async throws {
        let kas = FakeKAS()
        let provider = StandardTDFKeyProvider(
            kasURL: Fixture.kasURL,
            kasPublicKeyPEM: "",
            sessionManager: TDF3MediaSession(),
            kasKeyClient: StandardTDFKASKeyClient(urlSession: kas.install())
        )

        await #expect(throws: KeyProviderError.notAuthenticated) {
            _ = try await provider.unwrapSegmentKey(tdfData: try Fixture.tdfArchive(), useKASRewrap: true)
        }
        #expect(kas.requestedURLs.withLock { $0 }.isEmpty)
    }

    @Test("token provider returning nil throws notAuthenticated")
    func nilTokenThrowsNotAuthenticated() async throws {
        let kas = FakeKAS()
        let provider = StandardTDFKeyProvider(
            kasURL: Fixture.kasURL,
            kasPublicKeyPEM: "",
            sessionManager: TDF3MediaSession(),
            authTokenProvider: { nil },
            kasKeyClient: StandardTDFKASKeyClient(urlSession: kas.install())
        )

        await #expect(throws: KeyProviderError.notAuthenticated) {
            _ = try await provider.unwrapSegmentKey(tdfData: try Fixture.tdfArchive(), useKASRewrap: true)
        }
    }

    @Test("useKASRewrap with a token provider reaches the KAS and returns the DEK")
    func tokenProviderUnwrapsViaKAS() async throws {
        let kas = FakeKAS()
        let provider = StandardTDFKeyProvider(
            kasURL: Fixture.kasURL,
            kasPublicKeyPEM: "",
            sessionManager: TDF3MediaSession(),
            authTokenProvider: { kas.expectedBearer },
            kasKeyClient: StandardTDFKASKeyClient(urlSession: kas.install())
        )

        let key = try await provider.unwrapSegmentKey(tdfData: try Fixture.tdfArchive(), useKASRewrap: true)

        #expect(key.withUnsafeBytes { Data($0) } == kas.dekBytes)
        #expect(kas.requestedURLs.withLock { $0 }.last?.absoluteString == kas.connectRewrapURL)
    }

    @Test("offline RSA path is untouched by the KAS wiring")
    func offlinePathStillRequiresPrivateKey() async throws {
        let provider = StandardTDFKeyProvider(
            kasURL: Fixture.kasURL,
            kasPublicKeyPEM: "",
            sessionManager: TDF3MediaSession()
        )
        await #expect(throws: KeyProviderError.noPrivateKey) {
            _ = try await provider.unwrapSegmentKey(tdfData: try Fixture.tdfArchive(), useKASRewrap: false)
        }
    }
}

}
