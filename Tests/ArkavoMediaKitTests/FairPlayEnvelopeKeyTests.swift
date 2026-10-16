import CryptoKit
import Foundation
import OpenTDFKit
import Synchronization
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

/// `.keyEnvelope` wraps its DEK to the license service's envelope key from `media/v1/envelope-key`, never to the
/// platform KAS key; `.legacyV2` keeps fetching the KAS key. Stubbed HTTP only: nothing reaches a network.
@Suite("FairPlay envelope key fetch")
struct FairPlayEnvelopeKeyTests {
    let policy = Data(#"{"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}"#.utf8)

    @Test("without a PEM, the envelope DEK is wrapped to the fetched envelope key and the KAO names its kid")
    func fetchedKeyWrapsTheDEK() async throws {
        let platformKAS = try TestKASKeyPair(), envelopeKey = try TestKASKeyPair()
        let kasURL = PlatformKASProtocol.serve(platformKAS.spkiPublicKeyPEM)
        let licenseService = try EnvelopeKeyService(serving: envelopeKey)
        let service = FMP4RecordingProtectionService(kasURL: kasURL, kasPublicKeyPEM: nil,
                                                     envelopeKeyHTTP: licenseService)
        let info = try await encryptionInformation(service, profile: .keyEnvelope)

        let requests = await licenseService.requests
        #expect(requests.map(\.url) == [kasURL.appendingPathComponent("media/v1/envelope-key")])
        #expect(requests.first?.httpMethod == "GET")
        #expect(PlatformKASProtocol.paths(kasURL).isEmpty)
        let accesses = try #require(info["keyAccess"] as? [[String: Any]])
        try #require(accesses.count == 1)
        #expect(accesses[0]["kid"] as? String == envelopeKey.envelopeKeyID)
        #expect(accesses[0]["url"] as? String == kasURL.absoluteString)
        let wrapped = try #require(accesses[0]["wrappedKey"] as? String)
        let dek = TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: envelopeKey.privateKeyPEM, wrappedKey: wrapped))
        #expect(dek.count == 32)
        // The unwrapped key is the DEK: it reproduces the policy binding.
        let encodedPolicy = try #require(info["policy"] as? String)
        #expect((accesses[0]["policyBinding"] as? [String: String])?["hash"]
            == FairPlayPolicy.binding(policyBase64: encodedPolicy, dek: dek))
        #expect(throws: (any Error).self) {
            try TDFCrypto.unwrapSymmetricKeyWithRSA(privateKeyPEM: platformKAS.privateKeyPEM, wrappedKey: wrapped)
        }
    }

    @Test("an explicit kasKeyID overrides the fetched kid")
    func explicitKeyIDWins() async throws {
        let envelopeKey = try TestKASKeyPair()
        let kasURL = PlatformKASProtocol.serve(try TestKASKeyPair().spkiPublicKeyPEM)
        let licenseService = try EnvelopeKeyService(serving: envelopeKey)
        let service = FMP4RecordingProtectionService(kasURL: kasURL, kasPublicKeyPEM: nil,
                                                     envelopeKeyHTTP: licenseService)
        let info = try await encryptionInformation(service, profile: .keyEnvelope, kasKeyID: "caller-kid")

        #expect(await licenseService.requests.count == 1)
        let access = try #require((info["keyAccess"] as? [[String: Any]])?.first)
        #expect(access["kid"] as? String == "caller-kid")
        let wrapped = try #require(access["wrappedKey"] as? String)
        _ = try TDFCrypto.unwrapSymmetricKeyWithRSA(privateKeyPEM: envelopeKey.privateKeyPEM, wrappedKey: wrapped)
    }

    @Test("an explicit PEM is wrapped to as given, with the caller's kid or none, and nothing is fetched")
    func explicitPEMSkipsTheFetch() async throws {
        let envelopeKey = try TestKASKeyPair()
        let kasURL = PlatformKASProtocol.serve(try TestKASKeyPair().spkiPublicKeyPEM)
        let licenseService = EnvelopeKeyService(status: 503)
        let service = FMP4RecordingProtectionService(kasURL: kasURL, kasPublicKeyPEM: envelopeKey.spkiPublicKeyPEM,
                                                     envelopeKeyHTTP: licenseService)
        for kasKeyID in ["caller-kid", nil] as [String?] {
            let info = try await encryptionInformation(service, profile: .keyEnvelope, kasKeyID: kasKeyID)
            let access = try #require((info["keyAccess"] as? [[String: Any]])?.first)
            #expect(access["kid"] as? String == kasKeyID)
            let wrapped = try #require(access["wrappedKey"] as? String)
            _ = try TDFCrypto.unwrapSymmetricKeyWithRSA(privateKeyPEM: envelopeKey.privateKeyPEM, wrappedKey: wrapped)
        }
        #expect(await licenseService.requests.isEmpty)
        #expect(PlatformKASProtocol.paths(kasURL).isEmpty)
    }

    @Test(".legacyV2 without a PEM fetches the platform KAS key, never the envelope key")
    func legacyNeverFetchesTheEnvelopeKey() async throws {
        let platformKAS = try TestKASKeyPair()
        let kasURL = PlatformKASProtocol.serve(platformKAS.spkiPublicKeyPEM)
        let licenseService = try EnvelopeKeyService(serving: try TestKASKeyPair())
        let service = FMP4RecordingProtectionService(kasURL: kasURL, kasPublicKeyPEM: nil,
                                                     envelopeKeyHTTP: licenseService)
        let info = try await encryptionInformation(service, profile: .legacyV2, kasKeyID: "ignored")

        #expect(await licenseService.requests.isEmpty)
        #expect(PlatformKASProtocol.paths(kasURL) == ["/kas/v2/kas_public_key"])
        let access = try #require((info["keyAccess"] as? [[String: Any]])?.first)
        #expect(access["kid"] == nil)
        let wrapped = try #require(access["wrappedKey"] as? String)
        let videoKey = TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: platformKAS.privateKeyPEM, wrappedKey: wrapped))
        #expect(videoKey.count == 16)
    }

    /// A response the envelope-key fetch refuses.
    enum Refused: String, CaseIterable, Sendable {
        case notFound, serverError, profileOff, wrongAlgorithm, unparseableKey, weakKey, noKid, notJSON
    }

    @Test("anything but a 200 RSA-OAEP answer with a kid and a usable RSA key throws", arguments: Refused.allCases)
    func refusedResponse(_ refused: Refused) async throws {
        let key = try TestKASKeyPair()
        let (status, body, expected): (Int, Data, FairPlayEnvelopeKeyError) = switch refused {
        case .notFound:
            (404, Data(), .unexpectedStatus(404))
        case .serverError:
            (500, try EnvelopeKeyService.body(kid: key.envelopeKeyID, publicKey: key.spkiPublicKeyPEM),
             .unexpectedStatus(500))
        case .profileOff:
            (503, Data(#"{"error":"envelope profile disabled"}"#.utf8), .unexpectedStatus(503))
        case .wrongAlgorithm:
            (200, try EnvelopeKeyService.body(kid: key.envelopeKeyID, alg: "RSA1_5", publicKey: key.spkiPublicKeyPEM),
             .unsupportedAlgorithm("RSA1_5"))
        case .unparseableKey:
            (200, try EnvelopeKeyService.body(kid: "1f201402fd6b5f39c8b26994a2848c46",
                                              publicKey: "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----"),
             .invalidPublicKey(TDFManifestBuilder.TDFError.invalidPublicKeyFormat.localizedDescription))
        case .weakKey:
            (200, try EnvelopeKeyService.body(kid: "weak", publicKey: try TestKASKeyPair(bits: 1024).spkiPublicKeyPEM),
             .invalidPublicKey(TDFManifestBuilder.TDFError.weakPublicKey(bits: 1024).localizedDescription))
        case .noKid:
            (200, try EnvelopeKeyService.body(kid: nil, publicKey: key.spkiPublicKeyPEM), .invalidResponse("no kid"))
        case .notJSON:
            (200, Data(key.spkiPublicKeyPEM.utf8), .invalidResponse("the body is not a JSON object"))
        }
        let licenseService = EnvelopeKeyService(status: status, body: body)
        let error = await #expect(throws: expected) {
            _ = try await FairPlayEnvelopeKey.fetch(kasURL: URL(string: "https://platform.arkavo.net")!,
                                                    http: licenseService)
        }
        #expect(error?.errorDescription?.isEmpty == false)
        #expect(await licenseService.requests.count == 1)
    }

    @Test("a 503 stops packaging, with no fallback to the platform KAS key")
    func profileOffStopsPackaging() async throws {
        let kasURL = PlatformKASProtocol.serve(try TestKASKeyPair().spkiPublicKeyPEM)
        let service = FMP4RecordingProtectionService(kasURL: kasURL, kasPublicKeyPEM: nil,
                                                     envelopeKeyHTTP: EnvelopeKeyService(status: 503))
        let error = await #expect(throws: FairPlayEnvelopeKeyError.unexpectedStatus(503)) {
            _ = try await encryptionInformation(service, profile: .keyEnvelope)
        }
        #expect(error?.errorDescription?.contains("key-envelope profile turned off") == true)
        #expect(PlatformKASProtocol.paths(kasURL).isEmpty)
    }

    /// Packages a synthetic movie with `service`; the archive manifest's `encryptionInformation`.
    private func encryptionInformation(
        _ service: FMP4RecordingProtectionService, profile: FMP4RecordingProtectionService.PackagingProfile,
        kasKeyID: String? = nil
    ) async throws -> [String: Any] {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("envelope-key-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let movie = try await SyntheticMovie.make(in: directory)
        let archive = try await service.protectVideo(videoURL: movie, assetID: "test-asset", policyJSON: policy,
                                                     profile: profile, kasKeyID: kasKeyID)
        let zip = try Archive(data: archive, accessMode: .read)
        let entry = try #require(zip[FairPlayPackage.manifestName])
        var manifest = Data()
        _ = try zip.extract(entry) { manifest.append($0) }
        let object = try #require(JSONSerialization.jsonObject(with: manifest) as? [String: Any])
        return try #require(object["encryptionInformation"] as? [String: Any])
    }
}

private extension TestKASKeyPair {
    /// The license service's kid for this key: the first 32 lowercase hex characters of SHA-256 over its SPKI DER.
    var envelopeKeyID: String {
        // The body's lines end in CRLF (`.lineLength64Characters`).
        let base64 = spkiPublicKeyPEM.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix("-----") }.joined()
        let digest = SHA256.hash(data: Data(base64Encoded: base64)!)
        return String(digest.map { String(format: "%02x", $0) }.joined().prefix(32))
    }
}

/// The license service's `media/v1/envelope-key`: one scripted answer to every request, each request recorded.
actor EnvelopeKeyService: FairPlayHTTP {
    private(set) var requests: [URLRequest] = []
    private let status: Int
    private let body: Data

    init(status: Int, body: Data = Data()) {
        self.status = status
        self.body = body
    }

    /// Serves `key` as the live endpoint does: 200 and `{"kid", "alg": "RSA-OAEP", "publicKey"}`.
    init(serving key: TestKASKeyPair) throws {
        self.init(status: 200, body: try Self.body(kid: key.envelopeKeyID, publicKey: key.spkiPublicKeyPEM))
    }

    /// An envelope-key response body; a nil `kid` leaves it out.
    static func body(kid: String?, alg: String = "RSA-OAEP", publicKey: String) throws -> Data {
        var object = ["alg": alg, "publicKey": publicKey]
        object["kid"] = kid
        return try JSONSerialization.data(withJSONObject: object)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        requests.append(request)
        let url = try #require(request.url)
        let response = try #require(HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/2",
                                                    headerFields: ["Content-Type": "application/json"]))
        return (body, response)
    }
}

/// The platform KAS as `URLSession.shared` sees it, which is how `TDFManifestBuilder.fetchKASPublicKey()` reaches it.
/// It answers only hosts under `envelope-key-tests.invalid`, each a KAS of its own: `kas/v2/kas_public_key` gets the
/// key the host was made with, anything else a 404, and every path asked is recorded. Registered once and left in
/// place, it touches no other request, so tests running in parallel do not disturb each other.
final class PlatformKASProtocol: URLProtocol {
    private static let domain = ".envelope-key-tests.invalid"
    private static let kases = Mutex<[String: (pem: String, paths: [String])]>([:])
    private static let registration: Void = { _ = URLProtocol.registerClass(PlatformKASProtocol.self) }()

    /// The root of a new KAS whose public key is `pem`.
    static func serve(_ pem: String) -> URL {
        _ = registration
        let host = "kas-\(UUID().uuidString.lowercased())\(domain)"
        kases.withLock { $0[host] = (pem, []) }
        return URL(string: "https://\(host)")!
    }

    /// The paths asked of the KAS at `root`, in order.
    static func paths(_ root: URL) -> [String] {
        kases.withLock { $0[root.host ?? ""]?.paths ?? [] }
    }

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host?.hasSuffix(domain) == true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else { return }
        let pem: String? = Self.kases.withLock { kases in
            kases[url.host ?? ""]?.paths.append(url.path)
            return kases[url.host ?? ""]?.pem
        }
        var status = 404, body = Data()
        if url.path == "/kas/v2/kas_public_key", let pem,
           let json = try? JSONSerialization.data(withJSONObject: ["public_key": pem]) {
            status = 200
            body = json
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/2",
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
