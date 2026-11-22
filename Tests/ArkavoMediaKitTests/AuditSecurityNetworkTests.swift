import CryptoKit
import Foundation
import OpenTDFKit
import Synchronization
import Testing
@testable import ArkavoMediaKit

// MARK: - Isolated URLProtocol for Security & Network Tests

private final class AuditStubURLProtocol: URLProtocol {
    typealias Handler = @Sendable (URLRequest, Data?) throws -> (HTTPURLResponse, Data, URL?)
    private static let handlers = Mutex<[String: Handler]>([:])

    static func register(host: String, handler: @escaping Handler) {
        handlers.withLock { $0[host] = handler }
    }

    static func unregister(host: String) {
        handlers.withLock { _ = $0.removeValue(forKey: host) }
    }

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [AuditStubURLProtocol.self]
        return URLSession(configuration: config, delegate: RedirectRefusal(), delegateQueue: nil)
    }

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url,
              let host = url.host,
              let handler = Self.handlers.withLock({ $0[host] })
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            return
        }
        do {
            let (response, data, redirectTarget) = try handler(request, readBody(of: request))
            if let redirectTarget {
                var redirected = request
                redirected.url = redirectTarget
                client?.urlProtocol(self, wasRedirectedTo: redirected, redirectResponse: response)
                // If delegate refused redirect, deliver the 3xx response directly
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                client?.urlProtocolDidFinishLoading(self)
                return
            }
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    private func readBody(of request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buffer, maxLength: buffer.count)
            if n <= 0 { break }
            data.append(buffer, count: n)
        }
        return data
    }
}

// MARK: - SSRF, Origin Allowlist, Redirect Refusal & Path Traversal Tests

@Suite("Audit: SSRF, Origin Allowlist, Redirects & Path Traversal")
struct AuditSecurityNetworkTests {
    private static func makeManifest(kasURL: String) -> TDFManifest {
        let policyJSON = Data(#"{"uuid":"11111111-2222-3333-4444-555555555555","body":{}}"#.utf8)
        let dek = SymmetricKey(size: .bits128)
        let binding = TDFCrypto.policyBinding(policy: policyJSON, symmetricKey: dek)
        return OpenTDFKit.TDFManifestBuilder().buildStandardManifest(
            wrappedKey: Data(repeating: 0xAA, count: 256).base64EncodedString(),
            kasURL: URL(string: kasURL)!,
            policy: policyJSON.base64EncodedString(),
            iv: Data(repeating: 0x01, count: 16).base64EncodedString(),
            policyBinding: binding
        )
    }

    @Test("StandardTDFKASKeyClient rejects untrusted manifest kasURL origin before sending bearer token")
    func kasClientRejectsUntrustedOrigin() async throws {
        let host = "evil-\(UUID().uuidString.lowercased()).example.com"
        let requested = Mutex<[URL]>([])
        AuditStubURLProtocol.register(host: host) { req, _ in
            if let url = req.url { requested.withLock { $0.append(url) } }
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            return (resp, Data(), nil)
        }
        defer { AuditStubURLProtocol.unregister(host: host) }

        let client = StandardTDFKASKeyClient(
            urlSession: AuditStubURLProtocol.session(),
            allowedKASOrigins: ["https://trusted.arkavo.net"]
        )
        let manifest = Self.makeManifest(kasURL: "https://\(host)/kas")

        await #expect(throws: StandardTDFKASKeyClientError.untrustedKASOrigin("https://\(host)/kas")) {
            _ = try await client.unwrapKey(manifest: manifest, authToken: "secret-oauth-bearer")
        }
        #expect(requested.withLock { $0 }.isEmpty, "No request should be sent to untrusted origin")
    }

    @Test("StandardTDFKASKeyClient rejects SSRF private IPs and cleartext HTTP manifest kasURL")
    func kasClientRejectsSSRFURLs() async throws {
        let client = StandardTDFKASKeyClient(urlSession: AuditStubURLProtocol.session())
        let hostileURLs = [
            "http://attacker.example.com/kas",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.1/kas",
            "https://192.168.1.1/kas",
        ]
        for url in hostileURLs {
            let manifest = Self.makeManifest(kasURL: url)
            await #expect(throws: KASDiscoveryError.self) {
                _ = try await client.unwrapKey(manifest: manifest, authToken: "secret-token")
            }
        }
    }

    @Test("resolveKASConfiguration preserves hostile Connect endpoints so KasEndpoints.from throws SSRF error")
    func resolveKASConfigurationDoesNotSwallowSSRF() {
        let hostile = OpenTDFConfiguration(
            kas: KasConfig(
                uri: "https://trusted.example.com",
                algorithms: ["rsa:2048"],
                publicKeyURL: nil,
                rewrapURL: nil,
                connectPublicKeyURL: "https://169.254.169.254/kas.AccessService/PublicKey",
                connectRewrapURL: "https://169.254.169.254/kas.AccessService/Rewrap"
            ),
            idp: nil,
            platformIssuer: nil
        )

        let resolved = StandardTDFKASKeyClient.resolveKASConfiguration(
            platformBase: "https://trusted.example.com",
            discovered: .success(hostile)
        )
        #expect(throws: KASDiscoveryError.self) {
            _ = try KasEndpoints.from(resolved)
        }
    }

    @Test("StandardTDFKASKeyClient refuses HTTP redirects on well-known discovery")
    func kasClientRefusesWellKnownRedirect() async throws {
        let host = "redir-\(UUID().uuidString.lowercased()).example.com"
        let attackerHost = "attacker-\(UUID().uuidString.lowercased()).example.com"
        let hitAttacker = Mutex(false)

        AuditStubURLProtocol.register(host: host) { req, _ in
            let url = req.url!
            if url.path == "/.well-known/opentdf-configuration" {
                let target = URL(string: "https://\(attackerHost)/well-known")!
                let resp = HTTPURLResponse(
                    url: url, statusCode: 307, httpVersion: "HTTP/1.1",
                    headerFields: ["Location": target.absoluteString]
                )!
                return (resp, Data(), target)
            }
            // Fallback Connect rewrap returns 401 so unwrapKey terminates without hitting attacker
            let resp = HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1", headerFields: nil)!
            return (resp, Data(#"{"code":"unauthenticated","message":"denied"}"#.utf8), nil)
        }
        AuditStubURLProtocol.register(host: attackerHost) { req, _ in
            hitAttacker.withLock { $0 = true }
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            return (resp, Data(), nil)
        }
        defer {
            AuditStubURLProtocol.unregister(host: host)
            AuditStubURLProtocol.unregister(host: attackerHost)
        }

        let client = StandardTDFKASKeyClient(
            urlSession: AuditStubURLProtocol.session(),
            allowedKASOrigins: ["https://\(host)"]
        )
        let manifest = Self.makeManifest(kasURL: "https://\(host)/kas")
        await #expect(throws: (any Error).self) {
            _ = try await client.unwrapKey(manifest: manifest, authToken: "bearer-123")
        }
        #expect(!hitAttacker.withLock { $0 }, "Redirect target must never be contacted")
    }

    @Test("StandardTDFKeyProvider blocks off-origin manifest kasURL before calling KAS client")
    func keyProviderBlocksCrossOriginManifest() async throws {
        let kas = try TestKASKeyPair()
        let trustedURL = URL(string: "https://trusted.example.com/kas")!
        let attackerURL = URL(string: "https://attacker.example.com/kas")!
        let provider = StandardTDFKeyProvider(
            kasURL: trustedURL,
            kasPublicKeyPEM: kas.publicKeyPEM,
            sessionManager: TDF3MediaSession(),
            authTokenProvider: { "secret-bearer" }
        )

        let policyJSON = Data(#"{"uuid":"11111111-2222-3333-4444-555555555555","body":{}}"#.utf8)
        let dek = try TDFCrypto.generateSymmetricKey(size: .bits128)
        let wrapped = try TDFCrypto.wrapSymmetricKeyWithRSA(publicKeyPEM: kas.publicKeyPEM, symmetricKey: dek)
        let manifest = OpenTDFKit.TDFManifestBuilder().buildStandardManifest(
            wrappedKey: wrapped,
            kasURL: attackerURL,
            policy: policyJSON.base64EncodedString(),
            iv: Data(repeating: 1, count: 16).base64EncodedString(),
            policyBinding: TDFCrypto.policyBinding(policy: policyJSON, symmetricKey: dek)
        )
        let archive = try TDFArchiveWriter().buildArchive(manifest: manifest, payload: Data([1, 2, 3]))

        await #expect(throws: StandardTDFKASKeyClientError.untrustedKASOrigin(attackerURL.absoluteString)) {
            _ = try await provider.unwrapSegmentKey(tdfData: archive, useKASRewrap: true)
        }
    }

    @Test("StandardTDFKeyProvider verifies offline policyBinding, session ownership, non-double-base64 key, and random IV")
    func keyProviderSecurityFixes() async throws {
        let kas = try TestKASKeyPair()
        let sessionManager = TDF3MediaSession()
        let provider = StandardTDFKeyProvider(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: kas.publicKeyPEM,
            sessionManager: sessionManager,
            rsaPrivateKeyPEM: kas.privateKeyPEM
        )

        // 1. generateWrappedSegmentKey uses non-zero random 12-byte GCM IV
        let policyJSON = Data(#"{"uuid":"11111111-2222-3333-4444-555555555555","body":{"dataAttributes":[],"dissem":[]}}"#.utf8)
        let (manifestData1, dek1) = try await provider.generateWrappedSegmentKey(
            assetID: "asset-1",
            segmentIndex: 0,
            policy: MediaDRMPolicy(),
            policyJSON: policyJSON
        )
        let decodedManifest = try JSONDecoder().decode(TDFManifest.self, from: manifestData1)
        let ivBytes = try #require(Data(base64Encoded: decodedManifest.encryptionInformation.method.iv))
        #expect(ivBytes.count == 12)
        #expect(ivBytes != Data(count: 12), "GCM IV must not be all-zero")

        // 2. requestKey rejects mismatched userID or assetID for the session
        let session = try await sessionManager.startSession(userID: "alice", assetID: "asset-1")
        let wrongUserReq = KeyAccessRequest(
            sessionID: session.sessionID,
            userID: "bob",
            assetID: "asset-1",
            segmentIndex: 0,
            tdfManifest: manifestData1.base64EncodedString()
        )
        await #expect(throws: KeyProviderError.sessionInvalid) {
            _ = try await provider.requestKey(request: wrongUserReq, policy: MediaDRMPolicy(), deviceInfo: DeviceInfo())
        }

        // 3. requestKey returns wrappedKey directly without double-base64 encoding
        let validReq = KeyAccessRequest(
            sessionID: session.sessionID,
            userID: "alice",
            assetID: "asset-1",
            segmentIndex: 0,
            tdfManifest: manifestData1.base64EncodedString()
        )
        let response = try await provider.requestKey(
            request: validReq,
            policy: MediaDRMPolicy(maxConcurrentStreams: 1),
            deviceInfo: DeviceInfo()
        )
        let expectedWrappedKey = try #require(decodedManifest.encryptionInformation.keyAccess.first?.wrappedKey)
        #expect(response.wrappedKey == expectedWrappedKey, "wrappedKey must not be double-base64 encoded")

        // 4. Offline RSA unwrap rejects tampered policyBinding
        var tamperedManifest = decodedManifest
        tamperedManifest.encryptionInformation.keyAccess[0].policyBinding = TDFPolicyBinding(
            alg: "HS256",
            hash: Data(repeating: 0xFF, count: 32).base64EncodedString()
        )
        let tamperedArchive = try TDFArchiveWriter().buildArchive(manifest: tamperedManifest, payload: Data([1, 2, 3]))
        await #expect(throws: KeyProviderError.policyValidationFailed("Policy binding verification failed")) {
            _ = try await provider.unwrapSegmentKey(tdfData: tamperedArchive, useKASRewrap: false)
        }
        _ = dek1
    }

    @Test("MediaServerClient and FairPlayKeyClient reject sessionId path traversal and redirects")
    func sessionIdPathTraversalAndRedirects() async throws {
        let host = "media-\(UUID().uuidString.lowercased()).example.com"
        let requestedPaths = Mutex<[String]>([])

        AuditStubURLProtocol.register(host: host) { req, _ in
            let url = req.url!
            requestedPaths.withLock { $0.append(url.path) }
            if url.path.hasSuffix("/session/start") {
                let body = Data(#"{"sessionId":"../../etc/passwd","status":"active"}"#.utf8)
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, body, nil)
            }
            let target = URL(string: "https://evil.example.com/steal")!
            let resp = HTTPURLResponse(
                url: url, statusCode: 307, httpVersion: "HTTP/1.1",
                headerFields: ["Location": target.absoluteString]
            )!
            return (resp, Data(), target)
        }
        defer { AuditStubURLProtocol.unregister(host: host) }

        let config = try DRMConfiguration(
            serverURL: URL(string: "https://\(host)")!,
            fpsCertificateData: Data([0x30, 0x82])
        )
        let client = MediaServerClient(configuration: config, session: AuditStubURLProtocol.session())

        // Path traversal in sessionId is rejected before any network request
        for badID in ["../admin", "a/b", "sess?x=1", "sess#frag", "..", "", "sess\\x"] {
            await #expect(throws: ValidationError.self) {
                try await client.sendHeartbeat(sessionId: badID, state: "playing")
            }
            await #expect(throws: ValidationError.self) {
                try await client.endSession(sessionId: badID)
            }
        }
        #expect(requestedPaths.withLock { $0 }.isEmpty)

        // Malicious sessionId returned by server is also rejected
        await #expect(throws: ValidationError.self) {
            _ = try await client.startSession(userID: "alice", assetID: "asset-1")
        }

        // Valid sessionId that receives a 307 redirect fails with httpError(307) and does not follow
        await #expect(throws: MediaServerError.self) {
            try await client.sendHeartbeat(sessionId: "valid-session-123", state: "playing")
        }

        // FairPlayKeyClient rejects malicious server sessionId & cleartext HTTP serverURL
        let fpClient = FairPlayKeyClient(
            serverURL: URL(string: "https://\(host)")!,
            authToken: "tok",
            urlSession: AuditStubURLProtocol.session()
        )
        await #expect(throws: FairPlayKeyClient.FairPlayKeyError.invalidSessionResponse) {
            _ = try await fpClient.startSession(userId: "alice", assetId: "asset-1")
        }

        let httpClient = FairPlayKeyClient(serverURL: URL(string: "http://\(host)")!, authToken: "tok")
        await #expect(throws: FairPlayKeyClient.FairPlayKeyError.insecureServerURL) {
            _ = try await httpClient.fetchCertificate()
        }
    }

    @Test("DRMConfiguration and InputValidator enforce strict URL, interval, ASCII region, and query encoding")
    func configAndValidationHardening() throws {
        // Reject zero/negative/non-finite intervals and hostless/HTTP URLs
        #expect {
            _ = try DRMConfiguration(
                serverURL: URL(string: "https://drm.example.com")!,
                fpsCertificateData: Data([1]),
                heartbeatInterval: 0
            )
        } throws: { error in
            if case DRMConfigurationError.invalidInterval = error { return true }
            return false
        }
        #expect {
            _ = try DRMConfiguration(
                serverURL: URL(string: "https://drm.example.com")!,
                fpsCertificateData: Data([1]),
                sessionTimeout: -5
            )
        } throws: { error in
            if case DRMConfigurationError.invalidInterval = error { return true }
            return false
        }
        #expect {
            _ = try DRMConfiguration(
                serverURL: URL(string: "https:///no-host")!,
                fpsCertificateData: Data([1])
            )
        } throws: { error in
            if case DRMConfigurationError.invalidServerURL = error { return true }
            return false
        }

        // Region code rejects non-ASCII uppercase letters
        #expect(throws: ValidationError.self) { try InputValidator.validateRegionCode("ÄÖ") }
        #expect(throws: ValidationError.self) { try InputValidator.validateRegionCode("us") }
        try InputValidator.validateRegionCode("US")

        // Policy attribute encodes query-injection delimiters
        let encoded = try InputValidator.validatePolicyAttribute("tier=pro&admin=true+1;x")
        #expect(!encoded.contains("&"))
        #expect(!encoded.contains("="))
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains(";"))

        // URL validation rejects cleartext remote HTTP and hostless URLs
        #expect(throws: ValidationError.self) { _ = try InputValidator.validateURL("http://remote.example.com/a") }
        #expect(throws: ValidationError.self) { _ = try InputValidator.validateURL("https:///path") }
        _ = try InputValidator.validateURL("https://kas.example.com")
        _ = try InputValidator.validateURL("http://localhost:8080")
    }

    @Test("TDFContentKeyDelegate enforces HTTPS and accepts JSON with explicit error: null")
    func contentKeyDelegateHTTPSAndNullError() async throws {
        let policy = Data(#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{}}"#.utf8)
        let manifest = try TDFContentKeyDelegateComponentTests.manifest(policy: policy, accesses: 1)

        // Cleartext HTTP serverURL is refused without sending any network request
        let http = FakeMediaService()
        let insecureDelegate = TDFContentKeyDelegate(
            manifest: manifest,
            authToken: "secret",
            serverURL: URL(string: "http://insecure.example.com")!,
            http: http
        )
        let req = FakeKeyRequest("skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b")
        await insecureDelegate.handle(req)
        #expect(req.failures == 1)
        #expect(await http.calls.isEmpty)

        // {"error": null, "wrappedKey": "..."} succeeds instead of being treated as refusal
        actor NullErrorHTTP: FairPlayHTTP {
            func data(for request: URLRequest) async throws -> (Data, URLResponse) {
                let url = request.url!
                let path = url.path
                let body: Data
                if path.hasSuffix("/certificate") {
                    body = Data(repeating: 0x30, count: 32)
                } else if path.hasSuffix("/session/start") {
                    body = Data(#"{"sessionId":"sess-ok-1"}"#.utf8)
                } else if path.hasSuffix("/key-request") {
                    let ckc = Data(repeating: 0x55, count: 32).base64EncodedString()
                    body = Data(#"{"error":null,"wrappedKey":"\#(ckc)"}"#.utf8)
                } else {
                    body = Data()
                }
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (body, resp)
            }
        }
        let delegate = TDFContentKeyDelegate(
            manifest: manifest,
            authToken: "tok",
            serverURL: URL(string: "https://platform.arkavo.net")!,
            http: NullErrorHTTP()
        )
        let okReq = FakeKeyRequest("skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b")
        await delegate.handle(okReq)
        #expect(okReq.failures == 0)
        #expect(okReq.ckcs == [Data(repeating: 0x55, count: 32)])
    }

    @Test("TDFProtectionCore supports RSA-3072 wrapping and refuses HTTP/redirects in fetchKASRSAPublicKey")
    func protectionCoreRSA3072AndHTTPS() async throws {
        let rsa3072 = try TestKASKeyPair(bits: 3072)
        let dek = try TDFProtectionCore.generateDEK()
        let wrapped = try TDFProtectionCore.wrapDEKWithRSA(dek: dek, publicKeyPEM: rsa3072.spkiPublicKeyPEM)
        let wrappedBytes = try #require(Data(base64Encoded: wrapped))
        #expect(wrappedBytes.count == 384, "RSA-3072 wrapped key should be 384 bytes")

        await #expect {
            _ = try await TDFProtectionCore.fetchKASRSAPublicKey(
                kasURL: URL(string: "http://kas.example.com")!,
                session: AuditStubURLProtocol.session()
            )
        } throws: { error in
            if case TDFProtectionCoreError.invalidKASURL = error { return true }
            return false
        }
    }

    @Test("FairPlayEnvelopeKey rejects mismatched kid and cleartext HTTP; FairPlayKeyEnvelope rejects control chars & non-canonical rootSignature")
    func envelopeSecurityValidations() async throws {
        let key = try TestKASKeyPair()
        let badKidBody = try JSONSerialization.data(withJSONObject: [
            "alg": "RSA-OAEP",
            "kid": "00000000000000000000000000000000",
            "publicKey": key.spkiPublicKeyPEM,
        ])
        #expect(throws: FairPlayEnvelopeKeyError.invalidResponse("kid does not match publicKey")) {
            _ = try FairPlayEnvelopeKey.parse(badKidBody, kasURL: URL(string: "https://platform.arkavo.net")!)
        }

        await #expect(throws: FairPlayEnvelopeKeyError.invalidResponse("KAS URL must use HTTPS")) {
            _ = try await FairPlayEnvelopeKey.fetch(
                kasURL: URL(string: "http://platform.arkavo.net")!,
                http: FakeMediaService()
            )
        }

        // Control characters in payload entry names are rejected
        #expect(!FairPlayKeyEnvelope.isPayloadEntryName("0.payload\0"))
        #expect(!FairPlayKeyEnvelope.isPayloadEntryName("0.payload\n"))
        #expect(!FairPlayKeyEnvelope.isPayloadEntryName("0.payload\r"))
        #expect(!FairPlayKeyEnvelope.isPayloadEntryName("0.payload\u{7F}"))

        // Non-canonical rootSignature.sig (unused padding bits set) is rejected
        let policy = Data(#"{"uuid":"6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d","body":{}}"#.utf8)
        let files = ["master.m3u8": Data("m".utf8), "video.m3u8": Data("v".utf8)]
        let pubKey = try TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
            .publicKey(fromPEM: key.spkiPublicKeyPEM)
        let pkg = try FairPlayKeyEnvelope.build(
            componentKeys: [.init(component: .video, key: Data(repeating: 1, count: 16))],
            iv: Data(repeating: 2, count: 16),
            assetID: "a1",
            policyJSON: policy,
            mediaFiles: files,
            kasURL: URL(string: "https://platform.arkavo.net")!,
            publicKey: pubKey
        )
        var obj = try #require(JSONSerialization.jsonObject(with: pkg.manifest) as? [String: Any])
        var enc = try #require(obj["encryptionInformation"] as? [String: Any])
        var integ = try #require(enc["integrityInformation"] as? [String: Any])
        var root = try #require(integ["rootSignature"] as? [String: String])
        // Non-canonical 32-byte base64: last char before '=' has unused lower 2 bits set ('B' instead of 'A')
        root["sig"] = String(repeating: "A", count: 42) + "B="
        integ["rootSignature"] = root
        enc["integrityInformation"] = integ
        obj["encryptionInformation"] = enc
        let nonCanonical = try JSONSerialization.data(withJSONObject: obj)
        #expect(throws: FairPlayKeyEnvelope.Error.invalidProfile) {
            try FairPlayKeyEnvelope.validateManifest(nonCanonical, payload: pkg.payload)
        }

        // Non-finite number in JSON is rejected by FairPlayComponents.componentIDs
        let nonFinite = Data(#"{"encryptionInformation":{"policy":"e30="},"extra":1e400}"#.utf8)
        #expect(throws: FairPlayComponents.Error.malformedComponents) {
            _ = try FairPlayComponents.componentIDs(ofManifestJSON: nonFinite)
        }
    }
}
