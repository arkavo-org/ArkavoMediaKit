import CryptoKit
import Foundation
import OpenTDFKit
import Security
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

// MARK: - HLS TDF Packager Policy Injection Tests

/// Covers the caller-supplied TDF policy API (`package(policyJSON:)`) and the
/// OpenTDF policy-binding wire format as the KAS verifies it. See Creator#4
/// (HLS tier gating).
///
/// KAS contract (opentdf/platform `service/kas/access/rewrap.go`
/// `verifyPolicyBinding`, with opentdf/platform#4081), and what OpenTDFKit >= 5.0
/// `TDFCrypto.policyBinding(policy:symmetricKey:)` emits when handed the RAW
/// policy JSON — the OpenTDF spec form:
///
///   manifest.policy              = base64(policyJSON)
///   digest                       = HMAC-SHA256(key: DEK, msg: utf8(manifest.policy))
///   manifest.policyBinding.hash  = base64(digest)   // 44 chars, 32 raw bytes
///
/// OpenTDFKit 4 emitted the legacy base64(utf8(hex(digest))) instead.
///
/// The packager must therefore pass the raw JSON to `policyBinding`; passing
/// the already-base64'd string double-encodes and fails KAS rewrap.
@Suite("HLSTDFPackager policy injection")
struct HLSTDFPackagerPolicyTests {
    /// Builds an `HLSConversionResult` backed by a real on-disk segment file of
    /// arbitrary bytes. `package()` reads each segment via `Data(contentsOf:)`
    /// and encrypts with AES-CBC, neither of which require actual video data, so
    /// this fixture lets the whole pipeline run headless.
    private func makeFixture(
        segmentBytes: [Data]
    ) throws -> (result: HLSConversionResult, cleanup: () -> Void) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hls-policy-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        var segmentURLs: [URL] = []
        var durations: [Double] = []
        for (i, bytes) in segmentBytes.enumerated() {
            let url = dir.appendingPathComponent("segment_\(i).mov")
            try bytes.write(to: url)
            segmentURLs.append(url)
            durations.append(6.0)
        }

        // Minimal placeholder playlist; package() rewrites the playlist anyway.
        let playlistURL = dir.appendingPathComponent("playlist.m3u8")
        try "#EXTM3U\n".write(to: playlistURL, atomically: true, encoding: .utf8)

        let result = HLSConversionResult(
            playlistURL: playlistURL,
            segmentURLs: segmentURLs,
            segmentDurations: durations,
            totalDuration: Double(segmentBytes.count) * 6.0
        )
        let cleanup: () -> Void = { try? FileManager.default.removeItem(at: dir) }
        return (result, cleanup)
    }

    /// Reads `manifest.json` out of a packaged TDF (ZIP) archive and returns it
    /// as a JSON object.
    private func readManifest(fromTDF tdf: Data) throws -> [String: Any] {
        let archive = try Archive(data: tdf, accessMode: .read)
        let manifestEntry = try #require(archive["manifest.json"])
        var manifestData = Data()
        _ = try archive.extract(manifestEntry) { data in
            manifestData.append(data)
        }
        let object = try JSONSerialization.jsonObject(with: manifestData)
        return try #require(object as? [String: Any])
    }

    private func encryptionInfo(_ manifest: [String: Any]) throws -> [String: Any] {
        try #require(manifest["encryptionInformation"] as? [String: Any])
    }

    /// Decodes a manifest `policyBinding.hash` in the spec form:
    /// base64 -> 32 raw digest bytes (44 base64 characters).
    private func decodeBindingHash(_ hash: String) throws -> Data {
        #expect(hash.count == 44, "expected 44 base64 chars, got \(hash.count): \(hash)")
        let digest = try #require(Data(base64Encoded: hash))
        #expect(digest.count == 32, "expected a 32-byte digest, got \(digest.count) bytes")
        return digest
    }

    /// Mirrors KAS `verifyPolicyBinding`: unwrap the DEK from `wrappedKey` with
    /// the KAS private key, HMAC the base64 policy body from the manifest, and
    /// compare with the decoded `policyBinding.hash`. Returns the DEK and the
    /// decoded policy JSON so callers can make further assertions.
    @discardableResult
    private func kasVerifyBinding(
        _ encryptionInfo: [String: Any],
        kasKeyPair: TestKASKeyPair
    ) throws -> (dek: SymmetricKey, policyJSON: Data) {
        let keyAccess = try #require(encryptionInfo["keyAccess"] as? [[String: Any]])
        let first = try #require(keyAccess.first)
        let wrappedKey = try #require(first["wrappedKey"] as? String)
        let dek = try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: kasKeyPair.privateKeyPEM,
            wrappedKey: wrappedKey
        )

        let policyB64 = try #require(encryptionInfo["policy"] as? String)
        let policyJSON = try #require(Data(base64Encoded: policyB64))

        let binding = try #require(first["policyBinding"] as? [String: Any])
        #expect(binding["alg"] as? String == "HS256")
        let actual = try decodeBindingHash(try #require(binding["hash"] as? String))

        // KAS HMACs the base64 policy STRING (req.Policy.Body) with the DEK.
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: Data(policyB64.utf8), using: dek))
        #expect(actual == expected, "policyBinding.hash does not verify against the DEK")

        // Regression guard: the pre-4.0.1 packager double-encoded, HMACing
        // base64(base64(json)). That must NOT be what the manifest carries.
        let doubleEncoded = Data(HMAC<SHA256>.authenticationCode(
            for: Data(Data(policyB64.utf8).base64EncodedString().utf8), using: dek))
        #expect(actual != doubleEncoded, "binding was computed over a double-base64'd policy")

        return (dek, policyJSON)
    }

    // MARK: - (b) OpenTDFKit contract: raw JSON in, base64(HMAC(base64)) out

    @Test("TDFCrypto.policyBinding over raw policy JSON is the spec binding")
    func policyBindingKASWireFormat() throws {
        // Pins the OpenTDFKit >= 5.0 contract the packager relies on, with a
        // known DEK so the value is reproducible.
        let dek = Data(repeating: 0xAB, count: 16)
        let key = SymmetricKey(data: dek)
        let policyJSON = Data(#"{"uuid":"abc-123","body":{"dataAttributes":["https://example.com/attr/tier/value/premium"]}}"#.utf8)
        let policyBase64 = policyJSON.base64EncodedString()

        let binding = TDFCrypto.policyBinding(policy: policyJSON, symmetricKey: key)
        #expect(binding.alg == "HS256")

        // hash base64-decodes to the raw 32-byte digest.
        let digest = try decodeBindingHash(binding.hash)
        #expect(digest.count == 32)

        // HMAC input is the base64-policy STRING bytes — what the KAS re-HMACs
        // (rewrap.go verifyPolicyBinding over req.Policy.Body).
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8), using: key))
        #expect(digest == expected)

        #expect(binding.hash == expected.base64EncodedString())

        // Not the legacy OpenTDFKit 4 form, base64(utf8(hex(digest))).
        let legacyHex = expected.map { String(format: "%02x", $0) }.joined()
        #expect(binding.hash != Data(legacyHex.utf8).base64EncodedString())
    }

    // MARK: - (a) nil policyJSON: generated-UUID placeholder policy

    /// Reads the manifest's `meta.hls.assetId`.
    private func hlsAssetID(_ manifest: [String: Any]) throws -> String {
        let meta = try #require(manifest["meta"] as? [String: Any])
        let hls = try #require(meta["hls"] as? [String: Any])
        return try #require(hls["assetId"] as? String)
    }

    /// Asserts the placeholder policy shape the opentdf-platform KAS accepts:
    /// `uuid` must parse as a UUID (the KAS unmarshals it into `uuid.UUID`,
    /// service/kas/access/policy.go) and `body` is empty. Returns the uuid.
    @discardableResult
    private func expectPlaceholderPolicy(_ policyJSON: Data, assetID: String) throws -> String {
        let policy = try #require(try JSONSerialization.jsonObject(with: policyJSON) as? [String: Any])
        #expect(policy.count == 2, "placeholder policy should carry only uuid and body: \(policy)")
        let uuid = try #require(policy["uuid"] as? String)
        #expect(UUID(uuidString: uuid) != nil, "policy uuid is not a UUID: \(uuid)")
        #expect(uuid == uuid.lowercased(), "policy uuid should be lowercase like the Go side emits: \(uuid)")
        #expect(uuid != assetID, "policy uuid must not be the asset id")
        let body = try #require(policy["body"] as? [String: Any])
        #expect(body.isEmpty, "placeholder body should be empty: \(body)")
        return uuid
    }

    @Test("nil policyJSON with a non-UUID asset id embeds a generated-UUID placeholder policy")
    func nilPolicyNonUUIDAssetIDGeneratesUUIDPolicy() async throws {
        // Live evidence (platform.arkavo.net): the KAS parses the policy into
        // `Policy{UUID uuid.UUID}`; a non-UUID `uuid` fails json.Unmarshal and
        // every key-access object is rejected with "bad request" before any
        // decryption. The asset id therefore must never be used as the uuid.
        let assetID = "diag-hls-not-a-uuid"
        let (fixture, cleanup) = try makeFixture(segmentBytes: [Data(repeating: 0x33, count: 1024)])
        defer { cleanup() }

        let kasKeyPair = try TestKASKeyPair()
        let packager = HLSTDFPackager(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: kasKeyPair.publicKeyPEM
        )

        let tdf = try await packager.package(hlsResult: fixture, assetID: assetID)
        let manifest = try readManifest(fromTDF: tdf)
        let encInfo = try encryptionInfo(manifest)

        let policyB64 = try #require(encInfo["policy"] as? String)
        let policyData = try #require(Data(base64Encoded: policyB64))
        try expectPlaceholderPolicy(policyData, assetID: assetID)

        // The asset id still travels in the HLS metadata, not the policy.
        #expect(try hlsAssetID(manifest) == assetID)

        // Binding verifies against the real DEK over the generated policy.
        let verified = try kasVerifyBinding(encInfo, kasKeyPair: kasKeyPair)
        #expect(verified.policyJSON == policyData)
    }

    @Test("nil policyJSON embeds placeholder policy with a KAS-verifiable binding")
    func nilPolicyPlaceholderManifest() async throws {
        let assetID = "asset-placeholder-001"
        let (fixture, cleanup) = try makeFixture(segmentBytes: [Data(repeating: 0x11, count: 1024)])
        defer { cleanup() }

        let kasKeyPair = try TestKASKeyPair()
        let packager = HLSTDFPackager(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: kasKeyPair.publicKeyPEM
        )

        let tdf = try await packager.package(hlsResult: fixture, assetID: assetID)
        let manifest = try readManifest(fromTDF: tdf)
        let encInfo = try encryptionInfo(manifest)

        // policy field decodes to the placeholder {"uuid":"<generated UUID>","body":{}}
        let policyB64 = try #require(encInfo["policy"] as? String)
        let policyData = try #require(Data(base64Encoded: policyB64))
        try expectPlaceholderPolicy(policyData, assetID: assetID)
        #expect(try hlsAssetID(manifest) == assetID)

        // Binding verifies against the real DEK the way the KAS checks it.
        let verified = try kasVerifyBinding(encInfo, kasKeyPair: kasKeyPair)
        #expect(verified.policyJSON == policyData)
    }

    // MARK: - (c) policyJSON through package(): real policy + KAS binding

    @Test("policyJSON embeds caller policy and KAS-contract binding")
    func callerPolicyEmbeddedWithKASBinding() async throws {
        let assetID = "asset-policy-002"
        let policyJSON = Data(#"{"uuid":"asset-policy-002","body":{"dataAttributes":["https://example.com/attr/tier/value/premium"],"dissem":[]}}"#.utf8)
        let (fixture, cleanup) = try makeFixture(segmentBytes: [Data(repeating: 0x22, count: 2048)])
        defer { cleanup() }

        let kasKeyPair = try TestKASKeyPair()
        let packager = HLSTDFPackager(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: kasKeyPair.publicKeyPEM
        )

        let tdf = try await packager.package(
            hlsResult: fixture,
            assetID: assetID,
            policyJSON: policyJSON
        )
        let manifest = try readManifest(fromTDF: tdf)
        let encInfo = try encryptionInfo(manifest)

        // policy == base64(policyJSON) verbatim
        let policyB64 = try #require(encInfo["policy"] as? String)
        #expect(policyB64 == policyJSON.base64EncodedString())

        // Binding verifies against the real DEK the way the KAS checks it, and
        // the policy that binding covers is the caller's JSON verbatim.
        let verified = try kasVerifyBinding(encInfo, kasKeyPair: kasKeyPair)
        #expect(verified.policyJSON == policyJSON)
    }
}
