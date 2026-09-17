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
/// `verifyPolicyBinding`), and what OpenTDFKit >= 4.0.1
/// `TDFCrypto.policyBinding(policy:symmetricKey:)` emits when handed the RAW
/// policy JSON:
///
///   manifest.policy              = base64(policyJSON)
///   digest                       = HMAC-SHA256(key: DEK, msg: utf8(manifest.policy))
///   manifest.policyBinding.hash  = base64(utf8(hex(digest)))   // 64 hex chars
///
/// The packager must therefore pass the raw JSON to `policyBinding`; passing
/// the already-base64'd string double-encodes and fails KAS rewrap.
@Suite("HLSTDFPackager policy injection")
struct HLSTDFPackagerPolicyTests {
    /// A per-test 2048-bit RSA keypair standing in for the KAS key. The
    /// packager RSA-wraps the DEK with `publicKeyPEM` (OAEP-SHA1, as the KAS
    /// does); the tests unwrap it with `privateKeyPEM` so the manifest binding
    /// can be verified against the real DEK exactly the way KAS rewrap does.
    ///
    /// Generated at runtime with `SecKeyCreateRandomKey` so no key material
    /// lives in source. `SecKeyCopyExternalRepresentation` yields PKCS#1 DER for
    /// RSA keys, which is what OpenTDFKit's `loadRSAPublicKey` /
    /// `loadRSAPrivateKey` hand to `SecKeyCreateWithData` after stripping the
    /// `PUBLIC KEY` / `RSA PRIVATE KEY` PEM armor.
    struct TestKASKeyPair {
        let publicKeyPEM: String
        let privateKeyPEM: String

        init() throws {
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 2048,
                kSecAttrIsPermanent as String: false,
            ]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
            privateKeyPEM = try Self.pem(privateKey, label: "RSA PRIVATE KEY")
            publicKeyPEM = try Self.pem(publicKey, label: "PUBLIC KEY")
        }

        private static func pem(_ key: SecKey, label: String) throws -> String {
            var error: Unmanaged<CFError>?
            guard let der = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
                throw error!.takeRetainedValue() as Error
            }
            let body = der.base64EncodedString(options: [.lineLength64Characters])
            return "-----BEGIN \(label)-----\n\(body)\n-----END \(label)-----"
        }
    }

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

    /// Decodes a manifest `policyBinding.hash` the way rewrap.go does:
    /// base64 -> 64-char hex string -> 32 raw digest bytes.
    private func decodeBindingHash(_ hash: String) throws -> Data {
        let hexData = try #require(Data(base64Encoded: hash))
        let hex = try #require(String(data: hexData, encoding: .utf8))
        #expect(hex.count == 64, "expected 64 hex chars, got \(hex.count): \(hex)")
        #expect(hex.allSatisfy { $0.isHexDigit })
        var digest = Data(capacity: 32)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            digest.append(try #require(UInt8(hex[idx..<next], radix: 16)))
            idx = next
        }
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

    // MARK: - (b) OpenTDFKit contract: raw JSON in, base64(hex(HMAC(base64))) out

    @Test("TDFCrypto.policyBinding over raw policy JSON matches the KAS wire format")
    func policyBindingKASWireFormat() throws {
        // Pins the OpenTDFKit >= 4.0.1 contract the packager relies on, with a
        // known DEK so the value is reproducible.
        let dek = Data(repeating: 0xAB, count: 16)
        let key = SymmetricKey(data: dek)
        let policyJSON = Data(#"{"uuid":"abc-123","body":{"dataAttributes":["https://example.com/attr/tier/value/premium"]}}"#.utf8)
        let policyBase64 = policyJSON.base64EncodedString()

        let binding = TDFCrypto.policyBinding(policy: policyJSON, symmetricKey: key)
        #expect(binding.alg == "HS256")

        // hash base64-decodes to 64 hex chars, which hex-decode to the digest.
        let digest = try decodeBindingHash(binding.hash)
        #expect(digest.count == 32)

        // HMAC input is the base64-policy STRING bytes — what the KAS re-HMACs
        // (rewrap.go verifyPolicyBinding over req.Policy.Body).
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8), using: key))
        #expect(digest == expected)

        let expectedHex = expected.map { String(format: "%02x", $0) }.joined()
        #expect(binding.hash == Data(expectedHex.utf8).base64EncodedString())
    }

    // MARK: - (a) nil policyJSON: legacy structural invariants preserved

    @Test("nil policyJSON embeds placeholder policy with a KAS-verifiable binding")
    func nilPolicyPreservesLegacyManifest() async throws {
        let assetID = "asset-legacy-001"
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

        // policy field decodes to the placeholder {"uuid":"<assetID>","body":{}}
        let policyB64 = try #require(encInfo["policy"] as? String)
        let policyData = try #require(Data(base64Encoded: policyB64))
        let policyString = try #require(String(data: policyData, encoding: .utf8))
        #expect(policyString == "{\"uuid\":\"\(assetID)\",\"body\":{}}")

        // Binding verifies against the real DEK the way the KAS checks it.
        let verified = try kasVerifyBinding(encInfo, kasKeyPair: kasKeyPair)
        #expect(verified.policyJSON == Data("{\"uuid\":\"\(assetID)\",\"body\":{}}".utf8))
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
