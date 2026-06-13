import CryptoKit
import Foundation
import OpenTDFKit
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

// MARK: - HLS TDF Packager Policy Injection Tests

/// Covers the caller-supplied TDF policy API (`package(policyJSON:)`) and the
/// spec-form policy binding (Base64(HMAC) over the base64-policy, via the
/// OpenTDF SDK's `TDFCrypto.policyBinding`). See Creator#4 (HLS tier gating).
@Suite("HLSTDFPackager policy injection")
struct HLSTDFPackagerPolicyTests {
    // A throwaway RSA public key (PEM) is required to construct the packager.
    // 2048-bit public key generated for tests only; never used to protect real
    // content. The packager only needs it to RSA-wrap the DEK.
    static let testKASPublicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOmru7ayaBDgBvupLFyr
    OcikSmnvWT5fNm2MDjhpjl1Lykt94vFrt8sJBocHOFz6YtD7hGno1ABqm4+ccNhH
    kE9ryHrmqzw52E+56xxdIO6zIzPBYX482FODCD3bXPlsRro/QRXwBiYEcBtMDNaJ
    FPUlg2lpu0iFIF7nIrZHoa1fjyDMUUjLgHhQcdssjkpG1AlB/mv74gVvyduMGRAu
    K25S3UealDfM5zbVzK6O65O1psrN9DaOiyEaz+DGl3x26Otjqfy+vIBZxXO7trSX
    aS/5l8642F9+iusIZhTtL7sI5OQKxyo+EiTezYkOJ7F8tpEBDX07Qfxt2o9Jmmgo
    IwIDAQAB
    -----END PUBLIC KEY-----
    """

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

    private func policyBinding(_ encryptionInfo: [String: Any]) throws -> [String: Any] {
        let keyAccess = try #require(encryptionInfo["keyAccess"] as? [[String: Any]])
        let first = try #require(keyAccess.first)
        return try #require(first["policyBinding"] as? [String: Any])
    }

    // MARK: - (b) Binding convention: spec Base64(HMAC) over the base64-policy

    @Test("policy binding is the OpenTDF spec form: Base64(HMAC) over the base64-policy")
    func policyBindingSpecConvention() throws {
        // This is exactly what buildMasterManifest computes for the binding,
        // with a known DEK so the value is reproducible (package() generates the
        // DEK internally, so the through-package tests can only check shape).
        let dek = Data(repeating: 0xAB, count: 16)
        let key = SymmetricKey(data: dek)
        let policyJSON = Data(#"{"uuid":"abc-123","body":{"dataAttributes":["https://example.com/attr/tier/value/premium"]}}"#.utf8)
        let policyBase64 = policyJSON.base64EncodedString()

        let binding = TDFCrypto.policyBinding(policy: Data(policyBase64.utf8), symmetricKey: key)
        #expect(binding.alg == "HS256")

        // Spec form (opentdf >= 4.3.0; opentdf/platform#3597): Base64(rawDigest),
        // i.e. base64-decodes straight to the 32-byte HMAC — no hex layer.
        let hashData = try #require(Data(base64Encoded: binding.hash))
        #expect(hashData.count == 32)

        // HMAC input is the base64-policy STRING bytes — what the KAS re-HMACs
        // (rewrap.go VerifyBinding over req.Policy.Body).
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8), using: key))
        #expect(hashData == expected)
        #expect(binding.hash == expected.base64EncodedString())
    }

    // MARK: - (a) nil policyJSON: legacy structural invariants preserved

    @Test("nil policyJSON embeds placeholder policy with a spec-form binding")
    func nilPolicyPreservesLegacyManifest() async throws {
        let assetID = "asset-legacy-001"
        let (fixture, cleanup) = try makeFixture(segmentBytes: [Data(repeating: 0x11, count: 1024)])
        defer { cleanup() }

        let packager = HLSTDFPackager(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: Self.testKASPublicKeyPEM
        )

        let tdf = try await packager.package(hlsResult: fixture, assetID: assetID)
        let manifest = try readManifest(fromTDF: tdf)
        let encInfo = try encryptionInfo(manifest)

        // policy field decodes to the placeholder {"uuid":"<assetID>","body":{}}
        let policyB64 = try #require(encInfo["policy"] as? String)
        let policyData = try #require(Data(base64Encoded: policyB64))
        let policyString = try #require(String(data: policyData, encoding: .utf8))
        #expect(policyString == "{\"uuid\":\"\(assetID)\",\"body\":{}}")

        // Spec binding: alg HS256, base64-decodes to the 32-byte raw digest.
        // The DEK is generated internally and unobservable, so the exact hash
        // isn't reproduced here; value correctness is covered by (b).
        let binding = try policyBinding(encInfo)
        #expect(binding["alg"] as? String == "HS256")
        let hash = try #require(binding["hash"] as? String)
        let hashData = try #require(Data(base64Encoded: hash))
        #expect(hashData.count == 32)
    }

    // MARK: - (c) policyJSON through package(): real policy + KAS binding

    @Test("policyJSON embeds caller policy and KAS-contract binding")
    func callerPolicyEmbeddedWithKASBinding() async throws {
        let assetID = "asset-policy-002"
        let policyJSON = Data(#"{"uuid":"asset-policy-002","body":{"dataAttributes":["https://example.com/attr/tier/value/premium"],"dissem":[]}}"#.utf8)
        let (fixture, cleanup) = try makeFixture(segmentBytes: [Data(repeating: 0x22, count: 2048)])
        defer { cleanup() }

        let packager = HLSTDFPackager(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: Self.testKASPublicKeyPEM
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

        // Spec binding: alg HS256, hash base64-decodes to the 32-byte raw digest.
        let binding = try policyBinding(encInfo)
        #expect(binding["alg"] as? String == "HS256")
        let hash = try #require(binding["hash"] as? String)
        let hashData = try #require(Data(base64Encoded: hash))
        #expect(hashData.count == 32)
    }
}
