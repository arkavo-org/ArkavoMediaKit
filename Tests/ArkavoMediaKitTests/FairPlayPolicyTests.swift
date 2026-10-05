import CryptoKit
import Foundation
import Testing
@testable import ArkavoMediaKit

/// The FairPlay license contract (arkavo-rs PR #75, `tdf_policy.rs::check_manifest`):
/// binding = base64(HMAC-SHA256(key: DEK, msg: utf8(base64 policy))), raw digest.
@Suite("FairPlayPolicy")
struct FairPlayPolicyTests {
    // Golden values from arkavo-rs src/modules/license/fixtures/gen_fixtures.sh (openssl).
    static let goldenDEK = Data((0 ..< 32).map { UInt8($0) })
    static let goldenPolicy = #"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold"}],"dissem":[]}}"#
    static let goldenPolicyBase64 = "eyJ1dWlkIjoiM2YxYzllMmEtN2I0ZC00ZThmLTlhMjEtNWM2ZDdlOGY5YTBiIiwiYm9keSI6eyJkYXRhQXR0cmlidXRlcyI6W3siYXR0cmlidXRlIjoiaHR0cHM6Ly9wYXRyZW9uLmFya2F2by5jb20vYXR0ci9jYW1wYWlnbi10aWVyL3ZhbHVlLzExMTExMTExX2dvbGQifV0sImRpc3NlbSI6W119fQ=="
    static let goldenBinding = "Ua5XgGqgNmxdle4TockmCZbQAIGzR5IY3mffTDh+47Y="

    @Test("binding matches the openssl-produced arks fixture")
    func bindingMatchesGolden() {
        #expect(Data(Self.goldenPolicy.utf8).base64EncodedString() == Self.goldenPolicyBase64)
        #expect(FairPlayPolicy.binding(policyBase64: Self.goldenPolicyBase64, dek: Self.goldenDEK) == Self.goldenBinding)
    }

    @Test("binding is the raw digest, not base64(hex)")
    func bindingIsRawDigest() throws {
        let binding = FairPlayPolicy.binding(policyBase64: Self.goldenPolicyBase64, dek: Self.goldenDEK)
        #expect(try #require(Data(base64Encoded: binding)).count == 32)
    }

    @Test("placeholder policy is {uuid, body:{}} with a fresh lower-case UUID")
    func placeholder() throws {
        let a = FairPlayPolicy.placeholderJSON()
        let b = FairPlayPolicy.placeholderJSON()
        let uuid = try FairPlayPolicy.uuid(ofPolicyJSON: a)
        #expect(uuid == uuid.lowercased())
        #expect(UUID(uuidString: uuid) != nil)
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: b) != uuid)
        let object = try #require(JSONSerialization.jsonObject(with: a) as? [String: Any])
        #expect((object["body"] as? [String: Any])?.isEmpty == true)
    }

    @Test("uuid(ofPolicyJSON:) returns the uuid verbatim — arks compares it as written")
    func policyUUIDVerbatim() throws {
        let json = Data(#"{"uuid":"3F1C9E2A-7B4D-4E8F-9A21-5C6D7E8F9A0B","body":{}}"#.utf8)
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: json) == "3F1C9E2A-7B4D-4E8F-9A21-5C6D7E8F9A0B")
    }

    @Test("uuid(ofPolicyJSON:) rejects missing, non-UUID and non-object policies")
    func policyUUIDRejectsMissingOrInvalid() {
        #expect(throws: FairPlayPolicy.Error.missingUUID) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"body":{}}"#.utf8))
        }
        #expect(throws: FairPlayPolicy.Error.invalidUUID("asset-123")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"asset-123","body":{}}"#.utf8))
        }
        #expect(throws: FairPlayPolicy.Error.notJSONObject) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data("[1,2]".utf8))
        }
    }

    @Test("publicKey(fromPEM:) accepts SPKI (what a KAS serves) and PKCS#1")
    func publicKeyAcceptsSPKIAndPKCS1() throws {
        let kas = try TestKASKeyPair()
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
        _ = try builder.publicKey(fromPEM: kas.publicKeyPEM)
        _ = try builder.publicKey(fromPEM: kas.spkiPublicKeyPEM)
    }

    @Test("manifest carries the policy, one wrapped key and a binding arks accepts")
    func manifestPassesArksCheck() throws {
        let kas = try TestKASKeyPair()
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
        let dek = Data((0 ..< 16).map { _ in UInt8.random(in: 0 ... 255) })
        let iv = Data(repeating: 7, count: 16)
        let manifest = try builder.buildManifest(
            contentKey: dek, iv: iv,
            policyJSON: Data(Self.goldenPolicy.utf8),
            publicKey: builder.publicKey(fromPEM: kas.spkiPublicKeyPEM)
        )

        let info = manifest.encryptionInformation
        #expect(info.policy == Self.goldenPolicyBase64)
        #expect(info.keyAccess.count == 1)
        let kao = try #require(info.keyAccess.first)
        #expect(kao.type == "wrapped")
        #expect(kao.url == "https://platform.arkavo.net")
        // Independently recompute what arks checks: unwrap, then HMAC the base64 policy string.
        let unwrapped = try kas.unwrap(try #require(Data(base64Encoded: kao.wrappedKey)))
        #expect(unwrapped == dek)
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(try #require(info.policy).utf8), using: SymmetricKey(data: unwrapped))
        #expect(kao.policyBinding?.hash == Data(mac).base64EncodedString())
        #expect(kao.policyBinding?.alg == "HS256")
    }
}
