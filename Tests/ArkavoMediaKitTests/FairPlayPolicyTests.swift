import CryptoKit
import Foundation
import OpenTDFKit
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

    /// The golden binding is the raw 32-byte digest (the spec form), not OpenTDFKit 4's base64(hex).
    @Test("binding matches the openssl-produced arks fixture")
    func bindingMatchesGolden() {
        #expect(Data(Self.goldenPolicy.utf8).base64EncodedString() == Self.goldenPolicyBase64)
        #expect(FairPlayPolicy.binding(policyBase64: Self.goldenPolicyBase64, dek: Self.goldenDEK) == Self.goldenBinding)
    }

    /// OpenTDFKit 5 writes the same spec binding, so the HLS and fMP4 paths agree.
    @Test("OpenTDFKit's policy binding matches the arks fixture")
    func openTDFKitBindingMatchesGolden() {
        let binding = TDFCrypto.policyBinding(policy: Data(Self.goldenPolicy.utf8),
                                              symmetricKey: SymmetricKey(data: Self.goldenDEK))
        #expect(binding.alg == "HS256")
        #expect(binding.hash == Self.goldenBinding)
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

    @Test("uuid(ofPolicyJSON:) returns a lower-case uuid verbatim and refuses upper case")
    func policyUUIDLowerCaseOnly() throws {
        let lower = Data(#"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{}}"#.utf8)
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: lower) == "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b")
        // arks compares the key URI with the uuid verbatim; package profile v1 wants lower case.
        #expect(throws: FairPlayPolicy.Error.invalidUUID("3F1C9E2A-7B4D-4E8F-9A21-5C6D7E8F9A0B")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"3F1C9E2A-7B4D-4E8F-9A21-5C6D7E8F9A0B","body":{}}"#.utf8))
        }
    }

    /// arks parses the policy with serde_json: BOM-less UTF-8 only, and the
    /// last of duplicate keys wins. Anything it would read differently from
    /// JSONSerialization is refused before it is bound into an archive.
    @Test("uuid(ofPolicyJSON:) refuses a BOM and UTF-16")
    func policyUUIDRequiresPlainUTF8() throws {
        let policy = #"{"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b","body":{}}"#
        #expect(throws: FairPlayPolicy.Error.notJSONObject) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data([0xEF, 0xBB, 0xBF]) + Data(policy.utf8))
        }
        for encoding in [String.Encoding.utf16, .utf16LittleEndian, .utf16BigEndian, .utf32] {
            let data = try #require(policy.data(using: encoding))
            #expect(throws: FairPlayPolicy.Error.notJSONObject, "\(encoding)") {
                try FairPlayPolicy.uuid(ofPolicyJSON: data)
            }
        }
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: Data((" \n" + policy).utf8)) == "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b")
    }

    /// serde_json refuses these; JSONSerialization reads them.
    @Test("uuid(ofPolicyJSON:) refuses trailing commas, non-finite numbers and deep nesting")
    func policyUUIDRefusesWhatSerdeRefuses() throws {
        let a = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"
        #expect(throws: FairPlayPolicy.Error.unsupportedJSON("trailing comma")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","body":{"dissem":[]},}"#.utf8))
        }
        #expect(throws: FairPlayPolicy.Error.unsupportedJSON("trailing comma")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","body":{"dissem":["x" , ]}}"#.utf8))
        }
        #expect(throws: FairPlayPolicy.Error.unsupportedJSON("non-finite number")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","body":{},"x":-1e400}"#.utf8))
        }
        let deep = String(repeating: "[", count: 130) + String(repeating: "]", count: 130)
        #expect(throws: FairPlayPolicy.Error.unsupportedJSON("nested deeper than 64")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","body":{},"x":\#(deep)}"#.utf8))
        }
        // Commas inside strings, and moderate nesting, are fine.
        let shallow = String(repeating: "[", count: 20) + String(repeating: "]", count: 20)
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","body":{"dissem":["a,]"]},"x":\#(shallow)}"#.utf8)) == a)
    }

    /// Swift's String compares by canonical equivalence; serde keeps "é" (NFC)
    /// and "é" (NFD) as two keys, and so must this.
    @Test("uuid(ofPolicyJSON:) treats canonically equivalent but distinct keys as distinct")
    func policyUUIDKeysCompareByCodeUnits() throws {
        let a = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","é":1,"é":2,"body":{}}"#.utf8)) == a)
    }

    @Test("uuid(ofPolicyJSON:) refuses duplicate keys at any depth, however escaped")
    func policyUUIDRefusesDuplicateKeys() throws {
        let a = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b", b = "6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
        #expect(throws: FairPlayPolicy.Error.duplicateKey("uuid")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","body":{},"uuid":"\#(b)"}"#.utf8))
        }
        #expect(throws: FairPlayPolicy.Error.duplicateKey("uuid")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","uuid":"\#(b)","body":{}}"#.utf8))
        }
        #expect(throws: FairPlayPolicy.Error.duplicateKey("dissem")) {
            try FairPlayPolicy.uuid(ofPolicyJSON: Data(#"{"uuid":"\#(a)","body":{"dissem":[],"dissem":["x"]}}"#.utf8))
        }
        // The same key in sibling objects, and key-like strings in values, are fine.
        let siblings = #"{"uuid":"\#(a)","body":{"dataAttributes":[{"attribute":"uuid"},{"attribute":"b\",\"uuid"}],"dissem":[]}}"#
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: Data(siblings.utf8)) == a)
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

    @Test("publicKey(fromPEM:) refuses an RSA key under 2048 bits, as the other loaders do")
    func publicKeyRefusesWeakKey() throws {
        let weak = try TestKASKeyPair(bits: 1024)
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
        for pem in [weak.publicKeyPEM, weak.spkiPublicKeyPEM] {
            let error = #expect(throws: TDFManifestBuilder.TDFError.self) {
                _ = try builder.publicKey(fromPEM: pem)
            }
            guard case .weakPublicKey(bits: 1024) = error else {
                Issue.record("expected weakPublicKey(bits: 1024), got \(String(describing: error))")
                continue
            }
        }
    }

    /// RFC 7468 lets text surround the block and whitespace sit in the body;
    /// `openssl pkey -pubin -text` output is one example.
    @Test("publicKey(fromPEM:) reads PEM inside other text, indented, with trailing spaces")
    func publicKeyToleratesPEMLayout() throws {
        let kas = try TestKASKeyPair()
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
        for pem in [kas.publicKeyPEM, kas.spkiPublicKeyPEM] {
            let lines = pem.components(separatedBy: .newlines).filter { !$0.isEmpty }
            let laidOut = "Public-Key: (2048 bit)\nModulus:\n    00:c3:5e\n"
                + lines.map { "    \($0)  " }.joined(separator: "\n")
                + "\nExponent: 65537 (0x10001)\n"
            _ = try builder.publicKey(fromPEM: laidOut)
        }
    }

    /// main accepted a PEM missing its END line; keep accepting it.
    @Test("publicKey(fromPEM:) reads a PEM whose END line is missing")
    func publicKeyWithoutEndLine() throws {
        let kas = try TestKASKeyPair()
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
        for pem in [kas.publicKeyPEM, kas.spkiPublicKeyPEM] {
            let truncated = String(pem[..<pem.range(of: "-----END ")!.lowerBound])
            _ = try builder.publicKey(fromPEM: truncated)
        }
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
        let unwrapped = try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: kas.privateKeyPEM, wrappedKey: kao.wrappedKey)
        #expect(TDFCrypto.data(from: unwrapped) == dek)
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(try #require(info.policy).utf8), using: unwrapped)
        #expect(kao.policyBinding?.hash == Data(mac).base64EncodedString())
        #expect(kao.policyBinding?.alg == "HS256")
    }
}
