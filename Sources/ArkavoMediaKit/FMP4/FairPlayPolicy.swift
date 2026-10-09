import CryptoKit
import Foundation

/// TDF policy helpers for FairPlay (fMP4/CBCS) archives.
///
/// The arks license service (arkavo-rs PR #75, `tdf_policy.rs::check_manifest`)
/// verifies `policyBinding.hash == base64(HMAC-SHA256(key: DEK, msg:
/// utf8(encryptionInformation.policy)))` — the OpenTDF spec form with the raw
/// digest. OpenTDFKit 5's `TDFCrypto.policyBinding` emits the same form
/// (OpenTDFKit 4 emitted `base64(hex(...))`, which arks refuses); the FairPlay
/// path still computes it here, pinned to the arks fixture.
///
/// The policy `uuid` is the FairPlay content-key id: the playlist key URI is
/// `skd://<uuid>` and the SPC content identifier is the uuid.
public enum FairPlayPolicy {
    public enum Error: Swift.Error, Equatable {
        case notJSONObject
        case missingUUID
        case invalidUUID(String)
        case duplicateKey(String)
        case unsupportedJSON(String)
    }

    /// Placeholder policy for public content, `{"uuid":"<lowercase uuid>","body":{}}`.
    /// arks (after PR #75) refuses a policy with no data attributes, so content
    /// protected with this plays only against the pre-#75 license service.
    public static func placeholderJSON() -> Data {
        Data("{\"uuid\":\"\(UUID().uuidString.lowercased())\",\"body\":{}}".utf8)
    }

    /// The policy's `uuid` exactly as written (arks compares the SPC asset id
    /// with it verbatim). Throws unless it is a lower-case canonical UUID, and
    /// refuses JSON that arks' serde_json would read differently from
    /// JSONSerialization or refuse outright: anything but BOM-less UTF-8,
    /// duplicate keys (serde keeps the last, JSONSerialization the first),
    /// trailing commas, non-finite numbers, deep nesting.
    public static func uuid(ofPolicyJSON json: Data) throws -> String {
        guard isPlainUTF8Object(json),
              let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any]
        else {
            throw Error.notJSONObject
        }
        // JSONSerialization reads -1e400 as -inf; serde refuses it.
        guard JSONSerialization.isValidJSONObject(object) else {
            throw Error.unsupportedJSON("non-finite number")
        }
        try checkStructure(of: json)
        guard let raw = object["uuid"] as? String, !raw.isEmpty else {
            throw Error.missingUUID
        }
        guard let parsed = UUID(uuidString: raw), raw == parsed.uuidString.lowercased() else {
            throw Error.invalidUUID(raw)
        }
        return raw
    }

    /// The `uuid` of the policy in a TDF manifest's `encryptionInformation.policy`,
    /// read as arks reads it: any non-empty string, verbatim. Unlike
    /// `uuid(ofPolicyJSON:)` this does not judge the policy (it reads archives
    /// already made, which arks decides on); nil when there is none.
    static func uuid(ofManifestJSON json: Data) -> String? {
        guard let manifest = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let info = manifest["encryptionInformation"] as? [String: Any],
              let policyBase64 = info["policy"] as? String,
              let policyData = Data(base64Encoded: policyBase64),
              let policy = try? JSONSerialization.jsonObject(with: policyData) as? [String: Any],
              let uuid = policy["uuid"] as? String, !uuid.isEmpty
        else { return nil }
        return uuid
    }

    /// BOM-less UTF-8, no NUL bytes (so not UTF-16 or UTF-32), opening with `{`.
    private static func isPlainUTF8Object(_ json: Data) -> Bool {
        guard !json.contains(0), String(data: json, encoding: .utf8) != nil else { return false }
        let whitespace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D]
        return json.first { !whitespace.contains($0) } == UInt8(ascii: "{")
    }

    /// Refuses, in JSON that has already parsed, what serde_json reads
    /// differently or not at all: a key repeated in one object (decoded, so
    /// `"uuid"` is `uuid`, and compared by code units as serde does), a
    /// trailing comma (JSONSerialization allows one), nesting deeper than 64.
    private static func checkStructure(of json: Data) throws {
        enum Container { case object(Set<[UInt8]>), array }
        let bytes = [UInt8](json)
        var stack: [Container] = []
        var expectingKey = false
        var afterComma = false
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            switch byte {
            case 0x20, 0x09, 0x0A, 0x0D:
                index += 1
                continue
            case UInt8(ascii: "{"), UInt8(ascii: "["):
                guard stack.count < 64 else { throw Error.unsupportedJSON("nested deeper than 64") }
                stack.append(byte == UInt8(ascii: "{") ? .object([]) : .array)
                expectingKey = byte == UInt8(ascii: "{")
            case UInt8(ascii: "}"), UInt8(ascii: "]"):
                guard !afterComma else { throw Error.unsupportedJSON("trailing comma") }
                stack.removeLast()
                expectingKey = false
            case UInt8(ascii: ","):
                if case .object = stack.last { expectingKey = true }
            case UInt8(ascii: "\""):
                var end = index + 1
                while bytes[end] != UInt8(ascii: "\"") {
                    end += bytes[end] == UInt8(ascii: "\\") ? 2 : 1
                }
                if expectingKey, case var .object(keys) = stack.last {
                    let token = Data(bytes[index ... end])
                    let key = (try? JSONSerialization.jsonObject(with: token, options: .fragmentsAllowed)) as? String ?? ""
                    guard keys.insert(Array(key.utf8)).inserted else { throw Error.duplicateKey(key) }
                    stack[stack.count - 1] = .object(keys)
                }
                expectingKey = false
                index = end
            default:
                break
            }
            afterComma = byte == UInt8(ascii: ",")
            index += 1
        }
    }

    /// `base64(HMAC-SHA256(key: dek, msg: utf8(policyBase64)))`.
    public static func binding(policyBase64: String, dek: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8), using: SymmetricKey(data: dek))
        return Data(mac).base64EncodedString()
    }
}
