import CryptoKit
import Foundation

/// TDF policy helpers for FairPlay (fMP4/CBCS) archives.
///
/// The arks license service (arkavo-rs PR #75, `tdf_policy.rs::check_manifest`)
/// verifies `policyBinding.hash == base64(HMAC-SHA256(key: DEK, msg:
/// utf8(encryptionInformation.policy)))` — the OpenTDF spec form with the raw
/// digest. OpenTDFKit's `TDFCrypto.policyBinding` emits `base64(hex(...))`,
/// which arks refuses, so the FairPlay path computes the binding here.
///
/// The policy `uuid` is the FairPlay content-key id: the playlist key URI is
/// `skd://<uuid>` and the SPC content identifier is the uuid.
public enum FairPlayPolicy {
    public enum Error: Swift.Error, Equatable {
        case notJSONObject
        case missingUUID
        case invalidUUID(String)
        case duplicateKey(String)
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
    /// JSONSerialization: anything but BOM-less UTF-8, or duplicate keys
    /// (serde keeps the last, JSONSerialization the first).
    public static func uuid(ofPolicyJSON json: Data) throws -> String {
        guard isPlainUTF8Object(json),
              let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any]
        else {
            throw Error.notJSONObject
        }
        if let key = firstDuplicateKey(in: json) {
            throw Error.duplicateKey(key)
        }
        guard let raw = object["uuid"] as? String, !raw.isEmpty else {
            throw Error.missingUUID
        }
        guard let parsed = UUID(uuidString: raw), raw == parsed.uuidString.lowercased() else {
            throw Error.invalidUUID(raw)
        }
        return raw
    }

    /// BOM-less UTF-8, no NUL bytes (so not UTF-16 or UTF-32), opening with `{`.
    private static func isPlainUTF8Object(_ json: Data) -> Bool {
        guard !json.contains(0), String(data: json, encoding: .utf8) != nil else { return false }
        let whitespace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D]
        return json.first { !whitespace.contains($0) } == UInt8(ascii: "{")
    }

    /// The first key that appears twice in one object, decoded (`"\u0075uid"`
    /// is `uuid`). `json` must already have parsed.
    private static func firstDuplicateKey(in json: Data) -> String? {
        enum Container { case object(Set<String>), array }
        let bytes = [UInt8](json)
        var stack: [Container] = []
        var expectingKey = false
        var index = 0
        while index < bytes.count {
            switch bytes[index] {
            case UInt8(ascii: "{"):
                stack.append(.object([]))
                expectingKey = true
            case UInt8(ascii: "["):
                stack.append(.array)
                expectingKey = false
            case UInt8(ascii: "}"), UInt8(ascii: "]"):
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
                    guard keys.insert(key).inserted else { return key }
                    stack[stack.count - 1] = .object(keys)
                }
                expectingKey = false
                index = end
            default:
                break
            }
            index += 1
        }
        return nil
    }

    /// `base64(HMAC-SHA256(key: dek, msg: utf8(policyBase64)))`.
    public static func binding(policyBase64: String, dek: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8), using: SymmetricKey(data: dek))
        return Data(mac).base64EncodedString()
    }
}
