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
    }

    /// Placeholder policy for public content, `{"uuid":"<lowercase uuid>","body":{}}`.
    /// arks (after PR #75) refuses a policy with no data attributes, so content
    /// protected with this plays only against the pre-#75 license service.
    public static func placeholderJSON() -> Data {
        Data("{\"uuid\":\"\(UUID().uuidString.lowercased())\",\"body\":{}}".utf8)
    }

    /// The policy's `uuid` exactly as written (arks compares the SPC asset id
    /// with it verbatim). Throws unless it parses as a UUID.
    public static func uuid(ofPolicyJSON json: Data) throws -> String {
        guard let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else {
            throw Error.notJSONObject
        }
        guard let raw = object["uuid"] as? String, !raw.isEmpty else {
            throw Error.missingUUID
        }
        guard UUID(uuidString: raw) != nil else {
            throw Error.invalidUUID(raw)
        }
        return raw
    }

    /// `base64(HMAC-SHA256(key: dek, msg: utf8(policyBase64)))`.
    public static func binding(policyBase64: String, dek: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8), using: SymmetricKey(data: dek))
        return Data(mac).base64EncodedString()
    }
}
