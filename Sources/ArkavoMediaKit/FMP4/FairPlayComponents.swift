import CryptoKit
import Foundation

/// A media component of a FairPlay package profile v2 (ADR-0055 §1 in arkavo-ios). Its id is its kind. Version 2 has
/// a required `video` component and an optional `audio` component, in that order.
public enum FairPlayComponent: String, Sendable, CaseIterable {
    case video
    case audio
}

/// A component's content key: 16 random bytes, independent of every other component's key.
public struct FairPlayComponentKey: Sendable {
    public let component: FairPlayComponent
    public let key: Data

    public init(component: FairPlayComponent, key: Data) {
        self.component = component
        self.key = key
    }
}

/// The policy's `arkavo:components` list (ADR-0055 §3). It sits inside the policy, so every key's policy binding covers
/// it, and each entry's `keyBinding` ties a key to its component: a swapped key access object passes every policy
/// binding but fails `keyBinding`, which the key service checks before it issues a key.
public enum FairPlayComponents {
    public enum Error: Swift.Error, Equatable {
        /// The policy already has `arkavo:components`. The packager writes it, from the keys it made.
        case componentsPresent
        /// Not `video` alone, or `video` then `audio`.
        case unsupportedComponents([String])
        /// A content key that is not 16 bytes.
        case invalidKeySize(FairPlayComponent)
        /// Two components with the same key.
        case sharedKey
        /// The manifest's policy has `arkavo:components` but not as the v2 list, or the manifest or policy is unreadable.
        case malformedComponents
    }

    /// The policy's top-level key for the component list.
    public static let policyKey = "arkavo:components"
    static let bindingLabel = "arkavo:fps:component:v1:"

    /// `base64(HMAC-SHA256(key, utf8("arkavo:fps:component:v1:" + id)))`.
    public static func keyBinding(key: Data, component: FairPlayComponent) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data((bindingLabel + component.rawValue).utf8), using: SymmetricKey(data: key))
        return Data(mac).base64EncodedString()
    }

    /// Refuses a policy that `FairPlayPolicy.uuid(ofPolicyJSON:)` refuses, or that already has `arkavo:components`.
    public static func checkInsertable(_ policyJSON: Data) throws {
        _ = try FairPlayPolicy.uuid(ofPolicyJSON: policyJSON)
        let object = try JSONSerialization.jsonObject(with: policyJSON) as? [String: Any]
        guard object?[policyKey] == nil else { throw Error.componentsPresent }
    }

    /// The policy with `arkavo:components` inserted as its first member: compact, each entry's keys in the order `id`,
    /// `kind`, `keyBinding`, and every other byte of the policy unchanged.
    public static func insert(_ keys: [FairPlayComponentKey], intoPolicyJSON policyJSON: Data) throws -> Data {
        try checkInsertable(policyJSON)
        let components = keys.map(\.component)
        guard components == [.video] || components == [.video, .audio] else {
            throw Error.unsupportedComponents(components.map(\.rawValue))
        }
        if let short = keys.first(where: { $0.key.count != 16 }) { throw Error.invalidKeySize(short.component) }
        guard Set(keys.map(\.key)).count == keys.count else { throw Error.sharedKey }

        let entries = keys.map { entry in
            let id = entry.component.rawValue
            return #"{"id":"\#(id)","kind":"\#(id)","keyBinding":"\#(keyBinding(key: entry.key, component: entry.component))"}"#
        }
        let member = #""\#(policyKey)":[\#(entries.joined(separator: ","))],"#
        // checkInsertable has checked that the first byte past any whitespace opens a non-empty object: it has a uuid.
        let bytes = [UInt8](policyJSON)
        guard let open = bytes.firstIndex(of: UInt8(ascii: "{")) else { throw FairPlayPolicy.Error.notJSONObject }
        let inserted = Data(bytes[...open]) + Data(member.utf8) + Data(bytes[(open + 1)...])
        _ = try FairPlayPolicy.uuid(ofPolicyJSON: inserted)
        return inserted
    }

    /// The component ids of a package manifest's policy, in order: nil when the policy has no `arkavo:components`
    /// (profile v1). Throws `malformedComponents` when the member is present but is not the v2 list (a `video` entry,
    /// then optionally an `audio` entry, each exactly `id`, `kind` (equal to `id`) and `keyBinding`, standard base64 of
    /// 32 bytes), or when the manifest or its policy cannot be read: a present but malformed list is never profile v1.
    public static func componentIDs(ofManifestJSON json: Data) throws -> [String]? {
        guard let manifest = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let information = manifest["encryptionInformation"] as? [String: Any],
              let policyBase64 = information["policy"] as? String,
              let policyData = Data(base64Encoded: policyBase64),
              let policy = try? JSONSerialization.jsonObject(with: policyData) as? [String: Any]
        else { throw Error.malformedComponents }
        guard let member = policy[policyKey] else { return nil }
        guard let list = member as? [Any], list.count == 1 || list.count == 2 else { throw Error.malformedComponents }
        var ids: [String] = []
        for (entry, expected) in zip(list, FairPlayComponent.allCases) {
            guard let object = entry as? [String: Any], Set(object.keys) == ["id", "kind", "keyBinding"],
                  object["id"] as? String == expected.rawValue, object["kind"] as? String == expected.rawValue,
                  let binding = object["keyBinding"] as? String,
                  let decoded = Data(base64Encoded: binding), decoded.count == 32,
                  decoded.base64EncodedString() == binding
            else { throw Error.malformedComponents }
            ids.append(expected.rawValue)
        }
        return ids
    }
}
