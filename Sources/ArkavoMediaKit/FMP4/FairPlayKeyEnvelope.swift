import CryptoKit
import Foundation
import Security

/// OpenTDF 4.3 payload containing FairPlay keys, decrypted only by the license service.
/// Media remains CBCS encrypted; the payload uses an independent 256-bit AES-GCM key.
public enum FairPlayKeyEnvelope {
    public static let profile = "urn:arkavo:fairplay:key-envelope:1"
    public static let payloadName = "0.payload"
    public static let maximumPayloadSize = 2_097_180
    public static let maximumFiles = 8_191

    public enum Error: Swift.Error, Equatable {
        case invalidInventory, reservedPolicyMember, oversizedPayload, invalidIV, invalidProfile, invalidAssetID
    }

    public struct Package: Sendable {
        public let manifest: Data
        public let payload: Data
    }

    /// Validate the public envelope shape before contacting a license service. This does not
    /// authenticate policy/root bindings: only the KSM can do that with the unwrapped DEK.
    public static func validateManifest(_ manifestJSON: Data, payload: Data) throws {
        let manifest = try object(manifestJSON)
        guard manifest["schemaVersion"] as? String == "4.3.0",
              let descriptor = manifest["payload"] as? [String: Any],
              descriptor["type"] as? String == "reference", descriptor["url"] as? String == payloadName,
              descriptor["protocol"] as? String == "zip", descriptor["isEncrypted"] as? Bool == true,
              let information = manifest["encryptionInformation"] as? [String: Any],
              information["type"] as? String == "split",
              let access = information["keyAccess"] as? [[String: Any]], access.count == 1,
              let method = information["method"] as? [String: Any],
              method["algorithm"] as? String == "AES-256-GCM", method["isStreamable"] as? Bool == true,
              let integrity = information["integrityInformation"] as? [String: Any],
              integrity["segmentHashAlg"] as? String == "GMAC",
              integrity["segmentSizeDefault"] as? Int == maximumPayloadSize - 28,
              integrity["encryptedSegmentSizeDefault"] as? Int == maximumPayloadSize,
              let root = integrity["rootSignature"] as? [String: String], root["alg"] == "HS256",
              let rootString = root["sig"], let rootBytes = Data(base64Encoded: rootString), rootBytes.count == 32,
              let segments = integrity["segments"] as? [[String: Any]], segments.count == 1,
              payload.count > 28, payload.count <= maximumPayloadSize,
              segments[0]["encryptedSegmentSize"] as? Int == payload.count,
              segments[0]["segmentSize"] as? Int == payload.count - 28,
              segments[0]["hash"] as? String == Data(payload.suffix(16)).base64EncodedString(),
              let encodedPolicy = information["policy"] as? String,
              let policyJSON = Data(base64Encoded: encodedPolicy)
        else { throw Error.invalidProfile }
        let policy = try object(policyJSON)
        guard policy["arkavo:fpsProfile"] as? String == profile,
              let ids = try FairPlayComponents.componentIDs(ofManifestJSON: manifestJSON),
              let ivs = policy["arkavo:mediaIVs"] as? [String: String], Set(ivs.keys) == Set(ids)
        else { throw Error.invalidProfile }
        for iv in ivs.values {
            guard let decoded = Data(base64Encoded: iv), decoded.count == 16,
                  decoded.base64EncodedString() == iv else { throw Error.invalidIV }
        }
    }

    /// Public inventory digests are untrusted until the license service accepts the bound policy.
    /// Players must check the bytes before playback; the service authenticates the same inventory before a CKC.
    public static func verifyInventory(manifestJSON: Data, files: [String: Data]) throws {
        let manifest = try object(manifestJSON)
        guard let information = manifest["encryptionInformation"] as? [String: Any],
              let encoded = information["policy"] as? String,
              let policyData = Data(base64Encoded: encoded) else { throw Error.invalidProfile }
        let policy = try object(policyData)
        guard policy["arkavo:fpsProfile"] as? String == profile,
              let inventory = policy["arkavo:media"] as? [[String: String]],
              !inventory.isEmpty, inventory.count <= maximumFiles else { throw Error.invalidInventory }
        var seen = Set<String>()
        for entry in inventory {
            guard Set(entry.keys) == ["name", "sha256"], let name = entry["name"],
                  FairPlayPackage.isServed(name), seen.insert(name).inserted,
                  let bytes = files[name], let digest = entry["sha256"],
                  digest == Data(SHA256.hash(data: bytes)).base64EncodedString()
            else { throw Error.invalidInventory }
        }
        guard seen == Set(files.keys), seen.contains(FairPlayPackage.masterPlaylistName)
        else { throw Error.invalidInventory }
    }

    /// Build one standard TDF payload and one KAO. The RSA-wrapped key is the independent
    /// 32-byte envelope DEK, never a media key. No plaintext is put in encryptedMetadata.
    public static func build(
        componentKeys: [FairPlayComponentKey], iv: Data, assetID: String, policyJSON: Data,
        mediaFiles: [String: Data], kasURL: URL, publicKey: SecKey, kasKeyID: String? = nil
    ) throws -> Package {
        guard iv.count == 16 else { throw Error.invalidIV }
        guard !assetID.isEmpty, assetID.utf8.count <= 1024 else { throw Error.invalidAssetID }
        guard !mediaFiles.isEmpty, mediaFiles.count <= maximumFiles,
              mediaFiles.keys.allSatisfy(FairPlayPackage.isServed),
              mediaFiles[FairPlayPackage.masterPlaylistName] != nil else { throw Error.invalidInventory }
        let policyWithComponents = try FairPlayComponents.insert(componentKeys, intoPolicyJSON: policyJSON)
        var policy = try object(policyWithComponents)
        for name in ["arkavo:fpsProfile", "arkavo:media", "arkavo:mediaIVs"] {
            guard policy[name] == nil else { throw Error.reservedPolicyMember }
        }
        let contentKeyID = try FairPlayPolicy.uuid(ofPolicyJSON: policyJSON)
        let inventory = mediaFiles.keys.sorted().map { name in
            ["name": name, "sha256": Data(SHA256.hash(data: mediaFiles[name]!)).base64EncodedString()]
        }
        policy["arkavo:fpsProfile"] = profile
        policy["arkavo:media"] = inventory
        policy["arkavo:mediaIVs"] = Dictionary(uniqueKeysWithValues: componentKeys.map {
            ($0.component.rawValue, iv.base64EncodedString())
        })
        let encodedPolicy = try json(policy).base64EncodedString()
        let envelope: [String: Any] = [
            "profile": profile, "assetId": assetID, "contentKeyId": contentKeyID,
            "tracks": componentKeys.map {
                ["id": $0.component.rawValue, "key": $0.key.base64EncodedString(), "iv": iv.base64EncodedString()]
            }, "files": inventory,
        ]
        let plaintext = try json(envelope)
        guard plaintext.count <= maximumPayloadSize - 28 else { throw Error.oversizedPayload }
        let dek = SymmetricKey(size: .bits256)
        let dekData = dek.withUnsafeBytes { Data($0) }
        let sealed = try AES.GCM.seal(plaintext, using: dek)
        // CryptoKit's combined representation is nonce(12) || ciphertext || tag(16).
        let payload = sealed.combined!
        let tag = sealed.tag
        let wrappedKey = try TDFManifestBuilder(kasURL: kasURL).wrapKey(dekData, with: publicKey)
        var access: [String: Any] = [
            "type": "wrapped", "protocol": "kas", "url": kasURL.absoluteString,
            "wrappedKey": wrappedKey.base64EncodedString(),
            "policyBinding": ["alg": "HS256", "hash": FairPlayPolicy.binding(policyBase64: encodedPolicy, dek: dekData)],
        ]
        if let kasKeyID { access["kid"] = kasKeyID }
        let root = Data(HMAC<SHA256>.authenticationCode(for: tag, using: dek)).base64EncodedString()
        let manifest: [String: Any] = [
            "schemaVersion": "4.3.0",
            "payload": ["type": "reference", "url": payloadName, "protocol": "zip",
                        "isEncrypted": true, "mimeType": "application/json"],
            "encryptionInformation": [
                "type": "split", "keyAccess": [access], "policy": encodedPolicy,
                "method": ["algorithm": "AES-256-GCM", "isStreamable": true, "iv": ""],
                "integrityInformation": [
                    "rootSignature": ["alg": "HS256", "sig": root], "segmentHashAlg": "GMAC",
                    "segmentSizeDefault": maximumPayloadSize - 28, "encryptedSegmentSizeDefault": maximumPayloadSize,
                    "segments": [["hash": tag.base64EncodedString(), "segmentSize": plaintext.count,
                                  "encryptedSegmentSize": payload.count]],
                ],
            ],
        ]
        return Package(manifest: try json(manifest), payload: payload)
    }

    private static func object(_ data: Data) throws -> [String: Any] {
        guard FairPlayPolicy.isPlainUTF8Object(data),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw Error.invalidProfile }
        try FairPlayPolicy.checkStructure(of: data)
        return object
    }

    private static func json(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}
