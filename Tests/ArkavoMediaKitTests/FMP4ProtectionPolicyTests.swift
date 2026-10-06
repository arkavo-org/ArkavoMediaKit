import CryptoKit
import Foundation
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

/// The fMP4 FairPlay archive meets the arks license contract (arkavo-rs #75):
/// a bound policy, and a playlist key URI of `skd://<policy uuid>`.
@Suite("FMP4RecordingProtectionService policy and key URI")
struct FMP4ProtectionPolicyTests {
    static let kasURL = URL(string: "https://platform.arkavo.net")!
    static let tierPolicy = #"{"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}"#

    private func entries(_ archive: Data) throws -> [String: Data] {
        let zip = try Archive(data: archive, accessMode: .read)
        var out: [String: Data] = [:]
        for entry in zip {
            var data = Data()
            _ = try zip.extract(entry) { data.append($0) }
            out[entry.path] = data
        }
        return out
    }

    /// Protects a synthetic movie; `output` is everything printed to stdout meanwhile.
    private func protect(policyJSON: Data?) async throws -> (files: [String: Data], kas: TestKASKeyPair, output: String) {
        let kas = try TestKASKeyPair()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-policy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let movie = try await SyntheticMovie.make(in: dir)
        let service = FMP4RecordingProtectionService(kasURL: Self.kasURL, kasPublicKeyPEM: kas.spkiPublicKeyPEM)
        let (archive, output) = try await StdoutCapture.capture {
            try await service.protectVideo(videoURL: movie, assetID: "recording-asset-1", policyJSON: policyJSON)
        }
        return (try entries(archive), kas, output)
    }

    private func encryptionInformation(_ files: [String: Data]) throws -> [String: Any] {
        let manifestData = try #require(files["manifest.json"])
        let manifest = try #require(JSONSerialization.jsonObject(with: manifestData) as? [String: Any])
        return try #require(manifest["encryptionInformation"] as? [String: Any])
    }

    @Test("tier policy is embedded, bound, and names the skd:// key URI")
    func tierPolicyArchive() async throws {
        let (files, kas, _) = try await protect(policyJSON: Data(Self.tierPolicy.utf8))
        let info = try encryptionInformation(files)
        let policy = try #require(info["policy"] as? String)
        #expect(Data(base64Encoded: policy) == Data(Self.tierPolicy.utf8))
        let kao = try #require((info["keyAccess"] as? [[String: Any]])?.first)
        let wrappedBase64 = try #require(kao["wrappedKey"] as? String)
        let wrapped = try #require(Data(base64Encoded: wrappedBase64))
        let dek = try kas.unwrap(wrapped)
        let binding = try #require((kao["policyBinding"] as? [String: Any])?["hash"] as? String)
        #expect(binding == FairPlayPolicy.binding(policyBase64: policy, dek: dek))
        let playlistData = try #require(files["playlist.m3u8"])
        let playlist = String(decoding: playlistData, as: UTF8.self)
        #expect(playlist.contains(#"URI="skd://6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d""#))
        #expect(!playlist.contains("skd://recording-asset-1"))
        // fMP4 metadata still names the recording's asset id.
        let metaBase64 = try #require(kao["encryptedMetadata"] as? String)
        let metaData = try #require(Data(base64Encoded: metaBase64))
        let meta = try #require(JSONSerialization.jsonObject(with: metaData) as? [String: Any])
        #expect(meta["type"] as? String == "fmp4-fairplay")
        #expect(meta["assetId"] as? String == "recording-asset-1")
    }

    @Test("no policy → placeholder policy whose uuid is the key URI")
    func placeholderArchive() async throws {
        let (files, _, _) = try await protect(policyJSON: nil)
        let info = try encryptionInformation(files)
        let policyBase64 = try #require(info["policy"] as? String)
        let policyJSON = try #require(Data(base64Encoded: policyBase64))
        let uuid = try FairPlayPolicy.uuid(ofPolicyJSON: policyJSON)
        let playlistData = try #require(files["playlist.m3u8"])
        let playlist = String(decoding: playlistData, as: UTF8.self)
        #expect(playlist.contains("URI=\"skd://\(uuid)\""))
    }

    @Test("a policy without a uuid is refused before any work")
    func rejectsPolicyWithoutUUID() async throws {
        let service = FMP4RecordingProtectionService(
            kasURL: Self.kasURL, kasPublicKeyPEM: try TestKASKeyPair().spkiPublicKeyPEM)
        await #expect(throws: FairPlayPolicy.Error.missingUUID) {
            _ = try await service.protectVideo(
                videoURL: URL(fileURLWithPath: "/nonexistent.mov"), assetID: "a",
                policyJSON: Data(#"{"body":{}}"#.utf8))
        }
    }

    /// Nothing the protect path prints, from the service or anything it calls,
    /// may carry the content key or IV, however formatted. Runs in a Debug
    /// build, where the verbose logging is on.
    @Test("the protect path never prints the content key or IV")
    func protectPathPrintsNoKeyMaterial() async throws {
        let (files, kas, output) = try await protect(policyJSON: Data(Self.tierPolicy.utf8))
        #expect(output.contains("Wrapping content key"), "the capture must see the service's progress logs")
        let info = try encryptionInformation(files)
        let kao = try #require((info["keyAccess"] as? [[String: Any]])?.first)
        let wrappedBase64 = try #require(kao["wrappedKey"] as? String)
        let dek = try kas.unwrap(try #require(Data(base64Encoded: wrappedBase64)))
        let ivBase64 = try #require((info["method"] as? [String: Any])?["iv"] as? String)
        let iv = try #require(Data(base64Encoded: ivBase64))
        for (name, secret) in [("content key", dek), ("IV", iv)] {
            for (format, text) in Self.textForms(of: secret) {
                #expect(!output.contains(text), "stdout carries the \(name) as \(format)")
            }
        }
    }

    /// The ways a log line could plausibly render `bytes`.
    private static func textForms(of bytes: Data) -> [(format: String, text: String)] {
        let hex = bytes.map { String(format: "%02x", $0) }
        return [
            ("hex", hex.joined()),
            ("upper-case hex", hex.joined().uppercased()),
            ("spaced hex", hex.joined(separator: " ")),
            ("upper-case spaced hex", hex.joined(separator: " ").uppercased()),
            ("base64", bytes.base64EncodedString()),
        ]
    }
}
