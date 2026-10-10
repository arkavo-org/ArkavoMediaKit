import Foundation
import OpenTDFKit
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

    /// Protects a synthetic movie, with `sound` when given; `output` is everything printed to stdout meanwhile.
    private func protect(policyJSON: Data?, sound: SyntheticMovie.Sound? = nil)
        async throws -> (files: [String: Data], kas: TestKASKeyPair, output: String) {
        let kas = try TestKASKeyPair()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-policy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let movie = try await SyntheticMovie.make(in: dir, sound: sound)
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

    @Test("tier policy is embedded with the component list, bound under the key, and names the skd:// key URI")
    func tierPolicyArchive() async throws {
        let (files, kas, _) = try await protect(policyJSON: Data(Self.tierPolicy.utf8))
        let info = try encryptionInformation(files)
        let policy = try #require(info["policy"] as? String)
        // The synthetic movie has no sound: one component, video, under one key.
        let accesses = try #require(info["keyAccess"] as? [[String: Any]])
        try #require(accesses.count == 1)
        let kao = accesses[0]
        let wrappedBase64 = try #require(kao["wrappedKey"] as? String)
        let dek = TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: kas.privateKeyPEM, wrappedKey: wrappedBase64))
        // The caller's policy with the packager's component list as its first member, and nothing else changed.
        let expected = try FairPlayComponents.insert([FairPlayComponentKey(component: .video, key: dek)],
                                                     intoPolicyJSON: Data(Self.tierPolicy.utf8))
        #expect(Data(base64Encoded: policy) == expected)
        let binding = try #require((kao["policyBinding"] as? [String: Any])?["hash"] as? String)
        #expect(binding == FairPlayPolicy.binding(policyBase64: policy, dek: dek))
        let playlistData = try #require(files["video.m3u8"])
        let playlist = String(decoding: playlistData, as: UTF8.self)
        #expect(playlist.contains(#"URI="skd://6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d/video""#))
        #expect(!playlist.contains("skd://recording-asset-1"))
        // fMP4 metadata still names the recording's asset id, and names the master playlist.
        let metaBase64 = try #require(kao["encryptedMetadata"] as? String)
        let metaData = try #require(Data(base64Encoded: metaBase64))
        let meta = try #require(JSONSerialization.jsonObject(with: metaData) as? [String: Any])
        #expect(meta["type"] as? String == "fmp4-fairplay")
        #expect(meta["assetId"] as? String == "recording-asset-1")
        #expect(meta["playlistFilename"] as? String == "master.m3u8")
        #expect(meta["initFilename"] == nil)
        // The segment list is in the playlists; in the KAO it only grew every key request.
        #expect(meta["segmentFilenames"] == nil)
        // Readers find the key URIs' uuid without decoding the policy.
        #expect(meta["contentKeyId"] as? String == "6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
        let manifestData = try #require(files["manifest.json"])
        let manifest = try #require(JSONSerialization.jsonObject(with: manifestData) as? [String: Any])
        let topMeta = try #require(manifest["meta"] as? [String: Any])
        #expect(topMeta["assetId"] as? String == "recording-asset-1")
        #expect(topMeta["contentKeyId"] as? String == "6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
    }

    @Test("no policy → placeholder policy whose uuid is the key URI")
    func placeholderArchive() async throws {
        let (files, _, _) = try await protect(policyJSON: nil)
        let info = try encryptionInformation(files)
        let policyBase64 = try #require(info["policy"] as? String)
        let policyJSON = try #require(Data(base64Encoded: policyBase64))
        let uuid = try FairPlayPolicy.uuid(ofPolicyJSON: policyJSON)
        let playlistData = try #require(files["video.m3u8"])
        let playlist = String(decoding: playlistData, as: UTF8.self)
        #expect(playlist.contains("URI=\"skd://\(uuid)/video\""))
    }

    /// The PEM is not a key: parsing it before the policy check would throw
    /// invalidPublicKeyFormat instead.
    @Test("a policy without a uuid is refused before any work")
    func rejectsPolicyWithoutUUID() async throws {
        let service = FMP4RecordingProtectionService(kasURL: Self.kasURL, kasPublicKeyPEM: "not a key")
        await #expect(throws: FairPlayPolicy.Error.missingUUID) {
            _ = try await service.protectVideo(
                videoURL: URL(fileURLWithPath: "/nonexistent.mov"), assetID: "a",
                policyJSON: Data(#"{"body":{}}"#.utf8))
        }
    }

    /// The packager writes the component list from the keys it makes; a caller's list would name keys it did not.
    @Test("a policy that already lists components is refused before any work")
    func rejectsPolicyWithComponents() async throws {
        let service = FMP4RecordingProtectionService(kasURL: Self.kasURL, kasPublicKeyPEM: "not a key")
        await #expect(throws: FairPlayComponents.Error.componentsPresent) {
            _ = try await service.protectVideo(
                videoURL: URL(fileURLWithPath: "/nonexistent.mov"), assetID: "a",
                policyJSON: Data(#"{"arkavo:components":[],"body":{},"uuid":"6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}"#.utf8))
        }
    }

    /// A source that stops yielding samples part-way (a truncated file, a read
    /// error) must fail the protect, not produce a short archive.
    @Test("a source that fails part-way through reading is refused")
    func truncatedSourceIsRefused() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-truncated-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let movie = try await SyntheticMovie.make(in: dir, frames: 90, moovFirst: true)
        let handle = try FileHandle(forWritingTo: movie)
        try handle.truncate(atOffset: try handle.seekToEnd() * 6 / 10)
        try handle.close()

        let service = FMP4RecordingProtectionService(
            kasURL: Self.kasURL, kasPublicKeyPEM: try TestKASKeyPair().spkiPublicKeyPEM)
        let error = await #expect(throws: FMP4ProtectionError.self) {
            _ = try await service.protectVideo(videoURL: movie, assetID: "a", policyJSON: Data(Self.tierPolicy.utf8))
        }
        guard case .readFailed = error else {
            Issue.record("expected readFailed, got \(String(describing: error))")
            return
        }
    }

    /// Creator starts the writer session at zero on the first captured frame,
    /// then drops that frame, so the track opens with an empty edit as long as
    /// the first capture interval. A complete read of it is not short.
    @Test("a source with a leading empty edit, read whole, protects")
    func leadingEmptyEditProtects() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-edit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let times = (0 ..< 60).map { 0.050 + Double($0) / 30 }
        let movie = try await SyntheticMovie.make(in: dir, frameTimes: times)
        let service = FMP4RecordingProtectionService(
            kasURL: Self.kasURL, kasPublicKeyPEM: try TestKASKeyPair().spkiPublicKeyPEM)
        _ = try await service.protectVideo(videoURL: movie, assetID: "a", policyJSON: Data(Self.tierPolicy.utf8))
    }

    /// A paused recording holds one frame for the pause. When a truncated read
    /// of one finishes .completed, the shortfall can be smaller than that frame.
    @Test("a truncated source with a long held frame is refused on every read")
    func truncatedSourceWithHeldFrameIsRefused() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-pause-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        // 3 s at 30 fps, a frame held 20 s, then 6 s at 30 fps.
        let before: [Double] = (0 ..< 90).map { Double($0) / 30 }
        let after: [Double] = (0 ..< 180).map { 23 + Double($0) / 30 }
        let times = before + after
        let movie = try await SyntheticMovie.make(in: dir, frameTimes: times, moovFirst: true)
        let handle = try FileHandle(forWritingTo: movie)
        try handle.truncate(atOffset: try handle.seekToEnd() * 85 / 100)
        try handle.close()

        let service = FMP4RecordingProtectionService(
            kasURL: Self.kasURL, kasPublicKeyPEM: try TestKASKeyPair().spkiPublicKeyPEM)
        for attempt in 1 ... 4 {
            let error = await #expect(throws: FMP4ProtectionError.self, "attempt \(attempt)") {
                _ = try await service.protectVideo(videoURL: movie, assetID: "a", policyJSON: Data(Self.tierPolicy.utf8))
            }
            guard case .readFailed = error else {
                Issue.record("attempt \(attempt): expected readFailed, got \(String(describing: error))")
                continue
            }
        }
    }

    /// Nothing the protect path prints, from the service or anything it calls,
    /// may carry a content key or the IV, however formatted. Runs in a Debug
    /// build, where the verbose logging is on.
    @Test("the protect path never prints a content key or the IV")
    func protectPathPrintsNoKeyMaterial() async throws {
        let (files, kas, output) = try await protect(policyJSON: Data(Self.tierPolicy.utf8), sound: .aac(tracks: 1))
        #expect(output.contains("Wrapping content key"), "the capture must see the service's progress logs")
        let info = try encryptionInformation(files)
        let accesses = try #require(info["keyAccess"] as? [[String: Any]])
        #expect(accesses.count == 2, "a movie with sound has a video key and an audio key")
        var secrets: [(name: String, bytes: Data)] = []
        for access in accesses {
            let wrappedBase64 = try #require(access["wrappedKey"] as? String)
            secrets.append(("content key", TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: kas.privateKeyPEM, wrappedKey: wrappedBase64))))
        }
        let ivBase64 = try #require((info["method"] as? [String: Any])?["iv"] as? String)
        secrets.append(("IV", try #require(Data(base64Encoded: ivBase64))))
        for (name, secret) in secrets {
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
