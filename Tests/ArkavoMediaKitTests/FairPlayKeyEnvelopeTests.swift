import CryptoKit
import Foundation
import OpenTDFKit
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

@Suite("OpenTDF FairPlay key envelope")
struct FairPlayKeyEnvelopeTests {
    let policy = Data(#"{"uuid":"6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d","arkavo:classification":{"v":1,"filter":"passed","flagged":[]},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]}}"#.utf8)
    let files = ["master.m3u8": Data("master".utf8), "video.m3u8": Data("video".utf8),
                 "video-init.mp4": Data([1, 2, 3]), "video-segment0.m4s": Data([4, 5, 6])]

    @Test("one DEK decrypts the envelope; policy, root and segment bindings verify independently")
    func roundTrip() throws {
        let kas = try TestKASKeyPair()
        let mediaKey = Data(repeating: 7, count: 16), iv = Data(repeating: 8, count: 16)
        let package = try make(kas, mediaKey: mediaKey, iv: iv)
        let manifest = try #require(JSONSerialization.jsonObject(with: package.manifest) as? [String: Any])
        #expect(manifest["schemaVersion"] as? String == "4.3.0")
        let payloadInfo = try #require(manifest["payload"] as? [String: Any])
        #expect(payloadInfo["url"] as? String == "0.payload")
        #expect(payloadInfo["isEncrypted"] as? Bool == true)
        let info = try #require(manifest["encryptionInformation"] as? [String: Any])
        #expect((info["method"] as? [String: Any])?["algorithm"] as? String == "AES-256-GCM")
        let accesses = try #require(info["keyAccess"] as? [[String: Any]])
        try #require(accesses.count == 1)
        #expect(accesses[0]["encryptedMetadata"] == nil)
        #expect(accesses[0]["kid"] as? String == "test-kas")
        let wrapped = try #require(accesses[0]["wrappedKey"] as? String)
        let dek = TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(privateKeyPEM: kas.privateKeyPEM, wrappedKey: wrapped))
        #expect(dek.count == 32)
        if let directory = ProcessInfo.processInfo.environment["ARKAVO_ENVELOPE_FIXTURE_DIR"] {
            let output = URL(fileURLWithPath: directory, isDirectory: true)
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
            for (name, bytes) in files { try bytes.write(to: output.appendingPathComponent(name)) }
            try package.payload.write(to: output.appendingPathComponent("0.payload"))
            let archive = try FMP4RecordingProtectionService.createTDFArchive(
                tempDir: output, manifestData: package.manifest, entryNames: files.keys.sorted() + ["0.payload"])
            try archive.write(to: output.appendingPathComponent("envelope.tdf"))
            try dek.write(to: output.appendingPathComponent("test-dek.bin"))
            try Data(kas.privateKeyPEM.utf8).write(to: output.appendingPathComponent("test-kas-private.pem"))
            try package.manifest.write(to: output.appendingPathComponent("manifest.json"))
        }
        let encodedPolicy = try #require(info["policy"] as? String)
        #expect((accesses[0]["policyBinding"] as? [String: String])?["hash"] == FairPlayPolicy.binding(policyBase64: encodedPolicy, dek: dek))
        let integrity = try #require(info["integrityInformation"] as? [String: Any])
        let segments = try #require(integrity["segments"] as? [[String: Any]])
        #expect(segments.count == 1)
        let tag = Data(package.payload.suffix(16))
        #expect(segments[0]["hash"] as? String == tag.base64EncodedString())
        #expect(segments[0]["encryptedSegmentSize"] as? Int == package.payload.count)
        #expect(segments[0]["segmentSize"] as? Int == package.payload.count - 28)
        let key = SymmetricKey(data: dek)
        let expectedRoot = Data(HMAC<SHA256>.authenticationCode(for: tag, using: key)).base64EncodedString()
        #expect((integrity["rootSignature"] as? [String: String])?["sig"] == expectedRoot)
        let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: package.payload), using: key)
        let envelope = try #require(JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
        #expect(envelope["profile"] as? String == FairPlayKeyEnvelope.profile)
        let tracks = try #require(envelope["tracks"] as? [[String: String]])
        #expect(tracks == [["id": "video", "key": mediaKey.base64EncodedString(), "iv": iv.base64EncodedString()]])
        let policyData = try #require(Data(base64Encoded: encodedPolicy))
        let bound = try #require(JSONSerialization.jsonObject(with: policyData) as? [String: Any])
        #expect(bound["arkavo:media"] as? [[String: String]] == envelope["files"] as? [[String: String]])
        #expect((bound["arkavo:mediaIVs"] as? [String: String])?["video"] == iv.base64EncodedString())
        try FairPlayKeyEnvelope.validateManifest(package.manifest, payload: package.payload)
        try FairPlayKeyEnvelope.verifyInventory(manifestJSON: package.manifest, files: files)
        var damaged = package.payload
        damaged[12] ^= 1
        #expect(throws: (any Swift.Error).self) { try AES.GCM.open(AES.GCM.SealedBox(combined: damaged), using: key) }
        var modified = files
        modified["video-segment0.m4s"] = Data([9])
        #expect(throws: FairPlayKeyEnvelope.Error.invalidInventory) {
            try FairPlayKeyEnvelope.verifyInventory(manifestJSON: package.manifest, files: modified)
        }
        modified = files
        modified["audio.m3u8"] = Data()
        #expect(throws: FairPlayKeyEnvelope.Error.invalidInventory) {
            try FairPlayKeyEnvelope.verifyInventory(manifestJSON: package.manifest, files: modified)
        }
    }

    @Test("two track keys remain independent inside one payload and never become separate KAOs")
    func twoTracks() throws {
        let kas = try TestKASKeyPair()
        let package = try FairPlayKeyEnvelope.build(
            componentKeys: [.init(component: .video, key: Data(repeating: 1, count: 16)),
                            .init(component: .audio, key: Data(repeating: 2, count: 16))],
            iv: Data(repeating: 3, count: 16), assetID: "asset", policyJSON: policy, mediaFiles: files,
            kasURL: URL(string: "https://platform.arkavo.net")!, publicKey: try TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!).publicKey(fromPEM: kas.publicKeyPEM))
        let manifest = try #require(JSONSerialization.jsonObject(with: package.manifest) as? [String: Any])
        let info = try #require(manifest["encryptionInformation"] as? [String: Any])
        let accesses = try #require(info["keyAccess"] as? [[String: Any]])
        #expect(accesses.count == 1)
        #expect(try FairPlayComponents.componentIDs(ofManifestJSON: package.manifest) == ["video", "audio"])
    }

    @Test("reserved profile and unsafe media paths are refused")
    func refusesInvalidInput() throws {
        let kas = try TestKASKeyPair()
        var unsafe = files
        unsafe["../video.m3u8"] = Data()
        #expect(throws: FairPlayKeyEnvelope.Error.invalidInventory) { try make(kas, mediaFiles: unsafe) }
        let reserved = Data(#"{"arkavo:fpsProfile":"other","uuid":"6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d","body":{}}"#.utf8)
        #expect(throws: FairPlayKeyEnvelope.Error.reservedPolicyMember) { try make(kas, policyJSON: reserved) }
    }

    @Test("delegate sends encrypted payload to the KSM and receives only a CKC")
    func payloadTransport() async throws {
        let package = try make(TestKASKeyPair())
        let manifest = FairPlayManifest(assetID: "asset", kasURL: "https://platform.arkavo.net", wrappedKey: "",
                                        algorithm: "AES-256-GCM", iv: "", tdfManifestJSON: package.manifest,
                                        tdfPayload: package.payload)
        let http = FakeMediaService()
        let delegate = TDFContentKeyDelegate(manifest: manifest, authToken: nil,
                                             serverURL: URL(string: "https://platform.arkavo.net")!, http: http)
        let request = FakeKeyRequest("skd://6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d/video")
        await delegate.handle(request)
        let calls = await http.calls
        let keyRequest = try #require(calls.first { $0.route == "POST key-request" })
        #expect(keyRequest.body["tdfPayload"] == package.payload.base64EncodedString())
        #expect(keyRequest.body["component"] == "video")
    }

    @Test("a real two-track recording packages one OpenTDF payload and verifies every HLS file")
    func recordingArchive() async throws {
        let kas = try TestKASKeyPair()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let movie = try await SyntheticMovie.make(in: directory, sound: .aac(tracks: 1))
        let service = FMP4RecordingProtectionService(kasURL: URL(string: "https://platform.arkavo.net")!,
                                                      kasPublicKeyPEM: kas.spkiPublicKeyPEM)
        let archive = try await service.protectVideo(videoURL: movie, assetID: "test-asset", policyJSON: policy,
                                                     profile: .keyEnvelope, kasKeyID: "test-kas")
        let zip = try Archive(data: archive, accessMode: .read)
        var entries: [String: Data] = [:]
        for entry in zip {
            var bytes = Data()
            _ = try zip.extract(entry) { bytes.append($0) }
            entries[entry.path] = bytes
        }
        let manifestEntry = entries.removeValue(forKey: "manifest.json")
        let manifest = try #require(manifestEntry)
        let payloadEntry = entries.removeValue(forKey: "0.payload")
        let payload = try #require(payloadEntry)
        try FairPlayKeyEnvelope.validateManifest(manifest, payload: payload)
        try FairPlayKeyEnvelope.verifyInventory(manifestJSON: manifest, files: entries)
        #expect(try FairPlayComponents.componentIDs(ofManifestJSON: manifest) == ["video", "audio"])
        #expect(entries["audio-segment0.m4s"] != nil)
        if let path = ProcessInfo.processInfo.environment["ARKAVO_ENVELOPE_FIXTURE_DIR"] {
            let output = URL(fileURLWithPath: path).appendingPathComponent("two-tracks", isDirectory: true)
            try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
            try archive.write(to: output.appendingPathComponent("envelope.tdf"))
            try Data(kas.privateKeyPEM.utf8).write(to: output.appendingPathComponent("test-kas-private.pem"))
            let object = try #require(JSONSerialization.jsonObject(with: manifest) as? [String: Any])
            let info = try #require(object["encryptionInformation"] as? [String: Any])
            let accesses = try #require(info["keyAccess"] as? [[String: Any]])
            let wrapped = try #require(accesses.first?["wrappedKey"] as? String)
            let dek = TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: kas.privateKeyPEM, wrappedKey: wrapped))
            try dek.write(to: output.appendingPathComponent("test-dek.bin"))
        }
    }

    @Test("missing or modified envelope fails before network requests")
    func missingPayload() async throws {
        let package = try make(TestKASKeyPair())
        for payload in [nil, Data([1, 2, 3])] as [Data?] {
            let manifest = FairPlayManifest(assetID: "asset", kasURL: "https://platform.arkavo.net", wrappedKey: "",
                                            algorithm: "AES-256-GCM", iv: "", tdfManifestJSON: package.manifest,
                                            tdfPayload: payload)
            let http = FakeMediaService()
            let delegate = TDFContentKeyDelegate(manifest: manifest, authToken: nil,
                                                 serverURL: URL(string: "https://platform.arkavo.net")!, http: http)
            await delegate.handle(FakeKeyRequest("skd://6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d/video"))
            #expect(await http.calls.isEmpty)
        }
    }

    @Test("only a wrapped KAS access with a canonical policy binding is admitted")
    func invalidKeyAccess() throws {
        let package = try make(TestKASKeyPair())
        let original = try #require(JSONSerialization.jsonObject(with: package.manifest) as? [String: Any])
        let mutations: [(String, Any)] = [
            ("type", "remote"), ("protocol", "file"), ("wrappedKey", "invalid!"),
            ("policyBinding", ["alg": "HS256", "hash": "AA=="]),
            ("policyBinding", ["alg": "HS512", "hash": Data(repeating: 0, count: 32).base64EncodedString()]),
            ("encryptedMetadata", "e30="),
        ]
        for (member, value) in mutations {
            var manifest = original
            var information = try #require(manifest["encryptionInformation"] as? [String: Any])
            var accesses = try #require(information["keyAccess"] as? [[String: Any]])
            accesses[0][member] = value
            information["keyAccess"] = accesses
            manifest["encryptionInformation"] = information
            let bytes = try JSONSerialization.data(withJSONObject: manifest)
            #expect(throws: FairPlayKeyEnvelope.Error.invalidProfile) {
                try FairPlayKeyEnvelope.validateManifest(bytes, payload: package.payload)
            }
        }
    }

    private func make(_ kas: TestKASKeyPair, mediaKey: Data = Data(repeating: 7, count: 16),
                      iv: Data = Data(repeating: 8, count: 16), mediaFiles: [String: Data]? = nil,
                      policyJSON: Data? = nil) throws -> FairPlayKeyEnvelope.Package {
        try FairPlayKeyEnvelope.build(componentKeys: [.init(component: .video, key: mediaKey)], iv: iv,
                                      assetID: "asset", policyJSON: policyJSON ?? policy, mediaFiles: mediaFiles ?? files,
                                      kasURL: URL(string: "https://platform.arkavo.net")!, publicKey: try TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!).publicKey(fromPEM: kas.publicKeyPEM), kasKeyID: "test-kas")
    }
}
