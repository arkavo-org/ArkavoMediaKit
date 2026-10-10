import Foundation
import OpenTDFKit
import Testing
@testable import ArkavoMediaKit

/// The policy's component list and each component's key access (ADR-0055 §3 in arkavo-ios), pinned to the shared test
/// vectors of the profile v2 coordinating plan, so the packager, the key service and the readers agree byte for byte.
@Suite("FairPlayComponents")
struct FairPlayComponentsTests {
    static let videoKey = Data((0x00 ... 0x0F).map { UInt8($0) })
    static let audioKey = Data((0x10 ... 0x1F).map { UInt8($0) })
    static let uuid = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"
    static let before = #"{"arkavo:classification":{"filter":"passed","flagged":[],"v":1},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"}"#
    static let after = #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="},{"id":"audio","kind":"audio","keyBinding":"rVO1aH+bdtNnKvDGX38OaorFTRMJsPMGbMJNGKKLU3Q="}],"arkavo:classification":{"filter":"passed","flagged":[],"v":1},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"}"#
    static let videoOnly = #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="}],"arkavo:classification":{"filter":"passed","flagged":[],"v":1},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"}"#
    static let video = FairPlayComponentKey(component: .video, key: videoKey)
    static let audio = FairPlayComponentKey(component: .audio, key: audioKey)

    @Test("keyBinding is HMAC-SHA256 of the component's label under the component's key")
    func keyBindings() {
        #expect(FairPlayComponents.keyBinding(key: Self.videoKey, component: .video)
            == "9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4=")
        #expect(FairPlayComponents.keyBinding(key: Self.audioKey, component: .audio)
            == "rVO1aH+bdtNnKvDGX38OaorFTRMJsPMGbMJNGKKLU3Q=")
        // The swap: the audio key under the video component's label binds to something else.
        #expect(FairPlayComponents.keyBinding(key: Self.audioKey, component: .video)
            == "4WqNpABYVXOM11ru1ClCNaEZZ8HOCCY+Ag0tppvil80=")
    }

    @Test("The component list goes in as the policy's first member, and no other byte changes")
    func insertion() throws {
        let policy = Data(Self.before.utf8)
        #expect(try FairPlayComponents.insert([Self.video, Self.audio], intoPolicyJSON: policy) == Data(Self.after.utf8))
        #expect(try FairPlayComponents.insert([Self.video], intoPolicyJSON: policy) == Data(Self.videoOnly.utf8))
        #expect(try FairPlayPolicy.uuid(ofPolicyJSON: Data(Self.after.utf8)) == Self.uuid)
    }

    @Test("Each component's key binds the policy with its component list, as the shared vectors pin")
    func policyBindings() {
        let policy = Data(Self.after.utf8).base64EncodedString()
        #expect(FairPlayPolicy.binding(policyBase64: policy, dek: Self.videoKey)
            == "YfWHFTZaDRIdmvAJhng0YHwLLHeKeEYNGKXCXd9wWqc=")
        #expect(FairPlayPolicy.binding(policyBase64: policy, dek: Self.audioKey)
            == "BYwGfQat7pK/d/NCvjZZqIryPOUA72NPx+1O/oBXF5A=")
        #expect(FairPlayPolicy.binding(policyBase64: Data(Self.videoOnly.utf8).base64EncodedString(), dek: Self.videoKey)
            == "gzj4O10aZXXETOaFvB+qGPqBV48CYTEtDdPXk8azn8o=")
    }

    @Test("A policy that already lists components is refused")
    func refusesExistingComponents() {
        #expect(throws: FairPlayComponents.Error.componentsPresent) {
            try FairPlayComponents.insert([Self.video, Self.audio], intoPolicyJSON: Data(Self.after.utf8))
        }
        #expect(throws: FairPlayComponents.Error.componentsPresent) {
            try FairPlayComponents.checkInsertable(Data(#"{"uuid":"\#(Self.uuid)","arkavo:components":[]}"#.utf8))
        }
        // A null member is still a member: the packager never writes over one.
        #expect(throws: FairPlayComponents.Error.componentsPresent) {
            try FairPlayComponents.checkInsertable(Data(#"{"uuid":"\#(Self.uuid)","arkavo:components":null}"#.utf8))
        }
        #expect(throws: FairPlayPolicy.Error.missingUUID) {
            try FairPlayComponents.checkInsertable(Data(#"{"body":{}}"#.utf8))
        }
    }

    @Test("Only video, or video then audio, each with its own 16-byte key")
    func refusesOtherComponentSets() {
        let policy = Data(Self.before.utf8)
        #expect(throws: FairPlayComponents.Error.unsupportedComponents([])) {
            try FairPlayComponents.insert([], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.unsupportedComponents(["audio"])) {
            try FairPlayComponents.insert([Self.audio], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.unsupportedComponents(["audio", "video"])) {
            try FairPlayComponents.insert([Self.audio, Self.video], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.unsupportedComponents(["video", "video"])) {
            try FairPlayComponents.insert([Self.video, Self.video], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.invalidKeySize(.audio)) {
            try FairPlayComponents.insert(
                [Self.video, FairPlayComponentKey(component: .audio, key: Self.audioKey.prefix(15))], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.invalidKeySize(.video)) {
            try FairPlayComponents.insert(
                [FairPlayComponentKey(component: .video, key: Self.videoKey.prefix(15)), Self.audio], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.invalidKeySize(.video)) {
            try FairPlayComponents.insert(
                [FairPlayComponentKey(component: .video, key: Self.videoKey + Data([0x10]))], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.invalidKeySize(.audio)) {
            try FairPlayComponents.insert(
                [Self.video, FairPlayComponentKey(component: .audio, key: Self.audioKey + Self.audioKey)], intoPolicyJSON: policy)
        }
        #expect(throws: FairPlayComponents.Error.sharedKey) {
            try FairPlayComponents.insert(
                [Self.video, FairPlayComponentKey(component: .audio, key: Self.videoKey)], intoPolicyJSON: policy)
        }
    }

    @Test("The manifest has a key access object per component, each wrapping its own key and binding the policy with it")
    func manifest() throws {
        let kas = try TestKASKeyPair()
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
        let iv = Data((0xF0 ... 0xFF).map { UInt8($0) })
        let manifest = try builder.buildManifest(
            componentKeys: [Self.video, Self.audio], iv: iv, policyJSON: Data(Self.before.utf8),
            publicKey: builder.publicKey(fromPEM: kas.spkiPublicKeyPEM))

        let info = manifest.encryptionInformation
        let policy = try #require(info.policy)
        #expect(policy == Data(Self.after.utf8).base64EncodedString())
        #expect(info.method.iv == iv.base64EncodedString())
        #expect(info.keyAccess.count == 2)
        for (access, key) in zip(info.keyAccess, [Self.videoKey, Self.audioKey]) {
            #expect(access.type == "wrapped")
            #expect(access.url == "https://platform.arkavo.net")
            // Independently recompute what the key service checks: unwrap, then HMAC the base64 policy.
            let unwrapped = try TDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: kas.privateKeyPEM, wrappedKey: access.wrappedKey)
            #expect(TDFCrypto.data(from: unwrapped) == key)
            #expect(access.policyBinding?.alg == "HS256")
            #expect(access.policyBinding?.hash == FairPlayPolicy.binding(policyBase64: policy, dek: key))
        }
        #expect(try FairPlayComponents.componentIDs(ofManifestJSON: builder.serializeManifest(manifest)) == ["video", "audio"])
    }

    /// A manifest whose policy is `policy`, as `FairPlayComponents.componentIDs` reads it.
    static func manifestJSON(policy: String) -> Data {
        Data(#"{"encryptionInformation":{"policy":"\#(Data(policy.utf8).base64EncodedString())"}}"#.utf8)
    }

    static let videoEntry = #"{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="}"#
    static let audioEntry = #"{"id":"audio","kind":"audio","keyBinding":"rVO1aH+bdtNnKvDGX38OaorFTRMJsPMGbMJNGKKLU3Q="}"#

    @Test("A profile v1 manifest has no component list, which is nil and not an error")
    func profileV1HasNoComponents() throws {
        let kas = try TestKASKeyPair()
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://platform.arkavo.net")!)
        let manifest = try builder.buildManifest(
            contentKey: Self.videoKey, iv: Data(count: 16), policyJSON: Data(Self.before.utf8),
            publicKey: builder.publicKey(fromPEM: kas.spkiPublicKeyPEM))
        #expect(try FairPlayComponents.componentIDs(ofManifestJSON: builder.serializeManifest(manifest)) == nil)
        #expect(try FairPlayComponents.componentIDs(ofManifestJSON: Self.manifestJSON(policy: Self.before)) == nil)
    }

    @Test("The valid one- and two-component lists give their ids in order")
    func validLists() throws {
        #expect(try FairPlayComponents.componentIDs(ofManifestJSON: Self.manifestJSON(policy: Self.after)) == ["video", "audio"])
        #expect(try FairPlayComponents.componentIDs(ofManifestJSON: Self.manifestJSON(policy: Self.videoOnly)) == ["video"])
    }

    @Test("A present list that is not the v2 shape throws, and is never read as profile v1",
          arguments: [
              // Not a list, or an empty one.
              #"{"arkavo:components":null,"uuid":"u"}"#,
              #"{"arkavo:components":"video","uuid":"u"}"#,
              #"{"arkavo:components":{"id":"video"},"uuid":"u"}"#,
              #"{"arkavo:components":[],"uuid":"u"}"#,
              // Order, set and count: audio first or alone, a repeat, a third entry, an entry that is not an object.
              "{\"arkavo:components\":[\(FairPlayComponentsTests.audioEntry)],\"uuid\":\"u\"}",
              "{\"arkavo:components\":[\(FairPlayComponentsTests.audioEntry),\(FairPlayComponentsTests.videoEntry)],\"uuid\":\"u\"}",
              "{\"arkavo:components\":[\(FairPlayComponentsTests.videoEntry),\(FairPlayComponentsTests.videoEntry)],\"uuid\":\"u\"}",
              "{\"arkavo:components\":[\(FairPlayComponentsTests.videoEntry),\(FairPlayComponentsTests.audioEntry),\(FairPlayComponentsTests.audioEntry)],\"uuid\":\"u\"}",
              "{\"arkavo:components\":[\(FairPlayComponentsTests.videoEntry),\"audio\"],\"uuid\":\"u\"}",
              // Entry members: an id that is not its kind or not video/audio, a missing, extra or mistyped member.
              #"{"arkavo:components":[{"id":"video","kind":"audio","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"main","kind":"main","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video"}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4=","extra":1}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":1,"kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":7}],"uuid":"u"}"#,
              // keyBinding that is not standard base64 of 32 bytes: empty, 31 bytes, 33 bytes, URL-safe alphabet,
              // unpadded, not base64 at all.
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":""}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH_tZ98P5JMMEGIz1C-zwHbchEB4="}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4"}],"uuid":"u"}"#,
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"not base64!"}],"uuid":"u"}"#,
              // Non-canonical: the last character's unused bits set, still decoding to the video binding's 32 bytes.
              #"{"arkavo:components":[{"id":"video","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB5="}],"uuid":"u"}"#,
          ])
    func malformedLists(policy: String) {
        #expect(throws: FairPlayComponents.Error.malformedComponents) {
            try FairPlayComponents.componentIDs(ofManifestJSON: Self.manifestJSON(policy: policy))
        }
    }

    @Test("A manifest or policy that cannot be read throws, and is never read as profile v1")
    func unreadableManifests() {
        let unreadable: [Data] = [
            Data("not json".utf8),
            Data("[]".utf8),
            Data(#"{"payload":{}}"#.utf8),
            Data(#"{"encryptionInformation":{}}"#.utf8),
            Data(#"{"encryptionInformation":{"policy":7}}"#.utf8),
            Data(#"{"encryptionInformation":{"policy":"!!not base64!!"}}"#.utf8),
            Self.manifestJSON(policy: "not json"),
            Self.manifestJSON(policy: "[]"),
        ]
        for json in unreadable {
            #expect(throws: FairPlayComponents.Error.malformedComponents) {
                try FairPlayComponents.componentIDs(ofManifestJSON: json)
            }
        }
    }

    /// JSONSerialization keeps the first of a repeated key and the key service the last, so a repeated member anywhere in
    /// the manifest or its policy would let the two read different component lists.
    @Test("A repeated member in the manifest or its policy throws, and is never read as either list")
    func repeatedMembers() {
        let videoOnly = Data(Self.videoOnly.utf8).base64EncodedString()
        let after = Data(Self.after.utf8).base64EncodedString()
        let repeated: [Data] = [
            // The manifest's policy, twice: the first lists video alone, the second video and audio.
            Data(#"{"encryptionInformation":{"policy":"\#(videoOnly)","policy":"\#(after)"}}"#.utf8),
            // The policy's component list, twice.
            Self.manifestJSON(policy: "{\"arkavo:components\":[\(Self.videoEntry)],\"arkavo:components\":[\(Self.videoEntry),\(Self.audioEntry)],\"uuid\":\"\(Self.uuid)\"}"),
            // A component entry's id, twice.
            Self.manifestJSON(policy: #"{"arkavo:components":[{"id":"video","id":"audio","kind":"video","keyBinding":"9n5YWFmN3MC7g9kJH/tZ98P5JMMEGIz1C+zwHbchEB4="}],"uuid":"u"}"#),
            // Elsewhere in the manifest, outside the policy.
            Data(#"{"encryptionInformation":{"policy":"\#(after)"},"meta":{"a":1,"a":2}}"#.utf8),
        ]
        for json in repeated {
            #expect(throws: FairPlayComponents.Error.malformedComponents) {
                try FairPlayComponents.componentIDs(ofManifestJSON: json)
            }
        }
    }
}
