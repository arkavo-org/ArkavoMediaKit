import Testing
@testable import ArkavoMediaKit
import CryptoKit
import Foundation
import OpenTDFKit

@Suite("ArkavoMediaKit Tests")
struct ArkavoMediaKitTests {

    @Test("MediaSession creation and heartbeat")
    func testMediaSessionCreation() async throws {
        var session = MediaSession(
            userID: "user-001",
            assetID: "asset-123"
        )

        #expect(session.userID == "user-001")
        #expect(session.assetID == "asset-123")
        #expect(session.state == .idle)
        #expect(session.firstPlayTimestamp == nil)

        session.updateHeartbeat(state: .playing)
        #expect(session.state == .playing)
        #expect(session.firstPlayTimestamp != nil)
    }

    @Test("TDF3MediaSession concurrency limits")
    func testSessionConcurrencyLimits() async throws {
        let sessionManager = TDF3MediaSession()
        let policy = MediaDRMPolicy(maxConcurrentStreams: 2)

        // Create first session
        let session1 = try await sessionManager.startSession(
            userID: "user-001",
            assetID: "asset-1",
            policy: policy
        )
        #expect(session1.userID == "user-001")

        // Create second session
        let session2 = try await sessionManager.startSession(
            userID: "user-001",
            assetID: "asset-2",
            policy: policy
        )
        #expect(session2.userID == "user-001")

        // Third session should fail due to concurrency limit
        await #expect(throws: SessionError.self) {
            try await sessionManager.startSession(
                userID: "user-001",
                assetID: "asset-3",
                policy: policy
            )
        }

        // End first session
        try await sessionManager.endSession(sessionID: session1.sessionID)

        // Now third session should succeed
        let session3 = try await sessionManager.startSession(
            userID: "user-001",
            assetID: "asset-3",
            policy: policy
        )
        #expect(session3.userID == "user-001")
    }

    @Test("MediaDRMPolicy geo-restriction validation")
    func testPolicyGeoRestriction() async throws {
        let policy = MediaDRMPolicy(
            allowedRegions: ["US", "CA"]
        )

        let deviceInfo = DeviceInfo()

        // US region should pass
        var session = MediaSession(
            userID: "user-001",
            assetID: "asset-123",
            geoRegion: "US"
        )

        #expect(throws: Never.self) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: nil,
                currentActiveStreams: 0,
                deviceInfo: deviceInfo
            )
        }

        // GB region should fail
        session = MediaSession(
            userID: "user-001",
            assetID: "asset-123",
            geoRegion: "GB"
        )

        #expect(throws: PolicyViolation.self) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: nil,
                currentActiveStreams: 0,
                deviceInfo: deviceInfo
            )
        }
    }

    @Test("TDF3SegmentKey encryption/decryption")
    func testSegmentEncryption() async throws {
        let plaintext = Data("Test segment data".utf8)
        let key = TDF3SegmentKey.generateSegmentKey()

        // Encrypt
        let encrypted = try await TDF3SegmentKey.encryptSegment(
            data: plaintext,
            key: key
        )

        #expect(!encrypted.ciphertext.isEmpty)
        #expect(!encrypted.nonce.isEmpty)
        #expect(!encrypted.tag.isEmpty)

        // Decrypt
        let decrypted = try await TDF3SegmentKey.decryptSegment(
            encryptedSegment: encrypted,
            key: key
        )

        #expect(decrypted == plaintext)
    }

    @Test("HLSPlaylistGenerator master playlist")
    func testMasterPlaylistGeneration() {
        let generator = HLSPlaylistGenerator(
            kasBaseURL: URL(string: "https://kas.example.com")!,
            cdnBaseURL: URL(string: "https://cdn.example.com")!
        )

        let variants = [
            PlaylistVariant(
                bandwidth: 1_000_000,
                resolution: "640x360",
                playlistURL: URL(string: "https://cdn.example.com/low.m3u8")!
            ),
            PlaylistVariant(
                bandwidth: 5_000_000,
                resolution: "1920x1080",
                playlistURL: URL(string: "https://cdn.example.com/high.m3u8")!
            )
        ]

        let playlist = generator.generateMasterPlaylist(variants: variants)

        #expect(playlist.contains("#EXTM3U"))
        #expect(playlist.contains("#EXT-X-VERSION:6"))
        #expect(playlist.contains("BANDWIDTH=1000000"))
        #expect(playlist.contains("RESOLUTION=640x360"))
        #expect(playlist.contains("low.m3u8"))
    }

    @Test("SegmentMetadata creation")
    func testSegmentMetadata() {
        let metadata = SegmentMetadata(
            index: 0,
            duration: 10.0,
            url: URL(string: "https://cdn.example.com/segment_0.ts")!,
            nanoTDFHeader: "base64header",
            iv: Data(repeating: 0, count: 12),
            assetID: "asset-123"
        )

        #expect(metadata.index == 0)
        #expect(metadata.duration == 10.0)
        #expect(metadata.assetID == "asset-123")
    }
}
