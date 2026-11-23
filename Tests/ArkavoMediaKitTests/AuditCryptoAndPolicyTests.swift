import CryptoKit
import Foundation
import OpenTDFKit
import Testing
@testable import ArkavoMediaKit

@Suite("Audit: Segment Crypto & MediaDRMPolicy")
struct AuditCryptoAndPolicyTests {
    // MARK: - StandardTDFSegmentCrypto GCM round-trip & integrity

    @Test("StandardTDFSegmentCrypto default GCM mode appends tag, round-trips, and writes authentic integrity metadata")
    func standardTDFSegmentCryptoGCMRoundTripAndIntegrity() async throws {
        let kas = try TestKASKeyPair()
        let policyJSON = Data(#"{"uuid":"22222222-3333-4444-5555-666666666666","body":{"dataAttributes":[],"dissem":[]}}"#.utf8)
        let crypto = try StandardTDFSegmentCrypto(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: kas.spkiPublicKeyPEM,
            policyJSON: policyJSON
        )

        let plaintext = Data("MPEG-TS video segment payload bytes 0123456789".utf8)
        let (tdfData, dek) = try await crypto.encryptSegment(
            segmentData: plaintext,
            segmentIndex: 0,
            assetID: "asset-gcm-1"
        )

        // Decrypt round-trip must succeed and match exact plaintext
        let decrypted = try await crypto.decryptSegment(tdfData: tdfData, symmetricKey: dek)
        #expect(decrypted == plaintext)

        // Inspect manifest integrity metadata: authentic GMAC segment hash + HMAC rootSignature (NOT IV!)
        let reader = try TDFArchiveReader(data: tdfData)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData()
        let integrity = try #require(manifest.encryptionInformation.integrityInformation)
        #expect(integrity.segmentHashAlg == "GMAC")
        #expect(integrity.segments.count == 1)
        #expect(integrity.rootSignature.alg == "HS256")
        #expect(integrity.rootSignature.sig != manifest.encryptionInformation.method.iv, "rootSignature.sig must not be the IV")

        let expectedTag = Data(payload.suffix(16))
        #expect(integrity.segments[0].hash == expectedTag.base64EncodedString())
        #expect(integrity.segments[0].segmentSize == Int64(plaintext.count))
        #expect(integrity.segments[0].encryptedSegmentSize == Int64(payload.count))

        let expectedRootSig = Data(HMAC<SHA256>.authenticationCode(for: expectedTag, using: dek)).base64EncodedString()
        #expect(integrity.rootSignature.sig == expectedRootSig)

        // Tampering with payload ciphertext or tag must fail decryption
        var tamperedPayload = payload
        tamperedPayload[0] ^= 0xFF
        let tamperedTDF = try TDFArchiveWriter().buildArchive(manifest: manifest, payload: tamperedPayload)
        await #expect(throws: (any Error).self) {
            _ = try await crypto.decryptSegment(tdfData: tamperedTDF, symmetricKey: dek)
        }

        // Tampering with rootSignature must fail integrity verification
        var tamperedManifest = manifest
        tamperedManifest.encryptionInformation.integrityInformation?.rootSignature.sig = Data(repeating: 0, count: 32).base64EncodedString()
        let tamperedRootTDF = try TDFArchiveWriter().buildArchive(manifest: tamperedManifest, payload: payload)
        await #expect(throws: StandardTDFSegmentError.integrityVerificationFailed) {
            _ = try await crypto.decryptSegment(tdfData: tamperedRootTDF, symmetricKey: dek)
        }

        // GCM-configured crypto actor must refuse CBC downgrade
        let cbcCrypto = try StandardTDFSegmentCrypto(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: kas.spkiPublicKeyPEM,
            policyJSON: policyJSON,
            mode: .cbc
        )
        let (cbcTDF, cbcKey) = try await cbcCrypto.encryptSegment(
            segmentData: plaintext,
            segmentIndex: 0,
            assetID: "asset-cbc-1"
        )
        // CBC actor decrypts its own CBC segment cleanly
        #expect(try await cbcCrypto.decryptSegment(tdfData: cbcTDF, symmetricKey: cbcKey) == plaintext)
        // GCM actor refuses CBC downgrade
        await #expect(throws: StandardTDFSegmentError.unsupportedEncryptionMethod) {
            _ = try await crypto.decryptSegment(tdfData: cbcTDF, symmetricKey: cbcKey)
        }

        // Stripping policy fails closed
        var strippedPolicyManifest = manifest
        strippedPolicyManifest.encryptionInformation.policy = ""
        let strippedPolicyTDF = try TDFArchiveWriter().buildArchive(manifest: strippedPolicyManifest, payload: payload)
        await #expect(throws: StandardTDFSegmentError.integrityVerificationFailed) {
            _ = try await crypto.decryptSegment(tdfData: strippedPolicyTDF, symmetricKey: dek)
        }

        // Legacy hex-form policyBinding (OpenTDFKit <= 4) still verifies cleanly
        let rawHmac = Data(HMAC<SHA256>.authenticationCode(
            for: Data(manifest.encryptionInformation.policy.utf8),
            using: dek
        ))
        let hexBindingHash = Data(rawHmac.map { String(format: "%02x", $0) }.joined().utf8).base64EncodedString()
        var legacyManifest = manifest
        legacyManifest.encryptionInformation.keyAccess[0].policyBinding = TDFPolicyBinding(
            alg: "HS256",
            hash: hexBindingHash
        )
        let legacyTDF = try TDFArchiveWriter().buildArchive(manifest: legacyManifest, payload: payload)
        #expect(try await crypto.decryptSegment(tdfData: legacyTDF, symmetricKey: dek) == plaintext)

        // Stripping integrityInformation in CBC mode fails closed
        let cbcReader = try TDFArchiveReader(data: cbcTDF)
        var strippedCBCManifest = try cbcReader.manifest()
        let cbcPayload = try cbcReader.payloadData()
        strippedCBCManifest.encryptionInformation.integrityInformation = nil
        let strippedCBCTDF = try TDFArchiveWriter().buildArchive(manifest: strippedCBCManifest, payload: cbcPayload)
        await #expect(throws: StandardTDFSegmentError.integrityVerificationFailed) {
            _ = try await cbcCrypto.decryptSegment(tdfData: strippedCBCTDF, symmetricKey: cbcKey)
        }
    }

    // MARK: - MediaDRMPolicy ranked levels, fail-closed geo, concurrency boundary, rental & subscription

    @Test("MediaDRMPolicy compares DeviceSecurityLevel and HDCPLevel by numeric rank, not lexicographically")
    func rankedSecurityAndHDCPLevels() throws {
        #expect(MediaDRMPolicy.DeviceSecurityLevel.low < .medium)
        #expect(MediaDRMPolicy.DeviceSecurityLevel.medium < .high)
        #expect(!(MediaDRMPolicy.DeviceSecurityLevel.high < .low))

        #expect(MediaDRMPolicy.HDCPLevel.none < .type0)
        #expect(MediaDRMPolicy.HDCPLevel.type0 < .type1)

        let session = MediaSession(userID: "user-1", assetID: "asset-1")

        // Requiring .high rejects .low and .medium, allows .high
        let highPolicy = MediaDRMPolicy(minSecurityLevel: .high)
        #expect(throws: PolicyViolation.insufficientDeviceSecurity) {
            try highPolicy.validate(
                session: session, firstPlayTimestamp: nil, currentActiveStreams: 1,
                deviceInfo: DeviceInfo(securityLevel: .low)
            )
        }
        #expect(throws: PolicyViolation.insufficientDeviceSecurity) {
            try highPolicy.validate(
                session: session, firstPlayTimestamp: nil, currentActiveStreams: 1,
                deviceInfo: DeviceInfo(securityLevel: .medium)
            )
        }
        try highPolicy.validate(
            session: session, firstPlayTimestamp: nil, currentActiveStreams: 1,
            deviceInfo: DeviceInfo(securityLevel: .high)
        )

        // Requiring .low allows .high (previously failed because "high" < "low"!)
        let lowPolicy = MediaDRMPolicy(minSecurityLevel: .low)
        try lowPolicy.validate(
            session: session, firstPlayTimestamp: nil, currentActiveStreams: 1,
            deviceInfo: DeviceInfo(securityLevel: .high)
        )

        // HDCP enforcement
        let hdcpPolicy = MediaDRMPolicy(hdcpLevel: .type1)
        #expect(throws: PolicyViolation.insufficientHDCP(required: .type1)) {
            try hdcpPolicy.validate(
                session: session, firstPlayTimestamp: nil, currentActiveStreams: 1,
                deviceInfo: DeviceInfo(hdcpCapability: .type0)
            )
        }
        try hdcpPolicy.validate(
            session: session, firstPlayTimestamp: nil, currentActiveStreams: 1,
            deviceInfo: DeviceInfo(hdcpCapability: .type1)
        )
    }

    @Test("MediaDRMPolicy geo allowlist and blocklist fail closed when geoRegion is nil")
    func geoAllowlistFailClosed() {
        let nilRegionSession = MediaSession(userID: "u1", assetID: "a1", geoRegion: nil)
        let allowPolicy = MediaDRMPolicy(allowedRegions: ["US"])
        #expect(throws: PolicyViolation.geoRestricted(region: "unknown")) {
            try allowPolicy.validate(
                session: nilRegionSession, firstPlayTimestamp: nil, currentActiveStreams: 1,
                deviceInfo: DeviceInfo()
            )
        }

        let blockPolicy = MediaDRMPolicy(blockedRegions: ["KP"])
        #expect(throws: PolicyViolation.geoRestricted(region: "unknown")) {
            try blockPolicy.validate(
                session: nilRegionSession, firstPlayTimestamp: nil, currentActiveStreams: 1,
                deviceInfo: DeviceInfo()
            )
        }
    }

    @Test("MediaDRMPolicy concurrency limit allows currentActiveStreams == maxConcurrentStreams and rejects > max")
    func concurrencyLimitBoundary() throws {
        let session = MediaSession(userID: "u1", assetID: "a1")
        let singleStreamPolicy = MediaDRMPolicy(maxConcurrentStreams: 1)

        // Single-stream user with 1 active stream (their own session) must be allowed
        try singleStreamPolicy.validate(
            session: session, firstPlayTimestamp: nil, currentActiveStreams: 1,
            deviceInfo: DeviceInfo()
        )
        // 2 active streams exceeds limit of 1
        #expect(throws: PolicyViolation.concurrencyLimitExceeded) {
            try singleStreamPolicy.validate(
                session: session, firstPlayTimestamp: nil, currentActiveStreams: 2,
                deviceInfo: DeviceInfo()
            )
        }
        // maxConcurrentStreams == 0 always rejects
        let zeroPolicy = MediaDRMPolicy(maxConcurrentStreams: 0)
        #expect(throws: PolicyViolation.concurrencyLimitExceeded) {
            try zeroPolicy.validate(
                session: session, firstPlayTimestamp: nil, currentActiveStreams: 0,
                deviceInfo: DeviceInfo()
            )
        }
    }

    @Test("MediaDRMPolicy enforces purchaseWindow and requiredSubscriptionTier")
    func purchaseWindowAndSubscriptionTier() throws {
        let formatter = ISO8601DateFormatter()
        let expiredPurchase = formatter.string(from: Date(timeIntervalSinceNow: -200))
        let sessionExpiredPurchase = MediaSession(
            userID: "u1", assetID: "a1",
            metadata: ["purchasedAt": expiredPurchase, "subscriptionTier": "premium"]
        )
        let rentalPolicy = MediaDRMPolicy(
            rentalWindow: .init(purchaseWindow: 60, playbackWindow: 3600),
            requiredSubscriptionTier: "premium"
        )
        #expect(throws: PolicyViolation.rentalWindowExpired) {
            try rentalPolicy.validate(
                session: sessionExpiredPurchase, firstPlayTimestamp: nil, currentActiveStreams: 1,
                deviceInfo: DeviceInfo()
            )
        }

        // Malformed purchasedAt metadata must fail closed instead of falling back to session.createdAt
        for malformedDate in ["not-a-date", "", "2026-99-99T00:00:00Z"] {
            let malformedSession = MediaSession(
                userID: "u1", assetID: "a1",
                metadata: ["purchasedAt": malformedDate, "subscriptionTier": "premium"]
            )
            #expect(throws: PolicyViolation.rentalWindowExpired) {
                try rentalPolicy.validate(
                    session: malformedSession, firstPlayTimestamp: nil, currentActiveStreams: 1,
                    deviceInfo: DeviceInfo()
                )
            }
        }

        // Valid fractional-seconds ISO8601 purchasedAt within purchaseWindow passes
        let fractionalFormatter = ISO8601DateFormatter()
        fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let recentPurchase = fractionalFormatter.string(from: Date(timeIntervalSinceNow: -5))
        let validFractionalSession = MediaSession(
            userID: "u1", assetID: "a1",
            metadata: ["purchasedAt": recentPurchase, "subscriptionTier": "premium"]
        )
        try rentalPolicy.validate(
            session: validFractionalSession, firstPlayTimestamp: nil, currentActiveStreams: 1,
            deviceInfo: DeviceInfo()
        )

        let wrongTierSession = MediaSession(userID: "u1", assetID: "a1", metadata: ["subscriptionTier": "basic"])
        let tierPolicy = MediaDRMPolicy(requiredSubscriptionTier: "premium")
        #expect(throws: PolicyViolation.subscriptionRequired(tier: "premium")) {
            try tierPolicy.validate(
                session: wrongTierSession, firstPlayTimestamp: nil, currentActiveStreams: 1,
                deviceInfo: DeviceInfo()
            )
        }
        let okSession = MediaSession(userID: "u1", assetID: "a1", metadata: ["subscriptionTier": "premium"])
        try tierPolicy.validate(
            session: okSession, firstPlayTimestamp: nil, currentActiveStreams: 1,
            deviceInfo: DeviceInfo()
        )
    }

    // MARK: - TDF3MediaSession expiry & ended state

    @Test("TDF3MediaSession prunes expired sessions before concurrency checks, refuses reviving expired sessions, and ends on .ended heartbeat")
    func sessionLifecycleHardening() async throws {
        let manager = TDF3MediaSession(heartbeatTimeout: 0.05)
        let policy = MediaDRMPolicy(maxConcurrentStreams: 1)

        let s1 = try await manager.startSession(userID: "alice", assetID: "a1", policy: policy)
        try await Task.sleep(for: .milliseconds(80))

        // Expired session must not be revived by updateHeartbeat
        await #expect(throws: SessionError.self) {
            try await manager.updateHeartbeat(sessionID: s1.sessionID, state: .playing)
        }

        // Expired session must not block starting a new session under maxConcurrentStreams: 1
        let s2 = try await manager.startSession(userID: "alice", assetID: "a2", policy: policy)
        #expect(await manager.getActiveStreamCount(userID: "alice") == 1)

        // Updating heartbeat with .ended removes the session from active streams
        try await manager.updateHeartbeat(sessionID: s2.sessionID, state: .ended)
        #expect(await manager.getActiveStreamCount(userID: "alice") == 0)
    }
}
