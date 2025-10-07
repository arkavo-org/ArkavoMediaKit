import Testing
@testable import ArkavoMediaKit
import CryptoKit
import Foundation
import OpenTDFKit

@Suite("Integration Tests")
struct IntegrationTests {

    @Test("End-to-end encryption and decryption flow")
    func testE2EEncryptionFlow() async throws {
        // Setup
        let plaintext = Data("Test video segment data".utf8)
        let assetID = "test-asset-123"
        let segmentIndex = 0

        // Generate key
        let symmetricKey = TDF3SegmentKey.generateSegmentKey()

        // Encrypt
        let encryptedSegment = try await TDF3SegmentKey.encryptSegment(
            data: plaintext,
            key: symmetricKey
        )

        #expect(!encryptedSegment.ciphertext.isEmpty)
        #expect(encryptedSegment.nonce.count == CryptoConstants.nonceLengthBytes)
        #expect(encryptedSegment.tag.count == CryptoConstants.aesgcmTagLength)

        // Decrypt
        let decrypted = try await TDF3SegmentKey.decryptSegment(
            encryptedSegment: encryptedSegment,
            key: symmetricKey
        )

        #expect(decrypted == plaintext)
    }

    @Test("Session timeout and cleanup")
    func testSessionTimeoutCleanup() async throws {
        let sessionManager = TDF3MediaSession(heartbeatTimeout: 1.0) // 1 second timeout

        // Create session
        let session = try await sessionManager.startSession(
            userID: "user-timeout",
            assetID: "asset-123"
        )

        // Session should be active initially
        let retrieved = try await sessionManager.getSession(sessionID: session.sessionID)
        #expect(retrieved.sessionID == session.sessionID)

        // Wait for timeout
        try await Task.sleep(for: .seconds(2))

        // Cleanup expired sessions
        let cleaned = await sessionManager.cleanupExpiredSessions()
        #expect(cleaned == 1)

        // Session should no longer exist
        await #expect(throws: SessionError.self) {
            try await sessionManager.getSession(sessionID: session.sessionID)
        }
    }

    @Test("Rental window expiry enforcement")
    func testRentalWindowExpiry() async throws {
        let policy = MediaDRMPolicy(
            rentalWindow: .init(
                purchaseWindow: 100, // 100 seconds purchase window
                playbackWindow: 2     // 2 seconds playback window
            )
        )

        var session = MediaSession(
            userID: "user-rental",
            assetID: "rental-asset"
        )

        // Start playback (sets first play timestamp)
        session.updateHeartbeat(state: .playing)
        let firstPlay = session.firstPlayTimestamp!

        let deviceInfo = DeviceInfo()

        // Should pass immediately after first play
        #expect(throws: Never.self) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: firstPlay,
                currentActiveStreams: 0,
                deviceInfo: deviceInfo
            )
        }

        // Simulate 3 seconds elapsed (beyond 2-second playback window)
        let expiredFirstPlay = Date(timeIntervalSinceNow: -3)

        // Should fail after playback window expires
        #expect(throws: PolicyViolation.self) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: expiredFirstPlay,
                currentActiveStreams: 0,
                deviceInfo: deviceInfo
            )
        }
    }

    @Test("Policy denial for VM detection")
    func testVMDetectionPolicy() async throws {
        let policy = MediaDRMPolicy(
            allowVirtualMachines: false
        )

        let session = MediaSession(
            userID: "user-001",
            assetID: "asset-123"
        )

        // VM device should fail
        let vmDevice = DeviceInfo(
            securityLevel: .medium,
            isVirtualMachine: true
        )

        #expect(throws: PolicyViolation.virtualMachineDetected) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: nil,
                currentActiveStreams: 0,
                deviceInfo: vmDevice
            )
        }

        // Physical device should pass
        let physicalDevice = DeviceInfo(
            securityLevel: .medium,
            isVirtualMachine: false
        )

        #expect(throws: Never.self) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: nil,
                currentActiveStreams: 0,
                deviceInfo: physicalDevice
            )
        }
    }

    @Test("HDCP requirement validation")
    func testHDCPPolicyEnforcement() async throws {
        let policy = MediaDRMPolicy(
            hdcpLevel: .type1,
            minSecurityLevel: .high
        )

        let session = MediaSession(
            userID: "user-hdcp",
            assetID: "4k-movie"
        )

        // Low security device should fail
        let lowSecDevice = DeviceInfo(
            securityLevel: .low,
            isVirtualMachine: false,
            hdcpCapability: .type0
        )

        #expect(throws: PolicyViolation.insufficientDeviceSecurity) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: nil,
                currentActiveStreams: 0,
                deviceInfo: lowSecDevice
            )
        }

        // High security device should pass
        let highSecDevice = DeviceInfo(
            securityLevel: .high,
            isVirtualMachine: false,
            hdcpCapability: .type1
        )

        #expect(throws: Never.self) {
            try policy.validate(
                session: session,
                firstPlayTimestamp: nil,
                currentActiveStreams: 0,
                deviceInfo: highSecDevice
            )
        }
    }

    @Test("Input validation prevents injection")
    func testInputValidation() async throws {
        // Invalid asset ID (too long)
        let longAssetID = String(repeating: "a", count: 300)
        #expect(throws: ValidationError.self) {
            try InputValidator.validateAssetID(longAssetID)
        }

        // Invalid asset ID (special characters)
        let specialCharAssetID = "asset-123; DROP TABLE users;"
        #expect(throws: ValidationError.invalidCharacters(field: "assetID")) {
            try InputValidator.validateAssetID(specialCharAssetID)
        }

        // Valid asset ID should pass
        #expect(throws: Never.self) {
            try InputValidator.validateAssetID("valid-asset_123")
        }

        // Invalid region code
        #expect(throws: ValidationError.invalidRegionCode("USA")) {
            try InputValidator.validateRegionCode("USA") // Should be 2-letter
        }

        // Valid region code should pass
        #expect(throws: Never.self) {
            try InputValidator.validateRegionCode("US")
        }
    }
}
