import Testing
@testable import ArkavoMediaKit
import CryptoKit
import Foundation

@Suite("Integration Tests")
struct IntegrationTests {

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
        do {
            _ = try await sessionManager.getSession(sessionID: session.sessionID)
            Issue.record("Expected SessionError but no error was thrown")
        } catch is SessionError {
            // Expected
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
        try policy.validate(
            session: session,
            firstPlayTimestamp: firstPlay,
            currentActiveStreams: 0,
            deviceInfo: deviceInfo
        )

        // Simulate 3 seconds elapsed (beyond 2-second playback window)
        let expiredFirstPlay = Date(timeIntervalSinceNow: -3)

        // Should fail after playback window expires
        do {
            try policy.validate(
                session: session,
                firstPlayTimestamp: expiredFirstPlay,
                currentActiveStreams: 0,
                deviceInfo: deviceInfo
            )
            Issue.record("Expected PolicyViolation but no error was thrown")
        } catch is PolicyViolation {
            // Expected
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

        do {
            try policy.validate(
                session: session,
                firstPlayTimestamp: nil,
                currentActiveStreams: 0,
                deviceInfo: vmDevice
            )
            Issue.record("Expected PolicyViolation but no error was thrown")
        } catch is PolicyViolation {
            // Expected
        }

        // Physical device should pass
        let physicalDevice = DeviceInfo(
            securityLevel: .medium,
            isVirtualMachine: false
        )

        try policy.validate(
            session: session,
            firstPlayTimestamp: nil,
            currentActiveStreams: 0,
            deviceInfo: physicalDevice
        )
    }

    // TODO: Re-enable when HDCP policy enforcement is implemented
    // @Test("HDCP requirement validation")
    // func testHDCPPolicyEnforcement() async throws { ... }

    @Test("Input validation prevents injection")
    func testInputValidation() async throws {
        // Invalid asset ID (too long)
        let longAssetID = String(repeating: "a", count: 300)
        do {
            try InputValidator.validateAssetID(longAssetID)
            Issue.record("Expected ValidationError but no error was thrown")
        } catch is ValidationError {
            // Expected
        }

        // Invalid asset ID (special characters)
        let specialCharAssetID = "asset-123; DROP TABLE users;"
        do {
            try InputValidator.validateAssetID(specialCharAssetID)
            Issue.record("Expected ValidationError but no error was thrown")
        } catch is ValidationError {
            // Expected
        }

        // Valid asset ID should pass
        try InputValidator.validateAssetID("valid-asset_123")

        // Invalid region code
        do {
            try InputValidator.validateRegionCode("USA") // Should be 2-letter
            Issue.record("Expected ValidationError but no error was thrown")
        } catch is ValidationError {
            // Expected
        }

        // Valid region code should pass
        try InputValidator.validateRegionCode("US")
    }
}
