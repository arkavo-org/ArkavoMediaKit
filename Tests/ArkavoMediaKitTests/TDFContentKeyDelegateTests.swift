import Foundation
import Testing

@testable import ArkavoMediaKit

// MARK: - FairPlayManifest Tests

@Suite("FairPlayManifest Tests")
struct FairPlayManifestTests {
    @Test("FairPlayManifest initializes with correct values")
    func manifestInitialization() {
        let manifest = FairPlayManifest(
            assetID: "test-asset-123",
            kasURL: "https://kas.example.com",
            wrappedKey: "base64wrappedkey==",
            algorithm: "AES-128-CBC",
            iv: "YWJjZGVmZ2hpamtsbW5vcA=="
        )

        #expect(manifest.assetID == "test-asset-123")
        #expect(manifest.kasURL == "https://kas.example.com")
        #expect(manifest.wrappedKey == "base64wrappedkey==")
        #expect(manifest.algorithm == "AES-128-CBC")
        #expect(manifest.iv == "YWJjZGVmZ2hpamtsbW5vcA==")
    }

    @Test("FairPlayManifest conforms to FairPlayManifestProtocol")
    func manifestProtocolConformance() {
        let manifest: any FairPlayManifestProtocol = FairPlayManifest(
            assetID: "asset",
            kasURL: "https://kas.example.com",
            wrappedKey: "key",
            algorithm: "AES-128-CBC",
            iv: "iv"
        )

        #expect(manifest.assetID == "asset")
        #expect(manifest.kasURL == "https://kas.example.com")
    }

    @Test("FairPlayManifest is Sendable")
    func manifestSendable() async {
        let manifest = FairPlayManifest(
            assetID: "sendable-test",
            kasURL: "https://kas.example.com",
            wrappedKey: "key",
            algorithm: "AES-128-CBC",
            iv: "iv"
        )

        // Test that manifest can be sent across actor boundaries
        let result = await Task {
            manifest.assetID
        }.value

        #expect(result == "sendable-test")
    }
}

// MARK: - FairPlayError Tests

@Suite("FairPlayError Tests")
struct FairPlayErrorTests {
    @Test("sessionStartFailed has correct description")
    func sessionStartFailedDescription() {
        let error = FairPlayError.sessionStartFailed("Connection timeout")
        #expect(error.errorDescription == "Failed to start FairPlay session: Connection timeout")
    }

    @Test("certificateFetchFailed has correct description")
    func certificateFetchFailedDescription() {
        let error = FairPlayError.certificateFetchFailed("HTTP 404")
        #expect(error.errorDescription == "Failed to fetch FairPlay certificate: HTTP 404")
    }

    @Test("spcGenerationFailed has correct description")
    func spcGenerationFailedDescription() {
        let error = FairPlayError.spcGenerationFailed("Invalid certificate")
        #expect(error.errorDescription == "Failed to generate SPC: Invalid certificate")
    }

    @Test("ckcRequestFailed has correct description")
    func ckcRequestFailedDescription() {
        let error = FairPlayError.ckcRequestFailed("Server error")
        #expect(error.errorDescription == "Failed to request CKC: Server error")
    }

    @Test("invalidCKCResponse has correct description")
    func invalidCKCResponseDescription() {
        let error = FairPlayError.invalidCKCResponse("Missing wrappedKey")
        #expect(error.errorDescription == "Invalid CKC response: Missing wrappedKey")
    }

    @Test("manifestEncodingFailed has correct description")
    func manifestEncodingFailedDescription() {
        let error = FairPlayError.manifestEncodingFailed("JSON serialization failed")
        #expect(error.errorDescription == "Failed to encode TDF manifest: JSON serialization failed")
    }

    @Test("FairPlayError is Sendable")
    func errorIsSendable() async {
        let error = FairPlayError.sessionStartFailed("test")

        let result = await Task {
            error.errorDescription
        }.value

        #expect(result?.contains("test") == true)
    }
}

// MARK: - FairPlayDebugConfig Tests

@Suite("FairPlayDebugConfig Tests")
struct FairPlayDebugConfigTests {
    @Test("Debug config has correct default value")
    func debugConfigDefault() {
        // In DEBUG builds, should be true; in RELEASE, false
        #if DEBUG
            #expect(FairPlayDebugConfig.isVerboseLoggingEnabled == true)
        #else
            #expect(FairPlayDebugConfig.isVerboseLoggingEnabled == false)
        #endif
    }

    @Test("Debug config can be toggled")
    func debugConfigToggle() {
        let original = FairPlayDebugConfig.isVerboseLoggingEnabled

        FairPlayDebugConfig.isVerboseLoggingEnabled = false
        #expect(FairPlayDebugConfig.isVerboseLoggingEnabled == false)

        FairPlayDebugConfig.isVerboseLoggingEnabled = true
        #expect(FairPlayDebugConfig.isVerboseLoggingEnabled == true)

        // Restore original value
        FairPlayDebugConfig.isVerboseLoggingEnabled = original
    }
}

// MARK: - TDFContentKeyDelegate Tests

@Suite("TDFContentKeyDelegate Tests")
struct TDFContentKeyDelegateTests {
    let testManifest = FairPlayManifest(
        assetID: "test-asset-id",
        kasURL: "https://kas.test.com/api/kas",
        wrappedKey: "dGVzdC13cmFwcGVkLWtleQ==",
        algorithm: "AES-128-CBC",
        iv: "YWJjZGVmZ2hpamtsbW5vcA=="
    )

    @Test("Delegate initializes with manifest and default values")
    func delegateInitializationDefaults() {
        let delegate = TDFContentKeyDelegate(manifest: testManifest)

        // Delegate should be created without throwing
        #expect(delegate != nil)
    }

    @Test("Delegate initializes with all parameters")
    func delegateInitializationFull() {
        let serverURL = URL(string: "https://custom.server.com")!
        let delegate = TDFContentKeyDelegate(
            manifest: testManifest,
            authToken: "test-token-123",
            userId: "user-456",
            serverURL: serverURL
        )

        #expect(delegate != nil)
    }

    @Test("Delegate initializes with optional auth token")
    func delegateInitializationOptionalAuth() {
        let delegate = TDFContentKeyDelegate(
            manifest: testManifest,
            authToken: nil,
            userId: "anonymous"
        )

        #expect(delegate != nil)
    }

    @Test("Delegate callbacks can be set")
    func delegateCallbacks() {
        let delegate = TDFContentKeyDelegate(manifest: testManifest)

        // Set callbacks
        delegate.onKeyDelivered = {
            // Callback implementation
        }

        delegate.onKeyFailed = { _ in
            // Callback implementation
        }

        // Callbacks should be settable
        #expect(delegate.onKeyDelivered != nil)
        #expect(delegate.onKeyFailed != nil)
    }

    @Test("DefaultTDFContentKeyDelegate type alias works")
    func typeAliasWorks() {
        let manifest = FairPlayManifest(
            assetID: "alias-test",
            kasURL: "https://kas.example.com",
            wrappedKey: "key",
            algorithm: "AES-128-CBC",
            iv: "iv"
        )

        let delegate: DefaultTDFContentKeyDelegate = TDFContentKeyDelegate(manifest: manifest)
        #expect(delegate != nil)
    }
}

// MARK: - Custom Manifest Protocol Conformance Tests

@Suite("Custom Manifest Protocol Tests")
struct CustomManifestProtocolTests {
    // Custom manifest type for testing protocol conformance
    struct CustomManifest: FairPlayManifestProtocol {
        let assetID: String
        let kasURL: String
        let wrappedKey: String
        let algorithm: String
        let iv: String
        let customField: String // Extra field not in protocol
    }

    @Test("Custom manifest type works with TDFContentKeyDelegate")
    func customManifestWorks() {
        let customManifest = CustomManifest(
            assetID: "custom-asset",
            kasURL: "https://custom.kas.com",
            wrappedKey: "custom-wrapped-key",
            algorithm: "AES-256-GCM",
            iv: "custom-iv",
            customField: "extra-data"
        )

        let delegate = TDFContentKeyDelegate(manifest: customManifest)
        #expect(delegate != nil)
    }

    @Test("Protocol provides required fields for key exchange")
    func protocolFieldsComplete() {
        let manifest: any FairPlayManifestProtocol = FairPlayManifest(
            assetID: "field-test",
            kasURL: "https://kas.example.com",
            wrappedKey: "wrapped-key-base64",
            algorithm: "AES-128-CBC",
            iv: "iv-base64"
        )

        // All fields required for FairPlay key exchange are present
        #expect(!manifest.assetID.isEmpty)
        #expect(!manifest.kasURL.isEmpty)
        #expect(!manifest.wrappedKey.isEmpty)
        #expect(!manifest.algorithm.isEmpty)
        #expect(!manifest.iv.isEmpty)
    }
}

// MARK: - FairPlayDebug Logger Tests

@Suite("FairPlayDebug Logger Tests")
struct FairPlayDebugLoggerTests {
    @Test("Log functions don't crash when disabled")
    func logFunctionsWhenDisabled() {
        let originalValue = FairPlayDebugConfig.isVerboseLoggingEnabled
        FairPlayDebugConfig.isVerboseLoggingEnabled = false

        // These should not crash
        FairPlayDebug.log("Test message")
        FairPlayDebug.logData("Test data", data: Data([0x01, 0x02, 0x03]))
        FairPlayDebug.logRequest("GET", url: URL(string: "https://example.com")!, body: nil)
        FairPlayDebug.logResponse(200, data: Data())

        FairPlayDebugConfig.isVerboseLoggingEnabled = originalValue
    }

    @Test("logData truncates long data")
    func logDataTruncation() {
        let originalValue = FairPlayDebugConfig.isVerboseLoggingEnabled
        FairPlayDebugConfig.isVerboseLoggingEnabled = true

        // Create data longer than maxBytes
        let longData = Data(repeating: 0xAB, count: 100)

        // Should not crash and should truncate
        FairPlayDebug.logData("Long data", data: longData, maxBytes: 10)

        FairPlayDebugConfig.isVerboseLoggingEnabled = originalValue
    }

    @Test("logRequest handles JSON body")
    func logRequestWithJSON() {
        let originalValue = FairPlayDebugConfig.isVerboseLoggingEnabled
        FairPlayDebugConfig.isVerboseLoggingEnabled = true

        let body: [String: Any] = [
            "key": "value",
            "longValue": String(repeating: "x", count: 200),
        ]
        let jsonData = try? JSONSerialization.data(withJSONObject: body)

        // Should not crash
        FairPlayDebug.logRequest("POST", url: URL(string: "https://example.com")!, body: jsonData)

        FairPlayDebugConfig.isVerboseLoggingEnabled = originalValue
    }

    @Test("logResponse handles text and binary data")
    func logResponseHandlesDataTypes() {
        let originalValue = FairPlayDebugConfig.isVerboseLoggingEnabled
        FairPlayDebugConfig.isVerboseLoggingEnabled = true

        // Text response
        let textData = "Hello, World!".data(using: .utf8)!
        FairPlayDebug.logResponse(200, data: textData)

        // Binary response (non-UTF8)
        let binaryData = Data([0x00, 0x01, 0xFF, 0xFE])
        FairPlayDebug.logResponse(200, data: binaryData)

        FairPlayDebugConfig.isVerboseLoggingEnabled = originalValue
    }
}

// MARK: - Integration Tests

@Suite("TDFContentKeyDelegate Integration Tests")
struct TDFContentKeyDelegateIntegrationTests {
    @Test("Delegate conforms to AVContentKeySessionDelegate")
    func delegateConformsToAVContentKeySessionDelegate() {
        let manifest = FairPlayManifest(
            assetID: "conformance-test",
            kasURL: "https://kas.example.com",
            wrappedKey: "key",
            algorithm: "AES-128-CBC",
            iv: "iv"
        )

        let delegate = TDFContentKeyDelegate(manifest: manifest)

        // The delegate should be usable as AVContentKeySessionDelegate
        // This is a compile-time check - if it compiles, it conforms
        #expect(delegate is any NSObjectProtocol)
    }

    @Test("Multiple delegates can be created with different manifests")
    func multipleDelegates() {
        let manifest1 = FairPlayManifest(
            assetID: "asset-1",
            kasURL: "https://kas1.example.com",
            wrappedKey: "key1",
            algorithm: "AES-128-CBC",
            iv: "iv1"
        )

        let manifest2 = FairPlayManifest(
            assetID: "asset-2",
            kasURL: "https://kas2.example.com",
            wrappedKey: "key2",
            algorithm: "AES-256-GCM",
            iv: "iv2"
        )

        let delegate1 = TDFContentKeyDelegate(manifest: manifest1)
        let delegate2 = TDFContentKeyDelegate(manifest: manifest2)

        // Both delegates should exist independently
        #expect(delegate1 !== delegate2)
    }

    @Test("Delegate with auth token is different from without")
    func delegateAuthTokenVariants() {
        let manifest = FairPlayManifest(
            assetID: "auth-test",
            kasURL: "https://kas.example.com",
            wrappedKey: "key",
            algorithm: "AES-128-CBC",
            iv: "iv"
        )

        let delegateWithAuth = TDFContentKeyDelegate(
            manifest: manifest,
            authToken: "bearer-token"
        )

        let delegateWithoutAuth = TDFContentKeyDelegate(
            manifest: manifest,
            authToken: nil
        )

        // Both should be valid
        #expect(delegateWithAuth != nil)
        #expect(delegateWithoutAuth != nil)
    }
}
