import XCTest
@testable import ArkavoMediaKit

final class DRMMediaPlayerTests: XCTestCase {

    func testDRMConfigurationRequiresCertificate() throws {
        // Test that configuration requires certificate
        let testCert = Data([0x01, 0x02, 0x03, 0x04])
        let serverURL = URL(string: "https://test.arkavo.net")!

        let config = try DRMConfiguration(
            serverURL: serverURL,
            fpsCertificateData: testCert
        )

        XCTAssertFalse(config.fpsCertificate.isEmpty, "FPS certificate should not be empty")
        XCTAssertEqual(config.serverURL.absoluteString, "https://test.arkavo.net")
        XCTAssertEqual(config.heartbeatInterval, 30)
        XCTAssertEqual(config.sessionTimeout, 300)
    }

    func testDRMConfigurationCustom() throws {
        // Test custom configuration
        let customCert = Data([0x01, 0x02, 0x03, 0x04])
        let customURL = URL(string: "https://custom.server.com")!

        let config = try DRMConfiguration(
            serverURL: customURL,
            fpsCertificateData: customCert,
            heartbeatInterval: 60,
            sessionTimeout: 600
        )

        XCTAssertEqual(config.fpsCertificate, customCert)
        XCTAssertEqual(config.serverURL, customURL)
        XCTAssertEqual(config.heartbeatInterval, 60)
        XCTAssertEqual(config.sessionTimeout, 600)
    }

    func testSessionStartResponse() throws {
        // Test SessionStartResponse decoding
        let json = """
        {
            "sessionId": "test-session-123",
            "status": "active"
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(SessionStartResponse.self, from: data)

        XCTAssertEqual(response.sessionId, "test-session-123")
        XCTAssertEqual(response.status, "active")
    }

    func testKeyRequestResponse() throws {
        // Test KeyRequestResponse decoding and CKC extraction
        let testCKC = Data([0x01, 0x02, 0x03, 0x04])
        let base64CKC = testCKC.base64EncodedString()

        let json = """
        {
            "ckcData": "\(base64CKC)"
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let response = try decoder.decode(KeyRequestResponse.self, from: data)

        let decodedCKC = try response.decodedCKC()
        XCTAssertEqual(decodedCKC, testCKC)
    }

    func testKeyRequestBody() throws {
        // Test KeyRequestBody encoding
        let spcData = Data([0x10, 0x20, 0x30, 0x40])
        let body = KeyRequestBody(
            sessionId: "session-123",
            spcData: spcData,
            assetId: "asset-456"
        )

        let encoder = JSONEncoder()
        let data = try encoder.encode(body)

        let decoder = JSONDecoder()
        let decoded = try decoder.decode(KeyRequestBody.self, from: data)

        XCTAssertEqual(decoded.sessionId, "session-123")
        XCTAssertEqual(decoded.spcData, spcData.base64EncodedString())
        XCTAssertEqual(decoded.assetId, "asset-456")
    }

    func testHTTPSOnlyEnforcement() throws {
        // Test that only HTTPS URLs are allowed for server
        let testCert = Data([0x01, 0x02, 0x03, 0x04])

        // HTTPS should work
        XCTAssertNoThrow(try DRMConfiguration(
            serverURL: URL(string: "https://secure.server.com")!,
            fpsCertificateData: testCert
        ))

        // HTTP should throw
        XCTAssertThrowsError(try DRMConfiguration(
            serverURL: URL(string: "http://insecure.server.com")!,
            fpsCertificateData: testCert
        ))
    }

    func testEmptyCertificateRejected() throws {
        // Test that empty certificate is rejected
        XCTAssertThrowsError(try DRMConfiguration(
            serverURL: URL(string: "https://test.server.com")!,
            fpsCertificateData: Data()
        ))
    }

    func testInputValidation() throws {
        // Test user ID validation
        XCTAssertNoThrow(try InputValidator.validateUserID("user123"))
        XCTAssertNoThrow(try InputValidator.validateUserID("user@example.com"))
        XCTAssertThrowsError(try InputValidator.validateUserID(""))
        XCTAssertThrowsError(try InputValidator.validateUserID("user with spaces"))

        // Test asset ID validation
        XCTAssertNoThrow(try InputValidator.validateAssetID("asset123"))
        XCTAssertNoThrow(try InputValidator.validateAssetID("asset-456_test"))
        XCTAssertThrowsError(try InputValidator.validateAssetID(""))

        // Test region code validation
        XCTAssertNoThrow(try InputValidator.validateRegionCode("US"))
        XCTAssertNoThrow(try InputValidator.validateRegionCode("GB"))
        XCTAssertThrowsError(try InputValidator.validateRegionCode("usa"))
        XCTAssertThrowsError(try InputValidator.validateRegionCode("U"))
    }

    func testDRMPlayerInitialization() throws {
        // Test player initialization with required config
        let testCert = Data([0x01, 0x02, 0x03, 0x04])
        let config = try DRMConfiguration(
            serverURL: URL(string: "https://test.arkavo.net")!,
            fpsCertificateData: testCert
        )
        let player = DRMMediaPlayer(configuration: config)

        XCTAssertNil(player.player)
        XCTAssertNil(player.sessionId)
        XCTAssertNil(player.error)

        // Use pattern matching for state comparison
        if case .idle = player.state {
            // Pass
        } else {
            XCTFail("Expected idle state")
        }
    }

    func testDRMPlayerCustomConfiguration() throws {
        // Test player with custom configuration
        let customCert = Data([0x01, 0x02, 0x03, 0x04])
        let config = try DRMConfiguration(
            serverURL: URL(string: "https://custom.server.com")!,
            fpsCertificateData: customCert,
            heartbeatInterval: 60,
            sessionTimeout: 600
        )
        let player = DRMMediaPlayer(configuration: config)

        XCTAssertNil(player.player)

        // Use pattern matching for state comparison
        if case .idle = player.state {
            // Pass
        } else {
            XCTFail("Expected idle state")
        }
    }

    // Note: Integration tests with actual server would require:
    // - Mock server for /media/v1/session/start
    // - Mock server for /media/v1/key-request
    // - Test HLS streams with FairPlay encryption
}
