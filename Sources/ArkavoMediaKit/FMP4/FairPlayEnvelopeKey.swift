import CryptoKit
import Foundation
import Security

/// The license service's envelope key: the RSA public key a `.keyEnvelope` package wraps its DEK to. The service
/// serves it unauthenticated at `<kasURL>/media/v1/envelope-key` as `{"kid", "alg": "RSA-OAEP", "publicKey": <PEM>}`.
/// Only the KSM holds the private key. This is never the platform KAS key: the license service refuses an envelope
/// wrapped to that.
struct FairPlayEnvelopeKey {
    /// The endpoint's path below the KAS server root.
    static let path = "media/v1/envelope-key"
    /// The one wrapping the endpoint may advertise: RSA-OAEP with SHA-1, as `TDFManifestBuilder.wrapKey` does.
    static let algorithm = "RSA-OAEP"
    /// Maximum allowed response size for the envelope key endpoint (64 KiB).
    static let maxResponseBytes = 64 * 1024

    let publicKey: SecKey
    /// The license service picks the unwrapping key by this id: the first 32 lowercase hex characters of SHA-256
    /// over the key's SubjectPublicKeyInfo DER.
    let kid: String

    /// The endpoint for the KAS server root `kasURL`, derived as the KAS public-key URL is.
    static func url(kasURL: URL) -> URL {
        kasURL.appendingPathComponent(path)
    }

    /// Fetches the key from `kasURL`. Requires HTTPS, HTTP 200, bounded response size, `alg` RSA-OAEP,
    /// a valid RSA public key of at least 2048 bits, and a `kid` matching SHA-256(SPKI DER)[0..<32].
    static func fetch(kasURL: URL, http: any FairPlayHTTP) async throws -> FairPlayEnvelopeKey {
        guard InputValidator.isAllowedHTTPSOrLoopbackHTTP(kasURL) else {
            throw FairPlayEnvelopeKeyError.invalidResponse("KAS URL must use HTTPS")
        }
        var request = URLRequest(url: url(kasURL: kasURL))
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        request.cachePolicy = .reloadIgnoringLocalCacheData
        // The license service advertises `alt-svc: h3`, as KAS does.
        request.assumesHTTP3Capable = true
        let (data, response) = try await http.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw FairPlayEnvelopeKeyError.invalidResponse("not an HTTP response")
        }
        guard httpResponse.statusCode == 200 else {
            throw FairPlayEnvelopeKeyError.unexpectedStatus(httpResponse.statusCode)
        }
        guard data.count <= maxResponseBytes else {
            throw FairPlayEnvelopeKeyError.invalidResponse("response exceeds size limit")
        }
        return try parse(data, kasURL: kasURL)
    }

    /// The key in an envelope-key response body from `kasURL`.
    static func parse(_ body: Data, kasURL: URL) throws -> FairPlayEnvelopeKey {
        guard let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else {
            throw FairPlayEnvelopeKeyError.invalidResponse("the body is not a JSON object")
        }
        guard let alg = object["alg"] as? String else { throw FairPlayEnvelopeKeyError.invalidResponse("no alg") }
        guard alg == algorithm else { throw FairPlayEnvelopeKeyError.unsupportedAlgorithm(alg) }
        guard let kid = object["kid"] as? String, !kid.isEmpty else {
            throw FairPlayEnvelopeKeyError.invalidResponse("no kid")
        }
        guard let pem = object["publicKey"] as? String else {
            throw FairPlayEnvelopeKeyError.invalidResponse("no publicKey")
        }
        let key: SecKey
        do {
            key = try TDFManifestBuilder(kasURL: kasURL).publicKey(fromPEM: pem)
        } catch {
            throw FairPlayEnvelopeKeyError.invalidPublicKey(error.localizedDescription)
        }
        // Verify kid matches the first 32 lowercase hex characters of SHA-256 over the key's SPKI DER
        guard let expectedKid = Self.expectedKeyID(for: key), kid == expectedKid else {
            throw FairPlayEnvelopeKeyError.invalidResponse("kid does not match publicKey")
        }
        return FairPlayEnvelopeKey(publicKey: key, kid: kid)
    }

    /// Computes the first 32 lowercase hex characters of SHA-256 over `key`'s SubjectPublicKeyInfo DER.
    static func expectedKeyID(for key: SecKey) -> String? {
        var error: Unmanaged<CFError>?
        guard let pkcs1 = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            _ = error?.takeRetainedValue()
            return nil
        }
        // SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { 0x00, PKCS#1 } }
        let algorithm = Data([0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00])
        let bitString = derElement(tag: 0x03, Data([0x00]) + pkcs1)
        let spki = derElement(tag: 0x30, algorithm + bitString)
        let digest = SHA256.hash(data: spki)
        return String(digest.map { String(format: "%02x", $0) }.joined().prefix(32))
    }

    private static func derElement(tag: UInt8, _ body: Data) -> Data {
        var out = Data([tag])
        if body.count < 0x80 {
            out.append(UInt8(body.count))
        } else {
            var length = body.count
            var bytes: [UInt8] = []
            while length > 0 {
                bytes.insert(UInt8(length & 0xFF), at: 0)
                length >>= 8
            }
            out.append(0x80 | UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        return out + body
    }
}

/// Why `FMP4RecordingProtectionService` could not get the license service's envelope key for `.keyEnvelope`
/// packaging without a caller-supplied key. Packaging stops: it never falls back to the platform KAS key.
public enum FairPlayEnvelopeKeyError: Error, LocalizedError, Equatable {
    /// `media/v1/envelope-key` answered with this status, not 200. 503: the key-envelope profile is turned off.
    case unexpectedStatus(Int)
    /// The response advertises this wrapping algorithm, not RSA-OAEP.
    case unsupportedAlgorithm(String)
    /// The response's `publicKey` is not an RSA public key of at least 2048 bits, for this reason.
    case invalidPublicKey(String)
    /// The response is not an envelope-key object with `kid`, `alg` and `publicKey`, for this reason.
    case invalidResponse(String)

    public var errorDescription: String? {
        switch self {
        case .unexpectedStatus(503):
            "The license service has the key-envelope profile turned off (HTTP 503 from media/v1/envelope-key)"
        case let .unexpectedStatus(status):
            "Fetching the envelope key failed: HTTP \(status) from media/v1/envelope-key"
        case let .unsupportedAlgorithm(alg):
            "The envelope key's algorithm is \(alg); RSA-OAEP is required"
        case let .invalidPublicKey(reason):
            "The envelope key is not a usable RSA public key: \(reason)"
        case let .invalidResponse(reason):
            "The envelope-key response is malformed: \(reason)"
        }
    }
}
