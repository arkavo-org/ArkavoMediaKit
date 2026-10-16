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

    let publicKey: SecKey
    /// The license service picks the unwrapping key by this id: the first 32 lowercase hex characters of SHA-256
    /// over the key's SubjectPublicKeyInfo DER.
    let kid: String

    /// The endpoint for the KAS server root `kasURL`, derived as the KAS public-key URL is.
    static func url(kasURL: URL) -> URL {
        kasURL.appendingPathComponent(path)
    }

    /// Fetches the key from `kasURL`. It requires HTTP 200, `alg` RSA-OAEP, a non-empty `kid`, and a `publicKey`
    /// that is an RSA public key of at least 2048 bits. Transport errors are rethrown as they are.
    static func fetch(kasURL: URL, http: any FairPlayHTTP) async throws -> FairPlayEnvelopeKey {
        var request = URLRequest(url: url(kasURL: kasURL))
        request.httpMethod = "GET"
        // The license service advertises `alt-svc: h3`, as KAS does.
        request.assumesHTTP3Capable = true
        let (data, response) = try await http.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw FairPlayEnvelopeKeyError.invalidResponse("not an HTTP response")
        }
        guard httpResponse.statusCode == 200 else {
            throw FairPlayEnvelopeKeyError.unexpectedStatus(httpResponse.statusCode)
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
        do {
            let key = try TDFManifestBuilder(kasURL: kasURL).publicKey(fromPEM: pem)
            return FairPlayEnvelopeKey(publicKey: key, kid: kid)
        } catch {
            throw FairPlayEnvelopeKeyError.invalidPublicKey(error.localizedDescription)
        }
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
