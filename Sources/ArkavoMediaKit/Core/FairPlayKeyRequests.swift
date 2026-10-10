import AVFoundation
import Foundation

/// A key a package's playlists ask for (ADR-0055 §6 and §7 in arkavo-ios).
struct FairPlayKeyTarget: Equatable, Sendable {
    /// The policy uuid: the library asset id, and every session's and key request's `assetId`.
    let policyUUID: String
    /// The component id; nil for a profile v1 package, whose one key is the uuid's.
    let component: String?

    /// The SPC content identifier: the key URI without its scheme.
    var contentIdentifier: String { component.map { "\(policyUUID)/\($0)" } ?? policyUUID }

    /// The playlist's key URI.
    var uri: String { "skd://" + contentIdentifier }

    /// Every key the manifest's playlists ask for, in component order. There is one per entry of the policy's
    /// `arkavo:components`, or, without the list (or without an archive manifest), profile v1's one key. The uuid is the
    /// policy's, or `assetID` when the manifest has none (`TDFContentKeyDelegate.contentID(for:)`).
    ///
    /// Throws `FairPlayComponents.Error.malformedComponents` when the archive manifest has the list but not as the v2
    /// list, or cannot be read unambiguously (`FairPlayComponents.componentIDs(ofManifestJSON:)`): such a package has no
    /// keys, and is never played as profile v1.
    static func targets(for manifest: some FairPlayManifestProtocol) throws -> [FairPlayKeyTarget] {
        let uuid = manifest.tdfManifestJSON.flatMap(FairPlayPolicy.uuid(ofManifestJSON:)) ?? manifest.assetID
        guard let json = manifest.tdfManifestJSON, let ids = try FairPlayComponents.componentIDs(ofManifestJSON: json)
        else {
            return [FairPlayKeyTarget(policyUUID: uuid, component: nil)]
        }
        return ids.map { FairPlayKeyTarget(policyUUID: uuid, component: $0) }
    }
}

/// A key request the delegate answers: AVFoundation's, or a test's.
protocol FairPlayKeyRequesting: Sendable {
    /// The request's identifier as text: the playlist's `skd://` URI.
    var keyIdentifier: String? { get }
    func makeServerPlaybackContext(certificate: Data, contentIdentifier: Data) async throws -> Data
    func process(ckc: Data)
    func fail(_ error: Error)
}

/// AVFoundation's key request. `AVContentKeyRequest` is Sendable (`NS_SWIFT_SENDABLE`): AVFoundation lets any thread
/// make its SPC and give it a response or an error.
struct AVFoundationKeyRequest: FairPlayKeyRequesting {
    let request: AVContentKeyRequest

    var keyIdentifier: String? {
        switch request.identifier {
        case let text as String: text
        case let url as URL: url.absoluteString
        default: nil
        }
    }

    func makeServerPlaybackContext(certificate: Data, contentIdentifier: Data) async throws -> Data {
        try await request.makeStreamingContentKeyRequestData(forApp: certificate, contentIdentifier: contentIdentifier)
    }

    func process(ckc: Data) {
        request.processContentKeyResponse(AVContentKeyResponse(fairPlayStreamingKeyResponseData: ckc))
    }

    func fail(_ error: Error) {
        request.processContentKeyResponseError(error)
    }
}

/// The delegate's HTTP: URLSession, or a test's.
protocol FairPlayHTTP: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

struct URLSessionFairPlayHTTP: FairPlayHTTP {
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await URLSession.shared.data(for: request)
    }
}
