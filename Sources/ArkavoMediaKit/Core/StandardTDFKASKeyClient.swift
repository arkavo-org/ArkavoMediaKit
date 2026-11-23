import CryptoKit
import Foundation
import OpenTDFKit

/// Rewraps a standard-TDF (including HLS TDF) DEK at the KAS and unwraps it locally.
///
/// The KAS is resolved from the platform's `/.well-known/opentdf-configuration`
/// and the rewrap goes to the advertised Connect route. An unreachable, unusable
/// or REST-only document falls back to `OpenTDFConfiguration.forKasConnect`,
/// never to the legacy `/kas/v2/rewrap` route (see `resolveKASConfiguration`).
/// The session-wrapped DEK in the response is unwrapped with the standard-TDF
/// HKDF salt `SHA256("TDF")`, not OpenTDFKit's NanoTDF default.
///
/// Targets OpenTDFKit 4.0.1 API. The fetch → rewrap → unwrap sequence can
/// collapse to a single call once OpenTDFKit ships `rewrapAndUnwrapTDF`.
public struct StandardTDFKASKeyClient: Sendable {
    /// Maximum well-known document size (1 MiB)
    private static let maxWellKnownBytes = 1 * 1024 * 1024

    /// Default ephemeral session that refuses redirects and disables disk caching
    private static let defaultSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        return URLSession(configuration: config, delegate: RedirectRefusal(), delegateQueue: nil)
    }()

    private let urlSession: URLSession
    private let allowedKASOrigins: Set<String>

    /// - Parameters:
    ///   - urlSession: Session used for both the well-known fetch and the rewrap request.
    ///     Defaults to a redirect-refusing ephemeral session. Inject a stubbed session in tests.
    ///   - allowedKASOrigins: Allowlist of trusted KAS origins (`scheme://host[:port]` or URLs).
    ///     Fails closed by default when nil or empty so untrusted manifests cannot exfiltrate
    ///     bearer tokens to arbitrary public HTTPS hosts.
    public init(
        urlSession: URLSession? = nil,
        allowedKASOrigins: Set<String>? = nil
    ) {
        self.urlSession = urlSession ?? Self.defaultSession
        if let allowedKASOrigins {
            self.allowedKASOrigins = Set(allowedKASOrigins.compactMap { entry in
                URL(string: entry).flatMap(Self.origin(of:)) ?? entry.lowercased()
            })
        } else {
            self.allowedKASOrigins = []
        }
    }

    /// Normalized origin (`scheme://host` or `scheme://host:port` for non-default ports), lowercased.
    public static func origin(of url: URL) -> String? {
        guard let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased(),
              !host.isEmpty
        else {
            return nil
        }
        let normalizedHost = host.hasSuffix(".") ? String(host.dropLast()) : host
        if let port = url.port {
            let isDefaultPort = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
            if !isDefaultPort {
                return "\(scheme)://\(normalizedHost):\(port)"
            }
        }
        return "\(scheme)://\(normalizedHost)"
    }

    // MARK: - Public API

    /// HLS TDF: builds the `TDFManifest` from the `HLSManifest` and rewraps it.
    ///
    /// - Throws: `StandardTDFKASKeyClientError.missingPolicyData` when the HLS
    ///   manifest carries no policy or policy binding; `KASRewrapError` /
    ///   `KASDiscoveryError` from OpenTDFKit propagate unchanged.
    public func unwrapKey(manifest: HLSManifest, authToken: String) async throws -> SymmetricKey {
        guard let policy = manifest.policy,
              let policyBindingAlg = manifest.policyBindingAlg,
              let policyBindingHash = manifest.policyBindingHash
        else {
            throw StandardTDFKASKeyClientError.missingPolicyData
        }

        // The rewrap request carries only `policy` and the key-access object
        // (type, url, protocol, wrappedKey, policyBinding, ...); the payload
        // descriptor and the KAO `schemaVersion` the builder fills in never
        // reach the KAS, so the builder is equivalent to hand-assembling.
        let tdfManifest = OpenTDFKit.TDFManifestBuilder().buildStandardManifest(
            wrappedKey: manifest.wrappedKey,
            kasURL: manifest.kasURL,
            policy: policy,
            iv: manifest.segmentIVs.first ?? "",
            mimeType: "application/x-mpegURL",
            policyBinding: TDFPolicyBinding(alg: policyBindingAlg, hash: policyBindingHash),
            algorithm: manifest.algorithm
        )

        return try await unwrapKey(manifest: tdfManifest, authToken: authToken)
    }

    /// Any standard TDF manifest (used by `StandardTDFKeyProvider`).
    ///
    /// The KAS is taken from the first key-access object's `url`, validated against
    /// SSRF/scheme rules and `allowedKASOrigins` before any network request.
    public func unwrapKey(manifest: TDFManifest, authToken: String) async throws -> SymmetricKey {
        guard let keyAccess = manifest.encryptionInformation.keyAccess.first else {
            throw StandardTDFKASKeyClientError.missingWrappedKey
        }
        guard let kasURL = URL(string: keyAccess.url) else {
            throw StandardTDFKASKeyClientError.invalidKASURL(keyAccess.url)
        }

        // Validate scheme, non-empty host, and SSRF IP constraints before touching the network.
        try validateKasURL(keyAccess.url)
        try validateAllowedOrigin(kasURL, rawURL: keyAccess.url)

        let platformBase = Self.platformBase(forKASURL: kasURL)
        try validateKasURL(platformBase)

        let discovered: Result<OpenTDFConfiguration, Error>
        do {
            discovered = .success(try await fetchWellKnownNoRedirect(platformURL: platformBase))
        } catch {
            discovered = .failure(error)
        }
        let configuration = Self.resolveKASConfiguration(platformBase: platformBase, discovered: discovered)

        // Validate resolved endpoints (propagates SSRF / scheme errors from hostile well-known documents).
        let endpoints = try KasEndpoints.from(configuration)
        if let rewrapURL = URL(string: endpoints.rewrapURL) {
            try validateAllowedOrigin(rewrapURL, rawURL: endpoints.rewrapURL)
        }
        if let publicKeyURL = URL(string: endpoints.publicKeyURL) {
            try validateAllowedOrigin(publicKeyURL, rawURL: endpoints.publicKeyURL)
        }

        let kasClient = try KASRewrapClient(
            configuration: configuration,
            oauthToken: authToken,
            urlSession: urlSession
        )

        // One ephemeral P-256 key serves as the request's clientPublicKey, the
        // JWT signing key and the ECDH private key for the response.
        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let result = try await kasClient.rewrapTDF(
            manifest: manifest,
            clientPrivateKey: clientPrivateKey
        )

        guard let wrappedKey = result.wrappedKeys.values.first else {
            throw StandardTDFKASKeyClientError.missingWrappedKey
        }
        guard let sessionPublicKeyPEM = result.sessionPublicKeyPEM else {
            throw StandardTDFKASKeyClientError.missingSessionKey
        }

        return try Self.unwrapSessionWrappedKey(
            wrappedKey,
            sessionPublicKeyPEM: sessionPublicKeyPEM,
            clientPrivateKey: clientPrivateKey
        )
    }

    /// Picks the KAS configuration to rewrap against from the well-known lookup.
    ///
    /// The advertised document is used only when it advertises Connect endpoints
    /// with a non-empty `kas.uri`. A document that is unreachable, has no usable
    /// `kas` block, or advertises only the REST pair synthesizes the Connect
    /// endpoints under `platformBase` instead.
    ///
    /// Does NOT swallow SSRF or invalid-URL errors on advertised Connect
    /// endpoints: those remain intact so `KasEndpoints.from` rejects hostile
    /// well-known documents instead of silently falling back.
    public static func resolveKASConfiguration(
        platformBase: String,
        discovered: Result<OpenTDFConfiguration, Error>
    ) -> OpenTDFConfiguration {
        if case let .success(configuration) = discovered,
           let kas = configuration.kas,
           !kas.uri.isEmpty,
           kas.connectRewrapURL != nil,
           kas.connectPublicKeyURL != nil
        {
            return configuration
        }
        return .forKasConnect(platformBase)
    }

    // MARK: - Internals

    private func validateAllowedOrigin(_ url: URL, rawURL: String) throws {
        guard !allowedKASOrigins.isEmpty,
              let origin = Self.origin(of: url),
              allowedKASOrigins.contains(origin)
        else {
            throw StandardTDFKASKeyClientError.untrustedKASOrigin(rawURL)
        }
    }

    /// Fetches `/.well-known/opentdf-configuration` while explicitly refusing HTTP redirects.
    private func fetchWellKnownNoRedirect(platformURL: String) async throws -> OpenTDFConfiguration {
        var base = platformURL
        while base.hasSuffix("/") {
            base.removeLast()
        }
        let urlString = "\(base)/.well-known/opentdf-configuration"
        try validateKasURL(urlString)
        guard let url = URL(string: urlString) else {
            throw KASDiscoveryError.invalidURL("Failed to parse URL: \(urlString)")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.addValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await urlSession.data(for: request, delegate: RedirectRefusal())
        guard let http = response as? HTTPURLResponse else {
            throw KASDiscoveryError.invalidResponse("Non-HTTP response from \(urlString)")
        }
        guard (200 ..< 300).contains(http.statusCode) else {
            throw KASDiscoveryError.httpError(http.statusCode, "GET \(urlString): HTTP \(http.statusCode)")
        }
        guard data.count <= Self.maxWellKnownBytes else {
            throw KASDiscoveryError.invalidResponse("Well-known response exceeds size limit")
        }
        do {
            return try JSONDecoder().decode(OpenTDFConfiguration.self, from: data)
        } catch {
            throw KASDiscoveryError.invalidResponse("Failed to parse well-known JSON: \(error)")
        }
    }

    /// The platform base the well-known document is served from: the manifest's
    /// KAS URL with query/fragment and a trailing `/kas` path component stripped.
    static func platformBase(forKASURL kasURL: URL) -> String {
        var components = URLComponents(url: kasURL, resolvingAgainstBaseURL: true)
        components?.query = nil
        components?.fragment = nil
        let cleanURL = components?.url ?? kasURL
        let base = cleanURL.lastPathComponent == "kas" ? cleanURL.deletingLastPathComponent() : cleanURL
        var string = base.absoluteString
        while string.hasSuffix("/") {
            string.removeLast()
        }
        return string
    }

    /// Unwraps the session-wrapped DEK from a rewrap response with the client's
    /// ephemeral P-256 key (ECDH + HKDF + AES-GCM).
    static func unwrapSessionWrappedKey(
        _ wrappedKey: Data,
        sessionPublicKeyPEM: String,
        clientPrivateKey: P256.KeyAgreement.PrivateKey
    ) throws -> SymmetricKey {
        let sessionPublicKey: Data
        do {
            sessionPublicKey = try KASRewrapClient.validateEcPublicKeyPEM(sessionPublicKeyPEM).compressedKey
        } catch {
            throw StandardTDFKASKeyClientError.invalidSessionKey(String(describing: error))
        }

        // The salt is mandatory. `KASRewrapClient.unwrapKey` defaults its salt
        // to the NanoTDF v1.2 value; a standard (or HLS) TDF session key is
        // derived with SHA256("TDF"), as the platform KAS and the Go SDK do.
        // Passing the wrong salt yields a different KEK and AES-GCM fails with
        // an authentication error.
        return try KASRewrapClient.unwrapKey(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPublicKey,
            clientPrivateKey: clientPrivateKey.rawRepresentation,
            salt: KASRewrapClient.standardTDFSessionSalt
        )
    }
}

/// Errors raised by `StandardTDFKASKeyClient` itself. OpenTDFKit's
/// `KASRewrapError` and `KASDiscoveryError` propagate unchanged.
public enum StandardTDFKASKeyClientError: Error, LocalizedError, Equatable {
    /// The HLS manifest has no policy or policy binding to rewrap against.
    case missingPolicyData
    /// The manifest has no key-access object, or the KAS returned no wrapped key.
    case missingWrappedKey
    /// The KAS response carried no session public key.
    case missingSessionKey
    /// The KAS session public key could not be parsed.
    case invalidSessionKey(String)
    /// The manifest's key-access `url` is not a URL.
    case invalidKASURL(String)
    /// The manifest or well-known KAS endpoint origin is not in the trusted allowlist.
    case untrustedKASOrigin(String)

    public var errorDescription: String? {
        switch self {
        case .missingPolicyData:
            "TDF manifest missing policy data"
        case .missingWrappedKey:
            "KAS response missing wrapped key"
        case .missingSessionKey:
            "KAS response missing session public key"
        case let .invalidSessionKey(reason):
            "Invalid KAS session public key: \(reason)"
        case let .invalidKASURL(url):
            "Invalid KAS URL in manifest: \(url)"
        case let .untrustedKASOrigin(url):
            "Untrusted KAS origin: \(url)"
        }
    }
}
