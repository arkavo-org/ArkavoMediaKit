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
    private let urlSession: URLSession

    /// - Parameter urlSession: Session used for both the well-known fetch and
    ///   the rewrap request. Inject a stubbed session in tests.
    public init(urlSession: URLSession = .shared) {
        self.urlSession = urlSession
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
    /// The KAS is taken from the first key-access object's `url`.
    public func unwrapKey(manifest: TDFManifest, authToken: String) async throws -> SymmetricKey {
        guard let keyAccess = manifest.encryptionInformation.keyAccess.first else {
            throw StandardTDFKASKeyClientError.missingWrappedKey
        }
        guard let kasURL = URL(string: keyAccess.url) else {
            throw StandardTDFKASKeyClientError.invalidKASURL(keyAccess.url)
        }

        let platformBase = Self.platformBase(forKASURL: kasURL)
        let discovered: Result<OpenTDFConfiguration, Error>
        do {
            discovered = .success(try await fetchWellKnown(platformURL: platformBase, urlSession: urlSession))
        } catch {
            discovered = .failure(error)
        }
        let configuration = Self.resolveKASConfiguration(platformBase: platformBase, discovered: discovered)

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
    /// The advertised document is used only when it resolves to the Connect
    /// transport. A document that is unreachable, has no usable `kas` block, or
    /// advertises only the REST pair would otherwise make `KasEndpoints.from`
    /// throw or select `/kas/v2/rewrap`, which arkavo-rs serves locally for
    /// NanoTDF and which answers 400 for a standard TDF. All of those cases
    /// synthesize the Connect endpoints under `platformBase` instead.
    ///
    /// This deliberately differs from OpenTDFKit's
    /// `OpenTDFConfiguration.withKasFallback(baseURL:)`, which keeps a
    /// REST-only document as advertised.
    public static func resolveKASConfiguration(
        platformBase: String,
        discovered: Result<OpenTDFConfiguration, Error>
    ) -> OpenTDFConfiguration {
        if case let .success(configuration) = discovered,
           let endpoints = try? KasEndpoints.from(configuration),
           endpoints.transport == .connect
        {
            return configuration
        }
        return .forKasConnect(platformBase)
    }

    // MARK: - Internals

    /// The platform base the well-known document is served from: the manifest's
    /// KAS URL with a trailing `/kas` path component stripped.
    static func platformBase(forKASURL kasURL: URL) -> String {
        let base = kasURL.lastPathComponent == "kas" ? kasURL.deletingLastPathComponent() : kasURL
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
        }
    }
}
