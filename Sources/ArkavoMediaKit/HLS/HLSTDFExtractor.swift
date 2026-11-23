import CryptoKit
import Foundation
import OpenTDFKit
import ZIPFoundation

/// Extracts HLS content from a TDF archive for local playback
///
/// Parses the TDF archive and extracts:
/// - Master manifest with encryption metadata
/// - m3u8 playlist
/// - Encrypted video segments
public actor HLSTDFExtractor {
    /// Default ZIP extraction limits to prevent ZIP bomb OOM DoS attacks
    public struct ExtractionLimits: Sendable {
        public let maxManifestBytes: Int
        public let maxPlaylistBytes: Int
        public let maxSegmentBytes: Int
        public let maxTotalBytes: Int
        public let maxSegmentCount: Int

        public static let `default` = ExtractionLimits(
            maxManifestBytes: 1 * 1024 * 1024,
            maxPlaylistBytes: 1 * 1024 * 1024,
            maxSegmentBytes: 64 * 1024 * 1024,
            maxTotalBytes: 512 * 1024 * 1024,
            maxSegmentCount: 4_096
        )

        public init(
            maxManifestBytes: Int = 1 * 1024 * 1024,
            maxPlaylistBytes: Int = 1 * 1024 * 1024,
            maxSegmentBytes: Int = 64 * 1024 * 1024,
            maxTotalBytes: Int = 512 * 1024 * 1024,
            maxSegmentCount: Int = 4_096
        ) {
            self.maxManifestBytes = max(1, maxManifestBytes)
            self.maxPlaylistBytes = max(1, maxPlaylistBytes)
            self.maxSegmentBytes = max(1, maxSegmentBytes)
            self.maxTotalBytes = max(1, maxTotalBytes)
            self.maxSegmentCount = max(1, maxSegmentCount)
        }
    }

    private let kasURL: URL
    private let kasPublicKeyPEM: String?
    private let limits: ExtractionLimits

    /// Initialize with optional KAS configuration for key unwrapping
    ///
    /// - Parameters:
    ///   - kasURL: Trusted KAS server URL for key unwrapping
    ///   - kasPublicKeyPEM: KAS RSA public key (optional, for offline decryption)
    ///   - limits: Size and count caps applied during ZIP extraction
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String? = nil,
        limits: ExtractionLimits = .default
    ) {
        self.kasURL = kasURL
        self.kasPublicKeyPEM = kasPublicKeyPEM
        self.limits = limits
    }

    /// Extract HLS content from TDF archive to local directory
    ///
    /// - Parameters:
    ///   - tdfData: TDF archive data
    ///   - outputDirectory: Directory to extract HLS content
    /// - Returns: LocalHLSAsset with extracted content locations
    /// - Throws: HLSTDFExtractorError if extraction fails or archive violates security limits
    public func extract(
        tdfData: Data,
        outputDirectory: URL
    ) async throws -> LocalHLSAsset {
        // Open TDF archive
        let archive = try Archive(data: tdfData, accessMode: .read)

        // Reject any archive containing symlinks or path-traversal entries up front
        for entry in archive {
            if entry.type == .symlink {
                throw HLSTDFExtractorError.unsupportedEntryType(entry.path)
            }
            if entry.path.contains("..") || entry.path.hasPrefix("/") || entry.path.contains("\\") {
                throw HLSTDFExtractorError.invalidArchive
            }
        }

        var remainingTotal = limits.maxTotalBytes

        // Extract manifest.json with size cap and file-type verification
        guard let manifestEntry = archive["manifest.json"] else {
            throw HLSTDFExtractorError.missingManifest
        }
        let manifestData = try extractBoundedFile(
            from: archive,
            entry: manifestEntry,
            maxBytes: limits.maxManifestBytes,
            remainingTotal: &remainingTotal
        )

        // Parse and validate manifest before creating files on disk
        let manifest = try parseManifest(manifestData)

        // Extract playlist.m3u8 with size cap and file-type verification
        guard let playlistEntry = archive["playlist.m3u8"] else {
            throw HLSTDFExtractorError.missingPlaylist
        }
        let playlistData = try extractBoundedFile(
            from: archive,
            entry: playlistEntry,
            maxBytes: limits.maxPlaylistBytes,
            remainingTotal: &remainingTotal
        )

        // Create output directories
        try FileManager.default.createDirectory(
            at: outputDirectory,
            withIntermediateDirectories: true
        )

        let playlistURL = outputDirectory.appendingPathComponent("playlist.m3u8")
        try playlistData.write(to: playlistURL)

        let segmentsDir = outputDirectory.appendingPathComponent("segments")
        try FileManager.default.createDirectory(
            at: segmentsDir,
            withIntermediateDirectories: true
        )

        // Extract encrypted segments with bounded sizes and segment count cap
        var segmentURLs: [URL] = []
        var index = 0

        while true {
            let segmentPath = "segments/\(index).enc"
            guard let segmentEntry = archive[segmentPath] else {
                break
            }
            guard index < limits.maxSegmentCount else {
                throw HLSTDFExtractorError.entryTooLarge(segmentPath)
            }

            let segmentData = try extractBoundedFile(
                from: archive,
                entry: segmentEntry,
                maxBytes: limits.maxSegmentBytes,
                remainingTotal: &remainingTotal
            )

            let segmentURL = segmentsDir.appendingPathComponent("\(index).enc")
            try segmentData.write(to: segmentURL)
            segmentURLs.append(segmentURL)
            index += 1
        }

        guard !segmentURLs.isEmpty else {
            throw HLSTDFExtractorError.noSegmentsFound
        }

        // Save manifest for key access
        let manifestURL = outputDirectory.appendingPathComponent("manifest.json")
        try manifestData.write(to: manifestURL)

        return LocalHLSAsset(
            playlistURL: playlistURL,
            segmentURLs: segmentURLs,
            manifestURL: manifestURL,
            manifest: manifest,
            outputDirectory: outputDirectory
        )
    }

    private func extractBoundedFile(
        from archive: Archive,
        entry: Entry,
        maxBytes: Int,
        remainingTotal: inout Int
    ) throws -> Data {
        guard entry.type == .file else {
            throw HLSTDFExtractorError.unsupportedEntryType(entry.path)
        }
        let allowedBytes = min(maxBytes, remainingTotal)
        guard allowedBytes >= 0, entry.uncompressedSize <= UInt64(allowedBytes) else {
            throw HLSTDFExtractorError.entryTooLarge(entry.path)
        }

        var output = Data()
        output.reserveCapacity(min(Int(entry.uncompressedSize), allowedBytes))
        var exceeded = false
        do {
            _ = try archive.extract(entry) { chunk in
                if output.count + chunk.count > allowedBytes {
                    exceeded = true
                    throw HLSTDFExtractorError.entryTooLarge(entry.path)
                }
                output.append(chunk)
            }
        } catch let error as HLSTDFExtractorError {
            throw error
        } catch {
            if exceeded {
                throw HLSTDFExtractorError.entryTooLarge(entry.path)
            }
            throw error
        }
        remainingTotal -= output.count
        return output
    }

    /// Decrypt a segment using the wrapped key from manifest
    ///
    /// - Parameters:
    ///   - segmentData: Encrypted segment data
    ///   - segmentIndex: Segment index for IV lookup
    ///   - symmetricKey: Decryption key (from KAS unwrap or cache)
    ///   - manifest: TDF manifest with encryption info
    /// - Returns: Decrypted segment data
    /// - Throws: HLSTDFExtractorError if decryption or integrity validation fails
    public func decryptSegment(
        segmentData: Data,
        segmentIndex: Int,
        symmetricKey: SymmetricKey,
        manifest: HLSManifest
    ) throws -> Data {
        // Bounds-check segmentIndex against negative and out-of-range indices
        guard segmentIndex >= 0, segmentIndex < manifest.segmentIVs.count else {
            throw HLSTDFExtractorError.segmentIVNotFound(index: segmentIndex)
        }

        // Always require and verify policyBinding against DEK (fail closed if policy or binding is stripped).
        // Accepts both OpenTDF 5.0 raw-digest Base64(HMAC) and legacy hex-form Base64(utf8(hex(HMAC))).
        guard let policyBase64 = manifest.policy,
              !policyBase64.isEmpty,
              manifest.policyBindingAlg == "HS256",
              let bindingHash = manifest.policyBindingHash,
              let actual = Data(base64Encoded: bindingHash),
              StandardTDFSegmentCrypto.verifyPolicyBinding(
                  actual: actual,
                  policyBase64: policyBase64,
                  symmetricKey: symmetricKey
              )
        else {
            throw HLSTDFExtractorError.integrityCheckFailed
        }

        let ivBase64 = manifest.segmentIVs[segmentIndex]
        guard let iv = Data(base64Encoded: ivBase64) else {
            throw HLSTDFExtractorError.invalidIV
        }

        // Determine mode authoritatively from encryptionInformation.method.algorithm (never downgrade via unsigned meta.hls.encryptionMode)
        let isGCM: Bool
        switch manifest.algorithm {
        case "AES-128-GCM", "AES-256-GCM":
            isGCM = true
        case "AES-128-CBC", "AES-256-CBC":
            isGCM = false
        default:
            throw HLSTDFExtractorError.unsupportedAlgorithm(manifest.algorithm)
        }

        if let declaredMode = manifest.encryptionMode {
            let expectedMode = isGCM ? "GCM" : "CBC"
            guard declaredMode == expectedMode else {
                throw HLSTDFExtractorError.algorithmMismatch
            }
        }

        if isGCM {
            guard iv.count == 12 else {
                throw HLSTDFExtractorError.invalidIV
            }
            // GCM: last 16 bytes are the tag
            let tagSize = 16
            guard segmentData.count >= tagSize else {
                throw HLSTDFExtractorError.segmentTooSmall
            }
            let ciphertext = segmentData.dropLast(tagSize)
            let tag = Data(segmentData.suffix(tagSize))

            // Verify manifest integrity metadata if present
            if manifest.segmentHashes != nil || manifest.rootSignatureSig != nil {
                try Self.verifyManifestSegmentIntegrity(
                    segmentSignature: tag,
                    segmentIndex: segmentIndex,
                    manifest: manifest,
                    symmetricKey: symmetricKey
                )
            }

            return try TDFCrypto.decryptPayload(
                ciphertext: Data(ciphertext),
                iv: iv,
                tag: tag,
                symmetricKey: symmetricKey
            )
        } else {
            guard iv.count == 16 else {
                throw HLSTDFExtractorError.invalidIV
            }
            // CBC is unauthenticated at the cipher layer: require authentic HS256 segment + root integrity metadata
            let computedSig = TDFCrypto.segmentSignature(
                segmentCiphertext: segmentData,
                symmetricKey: symmetricKey
            )
            try Self.verifyManifestSegmentIntegrity(
                segmentSignature: computedSig,
                segmentIndex: segmentIndex,
                manifest: manifest,
                symmetricKey: symmetricKey
            )

            return try TDFCrypto.decryptPayloadCBC(
                ciphertext: segmentData,
                iv: iv,
                symmetricKey: symmetricKey
            )
        }
    }

    private static func verifyManifestSegmentIntegrity(
        segmentSignature: Data,
        segmentIndex: Int,
        manifest: HLSManifest,
        symmetricKey: SymmetricKey
    ) throws {
        guard let hashes = manifest.segmentHashes,
              segmentIndex >= 0, segmentIndex < hashes.count,
              let expectedSegmentHash = Data(base64Encoded: hashes[segmentIndex]),
              StandardTDFSegmentCrypto.constantTimeEquals(expectedSegmentHash, segmentSignature),
              manifest.rootSignatureAlg == "HS256",
              let rootSigBase64 = manifest.rootSignatureSig,
              let actualRootSig = Data(base64Encoded: rootSigBase64)
        else {
            throw HLSTDFExtractorError.integrityCheckFailed
        }
        var rawHashes: [Data] = []
        rawHashes.reserveCapacity(hashes.count)
        for hashB64 in hashes {
            guard let raw = Data(base64Encoded: hashB64) else {
                throw HLSTDFExtractorError.integrityCheckFailed
            }
            rawHashes.append(raw)
        }
        let expectedRootBase64 = TDFCrypto.rootSignatureBase64(
            rawSegmentSignatures: rawHashes,
            symmetricKey: symmetricKey
        )
        guard let expectedRootSig = Data(base64Encoded: expectedRootBase64),
              StandardTDFSegmentCrypto.constantTimeEquals(actualRootSig, expectedRootSig)
        else {
            throw HLSTDFExtractorError.integrityCheckFailed
        }
    }

    // MARK: - Private Helpers

    private func parseManifest(_ data: Data) throws -> HLSManifest {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw HLSTDFExtractorError.invalidManifestFormat
        }

        // Extract encryption information
        guard let encInfo = json["encryptionInformation"] as? [String: Any],
              let keyAccess = (encInfo["keyAccess"] as? [[String: Any]])?.first,
              let wrappedKey = keyAccess["wrappedKey"] as? String,
              let method = encInfo["method"] as? [String: Any],
              let algorithm = method["algorithm"] as? String
        else {
            throw HLSTDFExtractorError.invalidManifestFormat
        }

        // Reject untrusted manifest keyAccess.url that attempts to redirect KAS requests off-origin
        let resolvedKASURL: URL
        if let rawKASURL = keyAccess["url"] as? String, !rawKASURL.isEmpty {
            do {
                try validateKasURL(rawKASURL)
            } catch {
                throw HLSTDFExtractorError.untrustedKASURL(rawKASURL)
            }
            guard let manifestKASURL = URL(string: rawKASURL),
                  let manifestOrigin = StandardTDFKASKeyClient.origin(of: manifestKASURL),
                  let trustedOrigin = StandardTDFKASKeyClient.origin(of: kasURL),
                  manifestOrigin == trustedOrigin
            else {
                throw HLSTDFExtractorError.untrustedKASURL(rawKASURL)
            }
            resolvedKASURL = manifestKASURL
        } else {
            resolvedKASURL = kasURL
        }

        // Extract policy and policyBinding for KAS rewrap
        let policy = encInfo["policy"] as? String
        let policyBinding = keyAccess["policyBinding"] as? [String: String]
        let policyBindingAlg = policyBinding?["alg"]
        let policyBindingHash = policyBinding?["hash"]

        // Extract optional OpenTDF integrityInformation (required for CBC authentication)
        var segmentHashes: [String]?
        var segmentHashAlg: String?
        var rootSignatureAlg: String?
        var rootSignatureSig: String?
        if let integrityInfo = encInfo["integrityInformation"] as? [String: Any] {
            segmentHashAlg = integrityInfo["segmentHashAlg"] as? String
            if let rootSig = integrityInfo["rootSignature"] as? [String: Any] {
                rootSignatureAlg = rootSig["alg"] as? String
                rootSignatureSig = rootSig["sig"] as? String
            }
            if let segments = integrityInfo["segments"] as? [[String: Any]] {
                let hashes = segments.compactMap { $0["hash"] as? String }
                if hashes.count == segments.count, !hashes.isEmpty {
                    segmentHashes = hashes
                }
            }
        }

        // Extract HLS-specific metadata
        guard let meta = json["meta"] as? [String: Any],
              let hlsInfo = meta["hls"] as? [String: Any],
              let assetID = hlsInfo["assetId"] as? String,
              let segmentIVs = hlsInfo["segmentIVs"] as? [String]
        else {
            throw HLSTDFExtractorError.missingHLSMetadata
        }

        let totalDuration = hlsInfo["totalDuration"] as? Double ?? 0
        let segmentCount = hlsInfo["segmentCount"] as? Int ?? segmentIVs.count
        let encryptionMode = hlsInfo["encryptionMode"] as? String

        return HLSManifest(
            assetID: assetID,
            wrappedKey: wrappedKey,
            algorithm: algorithm,
            segmentIVs: segmentIVs,
            segmentCount: segmentCount,
            totalDuration: totalDuration,
            encryptionMode: encryptionMode,
            kasURL: resolvedKASURL,
            policy: policy,
            policyBindingAlg: policyBindingAlg,
            policyBindingHash: policyBindingHash,
            segmentHashes: segmentHashes,
            segmentHashAlg: segmentHashAlg,
            rootSignatureAlg: rootSignatureAlg,
            rootSignatureSig: rootSignatureSig
        )
    }
}

/// Represents extracted HLS content ready for local playback
public struct LocalHLSAsset: Sendable {
    /// URL to the local m3u8 playlist
    public let playlistURL: URL

    /// URLs to encrypted segment files
    public let segmentURLs: [URL]

    /// URL to the TDF manifest for key access
    public let manifestURL: URL

    /// Parsed HLS manifest with encryption info
    public let manifest: HLSManifest

    /// Output directory containing all extracted content
    public let outputDirectory: URL

    public init(
        playlistURL: URL,
        segmentURLs: [URL],
        manifestURL: URL,
        manifest: HLSManifest,
        outputDirectory: URL
    ) {
        self.playlistURL = playlistURL
        self.segmentURLs = segmentURLs
        self.manifestURL = manifestURL
        self.manifest = manifest
        self.outputDirectory = outputDirectory
    }
}

/// Parsed HLS-specific manifest data
public struct HLSManifest: Sendable {
    /// Asset identifier
    public let assetID: String

    /// Base64-encoded RSA-wrapped DEK
    public let wrappedKey: String

    /// Encryption algorithm (e.g., "AES-128-CBC")
    public let algorithm: String

    /// Base64-encoded IVs for each segment
    public let segmentIVs: [String]

    /// Number of segments
    public let segmentCount: Int

    /// Total duration in seconds
    public let totalDuration: Double

    /// Encryption mode (GCM or CBC)
    public let encryptionMode: String?

    /// KAS URL for key unwrapping
    public let kasURL: URL

    /// Base64-encoded policy (required for KAS rewrap)
    public let policy: String?

    /// Policy binding algorithm (e.g., "HS256")
    public let policyBindingAlg: String?

    /// Policy binding hash (HMAC-SHA256 of policy)
    public let policyBindingHash: String?

    /// Base64-encoded per-segment integrity hashes (GMAC or HS256)
    public let segmentHashes: [String]?

    /// Integrity hash algorithm for segments (e.g., "GMAC", "HS256")
    public let segmentHashAlg: String?

    /// Integrity root signature algorithm (e.g., "HS256")
    public let rootSignatureAlg: String?

    /// Base64-encoded root signature over concatenated raw segment hashes
    public let rootSignatureSig: String?

    public init(
        assetID: String,
        wrappedKey: String,
        algorithm: String,
        segmentIVs: [String],
        segmentCount: Int,
        totalDuration: Double,
        encryptionMode: String?,
        kasURL: URL,
        policy: String? = nil,
        policyBindingAlg: String? = nil,
        policyBindingHash: String? = nil,
        segmentHashes: [String]? = nil,
        segmentHashAlg: String? = nil,
        rootSignatureAlg: String? = nil,
        rootSignatureSig: String? = nil
    ) {
        self.assetID = assetID
        self.wrappedKey = wrappedKey
        self.algorithm = algorithm
        self.segmentIVs = segmentIVs
        self.segmentCount = segmentCount
        self.totalDuration = totalDuration
        self.encryptionMode = encryptionMode
        self.kasURL = kasURL
        self.policy = policy
        self.policyBindingAlg = policyBindingAlg
        self.policyBindingHash = policyBindingHash
        self.segmentHashes = segmentHashes
        self.segmentHashAlg = segmentHashAlg
        self.rootSignatureAlg = rootSignatureAlg
        self.rootSignatureSig = rootSignatureSig
    }
}

/// Errors that can occur during HLS TDF extraction
public enum HLSTDFExtractorError: Error, LocalizedError, Equatable, Sendable {
    case invalidArchive
    case missingManifest
    case missingPlaylist
    case noSegmentsFound
    case invalidManifestFormat
    case missingHLSMetadata
    case segmentIVNotFound(index: Int)
    case invalidIV
    case segmentTooSmall
    case decryptionFailed(String)
    case entryTooLarge(String)
    case unsupportedEntryType(String)
    case untrustedKASURL(String)
    case unsupportedAlgorithm(String)
    case algorithmMismatch
    case integrityCheckFailed

    public var errorDescription: String? {
        switch self {
        case .invalidArchive:
            "Invalid TDF archive format"
        case .missingManifest:
            "manifest.json not found in archive"
        case .missingPlaylist:
            "playlist.m3u8 not found in archive"
        case .noSegmentsFound:
            "No encrypted segments found in archive"
        case .invalidManifestFormat:
            "Invalid manifest JSON format"
        case .missingHLSMetadata:
            "Missing HLS metadata in manifest"
        case let .segmentIVNotFound(index):
            "IV not found for segment \(index)"
        case .invalidIV:
            "Invalid IV format"
        case .segmentTooSmall:
            "Segment data too small for authentication tag"
        case let .decryptionFailed(reason):
            "Decryption failed: \(reason)"
        case let .entryTooLarge(path):
            "Archive entry exceeds maximum allowed size: \(path)"
        case let .unsupportedEntryType(path):
            "Unsupported non-file archive entry (e.g. symlink): \(path)"
        case let .untrustedKASURL(url):
            "Manifest KAS URL is untrusted or invalid: \(url)"
        case let .unsupportedAlgorithm(algorithm):
            "Unsupported encryption algorithm: \(algorithm)"
        case .algorithmMismatch:
            "Manifest encryptionMode does not match encryptionInformation.method.algorithm"
        case .integrityCheckFailed:
            "Manifest policy binding or integrity verification failed"
        }
    }
}
