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
    private let kasURL: URL
    private let kasPublicKeyPEM: String?

    /// Initialize with optional KAS configuration for key unwrapping
    ///
    /// - Parameters:
    ///   - kasURL: KAS server URL for key unwrapping
    ///   - kasPublicKeyPEM: KAS RSA public key (optional, for offline decryption)
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String? = nil
    ) {
        self.kasURL = kasURL
        self.kasPublicKeyPEM = kasPublicKeyPEM
    }

    /// Extract HLS content from TDF archive to local directory
    ///
    /// - Parameters:
    ///   - tdfData: TDF archive data
    ///   - outputDirectory: Directory to extract HLS content
    /// - Returns: LocalHLSAsset with extracted content locations
    /// - Throws: HLSTDFExtractorError if extraction fails
    public func extract(
        tdfData: Data,
        outputDirectory: URL
    ) async throws -> LocalHLSAsset {
        // Create output directory
        try FileManager.default.createDirectory(
            at: outputDirectory,
            withIntermediateDirectories: true
        )

        // Open TDF archive
        let archive = try Archive(data: tdfData, accessMode: .read)

        // Extract manifest.json
        guard let manifestEntry = archive["manifest.json"] else {
            throw HLSTDFExtractorError.missingManifest
        }

        var manifestData = Data()
        _ = try archive.extract(manifestEntry) { data in
            manifestData.append(data)
        }

        // Parse manifest
        let manifest = try parseManifest(manifestData)

        // Extract playlist.m3u8
        guard let playlistEntry = archive["playlist.m3u8"] else {
            throw HLSTDFExtractorError.missingPlaylist
        }

        var playlistData = Data()
        _ = try archive.extract(playlistEntry) { data in
            playlistData.append(data)
        }

        let playlistURL = outputDirectory.appendingPathComponent("playlist.m3u8")
        try playlistData.write(to: playlistURL)

        // Create segments directory
        let segmentsDir = outputDirectory.appendingPathComponent("segments")
        try FileManager.default.createDirectory(
            at: segmentsDir,
            withIntermediateDirectories: true
        )

        // Extract encrypted segments
        var segmentURLs: [URL] = []
        var index = 0

        while true {
            let segmentPath = "segments/\(index).enc"
            guard let segmentEntry = archive[segmentPath] else {
                break
            }

            var segmentData = Data()
            _ = try archive.extract(segmentEntry) { data in
                segmentData.append(data)
            }

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

    /// Decrypt a segment using the wrapped key from manifest
    ///
    /// - Parameters:
    ///   - segmentData: Encrypted segment data
    ///   - segmentIndex: Segment index for IV lookup
    ///   - symmetricKey: Decryption key (from KAS unwrap or cache)
    ///   - manifest: TDF manifest with encryption info
    /// - Returns: Decrypted segment data
    /// - Throws: HLSTDFExtractorError if decryption fails
    public func decryptSegment(
        segmentData: Data,
        segmentIndex: Int,
        symmetricKey: SymmetricKey,
        manifest: HLSManifest
    ) throws -> Data {
        // Get IV for this segment
        guard segmentIndex < manifest.segmentIVs.count else {
            throw HLSTDFExtractorError.segmentIVNotFound(index: segmentIndex)
        }

        let ivBase64 = manifest.segmentIVs[segmentIndex]
        guard let iv = Data(base64Encoded: ivBase64) else {
            throw HLSTDFExtractorError.invalidIV
        }

        // Decrypt based on mode
        let mode = manifest.encryptionMode ?? "CBC"
        if mode == "GCM" {
            // GCM: last 16 bytes are the tag
            let tagSize = 16
            guard segmentData.count >= tagSize else {
                throw HLSTDFExtractorError.segmentTooSmall
            }
            let ciphertext = segmentData.dropLast(tagSize)
            let tag = segmentData.suffix(tagSize)

            return try TDFCrypto.decryptPayload(
                ciphertext: Data(ciphertext),
                iv: iv,
                tag: Data(tag),
                symmetricKey: symmetricKey
            )
        } else {
            // CBC mode (FairPlay compatible)
            return try TDFCrypto.decryptPayloadCBC(
                ciphertext: segmentData,
                iv: iv,
                symmetricKey: symmetricKey
            )
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

        // Extract policy and policyBinding for KAS rewrap
        let policy = encInfo["policy"] as? String
        let policyBinding = keyAccess["policyBinding"] as? [String: String]
        let policyBindingAlg = policyBinding?["alg"]
        let policyBindingHash = policyBinding?["hash"]

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
            kasURL: (keyAccess["url"] as? String).flatMap { URL(string: $0) } ?? kasURL,
            policy: policy,
            policyBindingAlg: policyBindingAlg,
            policyBindingHash: policyBindingHash
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
        policyBindingHash: String? = nil
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
    }
}

/// Errors that can occur during HLS TDF extraction
public enum HLSTDFExtractorError: Error, LocalizedError {
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
        }
    }
}
