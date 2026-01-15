import CryptoKit
import Foundation
import OpenTDFKit
import ZIPFoundation

/// Packages HLS content into a TDF archive
///
/// Creates a single TDF archive containing:
/// - Master manifest with encryption metadata
/// - m3u8 playlist
/// - Encrypted video segments
public actor HLSTDFPackager {
    private let kasURL: URL
    private let kasPublicKeyPEM: String
    private let keySize: TDFKeySize
    private let mode: TDFEncryptionMode

    /// Initialize with KAS configuration
    ///
    /// - Parameters:
    ///   - kasURL: KAS server URL for key access
    ///   - kasPublicKeyPEM: KAS RSA public key for key wrapping
    ///   - keySize: Encryption key size (default: .bits128 for FairPlay)
    ///   - mode: Encryption mode (default: .cbc for FairPlay compatibility)
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String,
        keySize: TDFKeySize = .bits128,
        mode: TDFEncryptionMode = .cbc
    ) {
        self.kasURL = kasURL
        self.kasPublicKeyPEM = kasPublicKeyPEM
        self.keySize = keySize
        self.mode = mode
    }

    /// Package HLS content into a TDF archive
    ///
    /// - Parameters:
    ///   - hlsResult: Result from HLSConverter containing playlist and segments
    ///   - assetID: Unique asset identifier
    /// - Returns: TDF archive data
    /// - Throws: HLSTDFPackagerError if packaging fails
    public func package(
        hlsResult: HLSConversionResult,
        assetID: String
    ) async throws -> Data {
        // Generate symmetric key for all segments (shared DEK)
        let symmetricKey = try TDFCrypto.generateSymmetricKey(size: keySize)

        // Wrap the DEK with KAS public key
        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: kasPublicKeyPEM,
            symmetricKey: symmetricKey
        )

        // Encrypt each segment
        var encryptedSegments: [(filename: String, data: Data, iv: Data)] = []

        for (index, segmentURL) in hlsResult.segmentURLs.enumerated() {
            let segmentData = try Data(contentsOf: segmentURL)
            let (iv, ciphertext) = try encryptSegment(
                data: segmentData,
                symmetricKey: symmetricKey
            )
            let encryptedFilename = "segments/\(index).enc"
            encryptedSegments.append((encryptedFilename, ciphertext, iv))
        }

        // Generate modified playlist pointing to encrypted segments
        let modifiedPlaylist = generateEncryptedPlaylist(
            originalDurations: hlsResult.segmentDurations,
            segmentCount: encryptedSegments.count
        )

        // Build master manifest
        let manifest = try buildMasterManifest(
            wrappedKey: wrappedKey,
            symmetricKey: symmetricKey,
            assetID: assetID,
            segmentIVs: encryptedSegments.map { $0.iv },
            totalDuration: hlsResult.totalDuration
        )

        // Create TDF archive
        return try createTDFArchive(
            manifest: manifest,
            playlist: modifiedPlaylist,
            encryptedSegments: encryptedSegments
        )
    }

    // MARK: - Private Helpers

    private func encryptSegment(
        data: Data,
        symmetricKey: SymmetricKey
    ) throws -> (iv: Data, ciphertext: Data) {
        switch mode {
        case .cbc:
            let result = try TDFCrypto.encryptPayloadCBC(
                plaintext: data,
                symmetricKey: symmetricKey
            )
            return (result.iv, result.cipherText)
        case .gcm:
            let result = try TDFCrypto.encryptPayload(
                plaintext: data,
                symmetricKey: symmetricKey
            )
            // For GCM, append tag to ciphertext
            return (result.iv, result.cipherText + result.authenticationTag)
        }
    }

    private func generateEncryptedPlaylist(
        originalDurations: [Double],
        segmentCount: Int
    ) -> String {
        var playlist = "#EXTM3U\n"
        playlist += "#EXT-X-VERSION:3\n"
        playlist += "#EXT-X-TARGETDURATION:\(Int(ceil(originalDurations.max() ?? 6.0)))\n"
        playlist += "#EXT-X-MEDIA-SEQUENCE:0\n"
        playlist += "#EXT-X-KEY:METHOD=AES-128,URI=\"key.bin\"\n"

        for i in 0..<segmentCount {
            let duration = i < originalDurations.count ? originalDurations[i] : 6.0
            playlist += "#EXTINF:\(String(format: "%.3f", duration)),\n"
            playlist += "segments/\(i).enc\n"
        }

        playlist += "#EXT-X-ENDLIST\n"
        return playlist
    }

    private func buildMasterManifest(
        wrappedKey: String,
        symmetricKey: SymmetricKey,
        assetID: String,
        segmentIVs: [Data],
        totalDuration: Double
    ) throws -> Data {
        // Create policy JSON (minimal for now)
        let policyJSON = "{\"uuid\":\"\(assetID)\",\"body\":{}}"
        let policyData = Data(policyJSON.utf8)
        let policyBase64 = policyData.base64EncodedString()

        // Calculate policy binding (HMAC-SHA256 of policy with symmetric key)
        let policyBinding = TDFCrypto.policyBinding(
            policy: policyData,
            symmetricKey: symmetricKey
        )

        // Create HLS-specific metadata
        let hlsMetadata: [String: Any] = [
            "type": "hls",
            "version": "1.0",
            "assetId": assetID,
            "totalDuration": totalDuration,
            "segmentCount": segmentIVs.count,
            "segmentIVs": segmentIVs.map { $0.base64EncodedString() },
            "encryptionMode": mode.rawValue,
            "keySize": keySize == .bits128 ? 128 : 256
        ]

        // Use first segment IV as the manifest IV for TDFManifestLite compatibility
        let manifestIV = segmentIVs.first?.base64EncodedString() ?? ""
        let protectedAt = ISO8601DateFormatter().string(from: Date())

        // Build KAS rewrap URL - append /kas path if not already present
        let kasRewrapURL: String
        if kasURL.path.contains("/kas") {
            kasRewrapURL = kasURL.absoluteString
        } else {
            kasRewrapURL = kasURL.appendingPathComponent("kas").absoluteString
        }

        let manifest: [String: Any] = [
            "schemaVersion": "4.3.0",
            "encryptionInformation": [
                "type": "split",
                "policy": policyBase64,
                "keyAccess": [[
                    "type": "wrapped",
                    "url": kasRewrapURL,
                    "protocol": "kas",
                    "wrappedKey": wrappedKey,
                    "policyBinding": [
                        "alg": policyBinding.alg,
                        "hash": policyBinding.hash
                    ]
                ]],
                "method": [
                    "algorithm": keySize.algorithm(mode: mode),
                    "iv": manifestIV,
                    "isStreamable": true
                ]
            ],
            "payload": [
                "type": "reference",
                "url": "playlist.m3u8",
                "protocol": "zip",
                "isEncrypted": true,
                "mimeType": "application/x-mpegURL"
            ],
            "meta": [
                "assetId": assetID,
                "protectedAt": protectedAt,
                "hls": hlsMetadata
            ]
        ]

        return try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.sortedKeys, .prettyPrinted]
        )
    }

    private func createTDFArchive(
        manifest: Data,
        playlist: String,
        encryptedSegments: [(filename: String, data: Data, iv: Data)]
    ) throws -> Data {
        let archiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("tdf")

        defer {
            try? FileManager.default.removeItem(at: archiveURL)
        }

        // Create ZIP archive
        let archive: Archive
        do {
            archive = try Archive(url: archiveURL, accessMode: .create)
        } catch {
            throw HLSTDFPackagerError.archiveCreationFailed
        }

        // Add manifest
        try archive.addEntry(
            with: "manifest.json",
            type: .file,
            uncompressedSize: Int64(manifest.count),
            provider: { position, size in
                manifest.subdata(in: Int(position)..<Int(position) + size)
            }
        )

        // Add playlist
        let playlistData = playlist.data(using: .utf8) ?? Data()
        try archive.addEntry(
            with: "playlist.m3u8",
            type: .file,
            uncompressedSize: Int64(playlistData.count),
            provider: { position, size in
                playlistData.subdata(in: Int(position)..<Int(position) + size)
            }
        )

        // Add encrypted segments
        for segment in encryptedSegments {
            try archive.addEntry(
                with: segment.filename,
                type: .file,
                uncompressedSize: Int64(segment.data.count),
                provider: { position, size in
                    segment.data.subdata(in: Int(position)..<Int(position) + size)
                }
            )
        }

        return try Data(contentsOf: archiveURL)
    }
}

/// Errors that can occur during HLS TDF packaging
public enum HLSTDFPackagerError: Error, LocalizedError {
    case archiveCreationFailed
    case manifestCreationFailed(String)
    case segmentEncryptionFailed(index: Int, reason: String)

    public var errorDescription: String? {
        switch self {
        case .archiveCreationFailed:
            "Failed to create TDF archive"
        case let .manifestCreationFailed(reason):
            "Failed to create manifest: \(reason)"
        case let .segmentEncryptionFailed(index, reason):
            "Failed to encrypt segment \(index): \(reason)"
        }
    }
}
