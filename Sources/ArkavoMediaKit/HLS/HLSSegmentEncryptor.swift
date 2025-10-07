import AVFoundation
import CryptoKit
import Foundation
import OpenTDFKit

/// Encrypts HLS segments with Standard TDF
///
/// Creates .tdf ZIP archives for each video segment (2-10MB typical).
/// Each .tdf contains:
/// - 0.manifest.json: Wrapped DEK, policy, KAS info
/// - 0.payload: AES-256-GCM encrypted segment data
public actor HLSSegmentEncryptor {
    private let kasURL: URL
    private let kasPublicKeyPEM: String
    private let policy: MediaDRMPolicy
    private let policyJSON: Data

    /// Initialize with KAS configuration and policy
    ///
    /// - Parameters:
    ///   - kasURL: KAS server URL
    ///   - kasPublicKeyPEM: RSA public key (2048+ bit)
    ///   - policy: Media DRM policy
    ///   - policyJSON: Standard TDF policy JSON
    public init(
        kasURL: URL,
        kasPublicKeyPEM: String,
        policy: MediaDRMPolicy,
        policyJSON: Data
    ) {
        self.kasURL = kasURL
        self.kasPublicKeyPEM = kasPublicKeyPEM
        self.policy = policy
        self.policyJSON = policyJSON
    }

    /// Encrypt a video segment to Standard TDF format
    ///
    /// - Parameters:
    ///   - segmentData: Raw video segment data (2-10MB typical)
    ///   - assetID: Asset identifier
    ///   - segmentIndex: Segment index
    ///   - duration: Segment duration in seconds
    /// - Returns: TDF archive data and metadata
    /// - Throws: EncryptorError if encryption fails
    public func encryptSegment(
        segmentData: Data,
        assetID: String,
        segmentIndex: Int,
        duration: Double
    ) async throws -> (tdfData: Data, metadata: SegmentMetadata) {
        // Create crypto instance
        let crypto = try StandardTDFSegmentCrypto(
            kasURL: kasURL,
            kasPublicKeyPEM: kasPublicKeyPEM,
            policyJSON: policyJSON,
            mimeType: "video/mp2t"
        )

        // Encrypt segment to .tdf
        let (tdfData, _) = try await crypto.encryptSegment(
            segmentData: segmentData,
            segmentIndex: segmentIndex,
            assetID: assetID
        )

        // Parse manifest for metadata
        let reader = try TDFArchiveReader(data: tdfData)
        let manifest = try reader.manifest()

        // Create segment URL pointing to .tdf file
        let segmentURL = URL(string: "https://cdn.arkavo.net/\(assetID)/segment_\(segmentIndex).tdf")!

        // Encode manifest as base64 for embedding in HLS playlist
        let manifestData = try JSONEncoder().encode(manifest)
        let manifestBase64 = manifestData.base64EncodedString()

        // Extract IV from manifest for HLS compatibility
        let iv = extractIV(from: manifest)

        // Create metadata
        let metadata = SegmentMetadata(
            index: segmentIndex,
            duration: duration,
            url: segmentURL,
            tdfManifest: manifestBase64,
            iv: iv,
            assetID: assetID
        )

        return (tdfData, metadata)
    }

    /// Decrypt a Standard TDF segment
    ///
    /// - Parameters:
    ///   - tdfData: Standard TDF archive data
    ///   - symmetricKey: Symmetric key (from KAS or offline cache)
    /// - Returns: Decrypted segment data
    /// - Throws: EncryptorError if decryption fails
    public func decryptSegment(
        tdfData: Data,
        symmetricKey: SymmetricKey
    ) async throws -> Data {
        let crypto = try StandardTDFSegmentCrypto(
            kasURL: kasURL,
            kasPublicKeyPEM: kasPublicKeyPEM,
            policyJSON: policyJSON
        )

        return try await crypto.decryptSegment(
            tdfData: tdfData,
            symmetricKey: symmetricKey
        )
    }

    /// Batch encrypt multiple segments
    ///
    /// - Parameters:
    ///   - segments: Array of (data, duration) tuples
    ///   - assetID: Asset identifier
    ///   - startIndex: Starting segment index (default: 0)
    /// - Returns: Array of (tdfData, metadata) tuples
    /// - Throws: EncryptorError if any encryption fails
    public func encryptSegments(
        segments: [(data: Data, duration: Double)],
        assetID: String,
        startIndex: Int = 0
    ) async throws -> [(tdfData: Data, metadata: SegmentMetadata)] {
        var results: [(Data, SegmentMetadata)] = []

        for (index, segment) in segments.enumerated() {
            let segmentIndex = startIndex + index
            let result = try await encryptSegment(
                segmentData: segment.data,
                assetID: assetID,
                segmentIndex: segmentIndex,
                duration: segment.duration
            )
            results.append(result)
        }

        return results
    }

    /// Save encrypted segment to file
    ///
    /// - Parameters:
    ///   - tdfData: TDF archive data
    ///   - outputURL: Output file URL (should end in .tdf)
    /// - Throws: EncryptorError if file write fails
    public func saveSegment(tdfData: Data, to outputURL: URL) throws {
        do {
            try tdfData.write(to: outputURL, options: [.atomic])
        } catch {
            throw EncryptorError.fileWriteFailed(error)
        }
    }

    // MARK: - Private Helpers

    private func extractIV(from manifest: TDFManifest) -> Data {
        // Extract IV from manifest for HLS #EXT-X-KEY directive
        // In OpenTDFKit, encryptionInformation and method are non-optional
        let encInfo = manifest.encryptionInformation
        let method = encInfo.method
        let ivString = method.iv

        guard let iv = Data(base64Encoded: ivString) else {
            // Generate random IV if base64 decode fails (fallback)
            var ivData = Data(count: 12)
            _ = ivData.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 12, $0.baseAddress!) }
            return ivData
        }
        return iv
    }
}

/// Encryptor errors
public enum EncryptorError: Error, LocalizedError {
    case invalidHeader
    case invalidData
    case encryptionFailed
    case decryptionFailed
    case fileWriteFailed(Error)

    public var errorDescription: String? {
        switch self {
        case .invalidHeader:
            "Invalid TDF manifest"
        case .invalidData:
            "Invalid encrypted data"
        case .encryptionFailed:
            "Segment encryption failed"
        case .decryptionFailed:
            "Segment decryption failed"
        case let .fileWriteFailed(error):
            "Failed to write segment file: \(error.localizedDescription)"
        }
    }
}
