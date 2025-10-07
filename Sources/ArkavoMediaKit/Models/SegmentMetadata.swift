import Foundation

/// Metadata for an HLS segment encrypted with Standard TDF
///
/// Each segment is a complete Standard TDF archive (.tdf) containing:
/// - 0.manifest.json: Wrapped DEK, policy, KAS info
/// - 0.payload: AES-256-GCM encrypted video data
public struct SegmentMetadata: Sendable {
    /// Segment index in the playlist
    public let index: Int

    /// Segment duration in seconds
    public let duration: Double

    /// URL to the .tdf segment file (ZIP archive)
    public let url: URL

    /// Standard TDF manifest (base64-encoded JSON)
    ///
    /// Contains the wrapped DEK, policy, and encryption parameters.
    /// The player extracts this to request key unwrapping from KAS.
    public let tdfManifest: String

    /// Initialization vector for AES encryption (for HLS compatibility)
    ///
    /// Extracted from the TDF manifest and exposed for HLS #EXT-X-KEY directives.
    public let iv: Data

    /// Segment creation timestamp
    public let createdAt: Date

    /// Asset identifier this segment belongs to
    public let assetID: String

    public init(
        index: Int,
        duration: Double,
        url: URL,
        tdfManifest: String,
        iv: Data,
        assetID: String
    ) {
        self.index = index
        self.duration = duration
        self.url = url
        self.tdfManifest = tdfManifest
        self.iv = iv
        self.createdAt = Date()
        self.assetID = assetID
    }
}

extension SegmentMetadata: Codable {}
extension SegmentMetadata: Identifiable {
    public var id: Int { index }
}
