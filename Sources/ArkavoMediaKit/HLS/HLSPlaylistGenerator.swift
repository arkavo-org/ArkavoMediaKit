import Foundation

/// Generates HLS playlists (.m3u8) for Standard TDF-protected content
///
/// Creates HLS manifests that reference .tdf segment files.
/// Each segment URL points to a Standard TDF archive containing encrypted video data.
public struct HLSPlaylistGenerator {
    private let kasBaseURL: URL
    private let cdnBaseURL: URL

    public init(kasBaseURL: URL, cdnBaseURL: URL) {
        self.kasBaseURL = kasBaseURL
        self.cdnBaseURL = cdnBaseURL
    }

    /// Generate master playlist for adaptive bitrate streaming
    public func generateMasterPlaylist(
        variants: [PlaylistVariant]
    ) -> String {
        var lines = [
            "#EXTM3U",
            "#EXT-X-VERSION:6",
        ]

        for variant in variants {
            var streamInf = "#EXT-X-STREAM-INF:BANDWIDTH=\(max(0, variant.bandwidth))"
            if let resolution = Self.sanitizedResolution(variant.resolution) {
                streamInf += ",RESOLUTION=\(resolution)"
            }
            lines.append(streamInf)
            lines.append(Self.sanitizedPlaylistLine(variant.playlistURL.absoluteString))
        }

        return lines.joined(separator: "\n")
    }

    /// Generate media playlist with Standard TDF segment references
    ///
    /// Creates an HLS manifest where each segment is a .tdf file.
    /// The player must implement custom resource loading to extract the encrypted payload from .tdf archives.
    ///
    /// - Parameters:
    ///   - segments: Array of segment metadata (each referencing a .tdf file)
    ///   - assetID: Asset identifier
    ///   - userID: Unused in playlist query parameters (avoid leaking PII in cleartext playlists)
    ///   - sessionID: Unused in playlist query parameters (avoid leaking session IDs in cleartext playlists)
    ///   - targetDuration: Target segment duration in seconds
    ///   - mediaSequence: Starting media sequence number
    /// - Returns: HLS media playlist string (.m3u8)
    public func generateMediaPlaylist(
        segments: [SegmentMetadata],
        assetID: String,
        userID _: String,
        sessionID _: UUID,
        targetDuration: Int = 10,
        mediaSequence: Int = 0
    ) -> String {
        var lines = [
            "#EXTM3U",
            "#EXT-X-VERSION:6",
            "#EXT-X-TARGETDURATION:\(max(1, targetDuration))",
            "#EXT-X-MEDIA-SEQUENCE:\(max(0, mediaSequence))",
        ]

        for segment in segments {
            // For Standard TDF, use a custom key URL without cleartext PII or session identifiers
            if let keyURL = generateKeyURL(assetID: assetID, segmentIndex: segment.index) {
                let sanitizedKeyURI = Self.sanitizedQuotedAttribute(keyURL.absoluteString)
                // RFC 8216 §4.3.2.4: AES-128 IV must be 16 bytes (128-bit); omit non-16-byte IVs (e.g., 12-byte GCM nonces)
                if segment.iv.count == 16 {
                    let ivHex = segment.iv.map { String(format: "%02x", $0) }.joined()
                    lines.append("#EXT-X-KEY:METHOD=AES-128,URI=\"\(sanitizedKeyURI)\",IV=0x\(ivHex)")
                } else {
                    lines.append("#EXT-X-KEY:METHOD=AES-128,URI=\"\(sanitizedKeyURI)\"")
                }
            }

            // Add segment - note this points to a .tdf file, not raw .ts
            let safeDuration = (segment.duration.isFinite && segment.duration >= 0) ? segment.duration : 0
            lines.append("#EXTINF:\(String(format: "%.3f", safeDuration)),")
            lines.append(Self.sanitizedPlaylistLine(segment.url.absoluteString))
        }

        lines.append("#EXT-X-ENDLIST")

        return lines.joined(separator: "\n")
    }

    /// Generate variant playlist (specific bitrate/resolution)
    public func generateVariantPlaylist(
        segments: [SegmentMetadata],
        assetID: String,
        userID: String,
        sessionID: UUID,
        variant: PlaylistVariant
    ) -> String {
        let maxDur = segments.map(\.duration).filter { $0.isFinite && $0 > 0 }.max() ?? 10.0
        return generateMediaPlaylist(
            segments: segments,
            assetID: assetID,
            userID: userID,
            sessionID: sessionID,
            targetDuration: max(1, Int(ceil(maxDur)))
        )
    }

    /// Generate TDF3 key URL for a segment without embedding PII or session IDs in cleartext query parameters
    private func generateKeyURL(
        assetID: String,
        segmentIndex: Int
    ) -> URL? {
        guard var components = URLComponents(url: kasBaseURL, resolvingAgainstBaseURL: false) else {
            return nil
        }
        components.scheme = "tdf3"
        components.path = "/key"
        components.queryItems = [
            URLQueryItem(name: "asset", value: assetID),
            URLQueryItem(name: "segment", value: String(segmentIndex)),
        ]
        return components.url
    }

    /// Validates an HLS decimal-resolution (`<width>x<height>`) to prevent playlist tag injection
    private static func sanitizedResolution(_ resolution: String) -> String? {
        let parts = resolution.split(separator: "x", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let width = Int(parts[0]), width > 0,
              let height = Int(parts[1]), height > 0,
              parts[0].allSatisfy(\.isASCII), parts[0].allSatisfy(\.isNumber),
              parts[1].allSatisfy(\.isASCII), parts[1].allSatisfy(\.isNumber)
        else {
            return nil
        }
        return "\(width)x\(height)"
    }

    private static func sanitizedPlaylistLine(_ value: String) -> String {
        String(value.unicodeScalars.filter { $0 != "\r" && $0 != "\n" && $0 != "\0" })
    }

    private static func sanitizedQuotedAttribute(_ value: String) -> String {
        String(value.unicodeScalars.filter { $0 != "\r" && $0 != "\n" && $0 != "\0" && $0 != "\"" })
    }

    /// Save playlist to file
    public func savePlaylist(_ content: String, to url: URL) throws {
        try content.write(to: url, atomically: true, encoding: .utf8)
    }
}

/// Playlist variant for adaptive bitrate streaming
public struct PlaylistVariant: Sendable {
    public let bandwidth: Int
    public let resolution: String
    public let playlistURL: URL

    public init(bandwidth: Int, resolution: String, playlistURL: URL) {
        self.bandwidth = bandwidth
        self.resolution = resolution
        self.playlistURL = playlistURL
    }
}

extension PlaylistVariant: Codable {}
