import Foundation

// MARK: - fMP4 HLS Generator

/// Generates HLS playlists for fMP4 FairPlay content
public final class FMP4HLSGenerator {
    // MARK: - Types

    /// Segment information for playlist
    public struct Segment {
        public let uri: String
        public let duration: Double
        public let byteRange: ByteRange?
        public let encryption: FairPlayConfig?  // Per-segment encryption (nil = inherit playlist default)

        public struct ByteRange {
            public let length: Int
            public let offset: Int
        }

        public init(uri: String, duration: Double, byteRange: ByteRange? = nil, encryption: FairPlayConfig? = nil) {
            self.uri = uri
            self.duration = duration
            self.byteRange = byteRange
            self.encryption = encryption
        }
    }

    /// FairPlay encryption configuration
    public struct FairPlayConfig: Equatable {
        public let keyURI: String      // skd:// URI
        public let keyID: Data         // 16-byte key ID
        public let iv: Data?           // Optional IV (for explicit IV mode)

        public init(keyURI: String, keyID: Data, iv: Data? = nil) {
            self.keyURI = keyURI
            self.keyID = keyID
            self.iv = iv
        }

        /// Create FairPlay config with asset ID
        public static func fairPlay(assetID: String, keyID: Data, iv: Data? = nil) -> FairPlayConfig {
            FairPlayConfig(keyURI: "skd://\(assetID)", keyID: keyID, iv: iv)
        }

        public static func == (lhs: FairPlayConfig, rhs: FairPlayConfig) -> Bool {
            lhs.keyURI == rhs.keyURI && lhs.keyID == rhs.keyID && lhs.iv == rhs.iv
        }
    }

    /// Playlist configuration
    public struct PlaylistConfig {
        public let targetDuration: Int
        public let playlistType: PlaylistType
        public let independentSegments: Bool
        public let initSegmentURI: String

        public enum PlaylistType {
            case vod
            case event
            case live
        }

        public init(targetDuration: Int,
                    playlistType: PlaylistType = .vod,
                    independentSegments: Bool = true,
                    initSegmentURI: String = "init.mp4") {
            self.targetDuration = targetDuration
            self.playlistType = playlistType
            self.independentSegments = independentSegments
            self.initSegmentURI = initSegmentURI
        }
    }

    // MARK: - Properties

    private let config: PlaylistConfig
    private let encryption: FairPlayConfig?

    // MARK: - Initialization

    public init(config: PlaylistConfig, encryption: FairPlayConfig? = nil) {
        self.config = config
        self.encryption = encryption
    }

    // MARK: - Media Playlist Generation

    /// Generate media playlist for fMP4 segments
    /// Supports per-segment encryption state changes for key rotation and clear/encrypted transitions
    public func generateMediaPlaylist(segments: [Segment]) -> String {
        var lines: [String] = []

        // Header
        lines.append("#EXTM3U")
        lines.append("#EXT-X-VERSION:7") // Version 7 for fMP4

        // Target duration
        lines.append("#EXT-X-TARGETDURATION:\(config.targetDuration)")

        // Media sequence
        lines.append("#EXT-X-MEDIA-SEQUENCE:0")

        // Playlist type
        switch config.playlistType {
        case .vod:
            lines.append("#EXT-X-PLAYLIST-TYPE:VOD")
        case .event:
            lines.append("#EXT-X-PLAYLIST-TYPE:EVENT")
        case .live:
            break // No type tag for live
        }

        // Independent segments
        if config.independentSegments {
            lines.append("#EXT-X-INDEPENDENT-SEGMENTS")
        }

        // Track encryption state for per-segment key changes
        var currentEncryption: FairPlayConfig? = nil

        // Check if any segment has explicit per-segment encryption
        let hasPerSegmentEncryption = segments.contains { $0.encryption != nil }

        // Emit playlist-level encryption key if set
        if let enc = encryption {
            lines.append(generateKeyTag(enc))
            currentEncryption = enc
        }

        // Init segment (MAP)
        lines.append("#EXT-X-MAP:URI=\"\(config.initSegmentURI)\"")

        // Segments with per-segment encryption state tracking
        for segment in segments {
            // Determine effective encryption for this segment:
            // - If segment has explicit encryption, use it
            // - If segment has nil encryption AND there's per-segment encryption in playlist, treat as clear
            // - If segment has nil encryption AND no per-segment encryption, inherit playlist default
            let effectiveEncryption: FairPlayConfig?
            if let segEnc = segment.encryption {
                // Explicit per-segment encryption
                effectiveEncryption = segEnc
            } else if hasPerSegmentEncryption {
                // Segment is explicitly clear (nil in a playlist with per-segment encryption)
                effectiveEncryption = nil
            } else {
                // Inherit playlist-level encryption (nil means "use default")
                effectiveEncryption = encryption
            }

            // Check for encryption state change
            if effectiveEncryption != currentEncryption {
                if let enc = effectiveEncryption {
                    // Transition to encrypted or new key
                    lines.append(generateKeyTag(enc))
                } else {
                    // Transition to clear
                    lines.append("#EXT-X-KEY:METHOD=NONE")
                }
                currentEncryption = effectiveEncryption
            }

            // Duration
            lines.append("#EXTINF:\(String(format: "%.5f", segment.duration)),")

            // Byte range (if applicable)
            if let range = segment.byteRange {
                lines.append("#EXT-X-BYTERANGE:\(range.length)@\(range.offset)")
            }

            // URI
            lines.append(segment.uri)
        }

        // End tag for VOD
        if config.playlistType == .vod {
            lines.append("#EXT-X-ENDLIST")
        }

        return lines.joined(separator: "\n")
    }

    /// Generate EXT-X-KEY tag for FairPlay CBCS
    private func generateKeyTag(_ fairplay: FairPlayConfig) -> String {
        var tag = "#EXT-X-KEY:METHOD=SAMPLE-AES"

        // URI (skd:// for FairPlay)
        tag += ",URI=\"\(fairplay.keyURI)\""

        // Key format
        tag += ",KEYFORMAT=\"com.apple.streamingkeydelivery\""

        // Key format versions
        tag += ",KEYFORMATVERSIONS=\"1\""

        // IV (if explicit)
        if let iv = fairplay.iv {
            tag += ",IV=0x\(iv.hexString)"
        }

        return tag
    }

    // MARK: - Master Playlist Generation

    /// Generate master playlist with variants
    public func generateMasterPlaylist(variants: [Variant]) -> String {
        var lines: [String] = []

        // Header
        lines.append("#EXTM3U")
        lines.append("#EXT-X-VERSION:7")

        // Independent segments
        if config.independentSegments {
            lines.append("#EXT-X-INDEPENDENT-SEGMENTS")
        }

        // Variants
        for variant in variants {
            lines.append(generateStreamInf(variant))
            lines.append(variant.uri)
        }

        return lines.joined(separator: "\n")
    }

    /// Variant stream configuration
    public struct Variant {
        public let uri: String
        public let bandwidth: Int
        public let averageBandwidth: Int?
        public let codecs: String
        public let resolution: Resolution?
        public let frameRate: Double?
        public let audioGroup: String?

        public struct Resolution {
            public let width: Int
            public let height: Int

            public init(width: Int, height: Int) {
                self.width = width
                self.height = height
            }
        }

        public init(uri: String,
                    bandwidth: Int,
                    averageBandwidth: Int? = nil,
                    codecs: String,
                    resolution: Resolution? = nil,
                    frameRate: Double? = nil,
                    audioGroup: String? = nil) {
            self.uri = uri
            self.bandwidth = bandwidth
            self.averageBandwidth = averageBandwidth
            self.codecs = codecs
            self.resolution = resolution
            self.frameRate = frameRate
            self.audioGroup = audioGroup
        }

        /// Create H.264 video variant
        public static func h264(uri: String,
                                bandwidth: Int,
                                width: Int,
                                height: Int,
                                profile: String = "avc1.640028", // High profile L4.0
                                frameRate: Double = 30) -> Variant {
            Variant(
                uri: uri,
                bandwidth: bandwidth,
                codecs: "\(profile),mp4a.40.2",
                resolution: Resolution(width: width, height: height),
                frameRate: frameRate
            )
        }

        /// Create HEVC video variant
        public static func hevc(uri: String,
                                bandwidth: Int,
                                width: Int,
                                height: Int,
                                profile: String = "hvc1.1.6.L120.90", // Main profile L4.0
                                frameRate: Double = 30) -> Variant {
            Variant(
                uri: uri,
                bandwidth: bandwidth,
                codecs: "\(profile),mp4a.40.2",
                resolution: Resolution(width: width, height: height),
                frameRate: frameRate
            )
        }
    }

    private func generateStreamInf(_ variant: Variant) -> String {
        var tag = "#EXT-X-STREAM-INF:BANDWIDTH=\(variant.bandwidth)"

        if let avgBw = variant.averageBandwidth {
            tag += ",AVERAGE-BANDWIDTH=\(avgBw)"
        }

        tag += ",CODECS=\"\(variant.codecs)\""

        if let res = variant.resolution {
            tag += ",RESOLUTION=\(res.width)x\(res.height)"
        }

        if let fps = variant.frameRate {
            tag += ",FRAME-RATE=\(String(format: "%.3f", fps))"
        }

        if let audio = variant.audioGroup {
            tag += ",AUDIO=\"\(audio)\""
        }

        return tag
    }
}

// MARK: - Data Extensions

extension Data {
    /// Convert data to hex string (uppercase for HLS IV compatibility)
    var hexString: String {
        map { String(format: "%02X", $0) }.joined()
    }
}

// MARK: - Convenience

extension FMP4HLSGenerator {
    /// Create generator for single-bitrate VOD content
    public static func vodGenerator(targetDuration: Int,
                                    initSegment: String = "init.mp4",
                                    assetID: String? = nil,
                                    keyID: Data? = nil) -> FMP4HLSGenerator {
        let config = PlaylistConfig(
            targetDuration: targetDuration,
            playlistType: .vod,
            initSegmentURI: initSegment
        )

        let encryption: FairPlayConfig?
        if let assetID = assetID, let keyID = keyID {
            encryption = .fairPlay(assetID: assetID, keyID: keyID)
        } else {
            encryption = nil
        }

        return FMP4HLSGenerator(config: config, encryption: encryption)
    }

    /// Generate playlist from segment durations
    public func generatePlaylist(segmentDurations: [Double],
                                 segmentPrefix: String = "segment",
                                 segmentExtension: String = "m4s") -> String {
        let segments = segmentDurations.enumerated().map { index, duration in
            Segment(uri: "\(segmentPrefix)\(index + 1).\(segmentExtension)", duration: duration)
        }
        return generateMediaPlaylist(segments: segments)
    }
}
