import Foundation

/// The entries and playlists of a FairPlay package profile v2 archive (ADR-0055 §2, §4 and §10 in arkavo-ios).
///
/// The archive holds `manifest.json` and `master.m3u8`. For each component it holds the media playlist
/// `<id>.m3u8`, the init segment `<id>-init.mp4` and the segments `<id>-segment<N>.m4s`, N from 0. A player is served
/// everything but the manifest.
public enum FairPlayPackage {
    public static let manifestName = "manifest.json"
    public static let masterPlaylistName = "master.m3u8"
    /// The last segment number: a component has at most 4,093 segments.
    public static let maxSegmentIndex = 4_092

    public static func playlistName(_ component: FairPlayComponent) -> String { "\(component.rawValue).m3u8" }

    public static func initName(_ component: FairPlayComponent) -> String { "\(component.rawValue)-init.mp4" }

    public static func segmentName(_ component: FairPlayComponent, index: Int) -> String {
        "\(component.rawValue)-segment\(index).m4s"
    }

    /// The component's key URI, `skd://<policy uuid>/<id>`. Without its scheme it is the SPC content identifier
    /// (ADR-0055 §6).
    public static func keyURI(policyUUID: String, component: FairPlayComponent) -> String {
        "skd://\(policyUUID)/\(component.rawValue)"
    }

    /// Whether a player serves `name` (ADR-0055 §10): the master playlist, and each component's playlist, init segment
    /// and segments. `manifest.json` and every other name are never served.
    public static func isServed(_ name: String) -> Bool {
        name == masterPlaylistName || FairPlayComponent.allCases.contains { component in
            name == playlistName(component) || name == initName(component) || segmentIndex(of: name, component) != nil
        }
    }

    /// N of `<id>-segment<N>.m4s`: decimal, without a leading zero, at most `maxSegmentIndex`.
    static func segmentIndex(of name: String, _ component: FairPlayComponent) -> Int? {
        let prefix = "\(component.rawValue)-segment", suffix = ".m4s"
        guard name.hasPrefix(prefix), name.hasSuffix(suffix), name.count > prefix.count + suffix.count else {
            return nil
        }
        let digits = name.dropFirst(prefix.count).dropLast(suffix.count)
        guard digits.allSatisfy({ ("0" ... "9").contains($0) }), digits == "0" || digits.first != "0",
              let index = Int(digits), index <= maxSegmentIndex else { return nil }
        return index
    }

    // MARK: - Playlists

    /// A component's media playlist: ADR-0047 §3's, with this component's init, its segments in order and the
    /// video's `#EXTINF` durations and target duration, and its own `skd://` key with the package's IV.
    static func mediaPlaylist(component: FairPlayComponent, policyUUID: String, iv: Data, durations: [Double],
                              targetDuration: Int) -> String {
        let generator = FMP4HLSGenerator(
            config: FMP4HLSGenerator.PlaylistConfig(targetDuration: targetDuration, playlistType: .vod,
                                                    initSegmentURI: initName(component)),
            encryption: FMP4HLSGenerator.FairPlayConfig(
                keyURI: keyURI(policyUUID: policyUUID, component: component), keyID: Data(count: 16), iv: iv))
        return generator.generateMediaPlaylist(segments: durations.enumerated().map { index, duration in
            FMP4HLSGenerator.Segment(uri: segmentName(component, index: index), duration: duration)
        })
    }

    /// What the master playlist states about the media (ADR-0055 §4).
    struct MasterPlaylist: Equatable {
        /// The video's peak segment bit rate plus the audio's (`bandwidth(segmentBytes:durations:)`).
        let bandwidth: Int
        /// The whole presentation's bit rate, video and audio together.
        let averageBandwidth: Int
        /// `avc1.PPCCLL`.
        let videoCodec: String
        let width: Int
        let height: Int
        let frameRate: Double
        /// The audio's channel count (`channelCount(ofAudioSpecificConfig:)`: 1-6 or 8); nil for a package without sound.
        let audioChannels: Int?
    }

    /// The master playlist: one variant, `video.m3u8`, and with sound one audio rendition, `audio.m3u8`.
    /// Nil when `audioChannels` is not a supported count (1-6 or 8): CHANNELS is never written for another number.
    static func masterPlaylist(_ master: MasterPlaylist) -> String? {
        if let channels = master.audioChannels, !supportedChannelCounts.contains(channels) { return nil }
        let audio = master.audioChannels.map { channels in
            [FMP4HLSGenerator.AudioRendition(groupID: "audio", name: "Audio", language: "und", channels: channels,
                                             uri: playlistName(.audio))]
        } ?? []
        let variant = FMP4HLSGenerator.Variant(
            uri: playlistName(.video),
            bandwidth: master.bandwidth,
            averageBandwidth: master.averageBandwidth,
            codecs: master.audioChannels == nil ? master.videoCodec : master.videoCodec + ",mp4a.40.2",
            resolution: FMP4HLSGenerator.Variant.Resolution(width: master.width, height: master.height),
            frameRate: master.frameRate,
            audioGroup: master.audioChannels == nil ? nil : "audio")
        return FMP4HLSGenerator(config: FMP4HLSGenerator.PlaylistConfig(targetDuration: 1))
            .generateMasterPlaylist(variants: [variant], audio: audio)
    }

    // MARK: - Measurements

    /// `BANDWIDTH` and `AVERAGE-BANDWIDTH` in bits per second, each rounded up and at least 1.
    /// - `segmentBytes[C][N]`: component C's segment N's size; every component's segment N spans `durations[N]`.
    /// - Each component is its own rendition, so (RFC 8216 §4.3.4.2) the peak is the sum of each component's peak
    ///   segment rate, wherever each falls, and the average the sum of their averages: video plus audio.
    /// - A component's peak is never below its average. A segment without duration has no rate.
    static func bandwidth(segmentBytes components: [[Int]], durations: [Double]) -> (peak: Int, average: Int) {
        let total = durations.reduce(0, +)
        var peak = 0.0, average = 0.0
        for segmentBytes in components {
            let componentAverage = total > 0 ? Double(segmentBytes.reduce(0, +) * 8) / total : 0
            let rates = zip(segmentBytes, durations).filter { $0.1 > 0 }.map { Double($0.0 * 8) / $0.1 }
            peak += max(rates.max() ?? 0, componentAverage)
            average += componentAverage
        }
        return (max(1, Int(peak.rounded(.up))), max(1, Int(average.rounded(.up))))
    }

    /// `avc1.PPCCLL` (RFC 6381): an SPS NAL unit's profile_idc, constraint flags and level_idc, in upper-case
    /// hexadecimal. Nil unless `sps` is an SPS (NAL unit type 7) of at least four bytes.
    static func avc1Codec(sps: Data) -> String? {
        let bytes = [UInt8](sps)
        guard bytes.count >= 4, bytes[0] & 0x1F == 7 else { return nil }
        return "avc1." + bytes[1 ... 3].map { String(format: "%02X", $0) }.joined()
    }

    /// An AudioSpecificConfig's channelConfiguration (ISO/IEC 14496-3 §1.6.2.1): after the 5-bit object type (and its
    /// 6-bit escape) and the 4-bit sampling frequency index (and its 24-bit explicit frequency). 0 means a program
    /// config element sets the channels. Nil when the bytes end first. This is the raw index, not a count: see
    /// `channelCount(ofAudioSpecificConfig:)`.
    static func channelConfiguration(ofAudioSpecificConfig config: Data) -> Int? {
        let bytes = [UInt8](config)
        var position = 0
        func read(_ count: Int) -> Int? {
            guard position + count <= bytes.count * 8 else { return nil }
            var value = 0
            for _ in 0 ..< count {
                value = value << 1 | Int(bytes[position / 8] >> (7 - position % 8) & 1)
                position += 1
            }
            return value
        }
        guard let objectType = read(5) else { return nil }
        if objectType == 31, read(6) == nil { return nil }
        guard let frequencyIndex = read(4) else { return nil }
        if frequencyIndex == 15, read(24) == nil { return nil }
        return read(4)
    }

    /// The channel counts a package's audio may state (ADR-0055 §4): 1-6 and 8 (7.1).
    static let supportedChannelCounts: Set<Int> = [1, 2, 3, 4, 5, 6, 8]

    /// An AudioSpecificConfig's channel count, which is what the master playlist's CHANNELS states: channelConfiguration
    /// 1-6 are 1-6 channels and 7 is 8 (7.1). Nil for configuration 0 (a program config element sets the channels),
    /// the reserved 8-15, and bytes that end first; the caller refuses the audio before writing any playlist.
    static func channelCount(ofAudioSpecificConfig config: Data) -> Int? {
        switch channelConfiguration(ofAudioSpecificConfig: config) {
        case let configuration? where (1 ... 6).contains(configuration): configuration
        case 7?: 8
        default: nil
        }
    }
}
