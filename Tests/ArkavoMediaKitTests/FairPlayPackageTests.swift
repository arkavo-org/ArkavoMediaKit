import Foundation
import Testing
@testable import ArkavoMediaKit

/// Profile v2's entry names and playlists (ADR-0055 §2, §4, §10 in arkavo-ios), pinned to the shared package vectors of
/// the coordinating plan.
@Suite("FairPlayPackage")
struct FairPlayPackageTests {
    static let uuid = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b"
    static let iv = Data((0xF0 ... 0xFF).map { UInt8($0) })
    static let durations = [6.0, 6.0, 4.5]

    @Test("The master playlist of a package with sound is the shared vector")
    func masterWithAudio() {
        let master = FairPlayPackage.masterPlaylist(.init(
            bandwidth: 2_500_000, averageBandwidth: 2_000_000, videoCodec: "avc1.640028",
            width: 1920, height: 1080, frameRate: 30, audioChannels: 2))
        #expect(master == [
            "#EXTM3U",
            "#EXT-X-VERSION:7",
            "#EXT-X-INDEPENDENT-SEGMENTS",
            #"#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="Audio",LANGUAGE="und",DEFAULT=YES,AUTOSELECT=YES,CHANNELS="2",URI="audio.m3u8""#,
            #"#EXT-X-STREAM-INF:BANDWIDTH=2500000,AVERAGE-BANDWIDTH=2000000,CODECS="avc1.640028,mp4a.40.2",RESOLUTION=1920x1080,FRAME-RATE=30.000,AUDIO="audio""#,
            "video.m3u8",
        ].joined(separator: "\n"))
    }

    @Test("The master playlist of a package without sound has no rendition, no audio codec and no AUDIO")
    func masterWithoutAudio() {
        let master = FairPlayPackage.masterPlaylist(.init(
            bandwidth: 2_400_000, averageBandwidth: 1_900_000, videoCodec: "avc1.640028",
            width: 1920, height: 1080, frameRate: 30, audioChannels: nil))
        #expect(master == [
            "#EXTM3U",
            "#EXT-X-VERSION:7",
            "#EXT-X-INDEPENDENT-SEGMENTS",
            #"#EXT-X-STREAM-INF:BANDWIDTH=2400000,AVERAGE-BANDWIDTH=1900000,CODECS="avc1.640028",RESOLUTION=1920x1080,FRAME-RATE=30.000"#,
            "video.m3u8",
        ].joined(separator: "\n"))
    }

    /// The shared vector, with the IV in RFC 8216's upper-case hexadecimal.
    @Test("A component's media playlist names its init, its segments and its own skd:// key")
    func mediaPlaylists() {
        for component in FairPlayComponent.allCases {
            let id = component.rawValue
            let playlist = FairPlayPackage.mediaPlaylist(component: component, policyUUID: Self.uuid, iv: Self.iv,
                                                         durations: Self.durations, targetDuration: 6)
            #expect(playlist == [
                "#EXTM3U",
                "#EXT-X-VERSION:7",
                "#EXT-X-TARGETDURATION:6",
                "#EXT-X-MEDIA-SEQUENCE:0",
                "#EXT-X-PLAYLIST-TYPE:VOD",
                "#EXT-X-INDEPENDENT-SEGMENTS",
                #"#EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b/\#(id)",KEYFORMAT="com.apple.streamingkeydelivery",KEYFORMATVERSIONS="1",IV=0xF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"#,
                #"#EXT-X-MAP:URI="\#(id)-init.mp4""#,
                "#EXTINF:6.00000,",
                "\(id)-segment0.m4s",
                "#EXTINF:6.00000,",
                "\(id)-segment1.m4s",
                "#EXTINF:4.50000,",
                "\(id)-segment2.m4s",
                "#EXT-X-ENDLIST",
            ].joined(separator: "\n"), "\(id)")
        }
    }

    @Test("Entry names and key URIs follow the component id")
    func names() {
        #expect(FairPlayPackage.manifestName == "manifest.json")
        #expect(FairPlayPackage.masterPlaylistName == "master.m3u8")
        #expect(FairPlayPackage.playlistName(.audio) == "audio.m3u8")
        #expect(FairPlayPackage.initName(.video) == "video-init.mp4")
        #expect(FairPlayPackage.segmentName(.audio, index: 12) == "audio-segment12.m4s")
        #expect(FairPlayPackage.keyURI(policyUUID: Self.uuid, component: .video) == "skd://\(Self.uuid)/video")
    }

    @Test("A player serves the playlists, inits and segments, and never the manifest")
    func served() {
        for name in ["master.m3u8", "video.m3u8", "audio.m3u8", "video-init.mp4", "audio-init.mp4",
                     "video-segment0.m4s", "audio-segment4092.m4s"] {
            #expect(FairPlayPackage.isServed(name), "\(name)")
        }
        for name in ["manifest.json", "playlist.m3u8", "init.mp4", "segment0.m4s", "video-segment01.m4s",
                     "video-segment4093.m4s", "video-segment.m4s", "video-segment-1.m4s", "../video.m3u8",
                     "subtitles.m3u8", "Video.m3u8", "video-segment0.m4s.tmp"] {
            #expect(!FairPlayPackage.isServed(name), "\(name)")
        }
    }

    @Test("BANDWIDTH is the peak segment bit rate and AVERAGE-BANDWIDTH the presentation's, rounded up")
    func bandwidth() {
        let rates = FairPlayPackage.bandwidth(segmentBytes: [750_000, 750_000, 400_000], durations: [6, 6, 4.5])
        #expect(rates.peak == 1_000_000)
        #expect(rates.average == 921_213)  // 15,200,000 bits over 16.5 s
        // A zero-length segment has no rate of its own; the peak is never below the average.
        let degenerate = FairPlayPackage.bandwidth(segmentBytes: [100, 200], durations: [0, 2])
        #expect(degenerate.peak == 1_200 && degenerate.average == 1_200)
    }

    @Test("CODECS names the SPS's profile, constraints and level in upper-case hexadecimal")
    func avc1Codec() {
        #expect(FairPlayPackage.avc1Codec(sps: Data([0x67, 0x64, 0x00, 0x28, 0xAC])) == "avc1.640028")
        #expect(FairPlayPackage.avc1Codec(sps: Data([0x67, 0x4D, 0x40, 0x1F])) == "avc1.4D401F")
        #expect(FairPlayPackage.avc1Codec(sps: Data([0x68, 0x4D, 0x40, 0x1F])) == nil, "a PPS, not an SPS")
        #expect(FairPlayPackage.avc1Codec(sps: Data([0x67, 0x4D])) == nil)
    }

    @Test("CHANNELS is the AudioSpecificConfig's channel configuration")
    func channels() {
        #expect(FairPlayPackage.channelConfiguration(ofAudioSpecificConfig: Data([0x11, 0x88])) == 1)  // 48 kHz mono
        #expect(FairPlayPackage.channelConfiguration(ofAudioSpecificConfig: Data([0x11, 0x90])) == 2)  // 48 kHz stereo
        #expect(FairPlayPackage.channelConfiguration(ofAudioSpecificConfig: Data([0x12, 0x10])) == 2)  // 44.1 kHz stereo
        // An explicit 24-bit sampling frequency (index 15) comes before the channels.
        #expect(FairPlayPackage.channelConfiguration(ofAudioSpecificConfig: Data([0x17, 0x80, 0x5D, 0xC0, 0x10])) == 2)
        #expect(FairPlayPackage.channelConfiguration(ofAudioSpecificConfig: Data([0x11, 0x80])) == 0)  // set by a PCE
        #expect(FairPlayPackage.channelConfiguration(ofAudioSpecificConfig: Data([0x11])) == nil)
    }
}
