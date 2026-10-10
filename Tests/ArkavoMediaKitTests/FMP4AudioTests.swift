import Foundation
import Testing
@testable import ArkavoMediaKit

/// An AAC track beside the H.264 track: ISO/IEC 23001-7 `cbcs` protects tracks other than video by whole-block
/// full-sample encryption, so its `tenc` has no pattern (version 0, 0:0) and, with a constant IV, its fragments carry
/// no sample auxiliary information (a `senc` without entries, and no `saiz` or `saio`), as Shaka Packager writes it.
@Suite("fMP4 AAC track")
struct FMP4AudioTests {
    let key = Data((0 ..< 16).map { UInt8($0 &* 11 &+ 1) })
    let iv = Data((0 ..< 16).map { UInt8(0x80 &+ $0 &* 3) })
    /// AAC-LC, 48 kHz, mono.
    let audioSpecificConfig = Data([0x11, 0x88])

    private func writer() -> FMP4Writer {
        let video = FMP4Writer.TrackConfig.h264Video(width: 320, height: 180, timescale: 30_000,
                                                     sps: [H264TestStream.sps], pps: [H264TestStream.pps])
        let audio = FMP4Writer.TrackConfig.aacAudio(channelCount: 1, sampleRate: 48_000,
                                                    audioSpecificConfig: audioSpecificConfig)
        return FMP4Writer(tracks: [video, audio],
                          encryption: FMP4Writer.EncryptionConfig(keyID: Data(count: 16), constantIV: iv))
    }

    @Test("The init segment protects the AAC track full-sample and the video track 1:9")
    func initSegment() throws {
        let reader = try FMP4PackageReader(initSegment: writer().generateInitSegment(), segments: [], key: key)

        let audio = try #require(reader.tracks[2])
        #expect(audio.handler == "soun")
        #expect(audio.sampleEntry == "enca")
        #expect(audio.originalFormat == "mp4a")
        #expect(audio.audioObjectType == 2)
        #expect(audio.tencVersion == 0)
        #expect(audio.cryptBlocks == 0 && audio.skipBlocks == 0)
        #expect(audio.constantIV == iv)
        let video = try #require(reader.tracks[1])
        #expect(video.tencVersion == 1)
        #expect(video.cryptBlocks == 1 && video.skipBlocks == 9)
        #expect(video.constantIV == iv)
    }

    @Test("A muxed segment holds a fragment per track, and each decrypts to its plaintext")
    func muxedSegment() throws {
        let encryptor = CBCSEncryptor(key: key, iv: iv)
        let videoPlain = (0 ..< 3).map { index in
            let nal = H264TestStream.slice(isIDR: index == 0, count: 700 + index * 90, filler: UInt8(index + 1))
            return Data(withUnsafeBytes(of: UInt32(nal.count).bigEndian, Array.init)) + nal
        }
        let audioPlain = (0 ..< 5).map { index in
            Data((0 ..< 150 + index * 13).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ index) })
        }
        let videoSamples = try videoPlain.map { plain in
            let result = try encryptor.encryptVideoSample(plain, sliceHeaders: H264TestStream.sliceHeaders())
            return FMP4Writer.Sample(data: result.encryptedData, duration: 1_000, isSync: true,
                                     subsamples: result.subsamples)
        }
        let audioSamples = audioPlain.map { plain in
            let result = encryptor.encryptAudioSample(plain)
            return FMP4Writer.Sample(data: result.encryptedData, duration: 1_024, isSync: true,
                                     subsamples: result.subsamples)
        }
        let writer = writer()

        let segment = writer.generateMediaSegment(fragments: [
            FMP4Writer.TrackFragment(trackID: 1, samples: videoSamples, baseDecodeTime: 3_000),
            FMP4Writer.TrackFragment(trackID: 2, samples: audioSamples, baseDecodeTime: 5_120),
        ])

        let reader = try FMP4PackageReader(initSegment: writer.generateInitSegment(), segments: [segment], key: key)
        let fragments = try #require(reader.segments.first)
        #expect(fragments.map(\.trackID) == [1, 2])
        #expect(fragments.map(\.baseDecodeTime) == [3_000, 5_120])
        #expect(fragments[0].auxiliaryBoxes == ["senc", "saiz", "saio"])
        #expect(fragments[0].sencFlags == 2)
        #expect(fragments[1].auxiliaryBoxes == ["senc"])
        #expect(fragments[1].sencFlags == 0)
        #expect(reader.samples[1] == videoPlain)
        #expect(reader.samples[2] == audioPlain)
    }

    @Test("An audio sample has no subsamples: the whole sample is protected")
    func audioHasNoSubsamples() {
        let result = CBCSEncryptor(key: key, iv: iv).encryptAudioSample(Data(repeating: 0x42, count: 100))
        #expect(result.subsamples.isEmpty)
    }
}
