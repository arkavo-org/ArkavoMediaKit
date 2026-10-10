import Foundation
import Testing
@testable import ArkavoMediaKit

/// Profile v2 writes each component to its own init segment and media segments, one track each, under its own key
/// (ADR-0055 §5 in arkavo-ios): video 1:9 pattern encrypted, audio whole-block full-sample encrypted.
@Suite("fMP4 component tracks")
struct FMP4ComponentTrackTests {
    let videoKey = Data((0x00 ... 0x0F).map { UInt8($0) })
    let audioKey = Data((0x10 ... 0x1F).map { UInt8($0) })
    let iv = Data((0xF0 ... 0xFF).map { UInt8($0) })
    /// AAC-LC, 48 kHz, mono.
    let audioSpecificConfig = Data([0x11, 0x88])

    private var encryption: FMP4Writer.EncryptionConfig { .init(keyID: Data(count: 16), constantIV: iv) }

    private func videoWriter() -> FMP4Writer {
        FMP4Writer(tracks: [.h264Video(trackID: 1, width: 320, height: 180, timescale: 30_000,
                                       sps: [H264TestStream.sps], pps: [H264TestStream.pps])],
                   encryption: encryption)
    }

    private func audioWriter(trackID: UInt32 = 1) -> FMP4Writer {
        FMP4Writer(tracks: [.aacAudio(trackID: trackID, channelCount: 1, sampleRate: 48_000,
                                      audioSpecificConfig: audioSpecificConfig)],
                   encryption: encryption)
    }

    /// The `mvhd`'s next_track_ID: the box's last four bytes.
    private func nextTrackID(_ initSegment: Data) throws -> UInt32 {
        let bytes = [UInt8](initSegment)
        let moov = try #require(FMP4PackageReader.boxes(bytes, in: 0 ..< bytes.count).first { $0.type == "moov" })
        let mvhd = try FMP4PackageReader.only("mvhd", in: moov, bytes)
        return FMP4PackageReader.be32(bytes, mvhd.end - 4)
    }

    @Test("An init segment's next track id follows its highest track id")
    func nextTrackIDFollowsHighestTrack() throws {
        #expect(try nextTrackID(audioWriter(trackID: 1).generateInitSegment()) == 2)
        #expect(try nextTrackID(videoWriter().generateInitSegment()) == 2)
        // One track whose id is 2, aacAudio's default: tracks.count + 1 would name track 2 again.
        #expect(try nextTrackID(audioWriter(trackID: 2).generateInitSegment()) == 3)
    }

    @Test("The video component's init holds one video track, 1:9 pattern encrypted")
    func videoInit() throws {
        let reader = try FMP4PackageReader(initSegment: videoWriter().generateInitSegment(), segments: [], key: videoKey)
        #expect(reader.tracks.keys.sorted() == [1])
        let track = try #require(reader.tracks[1])
        #expect(track.handler == "vide" && track.sampleEntry == "encv" && track.originalFormat == "avc1")
        #expect(track.tencVersion == 1 && track.cryptBlocks == 1 && track.skipBlocks == 9)
        #expect(track.constantIV == iv)
    }

    @Test("The audio component's init holds one audio track, whole-block full-sample encrypted")
    func audioInit() throws {
        let reader = try FMP4PackageReader(initSegment: audioWriter().generateInitSegment(), segments: [], key: audioKey)
        #expect(reader.tracks.keys.sorted() == [1])
        let track = try #require(reader.tracks[1])
        #expect(track.handler == "soun" && track.sampleEntry == "enca" && track.originalFormat == "mp4a")
        #expect(track.audioObjectType == 2)
        #expect(track.tencVersion == 0 && track.cryptBlocks == 0 && track.skipBlocks == 0)
        #expect(track.constantIV == iv)
    }

    @Test("Each component's segment decrypts under its own key, and not under the other's")
    func segmentsUnderOwnKeys() throws {
        let video = videoWriter(), audio = audioWriter()
        let videoEncryptor = CBCSEncryptor(key: videoKey, iv: iv)
        let audioEncryptor = CBCSEncryptor(key: audioKey, iv: iv)
        let videoPlain = (0 ..< 3).map { index in
            let nal = H264TestStream.slice(isIDR: index == 0, count: 700 + index * 90, filler: UInt8(index + 1))
            return Data(withUnsafeBytes(of: UInt32(nal.count).bigEndian, Array.init)) + nal
        }
        let audioPlain = (0 ..< 5).map { index in
            Data((0 ..< 150 + index * 13).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ index) })
        }
        let videoSamples = try videoPlain.map { plain in
            let result = try videoEncryptor.encryptVideoSample(plain, sliceHeaders: H264TestStream.sliceHeaders())
            return FMP4Writer.Sample(data: result.encryptedData, duration: 1_000, isSync: true,
                                     subsamples: result.subsamples)
        }
        let audioSamples = audioPlain.map { plain in
            FMP4Writer.Sample(data: audioEncryptor.encryptAudioSample(plain).encryptedData, duration: 1_024, isSync: true)
        }
        let videoSegment = video.generateMediaSegment(fragments: [
            FMP4Writer.TrackFragment(trackID: 1, samples: videoSamples, baseDecodeTime: 0),
        ])
        let audioSegment = audio.generateMediaSegment(fragments: [
            FMP4Writer.TrackFragment(trackID: 1, samples: audioSamples, baseDecodeTime: 0),
        ])

        let videoRead = try FMP4PackageReader(initSegment: video.generateInitSegment(), segments: [videoSegment],
                                              key: videoKey)
        let audioRead = try FMP4PackageReader(initSegment: audio.generateInitSegment(), segments: [audioSegment],
                                              key: audioKey)
        #expect(videoRead.samples[1] == videoPlain)
        #expect(audioRead.samples[1] == audioPlain)
        #expect(try #require(videoRead.segments.first).map(\.auxiliaryBoxes) == [["senc", "saiz", "saio"]])
        #expect(try #require(audioRead.segments.first).map(\.auxiliaryBoxes) == [["senc"]])
        #expect(try #require(audioRead.segments.first).map(\.sencFlags) == [0])
        // The keys are independent: neither component reads under the other's key.
        let audioUnderVideoKey = try FMP4PackageReader(initSegment: audio.generateInitSegment(),
                                                       segments: [audioSegment], key: videoKey)
        let videoUnderAudioKey = try FMP4PackageReader(initSegment: video.generateInitSegment(),
                                                       segments: [videoSegment], key: audioKey)
        #expect(audioUnderVideoKey.samples[1] != audioPlain)
        #expect(videoUnderAudioKey.samples[1] != videoPlain)
    }
}
