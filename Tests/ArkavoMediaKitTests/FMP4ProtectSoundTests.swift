import AVFoundation
import Foundation
import OpenTDFKit
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

/// A recording with sound is protected with its sound: profile v1 requires encrypted AAC-LC audio whenever the source
/// has sound (ADR-0047 in arkavo-ios), so the archive carries the AAC track, and both tracks decrypt, as a player
/// decrypts them, to the source's samples.
@Suite("FMP4RecordingProtectionService with sound")
struct FMP4ProtectSoundTests {
    static let kasURL = URL(string: "https://platform.arkavo.net")!

    private struct Protected {
        let archive: Data
        let files: [String: Data]
        let key: Data
        let movie: URL
    }

    private func protect(_ sound: SyntheticMovie.Sound, frames: Int, in dir: URL, policyJSON: Data? = nil,
                         audioDelay: Double = 0, soundExtra: Double = 0) async throws -> Protected {
        let kas = try TestKASKeyPair()
        var movie = try await SyntheticMovie.make(in: dir, frames: frames, sound: sound, soundExtra: soundExtra)
        if audioDelay > 0 { movie = try await SyntheticMovie.delayingAudio(of: movie, by: audioDelay, in: dir) }
        let service = FMP4RecordingProtectionService(kasURL: Self.kasURL, kasPublicKeyPEM: kas.spkiPublicKeyPEM)
        let (archive, _) = try await StdoutCapture.capture {
            try await service.protectVideo(videoURL: movie, assetID: "recording-with-sound", policyJSON: policyJSON)
        }
        let zip = try Archive(data: archive, accessMode: .read)
        var files: [String: Data] = [:]
        for entry in zip {
            var data = Data()
            _ = try zip.extract(entry) { data.append($0) }
            files[entry.path] = data
        }
        let manifestData = try #require(files["manifest.json"])
        let manifest = try #require(JSONSerialization.jsonObject(with: manifestData) as? [String: Any])
        let info = try #require(manifest["encryptionInformation"] as? [String: Any])
        let kao = try #require((info["keyAccess"] as? [[String: Any]])?.first)
        let key = TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: kas.privateKeyPEM, wrappedKey: try #require(kao["wrappedKey"] as? String)))
        return Protected(archive: archive, files: files, key: key, movie: movie)
    }

    private func directory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-sound-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// The playlist's segments, in order.
    private func segments(_ files: [String: Data]) throws -> [Data] {
        let playlist = String(decoding: try #require(files["playlist.m3u8"]), as: UTF8.self)
        return try playlist.split(separator: "\n").filter { $0.hasSuffix(".m4s") }.map {
            try #require(files[String($0)])
        }
    }

    /// Every sample of the source's first track of `type`, as stored: one per AAC packet.
    private func sourceSamples(_ movie: URL, _ type: AVMediaType) async throws -> [Data] {
        let asset = AVURLAsset(url: movie)
        let track = try #require(try await asset.loadTracks(withMediaType: type).first)
        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderTrackOutput(track: track, outputSettings: nil)
        reader.add(output)
        #expect(reader.startReading())
        var samples: [Data] = []
        while let buffer = output.copyNextSampleBuffer() {
            guard let block = CMSampleBufferGetDataBuffer(buffer) else { continue }
            var bytes = [UInt8](repeating: 0, count: CMBlockBufferGetDataLength(block))
            #expect(CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: bytes.count,
                                               destination: &bytes) == noErr)
            var sizes = [Int](repeating: 0, count: CMSampleBufferGetNumSamples(buffer))
            var count = 0
            if CMSampleBufferGetSampleSizeArray(buffer, entryCount: sizes.count, arrayToFill: &sizes,
                                                entriesNeededOut: &count) != noErr || count == 1 && sizes.count > 1 {
                sizes = Array(repeating: bytes.count / sizes.count, count: sizes.count)
            }
            var offset = 0
            for size in sizes {
                samples.append(Data(bytes[offset ..< offset + size]))
                offset += size
            }
        }
        #expect(reader.status == .completed)
        return samples
    }

    /// Writes a protected archive, its entries and its content key to `ARKAVO_DUMP_PACKAGE_DIR`, for other tools: the
    /// viewer's package reader, and other decryptors. The policy carries a bound classification, as Creator writes.
    @Test("Dump a protected archive with sound", .enabled(if: ProcessInfo.processInfo.environment["ARKAVO_DUMP_PACKAGE_DIR"] != nil))
    func dump() async throws {
        let out = URL(fileURLWithPath: try #require(ProcessInfo.processInfo.environment["ARKAVO_DUMP_PACKAGE_DIR"]))
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let policy = #"{"arkavo:classification":{"filter":"passed","flagged":[],"v":1},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"0f3c2a1b-5d6e-4f70-8a9b-c1d2e3f4a5b6"}"#
        let protected = try await protect(.aac(tracks: 1), frames: 240, in: dir, policyJSON: Data(policy.utf8))
        try protected.archive.write(to: out.appendingPathComponent("archive.tdf"))
        for (name, data) in protected.files { try data.write(to: out.appendingPathComponent(name)) }
        try protected.key.map { String(format: "%02x", $0) }.joined().write(
            to: out.appendingPathComponent("key.hex"), atomically: true, encoding: .utf8)
        try FileManager.default.copyItem(at: protected.movie, to: out.appendingPathComponent("source.mov"))
    }

    @Test("A recording with an AAC track is protected with it, and both tracks decrypt to the source")
    func aacTrack() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        // 8 s: two segments, so the audio is split at a segment boundary.
        let protected = try await protect(.aac(tracks: 1), frames: 240, in: dir)

        let reader = try FMP4PackageReader(initSegment: try #require(protected.files["init.mp4"]),
                                           segments: try segments(protected.files), key: protected.key)

        let audio = try #require(reader.tracks[2])
        #expect(audio.sampleEntry == "enca" && audio.audioObjectType == 2)
        #expect(audio.tencVersion == 0 && audio.cryptBlocks == 0 && audio.skipBlocks == 0)
        #expect(reader.segments.count == 2)
        for fragments in reader.segments {
            #expect(fragments.map(\.trackID) == [1, 2])
        }
        let audioFragments = reader.segments.compactMap { $0.first { $0.trackID == 2 } }
        // Each audio fragment starts where the one before it ends.
        #expect(audioFragments[1].baseDecodeTime == audioFragments[0].durations.reduce(0) { $0 + UInt64($1) })
        #expect(audioFragments.allSatisfy { $0.auxiliaryBoxes == ["senc"] && $0.sencFlags == 0 })
        // The second segment's audio starts with its video, to within one AAC packet (1,024 frames).
        let videoFragments = reader.segments.compactMap { $0.first { $0.trackID == 1 } }
        let videoTimescale = Double(try await videoTimescale(protected.movie))
        let audioStart = Double(audioFragments[1].baseDecodeTime) / 48_000
        let videoStart = Double(videoFragments[1].baseDecodeTime) / videoTimescale
        #expect(abs(audioStart - videoStart) <= 1_024 / 48_000)

        #expect(reader.samples[1] == (try await sourceSamples(protected.movie, .video)))
        // The audio is the source's packets, less the encoder priming that ends before the video starts.
        let sourceAudio = try await sourceSamples(protected.movie, .audio)
        let audioSamples = try #require(reader.samples[2])
        #expect(sourceAudio.count > 300)
        let firstSample = try #require(audioSamples.first)
        let first = try #require(sourceAudio.firstIndex(of: firstSample))
        #expect(first <= 3)
        #expect(Array(sourceAudio[first ..< first + audioSamples.count]) == audioSamples)
        #expect(audioSamples.count >= sourceAudio.count - 4)
    }

    /// The audio fragments' decode times, in seconds: where the first starts, and where the last ends.
    private func audioSpan(_ reader: FMP4PackageReader) throws -> (start: Double, end: Double) {
        let fragments = reader.segments.compactMap { $0.first { $0.trackID == 2 } }
        let first = try #require(fragments.first), last = try #require(fragments.last)
        let end = last.baseDecodeTime + last.durations.reduce(0) { $0 + UInt64($1) }
        return (Double(first.baseDecodeTime) / 48_000, Double(end) / 48_000)
    }

    @Test("Audio that starts after the video starts after it in the package")
    func lateAudio() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 90, in: dir, audioDelay: 1)

        let reader = try FMP4PackageReader(initSegment: try #require(protected.files["init.mp4"]),
                                           segments: try segments(protected.files), key: protected.key)

        // The audio's edit places it at 1 s; its first packet starts within a packet of that.
        let span = try audioSpan(reader)
        #expect(span.start > 1 - 3 * 1_024 / 48_000 && span.start <= 1)
    }

    @Test("Audio that runs past the video is cut at the video's end")
    func longAudio() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 90, in: dir, soundExtra: 3)

        let reader = try FMP4PackageReader(initSegment: try #require(protected.files["init.mp4"]),
                                           segments: try segments(protected.files), key: protected.key)

        let videoEnd = 90.0 / 30
        let span = try audioSpan(reader)
        #expect(span.end <= videoEnd + 1_024 / 48_000)
        #expect(span.end >= videoEnd - 2 * 1_024 / 48_000)
    }

    private func videoTimescale(_ movie: URL) async throws -> CMTimeScale {
        let track = try #require(try await AVURLAsset(url: movie).loadTracks(withMediaType: .video).first)
        return try await track.load(.naturalTimeScale)
    }

    @Test("A recording with two audio tracks is refused until they are mixed")
    func twoAudioTracks() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        await #expect {
            try await protect(.aac(tracks: 2), frames: 30, in: dir)
        } throws: { error in
            if case .unsupportedAudio = error as? FMP4ProtectionError { true } else { false }
        }
    }

    @Test("A recording whose audio is not AAC-LC is refused")
    func pcmAudio() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        await #expect {
            try await protect(.pcm, frames: 30, in: dir)
        } throws: { error in
            if case .unsupportedAudio = error as? FMP4ProtectionError { true } else { false }
        }
    }
}
