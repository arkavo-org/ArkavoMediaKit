import AVFoundation
import Foundation
import OpenTDFKit
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

/// FairPlay package profile v2 (ADR-0055 in arkavo-ios). A recording is packaged as its components, each with its own
/// playlist, init segment, segments and content key: `video`, and `audio` when it has sound. Each decrypts, as a
/// player decrypts it and under its own key, to the source's samples. Every segment of each names the same span of
/// time.
@Suite("FMP4RecordingProtectionService components")
struct FMP4ProtectSoundTests {
    static let kasURL = URL(string: "https://platform.arkavo.net")!

    private struct Protected {
        let archive: Data
        let files: [String: Data]
        /// Each component's content key, unwrapped from its own key access object with the test KAS's private key.
        let keys: [FairPlayComponent: Data]
        let movie: URL
    }

    private static func entries(_ archive: Data) throws -> [String: Data] {
        let zip = try Archive(data: archive, accessMode: .read)
        var files: [String: Data] = [:]
        for entry in zip {
            var data = Data()
            _ = try zip.extract(entry) { data.append($0) }
            files[entry.path] = data
        }
        return files
    }

    private func protect(_ sound: SyntheticMovie.Sound?, frames: Int, in dir: URL, policyJSON: Data? = nil,
                         audioDelay: Double = 0, soundExtra: Double = 0,
                         frameReordering: Bool = false) async throws -> Protected {
        var movie = try await SyntheticMovie.make(in: dir, frames: frames, sound: sound, soundExtra: soundExtra,
                                                  frameReordering: frameReordering)
        if audioDelay > 0 { movie = try await SyntheticMovie.delayingAudio(of: movie, by: audioDelay, in: dir) }
        return try await protect(movie: movie, policyJSON: policyJSON)
    }

    private func protect(movie: URL, policyJSON: Data?) async throws -> Protected {
        let kas = try TestKASKeyPair()
        let service = FMP4RecordingProtectionService(kasURL: Self.kasURL, kasPublicKeyPEM: kas.spkiPublicKeyPEM)
        let (archive, _) = try await StdoutCapture.capture {
            try await service.protectVideo(videoURL: movie, assetID: "recording-with-sound", policyJSON: policyJSON)
        }
        let files = try Self.entries(archive)
        let manifestData = try #require(files["manifest.json"])
        let manifest = try #require(JSONSerialization.jsonObject(with: manifestData) as? [String: Any])
        let information = try #require(manifest["encryptionInformation"] as? [String: Any])
        let accesses = try #require(information["keyAccess"] as? [[String: Any]])
        let ids = try #require(try FairPlayComponents.componentIDs(ofManifestJSON: manifestData))
        try #require(accesses.count == ids.count)
        var keys: [FairPlayComponent: Data] = [:]
        for (id, access) in zip(ids, accesses) {
            let component = try #require(FairPlayComponent(rawValue: id))
            let wrapped = try #require(access["wrappedKey"] as? String)
            keys[component] = TDFCrypto.data(from: try TDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: kas.privateKeyPEM, wrappedKey: wrapped))
        }
        return Protected(archive: archive, files: files, keys: keys, movie: movie)
    }

    private func directory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-sound-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// An entry's lines.
    private func lines(_ protected: Protected, _ name: String) throws -> [String] {
        String(decoding: try #require(protected.files[name]), as: UTF8.self).components(separatedBy: "\n")
    }

    /// A component's init segment and its segments, in playlist order, read as a player reads them under `key`: by
    /// default, the component's own.
    private func reader(_ component: FairPlayComponent, of protected: Protected,
                        key: Data? = nil) throws -> FMP4PackageReader {
        let names = try lines(protected, FairPlayPackage.playlistName(component)).filter { $0.hasSuffix(".m4s") }
        let segments = try names.map { try #require(protected.files[$0]) }
        let componentKey: Data
        if let key { componentKey = key } else { componentKey = try #require(protected.keys[component]) }
        return try FMP4PackageReader(initSegment: try #require(protected.files[FairPlayPackage.initName(component)]),
                                     segments: segments, key: componentKey)
    }

    /// Each segment's one fragment.
    private func fragments(_ reader: FMP4PackageReader) throws -> [FMP4PackageReader.Fragment] {
        try reader.segments.map { segment in
            try #require(segment.count == 1)
            return segment[0]
        }
    }

    /// The audio component's fragments, one per segment, each checked against what profile v2 requires of every audio
    /// fragment, which admission never reads (ADR-0055 §4 and §5):
    /// - a `senc` of version 0 and flags 0, whose sample_count is the `trun`'s and whose per-sample entries are empty,
    ///   and no `saiz` or `saio`;
    /// - decode times contiguous from segment to segment: each fragment starts where the one before it ends.
    private func audioFragments(_ protected: Protected) throws -> [FMP4PackageReader.Fragment] {
        let audio = try fragments(try reader(.audio, of: protected))
        for (index, fragment) in audio.enumerated() {
            #expect(fragment.auxiliaryBoxes == ["senc"], "audio segment \(index)")
            #expect(fragment.sencVersion == 0 && fragment.sencFlags == 0, "audio segment \(index)")
            #expect(fragment.sencSampleCount == fragment.durations.count, "audio segment \(index)")
            #expect(fragment.sencEntryBytes == 0, "audio segment \(index)")
        }
        for (index, (previous, next)) in zip(audio, audio.dropFirst()).enumerated() {
            #expect(next.baseDecodeTime == previous.baseDecodeTime + previous.durations.reduce(0) { $0 + UInt64($1) },
                    "audio segment \(index + 1) does not start where segment \(index) ends")
        }
        return audio
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

    /// The source's `avc1.PPCCLL`, from its avcC.
    private func sourceCodec(_ movie: URL) async throws -> String {
        let track = try #require(try await AVURLAsset(url: movie).loadTracks(withMediaType: .video).first)
        let format = try #require(try await track.load(.formatDescriptions).first)
        let extensions = try #require(CMFormatDescriptionGetExtensions(format) as? [String: Any])
        let atoms = try #require(extensions["SampleDescriptionExtensionAtoms"] as? [String: Any])
        let avcC = try #require(atoms["avcC"] as? Data)
        return "avc1." + avcC[1 ... 3].map { String(format: "%02X", $0) }.joined()
    }

    private func videoTimescale(_ movie: URL) async throws -> CMTimeScale {
        let track = try #require(try await AVURLAsset(url: movie).loadTracks(withMediaType: .video).first)
        return try await track.load(.naturalTimeScale)
    }

    /// Seconds from the source video's first decode time to the earliest presentation time of any of its samples: where
    /// the package presents its first frame, since the package's time 0 is the first decode time.
    private func firstPresentedFrame(_ movie: URL) async throws -> Double {
        let asset = AVURLAsset(url: movie)
        let track = try #require(try await asset.loadTracks(withMediaType: .video).first)
        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderTrackOutput(track: track, outputSettings: nil)
        reader.add(output)
        #expect(reader.startReading())
        var firstDecode: CMTime?, earliest: CMTime?
        while let buffer = output.copyNextSampleBuffer() {
            guard CMSampleBufferGetNumSamples(buffer) > 0 else { continue }
            let pts = CMSampleBufferGetPresentationTimeStamp(buffer), dts = CMSampleBufferGetDecodeTimeStamp(buffer)
            if firstDecode == nil { firstDecode = dts.isNumeric ? dts : pts }
            earliest = min(earliest ?? pts, pts)
        }
        return (try #require(earliest) - (try #require(firstDecode))).seconds
    }

    /// Where the package's video ends on its timeline: its samples' durations, laid end to end from 0.
    private func videoEnd(_ protected: Protected) async throws -> Double {
        let frames = try fragments(try reader(.video, of: protected))
        let ticks = frames.reduce(UInt64(0)) { $0 + $1.durations.reduce(0) { $0 + UInt64($1) } }
        return Double(ticks) / Double(try await videoTimescale(protected.movie))
    }

    /// Seconds from media time to presentation time in the first edit of the source's track of `type` that shows media.
    private func editOffset(_ movie: URL, _ type: AVMediaType) async throws -> Double {
        let track = try #require(try await AVURLAsset(url: movie).loadTracks(withMediaType: type).first)
        let edit = try #require(try await track.load(.segments).first { !$0.isEmpty })
        return edit.timeMapping.target.start.seconds - edit.timeMapping.source.start.seconds
    }

    /// Writes a protected archive and its entries to `ARKAVO_DUMP_PACKAGE_DIR`, for other tools: the viewer's package
    /// reader, ffmpeg, tdf-iroh-s3's ingest and the device spike.
    /// - `ARKAVO_DUMP_SOURCE`: the movie to protect, instead of an 8-second synthetic one with a tone.
    /// - `ARKAVO_DUMP_POLICY`: a policy JSON file, instead of a classified tier policy whose uuid is 0f3c2a1b-….
    /// - `ARKAVO_DUMP_KAS_URL`: wraps the keys to that KAS's public key, fetched from it, so its key service can license
    ///   the archive. Without it the keys are wrapped to a test KAS, and each is written as `<id>-key.hex`.
    @Test("Dump a protected archive", .enabled(if: ProcessInfo.processInfo.environment["ARKAVO_DUMP_PACKAGE_DIR"] != nil))
    func dump() async throws {
        let environment = ProcessInfo.processInfo.environment
        let out = URL(fileURLWithPath: try #require(environment["ARKAVO_DUMP_PACKAGE_DIR"]))
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let policy: Data
        if let path = environment["ARKAVO_DUMP_POLICY"] {
            policy = try Data(contentsOf: URL(fileURLWithPath: path))
        } else {
            policy = Data(#"{"arkavo:classification":{"filter":"passed","flagged":[],"v":1},"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign-tier/value/13167240_24457368"}],"dissem":[]},"uuid":"0f3c2a1b-5d6e-4f70-8a9b-c1d2e3f4a5b6"}"#.utf8)
        }
        let movie: URL
        if let path = environment["ARKAVO_DUMP_SOURCE"] {
            movie = URL(fileURLWithPath: path)
        } else {
            movie = try await SyntheticMovie.make(in: dir, frames: 240, sound: .aac(tracks: 1))
        }
        let archive: Data
        if let kas = environment["ARKAVO_DUMP_KAS_URL"] {
            let service = FMP4RecordingProtectionService(kasURL: try #require(URL(string: kas)))
            archive = try await service.protectVideo(videoURL: movie, assetID: "dump", policyJSON: policy)
        } else {
            let protected = try await protect(movie: movie, policyJSON: policy)
            archive = protected.archive
            for (component, key) in protected.keys {
                try key.map { String(format: "%02x", $0) }.joined().write(
                    to: out.appendingPathComponent("\(component.rawValue)-key.hex"), atomically: true, encoding: .utf8)
            }
        }
        try archive.write(to: out.appendingPathComponent("archive.tdf"))
        for (name, data) in try Self.entries(archive) { try data.write(to: out.appendingPathComponent(name)) }
        try? FileManager.default.removeItem(at: out.appendingPathComponent("source.mov"))
        try FileManager.default.copyItem(at: movie, to: out.appendingPathComponent("source.mov"))
    }

    @Test("A recording with an AAC track is two components, each decrypting under its own key to the source")
    func aacTrack() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        // 8 s: two segments, so the audio is split at a segment boundary.
        let protected = try await protect(.aac(tracks: 1), frames: 240, in: dir)

        #expect(Set(protected.files.keys) == [
            "manifest.json", "master.m3u8",
            "video.m3u8", "video-init.mp4", "video-segment0.m4s", "video-segment1.m4s",
            "audio.m3u8", "audio-init.mp4", "audio-segment0.m4s", "audio-segment1.m4s",
        ])
        let videoKey = try #require(protected.keys[.video]), audioKey = try #require(protected.keys[.audio])
        #expect(videoKey.count == 16 && audioKey.count == 16 && videoKey != audioKey)

        let video = try reader(.video, of: protected), audio = try reader(.audio, of: protected)
        #expect(video.tracks.keys.sorted() == [1] && audio.tracks.keys.sorted() == [1])
        let audioTrack = try #require(audio.tracks[1])
        #expect(audioTrack.handler == "soun" && audioTrack.sampleEntry == "enca" && audioTrack.audioObjectType == 2)
        #expect(audioTrack.tencVersion == 0 && audioTrack.cryptBlocks == 0 && audioTrack.skipBlocks == 0)
        let videoFragments = try fragments(video), audioFragments = try audioFragments(protected)
        #expect(videoFragments.count == 2 && audioFragments.count == 2)
        // Each audio fragment starts where the one before it ends.
        #expect(audioFragments[1].baseDecodeTime == audioFragments[0].durations.reduce(0) { $0 + UInt64($1) })
        // The second segment's audio starts with its video, to within one AAC packet (1,024 frames).
        let videoTimescale = Double(try await videoTimescale(protected.movie))
        let audioStart = Double(audioFragments[1].baseDecodeTime) / 48_000
        let videoStart = Double(videoFragments[1].baseDecodeTime) / videoTimescale
        #expect(abs(audioStart - videoStart) <= 1_024 / 48_000)

        #expect(video.samples[1] == (try await sourceSamples(protected.movie, .video)))
        // The audio is the source's packets, less the encoder priming that ends before the video starts.
        let sourceAudio = try await sourceSamples(protected.movie, .audio)
        let audioSamples = try #require(audio.samples[1])
        #expect(sourceAudio.count > 300)
        let firstSample = try #require(audioSamples.first)
        let first = try #require(sourceAudio.firstIndex(of: firstSample))
        #expect(first <= 3)
        #expect(Array(sourceAudio[first ..< first + audioSamples.count]) == audioSamples)
        #expect(audioSamples.count >= sourceAudio.count - 4)
        // The keys are independent: the audio read under the video key is not the source's sound.
        #expect(try reader(.audio, of: protected, key: videoKey).samples[1] != audioSamples)
    }

    @Test("Every component's playlist names the same segments, and the master playlist describes the media")
    func playlists() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 240, in: dir)
        let manifestData = try #require(protected.files["manifest.json"])
        let uuid = try #require(FairPlayPolicy.uuid(ofManifestJSON: manifestData))
        let manifest = try #require(JSONSerialization.jsonObject(with: manifestData) as? [String: Any])
        let method = try #require((manifest["encryptionInformation"] as? [String: Any])?["method"] as? [String: Any])
        let ivBase64 = try #require(method["iv"] as? String)
        let iv = try #require(Data(base64Encoded: ivBase64))
        let ivHex = iv.map { String(format: "%02X", $0) }.joined()

        let video = try lines(protected, "video.m3u8"), audio = try lines(protected, "audio.m3u8")
        // The same segment count, target duration and EXTINF value per segment (ADR-0055 §4).
        #expect(video.filter { $0.hasPrefix("#EXTINF:") } == audio.filter { $0.hasPrefix("#EXTINF:") })
        #expect(video.first { $0.hasPrefix("#EXT-X-TARGETDURATION:") }
            == audio.first { $0.hasPrefix("#EXT-X-TARGETDURATION:") })
        #expect(video.filter { $0.hasSuffix(".m4s") } == ["video-segment0.m4s", "video-segment1.m4s"])
        #expect(audio.filter { $0.hasSuffix(".m4s") } == ["audio-segment0.m4s", "audio-segment1.m4s"])
        for (component, playlist) in [("video", video), ("audio", audio)] {
            #expect(playlist.contains(#"#EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://\#(uuid)/\#(component)",KEYFORMAT="com.apple.streamingkeydelivery",KEYFORMATVERSIONS="1",IV=0x\#(ivHex)"#))
            #expect(playlist.contains(#"#EXT-X-MAP:URI="\#(component)-init.mp4""#))
        }
        // Each init's constant IV is method.iv.
        #expect(try reader(.video, of: protected).tracks[1]?.constantIV == iv)
        #expect(try reader(.audio, of: protected).tracks[1]?.constantIV == iv)

        try await expectMasterPlaylist(protected, videoPlaylist: video)
    }

    /// The master playlist of an 8-second mono recording: one audio rendition and one variant, describing the media.
    private func expectMasterPlaylist(_ protected: Protected, videoPlaylist video: [String]) async throws {
        let master = try lines(protected, "master.m3u8")
        try #require(master.count == 6)
        #expect(Array(master[0 ... 2]) == ["#EXTM3U", "#EXT-X-VERSION:7", "#EXT-X-INDEPENDENT-SEGMENTS"])
        #expect(master[3] == #"#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="audio",NAME="Audio",LANGUAGE="und",DEFAULT=YES,AUTOSELECT=YES,CHANNELS="1",URI="audio.m3u8""#)
        #expect(master[5] == "video.m3u8")
        let streamInf = master[4]
        let codec = try await sourceCodec(protected.movie)
        #expect(streamInf.contains(#",CODECS="\#(codec),mp4a.40.2",RESOLUTION=320x180,FRAME-RATE="#))
        #expect(streamInf.hasSuffix(#",AUDIO="audio""#))
        let frameRate = try #require(streamInf.firstMatch(of: /FRAME-RATE=(\d+\.\d{3}),/))
        #expect(abs(try #require(Double(frameRate.1)) - 30) < 0.5)
        // BANDWIDTH is the peak segment bit rate and AVERAGE-BANDWIDTH the presentation's, video and audio together.
        let stated = try #require(streamInf.firstMatch(of: /^#EXT-X-STREAM-INF:BANDWIDTH=(\d+),AVERAGE-BANDWIDTH=(\d+),/))
        let peak = try #require(Double(stated.1)), average = try #require(Double(stated.2))
        let sizes: [Int] = try (0 ..< 2).map { (index: Int) -> Int in
            let videoSize = try #require(protected.files["video-segment\(index).m4s"]).count
            let audioSize = try #require(protected.files["audio-segment\(index).m4s"]).count
            return videoSize + audioSize
        }
        let durations: [Double] = video.compactMap { (line: String) -> Double? in
            line.hasPrefix("#EXTINF:") ? Double(line.dropFirst("#EXTINF:".count).prefix { $0 != "," }) : nil
        }
        let rates: [Double] = zip(sizes, durations).map { (size: Int, duration: Double) in Double(size * 8) / duration }
        let expectedPeak = try #require(rates.max())
        let expectedAverage = Double(sizes.reduce(0, +) * 8) / durations.reduce(0, +)
        #expect(abs(peak / expectedPeak - 1) < 1e-4 && abs(average / expectedAverage - 1) < 1e-4)
        #expect(average <= peak)
    }

    @Test("A recording without sound is its video component alone, under one key")
    func noSound() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(nil, frames: 90, in: dir)

        #expect(Set(protected.files.keys)
            == ["manifest.json", "master.m3u8", "video.m3u8", "video-init.mp4", "video-segment0.m4s"])
        #expect(Array(protected.keys.keys) == [.video])
        let master = try lines(protected, "master.m3u8")
        try #require(master.count == 5)
        #expect(!master.contains { $0.hasPrefix("#EXT-X-MEDIA:") })
        let codec = try await sourceCodec(protected.movie)
        #expect(master[3].contains(#",CODECS="\#(codec)",RESOLUTION=320x180,FRAME-RATE="#))
        #expect(!master[3].contains("AUDIO=") && !master[3].contains("mp4a"))
        #expect(master[4] == "video.m3u8")
        #expect(try reader(.video, of: protected).samples[1] == (try await sourceSamples(protected.movie, .video)))
    }

    /// The audio fragments' decode times, in seconds: where the first starts, and where the last ends.
    private func audioSpan(_ protected: Protected) throws -> (start: Double, end: Double) {
        let audio = try audioFragments(protected)
        let first = try #require(audio.first), last = try #require(audio.last)
        let end = last.baseDecodeTime + last.durations.reduce(0) { $0 + UInt64($1) }
        return (Double(first.baseDecodeTime) / 48_000, Double(end) / 48_000)
    }

    /// The package's audio, decrypted under its key and decoded to mono PCM at 48 kHz.
    private func decodedAudio(_ protected: Protected) throws -> (track: FMP4PackageReader.Track, pcm: [Float]) {
        let audioReader = try reader(.audio, of: protected)
        let audio = try #require(audioReader.tracks[1])
        let pcm = try AACDecoder.decode(try #require(audioReader.samples[1]),
                                        magicCookie: try #require(audio.esDescriptor), sampleRate: 48_000,
                                        channels: UInt32(try #require(audio.channelCount)))
        return (audio, pcm)
    }

    /// The power of 440 Hz in `pcm` from `start` to `end` seconds.
    private func tone(_ pcm: [Float], from start: Double, to end: Double) throws -> Double {
        let range = Int(start * 48_000) ..< Int(end * 48_000)
        try #require(range.upperBound <= pcm.count)
        return AACDecoder.power(of: 440, in: Array(pcm[range]), sampleRate: 48_000)
    }

    @Test("Audio that starts after the video is packaged from the video's start, with silence before it")
    func lateAudio() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 90, in: dir, audioDelay: 1)

        #expect(try audioSpan(protected).start < 1_024 / 48_000)
        let (_, pcm) = try decodedAudio(protected)
        #expect(try tone(pcm, from: 0.1, to: 0.8) < 0.000_3)
        #expect(try tone(pcm, from: 1.3, to: 2.8) > 0.003)
    }

    @Test("Audio that starts a whole segment after the video still gives every segment audio")
    func audioAfterFirstSegment() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 400, in: dir, audioDelay: 7)

        let video = try fragments(try reader(.video, of: protected))
        let audio = try audioFragments(protected)
        #expect(video.count >= 2 && audio.count == video.count)
        #expect(audio.allSatisfy { !$0.durations.isEmpty })
        #expect(try audioSpan(protected).start < 1_024 / 48_000)
    }

    @Test("Audio that ends before the video is packaged to the video's end, with silence after it")
    func shortAudio() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 400, in: dir, soundExtra: -7)

        let video = try fragments(try reader(.video, of: protected))
        let audio = try audioFragments(protected)
        #expect(video.count >= 2 && audio.count == video.count)
        #expect(audio.allSatisfy { !$0.durations.isEmpty })
        let videoEnd = 400.0 / 30
        let span = try audioSpan(protected)
        #expect(span.end >= videoEnd - 2 * 1_024 / 48_000 && span.end <= videoEnd + 1_024 / 48_000)
        let (_, pcm) = try decodedAudio(protected)
        #expect(try tone(pcm, from: 1, to: 5) > 0.003)
        #expect(try tone(pcm, from: 8, to: 12.5) < 0.000_3)
    }

    @Test("Audio that runs past the video is cut at the video's end")
    func longAudio() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 90, in: dir, soundExtra: 3)

        let videoEnd = 90.0 / 30
        let span = try audioSpan(protected)
        #expect(span.end <= videoEnd + 1_024 / 48_000)
        #expect(span.end >= videoEnd - 2 * 1_024 / 48_000)
    }

    /// The device spike's source (H.264 High with B-frames, mono AAC) presents its first frame two frames after its
    /// first decode; the package's time 0 is that decode, so its sound starts at the first presented frame, not at 0.
    @Test("A B-frame video's sound is packaged as it is, from its first presented frame")
    func reorderingDelay() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 240, in: dir, frameReordering: true)
        // The spike's shape: the first sample decodes at 0 and is presented later, and the video's edit maps that to 0.
        let presented = try await firstPresentedFrame(protected.movie)
        try #require(presented > 0.03, "the fixture must have a reordering delay")
        #expect(abs(try await editOffset(protected.movie, .video) + presented) < 1e-6)

        let video = try reader(.video, of: protected)
        let videoFragments = try fragments(video), audioFragments = try audioFragments(protected)
        #expect(videoFragments.count == 2 && audioFragments.count == 2)
        #expect(video.samples[1] == (try await sourceSamples(protected.movie, .video)))
        // Packaged as it is: every source packet from the first, the encoder priming included, placed so that the
        // sound's presentation time 0 lands on the first presented frame.
        let audioSamples = try #require(try reader(.audio, of: protected).samples[1])
        let sourceAudio = try await sourceSamples(protected.movie, .audio)
        #expect(!audioSamples.isEmpty && Array(sourceAudio.prefix(audioSamples.count)) == audioSamples)
        let start = presented + (try await editOffset(protected.movie, .audio))
        #expect(abs(try audioSpan(protected).start - start) <= 1.0 / 48_000)
        // Every packet that starts before the video's end.
        let end = try await videoEnd(protected)
        #expect(audioSamples.count == min(sourceAudio.count, Int(((end - start) / (1_024.0 / 48_000)).rounded(.up))))
    }

    @Test("Sound that starts after a B-frame video's first presented frame is mixed with silence from that frame")
    func reorderingDelayLateSound() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 240, in: dir, audioDelay: 1,
                                          frameReordering: true)
        let presented = try await firstPresentedFrame(protected.movie)
        try #require(presented > 0.03, "the delayed copy must keep the reordering delay")

        let video = try fragments(try reader(.video, of: protected))
        let audio = try audioFragments(protected)
        #expect(video.count == 2 && audio.count == 2)
        let span = try audioSpan(protected)
        #expect(span.start <= presented + 1_024 / 48_000)
        let end = try await videoEnd(protected)
        #expect(span.end >= end - 2 * 1_024 / 48_000 && span.end <= end + 1_024 / 48_000)
        // The PCM starts at the first packet: silence until the sound, 1 s after the first presented frame.
        let (_, pcm) = try decodedAudio(protected)
        #expect(try tone(pcm, from: 0.15, to: 0.85) < 0.000_3)
        #expect(try tone(pcm, from: 1.4, to: 4) > 0.003)
    }

    /// Strong at each of `tones`, and not at an unrelated frequency.
    private func expectTones(_ tones: [Double], in pcm: [Float]) {
        #expect(pcm.count > 48_000)
        // A pure tone of amplitude 8,000/32,768 has power about 0.015; mixing keeps each tone's share.
        for tone in tones {
            #expect(AACDecoder.power(of: tone, in: pcm, sampleRate: 48_000) > 0.003, "\(tone) Hz")
        }
        #expect(AACDecoder.power(of: 1_234, in: pcm, sampleRate: 48_000) < 0.000_3)
    }

    @Test("The packaged AAC track decodes to the source's tone")
    func aacTone() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 1), frames: 90, in: dir)

        let (_, pcm) = try decodedAudio(protected)

        expectTones([440], in: pcm)
        #expect(AACDecoder.power(of: 660, in: pcm, sampleRate: 48_000) < 0.000_3)
    }

    @Test("A recording with two audio tracks is protected with them mixed into one AAC-LC track")
    func twoAudioTracks() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.aac(tracks: 2), frames: 90, in: dir)

        let (audio, pcm) = try decodedAudio(protected)

        #expect(audio.sampleEntry == "enca" && audio.audioObjectType == 2)
        expectTones([440, 660], in: pcm)
        // The mix keeps the source's timeline: it starts with the video and ends with it.
        let span = try audioSpan(protected)
        #expect(span.start < 3 * 1_024 / 48_000)
        #expect(abs(span.end - 3) <= 2 * 1_024 / 48_000)
    }

    @Test("A recording whose audio is not AAC is protected with it encoded as AAC-LC")
    func pcmAudio() async throws {
        let dir = try directory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let protected = try await protect(.pcm, frames: 90, in: dir)

        let (audio, pcm) = try decodedAudio(protected)

        #expect(audio.sampleEntry == "enca" && audio.audioObjectType == 2)
        expectTones([440], in: pcm)
    }
}

/// Whether placed audio covers the video's span (ADR-0055 §4): every segment holds a packet; the sound starts within a
/// packet of the first presented frame and ends within a packet of the video's end; and laid end to end, as the
/// segments place them, every packet stays within a packet of its own time.
@Suite("fMP4 audio coverage")
struct FMP4AudioCoverageTests {
    static let segmentStarts = [0.0, 6, 12]
    static let packet = 1_024.0 / 48_000

    /// Packets of 1,024 frames at 48 kHz, from `start` to `end` seconds.
    static func packets(from start: Double, to end: Double) -> [(sample: FMP4Writer.Sample, time: Double)] {
        stride(from: start, to: end, by: packet).map {
            (FMP4Writer.Sample(data: Data([0]), duration: 1_024, isSync: true), $0)
        }
    }

    private func covers(_ packets: [(sample: FMP4Writer.Sample, time: Double)], start: Double = 0) -> Bool {
        FMP4RecordingProtectionService.covers(packets, sampleRate: 48_000, segmentStarts: Self.segmentStarts,
                                              start: start, end: 13.3)
    }

    @Test("Packets from the video's start to its end, in every segment, cover it")
    func covering() {
        #expect(covers(Self.packets(from: 0, to: 13.3)))
    }

    @Test("Audio that starts late, ends early, skips a segment or is empty does not cover the video")
    func gaps() {
        #expect(!covers(Self.packets(from: 1, to: 13.3)))
        #expect(!covers(Self.packets(from: 0, to: 12)))
        #expect(!covers(Self.packets(from: 0, to: 5.9) + Self.packets(from: 12.1, to: 13.3)))
        #expect(!covers([]))
    }

    /// A B-frame video's first frame is presented after the package's time 0 (two frames, in the spike's source).
    @Test("The start is the first presented frame: sound may start before it, and up to a packet after it")
    func firstPresentedFrame() {
        let presented = 2.0 / 30
        // The spike's source: its first packet, the encoder priming, starts before the first presented frame.
        #expect(covers(Self.packets(from: presented - Self.packet, to: 13.3), start: presented))
        #expect(covers(Self.packets(from: presented + 0.9 * Self.packet, to: 13.3), start: presented))
        #expect(!covers(Self.packets(from: presented + 1.1 * Self.packet, to: 13.3), start: presented))
        // Measured from 0, the same packets start too late.
        #expect(!covers(Self.packets(from: presented - Self.packet, to: 13.3)))
    }

    /// ADR-0055 §4: the audio's decode times are contiguous from segment to segment, so the segments lay the packets
    /// end to end. A gap or an overlap in their times longer than a packet would move the sound after it.
    @Test("Packets with a gap of more than a packet are not contiguous; jitter within a packet is")
    func contiguity() {
        #expect(!covers(Self.packets(from: 0, to: 3) + Self.packets(from: 3.1, to: 13.3)))
        #expect(!covers(Self.packets(from: 0, to: 3) + Self.packets(from: 3 - 3 * Self.packet, to: 13.3)))
        // Each packet up to a third of a packet early or late.
        let jittered = Self.packets(from: 0, to: 13.3).enumerated().map { index, packet in
            (packet.sample, max(0, packet.time + Double(index % 3 - 1) * Self.packet / 3))
        }
        #expect(covers(jittered))
        // The first packet moved forward to 0, as `trim` moves the encoder priming that starts before 0.
        let primed = FMP4RecordingProtectionService.trim(Self.packets(from: -0.9 * Self.packet, to: 13.4),
                                                         sampleRate: 48_000, to: 13.3)
        #expect(primed.first?.time == 0)
        #expect(covers(primed))
    }
}

/// Each audio fragment's decode time (ADR-0055 §4): contiguous from segment to segment.
@Suite("fMP4 audio decode times")
struct FMP4AudioDecodeTimeTests {
    @Test("The first audio fragment starts at its first packet; each later one where the one before it ends")
    func contiguous() throws {
        let packet = 1_024.0 / 48_000
        // The first packet 2,176 frames in (where the spike's encoder priming lands), and every packet of the second
        // and third segments 1 ms late: each fragment still starts where the one before it ends, not at its first
        // packet's time.
        let packets = (0 ..< 600).map { index in
            (sample: FMP4Writer.Sample(data: Data([0]), duration: 1_024, isSync: true),
             time: 2_176.0 / 48_000 + Double(index) * packet + (index >= 280 ? 0.001 : 0))
        }
        let ranges = FMP4RecordingProtectionService.audioRanges(startTimes: packets.map(\.time),
                                                                segmentStarts: [0, 6, 12])
        try #require(ranges.count == 3 && ranges.allSatisfy { !$0.isEmpty } && ranges[1].lowerBound == 280)

        let times = FMP4RecordingProtectionService.audioDecodeTimes(packets, ranges: ranges, sampleRate: 48_000)

        #expect(times.first == 2_176)
        for index in 1 ..< ranges.count {
            #expect(times[index] == times[index - 1] + UInt64(ranges[index - 1].count * 1_024))
        }
    }
}

/// A component holds `<id>-segment0.m4s` to `<id>-segment4092.m4s` (ADR-0055 §2): a longer recording is refused, never
/// written as a package the viewer refuses.
@Suite("fMP4 segment count")
struct FMP4SegmentCountTests {
    @Test("A component holds at most 4,093 segments")
    func limit() throws {
        try FMP4RecordingProtectionService.checkSegmentCount(4_093)
        #expect(throws: FMP4ProtectionError.self) { try FMP4RecordingProtectionService.checkSegmentCount(4_094) }
    }
}

/// The audio mix: one AAC-LC track that covers the video's span, silence where there is no sound.
@Suite("fMP4 audio mix")
struct FMP4AudioMixTests {
    /// The M4A's sound, decoded to mono PCM at 48 kHz.
    private func decode(_ url: URL) async throws -> [Float] {
        let asset = AVURLAsset(url: url)
        let track = try #require(try await asset.loadTracks(withMediaType: .audio).first)
        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderTrackOutput(track: track, outputSettings: [
            AVFormatIDKey: kAudioFormatLinearPCM, AVSampleRateKey: 48_000, AVNumberOfChannelsKey: 1,
            AVLinearPCMBitDepthKey: 32, AVLinearPCMIsFloatKey: true, AVLinearPCMIsBigEndianKey: false,
            AVLinearPCMIsNonInterleaved: false,
        ])
        reader.add(output)
        #expect(reader.startReading())
        var pcm: [Float] = []
        while let buffer = output.copyNextSampleBuffer() {
            guard let block = CMSampleBufferGetDataBuffer(buffer) else { continue }
            var samples = [Float](repeating: 0, count: CMBlockBufferGetDataLength(block) / 4)
            #expect(CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: samples.count * 4,
                                               destination: &samples) == noErr)
            pcm += samples
        }
        #expect(reader.status == .completed)
        return pcm
    }

    private func tone(_ pcm: [Float], from start: Double, to end: Double) throws -> Double {
        let range = Int(start * 48_000) ..< Int(end * 48_000)
        try #require(range.upperBound <= pcm.count)
        return AACDecoder.power(of: 440, in: Array(pcm[range]), sampleRate: 48_000)
    }

    /// A video whose first presented frame is before the sound's time 0 (an edit that starts into a group of pictures,
    /// whose earlier frames the package keeps) needs silence before the sound.
    @Test("The mix adds silence before the sound back to a start before the source's 0, and after it to the end")
    func leadingSilence() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-mix-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        // 2 s of tone.
        let asset = AVURLAsset(url: try await SyntheticMovie.make(in: dir, frames: 60, sound: .aac(tracks: 1)))
        let tracks = try await asset.loadTracks(withMediaType: .audio)

        let mixed = try await FMP4RecordingProtectionService.mix(
            tracks, of: asset, into: dir.appendingPathComponent("early.m4a"),
            from: CMTime(value: -24_000, timescale: 48_000), through: CMTime(value: 144_000, timescale: 48_000))

        // The M4A's time 0 is the source's -0.5 s: silence to 0.5 s, the tone to 2.5 s, then silence to 3.5 s.
        #expect(mixed.origin == CMTime(value: -24_000, timescale: 48_000))
        let pcm = try await decode(mixed.url)
        #expect(abs(Double(pcm.count) / 48_000 - 3.5) < 0.05, "\(pcm.count) frames")
        #expect(try tone(pcm, from: 0.05, to: 0.45) < 0.000_3)
        #expect(try tone(pcm, from: 0.6, to: 2.4) > 0.003)
        #expect(try tone(pcm, from: 2.6, to: 3.4) < 0.000_3)

        // A start after the sound's adds nothing before it: the M4A's time 0 is the source's 0.
        let late = try await FMP4RecordingProtectionService.mix(
            tracks, of: asset, into: dir.appendingPathComponent("late.m4a"),
            from: CMTime(value: 12_000, timescale: 48_000), through: CMTime(value: 144_000, timescale: 48_000))
        #expect(late.origin == .zero)
        let latePCM = try await decode(late.url)
        #expect(abs(Double(latePCM.count) / 48_000 - 3) < 0.05, "\(latePCM.count) frames")
        #expect(try tone(latePCM, from: 0.1, to: 1.9) > 0.003)
    }
}

/// Where audio lands on the package's timeline, which starts at the first video sample's decode time.
@Suite("fMP4 audio timeline")
struct FMP4AudioTimelineTests {
    /// The video's edit offset and first decode time: none; a reordering delay; a stream that also decodes from before
    /// 0, as B-frame streams do; a leading empty edit; and both at once.
    static let videoTimings: [(Double, Double)] = [
        (0, 0), (-2.0 / 30, 0), (-2.0 / 30, -2.0 / 30), (0.5, 1.0 / 30), (-0.1, 0.25),
    ]

    @Test("An audio packet lands where the video frame shown at the same moment lands", arguments: videoTimings)
    func sameMoment(videoPresentationOffset: Double, firstVideoDecodeTime: Double) {
        // A video frame of media presentation time p is presented at p + the edit's offset, and in the package at
        // p - the first decode time (tfdt counts from it, and its composition offset is p - its decode time).
        let p = 0.4
        let presented = p + videoPresentationOffset
        let inPackage = p - firstVideoDecodeTime

        let offset = FMP4RecordingProtectionService.audioTimeOffset(
            videoPresentationOffset: videoPresentationOffset, firstVideoDecodeTime: firstVideoDecodeTime)

        #expect(abs(presented + offset - inPackage) < 1e-9)
    }

    @Test("The first presented frame is the earliest decode time plus composition offset, never before 0")
    func firstPresentation() {
        func samples(_ offsets: [Int32]) -> [FMP4Writer.Sample] {
            offsets.map { FMP4Writer.Sample(data: Data([0]), duration: 512, isSync: true, compositionTimeOffset: $0) }
        }
        // I P B B, as a High profile encoder orders them, at 30 fps on a 15,360 timescale: presented two frames in.
        #expect(FMP4RecordingProtectionService.firstPresentation(of: samples([1_024, 2_048, 0, 0]), timescale: 15_360)
            == 1_024.0 / 15_360)
        // A negative composition offset presents a frame before the first decode: the package presents from 0.
        #expect(FMP4RecordingProtectionService.firstPresentation(of: samples([0, -1_024]), timescale: 15_360) == 0)
        #expect(FMP4RecordingProtectionService.firstPresentation(of: [], timescale: 15_360) == 0)
    }
}
