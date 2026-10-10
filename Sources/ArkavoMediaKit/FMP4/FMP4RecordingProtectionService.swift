import AVFoundation
import Foundation

// MARK: - fMP4 Recording Protection Service

/// fMP4-based FairPlay protection service for hardware-enforced DRM streaming
///
/// Uses fMP4 (CMAF) with CBCS encryption for:
/// - True FairPlay hardware-enforced DRM
/// - Screen recording protection (black output on capture)
/// - Per-NAL-unit encryption with 1:9 pattern
/// - HLS Version 7 compatible streaming
public actor FMP4RecordingProtectionService {
    private let kasURL: URL
    private let kasPublicKeyPEM: String?

    /// - Parameters:
    ///   - kasURL: KAS server URL; the key access object names it and, when
    ///     `kasPublicKeyPEM` is nil, its RSA public key is fetched from it.
    ///   - kasPublicKeyPEM: The KAS RSA public key, when the caller already has it.
    public init(kasURL: URL, kasPublicKeyPEM: String? = nil) {
        self.kasURL = kasURL
        self.kasPublicKeyPEM = kasPublicKeyPEM
    }

    /// Protect video content with fMP4/CBCS encryption for FairPlay streaming, as FairPlay package profile v2
    /// (ADR-0055 in arkavo-ios).
    ///
    /// The archive holds `manifest.json` and `master.m3u8`. For each component it holds the media playlist
    /// `<id>.m3u8`, the init segment `<id>-init.mp4` and the segments `<id>-segment<N>.m4s`. The components are
    /// `video`, and `audio` when the source has sound. Each has its own content key, wrapped to the KAS in its own key
    /// access object. The policy gains `arkavo:components`, which ties each key to its component.
    ///
    /// - Parameters:
    ///   - videoURL: URL to the source video file
    ///   - assetID: Unique asset identifier, recorded in the fMP4 metadata and `meta`
    ///   - policyJSON: TDF policy JSON (`{"uuid", "body": {"dataAttributes", "dissem"}}`), without
    ///     `arkavo:components`, which the packager adds.
    ///     - BOM-less UTF-8 without duplicate keys.
    ///     - Its `uuid` must be a lower-case UUID: each component's key URI is `skd://<uuid>/<id>`.
    ///     - Nil embeds `FairPlayPolicy.placeholderJSON()`, which the license service refuses (no data attributes).
    /// - Returns: The TDF ZIP archive.
    /// - Throws: `FMP4ProtectionError.packagingFailed` for more than 4,093 segments, and `unsupportedAudio` for sound
    ///   that cannot be made into an audio component covering the video, rather than drop it.
    public func protectVideo(
        videoURL: URL,
        assetID: String,
        policyJSON: Data? = nil
    ) async throws -> Data {
        let policy = policyJSON ?? FairPlayPolicy.placeholderJSON()
        let contentKeyID = try FairPlayPolicy.uuid(ofPolicyJSON: policy)
        // The packager writes the component list from the keys it makes: a policy that has one is refused first.
        try FairPlayComponents.checkInsertable(policy)

        // Create temporary directory for fMP4 conversion
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }

        // 1. Analyze the source
        print("🎬 Analyzing source video...")
        let asset = AVURLAsset(url: videoURL)
        let tracks = try await asset.loadTracks(withMediaType: .video)
        guard let videoTrack = tracks.first else {
            throw FMP4ProtectionError.noVideoTrack
        }
        let formatDescriptions = try await videoTrack.load(.formatDescriptions)
        guard let formatDesc = formatDescriptions.first else {
            throw FMP4ProtectionError.noFormatDescription
        }
        let dimensions = try await videoTrack.load(.naturalSize)
        let timescale = try await videoTrack.load(.naturalTimeScale)
        let (trackSegments, totalSampleBytes) = try await videoTrack.load(.segments, .totalSampleDataLength)
        guard let h264Params = extractParameterSets(from: formatDesc),
              let videoCodec = h264Params.sps.first.flatMap(FairPlayPackage.avc1Codec(sps:)) else {
            throw FMP4ProtectionError.noParameterSets
        }
        // Profile v2 carries the sound as its own component whenever the source has sound (ADR-0055 §1).
        let audioTracks = try await asset.loadTracks(withMediaType: .audio)

        // 2. One independent 16-byte content key per component, and one constant IV for the package (ADR-0055 §3)
        print("🔑 Generating content encryption keys...")
        let videoKey = try CBCSEncryptor.generateContentKey()
        let audioKey = audioTracks.isEmpty ? nil : try CBCSEncryptor.generateContentKey()
        let constantIV = CBCSEncryptor.generateIV()
        // All-zero KID: FairPlay keys off the skd:// URI, not the KID, which is CENC bookkeeping only
        let keyID = Data(repeating: 0, count: 16)
        let componentKeys = [FairPlayComponentKey(component: .video, key: videoKey)]
            + (audioKey.map { [FairPlayComponentKey(component: .audio, key: $0)] } ?? [])

        // 3. Wrap each key with the KAS public key, under the policy with its component list
        print("🔐 Wrapping content keys with KAS public key...")
        let manifestBuilder = TDFManifestBuilder(kasURL: kasURL)
        let kasKey: SecKey
        if let pem = kasPublicKeyPEM {
            kasKey = try manifestBuilder.publicKey(fromPEM: pem)
        } else {
            kasKey = try await manifestBuilder.fetchKASPublicKey()
        }
        let manifest = try manifestBuilder.buildManifest(
            componentKeys: componentKeys,
            iv: constantIV,
            policyJSON: policy,
            publicKey: kasKey
        )
        let manifestData = try manifestBuilder.serializeManifest(manifest)

        // 4. The video component: one H.264 track, 1:9 pattern encrypted under the video key
        print("📦 Creating fMP4 writers with CBCS encryption...")
        let encryptionConfig = FMP4Writer.EncryptionConfig(keyID: keyID, constantIV: constantIV)
        let videoWriter = FMP4Writer(
            tracks: [.h264Video(trackID: 1, width: UInt16(dimensions.width), height: UInt16(dimensions.height),
                                timescale: UInt32(timescale), sps: h264Params.sps, pps: h264Params.pps)],
            encryption: encryptionConfig)
        let encryptor = CBCSEncryptor(key: videoKey, iv: constantIV)
        let nalLengthSize = h264Params.nalLengthSize
        // Protection starts after each slice header, measured from the stream's own parameter sets.
        let sliceHeaders = try H264SliceHeaderParser(sps: h264Params.sps, pps: h264Params.pps)

        print("🔒 Encrypting video samples...")
        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderTrackOutput(track: videoTrack, outputSettings: nil)
        reader.add(output)
        guard reader.startReading() else {
            throw FMP4ProtectionError.readFailed(reader.error?.localizedDescription ?? "reader did not start")
        }

        var samples: [FMP4Writer.Sample] = []
        var bytesRead: Int64 = 0
        var readEnd = CMTime.zero  // latest presentation end among the samples read
        var firstDecodeTime: CMTime?  // the first sample's, where the package's timeline starts

        while let sampleBuffer = output.copyNextSampleBuffer() {
            guard let dataBuffer = CMSampleBufferGetDataBuffer(sampleBuffer) else { continue }

            var length: Int = 0
            var dataPointer: UnsafeMutablePointer<Int8>?
            CMBlockBufferGetDataPointer(dataBuffer, atOffset: 0, lengthAtOffsetOut: nil, totalLengthOut: &length, dataPointerOut: &dataPointer)

            guard let pointer = dataPointer else { continue }
            let sampleData = Data(bytes: pointer, count: length)
            bytesRead += Int64(length)

            // Encrypt the sample using the actual NAL length size from the source video
            let encryptedResult = try encryptor.encryptVideoSample(sampleData, nalLengthSize: nalLengthSize,
                                                                   sliceHeaders: sliceHeaders)

            // CRITICAL ALIGNMENT CHECK: sum(clear + protected) must equal sample_size
            let originalSize = sampleData.count
            let encryptedSize = encryptedResult.encryptedData.count
            let totalClear = encryptedResult.subsamples.reduce(0) { $0 + Int($1.bytesOfClearData) }
            let totalProtected = encryptedResult.subsamples.reduce(0) { $0 + Int($1.bytesOfProtectedData) }
            let subsampleSum = totalClear + totalProtected

            if samples.count < 5 || subsampleSum != encryptedSize {
                // Log first few samples and any misalignments
                let aligned = subsampleSum == encryptedSize
                let prefix = aligned ? "✅" : "❌ MISMATCH"
                print("\(prefix) [Sample \(samples.count)] Alignment check:")
                print("   Original size: \(originalSize)")
                print("   Encrypted size: \(encryptedSize)")
                print("   Subsamples (\(encryptedResult.subsamples.count)): \(encryptedResult.subsamples.map { "[\($0.bytesOfClearData)c/\($0.bytesOfProtectedData)p]" }.joined(separator: " "))")
                print("   Sum(clear+protected): \(totalClear) + \(totalProtected) = \(subsampleSum)")
                if !aligned {
                    print("   ⚠️ CRITICAL: subsample sum (\(subsampleSum)) != encrypted size (\(encryptedSize))")
                    print("   ⚠️ This WILL cause AVPlayer to fail decryption!")
                }
            }

            // Get timing info
            let duration = CMSampleBufferGetDuration(sampleBuffer)
            let durationValue = UInt32(duration.value * Int64(timescale) / Int64(duration.timescale))

            // Calculate Composition Time Offset (CTS) for B-frame support
            // CTS = PTS - DTS (tells decoder when to display the frame relative to decode time)
            let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
            if pts.isNumeric, duration.isNumeric {
                readEnd = max(readEnd, pts + duration)
            }
            let dts = CMSampleBufferGetDecodeTimeStamp(sampleBuffer)
            if firstDecodeTime == nil { firstDecodeTime = dts.isNumeric ? dts : pts }
            var compositionTimeOffset: Int32 = 0

            // Only calculate CTS if both PTS and DTS are valid
            if pts.isValid && dts.isValid && pts != dts {
                // Convert both timestamps to the output timescale
                let ptsInTimescale = Int64(pts.value) * Int64(timescale) / Int64(pts.timescale)
                let dtsInTimescale = Int64(dts.value) * Int64(timescale) / Int64(dts.timescale)
                compositionTimeOffset = Int32(ptsInTimescale - dtsInTimescale)
            }

            // Check if sync sample
            let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false)
            var isSync = true
            if let attachments = attachments as? [[CFString: Any]],
               let first = attachments.first,
               let notSync = first[kCMSampleAttachmentKey_NotSync] as? Bool {
                isSync = !notSync
            }

            samples.append(FMP4Writer.Sample(
                data: encryptedResult.encryptedData,
                duration: durationValue,
                isSync: isSync,
                compositionTimeOffset: compositionTimeOffset,
                subsamples: encryptedResult.subsamples
            ))
        }
        // copyNextSampleBuffer() returns nil on failure as well as at the end.
        guard reader.status == .completed else {
            throw FMP4ProtectionError.readFailed(reader.error?.localizedDescription ?? "reader status \(reader.status.rawValue)")
        }
        guard !samples.isEmpty else {
            throw FMP4ProtectionError.readFailed("no video samples")
        }
        // On a truncated file the reader can also finish .completed short of the end.
        // A whole read took every sample byte, or reached the end of the last edit's
        // media (an edit that trims the tail leaves bytes unread). Not the track's
        // duration: empty and dwell edits make that differ from the samples'.
        let mediaEnd = trackSegments.last { !$0.isEmpty }?.timeMapping.source.end ?? .zero
        guard bytesRead == totalSampleBytes || readEnd >= mediaEnd else {
            throw FMP4ProtectionError.readFailed(
                "read \(bytesRead) of \(totalSampleBytes) sample bytes, to \(readEnd.seconds) s of \(mediaEnd.seconds) s")
        }
        let videoEnd = Double(samples.reduce(UInt64(0)) { $0 + UInt64($1.duration) }) / Double(timescale)
        guard videoEnd > 0 else {
            throw FMP4ProtectionError.readFailed("the video has no duration")
        }

        // 5. Segment ranges, each opening on a sync sample (about 6 seconds each)
        let ranges = Self.segmentRanges(
            for: samples.map { SegmentSample(duration: $0.duration, isSync: $0.isSync) },
            targetDuration: UInt64(timescale) * 6  // not Int32 6 * timescale: overflows past 357,913,941
        )
        try Self.checkSegmentCount(ranges.count)
        let segmentStarts = ranges.map { range in
            Double(samples[..<range.lowerBound].reduce(UInt64(0)) { $0 + UInt64($1.duration) }) / Double(timescale)
        }

        // 6. The audio component: the sound as one AAC-LC track, whole-block full-sample encrypted under the audio
        // key. It is placed on the video's timeline: the package's time 0 is the first video sample's decode time,
        // and both tracks' edits map media to presentation. It covers the video's span, from the first presented
        // frame (after time 0 for a B-frame stream) to the end, so every segment holds audio.
        var sound: (source: AudioSource, packets: [(sample: FMP4Writer.Sample, time: Double)])?
        if let audioKey {
            let audioOffset = Self.audioTimeOffset(videoPresentationOffset: Self.presentationOffset(of: trackSegments),
                                                   firstVideoDecodeTime: firstDecodeTime?.seconds ?? 0)
            sound = try await Self.coveringAudio(
                of: asset, tracks: audioTracks, mixingIn: tempDir,
                encryptor: CBCSEncryptor(key: audioKey, iv: constantIV),
                timeOffset: audioOffset, videoStart: Self.firstPresentation(of: samples, timescale: timescale),
                videoEnd: videoEnd, segmentStarts: segmentStarts)
        }
        let audioWriter = sound.map { FMP4Writer(tracks: [$0.source.config], encryption: encryptionConfig) }
        let audioRanges = sound.map {
            Self.audioRanges(startTimes: $0.packets.map(\.time), segmentStarts: segmentStarts)
        }
        // Each audio fragment's decode time: contiguous from segment to segment (ADR-0055 §4).
        let audioStarts = sound.flatMap { sound in
            audioRanges.map { Self.audioDecodeTimes(sound.packets, ranges: $0, sampleRate: sound.source.sampleRate) }
        }

        // 7. Each component's init segment and media segments: segment N of each names the video's segment N
        print("📝 Generating init segments...")
        try videoWriter.generateInitSegment().write(to: tempDir.appendingPathComponent(FairPlayPackage.initName(.video)))
        try audioWriter?.generateInitSegment().write(to: tempDir.appendingPathComponent(FairPlayPackage.initName(.audio)))

        print("📼 Generating media segments...")
        var durations: [Double] = []
        var segmentBytes: [Int] = []  // segment N's size, over every component
        var baseDecodeTime: UInt64 = 0

        for (segmentIndex, range) in ranges.enumerated() {
            let segmentSamples = Array(samples[range])
            let segmentDuration = segmentSamples.reduce(UInt64(0)) { $0 + UInt64($1.duration) }
            let videoSegment = videoWriter.generateMediaSegment(fragments: [
                FMP4Writer.TrackFragment(trackID: 1, samples: segmentSamples, baseDecodeTime: baseDecodeTime),
            ])
            try videoSegment.write(
                to: tempDir.appendingPathComponent(FairPlayPackage.segmentName(.video, index: segmentIndex)))
            var bytes = videoSegment.count
            if let sound, let audioWriter, let audioRanges, let audioStarts {
                let packets = sound.packets[audioRanges[segmentIndex]]
                guard !packets.isEmpty else {
                    // coveringAudio checked every segment: never write components of unequal segments.
                    throw FMP4ProtectionError.unsupportedAudio("audio segment \(segmentIndex) has no packets")
                }
                let audioSegment = audioWriter.generateMediaSegment(fragments: [
                    FMP4Writer.TrackFragment(trackID: 1, samples: packets.map(\.sample),
                                             baseDecodeTime: audioStarts[segmentIndex]),
                ])
                try audioSegment.write(
                    to: tempDir.appendingPathComponent(FairPlayPackage.segmentName(.audio, index: segmentIndex)))
                bytes += audioSegment.count
            }
            durations.append(Double(segmentDuration) / Double(timescale))
            segmentBytes.append(bytes)
            baseDecodeTime += segmentDuration
        }

        print("   Created \(durations.count) segments per component")

        // 8. The playlists: one media playlist per component, each with the video's EXTINF values and target duration,
        // and the master playlist (ADR-0055 §4)
        print("📋 Generating HLS playlists...")
        let components: [FairPlayComponent] = sound == nil ? [.video] : [.video, .audio]
        let targetDuration = Self.targetDuration(forSegmentDurations: durations)
        for component in components {
            let playlist = FairPlayPackage.mediaPlaylist(component: component, policyUUID: contentKeyID, iv: constantIV,
                                                         durations: durations, targetDuration: targetDuration)
            try Data(playlist.utf8).write(to: tempDir.appendingPathComponent(FairPlayPackage.playlistName(component)))
        }
        let bandwidth = FairPlayPackage.bandwidth(segmentBytes: segmentBytes, durations: durations)
        guard let master = FairPlayPackage.masterPlaylist(FairPlayPackage.MasterPlaylist(
            bandwidth: bandwidth.peak,
            averageBandwidth: bandwidth.average,
            videoCodec: videoCodec,
            width: Int(dimensions.width),
            height: Int(dimensions.height),
            frameRate: Double(samples.count) / videoEnd,
            audioChannels: sound?.source.channels
        )) else {
            // passThrough admitted only channel counts the master playlist states.
            throw FMP4ProtectionError.packagingFailed("the master playlist cannot state the audio's channel count")
        }
        try Data(master.utf8).write(to: tempDir.appendingPathComponent(FairPlayPackage.masterPlaylistName))

        // 9. Package into TDF archive (ZIP)
        print("📦 Packaging into TDF archive...")
        let enhancedManifestData = try addFMP4Metadata(
            to: manifestData,
            assetID: assetID,
            contentKeyID: contentKeyID,
            playlistFilename: FairPlayPackage.masterPlaylistName
        )
        let entryNames = [FairPlayPackage.masterPlaylistName] + components.flatMap { component in
            [FairPlayPackage.playlistName(component), FairPlayPackage.initName(component)]
                + durations.indices.map { FairPlayPackage.segmentName(component, index: $0) }
        }
        let archive = try createTDFArchive(tempDir: tempDir, manifestData: enhancedManifestData, entryNames: entryNames)

        print("✅ fMP4 FairPlay protection complete: \(archive.count) bytes")
        return archive
    }

    // MARK: - Audio

    /// The source's sound: one AAC-LC track, packaged as track 1 of the audio component at its sample rate.
    struct AudioSource {
        /// The asset the track is read from: the source, or the mix of its audio.
        let asset: AVURLAsset
        let track: AVAssetTrack
        let config: FMP4Writer.TrackConfig
        let sampleRate: UInt32
        /// The AudioSpecificConfig's channel count (`FairPlayPackage.channelCount(ofAudioSpecificConfig:)`: 1 to 6, or
        /// 8): the master playlist's `CHANNELS`.
        let channels: Int
        /// Seconds from a packet's media time to its presentation time: the track's first edit.
        let presentationOffset: Double
    }

    /// Seconds to add to an audio packet's presentation time to place it on the package's timeline, which starts at
    /// the first video sample's decode time: a video sample of media presentation time p is presented at p plus the
    /// video's edit offset, and in the package at p less that decode time.
    static func audioTimeOffset(videoPresentationOffset: Double, firstVideoDecodeTime: Double) -> Double {
        -(videoPresentationOffset + firstVideoDecodeTime)
    }

    /// Seconds from media time to presentation time in a track's first edit that shows media (an empty edit before
    /// it delays the track; an edit that starts into the media skips priming or reordering delay), or 0 with none.
    static func presentationOffset(of segments: [AVAssetTrackSegment]) -> Double {
        guard let edit = segments.first(where: { !$0.isEmpty }) else { return 0 }
        return edit.timeMapping.target.start.seconds - edit.timeMapping.source.start.seconds
    }

    /// Where the package presents its first frame, in seconds on its timeline: the earliest decode time plus
    /// composition offset, with the decode times laid end to end from 0 as the segments place them. Never before 0. A
    /// B-frame stream presents its first frame after its first decode (two frames later in the device spike's source).
    static func firstPresentation(of samples: [FMP4Writer.Sample], timescale: CMTimeScale) -> Double {
        guard !samples.isEmpty, timescale > 0 else { return 0 }
        var decodeTime: Int64 = 0, earliest = Int64.max
        for sample in samples {
            earliest = min(earliest, decodeTime + Int64(sample.compositionTimeOffset))
            decodeTime += Int64(sample.duration)
        }
        return Double(max(earliest, 0)) / Double(timescale)
    }

    /// The packets of the package's span: those that end after its start and start before `end` (the video's), the
    /// first moved to no earlier than 0.
    static func trim(_ packets: [(sample: FMP4Writer.Sample, time: Double)], sampleRate: UInt32,
                     to end: Double) -> [(sample: FMP4Writer.Sample, time: Double)] {
        packets
            .filter { $0.time + Double($0.sample.duration) / Double(sampleRate) > 0 && $0.time < end }
            .map { ($0.sample, max($0.time, 0)) }
    }

    /// The source's sound as one AAC-LC track, encrypted, placed on the package's timeline and cut to the video's
    /// span, covering that span (`covers`) from the first presented frame (`videoStart`) to `videoEnd`.
    ///
    /// One AAC-LC track that covers it is packaged as it is. Anything else is mixed and encoded once, as AAC-LC, with
    /// silence where there is no sound, into `directory`:
    /// - several tracks, as a recorder writes one per source;
    /// - audio in another format;
    /// - a track that starts after the first presented frame or stops before the video's end;
    /// - a track whose packets are not contiguous: a gap or an overlap of more than a packet.
    ///
    /// Profile v2 needs every segment of each component to name the same span, with the audio's decode times
    /// contiguous (ADR-0055 §4), and sound is never dropped.
    /// - Throws: `unsupportedAudio` for AAC-LC whose channel configuration states no supported channel count, and when
    ///   even the mix does not cover the video.
    static func coveringAudio(of asset: AVURLAsset, tracks: [AVAssetTrack], mixingIn directory: URL,
                              encryptor: CBCSEncryptor, timeOffset: Double, videoStart: Double, videoEnd: Double,
                              segmentStarts: [Double]) async throws
        -> (source: AudioSource, packets: [(sample: FMP4Writer.Sample, time: Double)]) {
        if tracks.count == 1, let source = try await passThrough(tracks[0], of: asset) {
            let packets = trim(try readAudio(source, encryptor: encryptor, timeOffset: timeOffset),
                               sampleRate: source.sampleRate, to: videoEnd)
            if covers(packets, sampleRate: source.sampleRate, segmentStarts: segmentStarts, start: videoStart,
                      end: videoEnd) {
                return (source, packets)
            }
        }
        // The mix is on the source's timeline, where package time t is at t less the offset.
        let mixed = try await mix(tracks, of: asset, into: directory.appendingPathComponent("audio.m4a"),
                                  from: CMTime(seconds: videoStart - timeOffset, preferredTimescale: 48_000),
                                  through: CMTime(seconds: videoEnd - timeOffset, preferredTimescale: 48_000))
        let mixedAsset = AVURLAsset(url: mixed.url)
        guard let track = try await mixedAsset.loadTracks(withMediaType: .audio).first,
              let source = try await passThrough(track, of: mixedAsset) else {
            throw FMP4ProtectionError.unsupportedAudio("mixing the audio did not produce AAC-LC")
        }
        // The mix's time 0 is its origin on the source's timeline.
        let packets = trim(try readAudio(source, encryptor: encryptor, timeOffset: timeOffset + mixed.origin.seconds),
                           sampleRate: source.sampleRate, to: videoEnd)
        guard covers(packets, sampleRate: source.sampleRate, segmentStarts: segmentStarts, start: videoStart,
                     end: videoEnd) else {
            throw FMP4ProtectionError.unsupportedAudio("the mixed audio does not cover the video")
        }
        return (source, packets)
    }

    /// Whether placed packets cover the video's span on the package's timeline, from `start` (where it presents its
    /// first frame) to `end` (ADR-0055 §4):
    /// - the first packet starts within its own duration of `start` (sound may start before it), and the last ends
    ///   within its own duration of `end`;
    /// - laid end to end from the first, as the segments place them (`audioDecodeTimes`), every packet stays within its
    ///   own duration of its time: jitter is absorbed, and a gap or an overlap longer than that is not contiguous;
    /// - every segment from `segmentStarts` holds at least one packet.
    static func covers(_ packets: [(sample: FMP4Writer.Sample, time: Double)], sampleRate: UInt32,
                       segmentStarts: [Double], start: Double, end: Double) -> Bool {
        guard let first = packets.first, let last = packets.last, sampleRate > 0 else { return false }
        let rate = Double(sampleRate)
        let firstLength = Double(first.sample.duration) / rate
        let lastLength = Double(last.sample.duration) / rate
        guard first.time <= max(start, 0) + firstLength, last.time + 2 * lastLength >= end else { return false }
        var laid: UInt64 = 0  // the frames of the packets before this one
        for packet in packets {
            guard abs(packet.time - (first.time + Double(laid) / rate)) <= Double(packet.sample.duration) / rate else {
                return false
            }
            laid += UInt64(packet.sample.duration)
        }
        return audioRanges(startTimes: packets.map(\.time), segmentStarts: segmentStarts).allSatisfy { !$0.isEmpty }
    }

    /// Each segment's audio decode time (`tfdt`), at the sample rate, for the packets of each of `ranges`. The first
    /// is its first packet's time, and each later one where the one before it ends: the audio's decode times are
    /// contiguous from segment to segment (ADR-0055 §4). `covers` has checked that this keeps every packet within its
    /// own duration of its time.
    static func audioDecodeTimes(_ packets: [(sample: FMP4Writer.Sample, time: Double)], ranges: [Range<Int>],
                                 sampleRate: UInt32) -> [UInt64] {
        var time = packets.first.map { UInt64(($0.time * Double(sampleRate)).rounded()) } ?? 0
        return ranges.map { range in
            defer { time += packets[range].reduce(UInt64(0)) { $0 + UInt64($1.sample.duration) } }
            return time
        }
    }

    /// `track` packaged as it is, when it is AAC-LC; otherwise nil.
    /// - Throws: `unsupportedAudio` for AAC-LC whose channel configuration states no channel count a playlist may
    ///   carry: 0 (a program config element sets the channels) or the reserved 8 to 15.
    private static func passThrough(_ track: AVAssetTrack, of asset: AVURLAsset) async throws -> AudioSource? {
        let descriptions = try await track.load(.formatDescriptions)
        guard descriptions.count == 1, let format = descriptions.first,
              CMFormatDescriptionGetMediaSubType(format) == kAudioFormatMPEG4AAC,
              let description = CMAudioFormatDescriptionGetStreamBasicDescription(format)?.pointee,
              description.mSampleRate > 0, description.mChannelsPerFrame > 0,
              let config = audioSpecificConfig(of: format), config.count >= 2, config[config.startIndex] >> 3 == 2
        else { return nil }
        guard let channels = FairPlayPackage.channelCount(ofAudioSpecificConfig: config) else {
            let configuration = FairPlayPackage.channelConfiguration(ofAudioSpecificConfig: config)
            throw FMP4ProtectionError.unsupportedAudio(
                "AAC channel configuration \(configuration.map(String.init) ?? "unreadable") is not supported")
        }
        let sampleRate = UInt32(description.mSampleRate)
        return AudioSource(
            asset: asset,
            track: track,
            // Track 1 of the audio component's own init segment (ADR-0055 §5).
            config: .aacAudio(trackID: 1, channelCount: UInt16(description.mChannelsPerFrame),
                              sampleRate: sampleRate, audioSpecificConfig: config),
            sampleRate: sampleRate,
            channels: channels,
            presentationOffset: presentationOffset(of: try await track.load(.segments)))
    }

    /// `tracks` mixed and encoded into an M4A at `url`: each track through its own edits, on the asset's timeline, as
    /// AAC-LC at 48 kHz, stereo when any of them is. The M4A covers `start` to at least `end` on that timeline:
    /// - the mix renders a gap in a track's edits as silence;
    /// - silence is added before the sound when it starts after `start`, which may be before the asset's 0 (a video
    ///   whose edit starts into a group of pictures, whose earlier frames the package keeps and presents);
    /// - and silence is added from where the sound ends to `end`.
    /// - Returns: The M4A, and its origin: where its time 0 is on the asset's timeline, which is where its first sample
    ///   is: the sound's start, or the silence's before it.
    static func mix(_ tracks: [AVAssetTrack], of asset: AVURLAsset, into url: URL, from start: CMTime,
                    through end: CMTime) async throws -> (url: URL, origin: CMTime) {
        var channels = 1
        for track in tracks {
            for format in try await track.load(.formatDescriptions)
            where (CMAudioFormatDescriptionGetStreamBasicDescription(format)?.pointee.mChannelsPerFrame ?? 1) > 1 {
                channels = 2
            }
        }
        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderAudioMixOutput(audioTracks: tracks, audioSettings: [
            AVFormatIDKey: kAudioFormatLinearPCM, AVSampleRateKey: 48_000, AVNumberOfChannelsKey: channels,
            AVLinearPCMBitDepthKey: 32, AVLinearPCMIsFloatKey: true, AVLinearPCMIsBigEndianKey: false,
            AVLinearPCMIsNonInterleaved: false,
        ])
        reader.add(output)
        let writer = try AVAssetWriter(outputURL: url, fileType: .m4a)
        let input = AVAssetWriterInput(mediaType: .audio, outputSettings: [
            AVFormatIDKey: kAudioFormatMPEG4AAC, AVSampleRateKey: 48_000, AVNumberOfChannelsKey: channels,
            AVEncoderBitRateKey: channels == 1 ? 96_000 : 160_000,
        ])
        input.expectsMediaDataInRealTime = false
        guard writer.canAdd(input) else { throw FMP4ProtectionError.encodingFailed("the audio mix cannot be written") }
        writer.add(input)
        guard reader.startReading() else {
            throw FMP4ProtectionError.readFailed(reader.error?.localizedDescription ?? "audio mix did not start")
        }
        guard writer.startWriting() else {
            throw FMP4ProtectionError.encodingFailed(writer.error?.localizedDescription ?? "audio mix writer")
        }
        writer.startSession(atSourceTime: .zero)
        var origin: CMTime?  // the M4A's time 0 on the asset's timeline: its first sample's time
        // `buffer`, at its time on the asset's timeline less the origin.
        func append(_ buffer: CMSampleBuffer) async throws {
            let buffer = try retimed(buffer, by: origin ?? .zero)
            while !input.isReadyForMoreMediaData {
                guard writer.status == .writing else {
                    throw FMP4ProtectionError.encodingFailed(writer.error?.localizedDescription ?? "audio mix writer")
                }
                try await Task.sleep(nanoseconds: 1_000_000)
            }
            guard input.append(buffer) else {
                throw FMP4ProtectionError.encodingFailed(writer.error?.localizedDescription ?? "audio mix append")
            }
        }
        // `frames` frames of silence from `time` on the asset's timeline, appended in buffers of at most 4,096.
        func appendSilence(frames: CMTimeValue, at time: CMTime, like format: CMFormatDescription) async throws {
            var written: CMTimeValue = 0
            while written < frames {
                let count = min(4_096, frames - written)
                try await append(try silence(frames: Int(count), like: format,
                                             at: time + CMTime(value: written, timescale: 48_000)))
                written += count
            }
        }
        var written = CMTime.zero  // where the last buffer appended ends, on the asset's timeline
        var format: CMFormatDescription?
        while let buffer = output.copyNextSampleBuffer() {
            let time = CMSampleBufferGetPresentationTimeStamp(buffer)
            if origin == nil {
                guard let first = CMSampleBufferGetFormatDescription(buffer) else {
                    throw FMP4ProtectionError.encodingFailed("audio mix without a format")
                }
                // Silence before the sound, when it starts after `start`, ending where the sound starts.
                let lead = max(0, (time - start).convertScale(48_000, method: .roundAwayFromZero).value)
                let leadStart = time - CMTime(value: lead, timescale: 48_000)
                origin = leadStart
                try await appendSilence(frames: lead, at: leadStart, like: first)
            }
            try await append(buffer)
            written = time + CMSampleBufferGetDuration(buffer)
            format = CMSampleBufferGetFormatDescription(buffer)
        }
        guard reader.status == .completed else {
            throw FMP4ProtectionError.readFailed(reader.error?.localizedDescription ?? "audio mix did not finish")
        }
        guard let origin, let format else { throw FMP4ProtectionError.unsupportedAudio("the audio mix is empty") }
        // Silence to `end`, so a sound that stops before the video still covers its span.
        if written < end {
            try await appendSilence(frames: (end - written).convertScale(48_000, method: .roundAwayFromZero).value,
                                    at: written, like: format)
        }
        input.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else {
            throw FMP4ProtectionError.encodingFailed(writer.error?.localizedDescription ?? "audio mix did not finish")
        }
        return (url, origin)
    }

    /// `buffer` with every timestamp `offset` earlier; `buffer` itself when `offset` is zero.
    private static func retimed(_ buffer: CMSampleBuffer, by offset: CMTime) throws -> CMSampleBuffer {
        guard offset != .zero else { return buffer }
        var count = 0
        guard CMSampleBufferGetSampleTimingInfoArray(buffer, entryCount: 0, arrayToFill: nil,
                                                     entriesNeededOut: &count) == noErr, count > 0 else {
            throw FMP4ProtectionError.encodingFailed("audio mix timing")
        }
        var timings = [CMSampleTimingInfo](repeating: CMSampleTimingInfo(), count: count)
        guard CMSampleBufferGetSampleTimingInfoArray(buffer, entryCount: count, arrayToFill: &timings,
                                                     entriesNeededOut: &count) == noErr else {
            throw FMP4ProtectionError.encodingFailed("audio mix timing")
        }
        for index in timings.indices {
            timings[index].presentationTimeStamp = timings[index].presentationTimeStamp - offset
            if timings[index].decodeTimeStamp.isNumeric {
                timings[index].decodeTimeStamp = timings[index].decodeTimeStamp - offset
            }
        }
        var copy: CMSampleBuffer?
        let status = CMSampleBufferCreateCopyWithNewTiming(allocator: nil, sampleBuffer: buffer,
                                                           sampleTimingEntryCount: count, sampleTimingArray: &timings,
                                                           sampleBufferOut: &copy)
        guard status == noErr, let copy else { throw FMP4ProtectionError.encodingFailed("audio mix retiming \(status)") }
        return copy
    }

    /// `frames` frames of silence at `time`, in the linear PCM format of `format`.
    static func silence(frames: Int, like format: CMFormatDescription, at time: CMTime) throws -> CMSampleBuffer {
        guard let description = CMAudioFormatDescriptionGetStreamBasicDescription(format)?.pointee,
              description.mBytesPerFrame > 0 else {
            throw FMP4ProtectionError.encodingFailed("silence needs linear PCM")
        }
        let length = frames * Int(description.mBytesPerFrame)
        var block: CMBlockBuffer?
        var status = CMBlockBufferCreateWithMemoryBlock(
            allocator: nil, memoryBlock: nil, blockLength: length, blockAllocator: nil, customBlockSource: nil,
            offsetToData: 0, dataLength: length, flags: kCMBlockBufferAssureMemoryNowFlag, blockBufferOut: &block)
        guard status == noErr, let block else { throw FMP4ProtectionError.encodingFailed("silence block \(status)") }
        status = CMBlockBufferFillDataBytes(with: 0, blockBuffer: block, offsetIntoDestination: 0, dataLength: length)
        guard status == noErr else { throw FMP4ProtectionError.encodingFailed("silence fill \(status)") }
        var buffer: CMSampleBuffer?
        status = CMAudioSampleBufferCreateReadyWithPacketDescriptions(
            allocator: nil, dataBuffer: block, formatDescription: format, sampleCount: frames,
            presentationTimeStamp: time, packetDescriptions: nil, sampleBufferOut: &buffer)
        guard status == noErr, let buffer else { throw FMP4ProtectionError.encodingFailed("silence buffer \(status)") }
        return buffer
    }

    // MARK: - Segment count

    /// Refuses more than 4,093 segments. A component holds `<id>-segment0.m4s` to `<id>-segment4092.m4s`
    /// (ADR-0055 §2), about six hours 49 minutes at six-second segments.
    static func checkSegmentCount(_ count: Int) throws {
        guard count <= FairPlayPackage.maxSegmentIndex + 1 else {
            throw FMP4ProtectionError.packagingFailed("\(count) segments; profile v2 holds at most 4,093")
        }
    }

    /// The AudioSpecificConfig of an AAC format description: its magic cookie, which is an MPEG-4 ES_Descriptor (the
    /// body of an `esds`, perhaps with the full box's version and flags first) or the bare AudioSpecificConfig.
    static func audioSpecificConfig(of format: CMAudioFormatDescription) -> Data? {
        var size = 0
        guard let cookie = CMAudioFormatDescriptionGetMagicCookie(format, sizeOut: &size), size > 0 else { return nil }
        var bytes = [UInt8](UnsafeRawBufferPointer(start: cookie, count: size))
        if bytes.count > 4, bytes[0 ..< 4] == [0, 0, 0, 0], bytes[4] == 0x03 { bytes.removeFirst(4) }
        guard bytes.first == 0x03 else { return Data(bytes) }
        // ES_Descriptor: ES_ID, flags and their optional fields, then the DecoderConfigDescriptor (tag 4), whose
        // 13 fixed bytes precede the DecoderSpecificInfo (tag 5).
        guard let stream = descriptor(bytes, at: 0), stream.tag == 0x03, stream.body.count >= 3 else { return nil }
        let flags = bytes[stream.body.lowerBound + 2]
        var cursor = stream.body.lowerBound + 3 + (flags & 0x80 != 0 ? 2 : 0) + (flags & 0x20 != 0 ? 2 : 0)
        if flags & 0x40 != 0 {
            guard cursor < stream.body.upperBound else { return nil }
            cursor += 1 + Int(bytes[cursor])
        }
        while cursor < stream.body.upperBound {
            guard let next = descriptor(bytes, at: cursor), next.body.upperBound <= stream.body.upperBound else {
                return nil
            }
            if next.tag == 0x04, next.body.count > 13 {
                var inner = next.body.lowerBound + 13
                while inner < next.body.upperBound {
                    guard let info = descriptor(bytes, at: inner), info.body.upperBound <= next.body.upperBound else {
                        return nil
                    }
                    if info.tag == 0x05 { return Data(bytes[info.body]) }
                    inner = info.body.upperBound
                }
            }
            cursor = next.body.upperBound
        }
        return nil
    }

    /// An MPEG-4 descriptor at `offset`: its tag and its body, whose length is the expandable size (ISO/IEC 14496-1).
    private static func descriptor(_ bytes: [UInt8], at offset: Int) -> (tag: UInt8, body: Range<Int>)? {
        guard offset < bytes.count else { return nil }
        var length = 0, cursor = offset + 1
        for _ in 0 ..< 4 {
            guard cursor < bytes.count else { return nil }
            let byte = bytes[cursor]
            cursor += 1
            length = length << 7 | Int(byte & 0x7F)
            if byte & 0x80 == 0 { break }
        }
        guard cursor + length <= bytes.count else { return nil }
        return (bytes[offset], cursor ..< cursor + length)
    }

    /// Every AAC packet of the audio track, each encrypted whole-block full-sample, with its duration at the sample
    /// rate and its presentation time plus `timeOffset`, in seconds. A sample buffer of compressed audio holds several
    /// packets; each is its own sample.
    static func readAudio(_ source: AudioSource, encryptor: CBCSEncryptor,
                          timeOffset: Double) throws -> [(sample: FMP4Writer.Sample, time: Double)] {
        let reader = try AVAssetReader(asset: source.asset)
        let output = AVAssetReaderTrackOutput(track: source.track, outputSettings: nil)
        reader.add(output)
        guard reader.startReading() else {
            throw FMP4ProtectionError.readFailed(reader.error?.localizedDescription ?? "audio reader did not start")
        }
        var samples: [(sample: FMP4Writer.Sample, time: Double)] = []
        while let buffer = output.copyNextSampleBuffer() {
            let count = CMSampleBufferGetNumSamples(buffer)
            guard count > 0, let block = CMSampleBufferGetDataBuffer(buffer) else { continue }
            var bytes = [UInt8](repeating: 0, count: CMBlockBufferGetDataLength(block))
            guard CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: bytes.count,
                                             destination: &bytes) == noErr else {
                throw FMP4ProtectionError.readFailed("audio sample data")
            }
            // One size or one timing entry stands for every packet of the buffer.
            var sizes = [Int](repeating: 0, count: count), sizeEntries = 0
            guard CMSampleBufferGetSampleSizeArray(buffer, entryCount: count, arrayToFill: &sizes,
                                                   entriesNeededOut: &sizeEntries) == noErr else {
                throw FMP4ProtectionError.readFailed("audio packet sizes")
            }
            if sizeEntries == 1 { sizes = Array(repeating: sizes[0], count: count) }
            var timings = [CMSampleTimingInfo](repeating: CMSampleTimingInfo(), count: count), timingEntries = 0
            guard CMSampleBufferGetSampleTimingInfoArray(buffer, entryCount: count, arrayToFill: &timings,
                                                         entriesNeededOut: &timingEntries) == noErr else {
                throw FMP4ProtectionError.readFailed("audio packet timing")
            }
            if timingEntries == 1 {
                // One entry: the first packet's time, and every packet's duration.
                timings = (0 ..< count).map { index in
                    var timing = timings[0]
                    timing.presentationTimeStamp = timings[0].presentationTimeStamp
                        + CMTimeMultiply(timings[0].duration, multiplier: Int32(index))
                    return timing
                }
            }
            guard sizes.reduce(0, +) == bytes.count else {
                throw FMP4ProtectionError.readFailed("audio packet sizes do not cover the buffer")
            }
            var offset = 0
            for index in 0 ..< count {
                let packet = Data(bytes[offset ..< offset + sizes[index]])
                offset += sizes[index]
                let duration = timings[index].duration, time = timings[index].presentationTimeStamp
                guard duration.isNumeric, duration.value > 0, time.isNumeric else {
                    throw FMP4ProtectionError.readFailed("audio packet without a duration or a time")
                }
                samples.append((FMP4Writer.Sample(
                    data: encryptor.encryptAudioSample(packet).encryptedData,
                    duration: UInt32((duration.seconds * Double(source.sampleRate)).rounded()),
                    isSync: true), time.seconds + source.presentationOffset + timeOffset))
            }
        }
        guard reader.status == .completed else {
            throw FMP4ProtectionError.readFailed(reader.error?.localizedDescription ?? "audio reader did not finish")
        }
        return samples
    }

    /// The audio packets of each segment: those that start at or after its start and before the next segment's, so
    /// the last segment takes every packet left, and the first every packet before the second.
    static func audioRanges(startTimes: [Double], segmentStarts: [Double]) -> [Range<Int>] {
        var ranges: [Range<Int>] = []
        var start = 0
        for (index, _) in segmentStarts.enumerated() {
            var end = startTimes.count
            if index + 1 < segmentStarts.count {
                end = startTimes[start...].firstIndex { $0 >= segmentStarts[index + 1] } ?? startTimes.count
            }
            ranges.append(start ..< end)
            start = end
        }
        return ranges
    }

    // MARK: - Segmentation

    /// A sample's duration (in the track timescale) and whether it is a sync sample.
    struct SegmentSample: Equatable {
        let duration: UInt32
        let isSync: Bool
    }

    /// Sample index ranges for the media segments. Each opens on a sync
    /// sample, as `#EXT-X-INDEPENDENT-SEGMENTS` promises: a segment closes at
    /// whichever sync sample lands nearer `targetDuration`, the first at or
    /// past it or the last short of it (if at least half way), so a keyframe
    /// a few ticks early does not stretch the segment a whole GOP.
    static func segmentRanges(for samples: [SegmentSample], targetDuration: UInt64) -> [Range<Int>] {
        var ranges: [Range<Int>] = []
        var start = 0
        var accumulated: UInt64 = 0  // duration of samples[start ..< index]
        var shortOfTarget: (index: Int, accumulated: UInt64)?  // last sync sample before the target
        for (index, sample) in samples.enumerated() {
            while index > start, sample.isSync {
                if accumulated < targetDuration {
                    shortOfTarget = (index, accumulated)
                    break
                }
                if let earlier = shortOfTarget, earlier.accumulated * 2 >= targetDuration,
                   targetDuration - earlier.accumulated < accumulated - targetDuration {
                    // Close at the earlier one, then weigh this sample again in the new segment.
                    ranges.append(start ..< earlier.index)
                    start = earlier.index
                    accumulated -= earlier.accumulated
                    shortOfTarget = nil
                    continue
                }
                ranges.append(start ..< index)
                start = index
                accumulated = 0
                shortOfTarget = nil
            }
            accumulated += UInt64(sample.duration)
        }
        if start < samples.count {
            ranges.append(start ..< samples.count)
        }
        return ranges
    }

    /// `#EXT-X-TARGETDURATION` for segments that end at sync samples, not at
    /// 6 s. RFC 8216: every EXTINF, rounded to the nearest integer, at most the
    /// target; at least 1.
    static func targetDuration(forSegmentDurations durations: [Double]) -> Int {
        max(1, Int((durations.max() ?? 0).rounded()))
    }

    // MARK: - Private Helpers

    /// Result of extracting H.264 parameters from format description
    private struct H264Parameters {
        let sps: [Data]
        let pps: [Data]
        let nalLengthSize: Int  // 1, 2, or 4 bytes
    }

    private func extractParameterSets(from formatDesc: CMFormatDescription) -> H264Parameters? {
        guard let extensions = CMFormatDescriptionGetExtensions(formatDesc) as? [String: Any],
              let sampleDescriptionExtensions = extensions["SampleDescriptionExtensionAtoms"] as? [String: Any],
              let avcCData = sampleDescriptionExtensions["avcC"] as? Data
        else {
            return nil
        }

        // Parse avcC to extract SPS/PPS and NAL length size
        // Format: configVersion(1) + profile(1) + compatibility(1) + level(1) + lengthSizeMinusOne(1)
        //         + numSPS(1) + [spsLen(2) + sps]* + numPPS(1) + [ppsLen(2) + pps]*
        guard avcCData.count >= 8 else { return nil }

        // Extract NAL length size from byte 4 (lower 2 bits + 1)
        // Values: 0 → 1 byte, 1 → 2 bytes, 3 → 4 bytes
        let lengthSizeMinusOne = Int(avcCData[4] & 0x03)
        let nalLengthSize = lengthSizeMinusOne + 1
        print("📏 NAL length size from avcC: \(nalLengthSize) bytes")

        var sps: [Data] = []
        var pps: [Data] = []
        var offset = 5  // Skip header (configVersion + profile + compatibility + level + lengthSizeMinusOne)

        // Number of SPS (lower 5 bits)
        let numSPS = Int(avcCData[offset] & 0x1F)
        offset += 1

        for _ in 0..<numSPS {
            guard offset + 2 <= avcCData.count else { break }
            let spsLen = Int(avcCData[offset]) << 8 | Int(avcCData[offset + 1])
            offset += 2
            guard offset + spsLen <= avcCData.count else { break }
            sps.append(avcCData.subdata(in: offset..<(offset + spsLen)))
            offset += spsLen
        }

        guard offset < avcCData.count else {
            return sps.isEmpty ? nil : H264Parameters(sps: sps, pps: pps, nalLengthSize: nalLengthSize)
        }

        let numPPS = Int(avcCData[offset])
        offset += 1

        for _ in 0..<numPPS {
            guard offset + 2 <= avcCData.count else { break }
            let ppsLen = Int(avcCData[offset]) << 8 | Int(avcCData[offset + 1])
            offset += 2
            guard offset + ppsLen <= avcCData.count else { break }
            pps.append(avcCData.subdata(in: offset..<(offset + ppsLen)))
            offset += ppsLen
        }

        return sps.isEmpty ? nil : H264Parameters(sps: sps, pps: pps, nalLengthSize: nalLengthSize)
    }

    /// Add fMP4-specific metadata to manifest using TDF spec's encryptedMetadata field.
    /// The metadata is base64-encoded JSON (unencrypted) per TDF spec allowance. No reader decides anything from it
    /// (ADR-0047 §2 in arkavo-ios). It names the master playlist for players that look the playlist up.
    private func addFMP4Metadata(
        to manifestData: Data,
        assetID: String,
        contentKeyID: String,
        playlistFilename: String
    ) throws -> Data {
        // Parse existing manifest
        guard var manifest = try JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            throw FMP4ProtectionError.manifestParsingFailed
        }

        let protectedAtTimestamp = ISO8601DateFormatter().string(from: Date())

        // Create fMP4 metadata (unencrypted, just base64-encoded)
        let fmp4Meta: [String: Any] = [
            "type": "fmp4-fairplay",
            "assetId": assetID,
            "contentKeyId": contentKeyID,
            "playlistFilename": playlistFilename,
            "encryption": "cbcs-1-9",
            "protectedAt": protectedAtTimestamp
        ]

        // Encode metadata as base64 JSON
        let metadataJSON = try JSONSerialization.data(withJSONObject: fmp4Meta, options: [.sortedKeys])
        let metadataBase64 = metadataJSON.base64EncodedString()

        // Add encryptedMetadata to the first key access object (per TDF spec)
        if var encInfo = manifest["encryptionInformation"] as? [String: Any],
           var keyAccessArray = encInfo["keyAccess"] as? [[String: Any]],
           !keyAccessArray.isEmpty {
            keyAccessArray[0]["encryptedMetadata"] = metadataBase64
            encInfo["keyAccess"] = keyAccessArray
            manifest["encryptionInformation"] = encInfo
        }

        // Add top-level meta section (required by IrohContentService). contentKeyId
        // is the key URIs' uuid (the policy uuid); assetId is the recording's id.
        manifest["meta"] = [
            "assetId": assetID,
            "contentKeyId": contentKeyID,
            "protectedAt": protectedAtTimestamp
        ]

        // Re-serialize
        return try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
    }

    /// A stored ZIP of `manifest.json` (`manifestData`), then each of `entryNames`, read from `tempDir`, in order.
    private func createTDFArchive(
        tempDir: URL,
        manifestData: Data,
        entryNames: [String]
    ) throws -> Data {
        // Create ZIP archive manually (simplified implementation)
        var archive = Data()

        // Files to include: the manifest, then the playlists, inits and segments
        var files: [(name: String, data: Data)] = [(FairPlayPackage.manifestName, manifestData)]
        for name in entryNames {
            files.append((name, try Data(contentsOf: tempDir.appendingPathComponent(name))))
        }

        // Simple ZIP creation (no compression for media files)
        var centralDirectory = Data()
        var localOffset: UInt32 = 0

        for file in files {
            // Local file header
            var localHeader = Data()
            localHeader.append(contentsOf: [0x50, 0x4B, 0x03, 0x04]) // Signature
            localHeader.append(contentsOf: [0x14, 0x00])            // Version needed (2.0)
            localHeader.append(contentsOf: [0x00, 0x00])            // General purpose bit flag
            localHeader.append(contentsOf: [0x00, 0x00])            // Compression method (store)
            localHeader.append(contentsOf: [0x00, 0x00])            // Last mod time
            localHeader.append(contentsOf: [0x00, 0x00])            // Last mod date

            // CRC-32 (calculated)
            let crc = crc32(file.data)
            localHeader.append(crc.littleEndianData)

            // Compressed size (same as uncompressed for store)
            localHeader.append(UInt32(file.data.count).littleEndianData)

            // Uncompressed size
            localHeader.append(UInt32(file.data.count).littleEndianData)

            // Filename length
            let filenameData = file.name.data(using: .utf8) ?? Data()
            localHeader.append(UInt16(filenameData.count).littleEndianData)

            // Extra field length
            localHeader.append(contentsOf: [0x00, 0x00])

            // Filename
            localHeader.append(filenameData)

            // File data
            archive.append(localHeader)
            archive.append(file.data)

            // Central directory entry
            var cdEntry = Data()
            cdEntry.append(contentsOf: [0x50, 0x4B, 0x01, 0x02]) // Signature
            cdEntry.append(contentsOf: [0x14, 0x00])            // Version made by
            cdEntry.append(contentsOf: [0x14, 0x00])            // Version needed
            cdEntry.append(contentsOf: [0x00, 0x00])            // General purpose bit flag
            cdEntry.append(contentsOf: [0x00, 0x00])            // Compression method
            cdEntry.append(contentsOf: [0x00, 0x00])            // Last mod time
            cdEntry.append(contentsOf: [0x00, 0x00])            // Last mod date
            cdEntry.append(crc.littleEndianData)
            cdEntry.append(UInt32(file.data.count).littleEndianData)
            cdEntry.append(UInt32(file.data.count).littleEndianData)
            cdEntry.append(UInt16(filenameData.count).littleEndianData)
            cdEntry.append(contentsOf: [0x00, 0x00])            // Extra field length
            cdEntry.append(contentsOf: [0x00, 0x00])            // Comment length
            cdEntry.append(contentsOf: [0x00, 0x00])            // Disk number start
            cdEntry.append(contentsOf: [0x00, 0x00])            // Internal file attributes
            cdEntry.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // External file attributes
            cdEntry.append(localOffset.littleEndianData)       // Relative offset
            cdEntry.append(filenameData)

            centralDirectory.append(cdEntry)
            localOffset = UInt32(archive.count)
        }

        let cdOffset = archive.count
        archive.append(centralDirectory)

        // End of central directory
        var eocd = Data()
        eocd.append(contentsOf: [0x50, 0x4B, 0x05, 0x06]) // Signature
        eocd.append(contentsOf: [0x00, 0x00])            // Disk number
        eocd.append(contentsOf: [0x00, 0x00])            // CD start disk
        eocd.append(UInt16(files.count).littleEndianData)
        eocd.append(UInt16(files.count).littleEndianData)
        eocd.append(UInt32(centralDirectory.count).littleEndianData)
        eocd.append(UInt32(cdOffset).littleEndianData)
        eocd.append(contentsOf: [0x00, 0x00])            // Comment length

        archive.append(eocd)

        return archive
    }

    /// Simple CRC-32 implementation
    private func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        let table = makeCRCTable()

        for byte in data {
            let index = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = table[index] ^ (crc >> 8)
        }

        return ~crc
    }

    private func makeCRCTable() -> [UInt32] {
        var table = [UInt32](repeating: 0, count: 256)
        for n in 0..<256 {
            var c = UInt32(n)
            for _ in 0..<8 {
                if c & 1 != 0 {
                    c = 0xEDB88320 ^ (c >> 1)
                } else {
                    c >>= 1
                }
            }
            table[n] = c
        }
        return table
    }
}

// MARK: - Extension for little-endian data

private extension UInt16 {
    var littleEndianData: Data {
        var value = self.littleEndian
        return Data(bytes: &value, count: 2)
    }
}

private extension UInt32 {
    var littleEndianData: Data {
        var value = self.littleEndian
        return Data(bytes: &value, count: 4)
    }
}

// MARK: - Errors

/// fMP4 recording protection errors
public enum FMP4ProtectionError: Error, LocalizedError {
    case noVideoTrack
    case noFormatDescription
    case noParameterSets
    case encodingFailed(String)
    case packagingFailed(String)
    case manifestParsingFailed
    case readFailed(String)
    /// Sound that could not be made into profile v2's audio component, one AAC-LC track covering the video: refused
    /// rather than dropped.
    case unsupportedAudio(String)

    public var errorDescription: String? {
        switch self {
        case .noVideoTrack:
            "No video track found in source"
        case .noFormatDescription:
            "No format description in video track"
        case .noParameterSets:
            "Could not extract SPS/PPS from video"
        case let .encodingFailed(reason):
            "fMP4 encoding failed: \(reason)"
        case let .packagingFailed(reason):
            "TDF packaging failed: \(reason)"
        case .manifestParsingFailed:
            "Failed to parse manifest JSON"
        case let .readFailed(reason):
            "Reading the source video failed: \(reason)"
        case let .unsupportedAudio(reason):
            "The source's audio cannot be protected: \(reason)"
        }
    }
}
