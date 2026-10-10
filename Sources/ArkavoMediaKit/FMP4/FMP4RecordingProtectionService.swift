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

    /// Protect video content with fMP4/CBCS encryption for FairPlay streaming
    ///
    /// This produces true FairPlay-compatible content with:
    /// - fMP4 (CMAF) container with encrypted sample entries (encv/enca)
    /// - CBCS 1:9 pattern encryption for video
    /// - HLS playlist with EXT-X-KEY using skd:// URI
    /// - pssh/tenc/sinf boxes for encryption signaling
    ///
    /// - Parameters:
    ///   - videoURL: URL to the source video file
    ///   - assetID: Unique asset identifier, recorded in the fMP4 metadata and `meta`
    ///   - policyJSON: TDF policy JSON (`{"uuid", "body": {"dataAttributes", "dissem"}}`).
    ///     BOM-less UTF-8 without duplicate keys; its `uuid` must be a lower-case
    ///     UUID: it becomes the FairPlay content-key id
    ///     (`skd://<uuid>` in the playlist). Nil embeds `FairPlayPolicy.placeholderJSON()`,
    ///     which the post-#75 license service refuses (no data attributes).
    /// - Returns: TDF ZIP archive data containing manifest, playlist, init.mp4, and encrypted segments
    public func protectVideo(
        videoURL: URL,
        assetID: String,
        policyJSON: Data? = nil
    ) async throws -> Data {
        let policy = policyJSON ?? FairPlayPolicy.placeholderJSON()
        let contentKeyID = try FairPlayPolicy.uuid(ofPolicyJSON: policy)

        // Create temporary directory for fMP4 conversion
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }

        // 1. Generate encryption key and IV
        print("🔑 Generating content encryption key...")
        let contentKey = CBCSEncryptor.generateKeyID()  // 16-byte AES-128 key
        let constantIV = CBCSEncryptor.generateIV()     // 16-byte constant IV
        // All-zero KID: FairPlay keys off the skd:// content-key id (the policy
        // uuid), not the KID, which is CENC bookkeeping only
        let keyID = Data(repeating: 0, count: 16)

        // 2. Fetch KAS public key and wrap content key
        print("🔐 Wrapping content key with KAS public key...")
        let manifestBuilder = TDFManifestBuilder(kasURL: kasURL)
        let kasKey: SecKey
        if let pem = kasPublicKeyPEM {
            kasKey = try manifestBuilder.publicKey(fromPEM: pem)
        } else {
            kasKey = try await manifestBuilder.fetchKASPublicKey()
        }
        let manifest = try manifestBuilder.buildManifest(
            contentKey: contentKey,
            iv: constantIV,
            policyJSON: policy,
            publicKey: kasKey
        )
        let manifestData = try manifestBuilder.serializeManifest(manifest)

        // 3. Extract video info from source
        print("🎬 Analyzing source video...")
        let asset = AVURLAsset(url: videoURL)
        let tracks = try await asset.loadTracks(withMediaType: .video)
        guard let videoTrack = tracks.first else {
            throw FMP4ProtectionError.noVideoTrack
        }

        // Get video parameters
        let formatDescriptions = try await videoTrack.load(.formatDescriptions)
        guard let formatDesc = formatDescriptions.first else {
            throw FMP4ProtectionError.noFormatDescription
        }

        let dimensions = try await videoTrack.load(.naturalSize)
        let timescale = try await videoTrack.load(.naturalTimeScale)
        let (trackSegments, totalSampleBytes) = try await videoTrack.load(.segments, .totalSampleDataLength)

        // Extract SPS/PPS and NAL length size from format description
        guard let h264Params = extractParameterSets(from: formatDesc) else {
            throw FMP4ProtectionError.noParameterSets
        }

        // Profile v1 carries the sound, as one AAC-LC track, whenever the source has sound.
        let audioSource = try await Self.audioSource(of: asset, mixingIn: tempDir)

        // 4. Create FMP4 writer with encryption config
        print("📦 Creating fMP4 writer with CBCS encryption...")
        let trackConfig = FMP4Writer.TrackConfig.h264Video(
            width: UInt16(dimensions.width),
            height: UInt16(dimensions.height),
            timescale: UInt32(timescale),
            sps: h264Params.sps,
            pps: h264Params.pps
        )

        let encryptionConfig = FMP4Writer.EncryptionConfig(
            keyID: keyID,
            constantIV: constantIV
        )

        let writer = FMP4Writer(tracks: [trackConfig] + (audioSource.map { [$0.config] } ?? []),
                                encryption: encryptionConfig)
        let encryptor = CBCSEncryptor(key: contentKey, iv: constantIV)
        let nalLengthSize = h264Params.nalLengthSize
        // Protection starts after each slice header, measured from the stream's own parameter sets.
        let sliceHeaders = try H264SliceHeaderParser(sps: h264Params.sps, pps: h264Params.pps)

        // 5. Generate init segment
        print("📝 Generating init segment...")
        let initSegment = writer.generateInitSegment()
        let initURL = tempDir.appendingPathComponent("init.mp4")
        try initSegment.write(to: initURL)

        // 6. Read and encrypt samples
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

        // 6b. Read and encrypt the audio packets, whole-block full-sample, placed on the video's timeline: the
        // package's time 0 is the first video sample's decode time, and both tracks' edits map media to presentation.
        let videoEnd = Double(samples.reduce(UInt64(0)) { $0 + UInt64($1.duration) }) / Double(timescale)
        let videoOffset = Self.presentationOffset(of: trackSegments) - (firstDecodeTime?.seconds ?? 0)
        let audio = try audioSource.map {
            Self.trim(try Self.readAudio($0, encryptor: encryptor, timeOffset: -videoOffset),
                      sampleRate: $0.sampleRate, to: videoEnd)
        } ?? []
        let audioSamples = audio.map(\.sample)

        // 7. Generate media segments (about 6 seconds each)
        print("📼 Generating media segments...")
        let ranges = Self.segmentRanges(
            for: samples.map { SegmentSample(duration: $0.duration, isSync: $0.isSync) },
            targetDuration: UInt64(timescale) * 6  // not Int32 6 * timescale: overflows past 357,913,941
        )
        // Each segment takes the audio packets that start within its video's time; the last takes the rest.
        let segmentStarts = ranges.map { range in
            Double(samples[..<range.lowerBound].reduce(UInt64(0)) { $0 + UInt64($1.duration) }) / Double(timescale)
        }
        let audioRanges = Self.audioRanges(startTimes: audio.map(\.time), segmentStarts: segmentStarts)
        var segments: [FMP4HLSGenerator.Segment] = []
        var baseDecodeTime: UInt64 = 0
        var audioDecodeTime: UInt64 = 0  // where the previous audio fragment ended

        for (segmentIndex, range) in ranges.enumerated() {
            let segmentSamples = Array(samples[range])
            let segmentDuration = segmentSamples.reduce(UInt64(0)) { $0 + UInt64($1.duration) }
            var fragments = [FMP4Writer.TrackFragment(trackID: 1, samples: segmentSamples,
                                                      baseDecodeTime: baseDecodeTime)]
            if let audioSource, let first = audioRanges[segmentIndex].first {
                let segmentAudio = Array(audioSamples[audioRanges[segmentIndex]])
                // Its first packet's time, so a gap before it is kept; never before the previous fragment's end.
                let start = max(audioDecodeTime,
                                UInt64((audio[first].time * Double(audioSource.sampleRate)).rounded()))
                fragments.append(FMP4Writer.TrackFragment(trackID: audioSource.config.trackID, samples: segmentAudio,
                                                          baseDecodeTime: start))
                audioDecodeTime = start + segmentAudio.reduce(UInt64(0)) { $0 + UInt64($1.duration) }
            }
            let segmentData = writer.generateMediaSegment(fragments: fragments)

            let segmentFilename = "segment\(segmentIndex).m4s"
            let segmentURL = tempDir.appendingPathComponent(segmentFilename)
            try segmentData.write(to: segmentURL)

            let duration = Double(segmentDuration) / Double(timescale)
            segments.append(FMP4HLSGenerator.Segment(uri: segmentFilename, duration: duration))

            baseDecodeTime += segmentDuration
        }

        print("   Created \(segments.count) segments")

        // 8. Generate HLS playlist
        print("📋 Generating HLS playlist...")
        let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: Self.targetDuration(forSegmentDurations: segments.map(\.duration)),
            playlistType: .vod,
            initSegmentURI: "init.mp4"
        )

        // The license service matches the SPC against the policy uuid.
        let fairPlayConfig = FMP4HLSGenerator.FairPlayConfig(
            keyURI: "skd://\(contentKeyID)",
            keyID: keyID,
            iv: constantIV
        )

        let hlsGenerator = FMP4HLSGenerator(config: playlistConfig, encryption: fairPlayConfig)
        let playlist = hlsGenerator.generateMediaPlaylist(segments: segments)

        let playlistURL = tempDir.appendingPathComponent("playlist.m3u8")
        try playlist.write(to: playlistURL, atomically: true, encoding: .utf8)

        // 9. Package into TDF archive (ZIP)
        print("📦 Packaging into TDF archive...")

        // Add fMP4-specific metadata to manifest (the segments are listed in the playlist)
        let enhancedManifestData = try addFMP4Metadata(
            to: manifestData,
            assetID: assetID,
            contentKeyID: contentKeyID,
            playlistFilename: "playlist.m3u8",
            initFilename: "init.mp4"
        )

        let archive = try createTDFArchive(
            tempDir: tempDir,
            manifestData: enhancedManifestData,
            segments: segments
        )

        print("✅ fMP4 FairPlay protection complete: \(archive.count) bytes")
        return archive
    }

    // MARK: - Audio

    /// The source's sound: its one AAC-LC track, packaged as track 2 at its sample rate.
    struct AudioSource {
        /// The asset the track is read from: the source, or the mix of its audio.
        let asset: AVURLAsset
        let track: AVAssetTrack
        let config: FMP4Writer.TrackConfig
        let sampleRate: UInt32
        /// Seconds from a packet's media time to its presentation time: the track's first edit.
        let presentationOffset: Double
    }

    /// Seconds from media time to presentation time in a track's first edit that shows media (an empty edit before
    /// it delays the track; an edit that starts into the media skips priming or reordering delay), or 0 with none.
    static func presentationOffset(of segments: [AVAssetTrackSegment]) -> Double {
        guard let edit = segments.first(where: { !$0.isEmpty }) else { return 0 }
        return edit.timeMapping.target.start.seconds - edit.timeMapping.source.start.seconds
    }

    /// The packets of the package's span: those that end after its start and start before `end` (the video's), the
    /// first moved to no earlier than 0.
    static func trim(_ packets: [(sample: FMP4Writer.Sample, time: Double)], sampleRate: UInt32,
                     to end: Double) -> [(sample: FMP4Writer.Sample, time: Double)] {
        packets
            .filter { $0.time + Double($0.sample.duration) / Double(sampleRate) > 0 && $0.time < end }
            .map { ($0.sample, max($0.time, 0)) }
    }

    /// The source's sound as one AAC-LC track, or nil when it has none.
    ///
    /// One AAC-LC track is packaged as it is. Anything else (several tracks, as a recorder writes one per source, or
    /// audio in another format) is mixed and encoded once, as AAC-LC, into `directory`, and that track is packaged:
    /// profile v1 carries one AAC-LC track, and sound is never dropped.
    static func audioSource(of asset: AVURLAsset, mixingIn directory: URL) async throws -> AudioSource? {
        let tracks = try await asset.loadTracks(withMediaType: .audio)
        guard !tracks.isEmpty else { return nil }
        if tracks.count == 1, let source = try await passThrough(tracks[0], of: asset) { return source }
        let mixed = AVURLAsset(url: try await mix(tracks, of: asset,
                                                  into: directory.appendingPathComponent("audio.m4a")))
        guard let track = try await mixed.loadTracks(withMediaType: .audio).first,
              let source = try await passThrough(track, of: mixed) else {
            throw FMP4ProtectionError.unsupportedAudio("mixing the audio did not produce AAC-LC")
        }
        return source
    }

    /// `track` packaged as it is, when it is AAC-LC; otherwise nil.
    private static func passThrough(_ track: AVAssetTrack, of asset: AVURLAsset) async throws -> AudioSource? {
        let descriptions = try await track.load(.formatDescriptions)
        guard descriptions.count == 1, let format = descriptions.first,
              CMFormatDescriptionGetMediaSubType(format) == kAudioFormatMPEG4AAC,
              let description = CMAudioFormatDescriptionGetStreamBasicDescription(format)?.pointee,
              description.mSampleRate > 0, description.mChannelsPerFrame > 0,
              let config = audioSpecificConfig(of: format), config.count >= 2, config[config.startIndex] >> 3 == 2
        else { return nil }
        let sampleRate = UInt32(description.mSampleRate)
        return AudioSource(
            asset: asset,
            track: track,
            config: .aacAudio(trackID: 2, channelCount: UInt16(description.mChannelsPerFrame),
                              sampleRate: sampleRate, audioSpecificConfig: config),
            sampleRate: sampleRate,
            presentationOffset: presentationOffset(of: try await track.load(.segments)))
    }

    /// `tracks` mixed (each through its own edits, on the asset's timeline from 0) and encoded as AAC-LC at 48 kHz,
    /// stereo when any of them is, into an M4A at `url`.
    static func mix(_ tracks: [AVAssetTrack], of asset: AVURLAsset, into url: URL) async throws -> URL {
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
        while let buffer = output.copyNextSampleBuffer() {
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
        guard reader.status == .completed else {
            throw FMP4ProtectionError.readFailed(reader.error?.localizedDescription ?? "audio mix did not finish")
        }
        input.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else {
            throw FMP4ProtectionError.encodingFailed(writer.error?.localizedDescription ?? "audio mix did not finish")
        }
        return url
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

    /// Add fMP4-specific metadata to manifest using TDF spec's encryptedMetadata field
    /// The metadata is base64-encoded JSON (unencrypted) per TDF spec allowance
    private func addFMP4Metadata(
        to manifestData: Data,
        assetID: String,
        contentKeyID: String,
        playlistFilename: String,
        initFilename: String
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
            "initFilename": initFilename,
            "encryption": "cbcs-1-9",
            "protectedAt": protectedAtTimestamp
        ]

        // Encode metadata as base64 JSON
        let metadataJSON = try JSONSerialization.data(withJSONObject: fmp4Meta, options: [.sortedKeys])
        let metadataBase64 = metadataJSON.base64EncodedString()

        // Add encryptedMetadata to keyAccess (per TDF spec)
        if var encInfo = manifest["encryptionInformation"] as? [String: Any],
           var keyAccessArray = encInfo["keyAccess"] as? [[String: Any]],
           !keyAccessArray.isEmpty {
            keyAccessArray[0]["encryptedMetadata"] = metadataBase64
            encInfo["keyAccess"] = keyAccessArray
            manifest["encryptionInformation"] = encInfo
        }

        // Add top-level meta section (required by IrohContentService). contentKeyId
        // is the skd:// id (the policy uuid); assetId is the recording's id.
        manifest["meta"] = [
            "assetId": assetID,
            "contentKeyId": contentKeyID,
            "protectedAt": protectedAtTimestamp
        ]

        // Re-serialize
        return try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
    }

    private func createTDFArchive(
        tempDir: URL,
        manifestData: Data,
        segments: [FMP4HLSGenerator.Segment]
    ) throws -> Data {
        // Create ZIP archive manually (simplified implementation)
        var archive = Data()

        // Files to include
        var files: [(name: String, data: Data)] = []

        // Add manifest
        files.append(("manifest.json", manifestData))

        // Add playlist
        let playlistURL = tempDir.appendingPathComponent("playlist.m3u8")
        let playlistData = try Data(contentsOf: playlistURL)
        files.append(("playlist.m3u8", playlistData))

        // Add init segment
        let initURL = tempDir.appendingPathComponent("init.mp4")
        let initData = try Data(contentsOf: initURL)
        files.append(("init.mp4", initData))

        // Add media segments
        for segment in segments {
            let segmentURL = tempDir.appendingPathComponent(segment.uri)
            let segmentData = try Data(contentsOf: segmentURL)
            files.append((segment.uri, segmentData))
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
    /// Sound that could not be made into profile v1's AAC-LC track: refused rather than dropped.
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
