import AVFoundation
import CoreVideo
import Foundation

/// A real H.264 `.mov` for tests that run the fMP4 protect pipeline end to end.
/// Ported from Creator's `LiveKASRewrapIntegrationTests.makeSyntheticMovie`.
enum SyntheticMovie {
    enum Failure: Error {
        case writerRejectedInput
        case startFailed
        case readyTimeout(Int)
        case noPixelBufferPool
        case pixelBuffer(CVReturn)
        case append(Int)
        case finish
        case audio(OSStatus)
    }

    /// The sound a synthetic movie records: sine tones at 48 kHz, mono, one tone per track.
    enum Sound {
        /// AAC-LC tracks.
        case aac(tracks: Int)
        /// One 16-bit linear PCM track.
        case pcm
        /// One AAC-LC track of `channels` channels in `layout`, the tone in each. Apple's encoder writes a layout no
        /// AAC channel configuration names with channelConfiguration 0 and a program config element (quadraphonic),
        /// or with a configuration that ISO/IEC 14496-3 reserved before it named it (11, for 6.1 and 7.0).
        case aacLayout(channels: Int, layout: AudioChannelLayoutTag)

        /// Each track's channel count and layout (nil: mono, no layout).
        var channels: (count: Int, layout: AudioChannelLayoutTag?) {
            if case let .aacLayout(channels, layout) = self { return (channels, layout) }
            return (1, nil)
        }
    }

    /// A 320x180, 30 fps H.264 `.mov` of `frames` solid-colour frames.
    /// - Parameters:
    ///   - keyFrameInterval: The most frames between sync samples, when set.
    ///   - moovFirst: Writes the movie header before the media data, so the
    ///     tracks still load after the file is truncated.
    ///   - variableFrameRate: Jitters each timestamp by up to ±13 ms on a µs
    ///     timescale, as a real-time recorder's frames arrive.
    ///   - frameTimes: Explicit presentation times in seconds, replacing `frames`
    ///     and `variableFrameRate`. The session still starts at zero, so a first
    ///     time above zero leaves the leading empty edit a recorder that drops
    ///     its first captured frame writes.
    ///   - mediaTimeScale: The video track's timescale, when set.
    ///   - sound: Audio tracks as long as the video (`frames` at 30 fps), when set.
    ///   - soundExtra: How long the audio runs past the video's end, in seconds.
    ///   - frameReordering: H.264 High with B-frames, passed through an MP4 export, which writes the reordering
    ///     delay as the video's edit, as the device spike's source has it: the first sample decodes at 0 and is
    ///     presented at a later media time, which the edit maps to 0. The result is an `.mp4`.
    static func make(
        in dir: URL, frames: Int = 30, frameTimes: [Double]? = nil, keyFrameInterval: Int? = nil,
        moovFirst: Bool = false, variableFrameRate: Bool = false, mediaTimeScale: CMTimeScale? = nil,
        sound: Sound? = nil, soundExtra: Double = 0, frameReordering: Bool = false
    ) async throws -> URL {
        let url = dir.appendingPathComponent("synthetic-\(UUID().uuidString).mov")
        let width = 320, height = 180, fps: Int32 = 30
        let writer = try AVAssetWriter(outputURL: url, fileType: .mov)
        writer.shouldOptimizeForNetworkUse = moovFirst
        var settings: [String: Any] = [
            AVVideoCodecKey: AVVideoCodecType.h264,
            AVVideoWidthKey: width,
            AVVideoHeightKey: height,
        ]
        var compression: [String: Any] = [:]
        if let keyFrameInterval { compression[AVVideoMaxKeyFrameIntervalKey] = keyFrameInterval }
        if frameReordering {
            compression[AVVideoAllowFrameReorderingKey] = true
            compression[AVVideoProfileLevelKey] = AVVideoProfileLevelH264HighAutoLevel
        }
        if !compression.isEmpty { settings[AVVideoCompressionPropertiesKey] = compression }
        let input = AVAssetWriterInput(mediaType: .video, outputSettings: settings)
        if let mediaTimeScale { input.mediaTimeScale = mediaTimeScale }
        input.expectsMediaDataInRealTime = false
        let adaptor = AVAssetWriterInputPixelBufferAdaptor(
            assetWriterInput: input,
            sourcePixelBufferAttributes: [
                kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
                kCVPixelBufferWidthKey as String: width,
                kCVPixelBufferHeightKey as String: height,
            ])
        guard writer.canAdd(input) else { throw Failure.writerRejectedInput }
        writer.add(input)
        let audioInputs = try sound.map { try addAudio($0, to: writer) } ?? []
        let audioChannels = sound?.channels ?? (1, nil)
        guard writer.startWriting() else { throw writer.error ?? Failure.startFailed }
        writer.startSession(atSourceTime: .zero)

        // Bounded wait: a failed writer never becomes ready.
        func waitUntilReady(_ input: AVAssetWriterInput, _ frame: Int) async throws {
            let deadline = Date().addingTimeInterval(5)
            while !input.isReadyForMoreMediaData {
                if writer.status == .failed { throw writer.error ?? Failure.append(frame) }
                guard Date() < deadline else { throw Failure.readyTimeout(frame) }
                try await Task.sleep(nanoseconds: 2_000_000)
            }
        }
        // Audio is appended alongside the video, a second ahead of it, so the writer can interleave.
        var audioFrames = 0
        let audioEnd = Int((Double(frames) / Double(fps) + soundExtra) * Self.audioRate)
        var audioFinished = audioInputs.isEmpty
        func appendAudio(through end: Int, _ frame: Int) async throws {
            defer {
                // Finished as soon as it is all written, so the writer does not wait on it for the video's sake.
                if audioFrames >= audioEnd, !audioFinished {
                    for audioInput in audioInputs { audioInput.markAsFinished() }
                    audioFinished = true
                }
            }
            while audioFrames < min(end, audioEnd) {
                let count = min(1_024, audioEnd - audioFrames)
                for (index, audioInput) in audioInputs.enumerated() {
                    try await waitUntilReady(audioInput, frame)
                    guard audioInput.append(try tone(track: index, channels: audioChannels, from: audioFrames,
                                                     count: count)) else {
                        throw writer.error ?? Failure.append(frame)
                    }
                }
                audioFrames += count
            }
        }

        try await appendAudio(through: Int(Self.audioRate), 0)
        for frame in 0 ..< (frameTimes?.count ?? frames) {
            // While the video waits, the writer may be waiting for audio to interleave: give it the next buffer.
            let deadline = Date().addingTimeInterval(5)
            while !input.isReadyForMoreMediaData {
                if writer.status == .failed { throw writer.error ?? Failure.append(frame) }
                guard Date() < deadline else { throw Failure.readyTimeout(frame) }
                if audioFrames < audioEnd, audioInputs.allSatisfy(\.isReadyForMoreMediaData) {
                    try await appendAudio(through: audioFrames + 1_024, frame)
                } else {
                    try await Task.sleep(nanoseconds: 2_000_000)
                }
            }
            guard let pool = adaptor.pixelBufferPool else { throw Failure.noPixelBufferPool }
            var buffer: CVPixelBuffer?
            let status = CVPixelBufferPoolCreatePixelBuffer(nil, pool, &buffer)
            guard status == kCVReturnSuccess, let buffer else { throw Failure.pixelBuffer(status) }

            CVPixelBufferLockBaseAddress(buffer, [])
            if let base = CVPixelBufferGetBaseAddress(buffer) {
                // One BGRA pixel, repeated over the whole buffer (row padding included).
                var pixel: [UInt8] = [UInt8(frame * 4 % 256), 0x60, UInt8(255 - frame * 4 % 256), 0xFF]
                memset_pattern4(base, &pixel, CVPixelBufferGetBytesPerRow(buffer) * height)
            }
            CVPixelBufferUnlockBaseAddress(buffer, [])

            let pts = if let frameTimes {
                CMTime(seconds: frameTimes[frame], preferredTimescale: 1_000_000)
            } else if variableFrameRate {
                // 33,333 µs apart ± 13,000 µs (deterministic), so still strictly increasing.
                CMTime(value: CMTimeValue(frame * 33_333 + (frame * 7_919) % 26_001 - 13_000).clamped(min: 0),
                       timescale: 1_000_000)
            } else {
                CMTime(value: CMTimeValue(frame), timescale: fps)
            }
            guard adaptor.append(buffer, withPresentationTime: pts) else {
                throw writer.error ?? Failure.append(frame)
            }
            try await appendAudio(through: Int((Double(frame + 1) / Double(fps) + 1) * Self.audioRate), frame)
        }
        // The video ends first, so the writer takes audio past its end.
        input.markAsFinished()
        try await appendAudio(through: audioEnd, frames)
        await writer.finishWriting()
        guard writer.status == .completed else { throw writer.error ?? Failure.finish }
        guard frameReordering else { return url }
        // AVAssetWriter writes B-frames as negative composition offsets; an MP4 export writes the delay as an edit.
        guard let export = AVAssetExportSession(asset: AVURLAsset(url: url), presetName: AVAssetExportPresetPassthrough)
        else { throw Failure.writerRejectedInput }
        let mp4 = dir.appendingPathComponent("reordered-\(UUID().uuidString).mp4")
        try await export.export(to: mp4, as: .mp4)
        return mp4
    }
}

extension SyntheticMovie {
    static let audioRate = 48_000.0

    /// A copy of `movie` whose audio starts `delay` seconds after its video (an empty edit before it), as an editor
    /// would place it: composed, then exported without re-encoding.
    static func delayingAudio(of movie: URL, by delay: Double, in dir: URL) async throws -> URL {
        let asset = AVURLAsset(url: movie)
        let duration = try await asset.load(.duration)
        let shift = CMTime(seconds: delay, preferredTimescale: 48_000)
        let composition = AVMutableComposition()
        for (type, at, length) in [(AVMediaType.video, CMTime.zero, duration), (.audio, shift, duration - shift)] {
            guard let source = try await asset.loadTracks(withMediaType: type).first,
                  let track = composition.addMutableTrack(withMediaType: type,
                                                          preferredTrackID: kCMPersistentTrackID_Invalid)
            else { throw Failure.writerRejectedInput }
            try track.insertTimeRange(CMTimeRange(start: .zero, duration: length), of: source, at: at)
        }
        guard let export = AVAssetExportSession(asset: composition, presetName: AVAssetExportPresetPassthrough)
        else { throw Failure.writerRejectedInput }
        let url = dir.appendingPathComponent("delayed-\(UUID().uuidString).mov")
        try await export.export(to: url, as: .mov)
        return url
    }

    private static func addAudio(_ sound: Sound, to writer: AVAssetWriter) throws -> [AVAssetWriterInput] {
        let settings: [String: Any]
        let tracks: Int
        switch sound {
        case .aac(let count):
            tracks = count
            settings = [AVFormatIDKey: kAudioFormatMPEG4AAC, AVSampleRateKey: audioRate,
                        AVNumberOfChannelsKey: 1, AVEncoderBitRateKey: 64_000]
        case let .aacLayout(channels, layout):
            tracks = 1
            settings = [AVFormatIDKey: kAudioFormatMPEG4AAC, AVSampleRateKey: audioRate,
                        AVNumberOfChannelsKey: channels, AVChannelLayoutKey: layoutData(layout)]
        case .pcm:
            tracks = 1
            settings = [AVFormatIDKey: kAudioFormatLinearPCM, AVSampleRateKey: audioRate, AVNumberOfChannelsKey: 1,
                        AVLinearPCMBitDepthKey: 16, AVLinearPCMIsFloatKey: false,
                        AVLinearPCMIsBigEndianKey: false, AVLinearPCMIsNonInterleaved: false]
        }
        return try (0 ..< tracks).map { _ in
            let input = AVAssetWriterInput(mediaType: .audio, outputSettings: settings)
            input.expectsMediaDataInRealTime = false
            guard writer.canAdd(input) else { throw Failure.writerRejectedInput }
            writer.add(input)
            return input
        }
    }

    private static func layoutData(_ tag: AudioChannelLayoutTag) -> Data {
        var layout = AudioChannelLayout()
        layout.mChannelLayoutTag = tag
        return Data(bytes: &layout, count: MemoryLayout<AudioChannelLayout>.size)
    }

    /// `count` frames of a sine tone (440 Hz, and a fifth higher for each further track) from frame `start`, as
    /// 16-bit linear PCM, the same in each of `channels`.
    private static func tone(track: Int, channels: (count: Int, layout: AudioChannelLayoutTag?), from start: Int,
                             count: Int) throws -> CMSampleBuffer {
        let width = channels.count
        var description = AudioStreamBasicDescription(
            mSampleRate: audioRate, mFormatID: kAudioFormatLinearPCM,
            mFormatFlags: kLinearPCMFormatFlagIsSignedInteger | kLinearPCMFormatFlagIsPacked,
            mBytesPerPacket: UInt32(2 * width), mFramesPerPacket: 1, mBytesPerFrame: UInt32(2 * width),
            mChannelsPerFrame: UInt32(width), mBitsPerChannel: 16, mReserved: 0)
        var format: CMAudioFormatDescription?
        var layout = AudioChannelLayout()
        layout.mChannelLayoutTag = channels.layout ?? 0
        var status = withUnsafePointer(to: &layout) { layoutPointer in
            CMAudioFormatDescriptionCreate(
                allocator: nil, asbd: &description,
                layoutSize: channels.layout == nil ? 0 : MemoryLayout<AudioChannelLayout>.size,
                layout: channels.layout == nil ? nil : layoutPointer, magicCookieSize: 0, magicCookie: nil,
                extensions: nil, formatDescriptionOut: &format)
        }
        guard status == noErr, let format else { throw Failure.audio(status) }
        let frequency = 440.0 * pow(1.5, Double(track))
        let samples = (0 ..< count * width).map { index in
            Int16(8_000 * sin(2 * Double.pi * frequency * Double(start + index / width) / audioRate))
        }
        let length = count * width * 2
        var block: CMBlockBuffer?
        status = CMBlockBufferCreateWithMemoryBlock(allocator: nil, memoryBlock: nil, blockLength: length,
                                                    blockAllocator: nil, customBlockSource: nil, offsetToData: 0,
                                                    dataLength: length, flags: 0, blockBufferOut: &block)
        guard status == noErr, let block else { throw Failure.audio(status) }
        status = samples.withUnsafeBytes {
            CMBlockBufferReplaceDataBytes(with: $0.baseAddress!, blockBuffer: block, offsetIntoDestination: 0,
                                          dataLength: length)
        }
        guard status == noErr else { throw Failure.audio(status) }
        var buffer: CMSampleBuffer?
        status = CMAudioSampleBufferCreateReadyWithPacketDescriptions(
            allocator: nil, dataBuffer: block, formatDescription: format, sampleCount: count,
            presentationTimeStamp: CMTime(value: CMTimeValue(start), timescale: CMTimeScale(audioRate)),
            packetDescriptions: nil, sampleBufferOut: &buffer)
        guard status == noErr, let buffer else { throw Failure.audio(status) }
        return buffer
    }
}

private extension CMTimeValue {
    func clamped(min lower: CMTimeValue) -> CMTimeValue { Swift.max(self, lower) }
}

extension SyntheticMovie {
    /// A copy of `movie`'s video alone, written as it is (no re-encoding), each sample's NAL units passed through
    /// `transform` and written with `nalLengthSize`-byte lengths, which the copy's avcC declares. The source's NAL
    /// units have 4-byte lengths.
    static func rewritingVideo(of movie: URL, in dir: URL, nalLengthSize: Int = 4,
                               transform: @escaping ([Data]) -> [Data] = { $0 }) async throws -> URL {
        let asset = AVURLAsset(url: movie)
        guard let track = try await asset.loadTracks(withMediaType: .video).first,
              let source = try await track.load(.formatDescriptions).first
        else { throw Failure.writerRejectedInput }
        // The source's parameter sets, under the new length size.
        var count = 0
        var status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            source, parameterSetIndex: 0, parameterSetPointerOut: nil, parameterSetSizeOut: nil,
            parameterSetCountOut: &count, nalUnitHeaderLengthOut: nil)
        guard status == noErr else { throw Failure.audio(status) }
        var pointers: [UnsafePointer<UInt8>] = [], sizes: [Int] = []
        for index in 0 ..< count {
            var pointer: UnsafePointer<UInt8>?, size = 0
            status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                source, parameterSetIndex: index, parameterSetPointerOut: &pointer, parameterSetSizeOut: &size,
                parameterSetCountOut: nil, nalUnitHeaderLengthOut: nil)
            guard status == noErr, let pointer else { throw Failure.audio(status) }
            pointers.append(pointer)
            sizes.append(size)
        }
        var format: CMFormatDescription?
        status = CMVideoFormatDescriptionCreateFromH264ParameterSets(
            allocator: nil, parameterSetCount: count, parameterSetPointers: pointers, parameterSetSizes: sizes,
            nalUnitHeaderLength: Int32(nalLengthSize), formatDescriptionOut: &format)
        guard status == noErr, let format else { throw Failure.audio(status) }

        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderTrackOutput(track: track, outputSettings: nil)
        reader.add(output)
        let url = dir.appendingPathComponent("rewritten-\(UUID().uuidString).mov")
        let writer = try AVAssetWriter(outputURL: url, fileType: .mov)
        let input = AVAssetWriterInput(mediaType: .video, outputSettings: nil, sourceFormatHint: format)
        input.expectsMediaDataInRealTime = false
        guard writer.canAdd(input) else { throw Failure.writerRejectedInput }
        writer.add(input)
        guard reader.startReading(), writer.startWriting() else { throw writer.error ?? Failure.startFailed }
        writer.startSession(atSourceTime: .zero)
        var frame = 0
        while let buffer = output.copyNextSampleBuffer() {
            guard let block = CMSampleBufferGetDataBuffer(buffer) else { continue }
            var bytes = [UInt8](repeating: 0, count: CMBlockBufferGetDataLength(block))
            guard CMBlockBufferCopyDataBytes(block, atOffset: 0, dataLength: bytes.count, destination: &bytes) == noErr
            else { throw Failure.append(frame) }
            var nals: [Data] = [], offset = 0
            while offset + 4 <= bytes.count {
                let length = bytes[offset ..< offset + 4].reduce(0) { $0 << 8 | Int($1) }
                nals.append(Data(bytes[offset + 4 ..< offset + 4 + length]))
                offset += 4 + length
            }
            var sample = Data()
            for nal in transform(nals) {
                sample += (0 ..< nalLengthSize).reversed().map { UInt8(truncatingIfNeeded: nal.count >> (8 * $0)) }
                sample += nal
            }
            var timing = CMSampleTimingInfo()
            guard CMSampleBufferGetSampleTimingInfo(buffer, at: 0, timingInfoOut: &timing) == noErr else {
                throw Failure.append(frame)
            }
            var rewritten: CMBlockBuffer?
            status = CMBlockBufferCreateWithMemoryBlock(
                allocator: nil, memoryBlock: nil, blockLength: sample.count, blockAllocator: nil,
                customBlockSource: nil, offsetToData: 0, dataLength: sample.count,
                flags: kCMBlockBufferAssureMemoryNowFlag, blockBufferOut: &rewritten)
            guard status == noErr, let rewritten else { throw Failure.audio(status) }
            status = sample.withUnsafeBytes {
                CMBlockBufferReplaceDataBytes(with: $0.baseAddress!, blockBuffer: rewritten,
                                              offsetIntoDestination: 0, dataLength: sample.count)
            }
            guard status == noErr else { throw Failure.audio(status) }
            var copy: CMSampleBuffer?
            var size = sample.count
            status = CMSampleBufferCreateReady(
                allocator: nil, dataBuffer: rewritten, formatDescription: format, sampleCount: 1,
                sampleTimingEntryCount: 1, sampleTimingArray: &timing, sampleSizeEntryCount: 1,
                sampleSizeArray: &size, sampleBufferOut: &copy)
            guard status == noErr, let copy else { throw Failure.audio(status) }
            // Keep which samples are sync samples.
            if let attachments = CMSampleBufferGetSampleAttachmentsArray(buffer, createIfNecessary: false)
                as? [[CFString: Any]], attachments.first?[kCMSampleAttachmentKey_NotSync] as? Bool == true,
                let target = CMSampleBufferGetSampleAttachmentsArray(copy, createIfNecessary: true) {
                let dictionary = unsafeBitCast(CFArrayGetValueAtIndex(target, 0), to: CFMutableDictionary.self)
                CFDictionarySetValue(dictionary, Unmanaged.passUnretained(kCMSampleAttachmentKey_NotSync).toOpaque(),
                                     Unmanaged.passUnretained(kCFBooleanTrue).toOpaque())
            }
            let deadline = Date().addingTimeInterval(5)
            while !input.isReadyForMoreMediaData {
                guard Date() < deadline, writer.status != .failed else { throw writer.error ?? Failure.append(frame) }
                try await Task.sleep(nanoseconds: 2_000_000)
            }
            guard input.append(copy) else { throw writer.error ?? Failure.append(frame) }
            frame += 1
        }
        guard reader.status == .completed else { throw reader.error ?? Failure.finish }
        input.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else { throw writer.error ?? Failure.finish }
        return url
    }

    /// A filler data NAL unit (type 12): kept clear, its own subsample.
    static let fillerNAL = Data([0x0C, 0xFF, 0xFF, 0x80])
}
