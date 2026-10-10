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
    static func make(
        in dir: URL, frames: Int = 30, frameTimes: [Double]? = nil, keyFrameInterval: Int? = nil,
        moovFirst: Bool = false, variableFrameRate: Bool = false, mediaTimeScale: CMTimeScale? = nil,
        sound: Sound? = nil
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
        if let keyFrameInterval {
            settings[AVVideoCompressionPropertiesKey] = [AVVideoMaxKeyFrameIntervalKey: keyFrameInterval]
        }
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
        let audioEnd = Int(Double(frames) / Double(fps) * Self.audioRate)
        func appendAudio(through end: Int, _ frame: Int) async throws {
            while audioFrames < min(end, audioEnd) {
                let count = min(1_024, audioEnd - audioFrames)
                for (index, audioInput) in audioInputs.enumerated() {
                    try await waitUntilReady(audioInput, frame)
                    guard audioInput.append(try tone(track: index, from: audioFrames, count: count)) else {
                        throw writer.error ?? Failure.append(frame)
                    }
                }
                audioFrames += count
            }
        }

        try await appendAudio(through: Int(Self.audioRate), 0)
        for frame in 0 ..< (frameTimes?.count ?? frames) {
            try await waitUntilReady(input, frame)
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
        try await appendAudio(through: audioEnd, frames)

        input.markAsFinished()
        for audioInput in audioInputs { audioInput.markAsFinished() }
        await writer.finishWriting()
        guard writer.status == .completed else { throw writer.error ?? Failure.finish }
        return url
    }
}

extension SyntheticMovie {
    static let audioRate = 48_000.0

    private static func addAudio(_ sound: Sound, to writer: AVAssetWriter) throws -> [AVAssetWriterInput] {
        let settings: [String: Any]
        let tracks: Int
        switch sound {
        case .aac(let count):
            tracks = count
            settings = [AVFormatIDKey: kAudioFormatMPEG4AAC, AVSampleRateKey: audioRate,
                        AVNumberOfChannelsKey: 1, AVEncoderBitRateKey: 64_000]
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

    /// `count` frames of a sine tone (440 Hz, and a fifth higher for each further track) from frame `start`, as
    /// 16-bit linear PCM.
    private static func tone(track: Int, from start: Int, count: Int) throws -> CMSampleBuffer {
        var description = AudioStreamBasicDescription(
            mSampleRate: audioRate, mFormatID: kAudioFormatLinearPCM,
            mFormatFlags: kLinearPCMFormatFlagIsSignedInteger | kLinearPCMFormatFlagIsPacked,
            mBytesPerPacket: 2, mFramesPerPacket: 1, mBytesPerFrame: 2, mChannelsPerFrame: 1, mBitsPerChannel: 16,
            mReserved: 0)
        var format: CMAudioFormatDescription?
        var status = CMAudioFormatDescriptionCreate(allocator: nil, asbd: &description, layoutSize: 0, layout: nil,
                                                    magicCookieSize: 0, magicCookie: nil, extensions: nil,
                                                    formatDescriptionOut: &format)
        guard status == noErr, let format else { throw Failure.audio(status) }
        let frequency = 440.0 * pow(1.5, Double(track))
        let samples = (0 ..< count).map { offset in
            Int16(8_000 * sin(2 * Double.pi * frequency * Double(start + offset) / audioRate))
        }
        var block: CMBlockBuffer?
        status = CMBlockBufferCreateWithMemoryBlock(allocator: nil, memoryBlock: nil, blockLength: count * 2,
                                                    blockAllocator: nil, customBlockSource: nil, offsetToData: 0,
                                                    dataLength: count * 2, flags: 0, blockBufferOut: &block)
        guard status == noErr, let block else { throw Failure.audio(status) }
        status = samples.withUnsafeBytes {
            CMBlockBufferReplaceDataBytes(with: $0.baseAddress!, blockBuffer: block, offsetIntoDestination: 0,
                                          dataLength: count * 2)
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
