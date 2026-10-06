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
    static func make(
        in dir: URL, frames: Int = 30, frameTimes: [Double]? = nil, keyFrameInterval: Int? = nil,
        moovFirst: Bool = false, variableFrameRate: Bool = false, mediaTimeScale: CMTimeScale? = nil
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
        guard writer.startWriting() else { throw writer.error ?? Failure.startFailed }
        writer.startSession(atSourceTime: .zero)

        for frame in 0 ..< (frameTimes?.count ?? frames) {
            // Bounded wait: a failed writer never becomes ready.
            let deadline = Date().addingTimeInterval(5)
            while !input.isReadyForMoreMediaData {
                if writer.status == .failed { throw writer.error ?? Failure.append(frame) }
                guard Date() < deadline else { throw Failure.readyTimeout(frame) }
                try await Task.sleep(nanoseconds: 2_000_000)
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
        }

        input.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else { throw writer.error ?? Failure.finish }
        return url
    }
}

private extension CMTimeValue {
    func clamped(min lower: CMTimeValue) -> CMTimeValue { Swift.max(self, lower) }
}
