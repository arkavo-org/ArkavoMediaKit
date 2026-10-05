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
    static func make(in dir: URL, frames: Int = 60) async throws -> URL {
        let url = dir.appendingPathComponent("synthetic-\(UUID().uuidString).mov")
        let width = 320, height = 180, fps: Int32 = 30
        let writer = try AVAssetWriter(outputURL: url, fileType: .mov)
        let input = AVAssetWriterInput(mediaType: .video, outputSettings: [
            AVVideoCodecKey: AVVideoCodecType.h264,
            AVVideoWidthKey: width,
            AVVideoHeightKey: height,
        ])
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

        for frame in 0 ..< frames {
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
                let bytesPerRow = CVPixelBufferGetBytesPerRow(buffer)
                let pixel: [UInt8] = [UInt8(frame * 4 % 256), 0x60, UInt8(255 - frame * 4 % 256), 0xFF] // BGRA
                for row in 0 ..< height {
                    let rowPointer = base.advanced(by: row * bytesPerRow).assumingMemoryBound(to: UInt8.self)
                    for x in 0 ..< width {
                        for channel in 0 ..< 4 { rowPointer[x * 4 + channel] = pixel[channel] }
                    }
                }
            }
            CVPixelBufferUnlockBaseAddress(buffer, [])

            let pts = CMTime(value: CMTimeValue(frame), timescale: fps)
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
