import AVFoundation
import CoreGraphics
import CoreMedia
import CoreVideo
import Foundation
import Synchronization

// MARK: - Synthetic Scene & Camera Channel Simulation

/// Base scene content rendered during offline synthetic watermark experiments.
public enum SyntheticSceneStyle: String, Sendable, Equatable, Codable, CaseIterable {
    /// Low-luminance dark scene with subtle motion.
    case dark
    /// High-luminance bright scene with gentle movement.
    case bright
    /// High-motion multi-color moving scene with periodic scene cuts.
    case movingWithSceneCuts
}

/// Simulated screen-to-camera capture degradations applied during synthetic video generation.
public struct SimulatedCameraDegradation: Sendable, Equatable, Codable {
    /// Fractional crop inset applied to each side (`0.0` = full frame, `0.2` = center 60% width & height).
    public let cropInsetFraction: Double
    /// Peak handheld pan/jitter amplitude in normalized screen fraction.
    public let handheldJitterFraction: Double
    /// Per-pixel independent RGB sensor noise standard deviation in `[0, 1]`.
    public let sensorNoiseStdDev: Double
    /// Slow spatially varying camera auto-exposure luminance drift amplitude in `[0, 1]`.
    public let autoExposureDriftAmplitude: Double
    /// Slow camera auto-white-balance blue-yellow drift amplitude in `[0, 1]`.
    public let autoWhiteBalanceDriftAmplitude: Double
    /// Playback start time offset in seconds (simulates trimming an arbitrary window of a longer video).
    public let startTimeOffsetSeconds: Double
    /// Target H.264/HEVC encoding bitrate in bits per second.
    public let averageBitRate: Int
    /// Video codec used for output compression.
    public let useHEVC: Bool
    /// When `true`, composites the watermark via the actual 16-bit `ForensicWatermarkRenderer.makeOverlayCGImage`
    /// path rather than float math, so simulations exercise the live player renderer.
    public let useRenderedOverlayTexture: Bool

    public init(
        cropInsetFraction: Double = 0.0,
        handheldJitterFraction: Double = 0.0,
        sensorNoiseStdDev: Double = 0.0,
        autoExposureDriftAmplitude: Double = 0.0,
        autoWhiteBalanceDriftAmplitude: Double = 0.0,
        startTimeOffsetSeconds: Double = 0.0,
        averageBitRate: Int = 2_500_000,
        useHEVC: Bool = false,
        useRenderedOverlayTexture: Bool = true
    ) {
        self.cropInsetFraction = cropInsetFraction
        self.handheldJitterFraction = handheldJitterFraction
        self.sensorNoiseStdDev = sensorNoiseStdDev
        self.autoExposureDriftAmplitude = autoExposureDriftAmplitude
        self.autoWhiteBalanceDriftAmplitude = autoWhiteBalanceDriftAmplitude
        self.startTimeOffsetSeconds = startTimeOffsetSeconds
        self.averageBitRate = averageBitRate
        self.useHEVC = useHEVC
        self.useRenderedOverlayTexture = useRenderedOverlayTexture
    }

    public static let clean = SimulatedCameraDegradation()

    /// Moderate handheld camera re-capture approximation (crop, jitter, spatially varying AE/AWB drift,
    /// independent RGB chroma/luma sensor noise, 16-bit live overlay texture, and H.264 recompression).
    public static let handheldRecompressed = SimulatedCameraDegradation(
        cropInsetFraction: 0.15,
        handheldJitterFraction: 0.03,
        sensorNoiseStdDev: 0.025,
        autoExposureDriftAmplitude: 0.06,
        autoWhiteBalanceDriftAmplitude: 0.04,
        startTimeOffsetSeconds: 4.3,
        averageBitRate: 900_000,
        useHEVC: false,
        useRenderedOverlayTexture: true
    )
}

/// Offline media helpers for blinded testing: metadata stripping and synthetic H.264/HEVC clip generation.
public enum ForensicWatermarkMediaUtilities {
    private static let sRGBColorSpace = CGColorSpace(name: CGColorSpace.sRGB) ?? CGColorSpaceCreateDeviceRGB()

    /// Creates a metadata-stripped, upright-oriented copy of `inputURL` at `outputURL` for blinded detector testing.
    ///
    /// - Applies the source track's `preferredTransform` in display space before cropping so portrait
    ///   iPhone recordings (e.g., 1920x1080 + 90 deg transform) are properly rotated and cropped with zero
    ///   uninitialized buffer rows.
    /// - Rejects identical input/output paths and directory targets, writes to a unique sibling temporary file,
    ///   verifies reader and writer completion, and atomically replaces `outputURL` only after success.
    public static func stripMetadata(
        from inputURL: URL,
        to outputURL: URL,
        trimStartSeconds: Double? = nil,
        trimDurationSeconds: Double? = nil,
        cropRectNormalized: CGRect? = nil,
        averageBitRate: Int = 2_500_000,
        overwrite: Bool = true
    ) async throws {
        try validateDestination(outputURL: outputURL, inputURL: inputURL, overwrite: overwrite)

        let asset = AVURLAsset(url: inputURL)
        let tracks = try await asset.loadTracks(withMediaType: .video)
        guard let track = tracks.first else {
            throw ForensicWatermarkError.videoTrackMissing
        }

        let naturalSize = try await track.load(.naturalSize)
        let preferredTransform = try await track.load(.preferredTransform)
        let transformedRect = CGRect(origin: .zero, size: naturalSize).applying(preferredTransform)
        let fullWidth = max(16, Int(abs(transformedRect.width).rounded()))
        let fullHeight = max(16, Int(abs(transformedRect.height).rounded()))
        let normalizedTransform = preferredTransform.concatenating(
            CGAffineTransform(translationX: -transformedRect.origin.x, y: -transformedRect.origin.y)
        )

        let crop = cropRectNormalized ?? CGRect(x: 0, y: 0, width: 1, height: 1)
        let outX = max(0, min(fullWidth - 16, Int((crop.minX * Double(fullWidth)).rounded())))
        let outY = max(0, min(fullHeight - 16, Int((crop.minY * Double(fullHeight)).rounded())))
        let rawW = max(16, min(fullWidth - outX, Int((crop.width * Double(fullWidth)).rounded())))
        let rawH = max(16, min(fullHeight - outY, Int((crop.height * Double(fullHeight)).rounded())))
        // H.264 requires even dimensions.
        let outWidth = rawW - (rawW % 2)
        let outHeight = rawH - (rawH % 2)

        let tempURL = makeSiblingTempURL(for: outputURL)
        var committed = false
        defer {
            if !committed {
                try? FileManager.default.removeItem(at: tempURL)
            }
        }

        let reader = try AVAssetReader(asset: asset)
        if let start = trimStartSeconds, let dur = trimDurationSeconds {
            reader.timeRange = CMTimeRange(
                start: CMTime(seconds: max(0, start), preferredTimescale: 600),
                duration: CMTime(seconds: max(0.1, dur), preferredTimescale: 600)
            )
        } else if let start = trimStartSeconds {
            let totalDuration = try await asset.load(.duration)
            let startTime = CMTime(seconds: max(0, start), preferredTimescale: 600)
            let remaining = CMTimeSubtract(totalDuration, startTime)
            if remaining.seconds > 0.1 {
                reader.timeRange = CMTimeRange(start: startTime, duration: remaining)
            }
        } else if let dur = trimDurationSeconds {
            reader.timeRange = CMTimeRange(
                start: .zero,
                duration: CMTime(seconds: max(0.1, dur), preferredTimescale: 600)
            )
        }

        let readerOutput = AVAssetReaderTrackOutput(
            track: track,
            outputSettings: [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
        )
        readerOutput.alwaysCopiesSampleData = false
        guard reader.canAdd(readerOutput) else {
            throw ForensicWatermarkError.metadataStripFailed("Cannot attach reader output")
        }
        reader.add(readerOutput)

        let writer = try AVAssetWriter(outputURL: tempURL, fileType: .mp4)
        writer.metadata = []
        writer.shouldOptimizeForNetworkUse = true

        let videoSettings: [String: Any] = [
            AVVideoCodecKey: AVVideoCodecType.h264,
            AVVideoWidthKey: outWidth,
            AVVideoHeightKey: outHeight,
            AVVideoCompressionPropertiesKey: [
                AVVideoAverageBitRateKey: averageBitRate,
                AVVideoProfileLevelKey: AVVideoProfileLevelH264MainAutoLevel,
            ],
        ]
        let writerInput = AVAssetWriterInput(mediaType: .video, outputSettings: videoSettings)
        writerInput.expectsMediaDataInRealTime = false
        writerInput.metadata = []
        writerInput.transform = .identity

        let adaptor = AVAssetWriterInputPixelBufferAdaptor(
            assetWriterInput: writerInput,
            sourcePixelBufferAttributes: [
                kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
                kCVPixelBufferWidthKey as String: outWidth,
                kCVPixelBufferHeightKey as String: outHeight,
            ]
        )

        guard writer.canAdd(writerInput) else {
            throw ForensicWatermarkError.metadataStripFailed("Cannot attach writer input")
        }
        writer.add(writerInput)

        guard reader.startReading() else {
            throw ForensicWatermarkError.metadataStripFailed(reader.error?.localizedDescription ?? "Reader failed")
        }
        guard writer.startWriting() else {
            reader.cancelReading()
            throw ForensicWatermarkError.metadataStripFailed(writer.error?.localizedDescription ?? "Writer failed")
        }
        writer.startSession(atSourceTime: .zero)

        let pump = StripPumpBox(
            reader: reader,
            readerOutput: readerOutput,
            writer: writer,
            writerInput: writerInput,
            adaptor: adaptor,
            naturalSize: naturalSize,
            normalizedTransform: normalizedTransform,
            cropOriginX: outX,
            cropOriginY: outY,
            outWidth: outWidth,
            outHeight: outHeight
        )
        try await pump.run()

        // Verify reader did not fail midway before finalizing writer (prevents silent truncation).
        if reader.status == .failed {
            writer.cancelWriting()
            throw ForensicWatermarkError.metadataStripFailed(
                reader.error?.localizedDescription ?? "Reader failed during transcode"
            )
        }
        if reader.status == .cancelled {
            writer.cancelWriting()
            throw CancellationError()
        }

        await writer.finishWriting()
        guard writer.status == .completed else {
            throw ForensicWatermarkError.metadataStripFailed(
                writer.error?.localizedDescription ?? "Writer did not complete"
            )
        }

        try commitTempFile(tempURL, to: outputURL, overwrite: overwrite)
        committed = true
    }

    /// Generates an H.264 or HEVC `.mp4` test clip with optional forensic watermark compositing
    /// and simulated handheld camera degradations.
    public static func generateSyntheticVideo(
        outputURL: URL,
        width: Int = 320,
        height: Int = 180,
        frameRate: Int = 30,
        durationSeconds: Double = 15.0,
        scene: SyntheticSceneStyle = .movingWithSceneCuts,
        sessionID: String? = nil,
        configuration: ForensicWatermarkConfiguration = .default,
        degradation: SimulatedCameraDegradation = .clean,
        randomSeed: UInt64 = 42,
        preferredTransform: CGAffineTransform = .identity,
        metadata: [AVMetadataItem] = [],
        overwrite: Bool = true
    ) async throws {
        try configuration.validate()
        if let sessionID {
            _ = try WatermarkSessionCode(sessionID)
        }
        guard width >= 32, height >= 32, width % 2 == 0, height % 2 == 0 else {
            throw ForensicWatermarkError.writerFailed("Video dimensions must be even and >= 32")
        }
        guard frameRate >= 10, frameRate <= 60, durationSeconds > 0 else {
            throw ForensicWatermarkError.writerFailed("Invalid frameRate or durationSeconds")
        }
        try validateDestination(outputURL: outputURL, inputURL: nil, overwrite: overwrite)

        let tempURL = makeSiblingTempURL(for: outputURL)
        var committed = false
        defer {
            if !committed {
                try? FileManager.default.removeItem(at: tempURL)
            }
        }

        let writer = try AVAssetWriter(outputURL: tempURL, fileType: .mp4)
        writer.metadata = metadata

        let codec: AVVideoCodecType = degradation.useHEVC ? .hevc : .h264
        var compressionProps: [String: Any] = [
            AVVideoAverageBitRateKey: degradation.averageBitRate,
        ]
        if !degradation.useHEVC {
            compressionProps[AVVideoProfileLevelKey] = AVVideoProfileLevelH264MainAutoLevel
        }

        let videoSettings: [String: Any] = [
            AVVideoCodecKey: codec,
            AVVideoWidthKey: width,
            AVVideoHeightKey: height,
            AVVideoCompressionPropertiesKey: compressionProps,
        ]

        let writerInput = AVAssetWriterInput(mediaType: .video, outputSettings: videoSettings)
        writerInput.expectsMediaDataInRealTime = false
        writerInput.metadata = []
        writerInput.transform = preferredTransform

        let adaptor = AVAssetWriterInputPixelBufferAdaptor(
            assetWriterInput: writerInput,
            sourcePixelBufferAttributes: [
                kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
                kCVPixelBufferWidthKey as String: width,
                kCVPixelBufferHeightKey as String: height,
            ]
        )

        guard writer.canAdd(writerInput) else {
            throw ForensicWatermarkError.writerFailed("Cannot attach writer input")
        }
        writer.add(writerInput)
        guard writer.startWriting() else {
            throw ForensicWatermarkError.writerFailed(writer.error?.localizedDescription ?? "startWriting failed")
        }
        writer.startSession(atSourceTime: .zero)

        let chips: [Float]? = sessionID.map {
            ForensicWatermarkSignal.chips(for: $0, configuration: configuration)
        }
        let totalFrames = max(1, Int((durationSeconds * Double(frameRate)).rounded()))

        let pump = SyntheticPumpBox(
            writer: writer,
            writerInput: writerInput,
            adaptor: adaptor,
            width: width,
            height: height,
            frameRate: frameRate,
            totalFrames: totalFrames,
            scene: scene,
            chips: chips,
            configuration: configuration,
            degradation: degradation,
            randomSeed: randomSeed
        )
        try await pump.run()

        await writer.finishWriting()
        guard writer.status == .completed else {
            throw ForensicWatermarkError.writerFailed(writer.error?.localizedDescription ?? "Writer failed")
        }

        try commitTempFile(tempURL, to: outputURL, overwrite: overwrite)
        committed = true
    }

    // MARK: - Path Safety Helpers

    private static func validateDestination(outputURL: URL, inputURL: URL?, overwrite: Bool) throws {
        let fm = FileManager.default
        let stdOut = outputURL.standardizedFileURL.resolvingSymlinksInPath()

        if let inputURL {
            let stdIn = inputURL.standardizedFileURL.resolvingSymlinksInPath()
            if stdIn == stdOut {
                throw ForensicWatermarkError.sameInputOutputPath
            }
            if let inID = try? stdIn.resourceValues(forKeys: [.fileResourceIdentifierKey]).fileResourceIdentifier,
               let outID = try? stdOut.resourceValues(forKeys: [.fileResourceIdentifierKey]).fileResourceIdentifier,
               inID.isEqual(outID)
            {
                throw ForensicWatermarkError.sameInputOutputPath
            }
        }

        var isDir: ObjCBool = false
        if fm.fileExists(atPath: stdOut.path, isDirectory: &isDir) {
            if isDir.boolValue {
                throw ForensicWatermarkError.outputPathIsDirectory
            }
            if !overwrite {
                throw ForensicWatermarkError.outputFileAlreadyExists(outputURL.path)
            }
        }

        let parentDir = stdOut.deletingLastPathComponent()
        if !fm.fileExists(atPath: parentDir.path) {
            try fm.createDirectory(at: parentDir, withIntermediateDirectories: true)
        }
    }

    private static func makeSiblingTempURL(for outputURL: URL) -> URL {
        let parent = outputURL.standardizedFileURL.deletingLastPathComponent()
        return parent.appendingPathComponent(".forensic-wm-tmp-\(UUID().uuidString).mp4")
    }

    private static func commitTempFile(_ tempURL: URL, to outputURL: URL, overwrite: Bool) throws {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: outputURL.path, isDirectory: &isDir) {
            if isDir.boolValue {
                throw ForensicWatermarkError.outputPathIsDirectory
            }
            if !overwrite {
                throw ForensicWatermarkError.outputFileAlreadyExists(outputURL.path)
            }
            _ = try fm.replaceItemAt(outputURL, withItemAt: tempURL)
        } else {
            try fm.moveItem(at: tempURL, to: outputURL)
        }
    }

    // MARK: - Oriented Display-Space Transform & Crop Blit

    fileprivate static func transformAndCropBGRA(
        from src: CVPixelBuffer,
        to dst: CVPixelBuffer,
        naturalSize: CGSize,
        normalizedTransform: CGAffineTransform,
        cropOriginX: Int,
        cropOriginY: Int,
        width: Int,
        height: Int
    ) -> Bool {
        CVPixelBufferLockBaseAddress(src, .readOnly)
        CVPixelBufferLockBaseAddress(dst, [])
        defer {
            CVPixelBufferUnlockBaseAddress(dst, [])
            CVPixelBufferUnlockBaseAddress(src, .readOnly)
        }

        guard let srcBase = CVPixelBufferGetBaseAddress(src),
              let dstBase = CVPixelBufferGetBaseAddress(dst)
        else { return false }

        let dstRowBytes = CVPixelBufferGetBytesPerRow(dst)
        let dstHeight = CVPixelBufferGetHeight(dst)
        // Always zero destination buffer so recycled CVPixelBufferPool memory can never leak into output.
        memset(dstBase, 0, dstRowBytes * dstHeight)

        let srcW = CVPixelBufferGetWidth(src)
        let srcH = CVPixelBufferGetHeight(src)
        let srcRowBytes = CVPixelBufferGetBytesPerRow(src)

        let bitmapInfo = CGBitmapInfo(
            rawValue: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue
        )

        guard let srcCtx = CGContext(
            data: srcBase,
            width: srcW,
            height: srcH,
            bitsPerComponent: 8,
            bytesPerRow: srcRowBytes,
            space: sRGBColorSpace,
            bitmapInfo: bitmapInfo.rawValue
        ),
            let srcImage = srcCtx.makeImage(),
            let dstCtx = CGContext(
                data: dstBase,
                width: width,
                height: height,
                bitsPerComponent: 8,
                bytesPerRow: dstRowBytes,
                space: sRGBColorSpace,
                bitmapInfo: bitmapInfo.rawValue
            )
        else {
            return false
        }

        dstCtx.interpolationQuality = .high
        // Map QuickTime top-left display space into CGContext bottom-left space, apply display crop,
        // apply track normalizedTransform, and draw the source image in natural top-left space.
        dstCtx.translateBy(x: 0, y: CGFloat(height))
        dstCtx.scaleBy(x: 1, y: -1)
        dstCtx.translateBy(x: -CGFloat(cropOriginX), y: -CGFloat(cropOriginY))
        dstCtx.concatenate(normalizedTransform)
        dstCtx.translateBy(x: 0, y: naturalSize.height)
        dstCtx.scaleBy(x: 1, y: -1)
        dstCtx.draw(srcImage, in: CGRect(origin: .zero, size: naturalSize))
        return true
    }

    // MARK: - Synthetic Frame Rendering (Independent RGB Noise + Live 16-Bit Overlay Texture)

    fileprivate static func renderSyntheticFrame(
        intoBGRA buffer: CVPixelBuffer,
        width: Int,
        height: Int,
        clipTime: Double,
        playbackTime: Double,
        scene: SyntheticSceneStyle,
        chips: [Float]?,
        configuration: ForensicWatermarkConfiguration,
        degradation: SimulatedCameraDegradation,
        rng: inout SplitMix64
    ) {
        let inset = max(0.0, min(0.4, degradation.cropInsetFraction))
        let span = 1.0 - 2.0 * inset
        let jitterX = degradation.handheldJitterFraction * sin(2.0 * Double.pi * 0.65 * clipTime + 0.4)
        let jitterY = degradation.handheldJitterFraction * cos(2.0 * Double.pi * 0.47 * clipTime + 1.1)

        // Step 1: Render base scene into BGRA buffer.
        renderBaseScene(
            intoBGRA: buffer,
            width: width,
            height: height,
            playbackTime: playbackTime,
            scene: scene,
            inset: inset,
            span: span,
            jitterX: jitterX,
            jitterY: jitterY
        )

        // Step 2: Composite watermark (using the actual 16-bit live overlay CGImage by default).
        if let chips {
            if degradation.useRenderedOverlayTexture,
               let overlayImage = ForensicWatermarkRenderer.makeOverlayCGImage(
                   at: playbackTime,
                   chips: chips,
                   configuration: configuration
               )
            {
                // Map the full virtual screen onto the cropped/jittered camera frame.
                let screenW = CGFloat(width) / CGFloat(max(0.1, span))
                let screenH = CGFloat(height) / CGFloat(max(0.1, span))
                let originX = -CGFloat(inset + jitterX) * screenW
                let originY = -CGFloat(inset + jitterY) * screenH
                ForensicWatermarkRenderer.compositeOverlayImage(
                    overlayImage,
                    ontoBGRA: buffer,
                    in: CGRect(x: originX, y: originY, width: screenW, height: screenH)
                )
            } else {
                compositeFloatWatermark(
                    intoBGRA: buffer,
                    width: width,
                    height: height,
                    playbackTime: playbackTime,
                    chips: chips,
                    configuration: configuration,
                    inset: inset,
                    span: span,
                    jitterX: jitterX,
                    jitterY: jitterY
                )
            }
        }

        // Step 3: Apply simulated camera degradations (spatially varying AE/AWB drift + independent RGB sensor noise).
        applyCameraDegradation(
            toBGRA: buffer,
            width: width,
            height: height,
            clipTime: clipTime,
            degradation: degradation,
            rng: &rng
        )
    }

    private static func renderBaseScene(
        intoBGRA buffer: CVPixelBuffer,
        width: Int,
        height: Int,
        playbackTime: Double,
        scene: SyntheticSceneStyle,
        inset: Double,
        span: Double,
        jitterX: Double,
        jitterY: Double
    ) {
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let baseAddress = CVPixelBufferGetBaseAddress(buffer) else { return }

        let bytesPerRow = CVPixelBufferGetBytesPerRow(buffer)
        let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)
        let cutIndex = Int(floor(playbackTime / 3.7))
        let invW = 1.0 / Double(width)
        let invH = 1.0 / Double(height)

        for y in 0 ..< height {
            let rowPtr = ptr.advanced(by: y * bytesPerRow)
            let vNorm = (Double(y) + 0.5) * invH
            let screenV = max(0.0, min(1.0, inset + vNorm * span + jitterY))

            for x in 0 ..< width {
                let uNorm = (Double(x) + 0.5) * invW
                let screenU = max(0.0, min(1.0, inset + uNorm * span + jitterX))

                let (r, g, b) = baseSceneColor(
                    u: Float(screenU),
                    v: Float(screenV),
                    t: Float(playbackTime),
                    cutIndex: cutIndex,
                    scene: scene
                )
                let offset = x * 4
                rowPtr[offset] = UInt8((max(0, min(1, b)) * 255.0).rounded())
                rowPtr[offset + 1] = UInt8((max(0, min(1, g)) * 255.0).rounded())
                rowPtr[offset + 2] = UInt8((max(0, min(1, r)) * 255.0).rounded())
                rowPtr[offset + 3] = 255
            }
        }
    }

    private static func compositeFloatWatermark(
        intoBGRA buffer: CVPixelBuffer,
        width: Int,
        height: Int,
        playbackTime: Double,
        chips: [Float],
        configuration: ForensicWatermarkConfiguration,
        inset: Double,
        span: Double,
        jitterX: Double,
        jitterY: Double
    ) {
        let temporal = ForensicWatermarkSignal.temporalValue(
            at: playbackTime,
            chips: chips,
            chipRateHz: configuration.chipRateHz
        )
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let baseAddress = CVPixelBufferGetBaseAddress(buffer) else { return }

        let bytesPerRow = CVPixelBufferGetBytesPerRow(buffer)
        let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)
        let invW = 1.0 / Double(width)
        let invH = 1.0 / Double(height)
        let inv255: Float = 1.0 / 255.0

        for y in 0 ..< height {
            let rowPtr = ptr.advanced(by: y * bytesPerRow)
            let vNorm = (Double(y) + 0.5) * invH
            let screenV = max(0.0, min(1.0, inset + vNorm * span + jitterY))

            for x in 0 ..< width {
                let uNorm = (Double(x) + 0.5) * invW
                let screenU = max(0.0, min(1.0, inset + uNorm * span + jitterX))
                let spatial = ForensicWatermarkSignal.spatialWeight(
                    u: Float(screenU),
                    v: Float(screenV),
                    pattern: configuration.spatialPattern
                )
                let ov = ForensicWatermarkSignal.overlayRGBA(
                    signal: spatial * temporal,
                    configuration: configuration
                )
                let a = ov.alpha
                let invA = 1.0 - a
                let offset = x * 4
                let b = invA * Float(rowPtr[offset]) * inv255 + a * ov.blue
                let g = invA * Float(rowPtr[offset + 1]) * inv255 + a * ov.green
                let r = invA * Float(rowPtr[offset + 2]) * inv255 + a * ov.red
                rowPtr[offset] = UInt8((max(0, min(1, b)) * 255.0).rounded())
                rowPtr[offset + 1] = UInt8((max(0, min(1, g)) * 255.0).rounded())
                rowPtr[offset + 2] = UInt8((max(0, min(1, r)) * 255.0).rounded())
            }
        }
    }

    private static func applyCameraDegradation(
        toBGRA buffer: CVPixelBuffer,
        width: Int,
        height: Int,
        clipTime: Double,
        degradation: SimulatedCameraDegradation,
        rng: inout SplitMix64
    ) {
        let hasNoise = degradation.sensorNoiseStdDev > 0
        let hasAE = degradation.autoExposureDriftAmplitude > 0
        let hasAWB = degradation.autoWhiteBalanceDriftAmplitude > 0
        guard hasNoise || hasAE || hasAWB else { return }

        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let baseAddress = CVPixelBufferGetBaseAddress(buffer) else { return }

        let bytesPerRow = CVPixelBufferGetBytesPerRow(buffer)
        let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)

        let aeBase = Float(degradation.autoExposureDriftAmplitude * sin(2.0 * Double.pi * 0.35 * clipTime))
        let awbBase = Float(degradation.autoWhiteBalanceDriftAmplitude * cos(2.0 * Double.pi * 0.25 * clipTime))
        let noiseAmp = Float(degradation.sensorNoiseStdDev)
        let invW = 1.0 / Float(width)
        let invH = 1.0 / Float(height)
        let inv255: Float = 1.0 / 255.0

        for y in 0 ..< height {
            let rowPtr = ptr.advanced(by: y * bytesPerRow)
            let v = (Float(y) + 0.5) * invH
            for x in 0 ..< width {
                let u = (Float(x) + 0.5) * invW
                // Spatially varying lighting/vignette factor so drift is not trivially removed by frame mean.
                let spatialGrad = 1.0 + 0.35 * (u - 0.5) - 0.25 * (v - 0.5)
                let ae = aeBase * spatialGrad
                let awb = awbBase * (1.0 + 0.30 * (v - 0.5))

                // Independent per-channel RGB noise so chroma (B - Y) genuinely experiences camera noise.
                let nB = hasNoise ? rng.nextSymmetricNoise() * noiseAmp : 0
                let nG = hasNoise ? rng.nextSymmetricNoise() * noiseAmp : 0
                let nR = hasNoise ? rng.nextSymmetricNoise() * noiseAmp : 0

                let offset = x * 4
                let b = max(0, min(1, Float(rowPtr[offset]) * inv255 + ae + awb + nB))
                let g = max(0, min(1, Float(rowPtr[offset + 1]) * inv255 + ae + 0.1 * awb + nG))
                let r = max(0, min(1, Float(rowPtr[offset + 2]) * inv255 + ae - 0.3 * awb + nR))

                rowPtr[offset] = UInt8((b * 255.0).rounded())
                rowPtr[offset + 1] = UInt8((g * 255.0).rounded())
                rowPtr[offset + 2] = UInt8((r * 255.0).rounded())
            }
        }
    }

    private static func baseSceneColor(
        u: Float,
        v: Float,
        t: Float,
        cutIndex: Int,
        scene: SyntheticSceneStyle
    ) -> (Float, Float, Float) {
        switch scene {
        case .dark:
            let wave = 0.04 * sin(3.0 * u + 0.8 * t) * cos(2.0 * v - 0.5 * t)
            let base = 0.08 + wave
            return (base, base + 0.01, base + 0.02)

        case .bright:
            let wave = 0.06 * sin(2.5 * u + 0.7 * t) + 0.04 * cos(2.0 * v + 0.4 * t)
            let base = 0.82 + wave
            return (base, base - 0.01, base - 0.02)

        case .movingWithSceneCuts:
            let phase = Float(cutIndex % 4) * 1.3
            let r = 0.42 + 0.25 * sin(4.0 * u + 1.4 * t + phase)
            let g = 0.45 + 0.22 * cos(3.5 * v - 1.1 * t + phase * 0.7)
            let b = 0.40 + 0.24 * sin(3.0 * (u + v) + 0.9 * t - phase)
            return (r, g, b)
        }
    }
}

// MARK: - Serial-Queue Reader/Writer Pumps

/// Single-queue `requestMediaDataWhenReady(on:)` pump for `stripMetadata` so `AVAssetReader` and
/// `AVAssetWriter` stay confined to one serial queue and never hang on writer failure or cancellation.
private final class StripPumpBox: @unchecked Sendable {
    private let reader: AVAssetReader
    private let readerOutput: AVAssetReaderTrackOutput
    private let writer: AVAssetWriter
    private let writerInput: AVAssetWriterInput
    private let adaptor: AVAssetWriterInputPixelBufferAdaptor
    private let naturalSize: CGSize
    private let normalizedTransform: CGAffineTransform
    private let cropOriginX: Int
    private let cropOriginY: Int
    private let outWidth: Int
    private let outHeight: Int
    private let queue = DispatchQueue(label: "com.arkavo.mediakit.watermark.strip")
    private let cancelled = Mutex(false)

    private var firstPTS: CMTime?

    init(
        reader: AVAssetReader,
        readerOutput: AVAssetReaderTrackOutput,
        writer: AVAssetWriter,
        writerInput: AVAssetWriterInput,
        adaptor: AVAssetWriterInputPixelBufferAdaptor,
        naturalSize: CGSize,
        normalizedTransform: CGAffineTransform,
        cropOriginX: Int,
        cropOriginY: Int,
        outWidth: Int,
        outHeight: Int
    ) {
        self.reader = reader
        self.readerOutput = readerOutput
        self.writer = writer
        self.writerInput = writerInput
        self.adaptor = adaptor
        self.naturalSize = naturalSize
        self.normalizedTransform = normalizedTransform
        self.cropOriginX = cropOriginX
        self.cropOriginY = cropOriginY
        self.outWidth = outWidth
        self.outHeight = outHeight
    }

    func run() async throws {
        let finished = Mutex(false)
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let complete: @Sendable (Result<Void, Error>) -> Void = { result in
                    let shouldResume = finished.withLock { done -> Bool in
                        guard !done else { return false }
                        done = true
                        return true
                    }
                    guard shouldResume else { return }
                    self.writerInput.markAsFinished()
                    continuation.resume(with: result)
                }

                self.writerInput.requestMediaDataWhenReady(on: self.queue) {
                    while self.writerInput.isReadyForMoreMediaData {
                        if self.cancelled.withLock({ $0 }) {
                            self.reader.cancelReading()
                            self.writer.cancelWriting()
                            complete(.failure(CancellationError()))
                            return
                        }
                        if self.writer.status != .writing {
                            self.reader.cancelReading()
                            let msg = self.writer.error?.localizedDescription ?? "Writer stopped with status \(self.writer.status.rawValue)"
                            complete(.failure(ForensicWatermarkError.metadataStripFailed(msg)))
                            return
                        }
                        guard let sampleBuffer = self.readerOutput.copyNextSampleBuffer() else {
                            complete(.success(()))
                            return
                        }
                        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
                        guard pts.isValid, pts.isNumeric,
                              let srcBuffer = CMSampleBufferGetImageBuffer(sampleBuffer)
                        else {
                            continue
                        }
                        if self.firstPTS == nil {
                            self.firstPTS = pts
                        }
                        let normalizedPTS = CMTimeSubtract(pts, self.firstPTS ?? pts)

                        guard let pool = self.adaptor.pixelBufferPool else {
                            self.reader.cancelReading()
                            self.writer.cancelWriting()
                            complete(.failure(ForensicWatermarkError.metadataStripFailed("Missing pixel buffer pool")))
                            return
                        }
                        var dstBufferOpt: CVPixelBuffer?
                        let status = CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, pool, &dstBufferOpt)
                        guard status == kCVReturnSuccess, let dstBuffer = dstBufferOpt else {
                            self.reader.cancelReading()
                            self.writer.cancelWriting()
                            complete(.failure(ForensicWatermarkError.metadataStripFailed("Failed to allocate destination pixel buffer")))
                            return
                        }

                        let ok = ForensicWatermarkMediaUtilities.transformAndCropBGRA(
                            from: srcBuffer,
                            to: dstBuffer,
                            naturalSize: self.naturalSize,
                            normalizedTransform: self.normalizedTransform,
                            cropOriginX: self.cropOriginX,
                            cropOriginY: self.cropOriginY,
                            width: self.outWidth,
                            height: self.outHeight
                        )
                        guard ok else {
                            self.reader.cancelReading()
                            self.writer.cancelWriting()
                            complete(.failure(ForensicWatermarkError.metadataStripFailed("Failed to transform and crop frame")))
                            return
                        }

                        guard self.adaptor.append(dstBuffer, withPresentationTime: normalizedPTS) else {
                            self.reader.cancelReading()
                            let msg = self.writer.error?.localizedDescription ?? "Failed to append frame"
                            complete(.failure(ForensicWatermarkError.metadataStripFailed(msg)))
                            return
                        }
                    }
                    if self.writer.status != .writing {
                        self.reader.cancelReading()
                        let msg = self.writer.error?.localizedDescription ?? "Writer stopped unexpectedly"
                        complete(.failure(ForensicWatermarkError.metadataStripFailed(msg)))
                    }
                }
            }
        } onCancel: {
            self.cancelled.withLock { $0 = true }
            self.queue.async {
                self.reader.cancelReading()
                self.writer.cancelWriting()
            }
        }
    }
}

/// Single-queue `requestMediaDataWhenReady(on:)` pump for `generateSyntheticVideo`.
private final class SyntheticPumpBox: @unchecked Sendable {
    private let writer: AVAssetWriter
    private let writerInput: AVAssetWriterInput
    private let adaptor: AVAssetWriterInputPixelBufferAdaptor
    private let width: Int
    private let height: Int
    private let frameRate: Int
    private let totalFrames: Int
    private let scene: SyntheticSceneStyle
    private let chips: [Float]?
    private let configuration: ForensicWatermarkConfiguration
    private let degradation: SimulatedCameraDegradation
    private let queue = DispatchQueue(label: "com.arkavo.mediakit.watermark.synth")
    private let cancelled = Mutex(false)

    private var frameIdx = 0
    private var rng: SplitMix64

    init(
        writer: AVAssetWriter,
        writerInput: AVAssetWriterInput,
        adaptor: AVAssetWriterInputPixelBufferAdaptor,
        width: Int,
        height: Int,
        frameRate: Int,
        totalFrames: Int,
        scene: SyntheticSceneStyle,
        chips: [Float]?,
        configuration: ForensicWatermarkConfiguration,
        degradation: SimulatedCameraDegradation,
        randomSeed: UInt64
    ) {
        self.writer = writer
        self.writerInput = writerInput
        self.adaptor = adaptor
        self.width = width
        self.height = height
        self.frameRate = frameRate
        self.totalFrames = totalFrames
        self.scene = scene
        self.chips = chips
        self.configuration = configuration
        self.degradation = degradation
        self.rng = SplitMix64(seed: randomSeed)
    }

    func run() async throws {
        let finished = Mutex(false)
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let complete: @Sendable (Result<Void, Error>) -> Void = { result in
                    let shouldResume = finished.withLock { done -> Bool in
                        guard !done else { return false }
                        done = true
                        return true
                    }
                    guard shouldResume else { return }
                    self.writerInput.markAsFinished()
                    continuation.resume(with: result)
                }

                self.writerInput.requestMediaDataWhenReady(on: self.queue) {
                    while self.writerInput.isReadyForMoreMediaData {
                        if self.cancelled.withLock({ $0 }) {
                            self.writer.cancelWriting()
                            complete(.failure(CancellationError()))
                            return
                        }
                        if self.writer.status != .writing {
                            let msg = self.writer.error?.localizedDescription ?? "Writer stopped with status \(self.writer.status.rawValue)"
                            complete(.failure(ForensicWatermarkError.writerFailed(msg)))
                            return
                        }
                        if self.frameIdx >= self.totalFrames {
                            complete(.success(()))
                            return
                        }

                        guard let pool = self.adaptor.pixelBufferPool else {
                            self.writer.cancelWriting()
                            complete(.failure(ForensicWatermarkError.writerFailed("Missing pixel buffer pool")))
                            return
                        }
                        var bufferOpt: CVPixelBuffer?
                        let status = CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, pool, &bufferOpt)
                        guard status == kCVReturnSuccess, let buffer = bufferOpt else {
                            self.writer.cancelWriting()
                            complete(.failure(ForensicWatermarkError.writerFailed("Failed to allocate pixel buffer")))
                            return
                        }

                        let clipTime = Double(self.frameIdx) / Double(self.frameRate)
                        let playbackTime = clipTime + self.degradation.startTimeOffsetSeconds
                        ForensicWatermarkMediaUtilities.renderSyntheticFrame(
                            intoBGRA: buffer,
                            width: self.width,
                            height: self.height,
                            clipTime: clipTime,
                            playbackTime: playbackTime,
                            scene: self.scene,
                            chips: self.chips,
                            configuration: self.configuration,
                            degradation: self.degradation,
                            rng: &self.rng
                        )

                        let pts = CMTime(value: CMTimeValue(self.frameIdx), timescale: CMTimeScale(self.frameRate))
                        guard self.adaptor.append(buffer, withPresentationTime: pts) else {
                            let msg = self.writer.error?.localizedDescription ?? "append failed"
                            complete(.failure(ForensicWatermarkError.writerFailed(msg)))
                            return
                        }
                        self.frameIdx += 1
                    }
                    if self.writer.status != .writing {
                        let msg = self.writer.error?.localizedDescription ?? "Writer stopped unexpectedly"
                        complete(.failure(ForensicWatermarkError.writerFailed(msg)))
                    }
                }
            }
        } onCancel: {
            self.cancelled.withLock { $0 = true }
            self.queue.async {
                self.writer.cancelWriting()
            }
        }
    }
}

/// Fast deterministic PRNG for reproducible synthetic camera noise.
private struct SplitMix64 {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func nextUInt64() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    /// Approximate zero-mean unit-variance symmetric noise using difference of two uniforms.
    mutating func nextSymmetricNoise() -> Float {
        let u1 = Float(nextUInt64() >> 40) / Float(1 << 24)
        let u2 = Float(nextUInt64() >> 40) / Float(1 << 24)
        return (u1 - u2) * 2.4494897 // sqrt(6) -> std dev ~= 1.0
    }
}
