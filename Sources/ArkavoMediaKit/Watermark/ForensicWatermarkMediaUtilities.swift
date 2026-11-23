import AVFoundation
import CoreGraphics
import CoreMedia
import CoreVideo
import Foundation

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
    /// Per-pixel additive sensor noise standard deviation in `[0, 1]`.
    public let sensorNoiseStdDev: Double
    /// Slow camera auto-exposure luminance drift amplitude in `[0, 1]`.
    public let autoExposureDriftAmplitude: Double
    /// Slow camera auto-white-balance blue-yellow drift amplitude in `[0, 1]`.
    public let autoWhiteBalanceDriftAmplitude: Double
    /// Playback start time offset in seconds (simulates trimming an arbitrary window of a longer video).
    public let startTimeOffsetSeconds: Double
    /// Target H.264/HEVC encoding bitrate in bits per second.
    public let averageBitRate: Int
    /// Video codec used for output compression.
    public let useHEVC: Bool

    public init(
        cropInsetFraction: Double = 0.0,
        handheldJitterFraction: Double = 0.0,
        sensorNoiseStdDev: Double = 0.0,
        autoExposureDriftAmplitude: Double = 0.0,
        autoWhiteBalanceDriftAmplitude: Double = 0.0,
        startTimeOffsetSeconds: Double = 0.0,
        averageBitRate: Int = 2_500_000,
        useHEVC: Bool = false
    ) {
        self.cropInsetFraction = cropInsetFraction
        self.handheldJitterFraction = handheldJitterFraction
        self.sensorNoiseStdDev = sensorNoiseStdDev
        self.autoExposureDriftAmplitude = autoExposureDriftAmplitude
        self.autoWhiteBalanceDriftAmplitude = autoWhiteBalanceDriftAmplitude
        self.startTimeOffsetSeconds = startTimeOffsetSeconds
        self.averageBitRate = averageBitRate
        self.useHEVC = useHEVC
    }

    public static let clean = SimulatedCameraDegradation()

    /// Moderate handheld camera re-capture approximation (crop, jitter, AE/AWB drift, noise, recompression).
    public static let handheldRecompressed = SimulatedCameraDegradation(
        cropInsetFraction: 0.15,
        handheldJitterFraction: 0.03,
        sensorNoiseStdDev: 0.025,
        autoExposureDriftAmplitude: 0.06,
        autoWhiteBalanceDriftAmplitude: 0.04,
        startTimeOffsetSeconds: 4.3,
        averageBitRate: 900_000,
        useHEVC: false
    )
}

/// Offline media helpers for blinded testing: metadata stripping and synthetic H.264/HEVC clip generation.
public enum ForensicWatermarkMediaUtilities {
    /// Creates a metadata-stripped copy of `inputURL` at `outputURL` for blinded detector testing.
    ///
    /// Re-encodes video frames without container metadata, creation dates, GPS, device model, or custom atoms.
    public static func stripMetadata(
        from inputURL: URL,
        to outputURL: URL,
        trimStartSeconds: Double? = nil,
        trimDurationSeconds: Double? = nil,
        cropRectNormalized: CGRect? = nil,
        averageBitRate: Int = 2_500_000
    ) async throws {
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

        let crop = cropRectNormalized ?? CGRect(x: 0, y: 0, width: 1, height: 1)
        let outX = max(0, min(fullWidth - 16, Int((crop.minX * Double(fullWidth)).rounded())))
        let outY = max(0, min(fullHeight - 16, Int((crop.minY * Double(fullHeight)).rounded())))
        let rawW = max(16, min(fullWidth - outX, Int((crop.width * Double(fullWidth)).rounded())))
        let rawH = max(16, min(fullHeight - outY, Int((crop.height * Double(fullHeight)).rounded())))
        // H.264 requires even dimensions.
        let outWidth = rawW - (rawW % 2)
        let outHeight = rawH - (rawH % 2)

        if FileManager.default.fileExists(atPath: outputURL.path) {
            try FileManager.default.removeItem(at: outputURL)
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

        let writer = try AVAssetWriter(outputURL: outputURL, fileType: .mp4)
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
            throw ForensicWatermarkError.metadataStripFailed(writer.error?.localizedDescription ?? "Writer failed")
        }
        writer.startSession(atSourceTime: .zero)

        var firstPTS: CMTime?
        while let sampleBuffer = readerOutput.copyNextSampleBuffer() {
            let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
            guard pts.isValid, pts.isNumeric, let srcBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else {
                continue
            }
            if firstPTS == nil {
                firstPTS = pts
            }
            let normalizedPTS = CMTimeSubtract(pts, firstPTS ?? pts)

            while !writerInput.isReadyForMoreMediaData {
                try await Task.sleep(nanoseconds: 2_000_000)
            }

            guard let pool = adaptor.pixelBufferPool else {
                throw ForensicWatermarkError.metadataStripFailed("Missing pixel buffer pool")
            }
            var dstBufferOpt: CVPixelBuffer?
            let status = CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, pool, &dstBufferOpt)
            guard status == kCVReturnSuccess, let dstBuffer = dstBufferOpt else {
                throw ForensicWatermarkError.metadataStripFailed("Failed to allocate destination pixel buffer")
            }

            copyCroppedBGRA(
                from: srcBuffer,
                to: dstBuffer,
                cropOriginX: outX,
                cropOriginY: outY,
                width: outWidth,
                height: outHeight
            )

            guard adaptor.append(dstBuffer, withPresentationTime: normalizedPTS) else {
                throw ForensicWatermarkError.metadataStripFailed(
                    writer.error?.localizedDescription ?? "Failed to append frame"
                )
            }
        }

        writerInput.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else {
            throw ForensicWatermarkError.metadataStripFailed(
                writer.error?.localizedDescription ?? "Writer did not complete"
            )
        }
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
        randomSeed: UInt64 = 42
    ) async throws {
        try configuration.validate()
        guard width >= 32, height >= 32, width % 2 == 0, height % 2 == 0 else {
            throw ForensicWatermarkError.writerFailed("Video dimensions must be even and >= 32")
        }
        guard frameRate >= 10, frameRate <= 60, durationSeconds > 0 else {
            throw ForensicWatermarkError.writerFailed("Invalid frameRate or durationSeconds")
        }

        if FileManager.default.fileExists(atPath: outputURL.path) {
            try FileManager.default.removeItem(at: outputURL)
        }

        let writer = try AVAssetWriter(outputURL: outputURL, fileType: .mp4)
        writer.metadata = []

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
        var rng = SplitMix64(seed: randomSeed)

        for frameIdx in 0 ..< totalFrames {
            while !writerInput.isReadyForMoreMediaData {
                try await Task.sleep(nanoseconds: 2_000_000)
            }

            guard let pool = adaptor.pixelBufferPool else {
                throw ForensicWatermarkError.writerFailed("Missing pixel buffer pool")
            }
            var bufferOpt: CVPixelBuffer?
            let status = CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, pool, &bufferOpt)
            guard status == kCVReturnSuccess, let buffer = bufferOpt else {
                throw ForensicWatermarkError.writerFailed("Failed to allocate pixel buffer")
            }

            let clipTime = Double(frameIdx) / Double(frameRate)
            let playbackTime = clipTime + degradation.startTimeOffsetSeconds
            renderSyntheticFrame(
                intoBGRA: buffer,
                width: width,
                height: height,
                clipTime: clipTime,
                playbackTime: playbackTime,
                scene: scene,
                chips: chips,
                configuration: configuration,
                degradation: degradation,
                rng: &rng
            )

            let pts = CMTime(value: CMTimeValue(frameIdx), timescale: CMTimeScale(frameRate))
            guard adaptor.append(buffer, withPresentationTime: pts) else {
                throw ForensicWatermarkError.writerFailed(writer.error?.localizedDescription ?? "append failed")
            }
        }

        writerInput.markAsFinished()
        await writer.finishWriting()
        guard writer.status == .completed else {
            throw ForensicWatermarkError.writerFailed(writer.error?.localizedDescription ?? "Writer failed")
        }
    }

    // MARK: - Private Pixel Helpers

    private static func copyCroppedBGRA(
        from src: CVPixelBuffer,
        to dst: CVPixelBuffer,
        cropOriginX: Int,
        cropOriginY: Int,
        width: Int,
        height: Int
    ) {
        CVPixelBufferLockBaseAddress(src, .readOnly)
        CVPixelBufferLockBaseAddress(dst, [])
        defer {
            CVPixelBufferUnlockBaseAddress(dst, [])
            CVPixelBufferUnlockBaseAddress(src, .readOnly)
        }

        guard let srcBase = CVPixelBufferGetBaseAddress(src),
              let dstBase = CVPixelBufferGetBaseAddress(dst)
        else { return }

        let srcW = CVPixelBufferGetWidth(src)
        let srcH = CVPixelBufferGetHeight(src)
        let srcRowBytes = CVPixelBufferGetBytesPerRow(src)
        let dstRowBytes = CVPixelBufferGetBytesPerRow(dst)
        let copyW = min(width, max(0, srcW - cropOriginX))
        let copyH = min(height, max(0, srcH - cropOriginY))
        let rowByteCount = copyW * 4

        for y in 0 ..< copyH {
            let srcRow = srcBase.advanced(by: (cropOriginY + y) * srcRowBytes + cropOriginX * 4)
            let dstRow = dstBase.advanced(by: y * dstRowBytes)
            memcpy(dstRow, srcRow, rowByteCount)
        }
    }

    private static func renderSyntheticFrame(
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
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let baseAddress = CVPixelBufferGetBaseAddress(buffer) else { return }

        let bytesPerRow = CVPixelBufferGetBytesPerRow(buffer)
        let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)

        let inset = max(0.0, min(0.4, degradation.cropInsetFraction))
        let span = 1.0 - 2.0 * inset
        let jitterX = degradation.handheldJitterFraction * sin(2.0 * Double.pi * 0.65 * clipTime + 0.4)
        let jitterY = degradation.handheldJitterFraction * cos(2.0 * Double.pi * 0.47 * clipTime + 1.1)

        let aeDrift = Float(degradation.autoExposureDriftAmplitude * sin(2.0 * Double.pi * 0.35 * clipTime))
        let awbDrift = Float(degradation.autoWhiteBalanceDriftAmplitude * cos(2.0 * Double.pi * 0.25 * clipTime))
        let noiseAmp = Float(degradation.sensorNoiseStdDev)

        let temporal: Float = if let chips {
            ForensicWatermarkSignal.temporalValue(
                at: playbackTime,
                chips: chips,
                chipRateHz: configuration.chipRateHz
            )
        } else {
            0
        }

        // Scene cut phase every ~3.7 seconds for moving scenes.
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

                var (r, g, b) = baseSceneColor(
                    u: Float(screenU),
                    v: Float(screenV),
                    t: Float(playbackTime),
                    cutIndex: cutIndex,
                    scene: scene
                )

                if chips != nil {
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
                    r = invA * r + a * ov.red
                    g = invA * g + a * ov.green
                    b = invA * b + a * ov.blue
                }

                // Simulated camera AE/AWB drift and zero-mean sensor noise.
                let n = noiseAmp > 0 ? rng.nextSymmetricNoise() * noiseAmp : 0
                r = max(0, min(1, r + aeDrift - 0.3 * awbDrift + n))
                g = max(0, min(1, g + aeDrift + 0.1 * awbDrift + n))
                b = max(0, min(1, b + aeDrift + awbDrift + n))

                let offset = x * 4
                rowPtr[offset] = UInt8((b * 255.0).rounded())
                rowPtr[offset + 1] = UInt8((g * 255.0).rounded())
                rowPtr[offset + 2] = UInt8((r * 255.0).rounded())
                rowPtr[offset + 3] = 255
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

    /// Approximate zero-mean unit-variance symmetric noise using sum of two uniforms.
    mutating func nextSymmetricNoise() -> Float {
        let u1 = Float(nextUInt64() >> 40) / Float(1 << 24)
        let u2 = Float(nextUInt64() >> 40) / Float(1 << 24)
        return (u1 - u2) * 2.4494897 // sqrt(6) -> std dev ~= 1.0
    }
}
