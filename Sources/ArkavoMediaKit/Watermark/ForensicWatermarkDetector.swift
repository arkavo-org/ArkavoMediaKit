import Accelerate
import AVFoundation
import CoreMedia
import CoreVideo
import Foundation

// MARK: - Detection Options & Results

/// Tunable parameters for the offline forensic watermark detector.
public struct ForensicWatermarkDetectionOptions: Sendable, Equatable, Codable {
    /// Target uniform resampling rate in Hz used before bandpass filtering and FFT correlation.
    ///
    /// The detector snaps this rate slightly to `round(periodSeconds * sampleRateHz) / periodSeconds`
    /// so every repeating code period contains an exact integer number of samples with zero cumulative
    /// phase drift on arbitrarily long recordings.
    public let sampleRateHz: Double

    /// Number of horizontal coarse spatial cells extracted per video frame.
    public let gridColumns: Int

    /// Number of vertical coarse spatial cells extracted per video frame.
    public let gridRows: Int

    /// Number of deterministic domain-separated decoy codes evaluated per clip for empirical null calibration.
    public let decoyCount: Int

    /// Base minimum decoy-calibrated z-score required to declare a positive detection instead of `.inconclusive`.
    ///
    /// For multi-candidate searches, the effective threshold is adjusted upward by
    /// `candidateCountPenaltyScale * ln(candidateCount)` to account for extreme-value multiple testing.
    public let minZScore: Double

    /// Extreme-value multiple-testing scale (`~0.78` for Gumbel right tails) applied as
    /// `candidateCountPenaltyScale * ln(max(1, candidateCount))` on top of `minZScore`.
    public let candidateCountPenaltyScale: Double

    /// Minimum calibrated z-score separation between the top candidate and runner-up (or max decoy).
    public let minMarginOverRunnerUp: Double

    /// Minimum analyzed clip duration in seconds required to attempt detection.
    public let minDurationSeconds: Double

    /// Upper bound on seconds analyzed per clip to keep memory and runtime bounded on long recordings.
    public let maxClipDurationSeconds: Double

    public init(
        sampleRateHz: Double = 32.0,
        gridColumns: Int = 6,
        gridRows: Int = 4,
        decoyCount: Int = 64,
        minZScore: Double = 5.0,
        candidateCountPenaltyScale: Double = 0.78,
        minMarginOverRunnerUp: Double = 2.0,
        minDurationSeconds: Double = 3.0,
        maxClipDurationSeconds: Double = 120.0
    ) {
        self.sampleRateHz = sampleRateHz
        self.gridColumns = gridColumns
        self.gridRows = gridRows
        self.decoyCount = decoyCount
        self.minZScore = minZScore
        self.candidateCountPenaltyScale = candidateCountPenaltyScale
        self.minMarginOverRunnerUp = minMarginOverRunnerUp
        self.minDurationSeconds = minDurationSeconds
        self.maxClipDurationSeconds = maxClipDurationSeconds
    }

    public static let `default` = ForensicWatermarkDetectionOptions()

    /// Computes the candidate-count-adjusted z-score threshold actually applied during decision making.
    public func effectiveMinZScore(candidateCount: Int) -> Double {
        let count = max(1, candidateCount)
        return minZScore + candidateCountPenaltyScale * log(Double(count))
    }

    public func validate(for configuration: ForensicWatermarkConfiguration) throws {
        guard sampleRateHz.isFinite, sampleRateHz >= configuration.chipRateHz * 4.0, sampleRateHz <= 120.0 else {
            throw ForensicWatermarkError.invalidConfiguration(
                "sampleRateHz must be at least 4x chipRateHz and at most 120 Hz"
            )
        }
        guard gridColumns >= 2, gridColumns <= 16, gridRows >= 2, gridRows <= 16 else {
            throw ForensicWatermarkError.invalidConfiguration("grid dimensions must be in 2...16")
        }
        guard decoyCount >= 16, decoyCount <= 512 else {
            throw ForensicWatermarkError.invalidConfiguration("decoyCount must be in 16...512")
        }
        guard minZScore.isFinite, minZScore >= 2.0 else {
            throw ForensicWatermarkError.invalidConfiguration("minZScore must be >= 2.0")
        }
        guard candidateCountPenaltyScale.isFinite, candidateCountPenaltyScale >= 0.0, candidateCountPenaltyScale <= 3.0 else {
            throw ForensicWatermarkError.invalidConfiguration("candidateCountPenaltyScale must be in [0.0, 3.0]")
        }
        guard minMarginOverRunnerUp.isFinite, minMarginOverRunnerUp >= 0.0 else {
            throw ForensicWatermarkError.invalidConfiguration("minMarginOverRunnerUp must be >= 0.0")
        }
        guard minDurationSeconds.isFinite, minDurationSeconds > 0, maxClipDurationSeconds >= minDurationSeconds else {
            throw ForensicWatermarkError.invalidConfiguration("Invalid clip duration bounds")
        }
    }
}

/// Reason why the detector refused to identify a session and returned `.inconclusive`.
public enum ForensicWatermarkInconclusiveReason: String, Sendable, Equatable, Codable {
    case clipTooShort
    case insufficientSignalVariance
    case noCandidates
    case belowDetectionThreshold
    case ambiguousMargin
}

/// Outcome of analyzing a video clip against a candidate session set.
public enum ForensicWatermarkDetectionOutcome: Sendable, Equatable, Codable {
    case detected(sessionID: String)
    case inconclusive(reason: ForensicWatermarkInconclusiveReason)

    public var detectedSessionID: String? {
        if case let .detected(sessionID) = self {
            return sessionID
        }
        return nil
    }
}

/// Detection score details for a single candidate session ID.
public struct ForensicWatermarkCandidateScore: Sendable, Equatable, Codable {
    public let sessionID: String
    /// Best channel standardized score (`max(z_spatial, z_global)`) prior to combined-max decoy calibration.
    public let combinedChannelScore: Double
    /// Empirical decoy-calibrated z-score of the combined-max statistic.
    public let zScore: Double
    /// Estimated clip start phase within the periodic watermark cycle, in seconds.
    public let estimatedPhaseOffsetSeconds: Double
    /// Separation in calibrated z-score units between this candidate and the strongest competitor (runner-up or max decoy).
    public let marginOverRunnerUp: Double

    public init(
        sessionID: String,
        combinedChannelScore: Double,
        zScore: Double,
        estimatedPhaseOffsetSeconds: Double,
        marginOverRunnerUp: Double
    ) {
        self.sessionID = sessionID
        self.combinedChannelScore = combinedChannelScore
        self.zScore = zScore
        self.estimatedPhaseOffsetSeconds = estimatedPhaseOffsetSeconds
        self.marginOverRunnerUp = marginOverRunnerUp
    }
}

/// Empirical null distribution measured on the analyzed clip using domain-separated decoy sequences.
public struct ForensicWatermarkNullStatistics: Sendable, Equatable, Codable {
    public let decoyCount: Int
    public let mean: Double
    public let standardDeviation: Double
    public let maxDecoyScore: Double
    public let maxDecoyZScore: Double
    public let effectiveZScoreThreshold: Double

    public init(
        decoyCount: Int,
        mean: Double,
        standardDeviation: Double,
        maxDecoyScore: Double,
        maxDecoyZScore: Double,
        effectiveZScoreThreshold: Double
    ) {
        self.decoyCount = decoyCount
        self.mean = mean
        self.standardDeviation = standardDeviation
        self.maxDecoyScore = maxDecoyScore
        self.maxDecoyZScore = maxDecoyZScore
        self.effectiveZScoreThreshold = effectiveZScoreThreshold
    }
}

/// Complete detection report for a single analyzed video clip.
public struct ForensicWatermarkDetectionResult: Sendable, Equatable, Codable {
    public let outcome: ForensicWatermarkDetectionOutcome
    public let clipDurationSeconds: Double
    public let analyzedFrameCount: Int
    public let estimatedFrameRate: Double
    public let bestCandidate: ForensicWatermarkCandidateScore?
    public let allCandidateScores: [ForensicWatermarkCandidateScore]
    public let nullStatistics: ForensicWatermarkNullStatistics

    public init(
        outcome: ForensicWatermarkDetectionOutcome,
        clipDurationSeconds: Double,
        analyzedFrameCount: Int,
        estimatedFrameRate: Double,
        bestCandidate: ForensicWatermarkCandidateScore?,
        allCandidateScores: [ForensicWatermarkCandidateScore],
        nullStatistics: ForensicWatermarkNullStatistics
    ) {
        self.outcome = outcome
        self.clipDurationSeconds = clipDurationSeconds
        self.analyzedFrameCount = analyzedFrameCount
        self.estimatedFrameRate = estimatedFrameRate
        self.bestCandidate = bestCandidate
        self.allCandidateScores = allCandidateScores
        self.nullStatistics = nullStatistics
    }
}

/// Pre-extracted per-frame coarse spatial measurements used by the detector core and synthetic unit tests.
public struct ForensicFrameSample: Sendable, Equatable {
    public let timestampSeconds: Double
    /// Coarse grid cell averages (`gridColumns * gridRows`) of the target channel.
    public let cellValues: [Float]
    /// Whole-frame mean of the target channel.
    public let globalMean: Float

    public init(timestampSeconds: Double, cellValues: [Float], globalMean: Float) {
        self.timestampSeconds = timestampSeconds
        self.cellValues = cellValues
        self.globalMean = globalMean
    }
}

// MARK: - Reference Offline Detector

/// Blind offline detector for player-only forensic watermarks in captured or recompressed video clips.
///
/// Requires no clip metadata, screen calibration, or playback timestamps:
/// - Extracts coarse spatial grid time series using actual frame presentation timestamps (VFR-safe).
/// - Resamples onto a period-aligned uniform grid (with bin averaging when input FPS exceeds the grid rate)
///   so multi-period folding accumulates zero cumulative phase drift on long clips.
/// - Subtracts per-frame spatial mean to cancel camera auto-exposure, auto-white-balance, and room flicker,
///   while retaining the global mean channel to survive extreme single-lobe crops.
/// - Applies reflective-padded zero-phase bandpass filtering around `chipRateHz` and robust MAD soft-clipping.
/// - Uses FFT-accelerated circular matched filtering across all temporal lags and calibrates every clip
///   empirically against domain-separated decoy sequences with candidate-count multiple-testing adjustment
///   so unmarked and out-of-set clips return `.inconclusive`.
public struct ForensicWatermarkDetector: Sendable {
    public let configuration: ForensicWatermarkConfiguration
    public let options: ForensicWatermarkDetectionOptions

    public init(
        configuration: ForensicWatermarkConfiguration = .default,
        options: ForensicWatermarkDetectionOptions = .default
    ) {
        self.configuration = configuration
        self.options = options
    }

    /// Analyzes a video file on disk against `candidateSessionIDs`.
    public func detect(
        videoURL: URL,
        candidateSessionIDs: [String]
    ) async throws -> ForensicWatermarkDetectionResult {
        try configuration.validate()
        try options.validate(for: configuration)
        let frames = try await extractFrameSamples(from: videoURL)
        return try detect(frames: frames, candidateSessionIDs: candidateSessionIDs)
    }

    /// Extracts coarse spatial grid samples directly from a video file via `AVAssetReader`.
    public func extractFrameSamples(from videoURL: URL) async throws -> [ForensicFrameSample] {
        try configuration.validate()
        try options.validate(for: configuration)

        let asset = AVURLAsset(url: videoURL)
        let videoTracks: [AVAssetTrack]
        do {
            videoTracks = try await asset.loadTracks(withMediaType: .video)
        } catch {
            throw ForensicWatermarkError.unreadableVideo(error.localizedDescription)
        }
        guard let track = videoTracks.first else {
            throw ForensicWatermarkError.videoTrackMissing
        }

        let reader: AVAssetReader
        do {
            reader = try AVAssetReader(asset: asset)
        } catch {
            throw ForensicWatermarkError.readerFailed(error.localizedDescription)
        }

        let outputSettings: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
        ]
        let trackOutput = AVAssetReaderTrackOutput(track: track, outputSettings: outputSettings)
        trackOutput.alwaysCopiesSampleData = false
        guard reader.canAdd(trackOutput) else {
            throw ForensicWatermarkError.readerFailed("Unable to attach video track output")
        }
        reader.add(trackOutput)
        guard reader.startReading() else {
            throw ForensicWatermarkError.readerFailed(reader.error?.localizedDescription ?? "startReading failed")
        }

        var samples: [ForensicFrameSample] = []
        samples.reserveCapacity(600)
        var firstTimestamp: Double?

        do {
            while let sampleBuffer = trackOutput.copyNextSampleBuffer() {
                try Task.checkCancellation()
                let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
                guard pts.isValid, pts.isNumeric else { continue }
                let seconds = pts.seconds
                guard seconds.isFinite else { continue }
                if firstTimestamp == nil {
                    firstTimestamp = seconds
                }
                let relativeSeconds = seconds - (firstTimestamp ?? seconds)
                if relativeSeconds > options.maxClipDurationSeconds {
                    reader.cancelReading()
                    break
                }
                guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { continue }
                let sample = Self.sampleGrid(
                    fromBGRA: pixelBuffer,
                    timestampSeconds: relativeSeconds,
                    columns: options.gridColumns,
                    rows: options.gridRows,
                    chromaMode: configuration.chromaMode
                )
                samples.append(sample)
            }
        } catch {
            reader.cancelReading()
            throw error
        }

        if reader.status == .failed {
            throw ForensicWatermarkError.readerFailed(reader.error?.localizedDescription ?? "Unknown reader failure")
        }
        return samples
    }

    /// Runs the detector core on pre-extracted frame samples.
    public func detect(
        frames: [ForensicFrameSample],
        candidateSessionIDs: [String]
    ) throws -> ForensicWatermarkDetectionResult {
        try configuration.validate()
        try options.validate(for: configuration)

        let uniqueCandidates = try validatedUniqueCandidates(candidateSessionIDs)
        let effectiveThreshold = options.effectiveMinZScore(candidateCount: uniqueCandidates.count)
        let emptyNull = ForensicWatermarkNullStatistics(
            decoyCount: options.decoyCount,
            mean: 0,
            standardDeviation: 0,
            maxDecoyScore: 0,
            maxDecoyZScore: 0,
            effectiveZScoreThreshold: effectiveThreshold
        )

        // Validate finite timestamps and enforce maxClipDurationSeconds to bound allocation and runtime.
        let validFrames = try validateAndBoundFrames(frames)
        let frameCount = validFrames.count

        let durationSeconds: Double
        let estimatedFPS: Double
        if frameCount >= 2 {
            let span = validFrames[frameCount - 1].timestampSeconds - validFrames[0].timestampSeconds
            let avgStep = span / Double(frameCount - 1)
            durationSeconds = max(0, span + max(0, avgStep))
            estimatedFPS = avgStep > 1e-6 ? 1.0 / avgStep : 0
        } else {
            durationSeconds = 0
            estimatedFPS = 0
        }

        guard !uniqueCandidates.isEmpty else {
            return ForensicWatermarkDetectionResult(
                outcome: .inconclusive(reason: .noCandidates),
                clipDurationSeconds: durationSeconds,
                analyzedFrameCount: frameCount,
                estimatedFrameRate: estimatedFPS,
                bestCandidate: nil,
                allCandidateScores: [],
                nullStatistics: emptyNull
            )
        }

        guard frameCount >= 16, durationSeconds >= options.minDurationSeconds else {
            return ForensicWatermarkDetectionResult(
                outcome: .inconclusive(reason: .clipTooShort),
                clipDurationSeconds: durationSeconds,
                analyzedFrameCount: frameCount,
                estimatedFrameRate: estimatedFPS,
                bestCandidate: nil,
                allCandidateScores: [],
                nullStatistics: emptyNull
            )
        }

        // Exact period-aligned sample rate eliminates cumulative phase drift when folding long clips.
        let periodSamples = max(
            16,
            Int((configuration.periodSeconds * options.sampleRateHz).rounded())
        )
        let alignedSampleRateHz = Double(periodSamples) / configuration.periodSeconds
        let cellCount = validFrames[0].cellValues.count

        let prepared = prepareFoldedChannels(
            frames: validFrames,
            cellCount: cellCount,
            periodSamples: periodSamples,
            alignedSampleRateHz: alignedSampleRateHz
        )

        let useSpatialChannels = configuration.spatialPattern != .uniform && !prepared.spatialFolded.isEmpty
        let useGlobalChannel = prepared.globalFolded != nil
        guard useSpatialChannels || useGlobalChannel else {
            return ForensicWatermarkDetectionResult(
                outcome: .inconclusive(reason: .insufficientSignalVariance),
                clipDurationSeconds: durationSeconds,
                analyzedFrameCount: frameCount,
                estimatedFrameRate: estimatedFPS,
                bestCandidate: nil,
                allCandidateScores: [],
                nullStatistics: emptyNull
            )
        }

        let correlator = CircularFFTCorrelator(periodSamples: periodSamples)
        let spatialSpectra = useSpatialChannels ? prepared.spatialFolded.map { correlator.forwardSignal($0) } : []
        let globalSpectrum = prepared.globalFolded.map { correlator.forwardSignal($0) }

        let decoyMetrics = evaluateDecoys(
            correlator: correlator,
            alignedSampleRateHz: alignedSampleRateHz,
            spatialSpectra: spatialSpectra,
            globalSpectrum: globalSpectrum
        )
        let candidateMetrics = uniqueCandidates.map { sessionID -> CandidateChannelMetric in
            let chips = ForensicWatermarkSignal.chips(for: sessionID, configuration: configuration)
            let template = ForensicWatermarkSignal.referenceWaveform(
                chips: chips,
                chipRateHz: configuration.chipRateHz,
                sampleRateHz: alignedSampleRateHz
            )
            return evaluateTemplate(
                id: sessionID,
                template: template,
                correlator: correlator,
                spatialSpectra: spatialSpectra,
                globalSpectrum: globalSpectrum
            )
        }

        return finalizeDecision(
            candidateMetrics: candidateMetrics,
            decoyMetrics: decoyMetrics,
            periodSamples: periodSamples,
            alignedSampleRateHz: alignedSampleRateHz,
            durationSeconds: durationSeconds,
            frameCount: frameCount,
            estimatedFPS: estimatedFPS
        )
    }

    // MARK: - Frame Validation & Grid Sampling

    private func validateAndBoundFrames(_ frames: [ForensicFrameSample]) throws -> [ForensicFrameSample] {
        guard !frames.isEmpty else { return [] }
        for frame in frames {
            guard frame.timestampSeconds.isFinite, frame.globalMean.isFinite else {
                throw ForensicWatermarkError.invalidFrameData("Frame contains non-finite timestamp or globalMean")
            }
            for v in frame.cellValues where !v.isFinite {
                throw ForensicWatermarkError.invalidFrameData("Frame contains non-finite cell value")
            }
        }
        let sorted = frames.sorted { $0.timestampSeconds < $1.timestampSeconds }
        let t0 = sorted[0].timestampSeconds
        return sorted.filter { ($0.timestampSeconds - t0) <= options.maxClipDurationSeconds }
    }

    private static func sampleGrid(
        fromBGRA pixelBuffer: CVPixelBuffer,
        timestampSeconds: Double,
        columns: Int,
        rows: Int,
        chromaMode: WatermarkChromaMode
    ) -> ForensicFrameSample {
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)
        let cellCount = columns * rows
        guard width > 0, height > 0 else {
            return ForensicFrameSample(
                timestampSeconds: timestampSeconds,
                cellValues: [Float](repeating: 0, count: cellCount),
                globalMean: 0
            )
        }

        CVPixelBufferLockBaseAddress(pixelBuffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, .readOnly) }
        guard let baseAddress = CVPixelBufferGetBaseAddress(pixelBuffer) else {
            return ForensicFrameSample(
                timestampSeconds: timestampSeconds,
                cellValues: [Float](repeating: 0, count: cellCount),
                globalMean: 0
            )
        }

        let bytesPerRow = CVPixelBufferGetBytesPerRow(pixelBuffer)
        let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)

        // Stride sampling keeps 1080p/4K decoding fast while still averaging thousands of pixels per cell.
        let stepX = max(1, width / 192)
        let stepY = max(1, height / 144)

        var cellSums = [Double](repeating: 0, count: cellCount)
        var cellCounts = [Int](repeating: 0, count: cellCount)
        var globalSum: Double = 0
        var globalCount = 0

        let isLuminance = (chromaMode == .luminance)
        let inv255 = 1.0 / 255.0

        var y = 0
        while y < height {
            let rowIdx = min(rows - 1, (y * rows) / height)
            let rowPtr = ptr.advanced(by: y * bytesPerRow)
            var x = 0
            while x < width {
                let colIdx = min(columns - 1, (x * columns) / width)
                let offset = x * 4
                let b = Double(rowPtr[offset]) * inv255
                let g = Double(rowPtr[offset + 1]) * inv255
                let r = Double(rowPtr[offset + 2]) * inv255

                let yLuma = 0.2126 * r + 0.7152 * g + 0.0722 * b
                let channelValue = isLuminance ? yLuma : (b - yLuma)

                let cellIdx = rowIdx * columns + colIdx
                cellSums[cellIdx] += channelValue
                cellCounts[cellIdx] += 1
                globalSum += channelValue
                globalCount += 1

                x += stepX
            }
            y += stepY
        }

        var cellValues = [Float](repeating: 0, count: cellCount)
        for i in 0 ..< cellCount where cellCounts[i] > 0 {
            cellValues[i] = Float(cellSums[i] / Double(cellCounts[i]))
        }
        let globalMean = globalCount > 0 ? Float(globalSum / Double(globalCount)) : 0
        return ForensicFrameSample(
            timestampSeconds: timestampSeconds,
            cellValues: cellValues,
            globalMean: globalMean
        )
    }

    // MARK: - Preprocessing (Resampling, Spatial Mean Subtraction, Bandpass, Robust Clipping, Folding)

    private struct PreparedChannels {
        let spatialFolded: [[Float]]
        let globalFolded: [Float]?
    }

    private func prepareFoldedChannels(
        frames: [ForensicFrameSample],
        cellCount: Int,
        periodSamples: Int,
        alignedSampleRateHz: Double
    ) -> PreparedChannels {
        let t0 = frames[0].timestampSeconds
        let tEnd = frames[frames.count - 1].timestampSeconds
        let boundedSpan = min(options.maxClipDurationSeconds, max(0, tEnd - t0))
        let uniformCount = max(2, Int(floor(boundedSpan * alignedSampleRateHz)) + 1)

        let timestamps = frames.map { $0.timestampSeconds - t0 }
        let globalSeries = frames.map(\.globalMean)
        let resampledGlobal = Self.resampleUniform(
            timestamps: timestamps,
            values: globalSeries,
            sampleRateHz: alignedSampleRateHz,
            outputCount: uniformCount
        )

        let biquad = BiquadBandpass(
            sampleRateHz: alignedSampleRateHz,
            centerFrequencyHz: configuration.chipRateHz,
            qualityFactor: 0.85
        )

        let globalFolded = preprocessAndFold(
            resampledGlobal,
            biquad: biquad,
            periodSamples: periodSamples
        )

        var spatialFolded: [[Float]] = []
        if cellCount > 0 {
            spatialFolded.reserveCapacity(cellCount)
            for cellIndex in 0 ..< cellCount {
                var diffSeries = [Float](repeating: 0, count: frames.count)
                for frameIdx in 0 ..< frames.count {
                    let frame = frames[frameIdx]
                    let cellVal = cellIndex < frame.cellValues.count ? frame.cellValues[cellIndex] : frame.globalMean
                    diffSeries[frameIdx] = cellVal - frame.globalMean
                }
                let resampled = Self.resampleUniform(
                    timestamps: timestamps,
                    values: diffSeries,
                    sampleRateHz: alignedSampleRateHz,
                    outputCount: uniformCount
                )
                if let folded = preprocessAndFold(resampled, biquad: biquad, periodSamples: periodSamples) {
                    spatialFolded.append(folded)
                }
            }
        }

        return PreparedChannels(spatialFolded: spatialFolded, globalFolded: globalFolded)
    }

    private func preprocessAndFold(
        _ series: [Float],
        biquad: BiquadBandpass,
        periodSamples: Int
    ) -> [Float]? {
        guard series.count >= 8 else { return nil }

        // Remove DC before filtering to avoid startup transient from non-zero color offsets.
        var mean: Float = 0
        vDSP_meanv(series, 1, &mean, vDSP_Length(series.count))
        var centered = [Float](repeating: 0, count: series.count)
        var negMean = -mean
        vDSP_vsadd(series, 1, &negMean, &centered, 1, vDSP_Length(series.count))

        // Reflective-padded zero-phase bandpass around chipRateHz.
        var filtered = biquad.zeroPhaseFilter(centered)

        // Robust MAD soft-clipping suppresses sudden scene cuts and handheld bumps.
        Self.robustSoftClip(&filtered)

        // Normalize to zero-mean, unit-RMS; reject static / dead cells.
        var postMean: Float = 0
        vDSP_meanv(filtered, 1, &postMean, vDSP_Length(filtered.count))
        var negPostMean = -postMean
        vDSP_vsadd(filtered, 1, &negPostMean, &filtered, 1, vDSP_Length(filtered.count))

        var rms: Float = 0
        vDSP_rmsqv(filtered, 1, &rms, vDSP_Length(filtered.count))
        guard rms.isFinite, rms > 1e-6 else { return nil }

        var invRMS = 1.0 / rms
        vDSP_vsmul(filtered, 1, &invRMS, &filtered, 1, vDSP_Length(filtered.count))

        // Coherently fold modulo exact periodSamples so clips longer than one period gain SNR with zero drift.
        var folded = [Float](repeating: 0, count: periodSamples)
        for idx in 0 ..< filtered.count {
            folded[idx % periodSamples] += filtered[idx]
        }

        var foldedRMS: Float = 0
        vDSP_rmsqv(folded, 1, &foldedRMS, vDSP_Length(periodSamples))
        guard foldedRMS.isFinite, foldedRMS > 1e-6 else { return nil }

        var invFoldedRMS = 1.0 / foldedRMS
        vDSP_vsmul(folded, 1, &invFoldedRMS, &folded, 1, vDSP_Length(periodSamples))
        return folded
    }

    /// Resamples irregular timestamps onto a uniform grid.
    ///
    /// When the source frame rate exceeds `sampleRateHz` (e.g., 60 fps or 120 fps captures),
    /// averages all frames falling inside each `[t - dt/2, t + dt/2]` bin as an anti-alias filter;
    /// otherwise linearly interpolates between neighboring frames.
    private static func resampleUniform(
        timestamps: [Double],
        values: [Float],
        sampleRateHz: Double,
        outputCount: Int
    ) -> [Float] {
        guard !timestamps.isEmpty, timestamps.count == values.count else { return [] }
        var output = [Float](repeating: 0, count: outputCount)
        let lastIdx = timestamps.count - 1
        let dt = 1.0 / sampleRateHz
        let halfDt = 0.5 * dt

        var binCursor = 0
        var interpCursor = 0

        for i in 0 ..< outputCount {
            let t = Double(i) * dt
            let winStart = t - halfDt
            let winEnd = t + halfDt

            while binCursor < lastIdx, timestamps[binCursor] < winStart {
                binCursor += 1
            }

            // Box-average if 2+ source frames fall inside this output bin (anti-aliasing for 60/120 fps).
            var sum: Double = 0
            var count = 0
            var scan = binCursor
            while scan <= lastIdx, timestamps[scan] <= winEnd {
                if timestamps[scan] >= winStart {
                    sum += Double(values[scan])
                    count += 1
                }
                scan += 1
            }
            if count >= 2 {
                output[i] = Float(sum / Double(count))
                continue
            }

            while interpCursor < lastIdx - 1, timestamps[interpCursor + 1] < t {
                interpCursor += 1
            }
            if t <= timestamps[0] {
                output[i] = values[0]
            } else if t >= timestamps[lastIdx] {
                output[i] = values[lastIdx]
            } else {
                let t0 = timestamps[interpCursor]
                let t1 = timestamps[interpCursor + 1]
                let span = t1 - t0
                if span > 1e-9 {
                    let frac = Float((t - t0) / span)
                    output[i] = values[interpCursor] * (1.0 - frac) + values[interpCursor + 1] * frac
                } else {
                    output[i] = values[interpCursor]
                }
            }
        }
        return output
    }

    private static func robustSoftClip(_ values: inout [Float]) {
        guard values.count >= 4 else { return }
        let sorted = values.sorted()
        let median = sorted[sorted.count / 2]
        let absDevs = sorted.map { abs($0 - median) }.sorted()
        let mad = absDevs[absDevs.count / 2]
        let robustSigma = 1.4826 * mad
        guard robustSigma > 1e-7 else { return }
        let limit = 3.0 * robustSigma
        let invLimit = 1.0 / limit
        for i in 0 ..< values.count {
            let centered = values[i] - median
            values[i] = median + limit * tanh(centered * invLimit)
        }
    }

    // MARK: - Matched Filter & Empirical Decoy Calibration

    private struct CandidateChannelMetric {
        let id: String
        let spatialPeak: Double?
        let spatialBestLag: Int
        let globalPeak: Double?
        let globalBestLag: Int
    }

    private func evaluateDecoys(
        correlator: CircularFFTCorrelator,
        alignedSampleRateHz: Double,
        spatialSpectra: [CircularFFTCorrelator.Spectrum],
        globalSpectrum: CircularFFTCorrelator.Spectrum?
    ) -> [CandidateChannelMetric] {
        (0 ..< options.decoyCount).map { index in
            let chips = ForensicWatermarkSignal.decoyChips(index: index, configuration: configuration)
            let template = ForensicWatermarkSignal.referenceWaveform(
                chips: chips,
                chipRateHz: configuration.chipRateHz,
                sampleRateHz: alignedSampleRateHz
            )
            return evaluateTemplate(
                id: "decoy-\(index)",
                template: template,
                correlator: correlator,
                spatialSpectra: spatialSpectra,
                globalSpectrum: globalSpectrum
            )
        }
    }

    private func evaluateTemplate(
        id: String,
        template: [Float],
        correlator: CircularFFTCorrelator,
        spatialSpectra: [CircularFFTCorrelator.Spectrum],
        globalSpectrum: CircularFFTCorrelator.Spectrum?
    ) -> CandidateChannelMetric {
        let templateSpectrum = correlator.forwardTemplate(template)
        let n = correlator.periodSamples

        var spatialPeak: Double?
        var spatialLag = 0
        if !spatialSpectra.isEmpty {
            var combined = [Double](repeating: 0, count: n)
            for spectrum in spatialSpectra {
                let corr = correlator.correlate(signalSpectrum: spectrum, templateSpectrum: templateSpectrum)
                let sidelobeScale = Self.robustSidelobeScale(corr)
                guard sidelobeScale.isFinite, sidelobeScale > 1e-9 else { continue }
                let invScale = 1.0 / sidelobeScale
                for lag in 0 ..< n {
                    let u = Double(corr[lag]) * invScale
                    let excess = u * u - 1.0
                    if excess > 0 {
                        combined[lag] += excess
                    }
                }
            }
            let scale = 1.0 / Double(spatialSpectra.count)
            var bestVal = -Double.infinity
            var bestIdx = 0
            for lag in 0 ..< n {
                let val = combined[lag] * scale
                if val > bestVal {
                    bestVal = val
                    bestIdx = lag
                }
            }
            spatialPeak = bestVal.isFinite ? bestVal : 0
            spatialLag = bestIdx
        }

        var globalPeak: Double?
        var globalLag = 0
        if let globalSpectrum {
            let corr = correlator.correlate(signalSpectrum: globalSpectrum, templateSpectrum: templateSpectrum)
            let sidelobeScale = Self.robustSidelobeScale(corr)
            if sidelobeScale.isFinite, sidelobeScale > 1e-9 {
                let invScale = 1.0 / sidelobeScale
                var bestVal = -Double.infinity
                var bestIdx = 0
                for lag in 0 ..< n {
                    let u = Double(corr[lag]) * invScale
                    let val = u * u
                    if val > bestVal {
                        bestVal = val
                        bestIdx = lag
                    }
                }
                globalPeak = bestVal.isFinite ? bestVal : 0
                globalLag = bestIdx
            }
        }

        return CandidateChannelMetric(
            id: id,
            spatialPeak: spatialPeak,
            spatialBestLag: spatialLag,
            globalPeak: globalPeak,
            globalBestLag: globalLag
        )
    }

    private func finalizeDecision(
        candidateMetrics: [CandidateChannelMetric],
        decoyMetrics: [CandidateChannelMetric],
        periodSamples: Int,
        alignedSampleRateHz: Double,
        durationSeconds: Double,
        frameCount: Int,
        estimatedFPS: Double
    ) -> ForensicWatermarkDetectionResult {
        let spatialDecoys = decoyMetrics.compactMap(\.spatialPeak)
        let globalDecoys = decoyMetrics.compactMap(\.globalPeak)
        let spatialNull = Self.meanAndStd(spatialDecoys)
        let globalNull = Self.meanAndStd(globalDecoys)

        func combinedMetric(for metric: CandidateChannelMetric) -> (score: Double, lag: Int) {
            var bestScore = -Double.infinity
            var bestLag = 0
            if let sp = metric.spatialPeak, !spatialDecoys.isEmpty {
                let zSp = (sp - spatialNull.mean) / max(spatialNull.std, 1e-6)
                if zSp > bestScore {
                    bestScore = zSp
                    bestLag = metric.spatialBestLag
                }
            }
            if let gl = metric.globalPeak, !globalDecoys.isEmpty {
                let zGl = (gl - globalNull.mean) / max(globalNull.std, 1e-6)
                if zGl > bestScore {
                    bestScore = zGl
                    bestLag = metric.globalBestLag
                }
            }
            if !bestScore.isFinite {
                return (0, 0)
            }
            return (bestScore, bestLag)
        }

        // Calibrate the combined (max-of-channels) statistic against the decoys' exact combined distribution
        // so taking max(spatial, global) introduces zero multiple-testing inflation.
        let decoyCombinedScores = decoyMetrics.map { combinedMetric(for: $0).score }
        let combinedNull = Self.meanAndStd(decoyCombinedScores)
        let maxDecoyScore = decoyCombinedScores.max() ?? 0
        let maxDecoyZ = (maxDecoyScore - combinedNull.mean) / max(combinedNull.std, 1e-6)
        let effectiveThreshold = options.effectiveMinZScore(candidateCount: candidateMetrics.count)

        let nullStats = ForensicWatermarkNullStatistics(
            decoyCount: decoyMetrics.count,
            mean: combinedNull.mean,
            standardDeviation: combinedNull.std,
            maxDecoyScore: maxDecoyScore,
            maxDecoyZScore: maxDecoyZ,
            effectiveZScoreThreshold: effectiveThreshold
        )

        struct ScoredItem {
            let id: String
            let channelScore: Double
            let z: Double
            let lag: Int
        }

        let scored: [ScoredItem] = candidateMetrics.map { metric in
            let combined = combinedMetric(for: metric)
            let z = (combined.score - combinedNull.mean) / max(combinedNull.std, 1e-6)
            return ScoredItem(id: metric.id, channelScore: combined.score, z: z, lag: combined.lag)
        }.sorted { $0.z > $1.z }

        let runnerUpZ: Double = if scored.count >= 2 {
            max(scored[1].z, maxDecoyZ)
        } else {
            maxDecoyZ
        }

        let finalScores: [ForensicWatermarkCandidateScore] = scored.enumerated().map { idx, item in
            let phaseSamples = (periodSamples - (item.lag % periodSamples)) % periodSamples
            let phaseSeconds = Double(phaseSamples) / alignedSampleRateHz
            let margin = (idx == 0) ? (item.z - runnerUpZ) : (item.z - scored[0].z)
            return ForensicWatermarkCandidateScore(
                sessionID: item.id,
                combinedChannelScore: item.channelScore,
                zScore: item.z,
                estimatedPhaseOffsetSeconds: phaseSeconds,
                marginOverRunnerUp: margin
            )
        }

        guard let top = finalScores.first else {
            return ForensicWatermarkDetectionResult(
                outcome: .inconclusive(reason: .noCandidates),
                clipDurationSeconds: durationSeconds,
                analyzedFrameCount: frameCount,
                estimatedFrameRate: estimatedFPS,
                bestCandidate: nil,
                allCandidateScores: [],
                nullStatistics: nullStats
            )
        }

        let passesThreshold = top.zScore >= effectiveThreshold && top.zScore > maxDecoyZ
        let passesMargin = top.marginOverRunnerUp >= options.minMarginOverRunnerUp

        let outcome: ForensicWatermarkDetectionOutcome
        if !passesThreshold {
            outcome = .inconclusive(reason: .belowDetectionThreshold)
        } else if !passesMargin {
            outcome = .inconclusive(reason: .ambiguousMargin)
        } else {
            outcome = .detected(sessionID: top.sessionID)
        }

        return ForensicWatermarkDetectionResult(
            outcome: outcome,
            clipDurationSeconds: durationSeconds,
            analyzedFrameCount: frameCount,
            estimatedFrameRate: estimatedFPS,
            bestCandidate: top,
            allCandidateScores: finalScores,
            nullStatistics: nullStats
        )
    }

    private func validatedUniqueCandidates(_ candidates: [String]) throws -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        result.reserveCapacity(candidates.count)
        for rawID in candidates {
            let validated = try WatermarkSessionCode(rawID)
            if seen.insert(validated.rawValue).inserted {
                result.append(validated.rawValue)
            }
        }
        return result
    }

    /// Estimates correlation sidelobe scale via MAD (`1.4826 * median(|corr|)`) so a strong true peak
    /// on short code periods does not inflate its own denominator (Peak-to-Sidelobe Ratio normalization).
    private static func robustSidelobeScale(_ corr: [Float]) -> Double {
        guard !corr.isEmpty else { return 0 }
        let absVals = corr.map { abs($0) }.sorted()
        let mad = Double(absVals[absVals.count / 2])
        let scale = 1.4826 * mad
        if scale > 1e-9 {
            return scale
        }
        var rms: Float = 0
        vDSP_rmsqv(corr, 1, &rms, vDSP_Length(corr.count))
        return Double(rms)
    }

    private static func meanAndStd(_ values: [Double]) -> (mean: Double, std: Double) {
        guard !values.isEmpty else { return (0, 0) }
        let count = Double(values.count)
        let mean = values.reduce(0, +) / count
        let variance = values.reduce(0) { acc, v in
            let d = v - mean
            return acc + d * d
        } / max(1.0, count - 1.0)
        return (mean, sqrt(max(0, variance)))
    }
}

// MARK: - Zero-Phase Biquad Bandpass Filter (Reflective Edge Padding)

private struct BiquadBandpass {
    let b0: Float
    let b1: Float
    let b2: Float
    let a1: Float
    let a2: Float
    let padLength: Int

    init(sampleRateHz: Double, centerFrequencyHz: Double, qualityFactor: Double) {
        let omega = 2.0 * Double.pi * centerFrequencyHz / sampleRateHz
        let sinW = sin(omega)
        let cosW = cos(omega)
        let alpha = sinW / (2.0 * qualityFactor)
        let a0 = 1.0 + alpha

        self.b0 = Float(alpha / a0)
        self.b1 = 0.0
        self.b2 = Float(-alpha / a0)
        self.a1 = Float((-2.0 * cosW) / a0)
        self.a2 = Float((1.0 - alpha) / a0)
        self.padLength = max(4, Int((sampleRateHz / max(0.5, centerFrequencyHz)).rounded()) * 2)
    }

    func zeroPhaseFilter(_ input: [Float]) -> [Float] {
        let n = input.count
        guard n >= 4 else { return input }

        let pad = min(padLength, n - 1)
        var padded = [Float](repeating: 0, count: n + 2 * pad)
        let first = input[0]
        let last = input[n - 1]
        for i in 0 ..< pad {
            padded[pad - 1 - i] = 2 * first - input[i + 1]
        }
        for i in 0 ..< n {
            padded[pad + i] = input[i]
        }
        for i in 0 ..< pad {
            padded[pad + n + i] = 2 * last - input[n - 2 - i]
        }

        let forward = filterOnce(padded)
        let reversedForward = Array(forward.reversed())
        let backward = filterOnce(reversedForward)
        let unreversed = Array(backward.reversed())
        return Array(unreversed[pad ..< (pad + n)])
    }

    private func filterOnce(_ input: [Float]) -> [Float] {
        var output = [Float](repeating: 0, count: input.count)
        var x1: Float = 0
        var x2: Float = 0
        var y1: Float = 0
        var y2: Float = 0
        for i in 0 ..< input.count {
            let x0 = input[i]
            let y0 = b0 * x0 + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2
            output[i] = y0
            x2 = x1
            x1 = x0
            y2 = y1
            y1 = y0
        }
        return output
    }
}

// MARK: - Radix-2 Complex FFT Circular Correlator

private final class CircularFFTCorrelator {
    struct Spectrum {
        let real: [Float]
        let imag: [Float]
    }

    let periodSamples: Int
    private let fftLength: Int
    private let log2n: vDSP_Length
    private let fftSetup: FFTSetup

    init(periodSamples: Int) {
        self.periodSamples = periodSamples
        var length = 1
        var log2Val: vDSP_Length = 0
        let target = max(2, periodSamples * 2)
        while length < target {
            length <<= 1
            log2Val += 1
        }
        self.fftLength = length
        self.log2n = log2Val
        guard let setup = vDSP_create_fftsetup(log2Val, FFTRadix(kFFTRadix2)) else {
            preconditionFailure("Failed to allocate vDSP FFT setup for log2n=\(log2Val)")
        }
        self.fftSetup = setup
    }

    deinit {
        vDSP_destroy_fftsetup(fftSetup)
    }

    /// Computes FFT of `[signal, signal]` zero-padded to `fftLength` for exact arbitrary-N circular correlation.
    func forwardSignal(_ foldedSignal: [Float]) -> Spectrum {
        var real = [Float](repeating: 0, count: fftLength)
        let imag = [Float](repeating: 0, count: fftLength)
        let n = min(periodSamples, foldedSignal.count)
        for i in 0 ..< n {
            real[i] = foldedSignal[i]
            real[i + periodSamples] = foldedSignal[i]
        }
        return transform(real: real, imag: imag, direction: FFTDirection(kFFTDirection_Forward))
    }

    /// Computes FFT of `template` zero-padded to `fftLength`.
    func forwardTemplate(_ template: [Float]) -> Spectrum {
        var real = [Float](repeating: 0, count: fftLength)
        let imag = [Float](repeating: 0, count: fftLength)
        let n = min(periodSamples, template.count)
        for i in 0 ..< n {
            real[i] = template[i]
        }
        return transform(real: real, imag: imag, direction: FFTDirection(kFFTDirection_Forward))
    }

    /// Returns exact circular cross-correlation `r[tau] = sum_n signal[(n + tau) % N] * template[n]` for `0..<N`.
    func correlate(signalSpectrum: Spectrum, templateSpectrum: Spectrum) -> [Float] {
        var prodReal = [Float](repeating: 0, count: fftLength)
        var prodImag = [Float](repeating: 0, count: fftLength)

        for k in 0 ..< fftLength {
            let sr = signalSpectrum.real[k]
            let si = signalSpectrum.imag[k]
            let tr = templateSpectrum.real[k]
            let ti = templateSpectrum.imag[k]
            // S * conj(T)
            prodReal[k] = sr * tr + si * ti
            prodImag[k] = si * tr - sr * ti
        }

        let inv = transform(real: prodReal, imag: prodImag, direction: FFTDirection(kFFTDirection_Inverse))
        let scale = 1.0 / Float(fftLength)
        var result = [Float](repeating: 0, count: periodSamples)
        for i in 0 ..< periodSamples {
            result[i] = inv.real[i] * scale
        }
        return result
    }

    private func transform(real: [Float], imag: [Float], direction: FFTDirection) -> Spectrum {
        var re = real
        var im = imag
        re.withUnsafeMutableBufferPointer { reBuf in
            im.withUnsafeMutableBufferPointer { imBuf in
                guard let reBase = reBuf.baseAddress, let imBase = imBuf.baseAddress else { return }
                var split = DSPSplitComplex(realp: reBase, imagp: imBase)
                vDSP_fft_zip(fftSetup, &split, 1, log2n, direction)
            }
        }
        return Spectrum(real: re, imag: im)
    }
}
