import ArgumentParser
import ArkavoMediaKit
import CoreGraphics
import Foundation

@main
struct ForensicWatermarkCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "forensic-watermark",
        abstract: "Offline forensic watermark detector, metadata stripper, and blinded evaluation harness.",
        subcommands: [
            DetectCommand.self,
            EvaluateCommand.self,
            StripMetadataCommand.self,
            SimulateCommand.self,
        ]
    )
}

// MARK: - Shared CLI Options

struct WatermarkSignalOptions: ParsableArguments {
    @Option(name: .long, help: "Chip rate in Hz (default: 4.0)")
    var chipRateHz: Double = 4.0

    @Option(name: .long, help: "Period length in chips (default: 64)")
    var periodChips: Int = 64

    @Option(name: .long, help: "Overlay opacity used during playback (default: 0.025)")
    var opacity: Double = 0.025

    @Option(name: .long, help: "Chroma mode: isoluminantBlueYellow, blueChannel, or luminance")
    var chromaMode: String = WatermarkChromaMode.isoluminantBlueYellow.rawValue

    @Option(name: .long, help: "Spatial pattern: smoothCosine3x2, smoothCosine2x2, or uniform")
    var spatialPattern: String = WatermarkSpatialPattern.smoothCosine3x2.rawValue

    @Option(name: .long, help: "Minimum decoy-calibrated z-score for detection (default: 5.0)")
    var minZScore: Double = 5.0

    @Option(name: .long, help: "Minimum z-score margin over runner-up/max decoy (default: 2.0)")
    var minMargin: Double = 2.0

    @Option(name: .long, help: "Number of domain-separated decoys for null calibration (default: 64)")
    var decoyCount: Int = 64

    func makeConfiguration() throws -> ForensicWatermarkConfiguration {
        guard let mode = WatermarkChromaMode(rawValue: chromaMode) else {
            throw ValidationError("Invalid chromaMode '\(chromaMode)'")
        }
        guard let pattern = WatermarkSpatialPattern(rawValue: spatialPattern) else {
            throw ValidationError("Invalid spatialPattern '\(spatialPattern)'")
        }
        let config = ForensicWatermarkConfiguration(
            chipRateHz: chipRateHz,
            periodChips: periodChips,
            opacity: opacity,
            chromaMode: mode,
            spatialPattern: pattern
        )
        try config.validate()
        return config
    }

    func makeDetectionOptions(for config: ForensicWatermarkConfiguration) throws -> ForensicWatermarkDetectionOptions {
        let options = ForensicWatermarkDetectionOptions(
            decoyCount: decoyCount,
            minZScore: minZScore,
            minMarginOverRunnerUp: minMargin
        )
        try options.validate(for: config)
        return options
    }
}

private func loadCandidateSessionIDs(inline: String?, filePath: String?) throws -> [String] {
    var ids: [String] = []
    if let inline {
        ids.append(contentsOf: inline.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) })
    }
    if let filePath {
        let content = try String(contentsOfFile: filePath, encoding: .utf8)
        ids.append(
            contentsOf: content
                .split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        )
    }
    let filtered = ids.filter { !$0.isEmpty }
    guard !filtered.isEmpty else {
        throw ValidationError("Provide at least one candidate session ID via --candidates or --candidates-file")
    }
    return filtered
}

// MARK: - detect

struct DetectCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "detect",
        abstract: "Run the blinded offline detector on a single video clip."
    )

    @Argument(help: "Path to the video file (.mov or .mp4)")
    var videoPath: String

    @Option(name: .long, help: "Comma-separated opaque candidate session IDs")
    var candidates: String?

    @Option(name: .long, help: "Newline-delimited file of opaque candidate session IDs")
    var candidatesFile: String?

    @Flag(name: .long, help: "Output JSON instead of human-readable text")
    var json: Bool = false

    @OptionGroup var signal: WatermarkSignalOptions

    mutating func run() async throws {
        let config = try signal.makeConfiguration()
        let options = try signal.makeDetectionOptions(for: config)
        let candidateIDs = try loadCandidateSessionIDs(inline: candidates, filePath: candidatesFile)

        let detector = ForensicWatermarkDetector(configuration: config, options: options)
        let result = try await detector.detect(
            videoURL: URL(fileURLWithPath: videoPath),
            candidateSessionIDs: candidateIDs
        )

        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(result)
            print(String(decoding: data, as: UTF8.self))
        } else {
            switch result.outcome {
            case let .detected(sessionID):
                print("Outcome: DETECTED -> \(sessionID)")
            case let .inconclusive(reason):
                print("Outcome: INCONCLUSIVE (\(reason.rawValue))")
            }
            print(
                String(
                    format: "Clip: %.2fs (%d frames, %.1f fps)",
                    result.clipDurationSeconds,
                    result.analyzedFrameCount,
                    result.estimatedFrameRate
                )
            )
            if let best = result.bestCandidate {
                print(
                    String(
                        format: "Top candidate: %@ (z=%.2f, margin=%.2f, raw=%.2f, phase=%.2fs)",
                        best.sessionID,
                        best.zScore,
                        best.marginOverRunnerUp,
                        best.rawScore,
                        best.estimatedPhaseOffsetSeconds
                    )
                )
            }
            print(
                String(
                    format: "Empirical null (%d decoys): mean=%.2f, std=%.2f, max=%.2f",
                    result.nullStatistics.decoyCount,
                    result.nullStatistics.mean,
                    result.nullStatistics.standardDeviation,
                    result.nullStatistics.maxDecoyScore
                )
            )
        }
    }
}

// MARK: - evaluate

struct EvaluateCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "evaluate",
        abstract: "Evaluate a JSON manifest of blinded trials and report correct, missed, wrong IDs, and controls."
    )

    @Option(name: .long, help: "Path to JSON array of ForensicWatermarkTrial entries")
    var manifest: String

    @Option(name: .long, help: "Comma-separated candidate session IDs")
    var candidates: String?

    @Option(name: .long, help: "Newline-delimited file of candidate session IDs")
    var candidatesFile: String?

    @Flag(name: .long, help: "Emit JSON report instead of Markdown")
    var json: Bool = false

    @OptionGroup var signal: WatermarkSignalOptions

    mutating func run() async throws {
        let config = try signal.makeConfiguration()
        let options = try signal.makeDetectionOptions(for: config)
        let candidateIDs = try loadCandidateSessionIDs(inline: candidates, filePath: candidatesFile)

        let manifestData = try Data(contentsOf: URL(fileURLWithPath: manifest))
        let trials = try JSONDecoder().decode([ForensicWatermarkTrial].self, from: manifestData)

        let evaluator = ForensicWatermarkEvaluator(configuration: config, options: options)
        let report = try await evaluator.evaluate(trials: trials, candidateSessionIDs: candidateIDs)

        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(report)
            print(String(decoding: data, as: UTF8.self))
        } else {
            print(report.markdownSummary())
        }
    }
}

// MARK: - strip-metadata

struct StripMetadataCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "strip-metadata",
        abstract: "Produce a blinded, metadata-stripped (and optionally trimmed/cropped/recompressed) copy of a clip."
    )

    @Argument(help: "Input video file path")
    var inputPath: String

    @Argument(help: "Output MP4 file path")
    var outputPath: String

    @Option(name: .long, help: "Optional trim start time in seconds")
    var trimStart: Double?

    @Option(name: .long, help: "Optional trim duration in seconds")
    var trimDuration: Double?

    @Option(name: .long, help: "Optional centered crop inset fraction per side (e.g. 0.15 keeps center 70%)")
    var cropInset: Double?

    @Option(name: .long, help: "Target H.264 bitrate in bps (default: 2500000)")
    var bitrate: Int = 2_500_000

    mutating func run() async throws {
        var cropRect: CGRect?
        if let inset = cropInset {
            guard inset >= 0, inset < 0.45 else {
                throw ValidationError("cropInset must be in [0, 0.45)")
            }
            cropRect = CGRect(x: inset, y: inset, width: 1.0 - 2.0 * inset, height: 1.0 - 2.0 * inset)
        }
        try await ForensicWatermarkMediaUtilities.stripMetadata(
            from: URL(fileURLWithPath: inputPath),
            to: URL(fileURLWithPath: outputPath),
            trimStartSeconds: trimStart,
            trimDurationSeconds: trimDuration,
            cropRectNormalized: cropRect,
            averageBitRate: bitrate
        )
        print("Wrote metadata-stripped clip to \(outputPath)")
    }
}

// MARK: - simulate

struct SimulateCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "simulate",
        abstract: "Generate a synthetic blinded experiment matrix (original, trimmed, cropped, recompressed, controls) and evaluate it."
    )

    @Option(name: .long, help: "Working directory for generated clips (default: temporary directory)")
    var outputDir: String?

    @Flag(name: .long, help: "Keep generated clips on disk instead of deleting temporary directory")
    var keepClips: Bool = false

    @OptionGroup var signal: WatermarkSignalOptions

    mutating func run() async throws {
        let config = try signal.makeConfiguration()
        let options = try signal.makeDetectionOptions(for: config)

        let dirURL: URL
        let ownsDir: Bool
        if let outputDir {
            dirURL = URL(fileURLWithPath: outputDir)
            ownsDir = false
        } else {
            dirURL = FileManager.default.temporaryDirectory
                .appendingPathComponent("forensic-wm-sim-\(UUID().uuidString)")
            ownsDir = true
        }
        try FileManager.default.createDirectory(at: dirURL, withIntermediateDirectories: true)
        defer {
            if ownsDir, !keepClips {
                try? FileManager.default.removeItem(at: dirURL)
            }
        }

        let candidates = (1 ... 12).map { String(format: "syn-sess-%02d", $0) }
        let outOfSetID = "syn-sess-outside-99"

        struct Spec {
            let label: String
            let sessionID: String?
            let inSet: Bool
            let duration: Double
            let scene: SyntheticSceneStyle
            let degradation: SimulatedCameraDegradation
            let tag: String
            let seed: UInt64
        }

        let specs: [Spec] = [
            Spec(label: "clip-01", sessionID: candidates[0], inSet: true, duration: 15, scene: .movingWithSceneCuts, degradation: .clean, tag: "original-15s-moving", seed: 101),
            Spec(label: "clip-02", sessionID: candidates[3], inSet: true, duration: 15, scene: .dark, degradation: .handheldRecompressed, tag: "handheld-recompressed-15s-dark", seed: 102),
            Spec(label: "clip-03", sessionID: candidates[7], inSet: true, duration: 15, scene: .bright, degradation: .handheldRecompressed, tag: "handheld-recompressed-15s-bright", seed: 103),
            Spec(label: "clip-04", sessionID: candidates[10], inSet: true, duration: 10, scene: .movingWithSceneCuts, degradation: .handheldRecompressed, tag: "trimmed-10s-handheld", seed: 104),
            Spec(label: "clip-05", sessionID: candidates[5], inSet: true, duration: 5, scene: .movingWithSceneCuts, degradation: .handheldRecompressed, tag: "trimmed-5s-handheld", seed: 105),
            Spec(
                label: "clip-06",
                sessionID: candidates[2],
                inSet: true,
                duration: 15,
                scene: .movingWithSceneCuts,
                degradation: SimulatedCameraDegradation(cropInsetFraction: 0.25, handheldJitterFraction: 0.02, sensorNoiseStdDev: 0.02, autoExposureDriftAmplitude: 0.05, autoWhiteBalanceDriftAmplitude: 0.03, startTimeOffsetSeconds: 7.1, averageBitRate: 800_000),
                tag: "cropped-50pct-recompressed-15s",
                seed: 106
            ),
            Spec(label: "clip-07", sessionID: nil, inSet: false, duration: 15, scene: .movingWithSceneCuts, degradation: .handheldRecompressed, tag: "unmarked-control-moving", seed: 201),
            Spec(label: "clip-08", sessionID: nil, inSet: false, duration: 15, scene: .dark, degradation: .clean, tag: "unmarked-control-dark", seed: 202),
            Spec(label: "clip-09", sessionID: outOfSetID, inSet: false, duration: 15, scene: .movingWithSceneCuts, degradation: .handheldRecompressed, tag: "outside-candidate-set-15s", seed: 301),
        ]

        var trials: [ForensicWatermarkTrial] = []
        for spec in specs {
            let clipURL = dirURL.appendingPathComponent("\(spec.label).mp4")
            try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
                outputURL: clipURL,
                width: 320,
                height: 180,
                frameRate: 30,
                durationSeconds: spec.duration,
                scene: spec.scene,
                sessionID: spec.sessionID,
                configuration: config,
                degradation: spec.degradation,
                randomSeed: spec.seed
            )
            trials.append(
                ForensicWatermarkTrial(
                    label: spec.label,
                    videoPath: clipURL.path,
                    expectedSessionID: spec.sessionID,
                    isInCandidateSet: spec.inSet,
                    transformTag: spec.tag,
                    playbackDevice: "SyntheticSimulator",
                    captureDevice: "SyntheticCamera",
                    cameraSettings: "320x180@30fps H.264"
                )
            )
        }

        let evaluator = ForensicWatermarkEvaluator(configuration: config, options: options)
        let report = try await evaluator.evaluate(trials: trials, candidateSessionIDs: candidates)
        print(report.markdownSummary())
    }
}
