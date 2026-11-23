import Foundation

// MARK: - Trial Manifest & Ground Truth

/// Ground-truth category for a single clip in a blinded evaluation experiment.
public enum ForensicWatermarkTrialCategory: String, Sendable, Equatable, Codable {
    /// Marked playback whose session ID is included in the detector's candidate set.
    case markedInCandidateSet
    /// Unmarked control playback (no watermark overlay active).
    case unmarkedControl
    /// Marked playback whose session ID is intentionally omitted from the detector's candidate set.
    case markedOutsideCandidateSet
}

/// Classification outcome comparing the detector's blinded decision against ground truth.
public enum ForensicWatermarkTrialClassification: String, Sendable, Equatable, Codable {
    case correctID
    case missedDetection
    case wrongID
    case controlTrueNegative
    case controlFalsePositive
    case outOfSetRejection
    case outOfSetFalsePositive
}

/// Specification of one blinded test clip for the evaluation harness.
public struct ForensicWatermarkTrial: Sendable, Equatable, Codable {
    /// Opaque clip label (e.g., `"clip-01"`). Never fed to the detector.
    public let label: String
    /// Local path to the blinded, metadata-stripped video clip.
    public let videoPath: String
    /// Ground-truth opaque session ID used during playback, or `nil` for unmarked controls.
    public let expectedSessionID: String?
    /// Whether `expectedSessionID` is present in the candidate list supplied to the detector.
    public let isInCandidateSet: Bool
    /// Transformation applied to the clip (e.g., `"original"`, `"trimmed-10s"`, `"cropped-60pct"`, `"recompressed"`).
    public let transformTag: String
    /// Optional metadata recorded for experiment reporting (never passed to the detector).
    public let playbackDevice: String?
    public let captureDevice: String?
    public let cameraSettings: String?

    public init(
        label: String,
        videoPath: String,
        expectedSessionID: String?,
        isInCandidateSet: Bool,
        transformTag: String = "original",
        playbackDevice: String? = nil,
        captureDevice: String? = nil,
        cameraSettings: String? = nil
    ) {
        self.label = label
        self.videoPath = videoPath
        self.expectedSessionID = expectedSessionID
        self.isInCandidateSet = isInCandidateSet
        self.transformTag = transformTag
        self.playbackDevice = playbackDevice
        self.captureDevice = captureDevice
        self.cameraSettings = cameraSettings
    }

    public var category: ForensicWatermarkTrialCategory {
        guard expectedSessionID != nil else { return .unmarkedControl }
        return isInCandidateSet ? .markedInCandidateSet : .markedOutsideCandidateSet
    }
}

/// Outcome of evaluating a single trial.
public struct ForensicWatermarkTrialResult: Sendable, Equatable, Codable {
    public let trial: ForensicWatermarkTrial
    public let category: ForensicWatermarkTrialCategory
    public let classification: ForensicWatermarkTrialClassification
    public let detection: ForensicWatermarkDetectionResult

    public init(
        trial: ForensicWatermarkTrial,
        category: ForensicWatermarkTrialCategory,
        classification: ForensicWatermarkTrialClassification,
        detection: ForensicWatermarkDetectionResult
    ) {
        self.trial = trial
        self.category = category
        self.classification = classification
        self.detection = detection
    }
}

/// Aggregated recovery statistics for clips grouped by duration bucket.
public struct ForensicWatermarkDurationSummary: Sendable, Equatable, Codable {
    /// Rounded clip duration bucket in seconds (e.g., 5, 10, 15).
    public let durationSecondsBucket: Int
    public let markedTrialCount: Int
    public let correctIDs: Int
    public let missedDetections: Int
    public let wrongIDs: Int

    public var recoveryRate: Double {
        guard markedTrialCount > 0 else { return 0 }
        return Double(correctIDs) / Double(markedTrialCount)
    }

    public init(
        durationSecondsBucket: Int,
        markedTrialCount: Int,
        correctIDs: Int,
        missedDetections: Int,
        wrongIDs: Int
    ) {
        self.durationSecondsBucket = durationSecondsBucket
        self.markedTrialCount = markedTrialCount
        self.correctIDs = correctIDs
        self.missedDetections = missedDetections
        self.wrongIDs = wrongIDs
    }
}

/// Complete blinded evaluation report separating correct IDs, missed detections, wrong IDs, and controls.
public struct ForensicWatermarkEvaluationReport: Sendable, Equatable, Codable {
    public let configuration: ForensicWatermarkConfiguration
    public let options: ForensicWatermarkDetectionOptions
    public let candidateCount: Int
    public let totalTrials: Int

    // Marked in-candidate-set counts
    public let markedInSetTrials: Int
    public let correctIDs: Int
    public let missedDetections: Int
    public let wrongIDs: Int

    // Unmarked control counts
    public let unmarkedControlTrials: Int
    public let controlTrueNegatives: Int
    public let controlFalsePositives: Int

    // Out-of-candidate-set marked counts
    public let outOfSetTrials: Int
    public let outOfSetRejections: Int
    public let outOfSetFalsePositives: Int

    /// Shortest duration bucket (in seconds) achieving 100% recovery with zero wrong IDs and at least one trial.
    public let shortestRepeatableDurationSeconds: Int?
    public let durationBreakdown: [ForensicWatermarkDurationSummary]
    public let trialResults: [ForensicWatermarkTrialResult]

    /// Generates a human-readable Markdown report suitable for GitHub issues or experiment logs.
    public func markdownSummary() -> String {
        var lines: [String] = []
        lines.append("## Forensic Watermark Blinded Evaluation Report")
        lines.append("")
        lines.append(
            "- **Configuration**: `\(configuration.chromaMode.rawValue)`, `\(configuration.spatialPattern.rawValue)`, "
                + "`opacity=\(String(format: "%.3f", configuration.opacity))`, "
                + "`chipRate=\(String(format: "%.1f", configuration.chipRateHz)) Hz`, "
                + "`period=\(configuration.periodChips) chips (\(String(format: "%.1f", configuration.periodSeconds))s)`"
        )
        lines.append("- **Candidate set size**: \(candidateCount) (decoys per clip: \(options.decoyCount))")
        lines.append(
            "- **Thresholds**: `minZScore=\(String(format: "%.1f", options.minZScore))`, "
                + "`minMargin=\(String(format: "%.1f", options.minMarginOverRunnerUp))`"
        )
        lines.append("")
        lines.append("### Summary Counts")
        lines.append("")
        lines.append("| Category | Trials | Correct / True Negative | Missed (Inconclusive) | Wrong ID / False Positive |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        lines.append("| Marked (in candidate set) | \(markedInSetTrials) | \(correctIDs) | \(missedDetections) | \(wrongIDs) |")
        lines.append("| Unmarked controls | \(unmarkedControlTrials) | \(controlTrueNegatives) | 0 | \(controlFalsePositives) |")
        lines.append("| Marked (outside candidate set) | \(outOfSetTrials) | \(outOfSetRejections) | 0 | \(outOfSetFalsePositives) |")
        lines.append("")

        if let shortest = shortestRepeatableDurationSeconds {
            lines.append("- **Shortest duration with repeatable recovery**: \(shortest)s")
        } else {
            lines.append("- **Shortest duration with repeatable recovery**: None achieved")
        }
        lines.append("")

        if !durationBreakdown.isEmpty {
            lines.append("### Duration Breakdown (Marked In-Set)")
            lines.append("")
            lines.append("| Duration (s) | Trials | Correct IDs | Missed | Wrong IDs | Recovery |")
            lines.append("| ---: | ---: | ---: | ---: | ---: | ---: |")
            for bucket in durationBreakdown {
                let pct = String(format: "%.0f%%", bucket.recoveryRate * 100.0)
                lines.append(
                    "| \(bucket.durationSecondsBucket)s | \(bucket.markedTrialCount) | \(bucket.correctIDs) | "
                        + "\(bucket.missedDetections) | \(bucket.wrongIDs) | \(pct) |"
                )
            }
            lines.append("")
        }

        lines.append("### Per-Clip Results")
        lines.append("")
        lines.append("| Clip | Category | Transform | Duration | Detected | z-score | Margin | Classification |")
        lines.append("| --- | --- | --- | ---: | --- | ---: | ---: | --- |")
        for item in trialResults {
            let dur = String(format: "%.1fs", item.detection.clipDurationSeconds)
            let detectedStr = item.detection.outcome.detectedSessionID ?? "inconclusive"
            let zStr = item.detection.bestCandidate.map { String(format: "%.2f", $0.zScore) } ?? "-"
            let marginStr = item.detection.bestCandidate.map { String(format: "%.2f", $0.marginOverRunnerUp) } ?? "-"
            lines.append(
                "| \(item.trial.label) | \(item.category.rawValue) | \(item.trial.transformTag) | \(dur) | "
                    + "\(detectedStr) | \(zStr) | \(marginStr) | \(item.classification.rawValue) |"
            )
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - Blinded Evaluator

/// Runs `ForensicWatermarkDetector` blinded across a set of trial clips and tabulates all error modes separately.
public struct ForensicWatermarkEvaluator: Sendable {
    public let detector: ForensicWatermarkDetector

    public init(detector: ForensicWatermarkDetector = ForensicWatermarkDetector()) {
        self.detector = detector
    }

    public init(
        configuration: ForensicWatermarkConfiguration = .default,
        options: ForensicWatermarkDetectionOptions = .default
    ) {
        self.detector = ForensicWatermarkDetector(configuration: configuration, options: options)
    }

    /// Evaluates every trial clip on disk blinded (only `videoPath` and `candidateSessionIDs` reach the detector).
    public func evaluate(
        trials: [ForensicWatermarkTrial],
        candidateSessionIDs: [String]
    ) async throws -> ForensicWatermarkEvaluationReport {
        var results: [ForensicWatermarkTrialResult] = []
        results.reserveCapacity(trials.count)

        for trial in trials {
            let detection = try await detector.detect(
                videoURL: URL(fileURLWithPath: trial.videoPath),
                candidateSessionIDs: candidateSessionIDs
            )
            let classification = Self.classify(trial: trial, outcome: detection.outcome)
            results.append(
                ForensicWatermarkTrialResult(
                    trial: trial,
                    category: trial.category,
                    classification: classification,
                    detection: detection
                )
            )
        }

        return Self.summarize(
            results: results,
            configuration: detector.configuration,
            options: detector.options,
            candidateCount: Set(candidateSessionIDs.filter { !$0.isEmpty }).count
        )
    }

    /// Classifies a single blinded detection outcome against ground truth.
    public static func classify(
        trial: ForensicWatermarkTrial,
        outcome: ForensicWatermarkDetectionOutcome
    ) -> ForensicWatermarkTrialClassification {
        switch trial.category {
        case .markedInCandidateSet:
            switch outcome {
            case let .detected(sessionID):
                return (sessionID == trial.expectedSessionID) ? .correctID : .wrongID
            case .inconclusive:
                return .missedDetection
            }

        case .unmarkedControl:
            switch outcome {
            case .detected:
                return .controlFalsePositive
            case .inconclusive:
                return .controlTrueNegative
            }

        case .markedOutsideCandidateSet:
            switch outcome {
            case .detected:
                return .outOfSetFalsePositive
            case .inconclusive:
                return .outOfSetRejection
            }
        }
    }

    /// Aggregates per-trial results into a full report.
    public static func summarize(
        results: [ForensicWatermarkTrialResult],
        configuration: ForensicWatermarkConfiguration,
        options: ForensicWatermarkDetectionOptions,
        candidateCount: Int
    ) -> ForensicWatermarkEvaluationReport {
        var markedInSet = 0
        var correctIDs = 0
        var missedDetections = 0
        var wrongIDs = 0

        var unmarkedControls = 0
        var controlTrueNegatives = 0
        var controlFalsePositives = 0

        var outOfSet = 0
        var outOfSetRejections = 0
        var outOfSetFalsePositives = 0

        var durationMap: [Int: (trials: Int, correct: Int, missed: Int, wrong: Int)] = [:]

        for item in results {
            switch item.classification {
            case .correctID:
                markedInSet += 1
                correctIDs += 1
            case .missedDetection:
                markedInSet += 1
                missedDetections += 1
            case .wrongID:
                markedInSet += 1
                wrongIDs += 1
            case .controlTrueNegative:
                unmarkedControls += 1
                controlTrueNegatives += 1
            case .controlFalsePositive:
                unmarkedControls += 1
                controlFalsePositives += 1
            case .outOfSetRejection:
                outOfSet += 1
                outOfSetRejections += 1
            case .outOfSetFalsePositive:
                outOfSet += 1
                outOfSetFalsePositives += 1
            }

            if item.category == .markedInCandidateSet {
                let bucket = max(1, Int(item.detection.clipDurationSeconds.rounded()))
                var entry = durationMap[bucket] ?? (0, 0, 0, 0)
                entry.trials += 1
                switch item.classification {
                case .correctID: entry.correct += 1
                case .missedDetection: entry.missed += 1
                case .wrongID: entry.wrong += 1
                default: break
                }
                durationMap[bucket] = entry
            }
        }

        let breakdown = durationMap.keys.sorted().map { bucket -> ForensicWatermarkDurationSummary in
            let entry = durationMap[bucket]!
            return ForensicWatermarkDurationSummary(
                durationSecondsBucket: bucket,
                markedTrialCount: entry.trials,
                correctIDs: entry.correct,
                missedDetections: entry.missed,
                wrongIDs: entry.wrong
            )
        }

        let shortestRepeatable = breakdown.first { summary in
            summary.markedTrialCount > 0 && summary.correctIDs == summary.markedTrialCount && summary.wrongIDs == 0
        }?.durationSecondsBucket

        return ForensicWatermarkEvaluationReport(
            configuration: configuration,
            options: options,
            candidateCount: candidateCount,
            totalTrials: results.count,
            markedInSetTrials: markedInSet,
            correctIDs: correctIDs,
            missedDetections: missedDetections,
            wrongIDs: wrongIDs,
            unmarkedControlTrials: unmarkedControls,
            controlTrueNegatives: controlTrueNegatives,
            controlFalsePositives: controlFalsePositives,
            outOfSetTrials: outOfSet,
            outOfSetRejections: outOfSetRejections,
            outOfSetFalsePositives: outOfSetFalsePositives,
            shortestRepeatableDurationSeconds: shortestRepeatable,
            durationBreakdown: breakdown,
            trialResults: results
        )
    }
}
