import AVFoundation
import CoreGraphics
import CoreVideo
import Foundation
import Testing
@testable import ArkavoMediaKit

@Suite("Forensic Watermark Prototype Tests")
struct ForensicWatermarkTests {
    // MARK: - Configuration & Session Code Validation

    @Test("Opaque session code rejects empty, control characters, and oversized strings")
    func sessionCodeValidation() throws {
        let valid = try WatermarkSessionCode("sess-8f3c2a1b-90e4")
        #expect(valid.rawValue == "sess-8f3c2a1b-90e4")

        #expect {
            _ = try WatermarkSessionCode("")
        } throws: { error in
            if case .invalidSessionID = error as? ForensicWatermarkError { return true }
            return false
        }

        #expect {
            _ = try WatermarkSessionCode("sess\n123")
        } throws: { error in
            if case .invalidSessionID = error as? ForensicWatermarkError { return true }
            return false
        }

        let oversized = String(repeating: "a", count: WatermarkSessionCode.maxByteLength + 1)
        #expect {
            _ = try WatermarkSessionCode(oversized)
        } throws: { error in
            if case .invalidSessionID = error as? ForensicWatermarkError { return true }
            return false
        }
    }

    @Test("Configuration validation rejects out-of-range parameters")
    func configurationValidation() throws {
        try ForensicWatermarkConfiguration.default.validate()
        try ForensicWatermarkConfiguration.subtle.validate()
        try ForensicWatermarkConfiguration.robust.validate()
        try ForensicWatermarkConfiguration.luminanceExperiment.validate()

        let badRate = ForensicWatermarkConfiguration(chipRateHz: 15.0)
        #expect { try badRate.validate() } throws: { $0 is ForensicWatermarkError }

        let badOpacity = ForensicWatermarkConfiguration(opacity: 0.0)
        #expect { try badOpacity.validate() } throws: { $0 is ForensicWatermarkError }

        let badPeriod = ForensicWatermarkConfiguration(periodChips: 4)
        #expect { try badPeriod.validate() } throws: { $0 is ForensicWatermarkError }
    }

    // MARK: - Geometry Alignment (Rotation & Aspect Fitting)

    @Test("Video rect constrains overlay to active picture bounds across aspect ratios and rotations")
    func geometryAlignmentAcrossRotations() {
        // Landscape 16:9 video in portrait iPhone container (letterboxed top and bottom)
        let portraitContainer = CGRect(x: 0, y: 0, width: 390, height: 844)
        let video16x9 = CGSize(width: 1920, height: 1080)
        let portraitRect = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: video16x9,
            in: portraitContainer,
            gravity: .resizeAspect
        )
        #expect(abs(portraitRect.width - 390) < 0.01)
        #expect(abs(portraitRect.height - 219.375) < 0.05)
        #expect(abs(portraitRect.minX - 0) < 0.01)
        #expect(abs(portraitRect.midY - portraitContainer.midY) < 0.01)

        // Same 16:9 video after rotating device to landscape (pillarboxed left and right on 19.5:9 screen)
        let landscapeContainer = CGRect(x: 0, y: 0, width: 844, height: 390)
        let landscapeRect = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: video16x9,
            in: landscapeContainer,
            gravity: .resizeAspect
        )
        #expect(abs(landscapeRect.height - 390) < 0.01)
        #expect(abs(landscapeRect.width - 693.333) < 0.1)
        #expect(abs(landscapeRect.midX - landscapeContainer.midX) < 0.01)
        #expect(abs(landscapeRect.minY - 0) < 0.01)

        // Portrait 9:16 video in landscape container (pillarboxed)
        let video9x16 = CGSize(width: 1080, height: 1920)
        let portraitVideoInLandscape = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: video9x16,
            in: landscapeContainer,
            gravity: .resizeAspect
        )
        #expect(abs(portraitVideoInLandscape.height - 390) < 0.01)
        #expect(abs(portraitVideoInLandscape.width - 219.375) < 0.05)

        // Aspect fill and resize fill full container
        let fillRect = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: video16x9,
            in: portraitContainer,
            gravity: .resizeAspectFill
        )
        #expect(fillRect == portraitContainer)

        // Zero presentation size falls back safely to container bounds
        let fallbackRect = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: .zero,
            in: portraitContainer
        )
        #expect(fallbackRect == portraitContainer)
    }

    // MARK: - Signal & Compositing Properties

    @Test("Isoluminant blue-yellow overlay has near-zero luminance delta and pixel-independent modulation")
    func isoluminantAndSourceOverProperties() {
        let config = ForensicWatermarkConfiguration.default
        let cPlus = ForensicWatermarkSignal.overlayRGBA(signal: 1.0, configuration: config)
        let cMinus = ForensicWatermarkSignal.overlayRGBA(signal: -1.0, configuration: config)

        // Rec. 709 sRGB luminance match
        let yPlus = 0.2126 * cPlus.red + 0.7152 * cPlus.green + 0.0722 * cPlus.blue
        let yMinus = 0.2126 * cMinus.red + 0.7152 * cMinus.green + 0.0722 * cMinus.blue
        #expect(abs(yPlus - yMinus) < 0.005)

        // Linear-light luminance match (gamma 2.2)
        let yLinPlus = 0.2126 * pow(cPlus.red, 2.2) + 0.7152 * pow(cPlus.green, 2.2) + 0.0722 * pow(cPlus.blue, 2.2)
        let yLinMinus = 0.2126 * pow(cMinus.red, 2.2) + 0.7152 * pow(cMinus.green, 2.2) + 0.0722 * pow(cMinus.blue, 2.2)
        #expect(abs(yLinPlus - yLinMinus) < 0.005)

        // Verify sourceOver delta (I+ - I-) is identical across pure black (V=0), mid-gray (V=0.5), and white (V=1)
        let a = cPlus.alpha
        #expect(abs(cPlus.alpha - cMinus.alpha) < 1e-6)
        for v in [Float(0.0), Float(0.5), Float(1.0)] {
            let bPlus = (1 - a) * v + a * cPlus.blue
            let bMinus = (1 - a) * v + a * cMinus.blue
            #expect(abs((bPlus - bMinus) - a) < 1e-5)
        }
    }

    @Test("Chip derivation is deterministic, distinct per session, and domain-separated from decoys")
    func chipDerivationAndZeroDC() {
        let config = ForensicWatermarkConfiguration.default
        let c1 = ForensicWatermarkSignal.chips(for: "sess-alpha", configuration: config)
        let c1Repeat = ForensicWatermarkSignal.chips(for: "sess-alpha", configuration: config)
        let c2 = ForensicWatermarkSignal.chips(for: "sess-beta", configuration: config)
        let decoy0 = ForensicWatermarkSignal.decoyChips(index: 0, configuration: config)

        #expect(c1.count == config.periodChips)
        #expect(c1 == c1Repeat)
        #expect(c1 != c2)
        #expect(c1 != decoy0)

        // Every single chip integrates to zero over its cycle
        let waveform = ForensicWatermarkSignal.referenceWaveform(
            chips: c1,
            chipRateHz: config.chipRateHz,
            sampleRateHz: 32.0
        )
        let mean = waveform.reduce(0, +) / Float(waveform.count)
        #expect(abs(mean) < 1e-5)
    }

    @Test("Overlay image renderer and CoreAnimation layer stay decoupled from media bytes")
    @MainActor
    func overlayRendererAndLayer() throws {
        let config = ForensicWatermarkConfiguration.default
        let chips = ForensicWatermarkSignal.chips(for: "sess-render-test", configuration: config)
        let image = ForensicWatermarkRenderer.makeOverlayCGImage(
            at: 1.125,
            chips: chips,
            configuration: config
        )
        #expect(image != nil)
        #expect(image?.width == 32)
        #expect(image?.height == 24)

        let layer = ForensicWatermarkLayer()
        try layer.configure(sessionID: "sess-render-test", configuration: config, startMediaTime: 100.0)
        layer.align(
            forPresentationSize: CGSize(width: 1920, height: 1080),
            in: CGRect(x: 0, y: 0, width: 390, height: 844)
        )
        #expect(abs(layer.frame.width - 390) < 0.01)
        #expect(abs(layer.frame.height - 219.375) < 0.05)

        layer.update(at: 100.5)
        #expect(layer.contents != nil)

        // Disabling overlay for unmarked control clears layer contents
        layer.isWatermarkEnabled = false
        #expect(layer.contents == nil)
    }

    // MARK: - Detector Edge Cases (Pure Frame Samples)

    @Test("Detector returns inconclusive on short clips, empty candidates, and static zero-variance frames")
    func detectorEdgeCases() throws {
        let detector = ForensicWatermarkDetector()

        // Empty candidates
        let shortFrames = (0 ..< 150).map { i in
            ForensicFrameSample(
                timestampSeconds: Double(i) / 30.0,
                cellValues: [Float](repeating: 0.5, count: 24),
                globalMean: 0.5
            )
        }
        let noCandResult = try detector.detect(frames: shortFrames, candidateSessionIDs: [])
        #expect(noCandResult.outcome == .inconclusive(reason: .noCandidates))

        // Static zero-variance unmarked frames
        let staticResult = try detector.detect(frames: shortFrames, candidateSessionIDs: ["sess-1", "sess-2"])
        #expect(staticResult.outcome == .inconclusive(reason: .insufficientSignalVariance))

        // Clip too short (1.5 seconds < 3.0s minimum)
        let tooShortFrames: [ForensicFrameSample] = (0 ..< 45).map { i in
            let sampleValue: Float = (i % 2 == 0) ? 0.0 : 0.1
            return ForensicFrameSample(
                timestampSeconds: Double(i) / 30.0,
                cellValues: [Float](repeating: sampleValue, count: 24),
                globalMean: sampleValue
            )
        }
        let tooShortResult = try detector.detect(frames: tooShortFrames, candidateSessionIDs: ["sess-1"])
        #expect(tooShortResult.outcome == .inconclusive(reason: .clipTooShort))
    }

    // MARK: - End-to-End H.264 / HEVC Detection, Transforms, and Blinded Evaluation

    @Test("End-to-end recovery across dark, bright, moving scenes, handheld degradations, controls, and out-of-set IDs")
    func endToEndBlindedEvaluation() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("forensic-wm-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let config = ForensicWatermarkConfiguration.default
        let candidates = (1 ... 10).map { String(format: "opaque-session-%02d", $0) }
        let outOfSetSession = "opaque-session-outside-99"

        // 1. Original 15s moving scene with scene cuts (in-set)
        let movingOriginalURL = tempDir.appendingPathComponent("moving-orig.mp4")
        try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
            outputURL: movingOriginalURL,
            width: 240,
            height: 136,
            frameRate: 30,
            durationSeconds: 15.0,
            scene: .movingWithSceneCuts,
            sessionID: candidates[2],
            configuration: config,
            degradation: .clean,
            randomSeed: 11
        )

        // 2. Metadata-stripped, trimmed (10s from t=2.5s), cropped (center 70%), recompressed copy of movingOriginalURL
        let transformedCopyURL = tempDir.appendingPathComponent("moving-trimmed-cropped-recomp.mp4")
        try await ForensicWatermarkMediaUtilities.stripMetadata(
            from: movingOriginalURL,
            to: transformedCopyURL,
            trimStartSeconds: 2.5,
            trimDurationSeconds: 10.0,
            cropRectNormalized: CGRect(x: 0.15, y: 0.15, width: 0.70, height: 0.70),
            averageBitRate: 800_000
        )

        // Verify metadata was actually stripped from the blinded copy
        let strippedAsset = AVURLAsset(url: transformedCopyURL)
        let commonMetadata = try await strippedAsset.load(.commonMetadata)
        #expect(commonMetadata.isEmpty)

        // 3. Dark scene under handheld camera degradation + H.264 recompression (15s)
        let darkHandheldURL = tempDir.appendingPathComponent("dark-handheld.mp4")
        try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
            outputURL: darkHandheldURL,
            width: 240,
            height: 136,
            frameRate: 30,
            durationSeconds: 15.0,
            scene: .dark,
            sessionID: candidates[5],
            configuration: config,
            degradation: .handheldRecompressed,
            randomSeed: 22
        )

        // 4. Bright scene under handheld camera degradation + HEVC recompression (15s)
        let brightHandheldURL = tempDir.appendingPathComponent("bright-handheld-hevc.mp4")
        let hevcDegradation = SimulatedCameraDegradation(
            cropInsetFraction: 0.15,
            handheldJitterFraction: 0.03,
            sensorNoiseStdDev: 0.02,
            autoExposureDriftAmplitude: 0.05,
            autoWhiteBalanceDriftAmplitude: 0.03,
            startTimeOffsetSeconds: 6.25,
            averageBitRate: 850_000,
            useHEVC: true
        )
        try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
            outputURL: brightHandheldURL,
            width: 240,
            height: 136,
            frameRate: 30,
            durationSeconds: 15.0,
            scene: .bright,
            sessionID: candidates[8],
            configuration: config,
            degradation: hevcDegradation,
            randomSeed: 33
        )

        // 5. Unmarked control (moving scene + handheld camera noise)
        let unmarkedControlURL = tempDir.appendingPathComponent("unmarked-control.mp4")
        try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
            outputURL: unmarkedControlURL,
            width: 240,
            height: 136,
            frameRate: 30,
            durationSeconds: 15.0,
            scene: .movingWithSceneCuts,
            sessionID: nil,
            configuration: config,
            degradation: .handheldRecompressed,
            randomSeed: 44
        )

        // 6. Marked session outside the candidate set
        let outOfSetURL = tempDir.appendingPathComponent("outside-candidate-set.mp4")
        try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
            outputURL: outOfSetURL,
            width: 240,
            height: 136,
            frameRate: 30,
            durationSeconds: 15.0,
            scene: .movingWithSceneCuts,
            sessionID: outOfSetSession,
            configuration: config,
            degradation: .handheldRecompressed,
            randomSeed: 55
        )

        let trials: [ForensicWatermarkTrial] = [
            ForensicWatermarkTrial(
                label: "clip-01",
                videoPath: movingOriginalURL.path,
                expectedSessionID: candidates[2],
                isInCandidateSet: true,
                transformTag: "original"
            ),
            ForensicWatermarkTrial(
                label: "clip-02",
                videoPath: transformedCopyURL.path,
                expectedSessionID: candidates[2],
                isInCandidateSet: true,
                transformTag: "trimmed-10s-cropped-70pct-recompressed"
            ),
            ForensicWatermarkTrial(
                label: "clip-03",
                videoPath: darkHandheldURL.path,
                expectedSessionID: candidates[5],
                isInCandidateSet: true,
                transformTag: "handheld-dark-h264"
            ),
            ForensicWatermarkTrial(
                label: "clip-04",
                videoPath: brightHandheldURL.path,
                expectedSessionID: candidates[8],
                isInCandidateSet: true,
                transformTag: "handheld-bright-hevc"
            ),
            ForensicWatermarkTrial(
                label: "clip-05",
                videoPath: unmarkedControlURL.path,
                expectedSessionID: nil,
                isInCandidateSet: false,
                transformTag: "unmarked-control"
            ),
            ForensicWatermarkTrial(
                label: "clip-06",
                videoPath: outOfSetURL.path,
                expectedSessionID: outOfSetSession,
                isInCandidateSet: false,
                transformTag: "out-of-candidate-set"
            ),
        ]

        let evaluator = ForensicWatermarkEvaluator(configuration: config)
        let report = try await evaluator.evaluate(trials: trials, candidateSessionIDs: candidates)

        #expect(report.markedInSetTrials == 4)
        #expect(report.correctIDs == 4)
        #expect(report.missedDetections == 0)
        #expect(report.wrongIDs == 0)

        #expect(report.unmarkedControlTrials == 1)
        #expect(report.controlTrueNegatives == 1)
        #expect(report.controlFalsePositives == 0)

        #expect(report.outOfSetTrials == 1)
        #expect(report.outOfSetRejections == 1)
        #expect(report.outOfSetFalsePositives == 0)

        #expect(report.shortestRepeatableDurationSeconds == 10)

        // Verify phase offset estimation on the 2.5s trimmed clip matches ~2.5s
        let trimmedResult = report.trialResults[1]
        if let best = trimmedResult.detection.bestCandidate {
            let phaseErr = abs(best.estimatedPhaseOffsetSeconds - 2.5)
            #expect(phaseErr < 0.35)
        } else {
            Issue.record("Expected bestCandidate on trimmed clip")
        }

        // Verify Markdown summary includes separate rows for all categories
        let md = report.markdownSummary()
        #expect(md.contains("Marked (in candidate set)"))
        #expect(md.contains("Unmarked controls"))
        #expect(md.contains("Marked (outside candidate set)"))
    }

    @Test("Luminance and blueChannel experimental presets recover session IDs cleanly")
    func alternativeChromaModesRecover() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("forensic-wm-modes-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let candidates = ["mode-sess-a", "mode-sess-b", "mode-sess-c", "mode-sess-d"]

        for mode in [WatermarkChromaMode.blueChannel, WatermarkChromaMode.luminance] {
            let config = ForensicWatermarkConfiguration(opacity: 0.025, chromaMode: mode)
            let clipURL = tempDir.appendingPathComponent("clip-\(mode.rawValue).mp4")
            try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
                outputURL: clipURL,
                width: 200,
                height: 112,
                frameRate: 30,
                durationSeconds: 12.0,
                scene: .movingWithSceneCuts,
                sessionID: candidates[1],
                configuration: config,
                degradation: .handheldRecompressed,
                randomSeed: 77
            )

            let detector = ForensicWatermarkDetector(configuration: config)
            let result = try await detector.detect(videoURL: clipURL, candidateSessionIDs: candidates)
            #expect(result.outcome == .detected(sessionID: candidates[1]))
        }
    }

    @Test("Extreme single-lobe corner crop still recovers via global mean fallback channel")
    func extremeSingleLobeCropRecovery() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("forensic-wm-crop-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let config = ForensicWatermarkConfiguration.default
        let candidates = ["crop-sess-1", "crop-sess-2", "crop-sess-3", "crop-sess-4"]

        let fullURL = tempDir.appendingPathComponent("full.mp4")
        try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
            outputURL: fullURL,
            width: 240,
            height: 136,
            frameRate: 30,
            durationSeconds: 15.0,
            scene: .movingWithSceneCuts,
            sessionID: candidates[2],
            configuration: config,
            degradation: .clean,
            randomSeed: 88
        )

        // Tight 20%x30% crop strictly inside the top-left positive lobe of cos(2*pi*u)*cos(pi*v)
        let cornerURL = tempDir.appendingPathComponent("corner.mp4")
        try await ForensicWatermarkMediaUtilities.stripMetadata(
            from: fullURL,
            to: cornerURL,
            cropRectNormalized: CGRect(x: 0.0, y: 0.0, width: 0.20, height: 0.30),
            averageBitRate: 1_200_000
        )

        let detector = ForensicWatermarkDetector(configuration: config)
        let result = try await detector.detect(videoURL: cornerURL, candidateSessionIDs: candidates)
        #expect(result.outcome == .detected(sessionID: candidates[2]))
    }
}
