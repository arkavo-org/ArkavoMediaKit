import AVFoundation
import CoreGraphics
import CoreVideo
import Foundation
import Testing
@testable import ArkavoMediaKit

@Suite("Forensic Watermark Prototype Tests")
struct ForensicWatermarkTests {
    // MARK: - Configuration & Session Code Validation

    @Test("Opaque session code accepts printable ASCII and rejects empty, whitespace, non-ASCII, control, and oversized strings")
    func sessionCodeValidation() throws {
        let valid = try WatermarkSessionCode("sess-8f3c2a1b_90e4:ok")
        #expect(valid.rawValue == "sess-8f3c2a1b_90e4:ok")

        for bad in ["", "sess\n123", "sess 123", "sess-caf\u{00E9}", String(repeating: "a", count: WatermarkSessionCode.maxByteLength + 1)] {
            #expect {
                _ = try WatermarkSessionCode(bad)
            } throws: { error in
                if case .invalidSessionID = error as? ForensicWatermarkError { return true }
                return false
            }
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

    @Test("Video rect constrains overlay to active picture bounds across rotations and returns zero when presentation size is unknown")
    func geometryAlignmentAcrossRotations() {
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

        // Rotated to landscape (pillarboxed on 19.5:9 screen)
        let landscapeContainer = CGRect(x: 0, y: 0, width: 844, height: 390)
        let landscapeRect = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: video16x9,
            in: landscapeContainer,
            gravity: .resizeAspect
        )
        #expect(abs(landscapeRect.height - 390) < 0.01)
        #expect(abs(landscapeRect.width - 693.333) < 0.1)
        #expect(abs(landscapeRect.midX - landscapeContainer.midX) < 0.01)

        // Portrait 9:16 video in landscape container
        let video9x16 = CGSize(width: 1080, height: 1920)
        let portraitVideoInLandscape = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: video9x16,
            in: landscapeContainer,
            gravity: .resizeAspect
        )
        #expect(abs(portraitVideoInLandscape.height - 390) < 0.01)
        #expect(abs(portraitVideoInLandscape.width - 219.375) < 0.05)

        // Aspect fill fills full container
        let fillRect = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: video16x9,
            in: portraitContainer,
            gravity: .resizeAspectFill
        )
        #expect(fillRect == portraitContainer)

        // Unknown / zero presentation size returns .zero so letterbox bars are never painted
        let unknownRect = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: .zero,
            in: portraitContainer
        )
        #expect(unknownRect == .zero)
    }

    // MARK: - 16-Bit Overlay Pixel Precision & Compositing Properties

    @Test("16-bit rendered overlay texture preserves isoluminant poles even at subtle opacity (0.015 and 0.025)")
    func rendered16BitTexturePreservesIsoluminance() throws {
        for opacity in [0.015, 0.025] {
            let config = ForensicWatermarkConfiguration(
                chipRateHz: 4.0,
                periodChips: 16,
                opacity: opacity,
                chromaMode: .isoluminantBlueYellow,
                spatialPattern: .uniform
            )
            // First chip +1 at t = 0.0625s (sin(pi/2) = +1), second chip -1 at t = 0.3125s (sin(pi/2) = +1 -> -1)
            let chips: [Float] = [1.0, -1.0] + [Float](repeating: 1.0, count: 14)

            let plusImg = try #require(ForensicWatermarkRenderer.makeOverlayCGImage(at: 0.0625, chips: chips, configuration: config, gridWidth: 4, gridHeight: 4))
            let minusImg = try #require(ForensicWatermarkRenderer.makeOverlayCGImage(at: 0.3125, chips: chips, configuration: config, gridWidth: 4, gridHeight: 4))
            #expect(plusImg.bitsPerComponent == 16)
            #expect(minusImg.bitsPerComponent == 16)

            let plusData = try #require(plusImg.dataProvider?.data as Data?)
            let minusData = try #require(minusImg.dataProvider?.data as Data?)

            func readFirstPixelStraight(_ data: Data) -> (r: Double, g: Double, b: Double, a: Double) {
                let words = data.withUnsafeBytes { Array($0.bindMemory(to: UInt16.self).prefix(4)) }
                let a = Double(words[3]) / 65535.0
                let r = (Double(words[0]) / 65535.0) / max(a, 1e-9)
                let g = (Double(words[1]) / 65535.0) / max(a, 1e-9)
                let b = (Double(words[2]) / 65535.0) / max(a, 1e-9)
                return (r, g, b, a)
            }

            let p = readFirstPixelStraight(plusData)
            let m = readFirstPixelStraight(minusData)
            #expect(abs(p.a - opacity) < 0.0005)
            #expect(abs(m.a - opacity) < 0.0005)
            // Verify R/G compensator actually differs between poles (0.46 vs 0.54, NOT collapsed to 0.50!)
            #expect(m.r - p.r > 0.07)
            #expect(p.b - m.b > 0.98)

            let yPlus = 0.2126 * p.r + 0.7152 * p.g + 0.0722 * p.b
            let yMinus = 0.2126 * m.r + 0.7152 * m.g + 0.0722 * m.b
            #expect(abs(yPlus - yMinus) < 0.005)
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

        let waveform = ForensicWatermarkSignal.referenceWaveform(
            chips: c1,
            chipRateHz: config.chipRateHz,
            sampleRateHz: 32.0
        )
        let mean = waveform.reduce(0, +) / Float(waveform.count)
        #expect(abs(mean) < 1e-5)
    }

    @Test("ForensicWatermarkLayer copies state in init(layer:) and ForensicWatermarkOverlay throws on invalid inputs")
    @MainActor
    func overlayValidationAndLayerPresentationCopy() throws {
        let config = ForensicWatermarkConfiguration.default
        let layer = ForensicWatermarkLayer()
        try layer.configure(sessionID: "sess-layer-copy", configuration: config, startMediaTime: 100.0)
        layer.align(toVideoRect: CGRect(x: 0, y: 120, width: 390, height: 220))
        layer.update(at: 100.5)
        #expect(layer.contents != nil)

        // Presentation copy via init(layer:) preserves state without crashing
        let presentationCopy = ForensicWatermarkLayer(layer: layer)
        presentationCopy.align(toVideoRect: CGRect(x: 0, y: 120, width: 390, height: 220))
        presentationCopy.update(at: 100.5)
        #expect(presentationCopy.contents != nil)

        // Zero video rect skips drawing
        layer.align(toVideoRect: .zero)
        layer.update(at: 100.75)
        #expect(layer.contents == nil)

        // SwiftUI overlay accepts nil (unmarked control) and rejects invalid sessionID / low refresh rate
        let player = AVPlayer()
        ForensicWatermarkPlayerPolicy.configureForWatermarkedPlayback(player)
        #expect(player.allowsExternalPlayback == false)

        _ = try ForensicWatermarkOverlay(sessionID: nil, player: player)
        #expect {
            _ = try ForensicWatermarkOverlay(sessionID: "bad\nid", player: player)
        } throws: { $0 is ForensicWatermarkError }
        #expect {
            _ = try ForensicWatermarkOverlay(
                sessionID: "valid-id",
                player: player,
                configuration: ForensicWatermarkConfiguration(chipRateHz: 8.0),
                refreshRateHz: 10.0
            )
        } throws: { $0 is ForensicWatermarkError }
    }

    // MARK: - Detector Timing, Bounds, VFR & False Positive Calibration

    @Test("Exact period-aligned folding eliminates phase drift for non-integer sample periods (32 chips @ 7.5 Hz at 15s and 120s)")
    func nonIntegerPeriodFoldingZeroDrift() throws {
        let config = ForensicWatermarkConfiguration(
            chipRateHz: 7.5,
            periodChips: 32,
            opacity: 0.025,
            chromaMode: .isoluminantBlueYellow,
            spatialPattern: .smoothCosine3x2
        )
        let detector = ForensicWatermarkDetector(configuration: config)
        let candidates = ["drift-sess-1", "drift-sess-2", "drift-sess-3", "drift-sess-4"]
        let chips = ForensicWatermarkSignal.chips(for: candidates[0], configuration: config)

        func makeNoiselessFrames(durationSeconds: Double) -> [ForensicFrameSample] {
            let count = Int(durationSeconds * 30.0)
            var result: [ForensicFrameSample] = []
            result.reserveCapacity(count)
            for i in 0 ..< count {
                let t = Double(i) / 30.0
                let temporal = ForensicWatermarkSignal.temporalValue(at: t, chips: chips, chipRateHz: config.chipRateHz)
                var cells = [Float](repeating: 0, count: 24)
                var sum: Float = 0
                for row in 0 ..< 4 {
                    let v = (Float(row) + 0.5) / 4.0
                    for col in 0 ..< 6 {
                        let u = (Float(col) + 0.5) / 6.0
                        let w = ForensicWatermarkSignal.spatialWeight(u: u, v: v, pattern: config.spatialPattern)
                        let val = 0.012 * w * temporal
                        cells[row * 6 + col] = val
                        sum += val
                    }
                }
                result.append(ForensicFrameSample(timestampSeconds: t, cellValues: cells, globalMean: sum / 24.0))
            }
            return result
        }

        let res15 = try detector.detect(frames: makeNoiselessFrames(durationSeconds: 15.0), candidateSessionIDs: candidates)
        let res120 = try detector.detect(frames: makeNoiselessFrames(durationSeconds: 120.0), candidateSessionIDs: candidates)

        #expect(res15.outcome == .detected(sessionID: candidates[0]))
        #expect(res120.outcome == .detected(sessionID: candidates[0]))
        // 120s must remain strongly detected (no drift cancellation!)
        #expect((res120.bestCandidate?.zScore ?? 0) >= 8.0)
    }

    @Test("Detector enforces maxClipDurationSeconds, rejects non-finite timestamps, and handles VFR / 60fps / dropped frames")
    func frameBoundsAndVFR60fps() throws {
        let config = ForensicWatermarkConfiguration.default
        let boundedOptions = ForensicWatermarkDetectionOptions(maxClipDurationSeconds: 10.0)
        let detector = ForensicWatermarkDetector(configuration: config, options: boundedOptions)

        // Non-finite timestamp throws invalidFrameData
        let badFrame = ForensicFrameSample(timestampSeconds: .infinity, cellValues: [Float](repeating: 0, count: 24), globalMean: 0)
        #expect {
            _ = try detector.detect(frames: [badFrame], candidateSessionIDs: ["sess-1"])
        } throws: { error in
            if case .invalidFrameData = error as? ForensicWatermarkError { return true }
            return false
        }

        // Enforce maxClipDurationSeconds on 60s of samples -> reports <= 10.1s
        let targetID = "vfr-sess-target"
        let candidates = [targetID, "vfr-sess-other-1", "vfr-sess-other-2", "vfr-sess-other-3"]
        let chips = ForensicWatermarkSignal.chips(for: targetID, configuration: config)

        // 60 fps VFR with jittered timestamps and 10% dropped frames over 30s
        var frames: [ForensicFrameSample] = []
        for i in 0 ..< 1800 {
            if i % 10 == 3 { continue } // simulated dropped frame
            let jitter = Double((i * 17) % 7 - 3) * 0.001
            let t = Double(i) / 60.0 + jitter
            let temporal = ForensicWatermarkSignal.temporalValue(at: t + 1.2, chips: chips, chipRateHz: config.chipRateHz)
            var cells = [Float](repeating: 0, count: 24)
            var sum: Float = 0
            for row in 0 ..< 4 {
                let v = (Float(row) + 0.5) / 4.0
                for col in 0 ..< 6 {
                    let u = (Float(col) + 0.5) / 6.0
                    let w = ForensicWatermarkSignal.spatialWeight(u: u, v: v, pattern: config.spatialPattern)
                    let val = 0.012 * w * temporal + 0.005 * sin(Float(t) * 0.8 + u * 2.0)
                    cells[row * 6 + col] = val
                    sum += val
                }
            }
            frames.append(ForensicFrameSample(timestampSeconds: t, cellValues: cells, globalMean: sum / 24.0))
        }

        let result = try detector.detect(frames: frames, candidateSessionIDs: candidates)
        #expect(result.clipDurationSeconds <= 10.2)
        #expect(result.outcome == .detected(sessionID: targetID))
    }

    @Test("Detector edge cases: empty candidates, static zero-variance frames, and too-short clips")
    func detectorEdgeCases() throws {
        let detector = ForensicWatermarkDetector()

        let staticFrames: [ForensicFrameSample] = (0 ..< 150).map { i in
            ForensicFrameSample(
                timestampSeconds: Double(i) / 30.0,
                cellValues: [Float](repeating: 0.5, count: 24),
                globalMean: 0.5
            )
        }
        let noCandResult = try detector.detect(frames: staticFrames, candidateSessionIDs: [])
        #expect(noCandResult.outcome == .inconclusive(reason: .noCandidates))

        let staticResult = try detector.detect(frames: staticFrames, candidateSessionIDs: ["sess-1", "sess-2"])
        #expect(staticResult.outcome == .inconclusive(reason: .insufficientSignalVariance))

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

    @Test("Monte Carlo null calibration produces zero false positives across 40 unmarked clips x 20 candidates")
    func monteCarloFalsePositiveRate() throws {
        let detector = ForensicWatermarkDetector()
        let candidates = (1 ... 20).map { String(format: "mc-sess-%02d", $0) }
        var falsePositives = 0

        for trial in 0 ..< 40 {
            var state: UInt64 = UInt64(trial + 1) &* 0x9E37_79B9_7F4A_7C15
            func nextNoise() -> Float {
                state &+= 0x9E37_79B9_7F4A_7C15
                var z = state
                z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
                z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
                let u = Float((z ^ (z >> 31)) >> 40) / Float(1 << 24)
                return (u - 0.5) * 0.06
            }

            var frames: [ForensicFrameSample] = []
            frames.reserveCapacity(450)
            for f in 0 ..< 450 {
                let t = Double(f) / 30.0
                var cells = [Float](repeating: 0, count: 24)
                var sum: Float = 0
                for c in 0 ..< 24 {
                    let drift = 0.04 * sin(Float(t) * 1.1 + Float(c) * 0.3)
                    let v = drift + nextNoise()
                    cells[c] = v
                    sum += v
                }
                frames.append(ForensicFrameSample(timestampSeconds: t, cellValues: cells, globalMean: sum / 24.0))
            }

            let res = try detector.detect(frames: frames, candidateSessionIDs: candidates)
            if res.outcome.detectedSessionID != nil {
                falsePositives += 1
            }
        }
        #expect(falsePositives == 0)
    }

    // MARK: - Path Safety, Rotated Portrait Clips & Real Metadata Stripping

    @Test("stripMetadata rejects identical input/output paths, directory destinations, and preserves source files")
    func stripMetadataPathSafety() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("forensic-wm-safety-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let srcURL = tempDir.appendingPathComponent("source.mp4")
        let sentinel = Data("sentinel-do-not-delete".utf8)
        try sentinel.write(to: srcURL)

        // Same input and output path must throw and MUST NOT delete the source file
        await #expect {
            try await ForensicWatermarkMediaUtilities.stripMetadata(from: srcURL, to: srcURL)
        } throws: { error in
            (error as? ForensicWatermarkError) == .sameInputOutputPath
        }
        #expect((try? Data(contentsOf: srcURL)) == sentinel)

        // Existing directory output path must throw and MUST NOT delete the directory
        let subDir = tempDir.appendingPathComponent("existing-dir")
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        let innerFile = subDir.appendingPathComponent("keep.txt")
        try sentinel.write(to: innerFile)

        await #expect {
            try await ForensicWatermarkMediaUtilities.stripMetadata(from: srcURL, to: subDir)
        } throws: { error in
            (error as? ForensicWatermarkError) == .outputPathIsDirectory
        }
        #expect(FileManager.default.fileExists(atPath: innerFile.path))

        // Existing output file with overwrite: false must fail without clobbering
        let existingOut = tempDir.appendingPathComponent("existing.mp4")
        try sentinel.write(to: existingOut)
        await #expect {
            try await ForensicWatermarkMediaUtilities.stripMetadata(from: srcURL, to: existingOut, overwrite: false)
        } throws: { error in
            if case .outputFileAlreadyExists = error as? ForensicWatermarkError { return true }
            return false
        }
        #expect((try? Data(contentsOf: existingOut)) == sentinel)
    }

    @Test("stripMetadata rotates 90-degree portrait tracks properly, strips real metadata atoms, and preserves watermark")
    func stripMetadataRotatedPortraitAndRealMetadata() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("forensic-wm-portrait-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let config = ForensicWatermarkConfiguration.default
        let candidates = ["portrait-sess-1", "portrait-sess-2", "portrait-sess-3", "portrait-sess-4"]

        // Build real metadata items (title + creator) to verify stripping actually removes them
        let titleItem = AVMutableMetadataItem()
        titleItem.identifier = .commonIdentifierTitle
        titleItem.value = "Sensitive iPhone Capture" as NSString
        let softwareItem = AVMutableMetadataItem()
        softwareItem.identifier = .commonIdentifierSoftware
        softwareItem.value = "iOS Camera Prototype" as NSString

        // 240x136 landscape buffer with 90-degree clockwise preferredTransform -> 136x240 portrait display
        let portraitTransform = CGAffineTransform(a: 0, b: 1, c: -1, d: 0, tx: 136, ty: 0)
        let rotatedURL = tempDir.appendingPathComponent("rotated-source.mp4")
        try await ForensicWatermarkMediaUtilities.generateSyntheticVideo(
            outputURL: rotatedURL,
            width: 240,
            height: 136,
            frameRate: 30,
            durationSeconds: 12.0,
            scene: .bright,
            sessionID: candidates[1],
            configuration: config,
            degradation: .clean,
            randomSeed: 91,
            preferredTransform: portraitTransform,
            metadata: [titleItem, softwareItem]
        )

        // Confirm source carries metadata and rotated transform
        let srcAsset = AVURLAsset(url: rotatedURL)
        let srcMeta = try await srcAsset.load(.commonMetadata)
        #expect(!srcMeta.isEmpty)

        // Strip metadata + crop center 70% in portrait display space
        let strippedURL = tempDir.appendingPathComponent("portrait-stripped-cropped.mp4")
        try await ForensicWatermarkMediaUtilities.stripMetadata(
            from: rotatedURL,
            to: strippedURL,
            cropRectNormalized: CGRect(x: 0.15, y: 0.15, width: 0.70, height: 0.70),
            averageBitRate: 1_200_000
        )

        let outAsset = AVURLAsset(url: strippedURL)
        let outCommonMeta = try await outAsset.load(.commonMetadata)
        let outAllMeta = try await outAsset.load(.metadata)
        #expect(outCommonMeta.isEmpty)
        #expect(outAllMeta.isEmpty)

        let outTrack = try #require(try await outAsset.loadTracks(withMediaType: .video).first)
        let outNatural = try await outTrack.load(.naturalSize)
        let outTransform = try await outTrack.load(.preferredTransform)
        #expect(outTransform.isIdentity)
        // Portrait output: height > width (~94 x 168)
        #expect(outNatural.height > outNatural.width)

        // Verify bottom rows of decoded frame were written (not zeroed/uninitialized)
        let reader = try AVAssetReader(asset: outAsset)
        let output = AVAssetReaderTrackOutput(
            track: outTrack,
            outputSettings: [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA]
        )
        reader.add(output)
        #expect(reader.startReading())
        let sample = try #require(output.copyNextSampleBuffer())
        let buffer = try #require(CMSampleBufferGetImageBuffer(sample))
        CVPixelBufferLockBaseAddress(buffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
        let base = try #require(CVPixelBufferGetBaseAddress(buffer)).assumingMemoryBound(to: UInt8.self)
        let bpr = CVPixelBufferGetBytesPerRow(buffer)
        let h = CVPixelBufferGetHeight(buffer)
        let w = CVPixelBufferGetWidth(buffer)
        let bottomRowOffset = (h - 2) * bpr + (w / 2) * 4
        // Bright scene pixel must be brightly populated at the very bottom of the portrait output
        #expect(base[bottomRowOffset] > 100)
        #expect(base[bottomRowOffset + 1] > 100)
        #expect(base[bottomRowOffset + 2] > 100)
        reader.cancelReading()

        // Watermark recovers from the rotated, stripped, cropped portrait clip!
        let detector = ForensicWatermarkDetector(configuration: config)
        let result = try await detector.detect(videoURL: strippedURL, candidateSessionIDs: candidates)
        #expect(result.outcome == .detected(sessionID: candidates[1]))
    }

    // MARK: - End-to-End H.264 / HEVC Detection & Blinded Evaluation Harness

    @Test("End-to-end recovery via 16-bit live overlay, independent RGB noise, controls, out-of-set IDs, and evaluator resilience")
    func endToEndBlindedEvaluation() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("forensic-wm-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let config = ForensicWatermarkConfiguration.default
        let candidates = (1 ... 10).map { String(format: "opaque-session-%02d", $0) }
        let outOfSetSession = "opaque-session-outside-99"

        // 1. Original 15s moving scene with scene cuts (in-set, via 16-bit rendered overlay)
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

        // 2. Metadata-stripped, trimmed (10s from t=2.5s), cropped (center 70%), recompressed copy
        let transformedCopyURL = tempDir.appendingPathComponent("moving-trimmed-cropped-recomp.mp4")
        try await ForensicWatermarkMediaUtilities.stripMetadata(
            from: movingOriginalURL,
            to: transformedCopyURL,
            trimStartSeconds: 2.5,
            trimDurationSeconds: 10.0,
            cropRectNormalized: CGRect(x: 0.15, y: 0.15, width: 0.70, height: 0.70),
            averageBitRate: 800_000
        )

        // 3. Dark scene under handheld camera degradation (independent RGB noise + spatially varying drift + H.264)
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

        // 4. Bright scene under handheld degradation + HEVC
        let brightHandheldURL = tempDir.appendingPathComponent("bright-handheld-hevc.mp4")
        let hevcDegradation = SimulatedCameraDegradation(
            cropInsetFraction: 0.15,
            handheldJitterFraction: 0.03,
            sensorNoiseStdDev: 0.02,
            autoExposureDriftAmplitude: 0.05,
            autoWhiteBalanceDriftAmplitude: 0.03,
            startTimeOffsetSeconds: 6.25,
            averageBitRate: 850_000,
            useHEVC: true,
            useRenderedOverlayTexture: true
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

        // 5. Unmarked control
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

        // 6. Marked session outside candidate set (intentionally mislabeled isInCandidateSet: true to verify authoritative derivation!)
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
            ForensicWatermarkTrial(label: "clip-01", videoPath: movingOriginalURL.path, expectedSessionID: candidates[2], isInCandidateSet: true, transformTag: "original"),
            ForensicWatermarkTrial(label: "clip-02", videoPath: transformedCopyURL.path, expectedSessionID: candidates[2], isInCandidateSet: true, transformTag: "trimmed-10s-cropped-70pct-recompressed"),
            ForensicWatermarkTrial(label: "clip-03", videoPath: darkHandheldURL.path, expectedSessionID: candidates[5], isInCandidateSet: true, transformTag: "handheld-dark-h264"),
            ForensicWatermarkTrial(label: "clip-04", videoPath: brightHandheldURL.path, expectedSessionID: candidates[8], isInCandidateSet: true, transformTag: "handheld-bright-hevc"),
            ForensicWatermarkTrial(label: "clip-05", videoPath: unmarkedControlURL.path, expectedSessionID: nil, isInCandidateSet: false, transformTag: "unmarked-control"),
            ForensicWatermarkTrial(label: "clip-06", videoPath: outOfSetURL.path, expectedSessionID: outOfSetSession, isInCandidateSet: true, transformTag: "out-of-candidate-set"),
        ]

        let evaluator = ForensicWatermarkEvaluator(configuration: config, minRepeatableTrialsPerDuration: 2)
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
        #expect(report.readErrors == 0)

        // 10s bucket only has n=1 trial, while 15s bucket has n=3 -> shortest repeatable with n>=2 is 15s, NOT 10s!
        #expect(report.shortestRepeatableDurationSeconds == 15)

        // Report redacts full local directory paths to filenames
        #expect(!report.trialResults[0].trial.videoPath.contains(tempDir.path))
        #expect(report.trialResults[0].trial.videoPath == "moving-orig.mp4")

        // Verify phase offset estimation on the 2.5s trimmed clip
        let trimmedDetection = try #require(report.trialResults[1].detection)
        let best = try #require(trimmedDetection.bestCandidate)
        #expect(abs(best.estimatedPhaseOffsetSeconds - 2.5) < 0.35)

        // Verify per-clip error resilience: an unreadable clip records .readError without discarding valid results
        let missingTrial = ForensicWatermarkTrial(
            label: "clip-missing",
            videoPath: tempDir.appendingPathComponent("does-not-exist.mp4").path,
            expectedSessionID: candidates[0],
            isInCandidateSet: true,
            transformTag: "missing"
        )
        let resilientReport = try await evaluator.evaluate(trials: [trials[0], missingTrial], candidateSessionIDs: candidates)
        #expect(resilientReport.correctIDs == 1)
        #expect(resilientReport.readErrors == 1)
        #expect(resilientReport.shortestRepeatableDurationSeconds == nil)
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
