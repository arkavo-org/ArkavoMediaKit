import Foundation

// MARK: - Watermark Modulation Modes

/// Color/luminance channel used by the player-only forensic watermark overlay.
///
/// All modes use standard `sourceOver` compositing over the displayed video bounds
/// without reading decrypted FairPlay frames.
public enum WatermarkChromaMode: String, Sendable, Equatable, Hashable, Codable, CaseIterable {
    /// Isoluminant blue-yellow opponent modulation (`C+ = (0.46, 0.46, 1.00)`, `C- = (0.54, 0.54, 0.00)`).
    ///
    /// Matched to ~0.50 Rec. 709 sRGB luminance (and ~0.24 linear luminance) for both poles so
    /// perceived luminance flicker is near zero while maximizing blue-yellow (`B - Y`) camera signal.
    case isoluminantBlueYellow

    /// Pure blue-channel `sourceOver` modulation with variable alpha in `[0, opacity]`.
    ///
    /// Minimizes OLED black-level lift on very dark scenes while modulating `B - Y`.
    case blueChannel

    /// Pure luminance modulation (white vs. black at constant alpha `opacity`).
    ///
    /// Useful as an experimental A/B baseline when comparing perceptibility against recovery
    /// under extreme lighting or monochrome capture.
    case luminance
}

/// Low-frequency spatial basis modulated by the temporal spreading code.
///
/// Zero-mean coarse patterns keep total frame luminance and color balance constant,
/// preventing camera auto-exposure (AE) and auto-white-balance (AWB) from cancelling the signal.
public enum WatermarkSpatialPattern: String, Sendable, Equatable, Hashable, Codable, CaseIterable {
    /// Smooth zero-mean 3x2 cosine pattern `cos(2 * pi * u) * cos(pi * v)`.
    ///
    /// Preserves both positive and negative lobes even under moderate cropping and resists
    /// display-to-camera moire because it has no sharp edges.
    case smoothCosine3x2

    /// Smooth zero-mean 2x2 cosine pattern `cos(pi * u) * cos(pi * v)`.
    case smoothCosine2x2

    /// Spatially uniform temporal modulation (`P(u, v) = 1`).
    ///
    /// Useful as a baseline for testing extreme crops against global AE/AWB interference.
    case uniform
}

// MARK: - Errors

/// Errors thrown by the forensic watermark renderer, detector, or evaluator.
public enum ForensicWatermarkError: Error, LocalizedError, Sendable, Equatable {
    case invalidSessionID(String)
    case invalidConfiguration(String)
    case unreadableVideo(String)
    case videoTrackMissing
    case readerFailed(String)
    case writerFailed(String)
    case metadataStripFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidSessionID(reason):
            "Invalid watermark session ID: \(reason)"
        case let .invalidConfiguration(reason):
            "Invalid watermark configuration: \(reason)"
        case let .unreadableVideo(reason):
            "Unable to read video asset: \(reason)"
        case .videoTrackMissing:
            "Video asset contains no readable video track"
        case let .readerFailed(reason):
            "Video frame decoding failed: \(reason)"
        case let .writerFailed(reason):
            "Synthetic video generation failed: \(reason)"
        case let .metadataStripFailed(reason):
            "Failed to strip metadata from video clip: \(reason)"
        }
    }
}

// MARK: - Opaque Session Code

/// Validated opaque playback session identifier for forensic watermarking.
///
/// Keeps account-to-session mapping strictly outside `ArkavoMediaKit` and the video renderer.
public struct WatermarkSessionCode: Sendable, Hashable, Codable {
    public static let maxByteLength = 256

    /// Opaque session identifier supplied by the host application.
    public let rawValue: String

    public init(_ rawValue: String) throws {
        guard !rawValue.isEmpty else {
            throw ForensicWatermarkError.invalidSessionID("Session ID must not be empty")
        }
        guard rawValue.utf8.count <= Self.maxByteLength else {
            throw ForensicWatermarkError.invalidSessionID("Session ID exceeds \(Self.maxByteLength) bytes")
        }
        for scalar in rawValue.unicodeScalars {
            if CharacterSet.controlCharacters.contains(scalar) {
                throw ForensicWatermarkError.invalidSessionID("Session ID must not contain control characters")
            }
        }
        self.rawValue = rawValue
    }
}

// MARK: - Configuration

/// Parameters defining the player-only spatiotemporal forensic watermark signal.
///
/// The playback overlay and offline detector must use the same configuration.
public struct ForensicWatermarkConfiguration: Sendable, Equatable, Hashable, Codable {
    /// Temporal chip rate in Hz. Each chip is one full sinusoidal bi-phase cycle (`sin(2 * pi * phase)`),
    /// ensuring zero DC per chip and staying well below 30 fps camera Nyquist (15 Hz).
    public let chipRateHz: Double

    /// Number of chips in one repeating code period.
    ///
    /// At `chipRateHz = 4.0` and `periodChips = 64`, one full period is 16.0 seconds,
    /// matching the 15-second initial capture target while folding coherently on longer clips.
    public let periodChips: Int

    /// Overlay `sourceOver` alpha strength in `(0, 0.25]`.
    public let opacity: Double

    /// Color/luminance modulation channel.
    public let chromaMode: WatermarkChromaMode

    /// Coarse spatial pattern over the aspect-fitted video rectangle.
    public let spatialPattern: WatermarkSpatialPattern

    /// Domain separation tag used when deriving pseudorandom chip sequences from session IDs.
    public let domainSeparator: String

    /// Duration of one full code cycle in seconds.
    public var periodSeconds: Double {
        Double(periodChips) / chipRateHz
    }

    public init(
        chipRateHz: Double = 4.0,
        periodChips: Int = 64,
        opacity: Double = 0.025,
        chromaMode: WatermarkChromaMode = .isoluminantBlueYellow,
        spatialPattern: WatermarkSpatialPattern = .smoothCosine3x2,
        domainSeparator: String = "arkavo.forensic-watermark.v1"
    ) {
        self.chipRateHz = chipRateHz
        self.periodChips = periodChips
        self.opacity = opacity
        self.chromaMode = chromaMode
        self.spatialPattern = spatialPattern
        self.domainSeparator = domainSeparator
    }

    /// Validates parameter bounds before rendering or detection.
    public func validate() throws {
        guard chipRateHz.isFinite, chipRateHz >= 1.0, chipRateHz <= 8.0 else {
            throw ForensicWatermarkError.invalidConfiguration("chipRateHz must be in [1.0, 8.0]")
        }
        guard periodChips >= 16, periodChips <= 512 else {
            throw ForensicWatermarkError.invalidConfiguration("periodChips must be in [16, 512]")
        }
        guard opacity.isFinite, opacity > 0.0, opacity <= 0.25 else {
            throw ForensicWatermarkError.invalidConfiguration("opacity must be in (0.0, 0.25]")
        }
        guard !domainSeparator.isEmpty, domainSeparator.utf8.count <= 128 else {
            throw ForensicWatermarkError.invalidConfiguration("domainSeparator must be 1...128 bytes")
        }
    }

    /// Balanced default for physical phone-to-phone prototype experiments.
    public static let `default` = ForensicWatermarkConfiguration()

    /// Lower-opacity preset for perceptibility threshold testing.
    public static let subtle = ForensicWatermarkConfiguration(opacity: 0.015)

    /// Higher-opacity preset for characterizing camera recovery ceilings.
    public static let robust = ForensicWatermarkConfiguration(opacity: 0.04)

    /// Luminance-channel A/B comparison preset.
    public static let luminanceExperiment = ForensicWatermarkConfiguration(
        opacity: 0.025,
        chromaMode: .luminance
    )
}
