import CryptoKit
import Foundation

/// Deterministic spatiotemporal signal generator shared by the live player overlay and offline detector.
public enum ForensicWatermarkSignal {
    /// Straight RGBA color sample in `[0, 1]`.
    public struct RGBAColor: Sendable, Equatable {
        public let red: Float
        public let green: Float
        public let blue: Float
        public let alpha: Float

        public init(red: Float, green: Float, blue: Float, alpha: Float) {
            self.red = red
            self.green = green
            self.blue = blue
            self.alpha = alpha
        }
    }

    /// Derives a deterministic antipodal chip sequence in `{-1, +1}` for an opaque session ID.
    public static func chips(
        for sessionID: String,
        configuration: ForensicWatermarkConfiguration
    ) -> [Float] {
        deriveChips(
            label: "real:\(sessionID)",
            count: configuration.periodChips,
            domainSeparator: configuration.domainSeparator
        )
    }

    /// Derives a deterministic decoy chip sequence guaranteed to be domain-separated from real session IDs.
    public static func decoyChips(
        index: Int,
        configuration: ForensicWatermarkConfiguration
    ) -> [Float] {
        deriveChips(
            label: "decoy:\(index)",
            count: configuration.periodChips,
            domainSeparator: configuration.domainSeparator
        )
    }

    private static func deriveChips(
        label: String,
        count: Int,
        domainSeparator: String
    ) -> [Float] {
        guard count > 0 else { return [] }
        let key = SymmetricKey(data: Data(domainSeparator.utf8))
        var result: [Float] = []
        result.reserveCapacity(count)

        var counter: UInt32 = 0
        while result.count < count {
            var blockInput = Data(label.utf8)
            blockInput.append(0x00)
            var beCounter = counter.bigEndian
            withUnsafeBytes(of: &beCounter) { blockInput.append(contentsOf: $0) }
            let digest = HMAC<SHA256>.authenticationCode(for: blockInput, using: key)
            for byte in digest {
                for bit in 0 ..< 8 where result.count < count {
                    let isSet = ((byte >> bit) & 1) == 1
                    result.append(isSet ? 1.0 : -1.0)
                }
            }
            counter &+= 1
        }
        return result
    }

    /// Evaluates the continuous bi-phase sinusoidal temporal waveform in `[-1, +1]` at `timeSeconds`.
    ///
    /// Each chip spans `1 / chipRateHz` seconds and is shaped by `sin(2 * pi * phase)`,
    /// giving exact zero DC per chip and continuous zero crossings at chip boundaries.
    public static func temporalValue(
        at timeSeconds: Double,
        chips: [Float],
        chipRateHz: Double
    ) -> Float {
        guard !chips.isEmpty, chipRateHz > 0, timeSeconds.isFinite else { return 0 }
        let totalChips = timeSeconds * chipRateHz
        let chipFloor = floor(totalChips)
        let phase = totalChips - chipFloor
        let rawIndex = Int(chipFloor)
        let period = chips.count
        let wrappedIndex = ((rawIndex % period) + period) % period
        let carrier = sin(2.0 * Double.pi * phase)
        return chips[wrappedIndex] * Float(carrier)
    }

    /// Evaluates the smooth spatial basis in `[-1, +1]` for normalized picture coordinates `(u, v) in [0, 1]^2`.
    public static func spatialWeight(
        u: Float,
        v: Float,
        pattern: WatermarkSpatialPattern
    ) -> Float {
        switch pattern {
        case .smoothCosine3x2:
            return cos(2.0 * Float.pi * u) * cos(Float.pi * v)
        case .smoothCosine2x2:
            return cos(Float.pi * u) * cos(Float.pi * v)
        case .uniform:
            return 1.0
        }
    }

    /// Maps a combined spatiotemporal sample `signal in [-1, +1]` to an overlay straight RGBA color.
    ///
    /// For `.isoluminantBlueYellow` and `.luminance`, alpha is held constant at `configuration.opacity`
    /// while the color interpolates linearly between two poles `C-` and `C+`. Under standard `sourceOver`
    /// compositing (`(1 - a) * V + a * C`), the modulation difference is strictly independent of the
    /// underlying decrypted video pixel `V` across dark, midtone, and bright scenes.
    public static func overlayRGBA(
        signal: Float,
        configuration: ForensicWatermarkConfiguration
    ) -> RGBAColor {
        let clamped = max(-1.0 as Float, min(1.0 as Float, signal))
        let mix = 0.5 * (1.0 + clamped)
        let opacity = Float(configuration.opacity)

        switch configuration.chromaMode {
        case .isoluminantBlueYellow:
            // C- = (0.54, 0.54, 0.00), C+ = (0.46, 0.46, 1.00)
            // Rec. 709 Y(C-) = 0.501, Y(C+) = 0.499; linear-light Y(C-) = 0.239, Y(C+) = 0.240
            let rg = 0.54 - 0.08 * mix
            let b = mix
            return RGBAColor(red: rg, green: rg, blue: b, alpha: opacity)

        case .blueChannel:
            return RGBAColor(red: 0.0, green: 0.0, blue: 1.0, alpha: opacity * mix)

        case .luminance:
            return RGBAColor(red: mix, green: mix, blue: mix, alpha: opacity)
        }
    }

    /// Generates one full period of the zero-mean, unit-RMS reference temporal waveform sampled at `sampleRateHz`.
    public static func referenceWaveform(
        chips: [Float],
        chipRateHz: Double,
        sampleRateHz: Double
    ) -> [Float] {
        let periodSamples = max(1, Int((Double(chips.count) / chipRateHz * sampleRateHz).rounded()))
        var samples = [Float](repeating: 0, count: periodSamples)
        var sum: Double = 0
        for i in 0 ..< periodSamples {
            let t = (Double(i) + 0.5) / sampleRateHz
            let v = temporalValue(at: t, chips: chips, chipRateHz: chipRateHz)
            samples[i] = v
            sum += Double(v)
        }
        let mean = Float(sum / Double(periodSamples))
        var energy: Double = 0
        for i in 0 ..< periodSamples {
            samples[i] -= mean
            energy += Double(samples[i]) * Double(samples[i])
        }
        let rms = sqrt(energy / Double(periodSamples))
        if rms > 1e-9 {
            let inv = Float(1.0 / rms)
            for i in 0 ..< periodSamples {
                samples[i] *= inv
            }
        }
        return samples
    }
}
