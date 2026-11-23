import AVFoundation
import CoreGraphics
import CoreVideo
import Foundation

#if canImport(QuartzCore)
import QuartzCore
#endif

#if canImport(SwiftUI)
import SwiftUI
#endif

// MARK: - Low-Cost Overlay Frame Renderer

/// Renders the smooth spatiotemporal forensic watermark into a tiny premultiplied RGBA `CGImage`
/// suitable for GPU bilinear scaling in a `sourceOver` composited player overlay.
public enum ForensicWatermarkRenderer {
    private static let sRGBColorSpace = CGColorSpace(name: CGColorSpace.sRGB) ?? CGColorSpaceCreateDeviceRGB()

    /// Renders a low-resolution (`gridWidth x gridHeight`) smooth premultiplied RGBA image for the given time.
    ///
    /// Because the watermark uses smooth low-frequency spatial patterns, a 32x24 texture scaled
    /// bilinearly by CoreAnimation/Metal produces a virtually exact continuous gradient at microsecond CPU cost.
    public static func makeOverlayCGImage(
        at timeSeconds: Double,
        chips: [Float],
        configuration: ForensicWatermarkConfiguration,
        gridWidth: Int = 32,
        gridHeight: Int = 24
    ) -> CGImage? {
        guard gridWidth > 0, gridHeight > 0, !chips.isEmpty else { return nil }
        let temporal = ForensicWatermarkSignal.temporalValue(
            at: timeSeconds,
            chips: chips,
            chipRateHz: configuration.chipRateHz
        )

        var bytes = [UInt8](repeating: 0, count: gridWidth * gridHeight * 4)
        let invW = 1.0 / Float(gridWidth)
        let invH = 1.0 / Float(gridHeight)

        for y in 0 ..< gridHeight {
            let v = (Float(y) + 0.5) * invH
            let rowBase = y * gridWidth * 4
            for x in 0 ..< gridWidth {
                let u = (Float(x) + 0.5) * invW
                let weight = ForensicWatermarkSignal.spatialWeight(
                    u: u,
                    v: v,
                    pattern: configuration.spatialPattern
                )
                let color = ForensicWatermarkSignal.overlayRGBA(
                    signal: weight * temporal,
                    configuration: configuration
                )
                let a = max(0, min(1, color.alpha))
                let pr = max(0, min(1, color.red * a))
                let pg = max(0, min(1, color.green * a))
                let pb = max(0, min(1, color.blue * a))

                let offset = rowBase + x * 4
                bytes[offset] = UInt8((pr * 255.0).rounded())
                bytes[offset + 1] = UInt8((pg * 255.0).rounded())
                bytes[offset + 2] = UInt8((pb * 255.0).rounded())
                bytes[offset + 3] = UInt8((a * 255.0).rounded())
            }
        }

        let data = Data(bytes)
        guard let provider = CGDataProvider(data: data as CFData) else { return nil }
        let bitmapInfo = CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue)
        return CGImage(
            width: gridWidth,
            height: gridHeight,
            bitsPerComponent: 8,
            bitsPerPixel: 32,
            bytesPerRow: gridWidth * 4,
            space: sRGBColorSpace,
            bitmapInfo: bitmapInfo,
            provider: provider,
            decode: nil,
            shouldInterpolate: true,
            intent: .defaultIntent
        )
    }

    /// Offline simulation helper that composites the watermark using exact `sourceOver` math onto a 32BGRA `CVPixelBuffer`.
    ///
    /// This helper is strictly for offline simulation and unit tests; live FairPlay playback renders
    /// only a semi-transparent overlay layer and never reads decrypted video frames.
    public static func compositeOverlay(
        ontoBGRA pixelBuffer: CVPixelBuffer,
        at timeSeconds: Double,
        chips: [Float],
        configuration: ForensicWatermarkConfiguration,
        targetRect: CGRect? = nil
    ) {
        guard CVPixelBufferGetPixelFormatType(pixelBuffer) == kCVPixelFormatType_32BGRA else { return }
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)
        guard width > 0, height > 0, !chips.isEmpty else { return }

        let fullRect = CGRect(x: 0, y: 0, width: width, height: height)
        let rect = (targetRect ?? fullRect).intersection(fullRect)
        guard !rect.isEmpty else { return }

        let minX = max(0, Int(floor(rect.minX)))
        let maxX = min(width, Int(ceil(rect.maxX)))
        let minY = max(0, Int(floor(rect.minY)))
        let maxY = min(height, Int(ceil(rect.maxY)))
        guard minX < maxX, minY < maxY else { return }

        let temporal = ForensicWatermarkSignal.temporalValue(
            at: timeSeconds,
            chips: chips,
            chipRateHz: configuration.chipRateHz
        )

        CVPixelBufferLockBaseAddress(pixelBuffer, [])
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }
        guard let baseAddress = CVPixelBufferGetBaseAddress(pixelBuffer) else { return }
        let bytesPerRow = CVPixelBufferGetBytesPerRow(pixelBuffer)
        let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)

        let rectW = Float(rect.width)
        let rectH = Float(rect.height)
        let rectMinX = Float(rect.minX)
        let rectMinY = Float(rect.minY)

        for y in minY ..< maxY {
            let v = (Float(y) + 0.5 - rectMinY) / rectH
            let rowPtr = ptr.advanced(by: y * bytesPerRow)
            for x in minX ..< maxX {
                let u = (Float(x) + 0.5 - rectMinX) / rectW
                let weight = ForensicWatermarkSignal.spatialWeight(
                    u: u,
                    v: v,
                    pattern: configuration.spatialPattern
                )
                let color = ForensicWatermarkSignal.overlayRGBA(
                    signal: weight * temporal,
                    configuration: configuration
                )
                let a = color.alpha
                let invA = 1.0 - a
                let offset = x * 4
                let dstB = Float(rowPtr[offset]) / 255.0
                let dstG = Float(rowPtr[offset + 1]) / 255.0
                let dstR = Float(rowPtr[offset + 2]) / 255.0

                let outB = max(0, min(1, invA * dstB + a * color.blue))
                let outG = max(0, min(1, invA * dstG + a * color.green))
                let outR = max(0, min(1, invA * dstR + a * color.red))

                rowPtr[offset] = UInt8((outB * 255.0).rounded())
                rowPtr[offset + 1] = UInt8((outG * 255.0).rounded())
                rowPtr[offset + 2] = UInt8((outR * 255.0).rounded())
            }
        }
    }
}

// MARK: - SwiftUI Player-Only Overlay

#if canImport(SwiftUI)

/// Reusable player-only forensic watermark overlay for FairPlay-protected TDF video.
///
/// Drop into SwiftUI's `VideoPlayer(player: player) { ForensicWatermarkOverlay(sessionID: ..., player: player) }`
/// or place in a `ZStack` directly over a video player view.
///
/// Design invariants:
/// - Never reads decrypted video frames or modifies the TDF archive, manifest, or FairPlay key session.
/// - Constrains rendering strictly to the aspect-fitted video picture rectangle (`ForensicWatermarkGeometry`)
///   and realigns automatically across rotations and aspect changes.
/// - Disables hit-testing (`allowsHitTesting(false)`) and accessibility so native player controls
///   remain completely unobstructed.
@available(iOS 18.0, macOS 15.0, tvOS 18.0, *)
public struct ForensicWatermarkOverlay: View {
    private let chips: [Float]
    private let configuration: ForensicWatermarkConfiguration
    private let videoGravity: WatermarkVideoGravity
    private let isEnabled: Bool
    private let player: AVPlayer?
    private let fixedPresentationSize: CGSize?
    private let frameIntervalSeconds: Double

    @State private var observedPresentationSize: CGSize = .zero
    @State private var anchorDate = Date()

    /// Creates an overlay synchronized to an `AVPlayer`'s displayed video bounds.
    ///
    /// - Parameters:
    ///   - sessionID: Opaque playback session identifier (not an account ID or PII). Pass `nil` for unmarked control playbacks.
    ///   - player: The `AVPlayer` presenting FairPlay-protected content (used only to observe `presentationSize`).
    ///   - configuration: Spatiotemporal modulation settings (defaults to `.default`).
    ///   - videoGravity: Player video gravity (defaults to `.resizeAspect`, matching `VideoPlayer`).
    ///   - isEnabled: Toggle for blinded marked vs. unmarked viewing comparisons.
    ///   - refreshRateHz: Overlay animation rate in Hz (default 30 Hz, smooth for 4 Hz chips).
    public init(
        sessionID: String?,
        player: AVPlayer,
        configuration: ForensicWatermarkConfiguration = .default,
        videoGravity: WatermarkVideoGravity = .resizeAspect,
        isEnabled: Bool = true,
        refreshRateHz: Double = 30.0
    ) {
        if let sessionID,
           let validated = try? WatermarkSessionCode(sessionID),
           (try? configuration.validate()) != nil
        {
            self.chips = ForensicWatermarkSignal.chips(for: validated.rawValue, configuration: configuration)
        } else {
            self.chips = []
        }
        self.configuration = configuration
        self.videoGravity = videoGravity
        self.isEnabled = isEnabled
        self.player = player
        self.fixedPresentationSize = nil
        self.frameIntervalSeconds = 1.0 / max(10.0, min(60.0, refreshRateHz))
    }

    /// Creates an overlay bound to an explicit video `presentationSize` (useful for tests or custom layers).
    public init(
        sessionID: String?,
        presentationSize: CGSize,
        configuration: ForensicWatermarkConfiguration = .default,
        videoGravity: WatermarkVideoGravity = .resizeAspect,
        isEnabled: Bool = true,
        refreshRateHz: Double = 30.0
    ) {
        if let sessionID,
           let validated = try? WatermarkSessionCode(sessionID),
           (try? configuration.validate()) != nil
        {
            self.chips = ForensicWatermarkSignal.chips(for: validated.rawValue, configuration: configuration)
        } else {
            self.chips = []
        }
        self.configuration = configuration
        self.videoGravity = videoGravity
        self.isEnabled = isEnabled
        self.player = nil
        self.fixedPresentationSize = presentationSize
        self.frameIntervalSeconds = 1.0 / max(10.0, min(60.0, refreshRateHz))
    }

    private var activePresentationSize: CGSize {
        fixedPresentationSize ?? observedPresentationSize
    }

    public var body: some View {
        Group {
            if isEnabled, !chips.isEmpty {
                GeometryReader { proxy in
                    let containerBounds = CGRect(origin: .zero, size: proxy.size)
                    let pictureRect = ForensicWatermarkGeometry.videoRect(
                        forPresentationSize: activePresentationSize,
                        in: containerBounds,
                        gravity: videoGravity
                    )

                    TimelineView(.animation(minimumInterval: frameIntervalSeconds, paused: !isEnabled)) { timeline in
                        let elapsed = max(0, timeline.date.timeIntervalSince(anchorDate))
                        Canvas(opaque: false, colorMode: .nonLinear, rendersAsynchronously: false) { context, _ in
                            guard pictureRect.width > 0, pictureRect.height > 0,
                                  let cgImage = ForensicWatermarkRenderer.makeOverlayCGImage(
                                      at: elapsed,
                                      chips: chips,
                                      configuration: configuration
                                  )
                            else {
                                return
                            }
                            context.draw(Image(decorative: cgImage, scale: 1.0), in: pictureRect)
                        }
                    }
                }
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
        .onAppear {
            anchorDate = Date()
            if let size = player?.currentItem?.presentationSize {
                observedPresentationSize = size
            }
        }
        .task(id: player.map(ObjectIdentifier.init)) {
            guard let player else { return }
            await observePresentationSize(for: player)
        }
    }

    @MainActor
    private func observePresentationSize(for player: AVPlayer) async {
        observedPresentationSize = player.currentItem?.presentationSize ?? .zero
        for await size in player.publisher(for: \.currentItem?.presentationSize).values {
            observedPresentationSize = size ?? .zero
        }
    }
}

#endif

// MARK: - CoreAnimation Layer Helper (UIKit / AppKit / AVPlayerViewController)

#if canImport(QuartzCore)

/// `CALayer` helper for hosting the player-only forensic watermark inside `AVPlayerViewController.contentOverlayView`
/// or alongside an `AVPlayerLayer` without SwiftUI.
///
/// The caller updates `videoRect` whenever the player view rotates or `videoBounds` changes,
/// and invokes `update(at:)` from a display link or timer.
@MainActor
public final class ForensicWatermarkLayer: CALayer {
    private var chips: [Float] = []
    private var configuration: ForensicWatermarkConfiguration = .default
    private var startMediaTime: CFTimeInterval = CACurrentMediaTime()

    /// Whether the overlay renders watermark frames. Set `false` for unmarked control sessions.
    public var isWatermarkEnabled: Bool = true {
        didSet {
            if !isWatermarkEnabled {
                contents = nil
            }
        }
    }

    override public init() {
        super.init()
        configureLayer()
    }

    override public init(layer: Any) {
        super.init(layer: layer)
        configureLayer()
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    private nonisolated func configureLayer() {
        isOpaque = false
        magnificationFilter = .linear
        minificationFilter = .linear
        contentsGravity = .resize
        actions = [
            "contents": NSNull(),
            "bounds": NSNull(),
            "position": NSNull(),
            "frame": NSNull(),
        ]
    }

    /// Configures the layer with an opaque session identifier and watermark parameters.
    public func configure(
        sessionID: String,
        configuration: ForensicWatermarkConfiguration = .default,
        startMediaTime: CFTimeInterval = CACurrentMediaTime()
    ) throws {
        let validatedCode = try WatermarkSessionCode(sessionID)
        try configuration.validate()
        self.chips = ForensicWatermarkSignal.chips(for: validatedCode.rawValue, configuration: configuration)
        self.configuration = configuration
        self.startMediaTime = startMediaTime
    }

    /// Updates layer geometry to match the displayed video picture area after layout or rotation.
    public func align(
        forPresentationSize presentationSize: CGSize,
        in containerBounds: CGRect,
        gravity: WatermarkVideoGravity = .resizeAspect
    ) {
        frame = ForensicWatermarkGeometry.videoRect(
            forPresentationSize: presentationSize,
            in: containerBounds,
            gravity: gravity
        )
    }

    /// Renders the watermark frame corresponding to `mediaTime` (e.g., `CADisplayLink.timestamp`).
    public func update(at mediaTime: CFTimeInterval = CACurrentMediaTime()) {
        guard isWatermarkEnabled, !chips.isEmpty else {
            contents = nil
            return
        }
        let elapsed = max(0, mediaTime - startMediaTime)
        contents = ForensicWatermarkRenderer.makeOverlayCGImage(
            at: elapsed,
            chips: chips,
            configuration: configuration
        )
    }
}

#endif
