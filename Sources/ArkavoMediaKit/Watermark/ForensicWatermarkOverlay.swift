import AVFoundation
import CoreGraphics
import CoreVideo
import Foundation
import Synchronization

#if canImport(QuartzCore)
import QuartzCore
#endif

#if canImport(SwiftUI)
import SwiftUI
#endif

// MARK: - Player Output Policy Helper

/// Helper for configuring an `AVPlayer` so FairPlay playback cannot bypass the local watermark overlay
/// via AirPlay external playback during watermarked sessions.
public enum ForensicWatermarkPlayerPolicy {
    /// Disables external playback (AirPlay video routing) while a local player-only watermark session is active.
    ///
    /// Note: Picture-in-Picture (`AVPlayerViewController.allowsPictureInPicturePlayback`) must also be
    /// disabled on the host `AVPlayerViewController` (or handled via PiP window attachment) when enforcing
    /// player-only overlays.
    @MainActor
    public static func configureForWatermarkedPlayback(_ player: AVPlayer) {
        player.allowsExternalPlayback = false
    }
}

// MARK: - High-Precision 16-Bit Overlay Frame Renderer

/// Renders the smooth spatiotemporal forensic watermark into a tiny 16-bit premultiplied RGBA `CGImage`
/// suitable for GPU bilinear scaling in a `sourceOver` composited player overlay.
///
/// Using 16 bits per component (`UInt16`, 65,535 levels) preserves exact isoluminant R/G/B pole ratios
/// even at subtle opacities (`0.015`–`0.025`), avoiding the 8-bit premultiplied quantization collapse
/// that would otherwise erase the yellow luminance compensator.
public enum ForensicWatermarkRenderer {
    private static let sRGBColorSpace = CGColorSpace(name: CGColorSpace.sRGB) ?? CGColorSpaceCreateDeviceRGB()

    /// Renders a low-resolution (`gridWidth x gridHeight`) 16-bit premultiplied RGBA image for `timeSeconds`.
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

        var components = [UInt16](repeating: 0, count: gridWidth * gridHeight * 4)
        let invW = 1.0 / Float(gridWidth)
        let invH = 1.0 / Float(gridHeight)
        let scale16: Float = 65535.0

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
                components[offset] = UInt16((pr * scale16).rounded()).littleEndian
                components[offset + 1] = UInt16((pg * scale16).rounded()).littleEndian
                components[offset + 2] = UInt16((pb * scale16).rounded()).littleEndian
                components[offset + 3] = UInt16((a * scale16).rounded()).littleEndian
            }
        }

        let byteCount = components.count * MemoryLayout<UInt16>.size
        let data = components.withUnsafeBytes { Data($0) }
        guard data.count == byteCount,
              let provider = CGDataProvider(data: data as CFData)
        else { return nil }

        let bitmapInfo = CGBitmapInfo(
            rawValue: CGImageAlphaInfo.premultipliedLast.rawValue | CGBitmapInfo.byteOrder16Little.rawValue
        )
        return CGImage(
            width: gridWidth,
            height: gridHeight,
            bitsPerComponent: 16,
            bitsPerPixel: 64,
            bytesPerRow: gridWidth * 8,
            space: sRGBColorSpace,
            bitmapInfo: bitmapInfo,
            provider: provider,
            decode: nil,
            shouldInterpolate: true,
            intent: .defaultIntent
        )
    }

    /// Offline simulation helper that composites an actual `makeOverlayCGImage` texture using CoreGraphics
    /// `sourceOver` bilinear drawing onto a 32BGRA `CVPixelBuffer`.
    ///
    /// Strictly for offline simulation and tests so benchmarks exercise the exact same 16-bit texture
    /// pipeline used by live playback; live playback never reads decrypted FairPlay frames.
    public static func compositeOverlayImage(
        _ overlayImage: CGImage,
        ontoBGRA pixelBuffer: CVPixelBuffer,
        in targetRect: CGRect? = nil
    ) {
        guard CVPixelBufferGetPixelFormatType(pixelBuffer) == kCVPixelFormatType_32BGRA else { return }
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)
        guard width > 0, height > 0 else { return }

        CVPixelBufferLockBaseAddress(pixelBuffer, [])
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }
        guard let baseAddress = CVPixelBufferGetBaseAddress(pixelBuffer) else { return }

        let bytesPerRow = CVPixelBufferGetBytesPerRow(pixelBuffer)
        let bitmapInfo = CGBitmapInfo(
            rawValue: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue
        )
        guard let context = CGContext(
            data: baseAddress,
            width: width,
            height: height,
            bitsPerComponent: 8,
            bytesPerRow: bytesPerRow,
            space: sRGBColorSpace,
            bitmapInfo: bitmapInfo.rawValue
        ) else {
            return
        }

        // Flip to top-left origin so image row 0 aligns with pixelBuffer row 0.
        context.translateBy(x: 0, y: CGFloat(height))
        context.scaleBy(x: 1, y: -1)
        context.interpolationQuality = .medium
        context.setBlendMode(.normal)
        let drawRect = targetRect ?? CGRect(x: 0, y: 0, width: width, height: height)
        context.draw(overlayImage, in: drawRect)
    }
}

// MARK: - SwiftUI Player-Only Overlay

#if canImport(SwiftUI)

/// Reusable player-only forensic watermark overlay for FairPlay-protected TDF video.
///
/// Drop into SwiftUI's `VideoPlayer(player: player) { try? ForensicWatermarkOverlay(sessionID: ..., player: player) }`
/// or place in a `ZStack` directly over a video player view.
///
/// Design invariants:
/// - Never reads decrypted video frames or modifies the TDF archive, manifest, or FairPlay key session.
/// - Constrains rendering strictly to the displayed picture rectangle (`videoBounds` if provided by the host,
///   otherwise `ForensicWatermarkGeometry.videoRect` over an edge-to-edge `.ignoresSafeArea()` geometry).
/// - Renders nothing while `presentationSize` is unknown (`.zero`), preventing letterbox spillover.
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
    private let explicitVideoBounds: CGRect?
    private let frameIntervalSeconds: Double

    @State private var observedPresentationSize: CGSize = .zero
    @State private var anchorDate = Date()

    /// Creates a validated overlay synchronized to an `AVPlayer`'s displayed video bounds.
    ///
    /// Pass `sessionID: nil` explicitly for unmarked control playbacks. Passing a non-nil malformed
    /// `sessionID`, an invalid `configuration`, or a `refreshRateHz` below `3 * chipRateHz` throws
    /// instead of silently degrading to unmarked playback.
    public init(
        sessionID: String?,
        player: AVPlayer,
        configuration: ForensicWatermarkConfiguration = .default,
        videoGravity: WatermarkVideoGravity = .resizeAspect,
        explicitVideoBounds: CGRect? = nil,
        isEnabled: Bool = true,
        refreshRateHz: Double = 30.0
    ) throws {
        try configuration.validate()
        let minRefresh = max(10.0, configuration.chipRateHz * 3.0)
        guard refreshRateHz.isFinite, refreshRateHz >= minRefresh, refreshRateHz <= 120.0 else {
            throw ForensicWatermarkError.invalidConfiguration(
                "refreshRateHz must be in [\(minRefresh), 120.0] for chipRateHz=\(configuration.chipRateHz)"
            )
        }
        if let sessionID {
            let code = try WatermarkSessionCode(sessionID)
            self.chips = ForensicWatermarkSignal.chips(for: code.rawValue, configuration: configuration)
        } else {
            self.chips = []
        }
        self.configuration = configuration
        self.videoGravity = videoGravity
        self.isEnabled = isEnabled
        self.player = player
        self.fixedPresentationSize = nil
        self.explicitVideoBounds = explicitVideoBounds
        self.frameIntervalSeconds = 1.0 / refreshRateHz
    }

    /// Creates a validated overlay using a pre-validated `WatermarkSessionCode`.
    public init(
        sessionCode: WatermarkSessionCode?,
        player: AVPlayer,
        configuration: ForensicWatermarkConfiguration = .default,
        videoGravity: WatermarkVideoGravity = .resizeAspect,
        explicitVideoBounds: CGRect? = nil,
        isEnabled: Bool = true,
        refreshRateHz: Double = 30.0
    ) throws {
        try self.init(
            sessionID: sessionCode?.rawValue,
            player: player,
            configuration: configuration,
            videoGravity: videoGravity,
            explicitVideoBounds: explicitVideoBounds,
            isEnabled: isEnabled,
            refreshRateHz: refreshRateHz
        )
    }

    /// Creates a validated overlay bound to an explicit video `presentationSize` (useful for tests or custom layers).
    public init(
        sessionID: String?,
        presentationSize: CGSize,
        configuration: ForensicWatermarkConfiguration = .default,
        videoGravity: WatermarkVideoGravity = .resizeAspect,
        explicitVideoBounds: CGRect? = nil,
        isEnabled: Bool = true,
        refreshRateHz: Double = 30.0
    ) throws {
        try configuration.validate()
        let minRefresh = max(10.0, configuration.chipRateHz * 3.0)
        guard refreshRateHz.isFinite, refreshRateHz >= minRefresh, refreshRateHz <= 120.0 else {
            throw ForensicWatermarkError.invalidConfiguration(
                "refreshRateHz must be in [\(minRefresh), 120.0] for chipRateHz=\(configuration.chipRateHz)"
            )
        }
        if let sessionID {
            let code = try WatermarkSessionCode(sessionID)
            self.chips = ForensicWatermarkSignal.chips(for: code.rawValue, configuration: configuration)
        } else {
            self.chips = []
        }
        self.configuration = configuration
        self.videoGravity = videoGravity
        self.isEnabled = isEnabled
        self.player = nil
        self.fixedPresentationSize = presentationSize
        self.explicitVideoBounds = explicitVideoBounds
        self.frameIntervalSeconds = 1.0 / refreshRateHz
    }

    private var activePresentationSize: CGSize {
        fixedPresentationSize ?? observedPresentationSize
    }

    public var body: some View {
        Group {
            if isEnabled, !chips.isEmpty {
                GeometryReader { proxy in
                    let containerBounds = CGRect(origin: .zero, size: proxy.size)
                    let pictureRect: CGRect = if let explicitVideoBounds,
                                                 explicitVideoBounds.width > 0,
                                                 explicitVideoBounds.height > 0
                    {
                        explicitVideoBounds
                    } else {
                        ForensicWatermarkGeometry.videoRect(
                            forPresentationSize: activePresentationSize,
                            in: containerBounds,
                            gravity: videoGravity
                        )
                    }

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
                .ignoresSafeArea()
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
        .task(id: player.map(ObjectIdentifier.init)) {
            guard let player else { return }
            await observePresentationSize(for: player)
        }
    }

    @MainActor
    private func observePresentationSize(for player: AVPlayer) async {
        for await size in Self.presentationSizeStream(for: player) {
            observedPresentationSize = size
        }
    }

    /// Buffered KVO stream (`bufferingNewest(1)`) so rapid `presentationSize` updates are never dropped.
    private static func presentationSizeStream(for player: AVPlayer) -> AsyncStream<CGSize> {
        AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let observation = player.observe(\.currentItem?.presentationSize, options: [.initial, .new]) { player, _ in
                continuation.yield(player.currentItem?.presentationSize ?? .zero)
            }
            continuation.onTermination = { _ in
                observation.invalidate()
            }
        }
    }
}

#endif

// MARK: - CoreAnimation Layer Helper (UIKit / AppKit / AVPlayerViewController)

#if canImport(QuartzCore)

/// `CALayer` helper for hosting the player-only forensic watermark inside `AVPlayerViewController.contentOverlayView`
/// or alongside an `AVPlayerLayer` without SwiftUI.
///
/// Intentionally non-`@MainActor` at the class level so Core Animation's off-main-thread presentation copy
/// (`init(layer:)`) never violates Swift 6 executor isolation. Mutable watermark state is synchronized via `Mutex`
/// and copied across presentation layers; UI/layout calls (`configure`, `align`, `align(toVideoRect:)`, `update`)
/// run on `@MainActor`.
public final class ForensicWatermarkLayer: CALayer, @unchecked Sendable {
    private struct WatermarkState: Sendable {
        var chips: [Float] = []
        var configuration: ForensicWatermarkConfiguration = .default
        var startMediaTime: CFTimeInterval = CACurrentMediaTime()
        var isWatermarkEnabled: Bool = true
    }

    private let state = Mutex(WatermarkState())

    /// Whether the overlay renders watermark frames. Set `false` for unmarked control sessions.
    @MainActor
    public var isWatermarkEnabled: Bool {
        get { state.withLock { $0.isWatermarkEnabled } }
        set {
            state.withLock { $0.isWatermarkEnabled = newValue }
            if !newValue {
                contents = nil
            }
        }
    }

    override public init() {
        super.init()
        configureInitialLayerProperties()
    }

    override public init(layer: Any) {
        super.init(layer: layer)
        if let source = layer as? ForensicWatermarkLayer {
            let snapshot = source.state.withLock { $0 }
            state.withLock { $0 = snapshot }
        }
        configureInitialLayerProperties()
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    private func configureInitialLayerProperties() {
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
    @MainActor
    public func configure(
        sessionID: String,
        configuration: ForensicWatermarkConfiguration = .default,
        startMediaTime: CFTimeInterval = CACurrentMediaTime()
    ) throws {
        let validatedCode = try WatermarkSessionCode(sessionID)
        try configuration.validate()
        let chips = ForensicWatermarkSignal.chips(for: validatedCode.rawValue, configuration: configuration)
        state.withLock { s in
            s.chips = chips
            s.configuration = configuration
            s.startMediaTime = startMediaTime
        }
    }

    /// Updates layer geometry directly from `AVPlayerLayer.videoRect` or `AVPlayerViewController.videoBounds`.
    @MainActor
    public func align(toVideoRect videoRect: CGRect) {
        guard videoRect.width.isFinite, videoRect.height.isFinite,
              videoRect.width > 0, videoRect.height > 0
        else {
            frame = .zero
            return
        }
        frame = videoRect
    }

    /// Updates layer geometry to match the displayed video picture area after layout or rotation.
    @MainActor
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
    @MainActor
    public func update(at mediaTime: CFTimeInterval = CACurrentMediaTime()) {
        let snapshot = state.withLock { $0 }
        guard snapshot.isWatermarkEnabled, !snapshot.chips.isEmpty, frame.width > 0, frame.height > 0 else {
            contents = nil
            return
        }
        let elapsed = max(0, mediaTime - snapshot.startMediaTime)
        contents = ForensicWatermarkRenderer.makeOverlayCGImage(
            at: elapsed,
            chips: snapshot.chips,
            configuration: snapshot.configuration
        )
    }
}

#endif
