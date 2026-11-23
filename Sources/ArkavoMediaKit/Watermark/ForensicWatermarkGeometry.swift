import AVFoundation
import CoreGraphics
import Foundation

/// How the player maps a video's presentation dimensions into its view bounds.
public enum WatermarkVideoGravity: String, Sendable, Equatable, Hashable, Codable {
    /// Preserves aspect ratio and fits inside the container (letterboxing/pillarboxing as needed).
    /// Matches `AVLayerVideoGravity.resizeAspect` and SwiftUI `VideoPlayer` default.
    case resizeAspect

    /// Preserves aspect ratio and fills the container, cropping overflow.
    /// Matches `AVLayerVideoGravity.resizeAspectFill`.
    case resizeAspectFill

    /// Stretches to fill the container bounds.
    /// Matches `AVLayerVideoGravity.resize`.
    case resize

    /// Converts from `AVLayerVideoGravity`.
    public init(avGravity: AVLayerVideoGravity) {
        switch avGravity {
        case .resizeAspectFill:
            self = .resizeAspectFill
        case .resize:
            self = .resize
        default:
            self = .resizeAspect
        }
    }
}

/// Pure geometry helpers for constraining the forensic watermark overlay to the displayed video bounds.
///
/// Ensures the overlay stays aligned to the active picture area across device rotations,
/// portrait/landscape tracks, and aspect-fit letterboxing without covering black bars.
public enum ForensicWatermarkGeometry {
    /// Computes the displayed picture rectangle for a video of `presentationSize` inside `containerBounds`.
    ///
    /// Returns `.zero` until both `containerBounds` and `presentationSize` have positive finite dimensions
    /// so the overlay never paints over letterbox/pillarbox bars while a FairPlay item is still loading.
    ///
    /// - Parameters:
    ///   - presentationSize: The `AVPlayerItem.presentationSize` (which already accounts for track `preferredTransform`).
    ///   - containerBounds: The coordinate space of the player container view.
    ///   - gravity: Video gravity mode (defaults to `.resizeAspect`).
    /// - Returns: The sub-rectangle within `containerBounds` occupied by the rendered video picture, or `.zero` if unknown.
    public static func videoRect(
        forPresentationSize presentationSize: CGSize,
        in containerBounds: CGRect,
        gravity: WatermarkVideoGravity = .resizeAspect
    ) -> CGRect {
        guard containerBounds.width.isFinite, containerBounds.height.isFinite,
              containerBounds.width > 0, containerBounds.height > 0,
              presentationSize.width.isFinite, presentationSize.height.isFinite,
              presentationSize.width > 0, presentationSize.height > 0
        else {
            return .zero
        }

        switch gravity {
        case .resize:
            return containerBounds

        case .resizeAspect:
            let videoAspect = presentationSize.width / presentationSize.height
            let containerAspect = containerBounds.width / containerBounds.height

            let fittedWidth: CGFloat
            let fittedHeight: CGFloat
            if videoAspect > containerAspect {
                fittedWidth = containerBounds.width
                fittedHeight = containerBounds.width / videoAspect
            } else {
                fittedHeight = containerBounds.height
                fittedWidth = containerBounds.height * videoAspect
            }

            let originX = containerBounds.minX + (containerBounds.width - fittedWidth) * 0.5
            let originY = containerBounds.minY + (containerBounds.height - fittedHeight) * 0.5
            return CGRect(x: originX, y: originY, width: fittedWidth, height: fittedHeight)

        case .resizeAspectFill:
            // Picture fills the entire visible container bounds (cropped outside container).
            return containerBounds
        }
    }
}
