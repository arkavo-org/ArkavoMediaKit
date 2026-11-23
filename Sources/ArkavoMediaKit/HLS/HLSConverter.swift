import AVFoundation
import Foundation

/// Result of HLS conversion
public struct HLSConversionResult: Sendable {
    /// URL to the master playlist (m3u8)
    public let playlistURL: URL
    /// URLs to individual segment files
    public let segmentURLs: [URL]
    /// Duration of each segment in seconds
    public let segmentDurations: [Double]
    /// Total duration of the video in seconds
    public let totalDuration: Double

    public init(
        playlistURL: URL,
        segmentURLs: [URL],
        segmentDurations: [Double],
        totalDuration: Double
    ) {
        self.playlistURL = playlistURL
        self.segmentURLs = segmentURLs
        self.segmentDurations = segmentDurations
        self.totalDuration = totalDuration
    }
}

/// Converts video files to HLS format
///
/// Uses AVAssetExportSession to create HLS segments from video files.
/// The output includes an m3u8 playlist and .ts segment files.
public actor HLSConverter {

    /// Default segment duration in seconds
    public static let defaultSegmentDuration: TimeInterval = 6.0

    public init() {}

    /// Convert a video file to HLS format
    ///
    /// - Parameters:
    ///   - videoURL: URL to the source video file
    ///   - outputDirectory: Directory to write HLS files
    ///   - segmentDuration: Target duration for each segment (default: 6 seconds)
    /// - Returns: HLSConversionResult with playlist and segment information
    /// - Throws: HLSConversionError if conversion fails
    public func convert(
        videoURL: URL,
        outputDirectory: URL,
        segmentDuration: TimeInterval = defaultSegmentDuration
    ) async throws -> HLSConversionResult {
        // Note: Double(Int.max) rounds up to 2^63 on 64-bit platforms, so cap strictly below Int.max
        let maxSafeTargetDuration = Double(Int.max / 2)
        guard segmentDuration.isFinite, segmentDuration > 0, ceil(segmentDuration) <= maxSafeTargetDuration else {
            throw HLSConversionError.invalidSourceVideo("Segment duration must be a finite positive number within valid bounds")
        }

        // Create output directory if needed
        try FileManager.default.createDirectory(
            at: outputDirectory,
            withIntermediateDirectories: true
        )

        // Load the asset
        let asset = AVURLAsset(url: videoURL)

        // Get duration
        let duration = try await asset.load(.duration)
        let totalDuration = CMTimeGetSeconds(duration)

        guard duration.isNumeric, totalDuration.isFinite, totalDuration > 0 else {
            throw HLSConversionError.invalidSourceVideo("Video has invalid or indefinite duration")
        }

        // Use manual segmentation for HLS output
        // AVAssetExportSession doesn't directly support HLS output on all platforms,
        // so we create segments manually for better control.
        return try await convertWithManualSegmentation(
            videoURL: videoURL,
            outputDirectory: outputDirectory,
            segmentDuration: segmentDuration
        )
    }

    /// Convert video to HLS using manual segmentation
    ///
    /// This method creates segments manually when AVAssetExportSession
    /// doesn't produce proper HLS output. It exports the video first,
    /// then segments it using AVAssetReader/Writer.
    ///
    /// - Parameters:
    ///   - videoURL: URL to the source video file
    ///   - outputDirectory: Directory to write HLS files
    ///   - segmentDuration: Target duration for each segment
    /// - Returns: HLSConversionResult with playlist and segment information
    public func convertWithManualSegmentation(
        videoURL: URL,
        outputDirectory: URL,
        segmentDuration: TimeInterval = defaultSegmentDuration
    ) async throws -> HLSConversionResult {
        // Note: Double(Int.max) rounds up to 2^63 on 64-bit platforms, so cap strictly below Int.max
        let maxSafeTargetDuration = Double(Int.max / 2)
        guard segmentDuration.isFinite, segmentDuration > 0, ceil(segmentDuration) <= maxSafeTargetDuration else {
            throw HLSConversionError.invalidSourceVideo("Segment duration must be a finite positive number within valid bounds")
        }

        // Create output directory if needed
        try FileManager.default.createDirectory(
            at: outputDirectory,
            withIntermediateDirectories: true
        )

        // Load the asset
        let asset = AVURLAsset(url: videoURL)
        let duration = try await asset.load(.duration)
        let totalDuration = CMTimeGetSeconds(duration)

        guard duration.isNumeric, totalDuration.isFinite, totalDuration > 0 else {
            throw HLSConversionError.invalidSourceVideo("Video has invalid or indefinite duration")
        }

        // Calculate segment count safely without float-to-Int traps
        let rawSegmentCount = ceil(totalDuration / segmentDuration)
        guard rawSegmentCount.isFinite, rawSegmentCount >= 1, rawSegmentCount <= 100_000 else {
            throw HLSConversionError.invalidSourceVideo("Computed segment count is out of valid bounds")
        }
        let segmentCount = Int(rawSegmentCount)
        let rawTargetDuration = ceil(segmentDuration)
        guard rawTargetDuration.isFinite, rawTargetDuration >= 1, rawTargetDuration <= maxSafeTargetDuration else {
            throw HLSConversionError.invalidSourceVideo("Target segment duration is out of valid bounds")
        }
        let targetDuration = Int(rawTargetDuration)
        var segmentURLs: [URL] = []
        var segmentDurations: [Double] = []

        for i in 0..<segmentCount {
            let startTime = CMTime(seconds: Double(i) * segmentDuration, preferredTimescale: 600)
            let endSeconds = min(Double(i + 1) * segmentDuration, totalDuration)
            let endTime = CMTime(seconds: endSeconds, preferredTimescale: 600)
            let segmentActualDuration = endSeconds - (Double(i) * segmentDuration)

            let segmentURL = outputDirectory.appendingPathComponent("segment_\(i).mov")

            try await exportSegment(
                from: asset,
                startTime: startTime,
                endTime: endTime,
                outputURL: segmentURL
            )

            segmentURLs.append(segmentURL)
            segmentDurations.append(segmentActualDuration)
        }

        // Generate m3u8 playlist
        let playlistURL = outputDirectory.appendingPathComponent("playlist.m3u8")
        try generatePlaylist(
            playlistURL: playlistURL,
            segmentURLs: segmentURLs,
            segmentDurations: segmentDurations,
            targetDuration: targetDuration
        )

        return HLSConversionResult(
            playlistURL: playlistURL,
            segmentURLs: segmentURLs,
            segmentDurations: segmentDurations,
            totalDuration: totalDuration
        )
    }

    // MARK: - Private Helpers

    private func exportSegment(
        from asset: AVAsset,
        startTime: CMTime,
        endTime: CMTime,
        outputURL: URL
    ) async throws {
        // Remove existing file if present
        try? FileManager.default.removeItem(at: outputURL)

        guard let exportSession = AVAssetExportSession(
            asset: asset,
            presetName: AVAssetExportPresetPassthrough
        ) else {
            throw HLSConversionError.exportSessionCreationFailed
        }

        // Use .mov as intermediate format, we'll read segments as raw data
        exportSession.timeRange = CMTimeRange(start: startTime, end: endTime)

        // Export to output URL using new async API
        do {
            try await exportSession.export(to: outputURL, as: .mov)
        } catch {
            throw HLSConversionError.segmentExportFailed(
                segment: outputURL.lastPathComponent,
                reason: error.localizedDescription
            )
        }
    }

    private func generatePlaylist(
        playlistURL: URL,
        segmentURLs: [URL],
        segmentDurations: [Double],
        targetDuration: Int
    ) throws {
        var content = "#EXTM3U\n"
        content += "#EXT-X-VERSION:3\n"
        content += "#EXT-X-TARGETDURATION:\(targetDuration)\n"
        content += "#EXT-X-MEDIA-SEQUENCE:0\n"

        for (index, url) in segmentURLs.enumerated() {
            let duration = segmentDurations[index]
            content += "#EXTINF:\(String(format: "%.3f", duration)),\n"
            content += "\(url.lastPathComponent)\n"
        }

        content += "#EXT-X-ENDLIST\n"

        try content.write(to: playlistURL, atomically: true, encoding: .utf8)
    }
}

/// Errors that can occur during HLS conversion
public enum HLSConversionError: Error, LocalizedError {
    case invalidSourceVideo(String)
    case exportSessionCreationFailed
    case exportFailed(String)
    case exportCancelled
    case segmentExportFailed(segment: String, reason: String)
    case playlistParsingFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidSourceVideo(reason):
            "Invalid source video: \(reason)"
        case .exportSessionCreationFailed:
            "Failed to create export session"
        case let .exportFailed(reason):
            "HLS export failed: \(reason)"
        case .exportCancelled:
            "HLS export was cancelled"
        case let .segmentExportFailed(segment, reason):
            "Failed to export segment \(segment): \(reason)"
        case let .playlistParsingFailed(reason):
            "Failed to parse playlist: \(reason)"
        }
    }
}
