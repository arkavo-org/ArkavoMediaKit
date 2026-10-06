import Foundation
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

/// Every media segment opens on a sync sample, as the playlist's
/// `#EXT-X-INDEPENDENT-SEGMENTS` promises, and the target duration covers the
/// longest segment.
@Suite("fMP4 segmentation")
struct FMP4SegmentationTests {
    private static func samples(count: Int, syncEvery gop: Int) -> [FMP4RecordingProtectionService.SegmentSample] {
        (0 ..< count).map { .init(duration: 1, isSync: $0 % gop == 0) }
    }

    @Test("cuts wait for the next sync sample once the target has accumulated")
    func cutsAtSyncSamples() {
        // 30 fps timescale, 6 s target, keyframe every 50 frames.
        let ranges = FMP4RecordingProtectionService.segmentRanges(
            for: Self.samples(count: 400, syncEvery: 50), targetDuration: 180)
        #expect(ranges == [0 ..< 200, 200 ..< 400])
    }

    @Test("all-sync sources cut exactly at the target")
    func allSyncCutsAtTarget() {
        let ranges = FMP4RecordingProtectionService.segmentRanges(
            for: Self.samples(count: 400, syncEvery: 1), targetDuration: 180)
        #expect(ranges == [0 ..< 180, 180 ..< 360, 360 ..< 400])
    }

    @Test("with no later sync sample everything stays in one segment")
    func noLaterSyncSample() {
        let ranges = FMP4RecordingProtectionService.segmentRanges(
            for: Self.samples(count: 400, syncEvery: 1000), targetDuration: 180)
        #expect(ranges == [0 ..< 400])
    }

    @Test("no samples, no segments")
    func empty() {
        #expect(FMP4RecordingProtectionService.segmentRanges(for: [], targetDuration: 180).isEmpty)
    }

    @Test("protected segments each open on a sync sample, within the target duration")
    func archiveSegmentsAreIndependent() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-gop-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        // 13.3 s with a keyframe at most every 50 frames, which does not divide 6 s.
        let movie = try await SyntheticMovie.make(in: dir, frames: 400, keyFrameInterval: 50)
        let kas = try TestKASKeyPair()
        let service = FMP4RecordingProtectionService(
            kasURL: URL(string: "https://platform.arkavo.net")!, kasPublicKeyPEM: kas.spkiPublicKeyPEM)
        let archive = try await service.protectVideo(videoURL: movie, assetID: "gop")

        let zip = try Archive(data: archive, accessMode: .read)
        var files: [String: Data] = [:]
        for entry in zip {
            var data = Data()
            _ = try zip.extract(entry) { data.append($0) }
            files[entry.path] = data
        }
        let playlist = String(decoding: try #require(files["playlist.m3u8"]), as: UTF8.self)
        let lines = playlist.components(separatedBy: .newlines)
        let target = try #require(lines.lazy.compactMap { line in
            line.hasPrefix("#EXT-X-TARGETDURATION:") ? Int(line.dropFirst("#EXT-X-TARGETDURATION:".count)) : nil
        }.first)
        let durations = lines.compactMap { line -> Double? in
            guard line.hasPrefix("#EXTINF:") else { return nil }
            return Double(line.dropFirst("#EXTINF:".count).prefix { $0 != "," })
        }
        let segmentNames = lines.filter { $0.hasSuffix(".m4s") }
        #expect(segmentNames.count >= 2, "the source must span more than one segment")
        #expect(durations.allSatisfy { $0 <= Double(target) }, "EXTINF \(durations) exceeds target \(target)")
        for name in segmentNames {
            let segment = try #require(files[name])
            let flags = try #require(Self.firstSampleFlags(inSegment: segment))
            #expect(flags & 0x0001_0000 == 0, "\(name) opens on a non-sync sample (flags \(String(flags, radix: 16)))")
        }
    }

    /// The first sample's flags from a media segment's `trun` box.
    private static func firstSampleFlags(inSegment data: Data) -> UInt32? {
        let bytes = [UInt8](data)
        guard let typeIndex = bytes.indices.dropLast(3).first(where: {
            bytes[$0] == 0x74 && bytes[$0 + 1] == 0x72 && bytes[$0 + 2] == 0x75 && bytes[$0 + 3] == 0x6E // "trun"
        }) else { return nil }
        func u32(_ i: Int) -> UInt32 {
            bytes[i ..< i + 4].reduce(0) { $0 << 8 | UInt32($1) }
        }
        let flags = u32(typeIndex + 4) & 0x00FF_FFFF
        var cursor = typeIndex + 12 // version/flags, sample_count
        if flags & 0x000001 != 0 { cursor += 4 } // data_offset
        if flags & 0x000004 != 0 { return u32(cursor) } // first_sample_flags
        if flags & 0x000100 != 0 { cursor += 4 } // sample_duration
        if flags & 0x000200 != 0 { cursor += 4 } // sample_size
        guard flags & 0x000400 != 0 else { return nil }
        return u32(cursor)
    }
}
