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

    private static func samples(count: Int, syncAt sync: Set<Int>) -> [FMP4RecordingProtectionService.SegmentSample] {
        (0 ..< count).map { .init(duration: 1, isSync: sync.contains($0)) }
    }

    /// A recorder's keyframes jitter around the GOP: one a few ticks short of
    /// the target must close the segment, not push it a whole GOP long.
    @Test("a sync sample just short of the target closes the segment when it is nearer")
    func nearestSyncSample() {
        let ranges = FMP4RecordingProtectionService.segmentRanges(
            for: Self.samples(count: 400, syncAt: [0, 178, 238, 300]), targetDuration: 180)
        #expect(ranges == [0 ..< 178, 178 ..< 400])
    }

    @Test("a sync sample less than half the target in does not close a segment")
    func earlySyncSampleIgnored() {
        let ranges = FMP4RecordingProtectionService.segmentRanges(
            for: Self.samples(count: 400, syncAt: [0, 15, 360]), targetDuration: 180)
        #expect(ranges == [0 ..< 360, 360 ..< 400])
    }

    @Test("after closing at an earlier sync sample the current one is weighed again")
    func reconsidersAfterEarlierCut() {
        let ranges = FMP4RecordingProtectionService.segmentRanges(
            for: Self.samples(count: 600, syncAt: [0, 100, 400]), targetDuration: 180)
        #expect(ranges == [0 ..< 100, 100 ..< 400, 400 ..< 600])
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
        // RFC 8216: each EXTINF, rounded to the nearest integer, at most the target;
        // and the target no larger than that requires.
        #expect(target == Int((durations.max() ?? 0).rounded()), "target \(target) for EXTINF \(durations)")
        for name in segmentNames {
            let segment = try #require(files[name])
            let flags = try #require(Self.firstSampleFlags(inSegment: segment))
            #expect(flags & 0x0001_0000 == 0, "\(name) opens on a non-sync sample (flags \(String(flags, radix: 16)))")
        }
    }

    /// Regression for the read-duration guard and the sync cuts on a source
    /// shaped like Creator's recorder: jittered real-time timestamps on a µs
    /// timescale, a keyframe every 60 frames.
    @Test("a variable-frame-rate source protects whole, each segment opening on a sync sample")
    func variableFrameRateSource() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-vfr-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let movie = try await SyntheticMovie.make(in: dir, frames: 400, keyFrameInterval: 60, variableFrameRate: true)
        let kas = try TestKASKeyPair()
        let service = FMP4RecordingProtectionService(
            kasURL: URL(string: "https://platform.arkavo.net")!, kasPublicKeyPEM: kas.spkiPublicKeyPEM)
        let archive = try await service.protectVideo(videoURL: movie, assetID: "vfr")

        let zip = try Archive(data: archive, accessMode: .read)
        var files: [String: Data] = [:]
        for entry in zip {
            var data = Data()
            _ = try zip.extract(entry) { data.append($0) }
            files[entry.path] = data
        }
        let playlist = String(decoding: try #require(files["playlist.m3u8"]), as: UTF8.self)
        let lines = playlist.components(separatedBy: .newlines)
        let total = lines.compactMap { line -> Double? in
            guard line.hasPrefix("#EXTINF:") else { return nil }
            return Double(line.dropFirst("#EXTINF:".count).prefix { $0 != "," })
        }.reduce(0, +)
        #expect(abs(total - 13.3) < 0.2, "segments cover \(total) s of a ~13.3 s source")
        let segmentNames = lines.filter { $0.hasSuffix(".m4s") }
        #expect(segmentNames.count >= 2)
        for name in segmentNames {
            let segment = try #require(files[name])
            let flags = try #require(Self.firstSampleFlags(inSegment: segment))
            #expect(flags & 0x0001_0000 == 0, "\(name) opens on a non-sync sample")
        }
    }

    /// A segment of 6.03 s needs a target of 6, not 7.
    @Test("the target duration is the longest segment rounded to the nearest second")
    func targetDurationRoundsToNearest() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-target-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let movie = try await SyntheticMovie.make(in: dir, frames: 400, keyFrameInterval: 181)
        let service = FMP4RecordingProtectionService(
            kasURL: URL(string: "https://platform.arkavo.net")!, kasPublicKeyPEM: try TestKASKeyPair().spkiPublicKeyPEM)
        let archive = try await service.protectVideo(videoURL: movie, assetID: "target")
        let zip = try Archive(data: archive, accessMode: .read)
        var playlistData = Data()
        _ = try zip.extract(try #require(zip["playlist.m3u8"])) { playlistData.append($0) }
        let lines = String(decoding: playlistData, as: UTF8.self).components(separatedBy: .newlines)
        let target = try #require(lines.lazy.compactMap { line in
            line.hasPrefix("#EXT-X-TARGETDURATION:") ? Int(line.dropFirst("#EXT-X-TARGETDURATION:".count)) : nil
        }.first)
        let longest = try #require(lines.compactMap { line -> Double? in
            guard line.hasPrefix("#EXTINF:") else { return nil }
            return Double(line.dropFirst("#EXTINF:".count).prefix { $0 != "," })
        }.max())
        #expect(longest.rounded() != longest.rounded(.up), "the source must give a segment just over a whole second (\(longest))")
        #expect(target == Int(longest.rounded()), "target \(target) for a longest segment of \(longest) s")
    }

    @Test("a clip under half a second still declares a target duration of 1")
    func shortClipTarget() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-short-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let movie = try await SyntheticMovie.make(in: dir, frames: 10)
        let service = FMP4RecordingProtectionService(
            kasURL: URL(string: "https://platform.arkavo.net")!, kasPublicKeyPEM: try TestKASKeyPair().spkiPublicKeyPEM)
        let archive = try await service.protectVideo(videoURL: movie, assetID: "short")
        let zip = try Archive(data: archive, accessMode: .read)
        var playlistData = Data()
        _ = try zip.extract(try #require(zip["playlist.m3u8"])) { playlistData.append($0) }
        #expect(String(decoding: playlistData, as: UTF8.self).contains("#EXT-X-TARGETDURATION:1\n"))
    }

    /// `6 * timescale` was Int32 arithmetic: a track timescale over 357,913,941
    /// trapped the process instead of protecting.
    @Test("a track with a nanosecond timescale protects")
    func nanosecondTimescale() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("fmp4-ns-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let movie = try await SyntheticMovie.make(in: dir, frames: 30, mediaTimeScale: 1_000_000_000)
        let service = FMP4RecordingProtectionService(
            kasURL: URL(string: "https://platform.arkavo.net")!, kasPublicKeyPEM: try TestKASKeyPair().spkiPublicKeyPEM)
        _ = try await service.protectVideo(videoURL: movie, assetID: "ns")
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
