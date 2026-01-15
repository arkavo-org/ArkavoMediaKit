import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - traf Box Structure Tests

/// Tests for validating the structure and ordering of boxes within traf.
/// FairPlay/AVPlayer require specific box ordering and flag settings.
@Suite("traf Box Structure Validation")
struct TrafBoxTests {

    // MARK: - Box Parsing Helpers

    /// Parse a box header and return (size, type, headerSize)
    private func parseBoxHeader(_ data: Data, at offset: Int) -> (size: Int, type: String, headerSize: Int)? {
        guard offset + 8 <= data.count else { return nil }

        let sizeData = data.subdata(in: offset..<(offset + 4))
        let size = Int(UInt32(bigEndian: sizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))

        let typeData = data.subdata(in: (offset + 4)..<(offset + 8))
        guard let type = String(data: typeData, encoding: .ascii) else { return nil }

        if size == 1 && offset + 16 <= data.count {
            let extSizeData = data.subdata(in: (offset + 8)..<(offset + 16))
            let extSize = Int(UInt64(bigEndian: extSizeData.withUnsafeBytes { $0.load(as: UInt64.self) }))
            return (extSize, type, 16)
        }

        return (size, type, 8)
    }

    /// Find box of given type starting from offset, searching within container bounds
    private func findBox(_ data: Data, type: String, startingAt start: Int = 0, endAt end: Int? = nil) -> (offset: Int, size: Int)? {
        var offset = start
        let endOffset = end ?? data.count
        while offset + 8 <= endOffset {
            guard let header = parseBoxHeader(data, at: offset) else { break }

            if header.type == type {
                return (offset, header.size)
            }

            if header.size > 0 {
                offset += header.size
            } else {
                break
            }
        }
        return nil
    }

    /// Find box recursively in nested containers
    private func findBoxRecursive(_ data: Data, type: String, startingAt start: Int = 0) -> (offset: Int, size: Int)? {
        var offset = start
        while offset + 8 <= data.count {
            guard let header = parseBoxHeader(data, at: offset) else { break }

            if header.type == type {
                return (offset, header.size)
            }

            // If this is a container box, search inside it
            let containerTypes = ["moov", "moof", "trak", "mdia", "minf", "stbl", "traf", "mvex", "edts", "dinf", "sinf", "schi"]
            if containerTypes.contains(header.type) {
                if let found = findBoxRecursive(data, type: type, startingAt: offset + 8) {
                    // Verify it's within the container
                    if found.offset + found.size <= offset + header.size {
                        return found
                    }
                }
            }

            if header.size > 0 {
                offset += header.size
            } else {
                break
            }
        }
        return nil
    }

    /// Get ordered list of child boxes within a container
    private func getChildBoxes(_ data: Data, containerOffset: Int, containerSize: Int) -> [(type: String, offset: Int, size: Int)] {
        var children: [(type: String, offset: Int, size: Int)] = []
        var offset = containerOffset + 8 // Skip container header
        let endOffset = containerOffset + containerSize

        while offset + 8 <= endOffset {
            guard let header = parseBoxHeader(data, at: offset) else { break }
            children.append((header.type, offset, header.size))

            if header.size > 0 {
                offset += header.size
            } else {
                break
            }
        }

        return children
    }

    /// Extract tfhd flags from box data
    private func extractTfhdFlags(_ data: Data, tfhdOffset: Int) -> UInt32? {
        guard tfhdOffset + 12 <= data.count else { return nil }

        // flags at offset 8 (size) + 4 (type) + 1 (version) = 9, 3 bytes
        let flags = (UInt32(data[tfhdOffset + 9]) << 16) |
                    (UInt32(data[tfhdOffset + 10]) << 8) |
                    UInt32(data[tfhdOffset + 11])
        return flags
    }

    /// Extract sample_description_index from tfhd if present
    private func extractSampleDescriptionIndex(_ data: Data, tfhdOffset: Int) -> UInt32? {
        guard let flags = extractTfhdFlags(data, tfhdOffset: tfhdOffset) else { return nil }

        // sample_description_index_present flag is 0x000002
        let sdiPresent = (flags & 0x000002) != 0
        if !sdiPresent { return nil }

        // tfhd structure:
        // size(4) + type(4) + version/flags(4) + track_id(4) = 16 bytes header
        // Then optional fields in order:
        // [base_data_offset (8) if 0x000001]
        // [sample_description_index (4) if 0x000002]
        var offset = tfhdOffset + 16 // After size + type + version/flags + track_id

        // If base_data_offset_present (0x000001), skip 8 bytes
        if (flags & 0x000001) != 0 {
            offset += 8
        }

        // Now at sample_description_index (4 bytes)
        guard offset + 4 <= data.count else { return nil }
        let sdiData = data.subdata(in: offset..<(offset + 4))
        return UInt32(bigEndian: sdiData.withUnsafeBytes { $0.load(as: UInt32.self) })
    }

    // MARK: - Box Order Tests

    @Test("traf contains boxes in correct order: tfhd, tfdt, trun")
    func trafBoxOrder() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find traf
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8) else {
            Issue.record("traf box not found")
            return
        }

        // Get children of traf
        let children = getChildBoxes(mediaSegment, containerOffset: trafInfo.offset, containerSize: trafInfo.size)

        #expect(children.count >= 3, "traf should have at least 3 children (tfhd, tfdt, trun)")

        // Verify order
        #expect(children[0].type == "tfhd", "First child should be tfhd")
        #expect(children[1].type == "tfdt", "Second child should be tfdt")
        #expect(children[2].type == "trun", "Third child should be trun")
    }

    @Test("Encrypted traf contains boxes in correct order: tfhd, tfdt, trun, senc, saiz, saio")
    func encryptedTrafBoxOrder() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let encryption = FMP4Writer.EncryptionConfig(
            keyID: Data(repeating: 0xAB, count: 16),
            constantIV: Data(repeating: 0xCD, count: 16)
        )

        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find traf
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8) else {
            Issue.record("traf box not found")
            return
        }

        // Get children of traf
        let children = getChildBoxes(mediaSegment, containerOffset: trafInfo.offset, containerSize: trafInfo.size)

        #expect(children.count >= 6, "Encrypted traf should have at least 6 children")

        // Verify order
        #expect(children[0].type == "tfhd", "First child should be tfhd")
        #expect(children[1].type == "tfdt", "Second child should be tfdt")
        #expect(children[2].type == "trun", "Third child should be trun")
        #expect(children[3].type == "senc", "Fourth child should be senc")
        #expect(children[4].type == "saiz", "Fifth child should be saiz")
        #expect(children[5].type == "saio", "Sixth child should be saio")
    }

    // MARK: - tfhd Flag Tests

    @Test("tfhd has sampleDescriptionIndex = 1 for unencrypted content")
    func tfhdSampleDescriptionIndexUnencrypted() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find tfhd
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let tfhdInfo = findBox(mediaSegment, type: "tfhd", startingAt: trafInfo.offset + 8) else {
            Issue.record("tfhd box not found")
            return
        }

        // Check flags for sample_description_index_present
        guard let flags = extractTfhdFlags(mediaSegment, tfhdOffset: tfhdInfo.offset) else {
            Issue.record("Could not extract tfhd flags")
            return
        }

        let sdiPresent = (flags & 0x000002) != 0
        #expect(sdiPresent, "sample_description_index_present flag should be set")

        // Extract and verify sample_description_index
        if sdiPresent {
            guard let sdi = extractSampleDescriptionIndex(mediaSegment, tfhdOffset: tfhdInfo.offset) else {
                Issue.record("Could not extract sample_description_index")
                return
            }
            #expect(sdi == 1, "sample_description_index should be 1")
        }
    }

    @Test("tfhd has sampleDescriptionIndex = 1 for encrypted content")
    func tfhdSampleDescriptionIndexEncrypted() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let encryption = FMP4Writer.EncryptionConfig(
            keyID: Data(repeating: 0xAB, count: 16),
            constantIV: Data(repeating: 0xCD, count: 16)
        )

        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find tfhd
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let tfhdInfo = findBox(mediaSegment, type: "tfhd", startingAt: trafInfo.offset + 8) else {
            Issue.record("tfhd box not found")
            return
        }

        // Check sample_description_index = 1 (critical for encrypted content)
        guard let flags = extractTfhdFlags(mediaSegment, tfhdOffset: tfhdInfo.offset) else {
            Issue.record("Could not extract tfhd flags")
            return
        }

        let sdiPresent = (flags & 0x000002) != 0
        #expect(sdiPresent, "sample_description_index_present flag must be set for encrypted content")

        if sdiPresent {
            guard let sdi = extractSampleDescriptionIndex(mediaSegment, tfhdOffset: tfhdInfo.offset) else {
                Issue.record("Could not extract sample_description_index")
                return
            }
            #expect(sdi == 1, "sample_description_index must be 1 to reference encv entry")
        }
    }

    @Test("tfhd has default_base_is_moof flag set")
    func tfhdDefaultBaseIsMoof() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find tfhd
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let tfhdInfo = findBox(mediaSegment, type: "tfhd", startingAt: trafInfo.offset + 8) else {
            Issue.record("tfhd box not found")
            return
        }

        guard let flags = extractTfhdFlags(mediaSegment, tfhdOffset: tfhdInfo.offset) else {
            Issue.record("Could not extract tfhd flags")
            return
        }

        // default_base_is_moof flag is 0x020000
        let defaultBaseIsMoof = (flags & 0x020000) != 0
        #expect(defaultBaseIsMoof, "default_base_is_moof flag should be set")
    }

    // MARK: - trun Tests

    @Test("trun has data_offset_present flag")
    func trunDataOffsetPresent() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find trun
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8) else {
            Issue.record("trun box not found")
            return
        }

        // Extract trun flags
        guard trunInfo.offset + 12 <= mediaSegment.count else {
            Issue.record("trun box too small")
            return
        }

        let flags = (UInt32(mediaSegment[trunInfo.offset + 9]) << 16) |
                    (UInt32(mediaSegment[trunInfo.offset + 10]) << 8) |
                    UInt32(mediaSegment[trunInfo.offset + 11])

        // data_offset_present is 0x000001
        let dataOffsetPresent = (flags & 0x000001) != 0
        #expect(dataOffsetPresent, "data_offset_present flag should be set")
    }

    @Test("trun has sample_duration_present flag")
    func trunSampleDurationPresent() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0xBB, count: 100), duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find trun
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8) else {
            Issue.record("trun box not found")
            return
        }

        guard trunInfo.offset + 12 <= mediaSegment.count else {
            Issue.record("trun box too small")
            return
        }

        let flags = (UInt32(mediaSegment[trunInfo.offset + 9]) << 16) |
                    (UInt32(mediaSegment[trunInfo.offset + 10]) << 8) |
                    UInt32(mediaSegment[trunInfo.offset + 11])

        // sample_duration_present is 0x000100
        let sampleDurationPresent = (flags & 0x000100) != 0
        #expect(sampleDurationPresent, "sample_duration_present flag should be set")
    }

    @Test("trun has sample_size_present flag")
    func trunSampleSizePresent() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0xBB, count: 200), duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find trun
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8) else {
            Issue.record("trun box not found")
            return
        }

        guard trunInfo.offset + 12 <= mediaSegment.count else {
            Issue.record("trun box too small")
            return
        }

        let flags = (UInt32(mediaSegment[trunInfo.offset + 9]) << 16) |
                    (UInt32(mediaSegment[trunInfo.offset + 10]) << 8) |
                    UInt32(mediaSegment[trunInfo.offset + 11])

        // sample_size_present is 0x000200
        let sampleSizePresent = (flags & 0x000200) != 0
        #expect(sampleSizePresent, "sample_size_present flag should be set")
    }

    @Test("trun has sample_flags_present flag")
    func trunSampleFlagsPresent() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0xBB, count: 100), duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find trun
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8) else {
            Issue.record("trun box not found")
            return
        }

        guard trunInfo.offset + 12 <= mediaSegment.count else {
            Issue.record("trun box too small")
            return
        }

        let flags = (UInt32(mediaSegment[trunInfo.offset + 9]) << 16) |
                    (UInt32(mediaSegment[trunInfo.offset + 10]) << 8) |
                    UInt32(mediaSegment[trunInfo.offset + 11])

        // sample_flags_present is 0x000400
        let sampleFlagsPresent = (flags & 0x000400) != 0
        #expect(sampleFlagsPresent, "sample_flags_present flag should be set for sync/non-sync distinction")
    }

    // MARK: - Encryption Box Tests

    @Test("senc box has use_subsample_encryption flag")
    func sencUseSubsampleEncryption() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let encryption = FMP4Writer.EncryptionConfig(
            keyID: Data(repeating: 0xAB, count: 16),
            constantIV: Data(repeating: 0xCD, count: 16)
        )

        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find senc using recursive search (it's inside moof > traf)
        guard let sencInfo = findBoxRecursive(mediaSegment, type: "senc") else {
            Issue.record("senc box not found")
            return
        }

        guard sencInfo.offset + 12 <= mediaSegment.count else {
            Issue.record("senc box too small")
            return
        }

        let flags = (UInt32(mediaSegment[sencInfo.offset + 9]) << 16) |
                    (UInt32(mediaSegment[sencInfo.offset + 10]) << 8) |
                    UInt32(mediaSegment[sencInfo.offset + 11])

        // use_subsample_encryption is 0x02
        let useSubsample = (flags & 0x02) != 0
        #expect(useSubsample, "use_subsample_encryption flag should be set for CBCS")
    }
}
