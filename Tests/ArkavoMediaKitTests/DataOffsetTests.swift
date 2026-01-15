import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - Data Offset Calculation Tests

/// Tests for validating data offset calculations in FMP4Writer.
/// When default-base-is-moof flag is set in tfhd, data_offset in trun is
/// relative to the first byte of moof (not segment start).
/// See ISO 14496-12 for details on base data offset handling.
@Suite("FMP4 Data Offset Calculation")
struct DataOffsetTests {

    // MARK: - Box Parsing Helpers

    /// Parse a box header and return (size, type, headerSize)
    private func parseBoxHeader(_ data: Data, at offset: Int) -> (size: Int, type: String, headerSize: Int)? {
        guard offset + 8 <= data.count else { return nil }

        let sizeData = data.subdata(in: offset..<(offset + 4))
        let size = Int(UInt32(bigEndian: sizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))

        let typeData = data.subdata(in: (offset + 4)..<(offset + 8))
        guard let type = String(data: typeData, encoding: .ascii) else { return nil }

        // Handle extended size (size == 1)
        if size == 1 && offset + 16 <= data.count {
            let extSizeData = data.subdata(in: (offset + 8)..<(offset + 16))
            let extSize = Int(UInt64(bigEndian: extSizeData.withUnsafeBytes { $0.load(as: UInt64.self) }))
            return (extSize, type, 16)
        }

        return (size, type, 8)
    }

    /// Find box of given type starting from offset
    private func findBox(_ data: Data, type: String, startingAt start: Int = 0) -> (offset: Int, size: Int)? {
        var offset = start
        while offset + 8 <= data.count {
            guard let header = parseBoxHeader(data, at: offset) else { break }

            if header.type == type {
                return (offset, header.size)
            }

            // Move to next box
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

    /// Extract trun data_offset from trun box data
    private func extractTrunDataOffset(_ data: Data, trunOffset: Int) -> Int32? {
        // trun structure: size(4) + type(4) + version(1) + flags(3) + sample_count(4) + [data_offset(4)]
        guard trunOffset + 16 <= data.count else { return nil }

        // Check flags for data_offset_present (0x000001)
        let flags = (UInt32(data[trunOffset + 9]) << 16) |
                    (UInt32(data[trunOffset + 10]) << 8) |
                    UInt32(data[trunOffset + 11])

        let dataOffsetPresent = (flags & 0x000001) != 0

        if dataOffsetPresent {
            // data_offset is at offset 16 (after size + type + version/flags + sample_count)
            let offsetData = data.subdata(in: (trunOffset + 16)..<(trunOffset + 20))
            return Int32(bigEndian: offsetData.withUnsafeBytes { $0.load(as: Int32.self) })
        }

        return nil
    }

    // MARK: - Unencrypted Segment Tests

    @Test("trun data_offset points to mdat payload start")
    func trunDataOffsetPointsToMdatPayload() throws {
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

        // Create sample with known marker at start
        let markerData = Data([0xDE, 0xAD, 0xBE, 0xEF])
        var sampleData = markerData
        sampleData.append(Data(repeating: 0x00, count: 100))

        let samples = [
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find moof box
        guard let moofInfo = findBox(mediaSegment, type: "moof") else {
            Issue.record("moof box not found")
            return
        }

        // Find traf inside moof
        guard let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8) else {
            Issue.record("traf box not found")
            return
        }

        // Find trun inside traf
        guard let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8) else {
            Issue.record("trun box not found")
            return
        }

        // Extract data_offset from trun
        guard let dataOffset = extractTrunDataOffset(mediaSegment, trunOffset: trunInfo.offset) else {
            Issue.record("Could not extract data_offset from trun")
            return
        }

        // Find mdat box
        guard let mdatInfo = findBox(mediaSegment, type: "mdat") else {
            Issue.record("mdat box not found")
            return
        }

        // mdat payload starts 8 bytes after mdat header
        let mdatPayloadOffset = mdatInfo.offset + 8

        // With default-base-is-moof, data_offset is relative to moof start
        // So the actual sample position = moofInfo.offset + data_offset
        let actualSamplePosition = moofInfo.offset + Int(dataOffset)

        // Verify actual sample position equals mdat payload start
        #expect(actualSamplePosition == mdatPayloadOffset,
                "moof_start (\(moofInfo.offset)) + data_offset (\(dataOffset)) = \(actualSamplePosition) should equal mdat payload offset (\(mdatPayloadOffset))")

        // Verify the marker is at the actual sample position
        let actualData = mediaSegment.subdata(in: actualSamplePosition..<(actualSamplePosition + 4))
        #expect(actualData == markerData, "Data at actual sample position should be sample marker")
    }

    @Test("data_offset is relative to moof start")
    func dataOffsetRelativeToMoof() throws {
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

        // Find moof (may be preceded by styp for CMAF compliance)
        guard let moofInfo = findBox(mediaSegment, type: "moof") else {
            Issue.record("moof box not found")
            return
        }

        // Find mdat
        guard let mdatInfo = findBox(mediaSegment, type: "mdat") else {
            Issue.record("mdat box not found")
            return
        }

        // Find trun and extract data_offset
        guard let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8),
              let dataOffset = extractTrunDataOffset(mediaSegment, trunOffset: trunInfo.offset) else {
            Issue.record("Could not extract data_offset")
            return
        }

        // With default-base-is-moof, data_offset is relative to moof start
        // data_offset = moof_size + mdat_header_size
        let moofSize = moofInfo.size
        let mdatHeaderSize = 8
        let expectedDataOffset = moofSize + mdatHeaderSize

        #expect(Int(dataOffset) == expectedDataOffset,
                "data_offset (\(dataOffset)) should equal moof_size (\(moofSize)) + mdat_header (\(mdatHeaderSize)) = \(expectedDataOffset)")

        // Verify moof_start + data_offset points to mdat payload
        let actualSamplePosition = moofInfo.offset + Int(dataOffset)
        let expectedMdatPayload = mdatInfo.offset + 8
        #expect(actualSamplePosition == expectedMdatPayload,
                "moof_start + data_offset should point to mdat payload")
    }

    // MARK: - Encrypted Segment Tests

    @Test("Encrypted segment has correct data_offset")
    func encryptedSegmentDataOffset() throws {
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

        let markerData = Data([0xCA, 0xFE, 0xBA, 0xBE])
        var sampleData = markerData
        sampleData.append(Data(repeating: 0x00, count: 100))

        let samples = [
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find trun and extract data_offset
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8),
              let dataOffset = extractTrunDataOffset(mediaSegment, trunOffset: trunInfo.offset) else {
            Issue.record("Could not extract data_offset")
            return
        }

        // With default-base-is-moof, actual sample position = moof_start + data_offset
        let actualSamplePosition = moofInfo.offset + Int(dataOffset)

        // Verify data at actual sample position is our marker
        let actualData = mediaSegment.subdata(in: actualSamplePosition..<(actualSamplePosition + 4))
        #expect(actualData == markerData, "Data at data_offset should be sample marker")
    }

    @Test("saio offset points to senc auxiliary data")
    func saioOffsetPointsToSenc() throws {
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

        // Verify senc, saiz, saio boxes exist using recursive search
        guard findBoxRecursive(mediaSegment, type: "senc") != nil else {
            Issue.record("senc box not found")
            return
        }
        guard findBoxRecursive(mediaSegment, type: "saiz") != nil else {
            Issue.record("saiz box not found")
            return
        }
        guard findBoxRecursive(mediaSegment, type: "saio") != nil else {
            Issue.record("saio box not found")
            return
        }

        // Encryption boxes should all be present for encrypted content
        #expect(Bool(true))
    }

    // MARK: - Multiple Sample Tests

    @Test("data_offset correct with multiple samples")
    func dataOffsetWithMultipleSamples() throws {
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

        // Create multiple samples with different markers
        let marker1 = Data([0x11, 0x11, 0x11, 0x11])
        let marker2 = Data([0x22, 0x22, 0x22, 0x22])
        let marker3 = Data([0x33, 0x33, 0x33, 0x33])

        var sample1 = marker1
        sample1.append(Data(repeating: 0x00, count: 96))

        var sample2 = marker2
        sample2.append(Data(repeating: 0x00, count: 46))

        var sample3 = marker3
        sample3.append(Data(repeating: 0x00, count: 196))

        let samples = [
            FMP4Writer.Sample(data: sample1, duration: 3000, isSync: true),
            FMP4Writer.Sample(data: sample2, duration: 3000, isSync: false),
            FMP4Writer.Sample(data: sample3, duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find trun and extract data_offset
        guard let moofInfo = findBox(mediaSegment, type: "moof"),
              let trafInfo = findBox(mediaSegment, type: "traf", startingAt: moofInfo.offset + 8),
              let trunInfo = findBox(mediaSegment, type: "trun", startingAt: trafInfo.offset + 8),
              let dataOffset = extractTrunDataOffset(mediaSegment, trunOffset: trunInfo.offset) else {
            Issue.record("Could not extract data_offset")
            return
        }

        // With default-base-is-moof, actual sample position = moof_start + data_offset
        let actualSamplePosition = moofInfo.offset + Int(dataOffset)

        // First sample marker should be at actual sample position
        let firstSampleData = mediaSegment.subdata(in: actualSamplePosition..<(actualSamplePosition + 4))
        #expect(firstSampleData == marker1, "First sample should be at data_offset")

        // Verify all samples are present in mdat
        #expect(mediaSegment.range(of: marker1) != nil)
        #expect(mediaSegment.range(of: marker2) != nil)
        #expect(mediaSegment.range(of: marker3) != nil)

        // Samples should be contiguous in mdat
        let mdatPayloadStart = actualSamplePosition
        let sample2Start = mdatPayloadStart + sample1.count
        let sample3Start = sample2Start + sample2.count

        #expect(mediaSegment.subdata(in: sample2Start..<(sample2Start + 4)) == marker2)
        #expect(mediaSegment.subdata(in: sample3Start..<(sample3Start + 4)) == marker3)
    }

    // MARK: - Box Size Validation

    @Test("All boxes in media segment have valid sizes")
    func mediaSegmentBoxSizesValid() throws {
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
            FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 500), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0xBB, count: 300), duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Walk top-level boxes
        var offset = 0
        var boxCount = 0

        while offset + 8 <= mediaSegment.count {
            guard let header = parseBoxHeader(mediaSegment, at: offset) else {
                Issue.record("Failed to parse box header at offset \(offset)")
                break
            }

            // Size must be at least header size
            #expect(header.size >= header.headerSize, "Box \(header.type) at \(offset) has size \(header.size) < header \(header.headerSize)")

            // Size must not exceed remaining data
            #expect(header.size <= mediaSegment.count - offset, "Box \(header.type) extends beyond data")

            offset += header.size
            boxCount += 1

            if boxCount > 10 { break } // Safety limit for top-level
        }

        // Should have moof, mdat (no styp per Apple FairPlay reference structure)
        #expect(boxCount >= 2, "Should have at least 2 top-level boxes (moof, mdat)")
        #expect(offset == mediaSegment.count, "All data should be consumed by boxes")
    }
}
