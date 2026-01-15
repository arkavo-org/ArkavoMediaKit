import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - Large Segment Tests

/// Tests for large segments with realistic sample counts (like real 6-second video segments)
@Suite("Large Segment Validation")
struct LargeSegmentTests {

    let testSPS = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78,
                        0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00, 0x03,
                        0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF2, 0x3C])
    let testPPS = Data([0x68, 0xEE, 0x3C, 0x80])
    let testKeyID = Data(repeating: 0x12, count: 16)
    let testIV = Data([0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
                       0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7])
    let testKey = Data(repeating: 0x3C, count: 16)

    // MARK: - Helper Functions

    /// Create a realistic video sample (H.264 NAL structure)
    func createVideoSample(isIDR: Bool, size: Int) -> Data {
        var sample = Data()

        // Helper to append 4-byte big-endian NAL length
        func appendNALLength(_ length: Int) {
            sample.append(UInt8((length >> 24) & 0xFF))
            sample.append(UInt8((length >> 16) & 0xFF))
            sample.append(UInt8((length >> 8) & 0xFF))
            sample.append(UInt8(length & 0xFF))
        }

        if isIDR {
            // IDR frame: SPS + PPS + IDR slice NAL
            // SPS NAL
            appendNALLength(testSPS.count)
            sample.append(testSPS)

            // PPS NAL
            appendNALLength(testPPS.count)
            sample.append(testPPS)

            // IDR slice NAL - fill remaining size
            let sliceSize = max(size - sample.count - 4, 100)
            appendNALLength(sliceSize)
            sample.append(0x65) // NAL type 5 (IDR)
            sample.append(Data(repeating: 0xAB, count: sliceSize - 1))
        } else {
            // P-frame: just a non-IDR slice NAL
            let sliceSize = max(size - 4, 50)
            appendNALLength(sliceSize)
            sample.append(0x41) // NAL type 1 (non-IDR)
            sample.append(Data(repeating: 0xCD, count: sliceSize - 1))
        }

        return sample
    }

    // MARK: - Tests

    @Test("Large segment with 180 samples (6 seconds at 30fps)")
    func largeSegmentWith180Samples() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [testSPS], pps: [testPPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // Create 180 samples (6 seconds at 30fps)
        var samples: [FMP4Writer.Sample] = []
        let sampleCount = 180
        var totalOriginalSize = 0

        for i in 0..<sampleCount {
            let isIDR = (i % 30 == 0) // IDR every second
            let size = isIDR ? 50000 : 5000 // IDR frames are larger

            let sampleData = createVideoSample(isIDR: isIDR, size: size)
            let encryptedResult = encryptor.encryptVideoSample(sampleData, nalLengthSize: 4)

            totalOriginalSize += sampleData.count

            samples.append(FMP4Writer.Sample(
                data: encryptedResult.encryptedData,
                duration: 3000, // 90000 / 30 = 3000 ticks per frame
                isSync: isIDR,
                subsamples: encryptedResult.subsamples
            ))
        }

        let segment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        print("\n=== Large Segment Analysis ===")
        print("Sample count: \(sampleCount)")
        print("Total sample data: \(totalOriginalSize) bytes")
        print("Segment size: \(segment.count) bytes")

        // Find mdat and verify payload size
        let mdatMarker = Data([0x6D, 0x64, 0x61, 0x74]) // "mdat"
        guard let mdatRange = segment.range(of: mdatMarker) else {
            Issue.record("mdat box not found")
            return
        }

        let mdatSizeOffset = mdatRange.lowerBound - 4
        let mdatSizeData = segment.subdata(in: mdatSizeOffset..<mdatRange.lowerBound)
        let mdatSize = Int(UInt32(bigEndian: mdatSizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
        let mdatPayloadSize = mdatSize - 8
        let mdatPayloadOffset = mdatRange.upperBound

        print("mdat size: \(mdatSize), payload: \(mdatPayloadSize), offset: \(mdatPayloadOffset)")

        // Verify mdat payload equals total sample data
        #expect(mdatPayloadSize == totalOriginalSize,
                "mdat payload (\(mdatPayloadSize)) should equal total sample data (\(totalOriginalSize))")

        // Verify segment is roughly expected size (overhead + samples)
        let expectedMinSize = totalOriginalSize + 4000 // At least samples + some overhead
        #expect(segment.count >= expectedMinSize,
                "Segment should be at least \(expectedMinSize) bytes")

        print("\n✅ Large segment structure is valid")
    }

    @Test("Verify saio offset matches actual senc position")
    func verifySaioOffsetMatchesSenc() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [testSPS], pps: [testPPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // Create samples similar to real video
        var samples: [FMP4Writer.Sample] = []
        for i in 0..<10 {
            let isIDR = (i == 0)
            let sampleData = createVideoSample(isIDR: isIDR, size: isIDR ? 50000 : 5000)
            let result = encryptor.encryptVideoSample(sampleData, nalLengthSize: 4)
            samples.append(FMP4Writer.Sample(
                data: result.encryptedData,
                duration: 3000,
                isSync: isIDR,
                subsamples: result.subsamples
            ))
        }

        let segment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        print("\n=== SAIO Offset Verification ===")
        print("Segment size: \(segment.count) bytes")

        // Find moof start
        let moofMarker = Data([0x6D, 0x6F, 0x6F, 0x66])
        guard let moofRange = segment.range(of: moofMarker) else {
            Issue.record("moof not found")
            return
        }
        let moofStart = moofRange.lowerBound - 4

        // Find senc box
        let sencMarker = Data([0x73, 0x65, 0x6E, 0x63])
        guard let sencRange = segment.range(of: sencMarker) else {
            Issue.record("senc not found")
            return
        }
        let sencStart = sencRange.lowerBound - 4
        let sencSize = Int(UInt32(bigEndian: segment.subdata(in: sencStart..<(sencStart+4)).withUnsafeBytes { $0.load(as: UInt32.self) }))

        // senc sample data starts after: header(8) + version/flags(4) + sample_count(4) = 16 bytes
        let sencSampleDataOffset = sencStart + 16
        let sencSampleDataOffsetFromMoof = sencSampleDataOffset - moofStart

        print("moof start: \(moofStart)")
        print("senc start: \(sencStart) (size: \(sencSize))")
        print("senc sample data starts at: \(sencSampleDataOffset)")
        print("senc sample data offset from moof: \(sencSampleDataOffsetFromMoof)")

        // Find saio box and extract the offset value
        let saioMarker = Data([0x73, 0x61, 0x69, 0x6F])
        guard let saioRange = segment.range(of: saioMarker) else {
            Issue.record("saio not found")
            return
        }
        let saioStart = saioRange.lowerBound - 4

        // saio structure: size(4) + type(4) + version/flags(4) + entry_count(4) = 16 bytes before offset
        let saioOffsetPosition = saioStart + 16
        let saioOffsetValue = Int(UInt32(bigEndian: segment.subdata(in: saioOffsetPosition..<(saioOffsetPosition+4)).withUnsafeBytes { $0.load(as: UInt32.self) }))

        print("saio box at: \(saioStart)")
        print("saio offset value: \(saioOffsetValue)")

        // With default-base-is-moof, saio offset should equal sencSampleDataOffsetFromMoof
        print("\nExpected saio offset (from moof): \(sencSampleDataOffsetFromMoof)")
        print("Actual saio offset value: \(saioOffsetValue)")

        #expect(saioOffsetValue == sencSampleDataOffsetFromMoof,
                "saio offset (\(saioOffsetValue)) should point to senc sample data at offset \(sencSampleDataOffsetFromMoof) from moof")

        // Also verify the offset points to valid data
        let targetOffset = moofStart + saioOffsetValue
        print("\nAbsolute target position: moof_start(\(moofStart)) + saio_offset(\(saioOffsetValue)) = \(targetOffset)")
        print("senc sample data position: \(sencSampleDataOffset)")
        #expect(targetOffset == sencSampleDataOffset,
                "saio should point to senc sample data")
    }

    @Test("Subsample info for large IDR frame")
    func subsampleInfoForLargeIDRFrame() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // Create a large IDR frame (like real 1080p video)
        let sampleData = createVideoSample(isIDR: true, size: 100000)
        let result = encryptor.encryptVideoSample(sampleData, nalLengthSize: 4)

        print("\n=== Large IDR Frame Subsample Analysis ===")
        print("Original size: \(sampleData.count) bytes")
        print("Encrypted size: \(result.encryptedData.count) bytes")
        print("Subsample count: \(result.subsamples.count)")

        var totalClear = 0
        var totalProtected = 0

        for (i, sub) in result.subsamples.enumerated() {
            print("  [\(i)] clear: \(sub.bytesOfClearData), protected: \(sub.bytesOfProtectedData)")
            totalClear += Int(sub.bytesOfClearData)
            totalProtected += Int(sub.bytesOfProtectedData)
        }

        print("Total: clear=\(totalClear), protected=\(totalProtected), sum=\(totalClear + totalProtected)")

        // Verify subsample sizes sum to sample size
        #expect(totalClear + totalProtected == sampleData.count,
                "Subsample sizes should sum to sample size")

        // Verify encrypted data is same size as original
        #expect(result.encryptedData.count == sampleData.count,
                "Encrypted data should be same size as original")
    }

    @Test("saiz box sizes match actual subsample info")
    func saizMatchesSubsampleInfo() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [testSPS], pps: [testPPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // Create a few samples with different subsample counts
        var samples: [FMP4Writer.Sample] = []

        for i in 0..<10 {
            let isIDR = (i == 0)
            let sampleData = createVideoSample(isIDR: isIDR, size: isIDR ? 50000 : 5000)
            let result = encryptor.encryptVideoSample(sampleData, nalLengthSize: 4)

            samples.append(FMP4Writer.Sample(
                data: result.encryptedData,
                duration: 3000,
                isSync: isIDR,
                subsamples: result.subsamples
            ))
        }

        let segment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Find and parse saiz box
        var offset = 0
        while offset + 8 <= segment.count {
            let sizeData = segment.subdata(in: offset..<(offset + 4))
            let size = Int(UInt32(bigEndian: sizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
            let typeData = segment.subdata(in: (offset + 4)..<(offset + 8))
            let type = String(data: typeData, encoding: .ascii) ?? "????"

            if type == "saiz" {
                // saiz: size(4) + type(4) + version(1) + flags(3) + [aux_info_type(4) + aux_info_type_parameter(4)]
                //       + default_sample_info_size(1) + sample_count(4) + [sample_info_size[]]

                var saizOffset = offset + 8
                // Skip version/flags
                let flags = UInt32(segment[saizOffset + 3])
                saizOffset += 4

                // Skip aux_info_type if present
                if flags & 0x01 != 0 {
                    saizOffset += 8
                }

                let defaultSize = segment[saizOffset]
                saizOffset += 1

                let sampleCountData = segment.subdata(in: saizOffset..<(saizOffset + 4))
                let sampleCount = UInt32(bigEndian: sampleCountData.withUnsafeBytes { $0.load(as: UInt32.self) })
                saizOffset += 4

                print("\n=== saiz Box Analysis ===")
                print("default_sample_info_size: \(defaultSize)")
                print("sample_count: \(sampleCount)")

                // If default is 0, read per-sample sizes
                if defaultSize == 0 {
                    for i in 0..<Int(sampleCount) {
                        let infoSize = segment[saizOffset + i]
                        let expectedSubsamples = samples[i].subsamples ?? []
                        let expectedSize = 2 + (expectedSubsamples.count * 6) // 2 for count, 6 per subsample

                        print("  [\(i)] saiz: \(infoSize), expected: \(expectedSize), subsamples: \(expectedSubsamples.count)")

                        #expect(Int(infoSize) == expectedSize,
                                "saiz[\(i)]=\(infoSize) should match expected \(expectedSize)")
                    }
                }
            }

            if size > 0 { offset += size } else { break }
        }
    }
}
