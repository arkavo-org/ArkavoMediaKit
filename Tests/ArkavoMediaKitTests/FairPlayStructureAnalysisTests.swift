import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - FairPlay Structure Analysis Tests

/// Deep analysis tests that dump the actual structure of generated fMP4 content
/// to identify exact issues with FairPlay playback.
@Suite("FairPlay Structure Analysis")
struct FairPlayStructureAnalysisTests {

    let sampleSPS = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78,
                          0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00, 0x03,
                          0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF2, 0x3C,
                          0x60, 0xC6, 0x58])
    let samplePPS = Data([0x68, 0xEE, 0x3C, 0x80])
    let testKeyID = Data(repeating: 0x12, count: 16)
    let testIV = Data([0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
                       0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7])

    // MARK: - Hex Dump Helper

    private func hexDump(_ data: Data, maxBytes: Int = 200) -> String {
        var result = ""
        let bytes = min(data.count, maxBytes)
        for i in stride(from: 0, to: bytes, by: 16) {
            let lineBytes = min(16, bytes - i)
            let hex = data[i..<(i + lineBytes)].map { String(format: "%02X", $0) }.joined(separator: " ")
            let ascii = data[i..<(i + lineBytes)].map { (0x20...0x7E).contains($0) ? Character(UnicodeScalar($0)) : "." }.map(String.init).joined()
            let paddedHex = hex.padding(toLength: 48, withPad: " ", startingAt: 0)
            result += String(format: "%04X: ", i) + paddedHex + " " + ascii + "\n"
        }
        if data.count > maxBytes {
            result += "... (\(data.count - maxBytes) more bytes)\n"
        }
        return result
    }

    // MARK: - Box Parsing

    private func parseAndDumpBoxes(_ data: Data, startOffset: Int = 0, indent: String = "", maxDepth: Int = 5) -> String {
        guard maxDepth > 0 else { return "" }
        var result = ""
        var offset = startOffset

        while offset + 8 <= data.count {
            let sizeData = data.subdata(in: offset..<(offset + 4))
            var size = Int(UInt32(bigEndian: sizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
            let typeData = data.subdata(in: (offset + 4)..<(offset + 8))
            guard let type = String(data: typeData, encoding: .ascii) else { break }

            var headerSize = 8
            if size == 1 && offset + 16 <= data.count {
                let extSizeData = data.subdata(in: (offset + 8)..<(offset + 16))
                size = Int(UInt64(bigEndian: extSizeData.withUnsafeBytes { $0.load(as: UInt64.self) }))
                headerSize = 16
            }

            guard size >= headerSize, offset + size <= data.count else { break }

            result += "\(indent)\(type) (size: \(size), offset: \(offset))\n"

            // Parse children for container boxes
            let containerTypes = ["moov", "moof", "trak", "mdia", "minf", "stbl", "traf", "mvex", "edts", "dinf", "sinf", "schi"]
            if containerTypes.contains(type) {
                result += parseAndDumpBoxes(data, startOffset: offset + headerSize, indent: indent + "  ", maxDepth: maxDepth - 1)
            } else if type == "stsd" {
                // stsd has special structure: version(1) + flags(3) + entry_count(4) + entries
                let entryCountOffset = offset + headerSize + 4
                if entryCountOffset + 4 <= data.count {
                    let entryCountData = data.subdata(in: entryCountOffset..<(entryCountOffset + 4))
                    let entryCount = UInt32(bigEndian: entryCountData.withUnsafeBytes { $0.load(as: UInt32.self) })
                    result += "\(indent)  (entry_count: \(entryCount))\n"
                    // Parse sample entries
                    var entryOffset = entryCountOffset + 4
                    for i in 0..<entryCount {
                        if entryOffset + 8 > offset + size { break }
                        let entrySizeData = data.subdata(in: entryOffset..<(entryOffset + 4))
                        let entrySize = Int(UInt32(bigEndian: entrySizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
                        let entryTypeData = data.subdata(in: (entryOffset + 4)..<(entryOffset + 8))
                        if let entryType = String(data: entryTypeData, encoding: .ascii) {
                            result += "\(indent)  [\(i)] \(entryType) (size: \(entrySize), offset: \(entryOffset))\n"
                            // Look for sinf inside sample entry (after fixed fields)
                            // Sample entry structure: 78 bytes fixed header + avcC + sinf
                            if entryType == "encv" || entryType == "avc1" || entryType == "hvc1" {
                                var innerOffset = entryOffset + 8 + 70 // Skip to variable part
                                while innerOffset + 8 <= entryOffset + entrySize {
                                    let innerSizeData = data.subdata(in: innerOffset..<(innerOffset + 4))
                                    let innerSize = Int(UInt32(bigEndian: innerSizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
                                    let innerTypeData = data.subdata(in: (innerOffset + 4)..<(innerOffset + 8))
                                    if let innerType = String(data: innerTypeData, encoding: .ascii), innerSize >= 8 {
                                        result += "\(indent)      \(innerType) (size: \(innerSize), offset: \(innerOffset))\n"
                                        if innerType == "sinf" {
                                            result += parseAndDumpBoxes(data, startOffset: innerOffset + 8, indent: indent + "        ", maxDepth: maxDepth - 2)
                                        }
                                    }
                                    if innerSize > 0 { innerOffset += innerSize } else { break }
                                }
                            }
                        }
                        if entrySize > 0 { entryOffset += entrySize } else { break }
                    }
                }
            }

            offset += size
        }
        return result
    }

    // MARK: - Analysis Tests

    @Test("Dump encrypted init segment structure")
    func dumpEncryptedInitStructure() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let initSegment = writer.generateInitSegment()

        print("\n" + String(repeating: "=", count: 60))
        print("ENCRYPTED INIT SEGMENT ANALYSIS")
        print("Total size: \(initSegment.count) bytes")
        print(String(repeating: "=", count: 60))

        print("\n--- Box Structure ---")
        print(parseAndDumpBoxes(initSegment))

        print("\n--- Hex Dump (first 300 bytes) ---")
        print(hexDump(initSegment, maxBytes: 300))

        // Find and dump specific boxes
        print("\n--- Sample Entry Analysis ---")
        // Search for sample entry types
        let encvMarker = Data([0x65, 0x6E, 0x63, 0x76])
        let avc1Marker = Data([0x61, 0x76, 0x63, 0x31])
        let sinfMarker = Data([0x73, 0x69, 0x6E, 0x66])
        let tencMarker = Data([0x74, 0x65, 0x6E, 0x63])
        let frmaMarker = Data([0x66, 0x72, 0x6D, 0x61])

        if let range = initSegment.range(of: encvMarker) {
            print("encv found at offset: \(range.lowerBound)")
        } else {
            print("❌ encv NOT found")
        }

        if let range = initSegment.range(of: avc1Marker) {
            print("avc1 found at offset: \(range.lowerBound) (may be in frma - original format)")
        }

        if let range = initSegment.range(of: sinfMarker) {
            print("sinf found at offset: \(range.lowerBound)")
            // Dump sinf contents
            let sinfStart = range.lowerBound - 4 // Back to size field
            if sinfStart >= 0 && sinfStart + 4 <= initSegment.count {
                let sinfSizeData = initSegment.subdata(in: sinfStart..<(sinfStart + 4))
                let sinfSize = Int(UInt32(bigEndian: sinfSizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
                if sinfStart + sinfSize <= initSegment.count {
                    print("sinf hex dump:")
                    print(hexDump(initSegment.subdata(in: sinfStart..<(sinfStart + sinfSize))))
                }
            }
        } else {
            print("❌ sinf NOT found")
        }

        if let range = initSegment.range(of: tencMarker) {
            print("tenc found at offset: \(range.lowerBound)")
        } else {
            print("❌ tenc NOT found")
        }

        if let range = initSegment.range(of: frmaMarker) {
            print("frma found at offset: \(range.lowerBound)")
        } else {
            print("❌ frma NOT found")
        }

        // This test always passes - it's for diagnostic output
        #expect(Bool(true))
    }

    @Test("Dump encrypted media segment structure")
    func dumpEncryptedMediaStructure() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0x11, count: 500), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0x22, count: 300), duration: 3000, isSync: false)
        ]
        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        print("\n" + String(repeating: "=", count: 60))
        print("ENCRYPTED MEDIA SEGMENT ANALYSIS")
        print("Total size: \(mediaSegment.count) bytes")
        print(String(repeating: "=", count: 60))

        print("\n--- Box Structure ---")
        print(parseAndDumpBoxes(mediaSegment))

        print("\n--- traf Contents ---")
        let trafMarker = Data([0x74, 0x72, 0x61, 0x66])
        if let range = mediaSegment.range(of: trafMarker) {
            let trafStart = range.lowerBound - 4
            if trafStart >= 0 && trafStart + 4 <= mediaSegment.count {
                let trafSizeData = mediaSegment.subdata(in: trafStart..<(trafStart + 4))
                let trafSize = Int(UInt32(bigEndian: trafSizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
                if trafStart + trafSize <= mediaSegment.count {
                    print("traf hex dump (first 200 bytes):")
                    let dumpSize = min(200, trafSize)
                    print(hexDump(mediaSegment.subdata(in: trafStart..<(trafStart + dumpSize))))
                }
            }
        }

        // Check for encryption boxes
        let sencMarker = Data([0x73, 0x65, 0x6E, 0x63])
        let saizMarker = Data([0x73, 0x61, 0x69, 0x7A])
        let saioMarker = Data([0x73, 0x61, 0x69, 0x6F])

        print("\n--- Encryption Boxes ---")
        if let range = mediaSegment.range(of: sencMarker) {
            print("✓ senc at offset: \(range.lowerBound)")
        } else {
            print("❌ senc NOT found")
        }

        if let range = mediaSegment.range(of: saizMarker) {
            print("✓ saiz at offset: \(range.lowerBound)")
        } else {
            print("❌ saiz NOT found")
        }

        if let range = mediaSegment.range(of: saioMarker) {
            print("✓ saio at offset: \(range.lowerBound)")
        } else {
            print("❌ saio NOT found")
        }

        #expect(Bool(true))
    }

    @Test("Verify CBCS encryption output structure")
    func verifyCBCSOutput() {
        let key = Data(repeating: 0x3C, count: 16)
        let iv = Data([0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
                       0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7])
        let encryptor = CBCSEncryptor(key: key, iv: iv)

        // Create a realistic video sample
        var sample = Data()

        // SPS NAL (type 7)
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x10]) // Length = 16
        sample.append(0x67) // NAL type 7 (SPS)
        sample.append(Data(repeating: 0xAA, count: 15))

        // PPS NAL (type 8)
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x08]) // Length = 8
        sample.append(0x68) // NAL type 8 (PPS)
        sample.append(Data(repeating: 0xBB, count: 7))

        // IDR NAL (type 5) - larger for encryption
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x60]) // Length = 96
        sample.append(0x65) // NAL type 5 (IDR)
        sample.append(Data(repeating: 0xCC, count: 95))

        print("\n" + String(repeating: "=", count: 60))
        print("CBCS ENCRYPTION OUTPUT ANALYSIS")
        print("Input size: \(sample.count) bytes")
        print(String(repeating: "=", count: 60))

        print("\n--- Input Sample ---")
        print(hexDump(sample))

        let result = encryptor.encryptVideoSample(sample, nalLengthSize: 4)

        print("\n--- Encrypted Output ---")
        print("Output size: \(result.encryptedData.count) bytes")
        print(hexDump(result.encryptedData))

        print("\n--- Subsamples ---")
        for (i, subsample) in result.subsamples.enumerated() {
            print("[\(i)] clear: \(subsample.bytesOfClearData), protected: \(subsample.bytesOfProtectedData)")
        }

        // Verify structure
        print("\n--- Verification ---")

        // Check NAL length preservation
        let nal1Len = sample[0..<4]
        let nal2Len = sample[20..<24]
        let nal3Len = sample[28..<32]

        let out1Len = result.encryptedData[0..<4]
        let out2Len = result.encryptedData[20..<24]
        let out3Len = result.encryptedData[28..<32]

        print("NAL 1 length preserved: \(nal1Len == out1Len)")
        print("NAL 2 length preserved: \(nal2Len == out2Len)")
        print("NAL 3 length preserved: \(nal3Len == out3Len)")

        // Check NAL types
        print("NAL 1 type preserved: \(sample[4] == result.encryptedData[4]) (0x\(String(format: "%02X", sample[4])) vs 0x\(String(format: "%02X", result.encryptedData[4])))")
        print("NAL 2 type preserved: \(sample[24] == result.encryptedData[24]) (0x\(String(format: "%02X", sample[24])) vs 0x\(String(format: "%02X", result.encryptedData[24])))")
        print("NAL 3 type preserved: \(sample[32] == result.encryptedData[32]) (0x\(String(format: "%02X", sample[32])) vs 0x\(String(format: "%02X", result.encryptedData[32])))")

        // Check that non-VCL NALs are unchanged
        let spsUnchanged = sample[0..<20] == result.encryptedData[0..<20]
        let ppsUnchanged = sample[20..<28] == result.encryptedData[20..<28]
        print("SPS unchanged: \(spsUnchanged)")
        print("PPS unchanged: \(ppsUnchanged)")

        // Verify subsamples total matches output size
        let totalFromSubsamples = result.subsamples.reduce(0) { $0 + Int($1.bytesOfClearData) + Int($1.bytesOfProtectedData) }
        print("Subsamples total: \(totalFromSubsamples), output size: \(result.encryptedData.count)")

        #expect(result.encryptedData.count == sample.count, "Output size must match input size")
        #expect(totalFromSubsamples == result.encryptedData.count, "Subsamples must account for all bytes")
    }

    @Test("Compare unencrypted vs encrypted stsd")
    func compareStsdStructure() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )

        // Unencrypted
        let unencryptedWriter = FMP4Writer(tracks: [track])
        let unencryptedInit = unencryptedWriter.generateInitSegment()

        // Encrypted
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let encryptedWriter = FMP4Writer(tracks: [track], encryption: encryption)
        let encryptedInit = encryptedWriter.generateInitSegment()

        print("\n" + String(repeating: "=", count: 60))
        print("STSD STRUCTURE COMPARISON")
        print(String(repeating: "=", count: 60))

        // Find stsd in each
        let stsdMarker = Data([0x73, 0x74, 0x73, 0x64])

        print("\n--- Unencrypted stsd ---")
        if let range = unencryptedInit.range(of: stsdMarker) {
            let stsdStart = range.lowerBound - 4
            if stsdStart >= 0 {
                let stsdSizeData = unencryptedInit.subdata(in: stsdStart..<(stsdStart + 4))
                let stsdSize = Int(UInt32(bigEndian: stsdSizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
                print("stsd at offset \(stsdStart), size \(stsdSize)")
                if stsdStart + stsdSize <= unencryptedInit.count {
                    print(hexDump(unencryptedInit.subdata(in: stsdStart..<(stsdStart + min(stsdSize, 150)))))
                }
            }
        }

        print("\n--- Encrypted stsd ---")
        if let range = encryptedInit.range(of: stsdMarker) {
            let stsdStart = range.lowerBound - 4
            if stsdStart >= 0 {
                let stsdSizeData = encryptedInit.subdata(in: stsdStart..<(stsdStart + 4))
                let stsdSize = Int(UInt32(bigEndian: stsdSizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
                print("stsd at offset \(stsdStart), size \(stsdSize)")
                if stsdStart + stsdSize <= encryptedInit.count {
                    print(hexDump(encryptedInit.subdata(in: stsdStart..<(stsdStart + min(stsdSize, 300)))))
                }
            }
        }

        // Check for sample entry types
        let avc1Marker = Data([0x61, 0x76, 0x63, 0x31])
        let encvMarker = Data([0x65, 0x6E, 0x63, 0x76])

        print("\n--- Sample Entry Types ---")
        print("Unencrypted has avc1: \(unencryptedInit.range(of: avc1Marker) != nil)")
        print("Unencrypted has encv: \(unencryptedInit.range(of: encvMarker) != nil)")
        print("Encrypted has avc1: \(encryptedInit.range(of: avc1Marker) != nil) (expected in frma)")
        print("Encrypted has encv: \(encryptedInit.range(of: encvMarker) != nil)")

        // Check size difference
        print("\nSize difference: \(encryptedInit.count - unencryptedInit.count) bytes")
        print("Expected extra: sinf(~100) + pssh(~50) = ~150 bytes")

        #expect(encryptedInit.range(of: encvMarker) != nil, "Encrypted should have encv")
        #expect(encryptedInit.count > unencryptedInit.count, "Encrypted should be larger due to sinf/pssh")
    }

    // MARK: - Additional Box Parsing Helpers

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

    private func findBox(_ data: Data, type: String, startingAt start: Int = 0, endAt end: Int? = nil) -> (offset: Int, size: Int)? {
        let endOffset = end ?? data.count
        var offset = start
        while offset + 8 <= endOffset {
            guard let header = parseBoxHeader(data, at: offset) else { break }
            if header.type == type { return (offset, header.size) }
            if header.size > 0 { offset += header.size } else { break }
        }
        return nil
    }

    private func findBoxRecursive(_ data: Data, type: String, startingAt start: Int = 0, endAt end: Int? = nil) -> (offset: Int, size: Int)? {
        let endOffset = end ?? data.count
        var offset = start
        while offset + 8 <= endOffset {
            guard let header = parseBoxHeader(data, at: offset) else { break }
            if header.type == type { return (offset, header.size) }

            let containerTypes = ["moov", "moof", "trak", "mdia", "minf", "stbl", "traf", "mvex", "edts", "dinf", "sinf", "schi"]
            if containerTypes.contains(header.type) {
                let boxEnd = min(offset + header.size, endOffset)
                if let found = findBoxRecursive(data, type: type, startingAt: offset + header.headerSize, endAt: boxEnd) {
                    return found
                }
            } else if header.type == "stsd" {
                let entryCountOffset = offset + 8 + 4
                if entryCountOffset + 4 <= endOffset {
                    let entryCountData = data.subdata(in: entryCountOffset..<(entryCountOffset + 4))
                    let entryCount = UInt32(bigEndian: entryCountData.withUnsafeBytes { $0.load(as: UInt32.self) })
                    var entryOffset = entryCountOffset + 4
                    let stsdEnd = min(offset + header.size, endOffset)

                    for _ in 0..<entryCount {
                        if entryOffset + 8 > stsdEnd { break }
                        guard let entryHeader = parseBoxHeader(data, at: entryOffset) else { break }

                        let sampleEntryTypes = ["avc1", "encv", "hvc1", "hev1", "mp4a", "enca"]
                        if sampleEntryTypes.contains(entryHeader.type) {
                            let isVideo = ["avc1", "encv", "hvc1", "hev1"].contains(entryHeader.type)
                            let fixedHeaderSize = isVideo ? 86 : 36
                            let nestedStart = entryOffset + fixedHeaderSize
                            let entryEnd = min(entryOffset + entryHeader.size, stsdEnd)

                            if nestedStart < entryEnd {
                                if let found = findBoxRecursive(data, type: type, startingAt: nestedStart, endAt: entryEnd) {
                                    return found
                                }
                            }
                        }
                        if entryHeader.size > 0 { entryOffset += entryHeader.size } else { break }
                    }
                }
            }
            if header.size > 0 { offset += header.size } else { break }
        }
        return nil
    }

    private func readUInt32BE(_ data: Data, at offset: Int) -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        return data.subdata(in: offset..<(offset + 4)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    }

    private func readUInt64BE(_ data: Data, at offset: Int) -> UInt64? {
        guard offset + 8 <= data.count else { return nil }
        return data.subdata(in: offset..<(offset + 8)).withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
    }

    private func readUInt16BE(_ data: Data, at offset: Int) -> UInt16? {
        guard offset + 2 <= data.count else { return nil }
        return data.subdata(in: offset..<(offset + 2)).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
    }

    private func readInt32BE(_ data: Data, at offset: Int) -> Int32? {
        guard offset + 4 <= data.count else { return nil }
        return data.subdata(in: offset..<(offset + 4)).withUnsafeBytes { $0.load(as: Int32.self).bigEndian }
    }

    // MARK: - CRITICAL: saio Offset Accuracy Test

    @Test("CRITICAL: saio offset points exactly to senc sample auxiliary data")
    func saioOffsetAccuracy() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let sampleData = Data(repeating: 0xAA, count: 1000)
        let samples = [FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: true)]
        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        print("\n" + String(repeating: "=", count: 60))
        print("🔍 CRITICAL: saio offset validation")
        print("   Media segment size: \(mediaSegment.count) bytes")
        print(String(repeating: "=", count: 60))

        // Find moof (should be at offset 0)
        guard let moofInfo = findBox(mediaSegment, type: "moof") else {
            Issue.record("Missing moof box")
            return
        }
        print("\n   moof: offset=\(moofInfo.offset), size=\(moofInfo.size)")

        // Find saio box
        guard let saioInfo = findBoxRecursive(mediaSegment, type: "saio") else {
            Issue.record("Missing saio box")
            return
        }

        // Parse saio to get the offset value
        let saioData = mediaSegment.subdata(in: saioInfo.offset..<(saioInfo.offset + saioInfo.size))
        let saioVersion = saioData[8]
        let saioFlags = (UInt32(saioData[9]) << 16) | (UInt32(saioData[10]) << 8) | UInt32(saioData[11])

        print("   saio: offset=\(saioInfo.offset), size=\(saioInfo.size), version=\(saioVersion), flags=0x\(String(format: "%06x", saioFlags))")

        var saioDataOffset = 12
        if saioFlags & 0x01 != 0 {
            saioDataOffset += 8
        }

        guard let entryCount = readUInt32BE(saioData, at: saioDataOffset) else {
            Issue.record("Cannot read saio entry_count")
            return
        }
        saioDataOffset += 4
        print("   saio entry_count: \(entryCount)")

        let sencOffset: Int
        if saioVersion == 0 {
            guard let offset32 = readUInt32BE(saioData, at: saioDataOffset) else {
                Issue.record("Cannot read saio offset")
                return
            }
            sencOffset = Int(offset32)
        } else {
            guard let offset64 = readUInt64BE(saioData, at: saioDataOffset) else {
                Issue.record("Cannot read saio offset")
                return
            }
            sencOffset = Int(offset64)
        }
        print("   saio offset value: \(sencOffset) (relative to moof start)")

        // Find senc box
        guard let sencInfo = findBoxRecursive(mediaSegment, type: "senc") else {
            Issue.record("Missing senc box")
            return
        }
        print("   senc: offset=\(sencInfo.offset), size=\(sencInfo.size)")

        // senc header: 8 (box header) + 1 (version) + 3 (flags) + 4 (sample_count) = 16 bytes
        let sencHeaderSize = 16
        let expectedSencDataOffset = sencInfo.offset + sencHeaderSize
        let actualTargetOffset = moofInfo.offset + sencOffset

        print("\n   📐 Offset calculation:")
        print("      moof start: \(moofInfo.offset)")
        print("      saio offset value: \(sencOffset)")
        print("      Expected target (moof + saio_offset): \(actualTargetOffset)")
        print("      senc box offset: \(sencInfo.offset)")
        print("      senc header size: \(sencHeaderSize)")
        print("      Expected senc data offset: \(expectedSencDataOffset)")
        print("      Delta: \(actualTargetOffset - expectedSencDataOffset)")

        #expect(actualTargetOffset == expectedSencDataOffset,
                "saio offset should point to senc data. Expected \(expectedSencDataOffset), got \(actualTargetOffset). Delta: \(actualTargetOffset - expectedSencDataOffset)")

        if actualTargetOffset == expectedSencDataOffset {
            print("\n✅ saio offset correctly points to senc sample auxiliary data!")
        } else {
            print("\n❌ saio offset MISMATCH - this is likely causing AVPlayer playback failure!")
            print("   The player will read encryption metadata from the wrong location.")
        }
    }

    // MARK: - saiz/senc Consistency Test

    @Test("saiz sample info sizes match senc entry sizes")
    func saizSencConsistency() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let sampleData = Data(repeating: 0xAA, count: 1000)
        let samples = [
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: true),
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: false),
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: false)
        ]
        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        print("\n" + String(repeating: "=", count: 60))
        print("🔍 saiz/senc consistency validation")
        print(String(repeating: "=", count: 60))

        // Find saiz box
        guard let saizInfo = findBoxRecursive(mediaSegment, type: "saiz") else {
            Issue.record("Missing saiz box")
            return
        }

        let saizData = mediaSegment.subdata(in: saizInfo.offset..<(saizInfo.offset + saizInfo.size))
        let saizFlags = (UInt32(saizData[9]) << 16) | (UInt32(saizData[10]) << 8) | UInt32(saizData[11])

        var saizDataOffset = 12
        if saizFlags & 0x01 != 0 {
            saizDataOffset += 8
        }

        let defaultSampleInfoSize = saizData[saizDataOffset]
        saizDataOffset += 1

        guard let saizSampleCount = readUInt32BE(saizData, at: saizDataOffset) else {
            Issue.record("Cannot read saiz sample_count")
            return
        }
        saizDataOffset += 4

        print("\n   saiz: defaultSampleInfoSize=\(defaultSampleInfoSize), sampleCount=\(saizSampleCount)")

        var sampleInfoSizes: [UInt8] = []
        if defaultSampleInfoSize == 0 {
            for i in 0..<Int(saizSampleCount) {
                if saizDataOffset + i < saizData.count {
                    sampleInfoSizes.append(saizData[saizDataOffset + i])
                }
            }
        } else {
            sampleInfoSizes = Array(repeating: defaultSampleInfoSize, count: Int(saizSampleCount))
        }

        print("   Sample info sizes: \(sampleInfoSizes)")

        // Find senc and verify
        guard let sencInfo = findBoxRecursive(mediaSegment, type: "senc") else {
            Issue.record("Missing senc box")
            return
        }

        let sencData = mediaSegment.subdata(in: sencInfo.offset..<(sencInfo.offset + sencInfo.size))
        let sencFlags = (UInt32(sencData[9]) << 16) | (UInt32(sencData[10]) << 8) | UInt32(sencData[11])
        let useSubsampleEncryption = (sencFlags & 0x02) != 0

        guard let sencSampleCount = readUInt32BE(sencData, at: 12) else {
            Issue.record("Cannot read senc sample_count")
            return
        }

        print("   senc: flags=0x\(String(format: "%06x", sencFlags)), sampleCount=\(sencSampleCount), subsampleEncryption=\(useSubsampleEncryption)")

        #expect(saizSampleCount == sencSampleCount, "saiz and senc sample counts must match")

        // Walk through senc entries
        var sencOffset = 16
        var allMatch = true
        for i in 0..<Int(sencSampleCount) {
            let expectedSize = Int(sampleInfoSizes[i])

            guard let subsampleCount = readUInt16BE(sencData, at: sencOffset) else {
                Issue.record("Cannot read subsample_count for sample \(i)")
                return
            }

            let actualSize = 2 + (Int(subsampleCount) * 6)
            print("   Sample \(i): expected_size=\(expectedSize), actual_size=\(actualSize), subsamples=\(subsampleCount)")

            if actualSize != expectedSize {
                allMatch = false
            }
            #expect(actualSize == expectedSize, "Sample \(i): saiz size (\(expectedSize)) doesn't match senc entry size (\(actualSize))")

            sencOffset += actualSize
        }

        if allMatch {
            print("\n✅ saiz/senc consistency verified - all sizes match")
        } else {
            print("\n❌ saiz/senc MISMATCH - this will cause AVPlayer to read wrong encryption metadata")
        }
    }

    // MARK: - senc Walkthrough (Simulating AVPlayer)

    @Test("senc walkthrough simulates AVPlayer reading encryption metadata")
    func sencWalkthrough() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let sampleData = Data(repeating: 0xAA, count: 500)
        let samples = [
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: true),
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: false)
        ]
        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        print("\n" + String(repeating: "=", count: 60))
        print("🔍 senc walkthrough - simulating AVPlayer behavior")
        print(String(repeating: "=", count: 60))

        guard let moofInfo = findBox(mediaSegment, type: "moof") else {
            Issue.record("Missing moof")
            return
        }

        guard let saioInfo = findBoxRecursive(mediaSegment, type: "saio"),
              let saizInfo = findBoxRecursive(mediaSegment, type: "saiz") else {
            Issue.record("Missing encryption boxes")
            return
        }

        // Read saio offset
        let saioData = mediaSegment.subdata(in: saioInfo.offset..<(saioInfo.offset + saioInfo.size))
        let saioVersion = saioData[8]
        let saioFlags = (UInt32(saioData[9]) << 16) | (UInt32(saioData[10]) << 8) | UInt32(saioData[11])
        var saioReadOffset = 12 + (saioFlags & 0x01 != 0 ? 8 : 0)
        guard readUInt32BE(saioData, at: saioReadOffset) != nil else { return }
        saioReadOffset += 4

        let auxInfoOffset: Int
        if saioVersion == 0 {
            guard let o = readUInt32BE(saioData, at: saioReadOffset) else { return }
            auxInfoOffset = Int(o)
        } else {
            guard let o = readUInt64BE(saioData, at: saioReadOffset) else { return }
            auxInfoOffset = Int(o)
        }

        // Read saiz sizes
        let saizData = mediaSegment.subdata(in: saizInfo.offset..<(saizInfo.offset + saizInfo.size))
        let saizFlags = (UInt32(saizData[9]) << 16) | (UInt32(saizData[10]) << 8) | UInt32(saizData[11])
        var saizReadOffset = 12 + (saizFlags & 0x01 != 0 ? 8 : 0)
        let defaultSize = saizData[saizReadOffset]
        saizReadOffset += 1
        guard let sampleCount = readUInt32BE(saizData, at: saizReadOffset) else { return }
        saizReadOffset += 4

        var sizes: [Int] = []
        if defaultSize == 0 {
            for i in 0..<Int(sampleCount) {
                sizes.append(Int(saizData[saizReadOffset + i]))
            }
        } else {
            sizes = Array(repeating: Int(defaultSize), count: Int(sampleCount))
        }

        print("\n   📖 AVPlayer would read:")
        print("   1. saio offset = \(auxInfoOffset) (relative to moof at \(moofInfo.offset))")
        print("   2. saiz sizes = \(sizes) for \(sampleCount) samples")

        // Simulate walking through senc data
        var currentOffset = moofInfo.offset + auxInfoOffset
        print("\n   3. Walking through senc data starting at absolute offset \(currentOffset):")

        var walkSuccessful = true
        for i in 0..<Int(sampleCount) {
            let size = sizes[i]
            print("\n      Sample \(i):")
            print("         Read from offset: \(currentOffset)")
            print("         Size to read: \(size) bytes")

            guard currentOffset + size <= mediaSegment.count else {
                Issue.record("Sample \(i): Read would exceed segment bounds")
                walkSuccessful = false
                break
            }

            let entryData = mediaSegment.subdata(in: currentOffset..<(currentOffset + size))
            print("         Raw bytes: \(entryData.map { String(format: "%02x", $0) }.joined(separator: " "))")

            guard let subsampleCount = readUInt16BE(entryData, at: 0) else {
                Issue.record("Cannot read subsample_count")
                walkSuccessful = false
                break
            }
            print("         Subsample count: \(subsampleCount)")

            var subsampleOffset = 2
            var totalClear = 0
            var totalProtected = 0
            for j in 0..<Int(subsampleCount) {
                guard let clearBytes = readUInt16BE(entryData, at: subsampleOffset) else { break }
                subsampleOffset += 2
                guard let protectedBytes = readUInt32BE(entryData, at: subsampleOffset) else { break }
                subsampleOffset += 4
                print("            Subsample \(j): clear=\(clearBytes), protected=\(protectedBytes)")
                totalClear += Int(clearBytes)
                totalProtected += Int(protectedBytes)
            }
            print("         Total: clear=\(totalClear), protected=\(totalProtected)")

            currentOffset += size
        }

        #expect(walkSuccessful, "senc walkthrough should complete without errors")

        if walkSuccessful {
            print("\n✅ senc walkthrough complete - AVPlayer should be able to read encryption metadata correctly")
        }
    }

    // MARK: - tenc Byte-Level Structure Test

    @Test("tenc box has correct byte-level structure for CBCS")
    func tencByteStructure() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(
            keyID: testKeyID,
            constantIV: testIV,
            cryptByteBlock: 1,
            skipByteBlock: 9
        )
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let initSegment = writer.generateInitSegment()

        guard let tencInfo = findBoxRecursive(initSegment, type: "tenc") else {
            Issue.record("Missing tenc box")
            return
        }

        let tencData = initSegment.subdata(in: tencInfo.offset..<(tencInfo.offset + tencInfo.size))
        print("\n" + String(repeating: "=", count: 60))
        print("📦 tenc byte-level structure analysis")
        print("   Offset: \(tencInfo.offset), Size: \(tencInfo.size)")
        print("   Hex: \(tencData.map { String(format: "%02x", $0) }.joined(separator: " "))")
        print(String(repeating: "=", count: 60))

        // Version (offset 8)
        let version = tencData[8]
        #expect(version == 1, "tenc version should be 1 for CBCS pattern encryption, got \(version)")
        print("\n   Version: \(version) (expected: 1)")

        // Flags (offset 9-11)
        let flags = (UInt32(tencData[9]) << 16) | (UInt32(tencData[10]) << 8) | UInt32(tencData[11])
        #expect(flags == 0, "tenc flags should be 0, got \(flags)")
        print("   Flags: \(flags) (expected: 0)")

        // Reserved (offset 12)
        let reserved = tencData[12]
        #expect(reserved == 0, "reserved byte should be 0, got \(reserved)")
        print("   Reserved: \(reserved) (expected: 0)")

        // Pattern byte (offset 13)
        let patternByte = tencData[13]
        let cryptBlocks = (patternByte >> 4) & 0x0F
        let skipBlocks = patternByte & 0x0F
        #expect(cryptBlocks == 1, "crypt_byte_block should be 1, got \(cryptBlocks)")
        #expect(skipBlocks == 9, "skip_byte_block should be 9, got \(skipBlocks)")
        print("   Pattern: 0x\(String(format: "%02x", patternByte)) (crypt=\(cryptBlocks), skip=\(skipBlocks))")

        // defaultIsProtected (offset 14)
        let isProtected = tencData[14]
        #expect(isProtected == 1, "defaultIsProtected should be 1, got \(isProtected)")
        print("   defaultIsProtected: \(isProtected) (expected: 1)")

        // defaultPerSampleIVSize (offset 15)
        let perSampleIVSize = tencData[15]
        #expect(perSampleIVSize == 0, "defaultPerSampleIVSize should be 0 for constant IV, got \(perSampleIVSize)")
        print("   defaultPerSampleIVSize: \(perSampleIVSize) (expected: 0)")

        // defaultKID (offset 16-31)
        guard tencInfo.size >= 32 else {
            Issue.record("tenc too small for KID")
            return
        }
        let kidData = tencData.subdata(in: 16..<32)
        #expect(kidData == testKeyID, "defaultKID mismatch")
        print("   defaultKID: \(kidData.map { String(format: "%02x", $0) }.joined())")

        // defaultConstantIVSize (offset 32)
        guard tencInfo.size >= 33 else {
            Issue.record("tenc too small for constantIVSize")
            return
        }
        let constantIVSize = tencData[32]
        #expect(constantIVSize == 16, "defaultConstantIVSize should be 16, got \(constantIVSize)")
        print("   defaultConstantIVSize: \(constantIVSize) (expected: 16)")

        // defaultConstantIV (offset 33-48)
        guard tencInfo.size >= 49 else {
            Issue.record("tenc too small for constantIV")
            return
        }
        let constantIVData = tencData.subdata(in: 33..<49)
        #expect(constantIVData == testIV, "defaultConstantIV mismatch")
        print("   defaultConstantIV: \(constantIVData.map { String(format: "%02x", $0) }.joined())")

        print("\n✅ tenc byte structure is correct for CBCS with constant IV")
    }

    // MARK: - tfhd Flags Validation

    @Test("tfhd has correct flags for CBCS playback")
    func tfhdFlags() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let samples = [FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)]
        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        print("\n" + String(repeating: "=", count: 60))
        print("🔍 tfhd flags validation")
        print(String(repeating: "=", count: 60))

        guard let tfhdInfo = findBoxRecursive(mediaSegment, type: "tfhd") else {
            Issue.record("Missing tfhd")
            return
        }

        let tfhdData = mediaSegment.subdata(in: tfhdInfo.offset..<(tfhdInfo.offset + tfhdInfo.size))
        let flags = (UInt32(tfhdData[9]) << 16) | (UInt32(tfhdData[10]) << 8) | UInt32(tfhdData[11])

        print("\n   tfhd flags: 0x\(String(format: "%06x", flags))")

        let defaultBaseIsMoof = (flags & 0x020000) != 0
        let sampleDescIndexPresent = (flags & 0x000002) != 0

        print("   default-base-is-moof (0x020000): \(defaultBaseIsMoof)")
        print("   sample-description-index-present (0x000002): \(sampleDescIndexPresent)")

        #expect(defaultBaseIsMoof, "default-base-is-moof flag MUST be set for CBCS. Without this, saio offsets are wrong.")
        #expect(sampleDescIndexPresent, "sample-description-index-present should be set")

        if sampleDescIndexPresent {
            guard let sampleDescIndex = readUInt32BE(tfhdData, at: 16) else {
                Issue.record("Cannot read sample_description_index")
                return
            }
            print("   sample_description_index: \(sampleDescIndex) (should be 1)")
            #expect(sampleDescIndex == 1, "sample_description_index should be 1")
        }

        print("\n✅ tfhd flags are correct for CBCS playback")
    }

    // MARK: - schm Box Validation

    @Test("schm box contains correct CBCS scheme type")
    func schmSchemeType() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let initSegment = writer.generateInitSegment()

        guard let schmInfo = findBoxRecursive(initSegment, type: "schm") else {
            Issue.record("Missing schm box")
            return
        }

        let schmData = initSegment.subdata(in: schmInfo.offset..<(schmInfo.offset + schmInfo.size))
        print("\n" + String(repeating: "=", count: 60))
        print("📦 schm box analysis")
        print("   Hex: \(schmData.map { String(format: "%02x", $0) }.joined(separator: " "))")
        print(String(repeating: "=", count: 60))

        let version = schmData[8]
        #expect(version == 0, "schm version should be 0, got \(version)")
        print("\n   Version: \(version)")

        let schemeTypeData = schmData.subdata(in: 12..<16)
        let schemeType = String(data: schemeTypeData, encoding: .ascii)
        #expect(schemeType == "cbcs", "scheme_type should be 'cbcs', got '\(schemeType ?? "nil")'")
        print("   scheme_type: '\(schemeType ?? "nil")' (expected: 'cbcs')")

        guard let schemeVersion = readUInt32BE(schmData, at: 16) else {
            Issue.record("Cannot read scheme_version")
            return
        }
        #expect(schemeVersion == 0x00010000, "scheme_version should be 0x00010000, got 0x\(String(format: "%08x", schemeVersion))")
        print("   scheme_version: 0x\(String(format: "%08x", schemeVersion)) (expected: 0x00010000)")

        print("\n✅ schm box contains correct CBCS scheme")
    }
}
