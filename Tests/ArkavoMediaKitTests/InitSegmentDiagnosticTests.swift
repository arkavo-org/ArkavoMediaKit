import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - Init Segment Diagnostic Tests

/// Diagnostic tests to validate init segment structure for FairPlay playback
@Suite("Init Segment Diagnostics")
struct InitSegmentDiagnosticTests {

    // Sample codec configuration from real video
    let realSPS = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78,
                        0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00, 0x03,
                        0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF2, 0x3C,
                        0x60, 0xC6, 0x58])
    let realPPS = Data([0x68, 0xEE, 0x3C, 0x80])
    let testKeyID = Data(repeating: 0x12, count: 16)
    let testIV = Data([0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
                       0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7])

    // MARK: - Box Parsing Helpers

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

    private func hexDump(_ data: Data, maxBytes: Int = 100) -> String {
        var result = ""
        let bytes = min(data.count, maxBytes)
        for i in stride(from: 0, to: bytes, by: 16) {
            let lineBytes = min(16, bytes - i)
            let hex = data[i..<(i + lineBytes)].map { String(format: "%02X", $0) }.joined(separator: " ")
            result += String(format: "%04X: %@\n", i, hex)
        }
        if data.count > maxBytes {
            result += "... (\(data.count - maxBytes) more bytes)\n"
        }
        return result
    }

    // MARK: - Diagnostic Tests

    @Test("Validate encrypted init segment box hierarchy")
    func validateEncryptedInitHierarchy() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [realSPS], pps: [realPPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let initSegment = writer.generateInitSegment()

        print("\n=== ENCRYPTED INIT SEGMENT DIAGNOSTIC ===")
        print("Total size: \(initSegment.count) bytes")

        // Parse and validate box hierarchy
        var offset = 0
        var boxPath: [String] = []

        func parseAndValidate(_ data: Data, startOffset: Int, endOffset: Int, depth: Int) {
            var offset = startOffset
            let indent = String(repeating: "  ", count: depth)

            while offset + 8 <= endOffset {
                guard let header = parseBoxHeader(data, at: offset) else { break }
                guard header.size >= 8 && offset + header.size <= endOffset else {
                    print("\(indent)❌ Invalid box at offset \(offset): size=\(header.size), type=\(header.type)")
                    break
                }

                print("\(indent)✓ \(header.type) (size: \(header.size), offset: \(offset))")

                // Validate specific boxes
                if header.type == "stsd" {
                    validateStsd(data, at: offset, size: header.size, indent: indent + "  ")
                } else if header.type == "tenc" {
                    validateTenc(data, at: offset, size: header.size, indent: indent + "  ")
                } else if header.type == "pssh" {
                    validatePssh(data, at: offset, size: header.size, indent: indent + "  ")
                }

                // Recurse into containers
                let containers = ["moov", "trak", "mdia", "minf", "stbl", "edts", "mvex", "dinf", "sinf", "schi"]
                if containers.contains(header.type) {
                    parseAndValidate(data, startOffset: offset + header.headerSize, endOffset: offset + header.size, depth: depth + 1)
                }

                offset += header.size
            }
        }

        parseAndValidate(initSegment, startOffset: 0, endOffset: initSegment.count, depth: 0)

        // Validate critical elements exist
        let encvMarker = Data([0x65, 0x6E, 0x63, 0x76])
        let sinfMarker = Data([0x73, 0x69, 0x6E, 0x66])
        let tencMarker = Data([0x74, 0x65, 0x6E, 0x63])
        let psshMarker = Data([0x70, 0x73, 0x73, 0x68])

        print("\n=== Critical Box Verification ===")
        print("encv present: \(initSegment.range(of: encvMarker) != nil)")
        print("sinf present: \(initSegment.range(of: sinfMarker) != nil)")
        print("tenc present: \(initSegment.range(of: tencMarker) != nil)")
        print("pssh present: \(initSegment.range(of: psshMarker) != nil)")

        #expect(initSegment.range(of: encvMarker) != nil, "Must have encv sample entry")
        #expect(initSegment.range(of: sinfMarker) != nil, "Must have sinf box")
        #expect(initSegment.range(of: tencMarker) != nil, "Must have tenc box")
        #expect(initSegment.range(of: psshMarker) != nil, "Must have pssh box")
    }

    private func validateStsd(_ data: Data, at offset: Int, size: Int, indent: String) {
        // stsd: size(4) + type(4) + version(1) + flags(3) + entry_count(4) + entries
        let entryCountOffset = offset + 12
        guard entryCountOffset + 4 <= data.count else { return }

        let entryCountData = data.subdata(in: entryCountOffset..<(entryCountOffset + 4))
        let entryCount = UInt32(bigEndian: entryCountData.withUnsafeBytes { $0.load(as: UInt32.self) })
        print("\(indent)entry_count: \(entryCount)")

        var entryOffset = entryCountOffset + 4
        for i in 0..<entryCount {
            guard let entryHeader = parseBoxHeader(data, at: entryOffset) else { break }
            print("\(indent)[\(i)] \(entryHeader.type) (size: \(entryHeader.size))")

            // For encv, check what's inside
            if entryHeader.type == "encv" {
                // Video sample entry: 78 bytes fixed payload after 8-byte header
                let nestedStart = entryOffset + 86
                let entryEnd = entryOffset + entryHeader.size
                print("\(indent)  Nested boxes starting at offset \(nestedStart):")

                var nestedOffset = nestedStart
                while nestedOffset + 8 <= entryEnd {
                    guard let nestedHeader = parseBoxHeader(data, at: nestedOffset) else { break }
                    guard nestedHeader.size >= 8 else { break }
                    print("\(indent)    \(nestedHeader.type) (size: \(nestedHeader.size))")
                    nestedOffset += nestedHeader.size
                }
            }

            entryOffset += entryHeader.size
        }
    }

    private func validateTenc(_ data: Data, at offset: Int, size: Int, indent: String) {
        // tenc: size(4) + type(4) + version(1) + flags(3) + reserved(1) + pattern/reserved(1)
        //       + default_isProtected(1) + default_Per_Sample_IV_Size(1) + default_KID(16)
        //       + [default_constant_IV_size(1) + default_constant_IV(N)] if IV size is 0

        guard offset + 24 <= data.count else { return }

        let version = data[offset + 8]
        let patternByte = data[offset + 13]
        let cryptBlocks = (patternByte >> 4) & 0x0F
        let skipBlocks = patternByte & 0x0F
        let isProtected = data[offset + 14]
        let ivSize = data[offset + 15]
        let keyID = data.subdata(in: (offset + 16)..<(offset + 32))

        print("\(indent)version: \(version)")
        print("\(indent)pattern: crypt=\(cryptBlocks), skip=\(skipBlocks)")
        print("\(indent)isProtected: \(isProtected)")
        print("\(indent)perSampleIVSize: \(ivSize)")
        print("\(indent)keyID: \(keyID.map { String(format: "%02X", $0) }.joined())")

        if ivSize == 0 && offset + 33 <= data.count {
            let constantIVSize = data[offset + 32]
            print("\(indent)constantIVSize: \(constantIVSize)")
            if constantIVSize > 0 && offset + 33 + Int(constantIVSize) <= data.count {
                let constantIV = data.subdata(in: (offset + 33)..<(offset + 33 + Int(constantIVSize)))
                print("\(indent)constantIV: \(constantIV.map { String(format: "%02X", $0) }.joined())")
            }
        }

        #expect(isProtected == 1, "Content should be protected")
        #expect(cryptBlocks == 1 && skipBlocks == 9, "CBCS pattern should be 1:9")
    }

    private func validatePssh(_ data: Data, at offset: Int, size: Int, indent: String) {
        // pssh: size(4) + type(4) + version(1) + flags(3) + systemID(16) + [KID_count(4) + KIDs] + dataSize(4) + data

        guard offset + 28 <= data.count else { return }

        let version = data[offset + 8]
        let systemID = data.subdata(in: (offset + 12)..<(offset + 28))

        print("\(indent)version: \(version)")
        print("\(indent)systemID: \(systemID.map { String(format: "%02X", $0) }.joined())")

        let fairPlayID = Data([0x94, 0xCE, 0x86, 0xFB, 0x07, 0xFF, 0x4F, 0x43,
                               0xAD, 0xB8, 0x93, 0xD2, 0xFA, 0x96, 0x8C, 0xA2])
        #expect(systemID == fairPlayID, "pssh should have FairPlay system ID")
    }

    @Test("Dump init segment hex for manual inspection")
    func dumpInitSegmentHex() {
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [realSPS], pps: [realPPS]
        )
        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let writer = FMP4Writer(tracks: [track], encryption: encryption)
        let initSegment = writer.generateInitSegment()

        print("\n=== INIT SEGMENT HEX DUMP ===")
        print("Size: \(initSegment.count) bytes")
        print(hexDump(initSegment, maxBytes: 200))

        // Find and dump stsd area
        let stsdMarker = Data([0x73, 0x74, 0x73, 0x64])
        if let range = initSegment.range(of: stsdMarker) {
            let stsdOffset = range.lowerBound - 4
            print("\n=== STSD BOX (at offset \(stsdOffset)) ===")
            let stsdSizeData = initSegment.subdata(in: stsdOffset..<(stsdOffset + 4))
            let stsdSize = Int(UInt32(bigEndian: stsdSizeData.withUnsafeBytes { $0.load(as: UInt32.self) }))
            let dumpEnd = min(stsdOffset + stsdSize, initSegment.count)
            print(hexDump(initSegment.subdata(in: stsdOffset..<dumpEnd), maxBytes: 300))
        }

        #expect(Bool(true))
    }
}
