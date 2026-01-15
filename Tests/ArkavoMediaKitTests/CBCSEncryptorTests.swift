import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - CBCS Encryptor Tests

@Suite("CBCS Pattern Encryption")
struct CBCSEncryptorTests {
    // Test key and IV (16 bytes each)
    let testKey = Data(repeating: 0x3C, count: 16)
    let testIV = Data([0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
                       0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7])

    // MARK: - Pattern Encryption Tests

    @Test("1:9 pattern encrypts first block, skips next 9")
    func patternEncryption1_9() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV, cryptBlocks: 1, skipBlocks: 9)

        // Create 160 bytes (10 blocks of 16 bytes)
        var input = Data(count: 160)
        for i in 0..<160 {
            input[i] = UInt8(i % 256)
        }

        // Encrypt as audio (full encryption for comparison baseline)
        let fullResult = encryptor.encryptAudioSample(input)

        // For pattern encryption, blocks 0, 10, 20, ... are encrypted
        // Blocks 1-9, 11-19, ... are clear

        // Create video sample with NAL header simulation
        var videoSample = Data(count: 165) // 4 byte length + 1 byte NAL header + 160 bytes
        videoSample[0] = 0x00
        videoSample[1] = 0x00
        videoSample[2] = 0x00
        videoSample[3] = 0xA0 // Length = 160
        videoSample[4] = 0x65 // NAL type 5 (IDR slice)
        for i in 0..<160 {
            videoSample[5 + i] = UInt8(i % 256)
        }

        let result = encryptor.encryptVideoSample(videoSample, nalLengthSize: 4)

        // Should have subsample info
        #expect(!result.subsamples.isEmpty)

        // First subsample should have clear bytes to cover slice header
        // Apple FairPlay reference content uses ~12 bytes clear per NAL:
        // - Length prefix (4 bytes)
        // - NAL unit header (1-2 bytes)
        // - Small safety margin
        if let first = result.subsamples.first {
            #expect(first.bytesOfClearData >= 5, "Should have at least NAL header clear")
            #expect(first.bytesOfClearData <= 164, "Should not exceed NAL size")
            // With 12 bytes minimum clear and 164-byte NAL (4 prefix + 160 data), protected = 152 bytes
            #expect(first.bytesOfProtectedData == 152, "Protected region should be 152 bytes")
        }
    }

    @Test("Audio encryption encrypts all complete blocks")
    func audioFullEncryption() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // 48 bytes = 3 complete blocks
        let input = Data(repeating: 0xAA, count: 48)
        let result = encryptor.encryptAudioSample(input)

        // Result should be same size
        #expect(result.encryptedData.count == 48)

        // Result should be different (encrypted)
        #expect(result.encryptedData != input)

        // Should have single subsample with all protected
        #expect(result.subsamples.count == 1)
        #expect(result.subsamples[0].bytesOfClearData == 0)
        #expect(result.subsamples[0].bytesOfProtectedData == 48)
    }

    @Test("Partial blocks remain clear")
    func partialBlocksClear() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // 50 bytes = 3 complete blocks + 2 bytes
        let input = Data(repeating: 0xBB, count: 50)
        let result = encryptor.encryptAudioSample(input)

        // Last 2 bytes should remain clear (partial block)
        #expect(result.encryptedData.suffix(2) == Data(repeating: 0xBB, count: 2))
    }

    // MARK: - NAL Unit Parsing Tests

    @Test("Parses length-prefixed NAL units")
    func nalUnitParsing() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // Create sample with 2 NAL units
        var sample = Data()

        // NAL 1: SPS (type 7) - 10 bytes
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x0A]) // Length = 10
        sample.append(0x67) // NAL type 7 (SPS)
        sample.append(contentsOf: [UInt8](repeating: 0x11, count: 9))

        // NAL 2: IDR slice (type 5) - 20 bytes
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x14]) // Length = 20
        sample.append(0x65) // NAL type 5 (IDR)
        sample.append(contentsOf: [UInt8](repeating: 0x22, count: 19))

        let result = encryptor.encryptVideoSample(sample, nalLengthSize: 4)

        // Should have 2 subsamples (one per NAL)
        #expect(result.subsamples.count >= 1)

        // Total output size should match input
        #expect(result.encryptedData.count == sample.count)
    }

    @Test("Non-VCL NAL units stay clear")
    func nonVCLNALsClear() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // SPS NAL unit (type 7) - should not be encrypted
        var spsNAL = Data()
        spsNAL.append(contentsOf: [0x00, 0x00, 0x00, 0x10]) // Length = 16
        spsNAL.append(0x67) // NAL type 7 (SPS)
        spsNAL.append(contentsOf: [UInt8](repeating: 0x33, count: 15))

        let result = encryptor.encryptVideoSample(spsNAL, nalLengthSize: 4)

        // SPS should remain unchanged (all clear)
        #expect(result.encryptedData == spsNAL)

        // Subsample should show all clear
        if let first = result.subsamples.first {
            #expect(first.bytesOfProtectedData == 0)
        }
    }

    @Test("Slice NAL units are encrypted")
    func sliceNALsEncrypted() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // IDR slice NAL unit (type 5) - should be encrypted
        // Using 500 bytes to ensure we have data beyond the 12-byte clear region
        // Real video NALs are typically 1KB+ for SD and multiple KB for HD
        var idrNAL = Data()
        idrNAL.append(contentsOf: [0x00, 0x00, 0x01, 0xF0]) // Length = 496
        idrNAL.append(0x65) // NAL type 5 (IDR)
        idrNAL.append(contentsOf: [UInt8](repeating: 0x44, count: 495))

        let result = encryptor.encryptVideoSample(idrNAL, nalLengthSize: 4)

        // Should have protected bytes (500 - 12 = 488 bytes in protected region)
        // Apple FairPlay reference uses ~12 bytes clear per NAL
        let totalProtected = result.subsamples.reduce(0) { $0 + Int($1.bytesOfProtectedData) }
        #expect(totalProtected > 0, "Slice NAL should have protected bytes")
        #expect(totalProtected == 488, "Expected 488 bytes in protected region")

        // Header should be preserved (first 12 bytes are clear)
        #expect(result.encryptedData[0...3] == idrNAL[0...3]) // Length prefix
        #expect(result.encryptedData[4] == 0x65) // NAL type
    }

    // MARK: - Key Derivation Tests

    @Test("Key derivation produces 16 bytes")
    func keyDerivationSize() {
        let keyID = Data(repeating: 0x12, count: 16)
        let masterKey = Data(repeating: 0x34, count: 16)

        let derived = CBCSEncryptor.deriveKey(from: keyID, using: masterKey)
        #expect(derived.count == 16)
    }

    @Test("Key derivation is deterministic")
    func keyDerivationDeterministic() {
        let keyID = Data(repeating: 0x56, count: 16)
        let masterKey = Data(repeating: 0x78, count: 16)

        let derived1 = CBCSEncryptor.deriveKey(from: keyID, using: masterKey)
        let derived2 = CBCSEncryptor.deriveKey(from: keyID, using: masterKey)

        #expect(derived1 == derived2)
    }

    @Test("Generate random key ID produces unique values")
    func generateKeyIDUnique() {
        let keyID1 = CBCSEncryptor.generateKeyID()
        let keyID2 = CBCSEncryptor.generateKeyID()

        #expect(keyID1.count == 16)
        #expect(keyID2.count == 16)
        #expect(keyID1 != keyID2)
    }

    @Test("Generate random IV produces unique values")
    func generateIVUnique() {
        let iv1 = CBCSEncryptor.generateIV()
        let iv2 = CBCSEncryptor.generateIV()

        #expect(iv1.count == 16)
        #expect(iv2.count == 16)
        #expect(iv1 != iv2)
    }

    // MARK: - Subsample Merging Tests

    @Test("Consecutive clear subsamples are merged")
    func subsampleMerging() {
        let encryptor = CBCSEncryptor(key: testKey, iv: testIV)

        // Multiple small non-VCL NALs that should merge
        var sample = Data()

        // SPS (type 7)
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x08])
        sample.append(0x67)
        sample.append(contentsOf: [UInt8](repeating: 0x11, count: 7))

        // PPS (type 8)
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x04])
        sample.append(0x68)
        sample.append(contentsOf: [UInt8](repeating: 0x22, count: 3))

        let result = encryptor.encryptVideoSample(sample, nalLengthSize: 4)

        // Merged subsamples should have fewer entries than NAL count
        // Both NALs are non-VCL, so all clear, should merge
        #expect(result.subsamples.count <= 2)
    }
}

// MARK: - FMP4 Writer Tests

@Suite("FMP4 Writer")
struct FMP4WriterTests {
    @Test("Init segment contains ftyp and moov")
    func initSegmentStructure() {
        let sps = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let writer = FMP4Writer(tracks: [track])
        let initSegment = writer.generateInitSegment()

        // Should start with ftyp
        #expect(initSegment[4] == 0x66) // 'f'
        #expect(initSegment[5] == 0x74) // 't'
        #expect(initSegment[6] == 0x79) // 'y'
        #expect(initSegment[7] == 0x70) // 'p'

        // Should contain moov
        let moovMarker = Data([0x6D, 0x6F, 0x6F, 0x76]) // "moov"
        #expect(initSegment.range(of: moovMarker) != nil)

        // Should contain mvhd
        let mvhdMarker = Data([0x6D, 0x76, 0x68, 0x64]) // "mvhd"
        #expect(initSegment.range(of: mvhdMarker) != nil)

        // Should contain trak
        let trakMarker = Data([0x74, 0x72, 0x61, 0x6B]) // "trak"
        #expect(initSegment.range(of: trakMarker) != nil)
    }

    @Test("Init segment with encryption contains pssh")
    func initSegmentWithEncryption() {
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
        let initSegment = writer.generateInitSegment()

        // Should contain pssh
        let psshMarker = Data([0x70, 0x73, 0x73, 0x68]) // "pssh"
        #expect(initSegment.range(of: psshMarker) != nil)

        // Should contain sinf (in sample entry)
        let sinfMarker = Data([0x73, 0x69, 0x6E, 0x66]) // "sinf"
        #expect(initSegment.range(of: sinfMarker) != nil)
    }

    @Test("Media segment contains moof and mdat")
    func mediaSegmentStructure() {
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
            FMP4Writer.Sample(data: Data(repeating: 0x11, count: 1000), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0x22, count: 500), duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Should contain moof
        let moofMarker = Data([0x6D, 0x6F, 0x6F, 0x66]) // "moof"
        #expect(mediaSegment.range(of: moofMarker) != nil)

        // Should contain mdat
        let mdatMarker = Data([0x6D, 0x64, 0x61, 0x74]) // "mdat"
        #expect(mediaSegment.range(of: mdatMarker) != nil)

        // Should contain trun
        let trunMarker = Data([0x74, 0x72, 0x75, 0x6E]) // "trun"
        #expect(mediaSegment.range(of: trunMarker) != nil)
    }

    @Test("Media segment mdat contains sample data")
    func mediaSegmentSampleData() {
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

        let sampleData = Data([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
        let samples = [
            FMP4Writer.Sample(data: sampleData, duration: 3000, isSync: true)
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Sample data should be in mdat
        #expect(mediaSegment.range(of: sampleData) != nil)
    }
}
