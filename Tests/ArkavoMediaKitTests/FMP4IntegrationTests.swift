import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - FMP4 Integration Tests

@Suite("FMP4 Integration Validation")
struct FMP4IntegrationTests {

    // MARK: - Init Segment Validation

    @Test("Init segment is valid ISO BMFF")
    func validateInitSegment() throws {
        // Create H.264 track config
        let sps = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78,
                        0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00, 0x03,
                        0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF2, 0x3C,
                        0x60, 0xC6, 0x58])
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

        // Verify minimum size
        #expect(initSegment.count > 100)

        // Verify ftyp box
        let ftypType = String(data: initSegment[4..<8], encoding: .ascii)
        #expect(ftypType == "ftyp")

        // Verify moov box exists
        let moovMarker = Data([0x6D, 0x6F, 0x6F, 0x76])
        #expect(initSegment.range(of: moovMarker) != nil)

        // Verify essential boxes exist
        let mvhdMarker = Data([0x6D, 0x76, 0x68, 0x64])
        let trakMarker = Data([0x74, 0x72, 0x61, 0x6B])
        let mdiaMarker = Data([0x6D, 0x64, 0x69, 0x61])
        let stblMarker = Data([0x73, 0x74, 0x62, 0x6C])

        #expect(initSegment.range(of: mvhdMarker) != nil)
        #expect(initSegment.range(of: trakMarker) != nil)
        #expect(initSegment.range(of: mdiaMarker) != nil)
        #expect(initSegment.range(of: stblMarker) != nil)
    }

    @Test("Init segment with encryption has sinf and pssh")
    func validateEncryptedInitSegment() throws {
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

        // Verify encryption boxes exist
        let sinfMarker = Data([0x73, 0x69, 0x6E, 0x66])
        let psshMarker = Data([0x70, 0x73, 0x73, 0x68])
        let tencMarker = Data([0x74, 0x65, 0x6E, 0x63])
        let schmMarker = Data([0x73, 0x63, 0x68, 0x6D])

        #expect(initSegment.range(of: sinfMarker) != nil)
        #expect(initSegment.range(of: psshMarker) != nil)
        #expect(initSegment.range(of: tencMarker) != nil)
        #expect(initSegment.range(of: schmMarker) != nil)

        // Verify encv sample entry (encrypted video)
        let encvMarker = Data([0x65, 0x6E, 0x63, 0x76])
        #expect(initSegment.range(of: encvMarker) != nil)
    }

    // MARK: - Media Segment Validation

    @Test("Media segment is valid ISO BMFF")
    func validateMediaSegment() throws {
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

        // Create sample data
        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0x11, count: 1000), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0x22, count: 500), duration: 3000, isSync: false),
            FMP4Writer.Sample(data: Data(repeating: 0x33, count: 800), duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Verify moof box
        let moofMarker = Data([0x6D, 0x6F, 0x6F, 0x66])
        #expect(mediaSegment.range(of: moofMarker) != nil)

        // Verify mdat box
        let mdatMarker = Data([0x6D, 0x64, 0x61, 0x74])
        #expect(mediaSegment.range(of: mdatMarker) != nil)

        // Verify traf box
        let trafMarker = Data([0x74, 0x72, 0x61, 0x66])
        #expect(mediaSegment.range(of: trafMarker) != nil)

        // Verify tfhd box
        let tfhdMarker = Data([0x74, 0x66, 0x68, 0x64])
        #expect(mediaSegment.range(of: tfhdMarker) != nil)

        // Verify trun box
        let trunMarker = Data([0x74, 0x72, 0x75, 0x6E])
        #expect(mediaSegment.range(of: trunMarker) != nil)
    }

    @Test("Media segment contains all sample data")
    func validateMediaSegmentSampleData() throws {
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

        let marker1 = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let marker2 = Data([0xCA, 0xFE, 0xBA, 0xBE])
        let marker3 = Data([0xFA, 0xCE, 0xB0, 0x0C])

        var sample1 = marker1
        sample1.append(Data(repeating: 0x00, count: 100))

        var sample2 = marker2
        sample2.append(Data(repeating: 0x00, count: 50))

        var sample3 = marker3
        sample3.append(Data(repeating: 0x00, count: 75))

        let samples = [
            FMP4Writer.Sample(data: sample1, duration: 3000, isSync: true),
            FMP4Writer.Sample(data: sample2, duration: 3000, isSync: false),
            FMP4Writer.Sample(data: sample3, duration: 3000, isSync: false),
        ]

        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

        // Verify all sample markers are present in mdat
        #expect(mediaSegment.range(of: marker1) != nil)
        #expect(mediaSegment.range(of: marker2) != nil)
        #expect(mediaSegment.range(of: marker3) != nil)
    }

    // MARK: - Box Size Validation

    @Test("All boxes have valid sizes")
    func validateBoxSizes() throws {
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
        let initSegment = writer.generateInitSegment()

        // Walk through boxes and verify sizes
        var offset = 0
        var boxCount = 0

        while offset + 8 <= initSegment.count {
            let sizeData = initSegment.subdata(in: offset..<(offset + 4))
            let size = UInt32(bigEndian: sizeData.withUnsafeBytes { $0.load(as: UInt32.self) })

            // Size must be at least 8 (header size)
            #expect(size >= 8, "Box at offset \(offset) has invalid size \(size)")

            // Size must not exceed remaining data
            #expect(Int(size) <= initSegment.count - offset, "Box at offset \(offset) extends beyond data")

            offset += Int(size)
            boxCount += 1

            // Safety limit
            if boxCount > 100 { break }
        }

        // Should have parsed at least ftyp and moov
        #expect(boxCount >= 2)
        #expect(offset == initSegment.count, "Data remaining after parsing all boxes")
    }

    // MARK: - CBCS Encryption Integration

    @Test("CBCS encrypts video NAL units correctly")
    func validateCBCSVideoEncryption() throws {
        let key = Data(repeating: 0x3C, count: 16)
        let iv = Data([0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
                       0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7])

        let encryptor = CBCSEncryptor(key: key, iv: iv)

        // Create a sample with IDR NAL unit (type 5)
        var sample = Data()
        // NAL length (4 bytes, big-endian)
        sample.append(contentsOf: [0x00, 0x00, 0x00, 0x30]) // 48 bytes
        // NAL header (type 5 = IDR)
        sample.append(0x65)
        // NAL payload (47 bytes)
        sample.append(Data(repeating: 0xAA, count: 47))

        let result = encryptor.encryptVideoSample(sample, nalLengthSize: 4)

        // Length prefix should be preserved
        #expect(result.encryptedData[0..<4] == sample[0..<4])

        // NAL type should be preserved
        #expect(result.encryptedData[4] == 0x65)

        // Subsample info should exist
        #expect(!result.subsamples.isEmpty)

        // Output size should match input
        #expect(result.encryptedData.count == sample.count)
    }

    @Test("CBCS preserves SPS/PPS NAL units")
    func validateCBCSPreservesNonVCL() throws {
        let key = Data(repeating: 0x3C, count: 16)
        let iv = Data(repeating: 0xCD, count: 16)

        let encryptor = CBCSEncryptor(key: key, iv: iv)

        // SPS NAL unit (type 7)
        var spsSample = Data()
        spsSample.append(contentsOf: [0x00, 0x00, 0x00, 0x10]) // 16 bytes
        spsSample.append(0x67) // NAL type 7 (SPS)
        spsSample.append(Data(repeating: 0x11, count: 15))

        let spsResult = encryptor.encryptVideoSample(spsSample, nalLengthSize: 4)

        // SPS should be unchanged (all clear)
        #expect(spsResult.encryptedData == spsSample)

        // Subsample should show all clear
        #expect(spsResult.subsamples.first?.bytesOfProtectedData == 0)

        // PPS NAL unit (type 8)
        var ppsSample = Data()
        ppsSample.append(contentsOf: [0x00, 0x00, 0x00, 0x08]) // 8 bytes
        ppsSample.append(0x68) // NAL type 8 (PPS)
        ppsSample.append(Data(repeating: 0x22, count: 7))

        let ppsResult = encryptor.encryptVideoSample(ppsSample, nalLengthSize: 4)

        // PPS should be unchanged
        #expect(ppsResult.encryptedData == ppsSample)
    }

    // MARK: - Unencrypted Playback Validation Tests

    @Test("Unencrypted init segment has correct stsd entry")
    func validateUnencryptedStsdEntry() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        // No encryption
        let writer = FMP4Writer(tracks: [track])
        let initSegment = writer.generateInitSegment()

        // Should have avc1, NOT encv
        let avc1Marker = Data([0x61, 0x76, 0x63, 0x31]) // "avc1"
        let encvMarker = Data([0x65, 0x6E, 0x63, 0x76]) // "encv"

        #expect(initSegment.range(of: avc1Marker) != nil, "Unencrypted content should have avc1 entry")
        #expect(initSegment.range(of: encvMarker) == nil, "Unencrypted content should NOT have encv entry")

        // Should NOT have encryption boxes
        let sinfMarker = Data([0x73, 0x69, 0x6E, 0x66]) // "sinf"
        let psshMarker = Data([0x70, 0x73, 0x73, 0x68]) // "pssh"
        let tencMarker = Data([0x74, 0x65, 0x6E, 0x63]) // "tenc"

        #expect(initSegment.range(of: sinfMarker) == nil, "Unencrypted content should NOT have sinf")
        #expect(initSegment.range(of: psshMarker) == nil, "Unencrypted content should NOT have pssh")
        #expect(initSegment.range(of: tencMarker) == nil, "Unencrypted content should NOT have tenc")
    }

    @Test("Unencrypted media segment has no senc/saiz/saio")
    func validateUnencryptedMediaSegmentNoEncryption() throws {
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

        // Should NOT have encryption boxes
        let sencMarker = Data([0x73, 0x65, 0x6E, 0x63]) // "senc"
        let saizMarker = Data([0x73, 0x61, 0x69, 0x7A]) // "saiz"
        let saioMarker = Data([0x73, 0x61, 0x69, 0x6F]) // "saio"

        #expect(mediaSegment.range(of: sencMarker) == nil, "Unencrypted segment should NOT have senc")
        #expect(mediaSegment.range(of: saizMarker) == nil, "Unencrypted segment should NOT have saiz")
        #expect(mediaSegment.range(of: saioMarker) == nil, "Unencrypted segment should NOT have saio")

        // Should still have required boxes
        let moofMarker = Data([0x6D, 0x6F, 0x6F, 0x66])
        let mdatMarker = Data([0x6D, 0x64, 0x61, 0x74])
        let trafMarker = Data([0x74, 0x72, 0x61, 0x66])
        let trunMarker = Data([0x74, 0x72, 0x75, 0x6E])

        #expect(mediaSegment.range(of: moofMarker) != nil)
        #expect(mediaSegment.range(of: mdatMarker) != nil)
        #expect(mediaSegment.range(of: trafMarker) != nil)
        #expect(mediaSegment.range(of: trunMarker) != nil)
    }

    @Test("Unencrypted HLS playlist has no KEY tag")
    func validateUnencryptedPlaylist() throws {
        let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: 6,
            playlistType: .vod,
            initSegmentURI: "init.mp4"
        )

        // No encryption
        let hlsGenerator = FMP4HLSGenerator(
            config: playlistConfig,
            encryption: nil
        )

        let segments = [
            FMP4HLSGenerator.Segment(uri: "segment0.m4s", duration: 6.0),
            FMP4HLSGenerator.Segment(uri: "segment1.m4s", duration: 6.0),
        ]

        let playlist = hlsGenerator.generateMediaPlaylist(segments: segments)

        // Should NOT have KEY tag
        #expect(!playlist.contains("#EXT-X-KEY"), "Unencrypted playlist should NOT have KEY tag")
        #expect(!playlist.contains("skd://"), "Unencrypted playlist should NOT have skd:// URI")

        // Should have required tags
        #expect(playlist.contains("#EXTM3U"))
        #expect(playlist.contains("#EXT-X-VERSION:7"))
        #expect(playlist.contains("#EXT-X-MAP:URI=\"init.mp4\""))
        #expect(playlist.contains("segment0.m4s"))
    }

    @Test("Complete unencrypted fMP4 package is valid")
    func validateCompleteUnencryptedPackage() throws {
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

        // Generate init segment
        let initSegment = writer.generateInitSegment()
        #expect(initSegment.count > 0)

        // Verify ftyp + moov structure
        let ftypType = String(data: initSegment[4..<8], encoding: .ascii)
        #expect(ftypType == "ftyp")

        // Generate multiple media segments
        for i in 0..<3 {
            let samples = [
                FMP4Writer.Sample(data: Data(repeating: UInt8(i * 0x11), count: 500), duration: 3000, isSync: i == 0),
                FMP4Writer.Sample(data: Data(repeating: UInt8(i * 0x22), count: 300), duration: 3000, isSync: false),
            ]

            let mediaSegment = writer.generateMediaSegment(
                trackID: 1,
                samples: samples,
                baseDecodeTime: UInt64(i * 6000)
            )

            #expect(mediaSegment.count > 0)

            // Parse top-level boxes to verify structure
            var topLevelBoxes: [String] = []
            var offset = 0
            while offset + 8 <= mediaSegment.count {
                let size = Int(UInt32(bigEndian: mediaSegment.subdata(in: offset..<(offset + 4)).withUnsafeBytes { $0.load(as: UInt32.self) }))
                guard size > 0, let boxType = String(data: mediaSegment.subdata(in: (offset + 4)..<(offset + 8)), encoding: .ascii) else { break }
                topLevelBoxes.append(boxType)
                offset += size
            }

            // Verify required boxes are present (moof and mdat required, styp optional for CMAF)
            #expect(topLevelBoxes.contains("moof"), "Segment \(i) must have moof")
            #expect(topLevelBoxes.contains("mdat"), "Segment \(i) must have mdat")
        }

        // Generate playlist
        let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: 6,
            playlistType: .vod,
            initSegmentURI: "init.mp4"
        )

        let hlsGenerator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)

        let segments = [
            FMP4HLSGenerator.Segment(uri: "segment0.m4s", duration: 6.0),
            FMP4HLSGenerator.Segment(uri: "segment1.m4s", duration: 6.0),
            FMP4HLSGenerator.Segment(uri: "segment2.m4s", duration: 6.0),
        ]

        let playlist = hlsGenerator.generateMediaPlaylist(segments: segments)

        #expect(playlist.contains("#EXTM3U"))
        #expect(playlist.contains("#EXT-X-ENDLIST"))
        #expect(!playlist.contains("#EXT-X-KEY"))
    }

    // MARK: - Full Pipeline Test

    @Test("Full FairPlay HLS package generation")
    func validateFullPipelineGeneration() throws {
        let sps = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40])
        let pps = Data([0x68, 0xEE, 0x3C, 0x80])

        let keyID = Data(repeating: 0x12, count: 16)
        let iv = Data(repeating: 0x34, count: 16)

        // Create video track
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1920,
            height: 1080,
            timescale: 90000,
            sps: [sps],
            pps: [pps]
        )

        let encryption = FMP4Writer.EncryptionConfig(
            keyID: keyID,
            constantIV: iv
        )

        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        // Generate init segment
        let initSegment = writer.generateInitSegment()
        #expect(initSegment.count > 0)

        // Generate media segment
        let samples = [
            FMP4Writer.Sample(data: Data(repeating: 0x11, count: 1000), duration: 3000, isSync: true),
            FMP4Writer.Sample(data: Data(repeating: 0x22, count: 500), duration: 3000, isSync: false),
        ]
        let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)
        #expect(mediaSegment.count > 0)

        // Generate HLS playlist
        let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: 6,
            playlistType: .vod,
            initSegmentURI: "init.mp4"
        )

        let fairPlayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(
            assetID: "test-asset",
            keyID: keyID
        )

        let hlsGenerator = FMP4HLSGenerator(
            config: playlistConfig,
            encryption: fairPlayConfig
        )

        let segments = [
            FMP4HLSGenerator.Segment(uri: "segment0.m4s", duration: 6.0),
            FMP4HLSGenerator.Segment(uri: "segment1.m4s", duration: 6.0),
        ]

        let playlist = hlsGenerator.generateMediaPlaylist(segments: segments)

        // Verify playlist structure
        #expect(playlist.contains("#EXTM3U"))
        #expect(playlist.contains("#EXT-X-VERSION:7"))
        #expect(playlist.contains("#EXT-X-KEY:METHOD=SAMPLE-AES"))
        #expect(playlist.contains("skd://"))
        #expect(playlist.contains("KEYFORMAT=\"com.apple.streamingkeydelivery\""))
        #expect(playlist.contains("#EXT-X-MAP:URI=\"init.mp4\""))
        #expect(playlist.contains("segment0.m4s"))
        #expect(playlist.contains("segment1.m4s"))
    }
}
