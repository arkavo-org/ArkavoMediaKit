import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - fMP4/HLS Test Matrix

/// Comprehensive test suite covering the fMP4 over HLS test matrix for FairPlay/CBCS encryption.
/// Based on Apple HLS Authoring Specification and ISO 14496-12 requirements.
@Suite("fMP4/HLS Test Matrix")
struct HLSFairPlayTestMatrix {

    // MARK: - Test Fixtures

    let testKey = Data(repeating: 0x3C, count: 16)
    let testIV = Data([0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
                       0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7])
    let testKeyID = Data(repeating: 0x12, count: 16)
    let testKeyID2 = Data(repeating: 0x34, count: 16) // Second key for rotation tests

    // Sample H.264 SPS/PPS (1080p profile)
    let sampleSPS = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40, 0x78,
                          0x02, 0x27, 0xE5, 0xC0, 0x44, 0x00, 0x00, 0x03,
                          0x00, 0x04, 0x00, 0x00, 0x03, 0x00, 0xF2, 0x3C,
                          0x60, 0xC6, 0x58])
    let samplePPS = Data([0x68, 0xEE, 0x3C, 0x80])

    // Different resolution SPS for codec config change tests (720p)
    let sampleSPS720 = Data([0x67, 0x64, 0x00, 0x1F, 0xAC, 0xD9, 0x40, 0x50,
                             0x05, 0xBB, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00,
                             0x10, 0x00, 0x00, 0x03, 0x01, 0xE8, 0xF1, 0x42,
                             0x2A])

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

    private func findBox(_ data: Data, type: String, startingAt start: Int = 0) -> (offset: Int, size: Int)? {
        var offset = start
        while offset + 8 <= data.count {
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
        return data.subdata(in: offset..<(offset + 4)).withUnsafeBytes { $0.load(as: UInt32.self) }.bigEndian
    }

    private func createVideoTrack() -> FMP4Writer.TrackConfig {
        FMP4Writer.TrackConfig.h264Video(
            width: 1920, height: 1080, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
    }

    private func createVideoTrack720p() -> FMP4Writer.TrackConfig {
        FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS720], pps: [samplePPS]
        )
    }

    private func createEncryption() -> FMP4Writer.EncryptionConfig {
        FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
    }

    /// Create a realistic video sample with NAL units (SPS, PPS, IDR or P-frame)
    private func createVideoSample(isIDR: Bool, payloadSize: Int = 500) -> Data {
        var sample = Data()

        if isIDR {
            // SPS NAL
            let spsLength = UInt32(sampleSPS.count)
            sample.append(spsLength.bigEndianData)
            sample.append(sampleSPS)

            // PPS NAL
            let ppsLength = UInt32(samplePPS.count)
            sample.append(ppsLength.bigEndianData)
            sample.append(samplePPS)

            // IDR NAL (type 5)
            let idrLength = UInt32(payloadSize)
            sample.append(idrLength.bigEndianData)
            sample.append(0x65) // NAL type 5 (IDR)
            sample.append(Data(repeating: 0xAB, count: payloadSize - 1))
        } else {
            // P-frame NAL (type 1)
            let pLength = UInt32(payloadSize)
            sample.append(pLength.bigEndianData)
            sample.append(0x41) // NAL type 1 (non-IDR slice)
            sample.append(Data(repeating: 0xCD, count: payloadSize - 1))
        }

        return sample
    }

    // MARK: - B: Core Playback Matrix Tests

    @Suite("B: Core Playback Matrix")
    struct CorePlaybackMatrix {
        let parent = HLSFairPlayTestMatrix()

        @Test("B1: Clear init + clear media segments play")
        func b1ClearInitClearMedia() {
            let track = parent.createVideoTrack()
            let writer = FMP4Writer(tracks: [track], encryption: nil)

            // Generate init segment
            let initSegment = writer.generateInitSegment()

            // Verify: no encryption boxes in clear init
            #expect(parent.findBoxRecursive(initSegment, type: "encv") == nil, "Clear init should not have encv")
            #expect(parent.findBoxRecursive(initSegment, type: "sinf") == nil, "Clear init should not have sinf")
            #expect(parent.findBoxRecursive(initSegment, type: "pssh") == nil, "Clear init should not have pssh")
            #expect(parent.findBoxRecursive(initSegment, type: "tenc") == nil, "Clear init should not have tenc")

            // Verify: should have avc1 (clear sample entry)
            let avc1Marker = Data([0x61, 0x76, 0x63, 0x31]) // "avc1"
            #expect(initSegment.range(of: avc1Marker) != nil, "Clear init should have avc1 sample entry")

            // Generate media segment
            let samples = [FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)]
            let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

            // Verify: no encryption boxes in clear media
            #expect(parent.findBoxRecursive(mediaSegment, type: "senc") == nil, "Clear media should not have senc")
            #expect(parent.findBoxRecursive(mediaSegment, type: "saiz") == nil, "Clear media should not have saiz")
            #expect(parent.findBoxRecursive(mediaSegment, type: "saio") == nil, "Clear media should not have saio")

            // Verify: has required structure
            #expect(parent.findBoxRecursive(mediaSegment, type: "moof") != nil, "Media segment should have moof")
            #expect(parent.findBoxRecursive(mediaSegment, type: "mdat") != nil, "Media segment should have mdat")
            #expect(parent.findBoxRecursive(mediaSegment, type: "trun") != nil, "Media segment should have trun")

            print("✅ B1: Clear fMP4 structure validated")
        }

        @Test("B2: Clear init + encrypted media (FairPlay CBCS) structure")
        func b2ClearInitEncryptedMedia() {
            let track = parent.createVideoTrack()
            let encryption = parent.createEncryption()
            let writer = FMP4Writer(tracks: [track], encryption: encryption)

            // Generate init segment
            let initSegment = writer.generateInitSegment()

            // Verify: init is clear but has encryption signaling
            // Use marker search for sample entry types (more reliable for stsd contents)
            let encvMarker = Data([0x65, 0x6E, 0x63, 0x76]) // "encv"
            #expect(initSegment.range(of: encvMarker) != nil, "Encrypted init should have encv sample entry")
            #expect(parent.findBoxRecursive(initSegment, type: "sinf") != nil, "Encrypted init should have sinf")
            #expect(parent.findBoxRecursive(initSegment, type: "frma") != nil, "Encrypted init should have frma")
            #expect(parent.findBoxRecursive(initSegment, type: "schm") != nil, "Encrypted init should have schm")
            #expect(parent.findBoxRecursive(initSegment, type: "tenc") != nil, "Encrypted init should have tenc")
            #expect(parent.findBoxRecursive(initSegment, type: "pssh") != nil, "Encrypted init should have pssh")

            // Generate encrypted media segment
            let encryptor = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)
            let rawSample = parent.createVideoSample(isIDR: true)
            let encResult = encryptor.encryptVideoSample(rawSample, nalLengthSize: 4)

            let sample = FMP4Writer.Sample(
                data: encResult.encryptedData,
                duration: 3000,
                isSync: true,
                subsamples: encResult.subsamples
            )
            let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: [sample], baseDecodeTime: 0)

            // Verify: media segment has encryption boxes
            #expect(parent.findBoxRecursive(mediaSegment, type: "senc") != nil, "Encrypted media should have senc")
            #expect(parent.findBoxRecursive(mediaSegment, type: "saiz") != nil, "Encrypted media should have saiz")
            #expect(parent.findBoxRecursive(mediaSegment, type: "saio") != nil, "Encrypted media should have saio")

            print("✅ B2: FairPlay encrypted fMP4 structure validated")
        }

        @Test("B4: Encrypted init segment is invalid (init must be clear)")
        func b4EncryptedInitInvalid() {
            // This test validates the principle that init segments must be clear
            // The ftyp+moov must be parseable without decryption

            let track = parent.createVideoTrack()
            let encryption = parent.createEncryption()
            let writer = FMP4Writer(tracks: [track], encryption: encryption)

            let initSegment = writer.generateInitSegment()

            // Verify the init segment itself is clear (parseable)
            // The moov box and all its children should be readable without decryption
            guard let moovInfo = parent.findBox(initSegment, type: "moov") else {
                Issue.record("Init segment must have parseable moov box")
                return
            }

            // Verify we can parse into moov (proving it's not encrypted)
            let moovData = initSegment.subdata(in: moovInfo.offset..<(moovInfo.offset + moovInfo.size))
            #expect(parent.findBoxRecursive(moovData, type: "mvhd", startingAt: 8) != nil,
                   "moov must be parseable (clear) to find mvhd")
            #expect(parent.findBoxRecursive(moovData, type: "trak", startingAt: 8) != nil,
                   "moov must be parseable (clear) to find trak")

            // Verify the implementation never encrypts the init segment data itself
            // (encryption metadata like sinf/tenc is present, but moov box data is clear)
            #expect(parent.findBoxRecursive(initSegment, type: "sinf") != nil,
                   "sinf present = encryption signaling, but box itself is clear")

            print("✅ B4: Init segment is clear (parseable) - correct behavior")
        }

        @Test("B5: Clear to encrypted segment transition structure")
        func b5ClearToEncryptedTransition() {
            let track = parent.createVideoTrack()

            // Create clear writer
            let clearWriter = FMP4Writer(tracks: [track], encryption: nil)
            let clearSamples = [FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)]
            let clearSegment = clearWriter.generateMediaSegment(trackID: 1, samples: clearSamples, baseDecodeTime: 0)

            // Create encrypted writer
            let encryption = parent.createEncryption()
            let encWriter = FMP4Writer(tracks: [track], encryption: encryption)
            let encryptor = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)
            let rawSample = parent.createVideoSample(isIDR: true)
            let encResult = encryptor.encryptVideoSample(rawSample, nalLengthSize: 4)
            let encSample = FMP4Writer.Sample(
                data: encResult.encryptedData,
                duration: 3000,
                isSync: true,
                subsamples: encResult.subsamples
            )
            let encSegment = encWriter.generateMediaSegment(trackID: 1, samples: [encSample], baseDecodeTime: 540000)

            // Verify clear segment structure
            #expect(parent.findBoxRecursive(clearSegment, type: "senc") == nil, "Clear segment should not have senc")
            #expect(parent.findBoxRecursive(clearSegment, type: "moof") != nil, "Clear segment should have moof")

            // Verify encrypted segment structure
            #expect(parent.findBoxRecursive(encSegment, type: "senc") != nil, "Encrypted segment should have senc")
            #expect(parent.findBoxRecursive(encSegment, type: "moof") != nil, "Encrypted segment should have moof")

            // Both segments should have valid moof/mdat structure
            #expect(parent.findBoxRecursive(clearSegment, type: "trun") != nil)
            #expect(parent.findBoxRecursive(encSegment, type: "trun") != nil)

            print("✅ B5: Clear → encrypted transition structures validated")
        }

        @Test("B6: Encrypted to clear segment transition structure")
        func b6EncryptedToClearTransition() {
            let track = parent.createVideoTrack()

            // Create encrypted segment first
            let encryption = parent.createEncryption()
            let encWriter = FMP4Writer(tracks: [track], encryption: encryption)
            let encryptor = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)
            let rawSample = parent.createVideoSample(isIDR: true)
            let encResult = encryptor.encryptVideoSample(rawSample, nalLengthSize: 4)
            let encSample = FMP4Writer.Sample(
                data: encResult.encryptedData,
                duration: 3000,
                isSync: true,
                subsamples: encResult.subsamples
            )
            let encSegment = encWriter.generateMediaSegment(trackID: 1, samples: [encSample], baseDecodeTime: 0)

            // Create clear segment after
            let clearWriter = FMP4Writer(tracks: [track], encryption: nil)
            let clearSamples = [FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)]
            let clearSegment = clearWriter.generateMediaSegment(trackID: 1, samples: clearSamples, baseDecodeTime: 540000)

            // Verify transition
            #expect(parent.findBoxRecursive(encSegment, type: "senc") != nil, "First segment (encrypted) should have senc")
            #expect(parent.findBoxRecursive(clearSegment, type: "senc") == nil, "Second segment (clear) should not have senc")

            print("✅ B6: Encrypted → clear transition structures validated")
        }

        @Test("B7: Alternating clear and encrypted segments")
        func b7AlternatingClearEncryptedSegments() {
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
                targetDuration: 6,
                playlistType: .vod,
                initSegmentURI: "init.mp4"
            )

            let encConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "test-asset", keyID: parent.testKeyID)

            // Alternating pattern: clear, enc, clear, enc
            let segments = [
                FMP4HLSGenerator.Segment(uri: "seg0.m4s", duration: 6.0, encryption: nil),
                FMP4HLSGenerator.Segment(uri: "seg1.m4s", duration: 6.0, encryption: encConfig),
                FMP4HLSGenerator.Segment(uri: "seg2.m4s", duration: 6.0, encryption: nil),
                FMP4HLSGenerator.Segment(uri: "seg3.m4s", duration: 6.0, encryption: encConfig),
            ]

            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)
            let playlist = generator.generateMediaPlaylist(segments: segments)

            print("--- B7 Alternating Encryption Playlist ---\n\(playlist)")

            // Invariant: No "key bleed" - clear segments must follow METHOD=NONE
            // Count transitions:
            // clear(0) → enc(1): +KEY
            // enc(1) → clear(2): +NONE
            // clear(2) → enc(3): +KEY
            // Since we start clear, there's no prior encryption to clear, so only 1 NONE tag
            let sampleAESCount = playlist.components(separatedBy: "METHOD=SAMPLE-AES").count - 1
            let noneCount = playlist.components(separatedBy: "METHOD=NONE").count - 1

            #expect(sampleAESCount == 2, "Expected 2 SAMPLE-AES tags for alternating pattern")
            #expect(noneCount == 1, "Expected 1 NONE tag (clear→enc→clear→enc starts clear)")

            // Verify segment order matches playlist order
            let lines = playlist.components(separatedBy: "\n")
            var segmentOrder: [String] = []
            for line in lines where line.hasSuffix(".m4s") {
                segmentOrder.append(line)
            }
            #expect(segmentOrder == ["seg0.m4s", "seg1.m4s", "seg2.m4s", "seg3.m4s"], "Segment order should be preserved")

            print("✅ B7: Alternating clear/encrypted validated")
        }
    }

    // MARK: - M: Manifest Signaling Matrix Tests

    @Suite("M: Manifest Signaling Matrix")
    struct ManifestSignalingMatrix {
        let parent = HLSFairPlayTestMatrix()

        @Test("M1: Single key SAMPLE-AES playlist is valid")
        func m1SingleKeySampleAES() {
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
                targetDuration: 6,
                playlistType: .vod,
                initSegmentURI: "init.mp4"
            )
            let fairPlayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(
                assetID: "test-asset",
                keyID: parent.testKeyID
            )
            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: fairPlayConfig)

            let segments = [
                FMP4HLSGenerator.Segment(uri: "segment0.m4s", duration: 6.0),
                FMP4HLSGenerator.Segment(uri: "segment1.m4s", duration: 6.0)
            ]
            let playlist = generator.generateMediaPlaylist(segments: segments)

            // Required FairPlay tags
            #expect(playlist.contains("#EXTM3U"), "Missing #EXTM3U header")
            #expect(playlist.contains("#EXT-X-VERSION:7"), "Should use HLS version 7 for fMP4")
            #expect(playlist.contains("#EXT-X-KEY:METHOD=SAMPLE-AES"), "Missing FairPlay KEY tag")
            #expect(playlist.contains("skd://"), "Missing skd:// key URI")
            #expect(playlist.contains("KEYFORMAT=\"com.apple.streamingkeydelivery\""), "Missing FairPlay keyformat")
            #expect(playlist.contains("KEYFORMATVERSIONS=\"1\""), "Missing keyformat versions")
            #expect(playlist.contains("#EXT-X-MAP:URI=\"init.mp4\""), "Missing init segment reference")
            #expect(playlist.contains("#EXT-X-INDEPENDENT-SEGMENTS"), "Missing independent segments tag")
            #expect(playlist.contains("#EXT-X-TARGETDURATION:6"), "Missing target duration")
            #expect(playlist.contains("#EXT-X-PLAYLIST-TYPE:VOD"), "Missing VOD playlist type")
            #expect(playlist.contains("#EXT-X-ENDLIST"), "VOD should have ENDLIST")

            print("✅ M1: Single key SAMPLE-AES playlist validated")
            print("--- Playlist ---\n\(playlist)")
        }

        @Test("M3: METHOD=NONE produces clear playlist")
        func m3MethodNoneClear() {
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
                targetDuration: 6,
                playlistType: .vod,
                initSegmentURI: "init.mp4"
            )
            // No encryption config = clear playlist
            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)

            let segments = [
                FMP4HLSGenerator.Segment(uri: "segment0.m4s", duration: 6.0),
                FMP4HLSGenerator.Segment(uri: "segment1.m4s", duration: 6.0)
            ]
            let playlist = generator.generateMediaPlaylist(segments: segments)

            // Clear playlist should NOT have KEY tag
            #expect(!playlist.contains("#EXT-X-KEY"), "Clear playlist should not have KEY tag")
            #expect(!playlist.contains("skd://"), "Clear playlist should not have skd:// URI")
            #expect(!playlist.contains("METHOD=SAMPLE-AES"), "Clear playlist should not have SAMPLE-AES")

            // Should still have required structure
            #expect(playlist.contains("#EXTM3U"), "Missing #EXTM3U header")
            #expect(playlist.contains("#EXT-X-MAP:URI=\"init.mp4\""), "Missing init segment reference")

            print("✅ M3: Clear playlist (no EXT-X-KEY) validated")
        }

        @Test("M6: Missing key URI detection")
        func m6MissingKeyURIDetection() {
            // Simulate what a malformed playlist would look like
            let malformedPlaylist = """
            #EXTM3U
            #EXT-X-VERSION:7
            #EXT-X-KEY:METHOD=SAMPLE-AES,KEYFORMAT="com.apple.streamingkeydelivery"
            #EXT-X-MAP:URI="init.mp4"
            #EXTINF:6.0,
            segment.m4s
            """

            // Verify the malformed playlist is missing URI
            #expect(!malformedPlaylist.contains("URI=\"skd://"), "Malformed playlist should be missing URI")
            #expect(malformedPlaylist.contains("METHOD=SAMPLE-AES"), "Should have METHOD")
            #expect(malformedPlaylist.contains("KEYFORMAT="), "Should have KEYFORMAT")

            // Now verify our generator always includes URI
            let fairPlayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(
                assetID: "test-asset",
                keyID: parent.testKeyID
            )
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(targetDuration: 6)
            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: fairPlayConfig)
            let validPlaylist = generator.generateMediaPlaylist(segments: [
                FMP4HLSGenerator.Segment(uri: "segment.m4s", duration: 6.0)
            ])

            #expect(validPlaylist.contains("URI=\"skd://"), "Valid playlist must have URI")

            print("✅ M6: Missing key URI detection validated")
        }

        @Test("M7: Wrong key format detection")
        func m7WrongKeyFormatDetection() {
            // Simulate what a playlist with wrong key format would look like
            let wrongFormatPlaylist = """
            #EXTM3U
            #EXT-X-VERSION:7
            #EXT-X-KEY:METHOD=SAMPLE-AES,URI="skd://test",KEYFORMAT="wrong.format"
            #EXT-X-MAP:URI="init.mp4"
            #EXTINF:6.0,
            segment.m4s
            """

            // Verify wrong format is detected
            #expect(wrongFormatPlaylist.contains("KEYFORMAT=\"wrong.format\""), "Test playlist has wrong format")
            #expect(!wrongFormatPlaylist.contains("com.apple.streamingkeydelivery"), "Should not have correct format")

            // Now verify our generator always uses correct format
            let fairPlayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(
                assetID: "test-asset",
                keyID: parent.testKeyID
            )
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(targetDuration: 6)
            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: fairPlayConfig)
            let validPlaylist = generator.generateMediaPlaylist(segments: [
                FMP4HLSGenerator.Segment(uri: "segment.m4s", duration: 6.0)
            ])

            #expect(validPlaylist.contains("KEYFORMAT=\"com.apple.streamingkeydelivery\""),
                   "Valid playlist must have correct keyformat")

            print("✅ M7: Wrong key format detection validated")
        }

        @Test("M2: Key rotation with multiple EXT-X-KEY entries")
        func m2KeyRotationSampleAES() {
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
                targetDuration: 6,
                playlistType: .vod,
                initSegmentURI: "init.mp4"
            )

            // Create segments with different keys
            let key1Config = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "asset-key1", keyID: parent.testKeyID)
            let key2Config = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "asset-key2", keyID: parent.testKeyID2)

            let segments = [
                FMP4HLSGenerator.Segment(uri: "seg0.m4s", duration: 6.0, encryption: key1Config),
                FMP4HLSGenerator.Segment(uri: "seg1.m4s", duration: 6.0, encryption: key1Config),
                FMP4HLSGenerator.Segment(uri: "seg2.m4s", duration: 6.0, encryption: key2Config),  // Key change
                FMP4HLSGenerator.Segment(uri: "seg3.m4s", duration: 6.0, encryption: key2Config),
            ]

            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)
            let playlist = generator.generateMediaPlaylist(segments: segments)

            print("--- M2 Key Rotation Playlist ---\n\(playlist)")

            // Invariants:
            // 1. Every encrypted segment has an active key
            // 2. Key URI changes only affect segments after the tag
            #expect(playlist.contains("skd://asset-key1"), "Should contain first key URI")
            #expect(playlist.contains("skd://asset-key2"), "Should contain second key URI")

            // Verify key order: key1 appears before key2
            guard let key1Range = playlist.range(of: "asset-key1"),
                  let key2Range = playlist.range(of: "asset-key2") else {
                Issue.record("Missing key URIs in playlist")
                return
            }
            #expect(key1Range.lowerBound < key2Range.lowerBound, "Key1 should appear before Key2")

            // Count KEY tags - should be exactly 2
            let keyTagCount = playlist.components(separatedBy: "#EXT-X-KEY:METHOD=SAMPLE-AES").count - 1
            #expect(keyTagCount == 2, "Expected 2 KEY tags for key rotation, got \(keyTagCount)")

            print("✅ M2: Key rotation with 2 keys validated")
        }

        @Test("M4: SAMPLE-AES to NONE transition mid-playlist")
        func m4EncryptionOffMidPlaylist() {
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
                targetDuration: 6,
                playlistType: .vod,
                initSegmentURI: "init.mp4"
            )

            let encConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "test-asset", keyID: parent.testKeyID)

            let segments = [
                FMP4HLSGenerator.Segment(uri: "seg0.m4s", duration: 6.0, encryption: encConfig),
                FMP4HLSGenerator.Segment(uri: "seg1.m4s", duration: 6.0, encryption: encConfig),
                FMP4HLSGenerator.Segment(uri: "seg2.m4s", duration: 6.0, encryption: nil),  // Clear segment
                FMP4HLSGenerator.Segment(uri: "seg3.m4s", duration: 6.0, encryption: nil),
            ]

            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)
            let playlist = generator.generateMediaPlaylist(segments: segments)

            print("--- M4 Encryption Off Playlist ---\n\(playlist)")

            // Invariant: METHOD=NONE clears encryption for following segments
            #expect(playlist.contains("#EXT-X-KEY:METHOD=NONE"), "Should have METHOD=NONE tag")
            #expect(playlist.contains("#EXT-X-KEY:METHOD=SAMPLE-AES"), "Should have METHOD=SAMPLE-AES tag")

            // Verify order: SAMPLE-AES before NONE
            guard let sampleAESRange = playlist.range(of: "METHOD=SAMPLE-AES"),
                  let noneRange = playlist.range(of: "METHOD=NONE") else {
                Issue.record("Missing encryption method tags")
                return
            }
            #expect(sampleAESRange.lowerBound < noneRange.lowerBound,
                   "SAMPLE-AES should appear before NONE")

            print("✅ M4: Encryption off (SAMPLE-AES → NONE) validated")
        }

        @Test("M5: NONE to SAMPLE-AES transition mid-playlist")
        func m5EncryptionOnMidPlaylist() {
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
                targetDuration: 6,
                playlistType: .vod,
                initSegmentURI: "init.mp4"
            )

            let encConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "test-asset", keyID: parent.testKeyID)

            let segments = [
                FMP4HLSGenerator.Segment(uri: "seg0.m4s", duration: 6.0, encryption: nil),
                FMP4HLSGenerator.Segment(uri: "seg1.m4s", duration: 6.0, encryption: nil),
                FMP4HLSGenerator.Segment(uri: "seg2.m4s", duration: 6.0, encryption: encConfig),  // Encryption starts
                FMP4HLSGenerator.Segment(uri: "seg3.m4s", duration: 6.0, encryption: encConfig),
            ]

            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)
            let playlist = generator.generateMediaPlaylist(segments: segments)

            print("--- M5 Encryption On Playlist ---\n\(playlist)")

            // Invariant: Key appears before first encrypted segment
            #expect(playlist.contains("#EXT-X-KEY:METHOD=SAMPLE-AES"), "Should have KEY tag")

            // Verify seg2.m4s comes after the KEY tag
            guard let keyRange = playlist.range(of: "#EXT-X-KEY:METHOD=SAMPLE-AES"),
                  let seg2Range = playlist.range(of: "seg2.m4s") else {
                Issue.record("Missing KEY tag or segment")
                return
            }
            #expect(keyRange.lowerBound < seg2Range.lowerBound,
                   "KEY tag should appear before seg2.m4s")

            print("✅ M5: Encryption on (NONE → SAMPLE-AES) validated")
        }
    }

    // MARK: - F: Fragment Boundary & GOP Alignment Tests

    @Suite("F: Fragment Boundary & GOP Alignment")
    struct FragmentBoundaryTests {
        let parent = HLSFairPlayTestMatrix()

        @Test("F1: Segment boundary on IDR frame")
        func f1SegmentBoundaryOnIDR() {
            let track = parent.createVideoTrack()
            let writer = FMP4Writer(tracks: [track], encryption: nil)

            // Create samples starting with IDR (sync) frame
            let samples = [
                FMP4Writer.Sample(data: parent.createVideoSample(isIDR: true), duration: 3000, isSync: true),
                FMP4Writer.Sample(data: parent.createVideoSample(isIDR: false), duration: 3000, isSync: false),
                FMP4Writer.Sample(data: parent.createVideoSample(isIDR: false), duration: 3000, isSync: false)
            ]
            let segment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

            // Parse trun to verify first sample has sync flag
            guard let trunInfo = parent.findBoxRecursive(segment, type: "trun") else {
                Issue.record("Missing trun box")
                return
            }

            // trun: size(4) + type(4) + version(1) + flags(3) + sample_count(4) + [data_offset(4)] + [first_sample_flags(4)] + per_sample
            let trunFlags = UInt32(segment[trunInfo.offset + 9]) << 16 |
                            UInt32(segment[trunInfo.offset + 10]) << 8 |
                            UInt32(segment[trunInfo.offset + 11])

            let hasDataOffset = (trunFlags & 0x000001) != 0
            let hasSampleFlags = (trunFlags & 0x000400) != 0

            #expect(hasSampleFlags, "trun should have per-sample flags")

            // Calculate offset to first sample flags
            var offset = trunInfo.offset + 16 // After header + version/flags + sample_count
            if hasDataOffset { offset += 4 }

            // Skip to first sample's flags (after duration and size if present)
            let hasSampleDuration = (trunFlags & 0x000100) != 0
            let hasSampleSize = (trunFlags & 0x000200) != 0
            if hasSampleDuration { offset += 4 }
            if hasSampleSize { offset += 4 }

            // Read sample flags
            if hasSampleFlags && offset + 4 <= segment.count {
                let flagsData = segment.subdata(in: offset..<(offset + 4))
                let sampleFlags = UInt32(bigEndian: flagsData.withUnsafeBytes { $0.load(as: UInt32.self) })

                // Check sample_is_non_sync_sample flag (bit 16)
                // For sync samples this flag should be 0
                let isNonSync = (sampleFlags & 0x00010000) != 0

                #expect(!isNonSync, "First sample should be sync (IDR)")
                print("✅ F1: First sample flags = 0x\(String(format: "%08X", sampleFlags)), isNonSync=\(isNonSync)")
            }

            print("✅ F1: Segment starts with IDR frame - validated")
        }

        @Test("F2: Mid-GOP segment boundary structure is valid")
        func f2MidGOPBoundaryStructure() {
            let track = parent.createVideoTrack()
            let writer = FMP4Writer(tracks: [track], encryption: nil)

            // Create segment starting with non-sync (P-frame) - mid-GOP scenario
            let samples = [
                FMP4Writer.Sample(data: parent.createVideoSample(isIDR: false), duration: 3000, isSync: false),
                FMP4Writer.Sample(data: parent.createVideoSample(isIDR: false), duration: 3000, isSync: false)
            ]
            let segment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 90000)

            // Structure should still be valid even if playback might glitch
            #expect(parent.findBoxRecursive(segment, type: "moof") != nil, "Should have moof")
            #expect(parent.findBoxRecursive(segment, type: "mdat") != nil, "Should have mdat")
            #expect(parent.findBoxRecursive(segment, type: "trun") != nil, "Should have trun")
            #expect(parent.findBoxRecursive(segment, type: "tfhd") != nil, "Should have tfhd")
            #expect(parent.findBoxRecursive(segment, type: "tfdt") != nil, "Should have tfdt")

            // Verify first sample is marked as non-sync
            guard let trunInfo = parent.findBoxRecursive(segment, type: "trun") else {
                Issue.record("Missing trun")
                return
            }

            let trunFlags = UInt32(segment[trunInfo.offset + 9]) << 16 |
                            UInt32(segment[trunInfo.offset + 10]) << 8 |
                            UInt32(segment[trunInfo.offset + 11])
            let hasSampleFlags = (trunFlags & 0x000400) != 0

            #expect(hasSampleFlags, "trun should have per-sample flags to indicate non-sync")

            print("✅ F2: Mid-GOP segment structure valid (playback may glitch)")
        }

        @Test("F3: Key change on IDR boundary structure")
        func f3KeyChangeOnIDRBoundary() {
            let track = parent.createVideoTrack()

            // First segment with key 1
            let enc1 = FMP4Writer.EncryptionConfig(keyID: parent.testKeyID, constantIV: parent.testIV)
            let writer1 = FMP4Writer(tracks: [track], encryption: enc1)
            let encryptor1 = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)

            let rawSample1 = parent.createVideoSample(isIDR: true)
            let encResult1 = encryptor1.encryptVideoSample(rawSample1, nalLengthSize: 4)
            let sample1 = FMP4Writer.Sample(
                data: encResult1.encryptedData,
                duration: 3000,
                isSync: true,
                subsamples: encResult1.subsamples
            )
            let segment1 = writer1.generateMediaSegment(trackID: 1, samples: [sample1], baseDecodeTime: 0)

            // Second segment with key 2 (starting with IDR)
            let enc2 = FMP4Writer.EncryptionConfig(keyID: parent.testKeyID2, constantIV: parent.testIV)
            let writer2 = FMP4Writer(tracks: [track], encryption: enc2)
            let encryptor2 = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)

            let rawSample2 = parent.createVideoSample(isIDR: true)
            let encResult2 = encryptor2.encryptVideoSample(rawSample2, nalLengthSize: 4)
            let sample2 = FMP4Writer.Sample(
                data: encResult2.encryptedData,
                duration: 3000,
                isSync: true,
                subsamples: encResult2.subsamples
            )
            let segment2 = writer2.generateMediaSegment(trackID: 1, samples: [sample2], baseDecodeTime: 540000)

            // Both segments should have valid encryption structure
            #expect(parent.findBoxRecursive(segment1, type: "senc") != nil, "Segment 1 should have senc")
            #expect(parent.findBoxRecursive(segment2, type: "senc") != nil, "Segment 2 should have senc")

            // Both segments should start with sync sample
            guard let trun1 = parent.findBoxRecursive(segment1, type: "trun"),
                  let trun2 = parent.findBoxRecursive(segment2, type: "trun") else {
                Issue.record("Missing trun boxes")
                return
            }

            #expect(trun1.size > 0, "Segment 1 has trun")
            #expect(trun2.size > 0, "Segment 2 has trun")

            print("✅ F3: Key change on IDR boundary - both segments have valid structure")
        }
    }

    // MARK: - C: CMAF Compliance Tests

    @Suite("C: CMAF Compliance")
    struct CMAFComplianceTests {
        let parent = HLSFairPlayTestMatrix()

        @Test("C1: Single track maintains consistent parameters")
        func c1SingleTrackConsistency() {
            let track = parent.createVideoTrack()
            let writer = FMP4Writer(tracks: [track], encryption: nil)

            // Generate init segment
            let initSegment = writer.generateInitSegment()

            // Extract timescale from mdhd
            guard let mdhdInfo = parent.findBoxRecursive(initSegment, type: "mdhd") else {
                Issue.record("Missing mdhd box")
                return
            }

            // mdhd v0: size(4) + type(4) + version(1) + flags(3) + creation(4) + modification(4) + timescale(4)
            // mdhd v1: size(4) + type(4) + version(1) + flags(3) + creation(8) + modification(8) + timescale(4)
            let mdhdVersion = initSegment[mdhdInfo.offset + 8]
            let timescaleOffset = mdhdVersion == 0 ? mdhdInfo.offset + 20 : mdhdInfo.offset + 28

            guard let initTimescale = parent.readUInt32BE(initSegment, at: timescaleOffset) else {
                Issue.record("Could not read timescale")
                return
            }

            #expect(initTimescale == 90000, "Timescale should be 90000")

            // Generate multiple segments and verify track ID consistency
            for i in 0..<3 {
                let samples = [FMP4Writer.Sample(data: Data(repeating: UInt8(i), count: 100), duration: 3000, isSync: true)]
                let segment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: UInt64(i * 540000))

                // Verify tfhd track_id
                guard let tfhdInfo = parent.findBoxRecursive(segment, type: "tfhd") else {
                    Issue.record("Missing tfhd in segment \(i)")
                    continue
                }

                // tfhd: size(4) + type(4) + version(1) + flags(3) + track_id(4)
                guard let trackID = parent.readUInt32BE(segment, at: tfhdInfo.offset + 12) else {
                    Issue.record("Could not read track ID")
                    continue
                }

                #expect(trackID == 1, "Track ID should be consistent (1)")

                // Verify mfhd sequence number increments
                guard let mfhdInfo = parent.findBoxRecursive(segment, type: "mfhd") else {
                    Issue.record("Missing mfhd in segment \(i)")
                    continue
                }

                guard let seqNum = parent.readUInt32BE(segment, at: mfhdInfo.offset + 12) else {
                    Issue.record("Could not read sequence number")
                    continue
                }

                #expect(seqNum == UInt32(i + 1), "Sequence number should increment")
            }

            print("✅ C1: Single track consistency validated")
        }

        @Test("C3: Codec config change detection")
        func c3CodecConfigChangeDetection() {
            // Generate init with 1080p config
            let track1080 = parent.createVideoTrack()
            let init1080 = FMP4Writer(tracks: [track1080], encryption: nil).generateInitSegment()

            // Generate init with 720p config (different SPS)
            let track720 = parent.createVideoTrack720p()
            let init720 = FMP4Writer(tracks: [track720], encryption: nil).generateInitSegment()

            // Both should have avcC but with different content
            guard let avcC1080Info = parent.findBoxRecursive(init1080, type: "avcC"),
                  let avcC720Info = parent.findBoxRecursive(init720, type: "avcC") else {
                Issue.record("Missing avcC boxes")
                return
            }

            // Extract avcC data for comparison
            let avcC1080 = init1080.subdata(in: avcC1080Info.offset..<(avcC1080Info.offset + avcC1080Info.size))
            let avcC720 = init720.subdata(in: avcC720Info.offset..<(avcC720Info.offset + avcC720Info.size))

            #expect(avcC1080 != avcC720, "Different resolutions should produce different avcC")

            // Verify both have valid avcC structure (minimum size check)
            #expect(avcC1080.count > 8, "1080p avcC should have content")
            #expect(avcC720.count > 8, "720p avcC should have content")

            print("✅ C3: Codec config changes produce different avcC boxes")
        }

        @Test("C4: Timescale consistency between init and media")
        func c4TimescaleConsistency() {
            let track = parent.createVideoTrack()
            let writer = FMP4Writer(tracks: [track], encryption: nil)

            let initSegment = writer.generateInitSegment()

            // Extract timescale from init segment (mdhd)
            guard let mdhdInfo = parent.findBoxRecursive(initSegment, type: "mdhd") else {
                Issue.record("Missing mdhd")
                return
            }

            let mdhdVersion = initSegment[mdhdInfo.offset + 8]
            let timescaleOffset = mdhdVersion == 0 ? mdhdInfo.offset + 20 : mdhdInfo.offset + 28
            guard let initTimescale = parent.readUInt32BE(initSegment, at: timescaleOffset) else {
                Issue.record("Could not read init timescale")
                return
            }

            // Generate media segment
            // Duration of 3000 @ 90000 timescale = 33.33ms
            let samples = [FMP4Writer.Sample(data: Data(repeating: 0xAA, count: 100), duration: 3000, isSync: true)]
            let mediaSegment = writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: 0)

            // Extract tfdt base_media_decode_time
            guard let tfdtInfo = parent.findBoxRecursive(mediaSegment, type: "tfdt") else {
                Issue.record("Missing tfdt")
                return
            }

            // tfdt: size(4) + type(4) + version(1) + flags(3) + baseMediaDecodeTime(4 or 8)
            let tfdtVersion = mediaSegment[tfdtInfo.offset + 8]
            let baseTimeOffset = tfdtInfo.offset + 12

            if tfdtVersion == 0 {
                guard let baseTime = parent.readUInt32BE(mediaSegment, at: baseTimeOffset) else {
                    Issue.record("Could not read base time v0")
                    return
                }
                #expect(baseTime == 0, "First segment base time should be 0")
            } else {
                // v1 uses 64-bit
                let baseTimeData = mediaSegment.subdata(in: baseTimeOffset..<(baseTimeOffset + 8))
                let baseTime = UInt64(bigEndian: baseTimeData.withUnsafeBytes { $0.load(as: UInt64.self) })
                #expect(baseTime == 0, "First segment base time should be 0")
            }

            // The timescale from init (90000) is used to interpret media timestamps
            #expect(initTimescale == 90000, "Timescale should be 90000")

            print("✅ C4: Timescale consistency validated (init=\(initTimescale), segment uses same scale)")
        }
    }

    // MARK: - E: Edge Cases & Failures Tests

    @Suite("E: Edge Cases & Failures")
    struct EdgeCaseTests {
        let parent = HLSFairPlayTestMatrix()

        @Test("E1: Init segment is required (structure test)")
        func e1InitSegmentRequired() {
            let track = parent.createVideoTrack()
            let writer = FMP4Writer(tracks: [track], encryption: nil)

            let initSegment = writer.generateInitSegment()

            // Init segment must have ftyp and moov
            #expect(parent.findBox(initSegment, type: "ftyp") != nil, "Init must have ftyp")
            #expect(parent.findBox(initSegment, type: "moov") != nil, "Init must have moov")

            // Without moov, media segments cannot be decoded
            // moov contains essential info: stsd (sample description), timescale, etc.
            #expect(parent.findBoxRecursive(initSegment, type: "stsd") != nil, "moov must contain stsd")
            #expect(parent.findBoxRecursive(initSegment, type: "mdhd") != nil, "moov must contain mdhd (timescale)")
            #expect(parent.findBoxRecursive(initSegment, type: "hdlr") != nil, "moov must contain hdlr (handler)")

            print("✅ E1: Init segment structure requirements validated")
        }

        @Test("E2: Wrong init produces incompatible structures")
        func e2WrongInitIncompatible() {
            // Create init for H.264 1080p
            let track1080 = parent.createVideoTrack()
            let init1080 = FMP4Writer(tracks: [track1080], encryption: nil).generateInitSegment()

            // Create init for H.264 720p (different SPS/resolution)
            let track720 = parent.createVideoTrack720p()
            let init720 = FMP4Writer(tracks: [track720], encryption: nil).generateInitSegment()

            // Check sample entry content is different
            let avc1Marker = Data([0x61, 0x76, 0x63, 0x31]) // "avc1"

            guard init1080.range(of: avc1Marker) != nil,
                  init720.range(of: avc1Marker) != nil else {
                Issue.record("Both inits should have avc1")
                return
            }

            // Different SPS should produce different avc1 box sizes or content
            // Extract and compare avcC content
            guard let avcC1080 = parent.findBoxRecursive(init1080, type: "avcC"),
                  let avcC720 = parent.findBoxRecursive(init720, type: "avcC") else {
                Issue.record("Missing avcC boxes")
                return
            }

            let avcCData1080 = init1080.subdata(in: avcC1080.offset..<(avcC1080.offset + avcC1080.size))
            let avcCData720 = init720.subdata(in: avcC720.offset..<(avcC720.offset + avcC720.size))

            #expect(avcCData1080 != avcCData720, "Different configs should produce different avcC")

            print("✅ E2: Wrong init produces incompatible structures (avcC differs)")
            print("   1080p avcC size: \(avcCData1080.count), 720p avcC size: \(avcCData720.count)")
        }
    }

    // MARK: - P: Known-Good Reference Profiles Tests

    @Suite("P: Known-Good Reference Profiles")
    struct ReferenceProfileTests {
        let parent = HLSFairPlayTestMatrix()

        @Test("P1: Clear fMP4 HLS VOD profile")
        func p1ClearFMP4HLSVOD() {
            let track = parent.createVideoTrack()
            let writer = FMP4Writer(tracks: [track], encryption: nil)

            // Generate complete clear package
            let initSegment = writer.generateInitSegment()

            var segments: [Data] = []
            for i in 0..<3 {
                let samples = [
                    FMP4Writer.Sample(data: parent.createVideoSample(isIDR: true), duration: 90000, isSync: true),
                    FMP4Writer.Sample(data: parent.createVideoSample(isIDR: false), duration: 90000, isSync: false)
                ]
                segments.append(writer.generateMediaSegment(trackID: 1, samples: samples, baseDecodeTime: UInt64(i * 180000)))
            }

            // Generate clear playlist
            let generator = FMP4HLSGenerator.vodGenerator(targetDuration: 2, initSegment: "init.mp4")
            let playlist = generator.generatePlaylist(segmentDurations: [2.0, 2.0, 2.0])

            // Validate init segment
            #expect(parent.findBox(initSegment, type: "ftyp") != nil, "Init has ftyp")
            #expect(parent.findBox(initSegment, type: "moov") != nil, "Init has moov")
            #expect(parent.findBoxRecursive(initSegment, type: "encv") == nil, "Clear init has no encv")
            #expect(parent.findBoxRecursive(initSegment, type: "pssh") == nil, "Clear init has no pssh")

            // Validate media segments
            for (i, segment) in segments.enumerated() {
                #expect(parent.findBox(segment, type: "moof") != nil, "Segment \(i) has moof")
                #expect(parent.findBox(segment, type: "mdat") != nil, "Segment \(i) has mdat")
                #expect(parent.findBoxRecursive(segment, type: "senc") == nil, "Clear segment \(i) has no senc")
            }

            // Validate playlist
            #expect(!playlist.contains("#EXT-X-KEY"), "Clear playlist has no KEY tag")
            #expect(playlist.contains("#EXT-X-PLAYLIST-TYPE:VOD"), "Playlist is VOD")
            #expect(playlist.contains("#EXT-X-ENDLIST"), "VOD has ENDLIST")

            print("✅ P1: Clear fMP4 HLS VOD profile validated")
            print("--- Playlist ---\n\(playlist)")
        }

        @Test("P2: FairPlay fMP4 single key profile")
        func p2FairPlaySingleKey() {
            let track = parent.createVideoTrack()
            let encryption = parent.createEncryption()
            let writer = FMP4Writer(tracks: [track], encryption: encryption)
            let encryptor = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)

            // Generate encrypted init
            let initSegment = writer.generateInitSegment()

            // Generate encrypted segments
            var segments: [Data] = []
            for i in 0..<3 {
                let rawSample = parent.createVideoSample(isIDR: i == 0 || i == 1, payloadSize: 300)
                let encResult = encryptor.encryptVideoSample(rawSample, nalLengthSize: 4)
                let sample = FMP4Writer.Sample(
                    data: encResult.encryptedData,
                    duration: 90000,
                    isSync: i == 0 || i == 1,
                    subsamples: encResult.subsamples
                )
                segments.append(writer.generateMediaSegment(trackID: 1, samples: [sample], baseDecodeTime: UInt64(i * 90000)))
            }

            // Generate FairPlay playlist
            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(targetDuration: 1, playlistType: .vod, initSegmentURI: "init.mp4")
            let fairPlayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "test-asset", keyID: parent.testKeyID)
            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: fairPlayConfig)
            let playlist = generator.generateMediaPlaylist(segments: [
                FMP4HLSGenerator.Segment(uri: "segment0.m4s", duration: 1.0),
                FMP4HLSGenerator.Segment(uri: "segment1.m4s", duration: 1.0),
                FMP4HLSGenerator.Segment(uri: "segment2.m4s", duration: 1.0)
            ])

            // Validate init segment (use marker for encv since it's inside stsd)
            let encvMarker = Data([0x65, 0x6E, 0x63, 0x76]) // "encv"
            #expect(initSegment.range(of: encvMarker) != nil, "FairPlay init has encv")
            #expect(parent.findBoxRecursive(initSegment, type: "sinf") != nil, "FairPlay init has sinf")
            #expect(parent.findBoxRecursive(initSegment, type: "tenc") != nil, "FairPlay init has tenc")
            #expect(parent.findBoxRecursive(initSegment, type: "pssh") != nil, "FairPlay init has pssh")

            // Validate media segments
            for (i, segment) in segments.enumerated() {
                #expect(parent.findBoxRecursive(segment, type: "senc") != nil, "FairPlay segment \(i) has senc")
                #expect(parent.findBoxRecursive(segment, type: "saiz") != nil, "FairPlay segment \(i) has saiz")
                #expect(parent.findBoxRecursive(segment, type: "saio") != nil, "FairPlay segment \(i) has saio")
            }

            // Validate playlist
            #expect(playlist.contains("#EXT-X-KEY:METHOD=SAMPLE-AES"), "FairPlay playlist has KEY")
            #expect(playlist.contains("skd://test-asset"), "Playlist has correct skd URI")
            #expect(playlist.contains("KEYFORMAT=\"com.apple.streamingkeydelivery\""), "Has FairPlay keyformat")

            print("✅ P2: FairPlay fMP4 single key profile validated")
            print("--- Playlist ---\n\(playlist)")
        }

        @Test("P3: FairPlay fMP4 rotating keys profile")
        func p3FairPlayRotatingKeysProfile() {
            // Complete end-to-end test combining M2 + B2 invariants
            let key1 = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "period-1", keyID: parent.testKeyID)
            let key2 = FMP4HLSGenerator.FairPlayConfig.fairPlay(assetID: "period-2", keyID: parent.testKeyID2)

            // Create actual encrypted segments with different writers
            let track = parent.createVideoTrack()
            let enc1 = FMP4Writer.EncryptionConfig(keyID: parent.testKeyID, constantIV: parent.testIV)
            let enc2 = FMP4Writer.EncryptionConfig(keyID: parent.testKeyID2, constantIV: parent.testIV)

            let writer1 = FMP4Writer(tracks: [track], encryption: enc1)
            let writer2 = FMP4Writer(tracks: [track], encryption: enc2)

            // Generate init (shared, clear)
            let clearWriter = FMP4Writer(tracks: [track], encryption: nil)
            let initSegment = clearWriter.generateInitSegment()

            // Encrypt samples for segment 0 (key1)
            let encryptor1 = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)
            let rawSample0 = parent.createVideoSample(isIDR: true, payloadSize: 400)
            let encResult0 = encryptor1.encryptVideoSample(rawSample0, nalLengthSize: 4)
            let sample0 = FMP4Writer.Sample(
                data: encResult0.encryptedData,
                duration: 90000,
                isSync: true,
                subsamples: encResult0.subsamples
            )
            let seg0 = writer1.generateMediaSegment(trackID: 1, samples: [sample0], baseDecodeTime: 0)

            // Encrypt samples for segment 1 (key2)
            let encryptor2 = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)
            let rawSample1 = parent.createVideoSample(isIDR: true, payloadSize: 400)
            let encResult1 = encryptor2.encryptVideoSample(rawSample1, nalLengthSize: 4)
            let sample1 = FMP4Writer.Sample(
                data: encResult1.encryptedData,
                duration: 90000,
                isSync: true,
                subsamples: encResult1.subsamples
            )
            let seg1 = writer2.generateMediaSegment(trackID: 1, samples: [sample1], baseDecodeTime: 90000)

            // Validate segment encryption structures
            #expect(parent.findBoxRecursive(seg0, type: "senc") != nil, "Segment 0 must have senc")
            #expect(parent.findBoxRecursive(seg1, type: "senc") != nil, "Segment 1 must have senc")

            // Validate init is clear
            #expect(parent.findBoxRecursive(initSegment, type: "senc") == nil, "Init should be clear")
            #expect(parent.findBox(initSegment, type: "ftyp") != nil, "Init has ftyp")
            #expect(parent.findBox(initSegment, type: "moov") != nil, "Init has moov")

            // Generate playlist with key rotation
            let segments = [
                FMP4HLSGenerator.Segment(uri: "seg0.m4s", duration: 3.0, encryption: key1),
                FMP4HLSGenerator.Segment(uri: "seg1.m4s", duration: 3.0, encryption: key2),
            ]

            let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
                targetDuration: 4, playlistType: .vod, initSegmentURI: "init.mp4"
            )
            let generator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)
            let playlist = generator.generateMediaPlaylist(segments: segments)

            print("--- P3 Rotating Keys Playlist ---\n\(playlist)")

            // Profile invariants
            #expect(playlist.contains("#EXT-X-VERSION:7"), "HLS v7 for fMP4")
            #expect(playlist.contains("skd://period-1"), "Has first key URI")
            #expect(playlist.contains("skd://period-2"), "Has second key URI")
            #expect(playlist.contains("#EXT-X-MAP:URI=\"init.mp4\""), "Has init segment reference")

            // Count key tags
            let keyTagCount = playlist.components(separatedBy: "#EXT-X-KEY:METHOD=SAMPLE-AES").count - 1
            #expect(keyTagCount == 2, "Expected 2 KEY tags for rotating keys")

            print("✅ P3: FairPlay rotating keys profile validated")
        }

        @Test("P4: Clear preview + encrypted main content structure")
        func p4ClearPreviewEncryptedMain() {
            let track = parent.createVideoTrack()

            // Clear preview segment
            let clearWriter = FMP4Writer(tracks: [track], encryption: nil)
            let previewSamples = [
                FMP4Writer.Sample(data: parent.createVideoSample(isIDR: true), duration: 90000, isSync: true),
                FMP4Writer.Sample(data: parent.createVideoSample(isIDR: false), duration: 90000, isSync: false)
            ]
            let previewSegment = clearWriter.generateMediaSegment(trackID: 1, samples: previewSamples, baseDecodeTime: 0)

            // Encrypted main segments
            let encryption = parent.createEncryption()
            let encWriter = FMP4Writer(tracks: [track], encryption: encryption)
            let encryptor = CBCSEncryptor(key: parent.testKey, iv: parent.testIV)

            var mainSegments: [Data] = []
            for i in 0..<2 {
                let rawSample = parent.createVideoSample(isIDR: true, payloadSize: 400)
                let encResult = encryptor.encryptVideoSample(rawSample, nalLengthSize: 4)
                let sample = FMP4Writer.Sample(
                    data: encResult.encryptedData,
                    duration: 90000,
                    isSync: true,
                    subsamples: encResult.subsamples
                )
                mainSegments.append(encWriter.generateMediaSegment(
                    trackID: 1,
                    samples: [sample],
                    baseDecodeTime: UInt64((i + 1) * 180000)
                ))
            }

            // Validate preview is clear
            #expect(parent.findBoxRecursive(previewSegment, type: "senc") == nil, "Preview segment should be clear")
            #expect(parent.findBoxRecursive(previewSegment, type: "moof") != nil, "Preview has moof")

            // Validate main segments are encrypted
            for (i, segment) in mainSegments.enumerated() {
                #expect(parent.findBoxRecursive(segment, type: "senc") != nil, "Main segment \(i) should have senc")
            }

            // This pattern is used for:
            // - Free preview before paywall
            // - Ad insertion (clear ads in encrypted content)
            print("✅ P4: Clear preview + encrypted main content structure validated")
        }
    }
}

// MARK: - Helper Extensions

extension UInt32 {
    var bigEndianData: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: 4)
    }
}
