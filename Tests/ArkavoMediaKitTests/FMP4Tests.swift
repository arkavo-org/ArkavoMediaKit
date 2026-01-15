import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - ISO BMFF Box Tests

@Suite("ISO BMFF Box Serialization")
struct ISOBoxTests {
    // MARK: - FourCC Tests

    @Test("FourCC creates correct 4-byte value")
    func fourCCValue() {
        let ftyp = FourCC("ftyp")
        #expect(ftyp.value == 0x66747970) // 'f' 't' 'y' 'p'

        let moov = FourCC("moov")
        #expect(moov.value == 0x6D6F6F76) // 'm' 'o' 'o' 'v'
    }

    @Test("FourCC serializes to 4 bytes big-endian")
    func fourCCSerialization() {
        let ftyp = FourCC("ftyp")
        let data = ftyp.data
        #expect(data.count == 4)
        #expect(data[0] == 0x66) // 'f'
        #expect(data[1] == 0x74) // 't'
        #expect(data[2] == 0x79) // 'y'
        #expect(data[3] == 0x70) // 'p'
    }

    // MARK: - FileType Box Tests

    @Test("FileTypeBox serializes with correct structure")
    func fileTypeBoxSerialization() {
        let ftyp = FileTypeBox.fairPlayHLS
        let data = ftyp.serialize()

        // Minimum size: 8 (header) + 4 (major brand) + 4 (minor version) + 4*n (compatible brands)
        #expect(data.count >= 20)

        // Check box type at offset 4
        #expect(data[4] == 0x66) // 'f'
        #expect(data[5] == 0x74) // 't'
        #expect(data[6] == 0x79) // 'y'
        #expect(data[7] == 0x70) // 'p'

        // Check major brand "isom" at offset 8
        #expect(data[8] == 0x69)  // 'i'
        #expect(data[9] == 0x73)  // 's'
        #expect(data[10] == 0x6F) // 'o'
        #expect(data[11] == 0x6D) // 'm'
    }

    // MARK: - Container Box Tests

    @Test("ContainerBox serializes children correctly")
    func containerBoxSerialization() {
        var moov = ContainerBox(type: .moov)

        // Add a simple child (mvhd placeholder)
        let mvhd = MovieHeaderBox(timescale: 90000, duration: 0, nextTrackID: 2)
        moov.append(mvhd)

        let data = moov.serialize()

        // Check moov box type
        #expect(data[4] == 0x6D) // 'm'
        #expect(data[5] == 0x6F) // 'o'
        #expect(data[6] == 0x6F) // 'o'
        #expect(data[7] == 0x76) // 'v'

        // Child should follow immediately after moov header (8 bytes)
        // mvhd should be at offset 8
        #expect(data[12] == 0x6D) // 'm'
        #expect(data[13] == 0x76) // 'v'
        #expect(data[14] == 0x68) // 'h'
        #expect(data[15] == 0x64) // 'd'
    }

    // MARK: - Movie Header Box Tests

    @Test("MovieHeaderBox has correct version and flags")
    func movieHeaderBoxVersion() {
        let mvhd = MovieHeaderBox(timescale: 90000, duration: 0, nextTrackID: 2)
        let data = mvhd.serialize()

        // Skip size (4) + type (4), then version (1) + flags (3)
        #expect(data[8] == 1) // Version 1 for 64-bit times
        #expect(data[9] == 0)  // Flags byte 1
        #expect(data[10] == 0) // Flags byte 2
        #expect(data[11] == 0) // Flags byte 3
    }

    @Test("MovieHeaderBox contains timescale")
    func movieHeaderBoxTimescale() {
        let mvhd = MovieHeaderBox(timescale: 90000, duration: 0, nextTrackID: 2)
        let data = mvhd.serialize()

        // Version 1: offset 8 (version+flags) + 8 (creation) + 8 (modification) = 24
        // Timescale at offset 8 + 4 + 8 + 8 = 28
        let timescaleOffset = 28
        let timescale = UInt32(bigEndian: data.subdata(in: timescaleOffset..<timescaleOffset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
        #expect(timescale == 90000)
    }

    // MARK: - Track Header Box Tests

    @Test("TrackHeaderBox has enabled flags set")
    func trackHeaderBoxFlags() {
        let tkhd = TrackHeaderBox(trackID: 1, duration: 0, width: 1920, height: 1080, isAudio: false)
        let data = tkhd.serialize()

        // Flags at offset 8+1 = 9 (3 bytes)
        // Should have track_enabled (0x1) | track_in_movie (0x2) | track_in_preview (0x4) = 0x7
        #expect(data[9] == 0)
        #expect(data[10] == 0)
        #expect(data[11] == 0x07)
    }

    // MARK: - Handler Box Tests

    @Test("HandlerBox video has correct type")
    func handlerBoxVideo() {
        let hdlr = HandlerBox.video
        let data = hdlr.serialize()

        // Handler type at offset 8 (version+flags) + 4 (pre-defined) = 16
        let handlerOffset = 16
        #expect(data[handlerOffset] == 0x76)     // 'v'
        #expect(data[handlerOffset + 1] == 0x69) // 'i'
        #expect(data[handlerOffset + 2] == 0x64) // 'd'
        #expect(data[handlerOffset + 3] == 0x65) // 'e'
    }

    @Test("HandlerBox audio has correct type")
    func handlerBoxAudio() {
        let hdlr = HandlerBox.audio
        let data = hdlr.serialize()

        let handlerOffset = 16
        #expect(data[handlerOffset] == 0x73)     // 's'
        #expect(data[handlerOffset + 1] == 0x6F) // 'o'
        #expect(data[handlerOffset + 2] == 0x75) // 'u'
        #expect(data[handlerOffset + 3] == 0x6E) // 'n'
    }
}

// MARK: - Encryption Box Tests

@Suite("Encryption Box Serialization")
struct EncryptionBoxTests {
    @Test("TrackEncryptionBox has CBCS pattern")
    func trackEncryptionBoxPattern() {
        let tenc = TrackEncryptionBox(
            defaultIsProtected: 1,
            defaultPerSampleIVSize: 0,
            defaultKID: Data(repeating: 0xAB, count: 16),
            defaultConstantIV: Data(repeating: 0xCD, count: 16),
            defaultCryptByteBlock: 1,
            defaultSkipByteBlock: 9
        )
        let data = tenc.serialize()

        // Version should be 1 for pattern encryption
        #expect(data[8] == 1)

        // Pattern byte at offset 8 (version+flags) + 1 (reserved) = 13
        // Pattern = (crypt << 4) | skip = (1 << 4) | 9 = 0x19
        #expect(data[13] == 0x19)
    }

    @Test("ProtectionSystemSpecificHeaderBox has FairPlay system ID")
    func psshFairPlaySystemID() {
        let pssh = ProtectionSystemSpecificHeaderBox(
            systemID: ProtectionSystemSpecificHeaderBox.fairPlaySystemID,
            keyIDs: [Data(repeating: 0x12, count: 16)]
        )
        let data = pssh.serialize()

        // System ID at offset 12 (size + type + version + flags)
        let systemIDOffset = 12
        let systemID = data.subdata(in: systemIDOffset..<systemIDOffset+16)
        #expect(systemID == ProtectionSystemSpecificHeaderBox.fairPlaySystemID)
    }

    @Test("SampleEncryptionBox has subsample flag")
    func sencSubsampleFlag() {
        let entry = SampleEncryptionEntry(
            iv: nil,
            subsamples: [SubsampleEntry(bytesOfClearData: 5, bytesOfProtectedData: 100)]
        )
        let senc = SampleEncryptionBox(entries: [entry], useSubsampleEncryption: true)
        let data = senc.serialize()

        // Flags at offset 9-11, subsample flag is 0x02
        #expect((data[11] & 0x02) == 0x02)
    }
}

// MARK: - Media Segment Box Tests

@Suite("Media Segment Box Serialization")
struct MediaSegmentBoxTests {
    @Test("MovieFragmentHeaderBox has sequence number")
    func mfhdSequenceNumber() {
        let mfhd = MovieFragmentHeaderBox(sequenceNumber: 42)
        let data = mfhd.serialize()

        // Sequence number at offset 12 (size + type + version + flags)
        let seqOffset = 12
        let seq = UInt32(bigEndian: data.subdata(in: seqOffset..<seqOffset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
        #expect(seq == 42)
    }

    @Test("TrackFragmentDecodeTimeBox has base decode time")
    func tfdtDecodeTime() {
        let tfdt = TrackFragmentDecodeTimeBox(baseMediaDecodeTime: 90000)
        let data = tfdt.serialize()

        // Version 0 (fits in 32 bits), decode time at offset 12
        #expect(data[8] == 0) // Version 0
        let timeOffset = 12
        let time = UInt32(bigEndian: data.subdata(in: timeOffset..<timeOffset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
        #expect(time == 90000)
    }

    @Test("TrackRunBox has data offset flag")
    func trunDataOffset() {
        let sample = TrackRunSample(duration: 3000, size: 1024, flags: TrackRunSample.syncFlags())
        let trun = TrackRunBox(samples: [sample], dataOffset: 100)
        let data = trun.serialize()

        // Check data_offset_present flag (0x01)
        #expect((data[11] & 0x01) == 0x01)
    }

    @Test("TrackRunSample sync flags are correct")
    func trunSyncFlags() {
        let syncFlags = TrackRunSample.syncFlags()
        let nonSyncFlags = TrackRunSample.nonSyncFlags()

        // Sync sample should have is_leading=0, depends_on=2, is_depended_on=0, has_redundancy=0
        #expect(syncFlags == 0x02000000)

        // Non-sync should have depends_on=1, is_non_sync=1
        #expect(nonSyncFlags == 0x01010000)
    }
}

// MARK: - Codec Box Tests

@Suite("Codec Box Serialization")
struct CodecBoxTests {
    @Test("AVCDecoderConfigurationRecord contains SPS/PPS")
    func avcCContainsSPSPPS() {
        let sps = Data([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40]) // Sample SPS
        let pps = Data([0x68, 0xEE, 0x3C, 0x80]) // Sample PPS

        let avcC = AVCDecoderConfigurationRecord(sps: [sps], pps: [pps])
        let data = avcC.serialize()

        // Config version at offset 8
        #expect(data[8] == 1)

        // Profile from SPS at offset 9
        #expect(data[9] == 0x64) // High profile

        // Find SPS in data
        #expect(data.range(of: sps) != nil)

        // Find PPS in data
        #expect(data.range(of: pps) != nil)
    }

    @Test("ElementaryStreamDescriptor has AAC object type")
    func esdsAACObjectType() {
        let asc = Data([0x11, 0x90]) // AAC-LC, 48kHz, stereo
        let esds = ElementaryStreamDescriptor(audioSpecificConfig: asc)
        let data = esds.serialize()

        // Should contain ES_DescrTag (0x03)
        #expect(data.contains(0x03))

        // Should contain DecoderConfigDescrTag (0x04)
        #expect(data.contains(0x04))

        // Should contain objectTypeIndication 0x40 (Audio ISO/IEC 14496-3)
        #expect(data.contains(0x40))
    }
}
