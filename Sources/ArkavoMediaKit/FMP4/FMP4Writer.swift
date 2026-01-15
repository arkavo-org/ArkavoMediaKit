import AVFoundation
import Foundation

// MARK: - FMP4 Writer

/// Fragmented MP4 writer for creating HLS-compatible fMP4 segments
public final class FMP4Writer {
    // MARK: - Types

    /// Track configuration for init segment
    public struct TrackConfig {
        public let trackID: UInt32
        public let mediaType: MediaType
        public let timescale: UInt32

        // Video-specific
        public let width: UInt16?
        public let height: UInt16?
        public let codecData: CodecData?

        // Audio-specific
        public let channelCount: UInt16?
        public let sampleRate: UInt32?

        public enum MediaType {
            case video
            case audio
        }

        public enum CodecData {
            case avc(sps: [Data], pps: [Data])
            case hevc(vps: [Data], sps: [Data], pps: [Data])
            case aac(audioSpecificConfig: Data)
        }

        /// Create video track config for H.264
        public static func h264Video(trackID: UInt32 = 1,
                                     width: UInt16,
                                     height: UInt16,
                                     timescale: UInt32 = 90000,
                                     sps: [Data],
                                     pps: [Data]) -> TrackConfig {
            TrackConfig(
                trackID: trackID,
                mediaType: .video,
                timescale: timescale,
                width: width,
                height: height,
                codecData: .avc(sps: sps, pps: pps),
                channelCount: nil,
                sampleRate: nil
            )
        }

        /// Create video track config for H.265/HEVC
        public static func hevcVideo(trackID: UInt32 = 1,
                                     width: UInt16,
                                     height: UInt16,
                                     timescale: UInt32 = 90000,
                                     vps: [Data],
                                     sps: [Data],
                                     pps: [Data]) -> TrackConfig {
            TrackConfig(
                trackID: trackID,
                mediaType: .video,
                timescale: timescale,
                width: width,
                height: height,
                codecData: .hevc(vps: vps, sps: sps, pps: pps),
                channelCount: nil,
                sampleRate: nil
            )
        }

        /// Create audio track config for AAC
        public static func aacAudio(trackID: UInt32 = 2,
                                    channelCount: UInt16,
                                    sampleRate: UInt32,
                                    audioSpecificConfig: Data) -> TrackConfig {
            TrackConfig(
                trackID: trackID,
                mediaType: .audio,
                timescale: sampleRate,
                width: nil,
                height: nil,
                codecData: .aac(audioSpecificConfig: audioSpecificConfig),
                channelCount: channelCount,
                sampleRate: sampleRate
            )
        }
    }

    /// Encryption configuration for CBCS
    public struct EncryptionConfig {
        public let keyID: Data       // 16 bytes
        public let constantIV: Data  // 16 bytes
        public let cryptByteBlock: UInt8
        public let skipByteBlock: UInt8

        public init(keyID: Data, constantIV: Data, cryptByteBlock: UInt8 = 1, skipByteBlock: UInt8 = 9) {
            precondition(keyID.count == 16, "Key ID must be 16 bytes")
            precondition(constantIV.count == 16, "Constant IV must be 16 bytes")
            self.keyID = keyID
            self.constantIV = constantIV
            self.cryptByteBlock = cryptByteBlock
            self.skipByteBlock = skipByteBlock
        }
    }

    /// Sample to be written
    public struct Sample {
        public let data: Data
        public let duration: UInt32
        public let isSync: Bool
        public let compositionTimeOffset: Int32
        public let subsamples: [SubsampleEntry]?  // Encryption subsample info

        public init(data: Data, duration: UInt32, isSync: Bool = false, compositionTimeOffset: Int32 = 0, subsamples: [SubsampleEntry]? = nil) {
            self.data = data
            self.duration = duration
            self.isSync = isSync
            self.compositionTimeOffset = compositionTimeOffset
            self.subsamples = subsamples
        }
    }

    // MARK: - Properties

    private let tracks: [TrackConfig]
    private let encryption: EncryptionConfig?
    private var sequenceNumber: UInt32 = 0

    // MARK: - Initialization

    public init(tracks: [TrackConfig], encryption: EncryptionConfig? = nil) {
        self.tracks = tracks
        self.encryption = encryption
    }

    // MARK: - Init Segment Generation

    /// Generate initialization segment (ftyp + moov)
    public func generateInitSegment() -> Data {
        var data = Data()

        // ftyp
        let ftyp = FileTypeBox.fairPlayHLS
        data.append(ftyp.serialize())

        // moov
        let moov = generateMoov()
        data.append(moov.serialize())

        return data
    }

    private func generateMoov() -> ContainerBox {
        var moov = ContainerBox(type: .moov)

        // mvhd - use first track's timescale
        let timescale = tracks.first?.timescale ?? 90000
        let mvhd = MovieHeaderBox(timescale: timescale, duration: 0, nextTrackID: UInt32(tracks.count + 1))
        moov.append(mvhd)

        // trak for each track
        for track in tracks {
            let trak = generateTrak(for: track)
            moov.append(trak)
        }

        // mvex - movie extends for fragmented content
        var mvex = ContainerBox(type: .mvex)
        for track in tracks {
            let trex = TrackExtendsBox(
                trackID: track.trackID,
                defaultSampleDescriptionIndex: 1,
                defaultSampleDuration: 0,
                defaultSampleSize: 0,
                defaultSampleFlags: 0
            )
            mvex.append(trex)
        }
        moov.append(mvex)

        // pssh - protection system specific header (if encrypted)
        if let enc = encryption {
            let pssh = ProtectionSystemSpecificHeaderBox(
                systemID: ProtectionSystemSpecificHeaderBox.fairPlaySystemID,
                keyIDs: [enc.keyID]
            )
            moov.append(pssh)
        }

        return moov
    }

    private func generateTrak(for track: TrackConfig) -> ContainerBox {
        var trak = ContainerBox(type: .trak)

        // tkhd
        let isAudio = track.mediaType == .audio
        let tkhd = TrackHeaderBox(
            trackID: track.trackID,
            duration: 0,
            width: UInt32(track.width ?? 0),
            height: UInt32(track.height ?? 0),
            isAudio: isAudio
        )
        trak.append(tkhd)

        // edts - edit list for presentation time mapping (required by Apple HLS Authoring Spec)
        var edts = ContainerBox(type: .edts)
        edts.append(EditListBox.identity)
        trak.append(edts)

        // mdia
        let mdia = generateMdia(for: track)
        trak.append(mdia)

        return trak
    }

    private func generateMdia(for track: TrackConfig) -> ContainerBox {
        var mdia = ContainerBox(type: .mdia)

        // mdhd
        let mdhd = MediaHeaderBox(timescale: track.timescale, duration: 0)
        mdia.append(mdhd)

        // hdlr
        let hdlr = track.mediaType == .video ? HandlerBox.video : HandlerBox.audio
        mdia.append(hdlr)

        // minf
        let minf = generateMinf(for: track)
        mdia.append(minf)

        return mdia
    }

    private func generateMinf(for track: TrackConfig) -> ContainerBox {
        var minf = ContainerBox(type: .minf)

        // vmhd or smhd
        if track.mediaType == .video {
            minf.append(VideoMediaHeaderBox())
        } else {
            minf.append(SoundMediaHeaderBox())
        }

        // dinf
        var dinf = ContainerBox(type: .dinf)
        dinf.append(DataReferenceBox())
        minf.append(dinf)

        // stbl
        let stbl = generateStbl(for: track)
        minf.append(stbl)

        return minf
    }

    private func generateStbl(for track: TrackConfig) -> ContainerBox {
        var stbl = ContainerBox(type: .stbl)

        // stsd - sample description
        let stsd = generateStsd(for: track)
        stbl.append(stsd)

        // Empty timing tables (data is in fragments)
        stbl.append(TimeToSampleBox())
        stbl.append(SampleToChunkBox())
        stbl.append(SampleSizeBox())
        stbl.append(ChunkOffsetBox())

        return stbl
    }

    private func generateStsd(for track: TrackConfig) -> SampleDescriptionBox {
        var entries: [any ISOBox] = []

        let encInfo: SampleEncryptionInfo? = encryption.map {
            SampleEncryptionInfo(
                keyID: $0.keyID,
                constantIV: $0.constantIV,
                cryptByteBlock: $0.cryptByteBlock,
                skipByteBlock: $0.skipByteBlock
            )
        }

        switch track.codecData {
        case .avc(let sps, let pps):
            let avcC = AVCDecoderConfigurationRecord(sps: sps, pps: pps)
            let avc1 = AVCSampleEntry(
                width: track.width ?? 0,
                height: track.height ?? 0,
                avcC: avcC,
                encrypted: encInfo
            )
            // Debug: Verify sample entry type
            print("🔍 [stsd] Sample entry type: \(avc1.type) (expected 'encv' for encrypted content)")
            if encInfo != nil {
                print("🔍 [stsd] Encryption info: keyID=\(encInfo!.keyID.prefix(4).map { String(format: "%02x", $0) }.joined())..., pattern=\(encInfo!.defaultCryptByteBlock):\(encInfo!.defaultSkipByteBlock)")
            } else {
                print("⚠️ [stsd] No encryption info - using clear 'avc1' sample entry!")
            }
            entries.append(avc1)

        case .hevc(let vps, let sps, let pps):
            let hvcC = HEVCDecoderConfigurationRecord(vps: vps, sps: sps, pps: pps)
            let hvc1 = HEVCSampleEntry(
                width: track.width ?? 0,
                height: track.height ?? 0,
                hvcC: hvcC,
                encrypted: encInfo
            )
            entries.append(hvc1)

        case .aac(let audioSpecificConfig):
            let esds = ElementaryStreamDescriptor(audioSpecificConfig: audioSpecificConfig)
            let mp4a = AACSampleEntry(
                channelCount: track.channelCount ?? 2,
                sampleRate: track.sampleRate ?? 48000,
                esds: esds,
                encrypted: encInfo
            )
            entries.append(mp4a)

        case .none:
            break
        }

        return SampleDescriptionBox(entries: entries)
    }

    // MARK: - Media Segment Generation

    /// Generate a media segment (styp + moof + mdat) for a single track
    public func generateMediaSegment(trackID: UInt32,
                                     samples: [Sample],
                                     baseDecodeTime: UInt64) -> Data {
        sequenceNumber += 1

        var data = Data()

        // styp - Segment Type Box (required for CMAF compliance)
        // This identifies the segment as a CMAF encrypted segment
        let styp = SegmentTypeBox.cmafEncryptedSegment
        let stypData = styp.serialize()
        data.append(stypData)
        print("🎬 FMP4Writer: Added styp box (\(stypData.count) bytes) with brands: msdh, msix, cmfc, iso6")

        // Calculate sample data size for offset calculation
        let sampleDataSize = samples.reduce(0) { $0 + $1.data.count }

        // moof - include styp size for correct data_offset calculation
        let moof = generateMoof(
            trackID: trackID,
            samples: samples,
            baseDecodeTime: baseDecodeTime,
            sampleDataSize: sampleDataSize,
            stypSize: stypData.count
        )
        let moofData = moof.serialize()
        data.append(moofData)

        // mdat
        let mdat = generateMdat(samples: samples)
        data.append(mdat.serialize())

        return data
    }

    private func generateMoof(trackID: UInt32,
                              samples: [Sample],
                              baseDecodeTime: UInt64,
                              sampleDataSize: Int,
                              stypSize: Int = 0) -> ContainerBox {
        var moof = ContainerBox(type: .moof)

        // mfhd
        let mfhd = MovieFragmentHeaderBox(sequenceNumber: sequenceNumber)
        moof.append(mfhd)

        // traf
        let traf = generateTraf(
            trackID: trackID,
            samples: samples,
            baseDecodeTime: baseDecodeTime,
            dataOffsetBase: 0, // Will be calculated
            stypSize: stypSize
        )
        moof.append(traf)

        // Recalculate with correct offset for data_offset
        // When default-base-is-moof flag is set in tfhd, data_offset is relative to
        // the first byte of moof (not segment start). This is per ISO 14496-12.
        let moofSize = moof.serialize().count
        let mdatHeaderSize = 8 // mdat box header
        let dataOffsetBase = moofSize + mdatHeaderSize

        // Rebuild traf with correct offset
        var correctedMoof = ContainerBox(type: .moof)
        correctedMoof.append(mfhd)

        let correctedTraf = generateTraf(
            trackID: trackID,
            samples: samples,
            baseDecodeTime: baseDecodeTime,
            dataOffsetBase: dataOffsetBase,
            stypSize: stypSize
        )
        correctedMoof.append(correctedTraf)

        return correctedMoof
    }

    private func generateTraf(trackID: UInt32,
                              samples: [Sample],
                              baseDecodeTime: UInt64,
                              dataOffsetBase: Int,
                              stypSize: Int = 0) -> ContainerBox {
        var traf = ContainerBox(type: .traf)

        // tfhd
        // sample_description_index = 1 tells decoder to use the first stsd entry (encv)
        // This is critical for encrypted content - without it, decoder may not find encryption info
        let tfhd = TrackFragmentHeaderBox(
            trackID: trackID,
            sampleDescriptionIndex: 1,
            defaultBaseIsMoof: true
        )
        traf.append(tfhd)

        // Debug: Verify tfhd flags
        // Box structure: size(4) + type(4) + version(1) + flags(3) + trackID(4) + ...
        let tfhdBytes = tfhd.serialize()
        if tfhdBytes.count >= 12 {
            let version = tfhdBytes[8]
            let flags = UInt32(tfhdBytes[9]) << 16 | UInt32(tfhdBytes[10]) << 8 | UInt32(tfhdBytes[11])
            let defaultBaseIsMoofSet = (flags & 0x020000) != 0
            let sampleDescIndexPresent = (flags & 0x000002) != 0
            print("🔍 [tfhd] version=\(version), flags=0x\(String(format: "%06x", flags)), default-base-is-moof=\(defaultBaseIsMoofSet), sample-desc-index=\(sampleDescIndexPresent)")
        }

        // tfdt
        let tfdt = TrackFragmentDecodeTimeBox(baseMediaDecodeTime: baseDecodeTime)
        traf.append(tfdt)

        // trun
        let trunSamples = samples.map { sample in
            TrackRunSample(
                duration: sample.duration,
                size: UInt32(sample.data.count),
                flags: sample.isSync ? TrackRunSample.syncFlags() : TrackRunSample.nonSyncFlags(),
                compositionTimeOffset: sample.compositionTimeOffset
            )
        }

        // Data offset from fragment start to mdat payload
        // AVPlayer uses fragment start as base (not moof start) despite default-base-is-moof
        let dataOffset = Int32(dataOffsetBase)

        if dataOffsetBase > 0 {
             print("🐞 FMP4Writer: dataOffsetBase = \(dataOffsetBase), trun dataOffset = \(dataOffset)")
        }

        // Don't use firstSampleFlags when per-sample flags are present - they're mutually exclusive
        // Per-sample flags already include sync/non-sync info for each sample
        let trun = TrackRunBox(
            samples: trunSamples,
            dataOffset: dataOffset,
            firstSampleFlags: nil
        )
        traf.append(trun)

        // senc, saiz, saio for encryption (if enabled)
        if encryption != nil {
            // Calculate offset to senc sample data from moof start
            // When default-base-is-moof flag is set in tfhd, offsets are relative to moof start
            // Structure: moof(8) + mfhd(16) + traf(8) + tfhd + tfdt + trun + senc_header(8) + version_flags(4) + sample_count(4)
            let tfhdSize = tfhd.serialize().count
            let tfdtSize = tfdt.serialize().count
            let trunSize = trun.serialize().count

            // Offset from moof start to senc sample auxiliary data
            // moof header (8) + mfhd (16) + traf header (8) + tfhd + tfdt + trun + senc overhead (16)
            let sencDataOffset = 8 + 16 + 8 + tfhdSize + tfdtSize + trunSize + 16

            print("🐞 FMP4Writer: sencDataOffset = \(sencDataOffset) (tfhd=\(tfhdSize), tfdt=\(tfdtSize), trun=\(trunSize))")

            let (senc, saiz, saio) = generateEncryptionBoxes(samples: samples, sencDataOffset: sencDataOffset)
            traf.append(senc)
            traf.append(saiz)
            traf.append(saio)
        }

        return traf
    }

    private func generateEncryptionBoxes(samples: [Sample], sencDataOffset: Int = 0) -> (SampleEncryptionBox, SampleAuxiliaryInfoSizesBox, SampleAuxiliaryInfoOffsetsBox) {
        // For CBCS with constant IV, we don't need per-sample IVs
        // Use actual subsample info from CBCSEncryptor if available

        var entries: [SampleEncryptionEntry] = []
        var sampleInfoSizes: [Int] = []

        for (sampleIdx, sample) in samples.enumerated() {
            let subsamples: [SubsampleEntry]

            if let actualSubsamples = sample.subsamples, !actualSubsamples.isEmpty {
                // Use actual subsample info from encryption
                subsamples = actualSubsamples
            } else {
                // Fallback: treat entire sample as protected (for unencrypted or unknown)
                subsamples = [SubsampleEntry(
                    bytesOfClearData: 0,
                    bytesOfProtectedData: UInt32(sample.data.count)
                )]
            }

            // CRITICAL ALIGNMENT VERIFICATION at write time
            let sampleSize = sample.data.count
            let subsampleSum = subsamples.reduce(0) { $0 + Int($1.bytesOfClearData) + Int($1.bytesOfProtectedData) }
            if subsampleSum != sampleSize {
                print("❌ [FMP4Writer] CRITICAL ALIGNMENT ERROR in sample \(sampleIdx):")
                print("   sample.data.count = \(sampleSize)")
                print("   sum(subsamples) = \(subsampleSum)")
                print("   Difference: \(abs(subsampleSum - sampleSize)) bytes")
                print("   Subsamples: \(subsamples.map { "[\($0.bytesOfClearData)c/\($0.bytesOfProtectedData)p]" }.joined(separator: " "))")
                print("   ⚠️ This WILL cause AVPlayer decryption failure!")
            }

            let entry = SampleEncryptionEntry(iv: nil, subsamples: subsamples)
            entries.append(entry)

            // Size = 2 (subsample count) + 6 bytes per subsample entry (2 clear + 4 protected)
            let infoSize = 2 + (subsamples.count * 6)
            sampleInfoSizes.append(infoSize)
        }

        let senc = SampleEncryptionBox(entries: entries, useSubsampleEncryption: true)

        // Debug: Verify senc structure for first sample
        if let firstEntry = entries.first, let firstSubsamples = firstEntry.subsamples {
            let expectedSize = 2 + (firstSubsamples.count * 6) // No per-sample IV for CBCS with constant IV
            let actualSencData = senc.serialize()
            print("🔍 [senc] First sample: \(firstSubsamples.count) subsamples, expected saiz=\(expectedSize)")
            print("🔍 [senc] Subsamples: \(firstSubsamples.map { "[\($0.bytesOfClearData)c/\($0.bytesOfProtectedData)p]" }.joined(separator: " "))")
            print("🔍 [senc] Total senc box size: \(actualSencData.count) bytes")
            // Show first 32 bytes of senc for debugging
            let hexBytes = actualSencData.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " ")
            print("🔍 [senc] Header bytes: \(hexBytes)")
        }

        // Check if all samples have uniform auxiliary info size (like Apple FairPlay reference content)
        // Reference uses defaultSampleInfoSize when all samples have the same size
        let uniqueSizes = Set(sampleInfoSizes)
        let saiz: SampleAuxiliaryInfoSizesBox

        if uniqueSizes.count == 1, let uniformSize = sampleInfoSizes.first, uniformSize <= 255 {
            // All samples have the same auxiliary info size - use defaultSampleInfoSize
            // This matches Apple FairPlay reference content structure
            saiz = SampleAuxiliaryInfoSizesBox(
                defaultSampleInfoSize: UInt8(uniformSize),
                sampleCount: UInt32(samples.count)
            )
            print("🔐 FMP4Writer: Using uniform saiz defaultSampleInfoSize=\(uniformSize) for \(samples.count) samples")
        } else {
            // Variable sizes - use per-sample array (with truncation warning)
            let truncatedSizes = sampleInfoSizes.map { size -> UInt8 in
                if size > 255 {
                    print("⚠️ FMP4Writer: Sample auxiliary info size \(size) exceeds 255, truncating")
                }
                return UInt8(min(size, 255))
            }
            saiz = SampleAuxiliaryInfoSizesBox(sampleInfoSizes: truncatedSizes)
            // Debug: Show unique sizes
            let sizeCounts = Dictionary(grouping: sampleInfoSizes) { $0 }.mapValues { $0.count }
            print("🔐 FMP4Writer: Variable saiz sizes for \(samples.count) samples: \(sizeCounts)")
        }

        // saio offset points to the sample auxiliary info data within senc (after senc header + version/flags + sample_count)
        let saio = SampleAuxiliaryInfoOffsetsBox(offsets: [UInt64(sencDataOffset)])

        return (senc, saiz, saio)
    }

    private func generateMdat(samples: [Sample]) -> RawDataBox {
        var mdatPayload = Data()
        for sample in samples {
            mdatPayload.append(sample.data)
        }
        return RawDataBox(type: .mdat, data: mdatPayload)
    }
}

// MARK: - Convenience Extensions

extension FMP4Writer {
    /// Create writer from AVAssetTrack for video
    public static func videoTrackConfig(from track: AVAssetTrack,
                                        formatDescription: CMFormatDescription) -> TrackConfig? {
        guard track.mediaType == .video else { return nil }

        let dimensions = track.naturalSize
        let timescale = UInt32(track.naturalTimeScale)

        // Extract codec data from format description
        guard let extensions = CMFormatDescriptionGetExtensions(formatDescription) as? [String: Any] else {
            return nil
        }

        let atoms = extensions["SampleDescriptionExtensionAtoms"] as? [String: Data]

        if let avcC = atoms?["avcC"] {
            // Parse avcC to extract SPS/PPS
            let (sps, pps) = parseAVCC(avcC)
            return .h264Video(
                width: UInt16(dimensions.width),
                height: UInt16(dimensions.height),
                timescale: timescale,
                sps: sps,
                pps: pps
            )
        } else if let hvcC = atoms?["hvcC"] {
            // Parse hvcC to extract VPS/SPS/PPS
            let (vps, sps, pps) = parseHVCC(hvcC)
            return .hevcVideo(
                width: UInt16(dimensions.width),
                height: UInt16(dimensions.height),
                timescale: timescale,
                vps: vps,
                sps: sps,
                pps: pps
            )
        }

        return nil
    }

    private static func parseAVCC(_ data: Data) -> (sps: [Data], pps: [Data]) {
        guard data.count > 6 else { return ([], []) }

        var sps: [Data] = []
        var pps: [Data] = []
        var offset = 5 // Skip config version, profile, compatibility, level, length size

        // Number of SPS
        let numSPS = Int(data[offset] & 0x1F)
        offset += 1

        for _ in 0..<numSPS {
            guard offset + 2 <= data.count else { break }
            let length = Int(UInt16(bigEndianData: data.subdata(in: offset..<offset+2)))
            offset += 2
            guard offset + length <= data.count else { break }
            sps.append(data.subdata(in: offset..<offset+length))
            offset += length
        }

        // Number of PPS
        guard offset < data.count else { return (sps, pps) }
        let numPPS = Int(data[offset])
        offset += 1

        for _ in 0..<numPPS {
            guard offset + 2 <= data.count else { break }
            let length = Int(UInt16(bigEndianData: data.subdata(in: offset..<offset+2)))
            offset += 2
            guard offset + length <= data.count else { break }
            pps.append(data.subdata(in: offset..<offset+length))
            offset += length
        }

        return (sps, pps)
    }

    private static func parseHVCC(_ data: Data) -> (vps: [Data], sps: [Data], pps: [Data]) {
        // Simplified HEVC config parsing
        guard data.count > 23 else { return ([], [], []) }

        var vps: [Data] = []
        var sps: [Data] = []
        var pps: [Data] = []

        var offset = 22 // Skip to numOfArrays
        let numArrays = Int(data[offset])
        offset += 1

        for _ in 0..<numArrays {
            guard offset + 3 <= data.count else { break }
            let nalUnitType = data[offset] & 0x3F
            offset += 1
            let numNalus = Int(UInt16(bigEndianData: data.subdata(in: offset..<offset+2)))
            offset += 2

            for _ in 0..<numNalus {
                guard offset + 2 <= data.count else { break }
                let length = Int(UInt16(bigEndianData: data.subdata(in: offset..<offset+2)))
                offset += 2
                guard offset + length <= data.count else { break }
                let nalData = data.subdata(in: offset..<offset+length)
                offset += length

                switch nalUnitType {
                case 32: vps.append(nalData)
                case 33: sps.append(nalData)
                case 34: pps.append(nalData)
                default: break
                }
            }
        }

        return (vps, sps, pps)
    }
}
