import Foundation

// MARK: - AVC Sample Entry (avc1)

/// AVC/H.264 sample entry
public struct AVCSampleEntry: ISOBox {
    public var type: FourCC {
        // Use 'encv' for encrypted video, 'avc1' for clear
        encryptionInfo != nil ? FourCC.encv : FourCC.avc1
    }

    public let dataReferenceIndex: UInt16
    public let width: UInt16
    public let height: UInt16
    public let avcC: AVCDecoderConfigurationRecord
    public let encryptionInfo: SampleEncryptionInfo?

    public init(width: UInt16, height: UInt16, avcC: AVCDecoderConfigurationRecord, encrypted: SampleEncryptionInfo? = nil) {
        self.dataReferenceIndex = 1
        self.width = width
        self.height = height
        self.avcC = avcC
        self.encryptionInfo = encrypted
    }

    public func serializePayload() -> Data {
        var data = Data()

        // Reserved (6 bytes)
        data.append(Data(count: 6))

        // Data reference index
        data.append(dataReferenceIndex.bigEndianData)

        // Pre-defined + reserved (16 bytes)
        data.append(Data(count: 16))

        // Width and height
        data.append(width.bigEndianData)
        data.append(height.bigEndianData)

        // Horizontal resolution (72 dpi = 0x00480000)
        data.append(UInt32(0x00480000).bigEndianData)

        // Vertical resolution (72 dpi = 0x00480000)
        data.append(UInt32(0x00480000).bigEndianData)

        // Reserved
        data.append(UInt32(0).bigEndianData)

        // Frame count (1)
        data.append(UInt16(1).bigEndianData)

        // Compressor name (32 bytes, padded)
        var compressorName = Data(count: 32)
        let name = "AVC Coding".data(using: .utf8) ?? Data()
        compressorName[0] = UInt8(min(name.count, 31))
        compressorName.replaceSubrange(1..<min(name.count + 1, 32), with: name)
        data.append(compressorName)

        // Depth (24 = 0x0018)
        data.append(UInt16(0x0018).bigEndianData)

        // Pre-defined (-1)
        data.append(Int16(-1).bigEndianData)

        // avcC box
        data.append(avcC.serialize())

        // Encryption info (sinf box) if encrypted
        if let encInfo = encryptionInfo {
            data.append(encInfo.serialize(originalFormat: .avc1))
        }

        return data
    }
}

// MARK: - AVC Decoder Configuration Record (avcC)

/// AVC decoder configuration record containing SPS/PPS
public struct AVCDecoderConfigurationRecord: ISOBox {
    public let type = FourCC.avcC

    public let configurationVersion: UInt8 = 1
    public let profileIndication: UInt8
    public let profileCompatibility: UInt8
    public let levelIndication: UInt8
    public let lengthSizeMinusOne: UInt8 = 3 // 4-byte NAL unit length
    public let sequenceParameterSets: [Data]
    public let pictureParameterSets: [Data]

    public init(sps: [Data], pps: [Data]) {
        self.sequenceParameterSets = sps
        self.pictureParameterSets = pps

        // Extract profile/level from first SPS
        if let firstSPS = sps.first, firstSPS.count >= 4 {
            self.profileIndication = firstSPS[1]
            self.profileCompatibility = firstSPS[2]
            self.levelIndication = firstSPS[3]
        } else {
            self.profileIndication = 100 // High profile
            self.profileCompatibility = 0
            self.levelIndication = 40   // Level 4.0
        }
    }

    public func serializePayload() -> Data {
        var data = Data()

        data.append(configurationVersion)
        data.append(profileIndication)
        data.append(profileCompatibility)
        data.append(levelIndication)

        // Reserved (6 bits = 111111) + lengthSizeMinusOne (2 bits)
        data.append(0xFC | (lengthSizeMinusOne & 0x03))

        // Reserved (3 bits = 111) + numSPS (5 bits)
        data.append(0xE0 | UInt8(sequenceParameterSets.count & 0x1F))

        // SPS entries
        for sps in sequenceParameterSets {
            data.append(UInt16(sps.count).bigEndianData)
            data.append(sps)
        }

        // Number of PPS
        data.append(UInt8(pictureParameterSets.count))

        // PPS entries
        for pps in pictureParameterSets {
            data.append(UInt16(pps.count).bigEndianData)
            data.append(pps)
        }

        return data
    }
}

// MARK: - HEVC Sample Entry (hvc1)

/// HEVC/H.265 sample entry
public struct HEVCSampleEntry: ISOBox {
    public var type: FourCC {
        // Use 'encv' for encrypted video, 'hvc1' for clear
        encryptionInfo != nil ? FourCC.encv : FourCC.hvc1
    }

    public let dataReferenceIndex: UInt16
    public let width: UInt16
    public let height: UInt16
    public let hvcC: HEVCDecoderConfigurationRecord
    public let encryptionInfo: SampleEncryptionInfo?

    public init(width: UInt16, height: UInt16, hvcC: HEVCDecoderConfigurationRecord, encrypted: SampleEncryptionInfo? = nil) {
        self.dataReferenceIndex = 1
        self.width = width
        self.height = height
        self.hvcC = hvcC
        self.encryptionInfo = encrypted
    }

    public func serializePayload() -> Data {
        var data = Data()

        // Reserved (6 bytes)
        data.append(Data(count: 6))

        // Data reference index
        data.append(dataReferenceIndex.bigEndianData)

        // Pre-defined + reserved (16 bytes)
        data.append(Data(count: 16))

        // Width and height
        data.append(width.bigEndianData)
        data.append(height.bigEndianData)

        // Horizontal resolution (72 dpi)
        data.append(UInt32(0x00480000).bigEndianData)

        // Vertical resolution (72 dpi)
        data.append(UInt32(0x00480000).bigEndianData)

        // Reserved
        data.append(UInt32(0).bigEndianData)

        // Frame count (1)
        data.append(UInt16(1).bigEndianData)

        // Compressor name (32 bytes)
        var compressorName = Data(count: 32)
        let name = "HEVC Coding".data(using: .utf8) ?? Data()
        compressorName[0] = UInt8(min(name.count, 31))
        compressorName.replaceSubrange(1..<min(name.count + 1, 32), with: name)
        data.append(compressorName)

        // Depth (24)
        data.append(UInt16(0x0018).bigEndianData)

        // Pre-defined (-1)
        data.append(Int16(-1).bigEndianData)

        // hvcC box
        data.append(hvcC.serialize())

        // Encryption info if encrypted
        if let encInfo = encryptionInfo {
            data.append(encInfo.serialize(originalFormat: .hvc1))
        }

        return data
    }
}

// MARK: - HEVC Decoder Configuration Record (hvcC)

/// HEVC decoder configuration record containing VPS/SPS/PPS
public struct HEVCDecoderConfigurationRecord: ISOBox {
    public let type = FourCC.hvcC

    public let generalProfileSpace: UInt8
    public let generalTierFlag: Bool
    public let generalProfileIDC: UInt8
    public let generalProfileCompatibilityFlags: UInt32
    public let generalConstraintIndicatorFlags: UInt64 // 48 bits
    public let generalLevelIDC: UInt8
    public let chromaFormatIDC: UInt8
    public let bitDepthLumaMinus8: UInt8
    public let bitDepthChromaMinus8: UInt8
    public let avgFrameRate: UInt16
    public let constantFrameRate: UInt8
    public let numTemporalLayers: UInt8
    public let temporalIdNested: Bool
    public let lengthSizeMinusOne: UInt8 = 3

    public let nalArrays: [HEVCNALArray]

    public init(vps: [Data], sps: [Data], pps: [Data]) {
        // Default HEVC profile/level configuration
        // TODO: Parse actual values from SPS NAL unit if needed
        self.generalProfileSpace = 0
        self.generalTierFlag = false
        self.generalProfileIDC = 1 // Main profile
        self.generalProfileCompatibilityFlags = 0x60000000
        self.generalConstraintIndicatorFlags = 0
        self.generalLevelIDC = 120 // Level 4.0

        self.chromaFormatIDC = 1 // 4:2:0
        self.bitDepthLumaMinus8 = 0
        self.bitDepthChromaMinus8 = 0
        self.avgFrameRate = 0
        self.constantFrameRate = 0
        self.numTemporalLayers = 1
        self.temporalIdNested = true

        var arrays: [HEVCNALArray] = []
        if !vps.isEmpty {
            arrays.append(HEVCNALArray(nalUnitType: 32, nalUnits: vps)) // VPS
        }
        if !sps.isEmpty {
            arrays.append(HEVCNALArray(nalUnitType: 33, nalUnits: sps)) // SPS
        }
        if !pps.isEmpty {
            arrays.append(HEVCNALArray(nalUnitType: 34, nalUnits: pps)) // PPS
        }
        self.nalArrays = arrays
    }

    public func serializePayload() -> Data {
        var data = Data()

        // Configuration version
        data.append(1)

        // general_profile_space (2) + general_tier_flag (1) + general_profile_idc (5)
        var byte = (generalProfileSpace & 0x03) << 6
        if generalTierFlag { byte |= 0x20 }
        byte |= (generalProfileIDC & 0x1F)
        data.append(byte)

        // general_profile_compatibility_flags
        data.append(generalProfileCompatibilityFlags.bigEndianData)

        // general_constraint_indicator_flags (48 bits = 6 bytes)
        for i in (0..<6).reversed() {
            data.append(UInt8((generalConstraintIndicatorFlags >> (i * 8)) & 0xFF))
        }

        // general_level_idc
        data.append(generalLevelIDC)

        // Reserved (4 bits = 1111) + min_spatial_segmentation_idc (12 bits)
        data.append(0xF0)
        data.append(0x00)

        // Reserved (6 bits = 111111) + parallelismType (2 bits)
        data.append(0xFC)

        // Reserved (6 bits) + chromaFormatIDC (2 bits)
        data.append(0xFC | (chromaFormatIDC & 0x03))

        // Reserved (5 bits) + bitDepthLumaMinus8 (3 bits)
        data.append(0xF8 | (bitDepthLumaMinus8 & 0x07))

        // Reserved (5 bits) + bitDepthChromaMinus8 (3 bits)
        data.append(0xF8 | (bitDepthChromaMinus8 & 0x07))

        // avgFrameRate
        data.append(avgFrameRate.bigEndianData)

        // constantFrameRate (2) + numTemporalLayers (3) + temporalIdNested (1) + lengthSizeMinusOne (2)
        var flags: UInt8 = (constantFrameRate & 0x03) << 6
        flags |= (numTemporalLayers & 0x07) << 3
        flags |= (temporalIdNested ? 0x04 : 0)
        flags |= (lengthSizeMinusOne & 0x03)
        data.append(flags)

        // Number of arrays
        data.append(UInt8(nalArrays.count))

        // NAL arrays
        for array in nalArrays {
            data.append(array.serialize())
        }

        return data
    }
}

/// HEVC NAL unit array for configuration
public struct HEVCNALArray {
    public let arrayCompleteness: Bool = true
    public let nalUnitType: UInt8
    public let nalUnits: [Data]

    public init(nalUnitType: UInt8, nalUnits: [Data]) {
        self.nalUnitType = nalUnitType
        self.nalUnits = nalUnits
    }

    public func serialize() -> Data {
        var data = Data()

        // array_completeness (1) + reserved (1) + NAL_unit_type (6)
        var byte: UInt8 = arrayCompleteness ? 0x80 : 0
        byte |= (nalUnitType & 0x3F)
        data.append(byte)

        // numNalus
        data.append(UInt16(nalUnits.count).bigEndianData)

        // NAL units
        for nal in nalUnits {
            data.append(UInt16(nal.count).bigEndianData)
            data.append(nal)
        }

        return data
    }
}

// MARK: - AAC Sample Entry (mp4a)

/// AAC audio sample entry
public struct AACSampleEntry: ISOBox {
    public var type: FourCC {
        // Use 'enca' for encrypted audio, 'mp4a' for clear
        encryptionInfo != nil ? FourCC.enca : FourCC.mp4a
    }

    public let dataReferenceIndex: UInt16 = 1
    public let channelCount: UInt16
    public let sampleSize: UInt16 = 16
    public let sampleRate: UInt32
    public let esds: ElementaryStreamDescriptor
    public let encryptionInfo: SampleEncryptionInfo?

    public init(channelCount: UInt16, sampleRate: UInt32, esds: ElementaryStreamDescriptor, encrypted: SampleEncryptionInfo? = nil) {
        self.channelCount = channelCount
        self.sampleRate = sampleRate
        self.esds = esds
        self.encryptionInfo = encrypted
    }

    public func serializePayload() -> Data {
        var data = Data()

        // Reserved (6 bytes)
        data.append(Data(count: 6))

        // Data reference index
        data.append(dataReferenceIndex.bigEndianData)

        // Reserved (8 bytes - version, revision level, vendor)
        data.append(Data(count: 8))

        // Channel count
        data.append(channelCount.bigEndianData)

        // Sample size
        data.append(sampleSize.bigEndianData)

        // Pre-defined + reserved
        data.append(Data(count: 4))

        // Sample rate (16.16 fixed point)
        data.append((sampleRate << 16).bigEndianData)

        // esds box
        data.append(esds.serialize())

        // Encryption info if encrypted
        if let encInfo = encryptionInfo {
            data.append(encInfo.serialize(originalFormat: .mp4a))
        }

        return data
    }
}

// MARK: - Elementary Stream Descriptor (esds)

/// Elementary stream descriptor for AAC configuration
public struct ElementaryStreamDescriptor: ISOFullBox {
    public let type = FourCC.esds
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public let audioSpecificConfig: Data

    public init(audioSpecificConfig: Data) {
        self.audioSpecificConfig = audioSpecificConfig
    }

    /// Create esds from AAC parameters
    public init(objectType: UInt8 = 2, sampleRateIndex: UInt8, channelConfig: UInt8) {
        // Build AudioSpecificConfig
        // objectType (5 bits) + samplingFrequencyIndex (4 bits) + channelConfiguration (4 bits) + ...
        var config = Data()
        let byte1 = (objectType << 3) | ((sampleRateIndex >> 1) & 0x07)
        let byte2 = ((sampleRateIndex & 0x01) << 7) | ((channelConfig & 0x0F) << 3)
        config.append(byte1)
        config.append(byte2)
        self.audioSpecificConfig = config
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // ES_Descriptor
        data.append(0x03) // ES_DescrTag
        let esDescContent = buildESDescriptorContent()
        data.append(contentsOf: encodeSize(esDescContent.count))
        data.append(esDescContent)

        return data
    }

    private func buildESDescriptorContent() -> Data {
        var data = Data()

        // ES_ID
        data.append(UInt16(1).bigEndianData)

        // Flags (streamDependenceFlag, URL_Flag, OCRstreamFlag, streamPriority)
        data.append(0x00)

        // DecoderConfigDescriptor
        data.append(0x04) // DecoderConfigDescrTag
        let decoderConfigContent = buildDecoderConfigContent()
        data.append(contentsOf: encodeSize(decoderConfigContent.count))
        data.append(decoderConfigContent)

        // SLConfigDescriptor
        data.append(0x06) // SLConfigDescrTag
        data.append(0x01) // Size = 1
        data.append(0x02) // Predefined = 2

        return data
    }

    private func buildDecoderConfigContent() -> Data {
        var data = Data()

        // objectTypeIndication (0x40 = Audio ISO/IEC 14496-3)
        data.append(0x40)

        // streamType (5 = audio) << 2 | upStream (0) << 1 | reserved (1)
        data.append(0x15)

        // bufferSizeDB (3 bytes)
        data.append(Data(count: 3))

        // maxBitrate
        data.append(UInt32(128000).bigEndianData)

        // avgBitrate
        data.append(UInt32(128000).bigEndianData)

        // DecoderSpecificInfo
        data.append(0x05) // DecSpecificInfoTag
        data.append(contentsOf: encodeSize(audioSpecificConfig.count))
        data.append(audioSpecificConfig)

        return data
    }

    private func encodeSize(_ size: Int) -> [UInt8] {
        if size < 128 {
            return [UInt8(size)]
        }
        var bytes: [UInt8] = []
        var remaining = size
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0x7F), at: 0)
            remaining >>= 7
        }
        for i in 0..<(bytes.count - 1) {
            bytes[i] |= 0x80
        }
        return bytes
    }
}
