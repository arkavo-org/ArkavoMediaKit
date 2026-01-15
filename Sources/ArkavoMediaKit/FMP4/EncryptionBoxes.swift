import Foundation

// MARK: - Sample Encryption Info (sinf container)

/// Protection scheme information box - wraps encryption metadata
public struct SampleEncryptionInfo {
    public let originalFormat: FourCC
    public let schemeType: FourCC
    public let schemeVersion: UInt32
    public let keyID: Data // 16 bytes
    public let defaultIsProtected: UInt8
    public let defaultPerSampleIVSize: UInt8
    public let defaultConstantIV: Data? // For CBCS (constant IV)
    public let defaultCryptByteBlock: UInt8 // For pattern encryption
    public let defaultSkipByteBlock: UInt8

    /// Create CBCS encryption info for FairPlay
    public init(keyID: Data,
                constantIV: Data,
                cryptByteBlock: UInt8 = 1,
                skipByteBlock: UInt8 = 9) {
        precondition(keyID.count == 16, "Key ID must be 16 bytes")
        precondition(constantIV.count == 16, "Constant IV must be 16 bytes")

        self.originalFormat = .avc1 // Will be overridden in serialize
        self.schemeType = FourCC("cbcs")
        self.schemeVersion = 0x00010000
        self.keyID = keyID
        self.defaultIsProtected = 1
        self.defaultPerSampleIVSize = 0 // Use constant IV
        self.defaultConstantIV = constantIV
        self.defaultCryptByteBlock = cryptByteBlock
        self.defaultSkipByteBlock = skipByteBlock
    }

    public func serialize(originalFormat: FourCC) -> Data {
        var sinf = ContainerBox(type: .sinf)

        // frma - original format
        sinf.append(OriginalFormatBox(dataFormat: originalFormat))

        // schm - scheme type
        sinf.append(SchemeTypeBox(schemeType: schemeType, schemeVersion: schemeVersion))

        // schi - scheme information container
        var schi = ContainerBox(type: .schi)

        // tenc - track encryption
        schi.append(TrackEncryptionBox(
            defaultIsProtected: defaultIsProtected,
            defaultPerSampleIVSize: defaultPerSampleIVSize,
            defaultKID: keyID,
            defaultConstantIV: defaultConstantIV,
            defaultCryptByteBlock: defaultCryptByteBlock,
            defaultSkipByteBlock: defaultSkipByteBlock
        ))

        sinf.append(schi)

        return sinf.serialize()
    }
}

// MARK: - Original Format Box (frma)

/// Original format box - indicates the original unencrypted format
public struct OriginalFormatBox: ISOBox {
    public let type = FourCC.frma
    public let dataFormat: FourCC

    public init(dataFormat: FourCC) {
        self.dataFormat = dataFormat
    }

    public func serializePayload() -> Data {
        dataFormat.data
    }
}

// MARK: - Scheme Type Box (schm)

/// Scheme type box - identifies the protection scheme
public struct SchemeTypeBox: ISOFullBox {
    public let type = FourCC.schm
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public let schemeType: FourCC
    public let schemeVersion: UInt32

    public init(schemeType: FourCC, schemeVersion: UInt32) {
        self.schemeType = schemeType
        self.schemeVersion = schemeVersion
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(schemeType.data)
        data.append(schemeVersion.bigEndianData)
        return data
    }
}

// MARK: - Track Encryption Box (tenc)

/// Track encryption box - default encryption parameters
public struct TrackEncryptionBox: ISOFullBox {
    public let type = FourCC.tenc
    public let version: UInt8
    public var flags: UInt32 = 0

    public let defaultIsProtected: UInt8
    public let defaultPerSampleIVSize: UInt8
    public let defaultKID: Data
    public let defaultConstantIV: Data?
    public let defaultCryptByteBlock: UInt8
    public let defaultSkipByteBlock: UInt8

    public init(defaultIsProtected: UInt8,
                defaultPerSampleIVSize: UInt8,
                defaultKID: Data,
                defaultConstantIV: Data? = nil,
                defaultCryptByteBlock: UInt8 = 0,
                defaultSkipByteBlock: UInt8 = 0) {
        // Version 1 for CBCS with pattern encryption
        self.version = (defaultCryptByteBlock > 0 || defaultSkipByteBlock > 0) ? 1 : 0
        self.defaultIsProtected = defaultIsProtected
        self.defaultPerSampleIVSize = defaultPerSampleIVSize
        self.defaultKID = defaultKID
        self.defaultConstantIV = defaultConstantIV
        self.defaultCryptByteBlock = defaultCryptByteBlock
        self.defaultSkipByteBlock = defaultSkipByteBlock
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Reserved (1 byte)
        data.append(0x00)

        if version >= 1 {
            // default_crypt_byte_block (4 bits) + default_skip_byte_block (4 bits)
            let patternByte = ((defaultCryptByteBlock & 0x0F) << 4) | (defaultSkipByteBlock & 0x0F)
            data.append(patternByte)
        } else {
            // Reserved
            data.append(0x00)
        }

        // default_isProtected (1 byte)
        data.append(defaultIsProtected)

        // default_Per_Sample_IV_Size (1 byte)
        data.append(defaultPerSampleIVSize)

        // default_KID (16 bytes)
        data.append(defaultKID)

        // default_constant_IV_size and default_constant_IV (if IV size is 0)
        if defaultPerSampleIVSize == 0, let constantIV = defaultConstantIV {
            data.append(UInt8(constantIV.count))
            data.append(constantIV)
        }

        return data
    }
}

// MARK: - Protection System Specific Header Box (pssh)

/// PSSH box - system-specific protection data
public struct ProtectionSystemSpecificHeaderBox: ISOFullBox {
    public let type = FourCC.pssh
    public let version: UInt8
    public var flags: UInt32 = 0

    public let systemID: Data // 16 bytes
    public let keyIDs: [Data] // For version 1
    public let data: Data

    /// FairPlay system ID
    public static let fairPlaySystemID = Data([
        0x94, 0xCE, 0x86, 0xFB, 0x07, 0xFF, 0x4F, 0x43,
        0xAD, 0xB8, 0x93, 0xD2, 0xFA, 0x96, 0x8C, 0xA2
    ])

    /// Common encryption system ID (for testing)
    public static let commonSystemID = Data([
        0x10, 0x77, 0xEF, 0xEC, 0xC0, 0xB2, 0x4D, 0x02,
        0xAC, 0xE3, 0x3C, 0x1E, 0x52, 0xE2, 0xFB, 0x4B
    ])

    public init(systemID: Data, keyIDs: [Data] = [], data: Data = Data()) {
        precondition(systemID.count == 16, "System ID must be 16 bytes")
        self.version = keyIDs.isEmpty ? 0 : 1
        self.systemID = systemID
        self.keyIDs = keyIDs
        self.data = data
    }

    public func serializePayload() -> Data {
        var output = serializeVersionAndFlags()

        // SystemID (16 bytes)
        output.append(systemID)

        // KID_count and KIDs (version 1 only)
        if version >= 1 {
            output.append(UInt32(keyIDs.count).bigEndianData)
            for kid in keyIDs {
                output.append(kid)
            }
        }

        // Data size and data
        output.append(UInt32(data.count).bigEndianData)
        output.append(data)

        return output
    }
}

// MARK: - Sample Encryption Box (senc)

/// Sample encryption box - per-sample encryption metadata
public struct SampleEncryptionBox: ISOFullBox {
    public let type = FourCC.senc
    public let version: UInt8 = 0
    public var flags: UInt32

    public let entries: [SampleEncryptionEntry]

    /// Create senc with subsample encryption (for video NAL units)
    public init(entries: [SampleEncryptionEntry], useSubsampleEncryption: Bool = true) {
        self.entries = entries
        // Flag 0x02 = use subsample encryption
        self.flags = useSubsampleEncryption ? 0x02 : 0x00
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Sample count
        data.append(UInt32(entries.count).bigEndianData)

        // Entries
        let hasSubsamples = (flags & 0x02) != 0
        for entry in entries {
            // Per-sample IV (only if not using constant IV)
            if let iv = entry.iv {
                data.append(iv)
            }

            // Subsample encryption
            if hasSubsamples, let subsamples = entry.subsamples {
                data.append(UInt16(subsamples.count).bigEndianData)
                for subsample in subsamples {
                    data.append(subsample.bytesOfClearData.bigEndianData)
                    data.append(subsample.bytesOfProtectedData.bigEndianData)
                }
            }
        }

        return data
    }
}

/// Single sample encryption entry
public struct SampleEncryptionEntry {
    public let iv: Data? // Per-sample IV (nil if using constant IV)
    public let subsamples: [SubsampleEntry]?

    public init(iv: Data? = nil, subsamples: [SubsampleEntry]? = nil) {
        self.iv = iv
        self.subsamples = subsamples
    }
}

/// Subsample encryption entry (clear + protected regions)
public struct SubsampleEntry {
    public let bytesOfClearData: UInt16
    public let bytesOfProtectedData: UInt32

    public init(bytesOfClearData: UInt16, bytesOfProtectedData: UInt32) {
        self.bytesOfClearData = bytesOfClearData
        self.bytesOfProtectedData = bytesOfProtectedData
    }
}

// MARK: - Sample Auxiliary Information Sizes Box (saiz)

/// Sample auxiliary information sizes for encryption
public struct SampleAuxiliaryInfoSizesBox: ISOFullBox {
    public let type = FourCC.saiz
    public let version: UInt8 = 0
    public var flags: UInt32

    public let auxInfoType: FourCC?
    public let auxInfoTypeParameter: UInt32?
    public let defaultSampleInfoSize: UInt8
    public let sampleInfoSizes: [UInt8]
    public let sampleCount: UInt32

    /// Initialize with per-sample sizes (defaultSampleInfoSize = 0)
    public init(sampleInfoSizes: [UInt8],
                auxInfoType: FourCC? = nil,
                auxInfoTypeParameter: UInt32? = nil) {
        self.defaultSampleInfoSize = 0
        self.sampleInfoSizes = sampleInfoSizes
        self.sampleCount = UInt32(sampleInfoSizes.count)
        self.auxInfoType = auxInfoType
        self.auxInfoTypeParameter = auxInfoTypeParameter
        self.flags = (auxInfoType != nil) ? 0x01 : 0x00
    }

    /// Initialize with uniform default size (matches Apple FairPlay reference content)
    public init(defaultSampleInfoSize: UInt8,
                sampleCount: UInt32,
                auxInfoType: FourCC? = nil,
                auxInfoTypeParameter: UInt32? = nil) {
        self.defaultSampleInfoSize = defaultSampleInfoSize
        self.sampleInfoSizes = []
        self.sampleCount = sampleCount
        self.auxInfoType = auxInfoType
        self.auxInfoTypeParameter = auxInfoTypeParameter
        self.flags = (auxInfoType != nil) ? 0x01 : 0x00
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // aux_info_type and aux_info_type_parameter (if flags & 0x01)
        if flags & 0x01 != 0 {
            data.append(auxInfoType?.data ?? Data(count: 4))
            data.append((auxInfoTypeParameter ?? 0).bigEndianData)
        }

        // default_sample_info_size
        data.append(defaultSampleInfoSize)

        // sample_count
        data.append(sampleCount.bigEndianData)

        // sample_info_size array (only if default is 0)
        if defaultSampleInfoSize == 0 {
            for size in sampleInfoSizes {
                data.append(size)
            }
        }

        return data
    }
}

// MARK: - Sample Auxiliary Information Offsets Box (saio)

/// Sample auxiliary information offsets for encryption
public struct SampleAuxiliaryInfoOffsetsBox: ISOFullBox {
    public let type = FourCC.saio
    public let version: UInt8
    public var flags: UInt32

    public let auxInfoType: FourCC?
    public let auxInfoTypeParameter: UInt32?
    public let offsets: [UInt64]

    public init(offsets: [UInt64],
                use64BitOffsets: Bool = false,
                auxInfoType: FourCC? = nil,
                auxInfoTypeParameter: UInt32? = nil) {
        self.version = use64BitOffsets ? 1 : 0
        self.offsets = offsets
        self.auxInfoType = auxInfoType
        self.auxInfoTypeParameter = auxInfoTypeParameter
        self.flags = (auxInfoType != nil) ? 0x01 : 0x00
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // aux_info_type and aux_info_type_parameter (if flags & 0x01)
        if flags & 0x01 != 0 {
            data.append(auxInfoType?.data ?? Data(count: 4))
            data.append((auxInfoTypeParameter ?? 0).bigEndianData)
        }

        // entry_count
        data.append(UInt32(offsets.count).bigEndianData)

        // offsets
        for offset in offsets {
            if version == 0 {
                data.append(UInt32(offset).bigEndianData)
            } else {
                data.append(offset.bigEndianData)
            }
        }

        return data
    }
}
