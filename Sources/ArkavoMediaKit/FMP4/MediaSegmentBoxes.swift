import Foundation

// MARK: - Movie Fragment Header Box (mfhd)

/// Movie fragment header - identifies fragment sequence
public struct MovieFragmentHeaderBox: ISOFullBox {
    public let type = FourCC.mfhd
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public let sequenceNumber: UInt32

    public init(sequenceNumber: UInt32) {
        self.sequenceNumber = sequenceNumber
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(sequenceNumber.bigEndianData)
        return data
    }
}

// MARK: - Track Fragment Header Box (tfhd)

/// Track fragment header - default values for samples in fragment
public struct TrackFragmentHeaderBox: ISOFullBox {
    public let type = FourCC.tfhd
    public let version: UInt8 = 0
    public var flags: UInt32

    public let trackID: UInt32
    public let baseDataOffset: UInt64?
    public let sampleDescriptionIndex: UInt32?
    public let defaultSampleDuration: UInt32?
    public let defaultSampleSize: UInt32?
    public let defaultSampleFlags: UInt32?

    // Flags
    public static let baseDataOffsetPresent: UInt32 = 0x000001
    public static let sampleDescriptionIndexPresent: UInt32 = 0x000002
    public static let defaultSampleDurationPresent: UInt32 = 0x000008
    public static let defaultSampleSizePresent: UInt32 = 0x000010
    public static let defaultSampleFlagsPresent: UInt32 = 0x000020
    public static let durationIsEmpty: UInt32 = 0x010000
    public static let defaultBaseIsMoof: UInt32 = 0x020000

    public init(trackID: UInt32,
                baseDataOffset: UInt64? = nil,
                sampleDescriptionIndex: UInt32? = nil,
                defaultSampleDuration: UInt32? = nil,
                defaultSampleSize: UInt32? = nil,
                defaultSampleFlags: UInt32? = nil,
                defaultBaseIsMoof: Bool = true) {
        self.trackID = trackID
        self.baseDataOffset = baseDataOffset
        self.sampleDescriptionIndex = sampleDescriptionIndex
        self.defaultSampleDuration = defaultSampleDuration
        self.defaultSampleSize = defaultSampleSize
        self.defaultSampleFlags = defaultSampleFlags

        var f: UInt32 = 0
        if baseDataOffset != nil { f |= Self.baseDataOffsetPresent }
        if sampleDescriptionIndex != nil { f |= Self.sampleDescriptionIndexPresent }
        if defaultSampleDuration != nil { f |= Self.defaultSampleDurationPresent }
        if defaultSampleSize != nil { f |= Self.defaultSampleSizePresent }
        if defaultSampleFlags != nil { f |= Self.defaultSampleFlagsPresent }
        if defaultBaseIsMoof { f |= Self.defaultBaseIsMoof }
        self.flags = f
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        data.append(trackID.bigEndianData)

        if let offset = baseDataOffset {
            data.append(offset.bigEndianData)
        }
        if let index = sampleDescriptionIndex {
            data.append(index.bigEndianData)
        }
        if let duration = defaultSampleDuration {
            data.append(duration.bigEndianData)
        }
        if let size = defaultSampleSize {
            data.append(size.bigEndianData)
        }
        if let sampleFlags = defaultSampleFlags {
            data.append(sampleFlags.bigEndianData)
        }

        return data
    }
}

// MARK: - Track Fragment Decode Time Box (tfdt)

/// Track fragment decode time - absolute decode time of first sample
public struct TrackFragmentDecodeTimeBox: ISOFullBox {
    public let type = FourCC.tfdt
    public let version: UInt8
    public var flags: UInt32 = 0

    public let baseMediaDecodeTime: UInt64

    public init(baseMediaDecodeTime: UInt64) {
        self.baseMediaDecodeTime = baseMediaDecodeTime
        // Use version 1 for 64-bit times
        self.version = baseMediaDecodeTime > UInt32.max ? 1 : 0
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        if version == 1 {
            data.append(baseMediaDecodeTime.bigEndianData)
        } else {
            data.append(UInt32(baseMediaDecodeTime).bigEndianData)
        }

        return data
    }
}

// MARK: - Track Run Box (trun)

/// Track run box - sample-specific data for fragment
public struct TrackRunBox: ISOFullBox {
    public let type = FourCC.trun
    public let version: UInt8 = 0
    public var flags: UInt32

    public let dataOffset: Int32?
    public let firstSampleFlags: UInt32?
    public let samples: [TrackRunSample]

    // Flags
    public static let dataOffsetPresent: UInt32 = 0x000001
    public static let firstSampleFlagsPresent: UInt32 = 0x000004
    public static let sampleDurationPresent: UInt32 = 0x000100
    public static let sampleSizePresent: UInt32 = 0x000200
    public static let sampleFlagsPresent: UInt32 = 0x000400
    public static let sampleCompositionTimeOffsetsPresent: UInt32 = 0x000800

    public init(samples: [TrackRunSample],
                dataOffset: Int32? = nil,
                firstSampleFlags: UInt32? = nil) {
        self.samples = samples
        self.dataOffset = dataOffset
        self.firstSampleFlags = firstSampleFlags

        var f: UInt32 = 0
        if dataOffset != nil { f |= Self.dataOffsetPresent }
        if firstSampleFlags != nil { f |= Self.firstSampleFlagsPresent }

        // Check first sample for optional fields
        if let first = samples.first {
            if first.duration != nil { f |= Self.sampleDurationPresent }
            if first.size != nil { f |= Self.sampleSizePresent }
            if first.flags != nil { f |= Self.sampleFlagsPresent }
            if first.compositionTimeOffset != nil { f |= Self.sampleCompositionTimeOffsetsPresent }
        }

        self.flags = f
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Sample count
        data.append(UInt32(samples.count).bigEndianData)

        // Data offset
        if let offset = dataOffset {
            data.append(offset.bigEndianData)
        }

        // First sample flags
        if let fsf = firstSampleFlags {
            data.append(fsf.bigEndianData)
        }

        // Per-sample data
        let hasDuration = (flags & Self.sampleDurationPresent) != 0
        let hasSize = (flags & Self.sampleSizePresent) != 0
        let hasFlags = (flags & Self.sampleFlagsPresent) != 0
        let hasCTO = (flags & Self.sampleCompositionTimeOffsetsPresent) != 0

        for sample in samples {
            if hasDuration {
                data.append((sample.duration ?? 0).bigEndianData)
            }
            if hasSize {
                data.append((sample.size ?? 0).bigEndianData)
            }
            if hasFlags {
                data.append((sample.flags ?? 0).bigEndianData)
            }
            if hasCTO {
                data.append((sample.compositionTimeOffset ?? 0).bigEndianData)
            }
        }

        return data
    }
}

/// Sample entry for track run box
public struct TrackRunSample {
    public let duration: UInt32?
    public let size: UInt32?
    public let flags: UInt32?
    public let compositionTimeOffset: Int32?

    public init(duration: UInt32? = nil,
                size: UInt32? = nil,
                flags: UInt32? = nil,
                compositionTimeOffset: Int32? = nil) {
        self.duration = duration
        self.size = size
        self.flags = flags
        self.compositionTimeOffset = compositionTimeOffset
    }

    // Sample flags helpers
    public static let syncSample: UInt32 = 0x02000000
    public static let nonSyncSample: UInt32 = 0x01010000

    /// Create sample flags for sync (IDR) frame
    public static func syncFlags() -> UInt32 {
        syncSample
    }

    /// Create sample flags for non-sync (P/B) frame
    public static func nonSyncFlags() -> UInt32 {
        nonSyncSample
    }
}

// MARK: - Segment Index Box (sidx)

/// Segment index for seeking
public struct SegmentIndexBox: ISOFullBox {
    public let type = FourCC.sidx
    public let version: UInt8
    public var flags: UInt32 = 0

    public let referenceID: UInt32
    public let timescale: UInt32
    public let earliestPresentationTime: UInt64
    public let firstOffset: UInt64
    public let references: [SegmentReference]

    public init(referenceID: UInt32,
                timescale: UInt32,
                earliestPresentationTime: UInt64,
                firstOffset: UInt64,
                references: [SegmentReference]) {
        self.referenceID = referenceID
        self.timescale = timescale
        self.earliestPresentationTime = earliestPresentationTime
        self.firstOffset = firstOffset
        self.references = references
        // Use version 1 for 64-bit times
        self.version = (earliestPresentationTime > UInt32.max || firstOffset > UInt32.max) ? 1 : 0
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        data.append(referenceID.bigEndianData)
        data.append(timescale.bigEndianData)

        if version == 0 {
            data.append(UInt32(earliestPresentationTime).bigEndianData)
            data.append(UInt32(firstOffset).bigEndianData)
        } else {
            data.append(earliestPresentationTime.bigEndianData)
            data.append(firstOffset.bigEndianData)
        }

        // Reserved
        data.append(UInt16(0).bigEndianData)

        // Reference count
        data.append(UInt16(references.count).bigEndianData)

        // References
        for ref in references {
            // reference_type (1 bit) + referenced_size (31 bits)
            var refTypeAndSize = ref.referencedSize & 0x7FFFFFFF
            if ref.referenceType { refTypeAndSize |= 0x80000000 }
            data.append(refTypeAndSize.bigEndianData)

            data.append(ref.subsegmentDuration.bigEndianData)

            // starts_with_SAP (1) + SAP_type (3) + SAP_delta_time (28)
            var sapInfo: UInt32 = 0
            if ref.startsWithSAP { sapInfo |= 0x80000000 }
            sapInfo |= UInt32(ref.sapType & 0x07) << 28
            sapInfo |= ref.sapDeltaTime & 0x0FFFFFFF
            data.append(sapInfo.bigEndianData)
        }

        return data
    }
}

/// Segment reference for sidx
public struct SegmentReference {
    public let referenceType: Bool // 0 = media, 1 = index
    public let referencedSize: UInt32
    public let subsegmentDuration: UInt32
    public let startsWithSAP: Bool
    public let sapType: UInt8
    public let sapDeltaTime: UInt32

    public init(referencedSize: UInt32,
                subsegmentDuration: UInt32,
                startsWithSAP: Bool = true,
                sapType: UInt8 = 1, // Type 1 = closed GOP
                sapDeltaTime: UInt32 = 0) {
        self.referenceType = false // Media reference
        self.referencedSize = referencedSize
        self.subsegmentDuration = subsegmentDuration
        self.startsWithSAP = startsWithSAP
        self.sapType = sapType
        self.sapDeltaTime = sapDeltaTime
    }
}
