import Foundation

// MARK: - File Type Box (ftyp)

/// File type and compatibility box - must be first box in file
public struct FileTypeBox: ISOBox {
    public let type = FourCC.ftyp
    public let majorBrand: FourCC
    public let minorVersion: UInt32
    public let compatibleBrands: [FourCC]

    public init(majorBrand: FourCC = FourCC("isom"),
                minorVersion: UInt32 = 0x200,
                compatibleBrands: [FourCC] = [FourCC("isom"), FourCC("iso6"), FourCC("mp41")]) {
        self.majorBrand = majorBrand
        self.minorVersion = minorVersion
        self.compatibleBrands = compatibleBrands
    }

    /// Create ftyp for FairPlay HLS (fMP4)
    public static var fairPlayHLS: FileTypeBox {
        FileTypeBox(
            majorBrand: FourCC("isom"),
            minorVersion: 0x200,
            compatibleBrands: [FourCC("isom"), FourCC("iso6"), FourCC("mp41"), FourCC("dash")]
        )
    }

    public func serializePayload() -> Data {
        var data = Data()
        data.append(majorBrand.data)
        data.append(minorVersion.bigEndianData)
        for brand in compatibleBrands {
            data.append(brand.data)
        }
        return data
    }
}

// MARK: - Segment Type Box (styp)

/// Segment type box - identifies media segment type (CMAF/HLS compliance)
public struct SegmentTypeBox: ISOBox {
    public let type = FourCC.styp
    public let majorBrand: FourCC
    public let minorVersion: UInt32
    public let compatibleBrands: [FourCC]

    public init(majorBrand: FourCC = FourCC("msdh"),
                minorVersion: UInt32 = 0,
                compatibleBrands: [FourCC] = [FourCC("msdh"), FourCC("msix")]) {
        self.majorBrand = majorBrand
        self.minorVersion = minorVersion
        self.compatibleBrands = compatibleBrands
    }

    /// Create styp for CMAF/HLS media segments
    public static var cmafSegment: SegmentTypeBox {
        SegmentTypeBox(
            majorBrand: FourCC("msdh"),
            minorVersion: 0,
            compatibleBrands: [FourCC("msdh"), FourCC("msix")]
        )
    }

    /// Create styp for encrypted CMAF media segments (CBCS/FairPlay)
    /// Includes iso6 brand for common encryption support
    public static var cmafEncryptedSegment: SegmentTypeBox {
        SegmentTypeBox(
            majorBrand: FourCC("msdh"),
            minorVersion: 0,
            compatibleBrands: [
                FourCC("msdh"),  // Media Segment Data handler
                FourCC("msix"),  // Segment Index
                FourCC("cmfc"),  // CMAF (Common Media Application Format)
                FourCC("iso6")   // ISO Base Media File Format v6 (encryption)
            ]
        )
    }

    public func serializePayload() -> Data {
        var data = Data()
        data.append(majorBrand.data)
        data.append(minorVersion.bigEndianData)
        for brand in compatibleBrands {
            data.append(brand.data)
        }
        return data
    }
}

// MARK: - Movie Header Box (mvhd)

/// Movie header with overall information about the movie
public struct MovieHeaderBox: ISOFullBox {
    public let type = FourCC.mvhd
    public let version: UInt8
    public var flags: UInt32 = 0

    public let creationTime: UInt64
    public let modificationTime: UInt64
    public let timescale: UInt32
    public let duration: UInt64
    public let nextTrackID: UInt32

    public init(timescale: UInt32, duration: UInt64 = 0, nextTrackID: UInt32 = 2) {
        // Use version 1 for 64-bit times
        self.version = 1
        let now = UInt64(Date().timeIntervalSince1970) + 2082844800 // Convert to 1904 epoch
        self.creationTime = now
        self.modificationTime = now
        self.timescale = timescale
        self.duration = duration
        self.nextTrackID = nextTrackID
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        if version == 1 {
            data.append(creationTime.bigEndianData)
            data.append(modificationTime.bigEndianData)
            data.append(timescale.bigEndianData)
            data.append(duration.bigEndianData)
        } else {
            data.append(UInt32(creationTime).bigEndianData)
            data.append(UInt32(modificationTime).bigEndianData)
            data.append(timescale.bigEndianData)
            data.append(UInt32(duration).bigEndianData)
        }

        // Rate (1.0 = 0x00010000)
        data.append(Int32(0x00010000).bigEndianData)

        // Volume (1.0 = 0x0100)
        data.append(Int16(0x0100).bigEndianData)

        // Reserved (2 + 8 bytes)
        data.append(Data(count: 10))

        // Matrix (identity matrix, 36 bytes)
        let matrix: [Int32] = [
            0x00010000, 0, 0,
            0, 0x00010000, 0,
            0, 0, 0x40000000
        ]
        for value in matrix {
            data.append(value.bigEndianData)
        }

        // Pre-defined (24 bytes)
        data.append(Data(count: 24))

        // Next track ID
        data.append(nextTrackID.bigEndianData)

        return data
    }
}

// MARK: - Track Header Box (tkhd)

/// Track header with characteristics of a single track
public struct TrackHeaderBox: ISOFullBox {
    public let type = FourCC.tkhd
    public let version: UInt8
    public var flags: UInt32

    public let creationTime: UInt64
    public let modificationTime: UInt64
    public let trackID: UInt32
    public let duration: UInt64
    public let width: UInt32  // 16.16 fixed point
    public let height: UInt32 // 16.16 fixed point
    public let volume: Int16  // 8.8 fixed point

    public init(trackID: UInt32, duration: UInt64 = 0, width: UInt32 = 0, height: UInt32 = 0, isAudio: Bool = false) {
        self.version = 1
        // Flags: track_enabled (0x1) | track_in_movie (0x2) | track_in_preview (0x4)
        self.flags = 0x000007
        let now = UInt64(Date().timeIntervalSince1970) + 2082844800
        self.creationTime = now
        self.modificationTime = now
        self.trackID = trackID
        self.duration = duration
        // Width/height in 16.16 fixed point
        self.width = width << 16
        self.height = height << 16
        self.volume = isAudio ? 0x0100 : 0
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        if version == 1 {
            data.append(creationTime.bigEndianData)
            data.append(modificationTime.bigEndianData)
            data.append(trackID.bigEndianData)
            data.append(UInt32(0).bigEndianData) // Reserved
            data.append(duration.bigEndianData)
        } else {
            data.append(UInt32(creationTime).bigEndianData)
            data.append(UInt32(modificationTime).bigEndianData)
            data.append(trackID.bigEndianData)
            data.append(UInt32(0).bigEndianData) // Reserved
            data.append(UInt32(duration).bigEndianData)
        }

        // Reserved (8 bytes)
        data.append(Data(count: 8))

        // Layer
        data.append(Int16(0).bigEndianData)

        // Alternate group
        data.append(Int16(0).bigEndianData)

        // Volume (8.8 fixed point)
        data.append(volume.bigEndianData)

        // Reserved
        data.append(UInt16(0).bigEndianData)

        // Matrix (identity)
        let matrix: [Int32] = [
            0x00010000, 0, 0,
            0, 0x00010000, 0,
            0, 0, 0x40000000
        ]
        for value in matrix {
            data.append(value.bigEndianData)
        }

        // Width and height (16.16 fixed point)
        data.append(width.bigEndianData)
        data.append(height.bigEndianData)

        return data
    }
}

// MARK: - Media Header Box (mdhd)

/// Media header with overall information about the media data
public struct MediaHeaderBox: ISOFullBox {
    public let type = FourCC.mdhd
    public let version: UInt8
    public var flags: UInt32 = 0

    public let creationTime: UInt64
    public let modificationTime: UInt64
    public let timescale: UInt32
    public let duration: UInt64
    public let language: UInt16

    public init(timescale: UInt32, duration: UInt64 = 0, language: String = "und") {
        self.version = 1
        let now = UInt64(Date().timeIntervalSince1970) + 2082844800
        self.creationTime = now
        self.modificationTime = now
        self.timescale = timescale
        self.duration = duration
        // Pack language code (ISO-639-2/T)
        self.language = Self.packLanguage(language)
    }

    private static func packLanguage(_ lang: String) -> UInt16 {
        let chars = Array(lang.prefix(3).lowercased().utf8)
        guard chars.count == 3 else { return 0x55C4 } // "und"
        let c1 = UInt16(chars[0] - 0x60)
        let c2 = UInt16(chars[1] - 0x60)
        let c3 = UInt16(chars[2] - 0x60)
        return (c1 << 10) | (c2 << 5) | c3
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        if version == 1 {
            data.append(creationTime.bigEndianData)
            data.append(modificationTime.bigEndianData)
            data.append(timescale.bigEndianData)
            data.append(duration.bigEndianData)
        } else {
            data.append(UInt32(creationTime).bigEndianData)
            data.append(UInt32(modificationTime).bigEndianData)
            data.append(timescale.bigEndianData)
            data.append(UInt32(duration).bigEndianData)
        }

        data.append(language.bigEndianData)
        data.append(UInt16(0).bigEndianData) // Pre-defined

        return data
    }
}

// MARK: - Handler Reference Box (hdlr)

/// Handler reference declaring media type
public struct HandlerBox: ISOFullBox {
    public let type = FourCC.hdlr
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public let handlerType: FourCC
    public let name: String

    public init(handlerType: FourCC, name: String) {
        self.handlerType = handlerType
        self.name = name
    }

    public static var video: HandlerBox {
        HandlerBox(handlerType: .vide, name: "VideoHandler")
    }

    public static var audio: HandlerBox {
        HandlerBox(handlerType: .soun, name: "SoundHandler")
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Pre-defined
        data.append(UInt32(0).bigEndianData)

        // Handler type
        data.append(handlerType.data)

        // Reserved (12 bytes)
        data.append(Data(count: 12))

        // Name (null-terminated string)
        data.append(name.data(using: .utf8) ?? Data())
        data.append(0) // Null terminator

        return data
    }
}

// MARK: - Video Media Header Box (vmhd)

/// Video media header for video tracks
public struct VideoMediaHeaderBox: ISOFullBox {
    public let type = FourCC.vmhd
    public let version: UInt8 = 0
    public var flags: UInt32 = 1 // Required to be 1

    public init() {}

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Graphics mode (copy = 0)
        data.append(UInt16(0).bigEndianData)

        // Opcolor (RGB, all zeros)
        data.append(Data(count: 6))

        return data
    }
}

// MARK: - Sound Media Header Box (smhd)

/// Sound media header for audio tracks
public struct SoundMediaHeaderBox: ISOFullBox {
    public let type = FourCC.smhd
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public init() {}

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Balance (0 = center)
        data.append(Int16(0).bigEndianData)

        // Reserved
        data.append(UInt16(0).bigEndianData)

        return data
    }
}

// MARK: - Data Reference Box (dref)

/// Data reference box containing data reference URLs
public struct DataReferenceBox: ISOFullBox {
    public let type = FourCC.dref
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public init() {}

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Entry count
        data.append(UInt32(1).bigEndianData)

        // URL entry (self-contained)
        let urlBox = DataEntryUrlBox()
        data.append(urlBox.serialize())

        return data
    }
}

/// Data entry URL box
public struct DataEntryUrlBox: ISOFullBox {
    public let type = FourCC.url
    public let version: UInt8 = 0
    public var flags: UInt32 = 1 // Self-contained flag

    public init() {}

    public func serializePayload() -> Data {
        serializeVersionAndFlags()
        // No URL when self-contained
    }
}

// MARK: - Sample Table Boxes (empty for fMP4)

/// Sample description box
public struct SampleDescriptionBox: ISOFullBox {
    public let type = FourCC.stsd
    public let version: UInt8 = 0
    public var flags: UInt32 = 0
    public var entries: [any ISOBox]

    public init(entries: [any ISOBox]) {
        self.entries = entries
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(UInt32(entries.count).bigEndianData)
        for entry in entries {
            data.append(entry.serialize())
        }
        return data
    }
}

/// Time-to-sample box (empty for fragmented)
public struct TimeToSampleBox: ISOFullBox {
    public let type = FourCC.stts
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public init() {}

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(UInt32(0).bigEndianData) // Entry count = 0
        return data
    }
}

/// Sample-to-chunk box (empty for fragmented)
public struct SampleToChunkBox: ISOFullBox {
    public let type = FourCC.stsc
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public init() {}

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(UInt32(0).bigEndianData) // Entry count = 0
        return data
    }
}

/// Sample size box (empty for fragmented)
public struct SampleSizeBox: ISOFullBox {
    public let type = FourCC.stsz
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public init() {}

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(UInt32(0).bigEndianData) // Sample size (0 = variable)
        data.append(UInt32(0).bigEndianData) // Sample count = 0
        return data
    }
}

/// Chunk offset box (empty for fragmented)
public struct ChunkOffsetBox: ISOFullBox {
    public let type = FourCC.stco
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public init() {}

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(UInt32(0).bigEndianData) // Entry count = 0
        return data
    }
}

// MARK: - Movie Extends Box (mvex)

/// Track extends box - default values for track fragments
public struct TrackExtendsBox: ISOFullBox {
    public let type = FourCC.trex
    public let version: UInt8 = 0
    public var flags: UInt32 = 0

    public let trackID: UInt32
    public let defaultSampleDescriptionIndex: UInt32
    public let defaultSampleDuration: UInt32
    public let defaultSampleSize: UInt32
    public let defaultSampleFlags: UInt32

    public init(trackID: UInt32,
                defaultSampleDescriptionIndex: UInt32 = 1,
                defaultSampleDuration: UInt32 = 0,
                defaultSampleSize: UInt32 = 0,
                defaultSampleFlags: UInt32 = 0) {
        self.trackID = trackID
        self.defaultSampleDescriptionIndex = defaultSampleDescriptionIndex
        self.defaultSampleDuration = defaultSampleDuration
        self.defaultSampleSize = defaultSampleSize
        self.defaultSampleFlags = defaultSampleFlags
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()
        data.append(trackID.bigEndianData)
        data.append(defaultSampleDescriptionIndex.bigEndianData)
        data.append(defaultSampleDuration.bigEndianData)
        data.append(defaultSampleSize.bigEndianData)
        data.append(defaultSampleFlags.bigEndianData)
        return data
    }
}

// MARK: - Edit List Box (edts/elst)

/// Edit list box - maps presentation timeline to media timeline
/// Required by Apple HLS Authoring Spec for proper time mapping
public struct EditListBox: ISOFullBox {
    public let type = FourCC("elst")
    public let version: UInt8
    public var flags: UInt32 = 0

    public let entries: [EditListEntry]

    public struct EditListEntry {
        public let segmentDuration: UInt64
        public let mediaTime: Int64
        public let mediaRateInteger: Int16
        public let mediaRateFraction: Int16

        /// Create identity edit (1:1 mapping from media time 0)
        public static func identity(duration: UInt64 = 0) -> EditListEntry {
            EditListEntry(
                segmentDuration: duration,
                mediaTime: 0,
                mediaRateInteger: 1,
                mediaRateFraction: 0
            )
        }

        public init(segmentDuration: UInt64, mediaTime: Int64, mediaRateInteger: Int16 = 1, mediaRateFraction: Int16 = 0) {
            self.segmentDuration = segmentDuration
            self.mediaTime = mediaTime
            self.mediaRateInteger = mediaRateInteger
            self.mediaRateFraction = mediaRateFraction
        }
    }

    public init(entries: [EditListEntry]) {
        self.entries = entries
        // Use version 1 for 64-bit durations
        self.version = 1
    }

    /// Create identity edit list (presentation starts at media time 0)
    public static var identity: EditListBox {
        EditListBox(entries: [.identity()])
    }

    public func serializePayload() -> Data {
        var data = serializeVersionAndFlags()

        // Entry count
        data.append(UInt32(entries.count).bigEndianData)

        for entry in entries {
            if version == 1 {
                data.append(entry.segmentDuration.bigEndianData)
                data.append(UInt64(bitPattern: entry.mediaTime).bigEndianData)
            } else {
                data.append(UInt32(entry.segmentDuration).bigEndianData)
                data.append(Int32(entry.mediaTime).bigEndianData)
            }
            data.append(entry.mediaRateInteger.bigEndianData)
            data.append(entry.mediaRateFraction.bigEndianData)
        }

        return data
    }
}
