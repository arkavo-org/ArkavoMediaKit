import Foundation

// MARK: - ISO BMFF Box Protocol

/// Protocol for all ISO Base Media File Format boxes
public protocol ISOBox {
    /// Four-character code identifying the box type
    var type: FourCC { get }

    /// Serialize box contents (excluding size and type header)
    func serializePayload() -> Data
}

extension ISOBox {
    /// Serialize complete box with size and type header
    public func serialize() -> Data {
        let payload = serializePayload()
        var data = Data()

        // Box size (4 bytes) = size field (4) + type field (4) + payload
        let size = UInt32(8 + payload.count)
        data.append(size.bigEndianData)

        // Box type (4 bytes)
        data.append(type.data)

        // Payload
        data.append(payload)

        return data
    }
}

// MARK: - Full Box Protocol

/// Protocol for full boxes (boxes with version and flags)
public protocol ISOFullBox: ISOBox {
    var version: UInt8 { get }
    var flags: UInt32 { get }
}

extension ISOFullBox {
    /// Serialize version and flags (4 bytes total)
    func serializeVersionAndFlags() -> Data {
        var data = Data()
        data.append(version)
        // Flags are 24 bits (3 bytes)
        data.append(UInt8((flags >> 16) & 0xFF))
        data.append(UInt8((flags >> 8) & 0xFF))
        data.append(UInt8(flags & 0xFF))
        return data
    }
}

// MARK: - Four Character Code

/// Four-character code for box type identification
public struct FourCC: Equatable, Hashable, CustomStringConvertible, Sendable {
    public let value: UInt32

    public init(_ string: String) {
        precondition(string.count == 4, "FourCC must be exactly 4 characters")
        let bytes = Array(string.utf8)
        self.value = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
    }

    public init(value: UInt32) {
        self.value = value
    }

    public var data: Data {
        value.bigEndianData
    }

    public var description: String {
        let bytes = [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ]
        return String(bytes: bytes, encoding: .ascii) ?? "????"
    }

    // Common box types
    public static let ftyp = FourCC("ftyp")
    public static let styp = FourCC("styp")  // Segment type box for media segments
    public static let moov = FourCC("moov")
    public static let mvhd = FourCC("mvhd")
    public static let trak = FourCC("trak")
    public static let tkhd = FourCC("tkhd")
    public static let mdia = FourCC("mdia")
    public static let mdhd = FourCC("mdhd")
    public static let hdlr = FourCC("hdlr")
    public static let minf = FourCC("minf")
    public static let vmhd = FourCC("vmhd")
    public static let smhd = FourCC("smhd")
    public static let dinf = FourCC("dinf")
    public static let dref = FourCC("dref")
    public static let url  = FourCC("url ")
    public static let stbl = FourCC("stbl")
    public static let stsd = FourCC("stsd")
    public static let stts = FourCC("stts")
    public static let stsc = FourCC("stsc")
    public static let stsz = FourCC("stsz")
    public static let stco = FourCC("stco")
    public static let mvex = FourCC("mvex")
    public static let trex = FourCC("trex")
    public static let moof = FourCC("moof")
    public static let mfhd = FourCC("mfhd")
    public static let traf = FourCC("traf")
    public static let tfhd = FourCC("tfhd")
    public static let tfdt = FourCC("tfdt")
    public static let trun = FourCC("trun")
    public static let mdat = FourCC("mdat")
    public static let sidx = FourCC("sidx")

    // Edit list boxes
    public static let edts = FourCC("edts")
    public static let elst = FourCC("elst")

    // Codec boxes
    public static let avc1 = FourCC("avc1")
    public static let avcC = FourCC("avcC")
    public static let hvc1 = FourCC("hvc1")
    public static let hvcC = FourCC("hvcC")
    public static let mp4a = FourCC("mp4a")
    public static let esds = FourCC("esds")

    // Encryption boxes
    public static let sinf = FourCC("sinf")
    public static let frma = FourCC("frma")
    public static let schm = FourCC("schm")
    public static let schi = FourCC("schi")
    public static let tenc = FourCC("tenc")
    public static let pssh = FourCC("pssh")
    public static let senc = FourCC("senc")
    public static let saiz = FourCC("saiz")
    public static let saio = FourCC("saio")
    public static let encv = FourCC("encv")
    public static let enca = FourCC("enca")
    public static let cbcs_aux = FourCC("cbcs")  // CBCS aux_info_type for saiz/saio

    // Handler types
    public static let vide = FourCC("vide")
    public static let soun = FourCC("soun")
}

// MARK: - Data Extensions

extension UInt16 {
    var bigEndianData: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: 2)
    }
}

extension UInt32 {
    var bigEndianData: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: 4)
    }
}

extension UInt64 {
    var bigEndianData: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: 8)
    }
}

extension Int16 {
    var bigEndianData: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: 2)
    }
}

extension Int32 {
    var bigEndianData: Data {
        var value = self.bigEndian
        return Data(bytes: &value, count: 4)
    }
}

extension FixedWidthInteger {
    init(bigEndianData data: Data) {
        var value: Self = 0
        _ = withUnsafeMutableBytes(of: &value) { data.copyBytes(to: $0) }
        self = Self(bigEndian: value)
    }
}

// MARK: - Container Box

/// A box that contains other boxes
public struct ContainerBox: ISOBox {
    public let type: FourCC
    public var children: [any ISOBox]

    public init(type: FourCC, children: [any ISOBox] = []) {
        self.type = type
        self.children = children
    }

    public func serializePayload() -> Data {
        var data = Data()
        for child in children {
            data.append(child.serialize())
        }
        return data
    }

    public mutating func append(_ box: any ISOBox) {
        children.append(box)
    }
}

// MARK: - Raw Data Box

/// A box with raw data payload (for mdat, etc.)
public struct RawDataBox: ISOBox {
    public let type: FourCC
    public let data: Data

    public init(type: FourCC, data: Data) {
        self.type = type
        self.data = data
    }

    public func serializePayload() -> Data {
        data
    }
}
