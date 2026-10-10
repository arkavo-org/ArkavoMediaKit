import Foundation

/// Slice header lengths measured by ffmpeg's `trace_headers` (its last slice header syntax element, before any
/// `cabac_alignment_one_bit`), as raw NAL bytes: the header byte and the slice header, emulation prevention bytes
/// included, rounded up. Each slice is its NAL unit's first bytes: the header and 8 bytes after it.
///
/// The streams are 320x180 `testsrc2` (fading in, so weighted prediction has something to do):
/// - `high`: libx264 High, CABAC, two slices a picture, three B frames with B-pyramid (memory management control
///   operations), four references (reference list modification) and explicit weighted P prediction.
/// - `baseline`: libx264 Baseline, CAVLC, two slices a picture, picture order count type 2.
/// - `interlaced`: libx264 High, MBAFF (`frame_mbs_only_flag` 0), two B frames.
/// - `vt`: Apple's VideoToolbox encoder (`h264_videotoolbox`) High, the encoder Creator records with.
/// - `creator`: the first frames of a recording Creator protected on 2026-10-09.
/// - `matrix`: libx264 High with a custom quantization matrix and the 8x8 transform.
enum H264SliceHeaderFixtures {
    struct Stream {
        let sps: String
        let pps: String
        let slices: [(nal: String, headerSize: Int)]
    }

    static let all: [(name: String, stream: Stream)] = [
        ("high", high), ("baseline", baseline), ("interlaced", interlaced), ("vt", vt), ("creator", creator),
        ("matrix", matrix),
    ]

    static let high = Stream(
        sps: "6764000dacd941419f9f0110000003001000000303c0f1429960",
        pps: "68e938f2c8b0",
        slices: [
            ("6588840027fffef5b17c0a6ae9ea", 6),  // type 5, header 42 bits
            ("6503c88840027ffef5b17c0a6ae9ea", 7),  // type 5, header 54 bits
            ("41888840bffde21c196cdc8223", 5),  // type 1, header 40 bits
            ("4103c888840bfffedb5bf32cad88db", 7),  // type 1, header 52 bits
            ("419a443c2108642e02380e3200ff20040602380e6046ff8e27389c07a64151", 23),  // type 1, header 180 bits
            ("4103c9a443c2108642e02380e3200ff20040602380e60427ff79dd6b0415e9e1e1", 25),  // type 1, header 194 bits
            ("419e626a53c9ff8e9fcbdbb03a7201", 7),  // type 1, header 50 bits
            ("4103c9e626a53c2bfffefd870e6b336d9b", 9),  // type 1, header 66 bits
            ("019e836a447f96bfff92b492eaaa", 6),  // type 1, header 44 bits
            ("0103c9e836a427fffb016b033bbf7b55", 8),  // type 1, header 58 bits
            ("419a854ba842105a218f0271e02781e80a2022c09c24022fff6887666dd938ba74", 25),  // type 1, header 193 bits
            ("4103c9a854ba842105a218f0271e02781e80a2022c09c240217ffe7fe018f222d968", 26),  // type 1, header 207 bits
            ("419aa94de10842968853c1d06e039806680e2018b0741d0027ff5707a3a3294b2300", 26),  // type 1, header 203 bits
            ("4103c9aa94de10842968853c1d06e039806680e2018b0741d00217ff85bcbdc995d7217d", 28),  // type 1, header 219 bits
            ("419ec76e5344c67faf4ec1b2e9ec20ba", 8),  // type 1, header 60 bits
            ("4103c9ec76e5344c2bfffefd870e6b336bdb", 10),  // type 1, header 74 bits
        ])
    static let baseline = Stream(
        sps: "6742c00dd901419f9f0110000003001000000303c0f142a480",
        pps: "68cb83cb20",
        slices: [
            ("65888409f2628000a16c9c9c9c", 5),  // type 5, header 36 bits
            ("6503c888409f2628000a16c9c9c9", 6),  // type 5, header 48 bits
            ("41888823fcc6ae0580978a0002", 5),  // type 1, header 34 bits
            ("4103c888827c4628000a0cc76380", 6),  // type 1, header 46 bits
            ("419a540fff1b552709bfafb852", 5),  // type 1, header 35 bits
            ("4103c9a54057f00e05476380008116", 7),  // type 1, header 49 bits
        ])
    static let interlaced = Stream(
        sps: "67640015acd941433f260220000003002000000783e28532c0",
        pps: "68fba3cb22c0",
        slices: [
            ("6588820b027ff6f5b17c0a6ae9ea", 6),  // type 5, header 46 bits
            ("418888360cfff5fb45f256dc8250", 6),  // type 1, header 44 bits
            ("419a425d11ff55a0a5d4c09e4679", 6),  // type 1, header 46 bits
            ("419e615ea53d7f66073ff0914ebcc5", 7),  // type 1, header 52 bits
            ("019e81dea447b5e23b18930c950d", 6),  // type 1, header 48 bits
            ("419a82db4b4446ff50ed6049e940023f", 8),  // type 1, header 60 bits
            ("419aa45bd29113ff4c1771ff5a662f35", 8),  // type 1, header 58 bits
            ("419ec35c5344c57fb46722bbd59a6826", 8),  // type 1, header 60 bits
            ("019ee3dea46796a18c0e21002e57", 6),  // type 1, header 48 bits
            ("419ae5db4b444fff44f2e33507bdc478", 8),  // type 1, header 58 bits
        ])
    static let vt = Stream(
        sps: "2764000dac56281419f9d0",
        pps: "28ee3cb0",
        slices: [
            ("25b82007fff08435757f81e598", 5),  // type 5, header 35 bits
            ("01e1049fffd756ae8512deb5df", 5),  // type 1, header 33 bits
            ("21e10844ffd2e4a79479dd8df1", 5),  // type 1, header 36 bits
            ("01e20c89ffd358a70d46e3287a", 5),  // type 1, header 35 bits
            ("21e21045ff51cd41fa40f58c61", 5),  // type 1, header 36 bits
            ("01e3148bff527e00ed35888c4b", 5),  // type 1, header 35 bits
            ("21e31846ff611a00f532d6cebc", 5),  // type 1, header 36 bits
            ("01e41c8dff7ec967010453dd11", 5),  // type 1, header 35 bits
        ])
    static let creator = Stream(
        sps: "6764001facd9405005bb0110000003001000000303c0f1831960",
        pps: "68ef8fcb",
        slices: [
            ("6588840047dae396a472138a57", 5),  // type 5, header 40 bits
            ("419a23188affbdba117ff03a7f36", 6),  // type 1, header 43 bits
            ("419e414216fffeed75ef51f2e306", 6),  // type 1, header 43 bits
            ("019e62442dffbc84660e513d628e", 6),  // type 1, header 42 bits
            ("419a65344ca78aff2ba9ce42002c736a", 8),  // type 1, header 59 bits
            ("019e84442dffb473b8933cbc1371", 6),  // type 1, header 42 bits
        ])
    static let matrix = Stream(
        sps: "6764000dacb202833f3e0220000003002000000781e28549",
        pps: "68ebc3cb3002c0",
        slices: [
            ("65888427d9674d6278ad3ceb", 4),  // type 5, header 32 bits
            ("419a3b127fbaf6a9cf81426e56", 5),  // type 1, header 36 bits
            ("419a4f0864ca6127aefdeff1cc27f5a9", 8),  // type 1, header 64 bits
            ("419a727843c994c093ffb2bd5d719dbd9509", 10),  // type 1, header 73 bits
        ])
}

extension Data {
    /// The bytes of a hexadecimal string of even length.
    init(hex: String) {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index ..< next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
