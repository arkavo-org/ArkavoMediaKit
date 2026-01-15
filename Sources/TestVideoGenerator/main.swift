import ArgumentParser
import ArkavoMediaKit
import AVFoundation
import Foundation
import Network

// MARK: - CLI Entry Point

@main
struct TestVideoGenerator: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "TestVideoGenerator",
        abstract: "Generate fMP4/HLS test videos for manual testing",
        discussion: """
            Generates test video packages based on the fMP4/HLS test matrix.
            Each scenario creates an init.mp4, media segments, and playlist.m3u8.

            For visual decode testing, use --source with a real video file:
              TestVideoGenerator --source video.mp4 -o ./output

            To serve content via HTTP for playback testing:
              TestVideoGenerator --serve ./output
            """
    )

    @Option(name: .shortAndLong, help: "Output directory for generated files")
    var output: String?

    @Option(name: .shortAndLong, help: "Specific scenario to generate (e.g., B1, B2, M1)")
    var scenario: String?

    @Option(name: .long, help: "Source video file to repackage as fMP4/HLS (for visual testing)")
    var source: String?

    @Option(name: .long, help: "Serve directory via HTTP (for AVPlayer playback)")
    var serve: String?

    @Option(name: .shortAndLong, help: "HTTP server port (default: 8888)")
    var port: UInt16 = 8888

    @Flag(name: .shortAndLong, help: "List all available scenarios")
    var list = false

    @Option(name: .shortAndLong, help: "Segment duration in seconds")
    var duration: Int = 6

    @Option(name: [.customShort("n"), .long], help: "Number of segments to generate")
    var segments: Int = 3

    mutating func run() async throws {
        if list {
            printScenarios()
            return
        }

        // Serve mode - start HTTP server
        if let servePath = serve {
            let serverDir = URL(fileURLWithPath: servePath)
            let server = SimpleHTTPServer(directory: serverDir, port: port)
            try await server.start()
            return
        }

        guard let output = output else {
            throw ValidationError("Missing required option '--output <output>' or '--serve <directory>'")
        }

        let outputURL = URL(fileURLWithPath: output)

        // If source video provided, repackage it as fMP4/HLS
        if let sourcePath = source {
            let sourceURL = URL(fileURLWithPath: sourcePath)
            let repackager = VideoRepackager(
                sourceURL: sourceURL,
                outputDir: outputURL,
                segmentDuration: duration
            )
            try await repackager.repackage()
            return
        }

        // Otherwise generate synthetic test scenarios
        let generator = VideoTestGenerator(
            outputDir: outputURL,
            segmentDuration: duration,
            segmentCount: segments
        )

        if let scenarioID = scenario?.uppercased() {
            try generator.generate(scenario: scenarioID)
        } else {
            try generator.generateAll()
        }
    }

    func printScenarios() {
        print("""
        Available Test Scenarios:

        Core Playback:
          B1  - Clear init + clear media (unencrypted)
          B2  - Clear init + encrypted media (FairPlay CBCS)

        Manifest Signaling:
          M1  - Single key SAMPLE-AES (FairPlay manifest)
          M3  - Clear (METHOD=NONE, no encryption tags)

        Fragment Boundary:
          F1  - Segment on IDR boundary
          F2  - Mid-GOP boundary (non-aligned)

        CMAF Compliance:
          C1  - CMAF single track (with styp box)

        Reference Profiles:
          P1  - Clear fMP4 HLS VOD (complete package)
          P2  - FairPlay single key (complete encrypted package)

        Usage: TestVideoGenerator -o ./output -s B2
        """)
    }
}

// MARK: - Video Test Generator

struct VideoTestGenerator {
    let outputDir: URL
    let segmentDuration: Int
    let segmentCount: Int

    // Test fixtures (same as HLSFairPlayTestMatrix.swift)
    let testKey = Data(repeating: 0x3C, count: 16)
    let testIV = Data([
        0xD5, 0xFB, 0xD6, 0xB8, 0x2E, 0xD9, 0x3E, 0x4E,
        0xF9, 0x8A, 0xE4, 0x09, 0x31, 0xEE, 0x33, 0xB7,
    ])
    let testKeyID = Data(repeating: 0x12, count: 16)

    // Realistic H.264 720p parameters
    // SPS: High profile, level 3.1, 1280x720
    let sampleSPS = Data([
        0x67, 0x64, 0x00, 0x1F, 0xAC, 0xD9, 0x40, 0x50,
        0x05, 0xBB, 0x01, 0x10, 0x00, 0x00, 0x03, 0x00,
        0x10, 0x00, 0x00, 0x03, 0x03, 0xC0, 0xF1, 0x83,
        0x19, 0x60,
    ])
    let samplePPS = Data([0x68, 0xEE, 0x3C, 0x80])

    func generateAll() throws {
        print("Generating all test scenarios to: \(outputDir.path)")

        try generateB1Clear()
        try generateB2FairPlay()
        try generateM1SampleAES()
        try generateM3Clear()
        try generateF1IDRBoundary()
        try generateF2MidGOP()
        try generateC1CMAF()
        try generateP1VODClear()
        try generateP2FairPlaySingleKey()

        print("\nAll scenarios generated successfully!")
    }

    func generate(scenario: String) throws {
        switch scenario {
        case "B1":
            try generateB1Clear()
        case "B2":
            try generateB2FairPlay()
        case "M1":
            try generateM1SampleAES()
        case "M3":
            try generateM3Clear()
        case "F1":
            try generateF1IDRBoundary()
        case "F2":
            try generateF2MidGOP()
        case "C1":
            try generateC1CMAF()
        case "P1":
            try generateP1VODClear()
        case "P2":
            try generateP2FairPlaySingleKey()
        default:
            throw ValidationError("Unknown scenario: \(scenario). Use --list to see available scenarios.")
        }
    }

    // MARK: - B1: Clear Init + Clear Media

    func generateB1Clear() throws {
        let dir = outputDir.appendingPathComponent("B1-clear")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: nil)

        // Generate init segment
        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        // Generate media segments
        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        // Generate playlist (clear, no encryption)
        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: nil)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated B1-clear: \(dir.path)")
    }

    // MARK: - B2: Clear Init + Encrypted Media (FairPlay)

    func generateB2FairPlay() throws {
        let dir = outputDir.appendingPathComponent("B2-fairplay")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        // Generate init segment (has encryption signaling but clear data)
        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        // Generate encrypted media segments
        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        // Generate playlist with FairPlay encryption
        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let fairplayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(
            assetID: "test-asset-b2",
            keyID: testKeyID,
            iv: testIV
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: fairplayConfig)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated B2-fairplay: \(dir.path)")
    }

    // MARK: - M1: Single Key SAMPLE-AES

    func generateM1SampleAES() throws {
        let dir = outputDir.appendingPathComponent("M1-sample-aes")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        // Playlist with METHOD=SAMPLE-AES and skd:// URI
        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let fairplayConfig = FMP4HLSGenerator.FairPlayConfig(
            keyURI: "skd://test-asset-m1",
            keyID: testKeyID,
            iv: testIV
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: fairplayConfig)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated M1-sample-aes: \(dir.path)")
    }

    // MARK: - M3: Clear (METHOD=NONE)

    func generateM3Clear() throws {
        let dir = outputDir.appendingPathComponent("M3-clear")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        // Clear content with no encryption
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: nil)

        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        // Playlist with no EXT-X-KEY tag
        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: nil)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated M3-clear: \(dir.path)")
    }

    // MARK: - F1: Segment on IDR Boundary

    func generateF1IDRBoundary() throws {
        let dir = outputDir.appendingPathComponent("F1-idr-boundary")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: nil)

        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        // Each segment starts with IDR (proper GOP alignment)
        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: nil)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated F1-idr-boundary: \(dir.path)")
    }

    // MARK: - F2: Mid-GOP Boundary

    func generateF2MidGOP() throws {
        let dir = outputDir.appendingPathComponent("F2-mid-gop")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: nil)

        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        // First segment starts with IDR, subsequent don't (mid-GOP)
        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let startWithIDR = (i == 0)  // Only first segment has IDR at start
            let samples = createSamples(duration: segmentDuration, startWithIDR: startWithIDR)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: nil)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated F2-mid-gop: \(dir.path)")
    }

    // MARK: - C1: CMAF Single Track

    func generateC1CMAF() throws {
        let dir = outputDir.appendingPathComponent("C1-cmaf")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        // CMAF single track - same as clear but validates styp box presence
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: nil)

        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: nil)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated C1-cmaf: \(dir.path)")
    }

    // MARK: - P1: Clear fMP4 HLS VOD (Reference)

    func generateP1VODClear() throws {
        let dir = outputDir.appendingPathComponent("P1-vod-clear")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: nil)

        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: nil)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated P1-vod-clear: \(dir.path)")
    }

    // MARK: - P2: FairPlay Single Key (Reference)

    func generateP2FairPlaySingleKey() throws {
        let dir = outputDir.appendingPathComponent("P2-fairplay-single-key")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let encryption = FMP4Writer.EncryptionConfig(keyID: testKeyID, constantIV: testIV)
        let track = FMP4Writer.TrackConfig.h264Video(
            width: 1280, height: 720, timescale: 90000,
            sps: [sampleSPS], pps: [samplePPS]
        )
        let writer = FMP4Writer(tracks: [track], encryption: encryption)

        let initData = writer.generateInitSegment()
        try initData.write(to: dir.appendingPathComponent("init.mp4"))

        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        for i in 0..<segmentCount {
            let samples = createSamples(duration: segmentDuration, startWithIDR: true)
            let baseTime = UInt64(i * segmentDuration * 90000)
            let segmentData = writer.generateMediaSegment(
                trackID: 1, samples: samples, baseDecodeTime: baseTime
            )
            let filename = "segment\(i).m4s"
            try segmentData.write(to: dir.appendingPathComponent(filename))
            hlsSegments.append(.init(uri: filename, duration: Double(segmentDuration)))
        }

        let hlsConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod
        )
        let fairplayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(
            assetID: "test-asset-p2",
            keyID: testKeyID,
            iv: testIV
        )
        let hlsGen = FMP4HLSGenerator(config: hlsConfig, encryption: fairplayConfig)
        let playlist = hlsGen.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(
            to: dir.appendingPathComponent("playlist.m3u8"),
            atomically: true, encoding: .utf8
        )

        print("Generated P2-fairplay-single-key: \(dir.path)")
    }

    // MARK: - Sample Creation

    func createSamples(duration: Int, startWithIDR: Bool) -> [FMP4Writer.Sample] {
        var samples: [FMP4Writer.Sample] = []
        let framesPerSecond = 30
        let frameDuration: UInt32 = 90000 / UInt32(framesPerSecond)  // 3000 ticks
        let totalFrames = duration * framesPerSecond

        for i in 0..<totalFrames {
            // IDR every 30 frames (1 second GOP) or first frame if startWithIDR
            let isIDR: Bool
            if i == 0 {
                isIDR = startWithIDR
            } else {
                isIDR = (i % 30 == 0)
            }

            let data = createVideoSample(isIDR: isIDR)
            samples.append(FMP4Writer.Sample(
                data: data,
                duration: frameDuration,
                isSync: isIDR
            ))
        }
        return samples
    }

    func createVideoSample(isIDR: Bool) -> Data {
        var data = Data()

        // NAL unit with 4-byte length prefix (Annex B to AVCC format)
        let nalType: UInt8 = isIDR ? 0x65 : 0x41  // IDR slice (5) vs non-IDR P-slice (1)

        // Create slice header + fake slice data
        // For IDR: larger to simulate keyframe (~8KB)
        // For P-frame: smaller (~2KB)
        let payloadSize = isIDR ? 8000 : 2000
        var nalData = Data([nalType])
        nalData.append(Data(repeating: 0xAB, count: payloadSize))

        // Write NAL length (big-endian 4 bytes)
        let length = UInt32(nalData.count)
        withUnsafeBytes(of: length.bigEndian) { data.append(contentsOf: $0) }
        data.append(nalData)

        return data
    }
}

// MARK: - Video Repackager (Real Video to fMP4/HLS)

/// Repackages a real video file as fMP4/HLS for visual decode testing
struct VideoRepackager {
    let sourceURL: URL
    let outputDir: URL
    let segmentDuration: Int

    func repackage() async throws {
        print("Repackaging \(sourceURL.lastPathComponent) as fMP4/HLS...")

        // Create output directory
        try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)

        // Load source video
        let asset = AVURLAsset(url: sourceURL)
        let videoTracks = try await asset.loadTracks(withMediaType: .video)
        guard let videoTrack = videoTracks.first else {
            throw RepackagerError.noVideoTrack
        }

        // Get video parameters
        let formatDescriptions = try await videoTrack.load(.formatDescriptions)
        guard let formatDesc = formatDescriptions.first else {
            throw RepackagerError.noFormatDescription
        }

        let dimensions = try await videoTrack.load(.naturalSize)
        let timescale = try await videoTrack.load(.naturalTimeScale)

        // Extract SPS/PPS from format description
        guard let h264Params = extractParameterSets(from: formatDesc) else {
            throw RepackagerError.noParameterSets
        }

        print("  Video: \(Int(dimensions.width))x\(Int(dimensions.height)), timescale: \(timescale)")
        print("  NAL length size: \(h264Params.nalLengthSize) bytes")

        // Create FMP4 writer (clear, no encryption)
        let trackConfig = FMP4Writer.TrackConfig.h264Video(
            width: UInt16(dimensions.width),
            height: UInt16(dimensions.height),
            timescale: UInt32(timescale),
            sps: h264Params.sps,
            pps: h264Params.pps
        )

        let writer = FMP4Writer(tracks: [trackConfig], encryption: nil)

        // Generate init segment
        print("  Generating init segment...")
        let initSegment = writer.generateInitSegment()
        try initSegment.write(to: outputDir.appendingPathComponent("init.mp4"))

        // Read samples from source
        print("  Reading video samples...")
        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderTrackOutput(track: videoTrack, outputSettings: nil)
        reader.add(output)
        reader.startReading()

        var allSamples: [FMP4Writer.Sample] = []

        while let sampleBuffer = output.copyNextSampleBuffer() {
            guard let dataBuffer = CMSampleBufferGetDataBuffer(sampleBuffer) else { continue }

            var length: Int = 0
            var dataPointer: UnsafeMutablePointer<Int8>?
            CMBlockBufferGetDataPointer(dataBuffer, atOffset: 0, lengthAtOffsetOut: nil, totalLengthOut: &length, dataPointerOut: &dataPointer)

            guard let pointer = dataPointer else { continue }
            let sampleData = Data(bytes: pointer, count: length)

            // Get timing info
            let duration = CMSampleBufferGetDuration(sampleBuffer)
            let durationValue = UInt32(duration.value * Int64(timescale) / Int64(duration.timescale))

            // Calculate Composition Time Offset for B-frames
            let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
            let dts = CMSampleBufferGetDecodeTimeStamp(sampleBuffer)
            var compositionTimeOffset: Int32 = 0

            if pts.isValid && dts.isValid && pts != dts {
                let ptsInTimescale = Int64(pts.value) * Int64(timescale) / Int64(pts.timescale)
                let dtsInTimescale = Int64(dts.value) * Int64(timescale) / Int64(dts.timescale)
                compositionTimeOffset = Int32(ptsInTimescale - dtsInTimescale)
            }

            // Check if sync sample
            let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false)
            var isSync = true
            if let attachments = attachments as? [[CFString: Any]],
               let first = attachments.first,
               let notSync = first[kCMSampleAttachmentKey_NotSync] as? Bool {
                isSync = !notSync
            }

            allSamples.append(FMP4Writer.Sample(
                data: sampleData,
                duration: durationValue,
                isSync: isSync,
                compositionTimeOffset: compositionTimeOffset
            ))
        }

        print("  Read \(allSamples.count) samples")

        // Generate media segments
        print("  Generating media segments...")
        let segmentDurationTicks = UInt64(segmentDuration * Int(timescale))
        var hlsSegments: [FMP4HLSGenerator.Segment] = []
        var segmentIndex = 0
        var sampleIndex = 0
        var currentSegmentSamples: [FMP4Writer.Sample] = []
        var currentSegmentDuration: UInt64 = 0
        var baseDecodeTime: UInt64 = 0

        while sampleIndex < allSamples.count {
            let sample = allSamples[sampleIndex]
            currentSegmentSamples.append(sample)
            currentSegmentDuration += UInt64(sample.duration)
            sampleIndex += 1

            // End segment when duration reached or last sample
            let shouldEndSegment = currentSegmentDuration >= segmentDurationTicks || sampleIndex == allSamples.count

            if shouldEndSegment && !currentSegmentSamples.isEmpty {
                let segmentData = writer.generateMediaSegment(
                    trackID: 1,
                    samples: currentSegmentSamples,
                    baseDecodeTime: baseDecodeTime
                )

                let segmentFilename = "segment\(segmentIndex).m4s"
                try segmentData.write(to: outputDir.appendingPathComponent(segmentFilename))

                let duration = Double(currentSegmentDuration) / Double(timescale)
                hlsSegments.append(FMP4HLSGenerator.Segment(uri: segmentFilename, duration: duration))

                baseDecodeTime += currentSegmentDuration
                currentSegmentSamples = []
                currentSegmentDuration = 0
                segmentIndex += 1
            }
        }

        print("  Created \(segmentIndex) segments")

        // Generate HLS playlist
        print("  Generating playlist...")
        let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: segmentDuration,
            playlistType: .vod,
            initSegmentURI: "init.mp4"
        )

        let hlsGenerator = FMP4HLSGenerator(config: playlistConfig, encryption: nil)
        let playlist = hlsGenerator.generateMediaPlaylist(segments: hlsSegments)
        try playlist.write(to: outputDir.appendingPathComponent("playlist.m3u8"), atomically: true, encoding: .utf8)

        print("Done! Output: \(outputDir.path)")
        print("  To play: open \(outputDir.path)/playlist.m3u8")
    }

    // MARK: - Parameter Set Extraction

    private struct H264Parameters {
        let sps: [Data]
        let pps: [Data]
        let nalLengthSize: Int
    }

    private func extractParameterSets(from formatDesc: CMFormatDescription) -> H264Parameters? {
        guard let extensions = CMFormatDescriptionGetExtensions(formatDesc) as? [String: Any],
              let sampleDescriptionExtensions = extensions["SampleDescriptionExtensionAtoms"] as? [String: Any],
              let avcCData = sampleDescriptionExtensions["avcC"] as? Data
        else {
            return nil
        }

        guard avcCData.count >= 8 else { return nil }

        // Extract NAL length size from byte 4 (lower 2 bits + 1)
        let lengthSizeMinusOne = Int(avcCData[4] & 0x03)
        let nalLengthSize = lengthSizeMinusOne + 1

        var sps: [Data] = []
        var pps: [Data] = []
        var offset = 5

        // Number of SPS (lower 5 bits)
        let numSPS = Int(avcCData[offset] & 0x1F)
        offset += 1

        for _ in 0..<numSPS {
            guard offset + 2 <= avcCData.count else { break }
            let spsLen = Int(avcCData[offset]) << 8 | Int(avcCData[offset + 1])
            offset += 2
            guard offset + spsLen <= avcCData.count else { break }
            sps.append(avcCData.subdata(in: offset..<(offset + spsLen)))
            offset += spsLen
        }

        guard offset < avcCData.count else {
            return sps.isEmpty ? nil : H264Parameters(sps: sps, pps: pps, nalLengthSize: nalLengthSize)
        }

        let numPPS = Int(avcCData[offset])
        offset += 1

        for _ in 0..<numPPS {
            guard offset + 2 <= avcCData.count else { break }
            let ppsLen = Int(avcCData[offset]) << 8 | Int(avcCData[offset + 1])
            offset += 2
            guard offset + ppsLen <= avcCData.count else { break }
            pps.append(avcCData.subdata(in: offset..<(offset + ppsLen)))
            offset += ppsLen
        }

        return sps.isEmpty ? nil : H264Parameters(sps: sps, pps: pps, nalLengthSize: nalLengthSize)
    }
}

// MARK: - Repackager Errors

enum RepackagerError: Error, LocalizedError {
    case noVideoTrack
    case noFormatDescription
    case noParameterSets

    var errorDescription: String? {
        switch self {
        case .noVideoTrack: "No video track found in source file"
        case .noFormatDescription: "No format description in video track"
        case .noParameterSets: "Could not extract SPS/PPS from video"
        }
    }
}

// MARK: - Simple HTTP Server

/// Simple HTTP server for serving fMP4/HLS content to AVPlayer
final class SimpleHTTPServer: @unchecked Sendable {
    private let directory: URL
    private let port: UInt16
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "SimpleHTTPServer")

    init(directory: URL, port: UInt16) {
        self.directory = directory
        self.port = port
    }

    func start() async throws {
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true

        listener = try NWListener(using: parameters, on: NWEndpoint.Port(rawValue: port)!)

        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleConnection(connection)
        }

        listener?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("HTTP server running at http://127.0.0.1:\(self.port)/")
                print("Playlist URL: http://127.0.0.1:\(self.port)/playlist.m3u8")
                print("Press Ctrl+C to stop")
            case .failed(let error):
                print("Server failed: \(error)")
            default:
                break
            }
        }

        listener?.start(queue: queue)

        // Keep running until interrupted
        await withCheckedContinuation { (_: CheckedContinuation<Void, Never>) in
            // Never resumes - runs until process killed
        }
    }

    private func handleConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = { state in
            if case .ready = state {
                self.receiveRequest(connection)
            }
        }
        connection.start(queue: queue)
    }

    private func receiveRequest(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, _, error in
            guard let self = self, let data = data, error == nil else {
                connection.cancel()
                return
            }

            guard let request = String(data: data, encoding: .utf8) else {
                connection.cancel()
                return
            }

            self.handleRequest(request, connection: connection)
        }
    }

    private func handleRequest(_ request: String, connection: NWConnection) {
        let lines = request.split(separator: "\r\n")
        guard let firstLine = lines.first else {
            sendError(connection, status: 400, message: "Bad Request")
            return
        }

        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2, parts[0] == "GET" else {
            sendError(connection, status: 405, message: "Method Not Allowed")
            return
        }

        var path = String(parts[1])
        if path == "/" {
            path = "/playlist.m3u8"
        }

        // Remove leading slash and decode URL
        let filename = String(path.dropFirst()).removingPercentEncoding ?? String(path.dropFirst())
        let fileURL = directory.appendingPathComponent(filename)

        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            print("  404: \(filename)")
            sendError(connection, status: 404, message: "Not Found")
            return
        }

        do {
            let fileData = try Data(contentsOf: fileURL)
            let mimeType = mimeTypeFor(filename)
            print("  200: \(filename) (\(fileData.count) bytes)")

            let response = """
            HTTP/1.1 200 OK\r
            Content-Type: \(mimeType)\r
            Content-Length: \(fileData.count)\r
            Access-Control-Allow-Origin: *\r
            Connection: close\r
            \r

            """

            var responseData = response.data(using: .utf8)!
            responseData.append(fileData)

            connection.send(content: responseData, completion: .contentProcessed { _ in
                connection.cancel()
            })
        } catch {
            sendError(connection, status: 500, message: "Internal Server Error")
        }
    }

    private func sendError(_ connection: NWConnection, status: Int, message: String) {
        let response = """
        HTTP/1.1 \(status) \(message)\r
        Content-Type: text/plain\r
        Content-Length: \(message.count)\r
        Connection: close\r
        \r
        \(message)
        """

        connection.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private func mimeTypeFor(_ filename: String) -> String {
        let ext = (filename as NSString).pathExtension.lowercased()
        switch ext {
        case "m3u8": return "application/vnd.apple.mpegurl"
        case "m4s": return "video/iso.segment"
        case "mp4": return "video/mp4"
        case "m4v": return "video/mp4"
        case "ts": return "video/mp2t"
        default: return "application/octet-stream"
        }
    }
}
