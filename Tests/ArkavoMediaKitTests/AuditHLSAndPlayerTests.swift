import AVFoundation
import CryptoKit
import Foundation
import OpenTDFKit
import Testing
import ZIPFoundation
@testable import ArkavoMediaKit

@Suite("Audit: HLS Resource Loader, Extractor, Playlist & Streaming Player")
struct AuditHLSAndPlayerTests {
    // MARK: - HLSResourceLoaderDelegate URL routing, playlist rewriting, and range checks

    @Test("HLSResourceLoaderDelegate routes both host-form and path-form URLs and rejects invalid/key routes")
    func resourceLoaderURLRouting() throws {
        // Both legacy host-form and normalized local-host form route properly
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://playlist.m3u8")!) == .playlist)
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://local/playlist.m3u8")!) == .playlist)
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://segments/0.enc")!) == .segment(0))
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://local/segments/42.enc")!) == .segment(42))

        // Raw key route, negative index, traversal, wrong scheme, and malformed segment names are rejected
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://key")!) == nil)
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://local/key")!) == nil)
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://segments/-1.enc")!) == nil)
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://local/segments/-5.enc")!) == nil)
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "tdf-hls://local/segments/abc.enc")!) == nil)
        #expect(HLSResourceLoaderDelegate.route(for: URL(string: "https://local/playlist.m3u8")!) == nil)
    }

    @Test("HLSResourceLoaderDelegate rewrites playlist line-by-line without corrupting duplicates and strips #EXT-X-KEY")
    func resourceLoaderPlaylistRewriting() {
        let input = """
        #EXTM3U
        #EXT-X-VERSION:3
        #EXT-X-TARGETDURATION:6
        #EXT-X-KEY:METHOD=AES-128,URI="key.bin"
        #EXTINF:6.000,
        segments/0.enc
        #EXTINF:6.000,
        segments/0.enc
        #EXTINF:6.000,
        segments/1.enc
        #EXT-X-ENDLIST
        """

        let rewritten = HLSResourceLoaderDelegate.rewritePlaylistURLs(input)
        #expect(!rewritten.contains("#EXT-X-KEY:"), "Must strip #EXT-X-KEY to prevent double-decryption and raw key exposure")
        #expect(!rewritten.contains("tdf-hls://local/tdf-hls://"), "Duplicate URIs must never be double-prefixed")
        let lines = rewritten.components(separatedBy: "\n")
        let seg0Lines = lines.filter { $0 == "tdf-hls://local/segments/0.enc" }
        #expect(seg0Lines.count == 2)
        #expect(lines.contains("tdf-hls://local/segments/1.enc"))
    }

    @Test("HLSResourceLoaderDelegate.safeByteRange guards against negative values and Int overflow")
    func resourceLoaderSafeByteRange() {
        #expect(HLSResourceLoaderDelegate.safeByteRange(requestedOffset: -1, requestedLength: 10, dataCount: 100) == nil)
        #expect(HLSResourceLoaderDelegate.safeByteRange(requestedOffset: 0, requestedLength: -5, dataCount: 100) == nil)
        #expect(HLSResourceLoaderDelegate.safeByteRange(requestedOffset: 0, requestedLength: 10, dataCount: -1) == nil)

        // Overflowing requestedOffset + requestedLength clamps safely to dataCount instead of trapping
        let overflowRange = HLSResourceLoaderDelegate.safeByteRange(
            requestedOffset: 50,
            requestedLength: Int.max,
            dataCount: 100
        )
        #expect(overflowRange == 50 ..< 100)

        // Offset past end returns empty range
        #expect(HLSResourceLoaderDelegate.safeByteRange(requestedOffset: 200, requestedLength: 10, dataCount: 100) == 100 ..< 100)
        // Normal range
        #expect(HLSResourceLoaderDelegate.safeByteRange(requestedOffset: 10, requestedLength: 25, dataCount: 100) == 10 ..< 35)
    }

    // MARK: - TDF3StreamingPlayer.waitForReadyToPlay KVO cancellation & synchronization

    #if canImport(UIKit) || canImport(AppKit)
    @Test("TDF3StreamingPlayer.waitForReadyToPlay handles cancellation and external abort without hang or double-resume")
    @MainActor
    func streamingPlayerWaitForReadyToPlayCancellation() async throws {
        // 1. Task cancellation wakes waitForReadyToPlay promptly with CancellationError
        let item1 = AVPlayerItem(url: URL(string: "https://example.invalid/never-resolves.m3u8")!)
        let waitTask = Task {
            try await TDF3StreamingPlayer.waitForReadyToPlay(playerItem: item1)
        }
        try await Task.sleep(for: .milliseconds(30))
        waitTask.cancel()
        await #expect(throws: CancellationError.self) {
            try await waitTask.value
        }

        // 2. Concurrent registerCancel + Task.cancel never double-resumes continuation
        let item2 = AVPlayerItem(url: URL(string: "https://example.invalid/never-resolves-2.m3u8")!)
        var cancelClosure: (() -> Void)?
        let raceTask = Task {
            try await TDF3StreamingPlayer.waitForReadyToPlay(playerItem: item2) { cancel in
                cancelClosure = cancel
            }
        }
        try await Task.sleep(for: .milliseconds(30))
        // Fire both external cancel and task cancel repeatedly to stress the one-shot Mutex guard
        cancelClosure?()
        cancelClosure?()
        raceTask.cancel()
        await #expect(throws: CancellationError.self) {
            try await raceTask.value
        }

        // 3. Overlapping loadStream calls + stop(): completing waiter A must not clear waiter B's cancel handler
        if #available(iOS 18.0, macOS 15.0, tvOS 18.0, *) {
            let provider = StandardTDFKeyProvider(
                kasURL: URL(string: "https://kas.example.com")!,
                kasPublicKeyPEM: "",
                sessionManager: TDF3MediaSession()
            )
            let player = TDF3StreamingPlayer(
                keyProvider: provider,
                policy: MediaDRMPolicy(),
                deviceInfo: DeviceInfo(),
                sessionID: UUID()
            )
            let sessionA = MediaSession(userID: "u1", assetID: "a1")
            let sessionB = MediaSession(userID: "u1", assetID: "a2")
            let loadA = Task {
                try await player.loadStream(url: URL(string: "https://example.invalid/a.m3u8")!, session: sessionA)
            }
            try await Task.sleep(for: .milliseconds(30))
            let loadB = Task {
                try await player.loadStream(url: URL(string: "https://example.invalid/b.m3u8")!, session: sessionB)
            }
            // Wait for loadA to finish cancelling (its defer runs while loadB is active!)
            await #expect(throws: CancellationError.self) {
                try await loadA.value
            }
            // Now stop() must STILL cancel loadB (proving loadA's defer did NOT clear loadB's cancel handle)
            player.stop()
            await #expect(throws: CancellationError.self) {
                try await loadB.value
            }
        }
    }
    #endif

    // MARK: - HLSTDFExtractor ZIP bomb size caps, symlink rejection & algorithm downgrade

    private static func makeZIP(entries: [(path: String, type: Entry.EntryType, data: Data)]) throws -> Data {
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-zip-\(UUID().uuidString).zip")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let archive = try Archive(url: tempURL, accessMode: .create)
        for entry in entries {
            try archive.addEntry(
                with: entry.path,
                type: entry.type,
                uncompressedSize: Int64(entry.data.count),
                compressionMethod: .deflate,
                provider: { pos, size in
                    entry.data.subdata(in: Int(pos) ..< (Int(pos) + size))
                }
            )
        }
        return try Data(contentsOf: tempURL)
    }

    private static func sampleHLSManifestData(
        kasURL: String = "https://kas.example.com/kas",
        algorithm: String = "AES-256-GCM",
        encryptionMode: String = "GCM"
    ) throws -> Data {
        let obj: [String: Any] = [
            "encryptionInformation": [
                "type": "split",
                "keyAccess": [[
                    "type": "wrapped",
                    "url": kasURL,
                    "protocol": "kas",
                    "wrappedKey": Data(repeating: 0x11, count: 32).base64EncodedString(),
                ]],
                "method": [
                    "algorithm": algorithm,
                    "iv": Data(repeating: 0x02, count: 12).base64EncodedString(),
                ],
            ],
            "meta": [
                "hls": [
                    "assetId": "asset-1",
                    "segmentIVs": [Data(repeating: 0x02, count: 12).base64EncodedString()],
                    "segmentCount": 1,
                    "totalDuration": 6.0,
                    "encryptionMode": encryptionMode,
                ],
            ],
        ]
        return try JSONSerialization.data(withJSONObject: obj)
    }

    @Test("HLSTDFExtractor enforces ZIP bomb size caps and rejects symlink entries")
    func extractorZipBombAndSymlinkRejection() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("audit-extract-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let trustedKAS = URL(string: "https://kas.example.com")!
        let smallLimits = HLSTDFExtractor.ExtractionLimits(
            maxManifestBytes: 16 * 1024,
            maxPlaylistBytes: 16 * 1024,
            maxSegmentBytes: 1024,
            maxTotalBytes: 2048,
            maxSegmentCount: 4
        )
        let extractor = HLSTDFExtractor(kasURL: trustedKAS, limits: smallLimits)

        // 1. Oversized segment (highly compressible ZIP bomb) is rejected by maxSegmentBytes
        let manifestData = try Self.sampleHLSManifestData()
        let bombSegment = Data(repeating: 0x00, count: 4096)
        let bombZIP = try Self.makeZIP(entries: [
            ("manifest.json", .file, manifestData),
            ("playlist.m3u8", .file, Data("#EXTM3U\nsegments/0.enc\n".utf8)),
            ("segments/0.enc", .file, bombSegment),
        ])
        await #expect(throws: HLSTDFExtractorError.entryTooLarge("segments/0.enc")) {
            _ = try await extractor.extract(tdfData: bombZIP, outputDirectory: dir)
        }

        // 2. Symlink entry inside archive is rejected
        let symlinkZIP = try Self.makeZIP(entries: [
            ("manifest.json", .file, manifestData),
            ("playlist.m3u8", .symlink, Data("/etc/passwd".utf8)),
            ("segments/0.enc", .file, Data(repeating: 0xAA, count: 32)),
        ])
        await #expect(throws: HLSTDFExtractorError.unsupportedEntryType("playlist.m3u8")) {
            _ = try await extractor.extract(tdfData: symlinkZIP, outputDirectory: dir)
        }

        // 3. Untrusted off-origin manifest kasURL is rejected during extraction
        let hostileManifest = try Self.sampleHLSManifestData(kasURL: "https://evil.attacker.example/kas")
        let hostileZIP = try Self.makeZIP(entries: [
            ("manifest.json", .file, hostileManifest),
            ("playlist.m3u8", .file, Data("#EXTM3U\nsegments/0.enc\n".utf8)),
            ("segments/0.enc", .file, Data(repeating: 0xAA, count: 32)),
        ])
        await #expect(throws: HLSTDFExtractorError.untrustedKASURL("https://evil.attacker.example/kas")) {
            _ = try await extractor.extract(tdfData: hostileZIP, outputDirectory: dir)
        }
    }

    @Test("HLSTDFExtractor rejects GCM->CBC downgrade, invalid policyBinding, and negative segmentIndex")
    func extractorDowngradeAndIntegrity() async throws {
        let extractor = HLSTDFExtractor(kasURL: URL(string: "https://kas.example.com")!)
        let dek = SymmetricKey(size: .bits256)
        let iv = Data(repeating: 0x05, count: 12)
        let policyBase64 = Data(#"{"uuid":"11111111-2222-3333-4444-555555555555","body":{}}"#.utf8).base64EncodedString()
        let goodBinding = Data(HMAC<SHA256>.authenticationCode(for: Data(policyBase64.utf8), using: dek)).base64EncodedString()

        // Downgrade attempt: method.algorithm is AES-256-GCM, but meta.hls.encryptionMode is forged to CBC
        let downgradeManifest = HLSManifest(
            assetID: "a1",
            wrappedKey: "d2s=",
            algorithm: "AES-256-GCM",
            segmentIVs: [iv.base64EncodedString()],
            segmentCount: 1,
            totalDuration: 6.0,
            encryptionMode: "CBC",
            kasURL: URL(string: "https://kas.example.com")!,
            policy: policyBase64,
            policyBindingAlg: "HS256",
            policyBindingHash: goodBinding
        )
        await #expect(throws: HLSTDFExtractorError.algorithmMismatch) {
            _ = try await extractor.decryptSegment(
                segmentData: Data(repeating: 0xAA, count: 32),
                segmentIndex: 0,
                symmetricKey: dek,
                manifest: downgradeManifest
            )
        }

        // Negative segmentIndex is rejected cleanly without OOB crash
        await #expect(throws: HLSTDFExtractorError.segmentIVNotFound(index: -1)) {
            _ = try await extractor.decryptSegment(
                segmentData: Data(repeating: 0xAA, count: 32),
                segmentIndex: -1,
                symmetricKey: dek,
                manifest: downgradeManifest
            )
        }

        // Tampered policyBinding fails integrity check
        let badBindingManifest = HLSManifest(
            assetID: "a1",
            wrappedKey: "d2s=",
            algorithm: "AES-256-GCM",
            segmentIVs: [iv.base64EncodedString()],
            segmentCount: 1,
            totalDuration: 6.0,
            encryptionMode: "GCM",
            kasURL: URL(string: "https://kas.example.com")!,
            policy: policyBase64,
            policyBindingAlg: "HS256",
            policyBindingHash: Data(repeating: 0x00, count: 32).base64EncodedString()
        )
        await #expect(throws: HLSTDFExtractorError.integrityCheckFailed) {
            _ = try await extractor.decryptSegment(
                segmentData: Data(repeating: 0xAA, count: 32),
                segmentIndex: 0,
                symmetricKey: dek,
                manifest: badBindingManifest
            )
        }

        // Stripping policy fails closed
        let noPolicyManifest = HLSManifest(
            assetID: "a1",
            wrappedKey: "d2s=",
            algorithm: "AES-256-GCM",
            segmentIVs: [iv.base64EncodedString()],
            segmentCount: 1,
            totalDuration: 6.0,
            encryptionMode: "GCM",
            kasURL: URL(string: "https://kas.example.com")!,
            policy: nil,
            policyBindingAlg: nil,
            policyBindingHash: nil
        )
        await #expect(throws: HLSTDFExtractorError.integrityCheckFailed) {
            _ = try await extractor.decryptSegment(
                segmentData: Data(repeating: 0xAA, count: 32),
                segmentIndex: 0,
                symmetricKey: dek,
                manifest: noPolicyManifest
            )
        }

        // CBC segment without integrityInformation fails closed; full HLSTDFPackager -> HLSTDFExtractor CBC round-trip succeeds
        let cbcNoIntegrity = HLSManifest(
            assetID: "a1",
            wrappedKey: "d2s=",
            algorithm: "AES-128-CBC",
            segmentIVs: [Data(repeating: 0x07, count: 16).base64EncodedString()],
            segmentCount: 1,
            totalDuration: 6.0,
            encryptionMode: "CBC",
            kasURL: URL(string: "https://kas.example.com")!,
            policy: policyBase64,
            policyBindingAlg: "HS256",
            policyBindingHash: goodBinding
        )
        await #expect(throws: HLSTDFExtractorError.integrityCheckFailed) {
            _ = try await extractor.decryptSegment(
                segmentData: Data(repeating: 0xBB, count: 32),
                segmentIndex: 0,
                symmetricKey: dek,
                manifest: cbcNoIntegrity
            )
        }

        let kas = try TestKASKeyPair()
        let srcDir = FileManager.default.temporaryDirectory.appendingPathComponent("audit-pkg-src-\(UUID().uuidString)")
        let outDir = FileManager.default.temporaryDirectory.appendingPathComponent("audit-pkg-out-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: srcDir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: srcDir)
            try? FileManager.default.removeItem(at: outDir)
        }
        let segPlaintext = Data("CBC-segment-payload-bytes-authenticated".utf8)
        let segFile = srcDir.appendingPathComponent("seg0.ts")
        try segPlaintext.write(to: segFile)
        let playlistFile = srcDir.appendingPathComponent("playlist.m3u8")
        try "#EXTM3U\n".write(to: playlistFile, atomically: true, encoding: .utf8)
        let convResult = HLSConversionResult(
            playlistURL: playlistFile,
            segmentURLs: [segFile],
            segmentDurations: [6.0],
            totalDuration: 6.0
        )
        let packager = HLSTDFPackager(
            kasURL: URL(string: "https://kas.example.com")!,
            kasPublicKeyPEM: kas.publicKeyPEM,
            keySize: .bits128,
            mode: .cbc
        )
        let packagedTDF = try await packager.package(hlsResult: convResult, assetID: "asset-cbc-rt")
        let local = try await extractor.extract(tdfData: packagedTDF, outputDirectory: outDir)
        let unwrappedKey = try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: kas.privateKeyPEM,
            wrappedKey: local.manifest.wrappedKey
        )
        let encryptedSeg = try Data(contentsOf: local.segmentURLs[0])
        let decryptedSeg = try await extractor.decryptSegment(
            segmentData: encryptedSeg,
            segmentIndex: 0,
            symmetricKey: unwrappedKey,
            manifest: local.manifest
        )
        #expect(decryptedSeg == segPlaintext)

        // Tampering with CBC segment ciphertext is caught by manifest integrityInformation
        var tamperedSeg = encryptedSeg
        tamperedSeg[0] ^= 0xFF
        await #expect(throws: HLSTDFExtractorError.integrityCheckFailed) {
            _ = try await extractor.decryptSegment(
                segmentData: tamperedSeg,
                segmentIndex: 0,
                symmetricKey: unwrappedKey,
                manifest: local.manifest
            )
        }
    }

    @Test("HLSPlaylistGenerator prevents tag injection, omits PII/session IDs, matches delegate URI parser, and guards huge finite durations")
    func playlistGeneratorAndConverterHardening() async throws {
        let gen = HLSPlaylistGenerator(
            kasBaseURL: URL(string: "https://kas.example.com")!,
            cdnBaseURL: URL(string: "https://cdn.example.com")!
        )

        let injectedMaster = gen.generateMasterPlaylist(variants: [
            PlaylistVariant(
                bandwidth: 1_000_000,
                resolution: "1920x1080\n#EXT-X-KEY:METHOD=NONE",
                playlistURL: URL(string: "https://cdn.example.com/v.m3u8")!
            ),
        ])
        #expect(!injectedMaster.contains("#EXT-X-KEY:METHOD=NONE"))
        #expect(!injectedMaster.contains("RESOLUTION="))

        let sessionID = UUID()
        let gcmSegment = SegmentMetadata(
            index: 0,
            duration: .greatestFiniteMagnitude, // Huge finite duration must not trap in Int(ceil(...))
            url: URL(string: "https://cdn.example.com/seg0.tdf")!,
            tdfManifest: "bQ==",
            iv: Data(repeating: 0xAA, count: 12), // 12-byte GCM nonce must not emit broken METHOD=AES-128
            assetID: "asset-1"
        )
        let cbcSegment = SegmentMetadata(
            index: 1,
            duration: 6.0,
            url: URL(string: "https://cdn.example.com/seg1.tdf")!,
            tdfManifest: "bQ==",
            iv: Data(repeating: 0xBB, count: 16),
            assetID: "asset-1"
        )
        let variantPlaylist = gen.generateVariantPlaylist(
            segments: [gcmSegment, cbcSegment],
            assetID: "asset-1",
            userID: "sensitive-user@example.com",
            sessionID: sessionID,
            variant: PlaylistVariant(bandwidth: 1_000_000, resolution: "1280x720", playlistURL: URL(string: "https://cdn.example.com/v.m3u8")!)
        )
        #expect(!variantPlaylist.contains("sensitive-user"))
        #expect(!variantPlaylist.contains(sessionID.uuidString))
        // Only the 16-byte IV segment gets #EXT-X-KEY:METHOD=AES-128, and its URI parses cleanly in StandardTDFContentKeyDelegate
        let keyLines = variantPlaylist.components(separatedBy: "\n").filter { $0.hasPrefix("#EXT-X-KEY:") }
        #expect(keyLines.count == 1)
        #expect(keyLines[0].contains("IV=0x" + String(repeating: "bb", count: 16)))
        #if canImport(UIKit) || canImport(AppKit)
        if #available(iOS 18.0, macOS 15.0, tvOS 18.0, *) {
            let uriStart = try #require(keyLines[0].range(of: "URI=\"")?.upperBound)
            let uriEnd = try #require(keyLines[0][uriStart...].firstIndex(of: "\""))
            let emittedURI = String(keyLines[0][uriStart ..< uriEnd])
            let parsed = try StandardTDFContentKeyDelegate.parseKeyRequestURI(emittedURI)
            #expect(parsed.assetID == "asset-1")
            #expect(parsed.segmentIndex == 1)
            #expect(parsed.userID == nil)
        }
        #endif

        let converter = HLSConverter()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("audit-conv-\(UUID().uuidString)")
        for badDuration in [0.0, .infinity, Double(Int.max)] {
            await #expect(throws: HLSConversionError.self) {
                _ = try await converter.convert(
                    videoURL: URL(fileURLWithPath: "/nonexistent.mov"),
                    outputDirectory: tmp,
                    segmentDuration: badDuration
                )
            }
        }
    }
}
