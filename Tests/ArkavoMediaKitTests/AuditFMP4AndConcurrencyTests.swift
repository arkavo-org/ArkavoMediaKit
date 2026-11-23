import AVFoundation
import CoreMedia
import CryptoKit
import Foundation
import Network
import Synchronization
import Testing
@testable import ArkavoMediaKit

// MARK: - URLProtocol for Concurrency & Actor Isolation Tests

private final class UncheckedSendableBox<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}

private final class ConcurrencyStubURLProtocol: URLProtocol {
    typealias Handler = @Sendable (URLRequest, Data?) async throws -> (HTTPURLResponse, Data)
    private static let handlers = Mutex<[String: Handler]>([:])

    static func register(host: String, handler: @escaping Handler) {
        handlers.withLock { $0[host] = handler }
    }

    static func unregister(host: String) {
        handlers.withLock { _ = $0.removeValue(forKey: host) }
    }

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ConcurrencyStubURLProtocol.self]
        return URLSession(configuration: config, delegate: RedirectRefusal(), delegateQueue: nil)
    }

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url,
              let host = url.host,
              let handler = Self.handlers.withLock({ $0[host] })
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            return
        }
        let capturedRequest = request
        let body = readBody(of: request)
        let protocolBox = UncheckedSendableBox(self)
        Task {
            let proto = protocolBox.value
            do {
                let (response, data) = try await handler(capturedRequest, body)
                proto.client?.urlProtocol(proto, didReceive: response, cacheStoragePolicy: .notAllowed)
                proto.client?.urlProtocol(proto, didLoad: data)
                proto.client?.urlProtocolDidFinishLoading(proto)
            } catch {
                proto.client?.urlProtocol(proto, didFailWithError: error)
            }
        }
    }

    override func stopLoading() {}

    private func readBody(of request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buffer, maxLength: buffer.count)
            if n <= 0 { break }
            data.append(buffer, count: n)
        }
        return data
    }
}

@Suite("Audit: CBCS, fMP4, Concurrency & TestVideoGenerator")
struct AuditFMP4AndConcurrencyTests {
    // MARK: - CBCSEncryptor HKDF, UInt16 splitting, 0:0 pattern & Data slices

    @Test("CBCSEncryptor.deriveKey uses HKDF-SHA256 (not XOR) and works on non-zero Data.startIndex slices")
    func cbcsHKDFAndSlices() {
        let masterBuffer = Data([0x99, 0x88]) + Data(repeating: 0x34, count: 16)
        let keyIDBuffer = Data([0x77, 0x66, 0x55]) + Data(repeating: 0x12, count: 16)
        let masterSlice = masterBuffer.dropFirst(2)
        let keyIDSlice = keyIDBuffer.dropFirst(3)
        #expect(masterSlice.startIndex == 2)
        #expect(keyIDSlice.startIndex == 3)

        let derivedFromSlice = CBCSEncryptor.deriveKey(from: keyIDSlice, using: masterSlice)
        let derivedFromFresh = CBCSEncryptor.deriveKey(from: Data(keyIDSlice), using: Data(masterSlice))
        #expect(derivedFromSlice.count == 16)
        #expect(derivedFromSlice == derivedFromFresh)

        // Must NOT equal plaintext XOR (0x34 ^ 0x12 == 0x26)
        let xorResult = Data(repeating: 0x34 ^ 0x12, count: 16)
        #expect(derivedFromSlice != xorResult)

        // Matches HKDF-SHA256 directly
        let expected = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(masterSlice)),
            salt: Data(keyIDSlice),
            info: Data("arkavo-cbcs-key-v1".utf8),
            outputByteCount: 16
        ).withUnsafeBytes { Data($0) }
        #expect(derivedFromSlice == expected)
    }

    @Test("CBCSEncryptor splits clear NALs > 65,535 bytes without UInt16 overflow and handles 0:0 pattern & Data slices")
    func cbcsLargeClearNALPattern00AndSlices() throws {
        let key = Data(repeating: 0x3C, count: 16)
        let iv = Data((0x10 ... 0x1F).map { UInt8($0) })
        let sliceHeaders = try H264TestStream.sliceHeaders()

        // 1. Non-slice SEI NAL of 70,000 bytes (> UInt16.max = 65,535) must split cleanly without trapping
        let seiLength: UInt32 = 70_000
        var largeSample = Data()
        withUnsafeBytes(of: seiLength.bigEndian) { largeSample.append(contentsOf: $0) }
        largeSample.append(0x06) // SEI NAL (non-slice)
        largeSample.append(Data(repeating: 0x55, count: Int(seiLength) - 1))

        // Wrap with non-zero startIndex slice
        let prefixed = Data([0xDE, 0xAD, 0xBE, 0xEF]) + largeSample
        let sampleSlice = prefixed.dropFirst(4)
        #expect(sampleSlice.startIndex == 4)

        let encryptor = CBCSEncryptor(key: key, iv: iv, cryptBlocks: 1, skipBlocks: 9)
        let result = try encryptor.encryptVideoSample(sampleSlice, nalLengthSize: 4, sliceHeaders: sliceHeaders)
        #expect(result.encryptedData == largeSample)
        #expect(result.subsamples.count == 2)
        #expect(result.subsamples[0] == SubsampleEntry(bytesOfClearData: 65_535, bytesOfProtectedData: 0))
        #expect(result.subsamples[1] == SubsampleEntry(bytesOfClearData: 4_469, bytesOfProtectedData: 0))
        let total = result.subsamples.reduce(0) { $0 + Int($1.bytesOfClearData) + Int($1.bytesOfProtectedData) }
        #expect(total == largeSample.count)

        // 2. Pattern 0:0 encrypts all complete blocks without % 0 crash
        let fullBlockEncryptor = CBCSEncryptor(key: key, iv: iv, cryptBlocks: 0, skipBlocks: 0)
        var idrSample = Data()
        let slice = H264TestStream.slice(isIDR: true, count: 160, filler: 0xAA)
        let sliceLen = UInt32(slice.count)
        withUnsafeBytes(of: sliceLen.bigEndian) { idrSample.append(contentsOf: $0) }
        idrSample.append(slice)

        let res00 = try fullBlockEncryptor.encryptVideoSample(idrSample, nalLengthSize: 4, sliceHeaders: sliceHeaders)
        let clearBytes = 4 + H264TestStream.headerSize(isIDR: true)
        let protected00 = res00.encryptedData.dropFirst(clearBytes)
        // With 0:0, BOTH block 0 and block 1 must be encrypted (whereas 1:9 leaves block 1 plaintext)
        #expect(protected00.prefix(16) != Data(repeating: 0xAA, count: 16))
        #expect(protected00.dropFirst(16).prefix(16) != Data(repeating: 0xAA, count: 16))

        // 3. Invalid nalLengthSize (0, 3) and 0-length NAL throw malformedSample
        #expect(throws: CBCSEncryptor.Failure.malformedSample) {
            _ = try encryptor.encryptVideoSample(idrSample, nalLengthSize: 0, sliceHeaders: sliceHeaders)
        }
        #expect(throws: CBCSEncryptor.Failure.malformedSample) {
            _ = try encryptor.encryptVideoSample(idrSample, nalLengthSize: 3, sliceHeaders: sliceHeaders)
        }
        let zeroLengthNAL = Data([0x00, 0x00, 0x00, 0x00, 0x67, 0x00])
        #expect(throws: CBCSEncryptor.Failure.malformedSample) {
            _ = try encryptor.encryptVideoSample(zeroLengthNAL, nalLengthSize: 4, sliceHeaders: sliceHeaders)
        }

        // 4. AVCDecoderConfigurationRecord handles non-zero startIndex SPS slice safely
        let spsSlice = (Data([0xFF, 0xFF]) + H264TestStream.sps).dropFirst(2)
        #expect(spsSlice.startIndex == 2)
        let avcC = AVCDecoderConfigurationRecord(sps: [spsSlice], pps: [H264TestStream.pps])
        #expect(avcC.profileIndication == H264TestStream.sps[1])
    }

    // MARK: - FMP4RecordingProtectionService CMBlockBuffer, CMTime & ES_Descriptor

    @Test("FMP4RecordingProtectionService.copyBlockBufferData reads non-contiguous multi-chunk CMBlockBuffer intact")
    func nonContiguousBlockBufferCopy() throws {
        var container: CMBlockBuffer?
        let statusCreate = CMBlockBufferCreateEmpty(
            allocator: kCFAllocatorDefault,
            capacity: 2,
            flags: 0,
            blockBufferOut: &container
        )
        #expect(statusCreate == kCMBlockBufferNoErr)
        let block = try #require(container)

        let chunk1Bytes: [UInt8] = Array(repeating: 0x11, count: 64)
        let chunk2Bytes: [UInt8] = Array(repeating: 0x22, count: 96)

        for chunk in [chunk1Bytes, chunk2Bytes] {
            var subBlock: CMBlockBuffer?
            let s1 = CMBlockBufferCreateWithMemoryBlock(
                allocator: kCFAllocatorDefault,
                memoryBlock: nil,
                blockLength: chunk.count,
                blockAllocator: kCFAllocatorDefault,
                customBlockSource: nil,
                offsetToData: 0,
                dataLength: chunk.count,
                flags: kCMBlockBufferAssureMemoryNowFlag,
                blockBufferOut: &subBlock
            )
            #expect(s1 == kCMBlockBufferNoErr)
            let sub = try #require(subBlock)
            let s2 = chunk.withUnsafeBytes { ptr in
                CMBlockBufferReplaceDataBytes(
                    with: ptr.baseAddress!,
                    blockBuffer: sub,
                    offsetIntoDestination: 0,
                    dataLength: chunk.count
                )
            }
            #expect(s2 == kCMBlockBufferNoErr)
            let s3 = CMBlockBufferAppendBufferReference(
                block,
                targetBBuf: sub,
                offsetToData: 0,
                dataLength: chunk.count,
                flags: 0
            )
            #expect(s3 == kCMBlockBufferNoErr)
        }

        // Verify the buffer really is non-contiguous, and copyBlockBufferData returns the exact 160 bytes
        #expect(!CMBlockBufferIsRangeContiguous(block, atOffset: 0, length: 0))
        let copied = try FMP4RecordingProtectionService.copyBlockBufferData(block)
        #expect(copied == Data(chunk1Bytes) + Data(chunk2Bytes))
    }

    @Test("FMP4RecordingProtectionService handles invalid/indefinite CMTime and bad track dimensions safely")
    func invalidCMTimeAndDimensions() throws {
        #expect(throws: FMP4ProtectionError.self) {
            _ = try FMP4RecordingProtectionService.sampleDuration(from: .invalid, timescale: 90_000)
        }
        #expect(throws: FMP4ProtectionError.self) {
            _ = try FMP4RecordingProtectionService.sampleDuration(from: .indefinite, timescale: 90_000)
        }
        #expect(throws: FMP4ProtectionError.self) {
            _ = try FMP4RecordingProtectionService.sampleDuration(
                from: CMTime(value: -10, timescale: 90_000),
                timescale: 90_000
            )
        }
        #expect(try FMP4RecordingProtectionService.sampleDuration(
            from: CMTime(value: 1, timescale: 30),
            timescale: 90_000
        ) == 3000)

        // CMTime.indefinite has isValid == true and timescale == 0; compositionTimeOffset must not divide by zero
        #expect(try FMP4RecordingProtectionService.compositionTimeOffset(
            pts: .indefinite, dts: .indefinite, timescale: 90_000
        ) == 0)
        #expect(try FMP4RecordingProtectionService.compositionTimeOffset(
            pts: .invalid, dts: CMTime(value: 0, timescale: 90_000), timescale: 90_000
        ) == 0)
        #expect(try FMP4RecordingProtectionService.compositionTimeOffset(
            pts: CMTime(value: 6000, timescale: 90_000),
            dts: CMTime(value: 3000, timescale: 90_000),
            timescale: 90_000
        ) == 3000)

        // Invalid dimensions & timescale rejected instead of trapping
        #expect(throws: FMP4ProtectionError.self) {
            _ = try FMP4RecordingProtectionService.validateDimensions(CGSize(width: -1, height: 720))
        }
        #expect(throws: FMP4ProtectionError.self) {
            _ = try FMP4RecordingProtectionService.validateDimensions(CGSize(width: 70_000, height: 720))
        }
        #expect(throws: FMP4ProtectionError.self) {
            _ = try FMP4RecordingProtectionService.validateTimescale(0)
        }
    }

    @Test("ES_Descriptor parser respects ISO/IEC 14496-1 URL_Flag (0x40) before OCRstreamFlag (0x20) order")
    func esDescriptorURLAndOCRFlagOrder() {
        // Build an ES_Descriptor with BOTH URL_Flag (0x40) and OCRstreamFlag (0x20) set:
        // ES_ID (2B) | flags (0x60) | URLlength (3) | "abc" (3B) | OCR_ES_Id (2B) | DecoderConfigDescriptor -> ASC [0x11, 0x90]
        let asc: [UInt8] = [0x11, 0x90]
        let decSpecificInfo: [UInt8] = [0x05, UInt8(asc.count)] + asc
        let decoderConfigBody: [UInt8] = [
            0x40, 0x15, 0x00, 0x00, 0x00, // objectType, streamType, bufferSizeDB
            0x00, 0x01, 0xF4, 0x00,       // maxBitrate
            0x00, 0x01, 0xF4, 0x00,       // avgBitrate
        ] + decSpecificInfo
        let decoderConfig: [UInt8] = [0x04, UInt8(decoderConfigBody.count)] + decoderConfigBody
        let urlBytes: [UInt8] = [UInt8(ascii: "a"), UInt8(ascii: "b"), UInt8(ascii: "c")]
        let esBody: [UInt8] = [
            0x00, 0x01,                   // ES_ID
            0x60,                         // URL_Flag (0x40) | OCRstreamFlag (0x20)
            UInt8(urlBytes.count),        // URLlength = 3
        ] + urlBytes + [
            0x00, 0x02,                   // OCR_ES_Id (2 bytes, AFTER URL per ISO 14496-1 §7.2.6.5)
        ] + decoderConfig
        let esDescriptor: [UInt8] = [0x03, UInt8(esBody.count)] + esBody

        let parsed = FMP4RecordingProtectionService.audioSpecificConfig(fromMagicCookie: esDescriptor)
        #expect(parsed == Data(asc))
    }

    @Test("ISO BMFF boxes and FMP4HLSGenerator handle edge cases cleanly")
    func isoBoxesAndFMP4HLSFixes() throws {
        // TrackRunBox checks ALL samples, not just first
        let trun = TrackRunBox(samples: [
            TrackRunSample(duration: 3000, size: 100, flags: TrackRunSample.syncSample, compositionTimeOffset: nil),
            TrackRunSample(duration: 3000, size: 100, flags: TrackRunSample.nonSyncSample, compositionTimeOffset: -1000),
        ])
        #expect(trun.version == 1)
        #expect((trun.flags & TrackRunBox.sampleCompositionTimeOffsetsPresent) != 0)

        // TrackEncryptionBox omits constant IV when defaultIsProtected == 0
        let unprotectedTenc = TrackEncryptionBox(
            defaultIsProtected: 0,
            defaultPerSampleIVSize: 0,
            defaultKID: Data(count: 16),
            defaultConstantIV: Data(repeating: 0xAA, count: 16)
        )
        #expect(unprotectedTenc.serializePayload().count == 4 + 20, "Constant IV must not be written when defaultIsProtected == 0")

        // SampleAuxiliaryInfoOffsetsBox auto-upgrades to version 1 for 64-bit offsets
        let saio = SampleAuxiliaryInfoOffsetsBox(offsets: [UInt64(UInt32.max) + 100])
        #expect(saio.version == 1)
        _ = saio.serialize()

        // MediaHeaderBox packLanguage does not trap on digits/punctuation/non-ASCII
        let mdhd = MediaHeaderBox(timescale: 90_000, language: "1! ")
        #expect(mdhd.language == 0x55C4)

        // AACSampleEntry writes 0 for 96 kHz per ISO/IEC 14496-12 §12.2.3 (exact rate in esds AudioSpecificConfig)
        let aac = AACSampleEntry(
            channelCount: 2,
            sampleRate: 96_000,
            esds: ElementaryStreamDescriptor(audioSpecificConfig: Data([0x11, 0x90]))
        )
        let payload = aac.serializePayload()
        let rateField = UInt32(bigEndianData: payload.subdata(in: 24 ..< 28)) >> 16
        #expect(rateField == 0)

        // ISOBox.headerSize switches from 8 bytes to 16 bytes for >4 GiB boxes (matching ISOBox.serialize)
        #expect(ContainerBox.headerSize(forPayloadSize: UInt64(UInt32.max) - 8) == 8)
        #expect(ContainerBox.headerSize(forPayloadSize: UInt64(UInt32.max) - 7) == 16)

        // FMP4HLSGenerator sanitizes quotes/newlines and omits non-16-byte IVs
        let hls = FMP4HLSGenerator(
            config: .init(targetDuration: 6, initSegmentURI: "init.mp4\"\n#EXT-X-KEY:METHOD=NONE"),
            encryption: .init(keyURI: "skd://id\"\r\n#INJECT", keyID: Data(count: 16), iv: Data(count: 12))
        )
        let playlist = hls.generateMediaPlaylist(segments: [
            .init(uri: "seg0.m4s\n#EXT-X-DISCONTINUITY", duration: 6.0),
        ])
        let playlistLines = playlist.components(separatedBy: "\n")
        #expect(!playlistLines.contains { $0.hasPrefix("#EXT-X-KEY:METHOD=NONE") })
        #expect(!playlistLines.contains { $0.hasPrefix("#INJECT") })
        #expect(!playlistLines.contains("#EXT-X-DISCONTINUITY"))
        // Quotes were stripped so URI attributes cannot break out of quotes
        let mapLine = try #require(playlistLines.first { $0.hasPrefix("#EXT-X-MAP:") })
        #expect(mapLine.filter { $0 == "\"" }.count == 2)
        #expect(!playlist.contains("IV=0x"), "Non-16-byte IV must be omitted")
    }

    // MARK: - MediaSessionManager, FairPlayKeyClient, FMP4ContentKeyDelegate & TDFManifestBuilder Concurrency

    @Test("MediaSessionManager prevents actor-reentrancy session resurrection and preserves concurrent updateState")
    func mediaSessionManagerActorReentrancy() async throws {
        let host = "msm-\(UUID().uuidString.lowercased()).example.com"
        let heartbeatEntered = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let heartbeatRelease = Mutex<CheckedContinuation<Void, Never>?>(nil)

        ConcurrencyStubURLProtocol.register(host: host) { req, _ in
            let url = req.url!
            if url.path.hasSuffix("/session/start") {
                let body = Data(#"{"sessionId":"sess-reentrancy-1","status":"active"}"#.utf8)
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, body)
            }
            if url.path.hasSuffix("/heartbeat") {
                heartbeatEntered.withLock { $0.take() }?.resume()
                await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                    heartbeatRelease.withLock { $0 = cont }
                }
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, Data())
            }
            // DELETE session returns 500 to also test local cleanup on failed server endSession
            let resp = HTTPURLResponse(url: url, statusCode: 500, httpVersion: "HTTP/1.1", headerFields: nil)!
            return (resp, Data())
        }
        defer { ConcurrencyStubURLProtocol.unregister(host: host) }

        let config = try DRMConfiguration(
            serverURL: URL(string: "https://\(host)")!,
            fpsCertificateData: Data([0x30]),
            heartbeatInterval: 60,
            sessionTimeout: 300
        )
        let client = MediaServerClient(configuration: config, session: ConcurrencyStubURLProtocol.session())
        let manager = MediaSessionManager(configuration: config, client: client)

        let sid = try await manager.startSession(userID: "alice", assetID: "asset-1")
        #expect(await manager.activeSessionCount == 1)

        // 1. Start heartbeat, pause mid-flight, updateState concurrently, resume heartbeat -> state preserved!
        let hbTask1 = Task { await manager.sendHeartbeats() }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            heartbeatEntered.withLock { $0 = cont }
        }
        await manager.updateState(sessionId: sid, state: .paused, position: 42.5)
        heartbeatRelease.withLock { $0.take() }?.resume()
        await hbTask1.value

        let afterUpdate = await manager.session(for: sid)
        #expect(afterUpdate?.state == .paused, "Concurrent updateState must not be clobbered by stale heartbeat snapshot")
        #expect(afterUpdate?.position == 42.5)

        // 2. Start heartbeat, pause mid-flight, endSession concurrently (even with 500 from server!) -> NOT resurrected!
        let hbTask2 = Task { await manager.sendHeartbeats() }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            heartbeatEntered.withLock { $0 = cont }
        }
        await #expect(throws: MediaServerError.self) {
            try await manager.endSession(sessionId: sid)
        }
        // Session removed locally despite 500
        #expect(await manager.activeSessionCount == 0)
        // Release in-flight heartbeat -> must NOT resurrect the ended session!
        heartbeatRelease.withLock { $0.take() }?.resume()
        await hbTask2.value
        #expect(await manager.activeSessionCount == 0, "In-flight heartbeat must not resurrect ended session")

        // 3. Ending unknown non-UUID session throws sessionNotFoundWithID (not random UUID)
        await #expect(throws: SessionError.self) {
            try await manager.endSession(sessionId: "not-a-uuid")
        }

        // 4. endAllSessions() does not stop heartbeat when a new session starts concurrently
        let endAllHost = "msm-endall-\(UUID().uuidString.lowercased()).example.com"
        let startSeq = Mutex(0)
        let deleteSeq = Mutex(0)
        let deleteEntered = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let deleteRelease = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let hbAfterEndAll = Mutex<CheckedContinuation<Void, Never>?>(nil)

        ConcurrencyStubURLProtocol.register(host: endAllHost) { req, _ in
            let url = req.url!
            if url.path.hasSuffix("/session/start") {
                let n = startSeq.withLock { $0 += 1; return $0 }
                let body = Data(#"{"sessionId":"sess-endall-\#(n)","status":"active"}"#.utf8)
                return (HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!, body)
            }
            if req.httpMethod == "DELETE" {
                let d = deleteSeq.withLock { $0 += 1; return $0 }
                if d == 1 {
                    deleteEntered.withLock { $0.take() }?.resume()
                    await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                        deleteRelease.withLock { $0 = cont }
                    }
                }
                return (HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!, Data())
            }
            if url.path.hasSuffix("/heartbeat") {
                hbAfterEndAll.withLock { $0.take() }?.resume()
                return (HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!, Data())
            }
            return (HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!, Data())
        }
        defer { ConcurrencyStubURLProtocol.unregister(host: endAllHost) }

        let fastConfig = try DRMConfiguration(
            serverURL: URL(string: "https://\(endAllHost)")!,
            fpsCertificateData: Data([0x30]),
            heartbeatInterval: 0.05,
            sessionTimeout: 300
        )
        let fastManager = MediaSessionManager(
            configuration: fastConfig,
            client: MediaServerClient(configuration: fastConfig, session: ConcurrencyStubURLProtocol.session())
        )
        _ = try await fastManager.startSession(userID: "alice", assetID: "a1")
        let endAllTask = Task { await fastManager.endAllSessions() }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            deleteEntered.withLock { $0 = cont }
        }
        // Start a brand-new session while endAllSessions is suspended in DELETE
        let sNew = try await fastManager.startSession(userID: "alice", assetID: "a2")
        deleteRelease.withLock { $0.take() }?.resume()
        await endAllTask.value

        #expect(await fastManager.activeSessionCount == 1)
        #expect(await fastManager.session(for: sNew) != nil)
        // Heartbeat task for sNew must still be running and fire promptly
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            hbAfterEndAll.withLock { $0 = cont }
        }
        await fastManager.endAllSessions()
    }

    @Test("FairPlayKeyClient endSession never clears a newer session started concurrently, and rejects empty cert/CKC")
    func fairPlayKeyClientConcurrencyAndEmptyResponses() async throws {
        let host = "fp-\(UUID().uuidString.lowercased()).example.com"
        let startCount = Mutex(0)
        let deleteEntered = Mutex<CheckedContinuation<Void, Never>?>(nil)
        let deleteRelease = Mutex<CheckedContinuation<Void, Never>?>(nil)

        ConcurrencyStubURLProtocol.register(host: host) { req, _ in
            let url = req.url!
            if url.path.hasSuffix("/certificate") {
                // Empty certificate body must be rejected and not cached
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, Data())
            }
            if url.path.hasSuffix("/session/start") {
                let n = startCount.withLock { $0 += 1; return $0 }
                let body = Data(#"{"sessionId":"fp-sess-\#(n)"}"#.utf8)
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, body)
            }
            if url.path.hasSuffix("/key-request") {
                // Empty wrappedKey must be rejected
                let body = Data(#"{"wrappedKey":""}"#.utf8)
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, body)
            }
            if req.httpMethod == "DELETE" {
                deleteEntered.withLock { $0.take() }?.resume()
                await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                    deleteRelease.withLock { $0 = cont }
                }
                let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, Data())
            }
            let resp = HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!
            return (resp, Data())
        }
        defer { ConcurrencyStubURLProtocol.unregister(host: host) }

        let client = FairPlayKeyClient(
            serverURL: URL(string: "https://\(host)")!,
            authToken: "tok",
            urlSession: ConcurrencyStubURLProtocol.session()
        )

        // Empty certificate is rejected
        await #expect(throws: FairPlayKeyClient.FairPlayKeyError.certificateFetchFailed) {
            _ = try await client.fetchCertificate()
        }

        // Start session 1
        let s1 = try await client.startSession(userId: "alice", assetId: "a1")
        #expect(s1.sessionId == "fp-sess-1")

        // Empty CKC is rejected
        await #expect(throws: FairPlayKeyClient.FairPlayKeyError.invalidCKCResponse) {
            _ = try await client.requestCKC(spcData: Data([1, 2, 3]), tdfManifest: Data("{}".utf8))
        }

        // Begin ending session 1, concurrently start session 2, then finish ending session 1 -> session 2 survives!
        let endTask = Task { try await client.endSession() }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            deleteEntered.withLock { $0 = cont }
        }
        let s2 = try await client.startSession(userId: "alice", assetId: "a2")
        #expect(s2.sessionId == "fp-sess-2")
        deleteRelease.withLock { $0.take() }?.resume()
        try await endTask.value

        #expect(client.activeSession?.sessionId == "fp-sess-2", "endSession must not clear a newly started session")

        // Verify FMP4ContentKeyDelegate & TDFManifestBuilder Sendable safety under concurrent access
        let kas = try TestKASKeyPair()
        let builder = TDFManifestBuilder(kasURL: URL(string: "https://\(host)")!)
        let pubKey = try builder.publicKey(fromPEM: kas.spkiPublicKeyPEM)
        let validPolicy = Data(#"{"uuid":"6a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d","body":{}}"#.utf8)

        // TDFManifestBuilder rejects invalid IV length and malformed policyJSON
        #expect(throws: TDFManifestBuilder.TDFError.invalidIVSize) {
            _ = try builder.buildManifest(
                contentKey: Data(repeating: 1, count: 16),
                iv: Data(repeating: 2, count: 12),
                policyJSON: validPolicy,
                publicKey: pubKey
            )
        }
        #expect(throws: (any Error).self) {
            _ = try builder.buildManifest(
                contentKey: Data(repeating: 1, count: 16),
                iv: Data(repeating: 2, count: 16),
                policyJSON: Data("not json".utf8),
                publicKey: pubKey
            )
        }
    }

    @available(*, deprecated, message: "Regression test for deprecated FMP4ContentKeyDelegate thread-safety")
    @Test("FMP4ContentKeyDelegate keyConfig access is synchronized under concurrent mutation")
    func fmp4ContentKeyDelegateConcurrency() async {
        let client = FairPlayKeyClient(
            serverURL: URL(string: "https://fp.example.com")!,
            authToken: "tok"
        )
        let delegate = FMP4ContentKeyDelegate(keyClient: client)
        await withTaskGroup(of: Void.self) { group in
            for i in 0 ..< 20 {
                group.addTask {
                    delegate.setKeyConfig(.init(
                        contentKey: Data(repeating: UInt8(i), count: 16),
                        contentIV: Data(repeating: 0xAA, count: 16),
                        assetId: "asset-\(i)",
                        userId: "user-\(i)"
                    ))
                    _ = delegate.currentKeyConfig
                }
            }
        }
        #expect(delegate.currentKeyConfig != nil)
    }

    // MARK: - TestVideoGenerator loopback-only bind, path-traversal confinement & B2 encryption

    #if os(macOS)
    private static func testVideoGeneratorBinaryURL() -> URL? {
        // Locate built TestVideoGenerator next to the running test bundle in SwiftPM's build directory
        let bundleURL = Bundle(for: AuditBundleLocator.self).bundleURL
        let buildProductsDir = bundleURL.deletingLastPathComponent()
        let candidate = buildProductsDir.appendingPathComponent("TestVideoGenerator")
        if FileManager.default.isExecutableFile(atPath: candidate.path) {
            return candidate
        }
        return nil
    }

    @Test("TestVideoGenerator rejects --port 0, binds loopback-only, confines path traversal/symlinks, and encrypts B2")
    func testVideoGeneratorSecurityAndEncryption() async throws {
        let binary = try #require(
            Self.testVideoGeneratorBinaryURL(),
            "TestVideoGenerator executable must be built alongside tests"
        )

        let rootDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tvg-audit-\(UUID().uuidString)")
        let serveDir = rootDir.appendingPathComponent("served")
        let outsideFile = rootDir.appendingPathComponent("secret.txt")
        let genDir = rootDir.appendingPathComponent("generated")
        try FileManager.default.createDirectory(at: serveDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: rootDir) }

        try Data("TOP-SECRET-OUTSIDE".utf8).write(to: outsideFile)
        try Data("#EXTM3U\n".utf8).write(to: serveDir.appendingPathComponent("playlist.m3u8"))
        try FileManager.default.createSymbolicLink(
            at: serveDir.appendingPathComponent("escape.txt"),
            withDestinationURL: outsideFile
        )

        // 1. --port 0 exits cleanly with non-zero status (no crash / SIGTRAP)
        let portZero = Process()
        portZero.executableURL = binary
        portZero.arguments = ["--serve", serveDir.path, "--port", "0"]
        portZero.standardOutput = FileHandle.nullDevice
        portZero.standardError = FileHandle.nullDevice
        try portZero.run()
        portZero.waitUntilExit()
        #expect(portZero.terminationReason == .exit)
        #expect(portZero.terminationStatus != 0)

        // 2. -s B2 actually CBCS-encrypts segment0.m4s (not plaintext 0xAB filler)
        let genProc = Process()
        genProc.executableURL = binary
        genProc.arguments = ["-o", genDir.path, "-s", "B2", "-d", "1", "-n", "1"]
        genProc.standardOutput = FileHandle.nullDevice
        genProc.standardError = FileHandle.nullDevice
        try genProc.run()
        genProc.waitUntilExit()
        #expect(genProc.terminationStatus == 0)
        let seg0 = try Data(contentsOf: genDir.appendingPathComponent("B2-fairplay/segment0.m4s"))
        #expect(seg0.range(of: Data("senc".utf8)) != nil)
        // First 16 bytes of protected IDR slice must NOT remain unencrypted 0xAB*16
        #expect(seg0.range(of: Data(repeating: 0xAB, count: 160)) == nil, "B2 fixture must actually encrypt slice blocks")

        // 3. --serve binds loopback-only and rejects path traversal, encoded traversal, and symlink escape
        // Pick an ephemeral free port on 127.0.0.1 first
        let port = try pickUnusedLoopbackPort()
        let serverProc = Process()
        serverProc.executableURL = binary
        serverProc.arguments = ["--serve", serveDir.path, "--port", "\(port)"]
        serverProc.standardOutput = FileHandle.nullDevice
        serverProc.standardError = FileHandle.nullDevice
        try serverProc.run()
        defer {
            serverProc.terminate()
            serverProc.waitUntilExit()
        }

        // Wait briefly for listener readiness on 127.0.0.1
        var readyResponse: String?
        for _ in 0 ..< 25 {
            if let resp = try? await sendRawHTTPRequest(port: port, path: "/playlist.m3u8") {
                readyResponse = resp
                break
            }
            try await Task.sleep(for: .milliseconds(50))
        }
        let okResp = try #require(readyResponse, "Server should listen on 127.0.0.1:\(port)")
        #expect(okResp.contains("HTTP/1.1 200 OK"))
        #expect(!okResp.contains("Access-Control-Allow-Origin: *"), "Must not emit wildcard CORS header")

        // Path traversal, percent-encoded traversal, and symlink escape must all be blocked (403)
        for attackPath in ["/../secret.txt", "/%2e%2e/secret.txt", "/escape.txt"] {
            let resp = try await sendRawHTTPRequest(port: port, path: attackPath)
            #expect(resp.contains("HTTP/1.1 403 Forbidden"), "Expected 403 for \(attackPath), got: \(resp)")
            #expect(!resp.contains("TOP-SECRET-OUTSIDE"))
        }
    }

    private func pickUnusedLoopbackPort() throws -> UInt16 {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw URLError(.cannotOpenFile) }
        defer { Darwin.close(fd) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bound = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw URLError(.cannotOpenFile) }

        var actualLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.getsockname(fd, sockPtr, &actualLen)
            }
        }
        return UInt16(bigEndian: addr.sin_port)
    }

    private func sendRawHTTPRequest(port: UInt16, path: String) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let conn = NWConnection(
                host: .ipv4(.loopback),
                port: NWEndpoint.Port(rawValue: port)!,
                using: .tcp
            )
            let queue = DispatchQueue(label: "tvg-test-client-\(UUID().uuidString)")
            let resumed = Mutex(false)
            let finish: @Sendable (Result<String, Error>) -> Void = { result in
                let shouldResume = resumed.withLock { already -> Bool in
                    if already { return false }
                    already = true
                    return true
                }
                if shouldResume {
                    conn.cancel()
                    continuation.resume(with: result)
                }
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    let req = Data("GET \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".utf8)
                    conn.send(content: req, completion: .contentProcessed { sendErr in
                        if let sendErr {
                            finish(.failure(sendErr))
                            return
                        }
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, _, recvErr in
                            if let recvErr {
                                finish(.failure(recvErr))
                                return
                            }
                            let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                            finish(.success(text))
                        }
                    })
                case let .waiting(err):
                    finish(.failure(err))
                case let .failed(err):
                    finish(.failure(err))
                default:
                    break
                }
            }
            conn.start(queue: queue)
        }
    }
    #endif
}

private final class AuditBundleLocator {}
