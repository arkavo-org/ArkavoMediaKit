import Foundation
import Testing
@testable import ArkavoMediaKit

// MARK: - Byte-Range Request Handling Tests

/// Tests for validating byte-range request handling in HTTP content servers.
/// These tests verify correct behavior for serving fMP4/HLS content with proper
/// HTTP byte-range semantics required by AVPlayer's HLS/FairPlay pipeline.
@Suite("Byte-Range Request Handling")
struct ByteRangeTests {

    // MARK: - Test Helpers

    /// Simulates HTTP byte-range serving logic for local content servers
    private func serveByteRange(
        fileData: Data,
        requestedOffset: Int,
        requestedLength: Int,
        requestsAllDataToEndOfResource: Bool
    ) -> Data? {
        // Validate offset is within bounds
        guard requestedOffset >= 0, requestedOffset < fileData.count else {
            return nil
        }

        let availableLength = fileData.count - requestedOffset

        // Respect requestsAllDataToEndOfResource flag
        let respondLength: Int
        if requestsAllDataToEndOfResource {
            respondLength = availableLength
        } else {
            respondLength = min(requestedLength, availableLength)
        }

        if respondLength > 0 {
            return fileData.subdata(in: requestedOffset..<(requestedOffset + respondLength))
        }

        return Data()
    }

    // MARK: - Basic Range Tests

    @Test("Full file request returns entire content")
    func fullFileRequest() {
        let fileData = Data(repeating: 0xAB, count: 1000)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 0,
            requestedLength: 1000,
            requestsAllDataToEndOfResource: false
        )

        #expect(result?.count == 1000)
        #expect(result == fileData)
    }

    @Test("Partial range request returns correct slice")
    func partialRangeRequest() {
        var fileData = Data()
        fileData.append(Data(repeating: 0x11, count: 100))  // 0-99
        fileData.append(Data(repeating: 0x22, count: 100))  // 100-199
        fileData.append(Data(repeating: 0x33, count: 100))  // 200-299

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 100,
            requestedLength: 100,
            requestsAllDataToEndOfResource: false
        )

        #expect(result?.count == 100)
        #expect(result == Data(repeating: 0x22, count: 100))
    }

    // MARK: - requestsAllDataToEndOfResource Tests

    @Test("requestsAllDataToEndOfResource returns all remaining data")
    func requestsAllDataToEndOfResource() {
        let fileData = Data(repeating: 0xAB, count: 1000)

        // Request with small length but allToEnd=true
        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 500,
            requestedLength: 1,  // Only requesting 1 byte, but allToEnd=true
            requestsAllDataToEndOfResource: true
        )

        // Should get 500 bytes (all remaining), not 1
        #expect(result?.count == 500)
    }

    @Test("requestsAllDataToEndOfResource from beginning returns entire file")
    func requestsAllDataFromBeginning() {
        let fileData = Data(repeating: 0xCD, count: 2000)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 0,
            requestedLength: 100,  // Small request
            requestsAllDataToEndOfResource: true
        )

        #expect(result?.count == 2000)
    }

    @Test("requestsAllDataToEndOfResource=false respects requestedLength")
    func allToEndFalseRespectsLength() {
        let fileData = Data(repeating: 0xEF, count: 1000)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 0,
            requestedLength: 100,
            requestsAllDataToEndOfResource: false
        )

        #expect(result?.count == 100)
    }

    // MARK: - Edge Case Tests

    @Test("Offset beyond file size returns nil")
    func offsetBeyondFileSize() {
        let fileData = Data(repeating: 0xAB, count: 100)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 100,  // Exactly at end
            requestedLength: 10,
            requestsAllDataToEndOfResource: false
        )

        #expect(result == nil)
    }

    @Test("Offset way beyond file size returns nil")
    func offsetWayBeyondFileSize() {
        let fileData = Data(repeating: 0xAB, count: 100)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 10000,
            requestedLength: 100,
            requestsAllDataToEndOfResource: false
        )

        #expect(result == nil)
    }

    @Test("Negative offset returns nil")
    func negativeOffset() {
        let fileData = Data(repeating: 0xAB, count: 100)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: -1,
            requestedLength: 100,
            requestsAllDataToEndOfResource: false
        )

        #expect(result == nil)
    }

    @Test("Zero length request returns empty data")
    func zeroLengthRequest() {
        let fileData = Data(repeating: 0xAB, count: 100)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 50,
            requestedLength: 0,
            requestsAllDataToEndOfResource: false
        )

        #expect(result?.count == 0)
    }

    @Test("Request length exceeds available data returns only available")
    func requestExceedsAvailable() {
        let fileData = Data(repeating: 0xAB, count: 100)

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 90,
            requestedLength: 100,  // Requesting 100 but only 10 available
            requestsAllDataToEndOfResource: false
        )

        #expect(result?.count == 10)
    }

    // MARK: - Empty File Tests

    @Test("Empty file with zero offset returns nil")
    func emptyFileZeroOffset() {
        let fileData = Data()

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 0,
            requestedLength: 100,
            requestsAllDataToEndOfResource: false
        )

        #expect(result == nil)
    }

    // MARK: - Boundary Tests

    @Test("Last byte request returns single byte")
    func lastByteRequest() {
        var fileData = Data(repeating: 0x00, count: 99)
        fileData.append(0xFF)  // Last byte is 0xFF

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 99,
            requestedLength: 1,
            requestsAllDataToEndOfResource: false
        )

        #expect(result?.count == 1)
        #expect(result?.first == 0xFF)
    }

    @Test("First byte request returns single byte")
    func firstByteRequest() {
        var fileData = Data()
        fileData.append(0xAA)  // First byte is 0xAA
        fileData.append(Data(repeating: 0x00, count: 99))

        let result = serveByteRange(
            fileData: fileData,
            requestedOffset: 0,
            requestedLength: 1,
            requestsAllDataToEndOfResource: false
        )

        #expect(result?.count == 1)
        #expect(result?.first == 0xAA)
    }

    // MARK: - HLS Playlist Simulation Tests

    @Test("HLS playlist byte-range simulation")
    func hlsPlaylistSimulation() {
        // Simulate a typical HLS playlist request pattern
        let playlist = """
        #EXTM3U
        #EXT-X-VERSION:7
        #EXT-X-TARGETDURATION:6
        #EXT-X-MAP:URI="init.mp4"
        #EXTINF:6.0,
        segment0.m4s
        #EXT-X-ENDLIST
        """.data(using: .utf8)!

        // First request: content info only (offset 0, length 2)
        let contentInfoRequest = serveByteRange(
            fileData: playlist,
            requestedOffset: 0,
            requestedLength: 2,
            requestsAllDataToEndOfResource: false
        )
        #expect(contentInfoRequest?.count == 2)

        // Second request: all data
        let fullRequest = serveByteRange(
            fileData: playlist,
            requestedOffset: 0,
            requestedLength: playlist.count,
            requestsAllDataToEndOfResource: true
        )
        #expect(fullRequest == playlist)
    }

    @Test("Init segment byte-range simulation")
    func initSegmentSimulation() {
        // Simulate fMP4 init segment (ftyp + moov)
        var initSegment = Data()

        // ftyp box (20 bytes minimum)
        initSegment.append(contentsOf: [0x00, 0x00, 0x00, 0x14])  // size = 20
        initSegment.append(contentsOf: [0x66, 0x74, 0x79, 0x70])  // "ftyp"
        initSegment.append(contentsOf: [0x69, 0x73, 0x6F, 0x6D])  // "isom"
        initSegment.append(contentsOf: [0x00, 0x00, 0x02, 0x00])  // minor version
        initSegment.append(contentsOf: [0x69, 0x73, 0x6F, 0x6D])  // compatible brand

        // moov box placeholder (100 bytes)
        initSegment.append(contentsOf: [0x00, 0x00, 0x00, 0x64])  // size = 100
        initSegment.append(contentsOf: [0x6D, 0x6F, 0x6F, 0x76])  // "moov"
        initSegment.append(Data(repeating: 0x00, count: 92))

        // Request entire init segment
        let result = serveByteRange(
            fileData: initSegment,
            requestedOffset: 0,
            requestedLength: initSegment.count,
            requestsAllDataToEndOfResource: true
        )

        #expect(result?.count == 120)
        #expect(result == initSegment)
    }
}
