import AVFoundation
import Foundation

// MARK: - fMP4 Recording Protection Service

/// fMP4-based FairPlay protection service for hardware-enforced DRM streaming
///
/// Uses fMP4 (CMAF) with CBCS encryption for:
/// - True FairPlay hardware-enforced DRM
/// - Screen recording protection (black output on capture)
/// - Per-NAL-unit encryption with 1:9 pattern
/// - HLS Version 7 compatible streaming
public actor FMP4RecordingProtectionService {
    private let kasURL: URL

    /// Initialize with KAS URL for key fetching and wrapping
    /// - Parameter kasURL: KAS server URL (e.g., https://kas.arkavo.net)
    public init(kasURL: URL) {
        self.kasURL = kasURL
    }

    /// Protect video content with fMP4/CBCS encryption for FairPlay streaming
    ///
    /// This produces true FairPlay-compatible content with:
    /// - fMP4 (CMAF) container with encrypted sample entries (encv/enca)
    /// - CBCS 1:9 pattern encryption for video
    /// - HLS playlist with EXT-X-KEY using skd:// URI
    /// - pssh/tenc/sinf boxes for encryption signaling
    ///
    /// - Parameters:
    ///   - videoURL: URL to the source video file
    ///   - assetID: Unique asset identifier for the manifest and skd:// URI
    /// - Returns: TDF ZIP archive data containing manifest, playlist, init.mp4, and encrypted segments
    public func protectVideo(
        videoURL: URL,
        assetID: String
    ) async throws -> Data {
        // Create temporary directory for fMP4 conversion
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }

        // 1. Generate encryption key and IV
        print("🔑 Generating content encryption key...")
        let contentKey = CBCSEncryptor.generateKeyID()  // 16-byte AES-128 key
        let constantIV = CBCSEncryptor.generateIV()     // 16-byte constant IV
        // Use all-zero KID - FairPlay uses Asset ID for key lookup, not KID
        // KID is CENC bookkeeping only; keep stable until playback works
        let keyID = Data(repeating: 0, count: 16)

        // Debug: Log key bytes for verification during playback troubleshooting
        print("🔑 DEBUG contentKey (hex): \(contentKey.map { String(format: "%02x", $0) }.joined())")
        print("🔑 DEBUG constantIV (hex): \(constantIV.map { String(format: "%02x", $0) }.joined())")

        // 2. Fetch KAS public key and wrap content key
        print("🔐 Wrapping content key with KAS public key...")
        let manifestBuilder = TDFManifestBuilder(kasURL: kasURL)
        let manifest = try await manifestBuilder.buildManifest(
            contentKey: contentKey,
            iv: constantIV,
            assetID: assetID
        )
        let manifestData = try manifestBuilder.serializeManifest(manifest)

        // 3. Extract video info from source
        print("🎬 Analyzing source video...")
        let asset = AVURLAsset(url: videoURL)
        let tracks = try await asset.loadTracks(withMediaType: .video)
        guard let videoTrack = tracks.first else {
            throw FMP4ProtectionError.noVideoTrack
        }

        // Get video parameters
        let formatDescriptions = try await videoTrack.load(.formatDescriptions)
        guard let formatDesc = formatDescriptions.first else {
            throw FMP4ProtectionError.noFormatDescription
        }

        let dimensions = try await videoTrack.load(.naturalSize)
        let timescale = try await videoTrack.load(.naturalTimeScale)

        // Extract SPS/PPS and NAL length size from format description
        guard let h264Params = extractParameterSets(from: formatDesc) else {
            throw FMP4ProtectionError.noParameterSets
        }

        // 4. Create FMP4 writer with encryption config
        print("📦 Creating fMP4 writer with CBCS encryption...")
        let trackConfig = FMP4Writer.TrackConfig.h264Video(
            width: UInt16(dimensions.width),
            height: UInt16(dimensions.height),
            timescale: UInt32(timescale),
            sps: h264Params.sps,
            pps: h264Params.pps
        )

        let encryptionConfig = FMP4Writer.EncryptionConfig(
            keyID: keyID,
            constantIV: constantIV
        )

        let writer = FMP4Writer(tracks: [trackConfig], encryption: encryptionConfig)
        let encryptor = CBCSEncryptor(key: contentKey, iv: constantIV)
        let nalLengthSize = h264Params.nalLengthSize

        // 5. Generate init segment
        print("📝 Generating init segment...")
        let initSegment = writer.generateInitSegment()
        let initURL = tempDir.appendingPathComponent("init.mp4")
        try initSegment.write(to: initURL)

        // 6. Read and encrypt samples
        print("🔒 Encrypting video samples...")
        let reader = try AVAssetReader(asset: asset)
        let output = AVAssetReaderTrackOutput(track: videoTrack, outputSettings: nil)
        reader.add(output)
        reader.startReading()

        var samples: [FMP4Writer.Sample] = []
        var totalDuration: UInt64 = 0

        while let sampleBuffer = output.copyNextSampleBuffer() {
            guard let dataBuffer = CMSampleBufferGetDataBuffer(sampleBuffer) else { continue }

            var length: Int = 0
            var dataPointer: UnsafeMutablePointer<Int8>?
            CMBlockBufferGetDataPointer(dataBuffer, atOffset: 0, lengthAtOffsetOut: nil, totalLengthOut: &length, dataPointerOut: &dataPointer)

            guard let pointer = dataPointer else { continue }
            let sampleData = Data(bytes: pointer, count: length)

            // Encrypt the sample using the actual NAL length size from the source video
            let encryptedResult = encryptor.encryptVideoSample(sampleData, nalLengthSize: nalLengthSize)

            // CRITICAL ALIGNMENT CHECK: sum(clear + protected) must equal sample_size
            let originalSize = sampleData.count
            let encryptedSize = encryptedResult.encryptedData.count
            let totalClear = encryptedResult.subsamples.reduce(0) { $0 + Int($1.bytesOfClearData) }
            let totalProtected = encryptedResult.subsamples.reduce(0) { $0 + Int($1.bytesOfProtectedData) }
            let subsampleSum = totalClear + totalProtected

            if samples.count < 5 || subsampleSum != encryptedSize {
                // Log first few samples and any misalignments
                let aligned = subsampleSum == encryptedSize
                let prefix = aligned ? "✅" : "❌ MISMATCH"
                print("\(prefix) [Sample \(samples.count)] Alignment check:")
                print("   Original size: \(originalSize)")
                print("   Encrypted size: \(encryptedSize)")
                print("   Subsamples (\(encryptedResult.subsamples.count)): \(encryptedResult.subsamples.map { "[\($0.bytesOfClearData)c/\($0.bytesOfProtectedData)p]" }.joined(separator: " "))")
                print("   Sum(clear+protected): \(totalClear) + \(totalProtected) = \(subsampleSum)")
                if !aligned {
                    print("   ⚠️ CRITICAL: subsample sum (\(subsampleSum)) != encrypted size (\(encryptedSize))")
                    print("   ⚠️ This WILL cause AVPlayer to fail decryption!")
                }
            }

            // Get timing info
            let duration = CMSampleBufferGetDuration(sampleBuffer)
            let durationValue = UInt32(duration.value * Int64(timescale) / Int64(duration.timescale))

            // Calculate Composition Time Offset (CTS) for B-frame support
            // CTS = PTS - DTS (tells decoder when to display the frame relative to decode time)
            let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
            let dts = CMSampleBufferGetDecodeTimeStamp(sampleBuffer)
            var compositionTimeOffset: Int32 = 0

            // Only calculate CTS if both PTS and DTS are valid
            if pts.isValid && dts.isValid && pts != dts {
                // Convert both timestamps to the output timescale
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

            samples.append(FMP4Writer.Sample(
                data: encryptedResult.encryptedData,
                duration: durationValue,
                isSync: isSync,
                compositionTimeOffset: compositionTimeOffset,
                subsamples: encryptedResult.subsamples
            ))

            totalDuration += UInt64(durationValue)
        }

        // 7. Generate media segments (6 second chunks)
        print("📼 Generating media segments...")
        let segmentDuration: UInt64 = UInt64(6 * timescale)  // 6 seconds
        var segments: [FMP4HLSGenerator.Segment] = []
        var segmentIndex = 0
        var sampleIndex = 0
        var currentSegmentSamples: [FMP4Writer.Sample] = []
        var currentSegmentDuration: UInt64 = 0
        var baseDecodeTime: UInt64 = 0

        while sampleIndex < samples.count {
            let sample = samples[sampleIndex]
            currentSegmentSamples.append(sample)
            currentSegmentDuration += UInt64(sample.duration)
            sampleIndex += 1

            // Check if we should end this segment
            let shouldEndSegment = currentSegmentDuration >= segmentDuration || sampleIndex == samples.count

            if shouldEndSegment && !currentSegmentSamples.isEmpty {
                let segmentData = writer.generateMediaSegment(
                    trackID: 1,
                    samples: currentSegmentSamples,
                    baseDecodeTime: baseDecodeTime
                )

                let segmentFilename = "segment\(segmentIndex).m4s"
                let segmentURL = tempDir.appendingPathComponent(segmentFilename)
                try segmentData.write(to: segmentURL)

                let duration = Double(currentSegmentDuration) / Double(timescale)
                segments.append(FMP4HLSGenerator.Segment(uri: segmentFilename, duration: duration))

                baseDecodeTime += currentSegmentDuration
                currentSegmentSamples = []
                currentSegmentDuration = 0
                segmentIndex += 1
            }
        }

        print("   Created \(segmentIndex) segments")

        // 8. Generate HLS playlist
        print("📋 Generating HLS playlist...")
        let playlistConfig = FMP4HLSGenerator.PlaylistConfig(
            targetDuration: 6,
            playlistType: .vod,
            initSegmentURI: "init.mp4"
        )

        let fairPlayConfig = FMP4HLSGenerator.FairPlayConfig.fairPlay(
            assetID: assetID,
            keyID: keyID,
            iv: constantIV
        )

        let hlsGenerator = FMP4HLSGenerator(config: playlistConfig, encryption: fairPlayConfig)
        let playlist = hlsGenerator.generateMediaPlaylist(segments: segments)

        let playlistURL = tempDir.appendingPathComponent("playlist.m3u8")
        try playlist.write(to: playlistURL, atomically: true, encoding: .utf8)

        // 9. Package into TDF archive (ZIP)
        print("📦 Packaging into TDF archive...")

        // Add fMP4-specific metadata to manifest
        let segmentFilenames = segments.map { $0.uri }
        let enhancedManifestData = try addFMP4Metadata(
            to: manifestData,
            assetID: assetID,
            playlistFilename: "playlist.m3u8",
            initFilename: "init.mp4",
            segmentFilenames: segmentFilenames
        )

        let archive = try createTDFArchive(
            tempDir: tempDir,
            manifestData: enhancedManifestData,
            segments: segments
        )

        print("✅ fMP4 FairPlay protection complete: \(archive.count) bytes")
        return archive
    }

    // MARK: - Private Helpers

    /// Result of extracting H.264 parameters from format description
    private struct H264Parameters {
        let sps: [Data]
        let pps: [Data]
        let nalLengthSize: Int  // 1, 2, or 4 bytes
    }

    private func extractParameterSets(from formatDesc: CMFormatDescription) -> H264Parameters? {
        guard let extensions = CMFormatDescriptionGetExtensions(formatDesc) as? [String: Any],
              let sampleDescriptionExtensions = extensions["SampleDescriptionExtensionAtoms"] as? [String: Any],
              let avcCData = sampleDescriptionExtensions["avcC"] as? Data
        else {
            return nil
        }

        // Parse avcC to extract SPS/PPS and NAL length size
        // Format: configVersion(1) + profile(1) + compatibility(1) + level(1) + lengthSizeMinusOne(1)
        //         + numSPS(1) + [spsLen(2) + sps]* + numPPS(1) + [ppsLen(2) + pps]*
        guard avcCData.count >= 8 else { return nil }

        // Extract NAL length size from byte 4 (lower 2 bits + 1)
        // Values: 0 → 1 byte, 1 → 2 bytes, 3 → 4 bytes
        let lengthSizeMinusOne = Int(avcCData[4] & 0x03)
        let nalLengthSize = lengthSizeMinusOne + 1
        print("📏 NAL length size from avcC: \(nalLengthSize) bytes")

        var sps: [Data] = []
        var pps: [Data] = []
        var offset = 5  // Skip header (configVersion + profile + compatibility + level + lengthSizeMinusOne)

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

    /// Add fMP4-specific metadata to manifest using TDF spec's encryptedMetadata field
    /// The metadata is base64-encoded JSON (unencrypted) per TDF spec allowance
    private func addFMP4Metadata(
        to manifestData: Data,
        assetID: String,
        playlistFilename: String,
        initFilename: String,
        segmentFilenames: [String]
    ) throws -> Data {
        // Parse existing manifest
        guard var manifest = try JSONSerialization.jsonObject(with: manifestData) as? [String: Any] else {
            throw FMP4ProtectionError.manifestParsingFailed
        }

        let protectedAtTimestamp = ISO8601DateFormatter().string(from: Date())

        // Create fMP4 metadata (unencrypted, just base64-encoded)
        let fmp4Meta: [String: Any] = [
            "type": "fmp4-fairplay",
            "assetId": assetID,
            "playlistFilename": playlistFilename,
            "initFilename": initFilename,
            "segmentFilenames": segmentFilenames,
            "encryption": "cbcs-1-9",
            "protectedAt": protectedAtTimestamp
        ]

        // Encode metadata as base64 JSON
        let metadataJSON = try JSONSerialization.data(withJSONObject: fmp4Meta, options: [.sortedKeys])
        let metadataBase64 = metadataJSON.base64EncodedString()

        // Add encryptedMetadata to keyAccess (per TDF spec)
        if var encInfo = manifest["encryptionInformation"] as? [String: Any],
           var keyAccessArray = encInfo["keyAccess"] as? [[String: Any]],
           !keyAccessArray.isEmpty {
            keyAccessArray[0]["encryptedMetadata"] = metadataBase64
            encInfo["keyAccess"] = keyAccessArray
            manifest["encryptionInformation"] = encInfo
        }

        // Add top-level meta section (required by IrohContentService)
        manifest["meta"] = [
            "assetId": assetID,
            "protectedAt": protectedAtTimestamp
        ]

        // Re-serialize
        return try JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys])
    }

    private func createTDFArchive(
        tempDir: URL,
        manifestData: Data,
        segments: [FMP4HLSGenerator.Segment]
    ) throws -> Data {
        // Create ZIP archive manually (simplified implementation)
        var archive = Data()

        // Files to include
        var files: [(name: String, data: Data)] = []

        // Add manifest
        files.append(("manifest.json", manifestData))

        // Add playlist
        let playlistURL = tempDir.appendingPathComponent("playlist.m3u8")
        let playlistData = try Data(contentsOf: playlistURL)
        files.append(("playlist.m3u8", playlistData))

        // Add init segment
        let initURL = tempDir.appendingPathComponent("init.mp4")
        let initData = try Data(contentsOf: initURL)
        files.append(("init.mp4", initData))

        // Add media segments
        for segment in segments {
            let segmentURL = tempDir.appendingPathComponent(segment.uri)
            let segmentData = try Data(contentsOf: segmentURL)
            files.append((segment.uri, segmentData))
        }

        // Simple ZIP creation (no compression for media files)
        var centralDirectory = Data()
        var localOffset: UInt32 = 0

        for file in files {
            // Local file header
            var localHeader = Data()
            localHeader.append(contentsOf: [0x50, 0x4B, 0x03, 0x04]) // Signature
            localHeader.append(contentsOf: [0x14, 0x00])            // Version needed (2.0)
            localHeader.append(contentsOf: [0x00, 0x00])            // General purpose bit flag
            localHeader.append(contentsOf: [0x00, 0x00])            // Compression method (store)
            localHeader.append(contentsOf: [0x00, 0x00])            // Last mod time
            localHeader.append(contentsOf: [0x00, 0x00])            // Last mod date

            // CRC-32 (calculated)
            let crc = crc32(file.data)
            localHeader.append(crc.littleEndianData)

            // Compressed size (same as uncompressed for store)
            localHeader.append(UInt32(file.data.count).littleEndianData)

            // Uncompressed size
            localHeader.append(UInt32(file.data.count).littleEndianData)

            // Filename length
            let filenameData = file.name.data(using: .utf8) ?? Data()
            localHeader.append(UInt16(filenameData.count).littleEndianData)

            // Extra field length
            localHeader.append(contentsOf: [0x00, 0x00])

            // Filename
            localHeader.append(filenameData)

            // File data
            archive.append(localHeader)
            archive.append(file.data)

            // Central directory entry
            var cdEntry = Data()
            cdEntry.append(contentsOf: [0x50, 0x4B, 0x01, 0x02]) // Signature
            cdEntry.append(contentsOf: [0x14, 0x00])            // Version made by
            cdEntry.append(contentsOf: [0x14, 0x00])            // Version needed
            cdEntry.append(contentsOf: [0x00, 0x00])            // General purpose bit flag
            cdEntry.append(contentsOf: [0x00, 0x00])            // Compression method
            cdEntry.append(contentsOf: [0x00, 0x00])            // Last mod time
            cdEntry.append(contentsOf: [0x00, 0x00])            // Last mod date
            cdEntry.append(crc.littleEndianData)
            cdEntry.append(UInt32(file.data.count).littleEndianData)
            cdEntry.append(UInt32(file.data.count).littleEndianData)
            cdEntry.append(UInt16(filenameData.count).littleEndianData)
            cdEntry.append(contentsOf: [0x00, 0x00])            // Extra field length
            cdEntry.append(contentsOf: [0x00, 0x00])            // Comment length
            cdEntry.append(contentsOf: [0x00, 0x00])            // Disk number start
            cdEntry.append(contentsOf: [0x00, 0x00])            // Internal file attributes
            cdEntry.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // External file attributes
            cdEntry.append(localOffset.littleEndianData)       // Relative offset
            cdEntry.append(filenameData)

            centralDirectory.append(cdEntry)
            localOffset = UInt32(archive.count)
        }

        let cdOffset = archive.count
        archive.append(centralDirectory)

        // End of central directory
        var eocd = Data()
        eocd.append(contentsOf: [0x50, 0x4B, 0x05, 0x06]) // Signature
        eocd.append(contentsOf: [0x00, 0x00])            // Disk number
        eocd.append(contentsOf: [0x00, 0x00])            // CD start disk
        eocd.append(UInt16(files.count).littleEndianData)
        eocd.append(UInt16(files.count).littleEndianData)
        eocd.append(UInt32(centralDirectory.count).littleEndianData)
        eocd.append(UInt32(cdOffset).littleEndianData)
        eocd.append(contentsOf: [0x00, 0x00])            // Comment length

        archive.append(eocd)

        return archive
    }

    /// Simple CRC-32 implementation
    private func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        let table = makeCRCTable()

        for byte in data {
            let index = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = table[index] ^ (crc >> 8)
        }

        return ~crc
    }

    private func makeCRCTable() -> [UInt32] {
        var table = [UInt32](repeating: 0, count: 256)
        for n in 0..<256 {
            var c = UInt32(n)
            for _ in 0..<8 {
                if c & 1 != 0 {
                    c = 0xEDB88320 ^ (c >> 1)
                } else {
                    c >>= 1
                }
            }
            table[n] = c
        }
        return table
    }
}

// MARK: - Extension for little-endian data

private extension UInt16 {
    var littleEndianData: Data {
        var value = self.littleEndian
        return Data(bytes: &value, count: 2)
    }
}

private extension UInt32 {
    var littleEndianData: Data {
        var value = self.littleEndian
        return Data(bytes: &value, count: 4)
    }
}

// MARK: - Errors

/// fMP4 recording protection errors
public enum FMP4ProtectionError: Error, LocalizedError {
    case noVideoTrack
    case noFormatDescription
    case noParameterSets
    case encodingFailed(String)
    case packagingFailed(String)
    case manifestParsingFailed

    public var errorDescription: String? {
        switch self {
        case .noVideoTrack:
            "No video track found in source"
        case .noFormatDescription:
            "No format description in video track"
        case .noParameterSets:
            "Could not extract SPS/PPS from video"
        case let .encodingFailed(reason):
            "fMP4 encoding failed: \(reason)"
        case let .packagingFailed(reason):
            "TDF packaging failed: \(reason)"
        case .manifestParsingFailed:
            "Failed to parse manifest JSON"
        }
    }
}
