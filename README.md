# ArkavoMediaKit

A Swift package for TDF3-based HLS streaming with DRM protection, providing an open alternative to proprietary DRM systems like FairPlay, Widevine, and PlayReady.

## Overview

ArkavoMediaKit enables:
- **Standard TDF Encryption**: Per-segment encryption using Standard TDF (ZIP-based) format
- **HLS Streaming**: Compatible with standard HLS players via AVFoundation
- **Media DRM Policies**: Rental windows, concurrency limits, geo-restrictions, HDCP
- **Cross-Platform**: iOS 18+, macOS 15+, tvOS 18+

## Architecture

### Components

- **Core**: Session management, key provision, AVContentKeySession integration
- **HLS**: Segment encryption, playlist generation, streaming player
- **Crypto**: TDF3 key wrapping, policy enforcement
- **Models**: Session, segment metadata, key access requests

### How It Works

1. **Content Creation** (macOS):
   - Import video → Segment with AVFoundation
   - Generate unique DEK per segment
   - Encrypt segment with AES-256-GCM
   - Wrap DEK with KAS RSA public key (2048+ bit)
   - Create Standard TDF archive (.tdf ZIP containing manifest.json + encrypted payload)
   - Generate HLS manifest with .tdf segment URLs

2. **Playback** (iOS/macOS/tvOS):
   - AVPlayer requests .tdf segment
   - StandardTDFContentKeyDelegate intercepts key request
   - Downloads .tdf archive and extracts manifest
   - Validates session and policy
   - Requests DEK unwrapping from KAS (RSA rewrap protocol)
   - Returns key to AVPlayer for decryption

## Usage

### Create Encrypted HLS Stream

```swift
import ArkavoMediaKit
import OpenTDFKit

// Setup KAS configuration
let kasURL = URL(string: "https://kas.arkavo.net")!
let kasPublicKeyPEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

let sessionManager = TDF3MediaSession()
let keyProvider = StandardTDFKeyProvider(
    kasURL: kasURL,
    kasPublicKeyPEM: kasPublicKeyPEM,
    sessionManager: sessionManager
)

let policy = MediaDRMPolicy(
    rentalWindow: .init(
        purchaseWindow: 7 * 24 * 3600,  // 7 days
        playbackWindow: 48 * 3600        // 48 hours
    ),
    maxConcurrentStreams: 2
)

// Create Standard TDF policy JSON
let policyJSON = """
{
  "uuid": "policy-12345",
  "body": {
    "dataAttributes": [],
    "dissem": ["user-001"]
  }
}
""".data(using: .utf8)!

// Encrypt segments
let encryptor = HLSSegmentEncryptor(
    kasURL: kasURL,
    kasPublicKeyPEM: kasPublicKeyPEM,
    policy: policy,
    policyJSON: policyJSON
)

let segments: [(Data, Double)] = // ... load video segments (2-10MB each)
let results = try await encryptor.encryptSegments(
    segments: segments,
    assetID: "movie-12345",
    startIndex: 0
)

// Save .tdf archives
for (index, result) in results.enumerated() {
    let tdfURL = outputDir.appendingPathComponent("segment_\(index).tdf")
    try encryptor.saveSegment(tdfData: result.tdfData, to: tdfURL)
}

// Generate playlist (points to .tdf files)
let generator = HLSPlaylistGenerator(
    kasBaseURL: URL(string: "https://kas.arkavo.net")!,
    cdnBaseURL: URL(string: "https://cdn.arkavo.net")!
)

let playlist = generator.generateMediaPlaylist(
    segments: results.map(\.metadata),
    assetID: "movie-12345",
    userID: "user-001",
    sessionID: UUID()
)

try generator.savePlaylist(playlist, to: playlistURL)
```

### Play Encrypted Stream

```swift
import ArkavoMediaKit

// Start session
let session = try await sessionManager.startSession(
    userID: "user-001",
    assetID: "movie-12345",
    policy: policy
)

// Create player
let player = TDF3StreamingPlayer(
    keyProvider: keyProvider,
    policy: policy,
    deviceInfo: DeviceInfo(),
    sessionID: session.sessionID
)

// Load and play
try await player.loadStream(
    url: playlistURL,
    session: session
)

player.play()
```

## Policy Enforcement

```swift
let policy = MediaDRMPolicy(
    rentalWindow: .init(
        purchaseWindow: 7 * 24 * 3600,
        playbackWindow: 48 * 3600
    ),
    maxConcurrentStreams: 2,
    allowedRegions: ["US", "CA", "GB"],
    hdcpLevel: .type1,
    minSecurityLevel: .high,
    allowVirtualMachines: false
)
```

## Integration

### iOS App (Arkavo.xcodeproj)

Add package dependency:
1. File → Add Package Dependencies
2. Enter path: `../ArkavoMediaKit`
3. Add to target: Arkavo

### Arkavo Creator (ArkavoCreator.xcodeproj)

Same steps as iOS app.

## Testing

Run tests:
```bash
swift test
```

Performance benchmarks target <50ms P95 key delivery latency.

## Dependencies

- [OpenTDFKit](https://github.com/arkavo-org/OpenTDFKit) - Standard TDF implementation (ZIP-based archives)
- AVFoundation - Video playback and content key management
- CryptoKit - AES-256-GCM encryption and RSA key operations

## Known Limitations

⚠️ **Critical**: This package requires additional implementation before production use.

### Implementation Required

1. **`fetchSegmentURL()` Method** (StandardTDFContentKeyDelegate.swift)
   - **Status**: Placeholder implementation that throws `notImplemented` error
   - **Impact**: Playback will not work until implemented
   - **Options**: Parse from HLS manifest, fetch from metadata endpoint, or load from cache
   - **Documentation**: See method documentation for integration guide

2. **KAS Rewrap Protocol** (StandardTDFKeyProvider.swift)
   - **Status**: Not yet implemented - currently uses offline decryption only
   - **Impact**: Online playback requires KAS integration
   - **Requirements**:
     - Generate ephemeral RSA key pair
     - Send Standard TDF manifest + ephemeral public key to KAS
     - KAS validates policy and rewraps DEK with ephemeral key
     - Decrypt rewrapped DEK with ephemeral private key
   - **Reference**: See OpenTDF protocol specification

3. **KAS Server Integration**
   - **Status**: Requires arkavo-rs deployment with media DRM endpoints
   - **Required Endpoints**:
     - `POST /media/v1/key-request` (Standard TDF manifest-based)
     - `POST /media/v1/session/start`
     - `POST /media/v1/session/{id}/heartbeat`
     - `DELETE /media/v1/session/{id}`
   - **Reference**: See [Integration Guide](INTEGRATION_GUIDE.md#backend-setup)

### Current Limitations

1. **No Session Persistence**
   - Sessions stored in memory only
   - Lost on app restart
   - No cross-device synchronization
   - **Workaround**: Implement Redis integration (see IMPLEMENTATION.md)

2. **No Offline Playback**
   - `AVAssetDownloadTask` integration not implemented
   - Cannot download content for offline viewing
   - **Roadmap**: Planned for future release

3. **Performance Not Validated**
   - Claims <50ms P95 key delivery but not benchmarked
   - No production load testing
   - **Action**: Run performance tests before production deployment

4. **No Policy Caching**
   - Policies evaluated on every key request
   - Potential performance bottleneck under load
   - **Optimization**: Implement Redis policy cache

5. **Limited Error Recovery**
   - Basic retry logic only
   - No circuit breaker for KAS failures
   - **Enhancement**: Add resilience patterns

### Security Hardening Required

Before production deployment, implement:

1. **TLS Certificate Pinning** - Pin KAS server certificates
2. **Rate Limiting** - Per-user request limits (60/min recommended)
3. **Audit Logging** - Log all key requests and policy violations
4. **Key Rotation** - KAS key rotation procedure (90-day schedule)
5. **Monitoring** - Metrics collection and alerting

See [SECURITY.md](SECURITY.md) for complete security guide.

### Platform Support

- ✅ iOS 18.0+
- ✅ macOS 15.0+
- ✅ tvOS 18.0+
- ❌ watchOS (AVPlayer limitations)

## Testing

Run tests:
```bash
swift test
```

**Current Coverage**:
- ✅ Unit tests (6 tests)
- ✅ Integration tests (6 tests)
- ❌ Performance tests (not implemented)
- ❌ E2E tests with real KAS (requires deployment)

## License

Same as parent Arkavo project.

## Related

- [Integration Guide](INTEGRATION_GUIDE.md) - Step-by-step integration
- [Security Guide](SECURITY.md) - Security best practices
- [Implementation Details](IMPLEMENTATION.md) - Technical architecture
- [TDF3 Media DRM Testing Plan](../vendor/FairPlay_Streaming_Server_SDK_26/TDF3_MEDIA_DRM_TESTING_PLAN.md)
- [arkavo-rs KAS Implementation](https://github.com/arkavo-org/arkavo-rs/issues/21)
