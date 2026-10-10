# ArkavoMediaKit

A Swift package providing comprehensive media DRM capabilities including:
- **FairPlay Streaming DRM**: Secure playback of DRM-protected HLS content on Apple platforms
- **TDF3-based HLS Streaming**: Open alternative to proprietary DRM systems

## FairPlay Streaming Certificate Requirements

### IMPORTANT: You Must Provide Your Own Certificate

ArkavoMediaKit **does not** include a FairPlay Streaming certificate. You must obtain your own certificate from Apple.

### How to Obtain a FairPlay Certificate

1. **Enroll in the Apple Developer Program** if you haven't already
2. **Request FairPlay Streaming Deployment Package**:
   - Go to [Apple Developer Portal](https://developer.apple.com/)
   - Navigate to Certificates, Identifiers & Profiles
   - Request FairPlay Streaming credentials
3. **Complete the FPS Deployment Package** request form
4. **Receive your certificate** from Apple (typically `.cer` or `.der` format)

### Loading Your FairPlay Certificate

```swift
import ArkavoMediaKit
import Foundation

// Load certificate from your app bundle or secure location
guard let certURL = Bundle.main.url(forResource: "fairplay_cert", withExtension: "cer"),
      let certData = try? Data(contentsOf: certURL) else {
    fatalError("FairPlay certificate not found")
}

// Create DRM configuration with your certificate
let configuration = try DRMConfiguration(
    serverURL: URL(string: "https://your-drm-server.com")!,
    fpsCertificateData: certData
)

// Initialize player with configuration
let player = try DRMMediaPlayer(configuration: configuration)
```

### Security Best Practices for FairPlay Certificates

1. **NEVER commit certificates to source control**
   - Certificates are tied to your Apple Developer account
   - Keep them secure and private
2. **Store certificates securely**:
   - Use encrypted storage for production certificates
   - Consider loading from Keychain on iOS/macOS
   - Use environment-specific certificates (dev/staging/prod)
3. **Use HTTPS only**:
   - DRMConfiguration enforces HTTPS for server URLs
   - Never transmit keys over unencrypted connections

### Example: Secure Certificate Loading from Keychain

```swift
// Load from Keychain (recommended for production)
func loadCertificateFromKeychain() throws -> Data {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "fairplay-certificate",
        kSecReturnData as String: true
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess,
          let certData = result as? Data else {
        throw NSError(domain: "FairPlay", code: -1)
    }

    return certData
}

// Use in configuration
let certData = try loadCertificateFromKeychain()
let config = try DRMConfiguration(
    serverURL: URL(string: "https://drm.example.com")!,
    fpsCertificateData: certData
)
```

---

# TDF3-Based HLS Streaming

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

## FairPlay package profile v2 (0.4.0)

`FMP4RecordingProtectionService.protectVideo(videoURL:assetID:policyJSON:)` writes FairPlay package profile v2 (ADR-0055 in arkavo-ios):

| Entry | Contents |
|---|---|
| `manifest.json` | The TDF manifest: the policy with `arkavo:components`, and one key access object per component, in component order. Never served to a player. |
| `master.m3u8` | One variant, `video.m3u8`, and when the recording has sound one audio rendition, `audio.m3u8`. |
| `<id>.m3u8` | The component's media playlist. Its key URI is `skd://<policy uuid>/<id>`. |
| `<id>-init.mp4`, `<id>-segment<N>.m4s` | The component's one track. Segment N of each component covers the same time. |

- **Components:** `video`, and `audio` when the source has sound. A recording without sound is a video-only package: `video` alone, one key, and a master playlist with no audio rendition.
- **Keys:** each component has its own 16-byte content key, and one IV serves both. The keys and the IV come from the system's random source, and protection fails rather than use an unfilled one.
- **`keyBinding`** = `base64(HMAC-SHA256(key, "arkavo:fps:component:v1:" + id))` ties each key to its component. The key service checks it before it issues a key.
- **The audio** covers the video from its first presented frame to the end of its last (a B-frame video presents its last frame after its last decode), within one AAC packet, its decode times contiguous from segment to segment.
  - One AAC-LC track of 1–6 or 8 channels (configuration 1–7) is packaged as it is.
  - Anything else is mixed and re-encoded once as AAC-LC: several tracks, another format, sound that starts late or stops early (padded with silence), and a single AAC-LC track whose channel configuration is 0 (a program config element) or 8–15 (for example 6.1).
  - CHANNELS in the master playlist is the channel count (configuration 7 is 8 channels).
- **BANDWIDTH** is the video's peak segment bit rate plus the audio's; AVERAGE-BANDWIDTH is the sum of their averages.
- **Refused** (`FMP4ProtectionError.packagingFailed`), never written as a package the viewer refuses or cannot decode:
  - more than 4,093 segments per component (about six hours 49 minutes at six-second segments);
  - an archive over 4,294,967,295 bytes, the most a ZIP without ZIP64 holds (about 71 minutes at 8 Mbit/s);
  - NAL unit lengths other than 4 bytes, and a video sample of more than 42 NAL units.
- **Refused before any work** (`FairPlayComponents.Error.componentsPresent`): a policy that already has `arkavo:components`. The packager writes that list itself, from the keys it makes.

`TDFContentKeyDelegate` answers every component's key (`keyIdentifiers`):
- each with its own session;
- the content identifier `<policy uuid>/<id>`;
- `component` in the key request.

`onKeyDelivered` is called at most once, when AVFoundation has **accepted** every key (`contentKeySession(_:contentKeyRequestDidSucceed:)`); a CKC handed to AVFoundation is not yet a key accepted. `onKeyFailed` is called at most once, at the first failure before that, a CKC AVFoundation rejects included. Never both, never twice, and renewals never report. If the player asks for fewer keys than the package has components, neither is called, so callers keep their own timeout. An empty `keyIdentifiers` means the package is malformed: treat it as refused.

A present-but-malformed `arkavo:components` list, a repeated JSON key, or an unknown key identifier is refused locally, with no request to the key service.

- **Never sent:** no request body names the user. The `userId` init parameter is kept for source compatibility and is unused; the bearer token identifies the viewer.
- **Redirects refused:** the certificate, session and key requests carry the bearer token (and the key request the SPC and the manifest), so none follows a redirect; a 3xx fails the key.
- **Never logged:** SPC, CKC, wrapped keys, the IV, the token and the session id. Errors carry the HTTP status or a fixed reason, never the server's response.

0.4.0 no longer writes profile v1 (`playlist.m3u8`, `init.mp4`, one key), which the viewer refuses.

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
