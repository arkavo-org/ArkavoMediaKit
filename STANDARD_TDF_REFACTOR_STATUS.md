# Standard TDF Refactor Status

## Critical Issue Identified
ArkavoMediaKit was incorrectly using **NanoTDF** (optimized for <10KB messages) for HLS video segments (2-10MB typical). Per OpenTDFKit guidance, **Standard TDF** (ZIP-based) is required for files >10KB.

## PR #135 Status
**CLOSED** - Fundamental architecture incompatibility. Complete redesign required.

## Refactor Progress

### ✅ Completed Files

1. **StandardTDFSegmentCrypto.swift** (NEW)
   - Wraps OpenTDFKit's StandardTDFEncryptor/Decryptor
   - Encrypts video segments to .tdf ZIP archives
   - RSA-2048+ key wrapping (vs EC for NanoTDF)
   - Creates manifest.json + encrypted payload structure

2. **StandardTDFKeyProvider.swift** (NEW)
   - RSA key management for Standard TDF
   - KAS integration for key unwrapping
   - DEK caching for performance
   - Offline/online decryption modes

3. **HLSSegmentEncryptor.swift** (UPDATED)
   - Now outputs .tdf ZIP files instead of raw encrypted segments
   - Each segment = complete Standard TDF archive
   - Metadata includes TDF manifest (not NanoTDF header)

4. **HLSPlaylistGenerator.swift** (UPDATED)
   - Segment URLs now point to .tdf files
   - Updated documentation for Standard TDF workflow

5. **SegmentMetadata.swift** (UPDATED)
   - Changed: `nanoTDFHeader` → `tdfManifest`
   - Stores base64-encoded Standard TDF manifest JSON

6. **KeyAccessRequest.swift** (UPDATED)
   - Changed: `nanoTDFHeader` → `tdfManifest`
   - KAS receives Standard TDF manifest for validation

7. **StandardTDFContentKeyDelegate.swift** (NEW)
   - AVContentKeySessionDelegate for .tdf segments
   - Downloads .tdf files, extracts manifests
   - DEK caching to avoid re-parsing ZIP archives
   - Placeholder for segment URL fetching (needs implementation)

### ❌ Deleted Files (NanoTDF-specific)

- `CryptoConstants.swift` - NanoTDF magic numbers
- `TDF3SegmentKey.swift` - NanoTDF encryption/decryption
- `TDF3KeyProvider.swift` - EC key management
- `TDF3ContentKeyDelegate.swift` - NanoTDF key handling

### 🔨 Remaining Work

#### 1. Fix Compilation Errors

**Issue**: OpenTDFKit TDFManifest API mismatch

**Errors**:
- `TDFKeyAccessObject` constructor requires `protocolValue` (enum), not `protocol` (string)
- `TDFKeyAccessObject.AccessType` is enum (`.wrapped`), not string
- `TDFManifest` requires `schemaVersion` parameter
- `TDFMethod` doesn't exist - need to use correct type
- `TDFPayload` doesn't exist - should be `TDFPayloadDescriptor`
- `TDFEncryptionInformation.KeyAccessType` is enum (`.split`), not string

**Files to fix**:
- `StandardTDFKeyProvider.swift` - lines 150-177
- `StandardTDFSegmentCrypto.swift` - TDF manifest creation

#### 2. Update TDF3StreamingPlayer

**Current**: Uses TDF3KeyProvider (deleted)
**Needed**: Use StandardTDFKeyProvider and StandardTDFContentKeyDelegate

**Changes**:
```swift
// Before
public init(
    keyProvider: TDF3KeyProvider,  // ❌ Deleted
    policy: MediaDRMPolicy,
    deviceInfo: DeviceInfo,
    sessionID: UUID
)

// After
public init(
    keyProvider: StandardTDFKeyProvider,  // ✅ Standard TDF
    policy: MediaDRMPolicy,
    deviceInfo: DeviceInfo,
    sessionID: UUID
)
```

#### 3. Rewrite Tests

**Current tests**: All use NanoTDF APIs
**Needed**: Complete rewrite for Standard TDF

**Test files**:
- `ArkavoMediaKitTests.swift` - all tests broken
- `IntegrationTests.swift` - all tests broken

**New tests needed**:
- Standard TDF segment encryption (2MB video data)
- .tdf ZIP archive creation and parsing
- TDF manifest generation with RSA wrapping
- HLS playlist generation with .tdf URLs
- AVContentKeySession with .tdf segments

#### 4. Fix TDFManifest API Usage

**Current code assumptions** (WRONG):
```swift
let method = TDFMethod(algorithm: "AES-256-GCM", isStreamable: true, iv: nil)
let keyAccess = TDFKeyAccessObject(type: "wrapped", protocol: "kas", ...)
let encInfo = TDFEncryptionInformation(type: "split", ...)
let payload = TDFPayload(type: "reference", ...)
```

**Actual OpenTDFKit API**:
```swift
// Need to find correct types in OpenTDFKit:
// - TDFEncryptionMethod (not TDFMethod)
// - TDFKeyAccessObject.AccessType.wrapped (enum)
// - TDFKeyAccessObject.AccessProtocol.kas (enum)
// - TDFEncryptionInformation.KeyAccessType (enum)
// - TDFPayloadDescriptor (not TDFPayload)
```

#### 5. Update Documentation

**Files**:
- `README.md` - Explain Standard TDF choice, architecture
- `INTEGRATION_GUIDE.md` - Update for .tdf workflow
- `SECURITY.md` - RSA key management (not EC keys)
- `IMPLEMENTATION.md` - Standard TDF details

#### 6. Create TDFArchiveWriter

**Issue**: `TDFArchiveWriter` used in `StandardTDFSegmentCrypto.swift` doesn't exist in OpenTDFKit

**Options**:
1. Use OpenTDFKit's `StandardTDFEncryptor` directly (recommended)
2. Implement simple ZIP writer using ZIPFoundation

## Architecture Changes Summary

### From (NanoTDF)
- Binary format (~250 byte overhead)
- EC key wrapping (P-256/P-384/P-521)
- ECDH + HKDF key derivation
- Single binary blob

### To (Standard TDF)
- ZIP archive (~1.1KB overhead)
- RSA key wrapping (2048+ bit)
- RSA-OAEP-SHA256
- Structured format:
  - `0.manifest.json` - metadata
  - `0.payload` - encrypted data

## File Size Impact

| Segment Size | NanoTDF Overhead | Standard TDF Overhead | Impact |
|--------------|------------------|----------------------|---------|
| 2 MB         | 250 bytes (0.01%) | 1.1 KB (0.05%)      | Negligible |
| 10 MB        | 250 bytes (0.002%) | 1.1 KB (0.01%)      | Negligible |

## Next Steps

1. **Fix compilation errors** - Update to correct OpenTDFKit API
2. **Update TDF3StreamingPlayer** - Use Standard TDF components
3. **Rewrite all tests** - Standard TDF integration tests
4. **Update documentation** - Explain architecture change
5. **Create new PR** - Fresh implementation with Standard TDF
6. **Backend coordination** - Ensure arkavo-rs KAS supports Standard TDF manifests

## Estimated Completion Time

- Fix APIs: 1-2 hours
- Update player: 1 hour
- Rewrite tests: 2-3 hours
- Update docs: 1 hour
- **Total**: 5-7 hours

## Key Decisions Made

1. ✅ Use Standard TDF for HLS segments (correct per OpenTDFKit guidance)
2. ✅ RSA-2048+ key wrapping (industry standard)
3. ✅ .tdf ZIP archives per segment (structured, cross-platform compatible)
4. ✅ DEK caching in ContentKeyDelegate (performance optimization)
5. ⚠️ Placeholder for segment URL fetching (implementation required)
6. ⚠️ KAS rewrap protocol not yet implemented (use offline decryption)

## Blockers

None - all APIs available in OpenTDFKit. Just need to use correct types.
