# FairPlay key-envelope profile

The opt-in `FMP4RecordingProtectionService.protectVideo(..., profile: .keyEnvelope)`
packages CBCS HLS as extra ZIP entries alongside a standard OpenTDF 4.3 encrypted
payload. The default remains `.legacyV2` until clients and the KSM support this
profile. Legacy v2 is a custom FairPlay manifest, not an interoperable TDF payload.

The discriminator is `urn:arkavo:fairplay:key-envelope:1`, independent of the
OpenTDF `schemaVersion: "4.3.0"`. New archives contain `manifest.json`, `0.payload`,
and the unchanged profile-v2 HLS filenames and per-component `skd://uuid/id` URIs.
The publisher can supply `kasKeyID` from the KAS public-key response.

One random 32-byte DEK is RSA-OAEP-SHA1 wrapped in a single KAO. Each media track
keeps its own independent 16-byte CBCS key. No track key appears in a KAO or in
public metadata. `encryptedMetadata` is omitted. The KAO policy binding is
base64(HMAC-SHA256(DEK, UTF8(base64(policyJSON)))).

`0.payload` is one AES-256-GCM segment: 12-byte nonce, ciphertext, 16-byte tag.
`segmentHashAlg` is `GMAC`; the segment hash is base64(tag). The root signature is
base64(raw HMAC-SHA256(DEK, tag)), with `alg: HS256`. Segment defaults are 2097152
plaintext and 2097180 encrypted bytes; the segment records its actual sizes. The
payload is capped at 2097180 encrypted bytes. `method.iv` is empty; media IVs are
separate from the GCM nonce.

The bound policy preserves `arkavo:components` from profile v2 and adds:

```json
{
  "arkavo:fpsProfile": "urn:arkavo:fairplay:key-envelope:1",
  "arkavo:media": [{"name": "master.m3u8", "sha256": "<base64 SHA256 of exact archived bytes>"}],
  "arkavo:mediaIVs": {"video": "<base64 16 bytes>", "audio": "<base64 16 bytes>"}
}
```

The inventory includes every HLS file, sorted by filename, at most 8191 entries.
Only `master.m3u8`, `video.m3u8`, `audio.m3u8`, `<id>-init.mp4` and
`<id>-segmentN.m4s` are allowed (`id` video/audio, canonical N from 0 through4092).
Neither the manifest nor payload is served as media. Reserved policy members
cannot be supplied by the caller.

Decrypted payload shape:

```json
{
  "profile": "urn:arkavo:fairplay:key-envelope:1",
  "assetId": "<nonempty recording id, at most 1024 UTF8 bytes>",
  "contentKeyId": "<policy uuid>",
  "tracks": [{"id": "video", "key": "<base64 16 bytes>", "iv": "<base64 16 bytes>"}],
  "files": [{"name": "master.m3u8", "sha256": "<base64 SHA256>"}]
}
```

`files` equals the policy inventory. Tracks follow the component list (video,
then optional audio), and their IVs equal `arkavo:mediaIVs`. The KSM verifies the
policy binding, root and segment integrity, decrypts the payload, verifies all
cross-bindings and per-component key bindings, then issues a CKC for the selected
component. General viewer rewrap access must not be granted to this DEK.

The FairPlay request adds `tdfPayload: base64(0.payload)` alongside the existing
`tdfManifest`, `component`, `spcData`, `sessionId` and `assetId` fields. Client
`FairPlayManifestProtocol.tdfPayload` defaults to nil for existing implementations.
A marked profile without its payload, or malformed envelope, fails before HTTP.
Players call `FairPlayKeyEnvelope.validateManifest` and `verifyInventory` before
playback. Public checks alone cannot authenticate the policy: the KSM validates
its secret bindings before returning the CKC. Only the KSM decrypts track keys.

## Verification

`swift test --filter 'FairPlayKeyEnvelopeTests|TDFContentKeyDelegate|FairPlayComponentsTests'`
covers the RSA/AES-GCM round trip, policy/root bindings, ciphertext and media
mutation, encrypted payload transport, fail-closed missing payload and a real
synthetic video+AAC packaging run. To export test-only archives and keys:

```sh
ARKAVO_ENVELOPE_FIXTURE_DIR=/tmp/arkavo-envelope-fixture swift test --filter FairPlayKeyEnvelopeTests
```

These fixtures use fresh disposable cryptographic keys. They contain no production
credentials. Device FairPlay playback still requires an envelope-capable deployed
KSM and signed client; unit and cross-SDK decryption do not establish that result.

The pinned Go reference check is reproducible with:

```sh
ARKAVO_ENVELOPE_FIXTURE_DIR=/tmp/arkavo-envelope-fixture tools/interop/verify-opentdf-go.sh
```

It checks `IsValidTdf`, strict schema loading, key reconstruction/root integrity,
full payload decryption and rejection after ciphertext mutation. The test injects
the disposable unwrapped DEK at the SDK's internal seam; it does not contact a
KAS or establish a real authorization grant. Add `/two-tracks` to the fixture
path to test the generated AAC+video package.
