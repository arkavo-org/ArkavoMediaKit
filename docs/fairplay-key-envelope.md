# FairPlay key-envelope profile

The opt-in `FMP4RecordingProtectionService.protectVideo(..., profile: .keyEnvelope)`
packages CBCS HLS as extra ZIP entries alongside a standard OpenTDF 4.3 encrypted
payload. The default remains `.legacyV2` until clients and the KSM support this
profile. Legacy v2 is a custom FairPlay manifest, not an interoperable TDF payload.

The discriminator is `urn:arkavo:fairplay:key-envelope:1`, independent of the
OpenTDF `schemaVersion: "4.3.0"`. New archives contain `manifest.json`, the payload
entry, and the unchanged profile-v2 HLS filenames and per-component `skd://uuid/id`
URIs. The KAO's `kid` names the envelope key the DEK is wrapped to (see below).

The payload entry is the one the manifest's `payload.url` names (`type: reference`,
`protocol: zip`, `isEncrypted: true`), as in the OpenTDF payload reference, which
gives `0.payload` only as an example. The writer names it `0.payload`
(`FairPlayKeyEnvelope.payloadName`). Readers locate it by `payload.url`
(`FairPlayKeyEnvelope.payloadEntryName(ofManifestJSON:)`) and admit any name
`FairPlayKeyEnvelope.isPayloadEntryName(_:)` accepts: one root-level entry, non-empty,
not `.` or `..`, without `/` or `\`, not `manifest.json` and not a served HLS name. Any
other reference throws `invalidPayloadReference`. Neither the policy binding, the root
signature nor the segment hash covers the descriptor, so the name is not bound.

One random 32-byte DEK is RSA-OAEP-SHA1 wrapped in a single KAO. Each media track
keeps its own independent 16-byte CBCS key. No track key appears in a KAO or in
public metadata. `encryptedMetadata` is omitted. The KAO policy binding is
base64(HMAC-SHA256(DEK, UTF8(base64(policyJSON)))).

The payload is one AES-256-GCM segment: 12-byte nonce, ciphertext, 16-byte tag.
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

The FairPlay request adds `tdfPayload: base64(payload entry)` alongside the existing
`tdfManifest`, `component`, `spcData`, `sessionId` and `assetId` fields. Client
`FairPlayManifestProtocol.tdfPayload` defaults to nil for existing implementations.
A marked profile without its payload, or malformed envelope, fails before HTTP.
Players call `FairPlayKeyEnvelope.validateManifest` and `verifyInventory` before
playback; `verifyInventory` takes every entry but `manifest.json` and the payload
entry. Public checks alone cannot authenticate the policy: the KSM validates its
secret bindings before returning the CKC. Only the KSM decrypts track keys.

## Getting the wrapping key

The DEK is wrapped to the license service's envelope key, a KSM-only RSA key. It is
never the platform KAS key: the license service refuses an envelope wrapped to that,
and the packager never falls back to it. The service publishes the key
unauthenticated, below the KAS server root (`kasURL`, e.g. `https://platform.arkavo.net`):

```
GET <kasURL>/media/v1/envelope-key
200 {"kid": "<32 lowercase hex>", "alg": "RSA-OAEP", "publicKey": "-----BEGIN PUBLIC KEY-----..."}
```

`kid` is the first 32 lowercase hex characters of SHA-256 over the key's
SubjectPublicKeyInfo DER. The license service picks the unwrapping key by it, so the
packager writes it on the KAO. The service answers 503 when the profile is turned off.

With no `kasPublicKeyPEM`, `.keyEnvelope` fetches this key. It requires HTTP 200,
`alg: RSA-OAEP`, a non-empty `kid` and an RSA public key of at least 2048 bits, and
otherwise throws `FairPlayEnvelopeKeyError`. It writes the fetched `kid` unless the
caller passes `kasKeyID`, which wins. A caller that passes `kasPublicKeyPEM` must pass
this key; it is used as given with the caller's `kasKeyID`, and nothing is fetched.
`.legacyV2` still fetches the platform KAS key (`kas/v2/kas_public_key`) and never
this one.

To check a `kid`:

```sh
curl -s https://platform.arkavo.net/media/v1/envelope-key | jq -r .publicKey \
  | openssl pkey -pubin -outform DER | shasum -a 256 | cut -c1-32
```

## Verification

`swift test --filter 'FairPlayKeyEnvelopeTests|FairPlayEnvelopeKeyTests|TDFContentKeyDelegate|FairPlayComponentsTests'`
covers the RSA/AES-GCM round trip, policy/root bindings, ciphertext and media
mutation, encrypted payload transport, fail-closed missing payload, a real
synthetic video+AAC packaging run, and the envelope-key fetch against stubbed
responses. To export test-only archives and keys:

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
