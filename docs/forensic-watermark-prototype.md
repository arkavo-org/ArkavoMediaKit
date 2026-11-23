# Player-Only Forensic Watermark Prototype (Issue #16)

> **Status: Prototype ready for physical two-iPhone validation.**
> Camera recovery from physical OLED screens and human perceptibility on iPhone displays remain **open empirical questions** until the physical device experiments below are completed.

## 1. Design Overview

This prototype implements a **player-only** spatiotemporal spread-spectrum forensic watermark owned by `ArkavoMediaKit`:

- **Byte-identical TDF media**: Two playback sessions play the exact same TDF archive, manifest, FairPlay key envelope, and encrypted fMP4 segments. No viewer or session data enters the container, manifest, or media bytes.
- **Opaque session identifiers**: The overlay accepts only an opaque printable-ASCII `WatermarkSessionCode`, keeping any account-to-session mapping strictly outside `ArkavoMediaKit` and the renderer.
- **Preserves FairPlay secure playback**: Uses standard `sourceOver` compositing of a 16-bit per component (32×24) bilinearly interpolated texture above the video bounds without reading decrypted frames, installing `AVPlayerItemVideoOutput`, or intercepting player controls (`allowsHitTesting(false)`).
- **Exact video-bounds alignment**: `ForensicWatermarkGeometry.videoRect(forPresentationSize:in:gravity:)` returns `.zero` until `presentationSize` is known (never painting letterbox/pillarbox bars), constrains rendering to the active picture area over an edge-to-edge `.ignoresSafeArea()` container, and also accepts explicit `videoBounds` / `AVPlayerLayer.videoRect` from UIKit/AVKit hosts.
- **External output & PiP limits**: Call `ForensicWatermarkPlayerPolicy.configureForWatermarkedPlayback(player)` to disable AirPlay (`allowsExternalPlayback = false`) and disable Picture-in-Picture on `AVPlayerViewController` while a local overlay session is active so video cannot route outside the watermarked view hierarchy.

### Signal & Detector Architecture

| Component | Default Prototype Setting | Rationale |
| --- | --- | --- |
| Modulation channel | `.isoluminantBlueYellow` (`C+ = (0.46, 0.46, 1.0)`, `C- = (0.54, 0.54, 0.0)`) | Matched Rec. 709 luminance in both sRGB (`0.499` vs `0.501`) and linear light (`0.240` vs `0.239`); rendered into 16-bit premultiplied RGBA so the yellow luminance compensator is preserved without 8-bit quantization collapse even at `opacity = 0.015`. `.blueChannel` and `.luminance` presets are included for A/B comparison. |
| Overlay opacity | `0.025` (`.subtle = 0.015`, `.robust = 0.04`) | Tunable knob to sweep the perceptibility-vs-recovery frontier on real hardware. |
| Spatial pattern | `.smoothCosine3x2` (`cos(2*pi*u) * cos(pi*v)`) | Zero spatial mean keeps total screen luminance and white balance constant (defeating uniform camera AE/AWB), avoids sharp edges/OLED moire, and retains opposite-sign lobes under cropping. |
| Temporal coding | 4.0 Hz bi-phase sinusoidal chips (`sin(2*pi*phase)`), period = 64 chips (16.0 s) | Exact zero DC per chip; sits well below 30 fps camera Nyquist (15 Hz) and above <1 Hz AE/AWB drift; aligns cleanly to a 15-second initial capture window and folds coherently on longer clips with exact period-aligned resampling. |
| Offline detector (`ForensicWatermarkDetector`) | Blind `AVAssetReader` (VFR-safe PTS), 6×4 coarse grid, spatial-mean subtraction + global-mean fallback, bin-averaging anti-alias resampler, reflective-padded zero-phase biquad bandpass, MAD soft-clipping, FFT circular cross-correlation with MAD sidelobe normalization, 64 domain-separated decoys + candidate-count extreme-value threshold adjustment | Requires no metadata, calibration markers, or timestamps; planar-rotation tolerant via non-coherent squared-cell combining (projective keystone warp and real lens distortion remain to be measured on hardware); empirical per-clip decoy calibration returns `.inconclusive` on weak, unmarked, or out-of-candidate-set clips. |

> **Note on `domainSeparator`**: `ForensicWatermarkConfiguration.domainSeparator` is a public domain tag, not a secret key; anyone with an opaque session ID can reproduce its prototype waveform. Production deployments requiring forgery resistance should issue opaque server-derived per-session tokens or keep a deployment-specific key outside the client.

---

## 2. iOS App Integration (`FMP4VideoPlayerView`)

In `arkavo-org/app` (`Arkavo/Arkavo/FMP4VideoPlayerView.swift`), pass an opaque `watermarkSessionID: String?` (use `nil` for unmarked controls), configure external playback off, and attach `ForensicWatermarkOverlay` inside `VideoPlayer`'s `videoOverlay` closure:

```swift
// When preparing AVPlayer in FMP4PlayerViewModel:
ForensicWatermarkPlayerPolicy.configureForWatermarkedPlayback(avPlayer)

// In FMP4VideoPlayerView.swift:
let watermarkSessionID: String?
var watermarkConfiguration: ForensicWatermarkConfiguration = .default

// Replace `VideoPlayer(player: player)` with:
VideoPlayer(player: player) {
    if let overlay = try? ForensicWatermarkOverlay(
        sessionID: watermarkSessionID,
        player: player,
        configuration: watermarkConfiguration
    ) {
        overlay
    }
}
.ignoresSafeArea()
```

Notes:
- `ForensicWatermarkOverlay.init` throws on invalid non-nil `sessionID`, invalid `configuration`, or `refreshRateHz < 3 * chipRateHz` instead of silently downgrading to unmarked playback. Handle/log initialization errors explicitly in the host view model.
- `VideoPlayer`'s `videoOverlay` renders inside `AVPlayerViewController.contentOverlayView` (above the FairPlay video layer, below native controls), and `ForensicWatermarkOverlay` applies `.ignoresSafeArea()`, `.allowsHitTesting(false)`, and `.accessibilityHidden(true)`.
- For UIKit `AVPlayerViewController` hosts (including zoom-to-fill support), attach `ForensicWatermarkLayer` to `contentOverlayView.layer`, disable `allowsPictureInPicturePlayback`, call `align(toVideoRect: playerViewController.videoBounds)` on layout/rotation/gravity changes, and call `update(at:)` from a `CADisplayLink`.

---

## 3. Reproduction Steps & Physical Experiment Protocol

### 3.1 Verify Synthetic Baseline Locally

Run the unit tests and the built-in synthetic benchmark CLI:

```bash
swift test --filter ForensicWatermarkTests
swift run ForensicWatermarkCLI simulate
```

#### Measured Synthetic Baseline (Software Channel with 16-Bit Live Overlay + Independent RGB Noise, NOT Physical Camera Capture)

Measured via `swift run ForensicWatermarkCLI simulate` (`isoluminantBlueYellow`, `smoothCosine3x2`, `opacity=0.025`, `4.0 Hz`, `64 chips`, 12 candidates, 64 decoys, `baseMinZ=5.0`, `effectiveMinZ=6.94`, `minMargin=2.0`, `minRepeatableTrials=2`):

| Category | Trials | Correct / True Negative | Missed (Inconclusive) | Wrong ID / False Positive |
| --- | ---: | ---: | ---: | ---: |
| Marked (in candidate set) | 8 | 5 | 3 | 0 |
| Unmarked controls | 2 | 2 | 0 | 0 |
| Marked (outside candidate set) | 1 | 1 | 0 | 0 |

- **Shortest duration with repeatable recovery (`n >= 2`, 0 false positives)**: **15s** (15s: 4/4 = 100%; 10s: 1/2 = 50%; 5s: 0/2 = 0%)

| Clip | Transform | Duration | Detected | z-score | Margin | Outcome |
| --- | --- | ---: | --- | ---: | ---: | --- |
| `clip-01` | `original-15s-moving` | 15.0s | `syn-sess-01` | 19.13 | 15.04 | `correctID` |
| `clip-02` | `handheld-recompressed-15s-dark` | 15.0s | `syn-sess-04` | 14.46 | 9.79 | `correctID` |
| `clip-03` | `handheld-recompressed-15s-bright` | 15.0s | `syn-sess-08` | 24.76 | 21.76 | `correctID` |
| `clip-04` | `trimmed-10s-handheld-a` | 10.0s | `inconclusive` | 6.03 | 2.40 | `missedDetection` |
| `clip-05` | `trimmed-10s-handheld-b` | 10.0s | `syn-sess-05` | 9.97 | 6.45 | `correctID` |
| `clip-06` | `trimmed-5s-handheld-a` | 5.0s | `inconclusive` | 3.23 | 0.81 | `missedDetection` |
| `clip-07` | `trimmed-5s-handheld-b` | 5.0s | `inconclusive` | 6.33 | 2.05 | `missedDetection` |
| `clip-08` | `cropped-50pct-recompressed-15s` | 15.0s | `syn-sess-03` | 9.74 | 7.07 | `correctID` |
| `clip-09` | `unmarked-control-moving` | 15.0s | `inconclusive` | 1.80 | -0.92 | `controlTrueNegative` |
| `clip-10` | `unmarked-control-dark` | 15.0s | `inconclusive` | 2.14 | -0.68 | `controlTrueNegative` |
| `clip-11` | `outside-candidate-set-15s` | 15.0s | `inconclusive` | 1.51 | -2.01 | `outOfSetRejection` |

> **Caution**: Synthetic simulation models crop, jitter, independent RGB sensor noise, spatially varying AE/AWB drift, 16-bit live overlay compositing, and H.264/HEVC compression, but does **not** capture real OLED PWM dimming, True Tone / Night Shift color transforms, HDR tone-mapping, optical lens blur/keystone warp, room-light reflections, or real ISP denoising. Physical testing is mandatory before deciding to integrate.

---

### 3.2 Physical Two-iPhone Capture Protocol (Acceptance Criteria 1–3)

1. **Prepare one FairPlay-protected fMP4 TDF asset** (~60s containing dark, bright, and high-motion scenes). Verify all sessions play the exact same SHA-256 TDF bytes.
2. **Generate synthetic opaque session IDs**:
   - Create a candidate list of e.g. 20 randomized opaque ASCII session IDs (`candidates.txt`), e.g. `exp-sess-<uuid>`.
   - Pick 5 in-set IDs to film (with >= 2 independent captures per duration bucket), 2 unmarked control runs (`sessionID: nil`), and 2 out-of-set IDs (marked during playback, omitted from `candidates.txt`).
3. **Record device & camera settings**:
   - Playback iPhone model, iOS version, display brightness (e.g. 50% and 100%), True Tone / Night Shift state, orientation (verify both portrait and landscape after rotation), AirPlay/PiP disabled.
   - Capture iPhone model, iOS version, camera resolution/fps (1080p 30fps default; optionally 4K 60fps), **HDR Video setting (On vs. Off)**, handheld distance (~30–50 cm), ambient lighting.
   - Start with **15-second** handheld captures (plus optional 30-second captures to trim down to 15s, 10s, 5s).
4. **Produce blinded, upright, metadata-stripped copies** (originals + trimmed, cropped, and recompressed variants):
   ```bash
   # Original (oriented upright, metadata stripped; never overwrites without --overwrite)
   swift run ForensicWatermarkCLI strip-metadata raw/take01.mov blinded/clip-01.mp4

   # Trimmed to 10s starting at 3s
   swift run ForensicWatermarkCLI strip-metadata raw/take01.mov blinded/clip-02.mp4 \
     --trim-start 3 --trim-duration 10

   # Cropped (center 70%) and aggressively recompressed (1 Mbps)
   swift run ForensicWatermarkCLI strip-metadata raw/take01.mov blinded/clip-03.mp4 \
     --crop-inset 0.15 --bitrate 1000000
   ```
   Verify stripped files on a real iPhone `.mov` via `mdls` / `ffprobe` to confirm all QuickTime/EXIF/GPS/device atoms are absent.
5. **Run the blinded evaluator** using a JSON manifest (`trials.json`) of `ForensicWatermarkTrial` entries:
   ```bash
   swift run ForensicWatermarkCLI evaluate \
     --manifest trials.json \
     --candidates-file candidates.txt
   ```
   To sweep operating points if physical SNR is lower than synthetic, repeat at `--opacity 0.04` or `--chroma-mode luminance` / `--chroma-mode blueChannel` and record the shortest duration with repeatable recovery (`n >= 2`, 0 false positives).

---

### 3.3 Blinded Perceptibility Protocol (Acceptance Criterion 4)

On the physical playback iPhone (normal viewing distance, both dim room and indoor daylight, dark / bright / moving scenes):
1. Run at least 10 randomized A/B trials comparing marked (`opacity=0.025`, `.isoluminantBlueYellow`) vs. unmarked (`sessionID: nil`) playback of the same FairPlay TDF asset.
2. Record for each trial:
   - Whether the viewer correctly identified marked vs. unmarked (target: near 50% chance).
   - Any perceived flicker, color shift, dark-scene black-level lift, or spatial texture/banding.
   - Verify alignment visually (temporarily test at `opacity=0.20` during setup only) before and after portrait ↔ landscape rotation to confirm the overlay stays strictly inside the aspect-fitted video rect and never covers letterbox bars or blocks controls.

---

## 4. Physical Measurement Log & Integration Recommendation (Template)

Fill in after executing Sections 3.2 and 3.3 on physical iPhones:

- **Playback device / settings**: `<TBD>`
- **Capture device / camera settings (incl. HDR)**: `<TBD>`
- **Shortest duration with repeatable recovery**: `<TBD>`
- **Blinded viewing result (dark / bright / moving)**: `<TBD>`
- **Measured limits**: `<TBD>`

### Go / No-Go Criteria for Integration Recommendation

- **Recommend integration** if at an opacity rated imperceptible in the blinded viewing test (no flicker/texture across dark, bright, and moving scenes):
  - ≥80% correct ID recovery on 15s handheld clips (including trimmed/cropped/recompressed variants), AND
  - 0 wrong IDs on marked trials, AND
  - 0 false positives on unmarked controls and out-of-candidate-set clips.
- **Recommend NOT integrating (or redesigning)** if achieving repeatable 15s physical recovery requires an opacity that produces visible flicker, color pulsing, or OLED dark-scene box artifacts during normal viewing.
