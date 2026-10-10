# AuthzLedger 1.1.0 launch assets

The keyvisuals use the established 0xFarag Navy `#071722`, Gold `#C8A66B`
and pale text `#EDF5F7`. The existing logo and Studio identity are unchanged.

| File | Purpose |
| --- | --- |
| `launch-landscape.png` | 1600 × 1000 launch image for GitHub and desktop posts |
| `launch-portrait.png` | 1080 × 1350 portrait image for a social feed |
| `launch-landscape.svg`, `launch-portrait.svg` | Editable, self-contained source compositions |
| `studio-source.png` | Unmodified 1200 × 900 capture from the final 1.1.0 browser acceptance run |
| `provenance.json` | Capture receipt, frozen source hashes, crop and output SHA-256 values |
| `capture-receipt.json` | Original successful browser acceptance receipt used to validate the capture |
| `authzledger-1.1.0-voiceover.srt` | Draft subtitle timing for the planned 60-second recording; not a completed video |

The screenshot shows an actual synthetic local test fixture, not a customer
system or an independently authenticated remote response. Both keyvisuals say
“Actual Studio capture · Synthetic local fixture”. The 14-pixel crop at the top
removes a partially clipped heading at the viewport edge. Displayed UI pixels,
findings, controls and identifiers are not retouched. The full original capture
is retained as `studio-source.png` and is bound to the successful acceptance
receipt by SHA-256. The version label does not itself assert publication.

Regeneration requires the matching successful browser acceptance receipt:

```sh
python brand/release-1.1.0/compose.py \
  --source brand/release-1.1.0/studio-source.png \
  --capture-receipt brand/release-1.1.0/capture-receipt.json \
  --out brand/release-1.1.0 --version 1.1.0 --crop-top 14

node brand/release-1.1.0/render.cjs brand/release-1.1.0
```

The renderer accepts the same `PLAYWRIGHT_MODULE` and `CHROME_EXECUTABLE`
environment variables as the browser acceptance suites. Pin the recorded
Chromium version and installed fonts for pixel-identical PNG output. The PNGs
are ready to use without these tools; SVG text uses DejaVu Sans with Arial as
fallback. No external assets, fonts or tracking are fetched by the composition.

Copyright © 2026 Nasser Aldin Farag / 0xFarag. Existing `LICENSE` and
`NOTICE.txt` apply. The original product and third-party font notices remain
unchanged.
