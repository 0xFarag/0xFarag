"""Compose an original 0xFarag frame around an unmodified Studio capture.

Run only against a reviewed screenshot from the matching code/version. This
script does not paint over, retouch or replace any interface text or evidence.
"""
import argparse
import base64
import hashlib
import json
import struct
from pathlib import Path
from xml.sax.saxutils import escape


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--version", required=True)
parser.add_argument("--code-commit", help="Set only if capture code is already committed")
parser.add_argument("--capture-receipt", type=Path, required=True)
parser.add_argument("--source-width", type=int, default=1200)
parser.add_argument("--source-height", type=int, default=900)
parser.add_argument("--crop-top", type=int, default=0)
args = parser.parse_args()
payload = args.source.read_bytes()
receipt = json.loads(args.capture_receipt.read_text())
if receipt.get("exit_code") != 0 or not receipt.get("acceptance", {}).get("passed"):
    raise ValueError("A successful browser acceptance receipt is required")
if receipt.get("product_version") != args.version or receipt.get("source_changed_during_execution") is not False:
    raise ValueError("Capture version and frozen source must match the label")
if sha(args.source) not in receipt.get("artifact_sha256", {}).values():
    raise ValueError("Source screenshot is not bound to the supplied acceptance receipt")
if payload[:8] != b"\x89PNG\r\n\x1a\n" or struct.unpack(">II", payload[16:24]) != (args.source_width, args.source_height):
    raise ValueError("Source must be a native PNG with the declared dimensions")
args.out.mkdir(parents=True, exist_ok=True)
image_uri = "data:image/png;base64," + base64.b64encode(payload).decode()
version = escape(args.version)

defs = """<defs>
 <radialGradient id="light" cx="78%" cy="35%" r="76%">
  <stop stop-color="#183448" stop-opacity=".64"/>
  <stop offset="1" stop-color="#071722" stop-opacity="0"/>
 </radialGradient>
 <linearGradient id="edge" x1="0" y1="0" x2="1" y2="1">
  <stop stop-color="#C8A66B" stop-opacity=".76"/>
  <stop offset=".46" stop-color="#536C80" stop-opacity=".64"/>
  <stop offset="1" stop-color="#536C80" stop-opacity=".26"/>
 </linearGradient>
 <filter id="shadow" x="-15%" y="-15%" width="130%" height="150%">
  <feDropShadow dx="0" dy="22" stdDeviation="26" flood-color="#000B13" flood-opacity=".7"/>
 </filter>
</defs>"""


def frame(x, y, width, height):
    # A documented top crop removes only a clipped heading at the viewport edge.
    # Original pixels, result labels and all retained interface content stay intact.
    if not 0 <= args.crop_top < args.source_height:
        raise ValueError("Invalid crop")
    crop_height = args.source_height - args.crop_top
    height = round(width * crop_height / args.source_width, 3)
    return f"""<g filter="url(#shadow)">
 <rect x="{x}" y="{y-40}" width="{width}" height="{height+40}" rx="12" fill="#0C1E2B" stroke="url(#edge)"/>
 <text x="{x+20}" y="{y-14}" fill="#A0B2C1" font-size="11" letter-spacing="1.8">AUTHZLEDGER STUDIO / LOCAL SYNTHETIC LAB</text>
 <circle cx="{x+width-24}" cy="{y-20}" r="3" fill="#C8A66B"/>
 <svg x="{x}" y="{y}" width="{width}" height="{height}" viewBox="0 {args.crop_top} {args.source_width} {crop_height}" overflow="hidden">
  <image width="{args.source_width}" height="{args.source_height}" href="{image_uri}"/>
 </svg>
</g>"""


def svg(width, height, content):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title description">
<title id="title">AuthzLedger {version} · 0xFarag</title>
<desc id="description">An actual Studio capture from the local synthetic authorization lab. The top {args.crop_top} viewport pixels are cropped; all displayed interface content is unmodified. Navy and Gold framing follows the original 0xFarag identity.</desc>
{defs}
<rect width="{width}" height="{height}" fill="#071722"/>
<rect width="{width}" height="{height}" fill="url(#light)"/>
<g font-family="DejaVu Sans, Arial, sans-serif">{content}</g>
</svg>\n'''


landscape = f"""
<path d="M72 62H112" stroke="#C8A66B" stroke-width="2"/>
<text x="128" y="67" fill="#C8A66B" font-size="14" letter-spacing="3">0xFARAG</text>
<text x="72" y="132" fill="#EDF5F7" font-size="38" font-weight="bold" letter-spacing="-1.6">AuthzLedger</text>
<text x="72" y="166" fill="#A0B2C1" font-size="17" letter-spacing="1">{version}</text>
<text x="72" y="292" fill="#EDF5F7" font-size="60" font-weight="bold" letter-spacing="-2.2">Show the</text>
<text x="72" y="364" fill="#EDF5F7" font-size="60" font-weight="bold" letter-spacing="-2.2">boundary.</text>
<text x="72" y="454" fill="#C8A66B" font-size="60" font-weight="bold" letter-spacing="-2.2">Keep the</text>
<text x="72" y="526" fill="#C8A66B" font-size="60" font-weight="bold" letter-spacing="-2.2">proof.</text>
<text x="76" y="602" fill="#A0B2C1" font-size="21">Local authorization experiments.</text>
<text x="76" y="636" fill="#A0B2C1" font-size="21">Controls attached to every finding.</text>
<text x="76" y="670" fill="#A0B2C1" font-size="21">A signed, reviewable handover.</text>
<path d="M76 736H428" stroke="#2B4151"/>
<text x="76" y="772" fill="#C8A66B" font-size="12" letter-spacing="1.7">RULE → CONTROLS → OBSERVATION</text>
{frame(552,176,1000,750)}
<text x="76" y="950" fill="#A0B2C1" font-size="13">github.com/0xFarag/0xFarag</text>
<text x="1552" y="958" fill="#A0B2C1" font-size="11" text-anchor="end">Actual Studio capture · Synthetic local fixture</text>
"""

portrait = f"""
<path d="M56 58H96" stroke="#C8A66B" stroke-width="2"/>
<text x="112" y="63" fill="#C8A66B" font-size="14" letter-spacing="3">0xFARAG</text>
<text x="1024" y="63" fill="#A0B2C1" font-size="14" text-anchor="end">AuthzLedger {version}</text>
<text x="56" y="170" fill="#EDF5F7" font-size="65" font-weight="bold" letter-spacing="-2.2">Show the boundary.</text>
<text x="56" y="250" fill="#C8A66B" font-size="65" font-weight="bold" letter-spacing="-2.2">Keep the proof.</text>
<text x="60" y="306" fill="#A0B2C1" font-size="22">Local experiments. Reviewable evidence. Signed handover.</text>
{frame(56,404,968,726)}
<text x="56" y="1172" fill="#A0B2C1" font-size="14">Actual Studio capture · Synthetic local fixture</text>
<path d="M56 1220H1024" stroke="#2B4151"/>
<text x="56" y="1270" fill="#EDF5F7" font-size="21">github.com/0xFarag/0xFarag</text>
<text x="1024" y="1315" fill="#A0B2C1" font-size="11" text-anchor="end">© 2026 Nasser Aldin Farag / 0xFarag</text>
"""

for name, width, height, content in [
    ("launch-landscape", 1600, 1000, landscape),
    ("launch-portrait", 1080, 1350, portrait),
]:
    (args.out / f"{name}.svg").write_text(svg(width, height, content))

(args.out / "studio-source.png").write_bytes(payload)
metadata = {
    "product": "AuthzLedger",
    "version": args.version,
    "capture_receipt": receipt,
    "source_capture": {
        "file": "studio-source.png",
        "sha256": sha(args.source),
        "dimensions": [args.source_width, args.source_height],
        "nature": "Actual Studio screenshot from synthetic local browser acceptance fixture",
        "crop": [0, args.crop_top, args.source_width, args.source_height - args.crop_top],
        "transform": "Documented top crop and uniform scaling only. Displayed pixels are not retouched; complete original source is retained.",
    },
    "palette": {"navy": "#071722", "gold": "#C8A66B", "text": "#EDF5F7"},
    "variants": ["launch-landscape.svg", "launch-portrait.svg"],
    "release_status": "Version label only; this asset is not evidence of publication or release-gate completion",
}
if args.code_commit:
    metadata["code_commit"] = args.code_commit
(args.out / "provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
print(json.dumps(metadata))
