"""Signed presentation files for AuthzLedger Team.
© Nasser Aldin Farag (0xFarag). All rights reserved.
"""
import base64
from html import escape
import io
from zipfile import BadZipFile, ZipFile, ZIP_STORED

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .evidence_formats import canonical, read_json, sha


RIGHTS = "© Nasser Aldin Farag (0xFarag). All rights reserved."
DOCUMENT_SCHEMA = "authzledger.team-document.v1"
DOCUMENT_CONTEXT = (DOCUMENT_SCHEMA + "\n").encode("ascii")
# The archive is sent through a 4 MiB JSON API as Base64. Bounded, stored
# entries can be inspected without extracting paths or decompressing content.
MAX_ARCHIVE = 3 * 1024 * 1024 - 4096
SUPPORTED = ("html", "pdf")
REF_LABELS = {
    "de": ("Befund", "Kontrolle", "Retest", "Retest-Kontrolle", "Fall", "Quellen"),
    "en": ("Finding", "Control", "Retest", "Retest control", "Case", "Sources"),
    "fr": ("Constat", "Contrôle", "Nouveau test", "Contrôle du nouveau test", "Dossier", "Sources"),
    "it": ("Riscontro", "Controllo", "Retest", "Controllo del retest", "Caso", "Fonti"),
    "ar": ("النتيجة", "الضبط", "إعادة الاختبار", "ضبط إعادة الاختبار", "الحالة", "المصادر"),
}


def render_html(report, manifest):
    """A standalone, script-free customer report containing the signed projection only."""
    esc = lambda value: escape(str(value), quote=True)
    lang = report["language"]
    names = REF_LABELS[lang]
    parts = [
        '<!doctype html>', f'<html lang="{esc(lang)}" dir="{esc(report["direction"])}"><head>',
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
        f'<meta name="copyright" content="{esc(RIGHTS)}"><title>AuthzLedger · {esc(report["title"])}</title>',
        '<style>:root{font:100%/1.55 system-ui,sans-serif;color:#071722;background:#fff}body{max-width:64rem;margin:auto;padding:1.5rem}header{border-bottom:3px solid #C8A66B}h2{margin-top:2rem}dt{font-weight:600}dd{margin:0 0 .6rem}code,bdi{overflow-wrap:anywhere}article{padding:.5rem 0;border-top:1px solid #b7cac9}footer{border-top:1px solid #C8A66B;margin-top:2rem;padding-top:.6rem}@media print{body{padding:0}h2,h3{break-after:avoid}li{break-inside:avoid}}</style></head><body>',
        f'<header><p>AuthzLedger</p><h1>{esc(report["title"])}</h1></header>',
        f'<p>{esc(names[4])} <bdi>{esc(manifest["case_id"])}</bdi> · <bdi>{esc(manifest["created_at"])}</bdi></p>',
        f'<h2>{esc(report["summary_heading"])}</h2><dl>',
    ]
    for key in ("findings", "hint", "confirmed", "not_retested", "fix_verified", "persists", "inconclusive"):
        parts.append(f'<dt>{esc(report["labels"][key])}</dt><dd>{esc(report["counts"][key])}</dd>')
    parts.extend(['</dl>', f'<p>{esc(report["limitations"])}</p>',
                  f'<h2>{esc(report["appendix_heading"])}</h2>'])
    for item in report["appendix"]:
        parts.extend([f'<article><h3><bdi>{esc(item["id"])}</bdi></h3>',
                      f'<p>{esc(item["status_label"])} · {esc(item["retest_label"])}<br>',
                      f'<code dir="ltr">{esc(item["status"])} / {esc(item["retest"])}</code></p>',
                      f'<p>SHA-256 <code dir="ltr">{esc(item["finding_sha256"])}</code></p><dl>'])
        for label, field in zip(names, ("evidence", "control", "retest_evidence", "retest_control")):
            source = item[field]
            if source:
                parts.extend([f'<dt>{esc(label)}</dt>',
                              f'<dd><bdi>{esc(source["format"])} #{esc(source["record"])}</bdi><br>',
                              f'SHA-256 <code dir="ltr">{esc(source["sha256"])}</code><br>',
                              f'<code dir="ltr">{esc(source["fingerprint"])}</code></dd>'])
        parts.append('</dl></article>')
    parts.append(f'<h2>{esc(names[5])}</h2><ul>')
    for source in manifest["sources"]:
        parts.append(f'<li><bdi>{esc(source["format"])} · {esc(source["id"])}</bdi><br>SHA-256 <code dir="ltr">{esc(source["sha256"])}</code></li>')
    parts.append(f'</ul><footer>{esc(RIGHTS)}</footer></body></html>')
    return "\n".join(parts).encode("utf-8")


def statement(package, fmt, document):
    manifest = package["manifest"]
    return {"schema": DOCUMENT_SCHEMA, "algorithm": "Ed25519", "format": fmt,
            "handover_sha256": sha(canonical(package)), "sha256": sha(document), "bytes": len(document),
            "fingerprint": manifest["fingerprint"], "team_id": manifest["team_id"], "case_id": manifest["case_id"],
            "scope_sha256": package["report"]["scope_sha256"], "rights": RIGHTS}


def build_archive(package, fmt, signing_key):
    from .evidence import require
    require(fmt in SUPPORTED, "Unknown document format")
    if fmt == "pdf":
        from .report_pdf import render_pdf
        document = render_pdf(package["report"], package["manifest"])
    else:
        document = render_html(package["report"], package["manifest"])
    description = statement(package, fmt, document)
    signed = signing_key.sign(DOCUMENT_CONTEXT + canonical(description))
    proof = {"handover": package, "document": description, "signature": base64.b64encode(signed).decode("ascii")}
    output = io.BytesIO()
    with ZipFile(output, "w", compression=ZIP_STORED) as archive:
        archive.comment = RIGHTS.encode("utf-8")
        archive.writestr("report." + fmt, document)
        archive.writestr("proof.json", canonical(proof))
    require(output.tell() <= MAX_ARCHIVE, "Rendered handover exceeds the size limit", 413)
    return output.getvalue()


def verify_document(proof, document, trusted_key, team=None, expected_format=None):
    from .evidence import verify_package
    invalid = {"valid": False, "reason": "invalid_or_untrusted", "fingerprint": None}
    try:
        if set(proof) != {"handover", "document", "signature"} or not isinstance(document, bytes):
            return invalid
        fmt = proof["document"]["format"]
        if fmt not in SUPPORTED or (expected_format and expected_format != fmt):
            return invalid
        package = proof["handover"]
        verified = verify_package(package, trusted_key, team)
        if not verified["valid"] or canonical(proof["document"]) != canonical(statement(package, fmt, document)):
            return invalid
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_key["public_key"], validate=True))
        key.verify(base64.b64decode(proof["signature"], validate=True), DOCUMENT_CONTEXT + canonical(proof["document"]))
        return {**verified, "format": fmt, "document_sha256": proof["document"]["sha256"], "report": package["report"]}
    except (InvalidSignature, ValueError, KeyError, TypeError, RecursionError, AttributeError, OverflowError):
        return invalid


def verify_archive(raw, trusted_key, team=None):
    invalid = {"valid": False, "reason": "invalid_or_untrusted", "fingerprint": None}
    try:
        if not 0 < len(raw) <= MAX_ARCHIVE:
            return invalid
        with ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = sorted(item.filename for item in entries)
            if names not in (["proof.json", "report.html"], ["proof.json", "report.pdf"]):
                return invalid
            if any(item.compress_type != ZIP_STORED or item.file_size != item.compress_size or
                   item.flag_bits & 1 or item.file_size > MAX_ARCHIVE for item in entries):
                return invalid
            proof = read_json(archive.read("proof.json").decode("utf-8"))
            return verify_document(proof, archive.read(names[1]), trusted_key, team, names[1].split(".")[1])
    except (ValueError, TypeError, BadZipFile, EOFError, OSError, RecursionError, RuntimeError):
        return invalid
