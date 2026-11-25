"""Workspace-scoped signing and source-bound report verification.
© Nasser Aldin Farag (0xFarag). All rights reserved.
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import hmac
from html import escape
from io import BytesIO
import json
import os
from zipfile import ZipFile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfdoc
from reportlab.pdfgen.canvas import Canvas

from . import keyring
from .proof_verify import (MAX_BYTES, RIGHTS, SCHEMA, archive_bytes, canonical, document_inventory,
                           digest, encode64, public_descriptor, verify_bytes)
from .report_pdf import ReportLayout

LANGUAGES = ("de", "en", "fr")
MASTER = "proof-workspaces.kek"
CAPTIONS = {
    "title": ("Beweisübergabe", "Evidence handover", "Remise des preuves"),
    "workspace": ("Workspace", "Workspace", "Espace de travail"),
    "scope": ("Geltungsbereich", "Scope", "Périmètre"),
    "budget": ("Verbrauchtes Budget", "Budget used", "Budget consommé"),
    "keyId": ("Schlüssel", "Signing key", "Clé de signature"),
    "fingerprint": ("Fingerabdruck", "Fingerprint", "Empreinte"),
    "findings": ("Beobachtungen und Ergebnisse", "Observations and results", "Observations et résultats"),
    "controls": ("Controls und Abhängigkeiten", "Controls and dependencies", "Contrôles et dépendances"),
    "retests": ("Quellgebundene Retests", "Source-bound retests", "Recontrôles liés aux sources"),
    "coverage": ("Retest-Abdeckung", "Retest coverage", "Couverture des recontrôles"),
    "roots": ("Gebundene Quellen", "Bound sources", "Sources liées"),
    "attachment": ("Der vollständige Bericht liegt als eingebettete report.json im PDF vor.",
                   "The complete report is embedded in this PDF as report.json.",
                   "Le rapport complet est intégré au PDF dans le fichier report.json."),
    "data": ("Vollständiger signierter Bericht", "Complete signed report", "Rapport signé complet"),
    "limit": ("Die Signatur belegt die inventarisierten Bytes. Die Richtigkeit einer entfernten Ausführung wird dadurch nicht belegt.",
              "The signature authenticates the inventoried bytes. It does not attest to execution on a remote system.",
              "La signature authentifie les octets inventoriés. Elle ne certifie pas une exécution sur un système distant."),
}


def init_db(db):
    db.execute("""CREATE TABLE IF NOT EXISTS proof_workspace_keys (
        workspace TEXT NOT NULL, key_id TEXT NOT NULL, public BLOB NOT NULL, wrapped_seed BLOB,
        created TEXT NOT NULL, retired TEXT, PRIMARY KEY(workspace,key_id),
        CHECK((retired IS NULL) = (wrapped_seed IS NOT NULL)))""")
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS proof_workspace_active
        ON proof_workspace_keys(workspace) WHERE retired IS NULL""")
    db.execute("""CREATE TABLE IF NOT EXISTS proof_workspace_seals(
        workspace TEXT PRIMARY KEY, mac BLOB NOT NULL)""")


def _begin(db, workspace):
    if not isinstance(workspace, str) or not 0 < len(workspace) <= 128:
        raise ValueError("Invalid workspace")
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    init_db(db)


def _master_key(db, data_dir):
    """Dedicated protected master key; database backups alone cannot decrypt active seeds."""
    directory = keyring._directory(data_dir)
    try:
        wrapped = keyring._read(directory / MASTER)
    except FileNotFoundError:
        if db.execute("SELECT 1 FROM proof_workspace_keys LIMIT 1").fetchone():
            raise keyring.KeyStoreError("Workspace key store is missing; restore the matching key backup") from None
        master = AESGCM.generate_key(bit_length=256)
        wrapped = keyring._dpapi(master, decrypt=False) if os.name == "nt" else master
        keyring._store(directory, MASTER, wrapped)
    master = keyring._dpapi(wrapped, decrypt=True) if os.name == "nt" else wrapped
    if len(master) != 32:
        raise keyring.KeyStoreError("Invalid workspace key store")
    return master


def _ring_rows(db, workspace):
    return list(db.execute("SELECT key_id,public,created,retired,wrapped_seed FROM proof_workspace_keys "
                           "WHERE workspace=? ORDER BY rowid", (workspace,)))


def _ring_mac(master, workspace, rows):
    # Split authentication of historical pins from encryption of the current signing seed.
    mac_key = hmac.digest(master, b"authzledger.workspace-pin-history.v1", hashlib.sha256)
    data = [[kid, encode64(public), created, retired, digest(wrapped) if wrapped is not None else None]
            for kid, public, created, retired, wrapped in rows]
    return hmac.digest(mac_key, canonical([workspace, data]), hashlib.sha256)


def _check_history(db, workspace, master):
    rows = _ring_rows(db, workspace)
    stamp = db.execute("SELECT mac FROM proof_workspace_seals WHERE workspace=?", (workspace,)).fetchone()
    if rows or stamp:
        if not (rows and stamp and hmac.compare_digest(_ring_mac(master, workspace, rows), stamp[0])):
            raise keyring.KeyStoreError("Workspace signing history failed authentication")
    return rows


def _binding(workspace, kid):
    return canonical({"schema": "authzledger.workspace-seed.v1", "workspace": workspace, "keyId": kid})


def _stamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _new_key(db, data_dir, workspace):
    master = _master_key(db, data_dir)
    _check_history(db, workspace, master)
    vault = AESGCM(master)
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    desc = public_descriptor(raw)
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    nonce = os.urandom(12)
    wrapped = nonce + vault.encrypt(nonce, seed, _binding(workspace, desc["keyId"]))
    stamp = _stamp()
    # Both retirement and registration are committed with the caller's audit event.
    db.execute("UPDATE proof_workspace_keys SET retired=?,wrapped_seed=NULL WHERE workspace=? AND retired IS NULL",
               (stamp, workspace))
    db.execute("INSERT INTO proof_workspace_keys VALUES(?,?,?,?,?,NULL)",
               (workspace, desc["keyId"], raw, wrapped, stamp))
    seal = _ring_mac(master, workspace, _ring_rows(db, workspace))
    db.execute("INSERT OR REPLACE INTO proof_workspace_seals VALUES(?,?)", (workspace, seal))
    return {**desc, "active": True, "created": stamp, "retired": None}


def rotate_key(db, data_dir, workspace):
    """Manual rotation only. The API authorizes the actor and commits its audit event."""
    _begin(db, workspace)
    return _new_key(db, data_dir, workspace)


def key_history(db, data_dir, workspace):
    _begin(db, workspace)
    rows = _check_history(db, workspace, _master_key(db, data_dir))
    if not rows:
        entries = [_new_key(db, data_dir, workspace)]
    else:
        entries = [{**public_descriptor(public), "created": created, "retired": retired, "active": retired is None}
                   for _, public, created, retired, _ in reversed(rows)]
    if sum(entry["active"] for entry in entries) != 1 or not entries[0]["active"]:
        raise keyring.KeyStoreError("Workspace signing history is inconsistent")
    return {"activeKeyId": entries[0]["keyId"], "keys": entries}


def _active_signer(db, data_dir, workspace):
    history = key_history(db, data_dir, workspace)
    desc = history["keys"][0]
    row = db.execute("SELECT wrapped_seed FROM proof_workspace_keys WHERE workspace=? AND key_id=? AND retired IS NULL",
                     (workspace, desc["keyId"])).fetchone()
    wrapped = row[0]
    try:
        seed = AESGCM(_master_key(db, data_dir)).decrypt(wrapped[:12], wrapped[12:], _binding(workspace, desc["keyId"]))
        key = Ed25519PrivateKey.from_private_bytes(seed)
    except (ValueError, InvalidTag, TypeError):
        raise keyring.KeyStoreError("Workspace key cannot be opened; restore the matching key backup") from None
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public_descriptor(raw)["keyId"] != desc["keyId"]:
        raise keyring.KeyStoreError("Workspace key identity mismatch")
    return key, desc


def _label(report, name):
    return CAPTIONS[name][LANGUAGES.index(report["language"])]


def _pretty(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)


def _overview(report):
    spent = report["spent"]
    return (("workspace", report["workspace"]), ("budget", f'{spent} / {report["budget"]}'),
            ("keyId", report["keyId"]), ("fingerprint", report["fingerprint"]))


def _sections(report):
    latest = {entry["id"]: entry for entry in report["retests"]}
    controls = [(name, (f"intended={str(row['intended']).lower()} / effective={str(row['effective']).lower()} / "
                        f"dependsOn={', '.join(row['dependsOn']) or '[]'}")) for name, row in sorted(report["controls"].items())]
    findings = []
    for finding in report["findings"]:
        seen = finding["observation"]
        retest = latest[finding["id"]]
        status = "?" if seen["status"] is None else str(seen["status"])
        findings.append((f"{seen['method']} {seen['host']}{seen['path']}",
                         f"{finding['id']} / {seen['source']} / HTTP {status} / {finding['status']} / "
                         f"{retest['status']} ({retest['reason']})"))
    roots = [("contractRoot", report["contractRoot"]), ("evidenceRoot", report["evidenceRoot"])]
    roots.extend((source["format"], source["sha256"]) for source in report["source"])
    return (("scope", [(", ".join(report["scope"]["hosts"]), report["scope"]["roe"])]),
            ("coverage", [(key, str(value)) for key, value in sorted(report["coverage"].items())]),
            ("controls", controls), ("findings", findings), ("roots", roots))


def _attach_report(pdf, body):
    # Retain every source and transitive control in a machine-readable, offline PDF attachment.
    name = pdfdoc.PDFString("report.json")
    stream = pdfdoc.PDFStream(pdfdoc.PDFDictionary({"Type": pdfdoc.PDFName("EmbeddedFile"),
                                                     "Subtype": "/application#2Fjson"}), body,
                              filters=[pdfdoc.PDFZCompress])
    file_spec = pdfdoc.PDFDictionary({"Type": pdfdoc.PDFName("Filespec"), "F": name,
                                     "EF": pdfdoc.PDFDictionary({"F": pdf._doc.Reference(stream)})})
    names = pdfdoc.PDFArray([name, pdf._doc.Reference(file_spec)])
    pdf._doc.Catalog.Names = pdfdoc.PDFDictionary({"EmbeddedFiles": pdfdoc.PDFDictionary({"Names": names})})


def render_html(report):
    """A script-free document; both presentation formats use the frozen report body."""
    parts = [
        '<!doctype html>', f'<html lang="{report["language"]}"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f'<title>AuthzLedger · {escape(_label(report, "title"))}</title>',
        '<style>body{max-width:60rem;margin:2rem auto;padding:0 1.5rem;color:#071722;font:1rem/1.55 system-ui,sans-serif}'
        'header{border-bottom:2px solid #43d6cf}header p{color:#765927}dt,h2{font-weight:650}dd{margin:0 0 .8rem}'
        'pre,dd{white-space:pre-wrap;overflow-wrap:anywhere}footer{border-top:1px solid #c8a66b;padding-top:1rem}'
        '@media print{details{display:block}body{margin:0}}</style></head><body>',
        f'<header><p>0xFarag · Show the proof.</p><h1>AuthzLedger · {_label(report,"title")}</h1></header><dl>',
    ]
    for name, value in _overview(report):
        parts.append(f'<dt>{_label(report,name)}</dt><dd>{escape(value)}</dd>')
    parts.extend(['</dl>', f'<p>{_label(report,"limit")}</p>'])
    for name, rows in _sections(report):
        parts.append(f'<section><h2>{_label(report,name)}</h2><dl>')
        for label, value in rows:
            parts.append(f'<dt>{escape(label)}</dt><dd>{escape(value)}</dd>')
        parts.append('</dl></section>')
    parts.append(f'<details><summary>{_label(report,"data")}</summary><pre>{escape(_pretty(report))}</pre></details>')
    parts.append(f'<footer>{RIGHTS}</footer></body></html>')
    return "\n".join(parts).encode("utf-8")


def render_pdf(report):
    output = BytesIO()
    pdf = Canvas(output, pagesize=A4, invariant=1, pageCompression=1)
    pdf.setTitle(f'AuthzLedger · {_label(report,"title")}')
    pdf.setAuthor("Nasser Aldin Farag (0xFarag)")
    pdf.setSubject(RIGHTS)
    layout = ReportLayout(pdf, rtl=False)
    layout.text("0xFarag / Show the proof.", 10)
    layout.section(_label(report, "title"))
    for name, value in _overview(report):
        layout.pair(_label(report, name), value)
    layout.text(_label(report, "limit"))
    for name, rows in _sections(report):
        layout.section(_label(report, name))
        for label, value in rows:
            layout.pair(label, value)
    layout.text(_label(report, "attachment"))
    _attach_report(pdf, canonical(report))
    pdf.save()
    return output.getvalue()


def _check_body(report):
    from .proof_engine import verify_semantics
    if not isinstance(report, dict) or not report.get("controls") or not report.get("findings"):
        raise ValueError("A report needs evaluated observations and controls")
    if not isinstance(report.get("retests"), list):
        raise ValueError("A report needs explicit retest coverage")
    if report.get("rights") != RIGHTS:
        raise ValueError("Missing report rights")
    allowed = {"product", "method", "scope", "budget", "spent", "source", "controls", "findings",
               "evidenceRoot", "contractRoot", "graph", "rights", "assurance", "retests", "retestRuns",
               "language", "workspace", "keyId", "fingerprint", "publicKey", "coverage"}
    if set(report) - allowed:
        raise ValueError("Unexpected report fields")
    if verify_semantics(report) is not True:
        raise ValueError("Source-bound proof verification failed")


def _coverage(report):
    result = Counter(row["status"] for row in report["retests"])
    result.setdefault("not_retested", 0)
    return dict(result)


def sign_package(db, data_dir, workspace, report, language="de"):
    if language not in LANGUAGES:
        raise ValueError("Unsupported report language")
    _check_body(report)
    if len(canonical(report)) > 512 * 1024:
        raise ValueError("Report exceeds the handover size limit")
    key, desc = _active_signer(db, data_dir, workspace)
    body = dict(report, language=language, workspace=workspace, keyId=desc["keyId"],
                fingerprint=desc["fingerprint"], publicKey=desc["jwk"], coverage=_coverage(report))
    parts = {"report.json": canonical(body), "report.html": render_html(body), "report.pdf": render_pdf(body)}
    inventory = {"schema": SCHEMA, "workspace": workspace, "rights": RIGHTS, **public_descriptor(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "files": document_inventory(parts)}
    parts["inventory.json"] = canonical(inventory)
    parts["signature.ed25519"] = key.sign(parts["inventory.json"])
    archive = archive_bytes(parts)
    if len(archive) > MAX_BYTES:
        raise ValueError("Package exceeds the handover size limit")
    return archive


def verify_package(archive, trusted_jwk, workspace=None):
    """In addition to the standalone byte checks, replay claims against the original sources."""
    report = verify_bytes(archive, trusted_jwk, workspace)
    _check_body(report)
    if report.get("language") not in LANGUAGES or report.get("coverage") != _coverage(report):
        raise ValueError("Invalid language or retest coverage")
    with ZipFile(BytesIO(archive)) as bundle:
        if render_html(report) != bundle.read("report.html") or render_pdf(report) != bundle.read("report.pdf"):
            raise ValueError("Presentation differs from the source-bound report")
    return report
