# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Passive, team-scoped evidence review, retests and verifiable customer handovers."""
import argparse
import base64
import hmac
import json
from pathlib import Path
import re
import uuid
from datetime import datetime, timezone
from xml.etree.ElementTree import ParseError

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import keyring, review_records
from .keyring import key_descriptor  # Existing public Python API.
from .documents import RIGHTS, MAX_ARCHIVE, SUPPORTED, build_archive, verify_archive, verify_document
from .evidence_formats import FORMATS, MAX_FILE, MAX_ROWS, canonical, host, parse_records, read_json, sha

LANGS = ("de", "en", "fr", "it", "ar")
SCHEMA = "authzledger.team-handover.v1"
EVIDENCE_INDEX_SCHEMA = "authzledger.evidence-index/v1"
SIGNING_CONTEXT = (SCHEMA + "\n").encode("ascii")
MAX_IMPORTS = 32
MAX_FINDINGS = 128
MAX_RETESTS = 384


class WorkflowError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def require(condition, message, status=400):
    if not condition:
        raise WorkflowError(status, message)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def string(value, label, maxlen):
    require(isinstance(value, str) and 0 < len(value.strip()) <= maxlen and len(value) <= maxlen
            and not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", value),
            "Invalid " + label)
    return value.strip()


def init_db(db):
    db.execute("""CREATE TABLE IF NOT EXISTS evidence_cases (
        team_id TEXT NOT NULL, id TEXT NOT NULL, document TEXT NOT NULL, PRIMARY KEY(team_id,id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS evidence_items (
        team_id TEXT NOT NULL, case_id TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, document TEXT NOT NULL,
        PRIMARY KEY(team_id,case_id,kind,id),
        FOREIGN KEY(team_id,case_id) REFERENCES evidence_cases(team_id,id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS evidence_bytes (
        team_id TEXT NOT NULL, case_id TEXT NOT NULL, import_id TEXT NOT NULL, attachment BLOB NOT NULL,
        PRIMARY KEY(team_id,case_id,import_id), FOREIGN KEY(team_id,case_id) REFERENCES evidence_cases(team_id,id))""")
    review_records.init_db(db)
    keyring.init_db(db)


def items(db, team, case, kind):
    rows = db.execute("SELECT document FROM evidence_items WHERE team_id=? AND case_id=? AND kind=? ORDER BY rowid", (team,case,kind))
    return [json.loads(r[0]) for r in rows]


def one(db, team, case, kind, key):
    require(isinstance(key, str), "Missing source-bound reference")
    row = db.execute("SELECT document FROM evidence_items WHERE team_id=? AND case_id=? AND kind=? AND id=?", (team,case,kind,key)).fetchone()
    require(row, "Unknown reference in this case", 404)
    return json.loads(row[0])


def store(db, team, case, kind, document):
    db.execute("INSERT INTO evidence_items(team_id,case_id,kind,id,document) VALUES(?,?,?,?,?)",
               (team,case,kind,document["id"],canonical(document).decode()))


def capacity(db, team, case, kind, limit):
    count = db.execute("SELECT count(*) FROM evidence_items WHERE team_id=? AND case_id=? AND kind=?", (team,case,kind)).fetchone()[0]
    require(count < limit, "Case capacity reached", 409)


def create_case(db, team, user, body):
    title = string(body.get("title"), "case title", 160)
    scope = string(body.get("scope"), "scope", 1200)
    supplied = body.get("assets", [scope])
    require(isinstance(supplied, list) and 1 <= len(supplied) <= 32, "Provide 1–32 scoped hostnames or IP addresses")
    assets = []
    for value in supplied:
        asset = string(value, "asset", 200)
        require("://" not in asset and host(asset), "Use an explicit hostname or IP address as the asset")
        assets.append(host(asset))
    require(len(assets) == len(set(assets)), "Duplicate scoped assets")
    case = {"id":uuid.uuid4().hex, "title":title, "scope":scope, "assets":assets, "created_at":now(), "created_by":user}
    db.execute("INSERT INTO evidence_cases VALUES(?,?,?)", (team, case["id"], canonical(case).decode()))
    return {"case":case}


def add_import(db, team, user, case, body):
    fmt = body.get("format")
    require(fmt in FORMATS, "Unsupported source format")
    encoded = body.get("content_b64")
    require(isinstance(encoded, str) and 0 < len(encoded) <= 4 * ((MAX_FILE + 2) // 3), "Original must be at most 1 MiB")
    try:
        raw = base64.b64decode(encoded, validate=True)
        require(0 < len(raw) <= MAX_FILE, "Original must be at most 1 MiB")
        digest = sha(raw)
        key = sha((fmt + ":" + digest).encode())
        existing = db.execute("SELECT document FROM evidence_items WHERE team_id=? AND case_id=? AND kind='imports' AND id=?",
                              (team,case["id"],key)).fetchone()
        if existing:
            return {"import":json.loads(existing[0]), "duplicate":True}
        capacity(db, team, case["id"], "imports", MAX_IMPORTS)
        records = parse_records(fmt, raw)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, OverflowError, ParseError, RecursionError):
        raise WorkflowError(400, "Invalid or unsupported source document") from None
    source = {"id":key,"format":fmt,"sha256":digest,"bytes":len(raw),"records":len(records),"entries":records,
              "created_at":now(),"created_by":user}
    store(db,team,case["id"],"imports",source)
    db.execute("INSERT INTO evidence_bytes VALUES(?,?,?,?)",(team,case["id"],key,raw))
    return {"import":source,"duplicate":False}


def reference(db, team, case_id, body, control=False):
    key, number = ("control_evidence_id", "control_record") if control else ("evidence_id","record")
    doc = one(db,team,case_id,"imports",body.get(key))
    n = body.get(number)
    require(type(n) is int and 1 <= n <= doc["records"], "Select a record within the attached source")
    return {"import_id":doc["id"],"format":doc["format"],"sha256":doc["sha256"],**doc["entries"][n-1]}


def checked_observations(db, team, case_id, asset, body, with_control):
    evidence = reference(db,team,case_id,body)
    asset_id = sha(asset.encode())
    require(evidence["asset_id"] in (None,asset_id), "Evidence asset is outside the selected scope")
    if not with_control:
        return evidence, None
    control = reference(db,team,case_id,body,True)
    require(evidence["asset_id"] == control["asset_id"] == asset_id, "Evidence and control must both identify the scoped asset")
    require(evidence["fingerprint"] != control["fingerprint"], "The control requires a distinct source observation")
    # Contracts, scanner assertions and discovered inventory are leads. They do
    # not document the observed application response and a comparable control.
    require(evidence["kind"] == control["kind"] == "http_exchange", "A confirmed observation and its control require captured HTTP exchanges")
    require(evidence.get("request_key") and control.get("request_key") and evidence.get("status_code") is not None and control.get("status_code") is not None,
            "Both HTTP exchanges require a recorded response status")
    expected = string(body.get("control_expected"), "control expectation", 2000)
    observed = string(body.get("control_observed"), "control observation", 2000)
    require(expected == observed, "Control expectation and observation do not match")
    return evidence, {"reference":control,"expected":expected,"observed":observed}


def source_endpoint(db, team, case_id, ref):
    """Earlier indexed imports can derive their endpoint from the retained original."""
    if ref.get("endpoint_key"):
        return ref["endpoint_key"]
    source = db.execute("SELECT attachment FROM evidence_bytes WHERE team_id=? AND case_id=? AND import_id=?",
                        (team, case_id, ref["import_id"])).fetchone()
    require(source and sha(source[0]) == ref["sha256"], "Stored source cannot be verified", 409)
    try:
        row = parse_records(ref["format"], source[0])[ref["record"] - 1]
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, ParseError, RecursionError):
        raise WorkflowError(400, "Source record has no comparable HTTP target") from None
    require(row["fingerprint"] == ref["fingerprint"], "Stored source observation differs", 409)
    return row.get("endpoint_key")


def add_finding(db,team,user,case,body):
    case_id = case["id"]
    capacity(db,team,case_id,"findings",MAX_FINDINGS)
    title = string(body.get("title"),"finding title",160)
    expected = string(body.get("expected"),"expected behaviour",2000)
    observed = string(body.get("observed"),"observed behaviour",2000)
    asset = host(string(body.get("asset"),"asset",200))
    require(asset in case["assets"],"Asset is outside the case scope")
    status = body.get("status")
    require(status in ("hint","confirmed"),"Unknown finding status")
    require(status != "confirmed" or expected != observed, "A confirmed deviation needs distinct expected and observed results")
    ref, control = checked_observations(db,team,case_id,asset,body,status == "confirmed")
    finding = {"id":uuid.uuid4().hex, "title":title, "asset":asset, "expected":expected, "observed":observed, "status":status,
               "evidence":ref, "control":control,"basis":"passive_human_review","created_at":now(),"created_by":user}
    if "zap_lead" in body:
        lead = body["zap_lead"]
        require(status == "confirmed" and isinstance(lead, dict) and set(lead) == {"import_id", "record"},
                "A linked ZAP lead requires a confirmed finding and a source record")
        alert = reference(db, team, case_id, {"evidence_id": lead["import_id"], "record": lead["record"]})
        require(alert["format"] == "zap" and alert["kind"] == "scanner_alert" and alert["asset_id"] == ref["asset_id"],
                "ZAP lead must identify the same scoped asset")
        endpoint = source_endpoint(db, team, case_id, alert)
        require(endpoint and endpoint == source_endpoint(db, team, case_id, ref),
                "ZAP instance and observation must share the same HTTP method and target")
        finding["scanner_lead"] = public_ref(alert)
    finding["finding_sha256"] = sha(canonical(finding))
    store(db,team,case_id,"findings",finding)
    return {"finding":finding}


def add_retest(db,team,user,case,body):
    case_id = case["id"]
    capacity(db,team,case_id,"retests",MAX_RETESTS)
    finding = one(db,team,case_id,"findings",body.get("finding_id"))
    status = body.get("status")
    require(status in ("not_retested","fix_verified","persists","inconclusive"),"Unknown retest status")
    ref = control = observed = None
    if status == "not_retested":
        require(all(body.get(k) in (None,"") for k in ("evidence_id","record","control_evidence_id","control_record","observed","control_expected","control_observed")),
                "A skipped retest cannot contain a new observation")
    else:
        strong = status in ("fix_verified","persists")
        require(not strong or finding["status"] == "confirmed", "A fix or persistent finding requires a confirmed baseline")
        observed = string(body.get("observed"),"retest observation",2000)
        ref, control = checked_observations(db,team,case_id,finding["asset"],body,strong)
        baseline = [finding["evidence"]]
        if finding["control"]:
            baseline.append(finding["control"]["reference"])
        for current in [ref] + ([control["reference"]] if control else []):
            require(all(current["sha256"] != original["sha256"] and current["fingerprint"] != original["fingerprint"] for original in baseline),
                    "Retest requires new source bytes and fresh observations")
        if strong:
            require(ref["request_key"] == finding["evidence"]["request_key"] and
                    control["reference"]["request_key"] == finding["control"]["reference"]["request_key"],
                    "Retest observation and control must repeat their original method and target")
            require(control["expected"] == finding["control"]["expected"],"Retest control expectation differs from the baseline control")
            target = finding["expected" if status == "fix_verified" else "observed"]
            require(observed == target,"Retest observation does not match the declared outcome")
    retest = {"id":uuid.uuid4().hex,"finding_id":finding["id"],"baseline_sha256":finding["finding_sha256"],"status":status,
              "observed":observed,"evidence":ref,"control":control,"created_at":now(),"created_by":user}
    store(db,team,case_id,"retests",retest)
    return {"retest":retest}


_REPORT = {
    "heading": ("Kundenbericht","Client report","Rapport client","Rapporto per il cliente","تقرير العميل"),
    "summary": ("Managementübersicht","Executive summary","Synthèse","Sintesi","الملخص التنفيذي"),
    "appendix": ("Technischer Beleganhang","Technical evidence appendix","Annexe technique des preuves","Allegato tecnico delle evidenze","ملحق الأدلة التقنية"),
    "findings": ("Dokumentierte Fälle","Documented findings","Constats documentés","Riscontri documentati","النتائج الموثّقة"),
    "hint": ("Unbestätigte Hinweise","Unconfirmed hints","Indices non confirmés","Indizi non confermati","ملاحظات غير مؤكدة"),
    "confirmed": ("Manuell bestätigte Befunde","Manually confirmed findings","Constats confirmés manuellement","Riscontri confermati manualmente","نتائج تم تأكيدها يدوياً"),
    "not_retested": ("Nicht nachgeprüft","Not retested","Non retestés","Non verificati di nuovo","لم يُعَد اختبارها"),
    "fix_verified": ("Behebung nachgeprüft","Fix checked","Corrections vérifiées","Correzioni verificate","إصلاحات جرى التحقق منها"),
    "persists": ("Befund besteht weiter","Finding persists","Constats persistants","Problemi persistenti","نتائج ما زالت قائمة"),
    "inconclusive": ("Retest ohne eindeutiges Ergebnis","Inconclusive retest","Nouveaux tests non concluants","Nuovi test inconcludenti","إعادات اختبار غير حاسمة"),
    "limit": ("Die Ergebnisse beruhen auf dokumentierten menschlichen Entscheidungen und passiven Quelldateien. Die Signatur schützt die Integrität der Übergabe. Jede SHA-256-Referenz kann mit dem getrennt aufbewahrten Original verglichen werden.",
              "Results are based on documented human decisions and passive source files. The signature protects handover integrity. Each SHA-256 reference can be compared with the separately retained original.",
              "Les résultats reposent sur des décisions humaines documentées et des sources passives. La signature protège l’intégrité du livrable. Chaque référence SHA-256 peut être comparée à l’original conservé séparément.",
              "I risultati si basano su decisioni umane documentate e file sorgente passivi. La firma protegge l’integrità della consegna. Ogni riferimento SHA-256 può essere confrontato con l’originale conservato separatamente.",
              "تستند النتائج إلى قرارات بشرية موثقة وملفات أدلة جُمعت بصورة سلبية. يحمي التوقيع سلامة حزمة التسليم. يمكن مقارنة كل بصمة SHA-256 بالملف الأصلي المحفوظ بشكل منفصل.")
}


def signer(db, data_dir, *, rotate=True):
    try:
        return keyring.signer(db, data_dir, rotate=rotate)
    except keyring.KeyStoreError as error:
        raise WorkflowError(error.status, error.message) from error


def key_history(db, data_dir):
    try:
        return keyring.history(db, data_dir)
    except keyring.KeyStoreError as error:
        raise WorkflowError(error.status, error.message) from error


def public_ref(value):
    if value is None:
        return None
    return {k:value[k] for k in ("format","sha256","record","fingerprint","asset_id")}


def minimal_observations(primary, control):
    result = []
    for role, reference in (("evidence", primary), ("control", control)):
        if reference is not None:
            result.append({"role": role, **{k: reference[k] for k in ("format", "sha256", "record", "fingerprint")}})
    return result


def finding_indices(db, team, case_id, findings):
    hashes = {finding["id"]: finding["finding_sha256"] for finding in findings}
    experiments = review_records.handover_experiments(db, team, case_id, hashes)
    indices = {}
    for finding in findings:
        control = finding["control"]["reference"] if finding["control"] else None
        indices[finding["id"]] = {
            "observations": minimal_observations(finding["evidence"], control),
            "experiments": experiments.get(finding["id"], []),
        }
    return indices


def checked_index_sources(manifest):
    entries = manifest["sources"]
    if not isinstance(entries, list) or len(entries) > MAX_IMPORTS:
        raise ValueError("Invalid source inventory")
    sources = {}
    for source in entries:
        identity = (source["format"], source["sha256"])
        if (identity in sources or source["format"] not in FORMATS or not re.fullmatch("[0-9a-f]{64}", source["sha256"])
                or type(source["records"]) is not int or not 0 <= source["records"] <= MAX_ROWS
                or type(source["bytes"]) is not int or not 1 <= source["bytes"] <= MAX_FILE):
            raise ValueError("Invalid indexed source")
        sources[identity] = source["records"]
    return sources


def check_index_reference(observation, sources):
    if observation is None:
        return
    limit = sources.get((observation["format"], observation["sha256"]), 0)
    asset = observation["asset_id"]
    if (type(observation["record"]) is not int or not 1 <= observation["record"] <= limit
            or not re.fullmatch("[0-9a-f]{64}", observation["fingerprint"])
            or (asset is not None and not re.fullmatch("[0-9a-f]{64}", asset))):
        raise ValueError("Invalid indexed source record")


def check_index_coverage(report, manifest):
    if not re.fullmatch("[0-9a-f]{64}", report["scope_sha256"]):
        raise ValueError("Invalid scope digest")
    rows = report["appendix"]
    baselines = {row["id"]: row["finding_sha256"] for row in rows}
    states = ("not_retested", "fix_verified", "persists", "inconclusive")
    latest = {}
    history = manifest["retests"]
    if not isinstance(history, list) or len(history) > MAX_RETESTS:
        raise ValueError("Invalid retest inventory")
    for test in history:
        if (test["status"] not in states or not re.fullmatch("[0-9a-f]{64}", test["sha256"])
                or not re.fullmatch("[0-9a-f]{64}", test["baseline_sha256"])
                or baselines.get(test["finding_id"]) != test["baseline_sha256"]):
            raise ValueError("Invalid retest baseline")
        latest[test["finding_id"]] = test["status"]
    counts = dict.fromkeys(("hint", "confirmed", *states), 0)
    counts["findings"] = len(rows)
    for row in rows:
        status = row["retest"]
        primary, control = row["retest_evidence"], row["retest_control"]
        if (status != latest.get(row["id"], "not_retested") or (primary is None) != (status == "not_retested")
                or (status == "not_retested" and control is not None)):
            raise ValueError("Inconsistent retest coverage")
        if status in ("fix_verified", "persists"):
            if (row["status"] != "confirmed" or control is None
                    or primary["asset_id"] != row["evidence"]["asset_id"] or primary["asset_id"] != control["asset_id"]
                    or primary["fingerprint"] == control["fingerprint"]):
                raise ValueError("Invalid retest control")
            for current in (primary, control):
                for original in (row["evidence"], row["control"]):
                    if current["sha256"] == original["sha256"] or current["fingerprint"] == original["fingerprint"]:
                        raise ValueError("Repeated retest evidence")
        counts[row["status"]] += 1
        counts[status] += 1
    if any(type(report["counts"][k]) is not int or report["counts"][k] != count for k, count in counts.items()):
        raise ValueError("Inconsistent retest counts")


def check_evidence_indices(report, manifest):
    """Check source record coordinates and the public experiment chains after signature verification."""
    rows = report["appendix"]
    if not isinstance(rows, list) or len(rows) > MAX_FINDINGS:
        raise ValueError("Invalid finding inventory")
    if "evidence_index_schema" not in report:
        if any("evidence_index" in row or "scanner_lead" in row for row in rows):
            raise ValueError("Evidence index schema missing")
        return  # Original v1 handovers did not include an index.
    if report["evidence_index_schema"] != EVIDENCE_INDEX_SCHEMA:
        raise ValueError("Unknown evidence index schema")
    sources = checked_index_sources(manifest)
    revision_ids, revision_hashes = set(), set()
    finding_ids = set()
    for row in rows:
        if (row["id"] in finding_ids or not re.fullmatch("[0-9a-f]{32}", row["id"])
                or not re.fullmatch("[0-9a-f]{64}", row["finding_sha256"])):
            raise ValueError("Invalid finding identifier")
        finding_ids.add(row["id"])
        if "scanner_lead" in row:
            lead = row["scanner_lead"]
            if (not isinstance(lead, dict) or set(lead) != {"format", "sha256", "record", "fingerprint", "asset_id"}
                    or lead["format"] != "zap" or row["status"] != "confirmed" or not row["evidence"]
                    or row["evidence"]["format"] not in ("har", "burp") or not row["control"]
                    or row["control"]["format"] not in ("har", "burp") or lead["asset_id"] != row["evidence"]["asset_id"]):
                raise ValueError("Invalid linked scanner lead")
            check_index_reference(lead, sources)
        index = row["evidence_index"]
        expected = minimal_observations(row["evidence"], row["control"])
        if (set(index) != {"observations", "experiments"} or not isinstance(index["experiments"], list)
                or canonical(index["observations"]) != canonical(expected)
                or row["evidence"] is None or row["status"] not in ("confirmed", "hint")
                or (row["status"] == "confirmed") != (row["control"] is not None)):
            raise ValueError("Invalid observation index")
        if row["control"] and (row["evidence"]["asset_id"] is None or
                               row["evidence"]["asset_id"] != row["control"]["asset_id"] or
                               row["evidence"]["fingerprint"] == row["control"]["fingerprint"]):
            raise ValueError("Invalid indexed control")
        for key in ("evidence", "control", "retest_evidence", "retest_control"):
            check_index_reference(row[key], sources)
        for experiment in index["experiments"]:
            revisions = experiment["revisions"]
            if (set(experiment) != {"plan_id", "revisions"} or not isinstance(revisions, list) or not revisions
                    or experiment["plan_id"] != revisions[0]["id"] or len(revision_ids) + len(revisions) > 256):
                raise ValueError("Invalid experiment inventory")
            previous = None
            for revision in revisions:
                identifier, checksum = revision["id"], revision["sha256"]
                if (set(revision) != {"id", "sha256", "parent_sha256"} or revision["parent_sha256"] != previous
                        or not re.fullmatch("[0-9a-f]{32}", identifier) or identifier in revision_ids
                        or not re.fullmatch("[0-9a-f]{64}", checksum) or checksum in revision_hashes):
                    raise ValueError("Invalid experiment revision")
                revision_ids.add(identifier)
                revision_hashes.add(checksum)
                previous = checksum
    check_index_coverage(report, manifest)


def make_package(db,team,user,case,language,data_dir, *, signing=None):
    require(language in LANGS,"Unknown report language")
    lang = LANGS.index(language)
    source = items(db,team,case["id"],"imports")
    findings = items(db,team,case["id"],"findings")
    indices = finding_indices(db, team, case["id"], findings)
    retests = items(db,team,case["id"],"retests")
    latest = {test["finding_id"]:test for test in retests}
    counts = dict.fromkeys(("hint","confirmed","not_retested","fix_verified","persists","inconclusive"),0)
    appendix = []
    for finding in findings:
        test = latest.get(finding["id"])
        after = test["status"] if test else "not_retested"
        counts[finding["status"]] += 1
        counts[after] += 1
        appendix.append({"id":finding["id"],"finding_sha256":finding["finding_sha256"],"status":finding["status"],
                         "evidence_index":indices[finding["id"]],
                         "status_label":_REPORT[finding["status"]][lang],"evidence":public_ref(finding["evidence"]),
                         "control":public_ref(finding["control"]["reference"]) if finding["control"] else None,
                         "retest":after,"retest_label":_REPORT[after][lang],"retest_evidence":public_ref(test["evidence"]) if test else None,
                         "retest_control":public_ref(test["control"]["reference"]) if test and test["control"] else None})
        if "scanner_lead" in finding:
            appendix[-1]["scanner_lead"] = public_ref(finding["scanner_lead"])
    report = {"rights":RIGHTS,"language":language,"direction":"rtl" if language=="ar" else "ltr","title":_REPORT["heading"][lang],
              "evidence_index_schema":EVIDENCE_INDEX_SCHEMA,
              "summary_heading":_REPORT["summary"][lang],"scope_sha256":sha(canonical([case["scope"],case["assets"]])),
              "counts":{"findings":len(findings),**counts},"labels":{k:_REPORT[k][lang] for k in ("findings",*counts)},
              "appendix_heading":_REPORT["appendix"][lang],"appendix":appendix,"limitations":_REPORT["limit"][lang]}
    key,descriptor = signing or signer(db,data_dir)
    manifest = {"rights":RIGHTS,"schema":SCHEMA,"algorithm":"Ed25519","fingerprint":descriptor["fingerprint"],"case_id":case["id"],"team_id":team,
                "created_at":now(),"report_sha256":sha(canonical(report)),
                "sources":[{k:item[k] for k in ("id","format","sha256","bytes","records")} for item in source],
                "retests":[{"id":test["id"],"finding_id":test["finding_id"],"baseline_sha256":test["baseline_sha256"],
                            "status":test["status"],"sha256":sha(canonical(test))} for test in retests]}
    try:
        check_evidence_indices(report, manifest)
    except (ValueError, KeyError, TypeError) as error:
        raise WorkflowError(409, "Stored evidence index is inconsistent") from error
    signature = key.sign(SIGNING_CONTEXT + canonical(manifest))
    return {"manifest":manifest,"report":report,"signature":base64.b64encode(signature).decode("ascii")}


def verify_package(package, trusted_key, team=None):
    try:
        if not isinstance(package,dict) or set(package) != {"manifest","report","signature"}:
            raise ValueError
        manifest,report = package["manifest"],package["report"]
        if callable(trusted_key):
            trusted_key = trusted_key(manifest["fingerprint"])
        raw = base64.b64decode(trusted_key["public_key"],validate=True)
        fingerprint = sha(raw)
        if (trusted_key["algorithm"] != "Ed25519" or not hmac.compare_digest(trusted_key["fingerprint"],fingerprint)
                or manifest["schema"] != SCHEMA or manifest["algorithm"] != "Ed25519" or manifest["fingerprint"] != fingerprint
                or (team is not None and manifest["team_id"] != team) or manifest["report_sha256"] != sha(canonical(report))):
            raise ValueError
        key = Ed25519PublicKey.from_public_bytes(raw)
        key.verify(base64.b64decode(package["signature"],validate=True), SIGNING_CONTEXT + canonical(manifest))
        check_evidence_indices(report, manifest)
        return {"valid":True,"reason":"verified","fingerprint":fingerprint}
    except (InvalidSignature,ValueError,TypeError,KeyError,UnicodeError,RecursionError,AttributeError):
        return {"valid":False,"reason":"invalid_or_untrusted","fingerprint":None}


def handle(db, team_id, user_id, method, segments, body, *, data_dir):
    """Called inside the authenticated server transaction, after role checks."""
    parts = list(segments)
    if method == "GET" and parts == ["trust-key"]:
        return signer(db,data_dir,rotate=False)[1]
    if method == "GET" and parts == ["trust-keys"]:
        return key_history(db, data_dir)
    if method == "POST" and parts == ["verify"]:
        trusted_keys = {entry["fingerprint"]: entry for entry in key_history(db, data_dir)["keys"]}
        if "archive_b64" in body:
            raw = body["archive_b64"]
            require(isinstance(raw,str) and 0 < len(raw) <= 4 * ((MAX_ARCHIVE + 2) // 3), "Invalid archive size")
            try:
                data = base64.b64decode(raw,validate=True)
            except ValueError:
                raise WorkflowError(400, "Invalid Base64 archive") from None
            return verify_archive(data,trusted_keys.get,team_id)
        return verify_package(body.get("package"),trusted_keys.get,team_id)
    if parts == ["cases"] and method == "POST":
        return create_case(db,team_id,user_id,body)
    if parts == ["cases"] and method == "GET":
        cases = db.execute("SELECT document FROM evidence_cases WHERE team_id=? ORDER BY rowid DESC", (team_id,))
        return {"cases":[json.loads(r[0]) for r in cases]}
    require(len(parts) >= 2 and parts[0]=="cases","Unknown route",404)
    row = db.execute("SELECT document FROM evidence_cases WHERE team_id=? AND id=?",(team_id,parts[1])).fetchone()
    require(row,"Unknown case",404)
    case = json.loads(row[0])
    if len(parts)==2 and method=="GET":
        inventory = {kind:items(db,team_id,case["id"],kind) for kind in ("imports","findings","retests")}
        indices = finding_indices(db, team_id, case["id"], inventory["findings"])
        for finding in inventory["findings"]:
            finding["evidence_index"] = indices[finding["id"]]
        return {"case":case, "evidence_index_schema":EVIDENCE_INDEX_SCHEMA, **inventory}
    if len(parts)==5 and method=="GET" and parts[2]=="imports" and parts[4]=="attachment":
        row = db.execute("SELECT attachment FROM evidence_bytes WHERE team_id=? AND case_id=? AND import_id=?",
                         (team_id,case["id"],parts[3])).fetchone()
        require(row,"Unknown original attachment",404)
        return {"sha256":sha(row[0]),"content_b64":base64.b64encode(row[0]).decode("ascii")}
    require(len(parts)==3 and method=="POST","Unknown route",404)
    if parts[2] == "imports":
        return add_import(db,team_id,user_id,case,body)
    if parts[2] == "finding":
        return add_finding(db,team_id,user_id,case,body)
    if parts[2] == "retest":
        return add_retest(db,team_id,user_id,case,body)
    if parts[2] == "handover":
        fmt = body.get("format","json")
        require(fmt in ("json", *SUPPORTED), "Unknown document format")
        signing = signer(db, data_dir)
        package = make_package(db,team_id,user_id,case,body.get("language","de"),data_dir,signing=signing)
        if fmt == "json":
            return {"package":package}
        archive = build_archive(package,fmt,signing[0])
        return {"format":fmt,"archive_b64":base64.b64encode(archive).decode("ascii")}
    raise WorkflowError(404,"Unknown route")


def main():
    cli = argparse.ArgumentParser(description="Verify an AuthzLedger handover against an independently obtained public key.")
    sub = cli.add_subparsers(dest="command",required=True)
    check = sub.add_parser("verify")
    check.add_argument("package",type=Path)
    check.add_argument("--trusted-key",type=Path,required=True)
    check.add_argument("--document",type=Path,help="Extracted report.html or report.pdf, with proof.json as the package")
    args = cli.parse_args()
    try:
        if args.package.stat().st_size > 8 * MAX_FILE or args.trusted_key.stat().st_size > 4096:
            raise ValueError
        trusted_key = read_json(args.trusted_key.read_text(encoding="utf-8"))
        data = args.package.read_bytes()
        if args.document:
            if args.document.stat().st_size > MAX_ARCHIVE:
                raise ValueError
            result = verify_document(read_json(data.decode("utf-8")), args.document.read_bytes(), trusted_key)
        elif data.startswith(b"PK"):
            result = verify_archive(data, trusted_key)
        else:
            result = verify_package(read_json(data.decode("utf-8")), trusted_key)
        result.pop("report",None)
    except (OSError,ValueError,RecursionError):
        result = {"valid":False,"reason":"unreadable_input"}
    print(json.dumps(result))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
