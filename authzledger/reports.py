"""Dependency-free, escaped HTML and JUnit views of configured checks."""

from __future__ import annotations

import html
import base64
from importlib.resources import files
import math
import xml.etree.ElementTree as ET
from typing import Any

from .evidence import verify_report


_OUTCOMES = ("pass", "fail", "error", "inconclusive")
_STYLE = """
:root{color-scheme:dark;--navy:#071722;--panel:#102735;--line:#244250;
--teal:#43D6CF;--gold:#C8A66B;--ink:#EDF6F8;--muted:#A8BBC4;--bad:#FF8B92;
--warn:#EDC782;--radius:16px;font-family:Inter,ui-sans-serif,system-ui,-apple-system,
BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--navy);color:var(--ink)}
*{box-sizing:border-box}body{margin:0;line-height:1.55}a{color:var(--teal)}
.shell{max-width:1440px;padding:40px 40px 24px;margin:auto}
.masthead{display:flex;align-items:center;justify-content:space-between;gap:20px;
padding-bottom:28px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;font-size:20px;font-weight:750;letter-spacing:-.5px}.brand span{color:var(--teal)}
.eyebrow,.kicker{text-transform:uppercase;letter-spacing:.16em;font-size:11px;
font-weight:650;color:var(--gold)}.masthead .eyebrow{text-align:right}
.hero{padding:48px 0 34px;max-width:960px}h1{font-size:clamp(30px,4.2vw,56px);
line-height:1.08;letter-spacing:-.045em;font-weight:650;margin:12px 0 18px}
h2{font-size:21px;letter-spacing:-.02em;margin:0 0 10px}h3{font-size:16px;margin:0}
p{margin:10px 0}.muted,.subtext{color:var(--muted)}.subtext{font-size:13px}
.lead{font-size:17px;color:var(--muted);max-width:750px}.layout{display:grid;
grid-template-columns:minmax(0,1.618fr) minmax(280px,1fr);gap:26px;align-items:start}
.stack{display:grid;gap:22px}.panel{background:var(--panel);border:1px solid var(--line);
border-radius:var(--radius);padding:26px;min-width:0}.section-label{display:flex;
justify-content:space-between;align-items:center;gap:16px;margin-bottom:20px}
.section-label h2{margin:0}.count{font-variant-numeric:tabular-nums;color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:26px}
.stat{border:1px solid var(--line);border-top:2px solid var(--muted);border-radius:10px;
padding:18px;background:var(--panel)}.stat strong{display:block;font-size:32px;
line-height:1.2;font-weight:550;font-variant-numeric:tabular-nums}
.stat span{font-size:12px;text-transform:uppercase;letter-spacing:.07em}
.stat.pass{border-top-color:var(--teal)}.stat.fail,.stat.error{border-top-color:var(--bad)}
.stat.inconclusive{border-top-color:var(--warn)}
.badge{display:inline-block;white-space:normal;border:1px solid currentColor;
border-radius:999px;padding:3px 10px;font-size:11px;letter-spacing:.05em;
text-transform:uppercase;font-weight:650}.badge.pass,.good{color:var(--teal)}
.badge.fail,.badge.error,.bad{color:var(--bad)}
.badge.inconclusive,.warning{color:var(--warn)}.badge.neutral{color:var(--muted)}
.banner{border-left:3px solid var(--teal);padding:14px 18px;background:#112D37;
border-radius:0 10px 10px 0;margin:20px 0 0}.banner.bad{border-left-color:var(--bad)}
.banner.warning{border-left-color:var(--warn)}.banner p{margin:4px 0}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}
th{font-size:10px;text-transform:uppercase;letter-spacing:.11em;color:var(--muted);
text-align:left;font-weight:650}th,td{padding:13px 10px;border-bottom:1px solid var(--line);
vertical-align:top}th:first-child,td:first-child{padding-left:0}
tr:last-child td{border-bottom:0}td.id{overflow-wrap:anywhere;font-weight:600}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;
overflow-wrap:anywhere;white-space:pre-wrap}.hash{display:block;padding:12px;background:var(--navy);
border:1px solid var(--line);border-radius:8px;color:var(--muted);margin-top:8px}
dl{margin:0}dt{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--gold);
margin-top:18px}dt:first-child{margin-top:0}dd{margin:5px 0 0;font-size:13px;overflow-wrap:anywhere}
.case{padding:22px 0;border-top:1px solid var(--line)}.case:first-of-type{padding-top:0;border-top:0}
.case:last-child{padding-bottom:0}.case-head{display:flex;justify-content:space-between;
align-items:flex-start;gap:14px}.case-title{overflow-wrap:anywhere}
.case .route{display:block;margin:12px 0 8px;color:var(--muted)}
.checks{display:flex;flex-wrap:wrap;gap:8px;list-style:none;padding:0;margin:12px 0}
.checks li{font-size:11px;padding:4px 9px;border:1px solid var(--line);border-radius:5px}
.checks li span{margin-right:5px;font-weight:650}.reason{font-size:13px;overflow-wrap:anywhere}
.scope-list{padding-left:18px;font-size:13px;color:var(--muted)}.scope-list li{margin:10px 0}
.divider{height:1px;background:var(--line);margin:22px 0}.empty{padding:24px;color:var(--muted)}
.compare-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:22px}
.compare-grid .panel{padding:20px}.outcome-line{display:flex;flex-wrap:wrap;gap:10px;
font-size:12px;margin-top:12px}.diff-stats{grid-template-columns:repeat(3,minmax(0,1fr))}
.foot{display:flex;justify-content:space-between;gap:20px;margin-top:40px;padding-top:20px;
border-top:1px solid var(--line);font-size:11px;color:var(--muted)}
@media(max-width:950px){.layout{grid-template-columns:1fr}.hero{padding-top:34px}}
@media(max-width:600px){.shell{padding:24px 18px}.masthead{align-items:flex-start}
.masthead .eyebrow{max-width:120px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}
.panel{padding:20px}.compare-grid{grid-template-columns:1fr}.foot{display:block}}
@media print{:root{color-scheme:light;background:white;color:#142A36;--panel:white;
--navy:#F4F7F8;--ink:#142A36;--muted:#485D69;--line:#CCD7DB;--teal:#087A74;
--gold:#806133;--bad:#A42336;--warn:#825E0E}.shell{padding:0}.layout{grid-template-columns:1fr}
.panel,.case,.stat{break-inside:avoid}.hero{padding:24px 0}.banner{background:#F2F7F7}
a{color:inherit;text-decoration:none}.foot{margin-top:20px}}
"""


def _logo_uri() -> str:
    return "data:image/png;base64," + base64.b64encode(files("authzledger").joinpath("brand_logo.png").read_bytes()).decode("ascii")


def _text(value: Any) -> str:
    return html.escape(str(value if value is not None else "—"), quote=True)


def _outcome(value: Any) -> str:
    return value if isinstance(value, str) and value in _OUTCOMES else "neutral"


def _badge(value: Any) -> str:
    return f'<span class="badge {_outcome(value)}">{_text(value)}</span>'


def _number(value: Any, *, divisor: float = 1.0) -> str:
    try:
        number = float(value) / divisor
        return f"{number:.3f}" if math.isfinite(number) and number >= 0 else "0.000"
    except (TypeError, ValueError, OverflowError):
        return "0.000"


def _document(title: str, body: str, *, kind: str) -> str:
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{_text(title)} · AuthzLedger</title><style>{_STYLE}</style></head>
<body><div class="shell"><header class="masthead">
<div class="brand"><img src="{_logo_uri()}" alt="0xFarag" width="58" height="58"><div>Authz<span>Ledger</span><div class="subtext">by 0xFarag</div></div></div>
<div class="eyebrow">Authorization regression<br>{_text(kind)}</div>
</header>{body}<footer class="foot"><span>AuthzLedger · Configured checks, traceable outcomes.<br>© 2026 Nasser Aldin Farag (0xFarag). All rights reserved.</span>
<span>Defined scope · Local integrity chain · No independent authenticity claim</span>
</footer></div></body></html>'''


def _counts(results: list[dict]) -> dict[str, int]:
    return {outcome: sum(result.get("outcome") == outcome for result in results) for outcome in _OUTCOMES}


def _stats(counts: dict) -> str:
    return '<section class="stats" aria-label="Case outcomes">' + "".join(
        f'<div class="stat {outcome}"><strong>{_text(counts.get(outcome, 0))}</strong>'
        f'<span>{outcome}</span></div>' for outcome in _OUTCOMES
    ) + "</section>"


def _case_detail(result: dict, index: int) -> str:
    control_labels = {
        "positive": "Positive control · permitted access",
        "negative": "Negative control · denied access",
        "configured": "Configured case",
    }
    control = control_labels.get(result.get("control_type"), "Configured case")
    checks = result.get("checks", [])
    check_html = "".join(
        '<li><span class="' + ("good" if check.get("passed") is True else "bad") + '">'
        + ("PASS" if check.get("passed") is True else "FAIL") + "</span>"
        + _text(check.get("type", "check")) + "</li>"
        for check in checks if isinstance(check, dict)
    )
    requires = result.get("requires", [])
    dependencies = (
        '<p class="subtext">Required controls: ' + ", ".join(_text(item) for item in requires) + "</p>"
        if isinstance(requires, list) and requires else ""
    )
    digest = result.get("response_sha256")
    response_hash = (
        '<details><summary class="subtext">Response SHA-256</summary>'
        f'<code class="hash">{_text(digest)}</code></details>' if digest else ""
    )
    return f'''<article class="case" id="case-{index}">
<div class="case-head"><div class="case-title"><div class="kicker">{control}</div>
<h3>{_text(result.get("id"))}</h3></div>{_badge(result.get("outcome"))}</div>
<code class="route">{_text(result.get("method"))} {_text(result.get("path"))}</code>
<p class="subtext">Identity: {_text(result.get("identity"))} · HTTP {_text(result.get("status"))}
 · {_number(result.get("duration_ms"))} ms</p>{dependencies}
<p class="reason">{_text(result.get("reason", ""))}</p>
{('<ul class="checks" aria-label="Assertions">' + check_html + '</ul>') if check_html else '<p class="subtext">No assertion results recorded.</p>'}
{response_hash}</article>'''


def render_html(report: dict) -> str:
    """Render all configured outcomes, with explicit scope and trust limits."""
    results = [item for item in report.get("results", []) if isinstance(item, dict)]
    counts = _counts(results)
    integrity_errors = verify_report(report)
    evidence = report.get("evidence", {})
    evidence = evidence if isinstance(evidence, dict) else {}
    if integrity_errors:
        integrity = '<div class="banner bad"><strong>Integrity verification failed</strong><p>' + "; ".join(
            _text(error) for error in integrity_errors
        ) + "</p></div>"
    else:
        integrity = '<div class="banner"><strong>Local hash chain consistent</strong><p class="subtext">Metadata, complete case records and their order match this seal.</p></div>'
    if counts["fail"] or counts["error"]:
        verdict, verdict_class = "Configured checks need attention", "bad"
    elif counts["inconclusive"]:
        verdict, verdict_class = "Inconclusive cases require follow-up", "warning"
    elif results:
        verdict, verdict_class = "All configured cases passed", "good"
    else:
        verdict, verdict_class = "No configured cases recorded", "muted"
    rows = "".join(
        f'<tr><td class="id"><a href="#case-{index}">{_text(result.get("id"))}</a></td>'
        f'<td>{_text(result.get("identity"))}</td><td>{_text(result.get("status"))}</td>'
        f'<td>{_badge(result.get("outcome"))}</td></tr>'
        for index, result in enumerate(results, 1)
    )
    table = (
        '<div class="table-wrap"><table><thead><tr><th scope="col">Stable case ID</th>'
        '<th scope="col">Identity</th><th scope="col">HTTP</th><th scope="col">Outcome</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>'
        if rows else '<p class="empty">This report contains no cases.</p>'
    )
    details = "".join(_case_detail(result, index) for index, result in enumerate(results, 1))
    body = f'''<section class="hero"><div class="eyebrow">Configured checks / execution report</div>
<h1>{_text(report.get("name", "Authorization report"))}</h1>
<p class="lead">Explicit authorization expectations. Positive controls, denied-access checks and results you can review.</p>
<p class="{verdict_class}"><strong>{verdict}</strong> · {len(results)} configured cases</p></section>
{_stats(counts)}<div class="layout"><main class="stack">
<section class="panel"><div class="section-label"><h2>Configured checks</h2><span class="count">{len(results)} cases</span></div>
{table}</section><section class="panel"><div class="section-label"><h2>Case evidence</h2></div>{details}</section>
</main><aside class="stack"><section class="panel"><h2>Defined scope</h2><dl>
<dt>Target</dt><dd><code>{_text(report.get("target"))}</code></dd>
<dt>Started · UTC</dt><dd>{_text(report.get("started_at"))}</dd>
<dt>Finished · UTC</dt><dd>{_text(report.get("finished_at"))}</dd>
<dt>Contract SHA-256</dt><dd><code class="hash">{_text(report.get("contract_sha256"))}</code></dd></dl>
<div class="divider"></div><ul class="scope-list">
<li>Results apply only to the configured identities, routes, assertions and run time.</li>
<li>A denial is meaningful only when its required positive controls succeed.</li>
<li>Inconclusive means the configured result was not established; it is never a pass.</li>
<li>Passing checks do not establish complete authorization coverage or certify the application.</li>
</ul></section><section class="panel"><h2>Evidence integrity</h2>{integrity}
<dl><dt>Root SHA-256 · external anchor candidate</dt><dd><code class="hash">{_text(evidence.get("root_sha256"))}</code></dd></dl>
<p class="subtext">This is a local integrity check, not a signature or independent proof of authenticity. A changed report can be resealed. Compare this root with a separately trusted anchor to detect replacement. An anchor does not prove the claimed network execution occurred.</p>
<p class="subtext">Response bodies and authentication headers are not included in this report.</p></section>
</aside></div>'''
    return _document(str(report.get("name", "Authorization report")), body, kind="Execution report")


def _xml_text(value: Any) -> str:
    """Escape via ElementTree after replacing XML 1.0-disallowed code points."""
    return "".join(
        char if (
            char in "\t\n\r" or 0x20 <= ord(char) <= 0xD7FF
            or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF
        ) else "\uFFFD" for char in str(value if value is not None else "")
    )


def render_junit(report: dict) -> str:
    """JUnit: failed assertions -> failure, execution errors -> error, inconclusive -> skipped.

    An invalid local evidence chain is rejected, so CI cannot mistake a modified
    report for trusted test results. JUnit's skipped count must not be read as a
    passed authorization check.
    """
    errors = verify_report(report)
    if errors:
        raise ValueError("cannot render JUnit from invalid evidence: " + "; ".join(errors))
    results = report["results"]
    counts = _counts(results)
    total_seconds = sum(float(_number(result.get("duration_ms"), divisor=1000)) for result in results)
    suite = ET.Element("testsuite", {
        "name": _xml_text(report.get("name", "AuthzLedger")),
        "tests": str(len(results)), "failures": str(counts["fail"]),
        "errors": str(counts["error"]), "skipped": str(counts["inconclusive"]),
        "time": _number(total_seconds),
    })
    properties = ET.SubElement(suite, "properties")
    for name, value in (
        ("scope", "Configured checks only; not a complete authorization assessment"),
        ("contract_sha256", report.get("contract_sha256")),
        ("evidence.root_sha256", report["evidence"]["root_sha256"]),
        ("evidence.trust", "Local integrity only, not independent authenticity; trusted external anchors help detect replacement, not prove execution"),
    ):
        ET.SubElement(properties, "property", {"name": name, "value": _xml_text(value)})
    for result in results:
        case = ET.SubElement(suite, "testcase", {
            "name": _xml_text(result["id"]),
            "classname": "AuthzLedger." + _xml_text(result["identity"]),
            "time": _number(result["duration_ms"], divisor=1000),
        })
        tag = {"fail": "failure", "error": "error", "inconclusive": "skipped"}.get(result["outcome"])
        if tag:
            node = ET.SubElement(case, tag, {
                "type": "AuthzLedger." + result["outcome"],
                "message": _xml_text(result["reason"]),
            })
            node.text = _xml_text(
                "Configured case outcome: " + result["outcome"] + ". " + result["reason"]
            )
    ET.indent(suite, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(suite, encoding="unicode") + "\n"


def render_diff_html(diff: dict) -> str:
    """Render a validated comparison produced by compare_reports."""
    categories = ("regressions", "resolved", "unchanged", "added", "removed", "inconclusive")
    groups = {key: diff.get(key, []) for key in categories}
    groups = {key: value if isinstance(value, list) else [] for key, value in groups.items()}
    labels = {"unchanged": "No conclusive change", "inconclusive": "Inconclusive transition"}
    colors = {"regressions": "fail", "resolved": "pass", "inconclusive": "inconclusive"}
    stat_html = '<section class="stats diff-stats" aria-label="Comparison outcomes">' + "".join(
        f'<div class="stat {colors.get(key, "neutral")}"><strong>{len(groups[key])}</strong>'
        f'<span>{_text(labels.get(key, key))}</span></div>' for key in categories
    ) + "</section>"
    transitions = diff.get("transitions", [])
    if not isinstance(transitions, list):
        transitions = []
    rows = "".join(
        f'<tr><td class="id">{_text(item.get("id"))}</td>'
        f'<td>{_badge(item.get("baseline"))}</td><td>{_badge(item.get("current"))}</td>'
        f'<td>{_text(labels.get(item.get("category"), item.get("category")))}</td></tr>'
        for item in transitions if isinstance(item, dict)
    )
    if not rows:
        rows = "".join(
            f'<tr><td class="id">{_text(case_id)}</td><td>—</td><td>—</td><td>{_text(labels.get(category, category))}</td></tr>'
            for category in categories for case_id in groups[category]
        )
    summaries = []
    for key, label in (("baseline", "Baseline"), ("current", "Current")):
        summary = diff.get(key + "_summary", {})
        summary = summary if isinstance(summary, dict) else {}
        summaries.append(
            f'<section class="panel"><div class="kicker">{label}</div>'
            f'<p class="subtext">{_text(diff.get(key + "_finished_at"))}</p>'
            '<div class="outcome-line">' + "".join(
                f'<span>{_text(summary.get(outcome, 0))} {outcome}</span>' for outcome in _OUTCOMES
            ) + "</div></section>"
        )
    body = f'''<section class="hero"><div class="eyebrow">Configured checks / baseline comparison</div>
<h1>Know what changed.</h1><p class="lead">{_text(diff.get("name", "Authorization regression comparison"))}</p>
<p class="subtext">Compared by stable case ID under the same contract digest.</p></section>
{stat_html}<div class="layout"><main class="stack"><div class="compare-grid">{"".join(summaries)}</div>
<section class="panel"><div class="section-label"><h2>Outcome transitions</h2></div>
<div class="table-wrap"><table><thead><tr><th scope="col">Stable case ID</th><th scope="col">Baseline</th>
<th scope="col">Current</th><th scope="col">Classification</th></tr></thead><tbody>{rows}</tbody></table></div>
</section></main><aside class="stack"><section class="panel"><h2>Comparison rules</h2><ul class="scope-list">
<li><strong>Regression:</strong> pass changed to fail or error.</li>
<li><strong>Resolved:</strong> fail or error changed to pass.</li>
<li><strong>Inconclusive:</strong> either compared outcome is inconclusive. This does not establish resolution.</li>
<li><strong>No conclusive change:</strong> both outcomes remain pass, or both remain fail/error. Exact outcomes are shown.</li>
<li>Version 1 requires identical case-ID sets, target and case definitions. Contradictory scope is rejected; added/removed counts are reserved.</li>
</ul></section><section class="panel"><h2>Bound comparison</h2><dl>
<dt>Target · current run</dt><dd><code>{_text(diff.get("target"))}</code></dd>
<dt>Contract SHA-256</dt><dd><code class="hash">{_text(diff.get("contract_sha256"))}</code></dd>
<dt>Baseline root SHA-256</dt><dd><code class="hash">{_text(diff.get("baseline_root_sha256"))}</code></dd>
<dt>Current root SHA-256</dt><dd><code class="hash">{_text(diff.get("current_root_sha256"))}</code></dd></dl>
<p class="subtext">Local chains were checked before comparison. Hash consistency is not independent proof of authenticity. Compare with separately trusted anchors to detect replacement; this does not prove the claimed network execution occurred.</p>
</section></aside></div>'''
    return _document("Regression comparison", body, kind="Comparison report")
