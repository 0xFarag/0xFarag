"""Aggregate revision snapshots for stakeholders. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from collections import Counter
from datetime import datetime, timezone
import json


SCHEMA = """
CREATE TABLE IF NOT EXISTS proof_management_reports(
 run_id TEXT NOT NULL REFERENCES proof_runs(id), revision INTEGER NOT NULL,
 summary TEXT NOT NULL, PRIMARY KEY(run_id,revision));
CREATE TRIGGER IF NOT EXISTS proof_management_reports_immutable_update BEFORE UPDATE ON proof_management_reports BEGIN
 SELECT RAISE(ABORT,'frozen management report'); END;
CREATE TRIGGER IF NOT EXISTS proof_management_reports_immutable_delete BEFORE DELETE ON proof_management_reports BEGIN
 SELECT RAISE(ABORT,'frozen management report'); END;
"""


def summarize(db, state):
    """Only labelled counts leave the workspace. Commit time comes from the revision history."""
    rid, revision = state['id'], state['version']
    at = db.execute('SELECT at FROM proof_history WHERE run_id=? AND version=?', (rid, revision)).fetchone()[0]
    latest_sign = db.execute("SELECT max(version) FROM proof_history WHERE run_id=? AND version<=? AND action='sign'",
                             (rid, revision)).fetchone()[0]
    scope = state['scope']
    evaluated = state['report'] or {}
    findings = evaluated.get('findings', [])
    statuses = dict.fromkeys(('confirmed', 'no_marker', 'inconclusive', 'budget_blocked', 'out_of_scope'), 0)
    statuses.update(Counter(item['status'] for item in findings))
    imported_hosts = {item['observation']['host'] for item in findings}
    files = Counter(source['format'] for source in state['sources'])
    severity = dict.fromkeys(('info', 'low', 'medium', 'high', 'critical', 'unknown'), 0)
    for finding in findings:
        row = finding['observation']
        if finding['status'] != 'out_of_scope' and row['source'] in ('Nessus', 'Nuclei'):
            severity[row.get('severity', 'unknown')] += 1
    retests = evaluated.get('retestRuns', [])
    latest = Counter(row['status'] for row in evaluated.get('retests', [])) if retests else {}
    spent = evaluated.get('spent', 0)
    return {
        'schema': 'authzledger.management-report.v1', 'runId': rid, 'revision': revision, 'mode': state['mode'],
        'updatedAt': datetime.fromtimestamp(at, timezone.utc).isoformat(timespec='seconds'),
        'exportStatus': 'unsigned', 'evidenceStatus': 'evaluated' if evaluated else 'awaiting_evidence',
        'handover': {'latestSignedRevision': latest_sign},
        'coverage': {'scopedHosts': len(scope['hosts']), 'observedScopedHosts': len(imported_hosts.intersection(scope['hosts']))},
        'sources': {'total': sum(files.values()), 'byFormat': dict(sorted(files.items()))},
        'baseline': {'observations': len(findings), 'byStatus': statuses},
        'scannerSignals': {'total': sum(severity.values()), 'bySeverity': severity},
        'retests': {'runs': len(retests), 'latestByStatus': dict(latest)},
        'budget': {'limit': scope['budget'], 'spent': spent, 'remaining': scope['budget'] - spent},
    }


def capture(db, state):
    db.execute('INSERT INTO proof_management_reports(run_id,revision,summary) VALUES(?,?,?)',
               (state['id'], state['version'], json.dumps(summarize(db, state), separators=(',', ':'))))


def capture_pre_upgrade(db, rid, revision):
    # On the first change after an upgrade, retain the actual last stored state before it is replaced.
    old = db.execute('SELECT document, mode FROM proof_runs WHERE id=? AND version=? AND NOT EXISTS '
                     '(SELECT 1 FROM proof_management_reports WHERE run_id=? AND revision=?)',
                     (rid, revision, rid, revision)).fetchone()
    if old:
        capture(db, json.loads(old['document']) | {'id': rid, 'version': revision, 'mode': old['mode']})
