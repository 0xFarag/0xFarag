"""Read existing file reputation by digest. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
import re
import secrets
import time

from .evidence_formats import read_json

HOST = 'www.virustotal.com'
TIMEOUT = 6
MAX_BYTES = 2 * 1024 * 1024
STATS = ('malicious', 'suspicious', 'harmless', 'undetected', 'timeout', 'confirmed-timeout', 'type-unsupported', 'failure')
WINDOW, TEAM_LIMIT, INSTALLATION_LIMIT = 60, 4, 12
CACHE_SECONDS = 300
HASH = re.compile(r'[a-fA-F0-9]{64}\Z')

SCHEMA = """
CREATE TABLE IF NOT EXISTS file_reputation_requests(
 id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id), lookup_key TEXT NOT NULL,
 started INTEGER NOT NULL, state TEXT NOT NULL, summary TEXT);
CREATE INDEX IF NOT EXISTS file_reputation_started ON file_reputation_requests(started);
CREATE INDEX IF NOT EXISTS file_reputation_key ON file_reputation_requests(team_id,lookup_key,started DESC);
"""


class Error(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def _key():
    # The operator supplies a key licensed for their own commercial deployment.
    key = os.environ.get('AUTHZLEDGER_VT_PREMIUM_API_KEY', '')
    return key if re.fullmatch(r'[!-~]{1,256}', key) else None


def read_report(sha256):
    key = _key()
    if not key:
        raise Error(503, 'vt_not_configured')
    if not isinstance(sha256, str) or not HASH.fullmatch(sha256):
        raise Error(400, 'invalid_hash')
    # Direct HTTPS with default certificate verification, no proxy or redirect handler.
    connection = http.client.HTTPSConnection(HOST, timeout=TIMEOUT)
    deadline = time.monotonic() + TIMEOUT
    try:
        connection.request('GET', '/api/v3/files/' + sha256, headers={'x-apikey': key, 'Accept': 'application/json'})
        with connection.getresponse() as response:
            if response.status == 404:
                raise Error(404, 'vt_not_found')
            if response.status == 429:
                raise Error(429, 'vt_rate_limited')
            if response.status != 200 or response.headers.get_content_type() != 'application/json':
                raise Error(502, 'vt_provider_error')
            size = response.headers.get('Content-Length')
            if size is not None and (not re.fullmatch(r'[0-9]{1,9}', size) or int(size) > MAX_BYTES):
                raise Error(502, 'vt_provider_error')
            raw = bytearray()
            while len(raw) <= MAX_BYTES:
                if time.monotonic() >= deadline:
                    raise Error(502, 'vt_provider_error')
                chunk = response.read1(min(65536, MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > MAX_BYTES or (size is not None and len(raw) != int(size)):
                raise Error(502, 'vt_provider_error')
        data = read_json(raw.decode('utf-8'))['data']
        attrs = data['attributes']
        if not isinstance(attrs, dict) or data['type'] != 'file' or data['id'] != sha256 or attrs.get('sha256', sha256) != sha256:
            raise ValueError
        counts = attrs.get('last_analysis_stats', {})
        if not isinstance(counts, dict) or (counts and counts.keys() != set(STATS)) or any(type(n) is not int or not 0 <= n <= 10000 for n in counts.values()):
            raise ValueError
        timestamp = attrs.get('last_analysis_date')
        if timestamp is not None and (type(timestamp) is not int or not 0 <= timestamp <= 253402300799):
            raise ValueError
        date = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec='seconds') if timestamp is not None else None
        return {'analysisDate': date, 'stats': {category: counts.get(category, 0) for category in STATS}}
    except (OSError, http.client.HTTPException, KeyError, ValueError, TypeError, RecursionError, OverflowError):
        raise Error(502, 'vt_provider_error') from None
    finally:
        connection.close()


def _reserve(db, tid, digest, now):
    db.execute('DELETE FROM file_reputation_requests WHERE started<=?', (now-CACHE_SECONDS,))
    # No original lookup digests, file names, or raw provider responses are stored.
    lookup_key = hashlib.sha256((tid + ':' + digest).encode('ascii')).hexdigest()
    recent = db.execute('SELECT state, started, summary FROM file_reputation_requests WHERE team_id=? AND lookup_key=? '
                        'ORDER BY started DESC, rowid DESC LIMIT 1', (tid, lookup_key)).fetchone()
    if recent:
        if recent['state'] == 'found':
            return {'provider': 'VirusTotal', 'sha256': digest, 'cached': True, **json.loads(recent['summary'])}
        if recent['state'] == 'missing':
            raise Error(404, 'vt_not_found')
        if recent['state'] == 'pending' and recent['started'] > now - 30:
            raise Error(409, 'vt_lookup_pending')
    total, workspace, cooled = db.execute("SELECT count(*),count(CASE WHEN team_id=? THEN 1 END),"
                                          "count(CASE WHEN state='limit' THEN 1 END) FROM file_reputation_requests WHERE started>?",
                                          (tid, now-WINDOW)).fetchone()
    if workspace >= TEAM_LIMIT or total >= INSTALLATION_LIMIT or cooled:
        raise Error(429, 'vt_rate_limited')
    rid = secrets.token_hex(16)
    db.execute("INSERT INTO file_reputation_requests VALUES(?,?,?,?,'pending',NULL)", (rid, tid, lookup_key, now))
    return {'prepareReputation': rid, 'sha256': digest}


def handle(db, tid, allowed, method, parts, body, now, completion):
    if method == 'GET' and parts == ['status']:
        return {'configured': bool(_key()), 'canLookup': allowed}
    if method != 'POST' or parts != ['lookup']:
        raise Error(404, 'not_found')
    if not allowed:
        raise Error(403, 'forbidden')
    if not isinstance(body, dict) or body.keys() - {'consent','sha256'}:
        raise Error(400, 'invalid_fields')
    if body.get('consent') is not True:
        raise Error(400, 'consent_required')
    digest = body.get('sha256')
    if not isinstance(digest, str) or not HASH.fullmatch(digest):
        raise Error(400, 'invalid_hash')
    if not _key():
        raise Error(503, 'vt_not_configured')
    digest = digest.lower()
    if completion is None:
        return _reserve(db, tid, digest, now)
    rid, summary, error = completion
    if error:
        state = {404: 'missing', 429: 'limit'}.get(error.status, 'failed')
        result = {'reputationError': (error.status, error.code)}
    else:
        state = 'found'
        result = {'provider': 'VirusTotal', 'sha256': digest, 'cached': False, **summary}
    saved = db.execute("UPDATE file_reputation_requests SET state=?,summary=? WHERE id=? AND team_id=? AND state='pending'",
                       (state, json.dumps(summary) if summary is not None else None, rid, tid))
    if saved.rowcount != 1:
        raise Error(409, 'vt_lookup_pending')
    return result
