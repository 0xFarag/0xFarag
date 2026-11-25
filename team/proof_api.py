"""Authenticated evidence workflow. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from pathlib import Path

from . import proof_engine as engine
from . import proof_packages as packages

RIGHTS = '© Nasser Aldin Farag (0xFarag). All rights reserved.'
WRITERS = frozenset(('admin', 'lead_pentester', 'pentester'))
CONTROLS = ('token', 'identity', 'owner', 'denial')
MAX_FILE = 2 * 1024 * 1024
MAX_ARCHIVE = 3 * 1024 * 1024 - 2048
MAX_OBSERVATIONS = 512
TOKEN_TTL = 5 * 60
LAB_HOST = 'lab.authz.local'
ID = re.compile(r'[a-f0-9]{32}\Z')

SCHEMA = """
CREATE TABLE IF NOT EXISTS proof_accounts(
 user_id TEXT PRIMARY KEY REFERENCES users(id));
CREATE TABLE IF NOT EXISTS proof_workspaces(
 team_id TEXT PRIMARY KEY REFERENCES teams(id));
CREATE TABLE IF NOT EXISTS proof_runs(
 id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id),
 creator TEXT NOT NULL REFERENCES users(id), mode TEXT NOT NULL CHECK(mode IN ('commercial','lab')),
 version INTEGER NOT NULL, document TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS proof_runs_team ON proof_runs(team_id);
CREATE TABLE IF NOT EXISTS proof_history(
 id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES proof_runs(id),
 actor TEXT NOT NULL REFERENCES users(id), action TEXT NOT NULL, at INTEGER NOT NULL,
 version INTEGER NOT NULL, details TEXT NOT NULL DEFAULT '{}', UNIQUE(run_id,version));
CREATE TABLE IF NOT EXISTS proof_archives(
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES proof_runs(id),
 actor TEXT NOT NULL REFERENCES users(id), key_id TEXT NOT NULL, language TEXT NOT NULL,
 content BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS proof_import_tokens(
 token_hash TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES proof_runs(id),
 session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
 actor TEXT NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS proof_history_immutable_update BEFORE UPDATE ON proof_history BEGIN
 SELECT RAISE(ABORT,'append-only proof history'); END;
CREATE TRIGGER IF NOT EXISTS proof_history_immutable_delete BEFORE DELETE ON proof_history BEGIN
 SELECT RAISE(ABORT,'append-only proof history'); END;
CREATE TRIGGER IF NOT EXISTS proof_archives_immutable_update BEFORE UPDATE ON proof_archives BEGIN
 SELECT RAISE(ABORT,'frozen signed archive'); END;
CREATE TRIGGER IF NOT EXISTS proof_archives_immutable_delete BEFORE DELETE ON proof_archives BEGIN
 SELECT RAISE(ABORT,'frozen signed archive'); END;
CREATE INDEX IF NOT EXISTS proof_token_session ON proof_import_tokens(session_hash,run_id);
"""

class Error(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


def init_db(db):
    db.executescript(SCHEMA)
    if 'details' not in {r[1] for r in db.execute('PRAGMA table_info(proof_history)')}:
        db.execute("ALTER TABLE proof_history ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")
    packages.init_db(db)


def _check(condition, code, status=400):
    if not condition:
        raise Error(status, code)


def _fields(body, required=(), optional=()):
    _check(isinstance(body, dict) and set(required) <= body.keys() <= set(required) | set(optional), 'invalid_fields')


def _dump(obj):
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(',', ':'))


def _hash(text):
    return hashlib.sha256(text.encode('ascii')).hexdigest()


def _key():
    return secrets.token_hex(16)


def proof_only(db, tid):
    return bool(db.execute('SELECT 1 FROM proof_workspaces WHERE team_id=?', (tid,)).fetchone())


def proof_account(db, uid):
    return bool(db.execute('SELECT 1 FROM proof_accounts WHERE user_id=?', (uid,)).fetchone())


def enable_account(db, uid):
    db.execute('INSERT OR IGNORE INTO proof_accounts(user_id) VALUES(?)', (uid,))


def enable_workbench(db, tid):
    db.execute('INSERT OR IGNORE INTO proof_workspaces(team_id) VALUES(?)', (tid,))


def _count(db, sql, args):
    return db.execute(sql, args).fetchone()[0]


def _run(db, tid, rid):
    row = db.execute('SELECT * FROM proof_runs WHERE team_id=? AND id=?', (tid, rid)).fetchone()
    _check(row is not None, 'not_found', 404)
    return json.loads(row['document']) | {'version': row['version'], 'id': rid, 'mode': row['mode']}


def _save(db, state, uid, action, now):
    version = state['version'] + 1
    stored = {k: v for k, v in state.items() if k not in ('id', 'version', 'mode')}
    db.execute('UPDATE proof_runs SET version=?,document=? WHERE id=? AND version=?',
               (version, _dump(stored), state['id'], state['version']))
    report = state['report']
    detail = {'evidenceRoot': report['evidenceRoot']} if report else {}
    if action == 'scope':
        detail.update({'mode':state['mode'], 'budget':state['scope']['budget']})
    elif action in ('import','zap','burp_import'):
        detail['sourceSha256'] = state['sources'][-1]['sha256']
    elif action == 'controls':
        detail['controls'] = state['controls']
    elif action == 'retest':
        detail['selected'] = state['selected']
        detail['afterControls'] = report['retestRuns'][-1]['afterControls']
        after = report['retestRuns'][-1]['afterSource']
        detail['afterSourceSha256'] = after['sha256'] if after else None
    db.execute('INSERT INTO proof_history(run_id,actor,action,at,version,details) VALUES(?,?,?,?,?,?)',
               (state['id'], uid, action, now, version, _dump(detail)))
    state['version'] = version


def _view(db, state):
    history = [dict(r) | {'details':json.loads(r['details'])} for r in db.execute(
        'SELECT version,at,action,actor,details FROM proof_history WHERE run_id=? ORDER BY version', (state['id'],))]
    signed = [dict(r) for r in db.execute(
        'SELECT id,key_id AS keyId,language FROM proof_archives WHERE run_id=? ORDER BY rowid DESC',
        (state['id'],))]
    report = state['report']
    return {'run': state | {'signed': signed, 'history': history, 'retests': report['retests'] if report else []}}


def _refresh_report(state):
    state['report'] = engine.evaluate(state['scope'], state['sources'], state['controls']) if state['sources'] else None


def _create_run(db, tid, uid, body, now):
    _fields(body, ('mode',), ('hosts', 'roe', 'budget'))
    mode = body['mode']
    _check(mode in ('commercial', 'lab'), 'invalid_mode')
    _check(_count(db, 'SELECT count(*) FROM proof_runs WHERE team_id=?', (tid,)) < 500, 'workspace_limit', 409)
    if mode == 'lab':
        hosts = body.get('hosts', [LAB_HOST])
        _check(hosts == [LAB_HOST], 'lab_scope_fixed')
        scope = engine.make_scope(hosts, body.get('roe', 'Synthetic offline evidence only'), body.get('budget', 12))
        sources = [engine.lab_source()]
        selected = [r['id'] for r in sources[0]['observations'][:3]]
    else:
        _check({'hosts', 'roe', 'budget'} <= body.keys(), 'scope_required')
        scope = engine.make_scope(body['hosts'], body['roe'], body['budget'])
        _check(LAB_HOST not in scope['hosts'], 'lab_scope_reserved')
        sources, selected = [], []
    state = {'id': _key(), 'mode': mode, 'scope': scope, 'sources': sources,
             'controls': dict.fromkeys(CONTROLS, False), 'locked': False, 'selected': selected,
             'version': 0}
    _refresh_report(state)
    db.execute('INSERT INTO proof_runs VALUES(?,?,?,?,?,?)', (state['id'], tid, uid, mode, 0, '{}'))
    _save(db, state, uid, 'scope', now)
    return _view(db, state)


def _decode(encoded, maximum):
    _check(isinstance(encoded, str) and 0 < len(encoded) <= 4*((maximum+2)//3), 'invalid_size', 413)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise Error(400, 'invalid_base64') from None
    _check(len(raw) <= maximum, 'invalid_size', 413)
    return raw


def _add_source(state, source):
    _check(not state['locked'], 'baseline_frozen', 409)
    _check(state['mode'] == 'commercial', 'lab_fixture_only', 409)
    _check(source['observations'], 'empty_import')
    _check(all(r['host'] != LAB_HOST for r in source['observations']), 'lab_evidence_reserved')
    if any(existing['sha256'] == source['sha256'] for existing in state['sources']):
        raise Error(409, 'already_imported')
    count = sum(len(s['observations']) for s in state['sources']) + len(source['observations'])
    _check(len(state['sources']) < engine.MAX_SOURCES and count <= MAX_OBSERVATIONS, 'evidence_limit', 413)
    state['sources'].append(source)
    _refresh_report(state)


def _version(body, state):
    _check(type(body.get('version')) is int and body['version'] == state['version'], 'version_conflict', 409)


def _controls(obj):
    _check(isinstance(obj, dict) and set(obj) == set(CONTROLS) and
           all(type(value) is bool for value in obj.values()), 'invalid_controls')
    return obj


def _token(db, rid, session_hash, uid, now):
    db.execute('DELETE FROM proof_import_tokens WHERE expires<=? OR (session_hash=? AND run_id=?)',
               (now, session_hash, rid))
    secret = secrets.token_urlsafe(32)
    db.execute('INSERT INTO proof_import_tokens VALUES(?,?,?,?,?)',
               (_hash(secret), rid, session_hash, uid, now + TOKEN_TTL))
    return {'token': secret, 'expiresAt': now + TOKEN_TTL, 'endpoint': '/api/proof-import'}


def burp_binding(db, bearer, now, idle, lifetime):
    _check(isinstance(bearer, str) and re.fullmatch(r'[a-zA-Z0-9_-]{43}', bearer), 'invalid_import_token', 401)
    digest = _hash(bearer)
    row = db.execute(
        'SELECT r.team_id,r.id,t.actor,u.username FROM proof_import_tokens t JOIN proof_runs r ON r.id=t.run_id '
        'JOIN users u ON u.id=t.actor JOIN sessions s ON s.token_hash=t.session_hash AND s.user_id=t.actor '
        'JOIN memberships m ON m.team_id=r.team_id AND m.user_id=t.actor AND m.active=1 '
        "WHERE t.token_hash=? AND t.expires>? AND s.created_at>? AND s.last_seen>? "
        "AND m.role IN ('admin','lead_pentester','pentester')",
        (digest, now, now-lifetime, now-idle)).fetchone()
    _check(row is not None, 'invalid_import_token', 401)
    return row, digest


def accept_burp(db, binding, body, now):
    row, digest = binding
    _fields(body, ('observations',))
    observations = body['observations']
    _check(isinstance(observations, list) and 0 < len(observations) <= MAX_OBSERVATIONS, 'invalid_observations')
    allowed = {'id','host','method','path','status','marker','rule','source'}
    _check(all(isinstance(item, dict) and allowed-{'marker'} <= item.keys() <= allowed and item['source']=='Burp'
               for item in observations), 'invalid_observations')
    state = _run(db, row['team_id'], row['id'])
    source = engine.import_source('burp', _dump(body).encode())
    _check(all(r['host'] in state['scope']['hosts'] for r in source['observations']), 'outside_token_scope', 403)
    _add_source(state, source)
    _save(db, state, row['actor'], 'burp_import', now)
    db.execute('DELETE FROM proof_import_tokens WHERE token_hash=?', (digest,))
    return {'accepted':len(source['observations']), 'runId':row['id']}


def _retest(state, body):
    _fields(body, ('version','selected','controls'), ('format','content_b64','labAfter'))
    _check(bool(state['report']), 'source_required', 409)
    selected = body['selected']
    _check(isinstance(selected, list), 'invalid_selection')
    controls = _controls(body['controls'])
    _check(('format' in body) == ('content_b64' in body), 'invalid_fields')
    _check(type(body.get('labAfter', False)) is bool and not(body.get('labAfter') and 'format' in body), 'invalid_fields')
    after = None
    if body.get('labAfter'):
        _check(state['mode'] == 'lab', 'lab_fixture_only')
        after = engine.lab_after_source()
    elif 'format' in body:
        _check(state['mode'] == 'commercial', 'lab_fixture_only')
        after = engine.import_source(body['format'], _decode(body['content_b64'], MAX_FILE))
        _check(len(after['observations']) <= MAX_OBSERVATIONS, 'evidence_limit', 413)
        _check(all(r['host'] != LAB_HOST for r in after['observations']), 'lab_evidence_reserved')
    report = state['report']
    runs = report['retestRuns']
    _check(len(runs) < 24, 'retest_limit', 409)
    engine.record_retest(report, selected, after, controls)
    state.update({'locked': True, 'selected': selected})


def _verify(db, directory, tid, state, body):
    _fields(body, ('archive_b64',))
    archive = _decode(body['archive_b64'], MAX_ARCHIVE)
    # Read the untrusted key identifier solely to select a locally trusted key.
    from .proof_verify import inventory_key_id
    try:
        wanted = inventory_key_id(archive)
        keys = packages.key_history(db, directory, tid)['keys']
        key = next((k for k in keys if k['keyId']==wanted), None)
        if key is None:
            return {'valid': False}
        signed = packages.verify_package(archive, key['jwk'], workspace=tid)
        if state['report'] is None or signed['evidenceRoot'] != state['report']['evidenceRoot']:
            return {'valid': False}
        return {'valid': True, 'keyId': key['keyId'], 'fingerprint': key['fingerprint']}
    except ValueError:
        return {'valid': False}


def handle(db, directory, tid, uid, role, method, parts, body, session_hash, now, zap_data=None):
    directory = Path(directory)
    if method == 'GET':
        if not parts:
            return {'runs': [dict(r) for r in db.execute(
                'SELECT id,mode,version FROM proof_runs WHERE team_id=? ORDER BY rowid DESC', (tid,))]}
        if parts == ['keys']:
            return packages.key_history(db, directory, tid)
        if len(parts) == 1 and ID.fullmatch(parts[0]):
            return _view(db, _run(db, tid, parts[0]))
        raise Error(404, 'not_found')
    _check(method == 'POST', 'method_not_allowed', 405)
    if parts == ['rotate']:
        _check(role == 'admin', 'forbidden', 403)
        _fields(body)
        key = packages.rotate_key(db, directory, tid)
        return {'key': key} | packages.key_history(db, directory, tid)
    if len(parts) == 2 and parts[1] == 'verify':
        return _verify(db, directory, tid, _run(db, tid, parts[0]), body)
    _check(role in WRITERS, 'forbidden', 403)
    if not parts:
        return _create_run(db, tid, uid, body, now)
    _check(len(parts)==2 and ID.fullmatch(parts[0]), 'not_found', 404)
    rid, action = parts
    state = _run(db, tid, rid)
    if action == 'token':
        _fields(body)
        _check(state['mode']=='commercial' and not state['locked'], 'closed_for_import', 409)
        return _token(db, rid, session_hash, uid, now)
    if action == 'export':
        _fields(body, ('packageId',))
        row = db.execute('SELECT content FROM proof_archives WHERE run_id=? AND id=?', (rid, body['packageId'])).fetchone() if isinstance(body['packageId'],str) else None
        _check(row is not None, 'not_found', 404)
        return {'filename':'AuthzLedger-'+rid+'-'+body['packageId']+'.zip',
                'archive_b64':base64.b64encode(row['content']).decode('ascii')}
    _check(action in ('import','zap','controls','retest','sign'), 'not_found', 404)
    _version(body, state)
    if action == 'import':
        _fields(body, ('version','format','content_b64'))
        _add_source(state, engine.import_source(body['format'], _decode(body['content_b64'], MAX_FILE)))
    elif action == 'zap':
        _fields(body, ('version','apiKey'))
        _check(isinstance(body['apiKey'],str) and len(body['apiKey']) <= 1024, 'zap_credentials')
        _check(state['mode']=='commercial' and not state['locked'], 'closed_for_import', 409)
        if zap_data is None:
            return {'prepareZap': True}
        source = engine.import_source('zap', _dump({'observations':zap_data}).encode())
        _add_source(state, source)
    elif action == 'controls':
        _fields(body, ('version','controls'))
        _check(not state['locked'], 'baseline_frozen', 409)
        _check(state['sources'], 'source_required', 409)
        state['controls'] = _controls(body['controls'])
        _refresh_report(state)
    elif action == 'retest':
        _retest(state, body)
    else:
        _fields(body, ('version','language'))
        _check(isinstance(body['language'], str) and body['language'] in ('de','en','fr'), 'invalid_locale')
        _check(state['report'] is not None, 'source_required', 409)
        _check(_count(db, 'SELECT COUNT(*) FROM proof_archives WHERE run_id=?',(rid,)) < 24, 'archive_limit', 409)
        key = packages.key_history(db, directory, tid)['activeKeyId']
        archive = packages.sign_package(db, directory, tid, state['report'], body['language'])
        _check(len(archive) <= MAX_ARCHIVE, 'archive_limit', 413)
        db.execute('INSERT INTO proof_archives VALUES(?,?,?,?,?,?)', (_key(),rid,uid,key,body['language'],archive))
        state['locked'] = True
    _save(db, state, uid, action, now)
    return _view(db, state)
