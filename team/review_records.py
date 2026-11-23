"""Immutable, case-scoped plans and manual reviews of already captured evidence."""
import json
import re
import sqlite3
import uuid

from team import evidence


def init_db(db):
    db.execute("""CREATE TABLE IF NOT EXISTS case_control_reviews (
        team_id TEXT NOT NULL, case_id TEXT NOT NULL, id TEXT NOT NULL, parent_id TEXT,
        actor_id TEXT NOT NULL, request_id TEXT NOT NULL, request_sha256 TEXT NOT NULL, document TEXT NOT NULL,
        PRIMARY KEY(team_id, case_id, id),
        UNIQUE(team_id, case_id, parent_id), UNIQUE(team_id, case_id, actor_id, request_id),
        FOREIGN KEY(team_id, case_id) REFERENCES evidence_cases(team_id, id),
        FOREIGN KEY(team_id, case_id, parent_id) REFERENCES case_control_reviews(team_id, case_id, id))""")
    for operation in ('UPDATE', 'DELETE'):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS control_reviews_block_{operation.lower()}
            BEFORE {operation} ON case_control_reviews
            BEGIN SELECT RAISE(ABORT, 'append-only control review'); END""")


def read_record(serialized):
    document = json.loads(serialized)
    digest = document.pop('sha256')
    evidence.require(evidence.sha(evidence.canonical(document)) == digest, 'Stored revision digest differs', 409)
    document['sha256'] = digest
    return document


def finding_reference(db, team, case, asset, identifier):
    if identifier is None:
        return None
    finding = evidence.one(db, team, case, 'findings', identifier)
    evidence.require(finding['asset'] == asset, 'Finding outside the selected asset')
    return {'id': finding['id'], 'sha256': finding['finding_sha256']}


def source_reference(db, team, case, asset, selected, decisive):
    if selected is None:
        evidence.require(not decisive, 'Select both source records for an assessed outcome')
        return None
    evidence.require(isinstance(selected, dict) and set(selected) == {'import_id', 'record'}, 'Invalid source selector')
    ref = evidence.reference(db, team, case, {'evidence_id': selected['import_id'], 'record': selected['record']})
    expected_asset = evidence.sha(asset.encode())
    evidence.require(ref['asset_id'] == expected_asset or (ref['asset_id'] is None and not decisive),
                     'Source record cannot be linked to the selected asset')
    # These identifiers re-locate a record in the exact original bytes. User text or raw traffic is not copied.
    return {k: ref[k] for k in ('import_id','format','sha256','record','fingerprint','kind','asset_id')}


def handle(db, team, actor, method, parts, body):
    """Server supplies authenticated membership, a write transaction, CSRF and role enforcement."""
    evidence.require(len(parts) == 3 and parts[0] == 'cases' and parts[2] == 'control-reviews', 'Unknown route', 404)
    case_id = parts[1]
    case_row = db.execute('SELECT document FROM evidence_cases WHERE team_id=? AND id=?', (team, case_id)).fetchone()
    evidence.require(case_row, 'Unknown case', 404)
    case = json.loads(case_row[0])
    if method == 'GET':
        rows = db.execute('SELECT document FROM case_control_reviews WHERE team_id=? AND case_id=? ORDER BY rowid', (team, case_id))
        return {'records': [read_record(row[0]) for row in rows]}
    evidence.require(method == 'POST' and isinstance(body, dict), 'Invalid control-review request')
    kind = body.get('kind')
    fields = {'kind','request_id','finding_id'}
    if kind == 'plan':
        fields.update(('asset','hypothesis','expected','control'))
    elif kind == 'review':
        fields.update(('parent_id','parent_sha256','observed','control_observed','outcome','evidence','control_evidence'))
    else:
        raise evidence.WorkflowError(400, 'Unknown control-review action')
    evidence.require(not (set(body) - fields), 'Unexpected control-review fields')
    nonce = body.get('request_id')
    evidence.require(isinstance(nonce, str) and re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', nonce), 'Invalid request identifier')
    request_hash = evidence.sha(evidence.canonical(body))
    saved = db.execute('SELECT request_sha256, document FROM case_control_reviews WHERE team_id=? AND case_id=? AND actor_id=? AND request_id=?',
                       (team, case_id, actor, nonce)).fetchone()
    if saved:
        evidence.require(saved[0] == request_hash, 'Request identifier already used for different input', 409)
        return {'record': read_record(saved[1])}

    count = db.execute('SELECT COUNT(*) FROM case_control_reviews WHERE team_id=? AND case_id=?', (team, case_id)).fetchone()[0]
    evidence.require(count < 256, 'Case review history is full', 409)
    identifier = uuid.uuid4().hex
    document = {'schema':'authzledger.control-review/v1','team_id':team,'case_id':case_id,'id':identifier,
                'kind':kind,'actor_id':actor,'created_at':evidence.now()}
    parent_id = None
    if kind == 'plan':
        asset = body.get('asset')
        evidence.require(isinstance(asset,str) and asset in case['assets'], 'Asset outside the case scope')
        document.update(plan_id=identifier, parent_id=None, parent_sha256=None, asset=asset,
                        hypothesis=evidence.string(body.get('hypothesis'),'hypothesis',1000),
                        expected=evidence.string(body.get('expected'),'expected observation',1500),
                        control=evidence.string(body.get('control'),'planned control',1500),
                        finding=finding_reference(db,team,case_id,asset,body.get('finding_id')))
    else:
        parent_id = body.get('parent_id')
        evidence.require(isinstance(parent_id,str) and len(parent_id)==32, 'Invalid previous revision')
        row = db.execute('SELECT document FROM case_control_reviews WHERE team_id=? AND case_id=? AND id=?', (team,case_id,parent_id)).fetchone()
        evidence.require(row, 'Unknown previous revision in this case',404)
        parent = read_record(row[0])
        evidence.require(body.get('parent_sha256') == parent['sha256'], 'Previous revision digest differs',409)
        existing_child = db.execute('SELECT 1 FROM case_control_reviews WHERE team_id=? AND case_id=? AND parent_id=?',(team,case_id,parent_id)).fetchone()
        evidence.require(not existing_child, 'A newer revision exists; reload the case',409)
        asset = parent['asset']
        finding_id = body.get('finding_id')
        finding = parent['finding']
        if finding_id is not None:
            evidence.require(finding is None or finding['id'] == finding_id, 'Linked finding cannot change')
            finding = finding_reference(db,team,case_id,asset,finding_id)
        outcome = body.get('outcome')
        evidence.require(outcome in ('supports','contradicts','inconclusive'), 'Unknown manual assessment')
        decisive = outcome != 'inconclusive'
        main = source_reference(db,team,case_id,asset,body.get('evidence'),decisive)
        control = source_reference(db,team,case_id,asset,body.get('control_evidence'),decisive)
        if main and control:
            evidence.require(main['fingerprint'] != control['fingerprint'], 'Select two distinct source observations')
        document.update(plan_id=parent['plan_id'], parent_id=parent_id, parent_sha256=parent['sha256'], asset=asset,
                        finding=finding, outcome=outcome, observed=evidence.string(body.get('observed'),'observed result',2000),
                        control_observed=evidence.string(body.get('control_observed'),'control observation',1500),
                        evidence=main, control_evidence=control)
    document['sha256'] = evidence.sha(evidence.canonical(document))
    try:
        db.execute('INSERT INTO case_control_reviews VALUES(?,?,?,?,?,?,?,?)',
                   (team, case_id, identifier, parent_id, actor, nonce, request_hash, evidence.canonical(document).decode()))
    except sqlite3.IntegrityError as error:
        raise evidence.WorkflowError(409, 'A concurrent revision exists; reload the case') from error
    return {'record': document}
