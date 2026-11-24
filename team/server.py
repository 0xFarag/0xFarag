"""Local and TLS team server. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
from getpass import getpass
import hashlib
import hmac
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import mimetypes
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from urllib.parse import urlsplit

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from team import evidence, keyring, review_records

ROLES = ('admin', 'lead_pentester', 'pentester', 'reviewer', 'read_only')
WRITERS = frozenset(ROLES[:3])
REVIEWERS = frozenset(('admin', 'lead_pentester', 'reviewer'))
LOCALES = ('de', 'en', 'fr', 'it', 'ar')
ABSOLUTE_LIFETIME = 8 * 3600
IDLE_LIFETIME = 30 * 60
MAX_BODY = 4 * 1024 * 1024
DEFAULT_DIR = Path.home() / '.authzledger-team'
STATIC = Path(__file__).resolve().parent / 'static'
USER_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@+-]{0,79}\Z')
TOKEN_PATTERN = re.compile(r'[a-zA-Z0-9_-]{43}\Z')
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, locale TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS teams(id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memberships(
 team_id TEXT NOT NULL REFERENCES teams(id), user_id TEXT NOT NULL REFERENCES users(id),
 role TEXT NOT NULL CHECK(role IN ('admin','lead_pentester','pentester','reviewer','read_only')),
 active INTEGER NOT NULL CHECK(active IN (0,1)), PRIMARY KEY(team_id,user_id));
CREATE INDEX IF NOT EXISTS user_teams ON memberships(user_id,active);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 csrf TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS login_limits(bucket TEXT PRIMARY KEY, failures INTEGER NOT NULL, until_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS login_limits_expiry ON login_limits(until_at);
CREATE TABLE IF NOT EXISTS audit_events(
 id INTEGER PRIMARY KEY, at TEXT NOT NULL, team_id TEXT, actor TEXT, action TEXT NOT NULL,
 resource TEXT NOT NULL, outcome TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_team ON audit_events(team_id,id DESC);
CREATE TRIGGER IF NOT EXISTS audit_immutable_update BEFORE UPDATE ON audit_events BEGIN
 SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER IF NOT EXISTS audit_immutable_delete BEFORE DELETE ON audit_events BEGIN
 SELECT RAISE(ABORT,'append-only audit'); END;
"""

class ApiError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code

def _key():
    return secrets.token_hex(16)

def _hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def _username(value):
    if not isinstance(value,str) or not USER_PATTERN.fullmatch(value):
        raise ApiError(400,'invalid_username')
    return value

def _password(value):
    if not isinstance(value,str) or not 12 <= len(value) <= 256 or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ApiError(400,'invalid_password_length')
    return value

def _derive(password,salt):
    return hashlib.scrypt(password.encode('utf-8'),salt=salt,n=32768,r=8,p=1,dklen=32,maxmem=64*1024*1024)

def _store_password(password):
    salt=secrets.token_bytes(16)
    return 'scrypt-32768-8-1$' + salt.hex() + '$' + _derive(_password(password),salt).hex()

def _matches(password,stored):
    try:
        scheme,salt,expected=stored.split('$')
        if scheme != 'scrypt-32768-8-1': return False
        return hmac.compare_digest(_derive(password,bytes.fromhex(salt)),bytes.fromhex(expected))
    except (ValueError,UnicodeError):
        return False

def _team_name(value):
    if not isinstance(value,str) or not 1<=len(value.strip())<=100 or any(ord(c)<32 for c in value):
        raise ApiError(400,'invalid_team_name')
    return value.strip()

def _one(value,choices,code):
    if value not in choices:
        raise ApiError(400,code)
    return value

def _fields(body, allowed, required=()):
    if not isinstance(body,dict) or body.keys()-set(allowed) or set(required)-body.keys():
        raise ApiError(400,'invalid_fields')

def connect(data_dir):
    db=sqlite3.connect(Path(data_dir)/'team.sqlite3',timeout=15,isolation_level=None)
    # A committed signer change must survive power loss before removing the retired private key.
    db.execute('PRAGMA synchronous=FULL')
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def initialize(data_dir):
    directory=Path(data_dir)
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    if os.name=='posix':
        directory_mode=directory.stat()
        if directory_mode.st_uid!=os.geteuid() or directory_mode.st_mode & 0o022:
            raise ValueError('Use a workspace directory owned by this account without group or public write access.')
    dbfile=directory/'team.sqlite3'
    flags=os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0)
    descriptor=os.open(dbfile,flags,0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('The workspace database must be a regular file.')
        if os.name=='posix': os.fchmod(descriptor,0o600)
    finally:
        os.close(descriptor)
    with closing(connect(directory)) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
        evidence.init_db(db)

def needs_bootstrap(data_dir):
    initialize(data_dir)
    with closing(connect(data_dir)) as db:
        return db.execute('SELECT 1 FROM users LIMIT 1').fetchone() is None

def _log(db,team_id,actor,action,resource,outcome='ok'):
    now=datetime.now(timezone.utc).isoformat(timespec='seconds')
    db.execute('INSERT INTO audit_events(at,team_id,actor,action,resource,outcome) VALUES(?,?,?,?,?,?)',
               (now,team_id,actor,action,resource,outcome))

def bootstrap(data_dir,username,password,team_name='Workspace',locale='de'):
    initialize(data_dir)
    username=_username(username)
    encoded=_store_password(password)
    name=_team_name(team_name)
    locale=_one(locale,LOCALES,'invalid_locale')
    with closing(connect(data_dir)) as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            raise ApiError(409,'already_initialized')
        uid,tid=_key(),_key()
        db.execute('INSERT INTO users VALUES(?,?,?,?)',(uid,username,encoded,locale))
        db.execute('INSERT INTO teams VALUES(?,?)',(tid,name))
        db.execute('INSERT INTO memberships VALUES(?,?,?,1)',(tid,uid,'admin'))
        _log(db,tid,username,'bootstrap',tid)
        db.commit()

def _teams(db,uid):
    return [dict(r) for r in db.execute(
        'SELECT t.id,t.name,m.role FROM memberships m JOIN teams t ON t.id=m.team_id '
        'WHERE m.user_id=? AND m.active=1 ORDER BY t.name,t.id',(uid,))]

def _session_json(db,user,csrf):
    return {'user':{'id':user['id'],'username':user['username'],'locale':user['locale']},
            'teams':_teams(db,user['id']),'csrf':csrf}

def _user_events(db,user,action):
    for team in _teams(db,user['id']):
        _log(db,team['id'],user['username'],action,'account')

def _login(db,body,client,now):
    _fields(body,('username','password'),('username','password'))
    username, password=body['username'],body['password']
    if not isinstance(username,str) or not isinstance(password,str) or len(username)>80 or len(password)>256:
        raise ApiError(401,'invalid_credentials')
    buckets=(('address:'+_hash(client),80),('account:'+_hash(username.lower()),10))
    db.execute('DELETE FROM login_limits WHERE until_at<=?',(now,))
    for bucket,limit in buckets:
        row=db.execute('SELECT failures FROM login_limits WHERE bucket=?',(bucket,)).fetchone()
        if row and row['failures']>=limit:
            raise ApiError(429,'login_rate_limited')
    user=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    dummy='scrypt-32768-8-1$'+'00'*16+'$'+'00'*32
    valid=_matches(password,user['password_hash'] if user else dummy)
    if not valid or not user or not _teams(db,user['id']):
        for bucket,_ in buckets:
            db.execute('INSERT INTO login_limits VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET failures=failures+1',
                       (bucket,now+900))
        if user:
            for team in _teams(db,user['id']):
                _log(db,team['id'],None,'login','account/'+user['id'],'denied')
        else:
            _log(db,None,None,'login','account','denied')
        db.commit()
        raise ApiError(401,'invalid_credentials')
    db.execute('DELETE FROM login_limits WHERE bucket=?',(buckets[1][0],))
    db.execute('DELETE FROM sessions WHERE created_at<=? OR last_seen<=?',(now-ABSOLUTE_LIFETIME,now-IDLE_LIFETIME))
    token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
    db.execute('INSERT INTO sessions VALUES(?,?,?,?,?)',(_hash(token),user['id'],csrf,now,now))
    _user_events(db,user,'login')
    return _session_json(db,user,csrf),token

def _authenticated(db,token,now):
    if not token or not TOKEN_PATTERN.fullmatch(token): raise ApiError(401,'unauthenticated')
    row=db.execute('SELECT u.*,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id '
                   'WHERE s.token_hash=? AND s.created_at>? AND s.last_seen>?',
                   (_hash(token),now-ABSOLUTE_LIFETIME,now-IDLE_LIFETIME)).fetchone()
    if not row: raise ApiError(401,'unauthenticated')
    db.execute('UPDATE sessions SET last_seen=? WHERE token_hash=?',(now,_hash(token)))
    return row

def _members(db,tid):
    return {'members':[dict(r) | {'active':bool(r['active'])} for r in db.execute(
        'SELECT u.id,u.username,u.locale,m.role,m.active FROM memberships m JOIN users u ON u.id=m.user_id '
        'WHERE m.team_id=? ORDER BY u.username',(tid,))]}

def _add_member(db,tid,body):
    _fields(body,('username','password','role','locale'),('username','role'))
    name=_username(body['username'])
    role=_one(body['role'],ROLES,'invalid_role')
    locale=_one(body.get('locale','de'),LOCALES,'invalid_locale')
    user=db.execute('SELECT id FROM users WHERE username=?',(name,)).fetchone()
    if user:
        uid=user['id']
        if 'password' in body or 'locale' in body: raise ApiError(409,'existing_account')
        member=db.execute('SELECT active FROM memberships WHERE team_id=? AND user_id=?',(tid,uid)).fetchone()
        if member and member['active']: raise ApiError(409,'already_member')
    else:
        if 'password' not in body: raise ApiError(400,'password_required')
        uid=_key()
        db.execute('INSERT INTO users VALUES(?,?,?,?)',(uid,name,_store_password(body['password']),locale))
    db.execute('INSERT INTO memberships VALUES(?,?,?,1) ON CONFLICT(team_id,user_id) '
               'DO UPDATE SET role=excluded.role,active=1',(tid,uid,role))
    return {'id':uid}

def _update_member(db,tid,uid,body):
    _fields(body,('role','active'))
    if not body: raise ApiError(400,'invalid_fields')
    current=db.execute('SELECT * FROM memberships WHERE team_id=? AND user_id=?',(tid,uid)).fetchone()
    if not current: raise ApiError(404,'not_found')
    role=_one(body.get('role',current['role']),ROLES,'invalid_role')
    active=body.get('active',bool(current['active']))
    if type(active) is not bool: raise ApiError(400,'invalid_active')
    if current['active'] and current['role']=='admin' and (not active or role!='admin'):
        count=db.execute("SELECT COUNT(*) FROM memberships WHERE team_id=? AND active=1 AND role='admin'",(tid,)).fetchone()[0]
        if count<=1: raise ApiError(409,'last_admin')
    db.execute('UPDATE memberships SET role=?,active=? WHERE team_id=? AND user_id=?',(role,int(active),tid,uid))
    if not active and not _teams(db,uid): db.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
    return {'ok':True}

def _team_route(db,data_dir,tid,user,role,method,parts,body):
    uid=user['id']
    if not parts and method=='PATCH':
        if role!='admin': raise ApiError(403,'forbidden')
        _fields(body,('name',),('name',))
        db.execute('UPDATE teams SET name=? WHERE id=?',(_team_name(body['name']),tid))
        return {'ok':True}
    if parts[:1]==['members']:
        if role!='admin': raise ApiError(403,'forbidden')
        if len(parts)==1 and method=='GET': return _members(db,tid)
        if len(parts)==1 and method=='POST': return _add_member(db,tid,body)
        if len(parts)==2 and method=='PATCH': return _update_member(db,tid,parts[1],body)
        raise ApiError(404,'not_found')
    if parts==['audit'] and method=='GET':
        if role not in REVIEWERS: raise ApiError(403,'forbidden')
        return {'events':[dict(row) for row in db.execute('SELECT id,at,actor,action,resource,outcome FROM audit_events '
                                                          'WHERE team_id=? ORDER BY id DESC LIMIT 500',(tid,))]}
    cases=parts[:1]==['cases']
    if cases and len(parts)==3 and parts[2]=='control-reviews':
        if method=='POST':
            allowed = WRITERS | REVIEWERS if isinstance(body,dict) and body.get('kind')=='review' else WRITERS
            if role not in allowed: raise ApiError(403,'forbidden')
        elif method!='GET':
            raise ApiError(405,'method_not_allowed')
        return review_records.handle(db,tid,uid,method,parts,body)
    raw_attachment=cases and len(parts)==5 and parts[2]=='imports' and parts[4]=='attachment'
    if raw_attachment and method=='GET' and role not in WRITERS: raise ApiError(403,'forbidden')
    permitted=(method=='GET' and ((cases and len(parts) in (1,2)) or parts in (['trust-key'],['trust-keys']) or raw_attachment)) or (method=='POST' and parts==['verify'])
    if not permitted and method=='POST':
        if parts==['cases'] or (cases and len(parts)==3 and parts[-1] in ('imports','finding','retest')):
            if role not in WRITERS: raise ApiError(403,'forbidden')
        elif cases and len(parts)==3 and parts[-1]=='handover':
            if role not in REVIEWERS: raise ApiError(403,'forbidden')
        else: raise ApiError(404,'not_found')
    elif not permitted: raise ApiError(404,'not_found')
    result=evidence.handle(db,tid,uid,method,parts,body,data_dir=Path(data_dir))
    if cases and len(parts)==2 and method=='GET':
        result['control_reviews']=review_records.handle(db,tid,uid,'GET',parts+['control-reviews'],{})['records']
    return result

def dispatch(data_dir,method,path,body=None,*,token=None,csrf=None,client='local',now=None):
    """One database transaction per request. Return JSON and newly issued/deleted session token."""
    now=int(time.time()) if now is None else now
    body={} if body is None else body
    parts=path.strip('/').split('/')
    if not parts or parts[0]!='api': raise ApiError(404,'not_found')
    published_token=None
    actor=tid=None
    action=method.lower()
    resource='/'.join(parts[1:])[:240]
    with closing(connect(data_dir)) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            if parts==['api','login'] and method=='POST':
                result,published_token=_login(db,body,client,now)
            else:
                user=_authenticated(db,token,now)
                actor=user['username']
                if parts[:2]==['api','teams'] and len(parts)>=3:
                    tid=parts[2]
                    membership=db.execute('SELECT role FROM memberships WHERE team_id=? AND user_id=? AND active=1',
                                          (tid,user['id'])).fetchone()
                    if not membership:
                        tid=None
                        raise ApiError(404,'not_found')
                if method not in ('GET','HEAD') and (not isinstance(csrf,str) or not hmac.compare_digest(csrf.encode(),user['csrf'].encode())):
                    raise ApiError(403,'invalid_csrf')
                if parts==['api','session'] and method=='GET':
                    result=_session_json(db,user,user['csrf'])
                elif parts==['api','logout'] and method=='POST':
                    db.execute('DELETE FROM sessions WHERE token_hash=?',(_hash(token),))
                    _user_events(db,user,'logout')
                    result,published_token={'ok':True},''
                elif parts==['api','me'] and method=='PATCH':
                    _fields(body,('locale','current_password','password'))
                    if not body or ('current_password' in body) != ('password' in body): raise ApiError(400,'invalid_fields')
                    if 'locale' in body:
                        locale=_one(body['locale'],LOCALES,'invalid_locale')
                        db.execute('UPDATE users SET locale=? WHERE id=?',(locale,user['id']))
                    if 'password' in body:
                        old=body['current_password']
                        if not isinstance(old,str) or len(old)>256 or not _matches(old,user['password_hash']):
                            raise ApiError(403,'invalid_credentials')
                        db.execute('UPDATE users SET password_hash=? WHERE id=?',(_store_password(body['password']),user['id']))
                        db.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
                        published_token=''
                    _user_events(db,user,'update_account')
                    result={'ok':True,'reauthenticate':published_token==''}
                elif parts==['api','teams'] and method=='GET':
                    result={'teams':_teams(db,user['id'])}
                elif parts==['api','teams'] and method=='POST':
                    if not any(t['role']=='admin' for t in _teams(db,user['id'])): raise ApiError(403,'forbidden')
                    _fields(body,('name',),('name',))
                    name=_team_name(body['name'])
                    tid=_key()
                    db.execute('INSERT INTO teams VALUES(?,?)',(tid,name))
                    db.execute('INSERT INTO memberships VALUES(?,?,?,1)',(tid,user['id'],'admin'))
                    result={'team':{'id':tid,'name':name,'role':'admin'}}
                elif tid:
                    result=_team_route(db,data_dir,tid,user,membership['role'],method,parts[3:],body)
                else: raise ApiError(404,'not_found')
                if tid:
                    action=method.lower()+'.'+(parts[-1] if parts[-1] in ('teams','members','audit','cases','imports','finding','retest','handover','verify','trust-key','trust-keys') else parts[-2])
                    if method=='POST' and parts[-1]=='members': resource+='/'+result['id']
                    if method in ('PATCH','POST') and 'members' in parts and 'role' in body:
                        resource+=' role='+body['role']
                    if method=='PATCH' and 'members' in parts and 'active' in body:
                        resource+=' active='+str(body['active']).lower()
                    if method=='POST' and parts[-1]=='cases' and 'case' in result:
                        resource+='/'+result['case']['id']
                    _log(db,tid,actor,action,resource)
            db.commit()
        except (ApiError,evidence.WorkflowError) as exc:
            db.rollback()
            if actor:
                _log(db,tid,actor,action,resource,'denied' if exc.status in (401,403,404) else 'rejected')
            raise
        if action in ('post.handover','get.trust-key','get.trust-keys'):
            try:
                keyring.prune_committed(db,Path(data_dir))
            except (OSError,sqlite3.Error,keyring.KeyStoreError):
                # The handover is committed. Cleanup is retried on the next key read or handover.
                logging.getLogger(__name__).warning('Signing-key cleanup pending')
        return result,published_token

def _loopback(host):
    if host=='localhost': return True
    try: return ipaddress.ip_address(host).is_loopback
    except ValueError: return False

class Handler(BaseHTTPRequestHandler):
    server_version='AuthzLedger'
    sys_version=''
    protocol_version='HTTP/1.0'

    def setup(self):
        self.request.settimeout(15)
        super().setup()

    def log_message(self,format,*args):
        # The audit log records authorised resource identifiers. Never log raw headers or credentials.
        pass

    def _send(self,status,data,content_type='application/json; charset=utf-8',token=None):
        if not isinstance(data,bytes):
            data=json.dumps(data,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if self.server.tls_enabled:
            self.send_header('Strict-Transport-Security','max-age=31536000')
        if token is not None:
            value=f'{self.server.cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ABSOLUTE_LIFETIME if token else 0}'
            if self.server.tls_enabled: value+='; Secure'
            self.send_header('Set-Cookie',value)
        self.end_headers()
        if self.command!='HEAD': self.wfile.write(data)

    def _check_host(self):
        names=self.headers.get_all('Host',[])
        if len(names)!=1 or not re.fullmatch(r'[a-zA-Z0-9.\[\]:-]{1,255}',names[0]): raise ApiError(400,'invalid_host')
        host=names[0]
        try:
            netloc=urlsplit('//'+host)
            hostname=netloc.hostname
            port=netloc.port
        except ValueError:
            raise ApiError(400,'invalid_host') from None
        if not hostname or not self.server.tls_enabled and (not _loopback(hostname) or (port or 80)!=self.server.server_address[1]):
            raise ApiError(403,'invalid_host')
        origins=self.headers.get_all('Origin',[])
        expected=('https://' if self.server.tls_enabled else 'http://')+host
        if origins and (len(origins)!=1 or origins[0].lower()!=expected.lower()):
            raise ApiError(403,'invalid_origin')
        if self.headers.get('Sec-Fetch-Site')=='cross-site' and self.command not in ('GET','HEAD'):
            raise ApiError(403,'invalid_origin')

    def _payload(self):
        if self.headers.get('Transfer-Encoding'): raise ApiError(400,'invalid_length')
        lengths=self.headers.get_all('Content-Length',[])
        if self.command in ('GET','HEAD'):
            if lengths and lengths!=['0']: raise ApiError(400,'unexpected_body')
            return None
        if self.headers.get_content_type()!='application/json': raise ApiError(415,'json_required')
        if len(lengths)!=1 or not re.fullmatch(r'[0-9]{1,9}',lengths[0]):
            raise ApiError(411,'length_required')
        count=int(lengths[0])
        if not 1<=count<=MAX_BODY: raise ApiError(413,'invalid_size')
        raw=self.rfile.read(count)
        if len(raw)!=count: raise ApiError(400,'invalid_json')
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result: raise ValueError()
                result[key]=value
            return result
        def no_constants(value): raise ValueError()
        try:
            value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,parse_constant=no_constants)
            if not isinstance(value,dict): raise ValueError()
            # Escape sequences may decode to unpaired surrogates even in otherwise valid UTF-8.
            json.dumps(value,ensure_ascii=False).encode('utf-8')
            return value
        except (ValueError,RecursionError): raise ApiError(400,'invalid_json') from None

    def _serve(self):
        response_token=None
        try:
            self._check_host()
            if not self.path.startswith('/') or self.path.startswith('//') or len(self.path)>2048: raise ApiError(400,'invalid_path')
            path=urlsplit(self.path).path
            if path.startswith('/api/'):
                if not re.fullmatch(r'/api(?:/[A-Za-z0-9_-]{1,80})+/?',path): raise ApiError(404,'not_found')
                cookie=SimpleCookie()
                try: cookie.load(self.headers.get('Cookie',''))
                except CookieError: pass
                session=cookie.get(self.server.cookie_name)
                payload=self._payload()
                result,response_token=dispatch(self.server.data_dir,self.command,path,payload,
                    token=session.value if session else None,csrf=self.headers.get('X-CSRF-Token'),client=self.client_address[0])
                self._send(200,result,token=response_token)
            elif self.command in ('GET','HEAD'):
                parts=path.strip('/').split('/') if path!='/' else ['index.html']
                if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',p) or p in ('.','..') for p in parts):
                    raise ApiError(404,'not_found')
                item=STATIC.joinpath(*parts).resolve()
                if not item.is_relative_to(STATIC.resolve()) or not item.is_file(): raise ApiError(404,'not_found')
                content_type='text/javascript' if item.suffix in ('.js','.mjs') else (mimetypes.guess_type(item.name)[0] or 'application/octet-stream')
                self._send(200,item.read_bytes(),content_type)
            else: raise ApiError(405,'method_not_allowed')
        except (ApiError,evidence.WorkflowError) as exc:
            self._send(exc.status,{'error':exc.code if isinstance(exc,ApiError) else str(exc)})
        except sqlite3.OperationalError:
            self._send(503,{'error':'storage_unavailable'})
        except (BrokenPipeError,ConnectionResetError,TimeoutError):
            return
        except Exception:
            self._send(500,{'error':'internal_error'})

    do_GET=do_HEAD=do_POST=do_PATCH=do_DELETE=_serve

class WorkspaceServer(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True

    def __init__(self,*args,**kwargs):
        self.capacity=threading.BoundedSemaphore(32)
        super().__init__(*args,**kwargs)

    def process_request(self,request,address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,address)
        except Exception:
            self.capacity.release()
            raise

    def process_request_thread(self,request,address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.capacity.release()

def make_server(data_dir,host='127.0.0.1',port=8765,certfile=None,keyfile=None):
    if bool(certfile)!=bool(keyfile): raise ValueError('Provide both a TLS certificate and its private key.')
    if not _loopback(host) and not certfile: raise ValueError('A non-loopback listener requires TLS.')
    if needs_bootstrap(data_dir): raise ValueError('Initialize the first admin using --bootstrap or the desktop setup.')
    cls=WorkspaceServer
    if ':' in host:
        class IPv6Server(WorkspaceServer):
            address_family=socket.AF_INET6
        cls=IPv6Server
    context=None
    if certfile:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile,keyfile)
    server=cls((host,port),Handler)
    server.data_dir=Path(data_dir)
    server.tls_enabled=context is not None
    if context:
        server.socket=context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    # A separate port and data directory get a separate cookie name.
    suffix=_hash(str(Path(data_dir).resolve())+':'+str(server.server_address[1]))[:16]
    server.cookie_name=('__Host-' if context else '')+'authz_session_'+suffix
    return server

def main(argv=None):
    parser=argparse.ArgumentParser(description='AuthzLedger local or TLS team workspace')
    parser.add_argument('--data-dir',type=Path,default=DEFAULT_DIR)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--certfile',type=Path)
    parser.add_argument('--keyfile',type=Path)
    parser.add_argument('--bootstrap',action='store_true',help='Create the first admin and team, then exit')
    args=parser.parse_args(argv)
    try:
        if args.bootstrap:
            if not needs_bootstrap(args.data_dir): raise ValueError('Already initialized.')
            name=input('Admin username [admin]: ').strip() or 'admin'
            password=getpass('Admin password (at least 12 characters): ')
            if password!=getpass('Repeat password: '): raise ValueError('Passwords do not match.')
            bootstrap(args.data_dir,name,password)
            print('Workspace initialized.')
            return
        server=make_server(args.data_dir,args.host,args.port,args.certfile,args.keyfile)
        print(f'AuthzLedger listening on {args.host}:{server.server_address[1]}',flush=True)
        with server:
            try: server.serve_forever()
            except KeyboardInterrupt: pass
    except (ValueError,ApiError,OSError) as exc:
        parser.exit(2,f'{exc}\n')

if __name__=='__main__': main()
