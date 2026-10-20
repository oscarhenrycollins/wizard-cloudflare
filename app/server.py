"""Private, owner-controlled Cloudflare connector (stdlib-only runtime)."""
import base64, hashlib, hmac, json, mimetypes, os, re, secrets, sqlite3, tempfile, threading, time
import urllib.error, urllib.parse, urllib.request
from contextlib import contextmanager
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent; DATA=Path(os.getenv('DATA_DIR',ROOT/'.data')); WEB=ROOT/'web'
APP_ID='wizard-cloudflare'; VERSION='1.3.0-testing'; PORT=int(os.getenv('PORT','18805'))
API='https://api.cloudflare.com/client/v4'
OAUTH={'auth':'https://dash.cloudflare.com/oauth2/auth','token':'https://dash.cloudflare.com/oauth2/token','revoke':'https://dash.cloudflare.com/oauth2/revoke','userinfo':'https://dash.cloudflare.com/oauth2/userinfo'}
WRITES=os.getenv('CF_ALLOW_WRITES','false').lower()=='true'
MAX_BODY=1_450_000; MAX_RESPONSE=2_000_000; MAX_OBJECT=1_048_576; FLOW_TTL=300; APPROVAL_TTL=300; SESSION_TTL=28800
ACCOUNT_ID=re.compile(r'^[0-9a-f]{32}$'); SAFE_ID=re.compile(r'^[A-Za-z0-9_.-]{1,128}$')
DOMAIN=re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')

class Problem(Exception):
 def __init__(self,status,code,message): super().__init__(code); self.status,self.code,self.message=status,code,message
def now(): return int(time.time())
def canon(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(value): return hashlib.sha256(value.encode() if isinstance(value,str) else value).hexdigest()
def safe_id(value,label='id'):
 if not isinstance(value,str) or not SAFE_ID.fullmatch(value): raise Problem(400,'invalid_parameter',f'Invalid {label}.')
 return value
def account_id(value):
 if not isinstance(value,str) or not ACCOUNT_ID.fullmatch(value): raise Problem(400,'invalid_account','Account id must be 32 lowercase hex characters.')
 return value
def provider_id(value,label):
 if not isinstance(value,str) or not ACCOUNT_ID.fullmatch(value): raise Problem(400,'invalid_parameter',f'Invalid {label}.')
 return value
def bounded_text(value,label,maximum,minimum=1):
 if not isinstance(value,str) or not minimum<=len(value)<=maximum: raise Problem(400,'invalid_payload',f'Invalid {label}.')
 return value
def exact_body(value,required=(),optional=()):
 if set(value)!=set(required)|(set(value)&set(optional)) or not set(required)<=set(value):raise Problem(400,'invalid_body','Request fields do not match the route schema.')
 return value

class ClosingConnection(sqlite3.Connection):
 def __exit__(self,*args):
  try:return super().__exit__(*args)
  finally:self.close()

SCHEMA='''PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,revision INTEGER NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL,account_inventory TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS connection_accounts(connection_id TEXT NOT NULL,account_id TEXT NOT NULL,name TEXT NOT NULL,PRIMARY KEY(connection_id,account_id),FOREIGN KEY(connection_id) REFERENCES connections(id));
CREATE TABLE IF NOT EXISTS sessions(cookie_hash TEXT PRIMARY KEY,csrf_hash TEXT NOT NULL,expires INTEGER NOT NULL,generation INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_flows(state_hash TEXT PRIMARY KEY,session_hash TEXT NOT NULL,verifier TEXT NOT NULL,name TEXT NOT NULL,expires INTEGER NOT NULL,status TEXT NOT NULL,session_generation INTEGER NOT NULL,global_generation INTEGER NOT NULL,connection_id TEXT,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,connection_id TEXT NOT NULL,account_id TEXT NOT NULL,action TEXT NOT NULL,payload TEXT NOT NULL,payload_digest TEXT NOT NULL,revision INTEGER NOT NULL,status TEXT NOT NULL,source TEXT NOT NULL,session_hash TEXT,expires INTEGER NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,connection_id TEXT NOT NULL,account_id TEXT NOT NULL,bucket TEXT NOT NULL,capabilities TEXT NOT NULL,client_identifier TEXT NOT NULL,bearer_hash TEXT NOT NULL UNIQUE,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,updated INTEGER NOT NULL);'''
def _private(path,mode):
 try:os.chmod(path,mode)
 except FileNotFoundError:pass
def db():
 DATA.mkdir(parents=True,exist_ok=True,mode=0o700); _private(DATA,0o700); path=DATA/'cloudflare.sqlite3'
 conn=sqlite3.connect(path,timeout=10,isolation_level=None,check_same_thread=False,factory=ClosingConnection); conn.row_factory=sqlite3.Row
 conn.executescript(SCHEMA); conn.execute("INSERT OR IGNORE INTO settings VALUES('oauth_generation','0')"); _migrate(conn)
 _private(path,0o600); _private(Path(str(path)+'-wal'),0o600); _private(Path(str(path)+'-shm'),0o600); return conn
def _migrate(conn):
 additions={'connections':{'account_inventory':"TEXT NOT NULL DEFAULT '{}'"},'oauth_flows':{'name':"TEXT NOT NULL DEFAULT 'Cloudflare'",'status':"TEXT NOT NULL DEFAULT 'pending'",'session_generation':'INTEGER NOT NULL DEFAULT 0','global_generation':'INTEGER NOT NULL DEFAULT 0','connection_id':'TEXT','created':'INTEGER NOT NULL DEFAULT 0','redirect_uri':'TEXT'},'approvals':{'source':"TEXT NOT NULL DEFAULT 'ui'",'updated':'INTEGER NOT NULL DEFAULT 0'},'grants':{'client_identifier':"TEXT NOT NULL DEFAULT 'legacy-consumer'",'updated':'INTEGER NOT NULL DEFAULT 0'}}
 for table,columns in additions.items():
  present={row['name'] for row in conn.execute(f'PRAGMA table_info({table})')}
  for name,declaration in columns.items():
   if name not in present:conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {declaration}')

class SecretStore:
 def __init__(self,path=None): self.path=Path(path or DATA/'credentials.json'); self.lock=threading.RLock()
 def _read_locked(self):
  if not self.path.exists():return {}
  try:value=json.loads(self.path.read_text(encoding='utf-8'))
  except (OSError,UnicodeDecodeError,json.JSONDecodeError):raise Problem(503,'credential_store_unavailable','Credential storage is unavailable.') from None
  if not isinstance(value,dict):raise Problem(503,'credential_store_unavailable','Credential storage is unavailable.')
  return value
 def read(self):
  with self.lock:return self._read_locked()
 def get(self,key):
  with self.lock:
   value=self._read_locked().get(key); return dict(value) if isinstance(value,dict) else None
 def _replace_locked(self,value):
  self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700); _private(self.path.parent,0o700)
  fd,temporary=tempfile.mkstemp(prefix='.credentials-',dir=self.path.parent)
  try:
   os.fchmod(fd,0o600)
   with os.fdopen(fd,'w',encoding='utf-8') as stream:
    json.dump(value,stream,separators=(',',':'),ensure_ascii=False); stream.flush(); os.fsync(stream.fileno())
   os.replace(temporary,self.path); _private(self.path,0o600)
   directory=os.open(self.path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
   try:os.fsync(directory)
   finally:os.close(directory)
  finally:
   try:os.unlink(temporary)
   except FileNotFoundError:pass
 def put(self,key,value):
  with self.lock:
   data=self._read_locked(); data[key]=value; self._replace_locked(data)
 def delete(self,key):
  with self.lock:
   data=self._read_locked()
   if key not in data:return False
   del data[key]; self._replace_locked(data); return True
SECRETS=SecretStore()

class RedirectRefused(Exception):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):raise RedirectRefused()
 def _refuse(self,req,fp,code,msg,headers):raise RedirectRefused()
 http_error_301=_refuse; http_error_302=_refuse; http_error_303=_refuse; http_error_307=_refuse; http_error_308=_refuse
class Transport:
 def __init__(self,opener=None):self.opener=opener or urllib.request.build_opener(NoRedirect())
 @staticmethod
 def _allowed(url):
  parsed=urllib.parse.urlsplit(url)
  if parsed.scheme!='https' or parsed.username or parsed.password or parsed.fragment:return False
  return (parsed.netloc=='api.cloudflare.com' and parsed.path.startswith('/client/v4/')) or url in OAUTH.values()
 @staticmethod
 def multipart(fields,files,boundary):
  chunks=[]
  for name,value in fields.items():
   if isinstance(value,tuple):
    content_type,content=value; content=content if isinstance(content,bytes) else str(content).encode(); chunks += [f'--{boundary}\r\n'.encode(),f'Content-Disposition: form-data; name="{name}"\r\n'.encode(),f'Content-Type: {content_type}\r\n\r\n'.encode(),content,b'\r\n']
   else:chunks += [f'--{boundary}\r\n'.encode(),f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),str(value).encode(),b'\r\n']
  for name,(filename,content_type,content) in files.items():chunks += [f'--{boundary}\r\n'.encode(),f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode(),f'Content-Type: {content_type}\r\n\r\n'.encode(),content,b'\r\n']
  chunks.append(f'--{boundary}--\r\n'.encode()); return b''.join(chunks)
 def request(self,method,url,headers=None,body=None,body_kind='json',envelope=True,require_result=True):
  if not self._allowed(url):raise Problem(500,'transport_policy','Provider endpoint refused.')
  request_headers={'User-Agent':f'{APP_ID}/{VERSION}','Accept':'application/json'}; request_headers.update(headers or {}); data=None
  if body is not None:
   if body_kind=='json':data=canon(body).encode(); request_headers['Content-Type']='application/json'
   elif body_kind=='form':
    if not isinstance(body,dict):raise Problem(500,'transport_policy','Invalid form body.')
    data=urllib.parse.urlencode(body).encode(); request_headers['Content-Type']='application/x-www-form-urlencoded'
   elif body_kind=='raw':
    if not isinstance(body,(bytes,bytearray)):raise Problem(500,'transport_policy','Invalid raw body.')
    data=bytes(body)
   elif body_kind=='multipart':
    if not isinstance(body,dict) or set(body)!={'fields','files'}:raise Problem(500,'transport_policy','Invalid multipart body.')
    boundary='wz-'+secrets.token_hex(16); data=self.multipart(body['fields'],body['files'],boundary); request_headers['Content-Type']=f'multipart/form-data; boundary={boundary}'
   else:raise Problem(500,'transport_policy','Unknown provider body encoding.')
  request=urllib.request.Request(url,data=data,method=method,headers=request_headers)
  try:
   with self.opener.open(request,timeout=12) as response:raw=response.read(MAX_RESPONSE+1); status=response.status
  except RedirectRefused:raise Problem(502,'provider_redirect','Cloudflare redirect refused.') from None
  except urllib.error.HTTPError as error:
   error.close()
   if 300<=error.code<400:code='provider_redirect'
   elif error.code in (401,403):code='provider_unauthorized'
   elif error.code==404:code='provider_not_found'
   elif error.code==429:code='provider_rate_limited'
   else:code='provider_rejected'
   raise Problem(502,code,'Cloudflare rejected the request.') from None
  except (urllib.error.URLError,TimeoutError,OSError):raise Problem(502,'provider_unavailable','Cloudflare is unavailable.') from None
  if len(raw)>MAX_RESPONSE:raise Problem(502,'provider_too_large','Cloudflare response was too large.')
  if not raw and not envelope and not require_result:value={}
  else:
   try:value=json.loads(raw)
   except (json.JSONDecodeError,UnicodeDecodeError):raise Problem(502,'provider_malformed','Cloudflare returned a malformed response.') from None
  if not isinstance(value,dict):raise Problem(502,'provider_malformed','Cloudflare returned a malformed response.')
  if envelope:
   if value.get('success') is not True:raise Problem(502,'provider_rejected','Cloudflare rejected the request.')
   if require_result and 'result' not in value:raise Problem(502,'provider_malformed','Cloudflare returned a malformed response.')
  return status,value

CONNECTION_LOCKS={}; GRANT_LOCKS={}; LOCK_MAP_GUARD=threading.Lock()
def keyed_lock(mapping,key):
 with LOCK_MAP_GUARD:return mapping.setdefault(key,threading.RLock())

class Service:
 def __init__(self,transport=None,secret_store=None,writes_allowed=None):
  self.transport=transport or Transport(); self.secrets=secret_store or SECRETS; self.writes_allowed=WRITES if writes_allowed is None else bool(writes_allowed); db().close(); self.reconcile()
 @staticmethod
 def oauth_config():return {'client_id':os.getenv('CF_OAUTH_CLIENT_ID','').strip(),'redirect_uri':os.getenv('CF_OAUTH_REDIRECT_URI','').strip(),'scope':os.getenv('CF_OAUTH_SCOPE','').strip()}
 @classmethod
 def redirect_uris(cls):
  # One exact registered callback per shell origin; the browser's own origin picks which one is used.
  values=[cls.oauth_config()['redirect_uri']]+[x.strip() for x in os.getenv('CF_OAUTH_REDIRECT_URIS','').split(',')]
  return [x for i,x in enumerate(values) if x and x.startswith(('http://','https://')) and (x.endswith('/oauth/callback') or x=='https://www.aiwizards.com/wizard-cloudflare/auth/callback') and x not in values[:i]]
 @classmethod
 def oauth_configured(cls):
  cfg=cls.oauth_config(); return bool(cfg['client_id'] and cfg['scope'] and cls.redirect_uris())
 @classmethod
 def pick_redirect(cls,origin=None):
  uris=cls.redirect_uris()
  if origin:
   wanted=urllib.parse.urlsplit(origin.lower()); matches=[uri for uri in uris if (lambda u:(u.scheme,u.netloc)==(wanted.scheme,wanted.netloc))(urllib.parse.urlsplit(uri.lower()))]
   if matches:return matches[0]
   if len(uris)>1:raise Problem(409,'oauth_origin_unregistered','Cloudflare sign-in is not set up for this address.')
  if not uris:raise Problem(409,'oauth_unavailable','Cloudflare OAuth is not configured.')
  return uris[0]
 def reconcile(self):
  with db() as conn:
   conn.execute("UPDATE approvals SET status='manual_review',updated=? WHERE status='executing'",(now(),))
   rows=conn.execute('SELECT id,status FROM connections').fetchall(); known={row['id'] for row in rows}
   for row in rows:
    if row['status']=='connected' and not self.secrets.get(row['id']):conn.execute("UPDATE connections SET status='credential_missing',revision=revision+1,updated=? WHERE id=?",(now(),row['id']))
  for key in self.secrets.read():
   if key not in known:self.secrets.delete(key)
 def list_connections(self):
  with db() as conn:
   rows=conn.execute('SELECT id,name,kind,status,revision,created,updated FROM connections ORDER BY created,id').fetchall(); values=[]
   for row in rows:
    item=dict(row); stored=conn.execute('SELECT account_inventory FROM connections WHERE id=?',(row['id'],)).fetchone()['account_inventory']
    try:item['account_inventory']=json.loads(stored)
    except (TypeError,json.JSONDecodeError):item['account_inventory']={'bounded':True,'complete':False,'is_truncated':None}
    item['accounts']=[dict(a) for a in conn.execute('SELECT account_id AS id,name FROM connection_accounts WHERE connection_id=? ORDER BY name,account_id',(row['id'],))]; values.append(item)
  return {'contract':'wizard.cloudflare-connection/1','provider':'cloudflare','connections':values,'oauth_configured':self.oauth_configured(),'token_fallback':not self.oauth_configured(),'writes_allowed':self.writes_allowed,'registrar_registration_enabled':False}
 def connection(self,connection_id,allow_disconnected=False):
  safe_id(connection_id,'connection id')
  with db() as conn:row=conn.execute('SELECT * FROM connections WHERE id=?',(connection_id,)).fetchone()
  if not row or (not allow_disconnected and row['status']!='connected'):raise Problem(404,'connection_unavailable','Connection is unavailable.')
  return dict(row)
 @staticmethod
 def _accounts_from_result(result):
  if not isinstance(result,list):raise Problem(502,'provider_malformed','Cloudflare returned malformed accounts.')
  accounts=[]
  for value in result:
   if not isinstance(value,dict) or not ACCOUNT_ID.fullmatch(str(value.get('id',''))):raise Problem(502,'provider_malformed','Cloudflare returned malformed accounts.')
   accounts.append({'id':value['id'],'name':str(value.get('name') or value['id'])[:200]})
  return accounts
 def _verify_accounts(self,access_token,exact=None):
  headers={'Authorization':'Bearer '+access_token}
  if exact:
   exact=account_id(exact); _,response=self.transport.request('GET',f'{API}/accounts/{exact}',headers); result=response['result']
   if not isinstance(result,dict) or result.get('id')!=exact:raise Problem(502,'provider_account_mismatch','Cloudflare account verification did not match.')
   return [{'id':exact,'name':str(result.get('name') or exact)[:200]}],{'bounded':True,'requested':1,'returned':1,'is_truncated':False,'complete':True}
  _,response=self.transport.request('GET',f'{API}/accounts?per_page=50&page=1',headers); accounts=self._accounts_from_result(response['result'])
  if not accounts:raise Problem(403,'no_authorized_accounts','No authorized account; supply an exact account id for a restricted token.')
  inventory=self._page_info(response,50,len(accounts),page=1); inventory['bounded']=True
  return accounts,inventory
 def _persist_connection(self,name,kind,secret,accounts,account_inventory=None):
  bounded_text(name.strip() if isinstance(name,str) else name,'name',80); connection_id=secrets.token_hex(12); stamp=now(); self.secrets.put(connection_id,secret)
  account_inventory=account_inventory or {'bounded':True,'requested':len(accounts),'returned':len(accounts),'is_truncated':False,'complete':True}
  try:
   with db() as conn:
    conn.execute('BEGIN IMMEDIATE'); conn.execute("INSERT INTO connections(id,name,kind,status,revision,created,updated,account_inventory) VALUES(?,?,?,'connected',1,?,?,?)",(connection_id,name.strip(),kind,stamp,stamp,canon(account_inventory))); conn.executemany('INSERT INTO connection_accounts VALUES(?,?,?)',[(connection_id,a['id'],a['name']) for a in accounts]); conn.commit()
  except Exception:self.secrets.delete(connection_id); raise
  return {'id':connection_id,'name':name.strip(),'kind':kind,'status':'connected','revision':1,'accounts':accounts,'account_inventory':account_inventory}
 def connect_token(self,name,token,exact_account=None):
  if self.oauth_configured() and os.getenv('CF_ALLOW_TOKEN_CONNECT','').lower()!='true':raise Problem(409,'oauth_required','Use Cloudflare sign-in while OAuth is configured.')
  bounded_text(name.strip() if isinstance(name,str) else name,'name',80)
  if not isinstance(token,str) or not 8<=len(token)<=4096:raise Problem(400,'invalid_token','A scoped token is required.')
  accounts,inventory=self._verify_accounts(token,exact_account); return self._persist_connection(name,'token',{'access_token':token},accounts,inventory)
 def _global_generation(self,conn):return int(conn.execute("SELECT value FROM settings WHERE key='oauth_generation'").fetchone()[0])
 def oauth_start(self,name,session_hash,origin=None):
  if not self.oauth_configured():raise Problem(409,'oauth_unavailable','Cloudflare OAuth is not configured.')
  name=name.strip() if isinstance(name,str) else ''
  if name:bounded_text(name,'name',80)
  redirect_uri=self.pick_redirect(origin); cfg=self.oauth_config(); state=secrets.token_urlsafe(32)
  if os.getenv('CF_OAUTH_RELAY','').lower()=='true':
   # The complete encoded state is hash-bound to this browser session in SQLite. The relay does not authenticate it.
   if redirect_uri!='https://www.aiwizards.com/wizard-cloudflare/auth/callback' or origin not in TRUSTED_ORIGINS:raise Problem(409,'oauth_origin_unregistered','Open sign-in from your Wizard address.')
   target=urllib.parse.urlsplit(origin)
   if target.scheme!='https' or target.username or target.password or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net',target.hostname or ''):raise Problem(409,'oauth_origin_unregistered','A private HTTPS Wizard address is required.')
   state='wcf1.'+base64.urlsafe_b64encode(canon({'n':state,'r':origin+'/wizard-cloudflare/oauth/callback'}).encode()).rstrip(b'=').decode()
  verifier=secrets.token_urlsafe(64); challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode(); stamp=now()
  with db() as conn:
   conn.execute('BEGIN IMMEDIATE'); session=conn.execute('SELECT generation,expires FROM sessions WHERE cookie_hash=?',(session_hash,)).fetchone()
   if not session or session['expires']<=stamp:raise Problem(401,'owner_session_required','Owner browser session required.')
   generation=session['generation']+1; conn.execute('UPDATE sessions SET generation=? WHERE cookie_hash=?',(generation,session_hash)); conn.execute("UPDATE oauth_flows SET status='cancelled' WHERE session_hash=? AND status IN ('pending','exchanging')",(session_hash,)); conn.execute("INSERT INTO oauth_flows(state_hash,session_hash,verifier,name,expires,status,session_generation,global_generation,connection_id,created,redirect_uri) VALUES(?,?,?,?,?,'pending',?,?,NULL,?,?)",(sha(state),session_hash,verifier,name,stamp+FLOW_TTL,generation,self._global_generation(conn),stamp,redirect_uri)); conn.commit()
  query=urllib.parse.urlencode({'response_type':'code','client_id':cfg['client_id'],'redirect_uri':redirect_uri,'scope':cfg['scope'],'state':state,'code_challenge':challenge,'code_challenge_method':'S256'})
  return {'authorization_url':OAUTH['auth']+'?'+query,'status':'pending','expires':stamp+FLOW_TTL}
 def oauth_status(self,session_hash):
  with db() as conn:
   conn.execute("UPDATE oauth_flows SET status='expired' WHERE session_hash=? AND status='pending' AND expires<=?",(session_hash,now())); rows=conn.execute('SELECT status,expires,connection_id,created FROM oauth_flows WHERE session_hash=? ORDER BY created DESC,rowid DESC LIMIT 10',(session_hash,)).fetchall()
  return {'flows':[dict(row) for row in rows]}
 def oauth_cancel(self,session_hash):
  with db() as conn:
   conn.execute('BEGIN IMMEDIATE'); session=conn.execute('SELECT 1 FROM sessions WHERE cookie_hash=?',(session_hash,)).fetchone()
   if not session:raise Problem(401,'owner_session_required','Owner browser session required.')
   conn.execute('UPDATE sessions SET generation=generation+1 WHERE cookie_hash=?',(session_hash,)); changed=conn.execute("UPDATE oauth_flows SET status='cancelled' WHERE session_hash=? AND status IN ('pending','exchanging')",(session_hash,)).rowcount; conn.commit()
  return {'status':'cancelled' if changed else 'not_pending','cancelled':changed}
 def oauth_fail(self,session_hash,state=None):
  # An error callback must be bound to the same one-use state; unsolicited errors cannot cancel sign-in.
  if not isinstance(state,str) or not state:return {'status':'failed','failed':0}
  with db() as conn:changed=conn.execute("UPDATE oauth_flows SET status='failed' WHERE session_hash=? AND state_hash=? AND status='pending'",(session_hash,sha(state))).rowcount
  return {'status':'failed','failed':changed}
 def _oauth_finalize_ready(self):pass
 def oauth_callback(self,state,code,session_hash):
  bounded_text(state,'state',512); bounded_text(code,'authorization code',4096); stamp=now(); state_hash=sha(state)
  with db() as conn:
   conn.execute('BEGIN IMMEDIATE'); flow=conn.execute('SELECT * FROM oauth_flows WHERE state_hash=?',(state_hash,)).fetchone(); session=conn.execute('SELECT generation,expires FROM sessions WHERE cookie_hash=?',(session_hash,)).fetchone()
   valid=flow and session and flow['session_hash']==session_hash and flow['status']=='pending' and flow['expires']>stamp and session['expires']>stamp and flow['session_generation']==session['generation'] and flow['global_generation']==self._global_generation(conn)
   if not valid:conn.rollback(); raise Problem(400,'oauth_flow_invalid','OAuth flow is expired, cancelled, stale, or already used.')
   conn.execute("UPDATE oauth_flows SET status='exchanging' WHERE state_hash=?",(state_hash,)); conn.commit()
  cfg=self.oauth_config()
  try:
   _,token_response=self.transport.request('POST',OAUTH['token'],body={'grant_type':'authorization_code','client_id':cfg['client_id'],'redirect_uri':flow['redirect_uri'] or cfg['redirect_uri'] or self.pick_redirect(),'code':code,'code_verifier':flow['verifier']},body_kind='form',envelope=False)
   access=token_response.get('access_token')
   if not isinstance(access,str) or not access:raise Problem(502,'provider_malformed','Cloudflare returned a malformed token response.')
   email=''
   try:
    _,identity=self.transport.request('GET',OAUTH['userinfo'],{'Authorization':'Bearer '+access},envelope=False,require_result=False)
    email=str((identity or {}).get('email') or '')[:80] if isinstance(identity,dict) else ''
   except Problem:pass  # identity is optional; Cloudflare clients may not be granted openid, and access is proven by the account check below
   accounts,inventory=self._verify_accounts(access); expires=token_response.get('expires_in',3600)
   label=flow['name'] or email or (accounts[0]['name'][:80] if accounts else '') or 'Cloudflare'
   if not isinstance(expires,int) or not 60<=expires<=31536000:expires=3600
   secret={'access_token':access,'expires_at':stamp+expires}
   if isinstance(token_response.get('refresh_token'),str) and token_response['refresh_token']:secret['refresh_token']=token_response['refresh_token']
   connection_id=secrets.token_hex(12); self.secrets.put(connection_id,secret)
   try:
    self._oauth_finalize_ready()
    with db() as conn:
     conn.execute('BEGIN IMMEDIATE'); current=conn.execute('SELECT status,session_hash,session_generation,global_generation,expires FROM oauth_flows WHERE state_hash=?',(state_hash,)).fetchone(); current_session=conn.execute('SELECT generation,expires FROM sessions WHERE cookie_hash=?',(session_hash,)).fetchone()
     valid=current and current['status']=='exchanging' and current['expires']>now() and current['session_hash']==session_hash and current_session and current_session['expires']>now() and current['session_generation']==current_session['generation'] and current['global_generation']==self._global_generation(conn)
     if not valid:raise Problem(400,'oauth_flow_invalid','OAuth flow was cancelled or became stale during exchange.')
     conn.execute("INSERT INTO connections(id,name,kind,status,revision,created,updated,account_inventory) VALUES(?,?,?,'connected',1,?,?,?)",(connection_id,label,'oauth',stamp,stamp,canon(inventory))); conn.executemany('INSERT INTO connection_accounts VALUES(?,?,?)',[(connection_id,a['id'],a['name']) for a in accounts]); changed=conn.execute("UPDATE oauth_flows SET status='completed',connection_id=? WHERE state_hash=? AND status='exchanging'",(connection_id,state_hash)).rowcount
     if changed!=1:raise Problem(400,'oauth_flow_invalid','OAuth flow was cancelled or became stale during exchange.')
     conn.commit()
    connected={'id':connection_id,'name':label,'kind':'oauth','status':'connected','revision':1,'accounts':accounts,'account_inventory':inventory}
   except Exception:
    self.secrets.delete(connection_id); raise
  except Exception:
   with db() as conn:conn.execute("UPDATE oauth_flows SET status='failed' WHERE state_hash=? AND status='exchanging'",(state_hash,))
   raise
  return connected
 def _linked(self,connection_id,account):
  connection=self.connection(connection_id); account=account_id(account)
  with db() as conn:linked=conn.execute('SELECT 1 FROM connection_accounts WHERE connection_id=? AND account_id=?',(connection_id,account)).fetchone()
  if not linked:raise Problem(403,'account_not_linked','Account is not linked to this connection.')
  return connection
 def _access_locked(self,connection):
  secret=self.secrets.get(connection['id'])
  if not secret or not isinstance(secret.get('access_token'),str):raise Problem(409,'credential_missing','Credential is unavailable.')
  if connection['kind']!='oauth' or secret.get('expires_at',now()+60)>now()+30:return secret['access_token']
  if secret.get('refresh_attempt')=='in_flight':raise Problem(409,'reauthorization_required','A prior refresh may have consumed the credential; Cloudflare sign-in must be renewed.')
  refresh=secret.get('refresh_token')
  if not isinstance(refresh,str) or not refresh:raise Problem(409,'reauthorization_required','Cloudflare sign-in must be renewed.')
  barrier=dict(secret); barrier['refresh_attempt']='in_flight'; self.secrets.put(connection['id'],barrier)
  try:_,response=self.transport.request('POST',OAUTH['token'],body={'grant_type':'refresh_token','refresh_token':refresh,'client_id':self.oauth_config()['client_id']},body_kind='form',envelope=False)
  except Exception:raise Problem(409,'reauthorization_required','Refresh outcome is uncertain; Cloudflare sign-in must be renewed.') from None
  access=response.get('access_token')
  rotated=response.get('refresh_token')
  if not isinstance(access,str) or not access or not isinstance(rotated,str) or not rotated:raise Problem(409,'reauthorization_required','Cloudflare did not return a complete rotated credential; sign-in must be renewed.')
  expires=response.get('expires_in',3600)
  if not isinstance(expires,int) or not 60<=expires<=31536000:expires=3600
  self.secrets.put(connection['id'],{'access_token':access,'refresh_token':rotated,'expires_at':now()+expires}); return access
 @contextmanager
 def authorized(self,connection_id,account):
  lock=keyed_lock(CONNECTION_LOCKS,safe_id(connection_id,'connection id'))
  with lock:
   connection=self._linked(connection_id,account); headers={'Authorization':'Bearer '+self._access_locked(connection)}
   yield connection,headers
 def disconnect(self,connection_id):
  safe_id(connection_id,'connection id')
  with keyed_lock(CONNECTION_LOCKS,connection_id):
   connection=self.connection(connection_id,allow_disconnected=True); secret=self.secrets.get(connection_id)
   if connection['status']=='disconnected' and not secret:return {'id':connection_id,'status':'disconnected','revision':connection['revision']}
   stamp=now()
   with db() as conn:
    conn.execute('BEGIN IMMEDIATE')
    if connection['status']=='connected':conn.execute("UPDATE connections SET status='disconnecting',revision=revision+1,updated=? WHERE id=?",(stamp,connection_id))
    conn.execute("UPDATE approvals SET status='disconnected',updated=? WHERE connection_id=? AND status IN ('pending','pending_review')",(stamp,connection_id)); conn.execute('UPDATE grants SET revoked=1,updated=? WHERE connection_id=?',(stamp,connection_id)); conn.execute("UPDATE oauth_flows SET status='cancelled' WHERE status IN ('pending','exchanging')"); conn.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='oauth_generation'"); conn.commit()
   revoke_pending=False
   if secret and connection['kind']=='oauth':
    try:self.transport.request('POST',OAUTH['revoke'],body={'token':secret.get('refresh_token') or secret.get('access_token'),'client_id':self.oauth_config()['client_id']},body_kind='form',envelope=False,require_result=False)
    except Problem:revoke_pending=True
   if not revoke_pending:self.secrets.delete(connection_id)
   status='disconnected_revoke_pending' if revoke_pending else 'disconnected'
   with db() as conn:
    conn.execute('UPDATE connections SET status=?,updated=? WHERE id=?',(status,now(),connection_id)); revision=conn.execute('SELECT revision FROM connections WHERE id=?',(connection_id,)).fetchone()['revision']
   return {'id':connection_id,'status':status,'revision':revision}
 @staticmethod
 def _page(params,maximum=100,mode='cursor'):
  try:per_page=int(params.get('per_page',50))
  except (TypeError,ValueError):raise Problem(400,'invalid_parameter','Invalid per_page.') from None
  if not 1<=per_page<=maximum:raise Problem(400,'invalid_parameter',f'per_page must be 1..{maximum}.')
  cursor=params.get('cursor') or ''
  if not isinstance(cursor,str) or len(cursor)>1024:raise Problem(400,'invalid_parameter','Invalid cursor.')
  raw_page=params.get('page',1)
  try:page=int(raw_page)
  except (TypeError,ValueError):raise Problem(400,'invalid_parameter','Invalid page.') from None
  if not 1<=page<=10000:raise Problem(400,'invalid_parameter','Invalid page.')
  if mode=='page' and cursor:raise Problem(400,'invalid_parameter','This resource uses page pagination.')
  if mode=='cursor' and 'page' in params and str(raw_page)!='1':raise Problem(400,'invalid_parameter','This resource uses cursor pagination.')
  return per_page,cursor,page
 @staticmethod
 def _page_info(response,requested,count,page=None,result_info=None):
  info=result_info if isinstance(result_info,dict) else response.get('result_info'); info=info if isinstance(info,dict) else {}
  cursor=info.get('cursor') if isinstance(info.get('cursor'),str) and info.get('cursor') else None
  output={'per_page':requested,'returned':count}
  if page is not None:
   total_pages=info.get('total_pages'); has_total=type(total_pages) is int and total_pages>=1
   truncated=total_pages>page if has_total else (bool(info.get('is_truncated')) if 'is_truncated' in info else None)
   if truncated:output['next_page']=page+1
   output.update({'page':page,'is_truncated':truncated,'complete':(not truncated) if truncated is not None else count<requested})
  else:
   explicit='cursor' in info or 'is_truncated' in info
   truncated=(bool(info.get('is_truncated')) or bool(cursor)) if explicit else None
   output.update({'cursor':cursor,'is_truncated':truncated,'complete':(not truncated) if truncated is not None else count<requested})
  if not info and count>=requested:output['complete']=False
  return output
 def _zone(self,headers,zone,account):
  zone=provider_id(zone,'zone id'); _,response=self.transport.request('GET',f'{API}/zones/{zone}',headers); result=response['result']
  if not isinstance(result,dict) or result.get('id')!=zone or not isinstance(result.get('account'),dict) or result['account'].get('id')!=account:raise Problem(403,'zone_account_mismatch','Zone does not belong to the linked account.')
  return result
 def read_resource(self,connection_id,account,section,params=None):
  params=params or {}; account=account_id(account)
  with self.authorized(connection_id,account) as (_,headers):
   if section=='account':
    _,response=self.transport.request('GET',f'{API}/accounts/{account}',headers); result=response['result']
    if not isinstance(result,dict) or result.get('id')!=account:raise Problem(502,'provider_account_mismatch','Cloudflare account verification did not match.')
    return {'section':section,'result':result,'links':{'dashboard':f'https://dash.cloudflare.com/{account}'},'complete':True}
   if section=='billing':return {'section':section,'result':{'available_via_api':False,'note':'Billing details are not assumed to have a universal account API.'},'links':{'billing_dashboard':f'https://dash.cloudflare.com/{account}/billing'},'complete':True}
   mode='page' if section in ('workers','zones','dns') else 'cursor'; maximum=50 if section=='registrations' else 100; per_page,cursor,page=self._page(params,maximum,mode); query={'per_page':per_page}
   if mode=='cursor' and cursor:query['cursor']=cursor
   page_number=None
   if section=='r2':url=f'{API}/accounts/{account}/r2/buckets?'+urllib.parse.urlencode(query)
   elif section in ('r2_objects','r2_metadata'):
    bucket=safe_id(params.get('bucket'),'bucket'); prefix=params.get('prefix','')
    if section=='r2_metadata':prefix=bounded_text(params.get('key'),'object key',1024); query['per_page']=min(per_page,100)
    if not isinstance(prefix,str) or len(prefix)>1024:raise Problem(400,'invalid_parameter','Invalid prefix.')
    query['prefix']=prefix; url=f"{API}/accounts/{account}/r2/buckets/{urllib.parse.quote(bucket,safe='')}/objects?"+urllib.parse.urlencode(query)
   elif section=='workers':
    page_number=page; url=f'{API}/accounts/{account}/workers/scripts?'+urllib.parse.urlencode({'page':page,'per_page':per_page})
   elif section=='worker':url=f"{API}/accounts/{account}/workers/scripts/{urllib.parse.quote(safe_id(params.get('script'),'script'),safe='')}/settings"
   elif section=='zones':
    page_number=page; url=f'{API}/zones?'+urllib.parse.urlencode({'account.id':account,'page':page,'per_page':per_page})
   elif section=='dns':
    zone=provider_id(params.get('zone'),'zone id'); self._zone(headers,zone,account); page_number=page; url=f'{API}/zones/{zone}/dns_records?'+urllib.parse.urlencode({'page':page,'per_page':per_page})
   elif section=='registrations':
    url=f'{API}/accounts/{account}/registrar/registrations?'+urllib.parse.urlencode(query)
   else:raise Problem(400,'invalid_section','Unknown resource section.')
   _,response=self.transport.request('GET',url,headers); result=response['result']
   if section=='worker':
    if not isinstance(result,dict):raise Problem(502,'provider_malformed','Cloudflare returned malformed Worker settings.')
    return {'section':section,'result':result,'complete':True}
   nested_info=None; provider_metadata=None
   if section=='r2':
    if not isinstance(result,dict) or not isinstance(result.get('buckets'),list):raise Problem(502,'provider_malformed','Cloudflare returned malformed R2 buckets.')
    nested_info=result.get('result_info'); provider_metadata={key:value for key,value in result.items() if key!='buckets'}; result=result['buckets']
   if not isinstance(result,list):raise Problem(502,'provider_malformed','Cloudflare returned a malformed resource list.')
   if section=='r2_metadata':
    matches=[item for item in result if isinstance(item,dict) and item.get('key')==params['key']]
    if len(matches)!=1:raise Problem(404,'object_metadata_not_found','Exact object metadata was not found in the bounded listing.')
    return {'section':section,'result':matches[0],'lookup':{'prefix':params['key'],'exact':True},'complete':True}
   output={'section':section,'result':result,'pagination':self._page_info(response,per_page,len(result),page_number,nested_info)}
   if provider_metadata:output['provider_metadata']=provider_metadata
   return output
 def registrar_search(self,connection_id,account,query):
  account=account_id(account)
  if not isinstance(query,str) or not DOMAIN.fullmatch(query):raise Problem(400,'invalid_domain','Invalid domain query.')
  with self.authorized(connection_id,account) as (_,headers):_,response=self.transport.request('GET',f'{API}/accounts/{account}/registrar/domain-search?'+urllib.parse.urlencode({'q':query}),headers)
  return {'result':response['result'],'read_only':True}
 def registrar_check(self,connection_id,account,domains):
  account=account_id(account)
  if not isinstance(domains,list) or not 1<=len(domains)<=20 or any(not isinstance(x,str) or not DOMAIN.fullmatch(x) for x in domains):raise Problem(400,'invalid_domains','Provide 1..20 valid domain names.')
  with self.authorized(connection_id,account) as (_,headers):_,response=self.transport.request('POST',f'{API}/accounts/{account}/registrar/domain-check',headers,{'domains':domains})
  return {'result':response['result'],'read_only':True}
 @staticmethod
 def _exact(payload,required,optional=()):
  if not isinstance(payload,dict) or set(payload)-set(required)-set(optional) or not set(required)<=set(payload):raise Problem(400,'invalid_payload','Payload fields do not match the action schema.')
 def validate_action(self,action,payload):
  if action in ('dns.create','dns.update'):
   required=['zone_id','type','name','content']+(['record_id'] if action=='dns.update' else []); self._exact(payload,required,['ttl','proxied']); provider_id(payload['zone_id'],'zone id')
   if action=='dns.update':provider_id(payload['record_id'],'record id')
   bounded_text(payload['type'],'record type',16); bounded_text(payload['name'],'record name',253); bounded_text(payload['content'],'record content',4096)
   if 'ttl' in payload and (type(payload['ttl']) is not int or not 1<=payload['ttl']<=2147483647):raise Problem(400,'invalid_payload','Invalid DNS ttl.')
   if 'proxied' in payload and type(payload['proxied']) is not bool:raise Problem(400,'invalid_payload','Invalid DNS proxied flag.')
  elif action=='r2.bucket.create':
   self._exact(payload,['name'],['location','storage_class']); safe_id(payload['name'],'bucket')
   for key in ('location','storage_class'):
    if key in payload:bounded_text(payload[key],key,64)
  elif action=='r2.object.put':
   self._exact(payload,['bucket','key','content_base64'],['content_type']); safe_id(payload['bucket'],'bucket'); bounded_text(payload['key'],'object key',1024)
   if 'content_type' in payload:bounded_text(payload['content_type'],'content type',200)
   try:content=base64.b64decode(payload['content_base64'],validate=True)
   except (ValueError,TypeError):raise Problem(400,'invalid_payload','Object content must be valid base64.') from None
   if len(content)>MAX_OBJECT:raise Problem(413,'object_too_large','R2 object exceeds 1 MiB.')
  elif action=='workers.deploy':
   self._exact(payload,['script','main_module','code']); safe_id(payload['script'],'script'); bounded_text(payload['main_module'],'main module',128); bounded_text(payload['code'],'Worker code',MAX_OBJECT)
   if payload['main_module'] not in ('worker.js','index.js','worker.mjs','index.mjs'):raise Problem(400,'invalid_payload','Main module filename is not allowed.')
  elif action=='registrar.register':
   self._exact(payload,['domain_name','years','privacy_mode','acknowledgements'])
   if not isinstance(payload['domain_name'],str) or not DOMAIN.fullmatch(payload['domain_name']) or type(payload['years']) is not int or not 1<=payload['years']<=10 or not isinstance(payload['privacy_mode'],str) or not 1<=len(payload['privacy_mode'])<=64 or not isinstance(payload['acknowledgements'],list) or not payload['acknowledgements'] or any(not isinstance(x,str) or not 1<=len(x)<=200 for x in payload['acknowledgements']):raise Problem(400,'invalid_payload','Invalid registration payload.')
  else:raise Problem(400,'invalid_action','Unsupported action.')
  raw=canon(payload)
  if len(raw.encode())>MAX_BODY:raise Problem(413,'payload_too_large','Payload is too large.')
  return raw
 def _verify_dns_binding(self,headers,account,action,payload):
  self._zone(headers,payload['zone_id'],account)
  if action=='dns.update':
   _,response=self.transport.request('GET',f"{API}/zones/{payload['zone_id']}/dns_records/{payload['record_id']}",headers); result=response['result']
   if not isinstance(result,dict) or result.get('id')!=payload['record_id'] or result.get('zone_id') not in (None,payload['zone_id']):raise Problem(403,'record_zone_mismatch','DNS record does not belong to the selected zone.')
 def prepare(self,connection_id,account,action,payload,session_hash=None,source='ui'):
  account=account_id(account); raw=self.validate_action(action,payload)
  with self.authorized(connection_id,account) as (connection,headers):
   if action.startswith('dns.'):self._verify_dns_binding(headers,account,action,payload)
   approval_id=secrets.token_hex(16); stamp=now(); status='pending' if source=='ui' and session_hash else 'pending_review'
   with db() as conn:conn.execute('INSERT INTO approvals(id,connection_id,account_id,action,payload,payload_digest,revision,status,source,session_hash,expires,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(approval_id,connection_id,account,action,raw,sha(raw),connection['revision'],status,source,session_hash if status=='pending' else None,stamp+APPROVAL_TTL,stamp,stamp))
  return self.approval(approval_id,True)
 @staticmethod
 def describe(action,payload):
  # Plain words for the owner's one-line approval card; exact payload stays behind Details.
  p=payload if isinstance(payload,dict) else {}
  if action=='dns.create':return f"add a DNS record {p.get('type','')} {p.get('name','')} → {p.get('content','')}"
  if action=='dns.update':return f"change the DNS record {p.get('type','')} {p.get('name','')} → {p.get('content','')}"
  if action=='r2.bucket.create':return f"create the storage bucket {p.get('name','')}"
  if action=='r2.object.put':return f"save {p.get('key','')} to {p.get('bucket','')}"
  if action=='workers.deploy':return f"publish the Worker {p.get('script','')}"
  if action=='registrar.register':return f"register {p.get('domain_name','')}"
  return action
 def home(self,session_hash):
  # Everything the owner screen needs in one read: logins, accounts, the sign-in in progress, waiting approvals.
  listing=self.list_connections(); flows=self.oauth_status(session_hash)['flows']; flow=flows[0] if flows else None
  with db() as conn:
   self._expire_approvals(conn); rows=conn.execute("SELECT * FROM approvals WHERE status IN ('pending','pending_review') ORDER BY created DESC LIMIT 20").fetchall()
  waiting=[{'id':r['id'],'connection_id':r['connection_id'],'account_id':r['account_id'],'action':r['action'],'status':r['status'],'text':self.describe(r['action'],json.loads(r['payload'])),'payload':json.loads(r['payload']),'payload_digest':r['payload_digest'],'expires':r['expires']} for r in rows]
  return {'connections':[{'id':c['id'],'name':c['name'],'status':c['status'],'accounts':c['accounts']} for c in listing['connections'] if c['status']=='connected'],
          'signin':{'available':listing['oauth_configured'],'status':flow['status'] if flow else None,'expires':flow['expires'] if flow else None},
          'approvals':waiting,'writes_allowed':self.writes_allowed}
 def _expire_approvals(self,conn):conn.execute("UPDATE approvals SET status='expired',updated=? WHERE status IN ('pending','pending_review') AND expires<=?",(now(),now()))
 def approvals(self):
  with db() as conn:
   self._expire_approvals(conn); rows=conn.execute('SELECT id,connection_id,account_id,action,payload_digest,revision,status,source,expires,created,updated FROM approvals ORDER BY created DESC LIMIT 100').fetchall()
  return {'approvals':[dict(row) for row in rows],'truncated':len(rows)==100}
 def approval(self,approval_id,include_payload=False):
  safe_id(approval_id,'approval id')
  with db() as conn:self._expire_approvals(conn); row=conn.execute('SELECT * FROM approvals WHERE id=?',(approval_id,)).fetchone()
  if not row:raise Problem(404,'approval_not_found','Approval not found.')
  result={key:row[key] for key in ('id','connection_id','account_id','action','payload_digest','revision','status','source','expires','created','updated')}
  if include_payload:result['payload']=json.loads(row['payload'])
  return result
 def review(self,approval_id,session_hash):
  with db() as conn:
   conn.execute('BEGIN IMMEDIATE'); self._expire_approvals(conn); row=conn.execute('SELECT status FROM approvals WHERE id=?',(safe_id(approval_id,'approval id'),)).fetchone()
   if not row:raise Problem(404,'approval_not_found','Approval not found.')
   if row['status']!='pending_review':raise Problem(409,'approval_closed','Approval is not awaiting owner review.')
   conn.execute("UPDATE approvals SET status='pending',session_hash=?,updated=? WHERE id=?",(session_hash,now(),approval_id)); conn.commit()
  return self.approval(approval_id,True)
 def cancel(self,approval_id):
  with db() as conn:
   conn.execute('BEGIN IMMEDIATE'); self._expire_approvals(conn); row=conn.execute('SELECT status FROM approvals WHERE id=?',(safe_id(approval_id,'approval id'),)).fetchone()
   if not row:raise Problem(404,'approval_not_found','Approval not found.')
   if row['status'] not in ('pending','pending_review'):raise Problem(409,'approval_closed','Approval is closed.')
   conn.execute("UPDATE approvals SET status='cancelled',updated=? WHERE id=?",(now(),approval_id)); conn.commit()
  return self.approval(approval_id,True)
 def confirm(self,approval_id,session_hash,digest):
  if not self.writes_allowed:raise Problem(403,'writes_disabled','Provider writes are disabled by CF_ALLOW_WRITES=false.')
  safe_id(approval_id,'approval id')
  with db() as conn:initial=conn.execute('SELECT connection_id FROM approvals WHERE id=?',(approval_id,)).fetchone()
  if not initial:raise Problem(404,'approval_not_found','Approval not found.')
  with keyed_lock(CONNECTION_LOCKS,initial['connection_id']):
   with db() as conn:
    conn.execute('BEGIN IMMEDIATE'); self._expire_approvals(conn); approval=conn.execute('SELECT * FROM approvals WHERE id=?',(approval_id,)).fetchone()
    if approval['status']!='pending':raise Problem(409,'approval_closed','Approval is not pending.')
    if not approval['session_hash'] or not hmac.compare_digest(approval['session_hash'],session_hash) or not isinstance(digest,str) or not hmac.compare_digest(approval['payload_digest'],digest):raise Problem(403,'approval_mismatch','Approval owner or digest did not match.')
    connection=conn.execute('SELECT * FROM connections WHERE id=?',(approval['connection_id'],)).fetchone()
    if not connection or connection['status']!='connected' or connection['revision']!=approval['revision']:raise Problem(409,'stale_approval','Connection changed after preparation.')
    if approval['action']=='registrar.register':raise Problem(409,'registration_blocked','Registration is blocked because the API cannot enforce a maximum price with required billing, contact, agreement, and fresh quote state.')
    conn.execute("UPDATE approvals SET status='executing',updated=? WHERE id=?",(now(),approval_id)); conn.commit()
   payload=json.loads(approval['payload']); headers={'Authorization':'Bearer '+self._access_locked(dict(connection))}
   try:
    if approval['action'].startswith('dns.'):self._verify_dns_binding(headers,approval['account_id'],approval['action'],payload)
    method,url,body,body_kind,extra=self._write_request(approval,payload); headers.update(extra); _,response=self.transport.request(method,url,headers,body,body_kind=body_kind)
   except Exception:
    with db() as conn:conn.execute("UPDATE approvals SET status='manual_review',updated=? WHERE id=? AND status='executing'",(now(),approval_id))
    raise
   with db() as conn:conn.execute("UPDATE approvals SET status='succeeded',updated=? WHERE id=? AND status='executing'",(now(),approval_id))
   return {'id':approval_id,'status':'succeeded','result':response['result']}
 def _write_request(self,approval,payload):
  account=approval['account_id']; action=approval['action']
  if action=='dns.create':return 'POST',f"{API}/zones/{payload['zone_id']}/dns_records",{k:v for k,v in payload.items() if k!='zone_id'},'json',{}
  if action=='dns.update':return 'PUT',f"{API}/zones/{payload['zone_id']}/dns_records/{payload['record_id']}",{k:v for k,v in payload.items() if k not in ('zone_id','record_id')},'json',{}
  if action=='r2.bucket.create':return 'POST',f'{API}/accounts/{account}/r2/buckets',payload,'json',{}
  if action=='r2.object.put':
   url=f"{API}/accounts/{account}/r2/buckets/{urllib.parse.quote(payload['bucket'],safe='')}/objects/{urllib.parse.quote(payload['key'],safe='')}"; return 'PUT',url,base64.b64decode(payload['content_base64'],validate=True),'raw',{'Content-Type':payload.get('content_type','application/octet-stream')}
  metadata=canon({'main_module':payload['main_module']}); multipart={'fields':{'metadata':('application/json',metadata.encode())},'files':{payload['main_module']:(payload['main_module'],'application/javascript+module',payload['code'].encode())}}
  return 'PUT',f"{API}/accounts/{account}/workers/scripts/{urllib.parse.quote(payload['script'],safe='')}",multipart,'multipart',{}
 def create_grant(self,connection_id,account,bucket,capabilities,client_identifier,ttl):
  account=account_id(account); bucket=safe_id(bucket,'bucket'); client_identifier=bounded_text(client_identifier,'client identifier',120); allowed={'r2.objects.read','r2.object.metadata.read'}
  if not isinstance(capabilities,list) or not capabilities or any(not isinstance(x,str) for x in capabilities) or not set(capabilities)<=allowed:raise Problem(400,'invalid_capabilities','Capabilities must be a non-empty read-only whitelist.')
  if type(ttl) is not int or not 60<=ttl<=2592000:raise Problem(400,'invalid_ttl','Grant ttl must be 60..2592000 seconds.')
  grant_id,bearer,stamp=secrets.token_hex(12),secrets.token_urlsafe(32),now(); caps=sorted(set(capabilities))
  with keyed_lock(CONNECTION_LOCKS,safe_id(connection_id,'connection id')):
   self._linked(connection_id,account)
   with db() as conn:conn.execute('INSERT INTO grants(id,connection_id,account_id,bucket,capabilities,client_identifier,bearer_hash,expires,revoked,created,updated) VALUES(?,?,?,?,?,?,?,?,0,?,?)',(grant_id,connection_id,account,bucket,canon(caps),client_identifier,sha(bearer),stamp+ttl,stamp,stamp))
  return {'contract':'wizard.cloudflare-connection/1','id':grant_id,'bearer':bearer,'expires':stamp+ttl,'connection_id':connection_id,'account_id':account,'bucket':bucket,'client_identifier':client_identifier,'capabilities':caps}
 def list_grants(self):
  stamp=now()
  with db() as conn:rows=conn.execute('SELECT id,connection_id,account_id,bucket,capabilities,client_identifier,expires,revoked,created,updated FROM grants ORDER BY created DESC LIMIT 100').fetchall()
  values=[]
  for row in rows:
   item=dict(row); item['capabilities']=json.loads(item['capabilities']); item['status']='revoked' if item.pop('revoked') else ('expired' if item['expires']<=stamp else 'active'); values.append(item)
  return {'grants':values,'truncated':len(values)==100}
 def revoke_grant(self,grant_id):
  safe_id(grant_id,'grant id')
  with keyed_lock(GRANT_LOCKS,grant_id),db() as conn:
   if not conn.execute('SELECT 1 FROM grants WHERE id=?',(grant_id,)).fetchone():raise Problem(404,'grant_not_found','Grant not found.')
   conn.execute('UPDATE grants SET revoked=1,updated=? WHERE id=?',(now(),grant_id))
  return {'id':grant_id,'status':'revoked'}
 def _grant(self,bearer,capability):
  if not isinstance(bearer,str) or len(bearer)<32:raise Problem(401,'grant_required','A consumer grant is required.')
  with db() as conn:row=conn.execute('SELECT * FROM grants WHERE bearer_hash=?',(sha(bearer),)).fetchone()
  if not row or row['revoked'] or row['expires']<=now() or capability not in json.loads(row['capabilities']):raise Problem(403,'grant_unavailable','Grant is expired, revoked, or out of scope.')
  return dict(row)
 def consumer(self,bearer,capability,params):
  initial=self._grant(bearer,capability)
  with keyed_lock(GRANT_LOCKS,initial['id']),keyed_lock(CONNECTION_LOCKS,initial['connection_id']):
   grant=self._grant(bearer,capability); connection=self._linked(grant['connection_id'],grant['account_id']); headers={'Authorization':'Bearer '+self._access_locked(connection)}; per_page,cursor,_=self._page(params); query={'per_page':per_page}
   if cursor:query['cursor']=cursor
   if capability=='r2.objects.read':
    prefix=params.get('prefix','')
    if not isinstance(prefix,str) or len(prefix)>1024:raise Problem(400,'invalid_parameter','Invalid prefix.')
    query['prefix']=prefix; url=f"{API}/accounts/{grant['account_id']}/r2/buckets/{urllib.parse.quote(grant['bucket'],safe='')}/objects?"+urllib.parse.urlencode(query); _,response=self.transport.request('GET',url,headers); result=response['result']
    if not isinstance(result,list):raise Problem(502,'provider_malformed','Cloudflare returned a malformed object list.')
    return {'contract':'wizard.cloudflare-connection/1','bucket':grant['bucket'],'result':result,'pagination':self._page_info(response,per_page,len(result))}
   key=bounded_text(params.get('key'),'object key',1024); query.update({'prefix':key,'per_page':min(per_page,100)}); url=f"{API}/accounts/{grant['account_id']}/r2/buckets/{urllib.parse.quote(grant['bucket'],safe='')}/objects?"+urllib.parse.urlencode(query); _,response=self.transport.request('GET',url,headers); result=response['result']; matches=[x for x in result if isinstance(x,dict) and x.get('key')==key] if isinstance(result,list) else []
   if len(matches)!=1:raise Problem(404,'object_metadata_not_found','Exact object metadata was not found in the bounded listing.')
   return {'contract':'wizard.cloudflare-connection/1','bucket':grant['bucket'],'result':matches[0],'lookup':{'prefix':key,'exact':True}}

def wait_for_storage(timeout=90):
 # Fresh Runtipi bind directories may be made writable only after compose up.
 deadline=time.monotonic()+timeout
 while True:
  try:
   DATA.mkdir(parents=True,exist_ok=True,mode=0o700); _private(DATA,0o700); return
  except PermissionError:
   if time.monotonic()>=deadline:raise
   time.sleep(0.25)

if __name__=='__main__':wait_for_storage()
SERVICE=Service()
TOOLS=[
 {'name':'cloudflare_connection_status','description':'Connection metadata only; never credentials.','inputSchema':{'type':'object','properties':{}}},
 {'name':'cloudflare_resources_read','description':'Read a bounded exact-account section. R2 objects require bucket; metadata also key; Worker detail requires script; DNS requires zone. Use page for Workers/zones/DNS and cursor for R2/registrations. Billing returns a dashboard link, not an invented billing API.','annotations':{'readOnlyHint':True},'inputSchema':{'type':'object','required':['connection_id','account_id','section'],'properties':{'connection_id':{'type':'string'},'account_id':{'type':'string'},'section':{'type':'string','enum':['account','billing','r2','r2_objects','r2_metadata','workers','worker','zones','dns','registrations']},'bucket':{'type':'string'},'key':{'type':'string'},'script':{'type':'string'},'zone':{'type':'string'},'prefix':{'type':'string'},'cursor':{'type':'string'},'page':{'type':'integer','minimum':1},'per_page':{'type':'integer','minimum':1,'maximum':100}}}},
 {'name':'cloudflare_registrar_search','description':'Read-only Registrar beta suggestions. Search is advisory, not availability proof. Never reserves or buys a domain.','annotations':{'readOnlyHint':True},'inputSchema':{'type':'object','required':['connection_id','account_id','q'],'properties':{'connection_id':{'type':'string'},'account_id':{'type':'string'},'q':{'type':'string'}}}},
 {'name':'cloudflare_registrar_check','description':'Read-only real-time Registrar beta availability/pricing for 1..20 domains. POST only queries availability; it never registers, reserves, or charges. Registration is blocked in this candidate.','annotations':{'readOnlyHint':True},'inputSchema':{'type':'object','required':['connection_id','account_id','domains'],'properties':{'connection_id':{'type':'string'},'account_id':{'type':'string'},'domains':{'type':'array','minItems':1,'maxItems':20,'items':{'type':'string'}}}}},
 {'name':'cloudflare_action_prepare','description':'Prepare an exact action for later owner review; never confirms.','inputSchema':{'type':'object','required':['connection_id','account_id','action','payload'],'properties':{'connection_id':{'type':'string'},'account_id':{'type':'string'},'action':{'type':'string'},'payload':{'type':'object'}}}},
 {'name':'cloudflare_approval_status','description':'Read durable approval status and digest.','inputSchema':{'type':'object','required':['id'],'properties':{'id':{'type':'string'}}}},
 {'name':'cloudflare_approval_cancel','description':'Cancel a pending approval.','inputSchema':{'type':'object','required':['id'],'properties':{'id':{'type':'string'}}}},
]
def rpc(message,service=None):
 service=service or SERVICE
 if not isinstance(message,dict) or message.get('jsonrpc')!='2.0' or not isinstance(message.get('method'),str):return {'jsonrpc':'2.0','id':None,'error':{'code':-32600,'message':'Invalid Request'}}
 if 'id' not in message:return None
 request_id=message.get('id'); params=message.get('params',{})
 if not isinstance(params,dict):return {'jsonrpc':'2.0','id':request_id,'error':{'code':-32602,'message':'Invalid params'}}
 try:
  method=message['method']
  if method=='initialize':result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':APP_ID,'version':VERSION}}
  elif method=='tools/list':result={'tools':TOOLS}
  elif method=='ping':result={}
  elif method=='tools/call':
   name,args=params.get('name'),params.get('arguments',{})
   if not isinstance(args,dict):raise Problem(400,'invalid_params','Arguments must be an object.')
   if name=='cloudflare_connection_status':value=service.list_connections()
   elif name=='cloudflare_resources_read':value=service.read_resource(args.get('connection_id'),args.get('account_id'),args.get('section'),args)
   elif name=='cloudflare_registrar_search':value=service.registrar_search(args.get('connection_id'),args.get('account_id'),args.get('q'))
   elif name=='cloudflare_registrar_check':value=service.registrar_check(args.get('connection_id'),args.get('account_id'),args.get('domains'))
   elif name=='cloudflare_action_prepare':value=service.prepare(args.get('connection_id'),args.get('account_id'),args.get('action'),args.get('payload'),source='mcp')
   elif name=='cloudflare_approval_status':value=service.approval(args.get('id'))
   elif name=='cloudflare_approval_cancel':value=service.cancel(args.get('id'))
   else:return {'jsonrpc':'2.0','id':request_id,'error':{'code':-32602,'message':'Unknown tool'}}
   result={'content':[{'type':'text','text':canon(value)}],'structuredContent':value,'isError':False}
  else:return {'jsonrpc':'2.0','id':request_id,'error':{'code':-32601,'message':'Method not found'}}
  return {'jsonrpc':'2.0','id':request_id,'result':result}
 except Problem as error:return {'jsonrpc':'2.0','id':request_id,'result':{'content':[{'type':'text','text':error.code}],'structuredContent':{'error':{'code':error.code,'message':error.message}},'isError':True}}

def csv_env(name):return {x.strip().lower() for x in os.getenv(name,'').split(',') if x.strip()}
LOCAL_HOSTS={f'127.0.0.1:{PORT}',f'localhost:{PORT}',f'wizard-cloudflare:{PORT}'}; TRUSTED_HOSTS=LOCAL_HOSTS|csv_env('WIZARD_TRUSTED_HOSTS'); TRUSTED_ORIGINS={'http://'+x for x in LOCAL_HOSTS}|csv_env('WIZARD_TRUSTED_ORIGINS'); FRAME_ANCESTORS=os.getenv('WIZARD_FRAME_ANCESTORS',"'self'")
FORWARDING=('Forwarded','X-Forwarded-For','X-Forwarded-Host','X-Forwarded-Proto','X-Real-IP')
SHELL_PATH=os.getenv('WIZARD_SHELL_PATH','/wizard-cloudflare/')
def shell_owner(headers,host):
 # Wizard shell mode: the app is opened inside the owner's Wizard shell through Tailscale Serve, which sets
 # Tailscale-User-Login for the signed-in tailnet user. Only exact shell hosts (never loopback/in-network names)
 # and an explicitly configured owner login are accepted; forwarding headers are never trusted for anything.
 if os.getenv('WIZARD_SHELL_AUTH','')!='tailscale-serve' or host in LOCAL_HOSTS or host not in TRUSTED_HOSTS:return False
 owners=csv_env('WIZARD_OWNER_LOGINS'); login=(headers.get('Tailscale-User-Login') or '').strip().lower()
 return bool(owners and login and len(headers.get_all('Tailscale-User-Login') or [])==1 and login in owners)
def cookie_path(host):return SHELL_PATH if os.getenv('WIZARD_SHELL_AUTH','')=='tailscale-serve' and host not in LOCAL_HOSTS else '/'
def development_owner_bypass(host):
 if os.getenv('CF_DEVELOPMENT_MODE','')!='loopback-single-owner' or host not in LOCAL_HOSTS:return False
 try:name=urllib.parse.urlsplit('//'+host).hostname
 except ValueError:return False
 return name in ('127.0.0.1','localhost')
def new_session(headers=None):
 # Keep cookie identity/generation stable across reloads, including pending OAuth.
 previous=''
 if headers:
  jar=cookies.SimpleCookie(headers.get('Cookie')); item=jar.get('cf_session'); previous=item.value if item else ''
 cookie,csrf,stamp=previous or secrets.token_urlsafe(32),secrets.token_urlsafe(32),now()
 with db() as conn:
  conn.execute('BEGIN IMMEDIATE'); conn.execute('DELETE FROM sessions WHERE expires<=?',(stamp,))
  existing=conn.execute('SELECT 1 FROM sessions WHERE cookie_hash=?',(sha(cookie),)).fetchone() if previous else None
  if existing:conn.execute('UPDATE sessions SET csrf_hash=?,expires=? WHERE cookie_hash=?',(sha(csrf),stamp+SESSION_TTL,sha(cookie)))
  else:
   cookie=secrets.token_urlsafe(32); conn.execute('INSERT INTO sessions VALUES(?,?,?,0,?)',(sha(cookie),sha(csrf),stamp+SESSION_TTL,stamp))
  conn.commit()
 return cookie,csrf
def session_from_headers(headers,csrf=False):
 jar=cookies.SimpleCookie(headers.get('Cookie')); item=jar.get('cf_session'); cookie=item.value if item else ''
 if not cookie:raise Problem(401,'owner_session_required','Owner browser session required.')
 cookie_hash=sha(cookie)
 with db() as conn:row=conn.execute('SELECT * FROM sessions WHERE cookie_hash=?',(cookie_hash,)).fetchone()
 if not row or row['expires']<=now():raise Problem(401,'owner_session_required','Owner browser session required.')
 if csrf:
  supplied=headers.get('X-CSRF-Token','')
  if not supplied or not hmac.compare_digest(row['csrf_hash'],sha(supplied)):raise Problem(403,'csrf_failed','CSRF check failed.')
 return cookie_hash

class Handler(BaseHTTPRequestHandler):
 server_version='WizardCloudflare/1'
 def _security_headers(self,content_type='application/json'):
  self.send_header('Content-Type',content_type); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()'); self.send_header('Content-Security-Policy',f"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors {FRAME_ANCESTORS}")
 def send_json(self,status,value,extra=None):
  raw=canon(value).encode(); self.send_response(status); self._security_headers(); self.send_header('Content-Length',str(len(raw)))
  for key,value in (extra or {}).items():self.send_header(key,value)
  self.end_headers(); self.wfile.write(raw)
 def send_html(self,status,title,message):
  body=f'<!doctype html><html><head><meta charset=utf-8><meta name=referrer content=no-referrer><title>{title}</title></head><body><main><h1>{title}</h1><p>{message}</p></main></body></html>'.encode(); self.send_response(status); self._security_headers('text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def fail(self,error):self.send_json(error.status,{'error':{'code':error.code,'message':error.message}})
 def host_guard(self):
  host=(self.headers.get('Host') or '').lower()
  if host not in TRUSTED_HOSTS:raise Problem(403,'unknown_host','Unknown host.')
  return host
 def owner_guard(self):
  host=self.host_guard()
  if self.headers.get('Authorization'):raise Problem(403,'owner_bearer_refused','Bearer credentials cannot authorize owner endpoints.')
  if development_owner_bypass(host):return host
  if shell_owner(self.headers,host):return host
  expected=os.getenv('WIZARD_OWNER_TOKEN','').strip()
  if not expected and os.getenv('WIZARD_SHELL_AUTH','')=='tailscale-serve' and csv_env('WIZARD_OWNER_LOGINS'):raise Problem(401,'owner_login_required','Open this app from your Wizard.')
  if not expected:raise Problem(503,'owner_auth_unconfigured','Owner gateway authentication is not configured.')
  supplied=self.headers.get('X-Wizard-Owner-Token','')
  if not supplied or not hmac.compare_digest(supplied,expected):raise Problem(401,'owner_token_required','Trusted owner gateway token required.')
  return host
 def browser_read(self):
  self.owner_guard(); site=(self.headers.get('Sec-Fetch-Site') or '').lower()
  if site!='same-origin':raise Problem(403,'same_origin_required','Same-origin browser request required.')
  origin=(self.headers.get('Origin') or '').lower()
  if origin and origin not in TRUSTED_ORIGINS:raise Problem(403,'origin_rejected','Browser origin is not trusted.')
  return session_from_headers(self.headers)
 def browser_write(self):
  self.owner_guard(); origin=(self.headers.get('Origin') or '').lower()
  if origin not in TRUSTED_ORIGINS or (self.headers.get('Sec-Fetch-Site') or '').lower()!='same-origin':raise Problem(403,'origin_required','Trusted browser Origin is required.')
  return session_from_headers(self.headers,True)
 def bootstrap_guard(self):
  self.owner_guard(); origin=(self.headers.get('Origin') or '').lower()
  if origin not in TRUSTED_ORIGINS or (self.headers.get('Sec-Fetch-Site') or '').lower()!='same-origin':raise Problem(403,'origin_required','Trusted browser Origin is required.')
  if self.headers.get('X-Wizard-Request')!='bootstrap' or self.headers.get('Authorization'):raise Problem(403,'bootstrap_refused','Owner session bootstrap refused.')
  if not shell_owner(self.headers,(self.headers.get('Host') or '').lower()) and any(self.headers.get(x) for x in FORWARDING):raise Problem(403,'bootstrap_refused','Owner session bootstrap refused.')
 def mcp_guard(self):
  self.host_guard(); site=(self.headers.get('Sec-Fetch-Site') or '').lower()
  if self.headers.get('Origin') or self.headers.get('Cookie') or site in ('cross-site','same-origin','same-site'):raise Problem(403,'mcp_browser_refused','Browser requests cannot use MCP.')
  if any(self.headers.get(x) for x in FORWARDING) or any(k.lower().startswith(('tailscale-','cf-')) for k in self.headers):raise Problem(403,'mcp_forwarding_refused','Forwarded MCP requests are refused.')
  expected=os.getenv('WIZARD_ADMIN_TOKEN','').strip(); supplied=self.headers.get('Authorization','')
  # Box-only agent access (the Wizard agent bridge reaches apps.json MCP URLs without a bearer), the same trust
  # model as other Wizard apps' MCP: loopback/in-network host only, no browser, forwarding or tailnet headers.
  # MCP never connects, confirms or reveals credentials; writes still need owner approval in the app.
  if not supplied and os.getenv('WIZARD_MCP_BOX_ONLY','').lower()=='true' and (self.headers.get('Host') or '').lower() in LOCAL_HOSTS:return
  if not expected:raise Problem(503,'admin_auth_unconfigured','MCP admin authentication is not configured.')
  if not hmac.compare_digest(supplied,'Bearer '+expected):raise Problem(401,'admin_token_required','Explicit admin token required for MCP.')
 def consumer_guard(self):
  self.host_guard()
  if self.headers.get('Cookie') or self.headers.get('Origin') or self.headers.get('X-CSRF-Token'):raise Problem(403,'consumer_boundary','Consumer grants cannot use owner browser credentials.')
  authorization=self.headers.get('Authorization','')
  if not authorization.startswith('Bearer '):raise Problem(401,'grant_required','A consumer grant is required.')
  return authorization[7:]
 def body(self):
  if self.headers.get('Content-Type','').split(';',1)[0].lower()!='application/json':raise Problem(415,'content_type','Use application/json.')
  try:length=int(self.headers.get('Content-Length',''))
  except ValueError:raise Problem(400,'invalid_length','Invalid Content-Length.') from None
  if not 1<=length<=MAX_BODY:raise Problem(413,'request_too_large','Request body is empty or too large.')
  try:value=json.loads(self.rfile.read(length))
  except (json.JSONDecodeError,UnicodeDecodeError):raise Problem(400,'invalid_json','Invalid JSON.') from None
  if not isinstance(value,dict):raise Problem(400,'invalid_body','Expected a JSON object.')
  return value
 @staticmethod
 def query(url):return {key:values[-1] for key,values in urllib.parse.parse_qs(url.query,keep_blank_values=True).items()}
 def do_GET(self):
  try:
   url=urllib.parse.urlsplit(self.path); path=url.path
   if path=='/healthz':self.host_guard(); return self.send_json(200,{'ok':True,'app':APP_ID,'version':VERSION})
   if path=='/oauth/callback':
    self.owner_guard(); session=session_from_headers(self.headers); query=self.query(url)
    if query.get('error'):SERVICE.oauth_fail(session,query.get('state')); return self.send_html(400,'Not connected','You can close this tab.')
    try:SERVICE.oauth_callback(query.get('state'),query.get('code'),session)
    except Problem:return self.send_html(400,'Not connected','You can close this tab.')
    return self.send_html(200,'Connected','You can close this tab.')
   if path.startswith('/consumer/v1/'):
    bearer=self.consumer_guard(); query=self.query(url)
    if path=='/consumer/v1/r2/objects':output=SERVICE.consumer(bearer,'r2.objects.read',query)
    elif path=='/consumer/v1/r2/metadata':output=SERVICE.consumer(bearer,'r2.object.metadata.read',query)
    else:raise Problem(404,'not_found','Not found.')
    return self.send_json(200,output)
   if path.startswith('/api/'):
    session=self.browser_read(); query=self.query(url)
    if path=='/api/connections':output=SERVICE.list_connections()
    elif path=='/api/home':output=SERVICE.home(session)
    elif path=='/api/oauth/status':output=SERVICE.oauth_status(session)
    elif path=='/api/approvals':output=SERVICE.approvals()
    elif path.startswith('/api/approvals/'):output=SERVICE.approval(path.split('/')[3],True)
    elif path=='/api/grants':output=SERVICE.list_grants()
    elif path.startswith('/api/connections/') and path.endswith('/resources'):output=SERVICE.read_resource(path.split('/')[3],query.get('account_id'),query.get('section'),query)
    else:raise Problem(404,'not_found','Not found.')
    return self.send_json(200,output)
   self.host_guard(); asset='index.html' if path in ('','/') else path.lstrip('/')
   if asset=='openapi.json':source=ROOT/'openapi.json'
   elif asset in {'index.html','app.js','styles.css','boot.js','theme-client.js','wizard-ui.css'}:source=WEB/asset
   else:raise Problem(404,'not_found','Not found.')
   raw=source.read_bytes(); content_type=mimetypes.guess_type(asset)[0] or 'application/octet-stream'; self.send_response(200); self._security_headers(content_type+('; charset=utf-8' if content_type.startswith(('text/','application/javascript')) else '')); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
  except (KeyError,TypeError,ValueError):self.fail(Problem(400,'invalid_parameter','Invalid parameter.'))
  except Problem as error:self.fail(error)
  except OSError:self.fail(Problem(404,'not_found','Not found.'))
 def do_POST(self):
  try:
   path=urllib.parse.urlsplit(self.path).path
   if path=='/api/session':
    self.bootstrap_guard(); exact_body(self.body()); cookie,csrf=new_session(self.headers); origin=(self.headers.get('Origin') or '').lower(); secure='; Secure' if origin.startswith('https://') and origin in TRUSTED_ORIGINS else ''; return self.send_json(201,{'csrf':csrf,'writes_allowed':SERVICE.writes_allowed},{'Set-Cookie':f'cf_session={cookie}; Path={cookie_path((self.headers.get("Host") or "").lower())}; HttpOnly; SameSite=Lax{secure}'})
   if path=='/mcp':
    self.mcp_guard(); output=rpc(self.body()); return self.send_json(202 if output is None else 200,{} if output is None else output)
   session=self.browser_write(); body=self.body(); status=200
   if path=='/api/connections/token':exact_body(body,('name','token'),('account_id',)); output=SERVICE.connect_token(body.get('name'),body.get('token'),body.get('account_id')); status=201
   elif path=='/api/oauth/start':exact_body(body,(),('name',)); output=SERVICE.oauth_start(body.get('name'),session,(self.headers.get('Origin') or '').lower()); status=201
   elif path=='/api/oauth/cancel':exact_body(body); output=SERVICE.oauth_cancel(session)
   elif path.startswith('/api/connections/') and path.endswith('/disconnect'):exact_body(body); output=SERVICE.disconnect(path.split('/')[3])
   elif path=='/api/registrar/search':exact_body(body,('connection_id','account_id','q')); output=SERVICE.registrar_search(body.get('connection_id'),body.get('account_id'),body.get('q'))
   elif path=='/api/registrar/check':exact_body(body,('connection_id','account_id','domains')); output=SERVICE.registrar_check(body.get('connection_id'),body.get('account_id'),body.get('domains'))
   elif path=='/api/approvals':exact_body(body,('connection_id','account_id','action','payload')); output=SERVICE.prepare(body.get('connection_id'),body.get('account_id'),body.get('action'),body.get('payload'),session,'ui'); status=201
   elif path.startswith('/api/approvals/') and path.endswith('/review'):exact_body(body); output=SERVICE.review(path.split('/')[3],session)
   elif path.startswith('/api/approvals/') and path.endswith('/confirm'):exact_body(body,('payload_digest',)); output=SERVICE.confirm(path.split('/')[3],session,body.get('payload_digest'))
   elif path.startswith('/api/approvals/') and path.endswith('/cancel'):exact_body(body); output=SERVICE.cancel(path.split('/')[3])
   elif path=='/api/grants':exact_body(body,('connection_id','account_id','bucket','capabilities','client_identifier','ttl')); output=SERVICE.create_grant(body.get('connection_id'),body.get('account_id'),body.get('bucket'),body.get('capabilities'),body.get('client_identifier'),body.get('ttl')); status=201
   elif path.startswith('/api/grants/') and path.endswith('/revoke'):exact_body(body); output=SERVICE.revoke_grant(path.split('/')[3])
   else:raise Problem(404,'not_found','Not found.')
   self.send_json(status,output)
  except (KeyError,TypeError,ValueError):self.fail(Problem(400,'invalid_parameter','Invalid parameter.'))
  except Problem as error:self.fail(error)
 def log_message(self,*args):pass

if __name__=='__main__':db().close(); ThreadingHTTPServer((os.getenv('BIND','0.0.0.0'),PORT),Handler).serve_forever()
