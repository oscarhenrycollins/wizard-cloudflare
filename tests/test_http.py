import http.client, json, os, tempfile, threading, unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest import mock
from test_service import server, FakeTransport, A

class HttpTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.auth_env=mock.patch.dict(os.environ,{'WIZARD_OWNER_TOKEN':'owner-secret','WIZARD_ADMIN_TOKEN':'admin-secret'}); cls.auth_env.start()
  cls.temp=tempfile.TemporaryDirectory(); server.DATA=Path(cls.temp.name); cls.fake=FakeTransport(); cls.store=server.SecretStore(); cls.service=server.Service(cls.fake,cls.store); server.SERVICE=cls.service
  cls.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler); cls.port=cls.httpd.server_address[1]; cls.host=f'127.0.0.1:{cls.port}'; cls.origin=f'http://{cls.host}'; server.TRUSTED_HOSTS.add(cls.host); server.TRUSTED_ORIGINS.add(cls.origin); server.LOCAL_HOSTS.add(cls.host)
  cls.thread=threading.Thread(target=cls.httpd.serve_forever,daemon=True); cls.thread.start()
 @classmethod
 def tearDownClass(cls):cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(); cls.temp.cleanup(); cls.auth_env.stop()
 def request(self,method,path,body=None,headers=None):
  conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3); outgoing={'Host':self.host}; outgoing.update(headers or {})
  if body is not None:
   body=json.dumps(body) if not isinstance(body,(bytes,str)) else body; outgoing.setdefault('Content-Type','application/json')
  conn.request(method,path,body=body,headers=outgoing); response=conn.getresponse(); raw=response.read(); result=(response.status,dict(response.getheaders()),raw); conn.close(); return result
 def bootstrap(self):
  status,headers,raw=self.request('POST','/api/session',{}, {'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap','X-Wizard-Owner-Token':'owner-secret'}); self.assertEqual(status,201); value=json.loads(raw); cookie=headers['Set-Cookie'].split(';',1)[0]; return cookie,value['csrf']
 def owner_get(self,path,cookie,extra=None):
  headers={'Cookie':cookie,'Sec-Fetch-Site':'same-origin','X-Wizard-Owner-Token':'owner-secret'}; headers.update(extra or {}); return self.request('GET',path,headers=headers)
 def owner_post(self,path,cookie,csrf,body,extra=None):
  headers={'Cookie':cookie,'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-CSRF-Token':csrf,'X-Wizard-Owner-Token':'owner-secret'}; headers.update(extra or {}); return self.request('POST',path,body,headers)
 def test_health_and_static_have_csp_no_store(self):
  status,headers,_=self.request('GET','/healthz'); self.assertEqual(status,200); self.assertIn("frame-ancestors",headers['Content-Security-Policy']); self.assertEqual(headers['Cache-Control'],'no-store')
  status,headers,_=self.request('GET','/'); self.assertEqual(status,200); self.assertIn("script-src 'self'",headers['Content-Security-Policy'])
  status,headers,raw=self.request('GET','/openapi.json'); self.assertEqual(status,200); self.assertEqual(headers['Content-Type'],'application/json'); self.assertIn(b'"openapi"',raw)
 def test_bootstrap_requires_actual_origin(self):status,_,raw=self.request('POST','/api/session',{}, {'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap','X-Wizard-Owner-Token':'owner-secret'}); self.assertEqual(status,403); self.assertIn(b'origin_required',raw)
 def test_bootstrap_rejects_bearer_and_forwarding(self):
  base={'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap','X-Wizard-Owner-Token':'owner-secret'}
  self.assertEqual(self.request('POST','/api/session',{},base|{'Authorization':'Bearer caller'})[0],403); self.assertEqual(self.request('POST','/api/session',{},base|{'X-Forwarded-For':'127.0.0.1'})[0],403)
 def test_production_default_rejects_forged_loopback_browser_headers(self):
  forged={'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap','Cookie':'cf_session=forged'}
  with mock.patch.dict(os.environ,{'WIZARD_OWNER_TOKEN':'','CF_DEVELOPMENT_MODE':''}):status,_,raw=self.request('POST','/api/session',{},forged)
  self.assertEqual(status,503); self.assertIn(b'owner_auth_unconfigured',raw)
 def test_all_owner_entry_points_fail_closed_without_gateway_secret(self):
  cookie,_=self.bootstrap(); forged={'Cookie':cookie,'Sec-Fetch-Site':'same-origin','Origin':self.origin}
  with mock.patch.dict(os.environ,{'WIZARD_OWNER_TOKEN':'','CF_DEVELOPMENT_MODE':''}):
   self.assertEqual(self.request('GET','/api/connections',headers=forged)[0],503); self.assertEqual(self.request('GET','/oauth/callback?state=x&code=y',headers=forged)[0],503)
 def test_invalid_owner_token_rejected_and_valid_gateway_header_works(self):
  base={'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap'}; self.assertEqual(self.request('POST','/api/session',{},base|{'X-Wizard-Owner-Token':'wrong'})[0],401); self.assertEqual(self.request('POST','/api/session',{},base|{'X-Wizard-Owner-Token':'owner-secret'})[0],201)
 def test_development_bypass_is_explicit_and_loopback_only(self):
  base={'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap'}
  with mock.patch.dict(os.environ,{'WIZARD_OWNER_TOKEN':'','CF_DEVELOPMENT_MODE':'loopback-single-owner'}):
   self.assertEqual(self.request('POST','/api/session',{},base)[0],201); self.assertEqual(self.request('POST','/api/session',{},base|{'Host':f'wizard-cloudflare:{server.PORT}'})[0],503)
 def test_https_origin_sets_secure_cookie(self):
  secure_origin='https://'+self.host; server.TRUSTED_ORIGINS.add(secure_origin)
  try:status,headers,_=self.request('POST','/api/session',{}, {'Origin':secure_origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap','X-Wizard-Owner-Token':'owner-secret'}); self.assertEqual(status,201); self.assertIn('Secure',headers['Set-Cookie']); self.assertIn('HttpOnly',headers['Set-Cookie']); self.assertIn('SameSite=Lax',headers['Set-Cookie'])
  finally:server.TRUSTED_ORIGINS.discard(secure_origin)
 def test_session_is_durable_hashed_and_get_has_no_origin(self):
  cookie,_=self.bootstrap(); raw_cookie=cookie.split('=',1)[1]
  with server.db() as conn:row=conn.execute('SELECT cookie_hash FROM sessions WHERE cookie_hash=?',(server.sha(raw_cookie),)).fetchone()
  self.assertEqual(row['cookie_hash'],server.sha(raw_cookie)); self.assertNotEqual(row['cookie_hash'],raw_cookie); self.assertEqual(self.owner_get('/api/connections',cookie)[0],200)
 def test_sensitive_get_rejects_cross_site(self):cookie,_=self.bootstrap(); self.assertEqual(self.request('GET','/api/connections',headers={'Cookie':cookie,'Sec-Fetch-Site':'cross-site','X-Wizard-Owner-Token':'owner-secret'})[0],403)
 def test_sensitive_get_rejects_untrusted_origin_if_present(self):cookie,_=self.bootstrap(); self.assertEqual(self.owner_get('/api/connections',cookie,{'Origin':'https://evil.example'})[0],403)
 def test_write_requires_origin_and_csrf(self):
  cookie,csrf=self.bootstrap(); headers={'Cookie':cookie,'Sec-Fetch-Site':'same-origin','X-CSRF-Token':csrf,'X-Wizard-Owner-Token':'owner-secret'}; self.assertEqual(self.request('POST','/api/oauth/cancel',{},headers)[0],403); self.assertEqual(self.owner_post('/api/oauth/cancel',cookie,'wrong',{})[0],403)
 def test_malformed_body_and_content_type(self):
  cookie,csrf=self.bootstrap(); headers={'Cookie':cookie,'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-CSRF-Token':csrf,'X-Wizard-Owner-Token':'owner-secret','Content-Type':'application/json'}; self.assertEqual(self.request('POST','/api/oauth/cancel',b'{',headers)[0],400); headers['Content-Type']='text/plain'; self.assertEqual(self.request('POST','/api/oauth/cancel','{}',headers)[0],415)
 def test_mcp_requires_admin_even_on_loopback_and_rejects_browser(self):
  message={'jsonrpc':'2.0','id':1,'method':'ping'}; self.assertEqual(self.request('POST','/mcp',message)[0],401); self.assertEqual(self.request('POST','/mcp',message,{'Authorization':'Bearer wrong'})[0],401); self.assertEqual(self.request('POST','/mcp',message,{'Authorization':'Bearer admin-secret'})[0],200); self.assertEqual(self.request('POST','/mcp',message,{'Authorization':'Bearer admin-secret','Origin':self.origin})[0],403); self.assertEqual(self.request('POST','/mcp',message,{'Authorization':'Bearer admin-secret','X-Forwarded-For':'1.2.3.4'})[0],403)
  with mock.patch.dict(os.environ,{'WIZARD_ADMIN_TOKEN':''}):self.assertEqual(self.request('POST','/mcp',message)[0],503)
 def test_consumer_grant_cannot_authorize_mcp_or_owner(self):
  connection=self.service._persist_connection('Boundary','token',{'access_token':'provider'},[{'id':A,'name':'A'}]); grant=self.service.create_grant(connection['id'],A,'bucket',['r2.objects.read'],'client',60); bearer={'Authorization':'Bearer '+grant['bearer']}; message={'jsonrpc':'2.0','id':1,'method':'ping'}; self.assertEqual(self.request('POST','/mcp',message,bearer)[0],401); self.assertEqual(self.request('POST','/api/session',{},bearer|{'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap','X-Wizard-Owner-Token':'owner-secret'})[0],403); self.service.disconnect(connection['id'])
 def test_mcp_cannot_mint_owner_session(self):self.assertEqual(self.request('POST','/api/session',{}, {'Authorization':'Bearer admin','Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-Wizard-Request':'bootstrap'})[0],403)
 def test_connection_route_never_returns_secret(self):
  connection=self.service._persist_connection('HTTP','token',{'access_token':'http-secret'},[{'id':A,'name':'A'}]); cookie,_=self.bootstrap(); status,_,raw=self.owner_get('/api/connections',cookie); self.assertEqual(status,200); self.assertNotIn(b'http-secret',raw); self.service.disconnect(connection['id'])
 def test_consumer_boundary_rejects_cookie(self):self.assertEqual(self.request('GET','/consumer/v1/r2/objects',headers={'Authorization':'Bearer '+('x'*40),'Cookie':'cf_session=x'})[0],403)
 def test_consumer_route_uses_grant_only(self):
  connection=self.service._persist_connection('Consumer','token',{'access_token':'provider-token'},[{'id':A,'name':'A'}]); grant=self.service.create_grant(connection['id'],A,'bucket',['r2.objects.read'],'client',60); self.fake.queue({'success':True,'result':[],'result_info':{}}); status,_,raw=self.request('GET','/consumer/v1/r2/objects?prefix=a&per_page=5',headers={'Authorization':'Bearer '+grant['bearer']}); self.assertEqual(status,200); self.assertNotIn(b'provider-token',raw); self.service.disconnect(connection['id'])
 def test_approval_http_review_flow(self):
  self.service.writes_allowed=True; connection=self.service._persist_connection('Review','token',{'access_token':'t'},[{'id':A,'name':'A'}]); approval=self.service.prepare(connection['id'],A,'r2.bucket.create',{'name':'b'},source='mcp'); cookie,csrf=self.bootstrap(); status,_,raw=self.owner_get('/api/approvals/'+approval['id'],cookie); self.assertEqual(status,200); self.assertEqual(json.loads(raw)['status'],'pending_review'); status,_,raw=self.owner_post('/api/approvals/'+approval['id']+'/review',cookie,csrf,{}); self.assertEqual(status,200); self.assertEqual(json.loads(raw)['status'],'pending'); self.service.disconnect(connection['id'])
 def test_unknown_host_refused(self):self.assertEqual(self.request('GET','/healthz',headers={'Host':'evil.example'})[0],403)

if __name__=='__main__':unittest.main()
