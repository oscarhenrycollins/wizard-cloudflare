import base64, importlib.util, io, json, os, tempfile, threading, time, unittest, urllib.error, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

SPEC=importlib.util.spec_from_file_location('cloudflare_server',Path(__file__).parents[1]/'app/server.py')
server=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(server)
A='a'*32; B='b'*32; Z='c'*32; R='d'*32

class FakeTransport:
 def __init__(self):self.calls=[]; self.results=[]; self.lock=threading.Lock()
 def queue(self,*values):self.results.extend(values); return self
 def request(self,method,url,headers=None,body=None,**kwargs):
  with self.lock:
   self.calls.append((method,url,headers or {},body,kwargs)); value=self.results.pop(0) if self.results else {'success':True,'result':[]}
  if isinstance(value,Exception):raise value
  return 200,value

class ServiceCase(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); server.DATA=Path(self.temp.name); self.store=server.SecretStore(); self.fake=FakeTransport(); self.service=server.Service(self.fake,self.store)
 def tearDown(self):self.temp.cleanup()
 def problem(self,code,fn):
  with self.assertRaises(server.Problem) as caught:fn()
  self.assertEqual(caught.exception.code,code)
 def connect(self,kind='token'):
  if kind=='token':self.fake.queue({'success':True,'result':{'id':A,'name':'Primary'}}); return self.service.connect_token('Mine','token-value',A)
  return self.service._persist_connection('OAuth','oauth',{'access_token':'old','refresh_token':'refresh','expires_at':server.now()-1},[{'id':A,'name':'Primary'}])

class ConnectionTests(ServiceCase):
 def test_exact_account_must_match(self):self.fake.queue({'success':True,'result':{'id':B}}); self.problem('provider_account_mismatch',lambda:self.service.connect_token('x','token-value',A))
 def test_connect_exact_and_secret_not_metadata(self):
  value=self.connect(); self.assertEqual(value['accounts'][0]['id'],A); self.assertNotIn('token-value',json.dumps(self.service.list_connections()))
 def test_connect_listing_bounded(self):
  self.fake.queue({'success':True,'result':[{'id':A,'name':'P'}]}); value=self.service.connect_token('x','token-value'); self.assertEqual(value['accounts'][0]['id'],A); self.assertIn('per_page=50&page=1',self.fake.calls[0][1])
 def test_connect_listing_at_limit_never_claims_complete(self):
  accounts=[{'id':f'{i:032x}','name':str(i)} for i in range(1,51)]; self.fake.queue({'success':True,'result':accounts}); value=self.service.connect_token('x','token-value'); self.assertFalse(value['account_inventory']['complete']); self.assertIsNone(value['account_inventory']['is_truncated']); self.assertFalse(self.service.list_connections()['connections'][0]['account_inventory']['complete'])
 def test_connect_listing_uses_provider_total_pages(self):
  self.fake.queue({'success':True,'result':[{'id':A}],'result_info':{'page':1,'total_pages':2}}); value=self.service.connect_token('x','token-value'); self.assertTrue(value['account_inventory']['is_truncated']); self.assertEqual(value['account_inventory']['next_page'],2)
 def test_connect_listing_malformed(self):self.fake.queue({'success':True,'result':[{'name':'bad'}]}); self.problem('provider_malformed',lambda:self.service.connect_token('x','token-value'))
 def test_token_fallback_disabled_when_oauth_ready(self):
  with mock.patch.dict(os.environ,{'CF_OAUTH_CLIENT_ID':'id','CF_OAUTH_REDIRECT_URI':'http://localhost/oauth/callback','CF_OAUTH_SCOPE':'scope'}):self.problem('oauth_required',lambda:self.service.connect_token('x','token-value',A))
 def test_secret_permissions(self):self.connect(); self.assertEqual(os.stat(server.DATA/'credentials.json').st_mode&0o777,0o600); self.assertEqual(os.stat(server.DATA).st_mode&0o777,0o700)
 def test_atomic_store_preserves_original_on_replace_failure(self):
  self.store.put('one',{'access_token':'a'})
  with mock.patch.object(server.os,'replace',side_effect=OSError('fail')):
   with self.assertRaises(OSError):self.store.put('two',{'access_token':'b'})
  self.assertEqual(self.store.get('one')['access_token'],'a'); self.assertIsNone(self.store.get('two'))
 def test_reconcile_marks_missing_secret(self):
  value=self.connect(); self.store.delete(value['id']); server.Service(self.fake,self.store); self.assertEqual(self.service.list_connections()['connections'][0]['status'],'credential_missing')
 def test_reconcile_removes_orphan_secret(self):self.store.put('orphan',{'access_token':'x'}); server.Service(self.fake,self.store); self.assertIsNone(self.store.get('orphan'))
 def test_disconnect_idempotent(self):
  value=self.connect(); first=self.service.disconnect(value['id']); second=self.service.disconnect(value['id']); self.assertEqual(first['status'],'disconnected'); self.assertEqual(second['revision'],first['revision'])
 def test_oauth_revoke_failure_is_durable_and_retryable(self):
  value=self.connect('oauth'); self.fake.queue(server.Problem(502,'provider_unavailable','x')); out=self.service.disconnect(value['id']); self.assertEqual(out['status'],'disconnected_revoke_pending'); self.assertIsNotNone(self.store.get(value['id']))
  self.fake.queue({}); out=self.service.disconnect(value['id']); self.assertEqual(out['status'],'disconnected'); self.assertIsNone(self.store.get(value['id']))
 def test_account_isolation(self):value=self.connect(); self.problem('account_not_linked',lambda:self.service.read_resource(value['id'],B,'r2'))

class ResourceTests(ServiceCase):
 def setUp(self):super().setUp(); self.connection=self.connect(); self.fake.calls.clear()
 def test_account_exact_result(self):self.fake.queue({'success':True,'result':{'id':B}}); self.problem('provider_account_mismatch',lambda:self.service.read_resource(self.connection['id'],A,'account'))
 def test_billing_is_local_link_no_provider_call(self):
  out=self.service.read_resource(self.connection['id'],A,'billing'); self.assertFalse(out['result']['available_via_api']); self.assertEqual(self.fake.calls,[])
 def test_r2_pagination_truthful(self):
  self.fake.queue({'success':True,'result':{'buckets':[{'name':'one'}],'result_info':{'cursor':'next','is_truncated':True},'jurisdiction':'default'}}); out=self.service.read_resource(self.connection['id'],A,'r2',{'per_page':10}); self.assertFalse(out['pagination']['complete']); self.assertEqual(out['pagination']['cursor'],'next'); self.assertEqual(out['provider_metadata']['jurisdiction'],'default')
 def test_r2_requires_provider_object_shape(self):self.fake.queue({'success':True,'result':[]}); self.problem('provider_malformed',lambda:self.service.read_resource(self.connection['id'],A,'r2'))
 def test_page_pagination_reports_next_page(self):
  self.fake.queue({'success':True,'result':[{'id':'worker'}],'result_info':{'page':1,'total_pages':3}}); out=self.service.read_resource(self.connection['id'],A,'workers',{'page':1,'per_page':1}); self.assertFalse(out['pagination']['complete']); self.assertEqual(out['pagination']['next_page'],2); self.assertNotIn('cursor',out['pagination']); self.assertIn('page=1',self.fake.calls[-1][1])
 def test_page_two_complete_from_total_pages(self):
  self.fake.queue({'success':True,'result':[{'id':'worker'}],'result_info':{'page':2,'total_pages':2}}); out=self.service.read_resource(self.connection['id'],A,'workers',{'page':2,'per_page':1}); self.assertTrue(out['pagination']['complete']); self.assertNotIn('next_page',out['pagination'])
 def test_full_page_without_provider_evidence_is_not_complete(self):
  self.fake.queue({'success':True,'result':[{'id':'worker'}]}); out=self.service.read_resource(self.connection['id'],A,'workers',{'page':1,'per_page':1}); self.assertFalse(out['pagination']['complete']); self.assertIsNone(out['pagination']['is_truncated'])
 def test_r2_object_list_has_prefix_cursor(self):
  self.fake.queue({'success':True,'result':[],'result_info':{}}); self.service.read_resource(self.connection['id'],A,'r2_objects',{'bucket':'backups','prefix':'daily/','cursor':'c','per_page':7}); url=self.fake.calls[-1][1]; self.assertIn('prefix=daily%2F',url); self.assertIn('cursor=c',url)
 def test_metadata_uses_list_not_binary_get(self):
  self.fake.queue({'success':True,'result':[{'key':'private/a','size':2}]}); out=self.service.read_resource(self.connection['id'],A,'r2_metadata',{'bucket':'b','key':'private/a'}); self.assertEqual(out['result']['size'],2); self.assertIn('/objects?',self.fake.calls[-1][1])
 def test_metadata_requires_exact_single_match(self):self.fake.queue({'success':True,'result':[{'key':'ab'}]}); self.problem('object_metadata_not_found',lambda:self.service.read_resource(self.connection['id'],A,'r2_metadata',{'bucket':'b','key':'a'}))
 def test_worker_detail_uses_settings(self):self.fake.queue({'success':True,'result':{'compatibility_date':'2026-01-01'}}); self.service.read_resource(self.connection['id'],A,'worker',{'script':'worker'}); self.assertTrue(self.fake.calls[-1][1].endswith('/settings'))
 def test_dns_reads_verify_zone_account_first(self):
  self.fake.queue({'success':True,'result':{'id':Z,'account':{'id':A}}},{'success':True,'result':[]}); self.service.read_resource(self.connection['id'],A,'dns',{'zone':Z}); self.assertEqual(len(self.fake.calls),2)
 def test_dns_cross_account_rejected_before_records(self):self.fake.queue({'success':True,'result':{'id':Z,'account':{'id':B}}}); self.problem('zone_account_mismatch',lambda:self.service.read_resource(self.connection['id'],A,'dns',{'zone':Z})); self.assertEqual(len(self.fake.calls),1)
 def test_registrar_search_is_documented_get(self):self.fake.queue({'success':True,'result':{}}); self.service.registrar_search(self.connection['id'],A,'example.com'); method,url,*_=self.fake.calls[-1]; self.assertEqual(method,'GET'); self.assertIn('/registrar/domain-search?q=example.com',url)
 def test_registrar_check_exact_body(self):self.fake.queue({'success':True,'result':{'domains':[]}}); self.service.registrar_check(self.connection['id'],A,['example.com']); self.assertEqual(self.fake.calls[-1][3],{'domains':['example.com']}); self.assertIn('/registrar/domain-check',self.fake.calls[-1][1])
 def test_registrations_list_uses_cursor_and_max_50(self):
  self.fake.queue({'success':True,'result':[]}); self.service.read_resource(self.connection['id'],A,'registrations',{'cursor':'next','per_page':50}); url=self.fake.calls[-1][1]; query=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query); self.assertIn('/registrar/registrations?',url); self.assertEqual(query['cursor'],['next']); self.assertNotIn('page',query); self.problem('invalid_parameter',lambda:self.service.read_resource(self.connection['id'],A,'registrations',{'per_page':51}))
 def test_page_resource_rejects_cursor(self):self.problem('invalid_parameter',lambda:self.service.read_resource(self.connection['id'],A,'workers',{'cursor':'2'}))
 def test_per_page_bounded(self):self.problem('invalid_parameter',lambda:self.service.read_resource(self.connection['id'],A,'r2',{'per_page':101}))

class ApprovalTests(ServiceCase):
 def setUp(self):super().setUp(); self.connection=self.connect(); self.fake.calls.clear(); self.service.writes_allowed=True
 def prepare_bucket(self,source='ui',session='owner'):return self.service.prepare(self.connection['id'],A,'r2.bucket.create',{'name':'bucket'},session if source=='ui' else None,source)
 def test_unknown_fields_rejected(self):self.problem('invalid_payload',lambda:self.service.prepare(self.connection['id'],A,'r2.bucket.create',{'name':'b','extra':1},'s'))
 def test_dns_prepare_verifies_zone_and_record(self):
  self.fake.queue({'success':True,'result':{'id':Z,'account':{'id':A}}},{'success':True,'result':{'id':R,'zone_id':Z}}); out=self.service.prepare(self.connection['id'],A,'dns.update',{'zone_id':Z,'record_id':R,'type':'A','name':'a.example','content':'192.0.2.1'},'s'); self.assertEqual(out['status'],'pending'); self.assertEqual(len(self.fake.calls),2)
 def test_dns_record_mismatch_rejected(self):
  self.fake.queue({'success':True,'result':{'id':Z,'account':{'id':A}}},{'success':True,'result':{'id':B}}); self.problem('record_zone_mismatch',lambda:self.service.prepare(self.connection['id'],A,'dns.update',{'zone_id':Z,'record_id':R,'type':'A','name':'a','content':'x'},'s'))
 def test_mcp_prepare_requires_owner_review(self):out=self.prepare_bucket('mcp',None); self.assertEqual(out['status'],'pending_review'); self.assertIsNone(self._row(out['id'])['session_hash'])
 def _row(self,pid):
  with server.db() as conn:return conn.execute('SELECT * FROM approvals WHERE id=?',(pid,)).fetchone()
 def test_owner_review_binds_session(self):out=self.prepare_bucket('mcp',None); reviewed=self.service.review(out['id'],'owner'); self.assertEqual(reviewed['status'],'pending'); self.assertEqual(self._row(out['id'])['session_hash'],'owner')
 def test_digest_and_payload_returned_for_review(self):out=self.prepare_bucket(); self.assertEqual(out['payload'],{'name':'bucket'}); self.assertEqual(out['payload_digest'],server.sha(server.canon(out['payload'])))
 def test_expiry_persisted(self):
  out=self.prepare_bucket()
  with server.db() as conn:conn.execute('UPDATE approvals SET expires=? WHERE id=?',(server.now()-1,out['id']))
  self.assertEqual(self.service.approval(out['id'])['status'],'expired'); self.assertEqual(self._row(out['id'])['status'],'expired')
 def test_disabled_write_has_zero_calls(self):out=self.prepare_bucket(); self.service.writes_allowed=False; count=len(self.fake.calls); self.problem('writes_disabled',lambda:self.service.confirm(out['id'],'owner',out['payload_digest'])); self.assertEqual(len(self.fake.calls),count)
 def test_digest_mismatch(self):self.service.writes_allowed=True; out=self.prepare_bucket(); self.problem('approval_mismatch',lambda:self.service.confirm(out['id'],'owner','0'*64))
 def test_cancel_and_replay(self):out=self.prepare_bucket(); self.assertEqual(self.service.cancel(out['id'])['status'],'cancelled'); self.problem('approval_closed',lambda:self.service.cancel(out['id']))
 def test_disconnect_closes_approval_and_grants(self):
  out=self.prepare_bucket(); grant=self.service.create_grant(self.connection['id'],A,'bucket',['r2.objects.read'],'backup',60); self.service.disconnect(self.connection['id']); self.assertEqual(self.service.approval(out['id'])['status'],'disconnected'); self.problem('grant_unavailable',lambda:self.service.consumer(grant['bearer'],'r2.objects.read',{}))
 def test_ambiguous_execution_becomes_manual_review(self):
  self.service.writes_allowed=True; out=self.prepare_bucket(); self.fake.queue(server.Problem(502,'provider_unavailable','x')); self.problem('provider_unavailable',lambda:self.service.confirm(out['id'],'owner',out['payload_digest'])); self.assertEqual(self.service.approval(out['id'])['status'],'manual_review'); self.problem('approval_closed',lambda:self.service.confirm(out['id'],'owner',out['payload_digest']))
 def test_r2_put_sends_decoded_raw_bytes(self):
  self.service.writes_allowed=True; payload={'bucket':'b','key':'folder/a','content_base64':base64.b64encode(b'hello').decode(),'content_type':'text/plain'}; out=self.service.prepare(self.connection['id'],A,'r2.object.put',payload,'owner'); self.fake.queue({'success':True,'result':{}}); self.service.confirm(out['id'],'owner',out['payload_digest']); call=self.fake.calls[-1]; self.assertEqual(call[3],b'hello'); self.assertEqual(call[4]['body_kind'],'raw')
 def test_worker_put_is_multipart_metadata_and_module(self):
  self.service.writes_allowed=True; payload={'script':'demo','main_module':'worker.js','code':'export default {}'}; out=self.service.prepare(self.connection['id'],A,'workers.deploy',payload,'owner'); self.fake.queue({'success':True,'result':{}}); self.service.confirm(out['id'],'owner',out['payload_digest']); call=self.fake.calls[-1]; self.assertEqual(call[4]['body_kind'],'multipart'); self.assertIn('metadata',call[3]['fields']); self.assertIn('worker.js',call[3]['files'])
 def test_registration_always_blocked(self):
  self.problem('registration_blocked',lambda:self.service.prepare(self.connection['id'],A,'registrar.register',{'domain_name':'example.com','years':1,'privacy_mode':'redacted_contact_data','acknowledgements':['x']},'owner'))
  with server.db() as conn:conn.execute("INSERT INTO approvals(id,connection_id,account_id,action,payload,payload_digest,revision,status,source,session_hash,expires,created,updated) VALUES('legacy',?,?,'registrar.register','{}',?,1,'pending','ui','owner',?,0,0)",(self.connection['id'],A,server.sha('{}'),server.now()+60))
  self.problem('registration_blocked',lambda:self.service.confirm('legacy','owner',server.sha('{}')))
 def test_disconnect_waits_for_inflight_write(self):
  self.service.writes_allowed=True; out=self.prepare_bucket(); entered=threading.Event(); release=threading.Event(); original=self.fake.request
  def blocking(method,url,headers=None,body=None,**kwargs):
   if method=='POST' and url.endswith('/r2/buckets'):entered.set(); release.wait(2); return 200,{'success':True,'result':{}}
   return original(method,url,headers,body,**kwargs)
  self.fake.request=blocking; done=[]; writer=threading.Thread(target=lambda:done.append(self.service.confirm(out['id'],'owner',out['payload_digest']))); writer.start(); self.assertTrue(entered.wait(1)); disconnect=threading.Thread(target=lambda:done.append(self.service.disconnect(self.connection['id']))); disconnect.start(); time.sleep(.05); self.assertTrue(disconnect.is_alive()); release.set(); writer.join(); disconnect.join(); self.assertEqual(done[-1]['status'],'disconnected')

class OAuthTests(ServiceCase):
 def setUp(self):
  self.env=mock.patch.dict(os.environ,{'CF_OAUTH_CLIENT_ID':'public','CF_OAUTH_REDIRECT_URI':'http://localhost:18799/oauth/callback','CF_OAUTH_SCOPE':'account:read'}); self.env.start(); super().setUp(); cookie,csrf=server.new_session(); self.session=server.sha(cookie)
 def tearDown(self):super().tearDown(); self.env.stop()
 def start(self):
  out=self.service.oauth_start('OAuth',self.session); query=urllib.parse.parse_qs(urllib.parse.urlsplit(out['authorization_url']).query); return out,query
 def test_pkce_consent_url(self):
  _,query=self.start(); self.assertEqual(query['code_challenge_method'],['S256']); self.assertEqual(query['client_id'],['public']); self.assertNotIn('code_verifier',query)
 def test_new_start_cancels_only_same_session_old_flow(self):
  self.start(); self.start(); statuses=self.service.oauth_status(self.session)['flows']; self.assertEqual([x['status'] for x in statuses],['pending','cancelled'])
 def test_multiple_browser_sessions_keep_independent_flows(self):
  self.start(); other=server.sha(server.new_session()[0]); self.service.oauth_start('Other',other); self.assertEqual(self.service.oauth_status(self.session)['flows'][0]['status'],'pending'); self.assertEqual(self.service.oauth_status(other)['flows'][0]['status'],'pending')
 def test_cancel_blocks_callback(self):
  _,query=self.start(); self.service.oauth_cancel(self.session); self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(query['state'][0],'code',self.session))
 def test_cancel_without_pending_flow_does_not_claim_cancelled(self):self.assertEqual(self.service.oauth_cancel(self.session)['status'],'not_pending')
 def test_callback_session_bound(self):
  _,query=self.start(); other=server.sha(server.new_session()[0]); self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(query['state'][0],'code',other))
 def test_callback_exchange_is_form_and_one_use(self):
  _,query=self.start(); self.fake.queue({'access_token':'access','refresh_token':'refresh','expires_in':3600},{'sub':'user'},{'success':True,'result':[{'id':A,'name':'P'}]}); result=self.service.oauth_callback(query['state'][0],'code',self.session); self.assertEqual(result['kind'],'oauth'); self.assertEqual(self.fake.calls[0][4]['body_kind'],'form'); self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(query['state'][0],'code',self.session))
 def test_callback_connects_when_userinfo_is_not_granted(self):
  _,query=self.start(); self.fake.queue({'access_token':'access','expires_in':3600},server.Problem(502,'provider_unauthorized','x'),{'success':True,'result':[{'id':A,'name':'P'}]}); result=self.service.oauth_callback(query['state'][0],'code',self.session); self.assertEqual(result['status'],'connected')
 def test_callback_still_fails_when_accounts_unreachable(self):
  _,query=self.start(); self.fake.queue({'access_token':'access','expires_in':3600},{'sub':'u'},server.Problem(502,'provider_unauthorized','x')); self.problem('provider_unauthorized',lambda:self.service.oauth_callback(query['state'][0],'code',self.session)); self.assertEqual(self.service.list_connections()['connections'],[]); self.assertEqual(self.store.read(),{})
 def test_pending_flow_survives_service_restart(self):
  _,query=self.start(); restarted=server.Service(self.fake,self.store); self.fake.queue({'access_token':'access','expires_in':3600},{'sub':'u'},{'success':True,'result':[{'id':A}]}); self.assertEqual(restarted.oauth_callback(query['state'][0],'code',self.session)['status'],'connected')
 def test_disconnect_global_generation_stales_other_flow(self):
  connected=self.service._persist_connection('t','token',{'access_token':'t'},[{'id':A,'name':'A'}]); _,query=self.start(); self.service.disconnect(connected['id']); self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(query['state'][0],'code',self.session))
 def test_refresh_is_serial_single_request(self):
  connection=self.connect('oauth'); self.fake.queue({'access_token':'new','refresh_token':'new-refresh','expires_in':3600}); errors=[]
  def work():
   try:self.service.read_resource(connection['id'],A,'billing')
   except Exception as error:errors.append(error)
  threads=[threading.Thread(target=work) for _ in range(4)]; [t.start() for t in threads]; [t.join() for t in threads]
  self.assertFalse(errors); self.assertEqual(len([c for c in self.fake.calls if c[1]==server.OAUTH['token']]),1)
 def test_cancel_during_exchange_prevents_persistence(self):
  _,query=self.start(); entered=threading.Event(); release=threading.Event(); original=self.fake.request
  def blocking(method,url,headers=None,body=None,**kwargs):
   if url==server.OAUTH['token']:entered.set(); release.wait(2); return 200,{'access_token':'access','expires_in':3600}
   if url==server.OAUTH['userinfo']:return 200,{'sub':'user'}
   if '/accounts?' in url:return 200,{'success':True,'result':[{'id':A}]}
   return original(method,url,headers,body,**kwargs)
  self.fake.request=blocking; errors=[]; thread=threading.Thread(target=lambda:self._capture(errors,lambda:self.service.oauth_callback(query['state'][0],'code',self.session))); thread.start(); self.assertTrue(entered.wait(1)); self.service.oauth_cancel(self.session); release.set(); thread.join(); self.assertEqual(errors[0].code,'oauth_flow_invalid'); self.assertEqual(self.service.list_connections()['connections'],[])
 def test_cancel_at_finalize_cas_deletes_orphan_secret(self):
  _,query=self.start(); self.fake.queue({'access_token':'access','refresh_token':'refresh','expires_in':3600},{'sub':'user'},{'success':True,'result':[{'id':A}]}); self.service._oauth_finalize_ready=lambda:self.service.oauth_cancel(self.session); self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(query['state'][0],'code',self.session)); self.assertEqual(self.service.list_connections()['connections'],[]); self.assertEqual(self.store.read(),{})
 def test_concurrent_cancel_wins_before_finalize_commit(self):
  _,query=self.start(); self.fake.queue({'access_token':'access','refresh_token':'refresh','expires_in':3600},{'sub':'user'},{'success':True,'result':[{'id':A}]}); entered=threading.Event(); release=threading.Event(); self.service._oauth_finalize_ready=lambda:(entered.set(),release.wait(2)); errors=[]; thread=threading.Thread(target=lambda:self._capture(errors,lambda:self.service.oauth_callback(query['state'][0],'code',self.session))); thread.start(); self.assertTrue(entered.wait(1)); self.service.oauth_cancel(self.session); release.set(); thread.join(); self.assertEqual([e.code for e in errors],['oauth_flow_invalid']); self.assertEqual(self.service.list_connections()['connections'],[])
 def test_disconnect_generation_wins_before_finalize_commit(self):
  existing=self.service._persist_connection('old','token',{'access_token':'token'},[{'id':A,'name':'A'}]); _,query=self.start(); self.fake.queue({'access_token':'access','refresh_token':'refresh','expires_in':3600},{'sub':'user'},{'success':True,'result':[{'id':A}]}); entered=threading.Event(); release=threading.Event(); self.service._oauth_finalize_ready=lambda:(entered.set(),release.wait(2)); errors=[]; thread=threading.Thread(target=lambda:self._capture(errors,lambda:self.service.oauth_callback(query['state'][0],'code',self.session))); thread.start(); self.assertTrue(entered.wait(1)); self.service.disconnect(existing['id']); release.set(); thread.join(); self.assertEqual([e.code for e in errors],['oauth_flow_invalid']); self.assertEqual(self.store.read(),{})
 def test_ambiguous_refresh_is_never_retried_after_restart(self):
  connection=self.connect('oauth'); self.fake.queue(server.Problem(502,'provider_unavailable','x')); self.problem('reauthorization_required',lambda:self.service.read_resource(connection['id'],A,'billing')); restarted=server.Service(self.fake,self.store); self.problem('reauthorization_required',lambda:restarted.read_resource(connection['id'],A,'billing')); self.assertEqual(len([c for c in self.fake.calls if c[1]==server.OAUTH['token']]),1)
 def test_refresh_401_leaves_durable_barrier(self):
  connection=self.connect('oauth'); self.fake.queue(server.Problem(502,'provider_unauthorized','x')); self.problem('reauthorization_required',lambda:self.service.read_resource(connection['id'],A,'billing')); self.assertEqual(self.store.get(connection['id'])['refresh_attempt'],'in_flight'); restarted=server.Service(self.fake,self.store); self.problem('reauthorization_required',lambda:restarted.read_resource(connection['id'],A,'billing')); self.assertEqual(len([c for c in self.fake.calls if c[1]==server.OAUTH['token']]),1)
 def test_restart_with_preexisting_refresh_barrier_never_posts(self):
  connection=self.connect('oauth'); secret=self.store.get(connection['id']); secret['refresh_attempt']='in_flight'; self.store.put(connection['id'],secret); restarted=server.Service(self.fake,self.store); self.problem('reauthorization_required',lambda:restarted.read_resource(connection['id'],A,'billing')); self.assertEqual([c for c in self.fake.calls if c[1]==server.OAUTH['token']],[])
 @staticmethod
 def _capture(errors,fn):
  try:fn()
  except Exception as error:errors.append(error)

class GrantTests(ServiceCase):
 def setUp(self):super().setUp(); self.connection=self.connect(); self.fake.calls.clear()
 def grant(self,caps=None,ttl=60):return self.service.create_grant(self.connection['id'],A,'backups',caps or ['r2.objects.read'],'backup-client',ttl)
 def test_bucket_and_client_required(self):self.problem('invalid_parameter',lambda:self.service.create_grant(self.connection['id'],A,None,['r2.objects.read'],'client',60))
 def test_bearer_shown_once_not_listed(self):grant=self.grant(); self.assertNotIn(grant['bearer'],json.dumps(self.service.list_grants()))
 def test_consumer_exact_bucket_and_prefix(self):
  grant=self.grant(); self.fake.queue({'success':True,'result':[],'result_info':{}}); self.service.consumer(grant['bearer'],'r2.objects.read',{'prefix':'daily/'}); self.assertIn('/buckets/backups/objects?',self.fake.calls[-1][1]); self.assertIn('prefix=daily%2F',self.fake.calls[-1][1])
 def test_capability_cannot_escalate(self):grant=self.grant(); self.problem('grant_unavailable',lambda:self.service.consumer(grant['bearer'],'r2.object.metadata.read',{'key':'a'}))
 def test_metadata_never_gets_binary(self):
  grant=self.grant(['r2.object.metadata.read']); self.fake.queue({'success':True,'result':[{'key':'a','etag':'e'}]}); out=self.service.consumer(grant['bearer'],'r2.object.metadata.read',{'key':'a'}); self.assertEqual(out['result']['etag'],'e'); self.assertIn('/objects?',self.fake.calls[-1][1])
 def test_revoke_idempotent_boundary(self):grant=self.grant(); self.service.revoke_grant(grant['id']); self.service.revoke_grant(grant['id']); self.problem('grant_unavailable',lambda:self.service.consumer(grant['bearer'],'r2.objects.read',{}))
 def test_expired(self):
  grant=self.grant()
  with server.db() as conn:conn.execute('UPDATE grants SET expires=? WHERE id=?',(server.now()-1,grant['id']))
  self.problem('grant_unavailable',lambda:self.service.consumer(grant['bearer'],'r2.objects.read',{}))
 def test_revoke_waits_for_inflight_consumer(self):
  grant=self.grant(); entered=threading.Event(); release=threading.Event(); original=self.fake.request
  def blocking(method,url,headers=None,body=None,**kwargs):entered.set(); release.wait(2); return 200,{'success':True,'result':[],'result_info':{}}
  self.fake.request=blocking; outcomes=[]; reader=threading.Thread(target=lambda:outcomes.append(self.service.consumer(grant['bearer'],'r2.objects.read',{}))); reader.start(); self.assertTrue(entered.wait(1)); revoke=threading.Thread(target=lambda:outcomes.append(self.service.revoke_grant(grant['id']))); revoke.start(); time.sleep(.05); self.assertTrue(revoke.is_alive()); release.set(); reader.join(); revoke.join(); self.problem('grant_unavailable',lambda:self.service.consumer(grant['bearer'],'r2.objects.read',{}))

class RpcTests(ServiceCase):
 def test_malformed(self):self.assertEqual(server.rpc([],self.service)['error']['code'],-32600)
 def test_bad_params(self):self.assertEqual(server.rpc({'jsonrpc':'2.0','id':1,'method':'ping','params':[]},self.service)['error']['code'],-32602)
 def test_notification(self):self.assertIsNone(server.rpc({'jsonrpc':'2.0','method':'ping'},self.service))
 def test_unknown_method(self):self.assertEqual(server.rpc({'jsonrpc':'2.0','id':1,'method':'unknown'},self.service)['error']['code'],-32601)
 def test_no_connect_or_confirm_tools(self):names={x['name'] for x in server.TOOLS}; self.assertNotIn('cloudflare_connect',names); self.assertNotIn('cloudflare_approval_confirm',names)
 def test_mcp_prepare_is_reviewable(self):
  self.service.writes_allowed=True; self.fake.queue({'success':True,'result':{'id':A}}); connection=self.service.connect_token('x','token-value',A); message={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'cloudflare_action_prepare','arguments':{'connection_id':connection['id'],'account_id':A,'action':'r2.bucket.create','payload':{'name':'b'}}}}; result=server.rpc(message,self.service); self.assertEqual(result['result']['structuredContent']['status'],'pending_review')

class Response:
 def __init__(self,value,status=200):self.raw=value if isinstance(value,bytes) else json.dumps(value).encode(); self.status=status
 def read(self,size):return self.raw
 def __enter__(self):return self
 def __exit__(self,*args):pass
class Opener:
 def __init__(self,value):self.value=value; self.requests=[]
 def open(self,request,timeout):
  self.requests.append(request)
  if isinstance(self.value,Exception):raise self.value
  return Response(self.value)

class TransportTests(unittest.TestCase):
 def problem(self,code,fn):
  with self.assertRaises(server.Problem) as caught:fn()
  self.assertEqual(caught.exception.code,code)
 def test_requests_identify_the_app(self):
  # Cloudflare's OAuth token endpoint returns error 1010 for Python's default urllib User-Agent.
  opener=Opener({'access_token':'a'}); server.Transport(opener).request('POST',server.OAUTH['token'],body={'grant_type':'authorization_code'},body_kind='form',envelope=False)
  ua=opener.requests[0].get_header('User-agent'); self.assertTrue(ua.startswith('wizard-cloudflare/')); self.assertNotIn('Python-urllib',ua)
 def test_success_false_on_200_fails(self):self.problem('provider_rejected',lambda:server.Transport(Opener({'success':False,'result':[]})).request('GET',server.API+'/accounts'))
 def test_missing_result_fails(self):self.problem('provider_malformed',lambda:server.Transport(Opener({'success':True})).request('GET',server.API+'/accounts'))
 def test_redirect_refused_before_follow(self):self.problem('provider_redirect',lambda:server.Transport(Opener(server.RedirectRefused())).request('GET',server.API+'/accounts'))
 def test_no_redirect_handler_never_reaches_target(self):
  hits=[]
  class RedirectHandler(BaseHTTPRequestHandler):
   def do_GET(self):
    hits.append(self.path)
    if self.path=='/start':self.send_response(302); self.send_header('Location','/target'); self.end_headers()
    else:self.send_response(200); self.end_headers()
   def log_message(self,*args):pass
  httpd=ThreadingHTTPServer(('127.0.0.1',0),RedirectHandler); thread=threading.Thread(target=httpd.serve_forever,daemon=True); thread.start()
  try:
   with self.assertRaises(server.RedirectRefused):server.urllib.request.build_opener(server.NoRedirect()).open(f'http://127.0.0.1:{httpd.server_address[1]}/start')
   self.assertEqual(hits,['/start'])
  finally:httpd.shutdown(); httpd.server_close(); thread.join()
 def test_endpoint_policy(self):self.problem('transport_policy',lambda:server.Transport(Opener({})).request('GET','https://evil.example/'))
 def test_form_encoding(self):
  opener=Opener({'access_token':'x'}); server.Transport(opener).request('POST',server.OAUTH['token'],body={'grant_type':'authorization_code'},body_kind='form',envelope=False); request=opener.requests[0]; self.assertEqual(request.headers['Content-type'],'application/x-www-form-urlencoded'); self.assertEqual(request.data,b'grant_type=authorization_code')
 def test_empty_non_envelope_response_allowed_only_when_optional(self):
  self.assertEqual(server.Transport(Opener(b'')).request('POST',server.OAUTH['revoke'],envelope=False,require_result=False)[1],{}); self.problem('provider_malformed',lambda:server.Transport(Opener(b'')).request('POST',server.OAUTH['token'],envelope=False))
 def test_raw_encoding(self):
  opener=Opener({'success':True,'result':{}}); server.Transport(opener).request('PUT',server.API+'/x',body=b'raw',body_kind='raw'); self.assertEqual(opener.requests[0].data,b'raw')
 def test_multipart_encoding(self):
  opener=Opener({'success':True,'result':{}}); server.Transport(opener).request('PUT',server.API+'/x',body={'fields':{'metadata':'{}'},'files':{'worker.js':('worker.js','application/javascript',b'code')}},body_kind='multipart'); request=opener.requests[0]; self.assertTrue(request.headers['Content-type'].startswith('multipart/form-data; boundary=')); self.assertIn(b'name="metadata"',request.data); self.assertIn(b'filename="worker.js"',request.data)
 def test_http_error_is_sanitized(self):
  error=urllib.error.HTTPError(server.API+'/x',403,'secret body',{},io.BytesIO(b'sensitive')); self.problem('provider_unauthorized',lambda:server.Transport(Opener(error)).request('GET',server.API+'/x'))

if __name__=='__main__':unittest.main()
