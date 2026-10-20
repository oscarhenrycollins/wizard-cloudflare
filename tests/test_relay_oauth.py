import base64,json,os,urllib.parse
from unittest import mock
from test_service import ServiceCase,server,A

CALLBACK='https://www.aiwizards.com/wizard-cloudflare/auth/callback'
ORIGIN='https://owner.tailtest.ts.net:8444'
class RelayOAuthTests(ServiceCase):
 def setUp(self):
  super().setUp(); self.env=mock.patch.dict(os.environ,{'CF_OAUTH_CLIENT_ID':'public-client','CF_OAUTH_REDIRECT_URI':CALLBACK,'CF_OAUTH_REDIRECT_URIS':'','CF_OAUTH_SCOPE':'offline_access zone.read','CF_OAUTH_RELAY':'true'}); self.env.start(); self.addCleanup(self.env.stop)
  self.origins=mock.patch.object(server,'TRUSTED_ORIGINS',{ORIGIN}); self.origins.start(); self.addCleanup(self.origins.stop)
  cookie,_=server.new_session(); self.session=server.sha(cookie)
 def start(self):
  return urllib.parse.parse_qs(urllib.parse.urlsplit(self.service.oauth_start('',self.session,ORIGIN)['authorization_url']).query)
 def success(self):self.fake.queue({'access_token':'access','refresh_token':'refresh','expires_in':3600},{},{'success':True,'result':[{'id':A,'name':'Owner'}]})
 def test_relay_state_and_direct_exchange(self):
  q=self.start(); state=q['state'][0]; data=json.loads(base64.urlsafe_b64decode(state[5:]+'='*(-len(state[5:])%4))); self.assertEqual(data['r'],ORIGIN+'/wizard-cloudflare/oauth/callback'); self.assertEqual(q['redirect_uri'],[CALLBACK]); self.assertEqual(len(data['n']),43)
  self.success(); self.service.oauth_callback(state,'provider-code',self.session); call=self.fake.calls[0]; self.assertEqual(call[1],server.OAUTH['token']); self.assertEqual(call[3]['redirect_uri'],CALLBACK); self.assertNotIn(call[3]['code_verifier'],state); self.assertEqual(len(self.service.list_connections()['connections']),1)
  self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(state,'provider-code',self.session)); self.assertEqual(len(self.fake.calls),3)
 def test_tamper_and_other_browser_fail_before_network(self):
  state=self.start()['state'][0]; self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(state+'x','code',self.session)); cookie,_=server.new_session(); self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(state,'code',server.sha(cookie))); self.assertEqual(self.fake.calls,[])
 def test_untrusted_origin_and_non_tailnet_refused(self):
  self.problem('oauth_origin_unregistered',lambda:self.service.oauth_start('',self.session,'https://evil.example'))
  with mock.patch.object(server,'TRUSTED_ORIGINS',{'https://evil.example'}):self.problem('oauth_origin_unregistered',lambda:self.service.oauth_start('',self.session,'https://evil.example'))
 def test_cancel_and_expiry_fail_before_network(self):
  state=self.start()['state'][0]; self.service.oauth_cancel(self.session); self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(state,'code',self.session)); state=self.start()['state'][0]
  with server.db() as conn:conn.execute('UPDATE oauth_flows SET expires=0')
  self.problem('oauth_flow_invalid',lambda:self.service.oauth_callback(state,'code',self.session)); self.assertEqual(self.fake.calls,[])
 def test_error_state_cannot_cancel_another_flow(self):
  state=self.start()['state'][0]; self.assertEqual(self.service.oauth_fail(self.session,'wrong')['failed'],0); self.assertEqual(self.service.oauth_fail(self.session)['failed'],0); self.assertEqual(self.service.oauth_status(self.session)['flows'][0]['status'],'pending'); self.assertEqual(self.service.oauth_fail(self.session,state)['failed'],1)
 def test_interrupted_exchange_is_never_retried(self):
  state=self.start()['state'][0]; self.fake.queue(KeyboardInterrupt())
  # Fake transport returns BaseException values; inject at the actual request boundary.
  with mock.patch.object(self.fake,'request',side_effect=KeyboardInterrupt):
   with self.assertRaises(KeyboardInterrupt):self.service.oauth_callback(state,'code',self.session)
  restarted=server.Service(self.fake,self.store); self.problem('oauth_flow_invalid',lambda:restarted.oauth_callback(state,'code',self.session)); self.assertEqual(self.store.read(),{})
