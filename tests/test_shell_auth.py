"""Wizard shell trust model: Tailscale Serve names the tailnet user; exact host/origin, CSRF, no forwarding trust."""
import http.client, json, os, tempfile, threading, unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest import mock
from test_service import server, FakeTransport, A

SHELL = 'box.example.ts.net:8444'
ORIGIN = 'https://' + SHELL

class ShellAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = mock.patch.dict(os.environ, {'WIZARD_SHELL_AUTH': 'tailscale-serve', 'WIZARD_OWNER_LOGINS': 'owner@example.com', 'WIZARD_OWNER_TOKEN': '', 'WIZARD_ADMIN_TOKEN': '', 'WIZARD_MCP_BOX_ONLY': 'true', 'CF_DEVELOPMENT_MODE': '', 'CF_OAUTH_CLIENT_ID': 'public', 'CF_OAUTH_SCOPE': 'offline_access zone.read', 'CF_OAUTH_REDIRECT_URI': ORIGIN + '/wizard-cloudflare/oauth/callback', 'CF_OAUTH_REDIRECT_URIS': 'https://box.example.ts.net:8796/wizard-cloudflare/oauth/callback'})
        cls.env.start()
        cls.temp = tempfile.TemporaryDirectory(); server.DATA = Path(cls.temp.name); cls.fake = FakeTransport(); server.SERVICE = server.Service(cls.fake, server.SecretStore())
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler); cls.port = cls.httpd.server_address[1]; cls.local = f'127.0.0.1:{cls.port}'
        server.LOCAL_HOSTS.add(cls.local); server.TRUSTED_HOSTS.update({cls.local, SHELL, 'box.example.ts.net:8796'}); server.TRUSTED_ORIGINS.update({ORIGIN, 'https://box.example.ts.net:8796'})
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True); cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.thread.join(); cls.temp.cleanup(); cls.env.stop()
    def req(self, method, path, body=None, headers=None, host=SHELL):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3); h = {'Host': host}; h.update(headers or {})
        if body is not None: body = json.dumps(body); h.setdefault('Content-Type', 'application/json')
        c.request(method, path, body=body, headers=h); r = c.getresponse(); out = (r.status, dict(r.getheaders()), r.read()); c.close(); return out
    def boot(self, extra=None, host=SHELL, origin=ORIGIN):
        h = {'Origin': origin, 'Sec-Fetch-Site': 'same-origin', 'X-Wizard-Request': 'bootstrap', 'Tailscale-User-Login': 'owner@example.com'}; h.update(extra or {})
        return self.req('POST', '/api/session', {}, h, host)
    def test_owner_login_bootstraps_with_prefix_cookie(self):
        status, headers, raw = self.boot(); self.assertEqual(status, 201, raw)
        self.assertIn('Path=/wizard-cloudflare/', headers['Set-Cookie']); self.assertIn('Secure', headers['Set-Cookie']); self.assertIn('HttpOnly', headers['Set-Cookie'])
    def test_other_tailnet_user_refused(self):
        self.assertEqual(self.boot({'Tailscale-User-Login': 'guest@example.com'})[0], 401)
    def test_missing_identity_refused(self):
        h = {'Origin': ORIGIN, 'Sec-Fetch-Site': 'same-origin', 'X-Wizard-Request': 'bootstrap'}
        self.assertEqual(self.req('POST', '/api/session', {}, h)[0], 401)
    def test_identity_not_trusted_on_loopback_host(self):
        # A local process can forge the header but cannot be the shell host.
        self.assertIn(self.boot(host=self.local, origin='http://' + self.local)[0], (401, 503))
    def test_cross_origin_and_untrusted_host_refused(self):
        self.assertEqual(self.boot(origin='https://evil.example')[0], 403)
        self.assertEqual(self.boot(host='evil.example')[0], 403)
    def test_write_needs_csrf(self):
        status, headers, raw = self.boot(); cookie = headers['Set-Cookie'].split(';', 1)[0]; csrf = json.loads(raw)['csrf']
        base = {'Cookie': cookie, 'Origin': ORIGIN, 'Sec-Fetch-Site': 'same-origin', 'Tailscale-User-Login': 'owner@example.com'}
        self.assertEqual(self.req('POST', '/api/oauth/cancel', {}, base)[0], 403)
        self.assertEqual(self.req('POST', '/api/oauth/cancel', {}, base | {'X-CSRF-Token': csrf})[0], 200)
    def test_redirect_follows_shell_origin(self):
        for host in (SHELL, 'box.example.ts.net:8796'):
            origin = 'https://' + host; status, headers, raw = self.boot(host=host, origin=origin); cookie = headers['Set-Cookie'].split(';', 1)[0]; csrf = json.loads(raw)['csrf']
            status, _, raw = self.req('POST', '/api/oauth/start', {}, {'Cookie': cookie, 'Origin': origin, 'Sec-Fetch-Site': 'same-origin', 'X-CSRF-Token': csrf, 'Tailscale-User-Login': 'owner@example.com'}, host)
            self.assertEqual(status, 201, raw); url = json.loads(raw)['authorization_url']
            self.assertIn('redirect_uri=' + http.client.parse_headers if False else 'redirect_uri=https%3A%2F%2F' + host.replace(':', '%3A') + '%2Fwizard-cloudflare%2Foauth%2Fcallback', url)
            self.assertNotIn('openid', url)
    def test_home_lists_nothing_secret(self):
        status, headers, raw = self.boot(); cookie = headers['Set-Cookie'].split(';', 1)[0]
        status, _, raw = self.req('GET', '/api/home', headers={'Cookie': cookie, 'Sec-Fetch-Site': 'same-origin', 'Tailscale-User-Login': 'owner@example.com'})
        self.assertEqual(status, 200); home = json.loads(raw); self.assertEqual(home['connections'], []); self.assertTrue(home['signin']['available'])
    def test_mcp_box_only(self):
        msg = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}
        self.assertEqual(self.req('POST', '/mcp', msg, host=self.local)[0], 200)
        self.assertEqual(self.req('POST', '/mcp', msg, {'Tailscale-User-Login': 'owner@example.com'}, host=self.local)[0], 403)
        self.assertEqual(self.req('POST', '/mcp', msg, {'X-Forwarded-For': '1.2.3.4'}, host=self.local)[0], 403)
        self.assertEqual(self.req('POST', '/mcp', msg, host=SHELL)[0], 503)
        self.assertEqual(self.req('POST', '/mcp', msg, {'Origin': 'http://' + self.local}, host=self.local)[0], 403)

if __name__ == '__main__':
    unittest.main()
