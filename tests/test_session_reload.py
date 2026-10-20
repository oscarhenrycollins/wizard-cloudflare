import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from test_service import server, FakeTransport, A


class SessionReloadTests(unittest.TestCase):
    def setUp(self):
        self.previous_data = server.DATA
        self.temp = tempfile.TemporaryDirectory(prefix='cf-session-reload-')
        server.DATA = Path(self.temp.name)

    def tearDown(self):
        server.DATA = self.previous_data
        self.temp.cleanup()

    def test_reload_keeps_cookie_and_generation_but_rotates_csrf(self):
        cookie, csrf = server.new_session()
        with server.db() as conn:
            conn.execute('UPDATE sessions SET generation=7 WHERE cookie_hash=?', (server.sha(cookie),))
        cookie2, csrf2 = server.new_session({'Cookie': 'cf_session=' + cookie})
        self.assertEqual(cookie, cookie2)
        self.assertNotEqual(csrf, csrf2)
        with server.db() as conn:
            row = conn.execute('SELECT generation FROM sessions WHERE cookie_hash=?', (server.sha(cookie),)).fetchone()
        self.assertEqual(row['generation'], 7)
        self.assertEqual(server.session_from_headers({'Cookie': 'cf_session=' + cookie2, 'X-CSRF-Token': csrf2}, True), server.sha(cookie))
        with self.assertRaises(server.Problem):
            server.session_from_headers({'Cookie': 'cf_session=' + cookie, 'X-CSRF-Token': csrf}, True)

    def test_expired_cookie_is_not_adopted(self):
        cookie, _ = server.new_session()
        with server.db() as conn:
            conn.execute('UPDATE sessions SET expires=0 WHERE cookie_hash=?', (server.sha(cookie),))
        cookie2, _ = server.new_session({'Cookie': 'cf_session=' + cookie})
        self.assertNotEqual(cookie, cookie2)

    def test_runtime_waits_for_post_up_directory_permission(self):
        with patch.object(Path, 'mkdir', side_effect=[PermissionError(), None]), patch.object(server, '_private'), patch.object(server.time, 'sleep') as sleep:
            server.wait_for_storage(timeout=10)
            sleep.assert_called_once_with(0.25)

    def test_storage_wait_is_bounded(self):
        with patch.object(Path, 'mkdir', side_effect=PermissionError()), patch.object(server.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaises(PermissionError):
                server.wait_for_storage(timeout=1)

    def test_mcp_resource_schema_exposes_detail_targets(self):
        tool = next(x for x in server.TOOLS if x['name'] == 'cloudflare_resources_read')
        self.assertTrue({'key', 'script', 'zone', 'page', 'cursor'} <= set(tool['inputSchema']['properties']))

    def test_mcp_registrar_reads_share_provider_service(self):
        transport = FakeTransport()
        service = server.Service(transport, server.SecretStore())
        connection = service._persist_connection('Synthetic RPC', 'token', {'access_token': 'synthetic-only'}, [{'id': A, 'name': 'Synthetic'}])
        for name, extra, method in [('cloudflare_registrar_search', {'q': 'example.com'}, 'GET'), ('cloudflare_registrar_check', {'domains': ['example.com']}, 'POST')]:
            transport.queue({'success': True, 'result': {'domains': []}})
            value = server.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': {'connection_id': connection['id'], 'account_id': A, **extra}}}, service=service)
            self.assertFalse(value['result']['isError'])
            self.assertTrue(value['result']['structuredContent']['read_only'])
            self.assertEqual(transport.calls[-1][0], method)

    def test_oauth_callback_survives_owner_page_reload(self):
        transport = FakeTransport()
        service = server.Service(transport, server.SecretStore())
        config = {'CF_OAUTH_CLIENT_ID': 'synthetic-public-client', 'CF_OAUTH_SCOPE': 'synthetic-scope', 'CF_OAUTH_REDIRECT_URI': 'http://localhost/oauth/callback'}
        with patch.dict(server.os.environ, config):
            cookie, _ = server.new_session()
            flow = service.oauth_start('Reload fixture', server.sha(cookie))
            state = parse_qs(urlsplit(flow['authorization_url']).query)['state'][0]
            cookie2, _ = server.new_session({'Cookie': 'cf_session=' + cookie})
            transport.queue({'access_token': 'synthetic-access', 'expires_in': 3600})
            transport.queue({'sub': 'synthetic-user'})
            transport.queue({'success': True, 'result': [{'id': A, 'name': 'Synthetic account'}], 'result_info': {'total_pages': 1}})
            connected = service.oauth_callback(state, 'synthetic-code', server.sha(cookie2))
            self.assertEqual(connected['status'], 'connected')
            self.assertEqual(service.oauth_status(server.sha(cookie2))['flows'][0]['status'], 'completed')


if __name__ == '__main__':
    unittest.main()
