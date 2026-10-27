"""Synthetic, no-network browser fixture. No production credentials or data."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import urllib.parse
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
STATE = tempfile.TemporaryDirectory(prefix='cf-browser-fixture-')
os.environ['DATA_DIR'] = STATE.name
os.environ['CF_DEVELOPMENT_MODE'] = 'loopback-single-owner'
os.environ['CF_ALLOW_WRITES'] = 'false'
for name in ('CF_OAUTH_CLIENT_ID', 'CF_OAUTH_SCOPE', 'CF_OAUTH_REDIRECT_URI'):
    os.environ.pop(name, None)
if os.environ.get('CF_FIXTURE_OAUTH') == '1':
    os.environ['CF_OAUTH_CLIENT_ID'] = 'synthetic-public-client'
    os.environ['CF_OAUTH_SCOPE'] = 'synthetic-scope'
    os.environ['CF_OAUTH_REDIRECT_URI'] = 'http://127.0.0.1/oauth/callback'
spec = importlib.util.spec_from_file_location('cloudflare_fixture_server', ROOT / 'app/server.py')
assert spec is not None and spec.loader is not None
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
A, B, Z = 'a' * 32, 'b' * 32, 'c' * 32

class SyntheticProvider:
    def request(self, method, url, headers=None, body=None, **kwargs):
        # Nothing in this fixture can fall through to an actual provider request.
        parsed = urllib.parse.urlsplit(url)
        assert parsed.netloc == 'api.cloudflare.com', 'Unexpected provider host'
        path = parsed.path.removeprefix('/client/v4')
        if method == 'GET' and path == '/accounts':
            result = [{'id': A, 'name': 'Synthetic account A'}, {'id': B, 'name': 'Synthetic account B'}]
        elif method == 'GET' and path in ('/accounts/' + A, '/accounts/' + B):
            result = {'id': path.rsplit('/', 1)[1], 'name': 'Synthetic account'}
        elif method == 'GET' and path.endswith('/r2/buckets'):
            result = {'buckets': [{'name': 'fixture-bucket', 'creation_date': '2026-01-01T00:00:00Z'}]}
        elif method == 'GET' and '/r2/buckets/fixture-bucket/objects' in path:
            result = [{'key': 'encrypted-snapshot.bin', 'size': 42, 'etag': 'synthetic-etag', 'last_modified': '2026-01-01T00:00:00Z'}]
        elif method == 'GET' and path.endswith('/r2/metrics'):
            result = {'standard': {'published': {'payloadSize': 123456789, 'metadataSize': 0, 'objects': 3}}}
        elif method == 'GET' and path.endswith('/workers/scripts'):
            result = [{'id': 'fixture-worker', 'modified_on': '2026-01-01T00:00:00Z'}]
        elif method == 'GET' and path.endswith('/workers/scripts/fixture-worker/settings'):
            result = {'bindings': [], 'compatibility_date': '2026-01-01'}
        elif method == 'GET' and path == '/zones':
            result = [{'id': Z, 'name': 'fixture.example', 'account': {'id': A}}]
        elif method == 'GET' and path == '/zones/' + Z:
            result = {'id': Z, 'name': 'fixture.example', 'account': {'id': A}}
        elif method == 'GET' and path == '/zones/' + Z + '/dns_records':
            result = [{'id': 'd' * 32, 'type': 'A', 'name': 'fixture.example', 'content': '192.0.2.1', 'ttl': 300}]
        elif method == 'GET' and path.endswith('/registrar/registrations'):
            result = [{'domain_name': 'fixture.example', 'status': 'active', 'auto_renew': False}]
        elif method == 'GET' and path.endswith('/registrar/domain-search'):
            result = {'domains': [{'name': 'fixture-domain.example', 'registrable': False, 'reason': 'extension_not_supported'}]}
        elif method == 'POST' and path.endswith('/registrar/domain-check'):
            result = {'domains': [{'name': x, 'registrable': False, 'reason': 'domain_unavailable'} for x in body['domains']]}
        else:
            raise AssertionError('Fixture rejected unexpected provider method/path')
        return 200, {'success': True, 'result': result, 'result_info': {'is_truncated': False, 'total_pages': 1}}

app.SERVICE = app.Service(transport=SyntheticProvider())
if os.environ.get('CF_FIXTURE_CONNECTED') == '1':
    app.SERVICE._persist_connection('Synthetic login', 'token', {'access_token': 'synthetic-only'}, [{'id': A, 'name': 'Synthetic account A'}, {'id': B, 'name': 'Synthetic account B'}])
    if os.environ.get('CF_FIXTURE_APPROVAL') == '1':
        connection = app.SERVICE.list_connections()['connections'][0]
        app.SERVICE.prepare(connection['id'], A, 'r2.bucket.create', {'name': 'fixture-created-never-submitted'}, source='mcp')
class FixtureHandler(app.Handler):
    def do_GET(self):
        if urllib.parse.urlsplit(self.path).path == '/qa-host.html':
            self.host_guard()
            raw = b'<!doctype html><html><head><title>Hosted connector QA</title></head><body style="margin:0"><iframe id="app" src="/" style="border:0;width:100vw;height:100vh"></iframe></body></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        super().do_GET()

server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
port = server.server_address[1]
if os.environ.get('CF_FIXTURE_OAUTH') == '1':
    os.environ['CF_OAUTH_REDIRECT_URI'] = f'http://127.0.0.1:{port}/oauth/callback'
app.TRUSTED_HOSTS.add(f'127.0.0.1:{port}')
app.TRUSTED_ORIGINS.add(f'http://127.0.0.1:{port}')
if hasattr(app, 'LOCAL_HOSTS'):
    app.LOCAL_HOSTS.add(f'127.0.0.1:{port}')
print(json.dumps({'url': f'http://127.0.0.1:{port}/'}), flush=True)
try:
    server.serve_forever()
finally:
    server.server_close()
    STATE.cleanup()
