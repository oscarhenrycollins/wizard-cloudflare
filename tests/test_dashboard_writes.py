import base64, hashlib, json, os, tempfile, unittest
from pathlib import Path
from unittest import mock
from test_service import server, ServiceCase, FakeTransport, A, B, Z

ALL = ' '.join(['offline_access', 'zone.read'] + server.WRITE_SCOPES)


class RoutingTransport(FakeTransport):
    """Answers by URL so parallel metric reads get the right reply regardless of order."""
    def __init__(self, routes):
        super().__init__(); self.routes = routes

    def request(self, method, url, headers=None, body=None, **kwargs):
        with self.lock:
            self.calls.append((method, url, headers or {}, body, kwargs))
        for needle, value in self.routes:
            if needle in url and (not isinstance(value, tuple) or value[0] == method):
                value = value[1] if isinstance(value, tuple) else value
                if isinstance(value, Exception): raise value
                return 200, value
        return 200, {'success': True, 'result': []}


def metric_routes(account, workers=2, buckets=3, zones=4, stored=1500, fail=None):
    routes = [
        (f'/accounts/{account}/workers/scripts', {'success': True, 'result': [{'id': f'w{i}'} for i in range(workers)]}),
        (f'/accounts/{account}/r2/buckets', {'success': True, 'result': {'buckets': [{'name': 'b'}][:buckets]}, 'result_info': {'total_count': buckets}}),
        (f'/accounts/{account}/r2/metrics', {'success': True, 'result': {'standard': {'published': {'objects': 7, 'payloadSize': stored, 'metadataSize': 0}}, 'infrequentAccess': {'published': {'objects': 1, 'payloadSize': 500, 'metadataSize': 0}}}}),
        (f'account.id={account}', {'success': True, 'result': [{'id': Z}], 'result_info': {'total_count': zones}}),
    ]
    if fail:
        routes = [(n, server.Problem(502, 'provider_unauthorized', 'x') if fail in n else v) for n, v in routes]
    return routes


class MetricsTests(ServiceCase):
    def setUp(self):
        super().setUp(); server.METRICS.clear()
        self.fake = RoutingTransport(metric_routes(A) + metric_routes(B, 0, 0, 0, 0)); self.service.transport = self.fake
        self.conn = self.service._persist_connection('Mine', 'token', {'access_token': 't'}, [{'id': A, 'name': 'One'}, {'id': B, 'name': 'Two'}])

    def test_numbers_and_empty_account(self):
        out = {m['account_id']: m for m in self.service.metrics_all()['accounts']}
        self.assertEqual((out[A]['websites'], out[A]['buckets'], out[A]['domains']), (2, 3, 4))
        self.assertEqual(out[A]['storage'], {'bytes': 2000, 'objects': 8})
        self.assertEqual((out[B]['websites'], out[B]['buckets'], out[B]['domains']), (0, 0, 0))
        self.assertNotIn('unavailable', out[B])

    def test_partial_failure_keeps_other_numbers(self):
        self.fake.routes = metric_routes(A, fail='r2/metrics')
        out = self.service.metrics(self.conn['id'], A)
        self.assertIsNone(out['storage']); self.assertEqual(out['unavailable'], {'storage': 'provider_unauthorized'})
        self.assertEqual((out['websites'], out['buckets'], out['domains']), (2, 3, 4))

    def test_one_account_failing_does_not_break_others(self):
        with mock.patch.object(self.service, 'metrics', side_effect=lambda c, a, fresh=False: (_ for _ in ()).throw(server.Problem(409, 'reauthorization_required', 'x')) if a == B else {'account_id': a}):
            out = self.service.metrics_all()['accounts']
        self.assertEqual({m['account_id']: m.get('error') for m in out}, {A: None, B: 'reauthorization_required'})

    def test_cache_and_fresh(self):
        self.service.metrics(self.conn['id'], A); first = len(self.fake.calls)
        self.service.metrics(self.conn['id'], A); self.assertEqual(len(self.fake.calls), first)
        self.service.metrics(self.conn['id'], A, fresh=True); self.assertEqual(len(self.fake.calls), first * 2)

    def test_failures_cached_briefly(self):
        self.fake.routes = metric_routes(A, fail='workers/scripts'); self.service.metrics(self.conn['id'], A)
        expiry = server.METRICS[(self.conn['id'], A)][0]
        self.assertLessEqual(expiry - server.time.monotonic(), server.METRIC_FAIL_TTL + 1)

    def test_unlinked_account_refused(self):
        self.problem('account_not_linked', lambda: self.service.metrics(self.conn['id'], Z))


class ScopeTests(ServiceCase):
    def oauth(self, scopes):
        value = self.service._persist_connection('OAuth', 'oauth', {'access_token': 'a', 'expires_at': server.now() + 3600}, [{'id': A, 'name': 'P'}])
        with server.db() as conn: conn.execute('UPDATE connections SET scopes=? WHERE id=?', (scopes, value['id']))
        return value

    def test_old_read_only_signin_cannot_change(self):
        self.service.writes_allowed = True; value = self.oauth(None)
        listing = self.service.list_connections()['connections'][0]
        self.assertFalse(listing['can_change'])
        self.problem('sign_in_again', lambda: self.service.prepare(value['id'], A, 'r2.bucket.create', {'name': 'b'}, source='mcp'))
        self.assertEqual(self.fake.calls, [])

    def test_partial_scopes_gate_per_action(self):
        self.service.writes_allowed = True; value = self.oauth('dns.read dns.write')
        self.problem('sign_in_again', lambda: self.service.prepare(value['id'], A, 'r2.bucket.create', {'name': 'b'}, source='mcp'))
        self.assertTrue(self.service.can_change(self.service.connection(value['id']), 'dns.create'))

    def test_full_scopes_can_change(self):
        self.service.writes_allowed = True; value = self.oauth(ALL)
        self.assertTrue(self.service.list_connections()['connections'][0]['can_change'])
        self.assertEqual(self.service.prepare(value['id'], A, 'r2.bucket.create', {'name': 'b'}, source='mcp')['status'], 'pending_review')

    def test_writes_off_blocks_prepare(self):
        value = self.oauth(ALL); self.service.writes_allowed = False
        self.problem('writes_disabled', lambda: self.service.prepare(value['id'], A, 'r2.bucket.create', {'name': 'b'}, source='mcp'))

    def test_callback_records_granted_scope_and_replaces_old_signin(self):
        old = self.oauth(None)
        with mock.patch.dict(os.environ, {'CF_OAUTH_CLIENT_ID': 'c', 'CF_OAUTH_SCOPE': ALL, 'CF_OAUTH_REDIRECT_URI': 'http://localhost/oauth/callback'}):
            cookie, _ = server.new_session(); session = server.sha(cookie)
            start = self.service.oauth_start('', session); state = dict(x.split('=', 1) for x in start['authorization_url'].split('?', 1)[1].split('&'))['state']
            self.fake.queue({'access_token': 'new', 'refresh_token': 'r', 'expires_in': 3600, 'scope': 'dns.write zone.read'}, server.Problem(404, 'provider_not_found', 'x'), {'success': True, 'result': [{'id': A, 'name': 'P'}]})
            new = self.service.oauth_callback(server.urllib.parse.unquote(state), 'code', session)
        self.assertEqual(new['scopes'], ['dns.write', 'zone.read'])
        rows = {c['id']: c['status'] for c in self.service.list_connections()['connections']}
        self.assertEqual(rows[old['id']], 'replaced'); self.assertEqual(rows[new['id']], 'connected')
        self.assertIsNone(self.store.get(old['id']))
        self.assertFalse(any('revoke' in c[1] for c in self.fake.calls), 'replacing must not revoke the old refresh token remotely')


class SelfApprovalTests(ServiceCase):
    def test_mcp_cannot_confirm_or_review(self):
        self.service.writes_allowed = True
        value = self.service._persist_connection('T', 'token', {'access_token': 't'}, [{'id': A, 'name': 'P'}])
        out = server.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'cloudflare_action_prepare', 'arguments': {'connection_id': value['id'], 'account_id': A, 'action': 'r2.bucket.create', 'payload': {'name': 'b'}}}}, self.service)['result']['structuredContent']
        self.assertEqual(out['status'], 'pending_review')
        names = {t['name'] for t in server.TOOLS}
        self.assertFalse(names & {'cloudflare_approval_confirm', 'cloudflare_approval_review', 'cloudflare_connect'})
        for name in ('cloudflare_approval_confirm', 'cloudflare_approval_review'):
            reply = server.rpc({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': name, 'arguments': {'id': out['id'], 'payload_digest': out['payload_digest']}}}, self.service)
            self.assertEqual(reply['error']['code'], -32602)
        self.problem('approval_closed', lambda: self.service.confirm(out['id'], 'anything', out['payload_digest']))
        self.assertEqual(self.service.approval(out['id'])['status'], 'pending_review')
        self.assertFalse(any(c[0] in ('POST', 'PUT') for c in self.fake.calls))

    def test_no_delete_or_purchase_actions(self):
        self.assertFalse([a for a in server.ACTION_SCOPES if 'delete' in a or 'register' in a])
        self.problem('invalid_action', lambda: self.service.validate_action('r2.bucket.delete', {'name': 'b'}))


class FolderTests(ServiceCase):
    def setUp(self):
        super().setUp(); self.media = tempfile.TemporaryDirectory(); server.MEDIA = Path(self.media.name)
        site = server.MEDIA / 'Sites' / 'hello'; (site / 'css').mkdir(parents=True)
        (site / 'index.html').write_text('<h1>hi</h1>'); (site / 'css' / 'a.css').write_text('h1{}'); (site / '.secret').write_text('x')
        self.service.writes_allowed = True
        self.conn = self.service._persist_connection('T', 'token', {'access_token': 't'}, [{'id': A, 'name': 'P'}])

    def tearDown(self): self.media.cleanup(); super().tearDown()

    def test_path_safety(self):
        for bad in ('/etc', '../x', 'Sites/../../etc', '.ssh', 'Sites/.hidden', ''):
            self.problem('invalid_folder', lambda bad=bad: server.media_path(bad))
        os.symlink('/etc', server.MEDIA / 'escape')
        self.problem('invalid_folder', lambda: server.media_path('escape'))

    def test_scan_skips_hidden_and_hashes(self):
        manifest = server.scan_folder('Sites/hello', server.SITE_LIMITS)
        self.assertEqual([f['path'] for f in manifest['files']], ['css/a.css', 'index.html'])
        self.assertEqual(manifest['files'][1]['sha256'], hashlib.sha256(b'<h1>hi</h1>').hexdigest())

    def test_limits(self):
        self.problem('folder_too_large', lambda: server.scan_folder('Sites/hello', (1, 100, 100)))
        self.problem('file_too_large', lambda: server.scan_folder('Sites/hello', (10, 3, 100)))

    def publish_flow(self):
        self.service.transport = self.fake = RoutingTransport([
            ('/settings', server.Problem(404, 'provider_not_found', 'x')),
            ('/assets-upload-session', {'success': True, 'result': {'jwt': 'session-jwt', 'buckets': [[]]}}),
            ('/workers/assets/upload', {'success': True, 'result': {'jwt': 'done-jwt'}}),
            ('/workers/subdomain', {'success': True, 'result': {'subdomain': 'acme'}}),
        ])
        out = self.service.prepare(self.conn['id'], A, 'site.publish', {'script': 'hello-site', 'folder': 'Sites/hello'}, source='mcp')
        self.assertEqual(out['status'], 'pending_review'); self.assertEqual(out['files']['count'], 2)
        self.assertIn('publish the website hello-site', self.service.home('s')['approvals'][0]['text'])
        return out

    def test_publish_digest_binds_manifest_and_uploads_assets(self):
        out = self.publish_flow(); manifest = json.loads(self.raw_manifest(out['id']))
        self.assertEqual(out['payload_digest'], server.sha(server.canon({'payload': out['payload'], 'manifest': manifest})))
        hashes = {f['path']: hashlib.sha256(base64.b64encode((server.MEDIA / 'Sites/hello' / f['path']).read_bytes()) + f['path'].rsplit('.', 1)[1].encode()).hexdigest()[:32] for f in manifest['files']}
        self.fake.routes[1] = ('/assets-upload-session', {'success': True, 'result': {'jwt': 'session-jwt', 'buckets': [list(hashes.values())]}})
        self.service.review(out['id'], 'owner'); before = len(self.fake.calls)
        result = self.service.confirm(out['id'], 'owner', out['payload_digest'])['result']
        self.assertEqual(result['url'], 'https://hello-site.acme.workers.dev')
        calls = self.fake.calls[before:]
        session_call = next(c for c in calls if 'assets-upload-session' in c[1])
        self.assertEqual({k: v['hash'] for k, v in session_call[3]['manifest'].items()}, {'/' + k: v for k, v in hashes.items()})
        upload = next(c for c in calls if 'assets/upload' in c[1]); self.assertEqual(upload[2]['Authorization'], 'Bearer session-jwt')
        self.assertEqual(set(upload[3]['files']), set(hashes.values()))
        script = next(c for c in calls if c[0] == 'PUT'); metadata = json.loads(script[3]['fields']['metadata'][1])
        self.assertEqual(metadata['assets']['jwt'], 'done-jwt'); self.assertEqual(metadata['bindings'], [{'type': 'assets', 'name': 'ASSETS'}])
        self.assertTrue(any(c[0] == 'POST' and c[1].endswith('/workers/scripts/hello-site/subdomain') for c in calls))
        self.assertFalse(any(c[0] == 'DELETE' or '/routes' in c[1] or '/domains' in c[1] for c in self.fake.calls))

    def test_changed_file_after_approval_is_refused(self):
        out = self.publish_flow(); self.service.review(out['id'], 'owner')
        (server.MEDIA / 'Sites/hello/index.html').write_text('<h1>swapped</h1>')
        self.problem('folder_changed', lambda: self.service.confirm(out['id'], 'owner', out['payload_digest']))
        self.assertEqual(self.service.approval(out['id'])['status'], 'failed')
        self.assertFalse(any(c[0] == 'PUT' for c in self.fake.calls))

    def test_backup_puts_each_file_under_prefix(self):
        out = self.service.prepare(self.conn['id'], A, 'r2.backup', {'bucket': 'backups', 'folder': 'Sites/hello', 'prefix': 'p1'}, source='mcp')
        self.service.review(out['id'], 'owner'); result = self.service.confirm(out['id'], 'owner', out['payload_digest'])['result']
        self.assertEqual(result['files'], 2)
        puts = [c[1].rsplit('/objects/', 1)[1] for c in self.fake.calls if c[0] == 'PUT']
        self.assertEqual(sorted(puts), ['p1%2Fcss%2Fa.css', 'p1%2Findex.html'])

    def test_bad_names_rejected(self):
        self.problem('invalid_payload', lambda: self.service.validate_action('site.publish', {'script': 'Bad_Name', 'folder': 'Sites/hello'}))
        self.problem('invalid_payload', lambda: self.service.validate_action('r2.backup', {'bucket': 'b', 'folder': 'Sites/hello', 'prefix': '../x'}))

    def test_symlinks_inside_folder_are_never_read(self):
        outside = Path(self.media.name).parent / (Path(self.media.name).name + '-outside.txt'); outside.write_text('secret')
        self.addCleanup(outside.unlink)
        os.symlink(outside, server.MEDIA / 'Sites/hello/leak.txt')
        os.symlink(Path(self.media.name).parent, server.MEDIA / 'Sites/hello/up')
        manifest = server.scan_folder('Sites/hello', server.SITE_LIMITS)
        self.assertEqual([f['path'] for f in manifest['files']], ['css/a.css', 'index.html'])

    def test_symlinked_folder_component_refused(self):
        os.symlink(server.MEDIA / 'Sites', server.MEDIA / 'Linked')
        self.problem('folder_not_found', lambda: server.scan_folder('Linked/hello', server.SITE_LIMITS))

    def test_file_swapped_for_symlink_after_scan_is_refused(self):
        manifest = server.scan_folder('Sites/hello', server.SITE_LIMITS)
        target = server.MEDIA / 'Sites/hello/index.html'; copy = Path(self.media.name) / 'copy.html'; copy.write_bytes(target.read_bytes())
        target.unlink(); os.symlink(copy, target)
        self.problem('folder_changed', lambda: server.read_checked('Sites/hello', manifest['files'][1]))
        (server.MEDIA / 'Sites/hello/css').rename(server.MEDIA / 'Sites/hello/css-real'); os.symlink(server.MEDIA / 'Sites/hello/css-real', server.MEDIA / 'Sites/hello/css')
        self.problem('folder_changed', lambda: server.read_checked('Sites/hello', manifest['files'][0]))

    def test_backup_prefix_is_bound_to_the_approval(self):
        with mock.patch.object(server.time, 'strftime', return_value='2026-10-21'):
            out = self.service.prepare(self.conn['id'], A, 'r2.backup', {'bucket': 'backups', 'folder': 'Sites/hello'}, source='mcp')
        manifest = json.loads(self.raw_manifest(out['id']))
        self.assertEqual(manifest['prefix'], '2026-10-21/hello')
        self.assertEqual(out['payload_digest'], server.sha(server.canon({'payload': out['payload'], 'manifest': manifest})))
        self.assertIn('backups/2026-10-21/hello', self.service.home('s')['approvals'][0]['text'])
        self.service.review(out['id'], 'owner')
        with mock.patch.object(server.time, 'strftime', return_value='2030-01-01'):
            self.service.confirm(out['id'], 'owner', out['payload_digest'])
        puts = [c[1].rsplit('/objects/', 1)[1] for c in self.fake.calls if c[0] == 'PUT']
        self.assertTrue(puts and all(x.startswith('2026-10-21%2Fhello%2F') for x in puts))

    def test_backup_never_overwrites(self):
        self.fake.queue({'success': True, 'result': [{'key': 'p1/index.html'}]})
        self.problem('backup_exists', lambda: self.service.prepare(self.conn['id'], A, 'r2.backup', {'bucket': 'backups', 'folder': 'Sites/hello', 'prefix': 'p1'}, source='mcp'))
        out = self.service.prepare(self.conn['id'], A, 'r2.backup', {'bucket': 'backups', 'folder': 'Sites/hello', 'prefix': 'p2'}, source='mcp')
        self.service.review(out['id'], 'owner'); self.fake.queue({'success': True, 'result': [{'key': 'p2/x'}]})
        self.problem('backup_exists', lambda: self.service.confirm(out['id'], 'owner', out['payload_digest']))
        self.assertFalse(any(c[0] == 'PUT' for c in self.fake.calls))

    def raw_manifest(self, approval_id):
        with server.db() as conn: return conn.execute('SELECT manifest FROM approvals WHERE id=?', (approval_id,)).fetchone()['manifest']


if __name__ == '__main__': unittest.main()
