"""Behavioral regressions for the single independent blocker review."""
import threading
from unittest import mock
from urllib.parse import parse_qs, urlsplit
from test_service import ServiceCase, server, A, Z


class SecurityReviewRegressions(ServiceCase):
    def connected(self):
        return self.service._persist_connection('Synthetic review fixture', 'token', {'access_token': 'synthetic-provider-token'}, [{'id': A, 'name': 'Synthetic'}])

    def race_disconnect(self, preparing=False):
        self.service.writes_allowed = True
        connection = self.connected()
        entered, release, attempted, disconnected = (threading.Event() for _ in range(4))
        errors, prepared = [], []
        def transport(*args, **kwargs):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('fixture release timeout')
            return 200, {'success': True, 'result': {'id': Z, 'account': {'id': A}} if preparing else {'id': A}}
        self.fake.request = transport
        def owner_operation():
            try:
                if preparing:
                    prepared.append(self.service.prepare(connection['id'], A, 'dns.create', {'zone_id': Z, 'type': 'A', 'name': 'fixture.example', 'content': '192.0.2.1'}, 'synthetic-session'))
                else:
                    self.service.read_resource(connection['id'], A, 'account')
            except Exception as error:
                errors.append(error)
        def disconnect():
            attempted.set()
            try:
                self.service.disconnect(connection['id'])
                disconnected.set()
            except Exception as error:
                errors.append(error)
        owner = threading.Thread(target=owner_operation)
        owner.start()
        self.assertTrue(entered.wait(2))
        stopper = threading.Thread(target=disconnect)
        stopper.start()
        self.assertTrue(attempted.wait(2))
        try:
            self.assertFalse(disconnected.wait(.15), 'disconnect acknowledged while authorized owner I/O was still blocked')
        finally:
            release.set()
            owner.join(3)
            stopper.join(3)
        self.assertFalse(owner.is_alive())
        self.assertFalse(stopper.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(disconnected.is_set())
        if preparing:
            self.assertEqual(self.service.approval(prepared[0]['id'])['status'], 'disconnected')

    def test_disconnect_waits_for_owner_read(self):
        self.race_disconnect()

    def test_disconnect_waits_for_dns_preparation_then_invalidates_it(self):
        self.race_disconnect(preparing=True)

    def test_oauth_expiry_during_exchange_rejects_finalization(self):
        config = {'CF_OAUTH_CLIENT_ID': 'synthetic-client', 'CF_OAUTH_SCOPE': 'synthetic-scope', 'CF_OAUTH_REDIRECT_URI': 'http://localhost/oauth/callback'}
        with mock.patch.dict(server.os.environ, config):
            cookie, _ = server.new_session()
            flow = self.service.oauth_start('Synthetic expiry', server.sha(cookie))
            state = parse_qs(urlsplit(flow['authorization_url']).query)['state'][0]
            self.fake.queue({'access_token': 'synthetic-access', 'expires_in': 3600}, {'sub': 'synthetic'}, {'success': True, 'result': [{'id': A}], 'result_info': {'total_pages': 1}})
            def expire():
                with server.db() as conn:
                    conn.execute('UPDATE oauth_flows SET expires=0 WHERE state_hash=?', (server.sha(state),))
            self.service._oauth_finalize_ready = expire
            self.problem('oauth_flow_invalid', lambda: self.service.oauth_callback(state, 'synthetic-code', server.sha(cookie)))
            self.assertEqual(self.service.list_connections()['connections'], [])
            self.assertEqual(self.store.read(), {})

    def crash_write(self, accepted=False):
        connection = self.connected()
        self.service.writes_allowed = True
        approval = self.service.prepare(connection['id'], A, 'r2.bucket.create', {'name': 'synthetic-never-created'}, 'synthetic-session')
        calls = []
        def interrupted(*args, **kwargs):
            if accepted:
                calls.append('synthetic-provider-accepted')
            raise KeyboardInterrupt('simulated process interruption')
        self.fake.request = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.service.confirm(approval['id'], 'synthetic-session', approval['payload_digest'])
        self.assertEqual(self.service.approval(approval['id'])['status'], 'executing')
        restarted = server.Service(self.fake, self.store, writes_allowed=True)
        self.assertEqual(restarted.approval(approval['id'])['status'], 'manual_review')
        before = list(calls)
        self.problem('approval_closed', lambda: restarted.confirm(approval['id'], 'synthetic-session', approval['payload_digest']))
        self.assertEqual(calls, before)

    def test_restart_fences_crash_before_provider_acceptance(self):
        self.crash_write()

    def test_restart_fences_crash_after_provider_acceptance(self):
        self.crash_write(accepted=True)
