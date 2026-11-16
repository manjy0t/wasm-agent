#!/usr/bin/env python3
"""Four real HTTP services plus real Rust host/Wasm agent. No TDX/Docker claims.

Run from the repository with a Python environment containing requirements-signing.txt.
Build the local host and agent first with: .venv/bin/python build.py --install-target
These local integration tests are not needed to onboard against the deployed VMs.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hal_fleet.authority import Authority
from hal_fleet.client import Client, benchmark
from hal_fleet.common import (DOCUMENT_DOMAIN, Error, Database, Transport, atomic_json, digest,
    private_hex, public, request, sign, verify, parse)
from hal_fleet.http_server import HTTPServer, make_server
from hal_fleet.policy import SETTINGS
from hal_fleet.runtime import Execution
from hal_fleet.services import Files, Management
from job_signing import DOMAIN, rule_digest


class FleetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Check once, before starting any HTTP services. Missing build outputs are
        # a setup failure, not 17 independent regressions (or silently skipped tests).
        missing = [name for name in ('dist/hal-on-demand', 'dist/agent.wasm')
                   if not (ROOT / name).is_file()]
        if missing:
            raise RuntimeError(
                'Local integration-test build is missing: ' + ', '.join(missing) + '\n'
                'From ' + str(ROOT) + ', run:\n'
                '  .venv/bin/python build.py --install-target\n'
                '  .venv/bin/python -B tests/test_fleet.py\n'
                'Build on the machine running these tests; a Linux VM binary cannot run on macOS.\n'
                'VM onboarding and benchmarking use fleet.py and do not require a local Rust build.')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hal-fleet-test-', dir='/tmp')
        self.root = Path(self.temp.name).resolve()
        self.operator, self.issuer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.trust = dict(version=1, issuer='hal-identity', management_audience='hal-management',
            execution_audience='intel-worker-1', files_audience='hal-files', identity_public_key=public(self.issuer),
            operator_public_key=public(self.operator), endpoints={})
        self.transport = Transport(timeout=30)
        self.clients = []
        self.apps, self.servers, self.databases = {}, {}, []
        for role in ('identity', 'files', 'execution', 'management'):
            directory = self.root / role
            directory.mkdir(mode=0o700)
            config = dict(role=role, trust=self.trust, state_dir=str(directory))
            db = Database(directory / 'db.sqlite3')
            self.databases.append(db)
            if role == 'identity':
                config['identity_key'] = str(directory / 'key.json')
                atomic_json(config['identity_key'], {'private_key': private_hex(self.issuer)})
                app = Authority(config, db)
            elif role == 'files':
                app = Files(config, db)
            elif role == 'execution':
                config.update(binary=str(ROOT/'dist/hal-on-demand'), agent=str(ROOT/'dist/agent.wasm'),
                    binary_sha256=digest((ROOT/'dist/hal-on-demand').read_bytes()),
                    agent_sha256=digest((ROOT/'dist/agent.wasm').read_bytes()),
                    mode='wasm', test_in_process=True, allow_non_tee=True, settings=SETTINGS,
                    container_image='unused-software-test', max_active_users=4)
                app = Execution(config, db, self.transport)
            else:
                app = Management(config, db, self.transport)
            server = HTTPServer(('127.0.0.1', 0), app)
            self.servers[role], self.apps[role] = server, app
            self.trust['endpoints'][role] = 'http://127.0.0.1:' + str(server.server_port)
            threading.Thread(target=server.serve_forever, kwargs={'poll_interval':.01}, daemon=True).start()
        for app in self.apps.values():
            for role, url in self.trust['endpoints'].items():
                app.config[role+'_url'] = url
        self.fixture = (ROOT/'tests/workloads/function0.wasm').read_bytes()
        sha = digest(self.fixture)
        self.workload = dict(name='hash-fixture', component=sha+'.wasm', sha256=sha, artifact_bytes=len(self.fixture),
            rule=dict(component=sha+'.wasm', cache='memory', cache_ttl_ms=300000, hal_permissions=['crypto'],
            memory_mib=64, fuel=1000000000, execution_timeout_ms=5000, max_output_bytes=4096, worker_max_jobs=128,
            validation=dict(kind='hex', value='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')))
        self.publish([self.workload], [self.fixture])
        self.alice = self.client('alice')

    def tearDown(self):
        for server in self.servers.values():
            server.shutdown()
            server.server_close()
        self.apps['execution'].close()
        for client in self.clients:
            client.transport.close()
        self.transport.close()
        # HTTP handlers can have idle persistent sockets; close client-side connections before DB teardown.
        time.sleep(.03)
        for db in self.databases:
            db.close()
        self.temp.cleanup()

    def api(self, role, path, body=None):
        return self.transport.call(self.trust['endpoints'][role], path, body)

    def publish(self, rows, data):
        for row, raw in zip(rows, data):
            self.api('files', '/v1/upload', request(self.operator, self.trust['files_audience'], 'upload', 'operator',
                dict(sha256=row['sha256'], wasm_base64=base64.b64encode(raw).decode())))
        return self.api('identity', '/v1/publish', request(self.operator, self.trust['issuer'], 'publish', 'operator', {'workloads':rows}))

    def client(self, name):
        key = Ed25519PrivateKey.generate()
        path = self.root / (name + '.json')
        atomic_json(path, dict(version=1, user=name, private_key=private_hex(key), trust=self.trust))
        client = Client(path)
        self.clients.append(client)
        return client

    def ready(self, client=None):
        client = client or self.alice
        client.register()
        client.approve(['hash-fixture'])
        client.open_session()
        return client

    def job_body(self, client, cache='bypass'):
        row = self.workload
        now, job_id = int(time.time()), str(uuid.uuid4())
        claims = dict(version=1, tenant=client.config['user'], audience=client.session['audience'],
            epoch=client.session['epoch'], job_id=job_id, nonce=os.urandom(32).hex(), operation='run',
            component=row['component'], sha256=row['sha256'], artifact_bytes=row['artifact_bytes'], cache=cache,
            rule_sha256=rule_digest(row['rule']), isolation=client.session['isolation'], input='none',
            issued_unix=now, expires_unix=now+120)
        ticket = sign(client.key, DOMAIN, claims)
        return dict(document=client.document, isolation=client.session['isolation'], job=dict(protocol=1,
            job_id=job_id, component=row['component'], sha256=row['sha256'], artifact_bytes=row['artifact_bytes'],
            cache=cache, job_ticket=ticket))

    def test_enrollment_approval_run_cache_isolation_and_fresh_workload_instances(self):
        alice = self.ready()
        first = alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        self.assertEqual(first['status'], 'completed', first)
        self.assertEqual(first['response']['agent']['cache_status'], 'miss')
        hit = alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        self.assertEqual(hit['response']['agent']['cache_status'], 'hit', hit)
        self.assertFalse(hit['response']['agent']['workload_instance_reused'])
        self.assertTrue(hit['response']['agent']['job_authorization']['helper_checked'])
        bob = self.ready(self.client('bob'))
        self.assertEqual(bob.job('hash-fixture', 'reuse', 'wasm', 'in-process')['response']['agent']['cache_status'], 'miss')
        self.assertNotEqual(self.apps['execution'].brokers['alice'].root, self.apps['execution'].brokers['bob'].root)
        bypass = alice.job('hash-fixture', 'bypass', 'wasm', 'in-process')
        self.assertEqual(bypass['response']['agent']['cache_status'], 'bypass')
        self.assertEqual(alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')['response']['agent']['cache_status'], 'hit')

    def test_name_takeover_stolen_document_and_forged_certificate_are_rejected(self):
        self.alice.register()
        impostor = Ed25519PrivateKey.generate()
        with self.assertRaises(Error):
            self.api('identity', '/v1/register', request(impostor, self.trust['issuer'], 'register', 'alice', {}))
        bob = self.client('bob')
        bob.register()
        with self.assertRaises(Error):
            self.api('execution', '/v1/enroll', bob.signed('execution', 'enroll', {'document': self.alice.document}))
        wrong = copy.deepcopy(self.alice.document)
        wrong['signature'] = '0'*128
        with self.assertRaises(Error):
            self.api('execution', '/v1/enroll', self.alice.signed('execution', 'enroll', {'document': wrong}))

    def test_registration_permissions_and_unapproved_workloads_fail_closed(self):
        self.alice.register()
        with self.assertRaises(Error):
            self.alice.approve(['unpublished'])
        with self.assertRaises(Error):
            self.alice.open_session()
        with self.assertRaises(Error):
            self.api('identity', '/v1/register', self.alice.signed('identity', 'register', {'max_inflight':999}))
        with self.assertRaises(Error):
            self.api('identity', '/v1/publish', self.alice.signed('identity', 'publish', {'workloads':[self.workload]}))

    def test_replay_changed_artifact_and_misrouting_are_rejected_before_execution(self):
        self.ready()
        body = self.job_body(self.alice)
        changed = copy.deepcopy(body)
        changed['job']['cache'] = 'reuse'
        with self.assertRaises(Error):
            self.api('execution', '/v1/run', changed)
        result = self.api('execution', '/v1/run', body)
        self.assertEqual(result['status'], 'ok', result)
        with self.assertRaises(Error):
            self.api('execution', '/v1/run', body)
        bob = self.ready(self.client('bob'))
        body = self.job_body(self.alice)
        body['document'] = bob.document
        with self.assertRaises(Error):
            self.api('execution', '/v1/run', body)

    def test_revocation_blocks_existing_session_and_old_enrollment(self):
        self.ready()
        body = self.job_body(self.alice)
        self.api('identity', '/v1/revoke', request(self.operator, self.trust['issuer'], 'revoke', 'operator', {'user':'alice'}))
        with self.assertRaises(Error):
            self.api('execution', '/v1/run', body)
        with self.assertRaises(Error):
            self.alice.register()
        with self.assertRaises(Error):
            self.alice.enroll()

    def test_expired_documents_wrong_destinations_and_oversized_rules(self):
        self.alice.register()
        doc = parse(self.alice.document['payload'])
        doc['issued_unix'], doc['expires_unix'] = int(time.time())-100, int(time.time())-1
        expired = sign(self.issuer, DOCUMENT_DOMAIN, doc)
        with self.assertRaises(Error):
            self.api('execution', '/v1/enroll', self.alice.signed('execution', 'enroll', {'document':expired}))
        with self.assertRaises(Error):
            self.api('execution', '/v1/enroll', self.alice.signed('management', 'enroll', {'document':self.alice.document}))
        wrong = copy.deepcopy(self.workload)
        wrong['rule']['memory_mib'] = 999
        with self.assertRaises(Error):
            self.publish([wrong], [self.fixture])

    def test_immutable_artifacts_digest_and_publisher_checks(self):
        self.alice.register()
        with self.assertRaises(Error):
            self.api('files', '/v1/upload', self.alice.signed('files', 'upload', dict(sha256=digest(self.fixture),
                     wasm_base64=base64.b64encode(self.fixture).decode())))
        with self.assertRaises(Error):
            self.api('files', '/v1/upload', request(self.operator, self.trust['files_audience'], 'upload', 'operator',
                     dict(sha256='0'*64, wasm_base64=base64.b64encode(self.fixture).decode())))
        with self.assertRaises(Error):
            self.api('files', '/artifacts/../../identity/key.json')

    def test_native_baseline_works_with_same_api_but_refuses_code_cache(self):
        self.apps['execution'].config['mode'] = 'native'
        self.ready()
        row = self.alice.job('hash-fixture', 'bypass', 'native', 'in-process')
        self.assertEqual(row['status'], 'completed', row)
        self.assertEqual(row['response']['agent']['agent_kind'], 'none')
        self.assertEqual(row['response']['agent']['configuration']['code_cache_storage'], 'disabled')
        with self.assertRaises(Error):
            self.alice.job('hash-fixture', 'reuse', 'native', 'in-process')

    def test_legacy_profile_cannot_enter_audited_benchmark_population(self):
        self.ready()
        with self.assertRaisesRegex(Error, 'Update management'):
            benchmark(self.alice, ['hash-fixture'], 8, 2, 'reuse', self.root/'benchmark', 'wasm', 'in-process')

    def test_session_refresh_after_broker_restart_needs_no_copied_epoch(self):
        self.ready()
        old = self.job_body(self.alice)
        epoch = self.alice.session['epoch']
        self.apps['execution'].brokers['alice'].close()
        self.alice.open_session()
        self.assertNotEqual(epoch, self.alice.session['epoch'])
        with self.assertRaises(Error):
            self.api('execution', '/v1/run', old)
        self.assertEqual(self.alice.job('hash-fixture', 'bypass', 'wasm', 'in-process')['status'], 'completed')

    def test_real_rust_host_downloads_over_https_with_a_pinned_private_ca(self):
        from hal_fleet.install import certificates
        info = dict(vms={r:dict(ip='127.0.0.'+str(i+1), ssh_user='tester')
                         for i, r in enumerate(('identity','files','management','execution'))})
        atomic_json(self.root/'inventory.json', info)
        certificates(self.root/'inventory.json', self.root/'tls')
        # The identity test certificate has the required 127.0.0.1 SAN; certificate
        # subject labels are not used for TLS authorization, the configured IP is.
        config = dict(listen='127.0.0.1:0', tls_cert=str(self.root/'tls/identity.crt'), tls_key=str(self.root/'tls/identity.key'))
        server = make_server(config, self.apps['files'])
        self.servers['tls-files'] = server
        threading.Thread(target=server.serve_forever, kwargs={'poll_interval':.01}, daemon=True).start()
        self.apps['execution'].config.update(files_url='https://127.0.0.1:'+str(server.server_port), ca_file=str(self.root/'tls/ca.pem'))
        self.ready()
        result = self.alice.job('hash-fixture', 'bypass', 'wasm', 'in-process')
        self.assertEqual(result['status'], 'completed', result)

    def test_parallel_duplicate_job_executes_once(self):
        self.ready()
        body = self.job_body(self.alice)
        def run(_):
            transport = Transport()
            try:
                return transport.call(self.trust['endpoints']['execution'], '/v1/run', body).get('status')
            except Error:
                return 'rejected'
            finally:
                transport.close()
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(run, range(4)))
        self.assertEqual(outcomes.count('ok'), 1, outcomes)
        self.assertEqual(outcomes.count('rejected'), 3, outcomes)

    def test_cli_onboarding_reuses_keys_and_runs_without_manual_policy_files(self):
        from hal_fleet.install import certificates
        info = dict(vms={r:dict(ip='127.0.0.'+str(i+1), ssh_user='tester')
                         for i, r in enumerate(('identity','files','management','execution'))})
        atomic_json(self.root/'inventory.json', info)
        certificates(self.root/'inventory.json', self.root/'tls')
        deployment = self.root/'deployment.json'
        atomic_json(deployment, dict(endpoints=self.trust['endpoints'],
            issuer_sha256=digest(bytes.fromhex(public(self.issuer))), ca_file=str(self.root/'tls/ca.pem')))
        destination = self.root/'charlie.json'
        command = [sys.executable, '-B', str(ROOT/'fleet.py'), 'onboard', '--user', 'charlie',
                   '--deployment', str(deployment), '--output', str(destination), '--workloads', 'all']
        first = json.loads(subprocess.check_output(command, text=True))
        private_key = parse(destination.read_text())['private_key']
        second = json.loads(subprocess.check_output(command, text=True))
        self.assertEqual(first['approved'], ['hash-fixture'])
        self.assertEqual(first['enrollment']['revision'], second['enrollment']['revision'])
        self.assertEqual(private_key, parse(destination.read_text())['private_key'])
        row = json.loads(subprocess.check_output([sys.executable, '-B', str(ROOT/'fleet.py'), 'run',
            '--client', str(destination), '--workload', 'hash-fixture', '--cache', 'bypass',
            '--expect-isolation', 'in-process'], text=True))
        self.assertEqual(row['status'], 'completed', row)

    def test_permission_update_replaces_only_that_users_broker(self):
        alice = self.ready()
        bob = self.ready(self.client('bob'))
        bob.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        alice_epoch, bob_epoch = alice.session['epoch'], bob.session['epoch']
        raw = (ROOT/'tests/workloads/function1.wasm').read_bytes()
        row = copy.deepcopy(self.workload)
        row.update(name='second-function', component=digest(raw)+'.wasm', sha256=digest(raw), artifact_bytes=len(raw))
        row['rule'].update(component=row['component'], validation={'kind':'bounded'})
        self.publish([row], [raw])
        alice.approve(['second-function'])
        alice.open_session()
        self.assertNotEqual(alice_epoch, alice.session['epoch'])
        bob.open_session()
        self.assertEqual(bob_epoch, bob.session['epoch'])
        self.assertEqual(bob.job('hash-fixture', 'reuse', 'wasm', 'in-process')['response']['agent']['cache_status'], 'hit')

    def test_matrix_command_runs_every_cache_concurrency_pair_and_saves_results(self):
        self.ready()
        folder = self.root/'matrix'
        result = subprocess.run([sys.executable, '-B', str(ROOT/'benchmarks/run_matrix.py'),
            '--client', str(self.alice.path), '--output', str(folder), '--jobs', '2', '--repeats', '1',
            '--expect-isolation', 'in-process'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = parse((folder/'matrix.json').read_text())
        self.assertEqual({(r['concurrency'], r['cache']) for r in rows},
                         {(q, p) for q in (1, 2, 4, 8) for p in ('bypass', 'reuse')})
        self.assertTrue(all(r['completed'] == 2 and r['failed_or_unknown'] == 0 for r in rows), rows)
        for row in rows:
            self.assertEqual(len((folder/row['label']/'jobs.jsonl').read_text().splitlines()), 2)

    def test_identity_outage_blocks_execution_and_recovers(self):
        self.ready()
        body = self.job_body(self.alice)
        execution = self.apps['execution']
        original = execution.config['identity_url']
        execution.config['identity_url'] = self.trust['endpoints']['files']
        try:
            with self.assertRaises(Error):
                self.api('execution', '/v1/run', body)
        finally:
            execution.config['identity_url'] = original
        self.assertEqual(self.api('execution', '/v1/run', body)['status'], 'ok')

    @unittest.skipUnless((ROOT/'benchmarks/artifacts/manifest.json').exists(), 'Build the 15 workloads first')
    def test_all_fifteen_real_components_match_independent_expected_outputs(self):
        manifest = parse((ROOT/'benchmarks/artifacts/manifest.json').read_text())
        rows = manifest['workloads']
        self.assertEqual(len(rows), 15)
        self.publish(rows, [(ROOT/'benchmarks/artifacts'/w['component']).read_bytes() for w in rows])
        self.alice.register()
        self.alice.approve([w['name'] for w in rows])
        self.alice.open_session()
        for row in rows:
            with self.subTest(workload=row['name']):
                result = self.alice.job(row['name'], 'reuse', 'wasm', 'in-process')
                self.assertEqual(result['status'], 'completed', result)
                self.assertEqual(result['response']['agent']['result']['hex'], row['rule']['validation']['value'])
                hit = self.alice.job(row['name'], 'reuse', 'wasm', 'in-process')
                self.assertEqual(hit['response']['agent']['cache_status'], 'hit', hit)


class TLSTest(unittest.TestCase):
    def test_private_ca_and_ip_certificate_verify_without_disabling_tls_checks(self):
        from hal_fleet.install import certificates
        import ssl
        with tempfile.TemporaryDirectory(dir='/tmp') as folder:
            root = Path(folder)
            inventory = dict(vms={role:dict(ip='127.0.0.'+str(i+1), ssh_user='tester')
                                  for i, role in enumerate(('identity','files','management','execution'))})
            atomic_json(root/'inventory.json', inventory)
            certificates(root/'inventory.json', root/'tls')
            class App:
                config = dict(role='identity')
            app = App()
            config = dict(listen='127.0.0.1:0', tls_cert=str(root/'tls/identity.crt'), tls_key=str(root/'tls/identity.key'))
            server = make_server(config, app)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                url = 'https://127.0.0.1:' + str(server.server_port)
                import socket
                # An incomplete TLS handshake must not block the next client.
                stalled = socket.create_connection(('127.0.0.1', server.server_port))
                client = Transport(ca_file=str(root/'tls/ca.pem'))
                self.assertEqual(client.call(url, '/health')['status'], 'ready')
                stalled.close()
                client.close()
                with self.assertRaises(Error):
                    Transport().call(url, '/health')
            finally:
                server.shutdown()
                server.server_close()


class InstallationTest(unittest.TestCase):
    def test_failed_initialization_can_be_corrected_and_identity_is_not_rotated_on_rerun(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as folder:
            root = Path(folder)
            config = root/'state/fleet.json'
            operator = Ed25519PrivateKey.generate()
            command = [sys.executable, '-B', str(ROOT/'fleet.py'), 'init', '--role', 'identity',
                '--config', str(config), '--identity-url', 'http://127.0.0.1:9200',
                '--execution-url', 'http://127.0.0.1:9201', '--files-url', 'http://127.0.0.1:9202',
                '--operator-public-key', public(operator), '--management-url']
            failure = subprocess.run(command+['invalid-url'], capture_output=True, text=True)
            self.assertNotEqual(failure.returncode, 0)
            self.assertFalse(config.exists())
            subprocess.run(command+['http://127.0.0.1:9203'], capture_output=True, text=True, check=True)
            state = parse(config.read_text())
            before = Path(state['identity_key']).read_bytes()
            repeat = subprocess.run(command+['http://127.0.0.1:9203'], capture_output=True, text=True)
            self.assertNotEqual(repeat.returncode, 0)
            self.assertEqual(before, Path(state['identity_key']).read_bytes())

    def test_source_package_contains_build_inputs_and_workloads_but_no_state_or_private_keys(self):
        from hal_fleet.install import package
        import tarfile
        with tempfile.TemporaryDirectory(dir='/tmp') as folder:
            root = Path(folder)/'repo'
            root.mkdir()
            files = ('.dockerignore', 'Cargo.toml', 'fleet.py', 'workloads.json', 'client.json', 'benchmarks/artifacts/abc.wasm',
                     'state/client.json', 'tls/server.key', 'src/test.key', 'src/main.rs',
                     'vendor/wasmhal/Cargo.toml', 'target/debug/binary', 'benchmarks/guest/target/private')
            for file in files:
                path = root/file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
            output = Path(folder)/'repo.tar.gz'
            package(root, output)
            with tarfile.open(output) as archive:
                names = set(archive.getnames())
            self.assertEqual(names, {'hal-on-demand/'+name for name in
                ('.dockerignore', 'Cargo.toml', 'fleet.py', 'workloads.json', 'benchmarks/artifacts/abc.wasm',
                 'src/main.rs', 'vendor/wasmhal/Cargo.toml')})


if __name__ == '__main__':
    unittest.main(verbosity=2)
