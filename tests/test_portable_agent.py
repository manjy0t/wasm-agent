#!/usr/bin/env python3
"""Portable control-plane tests. Fixture evidence is NOT hardware attestation.

Real cryptographic channels, four HTTP services, and the real Rust component
linker are exercised. Vendor verification and container execution are injected
fixtures; hardware/Docker acceptance remains a separate deployment check.
"""
import copy
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import test_fleet as legacy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from hal_fleet.attested_channel import (ABI, PROTOCOL, binding_hash, derive, public_hex, seal, unseal,
    verify_evidence, encode, decode)
from hal_fleet.common import (Error, canonical, digest, parse, atomic_json, private_hex, public, request)
from hal_fleet.portable import PortableExecution, PortableManagement


def policy():
    return dict(version=1, platform='intel-tdx', runtime_binding='approved-measured-boot', lease_seconds=300,
                measurements={k: 'a' * 96 for k in ('mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3')},
                verifier='external', verifier_argv=['/fixture-verifier'], verifier_files={'/fixture-verifier': 'b' * 64})


class ChannelTests(unittest.TestCase):
    def test_keys_binding_and_message_direction_are_authenticated(self):
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        binding = dict(challenge='a', tenant='alice', agent_sha256='f' * 64)
        left, right = derive(a, public_hex(b), binding), derive(b, public_hex(a), binding)
        self.assertEqual(left, right)
        message = seal(left, binding, 'deploy', {'secret': 'file credential'})
        self.assertEqual(unseal(right, binding, 'deploy', message)['secret'], 'file credential')
        for changed in (dict(binding, tenant='bob'), dict(binding, challenge='b'), dict(binding, agent_sha256='0' * 64)):
            with self.assertRaises(Error):
                unseal(right, changed, 'deploy', message)
        with self.assertRaises(Error):
            unseal(right, binding, 'run', message)
        with self.assertRaises(Error):
            unseal(os.urandom(32), binding, 'deploy', message)
        message['ciphertext'] = encode(decode(message['ciphertext'])[:-1] + b'!')
        with self.assertRaises(Error):
            unseal(right, binding, 'deploy', message)

    def test_verifier_must_check_all_security_claims(self):
        p = policy()
        binding = dict(challenge='fresh', recipient_key='a' * 64)
        evidence = dict(platform='intel-tdx', report_hex=b'fixture'.hex())
        claims = dict(verified=True, platform='intel-tdx', evidence_sha256=digest(b'fixture'),
                      report_data=binding_hash(binding), debug=False, tcb_status='UpToDate', measurements=p['measurements'])
        with mock.patch('hal_fleet.attested_channel.Path.read_bytes', return_value=b'fixture-adapter'):
            p['verifier_files']['/fixture-verifier'] = digest(b'fixture-adapter')
            with mock.patch('hal_fleet.attested_channel.bounded_command', return_value=claims):
                self.assertTrue(verify_evidence(p, evidence, binding)['verified'])
            changes = [dict(verified=False), dict(report_data='0' * 128), dict(debug=True), dict(tcb_status='OutOfDate'),
                       dict(evidence_sha256='0' * 64), dict(measurements={}), dict(platform='amd-sev-snp')]
            for change in changes:
                with self.subTest(change=change), mock.patch('hal_fleet.attested_channel.bounded_command', return_value=dict(claims, **change)):
                    with self.assertRaises(Error):
                        verify_evidence(p, evidence, binding)

    def test_amd_policy_uses_snp_claims_and_requires_vmpl_zero(self):
        p = dict(policy(), platform='amd-sev-snp', measurements={'measurement': 'c' * 96})
        binding = {'challenge': 'fresh-snp', 'recipient_key': 'b' * 64}
        evidence = dict(platform='amd-sev-snp', report_hex=b'snp-fixture'.hex())
        claims = dict(verified=True, platform=p['platform'], evidence_sha256=digest(b'snp-fixture'),
                      report_data=binding_hash(binding), debug=False, tcb_status='UpToDate', measurements=p['measurements'], vmpl=0)
        with mock.patch('hal_fleet.attested_channel.Path.read_bytes', return_value=b'adapter'):
            p['verifier_files']['/fixture-verifier'] = digest(b'adapter')
            with mock.patch('hal_fleet.attested_channel.bounded_command', return_value=claims):
                self.assertTrue(verify_evidence(p, evidence, binding)['verified'])
                claims['vmpl'] = 1
                with self.assertRaises(Error):
                    verify_evidence(p, evidence, binding)

    def test_remote_verified_boolean_is_not_evidence(self):
        with self.assertRaises(Error):
            verify_evidence(policy(), {'verified': True, 'platform': 'intel-tdx'}, {})

    def test_dcap_checks_vendor_result_collateral_and_quote_layout(self):
        from hal_fleet.dcap import verify_quote
        raw = bytearray(637)
        struct.pack_into('<H', raw, 0, 4)
        struct.pack_into('<I', raw, 4, 0x81)
        struct.pack_into('<I', raw, 632, 1)
        def verified(*args):
            args[4]._obj.value = 0
            args[5]._obj.value = 0
            return 0
        function = mock.Mock(side_effect=verified)
        with mock.patch('hal_fleet.dcap.ctypes.CDLL', return_value=mock.Mock(tdx_qv_verify_quote=function)):
            self.assertTrue(verify_quote(bytes(raw), '/fixture-qvl')['verified'])
            function.side_effect = lambda *args: 1
            with self.assertRaises(Error):
                verify_quote(bytes(raw), '/fixture-qvl')
            function.side_effect = lambda *args: 0  # Output status left uninitialized: reject.
            with self.assertRaises(Error):
                verify_quote(bytes(raw), '/fixture-qvl')
        struct.pack_into('<H', raw, 0, 5)
        with self.assertRaises(Error):
            verify_quote(bytes(raw), '/fixture-qvl')


class PortableInstallTests(unittest.TestCase):
    def test_role_packages_never_send_management_secret_to_execution_or_files(self):
        import io
        import tarfile
        from hal_fleet.portable_install import install_role
        key = Ed25519PrivateKey.generate()
        setup = dict(platform='intel-tdx', policy=policy(), agent=b'\0asm' + b'fixture',
                     key=dict(private_key=private_hex(key)), public_key=public(key), agent_configuration={'private': 'agent-secret'})
        archives = {}
        def ssh(role, command, data=None):
            if data:
                with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                    archives[role] = {entry.name: archive.extractfile(entry).read() for entry in archive}
            self.assertNotIn(private_hex(key), command)
        for role in ('files', 'execution', 'management'):
            install_role(ssh, role, 'hal-fleet/hal-on-demand', setup)
        for role in ('files', 'execution'):
            self.assertEqual(set(archives[role]), {'profile.json'})
            self.assertNotIn(private_hex(key), archives[role]['profile.json'].decode())
            self.assertNotIn('agent-secret', archives[role]['profile.json'].decode())
        self.assertIn('agent.wasm', archives['management'])
        self.assertIn('management-signing.json', archives['management'])

    def test_configuration_preview_preserves_keys_and_existing_config(self):
        from hal_fleet.portable_config import configure
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            cfg, profile_path = root/'fleet.json', root/'profile.json'
            original = dict(role='files', state_dir=str(root), trust={'endpoints': {'files': 'https://127.0.0.1'}},
                            tls_cert='server.crt', tls_key='server.key', existing='preserve')
            atomic_json(cfg, original)
            atomic_json(profile_path, dict(version=1, role='files', trusted_management_keys=['a' * 64]))
            self.assertFalse(configure(cfg, profile_path)['applied'])
            self.assertEqual(parse(cfg.read_text()), original)
            configure(cfg, profile_path, apply=True)
            changed = parse(cfg.read_text())
            self.assertTrue(changed['protected_artifacts'])
            self.assertEqual(changed['existing'], original['existing'])
            original['trust']['endpoints']['files'] = 'http://127.0.0.1'
            atomic_json(cfg, original)
            with self.assertRaises(Error):
                configure(cfg, profile_path, apply=True)
            self.assertEqual(parse(cfg.read_text()), original)


class PortableFlowTests(unittest.TestCase):
    """Real shared Wasm agent, native per-user brokers and workload components.

    Only vendor evidence and Docker are replaced: an explicit constructor fixture
    selects confined in-process test stores. These tests are not TEE validation.
    """
    api = legacy.FleetTest.api
    publish = legacy.FleetTest.publish
    client = legacy.FleetTest.client
    job_body = legacy.FleetTest.job_body
    tearDown = legacy.FleetTest.tearDown

    @classmethod
    def setUpClass(cls):
        legacy.FleetTest.setUpClass()
        for file in ('hal-agent-runner', 'orchestration-agent.wasm'):
            if not (ROOT / 'dist' / file).exists():
                raise RuntimeError('Run .venv/bin/python build.py --install-target first')

    def setUp(self):
        legacy.FleetTest.setUp(self)
        self.management_key = Ed25519PrivateKey.generate()
        self.apps['execution'].close()
        config = self.apps['execution'].config
        config.update(execution_architecture=PROTOCOL, test_in_process=False, allow_non_tee=False,
            trusted_management_keys=[public(self.management_key)], platform='intel-tdx',
            runner=str(ROOT/'dist/hal-agent-runner'), runner_sha256=digest((ROOT/'dist/hal-agent-runner').read_bytes()))
        self.launched = []
        from hal_fleet.gvisor import profile as sandbox_profile
        sandbox = mock.patch('hal_fleet.gvisor.check', return_value={
            'profile': sandbox_profile(), 'configuration_checked': True, 'version': 'test fixture only'})
        sandbox.start()
        self.addCleanup(sandbox.stop)
        from hal_fleet.agent_runtime import SharedAgentRuntime
        def factory(configuration):
            runtime = SharedAgentRuntime(dict(configuration, test_in_process=True))
            self.launched.append(runtime)
            return runtime
        self.factory = factory
        self.execution = PortableExecution(config, self.apps['execution'].db, self.transport,
            runner_factory=factory, collector=self.collect, runtime_root=self.root)
        self.apps['execution'] = self.servers['execution'].app = self.execution
        self.apps['files'].config.update(protected_artifacts=True, trusted_management_keys=[public(self.management_key)])
        self.policy_path = self.root / 'policy.json'
        atomic_json(self.policy_path, policy())
        keyfile = self.root / 'management.json'
        atomic_json(keyfile, {'private_key': private_hex(self.management_key)})
        config = self.apps['management'].config
        config.update(execution_architecture=PROTOCOL, management_key=str(keyfile), attestation_policy=str(self.policy_path),
            managed_agent=str(ROOT/'dist/orchestration-agent.wasm'), managed_agent_sha256=digest((ROOT/'dist/orchestration-agent.wasm').read_bytes()))
        self.manager = PortableManagement(config, self.apps['management'].db, self.transport, allow_test_in_process=True)
        self.apps['management'] = self.servers['management'].app = self.manager
        self.alice.register()
        self.alice.approve(['hash-fixture'])
        self.verify_patch = mock.patch('hal_fleet.portable.verify_evidence', side_effect=self.verify_fixture)
        self.verify_patch.start()
        self.addCleanup(self.verify_patch.stop)

    def collect(self, report_data):
        return dict(platform='intel-tdx', report_hex=report_data)

    def verify_fixture(self, policy, evidence, binding):
        self.assertEqual(evidence['report_hex'], binding_hash(binding))
        return dict(verified=True, platform='fixture-not-hardware', evidence_sha256=digest(bytes.fromhex(evidence['report_hex'])),
                    policy_sha256='test-only', verified_unix=int(time.time()))

    def ready(self, name='alice'):
        client = self.alice if name == 'alice' else self.client(name)
        if name != 'alice':
            client.register()
            client.approve(['hash-fixture'])
        client.open_session()
        return client

    def run_job(self, client=None, cache='reuse'):
        result = (client or self.alice).job('hash-fixture', cache, 'wasm', 'in-process')
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result.get('client_result_validation'), 'passed', result)
        return result['response']['agent']

    def test_one_real_agent_two_user_brokers_cache_isolation_and_identity(self):
        alice = self.ready()
        first = self.run_job()
        hit = self.run_job()
        bob = self.ready('bob')
        bob_first = self.run_job(bob)
        self.assertEqual([first['cache_status'], hit['cache_status'], bob_first['cache_status']], ['miss', 'hit', 'miss'])
        self.assertEqual(first['agent_instance'], bob_first['agent_instance'])
        self.assertEqual(len(self.launched), 1)
        self.assertNotEqual(alice.session['epoch'], bob.session['epoch'])
        self.assertTrue(hit['agent_identity_verified'])
        self.assertEqual(self.run_job(cache='bypass')['cache_status'], 'bypass')
        self.assertEqual(self.run_job()['cache_status'], 'hit')
        from hal_fleet.attested_channel import CERT_DOMAIN
        from hal_fleet.common import verify
        cert = verify(public(self.management_key), CERT_DOMAIN, alice.session['agent_certificate'])
        self.assertEqual(cert['identity'], alice.session['agent_identity'])
        self.assertNotIn('private_key', canonical(cert))
        self.assertFalse(hit['workload_instance_reused'])

    def test_unknown_broker_outcome_stays_unknown_and_is_not_retried(self):
        self.ready()
        with mock.patch.object(self.manager, 'dispatch', return_value={
                'status': 'error', 'execution_outcome': 'unknown',
                'error': 'Broker connection lost; do not retry'}) as dispatch:
            result = self.alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        self.assertEqual(result['status'], 'unknown')
        self.assertNotIn('client_result_validation', result)
        dispatch.assert_called_once()
        recorded = self.alice.call('management', '/v1/result',
            self.alice.signed('management', 'result',
                {'document': self.alice.document, 'job_id': result['job_id']}))
        self.assertEqual(recorded['status'], 'unknown')

    def test_signed_audit_history_is_collected_and_visible_only_to_its_user(self):
        alice = self.ready()
        result = self.run_job()
        bob = self.ready('bob')
        other = self.run_job(bob)
        self.assertTrue(result['audit_collected'])
        self.assertIn('agent_result_proof', result)
        page = alice.audit(job_id=result['job_id'])
        self.assertTrue(page['record_signatures_verified'])
        self.assertEqual({item['event'] for item in page['records']},
            {'job_dispatch_requested', 'job_accepted', 'result_committed', 'job_acknowledged'})
        self.assertTrue(all(item['data']['tenant'] == 'alice' for item in page['records']))
        self.assertEqual(alice.audit(job_id=other['job_id'])['records'], [])
        self.assertEqual(bob.audit(job_id=result['job_id'])['records'], [])
        raw = canonical(page)
        for name in ('file_token', 'private_key', 'result_hex', 'input_bytes'):
            self.assertNotIn('"' + name + '"', raw)
        request = alice.signed('management', 'audit', {'document': bob.document})
        with self.assertRaisesRegex(Error, 'mismatch'):
            self.api('management', '/v1/audit', request)

    def test_audit_cli_verifies_history_without_launching_another_job(self):
        import subprocess
        self.ready(); result = self.run_job()
        before = self.manager.audit.head(result['audit']['vm_id'])
        command = [sys.executable, '-B', str(ROOT/'fleet.py'), 'audit', '--client', str(self.alice.path),
                   '--job-id', result['job_id'], '--limit', '10']
        output = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertTrue(parse(output.stdout)['record_signatures_verified'])
        self.assertEqual(self.manager.audit.head(result['audit']['vm_id']), before)

    def test_client_rejects_modified_audit_receipt(self):
        self.ready()
        call = self.alice.call
        def tamper(role, path, body=None):
            result = call(role, path, body)
            if path == '/v1/run':
                result['response']['agent']['audit']['hash'] = '0' * 64
            return result
        with mock.patch.object(self.alice, 'call', side_effect=tamper):
            result = self.alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['client_result_validation'], 'failed')

    def test_management_audit_failure_prevents_job_dispatch(self):
        self.ready()
        event = self.manager.audit.event
        def unavailable(name, data, **kwargs):
            if name == 'job_dispatch_requested':
                raise Error('audit full', 503, 'audit_unavailable')
            return event(name, data, **kwargs)
        with mock.patch.object(self.manager.audit, 'event', side_effect=unavailable), \
             mock.patch.object(self.manager, 'call_channel', wraps=self.manager.call_channel) as calls:
            row = self.alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        self.assertNotEqual(row['status'], 'completed')
        self.assertFalse(any(c.args[1] == 'run' for c in calls.call_args_list))

    def test_collection_failure_after_execution_is_unknown_and_recovers_without_rerun(self):
        self.ready()
        ingest = self.manager.audit.ingest
        def fail_completion(vm_id, page):
            if any(parse(r['payload'])['event'] == 'result_committed' for r in page['records']):
                raise Error('collector disk full', 503, 'audit_unavailable')
            return ingest(vm_id, page)
        with mock.patch.object(self.manager.audit, 'ingest', side_effect=fail_completion), \
             mock.patch.object(self.manager, 'call_channel', wraps=self.manager.call_channel) as calls:
            row = self.alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        self.assertEqual(row['status'], 'unknown')
        self.assertEqual(row['error_code'], 'outcome_unknown')
        self.assertEqual(sum(c.args[1] == 'run' for c in calls.call_args_list), 1)
        self.manager.collect_audit(self.manager.sessions['alice']['channel'])
        page = self.alice.audit(job_id=row['job_id'])
        self.assertTrue(any(item['event'] == 'result_committed' and item['data']['outcome'] == 'completed'
                            for item in page['records']))

    def test_native_journal_failure_blocks_admission(self):
        self.ready()
        config = parse((self.launched[-1].root/'runtime.json').read_text())
        path = Path(config['audit_path'])
        before = path.read_bytes()
        with path.open('ab') as output:
            output.write(b'partial-corruption')
        row = self.alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        self.assertNotEqual(row['status'], 'completed')
        self.assertEqual(path.read_bytes(), before + b'partial-corruption')
        # No successful acceptance or completion was persisted for this job.
        self.assertNotIn(row['job_id'].encode(), path.read_bytes())

    def test_audit_continues_across_agent_restart_and_rejects_rollback(self):
        self.ready(); first = self.run_job()
        config = parse((self.launched[-1].root/'runtime.json').read_text())
        path = Path(config['audit_path'])
        self.execution.runtime.close()
        self.manager.sessions.clear(); self.manager.channels.clear()
        self.alice.open_session(); second = self.run_job()
        self.assertNotEqual(first['agent_instance'], second['agent_instance'])
        self.assertGreater(second['audit']['sequence'], first['audit']['sequence'])
        self.execution.runtime.close()
        path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
        self.manager.sessions.clear(); self.manager.channels.clear()
        grants = len(self.apps['files'].db.all('file-access'))
        with self.assertRaises(Error):
            self.alice.open_session()
        self.assertEqual(len(self.apps['files'].db.all('file-access')), grants)

    def test_pre_agent_rejections_are_recorded_without_claiming_a_user(self):
        with self.assertRaises(Error):
            self.api('execution', '/v2/agent/run', {})
        rows = self.execution.db.connection.execute('SELECT operation,reason FROM audit_gateway').fetchall()
        self.assertTrue(rows)
        self.assertEqual(rows[-1][0], '/v2/agent/run')

    def test_failed_attestation_releases_no_agent_or_credentials(self):
        with mock.patch('hal_fleet.portable.verify_evidence', side_effect=Error('rejected', 403)):
            with self.assertRaises(Error):
                self.alice.open_session()
        self.assertEqual(self.apps['files'].db.all('file-access'), [])
        self.assertEqual(self.launched, [])

    def test_agent_permissions_enforced_at_native_import(self):
        self.manager.config['agent_configuration'] = {'agent_permissions':['workload.policy', 'workload.launch', 'result.commit', 'identity.sign']}
        with self.assertRaisesRegex(Error, 'broker.launch'):
            self.alice.open_session()
        self.assertEqual(list(self.launched[0].root.glob('user-*')), [])

    def test_missing_hal_capability_prevents_deployment(self):
        with mock.patch.object(self.execution, 'capabilities', return_value={'interface': ABI, 'single_agent': False}):
            with self.assertRaises(Error):
                self.alice.open_session()
        self.assertEqual(self.launched, [])
        self.assertEqual(self.apps['files'].db.all('file-access'), [])

    def test_missing_gvisor_blocks_credentials_and_agent_deployment(self):
        with mock.patch.object(self.execution, 'sandbox_checker', side_effect=ValueError('runsc missing')):
            with self.assertRaisesRegex(Error, 'gVisor sandbox unavailable'):
                self.alice.open_session()
        self.assertEqual(self.launched, [])
        self.assertEqual(self.apps['files'].db.all('file-access'), [])

    def test_management_rejects_weaker_sandbox_manifest(self):
        capabilities = self.execution.capabilities()
        capabilities['workload_sandbox']['scope'] = 'vm'
        with mock.patch.object(self.execution, 'capabilities', return_value=capabilities):
            with self.assertRaisesRegex(Error, 'gVisor per-user'):
                self.alice.open_session()
        self.assertEqual(self.launched, [])
        self.assertEqual(self.apps['files'].db.all('file-access'), [])

    def test_owner_survives_service_restart_and_lease_expiry(self):
        identity = self.ready().session['agent_identity']
        other = Ed25519PrivateKey.generate()
        cfg = self.execution.config
        cfg['trusted_management_keys'].append(public(other))
        self.execution.close()
        self.execution = PortableExecution(cfg, self.apps['execution'].db, self.transport,
            runner_factory=self.factory, collector=self.collect, runtime_root=self.root)
        self.apps['execution'] = self.servers['execution'].app = self.execution
        payload = request(other, self.trust['execution_audience'], 'agent-challenge', 'management', {})
        with self.assertRaisesRegex(Error, 'another management'):
            self.api('execution', '/v2/agent/challenge', payload)
        renewed = self.alice.open_session()
        self.assertEqual(len(self.launched), 2)
        self.assertNotEqual(renewed['agent_identity']['instance'], identity['instance'])
        self.assertEqual(renewed['agent_identity']['vm_id'], identity['vm_id'])
        self.run_job()

    def test_live_agent_cannot_be_replaced_by_another_configuration(self):
        self.ready()
        self.manager.channels.clear()
        self.manager.sessions.clear()
        self.manager.config['agent_configuration'] = {'agent_permissions': ['identity.sign']}
        with self.assertRaisesRegex(Error, 'already deployed'):
            self.alice.open_session()
        self.assertEqual(len(self.launched), 1)

    def test_second_gateway_and_second_native_runner_rejected(self):
        self.ready()
        with self.assertRaises(BlockingIOError):
            PortableExecution(self.execution.config, self.execution.db, self.transport,
                runner_factory=self.factory, collector=self.collect, runtime_root=self.root)
        import subprocess
        runtime = self.launched[0]
        duplicate = subprocess.run([str(ROOT/'dist/hal-agent-runner'), '--orchestrator-config', str(runtime.root/'runtime.json')],
                                   capture_output=True, timeout=10)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn(b'already owns', duplicate.stderr)

    def test_re_attestation_reuses_agent_and_its_identity(self):
        session = self.ready().session
        self.manager.channels[next(iter(self.manager.channels))]['deadline'] = 0
        self.manager.sessions.clear()
        renewed = self.alice.open_session()
        self.assertEqual(session['agent_identity'], renewed['agent_identity'])
        self.assertEqual(len(self.launched), 1)
        self.run_job()

    def test_session_renews_near_expiry_but_reuses_a_healthy_session(self):
        self.ready()
        self.run_job()
        original = copy.deepcopy(self.alice.session)
        with mock.patch.object(self.manager, 'connect', wraps=self.manager.connect) as connected:
            unchanged = self.alice.open_session()
        self.assertEqual(unchanged['epoch'], original['epoch'])
        self.assertEqual(self.run_job()['cache_status'], 'hit')
        self.assertTrue(connected.called)
        old = self.manager.sessions['alice']
        old['expires'] = int(time.time()) + 20
        old['session']['expires_unix'] = old['expires']
        old['channel']['deadline'] = time.monotonic() + 20
        with mock.patch('hal_fleet.portable.verify_evidence', side_effect=self.verify_fixture) as verifier:
            renewed = self.alice.open_session()
        verifier.assert_called_once()
        self.assertGreater(renewed['expires_unix'] - time.time(), 180)
        self.assertEqual(renewed['agent_identity'], original['agent_identity'])
        self.assertNotEqual(renewed['epoch'], original['epoch'])
        self.assertEqual(len(self.launched), 1)
        self.assertEqual(self.run_job()['cache_status'], 'miss')

    def test_three_hour_session_covers_enrollment_files_channel_and_agent_certificate(self):
        for requirements in self.manager.policies.values():
            requirements['lease_seconds'] = 10800
        before = int(time.time())
        session = self.ready().session
        doc = parse(self.alice.document['payload'])
        self.assertEqual(doc['expires_unix'] - doc['issued_unix'], 10800)
        self.assertGreater(session['expires_unix'], before + 10740)
        self.assertLessEqual(session['expires_unix'], int(time.time()) + 10800)
        cert = parse(session['agent_certificate']['payload'])
        self.assertGreater(cert['expires_unix'], before + 10740)
        self.assertLessEqual(cert['expires_unix'] - cert['issued_unix'], 10800)
        channel = self.manager.sessions['alice']['channel']
        self.assertEqual(channel['binding']['lease_seconds'], 10800)
        self.assertGreater(self.execution.channels[channel['binding']['deployment_id']]['expires'], before + 10740)
        grants = self.apps['files'].db.all('file-access')
        self.assertTrue(grants)
        self.assertTrue(all(grant['expires_unix'] > before + 10740 for grant in grants))
        self.run_job()

        # Advance only the Python control-plane clock. This checks that opening
        # a new session after five minutes reuses the same attested channel and
        # user broker, without waiting or changing the Rust execution clock.
        later = mock.Mock(wraps=time)
        later.time.side_effect = lambda: time.time() + 360
        later.monotonic.side_effect = lambda: time.monotonic() + 360
        with mock.patch('hal_fleet.portable.time', later), \
                mock.patch('hal_fleet.portable.verify_evidence') as verifier:
            renewed = self.alice.open_session()
            self.run_job()
        verifier.assert_not_called()
        self.assertEqual(renewed['epoch'], session['epoch'])
        self.assertEqual(renewed['agent_identity'], session['agent_identity'])

    def test_session_credentials_longer_than_three_hours_are_rejected(self):
        from hal_fleet.attested_channel import CERT_DOMAIN, validate_requirements
        from hal_fleet.common import DOCUMENT_DOMAIN, sign
        from hal_fleet.policy import certificate
        with self.assertRaisesRegex(Error, 'Lease'):
            validate_requirements(dict(policy(), lease_seconds=10801))
        data = dict(challenge='a' * 64, agent_sha256=digest(self.manager.agent),
                    configuration_sha256=digest(b'{}'), interface=ABI, lease_seconds=10801)
        with self.assertRaisesRegex(Error, 'Invalid lease'):
            self.api('execution', '/v2/agent/challenge', self.manager.signed_execution('agent-challenge', data))
        with self.assertRaisesRegex(Error, 'file access scope'):
            self.api('files', '/v2/access', request(self.management_key,
                self.trust['files_audience'], 'agent-file-access', 'alice',
                dict(artifacts=[self.workload['sha256']], ttl_seconds=10801)))
        self.ready()
        doc = parse(self.alice.document['payload'])
        doc['expires_unix'] = doc['issued_unix'] + 10801
        with self.assertRaisesRegex(Error, 'Enrollment document expired'):
            certificate(sign(self.issuer, DOCUMENT_DOMAIN, doc), self.alice.config)
        channel = self.manager.sessions['alice']['channel']
        now = int(time.time())
        too_long = sign(self.management_key, CERT_DOMAIN,
            dict(version=1, kind='agent-identity', identity=channel['identity'],
                 issued_unix=now, expires_unix=now + 10801))
        with self.assertRaisesRegex(Error, 'certificate lifetime invalid'):
            self.manager.call_channel(channel, 'activate', certificate=too_long, challenge='test-limit')
        self.run_job()  # Rejection must leave the previous certificate usable.

    def test_renewal_cannot_extend_policy_or_bypass_failed_attestation(self):
        self.ready()
        old = self.manager.sessions['alice']
        old['expires'] = int(time.time()) + 20
        old['channel']['deadline'] = time.monotonic() + 20
        with mock.patch('hal_fleet.portable.verify_evidence', side_effect=Error('appraisal rejected')), \
                mock.patch.object(self.manager, 'dispatch') as dispatch:
            with self.assertRaisesRegex(Error, 'appraisal rejected'):
                self.alice.open_session()
        dispatch.assert_not_called()
        for target in self.manager.targets:
            self.manager.policies[target['url']]['lease_seconds'] = 120
        with self.assertRaisesRegex(Error, 'lease is too short'):
            self.alice.open_session()

    def test_benchmark_refreshes_session_and_records_new_cache_misses(self):
        from hal_fleet.client import benchmark
        job = self.alice.job
        finished = []
        def execute(*args, **kwargs):
            row = job(*args, **kwargs)
            finished.append(row)
            if len(finished) == 2:
                # Simulate a long batch reaching the renewal reserve. The actual
                # Rust agent and signed audit records still use the real clock.
                expires = int(time.time()) + 20
                self.alice.session['expires_unix'] = expires
                old = self.manager.sessions['alice']
                old['expires'] = old['session']['expires_unix'] = expires
                old['channel']['deadline'] = time.monotonic() + 20
            return row
        folder = self.root / 'session-bench'
        from hal_fleet.benchmark_guard import BenchmarkGate
        self.servers['management'].app = BenchmarkGate(self.manager)
        with mock.patch.object(self.alice, 'job', side_effect=execute):
            result = benchmark(self.alice, ['hash-fixture'], 4, 1, 'reuse', folder, 'wasm', 'in-process')
        self.assertEqual(result['completed'], 4)
        self.assertEqual(result['not_submitted'], 0)
        self.assertEqual(result['session_refresh_count'], 1)
        self.assertEqual(result['cache_status_counts'], {'miss': 2, 'hit': 2})
        config = parse((folder / 'config.json').read_text())
        self.assertEqual(config['session_refreshes'][0]['after_submitted'], 2)
        records = [parse(line) for line in (folder / 'jobs.jsonl').read_text().splitlines()]
        self.assertEqual([r['session_generation'] for r in records], [0, 0, 1, 1])
        self.assertEqual(len({r['job_id'] for r in records}), 4)

    def test_client_will_not_send_a_job_with_a_near_expired_session(self):
        self.ready()
        self.alice.session['expires_unix'] = int(time.time()) + 20
        with mock.patch.object(self.alice, 'call') as call:
            with self.assertRaisesRegex(Error, 'No job was submitted'):
                self.alice.job('hash-fixture', 'reuse', 'wasm', 'in-process')
        call.assert_not_called()

    def test_wrong_certificate_cannot_activate_identity(self):
        self.ready()
        from hal_fleet.common import sign
        from hal_fleet.attested_channel import CERT_DOMAIN
        channel = next(iter(self.manager.channels.values()))
        forged = sign(Ed25519PrivateKey.generate(), CERT_DOMAIN,
            dict(version=1, kind='agent-identity', identity=channel['identity'], issued_unix=int(time.time()), expires_unix=int(time.time())+100))
        with self.assertRaises(Error):
            self.manager.call_channel(channel, 'activate', certificate=forged, challenge='fresh')
        self.run_job()

    def test_policy_tampering_unsigned_jobs_and_replay_rejected(self):
        self.ready()
        payload = self.job_body(self.alice)
        channel = self.manager.sessions['alice']['channel']
        command = dict(tenant='alice', revision=self.alice.session['revision'], job=payload['job'], policy=self.workload['rule'])
        wrong = copy.deepcopy(command)
        wrong['policy']['hal_permissions'] = ['storage', 'crypto']
        with self.assertRaisesRegex(Error, 'policy'):
            self.manager.call_channel(channel, 'run', request=wrong)
        wrong = copy.deepcopy(command)
        wrong['job']['job_ticket']['signature'] = '0'*128
        with self.assertRaises(Error):
            self.manager.call_channel(channel, 'run', request=wrong)
        first = self.manager.call_channel(channel, 'run', request=command)
        self.assertEqual(self.manager.proof(channel, first, 'result', payload['job']['job_id'])['status'], 'ok')
        repeated = self.manager.call_channel(channel, 'run', request=command)
        self.assertEqual(self.manager.proof(channel, repeated, 'result', payload['job']['job_id'])['status'], 'error')

    def test_mandatory_policy_update_denies_crypto_after_prior_cache_hit(self):
        self.ready()
        self.run_job()
        self.assertEqual(self.run_job()['cache_status'], 'hit')
        ch = self.manager.sessions['alice']['channel']
        doc = parse(self.alice.document['payload'])
        doc['revision'] += 1
        doc['workloads'][0]['rule']['hal_permissions'] = []
        # A trusted-management grant updates the user; it is never a job-supplied policy.
        token = next(self.launched[0].root.glob('user-*/file.token')).read_text()
        grant = dict(document=doc, file_server=self.trust['endpoints']['files']+'/artifacts/',
                     file_token=token, expires_unix=int(time.time())+100)
        self.alice.session = self.manager.call_channel(ch, 'enroll', grant=grant)
        self.workload = doc['workloads'][0]
        payload = self.job_body(self.alice, 'reuse')
        result = self.manager.call_channel(ch, 'run', request=dict(tenant='alice', revision=doc['revision'],
            job=payload['job'], policy=self.workload['rule']))
        result = self.manager.proof(ch, result, 'result', payload['job']['job_id'])
        self.assertEqual(result['status'], 'error', result)
        # The fixture unwraps the denied HAL call and traps; no output may commit.
        self.assertNotEqual(result.get('result', {}).get('hex'), self.workload['rule']['validation']['value'])

    def install_access_profile(self, client, template, max_host_calls=1):
        from hal_fleet.access_profiles import create
        ch = self.manager.sessions[client.config['user']]['channel']
        doc = parse(client.document['payload'])
        doc['revision'] += 1
        row = doc['workloads'][0]
        row['rule']['access_profile'] = create(row['sha256'], row['rule']['hal_permissions'], template,
                                              max_host_calls=max_host_calls)
        broker_dir = next(path.parent for path in self.launched[0].root.glob('user-*/tenant.json')
                          if parse(path.read_text())['tenants'][0]['id'] == client.config['user'])
        token = (broker_dir/'file.token').read_text()
        grant = dict(document=doc, file_server=self.trust['endpoints']['files']+'/artifacts/',
                     file_token=token, expires_unix=int(time.time())+100)
        client.session = self.manager.call_channel(ch, 'enroll', grant=grant)
        self.workload = row
        return ch, doc

    def profiled_job(self, client, channel, doc, cache):
        payload = self.job_body(client, cache)
        command = dict(tenant=client.config['user'], revision=doc['revision'], job=payload['job'],
                       policy=self.workload['rule'])
        result = self.manager.call_channel(channel, 'run', request=command)
        return self.manager.proof(channel, result, 'result', payload['job']['job_id'])

    def test_agent_keeps_profile_bound_on_bypass_miss_hit_and_rejects_changes(self):
        self.ready()
        channel, doc = self.install_access_profile(self.alice, 'sha256')
        for cache, expected in [('bypass','bypass'), ('reuse','miss'), ('reuse','hit')]:
            result = self.profiled_job(self.alice, channel, doc, cache)
            self.assertEqual(result['status'], 'ok', result)
            self.assertEqual(result['cache_status'], expected)
            report = result['workload_access_profile']
            self.assertTrue(report['enforced'])
            self.assertEqual(report['operations'], ['crypto.hash.sha256'])
            self.assertEqual(report['host_call_attempts'], 1)
            self.assertFalse(result['workload_instance_reused'])
        for tamper in ('remove', 'widen'):
            body = self.job_body(self.alice, 'reuse')
            policy = copy.deepcopy(self.workload['rule'])
            if tamper == 'remove':
                del policy['access_profile']
            else:
                policy['access_profile']['operations'].append('crypto.sign')
            with self.assertRaises(Error):
                self.manager.call_channel(channel, 'run', request=dict(tenant='alice', revision=doc['revision'],
                    job=body['job'], policy=policy))

    def test_one_agent_different_user_profiles_do_not_share_permissions(self):
        alice, bob = self.ready(), self.ready('bob')
        self.run_job(alice)
        self.assertEqual(self.run_job(alice)['cache_status'], 'hit')
        channel, doc = self.install_access_profile(bob, 'compute')
        # Hash is still in Bob's broader category grant, but his profile denies it.
        for cache in ('bypass', 'reuse', 'reuse'):
            result = self.profiled_job(bob, channel, doc, cache)
            self.assertEqual(result['status'], 'error', result)
            self.assertEqual(result['workload_access_profile']['denied_calls'], 1)
        self.assertEqual(self.run_job(alice)['cache_status'], 'hit')
        self.assertEqual(len(self.launched), 1)

    def test_fifteen_workloads_use_one_compute_template_with_cache_hits(self):
        from hal_fleet.access_profiles import create
        rows = parse((ROOT/'benchmarks/artifacts/manifest.json').read_text())['workloads']
        self.assertEqual(len(rows), 15)
        for row in rows:
            row['rule']['access_profile'] = create(row['sha256'], row['rule']['hal_permissions'], 'compute')
        self.publish(rows, [(ROOT/'benchmarks/artifacts'/row['component']).read_bytes() for row in rows])
        client = self.client('compute-user')
        client.register()
        client.approve([row['name'] for row in rows])
        client.open_session()
        for row in rows:
            for expected in ('miss', 'hit'):
                with self.subTest(workload=row['name'], cache=expected):
                    result = client.job(row['name'], 'reuse', 'wasm', 'in-process')
                    self.assertEqual(result['status'], 'completed', result)
                    agent = result['response']['agent']
                    self.assertEqual(agent['result']['hex'], row['rule']['validation']['value'])
                    self.assertEqual(agent['cache_status'], expected)
                    self.assertTrue(agent['workload_access_profile']['enforced'])
                    self.assertEqual(agent['workload_access_profile']['operations'], [])

    def test_concurrent_users_share_agent_and_preserve_results(self):
        from concurrent.futures import ThreadPoolExecutor
        alice, bob = self.ready(), self.ready('bob')
        with ThreadPoolExecutor(max_workers=4) as pool:
            rows = list(pool.map(lambda c: self.run_job(c), [alice, bob]*4))
        self.assertEqual(len({r['agent_instance'] for r in rows}), 1)
        self.assertEqual({r['tenant'] for r in rows}, {'alice', 'bob'})

    def test_expired_channel_and_modified_ciphertext_rejected(self):
        self.ready()
        ch = self.manager.sessions['alice']['channel']
        encrypted = seal(ch['key'], ch['binding'], 'status', {'challenge':'fresh'})
        encrypted['ciphertext'] = encode(decode(encrypted['ciphertext'])[:-1] + b'!')
        with self.assertRaises(Error):
            self.api('execution', '/v2/agent/status', dict(deployment_id=ch['binding']['deployment_id'], sealed=encrypted))
        self.execution.channels[ch['binding']['deployment_id']]['expires'] = 0
        with self.assertRaises(Error):
            self.manager.call_channel(ch, 'status', challenge='fresh')

    def test_new_agent_world_required_and_old_workload_cannot_be_agent(self):
        self.manager.agent = self.fixture
        with self.assertRaises(Error):
            self.alice.open_session()
        self.assertEqual(self.launched, [])
        self.assertEqual(self.execution.channels, {})

    def test_client_refuses_legacy_downgrade(self):
        self.ready()
        self.servers['management'].app = legacy.Management(self.manager.config, self.manager.db, self.transport)
        with self.assertRaises(Error):
            self.alice.open_session()

    def test_management_can_choose_another_verified_vm_before_dispatch(self):
        unavailable = dict(url='http://127.0.0.1:1', attestation_policy=str(self.policy_path))
        self.manager.targets.insert(0, unavailable)
        self.manager.policies[unavailable['url']] = policy()
        session = self.ready().session
        self.assertEqual(session['execution_url'], self.trust['endpoints']['execution'])
        self.run_job()

if __name__ == '__main__':
    unittest.main(verbosity=2)
