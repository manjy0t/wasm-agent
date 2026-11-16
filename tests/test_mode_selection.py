"""Offline mode control: real signatures, native audit and durable databases.

Agent runtime/attestation and native processes are fixtures; no TEE, socket,
container or real process shutdown is claimed by these tests.
"""
import copy
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_native_audit as fixture
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hal_fleet.audit import AuditStore
from hal_fleet.benchmark_guard import BenchmarkGate, Experiment, verify_batch
from hal_fleet.benchmark_state import bind_state
from hal_fleet.client import benchmark
from hal_fleet.common import (Database, Error, atomic_json, digest, private_hex,
                              public, read_private, request, require)
from hal_fleet.lifecycle import ManagementLifecycle
from hal_fleet.mode_selection import (ARCHITECTURES, PROTOCOL, Backend, configure,
                                     SelectableExecution, SelectableManagement)
from hal_fleet.native_audit import NativeExecution, NativeManagement


class AgentExecutionFixture:
    def __init__(self, test, db):
        self.test, self.db, self.runtime = test, db, None

    def handle(self, method, path, body):
        if path == '/v1/capabilities':
            return dict(execution_architecture=ARCHITECTURES['agent'])
        raise Error('Fixture does not implement agent workload execution', 404)

    def close(self):
        require(self.runtime is None, 'Agent must be retired before backend close')


class AgentManagementFixture(ManagementLifecycle):
    def __init__(self, test, db):
        self.test, self.db, self.key = test, db, test.owner
        self.config = dict(test.configs['management'], execution_architecture=ARCHITECTURES['agent'])
        self.audit = AuditStore(db, self.key)
        self.targets = [dict(url=test.trust['endpoints']['execution'])]
        self.channels, self.sessions, self.session_lock = {}, {}, threading.RLock()
        self.init_lifecycle()

    def connect(self, target, maintenance=False):
        self.test.events.append('agent.verify')
        require(self.test.attestation_ok, 'Attestation verification failed', 403)
        self.test.events.append('agent.deploy')
        self.test.apps['execution'].app.runtime = object()
        return dict(identity=dict(vm_id='a'*64, instance=secrets.token_hex(32)))

    def execution_control(self, url, action, body):
        self.test.events.append('agent.' + action)
        require(action == 'resume', 'Unexpected fixture lifecycle operation')

    def undeploy_agent(self, target, seconds):
        # The native/agent drain protocol itself is covered by test_agent_lifecycle.
        self.test.events.extend(['agent.drain', 'agent.collect', 'agent.retire'])
        self.test.apps['execution'].app.runtime = None
        return self.save_target(target['url'], dict(state='undeployed', operation_id='d'*64))

    def handle(self, method, path, body):
        if path == '/v1/capabilities':
            return dict(execution_architecture=ARCHITECTURES['agent'])
        raise Error('Fixture does not implement agent workload execution', 404)


class ModeTest(unittest.TestCase):
    new_client = fixture.NativeAuditTest.new_client

    def setUp(self):
        fixture.NativeAuditTest.setUp(self)
        self.owner = Ed25519PrivateKey.generate()
        self.owner_path = self.root/'owner.json'
        atomic_json(self.owner_path, dict(private_key=private_hex(self.owner)))
        self.events, self.attestation_ok, self.open_failures = [], True, set()
        self.broker_factory = self.apps['execution'].factory
        original_transport = self.transport
        test = self

        class Route:
            drop_select_ack = False

            def call(self, base, path, body=None, token=None, **kwargs):
                if base in test.brokers and path == '/v1/stats':
                    test.assertEqual(token, 'operator-fixture')
                    return dict(requests_inflight=test.host_inflight)
                result = original_transport.call(base, path, body, token, **kwargs)
                if path == '/v2/execution-mode/select' and self.drop_select_ack:
                    self.drop_select_ack = False
                    raise Error('Lost mode acknowledgement', 503)
                return result

            def close(self):
                pass

        self.transport = Route()
        self.client.transport = self.transport
        self.host_inflight = 0
        self.agent_dbs, self.mode_dbs, self.mode_configs = {}, {}, {}
        for role in ('management', 'execution'):
            for mapping, label in ((self.agent_dbs, 'agent'), (self.mode_dbs, 'selector')):
                mapping[role] = Database(self.root/(label+'-'+role+'.sqlite3'))
                self.addCleanup(mapping[role].close)
            self.mode_configs[role] = dict(self.configs[role], execution_architecture=PROTOCOL,
                mode_control_key=str(self.owner_path), mode_control_public_key=public(self.owner))

        def factory(config, mode, transport):
            role = config['role']
            if (role, mode) in self.open_failures:
                self.open_failures.remove((role, mode))
                raise Error('Injected backend-open failure', 503)
            self.events.append(role + '.open.' + mode)
            if mode == 'agent':
                klass = AgentExecutionFixture if role == 'execution' else AgentManagementFixture
                app = klass(self, self.agent_dbs[role])
            elif role == 'execution':
                app = NativeExecution(self.configs[role], self.dbs[role], transport, self.broker_factory)
            else:
                app = NativeManagement(self.configs[role], self.dbs[role], transport)
            if role == 'management':
                app = BenchmarkGate(app)
            class Handle:
                def close(handle):
                    self.events.append(role + '.close.' + mode)
                    close = getattr(handle.app, 'close', None)
                    if close:
                        close()
            handle = Handle()
            handle.app = app
            return handle

        self.factory = factory
        self.apps['execution'] = SelectableExecution(self.mode_configs['execution'], self.mode_dbs['execution'], self.transport, factory)
        self.apps['management'] = SelectableManagement(self.mode_configs['management'], self.mode_dbs['management'], self.transport, factory)
        def cleanup():
            execution = self.apps['execution']
            if execution.backend and execution.state()['mode'] == 'agent':
                execution.app.runtime = None  # Fixture cleanup, never a deployment operation.
            self.apps['management'].close()
            execution.close()
        self.addCleanup(cleanup)

    def control(self, mode=None, seconds=0, key=None):
        action = 'select' if mode else 'status'
        body = dict(mode=mode, drain_seconds=seconds) if mode else {}
        return self.apps['management'].handle('POST', '/v1/mode/'+action,
            request(key or self.owner, self.trust['management_audience'], 'mode-'+action, 'management', body))

    def prepare_broker_exit(self, *, timeout=False, code=0):
        for broker in self.apps['execution'].app.brokers.values():
            broker.root = self.root/('process-'+broker.epoch)
            broker.root.mkdir()
            (broker.root/'operator.token').write_text('operator-fixture')
            broker.process = Mock(pid=12345)
            broker.process.poll.return_value = None
            def wait(timeout=None, broker=broker):
                broker.process.poll.return_value = code
                return code
            broker.process.wait.side_effect = subprocess.TimeoutExpired('fixture', 20) if timeout else wait

    def test_initial_state_blocks_jobs_until_explicit_selection(self):
        state = self.control()
        self.assertEqual(state['management']['phase'], 'inactive')
        for app in self.apps['management'], self.apps['execution']:
            with self.assertRaisesRegex(Error, 'not ready'):
                app.handle('POST', '/v1/run', {})
        self.assertNotIn('agent.deploy', self.events)

    def test_agent_activation_uses_existing_deployment_verification_order(self):
        selected = self.control('agent')
        self.assertTrue(selected['activation_attestation_verified'])
        self.assertEqual(self.events[-2:], ['agent.verify', 'agent.deploy'])
        previous = list(self.events)
        self.assertTrue(self.control('agent')['already_selected'])
        self.assertEqual(self.events, previous)

    def test_round_trip_keeps_separate_audit_stores_and_reverifies_agent(self):
        first = self.control('agent')
        native = self.control('native')
        self.assertFalse(native['activation_attestation_verified'])
        for before, after in (('agent.drain','agent.collect'), ('agent.collect','agent.retire'),
                              ('agent.retire','execution.open.native')):
            self.assertLess(self.events.index(before), self.events.index(after))
        self.client.open_session()
        row = self.client.job('fixture', 'bypass', 'native', 'in-process')
        self.assertEqual(row['status'], 'completed', row)
        self.assertEqual(row['mode_selection']['generation'], native['generation'])
        checkpoint = row['response']['agent']['audit']
        native_manager = self.apps['management'].app.app
        self.prepare_broker_exit()
        with patch('hal_fleet.mode_selection.os.killpg') as kill:
            selected = self.control('agent')
        kill.assert_called_once_with(12345, signal.SIGTERM)
        self.assertNotEqual(selected['generation'], first['generation'])
        self.assertTrue(native_manager.audit.contains(checkpoint))
        self.assertEqual(self.events.count('agent.verify'), 2)
        self.assertEqual(self.agent_dbs['management'].connection.execute(
            "SELECT count(*) FROM audit_records WHERE stream=?", (native_manager.identity['vm_id'],)).fetchone()[0], 0)
        with self.assertRaises(Error):
            self.apps['execution'].handle('POST', '/v2/native/run', {})

    def test_owner_only_and_replay_protection_survive_mode_change(self):
        for key in (self.manager_key, self.client.key, Ed25519PrivateKey.generate()):
            with self.assertRaisesRegex(Error, 'Only the owning'):
                self.control('native', key=key)
        envelope = request(self.owner, self.trust['management_audience'], 'mode-select', 'management', dict(mode='native', drain_seconds=0))
        self.apps['management'].handle('POST', '/v1/mode/select', envelope)
        with self.assertRaisesRegex(Error, 'already used'):
            self.apps['management'].handle('POST', '/v1/mode/select', envelope)
        with self.assertRaisesRegex(Error, 'Only the owning'):
            self.apps['execution'].handle('POST', '/v2/execution-mode/status', request(self.manager_key,
                self.trust['execution_audience'], 'vm-mode-status', 'management', {}))

    def test_benchmark_blocks_switch_without_changing_admission(self):
        self.control('native')
        folder = self.root/'experiment'; folder.mkdir()
        manager = self.apps['management']
        before = manager.state()
        with Experiment(self.client, ['fixture'], 'native', 'in-process', folder):
            with self.assertRaisesRegex(Error, 'benchmark'):
                self.control('agent')
            self.assertEqual(manager.state(), before)
            self.client.open_session()
            self.assertEqual(self.client.job('fixture', 'bypass', 'native', 'in-process')['status'], 'completed')
        self.assertIsNone(manager.app.lease())

    def test_concurrent_lease_acquisition_cannot_be_overtaken_by_switch(self):
        self.control('native')
        manager, entered, release = self.apps['management'], threading.Event(), threading.Event()
        experiment_id = str(uuid.uuid4())
        original = manager.app.control
        def acquire(body):
            entered.set()
            require(release.wait(3), 'Test lease did not resume')
            return original(body)
        body = self.client.signed('management', 'benchmark',
            dict(document=self.client.document, action='acquire', experiment_id=experiment_id))
        with patch.object(manager.app, 'control', side_effect=acquire), ThreadPoolExecutor(max_workers=2) as pool:
            lease = pool.submit(manager.handle, 'POST', '/v1/benchmark', body)
            self.assertTrue(entered.wait(3))
            switch = pool.submit(self.control, 'agent')
            release.set()
            self.assertEqual(lease.result(timeout=3)['experiment_id'], experiment_id)
            with self.assertRaisesRegex(Error, 'benchmark'):
                switch.result(timeout=3)
        self.assertEqual(manager.state()['phase'], 'ready')
        manager.handle('POST', '/v1/benchmark', self.client.signed('management', 'benchmark',
            dict(document=self.client.document, action='release', experiment_id=experiment_id)))

    def test_mode_generation_is_pinned_in_new_benchmark_evidence(self):
        selected = self.control('native')
        folder = self.root/'batch'
        summary = benchmark(self.client, ['fixture'], 2, 1, 'bypass', folder, 'native', 'in-process')
        self.assertTrue(summary['valid_for_comparison'])
        config = read_private(folder/'config.json')
        self.assertEqual(config['fingerprint']['mode_selection']['generation'], selected['generation'])
        self.assertTrue(verify_batch(folder)['verified'])
        with self.assertRaisesRegex(Error, 'forbids cache reuse'):
            benchmark(self.client, ['fixture'], 2, 1, 'reuse', self.root/'bad-cache', 'native', 'in-process')

    def test_changed_mode_generation_is_rejected_even_if_other_profile_fields_match(self):
        self.control('native')
        folder = self.root/'generation'; folder.mkdir()
        with Experiment(self.client, ['fixture'], 'native', 'in-process', folder) as run:
            session = self.client.open_session()
            run.session(session)
            changed = copy.deepcopy(session)
            changed['mode_selection']['generation'] = 'f'*64
            with self.assertRaisesRegex(Error, 'changed'):
                run.session(changed)
            row = self.client.job('fixture', 'bypass', 'native', 'in-process')
            row['mode_selection']['generation'] = 'f'*64
            with self.assertRaisesRegex(Error, 'mode changed'):
                run.check_row(row, 'bypass')

    def test_inflight_timeout_blocks_new_jobs_and_can_resume(self):
        self.control('native')
        manager = self.apps['management']
        manager.active = 1
        try:
            with self.assertRaisesRegex(Error, 'still running'):
                self.control('agent')
            with self.assertRaisesRegex(Error, 'not ready'):
                manager.handle('POST', '/v1/run', {})
            with self.assertRaisesRegex(Error, 'pending mode'):
                self.control('native')
        finally:
            manager.active = 0
        self.assertEqual(self.control('agent')['phase'], 'ready')

    def test_missing_final_audit_blocks_switch_and_retry_collects_it(self):
        self.control('native')
        manager = self.apps['management']
        with patch.object(manager.app.app, 'collect_audit', side_effect=Error('Audit unavailable', 503)):
            with self.assertRaisesRegex(Error, 'Audit unavailable'):
                self.control('agent')
        self.assertEqual(manager.state()['mode'], 'native')
        self.assertEqual(self.apps['execution'].state()['phase'], 'drained')
        self.assertNotIn('agent.deploy', self.events)
        self.assertEqual(self.control('agent')['phase'], 'ready')

    def test_failed_attestation_never_falls_back_or_opens_jobs(self):
        self.control('native')
        self.attestation_ok = False
        with self.assertRaisesRegex(Error, 'Attestation verification failed'):
            self.control('agent')
        self.assertEqual(self.apps['management'].state()['phase'], 'activating')
        self.assertNotIn('agent.deploy', self.events)
        with self.assertRaisesRegex(Error, 'not ready'):
            self.apps['management'].handle('POST', '/v1/run', {})
        with self.assertRaisesRegex(Error, 'pending mode'):
            self.control('native')
        self.attestation_ok = True
        self.assertEqual(self.control('agent')['phase'], 'ready')

    def test_lost_execution_ack_resumes_same_operation_without_double_retire(self):
        self.control('agent')
        self.transport.drop_select_ack = True
        with self.assertRaisesRegex(Error, 'Lost mode acknowledgement'):
            self.control('native')
        operation = self.apps['management'].state()['operation_id']
        self.assertEqual(self.apps['execution'].state()['generation'], operation)
        selected = self.control('native')
        self.assertEqual(selected['generation'], operation)
        self.assertEqual(self.events.count('agent.retire'), 1)

    def test_backend_open_failures_resume_persisted_destination(self):
        for role in ('execution', 'management'):
            with self.subTest(role=role):
                self.control('agent')
                self.open_failures.add((role, 'native'))
                with self.assertRaisesRegex(Error, 'backend-open failure'):
                    self.control('native')
                operation = self.apps['management'].state()['operation_id']
                self.assertEqual(self.control('native')['generation'], operation)

    def test_restart_preserves_pending_switch_and_does_not_reopen_jobs(self):
        self.control('native')
        manager = self.apps['management']
        with patch.object(manager.app.app, 'collect_audit', side_effect=Error('Audit unavailable', 503)):
            with self.assertRaises(Error):
                self.control('agent')
        operation = manager.state()['operation_id']
        manager.close()
        self.apps['management'] = SelectableManagement(self.mode_configs['management'], self.mode_dbs['management'], self.transport, self.factory)
        with self.assertRaisesRegex(Error, 'not ready'):
            self.apps['management'].handle('POST', '/v1/run', {})
        self.assertEqual(self.control('agent')['generation'], operation)

    def test_native_process_timeout_never_force_kills_or_claims_switch(self):
        self.control('native')
        self.client.open_session()
        self.prepare_broker_exit(timeout=True)
        with patch('hal_fleet.mode_selection.os.killpg') as kill:
            with self.assertRaisesRegex(Error, 'no force-kill'):
                self.control('agent')
        kill.assert_called_once_with(12345, signal.SIGTERM)
        self.assertEqual(self.apps['execution'].state()['phase'], 'draining')
        self.assertEqual(self.apps['management'].state()['mode'], 'native')

    def test_native_host_inflight_prevents_even_sigterm(self):
        self.control('native')
        self.client.open_session()
        self.prepare_broker_exit()
        self.host_inflight = 1
        with patch('hal_fleet.mode_selection.os.killpg') as kill:
            with self.assertRaisesRegex(Error, 'running request'):
                self.control('agent')
        kill.assert_not_called()

    def test_execution_rejects_bypassing_agent_retirement(self):
        self.control('agent')
        with self.assertRaisesRegex(Error, 'Retire the agent'):
            self.apps['management'].vm('select', operation_id='1'*64, source='agent', target='native')
        self.assertEqual(self.apps['execution'].state()['mode'], 'agent')

    def test_audit_maintenance_cannot_enter_during_backend_replacement(self):
        self.control('native')
        execution = self.apps['execution']
        execution.save(dict(execution.state(), phase='switching'))
        with self.assertRaisesRegex(Error, 'not ready'):
            self.apps['management'].app.collect_audit()


class ConfigurationTest(unittest.TestCase):
    new_client = fixture.NativeAuditTest.new_client
    setUp = fixture.NativeAuditTest.setUp

    def files(self, role):
        owner = Ed25519PrivateKey.generate()
        keypath = self.root/'owner.json'
        atomic_json(keypath, dict(private_key=private_hex(owner)))
        native = dict(self.configs[role], tls_cert='tls.crt', tls_key='tls.key', listen='0.0.0.0:443')
        agent = dict(native, execution_architecture=ARCHITECTURES['agent'], state_dir=str(self.root/'agent'),
                     management_key=str(keypath), trusted_management_keys=[public(owner)])
        a, n = self.root/'agent.json', self.root/'native.json'
        atomic_json(a, agent); atomic_json(n, native)
        return a, n, owner

    def test_fresh_configuration_preserves_profiles_and_pins_owner_and_files(self):
        a, n, owner = self.files('management')
        before = a.read_bytes(), n.read_bytes()
        result = configure(a, n, self.root/'switch.json')
        self.assertFalse(result['services_started'])
        config = read_private(result['config'])
        self.assertEqual(config['mode_control_public_key'], public(owner))
        self.assertEqual(config['profile_sha256'], dict(agent=digest(a.read_bytes()), native=digest(n.read_bytes())))
        self.assertEqual((a.read_bytes(), n.read_bytes()), before)
        with self.assertRaisesRegex(Error, 'new mode-selection'):
            configure(a, n, self.root/'switch.json')

    def test_execution_refuses_different_owner_or_untrusted_key(self):
        a, n, owner = self.files('execution')
        other = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(Error, 'Pin the existing'):
            configure(a, n, self.root/'switch.json', public(other))
        atomic_json(self.root/'agent/agent-owner.json', dict(management_key=public(other)))
        with self.assertRaisesRegex(Error, 'owned by another'):
            configure(a, n, self.root/'switch.json', public(owner))

    def test_mismatched_endpoint_and_multi_vm_profile_rejected(self):
        a, n, owner = self.files('management')
        agent = read_private(a)
        agent['execution_targets'] = [dict(url='https://execution'), dict(url='https://second')]
        atomic_json(a, agent)
        with self.assertRaisesRegex(Error, 'one shared execution VM'):
            configure(a, n, self.root/'switch.json')
        agent.pop('execution_targets'); agent['execution_url'] = 'https://other'
        atomic_json(a, agent)
        with self.assertRaisesRegex(Error, 'same service endpoint'):
            configure(a, n, self.root/'switch.json')

    def test_selector_state_rejects_repointing_profile_pins(self):
        a, n, owner = self.files('management')
        result = configure(a, n, self.root/'switch.json')
        config = read_private(result['config'])
        db = Database(Path(result['state_dir'])/'state.sqlite3')
        self.addCleanup(db.close)
        bind_state(config, db)
        changed = copy.deepcopy(config); changed['profile_sha256']['native'] = 'a'*64
        with self.assertRaisesRegex(Error, 'another execution profile'):
            bind_state(changed, db)
        altered = read_private(n); altered['listen'] = '127.0.0.1:9999'; atomic_json(n, altered)
        with self.assertRaisesRegex(Error, 'profile changed'):
            Backend(config, 'native', self.transport)


if __name__ == '__main__':
    unittest.main(verbosity=2)
