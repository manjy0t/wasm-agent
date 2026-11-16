#!/usr/bin/env python3
"""Real Wasm/native lifecycle checks; hardware quotes and gVisor are test fixtures."""
import os
from pathlib import Path
import signal
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_portable_agent as portable
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hal_fleet.common import Error, parse, public, request, verify
from hal_fleet.attested_channel import PROOF_DOMAIN
from hal_fleet.portable import PortableManagement, PortableExecution


class LifecycleTests(unittest.TestCase):
    for name in ('setUp', 'tearDown', 'api', 'publish', 'client', 'job_body', 'collect',
                 'verify_fixture', 'ready', 'run_job'):
        locals()[name] = getattr(portable.PortableFlowTests, name)

    @classmethod
    def setUpClass(cls):
        portable.PortableFlowTests.setUpClass()

    def control(self, action, **extra):
        body = dict(execution_url=self.trust['endpoints']['execution'], **extra)
        if action == 'undeploy':
            body.setdefault('drain_seconds', 30)
        return self.api('management', '/v2/agents/' + action, request(self.management_key,
            self.trust['management_audience'], 'agent-' + action, 'management', body))

    def restart_manager(self):
        self.manager = PortableManagement(self.manager.config, self.manager.db, self.transport, allow_test_in_process=True)
        self.apps['management'] = self.servers['management'].app = self.manager

    def test_undeploy_stops_users_collects_final_audit_and_keeps_ownership(self):
        alice, bob = self.ready(), self.ready('bob')
        self.run_job(alice); self.run_job(bob)
        self.assertEqual(self.run_job(alice)['cache_status'], 'hit')
        runtime = self.launched[-1]
        owner = dict(self.execution.owner.record)
        channel = self.manager.sessions['alice']['channel']
        stopped = self.control('undeploy')
        self.assertEqual(stopped['state'], 'undeployed')
        self.assertTrue(stopped['runtime_exit_confirmed'])
        self.assertTrue(stopped['runtime_files_removed'])
        self.assertTrue(stopped['ownership_reserved'])
        self.assertEqual(runtime.process.poll(), 0)
        self.assertFalse(runtime.root.exists())
        self.assertEqual(self.execution.owner.record, owner)
        self.assertEqual(self.execution.channels, {})
        self.assertEqual(self.manager.sessions, {})
        self.assertTrue(self.manager.audit.contains(stopped['checkpoint']))
        proof = verify(stopped['identity']['public_key'], PROOF_DOMAIN, stopped['drain_proof'])
        self.assertEqual(proof['data']['checkpoint'], stopped['checkpoint'])
        self.assertEqual(proof['data']['brokers_stopped'], 2)
        with self.assertRaises(Error):
            self.manager.call_channel(channel, 'status', challenge='old-channel')
        self.assertEqual(self.control('undeploy'), stopped)
        for client in (alice, bob):
            with self.assertRaises(Error):
                client.open_session()
        self.assertEqual(len(self.launched), 1)

    def test_only_management_may_undeploy_and_replay_does_not_mutate_state(self):
        self.ready()
        body = dict(execution_url=self.trust['endpoints']['execution'], drain_seconds=0)
        for key in (self.alice.key, self.operator, Ed25519PrivateKey.generate()):
            with self.assertRaises(Error) as rejected:
                self.api('management', '/v2/agents/undeploy', request(key,
                    self.trust['management_audience'], 'agent-undeploy', 'management', body))
            self.assertEqual(rejected.exception.status, 403)
        other = Ed25519PrivateKey.generate()
        self.execution.config['trusted_management_keys'].append(public(other))
        with self.assertRaisesRegex(Error, 'belongs to another'):
            self.api('execution', '/v2/agent/lifecycle-status', request(other,
                self.trust['execution_audience'], 'agent-lifecycle-status', 'management', {}))
        envelope = request(self.management_key, self.trust['management_audience'], 'agent-status', 'management',
                           dict(execution_url=self.trust['endpoints']['execution']))
        self.api('management', '/v2/agents/status', envelope)
        with self.assertRaises(Error) as replayed:
            self.api('management', '/v2/agents/status', envelope)
        self.assertEqual(replayed.exception.code, 'replay')
        self.assertEqual(self.control('status')['management']['state'], 'active')
        self.run_job()

    def test_disabled_target_survives_service_restart_and_only_owner_redeploys(self):
        self.ready(); self.run_job()
        old = self.control('undeploy')
        owner = dict(self.execution.owner.record)
        self.restart_manager()
        self.execution.close()
        self.execution = PortableExecution(self.execution.config, self.execution.db, self.transport,
            runner_factory=self.factory, collector=self.collect, runtime_root=self.root)
        self.apps['execution'] = self.servers['execution'].app = self.execution
        with self.assertRaises(Error):
            self.alice.open_session()
        self.assertEqual(self.control('status')['execution']['state'], 'undeployed')
        self.control('deploy')
        self.ready()
        fresh = self.run_job()
        self.assertEqual(fresh['cache_status'], 'miss')
        self.assertNotEqual(fresh['agent_instance'], old['identity']['instance'])
        self.assertEqual(self.execution.owner.record, owner)
        # A delayed retirement for the previous instance must not stop this one.
        with self.assertRaises(Error):
            self.manager.execution_control(self.trust['endpoints']['execution'], 'retire',
                {k: old[k] for k in ('operation_id', 'identity', 'checkpoint')})
        self.assertEqual(self.run_job()['cache_status'], 'hit')

    def test_deadline_does_not_kill_or_repeat_inflight_job_and_native_admission_closes(self):
        self.ready()
        entered, release = threading.Event(), threading.Event()
        original = self.apps['files'].handle_http
        def delayed(method, path, body, headers):
            if method == 'GET' and path.startswith('/artifacts/'):
                entered.set()
                if not release.wait(20):
                    raise RuntimeError('test release timed out')
            return original(method, path, body, headers)
        with mock.patch.object(self.apps['files'], 'handle_http', side_effect=delayed), ThreadPoolExecutor() as pool:
            job = pool.submit(self.run_job)
            try:
                self.assertTrue(entered.wait(15), 'real broker did not request the artifact')
                pending = self.control('undeploy', drain_seconds=0)
                self.assertEqual(pending['state'], 'draining')
                self.assertTrue(pending['drain_timed_out'])
                self.assertEqual(pending['active_jobs'], 1)
                self.assertIsNone(self.launched[-1].process.poll())
                # Direct native import path also rejects admission, independently of gateway checks.
                with self.assertRaisesRegex(Error, 'draining'):
                    self.launched[-1].call('enroll', grant={})
                with self.assertRaises(Error):
                    self.alice.open_session()
            finally:
                release.set()
            completed = job.result(15)
        stopped = self.control('undeploy')
        self.assertEqual(stopped['state'], 'undeployed')
        self.assertEqual(stopped['operation_id'], pending['operation_id'])
        rows = [parse(parse(line)['payload']) for line in
                (Path(self.execution.config['state_dir'])/'audit/agent.jsonl').read_text().splitlines()]
        matched = [r for r in rows if r['data'].get('job_id') == completed['job_id']]
        self.assertEqual([r['event'] for r in matched], ['job_accepted', 'result_committed'])
        self.assertEqual(rows[-1]['event'], 'agent_drained')

    def test_waits_for_management_acknowledgements_before_removing_channel(self):
        self.ready()
        entered, release = threading.Event(), threading.Event()
        original = self.manager.dispatch_job
        def delayed(*args):
            result = original(*args)
            entered.set()
            if not release.wait(20):
                raise RuntimeError('test release timed out')
            return result
        with mock.patch.object(self.manager, 'dispatch_job', side_effect=delayed), ThreadPoolExecutor() as pool:
            job = pool.submit(self.run_job)
            try:
                self.assertTrue(entered.wait(15))
                pending = self.control('undeploy', drain_seconds=0)
                self.assertEqual(pending['pending_acknowledgements'], 1)
                self.assertIsNone(self.launched[-1].process.poll())
            finally:
                release.set()
            job.result(15)
        self.assertEqual(self.control('undeploy')['state'], 'undeployed')

    def test_audit_collection_failure_keeps_runtime_until_final_record_is_persisted(self):
        self.ready(); self.run_job()
        original = self.manager.audit.ingest
        def fail_final(vm, page):
            if any(parse(r['payload'])['event'] == 'agent_drained' for r in page['records']):
                raise Error('injected collector failure', 503, 'audit_unavailable')
            return original(vm, page)
        with mock.patch.object(self.manager.audit, 'ingest', side_effect=fail_final):
            with self.assertRaises(Error):
                self.control('undeploy')
        self.assertIsNone(self.launched[-1].process.poll())
        self.assertEqual(self.execution.lifecycle_state()['state'], 'drained')
        with self.assertRaises(Error):
            self.control('deploy')
        # Re-attestation can renew a maintenance channel without changing the final audit tip.
        self.manager.channels[self.trust['endpoints']['execution']]['deadline'] = 0
        self.assertEqual(self.control('undeploy')['state'], 'undeployed')

    def test_cleanup_failure_is_not_reported_as_success_and_same_retirement_can_resume(self):
        self.ready(); self.run_job()
        runtime = self.launched[-1]
        with mock.patch.object(runtime, 'retire', side_effect=Error('injected cleanup failure', 503, 'cleanup_incomplete')):
            with self.assertRaises(Error):
                self.control('undeploy')
        state = self.control('status')
        self.assertEqual(state['management']['state'], 'retiring')
        self.assertEqual(state['execution']['state'], 'drained')
        self.assertTrue(runtime.root.exists())
        with self.assertRaises(Error):
            self.control('deploy')
        with self.assertRaises(Error):
            self.manager.execution_control(self.trust['endpoints']['execution'], 'retire', dict(
                operation_id=state['management']['operation_id'], identity=state['management']['identity'],
                checkpoint=dict(state['management']['checkpoint'], hash='0'*64)))
        self.assertIsNone(runtime.process.poll())
        self.assertEqual(self.control('undeploy')['operation_id'], state['management']['operation_id'])

    def test_lost_retirement_response_recovers_after_manager_restart_without_redeployment(self):
        self.ready(); self.run_job()
        original = self.manager.execution_control
        def lost(url, action, body):
            result = original(url, action, body)
            if action == 'retire':
                raise Error('injected lost response', 503, 'outcome_unknown')
            return result
        with mock.patch.object(self.manager, 'execution_control', side_effect=lost):
            with self.assertRaises(Error):
                self.control('undeploy')
        self.assertEqual(self.execution.lifecycle_state()['state'], 'undeployed')
        self.restart_manager()
        self.assertEqual(self.control('undeploy')['state'], 'undeployed')
        self.assertEqual(len(self.launched), 1)

    def test_dead_broker_cannot_produce_successful_cleanup_receipt(self):
        self.ready(); self.run_job()
        logs = list(self.launched[-1].root.glob('user-*/broker.log'))
        ready = next(parse(line) for line in logs[0].read_text().splitlines() if line.startswith('{') and parse(line).get('status') == 'ready')
        pid = int(ready['instance'].split('-')[0])
        os.kill(pid, signal.SIGKILL)
        with self.assertRaisesRegex(Error, 'cleanup'):
            self.control('undeploy')
        self.assertEqual(self.execution.lifecycle_state()['state'], 'draining')
        self.assertIsNone(self.launched[-1].process.poll())
        with self.assertRaises(Error):
            self.control('deploy')
        with self.assertRaises(Error):
            self.control('undeploy')

    def test_cli_uses_management_key_and_reports_incomplete_drain(self):
        import fleet
        from hal_fleet.common import atomic_json, verify_request
        config = self.root/'manager-cli.json'
        atomic_json(config, self.manager.config)
        def call(base, path, body):
            self.assertEqual(base, self.trust['endpoints']['management'])
            self.assertEqual(path, '/v2/agents/undeploy')
            signed = verify_request(body, self.trust['management_audience'], 'agent-undeploy', self.manager.db)
            self.assertEqual(signed['public_key'], public(self.management_key))
            self.assertEqual(signed['body']['drain_seconds'], 0)
            return dict(state='draining', drain_timed_out=True)
        with mock.patch.object(sys, 'argv', ['fleet.py', 'agent-undeploy', '--config', str(config),
                                '--execution-url', self.trust['endpoints']['execution'], '--drain-seconds', '0']), \
             mock.patch('hal_fleet.common.Transport.call', side_effect=call), mock.patch('builtins.print'):
            self.assertEqual(fleet.main(), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
