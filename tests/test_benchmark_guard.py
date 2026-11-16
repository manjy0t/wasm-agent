"""Cross-profile and interrupted-run provenance checks using real service signatures."""
import copy
import json
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import test_native_audit as fixture
from hal_fleet.benchmark_guard import BenchmarkGate, Experiment, verify_batch
from hal_fleet.client import benchmark
from hal_fleet.common import Error, parse


class GuardTest(unittest.TestCase):
    setUp = fixture.NativeAuditTest.setUp
    new_client = fixture.NativeAuditTest.new_client

    def test_agent_identity_and_workload_build_pins_reject_changes(self):
        directory = self.root/'agent-pin'; directory.mkdir()
        with Experiment(self.client, ['fixture'], 'wasm', 'per-user-container', directory) as run:
            # Model the public agent session schema; no hardware/Wasmtime claim.
            session = self.client.open_session()
            session.update(mode='wasm', isolation='per-user-container', execution_architecture='hal-managed-agent-v2',
                           agent_identity=session.pop('native_identity'), audit_log='hal-agent-audit-v1', agent_sha256='a'*64)
            run.session(session)
            for mutate in (lambda s: s['agent_identity'].update(public_key='f'*64),
                           lambda s: s.update(agent_sha256='f'*64),
                           lambda s: s['build'].update(service_sha256='e'*64),
                           lambda s: s.update(workload_configuration={'executions': 1})):
                changed = copy.deepcopy(session); mutate(changed)
                with self.assertRaisesRegex(Error, 'changed'):
                    run.session(changed)
            wrong_mode = dict(session, execution_architecture='hal-native-audited-v1', mode='native')
            with self.assertRaises(Error):
                run.session(wrong_mode)

    def test_restart_keeps_exclusive_lease_but_invalidates_old_run_identity(self):
        directory = self.root/'restart'; directory.mkdir()
        with Experiment(self.client, ['fixture'], 'native', 'in-process', directory) as run:
            run.session(self.client.open_session())
            old = self.apps['management']
            self.apps['management'] = BenchmarkGate(old.app)
            with self.assertRaisesRegex(Error, 'changed'):
                run.session(self.client.open_session())
            self.assertEqual(self.apps['management'].lease()['experiment_id'], run.id)

    def test_warmup_stays_separate_and_secrets_never_enter_result_files(self):
        folder = self.root/'warmup'
        summary = benchmark(self.client, ['fixture'], 2, 1, 'bypass', folder, 'native', 'in-process', phase='warmup')
        self.assertEqual(summary['phase'], 'warmup')
        with self.assertRaisesRegex(Error, 'not measured'):
            verify_batch(folder)
        for path in folder.glob('*.json*'):
            raw = path.read_text()
            self.assertNotIn('"token":', raw)
            self.assertNotIn('"private_key":', raw)
        manifest = parse((folder/'experiment.json').read_text())
        self.assertEqual(manifest['state'], 'complete')
        self.assertEqual(manifest['batches'][0]['phase'], 'warmup')

    def test_failed_batches_have_failed_experiment_manifest(self):
        with patch.object(self.client, 'job', return_value=dict(status='unknown', error='response lost')):
            summary = benchmark(self.client, ['fixture'], 2, 1, 'bypass', self.root/'failed', 'native', 'in-process')
        self.assertEqual(summary['completed'], 0)
        self.assertFalse(summary['valid_for_comparison'])
        manifest = parse((self.root/'failed/experiment.json').read_text())
        self.assertEqual(manifest['state'], 'failed')
        with self.assertRaises(Error):
            verify_batch(self.root/'failed')

    def test_missing_build_provenance_stops_before_any_job(self):
        original = self.client.open_session
        def missing():
            session = original(); session.pop('build'); return session
        with patch.object(self.client, 'open_session', side_effect=missing), self.assertRaisesRegex(Error, 'build provenance'):
            benchmark(self.client, ['fixture'], 2, 1, 'bypass', self.root/'missing', 'native', 'in-process')
        self.assertEqual(self.executions, 0)
        self.assertEqual(parse((self.root/'missing/experiment.json').read_text())['state'], 'failed')
        self.assertIsNone(self.apps['management'].lease())

    def test_expired_lease_never_becomes_an_ordinary_unleased_request(self):
        directory = self.root/'expiry'; directory.mkdir()
        with self.assertRaisesRegex(Error, 'release failed'):
            with Experiment(self.client, ['fixture'], 'native', 'in-process', directory):
                gate = self.apps['management']
                lease = gate.lease()
                gate.db.put('benchmark', 'lease', dict(lease, expires_unix=int(time.time()) - 1))
                with self.assertRaisesRegex(Error, 'expired'):
                    self.client.open_session()
        self.assertEqual(self.executions, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
