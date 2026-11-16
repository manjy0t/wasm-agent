#!/usr/bin/env python3
"""Offline checks for matrix selection and stopping after a failed batch."""
import argparse
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('run_matrix', ROOT / 'benchmarks/run_matrix.py')
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hal_fleet.common import atomic_json, private_hex, public, REQUEST_DOMAIN, verify


class BenchmarkMatrixTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def save_batch(self, folder, rows):
        folder.mkdir(parents=True)
        (folder / 'jobs.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        completed = sum(row['status'] == 'completed' for row in rows)
        summary = dict(requested=len(rows), completed=completed, failed_or_unknown=len(rows) - completed)
        (folder / 'summary.json').write_text(json.dumps(summary))
        return summary

    def invoke(self, benchmark, extra=()):
        client = Mock()
        args = ['run_matrix.py', '--client', 'unused.json', '--output', str(self.root / 'matrix'),
                '--jobs', '4', '--repeats', '1', '--concurrencies', '1,4', *extra]
        with patch.object(sys, 'argv', args), patch.object(matrix, 'Client', return_value=client), \
                patch.object(matrix, 'certificate', return_value={'workloads': [{'name': 'platform'}]}), \
                patch.object(matrix, 'Experiment', return_value=MagicMock()), \
                patch.object(matrix, 'benchmark', side_effect=benchmark) as calls, redirect_stdout(io.StringIO()):
            try:
                matrix.main()
            finally:
                client.transport.close.assert_called_once()
        return calls

    def test_selected_levels_keep_each_repeat_order_and_both_cache_policies(self):
        plan = list(matrix.matrix_plan(3, 'wasm', matrix.concurrency_levels('1,2,4')))
        self.assertEqual(len(plan), 18)
        self.assertEqual([q for r, q, c in plan if r == 2 and c == 'reuse'], [4, 2, 1])
        self.assertEqual([q for r, q, c in plan if r == 3 and c == 'bypass'], [2, 1, 4])
        self.assertEqual({(q, c) for _, q, c in plan},
                         {(q, c) for q in (1, 2, 4) for c in ('bypass', 'reuse')})
        self.assertEqual(len(list(matrix.matrix_plan(3, 'wasm'))), 18)
        self.assertEqual({c for _, _, c in matrix.matrix_plan(1, 'native')}, {'bypass'})

    def test_invalid_concurrency_selection_is_rejected(self):
        for value in ('', '0', '16', '1,1', '1,4,', 'a,4'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                matrix.concurrency_levels(value)

    def test_reuse_only_has_nine_batches_and_preserves_repeat_order(self):
        plan = list(matrix.matrix_plan(3, 'wasm', cache='reuse'))
        self.assertEqual(len(plan), 9)
        self.assertEqual([q for _, q, _ in plan], [1, 2, 4, 4, 2, 1, 2, 1, 4])
        self.assertEqual({cache for _, _, cache in plan}, {'reuse'})
        self.assertEqual(len(list(matrix.matrix_plan(3, 'wasm', cache='bypass'))), 9)
        self.assertEqual(len(list(matrix.matrix_plan(3, 'wasm', cache='both'))), 18)

    def test_native_cache_selection_cannot_enable_reuse(self):
        for cache in ('reuse', 'both', 'invalid'):
            with self.subTest(cache=cache), self.assertRaises(matrix.Error):
                list(matrix.matrix_plan(3, 'native', cache=cache))
        self.assertEqual(list(matrix.matrix_plan(3, 'native', cache='bypass')),
                         list(matrix.matrix_plan(3, 'native')))

    def test_cli_runs_only_selected_levels_and_keeps_warmups_separate(self):
        def batch(client, cases, jobs, concurrency, cache, folder, *profile, **context):
            return self.save_batch(folder, [{'status': 'completed'} for _ in range(jobs)])
        calls = self.invoke(batch)
        rows = json.loads((self.root / 'matrix/matrix.json').read_text())
        self.assertEqual([(r['concurrency'], r['cache']) for r in rows],
                         [(1, 'bypass'), (1, 'reuse'), (4, 'bypass'), (4, 'reuse')])
        self.assertEqual(calls.call_count, 6)  # Four batches and two separate warm-ups.

    def test_failed_batch_retains_results_reports_each_error_and_does_not_retry(self):
        def batch(client, cases, jobs, concurrency, cache, folder, *profile, **context):
            return self.save_batch(folder, [
                {'status': 'completed'},
                {'status': 'failed', 'response': {'error': 'tenant capacity exhausted'}},
                {'status': 'failed', 'response': {'agent': {'error': 'worker startup failed'}}},
                {'status': 'unknown', 'error': 'job may have run'},
            ])
        callback = Mock(side_effect=batch)
        with self.assertRaises(matrix.Error) as raised:
            self.invoke(callback)
        callback.assert_called_once()
        message = str(raised.exception)
        for text in ('1/4 completed', '3 failed/unknown', 'tenant capacity exhausted',
                     'worker startup failed', 'job may have run', 'No jobs retried',
                     str(self.root / 'matrix/r1-bypass-q1/jobs.jsonl')):
            self.assertIn(text, message)
        rows = json.loads((self.root / 'matrix/matrix.json').read_text())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['failed_or_unknown'], 3)
        self.assertFalse((self.root / 'matrix/r1-reuse-q1-warmup').exists())

    def test_failed_warmup_prevents_the_measurement(self):
        def batch(client, cases, jobs, concurrency, cache, folder, *profile, **context):
            rows = [{'status': 'unknown', 'error': 'response lost'}] if folder.name.endswith('-warmup') \
                else [{'status': 'completed'} for _ in range(jobs)]
            return self.save_batch(folder, rows)
        callback = Mock(side_effect=batch)
        with self.assertRaisesRegex(matrix.Error, 'r1-reuse-q1 warm-up failed'):
            self.invoke(callback)
        self.assertEqual(callback.call_count, 2)
        self.assertTrue((self.root / 'matrix/r1-reuse-q1-warmup/jobs.jsonl').exists())
        self.assertFalse((self.root / 'matrix/r1-reuse-q1').exists())


class WarmCacheSessionTest(unittest.TestCase):
    """Exercise the real client validation/signing with a simulated management API."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        key = Ed25519PrivateKey.generate()
        path = self.root / 'client.json'
        atomic_json(path, dict(user='alice', private_key=private_hex(key),
            required_execution_architecture='hal-managed-agent-v2', require_attested_agent=True,
            trust=dict(issuer='identity', management_audience='management', execution_audience='execution')))
        self.client = matrix.WarmCacheClient(path)
        self.addCleanup(self.client.transport.close)
        self.client.document = {'fixture': 'enrollment'}
        self.client.renew = Mock()
        self.now = 1000
        clock = patch.object(matrix.time, 'time', side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.session = dict(tenant='alice', audience='execution', mode='wasm', isolation='per-user-container',
                            execution_architecture='hal-managed-agent-v2', attestation_verified=True,
                            epoch='old', expires_unix=1185)
        self.requests = []
        self.forced_session = None
        self.caps = dict(session_via_management=True, session_minimum_validity=True,
                         execution_architecture='hal-managed-agent-v2')

        def api(role, endpoint, envelope=None):
            self.assertEqual(role, 'management')
            if endpoint == '/v1/capabilities':
                return self.caps
            self.assertEqual(endpoint, '/v1/session')
            claims = verify(public(key), REQUEST_DOMAIN, envelope)
            self.assertEqual(claims['operation'], 'session')
            self.assertEqual(claims['audience'], 'management')
            self.assertEqual(claims['subject'], 'alice')
            self.requests.append(claims['body'])
            minimum = claims['body'].get('minimum_validity_seconds', 10)
            if self.session['expires_unix'] <= self.now + minimum:
                self.session.update(epoch='renewed-' + str(len(self.requests)), expires_unix=self.now + 300)
            return copy.deepcopy(self.forced_session or self.session)
        self.client.call = Mock(side_effect=api)

    def warm(self):
        with self.client.warming():
            return self.client.open_session()

    def test_renewal_happens_before_warmup_and_measurement_keeps_that_session_once(self):
        warmed = self.warm()
        self.assertNotEqual(warmed['epoch'], 'old')
        self.assertEqual(self.requests[0]['minimum_validity_seconds'], 270)
        self.client.keep_warmed_session()
        self.now += 5
        self.assertIs(self.client.open_session(), warmed)
        self.assertEqual(len(self.requests), 1)  # No enrollment/session hop after warming.
        self.client.open_session()
        self.assertEqual(len(self.requests), 2)  # Only the immediately following open is reused.
        self.assertEqual(self.requests[-1]['minimum_validity_seconds'], 180)

    def test_bypass_and_other_signed_operations_keep_original_requests(self):
        self.client.open_session()
        self.assertEqual(self.requests[-1]['minimum_validity_seconds'], 180)
        body = {'action': 'acquire'}
        with self.client.warming():
            envelope = self.client.signed('management', 'benchmark', body)
        self.assertEqual(json.loads(envelope['payload'])['body'], body)

    def test_short_warmup_lifetime_is_rejected_without_extending_it(self):
        self.forced_session = dict(self.session, expires_unix=self.now + 260)
        with self.assertRaisesRegex(matrix.Error, 'too short for warm-up'):
            self.warm()
        self.assertEqual(self.client.session['expires_unix'], self.now + 260)
        self.assertFalse(self.client._warming)

    def test_slow_warmup_stops_before_measurement_without_silent_renewal(self):
        self.warm()
        self.client.keep_warmed_session()
        self.now += 61  # Less than the 150-second job reserve + 90 seconds for measurement.
        with self.assertRaisesRegex(matrix.Error, 'no measured job submitted'):
            self.client.open_session()
        self.assertEqual(len(self.requests), 1)
        self.assertIsNone(self.client._warmed_session)

    def test_changed_warmed_session_is_rejected(self):
        self.warm()
        self.client.keep_warmed_session()
        self.client.session['epoch'] = 'unexpected-broker'
        with self.assertRaisesRegex(matrix.Error, 'Session changed after warm-up'):
            self.client.open_session()
        self.assertEqual(len(self.requests), 1)

    def test_profile_attestation_tenant_and_expiry_checks_are_preserved(self):
        for change in ({'attestation_verified': False}, {'tenant': 'bob'}, {'mode': 'native'},
                       {'isolation': 'in-process'}, {'expires_unix': self.now + 120}):
            with self.subTest(change=change):
                self.forced_session = dict(self.session, **change)
                with self.assertRaises(matrix.Error):
                    self.warm()
        self.caps['session_minimum_validity'] = False
        count = len(self.requests)
        with self.assertRaisesRegex(matrix.Error, 'minimum-session-validity support'):
            self.warm()
        self.assertEqual(len(self.requests), count)

    def invoke(self, fail_warmup=False, measured_miss=False, extra=()):
        calls = []
        sessions = {}

        def batch(client, cases, jobs, concurrency, cache, folder, *profile, **context):
            sessions[folder.name] = copy.deepcopy(client.open_session())
            calls.append(folder.name)
            folder.mkdir()
            failed = fail_warmup and context.get('phase') == 'warmup'
            rows = [{'status': 'unknown' if failed else 'completed', 'error': 'response lost'} for _ in range(jobs)]
            (folder / 'jobs.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            status = 'bypass' if cache == 'bypass' else 'hit'
            if measured_miss and cache == 'reuse' and context.get('phase') != 'warmup':
                status = 'miss'
            return dict(requested=jobs, completed=0 if failed else jobs, failed_or_unknown=jobs if failed else 0,
                        cache_status_counts={status: jobs}, session_refresh_count=0)

        args = ['run_matrix.py', '--client', str(self.client.path), '--output', str(self.root / 'matrix'),
                '--jobs', '4', '--repeats', '1', '--concurrencies', '1,4', '--fully-warmed', *extra]
        with patch.object(sys, 'argv', args), patch.object(matrix, 'WarmCacheClient', return_value=self.client), \
                patch.object(matrix, 'certificate', return_value={'workloads': [{'name': 'platform'}]}), \
                patch.object(matrix, 'Experiment', return_value=MagicMock()), \
                patch.object(matrix, 'benchmark', side_effect=batch), redirect_stdout(io.StringIO()):
            matrix.main()
        return calls, sessions

    def test_matrix_pairs_warmups_and_measurements_without_another_session_request(self):
        calls, sessions = self.invoke()
        self.assertEqual(len(calls), 6)
        self.assertEqual(len(self.requests), 4)  # Two bypass openings and two warm-up openings.
        for q in (1, 4):
            self.assertEqual(sessions[f'r1-reuse-q{q}-warmup'], sessions[f'r1-reuse-q{q}'])
        protocol = json.loads((self.root / 'matrix/matrix-protocol.json').read_text())
        self.assertTrue(protocol['fully_warmed'])
        self.assertEqual(protocol['warmup_minimum_validity_seconds'], 270)

    def test_reuse_only_submits_no_bypass_batches_and_keeps_each_warmed_session(self):
        calls, sessions = self.invoke(extra=('--cache', 'reuse'))
        self.assertEqual(calls, ['r1-reuse-q1-warmup', 'r1-reuse-q1', 'r1-reuse-q4-warmup', 'r1-reuse-q4'])
        self.assertEqual(len(self.requests), 2)
        for q in (1, 4):
            self.assertEqual(sessions[f'r1-reuse-q{q}-warmup'], sessions[f'r1-reuse-q{q}'])
        protocol = json.loads((self.root / 'matrix/matrix-protocol.json').read_text())
        self.assertEqual(protocol['cache_policies'], ['reuse'])

    def test_failed_warmup_is_not_retried_and_stops_before_measurement(self):
        with self.assertRaisesRegex(matrix.Error, 'warm-up failed'):
            self.invoke(fail_warmup=True)
        self.assertTrue((self.root / 'matrix/r1-reuse-q1-warmup/jobs.jsonl').is_file())
        self.assertFalse((self.root / 'matrix/r1-reuse-q1').exists())
        self.assertIsNone(self.client._warmed_session)
        self.assertFalse(self.client._warming)

    def test_measured_miss_is_retained_and_stops_remaining_batches(self):
        with self.assertRaisesRegex(matrix.Error, 'not fully warmed'):
            self.invoke(measured_miss=True)
        recorded = json.loads((self.root / 'matrix/matrix.json').read_text())
        self.assertEqual(recorded[-1]['cache_status_counts'], {'miss': 4})
        self.assertTrue((self.root / 'matrix/r1-reuse-q1/jobs.jsonl').is_file())
        self.assertFalse((self.root / 'matrix/r1-bypass-q4').exists())

    def test_native_mode_cannot_enable_fully_warmed(self):
        args = ['run_matrix.py', '--client', 'unused.json', '--output', str(self.root / 'native'),
                '--expect-mode', 'native', '--expect-isolation', 'in-process', '--fully-warmed']
        with patch.object(sys, 'argv', args), self.assertRaisesRegex(matrix.Error, 'agent profile'):
            matrix.main()
        self.assertFalse((self.root / 'native').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
