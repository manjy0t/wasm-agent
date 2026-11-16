#!/usr/bin/env python3
"""Benchmark lease renewal: drain outstanding jobs and never retry outcomes."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet import client as module
from hal_fleet.common import Error


class SessionBenchmarkTest(unittest.TestCase):
    def run_batch(self, fail_refresh=False, unknown=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name) / 'batch'
        test = self

        class Client:
            def __init__(self):
                self.trust = {'endpoints': {}}
                self.active = self.opens = self.started = 0
                self.lock = threading.Lock()
                self.barrier = threading.Barrier(2)
                self.near_expiry = False

            def open_session(self):
                with self.lock:
                    test.assertEqual(self.active, 0, 'renewal must not replace an in-use broker')
                    self.opens += 1
                    if self.opens > 1 and fail_refresh:
                        raise Error('Trustee appraisal rejected')
                    self.near_expiry = False
                    return dict(mode='wasm', isolation='per-user-container', attestation_verified=True,
                                expires_unix=int(time.time()) + 300, epoch=str(self.opens))

            def job(self, *args):
                with self.lock:
                    self.active += 1
                    self.started += 1
                    index = self.started
                self.barrier.wait(timeout=5)
                with self.lock:
                    if index <= 2:
                        self.near_expiry = True
                    self.active -= 1
                if unknown:
                    return dict(status='unknown', error='response lost; job may have run', job_id=str(index))
                return dict(status='completed', job_id=str(index), client_observed_ms=1,
                            timings_ms={'management_total': 1}, attestation_verified=True,
                            response={'agent': dict(cache_status='hit', execution_mode='wasm',
                                configuration={'workload_isolation': 'per-user-container', 'compile_opt_level': 'speed'},
                                timings_ms={'host_request': 1})})

        client = Client()
        # This test isolates lease draining/timing. Real provenance, signatures
        # and exclusive admission are covered by test_native_audit.
        experiment = Mock(id='fixture-experiment', pin={}, output=folder, batches=[], runtime=None)
        experiment.session.return_value = 'f' * 64
        with patch.object(module, 'session_needs_refresh', side_effect=lambda _: client.near_expiry):
            result = module.benchmark(client, ['platform'], 4, 2, 'reuse', folder, 'wasm', 'per-user-container', experiment=experiment)
        rows = [json.loads(line) for line in (folder / 'jobs.jsonl').read_text().splitlines()]
        config = json.loads((folder / 'config.json').read_text())
        return result, rows, config, client

    def test_renewal_waits_for_both_jobs_and_records_its_time(self):
        summary, rows, config, client = self.run_batch()
        self.assertEqual(client.opens, 2)
        self.assertEqual(client.started, 4)
        self.assertEqual(summary['completed'], 4)
        self.assertEqual(summary['session_refresh_count'], 1)
        self.assertGreater(summary['session_refresh_ms'], 0)
        self.assertTrue(summary['session_refresh_included_in_batch_wall'])
        self.assertEqual([r['session_generation'] for r in sorted(rows, key=lambda r:r['trial_index'])], [0, 0, 1, 1])
        self.assertEqual(config['session_refreshes'][0]['after_submitted'], 2)

    def test_failed_renewal_preserves_completed_jobs_and_stops_submissions(self):
        summary, rows, config, client = self.run_batch(fail_refresh=True)
        self.assertEqual(client.opens, 2)
        self.assertEqual(client.started, 2)
        self.assertEqual(summary['completed'], 2)
        self.assertEqual(summary['not_submitted'], 2)
        self.assertEqual(summary['failed_or_unknown'], 2)
        self.assertEqual(summary['session_refresh_error'], 'Trustee appraisal rejected')
        self.assertEqual(len(rows), 2)
        self.assertEqual(config['session_refreshes'][0]['error'], 'Trustee appraisal rejected')

    def test_unknown_jobs_are_not_retried_on_session_renewal(self):
        summary, rows, _, client = self.run_batch(unknown=True)
        self.assertEqual(client.started, 4)
        self.assertEqual(len({r['job_id'] for r in rows}), 4)
        self.assertEqual(summary['completed'], 0)
        self.assertEqual(summary['statuses'], {'unknown': 4})


if __name__ == '__main__':
    unittest.main(verbosity=2)
