#!/usr/bin/env python3
"""Optimized no-agent execution keeps its limits and never caches workloads."""
from concurrent.futures import ThreadPoolExecutor
import threading
import unittest
from unittest.mock import patch

import test_system as support
from test_system import ROOT, WorkerHTTPClient


class NativeBaselineTest(unittest.TestCase):
    start = support.SystemTest.start
    stop = staticmethod(support.SystemTest.stop)
    tearDown = support.SystemTest.tearDown
    start_agent = support.SystemTest.start_agent
    stats = support.SystemTest.stats
    run_case = support.SystemTest.run_case

    def setUp(self):
        support.SystemTest.setUp(self)
        self.stop(self.host)

    def test_repeated_jobs_ignore_existing_code_cache_and_never_populate_it(self):
        item = self.cases['platform']
        old = self.root / 'cache' / (item['sha256'] + '.wasm')
        old.write_bytes((ROOT / 'tests/workloads' / item['artifact']).read_bytes())
        interrupted = self.root / 'cache/staging/job-existing.wasm'
        interrupted.write_bytes(b'leave earlier staging untouched')
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (old, interrupted)}
        # A tiny cache budget would evict the old artifact if native mode
        # accidentally opened the legacy code cache during startup.
        self.start_agent('--mode', 'native', '--transport', 'http', '--disk-cache-bytes', '1')
        rows = [self.run_case('platform') for _ in range(3)]
        self.assertTrue(all(row['status'] == 'ok' for row in rows), rows)
        for row in rows:
            self.assertTrue(row['runtime_reused'])
            self.assertFalse(row['workload_instance_reused'])
            self.assertTrue(row['configuration']['execution_limits_enabled'])
            self.assertEqual(row['configuration']['code_cache_storage'], 'disabled')
            self.assertFalse(row['preparation']['stored'])
            self.assertEqual(row['preparation']['source'], 'download')
            self.assertEqual(row['cache_status'], 'bypass')
        self.assertEqual(self.stats()['compiled_entries'], 0)
        self.assertEqual(self.stats()['shared_preparations'], 0)
        self.assertEqual(self.stats()['downloads'], 3)
        self.assertEqual(self.stats()['compiles'], 3)
        self.assertEqual(list((self.root / 'cache').glob('*.wasm')), [old])
        for path, snapshot in before.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), snapshot)
        rejected = self.run_case('platform', cache='reuse')
        self.assertEqual(rejected['status'], 'error')
        self.assertIn('--cache bypass', rejected['error'])
        self.assertEqual(self.stats()['downloads'], 3)
        self.files.fail = True
        self.assertEqual(self.run_case('platform')['status'], 'error')
        self.assertEqual(self.stats()['executions'], 3)

    def test_jobs_overlap_with_bounded_downloads_and_no_duplicate_preparation_reuse(self):
        self.start_agent('--mode', 'native', '--transport', 'http', '--downloads', '2',
                         '--compilers', '2', '--compiler-threads', '2',
                         '--executions', '2', '--max-inflight', '8')
        release = threading.Event()
        two_arrived = threading.Event()
        lock = threading.Lock()
        arrivals = []
        original = support.FixtureHandler.do_GET

        def gated(handler):
            with lock:
                arrivals.append(handler.path)
                if len(arrivals) >= 2:
                    two_arrived.set()
            if not release.wait(10):
                handler.send_error(503)
                return
            original(handler)

        with patch.object(support.FixtureHandler, 'do_GET', gated):
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(self.run_case, 'platform') for _ in range(8)]
                try:
                    self.assertTrue(two_arrived.wait(5), 'native jobs did not overlap')
                    self.assertEqual(self.stats()['downloads'], 2)
                    with lock:
                        self.assertEqual(len(arrivals), 2)
                finally:
                    release.set()
                rows = [f.result(timeout=30) for f in futures]
        self.assertTrue(all(row['status'] == 'ok' for row in rows), rows)
        for name in ('downloads', 'compiles', 'executions'):
            self.assertEqual(self.stats()[name], 8)
        self.assertEqual(self.stats()['shared_preparations'], 0)
        self.assertEqual(self.stats()['compiled_entries'], 0)
        self.assertEqual(self.stats()['compiler']['job_limit'], 2)
        self.assertEqual(self.stats()['compiler']['dedicated_threads'], 2)
        for row in rows:
            self.assertEqual(row['configuration']['executions'], 2)
            self.assertEqual(row['configuration']['max_inflight'], 8)

    def test_fuel_and_output_limits_remain_active_in_both_modes(self):
        for mode in ('native', 'wasm'):
            for flags, error in [
                (('--workload-fuel', '1'), 'fuel'),
                (('--max-output-bytes', '1'), 'output'),
            ]:
                with self.subTest(mode=mode, flags=flags):
                    self.stop(self.host)
                    self.start_agent('--mode', mode, '--transport', 'http', *flags)
                    row = self.run_case('sha256-abc', cache='bypass')
                    self.assertEqual(row['status'], 'error', row)
                    self.assertIn(error, row['error'])

    def test_native_job_deadline_remains_active(self):
        self.start_agent('--mode', 'native', '--transport', 'http',
                         '--job-timeout-secs', '1', '--execution-timeout-secs', '1')
        self.files.delay = 1.3
        row = self.run_case('platform')
        self.assertEqual(row['status'], 'error', row)
        self.assertIn('job deadline exceeded', row['error'])
        self.assertEqual(self.stats()['executions'], 0)
        self.assertEqual(row['configuration']['job_timeout_secs'], 1)

    def test_http_connections_reused_but_workload_preparation_is_not(self):
        self.start_agent('--mode', 'native', '--transport', 'http')
        self.files.delay = 0
        item = self.cases['platform']
        client = WorkerHTTPClient(self.worker_url, self.token, 10)
        try:
            reused = []
            for number in range(3):
                row = client.request(dict(protocol=1, op='run', job_id=f'uncached-{number}',
                    component=item['artifact'], sha256=item['sha256'],
                    artifact_bytes=item['artifact_bytes'], cache='bypass'))
                self.assertEqual(row['status'], 'ok', row)
                reused.append(client.last_connection_reused)
            self.assertEqual(reused, [False, True, True])
        finally:
            client.close()
        self.assertEqual(len(self.files.peers), 1, 'file download connections should be pooled')
        self.assertEqual(self.stats()['downloads'], 3)
        self.assertEqual(self.stats()['compiles'], 3)
        self.assertEqual(self.stats()['compiled_entries'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
