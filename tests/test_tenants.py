#!/usr/bin/env python3
"""Tenant boundaries with real Wasm workloads; software mode, not TDX attestation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError

import test_system as support
from test_system import FixtureHandler, ROOT, jobs, worker_http_request, agent_request


class TenantSystemTest(unittest.TestCase):
    start = support.SystemTest.start
    stop = staticmethod(support.SystemTest.stop)
    tearDown = support.SystemTest.tearDown
    start_agent = support.SystemTest.start_agent
    stats = support.SystemTest.stats

    def setUp(self):
        support.SystemTest.setUp(self)
        self.stop(self.host)
        self.bundle = self.root / 'bundles'
        done = subprocess.run([sys.executable, '-B', str(ROOT / 'configure_tenants.py'),
            '--catalog', str(self.root / 'catalog.json'), '--tenant', 'alice', '--tenant', 'bob',
            '--output', str(self.bundle)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.execution = self.bundle / 'execution'
        self.management = self.bundle / 'management'
        self.token = (self.execution / 'operator.token').read_text().strip()
        (self.root / 'agent.token').write_text(self.token)
        self.api_token = (self.management / 'api.token').read_text().strip()
        self.file_token = (self.execution / 'file.token').read_text().strip()
        self.files.RequestHandlerClass = partial(FixtureHandler, directory=ROOT / 'tests/workloads',
            max_bytes=16 * 1024 * 1024, token=self.file_token)
        self.files.delay = 0

    def restart(self, mode='wasm', transport='http', **limits):
        self.stop(self.host)
        policy_path = self.execution / 'policy.json'
        policy = json.loads(policy_path.read_text())
        for tenant in policy['tenants']:
            tenant.update(limits)
        policy_path.write_text(json.dumps(policy))
        self.start_agent('--mode', mode, '--transport', transport, '--tenant-policy', str(policy_path),
                         '--file-token-file', str(self.execution / 'file.token'))

    def client_token(self, tenant):
        return (self.bundle / 'clients' / f'{tenant}.token').read_text().strip()

    def run_as(self, owner, case='platform', **changes):
        item = self.cases[case]
        request = dict(protocol=1, op='run', job_id='test-' + str(time.time_ns()),
                       cache='bypass' if self.ready.get('execution_mode') == 'native' else 'reuse',
                       component=item['artifact'], sha256=item['sha256'], artifact_bytes=item['artifact_bytes'])
        request.update(changes)
        token = (self.execution / f'{owner}.token').read_text().strip()
        if self.worker_url:
            return worker_http_request(self.worker_url, token, request, 30)
        return agent_request(self.address, token, request, 30)

    def start_manager(self):
        process, ready = self.start([sys.executable, '-B', str(ROOT / 'server/management.py'),
            '--port', '0', '--worker-url', self.worker_url,
            '--api-token-file', str(self.management / 'api.token'),
            '--agent-token-file', str(self.management / 'worker.token'),
            '--tenant-policy', str(self.management / 'policy.json'),
            '--catalog', str(self.management / 'workloads.json'),
            '--state-dir', str(self.root / 'tenant-manager'), '--dispatchers', '2'])
        self.api = f'http://127.0.0.1:{ready["listen"][1]}'
        return process

    def test_agent_private_caches_and_native_bypass_keep_user_identity(self):
        for mode in ('wasm', 'native'):
            with self.subTest(mode=mode):
                self.restart(mode)
                alice, bob = self.run_as('alice'), self.run_as('bob')
                for owner, row in [('alice', alice), ('bob', bob)]:
                    self.assertEqual(row['status'], 'ok', row)
                    self.assertEqual(row['tenant'], owner)
                    self.assertEqual(row['cache_status'], 'miss' if mode == 'wasm' else 'bypass')
                    self.assertEqual(row['preparation']['source'], 'download')
                    self.assertEqual(self.run_as(owner)['cache_status'], 'hit' if mode == 'wasm' else 'bypass')
                    bypass = self.run_as(owner, cache='bypass')
                    self.assertEqual(bypass['preparation']['source'], 'download')
                    self.assertFalse(bypass['preparation']['stored'])
                if mode == 'wasm':
                    self.assertFalse(alice['agent_worker_reused'])
                    self.assertFalse(bob['agent_worker_reused'])
                    self.assertEqual(alice['agent_worker_job_number'], 1)
                    self.assertEqual(bob['agent_worker_job_number'], 1)
                self.assertEqual(self.stats()['compiled_entries'], 2 if mode == 'wasm' else 0)
                if mode == 'native':
                    self.assertEqual(self.stats()['downloads'], 6)
                    self.assertEqual(self.stats()['compiles'], 6)
                for owner in ('alice', 'bob'):
                    files = list((self.root / 'cache/tenants' / owner / 'cache').glob('*.wasm'))
                    self.assertEqual(len(files), 1)
                self.assertFalse(list((self.root / 'cache').glob('*.wasm')))

    def test_host_authorization_precedes_cache_and_survives_policy_change(self):
        for mode, transport in [('wasm', 'http'), ('native', 'tcp')]:
            with self.subTest(mode=mode, transport=transport):
                self.restart(mode, transport)
                self.assertEqual(self.run_as('alice')['status'], 'ok')
                for changes in [dict(tenant='bob'), dict(sha256='0' * 64), dict(artifact_bytes=9),
                                dict(component='../../escape.wasm')]:
                    self.assertEqual(self.run_as('alice', **changes)['status'], 'error')
                self.assertEqual(self.stats()['executions'], 1)
        self.stop(self.host)
        path = self.execution / 'policy.json'
        policy = json.loads(path.read_text())
        policy['tenants'][0]['artifacts'] = [a for a in policy['tenants'][0]['artifacts'] if a['component'] != 'function3.wasm']
        path.write_text(json.dumps(policy))
        self.restart()
        self.assertEqual(self.run_as('alice')['status'], 'error')
        self.assertEqual(self.run_as('bob')['status'], 'ok')
        self.assertEqual(self.stats()['executions'], 1)

    def test_eviction_is_private_and_corrupt_disk_is_reverified(self):
        self.restart(compiled_cache_entries=1, cache_bytes=85000)
        self.assertEqual(self.run_as('bob')['status'], 'ok')
        self.assertEqual(self.run_as('alice')['status'], 'ok')
        self.assertEqual(self.run_as('alice', 'sha256-abc')['status'], 'ok')
        self.assertEqual(self.run_as('bob')['cache_status'], 'hit')
        sha = self.cases['platform']['sha256']
        bob_file = self.root / 'cache/tenants/bob/cache' / f'{sha}.wasm'
        self.assertTrue(bob_file.exists())
        self.assertFalse((self.root / 'cache/tenants/alice/cache' / f'{sha}.wasm').exists())
        self.stop(self.host)
        bob_file.write_bytes(b'broken')
        self.restart()
        repaired = self.run_as('bob')
        self.assertTrue(repaired['preparation']['repaired_corrupt_file'], repaired)

    def test_concurrent_preparation_shares_only_within_the_same_tenant(self):
        self.restart(max_inflight=4)
        self.files.delay = .1
        owners = ['alice', 'bob'] * 4
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(self.run_as, owners))
        self.assertTrue(all(r['status'] == 'ok' for r in rows), rows)
        self.assertEqual(self.stats()['downloads'], 2)
        self.assertEqual(self.stats()['compiles'], 2)
        self.assertEqual(self.stats()['executions'], 8)

    def test_management_results_ids_catalog_and_credentials_are_private(self):
        self.restart()
        manager = self.start_manager()
        alice, bob = self.client_token('alice'), self.client_token('bob')
        first = jobs.run_job(self.api, alice, 'platform', 'reuse', job_id='same-id')
        self.assertEqual(first['status'], 'completed', first)
        with self.assertRaises(HTTPError) as error:
            jobs.api(self.api, bob, '/v1/jobs/same-id')
        self.assertEqual(error.exception.code, 404)
        second = jobs.run_job(self.api, bob, 'sha256-abc', 'reuse', job_id='same-id')
        self.assertEqual(second['status'], 'completed', second)
        self.assertEqual(jobs.api(self.api, alice, '/v1/jobs/same-id')['request']['case'], 'platform')
        for token, endpoint, data, status in [(bob, '/v1/worker-stats', None, 403),
            (self.api_token, '/v1/jobs', {'case':'platform'}, 403),
            (alice, '/v1/jobs', {'case':'platform', 'tenant':'bob'}, 400)]:
            with self.assertRaises(HTTPError) as error:
                jobs.api(self.api, token, endpoint, data)
            self.assertEqual(error.exception.code, status)
        self.assertEqual(jobs.api(self.api, self.api_token, '/v1/worker-stats')['status'], 'ok')
        self.stop(manager)
        path = self.management / 'policy.json'
        policy = json.loads(path.read_text()); policy['tenants'][0]['cases'] = ['platform']; path.write_text(json.dumps(policy))
        self.start_manager()
        self.assertEqual(jobs.api(self.api, alice, '/v1/cases')['cases'], ['platform'])
        self.assertEqual(jobs.api(self.api, alice, '/v1/jobs/same-id')['status'], 'completed')
        with self.assertRaises(HTTPError):
            jobs.api(self.api, alice, '/v1/jobs', {'case':'clock'})

    def test_protected_file_server_requires_credential(self):
        import urllib.request
        url = f'http://127.0.0.1:{self.files.server_port}/function0.wasm'
        for method in ('GET', 'HEAD'):
            with self.assertRaises(HTTPError) as error:
                urllib.request.urlopen(urllib.request.Request(url, method=method))
            self.assertEqual(error.exception.code, 401)
        request = urllib.request.Request(url, headers={'Authorization':'Bearer ' + self.file_token})
        with urllib.request.urlopen(request) as response:
            self.assertEqual(hashlib.sha256(response.read()).hexdigest(), self.cases['sha256-abc']['sha256'])

    def test_tenant_capacity_does_not_consume_another_tenants_slots(self):
        for mode in ('wasm', 'native'):
            self.restart(mode, max_inflight=1)
            self.files.delay = .2
            with ThreadPoolExecutor(max_workers=4) as pool:
                rows = list(pool.map(lambda who: self.run_as(who, cache='bypass'), ['alice'] * 3 + ['bob']))
            self.assertEqual(sum(row['status'] == 'ok' for row in rows[:3]), 1, rows)
            self.assertEqual(rows[3]['status'], 'ok', rows)
            self.assertEqual(self.stats()['executions'], 2)

    def test_tenant_benchmarks_keep_all_five_workloads_working_in_both_modes(self):
        for mode in ('native', 'wasm'):
            with self.subTest(mode=mode):
                self.restart(mode)
                manager = self.start_manager()
                for cache in (('bypass',) if mode == 'native' else ('reuse', 'bypass')):
                    done = subprocess.run([sys.executable, '-B', str(ROOT / 'jobs.py'),
                        '--url', self.api, '--token-file', str(self.bundle / 'clients/alice.token'),
                        'bench', '--jobs', '20', '--concurrency', '2', '--cache', cache,
                        '--expect-mode', mode, '--output', str(self.root / f'bench-{mode}-{cache}')],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                    status = json.loads(done.stdout)
                    self.assertEqual(status['completed'], 20)
                    if cache == 'bypass':
                        self.assertEqual(status['cache_status_counts'], {'bypass':20})
                self.assertEqual(self.stats()['executions'], 20 if mode == 'native' else 40)
                self.stop(manager)


if __name__ == '__main__':
    program = unittest.main(verbosity=2, exit=False)
    if os.environ.get('HAL_TEST_RESULTS_DIR'):
        path = Path(os.environ['HAL_TEST_RESULTS_DIR']); path.mkdir(parents=True, exist_ok=True)
        (path / 'tenant-integration-tests.json').write_text(json.dumps(dict(
            tests_run=program.result.testsRun, failures=len(program.result.failures), errors=len(program.result.errors),
            passed=program.result.wasSuccessful(), hardware_tee_tested=False,
            host_sha256=hashlib.sha256((ROOT / 'dist/hal-on-demand').read_bytes()).hexdigest()), indent=2) + '\n')
    sys.exit(0 if program.result.wasSuccessful() else 1)
