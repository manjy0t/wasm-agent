#!/usr/bin/env python3
"""Real agent.wasm and HAL fixtures, with the agent-only policy enabled.

Local software checks, not TDX attestation or a cloud performance claim.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

import test_tenants as tenants
from test_system import ROOT
import jobs


class AgentPolicyTest(unittest.TestCase):
    start = tenants.TenantSystemTest.start
    stop = staticmethod(tenants.TenantSystemTest.stop)
    tearDown = tenants.TenantSystemTest.tearDown
    start_agent = tenants.TenantSystemTest.start_agent
    stats = tenants.TenantSystemTest.stats
    run_as = tenants.TenantSystemTest.run_as
    start_manager = tenants.TenantSystemTest.start_manager
    client_token = tenants.TenantSystemTest.client_token

    def setUp(self):
        tenants.TenantSystemTest.setUp(self)
        self.agent_policy = self.execution / 'agent-policy.json'
        done = subprocess.run([sys.executable, '-B', str(ROOT / 'configure_agent.py'),
            '--tenant-policy', str(self.execution / 'policy.json'), '--catalog', str(self.root / 'catalog.json'),
            '--output', str(self.agent_policy)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def change(self, owner='alice', case='platform', **values):
        policy = json.loads(self.agent_policy.read_text())
        row = next(r for r in policy['workloads'] if r['tenant'] == owner and r['component'] == self.cases[case]['artifact'])
        row.update(values)
        self.agent_policy.write_text(json.dumps(policy))

    def restart(self):
        self.stop(self.host)
        self.start_agent('--mode', 'wasm', '--transport', 'http',
            '--tenant-policy', str(self.execution / 'policy.json'),
            '--agent-policy', str(self.agent_policy),
            '--file-token-file', str(self.execution / 'file.token'))

    def test_real_guest_validates_all_five_workloads_and_cache_is_private(self):
        self.restart()
        for owner in ('alice', 'bob'):
            for case in self.cases:
                first = self.run_as(owner, case)
                self.assertEqual(first['status'], 'ok', first)
                self.assertEqual(first['agent_result_validation'], 'passed')
                self.assertEqual(first['cache_status'], 'miss')
                self.assertFalse(first['preparation']['stored'])
                self.assertEqual(first['host_calls']['authorize_cache'], 1)
                self.assertEqual(first['host_calls']['commit_result'], 1)
                self.assertEqual(first['result_sha256'], hashlib.sha256(bytes.fromhex(first['result']['hex'])).hexdigest())
                self.assertEqual(first['security_trace'], ['policy_accepted', 'prepared', 'executed_in_fresh_instance', 'result_committed'])
                hit = self.run_as(owner, case)
                self.assertEqual(hit['cache_status'], 'hit')
                self.assertTrue(hit['agent_worker_reused'])
                self.assertEqual(hit['agent_worker_job_number'], 2)
                self.assertEqual(hit['agent_security']['policy_sha256'], hashlib.sha256(self.agent_policy.read_bytes()).hexdigest())
        self.assertEqual(self.stats()['downloads'], 10)
        self.assertEqual(self.stats()['compiled_entries'], 10)
        self.assertFalse(list((self.root / 'cache').rglob('*.wasm')))

    def test_expiry_and_restart_require_new_downloads(self):
        self.change(cache_ttl_ms=1000)
        self.restart()
        self.assertEqual(self.run_as('alice')['cache_status'], 'miss')
        self.assertEqual(self.run_as('alice')['cache_status'], 'hit')
        time.sleep(1.1)
        self.assertEqual(self.stats()['compiled_entries'], 0)
        self.assertEqual(self.stats()['cache_expirations'], 1)
        self.assertEqual(self.run_as('alice')['preparation']['source'], 'download')
        self.restart()
        self.assertEqual(self.run_as('alice')['preparation']['source'], 'download')

    def test_policy_disables_cache_and_request_cannot_override_it(self):
        self.change(cache='disabled')
        self.restart()
        for _ in range(2):
            row = self.run_as('alice', cache='reuse', validation={'kind':'bounded'}, agent_policy={'cache':'memory'})
            self.assertEqual(row['status'], 'ok', row)
            self.assertEqual(row['requested_cache_policy'], 'reuse')
            self.assertEqual(row['cache_policy'], 'bypass')
            self.assertEqual(row['cache_status'], 'bypass')
            self.assertNotIn('find_prepared', row['host_calls'])
        self.assertEqual(self.stats()['compiled_entries'], 0)
        self.assertEqual(self.stats()['downloads'], 2)
        self.assertFalse(list((self.root / 'cache').rglob('*.wasm')))

    def test_bypass_does_not_read_or_replace_existing_memory_entry(self):
        self.restart()
        self.run_as('alice')
        bypass = self.run_as('alice', cache='bypass')
        self.assertEqual(bypass['preparation']['source'], 'download')
        self.assertEqual(bypass['cache_status'], 'bypass')
        self.assertEqual(self.run_as('alice')['cache_status'], 'hit')
        self.assertEqual(self.stats()['downloads'], 2)

    def test_old_disk_cache_is_not_loaded_or_deleted(self):
        # Seed a deliberately corrupt old cache that exceeds the new byte quota.
        directory = self.root / 'cache/tenants/alice/cache'
        for parent in (directory.parent.parent, directory.parent, directory):
            parent.mkdir(mode=0o700, exist_ok=True)
        old = directory / (self.cases['platform']['sha256'] + '.wasm')
        old.write_bytes(b'old-cache-content')
        path = self.execution / 'policy.json'
        policy = json.loads(path.read_text())
        policy['tenants'][0]['cache_bytes'] = 1
        path.write_text(json.dumps(policy))
        self.restart()
        result = self.run_as('alice')
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(result['preparation']['source'], 'download')
        self.assertEqual(old.read_bytes(), b'old-cache-content')
        self.assertEqual(self.stats()['compiled_entries'], 0)

    def test_agent_instance_is_scoped_to_workload_and_recycled(self):
        self.change(worker_max_jobs=2)
        self.restart()
        first = self.run_as('alice')
        other = self.run_as('alice', 'sha256-abc')
        second = self.run_as('alice')
        third = self.run_as('alice')
        self.assertFalse(first['agent_worker_reused'])
        self.assertFalse(other['agent_worker_reused'])
        self.assertTrue(second['agent_worker_reused'])
        self.assertEqual(second['agent_worker_job_number'], 2)
        self.assertFalse(third['agent_worker_reused'])
        self.assertEqual(third['agent_worker_job_number'], 1)
        self.assertEqual(third['cache_status'], 'hit')

    def test_denied_hal_crypto_cannot_run_even_for_authorized_artifact(self):
        self.change(case='sha256-abc', hal_permissions=[])
        self.restart()
        denied = self.run_as('alice', 'sha256-abc')
        self.assertEqual(denied['status'], 'error', denied)
        self.assertNotIn('result', denied)
        self.assertEqual(self.run_as('alice')['status'], 'ok')
        self.assertEqual(self.run_as('bob', 'sha256-abc')['status'], 'ok')

    def test_invalid_result_is_not_returned_and_agent_is_discarded(self):
        self.change(validation={'kind':'hex', 'value':'00'})
        self.restart()
        for _ in range(2):
            row = self.run_as('alice', validation={'kind':'bounded'})
            self.assertEqual(row['status'], 'error', row)
            self.assertIn('result validation failed', row['error'])
            self.assertNotIn('result', row)
            self.assertNotIn('commit_result', row['host_calls'])
            self.assertFalse(row['agent_worker_reused'])

    def test_per_workload_output_and_fuel_limits(self):
        self.change(max_output_bytes=8, validation={'kind':'bounded'})
        self.change(case='sha256-abc', fuel=1)
        self.restart()
        for case in ('platform', 'sha256-abc'):
            row = self.run_as('alice', case)
            self.assertEqual(row['status'], 'error', row)
            self.assertNotIn('result', row)
        self.assertEqual(self.run_as('bob')['status'], 'ok')

    def test_unauthorized_agent_workload_denied_before_download(self):
        policy = json.loads(self.agent_policy.read_text())
        policy['workloads'] = [r for r in policy['workloads'] if not (r['tenant']=='alice' and r['component']=='function3.wasm')]
        self.agent_policy.write_text(json.dumps(policy))
        self.restart()
        self.assertEqual(self.run_as('alice')['status'], 'error')
        self.assertEqual(self.stats()['downloads'], 0)
        self.assertEqual(self.run_as('bob')['status'], 'ok')

    def test_parallel_preparation_is_shared_within_owner_only(self):
        self.restart()
        self.files.delay = .15
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(self.run_as, ['alice', 'bob'] * 4))
        self.assertTrue(all(r['status'] == 'ok' for r in rows), rows)
        self.assertEqual(self.stats()['downloads'], 2)
        self.assertEqual(self.stats()['compiles'], 2)
        self.assertEqual(self.stats()['executions'], 8)

    def test_cache_byte_budget_evicts_code_without_affecting_other_owner(self):
        path = self.execution / 'policy.json'
        policy = json.loads(path.read_text())
        policy['tenants'][0]['cache_bytes'] = 85000
        path.write_text(json.dumps(policy))
        self.restart()
        self.run_as('bob')
        self.run_as('alice')
        self.run_as('alice', 'sha256-abc')
        self.assertEqual(self.stats()['compiled_entries'], 2)
        self.assertEqual(self.run_as('bob')['cache_status'], 'hit')
        self.assertEqual(self.run_as('alice')['cache_status'], 'miss')

    def test_invalid_policy_and_changed_agent_are_rejected_at_startup(self):
        original = json.loads(self.agent_policy.read_text())
        for label in ('digest', 'permission', 'unknown-field', 'fuel'):
            policy = json.loads(json.dumps(original))
            if label == 'digest': policy['agent_sha256'] = '0' * 64
            if label == 'permission': policy['workloads'][0]['hal_permissions'] = ['sockets']
            if label == 'unknown-field': policy['workloads'][0]['ignored_security_setting'] = True
            if label == 'fuel': policy['workloads'][0]['fuel'] = 1000000001
            self.agent_policy.write_text(json.dumps(policy))
            done = subprocess.run([str(ROOT / 'dist/hal-on-demand'), '--allow-non-tee', '--mode', 'wasm',
                '--file-server', 'http://127.0.0.1:1/', '--token-file', str(self.execution / 'operator.token'),
                '--tenant-policy', str(self.execution / 'policy.json'), '--agent-policy', str(self.agent_policy),
                '--cache-dir', str(self.root / ('invalid-' + label))], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(done.returncode, 0, label)
            self.assertNotIn('"ready"', done.stdout)

    def test_management_benchmarks_use_the_secured_agent(self):
        self.restart()
        self.start_manager()
        for cache in ('reuse', 'bypass'):
            done = subprocess.run([sys.executable, '-B', str(ROOT / 'jobs.py'), '--url', self.api,
                '--token-file', str(self.bundle / 'clients/alice.token'), 'bench', '--jobs', '100',
                '--concurrency', '2', '--cache', cache, '--expect-mode', 'wasm',
                '--output', str(self.root / ('bench-' + cache))], capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertEqual(json.loads(done.stdout)['completed'], 100)
        self.assertEqual(self.stats()['executions'], 200)
        self.assertEqual(self.stats()['downloads'], 105)


if __name__ == '__main__':
    program = unittest.main(verbosity=2, exit=False)
    if os.environ.get('HAL_TEST_RESULTS_DIR'):
        output = Path(os.environ['HAL_TEST_RESULTS_DIR']); output.mkdir(parents=True, exist_ok=True)
        (output / 'agent-policy-tests.json').write_text(json.dumps(dict(tests_run=program.result.testsRun,
            failures=len(program.result.failures), errors=len(program.result.errors), passed=program.result.wasSuccessful(),
            hardware_tee_tested=False, agent_sha256=hashlib.sha256((ROOT/'dist/agent.wasm').read_bytes()).hexdigest()), indent=2)+'\n')
    sys.exit(0 if program.result.wasSuccessful() else 1)
