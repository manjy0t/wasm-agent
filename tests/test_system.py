#!/usr/bin/env python3
"""Functional integration tests using the real Wasm agent and real HAL components.

These tests deliberately use NON_TEE_TEST_ONLY on the development machine.
"""
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
VALIDATION = Path(os.environ.get('HAL_TEST_RESULTS_DIR', str(ROOT / 'validation')))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'server'))
import jobs
from management import agent_request, worker_http_request, validate_result, WorkerHTTPClient
from file_server import Handler as ArtifactHandler, HTTPServer as ArtifactServer


class FixtureHandler(ArtifactHandler):
    def setup(self):
        super().setup()
        with self.server.count_lock:
            self.server.peers.add(self.client_address)

    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.count_lock:
            self.server.downloads.append(self.path)
        if self.server.fail:
            self.send_error(503)
            return
        time.sleep(self.server.delay)
        super().do_GET()


class SystemTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hal-on-demand-test-')
        self.root = Path(self.temporary.name)
        self.processes = []
        self.logs = []
        self.token = 'agent-token-' + 'a' * 40
        self.api_token = 'api-token-' + 'b' * 40
        (self.root / 'agent.token').write_text(self.token)
        (self.root / 'api.token').write_text(self.api_token)
        catalog = json.loads((ROOT / 'workloads.json').read_text())
        self.cases = {case['name']: case for case in catalog['cases']}
        self.cases['platform']['validation']['value'] = 'AmdSev|'
        (self.root / 'catalog.json').write_text(json.dumps(catalog))
        for case in self.cases.values():
            data = (ROOT / 'tests/workloads' / case['artifact']).read_bytes()
            self.assertEqual(len(data), case['artifact_bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), case['sha256'])
        handler = partial(FixtureHandler, directory=ROOT / 'tests/workloads', max_bytes=16 * 1024 * 1024)
        self.files = ArtifactServer(('127.0.0.1', 0), handler)
        self.files.downloads = []
        self.files.count_lock = threading.Lock()
        self.files.peers = set()
        self.files.delay = 0.1
        self.files.fail = False
        self.files_thread = threading.Thread(target=self.files.serve_forever, daemon=True)
        self.files_thread.start()
        self.start_agent()

    def tearDown(self):
        for process in reversed(self.processes):
            self.stop(process)
        self.files.shutdown()
        self.files.server_close()
        for stream in self.logs:
            stream.close()
        self.temporary.cleanup()

    def start(self, command):
        log = self.root / f'process-{len(self.processes)}.log'
        stream = log.open('w')
        self.logs.append(stream)
        process = subprocess.Popen(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
            umask=getattr(self, 'process_umask', -1))
        self.processes.append(process)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for line in log.read_text().splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get('status') == 'ready':
                    return process, event
            if process.poll() is not None:
                self.fail(f'process exited: {log.read_text()}')
            time.sleep(.02)
        self.fail(f'process did not become ready: {log.read_text()}')

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def start_agent(self, *extra, agent_path=None):
        binary = os.environ.get('HAL_ON_DEMAND_BIN', str(ROOT / 'dist/hal-on-demand'))
        self.host, self.ready = self.start([
            binary, '--agent', str(agent_path or ROOT / 'dist/agent.wasm'), '--listen', '127.0.0.1:0',
            '--token-file', str(self.root / 'agent.token'), '--cache-dir', str(self.root / 'cache'),
            '--file-server', f'http://127.0.0.1:{self.files.server_port}/', '--allow-non-tee',
            *extra,
        ])
        host, port = self.ready['listen'].rsplit(':', 1)
        self.address = (host, int(port))
        self.worker_url = f'http://{host}:{port}' if self.ready.get('transport') == 'http' else None

    def start_manager(self, *extra):
        transport = ['--worker-url', self.worker_url] if self.worker_url else []
        process, ready = self.start([
            sys.executable, str(ROOT / 'server/management.py'), '--port', '0',
            '--catalog', str(self.root / 'catalog.json'), '--agent-host', self.address[0],
            '--agent-port', str(self.address[1]), '--agent-token-file', str(self.root / 'agent.token'),
            '--api-token-file', str(self.root / 'api.token'), '--state-dir', str(self.root / 'manager'),
            *transport, *extra,
        ])
        self.api = f'http://127.0.0.1:{ready["listen"][1]}'
        return process

    def stats(self):
        if self.worker_url:
            return jobs.api(self.worker_url, self.token, '/v1/stats')['stats']
        return agent_request(self.address, self.token, {'op': 'stats'}, 10)['stats']

    def run_case(self, case='sha256-abc', **changes):
        item = self.cases[case]
        request = {'protocol': 1, 'op': 'run', 'job_id': 'job-' + str(time.time_ns()),
                   'component': item['artifact'], 'sha256': item['sha256'],
                   'artifact_bytes': item['artifact_bytes'],
                   'cache': 'bypass' if self.ready.get('execution_mode') == 'native' else 'reuse'}
        request.update(changes)
        if self.worker_url:
            return worker_http_request(self.worker_url, self.token, request, 30)
        return agent_request(self.address, self.token, request, 30)

    def test_native_http_has_no_agent_and_executes_five_workloads(self):
        self.stop(self.host)
        self.start_agent('--mode', 'native', '--transport', 'http',
                         agent_path=self.root / 'does-not-exist.wasm')
        self.assertEqual(self.ready['execution_mode'], 'native')
        self.assertEqual(self.ready['agent_kind'], 'none')
        self.assertIsNone(self.ready['agent_sha256'])
        self.assertEqual(self.stats()['downloads'], 0)
        self.start_manager()
        for name in self.cases:
            result = jobs.run_job(self.api, self.api_token, name, 'bypass')
            self.assertEqual(result['status'], 'completed', result)
            response = result['response']
            worker = response['agent']
            self.assertEqual(response['dispatch_transport'], 'http')
            self.assertEqual(worker['execution_mode'], 'native')
            self.assertEqual(worker['agent_kind'], 'none')
            self.assertEqual(worker['cache_status'], 'bypass')
            self.assertIsNone(worker['agent_sha256'])
            self.assertIsNone(worker['agent_instance'])
            self.assertFalse(worker['agent_worker_reused'])
            self.assertTrue(worker['runtime_reused'])
            self.assertNotIn('agent_worker_job_number', worker)
            self.assertNotIn('agent_job', worker['timings_ms'])
            self.assertFalse(worker['attestation_verified'])
        self.assertEqual(self.stats()['downloads'], 5)
        self.assertEqual(self.stats()['compiles'], 5)
        first = self.run_case()
        self.assertEqual(first['cache_status'], 'bypass')
        self.assertFalse(first['preparation']['stored'])
        rejected = self.run_case(cache='reuse')
        self.assertEqual(rejected['status'], 'error')
        self.assertIn('no code cache', rejected['error'])
        self.files.fail = True
        unavailable = self.run_case()
        self.assertEqual(unavailable['status'], 'error', unavailable)
        self.assertEqual(self.stats()['executions'], 6)
        self.assertEqual(self.stats()['downloads'], 7)
        self.assertEqual(self.stats()['compiled_entries'], 0)
        self.assertEqual(self.stats()['shared_preparations'], 0)

    def test_native_http_rejects_auth_bad_hash_size_and_invalid_body(self):
        self.stop(self.host)
        self.start_agent('--mode', 'native', '--transport', 'http')
        with self.assertRaises(HTTPError) as context:
            jobs.api(self.worker_url, 'wrong', '/v1/stats')
        self.assertEqual(context.exception.code, 401)
        for body, code in (([], 400), ({'padding': 'x' * 20000}, 413)):
            with self.assertRaises(HTTPError) as context:
                jobs.api(self.worker_url, self.token, '/v1/run', body)
            self.assertEqual(context.exception.code, code)
        bad = self.run_case(sha256='0' * 64)
        self.assertEqual(bad['status'], 'error', bad)
        self.assertEqual(self.stats()['compiles'], 0)
        self.assertEqual(self.stats()['executions'], 0)
        self.assertEqual(self.run_case()['status'], 'ok')
        self.assertEqual(self.run_case(artifact_bytes=9)['status'], 'error')
        self.assertEqual(self.stats()['executions'], 1)

    def test_http_benchmark_both_modes_and_wrong_mode_detection(self):
        for mode in ('native', 'wasm'):
            with self.subTest(mode=mode):
                self.stop(self.host)
                self.start_agent('--mode', mode, '--transport', 'http')
                manager = self.start_manager()
                policy = 'bypass' if mode == 'native' else 'reuse'
                output = self.root / ('http-benchmark-' + mode)
                completed = subprocess.run([
                    sys.executable, str(ROOT / 'jobs.py'), '--url', self.api,
                    '--token-file', str(self.root / 'api.token'), 'bench', '--jobs', '100',
                    '--concurrency', '8', '--expect-mode', mode, '--expect-isolation', 'in-process',
                    '--cache', policy,
                    '--output', str(output),
                ], cwd=ROOT, capture_output=True, text=True, timeout=90)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                status = json.loads((output / 'status.json').read_text())
                self.assertEqual(status['completed'], 100)
                self.assertEqual(status['execution_modes'], {mode: 100})
                self.assertEqual(status['workload_isolations'], {'in-process': 100})
                self.assertEqual(self.stats()['compiles'], 100 if mode == 'native' else 5)
                self.assertEqual(self.stats()['executions'], 100)
                # The native baseline leaves no code cache for the agent.
                self.assertEqual(self.stats()['downloads'], 100 if mode == 'native' else 5)
                wrong = subprocess.run([
                    sys.executable, str(ROOT / 'jobs.py'), '--url', self.api,
                    '--token-file', str(self.root / 'api.token'), 'bench', '--jobs', '1',
                    '--expect-mode', 'wasm' if mode == 'native' else 'native',
                    '--cache', policy,
                    '--output', str(self.root / ('wrong-mode-' + mode)),
                ], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(wrong.returncode, 1, wrong.stdout + wrong.stderr)
                wrong_status = json.loads((self.root / ('wrong-mode-' + mode) / 'status.json').read_text())
                self.assertEqual(wrong_status['statuses'], {'mode_mismatch': 1})
                wrong_config = subprocess.run([
                    sys.executable, str(ROOT / 'jobs.py'), '--url', self.api,
                    '--token-file', str(self.root / 'api.token'), 'bench', '--jobs', '1',
                    '--expect-compile-opt-level', 'none',
                    '--cache', policy,
                    '--output', str(self.root / ('wrong-config-' + mode)),
                ], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(wrong_config.returncode, 1, wrong_config.stdout + wrong_config.stderr)
                config_status = json.loads((self.root / ('wrong-config-' + mode) / 'status.json').read_text())
                self.assertEqual(config_status['statuses'], {'configuration_mismatch': 1})
                wrong_isolation = subprocess.run([
                    sys.executable, str(ROOT / 'jobs.py'), '--url', self.api,
                    '--token-file', str(self.root / 'api.token'), 'bench', '--jobs', '1',
                    '--expect-isolation', 'per-user-container',
                    '--cache', policy,
                    '--output', str(self.root / ('wrong-isolation-' + mode)),
                ], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(wrong_isolation.returncode, 1, wrong_isolation.stdout + wrong_isolation.stderr)
                isolation_status = json.loads((self.root / ('wrong-isolation-' + mode) / 'status.json').read_text())
                self.assertEqual(isolation_status['statuses'], {'isolation_mismatch': 1})
                self.stop(manager)

    def test_concurrent_cold_requests_share_download_and_compile(self):
        self.assertEqual(self.stats()['downloads'], 0)  # Nothing prefetched.
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.run_case(), range(12)))
        for result in results:
            self.assertEqual(result['status'], 'ok', result)
            validate_result(result, self.cases['sha256-abc'])
            self.assertFalse(result['workload_instance_reused'])
            self.assertTrue(result['runtime_reused'])
        stats = self.stats()
        self.assertEqual(stats['downloads'], 1)
        self.assertEqual(stats['compiles'], 1)
        self.assertEqual(stats['executions'], 12)
        self.assertGreater(stats['shared_preparations'], 0)

    def test_five_workloads_and_persistent_agent(self):
        for name, case in self.cases.items():
            first = self.run_case(name)
            second = self.run_case(name)
            for result in (first, second):
                self.assertEqual(result['status'], 'ok', result)
                validate_result(result, case)
                self.assertTrue(result['non_tee_test_mode'])
                self.assertFalse(result['attestation_verified'])
            self.assertEqual(first['cache_status'], 'miss')
            self.assertEqual(second['cache_status'], 'hit')
            self.assertTrue(second['agent_worker_reused'])
            self.assertGreater(second['agent_worker_job_number'], first['agent_worker_job_number'])
            self.assertNotIn('preparation', second)
            if name == 'random-32':
                self.assertNotEqual(first['result']['hex'], second['result']['hex'])
        self.assertEqual(self.stats()['compiles'], 5)

    def test_bypass_redownloads_and_recompiles(self):
        self.assertEqual(self.run_case()['status'], 'ok')
        self.assertEqual(self.run_case(cache='bypass')['cache_status'], 'bypass')
        self.assertEqual(self.run_case(cache='bypass')['cache_status'], 'bypass')
        self.files.fail = True
        self.assertEqual(self.run_case()['cache_status'], 'hit')
        self.assertEqual(self.stats()['downloads'], 3)
        self.assertEqual(self.stats()['compiles'], 3)

    def test_fast_compilation_bypass_at_concurrency_six_in_both_modes(self):
        self.files.delay = 0
        for mode in ('wasm', 'native'):
            for parallel in ('true', 'false'):
                with self.subTest(mode=mode, parallel=parallel):
                    self.stop(self.host)
                    self.start_agent('--mode', mode, '--transport', 'http',
                                     '--compile-opt-level', 'none', '--parallel-compilation', parallel,
                                     '--compilers', '3', '--executions', '7')
                    manager = self.start_manager('--dispatchers', '6')
                    names = list(self.cases)
                    with ThreadPoolExecutor(max_workers=6) as pool:
                        results = list(pool.map(lambda i: jobs.run_job(
                            self.api, self.api_token, names[i % len(names)], 'bypass'), range(30)))
                    for row in results:
                        self.assertEqual(row['status'], 'completed', row)
                        worker = row['response']['agent']
                        self.assertEqual(worker['cache_status'], 'bypass')
                        self.assertEqual(worker['preparation']['source'], 'download')
                        self.assertFalse(worker['preparation']['stored'])
                        self.assertFalse(worker['workload_instance_reused'])
                        self.assertEqual(worker['configuration']['compile_opt_level'], 'none')
                        self.assertEqual(worker['configuration']['parallel_compilation'], parallel == 'true')
                    self.assertTrue(any(r['response']['dispatch_connection_reused'] for r in results))
                    self.assertEqual(self.stats()['downloads'], 30)
                    self.assertEqual(self.stats()['compiles'], 30)
                    self.assertEqual(self.stats()['executions'], 30)
                    self.assertEqual(self.stats()['compiled_entries'], 0)
                    self.assertFalse(list((self.root / 'cache').glob('*.wasm')))
                    self.stop(manager)

    def test_dedicated_compilation_resource_audit_in_both_modes(self):
        self.files.delay = 0
        for mode in ('wasm', 'native'):
            with self.subTest(mode=mode):
                self.stop(self.host)
                self.start_agent('--mode', mode, '--transport', 'http', '--compile-opt-level', 'none',
                                 '--compiler-threads', '2', '--compilers', '3')
                manager = self.start_manager('--dispatchers', '6')
                output = self.root / ('resources-' + mode)
                done = subprocess.run([
                    sys.executable, '-B', str(ROOT / 'jobs.py'), '--url', self.api,
                    '--token-file', str(self.root / 'api.token'), 'bench', '--jobs', '30',
                    '--concurrency', '6', '--cache', 'bypass', '--expect-mode', mode,
                    '--expect-compile-opt-level', 'none', '--record-host-stats', '--output', str(output),
                ], cwd=ROOT, capture_output=True, text=True, timeout=60)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                report = json.loads((output / 'host-resources.json').read_text())
                self.assertTrue(report['valid'], report)
                self.assertEqual(report['counter_deltas'], dict(downloads=30, compiles=30,
                                                               executions=30, shared_preparations=0))
                self.assertGreater(report['resources']['host_cpu_ms'], 0)
                self.assertGreater(report['resources']['host_lifetime_peak_rss_mib'], 0)
                self.assertEqual(report['after']['stats']['compiler']['dedicated_threads'], 2)
                self.assertEqual(report['after']['stats']['compiler']['finished'], 30)
                for line in (output / 'jobs.jsonl').read_text().splitlines():
                    worker = json.loads(line)['response']['agent']
                    for field in ('store_create', 'store_drop', 'component_release'):
                        self.assertGreaterEqual(worker['timings_ms'][field], 0)
                    self.assertEqual(worker['configuration']['compiler_pool'], 'dedicated')
                with self.assertRaises(HTTPError) as error:
                    jobs.api(self.api, 'wrong-token', '/v1/worker-stats')
                self.assertEqual(error.exception.code, 401)
                self.assertFalse(list((self.root / 'cache').glob('*.wasm')))
                self.stop(manager)

    def test_http_control_connection_reuse_and_server_opt_out(self):
        for keep in ('true', 'false'):
            with self.subTest(keep_alive=keep):
                self.stop(self.host)
                self.start_agent('--transport', 'http', '--http-keep-alive', keep)
                client = WorkerHTTPClient(self.worker_url, self.token, 10)
                case = self.cases['platform']
                payload = {'protocol': 1, 'job_id': 'persistent-1', 'cache': 'bypass',
                           'component': case['artifact'], 'sha256': case['sha256'],
                           'artifact_bytes': case['artifact_bytes']}
                try:
                    self.assertEqual(client.request(payload)['status'], 'ok')
                    self.assertFalse(client.last_connection_reused)
                    payload['job_id'] = 'persistent-2'
                    self.assertEqual(client.request(payload)['status'], 'ok')
                    self.assertEqual(client.last_connection_reused, keep == 'true')
                    client.token = 'wrong'
                    with self.assertRaises(HTTPError) as context:
                        client.request(payload)
                    self.assertEqual(context.exception.code, 401)
                    self.assertIsNone(client.connection)
                    self.assertEqual(self.stats()['executions'], 2)
                finally:
                    client.close()

    def test_file_server_reuses_connection_but_still_serves_every_fetch(self):
        client = http.client.HTTPConnection('127.0.0.1', self.files.server_port, timeout=10)
        try:
            first_socket = None
            for i in range(3):
                client.request('GET', '/function0.wasm')
                with client.getresponse() as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.getheader('Cache-Control'), 'no-store')
                    self.assertEqual(len(response.read()), self.cases['sha256-abc']['artifact_bytes'])
                if i == 0:
                    first_socket = client.sock
                    self.assertIsNotNone(first_socket)
                self.assertIs(client.sock, first_socket)
            self.assertEqual(len(self.files.peers), 1)
            self.assertEqual(len(self.files.downloads), 3)
        finally:
            client.close()

    def test_restart_reuses_verified_file_but_recompiles(self):
        self.assertEqual(self.run_case()['status'], 'ok')
        self.stop(self.host)
        self.files.fail = True
        self.start_agent()
        result = self.run_case()
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(result['preparation']['source'], 'disk')
        self.assertEqual(self.stats()['downloads'], 0)
        self.assertEqual(self.stats()['compiles'], 1)

    def test_hash_mismatch_never_compiles_or_executes_and_recovers(self):
        result = self.run_case(sha256='0' * 64)
        self.assertEqual(result['status'], 'error')
        self.assertIn('SHA-256 mismatch', result['error'])
        self.assertEqual(self.stats()['compiles'], 0)
        self.assertEqual(self.stats()['executions'], 0)
        self.assertEqual(self.run_case()['status'], 'ok')

    def test_rejects_wrong_size_even_on_compiled_hit(self):
        self.assertEqual(self.run_case()['status'], 'ok')
        self.assertEqual(self.run_case(artifact_bytes=9)['status'], 'error')
        self.assertEqual(self.stats()['executions'], 1)

    def test_corrupt_disk_entry_repaired(self):
        self.assertEqual(self.run_case()['status'], 'ok')
        self.stop(self.host)
        cached = self.root / 'cache' / (self.cases['sha256-abc']['sha256'] + '.wasm')
        cached.write_bytes(b'broken')
        self.start_agent()
        result = self.run_case()
        self.assertEqual(result['status'], 'ok', result)
        self.assertTrue(result['preparation']['repaired_corrupt_file'])

    def test_lru_eviction_recompiles_from_disk(self):
        self.stop(self.host)
        self.start_agent('--compiled-cache-entries', '1')
        self.run_case('sha256-abc')
        self.run_case('sha512-abc')
        self.files.fail = True
        result = self.run_case('sha256-abc')
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(result['preparation']['source'], 'disk')
        self.assertEqual(self.stats()['compiled_entries'], 1)
        self.assertEqual(self.stats()['compiles'], 3)

    def test_auth_paths_unsupported_arguments_and_missing_file(self):
        response = agent_request(self.address, 'wrong', {'op': 'stats'}, 10)
        self.assertEqual(response['status'], 'error')
        for fields in ({'component': '../function0.wasm'}, {'input': 'abc'}, {'cache': 'anything'}):
            self.assertEqual(self.run_case(**fields)['status'], 'error')
        self.assertEqual(self.run_case(component='missing.wasm')['status'], 'error')
        self.assertEqual(self.stats()['executions'], 0)

    def test_management_idempotency_validation_and_restart(self):
        manager = self.start_manager()
        first = jobs.run_job(self.api, self.api_token, 'sha256-abc', 'reuse', job_id='same-id')
        self.assertEqual(first['status'], 'completed', first)
        again = jobs.api(self.api, self.api_token, '/v1/jobs',
                         {'job_id': 'same-id', 'case': 'sha256-abc'})
        self.assertEqual(again['status'], 'completed')
        self.assertEqual(self.stats()['executions'], 1)
        with self.assertRaises(HTTPError) as context:
            jobs.api(self.api, self.api_token, '/v1/jobs', {'job_id': 'same-id', 'case': 'clock'})
        self.assertEqual(context.exception.code, 409)
        with self.assertRaises(HTTPError) as context:
            jobs.api(self.api, 'wrong', '/v1/cases')
        self.assertEqual(context.exception.code, 401)
        self.stop(manager)
        self.start_manager()
        recovered = jobs.api(self.api, self.api_token, '/v1/jobs/same-id')
        self.assertEqual(recovered['response']['result_validation'], 'passed')

    def test_management_queue_is_bounded(self):
        self.files.delay = .8
        self.start_manager('--dispatchers', '1', '--queue-size', '1')
        accepted = 0
        rejected = 0
        for index in range(10):
            try:
                jobs.api(self.api, self.api_token, '/v1/jobs', {'case': 'sha256-abc', 'job_id': f'queue-{index}'})
                accepted += 1
            except HTTPError as error:
                self.assertEqual(error.code, 429)
                rejected += 1
        self.assertLessEqual(accepted, 2)
        self.assertGreater(rejected, 0)

    def test_native_inflight_limit_rejects_excess_jobs_without_execution(self):
        self.stop(self.host)
        self.start_agent('--max-inflight', '2')
        self.files.delay = .5
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: self.run_case(), range(8)))
        successes = sum(r['status'] == 'ok' for r in responses)
        busy = [r for r in responses if r['status'] == 'busy']
        self.assertEqual(successes, 2, responses)
        self.assertEqual(len(busy), 6)
        self.assertTrue(all(r['executed'] is False for r in busy))
        self.assertEqual(self.stats()['executions'], 2)

    def test_management_crash_does_not_replay_dispatched_job(self):
        self.files.delay = .8
        manager = self.start_manager()
        jobs.api(self.api, self.api_token, '/v1/jobs', {'case': 'sha256-abc', 'job_id': 'interrupted'})
        deadline = time.monotonic() + 5
        while not self.files.downloads and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(self.files.downloads)
        manager.kill()
        manager.wait(timeout=5)
        self.start_manager()
        recovered = jobs.api(self.api, self.api_token, '/v1/jobs/interrupted')
        self.assertEqual(recovered['status'], 'unknown')
        time.sleep(1)
        self.assertEqual(self.stats()['executions'], 1)

    def test_actual_client_100_jobs_no_prefetch(self):
        self.start_manager()
        output = self.root / 'benchmark'
        completed = subprocess.run([
            sys.executable, str(ROOT / 'jobs.py'), '--url', self.api, '--token-file', str(self.root / 'api.token'),
            'bench', '--jobs', '100', '--concurrency', '8', '--output', str(output),
        ], cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        status = json.loads((output / 'status.json').read_text())
        self.assertEqual(status['completed'], 100)
        self.assertEqual(status['failed_or_unknown'], 0)
        self.assertEqual(len((output / 'jobs.jsonl').read_text().splitlines()), 100)
        self.assertEqual(self.stats()['downloads'], 5)
        self.assertEqual(self.stats()['compiles'], 5)
        self.assertEqual(self.stats()['executions'], 100)
        if os.environ.get('HAL_KEEP_TEST_RESULTS') == '1':
            import shutil
            destination = VALIDATION / 'software-stream-100'
            destination.parent.mkdir(exist_ok=True)
            shutil.copytree(output, destination, dirs_exist_ok=True)
            (destination / 'verification.json').write_text(json.dumps({
                'software_test_only': True, 'hardware_tee_tested': False,
                'native_statistics': self.stats(), 'expected_jobs': 100,
                'file_server_artificial_delay_seconds': self.files.delay,
                'note': 'Functional verification, not TDX performance results.',
            }, indent=2) + '\n')


class BenchmarkAuditTest(unittest.TestCase):
    def test_host_restart_extra_downloads_and_unfinished_work_invalidate_a_batch(self):
        import copy
        before = {'status': 'ok', 'instance': 'host-1', 'host_sha256': 'same-build',
                  'agent_sha256': 'same-agent', 'execution_mode': 'wasm', 'configuration': {},
                  'requests_inflight': 0, 'uptime_ms': 100,
                  'stats': dict(downloads=0, compiles=0, executions=0, shared_preparations=0,
                                compiler={'occupied_slots': 0}),
                  'process_resources': dict(available=True, user_cpu_ms=10, system_cpu_ms=1, peak_rss_mib=30)}
        after = copy.deepcopy(before)
        after['uptime_ms'] = 110
        after['stats'].update(downloads=1, compiles=1, executions=1)
        after['process_resources'].update(user_cpu_ms=16, system_cpu_ms=3)
        rows = [{'status': 'completed', 'response': {'agent': {
            'host_instance': 'host-1', 'host_sha256': 'same-build',
            'configuration': {}, 'execution_mode': 'wasm'}}}]
        valid = jobs.host_batch_metrics(before, after, rows, 'bypass')
        self.assertTrue(valid['valid'], valid)
        self.assertEqual(valid['resources']['average_cpu_cores_used'], .8)
        for change in ('restart', 'extra_download', 'unfinished'):
            with self.subTest(change=change):
                changed = copy.deepcopy(after)
                if change == 'restart':
                    changed['instance'] = 'host-2'
                elif change == 'extra_download':
                    changed['stats']['downloads'] += 1
                else:
                    changed['stats']['compiler']['occupied_slots'] = 1
                self.assertFalse(jobs.host_batch_metrics(before, changed, rows, 'bypass')['valid'])


class DispatchFailureTest(unittest.TestCase):
    def test_lost_response_is_not_replayed_and_next_job_can_reconnect(self):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                self.server.seen.append(request['job_id'])
                if request['job_id'] == 'lost-response':
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'{}')

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.seen = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = WorkerHTTPClient(f'http://127.0.0.1:{server.server_port}', 'test-token', 3)
        try:
            with self.assertRaises((http.client.HTTPException, OSError)):
                client.request({'job_id': 'lost-response'})
            self.assertEqual(server.seen, ['lost-response'])
            self.assertIsNone(client.connection)
            self.assertEqual(client.request({'job_id': 'next-job'}), {})
            self.assertEqual(server.seen, ['lost-response', 'next-job'])
        finally:
            client.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    if '--keep-results' in sys.argv:
        os.environ['HAL_KEEP_TEST_RESULTS'] = '1'
        sys.argv.remove('--keep-results')
    program = unittest.main(verbosity=2, exit=False)
    if os.environ.get('HAL_KEEP_TEST_RESULTS') == '1':
        import platform
        from datetime import datetime, timezone
        report = {
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'platform': platform.platform(), 'machine': platform.machine(),
            'tests_run': program.result.testsRun, 'failures': len(program.result.failures),
            'errors': len(program.result.errors), 'passed': program.result.wasSuccessful(),
            'hardware_tee_tested': False, 'remote_attestation_tested': False,
            'artifacts': {name: hashlib.sha256((ROOT / 'dist' / name).read_bytes()).hexdigest()
                          for name in ('agent.wasm', 'hal-on-demand')},
        }
        VALIDATION.mkdir(parents=True, exist_ok=True)
        (VALIDATION / 'integration-tests.json').write_text(json.dumps(report, indent=2) + '\n')
    sys.exit(0 if program.result.wasSuccessful() else 1)
