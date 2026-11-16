#!/usr/bin/env python3
"""Exercise real native worker processes and real Wasm over private Unix IPC.

These are software protocol checks. They do NOT claim Docker/TDX isolation.
Run test_docker_workers.py on Linux to check the actual container boundary.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HAL_ON_DEMAND_BIN', ROOT / 'dist/hal-on-demand'))


def rpc(path, request):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(15)
        client.connect(str(path))
        client.sendall(json.dumps(request).encode() + b'\n')
        with client.makefile('rb') as stream:
            return json.loads(stream.readline(16 * 1024 * 1024))


class ArtifactHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        request = json.loads(self.rfile.readline(16 * 1024))
        case = self.server.artifacts.get(request.get('component'))
        if (not case or 'tenant' in request or request.get('sha256') != case['sha256']
                or request.get('artifact_bytes') != case['artifact_bytes']):
            self.wfile.write(b'{"status":"error"}\n')
            return
        with self.server.lock:
            self.server.downloads[case['artifact']] += 1
        data = (ROOT / 'tests/workloads' / case['artifact']).read_bytes()
        if self.server.corrupt:
            data = bytes([data[0] ^ 1]) + data[1:]
        self.wfile.write(json.dumps(dict(status='ok', bytes=len(data))).encode() + b'\n')
        self.wfile.write(data)


class ArtifactServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class WorkerProtocolTest(unittest.TestCase):
    def setUp(self):
        # Unix socket paths have small limits, including on macOS.
        self.temp = tempfile.TemporaryDirectory(prefix='hal-cw-', dir='/tmp')
        self.root = Path(self.temp.name)
        self.processes = []
        self.streams = []
        self.servers = []
        self.workers = {}
        self.catalog = json.loads((ROOT / 'workloads.json').read_text())
        for case in self.catalog['cases']:
            if case['name'] == 'platform':
                case['validation']['value'] = 'AmdSev|'
        self.cases = {c['name']: c for c in self.catalog['cases']}
        (self.root / 'catalog.json').write_text(json.dumps(self.catalog))

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        for server in self.servers:
            server.shutdown(); server.server_close()
        for stream in self.streams:
            stream.close()
        self.temp.cleanup()

    def start_worker(self, user, allowed=None, modify=None, authorization=False):
        root = self.root / user
        root.mkdir(mode=0o700)
        for name in ('config', 'ipc', 'broker'):
            (root / name).mkdir(mode=0o700)
        config = root / 'config'
        (config / 'operator.token').write_text('operator-' + user + 'a' * 40)
        (config / 'worker.token').write_text('worker-' + user + 'b' * 40)
        selected = [self.cases[c] for c in (allowed or self.cases)]
        policy = dict(version=1, tenants=[dict(id=user, token_file='worker.token', max_inflight=4,
            artifacts=[dict(component=c['artifact'], sha256=c['sha256'], artifact_bytes=c['artifact_bytes']) for c in selected])])
        (config / 'tenant.json').write_text(json.dumps(policy))
        subprocess.run([sys.executable, '-B', str(ROOT / 'configure_agent.py'),
            '--tenant-policy', str(config / 'tenant.json'), '--catalog', str(self.root / 'catalog.json'),
            '--agent', str(ROOT / 'dist/agent.wasm'), '--output', str(config / 'agent-policy.json')],
            check=True, stdout=subprocess.DEVNULL)
        if modify:
            value = json.loads((config / 'agent-policy.json').read_text())
            modify(value)
            (config / 'agent-policy.json').write_text(json.dumps(value))
        server = ArtifactServer(str(root / 'broker/a.sock'), ArtifactHandler)
        server.artifacts = {c['artifact']: c for c in selected}
        server.downloads = Counter()
        server.lock = threading.Lock()
        server.corrupt = False
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        identity = dict(version=1, tenant=user, platform='NON_TEE_TEST_ONLY',
            socket=str(root / 'ipc/w.sock'), broker_socket=str(root / 'broker/a.sock'), args=[
                'worker', '--allow-non-tee', '--mode', 'wasm', '--file-server', 'http://127.0.0.1:1/',
                '--token-file', str(config / 'operator.token'), '--tenant-policy', str(config / 'tenant.json'),
                '--agent-policy', str(config / 'agent-policy.json'), '--cache-dir', str(root / 'state'),
                '--compiler-threads', '2', '--max-inflight', '4', '--download-timeout-secs', '3'])
        path = config / 'worker.json'
        if authorization:
            sys.path.insert(0, str(ROOT))
            from configure_authorization import generate
            output = generate(config / 'tenant.json', config / 'agent-policy.json', self.root / 'catalog.json',
                'test-private-worker', 'per-user-container', 120, root / 'auth')
            identity['args'].extend(['--job-authorization', str(output / 'execution-public/job-authorization.json')])
            identity['authorization_epoch'] = 'e' * 64
        path.write_text(json.dumps(identity))
        log = root / 'worker.log'
        stream = log.open('w'); self.streams.append(stream)
        process = subprocess.Popen([str(BINARY), '--container-worker-config', str(path)],
            cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        self.processes.append(process)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail('worker failed: ' + log.read_text())
            if Path(identity['socket']).exists():
                ready = rpc(identity['socket'], dict(op='stats'))
                self.assertEqual(ready['tenant'], user)
                self.workers[user] = (identity['socket'], server, process)
                return server
            time.sleep(.02)
        self.fail('worker did not become ready: ' + log.read_text())

    def run_as(self, user, case='platform', **changes):
        artifact = self.cases[case]
        request = dict(protocol=1, op='run', job_id='test-' + str(time.time_ns()), cache='reuse',
            component=artifact['artifact'], sha256=artifact['sha256'], artifact_bytes=artifact['artifact_bytes'])
        request.update(changes)
        return rpc(self.workers[user][0], request)

    def stats(self, user):
        return rpc(self.workers[user][0], dict(op='stats'))['stats']

    def test_two_users_have_independent_compiled_caches_for_all_workloads(self):
        for user in ('alice', 'bob'):
            server = self.start_worker(user)
            for case, artifact in self.cases.items():
                first = self.run_as(user, case)
                self.assertEqual(first['status'], 'ok', first)
                self.assertEqual(first['cache_status'], 'miss')
                self.assertEqual(first['tenant'], user)
                self.assertFalse(first['attestation_verified'])
                self.assertFalse(first['workload_instance_reused'])
                if artifact['validation']['kind'] == 'hex':
                    self.assertEqual(first['result']['hex'], artifact['validation']['value'])
                self.assertEqual(self.run_as(user, case)['cache_status'], 'hit')
            self.assertEqual(sum(server.downloads.values()), 5)
            self.assertEqual(self.stats(user)['compiled_entries'], 5)
        self.assertFalse(list(self.root.rglob('*.wasm')))

    def test_bypass_downloads_and_compiles_again_without_replacing_cache(self):
        server = self.start_worker('alice')
        self.assertEqual(self.run_as('alice')['cache_status'], 'miss')
        for _ in range(2):
            row = self.run_as('alice', cache='bypass')
            self.assertEqual(row['cache_status'], 'bypass', row)
            self.assertFalse(row['preparation']['stored'])
        self.assertEqual(self.run_as('alice')['cache_status'], 'hit')
        self.assertEqual(sum(server.downloads.values()), 3)
        self.assertEqual(self.stats('alice')['compiles'], 3)

    def test_injected_identity_and_other_users_artifacts_are_rejected_before_download(self):
        server = self.start_worker('alice', allowed=['platform'])
        for changes in [dict(tenant='bob'), dict(sha256='0'*64), dict(artifact_bytes=8), dict(component='../outside.wasm')]:
            self.assertEqual(self.run_as('alice', **changes)['status'], 'error')
        self.assertEqual(self.run_as('alice', 'sha256-abc')['status'], 'error')
        self.assertEqual(sum(server.downloads.values()), 0)
        self.assertEqual(self.stats('alice')['executions'], 0)

    def test_corrupt_download_is_never_compiled_or_executed(self):
        server = self.start_worker('alice')
        server.corrupt = True
        self.assertEqual(self.run_as('alice')['status'], 'error')
        self.assertEqual(self.stats('alice')['compiles'], 0)
        self.assertEqual(self.stats('alice')['executions'], 0)
        server.corrupt = False
        self.assertEqual(self.run_as('alice')['status'], 'ok')

    def test_worker_independently_enforces_disabled_cache_and_result_policy(self):
        def disable(policy):
            for row in policy['workloads']:
                row['cache'] = 'disabled'
        server = self.start_worker('alice', modify=disable)
        self.assertEqual(self.run_as('alice', cache='reuse')['status'], 'error')
        self.assertEqual(sum(server.downloads.values()), 0)
        self.assertEqual(self.run_as('alice', cache='bypass')['status'], 'ok')
        def wrong_output(policy):
            for row in policy['workloads']:
                if row['component'] == self.cases['platform']['artifact']:
                    row['validation'] = dict(kind='hex', value='00')
        self.start_worker('bob', modify=wrong_output)
        self.assertEqual(self.run_as('bob', cache='bypass')['status'], 'error')

    def test_concurrent_jobs_remain_scoped_to_their_own_worker(self):
        for user in ('alice', 'bob'):
            self.start_worker(user)
        owners = ['alice', 'bob'] * 4
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(self.run_as, owners))
        for owner, row in zip(owners, rows):
            self.assertEqual(row['status'], 'ok', row)
            self.assertEqual(row['tenant'], owner)
        for owner in ('alice', 'bob'):
            self.assertEqual(self.stats(owner)['compiles'], 1)
            self.assertEqual(self.stats(owner)['executions'], 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
