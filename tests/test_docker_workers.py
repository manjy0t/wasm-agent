#!/usr/bin/env python3
"""Linux acceptance tests with real per-user gVisor sandboxes and HAL workloads.

sudo python3 tests/test_docker_workers.py --image hal-user-worker:local
Uses synthetic HAL metadata so this checks containment, not TDX attestation.
Creates/removes only its own labelled containers and temporary state.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
import time

import test_agent_policy as policy_tests
from test_system import ROOT

IMAGE = os.environ.get('HAL_WORKER_TEST_IMAGE', 'hal-user-worker:local')
DOCKER = '/usr/bin/docker'
SIGNED_JOBS = False


def docker(*args, check=True):
    # Match the broker's local rootful daemon, irrespective of shell contexts.
    return subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', *args],
        env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, check=check, timeout=40)


def host_cgroup_limit(pid, controller, v2_file, v1_file):
    # gVisor virtualizes /proc and /sys inside the sandbox. Check the host cgroup
    # that actually contains the Sentry, rather than trusting virtualized files.
    for line in Path(f'/proc/{pid}/cgroup').read_text().splitlines():
        _, controllers, relative = line.split(':', 2)
        if controllers == '' or controller in controllers.split(','):
            base = Path('/sys/fs/cgroup')
            if controllers:
                base /= controllers
            path = base / relative.lstrip('/') / (v1_file if controllers else v2_file)
            return path.read_text().strip()
    raise AssertionError('No host cgroup for ' + controller)


class DockerWorkerTest(unittest.TestCase):
    # Match the installed service. Popen applies this only in the child process,
    # avoiding a process-wide os.umask change while HTTP test threads are running.
    process_umask = 0o077
    start = policy_tests.AgentPolicyTest.start
    start_agent = policy_tests.AgentPolicyTest.start_agent
    run_as = policy_tests.AgentPolicyTest.run_as
    stats = policy_tests.AgentPolicyTest.stats

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=75)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def setUp(self):
        self.container_names = []
        self.ipc = None
        self.addCleanup(self.cleanup_workers)
        policy_tests.AgentPolicyTest.setUp(self)
        self.ipc = tempfile.TemporaryDirectory(prefix='hal-ct-', dir='/run')
        self.stop(self.host)
        extra = []
        if SIGNED_JOBS:
            from configure_authorization import generate
            self.auth = generate(self.execution / 'policy.json', self.agent_policy, self.root / 'catalog.json',
                'docker-test', 'per-user-container', 120, self.root / 'authorizations')
            extra = ['--job-authorization', str(self.auth / 'execution-public/job-authorization.json')]
        self.start_agent('--mode', 'wasm', '--transport', 'http',
            '--tenant-policy', str(self.execution / 'policy.json'),
            '--agent-policy', str(self.agent_policy), '--file-token-file', str(self.execution / 'file.token'),
            '--user-containers', '--container-image', IMAGE, '--container-state-dir', self.ipc.name,
            '--container-cpus', '1', '--container-memory-mib', '512', '--compiler-threads', '1', *extra)
        if SIGNED_JOBS:
            from management import WorkerHTTPClient
            from job_signing import Signer
            client = WorkerHTTPClient(self.worker_url, self.token, 10)
            try:
                epoch = client.stats()['job_authorization']['epoch']
            finally:
                client.close()
            self.signers = {u: Signer(self.auth / 'clients-private' / (u + '.json'), epoch) for u in ('alice', 'bob')}

    def cleanup_workers(self):
        for process in reversed(getattr(self, 'processes', [])):
            self.stop(process)
        # Also find names for a startup that failed before returning its response.
        if self.ipc:
            for path in Path(self.ipc.name).glob('b-*/*/config/worker.json'):
                # Mount paths uniquely identify this test's workers, including failures.
                listing = docker('ps', '-aq', '--filter', 'label=hal.broker', check=False)
                for name in listing.stdout.split():
                    inspected = docker('inspect', name, check=False)
                    if inspected.returncode == 0 and str(path.parent) in inspected.stdout:
                        docker('rm', '-f', name, check=False)
            for name in self.container_names:
                docker('rm', '-f', name, check=False)
            self.ipc.cleanup()

    def tearDown(self):
        policy_tests.AgentPolicyTest.tearDown(self)
        for name in self.container_names:
            self.assertNotEqual(docker('inspect', name, check=False).returncode, 0,
                'broker shutdown should remove its worker containers')

    def execute(self, user, case='platform', **changes):
        if SIGNED_JOBS:
            changes.setdefault('job_id', 'docker-' + str(time.time_ns()))
            changes.setdefault('job_ticket', self.signers[user].ticket(case, changes.get('cache', 'reuse'), changes['job_id']))
        row = self.run_as(user, case, **changes)
        if SIGNED_JOBS and row['status'] == 'ok':
            self.assertTrue(row['job_authorization']['helper_checked'])
            self.assertTrue(row['job_authorization']['worker_checked'])
        if 'container' in row:
            name = row['container']['name']
            if name not in self.container_names:
                self.container_names.append(name)
        return row

    def test_concurrent_first_jobs_share_one_successful_worker_startup(self):
        cases = ('sha256-abc', 'sha512-abc', 'random-32', 'platform')
        ready = threading.Barrier(len(cases))

        def first_job(case):
            ready.wait(timeout=10)
            return self.execute('alice', case, cache='bypass')

        with ThreadPoolExecutor(max_workers=len(cases)) as executor:
            rows = list(executor.map(first_job, cases))
        for row in rows:
            self.assertEqual(row['status'], 'ok', row)
            self.assertEqual(row['cache_status'], 'bypass')
            self.assertFalse(row['workload_instance_reused'])
        self.assertEqual(len({row['container']['name'] for row in rows}), 1)
        self.assertEqual(sum(not row['container']['reused'] for row in rows), 1)

    def test_private_containers_caches_mounts_namespaces_and_fresh_execution(self):
        first = {}
        for user in ('alice', 'bob'):
            row = self.execute(user)
            self.assertEqual(row['status'], 'ok', row)
            self.assertEqual(row['cache_status'], 'miss')
            self.assertEqual(row['configuration']['workload_isolation'], 'per-user-container')
            self.assertFalse(row['container']['reused'])
            self.assertEqual(row['container']['runtime'], 'hal-gvisor')
            self.assertEqual(row['container']['sandbox_scope'], 'user')
            self.assertTrue(row['container']['launch_configuration_checked'])
            self.assertFalse(row['workload_instance_reused'])
            self.assertFalse(row['attestation_verified'])
            self.assertEqual(row['host_calls']['ensure_user_container'], 1)
            self.assertEqual(row['host_calls']['run_in_user_container'], 1)
            first[user] = row
            hit = self.execute(user)
            self.assertEqual(hit['cache_status'], 'hit')
            self.assertTrue(hit['container']['reused'])
            bypass = self.execute(user, cache='bypass')
            self.assertEqual(bypass['cache_status'], 'bypass')
            self.assertFalse(bypass['preparation']['stored'])
            other = self.execute(user, 'sha256-abc')
            self.assertEqual(other['status'], 'ok', other)
            self.assertTrue(other['container']['reused'])
            self.assertEqual(other['container']['name'], row['container']['name'],
                             'Different workloads of the same user must share one sandbox')
            self.assertFalse(other['workload_instance_reused'])
        self.assertNotEqual(first['alice']['container']['name'], first['bob']['container']['name'])
        inspected = {}
        for user in ('alice', 'bob'):
            name = first[user]['container']['name']
            info = json.loads(docker('inspect', name).stdout)[0]
            inspected[user] = info
            config = info['HostConfig']
            self.assertEqual(config['Runtime'], 'hal-gvisor')
            self.assertEqual(config['NetworkMode'], 'none')
            self.assertTrue(config['ReadonlyRootfs'])
            self.assertFalse(config['Privileged'])
            self.assertIn('ALL', config['CapDrop'])
            self.assertTrue(any('no-new-privileges' in s for s in config['SecurityOpt']))
            self.assertEqual(config['Memory'], 512 * 1024 * 1024)
            self.assertEqual(config['MemorySwap'], config['Memory'])
            self.assertEqual(config['PidsLimit'], 128)
            self.assertEqual(info['Config']['User'], '65532:65532')
            mounts = {m['Destination']: m for m in info['Mounts']}
            self.assertFalse(mounts['/config']['RW'])
            self.assertFalse(mounts['/run/broker']['RW'])
            # Restrictive service umask must not make the per-user snapshots
            # root-only. Their enclosing host directory must still be private.
            config_dir = Path(mounts['/config']['Source'])
            self.assertEqual(config_dir.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(config_dir.parent.stat().st_uid, 0)
            for path in config_dir.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o444, path.name)
                self.assertEqual(path.stat().st_uid, 0, path.name)
                self.assertEqual(docker('exec', name, 'test', '-r', '/config/' + path.name).returncode, 0)
                self.assertNotEqual(docker('exec', name, 'test', '-w', '/config/' + path.name,
                                          check=False).returncode, 0)
            self.assertEqual(docker('exec', name, 'id', '-u').stdout.strip(), '65532')
            self.assertNotEqual(docker('exec', name, 'touch', '/should-be-read-only', check=False).returncode, 0)
            self.assertNotEqual(docker('exec', name, 'touch', '/run/worker/host-file', check=False).returncode, 0)
            self.assertNotEqual(docker('exec', name, 'chmod', '777', '/run/worker', check=False).returncode, 0)
            self.assertEqual(docker('exec', name, 'stat', '-c', '%u:%g:%a', '/run/worker').stdout.strip(), '0:0:555')
            self.assertEqual(docker('exec', name, 'sh', '-c',
                'test ! -e /var/run/docker.sock && test ! -e /dev/tdx_guest && test ! -e /dev/sev-guest').returncode, 0)
            actual = json.loads(docker('exec', name, 'cat', '/config/tenant.json').stdout)
            self.assertEqual([t['id'] for t in actual['tenants']], [user])
            if SIGNED_JOBS:
                policy = json.loads(docker('exec', name, 'cat', '/config/job-authorization.json').stdout)
                self.assertEqual([u['tenant'] for u in policy['users']], [user])
                self.assertNotIn('private_key', json.dumps(policy))
            docker('exec', name, 'sh', '-c', f'printf %s {user} > /state/private-marker')
            self.assertEqual(docker('exec', name, 'cat', '/state/private-marker').stdout, user)
            status = docker('exec', name, 'cat', '/proc/self/status').stdout
            self.assertIn('CapEff:\t0000000000000000', status)
            pid = info['State']['Pid']
            host_status = Path(f'/proc/{pid}/status').read_text()
            self.assertIn('Seccomp:\t2', host_status)
            self.assertIn('NoNewPrivs:\t1', host_status)
            self.assertEqual(host_cgroup_limit(pid, 'memory', 'memory.max', 'memory.limit_in_bytes'),
                             str(512 * 1024 * 1024))
            self.assertEqual(host_cgroup_limit(pid, 'pids', 'pids.max', 'pids.max'), '128')
        # gVisor virtualizes guest namespaces. A separate Sentry for each user,
        # private mounts and the explicit runtime contract are the boundary;
        # host namespace inode numbers do not describe that virtualized boundary.
        pids = [inspected[u]['State']['Pid'] for u in ('alice', 'bob')]
        self.assertTrue(all(pid > 0 for pid in pids))
        self.assertNotEqual(*pids, 'Each user must have a separate Sentry process')
        self.assertEqual(self.stats()['compiles'], 0, 'workload compilation must not occur in broker')
        self.assertEqual(self.stats()['executions'], 0, 'workload execution must not occur in broker')

    def test_invalid_identity_fails_before_creation_and_one_dead_worker_does_not_stop_another(self):
        if SIGNED_JOBS:
            denied = self.run_as('alice')
            self.assertEqual(denied['status'], 'error')
            ticket = self.signers['alice'].ticket('platform', 'reuse', 'wrong-room')
            denied = self.run_as('bob', job_id='wrong-room', job_ticket=ticket)
            self.assertEqual(denied['status'], 'error')
        denied = self.execute('alice', tenant='bob')
        self.assertEqual(denied['status'], 'error')
        alice, bob = self.execute('alice'), self.execute('bob')
        self.assertEqual(alice['status'], 'ok', alice)
        self.assertEqual(bob['status'], 'ok', bob)
        docker('kill', alice['container']['name'])
        self.assertEqual(self.execute('alice')['status'], 'error')
        self.assertEqual(self.execute('alice')['status'], 'error', 'must not silently retry/recreate and duplicate a job')
        self.assertEqual(self.execute('bob')['cache_status'], 'hit')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--signed-jobs', action='store_true', help='also exercise signatures through real containers; test Python needs cryptography')
    args, remaining = parser.parse_known_args()
    IMAGE = args.image
    SIGNED_JOBS = args.signed_jobs
    if not sys.platform.startswith('linux') or os.geteuid() != 0 or not shutil.which(DOCKER):
        raise SystemExit('These acceptance tests require Linux, sudo and /usr/bin/docker. No container tests were run.')
    from hal_fleet.gvisor import check
    print(json.dumps(check(), indent=2), flush=True)
    docker('image', 'inspect', IMAGE)
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
