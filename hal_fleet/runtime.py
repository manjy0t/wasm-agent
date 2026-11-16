"""Shared native runtime launch primitives and legacy fleet admission.

Portable deployment uses LocalRuntime to start hal-agent-runner directly;
Broker is retained only for the original agent/native benchmark profiles.
"""
import copy
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time
import uuid
from job_signing import rule_digest
from .common import Error, atomic_json, canonical, digest, milliseconds, require, verify_request
from .policy import SETTINGS, signed_job
from .services import TrustChecks


class LocalRuntime:
    def __init__(self, config, document, transport):
        self.process = None
        self.log = None
        self.document = document
        self.active = 0
        self.last_used = time.monotonic()
        self.semaphore = threading.BoundedSemaphore(document['limits']['max_inflight'])
        self.root = Path(config['state_dir']) / 'brokers' / (document['subject'] + '-' + uuid.uuid4().hex[:12])
        self.root.mkdir(parents=True, mode=0o700)
        token = os.urandom(32).hex()
        self.token = os.urandom(32).hex()
        for name, value in (('operator.token', token), ('tenant.token', self.token)):
            fd = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(value + '\n')
        tenant = dict(id=document['subject'], token_file='tenant.token',
            artifacts=[{k: w[k] for k in ('component', 'sha256', 'artifact_bytes')} for w in document['workloads']],
            **document['limits'])
        atomic_json(self.root / 'tenant.json', dict(version=1, tenants=[tenant]))
        rules = [dict(w['rule'], tenant=document['subject'], sha256=w['sha256']) for w in document['workloads']]
        atomic_json(self.root / 'agent.json', dict(version=1, agent_sha256=config['agent_sha256'], workloads=rules))
        grants = [dict(component=w['component'], sha256=w['sha256'], artifact_bytes=w['artifact_bytes'],
                       rule_sha256=rule_digest(w['rule'])) for w in document['workloads']]
        isolation = 'in-process' if config['mode'] == 'native' or config.get('test_in_process') else 'per-user-container'
        atomic_json(self.root / 'authorization.json', dict(version=1, audience=config['trust']['execution_audience'],
            max_ttl_seconds=120, isolation=isolation,
            users=[dict(tenant=document['subject'], public_key=document['public_key'], workloads=grants)]))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(port)
        command = [config['binary'], '--mode', config['mode'], '--transport', 'http', '--listen', '127.0.0.1:' + str(port),
            '--token-file', str(self.root / 'operator.token'), '--tenant-policy', str(self.root / 'tenant.json'),
            '--file-server', config.get('artifact_url') or config['files_url'] + '/artifacts/', '--cache-dir', str(self.root / 'storage')]
        if config.get('file_token_file'):
            command += ['--file-token-file', config['file_token_file']]
        elif config.get('file_token'):
            from .local_files import write_private
            credential = self.root / 'file.token'
            write_private(credential, (config['file_token'] + '\n').encode(), exclusive=True)
            command += ['--file-token-file', str(credential)]
        if config.get('agent_configuration'):
            command += ['--agent-configuration', config['agent_configuration']]
        if config.get('ca_file'):
            command += ['--file-ca-cert', config['ca_file']]
        if config['mode'] == 'wasm':
            command += ['--agent', config['agent'], '--agent-policy', str(self.root / 'agent.json'),
                        '--job-authorization', str(self.root / 'authorization.json')]
            if not config.get('test_in_process'):
                self.container_state = Path('/run') / ('hal-fleet-' + uuid.uuid4().hex[:12])
                command += ['--user-containers', '--container-image', config['container_image'],
                            '--container-state-dir', str(self.container_state)]
        settings = config.get('settings', SETTINGS)
        for name, value in settings.items():
            require(name in SETTINGS, 'Unknown runtime setting: ' + name)
            if not name.startswith('container_') or isolation == 'per-user-container':
                command += ['--' + name.replace('_', '-'), str(value)]
        if config.get('allow_non_tee'):
            command += ['--allow-non-tee']
        self.log = (self.root / 'broker.log').open('ab')
        started = time.perf_counter()
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log, start_new_session=True)
        try:
            deadline = time.monotonic() + 60
            while True:
                require(self.process.poll() is None, 'Broker failed to start; see ' + str(self.root / 'broker.log'), 503)
                try:
                    status = transport.call(self.url, '/v1/stats', token=token)
                    break
                except Error:
                    require(time.monotonic() < deadline, 'Broker startup timed out', 503)
                    time.sleep(.05)
            self.epoch = (status.get('job_authorization') or {}).get('epoch') or os.urandom(32).hex()
            self.status = status
            self.startup_ms = milliseconds(started)
        except Exception:
            self.close()
            raise

    def close(self):
        if self.process and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()
        # Existing broker/container cleanup is owned by the Rust lifecycle; never
        # issue a broad Docker prune that could remove another application's data.


class Broker(LocalRuntime):
    """Compatibility implementation for the original benchmark profiles."""


class Execution(TrustChecks):
    def __init__(self, config, database, transport, broker_factory=Broker):
        super().__init__(config, database, transport)
        self.factory = broker_factory
        self.brokers, self.locks = {}, {}
        self.pool_lock = threading.RLock()
        self.permits = threading.BoundedSemaphore(config.get('global_inflight', 16))
        if broker_factory is Broker:
            require(digest(Path(config['binary']).read_bytes()) == config['binary_sha256'], 'Installed host changed; run trust-build after reviewing your build')
            if config['mode'] == 'wasm':
                require(digest(Path(config['agent']).read_bytes()) == config['agent_sha256'], 'Installed agent changed; run trust-build after reviewing your build')

    def lock(self, name):
        with self.pool_lock:
            require(len(self.locks) < 64 or name in self.locks, 'Enrollment capacity reached', 429)
            return self.locks.setdefault(name, threading.RLock())

    def ensure(self, doc):
        """Called while holding this user's lock; requests cannot race a policy change."""
        require(self.config['mode'] != 'native' or all('access_profile' not in w['rule'] for w in doc['workloads']),
                'Native baseline does not enforce workload access profiles; use agent mode', 400)
        name = doc['subject']
        with self.pool_lock:
            old = self.brokers.get(name)
            if old and old.process.poll() is None and old.document['revision'] == doc['revision']:
                return old
            if old:
                require(old.active == 0, 'Wait for this user\'s running jobs before changing its policy', 409, 'user_busy')
                old.close()
                del self.brokers[name]
            if len(self.brokers) >= self.config.get('max_active_users', 4):
                idle = [(b.last_used, n, b) for n, b in self.brokers.items() if b.active == 0]
                require(bool(idle), 'All user runtimes are busy', 429)
                _, owner, broker = min(idle, key=lambda x: x[0])
                broker.close()
                del self.brokers[owner]
            require(doc['workloads'], 'Approve at least one workload before starting a session', 403)
            broker = self.create_broker(doc)
            self.brokers[name] = broker
            return broker

    def create_broker(self, doc):
        return self.factory(self.config, doc, self.transport)

    def handle(self, method, path, body):
        require(method == 'POST', 'Endpoint not found', 404)
        audience = self.config['trust']['execution_audience']
        if path in ('/v1/enroll', '/v1/session'):
            operation = path.rsplit('/', 1)[1]
            req = verify_request(body, audience, operation, self.db)
            require(set(req['body']) == {'document'}, 'Enrollment only accepts a signed document')
            doc = self.check_document(req['body']['document'])
            require(req['subject'] == doc['subject'] and req['public_key'] == doc['public_key'],
                    'Prove possession of the enrolled user key', 403)
            with self.lock(doc['subject']):
                old = self.db.get('enrolled', doc['subject'])
                require(not old or (old['public_key'] == doc['public_key'] and doc['revision'] >= old['revision']),
                        'Enrollment rollback or key replacement denied', 403)
                self.db.put('enrolled', doc['subject'], doc)
                if operation == 'enroll':
                    return {'enrolled': doc['subject'], 'revision': doc['revision'], 'workloads': len(doc['workloads'])}
                broker = self.ensure(doc)
                broker.last_used = time.monotonic()
                return dict(tenant=doc['subject'], revision=doc['revision'], epoch=broker.epoch,
                    audience=audience, isolation='in-process' if self.config['mode'] == 'native' or self.config.get('test_in_process') else 'per-user-container',
                    mode=self.config['mode'], broker_startup_ms=broker.startup_ms, attestation_verified=False,
                    settings=self.config.get('settings', SETTINGS))
        require(path == '/v1/run', 'Endpoint not found', 404)
        start = time.perf_counter()
        require(isinstance(body, dict) and set(body) == {'document', 'job', 'isolation'}, 'Invalid execution request')
        doc = self.check_document(body['document'])
        isolation = 'in-process' if self.config['mode'] == 'native' or self.config.get('test_in_process') else 'per-user-container'
        require(body['isolation'] == isolation, 'Isolation does not match this deployment', 403)
        claims, approved = signed_job(doc, body['job'], audience, isolation)
        enrolled = self.db.get('enrolled', doc['subject'])
        require(enrolled and enrolled['public_key'] == doc['public_key'] and enrolled['revision'] == doc['revision'],
                'Enroll the current document before submitting a job', 403)
        if self.config['mode'] == 'native':
            require(body['job']['cache'] == 'bypass', 'Native mode has no code cache; use bypass', 400)
        require(self.permits.acquire(timeout=5), 'Execution queue full', 429)
        broker = None
        acquired = False
        counted = False
        try:
            with self.lock(doc['subject']), self.pool_lock:
                broker = self.brokers.get(doc['subject'])
                require(broker and broker.process.poll() is None and broker.document['revision'] == doc['revision']
                        and broker.epoch == claims['epoch'], 'Session changed; obtain a new session', 409, 'epoch_changed')
                broker.active += 1
                counted = True
            require(broker.semaphore.acquire(timeout=5), 'User queue full', 429)
            acquired = True
            # Durable replay admission is independent of management and the broker.
            self.db.consume('execution-job:' + doc['subject'], claims['job_id'])
            self.db.consume('execution-nonce:' + doc['subject'], claims['nonce'])
            job = copy.deepcopy(body['job'])
            if self.config['mode'] == 'native':
                job.pop('job_ticket')  # Native baseline: gateway checks, no helper/container profile.
            authorization_ms = milliseconds(start)
            result = self.execute_job(broker, job, doc, claims)
            result['fleet_timings_ms'] = dict(execution_authorization_and_queue=authorization_ms,
                                              execution_gateway_total=milliseconds(start))
            result['enrollment_revision'] = doc['revision']
            result['gateway_signature_checked'] = True
            return result
        finally:
            if acquired:
                broker.semaphore.release()
            if counted:
                with self.pool_lock:
                    broker.active -= 1
                    broker.last_used = time.monotonic()
            self.permits.release()

    def execute_job(self, broker, job, doc, claims):
        """Called only after authorization, queue admission and durable replay checks."""
        return self.transport.call(broker.url, '/v1/run', job, token=broker.token)

    def close(self):
        with self.pool_lock:
            for broker in self.brokers.values():
                broker.close()
            self.brokers.clear()
