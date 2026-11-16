"""Management-owned selection of existing agent and native service profiles.

This sits outside the Wasm agent, WIT and Rust broker. Agent retirement and
deployment use the existing lifecycle, including fresh attestation on deployment.
"""
import copy
import os
from pathlib import Path
import secrets
import signal
import subprocess
import threading
import time

from .common import (Database, Error, SHA, atomic_json, digest, key_from_hex,
                     public, read_private, request, require, verify_request)
from .benchmark_guard import BenchmarkGate
from .benchmark_state import bind_state
from .native_config import service_digest

PROTOCOL = 'hal-selectable-execution-v1'
ARCHITECTURES = {'agent': 'hal-managed-agent-v2', 'native': 'hal-native-audited-v1'}


def configure(agent_path, native_path, output, control_public_key=None):
    agent_path, native_path, output = [Path(p).resolve() for p in (agent_path, native_path, output)]
    agent, native = read_private(agent_path), read_private(native_path)
    role = agent['role']
    require(role in ('management', 'execution') and native['role'] == role, 'Configure matching management or execution profiles')
    require(agent.get('execution_architecture') == ARCHITECTURES['agent']
            and native.get('execution_architecture') == ARCHITECTURES['native'], 'Supply the existing agent and audited-native profiles')
    for field in ('trust', 'listen', 'identity_url', 'files_url', 'execution_url', 'management_url', 'ca_file', 'tls_cert', 'tls_key'):
        require(agent.get(field) == native.get(field), 'Mode profiles must share the same service endpoint/trust: ' + field)
    require(agent.get('tls_cert') and agent.get('tls_key') and agent['execution_url'].startswith('https://'), 'Mode selection requires HTTPS')
    require(not output.exists() and output not in (agent_path, native_path), 'Use a new mode-selection config path')
    state = output.parent / (output.stem + '-state')
    states = [Path(c['state_dir']).resolve() for c in (agent, native)] + [state]
    require(all(a != b and a not in b.parents and b not in a.parents for i, a in enumerate(states) for b in states[i+1:]),
            'Agent, native and selection state must be separate directories')
    require(not state.exists(), 'Use fresh mode-selection state')
    if role == 'management':
        key_path = agent['management_key']
        owner = public(key_from_hex(read_private(key_path)['private_key']))
        require(control_public_key in (None, owner), 'Mode control uses the existing agent management owner')
        targets = agent.get('execution_targets') or [dict(url=agent['execution_url'])]
        require(len(targets) == 1 and targets[0]['url'] == native['execution_url'],
                'Selectable mode currently requires one shared execution VM; existing multi-VM agent deployments are unchanged')
    else:
        owner = control_public_key
        require(isinstance(owner, str) and SHA.fullmatch(owner) and owner in agent.get('trusted_management_keys', []),
                'Pin the existing agent management public key for mode control')
        owner_file = Path(agent['state_dir']) / 'agent-owner.json'
        if owner_file.exists():
            require(read_private(owner_file)['management_key'] in (None, owner), 'Execution VM is owned by another management service', 403)
    result = {k: copy.deepcopy(agent[k]) for k in ('version', 'role', 'listen', 'trust', 'identity_url', 'files_url',
              'execution_url', 'management_url', 'ca_file', 'tls_cert', 'tls_key') if k in agent}
    result.update(execution_architecture=PROTOCOL, state_dir=str(state), mode_control_public_key=owner,
        profiles={'agent': str(agent_path), 'native': str(native_path)},
        profile_sha256={'agent': digest(agent_path.read_bytes()), 'native': digest(native_path.read_bytes())})
    if role == 'management':
        result['mode_control_key'] = key_path
    state.mkdir(parents=True, mode=0o700, exist_ok=False)
    atomic_json(output, result, exclusive=True)
    return dict(config=str(output), state_dir=str(state), mode_control_public_key=owner,
                execution_architecture=PROTOCOL, initial_state='inactive', services_started=False)


class Backend:
    def __init__(self, config, mode, transport):
        import fcntl
        path = Path(config['profiles'][mode])
        require(digest(path.read_bytes()) == config['profile_sha256'][mode], 'Execution profile changed; review mode configuration before starting', 409)
        profile = read_private(path)
        require(profile['role'] == config['role'] and profile.get('execution_architecture') == ARCHITECTURES[mode], 'Wrong service mode profile')
        self.lock = (Path(profile['state_dir']) / 'service.lock').open('a')
        self.db, self.app = None, None
        try:
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Error('The selected profile is already served by another process', 409) from exc
            self.db = Database(Path(profile['state_dir']) / 'state.sqlite3')
            bind_state(profile, self.db)
            if mode == 'agent':
                from .portable import PortableExecution, PortableManagement
                if profile['role'] == 'execution':
                    from .gvisor import check
                    check()
                klass = PortableExecution if profile['role'] == 'execution' else PortableManagement
            else:
                from .native_audit import NativeExecution, NativeManagement
                require(profile['service_sha256'] == service_digest(), 'Native source build changed; review the native profile')
                klass = NativeExecution if profile['role'] == 'execution' else NativeManagement
            self.app = klass(profile, self.db, transport)
            if profile['role'] == 'execution' and mode == 'agent':
                self.app.owner.check(config['mode_control_public_key'])
            if profile['role'] == 'management':
                self.app = BenchmarkGate(self.app)
        except Exception:
            self.close()
            raise

    def close(self):
        if self.app is not None:
            close = getattr(self.app, 'close', None)
            if close:
                close()
            self.app = None
        if self.db is not None:
            self.db.close()
            self.db = None
        self.lock.close()


class ModeService:
    def __init__(self, config, database, transport, backend_factory=Backend):
        self.config, self.db, self.transport, self.factory = config, database, transport, backend_factory
        self.condition = threading.Condition(threading.RLock())
        self.control_lock = threading.Lock()
        self.active = 0
        self.backend = None
        with self.db.lock:
            self.db.connection.execute('PRAGMA synchronous=FULL')
        if self.db.get('mode-selection', 'current') is None:
            self.save(dict(mode='agent', phase='inactive', generation=None, operation_id=None))
        self.open_backend(self.state()['mode'])

    def state(self):
        return self.db.get('mode-selection', 'current')

    def save(self, state):
        self.db.put('mode-selection', 'current', state)
        return state

    def open_backend(self, mode):
        require(self.backend is None, 'Previous service profile is still open', 409)
        self.backend = self.factory(self.config, mode, self.transport)

    @property
    def app(self):
        require(self.backend is not None, 'Mode activation is incomplete; retry the same selection command', 503, 'mode_unavailable')
        return self.backend.app

    def authenticated(self, envelope, audience, operation):
        req = verify_request(envelope, self.config['trust'][audience + '_audience'], operation, self.db)
        require(req['subject'] == 'management' and req['public_key'] == self.config['mode_control_public_key'],
                'Only the owning management service may select execution mode', 403)
        return req['body']

    def wait_idle(self, seconds):
        until = time.monotonic() + seconds
        with self.condition:
            while self.active:
                left = until - time.monotonic()
                require(left > 0, 'Jobs or acknowledgements are still running; retry the same mode selection after they drain',
                        409, 'mode_draining')
                self.condition.wait(min(left, 1))

    def forward(self, method, path, body, maintenance=False):
        with self.condition:
            state = self.state()
            allowed_maintenance = maintenance and state['mode'] == 'native' and state['phase'] in ('draining', 'drained')
            require(state['phase'] == 'ready' or allowed_maintenance, 'Mode selection is not ready; no job was submitted', 409, 'mode_unavailable')
            app = self.app
            self.active += 1
        try:
            result = app.handle(method, path, body)
            if isinstance(result, dict) and path in ('/v1/session', '/v1/run', '/v1/capabilities'):
                result['mode_selection'] = dict(mode=state['mode'], generation=state['generation'])
            return result
        finally:
            with self.condition:
                self.active -= 1
                self.condition.notify_all()

    def close(self):
        if self.backend is not None:
            self.backend.close()
            self.backend = None


class SelectableExecution(ModeService):
    def handle(self, method, path, body):
        if method == 'POST' and path in ('/v2/execution-mode/status', '/v2/execution-mode/drain', '/v2/execution-mode/select'):
            action = path.rsplit('/', 1)[1]
            data = self.authenticated(body, 'execution', 'vm-mode-' + action)
            if action == 'status':
                require(data == {}, 'Mode status takes no fields')
                return self.state()
            require(self.control_lock.acquire(blocking=False), 'Execution mode change already in progress', 409, 'mode_busy')
            try:
                return self.drain_native(data) if action == 'drain' else self.select(data)
            finally:
                self.control_lock.release()
        maintenance = path == '/v2/native/audit'
        return self.forward(method, path, body, maintenance=maintenance)

    def drain_native(self, data):
        require(set(data) == {'operation_id', 'drain_seconds'} and isinstance(data['operation_id'], str)
                and SHA.fullmatch(data['operation_id']), 'Invalid native drain operation')
        require(type(data['drain_seconds']) is int and 0 <= data['drain_seconds'] <= 60, 'Drain deadline must be 0..60 seconds')
        with self.condition:
            state = self.state()
            require(state['mode'] == 'native' and (state['phase'] == 'ready' or state.get('operation_id') == data['operation_id']),
                    'Native drain does not match the current mode operation', 409)
            if state['phase'] == 'drained':
                return state['drain_proof']
            self.save(dict(state, phase='draining', operation_id=data['operation_id']))
        self.wait_idle(data['drain_seconds'])
        app = self.app
        with app.pool_lock:
            for broker in app.brokers.values():
                require(broker.active == 0 and broker.process.poll() in (None, 0), 'Native broker cleanup is unconfirmed', 409, 'cleanup_incomplete')
                if broker.process.poll() is None:
                    token = (broker.root / 'operator.token').read_text().strip()
                    status = self.transport.call(broker.url, '/v1/stats', token=token)
                    require(status.get('requests_inflight') == 0, 'Native host still has a running request', 409, 'mode_draining')
                    os.killpg(broker.process.pid, signal.SIGTERM)
                    try:
                        code = broker.process.wait(timeout=20)
                    except subprocess.TimeoutExpired as exc:
                        raise Error('Native broker did not exit cleanly; no force-kill or mode change was performed', 503, 'cleanup_incomplete') from exc
                    require(code == 0, 'Native broker exit was not clean', 503, 'cleanup_incomplete')
                broker.close()  # Already exited; no SIGKILL fallback can execute.
            app.brokers.clear()
            app.grants.clear()
        checkpoint = app.journal.append('native_drained', dict(operation_id=data['operation_id']))
        proof = app.proof('drain', data['operation_id'], dict(operation_id=data['operation_id'], active_jobs=0, checkpoint=checkpoint))
        with self.condition:
            self.save(dict(self.state(), phase='drained', checkpoint=checkpoint, drain_proof=proof))
        return proof

    def select(self, data):
        require(set(data) == {'operation_id', 'source', 'target'} and data['source'] in ARCHITECTURES and data['target'] in ARCHITECTURES
                and isinstance(data['operation_id'], str) and SHA.fullmatch(data['operation_id']), 'Invalid execution mode selection')
        with self.condition:
            state = self.state()
            if state.get('generation') == data['operation_id'] and state['mode'] == data['target'] and state['phase'] == 'ready':
                return state
            require(state['mode'] in (data['source'], data['target'])
                    and (state['phase'] in ('ready', 'inactive') or state.get('operation_id') == data['operation_id']),
                    'Another execution mode operation is pending', 409)
            require(self.active == 0, 'Execution requests are still active', 409, 'mode_draining')
            if state['mode'] == data['source'] and data['source'] != data['target']:
                if data['source'] == 'agent':
                    require(self.app.runtime is None, 'Retire the agent through its existing lifecycle before changing mode', 409)
                else:
                    require(state['phase'] == 'drained', 'Native audit drain must finish before changing mode', 409)
            self.save(dict(state, phase='switching', operation_id=data['operation_id'], target=data['target']))
        if state['mode'] != data['target']:
            self.close()
            # Persist the destination before opening it: a crash cannot reopen the
            # retired source. Management still blocks jobs until activation succeeds.
            self.save(dict(self.state(), mode=data['target']))
            self.open_backend(data['target'])
        elif self.backend is None:
            self.open_backend(data['target'])
        return self.save(dict(mode=data['target'], phase='ready', generation=data['operation_id'], operation_id=data['operation_id']))


class SelectableManagement(ModeService):
    def __init__(self, config, database, transport, backend_factory=Backend):
        self.key = key_from_hex(read_private(config['mode_control_key'])['private_key'])
        require(public(self.key) == config['mode_control_public_key'], 'Wrong mode-control management key')
        super().__init__(config, database, transport, backend_factory)

    def vm(self, action, **data):
        return self.transport.call(self.config['execution_url'], '/v2/execution-mode/' + action,
            request(self.key, self.config['trust']['execution_audience'], 'vm-mode-' + action, 'management', data))

    def handle(self, method, path, body):
        if method == 'POST' and path in ('/v1/mode/status', '/v1/mode/select'):
            action = path.rsplit('/', 1)[1]
            data = self.authenticated(body, 'management', 'mode-' + action)
            if action == 'status':
                require(data == {}, 'Mode status takes no fields')
                return dict(management=self.state(), execution=self.vm('status'))
            require(set(data) == {'mode', 'drain_seconds'} and data['mode'] in ARCHITECTURES
                    and type(data['drain_seconds']) is int and 0 <= data['drain_seconds'] <= 60, 'Choose agent/native and a drain deadline of 0..60 seconds')
            require(self.control_lock.acquire(blocking=False), 'Mode selection already in progress', 409, 'mode_busy')
            try:
                return self.select(data['mode'], data['drain_seconds'])
            finally:
                self.control_lock.release()
        if method == 'POST' and path == '/v1/benchmark':
            # Complete lease acquisition/release under the admission lock, so
            # a lease cannot appear between the switch preflight and gate closure.
            with self.condition:
                return self.forward(method, path, body)
        return self.forward(method, path, body)

    def select(self, target, seconds):
        with self.condition:
            state = self.state()
            if state['phase'] == 'ready' and state['mode'] == target:
                return dict(state, already_selected=True)
            if state['phase'] in ('ready', 'inactive'):
                # Serializes with all forwarded benchmark-control requests too.
                require(self.app.lease() is None, 'Finish or release the benchmark before changing mode', 409, 'benchmark_busy')
                state = dict(state, phase='draining', source=state['mode'], target=target,
                             operation_id=secrets.token_hex(32), stage='drain', was_ready=state['phase'] == 'ready')
                self.save(state)
            else:
                require(state.get('target') == target, 'Finish the pending mode selection before choosing another mode', 409, 'mode_busy')
        self.wait_idle(seconds)
        if self.backend is None:
            self.open_backend(state['mode'])
        source, operation = state['source'], state['operation_id']
        if state['stage'] == 'drain':
            self.app.audit.event('mode_switch_requested', dict(source=source, target=target, operation_id=operation))
            if state['was_ready'] and source != target:
                if source == 'agent':
                    retired = self.app.undeploy_agent(self.app.targets[0], seconds)
                    require(retired['state'] == 'undeployed', 'Agent drain is incomplete; retry the same mode selection', 409, 'mode_draining')
                else:
                    proof = self.vm('drain', operation_id=operation, drain_seconds=seconds)
                    final = self.app.proof(proof, 'drain', operation)
                    require(final.get('operation_id') == operation and final.get('active_jobs') == 0, 'Invalid native drain receipt', 403)
                    self.app.collect_audit(final['checkpoint'])
                    self.app.audit.event('native_retirement_collected', dict(operation_id=operation, checkpoint=final['checkpoint']))
            state = self.save(dict(state, stage='select-execution'))
        if state['stage'] == 'select-execution':
            selected = self.vm('select', operation_id=operation, source=source, target=target)
            require(selected.get('mode') == target and selected.get('phase') == 'ready'
                    and selected.get('generation') == operation, 'Execution mode acknowledgement mismatch', 503)
            self.close()
            state = self.save(dict(state, mode=target, stage='activate', phase='activating'))
            self.open_backend(target)
        if self.backend is None:
            self.open_backend(target)
        if target == 'agent':
            # Unmodified lifecycle verifies fresh hardware evidence BEFORE deploying.
            activated = self.app.deploy_agent(self.app.targets[0])
            require(activated.get('state') == 'active', 'Attested agent deployment is incomplete', 503)
        else:
            self.app.collect_audit()
        self.app.audit.event('mode_selected', dict(source=source, target=target, operation_id=operation))
        return self.save(dict(mode=target, phase='ready', generation=operation, operation_id=operation,
                              activation_attestation_verified=target == 'agent'))
