"""Private native runner transport and persistent ownership of one VM agent slot."""
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from .common import Error, atomic_json, canonical, parse, require, read_private, SHA


class VMOwner:
    def __init__(self, state, runtime):
        import fcntl
        self.path = Path(state) / 'agent-owner.json'
        self.lock = os.open(Path(runtime) / 'gateway.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not self.path.exists():
                atomic_json(self.path, dict(version=1, vm_id=os.urandom(32).hex(), management_key=None), exclusive=True)
            self.record = read_private(self.path)
            require(self.record.get('version') == 1 and isinstance(self.record.get('vm_id'), str) and SHA.fullmatch(self.record['vm_id'])
                    and (self.record.get('management_key') is None or (isinstance(self.record['management_key'], str) and SHA.fullmatch(self.record['management_key']))),
                    'Invalid persistent VM ownership record')
        except Exception:
            os.close(self.lock)
            raise

    def check(self, key):
        require(self.record['management_key'] in (None, key),
                'This VM belongs to another management service', 403, 'vm_owned')

    def claim(self, key):
        self.check(key)
        if self.record['management_key'] is None:
            # Called while the service holds both the VM file lock and deployment mutex.
            updated = dict(self.record, management_key=key)
            atomic_json(self.path, updated)
            self.record = updated

    def close(self):
        os.close(self.lock)


class SharedAgentRuntime:
    def __init__(self, config):
        self.root = Path(config['runtime_dir'])
        self.process = None
        self.log = None
        atomic_json(self.root / 'runtime.json', config, exclusive=True)
        try:
            self.log = (self.root / 'runtime.log').open('ab')
            self.process = subprocess.Popen([config['runner'], '--orchestrator-config', str(self.root / 'runtime.json')],
                stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log, start_new_session=True)
            until = time.monotonic() + 60
            while True:
                require(self.process.poll() is None, 'Shared agent failed to start; inspect ' + str(self.root / 'runtime.log'), 503)
                if (self.root / 'agent.sock').exists():
                    break
                require(time.monotonic() < until, 'Shared agent startup timed out', 503)
                time.sleep(.025)
        except Exception:
            self.close()
            raise

    def call(self, operation, **body):
        require(self.process.poll() is None, 'Shared agent exited; reopen session', 409, 'session_changed')
        raw = (canonical(dict(op=operation, **body)) + '\n').encode()
        require(len(raw) <= 2 * 1024 * 1024, 'Agent command too large', 413)
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(150)
                connection.connect(str(self.root / 'agent.sock'))
                connection.sendall(raw)
                with connection.makefile('rb') as stream:
                    line = stream.readline(2 * 1024 * 1024 + 1)
            require(line.endswith(b'\n') and len(line) <= 2 * 1024 * 1024, 'Invalid native agent response', 502)
            result = parse(line)
            require(result.get('ok') is True, result.get('error', 'Agent request failed'), 409, 'agent_rejected')
            return result['value']
        except OSError as exc:
            # Never repeat a job on a socket failure: it may still be running.
            raise Error('Native agent connection failed; do not automatically repeat a job', 503, 'outcome_unknown') from exc

    def retire(self):
        """Only after native drain and management collection of the final audit record.

        No SIGKILL fallback: that would not establish successful worker cleanup.
        Deleting private tmpfs files is lifecycle cleanup, not a secure-erasure claim.
        """
        try:
            if self.process and self.process.poll() is None:
                os.kill(self.process.pid, signal.SIGTERM)
            require(self.process is not None and self.process.wait(timeout=30) == 0,
                    'Agent did not confirm a clean exit; retirement incomplete', 503, 'cleanup_incomplete')
            if self.log:
                self.log.close()
                self.log = None
            if self.root.exists():
                require(not self.root.is_symlink(), 'Runtime directory changed', 503, 'cleanup_incomplete')
                shutil.rmtree(self.root)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Error('Agent cleanup could not be confirmed; target stays disabled. Inspect runtime and Docker state.',
                        503, 'cleanup_incomplete') from exc

    def close(self):
        if self.process and self.process.poll() is None:
            # Let the shared runner drain and stop its user brokers and containers.
            os.kill(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=10)
        if self.log:
            self.log.close()
        # Successful cleanup is scoped to this random runtime directory.
        # Preserve logs on startup failure for diagnosis; never remove the owner file.
