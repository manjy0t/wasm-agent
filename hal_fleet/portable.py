"""One attested management-owned orchestration agent per VM; one broker per user.

The gateway is a protected loader/transport. Management supplies grants and the
trusted agent decides when to launch; native HAL enforces the resulting policy.
"""
import os
from pathlib import Path
import tempfile
import threading
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from .attested_channel import (ABI, PROTOCOL, MAX_AGENT, MAX_MESSAGE, AGENT_RIGHTS, CERT_DOMAIN,
    PROOF_DOMAIN, binding_hash, bounded_command, decode, derive, encode, public_hex, seal, unseal,
    verify_evidence, validate_policy)
from .common import (Error, SHA, atomic_json, canonical, digest, key_from_hex, milliseconds, parse,
    public, read_private, request, require, sign, verify, verify_request)
from .local_files import write_private
from .agent_runtime import VMOwner, SharedAgentRuntime
from .runtime import Execution
from .services import Management
from .audit import AuditStore, BoundaryLog, FORMAT as AUDIT_FORMAT
from .lifecycle import ExecutionLifecycle, ManagementLifecycle, PROTOCOL as LIFECYCLE_PROTOCOL
from .lifetimes import MAX_SESSION_SECONDS
def tmpfs_root(path):
    root = Path(path).resolve()
    require(os.name == 'posix' and Path('/proc/self/mountinfo').exists(), 'Agent deployment requires Linux tmpfs', 503)
    mounts = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        mount = Path(left.split()[4].replace('\\040', ' '))
        if root == mount or mount in root.parents:
            mounts.append((len(str(mount)), right.split()[0]))
    require(mounts and max(mounts)[1] == 'tmpfs', 'Agent secrets directory must be on tmpfs', 503)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(root.stat().st_uid == os.geteuid() and root.stat().st_mode & 0o077 == 0,
            'Agent runtime directory must be private and owned by the service', 503)
    return root


class PortableExecution(ExecutionLifecycle, Execution):
    def __init__(self, config, database, transport, runner_factory=SharedAgentRuntime,
                 collector=None, runtime_root=None, allow_test_http=False, sandbox_checker=None):
        require(config.get('mode') == 'wasm' and not config.get('allow_non_tee') and not config.get('test_in_process'),
                'Portable deployment requires a real TEE and workload containers')
        require(config.get('trusted_management_keys') and config.get('platform') in ('intel-tdx', 'amd-sev-snp'),
                'Pin management signing keys and configure the evidence backend')
        super().__init__(config, database, transport, broker_factory=runner_factory)
        self.boundary_log = BoundaryLog(database)
        self.state_lock = threading.RLock()
        self.pending, self.channels = {}, {}
        self.runtime = None
        self.runtime_configuration = None
        self.runtime_identity = None
        self.collector = collector or self.collect
        from .gvisor import check
        self.sandbox_checker = sandbox_checker or check
        self.runtime_root = Path(runtime_root) if runtime_root else tmpfs_root(config.get('agent_runtime_dir', '/run/hal-agents'))
        self.owner = VMOwner(config['state_dir'], self.runtime_root)
        self.check_runner()

    def check_runner(self):
        require(digest(Path(self.config['runner']).read_bytes()) == self.config['runner_sha256'],
                'Installed HAL runner differs from the approved build', 503)

    def collect(self, report_data):
        self.check_runner()
        return bounded_command([self.config['runner'], '--attestation-evidence'],
            {'platform': self.config['platform'], 'report_data': report_data})

    def capabilities(self):
        self.check_runner()
        capabilities = bounded_command([self.config['runner'], '--hal-capabilities'], {})
        # Check the installed runtime before producing a fresh attestation binding
        # or provisioning any agent credentials. Linux acceptance also boots it.
        try:
            runtime = self.sandbox_checker()
        except (OSError, ValueError) as exc:
            raise Error('Required gVisor sandbox unavailable: ' + str(exc), 503) from exc
        require(capabilities.get('workload_sandbox') == runtime.get('profile'),
                'HAL runner and installed sandbox profiles differ', 503)
        capabilities['sandbox_runtime'] = runtime
        from .native_config import service_digest
        capabilities['benchmark_build'] = dict(host_sha256=self.config['runner_sha256'], service_sha256=service_digest())
        return capabilities

    def management_request(self, body, operation):
        req = verify_request(body, self.config['trust']['execution_audience'], operation, self.db, MAX_MESSAGE)
        require(req['public_key'] in self.config['trusted_management_keys'], 'Untrusted management signer', 403)
        self.owner.check(req['public_key'])
        return req

    def challenge(self, envelope):
        req = self.management_request(envelope, 'agent-challenge')
        data = req['body']
        require(set(data) == {'challenge', 'agent_sha256', 'configuration_sha256', 'interface', 'lease_seconds'}, 'Invalid challenge')
        require(all(isinstance(data[k], str) and SHA.fullmatch(data[k]) for k in ('challenge', 'agent_sha256', 'configuration_sha256')),
                'Invalid challenge digest')
        require(data['interface'] == ABI, 'The management agent requires a different HAL interface', 409)
        require(type(data['lease_seconds']) is int and 60 <= data['lease_seconds'] <= MAX_SESSION_SECONDS, 'Invalid lease')
        key = X25519PrivateKey.generate()
        caps = self.capabilities()
        binding = dict(data, protocol=PROTOCOL, deployment_id=uuid.uuid4().hex,
            management_key=req['public_key'], recipient_key=public_hex(key), capabilities=caps,
            vm_id=self.owner.record['vm_id'], audience=self.config['trust']['execution_audience'],
            execution_url=self.config['execution_url'], expires_unix=int(time.time()) + 120)
        with self.state_lock:
            self.pending = {k: v for k, v in self.pending.items() if v['binding']['expires_unix'] > time.time()}
            require(len(self.pending) < 16, 'Challenge capacity reached', 429)
            self.pending[binding['deployment_id']] = {'binding': binding, 'key': key}
        try:
            return dict(binding=binding, evidence=self.collector(binding_hash(binding)))
        except Exception:
            with self.state_lock:
                self.pending.pop(binding['deployment_id'], None)
            raise

    def deploy(self, envelope):
        req = self.management_request(envelope, 'agent-deploy')
        data = req['body']
        require(set(data) == {'deployment_id', 'sender_key', 'sealed'}, 'Invalid deployment request')
        with self.state_lock:
            pending = self.pending.get(data['deployment_id'])
            require(pending and pending['binding']['expires_unix'] > time.time(), 'Deployment challenge expired', 409, 'session_changed')
            binding = pending['binding']
            require(binding['management_key'] == req['public_key'], 'Wrong deployment owner', 403)
            key = derive(pending['key'], data['sender_key'], binding)
            payload = unseal(key, binding, 'deploy', data['sealed'])
            del self.pending[data['deployment_id']]
            require(set(payload) == {'agent_base64', 'configuration', 'challenge'}, 'Invalid deployment payload')
            raw = decode(payload['agent_base64'], MAX_AGENT)
            require(raw.startswith(b'\0asm') and digest(raw) == binding['agent_sha256'], 'Agent fingerprint mismatch', 403)
            configuration = payload['configuration']
            require(isinstance(configuration, dict) and len(canonical(configuration).encode()) <= 65536
                    and digest(canonical(configuration).encode()) == binding['configuration_sha256'], 'Agent configuration mismatch')
            rights = configuration.get('agent_permissions', AGENT_RIGHTS)
            require(isinstance(rights, list) and all(isinstance(r, str) for r in rights)
                    and len(rights) == len(set(rights)) and set(rights) <= set(AGENT_RIGHTS), 'Invalid agent HAL permissions')
            if self.lifecycle_state()['state'] != 'active':
                require(self.runtime is not None and self.runtime.process.poll() is None,
                        'Agent is undeployed or retirement recovery is required', 409, 'agent_unavailable')
            self.owner.claim(req['public_key'])  # Remains claimed after failure, expiry and restart.
            if self.runtime and self.runtime.process.poll() is not None:
                self.runtime.close()
                self.runtime = None
                self.channels.clear()
            identity = (binding['agent_sha256'], binding['configuration_sha256'])
            if self.runtime:
                require(identity == self.runtime_configuration, 'An agent is already deployed; an owner-controlled service restart is required to replace it',
                        409, 'agent_already_deployed')
            else:
                self.check_runner()
                directory = Path(tempfile.mkdtemp(prefix='a-', dir=self.runtime_root))
                write_private(directory / 'agent.wasm', raw, exclusive=True)
                checked = bounded_command([self.config['runner'], '--check-agent', str(directory / 'agent.wasm')], {})
                require(checked['interface'] == ABI and checked['sha256'] == binding['agent_sha256'], 'Agent HAL world mismatch')
                config = dict(runtime_dir=str(directory), runner=self.config['runner'],
                    slot_lock=str(self.runtime_root / 'active-agent.lock'), vm_id=binding['vm_id'],
                    agent=str(directory / 'agent.wasm'), agent_sha256=binding['agent_sha256'],
                    management_key=req['public_key'], audience=binding['audience'],
                    agent_permissions=rights, configuration=configuration,
                    settings=self.config.get('settings', {}), max_active_users=self.config.get('max_active_users', 64),
                    container_image=self.config.get('container_image', 'hal-user-worker:local'), test_in_process=False)
                config.update(audit_path=str(Path(self.config['state_dir']) / 'audit' / 'agent.jsonl'),
                              audit_max_bytes=self.config.get('audit_max_bytes', 256 * 1024 * 1024))
                self.runtime = self.factory(config)
                self.runtime_configuration = identity
            self.channels = {k: v for k, v in self.channels.items() if v['expires'] > time.time()}
            require(len(self.channels) < 16, 'Agent channel capacity reached', 429)
            self.channels[binding['deployment_id']] = dict(key=key, binding=binding, runtime=self.runtime,
                expires=int(time.time()) + binding['lease_seconds'])
            proof = self.runtime.call('status', challenge=payload['challenge'])
            self.runtime_identity = parse(proof['payload'])['identity']
            return seal(key, binding, 'deployed', dict(proof=proof))

    def channel(self, body):
        require(isinstance(body, dict) and set(body) == {'deployment_id', 'sealed'}, 'Invalid protected channel')
        with self.state_lock:
            channel = self.channels.get(body['deployment_id'])
            require(channel and channel['expires'] > time.time() and channel['runtime'] is self.runtime
                    and self.runtime.process.poll() is None, 'Agent channel expired or restarted', 409, 'session_changed')
            return channel

    def handle(self, method, path, body):
        try:
            return self.handle_logged(method, path, body)
        except Error as exc:
            paths = ('/v2/agent/challenge', '/v2/agent/deploy', '/v2/agent/activate',
                     '/v2/agent/status', '/v2/agent/run', '/v2/agent/enroll', '/v2/agent/audit', '/v1/enroll',
                     '/v2/agent/drain', '/v2/agent/retire', '/v2/agent/resume', '/v2/agent/lifecycle-status')
            self.boundary_log.rejected(path if path in paths else 'other', exc.code)
            raise

    def handle_logged(self, method, path, body):
        if method == 'POST' and path in ('/v2/agent/lifecycle-status', '/v2/agent/retire', '/v2/agent/resume'):
            return self.lifecycle_control(path.rsplit('/', 1)[1], body)
        if method == 'POST' and path == '/v2/agent/challenge':
            return self.challenge(body)
        if method == 'POST' and path == '/v2/agent/deploy':
            return self.deploy(body)
        operations = {'/v2/agent/status': 'status', '/v2/agent/activate': 'activate',
                      '/v2/agent/enroll': 'enroll', '/v2/agent/run': 'run', '/v2/agent/audit': 'audit', '/v2/agent/drain': 'drain'}
        if method == 'POST' and path in operations:
            operation = operations[path]
            channel = self.channel(body)
            payload = unseal(channel['key'], channel['binding'], operation, body['sealed'])
            if operation == 'drain':
                result = self.drain_agent(channel, payload)
                return seal(channel['key'], channel['binding'], 'drain-result', dict(value=result))
            if operation in ('run', 'enroll'):
                with self.state_lock:
                    self.accepting_jobs()
            allowed = dict(status={'challenge'}, activate={'certificate', 'challenge'}, enroll={'grant'}, run={'request'},
                           audit={'after', 'previous_hash', 'limit', 'challenge'})
            require(set(payload) == allowed[operation], 'Unexpected control fields')
            result = channel['runtime'].call(operation, **payload)
            return seal(channel['key'], channel['binding'], operation + '-result', dict(value=result))
        if method == 'POST' and path == '/v1/enroll':
            return super().handle(method, path, body)  # Public identity enrollment does not deploy an agent.
        raise Error('Use the management session and protected agent APIs', 409, 'management_session_required')

    def close(self):
        with self.state_lock:
            if self.runtime:
                self.runtime.close()
            self.channels.clear()
            self.pending.clear()
            self.owner.close()


class PortableManagement(ManagementLifecycle, Management):
    def __init__(self, config, database, transport, *, allow_test_in_process=False):
        super().__init__(config, database, transport)
        self.expected_isolation = 'in-process' if allow_test_in_process else 'per-user-container'
        self.key = key_from_hex(read_private(config['management_key'])['private_key'])
        self.audit = AuditStore(database, self.key, config.get('audit_max_records', 200000))
        self.audit_lock = threading.RLock()
        self.agent = Path(config['managed_agent']).read_bytes()
        require(len(self.agent) <= MAX_AGENT and digest(self.agent) == config['managed_agent_sha256'], 'Management agent changed; review its build')
        self.targets = config.get('execution_targets') or [dict(url=config['execution_url'], attestation_policy=config['attestation_policy'])]
        require(isinstance(self.targets, list) and 1 <= len(self.targets) <= 32, 'Configure 1..32 execution VMs')
        require(len({t['url'] for t in self.targets}) == len(self.targets), 'Duplicate execution target')
        self.policies = {t['url']: validate_policy(parse(Path(t['attestation_policy']).read_text())) for t in self.targets}
        self.sessions, self.channels = {}, {}
        self.session_lock = threading.RLock()
        self.init_lifecycle()

    def signed_execution(self, operation, body):
        return request(self.key, self.config['trust']['execution_audience'], operation, 'management', body)

    def collect_audit(self, channel, required=None):
        # Collection and anchor advancement are serialized, but workload execution
        # stays concurrent. No private keys, inputs or file credentials are logged.
        with self.audit_lock:
            vm_id = channel['identity']['vm_id']
            self.audit.bind_target(channel['url'], vm_id)
            target = None
            for _ in range(2048):
                head = self.audit.head(vm_id)
                nonce = os.urandom(32).hex()
                page = self.proof(channel, self.call_channel(channel, 'audit', after=head['sequence'],
                    previous_hash=head['hash'], limit=64, challenge=nonce), 'audit', nonce)
                require(page.get('tip', {}).get('vm_id') == vm_id
                        and type(page['tip'].get('sequence')) is int and page['tip']['sequence'] >= head['sequence'],
                        'Audit journal rolled back', 409, 'audit_integrity_failed')
                if target is None:
                    target = page['tip']['sequence']
                latest = self.audit.ingest(vm_id, page)
                if latest['sequence'] >= target:
                    require(required is None or self.audit.contains(required), 'Result audit record not collected',
                            503, 'audit_unavailable')
                    return latest
                require(latest['sequence'] > head['sequence'], 'Audit collection made no progress', 503, 'audit_unavailable')
            raise Error('Audit catch-up limit reached; retry collection without resubmitting jobs', 503, 'audit_unavailable')

    def call_channel(self, channel, operation, **payload):
        response = self.transport.call(channel['url'], '/v2/agent/' + operation,
            dict(deployment_id=channel['binding']['deployment_id'], sealed=seal(channel['key'], channel['binding'], operation, payload)))
        return unseal(channel['key'], channel['binding'], operation + '-result', response)['value']

    def proof(self, channel, envelope, kind, challenge):
        proof = verify(channel['identity']['public_key'], PROOF_DOMAIN, envelope)
        require(proof.get('identity') == channel['identity'] and proof.get('kind') == kind
                and proof.get('challenge') == challenge, 'Agent identity proof mismatch', 403)
        return proof['data']

    def connect(self, target, *, maintenance=False, minimum_validity_seconds=10):
        url = target['url']
        require(maintenance or self.target_enabled(url), 'Execution target is draining or undeployed', 409, 'agent_unavailable')
        old = self.channels.get(url)
        if old and old['deadline'] > time.monotonic() + minimum_validity_seconds:
            nonce = os.urandom(32).hex()
            try:
                self.proof(old, self.call_channel(old, 'status', challenge=nonce), 'status', nonce)
                self.collect_audit(old)
                return old
            except Error as exc:
                if exc.code != 'session_changed':
                    raise
                self.channels.pop(url, None)
        policy = self.policies[url]
        configuration = dict(self.config.get('agent_configuration', {}))
        expected = dict(challenge=os.urandom(32).hex(), agent_sha256=digest(self.agent), interface=ABI,
            configuration_sha256=digest(canonical(configuration).encode()), lease_seconds=policy['lease_seconds'])
        started = time.perf_counter()
        response = self.transport.call(url, '/v2/agent/challenge', self.signed_execution('agent-challenge', expected))
        binding = response['binding']
        require(set(binding) == set(expected) | {'protocol', 'deployment_id', 'management_key', 'recipient_key',
                'capabilities', 'vm_id', 'audience', 'execution_url', 'expires_unix'}, 'Unexpected attestation binding')
        require(all(binding.get(k) == v for k, v in expected.items()) and binding['protocol'] == PROTOCOL
                and binding['management_key'] == public(self.key) and binding['execution_url'] == url
                and binding['audience'] == self.config['trust']['execution_audience'] and SHA.fullmatch(binding['vm_id'])
                and type(binding['expires_unix']) is int and time.time() < binding['expires_unix'] <= time.time() + 125,
                'Attestation does not describe this deployment', 403)
        capabilities = binding['capabilities']
        require(capabilities.get('interface') == ABI and capabilities.get('single_agent') is True
                and capabilities.get('mandatory_workload_policy') is True
                and set(AGENT_RIGHTS) <= set(capabilities.get('agent_rights', [])), 'VM lacks required HAL functions', 409)
        require(capabilities.get('agent_undeployment') == LIFECYCLE_PROTOCOL, 'VM lacks safe agent undeployment', 409)
        require(capabilities.get('audit_log') == AUDIT_FORMAT, 'VM lacks mandatory agent auditing', 409)
        from .gvisor import profile as sandbox_profile
        require(capabilities.get('workload_sandbox') == sandbox_profile()
                and capabilities.get('sandbox_runtime', {}).get('configuration_checked') is True
                and capabilities['sandbox_runtime'].get('profile') == sandbox_profile(),
                'VM lacks the required gVisor per-user sandbox', 409)
        # The authenticated quote covers the capability manifest, channel key and owner.
        verified = verify_evidence(policy, response['evidence'], binding)
        self.audit.event('platform_verified', dict(vm_id=binding['vm_id'], agent_sha256=digest(self.agent)), admission=True)
        nonce = os.urandom(32).hex()
        sender = X25519PrivateKey.generate()
        key = derive(sender, binding['recipient_key'], binding)
        deployed = self.transport.call(url, '/v2/agent/deploy', self.signed_execution('agent-deploy',
            dict(deployment_id=binding['deployment_id'], sender_key=public_hex(sender),
                sealed=seal(key, binding, 'deploy', dict(agent_base64=encode(self.agent), configuration=configuration, challenge=nonce)))))
        receipt = unseal(key, binding, 'deployed', deployed)['proof']
        identity = parse(receipt['payload'])['identity']
        require(set(identity) == {'vm_id', 'instance', 'agent_sha256', 'interface', 'public_key', 'management_key'}
                and identity['vm_id'] == binding['vm_id'] and identity['agent_sha256'] == digest(self.agent)
                and identity['interface'] == ABI and identity['management_key'] == public(self.key)
                and SHA.fullmatch(identity['instance']), 'Loaded agent identity mismatch', 403)
        channel = dict(url=url, key=key, binding=binding, identity=identity, attestation=verified)
        self.proof(channel, receipt, 'status', nonce)
        expires = verified['verified_unix'] + policy['lease_seconds']
        cert = sign(self.key, CERT_DOMAIN, dict(version=1, kind='agent-identity', identity=identity,
                    issued_unix=int(time.time()), expires_unix=expires))
        self.proof(channel, self.call_channel(channel, 'activate', certificate=cert, challenge=nonce), 'activated', nonce)
        self.collect_audit(channel)
        self.audit.event('agent_activated', dict(vm_id=identity['vm_id'], agent_instance=identity['instance']))
        channel.update(certificate=cert, expires=expires, deadline=time.monotonic() + max(0, expires-time.time()),
                       attestation_ms=milliseconds(started))
        self.channels[url] = channel
        return channel

    def session(self, envelope):
        req = verify_request(envelope, self.config['trust']['management_audience'], 'session', self.db)
        require(set(req['body']) in ({'document'}, {'document', 'minimum_validity_seconds'}), 'Invalid session request')
        minimum = req['body'].get('minimum_validity_seconds', 10)
        require(type(minimum) is int and 10 <= minimum <= MAX_SESSION_SECONDS, 'Invalid minimum session validity')
        document = req['body']['document']
        doc = self.check_document(document)
        require(doc['subject'] == req['subject'] and doc['public_key'] == req['public_key'], 'Session user mismatch', 403)
        require(doc['workloads'], 'Approve workloads first', 403)
        with self.session_lock:
            old = self.sessions.get(doc['subject'])
            if old and not self.target_enabled(old['target']['url']):
                old = None
            if old and old['session']['revision'] == doc['revision'] and old['expires'] > time.time() + minimum:
                channel = self.connect(old['target'], minimum_validity_seconds=minimum)
                if channel['identity'] == old['channel']['identity'] and old['expires'] > time.time() + minimum:
                    old['channel'] = channel
                    return old['session']
            # Stable reuse for an existing user; otherwise spread users across available VMs.
            targets = sorted([t for t in self.targets if self.target_enabled(t['url'])], key=lambda t: sum(s['target']['url'] == t['url'] for s in self.sessions.values()))
            if old:
                targets = [old['target']] + [t for t in targets if t['url'] != old['target']['url']]
            failures = []
            for target in targets:
                try:
                    require(self.policies[target['url']]['lease_seconds'] > minimum,
                            'Approved attestation lease is too short for the requested session validity', 409)
                    channel = self.connect(target, minimum_validity_seconds=minimum)
                    break
                except Error as exc:
                    failures.append(str(exc))
            else:
                raise Error('No compatible verified execution VM is available: ' + '; '.join(failures), 503, 'no_execution_target')
            # File credentials are issued only after platform verification and agent activation.
            grant = self.transport.call(self.config['files_url'], '/v2/access', request(self.key,
                self.config['trust']['files_audience'], 'agent-file-access', doc['subject'],
                dict(artifacts=sorted({w['sha256'] for w in doc['workloads']}), ttl_seconds=self.policies[target['url']]['lease_seconds'])))
            expires = min(grant['expires_unix'], channel['expires'], doc['expires_unix'])
            credentials = dict(document=doc, file_server=self.config['files_url'] + '/artifacts/',
                               file_token=grant['token'], expires_unix=expires)
            if self.config.get('ca_file'):
                credentials['file_ca_pem'] = Path(self.config['ca_file']).read_text()
            session = self.call_channel(channel, 'enroll', grant=credentials)
            self.collect_audit(channel)
            require(expires > time.time() + minimum,
                    'Verified session has insufficient remaining lifetime; no job was submitted', 409, 'session_changed')
            require(session.get('tenant') == doc['subject'] and session.get('revision') == doc['revision']
                    and session.get('audience') == self.config['trust']['execution_audience']
                    and session.get('mode') == 'wasm' and session.get('isolation') == self.expected_isolation,
                    'Agent enrollment acknowledgement mismatch', 403)
            session.update(expires_unix=expires, execution_url=target['url'], execution_architecture=PROTOCOL,
                attestation_verified=True, attestation=channel['attestation'], attestation_ms=channel['attestation_ms'],
                interface=ABI, agent_sha256=digest(self.agent), agent_identity=channel['identity'],
                agent_certificate=channel['certificate'], audit_log=AUDIT_FORMAT)
            session['build'] = channel['binding']['capabilities'].get('benchmark_build', {})
            session['workload_configuration'] = self.config.get('agent_configuration', {})
            require(len(self.sessions) < 64 or doc['subject'] in self.sessions, 'Session capacity reached', 429)
            self.sessions[doc['subject']] = dict(session=session, target=target, channel=channel, expires=expires)
            return session

    def dispatch(self, body):
        from .policy import certificate
        doc = certificate(body['document'], self.config)
        with self.session_lock:
            session = self.sessions.get(doc['subject'])
            require(session and session['session']['revision'] == doc['revision'] and session['expires'] > time.time(),
                    'Attested session expired; reopen session', 409, 'session_changed')
            channel = session['channel']
            require(self.target_enabled(channel['url']), 'Execution target is draining or undeployed', 409, 'agent_unavailable')
            self.dispatches[channel['url']] = self.dispatches.get(channel['url'], 0) + 1
        try:
            return self.dispatch_job(body, doc, channel)
        finally:
            with self.dispatch_condition:
                self.dispatches[channel['url']] -= 1
                self.dispatch_condition.notify_all()

    def dispatch_job(self, body, doc, channel):
        row = next(w for w in doc['workloads'] if w['sha256'] == body['job']['sha256'])
        submitted = dict(tenant=doc['subject'], revision=doc['revision'], job=body['job'], policy=row['rule'])
        metadata = dict(tenant=doc['subject'], user_key=doc['public_key'], job_id=body['job']['job_id'],
                        artifact_sha256=row['sha256'], vm_id=channel['identity']['vm_id'])
        self.collect_audit(channel)
        self.audit.event('job_dispatch_requested', metadata, admission=True)
        try:
            signed_result = self.call_channel(channel, 'run', request=submitted)
            result = self.proof(channel, signed_result, 'result', body['job']['job_id'])
            require(isinstance(result.get('audit'), dict) and result['audit']['vm_id'] == metadata['vm_id'],
                    'Missing result audit commitment', 503, 'audit_unavailable')
            self.collect_audit(channel, result['audit'])
            self.audit.check_completion(result['audit'], metadata, result)
        except Exception as exc:
            # Execution may already have occurred. Audit trouble is never a basis
            # for rerunning the job or reporting that execution definitely failed.
            try:
                self.collect_audit(channel)
                self.audit.event('job_outcome_unknown', metadata)
            except Exception:
                pass  # The durable pre-dispatch record remains unresolved.
            raise Error('Execution/audit acknowledgement unavailable; job may have run. Do not resubmit.',
                        503, 'outcome_unknown') from exc
        require(result.get('job_id') == body['job']['job_id'] and result.get('tenant') == doc['subject']
                and result.get('sha256') == body['job']['sha256'], 'Result belongs to another workload', 403)
        self.audit.event('job_acknowledged', dict(metadata, outcome='unknown' if result.get('execution_outcome') == 'unknown'
                        else 'completed' if result.get('status') == 'ok' else 'failed', audit=result['audit']))
        result.update(audit_collected=True, agent_result_proof=signed_result, agent_certificate=channel['certificate'])
        result.update(attestation_verified=True, attestation=channel['attestation'],
                      execution_architecture=PROTOCOL, gateway_signature_checked=True,
                      agent_identity_verified=True, execution_url=channel['url'])
        return result

    def handle(self, method, path, body):
        try:
            return self.handle_audited(method, path, body)
        except Error as exc:
            # No claimed user identity or raw request/exception text is recorded.
            self.audit.event('request_rejected', dict(operation=path if path in
                ('/v1/session', '/v1/run', '/v1/audit', '/v1/approve', '/v1/result') else 'other',
                reason=exc.code), admission=True)
            raise

    def handle_audited(self, method, path, body):
        if method == 'POST' and path in ('/v2/agents/status', '/v2/agents/undeploy', '/v2/agents/deploy'):
            return self.lifecycle_request(path.rsplit('/', 1)[1], body)
        if method == 'GET' and path == '/v1/capabilities':
            return dict(session_via_management=True, execution_architecture=PROTOCOL, interface=ABI,
                        attestation_required=True, agent_scope='one-per-vm', execution_targets=len(self.targets), audit_log=AUDIT_FORMAT, agent_undeployment=LIFECYCLE_PROTOCOL,
                        session_minimum_validity=True)
        if method == 'POST' and path == '/v1/session':
            return self.session(body)
        if method == 'POST' and path == '/v1/audit':
            req = verify_request(body, self.config['trust']['management_audience'], 'audit', self.db)
            require(set(req['body']) <= {'document', 'after', 'limit', 'job_id'}, 'Invalid audit request')
            doc = self.check_document(req['body'].get('document'))
            require(doc['subject'] == req['subject'] and doc['public_key'] == req['public_key'], 'Audit user mismatch', 403)
            self.audit.event('audit_read', dict(viewer_key_sha256=digest(req['public_key'].encode())), admission=True)
            return self.audit.user_page(doc['subject'], doc['public_key'], req['body'].get('after', 0),
                                        req['body'].get('limit', 50), req['body'].get('job_id'))
        return super().handle(method, path, body)
