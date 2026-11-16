"""Owner-only agent retirement: stop admission, collect audit, then destroy runtime.

The VM owner is never released. A drain timeout leaves admission closed; it is
not a request to kill or rerun jobs. All retries use the same retirement id.
"""
import os
import threading
import time
from .common import Error, SHA, public, require, verify, verify_request
from .attested_channel import PROOF_DOMAIN

PROTOCOL = 'drain-audit-retire-v1'


def operation_id(value):
    require(isinstance(value, str) and SHA.fullmatch(value), 'Invalid retirement identifier')
    return value


class ExecutionLifecycle:
    def lifecycle_state(self):
        return self.db.get('agent-lifecycle', 'current', {'state': 'active'})

    def accepting_jobs(self):
        require(self.lifecycle_state()['state'] == 'active',
                'Agent is draining or undeployed; management must explicitly deploy it', 409, 'agent_unavailable')

    def lifecycle_control(self, action, envelope):
        req = self.management_request(envelope, 'agent-' + action)
        data = req['body']
        with self.state_lock:
            state = self.lifecycle_state()
            if action == 'lifecycle-status':
                require(data == {}, 'Invalid lifecycle status request')
                return dict(state, vm_id=self.owner.record['vm_id'],
                            ownership_reserved=self.owner.record['management_key'] is not None,
                            runtime_alive=bool(self.runtime and self.runtime.process.poll() is None))
            require(set(data) == ({'operation_id', 'identity', 'checkpoint'} if action == 'retire' else {'operation_id'}),
                    'Invalid lifecycle control fields')
            identifier = operation_id(data['operation_id'])
            require(state.get('operation_id') == identifier, 'Retirement does not match this VM', 409)
            if action == 'resume':
                require(state['state'] in ('undeployed', 'active'), 'Cleanup is not complete', 409, 'cleanup_incomplete')
                # Idempotent after a lost response; never clears another retirement.
                self.db.put('agent-lifecycle', 'current', dict(state, state='active'))
                return dict(state='active', operation_id=identifier, ownership_reserved=True)
            require(action == 'retire', 'Unknown lifecycle operation')
            require(state.get('identity') == data['identity'] and state.get('checkpoint') == data['checkpoint'],
                    'Retirement identity/checkpoint mismatch', 409)
            if state['state'] == 'undeployed':
                return state
            require(state['state'] == 'drained', 'Agent must finish draining first', 409)
            require(self.runtime is not None, 'Runtime was lost during retirement; investigate cleanup before redeployment',
                    503, 'cleanup_incomplete')
            # Native drain already confirmed every user broker/worker has stopped.
            # Refuse to claim success if termination or private-directory removal fails.
            self.runtime.retire()
            receipt = dict(state, state='undeployed', runtime_exit_confirmed=True,
                           runtime_files_removed=True, ownership_reserved=True)
            self.db.put('agent-lifecycle', 'current', receipt)
            self.runtime = None
            self.runtime_configuration = None
            self.channels.clear()
            self.pending.clear()
            return receipt

    def drain_agent(self, channel, payload):
        require(set(payload) == {'operation_id', 'agent_instance', 'drain_seconds', 'challenge'}, 'Invalid drain request')
        identifier = operation_id(payload['operation_id'])
        require(type(payload['drain_seconds']) is int and 0 <= payload['drain_seconds'] <= 60, 'Drain deadline must be 0..60 seconds')
        operation_id(payload['challenge'])
        with self.state_lock:
            require(channel['runtime'] is self.runtime and payload['agent_instance'] == self.runtime_identity['instance'],
                    'Drain targets another agent', 409)
            state = self.lifecycle_state()
            if state['state'] == 'active':
                state = dict(state='draining', operation_id=identifier, identity=self.runtime_identity)
                # Persist before issuing the native command. Restart cannot reopen admission.
                self.db.put('agent-lifecycle', 'current', state)
                self.pending.clear()
            require(state.get('operation_id') == identifier and state['state'] in ('draining', 'drained'),
                    'Another retirement is in progress', 409)
        proof = channel['runtime'].call('drain', **payload)
        checked = verify(state['identity']['public_key'], PROOF_DOMAIN, proof)
        require(checked.get('identity') == state['identity'] and checked.get('kind') == 'drain'
                and checked.get('challenge') == payload['challenge'], 'Invalid drain identity proof', 403)
        result = checked['data']
        require(result.get('operation_id') == identifier, 'Wrong retirement receipt', 403)
        if result.get('state') == 'drained':
            require(result.get('active_jobs') == 0 and result.get('ownership_reserved') is True, 'Incomplete drain', 409)
            with self.state_lock:
                current = self.lifecycle_state()
                require(current.get('operation_id') == identifier and current['state'] in ('draining', 'drained'),
                        'Retirement changed during drain', 409)
                self.db.put('agent-lifecycle', 'current', dict(state, state='drained',
                            checkpoint=result['checkpoint'], drain_proof=proof))
        return proof


class ManagementLifecycle:
    def init_lifecycle(self):
        self.lifecycle_locks = {t['url']: threading.Lock() for t in self.targets}
        self.dispatches = {}
        self.dispatch_condition = threading.Condition(self.session_lock)

    def target_state(self, url):
        return self.db.get('agent-target', url, {'state': 'active'})

    def target_enabled(self, url):
        return self.target_state(url)['state'] == 'active'

    def execution_control(self, url, action, body):
        return self.transport.call(url, '/v2/agent/' + action, self.signed_execution('agent-' + action, body))

    def lifecycle_request(self, action, envelope):
        req = verify_request(envelope, self.config['trust']['management_audience'], 'agent-' + action, self.db)
        require(req['public_key'] == public(self.key) and req['subject'] == 'management',
                'Only the owning management service may control agent deployments', 403)
        data = req['body']
        require(set(data) == ({'execution_url', 'drain_seconds'} if action == 'undeploy' else {'execution_url'}),
                'Invalid agent control fields')
        target = next((t for t in self.targets if t['url'] == data['execution_url']), None)
        require(target is not None, 'Execution URL is not a configured target', 403)
        url = target['url']
        if action == 'status':
            return dict(execution_url=url, management=self.target_state(url),
                        execution=self.execution_control(url, 'lifecycle-status', {}))
        if action == 'undeploy':
            require(type(data['drain_seconds']) is int and 0 <= data['drain_seconds'] <= 60,
                    'Drain deadline must be 0..60 seconds')
        require(action in ('undeploy', 'deploy'), 'Unknown agent control command')
        lock = self.lifecycle_locks[url]
        require(lock.acquire(blocking=False), 'A lifecycle command is already in progress; check agent-status', 409, 'lifecycle_busy')
        try:
            return self.undeploy_agent(target, data['drain_seconds']) if action == 'undeploy' else self.deploy_agent(target)
        finally:
            lock.release()

    def save_target(self, url, state):
        self.db.put('agent-target', url, state)
        return dict(state, execution_url=url)

    def undeploy_agent(self, target, seconds):
        url = target['url']
        deadline = time.monotonic() + seconds
        with self.session_lock:
            state = self.target_state(url)
            if state['state'] == 'undeployed':
                return dict(state, execution_url=url)
            require(state['state'] in ('active', 'draining', 'retiring'), 'Deployment is in progress', 409)
            if state['state'] == 'active':
                state = dict(state='draining', operation_id=os.urandom(32).hex())
                # User sessions cannot cause an automatic redeployment, even after restart.
                self.save_target(url, state)
                self.audit.event('agent_undeployment_requested', dict(execution_url=url, operation_id=state['operation_id']))
        if state['state'] != 'retiring':
            # Never create a new agent just to shut it down.
            status = self.execution_control(url, 'lifecycle-status', {})
            require(status['runtime_alive'], 'No live agent to drain; target remains disabled. Check execution service state.',
                    409, 'agent_unavailable')
            with self.session_lock:
                channel = self.connect(target, maintenance=True)
            nonce = os.urandom(32).hex()
            proof = self.call_channel(channel, 'drain', operation_id=state['operation_id'],
                agent_instance=channel['identity']['instance'], drain_seconds=max(0, int(deadline-time.monotonic())), challenge=nonce)
            result = self.proof(channel, proof, 'drain', nonce)
            require(result.get('operation_id') == state['operation_id'] and result.get('ownership_reserved') is True,
                    'Unexpected drain receipt', 403)
            require(result.get('state') in ('draining', 'drained'), 'Unexpected drain state', 403)
            if result['state'] != 'drained':
                return dict(state, execution_url=url, active_jobs=result['active_jobs'],
                            drain_timed_out=True, ownership_reserved=True)
            require(result.get('active_jobs') == 0, 'Drain still has active jobs', 409)
            # Native completion and management result/audit acknowledgement are distinct.
            # Do not invalidate the channel while a dispatched result is being collected.
            with self.dispatch_condition:
                while self.dispatches.get(url, 0):
                    left = deadline - time.monotonic()
                    if left <= 0:
                        return dict(state, execution_url=url, pending_acknowledgements=self.dispatches[url], drain_timed_out=True)
                    self.dispatch_condition.wait(left)
            checkpoint = result['checkpoint']
            head = self.collect_audit(channel, checkpoint)
            require(head == {k: checkpoint[k] for k in ('sequence', 'hash')},
                    'Audit changed after final agent checkpoint', 409, 'audit_integrity_failed')
            self.audit.event('agent_retirement_authorized', dict(execution_url=url, operation_id=state['operation_id'], checkpoint=checkpoint))
            state = dict(state, state='retiring', identity=channel['identity'], checkpoint=checkpoint,
                         drain_proof=proof, agent_certificate=channel['certificate'])
            # Durable before network I/O: a lost response can only resume this same retirement.
            self.save_target(url, state)
        receipt = self.execution_control(url, 'retire', {k: state[k] for k in ('operation_id', 'identity', 'checkpoint')})
        require(receipt.get('state') == 'undeployed' and all(receipt.get(k) == state[k] for k in ('operation_id', 'identity', 'checkpoint'))
                and receipt.get('runtime_exit_confirmed') is True and receipt.get('runtime_files_removed') is True
                and receipt.get('ownership_reserved') is True, 'Execution did not confirm retirement', 503, 'cleanup_incomplete')
        self.audit.event('agent_undeployed', dict(execution_url=url, operation_id=state['operation_id'], checkpoint=state['checkpoint']))
        with self.session_lock:
            self.channels.pop(url, None)
            self.sessions = {u: s for u, s in self.sessions.items() if s['target']['url'] != url}
            return self.save_target(url, dict(state, state='undeployed', ownership_reserved=True,
                                             runtime_exit_confirmed=True, runtime_files_removed=True))

    def deploy_agent(self, target):
        url = target['url']
        with self.session_lock:
            state = self.target_state(url)
            require(state['state'] in ('active', 'undeployed', 'deploying'), 'Finish undeployment before deploying', 409)
            if state['state'] != 'active':
                self.save_target(url, dict(state, state='deploying'))
                self.execution_control(url, 'resume', {'operation_id': state['operation_id']})
            # Deployment always requires a fresh platform verification, including after retirement.
            self.channels.pop(url, None)
            channel = self.connect(target, maintenance=True)
            self.audit.event('agent_deployment_enabled', dict(execution_url=url, vm_id=channel['identity']['vm_id'],
                                                             agent_instance=channel['identity']['instance']))
            return self.save_target(url, dict(state='active', identity=channel['identity'], ownership_reserved=True))
