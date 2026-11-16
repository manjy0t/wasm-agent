#!/usr/bin/env python3
"""Signed approvals: real agent.wasm, native broker, management and private workers.

Software tests only. Docker confinement and TDX attestation are not claimed.
"""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import uuid

import test_agent_policy as previous
import test_container_worker as private_workers
from test_system import ROOT, worker_http_request, jobs
from job_signing import Signer, DOMAIN, canonical
from configure_authorization import generate


class SignedAgentTest(unittest.TestCase):
    start = previous.AgentPolicyTest.start
    stop = staticmethod(previous.AgentPolicyTest.stop)
    tearDown = previous.AgentPolicyTest.tearDown
    start_agent = previous.AgentPolicyTest.start_agent
    stats = previous.AgentPolicyTest.stats
    start_manager = previous.AgentPolicyTest.start_manager
    client_token = previous.AgentPolicyTest.client_token

    def setUp(self):
        previous.AgentPolicyTest.setUp(self)
        self.auth = generate(self.execution / 'policy.json', self.agent_policy, self.root / 'catalog.json',
                             'test-execution', 'in-process', 120, self.root / 'auth')
        self.restart()

    def restart(self):
        self.stop(self.host)
        self.start_agent('--mode', 'wasm', '--transport', 'http',
            '--tenant-policy', str(self.execution / 'policy.json'), '--agent-policy', str(self.agent_policy),
            '--job-authorization', str(self.auth / 'execution-public/job-authorization.json'),
            '--file-token-file', str(self.execution / 'file.token'))
        from management import WorkerHTTPClient
        client = WorkerHTTPClient(self.worker_url, self.token, 10)
        try:
            self.epoch = client.stats()['job_authorization']['epoch']
        finally:
            client.close()
        self.signers = {name: Signer(self.auth / 'clients-private' / (name + '.json'), self.epoch)
                        for name in ('alice', 'bob')}

    def request(self, user='alice', case='platform', cache='reuse', job_id=None):
        artifact = self.cases[case]
        job_id = job_id or str(uuid.uuid4())
        return dict(protocol=1, op='run', job_id=job_id, component=artifact['artifact'],
            sha256=artifact['sha256'], artifact_bytes=artifact['artifact_bytes'], cache=cache,
            job_ticket=self.signers[user].ticket(case, cache, job_id))

    def send(self, request, token_user='alice'):
        token = (self.execution / (token_user + '.token')).read_text().strip()
        return worker_http_request(self.worker_url, token, request, 20)

    def rewrite(self, request, signer='alice', **changes):
        value = copy.deepcopy(request)
        claims = json.loads(value['job_ticket']['payload'])
        claims.update(changes)
        payload = canonical(claims)
        value['job_ticket'] = dict(payload=payload, signature=self.signers[signer].key.sign(DOMAIN + payload.encode()).hex())
        return value

    def test_valid_signatures_cache_and_management_forwarding(self):
        self.start_manager()
        for user in ('alice', 'bob'):
            for case in self.cases:
                row = jobs.run_job(self.api, self.client_token(user), case, 'reuse', signer=self.signers[user])
                self.assertEqual(row['status'], 'completed', row)
                worker = row['response']['agent']
                self.assertEqual(worker['job_authorization']['verified'], True)
                self.assertEqual(worker['job_authorization']['tenant'], user)
                self.assertEqual(worker['security_trace'][0], 'signed_job_authorized')
                self.assertEqual(worker['cache_status'], 'miss')
            hit = self.send(self.request(user), user)
            self.assertEqual(hit['cache_status'], 'hit', hit)
        # Test the public command interface and its audit guard, including measured signing cost.
        output = self.root / 'signed-bench'
        command = [sys.executable, '-B', str(ROOT / 'jobs.py'), '--url', self.api,
            '--token-file', str(self.bundle / 'clients/alice.token'),
            '--signing-config', str(self.auth / 'clients-private/alice.json'), '--authorization-epoch', self.epoch,
            'bench', '--jobs', '10', '--concurrency', '2', '--cache', 'reuse', '--expect-mode', 'wasm',
            '--expect-isolation', 'in-process', '--output', str(output)]
        done = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(json.loads((output / 'config.json').read_text())['client_signing_included_in_batch_time'])

    def test_missing_and_tampered_tickets_rejected_inside_wasm_before_capabilities(self):
        original = self.request()
        values = []
        unsigned = copy.deepcopy(original); unsigned.pop('job_ticket'); values.append(unsigned)
        changed = copy.deepcopy(original)
        changed['job_ticket']['payload'] = changed['job_ticket']['payload'].replace('alice', 'bob')
        values.append(changed)
        changed = copy.deepcopy(original); changed['job_ticket']['signature'] = '0' * 128; values.append(changed)
        changed = copy.deepcopy(original); changed['cache'] = 'bypass'; values.append(changed)
        changed = copy.deepcopy(original); changed['job_id'] = 'misrouted-id'; values.append(changed)
        other = self.request(case='sha256-abc'); other['job_ticket'] = original['job_ticket']; values.append(other)
        for request in values:
            row = self.send(request)
            self.assertEqual(row['status'], 'error', row)
            self.assertEqual(row.get('host_calls'), {}, row)  # guest rejected before authorize_cache
        self.assertEqual(self.stats()['downloads'], 0)
        self.assertEqual(self.stats()['executions'], 0)

    def test_management_worker_tokens_cannot_mint_another_users_authority(self):
        # Both users are allowed the same artifact. Namespace allowlists alone
        # would allow this routing; the independent user signature must stop it.
        row = self.send(self.request(), 'bob')
        self.assertEqual(row['status'], 'error', row)
        for fields in [dict(tenant='bob'), dict(audience='different-worker'), dict(epoch='f' * 64),
                       dict(rule_sha256='f'*64), dict(isolation='per-user-container'),
                       dict(operation='admin'), dict(input='attacker-input')]:
            row = self.send(self.rewrite(self.request(), **fields), 'bob' if fields.get('tenant') == 'bob' else 'alice')
            self.assertEqual(row['status'], 'error', row)
        self.assertEqual(self.stats()['downloads'], 0)

    def test_expiry_future_time_excess_lifetime_and_ambiguous_claims(self):
        now = int(time.time())
        for changes in [dict(issued_unix=now-60, expires_unix=now-1),
                        dict(issued_unix=now+60, expires_unix=now+120),
                        dict(expires_unix=now+301), dict(nonce='bad'), dict(version=2), dict(unknown=True)]:
            row = self.send(self.rewrite(self.request(), **changes))
            self.assertEqual(row['status'], 'error', row)
        request = self.request()
        payload = request['job_ticket']['payload'][:-1] + ',"tenant":"bob"}'
        request['job_ticket'] = dict(payload=payload, signature=self.signers['alice'].key.sign(DOMAIN + payload.encode()).hex())
        self.assertEqual(self.send(request)['status'], 'error')
        self.assertEqual(self.stats()['downloads'], 0)

    def test_replay_is_atomic_across_helper_instances_and_rejects_new_signatures_for_old_ids(self):
        request = self.request(cache='bypass')
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.send(request), range(4)))
        self.assertEqual(sum(r['status'] == 'ok' for r in results), 1, results)
        self.assertEqual(self.stats()['executions'], 1)
        self.assertEqual(self.send(self.request(job_id=request['job_id']))['status'], 'error')
        nonce = json.loads(request['job_ticket']['payload'])['nonce']
        self.assertEqual(self.send(self.rewrite(self.request(), nonce=nonce))['status'], 'error')
        self.assertEqual(self.stats()['executions'], 1)

    def test_restart_rotates_epoch_and_rejects_pre_restart_unused_tickets(self):
        unused = self.request()
        old = self.epoch
        self.restart()
        self.assertNotEqual(old, self.epoch)
        self.assertEqual(self.send(unused)['status'], 'error')
        self.assertEqual(self.send(self.request())['status'], 'ok')

    def test_public_rules_never_contain_private_keys_and_policy_changes_fail_closed(self):
        public = self.auth / 'execution-public/job-authorization.json'
        for signer in self.signers.values():
            self.assertNotIn(signer.config['private_key'], public.read_text())
        self.stop(self.host)
        rules = json.loads(self.agent_policy.read_text())
        rules['workloads'][0]['fuel'] -= 1
        self.agent_policy.write_text(json.dumps(rules))
        done = subprocess.run([str(ROOT / 'dist/hal-on-demand'), '--allow-non-tee', '--mode', 'wasm',
            '--file-server', 'http://127.0.0.1:1/', '--token-file', str(self.execution / 'operator.token'),
            '--cache-dir', str(self.root / 'invalid-policy-cache'), '--tenant-policy', str(self.execution / 'policy.json'),
            '--agent-policy', str(self.agent_policy), '--job-authorization', str(public)],
            capture_output=True, text=True, timeout=20)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('different workload rule', done.stderr)

    def test_expired_during_preparation_does_not_execute(self):
        self.files.delay = 2.1
        now = int(time.time())
        request = self.rewrite(self.request(cache='bypass'), issued_unix=now, expires_unix=now+2)
        row = self.send(request)
        self.assertEqual(row['status'], 'error', row)
        self.assertIn('expired', row['error'])
        self.assertEqual(self.stats()['executions'], 0)


class SignedPrivateWorkerTest(unittest.TestCase):
    setUp = private_workers.WorkerProtocolTest.setUp
    tearDown = private_workers.WorkerProtocolTest.tearDown
    start_worker = private_workers.WorkerProtocolTest.start_worker
    run_as = private_workers.WorkerProtocolTest.run_as
    stats = private_workers.WorkerProtocolTest.stats

    def signer(self, user):
        return Signer(self.root / user / 'auth/clients-private' / (user + '.json'), 'e'*64)

    def test_recipient_independently_rejects_missing_tampered_misrouted_and_replayed_tickets(self):
        for user in ('alice', 'bob'):
            self.start_worker(user, authorization=True)
        ticket = self.signer('alice').ticket('platform', 'reuse', 'job-1')
        self.assertEqual(self.run_as('alice')['status'], 'error')
        self.assertEqual(self.run_as('bob', job_id='job-1', job_ticket=ticket)['status'], 'error')
        self.assertEqual(self.run_as('alice', job_id='job-1', cache='bypass', job_ticket=ticket)['status'], 'error')
        row = self.run_as('alice', job_id='job-1', job_ticket=ticket)
        self.assertEqual(row['status'], 'ok', row)
        self.assertTrue(row['job_authorization']['worker_checked'])
        self.assertEqual(self.run_as('alice', job_id='job-1', job_ticket=ticket)['status'], 'error')
        self.assertEqual(self.stats('alice')['executions'], 1)
        self.assertEqual(self.stats('bob')['downloads'], 0)

    def test_recipient_checks_policy_even_with_valid_user_signature(self):
        self.start_worker('alice', authorization=True)
        signer = self.signer('alice')
        ticket = signer.ticket('platform', 'reuse', 'job-1')
        payload = json.loads(ticket['payload']); payload['rule_sha256'] = '0'*64
        text = canonical(payload)
        ticket = dict(payload=text, signature=signer.key.sign(DOMAIN+text.encode()).hex())
        self.assertEqual(self.run_as('alice', job_id='job-1', job_ticket=ticket)['status'], 'error')
        self.assertEqual(self.stats('alice')['downloads'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
