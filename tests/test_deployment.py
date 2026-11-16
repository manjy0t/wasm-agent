#!/usr/bin/env python3
"""Configuration/approval tests in temporary directories; no VM or Docker claims."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import copy
import io
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deployment as d
from configure_authorization import generate
from job_signing import Signer, DOMAIN
from server.management import TenantManagement


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hal-deployment-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.execution = self.root / 'execution'
        self.management = self.root / 'management'
        self.client = self.root / 'client'
        for root in (self.execution, self.management, self.client):
            (root / 'state/tenant-config').mkdir(mode=0o700, parents=True)
        self.ep = self.execution / 'state/tenant-config'
        self.mp = self.management / 'state/tenant-config'
        (self.execution / 'dist').mkdir()
        self.agent_bytes = b'\0asm\x0d\0\x01\0' + b'fake-agent-for-configuration-tests'
        (self.execution / 'dist/agent.wasm').write_bytes(self.agent_bytes)
        (self.execution / 'dist/hal-on-demand').write_text('placeholder; never executed')
        old = (ROOT / 'tests/workloads/function0.wasm').read_bytes()
        self.case = dict(name='sha256-abc', artifact='function0.wasm', sha256=d.digest(old),
                         artifact_bytes=len(old), validation={'kind': 'hex', 'value':
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'})
        self.catalog = {'cases': [self.case]}
        tenants, managers, rules = [], [], []
        for i, identity in enumerate(('alice', 'bob')):
            (self.ep / f'{identity}.token').write_text(str(i + 3) * 64)
            (self.mp / f'{identity}-worker.token').write_text(str(i + 3) * 64)
            (self.mp / f'{identity}-api.token').write_text(str(i + 5) * 64)
            artifact = dict(component=self.case['artifact'], sha256=self.case['sha256'], artifact_bytes=len(old))
            tenants.append(dict(id=identity, token_file=f'{identity}.token', artifacts=[artifact],
                                cache_bytes=268435456, compiled_cache_entries=16, storage_bytes=16777216,
                                storage_entries=1024, max_inflight=4))
            managers.append(dict(id=identity, api_token_file=f'{identity}-api.token',
                                 worker_token_file=f'{identity}-worker.token', cases=['sha256-abc']))
            rules.append(dict(tenant=identity, component='function0.wasm', sha256=self.case['sha256'],
                              cache='memory', cache_ttl_ms=300000, hal_permissions=['crypto'],
                              memory_mib=64, fuel=999999999, execution_timeout_ms=5000,
                              max_output_bytes=4096, worker_max_jobs=77, validation=self.case['validation']))
        (self.ep / 'operator.token').write_text('1' * 64)
        (self.mp / 'worker.token').write_text('1' * 64)
        (self.mp / 'api.token').write_text('2' * 64)
        for path, value in (
            (self.ep / 'policy.json', dict(version=1, tenants=tenants)),
            (self.mp / 'management-policy.json', dict(version=1, tenants=managers)),
            (self.ep / 'agent-policy.json', dict(version=1, agent_sha256=d.digest(self.agent_bytes), workloads=rules)),
            (self.ep / 'workloads.json', self.catalog), (self.mp / 'workloads.json', self.catalog),
        ):
            d.write_new(path, d.encoded(value))
        approvals = generate(self.ep / 'policy.json', self.ep / 'agent-policy.json', self.ep / 'workloads.json',
                             'test-worker', 'per-user-container', 120, self.client / 'approvals')
        shutil.copyfile(approvals / 'execution-public/job-authorization.json', self.ep / 'job-authorization.json')
        self.signing = approvals / 'clients-private/alice.json'
        self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/')
        self.run_cli(self.management, 'init', '--role', 'management', '--worker-url', 'http://worker.internal:9100')
        self.spec = self.execution / 'new-workload.json'
        self.new_wasm = (ROOT / 'tests/workloads/function1.wasm').read_bytes()
        (self.execution / 'hash512-v2.wasm').write_bytes(self.new_wasm)
        d.write_new(self.spec, d.encoded(dict(tenant='alice', case='hash512-v2', wasm='hash512-v2.wasm',
            template='sha256-abc', validation={'kind': 'length', 'value': 64})))

    def run_cli(self, root, *args, success=True):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = d.main(list(args), root=root)
        if success:
            self.assertEqual(status, 0, out.getvalue() + err.getvalue())
        else:
            self.assertEqual(status, 1, out.getvalue() + err.getvalue())
        return out.getvalue() + err.getvalue()

    def config(self, root):
        return d.document(root / 'state/deployment.json')

    def prepare(self):
        self.run_cli(self.execution, 'prepare-workload', '--spec', str(self.spec), '--output', 'release')
        return self.execution / 'release/plan.json'

    def snapshot(self, directory):
        return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob('*') if p.is_file()}

    def test_stale_shell_variables_do_not_select_files(self):
        with patch.dict(os.environ, {'HAL_AGENT_POLICY': '/missing/agent-policy-updated-old.json',
                                    'HAL_JOB_AUTH': '/missing/old-auth.json'}):
            text = self.run_cli(self.execution, 'check')
        self.assertIn('checks passed', text)
        self.assertEqual(self.config(self.execution)['paths']['agent_policy'], 'state/tenant-config/agent-policy.json')

    def test_changed_agent_is_not_approved_by_check_or_start(self):
        policy = (self.ep / 'agent-policy.json').read_bytes()
        with (self.execution / 'dist/agent.wasm').open('ab') as stream:
            stream.write(b'changed')
        for args in [('check',), ('start', '--print-command')]:
            text = self.run_cli(self.execution, *args, success=False)
            self.assertIn('fingerprint mismatch', text)
        self.assertEqual(policy, (self.ep / 'agent-policy.json').read_bytes())

    def test_agent_approval_preserves_rules_credentials_keys_and_backs_up(self):
        before = self.snapshot(self.ep)
        signing = self.signing.read_bytes()
        with (self.execution / 'dist/agent.wasm').open('ab') as stream:
            stream.write(b'intentional-update')
        self.run_cli(self.execution, 'approve-agent')
        self.assertEqual(before, self.snapshot(self.ep))
        self.run_cli(self.execution, 'approve-agent', '--apply')
        after = self.snapshot(self.ep)
        self.assertEqual(set(before), set(after))
        for name in before:
            if name != 'agent-policy.json':
                self.assertEqual(before[name], after[name])
        old, new = json.loads(before['agent-policy.json']), json.loads(after['agent-policy.json'])
        self.assertEqual(old['workloads'], new['workloads'])
        self.assertNotEqual(old['agent_sha256'], new['agent_sha256'])
        self.assertEqual(signing, self.signing.read_bytes())
        copies = list((self.execution / 'state/deployment-backups').glob('*/0-agent-policy.json'))
        self.assertEqual(copies[0].read_bytes(), before['agent-policy.json'])
        self.assertEqual(stat.S_IMODE((self.ep / 'agent-policy.json').stat().st_mode), 0o600)
        self.run_cli(self.execution, 'check')

    def test_reported_package_upgrade_with_reviewed_catalog_is_completed_once(self):
        # Reproduce the actual upgrade: new package bytes, old approved digest,
        # catalog under reviewed/, and already provisioned identities/keys.
        actual = (ROOT / 'dist/agent.wasm').read_bytes()
        (self.execution / 'dist/agent.wasm').write_bytes(actual)
        policy_path = self.ep / 'agent-policy.json'
        policy = d.document(policy_path)
        policy['agent_sha256'] = '914f9c2c88613d0f8ca1a7a63fdba2e8da3b808ae5d04fc0bbba5794ae6fc53c'
        d.replace_file(policy_path, d.encoded(policy))
        reviewed = self.execution / 'reviewed'
        reviewed.mkdir()
        (self.ep / 'workloads.json').rename(reviewed / 'workloads.json')
        (self.execution / 'state/deployment.json').unlink()
        old_policy, signing = policy_path.read_bytes(), self.signing.read_bytes()
        text = self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/')
        self.assertIn('agent approval is still required', text)
        self.assertIn('approve-agent --sha256 ' + d.digest(actual) + ' --apply', text)
        self.assertEqual(old_policy, policy_path.read_bytes())
        self.assertEqual(self.config(self.execution)['paths']['catalog'], 'reviewed/workloads.json')
        error = self.run_cli(self.execution, 'check', success=False)
        self.assertIn(str(policy_path), error)
        self.assertIn('check only reads', error)
        text = self.run_cli(self.execution, 'approve-agent', '--sha256', d.digest(actual), '--apply')
        self.assertIn('checks passed after approval', text)
        self.assertEqual(policy['workloads'], d.document(policy_path)['workloads'])
        self.assertEqual(signing, self.signing.read_bytes())
        self.run_cli(self.execution, 'check')
        self.run_cli(self.execution, 'start', '--print-command')
        before_repeat = self.snapshot(self.execution / 'state')
        self.run_cli(self.execution, 'approve-agent', '--sha256', d.digest(actual), '--apply')
        self.assertEqual(before_repeat, self.snapshot(self.execution / 'state'))

    def test_approval_refuses_agent_changed_after_preview(self):
        path = self.execution / 'dist/agent.wasm'
        path.write_bytes(self.agent_bytes + b'intended-build')
        reviewed_hash = d.digest(path.read_bytes())
        preview = self.run_cli(self.execution, 'approve-agent')
        self.assertIn('--sha256 ' + reviewed_hash, preview)
        path.write_bytes(self.agent_bytes + b'different-build')
        before = self.snapshot(self.execution / 'state')
        text = self.run_cli(self.execution, 'approve-agent', '--sha256', reviewed_hash, '--apply', success=False)
        self.assertIn('No policy was changed', text)
        self.assertEqual(before, self.snapshot(self.execution / 'state'))

    def test_approval_instructions_retain_custom_configuration(self):
        with (self.execution / 'dist/agent.wasm').open('ab') as stream:
            stream.write(b'new-build')
        selected = 'state/custom deployment.json'
        text = self.run_cli(self.execution, '--config', selected, 'init', '--role', 'execution',
                            '--file-server', 'http://files.internal/')
        self.assertIn("--config 'state/custom deployment.json' approve-agent --sha256", text)
        text = self.run_cli(self.execution, '--config', selected, 'approve-agent')
        self.assertIn("--config 'state/custom deployment.json' approve-agent --sha256", text)

    def test_init_finds_checkout_root_catalog_for_both_roles(self):
        for root, policy, role, flag, url in (
                (self.execution, self.ep, 'execution', '--file-server', 'http://files.internal/'),
                (self.management, self.mp, 'management', '--worker-url', 'http://worker.internal:9100')):
            with self.subTest(role=role):
                (policy / 'workloads.json').rename(root / 'workloads.json')
                (root / 'state/deployment.json').unlink()
                original = (root / 'workloads.json').read_bytes()
                self.run_cli(root, 'init', '--role', role, flag, url)
                self.assertEqual(self.config(root)['paths']['catalog'], 'workloads.json')
                self.assertEqual(original, (root / 'workloads.json').read_bytes())
                self.run_cli(root, 'check')

    def test_no_catalog_lists_locations_and_writes_no_configuration(self):
        (self.ep / 'workloads.json').unlink()
        (self.execution / 'state/deployment.json').unlink()
        before = self.snapshot(self.ep)
        text = self.run_cli(self.execution, 'init', '--role', 'execution',
                            '--file-server', 'http://files.internal/', success=False)
        self.assertIn('No matching workload catalog', text)
        self.assertIn('reviewed/workloads.json', text)
        self.assertIn('init --catalog PATH', text)
        self.assertNotIn('Traceback', text)
        self.assertFalse((self.execution / 'state/deployment.json').exists())
        self.assertEqual(before, self.snapshot(self.ep))

    def test_catalog_hash_size_and_result_are_checked_against_existing_approvals(self):
        for mutation in ({'sha256': 'f' * 64}, {'artifact_bytes': self.case['artifact_bytes'] + 1},
                         {'validation': {'kind': 'length', 'value': 32}}):
            with self.subTest(mutation=mutation):
                d.replace_file(self.ep / 'workloads.json', d.encoded({'cases': [self.case | mutation]}))
                before = self.snapshot(self.ep)
                text = self.run_cli(self.execution, 'check', success=False)
                self.assertIn('Catalog', text)
                self.assertEqual(before, self.snapshot(self.ep))

    def test_fallback_catalog_must_match_approved_metadata(self):
        reviewed = self.execution / 'reviewed'
        reviewed.mkdir()
        (self.ep / 'workloads.json').rename(reviewed / 'workloads.json')
        d.write_new(self.execution / 'workloads.json', d.encoded({'cases': [self.case | {'sha256': 'f' * 64}]}))
        (self.execution / 'state/deployment.json').unlink()
        self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/')
        self.assertEqual(self.config(self.execution)['paths']['catalog'], 'reviewed/workloads.json')

    def test_distinct_matching_fallback_catalogs_require_explicit_selection(self):
        reviewed = self.execution / 'reviewed'
        reviewed.mkdir()
        (self.ep / 'workloads.json').rename(reviewed / 'workloads.json')
        other = {'cases': [self.case, self.case | {'name': 'alias-case'}]}
        d.write_new(self.execution / 'workloads.json', d.encoded(other))
        (self.execution / 'state/deployment.json').unlink()
        text = self.run_cli(self.execution, 'init', '--role', 'execution',
                            '--file-server', 'http://files.internal/', success=False)
        self.assertIn('Several different catalogs', text)
        self.assertFalse((self.execution / 'state/deployment.json').exists())
        self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/',
                     '--catalog', 'reviewed/workloads.json')
        self.assertEqual(self.config(self.execution)['paths']['catalog'], 'reviewed/workloads.json')

    def test_explicit_missing_or_provisioned_bad_catalog_is_not_silently_substituted(self):
        d.write_new(self.execution / 'workloads.json', d.encoded(self.catalog))
        (self.execution / 'state/deployment.json').unlink()
        text = self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/',
                            '--catalog', 'missing/workloads.json', success=False)
        self.assertIn('Missing file:', text)
        d.replace_file(self.ep / 'workloads.json', d.encoded({'cases': [self.case | {'sha256': 'f' * 64}]}))
        self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/',
                     success=False)
        self.assertFalse((self.execution / 'state/deployment.json').exists())

    def test_missing_file_is_an_actionable_error(self):
        config = self.config(self.execution)
        config['paths']['agent_policy'] = 'state/tenant-config/missing.json'
        d.replace_file(self.execution / 'state/deployment.json', d.encoded(config))
        text = self.run_cli(self.execution, 'check', success=False)
        self.assertIn('Missing file:', text)
        self.assertNotIn('Traceback', text)

    def test_wrong_role_policy_is_identified_without_raw_key_error(self):
        d.replace_file(self.mp / 'management-policy.json', (self.ep / 'policy.json').read_bytes())
        text = self.run_cli(self.management, 'check', success=False)
        self.assertIn('not a management policy', text)
        self.assertIn('cases', text)

    def test_duplicate_tokens_fail_without_printing_them(self):
        (self.mp / 'alice-worker.token').write_bytes((self.mp / 'api.token').read_bytes())
        text = self.run_cli(self.management, 'check', success=False)
        self.assertIn('must be distinct', text)
        self.assertNotIn('2' * 64, text)

    def test_init_is_idempotent_and_does_not_reset_settings(self):
        old = self.snapshot(self.execution / 'state/tenant-config')
        self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/')
        self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://another.internal/', success=False)
        self.assertEqual(old, self.snapshot(self.execution / 'state/tenant-config'))
        self.assertEqual(self.config(self.execution)['file_server'], 'http://files.internal/')

    def test_init_finds_one_existing_public_authorization_without_regenerating_keys(self):
        saved = self.ep / 'job-authorization.json'
        original = saved.read_bytes()
        other = self.execution / 'state/old-approvals/execution-public/job-authorization.json'
        other.parent.mkdir(parents=True)
        saved.rename(other)
        (self.execution / 'state/deployment.json').unlink()
        self.run_cli(self.execution, 'init', '--role', 'execution', '--file-server', 'http://files.internal/')
        self.assertEqual(self.config(self.execution)['paths']['job_authorization'],
                         'state/old-approvals/execution-public/job-authorization.json')
        self.assertEqual(original, other.read_bytes())
        self.assertFalse(saved.exists())
        self.run_cli(self.execution, 'check')

    def test_init_refuses_to_guess_between_different_authorization_files(self):
        saved = self.ep / 'job-authorization.json'
        original = saved.read_bytes()
        for i in range(2):
            other = self.execution / f'state/old-approvals-{i}/execution-public/job-authorization.json'
            other.parent.mkdir(parents=True)
            value = json.loads(original)
            value['audience'] = f'worker-{i}'
            d.write_new(other, d.encoded(value))
        saved.unlink()
        (self.execution / 'state/deployment.json').unlink()
        text = self.run_cli(self.execution, 'init', '--role', 'execution',
                            '--file-server', 'http://files.internal/', success=False)
        self.assertIn('Select the reviewed --job-authorization', text)
        self.assertFalse((self.execution / 'state/deployment.json').exists())

    def test_launch_keeps_signed_container_and_resource_settings(self):
        text = self.run_cli(self.execution, 'start', '--print-command')
        for flag in ('--mode wasm', '--user-containers', '--job-authorization', '--agent-policy',
                     '--compilers 2', '--compiler-threads 2', '--executions 4', '--container-cpus 2',
                     '--execution-timeout-secs 5', '--max-output-bytes 4096'):
            self.assertIn(flag, text)
        self.assertNotIn('--allow-non-tee', text)
        self.assertIn('--require-signed-jobs', self.run_cli(self.management, 'start', '--print-command'))

    def test_prepare_changes_no_deployment_and_exports_no_secrets(self):
        before = self.snapshot(self.ep)
        plan = self.prepare()
        self.assertEqual(before, self.snapshot(self.ep))
        secret = json.loads(self.signing.read_text())['private_key']
        for name, content in self.snapshot(plan.parent).items():
            self.assertNotIn(secret.encode(), content)
            self.assertNotIn(b'private_key', content)
            self.assertNotIn(b'1' * 64, content)
        self.assertEqual((plan.parent / 'file-server/hash512-v2.wasm').read_bytes(), self.new_wasm)
        row = d.document(plan)
        self.assertEqual(row['case']['sha256'], d.digest(self.new_wasm))
        self.assertEqual(row['rule']['fuel'], 999999999)
        self.assertEqual(row['rule']['worker_max_jobs'], 77)

    def test_full_release_preserves_keys_other_users_and_existing_restrictions(self):
        before_exec = d.document(self.ep / 'policy.json')
        before_auth = d.document(self.ep / 'job-authorization.json')
        before_sign = json.loads(self.signing.read_text())
        before_tokens = {p: p.read_bytes() for p in self.ep.glob('*.token')}
        plan = self.prepare()
        self.run_cli(self.execution, 'apply-workload', '--plan', str(plan))
        self.assertEqual(before_exec, d.document(self.ep / 'policy.json'))
        self.run_cli(self.execution, 'apply-workload', '--plan', str(plan), '--apply')
        self.run_cli(self.management, 'apply-workload', '--plan', str(plan), '--apply')
        self.run_cli(self.client, 'update-client', '--plan', str(plan), '--signing-config', str(self.signing), '--apply')
        self.run_cli(self.execution, 'check')
        self.run_cli(self.management, 'check')
        after_exec = d.document(self.ep / 'policy.json')
        after_auth = d.document(self.ep / 'job-authorization.json')
        after_sign = json.loads(self.signing.read_text())
        self.assertEqual(before_exec['tenants'][1], after_exec['tenants'][1])
        self.assertEqual(before_auth['users'][1], after_auth['users'][1])
        self.assertEqual(before_auth['users'][0]['public_key'], after_auth['users'][0]['public_key'])
        self.assertEqual(before_sign['private_key'], after_sign['private_key'])
        self.assertEqual(before_sign['public_key'], after_sign['public_key'])
        self.assertEqual(before_sign['workloads'], after_sign['workloads'][:-1])
        self.assertEqual(before_tokens, {p: p.read_bytes() for p in self.ep.glob('*.token')})
        signer = Signer(self.signing, 'a' * 64)
        ticket = signer.ticket('hash512-v2', 'reuse', 'test-release-job')
        signer.key.public_key().verify(bytes.fromhex(ticket['signature']), DOMAIN + ticket['payload'].encode())
        self.assertEqual(json.loads(ticket['payload'])['rule_sha256'], after_auth['users'][0]['workloads'][-1]['rule_sha256'])
        self.assertEqual(stat.S_IMODE(self.signing.stat().st_mode), 0o600)
        # Repeating a completed deployment must not rotate keys, reset rules, or
        # create a different release just to get past a filename collision.
        before_repeated = self.snapshot(self.ep), self.snapshot(self.mp), self.signing.read_bytes()
        self.run_cli(self.execution, 'apply-workload', '--plan', str(plan), '--apply')
        self.run_cli(self.management, 'apply-workload', '--plan', str(plan), '--apply')
        self.run_cli(self.client, 'update-client', '--plan', str(plan), '--signing-config', str(self.signing), '--apply')
        self.assertEqual(before_repeated, (self.snapshot(self.ep), self.snapshot(self.mp), self.signing.read_bytes()))

    def test_generated_management_files_load_in_the_actual_manager(self):
        plan = self.prepare()
        self.run_cli(self.management, 'apply-workload', '--plan', str(plan), '--apply')
        args = argparse.Namespace(api_token_file=self.mp / 'api.token', agent_token_file=self.mp / 'worker.token',
            tenant_policy=self.mp / 'management-policy.json', catalog=self.mp / 'workloads.json',
            state_dir=self.management / 'state/manager-test', worker_url='http://127.0.0.1:1',
            agent_host='127.0.0.1', agent_port=1, agent_timeout=1, worker_http_keepalive=True,
            dispatchers=1, queue_size=16, max_history=100, require_signed_jobs=True)
        manager = TenantManagement(args)
        try:
            alice, bob = manager.tenants
            self.assertIn('hash512-v2', alice.cases)
            self.assertNotIn('hash512-v2', bob.cases)
            with self.assertRaisesRegex(ValueError, 'signed job ticket'):
                alice.submit({'case': 'hash512-v2', 'cache': 'bypass'})
        finally:
            manager.close()

    def test_stale_release_refuses_to_overwrite_newer_policy(self):
        plan = self.prepare()
        old = d.document(self.ep / 'policy.json')
        old['tenants'][0]['max_inflight'] = 3
        d.replace_file(self.ep / 'policy.json', d.encoded(old))
        before = self.snapshot(self.ep)
        text = self.run_cli(self.execution, 'apply-workload', '--plan', str(plan), '--apply', success=False)
        self.assertIn('changed since', text)
        self.assertEqual(before, self.snapshot(self.ep))

    def test_client_rejects_other_user_or_replaced_key(self):
        plan = self.prepare()
        row = d.document(plan)
        row['public_key'] = 'f' * 64
        d.replace_file(plan, d.encoded(row))
        before = self.signing.read_bytes()
        self.run_cli(self.client, 'update-client', '--plan', str(plan), '--signing-config', str(self.signing),
                     '--apply', success=False)
        self.assertEqual(before, self.signing.read_bytes())

    def test_bad_or_unsupported_workload_is_not_registered(self):
        base = d.document(self.spec)
        for mutation in ({'hal_permissions': ['network']}, {'limits': {'fuel': 1000000001}},
                         {'validation': {'kind': 'bounded'}}, {'validation': {'kind': 'length', 'value': 5000}}):
            d.replace_file(self.spec, d.encoded(base | mutation))
            self.run_cli(self.execution, 'prepare-workload', '--spec', str(self.spec), '--output', 'rejected', success=False)
            self.assertFalse((self.execution / 'rejected').exists())

    def test_core_module_is_not_accepted_as_component(self):
        (self.execution / 'hash512-v2.wasm').write_bytes(b'\0asm\x01\0\0\0')
        self.run_cli(self.execution, 'prepare-workload', '--spec', str(self.spec), '--output', 'rejected', success=False)
        self.assertFalse((self.execution / 'rejected').exists())

    def test_existing_artifact_name_or_digest_cannot_be_silently_replaced(self):
        spec = d.document(self.spec)
        spec['wasm'] = 'function0.wasm'
        (self.execution / 'function0.wasm').write_bytes(self.new_wasm)
        d.replace_file(self.spec, d.encoded(spec))
        self.run_cli(self.execution, 'prepare-workload', '--spec', str(self.spec), '--output', 'rejected', success=False)
        spec['wasm'] = 'hash512-v2.wasm'
        (self.execution / 'hash512-v2.wasm').write_bytes((ROOT / 'tests/workloads/function0.wasm').read_bytes())
        d.replace_file(self.spec, d.encoded(spec))
        self.run_cli(self.execution, 'prepare-workload', '--spec', str(self.spec), '--output', 'rejected', success=False)

    def test_public_config_rejects_private_key_and_duplicate_json_fields(self):
        path = self.ep / 'job-authorization.json'
        obj = d.document(path)
        obj['private_key'] = 'example-not-a-real-key'
        d.replace_file(path, d.encoded(obj))
        text = self.run_cli(self.execution, 'check', success=False)
        self.assertIn('contains a private key', text)
        d.replace_file(path, b'{"version":1,"version":1}')
        text = self.run_cli(self.execution, 'check', success=False)
        self.assertIn('Duplicate JSON field', text)

    def test_failed_write_rolls_back_all_changed_policy_files(self):
        first, second = self.ep / 'agent-policy.json', self.ep / 'policy.json'
        old = {first: first.read_bytes(), second: second.read_bytes()}
        real = d.replace_file
        failed = False

        def failing(path, data):
            nonlocal failed
            if Path(path) == second and not failed:
                failed = True
                raise OSError('simulated write failure')
            real(path, data)

        with patch.object(d, 'replace_file', side_effect=failing):
            with self.assertRaises(OSError):
                d.change_files(self.execution, {first: b'changed', second: b'changed'})
        self.assertEqual(old, {p: p.read_bytes() for p in old})


@unittest.skipUnless(os.environ.get('HAL_TEST_RUNTIME') == '1', 'set HAL_TEST_RUNTIME=1 for the real native-worker test')
class DeploymentRuntimeTest(unittest.TestCase):
    setUp = DeploymentTest.setUp
    run_cli = DeploymentTest.run_cli
    prepare = DeploymentTest.prepare

    def test_new_release_executes_real_wasm_with_unchanged_client_key(self):
        # Uses the real private-worker protocol and a synthetic HAL on this Mac.
        # It does not create a Docker container or establish TDX attestation.
        plan = self.prepare()
        self.run_cli(self.execution, 'apply-workload', '--plan', str(plan), '--apply')
        self.run_cli(self.client, 'update-client', '--plan', str(plan), '--signing-config', str(self.signing), '--apply')
        native = ROOT / 'dist/hal-on-demand'
        self.assertTrue(native.is_file(), 'Build the native host before this optional integration test.')
        worker = self.root / 'w'
        worker.mkdir(mode=0o700)
        execution, agent, auth = (d.document(self.ep / name) for name in
                                  ('policy.json', 'agent-policy.json', 'job-authorization.json'))
        execution['tenants'] = [execution['tenants'][0]]
        execution['tenants'][0]['token_file'] = str(self.ep / 'alice.token')
        agent['workloads'] = [r for r in agent['workloads'] if r['tenant'] == 'alice']
        agent['agent_sha256'] = d.digest((ROOT / 'dist/agent.wasm').read_bytes())
        auth['users'] = [auth['users'][0]]
        for name, value in (('tenant.json', execution), ('agent.json', agent), ('auth.json', auth)):
            d.write_new(worker / name, d.encoded(value))
        wasm = self.new_wasm

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                request = json.loads(self.rfile.readline(16384))
                if (request.get('component') != 'hash512-v2.wasm' or request.get('sha256') != d.digest(wasm)
                        or request.get('artifact_bytes') != len(wasm)):
                    self.wfile.write(b'{"status":"error"}\n')
                    return
                self.wfile.write(json.dumps({'status': 'ok', 'bytes': len(wasm)}).encode() + b'\n')
                self.wfile.write(wasm)

        with socketserver.ThreadingUnixStreamServer(str(worker / 'b.sock'), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            identity = dict(version=1, tenant='alice', platform='NON_TEE_TEST_ONLY',
                socket=str(worker / 'w.sock'), broker_socket=str(worker / 'b.sock'), authorization_epoch='e' * 64,
                args=['worker', '--allow-non-tee', '--mode', 'wasm', '--file-server', 'http://127.0.0.1:1/',
                      '--token-file', str(self.ep / 'operator.token'), '--tenant-policy', str(worker / 'tenant.json'),
                      '--agent-policy', str(worker / 'agent.json'), '--job-authorization', str(worker / 'auth.json'),
                      '--cache-dir', str(worker / 'cache'), '--compiler-threads', '2', '--max-inflight', '4'])
            d.write_new(worker / 'worker.json', d.encoded(identity))
            process = None
            try:
                with (worker / 'log').open('w+') as log:
                    process = subprocess.Popen([str(native), '--container-worker-config', str(worker / 'worker.json')],
                                               cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 15
                    while not (worker / 'w.sock').exists():
                        self.assertIsNone(process.poll(), (worker / 'log').read_text())
                        self.assertLess(time.monotonic(), deadline, (worker / 'log').read_text())
                        time.sleep(.02)
                    signer = Signer(self.signing, 'e' * 64)
                    entry = d.document(plan)['case']
                    request = dict(protocol=1, op='run', job_id='release-job-1', cache='bypass',
                        component=entry['artifact'], sha256=entry['sha256'], artifact_bytes=entry['artifact_bytes'],
                        job_ticket=signer.ticket(entry['name'], 'bypass', 'release-job-1'))
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(15)
                        client.connect(str(worker / 'w.sock'))
                        client.sendall(json.dumps(request).encode() + b'\n')
                        with client.makefile('rb') as response:
                            result = json.loads(response.readline(1024 * 1024))
                    self.assertEqual(result['status'], 'ok', result)
                    self.assertTrue(result['job_authorization']['worker_checked'])
                    self.assertEqual(result['result']['hex'], d.hashlib.sha512(b'abc').hexdigest())
                    self.assertFalse(result['attestation_verified'])
            finally:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                server.shutdown()
                thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
