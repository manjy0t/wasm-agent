#!/usr/bin/env python3
"""Profile contract, portable generator and signed-rule tests; no VM required."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.access_profiles import create, validate, generate, definition
from hal_fleet.common import Error, digest
from hal_fleet.policy import workload
from job_signing import rule_digest


class AccessProfilesTest(unittest.TestCase):
    def row(self):
        data = (ROOT / 'tests/workloads/function0.wasm').read_bytes()
        sha = digest(data)
        return dict(name='hash', component=sha+'.wasm', sha256=sha, artifact_bytes=len(data), rule=dict(
            component=sha+'.wasm', cache='memory', cache_ttl_ms=300000, hal_permissions=['crypto'],
            memory_mib=64, fuel=1000000000, execution_timeout_ms=5000, max_output_bytes=4096,
            worker_max_jobs=128, validation={'kind':'bounded'})), data

    def test_profile_cannot_expand_management_rule_or_change_artifact(self):
        profile = create('a'*64, ['crypto'], 'sha256')
        for change in ({'artifact_sha256':'b'*64}, {'version':2}, {'version':True},
                       {'operations':['storage.store-object']}, {'operations':['crypto.unsupported']},
                       {'operations':['crypto.hash.sha256']*2}, {'max_host_calls':0},
                       {'max_host_calls':True}, {'max_buffer_bytes':1048577}, {'allow_all':True}):
            with self.subTest(change=change), self.assertRaises(Error):
                validate(dict(profile, **change), 'a'*64, ['crypto'])
        with self.assertRaises(Error):
            create('a'*64, [], 'sha256')

    def test_legacy_rules_remain_unchanged_and_profile_is_signed(self):
        row, _ = self.row()
        before = copy.deepcopy(row)
        workload(row)
        self.assertEqual(row, before)
        prior = rule_digest(row['rule'])
        row['rule']['access_profile'] = create(row['sha256'], ['crypto'], 'sha256')
        workload(row)
        bound = rule_digest(row['rule'])
        self.assertNotEqual(prior, bound)
        row['rule']['access_profile']['max_host_calls'] += 1
        self.assertNotEqual(rule_digest(row['rule']), bound)
        for value in (None, {}, []):
            row['rule']['access_profile'] = value
            with self.assertRaises(Error):
                workload(row)

    def test_templates_only_select_reviewed_operations(self):
        known = definition()['operations']
        self.assertEqual(definition()['templates']['compute'], [])
        for name, operations in definition()['templates'].items():
            permissions = sorted({known[op] for op in operations if known[op]})
            profile = create('a'*64, permissions, name)
            self.assertEqual(profile['operations'], operations)

    def test_generator_does_not_modify_input_or_overwrite_output(self):
        row, data = self.row()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'input.json'; output = root/'review'/'manifest.json'
            source.write_text(json.dumps({'workloads':[row]}))
            (root/row['component']).write_bytes(data)
            before = source.read_bytes()
            result = generate(source, output, 'sha256', name_suffix='-p1')
            self.assertFalse(result['published'])
            self.assertEqual(source.read_bytes(), before)
            generated = json.loads(output.read_text())['workloads'][0]
            self.assertEqual(generated['name'], 'hash-p1')
            self.assertEqual(generated['rule']['access_profile']['artifact_sha256'], row['sha256'])
            self.assertEqual((output.parent/row['component']).read_bytes(), data)
            with self.assertRaises(Error):
                generate(source, output, 'sha256')
            (root/row['component']).write_bytes(b'changed')
            bad_output = root/'bad'/'manifest.json'
            with self.assertRaises(Error):
                generate(source, bad_output, 'sha256')
            self.assertFalse(bad_output.parent.exists())

    def test_generator_requires_a_complete_explicit_assignment(self):
        row, data = self.row()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'input.json'; assignments = root/'assignments.json'
            source.write_text(json.dumps({'workloads':[row]})); (root/row['component']).write_bytes(data)
            assignments.write_text('{}')
            with self.assertRaises(Error):
                generate(source, root/'output.json', None, assignments)
            assignments.write_text('{"hash":"sha256"}')
            generate(source, root/'output.json', None, assignments)

    def test_vendored_core_matches_reviewed_source_snapshot(self):
        core = ROOT/'vendor/hal-access-profile'
        recorded = json.loads((core/'UPSTREAM.json').read_text())
        for name, expected in recorded['files'].items():
            self.assertEqual(hashlib.sha256((core/name).read_bytes()).hexdigest(), expected, name)

    def test_native_baseline_rejects_profiles_instead_of_ignoring_them(self):
        from hal_fleet.runtime import Execution
        from unittest import mock
        row, _ = self.row()
        row['rule']['access_profile'] = create(row['sha256'], ['crypto'], 'sha256')
        execution = object.__new__(Execution)
        execution.config = {'mode':'native'}
        execution.factory = mock.Mock()
        with self.assertRaisesRegex(Error, 'does not enforce'):
            execution.ensure({'subject':'alice', 'workloads':[row]})
        execution.factory.assert_not_called()

    def test_cli_is_python_only_and_creates_no_deployment_state(self):
        row, data = self.row()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'input.json'; output = root/'output.json'
            source.write_text(json.dumps({'workloads':[row]})); (root/row['component']).write_bytes(data)
            result = subprocess.run([sys.executable, '-B', str(ROOT/'fleet.py'), 'profile-manifest',
                '--manifest', str(source), '--output', str(output), '--template', 'sha256'],
                cwd=tmp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['published'])
            self.assertFalse((root/'state').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
