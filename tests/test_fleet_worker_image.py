#!/usr/bin/env python3
"""Exercise build/retry/promotion using a temporary Docker CLI stub, never a daemon."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.worker_image import build_worker_image

STUB = r'''
import json, os, sys
from pathlib import Path
root = Path(os.environ['HAL_IMAGE_TEST_ROOT'])
args = sys.argv[1:]
assert args[:2] == ['--host', 'unix:///var/run/docker.sock'], 'Use the local execution daemon'
args = args[2:]
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(args) + '\n')
mode = os.environ.get('HAL_IMAGE_TEST_MODE', 'success')
image_id = 'sha256:' + 'a' * 64
if args[0] == 'info':
    spec = json.loads(Path(os.environ['HAL_IMAGE_SANDBOX_SPEC']).read_text())
    print(json.dumps({'OSType': 'linux', 'Runtimes': {} if mode == 'no-gvisor' else {
        spec['runtime']: {k: spec[k] for k in ('path', 'runtimeArgs')}}}))
elif args[0] == 'build':
    count = root / 'attempts'
    attempt = int(count.read_text()) + 1 if count.exists() else 1
    count.write_text(str(attempt))
    if mode == 'compile-error':
        print('error[E0432]: unresolved import')
        sys.exit(1)
    if mode == 'always-snapshot' or (mode == 'snapshot-once' and attempt == 1):
        print('ERROR: failed to prepare extraction snapshot "extract": parent snapshot sha256:123 does not exist: not found')
        # Even a partial ID from a failed build cannot be accepted.
        Path(args[args.index('--iidfile') + 1]).write_text(image_id)
        sys.exit(1)
    if mode != 'no-iid':
        Path(args[args.index('--iidfile') + 1]).write_text(image_id)
    print('cached build exported')
elif args[:2] == ['image', 'inspect']:
    print(json.dumps(dict(Id=image_id, Os='linux', Architecture='amd64',
                         Config=dict(User='0' if mode == 'wrong-user' else '65532:65532',
                                     Entrypoint=['/usr/local/bin/hal-on-demand']))))
elif args[0] == 'run':
    if mode == 'run-error':
        print('image cannot unpack or start', file=sys.stderr)
        sys.exit(1)
    print('unexpected application' if mode == 'wrong-help' else
          'Usage: hal-on-demand --user-containers --job-authorization')
elif args[:2] == ['image', 'tag']:
    (root / 'promoted').write_text(args[-1])
elif args[:2] not in (['image', 'rm'], ['container', 'rm']):
    raise SystemExit('Unexpected Docker command: ' + repr(args))
'''


class WorkerImageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hal-worker-image-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'containers').mkdir()
        (self.root / 'containers/Dockerfile').write_text('# fixture\n')
        self.docker = self.root / 'docker'
        self.docker.write_text('#!' + sys.executable + '\n' + STUB)
        self.docker.chmod(0o700)
        environment = patch.dict(os.environ, HAL_IMAGE_TEST_ROOT=str(self.root), HAL_IMAGE_TEST_MODE='success',
                                 HAL_IMAGE_SANDBOX_SPEC=str(ROOT / 'src/gvisor-runtime.json'))
        environment.start()
        self.addCleanup(environment.stop)
        self.sleeps = patch('hal_fleet.worker_image.time.sleep')
        self.sleeps.start()
        self.addCleanup(self.sleeps.stop)

    def run_build(self, mode='success'):
        with patch.dict(os.environ, HAL_IMAGE_TEST_MODE=mode), contextlib.redirect_stdout(io.StringIO()):
            return build_worker_image(self.root, docker=str(self.docker))

    def calls(self):
        return [json.loads(line) for line in (self.root / 'calls.jsonl').read_text().splitlines()]

    def assert_not_promoted(self):
        self.assertFalse((self.root / 'promoted').exists())
        self.assertFalse(any(call[:2] == ['image', 'tag'] for call in self.calls()))

    def test_success_is_checked_by_immutable_id_before_promotion(self):
        result = self.run_build()
        self.assertEqual(result['startup_check'], 'passed')
        self.assertEqual(result['build_attempts'], 1)
        calls = self.calls()
        build = next(c for c in calls if c[0] == 'build')
        self.assertIn('--platform=linux/amd64', build)
        self.assertNotIn('hal-user-worker:local', build)
        run = next(c for c in calls if c[0] == 'run')
        self.assertEqual(run[-2:], [result['image_id'], '--help'])
        for option in ('--read-only', '--pull=never', '--rm', '--runtime=hal-gvisor'):
            self.assertIn(option, run)
        self.assertEqual(run[run.index('--network') + 1], 'none')
        self.assertEqual(run[run.index('--user') + 1], '65532:65532')
        tag = ['image', 'tag', result['image_id'], 'hal-user-worker:local']
        self.assertLess(calls.index(run), calls.index(tag))
        removals = [c for c in calls if c[:2] in (['image', 'rm'], ['container', 'rm'])]
        self.assertEqual(len(removals), 2)
        self.assertTrue(removals[0][-1].startswith('hal-fleet-image-check-'))
        self.assertTrue(removals[1][-1].startswith('hal-fleet-worker-build:'))

    def test_missing_gvisor_stops_before_build_or_promotion(self):
        with self.assertRaisesRegex(ValueError, 'hal-gvisor'):
            self.run_build('no-gvisor')
        self.assertEqual([call[0] for call in self.calls()], ['info'])
        self.assert_not_promoted()

    def test_snapshot_failure_retries_with_the_same_build_cache_then_checks_success(self):
        result = self.run_build('snapshot-once')
        self.assertEqual(result['build_attempts'], 2)
        builds = [c for c in self.calls() if c[0] == 'build']
        self.assertEqual(builds[0], builds[1])
        self.assertNotIn('--no-cache', builds[1])
        self.assertFalse(any('prune' in c or 'restart' in c for c in self.calls()))

    def test_persistent_snapshot_failure_stops_after_three_attempts(self):
        with self.assertRaisesRegex(ValueError, 'all three attempts'):
            self.run_build('always-snapshot')
        self.assertEqual(len([c for c in self.calls() if c[0] == 'build']), 3)
        self.assert_not_promoted()
        self.assertFalse(any(c[0] == 'run' for c in self.calls()))

    def test_compilation_failure_is_not_retried(self):
        with self.assertRaisesRegex(ValueError, 'build failed'):
            self.run_build('compile-error')
        self.assertEqual(len([c for c in self.calls() if c[0] == 'build']), 1)
        self.assert_not_promoted()

    def test_success_without_an_image_id_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'valid image ID'):
            self.run_build('no-iid')
        self.assert_not_promoted()

    def test_unusable_image_is_not_promoted(self):
        with self.assertRaisesRegex(ValueError, 'image cannot unpack or start'):
            self.run_build('run-error')
        self.assert_not_promoted()
        self.assertTrue(any(c[:2] == ['container', 'rm'] for c in self.calls()))

    def test_unexpected_root_image_is_not_run_or_promoted(self):
        with self.assertRaisesRegex(ValueError, 'expected Linux worker configuration'):
            self.run_build('wrong-user')
        self.assert_not_promoted()
        self.assertFalse(any(c[0] == 'run' for c in self.calls()))

    def test_wrong_executable_help_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'unexpected output'):
            self.run_build('wrong-help')
        self.assert_not_promoted()

    def test_timed_out_probe_is_cleaned_up_and_not_promoted(self):
        real_run = subprocess.run

        def run(command, *args, **kwargs):
            if len(command) > 3 and command[3] == 'run':
                raise subprocess.TimeoutExpired(command, 30)
            return real_run(command, *args, **kwargs)

        with patch('hal_fleet.worker_image.subprocess.run', side_effect=run):
            with self.assertRaisesRegex(ValueError, 'timed out'):
                self.run_build()
        self.assert_not_promoted()
        self.assertTrue(any(c[:2] == ['container', 'rm'] for c in self.calls()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
