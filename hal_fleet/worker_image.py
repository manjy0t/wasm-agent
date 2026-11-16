#!/usr/bin/env python3
"""Build and verify the local Linux worker image; no daemon resets or cache pruning."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hal_fleet.gvisor import profile as sandbox_profile, validate_info


def snapshot_export_failure(output):
    # BuildKit/containerd can GC a parent between snapshot lookup and unpack.
    # Retry only this reported failure, never arbitrary build/compile errors.
    # https://github.com/moby/buildkit/issues/6521
    return ('failed to prepare extraction snapshot' in output
            and 'parent snapshot' in output and 'does not exist' in output)


def stream_build(command, root):
    tail = ''
    with subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, errors='replace') as process:
        for line in process.stdout:
            print(line, end='', flush=True)
            tail = (tail + line)[-65536:]
        return process.wait(), tail


def capture(command):
    try:
        return subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=30).stdout
    except subprocess.CalledProcessError as exc:
        raise ValueError('Docker image check failed: ' + (exc.stderr or exc.stdout or str(exc))[-4000:].strip()) from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Docker image check timed out after 30 seconds') from exc


def cleanup(command):
    # Only objects named with this invocation's random identifier are removed.
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        print('Could not remove temporary build object: ' + command[-1], file=sys.stderr)


def build_worker_image(root, image='hal-user-worker:local', docker='docker'):
    root = Path(root).resolve()
    if not (root / 'containers/Dockerfile').is_file():
        raise ValueError('Run from the repository or supply --root with containers/Dockerfile')
    if not image or image.startswith('-') or '@' in image or any(c.isspace() for c in image):
        raise ValueError('Supply a local Docker image tag')
    local = [docker, '--host', 'unix:///var/run/docker.sock']
    # Never test/promote the worker under a weaker Docker default runtime.
    validate_info(json.loads(capture([*local, 'info', '--format={{json .}}'])))
    identifier = uuid.uuid4().hex
    candidate = 'hal-fleet-worker-build:' + identifier
    probe = 'hal-fleet-image-check-' + identifier
    probe_started = False
    try:
        with tempfile.TemporaryDirectory(prefix='hal-worker-build-') as folder:
            iid = Path(folder) / 'image-id'
            command = [*local, 'build', '--progress=plain', '--platform=linux/amd64',
                       '--iidfile', str(iid), '--tag', candidate, '--file', 'containers/Dockerfile', '.']
            for attempt in range(1, 4):
                # An unsuccessful prior attempt must not supply an image ID.
                if iid.exists():
                    iid.unlink()
                print('Building worker image (attempt ' + str(attempt) + '/3)', flush=True)
                code, tail = stream_build(command, root)
                if code == 0:
                    break
                if not snapshot_export_failure(tail):
                    raise ValueError('Worker image build failed; see Docker output above. Existing worker tag was not replaced.')
                if attempt == 3:
                    raise ValueError('Docker snapshot export failed on all three attempts. Check disk space and the '
                                     'Docker/BuildKit installation. Existing worker tag was not replaced; no caches were pruned.')
                print('Docker lost a parent snapshot during export; retrying with the completed build cache.', flush=True)
                time.sleep(2 * attempt)

            image_id = iid.read_text().strip() if iid.exists() else ''
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
                raise ValueError('Docker did not return a valid image ID for this build; worker tag was not replaced')
            details = json.loads(capture([*local, 'image', 'inspect', '--format', '{{json .}}', image_id]))
            config = details.get('Config') or {}
            if (details.get('Id') != image_id or details.get('Os') != 'linux'
                    or details.get('Architecture') != 'amd64' or config.get('User') != '65532:65532'
                    or config.get('Entrypoint') != ['/usr/local/bin/hal-on-demand']):
                raise ValueError('Built image does not match the expected Linux worker configuration; tag was not replaced')

            print('Checking that the built worker starts with a read-only filesystem and no network.', flush=True)
            probe_started = True
            output = capture([*local, 'run', '--runtime=' + sandbox_profile()['runtime'],
                              '--rm', '--pull=never', '--name', probe,
                              '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                              '--security-opt', 'no-new-privileges', '--user', '65532:65532',
                              '--pids-limit', '64', '--memory', '256m', '--cpus', '1', image_id, '--help'])
            if 'Usage:' not in output or '--user-containers' not in output or '--job-authorization' not in output:
                raise ValueError('Worker startup check returned unexpected output; tag was not replaced')
            capture([*local, 'image', 'tag', image_id, image])
            return dict(image=image, image_id=image_id, build_attempts=attempt, startup_check='passed',
                        sandbox_profile=sandbox_profile()['profile'])
    finally:
        if probe_started:
            cleanup([*local, 'container', 'rm', '--force', probe])
        # Removing this temporary tag retains the promoted image and its cache.
        cleanup([*local, 'image', 'rm', candidate])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--image', default='hal-user-worker:local')
    args = parser.parse_args()
    print(json.dumps(build_worker_image(args.root, args.image), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        sys.exit(1)
