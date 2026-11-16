#!/usr/bin/env python3
"""One repository, four VM roles, and a signing client. Run --help for commands."""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import sys
import threading

ROOT = Path(__file__).resolve().parent


def main():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from hal_fleet.common import (DOCUMENT_DOMAIN, Database, Error, Transport, atomic_json, digest,
        key_from_hex, origin, parse, private_hex, public, read_private, request, require, verify)
    from hal_fleet.policy import SETTINGS
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    key = sub.add_parser('operator-key', help='Create a publisher key on the operator laptop, once')
    key.add_argument('--output', type=Path, default=Path('state/fleet-operator.json'))
    audit_key = sub.add_parser('audit-key', help='Create a fresh service audit signing key; no authority is granted automatically')
    audit_key.add_argument('--output', type=Path, required=True)
    setup = sub.add_parser('init', help='Initialize one VM role; never overwrite existing state')
    setup.add_argument('--role', choices=['identity', 'files', 'management', 'execution'], required=True)
    setup.add_argument('--config', type=Path, default=Path('state/fleet.json'))
    setup.add_argument('--listen', default='127.0.0.1:9200')
    setup.add_argument('--identity-url', required=True)
    setup.add_argument('--management-url')
    setup.add_argument('--execution-url')
    setup.add_argument('--files-url')
    setup.add_argument('--operator-public-key')
    setup.add_argument('--issuer-sha256')
    setup.add_argument('--ca-file', type=Path)
    setup.add_argument('--tls-cert', type=Path)
    setup.add_argument('--tls-key', type=Path)
    setup.add_argument('--allow-http', action='store_true')
    setup.add_argument('--mode', choices=['wasm', 'native'], default='wasm')
    setup.add_argument('--container-image', default='hal-user-worker:local')
    setup.add_argument('--allow-non-tee', action='store_true')
    setup.add_argument('--test-in-process', action='store_true')
    for name in ('serve', 'unit', 'trust-build'):
        cmd = sub.add_parser(name, help={'serve':'Start the configured service', 'unit':'Print its systemd unit',
                                         'trust-build':'Approve an intentional local build change'}[name])
        cmd.add_argument('--config', type=Path, default=Path('state/fleet.json'))
        if name == 'trust-build':
            cmd.add_argument('--apply', action='store_true')
    portable = sub.add_parser('configure-agent', help='Configure the management-owned attested agent architecture')
    portable.add_argument('--config', type=Path, default=Path('state/fleet.json'))
    portable.add_argument('--profile', type=Path, required=True)
    portable.add_argument('--apply', action='store_true')
    native = sub.add_parser('configure-native-audit', help='Create a separate audited-native configuration and fresh state')
    native.add_argument('--config', type=Path, required=True)
    native.add_argument('--profile', type=Path, required=True)
    native.add_argument('--output', type=Path, required=True)
    modes = sub.add_parser('configure-modes', help='Create a selector around existing agent and audited-native profiles')
    modes.add_argument('--agent-config', type=Path, required=True)
    modes.add_argument('--native-config', type=Path, required=True)
    modes.add_argument('--output', type=Path, required=True)
    modes.add_argument('--control-public-key', help='Execution VM: pin the existing agent management public key')
    for name in ('mode-status', 'mode-select'):
        cmd = sub.add_parser(name, help='Management-owned execution mode control; requires the management selector config')
        cmd.add_argument('--config', type=Path, required=True)
        if name == 'mode-select':
            cmd.add_argument('--mode', choices=['agent', 'native'], required=True)
            cmd.add_argument('--drain-seconds', type=int, default=60, choices=range(0, 61), metavar='0..60')
    native_cert = sub.add_parser('native-audit-certificate', help='Certify a native audit signer; this is not TEE attestation')
    native_cert.add_argument('--management-key', type=Path, required=True)
    native_cert.add_argument('--native-public-key', required=True)
    native_cert.add_argument('--output', type=Path, required=True)
    native_cert.add_argument('--days', type=int, default=30)
    profile = sub.add_parser('client-profile', help='Copy a client identity into an explicitly pinned execution profile')
    profile.add_argument('--client', type=Path, required=True)
    profile.add_argument('--mode', choices=['native', 'wasm'], required=True)
    profile.add_argument('--output', type=Path, required=True)
    verify_bench = sub.add_parser('benchmark-verify', help='Check immutable evidence before comparing a measured batch')
    verify_bench.add_argument('--output', type=Path, required=True)
    release = sub.add_parser('benchmark-release', help='Release your interrupted experiment after its jobs have drained')
    release.add_argument('--client', type=Path, required=True)
    release.add_argument('--experiment-id', required=True)
    for name in ('agent-status', 'agent-undeploy', 'agent-deploy'):
        cmd = sub.add_parser(name, help='Management-server agent lifecycle control (requires management signing key)')
        cmd.add_argument('--config', type=Path, default=Path('state/fleet.json'))
        cmd.add_argument('--execution-url', required=True, help='One configured execution VM URL')
        if name == 'agent-undeploy':
            cmd.add_argument('--drain-seconds', type=int, default=30, choices=range(0, 61), metavar='0..60')
    client = sub.add_parser('client-init', help='Create a user key on the user laptop; pin the identity service')
    client.add_argument('--user', required=True)
    client.add_argument('--identity-url')
    client.add_argument('--issuer-sha256')
    client.add_argument('--deployment', type=Path)
    client.add_argument('--ca-file', type=Path)
    client.add_argument('--allow-http', action='store_true')
    client.add_argument('--output', type=Path, required=True)
    onboard = sub.add_parser('onboard', help='Create/reuse a user key, register, enroll and approve workloads through APIs')
    onboard.add_argument('--user', required=True)
    onboard.add_argument('--deployment', type=Path, required=True)
    onboard.add_argument('--ca-file', type=Path, help='Optional local CA path when moving a deployment to another computer')
    onboard.add_argument('--output', type=Path, required=True)
    onboard.add_argument('--workloads', default='all')
    for name in ('register', 'renew', 'approve', 'run', 'bench', 'catalog', 'result', 'audit'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--client', type=Path, required=True)
        if name == 'approve':
            cmd.add_argument('--workloads', required=True, help='Comma-separated approved catalog names, or all')
        if name in ('run', 'bench'):
            cmd.add_argument('--cache', choices=['bypass', 'reuse'], default='bypass')
            cmd.add_argument('--expect-mode', choices=['wasm', 'native'], default='wasm')
            cmd.add_argument('--expect-isolation', choices=['per-user-container', 'in-process'], default='per-user-container')
        if name == 'run':
            cmd.add_argument('--workload', required=True)
        if name == 'bench':
            cmd.add_argument('--workloads', default='all')
            cmd.add_argument('--jobs', type=int, default=100)
            cmd.add_argument('--concurrency', type=int, default=1)
            cmd.add_argument('--output', type=Path, required=True)
            cmd.add_argument('--phase', choices=['startup', 'warmup', 'measured'], default='measured')
        if name == 'result':
            cmd.add_argument('--job-id', required=True)
        if name == 'audit':
            cmd.add_argument('--job-id')
            cmd.add_argument('--after', type=int, default=0)
            cmd.add_argument('--limit', type=int, default=50)
    profiles = sub.add_parser('profile-manifest', help='Prepare optional workload permissions from reviewed templates; does not publish')
    profiles.add_argument('--manifest', type=Path, required=True)
    profiles.add_argument('--output', type=Path, required=True)
    choice = profiles.add_mutually_exclusive_group(required=True)
    choice.add_argument('--template', help='A reusable template, e.g. compute, sha256, signature-verify, storage-read')
    choice.add_argument('--assignments', type=Path, help='JSON mapping workload names to template names')
    profiles.add_argument('--name-suffix', default='', help='Optional catalog version suffix for new names')
    profiles.add_argument('--max-host-calls', type=int, default=10000)
    profiles.add_argument('--max-buffer-bytes', type=int, default=1048576)
    publish = sub.add_parser('publish', help='Upload immutable artifacts and approve their catalog via APIs')
    publish.add_argument('--operator', type=Path, required=True)
    publish.add_argument('--identity-url')
    publish.add_argument('--issuer-sha256')
    publish.add_argument('--deployment', type=Path)
    publish.add_argument('--ca-file', type=Path)
    publish.add_argument('--allow-http', action='store_true')
    publish.add_argument('--manifest', type=Path, required=True)
    revoke = sub.add_parser('revoke', help='Revoke a user through the authority API')
    for action in ('operator', 'ca-file'):
        revoke.add_argument('--' + action, type=Path, required=action == 'operator')
    revoke.add_argument('--identity-url')
    revoke.add_argument('--issuer-sha256')
    revoke.add_argument('--deployment', type=Path)
    revoke.add_argument('--user', required=True)
    revoke.add_argument('--allow-http', action='store_true')
    tls = sub.add_parser('certificates', help='Create a private CA and TLS certificates for four static IPs')
    tls.add_argument('--inventory', type=Path, required=True)
    tls.add_argument('--output', type=Path, required=True)
    bundle = sub.add_parser('package', help='Package this source repository without secrets, results, or build caches')
    bundle.add_argument('--output', type=Path, required=True)
    deploy = sub.add_parser('deploy', help='One-time SSH installation of the four HTTPS services')
    deploy.add_argument('--inventory', type=Path, required=True)
    deploy.add_argument('--credentials', type=Path, required=True)
    deploy.add_argument('--ssh-key', type=Path, required=True)
    deploy.add_argument('--operator', type=Path, required=True)
    deploy.add_argument('--install-dependencies', action='store_true')
    deploy.add_argument('--portable-profile', type=Path, help='Management agent + approved attestation policy; see PORTABLE_AGENT.md')
    network = sub.add_parser('network-check', help='Read-only identity HTTPS check from the other VMs over SSH')
    network.add_argument('--inventory', type=Path, required=True)
    network.add_argument('--credentials', type=Path, required=True)
    network.add_argument('--ssh-key', type=Path, required=True)
    network.add_argument('--from-role', choices=['files', 'execution', 'management'])
    args = parser.parse_args()
    require(os.name != 'nt' or args.command not in ('init', 'serve', 'unit', 'trust-build', 'configure-agent', 'configure-native-audit',
            'configure-modes', 'mode-select', 'mode-status', 'agent-status', 'agent-undeploy', 'agent-deploy'),
            'This command runs on a Linux service VM. From Windows use deploy, onboard, run or bench; see WINDOWS.md.')
    if args.command in ('client-init', 'publish', 'revoke', 'onboard'):
        if args.deployment:
            from hal_fleet.local_files import resolve_ca_file
            deployment = parse(args.deployment.read_text(encoding='utf-8-sig'))
            args.identity_url = deployment['endpoints']['identity']
            args.issuer_sha256 = deployment['issuer_sha256']
            if not args.ca_file:
                args.ca_file = Path(resolve_ca_file(args.deployment, deployment['ca_file']))
        require(args.identity_url and args.issuer_sha256, 'Use --deployment or supply --identity-url and --issuer-sha256')

    def output(value):
        print(json.dumps(value, indent=2))

    if args.command == 'native-audit-certificate':
        from hal_fleet.native_config import issue_certificate
        output(issue_certificate(args.management_key, args.native_public_key, args.output, args.days))
        return 0
    if args.command == 'configure-native-audit':
        from hal_fleet.native_config import configure
        output(configure(args.config, args.profile, args.output))
        return 0
    if args.command == 'client-profile':
        from hal_fleet.local_files import resolve_ca_file
        config = read_private(args.client)
        require(args.output.resolve() != args.client.resolve() and not args.output.exists(), 'Choose a new client path')
        if config.get('ca_file'):
            config['ca_file'] = resolve_ca_file(args.client, config['ca_file'])
        config['required_execution_architecture'] = 'hal-native-audited-v1' if args.mode == 'native' else 'hal-managed-agent-v2'
        config['require_attested_agent'] = args.mode == 'wasm'
        atomic_json(args.output, config, exclusive=True)
        output(dict(client=str(args.output), execution_architecture=config['required_execution_architecture']))
        return 0
    if args.command == 'benchmark-verify':
        from hal_fleet.benchmark_guard import verify_batch
        output(verify_batch(args.output))
        return 0

    def fetch_trust(identity_url, fingerprint, ca_file, allow_http):
        identity_url = origin(identity_url, allow_http)
        transport = Transport(timeout=10, ca_file=str(ca_file) if ca_file else None)
        try:
            result = transport.call(identity_url, '/v1/trust')
        finally:
            transport.close()
        candidate = parse(result['payload'])
        require(digest(bytes.fromhex(candidate['identity_public_key'])) == fingerprint, 'Identity fingerprint mismatch')
        trust = verify(candidate['identity_public_key'], DOCUMENT_DOMAIN, result)
        require(trust['endpoints']['identity'] == identity_url, 'Identity URL differs from trusted deployment')
        for url in trust['endpoints'].values():
            origin(url, allow_http)
        return trust

    if args.command == 'profile-manifest':
        from hal_fleet.access_profiles import generate
        output(generate(args.manifest, args.output, args.template, args.assignments,
                        args.name_suffix, args.max_host_calls, args.max_buffer_bytes))
        return 0
    if args.command in ('operator-key', 'audit-key'):
        k = Ed25519PrivateKey.generate()
        atomic_json(args.output, dict(private_key=private_hex(k), public_key=public(k)), exclusive=True)
        output({('operator_public_key' if args.command == 'operator-key' else 'audit_public_key'): public(k),
                'private_key_file': str(args.output)})
        return 0
    if args.command in ('certificates', 'package', 'deploy', 'network-check'):
        from hal_fleet.install import certificates, package, deploy, network_check
        if args.command == 'certificates':
            output(certificates(args.inventory, args.output))
        elif args.command == 'package':
            output(package(ROOT, args.output))
        elif args.command == 'network-check':
            result = network_check(args.inventory, args.credentials, args.ssh_key, args.from_role)
            output(result)
            return 0 if result['ok'] else 1
        else:
            output(deploy(ROOT, args.inventory, args.credentials, args.ssh_key, args.operator, args.install_dependencies, args.portable_profile))
        return 0
    if args.command in ('agent-status', 'agent-undeploy', 'agent-deploy'):
        config = read_private(args.config)
        require(config.get('role') == 'management' and config.get('execution_architecture') == 'hal-managed-agent-v2',
                'Run this command on the management server with its portable-agent configuration')
        key = key_from_hex(read_private(config['management_key'])['private_key'])
        body = dict(execution_url=args.execution_url.rstrip('/'))
        if args.command == 'agent-undeploy':
            body['drain_seconds'] = args.drain_seconds
        from hal_fleet.common import request
        control = request(key, config['trust']['management_audience'], args.command, 'management', body)
        transport = Transport(timeout=150, ca_file=config.get('ca_file'))
        try:
            result = transport.call(config['trust']['endpoints']['management'],
                                    '/v2/agents/' + args.command.removeprefix('agent-'), control)
            output(result)
            return 0 if args.command != 'agent-undeploy' or result.get('state') == 'undeployed' else 2
        finally:
            transport.close()
    if args.command == 'configure-agent':
        from hal_fleet.portable_config import configure
        output(configure(args.config, args.profile, args.apply))
        return 0
    if args.command == 'configure-modes':
        from hal_fleet.mode_selection import configure
        output(configure(args.agent_config, args.native_config, args.output, args.control_public_key))
        return 0
    if args.command in ('mode-status', 'mode-select'):
        from hal_fleet.mode_selection import PROTOCOL
        config = read_private(args.config)
        require(config.get('role') == 'management' and config.get('execution_architecture') == PROTOCOL,
                'Use the mode-selection configuration on the owning management server')
        key = key_from_hex(read_private(config['mode_control_key'])['private_key'])
        require(public(key) == config['mode_control_public_key'], 'Wrong management mode-control key')
        data = dict(mode=args.mode, drain_seconds=args.drain_seconds) if args.command == 'mode-select' else {}
        control = request(key, config['trust']['management_audience'], args.command, 'management', data)
        transport = Transport(timeout=300, ca_file=config.get('ca_file'))
        try:
            output(transport.call(config['management_url'], '/v1/mode/' + args.command.removeprefix('mode-'), control))
            return 0
        finally:
            transport.close()
    if args.command == 'init':
        from hal_fleet.common import SHA
        require(not args.config.exists(), 'Configuration already exists; keep it rather than regenerating identities', 409)
        require(not args.test_in_process or args.allow_non_tee, '--test-in-process requires explicit --allow-non-tee')
        require(bool(args.tls_cert) == bool(args.tls_key), 'Supply both TLS certificate and key')
        host = args.listen.rsplit(':', 1)[0]
        require(args.tls_cert or host in ('127.0.0.1', '::1', 'localhost') or args.allow_http,
                'Public listeners require TLS (or explicit isolated-test --allow-http)')
        config = dict(version=1, role=args.role, listen=args.listen,
                      state_dir=str(args.config.resolve().parent / ('fleet-' + args.role)))
        state = Path(config['state_dir'])
        identity_secret = None
        if args.role == 'identity':
            require(args.operator_public_key and SHA.fullmatch(args.operator_public_key), 'Supply the operator public key')
            endpoints = {r: origin(getattr(args, r + '_url') or '', args.allow_http)
                         for r in ('identity', 'management', 'execution', 'files')}
            config['identity_key'] = str(state / 'identity-key.json')
            if Path(config['identity_key']).exists():
                k = key_from_hex(read_private(config['identity_key'])['private_key'])
            else:
                k = Ed25519PrivateKey.generate()
                identity_secret = dict(private_key=private_hex(k))
            trust = dict(version=1, issuer='hal-identity', management_audience='hal-management', files_audience='hal-files',
                         execution_audience='intel-worker-1', identity_public_key=public(k),
                         operator_public_key=args.operator_public_key, endpoints=endpoints)
        else:
            require(args.issuer_sha256, 'Supply the identity public-key fingerprint from the operator setup')
            trust = fetch_trust(args.identity_url, args.issuer_sha256, args.ca_file, args.allow_http)
        config['trust'] = trust
        for role, url in trust['endpoints'].items():
            config[role + '_url'] = url
        if args.ca_file:
            config['ca_file'] = str(args.ca_file.resolve())
        if args.tls_cert:
            config.update(tls_cert=str(args.tls_cert.resolve()), tls_key=str(args.tls_key.resolve()))
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(config['tls_cert'], config['tls_key'])
        if args.role == 'execution':
            config.update(mode=args.mode, binary=str(ROOT / 'dist/hal-on-demand'), agent=str(ROOT / 'dist/agent.wasm'),
                container_image=args.container_image, settings=SETTINGS, max_active_users=4, global_inflight=16,
                allow_non_tee=args.allow_non_tee, test_in_process=args.test_in_process)
            config['binary_sha256'] = digest(Path(config['binary']).read_bytes())
            config['agent_sha256'] = digest(Path(config['agent']).read_bytes()) if args.mode == 'wasm' else '0' * 64
        # Complete preflight before creating state, so an ordinary configuration
        # error can be corrected and the same init command can be run again.
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        require(state.stat().st_uid == os.geteuid() and not state.stat().st_mode & 0o077,
                'Service state must belong to this user with mode 700')
        if identity_secret:
            atomic_json(config['identity_key'], identity_secret, exclusive=True)
        atomic_json(args.config, config, exclusive=True)
        output(dict(role=args.role, config=str(args.config), issuer_sha256=digest(bytes.fromhex(trust['identity_public_key']))))
        return 0
    if args.command in ('serve', 'unit', 'trust-build'):
        config = parse(args.config.read_text())
        require(args.command == 'trust-build' or config.get('execution_architecture') != 'hal-managed-agent-v1', 'Reconfigure the old portable profile with configure-agent before starting the shared-agent runtime')
        if args.command == 'unit':
            from hal_fleet.install import systemd_unit
            print(systemd_unit(ROOT, args.config, config))
            return 0
        if args.command == 'trust-build':
            require(config['role'] == 'execution', 'Only execution has runtime build pins')
            require(config.get('execution_architecture') != 'hal-selectable-execution-v1',
                    'Review build pins in the underlying profile, then configure a fresh selector; do not repin a live experiment')
            names = ('runner',) if config.get('execution_architecture') in ('hal-managed-agent-v1', 'hal-managed-agent-v2') else ('binary',) if config.get('mode') == 'native' else ('binary', 'agent')
            changes = {name + '_sha256': digest(Path(config[name]).read_bytes()) for name in names}
            if config.get('execution_architecture') == 'hal-native-audited-v1':
                from hal_fleet.native_config import service_digest
                changes['service_sha256'] = service_digest()
            output(dict(previous={k: config[k] for k in changes}, current=changes, applied=args.apply))
            if args.apply:
                config.update(changes)
                atomic_json(args.config, config)
            return 0
        from hal_fleet.authority import Authority
        from hal_fleet.services import Files, Management
        from hal_fleet.runtime import Execution
        from hal_fleet.http_server import make_server
        import fcntl
        if config['role'] == 'execution' and config.get('mode') == 'wasm' and not config.get('test_in_process'):
            from hal_fleet.gvisor import check
            check()
        state = Path(config['state_dir'])
        lock = (state / 'service.lock').open('a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error('This service state is already in use')
        database = Database(state / 'state.sqlite3')
        from hal_fleet.benchmark_state import bind_state, execution_slot
        bind_state(config, database)
        vm_slot = execution_slot() if config['role'] == 'execution' else None
        transport = Transport(ca_file=config.get('ca_file'))
        classes = dict(identity=Authority, files=Files, management=Management, execution=Execution)
        if config.get('execution_architecture') == 'hal-managed-agent-v2':
            from hal_fleet.portable import PortableExecution, PortableManagement
            classes.update(execution=PortableExecution, management=PortableManagement)
        elif config.get('execution_architecture') == 'hal-native-audited-v1':
            from hal_fleet.native_audit import NativeExecution, NativeManagement
            from hal_fleet.native_config import service_digest
            require(config['service_sha256'] == service_digest(), 'Native service source changed; review the build and configure fresh native state')
            classes.update(execution=NativeExecution, management=NativeManagement)
        elif config.get('execution_architecture') == 'hal-selectable-execution-v1':
            from hal_fleet.mode_selection import SelectableExecution, SelectableManagement
            classes.update(execution=SelectableExecution, management=SelectableManagement)
        klass = classes[config['role']]
        app = klass(config, database) if config['role'] in ('identity', 'files') else klass(config, database, transport)
        if config['role'] == 'management' and config.get('execution_architecture') != 'hal-selectable-execution-v1':
            from hal_fleet.benchmark_guard import BenchmarkGate
            app = BenchmarkGate(app)
        server = make_server(config, app)
        def stop(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        output(dict(status='ready', role=config['role'], listen=config['listen'], attestation_verified=False))
        sys.stdout.flush()
        try:
            server.serve_forever(poll_interval=.2)
        finally:
            server.server_close()
            if hasattr(app, 'close'):
                app.close()
            transport.close()
            database.close()
            lock.close()
            if vm_slot:
                vm_slot.close()
        return 0
    if args.command in ('client-init', 'onboard'):
        from hal_fleet.common import NAME
        require(NAME.fullmatch(args.user), 'Use a lowercase user name with letters, digits, hyphens or underscores')
        trust = fetch_trust(args.identity_url, args.issuer_sha256, args.ca_file, getattr(args, 'allow_http', False))
        if args.command == 'onboard' and args.output.exists():
            config = read_private(args.output)
            require(config['user'] == args.user and config['trust'] == trust, 'Existing client belongs to a different user/deployment')
            if args.ca_file:
                config['ca_file'] = str(args.ca_file.resolve())
                atomic_json(args.output, config)
        else:
            k = Ed25519PrivateKey.generate()
            config = dict(version=1, user=args.user, private_key=private_hex(k), trust=trust)
            if args.ca_file:
                config['ca_file'] = str(args.ca_file.resolve())
            atomic_json(args.output, config, exclusive=True)
        if args.command == 'onboard':
            from hal_fleet.client import Client
            client = Client(args.output)
            client.register()
            names = [w['name'] for w in client.call('management', '/v1/workloads')['workloads']] if args.workloads == 'all' else args.workloads.split(',')
            require(names, 'The operator must publish workloads before approval')
            output(dict(client=str(args.output), **client.approve(names)))
            client.transport.close()
        else:
            output(dict(client=str(args.output), user=args.user))
        return 0
    if args.command in ('publish', 'revoke'):
        import base64
        trust = fetch_trust(args.identity_url, args.issuer_sha256, args.ca_file, args.allow_http)
        operator = key_from_hex(read_private(args.operator)['private_key'])
        require(public(operator) == trust['operator_public_key'], 'This is not the trusted publisher key')
        transport = Transport(ca_file=str(args.ca_file) if args.ca_file else None)
        if args.command == 'revoke':
            output(transport.call(trust['endpoints']['identity'], '/v1/revoke',
                request(operator, trust['issuer'], 'revoke', 'operator', {'user': args.user})))
        else:
            from hal_fleet.policy import workload
            manifest = parse(args.manifest.read_text(encoding='utf-8-sig'))
            rows = manifest['workloads']
            for row in rows:
                workload(row)
                file = args.manifest.resolve().parent / row['component']
                raw = file.read_bytes()
                require(digest(raw) == row['sha256'] and len(raw) == row['artifact_bytes'], 'Build manifest/artifact mismatch')
                transport.call(trust['endpoints']['files'], '/v1/upload', request(operator, trust['files_audience'], 'upload',
                    'operator', dict(sha256=row['sha256'], wasm_base64=base64.b64encode(raw).decode())))
            output(transport.call(trust['endpoints']['identity'], '/v1/publish',
                request(operator, trust['issuer'], 'publish', 'operator', {'workloads': rows})))
        return 0
    from hal_fleet.client import Client, benchmark
    client = Client(args.client)
    if args.command == 'benchmark-release':
        try:
            client.renew()
            output(client.call('management', '/v1/benchmark', client.signed('management', 'benchmark',
                dict(document=client.document, action='release', experiment_id=args.experiment_id))))
        finally:
            client.transport.close()
    elif args.command in ('register', 'renew'):
        output(getattr(client, args.command)())
    elif args.command == 'catalog':
        output(client.call('management', '/v1/workloads'))
    elif args.command == 'approve':
        names = [w['name'] for w in client.call('management', '/v1/workloads')['workloads']] if args.workloads == 'all' else args.workloads.split(',')
        output(client.approve(names))
    elif args.command == 'result':
        client.renew()
        output(client.call('management', '/v1/result', client.signed('management', 'result',
            dict(document=client.document, job_id=args.job_id))))
    elif args.command == 'audit':
        output(client.audit(args.after, args.limit, args.job_id))
    elif args.command == 'run':
        client.open_session()
        row = client.job(args.workload, args.cache, args.expect_mode, args.expect_isolation)
        output(row)
        return 0 if row['status'] == 'completed' else 1
    elif args.command == 'bench':
        client.renew()
        names = [w['name'] for w in parse(client.document['payload'])['workloads']] if args.workloads == 'all' else args.workloads.split(',')
        row = benchmark(client, names, args.jobs, args.concurrency, args.cache, args.output,
                        args.expect_mode, args.expect_isolation, phase=args.phase)
        output(row)
        return 0 if row['failed_or_unknown'] == 0 else 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        from hal_fleet.common import Error
        if not isinstance(exc, Error):
            raise
        print('Error [' + exc.code + ']: ' + str(exc), file=sys.stderr)
        sys.exit(1)
