#!/usr/bin/env python3
"""Save deployment paths, check policies, and prepare reviewed workload updates.

This is an operator tool, not an HTTP API. It never downloads code to approve,
generates credentials, rotates signing keys, or disables a runtime check.
"""
import argparse
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler
import uuid

from job_signing import rule_digest
from server.management import load_catalog, token_file

ROOT = Path(__file__).resolve().parent
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
LIMITS = {
    'downloads': 4, 'compilers': 2, 'compiler_threads': 2,
    'executions': 4, 'max_inflight': 16, 'compile_opt_level': 'speed',
    'execution_timeout_secs': 5, 'max_output_bytes': 4096,
    'workload_memory_mib': 64, 'workload_fuel': 1000000000,
    'max_component_bytes': 16777216, 'container_cpus': 2,
    'container_memory_mib': 1024, 'container_pids': 128,
    'container_storage_mib': 64,
}
RULE_LIMITS = ('cache_ttl_ms', 'memory_mib', 'fuel', 'execution_timeout_ms',
               'max_output_bytes', 'worker_max_jobs')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path, maximum=4 * 1024 * 1024):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise ValueError(f'Missing file: {path}. Choose an existing file during init; '
                         'old HAL_* shell variables are not used.') from None
    with os.fdopen(fd, 'rb') as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), f'Not a regular file: {path}')
        data = stream.read(maximum + 1)
    need(len(data) <= maximum, f'File exceeds {maximum} bytes: {path}')
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, f'Duplicate JSON field: {key}')
        result[key] = value
    return result


def no_private_keys(value):
    if isinstance(value, dict):
        need('private_key' not in value, 'A public deployment document contains a private key.')
        for child in value.values():
            no_private_keys(child)
    elif isinstance(value, list):
        for child in value:
            no_private_keys(child)


def document(path, public=True):
    data = json.loads(read_bytes(path), object_pairs_hook=unique_object)
    need(isinstance(data, dict), f'Expected a JSON object: {path}')
    if public:
        no_private_keys(data)
    return data


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def replace_file(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def change_files(root, changes):
    """Back up first, atomically replace each file, roll back ordinary exceptions.

    Services must be stopped before applying a policy release. This is not a
    crash-atomic transaction across multiple files or multiple VMs.
    """
    old = {Path(path): read_bytes(path) for path in changes}
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    backup = root / 'state/deployment-backups' / stamp
    backup.mkdir(mode=0o700, parents=True)
    index = []
    for i, (path, content) in enumerate(old.items()):
        name = f'{i}-{path.name}'
        write_new(backup / name, content)
        index.append({'original': str(path), 'backup': name, 'sha256': digest(content)})
    write_new(backup / 'index.json', encoded(index))
    changed = []
    try:
        for path, content in changes.items():
            replace_file(path, content)
            changed.append(Path(path))
    except Exception:
        for path in reversed(changed):
            replace_file(path, old[path])
        raise
    return backup


@contextmanager
def operator_lock(root):
    state = root / 'state'
    state.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(state / '.deployment.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def resolve(root, value):
    path = Path(value)
    return path if path.is_absolute() else root / path


def stored_path(root, value):
    path = resolve(root, value).absolute()
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def url(value, origin=False):
    parsed = urlsplit(value)
    need(parsed.scheme in ('http', 'https') and parsed.hostname and parsed.username is None
         and parsed.password is None and not parsed.query and not parsed.fragment,
         'Use an HTTP(S) URL with a hostname and no credentials/query/fragment.')
    need(parsed.port is None or 1 <= parsed.port <= 65535, 'Invalid URL port.')
    need(not origin or parsed.path in ('', '/'), 'The worker URL must end at the host:port.')
    return value.rstrip('/') + '/'


def load_config(root, config_path):
    config = document(config_path)
    need(config.get('version') == 1 and config.get('role') in ('execution', 'management'),
         'Unsupported deployment configuration. Run deployment.py init first.')
    need(isinstance(config.get('paths'), dict) and isinstance(config.get('settings'), dict)
         and all(isinstance(v, str) and v for v in config['paths'].values()),
         'Saved configuration needs paths (filenames) and settings (limits) objects.')
    return config


def paths_for(root, config):
    return {key: resolve(root, value) for key, value in config['paths'].items()}


def identities(data, kind):
    need(data.get('version') == 1 and isinstance(data.get('tenants'), list)
         and 1 <= len(data['tenants']) <= 64, 'Invalid tenant policy version or tenant list.')
    result = {}
    for row in data['tenants']:
        need(isinstance(row, dict), 'Each tenant entry must be a JSON object.')
        identity = row.get('id')
        need(isinstance(identity, str) and NAME.fullmatch(identity) and len(identity) <= 64
             and identity == identity.lower() and identity != 'legacy' and identity not in result,
             'Invalid or duplicate tenant identity.')
        required = ('artifacts', 'token_file') if kind == 'execution' else (
            'cases', 'api_token_file', 'worker_token_file')
        need(all(key in row for key in required),
             f'{identity}: this is not a {kind} policy. Required fields: {", ".join(required)}. '
             'Management and execution policy.json files have different formats.')
        result[identity] = row
    return result


def artifact_tuple(row):
    return (row.get('component', row.get('artifact', row.get('url_path'))),
            row.get('sha256'), row.get('artifact_bytes'))


def validate_artifact(row, maximum):
    name, sha, size = artifact_tuple(row)
    need(isinstance(name, str) and NAME.fullmatch(name) and name.endswith('.wasm'),
         'Artifact must use a simple .wasm filename.')
    need(isinstance(sha, str) and SHA.fullmatch(sha), 'Expected a lowercase SHA-256 fingerprint.')
    need(type(size) is int and 8 <= size <= maximum, 'Artifact size exceeds the configured limit.')


def validate_result(rule, maximum, catalog=False):
    need(isinstance(rule, dict) and not set(rule) - {'kind', 'value'}, 'Invalid result rule.')
    kind, value = rule.get('kind'), rule.get('value')
    if kind in ('clock', 'bounded'):
        need('value' not in rule and (kind != 'bounded' or not catalog),
             'Catalogs require hex, length, utf8_contains or clock validation.')
    elif kind == 'hex':
        need(isinstance(value, str) and re.fullmatch(r'(?:[0-9a-f]{2})*', value)
             and len(value) // 2 <= maximum, 'Expected hex must be lowercase and fit the output limit.')
    elif kind == 'length':
        need(type(value) is int and 0 <= value <= maximum, 'Invalid expected output length.')
    elif kind == 'utf8_contains':
        need(isinstance(value, str) and 0 < len(value.encode()) <= maximum, 'Invalid expected text.')
    else:
        raise ValueError('Choose hex, length, utf8_contains or clock result validation.')


def validate_rule(row, settings):
    expected = {'tenant', 'component', 'sha256', 'cache', 'hal_permissions', 'validation', *RULE_LIMITS}
    need(set(row) == expected, 'Agent workload rule has missing or unknown fields.')
    need(row['cache'] in ('memory', 'disabled'), 'Unknown agent cache policy.')
    permissions = row['hal_permissions']
    need(isinstance(permissions, list) and all(isinstance(p, str) for p in permissions)
         and len(set(permissions)) == len(permissions)
         and set(permissions) <= {'crypto', 'random', 'clock', 'storage'}, 'Invalid HAL permissions.')
    maxima = {'cache_ttl_ms': 86400000, 'memory_mib': settings['workload_memory_mib'],
              'fuel': settings['workload_fuel'], 'execution_timeout_ms': settings['execution_timeout_secs'] * 1000,
              'max_output_bytes': settings['max_output_bytes'], 'worker_max_jobs': 10000}
    for key, maximum in maxima.items():
        need(type(row[key]) is int and 0 < row[key] <= maximum, f'Workload {key} exceeds host limits.')
    validate_result(row['validation'], row['max_output_bytes'])


def validate_chain(execution, agent, authorization, settings):
    tenants = identities(execution, 'execution')
    artifacts = {}
    for tenant, row in tenants.items():
        need(isinstance(row['artifacts'], list) and 1 <= len(row['artifacts']) <= 128,
             'Each tenant needs 1..128 approved artifacts.')
        names = set()
        for item in row['artifacts']:
            validate_artifact(item, settings['max_component_bytes'])
            name, sha, size = artifact_tuple(item)
            need(name not in names, 'Duplicate artifact filename for one tenant.')
            names.add(name)
            artifacts[tenant, name] = (sha, size)
        need(0 < row.get('max_inflight', min(4, settings['max_inflight'])) <= settings['max_inflight'],
             f'{tenant}: max_inflight exceeds the host setting.')
        need(row.get('storage_entries', 1024) > len(names), 'Not enough storage metadata entries.')
        need(row.get('storage_bytes', 16777216) + 8 * 1024 * 1024 <= settings['container_storage_mib'] * 1024 * 1024,
             f'{tenant}: container storage must cover its quota plus 8 MiB of metadata.')
    need(set(agent) == {'version', 'agent_sha256', 'workloads'}
         and agent.get('version') == 1 and isinstance(agent.get('agent_sha256'), str)
         and SHA.fullmatch(agent['agent_sha256']) and isinstance(agent.get('workloads'), list)
         and 1 <= len(agent['workloads']) <= 8192, 'Invalid agent policy.')
    rules, rule_ids = {}, set()
    for row in agent['workloads']:
        validate_rule(row, settings)
        key = (row['tenant'], row['component'])
        need(key in artifacts and artifacts[key][0] == row['sha256'],
             'Agent policy differs from execution artifact permissions.')
        identity = (row['tenant'], row['sha256'])
        need(identity not in rule_ids, 'Duplicate tenant/artifact digest in agent policy.')
        rule_ids.add(identity)
        rules[key] = row
    need(set(authorization) == {'version', 'audience', 'max_ttl_seconds', 'isolation', 'users'}
         and authorization.get('version') == 1 and authorization.get('isolation') == 'per-user-container'
         and isinstance(authorization.get('audience'), str) and NAME.fullmatch(authorization['audience'])
         and type(authorization.get('max_ttl_seconds')) is int and 1 <= authorization['max_ttl_seconds'] <= 300,
         'Invalid public job authorization. This launcher requires signed jobs in user containers.')
    users = authorization.get('users')
    need(isinstance(users, list) and 1 <= len(users) <= 64, 'Invalid authorization users.')
    names, keys = set(), set()
    for user in users:
        need(set(user) == {'tenant', 'public_key', 'workloads'}, 'Unknown authorization user fields.')
        tenant, public = user.get('tenant'), user.get('public_key')
        need(tenant in tenants and tenant not in names and isinstance(public, str)
             and SHA.fullmatch(public) and public not in keys, 'Invalid/duplicate authorization user or key.')
        names.add(tenant)
        keys.add(public)
        grants = user.get('workloads')
        need(isinstance(grants, list) and 1 <= len(grants) <= 128, 'Invalid workload grants.')
        seen = set()
        for grant in grants:
            need(set(grant) == {'component', 'sha256', 'artifact_bytes', 'rule_sha256'},
                 'Unknown authorization grant fields.')
            key = (tenant, grant['component'])
            need(key in rules and artifacts[key] == (grant['sha256'], grant['artifact_bytes'])
                 and grant['rule_sha256'] == rule_digest(rules[key]),
                 'Public authorization disagrees with workload bytes or rules. '
                 'Use a reviewed workload release; do not regenerate signing keys.')
            need(grant['sha256'] not in seen, 'Duplicate authorization digest.')
            seen.add(grant['sha256'])
    return tenants, rules


def execution_documents(paths):
    return tuple(document(paths[key]) for key in ('tenant_policy', 'agent_policy', 'job_authorization'))


def deployment_catalog(path):
    # Give the same missing-file diagnostic as policies, and reject duplicate
    # fields/private keys before using the management server's catalog parser.
    data = document(path)
    need(isinstance(data.get('cases'), list)
         and all(isinstance(row, dict) for row in data['cases']),
         f'Catalog needs a list of cases: {path}')
    return load_catalog(path)


def validate_catalog(cases, role, tenants, rules=()):
    if role == 'management':
        for row in tenants.values():
            allowed = row['cases']
            need(isinstance(allowed, list) and allowed
                 and all(isinstance(name, str) for name in allowed)
                 and len(allowed) == len(set(allowed)) and set(allowed) <= cases.keys(),
                 'Management cases must be a non-empty catalog subset.')
        return
    for rule in rules:
        artifact = next((item for item in tenants[rule['tenant']]['artifacts']
                         if item['component'] == rule['component']), None)
        matches = [case for case in cases.values()
                   if artifact is not None and artifact_tuple(case) == artifact_tuple(artifact)]
        need(matches, f'Catalog does not match approved workload {rule["tenant"]}/'
             f'{rule["component"]}: filename, SHA-256 and size must match the execution policy.')
        # A bounded rule permits any result within the host output limit. A
        # catalog can apply a stricter correctness test without changing it.
        if rule['validation']['kind'] != 'bounded':
            need(any(case['validation'] == rule['validation'] for case in matches),
                 f'Catalog result validation differs from the approved agent rule for '
                 f'{rule["tenant"]}/{rule["component"]}.')


def approval_command(config_path='state/deployment.json', expected=None, apply=False):
    command = ['python3', 'deployment.py']
    if str(config_path) != 'state/deployment.json':
        command += ['--config', str(config_path)]
    command += ['approve-agent']
    if expected is not None:
        command += ['--sha256', expected]
    if apply:
        command += ['--apply']
    return shlex.join(command)


def check(root, config, pin=True):
    paths = paths_for(root, config)
    settings = config['settings']
    for name, value in settings.items():
        if name != 'compile_opt_level':
            need(type(value) is int and value > 0, f'Invalid setting: {name}')
    if config['role'] == 'execution':
        need(set(settings) == set(LIMITS), 'Execution settings are incomplete or unknown.')
        need(settings['compile_opt_level'] in ('none', 'speed', 'speed-and-size'), 'Unknown compiler setting.')
        url(config['file_server'])
        execution, agent, auth = execution_documents(paths)
        tenants, rules = validate_chain(execution, agent, auth, settings)
        credentials = {token_file(paths['operator_token'])}
        for row in tenants.values():
            token = token_file(paths['tenant_policy'].parent / row['token_file'])
            need(token not in credentials, 'Execution tenant/operator tokens must be distinct.')
            credentials.add(token)
        data = read_bytes(paths['agent'], 64 * 1024 * 1024)
        need(data[:8] == b'\0asm\x0d\0\x01\0', 'agent.wasm is not a component-format Wasm file.')
        actual = digest(data)
        if pin:
            need(actual == agent['agent_sha256'],
                 f'Agent fingerprint mismatch.\n  Agent file: {paths["agent"]}\n'
                 f'  Policy file: {paths["agent_policy"]}\n'
                 f'  Approved: {agent["agent_sha256"]}\n  Current:  {actual}\n'
                 'check only reads these files; repeating it cannot update the approval. '
                 'For an intentional trusted build, run approve-agent --apply using this same '
                 'deployment configuration. It updates only agent_sha256 and rechecks the files. '
                 'Do not regenerate workload policies or signing keys for an agent-only update.')
        need(paths['binary'].is_file(), f'Build the native host first: {paths["binary"]}')
        validate_catalog(deployment_catalog(paths['catalog']), 'execution', tenants, rules.values())
        return {'role': 'execution', 'agent_sha256': actual, 'tenants': sorted(tenants),
                'approved_agent_sha256': agent['agent_sha256'],
                'agent_approval_matches': actual == agent['agent_sha256'],
                'agent_policy': str(paths['agent_policy']), 'catalog': str(paths['catalog']),
                'signed_jobs_required': True, 'isolation': 'per-user-container'}
    need(set(settings) == {'port', 'dispatchers', 'queue_size'} and settings['port'] <= 65535
         and settings['dispatchers'] <= 128 and settings['queue_size'] <= 100000, 'Invalid management settings.')
    url(config['worker_url'], origin=True)
    tenants = identities(document(paths['tenant_policy']), 'management')
    need(len(tenants) * settings['dispatchers'] <= 128, 'At most 128 total tenant dispatchers are supported.')
    cases = deployment_catalog(paths['catalog'])
    validate_catalog(cases, 'management', tenants)
    credentials = set()
    tokens = [paths['api_token'], paths['worker_token']]
    for row in tenants.values():
        tokens.extend(paths['tenant_policy'].parent / row[key] for key in ('api_token_file', 'worker_token_file'))
    for path in tokens:
        value = token_file(path)
        need(value not in credentials, 'Management tenant/operator tokens must be distinct.')
        credentials.add(value)
    return {'role': 'management', 'tenants': sorted(tenants), 'catalog': str(paths['catalog']),
            'require_signed_jobs': True}


def existing_policy(root, supplied, default, patterns, label):
    if supplied is not None or resolve(root, default).is_file():
        return supplied if supplied is not None else default
    candidates = sorted({p for pattern in patterns for p in root.glob(pattern) if p.is_file()})
    # Consider only public-policy filenames. Do not inspect clients-private keys,
    # pick the newest file, or choose a policy just because its hash happens to match.
    distinct = {digest(read_bytes(p)) for p in candidates}
    if len(distinct) == 1:
        print(f'Using existing {label}: {candidates[0]}')
        return str(candidates[0])
    choices = '\n  '.join(str(p) for p in candidates) if candidates else '(none found)'
    raise ValueError(f'Missing {default}. Select the reviewed {label} explicitly during init. '
                     f'Candidates:\n  {choices}')


def existing_catalog(root, supplied, config):
    default = root / 'state/tenant-config/workloads.json'
    # Explicit and provisioned choices are checked, never silently substituted.
    if supplied is not None or default.exists():
        return supplied if supplied is not None else str(default)
    paths = paths_for(root, config)
    tenants = identities(document(paths['tenant_policy']), config['role'])
    rules = document(paths['agent_policy'])['workloads'] if config['role'] == 'execution' else ()
    locations = list(dict.fromkeys((paths['tenant_policy'].parent / 'workloads.json',
                                   root / 'workloads.json', root / 'reviewed/workloads.json')))
    candidates, rejected = [], []
    for path in locations:
        if not path.exists():
            continue
        try:
            cases = deployment_catalog(path)
            validate_catalog(cases, config['role'], tenants, rules)
            candidates.append((path, json.dumps(cases, sort_keys=True)))
        except (OSError, ValueError, KeyError, TypeError) as error:
            rejected.append(f'{path}: {error}')
    if candidates and len({content for _, content in candidates}) == 1:
        print('Using existing catalog:', candidates[0][0])
        return str(candidates[0][0])
    if candidates:
        choices = '\n  '.join(str(path) for path, _ in candidates)
        raise ValueError('Several different catalogs match this deployment. Select one explicitly '
                         f'with init --catalog PATH. Candidates:\n  {choices}')
    searched = '\n  '.join(str(path) for path in dict.fromkeys((default, *locations)))
    reasons = '\nRejected files:\n  ' + '\n  '.join(rejected) if rejected else ''
    raise ValueError('No matching workload catalog found. Searched:\n  ' + searched + reasons +
                     '\nUse init --catalog PATH for your existing reviewed workloads.json. '
                     'No catalog, policy, token or signing key was generated.')


def init(root, args, destination):
    directory = 'state/tenant-config/'
    role = args.role
    if role == 'execution':
        need(args.file_server, 'Execution init requires --file-server URL.')
        paths = {'binary': 'dist/hal-on-demand', 'agent': 'dist/agent.wasm',
                 'tenant_policy': args.tenant_policy or directory + 'policy.json',
                 'agent_policy': existing_policy(root, args.agent_policy, directory + 'agent-policy.json',
                     ('state/tenant-config/agent-policy*.json', 'reviewed/agent-policy.json'), '--agent-policy'),
                 'job_authorization': existing_policy(root, args.job_authorization, directory + 'job-authorization.json',
                     ('state/**/execution-public/job-authorization.json', 'reviewed/job-authorization.json'), '--job-authorization'),
                 'operator_token': directory + 'operator.token',
                 'catalog': args.catalog or directory + 'workloads.json'}
        settings = {key: getattr(args, key) for key in LIMITS}
        config = dict(version=1, role=role, file_server=url(args.file_server),
                      listen=args.listen, container_image=args.container_image,
                      paths=paths, settings=settings)
    else:
        need(args.worker_url, 'Management init requires --worker-url URL.')
        policy = args.tenant_policy or directory + 'management-policy.json'
        if not args.tenant_policy and not resolve(root, policy).exists():
            candidate = resolve(root, directory + 'policy.json')
            identities(document(candidate), 'management')
            policy = directory + 'policy.json'
        config = dict(version=1, role=role, worker_url=url(args.worker_url, origin=True), bind=args.bind,
            paths={'tenant_policy': policy, 'catalog': args.catalog or directory + 'workloads.json',
                   'api_token': directory + 'api.token', 'worker_token': directory + 'worker.token'},
            settings={'port': args.port, 'dispatchers': args.dispatchers, 'queue_size': args.queue_size})
    config['paths']['catalog'] = existing_catalog(root, args.catalog, config)
    config['paths'] = {key: stored_path(root, value) for key, value in config['paths'].items()}
    report = check(root, config, pin=False)
    if destination.exists():
        need(document(destination) == config,
             f'{destination} already contains different settings. Edit that saved configuration deliberately; '
             'init does not reset it or replace credentials.')
        print('Configuration already saved:', destination)
    else:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(destination, encoded(config))
        print('Saved:', destination)
    if role == 'execution' and not report['agent_approval_matches']:
        print('Configuration saved; agent approval is still required before startup.')
        print('Policy file:', report['agent_policy'])
        print('Approved agent:', report['approved_agent_sha256'])
        print('Current agent: ', report['agent_sha256'])
        print('If this is your intended trusted build, approve exactly these bytes:')
        print(approval_command(args.config, expected=report['agent_sha256'], apply=True))
    else:
        print('Local configuration checks passed. Next: deployment.py start')


def approve_agent(root, config, apply, expected=None, config_path='state/deployment.json'):
    need(config['role'] == 'execution', 'Approve the agent on the execution VM.')
    report = check(root, config, pin=False)
    paths = paths_for(root, config)
    policy = document(paths['agent_policy'])
    if expected is not None:
        need(SHA.fullmatch(expected) and expected == report['agent_sha256'],
             'The current agent does not match the fingerprint you selected for approval. '
             'No policy was changed. Check the build/package before approving it.')
    print('Agent file: ', paths['agent'])
    print('Policy file:', paths['agent_policy'])
    print('Approved agent:', policy['agent_sha256'])
    print('Current agent: ', report['agent_sha256'])
    if policy['agent_sha256'] == report['agent_sha256']:
        print('Already matches; no changes.')
        return
    if not apply:
        print('Preview only. If this is your intended trusted build, approve these exact bytes:')
        print(approval_command(config_path, expected=report['agent_sha256'], apply=True))
        return
    policy['agent_sha256'] = report['agent_sha256']
    backup = change_files(root, {paths['agent_policy']: encoded(policy)})
    print('Approved the current agent; workload rules and signing keys are unchanged.')
    print('Previous policy backup:', backup)
    check(root, config)
    print('Local configuration checks passed after approval. Stop the old host, then start the replacement.')


def launch_command(root, config, run_id=None):
    paths = paths_for(root, config)
    run_id = run_id or uuid.uuid4().hex[:12]
    if config['role'] == 'management':
        command = [sys.executable, str(root / 'server/management.py'), '--bind', config['bind'],
                   '--worker-url', config['worker_url'], '--require-signed-jobs',
                   '--state-dir', str(root / 'state' / ('management-' + run_id))]
        for key, flag in (('tenant_policy', 'tenant-policy'), ('catalog', 'catalog'),
                          ('api_token', 'api-token-file'), ('worker_token', 'worker-token-file')):
            command += ['--' + flag, str(paths[key])]
    else:
        command = [str(paths['binary']), '--mode', 'wasm', '--transport', 'http',
                   '--listen', config['listen'], '--file-server', config['file_server'],
                   '--user-containers', '--container-image', config['container_image'],
                   '--cache-dir', '/var/tmp/hal-agent-' + run_id,
                   '--container-state-dir', '/run/hal-agent-' + run_id]
        for key, flag in (('agent', 'agent'), ('operator_token', 'token-file'),
                          ('tenant_policy', 'tenant-policy'), ('agent_policy', 'agent-policy'),
                          ('job_authorization', 'job-authorization')):
            command += ['--' + flag, str(paths[key])]
    for key, value in config['settings'].items():
        command += ['--' + key.replace('_', '-'), str(value)]
    return command


def epoch(root, config):
    need(config['role'] == 'execution', 'Read the public epoch on the execution VM.')
    # Connect locally; do not send an operator token through an environment proxy.
    listen = config['listen']
    host, port = listen.rsplit(':', 1)
    host = '127.0.0.1' if host == '0.0.0.0' else ('[::1]' if host == '[::]' else host)
    request = Request(f'http://{host}:{int(port)}/v1/stats',
                      headers={'Authorization': 'Bearer ' + token_file(paths_for(root, config)['operator_token'])})
    with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
        data = response.read(1024 * 1024 + 1)
    need(len(data) <= 1024 * 1024, 'Unexpectedly large stats response.')
    authorization = json.loads(data).get('job_authorization', {})
    value = authorization.get('epoch')
    need(authorization.get('required') is True and isinstance(value, str) and SHA.fullmatch(value),
         'The running host did not report signed-job authorization and a valid epoch.')
    print(value)


def validate_plan(plan):
    need(plan.get('version') == 1, 'Unsupported workload release.')
    no_private_keys(plan)
    case, rule, grant = (plan[key] for key in ('case', 'rule', 'grant'))
    validate_artifact(case, 64 * 1024 * 1024)
    need(NAME.fullmatch(case['name']) and case['name'] == grant['case'], 'Invalid release case name.')
    need(artifact_tuple(case) == artifact_tuple(rule | {'artifact_bytes': grant['artifact_bytes']})
         == artifact_tuple(grant), 'Release artifact fingerprints disagree.')
    need(plan['tenant'] == rule['tenant'] and grant['rule_sha256'] == rule_digest(rule)
         and grant['cache_allowed'] == (rule['cache'] == 'memory')
         and case['validation'] == rule['validation'], 'Release workload rules disagree.')
    need(isinstance(plan['public_key'], str) and SHA.fullmatch(plan['public_key']), 'Invalid public user key.')
    validate_result(case['validation'], rule['max_output_bytes'], catalog=True)


def append_execution(execution, agent, auth, plan):
    execution, agent, auth = copy.deepcopy((execution, agent, auth))
    tenants = identities(execution, 'execution')
    identity = plan['tenant']
    need(identity in tenants, 'Release user is not configured on this execution VM.')
    user = next((u for u in auth['users'] if u['tenant'] == identity), None)
    need(user is not None and user['public_key'] == plan['public_key'], 'Release does not match the existing user key.')
    for key in ('audience', 'isolation', 'max_ttl_seconds'):
        need(auth[key] == plan[key], 'Release belongs to a different authorization deployment.')
    name, sha, size = artifact_tuple(plan['case'])
    need(not any(a['component'] == name for a in tenants[identity]['artifacts']),
         'Artifact name already exists. Use a new versioned .wasm filename.')
    need(not any(r['tenant'] == identity and r['sha256'] == sha for r in agent['workloads']),
         'These exact Wasm bytes are already approved for this user; use their existing case.')
    tenants[identity]['artifacts'].append(dict(component=name, sha256=sha, artifact_bytes=size))
    agent['workloads'].append(copy.deepcopy(plan['rule']))
    user['workloads'].append({key: plan['grant'][key] for key in
                            ('component', 'sha256', 'artifact_bytes', 'rule_sha256')})
    return execution, agent, auth


def appended_catalog(catalog, case):
    need(not any(c['name'] == case['name'] or artifact_tuple(c)[0] == artifact_tuple(case)[0]
                 for c in catalog['cases']), 'Case or artifact filename already exists; use a new versioned name.')
    result = copy.deepcopy(catalog)
    result['cases'].append(copy.deepcopy(case))
    return result


def prepare_workload(root, config, spec_path, output):
    need(config['role'] == 'execution', 'Prepare the public workload release using the execution configuration.')
    check(root, config)
    paths = paths_for(root, config)
    spec_path = resolve(root, spec_path)
    spec = document(spec_path)
    need(not set(spec) - {'tenant', 'case', 'wasm', 'template', 'validation', 'hal_permissions', 'limits'},
         'Unknown workload specification field.')
    need(all(k in spec for k in ('tenant', 'case', 'wasm', 'template', 'validation')),
         'Workload spec requires tenant, case, wasm, template and validation.')
    execution, agent, auth = execution_documents(paths)
    cases = load_catalog(paths['catalog'])
    need(spec['template'] in cases, 'Template must name an existing approved case.')
    template = cases[spec['template']]
    rule = next((r for r in agent['workloads'] if r['tenant'] == spec['tenant']
                 and r['component'] == template['artifact'] and r['sha256'] == template['sha256']), None)
    need(rule is not None, 'This user has no agent rule for the selected template.')
    rule = copy.deepcopy(rule)
    wasm_path = resolve(spec_path.parent, spec['wasm'])
    wasm = read_bytes(wasm_path, config['settings']['max_component_bytes'])
    need(wasm[:8] == b'\0asm\x0d\0\x01\0', 'Build a Wasm component, not a core module, before registering it.')
    filename, sha = wasm_path.name, digest(wasm)
    rule.update(component=filename, sha256=sha, validation=spec['validation'])
    if 'hal_permissions' in spec:
        rule['hal_permissions'] = spec['hal_permissions']
    limits = spec.get('limits', {})
    need(isinstance(limits, dict) and not set(limits) - set(RULE_LIMITS), 'Unknown workload limit.')
    rule.update(limits)
    validate_rule(rule, config['settings'])
    user = next((u for u in auth['users'] if u['tenant'] == spec['tenant']), None)
    need(user is not None, 'Register the user signing key before adding workloads.')
    case = dict(name=spec['case'], artifact=filename, sha256=sha, artifact_bytes=len(wasm),
                validation=spec['validation'])
    grant = dict(component=filename, sha256=sha, artifact_bytes=len(wasm), rule_sha256=rule_digest(rule),
                 case=spec['case'], cache_allowed=rule['cache'] == 'memory')
    plan = dict(version=1, tenant=spec['tenant'], public_key=user['public_key'],
                case=case, rule=rule, grant=grant,
                base_sha256={key: digest(read_bytes(paths[key])) for key in
                             ('tenant_policy', 'agent_policy', 'job_authorization', 'catalog')},
                **{key: auth[key] for key in ('audience', 'isolation', 'max_ttl_seconds')})
    validate_plan(plan)
    candidate = append_execution(execution, agent, auth, plan)
    validate_chain(*candidate, config['settings'])
    appended_catalog(document(paths['catalog']), case)
    output = resolve(root, output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / 'file-server').mkdir(mode=0o700)
    write_new(output / 'plan.json', encoded(plan))
    write_new(output / 'file-server' / filename, wasm)
    print('Prepared public release:', output)
    print(json.dumps({'case': case, 'tenant': spec['tenant'], 'hal_permissions': rule['hal_permissions']}, indent=2))
    print('Review plan.json. Upload file-server/' + filename + ' to the artifact server.')
    print('Apply the plan separately on execution, management, and the signing client. No keys were generated.')


def apply_workload(root, config, plan_path, apply):
    check(root, config)
    plan = document(resolve(root, plan_path))
    validate_plan(plan)
    paths = paths_for(root, config)
    current_catalog = document(paths['catalog'])
    if plan['case'] in current_catalog['cases']:
        if config['role'] == 'management':
            current = identities(document(paths['tenant_policy']), 'management')
            installed = (plan['tenant'] in current and plan['case']['name'] in current[plan['tenant']]['cases'])
        else:
            execution, agent, auth = execution_documents(paths)
            tenants = identities(execution, 'execution')
            user = next((u for u in auth['users'] if u['tenant'] == plan['tenant']), None)
            grant = {key: plan['grant'][key] for key in ('component', 'sha256', 'artifact_bytes', 'rule_sha256')}
            installed = (plan['tenant'] in tenants and user is not None
                and user['public_key'] == plan['public_key'] and grant in user['workloads']
                and plan['rule'] in agent['workloads']
                and any(artifact_tuple(a) == artifact_tuple(plan['case']) for a in tenants[plan['tenant']]['artifacts'])
                and all(auth[key] == plan[key] for key in ('audience', 'isolation', 'max_ttl_seconds')))
        if installed:
            print('This exact workload release is already applied; no changes.')
            return
    catalog = appended_catalog(current_catalog, plan['case'])
    if config['role'] == 'execution':
        for key, expected in plan['base_sha256'].items():
            need(key in ('tenant_policy', 'agent_policy', 'job_authorization', 'catalog')
                 and digest(read_bytes(paths[key])) == expected,
                 'Execution configuration changed since this release was prepared. Prepare it again against current policies.')
        need(set(plan['base_sha256']) == {'tenant_policy', 'agent_policy', 'job_authorization', 'catalog'},
             'Release is missing base fingerprints.')
        candidate = append_execution(*execution_documents(paths), plan)
        validate_chain(*candidate, config['settings'])
        changes = {paths[key]: encoded(value) for key, value in zip(
            ('tenant_policy', 'agent_policy', 'job_authorization'), candidate)}
    else:
        policy = document(paths['tenant_policy'])
        tenants = identities(policy, 'management')
        need(plan['tenant'] in tenants, 'Release user is not configured on management.')
        tenants[plan['tenant']]['cases'].append(plan['case']['name'])
        changes = {paths['tenant_policy']: encoded(policy)}
    changes[paths['catalog']] = encoded(catalog)
    print('Add case', plan['case']['name'], 'for', plan['tenant'], 'on', config['role'])
    if not apply:
        print('Preview only. Stop this service, then repeat with --apply after reviewing the release.')
        return
    backup = change_files(root, changes)
    print('Applied. Previous files:', backup)
    print('Restart with deployment.py start. Execution restart creates a new public authorization epoch.')


def update_client(root, plan_path, signing_path, apply):
    # The existing Signer checks file ownership/mode and that public/private keys agree.
    from job_signing import Signer
    signing_path = resolve(root, signing_path)
    signer = Signer(signing_path, '0' * 64)
    plan = document(resolve(root, plan_path))
    validate_plan(plan)
    config = signer.config
    for key in ('tenant', 'public_key', 'audience', 'isolation', 'max_ttl_seconds'):
        need(config[key] == plan[key], 'Release differs from this client identity or deployment; no key change is allowed.')
    if plan['grant'] in config['workloads']:
        print('This exact client approval is already installed; no changes.')
        return
    need(not any(r['case'] == plan['grant']['case'] or r['component'] == plan['grant']['component']
                 or r['sha256'] == plan['grant']['sha256'] for r in config['workloads']),
         'This case, filename, or artifact is already in the client approval list.')
    config['workloads'].append(copy.deepcopy(plan['grant']))
    print('Approve case', plan['case']['name'], 'for signing client', plan['tenant'])
    if not apply:
        print('Preview only. Review the operator-provided plan, then repeat with --apply.')
        return
    backup = change_files(root, {signing_path: encoded(config)})
    print('Updated client approvals; the signing key is unchanged.')
    print('Private backup (keep on this client):', backup)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', default='state/deployment.json', help='saved config, relative to this checkout')
    sub = p.add_subparsers(dest='command', required=True)
    i = sub.add_parser('init', help='save existing paths/settings once; never create credentials')
    i.add_argument('--role', choices=('execution', 'management'), required=True)
    i.add_argument('--file-server')
    i.add_argument('--worker-url')
    for flag in ('tenant-policy', 'agent-policy', 'job-authorization', 'catalog'):
        i.add_argument('--' + flag)
    i.add_argument('--listen', default='0.0.0.0:9100')
    i.add_argument('--bind', default='0.0.0.0')
    i.add_argument('--port', type=int, default=9000)
    i.add_argument('--dispatchers', type=int, default=4)
    i.add_argument('--queue-size', type=int, default=256)
    i.add_argument('--container-image', default='hal-user-worker:local')
    for key, value in LIMITS.items():
        i.add_argument('--' + key.replace('_', '-'), type=type(value), default=value)
    sub.add_parser('check', help='check files, schemas, fingerprints, tokens and public authorization')
    a = sub.add_parser('approve-agent', help='review/approve only the current agent binary fingerprint')
    a.add_argument('--apply', action='store_true')
    a.add_argument('--sha256', help='refuse approval unless the current agent matches this reviewed fingerprint')
    s = sub.add_parser('start', help='validate and start the saved signed deployment in the foreground')
    s.add_argument('--print-command', action='store_true')
    sub.add_parser('epoch', help='print the running execution host public authorization epoch')
    w = sub.add_parser('prepare-workload', help='prepare a public release for a new workload; preserve keys')
    w.add_argument('--spec', required=True)
    w.add_argument('--output', required=True)
    a = sub.add_parser('apply-workload', help='apply a reviewed workload release on this VM')
    a.add_argument('--plan', required=True)
    a.add_argument('--apply', action='store_true')
    c = sub.add_parser('update-client', help='append a reviewed grant to this client without rotating its key')
    c.add_argument('--plan', required=True)
    c.add_argument('--signing-config', required=True)
    c.add_argument('--apply', action='store_true')
    return p


def main(argv=None, root=ROOT):
    args = parser().parse_args(argv)
    root = Path(root).absolute()
    path = resolve(root, args.config)
    try:
        command = None
        with operator_lock(root):
            if args.command == 'init':
                init(root, args, path)
            elif args.command == 'update-client':
                update_client(root, args.plan, args.signing_config, args.apply)
            else:
                config = load_config(root, path)
                if args.command == 'check':
                    print(json.dumps(check(root, config), indent=2))
                    print('Local configuration checks passed. Network/Docker/TDX execution must still be tested on the VMs.')
                elif args.command == 'approve-agent':
                    approve_agent(root, config, args.apply, args.sha256, args.config)
                elif args.command == 'epoch':
                    epoch(root, config)
                elif args.command == 'prepare-workload':
                    prepare_workload(root, config, args.spec, args.output)
                elif args.command == 'apply-workload':
                    apply_workload(root, config, args.plan, args.apply)
                elif args.command == 'start':
                    check(root, config)
                    command = launch_command(root, config)
                    print(shlex.join(command), flush=True)
                    if args.print_command:
                        command = None
                    elif config['role'] == 'execution':
                        need(sys.platform == 'linux' and os.geteuid() == 0,
                             'Run the execution host on Linux with sudo python3 deployment.py start.')
        if command is not None:
            os.chdir(root)
            os.execv(command[0], command)
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
