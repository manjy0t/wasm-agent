"""The authority chooses permissions; user requests only choose catalog names."""
import time
from job_signing import rule_digest
from .common import DOCUMENT_DOMAIN, NAME, SHA, require, verify
from .lifetimes import ENROLLMENT_SECONDS

LIMITS = dict(cache_bytes=268435456, compiled_cache_entries=16, storage_bytes=16777216,
              storage_entries=1024, max_inflight=4)
SETTINGS = dict(downloads=4, compilers=2, compiler_threads=2, executions=4, max_inflight=16,
                compile_opt_level='speed', execution_timeout_secs=5, max_output_bytes=4096,
                workload_memory_mib=64, workload_fuel=1000000000, max_component_bytes=16777216,
                container_cpus=2, container_memory_mib=1024, container_pids=128, container_storage_mib=64)
RULE_FIELDS = {'component', 'cache', 'cache_ttl_ms', 'hal_permissions', 'memory_mib', 'fuel',
               'execution_timeout_ms', 'max_output_bytes', 'worker_max_jobs', 'validation'}


def workload(row):
    require(isinstance(row, dict) and set(row) == {'name', 'component', 'sha256', 'artifact_bytes', 'rule'},
            'A workload needs name, component, sha256, artifact_bytes and rule')
    require(isinstance(row['name'], str) and NAME.fullmatch(row['name']), 'Invalid workload name')
    require(isinstance(row['sha256'], str) and SHA.fullmatch(row['sha256']), 'Invalid artifact digest')
    require(row['component'] == row['sha256'] + '.wasm', 'Artifacts must have immutable SHA-256 filenames')
    require(type(row['artifact_bytes']) is int and 8 <= row['artifact_bytes'] <= SETTINGS['max_component_bytes'],
            'Invalid artifact size')
    rule = row['rule']
    require(isinstance(rule, dict) and set(rule) in (RULE_FIELDS, RULE_FIELDS | {'access_profile'}) and rule['component'] == row['component'],
            'Invalid workload rule')
    require(rule['cache'] in ('memory', 'disabled'), 'Unsupported cache rule')
    for field, maximum in dict(cache_ttl_ms=86400000, memory_mib=64, fuel=1000000000,
                               execution_timeout_ms=5000, max_output_bytes=4096, worker_max_jobs=10000).items():
        require(type(rule[field]) is int and 1 <= rule[field] <= maximum, 'Invalid limit: ' + field)
    permissions = rule['hal_permissions']
    require(isinstance(permissions, list) and all(isinstance(p, str) for p in permissions)
            and len(permissions) == len(set(permissions)) and set(permissions) <= {'crypto', 'random', 'clock', 'storage'},
            'Invalid HAL permissions')
    if 'access_profile' in rule:
        from .access_profiles import validate
        validate(rule['access_profile'], row['sha256'], permissions)
    validation = rule['validation']
    require(isinstance(validation, dict), 'Invalid result rule')
    kind = validation.get('kind')
    if kind in ('bounded', 'clock'):
        require(set(validation) == {'kind'}, 'Unexpected validation fields')
    else:
        require(set(validation) == {'kind', 'value'}, 'Unexpected validation fields')
        value = validation['value']
        if kind == 'hex':
            try:
                data = bytes.fromhex(value)
            except (ValueError, TypeError):
                raise ValueError('Expected lowercase hex output')
            require(data.hex() == value and len(data) <= rule['max_output_bytes'], 'Invalid expected output')
        elif kind == 'length':
            require(type(value) is int and 0 <= value <= rule['max_output_bytes'], 'Invalid expected length')
        elif kind == 'utf8_contains':
            require(isinstance(value, str) and 0 < len(value.encode()) <= rule['max_output_bytes'], 'Invalid expected text')
        else:
            require(False, 'Unsupported validation kind')
    return row


def certificate(envelope, config):
    doc = verify(config['trust']['identity_public_key'], DOCUMENT_DOMAIN, envelope)
    require(set(doc) == {'version', 'kind', 'issuer', 'audience', 'subject', 'public_key', 'revision',
                        'issued_unix', 'expires_unix', 'limits', 'workloads'}, 'Invalid enrollment document')
    require(doc['version'] == 1 and doc['kind'] == 'enrollment' and doc['issuer'] == config['trust']['issuer']
            and doc['audience'] == config['trust']['execution_audience'], 'Wrong enrollment authority or destination', 403)
    now = int(time.time())
    require(type(doc['issued_unix']) is int and type(doc['expires_unix']) is int and doc['issued_unix'] <= now + 5
            and now < doc['expires_unix'] and 0 < doc['expires_unix'] - doc['issued_unix'] <= ENROLLMENT_SECONDS,
            'Enrollment document expired; renew it through identity', 401, 'certificate_expired')
    require(isinstance(doc['subject'], str) and NAME.fullmatch(doc['subject'])
            and isinstance(doc['public_key'], str) and SHA.fullmatch(doc['public_key'])
            and type(doc['revision']) is int and doc['revision'] >= 1, 'Invalid enrollment identity')
    require(isinstance(doc['limits'], dict) and set(doc['limits']) == set(LIMITS), 'Invalid tenant limits')
    for field, maximum in LIMITS.items():
        require(type(doc['limits'][field]) is int and 1 <= doc['limits'][field] <= maximum, 'Tenant limit exceeds local ceiling')
    require(isinstance(doc['workloads'], list) and len(doc['workloads']) <= 128, 'Too many approved workloads')
    seen = set()
    for row in doc['workloads']:
        workload(row)
        require(row['name'] not in seen, 'Duplicate workload')
        seen.add(row['name'])
    require(len({w['sha256'] for w in doc['workloads']}) == len(doc['workloads']), 'Duplicate artifact')
    return doc


def signed_job(doc, job, audience, isolation, epoch=None):
    """Check before provisioning or forwarding. Broker/helper/worker repeat these checks."""
    from job_signing import DOMAIN
    require(isinstance(job, dict) and set(job) == {'protocol', 'job_id', 'component', 'sha256',
                                                 'artifact_bytes', 'cache', 'job_ticket'}, 'Invalid job fields')
    claims = verify(doc['public_key'], DOMAIN, job['job_ticket'], maximum=4096)
    fields = {'version', 'tenant', 'audience', 'epoch', 'job_id', 'nonce', 'operation', 'component', 'sha256',
              'artifact_bytes', 'cache', 'rule_sha256', 'isolation', 'input', 'issued_unix', 'expires_unix'}
    require(set(claims) == fields and claims['version'] == 1 and job['protocol'] == 1, 'Invalid job ticket')
    approved = next((w for w in doc['workloads'] if w['component'] == job['component']), None)
    require(approved is not None, 'Workload not approved', 403)
    require(claims['tenant'] == doc['subject'] and claims['audience'] == audience
            and claims['isolation'] == isolation and claims['input'] == 'none' and claims['operation'] == 'run',
            'Ticket identity or destination mismatch', 403)
    for field in ('component', 'sha256', 'artifact_bytes'):
        require(claims[field] == job[field] == approved[field], 'Job differs from approved artifact', 403)
    require(claims['job_id'] == job['job_id'] and isinstance(job['job_id'], str)
            and 1 <= len(job['job_id']) <= 100 and all(c.isalnum() or c in '-_' for c in job['job_id']), 'Invalid job ID')
    require(claims['rule_sha256'] == rule_digest(approved['rule']), 'Job policy changed', 403)
    require(claims['cache'] == job['cache'] and job['cache'] in ('reuse', 'bypass')
            and (job['cache'] != 'reuse' or approved['rule']['cache'] == 'memory'), 'Cache permission rejected', 403)
    require(isinstance(claims['epoch'], str) and SHA.fullmatch(claims['epoch'])
            and (epoch is None or epoch == claims['epoch']), 'Execution session changed; obtain a new session', 409, 'epoch_changed')
    require(isinstance(claims['nonce'], str) and SHA.fullmatch(claims['nonce']), 'Invalid job nonce')
    now = int(time.time())
    require(type(claims['issued_unix']) is int and type(claims['expires_unix']) is int
            and claims['issued_unix'] <= now + 5 and now < claims['expires_unix']
            and 0 < claims['expires_unix'] - claims['issued_unix'] <= 120, 'Job ticket expired', 401)
    return claims, approved
