"""Exclusive benchmark admission, provenance and immutable output verification."""
import copy
from pathlib import Path
import secrets
import threading
import time
import uuid

from .common import (Error, atomic_json, canonical, digest, parse, require, verify_request)
from .native_config import service_digest

SCHEMA = 'hal-benchmark-v2'


class BenchmarkGate:
    """One experiment per management service, across users and HTTP clients.

    The durable lease survives a restart; the boot identity changes so an in-flight
    experiment cannot silently continue across that restart. No job is retried.
    """
    def __init__(self, app):
        self.app, self.lock, self.active = app, threading.RLock(), 0
        self.instance = secrets.token_hex(32)
        self.build = service_digest()

    def __getattr__(self, name):
        return getattr(self.app, name)

    def lease(self):
        value = self.app.db.get('benchmark', 'lease')
        return value if value and value['expires_unix'] > time.time() else None

    def control(self, body):
        req = verify_request(body, self.app.config['trust']['management_audience'], 'benchmark', self.app.db)
        data = req['body']
        require(set(data) <= {'document', 'action', 'experiment_id', 'token'}, 'Invalid benchmark control')
        doc = self.app.check_document(data.get('document'))
        require(doc['subject'] == req['subject'] and doc['public_key'] == req['public_key'], 'Benchmark owner mismatch', 403)
        experiment = data.get('experiment_id')
        require(isinstance(experiment, str) and str(uuid.UUID(experiment)) == experiment, 'Invalid experiment ID')
        with self.lock:
            lease = self.lease()
            if data['action'] == 'acquire':
                require(lease is None and self.active == 0, 'Another experiment or request is active; use an idle deployment', 409, 'benchmark_busy')
                require(self.app.db.get('benchmark-used', experiment) is None, 'Experiment ID already used; start a new experiment', 409)
                token = secrets.token_hex(32)
                lease = dict(experiment_id=experiment, tenant=doc['subject'], user_key=doc['public_key'],
                             token_hash=digest(token.encode()), expires_unix=int(time.time()) + 21600)
                self.app.db.put('benchmark-used', experiment, dict(created_unix=int(time.time())))
                self.app.db.put('benchmark', 'lease', lease)
                return dict(experiment_id=experiment, token=token, expires_unix=lease['expires_unix'],
                            management_instance=self.instance, management_source_sha256=self.build)
            require(data['action'] == 'release', 'Invalid benchmark operation')
            # A signed owner may release its interrupted experiment without the
            # secret token. This never authorizes submitting more jobs to it.
            require(lease and lease['experiment_id'] == experiment and lease['tenant'] == doc['subject']
                    and lease['user_key'] == doc['public_key'] and self.active == 0,
                    'Benchmark lease is not idle or does not belong to this user', 409)
            self.app.db.put('benchmark', 'lease', dict(lease, expires_unix=0))
            return dict(released=experiment)

    def handle(self, method, path, body):
        if method == 'GET' and path == '/v1/capabilities':
            result = self.app.handle(method, path, body)
            return dict(result, benchmark_protocol=SCHEMA)
        if method == 'POST' and path == '/v1/benchmark':
            return self.control(body)
        guarded = method == 'POST' and (path in ('/v1/run', '/v1/session', '/v1/approve') or path.startswith('/v2/agents/'))
        if not guarded:
            return self.app.handle(method, path, body)
        claim = None
        if isinstance(body, dict) and set(body) == {'benchmark', 'request'}:
            claim, body = body['benchmark'], body['request']
        with self.lock:
            lease = self.lease()
            if lease:
                require(isinstance(claim, dict) and claim.get('experiment_id') == lease['experiment_id']
                        and isinstance(claim.get('token'), str) and digest(claim['token'].encode()) == lease['token_hash'],
                        'Deployment reserved for a benchmark; competing requests are blocked', 409, 'benchmark_busy')
                if path == '/v1/run':
                    doc = parse(body['document']['payload'])
                    require(doc.get('subject') == lease['tenant'] and doc.get('public_key') == lease['user_key'],
                            'Benchmark workload owner mismatch', 403)
                elif path != '/v1/session':
                    raise Error('Policy and deployment changes are blocked during a benchmark', 409, 'benchmark_busy')
            else:
                require(claim is None, 'Benchmark lease expired or was released; stop this experiment', 409, 'benchmark_expired')
            self.active += 1
        try:
            result = self.app.handle(method, path, body)
            if claim:
                result['benchmark_service'] = dict(experiment_id=lease['experiment_id'], management_instance=self.instance,
                                                  management_source_sha256=self.build)
            return result
        finally:
            with self.lock:
                self.active -= 1


def fingerprint(client, cases, session):
    """Stable fields only. Expiring credentials and epochs may refresh, builds may not."""
    from .policy import certificate
    doc = certificate(client.document, client.config)
    rows = {w['name']: w for w in doc['workloads']}
    require(len(cases) == len(set(cases)) and set(cases) <= set(rows), 'Choose unique approved workloads')
    architecture = session.get('execution_architecture')
    require(architecture in ('hal-managed-agent-v2', 'hal-native-audited-v1'), 'Benchmark requires an explicit audited execution profile')
    require(isinstance(session.get('build'), dict) and session['build'].get('host_sha256')
            and session['build'].get('service_sha256'), 'Server lacks benchmark build provenance; update both services')
    identity = session.get('agent_identity') or session.get('native_identity')
    require(isinstance(identity, dict) and identity.get('vm_id') and identity.get('public_key'), 'Missing execution identity')
    require(session.get('benchmark_service'), 'Missing exclusive benchmark lease identity')
    return dict(schema=SCHEMA, execution_architecture=architecture, mode=session['mode'], isolation=session['isolation'],
        audit_log=session.get('audit_log'), identity=copy.deepcopy(identity), build=copy.deepcopy(session['build']),
        management=copy.deepcopy(session['benchmark_service']), settings=copy.deepcopy(session.get('settings', {})),
        mode_selection=copy.deepcopy(session.get('mode_selection')),
        workload_configuration=copy.deepcopy(session.get('workload_configuration', {})),
        agent_sha256=session.get('agent_sha256'), tenant=doc['subject'], user_key=doc['public_key'],
        revision=doc['revision'], limits=copy.deepcopy(doc['limits']),
        workloads=[copy.deepcopy(rows[name]) for name in cases], endpoints=copy.deepcopy(client.trust['endpoints']))


class Experiment:
    def __init__(self, client, cases, mode, isolation, output):
        self.client, self.cases, self.mode, self.isolation = client, cases, mode, isolation
        self.output = Path(output)
        self.id = str(uuid.uuid4())
        self.pin, self.job_ids, self.batches, self.runtime = None, set(), [], None
        self.lease = None

    def __enter__(self):
        initial = dict(schema=SCHEMA, experiment_id=self.id, mode=self.mode, isolation=self.isolation,
                       cases=self.cases, state='starting', batches=[])
        atomic_json(self.output / 'experiment.json', initial, exclusive=True)
        try:
            self.client.renew()
            caps = self.client.call('management', '/v1/capabilities')
            require(caps.get('benchmark_protocol') == SCHEMA, 'Update management before benchmarking; exclusive admission is required')
            self.lease = self.client.call('management', '/v1/benchmark', self.client.signed('management', 'benchmark',
                dict(document=self.client.document, action='acquire', experiment_id=self.id)))
            self.client.benchmark_lease = self.lease
        except Exception as exc:
            atomic_json(self.output / 'experiment.json', dict(initial, state='failed', error=str(exc)))
            raise
        return self

    def session(self, session):
        require(session['mode'] == self.mode and session['isolation'] == self.isolation, 'Wrong benchmark execution mode/isolation')
        pin = fingerprint(self.client, self.cases, session)
        if self.pin is None:
            self.pin = pin
        require(pin == self.pin, 'Benchmark identity, build, workload or policy changed; results must not be combined', 409, 'benchmark_contamination')
        return digest(canonical(self.pin).encode())

    def check_row(self, row, cache):
        job_id = row.get('job_id')
        if job_id:
            require(job_id not in self.job_ids, 'Duplicate job ID in experiment', 409, 'benchmark_contamination')
            self.job_ids.add(job_id)
        if row.get('status') != 'completed':
            return
        require(job_id and row.get('client_result_validation') == 'passed', 'Completion lacks validated job identity', 409, 'benchmark_contamination')
        expected_service = self.pin['management']
        require(row.get('benchmark_service') == expected_service, 'Result belongs to a different management run', 409, 'benchmark_contamination')
        require(row.get('mode_selection') == self.pin.get('mode_selection'),
                'Execution mode changed during experiment', 409, 'benchmark_contamination')
        result = row['response']['agent']
        require(result.get('execution_mode') == self.mode and result.get('cache_policy') == cache
                and result.get('cache_status') in (('bypass',) if cache == 'bypass' else ('hit', 'miss', 'shared'))
                and result.get('audit_collected') is True
                and result.get('configuration', {}).get('workload_isolation') == self.isolation,
                'Result execution/audit/cache profile mismatch', 409, 'benchmark_contamination')
        if self.mode == 'native':
            require(result.get('build') == self.pin['build'], 'Native build changed during experiment', 409, 'benchmark_contamination')
        require(result.get('host_sha256') == self.pin['build']['host_sha256'],
                'Workload host binary differs from the session build', 409, 'benchmark_contamination')
        runtime = dict(configuration=result.get('configuration'), tenant_limits=result.get('tenant_limits'),
                       host_sha256=result.get('host_sha256'))
        if self.runtime is None:
            self.runtime = copy.deepcopy(runtime)
        require(runtime == self.runtime, 'Runtime limits or configuration changed during experiment', 409, 'benchmark_contamination')

    def __exit__(self, kind, error, tb):
        release_error = None
        try:
            if self.lease:
                self.client.call('management', '/v1/benchmark', self.client.signed('management', 'benchmark',
                    dict(document=self.client.document, action='release', experiment_id=self.id)))
        except Exception as exc:
            release_error = str(exc)
        finally:
            self.client.benchmark_lease = None
            atomic_json(self.output / 'experiment.json', dict(schema=SCHEMA, experiment_id=self.id, mode=self.mode,
                isolation=self.isolation, cases=self.cases, fingerprint=self.pin, runtime_configuration=self.runtime, batches=self.batches,
                state='failed' if error or release_error or not self.batches or any(not b['valid_for_comparison'] for b in self.batches) else 'complete',
                error=str(error) if error else None,
                lease_release_error=release_error))
        if release_error and error is None:
            raise Error('Benchmark finished but lease release failed; keep this run separate: ' + release_error, 503)


def seal_batch(output, metadata):
    files = {name: digest((Path(output) / name).read_bytes()) for name in ('config.json', 'jobs.jsonl', 'summary.json')}
    atomic_json(Path(output) / 'integrity.json', dict(schema=SCHEMA, **metadata, files=files), exclusive=True)


def verify_batch(output):
    """Validate saved evidence before it is used in a comparison. No data is modified."""
    output = Path(output)
    seal = parse((output / 'integrity.json').read_text())
    require(seal.get('schema') == SCHEMA and set(seal.get('files', {})) == {'config.json', 'jobs.jsonl', 'summary.json'}, 'Invalid batch seal')
    for name, expected in seal['files'].items():
        require(digest((output / name).read_bytes()) == expected, 'Benchmark file changed: ' + name, 409, 'benchmark_contamination')
    config, summary = [parse((output / name).read_text()) for name in ('config.json', 'summary.json')]
    require(seal.get('phase') == 'measured', 'Startup/warmup records are not measured benchmark batches')
    require(digest(canonical(config.get('fingerprint')).encode()) == seal.get('profile_sha256'), 'Benchmark fingerprint mismatch')
    rows = [parse(line) for line in (output / 'jobs.jsonl').read_text().splitlines()]
    for value in [config, summary, *rows]:
        require(all(value.get(k) == seal[k] for k in ('experiment_id', 'batch_id', 'phase', 'profile_sha256')),
                'Mixed experiment/batch records', 409, 'benchmark_contamination')
    ids = [r['job_id'] for r in rows if r.get('job_id')]
    require(len(ids) == len(set(ids)) and len(rows) == summary['requested'] - summary['not_submitted'], 'Duplicate or missing benchmark jobs')
    require(len({r['trial_index'] for r in rows}) == len(rows)
            and {r['trial_index'] for r in rows} == set(range(len(rows))), 'Invalid trial indices')
    require(summary['completed'] == sum(r['status'] == 'completed' for r in rows), 'Benchmark count mismatch')
    require(summary['failed_or_unknown'] == summary['requested'] - summary['completed'], 'Invalid failure count')
    require(all(r.get('client_result_validation') == 'passed' for r in rows if r['status'] == 'completed'),
            'Missing client output validation')
    for row in rows:
        if row['status'] == 'completed':
            result = row['response']['agent']
            require(row.get('mode_selection') == config['fingerprint'].get('mode_selection'), 'Mixed execution mode selections')
            require(dict(configuration=result.get('configuration'), tenant_limits=result.get('tenant_limits'),
                         host_sha256=result.get('host_sha256')) == config['runtime_configuration'], 'Mixed runtime configuration')
    require(summary['batch_wall_ms'] > 0 and abs(summary['completed_jobs_per_second'] -
            summary['completed'] * 1000 / summary['batch_wall_ms']) < 1e-9, 'Invalid throughput denominator')
    require(summary.get('contamination_detected') is False and summary.get('valid_for_comparison') is True,
            'Batch is failed, incomplete or contaminated; keep it as failure evidence', 409)
    return dict(**seal, verified=True, completed=summary['completed'])
