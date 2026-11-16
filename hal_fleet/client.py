import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import json
from pathlib import Path
import secrets
import statistics
import sys
import time
import threading
import uuid
from job_signing import DOMAIN, rule_digest
from .common import (DOCUMENT_DOMAIN, Error, Transport, atomic_json, digest, key_from_hex,
                     milliseconds, public, read_private, request, require, sign, verify)
from .policy import certificate
from .local_files import resolve_ca_file

# The broker's whole-job timeout is 120 seconds. Leave time for transport and
# audited completion; these margins never extend the approved attestation lease.
SESSION_JOB_RESERVE_SECONDS = 150
SESSION_MINIMUM_VALIDITY_SECONDS = 180


def session_needs_refresh(session):
    expires = session.get('expires_unix')
    return expires is not None and expires <= time.time() + SESSION_JOB_RESERVE_SECONDS


class Client:
    def __init__(self, path):
        self.path = Path(path)
        self.config = read_private(path)
        self.key = key_from_hex(self.config['private_key'])
        if self.config.get('ca_file'):
            self.config['ca_file'] = resolve_ca_file(path, self.config['ca_file'])
        self.transport = Transport(ca_file=self.config.get('ca_file'))
        self.trust = self.config['trust']
        self.document = self.config.get('document')
        self.session = None
        self.renew_lock = threading.Lock()

    def signed(self, role, operation, body):
        audience = self.trust['issuer'] if role == 'identity' else self.trust[role + '_audience']
        return request(self.key, audience, operation, self.config['user'], body)

    def call(self, role, path, body=None):
        lease = getattr(self, 'benchmark_lease', None)
        if lease and role == 'management' and path in ('/v1/session', '/v1/run'):
            body = dict(benchmark={k: lease[k] for k in ('experiment_id', 'token')}, request=body)
        return self.transport.call(self.trust['endpoints'][role], path, body)

    def save_document(self, envelope):
        doc = certificate(envelope, self.config)
        require(doc['subject'] == self.config['user'] and doc['public_key'] == public(self.key), 'Enrollment key mismatch')
        self.document = self.config['document'] = envelope
        atomic_json(self.path, self.config)
        return doc

    def register(self):
        result = self.call('identity', '/v1/register', self.signed('identity', 'register', {}))
        doc = self.save_document(result['document'])
        enrolled = self.enroll()
        return dict(user=doc['subject'], registered=True, enrollment=enrolled)

    def renew(self):
        result = self.call('identity', '/v1/renew', self.signed('identity', 'renew', {}))
        self.save_document(result['document'])
        return self.enroll()

    def enroll(self):
        return self.call('execution', '/v1/enroll', self.signed('execution', 'enroll', {'document': self.document}))

    def approve(self, names):
        result = self.call('management', '/v1/approve', self.signed('management', 'approve', {'workloads': names}))
        doc = self.save_document(result['document'])
        enrolled = self.enroll()
        return dict(approved=[w['name'] for w in doc['workloads']], enrollment=enrolled)

    def open_session(self):
        self.renew()  # Also recovers a stale local revision; no copied epoch/token files.
        try:
            capabilities = self.call('management', '/v1/capabilities')
        except Error as exc:
            if exc.status != 404:
                raise
            capabilities = {}  # Compatibility with an older, explicitly legacy fleet.
        managed = capabilities.get('session_via_management') is True
        portable = managed and capabilities.get('execution_architecture') == 'hal-managed-agent-v2'
        required = self.config.get('required_execution_architecture')
        require(required is None or capabilities.get('execution_architecture') == required,
                'Management execution profile differs from this client profile', 403)
        require(not self.config.get('require_attested_agent') or portable, 'Attested agent service is required; refusing legacy downgrade', 403)
        role = 'management' if managed else 'execution'
        body = {'document': self.document}
        if portable and capabilities.get('session_minimum_validity') is True:
            body['minimum_validity_seconds'] = SESSION_MINIMUM_VALIDITY_SECONDS
        session = self.call(role, '/v1/session', self.signed(role, 'session', body))
        if portable:
            require(session.get('attestation_verified') is True, 'Management did not verify platform attestation', 403)
            require(type(session.get('expires_unix')) is int and not session_needs_refresh(session),
                    'Attested session expires too soon; no job was submitted. Update management to support '
                    'minimum session validity and reopen the session.', 409, 'session_changed')
            self.config['require_attested_agent'] = True
            atomic_json(self.path, self.config)
        elif managed:
            from .native_audit import PROFILE, FORMAT, identity_from_certificate
            require(capabilities.get('execution_architecture') == PROFILE and session.get('execution_architecture') == PROFILE
                    and session.get('mode') == 'native' and session.get('audit_log') == FORMAT,
                    'Unknown management-mediated native profile', 403)
            identity = session['native_identity']
            checked = identity_from_certificate(session['native_certificate'], identity['management_key'])
            require(checked['identity'] == identity and checked['issued_unix'] <= time.time() + 5 < checked['expires_unix'],
                    'Invalid native identity certificate', 403)
        require(session.get('tenant') == self.config['user'] and session.get('audience') == self.trust['execution_audience'],
                'Unexpected execution session')
        self.session = session
        return self.session

    def job(self, name, cache, expected_mode='wasm', expected_isolation='per-user-container'):
        start = time.perf_counter()
        require(self.session is not None, 'Open a session first')
        require(not session_needs_refresh(self.session),
                'Attested session expires soon; reopen session before submitting. No job was submitted.', 409, 'session_changed')
        require(self.session['mode'] == expected_mode and self.session['isolation'] == expected_isolation,
                'Execution profile differs from the requested benchmark profile')
        require(expected_mode != 'native' or cache == 'bypass', 'Native mode requires cache bypass')
        # Renew a long-running client's public document without changing its key,
        # grants, broker, container or cache. A revoked user cannot renew.
        from .common import parse
        if parse(self.document['payload'])['expires_unix'] - time.time() < 180:
            with self.renew_lock:
                if parse(self.document['payload'])['expires_unix'] - time.time() < 180:
                    self.renew()
        doc = certificate(self.document, self.config)
        row = next((w for w in doc['workloads'] if w['name'] == name), None)
        require(row is not None, 'Approve this workload first: ' + name)
        now, job_id = int(time.time()), str(uuid.uuid4())
        claims = dict(version=1, tenant=doc['subject'], audience=self.session['audience'], epoch=self.session['epoch'],
            job_id=job_id, nonce=secrets.token_hex(32), operation='run', component=row['component'], sha256=row['sha256'],
            artifact_bytes=row['artifact_bytes'], cache=cache, rule_sha256=rule_digest(row['rule']),
            isolation=expected_isolation, input='none', issued_unix=now, expires_unix=now + 120)
        ticket = sign(self.key, DOMAIN, claims)
        job = dict(protocol=1, job_id=job_id, component=row['component'], sha256=row['sha256'],
                   artifact_bytes=row['artifact_bytes'], cache=cache, job_ticket=ticket)
        signing_ms = milliseconds(start)
        try:
            result = self.call('management', '/v1/run', {'document': self.document, 'job': job, 'isolation': expected_isolation})
        except Error as exc:
            result = dict(job_id=job_id, tenant=doc['subject'], status='unknown', error=str(exc), error_code=exc.code)
        result['client_observed_ms'] = milliseconds(start)
        result['client_signing_ms'] = signing_ms
        result['case'] = name
        if result.get('status') == 'completed':
            agent = result.get('response', {}).get('agent', {})
            audit_valid = True
            if self.session.get('audit_log'):
                native_audit = self.session.get('execution_architecture') == 'hal-native-audited-v1'
                if native_audit:
                    from .native_audit import FORMAT, PROOF_DOMAIN
                    identity, proof_name = self.session['native_identity'], 'native_result_proof'
                else:
                    from .attested_channel import PROOF_DOMAIN
                    from .audit import FORMAT
                    identity, proof_name = self.session['agent_identity'], 'agent_result_proof'
                try:
                    receipt = verify(identity['public_key'], PROOF_DOMAIN, agent.get(proof_name))
                    audit_valid = (self.session['audit_log'] == FORMAT and agent.get('audit_collected') is True
                        and receipt.get('identity') == identity
                        and receipt.get('kind') == 'result' and receipt.get('challenge') == job_id
                        and all(receipt['data'].get(k) == agent.get(k) for k in
                            ('job_id', 'tenant', 'sha256', 'result', 'audit', 'status', 'cache_status',
                             'execution_mode', 'configuration', 'host_sha256', 'artifact_bytes',
                             'cache_policy', 'workload_instance_reused')))
                except (Error, KeyError, TypeError):
                    audit_valid = False
            valid = (result.get('job_id') == job_id and result.get('tenant') == doc['subject']
                and agent.get('job_id') == job_id and agent.get('tenant') == doc['subject']
                and agent.get('execution_mode') == expected_mode
                and agent.get('configuration', {}).get('workload_isolation') == expected_isolation
                and agent.get('workload_instance_reused') is False and agent.get('gateway_signature_checked') is True
                and agent.get('sha256') == row['sha256'] and agent.get('cache_policy') == cache
                and agent.get('cache_status') in (('bypass',) if cache == 'bypass' else ('miss', 'hit', 'shared')) and audit_valid)
            if expected_mode == 'wasm':
                valid = valid and agent.get('job_authorization', {}).get('verified') is True and agent.get('agent_result_validation') == 'passed'
            data = bytes.fromhex(agent.get('result', {}).get('hex', ''))
            rule = row['rule']['validation']
            kind = rule['kind']
            if kind == 'hex':
                valid = valid and data.hex() == rule['value']
            elif kind == 'length':
                valid = valid and len(data) == rule['value']
            elif kind == 'utf8_contains':
                valid = valid and rule['value'] in data.decode('utf8', errors='replace')
            valid = valid and len(data) <= row['rule']['max_output_bytes']
            if not valid:
                result['status'], result['error'] = 'failed', 'Client result/profile validation failed'
            result['client_result_validation'] = 'passed' if valid else 'failed'
        return result

    def audit(self, after=0, limit=50, job_id=None):
        from .audit import checked_record, checked_management_record
        from .native_audit import checked_native_record
        self.renew()
        data = dict(document=self.document, after=after, limit=limit)
        if job_id is not None:
            data['job_id'] = job_id
        page = self.call('management', '/v1/audit', self.signed('management', 'audit', data))
        # Bootstrap the signer from the configured management service over pinned
        # HTTPS. This verifies individual records, not completeness of a user view.
        key = page['management_public_key']
        for item in page['records']:
            require(item['source'] in ('agent', 'native', 'management'), 'Unexpected audit source')
            checker = {'agent': checked_record, 'native': checked_native_record, 'management': checked_management_record}[item['source']]
            entry = checker(item['record'], key)
            require(entry['data'].get('tenant') == self.config['user']
                    and entry['data'].get('user_key') == public(self.key), 'Audit record belongs to another user', 403)
            item['event'] = entry['event']
            item['data'] = entry['data']
        page['record_signatures_verified'] = True
        return page


def distribution(values):
    if not values:
        return None
    values = sorted(values)
    # Nearest rank quantiles, not interpolated values that were never measured.
    import math
    return dict(count=len(values), median=statistics.median(values), p95=values[math.ceil(.95 * len(values)) - 1],
                p99=values[math.ceil(.99 * len(values)) - 1], minimum=values[0], maximum=values[-1])


def benchmark(client, cases, jobs, concurrency, cache, output, mode, isolation, *, experiment=None, phase='measured'):
    require(1 <= jobs <= 100000 and 1 <= concurrency <= 128, 'Invalid job count/concurrency')
    require(cases and phase in ('startup', 'warmup', 'measured'), 'Choose workloads and a valid phase')
    require(mode != 'native' or cache == 'bypass', 'Native benchmark forbids cache reuse')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    if experiment is None:
        from .benchmark_guard import Experiment
        with Experiment(client, cases, mode, isolation, output) as run:
            return _benchmark(client, cases, jobs, concurrency, cache, output, mode, isolation, run, phase)
    return _benchmark(client, cases, jobs, concurrency, cache, output, mode, isolation, experiment, phase)


def _benchmark(client, cases, jobs, concurrency, cache, output, mode, isolation, experiment, phase):
    from .benchmark_guard import seal_batch
    session = client.open_session()
    require(session['mode'] == mode and session['isolation'] == isolation, 'Wrong execution profile')
    metadata = dict(experiment_id=experiment.id, batch_id=str(uuid.uuid4()), phase=phase,
                    profile_sha256=experiment.session(session))
    configuration = dict(**metadata, fingerprint=copy.deepcopy(experiment.pin), jobs=jobs, concurrency=concurrency, cache=cache, cases=cases,
        session=copy.deepcopy(session), transport='synchronous-http-keepalive', client_signing_included=True,
        setup_included=False, endpoints=client.trust['endpoints'], attestation_verified=session.get('attestation_verified') is True,
        session_job_reserve_seconds=SESSION_JOB_RESERVE_SECONDS, session_refreshes=[],
        session_refresh_included_in_batch_wall=True)
    atomic_json(output / 'config.json', configuration)
    rows = []
    refresh_error = None
    contaminated = False
    contamination_errors = []
    generation = 0
    started = time.perf_counter()
    with (output / 'jobs.jsonl').open('w', encoding='utf-8', newline='\n') as stream, ThreadPoolExecutor(max_workers=concurrency) as pool:
        # Keep at most concurrency outstanding futures, rather than queueing 100k jobs/keys.
        pending, next_index = {}, 0
        while next_index < jobs or pending:
            if contaminated and not pending:
                break
            # Drain before renewing: enrollment can replace this user's broker
            # and file credentials. Never change those under outstanding jobs.
            if next_index < jobs and not pending and session_needs_refresh(session):
                print('Benchmark: draining complete; renewing attested session before remaining jobs.', file=sys.stderr, flush=True)
                refreshed_at = time.perf_counter()
                event = dict(after_submitted=next_index)
                try:
                    session = client.open_session()
                    require(session['mode'] == mode and session['isolation'] == isolation, 'Wrong renewed execution profile')
                    experiment.session(session)
                    require(not session_needs_refresh(session), 'Renewed session expires too soon; no further jobs submitted')
                    generation += 1
                    event.update(session=copy.deepcopy(session), generation=generation)
                except Exception as exc:
                    refresh_error = str(exc)
                    event['error'] = refresh_error
                event['duration_ms'] = milliseconds(refreshed_at)
                configuration['session_refreshes'].append(event)
                atomic_json(output / 'config.json', configuration)
                if refresh_error:
                    break
            while not contaminated and next_index < jobs and len(pending) < concurrency and not session_needs_refresh(session):
                index = next_index
                future = pool.submit(client.job, cases[index % len(cases)], cache, mode, isolation)
                pending[future] = (index, generation)
                next_index += 1
            if not pending:
                continue  # The lease crossed the reserve while filling the queue.
            future = next(as_completed(pending))
            index, row_generation = pending.pop(future)
            try:
                row = future.result()
            except Exception as exc:
                row = dict(status='unknown', error=str(exc), case=cases[index % len(cases)])
            try:
                experiment.check_row(row, cache)
            except Error as exc:
                contaminated = True
                contamination_errors.append(str(exc))
                row.update(reported_status=row.get('status'), status='failed', error=str(exc), contamination_detected=True)
            row.update(metadata)
            row['trial_index'] = index
            row['session_generation'] = row_generation
            rows.append(row)
            stream.write(canonical_line(row))
            stream.flush()
        import os
        os.fsync(stream.fileno())
    elapsed = milliseconds(started)
    configuration['runtime_configuration'] = copy.deepcopy(experiment.runtime)
    atomic_json(output / 'config.json', configuration)
    complete = [r for r in rows if r['status'] == 'completed']
    from collections import Counter
    agents = [r['response']['agent'] for r in complete]
    summary = dict(**metadata, requested=jobs, completed=len(complete), failed_or_unknown=jobs-len(complete),
        statuses=dict(Counter(r['status'] for r in rows)), cache_status_counts=dict(Counter(a['cache_status'] for a in agents)),
        execution_modes=dict(Counter(a['execution_mode'] for a in agents)),
        workload_isolations=dict(Counter(a['configuration']['workload_isolation'] for a in agents)),
        compile_opt_levels=dict(Counter(a['configuration']['compile_opt_level'] for a in agents)),
        signed_job_checks_reported=sum(a.get('job_authorization', {}).get('verified') is True for a in agents),
        batch_wall_ms=elapsed, completed_jobs_per_second=len(complete)*1000/elapsed,
        timings_ms=dict(client=distribution([r['client_observed_ms'] for r in complete]),
                        management=distribution([r['timings_ms']['management_total'] for r in complete]),
                        host=distribution([a['timings_ms']['host_request'] for a in agents])),
        attestation_verified=bool(complete) and all(r.get('attestation_verified') is True for r in complete),
        setup_included=False, timing_population='completed_jobs', not_submitted=jobs-next_index,
        session_refresh_count=generation,
        session_refresh_ms=sum(e['duration_ms'] for e in configuration['session_refreshes']),
        session_refresh_error=refresh_error, session_refresh_included_in_batch_wall=True,
        contamination_detected=contaminated, contamination_errors=contamination_errors,
        valid_for_comparison=not contaminated and not refresh_error and len(complete) == jobs)
    atomic_json(output / 'summary.json', summary)
    seal_batch(output, metadata)
    experiment.batches.append(dict(**metadata, path=str(output.relative_to(experiment.output)),
                                   valid_for_comparison=summary['valid_for_comparison']))
    return summary


def canonical_line(value):
    from .common import canonical
    return canonical(value) + '\n'
