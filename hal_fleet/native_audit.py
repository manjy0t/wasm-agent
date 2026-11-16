"""Audited native control plane. No Wasm agent, code cache or attestation claim.

Execution signs and commits its journal locally; management independently checks
and persists that journal before acknowledging a result. Keys never enter a broker.
"""
import threading
import time

from .audit import AuditStore, BoundaryLog, ZERO
from .common import (Error, canonical, digest, key_from_hex, parse, public,
                     read_private, request, require, sign, verify, verify_request)
from .runtime import Broker, Execution
from .services import Management

PROFILE = 'hal-native-audited-v1'
FORMAT = 'hal-native-audit-v1'
DOMAIN = b'HAL-NATIVE-AUDIT-v1\0'
CERT_DOMAIN = b'HAL-NATIVE-CERTIFICATE-v1\0'
PROOF_DOMAIN = b'HAL-NATIVE-PROOF-v1\0'


def identity_from_certificate(certificate, owner):
    value = verify(owner, CERT_DOMAIN, certificate, 8192)
    identity = value.get('identity', {})
    require(value.get('version') == 1 and value.get('kind') == 'native-identity'
            and identity.get('management_key') == owner and identity.get('profile') == PROFILE,
            'Native certificate scope mismatch', 403)
    from .common import SHA
    require(all(isinstance(identity.get(k), str) and SHA.fullmatch(identity[k])
                for k in ('public_key', 'vm_id', 'instance')), 'Invalid native identity', 403)
    require(type(value.get('issued_unix')) is int and type(value.get('expires_unix')) is int
            and value['issued_unix'] < value['expires_unix'], 'Invalid native certificate lifetime', 403)
    return value


def checked_native_record(record, management_key, vm_id=None, sequence=None, previous=None):
    require(isinstance(record, dict) and set(record) == {'payload', 'signature', 'hash'}, 'Invalid native audit record', 403)
    require(isinstance(record['payload'], str) and len(record['payload'].encode()) <= 8192, 'Audit record too large')
    certificate = identity_from_certificate(parse(record['payload']).get('certificate'), management_key)
    identity = certificate['identity']
    entry = verify(identity['public_key'], DOMAIN, {k: record[k] for k in ('payload', 'signature')}, 8192)
    require(entry.get('format') == FORMAT and entry.get('vm_id') == identity['vm_id']
            and entry.get('native_instance') == identity['instance'], 'Native audit identity mismatch', 403)
    timestamp = entry.get('timestamp_unix')
    require(type(timestamp) is int and certificate['issued_unix'] <= timestamp + 5
            and timestamp < certificate['expires_unix'], 'Audit record outside certificate lifetime', 403)
    require(record['hash'] == digest(DOMAIN + record['payload'].encode()), 'Native audit hash mismatch', 403)
    if vm_id is not None:
        require(entry['vm_id'] == vm_id, 'Native audit VM mismatch', 403)
    if sequence is not None:
        require(entry.get('sequence') == sequence and entry.get('previous_hash') == previous,
                'Native audit gap, fork or rollback', 409, 'audit_integrity_failed')
    require(isinstance(entry.get('data'), dict), 'Invalid native audit event')
    return entry


class NativeJournal(AuditStore):
    """Append-only signed events, using the same FULL durability as the collector."""
    def __init__(self, database, key, certificate, owner, maximum=200000):
        self.certificate = certificate
        self.identity = identity_from_certificate(certificate, owner)['identity']
        require(public(key) == self.identity['public_key'], 'Native signing key mismatch', 403)
        self.failed = False
        super().__init__(database, key, maximum, record_checker=checked_native_record,
                         record_source='native', verification_key=owner)

    def append(self, event, data, admission=False):
        require(not self.failed, 'Native audit journal unavailable', 503, 'audit_unavailable')
        try:
            with self.db.lock, self.db.connection:
                self.capacity(admission=admission)
                vm = self.identity['vm_id']
                head = self.head(vm)
                value = dict(format=FORMAT, vm_id=vm, native_instance=self.identity['instance'],
                    sequence=head['sequence'] + 1, previous_hash=head['hash'], timestamp_unix=int(time.time()),
                    event=event, data=data, certificate=self.certificate)
                record = sign(self.key, DOMAIN, value)
                record['hash'] = digest(DOMAIN + record['payload'].encode())
                checked_native_record(record, self.public_key, vm, head['sequence'] + 1, head['hash'])
                self._insert(vm, record, value)
                return dict(vm_id=vm, sequence=value['sequence'], hash=record['hash'])
        except Exception as exc:
            self.failed = True
            raise Error('Native audit persistence failed; success cannot be acknowledged', 503, 'audit_unavailable') from exc

    def page(self, after, previous_hash, limit=64):
        require(type(after) is int and after >= 0 and type(limit) is int and 1 <= limit <= 64, 'Invalid native audit cursor')
        with self.db.lock:
            vm = self.identity['vm_id']
            tip = dict(vm_id=vm, **self.head(vm))
            row = self.db.connection.execute('SELECT hash FROM audit_records WHERE stream=? AND sequence=?', (vm, after)).fetchone()
            expected = ZERO if after == 0 else row[0] if row else None
            require(after <= tip['sequence'] and expected == previous_hash, 'Native audit checkpoint mismatch', 409, 'audit_integrity_failed')
            rows = self.db.connection.execute('SELECT record FROM audit_records WHERE stream=? AND sequence>? '
                                             'ORDER BY sequence LIMIT ?', (vm, after, limit)).fetchall()
            records = [parse(row[0]) for row in rows]
            checkpoint = dict(vm_id=vm, sequence=after, hash=previous_hash)
            for record in records:
                entry = checked_native_record(record, self.public_key, vm, checkpoint['sequence'] + 1, checkpoint['hash'])
                checkpoint = dict(vm_id=vm, sequence=entry['sequence'], hash=record['hash'])
            return dict(records=records, checkpoint=checkpoint, tip=tip)


class NativeExecution(Execution):
    def __init__(self, config, database, transport, broker_factory=Broker):
        require(config.get('mode') == 'native' and config.get('execution_architecture') == PROFILE, 'Audited native profile required')
        super().__init__(config, database, transport, broker_factory)
        self.key = key_from_hex(read_private(config['native_key'])['private_key'])
        self.journal = NativeJournal(database, self.key, read_private(config['native_certificate']),
                                    config['management_public_key'], config.get('audit_max_records', 200000))
        self.identity = self.journal.identity
        self.boundary = BoundaryLog(database)
        self.grants = {}
        self.build = dict(host_sha256=config['binary_sha256'], service_sha256=config['service_sha256'])
        self.journal.append('native_started', dict(profile=PROFILE, build=self.build), admission=True)

    def proof(self, kind, challenge, data):
        return sign(self.key, PROOF_DOMAIN, dict(identity=self.identity, kind=kind, challenge=challenge, data=data))

    def handle(self, method, path, body):
        try:
            return self.handle_audited(method, path, body)
        except Error:
            self.boundary.rejected(path if path in ('/v1/enroll', '/v2/native/session', '/v2/native/run', '/v2/native/audit') else 'other',
                                   'request_rejected')
            raise

    def handle_audited(self, method, path, body):
        if path == '/v1/enroll':
            return super().handle(method, path, body)
        require(method == 'POST' and path in ('/v2/native/session', '/v2/native/run', '/v2/native/audit'),
                'Use the audited management service for native execution', 404)
        operation = path.rsplit('/', 1)[1]
        req = verify_request(body, self.config['trust']['execution_audience'], 'native-' + operation, self.db)
        require(req['public_key'] == self.config['management_public_key'], 'Native management owner required', 403)
        data = req['body']
        if operation == 'audit':
            require(set(data) == {'after', 'previous_hash', 'limit', 'challenge'}, 'Invalid native audit request')
            return self.proof('audit', data['challenge'], self.journal.page(data['after'], data['previous_hash'], data['limit']))
        if operation == 'session':
            require(set(data) == {'document', 'file_grant', 'challenge'}, 'Invalid native session request')
            doc = self.check_document(data['document'])
            grant = data['file_grant']
            require(isinstance(grant, dict) and isinstance(grant.get('token'), str)
                    and type(grant.get('expires_unix')) is int and grant['expires_unix'] > time.time() + 180,
                    'File credential expires too soon')
            with self.lock(doc['subject']):
                old = self.brokers.get(doc['subject'])
                if old:
                    require(old.active == 0, 'Native user has active jobs', 409)
                    old.close()
                    del self.brokers[doc['subject']]
                enrolled = self.db.get('enrolled', doc['subject'])
                require(enrolled and enrolled['public_key'] == doc['public_key'] and enrolled['revision'] == doc['revision'],
                        'Enroll the current document first', 403)
                self.grants[doc['subject']] = grant
                broker = self.ensure(doc)
                session = dict(tenant=doc['subject'], revision=doc['revision'], epoch=broker.epoch,
                    audience=self.config['trust']['execution_audience'], mode='native', isolation='in-process',
                    broker_startup_ms=broker.startup_ms, expires_unix=grant['expires_unix'],
                    settings=self.config.get('settings', {}), execution_architecture=PROFILE, audit_log=FORMAT,
                    native_identity=self.identity, build=self.build, attestation_verified=False)
                self.journal.append('user_enrolled', dict(tenant=doc['subject'], user_key=doc['public_key'],
                                                        revision=doc['revision']), admission=True)
                return self.proof('session', data['challenge'], session)
        require(set(data) == {'request', 'challenge'}, 'Invalid native run request')
        submitted = data['request']
        require(data['challenge'] == submitted['job']['job_id'], 'Native job challenge mismatch', 403)
        result = super().handle('POST', '/v1/run', submitted)
        return self.proof('result', data['challenge'], result)

    def execute_job(self, broker, job, doc, claims):
        # Reuse the existing native authorization path exactly once. Auditing
        # begins only after the base gateway has admitted the signed job.
        require(self.grants.get(doc['subject'], {}).get('expires_unix', 0) > time.time() + 120,
                'Native session expired; reopen session', 409, 'session_changed')
        metadata = dict(tenant=doc['subject'], user_key=doc['public_key'], job_id=claims['job_id'],
            artifact_sha256=claims['sha256'], policy_sha256=claims['rule_sha256'], cache_policy='bypass', revision=doc['revision'])
        self.journal.append('job_accepted', metadata, admission=True)
        try:
            result = super().execute_job(broker, job, doc, claims)
        except Exception:
            self.journal.append('job_outcome_unknown', metadata)
            raise
        require(result.get('execution_mode') == 'native' and result.get('cache_policy') == 'bypass'
                and result.get('cache_status') in ('bypass', 'none')
                and result.get('job_id') == claims['job_id'] and result.get('tenant') == doc['subject']
                and result.get('sha256') == claims['sha256'], 'Native broker result scope mismatch', 503)
        outcome = 'unknown' if result.get('execution_outcome') == 'unknown' else 'completed' if result['status'] == 'ok' else 'failed'
        completion = dict(metadata, outcome=outcome, cache_status=result['cache_status'],
                          sandbox=dict(profile='in-process', runtime='native'))
        if outcome == 'completed':
            require(result['cache_status'] == 'bypass', 'Native cache reuse forbidden', 503)
            completion['result_sha256'] = digest(bytes.fromhex(result['result']['hex']))
        result.update(execution_architecture=PROFILE, build=self.build)
        result['configuration']['audit_log'] = FORMAT
        result['audit'] = self.journal.append('result_committed', completion)
        return result

    def create_broker(self, doc):
        # LocalRuntime alone owns process startup; no Wasm orchestration is used.
        config = dict(self.config, file_token=self.grants[doc['subject']]['token'])
        return self.factory(config, doc, self.transport)


class NativeManagement(Management):
    def __init__(self, config, database, transport):
        super().__init__(config, database, transport)
        self.key = key_from_hex(read_private(config['management_key'])['private_key'])
        self.certificate = read_private(config['native_certificate'])
        self.identity = identity_from_certificate(self.certificate, public(self.key))['identity']
        self.audit = AuditStore(database, self.key, config.get('audit_max_records', 200000),
                               record_checker=checked_native_record, record_source='native')
        self.audit_lock = threading.RLock()
        self.boundary = BoundaryLog(database)

    def call_native(self, operation, **data):
        envelope = request(self.key, self.config['trust']['execution_audience'], 'native-' + operation, 'management', data)
        return self.transport.call(self.config['execution_url'], '/v2/native/' + operation, envelope)

    def proof(self, envelope, kind, challenge):
        value = verify(self.identity['public_key'], PROOF_DOMAIN, envelope)
        require(value.get('identity') == self.identity and value.get('kind') == kind
                and value.get('challenge') == challenge, 'Native proof scope mismatch', 403)
        return value['data']

    def collect_audit(self, required=None):
        import secrets
        with self.audit_lock:
            vm = self.identity['vm_id']
            self.audit.bind_target(self.config['execution_url'], vm)
            target = None
            for _ in range(2048):
                head = self.audit.head(vm)
                challenge = secrets.token_hex(32)
                page = self.proof(self.call_native('audit', after=head['sequence'], previous_hash=head['hash'],
                                  limit=64, challenge=challenge), 'audit', challenge)
                require(page.get('tip', {}).get('vm_id') == vm and type(page['tip'].get('sequence')) is int
                        and page['tip']['sequence'] >= head['sequence'], 'Native audit journal rolled back', 409, 'audit_integrity_failed')
                if target is None:
                    target = page['tip']['sequence']
                latest = self.audit.ingest(vm, page)
                if latest['sequence'] >= target:
                    require(required is None or self.audit.contains(required), 'Native result audit not collected', 503, 'audit_unavailable')
                    return latest
                require(latest['sequence'] > head['sequence'], 'Native audit collection made no progress', 503, 'audit_unavailable')
            raise Error('Native audit catch-up limit reached', 503, 'audit_unavailable')

    def dispatch(self, body):
        from .policy import certificate
        doc = certificate(body['document'], self.config)
        job = body['job']
        require(body['isolation'] == 'in-process' and job['cache'] == 'bypass', 'Native requires cache bypass and in-process isolation')
        metadata = dict(tenant=doc['subject'], user_key=doc['public_key'], job_id=job['job_id'],
                        artifact_sha256=job['sha256'], vm_id=self.identity['vm_id'])
        self.collect_audit()
        self.audit.event('job_dispatch_requested', metadata, admission=True)
        try:
            envelope = self.call_native('run', request=body, challenge=job['job_id'])
            result = self.proof(envelope, 'result', job['job_id'])
            require(result.get('execution_architecture') == PROFILE and result.get('audit', {}).get('vm_id') == self.identity['vm_id'],
                    'Native result profile mismatch', 403)
            self.collect_audit(result['audit'])
            self.audit.check_completion(result['audit'], metadata, result)
        except Exception as exc:
            try:
                self.collect_audit()
                self.audit.event('job_outcome_unknown', metadata)
            except Exception:
                pass
            raise Error('Native execution/audit acknowledgement unavailable; job may have run. Do not resubmit.',
                        503, 'audit_unavailable') from exc
        self.audit.event('job_acknowledged', dict(metadata, outcome=result['status'], audit=result['audit']))
        result.update(audit_collected=True, native_result_proof=envelope, native_certificate=self.certificate)
        return result

    def handle(self, method, path, body):
        try:
            return self.handle_audited(method, path, body)
        except Error:
            self.boundary.rejected(path if path in ('/v1/session', '/v1/run', '/v1/audit') else 'other', 'request_rejected')
            raise

    def handle_audited(self, method, path, body):
        if method == 'GET' and path == '/v1/capabilities':
            return dict(session_via_management=True, execution_architecture=PROFILE, audit_log=FORMAT, attestation_required=False)
        if method == 'POST' and path in ('/v1/session', '/v1/audit'):
            operation = path.rsplit('/', 1)[1]
            req = verify_request(body, self.config['trust']['management_audience'], operation, self.db)
            doc = self.check_document(req['body'].get('document'))
            require(req['subject'] == doc['subject'] and req['public_key'] == doc['public_key'], 'Native user mismatch', 403)
            if operation == 'audit':
                require(set(req['body']) <= {'document', 'after', 'limit', 'job_id'}, 'Invalid audit request')
                self.audit.event('audit_read', dict(viewer_key_sha256=digest(req['public_key'].encode())), admission=True)
                return self.audit.user_page(doc['subject'], doc['public_key'], req['body'].get('after', 0),
                                            req['body'].get('limit', 50), req['body'].get('job_id'))
            require(set(req['body']) == {'document'}, 'Invalid native session request')
            import secrets
            challenge = secrets.token_hex(32)
            grant = self.transport.call(self.config['files_url'], '/v2/access', request(self.key,
                self.config['trust']['files_audience'], 'agent-file-access', 'management',
                dict(artifacts=[w['sha256'] for w in doc['workloads']], ttl_seconds=900)))
            session = self.proof(self.call_native('session', document=req['body']['document'], file_grant=grant,
                                                 challenge=challenge), 'session', challenge)
            require(session.get('tenant') == doc['subject'] and session.get('revision') == doc['revision']
                    and session.get('mode') == 'native' and session.get('isolation') == 'in-process'
                    and session.get('audit_log') == FORMAT and session.get('execution_architecture') == PROFILE,
                    'Native session acknowledgement mismatch', 403)
            self.collect_audit()
            session.update(execution_url=self.config['execution_url'], native_certificate=self.certificate)
            return session
        return super().handle(method, path, body)
