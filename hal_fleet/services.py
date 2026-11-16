import base64
import secrets
import os
from pathlib import Path
import time
from .common import (DOCUMENT_DOMAIN, Error, SHA, atomic_json, digest, milliseconds,
                     require, verify, verify_request)
from .policy import certificate, signed_job
from .lifetimes import MAX_SESSION_SECONDS


class TrustChecks:
    def __init__(self, config, database, transport):
        self.config, self.db, self.transport = config, database, transport

    def check_document(self, envelope):
        doc = certificate(envelope, self.config)
        # Revocations are checked online for every enrollment/session/job. There
        # is no stale authorization cache; an unavailable authority fails closed.
        status = self.transport.call(self.config['identity_url'], '/v1/status/' + doc['subject'])
        state = verify(self.config['trust']['identity_public_key'], DOCUMENT_DOMAIN, status)
        require(state.get('kind') == 'user-status' and state.get('issuer') == self.config['trust']['issuer']
                and state.get('subject') == doc['subject'] and state.get('public_key') == doc['public_key']
                and state.get('active') is True and state.get('revision') == doc['revision']
                and type(state.get('expires_unix')) is int and time.time() < state['expires_unix']
                and type(state.get('issued_unix')) is int and state['issued_unix'] <= time.time() + 5
                and state['expires_unix'] - state['issued_unix'] <= 5,
                'Enrollment is revoked or out of date; renew through identity', 403, 'authorization_changed')
        return doc


class Files:
    def __init__(self, config, database):
        self.config, self.db = config, database
        self.root = Path(config['state_dir']) / 'artifacts'
        self.root.mkdir(exist_ok=True, mode=0o700)

    def artifact(self, path):
        name = path[len('/artifacts/'):]
        require(name.endswith('.wasm') and SHA.fullmatch(name[:-5]), 'Artifact not found', 404)
        file = self.root / name
        require(file.is_file() and not file.is_symlink(), 'Artifact not found', 404)
        return file.read_bytes()

    def handle_http(self, method, path, body, headers):
        if method == 'GET' and path.startswith('/artifacts/') and self.config.get('protected_artifacts'):
            auth = headers.get('Authorization', '')
            require(auth.startswith('Bearer ') and SHA.fullmatch(auth[7:]), 'File access credential required', 401)
            grant = self.db.get('file-access', digest(auth[7:].encode()))
            name = path[len('/artifacts/'):]
            require(grant and grant['expires_unix'] > time.time() and name.endswith('.wasm')
                    and name[:-5] in grant['artifacts'], 'File credential expired or outside artifact scope', 403)
            return self.artifact(path)
        return self.handle(method, path, body)

    def handle(self, method, path, body):
        if method == 'POST' and path == '/v2/access':
            require(self.config.get('protected_artifacts'), 'Protected artifact service is not configured', 409)
            req = verify_request(body, self.config['trust']['files_audience'], 'agent-file-access', self.db)
            require(req['public_key'] in self.config.get('trusted_management_keys', []), 'Trusted management key required', 403)
            data = req['body']
            require(set(data) == {'artifacts', 'ttl_seconds'} and type(data['ttl_seconds']) is int
                    and 60 <= data['ttl_seconds'] <= MAX_SESSION_SECONDS and isinstance(data['artifacts'], list)
                    and 1 <= len(data['artifacts']) <= 128 and all(isinstance(x, str) and SHA.fullmatch(x) for x in data['artifacts']),
                    'Invalid file access scope')
            token = secrets.token_hex(32)
            expires = int(time.time()) + data['ttl_seconds']
            with self.db.lock, self.db.connection:
                rows = self.db.connection.execute("SELECT name, value FROM records WHERE kind='file-access'").fetchall()
                from .common import parse
                for name, value in rows:
                    if parse(value)['expires_unix'] <= time.time():
                        self.db.connection.execute("DELETE FROM records WHERE kind='file-access' AND name=?", (name,))
                count = self.db.connection.execute("SELECT count(*) FROM records WHERE kind='file-access'").fetchone()[0]
                require(count < 256, 'File access capacity reached', 429)
                self.db.put('file-access', digest(token.encode()), dict(tenant=req['subject'], artifacts=data['artifacts'], expires_unix=expires))
            return dict(token=token, expires_unix=expires)
        if method == 'GET' and path.startswith('/artifacts/'):
            require(not self.config.get('protected_artifacts'), 'File access credential required', 401)
            return self.artifact(path)
        require(method == 'POST' and path == '/v1/upload', 'Endpoint not found', 404)
        req = verify_request(body, self.config['trust']['files_audience'], 'upload', self.db, 24 * 1024 * 1024)
        require(req['public_key'] == self.config['trust']['operator_public_key'], 'Operator publication signature required', 403)
        data = req['body']
        require(set(data) == {'sha256', 'wasm_base64'} and isinstance(data['sha256'], str)
                and SHA.fullmatch(data['sha256']), 'Invalid upload')
        try:
            raw = base64.b64decode(data['wasm_base64'], validate=True)
        except (TypeError, ValueError) as exc:
            raise Error('Invalid base64 artifact') from exc
        require(8 <= len(raw) <= 16 * 1024 * 1024 and raw[:4] == b'\0asm', 'Expected a Wasm artifact', 400)
        require(digest(raw) == data['sha256'], 'Artifact digest mismatch')
        target = self.root / (data['sha256'] + '.wasm')
        with self.db.lock:
            existing = list(self.root.glob('*.wasm'))
            require(target.exists() or (len(existing) < 512 and sum(p.stat().st_size for p in existing)
                    + len(raw) <= self.config.get('artifact_quota_bytes', 2 * 1024**3)), 'Artifact storage quota exceeded', 507)
            if target.exists():
                require(not target.is_symlink() and digest(target.read_bytes()) == data['sha256'],
                        'Existing artifact is corrupt; operator repair required', 409)
            else:
                temporary = self.root / ('.upload-' + os.urandom(12).hex())
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, target)
                finally:
                    if temporary.exists():
                        temporary.unlink()
        return {'component': target.name, 'sha256': data['sha256'], 'artifact_bytes': len(raw)}


class Management(TrustChecks):
    def dispatch(self, body):
        return self.transport.call(self.config['execution_url'], '/v1/run', body)

    def handle(self, method, path, body):
        if method == 'GET' and path == '/v1/capabilities':
            return dict(session_via_management=False, execution_architecture='legacy')
        if method == 'GET' and path == '/v1/workloads':
            return self.transport.call(self.config['identity_url'], '/v1/workloads')
        require(method == 'POST', 'Endpoint not found', 404)
        if path == '/v1/approve':
            return self.transport.call(self.config['identity_url'], '/v1/approve', body)
        if path == '/v1/result':
            req = verify_request(body, self.config['trust']['management_audience'], 'result', self.db)
            doc = self.check_document(req['body'].get('document'))
            require(req['subject'] == doc['subject'] and req['public_key'] == doc['public_key'], 'Wrong user', 403)
            row = self.db.get('result:' + doc['subject'], req['body'].get('job_id'))
            require(row is not None, 'Job not found', 404)
            return row
        require(path == '/v1/run', 'Endpoint not found', 404)
        start = time.perf_counter()
        require(isinstance(body, dict) and set(body) == {'document', 'job', 'isolation'}, 'Invalid dispatch')
        doc = self.check_document(body['document'])
        require(body['isolation'] in ('per-user-container', 'in-process'), 'Invalid isolation mode')
        claims, approved = signed_job(doc, body['job'], self.config['trust']['execution_audience'], body['isolation'])
        self.db.consume('management-job:' + doc['subject'], claims['job_id'])
        job_id = claims['job_id']
        pending = {'job_id': job_id, 'tenant': doc['subject'], 'status': 'unknown',
                   'error': 'Dispatched; outcome not yet recorded. Do not resubmit this job ID.'}
        self.db.put('result:' + doc['subject'], job_id, pending)
        auth_ms = milliseconds(start)
        dispatched = time.perf_counter()
        try:
            result = self.dispatch(body)
            status = ('unknown' if result.get('execution_outcome') == 'unknown'
                      else 'completed' if result.get('status') == 'ok' else 'failed')
            row = dict(job_id=job_id, tenant=doc['subject'], status=status,
                response={'agent': result}, attestation_verified=(self.config.get('execution_architecture') == 'hal-managed-agent-v2' and result.get('attestation_verified') is True))
        except Error as exc:
            row = dict(pending, error=str(exc), error_code=exc.code)
        row['timings_ms'] = dict(management_authorization=auth_ms, dispatch_round_trip=milliseconds(dispatched),
                                 management_total=milliseconds(start))
        self.db.put('result:' + doc['subject'], job_id, row)
        # Bound result history without touching authorization/replay records.
        with self.db.lock, self.db.connection:
            self.db.connection.execute('DELETE FROM records WHERE rowid IN (SELECT rowid FROM records '
                'WHERE kind LIKE ? ORDER BY rowid DESC LIMIT -1 OFFSET 10000)', ('result:%',))
        return row
