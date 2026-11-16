#!/usr/bin/env python3
"""Management API: bounded job queue, metadata dispatch, durable results.

The management server never downloads a workload. It sends the selected file
name, expected SHA-256 and size to the execution host, with or without a Wasm agent.
"""
import argparse
import copy
import os
import stat
import fcntl
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import queue
import re
import socket
import sqlite3
import threading
import time
import uuid
from urllib.parse import urlsplit, parse_qs
from urllib.error import HTTPError

NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$')
SHA = re.compile(r'^[a-fA-F0-9]{64}$')
LIMIT = 16 * 1024
RESPONSE_LIMIT = 16 * 1024 * 1024


def token_file(path):
    token = Path(path).read_text().strip()
    if not 32 <= len(token) <= 256 or not all(33 <= ord(c) <= 126 for c in token):
        raise ValueError('token must be 32..256 ASCII characters')
    return token


def load_catalog(path):
    data = json.loads(Path(path).read_text())
    cases = {}
    for item in data['cases']:
        name = item['name']
        filename = item.get('artifact', item.get('url_path'))
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in cases:
            raise ValueError('invalid or duplicate case name')
        if not isinstance(filename, str) or not NAME.fullmatch(filename) or not filename.endswith('.wasm'):
            raise ValueError('artifact must be a simple .wasm filename')
        if not isinstance(item.get('sha256'), str) or not SHA.fullmatch(item['sha256']):
            raise ValueError('invalid artifact SHA-256')
        size = item.get('artifact_bytes')
        if type(size) is not int or not 8 <= size <= 64 * 1024 * 1024:
            raise ValueError('artifact_bytes must be a size between 8 B and 64 MiB')
        validation = item.get('validation', {})
        if validation.get('kind') not in ('hex', 'length', 'utf8_contains', 'clock'):
            raise ValueError('each case requires a supported result validator')
        cases[name] = dict(item, artifact=filename, sha256=item['sha256'].lower())
    if not cases:
        raise ValueError('catalog must contain at least one case')
    return cases


def agent_request(address, token, request, timeout):
    payload = json.dumps(dict(request, token=token), separators=(',', ':')).encode() + b'\n'
    if len(payload) > LIMIT:
        raise ValueError('agent request too large')
    with socket.create_connection(address, timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        with sock.makefile('rb') as stream:
            data = stream.readline(RESPONSE_LIMIT + 1)
    if not data.endswith(b'\n') or len(data) > RESPONSE_LIMIT:
        raise ValueError('incomplete or oversized agent response')
    response = json.loads(data)
    if not isinstance(response, dict):
        raise ValueError('agent response must be an object')
    return response


class WorkerHTTPClient:
    """One dispatcher owns one connection; a dispatched POST is never retried.

    Reconnect before sending when idle, or after a previous response explicitly
    closed the socket. If a connection fails during dispatch, the job stays
    unknown: the next job may reconnect, but this job is not sent again.
    """
    def __init__(self, base, token, timeout, keep_alive=True):
        url = urlsplit(base)
        if (url.scheme not in ('http', 'https') or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment or url.path not in ('', '/')):
            raise ValueError('worker URL must be an HTTP(S) origin')
        self.url = base.rstrip('/') + '/v1/run'
        self.address = (url.hostname, url.port)
        self.connection_type = http.client.HTTPSConnection if url.scheme == 'https' else http.client.HTTPConnection
        self.token, self.timeout, self.keep_alive = token, timeout, keep_alive
        self.connection = None
        self.last_used = 0.0
        self.last_connection_reused = False

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def request(self, request):
        data = json.dumps(request, separators=(',', ':')).encode()
        if len(data) > LIMIT:
            raise ValueError('worker request too large')
        return self.exchange('POST', '/v1/run', data)

    def stats(self):
        return self.exchange('GET', '/v1/stats', None)

    def exchange(self, method, path, data):
        # The host's request-header timeout is 10 seconds. Retire idle sockets
        # earlier instead of risking a POST on a connection it already closed.
        if time.monotonic() - self.last_used >= 5:
            self.close()
        self.last_connection_reused = self.connection is not None and self.connection.sock is not None
        if self.connection is None:
            # Direct connection: no ambient proxy; HTTPS uses normal certificate
            # verification. HTTP redirects are rejected below, never followed.
            self.connection = self.connection_type(*self.address, timeout=self.timeout)
        headers = {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json',
                   'Connection': 'keep-alive' if self.keep_alive else 'close'}
        try:
            self.connection.request(method, path, body=data, headers=headers)
            with self.connection.getresponse() as response:
                if response.status != 200:
                    raise HTTPError(self.url, response.status, response.reason, response.headers, None)
                data = response.read(RESPONSE_LIMIT + 1)
                if len(data) > RESPONSE_LIMIT:
                    raise ValueError('worker response too large')
                result = json.loads(data)
                if not isinstance(result, dict):
                    raise ValueError('worker response must be an object')
                if response.will_close or not self.keep_alive:
                    self.close()
            self.last_used = time.monotonic()
            return result
        except Exception:
            self.close()
            raise


def worker_http_request(base, token, request, timeout):
    """One-off HTTP dispatch, retained for scripts and tests."""
    client = WorkerHTTPClient(base, token, timeout, keep_alive=False)
    try:
        return client.request(request)
    finally:
        client.close()


def validate_result(response, case):
    result = response['result']
    data = bytes.fromhex(result['hex'])
    if result['bytes'] != len(data):
        raise ValueError('result length does not match the returned bytes')
    validation = case['validation']
    kind = validation['kind']
    if kind == 'hex':
        passed = data.hex() == validation['value'].lower()
    elif kind == 'length':
        passed = len(data) == validation['value']
    elif kind == 'utf8_contains':
        passed = validation['value'] in data.decode('utf-8')
    elif kind == 'clock':
        clock = json.loads(data)
        passed = (type(clock.get('seconds')) is int and clock['seconds'] >= 0
                  and type(clock.get('nanoseconds')) is int and 0 <= clock['nanoseconds'] < 1_000_000_000)
    else:
        raise ValueError('unsupported validator')
    if not passed:
        raise ValueError('workload result failed validation')


class CapacityError(Exception):
    pass


class ConflictError(Exception):
    pass


class Management:
    def __init__(self, args):
        self.cases = load_catalog(args.catalog)
        self.tenant = getattr(args, 'tenant_id', None)
        if self.tenant:
            self.cases = {name: self.cases[name] for name in args.allowed_cases}
        self.api_token = token_file(args.api_token_file)
        self.agent_token = token_file(args.agent_token_file)
        self.address = (args.agent_host, args.agent_port)
        self.worker_url = args.worker_url
        self.http_keep_alive = args.worker_http_keepalive
        self.timeout = args.agent_timeout
        self.max_history = args.max_history
        self.require_signed_jobs = getattr(args, 'require_signed_jobs', False)
        self.queue = queue.Queue(args.queue_size)
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.stop = threading.Event()
        directory = Path(args.state_dir)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_lock = (directory / '.lock').open('a')
        fcntl.flock(self.state_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.db = sqlite3.connect(directory / 'jobs.sqlite3', check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, request TEXT NOT NULL, status TEXT NOT NULL,
            accepted REAL NOT NULL, finished REAL, result TEXT)''')
        # Do not silently re-execute a workload after an interrupted response.
        self.db.execute('''UPDATE jobs SET status='unknown', finished=?, result=?
            WHERE status IN ('queued','running')''',
            (time.time(), json.dumps({'error': 'management restarted before completion; not replayed'})))
        self.db.commit()
        self.threads = [threading.Thread(target=self.worker, daemon=True, name=f'dispatch-{i}')
                        for i in range(args.dispatchers)]
        for thread in self.threads:
            thread.start()

    def submit(self, body):
        if not isinstance(body, dict) or set(body) - {'case', 'cache', 'job_id', 'job_ticket'}:
            raise ValueError('allowed fields: case, cache, job_id, job_ticket; run() takes no input')
        ticket = body.get('job_ticket')
        if self.require_signed_jobs and ticket is None:
            raise ValueError('a user-signed job ticket is required; management cannot sign on behalf of users')
        if ticket is not None and (not isinstance(ticket, dict) or set(ticket) != {'payload', 'signature'}
                or not isinstance(ticket.get('payload'), str) or len(ticket['payload'].encode()) > 4096
                or not isinstance(ticket.get('signature'), str) or not re.fullmatch('[0-9a-f]{128}', ticket['signature'])):
            raise ValueError('invalid job ticket envelope')
        name = body.get('case')
        if not isinstance(name, str) or name not in self.cases:
            raise ValueError('unknown case')
        policy = body.get('cache', 'reuse')
        if policy not in ('reuse', 'bypass'):
            raise ValueError('cache must be reuse or bypass')
        job_id = body.get('job_id', str(uuid.uuid4()))
        if not isinstance(job_id, str) or not NAME.fullmatch(job_id):
            raise ValueError('invalid job_id')
        case = self.cases[name]
        # Pin the complete metadata in the durable job, even if the catalog is
        # later replaced. Reusing an ID with different metadata is a conflict.
        request = {'case': name, 'cache': policy, 'component': case['artifact'],
                   'sha256': case['sha256'], 'artifact_bytes': case['artifact_bytes'],
                   'validation': case['validation']}
        if ticket is not None:
            # Forward the original signed bytes. Never re-sign or reinterpret the
            # user's claims; authorization happens independently at execution.
            request['job_ticket'] = ticket
        encoded = json.dumps(request, sort_keys=True)
        with self.lock:
            old = self.db.execute('SELECT request FROM jobs WHERE id=?', (job_id,)).fetchone()
            if old:
                if old[0] != encoded:
                    raise ConflictError('job_id already exists with different metadata')
                return self.get(job_id), False
            if self.queue.full():
                raise CapacityError('management queue is full')
            if self.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0] >= self.max_history:
                raise CapacityError('job history is full; archive it and start a new state directory')
            accepted = time.time()
            accepted_monotonic = time.perf_counter()
            self.db.execute('INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?)',
                            (job_id, encoded, 'queued', accepted, None, None))
            self.db.commit()
            self.queue.put_nowait((job_id, request, accepted_monotonic))
            return self.get(job_id), True

    def get(self, job_id):
        with self.lock:
            row = self.db.execute('SELECT request,status,accepted,finished,result FROM jobs WHERE id=?',
                                  (job_id,)).fetchone()
        if not row:
            return None
        request, status, accepted, finished, result = row
        return {'job_id': job_id, 'tenant': self.tenant, 'request': json.loads(request), 'status': status,
                'accepted_unix': accepted, 'finished_unix': finished,
                'response': json.loads(result) if result else None}

    def counts(self):
        with self.lock:
            return dict(self.db.execute('SELECT status,COUNT(*) FROM jobs GROUP BY status'))

    def worker_stats(self):
        # Use a separate connection; dispatcher connections belong to their
        # threads. The management API never exposes the worker's token.
        if not self.worker_url:
            return agent_request(self.address, self.agent_token, {'op': 'stats'}, min(10, self.timeout))
        client = WorkerHTTPClient(self.worker_url, self.agent_token, min(10, self.timeout), keep_alive=False)
        try:
            return client.stats()
        finally:
            client.close()

    def wait(self, job_id, seconds):
        deadline = time.monotonic() + seconds
        with self.changed:
            while True:
                job = self.get(job_id)
                if job is None or job['status'] not in ('queued', 'running'):
                    return job
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return job
                self.changed.wait(remaining)

    def worker(self):
        client = (WorkerHTTPClient(self.worker_url, self.agent_token, self.timeout, self.http_keep_alive)
                  if self.worker_url else None)
        try:
            self.dispatch_loop(client)
        finally:
            if client:
                client.close()

    def dispatch_loop(self, client):
        while not self.stop.is_set():
            try:
                job_id, request, accepted = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            start = time.perf_counter()
            with self.lock:
                self.db.execute("UPDATE jobs SET status='running' WHERE id=?", (job_id,))
                self.db.commit()
            status = 'unknown'
            response = {}
            try:
                payload = {
                    'protocol': 1, 'op': 'run', 'job_id': job_id, 'cache': request['cache'],
                    'component': request['component'], 'sha256': request['sha256'],
                    'artifact_bytes': request['artifact_bytes'],
                }
                if 'job_ticket' in request:
                    payload['job_ticket'] = request['job_ticket']
                native = (client.request(payload) if client else
                          agent_request(self.address, self.agent_token, payload, self.timeout))
                response['agent'] = native
                response['dispatch_connection_reused'] = client.last_connection_reused if client else False
                response['dispatch_http_keep_alive'] = self.http_keep_alive if client else False
                # Keep the existing "agent" JSON key for old consumers. It
                # contains the worker result; execution_mode identifies the path.
                response['execution_mode'] = native.get('execution_mode', 'wasm')
                response['dispatch_transport'] = 'http' if self.worker_url else 'tcp'
                if native.get('status') != 'ok':
                    status = 'unknown' if native.get('execution_outcome') == 'unknown' else 'failed'
                    response['error'] = native.get('error', native.get('status', 'invalid agent response'))
                else:
                    if (native.get('job_id') != job_id or native.get('sha256') != request['sha256']
                            or native.get('component') != request['component']):
                        raise ValueError('agent returned mismatched job metadata')
                    if self.tenant and native.get('tenant') != self.tenant:
                        raise ValueError('worker returned the wrong tenant')
                    try:
                        validate_result(native, {'validation': request['validation']})
                    except (ValueError, KeyError, TypeError) as error:
                        status = 'failed'
                        response.update(result_validation='failed', error=str(error))
                    else:
                        status = 'completed'
                        response['result_validation'] = 'passed'
            except Exception as error:
                # A timeout/disconnect cannot establish whether run() already
                # happened. There are intentionally no automatic execution retries.
                response['error'] = f'{type(error).__name__}: {error}'
            response['timings_ms'] = {
                'management_queue': (start - accepted) * 1000,
                'dispatch_round_trip': (time.perf_counter() - start) * 1000,
                'management_total': (time.perf_counter() - accepted) * 1000,
            }
            response['attestation_verified'] = False
            with self.lock:
                self.db.execute('UPDATE jobs SET status=?,finished=?,result=? WHERE id=?',
                                (status, time.time(), json.dumps(response), job_id))
                self.db.commit()
                self.changed.notify_all()
            self.queue.task_done()

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=self.timeout + 1)
        self.db.close()
        self.state_lock.close()


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid():
        raise ValueError('tenant state must be a private directory owned by this user')
    return path


class TenantManagement:
    """Each identity owns a distinct queue, database and worker credential.

    The operator token can inspect global worker statistics but cannot submit
    tenant jobs. A client cannot provide a tenant field in a request.
    """
    def __init__(self, args):
        self.api_token = token_file(args.api_token_file)
        self.agent_token = token_file(args.agent_token_file)
        self.worker_url = args.worker_url
        self.address = (args.agent_host, args.agent_port)
        self.timeout = args.agent_timeout
        self.http_keep_alive = args.worker_http_keepalive
        self.cases = {}
        self.tenants = []
        path = Path(args.tenant_policy)
        policy = json.loads(path.read_text())
        rows = policy.get('tenants', [])
        if policy.get('version') != 1 or not 1 <= len(rows) <= 64 or len(rows) * args.dispatchers > 128:
            raise ValueError('invalid policy; use 1..64 tenants and at most 128 total dispatchers')
        cases = load_catalog(args.catalog)
        configured, ids = [], set()
        credentials = {self.api_token, self.agent_token}
        for row in rows:
            identity = row['id']
            if not isinstance(identity, str) or not NAME.fullmatch(identity) or len(identity) > 64 or identity in ids or identity == 'legacy' or identity != identity.lower():
                raise ValueError('invalid or duplicate tenant id')
            ids.add(identity)
            allowed = row['cases']
            if not isinstance(allowed, list) or not allowed or len(allowed) != len(set(allowed)) or set(allowed) - cases.keys():
                raise ValueError('tenant cases must be a non-empty subset of the catalog')
            api_path = path.parent / row['api_token_file']
            worker_path = path.parent / row['worker_token_file']
            api_token, worker_token = token_file(api_path), token_file(worker_path)
            if api_token in credentials or worker_token in credentials or api_token == worker_token:
                raise ValueError('all tenant and operator credentials must be distinct')
            credentials.update((api_token, worker_token))
            configured.append((identity, allowed, api_path, worker_path))
        directory = private_directory(args.state_dir)
        self.state_lock = (directory / '.lock').open('a')
        fcntl.flock(self.state_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        root = private_directory(directory / 'tenants')
        try:
            for identity, allowed, api_path, worker_path in configured:
                child = copy.copy(args)
                child.tenant_id, child.allowed_cases = identity, allowed
                child.api_token_file, child.agent_token_file = api_path, worker_path
                child.state_dir = private_directory(root / identity)
                self.tenants.append(Management(child))
        except Exception:
            self.close()
            raise

    def authenticate(self, header):
        for tenant in self.tenants:
            if hmac.compare_digest(header.encode(), ('Bearer ' + tenant.api_token).encode()):
                return tenant
        if hmac.compare_digest(header.encode(), ('Bearer ' + self.api_token).encode()):
            return self
        return None

    def counts(self):
        return {tenant.tenant: tenant.counts() for tenant in self.tenants}

    def worker_stats(self):
        return Management.worker_stats(self)

    def close(self):
        for tenant in self.tenants:
            tenant.close()
        self.state_lock.close()


class HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, manager):
        self.manager = manager
        self.connections = threading.BoundedSemaphore(64)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(10)
            super().process_request_thread(request, address)
        finally:
            self.connections.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, payload):
        data = json.dumps(payload, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        root = self.server.manager
        header = self.headers.get('Authorization', '')
        self.manager = None
        self.operator = False
        if isinstance(root, TenantManagement):
            self.manager = root.authenticate(header)
            self.operator = self.manager is root
        elif hmac.compare_digest(header.encode(), ('Bearer ' + root.api_token).encode()):
            self.manager = root
        if self.manager is None:
            self.respond(401, {'error': 'unauthorized'})
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        url = urlsplit(self.path)
        if self.operator and url.path not in ('/health', '/v1/stats', '/v1/worker-stats'):
            return self.respond(403, {'error': 'operator token cannot access tenant jobs'})
        if url.path == '/v1/worker-stats' and getattr(self.manager, 'tenant', None):
            return self.respond(403, {'error': 'global worker statistics require the operator token'})
        if url.path == '/health':
            self.respond(200, {'status': 'ready', 'attestation_verified': False})
        elif url.path == '/v1/cases':
            self.respond(200, {'cases': list(self.manager.cases)})
        elif url.path == '/v1/stats':
            self.respond(200, {'jobs': self.manager.counts()})
        elif url.path == '/v1/worker-stats':
            try:
                result = self.manager.worker_stats()
            except Exception as error:
                return self.respond(502, {'error': f'worker statistics unavailable: {type(error).__name__}: {error}'})
            self.respond(200, result)
        elif url.path.startswith('/v1/jobs/') and NAME.fullmatch(url.path[9:]):
            try:
                query = parse_qs(url.query, strict_parsing=True) if url.query else {}
                if set(query) - {'wait'}:
                    raise ValueError('unsupported query parameter')
                seconds = float(query.get('wait', ['0'])[0])
                if not 0 <= seconds <= 20:
                    raise ValueError('wait must be between 0 and 20 seconds')
            except ValueError as error:
                return self.respond(400, {'error': str(error)})
            result = self.manager.wait(url.path[9:], seconds)
            self.respond(200 if result else 404, result or {'error': 'job not found'})
        else:
            self.respond(404, {'error': 'endpoint not found'})

    def do_POST(self):
        if not self.authorized():
            return
        if self.operator:
            return self.respond(403, {'error': 'use a tenant credential to submit jobs'})
        if self.path != '/v1/jobs':
            return self.respond(404, {'error': 'endpoint not found'})
        try:
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('chunked requests are not supported')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= LIMIT:
                raise ValueError('invalid Content-Length')
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError('incomplete request')
            job, created = self.manager.submit(json.loads(data))
            self.respond(202 if created else 200, job)
        except CapacityError as error:
            self.respond(429, {'error': str(error)})
        except ConflictError as error:
            self.respond(409, {'error': str(error)})
        except (ValueError, TypeError, KeyError) as error:
            self.respond(400, {'error': str(error)})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9000)
    p.add_argument('--agent-host', default='127.0.0.1')
    p.add_argument('--agent-port', type=int, default=9100)
    p.add_argument('--worker-url', help='HTTP execution endpoint, e.g. http://10.0.0.30:9100; replaces TCP dispatch')
    p.add_argument('--worker-http-keepalive', action=argparse.BooleanOptionalAction, default=True,
                   help='reuse a connection per dispatcher; disable to reproduce fresh connections')
    p.add_argument('--catalog', default='workloads.json')
    p.add_argument('--api-token-file', required=True)
    p.add_argument('--agent-token-file', '--worker-token-file', dest='agent_token_file', required=True)
    p.add_argument('--tenant-policy', help='enable per-tenant API credentials, cases and private job databases')
    p.add_argument('--require-signed-jobs', action='store_true', help='reject missing tickets early; execution host must independently require them too')
    p.add_argument('--state-dir', default='state/management')
    p.add_argument('--dispatchers', type=int, default=8)
    p.add_argument('--queue-size', type=int, default=256)
    p.add_argument('--max-history', type=int, default=10000)
    p.add_argument('--agent-timeout', type=float, default=180)
    args = p.parse_args()
    if args.worker_url:
        url = urlsplit(args.worker_url)
        try:
            port = url.port
        except ValueError:
            p.error('--worker-url has an invalid port')
        if (url.scheme not in ('http', 'https') or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment or url.path not in ('', '/')
                or (port is not None and not 1 <= port <= 65535)):
            p.error('--worker-url must be an HTTP(S) origin without credentials, query, or path')
    if not (1 <= args.dispatchers <= 128 and 1 <= args.queue_size <= 100000
            and args.max_history >= 1 and 1 <= args.agent_timeout <= 7200):
        p.error('invalid limits')
    manager = TenantManagement(args) if args.tenant_policy else Management(args)
    server = HTTPServer((args.bind, args.port), manager)
    print(json.dumps({'status': 'ready', 'listen': server.server_address,
                      'cases': list(manager.cases), 'tenant_isolation': bool(args.tenant_policy),
                      'worker_http_keepalive': bool(manager.worker_url and manager.http_keep_alive)}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        manager.close()


if __name__ == '__main__':
    main()
