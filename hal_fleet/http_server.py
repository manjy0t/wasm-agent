from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl
import threading
from .common import Error, canonical, parse


class HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, app, max_connections=64):
        self.app = app
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            # Handshakes run inside bounded workers, never in the accept loop.
            # One client that opens TCP and sends no TLS bytes cannot stall everyone.
            if isinstance(request, ssl.SSLSocket):
                request.settimeout(5)
                try:
                    request.do_handshake()
                except (OSError, ssl.SSLError):
                    self.shutdown_request(request)
                    return
            super().process_request_thread(request, address)
        finally:
            if hasattr(self.app, 'transport'):
                self.app.transport.close_thread()
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'HAL-Fleet/1'

    def setup(self):
        super().setup()
        self.connection.settimeout(15)
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *args):
        pass  # No authorization documents, credentials, or request bodies in logs.

    def respond(self, code, result):
        raw = result if isinstance(result, bytes) else canonical(result).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/wasm' if isinstance(result, bytes) else 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if code >= 400:
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        self.wfile.write(raw)

    def handle_api(self):
        try:
            body = None
            if self.command == 'POST':
                if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
                    raise Error('One Content-Length required; chunked bodies are not supported', 400)
                size = int(self.headers['Content-Length'])
                if not 1 <= size <= 24 * 1024 * 1024:
                    raise Error('Request body exceeds limit', 413)
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise Error('Incomplete request body')
                body = parse(raw)
            elif self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
                raise Error('GET takes no body')
            if self.path == '/health' and self.command == 'GET':
                return self.respond(200, {'status': 'ready', 'role': self.server.app.config['role'],
                                          'attestation_verified': False})
            if hasattr(self.server.app, 'handle_http'):
                result = self.server.app.handle_http(self.command, self.path, body, self.headers)
            else:
                result = self.server.app.handle(self.command, self.path, body)
            self.respond(200, result)
        except Error as exc:
            self.respond(exc.status, {'error': str(exc), 'code': exc.code})
        except (ValueError, TypeError, KeyError, AttributeError):
            self.respond(400, {'error': 'Invalid request fields', 'code': 'invalid_request'})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            # Local logs retain the traceback; clients never receive secret paths/configs.
            import traceback
            traceback.print_exc()
            self.respond(500, {'error': 'Service error; inspect service logs', 'code': 'internal_error'})

    do_GET = handle_api
    do_POST = handle_api


def make_server(config, app):
    host, port = config['listen'].rsplit(':', 1)
    server = HTTPServer((host, int(port)), app, config.get('max_connections', 64))
    if config.get('tls_cert'):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config['tls_cert'], config['tls_key'])
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server
