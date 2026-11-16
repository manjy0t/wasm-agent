#!/usr/bin/env python3
"""Serve only top-level .wasm components from a dedicated directory for experiments."""
import argparse
import hmac
from datetime import datetime, timezone
import functools
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import threading
from urllib.parse import unquote, urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WasmExperimentServer/1"

    def __init__(self, *args, directory, max_bytes, allowed_clients=(), close_connections=False, token=None, **kwargs):
        self.token = token
        self.directory = directory
        self.max_bytes = max_bytes
        self.allowed_clients = frozenset(allowed_clients)
        self.close_connections = close_connections
        super().__init__(*args, **kwargs)

    def setup(self):
        super().setup()
        self.connection.settimeout(10)
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, format_string, *args):
        # JSON-escape paths so terminal control characters cannot affect logs.
        print(json.dumps({"time": datetime.now(timezone.utc).isoformat(), "peer": self.client_address[0],
                          "message": format_string % args}), file=sys.stderr, flush=True)

    def do_GET(self):
        self.serve(send_body=True)

    def do_HEAD(self):
        self.serve(send_body=False)

    def serve(self, send_body):
        if self.token is not None and not hmac.compare_digest(
                self.headers.get('Authorization', '').encode(), ('Bearer ' + self.token).encode()):
            self.send_error(401, 'Unauthorized')
            return
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
            self.send_error(400, 'Artifact requests take no body')
            return
        # Match the TCP peer; do not trust a client-supplied forwarding header.
        if self.allowed_clients and ipaddress.ip_address(self.client_address[0]) not in self.allowed_clients:
            self.send_error(403, "Client address is not allowed")
            return
        decoded = unquote(urlsplit(self.path).path)
        name = decoded[1:] if decoded.startswith("/") else ""
        if not name or "/" in name or "\\" in name or "\x00" in name or not name.endswith(".wasm"):
            self.send_error(404, "Use a component filename, such as /function2.wasm")
            return
        candidate = self.directory / name
        if candidate.is_symlink() or candidate.resolve().parent != self.directory or not candidate.is_file():
            self.send_error(404, "Component not found")
            return
        try:
            with candidate.open("rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                if size > self.max_bytes or stream.read(8) != b"\0asm\x0d\0\x01\0":
                    self.send_error(422, "File is too large or is not a Wasm component")
                    return
                stream.seek(0)
                self.send_response(200)
                self.send_header("Content-Type", "application/wasm")
                self.send_header("Content-Length", str(size))
                self.send_header("Cache-Control", "no-store")
                if self.close_connections:
                    self.send_header("Connection", "close")
                self.end_headers()
                if send_body:
                    shutil.copyfileobj(stream, self.wfile)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
            return
        except OSError as error:
            self.close_connection = True
            self.log_error("File read failed: %s", error)


class HTTPServer(ThreadingHTTPServer):
    """Bound persistent connections; each handler also has a 10-second timeout."""
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, handler):
        self.connections = threading.BoundedSemaphore(128)
        super().__init__(address, handler)

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
            super().process_request_thread(request, address)
        finally:
            self.connections.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", type=Path, help="require an execution-host bearer token for GET and HEAD")
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    parser.add_argument("--max-bytes", default=16 * 1024 * 1024, type=int)
    parser.add_argument("--close-connections", action="store_true",
                        help="disable HTTP connection reuse to reproduce the earlier server")
    parser.add_argument("--allow-client", action="append", default=[], type=ipaddress.IPv4Address,
                        help="Allow only these peer IPv4 addresses; repeat for multiple clients. Omit to allow any peer.")
    args = parser.parse_args()
    directory = args.directory.expanduser().resolve()
    if not directory.is_dir() or not 1 <= args.port <= 65535 or args.max_bytes < 8:
        parser.error("Use an existing directory, port 1..65535 and max-bytes >= 8")
    token = args.token_file.read_text().strip() if args.token_file else None
    if token is not None and (not 32 <= len(token) <= 256 or not all(33 <= ord(c) <= 126 for c in token)):
        parser.error('token must be 32..256 printable ASCII characters')
    handler = functools.partial(Handler, token=token, directory=directory, max_bytes=args.max_bytes,
                                allowed_clients=args.allow_client, close_connections=args.close_connections)
    server = HTTPServer((args.bind, args.port), handler)
    print(f"Serving .wasm components from {directory} on {args.bind}:{args.port}", flush=True)
    print(f"HTTP connection reuse: {not args.close_connections}; workload downloads are not cached by this server.", flush=True)
    if args.allow_client:
        print("Allowed peer addresses: " + ", ".join(map(str, args.allow_client)), flush=True)
    print("The listening address does not assign a public IP or configure router/cloud firewall rules.", flush=True)
    print("This file server has no job queue, result-upload endpoint or TLS; bearer authentication is optional.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
