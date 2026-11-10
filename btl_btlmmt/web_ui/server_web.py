"""Local browser bridge for the v2 backend. No CLI/input loop or HTTP framework."""
import argparse
import base64
import binascii
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import queue
import secrets
import shutil
import sys
import tempfile
import threading
import time
from urllib.parse import quote, urlparse
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from application import ApplicationError
from client import CollaborationClient
from file_transfer import validate_filename
from protocol import validate_username
from security import client_context

ROOT = Path(__file__).resolve().parent
MAX_UPLOAD = 16 * 1024 * 1024
MAX_BODY = ((MAX_UPLOAD + 2) // 3) * 4 + 8192


class WebSession:
    def __init__(self, client):
        self.client = client
        self.lock = threading.RLock()
        self.history = deque(maxlen=500)
        self.files = {}
        self.jobs = {}
        self.closed = threading.Event()
        self.last_seen = time.monotonic()
        self.collector = threading.Thread(target=self._collect, daemon=True)
        self.collector.start()

    def record(self, **entry):
        with self.lock:
            self.history.append({**entry, 'time': time.strftime('%H:%M')})

    def _collect(self):
        while not self.closed.is_set():
            for receive, kind in ((self.client.receive_chat, 'chat'), (self.client.receive_file, 'file')):
                while not self.closed.is_set():
                    try:
                        event = receive(timeout=0)
                    except queue.Empty:
                        break
                    if kind == 'chat':
                        self.record(sender=event['sender'], target=None if event['broadcast'] else self.client.username,
                                    content=event['text'], type='broadcast' if event['broadcast'] else 'unicast')
                    else:
                        name = event['name']
                        with self.lock:
                            if len(self.files) >= 500:
                                self.files.pop(next(iter(self.files)))
                            self.files[event['file_id']] = (Path(event['path']), name)
                        self.record(sender=event['sender'], target=self.client.username,
                                    content=name, filename=name, file_id=event['file_id'], type='file')
            self.closed.wait(0.05)

    def status(self):
        with self.lock:
            return {'logged_in': self.client.connected and not self.closed.is_set(),
                    'username': self.client.username, 'peers': self.client.get_peers(),
                    'messages': list(self.history), 'transfers': [dict(job) for job in self.jobs.values()]}

    def close(self):
        self.closed.set()
        self.client.close()
        if self.collector is not threading.current_thread():
            self.collector.join(2)


class Bridge:
    def __init__(self, client_factory=None, download_root=None):
        self.client_factory = client_factory or CollaborationClient
        self.download_root = Path(download_root or ROOT.parents[1] / 'downloads' / 'web').resolve()
        self.sessions = {}
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.slots = threading.BoundedSemaphore(64)
        self.upload_slots = threading.BoundedSemaphore(8)
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.janitor = threading.Thread(target=self._expire, daemon=True)
        self.janitor.start()

    def login(self, username):
        validate_username(username)
        if not self.slots.acquire(blocking=False):
            raise BufferError('Maximum 64 web sessions')
        client = None
        session = None
        try:
            client = self.client_factory(username, download_dir=self.download_root / username)
            client.connect_and_authenticate()  # Returns only after server accepts login.
            session = WebSession(client)
            token = secrets.token_urlsafe(32)
            with self.lock:
                if self.stopped.is_set():
                    raise ConnectionError('Web bridge is stopping')
                self.sessions[token] = session
            return token
        except BaseException:
            if session is not None:
                session.close()
            elif client is not None:
                client.close()
            self.slots.release()
            raise

    def get(self, token):
        with self.lock:
            session = self.sessions.get(token)
            if session is not None:
                session.last_seen = time.monotonic()
            return session

    def logout(self, token):
        with self.lock:
            session = self.sessions.pop(token, None)
        if session is not None:
            session.close()
            self.slots.release()

    def _expire(self):
        while not self.stopped.wait(1):
            with self.lock:
                stale = [token for token, session in self.sessions.items()
                         if not session.client.connected or time.monotonic() - session.last_seen > 1800]
            for token in stale:
                self.logout(token)

    def upload(self, session, target, name, data):
        validate_username(target)
        validate_filename(name)
        if len(data) > MAX_UPLOAD:
            raise ValueError('Web uploads are limited to 16 MiB; use the Python API for larger files')
        if not self.upload_slots.acquire(blocking=False):
            raise BufferError('Upload queue is full')
        job_id = secrets.token_hex(16)
        try:
            with session.lock:
                if sum(job['state'] in ('queued', 'sending', 'verifying') for job in session.jobs.values()) >= 2:
                    raise BufferError('At most two active uploads per session')
                if len(session.jobs) >= 50:
                    oldest = next(key for key, job in session.jobs.items() if job['state'] in ('done', 'error'))
                    del session.jobs[oldest]
                session.jobs[job_id] = {'id': job_id, 'filename': name, 'target': target,
                                        'sent': 0, 'total': len(data), 'state': 'queued', 'error': None}
            future = self.executor.submit(self._transfer, session, job_id, target, name, data)
            future.add_done_callback(lambda _: self.upload_slots.release())
            return job_id
        except BaseException:
            with session.lock:
                session.jobs.pop(job_id, None)
            self.upload_slots.release()
            raise

    @staticmethod
    def _transfer(session, job_id, target, name, data):
        def progress(sent, total):
            if session.closed.is_set():
                raise ConnectionError('Session closed')
            with session.lock:
                session.jobs[job_id].update(sent=sent, total=total,
                                            state='verifying' if sent == total else 'sending')
        try:
            if session.closed.is_set():
                raise ConnectionError('Session closed')
            with session.lock:
                session.jobs[job_id]['state'] = 'sending'
            # Random directory isolates concurrent uploads; preserve the user's basename.
            with tempfile.TemporaryDirectory(prefix='collab-upload-') as directory:
                path = Path(directory) / name
                path.write_bytes(data)
                result = session.client.send_file(path, target, progress=progress)
            with session.lock:
                session.jobs[job_id].update(state='done', sent=len(data), result=result)
            if target != session.client.username:
                session.record(sender=session.client.username, target=target, content=name,
                               filename=name, type='file')
        except Exception as exc:
            with session.lock:
                session.jobs[job_id].update(state='error', error=str(exc))

    def close(self):
        self.stopped.set()
        with self.lock:
            tokens = list(self.sessions)
        for token in tokens:
            self.logout(token)
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.janitor.join(2)


class WebHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, bridge):
        self.bridge = bridge
        super().__init__(address, HTTPRequestHandler)


class HTTPRequestHandler(BaseHTTPRequestHandler):
    @property
    def web_server(self):
        return cast(WebHTTPServer, self.server)

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, format, *args):
        pass  # Do not log session tokens or uploaded data.

    def _json(self, status, data):
        raw = json.dumps(data, ensure_ascii=True).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(raw)

    def _same_origin(self):
        host = self.headers.get('Host', '')
        port = self.web_server.server_address[1]
        if host not in (f'127.0.0.1:{port}', f'localhost:{port}'):
            self._json(403, {'error': 'This bridge is available on localhost only'})
            return False
        origin = self.headers.get('Origin')
        if origin is not None and origin != 'http://' + host:
            self._json(403, {'error': 'Cross-origin request rejected'})
            return False
        return True

    def do_GET(self):
        if not self._same_origin():
            return
        path = urlparse(self.path).path
        if path in ('/', '/index.html', '/app.js'):
            file = ROOT / ('app.js' if path == '/app.js' else 'templates/index.html')
            raw = file.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript; charset=utf-8' if path == '/app.js' else 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(raw)
            return
        session = self.web_server.bridge.get(self.headers.get('X-Session-ID'))
        if path == '/api/status':
            self._json(200, session.status() if session else {'logged_in': False})
            return
        if session is None or not session.client.connected:
            self._json(401, {'error': 'Login required'})
            return
        if path.startswith('/api/download/'):
            file_id = path.rsplit('/', 1)[-1]
            with session.lock:
                entry = session.files.get(file_id)
            if entry is None:
                self._json(404, {'error': 'File not found in this session'})
                return
            file, name = entry
            try:
                source = file.open('rb')
            except OSError:
                self._json(404, {'error': 'File no longer available'})
                return
            with source:
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(file.stat().st_size))
                self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + quote(name, safe=''))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                shutil.copyfileobj(source, self.wfile)
            return
        self._json(404, {'error': 'Not found'})

    def do_POST(self):
        if not self._same_origin():
            return
        path = urlparse(self.path).path
        try:
            if self.headers.get('Transfer-Encoding'):
                raise ValueError('Chunked HTTP requests are not supported')
            size = int(self.headers.get('Content-Length', '0'))
            limit = MAX_BODY if path == '/api/upload' else 256 * 1024
            if not 0 <= size <= limit:
                self._json(413, {'error': 'Request too large'})
                return
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Truncated request')
            data = json.loads(raw) if raw else {}
            if not isinstance(data, dict):
                raise ValueError('JSON must be an object')
            if path == '/api/login':
                token = self.web_server.bridge.login(data.get('username'))
                self._json(200, {'success': True, 'session_id': token})
                return
            token = self.headers.get('X-Session-ID') or data.get('session_id')
            if not isinstance(token, str):
                self._json(401, {'error': 'Login required'})
                return
            if path == '/api/logout':
                self.web_server.bridge.logout(token)
                self._json(200, {'success': True})
                return
            session = self.web_server.bridge.get(token)
            if session is None or not session.client.connected:
                self._json(401, {'error': 'Login required'})
                return
            if path == '/api/send':
                target, message = data.get('target'), data.get('message')
                result = session.client.send_chat(message, recipient=target)
                if not isinstance(result, dict):
                    raise ValueError('Invalid delivery result')
                if target != session.client.username and (result['delivered'] or target is None):
                    session.record(sender=session.client.username, target=target, content=message,
                                   type='broadcast' if target is None else 'unicast', delivery=result)
                self._json(200, {'success': not result['failed'], **result})
            elif path == '/api/upload':
                encoded = data.get('filedata')
                if not isinstance(encoded, str):
                    raise ValueError('filedata must be base64')
                content = base64.b64decode(encoded, validate=True)
                job = self.web_server.bridge.upload(session, data.get('target'), data.get('filename'), content)
                self._json(202, {'success': True, 'transfer_id': job})
            else:
                self._json(404, {'error': 'Not found'})
        except (ValueError, TypeError, binascii.Error, ApplicationError) as exc:
            self._json(400, {'success': False, 'error': str(exc)})
        except (OSError, BufferError, RuntimeError) as exc:
            self._json(503, {'success': False, 'error': str(exc)})


def main():
    parser = argparse.ArgumentParser(description='Local web UI for collaboration backend v2')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--server', default='127.0.0.1')
    parser.add_argument('--tcp-port', type=int, default=8888)
    parser.add_argument('--ca')
    args = parser.parse_args()
    factory = partial(CollaborationClient, server_ip=args.server, server_tcp_port=args.tcp_port,
                      tls_context=client_context(args.ca))
    bridge = Bridge(factory)
    httpd = WebHTTPServer(('127.0.0.1', args.port), bridge)
    print(f'[WEB] http://127.0.0.1:{httpd.server_port} (no stdin required)', flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        bridge.close()


if __name__ == '__main__':
    main()
