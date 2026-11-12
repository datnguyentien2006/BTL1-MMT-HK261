"""Browser bridge for the v2 backend, usable on localhost or an offline LAN."""
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
from urllib.parse import parse_qs, quote, urlparse
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from application import ApplicationError
from client import CollaborationClient
from file_transfer import validate_filename
from protocol import validate_username
from security import client_context
from web_ui.lan import invitation_info, invitation_qr

ROOT = Path(__file__).resolve().parent
MAX_UPLOAD = 16 * 1024 * 1024
MAX_BODY = ((MAX_UPLOAD + 2) // 3) * 4 + 8192
WEB_IDLE_TIMEOUT = 90
PAGE_CLOSE_GRACE = 5


class WebSession:
    # Tạo trạng thái phiên web và chạy luồng thu thập tin nhắn, file từ client backend.
    def __init__(self, client):
        self.client = client
        self.lock = threading.RLock()
        self.history = deque(maxlen=500)
        self.files = {}
        self.jobs = {}
        self.closed = threading.Event()
        self.last_seen = time.monotonic()
        self.page_id = None
        self.close_after = None
        self.collector = threading.Thread(target=self._collect, daemon=True)
        self.collector.start()

    # Thêm một sự kiện kèm thời gian vào lịch sử của phiên web.
    def record(self, **entry):
        with self.lock:
            self.history.append({**entry, 'time': time.strftime('%H:%M')})

    # Thu thập chat và file đã nhận để cập nhật lịch sử cùng danh sách file tải xuống.
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

    # Chụp trạng thái đăng nhập, peer, tin nhắn và tiến độ truyền file cho giao diện.
    def status(self):
        with self.lock:
            return {'logged_in': self.client.connected and not self.closed.is_set(),
                    'username': self.client.username, 'peers': self.client.get_peers(),
                    'messages': list(self.history), 'transfers': [dict(job) for job in self.jobs.values()]}

    # Đóng client backend và chờ luồng thu thập sự kiện kết thúc.
    def close(self):
        self.closed.set()
        self.client.close()
        if self.collector is not threading.current_thread():
            self.collector.join(2)


class Bridge:
    # Khởi tạo bộ quản lý phiên web, giới hạn upload và các luồng chạy nền.
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

    # Đăng nhập client vào backend rồi cấp token dùng để truy cập phiên web.
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

    # Tra cứu phiên theo token và cập nhật thời điểm hoạt động gần nhất.
    def get(self, token, page_id=None):
        with self.lock:
            session = self.sessions.get(token)
            if session is not None:
                session.last_seen = time.monotonic()
                if page_id:
                    session.page_id = page_id
                    session.close_after = None
            return session

    # Hẹn đóng phiên khi trang rời đi; trang mới có thể nối lại trong thời gian chờ.
    def detach(self, token, page_id):
        with self.lock:
            session = self.sessions.get(token)
            if session is not None and page_id and session.page_id == page_id:
                if session.close_after is None:
                    session.close_after = time.monotonic() + PAGE_CLOSE_GRACE

    # Gỡ phiên web, đóng kết nối backend và trả lại suất đăng nhập.
    def logout(self, token):
        with self.lock:
            session = self.sessions.pop(token, None)
        if session is not None:
            session.close()
            self.slots.release()

    # Định kỳ đăng xuất các phiên mất kết nối hoặc không hoạt động quá lâu.
    def _expire(self):
        while not self.stopped.wait(1):
            self.expire_sessions()

    # Gỡ phiên hết hạn dưới khóa, rồi đóng client ngoài khóa để không chặn các phiên khác.
    def expire_sessions(self):
        now = time.monotonic()
        with self.lock:
            stale = [token for token, session in self.sessions.items()
                     if not session.client.connected
                     or now - session.last_seen >= WEB_IDLE_TIMEOUT
                     or (session.close_after is not None and now >= session.close_after)]
            sessions = [self.sessions.pop(token) for token in stale]
        for session in sessions:
            try:
                session.close()
            finally:
                self.slots.release()

    # Kiểm tra file tải lên, tạo công việc truyền file và đưa vào executor chạy nền.
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

    # Ghi nội dung upload vào file tạm, gửi đến người nhận và cập nhật kết quả công việc.
    @staticmethod
    def _transfer(session, job_id, target, name, data):
        # Cập nhật số byte đã gửi và trạng thái chờ xác minh cho công việc upload.
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

    # Đóng các phiên web, dừng executor và chờ luồng dọn phiên kết thúc.
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
    # Khởi tạo máy chủ HTTP nhiều luồng và gắn bộ quản lý phiên web.
    def __init__(self, address, bridge):
        self.bridge = bridge
        super().__init__(address, HTTPRequestHandler)


class HTTPRequestHandler(BaseHTTPRequestHandler):
    # Trả về máy chủ HTTP với kiểu WebHTTPServer để truy cập bridge.
    @property
    def web_server(self):
        return cast(WebHTTPServer, self.server)

    # Chuẩn bị kết nối HTTP và đặt timeout cho thao tác đọc/ghi.
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    # Tắt ghi log yêu cầu mặc định để tránh ghi token phiên hoặc dữ liệu tải lên.
    def log_message(self, format, *args):
        pass  # Do not log session tokens or uploaded data.

    # Gửi phản hồi JSON với mã HTTP, độ dài nội dung và chỉ dẫn không lưu cache.
    def _json(self, status, data):
        raw = json.dumps(data, ensure_ascii=True).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(raw)

    # Chấp nhận IP đích của kết nối LAN, vẫn kiểm tra Host và Origin cùng nguồn.
    def _same_origin(self):
        host = self.headers.get('Host', '')
        local_ip, port = self.connection.getsockname()[:2]
        # Use the actual destination interface, never trust arbitrary Host/DNS names
        # or the wildcard bind address. This also works when LAN DHCP changes IPs.
        names = [local_ip]
        if local_ip.startswith('127.'):
            names.append('localhost')
        allowed_hosts = {f'{name}:{port}' for name in names}
        if port == 80:
            allowed_hosts.update(names)
        if host not in allowed_hosts:
            self._json(403, {'error': 'Use the IP address of this web server'})
            return False
        origin = self.headers.get('Origin')
        if origin is not None and origin != 'http://' + host:
            self._json(403, {'error': 'Cross-origin request rejected'})
            return False
        return True

    # Phục vụ giao diện, trạng thái phiên hoặc tải file thuộc phiên đang đăng nhập.
    def do_GET(self):
        if not self._same_origin():
            return
        path = urlparse(self.path).path
        if path in ('/api/network', '/api/invite-qr.svg'):
            info = invitation_info(*self.web_server.server_address[:2],
                                   destination_ip=self.connection.getsockname()[0])
            if path == '/api/network':
                self._json(200, info)
                return
            ip = parse_qs(urlparse(self.path).query).get('ip', [''])[0]
            entry = next((entry for entry in info['addresses'] if entry['ip'] == ip), None)
            if entry is None:
                self._json(404, {'error': 'LAN address is no longer available; refresh the invitation'})
                return
            raw = invitation_qr(entry['url'])
            self.send_response(200)
            self.send_header('Content-Type', 'image/svg+xml')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(raw)
            return
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
        session = self.web_server.bridge.get(
            self.headers.get('X-Session-ID'),
            self.headers.get('X-Page-ID') if path == '/api/status' else None)
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

    # Đọc và kiểm tra JSON để xử lý đăng nhập, đăng xuất, gửi chat hoặc upload file.
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
            if path == '/api/detach':
                page_id = data.get('page_id')
                if not isinstance(page_id, str) or not 1 <= len(page_id) <= 128:
                    raise ValueError('Invalid page ID')
                self.web_server.bridge.detach(token, page_id)
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


# Đọc tham số dòng lệnh, khởi động cầu nối web và đóng tài nguyên khi kết thúc.
def main():
    parser = argparse.ArgumentParser(description='Offline LAN web UI for collaboration backend v2')
    parser.add_argument('--host', default='0.0.0.0',
                        help='HTTP bind address (default: all IPv4 interfaces; 127.0.0.1 for local only)')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--server', default='127.0.0.1')
    parser.add_argument('--tcp-port', type=int, default=8888)
    parser.add_argument('--ca')
    args = parser.parse_args()
    factory = partial(CollaborationClient, server_ip=args.server, server_tcp_port=args.tcp_port,
                      tls_context=client_context(args.ca))
    bridge = Bridge(factory)
    httpd = None
    try:
        httpd = WebHTTPServer((args.host, args.port), bridge)
        bound_ip = httpd.server_address[0]
        display_host = '127.0.0.1' if bound_ip == '0.0.0.0' else bound_ip
        print(f'[WEB] Tren may server / This computer: http://{display_host}:{httpd.server_port}', flush=True)
        info = invitation_info(bound_ip, httpd.server_port)
        for entry in info['addresses']:
            print(f"[WEB] May khac cung LAN / Other devices ({entry['interface']}): {entry['url']}", flush=True)
        if info['local_only']:
            print('[WEB] Local only. Use --host 0.0.0.0 to allow other LAN devices.', flush=True)
        elif not info['addresses']:
            print('[WEB] No LAN IPv4 found. Connect Wi-Fi/Ethernet, then refresh the invitation on the login page.', flush=True)
        print('[WEB] 127.0.0.1 always means the device opening the browser. LAN needs no Internet.', flush=True)
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if httpd is not None:
            httpd.server_close()
        bridge.close()


if __name__ == '__main__':
    main()
