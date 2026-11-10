import base64
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'btl_btlmmt'))
from client import CollaborationClient
from protocol import MsgType, Packet
from security import create_identity, server_context, client_context
from server import CollaborationServer
from web_ui.server_web import Bridge, WebHTTPServer


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.03)
    return predicate()


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.errors = []
        previous = threading.excepthook
        threading.excepthook = self.errors.append
        self.addCleanup(setattr, threading, 'excepthook', previous)
        self.cert, key = create_identity(Path(self.temp.name) / 'keys')
        self.backend = CollaborationServer('127.0.0.1', 0, 0, tls_context=server_context(self.cert, key))
        self.backend_thread = threading.Thread(target=self.backend.start)
        self.backend_thread.start()
        self.assertTrue(self.backend.ready.wait(3))
        factory = partial(CollaborationClient, server_tcp_port=self.backend.tcp_port,
                          tls_context=client_context(self.cert), heartbeat_interval=0.1)
        self.bridge = Bridge(factory, Path(self.temp.name) / 'downloads')
        self.web = WebHTTPServer(('127.0.0.1', 0), self.bridge)
        self.web_thread = threading.Thread(target=self.web.serve_forever)
        self.web_thread.start()

    def tearDown(self):
        self.web.shutdown()
        self.web.server_close()
        self.web_thread.join(3)
        self.bridge.close()
        self.backend.stop()
        self.backend_thread.join(7)
        self.assertFalse(self.backend_thread.is_alive())
        self.assertEqual(self.errors, [])

    def http(self, path, data=None, token=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.web.server_port, timeout=20)
        try:
            request_headers = dict(headers or {})
            if token:
                request_headers['X-Session-ID'] = token
            if data is not None:
                request_headers['Content-Type'] = 'application/json'
            conn.request('POST' if data is not None else 'GET', path,
                         json.dumps(data).encode() if data is not None else None, request_headers)
            response = conn.getresponse()
            raw = response.read()
            body = json.loads(raw) if 'application/json' in response.getheader('Content-Type', '') else raw
            return response.status, body, dict(response.getheaders())
        finally:
            conn.close()

    def login(self, name):
        status, result, _ = self.http('/api/login', {'username': name})
        self.assertEqual(status, 200, result)
        return result['session_id']

    def status(self, token):
        return self.http('/api/status', token=token)[1]

    def test_login_duplicate_logout_and_no_cli(self):
        with patch('builtins.input', side_effect=EOFError('stdin closed')) as input_mock:
            alice = self.login('alice')
            status, result, _ = self.http('/api/login', {'username': 'alice'})
            self.assertEqual(status, 400)
            self.assertFalse(result['success'])
            self.assertTrue(self.status(alice)['logged_in'])
            self.assertEqual(len(self.bridge.sessions), 1)
            input_mock.assert_not_called()
            self.assertEqual(self.http('/api/logout', {}, alice)[0], 200)
            self.assertFalse(self.status(alice)['logged_in'])
            self.assertEqual(self.http('/api/send', {'target': None, 'message': 'late'}, alice)[0], 401)

    def test_concurrent_unicast_and_reliable_broadcast(self):
        alice, bob, carol = (self.login(name) for name in ('alice', 'bob', 'carol'))
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks = [pool.submit(self.http, '/api/send', {'target': 'bob', 'message': text}, token)
                     for text, token in (('from alice', alice), ('from carol', carol))]
            for task in tasks:
                self.assertTrue(task.result()[1]['success'])
        self.assertTrue(wait_until(lambda: len(self.status(bob)['messages']) == 2))
        self.assertEqual(sorted(message['content'] for message in self.status(bob)['messages']),
                         ['from alice', 'from carol'])
        drops = []
        def install_loss(transport):
            original = transport.send_datagram
            dropped = set()
            def send(raw):
                pkt = Packet.from_bytes(raw)
                if pkt.msg_type in (MsgType.STREAM_DATA, MsgType.ACK) and pkt.msg_type not in dropped:
                    dropped.add(pkt.msg_type)
                    drops.append(pkt.msg_type)
                    return
                original(raw)
            transport.send_datagram = send
        for transport in (self.backend.transport_for('bob'), self.backend.transport_for('carol'),
                          self.bridge.get(bob).client.transport, self.bridge.get(carol).client.transport):
            install_loss(transport)
        response = self.http('/api/send', {'target': None, 'message': 'broadcast with loss'}, alice)[1]
        self.assertEqual(set(response['delivered']), {'bob', 'carol'})
        for token in (bob, carol):
            self.assertTrue(wait_until(lambda: any(message['type'] == 'broadcast' for message in self.status(token)['messages'])))
            messages = self.status(token)['messages']
            self.assertEqual(sum(message['content'] == 'broadcast with loss' for message in messages), 1)
        self.assertTrue(drops)

    def test_upload_progress_name_content_and_download_ownership(self):
        alice, bob, carol = (self.login(name) for name in ('alice', 'bob', 'carol'))
        receiver = self.bridge.get(bob).client
        original = receiver.file_receiver.handle
        allow_second = threading.Event()
        reached_second = threading.Event()
        def slow_second(header, body):
            if header['op'] == 'file_block' and header['offset'] > 0:
                reached_second.set()
                allow_second.wait(5)
            return original(header, body)
        receiver.file_receiver.handle = slow_second
        content = bytes(range(256)) * 2048
        status, result, _ = self.http('/api/upload', {'target': 'bob', 'filename': 'gui_up.bin',
                                      'filedata': base64.b64encode(content).decode()}, alice)
        self.assertEqual(status, 202)
        job_id = result['transfer_id']
        try:
            self.assertTrue(reached_second.wait(4))
            transfer = next(job for job in self.status(alice)['transfers'] if job['id'] == job_id)
            self.assertEqual(transfer['sent'], 256 * 1024)
            self.assertEqual(transfer['total'], len(content))
            self.assertEqual(transfer['state'], 'sending')
        finally:
            allow_second.set()
        self.assertTrue(wait_until(lambda: self.status(alice)['transfers'][-1]['state'] == 'done'))
        self.assertTrue(wait_until(lambda: any(message['type'] == 'file' for message in self.status(bob)['messages'])))
        message = next(message for message in self.status(bob)['messages'] if message['type'] == 'file')
        self.assertEqual(message['filename'], 'gui_up.bin')
        status, actual, headers = self.http('/api/download/' + message['file_id'], token=bob)
        self.assertEqual(status, 200)
        self.assertEqual(hashlib.sha256(actual).digest(), hashlib.sha256(content).digest())
        self.assertIn('gui_up.bin', headers['Content-Disposition'])
        self.assertNotIn('GUI_', headers['Content-Disposition'])
        self.assertEqual(self.http('/api/download/' + message['file_id'], token=carol)[0], 404)
        self.assertEqual(self.http('/api/download/' + message['file_id'])[0], 401)

    def test_validation_static_paths_and_polling(self):
        status, html, _ = self.http('/')
        self.assertEqual(status, 200)
        self.assertIn(b'/app.js', html)
        js = self.http('/app.js')[1]
        self.assertNotIn(b'setInterval', js)
        self.assertEqual(js.count(b'setTimeout(pollStatus,'), 1)
        self.assertNotIn(b'innerHTML', js)
        self.assertEqual(self.http('/api/login', {'username': 'alice'}, headers={'Origin': 'http://evil.invalid'})[0], 403)
        token = self.login('alice')
        self.assertEqual(self.http('/api/upload', {'target': 'bob', 'filename': '../escape', 'filedata': 'YWJj'}, token)[0], 400)
        self.assertEqual(self.http('/api/upload', {'target': 'bob', 'filename': 'ok', 'filedata': '!!'}, token)[0], 400)
        for path in ('/.security/server.key', '/templates/index.html', '/../../README.md', '/temp_uploads/test'):
            self.assertEqual(self.http(path, token=token)[0], 404)

    def test_headless_subprocess_stays_logged_in(self):
        command = [sys.executable, '-B', str(Path(__file__).resolve().parents[1] / 'btl_btlmmt/web_ui/server_web.py'),
                   '--port', '0', '--tcp-port', str(self.backend.tcp_port), '--ca', str(self.cert)]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        lines = []
        reader = threading.Thread(target=lambda: lines.append(process.stdout.readline()), daemon=True)
        reader.start()
        try:
            reader.join(5)
            self.assertTrue(lines, 'Bridge startup did not report an address')
            port = int(lines[0].split('127.0.0.1:')[1].split()[0])
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            conn.request('POST', '/api/login', json.dumps({'username': 'headless'}), {'Content-Type': 'application/json'})
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            token = json.loads(response.read())['session_id']
            conn.close()
            time.sleep(0.3)
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            conn.request('GET', '/api/status', headers={'X-Session-ID': token})
            self.assertTrue(json.loads(conn.getresponse().read())['logged_in'])
            conn.close()
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=5)
            reader.join(2)
            process.stdout.close()
            process.stderr.close()


if __name__ == '__main__':
    unittest.main()
