"""Real HTTP -> TLS -> encrypted UDP regression checks; no Internet services."""
import base64
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'btl_btlmmt'))
from client import CollaborationClient
from security import client_context, create_identity, server_context
from server import CollaborationServer
from web_ui.server_web import Bridge, WebHTTPServer


class LANWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cert, key = create_identity(Path(cls.temp.name) / 'identity')
        cls.backend = CollaborationServer('127.0.0.1', 0, 0,
                                         tls_context=server_context(cert, key))
        cls.backend_thread = threading.Thread(target=cls.backend.start, daemon=True)
        cls.backend_thread.start()
        cls.addClassCleanup(cls.stop_backend)
        if not cls.backend.ready.wait(5):
            raise RuntimeError('Backend did not start')
        factory = partial(CollaborationClient, server_tcp_port=cls.backend.tcp_port,
                          tls_context=client_context(cert))
        cls.bridge = Bridge(factory, download_root=Path(cls.temp.name) / 'downloads')
        cls.addClassCleanup(cls.bridge.close)
        cls.web = WebHTTPServer(('0.0.0.0', 0), cls.bridge)
        cls.web_thread = threading.Thread(target=cls.web.serve_forever, daemon=True)
        cls.web_thread.start()
        cls.addClassCleanup(cls.stop_web)

    @classmethod
    def stop_backend(cls):
        cls.backend.stop()
        cls.backend_thread.join(10)
        if cls.backend_thread.is_alive():
            raise RuntimeError('Backend failed to stop')

    @classmethod
    def stop_web(cls):
        cls.web.shutdown()
        cls.web.server_close()
        cls.web_thread.join(5)

    def request(self, path, data=None, token='', *, address='127.0.0.1', host=None, origin=None):
        conn = http.client.HTTPConnection(address, self.web.server_port, timeout=15)
        authority = host or f'{address}:{self.web.server_port}'
        headers = {'Host': authority, 'X-Session-ID': token}
        if origin is not None:
            headers['Origin'] = origin
        if data is not None:
            headers['Content-Type'] = 'application/json'
            headers.setdefault('Origin', 'http://' + authority)
        try:
            conn.request('GET' if data is None else 'POST', path,
                         body=None if data is None else json.dumps(data), headers=headers)
            response = conn.getresponse()
            body = response.read()
            if response.getheader('Content-Type', '').startswith('application/json'):
                body = json.loads(body)
            return response.status, body
        finally:
            conn.close()

    def wait_status(self, token, predicate, address):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            code, status = self.request('/api/status', token=token, address=address)
            self.assertEqual(code, 200)
            if predicate(status):
                return status
            time.sleep(0.05)
        self.fail(f'Timed out waiting for session state: {status}')

    def exercise_clients(self, address):
        tokens = []
        try:
            def login(name):
                return self.request('/api/login', {'username': name}, address=address)
            with ThreadPoolExecutor(max_workers=3) as pool:
                results = list(pool.map(login, ('alice', 'bob', 'carol')))
            tokens = [body['session_id'] for code, body in results if code == 200]
            self.assertEqual([code for code, _ in results], [200] * 3, results)
            self.assertEqual(len(set(tokens)), 3)
            for token in tokens:
                self.wait_status(token, lambda s: len(s['peers']) == 3, address)

            self.assertEqual(login('alice')[0], 400)  # Duplicate names still rejected.
            code, result = self.request('/api/send', {'target': 'bob', 'message': 'LAN offline'},
                                        tokens[0], address=address)
            self.assertEqual(code, 200, result)
            self.assertEqual(result['delivered'], ['bob'])
            self.wait_status(tokens[1], lambda s: any(m['content'] == 'LAN offline'
                             for m in s['messages']), address)
            _, carol = self.request('/api/status', token=tokens[2], address=address)
            self.assertFalse(carol['messages'])

            code, result = self.request('/api/send', {'target': None, 'message': 'Hello LAN'},
                                        tokens[0], address=address)
            self.assertEqual(code, 200, result)
            self.assertCountEqual(result['delivered'], ['bob', 'carol'])

            content = b'offline LAN file\x00\xff' * 100
            code, upload = self.request('/api/upload', {
                'target': 'bob', 'filename': 'lan.bin',
                'filedata': base64.b64encode(content).decode('ascii')}, tokens[0], address=address)
            self.assertEqual(code, 202, upload)
            status = self.wait_status(tokens[0], lambda s: any(
                job['id'] == upload['transfer_id'] and job['state'] in ('done', 'error')
                for job in s['transfers']), address)
            self.assertEqual(status['transfers'][0]['state'], 'done', status['transfers'])
            received = self.wait_status(tokens[1], lambda s: any(
                m.get('file_id') for m in s['messages']), address)
            file_id = next(m['file_id'] for m in received['messages'] if m.get('file_id'))
            self.assertEqual(self.request('/api/download/' + file_id, token=tokens[1],
                                          address=address), (200, content))
            self.assertEqual(self.request('/api/download/' + file_id, token=tokens[2],
                                          address=address)[0], 404)
            self.assertEqual(self.request('/api/status', address=address),
                             (200, {'logged_in': False}))
        finally:
            for token in tokens:
                self.request('/api/logout', {}, token, address=address)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with self.backend.peers_lock:
                    if not self.backend.active_peers:
                        break
                time.sleep(0.02)

    def test_concurrent_login_chat_file_and_isolated_sessions(self):
        self.exercise_clients('127.0.0.1')

    @unittest.skipUnless(os.environ.get('COLLAB_TEST_LAN_IP'), 'Set COLLAB_TEST_LAN_IP to test a LAN interface')
    def test_lan_interface(self):
        address = os.environ['COLLAB_TEST_LAN_IP']
        for path in ('/', '/app.js'):
            self.assertEqual(self.request(path, address=address)[0], 200)
        self.exercise_clients(address)

    def test_host_and_origin_validation(self):
        port = self.web.server_port
        self.assertEqual(self.request('/', host=f'localhost:{port}')[0], 200)
        for host in (f'evil.example:{port}', f'192.0.2.99:{port}', f'0.0.0.0:{port}',
                     f'127.0.0.1:{port + 1}'):
            self.assertEqual(self.request('/', host=host)[0], 403, host)
        for origin in ('http://evil.example', 'null', f'http://localhost:{port}'):
            self.assertEqual(self.request('/api/login', {'username': 'intruder'},
                                          origin=origin)[0], 403, origin)

    def test_invitation_and_qr_are_local_and_no_session_required(self):
        with patch('web_ui.lan.lan_addresses', return_value=[{'ip': '192.168.1.31', 'interface': 'Wi-Fi'}]):
            code, info = self.request('/api/network')
            self.assertEqual(code, 200)
            entry = info['addresses'][0]
            self.assertEqual(entry['url'], f'http://192.168.1.31:{self.web.server_port}')
            code, svg = self.request(entry['qr_url'])
            self.assertEqual(code, 200)
            self.assertEqual(ET.fromstring(svg).tag, '{http://www.w3.org/2000/svg}svg')
            self.assertEqual(self.request('/api/invite-qr.svg?ip=203.0.113.8')[0], 404)
            self.assertEqual(self.request('/api/invite-qr.svg?ip=127.0.0.1')[0], 404)


if __name__ == '__main__':
    unittest.main()
