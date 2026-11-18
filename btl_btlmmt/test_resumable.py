import hashlib
import base64
import http.client
import json
from types import SimpleNamespace
from pathlib import Path
import queue
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from client import CollaborationClient
from file_transfer import FileReceiver, FILE_BLOCK_SIZE
from security import create_identity, server_context, client_context
from server import CollaborationServer
from web_ui.durable_uploads import UploadStore
from web_ui.server_web import Bridge, WebHTTPServer


class ResumeTests(unittest.TestCase):
    def test_http_chunk_api_and_rejected_unauthenticated_upload(self):
        with tempfile.TemporaryDirectory() as folder:
            store = UploadStore(folder)
            session = SimpleNamespace(client=SimpleNamespace(username='alice', connected=True))
            bridge = SimpleNamespace(uploads=store, get=lambda token, *args: session if token == 'test-token' else None)
            httpd = WebHTTPServer(('127.0.0.1', 0), bridge)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            def post(path, data, token='test-token'):
                conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=5)
                try:
                    conn.request('POST', path, json.dumps(data),
                                 {'Content-Type': 'application/json', 'X-Session-ID': token})
                    response = conn.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    conn.close()
            try:
                data = dict(target='bob', filename='x.bin', size=262144, key='e' * 32)
                self.assertEqual(post('/api/upload/begin', data, '')[0], 401)
                status, row = post('/api/upload/begin', data)
                self.assertEqual(status, 200)
                status, row = post('/api/upload/chunk', dict(id=row['id'], offset=0,
                    filedata=base64.b64encode(b'x' * 262144).decode()))
                self.assertEqual(status, 200)
                self.assertEqual(row['offset'], 262144)
                self.assertEqual(row['state'], 'waiting')
                status, row = post('/api/upload/finish', dict(id=row['id']))
                self.assertEqual(status, 200)
                self.assertEqual(row['state'], 'waiting')
            finally:
                httpd.shutdown()
                httpd.server_close()
                worker.join(5)

    def test_upload_restart_retry_and_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            store = UploadStore(folder)
            row = store.begin('alice', 'bob', 'x.bin', 6, 'a' * 32)
            store.chunk('alice', row['id'], 0, b'abc')
            store = UploadStore(folder)
            self.assertEqual(store.begin('alice', 'bob', 'x.bin', 6, 'a' * 32)['offset'], 3)
            self.assertEqual(store.chunk('alice', row['id'], 0, b'abc')['offset'], 3)
            with self.assertRaises(ValueError):
                store.chunk('mallory', row['id'], 3, b'def')
            with self.assertRaises(ValueError):
                store.finish('alice', row['id'])
            self.assertEqual(store.chunk('alice', row['id'], 3, b'def')['state'], 'waiting')
            self.assertEqual(store.finish('alice', row['id'])['state'], 'waiting')
            empty = store.begin('alice', 'bob', 'empty.txt', 0, 'f' * 32)
            self.assertEqual(empty['state'], 'waiting')

    def test_done_jobs_and_corrupt_checkpoints_do_not_block_uploads(self):
        with tempfile.TemporaryDirectory() as folder:
            store = UploadStore(folder)
            for index in range(1000):
                job_id = format(index, '032x')
                (Path(folder) / (job_id + '.json')).write_text(json.dumps(dict(
                    id=job_id, key=job_id, sender='alice', target='bob', filename='x.bin',
                    total=1, offset=1, sent=1, state='done', error=None)))
            corrupt = 'f' * 32
            (Path(folder) / (corrupt + '.json')).write_text('{truncated')
            self.assertEqual(len(store.jobs()), 1000)
            row = store.begin('alice', 'bob', 'new.bin', 4, 'b' * 32)
            self.assertEqual(row['offset'], 0)
            # Only recent history is kept, so completed transfers cannot exhaust the quota.
            self.assertLessEqual(len(store.jobs()), 201)
            with self.assertRaises(ValueError):
                store.chunk('alice', corrupt, 0, b'x')

    def test_receiver_restart_and_lost_completion_ack(self):
        with tempfile.TemporaryDirectory() as folder:
            payload = b'abcdef'
            header = dict(sender='alice', sender_session='a' * 64, file_id='b' * 32,
                          resumable=True, name='x.bin', size=6, sha256=hashlib.sha256(payload).hexdigest())
            recv = FileReceiver(folder, queue.Queue())
            recv.handle(dict(header, op='file_begin'), b'')
            recv.handle(dict(header, op='file_block', offset=0), b'abc')
            recv.discard_sender('alice')
            recv.close()
            recv = FileReceiver(folder, queue.Queue())
            header['sender_session'] = 'c' * 64
            self.assertEqual(recv.handle(dict(header, op='file_begin'), b'')['offset'], 3)
            recv.handle(dict(header, op='file_block', offset=3), b'def')
            recv.handle(dict(header, op='file_end'), b'')
            recv.close()
            recv = FileReceiver(folder, queue.Queue())
            self.assertEqual(recv.handle(dict(header, op='file_begin'), b'')['offset'], 6)
            recv.handle(dict(header, op='file_end'), b'')
            self.assertEqual(len(list(Path(folder).glob('*_x.bin'))), 1)
            self.assertEqual(next(Path(folder).glob('*_x.bin')).read_bytes(), payload)

    def test_real_udp_resume_and_offline_outbox_after_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cert, key = create_identity(root / 'tls')
            server = CollaborationServer('127.0.0.1', 0, 0, tls_context=server_context(cert, key),
                                         user_db=root / 'users.db')
            thread = threading.Thread(target=server.start, daemon=True)
            thread.start()
            self.assertTrue(server.ready.wait(5))
            def factory(name, **kwargs):
                return CollaborationClient(name, server_ip='127.0.0.1', server_tcp_port=server.tcp_port,
                                           tls_context=client_context(cert), **kwargs)
            alice = factory('alice', download_dir=root / 'alice')
            bob = factory('bob', download_dir=root / 'bob')
            bridge = None
            try:
                alice.connect_and_authenticate()
                bob.connect_and_authenticate()
                source = root / 'example.bin'
                content = b'a' * FILE_BLOCK_SIZE + b'last-block'
                source.write_bytes(content)
                def interrupt(sent, total):
                    raise ConnectionError('Injected sender interruption')
                with self.assertRaises(ConnectionError):
                    alice.send_file(source, 'bob', file_id='c' * 32, progress=interrupt)
                bob.close()
                deadline = time.monotonic() + 5
                while 'bob' in server.active_peers and time.monotonic() < deadline:
                    time.sleep(.02)
                bob = factory('bob', download_dir=root / 'bob')
                bob.connect_and_authenticate()
                progress = []
                alice.send_file(source, 'bob', file_id='c' * 32, progress=lambda sent, total: progress.append(sent))
                self.assertEqual(progress, [len(content)])
                event = bob.receive_file(timeout=5)
                self.assertEqual(Path(event['path']).read_bytes(), content)
                alice.close()
                bob.close()
                bridge = Bridge(factory, root / 'downloads', root / 'outbox')
                token = bridge.login('alice')
                bridge.get(token, 'sender-tab')
                job = bridge.uploads.begin('alice', 'bob', 'offline.txt', 5, 'd' * 32)
                bridge.uploads.chunk('alice', job['id'], 0, b'hello')
                # The tab closes after its final chunk without calling /finish.
                with patch('web_ui.server_web.PAGE_CLOSE_GRACE', 0):
                    bridge.detach(token, 'sender-tab')
                bridge.expire_sessions()
                self.assertIsNone(bridge.get(token))
                self.assertEqual(bridge.uploads.jobs()[0]['state'], 'waiting')
                bridge.close()
                bridge = Bridge(factory, root / 'downloads', root / 'outbox')
                token = bridge.login('bob')
                deadline = time.monotonic() + 15
                while bridge.uploads.jobs()[0]['state'] != 'done' and time.monotonic() < deadline:
                    time.sleep(.1)
                self.assertEqual(bridge.uploads.jobs()[0]['state'], 'done')
                time.sleep(.2)
                self.assertIn(job['id'], bridge.get(token).files)
                bridge.logout(token)
                time.sleep(.2)
                token = bridge.login('bob')
                self.assertIn(job['id'], bridge.get(token).files)
            finally:
                if bridge:
                    bridge.close()
                alice.close()
                bob.close()
                server.stop()
                thread.join(10)


if __name__ == '__main__':
    unittest.main()
