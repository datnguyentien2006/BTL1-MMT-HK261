import ssl
from concurrent.futures import ThreadPoolExecutor
import hashlib
import queue
import tempfile
import uuid
import socket
import struct
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'btl_btlmmt'))
from client import CollaborationClient
from protocol import (HEADER_FORMAT, MAX_PAYLOAD_SIZE, MsgType, Packet,
                      PacketFlags, recv_tcp_packet)
from server import CollaborationServer
from security import create_identity, server_context, client_context, SessionCipher
from application import ApplicationError
from file_transfer import FILE_BLOCK_SIZE


def wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class ProtocolTests(unittest.TestCase):
    def test_roundtrip_and_corruption(self):
        raw = Packet(MsgType.HEARTBEAT, payload=b'abc').to_bytes()
        self.assertEqual(Packet.from_bytes(raw).payload, b'abc')
        corrupt = bytearray(raw)
        corrupt[-1] ^= 1
        for invalid in (raw + b'extra', raw[:-1], bytes(corrupt)):
            with self.assertRaises(ValueError):
                Packet.from_bytes(invalid)

    def test_payload_limits_and_mutation(self):
        pkt = Packet(MsgType.FILE_CHUNK, payload=b'x' * MAX_PAYLOAD_SIZE)
        self.assertEqual(len(Packet.from_bytes(pkt.to_bytes()).payload), MAX_PAYLOAD_SIZE)
        pkt.payload = b'a'
        self.assertEqual(Packet.from_bytes(pkt.to_bytes()).payload, b'a')
        pkt.payload = b'x' * (MAX_PAYLOAD_SIZE + 1)
        with self.assertRaises(ValueError):
            pkt.to_bytes()

    def test_reject_large_header_before_reading_body(self):
        header = struct.pack(HEADER_FORMAT, MsgType.AUTH_REQ, 1, 0, 0, 0, 64,
                             MAX_PAYLOAD_SIZE + 1, 0, 0)
        sock = Mock()
        sock.recv.return_value = header
        with self.assertRaises(ValueError):
            recv_tcp_packet(sock)
        sock.recv.assert_called_once()
        with self.assertRaises(ValueError):
            Packet.from_bytes(header + b'x' * (MAX_PAYLOAD_SIZE + 1))

    def test_json_must_be_object(self):
        for payload in (b'[]', b'null', b'123', b'bad', b'"name"'):
            with self.assertRaises(ValueError):
                Packet(MsgType.AUTH_REQ, payload=payload).decode_json()

    def test_fragmented_and_coalesced_tcp_frames(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        b.settimeout(2)
        raw = Packet(MsgType.HEARTBEAT, payload=b'abc').to_bytes()
        def send():
            for part in (raw[:3], raw[3:20], raw[20:] + raw):
                a.sendall(part)
        worker = threading.Thread(target=send)
        worker.start()
        self.assertEqual(recv_tcp_packet(b).payload, b'abc')
        self.assertEqual(recv_tcp_packet(b).payload, b'abc')
        worker.join()


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.thread_errors = []
        old_hook = threading.excepthook
        threading.excepthook = self.thread_errors.append
        self.addCleanup(setattr, threading, 'excepthook', old_hook)
        cert, key = create_identity(Path(self.temp.name) / 'keys')
        self.client_tls = client_context(cert)
        self.server = CollaborationServer('127.0.0.1', 0, 0, session_timeout=1.0,
                                          tls_context=server_context(cert, key))
        self.thread = threading.Thread(target=self.server.start)
        self.thread.start()
        self.assertTrue(self.server.ready.wait(3))
        self.clients = []
        self.sockets = []

    def tearDown(self):
        for client in self.clients:
            client.close()
        for sock in self.sockets:
            sock.close()
        self.server.stop()
        self.thread.join(7)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.server.active_peers, {})
        self.assertEqual(self.thread_errors, [], 'Unexpected worker thread exception')

    def client(self, name):
        client = CollaborationClient(name, server_tcp_port=self.server.tcp_port,
                                     heartbeat_interval=0.1, download_dir=Path(self.temp.name) / name, tls_context=self.client_tls)
        self.clients.append(client)
        client.connect_and_authenticate()
        return client

    def raw(self, handshake=True):
        sock = socket.create_connection(('127.0.0.1', self.server.tcp_port), timeout=2)
        sock = self.client_tls.wrap_socket(sock, server_hostname='127.0.0.1')
        self.sockets.append(sock)
        if handshake:
            sock.sendall(Packet(MsgType.HANDSHAKE_SYN, flags=PacketFlags.EOM).to_bytes())
            self.assertEqual(recv_tcp_packet(sock).msg_type, MsgType.HANDSHAKE_ACK)
        return sock

    def auth(self, sock, data):
        sock.sendall(Packet(MsgType.AUTH_REQ, flags=PacketFlags.EOM,
                            payload=Packet.json_payload(data)).to_bytes())
        return recv_tcp_packet(sock).decode_json()

    def test_duplicate_and_reauth_do_not_corrupt_owner(self):
        alice = self.raw()
        self.assertTrue(self.auth(alice, {'username': 'alice', 'udp_port': 12344})['success'])
        rejected = self.raw()
        self.assertFalse(self.auth(rejected, {'username': 'alice', 'udp_port': 12345})['success'])
        rejected.close()
        self.assertFalse(self.auth(alice, {'username': 'bob', 'udp_port': 12345})['success'])
        self.assertEqual(set(self.server.active_peers), {'alice'})
        alice.close()
        self.assertTrue(wait_until(lambda: not self.server.active_peers))
        self.client('alice')
        self.assertEqual(set(self.server.active_peers), {'alice'})

    def test_state_and_input_validation(self):
        sock = self.raw(False)
        self.assertFalse(self.auth(sock, {'username': 'alice', 'udp_port': 12345})['success'])
        sock = self.raw()
        for data in ([], {}, {'username': '', 'udp_port': 1},
                     {'username': 'a' * 33, 'udp_port': 1},
                     {'username': 'alice', 'udp_port': True},
                     {'username': 'alice', 'udp_port': 65536},
                     {'username': 'alice', 'udp_port': '9000'}):
            self.assertFalse(self.auth(sock, data)['success'])
        self.assertEqual(self.server.active_peers, {})

    def test_twenty_clients_and_paged_snapshot(self):
        # Long valid names force multiple AUTH_RES packets even on localhost.
        for i in range(20):
            last = self.client(f'student_{i:024d}')
        self.assertEqual(len(last.peers), 20)
        self.assertEqual(len(self.server.active_peers), 20)
        time.sleep(1.3)
        self.assertEqual(len(self.server.active_peers), 20)

    def test_missing_heartbeat_expires_session(self):
        sock = self.raw()
        self.assertTrue(self.auth(sock, {'username': 'idle', 'udp_port': 12345})['success'])
        self.assertTrue(wait_until(lambda: 'idle' not in self.server.active_peers))
        self.assertEqual(sock.recv(1), b'')

    def test_heartbeat_requires_token_and_source(self):
        sock = self.raw()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        self.sockets.append(udp)
        data = self.auth(sock, {'username': 'alice', 'udp_port': udp.getsockname()[1]})
        cipher = SessionCipher(data['session_id'], data['udp_secret'], is_client=True)
        original = self.server.active_peers['alice']['last_seen']
        def send(source, token):
            source.sendto(cipher.seal(Packet(MsgType.HEARTBEAT, flags=PacketFlags.EOM,
                                 payload=Packet.json_payload({'username': 'alice',
                                                              'session_id': token})).to_bytes()),
                          ('127.0.0.1', self.server.udp_port))
        send(udp, '0' * 64)
        other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockets.append(other)
        send(other, data['session_id'])
        time.sleep(0.15)
        self.assertEqual(self.server.active_peers['alice']['last_seen'], original)
        send(udp, data['session_id'])
        self.assertTrue(wait_until(lambda: self.server.active_peers['alice']['last_seen'] > original))

    def test_live_join_leave_and_timeout(self):
        alice = self.client('alice')
        bob = self.client('bob')
        self.assertTrue(wait_until(lambda: {p['user'] for p in alice.get_peers()} == {'alice', 'bob'}))
        bob.close()
        self.assertTrue(wait_until(lambda: {p['user'] for p in alice.get_peers()} == {'alice'}))
        idle = self.raw()
        self.assertTrue(self.auth(idle, {'username': 'idle', 'udp_port': 12345})['success'])
        self.assertTrue(wait_until(lambda: any(p['user'] == 'idle' for p in alice.get_peers())))
        self.assertTrue(wait_until(lambda: all(p['user'] != 'idle' for p in alice.get_peers())))

    def test_bidirectional_udp_streams(self):
        client = self.client('alice')
        data = bytes(range(256)) * 200
        receipt = client.send_stream(data)
        sid, actual = self.server.receive_stream('alice', timeout=3)
        self.assertEqual((sid, actual), (receipt.stream_id, data))
        receipt.wait(3)
        receipt = self.server.send_stream('alice', data[::-1])
        self.assertEqual(client.receive_stream(3), (receipt.stream_id, data[::-1]))
        receipt.wait(3)

    def test_chat_unicast_broadcast_and_identity(self):
        alice, bob, carol = self.client('alice'), self.client('bob'), self.client('carol')
        text = 'hello ' * 3000
        self.assertEqual(alice.send_chat(text, 'bob'), {'delivered': ['bob'], 'failed': {}})
        self.assertEqual(bob.receive_chat(2), {'sender': 'alice', 'text': text, 'broadcast': False})
        with self.assertRaises(queue.Empty):
            carol.receive_chat(0)
        result = alice.app.request('chat', b'global', sender='forged', to=None)
        self.assertEqual(set(result['delivered']), {'bob', 'carol'})
        for receiver in (bob, carol):
            self.assertEqual(receiver.receive_chat(2), {'sender': 'alice', 'text': 'global', 'broadcast': True})
        with self.assertRaises(queue.Empty):
            alice.receive_chat(0)

    def test_chat_offline_and_full_inbox(self):
        alice = self.client('alice')
        with self.assertRaises(ApplicationError):
            alice.send_chat('hello', 'missing')
        bob = self.client('bob')
        bob.chat_messages = queue.Queue(maxsize=1)
        alice.send_chat('first', 'bob')
        result = alice.send_chat('second', 'bob')
        self.assertEqual(result['delivered'], [])
        self.assertIn('bob', result['failed'])
        self.assertEqual(bob.receive_chat(1)['text'], 'first')

    def test_large_and_empty_files_with_no_overwrite(self):
        alice, bob = self.client('alice'), self.client('bob')
        source = Path(self.temp.name) / 'binary.dat'
        content = bytes(range(256)) * (32768 + 1)  # More than one 8 MiB transport message.
        source.write_bytes(content)
        progress = []
        result = alice.send_file(source, 'bob', progress=lambda sent, total: progress.append((sent, total)))
        event = bob.receive_file(3)
        self.assertEqual(Path(event['path']).read_bytes(), content)
        self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(progress[-1], (len(content), len(content)))
        source.write_bytes(b'')
        alice.send_file(source, 'bob')
        empty = bob.receive_file(3)
        self.assertNotEqual(event['path'], empty['path'])
        self.assertEqual(Path(empty['path']).read_bytes(), b'')
        self.assertEqual(Path(event['path']).read_bytes(), content)
        self.assertFalse(list((Path(self.temp.name) / 'bob').glob('.part-*')))

    def test_file_rejects_unsafe_name_wrong_offset_and_bad_hash(self):
        alice, bob = self.client('alice'), self.client('bob')
        def request(op, file_id, body=b'', **fields):
            return alice.app.request(op, body, to='bob', file_id=file_id, **fields)
        with self.assertRaises(ApplicationError):
            request('file_begin', uuid.uuid4().hex, name='../escape.txt', size=0)
        for invalid_op in ('offset', 'hash'):
            file_id = uuid.uuid4().hex
            request('file_begin', file_id, name='safe.dat', size=3)
            if invalid_op == 'offset':
                with self.assertRaises(ApplicationError):
                    request('file_block', file_id, b'abc', offset=1)
            else:
                request('file_block', file_id, b'abc', offset=0)
                with self.assertRaises(ApplicationError):
                    request('file_end', file_id, sha256='0' * 64)
        self.assertEqual(bob.file_receiver.active, {})
        self.assertFalse(list((Path(self.temp.name) / 'bob').glob('*')))
        with self.assertRaises(queue.Empty):
            bob.receive_file(0)

    def test_file_disconnect_cleans_partial(self):
        alice, bob = self.client('alice'), self.client('bob')
        file_id = uuid.uuid4().hex
        alice.app.request('file_begin', to='bob', file_id=file_id, name='partial.dat', size=100)
        alice.app.request('file_block', b'abc', to='bob', file_id=file_id, offset=0)
        alice.close()
        self.assertTrue(wait_until(lambda: not bob.file_receiver.active))
        self.assertFalse(list((Path(self.temp.name) / 'bob').glob('*')))

    def test_file_recipient_disconnect_is_reported(self):
        alice, bob = self.client('alice'), self.client('bob')
        source = Path(self.temp.name) / 'transfer.dat'
        source.write_bytes(b'x' * (FILE_BLOCK_SIZE + 5))
        with self.assertRaises((ApplicationError, ConnectionError)):
            alice.send_file(source, 'bob', progress=lambda *_: bob.close())
        self.assertFalse(list((Path(self.temp.name) / 'bob').glob('*')))

    def test_chat_and_file_survive_datagram_loss(self):
        alice, bob = self.client('alice'), self.client('bob')
        drops = []
        def lossy(transport):
            original = transport.send_datagram
            seen = set()
            def send(raw):
                pkt = Packet.from_bytes(raw)
                key = (pkt.msg_type, pkt.seq_num if pkt.msg_type == MsgType.STREAM_DATA else pkt.ack_num)
                if key in ((MsgType.STREAM_DATA, 1), (MsgType.ACK, 0)) and key not in seen:
                    seen.add(key)
                    drops.append(key)
                    return
                original(raw)
            transport.send_datagram = send
        for transport in (alice.transport, bob.transport,
                          self.server.transport_for('alice'), self.server.transport_for('bob')):
            lossy(transport)
        self.assertEqual(alice.send_chat('chat ' * 1000, 'bob')['delivered'], ['bob'])
        self.assertEqual(bob.receive_chat(2)['text'], 'chat ' * 1000)
        source = Path(self.temp.name) / 'lossy.bin'
        content = bytes(range(256)) * 1500
        source.write_bytes(content)
        alice.send_file(source, 'bob')
        event = bob.receive_file(2)
        self.assertEqual(Path(event['path']).read_bytes(), content)
        self.assertGreaterEqual(len(drops), 4)
        with self.assertRaises(queue.Empty):
            bob.receive_chat(0)
        with self.assertRaises(queue.Empty):
            bob.receive_file(0)

    def test_incomplete_file_expires_without_publishing(self):
        alice, bob = self.client('alice'), self.client('bob')
        bob.file_receiver.timeout = 0.2
        alice.app.request('file_begin', to='bob', file_id=uuid.uuid4().hex,
                          name='idle.dat', size=123)
        self.assertTrue(wait_until(lambda: not bob.file_receiver.active))
        self.assertFalse(list((Path(self.temp.name) / 'bob').glob('*')))

    def test_twenty_concurrent_encrypted_clients_and_ring_chat(self):
        with ThreadPoolExecutor(max_workers=20) as pool:
            clients = list(pool.map(lambda i: self.client(f'peer{i:02d}'), range(20)))
            self.assertTrue(wait_until(lambda: all(len(client.get_peers()) == 20 for client in clients)))
            results = list(pool.map(lambda i: clients[i].send_chat(f'message-{i}',
                                    recipient=f'peer{(i + 1) % 20:02d}'), range(20)))
        for i, result in enumerate(results):
            self.assertEqual(result['delivered'], [f'peer{(i + 1) % 20:02d}'])
            self.assertEqual(clients[(i + 1) % 20].receive_chat(3)['text'], f'message-{i}')
            self.assertEqual(clients[i].tcp_sock.version(), 'TLSv1.3')
        self.assertEqual(len({client.session_id for client in clients}), 20)

    def test_untrusted_certificate_and_wrong_hostname_rejected(self):
        other_cert, _ = create_identity(Path(self.temp.name) / 'other-keys')
        bad_client = CollaborationClient('untrusted', server_tcp_port=self.server.tcp_port,
                                          tls_context=client_context(other_cert))
        self.clients.append(bad_client)
        with self.assertRaises(ssl.SSLCertVerificationError):
            bad_client.connect_and_authenticate()
        raw = socket.create_connection(('127.0.0.1', self.server.tcp_port), timeout=2)
        self.sockets.append(raw)
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.client_tls.wrap_socket(raw, server_hostname='wrong-host.invalid')
        self.assertNotIn('untrusted', self.server.active_peers)

    def test_plaintext_and_replayed_heartbeat_cannot_keep_session_alive(self):
        sock = self.raw()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        self.sockets.append(udp)
        auth = self.auth(sock, {'username': 'secure', 'udp_port': udp.getsockname()[1]})
        cipher = SessionCipher(auth['session_id'], auth['udp_secret'], is_client=True)
        packet = Packet(MsgType.HEARTBEAT, flags=PacketFlags.EOM,
                         payload=Packet.json_payload({'username': 'secure', 'session_id': auth['session_id']}))
        encrypted = cipher.seal(packet.to_bytes())
        udp.sendto(encrypted, ('127.0.0.1', self.server.udp_port))
        time.sleep(0.1)
        last_seen = self.server.active_peers['secure']['last_seen']
        udp.sendto(packet.to_bytes(), ('127.0.0.1', self.server.udp_port))
        udp.sendto(encrypted, ('127.0.0.1', self.server.udp_port))
        time.sleep(0.1)
        self.assertEqual(self.server.active_peers['secure']['last_seen'], last_seen)
        self.assertTrue(wait_until(lambda: 'secure' not in self.server.active_peers))

    def test_client_run_exits_after_server_shutdown(self):
        client = CollaborationClient('runner', server_tcp_port=self.server.tcp_port,
                                     heartbeat_interval=0.1, tls_context=self.client_tls)
        self.clients.append(client)
        worker = threading.Thread(target=client.run)
        worker.start()
        self.assertTrue(wait_until(lambda: client.connected))
        self.server.stop()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(client.connected)


if __name__ == '__main__':
    unittest.main()
