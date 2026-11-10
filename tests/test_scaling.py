"""Regression checks for bounded multiplexed server I/O and transport buffers."""
from concurrent.futures import ThreadPoolExecutor
import queue
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'btl_btlmmt'))
from client import CollaborationClient
from congestion import CubicController
from protocol import HEADER_FORMAT, MAX_PAYLOAD_SIZE, MsgType, Packet, PacketFlags, recv_tcp_packet
from reliable_udp import BufferBudget, CHUNK_SIZE, META, ReliableUDP
from security import SessionCipher, create_identity, client_context, server_context
from server import CollaborationServer
from server_io import Connection, ServerIO


class BufferTests(unittest.TestCase):
    def test_views_crc_and_direct_encryption_remain_wire_compatible(self):
        raw = Packet(MsgType.STREAM_DATA, payload=b'abc').to_bytes()
        viewed = Packet.from_bytes(raw, copy_payload=False)
        self.assertIsInstance(viewed.payload, memoryview)
        self.assertEqual(viewed.to_bytes(), raw)
        bad = bytearray(raw)
        bad[-1] ^= 1
        with self.assertRaises(ValueError):
            Packet.from_bytes(bad, copy_payload=False)
        a = SessionCipher('12' * 32, '34' * 32, is_client=True)
        b = SessionCipher('12' * 32, '34' * 32, is_client=False)
        wire = a.seal(viewed)
        self.assertEqual(viewed.flags, 0)  # seal does not mutate caller's packet.
        self.assertEqual(b.open(Packet.from_bytes(wire, copy_payload=False)).payload, b'abc')

    def test_shared_budget_backpressure_release_and_expiry(self):
        budget = BufferBudget(12000)
        now = [0.0]
        a = ReliableUDP(lambda raw: None, '12' * 32, buffer_budget=budget)
        b = ReliableUDP(lambda raw: None, '34' * 32, buffer_budget=budget,
                        receive_timeout=1, clock=lambda: now[0])
        a.send(b'x' * 10000)
        with self.assertRaises(BufferError):
            b.send(b'y' * 3000)
        packet = Packet(MsgType.STREAM_DATA, stream_id=1,
                        payload=b.token + META.pack(2) + b'z' * CHUNK_SIZE)
        b.handle_packet(packet)
        self.assertEqual(b.incoming, {})  # No ACK/admission while global budget is full.
        a.close()
        b.handle_packet(packet)
        self.assertIn(1, b.incoming)
        now[0] = 2
        b.tick()
        self.assertEqual(budget.used, 0)
        b.handle_packet(Packet(MsgType.STREAM_DATA, stream_id=2, flags=PacketFlags.EOM,
                               payload=b.token + META.pack(1) + b'complete'))
        self.assertEqual(budget.used, len(b'complete'))
        self.assertEqual(b.receive(0)[1], b'complete')
        self.assertEqual(budget.used, 0)
        b.send(b'pending')
        b.close()
        self.assertEqual(budget.used, 0)

    def test_temporary_send_pressure_retries_and_pacing_caps_bursts(self):
        now = [0.0]
        raw = []
        def send(data):
            if now[0] == 0:
                raise BlockingIOError('buffer full')
            raw.append(data)
        sender = ReliableUDP(send, '12' * 32, clock=lambda: now[0])
        receipt = sender.send(b'retry after pressure')
        sender.tick()
        self.assertFalse(receipt.done.is_set())
        now[0] = 0.3
        sender.tick()
        self.assertEqual(len(raw), 1)
        sender.handle_packet(Packet(MsgType.ACK, flags=PacketFlags.ACK,
                                    stream_id=receipt.stream_id, payload=sender.token))
        receipt.wait(0)
        self.assertEqual(sender.buffered_bytes, 0)
        cc = CubicController(0)
        cc.cwnd = 200
        self.assertEqual(sum(cc.permit(1) for _ in range(200)), 8)

    def test_control_batch_preserves_frames_across_partial_writes(self):
        class PartialSocket:
            def __init__(self):
                self.wire = bytearray()
            def send(self, data):
                count = min(7, len(data))
                self.wire.extend(data[:count])
                return count
        sock = PartialSocket()
        conn = Connection(sock, ('127.0.0.1', 1))
        frames = [Packet(MsgType.PEER_UPDATE, payload=str(i).encode()).to_bytes() for i in range(5)]
        for frame in frames:
            conn.queue(frame)
        # _write only needs connection state; real selector/TLS is tested below.
        while conn.queued_bytes:
            ServerIO._write(None, conn)
        self.assertEqual(bytes(sock.wire), b''.join(frames))


class ReactorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.errors = []
        previous = threading.excepthook
        threading.excepthook = self.errors.append
        self.addCleanup(setattr, threading, 'excepthook', previous)
        cert, key = create_identity(Path(self.temp.name) / 'keys')
        self.tls = client_context(cert)
        self.server = CollaborationServer('127.0.0.1', 0, 0, tls_context=server_context(cert, key))
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
        self.thread.join(10)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.server.active_peers, {})
        self.assertEqual(self.server.buffer_budget.used, 0)
        self.assertEqual(self.errors, [])
        self.temp.cleanup()

    def client(self, name):
        client = CollaborationClient(name, server_tcp_port=self.server.tcp_port, tls_context=self.tls,
                                     download_dir=Path(self.temp.name) / name)
        self.clients.append(client)
        client.connect_and_authenticate()
        return client

    def test_slow_handshake_partial_frame_and_oversized_header_do_not_block_peers(self):
        silent = socket.create_connection(('127.0.0.1', self.server.tcp_port), timeout=2)
        self.sockets.append(silent)  # Never sends TLS ClientHello.
        raw = self.tls.wrap_socket(socket.create_connection(('127.0.0.1', self.server.tcp_port), timeout=2),
                                   server_hostname='127.0.0.1')
        self.sockets.append(raw)
        frame = Packet(MsgType.HANDSHAKE_SYN, flags=PacketFlags.EOM).to_bytes()
        raw.sendall(frame[:5])
        alice, bob = self.client('alice'), self.client('bob')
        self.assertEqual(alice.send_chat('still responsive', 'bob')['delivered'], ['bob'])
        self.assertEqual(bob.receive_chat(2)['text'], 'still responsive')
        raw.sendall(frame[5:])
        self.assertEqual(recv_tcp_packet(raw).msg_type, MsgType.HANDSHAKE_ACK)
        raw.sendall(struct.pack(HEADER_FORMAT, MsgType.AUTH_REQ, 1, 0, 0, 0, 32,
                               MAX_PAYLOAD_SIZE + 1, 0, 0))
        self.assertEqual(raw.recv(1), b'')
        partial = self.tls.wrap_socket(socket.create_connection(('127.0.0.1', self.server.tcp_port), timeout=2),
                                       server_hostname='127.0.0.1')
        self.sockets.append(partial)
        with patch('server_io.IO_TIMEOUT', 0.1):
            partial.sendall(frame[:3])
            self.assertEqual(partial.recv(1), b'')

    def test_forty_clients_ring_chat_and_shared_workers(self):
        with ThreadPoolExecutor(max_workers=40) as pool:
            clients = list(pool.map(self.client, [f'peer{i:02d}' for i in range(40)]))
            def send(index):
                target = clients[(index + 1) % len(clients)]
                return clients[index].send_chat(f'message-{index}', target.username)
            results = list(pool.map(send, range(40)))
        self.assertTrue(all(not result['failed'] for result in results))
        for i, client in enumerate(clients):
            self.assertEqual(client.receive_chat(3)['text'], f'message-{(i - 1) % 40}')
        self.assertEqual(len(self.server.active_peers), 40)
        self.assertTrue(all(peer['app'].reader is None and peer['app'].worker is None
                            for peer in self.server.active_peers.values()))
        self.assertEqual(len(self.server.udp_threads), 4)
        self.assertLessEqual(self.server.udp_queue_peak, 512)


if __name__ == '__main__':
    unittest.main()
