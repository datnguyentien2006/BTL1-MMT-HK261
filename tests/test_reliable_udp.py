import queue
import sys
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'btl_btlmmt'))
from protocol import MsgType, Packet, PacketFlags
from reliable_udp import CHUNK_SIZE, META, ReliableUDP


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.ab = []
        self.ba = []
        self.a = ReliableUDP(self.ab.append, 'ab' * 32, window=4, rto=0.1,
                             max_retries=4, clock=lambda: self.now)
        self.b = ReliableUDP(self.ba.append, 'ab' * 32, window=4, rto=0.1,
                             max_retries=4, clock=lambda: self.now)

    def pump(self, steps=1, drop=None, reverse=False, duplicate=False):
        for _ in range(steps):
            self.a.tick()
            self.b.tick()
            for packets, target in ((self.ab, self.b), (self.ba, self.a)):
                batch = packets[:]
                packets.clear()
                if reverse:
                    batch.reverse()
                for raw in batch:
                    pkt = Packet.from_bytes(raw)
                    if drop and drop(pkt):
                        continue
                    target.handle_packet(pkt)
                    if duplicate:
                        target.handle_packet(pkt)
            self.now += 0.05

    def test_loss_reorder_duplicate_and_lost_final_ack(self):
        data = bytes(range(256)) * 80
        receipt = self.a.send(data)
        counts = Counter()
        final = (len(data) - 1) // CHUNK_SIZE
        def drop(pkt):
            key = (pkt.msg_type, pkt.seq_num if pkt.msg_type == MsgType.STREAM_DATA else pkt.ack_num)
            counts[key] += 1
            return ((key == (MsgType.STREAM_DATA, 1) and counts[key] == 1)
                    or (key == (MsgType.ACK, final) and counts[key] <= 2))
        self.pump(300, drop=drop, reverse=True, duplicate=True)
        receipt.wait(0)
        self.assertEqual(self.b.receive(0), (receipt.stream_id, data))
        with self.assertRaises(queue.Empty):
            self.b.receive(0)
        self.assertGreater(counts[(MsgType.STREAM_DATA, 1)], 1)
        self.assertGreater(counts[(MsgType.STREAM_DATA, final)], 1)
        self.assertEqual(counts[(MsgType.STREAM_DATA, 2)], 1)

    def test_streams_do_not_block_each_other_and_retry_exhaustion(self):
        blocked = self.a.send(b'blocked')
        healthy = self.a.send(b'healthy')
        self.pump(200, drop=lambda pkt: pkt.stream_id == blocked.stream_id)
        healthy.wait(0)
        self.assertEqual(self.b.receive(0), (healthy.stream_id, b'healthy'))
        with self.assertRaises(TimeoutError):
            blocked.wait(0)
        self.assertEqual(self.a.outgoing, {})

    def test_window_bound_and_unsent_ack(self):
        receipt = self.a.send(b'x' * CHUNK_SIZE * 10)
        self.a.tick()
        self.assertEqual([Packet.from_bytes(p).seq_num for p in self.ab], [0, 1, 2, 3])
        self.a.handle_packet(Packet(MsgType.ACK, flags=PacketFlags.ACK,
                                    stream_id=receipt.stream_id, ack_num=9, payload=self.a.token))
        self.assertFalse(receipt.done.is_set())
        self.assertEqual(self.a.outgoing[receipt.stream_id]['base'], 0)

    def test_empty_message_wrong_token_and_close(self):
        receipt = self.a.send(b'')
        self.a.tick()
        pkt = Packet.from_bytes(self.ab[0])
        pkt.payload = bytes(32) + pkt.payload[32:]
        self.b.handle_packet(pkt)
        self.assertEqual(self.b.incoming, {})
        self.pump(10)
        receipt.wait(0)
        self.assertEqual(self.b.receive(0)[1], b'')
        pending = self.a.send(b'next')
        self.a.close()
        with self.assertRaises(ConnectionError):
            pending.wait(0)
        with self.assertRaises(ConnectionError):
            self.a.send(b'closed')

    def test_incomplete_expiry_and_late_packet(self):
        self.b.receive_timeout = 0.2
        self.a.send(b'x' * CHUNK_SIZE * 5)
        self.a.tick()
        first = Packet.from_bytes(self.ab[0])
        self.b.handle_packet(first)
        self.now = 0.3
        self.b.tick()
        self.assertEqual(self.b.incoming, {})
        self.b.handle_packet(first)
        self.assertEqual(self.b.incoming, {})
        self.assertIsInstance(self.b.errors.get_nowait()[1], TimeoutError)

    def test_application_backpressure(self):
        self.b.messages = queue.Queue(maxsize=1)
        first = self.a.send(b'first')
        second = self.a.send(b'second')
        self.pump(2)
        first.wait(0)
        self.assertFalse(second.done.is_set())
        self.assertEqual(self.b.receive(0)[1], b'first')
        self.pump(10)
        second.wait(0)
        self.assertEqual(self.b.receive(0)[1], b'second')

    def test_limits_and_no_stream_id_reuse(self):
        self.a.max_message = 2
        with self.assertRaises(ValueError):
            self.a.send(b'abc')
        self.a.next_stream = 65535
        last = self.a.send(b'ok')
        self.assertEqual(last.stream_id, 65535)
        with self.assertRaises(OverflowError):
            self.a.send(b'ok')


if __name__ == '__main__':
    unittest.main()
