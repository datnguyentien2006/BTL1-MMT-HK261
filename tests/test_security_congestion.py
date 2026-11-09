import queue
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'btl_btlmmt'))
from congestion import CubicController
from protocol import MAX_PACKET_SIZE, MsgType, Packet, PacketFlags
from reliable_udp import CHUNK_SIZE, ReliableUDP
from security import MAX_COUNTER, SessionCipher


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.sender = SessionCipher('12' * 32, '34' * 32, is_client=True,
                                    clock=lambda: self.now, epoch_packets=4)
        self.receiver = SessionCipher('12' * 32, '34' * 32, is_client=False,
                                      clock=lambda: self.now, epoch_packets=4)

    def packet(self, payload=b'secret message'):
        return Packet(MsgType.STREAM_DATA, flags=PacketFlags.EOM, stream_id=1, payload=payload)

    def test_confidentiality_roundtrip_and_payload_limit(self):
        payload = b'secret message' * 50
        raw = self.sender.seal(self.packet(payload).to_bytes())
        self.assertNotIn(payload, raw)
        self.assertTrue(Packet.from_bytes(raw).flags & PacketFlags.ENC)
        self.assertEqual(self.receiver.open(Packet.from_bytes(raw)).payload, payload)
        data = self.packet(b'x' * (32 + 4 + CHUNK_SIZE))
        self.assertEqual(len(self.sender.seal(data.to_bytes())), MAX_PACKET_SIZE)
        with self.assertRaises(ValueError):
            self.sender.seal(self.packet(b'x' * 1376).to_bytes())

    def test_header_and_ciphertext_tampering_do_not_advance_replay_window(self):
        raw = self.sender.seal(self.packet().to_bytes())
        for field in ('seq_num', 'ack_num', 'win_size', 'stream_id', 'timestamp'):
            pkt = Packet.from_bytes(raw)
            setattr(pkt, field, getattr(pkt, field) + 1)
            with self.assertRaises(ValueError):
                self.receiver.open(Packet.from_bytes(pkt.to_bytes()))
        pkt = Packet.from_bytes(raw)
        pkt.payload = pkt.payload[:-1] + bytes([pkt.payload[-1] ^ 1])
        with self.assertRaises(ValueError):
            self.receiver.open(Packet.from_bytes(pkt.to_bytes()))
        self.assertEqual(self.receiver.highest, -1)
        self.assertEqual(self.receiver.open(Packet.from_bytes(raw)).payload, b'secret message')

    def test_replay_reordering_and_key_rotation(self):
        packets = [self.sender.seal(self.packet(str(i).encode()).to_bytes()) for i in range(12)]
        for i in (3, 1, 0, 2, 7, 4, 6, 5, 11, 9, 10, 8):
            self.assertEqual(self.receiver.open(Packet.from_bytes(packets[i])).payload, str(i).encode())
        for raw in packets:
            with self.assertRaises(ValueError):
                self.receiver.open(Packet.from_bytes(raw))
        self.assertEqual(len(self.sender.keys), 3)

    def test_old_key_wrong_key_direction_and_session_are_rejected(self):
        raw = self.sender.seal(self.packet().to_bytes())
        for cipher in (self.sender,
                       SessionCipher('12' * 32, '56' * 32, is_client=False),
                       SessionCipher('78' * 32, '34' * 32, is_client=False)):
            with self.assertRaises(ValueError):
                cipher.open(Packet.from_bytes(raw))
        with self.assertRaises(ValueError):
            self.receiver.open(self.packet())

    def test_nonce_uniqueness_budget_expiry_and_close(self):
        raw = self.packet().to_bytes()
        first, retry = self.sender.seal(raw), self.sender.seal(raw)
        self.assertNotEqual(first, retry)
        self.receiver.open(Packet.from_bytes(first))
        self.receiver.open(Packet.from_bytes(retry))
        self.sender.counter = MAX_COUNTER
        with self.assertRaises(ConnectionError):
            self.sender.seal(raw)
        self.now = 3601
        with self.assertRaises(ConnectionError):
            self.receiver.open(Packet.from_bytes(first))
        self.sender.close()
        self.assertEqual(self.sender.keys, {})
        self.assertEqual(self.sender.secret, b'')


class CongestionTests(unittest.TestCase):
    def test_growth_rtt_loss_and_recovery(self):
        cc = CubicController(0)
        for i in range(40):
            cc.on_ack((i + 1) * 0.02, 0.02)
        before = cc.cwnd
        self.assertGreater(before, 32)
        self.assertAlmostEqual(cc.srtt, 0.02)
        self.assertGreaterEqual(cc.rto, 0.1)
        cc.on_timeout(2)
        self.assertEqual(cc.cwnd, 1)
        self.assertAlmostEqual(cc.ssthresh, before * 0.7)
        cc.on_timeout(2.01)
        self.assertEqual(cc.loss_events, 1)
        for i in range(100):
            cc.on_ack(3 + i * 0.02, 0.02)
        self.assertGreater(cc.cwnd, 1)
        self.assertLessEqual(cc.cwnd, cc.maximum)

    def test_pacing_limits_bursts(self):
        cc = CubicController(0)
        self.assertTrue(all(cc.permit(0) for _ in range(4)))
        self.assertFalse(cc.permit(0))
        self.assertFalse(cc.permit(0.001))
        self.assertTrue(cc.permit(0.1))

    def test_connection_budget_shared_by_streams_and_karn_rule(self):
        now = [0.0]
        wire = []
        transport = ReliableUDP(wire.append, '12' * 32, clock=lambda: now[0], rto=0.1)
        for _ in range(8):
            transport.send(b'x' * CHUNK_SIZE * 8)
        transport.tick()
        self.assertEqual(len(wire), 4)  # Not four packets per stream.
        self.assertEqual(len({Packet.from_bytes(raw).stream_id for raw in wire}), 4)
        now[0] = 0.2
        transport.tick()
        self.assertEqual(transport.cc.cwnd, 1)
        retried = Packet.from_bytes(wire[-1])
        transport.handle_packet(Packet(MsgType.ACK, flags=PacketFlags.ACK,
                                        stream_id=retried.stream_id, ack_num=retried.seq_num,
                                        payload=transport.token))
        self.assertIsNone(transport.cc.srtt)  # Retransmitted chunks cannot provide RTT samples.

    def test_encrypted_bidirectional_streams_with_loss_reorder_duplicate_corruption(self):
        rng = random.Random(731)
        now = [0.0]
        ab, ba = [], []
        a_crypto = SessionCipher('12' * 32, '34' * 32, is_client=True,
                                  clock=lambda: now[0], epoch_packets=16)
        b_crypto = SessionCipher('12' * 32, '34' * 32, is_client=False,
                                  clock=lambda: now[0], epoch_packets=16)
        a = ReliableUDP(lambda raw: ab.append(a_crypto.seal(raw)), '12' * 32, clock=lambda: now[0])
        b = ReliableUDP(lambda raw: ba.append(b_crypto.seal(raw)), '12' * 32, clock=lambda: now[0])
        data = bytes(range(256)) * 200
        receipts = [a.send(data), a.send(b'other stream'), b.send(data[::-1])]
        dropped = duplicated = rejected = 0
        corrupted = False
        for _ in range(2000):
            a.tick()
            b.tick()
            for wire, target, cipher in ((ab, b, b_crypto), (ba, a, a_crypto)):
                batch = wire[:]
                wire.clear()
                rng.shuffle(batch)
                for raw in batch:
                    if rng.random() < 0.06:
                        dropped += 1
                        continue
                    if not corrupted:
                        pkt = Packet.from_bytes(raw)
                        pkt.payload = pkt.payload[:-1] + bytes([pkt.payload[-1] ^ 1])
                        raw = pkt.to_bytes()
                        corrupted = True
                    copies = 2 if rng.random() < 0.2 else 1
                    duplicated += copies - 1
                    for _ in range(copies):
                        try:
                            target.handle_packet(cipher.open(Packet.from_bytes(raw)))
                        except ValueError:
                            rejected += 1
            now[0] += 0.02
            if all(receipt.done.is_set() for receipt in receipts):
                break
        for receipt in receipts:
            receipt.wait(0)
        received = {b.receive(0)[1], b.receive(0)[1]}
        self.assertEqual(received, {data, b'other stream'})
        self.assertEqual(a.receive(0)[1], data[::-1])
        self.assertTrue(dropped and duplicated and rejected)
        self.assertGreater(a.cc.loss_events + b.cc.loss_events, 0)
        with self.assertRaises(queue.Empty):
            b.receive(0)


if __name__ == '__main__':
    unittest.main()
