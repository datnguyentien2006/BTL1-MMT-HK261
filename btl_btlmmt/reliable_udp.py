"""Selective-repeat UDP messages. One bounded message per single-use stream ID.

The socket owner calls handle_packet() and tick() regularly. No socket reads or
application callbacks occur here. send() returns a receipt; receive() is a queue.
Production socket owners encrypt all datagrams with SessionCipher.
"""
import queue
import struct
import threading
import time
from dataclasses import dataclass, field

from protocol import MAX_PAYLOAD_SIZE, MsgType, Packet, PacketFlags
from security import UDP_OVERHEAD
from congestion import CubicController

TOKEN_SIZE = 32
META = struct.Struct('!I')
CHUNK_SIZE = MAX_PAYLOAD_SIZE - TOKEN_SIZE - META.size - UDP_OVERHEAD


@dataclass
class Receipt:
    stream_id: int
    done: threading.Event = field(default_factory=threading.Event)
    error: Exception | None = None

    def wait(self, timeout=None):
        if not self.done.wait(timeout):
            raise TimeoutError('Transfer is still pending')
        if self.error is not None:
            raise self.error
        return self.stream_id


class ReliableUDP:
    def __init__(self, send_datagram, session_id, *, window=32, rto=0.25,
                 max_retries=12, max_streams=16, max_message=8 * 1024 * 1024,
                 receive_timeout=30.0, clock=time.monotonic):
        if not 1 <= window <= 65535 or rto <= 0 or max_retries < 0:
            raise ValueError('Invalid transport configuration')
        if max_streams < 1 or max_message < 1 or receive_timeout <= 0:
            raise ValueError('Invalid transport limits')
        self.token = bytes.fromhex(session_id)
        if len(self.token) != TOKEN_SIZE:
            raise ValueError('Invalid session token')
        self.send_datagram = send_datagram
        self.window = window
        self.rto = rto
        self.max_retries = max_retries
        self.max_streams = max_streams
        self.max_message = max_message
        self.receive_timeout = receive_timeout
        self.clock = clock
        self.lock = threading.RLock()
        self.outgoing = {}
        self.incoming = {}
        # Tombstones survive for the session to ACK lost final ACKs without redelivery.
        self.retired = {}
        self.next_stream = 1
        self.messages = queue.Queue(maxsize=max_streams)
        self.errors = queue.Queue(maxsize=max_streams)
        self.closed = False
        self.cc = CubicController(clock(), initial_rto=rto, initial_window=min(4, window))
        self.schedule_cursor = 0

    def send(self, data):
        if not isinstance(data, bytes) or len(data) > self.max_message:
            raise ValueError('Message must be bytes within max_message')
        with self.lock:
            if self.closed:
                raise ConnectionError('Transport is closed')
            if len(self.outgoing) >= self.max_streams:
                raise BufferError('Too many active send streams')
            if self.next_stream > 65535:
                raise OverflowError('Stream IDs exhausted; establish a new session')
            sid = self.next_stream
            self.next_stream += 1
            receipt = Receipt(sid)
            chunks = [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)] or [b'']
            self.outgoing[sid] = dict(chunks=chunks, base=0, next=0, pending={},
                                      acked=set(), remote_window=self.window,
                                      receipt=receipt, progress=self.clock())
            return receipt

    def receive(self, timeout=None):
        """Return (stream_id, complete_bytes); queue.Empty indicates a read timeout."""
        return self.messages.get(timeout=timeout)

    def _emit(self, pkt):
        self.send_datagram(pkt.to_bytes())

    def _ack(self, sid, seq):
        self._emit(Packet(MsgType.ACK, flags=PacketFlags.ACK, stream_id=sid,
                          ack_num=seq, win_size=self.window, payload=self.token))

    def handle_packet(self, pkt):
        with self.lock:
            if self.closed or not pkt.stream_id or pkt.payload[:TOKEN_SIZE] != self.token:
                return
            sid = pkt.stream_id
            if pkt.msg_type == MsgType.ACK:
                if pkt.flags != PacketFlags.ACK or len(pkt.payload) != TOKEN_SIZE:
                    return
                state = self.outgoing.get(sid)
                if state is None or pkt.ack_num not in state['pending']:
                    return  # Never accept ACKs for unsent packets.
                sent_at, retries = state['pending'].pop(pkt.ack_num)
                self.cc.on_ack(self.clock(), self.clock() - sent_at if retries == 0 else None)
                state['acked'].add(pkt.ack_num)
                state['remote_window'] = pkt.win_size
                state['progress'] = self.clock()
                while state['base'] in state['acked']:
                    state['acked'].remove(state['base'])
                    state['base'] += 1
                if state['base'] == len(state['chunks']):
                    state['receipt'].done.set()
                    del self.outgoing[sid]
                return
            if pkt.msg_type != MsgType.STREAM_DATA or pkt.flags & ~int(PacketFlags.EOM):
                return
            if len(pkt.payload) < TOKEN_SIZE + META.size:
                return
            total = META.unpack_from(pkt.payload, TOKEN_SIZE)[0]
            chunk = pkt.payload[TOKEN_SIZE + META.size:]
            seq = pkt.seq_num
            if (not 1 <= total <= (self.max_message + CHUNK_SIZE - 1) // CHUNK_SIZE
                    or seq >= total or bool(pkt.flags & PacketFlags.EOM) != (seq == total - 1)
                    or len(chunk) > CHUNK_SIZE
                    or (seq < total - 1 and len(chunk) != CHUNK_SIZE)
                    or (total - 1) * CHUNK_SIZE + (len(chunk) if seq == total - 1 else 0) > self.max_message):
                return
            if sid in self.retired:
                if self.retired[sid] == total:
                    self._ack(sid, seq)
                return
            state = self.incoming.get(sid)
            if state is None:
                if len(self.incoming) >= self.max_streams or seq >= self.window:
                    return
                state = dict(total=total, base=0, chunks={}, updated=self.clock())
                self.incoming[sid] = state
            if state['total'] != total or seq >= state['base'] + self.window:
                return
            if seq in state['chunks'] and state['chunks'][seq] != chunk:
                return
            state['chunks'][seq] = chunk
            state['updated'] = self.clock()
            while state['base'] in state['chunks']:
                state['base'] += 1
            if state['base'] == total:
                if self.messages.full():
                    return  # Withhold ACK until application queue has room.
                data = b''.join(state['chunks'][i] for i in range(total))
                self.messages.put_nowait((sid, data))
                self.retired[sid] = total
                del self.incoming[sid]
            self._ack(sid, seq)

    def tick(self):
        with self.lock:
            if self.closed:
                return
            now = self.clock()
            items = list(self.outgoing.items())
            if items:
                cursor = self.schedule_cursor % len(items)
                items = items[cursor:] + items[:cursor]
                self.schedule_cursor += 1
            for sid, state in items:
                try:
                    if now - state['progress'] > self.receive_timeout:
                        raise TimeoutError('No transfer progress')
                    for seq, (sent_at, retries) in list(state['pending'].items()):
                        deadline = min(3.0, self.cc.rto * 2 ** min(retries, 4))
                        if now - sent_at >= deadline:
                            if retries >= self.max_retries:
                                raise TimeoutError('UDP retry limit reached')
                            self.cc.on_timeout(now)
                            if not self.cc.permit(now):
                                continue
                            self._send_chunk(sid, state, seq)
                            state['pending'][seq] = (now, retries + 1)
                except OSError as exc:
                    state['receipt'].error = exc
                    state['receipt'].done.set()
                    del self.outgoing[sid]
            # Round-robin streams share one congestion budget; per-stream windows
            # independently prevent exceeding the receiver's sequence span.
            inflight = sum(len(state['pending']) for state in self.outgoing.values())
            while inflight < int(self.cc.cwnd):
                sent = False
                for sid, state in items:
                    if sid not in self.outgoing:
                        continue
                    limit = state['base'] + min(self.window, state['remote_window'])
                    if state['next'] >= min(len(state['chunks']), limit):
                        continue
                    if inflight >= int(self.cc.cwnd) or not self.cc.permit(now):
                        break
                    seq = state['next']
                    try:
                        self._send_chunk(sid, state, seq)
                    except OSError as exc:
                        state['receipt'].error = exc
                        state['receipt'].done.set()
                        del self.outgoing[sid]
                        continue
                    state['pending'][seq] = (now, 0)
                    state['next'] += 1
                    inflight += 1
                    sent = True
                if not sent:
                    break
            for sid, state in list(self.incoming.items()):
                if now - state['updated'] >= self.receive_timeout:
                    del self.incoming[sid]
                    self.retired[sid] = None
                    if not self.errors.full():
                        self.errors.put_nowait((sid, TimeoutError('Incomplete stream expired')))

    def _send_chunk(self, sid, state, seq):
        total = len(state['chunks'])
        self._emit(Packet(MsgType.STREAM_DATA, stream_id=sid, seq_num=seq,
                          flags=PacketFlags.EOM if seq == total - 1 else PacketFlags.NONE,
                          win_size=self.window,
                          payload=self.token + META.pack(total) + state['chunks'][seq]))

    def close(self):
        with self.lock:
            self.closed = True
            for state in self.outgoing.values():
                state['receipt'].error = ConnectionError('Session closed')
                state['receipt'].done.set()
            self.outgoing.clear()
            self.incoming.clear()
            self.retired.clear()
