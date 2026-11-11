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


class BufferBudget:
    """Shared byte budget for queued sends, reassembly and completed messages."""
    # Khởi tạo hạn mức bộ nhớ dùng chung và các bộ đếm mức sử dụng.
    def __init__(self, limit):
        self.limit = limit
        self.used = 0
        self.peak = 0
        self.lock = threading.Lock()

    # Giữ thêm dung lượng nếu còn trong hạn mức và cập nhật mức sử dụng cao nhất.
    def acquire(self, size):
        with self.lock:
            if self.used + size > self.limit:
                return False
            self.used += size
            self.peak = max(self.peak, self.used)
            return True

    # Trả lại dung lượng đã giữ vào ngân sách bộ nhớ dùng chung.
    def release(self, size):
        with self.lock:
            self.used -= size


@dataclass
class Receipt:
    stream_id: int
    done: threading.Event = field(default_factory=threading.Event)
    error: Exception | None = None

    # Chờ luồng gửi hoàn tất; trả về ID luồng hoặc phát sinh lỗi gửi/timeout.
    def wait(self, timeout=None):
        if not self.done.wait(timeout):
            raise TimeoutError('Transfer is still pending')
        if self.error is not None:
            raise self.error
        return self.stream_id


class ReliableUDP:
    # Khởi tạo cơ chế UDP tin cậy với cửa sổ truyền, giới hạn bộ nhớ và điều khiển tắc nghẽn.
    def __init__(self, send_datagram, session_id, *, window=32, rto=0.25,
                 max_retries=12, max_streams=16, max_message=8 * 1024 * 1024,
                 receive_timeout=30.0, clock=time.monotonic, encode_packet=None,
                 buffer_budget=None, max_buffered_bytes=32 * 1024 * 1024,
                 wakeup=lambda: None):
        if not 1 <= window <= 65535 or rto <= 0 or max_retries < 0:
            raise ValueError('Invalid transport configuration')
        if max_streams < 1 or max_message < 1 or receive_timeout <= 0:
            raise ValueError('Invalid transport limits')
        self.token = bytes.fromhex(session_id)
        if len(self.token) != TOKEN_SIZE:
            raise ValueError('Invalid session token')
        self.send_datagram = send_datagram
        self.encode_packet = encode_packet or (lambda packet: packet.to_bytes())
        self.wakeup = wakeup
        self.buffer_budget = buffer_budget or BufferBudget(max_buffered_bytes)
        self.max_buffered_bytes = max_buffered_bytes
        self.buffered_bytes = 0
        self.message_sizes = {}
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

    # Chia bản tin thành các khối, cấp ID luồng mới và xếp vào danh sách chờ gửi.
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
            if not self._reserve(len(data)):
                raise BufferError('Transport byte budget exhausted')
            sid = self.next_stream
            self.next_stream += 1
            receipt = Receipt(sid)
            view = memoryview(data)
            chunks = [view[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)] or [view]
            self.outgoing[sid] = dict(chunks=chunks, base=0, next=0, pending={},
                                      acked=set(), remote_window=self.window,
                                      receipt=receipt, progress=self.clock(), reserved=len(data))
            self.wakeup()
            return receipt

    # Lấy bản tin đã ghép hoàn chỉnh và tùy chọn giữ lại phần ngân sách bộ nhớ của nó.
    def receive(self, timeout=None, *, retain=False):
        """Return (stream_id, complete_bytes); queue.Empty indicates a read timeout."""
        item = self.messages.get(timeout=timeout)
        if not retain:
            self.release_received(item[0])
        return item

    # Giải phóng ngân sách bộ nhớ của bản tin sau khi bên sử dụng xử lý xong.
    def release_received(self, stream_id):
        """Endpoint consumers retain a message's budget until their queue/work finishes."""
        with self.lock:
            self._release(self.message_sizes.pop(stream_id, 0))

    # Giữ dung lượng trong cả giới hạn riêng của transport và ngân sách dùng chung.
    def _reserve(self, size):
        if self.buffered_bytes + size > self.max_buffered_bytes or not self.buffer_budget.acquire(size):
            return False
        self.buffered_bytes += size
        return True

    # Giảm lượng bộ nhớ đã giữ ở transport và trả lại ngân sách chung.
    def _release(self, size):
        self.buffered_bytes -= size
        self.buffer_budget.release(size)

    # Mã hóa hoặc đóng gói bản tin rồi gọi hàm gửi datagram.
    def _emit(self, pkt):
        self.send_datagram(self.encode_packet(pkt))

    # Gửi ACK cho một khối dữ liệu, kèm cửa sổ nhận và token phiên.
    def _ack(self, sid, seq):
        self._emit(Packet(MsgType.ACK, flags=PacketFlags.ACK, stream_id=sid,
                          ack_num=seq, win_size=self.window, payload=self.token))

    # Xử lý ACK hoặc ghép các khối nhận được, kiểm tra phiên và ngăn giao bản tin trùng lặp.
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
                    self._release(state['reserved'])
                    del self.outgoing[sid]
                return
            if pkt.msg_type != MsgType.STREAM_DATA or pkt.flags & ~int(PacketFlags.EOM):
                return
            if len(pkt.payload) < TOKEN_SIZE + META.size:
                return
            total = META.unpack_from(pkt.payload, TOKEN_SIZE)[0]
            chunk = memoryview(pkt.payload)[TOKEN_SIZE + META.size:]
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
                # Reserve both chunks and the final join copy before accepting a stream.
                reserved = total * (CHUNK_SIZE + TOKEN_SIZE + META.size) * 2
                if not self._reserve(reserved):
                    return  # No ACK: sender backs off and retries when capacity is free.
                state = dict(total=total, base=0, chunks={}, updated=self.clock(), reserved=reserved)
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
                self._release(state['reserved'] - len(data))
                self.message_sizes[sid] = len(data)
                self.messages.put_nowait((sid, data))
                self.retired[sid] = total
                del self.incoming[sid]
            self._ack(sid, seq)

    # Gửi lại khối hết hạn, gửi khối mới theo cửa sổ/tốc độ cho phép và loại luồng nhận quá hạn.
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
                except BlockingIOError:
                    self.cc.on_timeout(now)
                except OSError as exc:
                    state['receipt'].error = exc
                    state['receipt'].done.set()
                    self._release(state['reserved'])
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
                    except BlockingIOError:
                        self.cc.on_timeout(now)
                        continue
                    except OSError as exc:
                        state['receipt'].error = exc
                        state['receipt'].done.set()
                        self._release(state['reserved'])
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
                    self._release(state['reserved'])
                    del self.incoming[sid]
                    self.retired[sid] = None
                    if not self.errors.full():
                        self.errors.put_nowait((sid, TimeoutError('Incomplete stream expired')))

    # Tạo gói dữ liệu cho một khối và đánh dấu EOM nếu đây là khối cuối.
    def _send_chunk(self, sid, state, seq):
        total = len(state['chunks'])
        self._emit(Packet(MsgType.STREAM_DATA, stream_id=sid, seq_num=seq,
                          flags=PacketFlags.EOM if seq == total - 1 else PacketFlags.NONE,
                          win_size=self.window,
                          payload=b''.join((self.token, META.pack(total), state['chunks'][seq]))))

    # Đóng transport, báo lỗi các lượt gửi chưa xong và giải phóng toàn bộ bộ đệm.
    def close(self):
        with self.lock:
            self.closed = True
            for state in self.outgoing.values():
                state['receipt'].error = ConnectionError('Session closed')
                state['receipt'].done.set()
            self.outgoing.clear()
            self.incoming.clear()
            self.retired.clear()
            while not self.messages.empty():
                self.messages.get_nowait()
            self.message_sizes.clear()
            self._release(self.buffered_bytes)
