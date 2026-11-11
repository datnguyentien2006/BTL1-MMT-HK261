"""One selector owns the server's TCP/TLS connections and UDP receive socket."""
from collections import deque
from dataclasses import dataclass, field
import selectors
import socket
import ssl
import time

from protocol import HEADER_SIZE, HEADER_STRUCT, IO_TIMEOUT, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, Packet

READ, WRITE = selectors.EVENT_READ, selectors.EVENT_WRITE


@dataclass(eq=False)
class Connection:
    sock: ssl.SSLSocket
    address: tuple
    created: float = field(default_factory=time.monotonic)
    tls_ready: bool = False
    handshake_event: int = READ
    read_event: int = READ
    write_event: int = WRITE
    username: str | None = None
    handshaken: bool = False
    closed: bool = False
    incoming: bytearray = field(default_factory=bytearray)
    frame_started: float | None = None
    outgoing: deque = field(default_factory=deque)
    pending: bytes = b''
    offset: int = 0
    queued_bytes: int = 0
    write_progress: float = field(default_factory=time.monotonic)

    # Xếp dữ liệu điều khiển chờ gửi, giới hạn bộ nhớ cho kết nối đọc chậm.
    def queue(self, data):
        if self.queued_bytes + len(data) > 512 * 1024:
            raise BufferError('Slow control reader exceeded output budget')
        if not self.queued_bytes:
            self.write_progress = time.monotonic()
        self.outgoing.append(data)
        self.queued_bytes += len(data)


class ServerIO:
    # Tạo selector theo dõi socket và cặp socket dùng để đánh thức vòng lặp I/O.
    def __init__(self, owner):
        self.owner = owner
        self.selector = selectors.DefaultSelector()
        self.connections = set()
        self.wake_read, self.wake_write = socket.socketpair()
        self.wake_read.setblocking(False)
        self.wake_write.setblocking(False)

    # Gửi tín hiệu đánh thức selector khi cần xử lý hoặc dừng máy chủ.
    def wake(self):
        try:
            self.wake_write.send(b'\0')
        except OSError:
            pass

    # Điều phối nhận kết nối, đọc UDP, xử lý TCP/TLS và kiểm tra timeout định kỳ.
    def run(self):
        owner = self.owner
        for sock, kind in ((owner.tcp_sock, 'accept'), (owner.udp_sock, 'udp'), (self.wake_read, 'wake')):
            sock.setblocking(False)
            self.selector.register(sock, READ, kind)
        next_maintenance = time.monotonic()
        while not owner.stop_event.is_set():
            for key, events in self.selector.select(max(0, next_maintenance - time.monotonic())):
                if key.data == 'accept':
                    self._accept()
                elif key.data == 'udp':
                    self._udp()
                elif key.data == 'wake':
                    try:
                        self.wake_read.recv(4096)
                    except BlockingIOError:
                        pass
                else:
                    self._service(key.data, events)
            now = time.monotonic()
            if now >= next_maintenance:
                # Timers run by time, never once per received UDP datagram.
                for conn in list(self.connections):
                    try:
                        if conn.username is None and now - conn.created >= IO_TIMEOUT * 2:
                            raise TimeoutError('Login timed out')
                        if conn.frame_started is not None and now - conn.frame_started >= IO_TIMEOUT:
                            raise TimeoutError('Partial control frame timed out')
                        if conn.queued_bytes and now - conn.write_progress >= IO_TIMEOUT:
                            raise TimeoutError('Control write timed out')
                        owner._maintain_connection(conn, now)
                        if conn.tls_ready and conn.sock.pending():
                            self._read(conn)
                        self._interest(conn)
                    except (OSError, ValueError, BufferError):
                        self.close_connection(conn)
                next_maintenance = now + 0.02

    # Nhận các kết nối TCP mới và đăng ký bắt tay TLS không chặn.
    def _accept(self):
        for _ in range(16):
            try:
                sock, address = self.owner.tcp_sock.accept()
            except BlockingIOError:
                return
            if len(self.connections) >= self.owner.max_connections:
                sock.close()
                continue
            try:
                sock.setblocking(False)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                tls = self.owner.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
                conn = Connection(tls, address)
                self.connections.add(conn)
                self.selector.register(tls, READ, conn)
            except OSError:
                sock.close()

    # Đọc một đợt datagram UDP và chuyển chúng tới hàng đợi xử lý của máy chủ.
    def _udp(self):
        for _ in range(128):
            try:
                raw, address = self.owner.udp_sock.recvfrom(MAX_PACKET_SIZE + 1)
            except BlockingIOError:
                return
            except OSError as exc:
                if isinstance(exc, ConnectionResetError) or getattr(exc, 'winerror', None) == 10040:
                    continue
                raise
            self.owner._enqueue_datagram(raw, address)

    # Cập nhật các sự kiện đọc/ghi cần theo dõi theo trạng thái TLS và dữ liệu chờ gửi.
    def _interest(self, conn):
        if conn.closed:
            return
        events = conn.handshake_event if not conn.tls_ready else (
            conn.read_event | (conn.write_event if conn.queued_bytes else 0))
        if self.selector.get_key(conn.sock).events != events:
            self.selector.modify(conn.sock, events, conn)

    # Thực hiện bước bắt tay hoặc đọc/ghi phù hợp khi socket sẵn sàng.
    def _service(self, conn, events):
        if conn.closed:
            return
        try:
            if not conn.tls_ready:
                try:
                    conn.sock.do_handshake()
                    conn.tls_ready = True
                except ssl.SSLWantReadError:
                    conn.handshake_event = READ
                except ssl.SSLWantWriteError:
                    conn.handshake_event = WRITE
            if conn.tls_ready:
                if events & conn.read_event or conn.sock.pending():
                    self._read(conn)
                if not conn.closed and events & conn.write_event:
                    self._write(conn)
            self._interest(conn)
        except (OSError, ValueError, BufferError):
            self.close_connection(conn)

    # Ghép dữ liệu TCP thành các gói hoàn chỉnh, kiểm tra header rồi chuyển gói điều khiển cho máy chủ.
    def _read(self, conn):
        for _ in range(4):  # Bound work per ready connection to keep UDP responsive.
            try:
                data = conn.sock.recv(16384)
            except ssl.SSLWantReadError:
                conn.read_event = READ
                return
            except ssl.SSLWantWriteError:
                conn.read_event = WRITE
                return
            if not data:
                self.close_connection(conn)
                return
            conn.read_event = READ
            if not conn.incoming:
                conn.frame_started = time.monotonic()
            conn.incoming.extend(data)
            while len(conn.incoming) >= HEADER_SIZE:
                header = HEADER_STRUCT.unpack_from(conn.incoming)
                Packet.validate_header(header[0], header[1])
                size = header[6]
                if size > MAX_PAYLOAD_SIZE:
                    raise ValueError('Oversized control frame')
                length = HEADER_SIZE + size
                if len(conn.incoming) < length:
                    break
                packet = Packet.from_bytes(bytes(conn.incoming[:length]))
                del conn.incoming[:length]
                conn.frame_started = time.monotonic() if conn.incoming else None
                self.owner._control_packet(conn, packet)
                if conn.closed:
                    return
            if not conn.sock.pending():
                return

    # Gộp các gói điều khiển để gửi qua TLS và lưu vị trí gửi tiếp nếu socket chỉ ghi được một phần.
    def _write(self, conn):
        if not conn.queued_bytes:
            return
        if not conn.pending:
            batch = []
            size = 0
            while conn.outgoing and size + len(conn.outgoing[0]) <= 65536:
                part = conn.outgoing.popleft()
                batch.append(part)
                size += len(part)
            # Coalesce complete v2 frames into one TLS write, preserving their order.
            conn.pending = b''.join(batch)
            conn.offset = 0
        try:
            sent = conn.sock.send(memoryview(conn.pending)[conn.offset:])
        except ssl.SSLWantReadError:
            conn.write_event = READ
            return
        except ssl.SSLWantWriteError:
            conn.write_event = WRITE
            return
        if not sent:
            raise ConnectionError('Control socket closed while writing')
        conn.write_event = WRITE
        conn.queued_bytes -= sent
        conn.offset += sent
        conn.write_progress = time.monotonic()
        if conn.offset == len(conn.pending):
            conn.pending = b''
            conn.offset = 0

    # Hủy theo dõi kết nối, thông báo cho máy chủ và giải phóng socket cùng bộ đệm.
    def close_connection(self, conn):
        if conn.closed:
            return
        conn.closed = True
        self.selector.unregister(conn.sock)
        self.connections.discard(conn)
        self.owner._connection_closed(conn)
        conn.sock.close()
        conn.outgoing.clear()
        conn.pending = b''
        conn.incoming.clear()

    # Đóng mọi kết nối, selector và các socket đánh thức.
    def close(self):
        for conn in list(self.connections):
            self.close_connection(conn)
        self.selector.close()
        self.wake_read.close()
        self.wake_write.close()
