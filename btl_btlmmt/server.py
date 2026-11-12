import queue
import secrets
import socket
import threading
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor

from protocol import (
    HEADER_SIZE, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, SESSION_TIMEOUT,
    MsgType, Packet, PacketFlags, validate_port, validate_username,
)

from reliable_udp import BufferBudget, ReliableUDP
from server_io import ServerIO
from security import SessionCipher, SESSION_LIFETIME, server_context
from application import Endpoint, ApplicationError
from file_transfer import FILE_BLOCK_SIZE, validate_file_id

TCP_HOST = '0.0.0.0'
TCP_PORT = 8888
UDP_PORT = 9000


class CollaborationServer:
    # Khởi tạo cấu hình máy chủ, danh sách phiên, ngân sách bộ nhớ và các nhóm xử lý dùng chung.
    def __init__(self, host=TCP_HOST, tcp_port=TCP_PORT, udp_port=UDP_PORT,
                 session_timeout=SESSION_TIMEOUT, tls_context=None, *,
                 max_clients=64, udp_workers=4, application_workers=8):
        if not 1 <= max_clients <= 128 or not 1 <= udp_workers <= 16 or application_workers < 1:
            raise ValueError('Invalid server capacity')
        self.tls_context = tls_context or server_context()
        self.host, self.tcp_port, self.udp_port = host, tcp_port, udp_port
        self.session_timeout = session_timeout
        self.max_clients = max_clients
        self.max_connections = max_clients + 32
        self.active_peers = {}
        self.peers_by_session = {}
        self.peers_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.application_pool = ThreadPoolExecutor(max_workers=application_workers,
                                                   thread_name_prefix='collab-app')
        self.router_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix='collab-route')
        self.buffer_budget = BufferBudget(64 * 1024 * 1024)
        self.udp_queues = [queue.Queue(maxsize=512) for _ in range(udp_workers)]
        self.udp_threads = []
        self.udp_dropped = 0
        self.udp_queue_peak = 0
        self.udp_tick_seconds = 0.01
        self.next_shard = 0
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
        self.io = ServerIO(self)

    # Mở cổng TCP/UDP, chạy các luồng UDP và vòng lặp xử lý kết nối.
    def start(self):
        try:
            self.tcp_sock.bind((self.host, self.tcp_port))
            self.tcp_port = self.tcp_sock.getsockname()[1]
            self.tcp_sock.listen(self.max_connections)
            self.udp_sock.bind((self.host, self.udp_port))
            self.udp_port = self.udp_sock.getsockname()[1]
            self.udp_sock.setblocking(False)
            for shard in range(len(self.udp_queues)):
                worker = threading.Thread(target=self._udp_worker, args=(shard,),
                                          name=f'collab-udp-{shard}', daemon=True)
                self.udp_threads.append(worker)
                worker.start()
            self.ready.set()
            print(f'[SERVER] TCP {self.host}:{self.tcp_port}, UDP {self.udp_port}')
            self.io.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            self.io.close()
            for worker in self.udp_threads:
                worker.join(3)
            self.application_pool.shutdown(wait=True, cancel_futures=True)
            self.router_pool.shutdown(wait=True, cancel_futures=True)
            self.tcp_sock.close()
            self.udp_sock.close()

    # Yêu cầu dừng máy chủ và đánh thức vòng lặp I/O để tiến hành kết thúc.
    def stop(self):
        # Socket shutdown and session removal belong to the selector thread.
        self.stop_event.set()
        self.io.wake()
        with self.peers_lock:
            endpoints = [peer['app'] for peer in self.active_peers.values()]
        for endpoint in endpoints:
            endpoint.close()  # Wake blocked application requests before joining workers.

    # Đưa thông báo tham gia hoặc rời phiên vào hàng đợi cập nhật của các peer.
    def _notify_peers_locked(self, event, peer, exclude=None):
        packet = Packet(MsgType.PEER_UPDATE, flags=PacketFlags.EOM,
                        payload=Packet.json_payload({'event': event, 'peer': peer})).to_bytes()
        for name, info in self.active_peers.items():
            if name != exclude:
                try:
                    info['updates'].put_nowait(packet)
                except queue.Full:
                    info['overflow'] = True  # Disconnect instead of silently losing peer state.

    # Tra cứu transport của người dùng đang trực tuyến dưới khóa bảo vệ danh sách phiên.
    def transport_for(self, username):
        with self.peers_lock:
            peer = self.active_peers.get(username)
            if peer is None:
                raise ConnectionError('Peer is not online')
            return peer['transport']

    # Gửi một bản tin thô qua transport UDP tin cậy của người dùng.
    def send_stream(self, username, data):
        return self.transport_for(username).send(data)

    # Lấy bản tin thô đã nhận từ hàng đợi ứng dụng của người dùng.
    def receive_stream(self, username, timeout=None):
        with self.peers_lock:
            app = self.active_peers[username]['app']
        return app.raw_messages.get(timeout=timeout)

    # Chia danh sách peer thành các gói phản hồi đăng nhập kèm thông tin phiên và khóa UDP.
    @staticmethod
    def auth_packets(peers, session_id, ack_num, udp_secret):
        """Split the login snapshot; EOM marks the final AUTH_RES page."""
        pages = []
        page = []
        base = {'success': True, 'session_id': session_id, 'udp_secret': udp_secret, 'version': 2}
        for peer in peers:
            if len(Packet.json_payload({**base, 'peers': page + [peer]})) > MAX_PAYLOAD_SIZE:
                pages.append(page)
                page = []
            page.append(peer)
        pages.append(page)
        return [Packet(MsgType.AUTH_RES,
                       flags=PacketFlags.ACK | (PacketFlags.EOM if i == len(pages) - 1 else 0),
                       ack_num=ack_num,
                       payload=Packet.json_payload({**base, 'peers': entries})).to_bytes()
                for i, entries in enumerate(pages)]

    # Kiểm tra thời hạn phiên và chuyển các cập nhật peer sang hàng đợi gửi TCP.
    def _maintain_connection(self, conn, now):
        if conn.username is None:
            return
        with self.peers_lock:
            peer = self.active_peers.get(conn.username)
            if (peer is None or peer['tcp_sock'] is not conn.sock or peer['overflow']
                    or now - peer['created'] >= SESSION_LIFETIME
                    or now - peer['last_seen'] >= self.session_timeout):
                raise TimeoutError('Session expired or peer update overflow')
        for _ in range(64):
            try:
                conn.queue(peer['updates'].get_nowait())
            except queue.Empty:
                break

    # Xử lý gói điều khiển theo trạng thái bắt tay, đăng nhập hoặc ngắt kết nối.
    def _control_packet(self, conn, pkt):
        if pkt.flags != PacketFlags.EOM:
            raise ValueError('Control packet requires only the EOM flag')
        ack_num = (pkt.seq_num + 1) & 0xFFFFFFFF
        if pkt.msg_type == MsgType.HANDSHAKE_SYN:
            if conn.handshaken or pkt.payload:
                raise ValueError('Unexpected handshake')
            conn.queue(Packet(MsgType.HANDSHAKE_ACK, flags=PacketFlags.ACK | PacketFlags.EOM,
                              ack_num=ack_num, payload=Packet.json_payload({
                                  'status': 'READY', 'server_udp_port': self.udp_port, 'version': 2})).to_bytes())
            conn.handshaken = True
        elif pkt.msg_type == MsgType.AUTH_REQ:
            try:
                self._authenticate(conn, pkt, ack_num)
            except ValueError as exc:
                conn.queue(Packet(MsgType.AUTH_RES, flags=PacketFlags.ACK | PacketFlags.EOM,
                                  ack_num=ack_num, payload=Packet.json_payload({
                                      'success': False, 'error': str(exc)})).to_bytes())
        elif pkt.msg_type == MsgType.DISCONNECT:
            if pkt.payload:
                raise ValueError('DISCONNECT must have an empty payload')
            self.io.close_connection(conn)
        else:
            raise ValueError('Unsupported TCP packet type')

    # Kiểm tra thông tin đăng nhập, tạo phiên mã hóa và đăng ký peer mới.
    def _authenticate(self, conn, pkt, ack_num):
        if not conn.handshaken or conn.username is not None:
            raise ValueError('Handshake first; only one login per connection')
        data = pkt.decode_json()
        candidate = validate_username(data.get('username'))
        port = validate_port(data.get('udp_port'))
        with self.peers_lock:
            if candidate in self.active_peers:
                raise ValueError('Username is already online')
            if len(self.active_peers) >= self.max_clients:
                raise ValueError('Server client capacity reached')
            session_id, udp_secret = secrets.token_hex(32), secrets.token_hex(32)
            cipher = SessionCipher(session_id, udp_secret, is_client=False)
            peers = [{'user': u, 'ip': info['ip'], 'udp_port': info['udp_port']}
                     for u, info in self.active_peers.items()]
            peers.append({'user': candidate, 'ip': conn.address[0], 'udp_port': port})
            responses = self.auth_packets(peers, session_id, ack_num, udp_secret)
            address = (conn.address[0], port)
            peer = {
                'username': candidate, 'ip': address[0], 'udp_port': port, 'tcp_sock': conn.sock,
                'session_id': session_id, 'last_seen': time.monotonic(), 'created': time.monotonic(),
                'cipher': cipher, 'generation': secrets.token_hex(32),
                'updates': queue.Queue(maxsize=256), 'overflow': False,
                'shard': self.next_shard % len(self.udp_queues), 'file_routes': {},
                'wake_pending': threading.Event(),
                'transport': ReliableUDP(lambda raw: self._send_udp(raw, address), session_id,
                                         encode_packet=cipher.seal, buffer_budget=self.buffer_budget,
                                         wakeup=lambda: self._wake_transport(peer)),
            }
            peer['app'] = Endpoint(peer['transport'],
                lambda header, body: self._route_application(candidate, peer, header, body),
                executor=self.application_pool)
            self.next_shard += 1
            self.active_peers[candidate] = peer
            self.peers_by_session[cipher.sid] = peer
            conn.username = candidate
            self._notify_peers_locked('join', peers[-1], exclude=candidate)
        for response in responses:
            conn.queue(response)

    # Gỡ đúng phiên sở hữu kết nối đã đóng và giải phóng tài nguyên của phiên đó.
    def _connection_closed(self, conn):
        with self.peers_lock:
            peer = self.active_peers.get(conn.username)
            if peer is None or peer['tcp_sock'] is not conn.sock:
                return
            del self.active_peers[conn.username]
            self.peers_by_session.pop(peer['cipher'].sid, None)
            self._notify_peers_locked('leave', {'user': conn.username})
        # Do not hold registry lock while closing transport/crypto locks.
        peer['app'].close()
        peer['transport'].close()
        peer['cipher'].close()

    # Chuyển tiếp chat hoặc file đến người nhận, dùng danh tính từ phiên đã xác thực.
    def _route_application(self, sender, owner, header, body):
        op = header.get('op')
        with self.peers_lock:
            if self.active_peers.get(sender) is not owner:
                raise ConnectionError('Sender session is no longer active')
        if op == 'chat':
            text = body.decode('utf-8')
            if not text or len(body) > 65536:
                raise ValueError('Chat text must contain 1..65536 UTF-8 bytes')
            recipient = header.get('to')
            with self.peers_lock:
                if recipient is None:
                    targets = [(name, peer) for name, peer in self.active_peers.items() if name != sender]
                else:
                    validate_username(recipient)
                    target = self.active_peers.get(recipient)
                    if target is None:
                        raise ApplicationError('Recipient is offline')
                    targets = [(recipient, target)]
            # Identity comes from the authenticated session, never from the sender's JSON.
            futures = {name: self.router_pool.submit(
                peer['app'].request, 'chat', body, timeout=5, sender=sender,
                broadcast=recipient is None) for name, peer in targets}
            delivered, failed = [], {}
            for name, future in futures.items():
                try:
                    future.result()
                    delivered.append(name)
                except (ApplicationError, OSError, BufferError, ValueError, OverflowError, CancelledError) as exc:
                    failed[name] = str(exc)
            return {'delivered': delivered, 'failed': failed}
        if op not in ('file_begin', 'file_block', 'file_end', 'file_abort'):
            raise ValueError('Unsupported application operation')
        file_id = validate_file_id(header.get('file_id'))
        recipient = validate_username(header.get('to'))
        if len(body) > FILE_BLOCK_SIZE:
            raise ValueError('File block exceeds limit')
        routes = owner['file_routes']  # Accessed only by this session's application worker.
        if op == 'file_begin':
            if len(routes) >= 8 or file_id in routes:
                raise ValueError('Too many transfers or duplicate file ID')
            with self.peers_lock:
                target = self.active_peers.get(recipient)
            if target is None:
                raise ApplicationError('Recipient is offline')
            routes[file_id] = (recipient, target)
        route = routes.get(file_id)
        if route is None or route[0] != recipient:
            raise ValueError('Unknown file transfer destination')
        target = route[1]
        with self.peers_lock:
            if self.active_peers.get(recipient) is not target:
                routes.pop(file_id, None)
                raise ApplicationError('Recipient disconnected or changed session')
        fields = {key: header[key] for key in ('file_id', 'name', 'size', 'offset', 'sha256') if key in header}
        try:
            return target['app'].request(op, body, timeout=10, sender=sender,
                                         sender_session=owner['generation'], **fields)
        except ApplicationError:
            if op == 'file_begin':
                routes.pop(file_id, None)
            raise
        finally:
            if op in ('file_end', 'file_abort'):
                routes.pop(file_id, None)

    # Gửi datagram UDP và chuẩn hóa lỗi bộ đệm đầy để transport có thể thử lại.
    def _send_udp(self, raw, address):
        try:
            self.udp_sock.sendto(raw, address)
        except OSError as exc:
            if isinstance(exc, BlockingIOError) or getattr(exc, 'winerror', None) == 10055:
                raise BlockingIOError('UDP send buffer full') from exc
            raise

    # Tra cứu phiên theo datagram và đưa dữ liệu vào hàng đợi của luồng UDP phụ trách.
    def _enqueue_datagram(self, raw, address):
        if not HEADER_SIZE + 32 <= len(raw) <= MAX_PACKET_SIZE:
            return
        # Session ID is only a routing hint until the worker authenticates GCM.
        with self.peers_lock:
            peer = self.peers_by_session.get(raw[HEADER_SIZE:HEADER_SIZE + 32])
            if peer is None or address != (peer['ip'], peer['udp_port']):
                return
        inbox = self.udp_queues[peer['shard']]
        try:
            inbox.put_nowait((peer, raw))
            self.udp_queue_peak = max(self.udp_queue_peak, inbox.qsize())
        except queue.Full:
            self.udp_dropped += 1  # Bounded overload; reliable transport retries/backoffs.

    # Đánh thức luồng UDP phụ trách khi transport có dữ liệu cần gửi.
    def _wake_transport(self, peer):
        if peer['wake_pending'].is_set():
            return
        peer['wake_pending'].set()
        try:
            self.udp_queues[peer['shard']].put_nowait((peer, None))
        except queue.Full:
            peer['wake_pending'].clear()  # Periodic tick remains the fallback.

    # Giải mã datagram, xử lý heartbeat và điều phối truyền UDP cho nhóm phiên được phân công.
    def _udp_worker(self, shard):
        inbox = self.udp_queues[shard]
        next_tick = time.monotonic()
        while not self.stop_event.is_set():
            now = time.monotonic()
            if now >= next_tick:
                with self.peers_lock:
                    peers = [peer for peer in self.active_peers.values() if peer['shard'] == shard]
                for peer in peers:
                    peer['transport'].tick()
                    peer['app'].poll()
                next_tick = time.monotonic() + self.udp_tick_seconds
            try:
                peer, raw = inbox.get(timeout=max(0, next_tick - time.monotonic()))
            except queue.Empty:
                continue
            if raw is None:
                peer['wake_pending'].clear()
                peer['transport'].tick()
                continue
            try:
                if time.monotonic() - peer['last_seen'] >= self.session_timeout:
                    continue
                pkt = peer['cipher'].open(Packet.from_bytes(raw, copy_payload=False))
                if pkt.msg_type in (MsgType.STREAM_DATA, MsgType.ACK):
                    peer['transport'].handle_packet(pkt)
                    peer['app'].poll()
                    peer['transport'].tick()  # ACK progress can open a send window immediately.
                elif pkt.msg_type == MsgType.HEARTBEAT and pkt.flags == PacketFlags.EOM:
                    data = pkt.decode_json()
                    token = data.get('session_id')
                    if (data.get('username') == peer['username'] and isinstance(token, str)
                            and len(token) == 64 and token.isascii()
                            and secrets.compare_digest(peer['session_id'], token)):
                        with self.peers_lock:
                            if (self.active_peers.get(peer['username']) is peer
                                    and time.monotonic() - peer['last_seen'] < self.session_timeout):
                                peer['last_seen'] = time.monotonic()
            except (OSError, ValueError):
                continue  # A malformed, stale or temporarily unsendable datagram is local to its session.



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='TLS + encrypted UDP collaboration server')
    parser.add_argument('--host', default=TCP_HOST)
    parser.add_argument('--tcp-port', type=int, default=TCP_PORT)
    parser.add_argument('--udp-port', type=int, default=UDP_PORT)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--max-clients', type=int, default=64)
    parser.add_argument('--udp-workers', type=int, default=4)
    args = parser.parse_args()
    try:
        CollaborationServer(args.host, args.tcp_port, args.udp_port,
                            tls_context=server_context(args.cert, args.key),
                            max_clients=args.max_clients, udp_workers=args.udp_workers).start()
    except FileNotFoundError:
        parser.exit(1, 'TLS identity missing. Run: python btl_btlmmt/security.py\n')
