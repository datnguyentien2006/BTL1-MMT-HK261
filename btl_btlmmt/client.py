import os
import stat
import hashlib
import queue
from pathlib import Path
import uuid
import select
import ssl
import socket
import threading
import time

from protocol import (
    HEARTBEAT_INTERVAL, IO_TIMEOUT, MAX_PACKET_SIZE, MsgType, Packet, PacketFlags,
    recv_tcp_packet, validate_port, validate_username,
)

from reliable_udp import ReliableUDP
from security import SessionCipher, client_context
from application import Endpoint
from file_transfer import FileReceiver, FILE_BLOCK_SIZE, MAX_FILE_SIZE, validate_filename

SERVER_IP = '127.0.0.1'
SERVER_TCP_PORT = 8888


class CollaborationClient:
    def __init__(self, username, server_ip=SERVER_IP, server_tcp_port=SERVER_TCP_PORT,
                 heartbeat_interval=HEARTBEAT_INTERVAL, download_dir=None, tls_context=None):
        self.tls_context = tls_context or client_context()
        self.cipher = None
        self.username = validate_username(username)
        self.server_ip = server_ip
        self.server_tcp_port = validate_port(server_tcp_port)
        self.heartbeat_interval = heartbeat_interval
        self.seq_num = 1
        self.session_id = None
        self.peers = []
        self.peers_lock = threading.Lock()
        self.receiver_thread = None
        self.transport = None
        self.app = None
        self.chat_messages = queue.Queue(maxsize=256)
        self.file_events = queue.Queue(maxsize=32)
        self.file_receiver = FileReceiver(download_dir or Path('downloads') / self.username,
                                          self.file_events)
        self.stop_event = threading.Event()
        self.connected = False
        self.heartbeat_thread = None
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.settimeout(IO_TIMEOUT)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
        self.udp_sock.bind(('0.0.0.0', 0))
        self.udp_sock.setblocking(False)
        self.local_udp_port = self.udp_sock.getsockname()[1]
        self.server_udp_port = None
        self.wake_read, self.wake_write = socket.socketpair()
        self.wake_read.setblocking(False)
        self.wake_write.setblocking(False)

    def _wake_receiver(self):
        try:
            self.wake_write.send(b'\0')
        except OSError:
            pass

    def _check_response(self, pkt, msg_type):
        if (pkt.msg_type != msg_type or not pkt.flags & PacketFlags.ACK
                or pkt.flags & ~(PacketFlags.ACK | PacketFlags.EOM)
                or pkt.ack_num != ((self.seq_num + 1) & 0xFFFFFFFF)):
            raise ValueError('Invalid response type, flags or ACK')
        return pkt.decode_json()

    def connect_and_authenticate(self):
        """Authenticate once and keep both sockets open until close()/run() exits."""
        if self.connected or self.stop_event.is_set():
            raise ValueError('Create a new client for a new connection')
        try:
            self.tcp_sock.connect((self.server_ip, self.server_tcp_port))
            self.tcp_sock = self.tls_context.wrap_socket(self.tcp_sock, server_hostname=self.server_ip)
            self.server_ip = self.tcp_sock.getpeername()[0]
            self.tcp_sock.sendall(Packet(MsgType.HANDSHAKE_SYN, flags=PacketFlags.EOM,
                                        seq_num=self.seq_num).to_bytes())
            reply = recv_tcp_packet(self.tcp_sock)
            data = self._check_response(reply, MsgType.HANDSHAKE_ACK)
            if data.get('status') != 'READY' or data.get('version') != 2 or not reply.flags & PacketFlags.EOM:
                raise ValueError('Server is not ready')
            self.server_udp_port = validate_port(data.get('server_udp_port'))
            self.seq_num += 1
            self.tcp_sock.sendall(Packet(
                MsgType.AUTH_REQ, flags=PacketFlags.EOM, seq_num=self.seq_num,
                payload=Packet.json_payload({'username': self.username,
                                             'udp_port': self.local_udp_port})).to_bytes())
            udp_secret = None
            while True:
                reply = recv_tcp_packet(self.tcp_sock)
                data = self._check_response(reply, MsgType.AUTH_RES)
                if data.get('success') is not True:
                    raise ValueError(f"Login failed: {data.get('error', 'invalid response')}")
                secret = data.get('udp_secret')
                if (data.get('version') != 2 or not isinstance(secret, str) or len(secret) != 64
                        or any(c not in '0123456789abcdef' for c in secret)
                        or (udp_secret is not None and udp_secret != secret)):
                    raise ValueError('Invalid UDP key exchange')
                udp_secret = secret
                token = data.get('session_id')
                if (not isinstance(token, str) or len(token) != 64
                        or any(c not in '0123456789abcdef' for c in token)
                        or (self.session_id is not None and token != self.session_id)):
                    raise ValueError('Invalid session ID')
                entries = data.get('peers')
                if not isinstance(entries, list):
                    raise ValueError('Invalid peer list')
                for peer in entries:
                    if not isinstance(peer, dict):
                        raise ValueError('Invalid peer')
                    validate_username(peer.get('user'))
                    validate_port(peer.get('udp_port'))
                    if not isinstance(peer.get('ip'), str):
                        raise ValueError('Invalid peer IP')
                    socket.inet_pton(socket.AF_INET, peer['ip'])
                self.session_id = token
                self.peers.extend(entries)
                if reply.flags & PacketFlags.EOM:
                    break
            cipher = SessionCipher(self.session_id, udp_secret, is_client=True)
            self.cipher = cipher
            self.transport = ReliableUDP(
                lambda raw: self.udp_sock.sendto(raw, (self.server_ip, self.server_udp_port)),
                self.session_id, encode_packet=cipher.seal, wakeup=self._wake_receiver)
            self.app = Endpoint(self.transport, self._handle_application, self.file_receiver.expire)
            self.connected = True
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()
            self.receiver_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receiver_thread.start()
            print(f'[CLIENT] {self.username!a} online. Peers: {len(self.peers)}. Ctrl+C to exit.')
        except BaseException:
            self.close()
            raise

    def _heartbeat_loop(self):
        while not self.stop_event.is_set():
            try:
                pkt = Packet(MsgType.HEARTBEAT, flags=PacketFlags.EOM,
                             payload=Packet.json_payload({'username': self.username,
                                                          'session_id': self.session_id}))
                cipher = self.cipher
                if cipher is None:
                    raise ConnectionError('Session cipher is not initialized')
                self.udp_sock.sendto(cipher.seal(pkt), (self.server_ip, self.server_udp_port))
            except BlockingIOError:
                pass  # Next heartbeat retries; a full local UDP buffer is temporary.
            except OSError:
                self.stop_event.set()
                return
            if self.stop_event.wait(self.heartbeat_interval):
                return

    def send_stream(self, data):
        transport = self.transport
        if not self.connected or transport is None:
            raise ConnectionError('Client is not online')
        return transport.send(data)

    def receive_stream(self, timeout=None):
        app = self.app
        if app is None:
            raise ConnectionError('Client is not online')
        return app.raw_messages.get(timeout=timeout)

    def _handle_application(self, header, body):
        sender = validate_username(header.get('sender'))
        if header.get('op') == 'chat':
            text = body.decode('utf-8')
            if not text or len(body) > 65536:
                raise ValueError('Invalid chat message')
            try:
                self.chat_messages.put_nowait({'sender': sender, 'text': text,
                                               'broadcast': header.get('broadcast') is True})
            except queue.Full:
                raise BufferError('Chat inbox is full')
            return {'accepted': True}
        if header.get('op') in ('file_begin', 'file_block', 'file_end', 'file_abort'):
            return self.file_receiver.handle(header, body)
        raise ValueError('Unsupported server application request')

    def send_chat(self, text, recipient=None, timeout=15):
        app = self.app
        if not self.connected or app is None:
            raise ConnectionError('Client is not online')
        if not isinstance(text, str) or not text or len(text.encode('utf-8')) > 65536:
            raise ValueError('Chat text must contain 1..65536 UTF-8 bytes')
        if recipient is not None:
            validate_username(recipient)
        return app.request('chat', text.encode('utf-8'), timeout=timeout, to=recipient)

    def receive_chat(self, timeout=None):
        return self.chat_messages.get(timeout=timeout)

    def receive_file(self, timeout=None):
        return self.file_events.get(timeout=timeout)

    def send_file(self, path, recipient, *, timeout=15, progress=None):
        """Send bounded blocks; return only after receiver verifies and publishes file.

        progress(sent_bytes, total_bytes) runs on the calling thread after each
        application-level block acknowledgement. Call from a worker for a UI.
        """
        app = self.app
        if not self.connected or app is None:
            raise ConnectionError('Client is not online')
        validate_username(recipient)
        path = Path(path)
        name = validate_filename(path.name)
        file_id = uuid.uuid4().hex
        try:
            with path.open('rb') as source:
                info = os.fstat(source.fileno())
                size = info.st_size
                if not stat.S_ISREG(info.st_mode) or size > MAX_FILE_SIZE:
                    raise ValueError('Source must be a regular file of at most 1 GiB')
                app.request('file_begin', timeout=timeout, to=recipient,
                                 file_id=file_id, name=name, size=size)
                offset = 0
                digest = hashlib.sha256()
                while True:
                    block = source.read(FILE_BLOCK_SIZE)
                    if not block:
                        break
                    result = app.request('file_block', block, timeout=timeout,
                                              to=recipient, file_id=file_id, offset=offset)
                    offset += len(block)
                    digest.update(block)
                    if not isinstance(result, dict) or result.get('offset') != offset:
                        raise ValueError('Invalid file block acknowledgement')
                    if progress is not None:
                        progress(offset, size)
                if offset != size:
                    raise ValueError('Source file size changed during transfer')
                result = app.request('file_end', timeout=timeout, to=recipient,
                                          file_id=file_id, sha256=digest.hexdigest())
                if (not isinstance(result, dict) or result.get('sha256') != digest.hexdigest()
                        or result.get('size') != size):
                    raise ValueError('Invalid file completion acknowledgement')
                return result
        except BaseException:
            try:
                app.request('file_abort', timeout=2, to=recipient, file_id=file_id)
            except (Exception, KeyboardInterrupt):
                pass
            raise

    def get_peers(self):
        with self.peers_lock:
            return [dict(peer) for peer in self.peers]

    def _apply_peer_update(self, pkt):
        if pkt.msg_type != MsgType.PEER_UPDATE or pkt.flags != PacketFlags.EOM:
            raise ValueError('Invalid peer update')
        data = pkt.decode_json()
        peer = data.get('peer')
        if not isinstance(peer, dict):
            raise ValueError('Invalid peer entry')
        name = validate_username(peer.get('user'))
        if data.get('event') == 'join':
            validate_port(peer.get('udp_port'))
            if not isinstance(peer.get('ip'), str):
                raise ValueError('Invalid IP')
            socket.inet_pton(socket.AF_INET, peer['ip'])
        elif data.get('event') == 'leave':
            self.file_receiver.discard_sender(name)
        else:
            raise ValueError('Invalid peer event')
        with self.peers_lock:
            self.peers = [entry for entry in self.peers if entry['user'] != name]
            if data['event'] == 'join':
                self.peers.append(peer)

    def _receive_loop(self):
        transport = self.transport
        cipher = self.cipher
        try:
            if transport is None or cipher is None:
                raise ConnectionError('Client transport is not initialized')
            next_tick = time.monotonic()
            while not self.stop_event.is_set():
                now = time.monotonic()
                if now >= next_tick:
                    transport.tick()
                    next_tick = time.monotonic() + 0.01
                tls_pending = isinstance(self.tcp_sock, ssl.SSLSocket) and self.tcp_sock.pending()
                readable = select.select([self.tcp_sock, self.udp_sock, self.wake_read], [], [],
                                         0 if tls_pending else max(0, next_tick - time.monotonic()))[0]
                if tls_pending and self.tcp_sock not in readable:
                    readable.append(self.tcp_sock)
                for sock in readable:
                    if sock is self.wake_read:
                        try:
                            sock.recv(4096)
                        except BlockingIOError:
                            pass
                        transport.tick()
                    elif sock is self.tcp_sock:
                        pkt = recv_tcp_packet(sock)
                        if pkt.msg_type == MsgType.DISCONNECT:
                            return
                        self._apply_peer_update(pkt)
                    else:
                        for _ in range(64):
                            try:
                                raw, addr = sock.recvfrom(MAX_PACKET_SIZE + 1)
                                if addr == (self.server_ip, self.server_udp_port):
                                    transport.handle_packet(cipher.open(Packet.from_bytes(raw, copy_payload=False)))
                            except BlockingIOError:
                                break
                            except ValueError:
                                continue  # Bad datagrams must not tear down the TCP session.
                            except OSError as exc:
                                if isinstance(exc, ConnectionResetError) or getattr(exc, 'winerror', None) == 10040:
                                    continue
                                raise
                        transport.tick()
        except (OSError, ValueError) as exc:
            if not self.stop_event.is_set():
                print(f'[CLIENT ERROR] {exc!a}')
        finally:
            self.close()

    def run(self):
        try:
            self.connect_and_authenticate()
            while not self.stop_event.wait(0.25):
                pass
        except KeyboardInterrupt:
            pass
        except (OSError, ValueError) as exc:
            print(f'[CLIENT ERROR] {exc!a}')
        finally:
            self.close()

    def close(self):
        self.stop_event.set()
        self._wake_receiver()
        if self.app is not None:
            self.app.close()
        if self.transport is not None:
            self.transport.close()
        if self.cipher is not None:
            self.cipher.close()
        if self.heartbeat_thread is not None and self.heartbeat_thread is not threading.current_thread():
            self.heartbeat_thread.join(IO_TIMEOUT)
        if self.connected:
            self.connected = False
            try:
                self.tcp_sock.sendall(Packet(MsgType.DISCONNECT,
                                            flags=PacketFlags.EOM).to_bytes())
            except OSError:
                pass
        try:
            self.tcp_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.tcp_sock.close()
        self.udp_sock.close()
        if self.receiver_thread is not None and self.receiver_thread is not threading.current_thread():
            self.receiver_thread.join(IO_TIMEOUT + 1)
        self.wake_read.close()
        self.wake_write.close()
        if self.app is not None:
            self.app.join()
        self.file_receiver.close()
        with self.peers_lock:
            self.peers = []


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='TLS + encrypted UDP collaboration client')
    parser.add_argument('username', nargs='?', default='alice')
    parser.add_argument('--server', default=SERVER_IP)
    parser.add_argument('--port', type=int, default=SERVER_TCP_PORT)
    parser.add_argument('--ca', help='Trusted server certificate, provisioned out of band')
    parser.add_argument('--downloads')
    args = parser.parse_args()
    try:
        CollaborationClient(args.username, server_ip=args.server, server_tcp_port=args.port,
                            download_dir=args.downloads, tls_context=client_context(args.ca)).run()
    except FileNotFoundError:
        parser.exit(1, 'Trusted certificate missing. Provision server.crt or run security.py for local setup.\n')
    except (ValueError, OSError) as exc:
        parser.exit(1, f'[CLIENT ERROR] {exc!a}\n')
