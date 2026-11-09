import queue
import secrets
import select
import socket
import threading
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor

from protocol import (
    IO_TIMEOUT, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, SESSION_TIMEOUT,
    MsgType, Packet, PacketFlags, recv_tcp_packet, validate_port, validate_username,
)

from reliable_udp import ReliableUDP
from security import SessionCipher, SESSION_LIFETIME, server_context
from application import Endpoint, ApplicationError
from file_transfer import FILE_BLOCK_SIZE, validate_file_id

TCP_HOST = '0.0.0.0'
TCP_PORT = 8888
UDP_PORT = 9000


class CollaborationServer:
    def __init__(self, host=TCP_HOST, tcp_port=TCP_PORT, udp_port=UDP_PORT,
                 session_timeout=SESSION_TIMEOUT, tls_context=None):
        self.tls_context = tls_context or server_context()
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.session_timeout = session_timeout
        self.active_peers = {}
        self.router_pool = ThreadPoolExecutor(max_workers=16)
        self.peers_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.connections = set()
        self.workers = set()
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self):
        udp_thread = None
        try:
            self.tcp_sock.bind((self.host, self.tcp_port))
            self.tcp_port = self.tcp_sock.getsockname()[1]
            self.tcp_sock.listen(20)
            self.tcp_sock.settimeout(0.5)
            self.udp_sock.bind((self.host, self.udp_port))
            self.udp_port = self.udp_sock.getsockname()[1]
            self.udp_sock.settimeout(0.02)
            udp_thread = threading.Thread(target=self.handle_udp_stream, daemon=True)
            udp_thread.start()
            self.ready.set()
            print(f'[SERVER] TCP {self.host}:{self.tcp_port}, UDP {self.udp_port}')
            while not self.stop_event.is_set():
                try:
                    client_sock, addr = self.tcp_sock.accept()
                except socket.timeout:
                    continue
                worker = threading.Thread(target=self.handle_tcp_client,
                                          args=(client_sock, addr), daemon=True)
                with self.peers_lock:
                    self.connections.add(client_sock)
                    self.workers.add(worker)
                worker.start()
        except KeyboardInterrupt:
            pass
        except OSError:
            if not self.stop_event.is_set():
                raise
        finally:
            self.stop()
            if udp_thread is not None:
                udp_thread.join(IO_TIMEOUT + 1)
            with self.peers_lock:
                workers = list(self.workers)
            for worker in workers:
                worker.join(IO_TIMEOUT + 1)
            self.router_pool.shutdown(wait=True, cancel_futures=True)

    def stop(self):
        self.stop_event.set()
        self.tcp_sock.close()
        self.udp_sock.close()
        with self.peers_lock:
            connections = list(self.connections)
            endpoints = [peer['app'] for peer in self.active_peers.values()]
        for endpoint in endpoints:
            endpoint.close()
        for sock in connections:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def _notify_peers_locked(self, event, peer, exclude=None):
        packet = Packet(MsgType.PEER_UPDATE, flags=PacketFlags.EOM,
                        payload=Packet.json_payload({'event': event, 'peer': peer})).to_bytes()
        for name, info in self.active_peers.items():
            if name != exclude:
                try:
                    info['updates'].put_nowait(packet)
                except queue.Full:
                    info['overflow'] = True  # Disconnect instead of silently losing peer state.

    def transport_for(self, username):
        with self.peers_lock:
            peer = self.active_peers.get(username)
            if peer is None:
                raise ConnectionError('Peer is not online')
            return peer['transport']

    def send_stream(self, username, data):
        return self.transport_for(username).send(data)

    def receive_stream(self, username, timeout=None):
        with self.peers_lock:
            app = self.active_peers[username]['app']
        return app.raw_messages.get(timeout=timeout)

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

    def handle_tcp_client(self, client_sock, client_addr):
        username = None
        handshaken = False
        login_deadline = time.monotonic() + IO_TIMEOUT * 2
        try:
            client_sock.settimeout(IO_TIMEOUT)
            raw_sock = client_sock
            client_sock = self.tls_context.wrap_socket(raw_sock, server_side=True, do_handshake_on_connect=False)
            with self.peers_lock:
                self.connections.discard(raw_sock)
                self.connections.add(client_sock)
            client_sock.do_handshake()
            while not self.stop_event.is_set():
                now = time.monotonic()
                if username is None:
                    if now >= login_deadline:
                        raise TimeoutError('Login timed out')
                else:
                    with self.peers_lock:
                        peer = self.active_peers.get(username)
                        expired = (peer is None or peer['tcp_sock'] is not client_sock
                                   or peer['overflow']
                                   or now - peer['created'] >= SESSION_LIFETIME
                                   or now - peer['last_seen'] >= self.session_timeout)
                    if peer is None or expired:
                        raise TimeoutError('Heartbeat expired or peer update queue overflowed')
                    while not peer['updates'].empty():
                        client_sock.sendall(peer['updates'].get_nowait())
                # Idle connections are polled; partial-frame timeouts close the connection.
                if not client_sock.pending() and not select.select([client_sock], [], [], 0.25)[0]:
                    continue
                pkt = recv_tcp_packet(client_sock)
                if pkt.flags != PacketFlags.EOM:
                    raise ValueError('Control packet requires only the EOM flag')
                ack_num = (pkt.seq_num + 1) & 0xFFFFFFFF
                if pkt.msg_type == MsgType.HANDSHAKE_SYN:
                    if handshaken or pkt.payload:
                        raise ValueError('Unexpected handshake')
                    response = Packet(MsgType.HANDSHAKE_ACK,
                                      flags=PacketFlags.ACK | PacketFlags.EOM,
                                      ack_num=ack_num,
                                      payload=Packet.json_payload({
                                          'status': 'READY', 'server_udp_port': self.udp_port, 'version': 2}))
                    client_sock.sendall(response.to_bytes())
                    handshaken = True
                elif pkt.msg_type == MsgType.AUTH_REQ:
                    try:
                        if not handshaken or username is not None:
                            raise ValueError('Handshake first; only one login per connection')
                        data = pkt.decode_json()
                        candidate = validate_username(data.get('username'))
                        port = validate_port(data.get('udp_port'))
                        session_id = secrets.token_hex(32)
                        udp_secret = secrets.token_hex(32)
                        cipher = SessionCipher(session_id, udp_secret, is_client=False)
                        with self.peers_lock:
                            if candidate in self.active_peers:
                                raise ValueError('Username is already online')
                            peers = [{'user': u, 'ip': info['ip'], 'udp_port': info['udp_port']}
                                     for u, info in self.active_peers.items()]
                            peers.append({'user': candidate, 'ip': client_addr[0], 'udp_port': port})
                            responses = self.auth_packets(peers, session_id, ack_num, udp_secret)
                            self.active_peers[candidate] = {
                                'ip': client_addr[0], 'udp_port': port, 'tcp_sock': client_sock,
                                'session_id': session_id, 'last_seen': time.monotonic(),
                                'created': time.monotonic(), 'cipher': cipher,
                                'generation': secrets.token_hex(32),
                                'updates': queue.Queue(maxsize=256), 'overflow': False,
                                'transport': ReliableUDP(
                                    lambda raw, addr=(client_addr[0], port), crypto=cipher:
                                        self.udp_sock.sendto(crypto.seal(raw), addr),
                                    session_id),
                            }
                            peer = self.active_peers[candidate]
                            peer['file_routes'] = {}
                            peer['app'] = Endpoint(peer['transport'],
                                lambda header, body, name=candidate, owner=peer:
                                    self._route_application(name, owner, header, body))
                            username = candidate
                            self._notify_peers_locked('join', peers[-1], exclude=candidate)
                        for response in responses:
                            client_sock.sendall(response)
                    except ValueError as exc:
                        client_sock.sendall(Packet(
                            MsgType.AUTH_RES, flags=PacketFlags.ACK | PacketFlags.EOM,
                            ack_num=ack_num, payload=Packet.json_payload({
                                'success': False, 'error': str(exc)})).to_bytes())
                elif pkt.msg_type == MsgType.DISCONNECT:
                    if pkt.payload:
                        raise ValueError('DISCONNECT must have an empty payload')
                    break
                else:
                    raise ValueError('Unsupported TCP packet type')
        except (OSError, ValueError) as exc:
            if not self.stop_event.is_set():
                print(f'[TCP] Closing {client_addr}: {exc!a}')
        finally:
            with self.peers_lock:
                peer = self.active_peers.get(username)
                if peer is not None and peer['tcp_sock'] is client_sock:
                    del self.active_peers[username]
                    peer['app'].close()
                    peer['transport'].close()
                    peer['cipher'].close()
                    self._notify_peers_locked('leave', {'user': username})
                self.connections.discard(client_sock)
                self.workers.discard(threading.current_thread())
            client_sock.close()
            if peer is not None and peer['tcp_sock'] is client_sock:
                peer['app'].join()

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

    def handle_udp_stream(self):
        while not self.stop_event.is_set():
            with self.peers_lock:
                transports = [peer['transport'] for peer in self.active_peers.values()]
            for transport in transports:
                transport.tick()
            try:
                # Extra byte detects oversized datagrams without accepting a truncated prefix.
                raw_data, addr = self.udp_sock.recvfrom(MAX_PACKET_SIZE + 1)
                pkt = Packet.from_bytes(raw_data)
                with self.peers_lock:
                    peer = next((entry for entry in self.active_peers.values()
                                 if addr == (entry['ip'], entry['udp_port'])
                                 and pkt.payload[:32] == entry['cipher'].sid
                                 and time.monotonic() - entry['last_seen'] < self.session_timeout), None)
                if peer is None:
                    continue
                try:
                    pkt = peer['cipher'].open(pkt)
                except (ValueError, ConnectionError):
                    continue
                if pkt.msg_type in (MsgType.STREAM_DATA, MsgType.ACK):
                    peer['transport'].handle_packet(pkt)
                    continue
                if pkt.msg_type != MsgType.HEARTBEAT or pkt.flags != PacketFlags.EOM:
                    continue
                data = pkt.decode_json()
                username = validate_username(data.get('username'))
                token = data.get('session_id')
                if not isinstance(token, str) or len(token) != 64 or not token.isascii():
                    continue
                with self.peers_lock:
                    peer = self.active_peers.get(username)
                    if (peer is not None and addr == (peer['ip'], peer['udp_port'])
                            and secrets.compare_digest(peer['session_id'], token)
                            and time.monotonic() - peer['last_seen'] < self.session_timeout):
                        peer['last_seen'] = time.monotonic()
            except socket.timeout:
                continue
            except ValueError:
                continue
            except OSError as exc:
                if self.stop_event.is_set():
                    break
                if isinstance(exc, ConnectionResetError) or getattr(exc, 'winerror', None) == 10040:
                    continue  # UDP ICMP errors / oversized Windows datagrams are per-packet errors.
                print(f'[UDP ERROR] {exc!a}')
                break


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='TLS + encrypted UDP collaboration server')
    parser.add_argument('--host', default=TCP_HOST)
    parser.add_argument('--tcp-port', type=int, default=TCP_PORT)
    parser.add_argument('--udp-port', type=int, default=UDP_PORT)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    args = parser.parse_args()
    try:
        CollaborationServer(args.host, args.tcp_port, args.udp_port,
                            tls_context=server_context(args.cert, args.key)).start()
    except FileNotFoundError:
        parser.exit(1, 'TLS identity missing. Run: python btl_btlmmt/security.py\n')
