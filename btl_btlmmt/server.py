import socket
import threading
import time
from queue import Queue
from typing import Dict, Any

from protocol import Packet, MsgType, PacketFlags, recv_tcp_packet

TCP_HOST = '0.0.0.0'
TCP_PORT = 8888
UDP_PORT = 9000

class CollaborationServer:
    def __init__(self, host=TCP_HOST, tcp_port=TCP_PORT, udp_port=UDP_PORT):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.is_running = False

        # Quản lý Peer: {username: {"ip": str, "udp_port": int, "tcp_sock": socket, "last_seen": float}}
        self.active_peers: Dict[str, Dict[str, Any]] = {}
        # Tra cứu ngược: (ip, udp_port) -> username
        self.addr_to_user: Dict[tuple, str] = {}
        self.peers_lock = threading.Lock()

        # Quản lý Stream File: {stream_id: {"sender": str, "target_user": str}}
        self.active_streams: Dict[int, Dict[str, str]] = {}
        self.streams_lock = threading.Lock()

        # Sockets
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Hàng đợi xử lý gói tin UDP tránh nghẽn luồng mạng chính
        self.udp_queue = Queue()

    def start(self):
        self.tcp_sock.bind((self.host, self.tcp_port))
        self.tcp_sock.listen(50)
        self.udp_sock.bind((self.host, self.udp_port))
        self.is_running = True

        print(f"[SERVER] TCP Listening: {self.host}:{self.tcp_port}", flush=True)
        print(f"[SERVER] UDP Streaming Engine: {self.host}:{self.udp_port}", flush=True)

        # 1. Luồng nhận gói tin thô UDP vào Queue
        threading.Thread(target=self._udp_receiver_loop, daemon=True, name="UDPReceiver").start()

        # 2. Worker Pool xử lý định tuyến UDP (2 luồng xử lý song song)
        for i in range(2):
            threading.Thread(target=self._udp_worker_loop, daemon=True, name=f"UDPWorker-{i}").start()

        # 3. Luồng kiểm tra Timeout định kỳ (Bước 7)
        threading.Thread(target=self.cleanup_dead_peers, daemon=True, name="PeerCleanup").start()

        # 4. Luồng chính: Chấp nhận kết nối TCP Client mới (Bước 2, 3)
        try:
            while self.is_running:
                client_sock, client_addr = self.tcp_sock.accept()
                threading.Thread(
                    target=self.handle_tcp_client,
                    args=(client_sock, client_addr),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\n[SERVER] Đang dừng máy chủ...", flush=True)
        finally:
            self.stop()

    def stop(self):
        self.is_running = False
        try:
            self.tcp_sock.close()
        except Exception:
            pass
        try:
            self.udp_sock.close()
        except Exception:
            pass

    def broadcast_peer_list(self):
        """Thông báo danh sách Active Peers tới toàn bộ Client qua TCP (Bước 3)."""
        with self.peers_lock:
            peer_list = [
                {"user": u, "ip": info["ip"], "udp_port": info["udp_port"]}
                for u, info in self.active_peers.items()
            ]
            pkt = Packet(
                msg_type=MsgType.PEER_UPDATE,
                stream_id=0,
                seq_num=0,
                flags=PacketFlags.EOM,
                payload=Packet.json_payload({"peers": peer_list})
            )
            raw_bytes = pkt.to_bytes()

            for u, info in list(self.active_peers.items()):
                try:
                    info["tcp_sock"].sendall(raw_bytes)
                except Exception:
                    pass

    def cleanup_dead_peers(self):
        """Kiểm tra nhịp tim, ngắt kết nối các client im lặng quá 15 giây (Bước 7)."""
        while self.is_running:
            time.sleep(5)
            now = time.time()
            dead_users = []

            with self.peers_lock:
                for username, info in self.active_peers.items():
                    if now - info["last_seen"] > 15:
                        dead_users.append(username)

                for u in dead_users:
                    print(f"[TIMEOUT] User '{u}' mất tín hiệu Heartbeat > 15s.", flush=True)
                    info = self.active_peers.pop(u, None)
                    if info:
                        self.addr_to_user.pop((info["ip"], info["udp_port"]), None)
                        try:
                            info["tcp_sock"].close()
                        except Exception:
                            pass

            if dead_users:
                self.broadcast_peer_list()

    def handle_tcp_client(self, client_sock: socket.socket, client_addr):
        """Bắt tay TCP và xác thực người dùng."""
        username = None
        try:
            while self.is_running:
                pkt = recv_tcp_packet(client_sock)
                if not pkt:
                    break

                # Bước 2: TCP Handshake (SYN -> ACK)
                if pkt.msg_type == MsgType.HANDSHAKE_SYN:
                    ack_payload = Packet.json_payload({
                        "status": "READY",
                        "server_udp_port": self.udp_port
                    })
                    ack_pkt = Packet(
                        msg_type=MsgType.HANDSHAKE_ACK,
                        stream_id=0,
                        flags=PacketFlags.ACK | PacketFlags.EOM,
                        seq_num=0,
                        ack_num=pkt.seq_num,
                        payload=ack_payload
                    )
                    client_sock.sendall(ack_pkt.to_bytes())

                # Bước 3: Xác thực người dùng (AUTH_REQ -> AUTH_RES)
                elif pkt.msg_type == MsgType.AUTH_REQ:
                    data = pkt.decode_json()
                    username = data.get("username")
                    client_udp_port = data.get("udp_port")

                    with self.peers_lock:
                        self.active_peers[username] = {
                            "ip": client_addr[0],
                            "udp_port": client_udp_port,
                            "tcp_sock": client_sock,
                            "last_seen": time.time()
                        }
                        self.addr_to_user[(client_addr[0], client_udp_port)] = username

                    print(f"[AUTH] User '{username}' đã đăng nhập (UDP: {client_addr[0]}:{client_udp_port})", flush=True)

                    res_pkt = Packet(
                        msg_type=MsgType.AUTH_RES,
                        stream_id=0,
                        flags=PacketFlags.ACK | PacketFlags.EOM,
                        seq_num=0,
                        ack_num=pkt.seq_num,
                        payload=Packet.json_payload({"success": True})
                    )
                    client_sock.sendall(res_pkt.to_bytes())
                    self.broadcast_peer_list()

                # Bước 7: Ngắt kết nối có chủ đích
                elif pkt.msg_type == MsgType.DISCONNECT:
                    print(f"[DISCONNECT] User '{username}' chủ động thoát.", flush=True)
                    break

        except (ConnectionError, socket.timeout, ValueError):
            pass
        finally:
            if username:
                with self.peers_lock:
                    info = self.active_peers.pop(username, None)
                    if info:
                        self.addr_to_user.pop((info["ip"], info["udp_port"]), None)
                self.broadcast_peer_list()
            try:
                client_sock.close()
            except Exception:
                pass

    def _udp_receiver_loop(self):
        """Hứng toàn bộ lưu lượng UDP và đẩy vào hàng đợi không đồng bộ."""
        while self.is_running:
            try:
                raw_data, addr = self.udp_sock.recvfrom(65535)
                self.udp_queue.put((raw_data, addr))
            except OSError:
                break
            except Exception as e:
                print(f"[UDP RECEIVER ERROR] {e}", flush=True)

    def _udp_worker_loop(self):
        """Lấy gói tin từ hàng đợi để giải mã và định tuyến tức thì."""
        while self.is_running:
            try:
                raw_data, addr = self.udp_queue.get()
                self._process_single_udp_packet(raw_data, addr)
                self.udp_queue.task_done()
            except Exception as e:
                print(f"[UDP WORKER ERROR] {e}", flush=True)

    def _process_single_udp_packet(self, raw_data: bytes, addr: tuple):
        pkt = Packet.from_bytes(raw_data)
        if not pkt:
            return

        # 1. Cập nhật nhịp tim & Dynamic Port Learning (Step 7)
        if pkt.msg_type == MsgType.HEARTBEAT:
            try:
                data = pkt.decode_json()
                sender = data.get("username")
                with self.peers_lock:
                    if sender in self.active_peers:
                        self.active_peers[sender]["last_seen"] = time.time()
                        # Cập nhật địa chỉ UDP thực tế nếu có NAT
                        if (self.active_peers[sender]["ip"], self.active_peers[sender]["udp_port"]) != addr:
                            self.active_peers[sender]["ip"] = addr[0]
                            self.active_peers[sender]["udp_port"] = addr[1]
                            self.addr_to_user[addr] = sender
            except Exception:
                pass
            return

        # 2. Xử lý phản hồi ACK (Chuyển tiếp lại cho bên gửi ban đầu)
        if pkt.msg_type == MsgType.ACK:
            # Tra cứu đích chuyển tiếp ACK dựa trên Stream ID hoặc người nhận
            with self.streams_lock:
                stream_info = self.active_streams.get(pkt.stream_id)
                if stream_info:
                    sender_name = stream_info["sender"]
                    with self.peers_lock:
                        if sender_name in self.active_peers:
                            target = self.active_peers[sender_name]
                            self.udp_sock.sendto(raw_data, (target["ip"], target["udp_port"]))
            return

        # 3. Tin nhắn Broadcast (Chat chung - Step 5)
        if pkt.msg_type == MsgType.MSG_BROADCAST:
            with self.peers_lock:
                for u, info in self.active_peers.items():
                    if (info["ip"], info["udp_port"]) != addr:
                        self.udp_sock.sendto(raw_data, (info["ip"], info["udp_port"]))
            return

        # 4. Tin nhắn Unicast (Chat riêng - Step 5)
        if pkt.msg_type == MsgType.MSG_UNICAST:
            inspect_pkt = Packet.from_bytes(raw_data)
            if inspect_pkt.flags & PacketFlags.ENC:
                inspect_pkt.decrypt_payload()

            data = inspect_pkt.decode_json()
            target_user = data.get("target_user")

            with self.peers_lock:
                if target_user and target_user in self.active_peers:
                    target = self.active_peers[target_user]
                    self.udp_sock.sendto(raw_data, (target["ip"], target["udp_port"]))
            return

        # 5. Khởi tạo phiên truyền File (Step 6: FILE_META)
        if pkt.msg_type == MsgType.FILE_META:
            inspect_pkt = Packet.from_bytes(raw_data)
            if inspect_pkt.flags & PacketFlags.ENC:
                inspect_pkt.decrypt_payload()

            data = inspect_pkt.decode_json()
            target_user = data.get("target_user")
            sender = data.get("sender")

            # Lưu lại session stream để định tuyến các chunk tiếp theo
            with self.streams_lock:
                self.active_streams[pkt.stream_id] = {
                    "sender": sender,
                    "target_user": target_user
                }

            with self.peers_lock:
                if target_user and target_user in self.active_peers:
                    target = self.active_peers[target_user]
                    self.udp_sock.sendto(raw_data, (target["ip"], target["udp_port"]))
            return

# 6. Truyền khối dữ liệu nhị phân của File (Step 6: FILE_CHUNK)
        if pkt.msg_type == MsgType.FILE_CHUNK:
            with self.streams_lock:
                stream_info = self.active_streams.get(pkt.stream_id)

            if stream_info:
                target_user = stream_info["target_user"]
                with self.peers_lock:
                    if target_user in self.active_peers:
                        target = self.active_peers[target_user]
                        self.udp_sock.sendto(raw_data, (target["ip"], target["udp_port"]))

                # KHÔNG pop ngay lập tức ở đây để gói ACK cuối cùng từ Receiver vẫn được forward về Sender
                if pkt.flags & PacketFlags.EOM:
                    # Lên lịch dọn dẹp stream sau 5 giây (đủ thời gian cho các gói ACK đi qua)
                    s_id = pkt.stream_id
                    threading.Timer(5.0, lambda: self.active_streams.pop(s_id, None)).start()

if __name__ == "__main__":
    server = CollaborationServer()
    server.start()