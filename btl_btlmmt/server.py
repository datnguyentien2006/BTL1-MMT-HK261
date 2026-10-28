import socket
import threading
from protocol import Packet, MsgType, PacketFlags, recv_tcp_packet

TCP_HOST = '0.0.0.0'
TCP_PORT = 8888
UDP_PORT = 9000

class CollaborationServer:
    def __init__(self, host=TCP_HOST, tcp_port=TCP_PORT, udp_port=UDP_PORT):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        
        # Lưu trạng thái Active Peers (Bước 3): {username: {"ip": str, "udp_port": int, "tcp_sock": socket}}
        self.active_peers = {}
        self.peers_lock = threading.Lock()

        # Khởi tạo Raw TCP Socket & UDP Socket
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self):
        self.tcp_sock.bind((self.host, self.tcp_port))
        self.tcp_sock.listen(20)  # Hỗ trợ tối소 10-20 clients đồng thời
        self.udp_sock.bind((self.host, self.udp_port))

        print(f"[SERVER] Đang lắng nghe TCP tại {self.host}:{self.tcp_port}")
        print(f"[SERVER] Đang lắng nghe UDP Streaming tại {self.host}:{self.udp_port}")

        # Luồng riêng xử lý các gói tin UDP (Heartbeat, Streaming Msg, File Transfer)
        udp_thread = threading.Thread(target=self.handle_udp_stream, daemon=True)
        udp_thread.start()

        # Vòng lặp chính chấp nhận kết nối TCP mới (Bước 2 & 4)
        try:
            while True:
                client_sock, client_addr = self.tcp_sock.accept()
                client_thread = threading.Thread(
                    target=self.handle_tcp_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Đang đóng máy chủ...")
        finally:
            self.tcp_sock.close()
            self.udp_sock.close()

    def handle_tcp_client(self, client_sock: socket.socket, client_addr):
        username = None
        print(f"[TCP] Kết nối mới từ {client_addr}")
        try:
            while True:
                pkt = recv_tcp_packet(client_sock)

                # BƯỚC 2: Xử lý bắt tay (Handshake)
                if pkt.msg_type == MsgType.HANDSHAKE_SYN:
                    print(f"[HANDSHAKE] Nhận SYN từ {client_addr}")
                    ack_payload = Packet.json_payload({
                        "status": "READY",
                        "server_udp_port": self.udp_port
                    })
                    ack_pkt = Packet(
                        msg_type=MsgType.HANDSHAKE_ACK,
                        flags=PacketFlags.ACK | PacketFlags.EOM,
                        ack_num=pkt.seq_num + 1,
                        payload=ack_payload
                    )
                    client_sock.sendall(ack_pkt.to_bytes())

                # BƯỚC 3: Xác thực & Lưu trạng thái người dùng (Authentication)
                elif pkt.msg_type == MsgType.AUTH_REQ:
                    data = pkt.decode_json()
                    username = data.get("username")
                    client_udp_port = data.get("udp_port")

                    with self.peers_lock:
                        self.active_peers[username] = {
                            "ip": client_addr[0],
                            "udp_port": client_udp_port,
                            "tcp_sock": client_sock
                        }
                        peer_list = [
                            {"user": u, "ip": info["ip"], "udp_port": info["udp_port"]}
                            for u, info in self.active_peers.items()
                        ]

                    print(f"[AUTH] User '{username}' đăng nhập thành công (UDP Port: {client_udp_port})")
                    res_payload = Packet.json_payload({
                        "success": True,
                        "peers": peer_list
                    })
                    res_pkt = Packet(
                        msg_type=MsgType.AUTH_RES,
                        flags=PacketFlags.ACK | PacketFlags.EOM,
                        ack_num=pkt.seq_num + 1,
                        payload=res_payload
                    )
                    client_sock.sendall(res_pkt.to_bytes())

                # BƯỚC 7: Ngắt kết nối chủ động
                elif pkt.msg_type == MsgType.DISCONNECT:
                    print(f"[DISCONNECT] User '{username}' đã thoát.")
                    break

        except (ConnectionError, socket.timeout, ValueError) as e:
            # BƯỚC 7: Xử lý lỗi mạng / ngắt kết nối đột ngột không làm sập Server
            print(f"[WARN] Mất kết nối với {client_addr} ({username}): {e}")
        finally:
            if username:
                with self.peers_lock:
                    self.active_peers.pop(username, None)
            client_sock.close()

    def handle_udp_stream(self):
        """Lắng nghe các gói tin UDP cho Heartbeat, Messaging và File Chunk."""
        while True:
            try:
                raw_data, addr = self.udp_sock.recvfrom(2048)
                pkt = Packet.from_bytes(raw_data)
                if pkt.msg_type == MsgType.HEARTBEAT:
                    data = pkt.decode_json()
                    print(f"[UDP HEARTBEAT] Từ {data.get('username')} tại {addr}")
            except Exception as e:
                print(f"[UDP ERROR] Lỗi xử lý gói UDP: {e}")

if __name__ == "__main__":
    server = CollaborationServer()
    server.start()