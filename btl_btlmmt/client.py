import socket
import sys
from protocol import Packet, MsgType, PacketFlags, recv_tcp_packet

SERVER_IP = '127.0.0.1'
SERVER_TCP_PORT = 8888

class CollaborationClient:
    def __init__(self, username: str):
        self.username = username
        self.seq_num = 1
        
        # Khởi tạo TCP Socket (cho Handshake & Auth)
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.settimeout(5.0)  # Bước 7: Tránh treo vô hạn khi mất mạng

        # Khởi tạo UDP Socket (cho Streaming & File Transfer) và bind vào cổng ngẫu nhiên
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('0.0.0.0', 0))
        self.local_udp_port = self.udp_sock.getsockname()[1]
        self.server_udp_port = None

    def connect_and_authenticate(self):
        try:
            # 1. Kết nối TCP & gửi HANDSHAKE_SYN (Bước 2)
            self.tcp_sock.connect((SERVER_IP, SERVER_TCP_PORT))
            syn_pkt = Packet(
                msg_type=MsgType.HANDSHAKE_SYN,
                flags=PacketFlags.EOM,
                seq_num=self.seq_num
            )
            self.tcp_sock.sendall(syn_pkt.to_bytes())

            # Nhận HANDSHAKE_ACK từ Server
            ack_pkt = recv_tcp_packet(self.tcp_sock)
            if ack_pkt.msg_type == MsgType.HANDSHAKE_ACK:
                data = ack_pkt.decode_json()
                self.server_udp_port = data.get("server_udp_port")
                print(f"[CLIENT] Handshake thành công! Server UDP Port: {self.server_udp_port}")

            # 2. Gửi yêu cầu Đăng nhập AUTH_REQ (Bước 3)
            self.seq_num += 1
            auth_payload = Packet.json_payload({
                "username": self.username,
                "udp_port": self.local_udp_port
            })
            auth_pkt = Packet(
                msg_type=MsgType.AUTH_REQ,
                flags=PacketFlags.EOM,
                seq_num=self.seq_num,
                payload=auth_payload
            )
            self.tcp_sock.sendall(auth_pkt.to_bytes())

            # Nhận kết quả đăng nhập & danh sách Peers đang online
            auth_res = recv_tcp_packet(self.tcp_sock)
            if auth_res.msg_type == MsgType.AUTH_RES:
                res_data = auth_res.decode_json()
                print(f"[CLIENT] Đăng nhập thành công! Danh sách Peers hiện tại: {res_data.get('peers')}")

            # 3. Gửi thử gói tin HEARTBEAT qua UDP
            hb_payload = Packet.json_payload({"username": self.username, "status": "ACTIVE"})
            hb_pkt = Packet(msg_type=MsgType.HEARTBEAT, flags=PacketFlags.EOM, payload=hb_payload)
            self.udp_sock.sendto(hb_pkt.to_bytes(), (SERVER_IP, self.server_udp_port))
            print("[CLIENT] Đã gửi gói tin UDP Heartbeat tới Server.")

        except Exception as e:
            print(f"[CLIENT ERROR] Lỗi kết nối: {e}")
        finally:
            self.tcp_sock.close()
            self.udp_sock.close()

if __name__ == "__main__":
    user = sys.argv[1] if len(sys.argv) > 1 else "alice"
    client = CollaborationClient(user)
    client.connect_and_authenticate()