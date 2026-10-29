import os
import sys
import time
import socket
import struct
import threading
from typing import Dict, Tuple

from protocol import Packet, MsgType, PacketFlags, recv_tcp_packet

# Tương thích nếu protocol.py dùng FILE_INIT thay vì FILE_META
FILE_META_TYPE = getattr(MsgType, 'FILE_META', getattr(MsgType, 'FILE_INIT', 0x40))

SERVER_IP = '127.0.0.1'
SERVER_TCP_PORT = 8888
CHUNK_SIZE = 1024  # An toàn dưới MTU 1500 bytes

class CollaborationClient:
    def __init__(self, username: str, server_ip: str = SERVER_IP, server_tcp_port: int = SERVER_TCP_PORT):
        self.username = username
        self.server_ip = server_ip
        self.server_tcp_port = server_tcp_port
        self.server_udp_port = None
        self.is_running = False

        # Sequence number counter
        self.seq_num = 1
        self.seq_lock = threading.Lock()

        # Quản lý danh sách Peer: {username: {"ip": str, "udp_port": int}}
        self.peers: Dict[str, dict] = {}

        # 1. Sockets
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('0.0.0.0', 0))
        self.local_udp_port = self.udp_sock.getsockname()[1]

        # 2. Quản lý độ tin cậy UDP (Reliability Layer: Pending ACKs)
        # Key: (stream_id, seq_num) -> Value: threading.Event
        self.pending_acks: Dict[Tuple[int, int], threading.Event] = {}
        self.ack_lock = threading.Lock()

        # 3. Quản lý nhận File Stream
        # Key: stream_id -> { "filename": str, "total_chunks": int, "chunks": dict, "sender": str }
        self.active_file_receivers = {}

    def _next_seq(self) -> int:
        with self.seq_lock:
            self.seq_num = (self.seq_num + 1) & 0xFFFFFFFF
            return self.seq_num

    def start(self):
        """Khởi động chu trình sống của Client."""
        if not self.connect_and_authenticate():
            return

        self.is_running = True

        # Luồng 1: Heartbeat UDP duy trì phiên (Bước 7)
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="HeartbeatThread").start()

        # Luồng 2: Lắng nghe TCP (Bước 3: Peer Discovery Updates)
        threading.Thread(target=self._listen_tcp, daemon=True, name="TCPListenThread").start()

        # Luồng 3: Lắng nghe UDP (Bước 5: Chat, File & ACKs)
        threading.Thread(target=self._listen_udp, daemon=True, name="UDPListenThread").start()

        # Luồng chính: CLI
        self._cli_loop()

    def connect_and_authenticate(self) -> bool:
        """BƯỚC 2 & 3: Bắt tay TCP và xác thực người dùng."""
        try:
            self.tcp_sock.connect((self.server_ip, self.server_tcp_port))

            # Handshake SYN
            syn_pkt = Packet(
                msg_type=MsgType.HANDSHAKE_SYN,
                stream_id=0,
                flags=PacketFlags.EOM,
                seq_num=self._next_seq()
            )
            self.tcp_sock.sendall(syn_pkt.to_bytes())

            ack_pkt = recv_tcp_packet(self.tcp_sock)
            if not ack_pkt or ack_pkt.msg_type != MsgType.HANDSHAKE_ACK:
                print("[ERROR] Bắt tay TCP thất bại.")
                return False

            handshake_data = ack_pkt.decode_json()
            self.server_udp_port = handshake_data.get("server_udp_port")
            print(f"[HANDSHAKE] Thành công. Server UDP Port: {self.server_udp_port}")

            # Đăng ký danh tính (AUTH_REQ)
            auth_payload = Packet.json_payload({
                "username": self.username,
                "udp_port": self.local_udp_port
            })
            auth_pkt = Packet(
                msg_type=MsgType.AUTH_REQ,
                stream_id=0,
                flags=PacketFlags.EOM,
                seq_num=self._next_seq(),
                payload=auth_payload
            )
            self.tcp_sock.sendall(auth_pkt.to_bytes())

            auth_res = recv_tcp_packet(self.tcp_sock)
            if auth_res and auth_res.msg_type == MsgType.AUTH_RES:
                print(f"[AUTH] Xác thực thành công cho user: '{self.username}'")
                return True

            print("[ERROR] Server từ chối xác thực.")
            return False
        except Exception as e:
            print(f"[ERROR] Ngoại lệ kết nối Server: {e}")
            return False

    def _heartbeat_loop(self):
        """Gửi heartbeat qua UDP mỗi 5 giây."""
        while self.is_running:
            try:
                hb_payload = Packet.json_payload({"username": self.username})
                hb_pkt = Packet(
                    msg_type=MsgType.HEARTBEAT,
                    stream_id=0,
                    seq_num=0,
                    flags=PacketFlags.EOM,
                    payload=hb_payload
                )
                self.udp_sock.sendto(hb_pkt.to_bytes(), (self.server_ip, self.server_udp_port))
            except Exception:
                pass
            time.sleep(5)

    def _listen_tcp(self):
        """Nhận thông báo cập nhật danh sách Peer động từ Server."""
        while self.is_running:
            try:
                pkt = recv_tcp_packet(self.tcp_sock)
                if not pkt:
                    if self.is_running:
                        print("\n[WARN] Mất kết nối TCP với Server.")
                        self.is_running = False
                    break

                if pkt.msg_type == MsgType.PEER_UPDATE:
                    data = pkt.decode_json()
                    raw_peers = data.get("peers", [])
                    self.peers = {p["user"]: {"ip": p["ip"], "udp_port": p["udp_port"]} for p in raw_peers}
                    print(f"\n[PEER UPDATE] Danh sách online ({len(self.peers)}): {list(self.peers.keys())}")
                    print(f"[{self.username}] > ", end="", flush=True)

            except Exception:
                break

    def _send_udp_reliable(self, pkt: Packet, addr: Tuple[str, int], max_retries: int = 3, timeout: float = 1.0) -> bool:
        """Gửi gói tin qua UDP và chờ ACK (Cơ chế retransmission ngăn mất gói)."""
        ack_key = (pkt.stream_id, pkt.seq_num)
        ack_event = threading.Event()

        with self.ack_lock:
            self.pending_acks[ack_key] = ack_event

        try:
            packet_bytes = pkt.to_bytes()

            for attempt in range(max_retries):
                self.udp_sock.sendto(packet_bytes, addr)
                if ack_event.wait(timeout=timeout):
                    return True

            return False
        finally:
            with self.ack_lock:
                self.pending_acks.pop(ack_key, None)

    def _send_ack(self, stream_id: int, ack_seq: int, addr: Tuple[str, int]):
        """Gửi phản hồi ACK ngay lập tức cho bên gửi."""
        ack_pkt = Packet(
            msg_type=MsgType.ACK,
            stream_id=stream_id,
            seq_num=0,
            ack_num=ack_seq,
            flags=PacketFlags.NONE
        )
        self.udp_sock.sendto(ack_pkt.to_bytes(), addr)

    def _listen_udp(self):
        """Lắng nghe và phân loại các gói tin UDP đến (Chat, File, ACK)."""
        while self.is_running:
            try:
                raw_data, addr = self.udp_sock.recvfrom(65535)
                pkt = Packet.from_bytes(raw_data)
                if not pkt:
                    continue

                # 1. Nhận gói ACK -> Báo hiệu cho hàm _send_udp_reliable
                if pkt.msg_type == MsgType.ACK:
                    ack_key = (pkt.stream_id, pkt.ack_num)
                    with self.ack_lock:
                        if ack_key in self.pending_acks:
                            self.pending_acks[ack_key].set()
                    continue

                # 2. Trả ACK xác nhận đã nhận gói
                if pkt.msg_type in (MsgType.MSG_UNICAST, MsgType.MSG_BROADCAST, FILE_META_TYPE, MsgType.FILE_CHUNK):
                    self._send_ack(pkt.stream_id, pkt.seq_num, addr)

                # Giải mã dữ liệu nếu có cờ mã hóa ENC
                if pkt.flags & PacketFlags.ENC:
                    pkt.decrypt_payload()

                # 3. Điều hướng xử lý
                if pkt.msg_type in (MsgType.MSG_UNICAST, MsgType.MSG_BROADCAST):
                    self._handle_chat_packet(pkt)

                elif pkt.msg_type == FILE_META_TYPE:
                    self._handle_file_meta(pkt)

                elif pkt.msg_type == MsgType.FILE_CHUNK:
                    self._handle_file_chunk(pkt)

            except OSError:
                break
            except Exception as e:
                if self.is_running:
                    print(f"\n[ERROR UDP] Lỗi xử lý gói tin: {e}")

    def _handle_chat_packet(self, pkt: Packet):
        data = pkt.decode_json()
        sender = data.get("sender")
        content = data.get("content")

        if sender == self.username:
            return

        if pkt.msg_type == MsgType.MSG_BROADCAST:
            print(f"\n[CHUNG] [{sender}]: {content}")
        else:
            print(f"\n[RIÊNG] [{sender}]: {content}")
        print(f"[{self.username}] > ", end="", flush=True)

    def _handle_file_meta(self, pkt: Packet):
        data = pkt.decode_json()
        stream_id = pkt.stream_id
        self.active_file_receivers[stream_id] = {
            "filename": data["filename"],
            "filesize": data["filesize"],
            "total_chunks": data["total_chunks"],
            "sender": data["sender"],
            "chunks": {}
        }
        print(f"\n[FILE] Nhận file '{data['filename']}' ({data['filesize']} bytes) từ {data['sender']}...")
        print(f"[{self.username}] > ", end="", flush=True)

    def _handle_file_chunk(self, pkt: Packet):
        stream_id = pkt.stream_id
        if stream_id not in self.active_file_receivers:
            return

        f_info = self.active_file_receivers[stream_id]
        chunk_idx = pkt.ack_num  # ack_num lưu index của chunk
        f_info["chunks"][chunk_idx] = pkt.payload

        progress = int((len(f_info["chunks"]) / f_info["total_chunks"]) * 100)
        print(f"\r[RECEIVING] '{f_info['filename']}': {progress}%", end="", flush=True)

        if len(f_info["chunks"]) == f_info["total_chunks"]:
            # Tạo thư mục received_files nếu chưa có
            save_dir = "received_files"
            os.makedirs(save_dir, exist_ok=True)

            output_path = os.path.join(save_dir, f_info['filename'])
            with open(output_path, "wb") as f:
                for idx in range(f_info["total_chunks"]):
                    f.write(f_info["chunks"][idx])
            print(f"\n[FILE COMPLETE] Đã lưu file thành công tại: {output_path}")
            print(f"[{self.username}] > ", end="", flush=True)
            del self.active_file_receivers[stream_id]

    def send_chat_message(self, target_user: str, text: str):
        """Gửi tin nhắn UDP tin cậy qua Server."""
        is_broadcast = (target_user.lower() == "all")
        msg_type = MsgType.MSG_BROADCAST if is_broadcast else MsgType.MSG_UNICAST
        stream_id = 1 if is_broadcast else 100
        seq = self._next_seq()

        payload = Packet.json_payload({
            "sender": self.username,
            "target_user": None if is_broadcast else target_user,
            "content": text
        })

        pkt = Packet(
            msg_type=msg_type,
            stream_id=stream_id,
            flags=PacketFlags.EOM,
            seq_num=seq,
            payload=payload
        )
        pkt.encrypt_payload()

        ok = self._send_udp_reliable(pkt, (self.server_ip, self.server_udp_port))
        if not ok:
            print(f"\n[WARN] Tin nhắn gửi tới '{target_user}' không nhận được phản hồi ACK.")

    def send_file(self, target_user: str, file_path: str):
        """Truyền file tin cậy: cắt nhỏ thành các chunk và truyền trên Stream riêng."""
        if not os.path.exists(file_path):
            print(f"[ERROR] Tệp tin không tồn tại: {file_path}")
            return

        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        # ĐÃ SỬA: % 60000 + 1000 để stream_id luôn <= 60999 (vừa vặn kiểu unsigned short 2 bytes 'H')
        stream_id = int(time.time() * 1000) % 60000 + 1000

        # Gửi Metadata
        meta_payload = Packet.json_payload({
            "sender": self.username,
            "target_user": target_user,
            "filename": filename,
            "filesize": file_size,
            "total_chunks": total_chunks
        })
        meta_pkt = Packet(
            msg_type=FILE_META_TYPE,
            stream_id=stream_id,
            seq_num=self._next_seq(),
            flags=PacketFlags.NONE,
            payload=meta_payload
        )
        meta_pkt.encrypt_payload()

        print(f"\n[FILE] Đang chuẩn bị truyền '{filename}' ({total_chunks} chunks)...")
        if not self._send_udp_reliable(meta_pkt, (self.server_ip, self.server_udp_port)):
            print("[ERROR] Không thể khởi tạo truyền file với Server (Timeout).")
            return

        # Gửi dữ liệu từng chunk
        with open(file_path, "rb") as f:
            chunk_idx = 0
            while True:
                chunk_data = f.read(CHUNK_SIZE)
                if not chunk_data:
                    break

                chunk_pkt = Packet(
                    msg_type=MsgType.FILE_CHUNK,
                    stream_id=stream_id,
                    seq_num=self._next_seq(),
                    ack_num=chunk_idx,
                    flags=PacketFlags.EOM if (chunk_idx == total_chunks - 1) else PacketFlags.NONE,
                    payload=chunk_data
                )

                success = self._send_udp_reliable(chunk_pkt, (self.server_ip, self.server_udp_port))
                if not success:
                    print(f"\n[ERROR] Thất bại tại chunk {chunk_idx + 1}/{total_chunks}. Ngắt truyền.")
                    return

                chunk_idx += 1
                progress = int((chunk_idx / total_chunks) * 100)
                print(f"\r[UPLOADING] '{filename}': {progress}%", end="", flush=True)

        print(f"\n[FILE COMPLETE] Đã gửi hoàn tất file: {filename}")
        print(f"[{self.username}] > ", end="", flush=True)

    def _cli_loop(self):
        """CLI điều khiển client."""
        print("\n--- HỆ THỐNG LỆNH HỖ TRỢ ---")
        print("  - Gửi chung:         all <nội dung>")
        print("  - Gửi riêng:         <user> <nội dung>")
        print("  - Gửi tệp tin:       file <user> <đường_dẫn_file>")
        print("  - Xem danh sách:     list")
        print("  - Thoát:             exit")
        print("----------------------------\n")

        while self.is_running:
            try:
                line = input(f"[{self.username}] > ").strip()
                if not line:
                    continue
                if line == "exit":
                    self.stop()
                    break
                elif line == "list":
                    print(f"Online peers: {list(self.peers.keys())}")
                    continue

                parts = line.split(" ", 2)
                if parts[0] == "file":
                    if len(parts) < 3:
                        print("Cú pháp gửi file: file <user> <path>")
                        continue
                    self.send_file(parts[1], parts[2])
                else:
                    if len(parts) < 2:
                        print("Cú pháp không hợp lệ. Ví dụ: 'all Xin chào' hoặc 'bob Alo'")
                        continue
                    self.send_chat_message(parts[0], line.split(" ", 1)[1])

            except (KeyboardInterrupt, EOFError):
                self.stop()
                break

    def stop(self):
        """Dừng client an toàn và giải phóng tài nguyên mạng."""
        if not self.is_running:
            return
        self.is_running = False

        try:
            disc_pkt = Packet(
                msg_type=MsgType.DISCONNECT,
                stream_id=0,
                flags=PacketFlags.EOM,
                payload=Packet.json_payload({"username": self.username})
            )
            self.tcp_sock.sendall(disc_pkt.to_bytes())
        except Exception:
            pass

        try:
            self.tcp_sock.close()
        except Exception:
            pass

        try:
            self.udp_sock.close()
        except Exception:
            pass

        print("\n[CLIENT] Đã đóng toàn bộ kết nối và thoát an toàn.")

if __name__ == "__main__":
    uname = sys.argv[1] if len(sys.argv) > 1 else f"user_{int(time.time() % 1000)}"
    client = CollaborationClient(uname)
    client.start()