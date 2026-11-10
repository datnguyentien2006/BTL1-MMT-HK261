import os
import sys
import time
import socket
import struct
import threading
from typing import Dict, Tuple, List

from protocol import Packet, MsgType, PacketFlags, recv_tcp_packet


def get_local_ip() -> str:
    """Tự động lấy địa chỉ IP nội bộ của máy tính đang chạy."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip


FILE_META_TYPE = getattr(MsgType, 'FILE_META', getattr(MsgType, 'FILE_INIT', 0x40))

SERVER_IP = get_local_ip()
SERVER_TCP_PORT = 8888
CHUNK_SIZE = 1024  # An toàn dưới MTU 1500 bytes


class CongestionController:
    """Mô phỏng bộ điều khiển tắc nghẽn TCP CUBIC / BBR (Additive Increase, Multiplicative Decrease)."""
    def __init__(self, initial_window: int = 16, min_window: int = 4, max_window: int = 128):
        self.window_size = initial_window
        self.min_window = min_window
        self.max_window = max_window
        self.rtt_samples: List[float] = []
        self.smoothed_rtt = 0.1  # Giây
        self.lock = threading.Lock()

    def update_rtt(self, rtt: float):
        with self.lock:
            self.rtt_samples.append(rtt)
            if len(self.rtt_samples) > 10:
                self.rtt_samples.pop(0)
            # Exponential Weighted Moving Average (EWMA) cho RTT
            self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * rtt

    def on_ack_received(self):
        """Additive Increase (AI) khi truyền thành công."""
        with self.lock:
            if self.window_size < self.max_window:
                self.window_size += 1

    def on_packet_loss(self):
        """Multiplicative Decrease (MD) khi mất gói / timeout / NACK."""
        with self.lock:
            self.window_size = max(self.min_window, int(self.window_size / 2))

    def get_adaptive_timeout(self) -> float:
        """Tính toán timeout động dựa trên RTT mượt (BBR/CUBIC style)."""
        with self.lock:
            return max(0.5, self.smoothed_rtt * 2.0)


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

        # 2. Bộ điều khiển tắc nghẽn & Cửa sổ trượt (Sliding Window & Congestion Control)
        self.cc = CongestionController(initial_window=64, min_window=16, max_window=128)

        # Quản lý độ tin cậy UDP (Sliding Window Pending ACKs)
        # Key: (stream_id, seq_num) -> Value: (threading.Event, send_timestamp)
        self.pending_acks: Dict[Tuple[int, int], Tuple[threading.Event, float]] = {}
        self.ack_lock = threading.Lock()

        # 3. Quản lý nhận File Stream
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

        # Luồng 1: Heartbeat UDP duy trì phiên
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="HeartbeatThread").start()

        # Luồng 2: Lắng nghe TCP (Peer Discovery Updates)
        threading.Thread(target=self._listen_tcp, daemon=True, name="TCPListenThread").start()

        # Luồng 3: Lắng nghe UDP (Chat, File & ACKs)
        threading.Thread(target=self._listen_udp, daemon=True, name="UDPListenThread").start()

        # Luồng chính: CLI
        self._cli_loop()

    def connect_and_authenticate(self) -> bool:
        """Bắt tay TCP và xác thực người dùng."""
        try:
            self.tcp_sock.connect((self.server_ip, self.server_tcp_port))

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

    def _send_udp_sliding_window_batch(self, packets: List[Packet], addr: Tuple[str, int]) -> bool:
        """
        Truyền danh sách gói tin sử dụng Thuật toán Cửa sổ trượt (Sliding Window ARQ)
        kết hợp Kiểm soát tắc nghẽn động (CUBIC/BBR Congestion Control).
        """
        total_packets = len(packets)
        base = 0
        max_retries = 3

        while base < total_packets and self.is_running:
            # Lấy kích thước cửa sổ hiện tại từ bộ điều khiển tắc nghẽn
            current_win = self.cc.window_size
            window_end = min(base + current_win, total_packets)

            # Gửi tất cả gói tin nằm trong cửa sổ hiện tại (Pipeline transmission)
            for i in range(base, window_end):
                pkt = packets[i]
                # Cập nhật win_size vào header gói tin để đồng bộ thông tin luồng
                pkt.win_size = current_win
                ack_key = (pkt.stream_id, pkt.seq_num)
                ack_event = threading.Event()
                send_time = time.time()

                with self.ack_lock:
                    self.pending_acks[ack_key] = (ack_event, send_time)

                try:
                    self.udp_sock.sendto(pkt.to_bytes(), addr)
                except Exception:
                    pass

            # Chờ ACK cho gói tin ở đầu cửa sổ (Go-Back-N / Sliding Window ACK tracking)
            first_pkt = packets[base]
            ack_key = (first_pkt.stream_id, first_pkt.seq_num)
            
            with self.ack_lock:
                entry = self.pending_acks.get(ack_key)
            
            if entry:
                ack_event, send_time = entry
                timeout_val = self.cc.get_adaptive_timeout()
                
                if ack_event.wait(timeout=timeout_val):
                    # Nhận ACK thành công -> Tăng cửa sổ (Additive Increase) & Cập nhật RTT
                    rtt = time.time() - send_time
                    self.cc.update_rtt(rtt)
                    self.cc.on_ack_received()
                    base += 1
                else:
                    # Timeout -> Mất gói hoặc tắc nghẽn mạng -> Giảm cửa sổ (Multiplicative Decrease) & Truyền lại
                    self.cc.on_packet_loss()
                    
                    # Thử lại tối đa số lần cho phép
                    retry_success = False
                    for attempt in range(max_retries):
                        if not self.is_running:
                            return False
                        try:
                            self.udp_sock.sendto(first_pkt.to_bytes(), addr)
                        except Exception:
                            pass
                        
                        if ack_event.wait(timeout=timeout_val * (attempt + 1)):
                            retry_success = True
                            self.cc.on_ack_received()
                            base += 1
                            break
                    
                    if not retry_success:
                        # Vượt quá số lần retry -> Hủy phiên
                        return False
            else:
                base += 1

        return True

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

    def _send_nack(self, stream_id: int, missing_seq: int, addr: Tuple[str, int]):
        """Gửi gói NACK yêu cầu truyền lại chunk bị thiếu (Selective Repeat)."""
        nack_pkt = Packet(
            msg_type=MsgType.ACK,
            stream_id=stream_id,
            seq_num=0,
            ack_num=missing_seq,
            flags=PacketFlags.NACK
        )
        self.udp_sock.sendto(nack_pkt.to_bytes(), addr)

    def _listen_udp(self):
        """Lắng nghe và phân loại các gói tin UDP đến (Chat, File, ACK, NACK)."""
        while self.is_running:
            try:
                raw_data, addr = self.udp_sock.recvfrom(65535)
                pkt = Packet.from_bytes(raw_data)
                if not pkt:
                    continue

                # 1. Nhận gói ACK -> Kích hoạt event tương ứng trong pending_acks
                if pkt.msg_type == MsgType.ACK and not (pkt.flags & PacketFlags.NACK):
                    ack_key = (pkt.stream_id, pkt.ack_num)
                    with self.ack_lock:
                        if ack_key in self.pending_acks:
                            event, _ = self.pending_acks[ack_key]
                            event.set()
                    continue

                # 1b. Nhận gói NACK -> Truyền lại ngay lập tức chunk bị thiếu (Selective Repeat)
                if pkt.flags & PacketFlags.NACK:
                    missing_chunk_idx = pkt.ack_num
                    stream_id = pkt.stream_id
                    self._retransmit_chunk_on_nack(stream_id, missing_chunk_idx, (self.server_ip, self.server_udp_port))
                    continue

                # Giải mã dữ liệu nếu có cờ mã hóa ENC
                if pkt.flags & PacketFlags.ENC:
                    pkt.decrypt_payload()
                    
                # 2. Trả ACK xác nhận đã nhận gói cho Server/Peer
                if pkt.msg_type in (MsgType.MSG_UNICAST, MsgType.MSG_BROADCAST, FILE_META_TYPE, MsgType.FILE_CHUNK):
                    self._send_ack(pkt.stream_id, pkt.seq_num, addr)

                # 3. Điều hướng xử lý nghiệp vụ
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
            "chunks": {},
            "next_expected": 0
        }
        print(f"\n[FILE] Nhận file '{data['filename']}' ({data['filesize']} bytes) từ {data['sender']}...")
        print(f"[{self.username}] > ", end="", flush=True)

    def _handle_file_chunk(self, pkt: Packet):
        stream_id = pkt.stream_id
        if stream_id not in self.active_file_receivers:
            return

        f_info = self.active_file_receivers[stream_id]
        chunk_idx = pkt.ack_num  # ack_num lưu index của chunk

        expected_idx = f_info.get("next_expected", 0)
        if chunk_idx > expected_idx:
            # Phát hiện khoảng trống gói tin bị mất -> Gửi NACK khôi phục (Selective Repeat)
            for missing_idx in range(expected_idx, chunk_idx):
                if missing_idx not in f_info["chunks"]:
                    self._send_nack(stream_id, missing_idx, (self.server_ip, self.server_udp_port))
        
        f_info["chunks"][chunk_idx] = pkt.payload
        f_info["next_expected"] = max(expected_idx, chunk_idx + 1)
        
        self._send_ack(stream_id, chunk_idx, (self.server_ip, self.server_udp_port))

        progress = int((len(f_info["chunks"]) / f_info["total_chunks"]) * 100)
        print(f"\r[RECEIVING] '{f_info['filename']}': {progress}% (Win: {pkt.win_size})", end="", flush=True)

        if len(f_info["chunks"]) == f_info["total_chunks"]:
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
        """Gửi tin nhắn UDP tin cậy thông qua sliding window batch."""
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

        if is_broadcast:
            self.udp_sock.sendto(pkt.to_bytes(), (self.server_ip, self.server_udp_port))
        else:
            ok = self._send_udp_sliding_window_batch([pkt], (self.server_ip, self.server_udp_port))
            if not ok:
                print(f"\n[WARN] Tin nhắn gửi tới '{target_user}' không nhận được phản hồi ACK.")

    def send_file(self, target_user: str, file_path: str):
        """Truyền file tin cậy bằng Cửa sổ trượt (Sliding Window) & Kiểm soát tắc nghẽn."""
        if not os.path.exists(file_path):
            print(f"[ERROR] Tệp tin không tồn tại: {file_path}")
            return

        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)
        stream_id = int(time.time() * 1000) % 60000 + 1000

        if not hasattr(self, 'upload_buffers'):
            self.upload_buffers = {}

        chunks_data = []
        with open(file_path, "rb") as f:
            while True:
                chunk_data = f.read(CHUNK_SIZE)
                if not chunk_data:
                    break
                chunks_data.append(chunk_data)

        total_chunks = len(chunks_data)
        self.upload_buffers[stream_id] = chunks_data

        try:
            # 1. Gửi Metadata khởi tạo phiên truyền file
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

            print(f"\n[FILE] Đang chuẩn bị truyền '{filename}' ({total_chunks} chunks, Sliding Window active)...")
            if not self._send_udp_sliding_window_batch([meta_pkt], (self.server_ip, self.server_udp_port)):
                print("[ERROR] Không thể khởi tạo truyền file với Server (Timeout).")
                return

            # 2. Đóng gói toàn bộ các chunks thành danh sách Packet
            chunk_packets = []
            for chunk_idx, chunk_data in enumerate(chunks_data):
                chunk_pkt = Packet(
                    msg_type=MsgType.FILE_CHUNK,
                    stream_id=stream_id,
                    seq_num=self._next_seq(),
                    ack_num=chunk_idx,
                    flags=PacketFlags.EOM if (chunk_idx == total_chunks - 1) else PacketFlags.NONE,
                    payload=chunk_data
                )
                chunk_pkt.encrypt_payload()
                chunk_packets.append(chunk_pkt)

            # 3. Truyền toàn bộ danh sách chunk theo cơ chế Cửa sổ trượt (Sliding Window & Congestion Control)
            # Thay vì gửi tuần tự từng gói (Stop-and-Wait), cửa sổ trượt gửi một chuỗi gói song song và dịch chuyển win.
            base = 0
            max_retries = 3

            while base < total_chunks and self.is_running:
                current_win = self.cc.window_size
                window_end = min(base + current_win, total_chunks)

                # Gửi batch trong cửa sổ
                for i in range(base, window_end):
                    pkt = chunk_packets[i]
                    pkt.win_size = current_win
                    ack_key = (pkt.stream_id, pkt.seq_num)
                    ack_event = threading.Event()
                    send_time = time.time()

                    with self.ack_lock:
                        self.pending_acks[ack_key] = (ack_event, send_time)

                    try:
                        self.udp_sock.sendto(pkt.to_bytes(), (self.server_ip, self.server_udp_port))
                    except Exception:
                        pass

                # Chờ ACK gói đầu cửa sổ
                first_pkt = chunk_packets[base]
                ack_key = (first_pkt.stream_id, first_pkt.seq_num)
                
                with self.ack_lock:
                    entry = self.pending_acks.get(ack_key)

                if entry:
                    ack_event, send_time = entry
                    timeout_val = self.cc.get_adaptive_timeout()

                    if ack_event.wait(timeout=timeout_val):
                        rtt = time.time() - send_time
                        self.cc.update_rtt(rtt)
                        self.cc.on_ack_received()
                        base += 1
                    else:
                        self.cc.on_packet_loss()
                        retry_ok = False
                        for attempt in range(max_retries):
                            if not self.is_running:
                                return
                            try:
                                self.udp_sock.sendto(first_pkt.to_bytes(), (self.server_ip, self.server_udp_port))
                            except Exception:
                                pass
                            if ack_event.wait(timeout=timeout_val * (attempt + 1)):
                                retry_ok = True
                                self.cc.on_ack_received()
                                base += 1
                                break
                        if not retry_ok:
                            print(f"\n[ERROR] Timeout truyền file tại chunk {base}. Ngắt kết nối.")
                            return
                else:
                    base += 1

                progress = int((base / total_chunks) * 100)
                print(f"\r[UPLOADING] '{filename}': {progress}% (WinSize: {self.cc.window_size}, RTT: {int(self.cc.smoothed_rtt*1000)}ms)", end="", flush=True)

            print(f"\n[FILE COMPLETE] Đã gửi hoàn tất file: {filename}")

        finally:
            self.upload_buffers.pop(stream_id, None)

        print(f"[{self.username}] > ", end="", flush=True)

    def _retransmit_chunk_on_nack(self, stream_id: int, chunk_idx: int, addr: Tuple[str, int]):
        """Truyền lại chính xác chunk bị thiếu khi nhận được NACK (Selective Repeat)."""
        if hasattr(self, 'upload_buffers') and stream_id in self.upload_buffers:
            chunks_data = self.upload_buffers[stream_id]
            if 0 <= chunk_idx < len(chunks_data):
                retry_pkt = Packet(
                    msg_type=MsgType.FILE_CHUNK,
                    stream_id=stream_id,
                    seq_num=self._next_seq(),
                    ack_num=chunk_idx,
                    flags=PacketFlags.NONE,
                    payload=chunks_data[chunk_idx]
                )
                retry_pkt.encrypt_payload()
                self.udp_sock.sendto(retry_pkt.to_bytes(), addr)

    def _cli_loop(self):
        """CLI điều khiển client."""
        print("\n--- HỆ THỐNG LỆNH HỖ TRỢ ---")
        print("  - Gửi chung:        all <nội dung>")
        print("  - Gửi riêng:        <user> <nội dung>")
        print("  - Gửi tệp tin:      file <user> <đường_dẫn_file>")
        print("  - Xem danh sách:    list")
        print("  - Thoát:            exit")
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