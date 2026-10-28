import struct
import time
import zlib
import json
from enum import IntEnum, IntFlag
from typing import Optional

# Định dạng Header nhị phân 24 bytes (Big-Endian / Network Byte Order '!'):
# B (1B): msg_type | B (1B): flags | H (2B): stream_id
# I (4B): seq_num  | I (4B): ack_num
# H (2B): win_size | H (2B): payload_len
# I (4B): timestamp| I (4B): checksum
HEADER_FORMAT = '!BBHIIHHII'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 24 bytes
MAX_PAYLOAD_SIZE = 1376  # Đảm bảo tổng gói tin <= 1400 bytes (tránh phân mảnh MTU)

class MsgType(IntEnum):
    HANDSHAKE_SYN = 0x01
    HANDSHAKE_ACK = 0x02
    AUTH_REQ      = 0x10
    AUTH_RES      = 0x11
    HEARTBEAT     = 0x20
    PEER_UPDATE   = 0x21
    MSG_UNICAST   = 0x30
    MSG_BROADCAST = 0x31
    FILE_INIT     = 0x40
    FILE_CHUNK    = 0x41
    ACK           = 0x50
    NACK          = 0x51
    DISCONNECT    = 0xFF

class PacketFlags(IntFlag):
    NONE = 0x00
    EOM  = 0x01  # End-of-Message Flag (Bắt buộc)
    ACK  = 0x02  # Có chứa ACK hợp lệ
    ENC  = 0x04  # Payload đã được mã hóa AES
    BRD  = 0x08  # Tin nhắn Broadcast
    NACK = 0x10  # Yêu cầu truyền lại chọn lọc (Selective Repeat)

class Packet:
    def __init__(self, msg_type: int, flags: int = PacketFlags.NONE,
                 stream_id: int = 0, seq_num: int = 0, ack_num: int = 0,
                 win_size: int = 64, payload: bytes = b'', timestamp: Optional[int] = None):
        self.msg_type = int(msg_type)
        self.flags = int(flags)
        self.stream_id = stream_id
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.win_size = win_size
        self.payload = payload if isinstance(payload, bytes) else payload.encode('utf-8')
        self.payload_len = len(self.payload)
        self.timestamp = timestamp if timestamp is not None else int(time.time() * 1000) & 0xFFFFFFFF
        self.checksum = 0

    def to_bytes(self) -> bytes:
        """Đóng gói Packet thành chuỗi bytes để gửi qua Raw Socket."""
        if self.payload_len > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload vượt quá kích thước tối đa ({MAX_PAYLOAD_SIZE} bytes)")

        # Bước 1: Đóng gói Header tạm với checksum = 0 để tính CRC32
        temp_header = struct.pack(
            HEADER_FORMAT,
            self.msg_type, self.flags, self.stream_id,
            self.seq_num, self.ack_num,
            self.win_size, self.payload_len,
            self.timestamp, 0
        )
        # Bước 2: Tính CRC32 trên toàn bộ Header tạm + Payload
        self.checksum = zlib.crc32(temp_header + self.payload) & 0xFFFFFFFF

        # Bước 3: Đóng gói Header chính thức cùng với Payload
        final_header = struct.pack(
            HEADER_FORMAT,
            self.msg_type, self.flags, self.stream_id,
            self.seq_num, self.ack_num,
            self.win_size, self.payload_len,
            self.timestamp, self.checksum
        )
        return final_header + self.payload

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> 'Packet':
        """Giải nén chuỗi bytes nhận từ Socket thành đối tượng Packet và kiểm tra toàn vẹn CRC32."""
        if len(raw_bytes) < HEADER_SIZE:
            raise ValueError("Gói tin không hợp lệ: Kích thước nhỏ hơn Header (24 bytes)")

        header_bytes = raw_bytes[:HEADER_SIZE]
        msg_type, flags, stream_id, seq_num, ack_num, win_size, payload_len, timestamp, recv_checksum = struct.unpack(
            HEADER_FORMAT, header_bytes
        )

        payload = raw_bytes[HEADER_SIZE:HEADER_SIZE + payload_len]
        if len(payload) < payload_len:
            raise ValueError("Gói tin bị thiếu hụt dữ liệu Payload")

        # Kiểm tra toàn vẹn dữ liệu bằng CRC32
        temp_header = struct.pack(
            HEADER_FORMAT,
            msg_type, flags, stream_id,
            seq_num, ack_num,
            win_size, payload_len,
            timestamp, 0
        )
        calc_checksum = zlib.crc32(temp_header + payload) & 0xFFFFFFFF
        if calc_checksum != recv_checksum:
            raise ValueError(f"Lỗi toàn vẹn dữ liệu (CRC32 mismatch): {calc_checksum} != {recv_checksum}")

        pkt = cls(msg_type, flags, stream_id, seq_num, ack_num, win_size, payload, timestamp)
        pkt.checksum = recv_checksum
        return pkt

    @staticmethod
    def json_payload(data: dict) -> bytes:
        return json.dumps(data).encode('utf-8')

    def decode_json(self) -> dict:
        return json.loads(self.payload.decode('utf-8'))

def recv_exact(sock, num_bytes: int) -> bytes:
    """Hàm hỗ trợ đọc chính xác số byte từ TCP stream (tránh hiện tượng đọc thiếu byte của TCP)."""
    buf = b''
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối TCP đã bị đóng bởi phía bên kia.")
        buf += chunk
    return buf

def recv_tcp_packet(sock) -> Packet:
    """Đọc trọn vẹn 1 Packet từ TCP Socket dựa vào trường payload_len trong Header."""
    header_bytes = recv_exact(sock, HEADER_SIZE)
    _, _, _, _, _, _, payload_len, _, _ = struct.unpack(HEADER_FORMAT, header_bytes)
    payload_bytes = recv_exact(sock, payload_len) if payload_len > 0 else b''
    return Packet.from_bytes(header_bytes + payload_bytes)