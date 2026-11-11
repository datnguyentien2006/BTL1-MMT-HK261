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
HEADER_STRUCT = struct.Struct(HEADER_FORMAT)
HEADER_SIZE = HEADER_STRUCT.size  # 24 bytes
MAX_PAYLOAD_SIZE = 1376  # Đảm bảo tổng gói tin <= 1400 bytes (tránh phân mảnh MTU)
MAX_PACKET_SIZE = HEADER_SIZE + MAX_PAYLOAD_SIZE
HEARTBEAT_INTERVAL = 5.0
SESSION_TIMEOUT = 20.0
IO_TIMEOUT = 5.0


# Kiểm tra độ dài và tập ký tự được phép trong tên người dùng.
def validate_username(username):
    if (not isinstance(username, str) or not 1 <= len(username) <= 32
            or not all(c.isalnum() or c in '_-.' for c in username)):
        raise ValueError('Username phải có 1–32 ký tự chữ, số, _, - hoặc .')
    return username


# Kiểm tra cổng là số nguyên trong phạm vi 1 đến 65535.
def validate_port(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('UDP port phải là số nguyên trong khoảng 1–65535')
    return port

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
    STREAM_DATA   = 0x60
    DISCONNECT    = 0xFF

class PacketFlags(IntFlag):
    NONE = 0x00
    EOM  = 0x01  # End-of-Message Flag (Bắt buộc)
    ACK  = 0x02  # Có chứa ACK hợp lệ
    ENC  = 0x04  # Payload đã được mã hóa AES
    BRD  = 0x08  # Tin nhắn Broadcast
    NACK = 0x10  # Yêu cầu truyền lại chọn lọc (Selective Repeat)

class Packet:
    # Khởi tạo các trường header và chuẩn hóa payload dạng chuỗi sang UTF-8.
    def __init__(self, msg_type: int, flags: int = PacketFlags.NONE,
                 stream_id: int = 0, seq_num: int = 0, ack_num: int = 0,
                 win_size: int = 64, payload: bytes | memoryview | str = b'', timestamp: Optional[int] = None):
        self.msg_type = int(msg_type)
        self.flags = int(flags)
        self.stream_id = stream_id
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.win_size = win_size
        self.payload = payload.encode('utf-8') if isinstance(payload, str) else payload
        self.payload_len = len(self.payload)
        self.timestamp = timestamp if timestamp is not None else int(time.time() * 1000) & 0xFFFFFFFF
        self.checksum = 0

    # Kiểm tra giới hạn các trường, tính CRC32 rồi đóng gói header và payload thành bytes.
    def to_bytes(self) -> bytes:
        """Đóng gói Packet thành chuỗi bytes để gửi qua Raw Socket."""
        self.payload_len = len(self.payload)
        self.validate_header(self.msg_type, self.flags)
        for name, maximum in [('stream_id', 65535), ('seq_num', 0xFFFFFFFF),
                              ('ack_num', 0xFFFFFFFF), ('win_size', 65535),
                              ('timestamp', 0xFFFFFFFF)]:
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError(f'{name} nằm ngoài phạm vi header')
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
        self.checksum = zlib.crc32(self.payload, zlib.crc32(temp_header)) & 0xFFFFFFFF

        # Bước 3: Đóng gói Header chính thức cùng với Payload
        final_header = struct.pack(
            HEADER_FORMAT,
            self.msg_type, self.flags, self.stream_id,
            self.seq_num, self.ack_num,
            self.win_size, self.payload_len,
            self.timestamp, self.checksum
        )
        return b''.join((final_header, self.payload))

    # Giải mã gói nhị phân, kiểm tra độ dài và CRC32 trước khi tạo đối tượng Packet.
    @classmethod
    def from_bytes(cls, raw_bytes: bytes, *, copy_payload=True) -> 'Packet':
        """Giải nén chuỗi bytes nhận từ Socket thành đối tượng Packet và kiểm tra toàn vẹn CRC32."""
        if len(raw_bytes) < HEADER_SIZE:
            raise ValueError("Gói tin không hợp lệ: Kích thước nhỏ hơn Header (24 bytes)")

        # A view is safe only while the caller owns the underlying receive buffer.
        raw = memoryview(raw_bytes)
        msg_type, flags, stream_id, seq_num, ack_num, win_size, payload_len, timestamp, recv_checksum = HEADER_STRUCT.unpack_from(raw)

        cls.validate_header(msg_type, flags)
        if payload_len > MAX_PAYLOAD_SIZE:
            raise ValueError('Payload vượt quá kích thước tối đa')
        if len(raw_bytes) != HEADER_SIZE + payload_len:
            raise ValueError('Độ dài packet không khớp header')

        payload = raw[HEADER_SIZE:]

        # Kiểm tra toàn vẹn dữ liệu bằng CRC32
        temp_header = struct.pack(
            HEADER_FORMAT,
            msg_type, flags, stream_id,
            seq_num, ack_num,
            win_size, payload_len,
            timestamp, 0
        )
        calc_checksum = zlib.crc32(payload, zlib.crc32(temp_header)) & 0xFFFFFFFF
        if calc_checksum != recv_checksum:
            raise ValueError(f"Lỗi toàn vẹn dữ liệu (CRC32 mismatch): {calc_checksum} != {recv_checksum}")

        pkt = cls(msg_type, flags, stream_id, seq_num, ack_num, win_size,
                  bytes(payload) if copy_payload else payload, timestamp)
        pkt.checksum = recv_checksum
        return pkt

    # Kiểm tra loại bản tin và từ chối các bit cờ ngoài phạm vi giao thức.
    @staticmethod
    def validate_header(msg_type, flags):
        MsgType(msg_type)
        if flags < 0 or flags & ~0x1F:
            raise ValueError('Packet chứa flags không hợp lệ')

    # Chuyển dữ liệu JSON thành bytes UTF-8 để làm payload.
    @staticmethod
    def json_payload(data: dict) -> bytes:
        return json.dumps(data).encode('utf-8')

    # Đọc payload JSON và bảo đảm kết quả là đối tượng dạng dictionary.
    def decode_json(self) -> dict:
        data = json.loads(bytes(self.payload).decode('utf-8'))
        if not isinstance(data, dict):
            raise ValueError('JSON payload phải là object')
        return data

# Đọc đủ số byte yêu cầu từ TCP, báo lỗi nếu kết nối đóng giữa chừng.
def recv_exact(sock, num_bytes: int) -> bytes:
    """Hàm hỗ trợ đọc chính xác số byte từ TCP stream (tránh hiện tượng đọc thiếu byte của TCP)."""
    buf = b''
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối TCP đã bị đóng bởi phía bên kia.")
        buf += chunk
    return buf

# Đọc header và payload theo độ dài khai báo để lấy đúng một gói TCP.
def recv_tcp_packet(sock) -> Packet:
    """Đọc trọn vẹn 1 Packet từ TCP Socket dựa vào trường payload_len trong Header."""
    header_bytes = recv_exact(sock, HEADER_SIZE)
    msg_type, flags, _, _, _, _, payload_len, _, _ = struct.unpack(HEADER_FORMAT, header_bytes)
    Packet.validate_header(msg_type, flags)
    if payload_len > MAX_PAYLOAD_SIZE:
        raise ValueError('Payload vượt quá kích thước tối đa')
    payload_bytes = recv_exact(sock, payload_len) if payload_len > 0 else b''
    return Packet.from_bytes(header_bytes + payload_bytes)
