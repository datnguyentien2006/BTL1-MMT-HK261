import struct
import time
import zlib
import json
from enum import IntEnum, IntFlag
from typing import Optional

# Thư viện mã hóa tiêu chuẩn theo yêu cầu Bước 8
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Định dạng Header nhị phân 24 bytes (Big-Endian / Network Byte Order '!'):
# B (1B): msg_type | B (1B): flags | H (2B): stream_id
# I (4B): seq_num   | I (4B): ack_num
# H (2B): win_size | H (2B): payload_len
# I (4B): timestamp| I (4B): checksum
HEADER_FORMAT = '!BBHIIHHII'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 24 bytes
MAX_PAYLOAD_SIZE = 1376  # 24 + 1376 = 1400 bytes (An toàn dưới MTU 1500)

# Khóa 256-bit chuẩn (32 bytes) dùng cho AES-GCM
DEFAULT_CRYPTO_KEY = b'16bytesSecretKey16bytesSecretKey'


class MsgType(IntEnum):
    HANDSHAKE_SYN = 0x01
    HANDSHAKE_ACK = 0x02
    AUTH_REQ       = 0x10
    AUTH_RES       = 0x11
    HEARTBEAT      = 0x20
    PEER_UPDATE    = 0x21
    MSG_UNICAST    = 0x30
    MSG_BROADCAST  = 0x31
    FILE_META      = 0x40  # Metadata khởi tạo truyền file
    FILE_INIT      = 0x40  # Alias đồng bộ
    FILE_CHUNK     = 0x41  # Dữ liệu chunk nhị phân
    ACK            = 0x50
    NACK           = 0x51
    DISCONNECT     = 0xFF


class PacketFlags(IntFlag):
    NONE = 0x00
    EOM  = 0x01  # End-of-Message Flag
    ACK  = 0x02  # Gói tin có chứa ACK hợp lệ
    ENC  = 0x04  # Payload đã được mã hóa
    BRD  = 0x08  # Tin nhắn Broadcast
    NACK = 0x10  # Selective Repeat NACK


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
        """Đóng gói Packet thành bytes để truyền qua Socket với CRC32 bảo vệ."""
        if self.payload_len > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload vượt quá kích thước tối đa ({MAX_PAYLOAD_SIZE} bytes)")

        # Tính CRC32 với trường checksum tạm = 0
        temp_header = struct.pack(
            HEADER_FORMAT,
            self.msg_type, self.flags, self.stream_id,
            self.seq_num, self.ack_num,
            self.win_size, self.payload_len,
            self.timestamp, 0
        )
        self.checksum = zlib.crc32(temp_header + self.payload) & 0xFFFFFFFF

        final_header = struct.pack(
            HEADER_FORMAT,
            self.msg_type, self.flags, self.stream_id,
            self.seq_num, self.ack_num,
            self.win_size, self.payload_len,
            self.timestamp, self.checksum
        )
        return final_header + self.payload

    @classmethod
    def from_bytes(cls, raw_bytes: bytes) -> Optional['Packet']:
        """Giải nén bytes từ Socket thành Packet và kiểm tra toàn vẹn CRC32."""
        if len(raw_bytes) < HEADER_SIZE:
            return None

        header_bytes = raw_bytes[:HEADER_SIZE]
        msg_type, flags, stream_id, seq_num, ack_num, win_size, payload_len, timestamp, recv_checksum = struct.unpack(
            HEADER_FORMAT, header_bytes
        )

        payload = raw_bytes[HEADER_SIZE:HEADER_SIZE + payload_len]
        if len(payload) < payload_len:
            return None

        temp_header = struct.pack(
            HEADER_FORMAT,
            msg_type, flags, stream_id,
            seq_num, ack_num,
            win_size, payload_len,
            timestamp, 0
        )
        calc_checksum = zlib.crc32(temp_header + payload) & 0xFFFFFFFF
        if calc_checksum != recv_checksum:
            # Gói tin bị hỏng trong quá trình truyền
            return None

        pkt = cls(msg_type, flags, stream_id, seq_num, ack_num, win_size, payload, timestamp)
        pkt.checksum = recv_checksum
        return pkt

    @staticmethod
    def json_payload(data: dict) -> bytes:
        return json.dumps(data).encode('utf-8')

    def decode_json(self) -> dict:
        try:
            return json.loads(self.payload.decode('utf-8'))
        except Exception:
            return {}

    # BƯỚC 8: Tích hợp mã hóa bảo mật chuẩn AES-GCM (với fallback)
    def encrypt_payload(self, key: bytes = DEFAULT_CRYPTO_KEY):
        """Mã hóa payload trước khi gửi đi và bật cờ ENC."""
        if not (self.flags & PacketFlags.ENC) and self.payload_len > 0:
            if HAS_CRYPTOGRAPHY:
                # 96-bit nonce + AES-GCM ciphertext + tag
                aesgcm = AESGCM(key)
                nonce = struct.pack("!II", self.timestamp, self.seq_num) + b'\x00' * 4
                self.payload = nonce + aesgcm.encrypt(nonce, self.payload, None)
            else:
                # Fallback: XOR cipher
                encrypted = bytearray()
                for i, b in enumerate(self.payload):
                    encrypted.append(b ^ key[i % len(key)])
                self.payload = bytes(encrypted)

            self.payload_len = len(self.payload)
            self.flags |= PacketFlags.ENC

    def decrypt_payload(self, key: bytes = DEFAULT_CRYPTO_KEY) -> bytes:
        """Giải mã payload khi nhận được và tắt cờ ENC."""
        if (self.flags & PacketFlags.ENC) and self.payload_len > 0:
            if HAS_CRYPTOGRAPHY and len(self.payload) >= 28:
                try:
                    nonce = self.payload[:12]
                    ciphertext = self.payload[12:]
                    aesgcm = AESGCM(key)
                    self.payload = aesgcm.decrypt(nonce, ciphertext, None)
                except Exception:
                    # Nếu giải mã lỗi, giữ nguyên payload
                    pass
            else:
                # Fallback XOR
                decrypted = bytearray()
                for i, b in enumerate(self.payload):
                    decrypted.append(b ^ key[i % len(key)])
                self.payload = bytes(decrypted)

            self.payload_len = len(self.payload)
            self.flags &= ~PacketFlags.ENC
        return self.payload


def recv_exact(sock, num_bytes: int) -> bytes:
    """Đọc chính xác num_bytes từ TCP stream, khắc phục hoàn toàn phân mảnh stream."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối TCP bị đóng.")
        buf.extend(chunk)
    return bytes(buf)


def recv_tcp_packet(sock) -> Optional[Packet]:
    """Đọc trọn vẹn 1 Packet từ TCP Socket."""
    try:
        header_bytes = recv_exact(sock, HEADER_SIZE)
    except (ConnectionError, OSError):
        return None

    _, _, _, _, _, _, payload_len, _, _ = struct.unpack(HEADER_FORMAT, header_bytes)
    try:
        payload_bytes = recv_exact(sock, payload_len) if payload_len > 0 else b''
    except (ConnectionError, OSError):
        return None

    return Packet.from_bytes(header_bytes + payload_bytes)