"""TLS setup and per-session authenticated UDP encryption (wire protocol v2)."""
import argparse
import datetime
import ipaddress
import os
from pathlib import Path
import ssl
import struct
import threading
import time

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

from protocol import HEADER_FORMAT, MAX_PAYLOAD_SIZE, Packet, PacketFlags

SECURITY_DIR = Path(__file__).resolve().parents[1] / '.security'
UDP_OVERHEAD = 32 + 8 + 16
KEY_EPOCH_PACKETS = 65536
SESSION_LIFETIME = 3600
MAX_COUNTER = 2 ** 32


# Tạo chứng chỉ tự ký và khóa riêng cho môi trường cục bộ, không ghi đè danh tính đã tồn tại.
def create_identity(directory=SECURITY_DIR, hosts=('localhost', '127.0.0.1')):
    """Create a local trust anchor once; never overwrite existing identity files."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / 'server.crt', directory / 'server.key'
    if cert_path.exists() or key_path.exists():
        raise FileExistsError('Identity already exists; use a new directory for rotation')
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Collaboration server')])
    names = []
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with cert_path.open('xb') as out:
        out.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


# Tạo cấu hình TLS phía máy chủ, nạp chứng chỉ/khóa và yêu cầu TLS từ phiên bản 1.3.
def server_context(cert=None, key=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(cert or SECURITY_DIR / 'server.crt'),
                            str(key or SECURITY_DIR / 'server.key'))
    return context


# Tạo cấu hình TLS phía client để xác minh chứng chỉ máy chủ bằng chứng chỉ tin cậy.
def client_context(cafile=None):
    context = ssl.create_default_context(cafile=str(cafile or SECURITY_DIR / 'server.crt'))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


class SessionCipher:
    # Khởi tạo khóa phiên, hướng truyền, bộ đếm gói và cửa sổ chống phát lại.
    def __init__(self, session_id, secret, *, is_client, clock=time.monotonic,
                 epoch_packets=KEY_EPOCH_PACKETS, lifetime=SESSION_LIFETIME):
        self.sid = bytes.fromhex(session_id)
        self.secret = bytes.fromhex(secret)
        if len(self.sid) != 32 or len(self.secret) != 32 or epoch_packets < 1:
            raise ValueError('Invalid session key material')
        self.send_direction = b'c2s' if is_client else b's2c'
        self.recv_direction = b's2c' if is_client else b'c2s'
        self.clock = clock
        self.created = clock()
        self.lifetime = lifetime
        self.epoch_packets = epoch_packets
        self.counter = 0
        self.highest = -1
        self.seen = 0
        self.replay_window = 4096
        self.keys = {}
        self.lock = threading.RLock()
        self.closed = False

    # Từ chối sử dụng khóa nếu phiên đã đóng hoặc hết thời hạn.
    def _check_live(self):
        if self.closed or self.clock() - self.created >= self.lifetime:
            raise ConnectionError('Session key expired; reconnect for new keys')

    # Dẫn xuất và lưu đệm khóa AES-GCM cùng tiền tố nonce theo hướng truyền và chu kỳ khóa.
    def _key(self, direction, counter):
        epoch = counter // self.epoch_packets
        label = direction + struct.pack('!Q', epoch)
        if label not in self.keys:
            material = HKDF(algorithm=hashes.SHA256(), length=36, salt=self.sid,
                            info=b'collab-v2-udp-' + label).derive(self.secret)
            if len(self.keys) >= 6:
                self.keys.pop(next(iter(self.keys)))
            self.keys[label] = (AESGCM(material[:32]), material[32:])
        return self.keys[label]

    # Đóng gói header thành dữ liệu xác thực bổ sung để phát hiện việc sửa header.
    @staticmethod
    def _aad(pkt, size):
        return struct.pack(HEADER_FORMAT, pkt.msg_type, pkt.flags, pkt.stream_id,
                           pkt.seq_num, pkt.ack_num, pkt.win_size, size, pkt.timestamp, 0)

    # Mã hóa và xác thực gói UDP bằng AES-GCM với bộ đếm dùng để tạo nonce.
    def seal(self, raw):
        with self.lock:
            self._check_live()
            # Production callers supply a Packet directly: avoid plaintext serialization,
            # CRC and reparsing. Bytes remain accepted for the low-level transport API.
            source = raw if isinstance(raw, Packet) else Packet.from_bytes(raw, copy_payload=False)
            pkt = Packet(source.msg_type, source.flags, source.stream_id, source.seq_num,
                         source.ack_num, source.win_size, source.payload, source.timestamp)
            if pkt.flags & PacketFlags.ENC or len(pkt.payload) + UDP_OVERHEAD > MAX_PAYLOAD_SIZE:
                raise ValueError('Invalid plaintext packet size or flags')
            if self.counter >= MAX_COUNTER:
                raise ConnectionError('Nonce budget exhausted; reconnect')
            counter = self.counter
            self.counter += 1  # Never reuse even if socket send fails.
            key, prefix = self._key(self.send_direction, counter)
            sequence = struct.pack('!Q', counter)
            pkt.flags |= PacketFlags.ENC
            aad = self._aad(pkt, len(pkt.payload) + UDP_OVERHEAD) + self.sid + sequence
            pkt.payload = self.sid + sequence + key.encrypt(prefix + sequence, bytes(pkt.payload), aad)
            return pkt.to_bytes()

    # Xác thực, giải mã gói UDP và chỉ cập nhật cửa sổ chống phát lại khi gói hợp lệ.
    def open(self, pkt):
        with self.lock:
            self._check_live()
            if (not pkt.flags & PacketFlags.ENC or len(pkt.payload) < UDP_OVERHEAD
                    or pkt.payload[:32] != self.sid):
                raise ValueError('Expected encrypted packet for this session')
            sequence = bytes(pkt.payload[32:40])
            counter = struct.unpack('!Q', sequence)[0]
            if counter >= MAX_COUNTER:
                raise ValueError('Counter outside session budget')
            age = self.highest - counter
            if age >= self.replay_window or (age >= 0 and self.seen & (1 << age)):
                raise ValueError('Replayed or stale datagram')
            key, prefix = self._key(self.recv_direction, counter)
            aad = self._aad(pkt, len(pkt.payload)) + self.sid + sequence
            try:
                plaintext = key.decrypt(prefix + sequence, bytes(pkt.payload[40:]), aad)
            except InvalidTag as exc:
                raise ValueError('UDP authentication failed') from exc
            # Only authenticated packets advance the replay window.
            if counter > self.highest:
                shift = counter - self.highest
                self.seen = 0 if shift >= self.replay_window else self.seen << shift
                self.highest = counter
                age = 0
            self.seen = (self.seen | (1 << age)) & ((1 << self.replay_window) - 1)
            return Packet(pkt.msg_type, pkt.flags & ~int(PacketFlags.ENC), pkt.stream_id,
                          pkt.seq_num, pkt.ack_num, pkt.win_size, plaintext, pkt.timestamp)

    # Đánh dấu phiên đã đóng và bỏ các tham chiếu đến khóa đang lưu.
    def close(self):
        with self.lock:
            self.closed = True
            self.secret = b''
            self.keys.clear()  # Python does not guarantee physical memory zeroization.
            self.seen = 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create server TLS identity; distribute only server.crt to clients')
    parser.add_argument('--directory', type=Path, default=SECURITY_DIR)
    parser.add_argument('--host', action='append', dest='hosts')
    args = parser.parse_args()
    cert, _ = create_identity(args.directory, args.hosts or ('localhost', '127.0.0.1'))
    print(f'Created identity. Trusted certificate: {cert}')
