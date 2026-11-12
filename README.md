# BTL1-MMT-HK261

## Run the backend

Requires Python 3.10+, OpenSSL with TLS 1.3 support, and `cryptography`.
Run from the repository root:

```powershell
python -m pip install -r requirements.txt
python btl_btlmmt/security.py
```

The second command creates `.security/server.crt` and `.security/server.key`
once; it refuses to overwrite an existing identity. Keep the private key on the
server. For local testing both processes use the same trusted certificate.
`.security`, private keys, downloads and Python caches are excluded by `.gitignore`.
Do not commit credentials or use test certificates for another deployment.

Start the server:

```powershell
python btl_btlmmt/server.py
```

Open separate terminals for clients:

```powershell
python btl_btlmmt/client.py alice
python btl_btlmmt/client.py bob
```

The server listens on TCP 8888 and UDP 9000. Clients default to localhost.
Press Ctrl+C to disconnect a client or stop the server.
For LAN usage, generate an identity containing the server's actual IP/DNS name:

```powershell
python btl_btlmmt/security.py --directory .security-lan --host localhost --host 127.0.0.1 --host 192.168.1.10
python btl_btlmmt/server.py --cert .security-lan/server.crt --key .security-lan/server.key
python btl_btlmmt/client.py alice --server 192.168.1.10 --ca trusted-server.crt
```

Copy **only** `server.crt` to the client as `trusted-server.crt` using a trusted
channel; verify its SHA-256 fingerprint out of band (`Get-FileHash ... -Algorithm SHA256`).
Never disable certificate or hostname verification. For a custom Python setup,
pass `tls_context=client_context(cafile)` / `server_context(cert, key)`.
Certificates last one year. Rotate into a new directory, distribute the new
certificate, then restart the server and reconnect clients. Protect the key with
owner-only filesystem permissions/Windows ACLs. Custom identity directories must
also be kept outside version control; `.security*/` is ignored by default.

Protocol specification: [docs/PROTOCOL.md](docs/PROTOCOL.md).
Test scenarios and scope: [docs/TESTING.md](docs/TESTING.md).

## Session and packet rules

- A connection first completes verified TLS 1.3, then HANDSHAKE_SYN/HANDSHAKE_ACK before AUTH_REQ.
- Usernames contain 1-32 letters, digits, `_`, `-` or `.` and are case-sensitive.
  Duplicate online names and repeated login on the same connection are rejected.
  This is name registration, not password-based identity authentication.
- AUTH_RES includes `version: 2`, `success`, `session_id`, `udp_secret`, and `peers`. Large peer snapshots
  span multiple AUTH_RES packets with the same ACK and session ID; only the last
  page has EOM. Failed login returns `success: false` and `error` in one packet.
- The client sends a UDP heartbeat every 5 seconds containing `username` and
  `session_id`. The server verifies the token and registered source IP/UDP port.
  Sessions expire after 20 seconds without an accepted heartbeat; keys/sessions
  have a one-hour maximum lifetime and require reconnecting afterwards.
- Login has a 10-second deadline checked between packets; socket reads/writes
  have a 5-second timeout. A timeout while receiving a partial packet closes
  the connection rather than retrying from the middle of a frame.
- Every packet has a 24-byte header and at most 1,376 payload bytes. Oversized,
  truncated, extra-byte, unknown-type/flag and invalid-CRC packets are rejected.
  TCP payload size is checked before reading the body.
- `connect_and_authenticate()` starts heartbeat and background receive threads;
  callers must call `close()`. `run()` waits until Ctrl+C, disconnect or error.
- Join/leave (including heartbeat expiry) generates ordered TCP PEER_UPDATE
  events. Each connection has a single TCP writer and a bounded update queue.
  `client.get_peers()` returns a thread-safe copy of the live peer list.

Chat unicast/broadcast and file relay use reliable UDP on both client-server hops.
TCP control traffic uses TLS 1.3. Every UDP DATA, ACK and heartbeat uses
AES-256-GCM authenticated encryption, with separate directional keys derived by
HKDF-SHA256. Fresh session secrets are delivered only over verified TLS. UDP
headers and session IDs remain visible but are authenticated; ciphertext,
metadata tampering and replay are rejected. Keys rotate every 65,536 datagrams
per direction and the nonce counter never resets within a session.

The server decrypts and re-encrypts relayed content: this is hop-by-hop security,
not end-to-end encryption. Usernames are still registration names, not password
or client-certificate authentication. Python cannot guarantee memory zeroization.
Both client and server must use this protocol version.

## Server capacity and resource limits

The server now multiplexes TCP/TLS and UDP reception with `selectors` and supports
64 authenticated clients by default. TLS handshakes, partial control frames and
slow readers have deadlines. No TCP or application reader thread is created per
server session. Four bounded UDP workers process sessions in fixed shards;
eight application workers and eight forwarding workers handle requests. A busy
session keeps its request order while other sessions can progress.

UDP routing uses a session-ID lookup, followed by endpoint and AES-GCM validation.
Each worker queue holds at most 512 datagrams. New sends wake their worker; ACKs
can immediately open the send window. Periodic retry/pacing timers are independent
of the incoming packet rate. CUBIC pacing caps a burst at eight DATA datagrams.

The server shares a 64 MiB payload reservation budget across transports and
application queues (32 MiB per session). This is not a process-RAM ceiling: Python
objects, TLS/OS buffers and temporary copies require additional memory. Full
receive budgets withhold ACKs; full send budgets return `BufferError`. Packet
parsing and send chunks use views; CRC is computed without concatenating a temporary
header/payload. Direct packet encryption avoids plaintext serialization and CRC.
The v2 wire format, CRC validation and AES-GCM authentication remain compatible.

File receivers already stream 256 KiB application blocks to temporary disk files;
they never reassemble a complete large file in RAM. TCP control frames are batched
into TLS writes without mixing them with UDP ACKs or changing frame boundaries.

```powershell
python btl_btlmmt/server.py --max-clients 64 --udp-workers 4
python scripts/benchmark_clients.py --clients 40 --file-mib 1 --output docs/performance/40-clients.json
```

The load check runs the backend in a separate process and verifies every received
file's hash. See [PERFORMANCE.md](docs/PERFORMANCE.md) for measurements, tradeoffs
and the mapping from the optimization suggestions to implemented changes.

## Web UI (Step 9)

The GUI from `origin/main` has been adapted to the v2 backend on this branch.
Start from the repository root, after installing requirements and creating the
TLS identity as above:

```powershell
# Terminal 1
python btl_btlmmt/server.py
# Terminal 2
python btl_btlmmt/web_ui/server_web.py --port 5000
```

Open `http://127.0.0.1:5000` in separate tabs for Alice and Bob. Login, select a
peer or Chat Chung, and send messages. Select a specific peer to upload a file.
Click the received file in its conversation to download it with its original name.
Do not run `python web_server.py`: that filename does not exist.
From inside `btl_btlmmt`, the equivalent bridge command is
`python web_ui/server_web.py --port 5000`.

- The bridge calls `connect_and_authenticate()` and never `input()`/a CLI loop;
  it also runs with closed stdin. Login succeeds only after backend acceptance.
- Uses only Python `http.server` and browser JavaScript; no Flask/Django/WebSockets.
  HTTP is a local browser adapter; inter-client traffic still uses TLS + reliable UDP.
- The HTTP listener defaults to `0.0.0.0`, allowing browsers on other LAN machines.
  Use `--host 127.0.0.1` for local-only access. Host validation accepts the actual
  destination IP and still rejects cross-origin requests.
- Progress reports receiver-acknowledged bytes from the backend callback. 100% of
  bytes can be acknowledged while SHA-256 verification is still pending; the UI
  reports success only after the final application result.
- One non-overlapping polling loop refreshes peers, history and transfer status.
  Logout/expired sessions return to login; text is rendered with `textContent`.
- Uploads run in a bounded background executor so status polling stays responsive.
  Web uploads are limited to 16 MiB (base64 HTTP adapter); Python API limit is 1 GiB.
- Upload staging uses a unique temporary directory and the original basename.
  Receiver storage retains the collision-safe UUID prefix, but display/download
  uses the original name. No `GUI_alice_`/temporary-name prefix is transmitted.
- Files can only be downloaded through the receiving web session; server files,
  private keys and arbitrary filesystem paths are not served.
- Browser sessions are tab-scoped, expire after 30 minutes without HTTP activity,
  and close when the backend disconnects. Histories/jobs are in memory and bounded.
  Downloaded backend files remain on disk after logout.

Structure: `btl_btlmmt/web_ui/server_web.py`, `web_ui/app.js`,
`web_ui/templates/index.html`. Report and review mapping:
[Technical report](report/Technical_Report.pdf), [report source](report/REPORT.md),
[PDF review resolution](docs/REVIEW_FIXES.md).

### Đăng nhập từ nhiều máy trong LAN, không cần Internet

Web tự in địa chỉ thật cho **máy server** và **thiết bị khác cùng LAN** khi khởi động.
Trên trang đăng nhập, mở **Mời thiết bị khác** để sao chép địa chỉ hoặc quét mã QR.
Mã QR chỉ chứa địa chỉ web, được tạo ngay trên server; không dùng dịch vụ Internet.
Nếu có nhiều card mạng, chọn Wi-Fi/Ethernet mà các thiết bị đang dùng; card mạng ảo
được xếp sau. Sau khi đổi mạng, bấm **Làm mới** để lấy IP hiện tại.
`127.0.0.1` luôn là chính thiết bị đang mở trình duyệt, không phải địa chỉ dùng chung.
Chế độ `--host 127.0.0.1` sẽ thông báo chỉ cho truy cập trên máy server và không tạo
lời mời LAN. Cài/cập nhật dependencies bằng `python -m pip install -r requirements.txt`
trước khi chạy offline (`psutil` để đọc card mạng, `qrcode` để tạo QR tại chỗ).

Chọn **một máy làm server**, cài dependencies trước khi ngắt Internet. Trên máy
này chạy hai terminal từ thư mục gốc dự án (chỉ chạy `security.py` nếu chưa có
`.security/server.crt` và `.security/server.key`):

```powershell
# Chuẩn bị một lần
python btl_btlmmt/security.py
# Terminal 1: backend
python btl_btlmmt/server.py
# Terminal 2: web dùng chung cho cả LAN
python btl_btlmmt/web_ui/server_web.py --host 0.0.0.0 --port 5000
```

Dùng `ipconfig` trên máy server để lấy IPv4 của Wi-Fi/Ethernet đang kết nối,
ví dụ `192.168.1.10` (không lấy IP VMware/VPN). Trên **tất cả máy client**, mở
`http://192.168.1.10:5000` và đăng nhập bằng **tên khác nhau**. Không dùng
`localhost`, `127.0.0.1` hoặc `0.0.0.0` trên máy client để truy cập server.
Các máy client chỉ cần trình duyệt; không cần chạy Python hay sao chép chứng chỉ.
Web và backend cùng chạy trên server nên `--server` vẫn là `127.0.0.1`, chứng chỉ
localhost hiện có vẫn dùng được. HTML/CSS/JS đều được phục vụ tại chỗ, không có CDN.

Nếu Windows Firewall chặn, mở PowerShell **Run as administrator** trên máy server
và cho phép cổng web từ mạng con cục bộ:

```powershell
New-NetFirewallRule -DisplayName "Collab Web LAN 5000" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -RemoteAddress LocalSubnet
```

Các máy phải truy cập được nhau; Wi-Fi guest/AP isolation có thể chặn dù cùng tên
mạng. Từ máy client có thể kiểm tra bằng `Test-NetConnection 192.168.1.10 -Port 5000`.
Không cần mở cổng TCP 8888/UDP 9000 cho cách dùng trình duyệt này.
HTTP giữa trình duyệt và web server không mã hóa; chỉ dùng chế độ này trong LAN
tin cậy. TLS và mã hóa UDP giữa bridge và backend vẫn giữ nguyên.

Nếu muốn chạy **Python client hoặc bridge riêng trên từng máy**, dùng `--server`
trỏ tới IP LAN của backend và chứng chỉ có IP đó như hướng dẫn LAN ở đầu README;
cho phép TCP 8888 và UDP 9000 trên máy backend. `--host` là địa chỉ lắng nghe web,
còn `--server` là địa chỉ backend, hai tham số có chức năng khác nhau.

Kiểm tra hồi quy LAN (Python và Node.js):

```powershell
python -B -m unittest discover -s tests -v
node tests/test_web_ui.js
# Tùy chọn: kiểm tra HTTP qua đúng card mạng LAN của máy chạy test
$env:COLLAB_TEST_LAN_IP = '192.168.1.10'
python -B -m unittest discover -s tests -v
```

## Chat and file API

The CLI maintains an online session; use the Web UI above or invoke these backend APIs from Python. Run this example from `btl_btlmmt` with the server running:

```python
from client import CollaborationClient

alice = CollaborationClient('alice')
bob = CollaborationClient('bob', download_dir='received/bob')
try:
    alice.connect_and_authenticate()
    bob.connect_and_authenticate()
    print(alice.send_chat('Private message', recipient='bob'))
    print(bob.receive_chat(timeout=5))
    print(alice.send_chat('Hello everyone'))  # All online peers except alice.
    print(bob.receive_chat(timeout=5))

    result = alice.send_file('example.pdf', recipient='bob',
                             progress=lambda sent, total: print(sent, total))
    print(result)  # file_id, size, sha256 after verified storage at bob.
    print(bob.receive_file(timeout=5))  # sender, name, path, size, sha256, file_id.
finally:
    alice.close()
    bob.close()
```

- Chat accepts 1..65,536 UTF-8 bytes. `send_chat` returns `delivered` and `failed`
  per recipient after recipient application acknowledgement. An offline unicast
  recipient raises `ApplicationError`; an empty broadcast returns empty lists.
  Delivered means queued in the recipient inbox, not read by a person.
- Server routing stamps the sender from its session. Broadcast recipients are a
  snapshot at send time. File routes are pinned to the receiving session so a
  reconnect under the same username cannot receive the remainder of an old file.
- `send_file` reads blocks of 256 KiB and waits for a receiver application ACK
  before the next block. Files may exceed the transport's 8 MiB message limit;
  the application limit is 1 GiB per file and 8 active incoming files per client.
  The server relays blocks without storing files. File transfer is unicast.
- Receivers write `.part-*` files in `download_dir` (default
  `downloads/<username>`). Size and incremental SHA-256 must match before the
  file is published as `<file_id>_<original_name>`. Existing files are never
  overwritten. Absolute/traversal paths and unsafe names are rejected.
- Publication uses an atomic hard link in the destination filesystem (e.g. NTFS,
  ext4, APFS). A filesystem without hard-link support returns a transfer error.
- Abort, invalid blocks/checksum, session close or sender leave removes partial
  files. Idle partial transfers expire after 60 seconds. Completed files remain.
- `send_chat`/`send_file` wait on the calling thread. Network I/O, heartbeat,
  request processing and response dispatch run on separate threads. Call these
  APIs from a worker when attaching a UI. `timeout` is per application request
  (default 15 seconds), not the total duration of a file transfer.
- Chat/file event queues are bounded; full inboxes reject new deliveries instead
  of silently reporting success. Drain them with `receive_chat`/`receive_file`.
  These receive methods raise `queue.Empty` on timeout.
- No automatic application retry/resume is performed. If a completion response
  is lost after delivery, a timeout does not prove that the recipient received
  nothing. Re-sending starts a new transfer/file ID.

`application.py` wraps reliable stream messages as `COLLAB1\\0`, a network-order
uint32 JSON-header length, a JSON header (max 8 KiB), and raw body bytes. Headers
contain `kind` (`request`/`result`), a UUID request `id`, and an operation:
`chat`, `file_begin`, `file_block`, `file_end`, or `file_abort`. Chat text and file
blocks are raw bodies. File metadata includes `file_id`, `name`, `size`, `offset`
or `sha256` as appropriate. Results correlate to the originating request ID.
Legacy MSG_UNICAST/MSG_BROADCAST/FILE_* enum values are reserved; application
messages are carried in STREAM_DATA so they share sequencing and retransmission.

## Reliable UDP transport

`reliable_udp.py` implements selective repeat in both directions between an
authenticated client and the server. Socket readers feed validated packets into
`handle_packet()` and call `tick()` every ~10 ms and on send/ACK progress; applications consume complete
messages through a queue without blocking the network loop.

- STREAM_DATA (0x60) uses `stream_id` 1..65535 and a zero-based chunk `seq_num`.
  Its payload is the 32-byte session token, a big-endian uint32 chunk count,
  then up to 1,284 data bytes before encryption. The encrypted envelope adds
  56 bytes (session ID, counter, GCM tag). Only the final chunk carries EOM.
- ACK (0x50) carries the token and acknowledges exactly one chunk in `ack_num`.
  ACKs for unsent packets, wrong tokens and wrong UDP endpoints are ignored.
- The send window spans 32 sequence positions from the first unacknowledged
  chunk. ACK `win_size` advertises the receive window width; the sender uses
  the smaller local/remote width. Only missing ACKs trigger retransmission,
  using an adaptive RTO (initial 250 ms, bounded to 100 ms..3 s), exponential
  retry backoff capped at 3 seconds, with at most 12 retries per chunk.
- One CUBIC-style congestion controller is shared by all streams of a session:
  initial cwnd 4 packets, slow start, cubic/Reno-friendly growth, timeout loss
  reduction and fast convergence, with a 256-packet cap. Aggregate in-flight
  data is limited by cwnd; token-bucket pacing includes retransmissions and caps
  bursts at eight datagrams.
  Streams are scheduled round-robin. RTT samples exclude retransmissions (Karn).
- Each stream has independent ordering, retry state and reassembly. A missing
  chunk in one stream does not prevent another stream from completing.
- One message uses one stream ID. IDs increase per direction and are never
  reused in a session; reconnect after 65,535 sends. Completed receive IDs are
  retained until session close so repeated packets get ACKed without redelivery.
- Defaults bound each message to 8 MiB, active streams to 16 per direction and
  completed receive queues to 16 messages. A full application queue withholds
  the completing chunk's ACK. Consumers should drain queues promptly.
- Incomplete receive streams expire after 30 seconds of inactivity; send streams
  fail after retry exhaustion or 30 seconds without ACK progress. Failures are
  exposed through receipts and the transport's `errors` queue. Session closure
  fails pending receipts and releases active stream buffers.
- `receipt.wait(timeout)` confirms transport acceptance, not application processing.
  A local wait timeout does not cancel a transfer. If all final ACKs are lost,
  the sender can report failure even though the receiver accepted the message.

Example with a running server and an authenticated `client`:

```python
receipt = client.send_stream(b'hello' * 1000)  # Enqueue immediately.
receipt.wait(timeout=5)                       # Optional delivery wait.
# In the server application:
stream_id, data = server.receive_stream('alice', timeout=5)
reply = server.send_stream('alice', b'received')
# In the client application:
stream_id, data = client.receive_stream(timeout=5)
```

The per-stream receive window is flow control; `congestion.py` adds CUBIC-style
congestion avoidance and pacing per connection. This custom UDP implementation
is not full TCP CUBIC conformance: ECN, HyStart++, fast retransmit/recovery and
spurious-loss undo are not implemented. The layer buffers bounded messages; `file_transfer.py` streams larger files as bounded
application blocks. Raw `send_stream` payloads must not start with the reserved
`COLLAB1\\0` envelope prefix. Drain raw queues when using the low-level API.

## Tests

```powershell
python -B -m unittest discover -s tests -v
```

Tests use ephemeral localhost ports and cover packet validation, TCP framing,
session ownership, rejected login data, heartbeat expiry/source validation,
20 and 40 simultaneous online clients, live join/leave/expiry, bidirectional UDP data,
paged peer snapshots and shutdown cleanup. A deterministic datagram simulator
also tests loss, reordering, duplicates, lost final ACKs, selective retries,
independent streams, window limits, queue backpressure and stream expiry.
Application tests cover chat routing and identity, offline/full recipients,
files larger than 8 MiB, empty files, no overwrite, invalid paths/offsets/hash,
partial-file cleanup, and chat/file delivery with real UDP datagrams dropped.

The security/congestion suite additionally checks encrypted mixed-loss/reordering/
duplication/corruption, header authentication, replay, key rotation/expiry,
nonce exhaustion, wrong certificate/hostname, pacing, shared congestion budgets,
and 20 concurrent TLS clients exchanging ring-chat messages. Tests create their
own temporary certificates and do not require `.security` setup.

The web suite adds real HTTP tests for headless login, concurrent private chats,
loss-tolerant broadcast, file progress and authorized downloads. See
[TESTING.md](docs/TESTING.md) for the optional Edge browser test and PDF build commands.
