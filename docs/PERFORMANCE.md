# Tối ưu cho 20–40 client

Bản kiểm tra ngày 10/11/2026. Backend giữ giao thức v2; thay đổi tập trung vào
I/O, lịch xử lý và giới hạn bộ nhớ. Server mặc định nhận tối đa 64 client đã đăng
nhập, cộng 32 kết nối chờ handshake/login. Web bridge cũng nhận tối đa 64 phiên.

## Đối chiếu các đề xuất

| Đề xuất | Cách xử lý trong mã hiện tại |
| --- | --- |
| Multiplexing TCP/UDP | `server_io.py` dùng một `DefaultSelector` nhận UDP và điều khiển tất cả TCP/TLS. TLS handshake, đọc frame và ghi một phần đều không chặn. Có timeout và giới hạn output cho client chậm. |
| Offload UDP | Bốn worker, mỗi worker có queue tối đa 512 mục. Một phiên luôn thuộc một worker, giữ thứ tự xử lý crypto/replay/ACK. Luồng nhận chỉ tra session ID và endpoint rồi enqueue. Mỗi gói vẫn phải qua CRC và GCM trước khi được chấp nhận. |
| Giảm thread theo client | Server endpoint được poll bởi worker UDP và gửi request tới pool tám worker; không tạo reader/worker riêng cho từng phiên. Tám worker khác chuyển tiếp chat. Mỗi phiên chỉ có một request đang được xử lý để giữ thứ tự file. |
| Zero-copy/memoryview | `Packet.from_bytes(..., copy_payload=False)` dùng `unpack_from` và payload view trên bytes nhận được. Chunks gửi là view của message gốc. Đây là giảm bản sao, không phải zero-copy toàn bộ: mã hóa, đóng gói cuối và ghép message vẫn cần bộ nhớ. |
| Stream-to-disk | Đã có: file được chia thành block ứng dụng 256 KiB, ghi file tạm và hash tăng dần. Sequence UDP chỉ là số chunk trong một stream; không phải offset của toàn file. Giữ offset file ở lớp ứng dụng tránh ghi đè nhầm khi stream mới bắt đầu từ sequence 0. |
| Bỏ CRC trên ENC | Giữ CRC wire để tương thích v2 và đặc tả header. Tối ưu bằng CRC tăng dần trên header/payload, không nối buffer tạm; `SessionCipher.seal(Packet)` bỏ bước serialize/CRC/parse plaintext trung gian. |
| Congestion control | Giữ CUBIC-style, SRTT/RTO, Karn, backoff và pacing đã có. Bổ sung burst cap tám DATA/phiên, xử lý đầy send buffer như áp lực tạm thời để retry. RTT tăng làm tốc độ pacing giảm; RTO làm cwnd giảm. Không mô tả đây là BBR hoặc đầy đủ TCP CUBIC. |
| Batching/piggybacking | Gộp nhiều control frame vào một lần ghi TLS tối đa 64 KiB, giữ ranh giới frame và thứ tự peer update. ACK UDP và PEER_UPDATE TLS thuộc hai transport khác nhau nên không ghép chung thành một packet. |

Việc dùng worker cố định giảm số luồng theo số client; hệ thống vẫn có chuyển đổi
ngữ cảnh. Worker được đánh thức khi có dữ liệu mới; ACK có thể mở cửa sổ gửi ngay.
Timer UDP chạy mỗi 10 ms cho pacing/retry, không quét tất cả phiên sau mỗi gói.
Session ID được tra bằng dictionary thay cho quét toàn bộ danh sách peers.

## Giới hạn bộ nhớ và quá tải

- Payload budget chung của server: 64 MiB; mỗi transport: 32 MiB. Reservation bao
  gồm message gửi, chunk nhận và bản ghép, message hoàn tất đang chờ hoặc đang xử
  lý ở lớp ứng dụng. Raw queue giữ reservation tới khi người gọi lấy message.
- Nếu thiếu budget nhận, chưa ACK chunk mới để sender retry/backoff. Nếu thiếu
  budget gửi, API trả `BufferError`. Close/expiry/tiêu thụ message giải phóng budget.
- Queue request giới hạn 32 mục và 2 MiB body/phiên. Endpoint chỉ có một công việc
  đang chạy hoặc chờ trong pool. Queue UDP đầy thì bỏ datagram và tăng bộ đếm;
  transport tin cậy xử lý mất gói bằng retransmission.
- Socket UDP server đề nghị buffer nhận/gửi 1 MiB; client 256 KiB. Giá trị thực tế
  còn tùy hệ điều hành. Thay đổi buffer không thay thế congestion control.
- 64 MiB là budget admission cho payload, không phải trần RSS. Object Python,
  TLS/OS buffers, metadata stream, bản sao tạm và GUI sử dụng thêm RAM. Web upload
  vẫn giới hạn 16 MiB và tám job toàn bridge, bốn worker; API Python hỗ trợ 1 GiB.

## Kết quả đo

Windows 11, Python 3.12.10, 20 CPU logic, localhost. Server chạy ở tiến trình riêng;
client tải chạy ở tiến trình khác trên cùng máy. Mỗi client gửi một chat riêng và
một file 1 MiB tới client kế tiếp; tất cả bắt đầu cùng lúc. Sau đó gửi một broadcast
tới các client còn lại. Mọi file đều được so SHA-256 với nguồn, kiểm tra peer list
và dừng server sạch. Benchmark dùng timeout 30 giây/request để quan sát hoàn tất;
API thông thường vẫn giữ mặc định 15 giây, request relay file của server là 10 giây.

| Chỉ số | Backend cũ, 40 client | Bản tối ưu, 40 client | Bản tối ưu, 20 client |
| --- | ---: | ---: | ---: |
| File đúng hash | 40/40 | 40/40 | 20/20 |
| Broadcast đã nhận | 39/39 | 39/39 | 19/19 |
| Số luồng server đỉnh | 139 | 22 | 22 |
| RSS đỉnh server (MiB) | 68.87 | 56.51 | 46.12 |
| CPU server (giây) | 1.078 | 0.844 | 0.578 |
| Tổng thời gian chat + file (giây) | 11.937 | 10.922 | 5.813 |
| Tốc độ file hữu ích tổng (MiB/s) | 3.351 | 3.662 | 3.441 |
| Chat p50 (ms) | 15 | 16 | 16 |
| Chat p95 (ms) | 46 | 31 | 16 |
| Peak payload reservation (MiB) | Chưa đo | 20.65 | 10.32 |
| Peak queue UDP/một worker | Chưa đo | 204/512 | 102/512 |
| Gói bỏ do queue UDP đầy | Chưa đo | 0 | 0 |

Số luồng đo gồm một luồng giám sát của benchmark; cấu hình mới có tối đa 21 luồng
thực hiện công việc server. CPU đo từ khi server ready đến trước stop, gồm đăng
nhập, truyền, broadcast và client cleanup; thời gian truyền trong bảng chỉ tính
chat/file. Tốc độ hữu ích không cộng hai lần dữ liệu relay và không tính overhead.

Baseline lấy từ commit `8bf1de1`, giải nén vào thư mục tạm, không đổi nhánh làm việc.
Mỗi cột là một lần chạy được lưu lại, không phải kết luận thống kê. Kết quả có thể
dao động theo tải máy và lịch của Windows. Không suy diễn từ localhost rằng mạng
LAN/WAN thật luôn có cùng throughput/latency hoặc rằng 40 client chắc chắn gây mất
gói. Các trường hợp loss/reorder/duplicate được kiểm tra riêng bằng test transport.

Dữ liệu gốc: [baseline 40](performance/baseline-40-clients.json),
[tối ưu 40](performance/40-clients.json), [tối ưu 20](performance/20-clients.json).

```powershell
python -B scripts/benchmark_clients.py --clients 20 --file-mib 1 --output docs/performance/20-clients.json
python -B scripts/benchmark_clients.py --clients 40 --file-mib 1 --output docs/performance/40-clients.json
```

Chạy riêng từng lệnh, tránh chạy song song benchmark với test suite để giảm nhiễu.
`--backend-root PATH` chọn một bản backend độc lập để đối chiếu. Bộ kiểm thử chính
có 52 test; lệnh và phạm vi được ghi ở [TESTING.md](TESTING.md).

Thiết kế readiness và TLS retry dựa trên tài liệu chính thức:
[selectors](https://docs.python.org/3/library/selectors.html),
[SSL nonblocking sockets](https://docs.python.org/3/library/ssl.html#notes-on-non-blocking-sockets).
