## DISTRIBUTED AND STREAMING BASE
## CLIENT-SERVER COLLABORATION APPLICATION


### 1. TỔNG QUAN HỆ THỐNG

Hệ thống cung cấp tính năng trò chuyện thời gian thực và chia sẻ tệp tin trong Mạng nội bộ (LAN), hoạt động hoàn toàn không cần kết nối Internet.

* **Backend**: Lập trình Socket Python tùy chỉnh (TCP Port 8888 dùng cho xác thực & phát hiện peer; UDP Port 9000 dùng cho nhắn tin & truyền dữ liệu file theo dạng chunk).
* **Frontend**: HTTP Bridge và Giao diện Web Portal (Mặc định HTTP Port 5000).

---

### 2. CẤU TRÚC THƯ MỤC DỰ ÁN

```text
Network_Application_Project/
│
├── protocol.py        # Định dạng gói tin nhị phân, kiểm tra toàn vẹn CRC32 và mã hóa AES-GCM
├── server.py          # Máy chủ trung tâm quản lý danh sách peer và định tuyến gói tin UDP
├── client.py          # Xử lý logic client với thuật toán Cửa sổ trượt (Sliding Window) & ACK
├── web_server.py      # HTTP daemon cầu nối giữa trình duyệt web và logic client Python
├── README.md          # Tệp hướng dẫn triển khai và kiểm thử dự án
│
└── templates/
    └── index.html     # Giao diện người dùng Web Portal
```

---

### 3. BƯỚC 1: CÀI ĐẶT CÁC THƯ VIỆN PHỤ THUỘC

Mở Terminal / Command Prompt tại thư mục gốc của dự án và chạy lệnh sau:

```bash
pip install cryptography
```

---

### 4. BƯỚC 2: KHỞI CHẠY MÁY CHỦ TRUNG TÂM (SERVER)

Mở **Terminal 1** và khởi chạy máy chủ chính:

```bash
python server.py
```

*Máy chủ sẽ lắng nghe kết nối tại các cổng **TCP Port 8888** và **UDP Port 9000**.*

---

### 5. BƯỚC 3: KHỞI CHẠY WEB CLIENT / BRIDGE

Mở **Terminal 2** và khởi chạy máy chủ Web Bridge (mặc định cổng 5000):

```bash
python web_server.py 5000
```

*Màn hình Terminal sẽ hiển thị địa chỉ IP nội bộ để kết nối, ví dụ: `http://192.168.1.50:5000`.*

---

### 6. BƯỚC 4: KẾT NỐI CLIENT VÀ KIỂM THỬ

#### Trường hợp A: Kiểm thử trên cùng một máy tính (Localhost)

1. **Client 1**: Mở trình duyệt web, truy cập `http://localhost:5000`, nhập tên `Alice` và bấm **Vào Phòng Chat**.
2. **Client 2**: Mở tab Ẩn danh (Incognito) hoặc trình duyệt khác, truy cập `http://localhost:5000` và đăng nhập với tên `Bob`.
3. **Kiểm tra các chức năng**:
   * **Chat Chung (Broadcast)**: Gửi tin nhắn trong mục `Chat Chung`.
   * **Chat Riêng (Unicast)**: Nhấp chọn một người dùng bên cột trái để gửi tin nhắn riêng tư.
   * **Truyền File qua UDP**: Chọn một file bất kỳ ở cột trái và bấm **Gửi Tệp Tin** để theo dõi thanh tiến trình truyền dữ liệu và tính năng tải về.

#### Trường hợp B: Kiểm thử giữa nhiều máy tính trong mạng LAN

1. Kết nối tất cả các máy tính vào cùng một mạng Wi-Fi hoặc bộ chia mạng LAN (Switch/Router).
2. Từ máy tính thứ hai, mở trình duyệt và truy cập vào địa chỉ IP LAN hiển thị trên Terminal máy chủ (ví dụ: `http://192.168.1.50:5000`).
3. Nhập tên định danh duy nhất để tham gia phòng chat và bắt đầu giao tiếp với các máy khác.

---

### 7. XỬ LÝ LỖI THƯỜNG GẶP (TROUBLESHOOTING)

* **Lỗi thiếu thư viện (`Missing Module Error`)**: Đảm bảo đã chạy lệnh `pip install cryptography` trong đúng môi trường Python đang dùng.
* **Không thể kết nối / Timeout trong LAN**: Kiểm tra cài đặt Tường lửa (Firewall) trên máy chạy Server và cho phép kết nối qua các cổng `5000`, `8888`, và `9000`.
* **Lỗi trùng cổng (`Address already in use`)**: Đổi sang cổng HTTP khác khi chạy web server, ví dụ: `python web_server.py 5001`.