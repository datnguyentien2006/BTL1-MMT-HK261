# Chạy ứng dụng chat và truyền file trên Windows

Bạn cần **hai cửa sổ PowerShell** trên máy chủ. Cửa sổ thứ nhất chạy backend. Cửa sổ thứ hai chạy Web UI. Giữ cả hai cửa sổ mở trong lúc sử dụng.

## 1. Chuẩn bị lần đầu

Mở PowerShell và vào thư mục chứa `server.py`:

```powershell
cd 'C:\Users\Admin\Downloads\btl_mmt\btl_btlmmt'
python --version
python -m pip install -r ..\requirements.txt
```

Các bước dưới đây dùng Python 3.12. Nếu PowerShell báo không tìm thấy `python`, hãy kiểm tra Python đã được cài và thêm vào PATH, rồi mở lại PowerShell.

Tạo chứng chỉ TLS lần đầu. Nếu cả hai tệp đã có sẵn, lệnh này sẽ giữ nguyên chúng:

```powershell
if (!(Test-Path ..\.security\server.crt) -and !(Test-Path ..\.security\server.key)) {
    python security.py
}
```

Backend dùng cặp `..\.security\server.crt` và `..\.security\server.key`. Nếu chỉ còn một trong hai tệp, hãy khôi phục tệp còn thiếu từ bản sao lưu trước khi chạy.

## 2. Chạy backend trong cửa sổ thứ nhất

Từ thư mục `btl_btlmmt`, chạy:

```powershell
python server.py
```

Đợi terminal hiện dòng tương tự `[SERVER] TCP 0.0.0.0:8888, UDP 9000`.

## 3. Bật Web UI trong cửa sổ thứ hai

Mở cửa sổ PowerShell mới và chạy:

```powershell
cd 'C:\Users\Admin\Downloads\btl_mmt\btl_btlmmt'
python web_ui/server_web.py --port 5000
```

Khi terminal hiện địa chỉ web, mở **[http://127.0.0.1:5000](http://127.0.0.1:5000)** trên máy chủ. Những lần chạy sau chỉ cần lặp lại bước 2 và 3. Nhấn `Ctrl+C` ở từng cửa sổ khi muốn dừng chương trình.

## 4. Thử chat và gửi file

1. Mở hai tab trên cùng trình duyệt. Đăng nhập bằng hai tên khác nhau, ví dụ `alice` và `bob`.
2. Chọn **Chat chung** để gửi broadcast hoặc chọn tên người nhận để chat riêng.
3. Để gửi file, chọn người nhận, chọn file rồi bấm **Gửi Tệp Tin**. Ở tab người nhận, mở cuộc trò chuyện với người gửi và bấm **Tải file**.
4. Để kiểm tra gửi khi người nhận offline, chọn cuộc trò chuyện với `bob` ở tab `alice` trước, rồi đóng phiên của `bob` và gửi file từ cuộc trò chuyện đã chọn. Khi máy chủ nhận đủ file, nó sẽ tự đưa file vào hàng đợi và gửi khi `bob` đăng nhập lại.

Khi máy chủ nhận đủ file, việc gửi qua UDP chạy nền dù bạn đóng tab. Nếu đóng tab hoặc mất mạng khi máy chủ mới nhận một phần, máy chủ giữ phần đã lưu. Để tiếp tục, mở lại cùng địa chỉ web trên cùng trình duyệt, đăng nhập bằng cùng tên, chọn lại người nhận và file gốc rồi bấm **Gửi Tệp Tin**.

## 5. Mở Web UI từ máy khác trong LAN

Trên máy chủ, xem địa chỉ LAN ở mục mời kết nối trong Web UI hoặc chạy `ipconfig` để lấy IPv4 của card Wi-Fi/Ethernet đang dùng. Trên máy khác cùng mạng, mở địa chỉ dạng `http://192.168.1.25:5000`, thay `192.168.1.25` bằng IPv4 của máy chủ. Máy chỉ dùng trình duyệt không cần cài Python hay chứng chỉ.

Nếu vào được web trên máy chủ nhưng máy khác cùng mạng không vào được, kiểm tra Windows Firewall. Khi cần mở cổng, chạy trong **PowerShell với quyền quản trị** trên máy chủ:

```powershell
New-NetFirewallRule -DisplayName "Collab Web LAN 5000" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5000 -RemoteAddress LocalSubnet
```

| Cổng mặc định | Vai trò |
| --- | --- |
| TCP 5000 | Trình duyệt mở Web UI |
| TCP 8888 | Web bridge kết nối TLS tới backend |
| UDP 9000 | Backend trao đổi dữ liệu chat và file |

## Xem gói chat và file trong Wireshark

Dùng bộ lọc `udp.port == 9000 && udp.payload[0] == 0x61` để xem gói chat, hoặc thay
`0x61` bằng `0x62` để xem các chunk dữ liệu file. Cả chunk cuối và gói gửi lại
giữ nguyên mã loại. Bắt đầu/kết thúc file và phản hồi ứng dụng dùng `0x60`.
Khi cập nhật, chạy lại cả backend và Web UI để hai bên nhận được các mã mới.

## Khi không chạy được

- **Web mở được nhưng đăng nhập lỗi kết nối.** Kiểm tra cửa sổ backend còn chạy và đang nghe TCP 8888. Nếu bạn đổi cổng backend bằng `--tcp-port`, truyền cùng cổng vào lệnh chạy Web UI.
- **Cổng web 5000 đang bận.** Chạy `python web_ui/server_web.py --port 5001` và mở `http://127.0.0.1:5001`. Upload đang dở cần mở lại đúng địa chỉ và cổng đã dùng lúc bắt đầu.
- **Tên đã online.** Đăng xuất phiên cũ hoặc dùng một tên khác để thử.

Hồ sơ người dùng được lưu trong `data/users.sqlite3`. Chạy `python users.py` để xem danh sách. Upload đang dở và hàng đợi file được giữ trong `data/uploads`. Web UI hỗ trợ tối đa **1 GiB mỗi file**. Hệ thống hiện đăng nhập bằng tên, chưa có mật khẩu.

Xem [README cấp dự án](../README.md) để biết thêm về giao thức và Python API.
