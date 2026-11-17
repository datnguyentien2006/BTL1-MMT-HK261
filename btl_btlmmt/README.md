# Chạy từ thư mục btl_btlmmt

## Upload tiếp tục và gửi file khi người nhận offline

Khởi động lại cả backend `python server.py` và web bridge
`python web_ui/server_web.py`, rồi tải lại trang để dùng giao thức mới.

- Web upload từng phần 256 KiB, tối đa 1 GiB/file. Tiến độ và nội dung lưu
  trong `btl_btlmmt/data/uploads`, không mất khi đóng tab hoặc khởi động lại web bridge.
- Nếu mất mạng lúc đang tải lên: dùng cùng trình duyệt/địa chỉ web, đăng nhập
  lại cùng tên, chọn cùng người nhận và đúng file chưa thay đổi, bấm Gửi để tiếp tục.
  Trình duyệt lưu mã upload trong localStorage; xóa dữ liệu trình duyệt sẽ mất mã này.
- Có thể nhập tên người nhận offline trong ô người nhận. Sau khi tải đủ,
  trạng thái chuyển sang chờ; web bridge tự thử gửi lại. Người gửi có thể đóng tab.
  Backend và web bridge phải đang chạy để thực hiện giao file.
- Web bridge vẫn truyền file qua UDP mã hóa. Bên nhận lưu checkpoint mỗi block
  và tiếp tục từ offset đã ghi khi kết nối lại. Chỉ công bố file sau khi đủ
  dung lượng và đúng SHA-256. File đã nhận được khôi phục trên UI khi đăng nhập lại.
- Khi người gửi không có phiên web, bridge tạo phiên backend tạm dưới tên đó
  để giao file. Nếu tên đang được dùng bởi client khác, hàng đợi chờ và thử lại.
- Với Python API: truyền `file_id` cố định (32 ký tự hex) vào `send_file` và
  gọi lại với cùng file, người nhận, ID sau khi kết nối lại. API không truyền
  `file_id` vẫn dùng cách gửi trực tiếp cũ, không tự có hàng đợi offline.

Giới hạn hiện tại: tối đa 10 GiB file chưa giao và 1.000 bản ghi ở outbox;
bên nhận tối đa 32 file đang dở. File tạm được giữ để resume, chưa tự hết hạn
hay có giao diện hủy. Outbox được xóa nội dung sau khi giao thành công nhưng
giữ metadata. Sao lưu cả `data/uploads` và thư mục downloads cùng checkpoint.
Đây vẫn là hệ thống đăng nhập bằng tên, chưa có mật khẩu xác minh chủ tài khoản.

Kiểm thử: `python -m unittest test_users test_resumable -v`.

## Lưu người dùng lâu dài

Server tự tạo `data/users.sqlite3` khi khởi động. Lần đăng nhập đầu tạo hồ sơ;
các lần sau cập nhật thời gian đăng nhập và số lần đăng nhập. Đăng xuất hoặc
khởi động lại server không xóa hồ sơ. Danh sách online vẫn chỉ gồm phiên đang kết nối.

Xem hồ sơ đã lưu: `python users.py`. Các mốc thời gian được lưu theo UTC.
Đổi đường dẫn database: `python server.py --user-db C:/path/users.sqlite3`;
khi xem dùng `python users.py --db C:/path/users.sqlite3`.
Sao lưu file database khi server đã dừng. Không đưa database vào Git.

Đây là hồ sơ theo tên, chưa có mật khẩu: người khác vẫn có thể dùng lại tên
khi tên đó không online. Tính năng này không xác minh quyền sở hữu tài khoản.

Xem [README chính](../README.md) để cài dependencies, tạo chứng thư và cấu hình LAN.
Nếu terminal đang ở thư mục này:

```powershell
python -m pip install -r ../requirements.txt
python security.py
python server.py
```

Ở terminal khác, cũng trong `btl_btlmmt`:

```powershell
python web_ui/server_web.py --port 5000
```

Mở http://127.0.0.1:5000. Tạo chứng thư chỉ một lần; bỏ qua `security.py` nếu identity
đã tồn tại. Bridge dùng API backend, không yêu cầu nhập CLI. UI gồm chat riêng/chung,
peers trực tuyến, upload tiến độ thật và tải file qua session của người nhận.

Máy khác trong LAN mở `http://<IPv4-máy-server>:5000`, mỗi người dùng một tên khác
nhau. Web mặc định lắng nghe trên `0.0.0.0`; không cần Internet, Python hoặc chứng
chỉ trên các máy chỉ dùng trình duyệt. Xem mục LAN trong README chính để mở cổng
5000 của Windows Firewall. Dùng `--host 127.0.0.1` nếu chỉ muốn truy cập trên máy này.
