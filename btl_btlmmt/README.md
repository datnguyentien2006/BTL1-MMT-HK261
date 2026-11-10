# Chạy từ thư mục btl_btlmmt

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
