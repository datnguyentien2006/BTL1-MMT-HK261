# Đối chiếu báo cáo kiểm tra sau pull

Báo cáo đầu vào: `bao_cao_kiem_tra_lai_sau_pull_commit_moi.pdf`, tham chiếu
`origin/main` tại `793c2fb`. Workspace gốc là `feature/tcp_udp_testing` tại
`8bf1de1`. Theo lựa chọn của người dùng, giữ backend v2 hiện tại và tích hợp GUI
của main; không merge đè client/server/protocol của main và không thay đổi nhánh.
Giao diện HTML được lấy từ main, JavaScript và bridge được sửa cho API v2.

| Phát hiện trong PDF | Xử lý trên bản tích hợp |
| --- | --- |
| Username trùng, cleanup xóa phiên khác | Backend hiện có từ chối tên trùng và kiểm tra socket sở hữu; thêm test HTTP đăng nhập trùng |
| Thiếu sliding window | Đã có per-stream window thật trong reliable_udp.py, giữ nguyên và kiểm thử lại |
| Thiếu BBR/CUBIC | Đã có CUBIC-style, pacing, RTO chung theo phiên; tài liệu ghi rõ giới hạn, không nhận là full TCP CUBIC |
| Broadcast không retry | Định tuyến qua cùng transport tin cậy; thêm test broadcast mất DATA/ACK tới hai người nhận |
| Stream unicast cố định gây ACK cross-talk | ID động theo phiên/hướng, ACK gắn phiên; thêm test Alice và Carol đồng thời DM Bob, mỗi tin đúng một bản |
| Key AES hardcode | Giữ TLS 1.3 + secret ngẫu nhiên mỗi phiên, HKDF/AES-GCM và counter nonce hiện có; không đưa key hardcode từ main vào |
| Web bridge gọi CLI/input | Bridge dùng connect_and_authenticate, không gọi run/start CLI; test subprocess stdin=DEVNULL |
| Progress giả 30/60/100 | Upload job + callback byte được receiver ACK; test giữ ACK khối thứ hai và quan sát đúng 262144/524288 bytes |
| Tên file bị GUI/user prefix | Stage trong thư mục tạm riêng với basename gốc; metadata name riêng; download Content-Disposition giữ tên gốc |
| Polling hai interval | Một recursive setTimeout sau khi request hoàn tất, thêm guard chống overlap |
| README sai đường dẫn/thiếu requirements | README gốc và README trong btl_btlmmt ghi đường dẫn thật; giữ requirements runtime hiện có |
| Diagram stream ID/window sai | Báo cáo mới mô tả ID động, window và v2; không nhập diagram cũ không khớp backend |
| Thiếu báo cáo tổng hợp/Challenges | Thêm report/REPORT.md và Technical_Report.pdf gồm kiến trúc, đặc tả, sequence, challenges/solutions và kiểm thử |

Bổ sung cho bridge: không phục vụ thư mục tùy ý, download gắn session, kiểm tra
filename/base64/giới hạn upload, không đưa tin nhắn/filename vào HTML thô, giới hạn
session/job/history và dọn temporary upload. GUI không tự nhận là E2E: server v2
giải mã rồi mã hóa lại trên hai chặng. Người dùng chưa có xác thực mật khẩu.

Phạm vi: HTTP adapter chỉ bind localhost; mỗi máy LAN chạy bridge riêng, kết nối
TLS/UDP tới server. Chưa cung cấp HTTPS cho truy cập trực tiếp bridge từ máy khác.
Giới hạn upload web là 16 MiB, API Python vẫn hỗ trợ 1 GiB. Xem
[kiểm thử](TESTING.md) và [báo cáo tổng hợp](../report/Technical_Report.pdf).
