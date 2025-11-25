# AES File Manager — Hướng dẫn sử dụng

## Giới thiệu
- Ứng dụng quản lý, mã hóa và giải mã tập tin bằng AES (128/192/256-bit).
- Hỗ trợ quản lý tập tin, lưu trữ an toàn trên cơ sở dữ liệu qua máy chủ HTTP với JWT.

## Cài đặt
- Cài thư viện: `pip install -r requirements.txt` (hoặc `pip install cryptography`)
- Chạy ứng dụng: `python main.py`

## Tính năng chính
- Mã hóa tập tin với AES-CBC, sinh `salt` và `iv` ngẫu nhiên.
- Giải mã tập tin `.aes` về dạng gốc.
- Quản lý tập tin: quét thư mục hoặc hiển thị danh sách file đã chọn, kèm thống kê.
- Trao đổi thông tin: máy chủ HTTP nội bộ với JWT, lưu trữ BLOB vào SQLite, chỉ chủ sở hữu được tải.

## Hướng dẫn sử dụng

### Mã hóa (Encrypt)
- Mở tab “Mã hóa”.
- Bấm `CHỌN TẬP TIN` để chọn các file cần mã hóa.
- Nhập mật khẩu và xác nhận mật khẩu.
- Chọn độ dài khóa AES: 128/192/256.
- Bấm `MÃ HÓA TẬP TIN` để tạo file `.aes` cho từng file.
- Ứng dụng sẽ xóa file gốc sau khi mã hóa thành công; file `.aes` được giữ lại ở cùng thư mục.

### Giải mã (Decrypt)
- Mở tab “Giải mã”.
- Bấm `CHỌN TẬP TIN .AES` để chọn các file `.aes`.
- Nhập mật khẩu đã dùng khi mã hóa.
- Bấm `GIẢI MÃ TẬP TIN` để khôi phục file gốc (tự động xóa file `.aes` sau thành công nếu được cấu hình trong code).

### Quản lý tập tin (Manage)
- Mở tab “Quản lý Tập tin”.
- Chế độ 1 — theo tập tin:
  - Bấm `CHỌN TẬP TIN` để chọn nhiều file, sau đó bấm `TÌM KIẾM` để hiển thị.
- Chế độ 2 — theo thư mục:
  - Bấm `CHỌN THƯ MỤC` để chọn thư mục, sau đó bấm `TÌM KIẾM` để quét toàn bộ thư mục và thư mục con.
- Bảng hiển thị gồm: tên, loại, kích thước, đường dẫn. Thanh thống kê hiển thị tổng số file, số file đã mã hóa và tổng dung lượng.

### Trao đổi thông tin (HTTP + JWT)
- Mở tab “Trao đổi Thông tin”.
- Máy chủ:
  - Bấm `KHỞI ĐỘNG MÁY CHỦ` để chạy tại `http://127.0.0.1:5000`.
  - Nếu ô `JWT Secret` để trống, hệ thống tự sinh secret ngẫu nhiên mạnh và dùng cho việc ký/kiểm tra JWT.
  - Bấm `DỪNG MÁY CHỦ` để tắt máy chủ.
- Xác thực:
  - Trong khung “Tài khoản (JWT)”, bấm `REGISTER` để tạo tài khoản; bấm `LOGIN` để nhận JWT.
- Upload:
  - Trong khung “Upload .AES”, bấm `CHỌN TẬP TIN` để chọn các file `.aes`.
  - Bấm `UPLOAD .AES` để gửi lên máy chủ; nội dung được lưu dạng BLOB trong SQLite kèm `owner_user_id`.
- Download:
  - Trong khung “Download .AES”, nhập tên file `.aes` trên máy chủ.
  - Bấm `CHỌN THƯ MỤC LƯU` để chọn nơi lưu file.
  - Bấm `TẢI FILE TỪ SERVER`; chỉ chủ sở hữu (trùng `uid` trong JWT) mới được tải.

## Bảo mật
- Mã hóa file: `PBKDF2-HMAC-SHA256` với 100.000 vòng lặp để dẫn xuất khóa AES từ mật khẩu (mỗi file sinh `salt` riêng).
- Mật khẩu người dùng (đăng nhập): băm bằng `PBKDF2-HMAC-SHA256` với 200.000 vòng lặp, `salt` ngẫu nhiên.
- JWT: thuật toán HS256; `JWT Secret` là khóa bí mật để ký và xác thực token.
- Chỉ chủ sở hữu tài nguyên mới được phép tải xuống.

## Định dạng file .aes
```
[2 bytes: Key Size] [16 bytes: Salt] [16 bytes: IV] [Ciphertext]
```

## Yêu cầu hệ thống
- Python 3.8+
- Windows/macOS/Linux
- RAM: 512 MB+
- Disk: 50 MB+

## Lưu ý quan trọng
- Không quên mật khẩu; không thể khôi phục dữ liệu nếu mất mật khẩu.
- Sao lưu dữ liệu quan trọng trước khi thực hiện mã hóa/giải mã.
- Sau mã hóa, file gốc sẽ bị xóa để tránh lưu song song (có thể đổi hành vi trong code nếu cần).

## Cấu trúc dự án
```
AES_File_Manager/
├── main.py
├── aes_crypto.py
├── file_utils.py
├── db_manager.py
├── http_server.py
├── GUI/
│   ├── main_window.py
│   ├── encrypt_tab.py
│   ├── decrypt_tab.py
│   ├── manage_tab.py
│   └── share_tab.py
└── requirements.txt
```
