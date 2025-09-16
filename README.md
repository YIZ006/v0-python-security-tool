# Information Security Tool - Công cụ An toàn Thông tin

## 📋 Mô tả
Tool bảo mật thông tin toàn diện được viết bằng Python với giao diện CLI, cung cấp các tính năng:

- 🖥️ **Thông tin hệ thống**: Hiển thị OS, IP, MAC, hostname và quét port local
- 🌐 **Kiểm tra bảo mật website**: Phân tích HTTP headers, SSL/TLS, redirects
- 🔐 **Hash & Mật khẩu**: Tạo hash, crack hash với wordlist
- 🔒 **Mã hóa/Giải mã**: AES encryption cho text và file
- 🌍 **Network Tools**: Ping, traceroute, port scan, packet sniffing

## 🚀 Cài đặt

### 1. Cài đặt Python 3
Đảm bảo Python 3.6+ đã được cài đặt trên hệ thống.

### 2. Cài đặt thư viện cần thiết
\`\`\`bash
pip install requests cryptography scapy
\`\`\`

### 3. Tải tool
Tải file `security_tool.py` về máy tính của bạn.

## 💻 Cách sử dụng

### Chạy tool:
\`\`\`bash
python security_tool.py
\`\`\`

### Hoặc trên Linux/Mac:
\`\`\`bash
python3 security_tool.py
\`\`\`

### Chạy với quyền admin (cho packet sniffing):
\`\`\`bash
# Windows (Command Prompt as Administrator)
python security_tool.py

# Linux/Mac
sudo python3 security_tool.py
\`\`\`

## 📖 Hướng dẫn sử dụng từng tính năng

### 1. 🖥️ Thông tin hệ thống
- Hiển thị thông tin OS, IP, MAC address
- Quét các port mở trên máy local (1-1000)
- Nhận diện dịch vụ chạy trên các port

### 2. 🌐 Kiểm tra bảo mật website
- Nhập URL website cần kiểm tra
- Phân tích security headers (X-Frame-Options, CSP, HSTS, etc.)
- Kiểm tra chứng chỉ SSL/TLS và thời hạn
- Phát hiện redirect nguy hiểm

### 3. 🔐 Hash & Mật khẩu
- **Tạo hash**: Tạo MD5, SHA1, SHA256 từ text
- **Crack hash**: Sử dụng wordlist để tìm password gốc
  - Wordlist mặc định hoặc đọc từ file
  - Hỗ trợ MD5, SHA1, SHA256

### 4. 🔒 Mã hóa/Giải mã
- **Sinh key**: Tạo key ngẫu nhiên và lưu file
- **Mã hóa text**: Mã hóa AES với key
- **Giải mã text**: Giải mã text đã mã hóa
- **Mã hóa file**: Mã hóa toàn bộ file
- **Giải mã file**: Khôi phục file gốc

### 5. 🌍 Network Tools
- **Ping**: Ping host với số lần tùy chỉnh
- **Traceroute**: Trace đường đi đến host
- **Port scan**: Quét port mở của host từ xa
- **Packet sniffing**: Bắt và phân tích network packets (cần quyền admin)

## ⚠️ Lưu ý quan trọng

### Quyền truy cập:
- **Packet sniffing** cần quyền administrator/root
- **Port scanning** có thể bị firewall chặn
- Chỉ sử dụng tool trên hệ thống của bạn hoặc có sự cho phép

### Bảo mật:
- Không sử dụng để tấn công hệ thống khác
- Giữ bí mật các key mã hóa
- Tool chỉ dành cho mục đích học tập và kiểm tra bảo mật hợp pháp

### Khắc phục lỗi:
- Nếu thiếu thư viện: `pip install <tên_thư_viện>`
- Nếu lỗi quyền truy cập: Chạy với quyền admin
- Nếu lỗi network: Kiểm tra firewall và kết nối internet

## 🛠️ Yêu cầu hệ thống
- Python 3.6+
- Windows/Linux/macOS
- Kết nối internet (cho web security check)
- Quyền admin (cho packet sniffing)

## 📝 Ví dụ sử dụng

### Kiểm tra bảo mật website:
\`\`\`
Nhập URL: https://google.com
-> Kiểm tra headers, SSL, redirects
\`\`\`

### Tạo hash:
\`\`\`
Nhập text: mypassword123
-> MD5: 482c811da5d5b4bc6d497ffa98491e38
-> SHA256: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
\`\`\`

### Mã hóa file:
\`\`\`
Đường dẫn file: document.txt
-> Tạo file: document.txt.encrypted
\`\`\`

Chúc bạn sử dụng tool hiệu quả và an toàn! 🔒
