#!/usr/bin/env python3
"""
Information Security Tool
Công cụ An toàn Thông tin

Author: v0
Description: Comprehensive security tool with system info, web security checks, 
             hash operations, encryption/decryption, and network utilities.
"""

import os
import sys
import socket
import hashlib
import platform
import subprocess
import threading
import time
import ssl
import json
from urllib.parse import urlparse
from datetime import datetime
import secrets
import base64

# Import thư viện bổ sung (cần cài đặt)
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("⚠️  Cần cài đặt: pip install requests")
    sys.exit(1)

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("⚠️  Cần cài đặt: pip install cryptography")
    sys.exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("⚠️  Cần cài đặt: pip install scapy")
    print("⚠️  Lưu ý: Scapy cần quyền admin/root để chạy packet sniffing")

class SecurityTool:
    def __init__(self):
        self.banner = """
╔══════════════════════════════════════════════════════════════╗
║                    INFORMATION SECURITY TOOL                 ║
║                        Công cụ Bảo mật                      ║
╚══════════════════════════════════════════════════════════════╝
        """
        
    def show_banner(self):
        """Hiển thị banner của tool"""
        print(self.banner)
        print(f"🕒 Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 62)
    
    def show_menu(self):
        """Hiển thị menu chính"""
        menu = """
📋 MENU CHÍNH:
1. 🖥️  Thông tin hệ thống (System Info)
2. 🌐 Kiểm tra bảo mật website (Web Security)
3. 🔐 Hash & Mật khẩu (Hash & Password)
4. 🔒 Mã hóa / Giải mã (Encryption/Decryption)
5. 🌍 Network Tools
6. ❌ Thoát (Exit)
        """
        print(menu)
    
    # ==================== 1. SYSTEM INFO ====================
    def get_system_info(self):
        """Thu thập thông tin hệ thống"""
        print("\n🖥️  THÔNG TIN HỆ THỐNG")
        print("=" * 50)
        
        try:
            # Thông tin cơ bản
            print(f"🔹 Hệ điều hành: {platform.system()} {platform.release()}")
            print(f"🔹 Kiến trúc: {platform.architecture()[0]}")
            print(f"🔹 Hostname: {socket.gethostname()}")
            
            # Lấy IP address
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"🔹 IP Local: {local_ip}")
            
            # Lấy MAC address
            mac = self.get_mac_address()
            if mac:
                print(f"🔹 MAC Address: {mac}")
            
            # Quét port local
            print(f"\n🔍 Quét các cổng mở trên {local_ip}:")
            self.scan_local_ports(local_ip)
            
        except Exception as e:
            print(f"❌ Lỗi khi lấy thông tin hệ thống: {e}")
    
    def get_mac_address(self):
        """Lấy MAC address"""
        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0,2*6,2)][::-1])
            return mac
        except:
            return None
    
    def scan_local_ports(self, host, start_port=1, end_port=1000):
        """Quét các cổng mở trên máy local"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        print(f"   Đang quét cổng {start_port}-{end_port}...")
        threads = []
        
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Giới hạn số thread đồng thời
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        
        # Đợi các thread còn lại
        for t in threads:
            t.join()
        
        if open_ports:
            print(f"   ✅ Tìm thấy {len(open_ports)} cổng mở:")
            for port in sorted(open_ports):
                service = self.get_service_name(port)
                print(f"      - Port {port}: {service}")
        else:
            print("   ❌ Không tìm thấy cổng mở nào")
    
    def get_service_name(self, port):
        """Lấy tên dịch vụ theo port"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"
        }
        return common_ports.get(port, "Unknown")
    
    # ==================== 2. WEB SECURITY ====================
    def web_security_check(self):
        """Kiểm tra bảo mật website"""
        print("\n🌐 KIỂM TRA BẢO MẬT WEBSITE")
        print("=" * 50)
        
        url = input("🔗 Nhập URL website (ví dụ: https://example.com): ").strip()
        if not url:
            print("❌ URL không được để trống!")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            print(f"\n🔍 Đang kiểm tra: {url}")
            
            # Kiểm tra HTTP headers
            self.check_security_headers(url)
            
            # Kiểm tra SSL/TLS
            if url.startswith('https://'):
                self.check_ssl_certificate(url)
            
            # Kiểm tra redirect
            self.check_redirects(url)
            
        except Exception as e:
            print(f"❌ Lỗi khi kiểm tra website: {e}")
    
    def check_security_headers(self, url):
        """Kiểm tra các HTTP security headers"""
        print("\n📋 KIỂM TRA SECURITY HEADERS:")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Bảo vệ khỏi clickjacking',
                'X-Content-Type-Options': 'Ngăn MIME type sniffing',
                'X-XSS-Protection': 'Bảo vệ khỏi XSS',
                'Strict-Transport-Security': 'Ép dùng HTTPS',
                'Content-Security-Policy': 'Ngăn code injection',
                'Referrer-Policy': 'Kiểm soát referrer info'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    print(f"   ✅ {header}: {headers[header]}")
                else:
                    print(f"   ❌ {header}: THIẾU - {description}")
            
            print(f"\n📊 Status Code: {response.status_code}")
            print(f"📊 Server: {headers.get('Server', 'Unknown')}")
            
        except Exception as e:
            print(f"❌ Lỗi khi kiểm tra headers: {e}")
    
    def check_ssl_certificate(self, url):
        """Kiểm tra chứng chỉ SSL/TLS"""
        print("\n🔒 KIỂM TRA CHỨNG CHỈ SSL/TLS:")
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    print(f"   ✅ Subject: {dict(x[0] for x in cert['subject'])}")
                    print(f"   ✅ Issuer: {dict(x[0] for x in cert['issuer'])}")
                    print(f"   ✅ Version: {cert['version']}")
                    print(f"   ✅ Not Before: {cert['notBefore']}")
                    print(f"   ✅ Not After: {cert['notAfter']}")
                    
                    # Kiểm tra hạn sử dụng
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.now()).days
                    
                    if days_left > 30:
                        print(f"   ✅ Chứng chỉ còn hiệu lực {days_left} ngày")
                    elif days_left > 0:
                        print(f"   ⚠️  Chứng chỉ sắp hết hạn trong {days_left} ngày")
                    else:
                        print(f"   ❌ Chứng chỉ đã hết hạn {abs(days_left)} ngày")
                        
        except Exception as e:
            print(f"❌ Lỗi khi kiểm tra SSL: {e}")
    
    def check_redirects(self, url):
        """Kiểm tra redirect nguy hiểm"""
        print("\n🔄 KIỂM TRA REDIRECTS:")
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=False, verify=False)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                print(f"   ⚠️  Redirect detected: {response.status_code}")
                print(f"   🔗 Location: {location}")
                
                # Kiểm tra redirect nguy hiểm
                if location.startswith('http://'):
                    print("   ❌ NGUY HIỂM: Redirect từ HTTPS sang HTTP!")
                elif not location.startswith(('https://', '/')):
                    print("   ⚠️  Cảnh báo: Redirect đến domain khác!")
                else:
                    print("   ✅ Redirect an toàn")
            else:
                print("   ✅ Không có redirect")
                
        except Exception as e:
            print(f"❌ Lỗi khi kiểm tra redirect: {e}")
    
    # ==================== 3. HASH & PASSWORD ====================
    def hash_operations(self):
        """Các thao tác với hash và mật khẩu"""
        print("\n🔐 HASH & MẬT KHẨU")
        print("=" * 50)
        
        while True:
            print("\n📋 Chọn chức năng:")
            print("1. Tạo hash từ text")
            print("2. Kiểm tra hash với wordlist")
            print("3. Quay lại menu chính")
            
            choice = input("\n👉 Lựa chọn (1-3): ").strip()
            
            if choice == '1':
                self.generate_hash()
            elif choice == '2':
                self.crack_hash()
            elif choice == '3':
                break
            else:
                print("❌ Lựa chọn không hợp lệ!")
    
    def generate_hash(self):
        """Tạo hash từ text"""
        print("\n🔨 TẠO HASH:")
        
        text = input("📝 Nhập text cần hash: ").strip()
        if not text:
            print("❌ Text không được để trống!")
            return
        
        text_bytes = text.encode('utf-8')
        
        # Tạo các loại hash
        md5_hash = hashlib.md5(text_bytes).hexdigest()
        sha1_hash = hashlib.sha1(text_bytes).hexdigest()
        sha256_hash = hashlib.sha256(text_bytes).hexdigest()
        
        print(f"\n📊 KẾT QUẢ HASH:")
        print(f"MD5:    {md5_hash}")
        print(f"SHA1:   {sha1_hash}")
        print(f"SHA256: {sha256_hash}")
    
    def crack_hash(self):
        """Kiểm tra hash với wordlist"""
        print("\n🔓 KIỂM TRA HASH VỚI WORDLIST:")
        
        target_hash = input("🎯 Nhập hash cần crack: ").strip().lower()
        if not target_hash:
            print("❌ Hash không được để trống!")
            return
        
        # Xác định loại hash
        hash_type = self.detect_hash_type(target_hash)
        print(f"🔍 Loại hash được phát hiện: {hash_type}")
        
        # Tạo wordlist đơn giản hoặc đọc từ file
        wordlist_choice = input("\n📋 Chọn wordlist:\n1. Wordlist mặc định\n2. Đọc từ file\n👉 Lựa chọn: ").strip()
        
        if wordlist_choice == '1':
            wordlist = self.get_default_wordlist()
        elif wordlist_choice == '2':
            file_path = input("📁 Đường dẫn file wordlist: ").strip()
            wordlist = self.read_wordlist_file(file_path)
        else:
            print("❌ Lựa chọn không hợp lệ!")
            return
        
        if not wordlist:
            print("❌ Wordlist trống!")
            return
        
        # Bắt đầu crack
        print(f"\n🚀 Bắt đầu crack hash với {len(wordlist)} từ...")
        found = self.crack_hash_with_wordlist(target_hash, wordlist, hash_type)
        
        if found:
            print(f"✅ CRACK THÀNH CÔNG! Password: {found}")
        else:
            print("❌ Không tìm thấy password trong wordlist")
    
    def detect_hash_type(self, hash_string):
        """Phát hiện loại hash dựa trên độ dài"""
        length = len(hash_string)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        else:
            return "Unknown"
    
    def get_default_wordlist(self):
        """Tạo wordlist mặc định"""
        return [
            "password", "123456", "password123", "admin", "root",
            "qwerty", "abc123", "123123", "password1", "admin123",
            "letmein", "welcome", "monkey", "dragon", "master"
        ]
    
    def read_wordlist_file(self, file_path):
        """Đọc wordlist từ file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"❌ Lỗi đọc file: {e}")
            return []
    
    def crack_hash_with_wordlist(self, target_hash, wordlist, hash_type):
        """Crack hash với wordlist"""
        hash_func = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256
        }.get(hash_type)
        
        if not hash_func:
            print("❌ Loại hash không được hỗ trợ!")
            return None
        
        for i, word in enumerate(wordlist):
            if i % 1000 == 0:
                print(f"   Đã thử {i}/{len(wordlist)} từ...")
            
            word_hash = hash_func(word.encode('utf-8')).hexdigest()
            if word_hash == target_hash:
                return word
        
        return None
    
    # ==================== 4. ENCRYPTION/DECRYPTION ====================
    def encryption_operations(self):
        """Các thao tác mã hóa/giải mã"""
        print("\n🔒 MÃ HÓA / GIẢI MÃ")
        print("=" * 50)
        
        while True:
            print("\n📋 Chọn chức năng:")
            print("1. Sinh key ngẫu nhiên")
            print("2. Mã hóa text")
            print("3. Giải mã text")
            print("4. Mã hóa file")
            print("5. Giải mã file")
            print("6. Quay lại menu chính")
            
            choice = input("\n👉 Lựa chọn (1-6): ").strip()
            
            if choice == '1':
                self.generate_key()
            elif choice == '2':
                self.encrypt_text()
            elif choice == '3':
                self.decrypt_text()
            elif choice == '4':
                self.encrypt_file()
            elif choice == '5':
                self.decrypt_file()
            elif choice == '6':
                break
            else:
                print("❌ Lựa chọn không hợp lệ!")
    
    def generate_key(self):
        """Sinh key ngẫu nhiên"""
        print("\n🔑 SINH KEY NGẪU NHIÊN:")
        
        key = Fernet.generate_key()
        key_string = key.decode()
        
        print(f"🔐 Key được tạo: {key_string}")
        
        save_choice = input("\n💾 Lưu key vào file? (y/n): ").strip().lower()
        if save_choice == 'y':
            filename = input("📁 Tên file (mặc định: secret.key): ").strip() or "secret.key"
            try:
                with open(filename, 'wb') as f:
                    f.write(key)
                print(f"✅ Key đã được lưu vào {filename}")
            except Exception as e:
                print(f"❌ Lỗi lưu file: {e}")
    
    def encrypt_text(self):
        """Mã hóa text"""
        print("\n🔒 MÃ HÓA TEXT:")
        
        text = input("📝 Nhập text cần mã hóa: ").strip()
        if not text:
            print("❌ Text không được để trống!")
            return
        
        key = self.get_encryption_key()
        if not key:
            return
        
        try:
            fernet = Fernet(key)
            encrypted_text = fernet.encrypt(text.encode())
            encrypted_b64 = base64.b64encode(encrypted_text).decode()
            
            print(f"\n🔐 Text đã mã hóa: {encrypted_b64}")
            
        except Exception as e:
            print(f"❌ Lỗi mã hóa: {e}")
    
    def decrypt_text(self):
        """Giải mã text"""
        print("\n🔓 GIẢI MÃ TEXT:")
        
        encrypted_text = input("🔐 Nhập text đã mã hóa: ").strip()
        if not encrypted_text:
            print("❌ Text không được để trống!")
            return
        
        key = self.get_encryption_key()
        if not key:
            return
        
        try:
            fernet = Fernet(key)
            encrypted_bytes = base64.b64decode(encrypted_text.encode())
            decrypted_text = fernet.decrypt(encrypted_bytes).decode()
            
            print(f"\n📝 Text đã giải mã: {decrypted_text}")
            
        except Exception as e:
            print(f"❌ Lỗi giải mã: {e}")
    
    def encrypt_file(self):
        """Mã hóa file"""
        print("\n🔒 MÃ HÓA FILE:")
        
        file_path = input("📁 Đường dẫn file cần mã hóa: ").strip()
        if not os.path.exists(file_path):
            print("❌ File không tồn tại!")
            return
        
        key = self.get_encryption_key()
        if not key:
            return
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(file_data)
            
            encrypted_file_path = file_path + '.encrypted'
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            
            print(f"✅ File đã được mã hóa: {encrypted_file_path}")
            
        except Exception as e:
            print(f"❌ Lỗi mã hóa file: {e}")
    
    def decrypt_file(self):
        """Giải mã file"""
        print("\n🔓 GIẢI MÃ FILE:")
        
        file_path = input("📁 Đường dẫn file đã mã hóa: ").strip()
        if not os.path.exists(file_path):
            print("❌ File không tồn tại!")
            return
        
        key = self.get_encryption_key()
        if not key:
            return
        
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            decrypted_file_path = file_path.replace('.encrypted', '.decrypted')
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"✅ File đã được giải mã: {decrypted_file_path}")
            
        except Exception as e:
            print(f"❌ Lỗi giải mã file: {e}")
    
    def get_encryption_key(self):
        """Lấy key để mã hóa/giải mã"""
        print("\n🔑 Chọn cách nhập key:")
        print("1. Nhập key trực tiếp")
        print("2. Đọc key từ file")
        
        choice = input("👉 Lựa chọn (1-2): ").strip()
        
        if choice == '1':
            key_string = input("🔐 Nhập key: ").strip()
            if not key_string:
                print("❌ Key không được để trống!")
                return None
            try:
                return key_string.encode()
            except:
                print("❌ Key không hợp lệ!")
                return None
                
        elif choice == '2':
            file_path = input("📁 Đường dẫn file key: ").strip()
            try:
                with open(file_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                print(f"❌ Lỗi đọc file key: {e}")
                return None
        else:
            print("❌ Lựa chọn không hợp lệ!")
            return None
    
    # ==================== 5. NETWORK TOOLS ====================
    def network_tools(self):
        """Các công cụ network"""
        print("\n🌍 NETWORK TOOLS")
        print("=" * 50)
        
        while True:
            print("\n📋 Chọn chức năng:")
            print("1. Ping host")
            print("2. Traceroute")
            print("3. Port scan")
            print("4. Packet sniffing")
            print("5. Quay lại menu chính")
            
            choice = input("\n👉 Lựa chọn (1-5): ").strip()
            
            if choice == '1':
                self.ping_host()
            elif choice == '2':
                self.traceroute()
            elif choice == '3':
                self.port_scan()
            elif choice == '4':
                self.packet_sniffing()
            elif choice == '5':
                break
            else:
                print("❌ Lựa chọn không hợp lệ!")
    
    def ping_host(self):
        """Ping một host"""
        print("\n🏓 PING HOST:")
        
        host = input("🎯 Nhập hostname/IP: ").strip()
        if not host:
            print("❌ Host không được để trống!")
            return
        
        count = input("📊 Số lần ping (mặc định: 4): ").strip() or "4"
        
        try:
            if platform.system().lower() == "windows":
                cmd = f"ping -n {count} {host}"
            else:
                cmd = f"ping -c {count} {host}"
            
            print(f"\n🚀 Đang ping {host}...")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            print("📊 KẾT QUẢ PING:")
            print(result.stdout)
            
            if result.stderr:
                print("❌ LỖI:")
                print(result.stderr)
                
        except Exception as e:
            print(f"❌ Lỗi khi ping: {e}")
    
    def traceroute(self):
        """Traceroute cơ bản"""
        print("\n🛤️  TRACEROUTE:")
        
        host = input("🎯 Nhập hostname/IP: ").strip()
        if not host:
            print("❌ Host không được để trống!")
            return
        
        try:
            if platform.system().lower() == "windows":
                cmd = f"tracert {host}"
            else:
                cmd = f"traceroute {host}"
            
            print(f"\n🚀 Đang trace route đến {host}...")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            print("📊 KẾT QUẢ TRACEROUTE:")
            print(result.stdout)
            
            if result.stderr:
                print("❌ LỖI:")
                print(result.stderr)
                
        except Exception as e:
            print(f"❌ Lỗi khi traceroute: {e}")
    
    def port_scan(self):
        """Quét port của một host"""
        print("\n🔍 PORT SCAN:")
        
        host = input("🎯 Nhập hostname/IP: ").strip()
        if not host:
            print("❌ Host không được để trống!")
            return
        
        port_range = input("📊 Nhập range port (ví dụ: 1-1000, mặc định: 1-100): ").strip() or "1-100"
        
        try:
            start_port, end_port = map(int, port_range.split('-'))
            if start_port > end_port or start_port < 1 or end_port > 65535:
                print("❌ Range port không hợp lệ!")
                return
        except:
            print("❌ Format range port không đúng! Ví dụ: 1-1000")
            return
        
        print(f"\n🚀 Đang quét port {start_port}-{end_port} trên {host}...")
        self.scan_ports(host, start_port, end_port)
    
    def scan_ports(self, host, start_port, end_port):
        """Quét port với threading"""
        open_ports = []
        
        def scan_single_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_single_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Giới hạn số thread
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Đợi thread còn lại
        for t in threads:
            t.join()
        
        print(f"\n📊 KẾT QUẢ SCAN:")
        if open_ports:
            print(f"✅ Tìm thấy {len(open_ports)} cổng mở:")
            for port in sorted(open_ports):
                service = self.get_service_name(port)
                print(f"   - Port {port}: {service}")
        else:
            print("❌ Không tìm thấy cổng mở nào")
    
    def packet_sniffing(self):
        """Packet sniffing với scapy"""
        print("\n📡 PACKET SNIFFING:")
        print("⚠️  Chức năng này cần quyền admin/root!")
        
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            print("❌ Scapy chưa được cài đặt!")
            return
        
        interface = input("🌐 Interface (để trống = auto): ").strip() or None
        count = input("📊 Số packet cần bắt (mặc định: 10): ").strip() or "10"
        
        try:
            count = int(count)
        except:
            count = 10
        
        print(f"\n🚀 Bắt đầu sniff {count} packets...")
        print("⏹️  Nhấn Ctrl+C để dừng")
        
        def packet_handler(packet):
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                if TCP in packet:
                    protocol = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                elif ICMP in packet:
                    protocol = "ICMP"
                    sport = dport = "N/A"
                else:
                    protocol = "OTHER"
                    sport = dport = "N/A"
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] {protocol}: {ip_src}:{sport} -> {ip_dst}:{dport}")
        
        try:
            sniff(iface=interface, prn=packet_handler, count=count)
            print("\n✅ Packet sniffing hoàn thành!")
        except Exception as e:
            print(f"❌ Lỗi khi sniff packet: {e}")
            print("💡 Thử chạy với quyền admin/root")
    
    # ==================== MAIN FUNCTION ====================
    def run(self):
        """Chạy tool chính"""
        self.show_banner()
        
        while True:
            self.show_menu()
            choice = input("\n👉 Lựa chọn của bạn (1-6): ").strip()
            
            if choice == '1':
                self.get_system_info()
            elif choice == '2':
                self.web_security_check()
            elif choice == '3':
                self.hash_operations()
            elif choice == '4':
                self.encryption_operations()
            elif choice == '5':
                self.network_tools()
            elif choice == '6':
                print("\n👋 Cảm ơn bạn đã sử dụng Security Tool!")
                print("🔒 Hãy luôn giữ an toàn thông tin!")
                break
            else:
                print("❌ Lựa chọn không hợp lệ! Vui lòng chọn từ 1-6.")
            
            input("\n⏸️  Nhấn Enter để tiếp tục...")

if __name__ == "__main__":
    try:
        tool = SecurityTool()
        tool.run()
    except KeyboardInterrupt:
        print("\n\n👋 Tool đã được dừng bởi người dùng!")
    except Exception as e:
        print(f"\n❌ Lỗi không mong muốn: {e}")
