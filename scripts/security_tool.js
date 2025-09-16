#!/usr/bin/env node

/**
 * Information Security Tool - JavaScript Version
 * Công cụ An toàn Thông tin - Phiên bản JavaScript
 *
 * Features:
 * 1. System Information
 * 2. Web Security Check
 * 3. Hash & Password Tools
 * 4. Encryption/Decryption
 * 5. Network Tools
 */

import crypto from "node:crypto"
import os from "node:os"
import fs from "node:fs/promises"
import net from "node:net"
import { exec } from "node:child_process"
import { promisify } from "node:util"
import readline from "node:readline"

const execAsync = promisify(exec)

// Colors for console output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
}

class SecurityTool {
  constructor() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    })
  }

  // Utility function to get user input
  async getUserInput(question) {
    return new Promise((resolve) => {
      this.rl.question(question, (answer) => {
        resolve(answer.trim())
      })
    })
  }

  // Print colored text
  printColored(text, color = "reset") {
    console.log(`${colors[color]}${text}${colors.reset}`)
  }

  // Print banner
  printBanner() {
    console.clear()
    this.printColored("=" * 60, "cyan")
    this.printColored("    🔒 INFORMATION SECURITY TOOL - JavaScript Version", "bright")
    this.printColored("    Công cụ An toàn Thông tin - Phiên bản JavaScript", "cyan")
    this.printColored("=" * 60, "cyan")
    console.log()
  }

  // Main menu
  showMenu() {
    this.printColored("\n📋 MENU CHÍNH:", "yellow")
    console.log("1. 💻 Thông tin hệ thống (System Info)")
    console.log("2. 🌐 Kiểm tra bảo mật website (Web Security)")
    console.log("3. 🔐 Hash & Mật khẩu (Hash & Password)")
    console.log("4. 🔒 Mã hóa / Giải mã (Encryption/Decryption)")
    console.log("5. 🌍 Network Tools")
    console.log("0. ❌ Thoát (Exit)")
    console.log()
  }

  // 1. System Information
  async getSystemInfo() {
    try {
      this.printColored("\n💻 THÔNG TIN HỆ THỐNG:", "green")
      console.log("-" * 40)

      // Basic system info
      console.log(`🖥️  Hệ điều hành: ${os.type()} ${os.release()}`)
      console.log(`🏗️  Kiến trúc: ${os.arch()}`)
      console.log(`💾 RAM tổng: ${(os.totalmem() / 1024 / 1024 / 1024).toFixed(2)} GB`)
      console.log(`💾 RAM trống: ${(os.freemem() / 1024 / 1024 / 1024).toFixed(2)} GB`)
      console.log(`⚡ CPU cores: ${os.cpus().length}`)
      console.log(`🏠 Hostname: ${os.hostname()}`)
      console.log(`👤 Username: ${os.userInfo().username}`)

      // Network interfaces
      const interfaces = os.networkInterfaces()
      this.printColored("\n🌐 Network Interfaces:", "cyan")

      for (const [name, addrs] of Object.entries(interfaces)) {
        if (addrs) {
          console.log(`\n📡 ${name}:`)
          addrs.forEach((addr) => {
            if (!addr.internal) {
              console.log(`   IP: ${addr.address}`)
              console.log(`   MAC: ${addr.mac}`)
              console.log(`   Family: ${addr.family}`)
            }
          })
        }
      }

      // Port scan
      await this.basicPortScan()
    } catch (error) {
      this.printColored(`❌ Lỗi: ${error.message}`, "red")
    }
  }

  // Basic port scan for localhost
  async basicPortScan() {
    this.printColored("\n🔍 Quét cổng cơ bản (localhost):", "yellow")
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3000, 3306, 5432, 8080]
    const openPorts = []

    for (const port of commonPorts) {
      try {
        await this.checkPort("localhost", port)
        openPorts.push(port)
      } catch (error) {
        // Port is closed
      }
    }

    if (openPorts.length > 0) {
      console.log(`✅ Cổng mở: ${openPorts.join(", ")}`)
    } else {
      console.log("🔒 Không tìm thấy cổng mở trong danh sách kiểm tra")
    }
  }

  // Check if port is open
  checkPort(host, port, timeout = 1000) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket()

      socket.setTimeout(timeout)

      socket.on("connect", () => {
        socket.destroy()
        resolve()
      })

      socket.on("timeout", () => {
        socket.destroy()
        reject(new Error("Timeout"))
      })

      socket.on("error", (err) => {
        socket.destroy()
        reject(err)
      })

      socket.connect(port, host)
    })
  }

  // 2. Web Security Check
  async webSecurityCheck() {
    try {
      const url = await this.getUserInput("🌐 Nhập URL để kiểm tra (ví dụ: https://example.com): ")

      if (!url) {
        this.printColored("❌ URL không hợp lệ!", "red")
        return
      }

      this.printColored(`\n🔍 Đang kiểm tra bảo mật cho: ${url}`, "yellow")
      console.log("-" * 50)

      // Import axios dynamically
      const axios = await import("axios").catch(() => null)
      if (!axios) {
        this.printColored("❌ Cần cài đặt axios: npm install axios", "red")
        return
      }

      const response = await axios.default.get(url, {
        timeout: 10000,
        validateStatus: () => true, // Accept all status codes
      })

      // Check HTTP headers
      this.checkSecurityHeaders(response.headers)

      // Check SSL/TLS
      if (url.startsWith("https://")) {
        await this.checkSSL(url)
      }

      // Check redirects
      this.checkRedirects(response)
    } catch (error) {
      this.printColored(`❌ Lỗi khi kiểm tra: ${error.message}`, "red")
    }
  }

  // Check security headers
  checkSecurityHeaders(headers) {
    this.printColored("\n🛡️  Kiểm tra HTTP Security Headers:", "green")

    const securityHeaders = {
      "x-frame-options": "X-Frame-Options",
      "content-security-policy": "Content-Security-Policy",
      "strict-transport-security": "Strict-Transport-Security (HSTS)",
      "x-content-type-options": "X-Content-Type-Options",
      "x-xss-protection": "X-XSS-Protection",
      "referrer-policy": "Referrer-Policy",
    }

    for (const [header, name] of Object.entries(securityHeaders)) {
      if (headers[header]) {
        this.printColored(`✅ ${name}: ${headers[header]}`, "green")
      } else {
        this.printColored(`❌ ${name}: Không có`, "red")
      }
    }
  }

  // Check SSL certificate
  async checkSSL(url) {
    try {
      this.printColored("\n🔒 Thông tin SSL/TLS:", "cyan")

      const hostname = new URL(url).hostname
      const { stdout } = await execAsync(
        `echo | openssl s_client -servername ${hostname} -connect ${hostname}:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer`,
      )

      console.log(stdout)
    } catch (error) {
      this.printColored(`⚠️  Không thể kiểm tra SSL: ${error.message}`, "yellow")
    }
  }

  // Check redirects
  checkRedirects(response) {
    this.printColored("\n🔄 Thông tin Response:", "cyan")
    console.log(`📊 Status Code: ${response.status}`)

    if (response.headers.location) {
      console.log(`🔗 Redirect to: ${response.headers.location}`)

      // Check for dangerous redirects
      const location = response.headers.location.toLowerCase()
      if (location.includes("javascript:") || location.includes("data:")) {
        this.printColored("⚠️  CẢNH BÁO: Redirect nguy hiểm phát hiện!", "red")
      }
    }
  }

  // 3. Hash & Password Tools
  async hashPasswordTools() {
    this.printColored("\n🔐 HASH & PASSWORD TOOLS:", "green")
    console.log("1. Tạo hash từ text")
    console.log("2. Kiểm tra hash với wordlist")
    console.log("3. Tạo mật khẩu ngẫu nhiên")

    const choice = await this.getUserInput("Chọn chức năng (1-3): ")

    switch (choice) {
      case "1":
        await this.generateHash()
        break
      case "2":
        await this.checkHashWordlist()
        break
      case "3":
        await this.generatePassword()
        break
      default:
        this.printColored("❌ Lựa chọn không hợp lệ!", "red")
    }
  }

  // Generate hash
  async generateHash() {
    try {
      const text = await this.getUserInput("📝 Nhập text cần hash: ")

      if (!text) {
        this.printColored("❌ Text không được để trống!", "red")
        return
      }

      this.printColored("\n🔐 Kết quả hash:", "cyan")
      console.log(`MD5:    ${crypto.createHash("md5").update(text).digest("hex")}`)
      console.log(`SHA1:   ${crypto.createHash("sha1").update(text).digest("hex")}`)
      console.log(`SHA256: ${crypto.createHash("sha256").update(text).digest("hex")}`)
      console.log(`SHA512: ${crypto.createHash("sha512").update(text).digest("hex")}`)
    } catch (error) {
      this.printColored(`❌ Lỗi: ${error.message}`, "red")
    }
  }

  // Check hash against wordlist
  async checkHashWordlist() {
    try {
      const hash = await this.getUserInput("🔍 Nhập hash cần kiểm tra: ")
      const wordlistPath = await this.getUserInput("📁 Nhập đường dẫn wordlist (để trống = tạo wordlist mẫu): ")

      let wordlist
      if (!wordlistPath) {
        // Create sample wordlist
        wordlist = ["password", "123456", "admin", "root", "test", "user", "guest"]
        this.printColored("📝 Sử dụng wordlist mẫu...", "yellow")
      } else {
        const content = await fs.readFile(wordlistPath, "utf8")
        wordlist = content
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line)
      }

      this.printColored(`\n🔍 Đang kiểm tra ${wordlist.length} từ...`, "yellow")

      // Detect hash type
      const hashType = this.detectHashType(hash)
      this.printColored(`🔍 Hash type phát hiện: ${hashType}`, "cyan")

      let found = false
      for (const word of wordlist) {
        const wordHash = crypto.createHash(hashType).update(word).digest("hex")
        if (wordHash === hash.toLowerCase()) {
          this.printColored(`✅ Tìm thấy: ${word}`, "green")
          found = true
          break
        }
      }

      if (!found) {
        this.printColored("❌ Không tìm thấy trong wordlist", "red")
      }
    } catch (error) {
      this.printColored(`❌ Lỗi: ${error.message}`, "red")
    }
  }

  // Detect hash type by length
  detectHashType(hash) {
    switch (hash.length) {
      case 32:
        return "md5"
      case 40:
        return "sha1"
      case 64:
        return "sha256"
      case 128:
        return "sha512"
      default:
        return "sha256" // default
    }
  }

  // Generate random password
  async generatePassword() {
    try {
      const length = (await this.getUserInput("📏 Nhập độ dài mật khẩu (mặc định 12): ")) || "12"
      const passwordLength = Number.parseInt(length)

      if (passwordLength < 4 || passwordLength > 128) {
        this.printColored("❌ Độ dài phải từ 4-128 ký tự!", "red")
        return
      }

      const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
      let password = ""

      for (let i = 0; i < passwordLength; i++) {
        const randomIndex = crypto.randomInt(0, charset.length)
        password += charset[randomIndex]
      }

      this.printColored(`\n🔑 Mật khẩu được tạo: ${password}`, "green")

      // Password strength check
      this.checkPasswordStrength(password)
    } catch (error) {
      this.printColored(`❌ Lỗi: ${error.message}`, "red")
    }
  }

  // Check password strength
  checkPasswordStrength(password) {
    let score = 0
    const checks = []

    if (password.length >= 8) {
      score += 1
      checks.push("✅ Độ dài >= 8")
    } else {
      checks.push("❌ Độ dài < 8")
    }

    if (/[a-z]/.test(password)) {
      score += 1
      checks.push("✅ Có chữ thường")
    } else {
      checks.push("❌ Không có chữ thường")
    }

    if (/[A-Z]/.test(password)) {
      score += 1
      checks.push("✅ Có chữ hoa")
    } else {
      checks.push("❌ Không có chữ hoa")
    }

    if (/[0-9]/.test(password)) {
      score += 1
      checks.push("✅ Có số")
    } else {
      checks.push("❌ Không có số")
    }

    if (/[^a-zA-Z0-9]/.test(password)) {
      score += 1
      checks.push("✅ Có ký tự đặc biệt")
    } else {
      checks.push("❌ Không có ký tự đặc biệt")
    }

    this.printColored("\n💪 Đánh giá độ mạnh:", "cyan")
    checks.forEach((check) => console.log(`   ${check}`))

    const strength = score <= 2 ? "Yếu" : score <= 3 ? "Trung bình" : score <= 4 ? "Mạnh" : "Rất mạnh"
    const color = score <= 2 ? "red" : score <= 3 ? "yellow" : score <= 4 ? "green" : "bright"
    this.printColored(`📊 Điểm: ${score}/5 - ${strength}`, color)
  }

  // 4. Encryption/Decryption
  async encryptionDecryption() {
    this.printColored("\n🔒 MÃ HÓA / GIẢI MÃ:", "green")
    console.log("1. Mã hóa text")
    console.log("2. Giải mã text")
    console.log("3. Tạo key ngẫu nhiên")

    const choice = await this.getUserInput("Chọn chức năng (1-3): ")

    switch (choice) {
      case "1":
        await this.encryptText()
        break
      case "2":
        await this.decryptText()
        break
      case "3":
        await this.generateKey()
        break
      default:
        this.printColored("❌ Lựa chọn không hợp lệ!", "red")
    }
  }

  // Encrypt text using AES-256-CBC
  async encryptText() {
    try {
      const text = await this.getUserInput("📝 Nhập text cần mã hóa: ")
      const password = await this.getUserInput("🔑 Nhập password: ")

      if (!text || !password) {
        this.printColored("❌ Text và password không được để trống!", "red")
        return
      }

      // Generate salt and IV
      const salt = crypto.randomBytes(16)
      const iv = crypto.randomBytes(16)

      // Derive key from password
      const key = crypto.pbkdf2Sync(password, salt, 10000, 32, "sha256")

      // Encrypt
      const cipher = crypto.createCipheriv("aes-256-cbc", key, iv)
      let encrypted = cipher.update(text, "utf8", "hex")
      encrypted += cipher.final("hex")

      // Combine salt + iv + encrypted
      const result = salt.toString("hex") + ":" + iv.toString("hex") + ":" + encrypted

      this.printColored("\n🔒 Kết quả mã hóa:", "green")
      console.log(result)

      // Save to file option
      const saveFile = await this.getUserInput("\n💾 Lưu vào file? (y/n): ")
      if (saveFile.toLowerCase() === "y") {
        const filename = `encrypted_${Date.now()}.txt`
        await fs.writeFile(filename, result)
        this.printColored(`✅ Đã lưu vào file: ${filename}`, "green")
      }
    } catch (error) {
      this.printColored(`❌ Lỗi: ${error.message}`, "red")
    }
  }

  // Decrypt text
  async decryptText() {
    try {
      const encryptedText = await this.getUserInput("🔒 Nhập text đã mã hóa: ")
      const password = await this.getUserInput("🔑 Nhập password: ")

      if (!encryptedText || !password) {
        this.printColored("❌ Text và password không được để trống!", "red")
        return
      }

      // Parse encrypted data
      const parts = encryptedText.split(":")
      if (parts.length !== 3) {
        this.printColored("❌ Format dữ liệu mã hóa không hợp lệ!", "red")
        return
      }

      const salt = Buffer.from(parts[0], "hex")
      const iv = Buffer.from(parts[1], "hex")
      const encrypted = parts[2]

      // Derive key from password
      const key = crypto.pbkdf2Sync(password, salt, 10000, 32, "sha256")

      // Decrypt
      const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv)
      let decrypted = decipher.update(encrypted, "hex", "utf8")
      decrypted += decipher.final("utf8")

      this.printColored("\n🔓 Kết quả giải mã:", "green")
      console.log(decrypted)
    } catch (error) {
      this.printColored(`❌ Lỗi giải mã: ${error.message}`, "red")
    }
  }

  // Generate random key
  async generateKey() {
    try {
      const keySize = (await this.getUserInput("📏 Nhập kích thước key (16/24/32 bytes, mặc định 32): ")) || "32"
      const size = Number.parseInt(keySize)

      if (![16, 24, 32].includes(size)) {
        this.printColored("❌ Kích thước key phải là 16, 24 hoặc 32 bytes!", "red")
        return
      }

      const key = crypto.randomBytes(size)

      this.printColored("\n🔑 Key được tạo:", "green")
      console.log(`Hex: ${key.toString("hex")}`)
      console.log(`Base64: ${key.toString("base64")}`)

      // Save key option
      const saveKey = await this.getUserInput("\n💾 Lưu key vào file? (y/n): ")
      if (saveKey.toLowerCase() === "y") {
        const filename = `key_${Date.now()}.txt`
        await fs.writeFile(filename, `Hex: ${key.toString("hex")}\nBase64: ${key.toString("base64")}`)
        this.printColored(`✅ Đã lưu key vào file: ${filename}`, "green")
      }
    } catch (error) {
      this.printColored(`❌ Lỗi: ${error.message}`, "red")
    }
  }

  // 5. Network Tools
  async networkTools() {
    this.printColored("\n🌍 NETWORK TOOLS:", "green")
    console.log("1. Ping host")
    console.log("2. Traceroute")
    console.log("3. DNS lookup")
    console.log("4. Port scan")

    const choice = await this.getUserInput("Chọn chức năng (1-4): ")

    switch (choice) {
      case "1":
        await this.pingHost()
        break
      case "2":
        await this.traceroute()
        break
      case "3":
        await this.dnsLookup()
        break
      case "4":
        await this.portScan()
        break
      default:
        this.printColored("❌ Lựa chọn không hợp lệ!", "red")
    }
  }

  // Ping host
  async pingHost() {
    try {
      const host = await this.getUserInput("🌐 Nhập host để ping: ")

      if (!host) {
        this.printColored("❌ Host không được để trống!", "red")
        return
      }

      this.printColored(`\n🏓 Đang ping ${host}...`, "yellow")

      const isWindows = os.platform() === "win32"
      const pingCmd = isWindows ? `ping -n 4 ${host}` : `ping -c 4 ${host}`

      const { stdout, stderr } = await execAsync(pingCmd)

      if (stderr) {
        this.printColored(`❌ Lỗi: ${stderr}`, "red")
      } else {
        console.log(stdout)
      }
    } catch (error) {
      this.printColored(`❌ Lỗi ping: ${error.message}`, "red")
    }
  }

  // Traceroute
  async traceroute() {
    try {
      const host = await this.getUserInput("🌐 Nhập host để traceroute: ")

      if (!host) {
        this.printColored("❌ Host không được để trống!", "red")
        return
      }

      this.printColored(`\n🛤️  Đang traceroute đến ${host}...`, "yellow")

      const isWindows = os.platform() === "win32"
      const traceCmd = isWindows ? `tracert ${host}` : `traceroute ${host}`

      const { stdout, stderr } = await execAsync(traceCmd)

      if (stderr && !stdout) {
        this.printColored(`❌ Lỗi: ${stderr}`, "red")
      } else {
        console.log(stdout)
      }
    } catch (error) {
      this.printColored(`❌ Lỗi traceroute: ${error.message}`, "red")
    }
  }

  // DNS lookup
  async dnsLookup() {
    try {
      const { promises: dns } = await import("node:dns")
      const host = await this.getUserInput("🌐 Nhập domain để lookup: ")

      if (!host) {
        this.printColored("❌ Domain không được để trống!", "red")
        return
      }

      this.printColored(`\n🔍 DNS Lookup cho ${host}:`, "cyan")

      try {
        // A records
        const addresses = await dns.resolve4(host)
        this.printColored("📍 A Records:", "green")
        addresses.forEach((addr) => console.log(`   ${addr}`))
      } catch (error) {
        this.printColored("❌ Không tìm thấy A records", "red")
      }

      try {
        // AAAA records
        const addresses6 = await dns.resolve6(host)
        this.printColored("📍 AAAA Records:", "green")
        addresses6.forEach((addr) => console.log(`   ${addr}`))
      } catch (error) {
        this.printColored("❌ Không tìm thấy AAAA records", "yellow")
      }

      try {
        // MX records
        const mxRecords = await dns.resolveMx(host)
        this.printColored("📧 MX Records:", "green")
        mxRecords.forEach((mx) => console.log(`   ${mx.priority} ${mx.exchange}`))
      } catch (error) {
        this.printColored("❌ Không tìm thấy MX records", "yellow")
      }
    } catch (error) {
      this.printColored(`❌ Lỗi DNS lookup: ${error.message}`, "red")
    }
  }

  // Port scan
  async portScan() {
    try {
      const host = await this.getUserInput("🌐 Nhập host để scan: ")
      const portRange = await this.getUserInput("🔢 Nhập range port (ví dụ: 1-100, mặc định: common ports): ")

      if (!host) {
        this.printColored("❌ Host không được để trống!", "red")
        return
      }

      let ports
      if (portRange && portRange.includes("-")) {
        const [start, end] = portRange.split("-").map((p) => Number.parseInt(p.trim()))
        ports = Array.from({ length: end - start + 1 }, (_, i) => start + i)
      } else {
        // Common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
      }

      this.printColored(`\n🔍 Đang scan ${ports.length} ports trên ${host}...`, "yellow")

      const openPorts = []
      const maxConcurrent = 50 // Limit concurrent connections

      for (let i = 0; i < ports.length; i += maxConcurrent) {
        const batch = ports.slice(i, i + maxConcurrent)
        const promises = batch.map((port) =>
          this.checkPort(host, port, 2000)
            .then(() => port)
            .catch(() => null),
        )

        const results = await Promise.all(promises)
        openPorts.push(...results.filter((port) => port !== null))

        // Progress indicator
        process.stdout.write(`\r🔍 Tiến độ: ${Math.min(i + maxConcurrent, ports.length)}/${ports.length}`)
      }

      console.log() // New line after progress

      if (openPorts.length > 0) {
        this.printColored(`\n✅ Tìm thấy ${openPorts.length} cổng mở:`, "green")
        openPorts
          .sort((a, b) => a - b)
          .forEach((port) => {
            const service = this.getServiceName(port)
            console.log(`   ${port}/tcp - ${service}`)
          })
      } else {
        this.printColored("\n🔒 Không tìm thấy cổng mở nào", "yellow")
      }
    } catch (error) {
      this.printColored(`❌ Lỗi port scan: ${error.message}`, "red")
    }
  }

  // Get service name for common ports
  getServiceName(port) {
    const services = {
      21: "FTP",
      22: "SSH",
      23: "Telnet",
      25: "SMTP",
      53: "DNS",
      80: "HTTP",
      110: "POP3",
      135: "RPC",
      139: "NetBIOS",
      143: "IMAP",
      443: "HTTPS",
      993: "IMAPS",
      995: "POP3S",
      1723: "PPTP",
      3306: "MySQL",
      3389: "RDP",
      5432: "PostgreSQL",
      5900: "VNC",
      8080: "HTTP-Alt",
    }
    return services[port] || "Unknown"
  }

  // Main program loop
  async run() {
    this.printBanner()

    while (true) {
      try {
        this.showMenu()
        const choice = await this.getUserInput("🎯 Chọn chức năng (0-5): ")

        switch (choice) {
          case "1":
            await this.getSystemInfo()
            break
          case "2":
            await this.webSecurityCheck()
            break
          case "3":
            await this.hashPasswordTools()
            break
          case "4":
            await this.encryptionDecryption()
            break
          case "5":
            await this.networkTools()
            break
          case "0":
            this.printColored("\n👋 Cảm ơn bạn đã sử dụng Security Tool!", "cyan")
            this.rl.close()
            process.exit(0)
            break
          default:
            this.printColored("❌ Lựa chọn không hợp lệ! Vui lòng chọn 0-5.", "red")
        }

        // Wait for user to continue
        await this.getUserInput("\n⏸️  Nhấn Enter để tiếp tục...")
      } catch (error) {
        this.printColored(`❌ Lỗi không mong muốn: ${error.message}`, "red")
        await this.getUserInput("\n⏸️  Nhấn Enter để tiếp tục...")
      }
    }
  }
}

// Run the tool
if (import.meta.url === `file://${process.argv[1]}`) {
  const tool = new SecurityTool()
  tool.run().catch(console.error)
}

export default SecurityTool
