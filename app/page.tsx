export default function HomePage() {
  return (
    <main className="min-h-screen bg-background flex items-center justify-center p-8">
      <div className="max-w-4xl mx-auto text-center space-y-8">
        <div className="space-y-4">
          <h1 className="text-4xl font-bold text-foreground">🔒 Python Security Tool</h1>
          <p className="text-xl text-muted-foreground">Công cụ An toàn Thông tin - Information Security Tool</p>
        </div>

        <div className="grid md:grid-cols-2 gap-6 mt-12">
          <div className="bg-card p-6 rounded-lg border">
            <h2 className="text-2xl font-semibold mb-4 text-green-600">🐍 Python Version</h2>
            <div className="space-y-2 text-left">
              <p>• System Information</p>
              <p>• Web Security Check</p>
              <p>• Hash & Password Tools</p>
              <p>• Encryption/Decryption</p>
              <p>• Network Tools</p>
            </div>
            <div className="mt-4 p-3 bg-muted rounded text-sm">
              <code>python scripts/security_tool.py</code>
            </div>
          </div>

          <div className="bg-card p-6 rounded-lg border">
            <h2 className="text-2xl font-semibold mb-4 text-blue-600">🟨 JavaScript Version</h2>
            <div className="space-y-2 text-left">
              <p>• System Information</p>
              <p>• Web Security Check</p>
              <p>• Hash & Password Tools</p>
              <p>• Encryption/Decryption</p>
              <p>• Network Tools</p>
            </div>
            <div className="mt-4 p-3 bg-muted rounded text-sm">
              <code>node scripts/security_tool.js</code>
            </div>
          </div>
        </div>

        <div className="bg-yellow-50 dark:bg-yellow-900/20 p-6 rounded-lg border border-yellow-200 dark:border-yellow-800">
          <h3 className="text-lg font-semibold text-yellow-800 dark:text-yellow-200 mb-2">⚠️ Lưu ý quan trọng</h3>
          <p className="text-yellow-700 dark:text-yellow-300">
            Các tool này chỉ dùng cho mục đích học tập và kiểm tra bảo mật hợp pháp. Không sử dụng để tấn công hoặc xâm
            nhập trái phép vào hệ thống.
          </p>
        </div>

        <div className="space-y-4">
          <h3 className="text-xl font-semibold">📋 Cách sử dụng</h3>
          <div className="grid md:grid-cols-2 gap-4 text-sm">
            <div className="bg-muted p-4 rounded">
              <h4 className="font-semibold mb-2">Python:</h4>
              <code className="block">pip install requests cryptography scapy</code>
              <code className="block mt-1">python scripts/security_tool.py</code>
            </div>
            <div className="bg-muted p-4 rounded">
              <h4 className="font-semibold mb-2">JavaScript:</h4>
              <code className="block">npm install</code>
              <code className="block mt-1">node scripts/security_tool.js</code>
            </div>
          </div>
        </div>
      </div>
    </main>
  )
}
