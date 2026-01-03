<h1 align="center">FileShare v2.0</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20Linux-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Security-Enhanced-red?style=for-the-badge&logo=security">
</p>

<p align="center">
  <b>📁 Secure File Sharing Server with Enhanced Security</b>
</p>

---

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| **🔐 HTTPS** | Self-signed SSL certificate |
| **🎫 Access Token** | Random token untuk autentikasi |
| **🛡️ Rate Limiting** | Block IP setelah 5x gagal login (15 menit) |
| **📋 IP Whitelist** | Hanya IP tertentu yang bisa akses |
| **🔍 Network Scanner** | Scan jaringan untuk pilih IP whitelist |
| **⏱️ Session Timeout** | Auto-stop setelah waktu tertentu |

---

## ⚡ Instalasi

```bash
git clone https://github.com/emRival/cli-local-share.git
cd cli-local-share
pip3 install --break-system-packages -r requirements.txt
python3 run.py
```

---

## 🎮 Penggunaan

```bash
python3 run.py
```

**Setup wizard akan memandu Anda:**

1. **Directory** - Folder yang akan di-share
2. **Port** - Port server (default: 8080)
3. **HTTPS** - Aktifkan enkripsi SSL
4. **Password** - Password untuk akses
5. **Token** - Generate random access token
6. **Timeout** - Durasi session
7. **IP Whitelist** - Pilih metode:
   - Manual: Input IP satu per satu
   - Scan: Scan jaringan dan pilih dari list
   - Both: Kombinasi keduanya

---

## 🔑 Autentikasi

Ada 3 cara login:

1. **Password only**: Masukkan password saja
2. **Token only**: Masukkan token sebagai password
3. **Combined**: Masukkan `password:token`

---

## 📸 Preview

```
╔═══════════════════════════════════════════════════════════╗
║   ███████╗██╗██╗     ███████╗                             ║
║   SHARE v2.0 - Secure File Sharing                        ║
║   🔒 HTTPS • 🛡️ Rate Limit • 📋 IP Whitelist             ║
╚═══════════════════════════════════════════════════════════╝

📡 FileShare Server Running  |  ⏱️ 29m 45s  |  🛡️ 3 whitelisted

┌─ 📋 Info ────────────────────────────────────────────────┐
│  🌐 URL        https://192.168.1.100:8080                │
│  🔐 Protocol   🔒 HTTPS                                   │
│  🔑 Password   ********                                   │
│  🎫 Token      abc123def456...                            │
│  📋 Whitelist  3 IPs                                      │
│  🚫 Blocked    0 IPs                                      │
└──────────────────────────────────────────────────────────┘
```

---

## 📄 Lisensi

MIT License
