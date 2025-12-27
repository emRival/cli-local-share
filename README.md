<h1 align="center">FileShare</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20Linux-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white">
</p>

<p align="center">
  <b>📁 Simple File Sharing Server with Password Protection</b>
</p>

---

## ✨ Fitur

| Fitur | Deskripsi |
|-------|-----------|
| 📁 **File Sharing** | Share folder via HTTP, bisa diakses dari browser |
| 🔐 **Password Protection** | Lindungi akses dengan password |
| ⏱️ **Session Timeout** | Auto-stop setelah waktu tertentu |
| 📱 **QR Code** | Scan untuk akses cepat dari HP |
| 📊 **Live Log** | Lihat siapa yang mengakses secara real-time |
| 🎨 **UI Interaktif** | Tampilan CLI yang menarik |

---

## ⚡ Instalasi

```bash
# Clone repository
git clone https://github.com/emRival/scam-check.git
cd scam-check

# Install dependencies
pip3 install --break-system-packages -r requirements.txt

# Jalankan
python3 run.py
```

---

## 🎮 Penggunaan

```bash
python3 run.py
```

Lalu ikuti prompt:
1. **Directory** - Folder yang ingin di-share (default: current directory)
2. **Port** - Port server (default: 8080)
3. **Password** - Password untuk akses (opsional)
4. **Timeout** - Berapa menit server aktif (default: 30 menit)

---

## 📸 Preview

```
╔═══════════════════════════════════════════════════════════╗
║   ███████╗██╗██╗     ███████╗                             ║
║   █████╗  ██║██║     █████╗                               ║
║   ██║     ██║███████╗███████╗                             ║
║   SHARE - Simple File Sharing with Password               ║
╚═══════════════════════════════════════════════════════════╝

📡 FileShare Server Running  |  ⏱️ Remaining: 29m 45s

┌─ 📋 Server Info ─────────────────────────────────────────┐
│  🌐 URL        http://192.168.1.100:8080                 │
│  📁 Directory  /home/user/shared                          │
│  🔐 Password   mypassword                                 │
│  ⏱️  Timeout   30 menit                                   │
└──────────────────────────────────────────────────────────┘
```

---

## 🔒 Keamanan

- Password menggunakan HTTP Basic Auth
- Session timeout untuk auto-stop
- Akses log untuk monitoring

---

## 📄 Lisensi

MIT License
