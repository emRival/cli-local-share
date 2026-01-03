<h1 align="center">FileShare v2.5</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20Linux-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Security-Enhanced-red?style=for-the-badge&logo=security">
</p>

<p align="center">
<p align="center">
  <b>📁 Share File Lokal Lebih Aman, Cepat, & Stylish Langsung dari Terminal.</b>
</p>

---

<!-- Placeholder untuk GIF (Wajib ditaruh sini biar user langsung lihat) -->
<div align="center">
  <video src="assets/demo.mp4" width="100%" controls autoplay muted></video>
</div>

---

## ✨ Tentang Aplikasi

**FileShare v2.5** adalah aplikasi CLI (Command Line Interface) yang memudahkan Anda berbagi file di jaringan lokal (WiFi/LAN) secara aman dan fleksibel.

Kelebihan utama aplikasi ini adalah **Kendali Penuh di Tangan Anda**:
*   📂 **Pilih Folder Bebas**: Tentukan folder mana saja yang ingin di-share, tidak terpaku pada direktori saat ini.
*   ⚙️ **Konfigurasi Mudah**: Atur Port, IP Whitelist, dan Timeout sesi sesuai kebutuhan.
*   🔒 **Keamanan Terjamin**: Opsi enkripsi HTTPS dan berbagai metode login (Password/Token) yang bisa diatur saat *start-up*.
*   ✅ **Tanpa Ribet**: Semua pengaturan dilakukan lewat panduan interaktif (Wizard) yang mudah dipahami.

### 🌟 Fitur Unggulan

**1. ⏱️ Atur Waktu Akses (Session Timeout)**
> Tidak mau server nyala terus? Anda bisa set timer (misal: 10 menit). Setelah waktu habis, server **otomatis mati**. Aman, hemat resource, dan anti lupa!

**2. 🔄 Auto-Update via Terminal**
> Ada fitur baru? Cukup pilih menu **`Check for Updates`** di dalam aplikasi, dan *Boom!* aplikasi langsung ter-update ke versi terbaru tanpa ribet git pull manual.

**3. 🛡️ Keamanan Level "Paranoia"**
> *   **HTTPS Enkripsi**: Data aman dari intip-intip tetangga.
> *   **Smart Blocking**: Salah password 5x? IP langsung diblokir otomatis.
> *   **Strict Whitelist**: Mode eksklusif di mana HANYA IP teman Anda yang bisa akses.
> *   **Secure Token**: Login instan tanpa password panjang, cukup pakai link token.

**4. 💻 UI yang Memanjakan Mata**
> *   **Terminal Dashboard**: Tui (Text UI) ala hacker yang menampilkan log *access* & *security* secara live.
> *   **Web Interface**: File browser di browser HP/Laptop lawan bicara tampil modern, responsif (Dark Mode ready), dan user-friendly.

---

## ⚡ Cara Install (Paling Gampang)

Cukup **Copy & Paste** mantra ini di terminal (Linux/Mac/Termux):

```bash
curl -sL https://raw.githubusercontent.com/emRival/cli-local-share/main/install.sh | bash
```

Selesai! Langsung jalankan aplikasinya dengan mengetik:
```bash
sharecli
```

*(Opsional)* **Cara Manual (Git Clone)**:
```bash
git clone https://github.com/emRival/cli-local-share.git
cd cli-local-share
pip3 install .
sharecli
```

---

## 📸 Gallery

### 🖼️ Tampilan Aplikasi
| **Terminal Dashboard** | **Web Interface (Mobile)** |
|:---:|:---:|
| ![Terminal Dashboard](assets/terminal.png) | ![Web Interface (Mobile)](assets/web.png) |

---

## 🎮 Panduan Singkat

Saat menjalankan `sharecli`, Anda akan disambut oleh Setup Wizard yang interaktif:

1.  **Pilih Folder**: Bisa browse folder langsung di terminal.
2.  **Set Port**: Default 8080 (bisa diganti sesuka hati).
3.  **Mode Keamanan**: Pilih password sendiri, token acak, atau tanpa password.
4.  **Fitur Tambahan**: Izinkan orang lain **Upload** atau **Hapus** file (Opsional).

---

## 📄 Lisensi

MIT License - Gratis, Open Source, dan Bebas Modifikasi.
