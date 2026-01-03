<h1 align="center">FileShare v2.5</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20Linux-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Security-Enhanced-red?style=for-the-badge&logo=security">
</p>

<p align="center">
  <b>📁 Secure File Sharing Server with Enhanced Security</b>
</p>

---

## ✨ Features

### 🛡️ Keamanan (Security)
*   **HTTPS Enkripsi**: Mengamankan transfer data dengan Self-signed SSL.
*   **Smart Rate Limiting**: Memblokir IP yang gagal login 5x berturut-turut.
*   **IP Whitelist**: Batasi akses hanya untuk device tertentu (bisa scan jaringan).
*   **Token Authentication**: Login cepat menggunakan secure token random.

### 💻 Interface
*   **CLI Dashboard**: Monitoring traffic real-time langsung dari terminal.
*   **Live Logs**: Lihat siapa yang download/upload/delete file secara detik itu juga.
*   **Responsive Web UI**: Tampilan web yang modern, support Dark Mode, dan nyaman di HP.

### 🚀 Performa & Tools
*   **No Dependencies Hell**: Hanya butuh 1 library (`rich`) untuk jalan.
*   **Upload & Delete**: Izinkan user upload atau hapus file (bisa diatur).
*   **Zip Download**: Download satu folder sekaligus dalam bentuk ZIP.

---

## ⚡ Instalasi

Cukup copas mantera ini di terminal Anda:

```bash
curl -sL https://raw.githubusercontent.com/emRival/cli-local-share/main/install.sh | bash
```

Setelah selesai, jalankan aplikasi dengan:
```bash
sharecli
```

---

## 📸 Gallery

<!-- Tempatkan screenshot di sini -->
> *Tambahkan screenshot CLI Dashboard di sini*

> *Tambahkan screenshot Web UI di HP di sini*

---

## 🎮 Cara Pakai

Saat pertama kali dijalankan (`sharecli`), setup wizard akan memandu Anda:
1.  Pilih folder yang mau di-share.
2.  Tentukan Port (default 8080).
3.  Aktifkan HTTPS/HTTP.
4.  Pilih metode login (Password / Token).

---

## 📄 Lisensi

MIT License - Bebas digunakan dan dimodifikasi.
