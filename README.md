<h1 align="center">Scam Check v2</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Debian%20%7C%20Ubuntu-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
</p>

<p align="center">
  <b>🔍 OSINT Phone Lookup Tool - Verifikasi nomor sebelum transaksi</b>
</p>

---

## 📖 Tentang

**Scam Check** adalah alat OSINT berbasis CLI untuk membantu verifikasi nomor telepon sebelum melakukan transaksi online. Alat ini memberikan informasi tentang operator, lokasi, dan format nomor untuk membantu Anda bertransaksi dengan lebih aman.

> *"Sedia Payung Sebelum Hujan"* 🌂

---

## 🧩 Fitur

| Fitur | Deskripsi |
|-------|-----------|
| 📱 **Phone Lookup** | Cek info carrier, lokasi, format nomor |
| 💳 **E-Wallet Check** | Cek registrasi e-wallet (demo mode) |
| 🌍 **Format Konversi** | Konversi ke format E164, International, National |

---

## ⚡ Instalasi

### Termux (Android)
```bash
pkg update && pkg upgrade
pkg install git python python-pip
git clone https://github.com/emRival/scam-check.git
cd scam-check
pip install -r requirements.txt
python run.py
```

### Debian / Ubuntu
```bash
apt update && apt upgrade -y
apt install git python3 python3-pip -y
git clone https://github.com/emRival/scam-check.git
cd scam-check
pip3 install --break-system-packages -r requirements.txt
python3 run.py
```

---

## 🎮 Penggunaan

```bash
# Cara 1: Langsung
python3 run.py

# Cara 2: Dengan Make
make install
make run

# Cara 3: Dengan Just (jika terinstall)
just install
just run
```

---

## 📸 Screenshot

```
╔═══════════════════════════════════════════════════════════════╗
║   ███████╗ ██████╗ █████╗ ███╗   ███╗                         ║
║   ██╔════╝██╔════╝██╔══██╗████╗ ████║                         ║
║   ███████╗██║     ███████║██╔████╔██║                         ║
║   ╚════██║██║     ██╔══██║██║╚██╔╝██║                         ║
║   ███████║╚██████╗██║  ██║██║ ╚═╝ ██║                         ║
║   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝                         ║
║   CHECK - OSINT Phone Lookup Tool                              ║
╚═══════════════════════════════════════════════════════════════╝

? Pilih menu:
❯ 📱 Phone Lookup - Cek informasi nomor HP
  💳 E-Wallet Check - Cek nama e-wallet
  ℹ️  About - Tentang aplikasi
  🚪 Exit - Keluar
```

---

## 🔒 Disclaimer

Tool ini hanya untuk tujuan **edukasi dan verifikasi**. Gunakan dengan bijak dan bertanggung jawab. Kami tidak bertanggung jawab atas penyalahgunaan tool ini.

---

## 📄 Lisensi

MIT License - Lihat file [LICENSE](LICENSE) untuk detail.
