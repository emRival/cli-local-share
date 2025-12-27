<h1 align="center">Scam Check</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Debian%20%7C%20Ubuntu-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
</p>

<p align="center">
  <b>Alat investigasi berbasis CLI untuk mengidentifikasi nomor WhatsApp yang berpotensi scammer</b>
</p>

---

## 📖 Tentang

**Scam Check** adalah alat penyelidikan berbasis CLI yang memanfaatkan teknik perhitungan berdasarkan data yang sudah dikumpulkan. Berfungsi untuk mengidentifikasi apakah sebuah nomor WhatsApp termasuk golongan scammer atau aman sebelum memulai transaksi.

> *"Sedia Payung Sebelum Hujan"* - Gunakan Scam Check sebelum bertransaksi!

---

## 🔎 Data yang Dikumpulkan

| Kategori | Informasi |
|----------|-----------|
| 📍 Profil | Foto profile WhatsApp |
| 🧪 Umum | Nomor HP dan informasi dasar |
| 🧾 Analisis | Hasil perhitungan algoritma untuk investigasi |
| 🕵️ Mendalam | Nama, tanggal lahir, pendidikan, lokasi |
| ☠️ Sangat Dalam | Nama lengkap, lokasi terdekat, gender, detail kota/kabupaten |

---

## 🧩 Fitur Utama

### OSINT Nomor Handphone
- ✅ Analisis Nomor Handphone (Search)
- ✅ Show Tag Victim (Detail Tag)
- ✅ Check Nama E-Wallet
- ✅ Check Komentar pada Nomor
- ✅ Doxing Nomor (Lokasi, Nama, Gender, Tanggal Lahir, BPJS, dll)

### Other OSINT
- 📦 SPX Tracking
- 👤 OSINT Name
- 🚗 Lookup Plat Kendaraan
- 🎓 Search Mahasiswa/Dosen (Nama & ID)
- 📱 Lookup IMEI
- 💼 Search Pekerja via NIK/Nama

---

## ⚡ Instalasi

### Termux (Android)
```bash
pkg update && pkg upgrade
pkg install git make just -y
git clone https://github.com/emRival/scam-check.git
cd scam-check
make install
just run
```

### Debian / Ubuntu
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git make python3 python3-pip -y
git clone https://github.com/emRival/scam-check.git
cd scam-check
make install
python3 src/app.py
```

---

## 🎮 Penggunaan

### Ukuran Layar yang Disarankan
| Mode | Ukuran |
|------|--------|
| Portrait | x: 101, y: 35 |
| Landscape | x: 181, y: 70 |

### Kontrol
- Gunakan **kursor / tombol panah** untuk navigasi
- Gunakan **keyboard** untuk input
- Cubit layar untuk mengatur ukuran (Termux)

---

## 🔧 Troubleshooting

Jika mengalami error Python:
```bash
make fix
make install
```

---

## � Keamanan

Script ini dilengkapi dengan:
- Anti MITM
- Obfuscate versi 10

---

## 📺 Tutorial

[![YouTube Tutorial](https://img.shields.io/badge/YouTube-Tutorial-red?style=for-the-badge&logo=youtube)](https://youtu.be/cMBJ_GvPey4)

---

## 📄 Lisensi

MIT License - Lihat file [LICENSE](LICENSE) untuk detail.
