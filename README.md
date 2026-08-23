# 🔍 BREACH INTEL — OSINT & Data Breach Intelligence

Tool pencarian data bocor (OSINT) dengan tema hacker terminal. Mendukung pencarian **Email, Telepon, Domain, Nama** + korelasi multi-parameter.

![Version](https://img.shields.io/badge/version-2.0-green) ![Node](https://img.shields.io/badge/node-22+-brightgreen)

## ✨ Fitur

### 📧 Email Breach Check (7 sumber)
| Sumber | Data | Key |
|--------|------|-----|
| XposedOrNot | Breach detail + analytics | Gratis |
| HackMyIP | Breach count + risk score | Gratis |
| LeakCheck Pro | Breach + **password terexpos** | Berbayar |
| HaveIBeenPwned | Database breach terlengkap | Berbayar |
| EmailRep.io | Reputasi email | Gratis (limit) |
| Gravatar | Profil publik terkait | Gratis |
| Domain Check | Validitas MX record | Gratis |

### 📱 Phone Lookup Maksimal
- Carrier & lokasi real (NumVerify, AbstractAPI)
- Multi-dork Google (8 query) via Serper
- Fallback DuckDuckGo gratis
- Identifikasi bisnis via Google Places
- Ekstraksi akun sosmed & lokasi dari jejak publik
- Cache 30 menit (hemat kuota)
- Export laporan `.txt`

### 👤 Nama / Lokasi / TTL
Serper dorking ke dump publik (pastebin, ext:sql/txt/xls) + sosmed.

### 🔗 Cross-Reference Panel
Tombol deep-OSINT otomatis: Truecaller, Sync.me, Epieos, Holehe, WhatsMyName, Kredibel, Shodan, crt.sh, dll.

### 👁️ Watchlist + Notifikasi Telegram
Pantau target otomatis tiap hari jam 08:00. Breach baru → notif Telegram.

### 📦 Batch Lookup
Tempel daftar email/nomor (satu per baris) → scan massal → export hasil.

### 🔐 Keamanan
- Login session 24 jam (cookie secure)
- Rate limit login: 5 gagal/15 menit (anti brute force)
- Rate limit search: 30 request/15 menit

## 🚀 Menjalankan

```bash
npm install
npm start          # atau: node server.js
```

Buka `http://localhost:3000` → login dengan `ADMIN_USERNAME` / `ADMIN_PASSWORD`.

## ⚙️ Konfigurasi (.env)

```env
PORT=3000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=passwordkuat123!
SESSION_SECRET=string-acak-panjang

# API Keys (opsional — fitur terkait aktif jika diisi)
SERPER_API_KEY=            # https://serper.dev (gratis 2500/bln)
NUMVERIFY_API_KEY=         # https://numverify.com (gratis 100/bln)
ABSTRACTAPI_PHONE_KEY=     # https://abstractapi.com (gratis 250/bln)
LEAKCHECK_API_KEY=         # https://leakcheck.io (berbayar, fitur password)
HIBP_API_KEY=              # https://haveibeenpwned.com/API/Key ($3.5/bln)

# Notifikasi watchlist (opsional)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Tanpa key apapun pun app tetap jalan (5 sumber email gratis + phone lookup dasar).

## ☁️ Deploy

### Render / Railway / VPS
1. Push repo ke GitHub
2. Buat Web Service → Start command: `node server.js`
3. Set Environment Variables (lihat render.yaml untuk daftar lengkap)
4. HTTPS wajib untuk PWA install di HP

### PWA (Android/iPhone)
Buka URL HTTPS dari Chrome HP → menu ⋮ → "Tambahkan ke layar utama".

## 🛠️ Teknologi

Node.js 22 · Express · SQLite (`node:sqlite` bawaan) · Vanilla JS frontend · Capacitor-ready

## ⚠️ Disclaimer

Gunakan hanya untuk keperluan sah: audit keamanan data sendiri, riset, edukasi.
