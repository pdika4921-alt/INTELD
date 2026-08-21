# 🔍 BREACH INTEL — Data Breach Intelligence Tool

Tools personal untuk cek kebocoran data (email, nama, telepon, domain).

## ⚡ Cara Jalankan

```bash
# 1. Install dependencies
npm install

# 2. Konfigurasi API key
cp .env.example .env
# Edit .env dan isi API key

# 3. Jalankan server
node server.js

# 4. Buka browser
# http://localhost:3000
```

## 🔑 Daftar API (Semua Ada Free Tier)

| API | Kegunaan | Free Tier | Link Daftar |
|-----|----------|-----------|-------------|
| HaveIBeenPwned | Email breach | 30 hari trial | https://haveibeenpwned.com/API/Key |
| EmailRep.io | Reputasi email | Ya | https://emailrep.io/key |
| LeakCheck | Email/phone/name | 10 req/hari | https://leakcheck.io/ |
| Hunter.io | Domain intel | 25 req/bulan | https://hunter.io/api |
| Shodan | Port/CVE exposure | Ya | https://account.shodan.io/ |

## 📁 Struktur File

```
breach-intel/
├── server.js           ← Server Express utama
├── database.js         ← Setup SQLite
├── services/
│   └── breachService.js ← Logic semua API
├── public/
│   └── index.html      ← UI web
├── data/               ← Database SQLite (auto dibuat)
├── .env.example        ← Template konfigurasi
└── README.md
```

## ⚠️ Disclaimer
Tools ini hanya untuk keperluan personal yang legal:
- Cek data diri sendiri
- Audit keamanan domain/perusahaan sendiri
- Riset keamanan siber

**Jangan gunakan untuk melacak orang lain tanpa izin.**
