// =============================================
// AUTO-FLAG: pastikan --experimental-sqlite aktif
// Parent = supervisor, child = server sebenarnya
// =============================================
if (!process.execArgv.some(a => a.includes('sqlite'))) {
  const { spawn } = require('child_process');
  const child = spawn(process.execPath, ['--experimental-sqlite', ...process.argv.slice(1)], {
    stdio: 'inherit',
    env: process.env
  });
  child.on('exit', (code) => process.exit(code ?? 0));
  // Parent tetap hidup sebagai supervisor (jangan jalankan sisa file)
  setInterval(() => {}, 1 << 30);
} else {
  main();
}

function main() {
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const session = require('express-session');
const cron = require('node-cron');
const crypto = require('crypto');
const db = require('./database');
const { runIntelligence, normalizePhone } = require('./services/breachService');
const axios = require('axios');

// =============================================
// MULTI-USER: hash password + seed admin default
// =============================================
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

// Audit log helper
function audit(req, action, detail = '') {
  try {
    db.raw.prepare(`INSERT INTO audit_log (username, action, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(req.session?.username || 'anon', action, String(detail).substring(0, 300), req.ip || '-', new Date().toISOString());
  } catch {}
}

(function seedAdmin() {
  const count = db.raw.prepare(`SELECT COUNT(*) AS c FROM users`).get().c;
  if (count === 0) {
    const u = process.env.ADMIN_USERNAME || 'admin';
    const p = process.env.ADMIN_PASSWORD || 'admin123';
    const salt = crypto.randomBytes(16).toString('hex');
    db.raw.prepare(`INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(u, hashPassword(p, salt), salt, 'admin', new Date().toISOString());
    console.log(`👤 Admin default dibuat: ${u} (password dari .env)`);
  }
})();

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (Render/Hostinger/Nginx di depan) agar req.https terdeteksi
app.set('trust proxy', 1);

// =============================================
// AUTENTIKASI SEDERHANA (credentials dari .env)
// =============================================
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASS) {
  console.warn('⚠️  ADMIN_PASSWORD tidak diset di .env — login dinonaktifkan (mode terbuka). Set segera untuk keamanan!');
}

function requireAuth(req, res, next) {
  if (!ADMIN_PASS) return next(); // mode terbuka jika password belum diset
  if (req.session && req.session.authenticated) return next();
  
  // API request → JSON response
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Unauthorized', need_login: true });
  }
  return res.redirect('/login.html');
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Allow inline scripts for simplicity
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session untuk login (cookie secure otomatis saat via HTTPS)
app.use(session({
  secret: process.env.SESSION_SECRET || 'breach-intel-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: 'auto', sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

// Anti brute-force login: maks 5 percobaan gagal / 15 menit / IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: { success: false, error: 'Terlalu banyak percobaan login gagal. Coba lagi dalam 15 menit.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Route login/logout (bebas auth)
app.post('/api/login', loginLimiter, (req, res) => {
  if (!ADMIN_PASS) return res.json({ success: true, message: 'Mode terbuka (password belum diset)' });
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(401).json({ success: false, error: 'Username dan password wajib diisi' });
  }

  // 1. Cek user dari database
  const user = db.raw.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
  if (user) {
    const hash = hashPassword(password, user.salt);
    if (crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(user.password_hash))) {
      req.session.authenticated = true;
      req.session.username = user.username;
      req.session.role = user.role;
      audit(req, 'login', `user=${user.username} role=${user.role}`);
      return res.json({ success: true, role: user.role, username: user.username });
    }
    audit(req, 'login_failed', `user=${username}`);
    setTimeout(() => res.status(401).json({ success: false, error: 'Username atau password salah' }), 600);
    return;
  }

  // 2. Fallback admin dari .env
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.authenticated = true;
    req.session.username = ADMIN_USER;
    req.session.role = 'admin';
    audit(req, 'login', 'admin env');
    return res.json({ success: true, role: 'admin', username: ADMIN_USER });
  }

  audit(req, 'login_failed', `user=${username}`);
  // Delay kecil anti brute-force
  setTimeout(() => res.status(401).json({ success: false, error: 'Username atau password salah' }), 600);
});

// Audit log (admin)
app.get('/api/audit', requireAuth, requireAdmin, (req, res) => {
  const rows = db.raw.prepare(`SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200`).all();
  res.json({ success: true, data: rows });
});

// Health check untuk uptime monitor
app.get('/health', (req, res) => {
  let dbOk = false;
  try { db.raw.prepare(`SELECT 1`).get(); dbOk = true; } catch {}
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? 'ok' : 'degraded',
    db: dbOk,
    uptime_seconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

function requireAdmin(req, res, next) {
  if (req.session?.role !== 'admin') {
    return res.status(403).json({ error: 'Hanya admin yang boleh mengakses fitur ini' });
  }
  next();
}

// ===== Manajemen User (admin only) =====
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const rows = db.raw.prepare(`SELECT id, username, role, totp_enabled, created_at FROM users ORDER BY created_at DESC`).all();
  res.json({ success: true, data: rows });
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username & password wajib diisi' });
  if (password.length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
  const finalRole = ['admin', 'user'].includes(role) ? role : 'user';
  try {
    const salt = crypto.randomBytes(16).toString('hex');
    db.raw.prepare(`INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(username.trim(), hashPassword(password, salt), salt, finalRole, new Date().toISOString());
    res.json({ success: true });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Username sudah dipakai' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const row = db.raw.prepare(`SELECT * FROM users WHERE id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'User tidak ditemukan' });
  if (row.username === req.session.username) return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri' });
  db.raw.prepare(`DELETE FROM users WHERE id = ?`).run(req.params.id);
  res.json({ success: true });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// PROTEKSI: semua route & static file setelah ini butuh login
// (login.html disajikan khusus sebelum proteksi)
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.use(requireAuth);

app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const searchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // limit each IP to 30 requests per windowMs
  message: { error: 'Terlalu banyak permintaan, coba lagi nanti' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/search', searchLimiter);
app.use('/api/cross-search', searchLimiter);
app.use('/api/phone-lookup', searchLimiter);
app.use('/api/batch', searchLimiter);

// =============================================
// ROUTES
// =============================================

// Halaman utama
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API: Single Search - Proxy ke breachService (fix CORS)
app.get('/api/search', async (req, res) => {
  const { q: query, type = 'email' } = req.query;
  
  if (!query || !query.trim()) {
    return res.status(400).json({ error: 'Query pencarian diperlukan' });
  }

  const validTypes = ['email', 'phone', 'domain', 'name', 'location', 'ttl', 'username'];
  const searchType = validTypes.includes(type) ? type : 'email';

  try {
    const results = await runIntelligence(query.trim(), searchType);

    // Simpan ke history + result_json untuk riwayat klik-able (tunggu selesai agar ID terkirim)
    const historyId = await new Promise((resolve) => {
      db.run(
        `INSERT INTO search_history (query, query_type, result_summary, breach_count, risk_level, result_json) VALUES (?, ?, ?, ?, ?, ?)`,
        [query.trim(), searchType, JSON.stringify(results.summary), results.summary.total_breaches || 0, results.summary.risk_level || 'SAFE', JSON.stringify(results)],
        function (err) { if (err) { console.error('History save error:', err); resolve(null); } else resolve(this.lastID); }
      );
    });

    audit(req, 'search', `${query.trim()} [${searchType}]`);
    res.json({ success: true, data: results, history_id: historyId });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Terjadi kesalahan pada server pencarian' });
  }
});

// =============================================
// HELPER: Klasifikasi platform dari URL
// =============================================
function detectPlatform(url) {
  const u = url.toLowerCase();
  const platforms = [
    ['instagram', '📸 Instagram'], ['facebook', '📘 Facebook'], ['tiktok', '🎵 TikTok'],
    ['twitter.com', '🐦 X/Twitter'], ['x.com', '🐦 X/Twitter'], ['linkedin', '💼 LinkedIn'],
    ['youtube', '▶️ YouTube'], ['tokopedia', '🛒 Tokopedia'], ['shopee', '🛍️ Shopee'],
    ['olx.co.id', '🏷️ OLX'], ['bukalapak', '📦 Bukalapak'], ['lazada', '🛒 Lazada'],
    ['wa.me', '💬 WhatsApp'], ['api.whatsapp', '💬 WhatsApp'], ['t.me', '✈️ Telegram'],
    ['pastebin', '📋 Pastebin'], ['github', '🐙 GitHub'], ['play.google', '📱 Google Play'],
    ['traveloka', '✈️ Traveloka'], ['gojek', '🟢 Gojek'], ['grab', '🚗 Grab']
  ];
  for (const [key, label] of platforms) {
    if (u.includes(key)) return label;
  }
  try {
    return '🌐 ' + new URL(url).hostname.replace('www.', '');
  } catch { return '🌐 Web'; }
}

// HELPER: Deteksi lokasi Indonesia dari teks
const ID_CITIES = ['Jakarta','Bandung','Surabaya','Medan','Bekasi','Depok','Tangerang','Semarang',
  'Palembang','Makassar','Batam','Bogor','Pekanbaru','Bandar Lampung','Padang','Malang',
  'Denpasar','Samarinda','Tasikmalaya','Yogyakarta','Jogja','Surakarta','Solo','Pontianak',
  'Balikpapan','Manado','Ambon','Jayapura','Kupang','Mataram','Palu','Banjarmasin',
  'Jakarta Selatan','Jakarta Timur','Jakarta Barat','Jakarta Utara','Jakarta Pusat'];
function detectLocations(text) {
  return ID_CITIES.filter(city => text.toLowerCase().includes(city.toLowerCase()));
}

// =============================================
// CACHE lookup nomor (hemat kuota API, TTL 30 menit)
// =============================================
const phoneCache = new Map();
const CACHE_TTL = 30 * 60 * 1000;
function getCache(key) {
  const c = phoneCache.get(key);
  if (c && Date.now() - c.ts < CACHE_TTL) return c.data;
  phoneCache.delete(key);
  return null;
}
function setCache(key, data) {
  phoneCache.set(key, { ts: Date.now(), data });
  // Bersihkan cache lama jika terlalu besar
  if (phoneCache.size > 200) {
    const oldest = [...phoneCache.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
    if (oldest) phoneCache.delete(oldest[0]);
  }
}

// =============================================
// HELPER: DuckDuckGo HTML search (gratis, tanpa key)
// =============================================
async function duckDuckGoSearch(query, maxResults = 8) {
  try {
    const r = await axios.get('https://html.duckduckgo.com/html/', {
      params: { q: query },
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
      }
    });
    const results = [];
    const regex = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g;
    let m;
    while ((m = regex.exec(r.data)) !== null && results.length < maxResults) {
      let link = m[1];
      // DDG pakai redirect uddg=
      const uddg = link.match(/uddg=([^&]+)/);
      if (uddg) link = decodeURIComponent(uddg[1]);
      const title = m[2].replace(/<[^>]*>/g, '').trim();
      if (title && !link.includes('duckduckgo.com')) {
        results.push({ title: title.substring(0, 150), link, snippet: '', platform: detectPlatform(link), source: 'DuckDuckGo' });
      }
    }
    return results;
  } catch (e) {
    console.warn('DuckDuckGo search failed:', e.message);
    return [];
  }
}

// =============================================
// HELPER: Serper Places (identifikasi bisnis)
// =============================================
async function serperPlaces(query, serperKey) {
  try {
    const r = await axios.post('https://google.serper.dev/places',
      { q: query },
      { headers: { 'X-API-KEY': serperKey, 'Content-Type': 'application/json' }, timeout: 12000 }
    );
    return (r.data.places || []).slice(0, 5).map(p => ({
      title: p.title,
      address: p.address || '',
      rating: p.rating || null,
      category: p.type || '',
      phone: p.phoneNumber || '',
      website: p.website || ''
    }));
  } catch (e) {
    console.warn('Serper Places failed:', e.message);
    return [];
  }
}

// API: Phone Owner Lookup (Reverse Phone / Caller ID) - MAX VERSION
app.get('/api/phone-lookup', async (req, res) => {
  const { q: phone, refresh } = req.query;
  
  if (!phone || !phone.trim()) {
    return res.status(400).json({ error: 'Nomor telepon diperlukan' });
  }

  // Cek cache dulu (hemat kuota) — skip jika refresh=1
  const cacheKey = 'phone:' + phone.trim();
  if (refresh !== '1') {
    const cached = getCache(cacheKey);
    if (cached) {
      return res.json({ success: true, data: { ...cached, from_cache: true } });
    }
  }
  try {
    const raw = phone.trim();
    const normalized = normalizePhone(raw);
    // Varian format untuk pencarian maksimal
    const digits = normalized.e164.replace('+', '');
    const localFmt = digits.startsWith('62') ? '0' + digits.slice(2) : raw;
    const spacedFmt = localFmt.replace(/^(\d{4})(\d{4})(\d+)$/, '$1-$2-$3');
    
    const lookupResults = {
      phone: normalized,
      sources: [],
      owner_info: null,
      confidence: 0,
      summary: {},
      config_warnings: []
    };

    // Diagnostik: key mana yang tidak tersedia di server ini
    const envChecks = [
      ['NUMVERIFY_API_KEY', 'Info carrier & lokasi terdaftar'],
      ['ABSTRACTAPI_PHONE_KEY', 'Detail operator ganda'],
      ['SERPER_API_KEY', 'Pencarian jejak publik Google'],
      ['LEAKCHECK_API_KEY', 'Cek breach nomor telepon']
    ];
    for (const [key, desc] of envChecks) {
      const val = process.env[key];
      if (!val || val.includes('your_')) {
        lookupResults.config_warnings.push(`${key} belum diset — fitur "${desc}" nonaktif`);
      }
    }

    // ============================================
    // 1 & 2. NumVerify + AbstractAPI (paralel)
    // ============================================
    const carrierPromises = [];
    const numverifyKey = process.env.NUMVERIFY_API_KEY;
    if (numverifyKey && !numverifyKey.includes('your_')) {
      carrierPromises.push(
        axios.get(`http://apilayer.net/api/validate?access_key=${numverifyKey}&number=${digits}&format=1`, { timeout: 8000 })
          .then(r => ({ ok: true, data: r.data })).catch(e => ({ ok: false, err: e.message }))
      );
    }
    const abstractKey = process.env.ABSTRACTAPI_PHONE_KEY;
    let abstractData = null;
    if (abstractKey && !abstractKey.includes('your_')) {
      carrierPromises.push(
        axios.get(`https://phonevalidation.abstractapi.com/v1/?api_key=${abstractKey}&phone=${encodeURIComponent(normalized.e164)}`, { timeout: 8000 })
          .then(r => abstractData = r.data).catch(e => console.warn('AbstractAPI failed:', e.message))
      );
    }

    // ============================================
    // 3. Serper Multi-Dork OSINT (batch agar tidak kena rate limit)
    // ============================================
    const serperKey = process.env.SERPER_API_KEY;
    let allRecords = [];
    let placesResults = [];
    let serperSuccessCount = 0;
    if (serperKey && !serperKey.includes('your_')) {
      const dorkQueries = [
        `"${normalized.e164}" OR "${localFmt}"`,
        `"${digits}"`,
        `"${localFmt}" (WA OR WhatsApp OR kontak OR hubungi)`,
        `"${localFmt}" (jual OR toko OR shop OR CS OR "customer service")`,
        `"${spacedFmt}"`,
        `"${localFmt}" site:kredibel.com OR site:cekrekening.id`,
        `"${localFmt}" (forum OR blog OR komunitas OR iklan) -site:facebook.com -site:instagram.com`
      ];

      async function serperSearch(q, endpoint = 'search', body = { q, num: 8 }) {
        return axios.post(`https://google.serper.dev/${endpoint}`, body,
          { headers: { 'X-API-KEY': serperKey, 'Content-Type': 'application/json' }, timeout: 12000 });
      }

      // Jalankan bertahap: batch 3 query per gelombang, delay antar gelombang
      const batches = [];
      for (let i = 0; i < dorkQueries.length; i += 3) batches.push(dorkQueries.slice(i, i + 3));

      const seen = new Set();
      for (const batch of batches) {
        const results = await Promise.allSettled(batch.map(q => serperSearch(q)));
        for (const result of results) {
          if (result.status === 'fulfilled') {
            serperSuccessCount++;
            for (const item of (result.value.data.organic || [])) {
              if (!seen.has(item.link)) {
                seen.add(item.link);
                allRecords.push({
                  title: item.title,
                  snippet: item.snippet || '',
                  link: item.link,
                  platform: detectPlatform(item.link)
                });
              }
            }
          }
        }
        if (batch === batches[batches.length - 1]) break;
        await new Promise(r => setTimeout(r, 400)); // jeda antar batch
      }

      // Google Places untuk identifikasi bisnis
      try {
        placesResults = await serperPlaces(`"${localFmt}"`, serperKey);
      } catch (e) { /* ignore */ }
    }

    // ============================================
    // 3b. DuckDuckGo fallback (gratis, tanpa kuota)
    // ============================================
    let ddgUsed = false;
    if (allRecords.length < 3) {
      const ddgResults = await duckDuckGoSearch(`"${normalized.e164}" OR "${localFmt}"`);
      if (ddgResults.length > 0) {
        const seen = new Set(allRecords.map(r => r.link));
        for (const r of ddgResults) {
          if (!seen.has(r.link)) {
            seen.add(r.link);
            allRecords.push(r);
          }
        }
        ddgUsed = true;
      }
    }

    // ============================================
    // 4. LeakCheck Phone Breach
    // Catatan: API v2 LeakCheck hanya mendukung EMAIL.
    // Query phone selalu 403 -> di-skip otomatis.
    // ============================================
    let leakcheckResult = null;

    // Tunggu hasil carrier
    const carrierResolved = await Promise.all(carrierPromises);

    // Proses NumVerify
    const nvRes = carrierResolved.find(r => r && r.ok);
    if (nvRes && nvRes.data.valid) {
      lookupResults.sources.push({ source: 'NumVerify', status: 'success', data: nvRes.data });
      lookupResults.owner_info = {
        carrier: nvRes.data.carrier,
        location: nvRes.data.location,
        line_type: nvRes.data.line_type,
        country: nvRes.data.country_name
      };
      lookupResults.confidence += 35;
    } else if (nvRes) {
      lookupResults.sources.push({ source: 'NumVerify', status: 'success', data: nvRes.data });
    }

    // Proses AbstractAPI
    if (abstractData) {
      lookupResults.sources.push({ source: 'AbstractAPI', status: 'success', data: abstractData });
      if (abstractData.connection?.current_carrier && !lookupResults.owner_info?.carrier) {
        lookupResults.owner_info = {
          ...lookupResults.owner_info,
          carrier: lookupResults.owner_info?.carrier || abstractData.connection.current_carrier,
          original_carrier: abstractData.connection.original_carrier,
          line_type: abstractData.connection.line_type,
          country: lookupResults.owner_info?.country || abstractData.country?.name
        };
      }
      lookupResults.confidence += 15;
    }

    // ============================================
    // Analisis jejak publik (identitas + lokasi + kategori)
    // ============================================
    if (allRecords.length > 0) {
      lookupResults.sources.push({ source: 'Serper OSINT', status: 'success', publicRecords: allRecords });
      lookupResults.confidence += 20;

      const possibleNames = new Set();
      const socialAccounts = new Set();
      const detectedLocations = new Set();

      for (const record of allRecords) {
        const text = `${record.title} ${record.snippet} ${record.link}`;

        for (const m of text.matchAll(/@([A-Za-z0-9_][A-Za-z0-9_.]{2,29})/g)) {
          socialAccounts.add(m[1].replace(/\.$/, ''));
        }
        for (const m of text.matchAll(/(?:nama|name|pemilik|owner|atas nama)\s*[:\-]\s*([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*)/g)) {
          possibleNames.add(m[1]);
        }
        for (const m of record.snippet.matchAll(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\s*(?:punya|menggunakan|miliki|nomornya)/g)) {
          possibleNames.add(m[1]);
        }
        for (const loc of detectLocations(text)) {
          detectedLocations.add(loc);
        }
      }

      if (possibleNames.size > 0 || socialAccounts.size > 0) lookupResults.confidence += 15;

      lookupResults.owner_info = {
        ...lookupResults.owner_info,
        ...(possibleNames.size > 0 && { possible_names: [...possibleNames].slice(0, 10) }),
        ...(socialAccounts.size > 0 && { social_accounts: [...socialAccounts].slice(0, 15) }),
        ...(detectedLocations.size > 0 && { public_locations: [...detectedLocations].slice(0, 5) })
      };
    }

    // LeakCheck breach
    if (leakcheckResult) {
      lookupResults.sources.push({ source: 'LeakCheck', status: 'success', ...leakcheckResult });
      if (leakcheckResult.found) {
        lookupResults.confidence += 20;
        lookupResults.owner_info = {
          ...lookupResults.owner_info,
          breach_exposure: `${leakcheckResult.count} data bocor ditemukan di database LeakCheck`
        };
      }
    }

    // Summary ringkas
    lookupResults.summary = {
      total_records: allRecords.length,
      platforms: [...new Set(allRecords.map(r => r.platform))],
      has_breach: leakcheckResult?.found || false,
      identity_hints: (lookupResults.owner_info?.possible_names?.length || 0) +
                      (lookupResults.owner_info?.social_accounts?.length || 0),
      serper_queries_ok: serperSuccessCount,
      ddg_used: ddgUsed,
      cached_at: new Date().toISOString()
    };

    // Bisnis terdaftar (Google Places)
    if (placesResults.length > 0) {
      lookupResults.places = placesResults;
      lookupResults.confidence += 15;
    }

    lookupResults.confidence = Math.min(lookupResults.confidence, 100);

    const hasOwnerInfo = lookupResults.owner_info && (
      lookupResults.owner_info.carrier ||
      lookupResults.owner_info.possible_names?.length ||
      lookupResults.owner_info.social_accounts?.length
    );

    const resultData = {
      ...lookupResults,
      from_cache: false,
      has_owner_info: !!hasOwnerInfo,
      note: lookupResults.summary.identity_hints > 0
        ? `Ditemukan ${lookupResults.summary.identity_hints} petunjuk identitas dari ${allRecords.length} jejak publik`
        : hasOwnerInfo 
          ? 'Hanya info carrier tersedia. Nomor tidak menunjukkan jejak publik yang mengandung identitas.'
          : 'Nomor tidak ditemukan di sumber publik manapun.'
    };

    res.json({ success: true, data: resultData });

    // Simpan ke cache setelah sukses
    setCache(cacheKey, resultData);
  } catch (err) {
    console.error('Phone lookup error:', err);
    res.status(500).json({ error: 'Gagal lookup nomor telepon' });
  }
});

// API: Batch Lookup (scan massal, maks 25 target per request)
app.post('/api/batch', async (req, res) => {
  const { items } = req.body; // [{ q, type }]
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Daftar target kosong' });
  }
  if (items.length > 25) {
    return res.status(400).json({ error: 'Maksimal 25 target per batch' });
  }

  const results = [];
  for (const item of items) {
    const q = String(item.q || '').trim();
    let type = String(item.type || 'email').toLowerCase();
    const validTypes = ['email', 'phone', 'domain', 'name', 'location', 'ttl'];
    if (!validTypes.includes(type)) {
      // auto-detect
      type = /^\+?\d[\d\s\-()]{6,}$/.test(q) ? 'phone'
        : /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q) ? 'email'
        : /^[\w-]+\.[a-z]{2,}$/i.test(q) ? 'domain' : 'name';
    }
    if (!q) continue;
    try {
      const r = await runIntelligence(q, type);
      results.push({
        query: q,
        type,
        status: 'ok',
        total_breaches: r.summary?.total_breaches ?? 0,
        risk_level: r.summary?.risk_level ?? 'SAFE',
        data_classes: (r.summary?.data_classes || []).slice(0, 8),
        sources_live: (r.sources || []).filter(s => s.status === 'success').map(s => s.source)
      });
      // Simpan history ringkas
      db.run(
        `INSERT INTO search_history (query, query_type, result_summary, breach_count, risk_level) VALUES (?, ?, ?, ?, ?)`,
        [q, 'batch-' + type, JSON.stringify(r.summary), r.summary?.total_breaches ?? 0, r.summary?.risk_level ?? 'SAFE'],
        () => {}
      );
    } catch (e) {
      results.push({ query: q, type, status: 'error', error: e.message });
    }
    await new Promise(r2 => setTimeout(r2, 300)); // jeda antar target
  }

  res.json({
    success: true,
    data: {
      processed: results.length,
      breached: results.filter(r => (r.total_breaches || 0) > 0).length,
      safe: results.filter(r => r.risk_level === 'SAFE').length,
      errors: results.filter(r => r.status === 'error').length,
      results
    }
  });
});

// =============================================
// TOOL SUITE: Email Finder, Password Breach, IP Lookup, Username Generator
// =============================================

// 1. Email Finder — generate variasi email dari nama + domain, verifikasi MX
app.post('/api/tools/email-finder', requireAuth, async (req, res) => {
  const { name, domain } = req.body || {};
  if (!name || !domain) return res.status(400).json({ error: 'Nama dan domain wajib diisi' });

  const clean = (s) => s.toLowerCase().trim().replace(/[^a-z\s]/g, '');
  const parts = clean(name).split(/\s+/).filter(Boolean);
  if (parts.length === 0) return res.status(400).json({ error: 'Nama tidak valid' });
  const [first, ...rest] = parts;
  const last = rest[parts.length - 2] || '';
  const f = first[0], l = last ? last[0] : '';

  // Pola umum email korporat diurut dari paling umum
  const patterns = [
    { p: `${first}`, label: 'first' },
    { p: `${first}.${last}`, label: 'first.last' },
    { p: `${f}${last}`, label: 'flast' },
    { p: `${f}${rest.join('')}`, label: 'ffirst...all' },
    { p: `${first}${l}`, label: 'firstl' },
    { p: `${first}_${last}`, label: 'first_last' },
    { p: `${first}${last}`, label: 'firstlast' },
    { p: `${f}.${last}`, label: 'f.last' },
    last ? { p: `${last}${f}`, label: 'lastf' } : null,
    last ? { p: `${first}.${rest.join('.')}` , label: 'first.rest.full' } : null
  ].filter(Boolean);

  // Verifikasi MX domain
  let mxValid = false, mxRecords = [];
  try {
    const mx = await require('dns').promises.resolveMx(domain.trim());
    mxValid = mx.length > 0;
    mxRecords = mx.map(m => m.exchange).slice(0, 3);
  } catch {}

  const seen = new Set();
  const candidates = patterns
    .map(p => `${p.p}@${domain.trim().toLowerCase()}`)
    .filter(e => { if (seen.has(e)) return false; seen.add(e); return true; })
    .slice(0, 10);

  res.json({
    success: true,
    data: {
      domain,
      mx_valid: mxValid,
      mx_records: mxRecords,
      candidates: patterns.slice(0, 10).map((p, i) => ({
        email: `${p.p}@${domain.trim().toLowerCase()}`,
        pattern: p.label,
        rank: i + 1,
        note: mxValid ? 'Domain aktif — pola umum' : '⚠️ Domain tanpa mail server'
      }))
    }
  });
});

// 2. Password Breach — cek siapa saja pakai password ini (LeakCheck Pro)
app.post('/api/tools/password-breach', requireAuth, async (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password minimal 4 karakter' });
  const key = process.env.LEAKCHECK_API_KEY;
  if (!key || key.includes('your_') || key === 'dummy') {
    return res.status(400).json({ error: 'Fitur butuh LEAKCHECK_API_KEY aktif (berbayar)' });
  }
  try {
    const r = await axios.get('https://leakcheck.io/api/v2/query', {
      params: { password },
      headers: { 'X-API-KEY': key },
      timeout: 20000
    });
    const d = r.data;
    res.json({
      success: true,
      data: {
        found: !!d.found,
        count: d.count || 0,
        results: (d.result || []).slice(0, 20).map(item => ({
          source: item.source,
          date: item.date,
          fields: Object.keys(item.fields || {}).join(', ')
        }))
      }
    });
  } catch (e) {
    const msg = e.response?.data?.error || e.message;
    res.status(502).json({ error: `LeakCheck: ${msg}` });
  }
});

// 3. IP Lookup — lokasi, ISP, deteksi proxy/VPN/hosting (ip-api.com gratis)
app.get('/api/tools/ip-lookup', requireAuth, async (req, res) => {
  const { ip } = req.query;
  if (!ip || !/^[\d.:a-fA-F]+$/.test(ip)) return res.status(400).json({ error: 'IP tidak valid' });
  try {
    const r = await axios.get(`http://ip-api.com/json/${encodeURIComponent(ip)}`, {
      params: { fields: 'status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query,message' },
      timeout: 10000
    });
    if (r.data.status !== 'success') return res.status(404).json({ error: r.data.message || 'IP tidak ditemukan' });
    const out = {
      ip: r.data.query,
      location: { country: r.data.country, region: r.data.regionName, city: r.data.city, zip: r.data.zip, lat: r.data.lat, lon: r.data.lon, timezone: r.data.timezone },
      network: { isp: r.data.isp, org: r.data.org, as: r.data.as },
      flags: { mobile: !!r.data.mobile, proxy_vpn: !!r.data.proxy, hosting_dc: !!r.data.hosting },
      map_url: `https://www.google.com/maps?q=${r.data.lat},${r.data.lon}`
    };
    // Shodan tambahan jika ada key
    const shodanKey = process.env.SHODAN_API_KEY;
    if (shodanKey && !shodanKey.includes('your_')) {
      try {
        const sh = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${shodanKey}`, { timeout: 10000 });
        out.open_ports = (sh.data.data || []).flatMap(x => x.port || []).filter(Boolean);
        out.vulns = sh.data.vulns ? Object.keys(sh.data.vulns).slice(0, 10) : [];
        out.hostnames = sh.data.hostnames || [];
      } catch {}
    }
    res.json({ success: true, data: out });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 4. Username Generator — dari nama asli → kemungkinan handle
app.post('/api/tools/username-generate', requireAuth, async (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Nama wajib diisi' });
  const parts = name.toLowerCase().trim().replace(/[^a-z\s]/g, '').split(/\s+/).filter(Boolean);
  const [first, ...rest] = parts;
  const last = rest[rest.length - 1] || '';
  const f = first[0], l = last[0];
  const seps = ['', '.', '_', '-'];
  const bases = new Set();
  for (const sep of seps) {
    if (last) { bases.add(`${first}${sep}${last}`); bases.add(`${f}${sep}${last}`); bases.add(`${first}${sep}${l}`); }
    bases.add(first);
    if (rest.length > 1) { bases.add(`${first}${sep}${rest.join('')}`); }
  }
  const suffixes = ['', '01', '12', '23', '99', '_id', 'id', 'official', 'real', '07'];
  const handles = [];
  const seen = new Set();
  outer:
  for (const b of [...bases]) {
    for (const s of suffixes) {
      const h = `${b}${s}`;
      if (!seen.has(h) && h.length >= 3 && h.length <= 25) { seen.add(h); handles.push(h); }
      if (handles.length >= 30) break outer;
    }
  }
  res.json({ success: true, data: { name, candidates: handles, tip: 'Scan tiap kandidat via tab @USER untuk cek platform mana yang dipakai target' } });
});

// 5. Compare dua target dari riwayat
app.post('/api/tools/compare', requireAuth, async (req, res) => {
  const { idA, idB } = req.body || {};
  const parse = (id) => {
    const row = db.raw.prepare(`SELECT * FROM search_history WHERE id = ?`).get(id);
    if (!row) return null;
    let full = null;
    try { full = row.result_json ? JSON.parse(row.result_json) : null; } catch {}
    return { id: row.id, query: row.query, risk: row.risk_level, breaches: row.breach_count, full };
  };
  const a = parse(idA), b = parse(idB);
  if (!a || !b) return res.status(404).json({ error: 'Satu atau kedua riwayat tidak ditemukan / tidak punya detail lengkap' });

  const extract = (x) => {
    const platforms = new Set(), dataClasses = new Set(), breachNames = new Set();
    for (const src of (x.full?.sources || [])) {
      src.breaches?.forEach(br => { breachNames.add(br.Name); (br.DataClasses || []).forEach(dc => dataClasses.add(dc)); });
      src.rawData?.forEach(rd => platforms.add(String(rd.context).split('—')[0].trim()));
    }
    return { platforms: [...platforms], dataClasses: [...dataClasses], breachNames: [...breachNames] };
  };
  const ea = extract(a), eb = extract(b);
  const same = ea.breachNames.filter(x => eb.breachNames.includes(x));
  const onlyA = ea.breachNames.filter(x => !eb.breachNames.includes(x));
  const onlyB = eb.breachNames.filter(x => !ea.breachNames.includes(x));

  res.json({
    success: true,
    data: {
      a: { id: a.id, query: a.query, risk: a.risk }, b: { id: b.id, query: b.query, risk: b.risk },
      shared_breaches: same, only_a: onlyA, only_b: onlyB,
      shared_data_classes: ea.dataClasses.filter(x => eb.dataClasses.includes(x)),
      verdict: same.length >= 2 ? 'Kemungkinan BESAR orang yang sama (≥2 breach identik)' :
               same.length === 1 ? 'Mungkin orang yang sama (1 breach sama)' : 'Tidak ada indikasi kuat keduanya orang sama'
    }
  });
});

// 6. AI Summary — butuh OPENAI_API_KEY (kompatibel OpenAI/DeepSeek/dll)
app.post('/api/tools/ai-summary', requireAuth, async (req, res) => {
  const { result } = req.body || {};
  const key = process.env.OPENAI_API_KEY;
  if (!key) return res.status(400).json({ error: 'Set OPENAI_API_KEY di .env untuk mengaktifkan AI summary' });
  if (!result) return res.status(400).json({ error: 'Data hasil pencarian wajib' });
  try {
    const brief = JSON.stringify(result).substring(0, 6000);
    const base = process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1';
    const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
    const r = await axios.post(`${base}/chat/completions`, {
      model,
      messages: [
        { role: 'system', content: 'Kamu analis OSINT. Ringkas temuan dalam bahasa Indonesia, maksimal 150 kata, format bullet. Sebutkan tingkat risiko dan rekomendasi tindakan.' },
        { role: 'user', content: `Ringkas hasil investigasi berikut:\n${brief}` }
      ],
      max_tokens: 350
    }, { headers: { Authorization: `Bearer ${key}` }, timeout: 30000 });
    res.json({ success: true, data: { summary: r.data.choices[0].message.content } });
  } catch (e) {
    res.status(502).json({ error: e.response?.data?.error?.message || e.message });
  }
});

// 7. Share link read-only dengan expiry
app.post('/api/share/:historyId', requireAuth, (req, res) => {
  const days = Math.min(parseInt(req.body?.days) || 7, 30);
  const row = db.raw.prepare(`SELECT result_json FROM search_history WHERE id = ?`).get(req.params.historyId);
  if (!row || !row.result_json) return res.status(404).json({ error: 'Riwayat tidak ditemukan / tanpa detail' });
  const token = crypto.randomBytes(16).toString('hex');
  db.raw.prepare(`INSERT INTO share_links (token, history_id, expires_at, created_at) VALUES (?, ?, ?, ?)`)
    .run(token, req.params.historyId, new Date(Date.now() + days * 86400000).toISOString(), new Date().toISOString());
  res.json({ success: true, data: { url: `/share/${token}`, expires_days: days } });
});

app.get('/share/:token', async (req, res) => {
  try {
    const link = db.raw.prepare(`SELECT * FROM share_links WHERE token = ? AND expires_at > ?`).get(req.params.token, new Date().toISOString());
    if (!link) return res.status(404).send('Link expired atau tidak valid');
    const row = db.raw.prepare(`SELECT result_json, query, created_at FROM search_history WHERE id = ?`).get(link.history_id);
    const result = JSON.parse(row.result_json);
    const s = result.summary || {};
    const srcList = (result.sources || []).map(x =>
      `<div style="background:#0a120a;border:1px solid #1a3320;border-radius:10px;padding:14px 18px;margin-bottom:12px;">
        <strong style="color:#00ff41;font-family:monospace;">${x.source}</strong>
        <span style="float:right;color:${x.status === 'success' ? '#00ff41' : '#ffb000'};font-size:0.75rem;">${(x.status || '').toUpperCase()}</span>
        ${x.breaches ? `<div style="margin-top:8px;color:#c8e6c9;font-size:0.85rem;">${x.breaches.length} breach ditemukan</div>` : ''}
        ${x.found !== undefined ? `<div style="margin-top:8px;color:#c8e6c9;font-size:0.85rem;">${x.found} temuan</div>` : ''}
      </div>`).join('');
    res.send(`<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Laporan Berbagi — BREACH INTEL</title></head>
      <body style="background:#030803;color:#c8e6c9;font-family:sans-serif;max-width:760px;margin:0 auto;padding:32px 20px;">
        <h1 style="color:#00ff41;font-family:monospace;letter-spacing:3px;">🔍 BREACH INTEL</h1>
        <p style="color:#4a7a52;font-size:0.85rem;">Laporan read-only · dibuat: ${new Date(row.created_at).toLocaleString('id-ID')} · berlaku s.d. ${new Date(link.expires_at).toLocaleDateString('id-ID')}</p>
        <h2 style="color:#fff;font-size:1rem;">Target: ${row.query}</h2>
        <p>Risiko: <strong style="color:#ff5555;">${s.risk_level || '-'}</strong> · Breach/temuan: <strong>${s.total_breaches ?? 0}</strong></p>
        ${s.data_classes?.length ? `<p style="font-size:0.85rem;">Data bocor: ${s.data_classes.join(', ')}</p>` : ''}
        <hr style="border-color:#1a3320;margin:20px 0;">
        ${srcList}
        <p style="color:#4a7a52;font-size:0.7rem;margin-top:30px;">Dihasilkan oleh BREACH INTEL — gunakan hanya untuk keperluan sah.</p>
      </body></html>`);
  } catch (e) {
    res.status(500).send('Error: ' + e.message);
  }
});

// API: Jalankan Multi-Parameter Cross-Search (v2 — pakai semua sumber)
app.post('/api/cross-search', async (req, res) => {
  const { email, phone, name, location } = req.body;

  if (!email && !phone && !name && !location) {
    return res.status(400).json({ error: 'Minimal satu parameter diperlukan' });
  }

  try {
    const tasks = [];
    if (email) tasks.push(runIntelligence(email, 'email'));
    if (phone) tasks.push(runIntelligence(phone, 'phone'));
    if (name) tasks.push(runIntelligence(name, 'name'));
    if (location && location !== name) tasks.push(runIntelligence(location, 'name'));

    // Korelasi gabungan via dork Serper (nama+lokasi+telepon dalam 1 query)
    let correlationSource = null;
    const serperKey = process.env.SERPER_API_KEY;
    const corrParts = [name, location].filter(Boolean);
    if (corrParts.length >= 2 && serperKey && !serperKey.includes('your_')) {
      try {
        const queryParts = corrParts.join(' AND ');
        const serperRes = await axios.post('https://google.serper.dev/search',
          { q: `"${queryParts}" (site:pastebin.com OR ext:txt OR ext:sql OR site:facebook.com OR site:linkedin.com)`, num: 8 },
          { headers: { 'X-API-KEY': serperKey, 'Content-Type': 'application/json' }, timeout: 12000 }
        );
        const items = (serperRes.data.organic || []);
        if (items.length > 0) {
          correlationSource = {
            source: 'Korelasi Silang Serper',
            status: 'success',
            rawData: items.map(item => ({
              context: item.title,
              date: 'Real-time Dork',
              tags: ['Cross-Reference', 'Public Dump'],
              details: {
                'Parameter_Dicari': queryParts,
                'URL_Sumber': item.link,
                'Korelasi_Teks': (item.snippet || '').substring(0, 200)
              }
            }))
          };
        }
      } catch (err) { console.warn('Serper correlation gagal:', err.message); }
    }

    // Gabungkan hasil semua task
    const settled = await Promise.allSettled(tasks);
    let combinedSources = [];
    let totalBreaches = 0;
    let allDataClasses = [];

    for (const s of settled) {
      if (s.status !== 'fulfilled' || !s.value) continue;
      for (const src of (s.value.sources || [])) {
        if (!src || !src.source) continue;
        // dedupe berdasar nama sumber
        const existing = combinedSources.find(x => x.source === src.source);
        if (existing) continue;
        combinedSources.push(src);
        totalBreaches = Math.max(totalBreaches,
          src.breaches?.length || src.found_count || src.found || 0,
          src.rawData?.length || 0
        );
        src.breaches?.forEach(b => allDataClasses.push(...(b.DataClasses || [])));
      }
      allDataClasses.push(...(s.value.summary?.data_classes || []));
    }

    if (correlationSource) {
      combinedSources.push(correlationSource);
      totalBreaches += correlationSource.rawData.length;
      allDataClasses.push('Public Records');
    }

    let riskLevel = 'SAFE';
    if (totalBreaches >= 10) riskLevel = 'CRITICAL';
    else if (totalBreaches >= 5) riskLevel = 'HIGH';
    else if (totalBreaches >= 2) riskLevel = 'MEDIUM';
    else if (totalBreaches === 1) riskLevel = 'LOW';

    const results = {
      query: [email, phone, name, location].filter(Boolean).join(' | '),
      summary: {
        total_breaches: totalBreaches,
        risk_level: riskLevel,
        data_classes: [...new Set(allDataClasses)]
      },
      sources: combinedSources.length > 0 ? combinedSources : [{
        source: 'Cross-Intelligence Engine',
        status: 'success',
        rawData: [{
          context: 'Analisis Parameter Gabungan',
          date: new Date().toISOString().split('T')[0],
          tags: ['Clean', 'No Match'],
          details: {
            'Status': 'Tidak ditemukan korelasi data terekspos untuk parameter yang dimasukkan.'
          }
        }]
      }]
    };

    // Simpan history
    db.run(
      `INSERT INTO search_history (query, query_type, result_summary, breach_count, risk_level, result_json) VALUES (?, ?, ?, ?, ?, ?)`,
      [results.query, 'cross', JSON.stringify(results.summary), totalBreaches, riskLevel, JSON.stringify(results)],
      () => {}
    );

    res.json({ success: true, data: results });

  } catch (err) {
    console.error('Cross-search error:', err);
    res.status(500).json({ error: 'Terjadi kesalahan pada server korelasi' });
  }
});

// API: Ambil riwayat pencarian
app.get('/api/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  db.all(
    `SELECT * FROM search_history ORDER BY created_at DESC LIMIT ?`,
    [limit],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, data: rows });
    }
  );
});

// API: Hapus riwayat
app.delete('/api/history/:id', (req, res) => {
  db.run(`DELETE FROM search_history WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: 'Riwayat dihapus' });
  });
});

// API: Detail riwayat lengkap (riwayat klik-able)
app.get('/api/history/:id', requireAuth, (req, res) => {
  try {
    const row = db.raw.prepare(`SELECT * FROM search_history WHERE id = ?`).get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Riwayat tidak ditemukan' });
    let full = null;
    try { full = row.result_json ? JSON.parse(row.result_json) : null; } catch { full = null; }
    res.json({ success: true, data: { ...row, result_json: undefined, full_result: full } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// API: Statistik harian untuk grafik (7 hari terakhir)
app.get('/api/stats-daily', requireAuth, (req, res) => {
  try {
    const rows = db.raw.prepare(`
      SELECT substr(created_at, 1, 10) as day,
             COUNT(*) as searches,
             SUM(breach_count) as breaches
      FROM search_history
      WHERE created_at >= date('now', '-6 days')
      GROUP BY substr(created_at, 1, 10)
      ORDER BY day ASC
    `).all();
    const risks = db.raw.prepare(`
      SELECT risk_level, COUNT(*) as cnt
      FROM search_history
      GROUP BY risk_level
    `).all();
    res.json({ success: true, data: { daily: rows, risks } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// API: Watchlist - Tambah
app.post('/api/watchlist', (req, res) => {
  const { query, type, label } = req.body;
  db.run(
    `INSERT INTO watchlist (query, query_type, label) VALUES (?, ?, ?)`,
    [query, type, label || query],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    }
  );
});

// API: Watchlist - Ambil semua
app.get('/api/watchlist', (req, res) => {
  db.all(`SELECT * FROM watchlist WHERE is_active = 1 ORDER BY created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, data: rows });
  });
});

// API: Watchlist - Hapus
app.delete('/api/watchlist/:id', (req, res) => {
  db.run(`UPDATE watchlist SET is_active = 0 WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// API: Stats dashboard
app.get('/api/stats', (req, res) => {
  db.get(
    `SELECT 
      COUNT(*) as total_searches,
      SUM(breach_count) as total_breaches_found,
      SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
      SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_count,
      SUM(CASE WHEN risk_level = 'SAFE' THEN 1 ELSE 0 END) as safe_count
    FROM search_history`,
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, data: row });
    }
  );
});

// =============================================
// WATCHLIST SCHEDULER + NOTIFIKASI TELEGRAM
// =============================================
async function sendTelegram(message) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId || token.includes('your_')) return false;
  try {
    await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
      chat_id: chatId,
      text: message,
      parse_mode: 'HTML'
    }, { timeout: 10000 });
    return true;
  } catch (e) {
    console.warn('Telegram notify gagal:', e.message);
    return false;
  }
}

async function checkWatchlist() {
  const items = await new Promise((resolve) => {
    db.all(`SELECT * FROM watchlist WHERE is_active = 1`, (err, rows) => resolve(err ? [] : rows));
  });

  if (items.length === 0) return { checked: 0, alerts: 0 };

  let alerts = 0;
  for (const item of items) {
    try {
      const results = await runIntelligence(item.query, item.query_type);
      const newCount = results.summary.total_breaches || 0;
      const oldCount = item.last_breach_count || 0;

      db.run(
        `UPDATE watchlist SET last_checked = ?, last_breach_count = ?, last_risk_level = ? WHERE id = ?`,
        [new Date().toISOString(), newCount, results.summary.risk_level || 'SAFE', item.id]
      );

      if (newCount > oldCount && oldCount > -1) {
        alerts++;
        const msgText =
          `🚨 <b>BREACH ALERT — BREACH INTEL</b>\n\n` +
          `Target: <code>${item.query}</code> (${item.label || '-'})\n` +
          `Breach baru terdeteksi: ${oldCount} → <b>${newCount}</b>\n` +
          `Risiko: <b>${results.summary.risk_level}</b>\n` +
          (results.summary.data_classes?.length ? `Data bocor: ${results.summary.data_classes.slice(0, 5).join(', ')}\n` : '') +
          `\n⏰ ${new Date().toLocaleString('id-ID')}`;
        await sendTelegram(msgText);
        // Webhook eksternal (n8n/Zapier/Slack-compatible)
        const hookUrl = process.env.WATCHLIST_WEBHOOK_URL;
        if (hookUrl) {
          try {
            await axios.post(hookUrl, {
              event: 'breach_alert',
              target: item.query,
              label: item.label,
              old_count: oldCount,
              new_count: newCount,
              risk: results.summary.risk_level,
              data_classes: results.summary.data_classes || [],
              timestamp: new Date().toISOString()
            }, { timeout: 10000 });
          } catch (e2) { console.warn('Webhook gagal:', e2.message); }
        }
      }
    } catch (e) {
      console.warn(`Watchlist check gagal untuk ${item.query}:`, e.message);
    }
  }
  return { checked: items.length, alerts };
}

// Manual trigger dari UI
app.post('/api/watchlist/check-all', async (req, res) => {
  try {
    const result = await checkWatchlist();
    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ error: 'Gagal menjalankan pengecekan watchlist' });
  }
});

// Otomatis setiap hari jam 08:00
cron.schedule('0 8 * * *', () => {
  console.log('⏰ Scheduler: cek watchlist harian dimulai...');
  checkWatchlist().then(r =>
    console.log(`   Selesai: ${r.checked} target dicek, ${r.alerts} alert terkirim`)
  );
});

// Backup database otomatis setiap hari jam 00:30 (simpan 7 hari terakhir)
cron.schedule('30 0 * * *', () => {
  try {
    const fs = require('fs');
    const path = require('path');
    const backupDir = path.join(__dirname, 'data', 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
    const stamp = new Date().toISOString().split('T')[0];
    db.raw.prepare(`VACUUM INTO ?`).run(path.join(backupDir, `breach_intel-${stamp}.db`));
    // hapus backup > 7 file
    const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.db')).sort();
    while (files.length > 7) fs.unlinkSync(path.join(backupDir, files.shift()));
    console.log(`💾 Backup database selesai: breach_intel-${stamp}.db`);
  } catch (e) {
    console.error('Backup gagal:', e.message);
  }
});

app.listen(PORT, () => {
  console.log(`\n🔍 BREACH INTEL berjalan di http://localhost:${PORT}`);
  console.log(`📁 Database: ./data/breach_intel.db (SQLite)`);
  console.log(`👤 Login: ${process.env.ADMIN_USERNAME || 'admin'} | ⏰ Watchlist auto-check: 08:00 harian\n`);
});
} // end main()