// SQLite via modul bawaan Node.js 22+ (tanpa dependensi native)
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const sqlite = new DatabaseSync(path.join(DATA_DIR, 'breach_intel.db'));
sqlite.exec('PRAGMA journal_mode = WAL;');

// Migrasi skema
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    query_type TEXT NOT NULL,
    result_summary TEXT,
    breach_count INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'SAFE',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS breach_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id INTEGER,
    source TEXT,
    breach_name TEXT,
    breach_date TEXT,
    data_classes TEXT,
    description TEXT,
    is_verified INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    query_type TEXT NOT NULL,
    label TEXT,
    last_checked TEXT,
    last_breach_count INTEGER DEFAULT 0,
    last_risk_level TEXT DEFAULT 'SAFE',
    is_active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TEXT NOT NULL
  );
`);

// Kolom result_json untuk riwayat klik-able (migrasi aman)
try {
  sqlite.exec(`ALTER TABLE search_history ADD COLUMN result_json TEXT;`);
} catch { /* kolom sudah ada */ }

// Tabel share link read-only
sqlite.exec(`
  CREATE TABLE IF NOT EXISTS share_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    history_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    ip TEXT,
    created_at TEXT NOT NULL
  );
`);

// Kolom 2FA
try {
  sqlite.exec(`ALTER TABLE users ADD COLUMN totp_secret TEXT;`);
} catch { /* sudah ada */ }
try {
  sqlite.exec(`ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;`);
} catch { /* sudah ada */ }

// Migrasi otomatis dari JSON lama (sekali saja)
const OLD_JSON = path.join(DATA_DIR, 'breach_intel.json');
try {
  if (fs.existsSync(OLD_JSON)) {
    const old = JSON.parse(fs.readFileSync(OLD_JSON, 'utf8'));
    const insHist = sqlite.prepare(`INSERT INTO search_history (query, query_type, result_summary, breach_count, risk_level, created_at) VALUES (?, ?, ?, ?, ?, ?)`);
    for (const r of (old.search_history || [])) {
      insHist.run(r.query, r.query_type, r.result_summary || '', r.breach_count || 0, r.risk_level || 'SAFE', r.created_at || new Date().toISOString());
    }
    const insWatch = sqlite.prepare(`INSERT INTO watchlist (query, query_type, label, is_active, created_at) VALUES (?, ?, ?, ?, ?)`);
    for (const w of (old.watchlist || [])) {
      insWatch.run(w.query, w.query_type, w.label || w.query, w.is_active ?? 1, w.created_at || new Date().toISOString());
    }
    fs.renameSync(OLD_JSON, OLD_JSON + '.migrated');
    console.log('✅ Migrasi data JSON → SQLite selesai (backup: breach_intel.json.migrated)');
  }
} catch (e) {
  console.warn('⚠️ Migrasi JSON dilewati:', e.message);
}

// Interface kompatibel dengan server.js (callback style)
const db = {
  run(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      let info;
      if (sql.includes('INSERT INTO search_history')) {
        // params: [query, type, summary, breach_count, risk, result_json?]
        info = sqlite.prepare(`INSERT INTO search_history (query, query_type, result_summary, breach_count, risk_level, created_at, result_json) VALUES (?, ?, ?, ?, ?, ?, ?)`)
          .run(params[0], params[1], String(params[2] || ''), params[3], params[4], new Date().toISOString(), params[5] ? String(params[5]) : null);
      }
      else if (sql.includes('INSERT INTO breach_results')) {
        info = sqlite.prepare(`INSERT INTO breach_results (search_id, source, breach_name, breach_date, data_classes, description, is_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(params[0], params[1], params[2], params[3], params[4], params[5], params[6] ? 1 : 0, new Date().toISOString());
      }
      else if (sql.includes('INSERT INTO watchlist')) {
        info = sqlite.prepare(`INSERT INTO watchlist (query, query_type, label, created_at) VALUES (?, ?, ?, ?)`)
          .run(params[0], params[1], params[2] || params[0], new Date().toISOString());
      }
      else if (sql.includes('UPDATE watchlist SET is_active = 0')) {
        info = sqlite.prepare(`UPDATE watchlist SET is_active = 0 WHERE id = ?`).run(params[params.length - 1]);
      }
      else if (sql.includes('UPDATE watchlist SET last_checked')) {
        info = sqlite.prepare(`UPDATE watchlist SET last_checked = ?, last_breach_count = ?, last_risk_level = ? WHERE id = ?`)
          .run(params[0], params[1], params[2], params[3]);
      }
      else { info = { changes: 0, lastInsertRowid: null }; }

      if (cb) cb.call({ lastID: Number(info.lastInsertRowid) }, null);
    } catch (e) { if (cb) cb(e); }
  },

  get(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      if (sql.includes('COUNT(*)') && sql.includes('search_history')) {
        const row = sqlite.prepare(`
          SELECT 
            COUNT(*) as total_searches,
            COALESCE(SUM(breach_count), 0) as total_breaches_found,
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN risk_level = 'SAFE' THEN 1 ELSE 0 END) as safe_count
          FROM search_history
        `).get();
        cb(null, row);
      } else { cb(null, null); }
    } catch (e) { cb(e); }
  },

  all(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      if (sql.includes('watchlist') && sql.includes('is_active')) {
        cb(null, sqlite.prepare(`SELECT * FROM watchlist WHERE is_active = 1 ORDER BY created_at DESC`).all());
      } else if (sql.includes('search_history')) {
        const limit = typeof params[0] === 'number' ? params[0] : 50;
        cb(null, sqlite.prepare(`SELECT * FROM search_history ORDER BY created_at DESC LIMIT ?`).all(limit));
      } else if (sql.includes('breach_results')) {
        cb(null, sqlite.prepare(`SELECT * FROM breach_results WHERE search_id = ?`).all(params[0]));
      } else { cb(null, []); }
    } catch (e) { cb(e, []); }
  },

  raw: sqlite,
  serialize(fn) { fn(); }
};

module.exports = db;
