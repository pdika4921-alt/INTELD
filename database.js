const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'breach_intel.db');

// Pastikan folder data ada
const fs = require('fs');
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  // Tabel riwayat pencarian
  db.run(`CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    query_type TEXT NOT NULL, -- email, name, phone, domain
    result_summary TEXT,
    breach_count INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'UNKNOWN', -- LOW, MEDIUM, HIGH, CRITICAL
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Tabel detail breach yang ditemukan
  db.run(`CREATE TABLE IF NOT EXISTS breach_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id INTEGER,
    source TEXT NOT NULL, -- HIBP, LeakCheck, dll
    breach_name TEXT,
    breach_date TEXT,
    data_classes TEXT, -- JSON array: email, password, phone, dll
    description TEXT,
    is_verified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (search_id) REFERENCES search_history(id)
  )`);

  // Tabel watchlist untuk monitoring otomatis
  db.run(`CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    query_type TEXT NOT NULL,
    label TEXT, -- nama/label untuk identifikasi
    last_checked DATETIME,
    last_breach_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

module.exports = db;
