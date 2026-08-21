const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'data', 'breach_intel.db');

// Pastikan folder data ada
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

const db = new Database(DB_PATH);

// Tabel riwayat pencarian
db.exec(`CREATE TABLE IF NOT EXISTS search_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  query TEXT NOT NULL,
  query_type TEXT NOT NULL,
  result_summary TEXT,
  breach_count INTEGER DEFAULT 0,
  risk_level TEXT DEFAULT 'UNKNOWN',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Tabel detail breach
db.exec(`CREATE TABLE IF NOT EXISTS breach_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  search_id INTEGER,
  source TEXT NOT NULL,
  breach_name TEXT,
  breach_date TEXT,
  data_classes TEXT,
  description TEXT,
  is_verified INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (search_id) REFERENCES search_history(id)
)`);

// Tabel watchlist
db.exec(`CREATE TABLE IF NOT EXISTS watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  query TEXT NOT NULL,
  query_type TEXT NOT NULL,
  label TEXT,
  last_checked DATETIME,
  last_breach_count INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

module.exports = db;