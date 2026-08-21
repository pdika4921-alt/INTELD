const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'breach_intel.json');

// Buat folder & file jika belum ada
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({
    search_history: [],
    breach_results: [],
    watchlist: []
  }));
}

// Load & save
function load() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function save(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Simulasi interface sqlite3 agar server.js tidak perlu banyak diubah
const db = {
  run(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const data = load();
      // INSERT search_history
      if (sql.includes('INSERT INTO search_history')) {
        const id = Date.now();
        data.search_history.push({
          id, query: params[0], query_type: params[1],
          result_summary: params[2], breach_count: params[3],
          risk_level: params[4], created_at: new Date().toISOString()
        });
        save(data);
        if (cb) cb.call({ lastID: id }, null);
      }
      // INSERT breach_results
      else if (sql.includes('INSERT INTO breach_results')) {
        const id = Date.now() + Math.random();
        data.breach_results.push({
          id, search_id: params[0], source: params[1],
          breach_name: params[2], breach_date: params[3],
          data_classes: params[4], description: params[5],
          is_verified: params[6], created_at: new Date().toISOString()
        });
        save(data);
        if (cb) cb.call({ lastID: id }, null);
      }
      // INSERT watchlist
      else if (sql.includes('INSERT INTO watchlist')) {
        const id = Date.now();
        data.watchlist.push({
          id, query: params[0], query_type: params[1],
          label: params[2], last_checked: null,
          last_breach_count: 0, is_active: 1,
          created_at: new Date().toISOString()
        });
        save(data);
        if (cb) cb.call({ lastID: id }, null);
      }
      // UPDATE watchlist (hapus / nonaktifkan)
      else if (sql.includes('UPDATE watchlist')) {
        const id = params[params.length - 1];
        const d = load();
        d.watchlist = d.watchlist.map(w =>
          w.id == id ? { ...w, is_active: 0 } : w
        );
        save(d);
        if (cb) cb(null);
      }
      else { if (cb) cb(null); }
    } catch(e) { if (cb) cb(e); }
  },

  get(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const data = load();
      if (sql.includes('search_history')) {
        const total = data.search_history.length;
        const breaches = data.search_history.reduce((s,r) => s + (r.breach_count||0), 0);
        const critical = data.search_history.filter(r=>r.risk_level==='CRITICAL').length;
        const high = data.search_history.filter(r=>r.risk_level==='HIGH').length;
        const safe = data.search_history.filter(r=>r.risk_level==='SAFE').length;
        cb(null, { total_searches: total, total_breaches_found: breaches,
          critical_count: critical, high_count: high, safe_count: safe });
      } else { cb(null, null); }
    } catch(e) { cb(e); }
  },

  all(sql, params, cb) {
    if (typeof params === 'function') { cb = params; params = []; }
    try {
      const data = load();
      if (sql.includes('watchlist')) {
        cb(null, data.watchlist.filter(w => w.is_active === 1));
      } else if (sql.includes('search_history')) {
        cb(null, [...data.search_history].reverse().slice(0, 50));
      } else if (sql.includes('breach_results')) {
        const id = params[0];
        cb(null, data.breach_results.filter(r => r.search_id == id));
      } else { cb(null, []); }
    } catch(e) { cb(e, []); }
  },

  serialize(fn) { fn(); }
};

module.exports = db;