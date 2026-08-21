require('dotenv').config();
const express = require('express');
const path = require('path');
const db = require('./database');
const { runIntelligence } = require('./services/breachService');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// =============================================
// ROUTES
// =============================================

// Halaman utama
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API: Jalankan pencarian intelligence
app.post('/api/search', async (req, res) => {
  const { query, type } = req.body;

  if (!query || !type) {
    return res.status(400).json({ error: 'Query dan type diperlukan' });
  }

  const validTypes = ['email', 'domain', 'phone', 'name'];
  if (!validTypes.includes(type)) {
    return res.status(400).json({ error: 'Type tidak valid. Gunakan: email, domain, phone, name' });
  }

  try {
    const results = await runIntelligence(query.trim(), type);

    // Simpan ke database
    db.run(
      `INSERT INTO search_history (query, query_type, result_summary, breach_count, risk_level) VALUES (?, ?, ?, ?, ?)`,
      [
        query.trim(),
        type,
        JSON.stringify(results.summary),
        results.summary.total_breaches,
        results.summary.risk_level
      ],
      function(err) {
        if (!err) {
          const searchId = this.lastID;
          // Simpan detail breach
          results.sources.forEach(source => {
            if (source.breaches) {
              source.breaches.forEach(breach => {
                db.run(
                  `INSERT INTO breach_results (search_id, source, breach_name, breach_date, data_classes, description, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                  [
                    searchId,
                    source.source || 'Unknown',
                    breach.Name || breach.name || '-',
                    breach.BreachDate || breach.breach_date || '-',
                    JSON.stringify(breach.DataClasses || breach.data_classes || []),
                    breach.Description || breach.description || '-',
                    breach.IsVerified ? 1 : 0
                  ]
                );
              });
            }
          });
        }
      }
    );

    res.json({ success: true, data: results });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Terjadi kesalahan saat memproses pencarian', detail: err.message });
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

app.listen(PORT, () => {
  console.log(`\n🔍 BREACH INTEL berjalan di http://localhost:${PORT}`);
  console.log(`📁 Database: ./data/breach_intel.db`);
  console.log(`⚙️  Konfigurasi: salin .env.example → .env dan isi API key\n`);
});
