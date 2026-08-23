const axios = require('axios');
require('dotenv').config();

function normalizePhone(raw) {
  let num = raw.replace(/[\s\-().+]/g, '');
  if (num.startsWith('08')) num = '+62' + num.slice(1);
  else if (num.startsWith('628')) num = '+' + num;
  else if (!num.startsWith('+')) num = '+' + num;
  return {
    e164: num,
    local: num.startsWith('+62') ? '0' + num.slice(3) : num,
    country_code: num.startsWith('+62') ? 'ID' : 'INTL',
    display: num
  };
}

function calculateRisk(breachCount, dataClasses = []) {
  const sensitiveData = ['Passwords','Credit cards','Bank account numbers','Social security numbers','Phone numbers'];
  const hasSensitive = dataClasses.some(d => sensitiveData.some(s => d.toLowerCase().includes(s.toLowerCase())));
  if (breachCount === 0) return 'SAFE';
  if (breachCount >= 10 || (hasSensitive && breachCount >= 3)) return 'CRITICAL';
  if (breachCount >= 5 || hasSensitive) return 'HIGH';
  if (breachCount >= 2) return 'MEDIUM';
  return 'LOW';
}

// =============================================
// 1a. XposedOrNot Detail Analytics (gratis)
// =============================================
async function getXonDetails(email) {
  try {
    const r = await axios.get(
      `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`,
      { headers: { 'User-Agent': 'BreachIntelTool' }, timeout: 10000 }
    );
    const exposed = r.data?.ExposedBreaches?.breaches_details || [];
    const pastes = r.data?.PastesSummary?.cnt || 0;
    const risks = r.data?.BreachMetrics?.risk || [];
    return { details: exposed, pastes, risks };
  } catch {
    return { details: [], pastes: 0, risks: [] };
  }
}

// =============================================
// 1. XposedOrNot - GRATIS, tanpa API key
// =============================================
async function checkXposedOrNot(email) {
  try {
    const [r, details] = await Promise.all([
      axios.get(
        `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`,
        { headers: { 'User-Agent': 'BreachIntelTool' }, timeout: 10000 }
      ),
      getXonDetails(email)
    ]);
    const data = r.data;

    // Jika analytics punya detail lengkap, gunakan itu
    if (details.details.length > 0) {
      const breaches = details.details.map(d => ({
        Name: d.breach || d.breachID || 'Unknown',
        BreachDate: d.xposed_date || d.breachDate || '-',
        DataClasses: d.xposed_data ? String(d.xposed_data).split(';').map(s => s.trim()).filter(Boolean) : [],
        IsVerified: true,
        PwnCount: d.xposed_records || 0,
        Domain: d.domain || '',
        Industry: d.industry || ''
      }));
      return { source: 'XposedOrNot', status: 'success', breaches, pastes: details.pastes };
    }

    // Fallback: nama saja
    const names = (data.breaches || []).flat();
    const breaches = names.map(n => ({
      Name: n,
      BreachDate: '-',
      DataClasses: [],
      IsVerified: true,
      PwnCount: 0
    }));
    return { source: 'XposedOrNot', status: 'success', breaches, pastes: details.pastes };
  } catch (err) {
    if (err.response?.status === 404) {
      return { source: 'XposedOrNot', status: 'success', breaches: [], message: 'Tidak ditemukan di database' };
    }
    return { source: 'XposedOrNot', status: 'error', message: err.message, breaches: [] };
  }
}

// =============================================
// 2. HackMyIP - GRATIS, tanpa API key
// =============================================
async function checkHackMyIP(email) {
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    'Accept': 'application/json'
  };
  // Coba hingga 2x (API kadang flaky)
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const r = await axios.get(
        `https://hackmyip.com/api/breach?email=${encodeURIComponent(email)}`,
        { headers, timeout: 15000 }
      );
      const data = r.data?.data || r.data;
      return {
        source: 'HackMyIP', status: 'success',
        found: data.breaches || 0,
        risk: data.risk || {},
        services: data.services || [],
        passwords: data.passwords || {},
        raw: data
      };
    } catch (err) {
      if (attempt === 2) {
        return { source: 'HackMyIP', status: 'error', message: err.message };
      }
      await new Promise(res => setTimeout(res, 1500)); // jeda sebelum retry
    }
  }
}

// =============================================
// 2b. LeakCheck - API v2 (berbayar) atau Public gratis
// =============================================
async function checkLeakCheckEmail(email) {
  const apiKey = process.env.LEAKCHECK_API_KEY;
  const hasKey = apiKey && !apiKey.includes('your_') && apiKey !== 'dummy';

  // ====== API v2 dengan key: detail lengkap termasuk PASSWORD ======
  if (hasKey) {
    try {
      const r = await axios.get(
        'https://leakcheck.io/api/v2/query',
        {
          params: { email },
          headers: { 'X-API-KEY': apiKey },
          timeout: 20000
        }
      );
      const d = r.data;
      if (!d.found) {
        return { source: 'LeakCheck Pro', status: 'success', found_count: 0, breaches: [], leaked_passwords: [] };
      }
      const breached = [];
      const leakedPasswords = [];
      for (const item of (d.result || [])) {
        const f = item.fields || {};
        breached.push({
          Name: item.source || 'Unknown DB',
          BreachDate: item.date || '-',
          DataClasses: Object.keys(f).map(k => k.charAt(0).toUpperCase() + k.slice(1)),
          IsVerified: true,
          PwnCount: 0
        });
        if (f.password) leakedPasswords.push({ source: item.source, password: f.password });
      }
      return {
        source: 'LeakCheck Pro', status: 'success',
        found_count: d.count || breached.length,
        breaches: breached,
        leaked_passwords: leakedPasswords.slice(0, 15)
      };
    } catch (err) {
      console.warn('LeakCheck v2 gagal, fallback ke public:', err.message);
      // jatuh ke API gratis di bawah
    }
  }

  // ====== Fallback: API publik gratis ======
  try {
    const r = await axios.get(
      `https://leakcheck.io/api/public?email=${encodeURIComponent(email)}`,
      { timeout: 15000, headers: { 'User-Agent': 'Mozilla/5.0' } }
    );
    const d = r.data;
    if (d.success && d.found) {
      return {
        source: 'LeakCheck', status: 'success',
        found_count: d.count || 0,
        breaches: (d.sources || []).map(s => ({
          Name: s.name || s.database || 'Unknown DB',
          BreachDate: s.date || '-',
          DataClasses: ['Passwords', 'Email addresses'],
          IsVerified: true,
          PwnCount: 0
        })),
        leaked_passwords: []
      };
    }
    return { source: hasKey ? 'LeakCheck Pro' : 'LeakCheck', status: 'success', found_count: 0, breaches: [], leaked_passwords: [] };
  } catch (err) {
    if (err.response?.status === 404) {
      return { source: hasKey ? 'LeakCheck Pro' : 'LeakCheck', status: 'success', found_count: 0, breaches: [], leaked_passwords: [] };
    }
    return { source: 'LeakCheck', status: 'error', message: err.message };
  }
}

// =============================================
// 3. HIBP - Berbayar (demo jika tidak ada key)
// =============================================
async function checkHIBP(email) {
  const apiKey = process.env.HIBP_API_KEY;
  const isDummy = !apiKey || ['your_hibp_api_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return { source: 'HaveIBeenPwned', status: 'demo', message: 'Butuh API key (haveibeenpwned.com)', breaches: [] };
  }
  try {
    const r = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      { headers: { 'hibp-api-key': apiKey, 'User-Agent': 'BreachIntelTool-Personal' }, timeout: 10000 }
    );
    return { source: 'HaveIBeenPwned', status: 'success', breaches: r.data || [] };
  } catch (err) {
    if (err.response?.status === 404) return { source: 'HaveIBeenPwned', status: 'success', breaches: [] };
    return { source: 'HaveIBeenPwned', status: 'error', message: err.message, breaches: [] };
  }
}

// =============================================
// 4. EmailRep.io — bekerja TANPA key (rate limit rendah)
// =============================================
async function checkEmailRep(email) {
  const apiKey = process.env.EMAILREP_API_KEY;
  const isDummy = !apiKey || ['your_emailrep_key_here','dummy'].includes(apiKey);
  const headers = { 'User-Agent': 'BreachIntelTool' };
  if (!isDummy) headers['Key'] = apiKey;
  try {
    const r = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`,
      { headers, timeout: 8000 });
    return { source: 'EmailRep.io', status: 'success', data: r.data };
  } catch (err) {
    // 429 = kena rate limit free tier
    if (err.response?.status === 429) {
      return { source: 'EmailRep.io', status: 'demo', message: 'Rate limit gratis tercapai, coba lagi nanti' };
    }
    return { source: 'EmailRep.io', status: 'error', message: err.message };
  }
}

// =============================================
// 4b. Gravatar Profile — GRATIS
// =============================================
const crypto = require('crypto');
async function checkGravatar(email) {
  try {
    const hash = crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex');
    const r = await axios.get(
      `https://api.gravatar.com/v3/profiles/${hash}`,
      { timeout: 8000, validateStatus: s => s < 500 }
    );
    if (r.status === 200 && r.data.hash) {
      return {
        source: 'Gravatar', status: 'success',
        data: {
          exists: true,
          display_name: r.data.display_name || '',
          description: r.data.description || '',
          location: r.data.location || '',
          accounts: (r.data.accounts || []).map(a => a.shortname || a.domain),
          avatar_url: `https://gravatar.com/avatar/${hash}?s=200`
        }
      };
    }
    return { source: 'Gravatar', status: 'success', data: { exists: false } };
  } catch (err) {
    return { source: 'Gravatar', status: 'error', message: err.message };
  }
}

// =============================================
// 4c. Validitas Domain Email (MX record) — GRATIS
// =============================================
const dns = require('dns').promises;
async function checkEmailDomain(email) {
  try {
    const domain = email.split('@')[1];
    if (!domain) return { source: 'Domain Check', status: 'error', message: 'Format email tidak valid' };
    const mx = await dns.resolveMx(domain).catch(() => []);
    return {
      source: 'Domain Check', status: 'success',
      data: {
        domain,
        mx_valid: mx.length > 0,
        mx_records: mx.map(m => m.exchange).slice(0, 3)
      }
    };
  } catch (err) {
    return { source: 'Domain Check', status: 'error', message: err.message };
  }
}

// =============================================
// 5. NumVerify - Phone
// =============================================
async function checkNumVerify(phone) {
  const apiKey = process.env.NUMVERIFY_API_KEY;
  const normalized = normalizePhone(phone);
  const e164clean = normalized.e164.replace('+', '');
  const isDummy = !apiKey || ['your_numverify_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    const isIndonesia = normalized.country_code === 'ID';
    return {
      source: 'NumVerify', status: 'demo', normalized,
      data: {
        valid: true, number: normalized.e164, local_format: normalized.local,
        international_format: normalized.e164,
        country_prefix: isIndonesia ? '+62' : '+1',
        country_code: normalized.country_code,
        country_name: isIndonesia ? 'Indonesia' : 'United States',
        location: isIndonesia ? 'Jakarta, DKI Jakarta' : 'New York',
        carrier: isIndonesia ? 'Telkomsel' : 'AT&T',
        line_type: 'mobile'
      }
    };
  }
  try {
    const r = await axios.get(
      `http://apilayer.net/api/validate?access_key=${apiKey}&number=${e164clean}&format=1`,
      { timeout: 8000 }
    );
    return { source: 'NumVerify', status: 'success', normalized, data: r.data };
  } catch (err) {
    return { source: 'NumVerify', status: 'error', message: err.message, normalized };
  }
}

// =============================================
// 6. AbstractAPI Phone
// =============================================
async function checkAbstractPhone(phone) {
  const apiKey = process.env.ABSTRACTAPI_PHONE_KEY;
  const normalized = normalizePhone(phone);
  const isDummy = !apiKey || ['your_abstractapi_phone_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'AbstractAPI Phone', status: 'demo',
      data: {
        phone: normalized.e164, valid: true,
        format: { international: normalized.e164, local: normalized.local },
        country: { code: normalized.country_code, name: normalized.country_code === 'ID' ? 'Indonesia' : 'International', prefix: normalized.country_code === 'ID' ? '+62' : '+1' },
        connection: { current_carrier: 'Telkomsel', original_carrier: 'Telkomsel', line_type: 'mobile' },
        timezone: [{ name: normalized.country_code === 'ID' ? 'Asia/Jakarta' : 'America/New_York', current_time: new Date().toLocaleString() }]
      }
    };
  }
  try {
    const r = await axios.get(
      `https://phonevalidation.abstractapi.com/v1/?api_key=${apiKey}&phone=${encodeURIComponent(normalized.e164)}`,
      { timeout: 8000 }
    );
    return { source: 'AbstractAPI Phone', status: 'success', data: r.data };
  } catch (err) {
    return { source: 'AbstractAPI Phone', status: 'error', message: err.message };
  }
}

// =============================================
// 7. Hunter.io - Domain
// =============================================
async function checkHunter(domain) {
  const apiKey = process.env.HUNTER_API_KEY;
  const isDummy = !apiKey || ['your_hunter_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'Hunter.io', status: 'demo',
      data: { domain, organization: 'Demo Organization', emails_found: 0,
        emails: [], technologies: [] }
    };
  }
  try {
    const r = await axios.get(
      `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${apiKey}&limit=10`,
      { timeout: 10000 }
    );
    return { source: 'Hunter.io', status: 'success', data: r.data.data };
  } catch (err) {
    return { source: 'Hunter.io', status: 'error', message: err.message };
  }
}

// =============================================
// 8. Shodan - Domain
// =============================================
async function checkShodan(domain) {
  const apiKey = process.env.SHODAN_API_KEY;
  const isDummy = !apiKey || ['your_shodan_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'Shodan', status: 'demo',
      data: { domain, subdomains: [], open_ports: [], vulnerabilities: [], tags: [] }
    };
  }
  try {
    const r = await axios.get(
      `https://api.shodan.io/dns/domain/${encodeURIComponent(domain)}?key=${apiKey}`,
      { timeout: 10000 }
    );
    return { source: 'Shodan', status: 'success', data: r.data };
  } catch (err) {
    return { source: 'Shodan', status: 'error', message: err.message };
  }
}

// =============================================
// 8b. Serper OSINT Dorking untuk Nama/Lokasi/TTL
// =============================================
async function osintNameSearch(name) {
  const apiKey = process.env.SERPER_API_KEY;
  const isDummy = !apiKey || ['your_serper_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return { source: 'Serper OSINT', status: 'demo', message: 'Butuh SERPER_API_KEY untuk pencarian nama', rawData: [] };
  }

  const queries = [
    `"${name}" (site:pastebin.com OR ext:sql OR ext:txt OR ext:xls)`,
    `"${name}" (site:facebook.com OR site:instagram.com OR site:linkedin.com OR site:tiktok.com)`
  ];

  const allItems = [];
  const seen = new Set();

  // Batch agar tidak kena rate limit
  for (let i = 0; i < queries.length; i += 2) {
    const batch = queries.slice(i, i + 2);
    const results = await Promise.allSettled(
      batch.map(q => axios.post('https://google.serper.dev/search',
        { q, num: 8 },
        { headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' }, timeout: 12000 }))
    );
    for (const r of results) {
      if (r.status === 'fulfilled') {
        for (const item of (r.value.data.organic || [])) {
          if (!seen.has(item.link)) {
            seen.add(item.link);
            allItems.push({
              context: item.title,
              date: 'Jejak Publik',
              tags: ['OSINT', 'Public Record'],
              details: {
                'URL_Sumber': item.link,
                'Korelasi_Teks': (item.snippet || '').substring(0, 250)
              }
            });
          }
        }
      }
    }
  }

  if (allItems.length === 0 && seen.size === 0) {
    return { source: 'Serper OSINT', status: 'error', message: 'Query gagal / kuota habis', rawData: [] };
  }
  return { source: 'Serper OSINT', status: 'success', rawData: allItems };
}

// =============================================
// MAIN
// =============================================
async function runIntelligence(query, type) {
  const results = { query, type, sources: [], summary: {}, phone_normalized: null };
  let totalBreaches = 0;
  let allDataClasses = [];

  if (type === 'email') {
    const [xon, hackmyip, hibp, emailrep, gravatar, domaincheck, leakcheck] = await Promise.allSettled([
      checkXposedOrNot(query),
      checkHackMyIP(query),
      checkHIBP(query),
      checkEmailRep(query),
      checkGravatar(query),
      checkEmailDomain(query),
      checkLeakCheckEmail(query)
    ]);
    const xonData = xon.value || {};
    const hackData = hackmyip.value || {};
    const hibpData = hibp.value || {};
    const emailrepData = emailrep.value || {};
    const leakData = leakcheck.value || {};

    results.sources.push(xonData, hackData, hibpData, emailrepData, leakData,
      gravatar.value || {}, domaincheck.value || {});

    totalBreaches = Math.max(
      xonData.breaches?.length || 0,
      hackData.found || 0,
      hibpData.breaches?.length || 0,
      leakData.found_count || 0
    );
    xonData.breaches?.forEach(b => allDataClasses.push(...(b.DataClasses || [])));
    hibpData.breaches?.forEach(b => allDataClasses.push(...(b.DataClasses || [])));
    leakData.breaches?.forEach(b => allDataClasses.push(...(b.DataClasses || [])));
    // Tambah info paste
    if (xonData.pastes > 0) {
      results.paste_exposure = xonData.pastes;
      totalBreaches += 1;
    }

  } else if (type === 'phone') {
    const normalized = normalizePhone(query);
    results.phone_normalized = normalized;
    const [numverify, abstractapi] = await Promise.allSettled([
      checkNumVerify(query), checkAbstractPhone(query)
    ]);
    results.sources.push(numverify.value || {}, abstractapi.value || {});
    totalBreaches = 0;

  } else if (type === 'domain') {
    const [xon, hunter, shodan] = await Promise.allSettled([
      checkXposedOrNot(query), checkHunter(query), checkShodan(query)
    ]);
    results.sources.push(xon.value || {}, hunter.value || {}, shodan.value || {});
    totalBreaches = xon.value?.breaches?.length || 0;

  } else if (type === 'name' || type === 'location') {
    // HackMyIP hanya untuk email — jangan kirim nama ke sana
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(query);
    if (isEmail) {
      const hackmyip = await checkHackMyIP(query);
      results.sources.push(hackmyip);
      totalBreaches = hackmyip.found || 0;
    }

    // Pencarian utama: OSINT dorking via Serper
    const dork = await osintNameSearch(query);
    results.sources.push(dork);
    if (dork.rawData?.length > 0) {
      totalBreaches += dork.rawData.length;
      allDataClasses.push('Public Records', 'Social Media');
    }

  } else if (type === 'ttl') {
    const dork = await osintNameSearch(query);
    results.sources.push(dork);
    if (dork.rawData?.length > 0) {
      totalBreaches += dork.rawData.length;
      allDataClasses.push('Public Records');
    }
  }

  results.summary = {
    total_breaches: totalBreaches,
    risk_level: calculateRisk(totalBreaches, [...new Set(allDataClasses)]),
    data_classes: [...new Set(allDataClasses)],
    checked_at: new Date().toISOString()
  };

  return results;
}

module.exports = { runIntelligence, normalizePhone };