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
// 1. XposedOrNot - GRATIS, tanpa API key
// =============================================
async function checkXposedOrNot(email) {
  try {
    const r = await axios.get(
      `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`,
      { headers: { 'User-Agent': 'BreachIntelTool' }, timeout: 10000 }
    );
    const data = r.data;
    // Format jadi breach list
    const breaches = (data.breaches || []).map(b => ({
      Name: b.breachID || b.name || 'Unknown',
      BreachDate: b.breachDate || '-',
      DataClasses: b.exposedData || [],
      IsVerified: true,
      PwnCount: b.exposedRecords || 0,
      Description: b.description || ''
    }));
    return { source: 'XposedOrNot', status: 'success', breaches, xon_data: data };
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
  try {
    const r = await axios.get(
      `https://hackmyip.com/api/breach?email=${encodeURIComponent(email)}`,
      { headers: { 'User-Agent': 'BreachIntelTool' }, timeout: 10000 }
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
    return { source: 'HackMyIP', status: 'error', message: err.message };
  }
}

// =============================================
// 3. HIBP - Berbayar (demo jika tidak ada key)
// =============================================
async function checkHIBP(email) {
  const apiKey = process.env.HIBP_API_KEY;
  const isDummy = !apiKey || ['your_hibp_api_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return { source: 'HaveIBeenPwned', status: 'no_key', breaches: [] };
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
// 4. EmailRep.io
// =============================================
async function checkEmailRep(email) {
  const apiKey = process.env.EMAILREP_API_KEY;
  const isDummy = !apiKey || ['your_emailrep_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return { source: 'EmailRep.io', status: 'no_key' };
  }
  try {
    const r = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`,
      { headers: { 'Key': apiKey, 'User-Agent': 'BreachIntelTool' }, timeout: 8000 });
    return { source: 'EmailRep.io', status: 'success', data: r.data };
  } catch (err) {
    return { source: 'EmailRep.io', status: 'error', message: err.message };
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
// MAIN
// =============================================
async function runIntelligence(query, type) {
  const results = { query, type, sources: [], summary: {}, phone_normalized: null };
  let totalBreaches = 0;
  let allDataClasses = [];

  if (type === 'email') {
    const [xon, hackmyip, hibp, emailrep] = await Promise.allSettled([
      checkXposedOrNot(query),
      checkHackMyIP(query),
      checkHIBP(query),
      checkEmailRep(query)
    ]);
    const xonData = xon.value || {};
    const hackData = hackmyip.value || {};
    const hibpData = hibp.value || {};
    const emailrepData = emailrep.value || {};

    results.sources.push(xonData, hackData, hibpData, emailrepData);

    totalBreaches = Math.max(
      xonData.breaches?.length || 0,
      hackData.found || 0,
      hibpData.breaches?.length || 0
    );
    xonData.breaches?.forEach(b => allDataClasses.push(...(b.DataClasses || [])));
    hibpData.breaches?.forEach(b => allDataClasses.push(...(b.DataClasses || [])));

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

  } else if (type === 'name') {
    const hackmyip = await checkHackMyIP(query);
    results.sources.push(hackmyip);
    totalBreaches = hackmyip.found || 0;
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