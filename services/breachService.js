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

async function checkHIBP(email) {
  const apiKey = process.env.HIBP_API_KEY;
  const isDummy = !apiKey || ['your_hibp_api_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'HaveIBeenPwned', status: 'demo',
      breaches: [
        { Name: 'Adobe', BreachDate: '2013-10-04', DataClasses: ['Email addresses','Passwords','Password hints','Usernames'], IsVerified: true, PwnCount: 152445165 },
        { Name: 'LinkedIn', BreachDate: '2016-05-22', DataClasses: ['Email addresses','Passwords'], IsVerified: true, PwnCount: 164611595 }
      ]
    };
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

async function checkEmailRep(email) {
  const apiKey = process.env.EMAILREP_API_KEY;
  const isDummy = !apiKey || ['your_emailrep_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'EmailRep.io', status: 'demo',
      data: { email, reputation: 'medium', suspicious: false, references: 42,
        details: { blacklisted: false, credentials_leaked: true, data_breach: true, first_seen: '2015-01-01', last_seen: '2024-12-01', profiles: ['facebook','linkedin','twitter'] }
      }
    };
  }
  try {
    const r = await axios.get(`https://emailrep.io/${encodeURIComponent(email)}`,
      { headers: { 'Key': apiKey, 'User-Agent': 'BreachIntelTool' }, timeout: 8000 });
    return { source: 'EmailRep.io', status: 'success', data: r.data };
  } catch (err) {
    return { source: 'EmailRep.io', status: 'error', message: err.message };
  }
}

async function checkLeakCheck(query, type = 'email') {
  const apiKey = process.env.LEAKCHECK_API_KEY;
  const isDummy = !apiKey || ['your_leakcheck_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'LeakCheck', status: 'demo', found: 3,
      results: [
        { source: { name: 'Collection#1', breach_date: '2019-01-07' }, line: `${query}:password123` },
        { source: { name: 'Verifications.io', breach_date: '2019-02-25' }, line: `${query}:p@ssw0rd` },
        { source: { name: 'Exploit.in', breach_date: '2015-01-01' }, line: `${query}:qwerty123` }
      ]
    };
  }
  try {
    const r = await axios({
      method: 'get',
      url: `https://leakcheck.io/api/v2/query/${encodeURIComponent(query)}`,
      headers: {
        'X-API-Key': apiKey.trim(),
        'Accept': 'application/json',
        'User-Agent': 'BreachIntelTool'
      },
      timeout: 10000
    });
    return { source: 'LeakCheck', status: 'success', ...r.data };
  } catch (err) {
    return { source: 'LeakCheck', status: 'error', message: err.response?.data?.error || err.message };
  }
}

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

async function checkHunter(domain) {
  const apiKey = process.env.HUNTER_API_KEY;
  const isDummy = !apiKey || ['your_hunter_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'Hunter.io', status: 'demo',
      data: { domain, organization: 'Demo Organization', emails_found: 127,
        emails: [
          { value: `admin@${domain}`, type: 'generic', confidence: 95 },
          { value: `info@${domain}`, type: 'generic', confidence: 90 },
          { value: `support@${domain}`, type: 'generic', confidence: 85 }
        ],
        technologies: ['WordPress','Cloudflare','Google Analytics']
      }
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

async function checkShodan(domain) {
  const apiKey = process.env.SHODAN_API_KEY;
  const isDummy = !apiKey || ['your_shodan_key_here','dummy'].includes(apiKey);
  if (isDummy) {
    return {
      source: 'Shodan', status: 'demo',
      data: { domain, subdomains: ['www','mail','ftp','api','dev'], open_ports: [80,443,22,3306], vulnerabilities: ['CVE-2021-44228','CVE-2022-0778'], tags: ['self-signed','cloud'] }
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

async function runIntelligence(query, type) {
  const results = { query, type, sources: [], summary: {}, phone_normalized: null };
  let totalBreaches = 0;
  let allDataClasses = [];

  if (type === 'email') {
    const [hibp, emailrep, leakcheck] = await Promise.allSettled([
      checkHIBP(query), checkEmailRep(query), checkLeakCheck(query, 'email')
    ]);
    const hibpData = hibp.value || {}, emailrepData = emailrep.value || {}, leakData = leakcheck.value || {};
    results.sources.push(hibpData, emailrepData, leakData);
    totalBreaches = (hibpData.breaches?.length || 0) + (leakData.found || 0);
    hibpData.breaches?.forEach(b => allDataClasses.push(...(b.DataClasses || [])));

  } else if (type === 'phone') {
    const normalized = normalizePhone(query);
    results.phone_normalized = normalized;
    const [numverify, abstractapi, leakcheck] = await Promise.allSettled([
      checkNumVerify(query), checkAbstractPhone(query), checkLeakCheck(normalized.e164, 'phone')
    ]);
    const nvData = numverify.value || {}, abData = abstractapi.value || {}, lcData = leakcheck.value || {};
    results.sources.push(nvData, abData, lcData);
    totalBreaches = lcData.found || 0;

  } else if (type === 'domain') {
    const [hibp, hunter, shodan] = await Promise.allSettled([
      checkHIBP(query), checkHunter(query), checkShodan(query)
    ]);
    results.sources.push(hibp.value || {}, hunter.value || {}, shodan.value || {});
    totalBreaches = hibp.value?.breaches?.length || 0;

  } else if (type === 'name') {
    const leakcheck = await checkLeakCheck(query, 'name');
    results.sources.push(leakcheck);
    totalBreaches = leakcheck.found || 0;
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