// ShieldMail v2 — Service Worker (corrigé)
// Gere les appels aux APIs externes (AbuseIPDB, VirusTotal)
// depuis le service worker pour eviter les problemes CORS

'use strict';

// ── Init ──────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    apiUrl:        'http://localhost:8000',
    abuseipdbKey:  '',
    virustotalKey: '',
    autoAnalyze:   true,
    showBadges:    true,
    showAlert:     true,
    stats:  { ham: 0, spam: 0, phishing: 0 },
    recents: [],
  });
});

// ── Cache IP/domaine (evite de requeter deux fois) ────────────────
const ipCache     = new Map();
const domainCache = new Map();

// ── Listener principal ────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === 'CHECK_IP') {
    checkIp(msg.ip, msg.abuseipdbKey)
      .then(result => sendResponse({ ok: true, result }))
      .catch(e    => sendResponse({ ok: false, error: e.message }));
    return true; // async
  }

  if (msg.type === 'CHECK_DOMAIN') {
    checkDomain(msg.domain, msg.virustotalKey)
      .then(result => sendResponse({ ok: true, result }))
      .catch(e    => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'ANALYZE_EMAIL') {
    analyzeWithLocalApi(msg.text, msg.apiUrl)
      .then(result => sendResponse({ ok: true, result }))
      .catch(e    => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'SAVE_RESULT') {
    saveResult(msg.result, msg.preview);
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'ANALYSIS_DONE') {
    chrome.runtime.sendMessage(msg).catch(() => {});
    return false;
  }
});

// ── API locale (pipeline hybride) ────────────────────────────────
async function analyzeWithLocalApi(text, apiUrl) {
  const url = (apiUrl || 'http://localhost:8000').replace(/\/$/, '');
  const r   = await fetch(`${url}/analyze`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ text }),
    signal:  AbortSignal.timeout(15000),
  });
  if (!r.ok) throw new Error(`API ${r.status}`);
  return r.json();
}

// ── AbuseIPDB ─────────────────────────────────────────────────────
async function checkIp(ip, apiKey) {
  if (!ip || !apiKey) return null;
  if (ipCache.has(ip)) return ipCache.get(ip);

  const r = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
    {
      headers: {
        'Key':    apiKey,
        'Accept': 'application/json',
      },
      signal: AbortSignal.timeout(8000),
    }
  );
  if (!r.ok) throw new Error(`AbuseIPDB ${r.status}`);
  const json = await r.json();
  const data = json.data || {};

  const result = {
    ip,
    abuseScore:       data.abuseConfidenceScore || 0,   // 0-100
    totalReports:     data.totalReports          || 0,
    lastReportedAt:   data.lastReportedAt        || null,
    countryCode:      data.countryCode           || '??',
    isp:              data.isp                   || '',
    usageType:        data.usageType             || '',
    isWhitelisted:    data.isWhitelisted          || false,
    threatLevel: scoreThreatLevel(data.abuseConfidenceScore || 0),
  };

  ipCache.set(ip, result);
  setTimeout(() => ipCache.delete(ip), 10 * 60 * 1000);
  return result;
}

// ── VirusTotal ────────────────────────────────────────────────────
async function checkDomain(domain, apiKey) {
  if (!domain || !apiKey) return null;
  if (domainCache.has(domain)) return domainCache.get(domain);

  const r = await fetch(
    `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
    {
      headers: { 'x-apikey': apiKey },
      signal:  AbortSignal.timeout(8000),
    }
  );
  if (!r.ok) throw new Error(`VirusTotal ${r.status}`);
  const json = await r.json();
  const stats = json.data?.attributes?.last_analysis_stats || {};
  const votes = json.data?.attributes?.total_votes         || {};

  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const total      = Object.values(stats).reduce((a,b) => a+b, 0) || 1;

  const result = {
    domain,
    malicious,
    suspicious,
    harmless:    stats.harmless    || 0,
    undetected:  stats.undetected  || 0,
    total,
    maliciousRatio: malicious / total,
    categories:  json.data?.attributes?.categories || {},
    reputation:  json.data?.attributes?.reputation || 0,
    communityVoteMalicious: votes.malicious || 0,
    threatLevel: malicious > 3 ? 'critical' : malicious > 0 ? 'high' : suspicious > 2 ? 'medium' : 'none',
  };

  domainCache.set(domain, result);
  setTimeout(() => domainCache.delete(domain), 10 * 60 * 1000);
  return result;
}

// ── Helper niveau de menace IP ────────────────────────────────────
function scoreThreatLevel(score) {
  if (score >= 75) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 15) return 'medium';
  if (score >   0) return 'low';
  return 'none';
}

// ── Sauvegarde dans le storage ────────────────────────────────────
// Correction : le content script transmet `ip_reputations` et
// `domain_reputations` (listes, pluriel) — l'ancienne version lisait
// `ip_reputation` / `domain_reputation` (singulier, jamais peuplés).
// On prend systématiquement le pire score de chaque liste.
function saveResult(result, preview) {
  chrome.storage.local.get(['stats','recents'], d => {
    const stats   = d.stats   || { ham:0, spam:0, phishing:0 };
    const recents = d.recents || [];
    const cls     = result.predicted_class || 'ham';
    stats[cls] = (stats[cls] || 0) + 1;

    const worstIp = (result.ip_reputations||[])
      .reduce((max,ip)=> (ip.abuseScore||0) > (max?.abuseScore||0) ? ip : max, null);
    const worstDom = (result.domain_reputations||[])
      .reduce((max,d)=> (d.malicious||0) > (max?.malicious||0) ? d : max, null);

    recents.unshift({
      cls,
      conf:    ((result.global_confidence || 0) * 100).toFixed(0),
      preview: (preview || '').slice(0, 55),
      ip_score: worstIp?.abuseScore ?? null,
      vt_hits:  worstDom?.malicious ?? null,
      time:    new Date().toLocaleTimeString('fr-FR'),
    });
    if (recents.length > 20) recents.pop();
    chrome.storage.local.set({ stats, recents });
  });
}
