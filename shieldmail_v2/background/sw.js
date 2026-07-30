// ShieldMail v2 — Service Worker
// Gere les appels aux APIs externes (AbuseIPDB, VirusTotal) depuis le service
// worker pour eviter les problemes CORS, et la persistance de l'historique
// détaillé des scans (paramètres complets, pour le dashboard).

'use strict';

const MAX_HISTORY = 500;   // historique détaillé complet (dashboard)
const MAX_RECENTS = 20;    // aperçu rapide (popup)

// ── Init ──────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(details => {
  chrome.storage.local.get(['setupComplete'], d => {
    // Ne réinitialise jamais une configuration déjà présente (ex. mise à jour de l'extension)
    chrome.storage.local.set({
      apiUrl:        d.apiUrl        ?? 'http://localhost:8000',
      abuseipdbKey:  d.abuseipdbKey  ?? '',
      virustotalKey: d.virustotalKey ?? '',
      setupComplete: d.setupComplete ?? false,
      autoAnalyze:   d.autoAnalyze   ?? true,
      showBadges:    d.showBadges    ?? true,
      showAlert:     d.showAlert     ?? true,
      theme:         d.theme         ?? 'cyber',
      font:          d.font          ?? 'moderne',
      detailLevel:   d.detailLevel   ?? 'full', // full | compact | minimal
      stats:         d.stats         ?? { ham: 0, spam: 0, phishing: 0, corrections: 0 },
      recents:       d.recents       ?? [],
      scanHistory:   d.scanHistory   ?? [],
    });

    // Config initiale définitive : demandée une seule fois, à la première installation
    if (details.reason === 'install' && !d.setupComplete) {
      chrome.tabs.create({ url: chrome.runtime.getURL('options/options.html?first=1') });
    }
  });
});

// ── Cache IP/domaine (evite de requeter deux fois) ────────────────
const ipCache     = new Map();
const domainCache = new Map();
const dnsCache     = new Map();

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

  if (msg.type === 'RESOLVE_DOMAIN_IP') {
    resolveDomainIp(msg.domain)
      .then(ip => sendResponse({ ok: true, ip }))
      .catch(e => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'ANALYZE_EMAIL') {
    analyzeWithLocalApi(msg.text, msg.apiUrl, msg.authSignals)
      .then(result => sendResponse({ ok: true, result }))
      .catch(e    => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'SAVE_RESULT') {
    saveResult(msg.result, msg.preview, msg.meta);
    // Notifie le popup/dashboard (s'ils sont ouverts) pour rafraîchir en direct
    chrome.runtime.sendMessage({ type: 'ANALYSIS_DONE' }).catch(() => {});
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'SAVE_CORRECTION') {
    saveCorrection(msg.recordId, msg.correctLabel);
    chrome.runtime.sendMessage({ type: 'ANALYSIS_DONE' }).catch(() => {});
    sendResponse({ ok: true });
    return false;
  }
});

// ── API locale (pipeline hybride) ────────────────────────────────
async function analyzeWithLocalApi(text, apiUrl, authSignals) {
  const url = (apiUrl || 'http://localhost:8000').replace(/\/$/, '');
  const r   = await fetch(`${url}/analyze`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ text, auth_signals: authSignals || null }),
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
    // Classification
    threatLevel: scoreThreatLevel(data.abuseConfidenceScore || 0),
  };

  ipCache.set(ip, result);
  // Cache TTL 10 min
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

// ── Résolution DNS (dernier recours pour AbuseIPDB) ────────────────
// Utilisée uniquement quand ni les en-têtes bruts ni le corps du message
// ne contiennent d'IP exploitable. Passe par DNS-over-HTTPS (Cloudflare)
// plutôt que par une résolution DNS système (inaccessible depuis une
// extension). Fait depuis le service worker comme AbuseIPDB/VirusTotal,
// pour éviter tout blocage CORS côté page.
async function resolveDomainIp(domain) {
  if (!domain) return null;
  if (dnsCache.has(domain)) return dnsCache.get(domain);

  const r = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
    { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) }
  );
  if (!r.ok) throw new Error(`DoH ${r.status}`);
  const json = await r.json();
  const answer = (json.Answer || []).find(a => a.type === 1); // type 1 = A record
  const ip = answer ? answer.data : null;

  dnsCache.set(domain, ip);
  setTimeout(() => dnsCache.delete(domain), 10 * 60 * 1000);
  return ip;
}

// ── Sauvegarde dans le storage ────────────────────────────────────
// `result.composite` porte le score de fusion multicouche calculé côté
// content script (voir fuseLayers() dans inject.js) : IA locale + headers
// d'authentification + AbuseIPDB + VirusTotal superposés, pas juste un
// "pire des cas" en secours. C'est ce score qui alimente stats + historique.
function saveResult(result, preview, meta) {
  chrome.storage.local.get(['stats', 'recents', 'scanHistory'], d => {
    const stats   = d.stats   || { ham:0, spam:0, phishing:0, corrections:0 };
    const recents = d.recents || [];
    const history = d.scanHistory || [];
    const cls     = result.predicted_class || 'ham';
    stats[cls] = (stats[cls] || 0) + 1;

    const id = `${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
    const record = {
      id,
      ts: Date.now(),
      time: new Date().toLocaleTimeString('fr-FR'),
      cls,
      conf: ((result.global_confidence || 0) * 100).toFixed(0),
      composite: result.composite || null,          // { score, level, layers:{ai,auth,ip,domain} }
      preview: (preview || '').slice(0, 80),
      sender: meta?.sender || '',
      domain: meta?.domain || '',
      source: meta?.mailClient || 'gmail',
      headerSource: result.auth_signals?.source || 'dom-heuristic',
      ip_reputations: result.ip_reputations || [],
      domain_reputations: result.domain_reputations || [],
      auth_signals: result.auth_signals || null,
      rules_triggered: result.rules_triggered || [],
      url_flags: result.url_flags || [],
      latency_ms: result.latency_ms || 0,
      corrected: null,
    };
    history.unshift(record);
    if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;

    // "recents" reste un aperçu compact pour le popup
    recents.unshift({
      cls, conf: record.conf, preview: record.preview,
      ip_score: result.ip_reputations?.[0]?.abuseScore ?? null,
      vt_hits:  result.domain_reputations?.[0]?.malicious ?? null,
      composite: result.composite?.score ?? null,
      time: record.time,
    });
    if (recents.length > MAX_RECENTS) recents.pop();

    chrome.storage.local.set({ stats, recents, scanHistory: history });
  });
}

// ── Correction post-entraînement : mise à jour des stats + historique ──
function saveCorrection(recordId, correctLabel) {
  chrome.storage.local.get(['stats', 'scanHistory'], d => {
    const stats = d.stats || { ham:0, spam:0, phishing:0, corrections:0 };
    stats.corrections = (stats.corrections || 0) + 1;
    const history = d.scanHistory || [];
    const rec = recordId && history.find(h => h.id === recordId);
    if (rec) rec.corrected = correctLabel;
    chrome.storage.local.set({ stats, scanHistory: history });
  });
}
