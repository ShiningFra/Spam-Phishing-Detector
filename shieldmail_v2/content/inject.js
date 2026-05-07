// ShieldMail v2 — Content Script (Gmail + Outlook)
'use strict';

let CFG = {
  apiUrl: 'http://localhost:8000',
  abuseipdbKey: '', virustotalKey: '',
  autoAnalyze: true, showBadges: true, showAlert: true,
};

chrome.storage.local.get(
  ['apiUrl','abuseipdbKey','virustotalKey','autoAnalyze','showBadges','showAlert'],
  d => Object.assign(CFG, d)
);
chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === 'SETTINGS_CHANGED') Object.assign(CFG, msg.settings);
});

const cache = new Map();

// ── Extraction texte / expéditeur / domaine ───────────────────────
function extractEmailInfo() {
  const BODY_SEL = [
    'div.a3s.aiL', 'div[data-message-id] .a3s',
    'div[aria-label="Message body"]', 'div.ReadingPaneContent div[dir]',
  ];
  let text = '';
  for (const s of BODY_SEL) {
    const el = document.querySelector(s);
    if (el && el.textContent.trim().length > 20) { text = el.textContent.trim().slice(0, 5000); break; }
  }

  // Expéditeur
  const senderEl = document.querySelector('span.gD, span[email]');
  const sender   = senderEl ? (senderEl.getAttribute('email') || senderEl.textContent) : '';

  // Domaine expéditeur
  const domainMatch = sender.match(/@([\w.-]+)/);
  const domain      = domainMatch ? domainMatch[1].toLowerCase() : '';

  // IP dans les URLs du corps
  const ipMatches = text.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g) || [];
  const ips = ipMatches.map(u => u.replace(/https?:\/\//, '').split('/')[0]);

  // Domaines dans les URLs
  const urlMatches = text.match(/https?:\/\/([^\/\s]+)/g) || [];
  const urlDomains = urlMatches.map(u => {
    try { return new URL(u).hostname; } catch { return ''; }
  }).filter(Boolean);

  return { text, sender, domain, ips, urlDomains };
}

// ── Panneau UI ────────────────────────────────────────────────────
function createPanel() {
  if (document.getElementById('sm-panel')) return;
  const el = document.createElement('div');
  el.id        = 'sm-panel';
  el.className = 'sm-hidden';
  el.innerHTML = `
    <div class="sm-header">
      <div class="sm-dot"></div>
      <span class="sm-title">ShieldMail</span>
      <span class="sm-badge-v">v2</span>
      <button class="sm-close">✕</button>
    </div>
    <div id="sm-verdict" class="sm-verdict">
      <div id="sm-icon" class="sm-vicon">🔍</div>
      <div>
        <div id="sm-class" class="sm-vclass">Analyse...</div>
        <div id="sm-sub"   class="sm-vsub">en cours</div>
      </div>
      <div class="sm-conf-wrap">
        <div id="sm-conf" class="sm-conf-num">—</div>
        <div class="sm-conf-lbl">confiance</div>
      </div>
    </div>

    <!-- Probas ML -->
    <div class="sm-section">
      <div class="sm-slabel">// Pipeline IA</div>
      <div class="sm-prow"><span class="sm-pname">HAM</span>
        <div class="sm-ptrack"><div class="sm-pfill ham" id="sm-ph"></div></div>
        <span class="sm-pval" id="sm-vh">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">SPAM</span>
        <div class="sm-ptrack"><div class="sm-pfill spam" id="sm-ps"></div></div>
        <span class="sm-pval" id="sm-vs">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">PHISHING</span>
        <div class="sm-ptrack"><div class="sm-pfill phishing" id="sm-pp"></div></div>
        <span class="sm-pval" id="sm-vp">0%</span></div>
    </div>

    <!-- IP Reputation -->
    <div class="sm-section" id="sm-ip-section" style="display:none">
      <div class="sm-slabel">// AbuseIPDB — Réputation IP</div>
      <div id="sm-ip-list" class="sm-iplist"></div>
    </div>

    <!-- VirusTotal -->
    <div class="sm-section" id="sm-vt-section" style="display:none">
      <div class="sm-slabel">// VirusTotal — Domaines</div>
      <div id="sm-vt-list" class="sm-vtlist"></div>
    </div>

    <!-- Flags -->
    <div class="sm-section">
      <div class="sm-slabel">// Indicateurs</div>
      <div id="sm-flags" class="sm-flags"></div>
    </div>

    <div class="sm-footer">
      <div class="sm-lat"><div class="sm-latdot"></div><span id="sm-latval">—</span></div>
      <button class="sm-reanalyze" id="sm-redo">↻ Réanalyser</button>
    </div>`;
  document.body.appendChild(el);
  el.querySelector('.sm-close').onclick = () => el.classList.replace('sm-visible','sm-hidden');
  el.querySelector('#sm-redo').onclick   = () => runAnalysis(true);
}

// ── Remplissage panneau ───────────────────────────────────────────
function fillPanel(r) {
  const p = document.getElementById('sm-panel'); if (!p) return;
  const cls = r.predicted_class || 'ham';
  const conf = r.global_confidence || 0;
  const ICONS  = { ham:'✓', spam:'✕', phishing:'⚠' };
  const LABELS = { ham:'Email légitime', spam:'Spam détecté', phishing:'Phishing — hameçonnage' };

  p.querySelector('#sm-verdict').className = `sm-verdict ${cls}`;
  p.querySelector('#sm-icon').textContent  = ICONS[cls];
  p.querySelector('#sm-class').textContent = cls.toUpperCase();
  p.querySelector('#sm-sub').textContent   = LABELS[cls];
  p.querySelector('#sm-conf').textContent  = `${(conf*100).toFixed(0)}%`;

  // Probas
  const pr = r.ml_probabilities || {};
  setTimeout(() => {
    [['ham','ph','vh'],['spam','ps','vs'],['phishing','pp','vp']].forEach(([k,fi,vi]) => {
      const v = (pr[k]||0)*100;
      const f = p.querySelector(`#sm-${fi}`); if(f) f.style.width=`${v.toFixed(1)}%`;
      const val = p.querySelector(`#sm-${vi}`); if(val) val.textContent=`${v.toFixed(0)}%`;
    });
  }, 100);

  // IP reputation
  if (r.ip_reputations && r.ip_reputations.length > 0) {
    const sec  = p.querySelector('#sm-ip-section');
    const list = p.querySelector('#sm-ip-list');
    sec.style.display = '';
    list.innerHTML = r.ip_reputations.map(ip => {
      const score = ip.abuseScore || 0;
      const color = score >= 75 ? 'danger' : score >= 15 ? 'warning' : 'ok';
      return `<div class="sm-ip-row">
        <span class="sm-flag ${color}">${ip.ip}</span>
        <span class="sm-ip-score ${color}">${score}% abuse</span>
        <span class="sm-ip-meta">${ip.countryCode} · ${ip.totalReports} signalements</span>
      </div>`;
    }).join('');
  }

  // VirusTotal
  if (r.domain_reputations && r.domain_reputations.length > 0) {
    const sec  = p.querySelector('#sm-vt-section');
    const list = p.querySelector('#sm-vt-list');
    sec.style.display = '';
    list.innerHTML = r.domain_reputations.map(d => {
      const color = d.malicious > 3 ? 'danger' : d.malicious > 0 ? 'warning' : 'ok';
      return `<div class="sm-vt-row">
        <span class="sm-flag ${color}">${d.domain}</span>
        <span class="sm-vt-score ${color}">${d.malicious}/${d.total} détections</span>
      </div>`;
    }).join('');
  }

  // Flags ML
  const allFlags = [
    ...(r.rules_triggered||[]).map(f=>({t:f,c:'warning'})),
    ...(r.url_flags||[]).map(f=>({t:f,c:'danger'})),
  ];
  p.querySelector('#sm-flags').innerHTML = allFlags.length > 0
    ? allFlags.map(f=>`<span class="sm-flag ${f.c}">${f.t}</span>`).join('')
    : '<span class="sm-flag ok">Aucun indicateur suspect</span>';

  // Latence
  const lat = r.latency_ms ? `${r.latency_ms.toFixed(1)}ms` : '—';
  p.querySelector('#sm-latval').textContent = `Pipeline: ${lat}`;
}

// ── Alerte critique ───────────────────────────────────────────────
function showAlert(r) {
  if (!CFG.showAlert) return;
  const threat = r.threat_level || r.ip_reputations?.find(i=>i.abuseScore>75) ? 'critical' : '';
  if (!['high','critical'].includes(r.threat_level) &&
      !(r.ip_reputations || []).some(i => i.abuseScore >= 75) &&
      !(r.domain_reputations || []).some(d => d.malicious > 3)) return;

  let el = document.getElementById('sm-alert');
  if (!el) { el = document.createElement('div'); el.id = 'sm-alert'; document.body.appendChild(el); }

  const ipHit = (r.ip_reputations || []).find(i => i.abuseScore >= 75);
  const vtHit = (r.domain_reputations || []).find(d => d.malicious > 3);
  let reason  = `IA : ${r.predicted_class} (${((r.global_confidence||0)*100).toFixed(0)}%)`;
  if (ipHit) reason += ` · IP ${ipHit.ip} — ${ipHit.abuseScore}% abuse`;
  if (vtHit) reason += ` · ${vtHit.domain} — ${vtHit.malicious} détections VT`;

  el.className = 'sm-alert-bar';
  el.innerHTML = `
    <span class="sm-alert-icon">🚨</span>
    <div class="sm-alert-txt">
      <b>ShieldMail — Menace détectée</b><br>
      <small>${reason}</small>
    </div>
    <button onclick="this.parentElement.remove()">✕</button>`;
  setTimeout(() => el?.remove(), 10000);
}

// ── Analyse principale ────────────────────────────────────────────
async function runAnalysis(force = false) {
  const key = window.location.href;
  if (!force && cache.has(key)) {
    const p = document.getElementById('sm-panel') || (createPanel(), document.getElementById('sm-panel'));
    p.className = 'sm-visible'; fillPanel(cache.get(key)); return;
  }

  const { text, sender, domain, ips, urlDomains } = extractEmailInfo();
  if (!text) return;

  const panel = document.getElementById('sm-panel') || (createPanel(), document.getElementById('sm-panel'));
  panel.querySelector('#sm-class').textContent = 'Analyse...';
  panel.querySelector('#sm-icon').textContent  = '⟳';
  panel.querySelector('#sm-conf').textContent  = '—';
  panel.className = 'sm-visible';

  // Lancer les 3 couches en parallèle
  const [mlResult, ipResults, domainResults] = await Promise.all([
    // 1. Pipeline IA local
    chrome.runtime.sendMessage({ type:'ANALYZE_EMAIL', text, apiUrl: CFG.apiUrl })
      .then(r => r.ok ? r.result : buildFallback(text))
      .catch(() => buildFallback(text)),

    // 2. AbuseIPDB pour chaque IP trouvée
    Promise.all(
      ips.slice(0, 3).map(ip =>
        chrome.runtime.sendMessage({ type:'CHECK_IP', ip, abuseipdbKey: CFG.abuseipdbKey })
          .then(r => r.ok ? r.result : null).catch(() => null)
      )
    ).then(rs => rs.filter(Boolean)),

    // 3. VirusTotal pour les domaines suspects
    Promise.all(
      [...new Set([domain, ...urlDomains])].slice(0, 3).map(d =>
        chrome.runtime.sendMessage({ type:'CHECK_DOMAIN', domain: d, virustotalKey: CFG.virustotalKey })
          .then(r => r.ok ? r.result : null).catch(() => null)
      )
    ).then(rs => rs.filter(Boolean)),
  ]);

  // Fusion du résultat final
  const result = {
    ...mlResult,
    ip_reputations:     ipResults,
    domain_reputations: domainResults,
    threat_level:       aggregateThreat(mlResult, ipResults, domainResults),
  };

  cache.set(key, result);
  fillPanel(result);
  showAlert(result);

  chrome.runtime.sendMessage({
    type: 'SAVE_RESULT', result,
    preview: text.slice(0, 60),
  });
}

function aggregateThreat(ml, ips, domains) {
  const ORDER = ['none','low','medium','high','critical'];
  const levels = [
    ml.threat_level || 'none',
    ...(ips.map(i => i.threatLevel || 'none')),
    ...(domains.map(d => d.threatLevel || 'none')),
  ];
  return levels.reduce((worst, l) =>
    ORDER.indexOf(l) > ORDER.indexOf(worst) ? l : worst, 'none');
}

function buildFallback(text) {
  const t = text.toLowerCase();
  const p = ['verify','suspended','login','paypal','bank','password'].filter(k=>t.includes(k)).length;
  const s = ['free','win','congratulations','click now','!!!'].filter(k=>t.includes(k)).length;
  let cls='ham', conf=0.88, threat='none';
  if (p>=2){cls='phishing';conf=0.82;threat='critical';}
  else if(s>=2){cls='spam';conf=0.78;threat='high';}
  const rest=(1-conf)/2;
  return { predicted_class:cls, threat_level:threat, global_confidence:conf,
    ml_probabilities:{ham:rest,spam:rest,phishing:rest,[cls]:conf},
    rules_triggered:[], url_flags:[], header_flags:[], latency_ms:0, _demo:true };
}

// ── Badges sur la liste ───────────────────────────────────────────
function addBadges() {
  if (!CFG.showBadges) return;
  document.querySelectorAll('tr.zA, div[role="option"]').forEach(row => {
    if (row.querySelector('.sm-badge')) return;
    const subjectEl = row.querySelector('span.bqe, span.bog, div[data-testid]');
    if (!subjectEl) return;
    const badge = document.createElement('span');
    badge.className = 'sm-badge loading';
    badge.textContent = '···';
    subjectEl.parentElement?.appendChild(badge);
    const snippet = row.querySelector('.y2')?.textContent || '';
    const text    = (subjectEl.textContent + ' ' + snippet).trim();
    if (!text) { badge.remove(); return; }
    chrome.runtime.sendMessage({ type:'ANALYZE_EMAIL', text, apiUrl: CFG.apiUrl })
      .then(r => {
        if (!r.ok) throw new Error();
        const cls  = r.result.predicted_class;
        const conf = ((r.result.global_confidence||0)*100).toFixed(0);
        badge.className   = `sm-badge ${cls}`;
        badge.textContent = `${cls} ${conf}%`;
      })
      .catch(() => { badge.remove(); });
  });
}

// ── Observer ──────────────────────────────────────────────────────
let lastUrl = '';
new MutationObserver(() => {
  const url = window.location.href;
  if (url !== lastUrl) {
    lastUrl = url;
    if (/\/(inbox|spam|sent|all|starred)\/[a-f0-9]+/.test(url) ||
        /outlook.*\/mail\//.test(url)) {
      if (CFG.autoAnalyze) setTimeout(() => runAnalysis(), 900);
    }
    if (CFG.showBadges) setTimeout(addBadges, 1500);
  }
}).observe(document.body, { childList:true, subtree:true });

// ── Init ──────────────────────────────────────────────────────────
createPanel();
if (CFG.autoAnalyze) setTimeout(() => runAnalysis(), 2000);
if (CFG.showBadges)  setTimeout(addBadges, 2500);
