// ShieldMail v2.3 — Content Script
'use strict';

let CFG = {
  apiUrl:'http://localhost:8000', abuseipdbKey:'', virustotalKey:'',
  autoAnalyze:true, showBadges:true, showAlert:true,
  theme:'cyber', font:'moderne', detailLevel:'full',
};
chrome.storage.local.get(
  ['apiUrl','abuseipdbKey','virustotalKey','autoAnalyze','showBadges','showAlert','theme','font','detailLevel'],
  d => { Object.assign(CFG, d); smApplyTheme(document.documentElement, CFG.theme, CFG.font); }
);
chrome.runtime.onMessage.addListener(msg => {
  if (msg.type==='SETTINGS_CHANGED') {
    const badgesWereOn = CFG.showBadges;
    Object.assign(CFG, msg.settings);
    if (msg.settings.theme || msg.settings.font) smApplyTheme(document.documentElement, CFG.theme, CFG.font);
    if (msg.settings.detailLevel) applyDetailLevel();
    // showBadges désactivé : retire immédiatement les badges déjà affichés
    // au lieu de les laisser visibles jusqu'au prochain rechargement de page
    if (badgesWereOn && !CFG.showBadges) {
      document.querySelectorAll('.sm-badge').forEach(b => b.remove());
      document.querySelectorAll('[data-sm-scanned]').forEach(r => r.removeAttribute('data-sm-scanned'));
    }
    // showBadges réactivé : relance un scan immédiat plutôt que d'attendre le prochain cycle
    if (!badgesWereOn && CFG.showBadges) {
      scanVisibleEmails();
    }
  }
});

const analysisCache = new Map();

// ── Envoi de message sécurisé ────────────────────────────────────
// chrome.runtime.sendMessage peut lancer une exception SYNCHRONE (pas un
// rejet de promesse) quand l'extension a été rechargée pendant qu'un onglet
// Gmail reste ouvert ("Extension context invalidated"). Un simple .catch()
// chaîné après l'appel ne suffit donc pas à l'intercepter — d'où ce wrapper,
// utilisé pour TOUS les appels sendMessage de ce fichier.
function smSendMessage(msg) {
  try {
    if (!chrome.runtime?.id) return Promise.resolve({ ok: false, error: 'context-invalidated' });
    return chrome.runtime.sendMessage(msg).catch(e => ({ ok: false, error: e?.message || 'sendMessage failed' }));
  } catch (e) {
    return Promise.resolve({ ok: false, error: e?.message || 'context-invalidated' });
  }
}

// ══════════════════════════════════════════════════════════════════
// EXTRACTION — message original (source brute) en priorité
// ══════════════════════════════════════════════════════════════════
// Gmail expose la "source brute" du message via son écran "Afficher
// l'original" (menu ⋮ d'un email ouvert). Cette page contient les vrais
// en-têtes (Received, Authentication-Results avec spf=/dkim=/dmarc=,
// Return-Path...) — bien plus fiables que le DOM rendu. On la récupère
// directement en fetch same-origin (les cookies de session suivent
// automatiquement) plutôt que de se contenter d'un proxy DOM.
//
// ⚠ Ceci s'appuie sur la structure interne non documentée de Gmail (jeton
// "ik" et identifiant de fil repris depuis l'URL). Si Gmail change cette
// structure, la fonction échoue proprement et le code retombe sur
// l'heuristique DOM existante — jamais de blocage ni de faux positif.
function getIkToken() {
  const m = document.documentElement.innerHTML.match(/[?&]ik=([0-9a-f]{6,})/);
  return m ? m[1] : null;
}
function getAccountIndex() {
  const m = location.pathname.match(/\/mail\/u\/(\d+)\//);
  return m ? m[1] : '0';
}
function getThreadIdFromHash() {
  const h = decodeURIComponent(location.hash || '');
  const m = h.match(/[#/]([0-9A-Za-z_-]{16,})$/);
  return m ? m[1] : null;
}

async function fetchOriginalMessageRaw() {
  try {
    const ik = getIkToken();
    const th = getThreadIdFromHash();
    if (!ik || !th) return null;
    const u = getAccountIndex();
    const url = `https://mail.google.com/mail/u/${u}/?ik=${ik}&view=om&th=${th}`;
    const res = await fetch(url, { credentials: 'same-origin', signal: AbortSignal.timeout(6000) });
    if (!res.ok) return null;
    const html = await res.text();
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('wbr').forEach(w => w.remove());
    const container = doc.querySelector('div.AO, div.h7, pre') || doc.body;
    const raw = container ? container.textContent : '';
    return raw && raw.length > 40 ? raw : null;
  } catch { return null; }
}

// ── Dernier recours : résolution DNS du domaine expéditeur ─────────
// Si ni les en-têtes bruts ni le corps du message ne contiennent d'IP
// exploitable (cas fréquent — la plupart des emails, légitimes ou non, ne
// contiennent aucune IP littérale), on résout l'IP du domaine expéditeur
// via DNS-over-HTTPS (Cloudflare) plutôt que de laisser la couche
// AbuseIPDB vide. Fait via le service worker pour éviter tout souci de
// CORS, comme pour AbuseIPDB/VirusTotal. Ce n'est PAS forcément l'IP réelle
// du serveur d'envoi (elle peut être derrière un load-balancer, un
// fournisseur d'emailing mutualisé, etc.) — l'UI l'indique clairement.
async function resolveDomainIp(domain) {
  if (!domain) return null;
  const r = await smSendMessage({ type: 'RESOLVE_DOMAIN_IP', domain });
  return r.ok ? r.ip : null;
}

// Parse les en-têtes bruts pour en tirer de vrais signaux d'authentification
// (SPF/DKIM/DMARC) et les IP des relais "Received", au lieu de la simple
// comparaison mailed-by/signed-by affichée par Gmail.
function parseRawHeaders(raw) {
  const headerBlock = raw.split(/\n\r?\n/)[0] || raw;
  const get = (name) => {
    const re = new RegExp(`^${name}:\\s*([^\\n]*(?:\\n[ \\t][^\\n]*)*)`, 'im');
    const m = headerBlock.match(re);
    return m ? m[1].replace(/\s+/g, ' ').trim() : '';
  };
  const from = get('From');
  const returnPath = get('Return-Path');
  const authResults = get('Authentication-Results');

  const domainOf = (addr) => { const m = (addr||'').match(/@([\w.-]+)/); return m ? m[1].toLowerCase().replace(/[>\s]/g,'') : ''; };
  const fromDomain = domainOf(from);
  const rpDomain = domainOf(returnPath);

  const pick = (mech) => {
    const m = authResults.match(new RegExp(`${mech}=(pass|fail|softfail|neutral|none|temperror|permerror)`, 'i'));
    return m ? m[1].toLowerCase() : 'none';
  };
  const spf = pick('spf');
  const dkim = pick('dkim');
  const dmarc = pick('dmarc');

  // Extraction élargie des IP : toutes les lignes "Received" (repliées sur
  // plusieurs lignes), avec ou sans crochets, plus les en-têtes ponctuels
  // que certains relais ajoutent. On écarte les IP privées/internes
  // (relais internes de Gmail par ex.) qui n'ont aucun intérêt pour une
  // réputation AbuseIPDB.
  const isPrivateIp = ip => /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
  const ipSet = new Set();
  const receivedBlocks = headerBlock.match(/^Received:[^\n]*(?:\n[ \t][^\n]*)*/gim) || [];
  receivedBlocks.forEach(block => {
    (block.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g) || []).forEach(ip => ipSet.add(ip));
  });
  ['X-Originating-IP', 'X-Sender-IP', 'X-Client-IP', 'X-Source-IP'].forEach(h => {
    const m = get(h).match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
    if (m) ipSet.add(m[0]);
  });
  const ips = [...ipSet].filter(ip => !isPrivateIp(ip)).slice(0, 6);

  const failed = [spf, dkim, dmarc].filter(v => v === 'fail').length;
  const mismatch = failed > 0 || (rpDomain && fromDomain && !rpDomain.includes(fromDomain) && !fromDomain.includes(rpDomain));

  return {
    available: !!(from || authResults),
    source: 'raw-headers',
    fromDomain, returnPathDomain: rpDomain,
    spf, dkim, dmarc,
    mismatch,
    relayIps: ips,
  };
}

// ── Extraction (DOM — fallback si le message original est inaccessible) ──
function extractEmailInfo() {
  const BODY = ['div.a3s.aiL','div[data-message-id] .a3s','div[aria-label="Message body"]','.ii.gt div'];
  let text = '';
  for (const s of BODY) {
    const el = document.querySelector(s);
    if (el && el.textContent.trim().length > 20) { text = el.textContent.trim().slice(0,5000); break; }
  }
  const senderEl = document.querySelector('span.gD, span[email]');
  const sender   = senderEl ? (senderEl.getAttribute('email') || senderEl.textContent) : '';
  const dm       = sender.match(/@([\w.-]+)/);
  const domain   = dm ? dm[1].toLowerCase() : '';
  const ips      = (text.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g)||[])
                     .map(u=>u.replace(/https?:\/\//,'').split('/')[0]);
  const urlDoms  = (text.match(/https?:\/\/([^\/\s"'<>]+)/g)||[])
                     .map(u=>{try{return new URL(u).hostname;}catch{return '';}}).filter(Boolean);
  const authSignalsDom = extractAuthSignalsDom(domain, senderEl);
  return {text,sender,domain,ips,urlDomains:urlDoms,authSignalsDom};
}

// Heuristique DOM (repli) : Gmail/Outlook n'exposent pas toujours les
// en-têtes bruts au premier clic — on s'appuie alors sur les lignes
// "mailed-by" / "signed-by" que Gmail calcule et affiche lui-même.
function extractAuthSignalsDom(fromDomain, senderEl) {
  const result = { mailedBy: '', signedBy: '', available: false, mismatch: false, source: 'dom-heuristic' };
  if (!senderEl) return result;

  let scope = senderEl;
  for (let i = 0; i < 6 && scope.parentElement; i++) scope = scope.parentElement;

  const LABELS = {
    mailedBy: ['mailed-by', 'envoyé par', 'envoye par'],
    signedBy: ['signed-by', 'signé par', 'signe par'],
  };
  const nodes = scope.querySelectorAll('span, td, div');
  for (const el of nodes) {
    const txt = (el.textContent || '').trim().toLowerCase();
    if (!txt || txt.length > 40) continue;
    for (const [key, variants] of Object.entries(LABELS)) {
      if (variants.includes(txt) && el.nextElementSibling) {
        const value = el.nextElementSibling.textContent.trim().toLowerCase();
        if (value) { result[key] = value; result.available = true; }
      }
    }
  }

  if (result.available) {
    const norm = d => (d || '').replace(/^www\./, '');
    const from = norm(fromDomain);
    const mismatchOn = v => v && from && !v.includes(from) && !from.includes(v);
    result.mismatch = mismatchOn(norm(result.mailedBy)) || mismatchOn(norm(result.signedBy));
  }
  return result;
}

// ══════════════════════════════════════════════════════════════════
// FUSION MULTICOUCHE — superposition, pas de secours séquentiel
// ══════════════════════════════════════════════════════════════════
// Les 4 couches (IA locale, authentification, AbuseIPDB, VirusTotal) sont
// TOUJOURS interrogées en parallèle (Promise.all dans runAnalysis) puis
// combinées ici en un score composite pondéré. Chaque couche contribue au
// résultat final proportionnellement à sa fiabilité — elle ne sert jamais
// de simple "secours" activé seulement si une autre couche échoue.
const LAYER_WEIGHTS = { ai: 0.45, auth: 0.15, ip: 0.20, domain: 0.20 };

// ── Normalisation du résultat de l'API locale ──────────────────────
// Le pipeline hybride annonce un verdict + une confiance globale
// (predicted_class, global_confidence) mais `ml_probabilities` peut être
// absent, renommé côté API, ou avec des clés dans une autre casse
// (Ham/Spam/Phishing au lieu de ham/spam/phishing) — un test du genre
// "y a-t-il une valeur positive quelque part" passait alors à tort (une
// valeur positive existe bien, juste sous la mauvaise clé), laissant le
// pipeline IA affiché à 0% partout à côté d'un verdict à 76% de confiance.
// On normalise donc explicitement les 3 clés attendues, et on ne
// reconstruit une distribution synthétique qu'en dernier recours.
function normalizeMlResult(ml) {
  const cls = String(ml.predicted_class || 'ham').toLowerCase();
  const conf = Number(ml.global_confidence ?? ml.confidence ?? 0) || 0;
  const rawPr = ml.ml_probabilities || ml.probabilities || ml.class_probabilities || {};
  const pr = {};
  Object.entries(rawPr).forEach(([k, v]) => {
    const num = typeof v === 'number' ? v : parseFloat(v);
    if (!Number.isNaN(num)) pr[k.toLowerCase()] = num;
  });
  const sum = ['ham','spam','phishing'].reduce((s,k) => s + (pr[k] || 0), 0);
  let synthesized = false;
  let finalPr = pr;
  if (sum <= 0) {
    // Aucune probabilité exploitable reçue : on reconstruit une distribution
    // cohérente avec le verdict annoncé plutôt que d'afficher un pipeline figé.
    const rest = (1 - conf) / 2;
    finalPr = { ham: rest, spam: rest, phishing: rest, [cls]: conf };
    synthesized = true;
  }
  return { ...ml, predicted_class: cls, global_confidence: conf, ml_probabilities: finalPr, _probaSynthesized: synthesized };
}

function levelFromScore(s) {
  if (s >= 80) return 'critical';
  if (s >= 60) return 'high';
  if (s >= 35) return 'medium';
  if (s >= 15) return 'low';
  return 'none';
}

function fuseLayers(ml, ipRes, domRes, auth, ctx) {
  const pr = ml.ml_probabilities || {};
  const aiScore = Math.round(100 * Math.min(1, (pr.spam||0)*0.6 + (pr.phishing||0)*1.0));

  let authScore = null;
  if (auth && auth.available) authScore = auth.mismatch ? 100 : 8;

  let ipScore = null;
  if (ipRes && ipRes.length) ipScore = Math.max(...ipRes.map(i => i.abuseScore || 0));

  let domScore = null;
  if (domRes && domRes.length) {
    domScore = Math.max(...domRes.map(d => Math.min(100, (d.malicious||0) * 25 + (d.suspicious||0) * 8)));
  }

  const layers = { ai: aiScore, auth: authScore, ip: ipScore, domain: domScore };
  const active = Object.entries(layers).filter(([,v]) => v !== null);
  const weightSum = active.reduce((s,[k]) => s + LAYER_WEIGHTS[k], 0) || 1;
  const score = Math.round(active.reduce((s,[k,v]) => s + v * LAYER_WEIGHTS[k], 0) / weightSum);

  // Raisons explicites pour une couche absente — évite un simple "—" muet
  // et répond concrètement à "pourquoi AbuseIPDB ne dit rien ici ?".
  const reasons = {};
  if (authScore === null) reasons.auth = 'aucun signal lisible';
  if (ipScore === null) {
    reasons.ip = !ctx?.hasIpKey ? 'clé non configurée'
      : !ctx?.ipCount ? 'aucune IP trouvée (en-têtes + DNS)'
      : 'aucune donnée retournée';
  }
  if (domScore === null) {
    reasons.domain = !ctx?.hasDomainKey ? 'clé non configurée'
      : !ctx?.domainCount ? 'aucun domaine détecté'
      : 'aucune donnée retournée';
  }

  return { score, level: levelFromScore(score), layers, reasons };
}

// ── Panneau ───────────────────────────────────────────────────────
function createPanel() {
  if (document.getElementById('sm-panel')) return;
  const el = document.createElement('div');
  el.id='sm-panel'; el.className='sm-hidden';
  el.innerHTML=`
    <div class="sm-header">
      <div class="sm-dot"></div><span class="sm-title">ShieldMail</span>
      <span class="sm-badge-v">v2.3</span><button class="sm-close">✕</button>
    </div>
    <div id="sm-verdict" class="sm-verdict">
      <div id="sm-icon" class="sm-vicon">🔍</div>
      <div style="flex:1"><div id="sm-class" class="sm-vclass">—</div><div id="sm-sub" class="sm-vsub">en attente</div></div>
      <div class="sm-conf-wrap"><div id="sm-conf" class="sm-conf-num">—</div></div>
    </div>
    <div class="sm-section" id="sm-fusion-section">
      <div class="sm-slabel">// Superposition des couches <span id="sm-fusion-score" class="sm-fusion-score"></span></div>
      <div class="sm-stack" id="sm-stack"></div>
      <div class="sm-stack-legend" id="sm-stack-legend"></div>
    </div>
    <div class="sm-section" id="sm-proba-section">
      <div class="sm-slabel">// Pipeline IA <span id="sm-proba-src" class="sm-src-tag"></span></div>
      <div class="sm-prow"><span class="sm-pname">HAM</span><div class="sm-ptrack"><div class="sm-pfill ham" id="sm-ph"></div></div><span class="sm-pval" id="sm-vh">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">SPAM</span><div class="sm-ptrack"><div class="sm-pfill spam" id="sm-ps"></div></div><span class="sm-pval" id="sm-vs">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">PHISHING</span><div class="sm-ptrack"><div class="sm-pfill phishing" id="sm-pp"></div></div><span class="sm-pval" id="sm-vp">0%</span></div>
    </div>
    <div class="sm-section" id="sm-auth-section" style="display:none">
      <div class="sm-slabel">// Authentification <span id="sm-auth-src" class="sm-src-tag"></span></div><div id="sm-auth-list"></div>
    </div>
    <div class="sm-section" id="sm-ip-section" style="display:none">
      <div class="sm-slabel">// AbuseIPDB</div><div id="sm-ip-list"></div>
    </div>
    <div class="sm-section" id="sm-vt-section" style="display:none">
      <div class="sm-slabel">// VirusTotal</div><div id="sm-vt-list"></div>
    </div>
    <div class="sm-section" id="sm-flags-section">
      <div class="sm-slabel">// Indicateurs</div>
      <div id="sm-flags" class="sm-flags"></div>
    </div>
    <div class="sm-section" id="sm-correct-section" style="display:none">
      <div class="sm-slabel">// Corriger la prédiction</div>
      <div id="sm-correct-btns" style="display:flex;gap:6px;flex-wrap:wrap"></div>
      <div id="sm-correct-fb" style="font-size:10px;color:var(--sm-accent,#00D4B4);margin-top:6px;display:none">✓ Correction enregistrée</div>
    </div>
    <div class="sm-footer">
      <div class="sm-lat"><div class="sm-latdot"></div><span id="sm-latval">—</span></div>
      <button class="sm-reanalyze" id="sm-redo">↻ Réanalyser</button>
    </div>`;
  document.body.appendChild(el);
  el.querySelector('.sm-close').onclick = () => el.classList.replace('sm-visible','sm-hidden');
  el.querySelector('#sm-redo').onclick  = () => runAnalysis(true);
  applyDetailLevel();
}

// Niveau de détail : full (tout) / compact (verdict + fusion + flags) / minimal (verdict seul)
function applyDetailLevel() {
  const p = document.getElementById('sm-panel'); if (!p) return;
  const hideAlways = ['sm-proba-section'];
  const hideCompact = ['sm-proba-section'];
  const hideMinimal = ['sm-proba-section','sm-auth-section','sm-ip-section','sm-vt-section','sm-flags-section','sm-fusion-section','sm-correct-section'];
  const all = ['sm-fusion-section','sm-proba-section','sm-auth-section','sm-ip-section','sm-vt-section','sm-flags-section','sm-correct-section'];
  all.forEach(id => { const s = p.querySelector('#'+id); if (s) s.style.removeProperty('display'); });
  let toHide = [];
  if (CFG.detailLevel === 'compact') toHide = hideCompact;
  else if (CFG.detailLevel === 'minimal') toHide = hideMinimal;
  toHide.forEach(id => { const s = p.querySelector('#'+id); if (s) s.style.display = 'none'; });
}

// ── Remplissage ───────────────────────────────────────────────────
function fillPanel(r, text) {
  const p = document.getElementById('sm-panel'); if (!p) return;
  const cls=r.predicted_class||'ham', conf=r.global_confidence||0;
  const ICONS={ham:'✓',spam:'✕',phishing:'⚠'};
  const LABELS={ham:'Email légitime',spam:'Spam détecté',phishing:'Phishing détecté'};
  p.querySelector('#sm-verdict').className=`sm-verdict ${cls}`;
  p.querySelector('#sm-icon').textContent=ICONS[cls]||'?';
  p.querySelector('#sm-class').textContent=cls.toUpperCase();
  p.querySelector('#sm-sub').textContent=LABELS[cls]||'';
  p.querySelector('#sm-conf').textContent=`${(conf*100).toFixed(0)}%`;
  const pr=r.ml_probabilities||{};
  const probaSrcEl = p.querySelector('#sm-proba-src');
  if (probaSrcEl) {
    probaSrcEl.textContent = r._probaSynthesized ? '(estimé depuis le verdict — API sans détail par classe)' : '(mesuré par le pipeline)';
  }
  setTimeout(()=>{
    [['ham','ph','vh'],['spam','ps','vs'],['phishing','pp','vp']].forEach(([k,fi,vi])=>{
      const v=(pr[k]||0)*100;
      const f=p.querySelector(`#sm-${fi}`); if(f) f.style.width=`${v.toFixed(1)}%`;
      const val=p.querySelector(`#sm-${vi}`); if(val) val.textContent=`${v.toFixed(0)}%`;
    });
  },100);

  // ── Superposition des couches ──
  if (r.composite) {
    const { score, level, layers, reasons } = r.composite;
    p.querySelector('#sm-fusion-score').textContent = `${score}/100 · ${level}`;
    p.querySelector('#sm-fusion-score').className = `sm-fusion-score lvl-${level}`;
    const LNAMES = { ai:'IA locale', auth:'Auth. (SPF/DKIM/DMARC)', ip:'AbuseIPDB', domain:'VirusTotal' };
    const active = Object.entries(layers).filter(([,v]) => v !== null);
    const stack = p.querySelector('#sm-stack');
    stack.innerHTML = active.map(([k,v]) => `<div class="sm-stack-seg lvl-${levelFromScore(v)}" style="flex:${Math.max(v,4)}" title="${LNAMES[k]}: ${v}/100"></div>`).join('');
    p.querySelector('#sm-stack-legend').innerHTML = active.map(([k,v]) =>
      `<span class="sm-leg lvl-${levelFromScore(v)}">${LNAMES[k]} <b>${v}</b></span>`
    ).join('') + Object.keys(layers).filter(k=>layers[k]===null).map(k=>
      `<span class="sm-leg lvl-off" title="${(reasons&&reasons[k])||'indisponible'}">${LNAMES[k]} · ${(reasons&&reasons[k])||'—'}</span>`
    ).join('');
  }

  if(r.auth_signals && r.auth_signals.available){
    p.querySelector('#sm-auth-section').style.display='';
    const a=r.auth_signals, c=a.mismatch?'danger':'ok';
    p.querySelector('#sm-auth-src').textContent = a.source === 'raw-headers' ? '(en-têtes réels)' : '(estimation DOM)';
    if (a.source === 'raw-headers') {
      p.querySelector('#sm-auth-list').innerHTML =
        `<div class="sm-ip-row"><span class="sm-flag ${a.spf==='fail'?'danger':a.spf==='pass'?'ok':'warning'}">SPF: ${a.spf}</span>
         <span class="sm-flag ${a.dkim==='fail'?'danger':a.dkim==='pass'?'ok':'warning'}">DKIM: ${a.dkim}</span>
         <span class="sm-flag ${a.dmarc==='fail'?'danger':a.dmarc==='pass'?'ok':'warning'}">DMARC: ${a.dmarc}</span></div>
         <div class="sm-ip-row"><span class="sm-flag ${c}">From: ${a.fromDomain||'—'}</span><span class="sm-flag ${c}">Return-Path: ${a.returnPathDomain||'—'}</span></div>`;
    } else {
      p.querySelector('#sm-auth-list').innerHTML=
        `<div class="sm-ip-row"><span class="sm-flag ${c}">mailed-by: ${a.mailedBy||'—'}</span></div>
         <div class="sm-ip-row"><span class="sm-flag ${c}">signed-by: ${a.signedBy||'—'}</span></div>`;
    }
  }
  if((r.ip_reputations||[]).length>0){
    p.querySelector('#sm-ip-section').style.display='';
    p.querySelector('#sm-ip-list').innerHTML=r.ip_reputations.map(ip=>{
      const c=ip.abuseScore>=75?'danger':ip.abuseScore>=15?'warning':'ok';
      const originTag = ip.resolvedFromDomain ? ' · IP du domaine (résolue par DNS, pas nécessairement le serveur d\'envoi réel)' : '';
      return `<div class="sm-ip-row"><span class="sm-flag ${c}">${ip.ip}</span><span class="sm-ip-score ${c}">${ip.abuseScore}% abuse</span><span class="sm-ip-meta">${ip.countryCode} · ${ip.totalReports} signalements${originTag}</span></div>`;
    }).join('');
  }
  if((r.domain_reputations||[]).length>0){
    p.querySelector('#sm-vt-section').style.display='';
    p.querySelector('#sm-vt-list').innerHTML=r.domain_reputations.map(d=>{
      const c=d.malicious>3?'danger':d.malicious>0?'warning':'ok';
      return `<div class="sm-vt-row"><span class="sm-flag ${c}">${d.domain}</span><span class="sm-vt-score ${c}">${d.malicious}/${d.total} détections</span></div>`;
    }).join('');
  }
  const flags=[...(r.rules_triggered||[]).map(f=>({t:f,c:'warning'})),...(r.url_flags||[]).map(f=>({t:f,c:'danger'}))];
  p.querySelector('#sm-flags').innerHTML=flags.length>0
    ?flags.map(f=>`<span class="sm-flag ${f.c}">${f.t}</span>`).join('')
    :'<span class="sm-flag ok">Aucun indicateur suspect</span>';
  p.querySelector('#sm-latval').textContent=r.latency_ms?`${r.latency_ms.toFixed(1)}ms`:'—';
  applyDetailLevel();
  showCorrectionButtons(cls, text, p, r._recordId);
}

// ── Boutons correction (post-entraînement) ────────────────────────
function showCorrectionButtons(predicted, text, p, recordId) {
  const section=p.querySelector('#sm-correct-section');
  const btnsDiv=p.querySelector('#sm-correct-btns');
  const fb=p.querySelector('#sm-correct-fb');
  section.style.display=''; fb.style.display='none';
  btnsDiv.innerHTML=['ham','spam','phishing'].map(cls=>`
    <button class="sm-correct-btn ${cls} ${cls===predicted?'active':''}" data-cls="${cls}">
      ${cls===predicted?'✓ ':''} ${cls.toUpperCase()}
    </button>`).join('');
  btnsDiv.querySelectorAll('.sm-correct-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
      sendCorrection(text, btn.dataset.cls, predicted, recordId);
      btnsDiv.querySelectorAll('.sm-correct-btn').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      fb.style.display='block';
      setTimeout(()=>{fb.style.display='none';},3000);
    });
  });
}

// ── Post-entraînement ─────────────────────────────────────────────
async function sendCorrection(text, correctLabel, predictedLabel, recordId) {
  // Buffer local
  chrome.storage.local.get(['corrections_buffer'],d=>{
    const buf=d.corrections_buffer||[];
    buf.push({text:text.slice(0,3000),label:correctLabel,predicted:predictedLabel,ts:Date.now()});
    chrome.storage.local.set({corrections_buffer:buf});
  });
  // Trace dans l'historique + stats dashboard
  smSendMessage({ type:'SAVE_CORRECTION', recordId, correctLabel, predictedLabel }).catch(()=>{});
  // Envoi API
  try {
    await fetch(`${CFG.apiUrl.replace(/\/$/,'')}/feedback`,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({text,correct_label:correctLabel,predicted_label:predictedLabel}),
      signal:AbortSignal.timeout(5000)
    });
  } catch { /* buffered */ }
}

// ── Alerte ────────────────────────────────────────────────────────
function showAlert(r) {
  if (!CFG.showAlert) return;
  const ipBad=(r.ip_reputations||[]).some(i=>i.abuseScore>=75);
  const vtBad=(r.domain_reputations||[]).some(d=>d.malicious>3);
  const fusionBad = r.composite && ['high','critical'].includes(r.composite.level);
  if (!['high','critical'].includes(r.threat_level)&&!ipBad&&!vtBad&&!fusionBad) return;
  let el=document.getElementById('sm-alert');
  if (!el){el=document.createElement('div');el.id='sm-alert';document.body.appendChild(el);}
  const conf=((r.global_confidence||0)*100).toFixed(0);
  const ipI=r.ip_reputations?.find(i=>i.abuseScore>=75);
  const vtI=r.domain_reputations?.find(d=>d.malicious>3);
  let reason=`IA: ${r.predicted_class} (${conf}%)`;
  if (r.composite) reason += ` · Score fusionné ${r.composite.score}/100`;
  if(ipI) reason+=` · IP ${ipI.ip} (${ipI.abuseScore}% abuse)`;
  if(vtI) reason+=` · ${vtI.domain} (${vtI.malicious} VT)`;
  el.className='sm-alert-bar';
  el.innerHTML=`<span class="sm-alert-icon">🚨</span>
    <div class="sm-alert-txt"><b>ShieldMail — Menace détectée</b><br><small>${reason}</small></div>
    <button class="sm-alert-close">✕</button>`;
  el.querySelector('.sm-alert-close').onclick = () => el.remove();
  setTimeout(()=>el?.remove(),10000);
}

// ── Analyse email ouvert ──────────────────────────────────────────
async function runAnalysis(force=false) {
  const key=window.location.href;
  const panel=document.getElementById('sm-panel')||(createPanel(),document.getElementById('sm-panel'));
  if (!force&&analysisCache.has(key)){
    panel.className='sm-visible';
    const cached=analysisCache.get(key);
    fillPanel(cached,cached._text||'');
    return;
  }
  const {text,sender,domain,ips,urlDomains,authSignalsDom}=extractEmailInfo();
  if (!text) return;
  panel.querySelector('#sm-class').textContent='Analyse...';
  panel.querySelector('#sm-icon').textContent='⟳';
  panel.querySelector('#sm-conf').textContent='—';
  panel.className='sm-visible';

  // Message original en priorité ; repli DOM si indisponible
  const raw = await fetchOriginalMessageRaw();
  const authSignals = raw ? parseRawHeaders(raw) : authSignalsDom;
  const relayIps = (authSignals.relayIps || []).filter(ip => !ips.includes(ip));
  const allIps = [...ips, ...relayIps];

  // Dernier recours : ni en-têtes ni corps ne donnent d'IP → on résout le
  // domaine expéditeur par DNS plutôt que de laisser AbuseIPDB sans rien à vérifier.
  let dnsResolvedIp = null;
  if (allIps.length === 0 && CFG.abuseipdbKey && domain) {
    dnsResolvedIp = await resolveDomainIp(domain);
    if (dnsResolvedIp) allIps.push(dnsResolvedIp);
  }

  const [mlRaw,ipRes,domRes]=await Promise.all([
    smSendMessage({type:'ANALYZE_EMAIL',text,apiUrl:CFG.apiUrl,authSignals})
      .then(r=>r.ok?r.result:buildFallback(text,authSignals)).catch(()=>buildFallback(text,authSignals)),
    CFG.abuseipdbKey?Promise.all(allIps.slice(0,4).map(ip=>
      smSendMessage({type:'CHECK_IP',ip,abuseipdbKey:CFG.abuseipdbKey})
        .then(r=>r.ok?r.result:null).catch(()=>null)
    )).then(rs=>rs.filter(Boolean)):Promise.resolve([]),
    CFG.virustotalKey?Promise.all([...new Set([domain,...urlDomains])].slice(0,3).map(d=>
      smSendMessage({type:'CHECK_DOMAIN',domain:d,virustotalKey:CFG.virustotalKey})
        .then(r=>r.ok?r.result:null).catch(()=>null)
    )).then(rs=>rs.filter(Boolean)):Promise.resolve([]),
  ]);
  const ml = normalizeMlResult(mlRaw);
  if (dnsResolvedIp) {
    const rec = ipRes.find(x => x && x.ip === dnsResolvedIp);
    if (rec) rec.resolvedFromDomain = true;
  }

  const domainCandidates = [...new Set([domain,...urlDomains])].filter(Boolean);
  const ctx = {
    hasIpKey: !!CFG.abuseipdbKey, ipCount: allIps.length,
    hasDomainKey: !!CFG.virustotalKey, domainCount: domainCandidates.length,
  };
  const composite = fuseLayers(ml, ipRes, domRes, authSignals, ctx);
  const recordId = `${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
  const result={...ml,_text:text,_recordId:recordId,ip_reputations:ipRes,domain_reputations:domRes,
    auth_signals:authSignals, composite,
    threat_level:composite.level};
  analysisCache.set(key,result);
  fillPanel(result,text);
  showAlert(result);
  smSendMessage({type:'SAVE_RESULT',result,preview:text.slice(0,80),meta:{sender,domain,mailClient:'gmail'}});
}

function buildFallback(text,authSignals){
  const t=text.toLowerCase();
  const p=['verify','suspended','login','paypal','bank','password'].filter(k=>t.includes(k)).length;
  const s=['free','win','congratulations','!!!','earn'].filter(k=>t.includes(k)).length;
  const authFail=!!(authSignals&&authSignals.mismatch);
  let cls='ham',conf=0.88,threat='none';
  if(p>=2||authFail){cls='phishing';conf=(authFail&&p>=2)?0.9:0.82;threat='critical';}
  else if(s>=2){cls='spam';conf=0.78;threat='high';}
  const rest=(1-conf)/2;
  return {predicted_class:cls,threat_level:threat,global_confidence:conf,
    ml_probabilities:{ham:rest,spam:rest,phishing:rest,[cls]:conf},
    rules_triggered:[],url_flags:[],
    header_flags:authFail?['Signal d\'authentification en échec ou incohérent avec le domaine affiché']:[],
    latency_ms:0,_demo:true};
}

// ── SCAN AUTOMATIQUE liste emails ─────────────────────────────────
async function scanVisibleEmails(){
  if (!CFG.showBadges) return;
  const rows=document.querySelectorAll('tr.zA:not([data-sm-scanned])');
  for (const row of rows){
    row.setAttribute('data-sm-scanned','1');
    const subjectEl=row.querySelector('span.bqe,span.bog');
    if (!subjectEl||row.querySelector('.sm-badge')) continue;
    const badge=document.createElement('span');
    badge.className='sm-badge loading'; badge.textContent='···';
    subjectEl.parentElement?.appendChild(badge);
    const snippet=row.querySelector('.y2')?.textContent?.trim()||'';
    const text=(subjectEl.textContent?.trim()+' '+snippet).trim();
    if (text.length<5){badge.remove();continue;}
    smSendMessage({type:'ANALYZE_EMAIL',text,apiUrl:CFG.apiUrl})
      .then(r=>{
        if(!r.ok) throw new Error();
        const cls=r.result.predicted_class;
        const conf=((r.result.global_confidence||0)*100).toFixed(0);
        badge.className=`sm-badge ${cls}`;
        badge.textContent=`${cls} ${conf}%`;
        badge.title=`ShieldMail: ${cls.toUpperCase()} — ${conf}%`;
      }).catch(()=>badge.remove());
  }
}

// ── Persistance changement d'onglet Gmail ─────────────────────────
let lastHash='', scanTimeout=null;

function handleUrlChange(){
  const hash=window.location.hash;
  if (hash===lastHash) return;
  lastHash=hash;
  const isEmail=/\/(inbox|spam|sent|all|starred|label)\/[a-f0-9]+/.test(hash)||
                /\/mail\//.test(window.location.href);
  if (isEmail){
    if (CFG.autoAnalyze) setTimeout(()=>runAnalysis(),900);
  } else {
    const panel=document.getElementById('sm-panel');
    if (panel) panel.classList.replace('sm-visible','sm-hidden');
    setTimeout(()=>scanVisibleEmails(),1200);
  }
}

// ── Observer ──────────────────────────────────────────────────────
new MutationObserver(()=>{
  handleUrlChange();
  if (CFG.showBadges){
    clearTimeout(scanTimeout);
    scanTimeout=setTimeout(()=>scanVisibleEmails(),800);
  }
}).observe(document.body,{childList:true,subtree:true});

// ── Init ──────────────────────────────────────────────────────────
createPanel();
handleUrlChange();
setTimeout(()=>scanVisibleEmails(),2000);
