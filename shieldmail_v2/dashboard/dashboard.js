// ShieldMail v2 — Dashboard
// Aucune dépendance externe : tous les graphiques sont du SVG fait main
// (léger, hors-ligne, conforme à la politique MV3 qui interdit le code
// distant — pas besoin d'aller chercher chart.js sur un CDN).
'use strict';

const COLORS = { ham: 'var(--sm-ham)', spam: 'var(--sm-spam)', phishing: 'var(--sm-phish)', accent: 'var(--sm-accent)' };
const RESOLVED = {}; // couleurs résolues (les var() CSS ne marchent pas dans les attributs SVG stroke/fill bruts calculés en JS)

function resolveColors() {
  const cs = getComputedStyle(document.documentElement);
  RESOLVED.ham = cs.getPropertyValue('--sm-ham').trim() || '#00D4B4';
  RESOLVED.spam = cs.getPropertyValue('--sm-spam').trim() || '#FF5B3A';
  RESOLVED.phishing = cs.getPropertyValue('--sm-phish').trim() || '#F5A623';
  RESOLVED.accent = cs.getPropertyValue('--sm-accent').trim() || '#00D4B4';
  RESOLVED.border = cs.getPropertyValue('--sm-border').trim() || '#1E3048';
  RESOLVED.dim = cs.getPropertyValue('--sm-text-dim').trim() || '#5C7A96';
}

let HISTORY = [];
let STATS = { ham:0, spam:0, phishing:0, corrections:0 };
let currentFilter = 'all';

// ── Chargement ──────────────────────────────────────────────────────
function load() {
  chrome.storage.local.get(['scanHistory', 'stats', 'theme', 'font'], d => {
    smApplyTheme(document.documentElement, d.theme || SM_DEFAULT_THEME, d.font || SM_DEFAULT_FONT);
    resolveColors();
    HISTORY = d.scanHistory || [];
    STATS = d.stats || { ham:0, spam:0, phishing:0, corrections:0 };
    renderAll();
    smBuildThemePicker(document.getElementById('theme-picker'), { theme: d.theme, font: d.font }, (theme, font) => {
      chrome.storage.local.set({ theme, font });
      smApplyTheme(document.documentElement, theme, font);
      resolveColors();
      renderAll();
      chrome.tabs.query({ url: ['https://mail.google.com/*','https://outlook.live.com/*','https://outlook.office.com/*'] }, tabs =>
        tabs.forEach(t => chrome.tabs.sendMessage(t.id, { type:'SETTINGS_CHANGED', settings:{theme,font} }).catch(()=>{})));
    });
  });
}

function renderAll() {
  renderKpis();
  renderDonut();
  renderVolumeBars();
  renderLayerBars();
  renderScoreCurve();
  renderTable();
}

// ── KPIs ──────────────────────────────────────────────────────────
function renderKpis() {
  const total = HISTORY.length;
  const spamPct = total ? Math.round(100 * HISTORY.filter(h=>h.cls==='spam').length / total) : 0;
  const phishPct = total ? Math.round(100 * HISTORY.filter(h=>h.cls==='phishing').length / total) : 0;
  const withComposite = HISTORY.filter(h => h.composite);
  const avgScore = withComposite.length ? Math.round(withComposite.reduce((s,h)=>s+h.composite.score,0)/withComposite.length) : 0;

  const cards = [
    { v: total, l: 'Emails scannés', cls: '' },
    { v: spamPct + '%', l: 'Taux de spam', cls: 'spam' },
    { v: phishPct + '%', l: 'Taux de phishing', cls: 'phish' },
    { v: STATS.corrections || 0, l: 'Corrections', cls: 'accent' },
    { v: avgScore + '/100', l: 'Score fusion moyen', cls: 'accent' },
  ];
  document.getElementById('kpis').innerHTML = cards.map(c =>
    `<div class="kpi ${c.cls}"><div class="v">${c.v}</div><div class="l">${c.l}</div></div>`
  ).join('');
}

// ── Donut (répartition des verdicts) ───────────────────────────────
function renderDonut() {
  const seg = [
    { k:'ham', label:'Ham', v: STATS.ham||0, color: RESOLVED.ham },
    { k:'spam', label:'Spam', v: STATS.spam||0, color: RESOLVED.spam },
    { k:'phishing', label:'Phishing', v: STATS.phishing||0, color: RESOLVED.phishing },
  ];
  const total = seg.reduce((s,x)=>s+x.v,0) || 1;
  const R = 52, C = 2*Math.PI*R, size = 140, stroke = 20;
  let offset = 0;
  const circles = seg.map(s => {
    const frac = s.v/total;
    const dash = `${(frac*C).toFixed(2)} ${(C-frac*C).toFixed(2)}`;
    const el = `<circle cx="${size/2}" cy="${size/2}" r="${R}" fill="none" stroke="${s.color}" stroke-width="${stroke}"
      stroke-dasharray="${dash}" stroke-dashoffset="${(-offset*C).toFixed(2)}" transform="rotate(-90 ${size/2} ${size/2})" stroke-linecap="butt"/>`;
    offset += frac;
    return el;
  }).join('');
  document.getElementById('donut-chart').innerHTML = `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${size/2}" cy="${size/2}" r="${R}" fill="none" stroke="${RESOLVED.border}" stroke-width="${stroke}"/>
      ${circles}
      <text x="${size/2}" y="${size/2-4}" text-anchor="middle" font-size="22" font-weight="800" fill="var(--sm-text)">${total}</text>
      <text x="${size/2}" y="${size/2+14}" text-anchor="middle" font-size="9" fill="${RESOLVED.dim}">scans</text>
    </svg>`;
  document.getElementById('donut-legend').innerHTML = seg.map(s =>
    `<div class="li"><i style="background:${s.color}"></i>${s.label}<b>${s.v}</b></div>`
  ).join('');
}

// ── Barres empilées (volume par jour, 14 derniers jours) ───────────
function dailyBuckets(days) {
  const now = new Date(); now.setHours(0,0,0,0);
  const buckets = [];
  for (let i = days-1; i >= 0; i--) {
    const d = new Date(now); d.setDate(d.getDate()-i);
    buckets.push({ date: d, key: d.toISOString().slice(0,10), ham:0, spam:0, phishing:0, scoreSum:0, scoreN:0 });
  }
  const byKey = Object.fromEntries(buckets.map(b => [b.key, b]));
  HISTORY.forEach(h => {
    const k = new Date(h.ts).toISOString().slice(0,10);
    const b = byKey[k];
    if (!b) return;
    b[h.cls] = (b[h.cls]||0) + 1;
    if (h.composite) { b.scoreSum += h.composite.score; b.scoreN++; }
  });
  return buckets;
}

function renderVolumeBars() {
  const buckets = dailyBuckets(14);
  const max = Math.max(1, ...buckets.map(b => b.ham+b.spam+b.phishing));
  const W = 620, H = 170, padB = 22, padT = 6, barW = Math.min(28, (W/buckets.length)-8);
  const bars = buckets.map((b,i) => {
    const total = b.ham+b.spam+b.phishing;
    const x = (i+0.5) * (W/buckets.length) - barW/2;
    const scale = (H-padB-padT) / max;
    let y = H - padB;
    const segs = ['ham','spam','phishing'].filter(k=>b[k]>0).map(k => {
      const h = b[k]*scale;
      y -= h;
      const color = RESOLVED[k];
      return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW}" height="${h.toFixed(1)}" fill="${color}" rx="2"/>`;
    }).join('');
    const label = b.date.toLocaleDateString('fr-FR',{day:'2-digit',month:'2-digit'});
    const showLabel = buckets.length <= 14 ? (i % 2 === 0) : (i % 4 === 0);
    return segs + (showLabel ? `<text x="${(x+barW/2).toFixed(1)}" y="${H-6}" text-anchor="middle" font-size="8.5" fill="${RESOLVED.dim}">${label}</text>` : '')
      + (total > 0 ? `<title>${label}: ${total} scan(s)</title>` : '');
  }).join('');
  document.getElementById('volume-chart').innerHTML = `<svg width="100%" height="${H}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">${bars}</svg>`;
}

// ── Courbe (score de fusion moyen par jour) ─────────────────────────
function renderScoreCurve() {
  const buckets = dailyBuckets(14);
  const W = 620, H = 170, padB = 22, padT = 10, padL = 4, padR = 4;
  const pts = buckets.map(b => b.scoreN ? b.scoreSum/b.scoreN : null);
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const step = plotW / (buckets.length-1 || 1);
  const known = pts.map((v,i)=>({v,i})).filter(p=>p.v!==null);
  const xy = (i,v) => [padL + i*step, padT + plotH - (v/100)*plotH];

  let pathD = '', areaD = '';
  if (known.length) {
    pathD = known.map((p,idx) => { const [x,y]=xy(p.i,p.v); return `${idx===0?'M':'L'}${x.toFixed(1)},${y.toFixed(1)}`; }).join(' ');
    const [firstX] = xy(known[0].i, known[0].v);
    const [lastX] = xy(known[known.length-1].i, known[known.length-1].v);
    areaD = `M${firstX.toFixed(1)},${(padT+plotH).toFixed(1)} ${pathD.replace('M','L')} L${lastX.toFixed(1)},${(padT+plotH).toFixed(1)} Z`;
  }
  const gridLines = [0,25,50,75,100].map(v => {
    const y = padT + plotH - (v/100)*plotH;
    return `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W-padR}" y2="${y.toFixed(1)}" stroke="${RESOLVED.border}" stroke-width="1" stroke-dasharray="3,4"/>
            <text x="2" y="${(y-2).toFixed(1)}" font-size="8" fill="${RESOLVED.dim}">${v}</text>`;
  }).join('');
  const dots = known.map(p => { const [x,y]=xy(p.i,p.v); const lvl = p.v>=60?RESOLVED.spam:p.v>=35?RESOLVED.phishing:RESOLVED.ham;
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" fill="${lvl}"><title>${Math.round(p.v)}/100</title></circle>`; }).join('');

  document.getElementById('score-chart').innerHTML = known.length ? `
    <svg width="100%" height="${H}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">
      <defs><linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${RESOLVED.accent}" stop-opacity=".35"/>
        <stop offset="100%" stop-color="${RESOLVED.accent}" stop-opacity="0"/>
      </linearGradient></defs>
      ${gridLines}
      <path d="${areaD}" fill="url(#scoreGrad)"/>
      <path d="${pathD}" fill="none" stroke="${RESOLVED.accent}" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>
      ${dots}
    </svg>` : `<div class="empty-state">Pas encore assez de scans pour tracer une tendance.</div>`;
}

// ── Contribution moyenne des couches ─────────────────────────────
function renderLayerBars() {
  const withComposite = HISTORY.filter(h => h.composite && h.composite.layers);
  const NAMES = { ai:'IA locale', auth:'Authentification', ip:'AbuseIPDB', domain:'VirusTotal' };
  const el = document.getElementById('layers-chart');
  if (!withComposite.length) { el.innerHTML = '<div class="empty-state">Aucune donnée de fusion pour le moment.</div>'; return; }
  const rows = Object.keys(NAMES).map(k => {
    const vals = withComposite.map(h => h.composite.layers[k]).filter(v => v !== null && v !== undefined);
    const avg = vals.length ? Math.round(vals.reduce((s,v)=>s+v,0)/vals.length) : null;
    const coverage = Math.round(100*vals.length/withComposite.length);
    const color = avg===null ? RESOLVED.border : avg>=60?RESOLVED.spam:avg>=35?RESOLVED.phishing:RESOLVED.ham;
    return `<div class="layer-row">
      <div class="layer-name">${NAMES[k]} <span style="opacity:.55">(${coverage}%)</span></div>
      <div class="layer-track"><div class="layer-fill" style="width:${avg||0}%;background:${color}"></div></div>
      <div class="layer-val">${avg===null?'—':avg}</div>
    </div>`;
  }).join('');
  el.innerHTML = rows;
}

// ── Tableau historique ────────────────────────────────────────────
function renderTable() {
  let rows = HISTORY;
  if (currentFilter === 'corrected') rows = rows.filter(h => h.corrected);
  else if (currentFilter !== 'all') rows = rows.filter(h => h.cls === currentFilter);
  rows = rows.slice(0, 80);

  if (!rows.length) {
    document.getElementById('table-wrap').innerHTML = '<div class="empty-state">Aucun scan à afficher pour ce filtre.</div>';
    return;
  }
  const trs = rows.map(h => {
    const date = new Date(h.ts);
    const when = `${date.toLocaleDateString('fr-FR')} ${date.toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'})}`;
    const fusion = h.composite ? `${h.composite.score}/100` : '—';
    const src = h.headerSource === 'raw-headers' ? 'en-têtes réels' : 'estimation DOM';
    const corr = h.corrected ? `<span class="corr-tag">→ ${h.corrected.toUpperCase()}</span>` : '<span style="opacity:.35">—</span>';
    return `<tr>
      <td>${when}</td>
      <td>${esc(h.domain || h.sender || '—')}</td>
      <td><span class="pill ${h.cls}">${h.cls}</span></td>
      <td>${h.conf}%</td>
      <td>${fusion}</td>
      <td><span class="src-tag">${src}</span></td>
      <td>${corr}</td>
    </tr>`;
  }).join('');

  document.getElementById('table-wrap').innerHTML = `
    <table>
      <thead><tr><th>Horodatage</th><th>Domaine / expéditeur</th><th>Verdict</th><th>Confiance IA</th><th>Score fusion</th><th>Source en-têtes</th><th>Correction</th></tr></thead>
      <tbody>${trs}</tbody>
    </table>`;
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }

// ── Filtres ────────────────────────────────────────────────────────
document.getElementById('filters').addEventListener('click', e => {
  const btn = e.target.closest('button[data-f]');
  if (!btn) return;
  currentFilter = btn.dataset.f;
  document.querySelectorAll('#filters button').forEach(b => b.classList.toggle('active', b===btn));
  renderTable();
});

// ── Popover thème ────────────────────────────────────────────────
document.getElementById('theme-toggle-btn').addEventListener('click', e => {
  e.stopPropagation();
  document.getElementById('theme-panel').classList.toggle('show');
});
document.addEventListener('click', () => document.getElementById('theme-panel').classList.remove('show'));

// ── Actions ───────────────────────────────────────────────────────
document.getElementById('refresh-btn').addEventListener('click', load);
document.getElementById('reset-btn').addEventListener('click', () => {
  if (!confirm('Effacer tout l\'historique local de scans (statistiques, courbes, tableau) ? Cette action est irréversible.')) return;
  chrome.storage.local.set({ scanHistory: [], recents: [], stats: { ham:0, spam:0, phishing:0, corrections:0 } }, load);
});
chrome.runtime.onMessage.addListener(msg => { if (msg.type === 'ANALYSIS_DONE') load(); });

load();
