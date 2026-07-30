// ShieldMail v2 — Popup
'use strict';

const HOST_PATTERNS = ['https://mail.google.com/*', 'https://outlook.live.com/*', 'https://outlook.office.com/*'];

function broadcastToMailTabs(settings) {
  chrome.tabs.query({ url: HOST_PATTERNS }, tabs => {
    tabs.forEach(t => chrome.tabs.sendMessage(t.id, { type: 'SETTINGS_CHANGED', settings }).catch(() => {}));
  });
}

function renderConfigStatus(d) {
  const hasKeys = !!(d.abuseipdbKey || d.virustotalKey);
  const ok = document.getElementById('cfg-ok-sec');
  const warn = document.getElementById('cfg-warn-sec');
  if (d.setupComplete) {
    ok.style.display = '';
    warn.style.display = 'none';
    document.getElementById('cfg-summary').textContent =
      hasKeys ? `${d.apiUrl} · clés API actives` : `${d.apiUrl} · sans clés API`;
  } else {
    ok.style.display = 'none';
    warn.style.display = '';
  }
}

function renderStats(s) {
  const st = s || { ham: 0, spam: 0, phishing: 0, corrections: 0 };
  document.getElementById('sham').textContent   = st.ham || 0;
  document.getElementById('sspam').textContent  = st.spam || 0;
  document.getElementById('sphish').textContent = st.phishing || 0;
  document.getElementById('scorr').textContent  = st.corrections || 0;
}

function setDetailLevel(level) {
  document.querySelectorAll('#detail-seg button').forEach(b => b.classList.toggle('active', b.dataset.v === level));
}

// ── Chargement initial ────────────────────────────────────────────
chrome.storage.local.get(
  ['apiUrl', 'abuseipdbKey', 'virustotalKey', 'setupComplete', 'autoAnalyze', 'showBadges', 'showAlert',
   'stats', 'recents', 'theme', 'font', 'detailLevel'],
  d => {
    smApplyTheme(document.documentElement, d.theme || SM_DEFAULT_THEME, d.font || SM_DEFAULT_FONT);
    if (d.autoAnalyze !== undefined) document.getElementById('autoAnalyze').checked = d.autoAnalyze;
    if (d.showBadges  !== undefined) document.getElementById('showBadges').checked  = d.showBadges;
    if (d.showAlert   !== undefined) document.getElementById('showAlert').checked   = d.showAlert;
    renderStats(d.stats);
    renderRecents(d.recents || []);
    renderConfigStatus(d);
    setDetailLevel(d.detailLevel || 'full');
    smBuildThemePicker(document.getElementById('theme-picker'), { theme: d.theme, font: d.font }, (theme, font) => {
      chrome.storage.local.set({ theme, font });
      smApplyTheme(document.documentElement, theme, font);
      broadcastToMailTabs({ theme, font });
    });
    checkApi();
  }
);

// ── Toggles — diffusés à TOUS les onglets Gmail/Outlook ouverts ────
// (avant : uniquement l'onglet actif, ce qui ratait les changements si
//  Gmail n'était pas au premier plan au moment du clic)
['autoAnalyze', 'showBadges', 'showAlert'].forEach(id => {
  document.getElementById(id).addEventListener('change', e => {
    chrome.storage.local.set({ [id]: e.target.checked });
    broadcastToMailTabs({ [id]: e.target.checked });
  });
});

// ── Niveau de détail ────────────────────────────────────────────────
document.getElementById('detail-seg').addEventListener('click', e => {
  const btn = e.target.closest('button[data-v]');
  if (!btn) return;
  const detailLevel = btn.dataset.v;
  setDetailLevel(detailLevel);
  chrome.storage.local.set({ detailLevel });
  broadcastToMailTabs({ detailLevel });
});

// ── Dashboard ─────────────────────────────────────────────────────
document.getElementById('dash-btn').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
});

// ── Configuration (clés API + URL) — gérée sur une page dédiée ─────
document.getElementById('cfg-edit-btn').addEventListener('click', () => chrome.runtime.openOptionsPage());
document.getElementById('cfg-setup-btn').addEventListener('click', () => chrome.runtime.openOptionsPage());

// ── Test API — lit l'URL depuis le storage (plus de champ dans ce popup) ──
async function checkApi() {
  const dot = document.getElementById('sd');
  const txt = document.getElementById('st');
  dot.className = 'sdot chk';
  txt.textContent = 'Vérification...';
  chrome.storage.local.get(['apiUrl'], async d => {
    const url = (d.apiUrl || 'http://localhost:8000').replace(/\/$/, '');
    try {
      const r = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3000) });
      if (r.ok) { dot.className = 'sdot on'; txt.textContent = 'API connectée'; }
      else throw new Error();
    } catch {
      dot.className = 'sdot off';
      txt.textContent = 'API hors ligne';
    }
  });
}
document.getElementById('test-btn').addEventListener('click', checkApi);

// ── Analyses récentes ───────────────────────────────────────────────
function renderRecents(recents) {
  const c = document.getElementById('rcnt');
  if (!recents || recents.length === 0) {
    c.innerHTML = '<div class="empty">Ouvrez un email dans Gmail ou Outlook<br>pour démarrer l\'analyse.</div>';
    return;
  }
  c.innerHTML = recents.slice(0, 6).map(r => {
    let meta = '';
    if (r.composite != null) {
      const cls = r.composite >= 60 ? 'ip-bad' : r.composite >= 35 ? 'ip-warn' : 'ip-ok';
      meta += `<span class="ri-meta ${cls}"> · fusion:${r.composite}</span>`;
    }
    if (r.ip_score != null) {
      const cls = r.ip_score >= 75 ? 'ip-bad' : r.ip_score >= 15 ? 'ip-warn' : 'ip-ok';
      meta += `<span class="ri-meta ${cls}"> · IP:${r.ip_score}%</span>`;
    }
    if (r.vt_hits != null && r.vt_hits > 0) {
      meta += `<span class="ri-meta ip-bad"> · VT:${r.vt_hits}</span>`;
    }
    return `<div class="ri">
      <span class="bx ${r.cls}">${r.cls}</span>
      <span class="rt">${esc(r.preview)}</span>
      <span class="rc">${r.conf}%</span>${meta}
    </div>`;
  }).join('');
}

function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;'); }

// ── Rafraîchissement en direct pendant que le popup est ouvert ─────
// (corrige un bug : ANALYSIS_DONE n'était auparavant jamais émis par
//  le service worker, ce message restait donc mort-code)
chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === 'ANALYSIS_DONE') {
    chrome.storage.local.get(['stats', 'recents'], d => {
      renderStats(d.stats);
      renderRecents(d.recents || []);
    });
  }
});
