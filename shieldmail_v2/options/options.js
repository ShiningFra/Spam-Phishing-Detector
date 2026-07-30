// ShieldMail v2 — Page de configuration (première installation + modifications)
'use strict';

const isFirstRun = new URLSearchParams(location.search).get('first') === '1';

const $apiUrl        = document.getElementById('apiUrl');
const $abuseipdbKey   = document.getElementById('abuseipdbKey');
const $virustotalKey  = document.getElementById('virustotalKey');
const $saveBtn        = document.getElementById('save-btn');
const $closeBtn       = document.getElementById('close-btn');
const $status         = document.getElementById('status');
const $note           = document.getElementById('note');

let currentTheme = SM_DEFAULT_THEME, currentFont = SM_DEFAULT_FONT, currentDetail = 'full';

function setDetailLevel(level) {
  currentDetail = level;
  document.querySelectorAll('#detail-seg button').forEach(b => b.classList.toggle('active', b.dataset.v === level));
}

// ── Chargement des valeurs existantes (utile pour une modification ultérieure) ──
chrome.storage.local.get(
  ['apiUrl', 'abuseipdbKey', 'virustotalKey', 'theme', 'font', 'detailLevel'],
  d => {
    $apiUrl.value        = d.apiUrl || 'http://localhost:8000';
    $abuseipdbKey.value   = d.abuseipdbKey  || '';
    $virustotalKey.value  = d.virustotalKey || '';
    currentTheme = d.theme || SM_DEFAULT_THEME;
    currentFont  = d.font  || SM_DEFAULT_FONT;
    smApplyTheme(document.documentElement, currentTheme, currentFont);
    setDetailLevel(d.detailLevel || 'full');
    smBuildThemePicker(document.getElementById('theme-picker'), { theme: currentTheme, font: currentFont }, (theme, font) => {
      currentTheme = theme; currentFont = font;
      smApplyTheme(document.documentElement, theme, font);
    });
  }
);

document.getElementById('detail-seg').addEventListener('click', e => {
  const btn = e.target.closest('button[data-v]');
  if (!btn) return;
  setDetailLevel(btn.dataset.v);
});

if (isFirstRun) {
  $note.textContent = 'Une fois enregistrée, cette étape ne sera plus demandée.';
}

// ── Sauvegarde ──────────────────────────────────────────────────────
$saveBtn.addEventListener('click', () => {
  const apiUrl = $apiUrl.value.trim().replace(/\/$/, '') || 'http://localhost:8000';

  $saveBtn.disabled = true;
  $saveBtn.textContent = 'Enregistrement...';

  const settings = {
    apiUrl,
    abuseipdbKey:  $abuseipdbKey.value.trim(),
    virustotalKey: $virustotalKey.value.trim(),
    theme: currentTheme,
    font: currentFont,
    detailLevel: currentDetail,
    setupComplete: true,
  };

  chrome.storage.local.set(settings, () => {
    $status.classList.add('show', 'ok');
    $status.textContent = '✓ Configuration enregistrée';
    $saveBtn.textContent = 'Enregistrer la configuration';
    $saveBtn.disabled = false;

    // Notifie tous les onglets Gmail / Outlook ouverts du changement
    chrome.tabs.query(
      { url: ['https://mail.google.com/*', 'https://outlook.live.com/*', 'https://outlook.office.com/*'] },
      tabs => tabs.forEach(t =>
        chrome.tabs.sendMessage(t.id, {
          type: 'SETTINGS_CHANGED',
          settings: { apiUrl, theme: currentTheme, font: currentFont, detailLevel: currentDetail },
        }).catch(() => {})
      )
    );

    if (isFirstRun) {
      $closeBtn.style.display = 'block';
      $note.textContent = 'Vous pouvez fermer cet onglet et ouvrir Gmail ou Outlook.';
    }
  });
});

$closeBtn.addEventListener('click', () => window.close());
