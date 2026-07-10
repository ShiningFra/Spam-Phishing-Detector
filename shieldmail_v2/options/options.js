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

// ── Chargement des valeurs existantes (utile pour une modification ultérieure) ──
chrome.storage.local.get(['apiUrl', 'abuseipdbKey', 'virustotalKey'], d => {
  $apiUrl.value        = d.apiUrl || 'http://localhost:8000';
  $abuseipdbKey.value   = d.abuseipdbKey  || '';
  $virustotalKey.value  = d.virustotalKey || '';
});

if (isFirstRun) {
  $note.textContent = 'Une fois enregistrée, cette étape ne sera plus demandée.';
}

// ── Sauvegarde ──────────────────────────────────────────────────────
$saveBtn.addEventListener('click', () => {
  const apiUrl = $apiUrl.value.trim().replace(/\/$/, '') || 'http://localhost:8000';

  $saveBtn.disabled = true;
  $saveBtn.textContent = 'Enregistrement...';

  chrome.storage.local.set({
    apiUrl,
    abuseipdbKey:  $abuseipdbKey.value.trim(),
    virustotalKey: $virustotalKey.value.trim(),
    setupComplete: true,
  }, () => {
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
          settings: { apiUrl },
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
