// ShieldMail v2.1 — Content Script (corrigé)
'use strict';

let CFG = {
  apiUrl:'http://localhost:8000', abuseipdbKey:'', virustotalKey:'',
  autoAnalyze:true, showBadges:true, showAlert:true,
};
chrome.storage.local.get(
  ['apiUrl','abuseipdbKey','virustotalKey','autoAnalyze','showBadges','showAlert'],
  d => Object.assign(CFG, d)
);
chrome.runtime.onMessage.addListener(msg => {
  if (msg.type==='SETTINGS_CHANGED') Object.assign(CFG, msg.settings);
});

const analysisCache = new Map();

// ── Extraction ────────────────────────────────────────────────────
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
  return {text,sender,domain,ips,urlDomains:urlDoms};
}

// ── Panneau ───────────────────────────────────────────────────────
function createPanel() {
  if (document.getElementById('sm-panel')) return;
  const el = document.createElement('div');
  el.id='sm-panel'; el.className='sm-hidden';
  el.innerHTML=`
    <div class="sm-header">
      <div class="sm-dot"></div><span class="sm-title">ShieldMail</span>
      <span class="sm-badge-v">v2.1</span><button class="sm-close">✕</button>
    </div>
    <div id="sm-verdict" class="sm-verdict">
      <div id="sm-icon" class="sm-vicon">🔍</div>
      <div style="flex:1"><div id="sm-class" class="sm-vclass">—</div><div id="sm-sub" class="sm-vsub">en attente</div></div>
      <div class="sm-conf-wrap"><div id="sm-conf" class="sm-conf-num">—</div><div class="sm-conf-lbl">confiance</div></div>
    </div>
    <div id="sm-explain" class="sm-explain"></div>
    <div class="sm-section">
      <div class="sm-slabel">// Probabilités par classe</div>
      <div class="sm-prow"><span class="sm-pname">HAM</span><div class="sm-ptrack"><div class="sm-pfill ham" id="sm-ph"></div></div><span class="sm-pval" id="sm-vh">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">SPAM</span><div class="sm-ptrack"><div class="sm-pfill spam" id="sm-ps"></div></div><span class="sm-pval" id="sm-vs">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">PHISHING</span><div class="sm-ptrack"><div class="sm-pfill phishing" id="sm-pp"></div></div><span class="sm-pval" id="sm-vp">0%</span></div>
    </div>
    <div class="sm-section" id="sm-ip-section" style="display:none">
      <div class="sm-slabel">// Réputation IP (AbuseIPDB)</div><div id="sm-ip-list"></div>
    </div>
    <div class="sm-section" id="sm-vt-section" style="display:none">
      <div class="sm-slabel">// Réputation domaine (VirusTotal)</div><div id="sm-vt-list"></div>
    </div>
    <div class="sm-section" id="sm-flags-section">
      <div class="sm-slabel">// Indicateurs détectés</div>
      <div id="sm-flags" class="sm-flags"></div>
    </div>
    <div class="sm-section" id="sm-correct-section" style="display:none">
      <div class="sm-slabel">// Corriger la prédiction</div>
      <div id="sm-correct-btns" style="display:flex;gap:6px;flex-wrap:wrap"></div>
      <div id="sm-correct-fb" style="font-size:10px;color:#00D4B4;margin-top:6px;display:none">✓ Correction enregistrée</div>
    </div>
    <div class="sm-footer">
      <div class="sm-lat"><div class="sm-latdot"></div><span id="sm-latval">—</span></div>
      <button class="sm-reanalyze" id="sm-redo">↻ Réanalyser</button>
    </div>`;
  document.body.appendChild(el);
  el.querySelector('.sm-close').onclick = () => el.classList.replace('sm-visible','sm-hidden');
  el.querySelector('#sm-redo').onclick  = () => runAnalysis(true);
}

// ── Remplissage ───────────────────────────────────────────────────
// IMPORTANT : l'API renvoie le champ `ml_proba` (pas `ml_probabilities`).
// Champs réels de /analyze (pipeline_v2.py) :
//   predicted_class, threat_level, global_confidence, ml_proba,
//   rule_score, header_score, rules_triggered, header_flags, url_flags,
//   latency_ms, decision_path, explanation, whitelisted, weights_used,
//   spam_category
function fillPanel(r, text) {
  const p = document.getElementById('sm-panel'); if (!p) return;
  const cls=r.predicted_class||'ham', conf=r.global_confidence||0;
  const ICONS={ham:'✓',spam:'✕',phishing:'⚠'};
  const LABELS={ham:'Email légitime',spam:'Spam détecté',phishing:'Phishing détecté'};

  p.querySelector('#sm-verdict').className=`sm-verdict ${cls}`;
  p.querySelector('#sm-icon').textContent=ICONS[cls]||'?';
  p.querySelector('#sm-class').textContent=cls.toUpperCase();

  let sub = LABELS[cls]||'';
  if (cls==='spam' && r.spam_category) {
    const CATS={financial:'investissement frauduleux',scam:'arnaque',pharma:'pharmaceutique',marketing:'marketing agressif'};
    sub += ` · ${CATS[r.spam_category]||r.spam_category}`;
  }
  if (r.whitelisted) sub = 'Domaine reconnu comme légitime';
  p.querySelector('#sm-sub').textContent=sub;
  p.querySelector('#sm-conf').textContent=`${(conf*100).toFixed(0)}%`;

  const explainEl = p.querySelector('#sm-explain');
  if (r.explanation) { explainEl.textContent = r.explanation; explainEl.style.display=''; }
  else { explainEl.style.display='none'; }

  // Probabilités par classe — champ correct : ml_proba
  // Cas whitelist : ml_proba est vide ({}), on force un affichage cohérent
  // avec la décision (ham=100%) plutôt que des barres à 0% trompeuses.
  const pr = (r.ml_proba && Object.keys(r.ml_proba).length>0)
    ? r.ml_proba
    : (r.whitelisted ? {ham:1,spam:0,phishing:0} : {ham:0,spam:0,phishing:0});
  setTimeout(()=>{
    [['ham','ph','vh'],['spam','ps','vs'],['phishing','pp','vp']].forEach(([k,fi,vi])=>{
      const v=(pr[k]||0)*100;
      const f=p.querySelector(`#sm-${fi}`); if(f) f.style.width=`${v.toFixed(1)}%`;
      const val=p.querySelector(`#sm-${vi}`); if(val) val.textContent=`${v.toFixed(0)}%`;
    });
  },80);

  const ipSection = p.querySelector('#sm-ip-section');
  if ((r.ip_reputations||[]).length>0){
    ipSection.style.display='';
    p.querySelector('#sm-ip-list').innerHTML=r.ip_reputations.map(ip=>{
      const c=ip.abuseScore>=75?'danger':ip.abuseScore>=15?'warning':'ok';
      return `<div class="sm-ip-row"><span class="sm-flag ${c}">${esc(ip.ip)}</span><span class="sm-ip-score ${c}">${ip.abuseScore}% abuse</span><span class="sm-ip-meta">${esc(ip.countryCode)} · ${ip.totalReports} signalements</span></div>`;
    }).join('');
  } else { ipSection.style.display='none'; }

  const vtSection = p.querySelector('#sm-vt-section');
  if ((r.domain_reputations||[]).length>0){
    vtSection.style.display='';
    p.querySelector('#sm-vt-list').innerHTML=r.domain_reputations.map(d=>{
      const c=d.malicious>3?'danger':d.malicious>0?'warning':'ok';
      return `<div class="sm-vt-row"><span class="sm-flag ${c}">${esc(d.domain)}</span><span class="sm-vt-score ${c}">${d.malicious}/${d.total} détections</span></div>`;
    }).join('');
  } else { vtSection.style.display='none'; }

  // Indicateurs : règles + URL + headers. On masque les codes purement
  // techniques sans valeur pour l'utilisateur (ex: "no_raw_email").
  const TECHNICAL_NOISE = new Set(['no_raw_email']);
  const allFlags = [
    ...(r.rules_triggered||[]).map(f=>({t:f,c:'warning'})),
    ...(r.url_flags||[]).map(f=>({t:f,c:'danger'})),
    ...(r.header_flags||[]).filter(f=>!TECHNICAL_NOISE.has(f)).map(f=>({t:f,c:'danger'})),
  ];
  p.querySelector('#sm-flags').innerHTML = allFlags.length>0
    ? allFlags.map(f=>`<span class="sm-flag ${f.c}">${esc(humanizeFlag(f.t))}</span>`).join('')
    : '<span class="sm-flag ok">Aucun indicateur suspect</span>';

  p.querySelector('#sm-latval').textContent=r.latency_ms?`${r.latency_ms.toFixed(1)}ms`:'—';
  showCorrectionButtons(cls, text, p);
}

// Reformulation succincte des codes techniques en libellés lisibles,
// sans perdre l'information (objectif : filtrer le bruit pur tout en
// restant exploitable pour une analyse technique).
function humanizeFlag(flag) {
  const RENAMES = {
    'spf_fail':'SPF invalide', 'spf_missing':'SPF absent', 'spf_pass':'SPF valide',
    'dkim_missing':'DKIM absent', 'dkim_present':'DKIM présent',
    'dmarc_fail':'DMARC invalide', 'dmarc_pass':'DMARC valide',
    'at_in_url':'URL avec @ (obfuscation)',
  };
  if (RENAMES[flag]) return RENAMES[flag];
  if (flag.startsWith('ip_url:'))               return 'URL avec IP brute';
  if (flag.startsWith('suspicious_tld:'))       return `TLD suspect (${flag.split(':')[1]})`;
  if (flag.startsWith('brand_impersonation:'))  return `Marque usurpée (${flag.split(':')[1]||''})`;
  if (flag.startsWith('scam_domain_keyword:'))  return `Domaine suspect (${flag.split('@')[1]||''})`;
  if (flag.startsWith('domain_mismatch:'))      return 'Expéditeur ≠ Répondre-à';
  if (flag.startsWith('return_path_mismatch:')) return 'Chemin de retour incohérent';
  if (flag.startsWith('uppercase_'))            return 'Majuscules excessives';
  if (flag.startsWith('exclamation_x'))         return 'Ponctuation excessive';
  if (flag.startsWith('spam_financial'))        return 'Vocabulaire investissement frauduleux';
  if (flag.startsWith('spam_scam'))             return 'Vocabulaire arnaque';
  if (flag.startsWith('spam_pharma'))           return 'Vocabulaire pharmaceutique douteux';
  if (flag.startsWith('spam_marketing'))        return 'Marketing agressif';
  if (flag.startsWith('phish_kw:'))             return `Mot-clé phishing (${flag.split(':')[1]||''})`;
  if (flag.startsWith('invisible_unicode'))     return 'Caractères invisibles détectés';
  return flag;
}

function esc(s){ return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;'); }

// ── Boutons correction (post-entraînement) ────────────────────────
function showCorrectionButtons(predicted, text, p) {
  const section=p.querySelector('#sm-correct-section');
  const btnsDiv=p.querySelector('#sm-correct-btns');
  const fb=p.querySelector('#sm-correct-fb');
  section.style.display=''; fb.style.display='none';
  btnsDiv.innerHTML=['ham','spam','phishing'].map(cls=>`
    <button class="sm-correct-btn ${cls} ${cls===predicted?'active':''}" data-cls="${cls}">
      ${cls===predicted?'✓ ':''}${cls.toUpperCase()}
    </button>`).join('');
  btnsDiv.querySelectorAll('.sm-correct-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
      sendCorrection(text, btn.dataset.cls, predicted);
      btnsDiv.querySelectorAll('.sm-correct-btn').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      fb.style.display='block';
      setTimeout(()=>{fb.style.display='none';},3000);
    });
  });
}

// ── Post-entraînement ─────────────────────────────────────────────
async function sendCorrection(text, correctLabel, predictedLabel) {
  chrome.storage.local.get(['corrections_buffer'],d=>{
    const buf=d.corrections_buffer||[];
    buf.push({text:text.slice(0,3000),label:correctLabel,predicted:predictedLabel,ts:Date.now()});
    chrome.storage.local.set({corrections_buffer:buf});
  });
  try {
    await fetch(`${CFG.apiUrl.replace(/\/$/,'')}/feedback`,{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        text,
        correct_label:correctLabel,
        predicted_label:predictedLabel,
        confidence:0,
      }),
      signal:AbortSignal.timeout(5000)
    });
  } catch { /* mis en buffer local, sera retenté plus tard */ }
}

// ── Alerte ────────────────────────────────────────────────────────
function showAlert(r) {
  if (!CFG.showAlert) return;
  const ipBad=(r.ip_reputations||[]).some(i=>i.abuseScore>=75);
  const vtBad=(r.domain_reputations||[]).some(d=>d.malicious>3);
  if (!['high','critical'].includes(r.threat_level)&&!ipBad&&!vtBad) return;
  let el=document.getElementById('sm-alert');
  if (!el){el=document.createElement('div');el.id='sm-alert';document.body.appendChild(el);}
  const conf=((r.global_confidence||0)*100).toFixed(0);
  const ipI=r.ip_reputations?.find(i=>i.abuseScore>=75);
  const vtI=r.domain_reputations?.find(d=>d.malicious>3);
  let reason=`${(r.predicted_class||'').toUpperCase()} détecté (${conf}%)`;
  if(ipI) reason+=` · IP suspecte (${ipI.abuseScore}%)`;
  if(vtI) reason+=` · domaine signalé (${vtI.malicious} moteurs)`;
  el.className='sm-alert-bar';
  el.innerHTML=`<span class="sm-alert-icon">🚨</span>
    <div class="sm-alert-txt"><b>ShieldMail — Menace détectée</b><br><small>${esc(reason)}</small></div>
    <button id="sm-alert-close">✕</button>`;
  el.querySelector('#sm-alert-close').onclick=()=>el.remove();
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
  const {text,domain,ips,urlDomains}=extractEmailInfo();
  if (!text) return;
  panel.querySelector('#sm-class').textContent='Analyse...';
  panel.querySelector('#sm-icon').textContent='⟳';
  panel.querySelector('#sm-conf').textContent='—';
  panel.querySelector('#sm-sub').textContent='en cours';
  panel.className='sm-visible';

  const [mlRes,ipRes,domRes]=await Promise.all([
    chrome.runtime.sendMessage({type:'ANALYZE_EMAIL',text,apiUrl:CFG.apiUrl})
      .then(r=>r.ok?{result:r.result,demo:false}:{result:buildFallback(text),demo:true})
      .catch(()=>({result:buildFallback(text),demo:true})),
    CFG.abuseipdbKey?Promise.all(ips.slice(0,3).map(ip=>
      chrome.runtime.sendMessage({type:'CHECK_IP',ip,abuseipdbKey:CFG.abuseipdbKey})
        .then(r=>r.ok?r.result:null).catch(()=>null)
    )).then(rs=>rs.filter(Boolean)):Promise.resolve([]),
    CFG.virustotalKey?Promise.all([...new Set([domain,...urlDomains])].slice(0,3).map(d=>
      chrome.runtime.sendMessage({type:'CHECK_DOMAIN',domain:d,virustotalKey:CFG.virustotalKey})
        .then(r=>r.ok?r.result:null).catch(()=>null)
    )).then(rs=>rs.filter(Boolean)):Promise.resolve([]),
  ]);

  const ml=mlRes.result;
  const result={...ml,_text:text,ip_reputations:ipRes,domain_reputations:domRes,
    threat_level:aggThreat(ml,ipRes,domRes),_demo:mlRes.demo};
  analysisCache.set(key,result);
  fillPanel(result,text);
  showAlert(result);
  chrome.runtime.sendMessage({type:'SAVE_RESULT',result,preview:text.slice(0,60)});
}

function aggThreat(ml,ips,doms){
  const O=['none','low','medium','high','critical'];
  return [[ml.threat_level||'none'],...ips.map(i=>i.threatLevel||'none'),...doms.map(d=>d.threatLevel||'none')]
    .reduce((w,l)=>O.indexOf(l)>O.indexOf(w)?l:w,'none');
}

// Mode dégradé si l'API locale est inaccessible (affiché clairement
// comme estimation grossière, pas comme un résultat du pipeline réel).
function buildFallback(text){
  const t=text.toLowerCase();
  const p=['verify','suspended','login','paypal','bank','password'].filter(k=>t.includes(k)).length;
  const s=['free','win','congratulations','!!!','earn'].filter(k=>t.includes(k)).length;
  let cls='ham',conf=0.55,threat='none';
  if(p>=2){cls='phishing';conf=0.60;threat='medium';}
  else if(s>=2){cls='spam';conf=0.55;threat='low';}
  const rest=(1-conf)/2;
  return {predicted_class:cls,threat_level:threat,global_confidence:conf,
    ml_proba:{ham:rest,spam:rest,phishing:rest,[cls]:conf},
    rules_triggered:[],url_flags:[],header_flags:[],latency_ms:0,
    explanation:'Estimation hors-ligne (API locale inaccessible) — résultat indicatif uniquement.',
    whitelisted:false, weights_used:{}, spam_category:''};
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
    chrome.runtime.sendMessage({type:'ANALYZE_EMAIL',text,apiUrl:CFG.apiUrl})
      .then(r=>{
        if(!r.ok) throw new Error();
        const cls=r.result.predicted_class;
        const conf=((r.result.global_confidence||0)*100).toFixed(0);
        badge.className=`sm-badge ${cls}`;
        badge.textContent=`${cls} ${conf}%`;
        badge.title=`ShieldMail : ${cls.toUpperCase()} — ${conf}%`;
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
