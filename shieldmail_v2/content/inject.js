// ShieldMail v2.1 — Content Script
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
    <div class="sm-section">
      <div class="sm-slabel">// Pipeline IA</div>
      <div class="sm-prow"><span class="sm-pname">HAM</span><div class="sm-ptrack"><div class="sm-pfill ham" id="sm-ph"></div></div><span class="sm-pval" id="sm-vh">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">SPAM</span><div class="sm-ptrack"><div class="sm-pfill spam" id="sm-ps"></div></div><span class="sm-pval" id="sm-vs">0%</span></div>
      <div class="sm-prow"><span class="sm-pname">PHISHING</span><div class="sm-ptrack"><div class="sm-pfill phishing" id="sm-pp"></div></div><span class="sm-pval" id="sm-vp">0%</span></div>
    </div>
    <div class="sm-section" id="sm-ip-section" style="display:none">
      <div class="sm-slabel">// AbuseIPDB</div><div id="sm-ip-list"></div>
    </div>
    <div class="sm-section" id="sm-vt-section" style="display:none">
      <div class="sm-slabel">// VirusTotal</div><div id="sm-vt-list"></div>
    </div>
    <div class="sm-section">
      <div class="sm-slabel">// Indicateurs</div>
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
  setTimeout(()=>{
    [['ham','ph','vh'],['spam','ps','vs'],['phishing','pp','vp']].forEach(([k,fi,vi])=>{
      const v=(pr[k]||0)*100;
      const f=p.querySelector(`#sm-${fi}`); if(f) f.style.width=`${v.toFixed(1)}%`;
      const val=p.querySelector(`#sm-${vi}`); if(val) val.textContent=`${v.toFixed(0)}%`;
    });
  },100);
  if((r.ip_reputations||[]).length>0){
    p.querySelector('#sm-ip-section').style.display='';
    p.querySelector('#sm-ip-list').innerHTML=r.ip_reputations.map(ip=>{
      const c=ip.abuseScore>=75?'danger':ip.abuseScore>=15?'warning':'ok';
      return `<div class="sm-ip-row"><span class="sm-flag ${c}">${ip.ip}</span><span class="sm-ip-score ${c}">${ip.abuseScore}% abuse</span><span class="sm-ip-meta">${ip.countryCode} · ${ip.totalReports} signalements</span></div>`;
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
  showCorrectionButtons(cls, text, p);
}

// ── Boutons correction (post-entraînement) ────────────────────────
function showCorrectionButtons(predicted, text, p) {
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
  // Buffer local
  chrome.storage.local.get(['corrections_buffer'],d=>{
    const buf=d.corrections_buffer||[];
    buf.push({text:text.slice(0,3000),label:correctLabel,predicted:predictedLabel,ts:Date.now()});
    chrome.storage.local.set({corrections_buffer:buf});
  });
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
  if (!['high','critical'].includes(r.threat_level)&&!ipBad&&!vtBad) return;
  let el=document.getElementById('sm-alert');
  if (!el){el=document.createElement('div');el.id='sm-alert';document.body.appendChild(el);}
  const conf=((r.global_confidence||0)*100).toFixed(0);
  const ipI=r.ip_reputations?.find(i=>i.abuseScore>=75);
  const vtI=r.domain_reputations?.find(d=>d.malicious>3);
  let reason=`IA: ${r.predicted_class} (${conf}%)`;
  if(ipI) reason+=` · IP ${ipI.ip} (${ipI.abuseScore}% abuse)`;
  if(vtI) reason+=` · ${vtI.domain} (${vtI.malicious} VT)`;
  el.className='sm-alert-bar';
  el.innerHTML=`<span class="sm-alert-icon">🚨</span>
    <div class="sm-alert-txt"><b>ShieldMail — Menace détectée</b><br><small>${reason}</small></div>
    <button onclick="this.parentElement.remove()">✕</button>`;
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
  panel.className='sm-visible';

  const [ml,ipRes,domRes]=await Promise.all([
    chrome.runtime.sendMessage({type:'ANALYZE_EMAIL',text,apiUrl:CFG.apiUrl})
      .then(r=>r.ok?r.result:buildFallback(text)).catch(()=>buildFallback(text)),
    CFG.abuseipdbKey?Promise.all(ips.slice(0,3).map(ip=>
      chrome.runtime.sendMessage({type:'CHECK_IP',ip,abuseipdbKey:CFG.abuseipdbKey})
        .then(r=>r.ok?r.result:null).catch(()=>null)
    )).then(rs=>rs.filter(Boolean)):Promise.resolve([]),
    CFG.virustotalKey?Promise.all([...new Set([domain,...urlDomains])].slice(0,3).map(d=>
      chrome.runtime.sendMessage({type:'CHECK_DOMAIN',domain:d,virustotalKey:CFG.virustotalKey})
        .then(r=>r.ok?r.result:null).catch(()=>null)
    )).then(rs=>rs.filter(Boolean)):Promise.resolve([]),
  ]);

  const result={...ml,_text:text,ip_reputations:ipRes,domain_reputations:domRes,
    threat_level:aggThreat(ml,ipRes,domRes)};
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

function buildFallback(text){
  const t=text.toLowerCase();
  const p=['verify','suspended','login','paypal','bank','password'].filter(k=>t.includes(k)).length;
  const s=['free','win','congratulations','!!!','earn'].filter(k=>t.includes(k)).length;
  let cls='ham',conf=0.88,threat='none';
  if(p>=2){cls='phishing';conf=0.82;threat='critical';}
  else if(s>=2){cls='spam';conf=0.78;threat='high';}
  const rest=(1-conf)/2;
  return {predicted_class:cls,threat_level:threat,global_confidence:conf,
    ml_probabilities:{ham:rest,spam:rest,phishing:rest,[cls]:conf},
    rules_triggered:[],url_flags:[],header_flags:[],latency_ms:0,_demo:true};
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
