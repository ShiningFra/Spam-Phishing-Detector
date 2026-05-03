# -*- coding: utf-8 -*-
import re
import html
import logging
import joblib
import numpy as np
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
from dataclasses import dataclass, field

logger = logging.getLogger("spam_detector")

DATA_DIR = Path(__file__).parent.parent / "data"

# ── Listes noires ─────────────────────────────────────────────────
BLACKLISTED_TLDS = {
    'xyz','info','biz','club','online','site','top','win','gq','tk','ml',
    'ga','cf','pw','cc','ws','icu','live','click','link','loan','work','men','download'
}
IMPERSONATED_BRANDS = [
    'paypal','amazon','microsoft','apple','google','netflix','facebook',
    'instagram','dhl','fedex','ups','irs','bank','secure','login','verify',
    'account','update','confirm','coinbase','binance','zoom','docusign'
]
SPAM_KEYWORDS = [
    'click here','act now','limited time','free gift','you won','congratulations',
    'claim your','no prescription','weight loss','make money','work from home',
    'earn cash','million dollar','casino','guaranteed return','double your',
    'wire transfer','nigerian prince','viagra','cialis'
]
PHISHING_KEYWORDS = [
    'verify your account','confirm your identity','suspended','unusual activity',
    'security alert','update your password','click to verify',
    'your account will be','immediately','within 24 hours','unauthorized access'
]

# ── Nettoyage texte ───────────────────────────────────────────────
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.stem   import WordNetLemmatizer
    nltk.download('stopwords', quiet=True)
    nltk.download('wordnet',   quiet=True)
    STOP_WORDS = set(stopwords.words('english'))
    LEMMATIZER = WordNetLemmatizer()
    NLTK_OK    = True
except Exception:
    STOP_WORDS = set()
    LEMMATIZER = None
    NLTK_OK    = False

_RE_HTML  = re.compile(r'<[^>]+>')
_RE_URL   = re.compile(r'https?://\S+|www\.\S+')
_RE_EMAIL = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')
_RE_NUM   = re.compile(r'\b\d+\b')
_RE_PUNCT = re.compile(r'[^\w\s]')

def clean_text(text: str) -> str:
    if not isinstance(text, str): return ''
    text = html.unescape(text)
    text = _RE_HTML.sub(' ', text)
    text = _RE_URL.sub(' urltoken ', text)
    text = _RE_EMAIL.sub(' emailtoken ', text)
    text = text.lower()
    text = _RE_NUM.sub(' numtoken ', text)
    text = _RE_PUNCT.sub(' ', text)
    tokens = text.split()
    if NLTK_OK:
        tokens = [LEMMATIZER.lemmatize(t) for t in tokens
                  if t not in STOP_WORDS or t in ('urltoken','emailtoken')]
    return ' '.join(t for t in tokens if len(t) >= 2)


# ── Features structurelles ────────────────────────────────────────
def extract_structural_features(text: str) -> dict:
    urls  = re.findall(r'https?://[^\s<>"]+', text)
    words = text.split()
    alpha = [c for c in text if c.isalpha()]
    ip_url   = sum(1 for u in urls if re.search(r'https?://\d{1,3}\.\d{1,3}', u))
    susp_tld = sum(1 for u in urls
                   if urlparse(u).netloc.rsplit('.',1)[-1] in BLACKLISTED_TLDS)
    brand    = sum(1 for u in urls for b in IMPERSONATED_BRANDS if b in u.lower())
    return {
        'url_count':           len(urls),
        'has_ip_url':          int(ip_url > 0),
        'has_suspicious_tld':  int(susp_tld > 0),
        'has_brand_in_url':    int(brand > 0),
        'url_max_length':      max((len(u) for u in urls), default=0),
        'url_avg_length':      float(np.mean([len(u) for u in urls])) if urls else 0.0,
        'url_subdomain_count': float(np.mean([urlparse(u).netloc.count('.')-1 for u in urls])) if urls else 0.0,
        'has_at_in_url':       int(any('@' in u for u in urls)),
        'url_digit_ratio':     sum(c.isdigit() for u in urls for c in u)/max(sum(len(u) for u in urls),1),
        'url_special_char':    sum(len(re.findall(r'[%@#!$&*]', u)) for u in urls),
        'char_count':          len(text),
        'word_count':          len(words),
        'exclamation_count':   text.count('!'),
        'question_count':      text.count('?'),
        'dollar_count':        text.count('$'),
        'uppercase_ratio':     sum(1 for c in alpha if c.isupper())/max(len(alpha),1),
        'digit_ratio':         sum(c.isdigit() for c in text)/max(len(text),1),
        'has_html':            int(bool(re.search(r'<[a-zA-Z][^>]*>', text))),
        'avg_word_length':     float(np.mean([len(w) for w in words])) if words else 0.0,
        'unique_word_ratio':   len(set(words))/max(len(words),1),
    }


# ── Regles heuristiques ───────────────────────────────────────────
def apply_heuristic_rules(text: str):
    if not isinstance(text, str): return 0.0, 0.0, [], []
    tl = text.lower()
    rules, url_flags, spam_pts, phish_pts = [], [], 0.0, 0.0
    excl = text.count('!')
    if excl >= 3: spam_pts += min(excl*0.05, 0.25); rules.append(f'exclamation_x{excl}')
    alpha = [c for c in text if c.isalpha()]
    up_r  = sum(1 for c in alpha if c.isupper())/max(len(alpha),1)
    if up_r > 0.3: spam_pts += 0.2; rules.append(f'uppercase_{up_r:.0%}')
    if text.count('$') >= 2: spam_pts += 0.15; rules.append('dollar_signs')
    for kw in SPAM_KEYWORDS:
        if kw in tl: spam_pts += 0.1; rules.append(f'spam_kw:{kw}')
    urls = re.findall(r'https?://[^\s<>"]+', text)
    for url in urls:
        try:
            parsed = urlparse(url)
            h = parsed.netloc.lower()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', h):
                phish_pts += 0.4; url_flags.append(f'ip_url:{url[:50]}')
            tld = h.rsplit('.',1)[-1] if '.' in h else ''
            if tld in BLACKLISTED_TLDS:
                phish_pts += 0.25; url_flags.append(f'suspicious_tld:.{tld}')
            for brand in IMPERSONATED_BRANDS:
                if brand in h and not h.endswith(f'{brand}.com'):
                    phish_pts += 0.3; url_flags.append(f'brand:{brand}@{h}'); break
            if '@' in parsed.netloc:
                phish_pts += 0.35; url_flags.append('at_in_url')
        except Exception: pass
    for kw in PHISHING_KEYWORDS:
        if kw in tl: phish_pts += 0.08; rules.append(f'phish_kw:{kw}')
    invisible = sum(1 for c in text if ord(c) in range(0x200B,0x200F))
    if invisible: phish_pts += 0.4; rules.append(f'invisible_chars_x{invisible}')
    return min(spam_pts,1.0), min(phish_pts,1.0), rules, url_flags


# ── Analyse headers ───────────────────────────────────────────────
import email as email_lib

def analyze_headers(raw_email: str):
    try: msg = email_lib.message_from_string(raw_email)
    except Exception: return 0.0, ['no_headers_parsed']
    flags, score = [], 0.0
    def dom(addr):
        m = re.search(r'@([\w.-]+)', addr or '')
        return m.group(1).lower() if m else ''
    from_dom   = dom(msg.get('From',''))
    reply_dom  = dom(msg.get('Reply-To',''))
    return_dom = dom(msg.get('Return-Path',''))
    spf = msg.get('Received-SPF','').lower()
    if 'fail' in spf or 'softfail' in spf: score += 0.35; flags.append('spf_fail')
    elif 'pass' in spf: score -= 0.1; flags.append('spf_pass')
    else: score += 0.1; flags.append('spf_missing')
    if not msg.get('DKIM-Signature',''): score += 0.15; flags.append('dkim_missing')
    else: flags.append('dkim_present')
    dmarc = msg.get('Authentication-Results','').lower()
    if 'dmarc=fail' in dmarc: score += 0.4; flags.append('dmarc_fail')
    elif 'dmarc=pass' in dmarc: score -= 0.15; flags.append('dmarc_pass')
    if reply_dom and from_dom and reply_dom != from_dom:
        score += 0.3; flags.append(f'domain_mismatch:from={from_dom},reply={reply_dom}')
    if return_dom and from_dom and return_dom != from_dom:
        score += 0.2; flags.append(f'return_path_mismatch:{return_dom}')
    return max(0.0, min(score,1.0)), flags


# ── Dataclass resultat ────────────────────────────────────────────
@dataclass
class AnalysisResult:
    predicted_class:   str   = 'ham'
    threat_level:      str   = 'none'
    global_confidence: float = 0.0
    rule_score:        float = 0.0
    header_score:      float = 0.0
    ml_proba:          dict  = field(default_factory=dict)
    bert_proba:        dict  = field(default_factory=dict)
    rules_triggered:   list  = field(default_factory=list)
    header_flags:      list  = field(default_factory=list)
    url_flags:         list  = field(default_factory=list)
    latency_ms:        float = 0.0
    decision_path:     str   = ''

    def to_dict(self):
        return {
            'predicted_class':   self.predicted_class,
            'threat_level':      self.threat_level,
            'global_confidence': round(self.global_confidence, 4),
            'rule_score':        round(self.rule_score, 4),
            'header_score':      round(self.header_score, 4),
            'ml_proba':          {k: round(v,4) for k,v in self.ml_proba.items()},
            'bert_proba':        {k: round(v,4) for k,v in self.bert_proba.items()},
            'rules_triggered':   self.rules_triggered,
            'header_flags':      self.header_flags,
            'url_flags':         self.url_flags,
            'latency_ms':        round(self.latency_ms, 2),
            'decision_path':     self.decision_path,
        }


# ── Pipeline hybride reconstruit ──────────────────────────────────
class HybridEmailPipeline:
    """Pipeline hybride reconstruit directement — pas de dependance au pkl notebook."""

    WEIGHTS = {'rules': 0.20, 'headers': 0.25, 'ml': 0.55}
    LEVELS  = ['none','low','medium','high','critical']

    def __init__(self):
        self._ml_model      = None
        self._tfidf         = None
        self._label_encoder = None
        self._class_names   = ['ham','phishing','spam']

    def load_models(self):
        self._tfidf         = joblib.load(DATA_DIR / 'tfidf_vectorizer.pkl')
        self._ml_model      = joblib.load(DATA_DIR / 'best_model.pkl')
        self._label_encoder = joblib.load(DATA_DIR / 'label_encoder.pkl')
        self._class_names   = list(self._label_encoder.classes_)
        logger.info(f"Modeles charges — classes : {self._class_names}")

    def _predict_ml(self, text: str) -> dict:
        cleaned  = clean_text(text)
        X_tfidf  = self._tfidf.transform([cleaned])
        X_struct = csr_matrix([list(extract_structural_features(text).values())])
        # Ajuster la taille si necessaire
        expected = self._tfidf.transform(['']).shape[1]
        if X_struct.shape[1] + X_tfidf.shape[1] != X_tfidf.shape[1] + X_struct.shape[1]:
            pass
        try:
            X = hstack([X_tfidf, X_struct])
            proba = self._ml_model.predict_proba(X)[0]
        except Exception:
            X = X_tfidf
            proba = self._ml_model.predict_proba(X)[0]
        return {c: float(p) for c, p in zip(self._class_names, proba)}

    def _aggregate(self, rule_spam, rule_phish, header_score, ml_proba):
        rule_ham = max(0.0, 1.0 - rule_spam - rule_phish)
        rule_vec = {'ham': rule_ham, 'spam': rule_spam, 'phishing': rule_phish}
        head_vec = {
            'ham':      max(0.0, 1.0 - header_score),
            'spam':     header_score * 0.4,
            'phishing': header_score * 0.6,
        }
        final = {}
        for c in self._class_names:
            final[c] = (self.WEIGHTS['rules']   * rule_vec.get(c,0) +
                        self.WEIGHTS['headers']  * head_vec.get(c,0) +
                        self.WEIGHTS['ml']       * ml_proba.get(c,0))
        total = sum(final.values())
        if total > 0: final = {c: v/total for c,v in final.items()}
        pred = max(final, key=final.get)
        conf = final[pred]
        if pred == 'ham': threat = 'none'
        elif conf >= 0.75: threat = 'critical' if pred=='phishing' else 'high'
        elif conf >= 0.50: threat = 'high'     if pred=='phishing' else 'medium'
        elif conf >= 0.30: threat = 'medium'   if pred=='phishing' else 'low'
        else:              threat = 'low'
        return pred, conf, threat

    def analyze(self, text: str, raw_email: str = '') -> AnalysisResult:
        from time import time
        t0 = time()
        result = AnalysisResult()
        path   = []

        # Couche 1 : regles
        rule_spam, rule_phish, rules_hit, url_flags = apply_heuristic_rules(text)
        result.rule_score      = max(rule_spam, rule_phish)
        result.rules_triggered = rules_hit
        result.url_flags       = url_flags
        path.append(f'rules(s={rule_spam:.2f},p={rule_phish:.2f})')

        # Early stop
        if rule_phish >= 0.95:
            result.predicted_class   = 'phishing'
            result.global_confidence = rule_phish
            result.threat_level      = 'critical'
            result.latency_ms        = (time()-t0)*1000
            result.decision_path     = ' -> '.join(path) + ' -> EARLY_STOP_PHISHING'
            return result
        if rule_spam >= 0.95:
            result.predicted_class   = 'spam'
            result.global_confidence = rule_spam
            result.threat_level      = 'critical'
            result.latency_ms        = (time()-t0)*1000
            result.decision_path     = ' -> '.join(path) + ' -> EARLY_STOP_SPAM'
            return result

        # Couche 2 : headers
        if raw_email:
            header_score, header_flags = analyze_headers(raw_email)
        else:
            header_score, header_flags = 0.0, ['no_raw_email']
        result.header_score = header_score
        result.header_flags = header_flags
        path.append(f'headers({header_score:.2f})')

        # Couche 3 : ML
        try:
            ml_proba = self._predict_ml(text)
        except Exception as e:
            logger.warning(f"ML predict failed: {e} — fallback uniform")
            ml_proba = {c: 1.0/len(self._class_names) for c in self._class_names}
        result.ml_proba = ml_proba
        path.append(f'ml({max(ml_proba,key=ml_proba.get)})')

        # Agregation
        pred, conf, threat = self._aggregate(rule_spam, rule_phish, header_score, ml_proba)
        result.predicted_class   = pred
        result.global_confidence = conf
        result.threat_level      = threat
        result.latency_ms        = (time()-t0)*1000
        result.decision_path     = ' -> '.join(path) + f' -> {pred.upper()}({conf:.2f})'
        return result


# ── Loader (interface pour main.py) ──────────────────────────────
class PipelineLoader:
    def __init__(self):
        self._pipeline = HybridEmailPipeline()
        self._loaded   = False

    def load(self):
        logger.info("Chargement du pipeline hybride...")
        try:
            self._pipeline.load_models()
            self._loaded = True
            logger.info("Pipeline pret.")
        except FileNotFoundError as e:
            logger.error(f"Modele manquant : {e}")
            logger.error("Executer les notebooks 02, 03 et 05 pour generer les modeles.")
            raise

    @property
    def is_loaded(self): return self._loaded

    def analyze(self, text: str, raw_email: Optional[str] = None) -> dict:
        if not self._loaded: raise RuntimeError("Pipeline non charge.")
        return self._pipeline.analyze(text, raw_email or '').to_dict()

    def get_models_info(self) -> dict:
        return {
            'pipeline':    'HybridEmailPipeline (reconstruit)',
            'ml_model':    'LinearSVC (calibrated)',
            'bert':        False,
            'class_names': self._pipeline._class_names,
        }


pipeline_loader = PipelineLoader()
