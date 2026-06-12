# -*- coding: utf-8 -*-
"""
main_v2.py
==========
API FastAPI v2 — intègre pipeline_v2.py et auto_trainer.py.

Nouveaux endpoints :
  POST /whitelist          Ajouter un domaine à la whitelist
  GET  /performance        Métriques de performance temps réel
  GET  /scheduler/status   État du scheduler intelligent
  GET  /spam/stats         Statistiques dédiées à la classe spam
"""

import asyncio
import json
import logging
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ── Import des modules v2 ─────────────────────────────────────────
from pipeline_v2 import pipeline_loader
from auto_trainer import (
    scheduler, process_feedback, process_analysis_result,
    FEEDBACK_FILE, LOGS_DIR, DATA_DIR
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("api_v2")

_ROOT_DIR = Path(__file__).parent.parent
LOGS_DIR.mkdir(parents=True, exist_ok=True)
_DETECT_FILE = LOGS_DIR / "detections.jsonl"
_STATS_FILE  = DATA_DIR / "api_stats.json"


# ══════════════════════════════════════════════════════════════════
# GESTION LIFESPAN
# ══════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Démarrage API v2 — Détection Spam & Phishing...")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    pipeline_loader.load()
    logger.info("API v2 prête.")
    yield
    logger.info("Arrêt de l'API v2.")


# ══════════════════════════════════════════════════════════════════
# APPLICATION
# ══════════════════════════════════════════════════════════════════

app = FastAPI(
    title="API Détection Spam & Phishing v2",
    description=(
        "Pipeline hybride 4 couches avec apprentissage continu intelligent.\n\n"
        "Améliorations v2 : SpamBooster, Whitelist automatique, "
        "poids adaptatifs, scheduler intelligent, auto-labelling.\n\n"
        "Projet ENSPY 5GI — Nghogué Taptué Franck Roddier"
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Statistiques globales ─────────────────────────────────────────
_stats = {
    'total_analyzed':    0,
    'by_class':          {'ham': 0, 'spam': 0, 'phishing': 0},
    'by_threat':         {'none': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
    'spam_by_category':  {'financial': 0, 'scam': 0, 'pharma': 0, 'marketing': 0},
    'whitelisted_count': 0,
    'auto_labels_generated': 0,
    'updates_triggered': 0,
    'started_at':        datetime.now().isoformat(),
    'avg_latency_ms':    0.0,
}


def _update_stats(result: dict):
    _stats['total_analyzed'] += 1
    pred = result.get('predicted_class', 'ham')
    _stats['by_class'][pred] = _stats['by_class'].get(pred, 0) + 1
    threat = result.get('threat_level', 'none')
    _stats['by_threat'][threat] = _stats['by_threat'].get(threat, 0) + 1
    if result.get('whitelisted'):
        _stats['whitelisted_count'] += 1
    cat = result.get('spam_category', '')
    if cat:
        _stats['spam_by_category'][cat] = _stats['spam_by_category'].get(cat, 0) + 1
    # Moyenne glissante de la latence
    n = _stats['total_analyzed']
    _stats['avg_latency_ms'] = (
        (_stats['avg_latency_ms'] * (n - 1) + result.get('latency_ms', 0)) / n
    )


def _log_detection(result: dict, text_preview: str = ''):
    entry = {**result, 'text_preview': text_preview[:200],
             'analyzed_at': datetime.now().isoformat()}
    with open(_DETECT_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


# ══════════════════════════════════════════════════════════════════
# MODÈLES PYDANTIC
# ══════════════════════════════════════════════════════════════════

class EmailRequest(BaseModel):
    text:      str            = Field(..., min_length=1)
    raw_email: Optional[str]  = None
    email_id:  Optional[str]  = None

class BatchRequest(BaseModel):
    emails: List[EmailRequest] = Field(..., max_length=100)

class FeedbackRequest(BaseModel):
    text:            str
    correct_label:   str = Field(..., pattern='^(ham|spam|phishing)$')
    predicted_label: str = Field(..., pattern='^(ham|spam|phishing)$')
    confidence:      float = 0.0

class WhitelistRequest(BaseModel):
    domain: str = Field(..., min_length=3)
    reason: Optional[str] = None


# ══════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/analyze", tags=["Analyse"])
async def analyze_email(request: EmailRequest):
    if not pipeline_loader.is_loaded:
        raise HTTPException(503, "Pipeline en cours de chargement")
    try:
        result = pipeline_loader.analyze(request.text, request.raw_email)
    except Exception as e:
        logger.error(f"Erreur analyse : {e}")
        raise HTTPException(500, str(e))

    _update_stats(result)
    _log_detection(result, request.text[:200])

    # Auto-labelling en arrière-plan
    process_analysis_result(request.text, result)

    if request.email_id:
        result['email_id'] = request.email_id
    return result


@app.post("/batch", tags=["Analyse"])
async def analyze_batch(request: BatchRequest):
    if not pipeline_loader.is_loaded:
        raise HTTPException(503, "Pipeline en cours de chargement")
    results = []
    for email_req in request.emails:
        try:
            r = pipeline_loader.analyze(email_req.text, email_req.raw_email)
            _update_stats(r)
            if email_req.email_id:
                r['email_id'] = email_req.email_id
            results.append(r)
        except Exception as e:
            results.append({'error': str(e), 'email_id': email_req.email_id})

    by_class = {}
    for r in results:
        c = r.get('predicted_class', 'error')
        by_class[c] = by_class.get(c, 0) + 1
    return {'results': results, 'summary': {'total': len(results), 'by_class': by_class}}


@app.post("/feedback", tags=["Apprentissage"])
async def submit_feedback(data: FeedbackRequest, background: BackgroundTasks):
    """
    v2 : utilise SmartScheduler au lieu d'un compteur fixe.
    Déclenche la mise à jour selon la dérive de performance détectée.
    """
    should_trigger, reason = process_feedback(
        data.text,
        data.predicted_label,
        data.correct_label,
        data.confidence,
    )

    pending = scheduler.status()['pending_corrections']

    if should_trigger:
        _stats['updates_triggered'] += 1
        script = _ROOT_DIR / "incremental_layer.py"
        if script.exists():
            subprocess.Popen(
                [sys.executable, str(script), "--force"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"[AutoTrigger] incremental_layer.py lancé — {reason}")

            async def _auto_reload():
                await asyncio.sleep(25)
                pipeline_loader.reload_corrector()
                scheduler.record_update(reason)
                logger.info("[AutoTrigger] Correcteur rechargé.")
            background.add_task(_auto_reload)

    return {
        "status":          "ok",
        "total_pending":   pending,
        "triggered":       should_trigger,
        "trigger_reason":  reason or "threshold_not_reached",
        "message":         f"Mise à jour déclenchée ({reason})" if should_trigger
                          else f"En attente ({pending} corrections accumulées)",
    }


@app.post("/reload-corrector", tags=["Apprentissage"])
async def reload_corrector():
    pipeline_loader.reload_corrector()
    return {"status": "ok", "message": "Correcteur rechargé sans redémarrage."}


@app.post("/whitelist", tags=["Configuration"])
async def add_to_whitelist(request: WhitelistRequest):
    """
    Ajoute un domaine à la whitelist de domaines légitimes.
    Résout les faux positifs newsletters (Duolingo, Microsoft, etc.).
    """
    pipeline_loader.add_to_whitelist(request.domain)
    return {
        "status":  "ok",
        "domain":  request.domain,
        "message": f"{request.domain} ajouté à la whitelist. Emails de ce domaine → HAM automatique.",
        "reason":  request.reason,
    }


@app.get("/feedback/status", tags=["Apprentissage"])
async def feedback_status():
    return scheduler.status()


@app.get("/performance", tags=["Monitoring"])
async def get_performance():
    """Métriques de performance en temps réel (fenêtre glissante 100 emails)."""
    return {
        **scheduler.tracker.report(),
        'drift_detection': 'active',
        'auto_labeler':    'active',
        'scheduler':       'smart (drift + volume + time)',
    }


@app.get("/spam/stats", tags=["Monitoring"])
async def spam_stats():
    """Statistiques dédiées à la détection spam."""
    total = _stats['total_analyzed']
    spam_count = _stats['by_class'].get('spam', 0)
    return {
        'spam_detected':        spam_count,
        'spam_rate':            round(spam_count / max(total, 1), 4),
        'spam_by_category':     _stats['spam_by_category'],
        'spam_recall_window':   scheduler.tracker.spam_recall(),
        'whitelisted':          _stats['whitelisted_count'],
        'auto_labels_generated': _stats['auto_labels_generated'],
        'note': (
            "Si spam_rate ≈ 0 avec total_analyzed > 50 : activer le SpamBooster "
            "ou ajouter des corrections spam via l'extension ShieldMail."
        ),
    }


@app.get("/health", tags=["Monitoring"])
async def health():
    from time import time
    info = pipeline_loader.get_models_info()
    return {
        "status":      "ok",
        "version":     "2.0.0",
        "models":      info,
        "uptime_s":    round(time(), 0),
        "features":    [
            "whitelist", "spam_booster", "adaptive_weights",
            "smart_scheduler", "drift_detection", "auto_labeling",
            "explain_engine",
        ],
    }


@app.get("/stats", tags=["Monitoring"])
async def get_stats():
    return {**_stats, 'retrieved_at': datetime.now().isoformat()}
