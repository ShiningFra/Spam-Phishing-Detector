# -*- coding: utf-8 -*-
"""
main_v2.py  —  API FastAPI v2 finale
=====================================
Corrections vs version précédente :
  - Appelle incremental_layer_v2.py (spam oversampling + migration dims)
  - Intègre ai_engine.py (ActiveLearner, SpamDiagnostic, ConceptDriftResponder)
  - Appelle ai_loop.on_analysis() après chaque analyse
  - Nouveaux endpoints : /ai/health, /ai/review-queue, /ai/spam-diagnostic
  - ConceptDriftResponder branché sur les dérives détectées par SmartScheduler
"""

import asyncio, json, logging, subprocess, sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from pipeline_v2  import pipeline_loader
from auto_trainer import (scheduler, process_feedback,
                           process_analysis_result,
                           FEEDBACK_FILE, LOGS_DIR, DATA_DIR)
from ai_engine    import autonomous_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("api_v2")

# ── Résolution des chemins ───────────────────────────────────────
# uvicorn est lancé depuis api/ → __file__ = main_v2.py (relatif)
# .resolve() garantit le chemin absolu quel que soit le cwd
_API_DIR  = Path(__file__).resolve().parent          # .../notebooks/api/
_ROOT_DIR = _API_DIR.parent                          # .../notebooks/

_DETECT_FILE = LOGS_DIR / "detections.jsonl"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ── Script incrémental (dans notebooks/, pas dans api/) ──────────
_INCREMENTAL_SCRIPT = _ROOT_DIR / "incremental_layer_v2.py"
if not _INCREMENTAL_SCRIPT.exists():
    _INCREMENTAL_SCRIPT = _ROOT_DIR / "incremental_layer.py"

logger.info(f"API dir  : {_API_DIR}")
logger.info(f"Root dir : {_ROOT_DIR}")
logger.info(f"Script   : {_INCREMENTAL_SCRIPT} (existe={_INCREMENTAL_SCRIPT.exists()})")


# ═══════════════════════════════════════════════════════════════
# LIFESPAN
# ═══════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Démarrage API v2 finale...")
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    pipeline_loader.load()

    # Brancher ai_engine sur le pipeline_loader
    autonomous_loop._pipeline_loader = pipeline_loader
    autonomous_loop.start()

    logger.info("API v2 prête — pipeline + IA autonome actifs.")
    yield
    autonomous_loop.stop()
    logger.info("Arrêt propre.")


app = FastAPI(
    title="API Détection Spam & Phishing v2",
    description=(
        "Pipeline hybride 4 couches · Seuils calibrés (phishing≥0.90, spam≥0.60) · "
        "Apprentissage continu intelligent · IA autonome (ActiveLearner, "
        "DriftDetector, SpamDiagnostic)\n\n"
        "Projet ENSPY 5GI — Nghogué Taptué Franck Roddier"
    ),
    version="2.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ── Statistiques globales ────────────────────────────────────────
_stats = {
    "total_analyzed":    0,
    "by_class":          {"ham": 0, "spam": 0, "phishing": 0},
    "by_threat":         {"none": 0, "low": 0, "medium": 0,
                          "high": 0, "critical": 0},
    "spam_by_category":  {"financial": 0, "scam": 0,
                          "pharma": 0, "marketing": 0},
    "whitelisted_count": 0,
    "updates_triggered": 0,
    "review_requests":   0,
    "started_at":        datetime.now().isoformat(),
    "avg_latency_ms":    0.0,
}

def _update_stats(result: dict):
    _stats["total_analyzed"] += 1
    pred   = result.get("predicted_class", "ham")
    threat = result.get("threat_level", "none")
    _stats["by_class"][pred]    = _stats["by_class"].get(pred, 0) + 1
    _stats["by_threat"][threat] = _stats["by_threat"].get(threat, 0) + 1
    if result.get("whitelisted"):
        _stats["whitelisted_count"] += 1
    cat = result.get("spam_category", "")
    if cat:
        _stats["spam_by_category"][cat] = \
            _stats["spam_by_category"].get(cat, 0) + 1
    n = _stats["total_analyzed"]
    _stats["avg_latency_ms"] = (
        (_stats["avg_latency_ms"] * (n-1) + result.get("latency_ms", 0)) / n
    )

def _log_detection(result: dict, preview: str = ""):
    entry = {**result,
             "text_preview": preview[:200],
             "analyzed_at":  datetime.now().isoformat()}
    with open(_DETECT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ═══════════════════════════════════════════════════════════════
# SCHÉMAS PYDANTIC
# ═══════════════════════════════════════════════════════════════

class EmailRequest(BaseModel):
    text:      str           = Field(..., min_length=1)
    raw_email: Optional[str] = None
    email_id:  Optional[str] = None

class BatchRequest(BaseModel):
    emails: List[EmailRequest] = Field(..., max_length=100)

class FeedbackRequest(BaseModel):
    text:            str
    correct_label:   str   = Field(..., pattern="^(ham|spam|phishing)$")
    predicted_label: str   = Field(..., pattern="^(ham|spam|phishing)$")
    confidence:      float = 0.0

class WhitelistRequest(BaseModel):
    domain: str            = Field(..., min_length=3)
    reason: Optional[str]  = None


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS — ANALYSE
# ═══════════════════════════════════════════════════════════════

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

    # Auto-labelling (AutoLabeler dans SmartScheduler)
    process_analysis_result(request.text, result)

    # ActiveLearner — signaler les emails borderline à réviser
    ai_meta = autonomous_loop.on_analysis(request.text, result)
    if ai_meta.get("review_requested"):
        _stats["review_requests"] += 1
        logger.info(
            f"[ActiveLearner] Révision demandée : {ai_meta['review_reason']} "
            f"({result.get('predicted_class')}, conf={result.get('global_confidence', 0):.2f})"
        )

    if request.email_id:
        result["email_id"] = request.email_id
    result["ai_review_requested"] = ai_meta.get("review_requested", False)
    return result


@app.post("/batch", tags=["Analyse"])
async def analyze_batch(request: BatchRequest):
    if not pipeline_loader.is_loaded:
        raise HTTPException(503, "Pipeline en cours de chargement")
    results = []
    for req in request.emails:
        try:
            r = pipeline_loader.analyze(req.text, req.raw_email)
            _update_stats(r)
            process_analysis_result(req.text, r)
            autonomous_loop.on_analysis(req.text, r)
            if req.email_id:
                r["email_id"] = req.email_id
            results.append(r)
        except Exception as e:
            results.append({"error": str(e), "email_id": req.email_id})

    by_class = {}
    for r in results:
        c = r.get("predicted_class", "error")
        by_class[c] = by_class.get(c, 0) + 1
    return {"results": results,
            "summary": {"total": len(results), "by_class": by_class}}


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS — APPRENTISSAGE CONTINU
# ═══════════════════════════════════════════════════════════════

@app.post("/feedback", tags=["Apprentissage"])
async def submit_feedback(data: FeedbackRequest,
                           background: BackgroundTasks):
    """
    Correction utilisateur.
    Déclenche la mise à jour selon SmartScheduler (dérive/volume/délai).
    Appelle incremental_layer_v2.py (spam oversampling + migration dims).
    """
    should_trigger, reason = process_feedback(
        data.text, data.predicted_label,
        data.correct_label, data.confidence,
    )

    # Si dérive détectée, informer le ConceptDriftResponder
    if reason == "drift_detected":
        drift_response = autonomous_loop.on_drift(reason)
        logger.info(f"[DriftResponder] {drift_response}")

    pending = scheduler.status()["pending_corrections"]

    if should_trigger:
        _stats["updates_triggered"] += 1
        if _INCREMENTAL_SCRIPT.exists():
            subprocess.Popen(
                [sys.executable, str(_INCREMENTAL_SCRIPT), "--force"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(
                f"[AutoTrigger] {_INCREMENTAL_SCRIPT.name} lancé — {reason}"
            )

            async def _auto_reload():
                await asyncio.sleep(25)
                pipeline_loader.reload_corrector()
                scheduler.record_update(reason)
                logger.info("[AutoTrigger] Correcteur rechargé.")
            background.add_task(_auto_reload)
        else:
            logger.error(f"Script incrémental introuvable : {_INCREMENTAL_SCRIPT}")

    return {
        "status":         "ok",
        "total_pending":  pending,
        "triggered":      should_trigger,
        "trigger_reason": reason or "threshold_not_reached",
        "message": (f"Mise à jour déclenchée ({reason})"
                    if should_trigger
                    else f"En attente ({pending} corrections)"),
    }


@app.post("/reload-corrector", tags=["Apprentissage"])
async def reload_corrector():
    pipeline_loader.reload_corrector()
    return {"status": "ok", "message": "Correcteur rechargé."}


@app.get("/feedback/status", tags=["Apprentissage"])
async def feedback_status():
    return scheduler.status()


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS — CONFIGURATION
# ═══════════════════════════════════════════════════════════════

@app.post("/whitelist", tags=["Configuration"])
async def add_to_whitelist(request: WhitelistRequest):
    pipeline_loader.add_to_whitelist(request.domain)
    return {
        "status":  "ok",
        "domain":  request.domain,
        "message": f"{request.domain} ajouté — emails de ce domaine → HAM.",
        "reason":  request.reason,
    }


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS — MONITORING
# ═══════════════════════════════════════════════════════════════

@app.get("/health", tags=["Monitoring"])
async def health():
    info = pipeline_loader.get_models_info()
    return {
        "status":   "ok",
        "version":  "2.1.0",
        "models":   info,
        "features": [
            "whitelist", "spam_booster", "calibrated_thresholds(0.90/0.60)",
            "adaptive_weights", "smart_scheduler", "drift_detection",
            "auto_labeling", "active_learner", "spam_diagnostic",
            "explain_engine", "concept_drift_responder",
        ],
        "thresholds": {"phishing": 0.90, "spam": 0.60},
    }


@app.get("/stats", tags=["Monitoring"])
async def get_stats():
    return {**_stats, "retrieved_at": datetime.now().isoformat()}


@app.get("/performance", tags=["Monitoring"])
async def get_performance():
    perf = scheduler.tracker.report()
    return {
        **perf,
        "calibrated_thresholds": {"phishing": 0.90, "spam": 0.60},
        "drift_detection":       "active (Page-Hinkley)",
        "auto_labeler":          "active",
        "scheduler":             "smart (drift + volume + time)",
        "note": (
            "Ces métriques sont calculées sur la fenêtre glissante "
            "des 100 derniers feedbacks utilisateur. "
            "Pour les métriques académiques réelles : F1-Macro RF = 0.7357 "
            "(seuil défaut) → 0.9018 (seuils calibrés 0.90/0.60)."
        ),
    }


@app.get("/spam/stats", tags=["Monitoring"])
async def spam_stats():
    total      = _stats["total_analyzed"]
    spam_count = _stats["by_class"].get("spam", 0)
    return {
        "spam_detected":         spam_count,
        "spam_rate":             round(spam_count / max(total, 1), 4),
        "spam_by_category":      _stats["spam_by_category"],
        "spam_recall_window":    scheduler.tracker.spam_recall(),
        "whitelisted_count":     _stats["whitelisted_count"],
        "threshold_spam":        0.60,
        "note": (
            "Seuil calibré sur test set réel (27 061 emails). "
            "spam_recall RF réel = 99.65% avec seuil 0.60. "
            "Si spam_rate ≈ 0 après 50+ analyses : corriger via ShieldMail."
        ),
    }


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS — IA AUTONOME
# ═══════════════════════════════════════════════════════════════

@app.get("/ai/health", tags=["IA Autonome"])
async def ai_health():
    """
    Rapport de santé complet de l'IA autonome.
    Inclut : évaluation proxy, diagnostic spam, ActiveLearner, historique dérives.
    """
    return autonomous_loop.health_report()


@app.get("/ai/review-queue", tags=["IA Autonome"])
async def ai_review_queue():
    """
    File d'emails identifiés par l'ActiveLearner comme nécessitant
    une révision manuelle (incertitude élevée, spam borderline...).
    """
    queue = autonomous_loop.get_review_queue()
    return {
        "count":  len(queue),
        "emails": queue,
        "note":   (
            "Ces emails ont été identifiés comme informatifs pour le correcteur. "
            "Les corriger via POST /feedback améliore efficacement le modèle."
        ),
    }


@app.get("/ai/spam-diagnostic", tags=["IA Autonome"])
async def ai_spam_diagnostic():
    """
    Diagnostic automatique du problème de détection spam.
    Analyse les détections récentes et propose des actions correctives.
    """
    from ai_engine import SpamDiagnostic
    return SpamDiagnostic().run()


@app.post("/ai/trigger-eval", tags=["IA Autonome"])
async def ai_trigger_eval(background: BackgroundTasks):
    """Force une évaluation immédiate du système."""
    async def _eval():
        autonomous_loop.self_evaluator.evaluate()
    background.add_task(_eval)
    return {"status": "ok", "message": "Évaluation lancée en arrière-plan."}
