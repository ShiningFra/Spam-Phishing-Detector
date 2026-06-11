# -*- coding: utf-8 -*-
import json as _json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from time import time
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from models   import (EmailRequest, AnalysisResponse, BatchRequest,
                      BatchResponse, HealthResponse, StatsResponse,
                      ClassProbability)
from pipeline import pipeline_loader
from notifier import notifier
from logger   import detection_logger, logger

# ── Chemins absolus ───────────────────────────────────────────────
_API_DIR       = Path(__file__).parent
_ROOT_DIR      = _API_DIR.parent
_LOGS_DIR      = _ROOT_DIR / "logs"
_FEEDBACK_FILE = _LOGS_DIR / "feedback_verified.jsonl"

START_TIME = time()

# ── Démarrage ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Démarrage de l'API de détection spam/phishing...")
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)
    pipeline_loader.load()
    logger.info("API prête.")
    yield
    logger.info("Arrêt de l'API.")

# ── Application ───────────────────────────────────────────────────
app = FastAPI(
    title="API de Détection Spam & Phishing",
    description=(
        "Système intelligent de détection de spam et de phishing.\n\n"
        "Pipeline hybride : règles heuristiques + analyse headers (SPF/DKIM) "
        "+ Random Forest + correcteur incrémental.\n\n"
        "Projet ENSPY 5GI — Nghogué Taptué Franck Roddier"
    ),
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helpers ───────────────────────────────────────────────────────
def result_to_response(result: dict, email_id: str = None) -> AnalysisResponse:
    ml_p = result.get("ml_proba", {})
    return AnalysisResponse(
        email_id          = email_id,
        predicted_class   = result["predicted_class"],
        threat_level      = result["threat_level"],
        global_confidence = result["global_confidence"],
        ml_probabilities  = ClassProbability(
            ham      = ml_p.get("ham",      0.0),
            spam     = ml_p.get("spam",     0.0),
            phishing = ml_p.get("phishing", 0.0),
        ),
        rule_score      = result["rule_score"],
        header_score    = result["header_score"],
        rules_triggered = result["rules_triggered"],
        header_flags    = result["header_flags"],
        url_flags       = result["url_flags"],
        latency_ms      = result["latency_ms"],
        decision_path   = result["decision_path"],
        analyzed_at     = datetime.utcnow().isoformat(),
    )

# ── Endpoints info ────────────────────────────────────────────────
@app.get("/", tags=["Info"])
async def root():
    return {
        "service": "Détection Spam & Phishing",
        "version": "1.0.0",
        "author":  "Nghogué Taptué Franck Roddier — ENSPY 5GI",
        "docs":    "/docs",
        "health":  "/health",
    }

@app.get("/health", response_model=HealthResponse, tags=["Monitoring"])
async def health_check():
    return HealthResponse(
        status        = "ok" if pipeline_loader.is_loaded else "loading",
        models_loaded = pipeline_loader.get_models_info(),
        uptime_s      = round(time() - START_TIME, 1),
        version       = "1.0.0",
    )

@app.get("/stats", response_model=StatsResponse, tags=["Monitoring"])
async def get_stats():
    return StatsResponse(**detection_logger.get_stats())

# ── Endpoints analyse ─────────────────────────────────────────────
@app.post("/analyze", response_model=AnalysisResponse, tags=["Analyse"])
async def analyze_email(request: EmailRequest):
    if not pipeline_loader.is_loaded:
        raise HTTPException(status_code=503, detail="Pipeline en cours de chargement")
    try:
        result = pipeline_loader.analyze(request.text, request.raw_email)
    except Exception as e:
        logger.error(f"Erreur analyse : {e}")
        raise HTTPException(status_code=500, detail=str(e))
    detection_logger.log_detection(result)
    notifier.send_alert(result, text_preview=request.text[:300])
    return result_to_response(result, request.email_id)

@app.post("/batch", response_model=BatchResponse, tags=["Analyse"])
async def analyze_batch(request: BatchRequest):
    if not pipeline_loader.is_loaded:
        raise HTTPException(status_code=503, detail="Pipeline en cours de chargement")
    t0      = time()
    results = []
    summary = {"ham": 0, "spam": 0, "phishing": 0, "alerts": 0}
    for req in request.emails:
        try:
            r = pipeline_loader.analyze(req.text, req.raw_email)
            detection_logger.log_detection(r)
            notifier.send_alert(r, text_preview=req.text[:300])
            results.append(result_to_response(r, req.email_id))
            summary[r["predicted_class"]] = summary.get(r["predicted_class"], 0) + 1
            if r["threat_level"] in ("high", "critical"):
                summary["alerts"] += 1
        except Exception as e:
            logger.error(f"Erreur batch : {e}")
    return BatchResponse(
        total            = len(results),
        results          = results,
        summary          = summary,
        total_latency_ms = round((time() - t0) * 1000, 2),
    )

# ── Endpoints apprentissage continu ───────────────────────────────
@app.post("/feedback", tags=["Apprentissage"])
async def submit_feedback(data: dict):
    """
    Reçoit une correction utilisateur depuis l'extension Chrome.
    Sauvegarde dans logs/feedback_verified.jsonl pour le correcteur incrémental.

    Exemple de corps :
        {"text": "...", "correct_label": "ham", "predicted_label": "phishing"}
    """
    text          = str(data.get("text", "")).strip()
    correct_label = str(data.get("correct_label", "")).lower().strip()
    predicted     = str(data.get("predicted_label", "")).lower().strip()

    if not text:
        raise HTTPException(status_code=400, detail="Le champ 'text' est requis")
    if correct_label not in {"ham", "spam", "phishing"}:
        raise HTTPException(
            status_code=400,
            detail=f"'correct_label' invalide : '{correct_label}'. Valeurs : ham, spam, phishing"
        )

    # Créer logs/ si inexistant
    _LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Écrire la correction
    entry = {
        "text":      text[:3000],
        "label":     correct_label,
        "predicted": predicted,
        "source":    "user_feedback",
        "ts":        datetime.utcnow().isoformat(),
    }
    with open(_FEEDBACK_FILE, "a", encoding="utf-8") as f:
        f.write(_json.dumps(entry, ensure_ascii=False) + "\n")

    # Compter les corrections en attente
    try:
        with open(_FEEDBACK_FILE, encoding="utf-8") as f:
            pending = sum(1 for _ in f)
    except Exception:
        pending = 1

    logger.info(f"[FEEDBACK] {predicted or '?'} -> {correct_label} | total: {pending}")

    # ── Déclenchement automatique tous les 10 feedbacks ─────────────
    if pending % 10 == 0:
        import subprocess, sys, asyncio

        script = _ROOT_DIR / "incremental_layer.py"
        if script.exists():
            # Lancer incremental_layer.py en arrière-plan (non bloquant)
            subprocess.Popen(
                [sys.executable, str(script), "--force"],
                cwd=str(_ROOT_DIR),
                stdout=open(_LOGS_DIR / "incremental.log", "a"),
                stderr=subprocess.STDOUT,
            )
            logger.info(f"[AUTO] incremental_layer.py lancé ({pending} corrections)")

            # Recharger le correcteur 20s après (le temps que le script finisse)
            async def _auto_reload():
                await asyncio.sleep(20)
                pipeline_loader.reload_corrector()
                logger.info("[AUTO] Correcteur rechargé automatiquement.")

            asyncio.create_task(_auto_reload())
            msg = f"Mise à jour automatique lancée ({pending} corrections) — correcteur rechargé dans ~20s"
        else:
            msg = f"Script incremental_layer.py introuvable dans {_ROOT_DIR}"
    elif pending >= 10:
        msg = f"Prêt ! {pending} corrections — lancez : python incremental_layer.py"
    else:
        msg = f"{pending}/10 corrections avant mise à jour disponible"

    return {"status": "ok", "total_pending": pending, "message": msg}


@app.get("/feedback/status", tags=["Apprentissage"])
async def feedback_status():
    """Retourne le nombre de corrections en attente."""
    if not _FEEDBACK_FILE.exists():
        return {"pending": 0, "ready": False,
                "message": "Aucune correction encore — corrigez des emails via l'extension"}
    try:
        with open(_FEEDBACK_FILE, encoding="utf-8") as f:
            pending = sum(1 for _ in f)
    except Exception:
        pending = 0

    # Détail par label
    by_label = {"ham": 0, "spam": 0, "phishing": 0}
    try:
        with open(_FEEDBACK_FILE, encoding="utf-8") as f:
            for line in f:
                try:
                    e = _json.loads(line)
                    lbl = e.get("label", "")
                    if lbl in by_label:
                        by_label[lbl] += 1
                except Exception:
                    pass
    except Exception:
        pass

    return {
        "pending":   pending,
        "by_label":  by_label,
        "ready":     pending >= 10,
        "file":      str(_FEEDBACK_FILE),
        "message":   f"Lancez : python incremental_layer.py ({pending} corrections)"
                     if pending >= 10 else f"{pending}/10 corrections",
    }


@app.post("/reload-corrector", tags=["Apprentissage"])
async def reload_corrector():
    """Recharge le correcteur incrémental sans redémarrer l'API."""
    pipeline_loader.reload_corrector()
    info = pipeline_loader.get_models_info()
    logger.info(f"[CORRECTOR] Rechargé : {info.get('corrector', '?')}")
    return {"status": "ok", "corrector": info.get("corrector", "inactif")}
