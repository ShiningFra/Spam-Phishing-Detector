# -*- coding: utf-8 -*-
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime
from time import time
import logging

from api.models   import (EmailRequest, AnalysisResponse, BatchRequest,
                      BatchResponse, HealthResponse, StatsResponse,
                      ClassProbability)
from api.pipeline import pipeline_loader
from api.notifier import notifier
from api.logger   import detection_logger, logger

# aaa DÃ©marrage / arrÃªt aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
START_TIME = time()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Chargement du pipeline au dÃ©marrage."""
    logger.info("DÃ©marrage de l'API de dÃ©tection spam/phishing...")
    pipeline_loader.load()
    logger.info("API prÃªte.")
    yield
    logger.info("ArrÃªt de l'API.")


# aaa Application aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
app = FastAPI(
    title="API de DÃ©tection Spam & Phishing",
    description=(
        "SystÃ¨me intelligent de dÃ©tection de spam et de phishing.\n\n"
        "Pipeline hybride : rÃ¨gles heuristiques + analyse headers (SPF/DKIM) "
        "+ ML (LinearSVC) + DistilBERT.\n\n"
        "Projet ENSPY 5GI a NghoguÃ© TaptuÃ© Franck Roddier"
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


# aaa Helpers aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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


# aaa Endpoints aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

@app.get("/health", response_model=HealthResponse, tags=["Monitoring"])
async def health_check():
    """VÃ©rification de l'Ã©tat du service."""
    return HealthResponse(
        status       = "ok" if pipeline_loader.is_loaded else "loading",
        models_loaded = pipeline_loader.get_models_info(),
        uptime_s     = round(time() - START_TIME, 1),
        version      = "1.0.0",
    )


@app.post("/analyze", response_model=AnalysisResponse, tags=["Analyse"])
async def analyze_email(request: EmailRequest):
    """
    Analyse un email et retourne la classification complÃ¨te.

    - **text** : corps de l'email (obligatoire)
    - **raw_email** : email complet avec headers pour l'analyse SPF/DKIM (optionnel)
    - **email_id** : identifiant pour le suivi (optionnel)
    """
    if not pipeline_loader.is_loaded:
        raise HTTPException(status_code=503, detail="Pipeline en cours de chargement")

    try:
        result = pipeline_loader.analyze(request.text, request.raw_email)
    except Exception as e:
        logger.error(f"Erreur analyse : {e}")
        raise HTTPException(status_code=500, detail=str(e))

    # Journalisation
    detection_logger.log_detection(result)

    # Notification si menace haute
    notifier.send_alert(result, text_preview=request.text[:300])

    return result_to_response(result, request.email_id)


@app.post("/batch", response_model=BatchResponse, tags=["Analyse"])
async def analyze_batch(request: BatchRequest):
    """
    Analyse un lot d'emails (max 100).
    Retourne un rÃ©sumÃ© statistique en plus des rÃ©sultats individuels.
    """
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
            logger.error(f"Erreur batch email {req.email_id}: {e}")

    return BatchResponse(
        total            = len(results),
        results          = results,
        summary          = summary,
        total_latency_ms = round((time() - t0) * 1000, 2),
    )


@app.get("/stats", response_model=StatsResponse, tags=["Monitoring"])
async def get_stats():
    """Statistiques globales depuis le dÃ©marrage du service."""
    return StatsResponse(**detection_logger.get_stats())


@app.get("/", tags=["Info"])
async def root():
    return {
        "service":  "DÃ©tection Spam & Phishing",
        "version":  "1.0.0",
        "author":   "NghoguÃ© TaptuÃ© Franck Roddier a ENSPY 5GI",
        "docs":     "/docs",
        "health":   "/health",
    }