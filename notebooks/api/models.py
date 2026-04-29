# -*- coding: utf-8 -*-
from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class ThreatLevel(str, Enum):
    none     = "none"
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class EmailRequest(BaseModel):
    """Corps d'une requete d'analyse d'email."""
    text:      str = Field(..., description="Corps de l'email (texte brut)", min_length=1)
    raw_email: Optional[str] = Field(None, description="Email complet avec headers (optionnel)")
    email_id:  Optional[str] = Field(None, description="Identifiant de l'email (pour le suivi)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "text": "Dear customer, your account has been suspended. Verify: http://paypa1.xyz/login",
                "raw_email": "From: support@paypa1.xyz\nSubject: Account suspended\n\nDear customer...",
                "email_id": "email-001"
            }
        }
    }


class ClassProbability(BaseModel):
    ham:      float
    spam:     float
    phishing: float


class AnalysisResponse(BaseModel):
    """Resultat complet d'analyse d'un email."""
    email_id:          Optional[str] = None
    predicted_class:   str
    threat_level:      ThreatLevel
    global_confidence: float = Field(..., ge=0.0, le=1.0)
    ml_probabilities:  ClassProbability
    rule_score:        float
    header_score:      float
    rules_triggered:   List[str]
    header_flags:      List[str]
    url_flags:         List[str]
    latency_ms:        float
    decision_path:     str
    analyzed_at:       str


class BatchRequest(BaseModel):
    """Requete d'analyse en lot."""
    emails: List[EmailRequest] = Field(..., max_length=100)


class BatchResponse(BaseModel):
    total:             int
    results:           List[AnalysisResponse]
    summary:           dict
    total_latency_ms:  float


class HealthResponse(BaseModel):
    status:        str
    models_loaded: dict
    uptime_s:      float
    version:       str


class StatsResponse(BaseModel):
    total_analyzed:  int
    by_class:        dict
    by_threat:       dict
    avg_latency_ms:  float
    alerts_sent:     int
    since:           str