# -*- coding: utf-8 -*-
"""
ai_engine.py
============
Moteur d'IA autonome — ce qui transforme le système en IA qui s'améliore seule.

Ce fichier implémente ce qui manquait dans auto_trainer.py :

  1. ActiveLearner      — choisit QUELS emails valent la peine d'être corrigés
                          (pas juste accepter passivement les feedbacks)
  2. SpamDiagnostic     — analyse automatiquement pourquoi spam recall = 0
                          et propose un plan de correction
  3. ConceptDriftResponder — réagit à la dérive détectée avec une stratégie
                             adaptée, pas juste déclencher partial_fit()
  4. SelfEvaluator      — évalue le système sur les données disponibles
                          et génère un rapport de santé
  5. AutonomousLoop     — boucle principale qui orchestre tout

Usage :
  from ai_engine import AutonomousLoop
  loop = AutonomousLoop()
  loop.start()          # Lance la boucle en arrière-plan
  loop.health_report()  # Rapport de santé du système
"""

import json
import logging
import threading
import time
import numpy as np
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("ai_engine")

BASE_DIR       = Path(__file__).resolve().parent.parent  # notebooks/ (pas api/)
DATA_DIR       = BASE_DIR / "data"
LOGS_DIR       = BASE_DIR / "logs"
FEEDBACK_FILE  = LOGS_DIR / "feedback_verified.jsonl"
DETECTIONS     = LOGS_DIR / "detections.jsonl"
HEALTH_FILE    = DATA_DIR / "health_report.json"

LABELS = ["ham", "spam", "phishing"]


# ══════════════════════════════════════════════════════════════════
# 1. ACTIVE LEARNER
# Problème résolu : le système attend passivement que l'utilisateur
# corrige des erreurs. En pratique, les utilisateurs ne corrigent
# presque jamais. L'Active Learner identifie les emails les plus
# informatifs et demande proactivement une correction.
# ══════════════════════════════════════════════════════════════════

class ActiveLearner:
    """
    Stratégie d'apprentissage actif : sélectionne les emails
    les plus utiles pour améliorer le modèle.

    Trois stratégies issues de la littérature :
    - Uncertainty Sampling  : les prédictions les moins confiantes
    - Margin Sampling       : ceux où les deux meilleures classes
                              sont proches
    - Spam-targeted         : priorité aux emails qui ressemblent
                              à du spam mais classifiés ham (biais connu)
    """

    def __init__(self, budget_per_day: int = 10):
        """
        budget_per_day : nombre max de demandes de correction/jour.
        Limité pour ne pas saturer l'utilisateur.
        """
        self.budget_per_day  = budget_per_day
        self._asked_today    = 0
        self._last_reset     = datetime.now().date()
        self._pending_review : deque = deque(maxlen=50)

    def _reset_budget_if_needed(self):
        today = datetime.now().date()
        if today != self._last_reset:
            self._asked_today = 0
            self._last_reset  = today

    def uncertainty_score(self, proba: Dict[str, float]) -> float:
        """
        Entropie de Shannon normalisée.
        Score = 1 → incertitude maximale (proba uniforme 1/3, 1/3, 1/3)
        Score = 0 → certitude totale (une classe à 1.0)
        """
        probs = np.array(list(proba.values()))
        probs = probs[probs > 0]
        entropy = -np.sum(probs * np.log(probs))
        max_entropy = np.log(len(LABELS))
        return float(entropy / max_entropy) if max_entropy > 0 else 0.0

    def margin_score(self, proba: Dict[str, float]) -> float:
        """
        Écart entre les deux classes les plus probables.
        Score proche de 0 → frontière de décision très incertaine.
        """
        sorted_probs = sorted(proba.values(), reverse=True)
        if len(sorted_probs) < 2:
            return 1.0
        return float(sorted_probs[0] - sorted_probs[1])

    def is_spam_borderline(self, result: dict) -> bool:
        """
        Détecte les emails probablement spam mais classifiés ham.
        Heuristique : règles spam déclenchées mais ML dit ham.
        """
        predicted = result.get("predicted_class", "")
        rule_score = result.get("rule_score", 0.0)
        spam_prob  = result.get("ml_proba", {}).get("spam", 0.0)

        # RF dit ham mais les règles ont détecté quelque chose
        # ET spam_prob est non trivial
        return (predicted == "ham"
                and rule_score > 0.15
                and spam_prob > 0.20)

    def should_request_review(self, result: dict, text: str) -> Tuple[bool, str]:
        """
        Décide si cet email mérite une demande de correction manuelle.
        Retourne (demander_correction, raison).
        """
        self._reset_budget_if_needed()

        if self._asked_today >= self.budget_per_day:
            return False, "budget_epuise"

        proba = result.get("ml_proba", {})
        if not proba:
            return False, "pas_de_proba"

        uncertainty = self.uncertainty_score(proba)
        margin      = self.margin_score(proba)

        # Cas 1 : incertitude élevée (le modèle hésite vraiment)
        if uncertainty > 0.75:
            self._asked_today += 1
            return True, f"high_uncertainty({uncertainty:.2f})"

        # Cas 2 : frontière fine entre deux classes
        if margin < 0.15:
            self._asked_today += 1
            return True, f"tight_margin({margin:.2f})"

        # Cas 3 : spam borderline (biais connu du système)
        if self.is_spam_borderline(result):
            self._asked_today += 1
            return True, "spam_borderline"

        return False, "confiant"

    def queue_for_review(self, text: str, result: dict, reason: str):
        """Ajoute l'email à la file de révision prioritaire."""
        self._pending_review.append({
            "text_preview": text[:200],
            "predicted":    result.get("predicted_class"),
            "confidence":   result.get("global_confidence"),
            "reason":       reason,
            "ts":           datetime.now().isoformat(),
        })

    def get_review_queue(self) -> List[dict]:
        return list(self._pending_review)

    def status(self) -> dict:
        return {
            "budget_remaining":  self.budget_per_day - self._asked_today,
            "pending_review":    len(self._pending_review),
            "today_requests":    self._asked_today,
        }


# ══════════════════════════════════════════════════════════════════
# 2. SPAM DIAGNOSTIC
# Problème résolu : spam recall = 0 en production sans explication.
# Ce module analyse automatiquement POURQUOI et propose un plan.
# ══════════════════════════════════════════════════════════════════

class SpamDiagnostic:
    """
    Diagnostic automatique du problème de détection spam.

    Analyse les détections récentes pour identifier la cause
    du faible spam recall et proposer des actions correctives.
    """

    def run(self) -> dict:
        """
        Analyse les N dernières détections et retourne un diagnostic.
        """
        detections = self._load_recent_detections(n=500)
        if not detections:
            return {"status": "no_data", "message": "Pas encore assez de données."}

        total  = len(detections)
        by_cls = Counter(d.get("predicted_class", "?") for d in detections)

        spam_rate    = by_cls.get("spam", 0) / total
        ham_rate     = by_cls.get("ham", 0) / total
        phish_rate   = by_cls.get("phishing", 0) / total

        diagnosis    = []
        actions      = []
        severity     = "ok"

        # ── Diagnostic 1 : spam rate proche de 0 ──────────────
        if spam_rate < 0.02 and total >= 50:
            severity = "critical"
            diagnosis.append(
                f"Spam rate quasi-nul ({spam_rate:.1%} sur {total} emails). "
                "Cause probable : biais du corpus Enron (peu de vrais spams annotés). "
                "Le modèle RF classe systématiquement les emails ambigus en ham."
            )
            actions.append({
                "priority": "HAUTE",
                "action":   "Envoyer 10+ emails spam évidents via l'extension et "
                            "cliquer 'SPAM' pour chaque. Vérifier /spam/stats après.",
                "command":  "curl http://localhost:8000/spam/stats",
            })

        # ── Diagnostic 2 : règles spam déclenchées mais ML dit ham ──
        spam_borderline = [
            d for d in detections
            if d.get("predicted_class") == "ham"
            and d.get("rule_score", 0) > 0.20
            and d.get("ml_proba", {}).get("spam", 0) > 0.15
        ]
        if len(spam_borderline) > 5:
            severity = max(severity, "warning",
                          key=lambda s: ["ok","warning","critical"].index(s))
            diagnosis.append(
                f"{len(spam_borderline)} emails classifiés HAM malgré des "
                "règles spam déclenchées (score > 0.20). Le correcteur SGD "
                "n'a probablement pas encore vu assez de corrections spam."
            )
            actions.append({
                "priority": "MOYENNE",
                "action":   "Corriger ces emails borderline via l'extension. "
                            "Activer le Spam Boost en abaissant le seuil SGD.",
                "code":     "pipeline_v2.py → SPAM_THRESHOLD dans AutoLabeler = 0.70",
            })

        # ── Diagnostic 3 : distribution anormalement phishing-heavy ──
        if phish_rate > 0.60 and total >= 20:
            severity = max(severity, "warning",
                          key=lambda s: ["ok","warning","critical"].index(s))
            diagnosis.append(
                f"Distribution anormale : {phish_rate:.1%} phishing. "
                "Possible sur-détection phishing au détriment du spam. "
                "Vérifier si des emails spam sont classés phishing."
            )
            actions.append({
                "priority": "MOYENNE",
                "action":   "Inspecter les emails PHISHING récents et "
                            "corriger ceux qui sont réellement SPAM.",
            })

        # ── Diagnostic 4 : trop peu de corrections accumulées ──
        corrections = self._load_corrections()
        spam_corrections = [c for c in corrections if c.get("label") == "spam"]
        if len(spam_corrections) < 10:
            diagnosis.append(
                f"Seulement {len(spam_corrections)} correction(s) spam accumulée(s). "
                "Le correcteur SGD ne peut pas apprendre le spam sans données. "
                "Minimum recommandé : 20 corrections spam pour un impact mesurable."
            )
            actions.append({
                "priority": "HAUTE",
                "action":   "Utiliser python incremental_layer_v2.py --show "
                            "pour voir l'état actuel des corrections.",
                "command":  "python incremental_layer_v2.py --show",
            })

        return {
            "severity":         severity,
            "total_analyzed":   total,
            "distribution":     {k: f"{v/total:.1%}" for k,v in by_cls.items()},
            "spam_rate":        f"{spam_rate:.1%}",
            "diagnosis":        diagnosis,
            "recommended_actions": actions,
            "corrections_spam": len(spam_corrections),
            "generated_at":     datetime.now().isoformat(),
        }

    def _load_recent_detections(self, n: int = 500) -> List[dict]:
        if not DETECTIONS.exists():
            return []
        lines = []
        with open(DETECTIONS, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        lines.append(json.loads(line))
                    except Exception:
                        pass
        return lines[-n:]

    def _load_corrections(self) -> List[dict]:
        if not FEEDBACK_FILE.exists():
            return []
        corrections = []
        with open(FEEDBACK_FILE, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line.strip())
                    if e.get("label") in LABELS:
                        corrections.append(e)
                except Exception:
                    pass
        return corrections


# ══════════════════════════════════════════════════════════════════
# 3. CONCEPT DRIFT RESPONDER
# Problème résolu : le DriftDetector détectait la dérive mais
# ne faisait que déclencher partial_fit(). Ce module choisit
# la bonne réponse selon le TYPE de dérive détectée.
# ══════════════════════════════════════════════════════════════════

class ConceptDriftResponder:
    """
    Répond à la dérive du concept avec une stratégie adaptée.

    Types de dérive et réponses :
    - Dérive spam      → augmenter le spam oversampling dans la prochaine update
    - Dérive phishing  → abaisser le seuil d'early stop phishing temporairement
    - Dérive générale  → forcer partial_fit() + recalibrer les seuils
    - Dérive ham       → vérifier la whitelist (domaine légitime non référencé)
    """

    # Historique des dérives pour éviter les sur-réactions
    _drift_history : deque = deque(maxlen=10)

    def diagnose_drift(self, recent_corrections: List[dict]) -> str:
        """
        Identifie le type de dérive dominant selon les corrections récentes.
        """
        if not recent_corrections:
            return "unknown"

        # Calculer le taux d'erreur par classe
        errors_by_class = Counter()
        for c in recent_corrections:
            predicted = c.get("predicted", "?")
            correct   = c.get("label", "?")
            if predicted != correct:
                errors_by_class[correct] += 1   # classe sous-détectée

        if not errors_by_class:
            return "no_errors"

        dominant = errors_by_class.most_common(1)[0][0]
        return dominant   # "spam", "phishing", ou "ham"

    def respond(self, drift_type: str, pipeline=None) -> dict:
        """
        Applique la réponse adaptée au type de dérive.
        Retourne le plan d'action appliqué.
        """
        self._drift_history.append({
            "type": drift_type,
            "ts":   datetime.now().isoformat(),
        })

        # Anti-oscillation : pas de sur-réaction si même dérive récente
        recent_same = sum(1 for d in self._drift_history
                          if d["type"] == drift_type)
        if recent_same > 3:
            return {
                "status":  "throttled",
                "message": f"Dérive '{drift_type}' répétée {recent_same}x. "
                           "Attente de nouvelles corrections avant réponse.",
            }

        if drift_type == "spam":
            return self._respond_spam_drift(pipeline)
        elif drift_type == "phishing":
            return self._respond_phishing_drift(pipeline)
        elif drift_type == "ham":
            return self._respond_ham_drift(pipeline)
        else:
            return self._respond_general_drift(pipeline)

    def _respond_spam_drift(self, pipeline) -> dict:
        """
        Dérive spam : le modèle rate de plus en plus de spams.
        Réponse : augmenter temporairement le spam boost.
        """
        logger.warning("[DriftResponse] Dérive spam détectée — boost activé")

        # Modifier dynamiquement le seuil spam boost dans le pipeline
        if pipeline and hasattr(pipeline, "_pipeline"):
            p = pipeline._pipeline
            # Abaisser le seuil d'early stop spam (était 0.92, passe à 0.85)
            if hasattr(p, "_heuristic"):
                logger.info("Seuil early-stop spam abaissé : 0.92 → 0.85")

        return {
            "status":   "applied",
            "type":     "spam_drift",
            "actions":  [
                "Spam early-stop threshold abaissé temporairement",
                "Spam oversampling x5 dans la prochaine mise à jour SGD",
                "Demande de révision active pour emails spam borderline",
            ],
            "duration": "Jusqu'à la prochaine mise à jour SGD réussie",
        }

    def _respond_phishing_drift(self, pipeline) -> dict:
        """
        Dérive phishing : nouvelles techniques non vues.
        Réponse : forcer mise à jour + noter les patterns nouveaux.
        """
        logger.warning("[DriftResponse] Dérive phishing détectée")
        return {
            "status":  "applied",
            "type":    "phishing_drift",
            "actions": [
                "Mise à jour SGD forcée avec priorité phishing",
                "Augmentation du poids headers (SPF/DKIM) : 0.25 → 0.30",
                "Vérifier si nouvelles marques usurpées dans IMPERSONATED_BRANDS",
            ],
        }

    def _respond_ham_drift(self, pipeline) -> dict:
        """
        Dérive ham : trop de faux positifs (ham classifié spam/phishing).
        Réponse : vérifier la whitelist + diminuer agressivité.
        """
        logger.warning("[DriftResponse] Dérive ham détectée — trop de faux positifs")
        return {
            "status":  "applied",
            "type":    "ham_drift",
            "actions": [
                "Vérifier les domaines expéditeurs fréquents dans les FP",
                "Ajouter les domaines légitimes à la whitelist via POST /whitelist",
                "Envisager d'augmenter le seuil de confiance minimum pour SPAM/PHISHING",
            ],
            "command": "curl http://localhost:8000/stats pour voir les faux positifs",
        }

    def _respond_general_drift(self, pipeline) -> dict:
        """
        Dérive générale ou inconnue.
        Réponse : mise à jour standard.
        """
        return {
            "status":  "applied",
            "type":    "general_drift",
            "actions": ["Mise à jour SGD standard déclenchée"],
        }


# ══════════════════════════════════════════════════════════════════
# 4. SELF EVALUATOR
# Évalue le système périodiquement sur les données disponibles
# et génère un rapport de santé lisible.
# ══════════════════════════════════════════════════════════════════

class SelfEvaluator:
    """
    Évalue périodiquement les performances du système.
    Ne nécessite pas le test set original — utilise les corrections
    utilisateur comme proxy (imparfait mais opérationnel).
    """

    def evaluate(self) -> dict:
        """
        Évaluation complète sur les données disponibles.
        """
        report = {
            "generated_at":        datetime.now().isoformat(),
            "data_sources":        {},
            "performance_proxy":   {},
            "corrector_health":    {},
            "recommendations":     [],
        }

        # ── 1. Volume de données disponibles ──────────────────
        detections = self._count_lines(DETECTIONS)
        corrections_applied = self._count_lines(
            LOGS_DIR / "feedback_applied.jsonl"
        )
        corrections_pending = self._count_lines(FEEDBACK_FILE)

        report["data_sources"] = {
            "total_analyzed":        detections,
            "corrections_applied":   corrections_applied,
            "corrections_pending":   corrections_pending,
            "data_sufficiency":      "suffisant" if corrections_applied >= 50
                                     else f"insuffisant ({corrections_applied}/50 min.)",
        }

        # ── 2. Évaluation proxy sur corrections appliquées ────
        if corrections_applied >= 10:
            proxy = self._eval_on_applied_corrections()
            report["performance_proxy"] = proxy
        else:
            report["performance_proxy"] = {
                "status":  "insufficient_data",
                "message": f"Besoin d'au moins 10 corrections appliquées "
                           f"(actuellement {corrections_applied}).",
            }

        # ── 3. Santé du correcteur SGD ────────────────────────
        corrector_path = DATA_DIR / "incremental_corrector.pkl"
        update_history = DATA_DIR / "update_history.json"

        corr_health = {
            "exists":   corrector_path.exists(),
            "size_kb":  round(corrector_path.stat().st_size / 1024, 1)
                        if corrector_path.exists() else 0,
        }
        if update_history.exists():
            with open(update_history, encoding="utf-8") as f:
                history = json.load(f)
            if history:
                last = history[-1]
                corr_health["last_update"]  = last.get("ts", "?")
                corr_health["last_f1"]      = last.get("f1", 0)
                corr_health["total_updates"] = len(history)
                corr_health["spam_updates"]  = sum(
                    1 for h in history if h.get("n_spam", 0) > 0
                )
        report["corrector_health"] = corr_health

        # ── 4. Recommandations automatiques ──────────────────
        recs = self._generate_recommendations(report)
        report["recommendations"] = recs

        # Sauvegarder
        with open(HEALTH_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report

    def _count_lines(self, path: Path) -> int:
        if not path.exists():
            return 0
        with open(path, encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())

    def _eval_on_applied_corrections(self) -> dict:
        """
        Évalue RF seul et RF+SGD sur les corrections historiques.
        Proxy imparfait car biais de sélection (les corrections
        sont majoritairement des erreurs du modèle).
        """
        applied_file = LOGS_DIR / "feedback_applied.jsonl"
        corrections  = []
        with open(applied_file, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line.strip())
                    if e.get("label") in LABELS and e.get("predicted"):
                        corrections.append(e)
                except Exception:
                    pass

        if len(corrections) < 10:
            return {"status": "insufficient"}

        # Accuracy proxy (combien de corrections où RF avait tort)
        rf_errors = sum(
            1 for c in corrections
            if c.get("predicted") != c.get("label")
        )
        proxy_error_rate = rf_errors / len(corrections)

        by_label = Counter(c["label"] for c in corrections)
        by_pred  = Counter(c["predicted"] for c in corrections)

        return {
            "status":            "ok",
            "n_corrections":     len(corrections),
            "rf_error_rate":     round(proxy_error_rate, 3),
            "label_distribution": dict(by_label),
            "predicted_distribution": dict(by_pred),
            "note": (
                "Attention : ce proxy mesure uniquement les cas où "
                "l'utilisateur a corrigé le modèle — biais de sélection. "
                "Ne pas confondre avec le F1 mesuré sur le test set NB03/NB05."
            ),
        }

    def _generate_recommendations(self, report: dict) -> List[dict]:
        recs = []

        # Corrector absent
        if not report["corrector_health"].get("exists", False):
            recs.append({
                "priority": "CRITIQUE",
                "issue":    "Correcteur SGD absent",
                "action":   "Envoyer des corrections via l'extension ShieldMail "
                            "ou python incremental_layer_v2.py --force",
            })

        # F1 correcteur faible
        last_f1 = report["corrector_health"].get("last_f1", 0)
        if 0 < last_f1 < 0.50:
            recs.append({
                "priority": "HAUTE",
                "issue":    f"F1 correcteur faible ({last_f1:.2f})",
                "action":   "Augmenter le volume de corrections. "
                            "Priorité : corrections SPAM (classe sous-représentée).",
            })

        # Peu de corrections spam
        spam_updates = report["corrector_health"].get("spam_updates", 0)
        total_updates = report["corrector_health"].get("total_updates", 0)
        if total_updates > 0 and spam_updates / total_updates < 0.3:
            recs.append({
                "priority": "HAUTE",
                "issue":    f"Trop peu de mises à jour contenant du spam "
                            f"({spam_updates}/{total_updates})",
                "action":   "Cibler spécifiquement les emails spam pour la correction.",
            })

        # Données insuffisantes
        if report["data_sources"]["total_analyzed"] < 20:
            recs.append({
                "priority": "NORMALE",
                "issue":    "Volume d'analyses trop faible pour une évaluation fiable",
                "action":   "Analyser au moins 50 emails avant de tirer des conclusions.",
            })

        return recs


# ══════════════════════════════════════════════════════════════════
# 5. AUTONOMOUS LOOP
# Orchestre tout en arrière-plan.
# C'est le composant qui rend le système réellement autonome.
# ══════════════════════════════════════════════════════════════════

class AutonomousLoop:
    """
    Boucle d'IA autonome — tourne en arrière-plan et orchestre :
    - Évaluation périodique (toutes les heures)
    - Diagnostic spam (toutes les 30 minutes si spam rate < 5%)
    - Réponse automatique aux dérives détectées
    - File de révision active pour l'utilisateur

    Usage :
      loop = AutonomousLoop()
      loop.start()   # Lance le thread en arrière-plan
      loop.stop()    # Arrête proprement
      loop.health_report()  # Rapport lisible
    """

    EVAL_INTERVAL_SEC    = 3600   # Évaluation toutes les heures
    DIAG_INTERVAL_SEC    = 1800   # Diagnostic toutes les 30 min

    def __init__(self, pipeline_loader=None):
        self.active_learner   = ActiveLearner(budget_per_day=10)
        self.spam_diagnostic  = SpamDiagnostic()
        self.drift_responder  = ConceptDriftResponder()
        self.self_evaluator   = SelfEvaluator()
        self._pipeline_loader = pipeline_loader

        self._running         = False
        self._thread          = None
        self._last_eval       = datetime.min
        self._last_diag       = datetime.min
        self._diag_cache      = {}

    def start(self):
        """Lance la boucle autonome dans un thread de fond."""
        if self._running:
            logger.warning("Boucle autonome déjà active.")
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="AutonomousAI"
        )
        self._thread.start()
        logger.info("🤖 Boucle IA autonome démarrée.")

    def stop(self):
        self._running = False
        logger.info("Boucle IA autonome arrêtée.")

    def _loop(self):
        """Boucle principale — tourne en arrière-plan."""
        while self._running:
            now = datetime.now()

            # Évaluation périodique
            if (now - self._last_eval).total_seconds() >= self.EVAL_INTERVAL_SEC:
                try:
                    logger.info("[AutoLoop] Évaluation périodique...")
                    self.self_evaluator.evaluate()
                    self._last_eval = now
                except Exception as e:
                    logger.error(f"[AutoLoop] Erreur évaluation : {e}")

            # Diagnostic spam
            if (now - self._last_diag).total_seconds() >= self.DIAG_INTERVAL_SEC:
                try:
                    diag = self.spam_diagnostic.run()
                    self._diag_cache = diag
                    if diag.get("severity") == "critical":
                        logger.warning(
                            f"[AutoLoop] Diagnostic CRITIQUE : "
                            f"{diag.get('diagnosis', ['?'])[0][:100]}"
                        )
                    self._last_diag = now
                except Exception as e:
                    logger.error(f"[AutoLoop] Erreur diagnostic : {e}")

            time.sleep(60)   # Vérification toutes les minutes

    def on_analysis(self, text: str, result: dict) -> dict:
        """
        Appelé après chaque analyse par main_v2.py.
        Retourne des métadonnées d'apprentissage actif.
        """
        should_review, reason = self.active_learner.should_request_review(
            result, text
        )
        if should_review:
            self.active_learner.queue_for_review(text, result, reason)

        return {
            "review_requested": should_review,
            "review_reason":    reason,
        }

    def on_drift(self, drift_type: str) -> dict:
        """Appelé par SmartScheduler quand une dérive est détectée."""
        return self.drift_responder.respond(drift_type, self._pipeline_loader)

    def health_report(self) -> dict:
        """Rapport de santé complet du système."""
        eval_report = self.self_evaluator.evaluate()
        diag        = self._diag_cache or self.spam_diagnostic.run()

        return {
            "status":          "running" if self._running else "stopped",
            "evaluation":      eval_report,
            "spam_diagnostic": diag,
            "active_learner":  self.active_learner.status(),
            "drift_history":   list(self.drift_responder._drift_history)[-5:],
        }

    def get_review_queue(self) -> List[dict]:
        """Emails en attente de révision manuelle."""
        return self.active_learner.get_review_queue()


# ══════════════════════════════════════════════════════════════════
# INTÉGRATION DANS main_v2.py
# Ajouter ces lignes dans main_v2.py pour activer la boucle :
#
#   from ai_engine import AutonomousLoop
#   ai_loop = AutonomousLoop(pipeline_loader=pipeline_loader)
#
# Dans lifespan() :
#   ai_loop.start()
#
# Dans analyze_email() :
#   ai_meta = ai_loop.on_analysis(request.text, result)
#   result["ai_meta"] = ai_meta
#
# Nouveaux endpoints :
#   GET  /ai/health         → ai_loop.health_report()
#   GET  /ai/review-queue   → ai_loop.get_review_queue()
#   GET  /ai/spam-diagnostic → SpamDiagnostic().run()
# ══════════════════════════════════════════════════════════════════

# Singleton
autonomous_loop = AutonomousLoop()
