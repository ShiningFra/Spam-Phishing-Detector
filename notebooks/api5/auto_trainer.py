# -*- coding: utf-8 -*-
"""
auto_trainer.py
===============
Module d'automatisation intelligente de l'apprentissage continu.

Problème v1 : le correcteur SGD est déclenché manuellement ou tous les 10
feedbacks fixes. Pas de logique d'adaptation.

Solution v2 :
  1. SmartScheduler  — déclenche l'update selon la dérive de performance,
                       pas juste un compteur fixe
  2. DriftDetector   — détecte quand le modèle se dégrade (concept drift)
  3. AutoLabeler     — labellise automatiquement les cas très confiants
                       pour nourrir le correcteur sans intervention humaine
  4. PerformanceTracker — suit les métriques de performance dans le temps
"""

import json
import logging
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("auto_trainer")

BASE_DIR      = Path(__file__).resolve().parent.parent  # notebooks/ (pas api/)
LOGS_DIR      = BASE_DIR / "logs"
DATA_DIR      = BASE_DIR / "data"
FEEDBACK_FILE = LOGS_DIR / "feedback_verified.jsonl"
DETECTIONS    = LOGS_DIR / "detections.jsonl"
PERF_FILE     = DATA_DIR / "performance_history.json"

LOGS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════════
# PERFORMANCE TRACKER
# ══════════════════════════════════════════════════════════════════

class PerformanceTracker:
    """
    Suit les métriques de performance en temps réel.
    Utilise une fenêtre glissante sur les N derniers emails corrigés.
    """

    WINDOW = 100  # Taille de la fenêtre glissante

    def __init__(self):
        self.history: deque = deque(maxlen=self.WINDOW)
        self._load()

    def _load(self):
        if PERF_FILE.exists():
            try:
                with open(PERF_FILE) as f:
                    data = json.load(f)
                for entry in data.get('history', [])[-self.WINDOW:]:
                    self.history.append(entry)
            except Exception:
                pass

    def save(self):
        with open(PERF_FILE, 'w') as f:
            json.dump({'history': list(self.history),
                       'updated_at': datetime.now().isoformat()}, f, indent=2)

    def record(self, predicted: str, correct: str, confidence: float):
        """Enregistre un résultat (depuis un feedback utilisateur)."""
        self.history.append({
            'predicted':  predicted,
            'correct':    correct,
            'confidence': confidence,
            'correct_yn': int(predicted == correct),
            'ts':         datetime.now().isoformat(),
        })
        self.save()

    def accuracy_by_class(self) -> Dict[str, float]:
        """Accuracy par classe sur la fenêtre glissante."""
        per_class = defaultdict(lambda: {'correct': 0, 'total': 0})
        for e in self.history:
            c = e['correct']
            per_class[c]['total'] += 1
            if e['correct_yn']:
                per_class[c]['correct'] += 1
        return {
            cls: d['correct'] / d['total'] if d['total'] > 0 else None
            for cls, d in per_class.items()
        }

    def spam_recall(self) -> Optional[float]:
        """Rappel spam — métrique critique pour ce projet."""
        acc = self.accuracy_by_class()
        return acc.get('spam')

    def overall_accuracy(self) -> float:
        if not self.history:
            return 0.0
        return np.mean([e['correct_yn'] for e in self.history])

    def report(self) -> dict:
        acc = self.accuracy_by_class()
        return {
            'window_size':        len(self.history),
            'overall_accuracy':   round(self.overall_accuracy(), 4),
            'accuracy_by_class':  {k: round(v, 4) if v is not None else None
                                   for k, v in acc.items()},
            'spam_recall':        round(self.spam_recall(), 4)
                                  if self.spam_recall() is not None else None,
        }


# ══════════════════════════════════════════════════════════════════
# DRIFT DETECTOR
# ══════════════════════════════════════════════════════════════════

class DriftDetector:
    """
    Détecte la dérive du concept (concept drift) en comparant les performances
    sur deux fenêtres temporelles.

    Méthode : Page-Hinkley Test (détecteur de changement de moyenne adapté
    aux séquences de performances).
    """

    def __init__(self, delta: float = 0.005, lambda_: float = 0.10):
        self.delta    = delta    # Sensibilité au changement
        self.lambda_  = lambda_  # Seuil de détection
        self._sum     = 0.0
        self._minimum = 0.0
        self._n       = 0
        self._mean    = 0.0

    def update(self, correct: bool) -> bool:
        """
        Met à jour le détecteur avec une nouvelle observation.
        Retourne True si une dérive est détectée.
        """
        x = 1.0 if correct else 0.0
        self._n += 1
        self._mean += (x - self._mean) / self._n

        # Page-Hinkley update
        self._sum += x - self._mean - self.delta
        self._minimum = min(self._minimum, self._sum)

        return (self._sum - self._minimum) > self.lambda_

    def reset(self):
        self._sum = 0.0
        self._minimum = 0.0
        self._n = 0
        self._mean = 0.0


# ══════════════════════════════════════════════════════════════════
# AUTO LABELER (labellisation automatique des cas confiants)
# ══════════════════════════════════════════════════════════════════

class AutoLabeler:
    """
    Génère des pseudo-labels automatiques pour nourrir le correcteur SGD
    sans intervention humaine.

    Principe : si le pipeline est très confiant (> seuil) ET que les
    signaux sont cohérents (règles + ML + headers tous d'accord),
    on utilise cette prédiction comme label automatique.

    Cela simule un "oracle partiel" — uniquement sur les cas faciles.
    Les cas difficiles restent pour les corrections manuelles.
    """

    CONFIDENCE_THRESHOLD = 0.92  # Seuil de confiance pour auto-label
    MAX_AUTO_PER_DAY     = 50    # Limite pour éviter le biais
    SPAM_THRESHOLD       = 0.85  # Seuil plus bas pour spam (compenser le biais)

    def __init__(self):
        self._auto_labels_today = 0
        self._last_reset        = datetime.now().date()

    def _reset_if_needed(self):
        today = datetime.now().date()
        if today != self._last_reset:
            self._auto_labels_today = 0
            self._last_reset = today

    def should_auto_label(self, result: dict) -> bool:
        """Détermine si on peut auto-labelliser ce résultat."""
        self._reset_if_needed()

        if self._auto_labels_today >= self.MAX_AUTO_PER_DAY:
            return False

        pred = result.get('predicted_class', '')
        conf = result.get('global_confidence', 0.0)
        path = result.get('decision_path', '')

        # Pour les spams : seuil plus bas (compenser le biais RF)
        threshold = (self.SPAM_THRESHOLD
                     if pred == 'spam'
                     else self.CONFIDENCE_THRESHOLD)

        if conf < threshold:
            return False

        # Vérification de cohérence : plusieurs couches d'accord
        rule_score   = result.get('rule_score', 0)
        header_score = result.get('header_score', 0)

        if pred == 'phishing':
            # Exiger que les règles ou les headers confirment
            return rule_score > 0.40 or header_score > 0.50

        if pred == 'spam':
            # Exiger un signal spam fort dans les règles
            rules = result.get('rules_triggered', [])
            has_spam_rule = any('spam_financial' in r or 'spam_scam' in r
                                or 'spam_pharma' in r for r in rules)
            return has_spam_rule

        # Pour ham : auto-label si très confiant et aucun signal d'alerte
        if pred == 'ham':
            return (conf > 0.95
                    and rule_score < 0.10
                    and header_score < 0.10
                    and not result.get('url_flags'))

        return False

    def generate_label(self, text: str, result: dict) -> Optional[dict]:
        """Génère un pseudo-label si les conditions sont remplies."""
        if not self.should_auto_label(result):
            return None

        self._auto_labels_today += 1
        entry = {
            'text':        text[:3000],
            'label':       result['predicted_class'],
            'predicted':   result['predicted_class'],
            'source':      'auto_label',
            'confidence':  result['global_confidence'],
            'ts':          datetime.now().isoformat(),
        }
        logger.debug(f"Auto-label généré : {entry['label']} (conf={entry['confidence']:.2f})")
        return entry


# ══════════════════════════════════════════════════════════════════
# SMART SCHEDULER
# ══════════════════════════════════════════════════════════════════

class SmartScheduler:
    """
    Décide intelligemment quand déclencher la mise à jour du correcteur SGD.

    Stratégie v2 (remplace le simple compteur à 10) :
    1. Drift détecté  → mise à jour immédiate
    2. Spam recall < 0.60 avec ≥ 5 corrections spam → mise à jour urgente
    3. Volume ≥ 20 corrections → mise à jour normale
    4. Volume ≥ 5 corrections + 24h sans mise à jour → mise à jour légère
    5. Auto-labels accumulés (≥ 30) → mise à jour silencieuse
    """

    def __init__(self):
        self.tracker      = PerformanceTracker()
        self.drift_det    = DriftDetector()
        self.auto_labeler = AutoLabeler()
        self._last_update: Optional[datetime] = None
        self._update_count = 0
        self._load_state()

    def _load_state(self):
        state_file = DATA_DIR / "scheduler_state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    state = json.load(f)
                lu = state.get('last_update')
                if lu:
                    self._last_update = datetime.fromisoformat(lu)
                self._update_count = state.get('update_count', 0)
            except Exception:
                pass

    def _save_state(self):
        state_file = DATA_DIR / "scheduler_state.json"
        with open(state_file, 'w') as f:
            json.dump({
                'last_update':  self._last_update.isoformat() if self._last_update else None,
                'update_count': self._update_count,
                'saved_at':     datetime.now().isoformat(),
            }, f, indent=2)

    def on_feedback(self, predicted: str, correct: str, confidence: float) -> str:
        """
        Appelé à chaque feedback utilisateur.
        Retourne la raison de déclenchement ou '' si pas de déclenchement.
        """
        # Enregistrer la performance
        self.tracker.record(predicted, correct, confidence)

        # Drift detector
        is_correct = (predicted == correct)
        drift_detected = self.drift_det.update(is_correct)
        if drift_detected:
            self.drift_det.reset()
            return 'drift_detected'

        corrections = self._load_pending_corrections()
        n = len(corrections)

        if n == 0:
            return ''

        # Spam recall critique
        spam_corrections = [c for c in corrections if c.get('label') == 'spam']
        spam_recall = self.tracker.spam_recall()
        if len(spam_corrections) >= 5 and spam_recall is not None and spam_recall < 0.60:
            return f'spam_recall_critical({spam_recall:.2f})'

        # Volume élevé
        if n >= 20:
            return f'volume_threshold({n})'

        # Volume modéré + délai
        if n >= 5 and self._last_update:
            hours_since = (datetime.now() - self._last_update).total_seconds() / 3600
            if hours_since >= 24:
                return f'time_threshold({hours_since:.0f}h)'

        # Auto-labels accumulés
        auto_labels = [c for c in corrections if c.get('source') == 'auto_label']
        if len(auto_labels) >= 30:
            return f'auto_labels_threshold({len(auto_labels)})'

        return ''

    def on_analysis(self, text: str, result: dict) -> Optional[dict]:
        """
        Appelé après chaque analyse. Génère un auto-label si pertinent.
        """
        return self.auto_labeler.generate_label(text, result)

    def record_update(self, reason: str):
        """Enregistre qu'une mise à jour a été effectuée."""
        self._last_update = datetime.now()
        self._update_count += 1
        self._save_state()
        logger.info(f"[Scheduler] Mise à jour #{self._update_count} — raison : {reason}")

    def _load_pending_corrections(self) -> List[dict]:
        if not FEEDBACK_FILE.exists():
            return []
        corrections = []
        with open(FEEDBACK_FILE, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if e.get('text') and e.get('label') in ('ham', 'spam', 'phishing'):
                        corrections.append(e)
                except Exception:
                    pass
        return corrections

    def status(self) -> dict:
        corrections = self._load_pending_corrections()
        perf = self.tracker.report()
        return {
            'pending_corrections':  len(corrections),
            'spam_pending':         sum(1 for c in corrections if c.get('label') == 'spam'),
            'ham_pending':          sum(1 for c in corrections if c.get('label') == 'ham'),
            'phishing_pending':     sum(1 for c in corrections if c.get('label') == 'phishing'),
            'auto_labels_pending':  sum(1 for c in corrections if c.get('source') == 'auto_label'),
            'last_update':          self._last_update.isoformat() if self._last_update else None,
            'update_count':         self._update_count,
            'performance':          perf,
        }


# ══════════════════════════════════════════════════════════════════
# INTÉGRATION AVEC main.py
# ══════════════════════════════════════════════════════════════════

# Singleton global (partagé avec main.py)
scheduler = SmartScheduler()


def process_feedback(text: str, predicted: str, correct: str,
                     confidence: float) -> Tuple[bool, str]:
    """
    Point d'entrée unique pour traiter un feedback.
    Remplace la logique du endpoint /feedback dans main.py.

    Retourne (should_trigger_update, reason).
    """
    reason = scheduler.on_feedback(predicted, correct, confidence)
    should_trigger = bool(reason)

    # Sauvegarder le feedback
    entry = {
        'text':      text[:3000],
        'label':     correct,
        'predicted': predicted,
        'source':    'user_feedback',
        'ts':        datetime.now().isoformat(),
    }
    with open(FEEDBACK_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    if should_trigger:
        logger.info(f"[AutoTrigger] Déclenchement : {reason}")

    return should_trigger, reason


def process_analysis_result(text: str, result: dict):
    """
    Appelé après chaque analyse pour potentiellement générer un auto-label.
    """
    auto_label = scheduler.on_analysis(text, result)
    if auto_label:
        with open(FEEDBACK_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(auto_label, ensure_ascii=False) + '\n')
        logger.debug(f"Auto-label sauvegardé : {auto_label['label']}")
