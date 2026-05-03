import joblib
import logging
import json
from pathlib import Path
from typing import Optional

logger = logging.getLogger("spam_detector")

DATA_DIR = Path("data")


class PipelineLoader:
    """
    Charge et expose le pipeline hybride pour l'API.
    Chargement unique au démarrage (singleton pattern).
    """

    def __init__(self):
        self._pipeline = None
        self._config   = None
        self._loaded   = False

    def load(self) -> None:
        """Charge le pipeline et sa configuration depuis data/."""
        logger.info("Chargement du pipeline hybride...")

        try:
            self._pipeline = joblib.load(DATA_DIR / "pipeline_hybride.pkl")
            logger.info("Pipeline hybride chargé.")
        except FileNotFoundError:
            logger.error("pipeline_hybride.pkl introuvable. Exécuter NB 05.")
            raise

        try:
            with open(DATA_DIR / "pipeline_config.json") as f:
                self._config = json.load(f)
        except FileNotFoundError:
            self._config = {}

        self._loaded = True
        logger.info("Pipeline prêt.")

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def config(self) -> dict:
        return self._config or {}

    def analyze(self, text: str, raw_email: Optional[str] = None) -> dict:
        """Analyse un email et retourne le résultat sérialisable."""
        if not self._loaded:
            raise RuntimeError("Pipeline non chargé. Appeler load() d'abord.")

        result = self._pipeline.analyze(text, raw_email or "")
        return result.to_dict()

    def get_models_info(self) -> dict:
        """Retourne les informations sur les modèles chargés."""
        return {
            "pipeline":    "HybridEmailPipeline",
            "ml_model":    "LinearSVC (calibrated)",
            "bert":        self._config.get("use_bert", False),
            "class_names": self._config.get("class_names", []),
            "weights":     self._config.get("weights", {}),
        }


pipeline_loader = PipelineLoader()