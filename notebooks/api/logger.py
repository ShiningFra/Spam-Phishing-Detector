import json
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Logger standard Python
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("spam_detector")


class DetectionLogger:
    """
    Journalise chaque analyse dans un fichier JSONL.
    Permet l'audit et le réentraînement futur (§3.5 apprentissage continu).
    """

    def __init__(self):
        self.log_file   = LOG_DIR / "detections.jsonl"
        self.stats      = {
            "total":     0,
            "by_class":  defaultdict(int),
            "by_threat": defaultdict(int),
            "latencies": [],
            "alerts":    0,
            "since":     datetime.utcnow().isoformat(),
        }

    def log_detection(self, result: dict) -> None:
        """Journalise une détection dans le fichier JSONL."""
        entry = {
            "ts":              datetime.utcnow().isoformat(),
            "predicted_class": result.get("predicted_class"),
            "threat_level":    result.get("threat_level"),
            "confidence":      result.get("global_confidence"),
            "latency_ms":      result.get("latency_ms"),
            "rules_count":     len(result.get("rules_triggered", [])),
            "url_flags_count": len(result.get("url_flags", [])),
            "header_score":    result.get("header_score"),
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        # Mise à jour des statistiques en mémoire
        self.stats["total"] += 1
        self.stats["by_class"][entry["predicted_class"]] += 1
        self.stats["by_threat"][entry["threat_level"]]   += 1
        self.stats["latencies"].append(entry["latency_ms"])

        if entry["threat_level"] in ("high", "critical"):
            self.stats["alerts"] += 1
            logger.warning(f"[ALERT] {entry['threat_level'].upper()} — {entry['predicted_class']} (conf={entry['confidence']:.2%})")

    def get_stats(self) -> dict:
        lats = self.stats["latencies"]
        return {
            "total_analyzed": self.stats["total"],
            "by_class":       dict(self.stats["by_class"]),
            "by_threat":      dict(self.stats["by_threat"]),
            "avg_latency_ms": round(sum(lats) / len(lats), 2) if lats else 0.0,
            "alerts_sent":    self.stats["alerts"],
            "since":          self.stats["since"],
        }


detection_logger = DetectionLogger()