"""
apply_bert_integration_patch.py
=================================
Intègre DistilBERT dans HybridEmailPipelineV2 :
  1. Import torch/transformers (avec repli gracieux si absents)
  2. __init__ : nouveaux attributs _bert_tokenizer / _bert_model
  3. load_models() : chargement de DistilBERT si le dossier existe
  4. _predict_bert() : nouvelle méthode de prédiction
  5. AdaptiveWeights.BASE : ajout d'un poids 'bert'
  6. _aggregate() : bert_proba intégré au score pondéré ET au score
     composite de phishing (qui pilote réellement le seuil de décision)
  7. analyze() : appel de _predict_bert() et transmission à _aggregate()

Chaque étape vérifie son texte cible avant modification ; si l'une
d'elles échoue, le script s'arrête sans rien écrire sur le disque.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python apply_bert_integration_patch.py

Nécessite : pip install torch transformers  (si pas déjà fait)
"""

import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/api/")

src = TARGET.read_text(encoding="utf-8")

if "_predict_bert" in src:
    raise SystemExit("L'intégration BERT semble déjà appliquée — rien à faire.")

steps_done = []

def require(old, label):
    if src.count(old) != 1:
        raise SystemExit(
            f"[{label}] texte cible introuvable ou ambigu (trouvé {src.count(old)} fois, "
            f"1 attendue). N'a rien changé sur le disque."
        )

# ── Étape 1 : imports ────────────────────────────────────────────────
old1 = "from urllib.parse import urlparse"
require(old1, "imports")
new1 = old1 + (
    "\n\ntry:\n"
    "    import torch\n"
    "    from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification\n"
    "    _BERT_AVAILABLE = True\n"
    "except ImportError:\n"
    "    _BERT_AVAILABLE = False\n"
)
src = src.replace(old1, new1, 1)
steps_done.append("imports torch/transformers (avec repli gracieux)")

# ── Étape 2 : __init__ ───────────────────────────────────────────────
old2 = (
    "        self._class_names   = ['ham', 'phishing', 'spam']\n"
    "        self._corrector     = None\n"
)
require(old2, "__init__")
new2 = old2 + (
    "        self._bert_tokenizer = None\n"
    "        self._bert_model     = None\n"
)
src = src.replace(old2, new2, 1)
steps_done.append("__init__ : attributs _bert_tokenizer / _bert_model")

# ── Étape 3 : load_models() ──────────────────────────────────────────
old3 = (
    "        self._corrector     = _load_corrector()\n"
    "\n"
    "        logger.info(f\"Modèle base  : {type(self._ml_model).__name__}\")"
)
require(old3, "load_models")
new3 = (
    "        self._corrector     = _load_corrector()\n"
    "\n"
    "        bert_dir = DATA_DIR / 'distilbert_model'\n"
    "        if _BERT_AVAILABLE and bert_dir.exists():\n"
    "            try:\n"
    "                self._bert_tokenizer = DistilBertTokenizerFast.from_pretrained(str(bert_dir))\n"
    "                self._bert_model = DistilBertForSequenceClassification.from_pretrained(\n"
    "                    str(bert_dir), num_labels=len(self._class_names)\n"
    "                )\n"
    "                self._bert_model.eval()\n"
    "                logger.info(\"DistilBERT chargé.\")\n"
    "            except Exception as e:\n"
    "                logger.warning(f\"DistilBERT non chargé : {e}\")\n"
    "                self._bert_tokenizer = None\n"
    "                self._bert_model = None\n"
    "        else:\n"
    "            logger.info(\"DistilBERT indisponible (torch/transformers absent ou dossier manquant) "
    "— pipeline exécuté sans cette couche.\")\n"
    "\n"
    "        logger.info(f\"Modèle base  : {type(self._ml_model).__name__}\")"
)
src = src.replace(old3, new3, 1)
steps_done.append("load_models() : chargement conditionnel de DistilBERT")

# ── Étape 4 : _predict_bert() (insérée juste après _predict_ml) ─────
old4 = (
    "        proba_dict = {c: float(p) for c, p in zip(self._class_names, proba)}\n"
    "        return proba_dict, X_tfidf, struct\n"
)
require(old4, "_predict_ml (point d'insertion de _predict_bert)")
new4 = old4 + (
    "\n"
    "    def _predict_bert(self, text: str) -> dict:\n"
    "        \"\"\"Prédiction DistilBERT — retourne un dict {classe: probabilité}.\"\"\"\n"
    "        if self._bert_model is None:\n"
    "            return {}\n"
    "        with torch.no_grad():\n"
    "            encoding = self._bert_tokenizer(\n"
    "                text[:2000], max_length=256, padding='max_length',\n"
    "                truncation=True, return_tensors='pt',\n"
    "            )\n"
    "            outputs = self._bert_model(**encoding)\n"
    "            probs = torch.softmax(outputs.logits, dim=-1).numpy()[0]\n"
    "        id2label = self._bert_model.config.id2label\n"
    "        bert_by_name = {id2label[i]: float(p) for i, p in enumerate(probs)}\n"
    "        return {c: bert_by_name.get(c, 0.0) for c in self._class_names}\n"
)
src = src.replace(old4, new4, 1)
steps_done.append("_predict_bert() ajoutée")

# ── Étape 5 : AdaptiveWeights.BASE ───────────────────────────────────
old5 = "    BASE = {'rules': 0.20, 'headers': 0.25, 'ml': 0.55}"
require(old5, "AdaptiveWeights.BASE")
new5 = "    BASE = {'rules': 0.16, 'headers': 0.20, 'ml': 0.44, 'bert': 0.20}"
src = src.replace(old5, new5, 1)
steps_done.append("AdaptiveWeights.BASE : poids 'bert' ajouté (0.20)")

# ── Étape 6a : signature + docstring de _aggregate ──────────────────
old6a = (
    "    def _aggregate(self, rule_spam: float, rule_phish: float,\n"
    "                   header_score: float, ml_proba: dict,\n"
    "                   weights: dict) -> Tuple[str, float, str]:\n"
    "        \"\"\"Agrégation pondérée avec poids adaptatifs.\"\"\"\n"
)
require(old6a, "_aggregate signature")
new6a = (
    "    def _aggregate(self, rule_spam: float, rule_phish: float,\n"
    "                   header_score: float, ml_proba: dict,\n"
    "                   weights: dict, bert_proba: dict = None) -> Tuple[str, float, str]:\n"
    "        \"\"\"Agrégation pondérée avec poids adaptatifs (inclut DistilBERT si disponible).\"\"\"\n"
    "        bert_proba = bert_proba or {}\n"
)
src = src.replace(old6a, new6a, 1)
steps_done.append("_aggregate() : paramètre bert_proba ajouté")

# ── Étape 6b : intégration dans le score pondéré `final` ────────────
old6b = (
    "        final = {}\n"
    "        for c in self._class_names:\n"
    "            final[c] = (weights.get('rules', 0.20)   * rule_vec.get(c, 0) +\n"
    "                        weights.get('headers', 0.25)  * head_vec.get(c, 0) +\n"
    "                        weights.get('ml', 0.55)       * ml_proba.get(c, 0))\n"
)
require(old6b, "_aggregate score pondéré")
new6b = (
    "        final = {}\n"
    "        for c in self._class_names:\n"
    "            final[c] = (weights.get('rules', 0.20)   * rule_vec.get(c, 0) +\n"
    "                        weights.get('headers', 0.25)  * head_vec.get(c, 0) +\n"
    "                        weights.get('ml', 0.35)       * ml_proba.get(c, 0) +\n"
    "                        weights.get('bert', 0.20)     * bert_proba.get(c, ml_proba.get(c, 0)))\n"
)
src = src.replace(old6b, new6b, 1)
steps_done.append("_aggregate() : bert_proba intégré au score pondéré `final`")

# ── Étape 6c : intégration dans composite_phish ──────────────────────
old6c = (
    "        ml_phish = ml_proba.get('phishing', 0.0)\n"
    "        ml_ham   = ml_proba.get('ham', 0.0)\n"
    "\n"
    "        composite_phish = min(ml_phish + 0.5 * rule_phish + 0.5 * head_vec.get('phishing', 0), 1.0)\n"
)
require(old6c, "_aggregate composite_phish")
new6c = (
    "        ml_phish   = ml_proba.get('phishing', 0.0)\n"
    "        ml_ham     = ml_proba.get('ham', 0.0)\n"
    "        bert_phish = bert_proba.get('phishing', 0.0)\n"
    "\n"
    "        composite_phish = min(\n"
    "            ml_phish + 0.5 * rule_phish + 0.5 * head_vec.get('phishing', 0) + 0.5 * bert_phish,\n"
    "            1.0,\n"
    "        )\n"
)
src = src.replace(old6c, new6c, 1)
steps_done.append("_aggregate() : bert_phish intégré au score composite (pilote le seuil de décision)")

# ── Étape 7 : analyze() — appel de _predict_bert et transmission ────
old7 = (
    "        result.ml_proba = ml_proba\n"
    "\n"
    "        # ── Poids adaptatifs ────────────────────────────────────\n"
    "        weights = self._adapt_weights.compute(\n"
    "            rule_spam, rule_phish, header_score,\n"
    "            has_headers=has_headers,\n"
    "            has_corrector=self._corrector is not None,\n"
    "            ml_max_conf=ml_max_conf,\n"
    "        )\n"
    "        result.weights_used = weights\n"
    "\n"
    "        # ── Agrégation ──────────────────────────────────────────\n"
    "        pred, conf, threat = self._aggregate(\n"
    "            rule_spam, rule_phish, header_score, ml_proba, weights\n"
    "        )\n"
)
require(old7, "analyze() appel aggregate")
new7 = (
    "        result.ml_proba = ml_proba\n"
    "\n"
    "        # ── Couche 3b : DistilBERT (optionnelle) ────────────────\n"
    "        bert_proba = {}\n"
    "        if self._bert_model is not None:\n"
    "            try:\n"
    "                bert_proba = self._predict_bert(text)\n"
    "                path.append(f'bert({max(bert_proba, key=bert_proba.get)})')\n"
    "            except Exception as e:\n"
    "                logger.warning(f\"BERT predict failed: {e}\")\n"
    "                bert_proba = {}\n"
    "\n"
    "        # ── Poids adaptatifs ────────────────────────────────────\n"
    "        weights = self._adapt_weights.compute(\n"
    "            rule_spam, rule_phish, header_score,\n"
    "            has_headers=has_headers,\n"
    "            has_corrector=self._corrector is not None,\n"
    "            ml_max_conf=ml_max_conf,\n"
    "        )\n"
    "        result.weights_used = weights\n"
    "\n"
    "        # ── Agrégation ──────────────────────────────────────────\n"
    "        pred, conf, threat = self._aggregate(\n"
    "            rule_spam, rule_phish, header_score, ml_proba, weights, bert_proba\n"
    "        )\n"
)
src = src.replace(old7, new7, 1)
steps_done.append("analyze() : appel de _predict_bert() et transmission à _aggregate()")

# ── Écriture ──────────────────────────────────────────────────────────
backup = TARGET.with_suffix(".py.bak8")
shutil.copy2(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print("Patch appliqué avec succès. Étapes :")
for s in steps_done:
    print(f"  - {s}")
print(f"\nSauvegarde de l'original : {backup}")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
