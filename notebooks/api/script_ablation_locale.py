"""
Étude d'ablation réelle — version locale, autonome.

Usage :
    cd shieldmail_local          (le dossier qui contient notebooks/)
    source venv/Scripts/activate
    python script_ablation_locale.py

Attend l'arborescence réelle :
    shieldmail_local/
    ├── notebooks/
    │   ├── api/
    │   │   └── pipeline_v2.py
    │   └── data/
    │       ├── best_model.pkl
    │       ├── tfidf_vectorizer.pkl
    │       ├── label_encoder.pkl
    │       ├── emails_features.csv
    │       ├── incremental_corrector.pkl   (optionnel)
    │       └── whitelist_domains.txt       (optionnel)
    └── script_ablation_locale.py           <- ce fichier

Note : pipeline_v2.py calcule lui-même son DATA_DIR ainsi :
    DATA_DIR = Path(__file__).parent.parent / "data"
Comme le fichier est dans notebooks/api/, cela pointe automatiquement
vers notebooks/data/ — aucune variable d'environnement à régler.
"""

import sys
from pathlib import Path

# --- Rendre pipeline_v2.py importable (il vit dans notebooks/api/) ---
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR / "notebooks" / "api"))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, recall_score
from tqdm import tqdm

from pipeline_v2 import HybridEmailPipelineV2, DATA_DIR

# ---------------------------------------------------------------------------
# 1. Charger le pipeline (modèles réels, rien n'est réentraîné)
# ---------------------------------------------------------------------------
print("Chargement du pipeline v2...")
pipeline_v2 = HybridEmailPipelineV2()
pipeline_v2.load_models()
print("Pipeline prêt.\n")

# ---------------------------------------------------------------------------
# 2. Reconstruire EXACTEMENT le même test set que NB02
#    (même random_state=42, même test_size=0.15, même stratify)
# ---------------------------------------------------------------------------
print("Chargement du corpus et reconstruction du split de test...")
df_full = pd.read_csv(DATA_DIR / 'emails_features.csv')
X_all = df_full['text']
y_all = df_full['label']

_, X_test_text, _, y_test_labels = train_test_split(
    X_all, y_all, test_size=0.15, random_state=42, stratify=y_all
)
X_test_text = X_test_text.reset_index(drop=True)
y_test_labels = y_test_labels.reset_index(drop=True)
print(f"Test set reconstruit : {len(X_test_text)} emails\n")

# ---------------------------------------------------------------------------
# 3. Fonction d'évaluation
# ---------------------------------------------------------------------------
def run_eval(pipeline_obj, label, sample_size=None, seed=42):
    if sample_size and sample_size < len(X_test_text):
        rng = np.random.RandomState(seed)
        idx = rng.choice(len(X_test_text), size=sample_size, replace=False)
        texts = X_test_text.iloc[idx].tolist()
        labels = y_test_labels.iloc[idx].tolist()
    else:
        texts = X_test_text.tolist()
        labels = y_test_labels.tolist()

    preds = []
    for t in tqdm(texts, desc=label):
        r = pipeline_obj.analyze(str(t))
        preds.append(r.predicted_class)

    f1 = f1_score(labels, preds, average='macro', zero_division=0)
    rec_spam = recall_score(labels, preds, labels=['spam'], average='macro', zero_division=0)
    rec_phish = recall_score(labels, preds, labels=['phishing'], average='macro', zero_division=0)
    return {'config': label, 'f1_macro': round(f1, 4),
            'rappel_spam': round(rec_spam, 4), 'rappel_phishing': round(rec_phish, 4),
            'n': len(texts)}

# ---------------------------------------------------------------------------
# 4. Conseil : commencer par un échantillon réduit pour vérifier que tout
#    tourne avant de lancer sur les 27 060 emails (peut prendre du temps
#    en pur CPU sans GPU). Mets SAMPLE_SIZE = None pour l'évaluation complète.
# ---------------------------------------------------------------------------
SAMPLE_SIZE = 500   # <- mets None pour tourner sur tout le test set

results = []
results.append(run_eval(pipeline_v2, "Pipeline complet (référence)", SAMPLE_SIZE))

original_domains = pipeline_v2._whitelist.domains
pipeline_v2._whitelist.domains = set()
results.append(run_eval(pipeline_v2, "Sans couche 0 (whitelist)", SAMPLE_SIZE))
pipeline_v2._whitelist.domains = original_domains

original_heuristic_analyze = pipeline_v2._heuristic.analyze
pipeline_v2._heuristic.analyze = lambda text, is_whitelisted=False: (0.0, 0.0, [], [])
results.append(run_eval(pipeline_v2, "Sans couche 1 (règles)", SAMPLE_SIZE))
pipeline_v2._heuristic.analyze = original_heuristic_analyze

original_corrector = pipeline_v2._corrector
pipeline_v2._corrector = None
results.append(run_eval(pipeline_v2, "Sans correcteur SGD", SAMPLE_SIZE))
pipeline_v2._corrector = original_corrector

# Note : la couche 2 (en-têtes) n'est pas mesurable ici car analyze() est
# appelé sans raw_email (texte seul), exactement comme l'éval actuelle du
# notebook 05. Pour la mesurer, il faudrait des emails complets avec
# en-têtes réels, pas seulement le corps du texte.

# ---------------------------------------------------------------------------
# 5. Résultat
# ---------------------------------------------------------------------------
df_ablation = pd.DataFrame(results)
print("\n" + "=" * 70)
print(df_ablation.to_string(index=False))
print("=" * 70)

out_path = BASE_DIR / "ablation_reelle.csv"
df_ablation.to_csv(out_path, index=False)
print(f"\nSauvegardé dans {out_path}")
