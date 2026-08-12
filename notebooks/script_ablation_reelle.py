# ============================================================================
# ÉTUDE D'ABLATION RÉELLE — à coller dans une nouvelle cellule du notebook 05,
# APRÈS avoir chargé pipeline_v2.py (HybridEmailPipelineV2 déjà instancié et
# .load_models() déjà appelé, comme le fait le reste du notebook).
#
# Reconstruit exactement le même split de test que NB02 (même random_state,
# même stratify) pour évaluer sur les 27 060 emails du vrai test set — pas
# un échantillon de 300 comme l'évaluation rapide du notebook 05 actuel.
#
# Principe : on ne réentraîne rien. On désactive chaque couche une par une
# en patchant temporairement la méthode correspondante de l'objet pipeline,
# puis on restaure l'original. Rien n'est modifié de façon permanente.
# ============================================================================

import copy
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, recall_score
from tqdm import tqdm

# ---------------------------------------------------------------------------
# 1. Reconstruire EXACTEMENT le même test set que NB02
#    (même appel, même random_state=42, même test_size=0.15, même stratify)
# ---------------------------------------------------------------------------
df_full = pd.read_csv(DATA_DIR / 'emails_features.csv')
X_all = df_full['text']
y_all = df_full['label']

X_train_raw, X_test_text, y_train_raw, y_test_labels = train_test_split(
    X_all, y_all, test_size=0.15, random_state=42, stratify=y_all
)
# (le split train/val intermédiaire de NB02 n'affecte pas X_test_text, donc
#  inutile de le reproduire ici — seul le premier split définit le test set)

X_test_text = X_test_text.reset_index(drop=True)
y_test_labels = y_test_labels.reset_index(drop=True)
print(f"Test set reconstruit : {len(X_test_text)} emails "
      f"(doit correspondre à X_test.npz / y_test.npy déjà sauvegardés)")

# ---------------------------------------------------------------------------
# 2. Pipeline v2 déjà chargé dans le notebook — on s'appuie dessus
#    (adapter le nom de variable si besoin, ex. `pipeline` ou `p2`)
# ---------------------------------------------------------------------------
# pipeline_v2 = HybridEmailPipelineV2() ; pipeline_v2.load_models()  # déjà fait plus haut

def run_eval(pipeline_obj, label, sample_size=None, seed=42):
    """Évalue le pipeline (éventuellement patché) sur le test set réel."""
    if sample_size:
        rng = np.random.RandomState(seed)
        idx = rng.choice(len(X_test_text), size=sample_size, replace=False)
        texts = X_test_text.iloc[idx].tolist()
        labels = y_test_labels.iloc[idx].tolist()
    else:
        texts = X_test_text.tolist()
        labels = y_test_labels.tolist()

    preds = []
    for t in tqdm(texts, desc=label):
        r = pipeline_obj.analyze(str(t))  # pas de raw_email : conforme à l'éval actuelle NB05
        preds.append(r.predicted_class)

    f1 = f1_score(labels, preds, average='macro', zero_division=0)
    rec_spam = recall_score(labels, preds, labels=['spam'], average='macro', zero_division=0)
    rec_phish = recall_score(labels, preds, labels=['phishing'], average='macro', zero_division=0)
    return {'config': label, 'f1_macro': round(f1, 4),
            'rappel_spam': round(rec_spam, 4), 'rappel_phishing': round(rec_phish, 4),
            'n': len(texts)}

# ---------------------------------------------------------------------------
# 3. Configurations d'ablation — chaque bloc désactive une seule couche
#    en patchant l'objet, puis restaure l'état d'origine.
# ---------------------------------------------------------------------------
results = []

# --- Référence : pipeline complet ---
results.append(run_eval(pipeline_v2, "Pipeline complet (référence)"))

# --- Sans couche 0 (whitelist) : on vide temporairement les domaines ---
original_domains = pipeline_v2._whitelist.domains
pipeline_v2._whitelist.domains = set()
results.append(run_eval(pipeline_v2, "Sans couche 0 (whitelist)"))
pipeline_v2._whitelist.domains = original_domains

# --- Sans couche 1 (règles) : on neutralise HeuristicLayer.analyze ---
original_heuristic_analyze = pipeline_v2._heuristic.analyze
pipeline_v2._heuristic.analyze = lambda text, is_whitelisted=False: (0.0, 0.0, [], [])
results.append(run_eval(pipeline_v2, "Sans couche 1 (règles)"))
pipeline_v2._heuristic.analyze = original_heuristic_analyze

# --- Sans couche 2 (en-têtes) : aucun raw_email n'est jamais transmis dans
#     l'éval actuelle de NB05 (texte seul) — cette couche est donc déjà
#     structurellement inactive dans l'éval de référence ci-dessus. Pour la
#     mesurer, il faut passer des emails complets (texte + en-têtes) : à
#     faire séparément avec emails_raw.csv si les en-têtes y sont présents,
#     sinon cette ligne d'ablation n'est pas mesurable avec les données
#     actuelles et doit être retirée du tableau plutôt que devinée.
# results.append(run_eval(..., "Sans couche 2 (en-têtes)"))  # cf. note ci-dessus

# --- Sans correcteur SGD : on force le pipeline à ignorer le correcteur ---
original_corrector = pipeline_v2._corrector
pipeline_v2._corrector = None
results.append(run_eval(pipeline_v2, "Sans correcteur SGD"))
pipeline_v2._corrector = original_corrector

# --- RF seul (baseline) : déjà mesuré et sauvegardé dans best_model_metrics.json
#     — à reporter tel quel plutôt qu'à recalculer.

# ---------------------------------------------------------------------------
# 4. Résultat
# ---------------------------------------------------------------------------
df_ablation = pd.DataFrame(results)
print(df_ablation.to_string(index=False))
df_ablation.to_csv(DATA_DIR / 'ablation_reelle.csv', index=False)
print(f"\nSauvegardé dans {DATA_DIR / 'ablation_reelle.csv'} — à transmettre pour mise à jour du tableau 5.4 du mémoire.")
