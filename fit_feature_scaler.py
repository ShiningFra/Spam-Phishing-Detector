"""
fit_feature_scaler.py
======================
Ajuste UNE SEULE FOIS un normaliseur (MaxAbsScaler, compatible matrices
creuses) sur les 523 dimensions du correcteur, à partir d'un échantillon
représentatif et équilibré du vrai corpus — pas seulement des petits lots
de corrections, qui ne couvrent pas toute la distribution réelle des
valeurs (en particulier char_count/word_count/url_max_length, dont
l'échelle varie énormément d'un email à l'autre).

IMPORTANT — ordre d'exécution :
    1. Lancer CE script en premier (avant tout patch), pendant que
       prepare_features_v2() est encore dans son état non modifié —
       il en a besoin pour produire les features brutes à normaliser.
    2. Appliquer ensuite apply_scaler_patch_training.py et
       apply_scaler_patch_inference.py, qui font charger et appliquer
       ce normaliseur aux deux endroits concernés.
    3. Refaire le cycle --reset / generate_balanced_corrections.py /
       --force habituel — cette fois avec des features normalisées de
       bout en bout.

Usage :
    cd E:\\Workspace\\Memory\\Spc
    python fit_feature_scaler.py
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
NOTEBOOKS_DIR = BASE_DIR / "notebooks"
DATA_DIR = NOTEBOOKS_DIR / "data"
SCALER_PATH = DATA_DIR / "corrector_feature_scaler.pkl"

sys.path.insert(0, str(NOTEBOOKS_DIR))


def main():
    import joblib
    import pandas as pd
    import numpy as np
    from sklearn.preprocessing import MaxAbsScaler

    print("Chargement du corpus et des modèles réels...")
    df = pd.read_csv(DATA_DIR / "emails_features.csv")
    tfidf = joblib.load(DATA_DIR / "tfidf_vectorizer.pkl")
    rf_model = joblib.load(DATA_DIR / "best_model.pkl")

    # Import direct de la fonction réelle de préparation des features —
    # pas de duplication de logique qui pourrait diverger avec le temps.
    from incremental_layer_v2 import prepare_features_v2

    N_PER_CLASS = 1000
    parts = []
    for cls in ["ham", "spam", "phishing"]:
        subset = df[df["label"] == cls]
        n = min(len(subset), N_PER_CLASS)
        parts.append(subset.sample(n, random_state=42))
        print(f"  {cls:10s} : {n} exemples pour l'ajustement du normaliseur")
    sample_df = pd.concat(parts)
    texts = sample_df["text"].astype(str).tolist()

    print(f"\nConstruction des features (523 dims) sur {len(texts)} emails...")
    X, _ = prepare_features_v2(texts, rf_model, tfidf)
    print(f"Forme de X : {X.shape}")

    scaler = MaxAbsScaler()
    scaler.fit(X)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\nNormaliseur sauvegardé : {SCALER_PATH}")

    # Aperçu de l'effet, pour vérifier que ça a du sens
    X_scaled = scaler.transform(X)
    print("\nAvant normalisation — colonnes 3 à 22 (features structurelles), "
          "valeurs max observées :")
    print(np.asarray(X[:, 3:23].max(axis=0).todense()).flatten())
    print("\nAprès normalisation — mêmes colonnes, valeurs max (doivent être ≈1.0) :")
    print(np.asarray(X_scaled[:, 3:23].max(axis=0).todense()).flatten())


if __name__ == "__main__":
    main()
