"""
generate_balanced_corrections.py
=================================
Génère des corrections d'entraînement RÉELLEMENT équilibrées pour le
correcteur SGD, à partir du corpus labellisé (emails_features.csv) —
pas des corrections de production, structurellement biaisées (0 vrai
phishing sur 24 corrections appliquées à ce jour).

Principe : pour chaque classe (ham, spam, phishing), on échantillonne
des exemples réels du corpus, on les fait passer par le vrai Random
Forest, et on garde en priorité les cas où le RF s'est trompé — ce
sont les corrections les plus informatives pour le correcteur, exactement
comme le ferait une vraie correction utilisateur. On complète avec des
exemples bien classés si le nombre d'erreurs naturelles est insuffisant,
pour garantir un vrai volume par classe.

Sortie : ajoute les corrections au format attendu dans
    notebooks/logs/feedback_verified.jsonl
(le même fichier que lit notebooks/incremental_layer_v2.py — celui à la
RACINE de notebooks/, pas notebooks/api/incremental_layer_v2.py, qui est
une copie parallèle pointant vers un autre dossier data/logs jamais
utilisé pour produire le correcteur actuel)

Usage :
    cd shieldmail_local      (le dossier qui contient notebooks/)
    python generate_balanced_corrections.py --n-per-class 60

Puis, pour appliquer réellement ces corrections au correcteur :
    cd notebooks
    python incremental_layer_v2.py --show     # vérifier ce qui est en attente
    python incremental_layer_v2.py --force    # réentraîner
    python incremental_layer_v2.py --eval     # comparer RF seul vs RF+correcteur
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
API_DIR = BASE_DIR / "notebooks" / "api"
DATA_DIR = BASE_DIR / "notebooks" / "data"
LOGS_DIR = BASE_DIR / "notebooks" / "logs"
FEEDBACK_FILE = LOGS_DIR / "feedback_verified.jsonl"

sys.path.insert(0, str(API_DIR))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-per-class", type=int, default=60,
                         help="Nombre de corrections à générer par classe (ham/spam/phishing)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    import joblib
    import pandas as pd
    import numpy as np
    from scipy.sparse import hstack, csr_matrix

    print("Chargement du corpus et du modèle réel...")
    df = pd.read_csv(DATA_DIR / "emails_features.csv")
    tfidf = joblib.load(DATA_DIR / "tfidf_vectorizer.pkl")
    rf = joblib.load(DATA_DIR / "best_model.pkl")
    le = joblib.load(DATA_DIR / "label_encoder.pkl")
    class_names = list(le.classes_)

    # --- Importer les VRAIES fonctions de feature-engineering du pipeline
    #     (pour rester identique à ce qui est utilisé en production) ---
    from pipeline_v2 import clean_text, extract_structural_features

    def predict_rf(texts):
        cleaned = [clean_text(t) for t in texts]
        X_tfidf = tfidf.transform(cleaned)
        struct_rows = []
        n_failed = 0
        for t in texts:
            try:
                struct_rows.append(list(extract_structural_features(t).values()))
            except Exception:
                # Texte contenant une URL malformée (ex. faux littéral IPv6)
                # qui fait planter urlparse() dans pipeline_v2.py. On ne
                # bloque pas tout le lot pour un seul email problématique :
                # vecteur de repli à zéro, l'email est quand même utilisable
                # pour le RF (qui se base surtout sur le TF-IDF).
                n_failed += 1
                struct_rows.append([0] * 20)
        if n_failed:
            print(f"    (avertissement : {n_failed} texte(s) avec URL malformée, "
                  f"features structurelles mises à zéro pour ces cas — voir note ci-dessous)")
        X_struct = csr_matrix(struct_rows)
        try:
            X = hstack([X_tfidf, X_struct])
            proba = rf.predict_proba(X)
        except Exception:
            proba = rf.predict_proba(X_tfidf)
        preds = [class_names[i] for i in proba.argmax(axis=1)]
        return preds

    rng = np.random.RandomState(args.seed)
    generated = []

    for cls in ["ham", "spam", "phishing"]:
        subset = df[df["label"] == cls]
        if len(subset) == 0:
            print(f"  ATTENTION : aucune ligne de classe '{cls}' trouvée dans le corpus, ignorée.")
            continue

        # On tire un échantillon plus large que n_per_class pour avoir de
        # quoi trouver de vraies erreurs RF à corriger en priorité.
        pool_size = min(len(subset), args.n_per_class * 8)
        pool = subset.sample(pool_size, random_state=args.seed)
        preds = predict_rf(pool["text"].tolist())
        pool = pool.assign(rf_pred=preds)

        wrong = pool[pool["rf_pred"] != cls]
        right = pool[pool["rf_pred"] == cls]

        n_wrong = min(len(wrong), args.n_per_class)
        n_right = max(0, args.n_per_class - n_wrong)

        chosen = pd.concat([
            wrong.sample(n_wrong, random_state=args.seed) if n_wrong > 0 else wrong.iloc[0:0],
            right.sample(min(n_right, len(right)), random_state=args.seed) if n_right > 0 else right.iloc[0:0],
        ])

        print(f"  {cls:10s} : {len(chosen)} corrections "
              f"({n_wrong} erreurs RF réelles corrigées + {len(chosen) - n_wrong} exemples de renforcement)")

        for _, row in chosen.iterrows():
            generated.append({
                "text": str(row["text"]),
                "label": cls,
                "predicted": row["rf_pred"],
                "source": "corpus_balanced",
                "confidence": None,
                "ts": datetime.now().isoformat(),
            })

    if not generated:
        print("Aucune correction générée — vérifie emails_features.csv.")
        return

    FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(FEEDBACK_FILE, "a", encoding="utf-8") as f:
        for g in generated:
            f.write(json.dumps(g, ensure_ascii=False) + "\n")

    from collections import Counter
    counts = Counter(g["label"] for g in generated)
    print(f"\n{len(generated)} corrections ajoutées à {FEEDBACK_FILE}")
    print(f"Répartition : {dict(counts)}")
    print("\nPour les appliquer réellement au correcteur :")
    print(f"  cd {BASE_DIR / 'notebooks'}")
    print("  python incremental_layer_v2.py --show")
    print("  python incremental_layer_v2.py --force")
    print("  python incremental_layer_v2.py --eval")


if __name__ == "__main__":
    main()
