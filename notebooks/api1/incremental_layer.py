# -*- coding: utf-8 -*-
"""
incremental_layer.py
====================
Couche d'apprentissage incremental par-dessus le Random Forest existant.

Principe :
  Random Forest (intact, jamais retouche)
       |
       v  probabilites [p_ham, p_phishing, p_spam]
  Correcteur SGD (LinearSVC incremental)
       |
       v  prediction finale corrigee

Le correcteur apprend uniquement des corrections utilisateur.
Il ne remplace pas RF, il le corrige sur les cas difficiles.

Usage :
  python incremental_layer.py --show      Voir corrections en attente
  python incremental_layer.py             Mettre a jour le correcteur
  python incremental_layer.py --reset     Remettre le correcteur a zero
  python incremental_layer.py --fix-compat Resoudre le warning sklearn
"""

import argparse
import json
import logging
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("incremental")

# Supprimer les warnings de version sklearn
warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR      = Path(__file__).parent
DATA_DIR      = BASE_DIR / "data"
LOGS_DIR      = BASE_DIR / "logs"
FEEDBACK_FILE = LOGS_DIR / "feedback_verified.jsonl"
CORRECTOR_PKL = DATA_DIR / "incremental_corrector.pkl"
BACKUP_DIR    = DATA_DIR / "backups"

for d in [LOGS_DIR, BACKUP_DIR]:
    d.mkdir(exist_ok=True)

CLASS_NAMES = ["ham", "phishing", "spam"]
LABEL2ID    = {c: i for i, c in enumerate(CLASS_NAMES)}
MIN_CORRECTIONS = 10  # Minimum pour declencher une mise a jour


# ══════════════════════════════════════════════════════════════════
# 1. CHARGEMENT DES MODELES EXISTANTS (sans les modifier)
# ══════════════════════════════════════════════════════════════════

def load_base_models():
    """
    Charge Random Forest et les preprocesseurs SANS LES MODIFIER.
    Le warning sklearn est attendu (version 1.6.1 -> 1.8.0) et inoffensif
    pour la prediction.
    """
    import joblib

    logger.info("Chargement Random Forest (intact)...")
    rf_model      = joblib.load(DATA_DIR / "best_model.pkl")
    tfidf         = joblib.load(DATA_DIR / "tfidf_vectorizer.pkl")
    label_encoder = joblib.load(DATA_DIR / "label_encoder.pkl")

    logger.info(f"  Modele : {type(rf_model).__name__}")
    logger.info(f"  Classes : {label_encoder.classes_}")
    logger.info(f"  Estimateurs RF : {rf_model.n_estimators}")

    return rf_model, tfidf, label_encoder


# ══════════════════════════════════════════════════════════════════
# 2. RESOLUTION DU WARNING SKLEARN (optionnel mais propre)
# ══════════════════════════════════════════════════════════════════

def fix_sklearn_compat():
    """
    Recharge et resauvegarde les modeles avec la version sklearn actuelle.
    Elimine le InconsistentVersionWarning sans retoucher les poids.
    """
    import joblib

    logger.info("Correction compatibilite sklearn...")
    files = [
        DATA_DIR / "best_model.pkl",
        DATA_DIR / "tfidf_vectorizer.pkl",
        DATA_DIR / "label_encoder.pkl",
    ]
    for f in files:
        if not f.exists():
            logger.warning(f"Fichier manquant : {f}")
            continue
        # Backup
        backup = BACKUP_DIR / f"{f.stem}_v1.6.1_backup{f.suffix}"
        if not backup.exists():
            import shutil
            shutil.copy2(f, backup)
            logger.info(f"  Backup : {backup.name}")
        # Recharger et resauvegarder avec sklearn actuel
        obj = joblib.load(f)
        joblib.dump(obj, f, compress=3)
        logger.info(f"  Mis a jour : {f.name}")

    logger.info("Warning sklearn resolu. Relancer l'API.")


# ══════════════════════════════════════════════════════════════════
# 3. PREPARATION DES FEATURES POUR LE CORRECTEUR
# ══════════════════════════════════════════════════════════════════

def prepare_corrector_features(texts, rf_model, tfidf, label_encoder):
    """
    Cree les features d'entree pour le correcteur :
    - Probabilites RF (3 valeurs) — sortie du modele existant
    - TF-IDF reduit (top 500 features) — contexte textuel
    - Features structurelles legeres (5 valeurs)

    Total : 3 + 500 + 5 = 508 features par email.
    """
    import re
    import html as html_lib
    from scipy.sparse import hstack, csr_matrix
    from urllib.parse import urlparse

    # Nettoyage minimal
    def quick_clean(text):
        text = html_lib.unescape(str(text))
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'https?://\S+', ' urltoken ', text)
        text = text.lower()
        return text

    cleaned = [quick_clean(t) for t in texts]

    # Features structurelles completes (identiques a l'entrainement NB02)
    BLACKLISTED_TLDS = {'xyz','info','biz','club','online','site','top','win',
                        'gq','tk','ml','ga','cf','pw','cc','ws','icu','live'}
    BRANDS = ['paypal','amazon','microsoft','apple','google','netflix','facebook']

    def full_struct_feats(text):
        urls  = re.findall(r'https?://[^\s<>"]+', text)
        words = text.split()
        alpha = [c for c in text if c.isalpha()]
        ip_url   = sum(1 for u in urls if re.search(r'https?://\d{1,3}\.\d{1,3}', u))
        susp_tld = sum(1 for u in urls
                       if urlparse(u).netloc.rsplit('.',1)[-1] in BLACKLISTED_TLDS)
        brand    = sum(1 for u in urls for b in BRANDS if b in u.lower())
        return [
            len(urls),
            int(ip_url > 0),
            int(susp_tld > 0),
            int(brand > 0),
            max((len(u) for u in urls), default=0),
            float(np.mean([len(u) for u in urls])) if urls else 0.0,
            float(np.mean([urlparse(u).netloc.count('.')-1 for u in urls])) if urls else 0.0,
            int(any('@' in u for u in urls)),
            sum(c.isdigit() for u in urls for c in u)/max(sum(len(u) for u in urls),1),
            sum(len(re.findall(r'[%@#!$&*]', u)) for u in urls),
            len(text),
            len(words),
            text.count('!'),
            text.count('?'),
            text.count('$'),
            sum(1 for c in alpha if c.isupper())/max(len(alpha),1),
            sum(c.isdigit() for c in text)/max(len(text),1),
            int(bool(re.search(r'<[a-zA-Z][^>]*>', text))),
            float(np.mean([len(w) for w in words])) if words else 0.0,
            len(set(words))/max(len(words),1),
        ]

    # X complet pour RF (TF-IDF + 20 features structurelles = 10020)
    X_tfidf_full = tfidf.transform(cleaned)
    X_struct_full = csr_matrix([full_struct_feats(t) for t in texts])
    X_for_rf = hstack([X_tfidf_full, X_struct_full])

    # Prediction RF avec le bon nombre de features
    rf_proba = rf_model.predict_proba(X_for_rf)  # (n, 3)

    # TF-IDF reduit : top 500 features par variance
    # (evite de trop charger la memoire)
    if X_tfidf_full.shape[1] > 500:
        variances = np.asarray(X_tfidf_full.power(2).mean(axis=0)).flatten()
        top500 = np.argsort(variances)[-500:]
        X_tfidf_small = X_tfidf_full[:, top500]
    else:
        X_tfidf_small = X_tfidf_full

    # Features structurelles legeres
    def struct_feats(text):
        urls = re.findall(r'https?://', text)
        words = text.split()
        alpha = [c for c in text if c.isalpha()]
        return [
            len(urls),
            text.count('!'),
            sum(1 for c in alpha if c.isupper()) / max(len(alpha), 1),
            int(bool(re.search(r'https?://\d{1,3}\.\d{1,3}', text))),
            len(words),
        ]

    X_struct = csr_matrix([struct_feats(t) for t in texts])

    # Concatenation : proba RF + TF-IDF + struct
    X_rf_proba = csr_matrix(rf_proba)
    X = hstack([X_rf_proba, X_tfidf_small, X_struct])

    return X


# ══════════════════════════════════════════════════════════════════
# 4. LE CORRECTEUR INCREMENTAL (SGDClassifier)
# ══════════════════════════════════════════════════════════════════

def load_corrector():
    """
    Charge le correcteur existant ou en cree un nouveau.
    SGDClassifier supporte partial_fit() — mise a jour sans tout reapprendre.
    """
    import joblib
    from sklearn.linear_model import SGDClassifier

    if CORRECTOR_PKL.exists():
        corrector = joblib.load(CORRECTOR_PKL)
        logger.info(f"Correcteur charge : {CORRECTOR_PKL.name}")
        if hasattr(corrector, 'n_iter_'):
            logger.info(f"  Iterations passees : {corrector.n_iter_}")
    else:
        # Premier lancement : correcteur vierge
        corrector = SGDClassifier(
            loss="modified_huber",  # Donne des probabilites
            alpha=0.001,            # Regularisation legere
            max_iter=100,
            tol=1e-4,
            random_state=42,
            # class_weight="balanced" incompatible avec partial_fit
        )
        logger.info("Nouveau correcteur cree (SGDClassifier).")

    return corrector


def save_corrector(corrector):
    import joblib
    # Backup si existant
    if CORRECTOR_PKL.exists():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = BACKUP_DIR / f"incremental_corrector_{ts}.pkl"
        import shutil
        shutil.copy2(CORRECTOR_PKL, backup)

    joblib.dump(corrector, CORRECTOR_PKL, compress=3)
    logger.info(f"Correcteur sauvegarde : {CORRECTOR_PKL}")


# ══════════════════════════════════════════════════════════════════
# 5. CHARGEMENT DES CORRECTIONS UTILISATEUR
# ══════════════════════════════════════════════════════════════════

def load_corrections():
    if not FEEDBACK_FILE.exists():
        return []
    corrections = []
    with open(FEEDBACK_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                entry = json.loads(line)
                if (entry.get("source") == "user_feedback"
                        and entry.get("text")
                        and entry.get("label") in CLASS_NAMES):
                    corrections.append(entry)
            except json.JSONDecodeError:
                pass
    return corrections


def mark_done(corrections):
    done_path = LOGS_DIR / "feedback_applied.jsonl"
    with open(done_path, "a", encoding="utf-8") as f:
        for c in corrections:
            c["applied_at"] = datetime.now().isoformat()
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    # Vider le fichier en attente
    FEEDBACK_FILE.write_text("", encoding="utf-8")
    logger.info(f"{len(corrections)} corrections marquees appliquees.")


# ══════════════════════════════════════════════════════════════════
# 6. MISE A JOUR INCREMENTALE
# ══════════════════════════════════════════════════════════════════

def update_corrector(corrections, rf_model, tfidf, label_encoder, force=False):
    """
    Met a jour le correcteur avec partial_fit() — uniquement les nouvelles corrections.
    Random Forest n'est PAS modifie.
    """
    from sklearn.metrics import f1_score, classification_report

    if len(corrections) < MIN_CORRECTIONS and not force:
        logger.info(f"Corrections : {len(corrections)} / {MIN_CORRECTIONS} minimum.")
        logger.info("Utiliser --force pour appliquer quand meme.")
        return False

    texts  = [c["text"]  for c in corrections]
    labels = [c["label"] for c in corrections]

    logger.info(f"Preparation des features ({len(texts)} corrections)...")
    X = prepare_corrector_features(texts, rf_model, tfidf, label_encoder)
    y = np.array([LABEL2ID[l] for l in labels])

    corrector = load_corrector()

    # Calcul manuel des poids de classe (remplace class_weight="balanced")
    from sklearn.utils.class_weight import compute_class_weight
    classes_present = list(range(len(CLASS_NAMES)))
    try:
        weights = compute_class_weight("balanced", classes=classes_present, y=y)
        sample_weight = np.array([weights[yi] for yi in y])
    except Exception:
        sample_weight = None

    # partial_fit() : UNIQUEMENT les nouvelles donnees, pas de reentrain. complet
    logger.info("Mise a jour incrementale (partial_fit)...")
    if sample_weight is not None:
        corrector.partial_fit(X, y, classes=classes_present, sample_weight=sample_weight)
    else:
        corrector.partial_fit(X, y, classes=classes_present)

    # Evaluation rapide
    y_pred = corrector.predict(X)
    f1 = f1_score(y, y_pred, average="macro", zero_division=0)
    logger.info(f"F1-Macro sur corrections : {f1:.4f}")
    # labels= pour ne rapporter que les classes presentes dans y
    present = sorted(set(y))
    logger.info(classification_report(
        y, y_pred,
        labels=present,
        target_names=[CLASS_NAMES[i] for i in present],
        zero_division=0
    ))

    save_corrector(corrector)
    mark_done(corrections)

    logger.info("\nMise a jour terminee. Redemarrer l'API pour prendre en compte.")
    return True


# ══════════════════════════════════════════════════════════════════
# 7. CLASSE PIPELINE CORRIGE (pour api/pipeline.py)
# ══════════════════════════════════════════════════════════════════

PIPELINE_PATCH = '''
# ── A ajouter dans api/pipeline.py ────────────────────────────────
# Apres le chargement de best_model.pkl, charger le correcteur :

from pathlib import Path as _Path
import joblib as _joblib
import numpy as np

_CORRECTOR_PATH = _Path(__file__).parent.parent / "data" / "incremental_corrector.pkl"

def load_corrector():
    if _CORRECTOR_PATH.exists():
        return _joblib.load(_CORRECTOR_PATH)
    return None

# Dans la methode analyze() du pipeline, apres la prediction ML :
# (remplacer la prediction simple par la prediction corrigee)

def predict_with_corrector(text, rf_model, tfidf, corrector, class_names):
    """
    Prediction avec couche correctrice.
    Si pas de correcteur : utilise RF seul.
    Si correcteur disponible : fusionne RF + correcteur.
    """
    import re, html
    from scipy.sparse import hstack, csr_matrix

    def quick_clean(t):
        t = html.unescape(str(t))
        t = re.sub(r\'<[^>]+>\', \' \', t)
        t = re.sub(r\'https?://\\S+\', \' urltoken \', t)
        return t.lower()

    cleaned = quick_clean(text)
    X_full  = tfidf.transform([cleaned])

    # Prediction RF (base)
    rf_proba = rf_model.predict_proba(X_full)[0]  # [p_ham, p_phish, p_spam]

    if corrector is None:
        pred_idx = np.argmax(rf_proba)
        return class_names[pred_idx], float(rf_proba[pred_idx]), rf_proba

    # Features pour le correcteur
    if X_full.shape[1] > 500:
        variances = np.asarray(X_full.power(2).mean(axis=0)).flatten()
        top500 = np.argsort(variances)[-500:]
        X_small = X_full[:, top500]
    else:
        X_small = X_full

    urls  = len(re.findall(r\'https?://\', text))
    alpha = [c for c in text if c.isalpha()]
    struct = [urls, text.count(\'!\'),
              sum(1 for c in alpha if c.isupper())/max(len(alpha),1),
              int(bool(re.search(r\'https?://\\d{1,3}\\.\\d{1,3}\', text))),
              len(text.split())]
    X_struct = csr_matrix([struct])
    X_corr   = hstack([csr_matrix([rf_proba]), X_small, X_struct])

    # Probabilites du correcteur
    if hasattr(corrector, \'predict_proba\'):
        corr_proba = corrector.predict_proba(X_corr)[0]
    else:
        corr_proba = rf_proba  # Fallback si pas de proba

    # Fusion : RF 60% + correcteur 40%
    # (le correcteur a plus de poids quand sa confiance est elevee)
    corr_conf = float(corr_proba.max())
    w_corr    = 0.4 * corr_conf   # Poids dynamique selon confiance
    w_rf      = 1.0 - w_corr

    final_proba = w_rf * rf_proba + w_corr * corr_proba
    final_proba = final_proba / final_proba.sum()

    pred_idx = int(np.argmax(final_proba))
    return class_names[pred_idx], float(final_proba[pred_idx]), final_proba
'''


# ══════════════════════════════════════════════════════════════════
# 8. POINT D'ENTREE
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Couche d'apprentissage incremental par-dessus Random Forest"
    )
    parser.add_argument("--show",       action="store_true",
                        help="Afficher les corrections en attente")
    parser.add_argument("--force",      action="store_true",
                        help="Forcer meme avec peu de corrections")
    parser.add_argument("--reset",      action="store_true",
                        help="Remettre le correcteur a zero")
    parser.add_argument("--fix-compat", action="store_true",
                        help="Resoudre le warning sklearn 1.6.1→1.8.0")
    parser.add_argument("--show-patch", action="store_true",
                        help="Afficher le patch a appliquer dans api/pipeline.py")
    args = parser.parse_args()

    if args.fix_compat:
        fix_sklearn_compat()
        return

    if args.show_patch:
        print(PIPELINE_PATCH)
        return

    if args.reset:
        if CORRECTOR_PKL.exists():
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = BACKUP_DIR / f"incremental_corrector_RESET_{ts}.pkl"
            import shutil
            shutil.copy2(CORRECTOR_PKL, backup)
            CORRECTOR_PKL.unlink()
            logger.info(f"Correcteur remis a zero. Backup : {backup.name}")
        else:
            logger.info("Pas de correcteur existant.")
        return

    corrections = load_corrections()

    if args.show:
        from collections import Counter
        print(f"\nCorrections en attente : {len(corrections)}")
        if corrections:
            labels = Counter(c["label"] for c in corrections)
            preds  = Counter(c.get("predicted","?") for c in corrections)
            print("Labels corriges :")
            for k,v in labels.most_common(): print(f"  {k:12s} : {v}")
            print("Predictions erronees :")
            for k,v in preds.most_common(): print(f"  {k:12s} : {v}")
        print(f"\nCorrecteur existant : {CORRECTOR_PKL.exists()}")
        print(f"Seuil minimum       : {MIN_CORRECTIONS}")
        return

    if not corrections:
        logger.info("Aucune correction. Corriger des emails via l'extension Chrome.")
        logger.info("Les corrections arrivent via POST /feedback → logs/feedback_verified.jsonl")
        return

    logger.info(f"Chargement des modeles...")
    rf_model, tfidf, label_encoder = load_base_models()

    update_corrector(corrections, rf_model, tfidf, label_encoder, args.force)


if __name__ == "__main__":
    main()
