"""
apply_scaler_patch_training.py
================================
Fait charger et appliquer le normaliseur (corrector_feature_scaler.pkl,
ajusté au préalable par fit_feature_scaler.py) dans prepare_features_v2(),
côté entraînement (notebooks/incremental_layer_v2.py).

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks
    python apply_scaler_patch_training.py

À exécuter APRÈS fit_feature_scaler.py (qui doit avoir déjà produit
notebooks/data/corrector_feature_scaler.pkl).
"""

import re
import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "incremental_layer_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/")

src = TARGET.read_text(encoding="utf-8")

if "_load_feature_scaler" in src:
    raise SystemExit("Le patch du normaliseur semble déjà appliqué — rien à faire.")

pattern = re.compile(
    r'(?P<indent>[ \t]*)X = hstack\(\[csr_matrix\(rf_proba\), X_tfidf_small, X_struct\]\)\n'
    r'(?P=indent)return X, rf_proba\n'
)

m = pattern.search(src)
if not m:
    raise SystemExit(
        "Bloc attendu introuvable dans prepare_features_v2(). N'a rien changé. "
        "Le fichier a peut-être déjà été modifié différemment."
    )

indent = m.group("indent")

replacement = (
    f'{indent}X = hstack([csr_matrix(rf_proba), X_tfidf_small, X_struct])\n'
    f'\n'
    f'{indent}# Normalisation : indispensable pour SGDClassifier, dont la\n'
    f'{indent}# descente de gradient est dominée par les colonnes à grande\n'
    f'{indent}# échelle (char_count, word_count...) sans elle. Le normaliseur\n'
    f'{indent}# est ajusté une seule fois (fit_feature_scaler.py) et rechargé\n'
    f'{indent}# ici tel quel, pour rester cohérent entre les mises à jour\n'
    f'{indent}# successives du correcteur.\n'
    f'{indent}scaler = _load_feature_scaler()\n'
    f'{indent}if scaler is not None:\n'
    f'{indent}    X = scaler.transform(X)\n'
    f'\n'
    f'{indent}return X, rf_proba\n'
)

new_src = src[:m.start()] + replacement + src[m.end():]

# Ajouter la fonction _load_feature_scaler() juste avant prepare_features_v2
helper = (
    'import joblib as _joblib_scaler\n'
    '_FEATURE_SCALER_CACHE = None\n'
    '_FEATURE_SCALER_PATH = Path(__file__).parent / "data" / "corrector_feature_scaler.pkl"\n'
    '\n'
    'def _load_feature_scaler():\n'
    '    """Charge (et met en cache) le normaliseur ajusté par fit_feature_scaler.py."""\n'
    '    global _FEATURE_SCALER_CACHE\n'
    '    if _FEATURE_SCALER_CACHE is not None:\n'
    '        return _FEATURE_SCALER_CACHE\n'
    '    if _FEATURE_SCALER_PATH.exists():\n'
    '        try:\n'
    '            _FEATURE_SCALER_CACHE = _joblib_scaler.load(_FEATURE_SCALER_PATH)\n'
    '            logger.info("Normaliseur de features chargé.")\n'
    '        except Exception as e:\n'
    '            logger.warning(f"Normaliseur non chargé : {e}")\n'
    '            _FEATURE_SCALER_CACHE = None\n'
    '    return _FEATURE_SCALER_CACHE\n'
    '\n'
    '\n'
)

def_marker = "def prepare_features_v2(texts, rf_model, tfidf):"
idx = new_src.index(def_marker)
new_src = new_src[:idx] + helper + new_src[idx:]

if "from pathlib import Path" not in new_src.split(def_marker)[0]:
    new_src = "from pathlib import Path\n" + new_src

backup = TARGET.with_suffix(".py.bak3")
shutil.copy2(TARGET, backup)
TARGET.write_text(new_src, encoding="utf-8")

print("Patch appliqué avec succès.")
print(f"Sauvegarde de l'original : {backup}")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
