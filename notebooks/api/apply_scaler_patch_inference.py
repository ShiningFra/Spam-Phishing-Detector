"""
apply_scaler_patch_inference.py
=================================
Fait charger et appliquer le MÊME normaliseur (corrector_feature_scaler.pkl)
côté inférence, dans _build_corrector_input() de notebooks/api/pipeline_v2.py
— uniquement pour la branche 523 features (le format v2 actuellement actif).
Les branches 508/503/fallback, qui ne servent qu'à la compatibilité
ascendante avec d'anciens correcteurs, ne sont pas touchées.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python apply_scaler_patch_inference.py

À exécuter APRÈS fit_feature_scaler.py et après
apply_scaler_patch_training.py (le normaliseur doit déjà exister sur
disque, et le format d'entraînement doit déjà être cohérent).
"""

import re
import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/api/")

src = TARGET.read_text(encoding="utf-8")

if "_load_feature_scaler" in src:
    raise SystemExit("Le patch du normaliseur semble déjà appliqué — rien à faire.")

pattern = re.compile(
    r"(?P<indent>[ \t]*)if n_expected == 523:\n"
    r"(?P<indent2>[ \t]*)# v2 : struct complètes \(20\)\n"
    r"(?P=indent2)X_struct = csr_matrix\(\[struct_values\]\)\n"
    r"(?P=indent2)return hstack\(\[csr_matrix\(\[rf_proba\]\), X_small, X_struct\]\)\n"
)

m = pattern.search(src)
if not m:
    raise SystemExit(
        "Bloc attendu introuvable dans _build_corrector_input(). N'a rien changé. "
        "Le fichier a peut-être déjà été modifié différemment."
    )

indent = m.group("indent")
indent2 = m.group("indent2")

replacement = (
    f'{indent}if n_expected == 523:\n'
    f'{indent2}# v2 : struct complètes (20)\n'
    f'{indent2}X_struct = csr_matrix([struct_values])\n'
    f'{indent2}X_corr_523 = hstack([csr_matrix([rf_proba]), X_small, X_struct])\n'
    f'{indent2}# Même normaliseur que côté entraînement (fit_feature_scaler.py) —\n'
    f'{indent2}# indispensable pour que le correcteur reçoive des features à la\n'
    f'{indent2}# même échelle qu\'au moment de son partial_fit().\n'
    f'{indent2}scaler = _load_feature_scaler()\n'
    f'{indent2}if scaler is not None:\n'
    f'{indent2}    X_corr_523 = scaler.transform(X_corr_523)\n'
    f'{indent2}return X_corr_523\n'
)

new_src = src[:m.start()] + replacement + src[m.end():]

# Ajouter _load_feature_scaler() juste avant _build_corrector_input
helper = (
    '_FEATURE_SCALER_CACHE = None\n'
    '\n'
    'def _load_feature_scaler():\n'
    '    """Charge (et met en cache) le normaliseur ajusté par fit_feature_scaler.py."""\n'
    '    global _FEATURE_SCALER_CACHE\n'
    '    if _FEATURE_SCALER_CACHE is not None:\n'
    '        return _FEATURE_SCALER_CACHE\n'
    '    scaler_path = DATA_DIR / "corrector_feature_scaler.pkl"\n'
    '    if scaler_path.exists():\n'
    '        try:\n'
    '            _FEATURE_SCALER_CACHE = joblib.load(scaler_path)\n'
    '            logger.info("Normaliseur de features chargé.")\n'
    '        except Exception as e:\n'
    '            logger.warning(f"Normaliseur non chargé : {e}")\n'
    '            _FEATURE_SCALER_CACHE = None\n'
    '    return _FEATURE_SCALER_CACHE\n'
    '\n'
    '\n'
)

def_marker = "def _build_corrector_input(rf_proba, X_small, struct_feats: dict,"
idx = new_src.index(def_marker)
new_src = new_src[:idx] + helper + new_src[idx:]

backup = TARGET.with_suffix(".py.bak4")
shutil.copy2(TARGET, backup)
TARGET.write_text(new_src, encoding="utf-8")

print("Patch appliqué avec succès.")
print(f"Sauvegarde de l'original : {backup}")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
