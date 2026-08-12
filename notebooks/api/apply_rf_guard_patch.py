"""
apply_rf_guard_patch.py
========================
Ajoute la garde de protection dans _apply_corrector() de pipeline_v2.py :
si le Random Forest est déjà très confiant sur 'phishing', le correcteur
ne peut plus écraser ce signal, quelle que soit sa propre confiance.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python apply_rf_guard_patch.py

Sauvegarde automatique (pipeline_v2.py.bak) avant modification. Si le
bloc attendu n'est pas trouvé, ne touche à rien et l'explique.
"""

import re
import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/api/")

src = TARGET.read_text(encoding="utf-8")

pattern = re.compile(
    r'(?P<indent>[ \t]*)w_rf[ \t]*= 1\.0 - w_corr\n'
    r'(?P=indent)final = w_rf \* rf_proba \+ w_corr \* corr_proba\n'
)

m = pattern.search(src)
if not m:
    raise SystemExit(
        "Bloc attendu introuvable (recherché : 'w_rf = 1.0 - w_corr' suivi de "
        "'final = w_rf * rf_proba + w_corr * corr_proba'). Le fichier a peut-être "
        "déjà été modifié. N'a rien changé. Colle-moi les ~20 lignes autour de "
        "'w_corr' dans _apply_corrector() (depuis un éditeur, pas le terminal) "
        "et je fais le patch à la main."
    )

if "Protection RF phishing" in src:
    raise SystemExit("La garde de protection semble déjà présente dans ce fichier — rien à faire.")

indent = m.group("indent")

guard = (
    f'{indent}# Garde de protection : si le RF est déjà très confiant sur phishing,\n'
    f'{indent}# le correcteur ne doit pas pouvoir écraser ce signal — tant qu\'il n\'a\n'
    f'{indent}# pas reçu un volume suffisant de vraies corrections phishing bien\n'
    f'{indent}# calibrées, son jugement sur cette classe reste structurellement\n'
    f'{indent}# moins fiable que celui du RF seul.\n'
    f'{indent}rf_phish_idx = class_names.index(\'phishing\') if \'phishing\' in class_names else None\n'
    f'{indent}if rf_phish_idx is not None and rf_proba[rf_phish_idx] > 0.70:\n'
    f'{indent}    w_corr = min(w_corr, 0.15)\n'
    f'{indent}    logger.debug(f"Protection RF phishing activée (w_corr plafonné à {{w_corr:.2f}})")\n'
    f'\n'
)

new_src = src[:m.start()] + guard + src[m.start():]

backup = TARGET.with_suffix(".py.bak2")
shutil.copy2(TARGET, backup)
TARGET.write_text(new_src, encoding="utf-8")

print("Patch appliqué avec succès.")
print(f"Sauvegarde de l'original : {backup}")
print(f"Indentation détectée et réutilisée : {len(indent)} caractère(s)")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
