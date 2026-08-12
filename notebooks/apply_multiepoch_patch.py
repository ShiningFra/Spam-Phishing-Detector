"""
apply_multiepoch_patch.py
==========================
Remplace l'unique appel partial_fit() par une boucle de plusieurs passes,
directement dans notebooks/incremental_layer_v2.py — sans risque d'erreur
d'indentation puisque l'indentation d'origine est détectée automatiquement
et réutilisée pour le nouveau bloc.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks
    python apply_multiepoch_patch.py

Le script fait une sauvegarde (incremental_layer_v2.py.bak) avant de
toucher au fichier. S'il ne trouve pas le bloc attendu (fichier déjà
modifié différemment), il ne touche à rien et l'explique.
"""

import re
import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "incremental_layer_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/")

src = TARGET.read_text(encoding="utf-8")

# On cherche le bloc "logger.info(...partial_fit...)" suivi de l'appel
# corrector.partial_fit(...) sur un seul passage, en capturant précisément
# l'indentation utilisée dans LE FICHIER RÉEL (peu importe qu'il utilise
# des tabulations ou 4/8 espaces — on la récupère telle quelle).
pattern = re.compile(
    r'(?P<indent>[ \t]*)logger\.info\("Mise à jour incrémentale \(partial_fit\)\.\.\."\)\n'
    r'(?P=indent)corrector\.partial_fit\(\n'
    r'(?P<body_indent>[ \t]*)X, y,\n'
    r'(?P=body_indent)classes=classes_present,\n'
    r'(?P=body_indent)sample_weight=sample_weight,\n'
    r'(?P=indent)\)\n'
)

m = pattern.search(src)
if not m:
    raise SystemExit(
        "Bloc attendu introuvable — le fichier a peut-être déjà été modifié "
        "manuellement d'une façon qui ne correspond plus exactement au texte "
        "recherché. N'a rien changé. Colle-moi les ~15 lignes autour de "
        "'partial_fit' (avec les espaces, copiées depuis un éditeur comme "
        "VS Code plutôt que le terminal) et je fais le patch à la main."
    )

indent = m.group("indent")
body_indent = m.group("body_indent")

replacement = (
    f'{indent}logger.info("Mise à jour incrémentale (partial_fit, plusieurs passes)...")\n'
    f'{indent}N_EPOCHS = 15\n'
    f'{indent}rng = np.random.RandomState(42)\n'
    f'{indent}for _epoch in range(N_EPOCHS):\n'
    f'{indent}{body_indent[:len(body_indent)] if body_indent else "    "}_idx = rng.permutation(X.shape[0])\n'
    f'{indent}{body_indent}corrector.partial_fit(\n'
    f'{indent}{body_indent}{body_indent}X[_idx], y[_idx],\n'
    f'{indent}{body_indent}{body_indent}classes=classes_present,\n'
    f'{indent}{body_indent}{body_indent}sample_weight=sample_weight[_idx] if sample_weight is not None else None,\n'
    f'{indent}{body_indent})\n'
    f'{indent}logger.info(f"Entraînement terminé ({{N_EPOCHS}} passes).")\n'
)

new_src = src[:m.start()] + replacement + src[m.end():]

backup = TARGET.with_suffix(".py.bak")
shutil.copy2(TARGET, backup)
TARGET.write_text(new_src, encoding="utf-8")

print(f"Patch appliqué avec succès.")
print(f"Sauvegarde de l'original : {backup}")
print(f"Indentation détectée et réutilisée : {len(indent)} caractère(s)")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
