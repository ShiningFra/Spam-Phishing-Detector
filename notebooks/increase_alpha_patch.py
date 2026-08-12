"""
increase_alpha_patch.py
=========================
Augmente alpha (force de régularisation L2) de 0.001 à 0.1 dans les deux
instanciations de SGDClassifier (load_corrector() et le bloc de migration
de update_corrector_v2()) — pour empêcher le correcteur de mémoriser un
petit lot de corrections dans un espace à 523 dimensions, comme le
montrait le F1=1.0000 systématique sur l'entraînement quel que soit le
nombre de passes.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks
    python increase_alpha_patch.py
"""

import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "incremental_layer_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/")

src = TARGET.read_text(encoding="utf-8")

old = "alpha=0.001"
new = "alpha=0.1"

count = src.count(old)
if count != 2:
    raise SystemExit(
        f"'{old}' trouvé {count} fois (2 attendues, une par instanciation de "
        f"SGDClassifier). N'a rien changé — le fichier a peut-être déjà été "
        f"modifié différemment entre-temps."
    )

src = src.replace(old, new)

backup = TARGET.with_suffix(".py.bak7")
shutil.copy2(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print(f"Patch appliqué : alpha=0.001 -> alpha=0.1 ({count} occurrences)")
print(f"Sauvegarde de l'original : {backup}")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
