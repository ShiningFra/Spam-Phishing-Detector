"""
reduce_epochs_patch.py
=======================
Réduit N_EPOCHS de 15 à 3 dans update_corrector_v2() — maintenant que les
features sont normalisées (patch précédent), le gradient converge
beaucoup plus vite, et 15 passes sur un petit lot de corrections mène au
surapprentissage plutôt qu'à un meilleur entraînement (signe : F1=1.0000
sur l'entraînement, mais un F1-Macro qui se dégrade sur le vrai test set).

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks
    python reduce_epochs_patch.py
"""

from pathlib import Path

TARGET = Path(__file__).parent / "incremental_layer_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/")

src = TARGET.read_text(encoding="utf-8")

old = "N_EPOCHS = 15"
new = "N_EPOCHS = 3"

count = src.count(old)
if count == 0:
    raise SystemExit("'N_EPOCHS = 15' introuvable — le fichier a peut-être déjà été modifié.")
if count > 1:
    raise SystemExit(f"'N_EPOCHS = 15' trouvé {count} fois — ambigu, n'a rien changé.")

src = src.replace(old, new)

import shutil
backup = TARGET.with_suffix(".py.bak6")
shutil.copy2(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print("Patch appliqué : N_EPOCHS 15 -> 3")
print(f"Sauvegarde de l'original : {backup}")
