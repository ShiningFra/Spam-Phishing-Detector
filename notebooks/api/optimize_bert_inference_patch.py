"""
optimize_bert_inference_patch.py
==================================
Deux optimisations sans risque sur _predict_bert() (pipeline_v2.py) :
  1. padding=True (dynamique) au lieu de padding='max_length' (256 tokens
     fixes) — un email court n'est plus artificiellement complété à 256
     tokens à chaque appel, ce qui réduit le calcul proportionnellement
     à la longueur réelle du texte plutôt qu'à un maximum fixe.
  2. torch.inference_mode() au lieu de torch.no_grad() — légèrement plus
     rapide, désactive un peu plus de mécanique de calcul de gradient
     inutile en pure inférence.

Aucun changement de comportement/précision : le modèle produit les
mêmes prédictions, juste plus vite.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python optimize_bert_inference_patch.py
"""

import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/api/")

src = TARGET.read_text(encoding="utf-8")

old = (
    "        with torch.no_grad():\n"
    "            encoding = self._bert_tokenizer(\n"
    "                text[:2000], max_length=256, padding='max_length',\n"
    "                truncation=True, return_tensors='pt',\n"
    "            )\n"
)

count = src.count(old)
if count == 0:
    raise SystemExit(
        "Bloc _predict_bert introuvable tel qu'attendu — le patch BERT "
        "(apply_bert_integration_patch.py) a-t-il bien été appliqué avant "
        "celui-ci ? N'a rien changé."
    )
if count > 1:
    raise SystemExit(f"Bloc trouvé {count} fois — ambigu, n'a rien changé.")

new = (
    "        with torch.inference_mode():\n"
    "            encoding = self._bert_tokenizer(\n"
    "                text[:2000], max_length=256, padding=True,\n"
    "                truncation=True, return_tensors='pt',\n"
    "            )\n"
)

src = src.replace(old, new, 1)

backup = TARGET.with_suffix(".py.bak10")
shutil.copy2(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print("Patch appliqué : padding dynamique + inference_mode.")
print(f"Sauvegarde de l'original : {backup}")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
