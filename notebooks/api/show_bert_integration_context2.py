"""
show_bert_integration_context2.py
===================================
Complète l'extraction précédente : la suite de analyze() (au-delà de la
ligne 1005, coupée par erreur la fois précédente), et la vraie classe
AdaptiveWeights (la recherche précédente avait affiché un commentaire
qui la mentionne, pas sa définition réelle).

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python show_bert_integration_context2.py
"""

import re
from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"
lines = TARGET.read_text(encoding="utf-8").splitlines()

out_path = Path(__file__).parent / "bert_integration_context2.txt"
with open(out_path, "w", encoding="utf-8") as f:
    f.write(f"=== {TARGET} ===\n\n")

    # 1) La suite de analyze() : de la ligne 1000 (0-indexé 999) à 200 lignes
    #    plus loin, pour être large et ne rien couper cette fois.
    start = 999
    end = min(len(lines), start + 200)
    f.write(f"--- suite de analyze() (lignes {start+1} à {end}) ---\n")
    for j in range(start, end):
        f.write(f"{j+1:5d} | {repr(lines[j])}\n")
    f.write("\n")

    # 2) La vraie classe AdaptiveWeights (définition explicite, pas une
    #    simple mention dans un commentaire ou docstring).
    found = False
    for i, l in enumerate(lines):
        if re.match(r'\s*class AdaptiveWeights\b', l):
            found = True
            base_indent = len(l) - len(l.lstrip())
            end_idx = len(lines)
            for k in range(i + 1, len(lines)):
                ln = lines[k]
                if ln.strip() == "":
                    continue
                indent = len(ln) - len(ln.lstrip())
                if indent <= base_indent:
                    end_idx = k
                    break
            f.write(f"--- class AdaptiveWeights (lignes {i+1} à {end_idx}) ---\n")
            for j in range(i, end_idx):
                f.write(f"{j+1:5d} | {repr(lines[j])}\n")
            f.write("\n")
            break
    if not found:
        f.write("--- class AdaptiveWeights : NON TROUVÉE (peut-être un autre nom) ---\n\n")
        # Filet de sécurité : montrer toutes les lignes contenant "weights.compute" ou ".compute("
        for i, l in enumerate(lines):
            if "_adapt_weights" in l or "def compute(" in l:
                start2 = max(0, i - 2)
                end2 = min(len(lines), i + 20)
                f.write(f"--- indice autour de la ligne {i+1} ---\n")
                for j in range(start2, end2):
                    f.write(f"{j+1:5d} | {repr(lines[j])}\n")
                f.write("\n")

print(f"Écrit : {out_path}")
print("Upload ce fichier dans le chat.")
