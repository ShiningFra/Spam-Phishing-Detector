"""
show_corrector_context.py
==========================
Affiche les lignes autour de 'w_corr' dans pipeline_v2.py, avec leurs
numéros, pour que le contexte exact (espaces compris) puisse être copié
sans les problèmes d'encodage du terminal Windows.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python show_corrector_context.py
"""

from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"
lines = TARGET.read_text(encoding="utf-8").splitlines()

hits = [i for i, l in enumerate(lines) if "w_corr" in l]
if not hits:
    print("Aucune occurrence de 'w_corr' trouvée dans le fichier.")
else:
    first, last = min(hits), max(hits)
    start = max(0, first - 3)
    end = min(len(lines), last + 4)
    out_path = TARGET.parent / "w_corr_context.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for i in range(start, end):
            line = f"{i+1:5d} | {repr(lines[i])}\n"
            f.write(line)
    print(f"Contexte écrit dans {out_path}")
    print("Ouvre ce fichier (VS Code, Notepad++) et colle-moi son contenu tel quel.")
