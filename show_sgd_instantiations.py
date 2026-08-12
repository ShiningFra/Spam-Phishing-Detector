"""
show_sgd_instantiations.py
============================
Localise TOUS les endroits où SGDClassifier(...) est instancié dans
notebooks/incremental_layer_v2.py — pour repérer précisément où changer
le paramètre alpha (régularisation), y compris dans load_corrector(),
qui n'avait pas été extrait la fois précédente.

Usage :
    cd E:\\Workspace\\Memory\\Spc
    python show_sgd_instantiations.py
"""

from pathlib import Path

TARGET = Path(__file__).parent / "notebooks" / "incremental_layer_v2.py"
lines = TARGET.read_text(encoding="utf-8").splitlines()

hits = [i for i, l in enumerate(lines)
        if "SGDClassifier(" in l or "SGDClassifier (" in l
        or "_SGD(" in l or "_SGD (" in l]

out_path = Path(__file__).parent / "sgd_instantiations.txt"
with open(out_path, "w", encoding="utf-8") as f:
    f.write(f"=== {TARGET} ===\n\n")
    if not hits:
        f.write("Aucune instanciation de SGDClassifier trouvée directement.\n")
        f.write("Recherche élargie de 'load_corrector' :\n\n")
        for i, l in enumerate(lines):
            if "load_corrector" in l:
                start = max(0, i - 2)
                end = min(len(lines), i + 20)
                f.write(f"--- autour de la ligne {i+1} ---\n")
                for j in range(start, end):
                    f.write(f"{j+1:5d} | {repr(lines[j])}\n")
                f.write("\n")
    else:
        for i in hits:
            start = max(0, i - 5)
            end = min(len(lines), i + 8)
            f.write(f"--- occurrence ligne {i+1} ---\n")
            for j in range(start, end):
                f.write(f"{j+1:5d} | {repr(lines[j])}\n")
            f.write("\n")

print(f"Écrit : {out_path}")
print("Upload ce fichier dans le chat.")
