"""
show_feature_functions.py
==========================
Extrait le texte exact (espaces compris, via repr()) des fonctions liées
à la préparation des features du correcteur, dans les deux fichiers
concernés :
    - notebooks/incremental_layer_v2.py   (entraînement)
    - notebooks/api/pipeline_v2.py        (inférence)

Usage :
    cd E:\\Workspace\\Memory\\Spc
    python show_feature_functions.py

Écrit deux fichiers :
    feature_functions_training.txt
    feature_functions_inference.txt
À uploader tels quels, pas à copier-coller depuis le terminal.
"""

import re
from pathlib import Path

BASE_DIR = Path(__file__).parent

TARGETS = [
    (BASE_DIR / "notebooks" / "incremental_layer_v2.py",
     "feature_functions_training.txt",
     ["def prepare_features_v2", "def update_corrector_v2"]),
    (BASE_DIR / "notebooks" / "api" / "pipeline_v2.py",
     "feature_functions_inference.txt",
     ["def prepare_features_v2", "def _build_corrector_input", "def _apply_corrector",
      "def _predict_ml", "def load_models", "def load_corrector", "_load_corrector"]),
]


def extract_function(lines, start_idx):
    """Extrait une fonction en se basant sur l'indentation du 'def'."""
    def_line = lines[start_idx]
    base_indent = len(def_line) - len(def_line.lstrip())
    end_idx = len(lines)
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        if line.strip() == "":
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent:
            end_idx = i
            break
    return start_idx, end_idx


for path, out_name, needles in TARGETS:
    if not path.exists():
        print(f"INTROUVABLE : {path}")
        continue
    lines = path.read_text(encoding="utf-8").splitlines()
    out_path = BASE_DIR / out_name
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"=== Fichier source : {path} ===\n\n")
        found_any = False
        for needle in needles:
            for i, line in enumerate(lines):
                if needle in line and line.strip().startswith(("def ", "async def")):
                    found_any = True
                    s, e = extract_function(lines, i)
                    f.write(f"--- {needle} (lignes {s+1} à {e}) ---\n")
                    for j in range(s, e):
                        f.write(f"{j+1:5d} | {repr(lines[j])}\n")
                    f.write("\n")
                    break
            else:
                f.write(f"--- {needle} : NON TROUVÉE dans ce fichier ---\n\n")
        if not found_any:
            f.write("Aucune des fonctions recherchées n'a été trouvée.\n")
    print(f"Écrit : {out_path}")

print("\nUpload ces deux fichiers directement dans le chat.")
