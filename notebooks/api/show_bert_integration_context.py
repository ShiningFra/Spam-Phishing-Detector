"""
show_bert_integration_context.py
==================================
Extrait le texte exact des éléments nécessaires pour intégrer DistilBERT
dans pipeline_v2.py : analyze(), _aggregate(), la classe/le dict des
poids adaptatifs, et le(s) __init__ de la classe pipeline.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python show_bert_integration_context.py

Écrit bert_integration_context.txt — upload-le directement.
"""

import re
from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"
lines = TARGET.read_text(encoding="utf-8").splitlines()


def extract_block(start_idx, max_lines=80):
    """Extrait un bloc en se basant sur l'indentation de la première ligne."""
    first = lines[start_idx]
    base_indent = len(first) - len(first.lstrip())
    end_idx = min(len(lines), start_idx + max_lines)
    for i in range(start_idx + 1, min(len(lines), start_idx + max_lines)):
        line = lines[i]
        if line.strip() == "":
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base_indent and line.strip():
            end_idx = i
            break
    return start_idx, end_idx


out_path = Path(__file__).parent / "bert_integration_context.txt"
with open(out_path, "w", encoding="utf-8") as f:
    f.write(f"=== {TARGET} ===\n\n")

    # 1) Toutes les occurrences de "def analyze("
    for i, l in enumerate(lines):
        if re.match(r'\s*def analyze\(', l):
            s, e = extract_block(i)
            f.write(f"--- def analyze (lignes {s+1} à {e}) ---\n")
            for j in range(s, e):
                f.write(f"{j+1:5d} | {repr(lines[j])}\n")
            f.write("\n")

    # 2) Toutes les occurrences de "def _aggregate("
    for i, l in enumerate(lines):
        if re.match(r'\s*def _aggregate\(', l):
            s, e = extract_block(i)
            f.write(f"--- def _aggregate (lignes {s+1} à {e}) ---\n")
            for j in range(s, e):
                f.write(f"{j+1:5d} | {repr(lines[j])}\n")
            f.write("\n")

    # 3) Classe ou dict de poids adaptatifs (recherche large)
    for i, l in enumerate(lines):
        if "AdaptiveWeights" in l or ("BASE" in l and "weights" in l.lower()) or re.search(r"['\"]rules['\"]\s*:", l):
            start = max(0, i - 2)
            end = min(len(lines), i + 15)
            f.write(f"--- contexte poids adaptatifs (autour de la ligne {i+1}) ---\n")
            for j in range(start, end):
                f.write(f"{j+1:5d} | {repr(lines[j])}\n")
            f.write("\n")
            break  # un seul contexte suffit, évite la répétition

    # 4) Tous les __init__ (avec le nom de la classe juste avant)
    for i, l in enumerate(lines):
        if re.match(r'\s*def __init__\(', l):
            # remonter pour trouver la classe englobante
            class_line = ""
            for k in range(i, -1, -1):
                if re.match(r'\s*class ', lines[k]):
                    class_line = lines[k].strip()
                    break
            s, e = extract_block(i)
            f.write(f"--- __init__ de [{class_line}] (lignes {s+1} à {e}) ---\n")
            for j in range(s, e):
                f.write(f"{j+1:5d} | {repr(lines[j])}\n")
            f.write("\n")

print(f"Écrit : {out_path}")
print("Upload ce fichier dans le chat.")
