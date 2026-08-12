"""
add_bert_cache_patch.py
=========================
Met en cache les prédictions DistilBERT dans script_ablation_locale.py.

Les 4 configurations testées (référence, sans whitelist, sans règles,
sans correcteur) utilisent exactement le même échantillon de 500 emails
(même graine aléatoire, même population) — le texte envoyé à BERT est
donc identique d'une configuration à l'autre. Sans cache, BERT tourne
4 fois sur les mêmes textes ; avec cache, une seule fois.

Aucun changement de résultat : les prédictions BERT sont déterministes
pour un texte donné (mode inférence, pas d'aléatoire), le cache renvoie
donc exactement ce que le modèle aurait recalculé.

Usage :
    cd E:\\Workspace\\Memory\\Spc
    python add_bert_cache_patch.py
"""

import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "script_ablation_locale.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis la racine du projet.")

src = TARGET.read_text(encoding="utf-8")

if "_bert_cache" in src:
    raise SystemExit("Le cache BERT semble déjà en place — rien à faire.")

old = (
    'print("Pipeline prêt.")\n'
)
count = src.count(old)
if count != 1:
    raise SystemExit(
        f"Point d'insertion introuvable ou ambigu (trouvé {count} fois, 1 attendue). "
        "N'a rien changé. Colle-moi les lignes autour du chargement du pipeline "
        "('Pipeline prêt.') pour ajuster."
    )

cache_code = (
    'print("Pipeline prêt.")\n'
    '\n'
    '# ── Cache des prédictions BERT ─────────────────────────────────────\n'
    '# Les 4 configurations d\'ablation utilisent le même échantillon de\n'
    '# textes (même graine aléatoire) — BERT n\'a besoin de tourner qu\'une\n'
    '# seule fois par texte, pas une fois par configuration.\n'
    'import pipeline_v2 as _pv2_module\n'
    '_bert_cache = {}\n'
    '_original_predict_bert = _pv2_module.HybridEmailPipelineV2._predict_bert\n'
    '\n'
    'def _cached_predict_bert(self, text):\n'
    '    if text not in _bert_cache:\n'
    '        _bert_cache[text] = _original_predict_bert(self, text)\n'
    '    return _bert_cache[text]\n'
    '\n'
    'if getattr(_pv2_module, "_BERT_AVAILABLE", False):\n'
    '    _pv2_module.HybridEmailPipelineV2._predict_bert = _cached_predict_bert\n'
    '    print("Cache BERT activé (les 4 configurations partageront les mêmes prédictions).")\n'
)

src = src.replace(old, cache_code, 1)

backup = TARGET.with_suffix(".py.bak")
shutil.copy2(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print("Patch appliqué : cache BERT ajouté.")
print(f"Sauvegarde de l'original : {backup}")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
