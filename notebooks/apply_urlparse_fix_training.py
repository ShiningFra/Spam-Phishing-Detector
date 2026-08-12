"""
apply_urlparse_fix_training.py
================================
Sécurise les deux appels urlparse() dans struct_feats_20(), à l'intérieur
de prepare_features_v2() (notebooks/incremental_layer_v2.py) — même bug
que celui déjà corrigé côté generate_balanced_corrections.py et à
corriger côté pipeline_v2.py (extract_structural_features), mais ici
c'est une troisième copie de la même logique, dans un troisième fichier.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks
    python apply_urlparse_fix_training.py
"""

import re
import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "incremental_layer_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/")

src = TARGET.read_text(encoding="utf-8")

if "def safe_netloc" in src:
    raise SystemExit("Le correctif urlparse semble déjà appliqué — rien à faire.")

# 1) Insertion de safe_netloc() juste avant son premier usage (susp_tld)
pattern1 = re.compile(
    r'(?P<indent>[ \t]*)ip_url[ \t]*= sum\(1 for u in urls if re\.search\(r\'https\?://\\d\{1,3\}\\\.\\d\{1,3\}\', u\)\)\n'
    r'(?P=indent)susp_tld = sum\(1 for u in urls\n'
)
m1 = pattern1.search(src)
if not m1:
    raise SystemExit(
        "Bloc 'ip_url / susp_tld' introuvable dans struct_feats_20(). N'a rien changé. "
        "Le fichier a peut-être déjà été modifié différemment."
    )
indent = m1.group("indent")

# Compté AVANT insertion de safe_netloc() (qui contient elle-même un appel
# urlparse(u).netloc légitime, à ne pas compter comme un site à corriger).
count_before = src.count("urlparse(u).netloc")

safe_netloc_def = (
    f'{indent}def safe_netloc(u):\n'
    f'{indent}    try:\n'
    f'{indent}        return urlparse(u).netloc\n'
    f'{indent}    except ValueError:\n'
    f'{indent}        return \'\'\n'
    f'\n'
)

insert_before = f'{indent}ip_url'
idx1 = src.index(insert_before)
src = src[:idx1] + safe_netloc_def + src[idx1:]

# 2) Remplacer les deux usages de urlparse(u).netloc par safe_netloc(u)
src = src.replace(
    "if urlparse(u).netloc.rsplit('.',1)[-1] in BLACKLISTED_TLDS)",
    "if safe_netloc(u).rsplit('.',1)[-1] in BLACKLISTED_TLDS)",
)
src = src.replace(
    "float(np.mean([urlparse(u).netloc.count('.')-1 for u in urls])) if urls else 0.0,",
    "float(np.mean([safe_netloc(u).count('.')-1 for u in urls])) if urls else 0.0,",
)
# Il doit rester exactement 1 occurrence : celle, légitime, à l'intérieur
# de safe_netloc() elle-même. Si ce n'est pas le cas, un des deux textes
# recherchés ne correspondait pas exactement à ce qu'il y a dans le fichier.
count_after = src.count("urlparse(u).netloc")
n_fixed = count_before - (count_after - 1)

if n_fixed != 2:
    raise SystemExit(
        f"Attention : {n_fixed}/2 remplacement(s) réussi(s) seulement — le texte "
        "exact ne correspondait pas partout. N'a rien sauvegardé. Colle-moi les "
        "lignes concernées pour ajuster le patch."
    )

backup = TARGET.with_suffix(".py.bak5")
shutil.copy2(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print("Patch appliqué avec succès.")
print(f"Sauvegarde de l'original : {backup}")
print(f"{n_fixed} appel(s) urlparse(u).netloc sécurisé(s) via safe_netloc().")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
