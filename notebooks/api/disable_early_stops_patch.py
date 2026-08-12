"""
disable_early_stops_patch.py
==============================
Désactive les 3 arrêts anticipés de analyze() (scam_domain, rule_phish
>= 0.95, rule_spam >= 0.92) sans les supprimer — ils sont conservés dans
le code, juste rendus inatteignables (`if False and ...`), pour pouvoir
être réactivés facilement en un revert si l'hypothèse ne se confirme
pas. rule_spam/rule_phish continuent d'être calculés normalement et
pèsent toujours dans l'agrégation pondérée et dans composite_phish/
composite_spam — seul le court-circuit qui empêche BERT et RF+correcteur
de se prononcer est neutralisé.

Usage :
    cd E:\\Workspace\\Memory\\Spc\\notebooks\\api
    python disable_early_stops_patch.py
"""

import shutil
from pathlib import Path

TARGET = Path(__file__).parent / "pipeline_v2.py"

if not TARGET.exists():
    raise SystemExit(f"Fichier introuvable : {TARGET} — lance ce script depuis notebooks/api/")

src = TARGET.read_text(encoding="utf-8")

if "# early-stop désactivé pour test" in src:
    raise SystemExit("Les arrêts anticipés semblent déjà désactivés — rien à faire.")


def require(old, label):
    n = src.count(old)
    if n != 1:
        raise SystemExit(
            f"[{label}] texte cible introuvable ou ambigu (trouvé {n} fois, "
            f"1 attendue). N'a rien changé sur le disque."
        )


steps_done = []

# 1) Arrêt anticipé "scam domain"
old1 = "        if scam_domain_hit and rule_phish >= 0.50:\n"
require(old1, "early-stop scam_domain")
new1 = "        if False and scam_domain_hit and rule_phish >= 0.50:  # early-stop désactivé pour test\n"
src = src.replace(old1, new1, 1)
steps_done.append("early-stop scam_domain désactivé")

# 2) Arrêt anticipé phishing
old2 = "        if rule_phish >= 0.95:\n"
require(old2, "early-stop rule_phish>=0.95")
new2 = "        if False and rule_phish >= 0.95:  # early-stop désactivé pour test\n"
src = src.replace(old2, new2, 1)
steps_done.append("early-stop rule_phish>=0.95 désactivé")

# 3) Arrêt anticipé spam
old3 = "        if rule_spam >= 0.92:   # Seuil légèrement abaissé vs v1 (0.95)\n"
require(old3, "early-stop rule_spam>=0.92")
new3 = "        if False and rule_spam >= 0.92:  # early-stop désactivé pour test (seuil vs v1 : 0.95)\n"
src = src.replace(old3, new3, 1)
steps_done.append("early-stop rule_spam>=0.92 désactivé")

backup = TARGET.with_suffix(".py.bak9")
shutil.copy2(TARGET, backup)
TARGET.write_text(src, encoding="utf-8")

print("Patch appliqué avec succès. Étapes :")
for s in steps_done:
    print(f"  - {s}")
print(f"\nSauvegarde de l'original : {backup}")
print("\nPour réactiver les arrêts anticipés plus tard : restaure la sauvegarde,")
print("ou cherche 'False and' dans analyze() et retire-le des 3 conditions.")
print("\nVérifie que ça compile :")
print(f"  python -c \"import ast; ast.parse(open(r'{TARGET}', encoding='utf-8').read())\" && echo OK")
