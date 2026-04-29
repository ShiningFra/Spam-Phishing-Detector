"""
fix_encoding.py
Corrige l'encodage de tous les fichiers .py dans api/
Ajoute # -*- coding: utf-8 -*- en tête si absent
Supprime les caractères non-ASCII dans les docstrings et commentaires

Lancer depuis E:\\Workspace\\Memory\\Spc\\notebooks :
    python fix_encoding.py
"""
import os
import re
from pathlib import Path

API_DIR = Path(__file__).parent / 'api'

def fix_file(path: Path):
    # Lire en ignorant les erreurs
    raw = path.read_bytes()
    
    # Décoder en latin-1 (accepte tout) puis réencoder en UTF-8
    # après avoir remplacé les caractères spéciaux par leurs equivalents ASCII
    text = raw.decode('latin-1', errors='replace')
    
    # Remplacements courants français → ASCII pur
    replacements = {
        'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
        'à': 'a', 'â': 'a', 'ä': 'a',
        'î': 'i', 'ï': 'i',
        'ô': 'o', 'ö': 'o',
        'ù': 'u', 'û': 'u', 'ü': 'u',
        'ç': 'c', 'ñ': 'n',
        'É': 'E', 'È': 'E', 'Ê': 'E',
        'À': 'A', 'Â': 'A',
        'Î': 'I', 'Ô': 'O', 'Ù': 'U', 'Û': 'U',
        'Ç': 'C',
        '\u2019': "'",  # apostrophe typographique
        '\u2018': "'",
        '\u201c': '"',
        '\u201d': '"',
        '\u2013': '-',
        '\u2014': '--',
        '\ufffd': '?',  # replacement character
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)
    
    # Ajouter # -*- coding: utf-8 -*- si absent
    lines = text.splitlines(keepends=True)
    has_coding = any('coding' in l for l in lines[:2])
    if not has_coding:
        lines.insert(0, '# -*- coding: utf-8 -*-\n')
    
    new_text = ''.join(lines)
    path.write_text(new_text, encoding='utf-8')
    print(f'  Corrige : {path.name}')

if __name__ == '__main__':
    print(f'Correction des fichiers dans {API_DIR}')
    for f in API_DIR.glob('*.py'):
        try:
            fix_file(f)
        except Exception as e:
            print(f'  ERREUR {f.name}: {e}')
    print('Termine. Relancer uvicorn.')
