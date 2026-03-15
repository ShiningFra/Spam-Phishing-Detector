# Spam-Phishing-Detector
A Machine Learning solution for spam and phishing detection


## First Steps :

### Installer Python :

Pour commencer il faut installer python

Sur un système Windows, taper la commande 
```bash
python
```
aura pour effet d'installer le py-manager, qui à son lancement installera une version de python. A chaque demande `[y/N]?` entrer `y`

### Créer un Venv Python :

Ensuite il faut créer un venv (virtual environment) Python. Pour cela il faut saisir sur son terminal 
```bash
python -m venv .venv
```
Cela crée un environnement virtuel python appelé .venv dans le répertoire actif

### Activer le venv :

Pour ce faire, il suffit de saisir 
```bash
.venv\Scripts\activate
```
(depuis le répertoire où l'on a saisi la commande de création du venv)
On activera ainsi le venv .venv à chaque fois que l'on travaillera.

### Installer les dépendances :

Pour cela, il faut repérer le fichier `requirements.txt` que l'on devrait trouver à la racine du projet. Puis faire un 
```bash
pip install -r requirements.txt
```


Une fois ces étapes préliminaires terminées, il est temps de passer à la suite.

## Le jeu de données :

Nous utilisons les données disponibles sur https://www.kaggle.com :

Spams (SMS) : https://www.kaggle.com/datasets/uciml/sms-spam-collection-dataset

Phishing (Emails) : https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset

Hams (Emails) : https://www.kaggle.com/datasets/wcukierski/enron-email-dataset