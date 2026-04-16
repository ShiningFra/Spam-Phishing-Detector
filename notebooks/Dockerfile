FROM python:3.11-slim

# Métadonnées
LABEL maintainer="Nghogué Taptué Franck Roddier <enspy5gi>"
LABEL description="Système de détection spam et phishing — ENSPY 5GI"

WORKDIR /app

# Dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Téléchargement des ressources NLTK
RUN python -c "import nltk; nltk.download('stopwords'); nltk.download('wordnet'); nltk.download('punkt')"

# Code source
COPY api/ ./api/
COPY data/ ./data/

# Création du dossier logs
RUN mkdir -p /app/logs

# Port exposé
EXPOSE 8000

# Variables d'environnement par défaut
ENV ALERT_MIN_LEVEL=high
ENV PYTHONPATH=/app

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Démarrage
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
