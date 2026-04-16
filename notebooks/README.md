# Système Intelligent de Détection de Spam et de Phishing

**Auteur :** Nghogué Taptué Franck Roddier — 5GI, ENSPY  
**Version :** 1.0.0  

## Description

Pipeline hybride de détection de spam et de phishing combinant :
- Règles heuristiques (URLs, patterns, obfuscation)
- Analyse des headers email (SPF/DKIM/DMARC)
- Modèle ML classique (LinearSVC + TF-IDF)
- DistilBERT fine-tuné (analyse sémantique contextuelle)

## Démarrage rapide

### Avec Docker (recommandé)
```bash
# Build et lancement
docker-compose up --build

# Test
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: verify your account at http://paypa1.xyz/login"}'
```

### Sans Docker
```bash
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
```

## Endpoints

| Méthode | Endpoint   | Description |
|---------|------------|-------------|
| GET     | /health    | État du service + modèles chargés |
| POST    | /analyze   | Analyse un email |
| POST    | /batch     | Analyse un lot d'emails (max 100) |
| GET     | /stats     | Statistiques de détection |
| GET     | /docs      | Documentation interactive (Swagger) |

## Exemple de réponse

```json
{
  "predicted_class":   "phishing",
  "threat_level":      "critical",
  "global_confidence": 0.94,
  "ml_probabilities":  {"ham": 0.02, "spam": 0.04, "phishing": 0.94},
  "rule_score":        0.65,
  "header_score":      0.80,
  "url_flags":         ["suspicious_tld:.xyz", "brand_impersonation:paypal"],
  "latency_ms":        12.4
}
```

## Configuration des alertes (§6.4)

Configurer via variables d'environnement dans `.env` :
```
ALERT_EMAIL_FROM=detector@enspy.cm
ALERT_EMAIL_TO=admin@enspy.cm
SMTP_HOST=smtp.gmail.com
SMTP_PASSWORD=votre_mot_de_passe_app
ALERT_MIN_LEVEL=high
```
