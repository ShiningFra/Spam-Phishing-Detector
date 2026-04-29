# -*- coding: utf-8 -*-
import smtplib
import logging
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logger = logging.getLogger("spam_detector")


class AlertNotifier:
    """
    Systeme de notification par email pour les menaces detectees.
    Correspond au §6.4 du cahier de charges.

    Configuration via variables d'environnement :
        ALERT_EMAIL_FROM   : adresse expediteur
        ALERT_EMAIL_TO     : adresse administrateur
        SMTP_HOST          : serveur SMTP (ex: smtp.gmail.com)
        SMTP_PORT          : port SMTP (ex: 587)
        SMTP_PASSWORD      : mot de passe app
        ALERT_MIN_LEVEL    : niveau minimum pour alerter (high/critical)
    """

    THREAT_LEVELS_ORDER = ["none", "low", "medium", "high", "critical"]

    def __init__(self):
        self.from_addr  = os.getenv("ALERT_EMAIL_FROM", "detector@enspy.cm")
        self.to_addr    = os.getenv("ALERT_EMAIL_TO",   "admin@enspy.cm")
        self.smtp_host  = os.getenv("SMTP_HOST",        "smtp.gmail.com")
        self.smtp_port  = int(os.getenv("SMTP_PORT",    "587"))
        self.smtp_pass  = os.getenv("SMTP_PASSWORD",    "")
        self.min_level  = os.getenv("ALERT_MIN_LEVEL",  "high")
        self.enabled    = bool(self.smtp_pass)

    def should_alert(self, threat_level: str) -> bool:
        """Determine si une alerte doit etre envoyee selon le niveau de menace."""
        try:
            return (self.THREAT_LEVELS_ORDER.index(threat_level) >=
                    self.THREAT_LEVELS_ORDER.index(self.min_level))
        except ValueError:
            return False

    def build_alert_body(self, result: dict, text_preview: str) -> str:
        """Construit le corps de l'email d'alerte (§6.4.3)."""
        return f"""
ALERTE DE SECURITE  Systeme de Detection Spam/Phishing
========================================================

Date/Heure     : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
Type de menace : {result.get('predicted_class', '?')}  Niveau : {result.get('threat_level', '?')} 
Score confiance: {result.get('global_confidence', 0):.1%}
Expediteur     : {result.get('sender', 'Non disponible')}

--- Analyse IP/DNS ---
Score headers  : {result.get('header_score', 0):.2f}
Flags headers  : {', '.join(result.get('header_flags', []))}
URLs suspectes : {', '.join(result.get('url_flags', []))}

--- Regles declenchees ---
{chr(10).join('  · ' + r for r in result.get('rules_triggered', []))}

--- Extrait du message suspect ---
{text_preview[:500]}

--- Chemin de decision ---
{result.get('decision_path', 'N/A')}

========================================================
Ce message est genere automatiquement par le systeme de detection ENSPY.
"""

    def send_alert(self, result: dict, text_preview: str = "") -> bool:
        """
        Envoie une alerte par email si le niveau de menace est suffisant.
        Retourne True si l'alerte a ete envoyee, False sinon.
        """
        if not self.should_alert(result.get("threat_level", "none")):
            return False

        if not self.enabled:
            logger.info(f"[NOTIFIER] Alerte simulee (SMTP non configure)  "
                        f"{result.get('threat_level')} {result.get('predicted_class')}")
            return True

        try:
            msg = MIMEMultipart()
            msg["From"]    = self.from_addr
            msg["To"]      = self.to_addr
            msg["Subject"] = (f"[ALERTE {result.get('threat_level', '?'). upper()}] "
                              f"Email {result.get('predicted_class', '?')} detecte")
            msg.attach(MIMEText(self.build_alert_body(result, text_preview), "plain", "utf-8"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.from_addr, self.smtp_pass)
                server.send_message(msg)

            logger.info(f"[NOTIFIER] Alerte envoyee a {self.to_addr}")
            return True

        except Exception as e:
            logger.error(f"[NOTIFIER] Echec envoi alerte : {e}")
            return False


notifier = AlertNotifier()