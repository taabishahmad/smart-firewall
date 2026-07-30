"""
Administrator alerting. Sends an email when a threat is blocked. If SMTP is not
configured (the common case on a lab machine) it degrades to writing the alert
to the application log so the pipeline still runs end to end.
"""

import logging
import smtplib
import ssl
from email.message import EmailMessage

log = logging.getLogger("smartfw.alerts")


class AlertManager:
    def __init__(self, cfg=None):
        cfg = cfg or {}
        self.host = cfg.get("smtp_host")
        self.port = int(cfg.get("smtp_port", 587))
        self.user = cfg.get("smtp_user")
        self.password = cfg.get("smtp_password")
        self.sender = cfg.get("mail_from") or self.user
        self.recipient = cfg.get("mail_to")
        self.enabled = bool(cfg.get("enabled", True))

    @property
    def configured(self):
        return all([self.host, self.user, self.password, self.recipient])

    def send_threat(self, ip, attack_type, confidence, service):
        subject = f"[Smart Firewall] Blocked {attack_type} from {ip}"
        body = (
            f"A threat was detected and the source address has been blocked.\n\n"
            f"Source IP : {ip}\n"
            f"Category  : {attack_type}\n"
            f"Service   : {service}\n"
            f"Confidence: {confidence:.1f}%\n\n"
            f"This is an automated message from the AI-Based Smart Firewall."
        )
        return self.send(subject, body)

    def send(self, subject, body):
        if not self.enabled:
            return False
        if not self.configured:
            log.info("ALERT (email not configured): %s", subject)
            return False
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = self.sender
            msg["To"] = self.recipient
            msg.set_content(body)
            ctx = ssl.create_default_context()
            with smtplib.SMTP(self.host, self.port, timeout=10) as s:
                s.starttls(context=ctx)
                s.login(self.user, self.password)
                s.send_message(msg)
            log.info("Alert email sent to %s", self.recipient)
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("Alert email failed: %s", exc)
            return False
