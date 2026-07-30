import os

BASE = os.path.dirname(os.path.abspath(__file__))


def _bool(name, default=False):
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production-please")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE, 'instance', 'smartfw.db')}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # pfSense enforcement (optional). Leave PFSENSE_URL empty to fall back to
    # local iptables / simulation blocking.
    PFSENSE_URL = os.environ.get("PFSENSE_URL", "")
    PFSENSE_API_KEY = os.environ.get("PFSENSE_API_KEY", "")
    PFSENSE_API_SECRET = os.environ.get("PFSENSE_API_SECRET", "")
    PFSENSE_ALIAS = os.environ.get("PFSENSE_ALIAS", "smartfw_block")
    PFSENSE_VERIFY_TLS = _bool("PFSENSE_VERIFY_TLS", False)

    # Email alerts (optional). Without these, alerts are written to the log.
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    MAIL_FROM = os.environ.get("MAIL_FROM", "")
    MAIL_TO = os.environ.get("MAIL_TO", "")
