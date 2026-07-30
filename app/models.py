from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="admin")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class TrafficEvent(db.Model):
    __tablename__ = "traffic_events"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45))
    protocol = db.Column(db.String(8))
    service = db.Column(db.String(24))
    flag = db.Column(db.String(8))
    src_bytes = db.Column(db.Integer, default=0)
    dst_bytes = db.Column(db.Integer, default=0)
    verdict = db.Column(db.String(12))          # allow | block
    confidence = db.Column(db.Float, default=0)
    attack_type = db.Column(db.String(32))

    def as_dict(self):
        return {
            "id": self.id,
            "ts": self.ts.strftime("%H:%M:%S"),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "service": self.service,
            "flag": self.flag,
            "bytes": f"{self.src_bytes}/{self.dst_bytes}",
            "verdict": self.verdict,
            "confidence": round(self.confidence, 1),
            "attack_type": self.attack_type,
        }


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), index=True)
    reason = db.Column(db.String(120))
    attack_type = db.Column(db.String(32))
    confidence = db.Column(db.Float, default=0)
    enforcement = db.Column(db.String(16))      # pfsense | iptables | simulation
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)
    unblocked_at = db.Column(db.DateTime)

    def as_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "attack_type": self.attack_type,
            "confidence": round(self.confidence, 1),
            "enforcement": self.enforcement,
            "blocked_at": self.blocked_at.strftime("%Y-%m-%d %H:%M:%S"),
            "active": self.active,
        }


class ThreatAlert(db.Model):
    __tablename__ = "threat_alerts"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(45))
    attack_type = db.Column(db.String(32))
    service = db.Column(db.String(24))
    confidence = db.Column(db.Float, default=0)
    severity = db.Column(db.String(12), default="high")
    emailed = db.Column(db.Boolean, default=False)
    acknowledged = db.Column(db.Boolean, default=False)

    def as_dict(self):
        return {
            "id": self.id,
            "ts": self.ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": self.src_ip,
            "attack_type": self.attack_type,
            "service": self.service,
            "confidence": round(self.confidence, 1),
            "severity": self.severity,
            "emailed": self.emailed,
            "acknowledged": self.acknowledged,
        }


class Setting(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(255))


class ActivityLog(db.Model):
    __tablename__ = "activity_log"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    level = db.Column(db.String(12), default="info")
    message = db.Column(db.String(255))

    def as_dict(self):
        return {
            "ts": self.ts.strftime("%Y-%m-%d %H:%M:%S"),
            "level": self.level,
            "message": self.message,
        }


DEFAULT_SETTINGS = {
    "block_threshold": "3",       # malicious flows from one IP before blocking
    "min_confidence": "70",       # minimum model confidence to act on (%)
    "auto_block": "on",
    "whitelist": "127.0.0.1",
    "capture_interface": "",
    "enforcement_mode": "auto",
}
