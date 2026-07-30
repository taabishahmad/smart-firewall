"""
Runtime engine. Pulls connection records from a source (a live sniffer, or the
synthetic generator used for demos), turns each into a feature vector, asks the
classifier for a verdict, applies the blocking policy, and records everything to
the database so the console can render it.
"""

import random
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from engine.detector import Detector
from engine.features import (Connection, FeatureAggregator, FlowTracker,
                             service_for_port)
from engine.firewall import FirewallController
from engine.rules import RateSignatureEngine
from engine.alerts import AlertManager

from .extensions import db
from .models import (ActivityLog, BlockedIP, Setting, ThreatAlert,
                     TrafficEvent)


class Monitor:
    def __init__(self, app):
        self.app = app
        self.detector = Detector()
        self.aggregator = FeatureAggregator()
        self.tracker = FlowTracker()
        self.rules = RateSignatureEngine()
        self.lock = threading.Lock()

        self.firewall = None
        self.alerts = None

        self.started_at = time.time()
        self.capturing = False
        self._sniffer = None
        self._stop = threading.Event()
        self.source_status = "idle"
        self.interface = None

        self.mal_counts = defaultdict(int)
        self.blocked_ips = set()
        self.rate_window = deque(maxlen=60)   # (second, connections)
        self.stats = {
            "flows": 0, "allowed": 0, "flagged": 0, "blocked": 0,
            "packets": 0,
        }

    # ------------------------------------------------------------------ config
    def _cfg(self):
        rows = {s.key: s.value for s in Setting.query.all()}
        return rows

    def configure_enforcement(self):
        with self.app.app_context():
            self._configure_enforcement()

    def _configure_enforcement(self):
        cfg = self._cfg()
        pf = {
            "url": self.app.config.get("PFSENSE_URL", ""),
            "api_key": self.app.config.get("PFSENSE_API_KEY", ""),
            "api_secret": self.app.config.get("PFSENSE_API_SECRET", ""),
            "alias": self.app.config.get("PFSENSE_ALIAS", "smartfw_block"),
            "verify_tls": self.app.config.get("PFSENSE_VERIFY_TLS", False),
        }
        self.firewall = FirewallController(
            mode=cfg.get("enforcement_mode", "auto"), pfsense_cfg=pf)
        self.alerts = AlertManager({
            "smtp_host": self.app.config.get("SMTP_HOST"),
            "smtp_port": self.app.config.get("SMTP_PORT", 587),
            "smtp_user": self.app.config.get("SMTP_USER"),
            "smtp_password": self.app.config.get("SMTP_PASSWORD"),
            "mail_from": self.app.config.get("MAIL_FROM"),
            "mail_to": self.app.config.get("MAIL_TO"),
        })
        self._log("info", f"Enforcement ready: {self.firewall.mode} back-end")
        # restore already-active blocks so we do not double-count
        for b in BlockedIP.query.filter_by(active=True).all():
            self.blocked_ips.add(b.ip)

    # -------------------------------------------------------------- core logic
    def handle_connection(self, conn: Connection):
        with self.lock:
            feat = self.aggregator.add(conn)
        pred, proba = self.detector.score(feat)
        ml_conf = round(proba * 100, 1)

        cfg = self._cfg()
        min_conf = float(cfg.get("min_confidence", 70))
        threshold = int(cfg.get("block_threshold", 3))
        auto = cfg.get("auto_block", "on") == "on"
        whitelist = {w.strip() for w in cfg.get("whitelist", "").split(",") if w.strip()}

        # primary decision: the classifier; secondary: the rate signature layer
        ml_hit = pred == 1 and ml_conf >= min_conf
        rule_family, rule_conf = self.rules.evaluate(conn)
        rule_hit = rule_family is not None

        malicious = ml_hit or rule_hit
        if ml_hit:
            attack_type = self.detector.classify_attack(feat)
            confidence = ml_conf
        elif rule_hit:
            attack_type = rule_family
            confidence = rule_conf
        else:
            attack_type = None
            confidence = ml_conf

        verdict = "allow"
        if malicious:
            verdict = "flag"
            self.mal_counts[conn.src] += 1
            do_block = (auto and conn.src not in whitelist
                        and conn.src not in self.blocked_ips
                        and self.mal_counts[conn.src] >= threshold)
            if do_block:
                verdict = "block"
                self._apply_block(conn, attack_type, confidence)
        elif conn.src in self.blocked_ips:
            verdict = "block"

        self._persist_event(conn, feat, verdict, confidence, attack_type)
        self._tick(conn, verdict)
        return verdict

    def _apply_block(self, conn, attack_type, confidence):
        ok = self.firewall.block(conn.src)
        self.blocked_ips.add(conn.src)
        row = BlockedIP(
            ip=conn.src, reason=f"{attack_type} on {conn.service}",
            attack_type=attack_type, confidence=confidence,
            enforcement=self.firewall.mode, active=True)
        db.session.add(row)
        alert = ThreatAlert(
            src_ip=conn.src, attack_type=attack_type, service=conn.service,
            confidence=confidence, severity="high")
        db.session.add(alert)
        db.session.commit()
        emailed = self.alerts.send_threat(
            conn.src, attack_type, confidence, conn.service)
        alert.emailed = bool(emailed)
        db.session.commit()
        state = "enforced" if ok else "recorded"
        self._log("threat",
                  f"Blocked {conn.src} ({attack_type}) via "
                  f"{self.firewall.mode} [{state}]")

    def _persist_event(self, conn, feat, verdict, confidence, attack_type):
        ev = TrafficEvent(
            src_ip=conn.src, dst_ip=conn.dst, protocol=conn.proto,
            service=conn.service, flag=conn.flag,
            src_bytes=conn.src_bytes, dst_bytes=conn.dst_bytes,
            verdict=verdict, confidence=confidence, attack_type=attack_type)
        db.session.add(ev)
        db.session.commit()

    def _tick(self, conn, verdict):
        self.stats["flows"] += 1
        if verdict == "allow":
            self.stats["allowed"] += 1
        elif verdict == "flag":
            self.stats["flagged"] += 1
        else:
            self.stats["blocked"] += 1
        sec = int(time.time())
        if self.rate_window and self.rate_window[-1][0] == sec:
            self.rate_window[-1][1] += 1
        else:
            self.rate_window.append([sec, 1])

    def _log(self, level, message):
        db.session.add(ActivityLog(level=level, message=message))
        db.session.commit()

    def _prune(self):
        keep = 1000
        total = TrafficEvent.query.count()
        if total > keep:
            cutoff = (TrafficEvent.query.order_by(TrafficEvent.id.desc())
                      .offset(keep).first())
            if cutoff:
                TrafficEvent.query.filter(
                    TrafficEvent.id < cutoff.id).delete()
                db.session.commit()

    # ----------------------------------------------------------- live capture
    def start_capture(self, interface=None):
        if self.capturing:
            return False, "Capture already running."
        try:
            from scapy.all import sniff  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            return False, f"scapy unavailable: {exc}"

        self.interface = interface or None
        self._stop.clear()
        self._sniffer = threading.Thread(
            target=self._sniff_loop, daemon=True)
        self.capturing = True
        self.source_status = "capturing"
        self._sniffer.start()
        with self.app.app_context():
            self._log("info",
                      f"Live capture started on "
                      f"{self.interface or 'default interface'}")
        return True, "Capture started."

    def _sniff_loop(self):
        from scapy.all import sniff
        with self.app.app_context():
            try:
                def cb(pkt):
                    if self._stop.is_set():
                        return
                    self.stats["packets"] += 1
                    for conn in self.tracker.ingest(pkt):
                        self.handle_connection(conn)

                while not self._stop.is_set():
                    sniff(prn=cb, store=False, timeout=2,
                          iface=self.interface,
                          stop_filter=lambda p: self._stop.is_set())
                    for conn in self.tracker.flush():
                        self.handle_connection(conn)
            except PermissionError:
                self.source_status = "error: root required for capture"
                self._log("error",
                          "Capture failed: raw sockets need root. "
                          "Run with sudo.")
            except Exception as exc:  # noqa: BLE001
                self.source_status = f"error: {exc}"
                self._log("error", f"Capture error: {exc}")
            finally:
                self.capturing = False

    def stop_capture(self):
        self._stop.set()
        self.capturing = False
        self.source_status = "idle"
        with self.app.app_context():
            for conn in self.tracker.flush():
                self.handle_connection(conn)
            self._log("info", "Live capture stopped.")
        return True

    # -------------------------------------------------------- synthetic source
    def inject_scenario(self, name, target="192.168.1.10"):
        """Push a burst of connections through the real pipeline for a demo."""
        with self.app.app_context():
            with self.lock:
                self.aggregator.reset()   # isolate this demo burst
            conns = SCENARIOS.get(name, lambda t: [])(target)
            blocked_before = len(self.blocked_ips)
            for conn in conns:
                self.handle_connection(conn)
                time.sleep(0.003)
            self._prune()
            gained = len(self.blocked_ips) - blocked_before
            self._log("info",
                      f"Simulated '{name}' traffic: {len(conns)} flows, "
                      f"{gained} new block(s)")
        return len(conns)

    # ---------------------------------------------------------------- snapshot
    def snapshot(self):
        now = int(time.time())
        series = {s: 0 for s in range(now - 59, now + 1)}
        for sec, n in self.rate_window:
            if sec in series:
                series[sec] = n
        rate = [series[s] for s in sorted(series)]
        return {
            "uptime": int(time.time() - self.started_at),
            "capturing": self.capturing,
            "source_status": self.source_status,
            "enforcement": self.firewall.mode if self.firewall else "-",
            "model": self.detector.model_name,
            "interface": self.interface or "default",
            "stats": dict(self.stats),
            "rate": rate,
            "active_blocks": len(self.blocked_ips),
        }


# --------------------------------------------------------------------- demo data
def _norm_conns(target):
    lan = [f"192.168.1.{i}" for i in (12, 15, 21, 33, 40)]
    out = []
    now = time.time()
    services = [(80, "http"), (443, "http_443"), (53, "domain"), (22, "ssh")]
    for i in range(24):
        src = random.choice(lan)
        port, _ = random.choice(services)
        sb = random.randint(180, 2200)
        dbb = random.randint(400, 18000)
        out.append(Connection(
            src=src, dst=target, dport=port, proto="tcp",
            service=service_for_port(port, "tcp"), flag="SF",
            duration=round(random.uniform(0.05, 2.5), 2),
            src_bytes=sb, dst_bytes=dbb, ts=now + i * 0.02))
    return out


def _portscan_conns(target):
    attacker = "45.83.219.14"
    out = []
    now = time.time()
    for i, port in enumerate(range(20, 20 + 60)):
        out.append(Connection(
            src=attacker, dst=target, dport=port, proto="tcp",
            service=service_for_port(port, "tcp"), flag="S0",
            duration=0.0, src_bytes=0, dst_bytes=0, ts=now + i * 0.005))
    return out


def _dos_conns(target):
    attacker = "185.220.101.47"
    out = []
    now = time.time()
    for i in range(150):
        out.append(Connection(
            src=attacker, dst=target, dport=80, proto="tcp",
            service="http", flag="S0", duration=0.0,
            src_bytes=0, dst_bytes=0, ts=now + i * 0.002))
    return out


def _brute_conns(target):
    attacker = "103.97.203.9"
    out = []
    now = time.time()
    for i in range(40):
        flag = "REJ" if i % 3 == 0 else "RSTO"
        out.append(Connection(
            src=attacker, dst=target, dport=22, proto="tcp",
            service="ssh", flag=flag, duration=round(random.uniform(0, 0.3), 2),
            src_bytes=random.randint(20, 90), dst_bytes=0,
            ts=now + i * 0.01))
    return out


def _mixed_conns(target):
    conns = _norm_conns(target) + _portscan_conns(target) + _brute_conns(target)
    conns.sort(key=lambda c: c.ts)
    return conns


SCENARIOS = {
    "benign": _norm_conns,
    "portscan": _portscan_conns,
    "dos": _dos_conns,
    "bruteforce": _brute_conns,
    "mixed": _mixed_conns,
}
