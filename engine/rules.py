"""
Rate-based signature layer.

The classifier is strong on scans and floods, whose signal lives in the traffic
and host features. Credential brute force is different: in NSL-KDD that class is
carried by content features (failed-login counts, guest-login flags) that a
real-time firewall cannot read without inspecting payloads. Rather than pretend
the model catches it, we add a small signature that watches connection rate per
source over a short window -- the same idea fail2ban uses. This makes the system
a hybrid detector (anomaly + signature), which is exactly the category Liao et
al. (2013) describe as the most robust in practice.

Signatures only ever *raise* a detection; the classifier remains the primary
decision-maker for everything else.
"""

from collections import defaultdict, deque

AUTH_SERVICES = {"ssh", "telnet", "ftp", "rdp", "microsoft_ds", "pop_3",
                 "imap4", "login", "shell"}


class RateSignatureEngine:
    def __init__(self, window=12.0, brute_hits=8, scan_ports=15, flood_hits=60):
        self.window = window
        self.brute_hits = brute_hits
        self.scan_ports = scan_ports
        self.flood_hits = flood_hits
        self.history = defaultdict(deque)   # src -> deque[(ts, dst, dport, service)]

    def _observe(self, conn):
        dq = self.history[conn.src]
        dq.append((conn.ts, conn.dst, conn.dport, conn.service))
        cutoff = conn.ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return dq

    def evaluate(self, conn):
        """Return (attack_type, confidence) or (None, 0.0)."""
        dq = self._observe(conn)
        to_target = [h for h in dq if h[1] == conn.dst]

        if conn.service in AUTH_SERVICES:
            auth_hits = sum(1 for h in to_target if h[3] in AUTH_SERVICES)
            if auth_hits >= self.brute_hits:
                conf = min(0.99, 0.72 + auth_hits * 0.008)
                return "Brute force", round(conf * 100, 1)

        distinct_ports = {h[2] for h in to_target}
        if len(distinct_ports) >= self.scan_ports:
            conf = min(0.99, 0.72 + len(distinct_ports) * 0.004)
            return "Port scan", round(conf * 100, 1)

        if len(dq) >= self.flood_hits:
            conf = min(0.99, 0.75 + len(dq) * 0.001)
            return "DoS / flood", round(conf * 100, 1)

        return None, 0.0

    def forget(self, ip):
        self.history.pop(ip, None)
