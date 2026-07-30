"""
Flow tracking and feature aggregation.

Packets are grouped into bidirectional flows keyed by
(src, dst, dst_port, protocol). When a flow finishes -- a FIN/RST is seen, or it
sits idle past a timeout -- it becomes a "connection record" carrying the basic
NSL-KDD features (duration, protocol, service, flag, bytes each way).

Each completed connection is then handed to the aggregator, which keeps two
rolling views to reproduce the rest of the NSL-KDD feature set:

  * a two-second time window  -> count / srv_count and the *error / same_srv rates
  * the last 100 connections  -> the dst_host_* host-based features

The output is a dict keyed exactly by ml.preprocess.FEATURES, ready to score.
"""

import time
from collections import deque
from dataclasses import dataclass, field

# Ports mapped to the service names NSL-KDD actually uses. Ports we do not
# recognise fall through to "private" for the high/ephemeral range and "other"
# otherwise, both of which exist in the dataset vocabulary.
PORT_SERVICE = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    43: "whois", 53: "domain", 79: "finger", 80: "http", 110: "pop_3",
    111: "sunrpc", 113: "auth", 119: "nntp", 143: "imap4", 161: "snmp",
    179: "bgp", 389: "ldap", 443: "http_443", 445: "microsoft_ds",
    513: "login", 514: "shell", 3306: "sql_net", 3389: "rdp", 8080: "http_8001",
}


def service_for_port(port, proto):
    if port in PORT_SERVICE:
        return PORT_SERVICE[port]
    if proto == "icmp":
        return "eco_i"
    if port and port >= 1024:
        return "private"
    return "other"


@dataclass
class Flow:
    src: str
    dst: str
    dport: int
    proto: str
    start: float
    last: float
    src_bytes: int = 0
    dst_bytes: int = 0
    syn: bool = False
    synack: bool = False
    fin: bool = False
    rst: bool = False
    established: bool = False
    packets: int = 0

    def flag(self):
        if self.proto != "tcp":
            return "SF"
        if self.rst:
            return "RSTO" if self.synack else "REJ"
        if self.syn and not self.synack:
            return "S0"
        if self.synack and (self.fin or self.src_bytes or self.dst_bytes):
            return "SF"
        if self.synack:
            return "S1"
        return "OTH"


@dataclass
class Connection:
    src: str
    dst: str
    dport: int
    proto: str
    service: str
    flag: str
    duration: float
    src_bytes: int
    dst_bytes: int
    ts: float = field(default_factory=time.time)


class FlowTracker:
    """Consumes scapy packets and yields completed Connection records."""

    def __init__(self, idle_timeout=2.0):
        self.flows = {}
        self.idle_timeout = idle_timeout

    def _key(self, src, dst, dport, proto):
        return (src, dst, dport, proto)

    def ingest(self, pkt):
        """Feed one scapy packet. Returns a list of Connections that just closed."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
        except Exception:
            return []
        if IP not in pkt:
            return []

        ip = pkt[IP]
        now = float(pkt.time) if hasattr(pkt, "time") else time.time()
        closed = []

        if TCP in pkt:
            proto, l4 = "tcp", pkt[TCP]
            dport, sport = int(l4.dport), int(l4.sport)
            flags = int(l4.flags)
        elif UDP in pkt:
            proto, l4 = "udp", pkt[UDP]
            dport, sport = int(l4.dport), int(l4.sport)
            flags = 0
        elif ICMP in pkt:
            proto = "icmp"
            dport, sport, flags = 0, 0, 0
        else:
            return []

        # Normalise direction so both halves of a conversation share a key.
        fwd_key = self._key(ip.src, ip.dst, dport, proto)
        rev_key = self._key(ip.dst, ip.src, sport, proto)
        if rev_key in self.flows:
            flow, forward = self.flows[rev_key], False
        else:
            flow = self.flows.get(fwd_key)
            if flow is None:
                flow = Flow(ip.src, ip.dst, dport, proto, now, now)
                self.flows[fwd_key] = flow
            forward = True

        size = len(pkt)
        flow.packets += 1
        flow.last = now
        if forward:
            flow.src_bytes += size
        else:
            flow.dst_bytes += size

        if proto == "tcp":
            syn, ack = flags & 0x02, flags & 0x10
            fin, rst = flags & 0x01, flags & 0x04
            if syn and not ack:
                flow.syn = True
            if syn and ack:
                flow.synack = True
                flow.established = True
            if fin:
                flow.fin = True
            if rst:
                flow.rst = True
            if (fin or rst) and (forward is not None):
                closed.append(self._finish(fwd_key if forward else rev_key, flow))

        closed.extend(self._expire(now))
        return [c for c in closed if c is not None]

    def _finish(self, key, flow):
        if key not in self.flows:
            return None
        del self.flows[key]
        return Connection(
            src=flow.src, dst=flow.dst, dport=flow.dport, proto=flow.proto,
            service=service_for_port(flow.dport, flow.proto), flag=flow.flag(),
            duration=max(0.0, flow.last - flow.start),
            src_bytes=flow.src_bytes, dst_bytes=flow.dst_bytes, ts=flow.last,
        )

    def _expire(self, now):
        stale = [k for k, f in self.flows.items()
                 if now - f.last > self.idle_timeout]
        return [self._finish(k, self.flows[k]) for k in stale]

    def flush(self):
        now = time.time()
        out = [self._finish(k, self.flows[k]) for k in list(self.flows)]
        return [c for c in out if c is not None]


class FeatureAggregator:
    """Builds the full feature vector for each completed Connection."""

    def __init__(self, time_window=2.0, host_window=100):
        self.time_window = time_window
        self.recent = deque()          # (ts, Connection) within time_window
        self.per_host = {}             # dst -> deque of last host_window conns
        self.host_window = host_window

    def reset(self):
        self.recent.clear()
        self.per_host.clear()

    def _trim(self, now):
        while self.recent and now - self.recent[0][0] > self.time_window:
            self.recent.popleft()

    @staticmethod
    def _rate(items, predicate):
        if not items:
            return 0.0
        return round(sum(1 for i in items if predicate(i)) / len(items), 4)

    def add(self, conn: Connection) -> dict:
        now = conn.ts
        self._trim(now)
        window = [c for _, c in self.recent]

        same_host = [c for c in window if c.dst == conn.dst]
        same_srv = [c for c in window if c.service == conn.service]

        def is_serror(c):
            return c.flag in ("S0", "S1", "S2", "S3")

        def is_rerror(c):
            return c.flag in ("REJ", "RSTO", "RSTR")

        count = len(same_host)
        srv_count = len(same_srv)

        hq = self.per_host.setdefault(conn.dst, deque(maxlen=self.host_window))
        host_list = list(hq)
        host_srv = [c for c in host_list if c.service == conn.service]

        feat = {
            "duration": round(conn.duration, 3),
            "protocol_type": conn.proto,
            "service": conn.service,
            "flag": conn.flag,
            "src_bytes": conn.src_bytes,
            "dst_bytes": conn.dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": self._rate(same_host, is_serror),
            "srv_serror_rate": self._rate(same_srv, is_serror),
            "rerror_rate": self._rate(same_host, is_rerror),
            "srv_rerror_rate": self._rate(same_srv, is_rerror),
            "same_srv_rate": self._rate(same_host, lambda c: c.service == conn.service),
            "diff_srv_rate": self._rate(same_host, lambda c: c.service != conn.service),
            "srv_diff_host_rate": self._rate(same_srv, lambda c: c.dst != conn.dst),
            "dst_host_count": len(host_list),
            "dst_host_srv_count": len(host_srv),
            "dst_host_same_srv_rate": self._rate(host_list, lambda c: c.service == conn.service),
            "dst_host_diff_srv_rate": self._rate(host_list, lambda c: c.service != conn.service),
            "dst_host_same_src_port_rate": self._rate(host_list, lambda c: c.dport == conn.dport),
            "dst_host_srv_diff_host_rate": self._rate(host_srv, lambda c: c.src != conn.src),
            "dst_host_serror_rate": self._rate(host_list, is_serror),
            "dst_host_srv_serror_rate": self._rate(host_srv, is_serror),
            "dst_host_rerror_rate": self._rate(host_list, is_rerror),
            "dst_host_srv_rerror_rate": self._rate(host_srv, is_rerror),
        }

        self.recent.append((now, conn))
        hq.append(conn)
        return feat
