"""
Enforcement layer.

The classifier decides *what* to block; this module decides *how*. Three
back-ends are supported and chosen at start-up:

  * pfsense     - pushes the offending address into a pfSense alias/table over
                  its REST API. This is the deployment target described in the
                  proposal and is used when PFSENSE_URL is configured.
  * iptables    - drops the address on the local Linux host with an nftables/
                  iptables rule. Used when the app runs as root on the gateway,
                  which is how the single-box test setup blocks real attackers.
  * simulation  - records the block in the database only. The default when the
                  process is unprivileged and no pfSense is configured, so the
                  full pipeline can still be demonstrated safely.

The controller auto-selects the strongest back-end available unless one is
forced through configuration.
"""

import shutil
import subprocess

try:
    import requests
except ImportError:  # only the optional pfSense adapter needs it
    requests = None

CHAIN = "SMARTFW"


class SimulationAdapter:
    name = "simulation"

    def available(self):
        return True

    def setup(self):
        return True

    def block(self, ip):
        return True

    def unblock(self, ip):
        return True


class IptablesAdapter:
    name = "iptables"

    def available(self):
        if not shutil.which("iptables"):
            return False
        try:
            r = subprocess.run(["iptables", "-L", "-n"],
                               capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def setup(self):
        try:
            subprocess.run(["iptables", "-N", CHAIN],
                           capture_output=True, timeout=5)
            check = subprocess.run(["iptables", "-C", "INPUT", "-j", CHAIN],
                                   capture_output=True, timeout=5)
            if check.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "-j", CHAIN],
                               capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def block(self, ip):
        try:
            check = subprocess.run(
                ["iptables", "-C", CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5)
            if check.returncode == 0:
                return True
            r = subprocess.run(
                ["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def unblock(self, ip):
        try:
            subprocess.run(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"],
                           capture_output=True, timeout=5)
            return True
        except Exception:
            return False


class PfSenseAdapter:
    """
    Talks to a pfSense box running the REST API package. The address is added to
    a firewall alias (a named table) that a floating block rule references, then
    a filter reload applies it. Credentials come from the app configuration.
    """
    name = "pfsense"

    def __init__(self, base_url, api_key, api_secret, alias="smartfw_block",
                 verify_tls=False):
        self.base = base_url.rstrip("/")
        self.alias = alias
        self.verify = verify_tls
        self.headers = {"Authorization": f"{api_key} {api_secret}"}

    def available(self):
        if requests is None or not self.base:
            return False
        try:
            r = requests.get(f"{self.base}/api/v1/system/version",
                             headers=self.headers, verify=self.verify, timeout=6)
            return r.status_code == 200
        except Exception:
            return False

    def setup(self):
        return self.available()

    def _current(self):
        r = requests.get(f"{self.base}/api/v1/firewall/alias",
                         headers=self.headers, verify=self.verify, timeout=8)
        r.raise_for_status()
        for a in r.json().get("data", []):
            if a.get("name") == self.alias:
                return set(a.get("address", "").split())
        return set()

    def _apply(self, addresses):
        requests.put(
            f"{self.base}/api/v1/firewall/alias",
            headers=self.headers, verify=self.verify, timeout=8,
            json={"name": self.alias, "type": "host",
                  "address": " ".join(sorted(addresses)),
                  "apply": True},
        ).raise_for_status()

    def block(self, ip):
        try:
            addrs = self._current()
            addrs.add(ip)
            self._apply(addrs)
            return True
        except Exception:
            return False

    def unblock(self, ip):
        try:
            addrs = self._current()
            addrs.discard(ip)
            self._apply(addrs)
            return True
        except Exception:
            return False


class FirewallController:
    def __init__(self, mode="auto", pfsense_cfg=None):
        self.pfsense_cfg = pfsense_cfg or {}
        self.adapter = self._select(mode)
        self.adapter.setup()

    def _select(self, mode):
        pf = None
        if self.pfsense_cfg.get("url"):
            pf = PfSenseAdapter(
                self.pfsense_cfg["url"],
                self.pfsense_cfg.get("api_key", ""),
                self.pfsense_cfg.get("api_secret", ""),
                self.pfsense_cfg.get("alias", "smartfw_block"),
                self.pfsense_cfg.get("verify_tls", False),
            )
        if mode == "pfsense":
            return pf or SimulationAdapter()
        if mode == "iptables":
            ipt = IptablesAdapter()
            return ipt if ipt.available() else SimulationAdapter()
        if mode == "simulation":
            return SimulationAdapter()
        # auto: strongest first
        if pf and pf.available():
            return pf
        ipt = IptablesAdapter()
        if ipt.available():
            return ipt
        return SimulationAdapter()

    @property
    def mode(self):
        return self.adapter.name

    def block(self, ip):
        return self.adapter.block(ip)

    def unblock(self, ip):
        return self.adapter.unblock(ip)
