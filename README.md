# AI-Based Smart Firewall for Small Network Security

A machine-learning intrusion detection and prevention system for small networks.
Live network traffic is captured, converted into NSL-KDD style features, classified
by a trained Random Forest model, and malicious sources are automatically blocked at
the firewall while an email alert is raised. Everything is driven from a real-time
web console.

This is the reference implementation of the Final Year Project proposal
*"AI-Based Smart Firewall for Small Network Security Using Machine Learning &
Intrusion Detection"* (AbdiAziz Hassan Osman, BS Information Technology, IIUI).

---

## 1. What it does

| Layer | Responsibility |
|-------|----------------|
| **Capture** | Sniffs live packets with `scapy`, reassembles them into bidirectional connections, and derives 25 NSL-KDD features (basic + 2-second time-based + 100-connection host-based). |
| **Detection** | A Random Forest classifier (trained on NSL-KDD) labels each connection *normal* or *attack* and estimates a confidence. A lightweight heuristic names the attack type (port scan / DoS / brute force / probe). |
| **Prevention** | Once a source crosses the block threshold it is dropped automatically. Three enforcement back-ends are supported: **pfSense** REST API, local **iptables**, or **simulation** (database only). The strongest available one is auto-selected. |
| **Alerting** | Every block raises an alert in the console and, if SMTP is configured, sends an email. |
| **Console** | A responsive multi-page web GUI (login/sign-up, dashboard, live traffic, threats, blocked IPs, model analytics, activity log, settings, about) with real-time updates. |

### Model performance (this build)

Trained on NSL-KDD (125,973 train rows, 22,544 test rows, 25 features). Random
Forest was selected over Decision Tree and Naïve Bayes.

| Evaluation | Accuracy | Precision | Recall | F1 |
|------------|:--------:|:---------:|:------:|:--:|
| **Within-distribution** (80/20 split of KDDTrain+) | 99.90% | 99.93% | 99.86% | 99.89% |
| **Generalisation** (train KDDTrain+, test KDDTest+) | 78.32% | 96.67% | 64.12% | 77.10% |

The within-distribution number is the headline accuracy (well above the 90% target).
The generalisation number is reported honestly: KDDTest+ deliberately contains attack
types absent from training, so it measures how the model copes with *novel* attacks —
a realistic lower bound. Both numbers are shown on the **Model Analytics** page.

---

## 2. Requirements

- **Linux** (Ubuntu 22.04+, Debian, or Kali all work). The app also runs on macOS/Windows
  for the GUI, but live capture and iptables enforcement are Linux features.
- **Python 3.10 – 3.12**
- Root privileges *only* if you want live packet capture and real iptables blocking.
  Without root the app still runs fully in **simulation** mode using the built-in
  attack generator.

---

## 3. Installation

```bash
# 1. unzip and enter the project
unzip smart_firewall.zip
cd smart_firewall

# 2. create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. install dependencies
pip install -r requirements.txt
```

The trained model (`ml/artifacts/firewall_model.joblib`) ships with the project, so
you do **not** need to retrain to run the app.

---

## 4. Running the app

### Demo mode (no root, works anywhere)

```bash
python run.py
```

Open <http://127.0.0.1:5000> and log in with:

```
username: admin
password: admin123
```

On the **Dashboard**, use the **Simulate** control to inject a benign / port-scan /
DoS / brute-force / mixed traffic scenario. The synthetic traffic runs through the
*same* detection pipeline as real packets, so you can watch detections, blocks and
alerts appear live without needing an attacker machine.

### Live mode (real capture + real blocking, needs root)

```bash
sudo -E .venv/bin/python run.py
```

Then on the **Dashboard** press **Start Capture** (optionally set the interface, e.g.
`eth0`, on the Settings page). Running as root lets the app open raw sockets for
capture and install `iptables` DROP rules in its own `SMARTFW` chain. If it is not
run as root, capture reports *"root required"* and enforcement falls back to
simulation — nothing crashes.

---

## 5. Testing with real attacks from Kali Linux

This mirrors the test setup in the proposal: a **Kali** attacker VM and the
**Smart Firewall** host on the same host-only / internal network in VirtualBox.

### Setup

1. Two VMs on the same VirtualBox *host-only* or *internal* network, e.g.
   - Firewall host: `192.168.56.10`
   - Kali attacker: `192.168.56.20`
2. On the firewall host, start the app **as root** and press **Start Capture**:
   ```bash
   sudo -E .venv/bin/python run.py
   ```
3. Keep the **Dashboard** and **Live Traffic** pages open while you attack.

### Attack commands (run these on Kali, targeting the firewall host)

**Port scan — detected as "Port scan":**
```bash
nmap -sS -p 1-1000 192.168.56.10        # SYN scan across 1000 ports
nmap -sV 192.168.56.10                  # service/version scan (noisier)
```

**Denial of service / flood — detected as "DoS / flood":**
```bash
sudo hping3 -S --flood -p 80 192.168.56.10     # SYN flood on port 80
sudo hping3 -1 --flood 192.168.56.10           # ICMP flood
```

**Brute force — detected as "Brute force":**
```bash
# many rapid connections to an auth service (ssh/ftp). Even against a closed
# port the repeated connection attempts show the brute-force pattern.
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.10
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.56.10
```

### What you should see

- **Live Traffic** fills with connections from the Kali IP, flagged red.
- Within a few seconds the attacker crosses the block threshold and appears on
  **Blocked IPs** with the detected attack type and confidence.
- A matching entry shows up under **Threats** (and an email is sent if SMTP is set).
- If running as root, verify the real rule was installed:
  ```bash
  sudo iptables -L SMARTFW -n -v
  ```
  You should see a DROP rule for the Kali IP. From Kali, further packets to the
  host now time out. Unblock the IP from the **Blocked IPs** page to remove the rule.

> Tip: add the attacker IP to the whitelist on the **Settings** page if you want to
> observe detections without auto-blocking your test machine.

---

## 6. Retraining the model (optional)

The dataset files are large and are not required to run the app, but you can retrain:

```bash
# download NSL-KDD into data/ (KDDTrain+.txt and KDDTest+.txt), then:
python ml/train_model.py
```

This re-evaluates Random Forest, Decision Tree and Naïve Bayes on both the
within-distribution split and the KDDTest+ generalisation set, prints the comparison,
and writes `ml/artifacts/firewall_model.joblib` and `ml/artifacts/metrics.json`
(which the Analytics page reads).

---

## 7. Configuration

All settings have working defaults. To override, copy `.env.example` to `.env` and
edit it (pfSense credentials, SMTP for email alerts, admin password, secret key).
Detection thresholds (block threshold, minimum confidence, auto-block on/off,
whitelist, capture interface, enforcement mode) are editable live on the
**Settings** page.

---

## 8. Project layout

```
smart_firewall/
├── run.py                  # entry point
├── config.py               # environment-driven configuration
├── requirements.txt
├── ml/
│   ├── preprocess.py       # NSL-KDD feature selection + encoding
│   ├── train_model.py      # trains & compares RF / DT / NB, exports model
│   └── artifacts/          # firewall_model.joblib + metrics.json
├── engine/
│   ├── features.py         # packets -> connections -> 25 NSL-KDD features
│   ├── detector.py         # loads model, scores, names attack type
│   ├── firewall.py         # pfSense / iptables / simulation enforcement
│   └── alerts.py           # email alerting
├── app/
│   ├── __init__.py         # Flask app factory
│   ├── models.py           # users, events, alerts, blocked IPs, settings, logs
│   ├── monitor.py          # orchestration + synthetic attack generator
│   ├── auth.py             # login / signup / logout
│   ├── views.py            # page routes
│   └── api.py              # JSON API for the live dashboard
├── templates/              # Jinja2 pages
└── static/                 # CSS + JavaScript
```

---

## 9. Default credentials

```
username: admin
password: admin123
```

Change the password from `.env` (`ADMIN_PASSWORD`) before any non-local use, and you
can register additional accounts from the **Sign up** page.
