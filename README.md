# NetGuard — Network Intrusion Detection System

A real-time network IDS with a cyberpunk-styled web dashboard.
Detects **Port Scanning**, **Brute-Force Login Attempts**, and **DoS Attacks**,
logs every alert, and lets you block suspicious IPs from the UI.

---

## Project Structure

```
network-ids/
├── app.py                  ← Flask + SocketIO entry point
├── requirements.txt
├── README.md
├── backend/
│   ├── __init__.py
│   ├── detector.py         ← Threat detection engine
│   └── sniffer.py          ← Scapy packet capture (+ demo mode)
├── templates/
│   └── dashboard.html      ← Full dashboard UI
├── static/                 ← (css / js assets if added later)
└── logs/
    ├── ids.log             ← Text log (auto-created)
    └── alerts.json         ← JSON alert log (auto-created)
```

---

## Quick Start

### 1 — Clone / download the project
```bash
cd network-ids
```

### 2 — Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### 4 — Run the server

**Just want to see it working (no root needed):**
```bash
python app.py --demo
```

**Live packet capture — Linux / macOS (needs root):**
```bash
sudo venv/bin/python app.py          # use the venv's python, plain `sudo python` skips the venv
```

**Live packet capture — Windows (Administrator terminal, [Npcap](https://npcap.com) installed):**
```powershell
python app.py
```

Options: `--demo` (simulated traffic) · `--iface eth0` (one interface) ·
`--port 8080` · `--host 0.0.0.0` (expose on LAN — the dashboard has no login).

> **No root / no Npcap / wrong interface?**
> The sniffer automatically falls back to **Demo Mode**, which simulates
> realistic traffic including port scans, brute-force, and DoS bursts —
> and prints why it switched.

### 5 — Open the dashboard
```
http://localhost:5000
```

---

## Detection Rules

| Threat | Trigger |
|---|---|
| **Port Scan** | ≥ 15 distinct destination ports probed by one IP within 10 s (TCP packets *without* the ACK bit: SYN, FIN, NULL, Xmas) |
| **Brute Force** | ≥ 10 SYN packets to a login port (22, 3389, 3306 …) within 10 s |
| **DoS Attack** | ≥ 500 packets/second from a single source IP |

> Replies and established-session traffic (ACK set) are deliberately ignored, so a
> busy server answering many clients is not flagged as a scanner. A legitimate
> high-bandwidth download can still exceed 500 pkt/s — raise `DOS_THRESHOLD` if needed.

Thresholds are constants at the top of `backend/detector.py` — tune freely.

---

## Dashboard Features

| Feature | Details |
|---|---|
| Live traffic stats | Total / TCP / UDP / ICMP packet counters via WebSocket |
| Protocol breakdown chart | Doughnut chart (Chart.js) |
| Alert timeline | Per-minute bar chart of alert frequency |
| Live alert stream | Colour-coded severity (CRITICAL / HIGH / MEDIUM) |
| Suspicious IP table | Attack type, hit count, last-seen time |
| Block / Unblock IP | Sidebar form **or** per-row button in the table |
| Attack log | Last 100 alerts from `logs/alerts.json`, newest first |

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/snapshot` | Full state dump (stats, alerts, suspicious, blocked) |
| GET | `/api/alerts` | Recent alerts (ring-buffer, max 200) |
| GET | `/api/suspicious` | Suspicious IP registry |
| GET | `/api/blocked` | Currently blocked IPs |
| GET | `/api/logs` | Last 100 entries from the JSON log file |
| POST | `/api/block` | `{"ip": "1.2.3.4"}` — block an IP |
| POST | `/api/unblock` | `{"ip": "1.2.3.4"}` — unblock an IP |

### WebSocket Events (Socket.IO)

| Event | Direction | Payload |
|---|---|---|
| `init` | server → client | Full snapshot on connect |
| `stats_update` | server → client | Packet counters (every second) |
| `new_alert` | server → client | Single alert dict |
| `ip_blocked` | server → client | `{"ip": "..."}` |
| `ip_unblocked` | server → client | `{"ip": "..."}` |

---

## Customising

**Add more login ports** — edit `LOGIN_PORTS` in `backend/detector.py`.

**Change thresholds** — edit the constants at the top of `backend/detector.py`:
```python
PORT_SCAN_THRESHOLD   = 15   # distinct ports
BRUTE_FORCE_THRESHOLD = 10   # SYN attempts
DOS_THRESHOLD         = 500  # packets/second
TIME_WINDOW           = 10   # seconds
```

**Sniff a specific interface:**
```bash
python app.py --iface eth0        # or: IDS_IFACE=eth0 python app.py
```

**Note on blocking:** "Block" tells the IDS to ignore/stop alerting on that IP.
It does **not** add firewall rules to your OS.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Dashboard loads but stays at 0 packets | Live capture is running but the network is quiet, or you're not root. Try `python app.py --demo`. |
| `[IDS] Live capture failed … switching to DEMO mode` | Read the reason in the message: missing Npcap (Windows), wrong `--iface`, or no permission. |
| `sudo python app.py` → `ModuleNotFoundError` | `sudo` ignores your venv. Use `sudo venv/bin/python app.py`. |
| Alerts appear only once per attacker | By design: one alert per IP per attack type, reset every 60 s. |

---

## Requirements

- Python 3.9+ (tested on 3.12)
- Linux / macOS / Windows
- Root / Administrator privileges for live capture (optional — demo mode otherwise)
