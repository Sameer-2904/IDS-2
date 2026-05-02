# Network Intrusion Detection System (IDS)

A Python-based Network IDS that monitors live network traffic in real time, detects suspicious activity (port scanning, brute-force login attempts, DoS behaviour), persists structured alerts, and surfaces findings through a Flask web dashboard.

---

## Prerequisites

- Python 3.11 or later
- **Root / Administrator privileges** — required to open a raw network socket for packet capture (and for the optional IP-blocking feature)
- On Linux: `iptables` must be installed if IP blocking is enabled
- On Windows: `netsh` is built-in; run the terminal as Administrator

---

## Installation

1. Clone or download the repository.

2. (Recommended) Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   # Linux / macOS
   source .venv/bin/activate
   # Windows
   .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## Configuration

All settings are read from a YAML file (default: `config.yaml` in the working directory). Pass a custom path with `--config`:

```bash
python main.py --config /path/to/my-config.yaml
```

### Configuration reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interface` | string | *(required)* | Network interface to capture on (e.g. `eth0`, `en0`, `Wi-Fi`) |
| `bpf_filter` | string | `""` | Optional BPF filter string (e.g. `"tcp port 80"`). Empty = capture all |
| `port_scan_threshold` | int > 0 | `20` | Distinct destination ports per window before a PORT_SCAN alert fires |
| `port_scan_window_seconds` | int > 0 | `10` | Port-scan observation window duration (seconds) |
| `brute_force_threshold` | int > 0 | `10` | TCP SYN packets per monitored port per window before a BRUTE_FORCE alert fires |
| `brute_force_window_seconds` | int > 0 | `10` | Brute-force observation window duration (seconds) |
| `brute_force_ports` | list[int] | `[22, 21, 3389, 5900]` | Destination ports monitored for brute-force activity |
| `dos_threshold_pps` | int > 0 | `100` | Packets per second per source IP before a DOS alert fires |
| `dos_window_seconds` | int > 0 | `10` | DoS observation window duration (seconds) |
| `dos_consecutive_intervals` | int > 0 | `3` | Consecutive 1-second intervals above threshold required before a DOS alert fires |
| `dashboard_port` | int > 0 | `5000` | TCP port the Flask dashboard listens on |
| `log_store_path` | string | `ids.db` | Path to the SQLite database file |
| `log_file_path` | string | `ids.log` | Path to the structured JSON log file |
| `log_level` | string | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `ip_blocker_enabled` | bool | `false` | Enable the IP-blocking feature (requires root/admin) |

A fully-commented sample configuration is provided in `config.yaml`.

---

## Running the IDS

```bash
# Linux / macOS (root required for raw socket)
sudo python main.py --config config.yaml

# Windows (run terminal as Administrator)
python main.py --config config.yaml
```

The IDS will:
1. Load and validate the configuration.
2. Open the network interface for packet capture.
3. Start the detection engine and alert manager.
4. Start the Flask dashboard.
5. Log all events to `ids.log` (JSON) and stdout.

Stop the IDS gracefully with **Ctrl+C** (SIGINT) or by sending SIGTERM. The IDS will flush all pending writes and exit with code 0.

---

## Accessing the Dashboard

Once the IDS is running, open a browser and navigate to:

```
http://localhost:5000
```

(Replace `5000` with your configured `dashboard_port`.)

The dashboard provides:
- **Traffic Stats** — total packets captured and a live packet-rate chart (updated every 2 seconds)
- **Alerts** — the 50 most recent alerts with severity colour coding
- **Suspicious IPs** — all flagged source IPs sorted by alert count
- **Logs** — searchable, paginated alert history with client-side filtering

If `ip_blocker_enabled: true` is set in the config, each suspicious IP row shows **Block** / **Unblock** buttons.

---

## Running Tests

```bash
# Run the full test suite
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_detection.py -v

# Run with coverage (requires pytest-cov)
python -m pytest tests/ --cov=ids --cov-report=term-missing
```

All tests mock Scapy and subprocess calls — no network interface or firewall privileges are required to run the test suite.

---

## Folder Structure

```
.
├── main.py                     # Entry point — wires all components together
├── config.yaml                 # Sample configuration file
├── requirements.txt            # Pinned Python dependencies
├── ids/                        # Main package
│   ├── __init__.py
│   ├── capture.py              # PacketCaptureEngine — Scapy-based packet capture
│   ├── detection.py            # DetectionEngine, PortScanDetector,
│   │                           #   BruteForceDetector, DoSDetector
│   ├── alert_manager.py        # AlertManager — UUID assignment, persistence, ring buffer
│   ├── log_store.py            # LogStore — SQLite persistence layer
│   ├── models.py               # Shared data models (Alert, SuspiciousIP, enums)
│   ├── config.py               # DetectionConfig (pydantic v2) and load_config()
│   ├── logger.py               # JSON structured logging setup
│   ├── ip_blocker.py           # IPBlocker — iptables / netsh firewall rules
│   └── dashboard/              # Flask web dashboard
│       ├── __init__.py         # create_app() factory
│       ├── routes.py           # REST API route handlers
│       └── templates/
│           └── index.html      # Bootstrap 5 + Chart.js single-page UI
└── tests/                      # pytest test suite
    ├── test_config.py
    ├── test_logger.py
    ├── test_models.py
    ├── test_log_store.py
    ├── test_alert_manager.py
    ├── test_detection.py
    ├── test_detection_engine.py
    ├── test_capture.py
    ├── test_dashboard.py
    └── test_ip_blocker.py
```
