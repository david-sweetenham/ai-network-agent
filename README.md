# AI Network Advisor

A self-hosted home network monitoring agent with an AI-powered web dashboard. Scans your LAN on a schedule, analyses trends using a local LLM (no cloud, no API keys), raises alerts for anomalies, and lets you interrogate your network in plain English.

---

## Features

**Monitoring & Scanning**
- ARP scan to discover all devices on the local network
- Bandwidth tracking via `vnstat`
- Active connection counting via `ss`
- Internet connectivity check with latency and packet-loss measurement
- Scheduled scanning via cron (or on-demand from the dashboard)

**AI Analysis**
- Sends scan summaries to a local [Ollama](https://ollama.com) instance running `mistral`
- Compares current metrics against recent history to detect anomalies
- Generates plain-English analysis and actionable suggestions
- Floating AI chat popup available on every page — ask anything about your network
- Suggested starter questions so you know what to ask

**Alerting**
- Threshold-based alerts: high latency (>80ms), packet loss (>5%), host unreachable, duplicate ARP, new unknown devices
- Alerts categorised by type with colour-coded badges (New Device, Packet Loss, Unreachable, Duplicate ARP, High Latency)
- Alert escalation tracking — fires again if a condition persists
- Auto-resolve when a condition clears
- Desktop notifications (via `notify-send`) for critical and warning events
- Cooldown state persisted to SQLite so restarts don't reset alert frequency

**Device Inventory**
- Tracks every MAC address ever seen, with first/last seen timestamps
- Assign human-readable labels to devices (e.g. "David's laptop", "Smart TV")
- Click any "New device" alert to see device details in a modal
- Unlabelled devices are visually flagged in the table

**Dashboard**
- Tabbed layout: Overview, Summary, Devices, Trends
- Active alert count badge on the Overview tab
- Dark and light theme with toggle (preference saved to localStorage)
- Collapsible cards (state saved to localStorage)
- Trend charts for bandwidth, device count, and duplicate ARP events (Chart.js)
- CSV export endpoints for metrics, devices, and alerts — compatible with Power BI and Databricks

**Security**
- HTTP Basic Auth on all routes
- LAN-accessible (binds to `0.0.0.0`) — keep behind a firewall or router NAT
- All AI processing is local — no data leaves your network

---

## Screenshots

> _Screenshots coming soon._
>
> The dashboard has four tabs: **Overview** (active alerts and AI suggestions), **Summary** (latest scan results and AI analysis), **Devices** (full device inventory with labels), and **Trends** (bandwidth, device count, and duplicate ARP charts). A floating chat button is available on every tab.

---

## Requirements

### System packages

| Package | Purpose |
|---|---|
| `arp-scan` | LAN device discovery |
| `vnstat` | Bandwidth usage tracking |
| `iproute2` | Active connection counting (`ss` command) |
| `python3` | Runtime (3.10+ required, developed on 3.14) |
| `pip` | Python package installer |

Install on Debian/Ubuntu/Arch:

```bash
# Debian / Ubuntu
sudo apt install arp-scan vnstat iproute2 python3 python3-pip python3-venv

# Arch / CachyOS
sudo pacman -S arp-scan vnstat iproute2 python python-pip
```

### Ollama + Mistral

Ollama runs the LLM locally. Install it and pull the model:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral
```

Ollama must be running (`ollama serve` or via systemd) before starting a scan. If Ollama is unavailable, the AI analysis step is skipped gracefully — the rest of the scan still runs.

### Python packages

```
flask>=3.0
ping3>=4.0
requests>=2.28
```

These are installed automatically in the venv during setup.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/david-sweetenham/ai-network-agent.git
cd ai-network-agent

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install flask ping3 requests

# 4. Make the helper scripts executable
chmod +x run_scan.sh start_dashboard.sh
```

### Optional: configure credentials

The dashboard is protected by HTTP Basic Auth. The defaults are `admin` / `changeme`. Change them in [dashboard.py](dashboard.py) before exposing the dashboard on your network:

```python
DASHBOARD_USER = "admin"
DASHBOARD_PASS = "changeme"   # <-- change this
```

---

## Running

### Start the web dashboard

```bash
./start_dashboard.sh
```

The dashboard will be available at `http://<your-machine-ip>:5000` from any device on your LAN.

### Run a manual scan (CLI)

```bash
./run_scan.sh
```

This collects metrics, requests an AI analysis, saves results to the database, and evaluates alerts. Output is printed to stdout.

You can also trigger a scan from the dashboard using the **Run Scan** button, which runs the same logic inline and redirects back to the refreshed dashboard.

### Schedule automatic scans with cron

```bash
crontab -e
```

Add a line to scan every 3 hours (adjust the path to match your install location):

```cron
0 */3 * * * /home/david/ai-network-agent/run_scan.sh >> /home/david/ai-network-agent/scan.log 2>&1
```

---

## Data exports

Three CSV endpoints are available for integration with external tools:

| Endpoint | Contents |
|---|---|
| `/export/metrics.csv` | Historical metric readings (timestamp, device count, bandwidth, etc.) |
| `/export/devices.csv` | Full device inventory with first/last seen timestamps |
| `/export/alerts.csv` | Complete alert history including resolved alerts |

These can be used as a "Get Data from Web" source in Power BI, or fetched via `requests.get()` in a Databricks notebook.

---

## Project structure

```
ai-network-agent/
├── network_summary.py   # Data collection, DB schema, AI query, alert bridging
├── alerts.py            # Alert dataclass, storage, and threshold engine
├── dashboard.py         # Flask app; full HTML/CSS/JS as inline template string
├── run_scan.sh          # CLI entry point — safe to run from cron
├── start_dashboard.sh   # Starts the Flask dev server
└── network_history.db   # SQLite database (created on first run)
```

### Database tables

| Table | Contents |
|---|---|
| `metrics` | One row per scan: timestamp, device count, bandwidth, connections, duplicate ARP |
| `summaries` | Raw scan text and AI analysis from each run |
| `devices` | Device inventory: MAC, IP, first/last seen, label |
| `alerts` | Alert history with level, title, message, resolved flag, fire count |
| `alert_cooldowns` | Persisted cooldown state so alert frequency survives restarts |
| `pending_actions` | AI-suggested actions awaiting approval or rejection |

---

## Tech stack

| Layer | Technology |
|---|---|
| Language | Python 3 |
| Web framework | Flask 3 |
| Database | SQLite (via `sqlite3` stdlib) |
| AI / LLM | Ollama (local) + Mistral 7B |
| Network scanning | `arp-scan`, `ping3`, `vnstat`, `ss` |
| Frontend charts | Chart.js (CDN) |
| Frontend styles | Vanilla CSS with custom properties (no framework) |
| Auth | HTTP Basic Auth |

No external AI APIs, no Docker required, no cloud dependencies. Everything runs on the local machine.

---

## Notes

- `arp-scan` requires root or `CAP_NET_RAW`. If you run into permission errors, either run as root or set the capability: `sudo setcap cap_net_raw+ep $(which arp-scan)`
- `vnstat` must have been collecting data for at least one monitoring period before bandwidth figures appear
- The Flask server runs in debug mode (`debug=True`) which is fine for a home network tool but should not be exposed to the internet
