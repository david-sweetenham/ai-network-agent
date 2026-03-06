# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Run a network scan (CLI):**
```bash
./run_scan.sh
```

**Start the web dashboard:**
```bash
./start_dashboard.sh
```

**Activate the venv manually:**
```bash
source venv/bin/activate
```

**Install a new dependency:**
```bash
source venv/bin/activate && pip install <package>
```

There are no tests in this project.

## Architecture

This is a home network monitoring agent with three Python modules and a Flask web UI.

### Data Flow

**Scheduled scan path** (`run_scan.sh`):
1. Calls `network_summary.init_db()` to ensure tables exist
2. Calls `network_summary.collect_summary()` — runs `arp-scan`, `vnstat`, `ss` via subprocess and pings `8.8.8.8` via `ping3`
3. Sends the summary + history to a local Ollama instance (`http://localhost:11434`) using the `mistral` model
4. Saves the text summary to the `summaries` table in `network_history.db`

**Dashboard path** (`start_dashboard.sh` → `dashboard.py`):
- Flask app on the default port (5000), debug mode enabled
- `/` — renders the main dashboard (reads alerts, latest summary/analysis from in-memory globals)
- `/run` — triggers a full scan inline (same logic as `run_scan.sh`), updates in-memory `latest_summary` / `latest_analysis` globals, then redirects to `/`
- `/metrics` — returns JSON of all historical metrics for Chart.js charts (bandwidth, device count, duplicate ARP)

### Module Responsibilities

- **`network_summary.py`** — data collection, DB schema, AI query, and the `MetricAdapter` class that bridges raw metrics to the alert system
- **`alerts.py`** — `Alert` dataclass, `AlertStorage` (SQLite persistence in `network_history.db`), and `AlertEngine` (threshold checks with a 10-minute cooldown per alert key)
- **`dashboard.py`** — Flask app; HTML/CSS/JS is a single inline `TEMPLATE` string; uses `AlertStorage` for alert panels and Chart.js (CDN) for trend charts

### Databases

- **`network_history.db`** — primary database used by all modules; contains `summaries`, `metrics`, and `alerts` tables
- **`network.db`** — older/unused database file; can be ignored

### External Dependencies

System tools that must be installed: `arp-scan`, `vnstat`, `iproute2` (`ss`).

Ollama must be running locally with the `mistral` model pulled (`ollama pull mistral`). The AI call is optional — failures return a string message rather than raising.

### Alert Logic

`AlertEngine.run_checks()` reads the latest metric row and pings the network to check host reachability, latency (>80ms threshold), and packet loss (>5%). It emits `critical`/`warning` alerts for new problems and `info` alerts when a condition clears. `AlertStorage` deduplicates by title so the same alert is not inserted twice while unresolved.
