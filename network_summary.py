import subprocess
import sqlite3
import re
import json
import requests
from datetime import datetime
from ping3 import ping
from alerts import Alert, AlertEngine, AlertStorage

DB_FILE = "network_history.db"

# -----------------------------
# Database setup
# -----------------------------

def init_db():
    # Creates the summaries and metrics tables in the SQLite database if they don't exist.
    # Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    # Also migrates older databases that lack the analysis column in summaries.
    # Must be called before any other DB operations (e.g. at the start of a scan).
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS summaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            summary TEXT,
            analysis TEXT DEFAULT ''
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_count INTEGER,
            dup_arp INTEGER,
            connections INTEGER,
            bandwidth_today REAL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    # Migrate older databases that don't have the analysis column yet.
    # SQLite doesn't support ALTER TABLE ADD COLUMN IF NOT EXISTS, so we use try/except.
    try:
        c.execute("ALTER TABLE summaries ADD COLUMN analysis TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # Column already exists — safe to ignore

    # Migrate devices table to add label column for known-device tagging.
    try:
        c.execute("ALTER TABLE devices ADD COLUMN label TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    c.execute("""
        CREATE TABLE IF NOT EXISTS pending_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,
            params TEXT NOT NULL,
            display_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'pending'
        )
    """)

    conn.commit()
    conn.close()

# -----------------------------
# Save text summary (used by dashboard)
# -----------------------------

def save_summary(summary, analysis=""):
    # Inserts a plain-text network summary and optional AI analysis into the summaries table.
    # init_db() must have been called first to ensure the table and analysis column exist.
    # Used by both the CLI scan and the dashboard /run route to persist results.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute(
        "INSERT INTO summaries (timestamp, summary, analysis) VALUES (?, ?, ?)",
        (str(datetime.now()), summary, analysis)
    )

    conn.commit()
    conn.close()


def load_latest_summary():
    # Returns the most recent (summary, analysis) pair from the summaries table.
    # Used by the dashboard on startup to restore the last scan result without needing a rescan.
    # Returns ("", "") if no summaries have been saved yet.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT summary, analysis FROM summaries ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return row[0], row[1] or ""
    return "", ""


def load_recent_summaries(limit=8):
    # Returns the last `limit` (timestamp, summary) pairs in chronological order (oldest first).
    # Passed to ask_ai() as historical context so the AI can spot trends across scans
    # rather than only seeing the current snapshot.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, summary FROM summaries ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return list(reversed(rows))  # oldest first so the AI reads chronologically

# -----------------------------
# Metric storage
# -----------------------------

def save_metrics(device_count, dup_arp, connections, bandwidth):
    # Inserts a single row of numeric metrics into the metrics table with the current timestamp.
    # Called after every scan so that trend charts in the dashboard have historical data to display.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO metrics VALUES (NULL,?,?,?,?,?)",
        (str(datetime.now()), device_count, dup_arp, connections, bandwidth)
    )
    conn.commit()
    conn.close()


def load_recent_metrics(limit=5):
    # Returns the most recent `limit` metric rows from the database, newest first.
    # Each row is a tuple of (device_count, dup_arp, connections, bandwidth_today).
    # Used by detect_changes() to compute rolling averages and by MetricAdapter.get_latest()
    # to confirm that at least one metric row exists before running alert checks.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT device_count, dup_arp, connections, bandwidth_today FROM metrics ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return rows

# -----------------------------
# Device inventory
# -----------------------------

# Matches lines like: "192.168.1.1\taa:bb:cc:dd:ee:ff\tVendor Name"
# The optional third capture group grabs the vendor name that arp-scan appends.
_MAC_RE = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)\s+([\da-f]{2}(?::[\da-f]{2}){5})(?:\s+(.+))?',
    re.IGNORECASE
)

def parse_devices(arp_raw):
    # Extracts (mac, ip, vendor) tuples from raw arp-scan output.
    # The vendor comes from arp-scan's built-in OUI database (e.g. "Apple, Inc.").
    # DUP lines share the same MAC and collapse on upsert; the "(DUP: N)" suffix
    # is stripped from the vendor field before storing.
    devices = []
    for line in arp_raw.split("\n"):
        match = _MAC_RE.search(line)
        if match:
            ip = match.group(1)
            mac = match.group(2).lower()
            vendor = match.group(3) or ""
            vendor = re.sub(r'\s*\(DUP:\s*\d+\)', '', vendor).strip()
            devices.append((mac, ip, vendor))
    return devices


def upsert_devices(devices):
    # Inserts new devices and updates last_seen + ip_address for existing ones.
    # Uses mac_address as the stable identifier — IP addresses can change on DHCP networks.
    # For new devices, the vendor name from arp-scan is used as the initial label suggestion
    # so the user can see "Apple, Inc." straight away rather than a blank field.
    # For existing devices, the vendor is only applied if the user hasn't set a label yet.
    # Returns a list of MAC addresses that were inserted for the first time,
    # so callers can fire "new device" alerts for them.
    now = str(datetime.now())
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    new_macs = []
    for mac, ip, vendor in devices:
        c.execute("SELECT id, label FROM devices WHERE mac_address = ?", (mac,))
        row = c.fetchone()
        if row is None:
            new_macs.append(mac)
            c.execute(
                "INSERT INTO devices (mac_address, ip_address, first_seen, last_seen, label) VALUES (?, ?, ?, ?, ?)",
                (mac, ip, now, now, vendor)
            )
        else:
            # Preserve any label the user has set; fall back to vendor if still blank.
            current_label = row[1] or ""
            new_label = current_label if current_label else vendor
            c.execute(
                "UPDATE devices SET ip_address = ?, last_seen = ?, label = ? WHERE mac_address = ?",
                (ip, now, new_label, mac)
            )
    conn.commit()
    conn.close()
    return new_macs


def load_devices():
    # Returns all known devices ordered by most recently seen first.
    # Each row is (mac_address, ip_address, first_seen, last_seen, label).
    # Used by the dashboard /devices endpoint to populate the inventory table.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT mac_address, ip_address, first_seen, last_seen, label FROM devices ORDER BY last_seen DESC"
    )
    rows = c.fetchall()
    conn.close()
    return rows


def set_device_label(mac, label):
    # Saves a human-readable name for a device (e.g. "David's laptop", "Smart TV").
    # Once labelled, the corresponding "New device" alert can be auto-resolved
    # because the device is now acknowledged as known.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE devices SET label = ? WHERE mac_address = ?", (label, mac))
    conn.commit()
    conn.close()


# -----------------------------
# AI-suggested pending actions
# -----------------------------

def save_pending_actions(actions):
    # Inserts a list of AI-suggested actions into the pending_actions table.
    # Each action is a dict with action_type, params (JSON string), and display_text.
    # Skips duplicates — if a pending action with the same action_type and params already
    # exists, it is not inserted again (avoids flooding the queue across multiple scans).
    if not actions:
        return
    now = str(datetime.now())
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for action in actions:
        c.execute(
            "SELECT id FROM pending_actions WHERE action_type = ? AND params = ? AND status = 'pending'",
            (action["action_type"], action["params"])
        )
        if not c.fetchone():
            c.execute(
                "INSERT INTO pending_actions (action_type, params, display_text, created_at, status) VALUES (?, ?, ?, ?, 'pending')",
                (action["action_type"], action["params"], action["display_text"], now)
            )
    conn.commit()
    conn.close()


def load_pending_actions():
    # Returns all actions with status='pending', newest first.
    # Each row is (id, action_type, display_text, created_at).
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT id, action_type, display_text, created_at FROM pending_actions WHERE status = 'pending' ORDER BY created_at DESC"
    )
    rows = c.fetchall()
    conn.close()
    return rows


def approve_action(action_id):
    # Executes the action and marks it as approved.
    # Supported action types: label_device, resolve_alert.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT action_type, params FROM pending_actions WHERE id = ?", (action_id,))
    row = c.fetchone()
    if row:
        action_type, params_json = row
        params = json.loads(params_json)
        if action_type == "label_device":
            set_device_label(params["mac"], params["label"])
        elif action_type == "resolve_alert":
            AlertStorage().resolve_by_title(params["title"])
        c.execute("UPDATE pending_actions SET status = 'approved' WHERE id = ?", (action_id,))
    conn.commit()
    conn.close()


def reject_action(action_id):
    # Marks an action as rejected without executing it.
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE pending_actions SET status = 'rejected' WHERE id = ?", (action_id,))
    conn.commit()
    conn.close()


# -----------------------------
# Detect metric changes (used by dashboard)
# -----------------------------

def detect_changes(current, history):
    # Compares the current scan's metrics against the rolling average of recent history rows.
    # Returns a newline-separated string of any anomalies detected, or a "no changes" message.
    # Thresholds (all relative to the historical average):
    #   - device_count > avg + 3 → "Device count higher than usual"
    #   - dup_arp > avg + 2      → "Spike in duplicate ARP responses"
    #   - bandwidth > avg * 1.5  → "Bandwidth usage significantly above average"
    #   - connections > avg + 3  → "Higher number of active connections"
    # The output is appended to the AI prompt so the model can comment on changes.
    if not history:
        return "No historical data yet."

    avg_devices = sum(r[0] for r in history) / len(history)
    avg_dup = sum(r[1] for r in history) / len(history)
    avg_conn = sum(r[2] for r in history) / len(history)
    avg_bw = sum(r[3] for r in history) / len(history)

    device_count, dup_arp, connections, bandwidth = current

    changes = []

    if device_count > avg_devices + 3:
        changes.append("Device count higher than usual")

    if dup_arp > avg_dup + 2:
        changes.append("Spike in duplicate ARP responses")

    if bandwidth > avg_bw * 1.5:
        changes.append("Bandwidth usage significantly above average")

    if connections > avg_conn + 3:
        changes.append("Higher number of active connections")

    if not changes:
        return "No significant metric changes detected."

    return "\n".join(changes)

# -----------------------------
# Ping test
# -----------------------------

def check_network_health(host="8.8.8.8", attempts=4):
    # Pings the given host `attempts` times (default: 4 pings to 8.8.8.8) with a 2-second timeout each.
    # Returns a tuple of (reachable, avg_latency_ms, packet_loss_percent).
    # If all pings fail, avg_latency is returned as 999ms and reachable is False.
    # Used by MetricAdapter.get_latest() to feed live connectivity data into the alert engine.
    latencies = []
    lost = 0

    for _ in range(attempts):
        result = ping(host, timeout=2)
        if result is None:
            lost += 1
        else:
            latencies.append(result * 1000)  # ping3 returns seconds; convert to ms

    packet_loss = (lost / attempts) * 100
    reachable = len(latencies) > 0
    avg_latency = sum(latencies)/len(latencies) if latencies else 999

    return reachable, avg_latency, packet_loss


# -----------------------------
# Adapter for alerts
# -----------------------------

class MetricAdapter:
    # Bridges the raw data sources (DB metrics + live ping) into the dict format
    # that AlertEngine.run_checks() expects.
    # AlertEngine calls get_latest() each time run_checks() is invoked.

    def get_latest(self):
        # Fetches the most recent metric row from the DB to confirm data exists,
        # then performs a live ping to get current reachability and latency.
        # Returns None if no metrics have been saved yet (skips alert checks).
        # Returns a dict with keys: host_reachable, latency_ms, packet_loss.
        rows = load_recent_metrics(1)
        if not rows:
            return None

        device_count, dup_arp, connections, bandwidth = rows[0]
        reachable, latency, packet_loss = check_network_health()

        return {
            "host_reachable": reachable,
            "latency_ms": latency,
            "packet_loss": packet_loss,
        }


# -----------------------------
# Collect metrics
# -----------------------------

def get_connections_by_ip():
    # Parses live ss -tun output to count active TCP/UDP connections per peer IP.
    # Only counts peers in the 192.168.x.x range (local network devices).
    # Returns a dict mapping IP -> connection count, e.g. {"192.168.1.5": 3}.
    # This shows which local devices are actively communicating with this machine
    # without requiring gateway/router access.
    conn_raw = subprocess.getoutput("ss -tun | tail -n +2")
    counts = {}
    for line in conn_raw.split("\n"):
        parts = line.split()
        if len(parts) < 5:
            continue
        peer = parts[4]  # e.g. "192.168.1.5:54321"
        # Strip port — handle both IPv4 (addr:port) and IPv6 ([addr]:port)
        if peer.startswith("["):
            ip = peer.split("]")[0][1:]
        elif ":" in peer:
            ip = peer.rsplit(":", 1)[0]
        else:
            continue
        if ip.startswith("192.168."):
            counts[ip] = counts.get(ip, 0) + 1
    return counts

def collect_summary():
    # Runs three system tools to gather a snapshot of the current network state:
    #   - vnstat: reads today's total bandwidth usage (looks for "today" + "GiB" line)
    #   - arp-scan --localnet: discovers devices on the LAN; counts 192.168.x.x lines and "DUP" entries
    #   - ss -tun: lists active TCP/UDP connections; counts non-header lines
    # Returns a tuple of (summary_text, device_count, dup_count, connection_count, bandwidth_today).
    # The summary_text is a formatted string used for display and AI input.
    vnstat_raw = subprocess.getoutput("vnstat")
    arp_raw = subprocess.getoutput("arp-scan --localnet")
    conn_raw = subprocess.getoutput("ss -tun | tail -n +2")

    # Count only lines matching the arp-scan data format (IP + TAB + MAC) to avoid
    # accidentally counting error messages or header/footer lines that contain "192.168".
    device_count = len([l for l in arp_raw.split("\n") if re.match(r'192\.168\.\d+\.\d+\t', l)])
    dup_count = arp_raw.count("DUP")
    # Filter out blank lines so an empty ss output doesn't count as 1 connection.
    connection_count = len([l for l in conn_raw.split("\n") if l.strip()])

    # Parse bandwidth from vnstat — units vary depending on usage level (GiB, MiB, KiB).
    # The original code only matched "GiB" lines, silently returning 0.0 on low-traffic days.
    bandwidth_today = 0.0
    for line in vnstat_raw.split("\n"):
        if "today" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "GiB" and i > 0:
                    bandwidth_today = float(parts[i - 1])
                    break
                elif part == "MiB" and i > 0:
                    bandwidth_today = float(parts[i - 1]) / 1024
                    break
                elif part == "KiB" and i > 0:
                    bandwidth_today = float(parts[i - 1]) / (1024 * 1024)
                    break

    summary = f"""
HOME NETWORK SUMMARY
Generated: {datetime.now()}

Devices: {device_count}
Duplicate ARP: {dup_count}
Connections: {connection_count}
Bandwidth today: {bandwidth_today} GiB
"""
    devices = parse_devices(arp_raw)
    return summary, device_count, dup_count, connection_count, bandwidth_today, devices

# -----------------------------
# Desktop notifications
# -----------------------------

def _send_desktop_notification(title, message):
    # Fires a desktop notification via notify-send (requires libnotify).
    # Called when a new critical alert is saved or a warning is escalated to critical.
    # Errors are silently swallowed — the scan should never fail just because
    # the display server isn't available (e.g. running headless overnight).
    try:
        subprocess.run(
            ["notify-send", "--urgency=critical", f"Network Alert: {title}", message],
            timeout=5,
            capture_output=True
        )
    except Exception:
        pass

# -----------------------------
# AI analysis (Ollama)
# -----------------------------

def ask_ai(today_summary, history=""):
    # Sends the network summary and optional change history to a local Ollama instance
    # running the mistral model, and returns the model's analysis as a string.
    # The prompt instructs the model to reply "All looks normal." if nothing is unusual.
    # If the model has concrete actions to suggest, it appends a structured SUGGESTIONS block
    # which parse_ai_suggestions() will strip out and convert into pending_actions rows.
    # On any error (Ollama not running, timeout, bad response), returns a fallback string
    # so the dashboard can still display something instead of crashing.

    prompt = f"""
You are a home network monitoring assistant.
If nothing is unusual, reply with 'All looks normal.'

Analyse the following network summary and detected changes.

SUMMARY:
{today_summary}

HISTORY:
{history}

After your analysis, if you have specific action suggestions, append them in this EXACT format (no extra text around it):

---SUGGESTIONS---
LABEL_DEVICE|mac_address|Suggested Label|Reason
RESOLVE_ALERT|Alert Title|Reason
---END SUGGESTIONS---

Only include a SUGGESTIONS block if you have concrete, specific actions to suggest.
Supported actions:
- LABEL_DEVICE: suggest a human-readable name for a device you can identify from its MAC vendor or behaviour
- RESOLVE_ALERT: suggest dismissing an alert that appears to be a false positive or is no longer relevant

Do not include placeholder or example lines — only real suggestions based on the data.
"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "mistral",
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )

        return response.json()["response"]

    except Exception as e:
        return f"AI analysis unavailable: {e}"


def parse_ai_suggestions(response):
    # Splits the AI response into (clean_analysis_text, list_of_action_dicts).
    # Looks for a ---SUGGESTIONS--- / ---END SUGGESTIONS--- block appended by the model.
    # Strips the block from the display text so the dashboard only shows the human-readable part.
    # Each returned action dict has: action_type, params (JSON string), display_text.
    # Unknown or malformed suggestion lines are silently skipped.
    suggestions = []
    clean = response

    match = re.search(r'---SUGGESTIONS---(.*?)---END SUGGESTIONS---', response, re.DOTALL)
    if match:
        clean = (response[:match.start()] + response[match.end():]).strip()
        for line in match.group(1).strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split('|')]
            if parts[0] == 'LABEL_DEVICE' and len(parts) >= 3:
                mac = parts[1]
                label = parts[2]
                reason = parts[3] if len(parts) > 3 else ""
                display = f"Label {mac} as '{label}'" + (f" — {reason}" if reason else "")
                suggestions.append({
                    "action_type": "label_device",
                    "params": json.dumps({"mac": mac, "label": label}),
                    "display_text": display
                })
            elif parts[0] == 'RESOLVE_ALERT' and len(parts) >= 2:
                title = parts[1]
                reason = parts[2] if len(parts) > 2 else ""
                display = f"Resolve alert: '{title}'" + (f" — {reason}" if reason else "")
                suggestions.append({
                    "action_type": "resolve_alert",
                    "params": json.dumps({"title": title}),
                    "display_text": display
                })

    return clean, suggestions

# -----------------------------
# Chat (used by dashboard chatbot)
# -----------------------------

def ask_ai_chat(message, context=""):
    # Sends a user chat message to Ollama with the current network state as context.
    # Used by the dashboard /chat endpoint so the user can ask free-form questions
    # like "which devices haven't been seen before?" or "is my latency normal?".
    # Returns the model's reply as a string, or an error message on failure.
    prompt = f"""You are a home network monitoring assistant with access to the current network state shown below.
Answer the user's question clearly and concisely based on the data provided.
If the data doesn't contain enough information to answer, say so.

NETWORK CONTEXT:
{context}

USER QUESTION: {message}
"""
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "mistral", "prompt": prompt, "stream": False},
            timeout=60
        )
        return response.json()["response"]
    except Exception as e:
        return f"AI unavailable: {e}"


# -----------------------------
# Shared alert processing
# -----------------------------

def process_scan_alerts(new_macs, alert_storage, verbose=False):
    # Fires new-device alerts and runs threshold checks after every scan.
    # Extracted here so both main() and the dashboard /run route use identical logic
    # rather than maintaining two copies that can silently drift apart.
    # verbose=True prints status lines to stdout (CLI scan path only).
    for mac in new_macs:
        alert = Alert(
            level="warning",
            title=f"New device: {mac}",
            message=f"Unknown device joined the network (MAC: {mac})",
            timestamp=datetime.utcnow()
        )
        if not alert_storage.get_active_by_title(alert.title):
            alert_storage.save(alert)
            _send_desktop_notification(f"New device: {mac}", "Unknown device joined the network")
            if verbose:
                print(f"NEW DEVICE: {mac}")

    metric_adapter = MetricAdapter()
    alert_engine = AlertEngine(metric_adapter)
    for alert in alert_engine.run_checks():
        existing = alert_storage.get_active_by_title(alert.title)
        if alert.level in ["critical", "warning"]:
            if not existing:
                alert_storage.save(alert)
                if alert.level == "critical":
                    _send_desktop_notification(alert.title, alert.message)
                if verbose:
                    print(f"NEW ALERT: {alert.title}")
            else:
                escalated = alert_storage.increment_fire_count(alert.title)
                if escalated:
                    _send_desktop_notification(alert.title, f"Escalated to critical: {alert.message}")
                    if verbose:
                        print(f"ESCALATED: {alert.title}")
        elif alert.level == "info" and existing:
            alert_storage.resolve_by_title(alert.title)
            if verbose:
                print(f"RESOLVED: {alert.title}")


# -----------------------------
# MAIN
# -----------------------------

def main():
    # Entry point for running a scan from the command line (called by run_scan.sh).
    # Steps:
    #   1. Ensures the DB schema exists
    #   2. Collects current network metrics and saves them
    #   3. Runs alert checks via AlertEngine (pings 8.8.8.8, checks thresholds)
    #   4. Saves new critical/warning alerts; resolves existing alerts when conditions clear
    #   5. Prints the plain-text summary to stdout
    # Note: the AI analysis step is omitted here — it only runs via the dashboard /run route.
    init_db()

    alert_storage = AlertStorage()

    summary, device_count, dup_arp, connections, bandwidth, devices = collect_summary()
    save_metrics(device_count, dup_arp, connections, bandwidth)

    history_metrics = load_recent_metrics()
    changes = detect_changes((device_count, dup_arp, connections, bandwidth), history_metrics)

    # Build historical summary context for the AI — last 8 scans (up to 24 hours).
    history_rows = load_recent_summaries()
    history_text = "\n\n".join(f"[{ts}]\n{s.strip()}" for ts, s in history_rows)
    raw_analysis = ask_ai(summary + "\nDetected changes:\n" + changes, history_text)
    analysis, suggestions = parse_ai_suggestions(raw_analysis)
    save_summary(summary, analysis)
    save_pending_actions(suggestions)

    new_macs = upsert_devices(devices)
    process_scan_alerts(new_macs, alert_storage, verbose=True)
    print(summary)


if __name__ == "__main__":
    main()
