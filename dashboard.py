from flask import Flask, render_template_string, redirect, url_for, Response, request
import network_summary
import sqlite3
import csv
import io
from alerts import Alert, AlertStorage, AlertEngine
from datetime import datetime

app = Flask(__name__)

# AlertStorage is instantiated once at startup and shared across all requests.
# It handles reading active/resolved alerts from the SQLite database.
alert_storage = AlertStorage()

# The full HTML/CSS/JS for the dashboard is defined as a single inline string.
# This avoids needing a templates/ directory. Jinja2 variables ({{ }}) are injected
# by render_template_string() at request time.
TEMPLATE = """
<!doctype html>
<html>
<head>
<title>AI Network Advisor</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Apply saved theme before first paint to prevent flash
(function(){ document.documentElement.setAttribute('data-theme', localStorage.getItem('theme') || 'dark'); })();
</script>

<style>
:root {
    --bg:#0f172a; --card:#111827; --text:#e5e7eb; --muted:#9ca3af;
    --border:#374151; --row-border:#1f2937; --item-bg:#020617;
    --input-bg:#1f2937; --scrollbar:#374151;
    --chat-user:#1e3a5f; --chat-user-text:#e5e7eb;
    --chat-ai:#1f2937;
}
[data-theme="light"] {
    --bg:#f1f5f9; --card:#ffffff; --text:#1e293b; --muted:#64748b;
    --border:#e2e8f0; --row-border:#f1f5f9; --item-bg:#f8fafc;
    --input-bg:#f8fafc; --scrollbar:#cbd5e1;
    --chat-user:#dbeafe; --chat-user-text:#1e3a5f;
    --chat-ai:#f1f5f9;
}

body {
    font-family: system-ui, sans-serif;
    background:var(--bg);
    color:var(--text);
    padding:30px;
    max-width:1400px;
    margin:auto;
}

.grid {
    display:grid;
    grid-template-columns: 1fr 1fr;
    gap:20px;
    margin-bottom:20px;
}

.charts {
    display:grid;
    grid-template-columns: repeat(3, 1fr);
    gap:20px;
}

.card {
    background:var(--card);
    padding:18px;
    border-radius:12px;
}

button {
    background:#2563eb;
    color:white;
    border:none;
    padding:10px 16px;
    border-radius:8px;
    cursor:pointer;
    margin-right:10px;
}

pre {
    white-space: pre-wrap;
    font-size:13px;
    max-height:320px;
    overflow:auto;
    color:var(--text);
}

canvas { height:220px !important; }

/* Scrollable alert boxes */
.alert-box {
    max-height:260px;
    overflow-y:auto;
    padding-right:8px;
}
.alert-box::-webkit-scrollbar { width:8px; }
.alert-box::-webkit-scrollbar-thumb {
    background:var(--scrollbar);
    border-radius:6px;
}

/* Compact alert rows */
.alert-item {
    padding:8px 10px;
    margin-bottom:8px;
    border-radius:8px;
    background:var(--item-bg);
    font-size:13px;
}

.alert-title { font-weight:600; }
.alert-msg { color:#fca5a5; font-size:12px; }
.alert-time { color:var(--muted); font-size:11px; }

table.device-table {
    width:100%;
    border-collapse:collapse;
    font-size:13px;
}
table.device-table th {
    text-align:left;
    padding:6px 10px;
    border-bottom:1px solid var(--border);
    color:var(--muted);
    font-weight:600;
}
table.device-table td {
    padding:6px 10px;
    border-bottom:1px solid var(--row-border);
    font-family:monospace;
    color:var(--text);
}

/* Light-mode overrides */
[data-theme="light"] .card {
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}
/* Export buttons have inline background:#374151 — soften in light mode */
[data-theme="light"] button[style] {
    background:#e2e8f0 !important;
    color:#1e293b !important;
}
[data-theme="light"] .alert-msg { color:#dc2626; }
[data-theme="light"] #device-table input[type="text"] {
    background:var(--input-bg) !important;
    border-color:var(--border) !important;
    color:var(--text) !important;
}
[data-theme="light"] #device-table button {
    background:var(--border) !important;
    color:var(--text) !important;
}
[data-theme="light"] #device-table p { color:var(--muted); }

.alert-critical { border-left:4px solid #ef4444; }
.alert-warning  { border-left:4px solid #f59e0b; }
.alert-ok { border-left:4px solid #22c55e; }

/* Collapsible cards */
.card h2, .card h3 {
    cursor:pointer;
    user-select:none;
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-top:0;
}
.card h2 .chevron, .card h3 .chevron {
    font-size:11px;
    color:var(--muted);
    margin-left:10px;
    flex-shrink:0;
}
.card.collapsed > *:not(h2):not(h3) { display:none !important; }

.suggestion-item {
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:8px 10px;
    margin-bottom:8px;
    border-radius:8px;
    background:var(--item-bg);
    border-left:4px solid #6366f1;
    font-size:13px;
    gap:10px;
}
.suggestion-text { flex:1; }
.suggestion-actions { display:flex; gap:6px; flex-shrink:0; }
.btn-approve { background:#16a34a; color:white; padding:4px 10px; font-size:11px; margin:0; }
.btn-reject  { background:#6b7280; color:white; padding:4px 10px; font-size:11px; margin:0; }

/* Chat */
.chat-messages {
    height:280px;
    overflow-y:auto;
    display:flex;
    flex-direction:column;
    gap:8px;
    padding:4px 0 8px;
}
.chat-msg {
    padding:8px 12px;
    border-radius:8px;
    max-width:85%;
    font-size:13px;
    white-space:pre-wrap;
    line-height:1.5;
}
.chat-user { background:var(--chat-user); color:var(--chat-user-text); align-self:flex-end; }
.chat-ai   { background:var(--chat-ai); color:var(--text); align-self:flex-start; border-left:3px solid #6366f1; }
.chat-row  { display:flex; gap:8px; margin-top:10px; }
.chat-row input {
    flex:1;
    background:var(--input-bg);
    border:1px solid var(--border);
    color:var(--text);
    padding:8px 12px;
    border-radius:8px;
    font-size:13px;
}
.chat-row input:focus { outline:none; border-color:#6366f1; }

/* Theme toggle */
.theme-toggle-wrap {
    display:flex;
    flex-direction:row;
    align-items:center;
    gap:6px;
    margin-left:auto;
}
.theme-toggle-wrap .t-icon { font-size:15px; line-height:1; }
.toggle-switch {
    position:relative;
    display:inline-block;
    width:44px;
    height:24px;
    cursor:pointer;
}
.toggle-switch input { opacity:0; width:0; height:0; position:absolute; }
.toggle-track {
    position:absolute;
    inset:0;
    background:var(--border);
    border-radius:12px;
    transition:background 0.2s;
}
.toggle-track::before {
    content:'';
    position:absolute;
    width:18px; height:18px;
    left:3px; top:3px;
    background:#fff;
    border-radius:50%;
    transition:transform 0.2s;
    box-shadow:0 1px 3px rgba(0,0,0,0.3);
}
.toggle-switch input:checked + .toggle-track { background:#6366f1; }
.toggle-switch input:checked + .toggle-track::before { transform:translateX(20px); }

/* Button bar */
.btn-bar {
    display:flex;
    flex-wrap:wrap;
    gap:8px;
    align-items:center;
    margin-bottom:14px;
}
.btn-bar a, .btn-bar button { margin:0; }

/* Responsive */
@media (max-width:640px) {
    body { padding:14px; }
    h1 { font-size:1.2rem; }
    .grid { grid-template-columns:1fr; }
    .charts { grid-template-columns:1fr; }
    .suggestion-item { flex-direction:column; align-items:flex-start; }
    .suggestion-actions { width:100%; justify-content:flex-end; }
    .chat-messages { height:200px; }
}
</style>
</head>

<body>

<h1>🤖 AI Network Advisor</h1>

<div class="btn-bar">
  <a href="/run"><button>Run Scan</button></a>
  <a href="/"><button>Refresh</button></a>
  <a href="/export/metrics.csv"><button style="background:#374151;">Export Metrics CSV</button></a>
  <a href="/export/devices.csv"><button style="background:#374151;">Export Devices CSV</button></a>
  <a href="/export/alerts.csv"><button style="background:#374151;">Export Alerts CSV</button></a>
  <div class="theme-toggle-wrap">
    <span class="t-icon">🌙</span>
    <label class="toggle-switch" title="Toggle light/dark mode">
      <input type="checkbox" id="theme-checkbox">
      <span class="toggle-track"></span>
    </label>
    <span class="t-icon">☀️</span>
  </div>
</div>

<div style="margin:0 0 20px;font-size:13px;display:flex;flex-wrap:wrap;gap:16px;color:var(--muted);">
  <span>Last scan: <strong style="color:var(--text);">{{last_scan_ago}}</strong></span>
  <span>Next scan: <strong style="color:var(--text);" id="next-countdown">—</strong></span>
</div>
<script>
(function(){
  const next = new Date('{{next_scan_iso}}');
  function tick(){
    const s = Math.max(0, Math.floor((next - new Date()) / 1000));
    if(s === 0){ document.getElementById('next-countdown').textContent = 'due now'; return; }
    const h = String(Math.floor(s/3600)).padStart(2,'0');
    const m = String(Math.floor(s%3600/60)).padStart(2,'0');
    const sc = String(s%60).padStart(2,'0');
    document.getElementById('next-countdown').textContent = `in ${h}:${m}:${sc}`;
  }
  tick(); setInterval(tick, 1000);
})();
</script>

<!-- 🚨 ALERT PANELS -->
<div class="grid">

  <div class="card">
    <h2>🚨 Active Alerts</h2>
    <div class="alert-box">
    {% if active_alerts %}
        {% for level, title, message, created, fire_count in active_alerts %}
          <div class="alert-item alert-{{level}}">
              <div class="alert-title">{{title}}{% if fire_count >= 3 %} <span style="font-size:10px;background:#ef4444;color:white;padding:2px 6px;border-radius:4px;margin-left:6px;">ESCALATED</span>{% endif %}</div>
              <div class="alert-msg">{{message}}</div>
          </div>
        {% endfor %}
    {% else %}
        <p style="color:#4ade80;">No active alerts 🎉</p>
    {% endif %}
    </div>
  </div>

  <div class="card">
    <h2>🟢 Recently Resolved (7 days)</h2>
    <div class="alert-box">
    {% if recent_alerts %}
        {% for level, title, message, created in recent_alerts %}
          <div class="alert-item alert-ok">
              <div class="alert-title">{{title}}</div>
              <div class="alert-time">{{created}}</div>
          </div>
        {% endfor %}
    {% else %}
        <p>No recently resolved alerts</p>
    {% endif %}
    </div>
  </div>

</div>

{% if pending_actions %}
<div class="card" style="margin-bottom:20px;border:1px solid #6366f1;">
  <h2>🤖 AI Suggestions <span style="font-size:13px;color:var(--muted);font-weight:400;">— approve or reject each action</span></h2>
  <div class="alert-box">
    {% for action_id, action_type, display_text, created_at in pending_actions %}
      <div class="suggestion-item">
        <div class="suggestion-text">{{display_text}}</div>
        <div class="suggestion-actions">
          <form method="POST" action="/actions/{{action_id}}/approve" style="display:inline;">
            <button class="btn-approve" type="submit">Approve</button>
          </form>
          <form method="POST" action="/actions/{{action_id}}/reject" style="display:inline;">
            <button class="btn-reject" type="submit">Reject</button>
          </form>
        </div>
      </div>
    {% endfor %}
  </div>
</div>
{% endif %}

<div class="grid">
  <div class="card">
    <h2>📊 Latest Summary</h2>
    <pre>{{summary}}</pre>
  </div>

  <div class="card">
    <h2>🧠 AI Analysis</h2>
    <pre>{{analysis}}</pre>
  </div>
</div>

<div class="card" style="margin-bottom:20px;">
  <h2>💬 Ask the AI</h2>
  <div class="chat-messages" id="chat-messages">
    <div class="chat-msg chat-ai">Hi! Ask me anything about your network — devices, alerts, trends, anything in the current data.</div>
  </div>
  <div class="chat-row">
    <input type="text" id="chat-input" placeholder="e.g. Are there any unfamiliar devices?" />
    <button id="chat-send">Send</button>
  </div>
</div>

<div class="card" style="margin-bottom:20px;">
  <h2>Device Inventory</h2>
  <div id="device-table" style="overflow-x:auto;">Loading...</div>
</div>

<div class="charts">
  <div class="card"><h3>📈 Bandwidth</h3><canvas id="bandwidthChart"></canvas></div>
  <div class="card"><h3>🖥 Devices</h3><canvas id="deviceChart"></canvas></div>
  <div class="card"><h3>🔁 Duplicate ARP</h3><canvas id="arpChart"></canvas></div>
</div>

<script>
Promise.all([fetch('/devices').then(r => r.json()), fetch('/connections').then(r => r.json())])
.then(([devData, connData]) => {
    const el = document.getElementById('device-table');
    if (!devData.devices.length) {
        el.innerHTML = '<p style="color:#9ca3af;">No devices recorded yet — run a scan first.</p>';
        return;
    }
    const conns = connData.connections;
    let html = '<table class="device-table"><thead><tr><th>Label</th><th>MAC Address</th><th>IP Address</th><th>Active Connections</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>';
    devData.devices.forEach(d => {
        const unlabelled = !d.label;
        const connCount = conns[d.ip] || 0;
        const connStyle = connCount > 0 ? 'color:#34d399;font-weight:600;' : 'color:#6b7280;';
        html += `<tr>
            <td style="font-family:system-ui;">
                <form method="POST" action="/devices/${d.mac}/label" style="display:flex;gap:6px;align-items:center;">
                    <input type="text" name="label" value="${d.label}" placeholder="Unlabelled"
                        style="background:#1f2937;border:1px solid ${unlabelled ? '#f59e0b' : '#374151'};color:#e5e7eb;padding:3px 8px;border-radius:4px;font-size:12px;width:130px;">
                    <button type="submit" style="background:#374151;padding:3px 8px;font-size:11px;margin:0;">Save</button>
                </form>
            </td>
            <td>${d.mac}</td><td>${d.ip}</td>
            <td style="${connStyle}">${connCount > 0 ? connCount : '—'}</td>
            <td>${d.first_seen}</td><td>${d.last_seen}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    el.innerHTML = html;
});

fetch('/metrics')
.then(res => res.json())
.then(data => {

const opts = {
    responsive: true,
    maintainAspectRatio: false,
    scales: { y: { beginAtZero: true } }
};

new Chart(document.getElementById('bandwidthChart'), {
    type:'line',
    data:{ labels:data.timestamps, datasets:[{ label:'Bandwidth', data:data.bandwidth, borderColor:'cyan', tension:0.2 }]},
    options:opts
});

new Chart(document.getElementById('deviceChart'), {
    type:'line',
    data:{ labels:data.timestamps, datasets:[{ label:'Devices', data:data.devices, borderColor:'orange', tension:0.2 }]},
    options:opts
});

new Chart(document.getElementById('arpChart'), {
    type:'line',
    data:{ labels:data.timestamps, datasets:[{ label:'Duplicate ARP', data:data.dup_arp, borderColor:'red', tension:0.2 }]},
    options:opts
});
});
</script>

<script>
(function(){
  var box = document.getElementById('chat-messages');
  var input = document.getElementById('chat-input');
  var btn = document.getElementById('chat-send');

  function addMsg(text, role) {
    var div = document.createElement('div');
    div.className = 'chat-msg chat-' + role;
    div.textContent = text;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
    return div;
  }

  async function send() {
    var msg = input.value.trim();
    if (!msg) return;
    input.value = '';
    addMsg(msg, 'user');
    var thinking = addMsg('Thinking…', 'ai');
    btn.disabled = true;
    input.disabled = true;
    try {
      var res = await fetch('/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: msg})
      });
      var data = await res.json();
      thinking.textContent = data.reply;
    } catch(e) {
      thinking.textContent = 'Could not reach AI.';
    }
    btn.disabled = false;
    input.disabled = false;
    input.focus();
  }

  btn.addEventListener('click', send);
  input.addEventListener('keydown', function(e){ if(e.key === 'Enter') send(); });
})();
</script>

<script>
(function(){
  var cb = document.getElementById('theme-checkbox');
  function applyTheme(t){
    document.documentElement.setAttribute('data-theme', t);
    cb.checked = (t === 'light');
    localStorage.setItem('theme', t);
  }
  applyTheme(localStorage.getItem('theme') || 'dark');
  cb.addEventListener('change', function(){
    applyTheme(cb.checked ? 'light' : 'dark');
  });
})();
</script>

<script>
(function(){
  document.querySelectorAll('.card').forEach(function(card){
    var heading = card.querySelector('h2, h3');
    if (!heading) return;
    var key = 'collapse:' + heading.textContent.trim().replace(/\s+/g,' ').substring(0, 40);
    var chevron = document.createElement('span');
    chevron.className = 'chevron';
    heading.appendChild(chevron);
    function update(){ chevron.textContent = card.classList.contains('collapsed') ? '▼' : '▲'; }
    if (localStorage.getItem(key) === '1') card.classList.add('collapsed');
    update();
    heading.addEventListener('click', function(){
      card.classList.toggle('collapsed');
      localStorage.setItem(key, card.classList.contains('collapsed') ? '1' : '0');
      update();
    });
  });
})();
</script>

</body>
</html>
"""

# Load the most recent scan results from the database on startup.
# Previously these were plain empty strings, so the dashboard always showed blank panels
# after a Flask restart even though scan results were persisted in the DB.
network_summary.init_db()
latest_summary, latest_analysis = network_summary.load_latest_summary()


def _scan_times():
    # Returns (last_scan_ago, next_scan_iso) for the dashboard status bar.
    # last_scan_ago: human-readable "Xh Ym ago" string from the most recent metrics row.
    # next_scan_iso: ISO timestamp of the next 3-hourly boundary (00/03/06...21:00).
    conn = sqlite3.connect("network_history.db")
    c = conn.cursor()
    c.execute("SELECT timestamp FROM metrics ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()

    last_scan_ago = "Never"
    if row:
        try:
            dt = datetime.fromisoformat(row[0])
            diff = int((datetime.now() - dt).total_seconds())
            if diff < 60:
                last_scan_ago = f"{diff}s ago"
            elif diff < 3600:
                last_scan_ago = f"{diff // 60}m ago"
            else:
                h, m = diff // 3600, (diff % 3600) // 60
                last_scan_ago = f"{h}h {m}m ago" if m else f"{h}h ago"
        except Exception:
            last_scan_ago = row[0]

    now = datetime.now()
    next_hour = ((now.hour // 3) + 1) * 3
    if next_hour >= 24:
        from datetime import timedelta
        next_dt = datetime(now.year, now.month, now.day) + timedelta(days=1)
    else:
        next_dt = datetime(now.year, now.month, now.day, next_hour, 0, 0)

    return last_scan_ago, next_dt.isoformat()


@app.route("/")
def home():
    # Renders the main dashboard page.
    # Reads active and recently resolved alerts fresh from the DB on every request
    # so the alert panels always reflect current state without needing a rescan.
    # Summary and analysis come from in-memory globals — they only update on /run.
    active_alerts = alert_storage.get_active_alerts()
    recent_alerts = alert_storage.get_recent_resolved()
    pending_actions = network_summary.load_pending_actions()
    last_scan_ago, next_scan_iso = _scan_times()

    return render_template_string(
        TEMPLATE,
        summary=latest_summary,
        analysis=latest_analysis,
        active_alerts=active_alerts,
        recent_alerts=recent_alerts,
        pending_actions=pending_actions,
        last_scan_ago=last_scan_ago,
        next_scan_iso=next_scan_iso
    )

@app.route("/run")
def run_scan():
    # Triggers a full network scan inline (same logic as run_scan.sh but with AI analysis).
    # Steps:
    #   1. Ensures DB schema exists
    #   2. Collects current metrics via arp-scan, vnstat, ss
    #   3. Compares to recent history to detect anomalies
    #   4. Sends summary + anomalies to Ollama (mistral) for AI analysis
    #   5. Saves metrics and summary to the DB
    #   6. Updates the in-memory globals so the dashboard shows fresh data
    #   7. Redirects back to / so the user sees the updated dashboard
    # Note: alert checks are NOT run here — they only run via network_summary.main().
    global latest_summary, latest_analysis

    network_summary.init_db()
    today_summary, device_count, dup_arp, connections, bandwidth, devices = network_summary.collect_summary()

    history_metrics = network_summary.load_recent_metrics()
    changes = network_summary.detect_changes(
        (device_count, dup_arp, connections, bandwidth),
        history_metrics
    )

    latest_summary = today_summary

    # Pass last 8 summaries as historical context so the AI can spot trends.
    history_rows = network_summary.load_recent_summaries()
    history_text = "\n\n".join(f"[{ts}]\n{s.strip()}" for ts, s in history_rows)
    raw_analysis = network_summary.ask_ai(
        today_summary + "\nDetected changes:\n" + changes, history_text
    )
    latest_analysis, suggestions = network_summary.parse_ai_suggestions(raw_analysis)

    network_summary.save_metrics(device_count, dup_arp, connections, bandwidth)
    network_summary.save_summary(today_summary, latest_analysis)
    network_summary.save_pending_actions(suggestions)

    # Upsert device inventory and fire a warning + notification for any new MAC.
    new_macs = network_summary.upsert_devices(devices)
    for mac in new_macs:
        alert = Alert(
            level="warning",
            title=f"New device: {mac}",
            message=f"Unknown device joined the network (MAC: {mac})",
            timestamp=datetime.utcnow()
        )
        if not alert_storage.get_active_by_title(alert.title):
            alert_storage.save(alert)
            network_summary._send_desktop_notification(f"New device: {mac}", "Unknown device joined the network")

    # Run alert checks with escalation and desktop notifications.
    metric_adapter = network_summary.MetricAdapter()
    alert_engine = AlertEngine(metric_adapter)
    for alert in alert_engine.run_checks():
        existing = alert_storage.get_active_by_title(alert.title)
        if alert.level in ["critical", "warning"]:
            if not existing:
                alert_storage.save(alert)
                if alert.level == "critical":
                    network_summary._send_desktop_notification(alert.title, alert.message)
            else:
                escalated = alert_storage.increment_fire_count(alert.title)
                if escalated:
                    network_summary._send_desktop_notification(alert.title, f"Escalated to critical: {alert.message}")
        elif alert.level == "info" and existing:
            alert_storage.resolve_by_title(alert.title)

    return redirect(url_for("home"))

@app.route("/metrics")
def metrics():
    # Returns all historical metric rows as JSON for the Chart.js trend charts.
    # Reads every row from the metrics table in chronological order (oldest first)
    # so the charts plot correctly left-to-right over time.
    # Response shape: { timestamps, devices, dup_arp, connections, bandwidth }
    conn = sqlite3.connect("network_history.db")
    c = conn.cursor()
    c.execute("SELECT timestamp, device_count, dup_arp, connections, bandwidth_today FROM metrics ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    return {
        "timestamps": [r[0] for r in rows],
        "devices": [r[1] for r in rows],
        "dup_arp": [r[2] for r in rows],
        "connections": [r[3] for r in rows],
        "bandwidth": [r[4] for r in rows],
    }

@app.route("/devices")
def devices_endpoint():
    # Returns the full device inventory as JSON for the dashboard table.
    # Each entry has mac, ip, first_seen, and last_seen fields.
    rows = network_summary.load_devices()
    return {
        "devices": [
            {"mac": r[0], "ip": r[1], "first_seen": r[2], "last_seen": r[3], "label": r[4] or ""}
            for r in rows
        ]
    }


@app.route("/connections")
def connections_endpoint():
    # Returns a live count of active TCP/UDP connections per local network IP.
    # Used by the device table to show which devices are currently talking to this machine.
    # Runs ss -tun on every request so the data is always fresh.
    return {"connections": network_summary.get_connections_by_ip()}


@app.route("/devices/<mac>/label", methods=["POST"])
def label_device(mac):
    # Saves a human-readable label for a device and resolves its "New device" alert.
    # Labelling a device is the user's way of saying "I know what this is" —
    # so any active warning for that MAC is automatically cleared.
    label = request.form.get("label", "").strip()
    network_summary.set_device_label(mac, label)
    if label:
        alert_storage.resolve_by_title(f"New device: {mac}")
    return redirect(url_for("home"))


@app.route("/chat", methods=["POST"])
def chat():
    # Accepts a JSON body with a "message" key and returns an AI reply as JSON.
    # Passes the current in-memory summary and analysis as context so the model
    # can answer questions grounded in the actual network state.
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    if not message:
        return {"reply": "Please enter a message."}, 400
    context = f"Latest network summary:\n{latest_summary}\n\nLatest AI analysis:\n{latest_analysis}"
    reply = network_summary.ask_ai_chat(message, context)
    return {"reply": reply}


@app.route("/actions/<int:action_id>/approve", methods=["POST"])
def approve_action(action_id):
    # Executes the AI-suggested action and marks it approved.
    network_summary.approve_action(action_id)
    return redirect(url_for("home"))


@app.route("/actions/<int:action_id>/reject", methods=["POST"])
def reject_action(action_id):
    # Dismisses the suggestion without executing it.
    network_summary.reject_action(action_id)
    return redirect(url_for("home"))


def _csv_response(filename, headers, rows):
    # Helper that builds a CSV string in memory and returns it as a downloadable Flask response.
    # Using StringIO avoids writing a temp file — the whole CSV is built in RAM and streamed.
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/export/metrics.csv")
def export_metrics():
    # Downloads the full metrics history as a CSV file.
    # Columns match the metrics table: timestamp, device_count, dup_arp, connections, bandwidth_today.
    # Can be used as a "Get Data from Web" source in Power BI or read via requests.get() in Databricks.
    conn = sqlite3.connect("network_history.db")
    c = conn.cursor()
    c.execute("SELECT timestamp, device_count, dup_arp, connections, bandwidth_today FROM metrics ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return _csv_response(
        "metrics.csv",
        ["timestamp", "device_count", "dup_arp", "connections", "bandwidth_today_gib"],
        rows
    )


@app.route("/export/devices.csv")
def export_devices():
    # Downloads the full device inventory as a CSV file.
    # Columns: mac_address, ip_address, first_seen, last_seen.
    # One row per unique device ever seen on the network.
    conn = sqlite3.connect("network_history.db")
    c = conn.cursor()
    c.execute("SELECT mac_address, ip_address, first_seen, last_seen FROM devices ORDER BY first_seen ASC")
    rows = c.fetchall()
    conn.close()
    return _csv_response(
        "devices.csv",
        ["mac_address", "ip_address", "first_seen", "last_seen"],
        rows
    )


@app.route("/export/alerts.csv")
def export_alerts():
    # Downloads the full alert history as a CSV file, including resolved alerts.
    # Columns: level, title, message, created_at, resolved (0=active, 1=resolved).
    # Useful for analysing alert frequency and duration over time.
    conn = sqlite3.connect("network_history.db")
    c = conn.cursor()
    c.execute("SELECT level, title, message, created_at, resolved FROM alerts ORDER BY created_at ASC")
    rows = c.fetchall()
    conn.close()
    return _csv_response(
        "alerts.csv",
        ["level", "title", "message", "created_at", "resolved"],
        rows
    )


# Start the Flask development server when dashboard.py is run directly.
# debug=True enables auto-reload on code changes and shows full tracebacks in the browser.
# The server listens on localhost:5000 by default.
app.run(debug=True)
