from flask import Flask, render_template_string, redirect, url_for, Response, request
import network_summary
import sqlite3
import csv
import io
import functools
import os
from alerts import AlertStorage
from datetime import datetime

app = Flask(__name__)

# AlertStorage is instantiated once at startup and shared across all requests.
# It handles reading active/resolved alerts from the SQLite database.
alert_storage = AlertStorage()

# Basic auth credentials — loaded from environment variables.
# Set DASHBOARD_USER and DASHBOARD_PASS in your .env file (never commit .env).
# Falls back to placeholder values if the env vars are not set.
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "changeme")

def require_auth(f):
    # Decorator that enforces HTTP Basic Auth on any route it wraps.
    # Returns a 401 with WWW-Authenticate header so the browser shows a login prompt.
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != DASHBOARD_USER or auth.password != DASHBOARD_PASS:
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Network Dashboard"'}
            )
        return f(*args, **kwargs)
    return wrapper

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
    padding:24px 30px;
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
    margin-bottom:20px;
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
[data-theme="light"] .card { box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
[data-theme="light"] button[style] { background:#e2e8f0 !important; color:#1e293b !important; }
[data-theme="light"] .alert-msg { color:#dc2626; }
[data-theme="light"] #device-table input[type="text"] {
    background:var(--input-bg) !important;
    border-color:var(--border) !important;
    color:var(--text) !important;
}
[data-theme="light"] #device-table button { background:var(--border) !important; color:var(--text) !important; }
[data-theme="light"] #device-table p { color:var(--muted); }

.alert-critical { border-left:4px solid #ef4444; }
.alert-warning  { border-left:4px solid #f59e0b; }
.alert-ok       { border-left:4px solid #22c55e; }

/* Alert type badges */
.alert-tag {
    display:inline-block; font-size:10px; padding:1px 7px;
    border-radius:10px; margin-left:7px; vertical-align:middle; font-weight:500;
}
/* Clickable alert rows (new device alerts) */
.alert-clickable { cursor:pointer; }
.alert-clickable:hover { filter:brightness(1.2); }

/* Chat suggestion chips */
.chat-suggestions { display:flex; flex-wrap:wrap; gap:6px; padding:6px 12px 4px; }
.chat-suggestion {
    background:var(--item-bg); border:1px solid var(--border); color:var(--muted);
    font-size:11px; padding:4px 10px; border-radius:12px; cursor:pointer; margin:0;
    transition:border-color 0.15s, color 0.15s;
}
.chat-suggestion:hover { border-color:#6366f1; color:#6366f1; }

/* Collapsible cards */
.card h2, .card h3 {
    cursor:pointer; user-select:none;
    display:flex; justify-content:space-between; align-items:center;
    margin-top:0;
}
.card h2 .chevron, .card h3 .chevron {
    font-size:11px; color:var(--muted); margin-left:10px; flex-shrink:0;
}
.card.collapsed > *:not(h2):not(h3) { display:none !important; }

.suggestion-item {
    display:flex; align-items:center; justify-content:space-between;
    padding:8px 10px; margin-bottom:8px; border-radius:8px;
    background:var(--item-bg); border-left:4px solid #6366f1;
    font-size:13px; gap:10px;
}
.suggestion-text { flex:1; }
.suggestion-actions { display:flex; gap:6px; flex-shrink:0; }
.btn-approve { background:#16a34a; color:white; padding:4px 10px; font-size:11px; margin:0; }
.btn-reject  { background:#6b7280; color:white; padding:4px 10px; font-size:11px; margin:0; }

/* Chat */
.chat-messages {
    height:320px; overflow-y:auto;
    display:flex; flex-direction:column; gap:8px; padding:4px 0 8px;
}
.chat-msg {
    padding:8px 12px; border-radius:8px; max-width:85%;
    font-size:13px; white-space:pre-wrap; line-height:1.5;
}
.chat-user { background:var(--chat-user); color:var(--chat-user-text); align-self:flex-end; }
.chat-ai   { background:var(--chat-ai); color:var(--text); align-self:flex-start; border-left:3px solid #6366f1; }
.chat-row  { display:flex; gap:8px; margin-top:10px; }
.chat-row input {
    flex:1; background:var(--input-bg); border:1px solid var(--border);
    color:var(--text); padding:8px 12px; border-radius:8px; font-size:13px;
}
.chat-row input:focus { outline:none; border-color:#6366f1; }

/* Floating chat FAB + panel */
#chat-fab {
    position:fixed; bottom:24px; right:24px;
    width:52px; height:52px; border-radius:50%;
    background:#6366f1; color:white; font-size:22px;
    border:none; cursor:pointer; margin:0;
    box-shadow:0 4px 16px rgba(0,0,0,0.4);
    z-index:1000;
    display:flex; align-items:center; justify-content:center;
    transition:transform 0.15s;
}
#chat-fab:hover { transform:scale(1.08); }
#chat-panel {
    position:fixed; bottom:88px; right:24px;
    width:360px; max-width:calc(100vw - 48px);
    background:var(--card); border-radius:14px;
    box-shadow:0 8px 32px rgba(0,0,0,0.4);
    z-index:999; display:none; flex-direction:column;
    overflow:hidden; border:1px solid var(--border);
}
#chat-panel.open { display:flex; }
#chat-panel-header {
    display:flex; justify-content:space-between; align-items:center;
    padding:12px 14px; background:#6366f1; color:white; font-weight:600;
}
#chat-close {
    background:transparent; border:none; color:white;
    font-size:16px; cursor:pointer; margin:0; padding:2px 6px; line-height:1;
}
#chat-panel .chat-messages { height:260px; padding:8px 12px; }
#chat-panel .chat-row { padding:0 12px 12px; }

/* Theme toggle */
.theme-toggle-wrap {
    display:flex; flex-direction:row; align-items:center; gap:6px; margin-left:auto;
}
.theme-toggle-wrap .t-icon { font-size:15px; line-height:1; }
.toggle-switch { position:relative; display:inline-block; width:44px; height:24px; cursor:pointer; }
.toggle-switch input { opacity:0; width:0; height:0; position:absolute; }
.toggle-track { position:absolute; inset:0; background:var(--border); border-radius:12px; transition:background 0.2s; }
.toggle-track::before {
    content:''; position:absolute; width:18px; height:18px; left:3px; top:3px;
    background:#fff; border-radius:50%; transition:transform 0.2s; box-shadow:0 1px 3px rgba(0,0,0,0.3);
}
.toggle-switch input:checked + .toggle-track { background:#6366f1; }
.toggle-switch input:checked + .toggle-track::before { transform:translateX(20px); }
#demo-checkbox:checked + .toggle-track { background:#f59e0b; }

/* Button bar */
.btn-bar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:10px; }
.btn-bar a, .btn-bar button { margin:0; }

/* Status bar */
.status-bar { font-size:13px; display:flex; flex-wrap:wrap; gap:16px; color:var(--muted); margin-bottom:18px; }

/* Tab strip */
.tabs {
    display:grid;
    grid-template-columns: repeat(4, 1fr);
    gap:4px;
    background:var(--card);
    border-radius:12px;
    padding:4px;
    margin-bottom:24px;
}
.tab-btn {
    background:transparent; border:none; color:var(--muted);
    padding:10px 6px; border-radius:8px; cursor:pointer;
    font-size:13px; font-weight:500; margin:0;
    display:flex; align-items:center; justify-content:center; gap:5px;
    transition:background 0.15s, color 0.15s;
}
.tab-btn.active { background:#6366f1; color:#fff; }
.tab-btn:hover:not(.active) { background:var(--item-bg); color:var(--text); }
.tab-badge {
    background:#ef4444; color:#fff;
    border-radius:10px; font-size:10px; padding:1px 5px; line-height:1.4;
}
.tab-btn.active .tab-badge { background:rgba(255,255,255,0.3); }
.tab-panel { display:none; }
.tab-panel.active { display:block; }

/* Responsive */
@media (max-width:640px) {
    body { padding:12px; }
    h1 { font-size:1.2rem; }
    .grid { grid-template-columns:1fr; }
    .charts { grid-template-columns:1fr; }
    .suggestion-item { flex-direction:column; align-items:flex-start; }
    .suggestion-actions { width:100%; justify-content:flex-end; }
    .chat-messages { height:240px; }
}
/* On very small screens show only emoji in tabs */
@media (max-width:400px) {
    .tab-label { display:none; }
    .tab-btn { font-size:18px; }
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
  <div class="theme-toggle-wrap" style="margin-left:12px;">
    <label class="toggle-switch" title="Demo mode — anonymises MAC addresses and IPs">
      <input type="checkbox" id="demo-checkbox">
      <span class="toggle-track"></span>
    </label>
    <span style="font-size:12px;color:var(--muted);line-height:1;">Demo</span>
  </div>
</div>

<div id="demo-banner" style="display:none;position:fixed;top:0;left:0;right:0;background:#f59e0b;color:#1e293b;text-align:center;padding:9px 16px;font-weight:600;font-size:13px;z-index:3000;letter-spacing:0.01em;">
  🕵️ Demo Mode Active — MAC addresses and IPs are anonymised
</div>

<div class="status-bar">
  <span>Last scan: <strong style="color:var(--text);">{{last_scan_ago}}</strong></span>
  <span>Next scan: <strong style="color:var(--text);" id="next-countdown">—</strong></span>
</div>

<div class="tabs" id="main-tabs">
  <button class="tab-btn" data-tab="overview">
    🚨 <span class="tab-label">Overview</span>
    {% if active_alerts %}<span class="tab-badge">{{active_alerts|length}}</span>{% endif %}
  </button>
  <button class="tab-btn" data-tab="summary">
    🧠 <span class="tab-label">Summary</span>
  </button>
  <button class="tab-btn" data-tab="devices">
    🖥 <span class="tab-label">Devices</span>
  </button>
  <button class="tab-btn" data-tab="trends">
    📈 <span class="tab-label">Trends</span>
  </button>
</div>

<!-- TAB: Overview -->
<div class="tab-panel" id="tab-overview">

  <div class="grid">
    <div class="card">
      <h2>🚨 Active Alerts</h2>
      <div class="alert-box">
      {% if active_alerts %}
          {% for level, title, message, created, fire_count in active_alerts %}
            {% if title.startswith('New device:') %}
            <div class="alert-item alert-{{level}} alert-clickable" data-mac="{{ title[12:] }}" title="Click for device details">
            {% else %}
            <div class="alert-item alert-{{level}}">
            {% endif %}
                <div class="alert-title">
                  {{title}}
                  {% if title.startswith('New device:') %}<span class="alert-tag" style="background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b55;">New Device</span>
                  {% elif 'packet loss' in title.lower() %}<span class="alert-tag" style="background:#f9731622;color:#f97316;border:1px solid #f9731655;">Packet Loss</span>
                  {% elif 'unreachable' in title.lower() %}<span class="alert-tag" style="background:#ef444422;color:#ef4444;border:1px solid #ef444455;">Unreachable</span>
                  {% elif 'duplicate arp' in title.lower() or 'dup arp' in title.lower() %}<span class="alert-tag" style="background:#a855f722;color:#a855f7;border:1px solid #a855f755;">Duplicate ARP</span>
                  {% elif 'latency' in title.lower() %}<span class="alert-tag" style="background:#3b82f622;color:#3b82f6;border:1px solid #3b82f655;">High Latency</span>
                  {% endif %}
                  {% if fire_count >= 3 %}<span style="font-size:10px;background:#ef4444;color:white;padding:2px 6px;border-radius:4px;margin-left:6px;">ESCALATED</span>{% endif %}
                </div>
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
  <div class="card" style="border:1px solid #6366f1;">
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

</div>

<!-- TAB: Summary -->
<div class="tab-panel" id="tab-summary">
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
  <div class="card">
    <h2>🕐 Scan History</h2>
    <div id="scan-history-table" style="overflow-x:auto;">Loading...</div>
  </div>
</div>

<!-- TAB: Devices -->
<div class="tab-panel" id="tab-devices">
  <div class="card">
    <h2>🖥 Device Inventory</h2>
    <div id="device-table" style="overflow-x:auto;">Loading...</div>
  </div>
</div>

<!-- TAB: Trends -->
<div class="tab-panel" id="tab-trends">
  <div class="charts">
    <div class="card"><h3>📈 Bandwidth</h3><canvas id="bandwidthChart"></canvas></div>
    <div class="card"><h3>🖥 Devices</h3><canvas id="deviceChart"></canvas></div>
    <div class="card"><h3>🔁 Duplicate ARP</h3><canvas id="arpChart"></canvas></div>
  </div>
</div>

<script>
// Countdown timer
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

<script>
// Escape untrusted strings before inserting into innerHTML.
function esc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Device table
Promise.all([fetch('/devices').then(r => r.json()), fetch('/connections').then(r => r.json())])
.then(([devData, connData]) => {
    const el = document.getElementById('device-table');
    if (!devData.devices.length) {
        el.innerHTML = '<p style="color:#9ca3af;">No devices recorded yet — run a scan first.</p>';
        return;
    }
    const conns = connData.connections;
    let html = '<table class="device-table"><thead><tr><th style="width:32px;text-align:center;">●</th><th>Label</th><th>MAC Address</th><th>IP Address</th><th>Active Connections</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>';
    devData.devices.forEach(d => {
        const unlabelled = !d.label;
        const connCount = conns[d.ip] || 0;
        const connStyle = connCount > 0 ? 'color:#34d399;font-weight:600;' : 'color:#6b7280;';
        const statusDot = d.online
            ? '<span style="color:#4ade80;font-size:14px;" title="Online">●</span>'
            : '<span style="color:#6b7280;font-size:14px;" title="Offline">●</span>';
        html += `<tr>
            <td style="text-align:center;">${statusDot}</td>
            <td style="font-family:system-ui;">
                <form method="POST" action="/devices/${esc(d.mac)}/label" style="display:flex;gap:6px;align-items:center;">
                    <input type="text" name="label" value="${esc(d.label)}" placeholder="Unlabelled"
                        style="background:#1f2937;border:1px solid ${unlabelled ? '#f59e0b' : '#374151'};color:#e5e7eb;padding:3px 8px;border-radius:4px;font-size:12px;width:130px;">
                    <button type="submit" style="background:#374151;padding:3px 8px;font-size:11px;margin:0;">Save</button>
                </form>
            </td>
            <td>${esc(d.mac)}</td><td>${esc(d.ip)}</td>
            <td style="${connStyle}">${connCount > 0 ? connCount : '—'}</td>
            <td>${esc(d.first_seen)}</td><td>${esc(d.last_seen)}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    el.innerHTML = html;
});
</script>

<script>
// Scan history table
fetch('/history')
.then(r => r.json())
.then(data => {
    const el = document.getElementById('scan-history-table');
    if (!data.history.length) {
        el.innerHTML = '<p style="color:#9ca3af;">No scan history yet.</p>';
        return;
    }
    let html = '<table class="device-table"><thead><tr><th>Timestamp</th><th>Devices</th><th>Bandwidth</th></tr></thead><tbody>';
    data.history.forEach(h => {
        html += `<tr>
            <td>${esc(h.timestamp)}</td>
            <td style="font-family:system-ui;">${h.devices != null ? h.devices : '—'}</td>
            <td style="font-family:system-ui;">${h.bandwidth != null ? h.bandwidth.toFixed(2) + ' GiB' : '—'}</td>
        </tr>`;
    });
    html += '</tbody></table>';
    el.innerHTML = html;
});
</script>

<script>
// Charts — store instances so we can resize when the tab becomes visible
var _charts = [];
fetch('/metrics')
.then(res => res.json())
.then(data => {
    const opts = {
        responsive: true,
        maintainAspectRatio: false,
        scales: { y: { beginAtZero: true } }
    };
    _charts.push(new Chart(document.getElementById('bandwidthChart'), {
        type:'line',
        data:{ labels:data.timestamps, datasets:[{ label:'Bandwidth', data:data.bandwidth, borderColor:'cyan', tension:0.2 }]},
        options:opts
    }));
    _charts.push(new Chart(document.getElementById('deviceChart'), {
        type:'line',
        data:{ labels:data.timestamps, datasets:[{ label:'Devices', data:data.devices, borderColor:'orange', tension:0.2 }]},
        options:opts
    }));
    _charts.push(new Chart(document.getElementById('arpChart'), {
        type:'line',
        data:{ labels:data.timestamps, datasets:[{ label:'Duplicate ARP', data:data.dup_arp, borderColor:'red', tension:0.2 }]},
        options:opts
    }));
});
</script>


<script>
// Theme toggle
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
// Tab switching
(function(){
  function showTab(name) {
    document.querySelectorAll('.tab-btn').forEach(function(b){
      b.classList.toggle('active', b.dataset.tab === name);
    });
    document.querySelectorAll('.tab-panel').forEach(function(p){
      p.classList.toggle('active', p.id === 'tab-' + name);
    });
    localStorage.setItem('active-tab', name);
    // Charts need a resize after becoming visible
    if (name === 'trends' && typeof _charts !== 'undefined') {
      setTimeout(function(){ _charts.forEach(function(c){ c.resize(); }); }, 10);
    }
  }
  document.querySelectorAll('.tab-btn').forEach(function(b){
    b.addEventListener('click', function(){ showTab(b.dataset.tab); });
  });
  showTab(localStorage.getItem('active-tab') || 'overview');
})();
</script>

<script>
// Collapsible cards
(function(){
  document.querySelectorAll('.card').forEach(function(card){
    var heading = card.querySelector('h2, h3');
    if (!heading) return;
    var key = 'collapse:' + heading.textContent.trim().replace(/[\\s]+/g,' ').substring(0, 40);
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

<!-- Device detail modal -->
<div id="device-modal" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.6); z-index:2000; align-items:center; justify-content:center;">
  <div style="background:var(--card); border-radius:14px; padding:24px; max-width:400px; width:90%; position:relative;">
    <button id="modal-close" style="position:absolute;top:12px;right:14px;background:transparent;border:none;color:var(--muted);font-size:20px;cursor:pointer;margin:0;line-height:1;">✕</button>
    <h3 id="modal-title" style="margin-top:0; margin-bottom:14px;">Device Details</h3>
    <div id="modal-body"></div>
  </div>
</div>

<!-- Floating chat -->
<button id="chat-fab" title="Ask the AI">💬</button>
<div id="chat-panel">
  <div id="chat-panel-header">
    <span>💬 Ask the AI</span>
    <button id="chat-close" title="Close">✕</button>
  </div>
  <div class="chat-messages" id="chat-messages">
    <div class="chat-msg chat-ai">Hi! Ask me anything about your network — devices, alerts, trends, anything in the current data.</div>
  </div>
  <div class="chat-suggestions" id="chat-suggestions">
    <button class="chat-suggestion">Any unfamiliar devices?</button>
    <button class="chat-suggestion">Any network problems?</button>
    <button class="chat-suggestion">Bandwidth spikes?</button>
    <button class="chat-suggestion">New devices today?</button>
  </div>
  <div class="chat-row">
    <input type="text" id="chat-input" placeholder="Ask about your network…" />
    <button id="chat-send">Send</button>
  </div>
</div>

<script>
// Floating chat toggle
(function(){
  var fab = document.getElementById('chat-fab');
  var panel = document.getElementById('chat-panel');
  fab.addEventListener('click', function(){ panel.classList.toggle('open'); });
  document.getElementById('chat-close').addEventListener('click', function(){ panel.classList.remove('open'); });
})();

// Chat — must run after floating chat HTML so all IDs exist
(function(){
  var box   = document.getElementById('chat-messages');
  var input = document.getElementById('chat-input');
  var btn   = document.getElementById('chat-send');

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
    var thinking = addMsg('Thinking\u2026', 'ai');
    btn.disabled = true; input.disabled = true;
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
    btn.disabled = false; input.disabled = false; input.focus();
  }

  btn.addEventListener('click', send);
  input.addEventListener('keydown', function(e){ if(e.key === 'Enter') send(); });

  document.querySelectorAll('.chat-suggestion').forEach(function(chip){
    chip.addEventListener('click', function(){
      input.value = chip.textContent.trim();
      document.getElementById('chat-suggestions').style.display = 'none';
      send();
    });
  });
})();

// Device detail modal
(function(){
  function openModal(mac) {
    fetch('/devices/' + encodeURIComponent(mac))
      .then(function(r){ return r.json(); })
      .then(function(d){
        var modalTitle = document.getElementById('modal-title');
        var modalBody  = document.getElementById('modal-body');
        modalTitle.textContent = d.label || mac;
        modalBody.innerHTML =
          '<table style="width:100%;font-size:13px;border-collapse:collapse;">' +
          '<tr><td style="padding:6px 0;color:var(--muted);width:90px;">MAC</td><td style="font-family:monospace;">' + esc(d.mac) + '</td></tr>' +
          '<tr><td style="padding:6px 0;color:var(--muted);">IP</td><td style="font-family:monospace;">' + esc(d.ip) + '</td></tr>' +
          '<tr><td style="padding:6px 0;color:var(--muted);">Label</td><td>' + (d.label ? esc(d.label) : '<em style="color:var(--muted)">Unlabelled</em>') + '</td></tr>' +
          '<tr><td style="padding:6px 0;color:var(--muted);">First seen</td><td>' + esc(d.first_seen) + '</td></tr>' +
          '<tr><td style="padding:6px 0;color:var(--muted);">Last seen</td><td>' + esc(d.last_seen) + '</td></tr>' +
          '</table>' +
          '<p style="margin-top:14px;font-size:12px;color:var(--muted);">Go to the Devices tab to add a label for this device.</p>';
        if (localStorage.getItem('demo-mode') === '1') {
          if (window._demoAnonymise) { window._demoAnonymise(modalTitle); window._demoAnonymise(modalBody); }
        }
        document.getElementById('device-modal').style.display = 'flex';
      });
  }
  document.addEventListener('click', function(e){
    var item = e.target.closest('.alert-clickable');
    if (item) openModal(item.dataset.mac);
  });
  document.getElementById('modal-close').addEventListener('click', function(){
    document.getElementById('device-modal').style.display = 'none';
  });
  document.getElementById('device-modal').addEventListener('click', function(e){
    if (e.target === this) this.style.display = 'none';
  });
})();

// Demo mode — replaces real MACs and IPs with consistent fake values
(function(){
  var DEMO_KEY = 'demo-mode';
  var macMap = {}, ipMap = {};
  var MAC_PREFIXES = ['DE:AD:BE', 'FA:KE:01', 'C0:FF:EE', '00:1A:2B', 'AC:DE:48'];
  var MAC_RE = /([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/g;
  var IP_RE = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g;

  function hash(s) {
    var h = 0;
    for (var i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
    return Math.abs(h);
  }

  function fakeMac(real) {
    var key = real.toUpperCase();
    if (!macMap[key]) {
      var h = hash(key);
      var pfx = MAC_PREFIXES[h % MAC_PREFIXES.length];
      var b = function(n){ return ('0' + (n & 0xFF).toString(16)).slice(-2).toUpperCase(); };
      macMap[key] = pfx + ':' + b(h >> 8) + ':' + b(h >> 16) + ':' + b(h >> 24);
    }
    return macMap[key];
  }

  function fakeIp(real) {
    if (!ipMap[real]) {
      var h = hash(real);
      ipMap[real] = '10.0.' + ((h >> 8) & 0xFE) + '.' + ((h & 0xFE) || 2);
    }
    return ipMap[real];
  }

  function anonymiseText(t) {
    return t.replace(MAC_RE, function(m){ return fakeMac(m); })
            .replace(IP_RE,  function(m){ return fakeIp(m); });
  }

  function anonymiseNode(node) {
    if (node.nodeType === 3) {
      var o = node.textContent, r = anonymiseText(o);
      if (r !== o) node.textContent = r;
    } else if (node.nodeType === 1) {
      ['title', 'placeholder', 'value'].forEach(function(a){
        if (node.hasAttribute && node.hasAttribute(a)) {
          var o = node.getAttribute(a), r = anonymiseText(o);
          if (r !== o) node.setAttribute(a, r);
        }
      });
      node.childNodes.forEach(anonymiseNode);
    }
  }

  // Watch the device table so async-rendered or refreshed content gets anonymised.
  // Stored outside setDemo so we only create one observer instance.
  var _observer = null;

  function ensureObserver() {
    if (_observer) return;
    _observer = new MutationObserver(function(muts){
      muts.forEach(function(m){
        m.addedNodes.forEach(function(n){ anonymiseNode(n); });
      });
    });
    _observer.observe(document.getElementById('device-table'), { childList: true, subtree: true });
  }

  function setDemo(on) {
    document.getElementById('demo-banner').style.display = on ? 'block' : 'none';
    document.getElementById('demo-checkbox').checked = on;
    localStorage.setItem(DEMO_KEY, on ? '1' : '0');
    if (on) {
      ensureObserver();
      anonymiseNode(document.body);
    } else {
      location.reload();
    }
  }

  document.getElementById('demo-checkbox').addEventListener('change', function(){
    setDemo(this.checked);
  });

  // Expose for external callers (e.g. the device modal)
  window._demoAnonymise = anonymiseNode;

  if (localStorage.getItem(DEMO_KEY) === '1') {
    setDemo(true);
  }
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
@require_auth
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
@require_auth
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

    new_macs = network_summary.upsert_devices(devices)
    went_offline, came_online = network_summary.update_device_status([d[0] for d in devices])
    network_summary.process_scan_alerts(new_macs, alert_storage,
                                        devices=devices,
                                        went_offline=went_offline,
                                        came_online=came_online)

    return redirect(url_for("home"))

@app.route("/metrics")
@require_auth
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
@require_auth
def devices_endpoint():
    # Returns the full device inventory as JSON for the dashboard table.
    rows = network_summary.load_devices()
    return {
        "devices": [
            {"mac": r[0], "ip": r[1], "first_seen": r[2], "last_seen": r[3],
             "label": r[4] or "", "online": bool(r[5])}
            for r in rows
        ]
    }


@app.route("/devices/<mac>")
@require_auth
def device_detail(mac):
    # Returns a single device's details as JSON for the alert click-through modal.
    rows = network_summary.load_devices()
    for r in rows:
        if r[0].lower() == mac.lower():
            return {"mac": r[0], "ip": r[1], "first_seen": r[2], "last_seen": r[3], "label": r[4] or ""}
    return {"error": "Not found"}, 404


@app.route("/history")
@require_auth
def history():
    # Returns the last 20 scans as JSON for the scan history table in the Summary tab.
    return {"history": network_summary.load_scan_history()}


@app.route("/connections")
@require_auth
def connections_endpoint():
    # Returns a live count of active TCP/UDP connections per local network IP.
    # Used by the device table to show which devices are currently talking to this machine.
    # Runs ss -tun on every request so the data is always fresh.
    return {"connections": network_summary.get_connections_by_ip()}


@app.route("/devices/<mac>/label", methods=["POST"])
@require_auth
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
@require_auth
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
@require_auth
def approve_action(action_id):
    # Executes the AI-suggested action and marks it approved.
    network_summary.approve_action(action_id)
    return redirect(url_for("home"))


@app.route("/actions/<int:action_id>/reject", methods=["POST"])
@require_auth
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
@require_auth
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
@require_auth
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
@require_auth
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
# The __main__ guard prevents the server starting if dashboard is ever imported
# by another module (e.g. tests, or a future WSGI entry point).
# Set FLASK_DEBUG=1 in .env to enable debug mode (auto-reload + full tracebacks).
# Defaults to off so it is safe to run without .env.
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=os.environ.get("FLASK_DEBUG", "0") == "1")
