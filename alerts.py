import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta


# ==========================
# Alert Model
# ==========================

# Simple data container for a single alert event.
# level: "critical", "warning", or "info" (info is used when a condition clears)
# title: a stable string that identifies the alert type (used as the dedup key)
# message: human-readable detail shown in the dashboard
# timestamp: when the alert was generated (UTC)
@dataclass
class Alert:
    level: str
    title: str
    message: str
    timestamp: datetime


# ==========================
# Alert Storage
# ==========================

class AlertStorage:
    # Handles reading and writing alerts to the SQLite database.
    # Each alert row tracks whether it has been resolved (resolved = 0/1).
    # Deduplication is done by title — only one unresolved alert per title
    # can exist at a time.

    def __init__(self, db_path="network_history.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        # Creates the alerts table if it doesn't already exist.
        # Called automatically on construction so callers don't need to worry about setup.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            fire_count INTEGER DEFAULT 1
        )
        """)

        # Migrate older databases that don't have the fire_count column yet.
        try:
            cursor.execute("ALTER TABLE alerts ADD COLUMN fire_count INTEGER DEFAULT 1")
        except sqlite3.OperationalError:
            pass

        # Cooldown log — persists last-fired timestamps across process restarts.
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_cooldowns (
            key TEXT PRIMARY KEY,
            last_fired TEXT NOT NULL
        )
        """)

        conn.commit()
        conn.close()

    # -------------------------
    # Cooldown persistence
    # -------------------------

    def get_last_fired(self, key):
        # Returns the datetime the given alert key last fired, or None if never.
        # Used by AlertEngine to check cooldown across process restarts.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT last_fired FROM alert_cooldowns WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        if row:
            try:
                return datetime.fromisoformat(row[0])
            except ValueError:
                return None
        return None

    def set_last_fired(self, key):
        # Records the current UTC time as the last-fired time for this alert key.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO alert_cooldowns (key, last_fired) VALUES (?, ?)",
            (key, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()

    # -------------------------
    # Create / Update Alerts
    # -------------------------

    def save(self, alert: Alert):
        # Inserts a new alert row into the database as unresolved (resolved = 0).
        # Callers should check get_active_by_title() first to avoid duplicates.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO alerts (level, title, message, created_at, resolved, fire_count)
        VALUES (?, ?, ?, ?, 0, 1)
        """, (
            alert.level,
            alert.title,
            alert.message,
            alert.timestamp.isoformat()
        ))

        conn.commit()
        conn.close()

    def get_active_by_title(self, title):
        # Returns the ID of the first unresolved alert matching the given title,
        # or None if no such alert exists.
        # Used to prevent inserting duplicate alerts for the same ongoing condition.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        SELECT id FROM alerts
        WHERE title = ? AND resolved = 0
        """, (title,))

        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def increment_fire_count(self, title):
        # Increments the scan count for an active alert each time the condition is still present.
        # When fire_count reaches 3 (the condition has persisted across 3 scans / ~9 hours),
        # the alert is automatically escalated from "warning" to "critical".
        # Returns True if the alert was just escalated so the caller can send a desktop notification.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT fire_count, level FROM alerts WHERE title = ? AND resolved = 0",
            (title,)
        )
        row = cursor.fetchone()
        escalated = False

        if row:
            new_count = row[0] + 1
            new_level = "critical" if new_count >= 3 and row[1] == "warning" else row[1]
            escalated = (new_count == 3 and row[1] == "warning")
            cursor.execute(
                "UPDATE alerts SET fire_count = ?, level = ? WHERE title = ? AND resolved = 0",
                (new_count, new_level, title)
            )

        conn.commit()
        conn.close()
        return escalated

    def resolve_by_title(self, title):
        # Marks all unresolved alerts with the given title as resolved (resolved = 1).
        # Called when an "info" alert arrives, indicating the problem has cleared.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
        UPDATE alerts
        SET resolved = 1
        WHERE title = ? AND resolved = 0
        """, (title,))

        conn.commit()
        conn.close()

    # -------------------------
    # Dashboard Queries
    # -------------------------

    def get_active_alerts(self):
        # Returns all currently unresolved alerts, newest first.
        # Used by the dashboard to populate the "Active Alerts" panel.
        # Each row is (level, title, message, created_at, fire_count).
        # fire_count >= 3 means the condition has been present for 3+ scans and was escalated.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT level, title, message, created_at, fire_count
            FROM alerts
            WHERE resolved = 0
            ORDER BY created_at DESC
        """)

        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_recent_resolved(self):
        # Returns up to 20 alerts that were resolved within the last 7 days, newest first.
        # Used by the dashboard to populate the "Recently Resolved" panel.
        # Each row is (level, title, message, created_at).
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT level, title, message, created_at
            FROM alerts
            WHERE resolved = 1
            AND datetime(created_at) >= datetime('now','-7 days')
            ORDER BY created_at DESC
            LIMIT 20
        """)

        rows = cursor.fetchall()
        conn.close()
        return rows


# ==========================
# Alert Engine
# ==========================

class AlertEngine:
    # Evaluates current network metrics against thresholds and produces Alert objects.
    # Takes a metric_storage object (expected to have a get_latest() method that returns
    # a dict with host_reachable, latency_ms, and packet_loss keys).
    # Cooldown state is persisted to the DB via alert_storage so it survives restarts —
    # the same alert key won't fire again until cooldown_minutes (10) have passed.

    def __init__(self, metric_storage, alert_storage=None):
        self.metric_storage = metric_storage
        self.alert_storage = alert_storage
        self.cooldown_minutes = 10

    def can_alert(self, key):
        # Returns True if enough time has passed since the last alert for this key.
        # Checks the DB when alert_storage is provided; falls back to always-true otherwise.
        # Records the current time as the last-fired timestamp when returning True.
        now = datetime.utcnow()
        if self.alert_storage:
            last = self.alert_storage.get_last_fired(key)
            if last and now - last <= timedelta(minutes=self.cooldown_minutes):
                return False
            self.alert_storage.set_last_fired(key)
        return True

    def run_checks(self):
        # Fetches the latest metrics and runs all threshold checks.
        # Returns a list of Alert objects — both problem alerts (critical/warning)
        # and clearance alerts (info, used to resolve previously active alerts).
        # Returns an empty list if no metric data is available yet.
        alerts = []
        latest = self.metric_storage.get_latest()

        if not latest:
            return alerts

        # Check 1a: gateway reachability — critical if the local router doesn't respond
        # (indicates a LAN problem rather than an ISP problem)
        if latest.get("gateway_ip"):
            if not latest.get("gateway_reachable"):
                if self.can_alert("gateway_down"):
                    alerts.append(Alert(
                        level="critical",
                        title="Gateway unreachable",
                        message=f"Local gateway ({latest['gateway_ip']}) is not responding — LAN may be down",
                        timestamp=datetime.utcnow()
                    ))
            else:
                alerts.append(Alert(
                    level="info",
                    title="Gateway unreachable",
                    message="Gateway reachable again",
                    timestamp=datetime.utcnow()
                ))

        # Check 1b: internet reachability — critical if 8.8.8.8 is not responding
        # (gateway is up but ISP connection is down)
        if not latest["host_reachable"]:
            if self.can_alert("host_down"):
                alerts.append(Alert(
                    level="critical",
                    title="Host unreachable",
                    message="Internet host (8.8.8.8) not responding — ISP connection may be down",
                    timestamp=datetime.utcnow()
                ))
        else:
            # Emit an info alert to clear any existing "Host unreachable" alert
            alerts.append(Alert(
                level="info",
                title="Host unreachable",
                message="Internet host reachable again",
                timestamp=datetime.utcnow()
            ))

        # Check 2: latency — warning if average round-trip to 8.8.8.8 exceeds 80ms
        if latest["latency_ms"] > 80:
            if self.can_alert("latency"):
                alerts.append(Alert(
                    level="warning",
                    title="High latency detected",
                    message=f"Latency is {latest['latency_ms']:.1f} ms",
                    timestamp=datetime.utcnow()
                ))
        else:
            # Emit an info alert to clear any existing "High latency" alert
            alerts.append(Alert(
                level="info",
                title="High latency detected",
                message="Latency back to normal",
                timestamp=datetime.utcnow()
            ))

        # Check 3: packet loss — critical if more than 5% of pings are dropped
        if latest["packet_loss"] > 5:
            if self.can_alert("packet_loss"):
                alerts.append(Alert(
                    level="critical",
                    title="Packet loss detected",
                    message=f"{latest['packet_loss']:.1f}% packet loss",
                    timestamp=datetime.utcnow()
                ))
        else:
            # Emit an info alert to clear any existing "Packet loss" alert
            alerts.append(Alert(
                level="info",
                title="Packet loss detected",
                message="Packet loss cleared",
                timestamp=datetime.utcnow()
            ))

        return alerts
