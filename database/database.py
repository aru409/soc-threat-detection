from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pandas as pd


class SOCDatabase:
    def __init__(self, db_path: str = "soc_monitoring.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def initialize(self) -> None:
        cursor = self.conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS normalized_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                event_type TEXT,
                action TEXT,
                status TEXT,
                message TEXT,
                source TEXT,
                source_type TEXT DEFAULT 'sample',
                destination_port INTEGER,
                event_hash TEXT UNIQUE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                rule_name TEXT,
                event_type TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                severity TEXT,
                confidence REAL,
                description TEXT,
                mitre_technique TEXT,
                status TEXT DEFAULT 'Open',
                source TEXT,
                source_type TEXT DEFAULT 'sample',
                evidence TEXT,
                event_count INTEGER DEFAULT 1,
                correlated INTEGER DEFAULT 0,
                correlation_key TEXT,
                alert_fingerprint TEXT UNIQUE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE,
                status TEXT,
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
            )
            """
        )

        self._ensure_column("normalized_events", "source_type", "TEXT DEFAULT 'sample'")
        self._ensure_column("normalized_events", "event_hash", "TEXT")

        self._ensure_column("alerts", "destination_ip", "TEXT")
        self._ensure_column("alerts", "source", "TEXT")
        self._ensure_column("alerts", "source_type", "TEXT DEFAULT 'sample'")
        self._ensure_column("alerts", "evidence", "TEXT")
        self._ensure_column("alerts", "event_count", "INTEGER DEFAULT 1")
        self._ensure_column("alerts", "correlated", "INTEGER DEFAULT 0")
        self._ensure_column("alerts", "correlation_key", "TEXT")
        self._ensure_column("alerts", "alert_fingerprint", "TEXT")

        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_normalized_events_hash ON normalized_events(event_hash)"
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(alert_fingerprint)"
        )
        self.conn.commit()

    def _ensure_column(self, table_name: str, column_name: str, definition: str) -> None:
        cursor = self.conn.cursor()
        existing = {
            row["name"] for row in cursor.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name not in existing:
            cursor.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
            )

    def insert_events(self, events: pd.DataFrame) -> int:
        if events.empty:
            return 0

        payload = events.copy()
        columns = [
            "timestamp",
            "source_ip",
            "destination_ip",
            "username",
            "event_type",
            "action",
            "status",
            "message",
            "source",
            "source_type",
            "destination_port",
        ]
        for column in columns:
            if column not in payload.columns:
                payload[column] = "" if column != "destination_port" else None

        payload["source_type"] = payload["source_type"].replace("", "sample")
        payload["event_hash"] = payload.apply(self._build_event_hash, axis=1)

        rows = [
            (
                row["timestamp"],
                row["source_ip"],
                row["destination_ip"],
                row["username"],
                row["event_type"],
                row["action"],
                row["status"],
                row["message"],
                row["source"],
                row["source_type"],
                row["destination_port"],
                row["event_hash"],
            )
            for _, row in payload.iterrows()
        ]

        cursor = self.conn.cursor()
        cursor.executemany(
            """
            INSERT OR IGNORE INTO normalized_events (
                timestamp, source_ip, destination_ip, username, event_type,
                action, status, message, source, source_type, destination_port, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()
        return cursor.rowcount

    def _build_event_hash(self, row: pd.Series) -> str:
        fields = [
            str(row.get("timestamp", "")),
            str(row.get("source_ip", "")),
            str(row.get("destination_ip", "")),
            str(row.get("username", "")),
            str(row.get("event_type", "")),
            str(row.get("action", "")),
            str(row.get("status", "")),
            str(row.get("message", "")),
            str(row.get("source", "")),
            str(row.get("source_type", "sample") or "sample"),
            str(row.get("destination_port", "")),
        ]
        return hashlib.sha256("|".join(fields).encode("utf-8")).hexdigest()

    def insert_alerts(self, alerts: list[dict]) -> int:
        if not alerts:
            return 0

        cursor = self.conn.cursor()
        inserted = 0

        for alert in alerts:
            fingerprint = alert.get("alert_fingerprint") or self._build_alert_fingerprint(alert)
            alert_id = alert.get("alert_id")
            if not alert_id:
                alert_id = hashlib.md5(fingerprint.encode("utf-8")).hexdigest()

            cursor.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    alert_id, timestamp, rule_name, event_type, source_ip,
                    destination_ip, username, severity, confidence, description,
                    mitre_technique, status, source, source_type, evidence,
                    event_count, correlated, correlation_key, alert_fingerprint
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    alert.get("timestamp", ""),
                    alert.get("rule_name", ""),
                    alert.get("event_type", ""),
                    alert.get("source_ip", ""),
                    alert.get("destination_ip", ""),
                    alert.get("username", ""),
                    alert.get("severity", "LOW"),
                    alert.get("confidence", 0.0),
                    alert.get("description", ""),
                    alert.get("mitre_technique", ""),
                    alert.get("status", "Open"),
                    alert.get("source", ""),
                    alert.get("source_type", "sample"),
                    alert.get("evidence", ""),
                    int(alert.get("event_count", 1)),
                    int(alert.get("correlated", 0)),
                    alert.get("correlation_key", ""),
                    fingerprint,
                ),
            )

            if cursor.rowcount == 1:
                inserted += 1
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO incidents(alert_id, status, created_at, updated_at)
                    VALUES (?, ?, datetime('now'), datetime('now'))
                    """,
                    (alert_id, alert.get("status", "Open")),
                )

        self.conn.commit()
        return inserted

    def _build_alert_fingerprint(self, alert: dict) -> str:
        fields = [
            str(alert.get("timestamp", "")),
            str(alert.get("rule_name", "")),
            str(alert.get("event_type", "")),
            str(alert.get("source_ip", "")),
            str(alert.get("destination_ip", "")),
            str(alert.get("username", "")),
            str(alert.get("severity", "")),
            str(alert.get("description", "")),
            str(alert.get("mitre_technique", "")),
            str(alert.get("source", "")),
            str(alert.get("source_type", "")),
            str(alert.get("evidence", "")),
            str(alert.get("event_count", 1)),
        ]
        return hashlib.sha256("|".join(fields).encode("utf-8")).hexdigest()

    def fetch_alerts(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", self.conn)

    def fetch_incidents(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT * FROM incidents ORDER BY updated_at DESC", self.conn)

    def fetch_events(self) -> pd.DataFrame:
        return pd.read_sql_query(
            """
            SELECT timestamp, source_ip, destination_ip, username, event_type,
                   action, status, message, source, source_type, destination_port
            FROM normalized_events
            ORDER BY timestamp DESC
            """,
            self.conn,
        )

    def fetch_events_count(self) -> int:
        cursor = self.conn.cursor()
        value = cursor.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
        return int(value)

    def update_alert_status(self, alert_id: str, status: str) -> None:
        cursor = self.conn.cursor()
        cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))

        cursor.execute(
            """
            INSERT OR IGNORE INTO incidents(alert_id, status, created_at, updated_at)
            VALUES (?, ?, datetime('now'), datetime('now'))
            """,
            (alert_id, status),
        )

        cursor.execute(
            """
            UPDATE incidents
            SET status = ?, updated_at = datetime('now')
            WHERE alert_id = ?
            """,
            (status, alert_id),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
