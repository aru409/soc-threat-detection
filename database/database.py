from __future__ import annotations

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
                destination_port INTEGER
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
                username TEXT,
                severity TEXT,
                confidence REAL,
                description TEXT,
                mitre_technique TEXT,
                status TEXT DEFAULT 'Open'
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

        self.conn.commit()

    def insert_events(self, events: pd.DataFrame) -> None:
        if events.empty:
            return

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
            "destination_port",
        ]
        payload = events.copy()
        for column in columns:
            if column not in payload.columns:
                payload[column] = None

        payload[columns].to_sql(
            "normalized_events", self.conn, if_exists="append", index=False
        )

    def insert_alerts(self, alerts: list[dict]) -> None:
        if not alerts:
            return

        cursor = self.conn.cursor()
        for alert in alerts:
            cursor.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, rule_name, event_type, source_ip,
                    username, severity, confidence, description, mitre_technique, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["alert_id"],
                    alert["timestamp"],
                    alert["rule_name"],
                    alert["event_type"],
                    alert["source_ip"],
                    alert["username"],
                    alert["severity"],
                    alert["confidence"],
                    alert["description"],
                    alert["mitre_technique"],
                    alert["status"],
                ),
            )

            cursor.execute(
                """
                INSERT OR IGNORE INTO incidents(alert_id, status, created_at, updated_at)
                VALUES (?, ?, datetime('now'), datetime('now'))
                """,
                (alert["alert_id"], alert["status"]),
            )

        self.conn.commit()

    def fetch_alerts(self) -> pd.DataFrame:
        return pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY timestamp DESC", self.conn
        )

    def fetch_incidents(self) -> pd.DataFrame:
        return pd.read_sql_query(
            "SELECT * FROM incidents ORDER BY updated_at DESC", self.conn
        )

    def update_alert_status(self, alert_id: str, status: str) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id)
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

    def fetch_events_count(self) -> int:
        cursor = self.conn.cursor()
        value = cursor.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
        return int(value)
