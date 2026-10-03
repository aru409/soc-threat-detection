from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
import re

import pandas as pd

from detection.mitre_mapping import MITRE_MAPPING

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SQLI_PATTERN = re.compile(
    r"(union\s+select|or\s+1=1|drop\s+table|sleep\s*\(|information_schema)",
    re.IGNORECASE,
)
SUSPICIOUS_URL_PATTERN = re.compile(
    r"(\.\./|/etc/passwd|/wp-admin|/admin|select\s+\*)", re.IGNORECASE
)


def classify_severity(rule_name: str, count: int = 1) -> str:
    if rule_name in {"Brute Force Login", "SQL Injection Indicators"}:
        return "HIGH" if count < 10 else "CRITICAL"
    if rule_name in {"Port Scanning Indicators", "Suspicious Login"}:
        return "HIGH"
    if rule_name in {"Excessive HTTP Requests", "Multiple Failed Login Attempts"}:
        return "MEDIUM"
    return "LOW"


def _build_alert(
    timestamp: str,
    rule_name: str,
    event_type: str,
    source_ip: str,
    username: str,
    confidence: float,
    description: str,
) -> dict:
    return {
        "timestamp": timestamp,
        "rule_name": rule_name,
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "severity": classify_severity(rule_name),
        "confidence": confidence,
        "description": description,
        "mitre_technique": MITRE_MAPPING.get(rule_name, ""),
        "status": "Open",
    }


def detect_brute_force_logins(events: pd.DataFrame) -> list[dict]:
    failed = events[
        (events["event_type"].str.contains("auth", case=False, na=False))
        & (events["status"].str.contains("fail", case=False, na=False))
    ].copy()

    if failed.empty:
        return []

    failed["timestamp"] = pd.to_datetime(failed["timestamp"])
    alerts = []

    for source_ip, group in failed.groupby("source_ip"):
        ordered = group.sort_values("timestamp")
        for _, event in ordered.iterrows():
            window_end = event["timestamp"] + timedelta(minutes=10)
            attempts = ordered[
                (ordered["timestamp"] >= event["timestamp"])
                & (ordered["timestamp"] <= window_end)
            ]
            if len(attempts) >= 5:
                alerts.append(
                    _build_alert(
                        timestamp=event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        rule_name="Brute Force Login",
                        event_type="authentication",
                        source_ip=source_ip,
                        username=str(event.get("username", "")),
                        confidence=0.9,
                        description=f"{len(attempts)} failed logins from {source_ip} in 10 minutes.",
                    )
                )
                break
    return alerts


def detect_multiple_failed_logins(events: pd.DataFrame) -> list[dict]:
    failed = events[
        (events["event_type"].str.contains("auth", case=False, na=False))
        & (events["status"].str.contains("fail", case=False, na=False))
    ].copy()

    if failed.empty:
        return []

    failed["timestamp"] = pd.to_datetime(failed["timestamp"])
    alerts = []

    for username, group in failed.groupby("username"):
        if not username:
            continue
        first = group["timestamp"].min()
        last = group["timestamp"].max()
        if len(group) >= 3 and (last - first) <= timedelta(minutes=15):
            alerts.append(
                _build_alert(
                    timestamp=first.strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Multiple Failed Login Attempts",
                    event_type="authentication",
                    source_ip=str(group.iloc[0].get("source_ip", "")),
                    username=username,
                    confidence=0.75,
                    description=f"User {username} had {len(group)} failed logins in a short period.",
                )
            )
    return alerts


def detect_suspicious_login(events: pd.DataFrame) -> list[dict]:
    events = events.copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"])

    failed = events[
        (events["event_type"].str.contains("auth", case=False, na=False))
        & (events["status"].str.contains("fail", case=False, na=False))
    ]
    success = events[
        (events["event_type"].str.contains("auth", case=False, na=False))
        & (events["status"].str.contains("success", case=False, na=False))
    ]

    alerts = []
    for _, successful in success.iterrows():
        source_ip = successful.get("source_ip", "")
        username = successful.get("username", "")
        attempts = failed[
            (failed["source_ip"] == source_ip)
            & (failed["username"] == username)
            & (
                (successful["timestamp"] - failed["timestamp"])
                <= timedelta(minutes=20)
            )
            & ((successful["timestamp"] - failed["timestamp"]) >= timedelta(0))
        ]
        if len(attempts) >= 3:
            alerts.append(
                _build_alert(
                    timestamp=successful["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Suspicious Login",
                    event_type="authentication",
                    source_ip=str(source_ip),
                    username=str(username),
                    confidence=0.8,
                    description="Successful login happened soon after repeated failures.",
                )
            )
    return alerts


def detect_sql_injection(events: pd.DataFrame) -> list[dict]:
    web_events = events[
        events["event_type"].str.contains("web", case=False, na=False)
    ]
    alerts = []

    for _, event in web_events.iterrows():
        message = str(event.get("message", ""))
        if SQLI_PATTERN.search(message):
            alerts.append(
                _build_alert(
                    timestamp=str(event.get("timestamp", "")),
                    rule_name="SQL Injection Indicators",
                    event_type="web",
                    source_ip=str(event.get("source_ip", "")),
                    username=str(event.get("username", "")),
                    confidence=0.92,
                    description=f"Request contains SQL injection pattern: {message[:120]}",
                )
            )
    return alerts


def detect_port_scan(events: pd.DataFrame) -> list[dict]:
    network_events = events[
        events["event_type"].str.contains("network", case=False, na=False)
    ].copy()
    if network_events.empty:
        return []

    network_events["timestamp"] = pd.to_datetime(network_events["timestamp"])
    if "destination_port" not in network_events.columns:
        network_events["destination_port"] = pd.to_numeric(
            network_events["message"].str.extract(r"port=(\d+)")[0], errors="coerce"
        )

    alerts = []
    for source_ip, group in network_events.groupby("source_ip"):
        group = group.sort_values("timestamp")
        first = group["timestamp"].min()
        window = group[group["timestamp"] <= first + timedelta(minutes=5)]
        unique_ports = window["destination_port"].dropna().nunique()

        if unique_ports >= 10:
            alerts.append(
                _build_alert(
                    timestamp=first.strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Port Scanning Indicators",
                    event_type="network",
                    source_ip=str(source_ip),
                    username=str(group.iloc[0].get("username", "")),
                    confidence=0.88,
                    description=f"Source {source_ip} probed {unique_ports} ports in 5 minutes.",
                )
            )
    return alerts


def detect_excessive_http_requests(events: pd.DataFrame) -> list[dict]:
    web_events = events[
        events["event_type"].str.contains("web", case=False, na=False)
    ].copy()
    if web_events.empty:
        return []

    web_events["timestamp"] = pd.to_datetime(web_events["timestamp"])
    alerts = []

    for source_ip, group in web_events.groupby("source_ip"):
        first = group["timestamp"].min()
        one_minute = group[group["timestamp"] <= first + timedelta(minutes=1)]
        if len(one_minute) >= 30:
            alerts.append(
                _build_alert(
                    timestamp=first.strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Excessive HTTP Requests",
                    event_type="web",
                    source_ip=str(source_ip),
                    username=str(group.iloc[0].get("username", "")),
                    confidence=0.7,
                    description=f"{len(one_minute)} requests from {source_ip} in 1 minute.",
                )
            )
    return alerts


def detect_suspicious_urls(events: pd.DataFrame) -> list[dict]:
    web_events = events[
        events["event_type"].str.contains("web", case=False, na=False)
    ]
    alerts = []

    for _, event in web_events.iterrows():
        message = str(event.get("message", ""))
        if SUSPICIOUS_URL_PATTERN.search(message):
            alerts.append(
                _build_alert(
                    timestamp=str(event.get("timestamp", "")),
                    rule_name="Suspicious URL Pattern",
                    event_type="web",
                    source_ip=str(event.get("source_ip", "")),
                    username=str(event.get("username", "")),
                    confidence=0.72,
                    description=f"Suspicious URL/request pattern observed: {message[:120]}",
                )
            )
    return alerts


def correlate_alerts(alerts: list[dict], time_window_minutes: int = 30) -> list[dict]:
    if not alerts:
        return alerts

    grouped = defaultdict(list)
    for idx, alert in enumerate(alerts):
        grouped[alert.get("source_ip", "")].append((idx, alert))

    for source_ip, entries in grouped.items():
        if not source_ip or len(entries) < 2:
            continue
        entries = sorted(
            entries,
            key=lambda item: pd.to_datetime(item[1]["timestamp"], errors="coerce"),
        )

        first_ts = pd.to_datetime(entries[0][1]["timestamp"], errors="coerce")
        last_ts = pd.to_datetime(entries[-1][1]["timestamp"], errors="coerce")

        if pd.isna(first_ts) or pd.isna(last_ts):
            continue
        if (last_ts - first_ts) <= timedelta(minutes=time_window_minutes):
            for _, alert in entries:
                current = alert["severity"]
                position = min(SEVERITY_ORDER.index(current) + 1, len(SEVERITY_ORDER) - 1)
                alert["severity"] = SEVERITY_ORDER[position]
                alert["description"] += " Correlated activity from same source IP increased risk."

    return alerts
