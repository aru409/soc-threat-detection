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
    if rule_name == "Brute Force Login":
        return "HIGH" if count < 10 else "CRITICAL"
    if rule_name == "SQL Injection Indicators":
        return "HIGH" if count < 5 else "CRITICAL"
    if rule_name == "Port Scanning Indicators":
        return "HIGH" if count < 30 else "CRITICAL"
    if rule_name == "Suspicious Login":
        return "HIGH"
    if rule_name == "Excessive HTTP Requests":
        if count >= 120:
            return "CRITICAL"
        return "MEDIUM" if count < 60 else "HIGH"
    if rule_name == "Multiple Failed Login Attempts":
        return "MEDIUM" if count < 6 else "HIGH"
    if rule_name == "Suspicious URL Pattern":
        return "MEDIUM"
    return "LOW"


def _safe_string(value: object) -> str:
    if value is None:
        return ""
    if pd.isna(value):
        return ""
    return str(value)


def _build_alert(
    timestamp: str,
    rule_name: str,
    event_type: str,
    source_ip: str,
    username: str,
    confidence: float,
    description: str,
    destination_ip: str = "",
    source: str = "",
    source_type: str = "sample",
    evidence: str = "",
    event_count: int = 1,
) -> dict:
    return {
        "timestamp": timestamp,
        "rule_name": rule_name,
        "event_type": event_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "severity": classify_severity(rule_name, count=event_count),
        "confidence": confidence,
        "description": description,
        "mitre_technique": MITRE_MAPPING.get(rule_name, ""),
        "status": "Open",
        "source": source,
        "source_type": source_type,
        "evidence": evidence,
        "event_count": event_count,
        "correlated": 0,
        "correlation_key": "",
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
                evidence_messages = attempts["message"].astype(str).head(3).tolist()
                alerts.append(
                    _build_alert(
                        timestamp=event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                        rule_name="Brute Force Login",
                        event_type="authentication",
                        source_ip=_safe_string(source_ip),
                        destination_ip=_safe_string(event.get("destination_ip", "")),
                        username=_safe_string(event.get("username", "")),
                        confidence=0.9,
                        description=f"{len(attempts)} failed logins from {source_ip} in 10 minutes.",
                        source=_safe_string(event.get("source", "")),
                        source_type=_safe_string(event.get("source_type", "sample")) or "sample",
                        evidence=" | ".join(evidence_messages),
                        event_count=len(attempts),
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
            event = group.iloc[0]
            evidence_messages = group["message"].astype(str).head(3).tolist()
            alerts.append(
                _build_alert(
                    timestamp=first.strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Multiple Failed Login Attempts",
                    event_type="authentication",
                    source_ip=_safe_string(event.get("source_ip", "")),
                    destination_ip=_safe_string(event.get("destination_ip", "")),
                    username=_safe_string(username),
                    confidence=0.75,
                    description=f"User {username} had {len(group)} failed logins in a short period.",
                    source=_safe_string(event.get("source", "")),
                    source_type=_safe_string(event.get("source_type", "sample")) or "sample",
                    evidence=" | ".join(evidence_messages),
                    event_count=len(group),
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
            & ((successful["timestamp"] - failed["timestamp"]) <= timedelta(minutes=20))
            & ((successful["timestamp"] - failed["timestamp"]) >= timedelta(0))
        ]
        if len(attempts) >= 3:
            evidence = attempts["message"].astype(str).head(3).tolist()
            alerts.append(
                _build_alert(
                    timestamp=successful["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Suspicious Login",
                    event_type="authentication",
                    source_ip=_safe_string(source_ip),
                    destination_ip=_safe_string(successful.get("destination_ip", "")),
                    username=_safe_string(username),
                    confidence=0.8,
                    description="Successful login happened soon after repeated failures.",
                    source=_safe_string(successful.get("source", "")),
                    source_type=_safe_string(successful.get("source_type", "sample")) or "sample",
                    evidence=" | ".join(evidence),
                    event_count=len(attempts),
                )
            )
    return alerts


def detect_sql_injection(events: pd.DataFrame) -> list[dict]:
    web_events = events[events["event_type"].str.contains("web", case=False, na=False)]
    alerts = []

    for _, event in web_events.iterrows():
        message = _safe_string(event.get("message", ""))
        if SQLI_PATTERN.search(message):
            alerts.append(
                _build_alert(
                    timestamp=_safe_string(event.get("timestamp", "")),
                    rule_name="SQL Injection Indicators",
                    event_type="web",
                    source_ip=_safe_string(event.get("source_ip", "")),
                    destination_ip=_safe_string(event.get("destination_ip", "")),
                    username=_safe_string(event.get("username", "")),
                    confidence=0.92,
                    description=f"Request contains SQL injection pattern: {message[:120]}",
                    source=_safe_string(event.get("source", "")),
                    source_type=_safe_string(event.get("source_type", "sample")) or "sample",
                    evidence=message[:250],
                    event_count=1,
                )
            )
    return alerts


def detect_port_scan(events: pd.DataFrame) -> list[dict]:
    network_events = events[events["event_type"].str.contains("network", case=False, na=False)].copy()
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
            event = group.iloc[0]
            sample_ports = window["destination_port"].dropna().astype(int).astype(str).head(10).tolist()
            alerts.append(
                _build_alert(
                    timestamp=first.strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Port Scanning Indicators",
                    event_type="network",
                    source_ip=_safe_string(source_ip),
                    destination_ip=_safe_string(event.get("destination_ip", "")),
                    username=_safe_string(event.get("username", "")),
                    confidence=0.88,
                    description=f"Source {source_ip} probed {unique_ports} ports in 5 minutes.",
                    source=_safe_string(event.get("source", "")),
                    source_type=_safe_string(event.get("source_type", "sample")) or "sample",
                    evidence=f"Ports: {', '.join(sample_ports)}",
                    event_count=int(unique_ports),
                )
            )
    return alerts


def detect_excessive_http_requests(events: pd.DataFrame) -> list[dict]:
    web_events = events[events["event_type"].str.contains("web", case=False, na=False)].copy()
    if web_events.empty:
        return []

    web_events["timestamp"] = pd.to_datetime(web_events["timestamp"])
    alerts = []

    for source_ip, group in web_events.groupby("source_ip"):
        first = group["timestamp"].min()
        one_minute = group[group["timestamp"] <= first + timedelta(minutes=1)]
        if len(one_minute) >= 30:
            event = group.iloc[0]
            alerts.append(
                _build_alert(
                    timestamp=first.strftime("%Y-%m-%d %H:%M:%S"),
                    rule_name="Excessive HTTP Requests",
                    event_type="web",
                    source_ip=_safe_string(source_ip),
                    destination_ip=_safe_string(event.get("destination_ip", "")),
                    username=_safe_string(event.get("username", "")),
                    confidence=0.7,
                    description=f"{len(one_minute)} requests from {source_ip} in 1 minute.",
                    source=_safe_string(event.get("source", "")),
                    source_type=_safe_string(event.get("source_type", "sample")) or "sample",
                    evidence=" | ".join(one_minute["message"].astype(str).head(5).tolist()),
                    event_count=len(one_minute),
                )
            )
    return alerts


def detect_suspicious_urls(events: pd.DataFrame) -> list[dict]:
    web_events = events[events["event_type"].str.contains("web", case=False, na=False)]
    alerts = []

    for _, event in web_events.iterrows():
        message = _safe_string(event.get("message", ""))
        if SUSPICIOUS_URL_PATTERN.search(message):
            alerts.append(
                _build_alert(
                    timestamp=_safe_string(event.get("timestamp", "")),
                    rule_name="Suspicious URL Pattern",
                    event_type="web",
                    source_ip=_safe_string(event.get("source_ip", "")),
                    destination_ip=_safe_string(event.get("destination_ip", "")),
                    username=_safe_string(event.get("username", "")),
                    confidence=0.72,
                    description=f"Suspicious URL/request pattern observed: {message[:120]}",
                    source=_safe_string(event.get("source", "")),
                    source_type=_safe_string(event.get("source_type", "sample")) or "sample",
                    evidence=message[:250],
                    event_count=1,
                )
            )
    return alerts


def correlate_alerts(alerts: list[dict], time_window_minutes: int = 30) -> list[dict]:
    if not alerts:
        return alerts

    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for alert in alerts:
        group_key = (
            _safe_string(alert.get("source_ip", "")).strip(),
            _safe_string(alert.get("username", "")).strip(),
            _safe_string(alert.get("event_type", "")).strip(),
        )
        grouped[group_key].append(alert)

    for group_key, entries in grouped.items():
        source_ip, _, _ = group_key
        if not source_ip or len(entries) < 2:
            continue

        entries.sort(key=lambda item: pd.to_datetime(item["timestamp"], errors="coerce"))
        cluster = [entries[0]]

        for candidate in entries[1:]:
            previous_time = pd.to_datetime(cluster[-1]["timestamp"], errors="coerce")
            current_time = pd.to_datetime(candidate["timestamp"], errors="coerce")

            if pd.isna(previous_time) or pd.isna(current_time):
                continue

            if (current_time - previous_time) <= timedelta(minutes=time_window_minutes):
                cluster.append(candidate)
            else:
                _apply_correlation_to_cluster(cluster)
                cluster = [candidate]

        _apply_correlation_to_cluster(cluster)

    return alerts


def _apply_correlation_to_cluster(cluster: list[dict]) -> None:
    if len(cluster) < 2:
        return

    start_ts = pd.to_datetime(cluster[0]["timestamp"], errors="coerce")
    correlation_key = (
        f"{cluster[0].get('source_ip','')}|"
        f"{cluster[0].get('username','')}|"
        f"{cluster[0].get('event_type','')}|"
        f"{start_ts.strftime('%Y%m%d%H%M%S') if not pd.isna(start_ts) else 'unknown'}"
    )

    for alert in cluster:
        current = alert.get("severity", "LOW")
        if current in SEVERITY_ORDER:
            position = min(SEVERITY_ORDER.index(current) + 1, len(SEVERITY_ORDER) - 1)
            alert["severity"] = SEVERITY_ORDER[position]
        alert["correlated"] = 1
        alert["correlation_key"] = correlation_key
        suffix = " Correlated activity detected for the same source, user, and event type."
        if suffix.strip() not in alert.get("description", ""):
            alert["description"] = f"{alert.get('description', '').strip()}{suffix}".strip()
