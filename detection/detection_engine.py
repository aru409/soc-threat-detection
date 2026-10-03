from __future__ import annotations

import hashlib
import uuid

import pandas as pd

from detection.rules import (
    correlate_alerts,
    detect_brute_force_logins,
    detect_excessive_http_requests,
    detect_multiple_failed_logins,
    detect_port_scan,
    detect_sql_injection,
    detect_suspicious_login,
    detect_suspicious_urls,
)


def run_detection(events: pd.DataFrame) -> list[dict]:
    if events.empty:
        return []

    alerts: list[dict] = []
    detectors = [
        detect_brute_force_logins,
        detect_multiple_failed_logins,
        detect_suspicious_login,
        detect_sql_injection,
        detect_port_scan,
        detect_excessive_http_requests,
        detect_suspicious_urls,
    ]

    for detector in detectors:
        alerts.extend(detector(events))

    alerts = correlate_alerts(alerts)

    for alert in alerts:
        fingerprint = _build_alert_fingerprint(alert)
        alert["alert_fingerprint"] = fingerprint
        alert["alert_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint))

    return alerts


def _build_alert_fingerprint(alert: dict) -> str:
    fields = [
        str(alert.get("timestamp", "")),
        str(alert.get("rule_name", "")),
        str(alert.get("event_type", "")),
        str(alert.get("source_ip", "")),
        str(alert.get("destination_ip", "")),
        str(alert.get("username", "")),
        str(alert.get("severity", "")),
        str(alert.get("mitre_technique", "")),
        str(alert.get("description", "")),
        str(alert.get("evidence", "")),
        str(alert.get("event_count", "")),
        str(alert.get("source_type", "")),
    ]
    digest_input = "|".join(fields)
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
