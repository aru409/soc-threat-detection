from __future__ import annotations

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
        alert["alert_id"] = str(uuid.uuid4())

    return alerts
