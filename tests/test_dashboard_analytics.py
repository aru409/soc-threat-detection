import pandas as pd

from dashboard.analytics import build_alerts_timeline, compute_siem_kpis


def test_compute_siem_kpis_counts_are_correct():
    alerts = pd.DataFrame(
        [
            {"severity": "CRITICAL", "status": "Open", "source_ip": "1.1.1.1"},
            {"severity": "HIGH", "status": "Investigating", "source_ip": "2.2.2.2"},
            {"severity": "MEDIUM", "status": "Resolved", "source_ip": "3.3.3.3"},
            {"severity": "LOW", "status": "False Positive", "source_ip": "3.3.3.3"},
        ]
    )
    events = pd.DataFrame(
        [
            {"source_ip": "1.1.1.1"},
            {"source_ip": "2.2.2.2"},
            {"source_ip": "3.3.3.3"},
            {"source_ip": "4.4.4.4"},
        ]
    )

    metrics = compute_siem_kpis(alerts, events)

    assert metrics["total_events"] == 4
    assert metrics["total_alerts"] == 4
    assert metrics["critical_alerts"] == 1
    assert metrics["high_critical_alerts"] == 2
    assert metrics["open_incidents"] == 2
    assert metrics["resolved_incidents"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["unique_source_ips"] == 4


def test_build_alerts_timeline_groups_hourly():
    alerts = pd.DataFrame(
        [
            {"timestamp": "2026-10-03 08:00:00"},
            {"timestamp": "2026-10-03 08:20:00"},
            {"timestamp": "2026-10-03 09:10:00"},
        ]
    )
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

    timeline = build_alerts_timeline(alerts)

    assert len(timeline) == 2
    assert timeline.iloc[0]["count"] == 2
    assert timeline.iloc[1]["count"] == 1
