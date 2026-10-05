import pandas as pd

from detection.rules import (
    classify_severity,
    correlate_alerts,
    detect_brute_force_logins,
    detect_port_scan,
    detect_sql_injection,
)


def test_brute_force_detection_triggers_alert():
    events = pd.DataFrame(
        [
            {
                "timestamp": f"2026-10-03 08:0{i}:00",
                "source_ip": "203.0.113.10",
                "destination_ip": "10.0.0.10",
                "username": "alice",
                "event_type": "authentication",
                "action": "login",
                "status": "failed",
                "message": "invalid password",
                "source": "vpn",
                "source_type": "sample",
            }
            for i in range(5)
        ]
    )

    alerts = detect_brute_force_logins(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Brute Force Login"
    assert alerts[0]["event_count"] == 5


def test_sql_injection_detection_triggers_alert():
    events = pd.DataFrame(
        [
            {
                "timestamp": "2026-10-03 08:21:00",
                "source_ip": "203.0.113.15",
                "destination_ip": "10.0.0.20",
                "username": "",
                "event_type": "web",
                "action": "GET",
                "status": "success",
                "message": "/login.php?id=1 OR 1=1",
                "source": "web_server",
                "source_type": "sample",
            }
        ]
    )

    alerts = detect_sql_injection(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "SQL Injection Indicators"


def test_port_scan_detection_triggers_alert():
    events = pd.DataFrame(
        [
            {
                "timestamp": f"2026-10-03 08:3{i//4}:{(i%4)*15:02d}",
                "source_ip": "198.51.100.88",
                "destination_ip": "10.0.0.30",
                "destination_port": 20 + i,
                "username": "",
                "event_type": "network",
                "action": "connection_attempt",
                "status": "blocked",
                "message": f"Scan attempt on port={20+i}",
                "source": "firewall",
                "source_type": "sample",
            }
            for i in range(11)
        ]
    )

    alerts = detect_port_scan(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Port Scanning Indicators"
    assert alerts[0]["event_count"] == 11


def test_severity_classification_uses_detection_count():
    assert classify_severity("Brute Force Login", count=5) == "HIGH"
    assert classify_severity("Brute Force Login", count=10) == "CRITICAL"
    assert classify_severity("Excessive HTTP Requests", count=59) == "MEDIUM"
    assert classify_severity("Excessive HTTP Requests", count=61) == "HIGH"
    assert classify_severity("Excessive HTTP Requests", count=121) == "CRITICAL"
    assert classify_severity("Unknown Rule", count=999) == "LOW"


def test_correlation_groups_by_source_user_event_type_and_time_window():
    alerts = [
        {
            "timestamp": "2026-10-03 08:00:00",
            "rule_name": "Brute Force Login",
            "event_type": "authentication",
            "source_ip": "203.0.113.10",
            "username": "alice",
            "severity": "HIGH",
            "description": "first",
        },
        {
            "timestamp": "2026-10-03 08:20:00",
            "rule_name": "Suspicious Login",
            "event_type": "authentication",
            "source_ip": "203.0.113.10",
            "username": "alice",
            "severity": "HIGH",
            "description": "second",
        },
        {
            "timestamp": "2026-10-03 10:30:00",
            "rule_name": "Suspicious Login",
            "event_type": "authentication",
            "source_ip": "203.0.113.10",
            "username": "alice",
            "severity": "HIGH",
            "description": "third",
        },
    ]

    correlated = correlate_alerts(alerts, time_window_minutes=30)

    assert correlated[0]["severity"] == "CRITICAL"
    assert correlated[1]["severity"] == "CRITICAL"
    assert correlated[0]["correlated"] == 1
    assert correlated[1]["correlated"] == 1
    assert correlated[2].get("correlated", 0) == 0
