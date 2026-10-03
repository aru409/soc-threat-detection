import pandas as pd

from detection.rules import (
    classify_severity,
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
            }
            for i in range(5)
        ]
    )

    alerts = detect_brute_force_logins(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Brute Force Login"


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
            }
            for i in range(11)
        ]
    )

    alerts = detect_port_scan(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Port Scanning Indicators"


def test_severity_classification_is_explainable():
    assert classify_severity("Brute Force Login") == "HIGH"
    assert classify_severity("Excessive HTTP Requests") == "MEDIUM"
    assert classify_severity("Unknown Rule") == "LOW"
