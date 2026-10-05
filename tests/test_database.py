import pandas as pd

from database.database import SOCDatabase
from detection.detection_engine import run_detection


def _sample_events_df() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "timestamp": f"2026-10-03 08:0{i}:00",
                "source_ip": "203.0.113.10",
                "destination_ip": "10.0.0.10",
                "username": "alice",
                "event_type": "authentication",
                "action": "login",
                "status": "failed",
                "message": "Invalid password attempt",
                "source": "vpn_gateway",
                "source_type": "sample",
            }
            for i in range(5)
        ]
    )


def test_duplicate_event_ingestion_is_prevented(tmp_path):
    db = SOCDatabase(str(tmp_path / "soc.db"))
    db.initialize()
    events = _sample_events_df()

    first_inserted = db.insert_events(events)
    second_inserted = db.insert_events(events)

    assert first_inserted == 5
    assert second_inserted == 0
    assert db.fetch_events_count() == 5


def test_duplicate_alert_ingestion_is_prevented(tmp_path):
    db = SOCDatabase(str(tmp_path / "soc.db"))
    db.initialize()
    events = _sample_events_df()
    alerts = run_detection(events)

    first_inserted = db.insert_alerts(alerts)
    second_inserted = db.insert_alerts(alerts)

    assert first_inserted == len(alerts)
    assert second_inserted == 0
    assert len(db.fetch_alerts()) == len(alerts)


def test_incident_status_update_keeps_alert_and_incident_consistent(tmp_path):
    db = SOCDatabase(str(tmp_path / "soc.db"))
    db.initialize()
    events = _sample_events_df()
    alerts = run_detection(events)
    db.insert_alerts(alerts)

    alert_id = alerts[0]["alert_id"]
    db.update_alert_status(alert_id, "Resolved")

    alerts_df = db.fetch_alerts()
    incidents_df = db.fetch_incidents()

    alert_row = alerts_df[alerts_df["alert_id"] == alert_id].iloc[0]
    incident_row = incidents_df[incidents_df["alert_id"] == alert_id].iloc[0]

    assert alert_row["status"] == "Resolved"
    assert incident_row["status"] == "Resolved"
