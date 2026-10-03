import pandas as pd

from ingestion.log_parser import parse_log_file


def test_parse_log_file_normalizes_required_fields(tmp_path):
    csv_path = tmp_path / "auth.csv"
    pd.DataFrame(
        [
            {
                "time": "2026-10-03 09:00:00",
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "user": "alice",
                "event": "authentication",
                "action": "login",
                "result": "failed",
                "request": "invalid password",
                "log_source": "vpn",
            }
        ]
    ).to_csv(csv_path, index=False)

    parsed = parse_log_file(csv_path)

    expected_columns = {
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
    }
    assert expected_columns.issubset(set(parsed.columns))
    assert parsed.iloc[0]["source_ip"] == "10.0.0.1"
    assert parsed.iloc[0]["status"] == "failed"
    assert parsed.iloc[0]["source_type"] == "sample"
