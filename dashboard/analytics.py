from __future__ import annotations

import pandas as pd


def prepare_alerts_dataframe(alerts_df: pd.DataFrame) -> pd.DataFrame:
    if alerts_df.empty:
        return alerts_df
    result = alerts_df.copy()
    result["timestamp"] = pd.to_datetime(result["timestamp"], errors="coerce")
    return result


def prepare_events_dataframe(events_df: pd.DataFrame) -> pd.DataFrame:
    if events_df.empty:
        return events_df
    result = events_df.copy()
    result["timestamp"] = pd.to_datetime(result["timestamp"], errors="coerce")
    return result


def compute_siem_kpis(alerts_df: pd.DataFrame, events_df: pd.DataFrame) -> dict[str, int]:
    total_events = len(events_df)
    total_alerts = len(alerts_df)

    if alerts_df.empty:
        return {
            "total_events": total_events,
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_critical_alerts": 0,
            "open_incidents": 0,
            "resolved_incidents": 0,
            "false_positives": 0,
            "unique_source_ips": 0,
        }

    critical_alerts = len(alerts_df[alerts_df["severity"] == "CRITICAL"])
    high_critical_alerts = len(alerts_df[alerts_df["severity"].isin(["HIGH", "CRITICAL"])])
    open_incidents = len(alerts_df[alerts_df["status"].isin(["Open", "Investigating"])])
    resolved_incidents = len(alerts_df[alerts_df["status"] == "Resolved"])
    false_positives = len(alerts_df[alerts_df["status"] == "False Positive"])

    unique_ips_from_events = events_df["source_ip"].replace("", pd.NA).dropna().nunique() if not events_df.empty else 0
    unique_ips_from_alerts = alerts_df["source_ip"].replace("", pd.NA).dropna().nunique()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_critical_alerts": high_critical_alerts,
        "open_incidents": open_incidents,
        "resolved_incidents": resolved_incidents,
        "false_positives": false_positives,
        "unique_source_ips": int(max(unique_ips_from_events, unique_ips_from_alerts)),
    }


def count_by_column(df: pd.DataFrame, column: str, label: str = "count") -> pd.DataFrame:
    if df.empty or column not in df.columns:
        return pd.DataFrame(columns=[column, label])
    return (
        df.groupby(column, as_index=False)
        .size()
        .rename(columns={"size": label})
        .sort_values(label, ascending=False)
    )


def build_alerts_timeline(alerts_df: pd.DataFrame) -> pd.DataFrame:
    if alerts_df.empty:
        return pd.DataFrame(columns=["timestamp", "count"])

    timeline = (
        alerts_df.dropna(subset=["timestamp"])
        .set_index("timestamp")
        .resample("h")
        .size()
        .reset_index(name="count")
    )
    return timeline
