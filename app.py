from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from database.database import SOCDatabase
from detection.detection_engine import run_detection
from ingestion.log_parser import parse_log_directory


st.set_page_config(page_title="SOC Threat Detection Platform", layout="wide")
st.title("SOC Threat Detection and Monitoring Platform")

BASE_DIR = Path(__file__).parent
SAMPLE_LOGS_DIR = BASE_DIR / "data" / "sample_logs"
DB_PATH = BASE_DIR / "soc_monitoring.db"


def load_data(db: SOCDatabase) -> pd.DataFrame:
    alerts = db.fetch_alerts()
    if alerts.empty:
        return alerts
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
    return alerts


def apply_filters(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return alerts

    st.sidebar.header("Filters")
    severities = sorted(alerts["severity"].dropna().unique().tolist())
    selected_severity = st.sidebar.multiselect(
        "Severity", options=severities, default=severities
    )

    rules = sorted(alerts["rule_name"].dropna().unique().tolist())
    selected_rules = st.sidebar.multiselect(
        "Detection Type", options=rules, default=rules
    )

    source_ips = sorted([ip for ip in alerts["source_ip"].dropna().unique().tolist() if ip])
    selected_source_ip = st.sidebar.selectbox(
        "Source IP",
        options=["All"] + source_ips,
        index=0,
    )

    min_date = alerts["timestamp"].min().date()
    max_date = alerts["timestamp"].max().date()
    selected_dates = st.sidebar.date_input(
        "Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )

    filtered = alerts[
        alerts["severity"].isin(selected_severity)
        & alerts["rule_name"].isin(selected_rules)
    ]

    if selected_source_ip != "All":
        filtered = filtered[filtered["source_ip"] == selected_source_ip]

    if isinstance(selected_dates, tuple) and len(selected_dates) == 2:
        start_date, end_date = selected_dates
        filtered = filtered[
            (filtered["timestamp"].dt.date >= start_date)
            & (filtered["timestamp"].dt.date <= end_date)
        ]

    return filtered


def ingest_sample_logs(db: SOCDatabase) -> tuple[int, int]:
    events = parse_log_directory(SAMPLE_LOGS_DIR)
    db.insert_events(events)

    alerts = run_detection(events)
    db.insert_alerts(alerts)
    return len(events), len(alerts)


db = SOCDatabase(str(DB_PATH))
db.initialize()

if st.sidebar.button("Ingest Sample Logs"):
    event_count, alert_count = ingest_sample_logs(db)
    st.sidebar.success(f"Ingested {event_count} events and created {alert_count} alerts")

alerts_df = load_data(db)
filtered_alerts = apply_filters(alerts_df) if not alerts_df.empty else alerts_df

col1, col2, col3, col4 = st.columns(4)
total_events = db.fetch_events_count()
total_alerts = len(alerts_df)
high_critical = (
    len(alerts_df[alerts_df["severity"].isin(["HIGH", "CRITICAL"])])
    if not alerts_df.empty
    else 0
)
open_incidents = (
    len(alerts_df[alerts_df["status"].isin(["Open", "Investigating"])])
    if not alerts_df.empty
    else 0
)

col1.metric("Total Events", total_events)
col2.metric("Total Alerts", total_alerts)
col3.metric("High/Critical Alerts", high_critical)
col4.metric("Open Incidents", open_incidents)

st.subheader("Visualizations")
if filtered_alerts.empty:
    st.info("No alerts available yet. Click 'Ingest Sample Logs' to load demo data.")
else:
    viz_col1, viz_col2 = st.columns(2)

    severity_counts = filtered_alerts.groupby("severity", as_index=False).size()
    fig_severity = px.bar(
        severity_counts,
        x="severity",
        y="size",
        title="Alerts by Severity",
        labels={"size": "Count"},
    )
    viz_col1.plotly_chart(fig_severity, use_container_width=True)

    timeline = (
        filtered_alerts.set_index("timestamp")
        .resample("H")
        .size()
        .reset_index(name="count")
    )
    fig_time = px.line(timeline, x="timestamp", y="count", title="Alerts Over Time")
    viz_col2.plotly_chart(fig_time, use_container_width=True)

    viz_col3, viz_col4 = st.columns(2)
    top_sources = (
        filtered_alerts.groupby("source_ip", as_index=False)
        .size()
        .sort_values("size", ascending=False)
        .head(10)
    )
    fig_sources = px.bar(
        top_sources,
        x="source_ip",
        y="size",
        title="Top Source IPs",
        labels={"size": "Alert Count"},
    )
    viz_col3.plotly_chart(fig_sources, use_container_width=True)

    rule_distribution = filtered_alerts.groupby("rule_name", as_index=False).size()
    fig_rules = px.pie(
        rule_distribution,
        names="rule_name",
        values="size",
        title="Detection Type Distribution",
    )
    viz_col4.plotly_chart(fig_rules, use_container_width=True)

st.subheader("Recent Alerts")
if filtered_alerts.empty:
    st.write("No alerts to display.")
else:
    display_columns = [
        "alert_id",
        "timestamp",
        "rule_name",
        "severity",
        "source_ip",
        "username",
        "mitre_technique",
        "status",
    ]
    st.dataframe(filtered_alerts[display_columns].head(50), use_container_width=True)

st.subheader("Suspicious IPs")
if filtered_alerts.empty:
    st.write("No suspicious IPs yet.")
else:
    suspicious_ips = (
        filtered_alerts.groupby("source_ip", as_index=False)
        .agg(alert_count=("alert_id", "count"))
        .sort_values("alert_count", ascending=False)
        .head(10)
    )
    st.dataframe(suspicious_ips, use_container_width=True)

st.subheader("Incident Management")
if alerts_df.empty:
    st.write("No incidents available.")
else:
    selected_alert_id = st.selectbox("Select Alert ID", alerts_df["alert_id"].tolist())
    selected_status = st.selectbox(
        "Update Status", ["Open", "Investigating", "Resolved", "False Positive"]
    )

    if st.button("Update Incident Status"):
        db.update_alert_status(selected_alert_id, selected_status)
        st.success(f"Alert {selected_alert_id} updated to {selected_status}")
