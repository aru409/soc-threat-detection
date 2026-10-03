from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.analytics import (
    build_alerts_timeline,
    compute_siem_kpis,
    count_by_column,
    prepare_alerts_dataframe,
    prepare_events_dataframe,
)
from database.database import SOCDatabase
from detection.detection_engine import run_detection
from ingestion.log_parser import parse_log_directory


BASE_DIR = Path(__file__).parent
SAMPLE_LOGS_DIR = BASE_DIR / "data" / "sample_logs"
DB_PATH = BASE_DIR / "soc_monitoring.db"


st.set_page_config(page_title="SOC/SIEM Threat Monitoring", layout="wide")


def apply_soc_theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {background-color: #050505; color: #EAEAEA;}
        div[data-testid="stMetric"] {
            background: #111111;
            border: 1px solid #262626;
            border-radius: 10px;
            padding: 8px;
        }
        .soc-panel {
            background: #111111;
            border: 1px solid #262626;
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 10px;
        }
        .stDataFrame, .stTable {background-color: #0D0D0D;}
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_data(db: SOCDatabase) -> tuple[pd.DataFrame, pd.DataFrame]:
    alerts = prepare_alerts_dataframe(db.fetch_alerts())
    events = prepare_events_dataframe(db.fetch_events())
    return alerts, events


def ingest_sample_logs(db: SOCDatabase) -> tuple[int, int, int, int]:
    events = parse_log_directory(SAMPLE_LOGS_DIR, source_type="sample")
    ingested_events = db.insert_events(events)

    alerts = run_detection(events)
    ingested_alerts = db.insert_alerts(alerts)

    return len(events), ingested_events, len(alerts), ingested_alerts


def apply_filters(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return alerts

    st.sidebar.header("SIEM Filters")

    severities = sorted(alerts["severity"].dropna().unique().tolist())
    selected_severity = st.sidebar.multiselect("Severity", options=severities, default=severities)

    rules = sorted(alerts["rule_name"].dropna().unique().tolist())
    selected_rules = st.sidebar.multiselect("Detection Type", options=rules, default=rules)

    source_ips = sorted([ip for ip in alerts["source_ip"].dropna().unique().tolist() if ip])
    selected_source_ip = st.sidebar.selectbox("Source IP", options=["All"] + source_ips, index=0)

    min_date = alerts["timestamp"].min().date()
    max_date = alerts["timestamp"].max().date()
    selected_dates = st.sidebar.date_input(
        "Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )

    filtered = alerts[
        alerts["severity"].isin(selected_severity) & alerts["rule_name"].isin(selected_rules)
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


def render_kpis(kpis: dict[str, int]) -> None:
    st.subheader("SIEM Overview")
    row1 = st.columns(4)
    row2 = st.columns(4)

    row1[0].metric("Total Events", kpis["total_events"])
    row1[1].metric("Total Alerts", kpis["total_alerts"])
    row1[2].metric("Critical Alerts", kpis["critical_alerts"])
    row1[3].metric("High/Critical Alerts", kpis["high_critical_alerts"])

    row2[0].metric("Open Incidents", kpis["open_incidents"])
    row2[1].metric("Resolved Incidents", kpis["resolved_incidents"])
    row2[2].metric("False Positives", kpis["false_positives"])
    row2[3].metric("Unique Source IPs", kpis["unique_source_ips"])


def render_charts(alerts_df: pd.DataFrame, events_df: pd.DataFrame, incidents_df: pd.DataFrame) -> None:
    st.subheader("SIEM Analytics")
    if alerts_df.empty:
        st.info("No alerts available yet. Click 'Ingest Sample Logs' to load demo data.")
        return

    chart_theme = "plotly_dark"

    row1 = st.columns(3)
    severity_counts = count_by_column(alerts_df, "severity")
    fig_severity = px.bar(severity_counts, x="severity", y="count", title="Alerts by Severity", template=chart_theme)
    row1[0].plotly_chart(fig_severity, use_container_width=True)

    timeline = build_alerts_timeline(alerts_df)
    fig_timeline = px.line(timeline, x="timestamp", y="count", title="Alerts Over Time", template=chart_theme)
    row1[1].plotly_chart(fig_timeline, use_container_width=True)

    by_rule = count_by_column(alerts_df, "rule_name")
    fig_rules = px.bar(by_rule, x="rule_name", y="count", title="Alerts by Detection Rule", template=chart_theme)
    row1[2].plotly_chart(fig_rules, use_container_width=True)

    row2 = st.columns(3)
    by_mitre = count_by_column(alerts_df, "mitre_technique")
    by_mitre = by_mitre[by_mitre["mitre_technique"] != ""]
    fig_mitre = px.pie(by_mitre, names="mitre_technique", values="count", title="Alerts by MITRE ATT&CK Technique", template=chart_theme)
    row2[0].plotly_chart(fig_mitre, use_container_width=True)

    top_ips = count_by_column(alerts_df, "source_ip").head(10)
    fig_ips = px.bar(top_ips, x="source_ip", y="count", title="Top Source IPs", template=chart_theme)
    row2[1].plotly_chart(fig_ips, use_container_width=True)

    events_by_source = count_by_column(events_df, "source")
    fig_events_source = px.bar(events_by_source, x="source", y="count", title="Events by Source", template=chart_theme)
    row2[2].plotly_chart(fig_events_source, use_container_width=True)

    row3 = st.columns(3)
    incident_dist = count_by_column(incidents_df, "status")
    fig_incidents = px.pie(incident_dist, names="status", values="count", title="Incident Status Distribution", template=chart_theme)
    row3[0].plotly_chart(fig_incidents, use_container_width=True)


def render_recent_alerts(filtered_alerts: pd.DataFrame) -> None:
    st.subheader("Recent Alerts")
    if filtered_alerts.empty:
        st.write("No alerts to display.")
        return

    display_columns = [
        "alert_id",
        "timestamp",
        "rule_name",
        "severity",
        "source_ip",
        "username",
        "mitre_technique",
        "source_type",
        "status",
    ]
    st.dataframe(filtered_alerts[display_columns].head(50), use_container_width=True)


def render_suspicious_ips(filtered_alerts: pd.DataFrame) -> None:
    st.subheader("Suspicious IPs")
    if filtered_alerts.empty:
        st.write("No suspicious IPs yet.")
        return

    suspicious_ips = (
        filtered_alerts.groupby("source_ip", as_index=False)
        .agg(
            alert_count=("alert_id", "count"),
            max_severity=("severity", "max"),
            latest_alert=("timestamp", "max"),
        )
        .sort_values("alert_count", ascending=False)
        .head(10)
    )
    st.dataframe(suspicious_ips, use_container_width=True)


def render_alert_investigation(alerts_df: pd.DataFrame) -> None:
    st.subheader("Alert Investigation")
    if alerts_df.empty:
        st.write("No alerts available for investigation.")
        return

    selected_alert_id = st.selectbox("Select Alert for Investigation", alerts_df["alert_id"].tolist())
    selected = alerts_df[alerts_df["alert_id"] == selected_alert_id].iloc[0]

    details = {
        "Alert ID": selected.get("alert_id", ""),
        "Timestamp": str(selected.get("timestamp", "")),
        "Detection Rule": selected.get("rule_name", ""),
        "Event Type": selected.get("event_type", ""),
        "Source IP": selected.get("source_ip", ""),
        "Destination IP": selected.get("destination_ip", ""),
        "Username": selected.get("username", ""),
        "Severity": selected.get("severity", ""),
        "Confidence": selected.get("confidence", ""),
        "Description": selected.get("description", ""),
        "MITRE ATT&CK Technique": selected.get("mitre_technique", ""),
        "Current Status": selected.get("status", ""),
        "Source/Dataset": f"{selected.get('source', '')} ({selected.get('source_type', '')})",
        "Event Count": selected.get("event_count", 1),
    }

    for label, value in details.items():
        st.markdown(f"**{label}:** {value if value != '' else 'N/A'}")

    evidence = selected.get("evidence", "")
    st.markdown("**Evidence / Event Information:**")
    if evidence:
        st.code(str(evidence))
    else:
        st.write("No direct evidence string available for this alert.")


def render_incident_management(db: SOCDatabase, alerts_df: pd.DataFrame) -> None:
    st.subheader("Incident Management")
    if alerts_df.empty:
        st.write("No incidents available.")
        return

    selected_alert_id = st.selectbox("Select Alert ID to Update", alerts_df["alert_id"].tolist())
    current_status = alerts_df.loc[alerts_df["alert_id"] == selected_alert_id, "status"].iloc[0]
    st.write(f"Current Status: **{current_status}**")

    selected_status = st.selectbox(
        "Update Status",
        ["Open", "Investigating", "Resolved", "False Positive"],
    )

    if st.button("Update Incident Status"):
        db.update_alert_status(selected_alert_id, selected_status)
        st.success(f"Alert {selected_alert_id} updated to {selected_status}")


apply_soc_theme()
st.title("SOC/SIEM Threat Detection and Monitoring Prototype")
st.caption("A local SOC/SIEM threat detection and monitoring prototype for learning and portfolio use.")

db = SOCDatabase(str(DB_PATH))
db.initialize()

if st.sidebar.button("Ingest Sample Logs"):
    total_events, ingested_events, total_alerts, ingested_alerts = ingest_sample_logs(db)
    st.sidebar.success(
        "Ingestion complete. "
        f"Events processed: {total_events}, new events inserted: {ingested_events}. "
        f"Alerts generated: {total_alerts}, new alerts inserted: {ingested_alerts}."
    )

alerts_df, events_df = load_data(db)
incidents_df = db.fetch_incidents()
filtered_alerts = apply_filters(alerts_df) if not alerts_df.empty else alerts_df

kpis = compute_siem_kpis(alerts_df, events_df)
render_kpis(kpis)
render_charts(filtered_alerts, events_df, incidents_df)
render_recent_alerts(filtered_alerts)
render_suspicious_ips(filtered_alerts)
render_alert_investigation(filtered_alerts if not filtered_alerts.empty else alerts_df)
render_incident_management(db, alerts_df)
