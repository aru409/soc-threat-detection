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

SEVERITY_COLORS = {
    "CRITICAL": "#FF4D4D",
    "HIGH": "#FF9F43",
    "MEDIUM": "#FFD166",
    "LOW": "#6C8DFF",
}

STATUS_COLORS = {
    "Open": "#FF4D4D",
    "Investigating": "#FF9F43",
    "Resolved": "#52C41A",
    "False Positive": "#7F8C8D",
}

st.set_page_config(page_title="SOC/SIEM Threat Monitoring", layout="wide")


def apply_soc_theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: #050505;
            color: #EAEAEA;
        }
        [data-testid="stSidebar"] {
            background: #0D0D0D;
            border-right: 1px solid #232323;
        }
        [data-testid="stSidebar"] * {
            color: #EAEAEA;
        }
        [data-testid="stMetric"] {
            background: #111111;
            border: 1px solid #262626;
            border-radius: 10px;
            padding: 10px;
        }
        .soc-card {
            background: #111111;
            border: 1px solid #262626;
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 10px;
        }
        .soc-header {
            background: linear-gradient(90deg, #101820 0%, #0A0A0A 100%);
            border: 1px solid #262626;
            border-radius: 12px;
            padding: 12px 16px;
            margin-bottom: 12px;
        }
        .soc-title {
            margin: 0;
            font-size: 1.35rem;
            font-weight: 700;
            letter-spacing: 0.03em;
            color: #F4F4F4;
        }
        .soc-subtitle {
            margin-top: 4px;
            font-size: 0.85rem;
            color: #B9BDC7;
        }
        .stDataFrame, .stTable {
            border: 1px solid #262626;
            border-radius: 8px;
            background-color: #0D0D0D;
        }
        .stSelectbox > div > div,
        .stMultiSelect > div > div,
        .stDateInput > div > div,
        .stTextInput > div > div {
            background-color: #141414;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def apply_dark_table_style(df: pd.DataFrame, include_severity: bool = False) -> pd.io.formats.style.Styler:
    table_style = (
        df.style.set_properties(
            **{
                "background-color": "#0D0D0D",
                "color": "#EAEAEA",
                "border-color": "#262626",
                "font-size": "0.86rem",
            }
        )
        .set_table_styles(
            [
                {
                    "selector": "th",
                    "props": [
                        ("background-color", "#161616"),
                        ("color", "#EAEAEA"),
                        ("border", "1px solid #262626"),
                    ],
                },
                {
                    "selector": "td",
                    "props": [("border", "1px solid #262626")],
                },
            ]
        )
    )

    if include_severity and "severity" in df.columns:
        table_style = table_style.map(
            lambda v: f"color: {SEVERITY_COLORS.get(v, '#EAEAEA')}; font-weight: 700;"
            if v in SEVERITY_COLORS
            else "",
            subset=["severity"],
        )

    if "status" in df.columns:
        table_style = table_style.map(
            lambda v: f"color: {STATUS_COLORS.get(v, '#EAEAEA')}; font-weight: 700;"
            if v in STATUS_COLORS
            else "",
            subset=["status"],
        )

    return table_style


def style_figure(fig):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#EAEAEA"),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=20, r=20, t=45, b=25),
    )
    fig.update_xaxes(showgrid=True, gridcolor="#2A2A2A", zeroline=False)
    fig.update_yaxes(showgrid=True, gridcolor="#2A2A2A", zeroline=False)
    return fig


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

    st.sidebar.markdown("### SIEM Filters")

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

    primary = st.columns(4)
    primary[0].metric("Total Events", kpis["total_events"])
    primary[1].metric("Total Alerts", kpis["total_alerts"])
    primary[2].metric("High/Critical Alerts", kpis["high_critical_alerts"])
    primary[3].metric("Open Incidents", kpis["open_incidents"])

    with st.expander("Additional SIEM Metrics", expanded=True):
        secondary = st.columns(4)
        secondary[0].metric("Critical Alerts", kpis["critical_alerts"])
        secondary[1].metric("Resolved Incidents", kpis["resolved_incidents"])
        secondary[2].metric("False Positives", kpis["false_positives"])
        secondary[3].metric("Unique Source IPs", kpis["unique_source_ips"])


def render_charts(alerts_df: pd.DataFrame, events_df: pd.DataFrame, incidents_df: pd.DataFrame) -> None:
    st.subheader("SIEM Analytics")
    if alerts_df.empty:
        st.info("No alerts available yet. Click 'Ingest Sample Logs' to load demo data.")
        return

    chart_theme = "plotly_dark"

    row1 = st.columns(3)
    severity_counts = count_by_column(alerts_df, "severity")
    severity_counts["severity"] = pd.Categorical(
        severity_counts["severity"], categories=["CRITICAL", "HIGH", "MEDIUM", "LOW"], ordered=True
    )
    severity_counts = severity_counts.sort_values("severity")
    fig_severity = px.bar(
        severity_counts,
        x="severity",
        y="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Alerts by Severity",
        template=chart_theme,
    )
    row1[0].plotly_chart(style_figure(fig_severity), use_container_width=True)

    timeline = build_alerts_timeline(alerts_df)
    fig_timeline = px.line(
        timeline,
        x="timestamp",
        y="count",
        title="Alerts Over Time",
        template=chart_theme,
    )
    fig_timeline.update_traces(line_color="#00B2FF")
    row1[1].plotly_chart(style_figure(fig_timeline), use_container_width=True)

    by_rule = count_by_column(alerts_df, "rule_name")
    fig_rules = px.bar(
        by_rule,
        x="rule_name",
        y="count",
        title="Alerts by Detection Rule",
        template=chart_theme,
        color_discrete_sequence=["#22D3EE"],
    )
    row1[2].plotly_chart(style_figure(fig_rules), use_container_width=True)

    row2 = st.columns(3)
    by_mitre = count_by_column(alerts_df, "mitre_technique")
    by_mitre = by_mitre[by_mitre["mitre_technique"] != ""]
    fig_mitre = px.pie(
        by_mitre,
        names="mitre_technique",
        values="count",
        title="Alerts by MITRE ATT&CK Technique",
        template=chart_theme,
        color_discrete_sequence=["#00B2FF", "#5E8CFF", "#7AA2F7", "#22D3EE", "#9B8AFB"],
    )
    row2[0].plotly_chart(style_figure(fig_mitre), use_container_width=True)

    top_ips = count_by_column(alerts_df, "source_ip").head(10)
    fig_ips = px.bar(
        top_ips,
        x="source_ip",
        y="count",
        title="Top Source IPs",
        template=chart_theme,
        color_discrete_sequence=["#00B2FF"],
    )
    row2[1].plotly_chart(style_figure(fig_ips), use_container_width=True)

    events_by_source = count_by_column(events_df, "source")
    fig_events_source = px.bar(
        events_by_source,
        x="source",
        y="count",
        title="Events by Source",
        template=chart_theme,
        color_discrete_sequence=["#8B5CF6"],
    )
    row2[2].plotly_chart(style_figure(fig_events_source), use_container_width=True)

    row3 = st.columns(3)
    incident_dist = count_by_column(incidents_df, "status")
    fig_incidents = px.pie(
        incident_dist,
        names="status",
        values="count",
        title="Incident Status Distribution",
        template=chart_theme,
        color="status",
        color_discrete_map=STATUS_COLORS,
    )
    row3[0].plotly_chart(style_figure(fig_incidents), use_container_width=True)


def render_recent_alerts(filtered_alerts: pd.DataFrame) -> None:
    st.subheader("Recent Alerts")
    if filtered_alerts.empty:
        st.write("No alerts to display.")
        return

    display_columns = [
        "severity",
        "rule_name",
        "source_ip",
        "username",
        "mitre_technique",
        "timestamp",
        "status",
    ]
    table_df = filtered_alerts[display_columns].head(50).rename(
        columns={
            "severity": "Severity",
            "rule_name": "Detection Rule",
            "source_ip": "Source IP",
            "username": "Username",
            "mitre_technique": "MITRE Technique",
            "timestamp": "Timestamp",
            "status": "Status",
        }
    )
    styled = apply_dark_table_style(table_df.rename(columns={"Severity": "severity", "Status": "status"}), include_severity=True)
    # Re-apply display labels for user view
    styled = styled.format(na_rep="N/A")
    st.dataframe(styled, use_container_width=True)


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
    suspicious_ips = suspicious_ips.rename(
        columns={
            "source_ip": "Source IP",
            "alert_count": "Alert Count",
            "max_severity": "Max Severity",
            "latest_alert": "Latest Alert",
        }
    )
    st.dataframe(apply_dark_table_style(suspicious_ips), use_container_width=True)


def render_alert_investigation(alerts_df: pd.DataFrame) -> None:
    st.subheader("Alert Investigation")
    if alerts_df.empty:
        st.write("No alerts available for investigation.")
        return

    selected_alert_id = st.selectbox("Select Alert for Investigation", alerts_df["alert_id"].tolist())
    selected = alerts_df[alerts_df["alert_id"] == selected_alert_id].iloc[0]

    info_col, evidence_col = st.columns([1.2, 1])

    with info_col:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown("**Alert Information**")
        st.markdown(f"**Alert ID:** {selected.get('alert_id', '')}")
        st.markdown(f"**Timestamp:** {selected.get('timestamp', '')}")
        st.markdown(f"**Detection Rule:** {selected.get('rule_name', '')}")
        st.markdown(f"**Event Type:** {selected.get('event_type', '')}")
        st.markdown(f"**Source IP:** {selected.get('source_ip', '') or 'N/A'}")
        st.markdown(f"**Destination IP:** {selected.get('destination_ip', '') or 'N/A'}")
        st.markdown(f"**Username:** {selected.get('username', '') or 'N/A'}")
        st.markdown(f"**Severity:** {selected.get('severity', '')}")
        st.markdown(f"**Confidence:** {selected.get('confidence', '')}")
        st.markdown(f"**Source/Dataset:** {selected.get('source', '')} ({selected.get('source_type', '')})")
        st.markdown("</div>", unsafe_allow_html=True)

    with evidence_col:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown("**Detection Evidence**")
        evidence = selected.get("evidence", "")
        if evidence:
            st.code(str(evidence))
        else:
            st.write("No direct evidence string available for this alert.")
        st.markdown("**MITRE Information**")
        st.markdown(f"Technique: {selected.get('mitre_technique', '') or 'N/A'}")
        st.markdown(f"Description: {selected.get('description', '') or 'N/A'}")
        st.markdown("**Incident Status**")
        st.markdown(f"Current Status: {selected.get('status', '')}")
        st.markdown("</div>", unsafe_allow_html=True)


def render_incident_management(db: SOCDatabase, alerts_df: pd.DataFrame) -> None:
    st.subheader("Incident Management")
    if alerts_df.empty:
        st.write("No incidents available.")
        return

    select_col, action_col = st.columns([1.4, 1])
    with select_col:
        selected_alert_id = st.selectbox("Select Alert ID to Update", alerts_df["alert_id"].tolist())
    with action_col:
        current_status = alerts_df.loc[alerts_df["alert_id"] == selected_alert_id, "status"].iloc[0]
        st.markdown(f"**Current Status:** {current_status}")

    selected_status = st.selectbox(
        "Update Status",
        ["Open", "Investigating", "Resolved", "False Positive"],
    )

    if st.button("Update Incident Status"):
        db.update_alert_status(selected_alert_id, selected_status)
        st.success(f"Alert {selected_alert_id} updated to {selected_status}")


apply_soc_theme()
st.markdown(
    """
    <div class="soc-header">
      <p class="soc-title">SOC THREAT DETECTION &amp; MONITORING</p>
      <p class="soc-subtitle">Security Operations Center | Threat Detection | SIEM Analytics</p>
    </div>
    """,
    unsafe_allow_html=True,
)

db = SOCDatabase(str(DB_PATH))
db.initialize()

st.sidebar.markdown("### Data Ingestion")
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
