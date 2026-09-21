"""
Security Event Timeline & Heatmap Component
Provides visual timeline of events, heatmap by hour/day, and source breakdown.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import sqlite3
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

BACKEND = BACKEND
VERIFY_SSL = False
DB_PATH = str(Path(__file__).parent.parent.parent / "data" / "siem.db")

SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#f78166",
    "MEDIUM":   "#e3b341",
    "LOW":      "#56d364",
    "INFO":     "#79c0ff",
}


def _load_events(hours: int = 24) -> pd.DataFrame:
    """Load events from the backend API."""
    import requests
    try:
        r = requests.get(f"{BACKEND}/threats", verify=VERIFY_SSL, timeout=15)
        if r.status_code != 200:
            st.error(f"Backend error: {r.status_code}")
            return pd.DataFrame()
        data = r.json()
    except Exception as e:
        st.error(f"Error loading events: {e}")
        return pd.DataFrame()

    if not data:
        return pd.DataFrame()

    df = pd.DataFrame(data)
    if df.empty:
        return df

    # Normalise timestamp field
    ts_col = "timestamp" if "timestamp" in df.columns else None
    if ts_col is None:
        return df

    df["_ts"] = pd.to_datetime(df[ts_col], errors="coerce", utc=False)
    cutoff = pd.Timestamp.now() - pd.Timedelta(hours=hours)
    df = df[df["_ts"] >= cutoff].copy()

    if df.empty:
        # If no events in window (old dummy data), use all data
        df = pd.DataFrame(data)
        df["_ts"] = pd.to_datetime(df[ts_col], errors="coerce", utc=False)

    df["created_at"] = df["_ts"]
    df["timestamp"]  = df["_ts"]
    df["hour"]       = df["_ts"].dt.hour
    df["day_name"]   = df["_ts"].dt.day_name()
    df["day_num"]    = df["_ts"].dt.dayofweek
    df["severity"]   = df["severity"].fillna("INFO").str.upper()
    if "agent_id" not in df.columns:
        df["agent_id"] = "unknown"
    return df


def _load_correlations(hours: int = 24) -> pd.DataFrame:
    """Load correlation incidents."""
    backend = BACKEND
    try:
        import requests as _requests
        r = _requests.get(
            f"{backend}/correlations",
            params={"hours": hours},
            verify=VERIFY_SSL,
            timeout=12,
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict):
                df = pd.DataFrame(data.get("correlations", []))
            else:
                df = pd.DataFrame()
            if not df.empty and "fired_at" in df.columns:
                df["fired_at"] = pd.to_datetime(df["fired_at"], errors="coerce")
            if not df.empty and "acknowledged" not in df.columns:
                df["acknowledged"] = 0
            return df
    except Exception:
        pass

    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            """
            SELECT id, rule_name, mitre_id, mitre_tactic, severity,
                   source, matched_count, fired_at, acknowledged
            FROM correlations
            WHERE fired_at >= datetime('now', ? || ' hours')
            ORDER BY fired_at DESC
            """,
            conn,
            params=(f"-{hours}",),
        )
        conn.close()
        df["fired_at"] = pd.to_datetime(df["fired_at"], errors="coerce")
        return df
    except Exception:
        return pd.DataFrame()


def render_timeline(hours: int = 24):
    """Render the full timeline dashboard."""
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Security Event Timeline
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Scatter timeline, hour-of-day heatmap, and MITRE ATT&CK correlation view.
      </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        hours = st.selectbox("Time window", [6, 12, 24, 48, 72, 168], index=2,
                             format_func=lambda h: f"Last {h}h")
    with col2:
        severity_filter = st.multiselect(
            "Severity filter",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            default=["CRITICAL", "HIGH", "MEDIUM"],
        )
    with col3:
        st.markdown("")
        auto = st.checkbox("Auto-refresh (30s)", value=False)

    if auto:
        import time
        time.sleep(30)
        st.rerun()

    df = _load_events(hours)

    if df.empty:
        st.info("No events found in the selected time window.")
        return

    # Apply severity filter
    if severity_filter:
        df = df[df["severity"].isin(severity_filter)]

    if df.empty:
        st.warning("No events match the selected severity filter.")
        return

    # ------------------------------------------------------------------ #
    #  Metrics row                                                         #
    # ------------------------------------------------------------------ #
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Events", len(df))
    m2.metric("Critical", len(df[df["severity"] == "CRITICAL"]))
    m3.metric("High",     len(df[df["severity"] == "HIGH"]))
    m4.metric("Unique Sources", df["source"].nunique())
    m5.metric("Unique Agents", df["agent_id"].nunique() if "agent_id" in df.columns else 0)

    st.divider()

    # ------------------------------------------------------------------ #
    #  Timeline scatter plot                                               #
    # ------------------------------------------------------------------ #
    st.subheader("Event Timeline")
    fig_timeline = px.scatter(
        df,
        x="created_at",
        y="source",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        size_max=12,
        hover_data={"message": True, "created_at": True, "severity": True},
        title=f"Events over the last {hours} hours",
        labels={"created_at": "Time", "source": "Source"},
    )
    fig_timeline.update_layout(
        plot_bgcolor="#1a1a2e",
        paper_bgcolor="#0d0d1a",
        font_color="#e0e0e0",
        height=350,
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

    # ------------------------------------------------------------------ #
    #  Side-by-side: heatmap + source bar                                 #
    # ------------------------------------------------------------------ #
    left, right = st.columns(2)

    with left:
        st.subheader("Attack Heatmap (Hour × Day)")
        day_order = ["Monday", "Tuesday", "Wednesday", "Thursday",
                     "Friday", "Saturday", "Sunday"]
        heat_df = (
            df.groupby(["day_name", "hour"])
            .size()
            .reset_index(name="count")
        )
        # Pivot
        pivot = heat_df.pivot(index="day_name", columns="hour", values="count").fillna(0)
        # Reorder rows
        pivot = pivot.reindex([d for d in day_order if d in pivot.index])

        fig_heat = go.Figure(
            data=go.Heatmap(
                z=pivot.values,
                x=[f"{h:02d}:00" for h in pivot.columns],
                y=list(pivot.index),
                colorscale="Reds",
                showscale=True,
            )
        )
        fig_heat.update_layout(
            plot_bgcolor="#1a1a2e",
            paper_bgcolor="#0d0d1a",
            font_color="#e0e0e0",
            height=300,
            xaxis_title="Hour of Day",
            yaxis_title="",
        )
        st.plotly_chart(fig_heat, use_container_width=True)

    with right:
        st.subheader("Events by Source")
        source_df = (
            df.groupby(["source", "severity"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=True)
        )
        fig_source = px.bar(
            source_df,
            x="count",
            y="source",
            color="severity",
            color_discrete_map=SEVERITY_COLORS,
            orientation="h",
            title="Top Sources",
            labels={"count": "Event Count", "source": "Source"},
        )
        fig_source.update_layout(
            plot_bgcolor="#1a1a2e",
            paper_bgcolor="#0d0d1a",
            font_color="#e0e0e0",
            height=300,
            showlegend=False,
        )
        st.plotly_chart(fig_source, use_container_width=True)

    # ------------------------------------------------------------------ #
    #  MITRE ATT&CK Correlations                                          #
    # ------------------------------------------------------------------ #
    corr_df = _load_correlations(hours)
    if not corr_df.empty:
        st.divider()
        st.subheader("MITRE ATT&CK Correlations Detected")

        unacked = corr_df[corr_df["acknowledged"] == 0]
        if not unacked.empty:
            st.error(f"**{len(unacked)} unacknowledged correlation(s)!**")

        for _, row in corr_df.iterrows():
            sev_color = SEVERITY_COLORS.get(row["severity"], "#888")
            acked_icon = "✅" if row["acknowledged"] else "🔴"
            with st.expander(
                f"{acked_icon} [{row['mitre_id']}] {row['rule_name']} — {row['severity']}",
                expanded=(not row["acknowledged"] and row["severity"] in ("CRITICAL", "HIGH")),
            ):
                c1, c2, c3 = st.columns(3)
                c1.metric("MITRE ID", row["mitre_id"])
                c2.metric("Tactic", row["mitre_tactic"])
                c3.metric("Matched Events", row["matched_count"])

                st.markdown(
                    f"**Source:** {row['source']}  |  "
                    f"**Fired:** {row['fired_at']}  |  "
                    f"**Status:** {'Acknowledged' if row['acknowledged'] else 'Open'}"
                )
    else:
        st.info("No MITRE ATT&CK correlations detected in this time window.")


def render_agent_dashboard():
    """Render the registered agents dashboard."""
    import requests as _requests

    st.subheader("Connected Monitoring Agents")

    try:
        resp = _requests.get(f"{BACKEND}/agents", verify=VERIFY_SSL, timeout=30)
        if resp.status_code != 200:
            st.warning(f"Backend returned status {resp.status_code}")
            return
        agents = resp.json()
    except _requests.exceptions.ConnectionError:
        st.error("Cannot reach backend API. Is the backend container running?")
        return
    except Exception as e:
        st.error(f"Error loading agents: {e}")
        return

    if not agents:
        st.info("No agents registered yet. Deploy an agent to start monitoring remote machines.")
        return

    now = datetime.utcnow()
    for agent in agents:
        last_seen = agent.get("last_seen")
        if last_seen:
            try:
                last_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                delta = now - last_dt.replace(tzinfo=None)
                online = delta.total_seconds() < 120
                last_str = f"{int(delta.total_seconds() // 60)}m ago"
            except Exception:
                online = False
                last_str = last_seen
        else:
            online = False
            last_str = "Never"

        status_icon = "🟢 Online" if online else "🔴 Offline"
        platform_icon = {
            "Windows": "🪟",
            "Linux":   "🐧",
            "macOS":   "🍎",
        }.get(agent.get("platform", "").split("/")[0], "💻")

        with st.container():
            c1, c2, c3, c4, c5 = st.columns([2, 2, 1, 1, 1])
            c1.markdown(f"**{platform_icon} {agent.get('hostname', 'Unknown')}**")
            c2.markdown(f"`{agent.get('agent_id', '')}`")
            c3.markdown(agent.get("platform", "Unknown"))
            c4.markdown(status_icon)
            c5.markdown(f"Last: {last_str}")
            st.divider()
