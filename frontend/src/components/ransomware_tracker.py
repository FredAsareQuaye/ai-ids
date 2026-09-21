"""
Ransomware Live Tracking Dashboard.

Displays real-time ransomware detection events, threat level, IOC breakdown,
MITRE ATT&CK mapping, affected hosts, and a time-series activity chart.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime

BACKEND    = BACKEND
VERIFY_SSL = False

_DARK = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="#0d1117",
    font_color="#c9d1d9",
    margin=dict(l=10, r=10, t=36, b=10),
)

IOC_COLORS = {
    "Ransom Command":   "#ff4444",
    "Ransom Extension": "#f78166",
    "Ransom Process":   "#e3b341",
}

SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#f78166",
    "MEDIUM":   "#e3b341",
    "LOW":      "#56d364",
}

THREAT_LEVEL_CONFIG = {
    "CRITICAL": ("#ff4444", "Active Ransomware Detected — Immediate Response Required"),
    "HIGH":     ("#f78166", "High-Confidence Ransomware Indicators — Investigate Now"),
    "ELEVATED": ("#e3b341", "Suspicious Activity Detected — Monitor Closely"),
    "LOW":      ("#56d364", "Low-Level Indicators — Continue Standard Monitoring"),
    "NONE":     ("#484f58", "No Ransomware Indicators Detected"),
}

MITRE_LABELS = {
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop",
    "T1070": "Indicator Removal",
    "T1562": "Impair Defenses",
    "T1059": "Command & Scripting Interpreter",
    "T1021": "Remote Services",
    "T1078": "Valid Accounts",
    "T1485": "Data Destruction",
    "T1491": "Defacement",
}


def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params,
                         verify=VERIFY_SSL, timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Connection error: {e}")
    return None


def _post(path, params=None):
    try:
        r = requests.post(f"{BACKEND}{path}", params=params,
                          verify=VERIFY_SSL, timeout=20)
        return r.status_code == 200, r.json() if r.ok else {}
    except Exception as e:
        return False, {"error": str(e)}


def _patch(path):
    try:
        r = requests.patch(f"{BACKEND}{path}", verify=VERIFY_SSL, timeout=30)
        return r.status_code == 200
    except Exception:
        return False


def _badge(text, color):
    return (
        f'<span style="background:{color}22;color:{color};border:1px solid {color};'
        f'border-radius:20px;font-size:0.68rem;font-weight:600;padding:2px 9px;">'
        f'{text}</span>'
    )


def render_ransomware_tracker():
    # Page header
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #e7554b;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Ransomware Live Tracker
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Real-time detection of ransomware indicators &nbsp;&middot;&nbsp;
        Extension signatures &nbsp;&middot;&nbsp; Command patterns &nbsp;&middot;&nbsp;
        MITRE ATT&CK mapping &nbsp;&middot;&nbsp; Affected host tracking
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Controls row
    c_hours, c_refresh, c_scan, _ = st.columns([1, 1, 1, 3])
    with c_hours:
        hours = st.selectbox("Time window", [1, 6, 12, 24, 48, 72, 168],
                             index=3, format_func=lambda h: f"Last {h}h",
                             key="rw_hours")
    with c_refresh:
        auto = st.checkbox("Auto-refresh (60s)", value=False, key="rw_auto")
    with c_scan:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        if st.button("Run Scan Now", type="primary", use_container_width=True):
            ok, result = _post("/ransomware/scan", params={"hours": hours})
            if ok:
                st.success(f"Scan complete — {result.get('new_detections', 0)} new detections.")
            else:
                st.error("Scan failed. Is the backend running?")

    if auto:
        import time
        time.sleep(60)
        st.rerun()

    # -----------------------------------------------------------------------
    # Load data
    # -----------------------------------------------------------------------
    stats  = _get("/ransomware/stats",  params={"hours": hours}) or {}
    events = _get("/ransomware/events", params={"hours": hours, "limit": 500}) or []
    iocs   = _get("/ransomware/indicators") or []

    # -----------------------------------------------------------------------
    # Threat Level Banner
    # -----------------------------------------------------------------------
    threat_level = stats.get("threat_level", "NONE")
    tl_color, tl_msg = THREAT_LEVEL_CONFIG.get(threat_level, THREAT_LEVEL_CONFIG["NONE"])

    st.markdown(f"""
    <div style="background:{tl_color}18;border:1px solid {tl_color}55;border-left:6px solid {tl_color};
                border-radius:8px;padding:14px 20px;margin-bottom:18px;
                display:flex;align-items:center;gap:16px;">
      <div style="font-size:1.6rem;font-weight:900;color:{tl_color};min-width:100px;
                  text-align:center;letter-spacing:.05em;">{threat_level}</div>
      <div>
        <div style="color:#e6edf3;font-weight:700;font-size:.95rem;">{tl_msg}</div>
        <div style="color:#6e7681;font-size:.75rem;margin-top:3px;">
          Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # KPI row
    # -----------------------------------------------------------------------
    total    = stats.get("total", 0)
    critical = stats.get("critical", 0)
    high     = stats.get("high", 0)
    hosts    = stats.get("affected_hosts", [])
    ioc_bkdn = stats.get("ioc_breakdown", {})
    top_ioc  = max(ioc_bkdn, key=ioc_bkdn.get) if ioc_bkdn else "—"

    kpi_data = [
        ("Total Detections", total,           "#e3b341"),
        ("Critical Events",  critical,         "#ff4444"),
        ("High Events",      high,             "#f78166"),
        ("Affected Hosts",   len(hosts),       "#d2a8ff"),
        ("Top IOC Type",     top_ioc[:18],     "#58a6ff"),
    ]
    cols = st.columns(5)
    for col, (label, val, color) in zip(cols, kpi_data):
        with col:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                        padding:14px;text-align:center;border-top:3px solid {color};">
              <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;
                          letter-spacing:.08em;">{label}</div>
              <div style="color:{color};font-size:1.7rem;font-weight:700;">{val}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # -----------------------------------------------------------------------
    # Main content — tabs
    # -----------------------------------------------------------------------
    tab_live, tab_iocs, tab_mitre, tab_hosts, tab_timeline = st.tabs([
        "Live Events",
        "IOC Indicators",
        "MITRE ATT&CK",
        "Affected Hosts",
        "Activity Timeline",
    ])

    with tab_live:
        _render_live_events(events)

    with tab_iocs:
        _render_ioc_panel(iocs, ioc_bkdn)

    with tab_mitre:
        _render_mitre_panel(events)

    with tab_hosts:
        _render_hosts_panel(events, hosts)

    with tab_timeline:
        _render_timeline(stats.get("timeline", []))


# ---------------------------------------------------------------------------
# Tab renderers
# ---------------------------------------------------------------------------

def _render_live_events(events):
    if not events:
        st.info("No ransomware events detected in the selected time window.")
        return

    unacked = [e for e in events if not e.get("acknowledged")]
    if unacked:
        st.error(f"**{len(unacked)} unacknowledged ransomware event(s) require attention.**")

    for ev in events[:100]:
        sev       = ev.get("severity", "HIGH")
        sev_color = SEV_COLORS.get(sev, "#888")
        ioc_type  = ev.get("ioc_type", "")
        ioc_color = IOC_COLORS.get(ioc_type, "#888")
        ts        = str(ev.get("detected_at", ""))[:16]
        mitre_id  = ev.get("mitre_id", "")
        mitre_nm  = ev.get("mitre_name", "")
        source    = str(ev.get("source") or "—")[:40]
        indicator = str(ev.get("indicator") or "")[:120]
        msg       = str(ev.get("message") or "")[:120]
        ev_id     = ev.get("id")
        acked     = bool(ev.get("acknowledged"))

        ack_icon = "Acknowledged" if acked else "Open"
        ack_col  = "#484f58" if acked else sev_color

        with st.expander(
            f"[{sev}] {ioc_type} — {indicator[:60]}",
            expanded=(not acked and sev in ("CRITICAL", "HIGH")),
        ):
            col1, col2, col3 = st.columns(3)
            col1.metric("Severity",  sev)
            col2.metric("IOC Type",  ioc_type)
            col3.metric("MITRE",     mitre_id or "—")

            st.markdown(f"""
            <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;
                        padding:10px 14px;margin:8px 0;font-size:.82rem;">
              <div style="color:#8b949e;margin-bottom:4px;">Indicator</div>
              <code style="color:{ioc_color};word-break:break-all;">{indicator}</code>
            </div>
            """, unsafe_allow_html=True)

            if msg:
                st.markdown(f"""
                <div style="color:#8b949e;font-size:.8rem;margin-bottom:4px;">
                  Source: <span style="color:#c9d1d9;">{source}</span>
                  &nbsp;&middot;&nbsp; {ts}
                  &nbsp;&middot;&nbsp; {mitre_nm or mitre_id}
                </div>
                <div style="color:#6e7681;font-size:.75rem;
                            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                  {msg}
                </div>
                """, unsafe_allow_html=True)

            if not acked and ev_id:
                if st.button("Acknowledge", key=f"rw_ack_{ev_id}"):
                    if _patch(f"/ransomware/events/{ev_id}/acknowledge"):
                        st.success("Event acknowledged.")
                        st.rerun()
                    else:
                        st.error("Failed to acknowledge.")


def _render_ioc_panel(iocs, ioc_bkdn):
    # Breakdown donut
    if ioc_bkdn:
        labels = list(ioc_bkdn.keys())
        values = list(ioc_bkdn.values())
        colors = [IOC_COLORS.get(l, "#888") for l in labels]

        fig = go.Figure(go.Pie(
            labels=labels, values=values,
            hole=0.6,
            marker=dict(colors=colors, line=dict(color="#0d1117", width=2)),
            textinfo="percent+label",
            textfont=dict(size=11),
        ))
        fig.update_layout(
            **_DARK,
            height=260,
            showlegend=False,
            title=dict(text="IOC Type Distribution", font=dict(color="#58a6ff", size=13)),
            annotations=[dict(text=f"<b>{sum(values)}</b><br>IOCs",
                              x=0.5, y=0.5, showarrow=False,
                              font=dict(size=14, color="#c9d1d9"))],
        )
        st.plotly_chart(fig, use_container_width=True)

    if not iocs:
        st.info("No recurring indicators yet.")
        return

    st.markdown("#### Top Recurring Indicators")
    for row in iocs[:40]:
        itype    = row.get("ioc_type", "")
        ic       = IOC_COLORS.get(itype, "#888")
        sev      = row.get("severity", "MEDIUM")
        sc       = SEV_COLORS.get(sev, "#888")
        hits     = row.get("hit_count", 0)
        last     = str(row.get("last_seen", ""))[:16]
        indic    = str(row.get("indicator", ""))[:100]

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {ic};
                    border-radius:8px;padding:9px 14px;margin-bottom:5px;
                    display:flex;justify-content:space-between;align-items:center;gap:10px;">
          <div style="flex:1;min-width:0;">
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:3px;">
              {_badge(itype, ic)}
              {_badge(sev, sc)}
            </div>
            <code style="color:#c9d1d9;font-size:.78rem;word-break:break-all;">{indic}</code>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="color:{ic};font-weight:700;font-size:1.1rem;">{hits}x</div>
            <div style="color:#484f58;font-size:.68rem;">{last}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)


def _render_mitre_panel(events):
    if not events:
        st.info("No MITRE ATT&CK data available.")
        return

    tactic_counts: dict = {}
    for ev in events:
        mid = ev.get("mitre_id")
        if mid:
            tactic_counts[mid] = tactic_counts.get(mid, 0) + 1

    if not tactic_counts:
        st.info("No MITRE technique data in current events.")
        return

    sorted_tactics = sorted(tactic_counts.items(), key=lambda x: -x[1])

    # Bar chart
    ids    = [t[0] for t in sorted_tactics]
    counts = [t[1] for t in sorted_tactics]
    names  = [MITRE_LABELS.get(i, i) for i in ids]

    fig = go.Figure(go.Bar(
        x=counts, y=[f"{i}: {n}" for i, n in zip(ids, names)],
        orientation="h",
        marker_color="#e7554b",
        text=counts, textposition="outside",
        textfont=dict(color="#c9d1d9"),
    ))
    fig.update_layout(
        **_DARK,
        height=max(200, len(ids) * 42),
        title=dict(text="MITRE ATT&CK Techniques Observed", font=dict(color="#58a6ff", size=13)),
        xaxis=dict(gridcolor="#21262d", title="Event Count"),
        yaxis=dict(gridcolor="#21262d"),
    )
    st.plotly_chart(fig, use_container_width=True)

    # Tactic cards
    st.markdown("#### Technique Details")
    for mid, count in sorted_tactics:
        name  = MITRE_LABELS.get(mid, "Unknown Technique")
        color = "#e7554b" if count >= 3 else "#f78166" if count >= 1 else "#888"
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {color};
                    border-radius:8px;padding:10px 14px;margin-bottom:6px;
                    display:flex;justify-content:space-between;align-items:center;">
          <div>
            <span style="color:{color};font-weight:700;font-size:.85rem;">{mid}</span>
            &nbsp;&middot;&nbsp;
            <span style="color:#c9d1d9;font-size:.82rem;">{name}</span>
          </div>
          <div style="color:{color};font-weight:700;font-size:1.1rem;">{count} hit{'s' if count!=1 else ''}</div>
        </div>
        """, unsafe_allow_html=True)


def _render_hosts_panel(events, hosts):
    if not hosts:
        st.info("No affected hosts identified.")
        return

    host_stats: dict = {}
    for ev in events:
        src = ev.get("source") or "unknown"
        if src not in host_stats:
            host_stats[src] = {"critical": 0, "high": 0, "total": 0, "iocs": set()}
        sev = ev.get("severity", "")
        if sev == "CRITICAL":
            host_stats[src]["critical"] += 1
        elif sev == "HIGH":
            host_stats[src]["high"] += 1
        host_stats[src]["total"] += 1
        host_stats[src]["iocs"].add(ev.get("ioc_type", ""))

    sorted_hosts = sorted(host_stats.items(), key=lambda x: (-x[1]["critical"], -x[1]["total"]))

    st.markdown(f"**{len(hosts)} host(s) with ransomware activity**")
    for hostname, s in sorted_hosts:
        risk_color = "#ff4444" if s["critical"] > 0 else "#f78166" if s["high"] > 0 else "#e3b341"
        risk_label = "CRITICAL" if s["critical"] > 0 else "HIGH" if s["high"] > 0 else "ELEVATED"

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {risk_color};
                    border-radius:8px;padding:12px 16px;margin-bottom:6px;">
          <div style="display:flex;justify-content:space-between;align-items:center;
                      margin-bottom:6px;">
            <div>
              <span style="color:#e6edf3;font-weight:700;">{hostname}</span>
              &nbsp;{_badge(risk_label, risk_color)}
            </div>
            <div style="color:{risk_color};font-weight:700;font-size:1.1rem;">{s['total']} events</div>
          </div>
          <div style="display:flex;gap:16px;font-size:.78rem;color:#8b949e;">
            <span>Critical: <b style="color:#ff4444;">{s['critical']}</b></span>
            <span>High: <b style="color:#f78166;">{s['high']}</b></span>
            <span>IOC Types: <b style="color:#c9d1d9;">{', '.join(s['iocs'])}</b></span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    # Host risk chart
    h_names  = [h[0][:30] for h in sorted_hosts]
    h_totals = [h[1]["total"] for h in sorted_hosts]
    h_colors = [
        "#ff4444" if h[1]["critical"] > 0 else
        "#f78166" if h[1]["high"] > 0 else "#e3b341"
        for h in sorted_hosts
    ]

    fig = go.Figure(go.Bar(
        x=h_totals, y=h_names,
        orientation="h",
        marker_color=h_colors,
        text=h_totals, textposition="outside",
        textfont=dict(color="#c9d1d9"),
    ))
    fig.update_layout(
        **_DARK,
        height=max(200, len(h_names) * 38),
        title=dict(text="Events per Host", font=dict(color="#58a6ff", size=13)),
        xaxis=dict(gridcolor="#21262d"),
        yaxis=dict(gridcolor="#21262d"),
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_timeline(timeline):
    if not timeline:
        st.info("No timeline data available for the selected window.")
        return

    df = pd.DataFrame(timeline)
    if df.empty or "hour" not in df.columns:
        st.info("Insufficient data for timeline.")
        return

    df["hour"] = pd.to_datetime(df["hour"], errors="coerce")
    df = df.dropna(subset=["hour"]).sort_values("hour")

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["hour"], y=df["count"],
        mode="lines+markers",
        line=dict(color="#e7554b", width=2),
        marker=dict(size=6, color="#e7554b"),
        fill="tozeroy",
        fillcolor="rgba(231,85,75,0.12)",
        name="Detections",
    ))
    fig.update_layout(
        **_DARK,
        height=280,
        title=dict(text="Ransomware Detection Activity Over Time",
                   font=dict(color="#58a6ff", size=13)),
        xaxis=dict(gridcolor="#21262d", title="Time"),
        yaxis=dict(gridcolor="#21262d", title="Detections"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

    # Peak hour callout
    peak = df.loc[df["count"].idxmax()]
    st.markdown(f"""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                padding:10px 16px;display:flex;gap:20px;flex-wrap:wrap;">
      <span style="color:#8b949e;font-size:.8rem;">
        Peak activity: <b style="color:#e7554b;">{peak['count']} detections</b>
        at <b style="color:#c9d1d9;">{str(peak['hour'])[:16]}</b>
      </span>
      <span style="color:#8b949e;font-size:.8rem;">
        Total detections: <b style="color:#e3b341;">{df['count'].sum()}</b>
      </span>
    </div>
    """, unsafe_allow_html=True)
