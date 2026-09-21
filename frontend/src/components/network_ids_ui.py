"""
Network Threat Sensor — live intrusion detection dashboard.

Displays real-time network alert events, protocol telemetry,
top attacking IPs, MITRE ATT&CK technique mapping, DNS analysis,
HTTP traffic inspection, and sensor health status.
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

SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#f78166",
    "MEDIUM":   "#e3b341",
    "LOW":      "#56d364",
}

PROTO_COLORS = {
    "TCP":  "#58a6ff",
    "UDP":  "#1db8c2",
    "ICMP": "#e3b341",
    "HTTP": "#56d364",
    "TLS":  "#d2a8ff",
    "DNS":  "#f78166",
}

EVENT_ICONS = {
    "alert":    "ALERT",
    "dns":      "DNS",
    "http":     "HTTP",
    "tls":      "TLS",
    "ssh":      "SSH",
    "smb":      "SMB",
    "flow":     "FLOW",
    "fileinfo": "FILE",
    "anomaly":  "ANOM",
    "generic":  "EVT",
}


def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params,
                         verify=VERIFY_SSL, timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _post(path, json_body=None, params=None):
    try:
        r = requests.post(f"{BACKEND}{path}", json=json_body, params=params,
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


def _badge(text, color="#58a6ff"):
    return (
        f'<span style="background:{color}22;color:{color};border:1px solid {color};'
        f'border-radius:20px;font-size:0.67rem;font-weight:600;padding:2px 9px;'
        f'white-space:nowrap;">{text}</span>'
    )


def render_network_ids():
    # ---- Page header -------------------------------------------------------
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #58a6ff;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Network Threat Sensor
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Real-time network intrusion detection &nbsp;&middot;&nbsp;
        Protocol telemetry &nbsp;&middot;&nbsp; Traffic analysis &nbsp;&middot;&nbsp;
        MITRE ATT&CK mapping &nbsp;&middot;&nbsp; DNS &amp; HTTP inspection
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ---- Controls ----------------------------------------------------------
    c_hours, c_refresh, c_poll, _ = st.columns([1, 1, 1, 3])
    with c_hours:
        hours = st.selectbox("Time window", [1, 6, 12, 24, 48, 72, 168],
                             index=3, format_func=lambda h: f"Last {h}h",
                             key="nids_hours")
    with c_refresh:
        auto = st.checkbox("Auto-refresh (60s)", value=False, key="nids_auto")
    with c_poll:
        st.markdown("<div style='margin-top:28px;'></div>", unsafe_allow_html=True)
        if st.button("Poll Sensor Now", type="primary", use_container_width=True):
            ok, res = _post("/nids/poll")
            if ok:
                st.success(f"Poll complete — {res.get('new_events', 0)} new events ingested.")
            else:
                st.error("Poll failed — check sensor configuration.")

    if auto:
        import time; time.sleep(60); st.rerun()

    # ---- Load data ---------------------------------------------------------
    stats  = _get("/nids/stats",  params={"hours": hours}) or {}
    status = _get("/nids/status") or {}

    # ---- Sensor status bar -------------------------------------------------
    active     = status.get("sensor_active", False)
    eve_found  = status.get("eve_file_found", False)
    eve_path   = status.get("eve_file_path", "—")
    last_ev    = status.get("last_event_at") or "—"
    s_color    = "#56d364" if (active and eve_found) else "#e3b341" if active else "#ff4444"
    s_label    = "ACTIVE" if (active and eve_found) else "NO EVE FILE" if active else "OFFLINE"

    total_stored = status.get("total_events_stored", 0)
    eve_size     = status.get("eve_file_size_bytes", 0)

    st.markdown(f"""
    <div style="background:#0c1225;border:1px solid #131d35;border-radius:8px;
                padding:10px 16px;margin-bottom:16px;
                display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
      <span style="display:flex;align-items:center;gap:8px;">
        <span style="width:9px;height:9px;border-radius:50%;background:{s_color};
                     box-shadow:0 0 6px {s_color};display:inline-block;"></span>
        <span style="color:{s_color};font-weight:700;font-size:.82rem;">Sensor {s_label}</span>
      </span>
      <span style="color:#484f58;font-size:.78rem;">
        EVE file: <span style="color:#8b949e;">{eve_path}</span>
      </span>
      <span style="color:#484f58;font-size:.78rem;">
        File size: <span style="color:#8b949e;">{eve_size:,} bytes</span>
      </span>
      <span style="color:#484f58;font-size:.78rem;">
        Events stored: <span style="color:#8b949e;">{total_stored:,}</span>
      </span>
      <span style="color:#484f58;font-size:.78rem;">
        Last event: <span style="color:#8b949e;">{str(last_ev)[:16]}</span>
      </span>
    </div>
    """, unsafe_allow_html=True)

    # ---- KPI cards ---------------------------------------------------------
    total_ev  = stats.get("total_events", 0)
    total_al  = stats.get("total_alerts", 0)
    critical  = stats.get("critical", 0)
    high      = stats.get("high", 0)
    blocked   = stats.get("blocked", 0)
    protos    = stats.get("protocols", {})

    kpis = [
        ("Network Events",  total_ev,  "#58a6ff"),
        ("IDS Alerts",      total_al,  "#f78166"),
        ("Critical Alerts", critical,  "#ff4444"),
        ("High Alerts",     high,      "#e3b341"),
        ("Blocked Flows",   blocked,   "#56d364"),
        ("Protocols Seen",  len(protos),"#d2a8ff"),
    ]
    cols = st.columns(6)
    for col, (label, val, color) in zip(cols, kpis):
        with col:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                        padding:12px;text-align:center;border-top:3px solid {color};">
              <div style="color:#8b949e;font-size:.68rem;text-transform:uppercase;
                          letter-spacing:.08em;">{label}</div>
              <div style="color:{color};font-size:1.65rem;font-weight:700;">{val}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ---- Tabs --------------------------------------------------------------
    tab_alerts, tab_traffic, tab_mitre, tab_dns, tab_http, tab_status = st.tabs([
        "IDS Alerts",
        "Traffic Overview",
        "MITRE ATT&CK",
        "DNS Analysis",
        "HTTP Inspection",
        "Sensor Config",
    ])

    with tab_alerts:
        _render_alerts(hours)

    with tab_traffic:
        _render_traffic(stats)

    with tab_mitre:
        _render_mitre(stats)

    with tab_dns:
        _render_dns(hours)

    with tab_http:
        _render_http(hours)

    with tab_status:
        _render_sensor_config(status, eve_path)


# ---------------------------------------------------------------------------
# Tab renderers
# ---------------------------------------------------------------------------

def _render_alerts(hours):
    sev_filter = st.multiselect(
        "Filter severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH"],
        key="nids_sev_filter",
    )
    alerts = _get("/nids/alerts", params={"hours": hours, "limit": 300}) or []

    if sev_filter:
        alerts = [a for a in alerts if a.get("severity") in sev_filter]

    if not alerts:
        st.info("No IDS alerts in the selected window.")
        return

    unacked = [a for a in alerts if not a.get("acknowledged")]
    if unacked:
        st.error(f"**{len(unacked)} unacknowledged alert(s) require review.**")

    for ev in alerts[:150]:
        sev   = ev.get("severity", "LOW")
        sc    = SEV_COLORS.get(sev, "#888")
        sig   = ev.get("sig_name") or "Unknown Signature"
        cat   = ev.get("sig_category") or "—"
        src   = f"{ev.get('src_ip') or '?'}:{ev.get('src_port') or '?'}"
        dst   = f"{ev.get('dest_ip') or '?'}:{ev.get('dest_port') or '?'}"
        proto = str(ev.get("proto") or "—")
        ts    = str(ev.get("ts") or "")[:16]
        mid   = ev.get("mitre_id") or ""
        mnm   = ev.get("mitre_name") or ""
        act   = ev.get("action") or "allowed"
        act_c = "#56d364" if act == "blocked" else "#f78166"
        ev_id = ev.get("id")
        acked = bool(ev.get("acknowledged"))

        with st.expander(
            f"[{sev}] {sig[:70]}",
            expanded=(not acked and sev in ("CRITICAL", "HIGH")),
        ):
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Severity", sev)
            c2.metric("Action",   act.upper())
            c3.metric("Protocol", proto)
            c4.metric("Sig ID",   ev.get("sig_id") or "—")

            st.markdown(f"""
            <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;
                        padding:10px 14px;margin:8px 0;font-size:.82rem;">
              <div style="color:#8b949e;margin-bottom:4px;">Signature</div>
              <div style="color:{sc};font-weight:600;">{sig}</div>
              <div style="color:#484f58;font-size:.74rem;margin-top:4px;">
                Category: <span style="color:#8b949e;">{cat}</span>
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:6px 0;">
              <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;
                          padding:8px 12px;font-size:.8rem;">
                <span style="color:#6e7681;">Source</span><br>
                <span style="color:#58a6ff;font-weight:600;">{src}</span>
              </div>
              <div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;
                          padding:8px 12px;font-size:.8rem;">
                <span style="color:#6e7681;">Destination</span><br>
                <span style="color:#f78166;font-weight:600;">{dst}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

            if mid:
                st.markdown(f"""
                <div style="color:#8b949e;font-size:.78rem;margin-top:4px;">
                  MITRE: <span style="color:#d2a8ff;font-weight:600;">{mid}</span>
                  &nbsp;—&nbsp; {mnm}
                  &nbsp;&middot;&nbsp; {ts}
                </div>
                """, unsafe_allow_html=True)

            if not acked and ev_id:
                if st.button("Acknowledge", key=f"nids_ack_{ev_id}"):
                    if _patch(f"/nids/alerts/{ev_id}/acknowledge"):
                        st.success("Alert acknowledged.")
                        st.rerun()


def _render_traffic(stats):
    protos   = stats.get("protocols", {})
    ev_types = stats.get("event_types", {})
    top_ips  = stats.get("top_src_ips", [])
    timeline = stats.get("timeline", [])
    top_sigs = stats.get("top_signatures", [])

    # Row 1: timeline + protocol donut
    col1, col2 = st.columns([2, 1])

    with col1:
        if timeline:
            df = pd.DataFrame(timeline)
            df["hour"] = pd.to_datetime(df["hour"], errors="coerce")
            df = df.dropna(subset=["hour"]).sort_values("hour")
            fig = go.Figure(go.Scatter(
                x=df["hour"], y=df["count"],
                mode="lines+markers",
                line=dict(color="#58a6ff", width=2),
                marker=dict(size=5),
                fill="tozeroy",
                fillcolor="rgba(88,166,255,0.1)",
            ))
            fig.update_layout(**_DARK, height=260,
                              title=dict(text="IDS Alerts Over Time",
                                         font=dict(color="#58a6ff", size=13)),
                              xaxis=dict(gridcolor="#21262d"),
                              yaxis=dict(gridcolor="#21262d"),
                              showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No timeline data yet.")

    with col2:
        if protos:
            labels = list(protos.keys())
            values = list(protos.values())
            colors = [PROTO_COLORS.get(l.upper(), "#888") for l in labels]
            fig = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.58,
                marker=dict(colors=colors, line=dict(color="#0d1117", width=2)),
                textinfo="percent+label", textfont=dict(size=11),
            ))
            fig.update_layout(**_DARK, height=260, showlegend=False,
                              title=dict(text="Protocol Mix",
                                         font=dict(color="#58a6ff", size=13)))
            st.plotly_chart(fig, use_container_width=True)

    # Row 2: top IPs + event type breakdown
    col3, col4 = st.columns([1, 1])

    with col3:
        st.markdown("#### Top Attacking IPs")
        if top_ips:
            max_cnt = max(r["count"] for r in top_ips) or 1
            for r in top_ips:
                pct = r["count"] / max_cnt * 100
                st.markdown(f"""
                <div style="background:#161b22;border:1px solid #30363d;
                            border-radius:6px;padding:8px 12px;margin-bottom:4px;">
                  <div style="display:flex;justify-content:space-between;
                              align-items:center;margin-bottom:4px;">
                    <span style="color:#58a6ff;font-size:.82rem;font-weight:600;">
                      {r['ip']}
                    </span>
                    <span style="color:#e3b341;font-weight:700;">{r['count']}</span>
                  </div>
                  <div style="background:#21262d;border-radius:4px;height:4px;">
                    <div style="background:#58a6ff;width:{pct:.0f}%;height:4px;
                                border-radius:4px;"></div>
                  </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No attacking IPs recorded.")

    with col4:
        st.markdown("#### Event Types")
        if ev_types:
            for etype, cnt in sorted(ev_types.items(), key=lambda x: -x[1]):
                label = EVENT_ICONS.get(etype, etype.upper())
                color = "#58a6ff" if etype == "alert" else "#1db8c2"
                st.markdown(f"""
                <div style="background:#161b22;border:1px solid #30363d;
                            border-radius:6px;padding:8px 12px;margin-bottom:4px;
                            display:flex;justify-content:space-between;align-items:center;">
                  {_badge(label, color)}
                  <span style="color:#c9d1d9;font-weight:600;">{cnt:,}</span>
                </div>
                """, unsafe_allow_html=True)

    # Row 3: top signatures
    st.markdown("#### Top Triggered Signatures")
    if top_sigs:
        max_sig = max(r["count"] for r in top_sigs) or 1
        for r in top_sigs:
            pct = r["count"] / max_sig * 100
            cat = r.get("category") or "—"
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid #f78166;
                        border-radius:6px;padding:8px 14px;margin-bottom:5px;">
              <div style="display:flex;justify-content:space-between;align-items:center;
                          margin-bottom:4px;">
                <div>
                  <span style="color:#c9d1d9;font-size:.82rem;font-weight:600;">
                    {r['name'][:80]}
                  </span><br>
                  <span style="color:#484f58;font-size:.71rem;">{cat}</span>
                </div>
                <span style="color:#f78166;font-weight:700;flex-shrink:0;margin-left:12px;">
                  {r['count']}x
                </span>
              </div>
              <div style="background:#21262d;border-radius:4px;height:3px;">
                <div style="background:#f78166;width:{pct:.0f}%;height:3px;
                            border-radius:4px;"></div>
              </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No signatures fired yet.")


def _render_mitre(stats):
    mitre = stats.get("mitre", [])

    if not mitre:
        st.info("No MITRE ATT&CK technique data in the selected window.")
        return

    ids    = [r["id"]    for r in mitre]
    names  = [r["name"]  for r in mitre]
    counts = [r["count"] for r in mitre]

    fig = go.Figure(go.Bar(
        x=counts,
        y=[f"{i}: {n}" for i, n in zip(ids, names)],
        orientation="h",
        marker_color="#58a6ff",
        text=counts, textposition="outside",
        textfont=dict(color="#c9d1d9"),
    ))
    fig.update_layout(
        **_DARK,
        height=max(220, len(ids) * 42),
        title=dict(text="MITRE ATT&CK Techniques — Network Layer",
                   font=dict(color="#58a6ff", size=13)),
        xaxis=dict(gridcolor="#21262d", title="Alert Count"),
        yaxis=dict(gridcolor="#21262d"),
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("#### Technique Detail")
    for r in mitre:
        color = "#ff4444" if r["count"] >= 10 else "#f78166" if r["count"] >= 3 else "#e3b341"
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {color};
                    border-radius:8px;padding:10px 14px;margin-bottom:5px;
                    display:flex;justify-content:space-between;align-items:center;">
          <div>
            <span style="color:{color};font-weight:700;font-size:.85rem;">{r['id']}</span>
            &nbsp;&middot;&nbsp;
            <span style="color:#c9d1d9;font-size:.82rem;">{r['name']}</span>
          </div>
          <span style="color:{color};font-weight:700;font-size:1.05rem;">
            {r['count']} alert{'s' if r['count'] != 1 else ''}
          </span>
        </div>
        """, unsafe_allow_html=True)


def _render_dns(hours):
    dns = _get("/nids/dns", params={"hours": hours, "limit": 200}) or []

    if not dns:
        st.info("No DNS events recorded. DNS logging must be enabled on the sensor.")
        return

    st.markdown(f"**{len(dns)} unique domains queried in window**")

    search = st.text_input("Filter domain", placeholder="e.g. malware.com", key="nids_dns_search")

    if search:
        dns = [r for r in dns if search.lower() in (r.get("dns_query") or "").lower()]

    # Top domains chart
    df = pd.DataFrame(dns[:30])
    if not df.empty and "dns_query" in df.columns:
        fig = go.Figure(go.Bar(
            x=df["cnt"],
            y=df["dns_query"],
            orientation="h",
            marker_color="#1db8c2",
        ))
        fig.update_layout(**_DARK, height=min(600, len(df) * 30 + 80),
                          title=dict(text="Top Queried Domains",
                                     font=dict(color="#58a6ff", size=13)),
                          xaxis=dict(gridcolor="#21262d"),
                          yaxis=dict(gridcolor="#21262d"))
        st.plotly_chart(fig, use_container_width=True)

    # Table
    for r in dns[:100]:
        domain = r.get("dns_query") or "—"
        cnt    = r.get("cnt", 0)
        src    = r.get("src_ip") or "—"
        last   = str(r.get("last_seen") or "")[:16]

        suspicious = any(p in domain.lower() for p in [
            "dyndns", "no-ip", "ddns", ".xyz", ".top", ".club",
            "bit.ly", "tinyurl", "tor2web",
        ])
        color = "#e3b341" if suspicious else "#c9d1d9"

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;
                    border-left:4px solid {'#e3b341' if suspicious else '#21262d'};
                    border-radius:6px;padding:7px 12px;margin-bottom:3px;
                    display:flex;justify-content:space-between;align-items:center;gap:10px;">
          <div style="flex:1;min-width:0;">
            <code style="color:{color};font-size:.78rem;">{domain}</code>
            {'<span style="color:#e3b341;font-size:.68rem;margin-left:8px;">suspicious pattern</span>' if suspicious else ''}
          </div>
          <div style="text-align:right;flex-shrink:0;font-size:.75rem;color:#484f58;">
            <span>from {src}</span> &middot;
            <span style="color:#1db8c2;font-weight:600;">{cnt}x</span> &middot;
            <span>{last}</span>
          </div>
        </div>
        """, unsafe_allow_html=True)


def _render_http(hours):
    http = _get("/nids/http", params={"hours": hours, "limit": 200}) or []

    if not http:
        st.info("No HTTP events recorded. HTTP logging must be enabled on the sensor.")
        return

    st.markdown(f"**{len(http)} HTTP transactions observed**")

    search = st.text_input("Filter URL / host", placeholder="e.g. /admin or evil.com",
                           key="nids_http_search")
    if search:
        http = [r for r in http if (
            search.lower() in (r.get("http_url") or "").lower() or
            search.lower() in (r.get("http_host") or "").lower()
        )]

    for r in http[:100]:
        method  = r.get("http_method") or "GET"
        url     = r.get("http_url") or "/"
        host    = r.get("http_host") or "—"
        status  = r.get("http_status") or "—"
        src     = r.get("src_ip") or "—"
        dst     = r.get("dest_ip") or "—"
        ts      = str(r.get("ts") or "")[:16]

        m_color = {"GET": "#56d364", "POST": "#e3b341", "PUT": "#58a6ff",
                   "DELETE": "#ff4444", "HEAD": "#1db8c2"}.get(method, "#888")
        s_color = ("#56d364" if str(status).startswith("2") else
                   "#e3b341" if str(status).startswith("3") else
                   "#ff4444" if str(status).startswith(("4","5")) else "#888")

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:6px;
                    padding:8px 12px;margin-bottom:4px;font-size:.79rem;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap;">
            {_badge(method, m_color)}
            <code style="color:#c9d1d9;word-break:break-all;">{host}{url[:100]}</code>
            <span style="color:{s_color};font-weight:600;flex-shrink:0;">{status}</span>
          </div>
          <div style="color:#484f58;font-size:.72rem;">
            {src} → {dst} &nbsp;&middot;&nbsp; {ts}
          </div>
        </div>
        """, unsafe_allow_html=True)


def _render_sensor_config(status, eve_path):
    st.markdown("#### Sensor Configuration")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;">
          <div style="color:#8b949e;font-size:.72rem;text-transform:uppercase;
                      letter-spacing:.07em;margin-bottom:12px;">Sensor Status</div>
          <table style="width:100%;font-size:.8rem;border-collapse:collapse;">
            <tr><td style="color:#6e7681;padding:4px 0;">Engine Active</td>
                <td style="color:#c9d1d9;text-align:right;">
                  {'<span style="color:#56d364;">Yes</span>' if status.get("sensor_active") else '<span style="color:#ff4444;">No</span>'}
                </td></tr>
            <tr><td style="color:#6e7681;padding:4px 0;">EVE File Found</td>
                <td style="color:#c9d1d9;text-align:right;">
                  {'<span style="color:#56d364;">Yes</span>' if status.get("eve_file_found") else '<span style="color:#ff4444;">No</span>'}
                </td></tr>
            <tr><td style="color:#6e7681;padding:4px 0;">Poll Interval</td>
                <td style="color:#c9d1d9;text-align:right;">{status.get("poll_interval_s","—")}s</td></tr>
            <tr><td style="color:#6e7681;padding:4px 0;">File Offset</td>
                <td style="color:#c9d1d9;text-align:right;">{status.get("file_offset",0):,} bytes</td></tr>
            <tr><td style="color:#6e7681;padding:4px 0;">Total Stored</td>
                <td style="color:#c9d1d9;text-align:right;">{status.get("total_events_stored",0):,}</td></tr>
            <tr><td style="color:#6e7681;padding:4px 0;">Last Event</td>
                <td style="color:#c9d1d9;text-align:right;">{str(status.get("last_event_at") or "—")[:16]}</td></tr>
          </table>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;">
          <div style="color:#8b949e;font-size:.72rem;text-transform:uppercase;
                      letter-spacing:.07em;margin-bottom:12px;">EVE Log Path</div>
          <code style="color:#58a6ff;font-size:.8rem;word-break:break-all;">{eve_path}</code>
          <div style="color:#6e7681;font-size:.74rem;margin-top:12px;">
            Override with env var:<br>
            <code style="color:#56d364;">NIDS_EVE_PATH=/path/to/eve.json</code>
          </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("#### Push Events via API")
    st.markdown("""
    Remote sensors can forward EVE JSON lines directly to the ingest endpoint:
    """)
    st.code("""# Push EVE JSON lines from a remote host
curl -sk -X POST https://<siem-host>:8000/api/v1/nids/ingest \\
  -H 'Content-Type: application/json' \\
  -d '{"lines": ["<eve json line>", "..."]}'

# Or pipe a batch from the EVE log file:
jq -c '.' /var/log/suricata/eve.json | head -100 | python3 -c "
import sys, json, requests
lines = sys.stdin.read().splitlines()
requests.post('https://<siem>:8000/api/v1/nids/ingest',
              json={'lines': lines}, verify=False)
print('Done')
"
""", language="bash")

    st.markdown("#### Demo — Inject Test Events")
    if st.button("Inject 10 Sample Events", key="nids_demo"):
        _inject_demo_events()
        st.success("Sample events injected. Refresh to see them.")


def _inject_demo_events():
    """Push synthetic EVE JSON events for demo/testing."""
    import json as _json
    now = datetime.utcnow()

    samples = [
        {"timestamp": now.isoformat(), "event_type": "alert",
         "src_ip": "198.51.100.42", "src_port": 54123,
         "dest_ip": "10.0.1.5", "dest_port": 22,
         "proto": "TCP",
         "alert": {"action": "allowed", "gid": 1, "signature_id": 2010937,
                   "rev": 3, "signature": "ET SCAN SSH Scan Detection",
                   "category": "Network Scan", "severity": 2}},
        {"timestamp": now.isoformat(), "event_type": "alert",
         "src_ip": "203.0.113.88", "src_port": 41900,
         "dest_ip": "10.0.1.10", "dest_port": 80,
         "proto": "TCP",
         "alert": {"action": "allowed", "gid": 1, "signature_id": 2019284,
                   "rev": 5, "signature": "ET WEB_SERVER SQL Injection Attempt",
                   "category": "Web Application Attack", "severity": 1}},
        {"timestamp": now.isoformat(), "event_type": "alert",
         "src_ip": "198.51.100.7", "src_port": 3372,
         "dest_ip": "10.0.1.20", "dest_port": 443,
         "proto": "TCP",
         "alert": {"action": "blocked", "gid": 1, "signature_id": 2014702,
                   "rev": 4, "signature": "ET MALWARE CobaltStrike Beacon Activity",
                   "category": "A Network Trojan was detected", "severity": 1}},
        {"timestamp": now.isoformat(), "event_type": "dns",
         "src_ip": "10.0.1.15", "src_port": 51234,
         "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "UDP",
         "dns": {"type": "query", "rrname": "malware-c2.dyndns.org", "rrtype": "A"}},
        {"timestamp": now.isoformat(), "event_type": "dns",
         "src_ip": "10.0.1.8", "src_port": 51235,
         "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "UDP",
         "dns": {"type": "query", "rrname": "update.microsoft.com", "rrtype": "A"}},
        {"timestamp": now.isoformat(), "event_type": "http",
         "src_ip": "10.0.1.15", "src_port": 49812,
         "dest_ip": "198.51.100.33", "dest_port": 80, "proto": "TCP",
         "http": {"hostname": "malware-c2.dyndns.org", "url": "/gate.php",
                  "http_method": "POST", "status": 200}},
        {"timestamp": now.isoformat(), "event_type": "tls",
         "src_ip": "10.0.1.22", "src_port": 49901,
         "dest_ip": "203.0.113.55", "dest_port": 443, "proto": "TCP",
         "tls": {"sni": "suspicious-c2.xyz", "version": "TLS 1.2"}},
        {"timestamp": now.isoformat(), "event_type": "ssh",
         "src_ip": "198.51.100.42", "src_port": 54200,
         "dest_ip": "10.0.1.5", "dest_port": 22, "proto": "TCP",
         "ssh": {"client": {"software_version": "libssh-0.9.3"}}},
        {"timestamp": now.isoformat(), "event_type": "alert",
         "src_ip": "203.0.113.99", "src_port": 6666,
         "dest_ip": "10.0.1.25", "dest_port": 4444,
         "proto": "TCP",
         "alert": {"action": "blocked", "gid": 1, "signature_id": 2003068,
                   "rev": 7, "signature": "ET TROJAN Metasploit Meterpreter Reverse Shell",
                   "category": "Trojan Activity", "severity": 1}},
        {"timestamp": now.isoformat(), "event_type": "alert",
         "src_ip": "10.0.0.0", "src_port": 0,
         "dest_ip": "10.0.1.30", "dest_port": 445,
         "proto": "TCP",
         "alert": {"action": "allowed", "gid": 1, "signature_id": 2027539,
                   "rev": 1, "signature": "ET SMB Possible ETERNALBLUE Probe",
                   "category": "Attempted Administrator Privilege Gain", "severity": 1}},
    ]

    lines = [_json.dumps(s) for s in samples]
    _post("/nids/ingest", json_body={"lines": lines})
