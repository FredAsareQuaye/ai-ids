"""
AI Autonomous Agent Dashboard
Shows real-time status, stats, recent AI verdicts and auto-blocked IPs.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import json
from datetime import datetime

BACKEND = BACKEND_BASE

# ── helpers ───────────────────────────────────────────────────────────────────

def _get(path: str):
    try:
        r = requests.get(f"{BACKEND}{path}", verify=False, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def _post(path: str):
    try:
        r = requests.post(f"{BACKEND}{path}", verify=False, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def _threat_color(level: str) -> str:
    return {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#eab308",
        "low":      "#22c55e",
    }.get((level or "").lower(), "#64748b")

def _conf_bar(conf: float) -> str:
    pct = int(conf * 100)
    color = "#ef4444" if pct >= 85 else "#f97316" if pct >= 70 else "#eab308" if pct >= 50 else "#22c55e"
    return (
        f'<div style="background:#1a2235;border-radius:4px;height:6px;width:100%;margin-top:4px">'
        f'<div style="background:{color};width:{pct}%;height:6px;border-radius:4px"></div></div>'
        f'<div style="font-size:10px;color:{color};margin-top:2px;text-align:right">{pct}%</div>'
    )


# ── main render ───────────────────────────────────────────────────────────────

def render_ai_agent_dashboard():
    # Inject CSS
    st.markdown("""
    <style>
    .agent-header{background:#0d1526;border:1px solid #1a2235;border-radius:12px;
        padding:20px 28px;margin-bottom:20px}
    .agent-title{font-size:22px;font-weight:700;color:#e2e8f0;letter-spacing:-.3px}
    .agent-sub{font-size:12px;color:#475569;margin-top:2px}
    .agent-badge-on{background:#052e16;color:#22c55e;border:1px solid #22c55e44;
        padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700}
    .agent-badge-off{background:#1c0a09;color:#ef4444;border:1px solid #ef444444;
        padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700}
    .kpi-card{background:#0d1526;border:1px solid #1a2235;border-radius:10px;
        padding:18px 20px;text-align:center}
    .kpi-val{font-size:28px;font-weight:800;letter-spacing:-.5px}
    .kpi-lbl{font-size:10px;color:#475569;text-transform:uppercase;font-weight:700;
        letter-spacing:.06em;margin-top:4px}
    .verdict-card{background:#0d1526;border:1px solid #1a2235;border-radius:10px;
        padding:16px 18px;margin-bottom:10px;border-left:4px solid}
    .v-msg{font-size:13px;color:#e2e8f0;margin-bottom:6px;font-weight:600}
    .v-meta{font-size:11px;color:#475569}
    .v-summary{font-size:12px;color:#94a3b8;margin-top:8px;line-height:1.6;
        background:#060d1b;padding:10px 12px;border-radius:6px}
    .v-actions li{font-size:12px;color:#cbd5e1;margin:3px 0}
    .section-head{font-size:11px;font-weight:700;text-transform:uppercase;
        letter-spacing:.08em;color:#475569;margin:20px 0 10px}
    .mitre-pill{display:inline-block;background:#1e1b4b;color:#a5b4fc;
        border:1px solid #3730a344;padding:2px 8px;border-radius:4px;
        font-size:10px;font-weight:700;margin-right:4px}
    .autoblock-pill{display:inline-block;background:#1c0a09;color:#ef4444;
        border:1px solid #ef444444;padding:2px 8px;border-radius:4px;
        font-size:10px;font-weight:700}
    </style>
    """, unsafe_allow_html=True)

    # ── header ────────────────────────────────────────────────────────────────
    status_data = _get("/api/v1/ai-agent/status")
    running = status_data.get("running", False)
    stats   = status_data.get("stats", {})

    badge_cls = "agent-badge-on" if running else "agent-badge-off"
    badge_txt = "ACTIVE" if running else "OFFLINE"
    mode_now  = "AFTER-HOURS" if _is_after_hours() else "OFFICE HOURS"
    mode_color = "#7c3aed" if _is_after_hours() else "#1ec8ff"

    st.markdown(f"""
    <div class="agent-header">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div>
          <div class="agent-title">AI Autonomous Agent</div>
          <div class="agent-sub">DeepSeek-powered 24/7 threat detection &amp; response engine</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center">
          <span class="{badge_cls}">{badge_txt}</span>
          <span style="background:#0d1526;color:{mode_color};border:1px solid {mode_color}44;
              padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700">
            {mode_now}
          </span>
        </div>
      </div>
      <div style="margin-top:10px;font-size:11px;color:#334155">
        Active since {stats.get('started_at','—')[:16]} UTC &nbsp;·&nbsp;
        Interval: every 2 minutes &nbsp;·&nbsp;
        Auto-block threshold: 85% confidence
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── manual trigger ────────────────────────────────────────────────────────
    col_btn, col_refresh, _ = st.columns([1, 1, 4])
    with col_btn:
        if st.button("Run Cycle Now", use_container_width=True):
            result = _post("/api/v1/ai-agent/trigger")
            if "error" in result:
                st.error(result["error"])
            else:
                st.success("Analysis cycle triggered")
                st.rerun()
    with col_refresh:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    # ── KPI row ───────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    kpis = [
        (c1, stats.get("cycles", 0),          "#1ec8ff", "Cycles Run"),
        (c2, stats.get("logs_analysed", 0),   "#1ec8ff", "Logs Analysed"),
        (c3, stats.get("threats_found", 0),   "#f97316", "Threats Found"),
        (c4, stats.get("auto_blocks", 0),     "#ef4444", "Auto-Blocked"),
        (c5, stats.get("alerts_sent", 0),     "#eab308", "Alerts Sent"),
    ]
    for col, val, color, label in kpis:
        with col:
            st.markdown(f"""
            <div class="kpi-card">
              <div class="kpi-val" style="color:{color}">{val}</div>
              <div class="kpi-lbl">{label}</div>
            </div>""", unsafe_allow_html=True)

    # ── blocked IPs ───────────────────────────────────────────────────────────
    blocked = stats.get("blocked_ips", [])
    if blocked:
        st.markdown('<div class="section-head">Auto-Blocked IPs</div>', unsafe_allow_html=True)
        pills = " ".join(
            f'<span class="autoblock-pill">{ip}</span>' for ip in blocked
        )
        st.markdown(f'<div style="margin-bottom:16px">{pills}</div>', unsafe_allow_html=True)

    # ── recent AI verdicts ────────────────────────────────────────────────────
    st.markdown('<div class="section-head">Recent AI Verdicts</div>', unsafe_allow_html=True)

    verdicts_raw = _get("/api/v1/ai-agent/verdicts?limit=30")
    if isinstance(verdicts_raw, dict) and "error" in verdicts_raw:
        st.error(f"Cannot reach backend: {verdicts_raw['error']}")
        return

    if not verdicts_raw:
        st.info("No AI-analysed logs yet. The agent runs every 2 minutes and will process incoming HIGH/CRITICAL events.")
        return

    # Filter controls
    col_sev, col_atk, _ = st.columns([1, 1, 2])
    with col_sev:
        sev_filter = st.selectbox("Threat Level", ["All", "Critical", "High", "Medium", "Low"], key="agent_sev_filter")
    with col_atk:
        search_txt = st.text_input("Search message / attack type", "", key="agent_search")

    for row in verdicts_raw:
        verdict = row.get("ai_analysis") or {}
        if isinstance(verdict, str):
            try:
                verdict = json.loads(verdict)
            except Exception:
                verdict = {}

        threat_lvl = verdict.get("threat_level", "unknown")
        attack_type = verdict.get("attack_type", "unknown")
        confidence  = float(verdict.get("confidence", 0))
        summary     = verdict.get("summary", "")
        actions     = verdict.get("immediate_actions", [])
        mitre_tac   = verdict.get("mitre_tactic", "")
        mitre_tech  = verdict.get("mitre_technique", "")
        src_ip      = verdict.get("source_ip", "")

        # Filters
        if sev_filter != "All" and threat_lvl.lower() != sev_filter.lower():
            continue
        msg = row.get("message", "")
        if search_txt and search_txt.lower() not in (msg + attack_type).lower():
            continue

        color = _threat_color(threat_lvl)
        ts    = row.get("timestamp", "")[:16].replace("T", " ")

        mitre_pills = ""
        if mitre_tac:
            mitre_pills += f'<span class="mitre-pill">{mitre_tac}</span>'
        if mitre_tech:
            mitre_pills += f'<span class="mitre-pill">{mitre_tech}</span>'

        actions_html = ""
        if actions:
            items = "".join(f"<li>{a}</li>" for a in actions[:3])
            actions_html = f'<ul class="v-actions" style="margin:6px 0 0 16px;padding:0">{items}</ul>'

        autoblock_pill = ""
        if verdict.get("auto_block_recommended"):
            autoblock_pill = '<span class="autoblock-pill" style="margin-left:8px">AUTO-BLOCK RECOMMENDED</span>'

        src_ip_html = f'<span style="color:#94a3b8;font-size:11px">IP: {src_ip}</span> &nbsp;' if src_ip else ""

        st.markdown(f"""
        <div class="verdict-card" style="border-left-color:{color}">
          <div class="v-msg">{msg[:120]}</div>
          <div class="v-meta">
            {src_ip_html}
            <span style="color:{color};font-weight:700;font-size:11px">{threat_lvl.upper()}</span>
            &nbsp;·&nbsp;{attack_type.replace('_',' ').title()}
            &nbsp;·&nbsp;{row.get('source','?')}
            &nbsp;·&nbsp;{ts}
            {autoblock_pill}
          </div>
          {mitre_pills}
          {_conf_bar(confidence)}
          {f'<div class="v-summary">{summary}</div>' if summary else ""}
          {actions_html}
        </div>
        """, unsafe_allow_html=True)


def _is_after_hours() -> bool:
    h = datetime.now().hour
    return h < 8 or h >= 18
