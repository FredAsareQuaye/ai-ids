"""
AI-IDS Security Operations Platform
Wazuh-inspired enterprise security dashboard
"""
import json
import os
import sys
import warnings
from datetime import datetime, timedelta
from collections import Counter

warnings.filterwarnings("ignore")

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(
    page_title="AI-IDS | Security Operations",
    layout="wide",
    initial_sidebar_state="expanded",
)

from components.enhanced_login import render_login_page, logout, get_current_user
from components.auth_manager import auth_manager
from components.user_management import render_user_management
from components.notification_system import render_notification_dashboard, render_live_log_monitor
from components.enhanced_detail_view import render_enhanced_detail_view
from components.ai_assistant import ai_assistant, render_ai_components
from components.ai_logs_overview import render_ai_logs_overview
from components.ai_vuln_test import AIVulnerabilityTester
from components.full_logs import render_full_logs
from components.scan_analyzer import ScanAnalyzer
from components.vuln_overview import render_vuln_overview
from components.vuln_scanner import VulnerabilityScanner
from components.timeline_view import render_timeline, render_agent_dashboard
from components.playbook_manager import render_playbook_manager
from components.whitelist_manager import render_whitelist_manager
from components.threat_hunter import render_threat_hunter
from components.geoip_map import render_geoip_map
from components.case_manager_ui import render_case_manager
from components.asset_inventory_ui import render_asset_inventory
from components.ueba_dashboard import render_ueba_dashboard
from components.threat_feeds_ui import render_threat_feeds
from components.dedup_ui import render_dedup_dashboard
from components.playbook_builder import render_playbook_builder
from components.compliance_ui import render_compliance_ui
from components.ransomware_tracker import render_ransomware_tracker
from components.network_ids_ui import render_network_ids
from components.ai_agent_dashboard import render_ai_agent_dashboard
from _pages.detailed_scan import render_detailed_scan
from _pages.sniper_scan import render_page as render_sniper_scan
from _pages.multi_scan import render_page as render_multi_scan
from _pages.scan_results import render_scan_results
from _pages.settings import render_settings
from utils.api import create_session

from config import BACKEND, BACKEND_BASE

BACKEND_URL_RAW = BACKEND_BASE


def _on_alert_click(log_id):
    st.session_state["selected_log_id"] = log_id
    st.session_state["view"] = "log_details"
    st.query_params["view"] = "log_details"


def _render_full_logs_wrapped():
    render_full_logs(create_session(), BACKEND, _on_alert_click)
VERIFY_SSL = False
_DARK = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font_color="#a8b4d4", margin=dict(l=10, r=10, t=30, b=10)
)


def main():
    # Read ?view= from URL query params (persists across hard refresh)
    url_view = st.query_params.get("view")
    if url_view:
        st.session_state.view = url_view
    elif "view" in st.session_state:
        # Keep current view but sync it back to URL
        st.query_params["view"] = st.session_state.view
    else:
        st.session_state.view = "overview"
        st.query_params["view"] = "overview"
    if "settings" not in st.session_state:
        st.session_state.settings = {}

    if not render_login_page():
        return

    user = get_current_user()
    apply_css()
    render_sidebar(user)
    render_content(user)


# ─────────────────────────────────────────────────────────────────────────────
# CSS — Wazuh-inspired dark navy
# ─────────────────────────────────────────────────────────────────────────────

def apply_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }

    /* ── Background ── */
    [data-testid="stAppViewContainer"] { background: #080d1c; }
    [data-testid="stSidebar"] {
        background: #060a17 !important;
        border-right: 1px solid #131d35 !important;
    }
    [data-testid="stSidebar"] * { color: #a8b4d4 !important; }
    .block-container { padding: 0 1.5rem 2rem 1.5rem !important; }
    [data-testid="stHeader"] { background: transparent !important; }

    /* ── Top header bar ── */
    .top-bar {
        background: #0c1225;
        border-bottom: 1px solid #131d35;
        padding: 10px 24px;
        display: flex; align-items: center;
        justify-content: space-between;
        gap: 16px; margin-bottom: 20px;
        border-radius: 0 0 6px 6px;
    }
    .top-bar-left { display: flex; align-items: center; gap: 16px; }
    .top-bar-breadcrumb { font-size: 0.78rem; color: #5a6a9a; }
    .top-bar-title { font-size: 1.05rem; font-weight: 600; color: #dfe5ef; }
    .top-bar-right { display: flex; align-items: center; gap: 12px; }
    .top-bar-user {
        font-size: 0.78rem; color: #8896c8;
        background: #131d35; border: 1px solid #1e2a50;
        border-radius: 4px; padding: 4px 10px;
    }
    .top-bar-time { font-size: 0.72rem; color: #5a6a9a; font-variant-numeric: tabular-nums; }

    /* ── Sidebar brand ── */
    .sb-logo {
        padding: 16px 14px 12px 14px;
        border-bottom: 1px solid #131d35;
        margin-bottom: 6px;
    }
    .sb-logo-name {
        font-size: 1.1rem; font-weight: 800; letter-spacing: .08em;
        background: linear-gradient(90deg, #1db8c2, #0075a8);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .sb-logo-sub { font-size: 0.6rem; color: #3a4a6a !important; letter-spacing: .1em; margin-top: 2px; }

    /* ── Sidebar user ── */
    .sb-user {
        margin: 4px 10px 6px 10px;
        background: #0c1225; border: 1px solid #131d35;
        border-radius: 5px; padding: 9px 12px;
    }
    .sb-user-name { font-size: 0.85rem; font-weight: 600; color: #dfe5ef !important; }
    .sb-user-sub { font-size: 0.68rem; color: #5a6a9a !important; margin-top: 2px; }
    .sb-role {
        display: inline-block; border-radius: 3px; margin-top: 4px;
        font-size: 0.58rem; font-weight: 700; padding: 1px 6px; letter-spacing: .06em;
    }
    .sb-online {
        display: inline-block; width: 6px; height: 6px;
        background: #1db8c2; border-radius: 50%;
        margin-right: 5px; vertical-align: middle;
        box-shadow: 0 0 5px #1db8c255;
    }

    /* ── Sidebar section label ── */
    .sb-sec {
        padding: 10px 14px 3px 14px;
        font-size: 0.58rem; font-weight: 700;
        color: #3a4a6a !important; letter-spacing: .14em;
        text-transform: uppercase;
    }

    /* ── Sidebar nav buttons ── */
    [data-testid="stSidebar"] .stButton > button {
        background: transparent !important;
        border: none !important;
        border-left: 2px solid transparent !important;
        border-radius: 0 4px 4px 0 !important;
        color: #7888b8 !important;
        text-align: left !important;
        font-size: 0.81rem !important;
        font-weight: 400 !important;
        padding: 6px 12px 6px 14px !important;
        width: 100% !important;
        transition: all 0.12s !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover {
        background: #0c1938 !important;
        color: #1db8c2 !important;
        border-left-color: #1db8c2 !important;
    }

    /* ── Main content buttons (outside sidebar) ── */
    .main .stButton > button {
        background: #0c1225 !important;
        border: 1px solid #1e2d3d !important;
        border-radius: 6px !important;
        color: #94a3b8 !important;
        font-size: 0.8rem !important;
        font-weight: 500 !important;
        padding: 6px 14px !important;
        transition: all 0.15s !important;
        text-align: center !important;
    }
    .main .stButton > button:hover {
        background: #101a33 !important;
        border-color: #1db8c2 !important;
        color: #1db8c2 !important;
    }

    hr { border-color: #131d35 !important; margin: 3px 0 !important; }

    /* ── KPI cards ── */
    .kpi {
        background: #0c1225;
        border: 1px solid #131d35;
        border-radius: 6px;
        padding: 18px 16px 14px 16px;
        position: relative;
    }
    .kpi-bar {
        position: absolute; top: 0; left: 0; right: 0; height: 3px;
        border-radius: 6px 6px 0 0;
    }
    .kpi-label {
        font-size: 0.65rem; text-transform: uppercase;
        letter-spacing: .12em; color: #5a6a9a; margin-bottom: 8px;
        font-weight: 600;
    }
    .kpi-value {
        font-size: 2.1rem; font-weight: 700; color: #dfe5ef;
        line-height: 1; font-variant-numeric: tabular-nums;
    }
    .kpi-sub { font-size: 0.68rem; color: #3a4a6a; margin-top: 5px; }
    .kpi-delta { font-size: 0.7rem; margin-top: 4px; }
    .delta-up   { color: #1db8c2; }
    .delta-down { color: #e7554b; }

    /* ── Module tiles ── */
    .module-tile {
        background: #0c1225;
        border: 1px solid #131d35;
        border-radius: 6px;
        padding: 16px;
        cursor: pointer;
        transition: all 0.18s;
        height: 100%;
    }
    .module-tile:hover {
        background: #101a33;
        border-color: #1db8c2;
        transform: translateY(-1px);
        box-shadow: 0 4px 20px rgba(29,184,194,0.1);
    }
    .tile-icon {
        width: 34px; height: 34px; border-radius: 6px;
        display: flex; align-items: center; justify-content: center;
        font-size: 1rem; margin-bottom: 10px; font-weight: 700;
        font-family: monospace;
    }
    .tile-name { font-size: 0.88rem; font-weight: 600; color: #dfe5ef; margin-bottom: 4px; }
    .tile-desc { font-size: 0.7rem; color: #5a6a9a; line-height: 1.4; }
    .tile-count { font-size: 0.72rem; color: #1db8c2; margin-top: 8px; font-weight: 600; }

    /* ── Section heading ── */
    .sec-heading {
        font-size: 0.63rem; text-transform: uppercase; letter-spacing: .14em;
        color: #3a4a6a; padding: 4px 0 8px 0; font-weight: 700;
        border-bottom: 1px solid #131d35; margin-bottom: 12px;
    }

    /* ── Alert rows ── */
    .alert-row {
        display: flex; align-items: flex-start; gap: 10px;
        padding: 9px 0; border-bottom: 1px solid #0c1225;
    }
    .sev-badge {
        font-size: 0.58rem; font-weight: 700; padding: 2px 6px;
        border-radius: 3px; white-space: nowrap; margin-top: 1px;
        letter-spacing: .06em; text-transform: uppercase;
        font-variant: small-caps;
    }
    .sev-critical { background: #2a0a0a; color: #e7554b; border: 1px solid #e7554b44; }
    .sev-high     { background: #1f1200; color: #f5a623; border: 1px solid #f5a62344; }
    .sev-medium   { background: #1a1600; color: #d4c000; border: 1px solid #d4c00044; }
    .sev-low      { background: #061510; color: #54c57d; border: 1px solid #54c57d44; }
    .sev-info     { background: #061626; color: #2eb5e6; border: 1px solid #2eb5e644; }
    .alert-msg  { color: #c8d4e8; font-size: 0.8rem; flex: 1; min-width: 0; }
    .alert-src  { color: #5a6a9a; font-size: 0.7rem; margin-top: 2px; }
    .alert-ts   { color: #3a4a6a; font-size: 0.68rem; white-space: nowrap; font-variant-numeric: tabular-nums; }

    /* ── Agent status ── */
    .agent-card {
        background: #0c1225; border: 1px solid #131d35;
        border-radius: 5px; padding: 10px 12px; margin-bottom: 5px;
        display: flex; align-items: center; gap: 10px;
    }
    .agent-status-dot {
        width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
    }
    .dot-online  { background: #1db8c2; box-shadow: 0 0 6px #1db8c255; }
    .dot-offline { background: #e7554b; }
    .dot-never   { background: #3a4a6a; }
    .agent-name { font-size: 0.82rem; font-weight: 600; color: #dfe5ef; }
    .agent-meta { font-size: 0.68rem; color: #5a6a9a; margin-top: 2px; }

    /* ── Page header ── */
    .page-hdr {
        background: #0c1225;
        border-left: 3px solid #1db8c2;
        border-radius: 0 5px 5px 0;
        padding: 12px 18px;
        margin-bottom: 20px;
    }
    .page-hdr-title { font-size: 1.05rem; font-weight: 700; color: #dfe5ef; }
    .page-hdr-sub { font-size: 0.75rem; color: #5a6a9a; margin-top: 3px; }

    /* ── Tabs ── */
    [data-testid="stTabs"] button {
        color: #5a6a9a !important; font-size: 0.8rem !important;
        font-weight: 500 !important;
    }
    [data-testid="stTabs"] button[aria-selected="true"] {
        color: #1db8c2 !important;
        border-bottom: 2px solid #1db8c2 !important;
    }

    /* ── Metrics ── */
    [data-testid="stMetricValue"] { color: #dfe5ef !important; }
    [data-testid="stMetricLabel"] { color: #5a6a9a !important; font-size: 0.72rem !important; }

    /* ── Inputs / selects ── */
    [data-testid="stTextInput"] input,
    [data-testid="stTextArea"] textarea {
        background: #0c1225 !important;
        border-color: #131d35 !important;
        color: #dfe5ef !important;
    }
    </style>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────

def _go(label, view, key=None):
    if st.button(label, use_container_width=True, key=key or f"nav_{view}"):
        st.session_state.view = view
        st.query_params["view"] = view
        st.rerun()



def render_log_upload():
    """Upload a log file (JSON/CSV/LOG/TXT) to the backend for analysis."""
    st.markdown(
        '<div class="page-hdr">'
        '<div class="page-hdr-title">📤 Upload Log File</div>'
        '<div class="page-hdr-sub">Upload a security log file (.json, .csv, .log, .txt) for batch analysis</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "Choose a log file",
        type=["json", "log", "csv", "txt"],
        help="Upload a .json, .csv, .log, or .txt file containing security logs.",
    )

    if uploaded is not None:
        content = uploaded.read()

        name_lower = uploaded.name.lower()
        if name_lower.endswith(".json"):
            try:
                parsed = json.loads(content)
                entries = parsed if isinstance(parsed, list) else [parsed]
                st.success(f"File parsed: **{len(entries)}** JSON log entries detected.")
                with st.expander("Preview (first 5 entries)", expanded=False):
                    for entry in entries[:5]:
                        st.json(entry)
            except json.JSONDecodeError:
                st.error("File has .json extension but is not valid JSON.")
                return
        else:
            lines = content.decode("utf-8", errors="replace").splitlines()
            non_empty = [l for l in lines if l.strip()]
            st.success(f"File loaded: **{len(non_empty)}** lines detected ({uploaded.name})")
            with st.expander("Preview (first 5 lines)", expanded=False):
                for line in non_empty[:5]:
                    st.code(line)

        if st.button("Upload & Analyse", type="primary", key="btn_upload_logs"):
            with st.spinner("Sending to backend for analysis..."):
                try:
                    url = f"{BACKEND_BASE}/api/v1/logs/upload"
                    ctype = "application/json" if name_lower.endswith(".json") else "text/plain"
                    resp = requests.post(
                        url,
                        files={"file": (uploaded.name, content, ctype)},
                        verify=False,
                        timeout=3600,
                    )
                    if resp.status_code == 200:
                        result = resp.json()
                        st.success(
                            f"Upload complete — **{result.get('ingested', 0)}** logs ingested, "
                            f"**{result.get('skipped', 0)}** skipped."
                        )
                        if result.get("errors"):
                            with st.expander(f"Errors ({len(result['errors'])})"):
                                for err in result["errors"]:
                                    st.write(f"Entry #{err['index']}: {err['error']}")
                    else:
                        st.error(f"Backend error ({resp.status_code}): {resp.text[:300]}")
                except requests.exceptions.ConnectionError:
                    st.error("Cannot reach backend. Is the backend container running?")
                except Exception as e:
                    st.error(f"Upload failed: {e}")


def render_sidebar(user):
    with st.sidebar:
        # Logo
        st.markdown("""
        <div class="sb-logo">
          <div class="sb-logo-name">AI-IDS</div>
          <div class="sb-logo-sub">SECURITY OPERATIONS PLATFORM</div>
        </div>
        """, unsafe_allow_html=True)

        # User
        role_color = "#f5a623" if user["role"] == "admin" else "#1db8c2"
        role_bg    = "#1f1200" if user["role"] == "admin" else "#041820"
        st.markdown(f"""
        <div class="sb-user">
          <div class="sb-user-name">
            <span class="sb-online"></span>{user['username']}
          </div>
          <div class="sb-user-sub">{user.get('email','—')}</div>
          <span class="sb-role" style="background:{role_bg};color:{role_color};
                border:1px solid {role_color}44;">
            {user['role'].upper()}
          </span>
        </div>
        """, unsafe_allow_html=True)

        st.divider()

        # OVERVIEW
        _go("Overview", "overview")
        _go("Log Events", "logs_overview")
        _go("Full Logs", "full_logs")

        st.divider()

        # AI AGENT
        st.markdown('<div class="sb-sec">AI Autonomous Agent</div>', unsafe_allow_html=True)
        _go("AI Agent Dashboard", "ai_agent")
        _go("AI Log Analysis", "ai_analysis")

        # THREAT DETECTION
        st.markdown('<div class="sb-sec">Threat Detection</div>', unsafe_allow_html=True)
        _go("Security Events Timeline", "timeline")
        _go("MITRE ATT&CK", "correlations")
        _go("Anomaly Detection (UEBA)", "ueba")
        _go("Alert Deduplication", "dedup")
        _go("Ransomware Tracker", "ransomware")
        _go("Network Threat Sensor", "nids")

        st.divider()

        # THREAT INTELLIGENCE
        st.markdown('<div class="sb-sec">Threat Intelligence</div>', unsafe_allow_html=True)
        _go("Threat Hunter", "threat_hunter")
        _go("GeoIP Attack Map", "geoip_map")
        _go("IOC Feed Management", "threat_feeds")

        st.divider()

        # VULNERABILITY
        st.markdown('<div class="sb-sec">Vulnerability</div>', unsafe_allow_html=True)
        _go("Vulnerability Scanner", "vuln_scanner")
        _go("Sniper Scan", "sniper_scan")
        _go("Multi-Target Scan", "multi_scan")
        _go("Scan Results", "scan_results")

        st.divider()

        # INCIDENT RESPONSE
        st.markdown('<div class="sb-sec">Incident Response</div>', unsafe_allow_html=True)
        _go("Case Management", "cases")
        _go("Playbooks", "playbooks")
        _go("Playbook Builder", "playbook_builder")
        _go("Whitelist", "whitelist")

        st.divider()

        # COMPLIANCE
        st.markdown('<div class="sb-sec">Compliance</div>', unsafe_allow_html=True)
        _go("Compliance Reports", "compliance")
        _go("Asset Inventory", "assets")
        _go("Connected Agents", "agents")

        # MANAGEMENT
        st.divider()
        st.markdown('<div class="sb-sec">Management</div>', unsafe_allow_html=True)
        if user["role"] == "admin":
            _go("User Management", "user_management")
            _go("Live Monitor", "live_monitor")
        _go("Notifications", "notifications")
        _go("Settings", "settings")
        _go("Upload Logs", "upload_logs")

        st.divider()
        if st.button("Sign Out", use_container_width=True, key="signout"):
            logout()


# ─────────────────────────────────────────────────────────────────────────────
# Content router
# ─────────────────────────────────────────────────────────────────────────────

def render_content(user):
    view = st.session_state.get("view", "overview")
    try:
        ROUTES = {
            "overview":        lambda: render_overview(user),
            "logs_overview":   render_ai_logs_overview,
            "full_logs":       lambda: _render_full_logs_wrapped(),
            "vuln_scanner":    render_vuln_overview,
            "vuln_overview":   render_vuln_overview,
            "notifications":   render_notification_dashboard,
            "sniper_scan":     render_sniper_scan,
            "multi_scan":      render_multi_scan,
            "scan_results":    render_scan_results,
            "live_monitor":    render_live_log_monitor,
            "settings":        render_settings,
            "timeline":        render_timeline,
            "correlations":    render_timeline,
            "agents":          render_agent_dashboard,
            "playbooks":       render_playbook_manager,
            "whitelist":       render_whitelist_manager,
            "threat_hunter":   render_threat_hunter,
            "geoip_map":       render_geoip_map,
            "cases":           render_case_manager,
            "assets":          render_asset_inventory,
            "ueba":            render_ueba_dashboard,
            "threat_feeds":    render_threat_feeds,
            "dedup":           render_dedup_dashboard,
            "playbook_builder": render_playbook_builder,
            "compliance":      render_compliance_ui,
            "ransomware":      render_ransomware_tracker,
            "nids":            render_network_ids,
            "ai_agent":        render_ai_agent_dashboard,
            "ai_analysis":     render_ai_logs_overview,
            "upload_logs":     render_log_upload,
        }
        if view == "user_management" and user["role"] == "admin":
            render_user_management()
        elif view == "log_details":
            log_id = st.session_state.get("selected_log_id")
            if log_id:
                render_enhanced_detail_view(log_id=log_id)
            else:
                st.session_state.view = "overview"
                st.query_params["view"] = "overview"
                st.rerun()
        elif view in ROUTES:
            ROUTES[view]()
        else:
            st.session_state.view = "overview"
            st.query_params["view"] = "overview"
            st.rerun()
    except Exception as e:
        st.error(f"Render error: {e}")
        import traceback; st.code(traceback.format_exc(), language="text")


# ─────────────────────────────────────────────────────────────────────────────
# Overview Dashboard (Wazuh-style)
# ─────────────────────────────────────────────────────────────────────────────

def _api(path, params=None, timeout=30):
    try:
        import time as _time
        p = dict(params or {})
        p["_t"] = int(_time.time())
        r = requests.get(f"{BACKEND}{path}", params=p, verify=VERIFY_SSL, timeout=timeout)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def render_overview(user):
    now = datetime.now()

    # Top bar
    st.markdown(f"""
    <div class="top-bar">
      <div class="top-bar-left">
        <div>
          <div class="top-bar-breadcrumb">Security Operations</div>
          <div class="top-bar-title">Overview Dashboard</div>
        </div>
      </div>
      <div class="top-bar-right">
        <span class="top-bar-time">{now.strftime('%d %b %Y  %H:%M:%S')}</span>
        <span class="top-bar-user">
          <span class="sb-online"></span>{user['username']} &nbsp;·&nbsp; {user['role'].upper()}
        </span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Fetch all data ────────────────────────────────────────────────────────
    api_stats    = _api("/stats")          or {}
    case_stats   = _api("/cases/stats")   or {}
    ioc_data     = _api("/feeds/ioc-count") or {}
    dedup_stats  = _api("/dedup/stats")   or {}
    agents_raw   = _api("/agents")        or []
    threats_raw  = _api("/threats", params={"limit": 500}) or []
    corr_raw     = _api("/correlations", params={"hours": 24}) or []

    # normalise severity
    events = []
    for t in threats_raw:
        sev = str(t.get("severity", "INFO")).upper()
        t["severity"] = sev
        events.append(t)

    total_events  = api_stats.get("total", len(events))
    crit_count    = api_stats.get("critical", sum(1 for e in events if e["severity"] == "CRITICAL"))
    high_count    = api_stats.get("high", sum(1 for e in events if e["severity"] == "HIGH"))
    open_cases    = case_stats.get("by_status", {}).get("open", 0)
    invest_cases  = case_stats.get("by_status", {}).get("investigating", 0)
    total_cases   = case_stats.get("total", 0)
    ioc_count     = ioc_data.get("ioc_count", 0)
    noise_reduced = dedup_stats.get("total_suppressed", 0)
    active_agents = sum(1 for a in agents_raw if a.get("is_active"))
    unack_corr    = sum(1 for c in corr_raw if not c.get("acknowledged"))

    # ── KPI row ───────────────────────────────────────────────────────────────
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    kpis = [
        (k1, "#1db8c2", "Total Events",     f"{total_events:,}",   "all time"),
        (k2, "#e7554b", "Critical Alerts",  f"{crit_count:,}",     "last 24 hours"),
        (k3, "#f5a623", "High Severity",    f"{high_count:,}",     "last 24 hours"),
        (k4, "#1db8c2", "Active Agents",    str(active_agents),    "online now"),
        (k5, "#9b6dff", "Open Cases",       str(open_cases + invest_cases), "need attention"),
        (k6, "#54c57d", "IOC Indicators",   f"{ioc_count:,}",     "threat feeds"),
    ]
    for col, color, label, value, sub in kpis:
        with col:
            st.markdown(f"""
            <div class="kpi">
              <div class="kpi-bar" style="background:{color};"></div>
              <div class="kpi-label">{label}</div>
              <div class="kpi-value">{value}</div>
              <div class="kpi-sub">{sub}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts row ────────────────────────────────────────────────────────────
    chart_left, chart_right = st.columns([3, 2])

    with chart_left:
        st.markdown('<div class="sec-heading">Security Events — Last 24 Hours</div>',
                    unsafe_allow_html=True)
        _render_events_timeline(events)

    with chart_right:
        st.markdown('<div class="sec-heading">Events by Severity</div>',
                    unsafe_allow_html=True)
        _render_severity_donut(events)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Module tiles + agent panel ─────────────────────────────────────────────
    tiles_col, agent_col = st.columns([3, 1])

    with tiles_col:
        st.markdown('<div class="sec-heading">Security Modules</div>', unsafe_allow_html=True)
        _render_module_tiles(total_events, crit_count, ioc_count,
                             total_cases, noise_reduced, unack_corr)

    with agent_col:
        st.markdown('<div class="sec-heading">Agent Status</div>', unsafe_allow_html=True)
        _render_agent_panel(agents_raw)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── MITRE + Recent alerts ─────────────────────────────────────────────────
    mitre_col, feed_col = st.columns([1, 2])

    with mitre_col:
        st.markdown('<div class="sec-heading">MITRE ATT&CK Detections</div>',
                    unsafe_allow_html=True)
        _render_mitre_panel(corr_raw)

    with feed_col:
        st.markdown('<div class="sec-heading">Recent Security Alerts</div>',
                    unsafe_allow_html=True)
        _render_alert_feed(events)


# ── Charts ────────────────────────────────────────────────────────────────────

def _render_events_timeline(events):
    if not events:
        st.info("No event data available.")
        return

    df = pd.DataFrame(events)
    df["_ts"] = pd.to_datetime(df.get("timestamp", pd.Series(dtype=str)),
                               errors="coerce", utc=False)
    cutoff = pd.Timestamp.now() - pd.Timedelta(hours=24)
    df24 = df[df["_ts"] >= cutoff].copy()
    if df24.empty:
        df24 = df.copy()   # fall back to all data for demo

    df24["hour"] = df24["_ts"].dt.floor("h")
    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    SEV_COLORS = {
        "CRITICAL": "#e7554b", "HIGH": "#f5a623",
        "MEDIUM": "#d4c000", "LOW": "#54c57d", "INFO": "#2eb5e6",
    }
    SEV_FILL = {
        "CRITICAL": "rgba(231,85,75,0.5)",  "HIGH": "rgba(245,166,35,0.5)",
        "MEDIUM":   "rgba(212,192,0,0.5)",  "LOW":  "rgba(84,197,125,0.5)",
        "INFO":     "rgba(46,181,230,0.5)",
    }

    agg = (df24.groupby(["hour", "severity"])
               .size()
               .reset_index(name="count"))

    fig = go.Figure()
    for sev in SEV_ORDER:
        d = agg[agg["severity"] == sev]
        if d.empty:
            continue
        fig.add_trace(go.Scatter(
            x=d["hour"], y=d["count"],
            name=sev, stackgroup="one",
            line=dict(width=0),
            fillcolor=SEV_FILL.get(sev, "rgba(46,181,230,0.5)"),
            hovertemplate=f"<b>{sev}</b>: %{{y}}<extra></extra>",
        ))

    fig.update_layout(
        **_DARK,
        height=220,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.3,
                    font=dict(size=10, color="#5a6a9a")),
        xaxis=dict(gridcolor="#131d35", tickfont=dict(size=10)),
        yaxis=dict(gridcolor="#131d35", tickfont=dict(size=10)),
        hovermode="x unified",
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_severity_donut(events):
    if not events:
        st.info("No data.")
        return

    counts = Counter(e["severity"] for e in events)
    labels  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    values  = [counts.get(l, 0) for l in labels]
    colors  = ["#e7554b", "#f5a623", "#d4c000", "#54c57d", "#2eb5e6"]

    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        hole=0.62,
        marker=dict(colors=colors, line=dict(color="#080d1c", width=2)),
        textfont=dict(size=11, color="#dfe5ef"),
        hovertemplate="<b>%{label}</b>: %{value}<extra></extra>",
    ))
    total = sum(values)
    fig.add_annotation(
        text=f"<b>{total:,}</b><br><span style='font-size:10px'>total</span>",
        x=0.5, y=0.5, showarrow=False,
        font=dict(size=16, color="#dfe5ef"),
    )
    fig.update_layout(
        **_DARK, height=220,
        showlegend=True,
        legend=dict(orientation="v", x=1.02, y=0.5,
                    font=dict(size=10, color="#5a6a9a")),
    )
    st.plotly_chart(fig, use_container_width=True)


# ── Module tiles ──────────────────────────────────────────────────────────────

def _tile(view, icon, color, name, desc, stat):
    clicked = st.button(
        f"{name}",
        key=f"tile_{view}",
        use_container_width=True,
        help=desc,
    )
    if clicked:
        st.session_state.view = view
        st.rerun()
    st.markdown(f"""
    <div class="module-tile" onclick="">
      <div class="tile-icon" style="background:{color}22;color:{color};">{icon}</div>
      <div class="tile-name">{name}</div>
      <div class="tile-desc">{desc}</div>
      <div class="tile-count">{stat}</div>
    </div>
    """, unsafe_allow_html=True)


def _render_module_tiles(total_events, crit, iocs, cases, noise, corr):
    TILES = [
        ("timeline",        "SE",  "#2eb5e6", "Security Events",
         "Timeline scatter, heatmap, source breakdown",
         f"{total_events:,} events"),
        ("correlations",    "MA",  "#9b6dff", "MITRE ATT&CK",
         "Sliding-window rule-based correlation engine",
         f"{corr} unacknowledged"),
        ("ueba",            "UE",  "#f5a623", "Behavior Analytics",
         "Per-user baseline, anomaly scoring, risk rank",
         "UEBA active"),
        ("threat_hunter",   "TH",  "#1db8c2", "Threat Hunter",
         "Ad-hoc search: time, IP, severity, regex",
         "Search all logs"),
        ("geoip_map",       "GI",  "#54c57d", "GeoIP Attack Map",
         "IP geolocation — scatter world map",
         "IP enrichment live"),
        ("threat_feeds",    "TI",  "#e7554b", "IOC Feeds",
         "Feodo Tracker · URLhaus · Emerging Threats",
         f"{iocs:,} IOCs loaded"),
        ("cases",           "CM",  "#f5a623", "Case Management",
         "Incidents from detection to resolution",
         f"{cases} total cases"),
        ("playbooks",       "IR",  "#9b6dff", "Incident Response",
         "Automated playbooks: block, notify, snapshot",
         "Playbooks active"),
        ("dedup",           "DD",  "#2eb5e6", "Deduplication",
         "Signature-based alert grouping & suppression",
         f"{noise:,} events suppressed"),
        ("compliance",      "CL",  "#54c57d", "Compliance",
         "PCI-DSS v4 · ISO 27001:2022 · SOC 2",
         "PDF reports available"),
        ("assets",          "AI",  "#1db8c2", "Asset Inventory",
         "Host registry with criticality-based boost",
         "Risk scores live"),
        ("vuln_scanner",    "VS",  "#e7554b", "Vulnerability Scanner",
         "Network & host-based vulnerability assessment",
         "Scan on demand"),
        ("ransomware",      "RW",  "#ff4444", "Ransomware Tracker",
         "Extension signatures · VSS deletion · Command patterns",
         "Live detection"),
        ("nids",            "NS",  "#58a6ff", "Network Threat Sensor",
         "IDS alerts · Protocol telemetry · DNS · HTTP · MITRE",
         "Sensor active"),
    ]

    rows = [TILES[i:i+4] for i in range(0, len(TILES), 4)]
    for row in rows:
        cols = st.columns(len(row))
        for col, (view, icon, color, name, desc, stat) in zip(cols, row):
            with col:
                st.markdown(
                    f'<div class="module-tile" style="margin-bottom:6px;">'
                    f'<div class="tile-icon" style="background:{color}22;color:{color}">{icon}</div>'
                    f'<div class="tile-name">{name}</div>'
                    f'<div class="tile-desc">{desc}</div>'
                    f'<div class="tile-count">{stat}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                if st.button(f"Open {name}", key=f"tile_{view}", use_container_width=True):
                    st.session_state.view = view
                    st.query_params["view"] = view
                    st.rerun()


# ── Agent panel ───────────────────────────────────────────────────────────────

def _render_agent_panel(agents_raw):
    if not agents_raw:
        st.markdown('<div style="color:#3a4a6a;font-size:0.8rem;">No agents registered.</div>',
                    unsafe_allow_html=True)
        if st.button("View Agents", key="goto_agents_dash"):
            st.session_state.view = "agents"
            st.query_params["view"] = "agents"
            st.rerun()
        return

    now = datetime.utcnow()
    for a in agents_raw[:8]:
        last_seen = a.get("last_seen") or ""
        try:
            delta = (now - datetime.fromisoformat(last_seen)).total_seconds()
            online = delta < 120
            last_str = f"{int(delta//60)}m ago" if delta < 3600 else "offline"
        except Exception:
            online = a.get("is_active", False)
            last_str = "—"

        dot_cls = "dot-online" if online else "dot-offline"
        platform = (a.get("platform") or "Linux")[:20]
        st.markdown(f"""
        <div class="agent-card">
          <div class="agent-status-dot {dot_cls}"></div>
          <div style="flex:1;min-width:0;">
            <div class="agent-name">{a.get('hostname','?')}</div>
            <div class="agent-meta">{platform} &nbsp;·&nbsp; {last_str}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    online_n  = sum(1 for a in agents_raw if a.get("is_active"))
    offline_n = len(agents_raw) - online_n
    st.markdown(f"""
    <div style="font-size:0.68rem;color:#3a4a6a;margin-top:6px;padding:0 4px;">
      <span style="color:#1db8c2;">{online_n} active</span>
      &nbsp;·&nbsp;
      <span style="color:#e7554b;">{offline_n} offline</span>
      &nbsp;·&nbsp; {len(agents_raw)} total
    </div>
    """, unsafe_allow_html=True)

    if st.button("Manage Agents", key="goto_agents_main"):
        st.session_state.view = "agents"
        st.query_params["view"] = "agents"
        st.rerun()


# ── MITRE panel ───────────────────────────────────────────────────────────────

def _render_mitre_panel(corr_raw):
    if not corr_raw:
        st.markdown('<div style="color:#3a4a6a;font-size:0.8rem;">No correlations in last 24h.</div>',
                    unsafe_allow_html=True)
        return

    tactic_counts = Counter(c.get("mitre_tactic", "Unknown") for c in corr_raw)
    top_tactics = tactic_counts.most_common(8)

    max_val = max(v for _, v in top_tactics) if top_tactics else 1
    for tactic, count in top_tactics:
        pct = count / max_val * 100
        acked = sum(1 for c in corr_raw if c.get("mitre_tactic") == tactic
                    and c.get("acknowledged"))
        unack = count - acked
        color = "#e7554b" if unack > 0 else "#54c57d"
        st.markdown(f"""
        <div style="margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
            <span style="font-size:0.75rem;color:#c8d4e8;">{tactic}</span>
            <span style="font-size:0.72rem;color:{color};font-weight:600;">{count}</span>
          </div>
          <div style="background:#0c1225;border-radius:2px;height:4px;overflow:hidden;">
            <div style="background:{color};width:{pct:.0f}%;height:100%;border-radius:2px;"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    if st.button("View All Correlations", key="goto_corr"):
        st.session_state.view = "correlations"
        st.query_params["view"] = "correlations"
        st.rerun()


# ── Alert feed ────────────────────────────────────────────────────────────────

def _render_alert_feed(events):
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sev_cls   = {
        "CRITICAL": "sev-critical", "HIGH": "sev-high",
        "MEDIUM": "sev-medium", "LOW": "sev-low", "INFO": "sev-info",
    }

    recent = sorted(
        events,
        key=lambda e: (SEV_ORDER.get(e.get("severity", "INFO"), 9),
                       str(e.get("timestamp", ""))),
    )[:20]

    for e in recent:
        sev = e.get("severity", "INFO")
        msg = str(e.get("message", ""))[:90]
        src = str(e.get("source", "—"))[:35]
        ts  = str(e.get("timestamp", ""))[:16]
        cls = sev_cls.get(sev, "sev-info")
        st.markdown(f"""
        <div class="alert-row">
          <span class="sev-badge {cls}">{sev}</span>
          <div style="flex:1;min-width:0;">
            <div class="alert-msg"
                 style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{msg}</div>
            <div class="alert-src">{src}</div>
          </div>
          <div class="alert-ts">{ts}</div>
        </div>
        """, unsafe_allow_html=True)

    if st.button("View All Alerts", key="goto_full_logs"):
        st.session_state.view = "full_logs"
        st.query_params["view"] = "full_logs"
        st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# Report generator (unchanged logic, cleaner trigger)
# ─────────────────────────────────────────────────────────────────────────────

def generate_system_report(user):
    import sqlite3
    from pathlib import Path
    with st.spinner("Generating report…"):
        try:
            db_path = Path(__file__).parent.parent / "data" / "siem.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            def sq(sql):
                try:
                    cursor.execute(sql)
                    return cursor.fetchone()[0] or 0
                except Exception:
                    return 0

            data = {
                "generated_by": user["username"],
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_logs": sq("SELECT COUNT(*) FROM logs"),
                "critical": sq("SELECT COUNT(*) FROM logs WHERE UPPER(severity)='CRITICAL'"),
                "high": sq("SELECT COUNT(*) FROM logs WHERE UPPER(severity)='HIGH'"),
                "medium": sq("SELECT COUNT(*) FROM logs WHERE UPPER(severity)='MEDIUM'"),
                "low": sq("SELECT COUNT(*) FROM logs WHERE UPPER(severity)='LOW'"),
            }
            conn.close()

            st.download_button("Download JSON Report",
                               json.dumps(data, indent=2),
                               "siem_report.json", "application/json")
        except Exception as e:
            st.error(f"Report error: {e}")


if __name__ == "__main__":
    main()
