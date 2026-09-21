"""
Threat Hunter — ad-hoc search across all SIEM logs.
Supports time range, IP/source, severity, and regex message filters.
Allows saving named searches for quick re-use.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import plotly.graph_objects as go
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

BACKEND = BACKEND
VERIFY_SSL = False
SAVED_SEARCHES_FILE = Path(__file__).parent.parent.parent / "data" / "saved_searches.json"

SEVERITY_COLORS = {
    "CRITICAL": "#ff6b6b",
    "HIGH":     "#f78166",
    "MEDIUM":   "#e3b341",
    "LOW":      "#56d364",
    "INFO":     "#79c0ff",
}

_DARK = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0d1117",
             font_color="#c9d1d9", margin=dict(l=10, r=10, t=30, b=10))


def _load_saved():
    try:
        if SAVED_SEARCHES_FILE.exists():
            return json.loads(SAVED_SEARCHES_FILE.read_text())
    except Exception:
        pass
    return []


def _save_searches(searches):
    SAVED_SEARCHES_FILE.parent.mkdir(parents=True, exist_ok=True)
    SAVED_SEARCHES_FILE.write_text(json.dumps(searches, indent=2))


def render_threat_hunter():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Threat Hunter
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Search all ingested logs with advanced filters. Results can be linked
        directly to investigation cases.
      </div>
    </div>
    """, unsafe_allow_html=True)

    saved = _load_saved()

    # Saved searches sidebar strip
    if saved:
        with st.expander(f"Saved Searches ({len(saved)})", expanded=False):
            names = [s["name"] for s in saved]
            chosen = st.selectbox("Load search", ["— select —"] + names, key="hunter_load")
            if chosen != "— select —":
                s = next((x for x in saved if x["name"] == chosen), None)
                if s:
                    for k, v in s.get("params", {}).items():
                        st.session_state[f"hunt_{k}"] = v
                    st.rerun()

            # Delete saved search
            del_name = st.selectbox("Delete search", ["— select —"] + names, key="hunter_del")
            if del_name != "— select —":
                if st.button("Delete", key="del_saved_search"):
                    searches = [s for s in saved if s["name"] != del_name]
                    _save_searches(searches)
                    st.rerun()

    # Search form
    st.markdown("""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                padding:16px 18px;margin-bottom:14px;">
    """, unsafe_allow_html=True)

    with st.form("hunt_form"):
        c1, c2 = st.columns(2)
        with c1:
            time_range = st.selectbox(
                "Time range",
                ["Last 1 hour", "Last 6 hours", "Last 24 hours",
                 "Last 7 days", "Last 30 days", "All time"],
                key="hunt_time_range",
            )
            severity_filter = st.multiselect(
                "Severity",
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                key="hunt_severity",
            )
        with c2:
            source_filter = st.text_input(
                "Source / IP contains",
                key="hunt_source",
                placeholder="192.168.1.0 or web-server",
            )
            message_filter = st.text_input(
                "Message regex",
                key="hunt_message",
                placeholder="failed login|brute.force",
            )

        c3, c4, c5 = st.columns([2, 2, 1])
        with c3:
            submitted = st.form_submit_button("Search", type="primary", use_container_width=True)
        with c4:
            save_name = st.text_input("Save as…", key="hunt_save_name",
                                      placeholder="My saved search")
        with c5:
            save_btn = st.form_submit_button("Save", use_container_width=True)

        if save_btn and save_name:
            searches = _load_saved()
            searches = [s for s in searches if s["name"] != save_name]
            searches.append({
                "name": save_name,
                "params": {
                    "time_range": time_range,
                    "severity": severity_filter,
                    "source": source_filter,
                    "message": message_filter,
                },
            })
            _save_searches(searches)
            st.success(f"Search '{save_name}' saved.")

    st.markdown("</div>", unsafe_allow_html=True)

    if submitted:
        results = _run_search(time_range, severity_filter, source_filter, message_filter)
        _render_results(results)
    elif "hunt_results" in st.session_state:
        _render_results(st.session_state["hunt_results"])
    else:
        st.markdown("""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                    padding:40px;text-align:center;margin-top:8px;">
          <div style="font-size:3rem;margin-bottom:12px;">🔎</div>
          <div style="color:#58a6ff;font-size:1rem;font-weight:600;">
            Set your filters and click Search
          </div>
          <div style="color:#6e7681;margin-top:8px;font-size:.85rem;">
            Searches across all ingested logs. Use regex for message matching.
          </div>
        </div>
        """, unsafe_allow_html=True)


def _parse_time_range(label: str) -> datetime:
    mapping = {
        "Last 1 hour":  timedelta(hours=1),
        "Last 6 hours": timedelta(hours=6),
        "Last 24 hours": timedelta(hours=24),
        "Last 7 days":  timedelta(days=7),
        "Last 30 days": timedelta(days=30),
        "All time":     timedelta(days=36500),
    }
    return datetime.now() - mapping.get(label, timedelta(hours=24))


def _run_search(time_range, severities, source_kw, message_regex) -> list:
    try:
        resp = requests.get(f"{BACKEND}/threats", verify=VERIFY_SSL, timeout=15)
        if resp.status_code != 200:
            st.error(f"Failed to fetch logs: {resp.status_code}")
            return []
        all_logs = resp.json()
    except Exception as e:
        st.error(f"Connection error: {e}")
        return []

    cutoff = _parse_time_range(time_range)
    compiled = None
    if message_regex:
        try:
            compiled = re.compile(message_regex, re.IGNORECASE)
        except re.error as e:
            st.warning(f"Invalid regex: {e}")

    results = []
    for log in all_logs:
        ts_str = log.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts < cutoff:
                continue
        except Exception:
            pass

        if severities and log.get("severity", "").upper() not in severities:
            continue
        if source_kw and source_kw.lower() not in (log.get("source", "") or "").lower():
            continue
        if compiled and not compiled.search(log.get("message", "") or ""):
            continue

        results.append(log)

    st.session_state["hunt_results"] = results
    return results


def _render_results(results: list):
    if not results:
        st.markdown("""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:20px;text-align:center;margin-top:8px;">
          <span style="color:#8b949e;font-size:.85rem;">No matching events found.</span>
        </div>
        """, unsafe_allow_html=True)
        return

    df = pd.DataFrame(results)

    # Result summary bar
    crit = len(df[df.get("severity", pd.Series(dtype=str)).str.upper() == "CRITICAL"]) if "severity" in df.columns else 0
    high = len(df[df["severity"].str.upper() == "HIGH"]) if "severity" in df.columns else 0

    st.markdown(f"""
    <div style="background:#0d2119;border:1px solid #238636;border-radius:8px;
                padding:10px 14px;margin-bottom:12px;display:flex;gap:20px;flex-wrap:wrap;">
      <span style="color:#56d364;font-weight:600;">{len(results)} events found</span>
      {f'<span style="color:#ff6b6b;font-size:.82rem;">{crit} CRITICAL</span>' if crit else ''}
      {f'<span style="color:#f78166;font-size:.82rem;">{high} HIGH</span>' if high else ''}
    </div>
    """, unsafe_allow_html=True)

    # Severity distribution chart
    if "severity" in df.columns:
        sev_counts = df["severity"].str.upper().value_counts()
        ordered = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if s in sev_counts]
        colors = [SEVERITY_COLORS[s] for s in ordered]
        vals = [sev_counts[s] for s in ordered]

        fig = go.Figure(go.Bar(
            x=ordered, y=vals,
            marker_color=colors,
            text=vals, textposition="outside",
            textfont=dict(color="#c9d1d9", size=11),
        ))
        fig.update_layout(
            **_DARK,
            height=220,
            title=dict(text="Severity Distribution", font=dict(color="#58a6ff", size=12)),
            xaxis=dict(gridcolor="#21262d"),
            yaxis=dict(gridcolor="#21262d"),
        )
        st.plotly_chart(fig, use_container_width=True)

    # Results list
    st.markdown("**Matching Events**")
    display_cols = ["timestamp", "severity", "source", "message"]
    for log in results[:200]:
        sev = str(log.get("severity", "INFO")).upper()
        sc = SEVERITY_COLORS.get(sev, "#79c0ff")
        src = str(log.get("source", "—"))[:40]
        msg = str(log.get("message", ""))[:100]
        ts = str(log.get("timestamp", ""))[:16]
        log_id = log.get("id", "")

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:8px 12px;margin-bottom:4px;display:flex;
                    justify-content:space-between;align-items:flex-start;gap:8px;">
          <div style="flex:1;min-width:0;">
            <span style="background:{sc}22;color:{sc};border:1px solid {sc}44;
                         border-radius:8px;font-size:.63rem;font-weight:700;
                         padding:1px 6px;margin-right:6px;">{sev}</span>
            <span style="color:#8b949e;font-size:.76rem;">{src}</span>
            <div style="color:#c9d1d9;font-size:.78rem;margin-top:3px;
                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
              {msg}
            </div>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="color:#484f58;font-size:.68rem;">{ts}</div>
            {f'<div style="color:#30363d;font-size:.65rem;">#{log_id}</div>' if log_id else ''}
          </div>
        </div>
        """, unsafe_allow_html=True)

    # Actions
    col1, col2 = st.columns(2)
    with col1:
        show = [{c: r.get(c, "") for c in display_cols} for r in results]
        csv = pd.DataFrame(show).to_csv(index=False)
        st.download_button("Export CSV", csv, "hunt_results.csv", "text/csv",
                           use_container_width=True)
    with col2:
        if st.button("Create Case from Results", use_container_width=True):
            log_ids = [r.get("id") for r in results if r.get("id")]
            st.session_state["new_case_log_ids"] = log_ids
            st.session_state["view"] = "cases"
            st.rerun()
