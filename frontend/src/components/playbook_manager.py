"""
Playbook Manager UI — view, enable/disable built-in playbooks,
inspect execution history, and see blocked IPs.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd

BACKEND = BACKEND
VERIFY_SSL = False

TRIGGER_COLORS = {
    "critical": "#ff6b6b",
    "high":     "#f78166",
    "medium":   "#e3b341",
    "low":      "#56d364",
    "any":      "#79c0ff",
}


def _api_key() -> str:
    return st.session_state.get("siem_api_key", "")


def _headers() -> dict:
    return {"X-API-Key": _api_key()}


def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, verify=VERIFY_SSL, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Request error: {e}")
    return None


def render_playbook_manager():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Automated Incident Response
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Built-in playbooks fire automatically on matching events — blocking IPs,
        snapshotting state, and triggering notifications without analyst intervention.
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("Admin API Key", expanded=not _api_key()):
        k = st.text_input("Key (required to enable/disable playbooks)",
                          type="password", key="pb_mgr_api_key", value=_api_key())
        if k:
            st.session_state["siem_api_key"] = k

    playbooks = _get("/playbooks") or []
    executions = _get("/playbooks/executions", params={"limit": 200}) or []
    blocked_data = _get("/playbooks/blocked-ips") or {}
    blocked = blocked_data.get("blocked_ips", [])

    c1, c2, c3 = st.columns(3)
    enabled_count = sum(1 for p in playbooks if p.get("enabled"))
    for col, label, val, color in [
        (c1, "Playbooks",      len(playbooks),   "#58a6ff"),
        (c2, "Active",         enabled_count,    "#56d364"),
        (c3, "Blocked IPs",    len(blocked),     "#ff6b6b"),
    ]:
        with col:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                        padding:14px;text-align:center;border-top:3px solid {color};">
              <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">{label}</div>
              <div style="color:{color};font-size:1.8rem;font-weight:700;">{val}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["Playbooks", "Execution History", "Blocked IPs"])

    with tab1:
        _render_playbooks(playbooks)

    with tab2:
        _render_executions(executions)

    with tab3:
        _render_blocked_ips(blocked)


def _render_playbooks(playbooks):
    if not playbooks:
        st.info("No playbooks found.")
        return

    for pb in playbooks:
        enabled = pb.get("enabled", False)
        status_color = "#56d364" if enabled else "#6e7681"
        status_label = "ACTIVE" if enabled else "PAUSED"
        status_bg = "#0d2119" if enabled else "#161b22"
        trigger = pb.get("trigger_rule", "?")
        min_sev = (pb.get("min_severity") or "any").lower()
        sev_color = TRIGGER_COLORS.get(min_sev, "#79c0ff")

        actions = pb.get("actions", [])
        action_html = ""
        for a in actions:
            atype = a.get("type", "?")
            action_html += (
                f'<span style="background:#21262d;color:#8b949e;border-radius:8px;'
                f'font-size:.65rem;padding:2px 7px;margin-right:4px;">{atype}</span>'
            )

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                    padding:14px 18px;margin-bottom:8px;border-left:4px solid {status_color};">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;">
            <div style="flex:1;min-width:0;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
                <span style="background:{status_bg};color:{status_color};border:1px solid {status_color};
                             border-radius:10px;font-size:.62rem;font-weight:700;padding:1px 7px;">
                  {status_label}
                </span>
                <span style="color:#e6edf3;font-weight:600;font-size:.9rem;">{pb.get('name','')}</span>
              </div>
              <div style="color:#8b949e;font-size:.78rem;margin-bottom:6px;">
                {pb.get('description','—')[:80]}
              </div>
              <div style="font-size:.73rem;margin-bottom:6px;">
                <span style="color:#6e7681;">Triggers on: </span>
                <code style="background:#21262d;color:#79c0ff;padding:1px 5px;border-radius:3px;">
                  {trigger}
                </code>
                &nbsp;·&nbsp;
                <span style="color:#6e7681;">Min severity: </span>
                <span style="color:{sev_color};font-weight:600;">{min_sev.upper()}</span>
              </div>
              <div>{action_html}</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        col_toggle, _ = st.columns([1, 5])
        with col_toggle:
            btn_label = "Disable" if enabled else "Enable"
            if st.button(btn_label, key=f"toggle_{pb['id']}", use_container_width=True):
                _toggle_playbook(pb["id"], not enabled)
                st.rerun()


def _toggle_playbook(pb_id: str, enabled: bool):
    try:
        resp = requests.put(
            f"{BACKEND}/playbooks/{pb_id}",
            json={"enabled": enabled},
            headers=_headers(),
            verify=VERIFY_SSL,
            timeout=10,
        )
        if resp.status_code == 200:
            st.success(f"Playbook {'enabled' if enabled else 'disabled'}.")
        else:
            st.error(f"Failed: {resp.text}")
    except Exception as e:
        st.error(str(e))


def _render_executions(executions):
    if not executions:
        st.info("No playbook executions recorded yet.")
        return

    st.markdown(f"**{len(executions)} executions recorded**")

    for ex in executions[:100]:
        pb_name = ex.get("playbook_name", "?")
        triggered = str(ex.get("triggered_by", ""))[:60]
        src = str(ex.get("source", "—"))
        ts = str(ex.get("executed_at", ""))[:16]
        actions_list = ex.get("actions") or []
        action_summary = ", ".join(
            a.get("type", "?") for a in actions_list if isinstance(a, dict)
        ) or str(actions_list)[:40]

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:9px 14px;margin-bottom:5px;display:flex;
                    justify-content:space-between;align-items:center;gap:8px;">
          <div style="flex:1;min-width:0;">
            <div style="color:#e6edf3;font-size:.82rem;font-weight:600;">{pb_name}</div>
            <div style="color:#6e7681;font-size:.72rem;margin-top:2px;
                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{triggered}</div>
            <div style="color:#8b949e;font-size:.7rem;margin-top:2px;">
              Actions: <span style="color:#79c0ff;">{action_summary}</span>
            </div>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="color:#8b949e;font-size:.72rem;">{src}</div>
            <div style="color:#484f58;font-size:.68rem;">{ts}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)


def _render_blocked_ips(blocked):
    if not blocked:
        st.info("No IPs are currently blocked by the playbook engine.")
        st.markdown("""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:16px;margin-top:8px;color:#6e7681;font-size:.8rem;">
          IPs get blocked when a <code>block_ip</code> action fires in a triggered playbook.
          Blocks are in-memory and reset on server restart unless iptables rules are persisted.
        </div>
        """, unsafe_allow_html=True)
        return

    st.markdown(f"""
    <div style="background:#3d1c1c;border:1px solid #ff6b6b;border-radius:8px;
                padding:10px 14px;margin-bottom:12px;">
      <span style="color:#ff6b6b;font-weight:600;">
        🚫 {len(blocked)} IP{'s' if len(blocked) != 1 else ''} currently blocked
      </span>
    </div>
    """, unsafe_allow_html=True)

    for ip in blocked:
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #ff6b6b44;border-radius:8px;
                    padding:9px 14px;margin-bottom:5px;display:flex;
                    align-items:center;gap:10px;">
          <span style="font-size:1rem;">🚫</span>
          <code style="color:#ff6b6b;font-size:.88rem;">{ip}</code>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="color:#6e7681;font-size:.75rem;margin-top:10px;padding:8px 0;">
      Blocks are enforced via iptables/Windows Firewall by the automated playbook engine.
      Blocks reset on server restart unless rules are persisted externally.
    </div>
    """, unsafe_allow_html=True)
