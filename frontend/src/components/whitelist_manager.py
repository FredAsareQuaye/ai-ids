"""
False-Positive Whitelist Manager UI
Add, view, and remove whitelist entries that suppress known-safe sources.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd

BACKEND = BACKEND
VERIFY_SSL = False
WHITELIST_TYPES = ["ip", "hostname", "username", "source", "pattern"]

TYPE_ICONS = {
    "ip":       "🌐",
    "hostname": "🖥️",
    "username": "👤",
    "source":   "📡",
    "pattern":  "🔍",
}

TYPE_COLORS = {
    "ip":       "#58a6ff",
    "hostname": "#56d364",
    "username": "#e3b341",
    "source":   "#d2a8ff",
    "pattern":  "#f78166",
}

TYPE_PLACEHOLDERS = {
    "ip":       "1.2.3.4",
    "hostname": "monitor.internal",
    "username": "backup_user",
    "source":   "nagios",
    "pattern":  r"heartbeat|healthcheck",
}


def _api_key() -> str:
    return st.session_state.get("siem_api_key", "")


def _headers() -> dict:
    return {"X-API-Key": _api_key()}


def _get(path):
    try:
        r = requests.get(f"{BACKEND}{path}", verify=VERIFY_SSL, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Request error: {e}")
    return None


def render_whitelist_manager():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        False-Positive Whitelist
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Suppress known-safe events before they reach correlations or alerts, eliminating
        noise from monitoring tools, internal scanners, and trusted sources.
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("Admin API Key", expanded=not _api_key()):
        k = st.text_input("Key (required to add / remove entries)",
                          type="password", key="wl_api_key", value=_api_key())
        if k:
            st.session_state["siem_api_key"] = k

    entries = _get("/whitelist") or []

    type_counts = {}
    for e in entries:
        t = e.get("type", "?")
        type_counts[t] = type_counts.get(t, 0) + 1

    c1, c2, c3 = st.columns(3)
    for col, label, val, color in [
        (c1, "Total Entries",   len(entries),              "#58a6ff"),
        (c2, "Types Covered",   len(type_counts),          "#56d364"),
        (c3, "Events Suppressed", "Real-time",             "#e3b341"),
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

    tab1, tab2 = st.tabs(["Active Entries", "Add Entry"])

    with tab1:
        _render_entries(entries)

    with tab2:
        _render_add_form()


def _render_entries(entries):
    if not entries:
        st.markdown("""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                    padding:30px;text-align:center;margin-top:8px;">
          <div style="font-size:2rem;margin-bottom:8px;">✅</div>
          <div style="color:#8b949e;font-size:.85rem;">
            No whitelist entries yet. Use 'Add Entry' to suppress known-safe sources.
          </div>
        </div>
        """, unsafe_allow_html=True)
        return

    type_filter = st.multiselect("Filter by type", WHITELIST_TYPES, default=[], key="wl_type_filter")
    filtered = entries if not type_filter else [e for e in entries if e.get("type") in type_filter]

    for e in filtered:
        wtype = e.get("type", "?")
        icon = TYPE_ICONS.get(wtype, "•")
        color = TYPE_COLORS.get(wtype, "#79c0ff")
        val = e.get("value", "—")
        reason = e.get("reason", "") or "—"
        created_by = e.get("created_by", "") or "—"
        added = str(e.get("created_at", ""))[:10]
        eid = e.get("id", "?")

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:10px 14px;margin-bottom:5px;display:flex;
                    justify-content:space-between;align-items:center;gap:8px;">
          <div style="flex:1;min-width:0;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
              <span style="background:{color}22;color:{color};border:1px solid {color}44;
                           border-radius:10px;font-size:.63rem;font-weight:700;padding:1px 7px;">
                {icon} {wtype.upper()}
              </span>
              <code style="color:{color};font-size:.82rem;">{val}</code>
            </div>
            <div style="color:#6e7681;font-size:.73rem;">
              {reason}
              <span style="color:#484f58;margin-left:8px;">by {created_by} · {added}</span>
            </div>
          </div>
          <div style="color:#484f58;font-size:.7rem;flex-shrink:0;">#{eid}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>**Remove Entry**")
    col_id, col_del = st.columns([2, 1])
    with col_id:
        entry_id = st.number_input("Entry ID", min_value=1, step=1, key="wl_remove_id",
                                   label_visibility="collapsed")
    with col_del:
        if st.button("Remove Entry", use_container_width=True):
            _remove_entry(int(entry_id))
            st.rerun()


def _remove_entry(entry_id: int):
    try:
        resp = requests.delete(
            f"{BACKEND}/whitelist/{entry_id}",
            headers=_headers(),
            verify=VERIFY_SSL,
            timeout=10,
        )
        if resp.status_code == 200:
            st.success(f"Entry {entry_id} removed.")
        elif resp.status_code == 404:
            st.warning("Entry not found.")
        else:
            st.error(f"Failed: {resp.text}")
    except Exception as e:
        st.error(str(e))


def _render_add_form():
    st.markdown("""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                padding:12px 14px;margin-bottom:14px;">
      <div style="color:#58a6ff;font-size:.82rem;font-weight:600;margin-bottom:4px;">
        Whitelist types
      </div>
      <div style="color:#8b949e;font-size:.76rem;line-height:1.6;">
        <strong style="color:#c9d1d9;">ip</strong> — suppress all events from a specific IP address<br>
        <strong style="color:#c9d1d9;">hostname</strong> — suppress events from a named host<br>
        <strong style="color:#c9d1d9;">username</strong> — suppress events attributed to a user<br>
        <strong style="color:#c9d1d9;">source</strong> — suppress events from a log source (e.g. nagios)<br>
        <strong style="color:#c9d1d9;">pattern</strong> — regex matched against the log message (re.search)
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.form("add_whitelist"):
        c1, c2 = st.columns(2)
        with c1:
            wtype = st.selectbox("Type", WHITELIST_TYPES)
        with c2:
            value = st.text_input("Value *", placeholder=TYPE_PLACEHOLDERS.get(wtype, ""))

        reason = st.text_input("Reason", placeholder="Why is this safe to ignore?")
        created_by = st.text_input("Your name / ticket", value="admin")

        submitted = st.form_submit_button("Add Entry", type="primary", use_container_width=True)

    if submitted:
        if not value.strip():
            st.error("Value is required.")
        else:
            _add_entry(wtype, value.strip(), reason.strip(), created_by.strip())


def _add_entry(wtype: str, value: str, reason: str, created_by: str):
    try:
        resp = requests.post(
            f"{BACKEND}/whitelist",
            json={"type": wtype, "value": value, "reason": reason, "created_by": created_by},
            headers=_headers(),
            verify=VERIFY_SSL,
            timeout=10,
        )
        if resp.status_code == 200:
            st.success(f"Entry added (ID={resp.json().get('id')}).")
            st.rerun()
        else:
            st.error(f"Failed: {resp.text}")
    except Exception as e:
        st.error(str(e))
