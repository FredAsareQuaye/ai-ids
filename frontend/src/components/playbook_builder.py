"""
Visual Playbook Builder — create and manage custom automation rules through the UI.
No Python editing required. Triggers + action chains stored in the backend DB.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import json

BACKEND = BACKEND
VERIFY_SSL = False

TRIGGER_FIELDS = ["severity", "source", "source_ip", "event_type", "message"]
TRIGGER_OPS = ["==", "!=", "contains", "not_contains", "starts_with", "regex"]
ACTION_TYPES = ["log_event", "block_ip", "send_webhook", "create_case", "notify_email"]

FIELD_HELP = {
    "severity": "e.g. CRITICAL, HIGH, MEDIUM",
    "source": "hostname or IP string",
    "source_ip": "exact or partial IP",
    "event_type": "syslog, cef, auth, etc.",
    "message": "free-text in the log message",
}

OP_HELP = {
    "==": "exact match (case-insensitive)",
    "!=": "does not match",
    "contains": "value appears anywhere in field",
    "not_contains": "value does NOT appear in field",
    "starts_with": "field starts with value",
    "regex": "Python regex pattern",
}

ACTION_ICONS = {
    "log_event": "📝",
    "block_ip": "🚫",
    "send_webhook": "🔔",
    "create_case": "📁",
    "notify_email": "📧",
}

ACTION_COLORS = {
    "log_event": "#58a6ff",
    "block_ip": "#ff6b6b",
    "send_webhook": "#e3b341",
    "create_case": "#56d364",
    "notify_email": "#d2a8ff",
}


def _api_key() -> str:
    return st.session_state.get("siem_api_key", "")


def _auth_headers() -> dict:
    return {"X-API-Key": _api_key()}


def _get(path):
    try:
        r = requests.get(f"{BACKEND}{path}", verify=VERIFY_SSL, timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Request error: {e}")
    return None


def _post(path, payload):
    try:
        return requests.post(f"{BACKEND}{path}", json=payload,
                             headers=_auth_headers(), verify=VERIFY_SSL, timeout=30)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None


def _put(path, payload):
    try:
        return requests.put(f"{BACKEND}{path}", json=payload,
                            headers=_auth_headers(), verify=VERIFY_SSL, timeout=30)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None


def _delete(path):
    try:
        return requests.delete(f"{BACKEND}{path}",
                               headers=_auth_headers(), verify=VERIFY_SSL, timeout=30)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None


def render_playbook_builder():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Playbook Builder
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Define custom automation rules. When a trigger condition matches an ingested event,
        the action chain executes automatically in real-time.
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("Admin API Key", expanded=not _api_key()):
        k = st.text_input("Key (required to create / edit / delete playbooks)",
                          type="password", key="pb_api_key", value=_api_key())
        if k:
            st.session_state["siem_api_key"] = k

    playbooks = _get("/custom-playbooks") or []
    execs = _get("/custom-playbooks/executions") or []

    c1, c2, c3 = st.columns(3)
    enabled_count = sum(1 for p in playbooks if p.get("enabled"))
    for col, label, val, color in [
        (c1, "Total Playbooks",  len(playbooks),   "#58a6ff"),
        (c2, "Active",           enabled_count,    "#56d364"),
        (c3, "Executions",       len(execs),        "#e3b341"),
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

    tab_list, tab_create, tab_executions = st.tabs(
        ["My Playbooks", "Create New", "Execution History"]
    )

    with tab_list:
        _render_playbook_list(playbooks)

    with tab_create:
        _render_create_form()

    with tab_executions:
        _render_executions(execs)


def _render_playbook_list(playbooks):
    if not playbooks:
        st.markdown("<br>", unsafe_allow_html=True)
        st.info("No custom playbooks yet. Use 'Create New' to build one.")
        return

    for pb in playbooks:
        enabled = pb.get("enabled", False)
        status_color = "#56d364" if enabled else "#6e7681"
        status_label = "ACTIVE" if enabled else "PAUSED"
        status_bg = "#0d2119" if enabled else "#161b22"

        actions = pb.get("actions", [])
        action_pills = ""
        for a in actions[:4]:
            atype = a.get("type", "?")
            ic = ACTION_ICONS.get(atype, "▶")
            ac = ACTION_COLORS.get(atype, "#79c0ff")
            action_pills += (
                f'<span style="background:{ac}22;color:{ac};border:1px solid {ac}44;'
                f'border-radius:12px;font-size:.65rem;padding:2px 7px;margin-right:4px;">'
                f'{ic} {atype}</span>'
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
                <span style="color:#e6edf3;font-weight:600;font-size:.9rem;">
                  #{pb['id']} · {pb.get('name','')[:50]}
                </span>
              </div>
              <div style="color:#8b949e;font-size:.78rem;margin-bottom:6px;">
                {pb.get('description','—')[:80]}
              </div>
              <div style="font-size:.75rem;margin-bottom:6px;">
                <code style="background:#21262d;color:#79c0ff;padding:2px 6px;border-radius:4px;">
                  {pb.get('trigger_field','')}
                </code>
                <span style="color:#6e7681;margin:0 4px;">{pb.get('trigger_operator','')}</span>
                <code style="background:#21262d;color:#f78166;padding:2px 6px;border-radius:4px;">
                  {pb.get('trigger_value','')[:30]}
                </code>
              </div>
              <div>{action_pills}</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        col_toggle, col_del, _ = st.columns([1, 1, 4])
        with col_toggle:
            label = "Disable" if enabled else "Enable"
            if st.button(label, key=f"toggle_{pb['id']}", use_container_width=True):
                resp = _put(f"/custom-playbooks/{pb['id']}", {"enabled": not enabled})
                if resp and resp.status_code == 200:
                    st.rerun()
                else:
                    st.error("Failed — check API key.")
        with col_del:
            if st.button("Delete", key=f"del_{pb['id']}", use_container_width=True):
                resp = _delete(f"/custom-playbooks/{pb['id']}")
                if resp and resp.status_code == 200:
                    st.rerun()
                else:
                    st.error("Failed.")


def _render_create_form():
    st.markdown("""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                padding:20px;margin-bottom:12px;">
      <div style="color:#58a6ff;font-size:.85rem;font-weight:600;margin-bottom:4px;">
        How playbooks work
      </div>
      <div style="color:#8b949e;font-size:.78rem;line-height:1.5;">
        Each playbook defines a <strong style="color:#c9d1d9;">trigger condition</strong>
        (field + operator + value) evaluated against every ingested log event.
        When matched, the <strong style="color:#c9d1d9;">action chain</strong> fires automatically.
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.form("pb_create_form"):
        st.markdown("**Playbook Identity**")
        c1, c2 = st.columns([2, 1])
        with c1:
            name = st.text_input("Name *", placeholder="e.g. Block CRITICAL IPs automatically")
        with c2:
            enabled = st.checkbox("Enable immediately", value=True)
        description = st.text_area("Description", placeholder="What does this playbook do?",
                                   height=70)

        st.markdown("**Trigger Condition**")
        tc1, tc2, tc3 = st.columns(3)
        with tc1:
            field = st.selectbox("Field", TRIGGER_FIELDS,
                                 help="\n".join(f"**{k}**: {v}" for k, v in FIELD_HELP.items()))
        with tc2:
            op = st.selectbox("Operator", TRIGGER_OPS,
                              help="\n".join(f"**{k}**: {v}" for k, v in OP_HELP.items()))
        with tc3:
            value = st.text_input("Value", placeholder=FIELD_HELP.get(field, ""))

        st.markdown("**Actions** — up to 5, leave unused blank")
        actions = []
        for i in range(5):
            ac1, ac2 = st.columns([1, 2])
            with ac1:
                atype = st.selectbox(f"Action {i+1}", ["(none)"] + ACTION_TYPES, key=f"atype_{i}")
            with ac2:
                aparams = st.text_input(
                    f"Params",
                    key=f"aparams_{i}",
                    placeholder='{"url": "https://..."} or plain value',
                    label_visibility="collapsed",
                )
            if atype != "(none)":
                try:
                    params = json.loads(aparams) if aparams.strip().startswith("{") else {"value": aparams}
                except Exception:
                    params = {"value": aparams}
                actions.append({"type": atype, "params": params})

        submitted = st.form_submit_button("Create Playbook", type="primary", use_container_width=True)

    if submitted:
        if not name.strip():
            st.error("Name is required.")
            return
        if not value.strip():
            st.error("Trigger value is required.")
            return

        from components.enhanced_login import get_current_user
        user = get_current_user()

        payload = {
            "name": name.strip(),
            "description": description.strip(),
            "trigger_field": field,
            "trigger_operator": op,
            "trigger_value": value.strip(),
            "actions": actions,
            "enabled": enabled,
            "created_by": user.get("username", "analyst") if user else "analyst",
        }
        resp = _post("/custom-playbooks", payload)
        if resp and resp.status_code == 200:
            pb_id = resp.json().get("id")
            st.success(f"Playbook #{pb_id} created successfully!")
        else:
            detail = resp.json().get("detail", "unknown") if resp else "no response"
            st.error(f"Failed: {detail}")


def _render_executions(execs):
    if not execs:
        st.info("No custom playbook executions yet.")
        return

    st.markdown(f"**{len(execs)} executions recorded**")

    for e in execs[:50]:
        pb_name = e.get("playbook_name", "Unknown")
        src = str(e.get("source", "—"))[:40]
        ts = str(e.get("executed_at", ""))[:16]
        actions_list = e.get("actions", [])
        triggered = str(e.get("triggered_by", ""))[:60]

        action_pills = ""
        for a in (actions_list or []):
            ac = ACTION_COLORS.get(a, "#79c0ff")
            action_pills += (
                f'<span style="background:{ac}22;color:{ac};border:1px solid {ac}44;'
                f'border-radius:10px;font-size:.63rem;padding:1px 6px;margin-right:3px;">'
                f'{ACTION_ICONS.get(a,"▶")} {a}</span>'
            )

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:10px 14px;margin-bottom:5px;display:flex;
                    justify-content:space-between;align-items:center;gap:8px;">
          <div style="flex:1;min-width:0;">
            <div style="color:#e6edf3;font-size:.82rem;font-weight:600;">{pb_name}</div>
            <div style="color:#6e7681;font-size:.72rem;margin-top:2px;
                        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{triggered}</div>
            <div style="margin-top:4px;">{action_pills}</div>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="color:#8b949e;font-size:.72rem;">{src}</div>
            <div style="color:#484f58;font-size:.68rem;">{ts}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)
