"""
Case Management UI — create, track, and investigate security incidents.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
from datetime import datetime

BACKEND = BACKEND
VERIFY_SSL = False

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
STATUSES   = ["open", "investigating", "resolved", "closed", "false_positive"]

_SEV_COLOR = {"CRITICAL":"#ff6b6b","HIGH":"#f78166","MEDIUM":"#e3b341",
              "LOW":"#56d364","INFO":"#79c0ff"}
_STATUS_COLOR = {"open":"#ff6b6b","investigating":"#f78166","resolved":"#56d364",
                 "closed":"#6e7681","false_positive":"#d2a8ff"}
_STATUS_BG    = {"open":"#3d1c1c","investigating":"#2d1f0e","resolved":"#0d2119",
                 "closed":"#161b22","false_positive":"#1f1635"}


def _api_key():
    return st.session_state.get("siem_api_key", "")

def _auth_headers():
    return {"X-API-Key": _api_key()}

def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, verify=VERIFY_SSL, timeout=30)
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


def _pill(text, color, bg):
    return (f'<span style="background:{bg};color:{color};border:1px solid {color};'
            f'border-radius:20px;font-size:.68rem;font-weight:600;padding:2px 9px;">{text}</span>')


def render_case_manager():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Case Management
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Track security incidents from initial detection through investigation and resolution.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # API key (collapsed by default)
    with st.expander("Admin API Key", expanded=not _api_key()):
        k = st.text_input("Key (required to update/create cases)", type="password",
                          key="case_api_key", value=_api_key())
        if k:
            st.session_state["siem_api_key"] = k

    # Stats bar
    stats = _get("/cases/stats") or {}
    by_status = stats.get("by_status", {})
    c1,c2,c3,c4,c5 = st.columns(5)
    for col, label, val, color in [
        (c1,"Total Cases",  stats.get("total",0),           "#58a6ff"),
        (c2,"Open",         by_status.get("open",0),        "#ff6b6b"),
        (c3,"Investigating",by_status.get("investigating",0),"#f78166"),
        (c4,"Resolved",     by_status.get("resolved",0),    "#56d364"),
        (c5,"Closed",       by_status.get("closed",0),      "#6e7681"),
    ]:
        with col:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:9px;
                        padding:12px;text-align:center;border-top:3px solid {color};">
              <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">{label}</div>
              <div style="color:{color};font-size:1.7rem;font-weight:700;">{val}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab_list, tab_detail, tab_new = st.tabs(["📋 Case List", "🔍 Case Detail", "➕ New Case"])

    with tab_list:
        _render_case_list()
    with tab_detail:
        _render_case_detail()
    with tab_new:
        _render_new_case_form()


def _render_case_list():
    col1, col2, col3 = st.columns(3)
    with col1:
        sf = st.selectbox("Status", ["all"] + STATUSES, key="cl_status")
    with col2:
        svf = st.selectbox("Severity", ["all"] + SEVERITIES, key="cl_sev")
    with col3:
        limit = st.number_input("Limit", 10, 500, 100, 10)

    params = {"limit": limit}
    if sf != "all": params["status"] = sf
    if svf != "all": params["severity"] = svf

    cases = _get("/cases", params=params) or []

    if not cases:
        st.info("No cases match the current filters.")
        return

    st.markdown(f"**{len(cases)} cases**")

    for c in cases:
        sev = c.get("severity","LOW").upper()
        status = c.get("status","open")
        sc = _SEV_COLOR.get(sev,"#79c0ff")
        stc = _STATUS_COLOR.get(status,"#6e7681")
        stbg = _STATUS_BG.get(status,"#161b22")
        ts = str(c.get("created_at",""))[:10]
        assigned = c.get("assigned_to") or "Unassigned"

        col_main, col_open = st.columns([5,1])
        with col_main:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;
                        border-left:4px solid {sc};border-radius:8px;
                        padding:10px 14px;margin-bottom:6px;">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                <div style="flex:1;">
                  <span style="color:#e6edf3;font-weight:600;font-size:.9rem;">
                    #{c['id']} · {c.get('title','')[:60]}
                  </span>
                  <div style="margin-top:5px;display:flex;gap:8px;flex-wrap:wrap;">
                    {_pill(sev, sc, sc+'22')}
                    {_pill(status, stc, stbg)}
                    <span style="color:#6e7681;font-size:.72rem;">👤 {assigned}</span>
                    <span style="color:#484f58;font-size:.72rem;">📅 {ts}</span>
                  </div>
                  <div style="color:#6e7681;font-size:.78rem;margin-top:4px;">
                    {c.get('description','')[:80]}
                  </div>
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)
        with col_open:
            if st.button("Open", key=f"open_{c['id']}"):
                st.session_state["open_case_id"] = c["id"]
                st.rerun()


def _render_case_detail():
    case_id = st.session_state.get("open_case_id")

    col_id, col_go = st.columns([2, 1])
    with col_id:
        typed_id = st.number_input("Case ID", min_value=1,
                                   value=int(case_id) if case_id else 1, step=1)
    with col_go:
        if st.button("Load Case", use_container_width=True):
            st.session_state["open_case_id"] = typed_id
            case_id = typed_id

    if not case_id:
        st.info("Select a case from the list tab or enter an ID.")
        return

    case = _get(f"/cases/{case_id}")
    if not case:
        st.error(f"Case #{case_id} not found.")
        return

    sev    = case.get("severity","INFO").upper()
    status = case.get("status","open")
    sc     = _SEV_COLOR.get(sev,"#79c0ff")
    stc    = _STATUS_COLOR.get(status,"#6e7681")
    stbg   = _STATUS_BG.get(status,"#161b22")

    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#161b22,#1c2128);
                border:1px solid #30363d;border-left:5px solid {sc};
                border-radius:10px;padding:16px 20px;margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;">
        <div>
          <div style="color:#8b949e;font-size:.72rem;">CASE #{case['id']}</div>
          <div style="color:#e6edf3;font-size:1.1rem;font-weight:700;">{case.get('title','')}</div>
          <div style="color:#8b949e;font-size:.82rem;margin-top:4px;">{case.get('description','')}</div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start;">
          {_pill(sev, sc, sc+'22')}
          {_pill(status, stc, stbg)}
        </div>
      </div>
      <div style="display:flex;gap:20px;margin-top:10px;flex-wrap:wrap;">
        <div><span style="color:#6e7681;font-size:.72rem;">SOURCE</span>
             <div style="color:#c9d1d9;font-size:.82rem;">{case.get('source','—')}</div></div>
        <div><span style="color:#6e7681;font-size:.72rem;">ASSIGNED</span>
             <div style="color:#c9d1d9;font-size:.82rem;">{case.get('assigned_to') or '—'}</div></div>
        <div><span style="color:#6e7681;font-size:.72rem;">CREATED</span>
             <div style="color:#c9d1d9;font-size:.82rem;">{str(case.get('created_at',''))[:16]}</div></div>
        <div><span style="color:#6e7681;font-size:.72rem;">UPDATED</span>
             <div style="color:#c9d1d9;font-size:.82rem;">{str(case.get('updated_at',''))[:16]}</div></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Update panel
    with st.expander("Update Case Status / Assignment"):
        u1,u2,u3 = st.columns(3)
        with u1:
            new_status = st.selectbox("Status", STATUSES,
                                      index=STATUSES.index(status) if status in STATUSES else 0,
                                      key=f"cs_{case_id}")
        with u2:
            new_sev = st.selectbox("Severity", SEVERITIES,
                                   index=SEVERITIES.index(sev) if sev in SEVERITIES else 1,
                                   key=f"cv_{case_id}")
        with u3:
            new_assign = st.text_input("Assign to", value=case.get("assigned_to",""),
                                       key=f"ca_{case_id}")
        if st.button("Save", key=f"save_{case_id}"):
            r = _put(f"/cases/{case_id}",
                     {"status": new_status, "severity": new_sev, "assigned_to": new_assign})
            if r and r.status_code == 200:
                st.success("Updated.")
                st.rerun()
            else:
                st.error(f"Failed — check API key. ({r.status_code if r else 'no response'})")

    # Notes timeline
    st.markdown("**Investigation Notes**")
    notes = sorted(case.get("notes",[]), key=lambda x: x.get("created_at",""), reverse=True)
    if notes:
        for n in notes:
            ts = str(n.get("created_at",""))[:16]
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                        padding:10px 14px;margin-bottom:6px;">
              <div style="display:flex;justify-content:space-between;">
                <span style="color:#58a6ff;font-weight:600;font-size:.82rem;">
                  👤 {n.get('author','?')}
                </span>
                <span style="color:#484f58;font-size:.72rem;">{ts}</span>
              </div>
              <div style="color:#c9d1d9;font-size:.84rem;margin-top:6px;">{n.get('note','')}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown('<div style="color:#484f58;font-size:.82rem;">No notes yet.</div>',
                    unsafe_allow_html=True)

    with st.form(f"note_form_{case_id}"):
        from components.enhanced_login import get_current_user
        cu = get_current_user()
        note_author = st.text_input("Your name", value=cu.get("username","") if cu else "")
        note_text   = st.text_area("Add a note", placeholder="Describe findings, actions taken…")
        if st.form_submit_button("Add Note", type="primary"):
            if note_text.strip():
                r = _post(f"/cases/{case_id}/notes",
                          {"author": note_author, "note": note_text.strip()})
                if r and r.status_code == 200:
                    st.success("Note added.")
                    st.rerun()

    log_ids = case.get("log_ids",[])
    if log_ids:
        st.markdown(f"**Linked Logs ({len(log_ids)})**")
        st.code(", ".join(str(i) for i in log_ids))

    with st.expander("Link Additional Logs"):
        raw = st.text_input("Log IDs (comma-separated)", key=f"link_{case_id}")
        if st.button("Link", key=f"linkbtn_{case_id}"):
            try:
                ids = [int(x.strip()) for x in raw.split(",") if x.strip()]
                r = _post(f"/cases/{case_id}/logs", {"log_ids": ids})
                if r and r.status_code == 200:
                    st.success(f"Linked {r.json().get('added', len(ids))} logs.")
                    st.rerun()
            except ValueError:
                st.error("Enter valid integer IDs.")


def _render_new_case_form():
    st.markdown("**Create a New Security Case**")
    prefill_ids = st.session_state.pop("new_case_log_ids", [])

    with st.form("new_case_form"):
        title = st.text_input("Title *", placeholder="e.g. Brute-force on SSH from 1.2.3.4")
        desc  = st.text_area("Description", placeholder="Brief summary…")
        c1,c2 = st.columns(2)
        with c1:
            sev    = st.selectbox("Severity", SEVERITIES, index=1)
            source = st.text_input("Source / host", placeholder="192.168.1.10 or server-01")
        with c2:
            assign = st.text_input("Assign to", placeholder="analyst@company.com")
            tags   = st.text_input("Tags", placeholder="ssh, brute-force, linux")

        log_ids_raw = st.text_input(
            "Linked Log IDs",
            value=", ".join(str(i) for i in prefill_ids) if prefill_ids else "",
        )
        submitted = st.form_submit_button("Create Case", type="primary")

    if submitted:
        if not title.strip():
            st.error("Title is required.")
            return
        try:
            log_ids = [int(x.strip()) for x in log_ids_raw.split(",") if x.strip()]
        except ValueError:
            st.error("Log IDs must be integers.")
            return

        from components.enhanced_login import get_current_user
        user = get_current_user()
        r = _post("/cases", {
            "title": title.strip(), "description": desc.strip(), "severity": sev,
            "assigned_to": assign.strip() or None,
            "created_by": user.get("username","unknown") if user else "unknown",
            "source": source.strip() or None,
            "tags": [t.strip() for t in tags.split(",") if t.strip()],
            "log_ids": log_ids,
        })
        if r and r.status_code == 200:
            new_id = r.json().get("id")
            st.success(f"Case #{new_id} created.")
            st.session_state["open_case_id"] = new_id
        else:
            detail = r.json().get("detail","?") if r else "no response"
            st.error(f"Failed: {detail}")
