"""
Compliance Report UI — PCI-DSS / ISO 27001 / SOC 2
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

BACKEND = BACKEND
VERIFY_SSL = False
FRAMEWORKS = ["PCI-DSS", "ISO 27001", "SOC 2"]

_DARK = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0d1117",
             font_color="#c9d1d9", margin=dict(l=10,r=10,t=40,b=10))

def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, verify=VERIFY_SSL, timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Request error: {e}")
    return None

def _get_bytes(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, verify=VERIFY_SSL, timeout=60)
        if r.status_code == 200:
            return r.content
        st.error(f"Server error {r.status_code}")
    except Exception as e:
        st.error(f"Request error: {e}")
    return None


def render_compliance_ui():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Compliance Reports
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Maps SIEM events to PCI-DSS v4, ISO/IEC 27001:2022, and SOC 2 controls.
        Download audit-ready PDF reports.
      </div>
    </div>
    """, unsafe_allow_html=True)

    col_fw, col_days, col_run = st.columns([2, 2, 1])
    with col_fw:
        framework = st.selectbox("Framework", FRAMEWORKS, key="compliance_framework")
    with col_days:
        days = st.number_input("Period (days — use 365 for all-time)",
                               min_value=1, max_value=3650, value=365)
    with col_run:
        st.markdown("<br>", unsafe_allow_html=True)
        run = st.button("Analyse", type="primary", use_container_width=True)

    if run:
        with st.spinner(f"Analysing {framework} controls across {days} days of data…"):
            data = _get("/compliance/analyse", params={"framework": framework, "days": days})
        if data:
            st.session_state["compliance_data"] = data
            st.session_state["compliance_days"] = days

    data = st.session_state.get("compliance_data")
    if not data:
        _render_empty_state()
        return

    framework = st.session_state.get("compliance_framework", framework)
    days = st.session_state.get("compliance_days", days)
    _render_report(data, framework, days)


def _render_empty_state():
    st.markdown("""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;
                padding:40px;text-align:center;margin-top:20px;">
      <div style="font-size:3rem;margin-bottom:12px;">📋</div>
      <div style="color:#58a6ff;font-size:1.1rem;font-weight:600;">Select a framework and click Analyse</div>
      <div style="color:#6e7681;margin-top:8px;">
        Supports PCI-DSS v4.0 · ISO/IEC 27001:2022 · SOC 2 Trust Service Criteria
      </div>
    </div>
    """, unsafe_allow_html=True)


def _render_report(data, framework, days):
    controls = data.get("controls", [])
    cov_pct = data.get("coverage_pct", 0)
    viol = data.get("total_violations", 0)

    # ── Hero summary ──────────────────────────────────────────────────────────
    cov_color = "#56d364" if cov_pct >= 70 else "#e3b341" if cov_pct >= 40 else "#ff6b6b"
    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#161b22,#1c2128);border:1px solid #30363d;
                border-radius:12px;padding:20px 24px;margin-bottom:18px;">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;">
        <div>
          <div style="color:#58a6ff;font-size:1.1rem;font-weight:700;">{framework}</div>
          <div style="color:#6e7681;font-size:.8rem;">Last {days} days of event data</div>
        </div>
        <div style="display:flex;gap:24px;flex-wrap:wrap;">
          <div style="text-align:center;">
            <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">Coverage</div>
            <div style="color:{cov_color};font-size:1.6rem;font-weight:700;">{cov_pct:.0f}%</div>
          </div>
          <div style="text-align:center;">
            <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">Controls</div>
            <div style="color:#e6edf3;font-size:1.6rem;font-weight:700;">{data['covered']}/{data['total_controls']}</div>
          </div>
          <div style="text-align:center;">
            <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">Violations</div>
            <div style="color:#ff6b6b;font-size:1.6rem;font-weight:700;">{viol:,}</div>
          </div>
          <div style="text-align:center;">
            <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">Evidence</div>
            <div style="color:#56d364;font-size:1.6rem;font-weight:700;">{data['total_evidence']:,}</div>
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    col_chart, col_table = st.columns([1, 2])

    # ── Donut ─────────────────────────────────────────────────────────────────
    with col_chart:
        compliant_n  = sum(1 for c in controls if c["status"] == "compliant")
        violation_n  = sum(1 for c in controls if c["status"] == "violations")
        nocoverage_n = sum(1 for c in controls if c["status"] == "no_coverage")

        fig = go.Figure(go.Pie(
            labels=["Compliant","Violations","No Coverage"],
            values=[compliant_n, violation_n, nocoverage_n],
            hole=0.55,
            marker=dict(colors=["#238636","#da3633","#30363d"],
                        line=dict(color="#0d1117", width=2)),
            textfont=dict(color="#e6edf3", size=11),
        ))
        fig.add_annotation(text=f"{cov_pct:.0f}%<br><span style='font-size:10px'>covered</span>",
                           x=0.5, y=0.5, showarrow=False,
                           font=dict(size=18, color=cov_color))
        fig.update_layout(**_DARK, height=280, showlegend=True,
                          legend=dict(orientation="h", yanchor="bottom", y=-0.2,
                                      font=dict(color="#8b949e")))
        st.plotly_chart(fig, use_container_width=True)

    # ── Controls table ────────────────────────────────────────────────────────
    with col_table:
        st.markdown("**Control Assessment**")
        status_cfg = {
            "compliant":   ("#0d2119","#56d364","✓ Compliant"),
            "violations":  ("#3d1c1c","#ff6b6b","✗ Violations"),
            "no_coverage": ("#161b22","#6e7681","– No Coverage"),
        }
        for ctrl in controls:
            bg, color, label = status_cfg.get(ctrl["status"], status_cfg["no_coverage"])
            ev = ctrl.get("evidence_count",0)
            vl = ctrl.get("violation_count",0)
            st.markdown(f"""
            <div style="background:{bg};border:1px solid #30363d;border-left:3px solid {color};
                        border-radius:6px;padding:7px 12px;margin-bottom:4px;
                        display:flex;justify-content:space-between;align-items:center;">
              <div>
                <span style="color:#8b949e;font-size:.7rem;font-family:monospace;">{ctrl['id']}</span>
                &nbsp;
                <span style="color:#c9d1d9;font-size:.8rem;">{ctrl['name'][:45]}</span>
              </div>
              <div style="display:flex;gap:8px;align-items:center;flex-shrink:0;">
                {'<span style="color:#56d364;font-size:.7rem;">+'+str(ev)+'</span>' if ev else ''}
                {'<span style="color:#ff6b6b;font-size:.7rem;">⚠'+str(vl)+'</span>' if vl else ''}
                <span style="color:{color};font-size:.72rem;font-weight:600;">{label}</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

    # ── Violations detail ─────────────────────────────────────────────────────
    violations_ctrl = [c for c in controls if c["status"] == "violations"]
    if violations_ctrl:
        st.markdown("---")
        st.markdown(f"**Violation Details** — {len(violations_ctrl)} controls affected")
        for ctrl in violations_ctrl:
            with st.expander(f"[{ctrl['id']}] {ctrl['name']} — {ctrl['violation_count']} violations"):
                for v in ctrl.get("violation_samples", []):
                    sev = v.get("severity","")
                    c = "#ff6b6b" if sev=="CRITICAL" else "#f78166"
                    st.markdown(f"""
                    <div style="border-left:3px solid {c};padding:4px 10px;margin:4px 0;
                                color:#c9d1d9;font-size:.8rem;">
                      <strong style="color:{c};">[{sev}]</strong>
                      {v.get('source','')} @ {v.get('timestamp','')} —
                      {v.get('message','')}
                    </div>
                    """, unsafe_allow_html=True)

    # ── Coverage gaps ─────────────────────────────────────────────────────────
    no_cov = [c for c in controls if c["status"] == "no_coverage"]
    if no_cov:
        with st.expander(f"Coverage Gaps ({len(no_cov)} controls with no evidence)"):
            for ctrl in no_cov:
                st.markdown(f"- **{ctrl['id']}** — {ctrl['name']}")

    # ── PDF download ──────────────────────────────────────────────────────────
    st.markdown("---")
    col_dl, col_info = st.columns([1, 3])
    with col_dl:
        if st.button("Generate PDF Report", type="primary", use_container_width=True):
            with st.spinner("Building PDF…"):
                pdf = _get_bytes("/compliance/pdf",
                                 params={"framework": framework, "days": days})
            if pdf:
                fname = f"compliance_{framework.replace(' ','_')}.pdf"
                st.download_button("Download PDF", pdf, fname, "application/pdf",
                                   use_container_width=True)
    with col_info:
        st.markdown(f"""
        <div style="color:#6e7681;font-size:.8rem;padding-top:8px;">
          Report covers {data['total_controls']} controls · {days} days ·
          Generated {data.get('generated_at','')[:16]}
        </div>
        """, unsafe_allow_html=True)
