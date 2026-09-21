"""
UEBA Dashboard — User & Entity Behavior Analytics.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

BACKEND = BACKEND
VERIFY_SSL = False

_DARK = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0d1117",
             font_color="#c9d1d9", margin=dict(l=10,r=10,t=36,b=10))

def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, verify=VERIFY_SSL, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Connection error: {e}")
    return None


def _badge(text, color):
    return f'<span style="background:{color}22;color:{color};border:1px solid {color};border-radius:20px;font-size:0.68rem;font-weight:600;padding:2px 9px;">{text}</span>'


def render_ueba_dashboard():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        User &amp; Entity Behavior Analytics (UEBA)
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Per-user behavioral baselines &nbsp;·&nbsp; statistical anomaly detection &nbsp;·&nbsp; risk scoring
      </div>
    </div>
    """, unsafe_allow_html=True)

    col_ref, _ = st.columns([1,5])
    with col_ref:
        if st.button("↻ Refresh"):
            st.rerun()

    # Summary metrics
    scores = _get("/ueba/risk-scores") or []
    anomalies_all = _get("/ueba/anomalies", params={"limit": 500}) or []

    high_risk = sum(1 for u in scores if u.get("risk_score", 0) >= 200)
    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, color in [
        (c1, "Users Tracked", len(scores), "#58a6ff"),
        (c2, "High Risk Users", high_risk, "#ff6b6b"),
        (c3, "Anomalies Detected", len(anomalies_all), "#f78166"),
        (c4, "Anomaly Types", len({a.get("anomaly_type") for a in anomalies_all}), "#d2a8ff"),
    ]:
        with col:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                        padding:14px;text-align:center;border-top:3px solid {color};">
              <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;
                          letter-spacing:.08em;">{label}</div>
              <div style="color:{color};font-size:1.9rem;font-weight:700;">{val}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab_risk, tab_anomalies, tab_profile = st.tabs(
        ["🏆 Risk Leaderboard", "⚠️ Anomaly Feed", "🔍 User Profile"]
    )

    with tab_risk:
        _render_risk_leaderboard(scores)

    with tab_anomalies:
        _render_anomaly_events(anomalies_all)

    with tab_profile:
        _render_user_profile(scores)


def _render_risk_leaderboard(scores):
    if not scores:
        st.info("No UEBA data yet. Risk scores accumulate as user events are processed.")
        return

    df = pd.DataFrame(scores)
    if "risk_score" not in df.columns:
        return

    top = df.nlargest(20, "risk_score")

    def _bar_color(score):
        if score >= 500: return "#ff6b6b"
        if score >= 200: return "#f78166"
        if score >= 100: return "#e3b341"
        return "#56d364"

    fig = go.Figure()
    for _, row in top.iterrows():
        fig.add_trace(go.Bar(
            x=[row["risk_score"]], y=[row["username"]],
            orientation="h",
            marker_color=_bar_color(row["risk_score"]),
            showlegend=False,
            hovertemplate=f"<b>{row['username']}</b><br>Risk: {row['risk_score']:.0f}<extra></extra>",
        ))

    fig.update_layout(
        **_DARK,
        title=dict(text="Top 20 Riskiest Users", font=dict(color="#58a6ff", size=14)),
        xaxis=dict(gridcolor="#21262d", title="Risk Score"),
        yaxis=dict(categoryorder="total ascending", gridcolor="#21262d"),
        height=420, barmode="overlay",
    )
    st.plotly_chart(fig, use_container_width=True)

    # Table with colour-coded risk
    st.markdown("#### All Users")
    for _, row in df.sort_values("risk_score", ascending=False).iterrows():
        score = row.get("risk_score", 0)
        color = "#ff6b6b" if score >= 500 else "#f78166" if score >= 200 else "#e3b341" if score >= 100 else "#56d364"
        risk_label = "CRITICAL" if score >= 500 else "HIGH" if score >= 200 else "MEDIUM" if score >= 100 else "LOW"
        lu = str(row.get("last_updated",""))[:10]
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:12px;padding:7px 0;
                    border-bottom:1px solid #21262d;">
          <div style="width:140px;color:#e6edf3;font-weight:600;">{row['username']}</div>
          {_badge(risk_label, color)}
          <div style="flex:1;">
            <div style="background:#21262d;border-radius:4px;height:6px;overflow:hidden;">
              <div style="background:{color};width:{min(score/10,100):.0f}%;height:100%;border-radius:4px;"></div>
            </div>
          </div>
          <div style="color:{color};font-weight:700;min-width:60px;text-align:right;">{score:.0f}</div>
          <div style="color:#484f58;font-size:.72rem;min-width:80px;">{lu}</div>
        </div>
        """, unsafe_allow_html=True)


def _render_anomaly_events(anomalies):
    if not anomalies:
        st.info("No UEBA anomalies detected yet.")
        return

    st.success(f"**{len(anomalies)}** behavioral anomalies detected")

    type_colors = {"New Source IP": "#58a6ff", "Unusual Login Hour": "#f78166",
                   "High Event Rate": "#e3b341"}

    for a in anomalies[:50]:
        atype = a.get("anomaly_type","?")
        color = type_colors.get(atype, "#d2a8ff")
        ts = str(a.get("fired_at",""))[:16]
        z = a.get("z_score")
        z_str = f"z={z:.1f}" if z else ""
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {color};
                    border-radius:8px;padding:10px 14px;margin-bottom:6px;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;">
            <div>
              <span style="color:{color};font-weight:700;font-size:.85rem;">{atype}</span>
              &nbsp;·&nbsp;<span style="color:#8b949e;font-size:.78rem;">{a.get('username','?')}</span>
              {f'&nbsp;<span style="color:#484f58;font-size:.72rem;">{z_str}</span>' if z_str else ''}
            </div>
            <div style="color:#484f58;font-size:.72rem;">{ts}</div>
          </div>
          <div style="color:#8b949e;font-size:.8rem;margin-top:4px;">{a.get('description','')}</div>
          {f'<div style="color:#6e7681;font-size:.72rem;margin-top:3px;">IP: {a.get("source_ip","")}</div>' if a.get("source_ip") else ''}
        </div>
        """, unsafe_allow_html=True)

    df = pd.DataFrame(anomalies)
    csv = df.to_csv(index=False)
    st.download_button("Export CSV", csv, "ueba_anomalies.csv", "text/csv")


def _render_user_profile(scores):
    users = [s["username"] for s in scores] if scores else []
    extra_users = _get("/ueba/users") or []
    all_users = list(dict.fromkeys(users + extra_users))

    if not all_users:
        st.info("No users tracked yet.")
        return

    selected = st.selectbox("Select user", all_users, key="ueba_user_select")
    if not selected:
        return

    profile = _get(f"/ueba/users/{selected}")
    if not profile:
        st.error("Could not load profile.")
        return

    score = profile.get("risk_score", 0)
    color = "#ff6b6b" if score >= 500 else "#f78166" if score >= 200 else "#e3b341" if score >= 100 else "#56d364"

    st.markdown(f"""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                padding:16px 20px;margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
          <span style="color:#e6edf3;font-size:1.1rem;font-weight:700;">👤 {selected}</span>
        </div>
        <div style="text-align:right;">
          <div style="color:#8b949e;font-size:.72rem;">RISK SCORE</div>
          <div style="color:{color};font-size:1.8rem;font-weight:700;">{score:.0f}</div>
        </div>
      </div>
      <div style="background:#21262d;border-radius:4px;height:8px;margin-top:10px;overflow:hidden;">
        <div style="background:linear-gradient(90deg,{color},{color}88);
                    width:{min(score/10,100):.0f}%;height:100%;border-radius:4px;"></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    col_hours, col_ips = st.columns(2)

    with col_hours:
        hours = profile.get("hour_distribution", [])
        if hours:
            df_h = pd.DataFrame(hours)
            # All 24 hours
            full = pd.DataFrame({"hour_of_day": range(24)})
            df_h = full.merge(df_h, on="hour_of_day", how="left").fillna(0)
            fig = px.bar(df_h, x="hour_of_day", y="mean",
                         title="Activity by Hour of Day",
                         labels={"hour_of_day":"Hour (24h)","mean":"Avg events"},
                         color="mean", color_continuous_scale="Blues")
            fig.update_layout(**_DARK, height=240, coloraxis_showscale=False,
                              title=dict(text="Activity by Hour", font=dict(color="#58a6ff",size=13)))
            fig.update_xaxes(tickvals=list(range(0,24,3)), gridcolor="#21262d")
            fig.update_yaxes(gridcolor="#21262d")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hour data.")

    with col_ips:
        ips = profile.get("known_ips", [])
        if ips:
            st.markdown("**Known Source IPs**")
            for ip_row in sorted(ips, key=lambda x: -x.get("hit_count",0)):
                hits = ip_row.get("hit_count", 0)
                is_new = hits <= 2
                ip_color = "#ff6b6b" if is_new else "#56d364"
                st.markdown(f"""
                <div style="display:flex;justify-content:space-between;align-items:center;
                            padding:5px 0;border-bottom:1px solid #21262d;font-size:.82rem;">
                  <code style="color:{ip_color};">{ip_row['ip_address']}</code>
                  {_badge('NEW','#ff6b6b') if is_new else ''}
                  <span style="color:#6e7681;">{hits:,} hits</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No IP data.")

    st.markdown("**Recent Anomalies**")
    anomalies = profile.get("recent_anomalies", [])
    if anomalies:
        for a in anomalies:
            st.warning(f"**{a.get('anomaly_type')}** @ {str(a.get('fired_at',''))[:16]}  \n{a.get('description','')}")
    else:
        st.success("No anomalies detected for this user.")
