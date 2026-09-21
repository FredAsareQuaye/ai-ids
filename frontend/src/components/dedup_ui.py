"""
Alert Deduplication Dashboard — view grouped/suppressed alerts and noise reduction stats.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import plotly.express as px

BACKEND = BACKEND
VERIFY_SSL = False

_DARK = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0d1117",
             font_color="#c9d1d9", margin=dict(l=10,r=10,t=40,b=10))


def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, verify=VERIFY_SSL, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Request error: {e}")
    return None


def render_dedup_dashboard():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Alert Deduplication
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Identical events are grouped within a configurable window, reducing noise
        while ensuring every unique signal is preserved.
      </div>
    </div>
    """, unsafe_allow_html=True)

    col_ref, _ = st.columns([1, 5])
    with col_ref:
        if st.button("↻ Refresh"):
            st.rerun()

    stats  = _get("/dedup/stats")  or {}
    groups = _get("/dedup/groups", params={"limit": 300}) or []

    total_groups    = stats.get("total_groups", 0)
    total_suppressed = stats.get("total_suppressed", 0)
    top_hit = stats.get("top_repeated", [{}])[0].get("hit_count", 0) if stats.get("top_repeated") else 0
    noise_pct = round(total_suppressed / max(total_suppressed + total_groups, 1) * 100, 1)

    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, sub, color in [
        (c1, "Alert Groups",      total_groups,     "unique signatures", "#58a6ff"),
        (c2, "Events Suppressed", total_suppressed, "noise eliminated",  "#56d364"),
        (c3, "Highest Repeat",    top_hit,          "single alert group","#e3b341"),
        (c4, "Noise Reduction",   f"{noise_pct}%",  "of events filtered","#d2a8ff"),
    ]:
        with col:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                        padding:14px;text-align:center;border-top:3px solid {color};">
              <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">{label}</div>
              <div style="color:{color};font-size:1.8rem;font-weight:700;">{val}</div>
              <div style="color:#6e7681;font-size:.7rem;">{sub}</div>
            </div>
            """, unsafe_allow_html=True)

    if not groups:
        st.markdown("<br>", unsafe_allow_html=True)
        st.info("No deduplicated groups yet. Groups appear as repeated events arrive.")
        return

    st.markdown("<br>", unsafe_allow_html=True)
    df = pd.DataFrame(groups)

    # ── Bar chart ─────────────────────────────────────────────────────────────
    if "source" in df.columns and "hit_count" in df.columns:
        top15 = df.nlargest(15, "hit_count")
        fig = px.bar(
            top15, x="hit_count", y="source", orientation="h",
            color="hit_count", color_continuous_scale="Oranges",
            title="Top 15 Most Repeated Alert Sources",
            labels={"hit_count": "Repeat Count", "source": ""},
        )
        fig.update_layout(
            **_DARK, height=360, coloraxis_showscale=False,
            title=dict(text="Most Repeated Alert Sources", font=dict(color="#58a6ff", size=13)),
            xaxis=dict(gridcolor="#21262d"),
            yaxis=dict(categoryorder="total ascending", gridcolor="#21262d"),
        )
        st.plotly_chart(fig, use_container_width=True)

    # ── Groups table ──────────────────────────────────────────────────────────
    st.markdown("**All Alert Groups**")
    sev_color = {"CRITICAL":"#ff6b6b","HIGH":"#f78166","MEDIUM":"#e3b341",
                 "LOW":"#56d364","INFO":"#79c0ff"}

    for _, row in df.sort_values("hit_count", ascending=False).iterrows():
        hits  = int(row.get("hit_count", 1))
        sev   = str(row.get("severity","")).upper()
        src   = row.get("source","—")
        msg   = str(row.get("message",""))[:80]
        first = str(row.get("first_seen",""))[:16]
        last  = str(row.get("last_seen",""))[:16]
        sc    = sev_color.get(sev,"#79c0ff")
        width = min(hits / max(df["hit_count"].max(),1) * 100, 100)

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:10px 14px;margin-bottom:6px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
            <div style="flex:1;min-width:0;">
              <span style="color:{sc};font-size:.72rem;font-weight:700;">{sev}</span>
              &nbsp;
              <span style="color:#8b949e;font-size:.78rem;">{src}</span>
              <div style="color:#6e7681;font-size:.75rem;margin-top:2px;
                          white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{msg}</div>
              <div style="display:flex;gap:12px;margin-top:4px;">
                <span style="color:#484f58;font-size:.7rem;">First: {first}</span>
                <span style="color:#484f58;font-size:.7rem;">Last: {last}</span>
              </div>
            </div>
            <div style="text-align:right;flex-shrink:0;">
              <div style="color:#e3b341;font-size:1.2rem;font-weight:700;">{hits}×</div>
              <div style="color:#6e7681;font-size:.68rem;">suppressed</div>
            </div>
          </div>
          <div style="background:#21262d;border-radius:4px;height:4px;margin-top:8px;overflow:hidden;">
            <div style="background:linear-gradient(90deg,#e3b341,#f78166);
                        width:{width:.0f}%;height:100%;border-radius:4px;"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    csv = df.to_csv(index=False)
    st.download_button("Export CSV", csv, "dedup_groups.csv", "text/csv")
