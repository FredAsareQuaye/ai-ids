"""
GeoIP Attack Map — visualises the geographic origins of ingested events.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter

BACKEND = BACKEND
VERIFY_SSL = False

_DARK = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0d1117",
             font_color="#c9d1d9", margin=dict(l=0,r=0,t=40,b=0))


def _get(path):
    try:
        r = requests.get(f"{BACKEND}{path}", verify=VERIFY_SSL, timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Connection error: {e}")
    return None


def render_geoip_map():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        GeoIP Attack Map
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Geographic origins of event sources enriched with IP geolocation data.
      </div>
    </div>
    """, unsafe_allow_html=True)

    col_ref, _ = st.columns([1, 5])
    with col_ref:
        if st.button("↻ Refresh"):
            st.rerun()

    geo_data = _get("/geoip") or []

    if not geo_data:
        st.info("No GeoIP data yet — events with public IPs are automatically enriched on ingestion.")
        _render_threat_source_table()
        return

    df = pd.DataFrame(geo_data)
    required = {"lat", "lon", "country", "ip"}
    if not required.issubset(df.columns):
        st.warning("GeoIP data missing required fields.")
        return

    df = df.dropna(subset=["lat", "lon"])
    if df.empty:
        st.info("No mappable coordinates found.")
        return

    # Count events per IP/country
    country_counts = df.groupby("country_code").size().reset_index(name="event_count")
    df = df.merge(country_counts, on="country_code", how="left")

    # ── KPI row ───────────────────────────────────────────────────────────────
    top_country = df.groupby("country").size().idxmax() if not df.empty else "—"
    top_ip = df.sort_values("event_count", ascending=False).iloc[0]["ip"] if not df.empty else "—"

    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, color in [
        (c1, "Unique Source IPs",   df["ip"].nunique(),      "#58a6ff"),
        (c2, "Countries",           df["country"].nunique(), "#f78166"),
        (c3, "Top Origin Country",  top_country,             "#e3b341"),
        (c4, "Most Active IP",      top_ip,                  "#d2a8ff"),
    ]:
        with col:
            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:9px;
                        padding:12px;text-align:center;border-top:3px solid {color};">
              <div style="color:#8b949e;font-size:.7rem;text-transform:uppercase;">{label}</div>
              <div style="color:{color};font-size:1.1rem;font-weight:700;word-break:break-all;">{val}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── World scatter map ─────────────────────────────────────────────────────
    fig = px.scatter_geo(
        df.drop_duplicates(subset=["ip"]),
        lat="lat", lon="lon",
        hover_name="ip",
        hover_data={"country": True, "city": True, "isp": True,
                    "event_count": True, "lat": False, "lon": False},
        color="event_count",
        color_continuous_scale="Reds",
        size="event_count",
        size_max=28,
        projection="natural earth",
        title="Attack Source Locations",
    )
    fig.update_layout(
        **_DARK,
        height=480,
        title=dict(text="Global Attack Source Map", font=dict(color="#58a6ff", size=14)),
        geo=dict(
            showframe=False, showcoastlines=True,
            coastlinecolor="rgba(80,100,130,0.6)",
            showland=True,  landcolor="#0d1117",
            showocean=True, oceancolor="#090e18",
            showlakes=False, showcountries=True,
            countrycolor="rgba(48,54,61,0.8)",
            bgcolor="#0d1117",
        ),
        coloraxis_colorbar=dict(
            title=dict(text="Events", font=dict(color="#8b949e")),
            tickfont=dict(color="#8b949e"),
            len=0.5,
        ),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Country bar chart + IP table ──────────────────────────────────────────
    col_bar, col_table = st.columns([1, 1])

    with col_bar:
        country_df = (
            df.groupby("country").size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(12)
        )
        fig2 = px.bar(
            country_df, x="count", y="country", orientation="h",
            color="count", color_continuous_scale="Reds",
            title="Top Source Countries",
            labels={"count": "IPs", "country": ""},
        )
        fig2.update_layout(
            **_DARK,
            height=360,
            title=dict(text="Top Source Countries", font=dict(color="#58a6ff", size=13)),
            xaxis=dict(gridcolor="#21262d"),
            yaxis=dict(categoryorder="total ascending", gridcolor="#21262d"),
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig2, use_container_width=True)

    with col_table:
        st.markdown("**IP Intelligence**")
        display = df.drop_duplicates(subset=["ip"]).sort_values("event_count", ascending=False)
        for _, row in display.head(12).iterrows():
            flag = _country_flag(row.get("country_code",""))
            isp_str = (row.get("isp") or row.get("org") or "—")[:30]
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:8px;padding:5px 0;
                        border-bottom:1px solid #21262d;font-size:.8rem;">
              <span style="font-size:1rem;">{flag}</span>
              <code style="color:#f78166;flex:0 0 120px;">{row['ip']}</code>
              <div style="flex:1;min-width:0;">
                <div style="color:#c9d1d9;">{row.get('city','?')}, {row.get('country','?')}</div>
                <div style="color:#6e7681;font-size:.72rem;">{isp_str}</div>
              </div>
              <span style="color:#8b949e;font-size:.72rem;">{int(row.get('event_count',1))} ev</span>
            </div>
            """, unsafe_allow_html=True)


def _country_flag(code):
    if not code or len(code) != 2:
        return "🌐"
    try:
        return chr(0x1F1E6 + ord(code[0].upper()) - ord('A')) + \
               chr(0x1F1E6 + ord(code[1].upper()) - ord('A'))
    except Exception:
        return "🌐"


def _render_threat_source_table():
    threats = None
    try:
        r = requests.get(f"{BACKEND}/threats", verify=VERIFY_SSL, timeout=30)
        if r.status_code == 200:
            threats = r.json()
    except Exception:
        pass

    if not threats:
        return
    sources = Counter(t.get("source","unknown") for t in threats)
    df = pd.DataFrame(sources.most_common(15), columns=["source","event_count"])
    st.subheader("Top Event Sources")
    st.dataframe(df, use_container_width=True, height=300)
