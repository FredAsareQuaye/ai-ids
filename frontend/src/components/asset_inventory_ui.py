"""
Asset Inventory UI — manage monitored hosts, view criticality, and track risk scores.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd
import plotly.graph_objects as go

BACKEND = BACKEND
VERIFY_SSL = False

CRITICALITIES = ["critical", "high", "medium", "low"]

CRIT_COLORS = {
    "critical": "#ff6b6b",
    "high":     "#f78166",
    "medium":   "#e3b341",
    "low":      "#56d364",
}

CRIT_BG = {
    "critical": "#3d1c1c",
    "high":     "#2d1f0e",
    "medium":   "#2d2108",
    "low":      "#0d2119",
}

_DARK = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0d1117",
             font_color="#c9d1d9", margin=dict(l=10, r=10, t=40, b=10))


def _api_key() -> str:
    return st.session_state.get("siem_api_key", "")


def _auth_headers() -> dict:
    return {"X-API-Key": _api_key()}


def _get(path):
    try:
        r = requests.get(f"{BACKEND}{path}", verify=VERIFY_SSL, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Request error: {e}")
    return None


def _post(path, payload):
    try:
        return requests.post(f"{BACKEND}{path}", json=payload,
                             headers=_auth_headers(), verify=VERIFY_SSL, timeout=10)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None


def _put(path, payload):
    try:
        return requests.put(f"{BACKEND}{path}", json=payload,
                            headers=_auth_headers(), verify=VERIFY_SSL, timeout=10)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None


def _delete(path):
    try:
        return requests.delete(f"{BACKEND}{path}",
                               headers=_auth_headers(), verify=VERIFY_SSL, timeout=10)
    except Exception as e:
        st.error(f"Request error: {e}")
        return None


def render_asset_inventory():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Asset Inventory
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Register and manage monitored hosts. Critical assets automatically receive
        severity boosts during log processing, ensuring high-priority alerts surface first.
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("Admin API Key", expanded=not _api_key()):
        k = st.text_input("Key (required to add / edit / remove assets)",
                          type="password", key="asset_api_key", value=_api_key())
        if k:
            st.session_state["siem_api_key"] = k

    assets = _get("/assets") or []

    crit_count   = sum(1 for a in assets if a.get("criticality") == "critical")
    high_count   = sum(1 for a in assets if a.get("criticality") == "high")
    medium_count = sum(1 for a in assets if a.get("criticality") == "medium")
    low_count    = sum(1 for a in assets if a.get("criticality") == "low")

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, val, color in [
        (c1, "Total Assets", len(assets),   "#58a6ff"),
        (c2, "Critical",     crit_count,    "#ff6b6b"),
        (c3, "High",         high_count,    "#f78166"),
        (c4, "Medium",       medium_count,  "#e3b341"),
        (c5, "Low",          low_count,     "#56d364"),
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

    tab_assets, tab_risk, tab_add = st.tabs(
        ["Asset Registry", "Risk Leaderboard", "Add / Edit Asset"]
    )

    with tab_assets:
        _render_asset_registry(assets)

    with tab_risk:
        _render_risk_leaderboard()

    with tab_add:
        _render_add_asset_form()


def _render_asset_registry(assets):
    if not assets:
        st.info("No assets registered yet. Use the 'Add / Edit Asset' tab to register hosts.")
        return

    crit_filter = st.multiselect(
        "Filter by criticality",
        CRITICALITIES,
        default=[],
        key="asset_filter",
    )
    filtered = assets if not crit_filter else [
        a for a in assets if a.get("criticality") in crit_filter
    ]

    for a in filtered:
        crit = (a.get("criticality") or "low").lower()
        cc = CRIT_COLORS.get(crit, "#79c0ff")
        cbg = CRIT_BG.get(crit, "#161b22")
        hostname = a.get("hostname", "—")
        ip = a.get("ip_address") or a.get("cidr_range") or "—"
        owner = a.get("owner") or "—"
        desc = (a.get("description") or "")[:60]
        tags = a.get("tags") or []
        tag_html = "".join(
            f'<span style="background:#21262d;color:#8b949e;border-radius:8px;'
            f'font-size:.62rem;padding:1px 6px;margin-right:3px;">{t}</span>'
            for t in tags[:5]
        )

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                    padding:12px 16px;margin-bottom:7px;border-left:4px solid {cc};">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;">
            <div style="flex:1;min-width:0;">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
                <span style="background:{cbg};color:{cc};border:1px solid {cc};
                             border-radius:10px;font-size:.62rem;font-weight:700;padding:1px 7px;">
                  {crit.upper()}
                </span>
                <span style="color:#e6edf3;font-weight:600;font-size:.9rem;">{hostname}</span>
              </div>
              <div style="color:#8b949e;font-size:.78rem;margin-bottom:4px;">
                <code style="background:#21262d;color:#79c0ff;padding:1px 5px;border-radius:3px;">
                  {ip}
                </code>
                &nbsp;·&nbsp;
                <span style="color:#6e7681;">Owner: {owner}</span>
              </div>
              {f'<div style="color:#6e7681;font-size:.75rem;margin-bottom:4px;">{desc}</div>' if desc else ''}
              <div>{tag_html}</div>
            </div>
            <div style="text-align:right;flex-shrink:0;">
              <span style="color:#484f58;font-size:.7rem;">#{a.get('id','?')}</span>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>**Remove Asset**")
    col_id, col_del = st.columns([2, 1])
    with col_id:
        del_id = st.number_input("Asset ID", min_value=1, step=1, key="del_asset_id",
                                 label_visibility="collapsed")
    with col_del:
        if st.button("Remove Asset", use_container_width=True):
            resp = _delete(f"/assets/{del_id}")
            if resp and resp.status_code == 200:
                st.success(f"Asset #{del_id} removed.")
                st.rerun()
            else:
                st.error("Failed — check API key.")


def _render_risk_leaderboard():
    scores = _get("/assets/risk-scores") or []

    if not scores:
        st.info("No risk data yet. Scores accumulate as events match registered assets.")
        return

    st.markdown("""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                padding:10px 14px;margin-bottom:14px;">
      <span style="color:#8b949e;font-size:.78rem;">
        Risk Score = CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1 events (past 7 days)
      </span>
    </div>
    """, unsafe_allow_html=True)

    df = pd.DataFrame(scores)
    if "rank" not in df.columns:
        df.insert(0, "rank", range(1, len(df) + 1))

    if "risk_score" in df.columns and "hostname" in df.columns:
        top15 = df.head(15).copy()
        max_score = top15["risk_score"].max() or 1

        bar_colors = []
        for _, row in top15.iterrows():
            pct = row["risk_score"] / max_score
            if pct >= 0.8:
                bar_colors.append("#ff6b6b")
            elif pct >= 0.5:
                bar_colors.append("#f78166")
            elif pct >= 0.25:
                bar_colors.append("#e3b341")
            else:
                bar_colors.append("#56d364")

        fig = go.Figure(go.Bar(
            x=top15["risk_score"],
            y=top15["hostname"],
            orientation="h",
            marker=dict(color=bar_colors),
            text=top15["risk_score"],
            textposition="outside",
            textfont=dict(color="#c9d1d9", size=11),
        ))
        fig.update_layout(
            **_DARK,
            height=380,
            title=dict(text="Asset Risk Leaderboard", font=dict(color="#58a6ff", size=13)),
            xaxis=dict(gridcolor="#21262d", title="Risk Score"),
            yaxis=dict(categoryorder="total ascending", gridcolor="#21262d"),
        )
        st.plotly_chart(fig, use_container_width=True)

    for _, row in df.iterrows():
        crit = str(row.get("criticality", "low")).lower()
        cc = CRIT_COLORS.get(crit, "#79c0ff")
        score = int(row.get("risk_score", 0))
        max_score = df["risk_score"].max() or 1
        width = min(score / max_score * 100, 100)
        rank = int(row.get("rank", 0))

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:9px 14px;margin-bottom:5px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
            <div style="display:flex;align-items:center;gap:8px;flex:1;">
              <span style="color:#484f58;font-size:.8rem;font-weight:700;min-width:20px;">
                #{rank}
              </span>
              <div style="flex:1;min-width:0;">
                <span style="color:#e6edf3;font-size:.85rem;font-weight:600;">
                  {row.get('hostname','?')}
                </span>
                <span style="color:#6e7681;font-size:.72rem;margin-left:8px;">
                  {row.get('ip_address','') or ''}
                </span>
              </div>
            </div>
            <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
              <span style="background:{cc}22;color:{cc};border:1px solid {cc}44;
                           border-radius:8px;font-size:.62rem;padding:1px 6px;">
                {crit.upper()}
              </span>
              <span style="color:{cc};font-size:1rem;font-weight:700;">{score}</span>
              <span style="color:#6e7681;font-size:.7rem;">pts</span>
            </div>
          </div>
          <div style="background:#21262d;border-radius:4px;height:3px;margin-top:7px;overflow:hidden;">
            <div style="background:{cc};width:{width:.0f}%;height:100%;border-radius:4px;"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)


def _render_add_asset_form():
    st.markdown("""
    <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                padding:10px 14px;margin-bottom:14px;">
      <span style="color:#8b949e;font-size:.78rem;">
        Leave <strong style="color:#c9d1d9;">Asset ID</strong> at 0 to register a new asset.
        Enter an existing ID to update it.
      </span>
    </div>
    """, unsafe_allow_html=True)

    with st.form("asset_form"):
        asset_id = st.number_input("Asset ID (0 = new)", min_value=0, step=1, value=0)

        col1, col2 = st.columns(2)
        with col1:
            hostname = st.text_input("Hostname *", placeholder="web-server-01")
            ip_address = st.text_input("IP Address", placeholder="192.168.1.10")
            cidr_range = st.text_input("CIDR Range", placeholder="192.168.1.0/24")
        with col2:
            criticality = st.selectbox("Criticality", CRITICALITIES, index=2)
            owner = st.text_input("Owner", placeholder="security-team@company.com")

        description = st.text_area("Description", placeholder="Describe the asset and its role…",
                                   height=80)
        tags = st.text_input("Tags (comma-separated)", placeholder="linux, web, production")

        submitted = st.form_submit_button("Save Asset", type="primary", use_container_width=True)

    if submitted:
        if not hostname.strip():
            st.error("Hostname is required.")
            return

        payload = {
            "hostname": hostname.strip(),
            "ip_address": ip_address.strip() or None,
            "cidr_range": cidr_range.strip() or None,
            "criticality": criticality,
            "owner": owner.strip() or None,
            "description": description.strip() or None,
            "tags": [t.strip() for t in tags.split(",") if t.strip()],
        }

        if asset_id > 0:
            resp = _put(f"/assets/{asset_id}", payload)
            if resp and resp.status_code == 200:
                st.success(f"Asset #{asset_id} updated.")
                st.rerun()
            else:
                st.error("Failed to update asset — check API key.")
        else:
            resp = _post("/assets", payload)
            if resp and resp.status_code == 200:
                new_id = resp.json().get("id")
                st.success(f"Asset #{new_id} registered successfully.")
                st.rerun()
            else:
                detail = resp.json().get("detail", "Unknown error") if resp else "No response"
                st.error(f"Failed: {detail}")
