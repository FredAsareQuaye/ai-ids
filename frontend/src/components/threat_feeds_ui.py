"""
Threat Intelligence Feed UI — manage IOC feed syncs and browse matches.
"""
import streamlit as st
from config import BACKEND, BACKEND_BASE
import requests
import pandas as pd

BACKEND = BACKEND
VERIFY_SSL = False

FEED_ICONS = {
    "feodo_tracker": "🏴",
    "urlhaus": "🔗",
    "emerging_threats": "⚡",
}

FEED_DESCRIPTIONS = {
    "feodo_tracker": "C2 servers & botnet infrastructure IPs",
    "urlhaus": "Malware distribution URLs and domains",
    "emerging_threats": "Snort/Suricata IP blocklist from proofpoint",
}


def _api_key() -> str:
    return st.session_state.get("siem_api_key", "")


def _auth_headers() -> dict:
    return {"X-API-Key": _api_key()}


def _get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, verify=VERIFY_SSL, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"Request error: {e}")
    return None


def _post(path):
    try:
        r = requests.post(f"{BACKEND}{path}", headers=_auth_headers(), verify=VERIFY_SSL, timeout=60)
        return r
    except Exception as e:
        st.error(f"Request error: {e}")
        return None


def render_threat_feeds():
    st.markdown("""
    <div style="background:#0c1225;border:1px solid #131d35;border-left:4px solid #1db8c2;
                border-radius:6px;padding:12px 18px;margin-bottom:18px;">
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.01em;">
        Threat Intelligence Feeds
      </div>
      <div style="font-size:0.78rem;color:#6e7681;margin-top:3px;">
        Auto-syncs IOC feeds (Feodo Tracker, URLhaus, Emerging Threats) and matches
        every ingested event against the local IOC database in real-time.
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("Admin API Key", expanded=not _api_key()):
        k = st.text_input("Key (required to trigger manual sync)",
                          type="password", key="feed_api_key", value=_api_key())
        if k:
            st.session_state["siem_api_key"] = k

    ioc_data = _get("/feeds/ioc-count") or {}
    feed_status = _get("/feeds/status") or []
    matches = _get("/feeds/matches", params={"limit": 500}) or []

    total_iocs = ioc_data.get("ioc_count", 0)
    active_feeds = len(feed_status)
    total_matches = len(matches)

    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, sub, color in [
        (c1, "Total IOCs",     f"{total_iocs:,}", "in local cache",   "#58a6ff"),
        (c2, "Active Feeds",   active_feeds,       "syncing sources",  "#56d364"),
        (c3, "IOC Matches",    total_matches,      "events flagged",   "#ff6b6b"),
        (c4, "Feed Sync",      "AUTO",             "background task",  "#e3b341"),
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

    st.markdown("<br>", unsafe_allow_html=True)

    tab_feeds, tab_matches, tab_search = st.tabs(["Feed Status", "IOC Matches", "Search IOCs"])

    with tab_feeds:
        _render_feed_status(feed_status)

    with tab_matches:
        _render_matches(matches)

    with tab_search:
        _render_search()


def _render_feed_status(feed_status):
    col_sync, _ = st.columns([1, 4])
    with col_sync:
        if st.button("Force Sync All Feeds", type="primary", use_container_width=True):
            with st.spinner("Syncing feeds… this may take 30–60 seconds"):
                resp = _post("/feeds/sync")
                if resp and resp.status_code == 200:
                    st.success("Sync complete.")
                    st.rerun()
                else:
                    st.error("Sync failed — check API key and backend logs.")

    st.markdown("<br>", unsafe_allow_html=True)

    if not feed_status:
        st.info("No feed data available.")
        return

    for f in feed_status:
        fname = f.get("feed_name", "?")
        icon = FEED_ICONS.get(fname, "📡")
        desc = FEED_DESCRIPTIONS.get(fname, f.get("description", ""))
        ioc_count = f.get("ioc_count", 0)
        last = str(f.get("last_synced", "never"))[:16] or "never"
        pct = min(ioc_count / 2000 * 100, 100)

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
                    padding:16px 20px;margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
            <div style="flex:1;">
              <div style="font-size:1rem;font-weight:600;color:#e6edf3;margin-bottom:2px;">
                {icon} {fname.replace('_', ' ').title()}
              </div>
              <div style="color:#8b949e;font-size:.78rem;">{desc}</div>
            </div>
            <div style="text-align:right;flex-shrink:0;">
              <div style="color:#58a6ff;font-size:1.2rem;font-weight:700;">{ioc_count:,}</div>
              <div style="color:#6e7681;font-size:.68rem;">IOCs cached</div>
              <div style="color:#484f58;font-size:.68rem;">Last: {last}</div>
            </div>
          </div>
          <div style="background:#21262d;border-radius:4px;height:4px;margin-top:10px;overflow:hidden;">
            <div style="background:linear-gradient(90deg,#58a6ff,#56d364);
                        width:{pct:.0f}%;height:100%;border-radius:4px;"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background:#0d2119;border:1px solid #238636;border-radius:8px;
                padding:10px 14px;margin-top:8px;">
      <span style="color:#56d364;font-size:.8rem;">
        ✓ Feeds sync automatically in the background every 6 hours.
        Manual sync forces an immediate refresh of all sources.
      </span>
    </div>
    """, unsafe_allow_html=True)


def _render_matches(matches):
    if not matches:
        st.info("No IOC matches detected yet. Matches appear as events are ingested.")
        return

    st.markdown(f"""
    <div style="background:#3d1c1c;border:1px solid #ff6b6b;border-radius:8px;
                padding:10px 14px;margin-bottom:12px;">
      <span style="color:#ff6b6b;font-weight:600;">
        ⚠ {len(matches)} IOC match{'es' if len(matches) != 1 else ''} detected in ingested logs
      </span>
    </div>
    """, unsafe_allow_html=True)

    ioc_type_colors = {
        "ip": "#ff6b6b",
        "url": "#f78166",
        "domain": "#e3b341",
        "hash": "#d2a8ff",
    }

    for m in matches[:100]:
        ioc_type = m.get("ioc_type", "?")
        ioc_val = str(m.get("ioc_value", ""))[:50]
        feed = m.get("feed_name", "?").replace("_", " ").title()
        threat = m.get("threat", "") or ""
        matched_at = str(m.get("matched_at", ""))[:16]
        log_id = m.get("log_id", "?")
        tc = ioc_type_colors.get(ioc_type, "#79c0ff")

        st.markdown(f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:9px 14px;margin-bottom:5px;display:flex;
                    justify-content:space-between;align-items:center;gap:8px;">
          <div style="flex:1;min-width:0;">
            <span style="background:{tc}22;color:{tc};border:1px solid {tc}44;
                         border-radius:10px;font-size:.63rem;padding:1px 6px;margin-right:6px;">
              {ioc_type.upper()}
            </span>
            <code style="color:{tc};font-size:.8rem;">{ioc_val}</code>
            <div style="color:#8b949e;font-size:.72rem;margin-top:3px;">
              {feed}{(' · ' + threat[:40]) if threat else ''}
            </div>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <div style="color:#6e7681;font-size:.7rem;">Log #{log_id}</div>
            <div style="color:#484f58;font-size:.68rem;">{matched_at}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    df = pd.DataFrame(matches)
    if not df.empty:
        csv = df.to_csv(index=False)
        st.download_button("Export CSV", csv, "ioc_matches.csv", "text/csv")


def _render_search():
    st.markdown("**Search IOC Database**")
    query = st.text_input(
        "Search",
        placeholder="IP address, URL, domain, hash, or threat name…",
        label_visibility="collapsed",
    )

    if query:
        with st.spinner("Searching…"):
            results = _get("/feeds/search", params={"q": query, "limit": 100}) or []

        if results:
            st.markdown(f"""
            <div style="background:#0d2119;border:1px solid #238636;border-radius:8px;
                        padding:8px 14px;margin-bottom:10px;">
              <span style="color:#56d364;font-size:.82rem;">
                Found {len(results)} matching IOC{'s' if len(results) != 1 else ''}
              </span>
            </div>
            """, unsafe_allow_html=True)

            ioc_type_colors = {"ip": "#ff6b6b", "url": "#f78166",
                               "domain": "#e3b341", "hash": "#d2a8ff"}
            for r in results[:50]:
                ioc_type = r.get("ioc_type", "?")
                tc = ioc_type_colors.get(ioc_type, "#79c0ff")
                val = str(r.get("value", ""))[:60]
                threat = r.get("threat", "") or "—"
                malware = r.get("malware", "") or ""
                feed = (r.get("feed_name", "") or "").replace("_", " ").title()
                country = r.get("country", "") or ""
                added = str(r.get("added_at", ""))[:10]

                st.markdown(f"""
                <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                            padding:10px 14px;margin-bottom:5px;">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
                    <div style="flex:1;min-width:0;">
                      <span style="background:{tc}22;color:{tc};border:1px solid {tc}44;
                                   border-radius:10px;font-size:.63rem;padding:1px 6px;margin-right:6px;">
                        {ioc_type.upper()}
                      </span>
                      <code style="color:{tc};font-size:.82rem;">{val}</code>
                      <div style="color:#8b949e;font-size:.73rem;margin-top:3px;">
                        {threat}{(' · ' + malware[:30]) if malware else ''}
                      </div>
                    </div>
                    <div style="text-align:right;flex-shrink:0;">
                      <div style="color:#6e7681;font-size:.72rem;">{feed}</div>
                      <div style="color:#484f58;font-size:.68rem;">
                        {(country + ' · ') if country else ''}{added}
                      </div>
                    </div>
                  </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No matching IOCs found in local database.")
    else:
        st.markdown("""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:30px;text-align:center;margin-top:10px;">
          <div style="font-size:2rem;margin-bottom:8px;">🔍</div>
          <div style="color:#8b949e;font-size:.85rem;">
            Enter an IP, URL, domain, or threat name above to search the IOC database
          </div>
        </div>
        """, unsafe_allow_html=True)
