"""
Enhanced Notification System for Real-time Log Tracking
"""
import os
import streamlit as st
import sqlite3
import requests
from datetime import datetime, timedelta
from .auth_manager import auth_manager
from .enhanced_login import get_current_user
from config import BACKEND_BASE

BACKEND_URL = BACKEND_BASE
VERIFY_SSL = False


def _api(path, method="GET", **kwargs):
    """Call backend API and return JSON or None."""
    url = f"{BACKEND_URL}/api/v1{path}"
    try:
        r = requests.request(method, url, verify=VERIFY_SSL, timeout=10, **kwargs)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def render_notification_dashboard():
    """Render the notification dashboard"""
    user = get_current_user()
    if not user:
        st.error("Authentication required")
        return

    st.title("Notifications Dashboard")

    # Log statistics from backend API
    col1, col2, col3, col4 = st.columns(4)

    threats = _api("/threats", params={"limit": 200}) or []
    if isinstance(threats, dict):
        threats = threats.get("logs", threats.get("threats", []))

    now = datetime.utcnow()
    today_str = now.strftime("%Y-%m-%d")
    hour_ago = now - timedelta(hours=1)

    total_today = 0
    last_hour = 0
    critical_count = 0
    error_count = 0

    for t in threats:
        ts = t.get("timestamp", "")
        sev = str(t.get("severity", "INFO")).upper()
        try:
            tdt = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            continue
        if tdt.strftime("%Y-%m-%d") == today_str:
            total_today += 1
        if tdt > hour_ago:
            last_hour += 1
        if sev == "CRITICAL":
            critical_count += 1
        elif sev in ("ERROR", "HIGH"):
            error_count += 1

    with col1:
        st.metric("Logs Today", total_today)
    with col2:
        st.metric("Logs Last Hour", last_hour)
    with col3:
        st.metric("Critical Logs", critical_count, delta=critical_count if critical_count > 0 else None)
    with col4:
        st.metric("High / Error Logs", error_count, delta=error_count if error_count > 0 else None)

    st.divider()

    # Notification list + settings side by side
    col_notifs, col_prefs = st.columns([2, 1])

    with col_notifs:
        st.subheader("Recent Notifications")
        _render_user_notifications(user.get("user_id") or user.get("id"))

    with col_prefs:
        st.subheader("Notification Settings")
        _render_notification_preferences(user.get("user_id") or user.get("id"))


def _render_user_notifications(user_id):
    """Render user notifications using auth_manager (direct SQLite for user prefs)."""
    notifications = auth_manager.get_user_notifications(user_id, unread_only=False)

    if not notifications:
        st.info("No notifications yet")
        return

    tab1, tab2 = st.tabs(["Unread", "All"])

    with tab1:
        unread = [n for n in notifications if not n["is_read"]]
        if unread:
            for notification in unread:
                _render_notification_item(notification, user_id)
        else:
            st.info("No unread notifications")

    with tab2:
        for notification in notifications[:10]:
            _render_notification_item(notification, user_id)


def _render_notification_item(notification, user_id):
    """Render individual notification item"""
    icon = "🔴" if not notification["is_read"] else "✅"
    with st.expander(f"{icon} {notification['type']}", expanded=not notification["is_read"]):
        st.markdown(notification["message"])
        st.caption(f"Sent: {notification['sent_at']}")

        if not notification["is_read"]:
            if st.button("Mark as Read", key=f"read_{notification['id']}_{user_id}"):
                auth_manager.mark_notification_read(notification["id"], user_id)
                st.success("Marked as read")
                st.rerun()


def _render_notification_preferences(user_id):
    """Render notification preferences form"""
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("""
        SELECT email_notifications, log_alerts, vulnerability_alerts,
               system_alerts, notification_frequency
        FROM notification_preferences WHERE user_id = ?
        """, (user_id,))

        current_prefs = cursor.fetchone()
        if not current_prefs:
            cursor.execute("""
            INSERT INTO notification_preferences (user_id)
            VALUES (?)
            """, (user_id,))
            conn.commit()
            current_prefs = (1, 1, 1, 1, "real-time")

        email_notifs, log_alerts, vuln_alerts, system_alerts, frequency = current_prefs

        with st.form("notification_preferences"):
            st.markdown("**Alert Types**")
            new_email_notifs = st.checkbox("Email Notifications", value=bool(email_notifs))
            new_log_alerts = st.checkbox("Log Alerts", value=bool(log_alerts))
            new_vuln_alerts = st.checkbox("Vulnerability Alerts", value=bool(vuln_alerts))
            new_system_alerts = st.checkbox("System Alerts", value=bool(system_alerts))

            st.markdown("**Frequency**")
            new_frequency = st.selectbox(
                "Notification Frequency",
                ["real-time", "hourly", "daily"],
                index=["real-time", "hourly", "daily"].index(frequency),
            )

            if st.form_submit_button("Save Preferences"):
                cursor.execute("""
                UPDATE notification_preferences
                SET email_notifications = ?, log_alerts = ?, vulnerability_alerts = ?,
                    system_alerts = ?, notification_frequency = ?, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                """, (new_email_notifs, new_log_alerts, new_vuln_alerts,
                      new_system_alerts, new_frequency, user_id))
                conn.commit()
                st.success("Preferences updated!")
                st.rerun()

    except Exception as e:
        st.error(f"Error loading preferences: {e}")
    finally:
        conn.close()


def render_live_log_monitor():
    """Render live log monitoring component — reads from backend API."""
    st.subheader("Live Log Monitor")

    # JS-based auto-refresh (non-blocking, no time.sleep)
    auto_refresh = st.checkbox("Auto-refresh (5 seconds)", value=True)
    if auto_refresh:
        st.components.v1.html(
            '<script>setTimeout(function(){window.parent.location.href=window.parent.location.href;},5000);</script>',
            height=0,
        )

    # Filter controls
    col_filter, col_count = st.columns([2, 1])
    with col_filter:
        severity_filter = st.selectbox(
            "Filter by severity",
            ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            index=0,
            key="live_mon_sev_filter",
        )
    with col_count:
        limit = st.slider("Max logs", 10, 100, 30, key="live_mon_limit")

    # Fetch from backend
    api_url = f"{BACKEND_URL}/api/v1/threats"
    if severity_filter != "ALL":
        api_url = f"{BACKEND_URL}/api/v1/threats/severity/{severity_filter.lower()}"

    try:
        resp = requests.get(api_url, verify=VERIFY_SSL, timeout=30)
        if resp.status_code != 200:
            st.warning(f"Backend returned status {resp.status_code}")
            return
        logs = resp.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot reach backend API. Is the backend container running?")
        return
    except Exception as e:
        st.error(f"Error fetching logs: {e}")
        return

    if isinstance(logs, dict):
        logs = logs.get("logs", logs.get("threats", []))
    logs = logs[:limit]

    if not logs:
        st.info("No logs found.")
        return

    SEV_COLOR = {
        "CRITICAL": "#e7554b",
        "HIGH":     "#f5a623",
        "MEDIUM":   "#d4c000",
        "LOW":      "#54c57d",
        "INFO":     "#2eb5e6",
    }

    # Summary bar
    sev_counts = {}
    for log in logs:
        s = str(log.get("severity", "INFO")).upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    summary_parts = " &middot; ".join(
        f'<span style="color:{SEV_COLOR.get(s, "#aaa")}">{s}: {c}</span>'
        for s, c in sorted(sev_counts.items(), key=lambda x: x[0])
    )
    st.markdown(
        f'<div style="background:#0c1225;border:1px solid #131d35;border-radius:5px;'
        f'padding:8px 14px;margin-bottom:12px;font-size:0.78rem;color:#8896c8;">'
        f"Showing <strong>{len(logs)}</strong> logs &nbsp;&middot;&nbsp; {summary_parts}</div>",
        unsafe_allow_html=True,
    )

    # Log rows
    for log in logs:
        sev = str(log.get("severity", "INFO")).upper()
        color = SEV_COLOR.get(sev, "#2eb5e6")
        source = log.get("source", "—")
        message = str(log.get("message", ""))
        timestamp = log.get("timestamp", "—")

        st.markdown(
            f'<div style="border-left:4px solid {color};padding-left:10px;margin:4px 0;'
            f'background:#0a1020;border-radius:0 4px 4px 0;padding:8px 10px;">'
            f'<span style="color:{color};font-weight:700;font-size:0.72rem;">{sev}</span>'
            f'&nbsp;&nbsp;<span style="color:#5a6a9a;font-size:0.7rem;">{source}</span>'
            f'<br><span style="color:#c8d4e8;font-size:0.8rem;">{message[:120]}{"…" if len(message) > 120 else ""}</span>'
            f'<br><span style="color:#3a4a6a;font-size:0.65rem;">{timestamp}</span>'
            f"</div>",
            unsafe_allow_html=True,
        )


def create_custom_notification(user_id, title, message, notification_type="Custom"):
    """Create a custom notification for a user"""
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("""
        INSERT INTO log_notifications (user_id, notification_type, message)
        VALUES (?, ?, ?)
        """, (user_id, title, message))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error creating custom notification: {e}")
        return False
    finally:
        conn.close()
