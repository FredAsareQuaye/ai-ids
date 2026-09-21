import streamlit as st
import os
import json
import hashlib
import sqlite3
import requests  # type: ignore
import time
from pathlib import Path
from components.page_style import inject_page_css, page_header
from config import BACKEND_BASE

SETTINGS_FILE = Path("./data/user_settings.json")


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------
def load_settings():
    defaults = {
        "username": "admin",
        "ai_enabled": False,
        "theme": "dark",
        "notifications": True,
        "refresh_rate": 30,
    }
    if "ai_mode" not in st.session_state:
        st.session_state.ai_mode = defaults["ai_enabled"]
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, "r") as f:
                return {**defaults, **json.load(f)}
    except Exception as e:
        st.error(f"Error loading settings: {e}")
    return defaults


def save_settings(settings):
    try:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        st.error(f"Error saving settings: {e}")
        return False


def wipe_all_logs():
    try:
        try:
            from utils.api import create_session
            import os
            api_key = os.environ.get("SIEM_API_KEY", "")
            session = create_session()
            headers = {}
            if api_key:
                headers["X-API-Key"] = api_key
            r = session.delete(f"{BACKEND_BASE}/api/v1/logs",
                               headers=headers, verify=False, timeout=10)
            if r.status_code == 200:
                return True
        except Exception:
            pass

        db_paths = [
            "./data/siem.db", "../data/siem.db", "../server/siem.db",
            "../../server/siem.db", "./frontend/data/siem.db", "./server/siem.db",
        ]
        for db_path in db_paths:
            try:
                if os.path.exists(db_path):
                    with sqlite3.connect(db_path) as conn:
                        for tbl in ("logs", "security_logs", "threats", "events"):
                            try:
                                conn.execute(f"DELETE FROM {tbl}")
                                conn.execute(f"DELETE FROM sqlite_sequence WHERE name='{tbl}'")
                            except sqlite3.OperationalError:
                                pass
                        conn.commit()
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------
def render_settings():
    inject_page_css()
    settings = load_settings()

    page_header("Settings", "Manage your account, AI features, and system preferences")

    # Tab navigation
    tab_profile, tab_security, tab_ai, tab_prefs, tab_users, tab_danger = st.tabs([
        "Profile", "Security", "AI & API", "Preferences", "Users", "Danger Zone",
    ])

    # ── Profile ────────────────────────────────────────────────────────────
    with tab_profile:
        st.markdown("<div style='max-width:480px'>", unsafe_allow_html=True)
        _section_label("Account details")

        with st.form("profile_form"):
            new_username = st.text_input("Username", value=settings.get("username", "admin"))
            change_pwd   = st.checkbox("Change password")

            current_password = confirm_password = new_password = ""
            if change_pwd:
                current_password = st.text_input("Current password", type="password")
                new_password     = st.text_input("New password", type="password")
                confirm_password = st.text_input("Confirm new password", type="password")

            submitted = st.form_submit_button("Save profile", type="primary")

        if submitted:
            if not new_username:
                st.error("Username cannot be empty.")
            elif change_pwd:
                if new_password != confirm_password:
                    st.error("New passwords do not match.")
                elif new_password:
                    settings["password_hash"] = hashlib.sha256(new_password.encode()).hexdigest()
                    settings["username"] = new_username
                    if save_settings(settings):
                        st.success("Profile updated. Please sign in again with your new password.")
                        st.session_state.username    = new_username
                        st.session_state.authenticated = False
                        st.rerun()
            else:
                settings["username"] = new_username
                if save_settings(settings):
                    st.session_state.username = new_username
                    st.success("Profile saved.")

        st.markdown("</div>", unsafe_allow_html=True)

    # ── Security / 2FA ─────────────────────────────────────────────────────
    with tab_security:
        st.markdown("<div style='max-width:480px'>", unsafe_allow_html=True)
        _section_label("Two-Factor Authentication (TOTP)")
        user_data = st.session_state.get("user_data", {})
        user_id   = user_data.get("user_id") or user_data.get("id") if user_data else None
        if user_id:
            render_2fa_settings(user_id)
        else:
            st.warning("Session not found — please sign in again.")
        st.markdown("</div>", unsafe_allow_html=True)

    # ── AI & API ───────────────────────────────────────────────────────────
    with tab_ai:
        st.markdown("<div style='max-width:520px'>", unsafe_allow_html=True)
        _section_label("AI features")

        ai_enabled = st.toggle(
            "Enable AI-powered analysis",
            value=st.session_state.get("ai_mode", False),
            help="Enables DeepSeek-based scan analysis and SIEM insights",
        )
        if ai_enabled != st.session_state.get("ai_mode", False):
            st.session_state.ai_mode    = ai_enabled
            st.session_state.ai_enabled = ai_enabled
            settings["ai_enabled"]      = ai_enabled
            st.session_state.settings   = settings
            save_settings(settings)
            st.rerun()

        if ai_enabled:
            st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
            _section_label("DeepSeek API key")

            env_path     = Path("../server/.env")
            ai_configured = False
            if env_path.exists():
                try:
                    ai_configured = "OPENROUTER_API_KEY" in env_path.read_text()
                except Exception:
                    pass

            if ai_configured:
                st.markdown(
                    "<div style='display:flex;align-items:center;gap:8px;font-size:13px;"
                    "color:#16a34a;background:#051a0d;border:1px solid #14532d;"
                    "border-radius:6px;padding:8px 12px;margin-bottom:12px'>"
                    "<span>&#10003;</span> API key is configured</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<div style='font-size:13px;color:#d97706;background:#1a1005;"
                    "border:1px solid #92400e;border-radius:6px;"
                    "padding:8px 12px;margin-bottom:12px'>"
                    "No API key configured</div>",
                    unsafe_allow_html=True,
                )

            with st.form("api_key_form"):
                api_key   = st.text_input("API key", type="password", placeholder="sk-…")
                save_key  = st.form_submit_button("Save API key", type="primary")

            if save_key:
                if not api_key:
                    st.error("Enter a valid API key.")
                else:
                    try:
                        env_path.parent.mkdir(parents=True, exist_ok=True)
                        env_vars = {}
                        if env_path.exists():
                            for line in env_path.read_text().splitlines():
                                line = line.strip()
                                if line and not line.startswith("#") and "=" in line:
                                    k, v = line.split("=", 1)
                                    env_vars[k] = v
                        env_vars["OPENROUTER_API_KEY"] = api_key
                        with open(env_path, "w") as f:
                            f.write("\n".join(f"{k}={v}" for k, v in env_vars.items()) + "\n")
                        st.success("API key saved.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to save: {e}")
        else:
            st.markdown(
                "<div style='font-size:13px;color:#4a5568;margin-top:8px'>"
                "Enable the toggle above to configure AI settings.</div>",
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)

    # ── Preferences ────────────────────────────────────────────────────────
    with tab_prefs:
        st.markdown("<div style='max-width:480px'>", unsafe_allow_html=True)
        _section_label("Display & notifications")

        with st.form("prefs_form"):
            notifications = st.checkbox(
                "Enable desktop notifications",
                value=settings.get("notifications", True),
            )
            refresh_rate = st.slider(
                "Dashboard refresh interval (seconds)",
                10, 300, settings.get("refresh_rate", 30), 10,
            )
            submitted = st.form_submit_button("Save preferences", type="primary")

        if submitted:
            settings["notifications"] = notifications
            settings["refresh_rate"]  = refresh_rate
            if save_settings(settings):
                st.session_state.settings = settings
                st.success("Preferences saved.")

        st.markdown("</div>", unsafe_allow_html=True)

    # ── User Management ────────────────────────────────────────────────────
    with tab_users:
        if st.session_state.get("user_data", {}).get("role") == "admin":
            render_user_management_in_settings()
        else:
            st.info("Administrator access required to manage users.")

    # ── Danger Zone ────────────────────────────────────────────────────────
    with tab_danger:
        st.markdown("<div style='max-width:560px'>", unsafe_allow_html=True)
        st.markdown(
            "<div style='border:1px solid #7f1d1d;border-radius:8px;"
            "padding:20px 24px;background:#0d0505;margin-bottom:24px'>"
            "<div style='font-size:13px;font-weight:700;color:#ef4444;"
            "text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px'>"
            "Danger Zone</div>"
            "<div style='font-size:13px;color:#64748b;line-height:1.6'>"
            "Actions in this section are permanent and cannot be undone. "
            "Proceed only if you know what you are doing.</div>"
            "</div>",
            unsafe_allow_html=True,
        )

        _section_label("Clear all security logs")

        # Try to get log count
        log_count_str = "all security logs"
        try:
            from utils.api import create_session
            r = create_session().get(f"{BACKEND_BASE}/api/v1/threats", verify=False, timeout=3)
            if r.status_code == 200:
                n = len(r.json())
                log_count_str = f"{n} log entries" if n else "0 logs (database is empty)"
        except Exception:
            pass

        st.markdown(
            f"<div style='font-size:13px;color:#64748b;margin-bottom:16px'>"
            f"This will permanently delete {log_count_str} from the SIEM database.</div>",
            unsafe_allow_html=True,
        )

        if "confirm_wipe" not in st.session_state:
            st.session_state.confirm_wipe = False

        if not st.session_state.confirm_wipe:
            if st.button("Delete all logs", type="secondary"):
                st.session_state.confirm_wipe = True
                st.rerun()
        else:
            st.markdown(
                "<div style='font-size:13px;color:#f97316;font-weight:600;"
                "margin-bottom:12px'>Are you sure? This cannot be undone.</div>",
                unsafe_allow_html=True,
            )
            c1, c2, _ = st.columns([1, 1, 3])
            with c1:
                if st.button("Confirm delete", type="primary"):
                    if wipe_all_logs():
                        for k in list(st.session_state.keys()):
                            if k.startswith("compliance_") or k.startswith("cached_"):
                                del st.session_state[k]
                        st.success("All security logs deleted.")
                    else:
                        st.error("Failed — check database connection.")
                    st.session_state.confirm_wipe = False
                    st.rerun()
            with c2:
                if st.button("Cancel"):
                    st.session_state.confirm_wipe = False
                    st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Section label helper
# ---------------------------------------------------------------------------
def _section_label(text: str):
    st.markdown(
        f"<div style='font-size:11px;font-weight:700;text-transform:uppercase;"
        f"letter-spacing:.08em;color:#334155;margin:20px 0 10px'>{text}</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------
def render_user_management_in_settings():
    from components.login import init_enhanced_database, hash_password, DB_PATH

    init_enhanced_database()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    except Exception:
        user_count = 0

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Total users", user_count)
    with c2:
        st.metric("Database", "Connected")
    with c3:
        if st.button("Refresh", key="refresh_users"):
            st.rerun()

    st.markdown("<hr>", unsafe_allow_html=True)
    _section_label("Add new user")

    with st.form("add_user_form", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            new_uname = st.text_input("Username", placeholder="jsmith")
            new_pwd   = st.text_input("Password", type="password")
        with col2:
            new_email = st.text_input("Email", placeholder="jane@company.com")
            new_role  = st.selectbox("Role", ["user", "admin"])

        c1, _ = st.columns([1, 3])
        with c1:
            submitted = st.form_submit_button("Add user", type="primary", use_container_width=True)

    if submitted:
        if not new_uname or not new_pwd:
            st.error("Username and password are required.")
        elif len(new_uname.strip()) < 3:
            st.error("Username must be at least 3 characters.")
        elif len(new_pwd) < 4:
            st.error("Password must be at least 4 characters.")
        else:
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    exists = conn.execute(
                        "SELECT COUNT(*) FROM users WHERE username=?", (new_uname.strip(),)
                    ).fetchone()[0]
                    if exists:
                        st.error(f"Username '{new_uname}' already exists.")
                    else:
                        conn.execute(
                            "INSERT INTO users (username,password_hash,email,role,active,failed_attempts) VALUES (?,?,?,?,1,0)",
                            (new_uname.strip(), hash_password(new_pwd), new_email.strip() or None, new_role),
                        )
                        conn.commit()
                        st.success(f"User '{new_uname}' created with role '{new_role}'.")
                        time.sleep(1)
                        st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")

    st.markdown("<hr>", unsafe_allow_html=True)
    _section_label("Current users")

    try:
        with sqlite3.connect(DB_PATH) as conn:
            try:
                users = conn.execute(
                    "SELECT id,username,COALESCE(email,'—'),COALESCE(role,'user'),"
                    "COALESCE(active,1),COALESCE(failed_attempts,0),created_at "
                    "FROM users ORDER BY created_at DESC"
                ).fetchall()
            except sqlite3.OperationalError:
                users = conn.execute(
                    'SELECT id,username,"—","user",1,0,created_at FROM users ORDER BY created_at DESC'
                ).fetchall()

        for uid, uname, email, role, active, fails, created in users:
            with st.container():
                c1, c2, c3, c4 = st.columns([3, 3, 2, 1])
                status_dot = (
                    '<span style="color:#22c55e;font-size:8px">&#9679;</span>'
                    if active else
                    '<span style="color:#ef4444;font-size:8px">&#9679;</span>'
                )
                role_badge = (
                    '<span style="font-size:10px;color:#1ec8ff;background:#0d2040;'
                    'padding:1px 7px;border-radius:4px;border:1px solid #1e3a5f;font-weight:600">ADMIN</span>'
                    if role == "admin" else
                    '<span style="font-size:10px;color:#64748b;background:#131c2e;'
                    'padding:1px 7px;border-radius:4px;border:1px solid #1e2d3d;font-weight:600">USER</span>'
                )
                with c1:
                    st.markdown(
                        f"{status_dot} <span style='font-size:14px;font-weight:600;"
                        f"color:#e2e8f0'>{uname}</span> &nbsp;{role_badge}",
                        unsafe_allow_html=True,
                    )
                with c2:
                    st.markdown(
                        f"<span style='font-size:13px;color:#4a5568'>{email}</span>",
                        unsafe_allow_html=True,
                    )
                    if fails:
                        st.markdown(
                            f"<span style='font-size:11px;color:#d97706'>{fails} failed login(s)</span>",
                            unsafe_allow_html=True,
                        )
                with c3:
                    st.markdown(
                        f"<span style='font-size:11px;color:#334155'>{str(created)[:16]}</span>",
                        unsafe_allow_html=True,
                    )
                with c4:
                    if uname != st.session_state.get("username"):
                        action = "Activate" if not active else "Deactivate"
                        if st.button(action, key=f"toggle_{uid}", use_container_width=True):
                            with sqlite3.connect(DB_PATH) as conn:
                                conn.execute("UPDATE users SET active=? WHERE id=?", (not active, uid))
                                conn.commit()
                            st.rerun()
                st.markdown("<div style='border-bottom:1px solid #1a2235;margin:8px 0'></div>", unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Error loading users: {e}")


# ---------------------------------------------------------------------------
# 2FA settings (unchanged logic, cleaned UI)
# ---------------------------------------------------------------------------
def render_2fa_settings(user_id: int):
    from components.auth_manager import auth_manager, TOTP_AVAILABLE

    if not TOTP_AVAILABLE:
        st.warning("Install pyotp and qrcode: `pip install pyotp qrcode[pil]`")
        return

    status = auth_manager.get_user_2fa_status(user_id)

    if status.get("enabled"):
        st.markdown(
            "<div style='font-size:13px;color:#22c55e;background:#051a0d;"
            "border:1px solid #14532d;border-radius:6px;padding:10px 14px;"
            "margin-bottom:16px'>Two-factor authentication is enabled on this account.</div>",
            unsafe_allow_html=True,
        )
        if st.button("Disable 2FA", type="secondary"):
            auth_manager.disable_totp(user_id)
            st.success("Two-factor authentication disabled.")
            st.rerun()
    else:
        st.markdown(
            "<div style='font-size:13px;color:#4a5568;background:#131c2e;"
            "border:1px solid #1a2235;border-radius:6px;padding:10px 14px;"
            "margin-bottom:16px'>2FA is not enabled. Add an extra layer of security to your account.</div>",
            unsafe_allow_html=True,
        )
        if st.button("Set up 2FA", type="primary"):
            setup = auth_manager.setup_totp(user_id)
            if setup:
                st.session_state["totp_setup"] = setup

        setup = st.session_state.get("totp_setup")
        if setup:
            st.markdown(
                "<div style='font-size:13px;color:#94a3b8;margin-bottom:12px'>"
                "Scan the QR code with Google Authenticator, Authy, or any TOTP app.</div>",
                unsafe_allow_html=True,
            )
            if setup.get("qr_png"):
                st.image(setup["qr_png"], width=200)
            st.markdown(
                "<div style='font-size:12px;color:#4a5568;margin:8px 0 4px'>Or enter this key manually:</div>",
                unsafe_allow_html=True,
            )
            st.code(setup["secret"], language=None)

            with st.form("confirm_2fa_form"):
                code = st.text_input("Enter code from app", max_chars=6, placeholder="123456")
                ok   = st.form_submit_button("Enable 2FA", type="primary")
                if ok:
                    success, msg = auth_manager.enable_totp(user_id, code)
                    if success:
                        st.success(msg)
                        st.session_state.pop("totp_setup", None)
                        st.rerun()
                    else:
                        st.error(msg)
