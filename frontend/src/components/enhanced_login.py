"""
Login System — professional split-panel design.
Brand panel is injected via <script> to avoid Streamlit's Markdown
parser treating indented SVG content as code blocks.
"""
import streamlit as st
import re
import time
from .auth_manager import auth_manager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def is_strong_password(password: str):
    issues = []
    if len(password) < 8:              issues.append("At least 8 characters")
    if not re.search(r'[A-Z]', password): issues.append("One uppercase letter")
    if not re.search(r'[a-z]', password): issues.append("One lowercase letter")
    if not re.search(r'\d', password):    issues.append("One number")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password): issues.append("One special character")
    return len(issues) == 0, issues


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
LOGIN_CSS = """<style>
html,body,[data-testid="stApp"]{background:#0b0f19!important;font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif!important}
[data-testid="stSidebar"],[data-testid="stHeader"],[data-testid="stToolbar"],[data-testid="stDecoration"],[data-testid="stStatusWidget"]{display:none!important}
#MainMenu,footer{visibility:hidden!important}
.main .block-container{padding:0!important;max-width:100%!important}

#lp-brand{position:fixed;top:0;left:0;width:44%;height:100%;background:#0b0f19;border-right:1px solid #1a2235;display:flex;flex-direction:column;justify-content:space-between;padding:52px 56px;z-index:999;overflow:hidden;box-sizing:border-box}
#lp-brand::before{content:'';position:absolute;inset:0;background-image:linear-gradient(rgba(30,200,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(30,200,255,.04) 1px,transparent 1px);background-size:42px 42px;pointer-events:none}
#lp-brand::after{content:'';position:absolute;top:-200px;left:-200px;width:600px;height:600px;background:radial-gradient(circle,rgba(0,157,255,.11) 0%,transparent 70%);pointer-events:none}
#lp-brand-top{position:relative;z-index:1}

.lp-logo{display:flex;align-items:center;gap:14px;margin-bottom:56px}
.lp-logo-icon{width:38px;height:38px;flex-shrink:0}
.lp-wordmark{font-size:17px;font-weight:700;letter-spacing:.06em;color:#e2e8f0}
.lp-wordmark em{font-style:normal;color:#1ec8ff}
.lp-headline{font-size:30px;font-weight:700;line-height:1.3;color:#f0f4ff;margin-bottom:16px;letter-spacing:-.01em}
.lp-sub{font-size:14px;color:#3d4e62;line-height:1.75;max-width:380px;margin-bottom:48px}
.lp-features{list-style:none;margin:0;padding:0}
.lp-features li{display:flex;align-items:flex-start;gap:14px;margin-bottom:22px}
.lp-feat-bar{margin-top:5px;width:3px;height:30px;background:linear-gradient(to bottom,#1ec8ff,rgba(30,200,255,.08));border-radius:2px;flex-shrink:0}
.lp-feat-title{font-size:13px;font-weight:600;color:#cbd5e1;line-height:1.4;display:block}
.lp-feat-desc{font-size:12px;color:#3a4a5c;line-height:1.6;margin-top:3px;display:block}

.lp-strip{position:relative;z-index:1;display:flex;gap:28px;padding-top:28px;border-top:1px solid #1a2235}
.lp-stat-val{font-size:16px;font-weight:700;color:#1ec8ff;display:block;margin-bottom:2px;font-variant-numeric:tabular-nums}
.lp-stat-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:#2e3c4a}
.lp-pulse{display:inline-block;width:7px;height:7px;border-radius:50%;background:#22c55e;animation:lpp 2s infinite;margin-right:5px;vertical-align:middle}
@keyframes lpp{0%{box-shadow:0 0 0 0 rgba(34,197,94,.5)}70%{box-shadow:0 0 0 7px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}

.main .block-container>div{margin-left:44%!important}

.lp-form-title{font-size:23px;font-weight:600;color:#e2e8f0;margin-bottom:4px}
.lp-form-hint{font-size:13px;color:#475569;margin-bottom:28px}

div[data-testid="stTextInput"] label{font-size:11px!important;font-weight:600!important;letter-spacing:.06em!important;text-transform:uppercase!important;color:#4a5568!important;margin-bottom:6px!important}
div[data-testid="stTextInput"] input{background:#131c2e!important;border:1px solid #1e293b!important;border-radius:6px!important;color:#e2e8f0!important;font-size:14px!important;padding:10px 13px!important;transition:border-color .18s,box-shadow .18s!important}
div[data-testid="stTextInput"] input:focus{border-color:#1ec8ff!important;box-shadow:0 0 0 3px rgba(30,200,255,.1)!important;outline:none!important}
div[data-testid="stTextInput"] input::placeholder{color:#1e2d3d!important}

div[data-testid="stCheckbox"] label{font-size:13px!important;color:#475569!important}
div[data-testid="stCheckbox"] input[type="checkbox"]{accent-color:#1ec8ff!important}

div[data-testid="stButton"]>button{background:#0f1929!important;border:1px solid #1a2540!important;border-radius:6px!important;color:#475569!important;font-size:12px!important;font-weight:600!important;letter-spacing:.02em!important;padding:7px 10px!important;transition:all .15s!important}
div[data-testid="stButton"]>button:hover{border-color:#1ec8ff!important;color:#1ec8ff!important}
div[data-testid="stButton"]>button[kind="primary"]{background:#0f2240!important;border-color:#1976d2!important;color:#60a5fa!important}

div[data-testid="stFormSubmitButton"]>button{background:linear-gradient(135deg,#1565c0 0%,#1976d2 60%,#1e88e5 100%)!important;border:none!important;border-radius:6px!important;color:#fff!important;font-size:14px!important;font-weight:600!important;letter-spacing:.03em!important;padding:11px 0!important;width:100%!important;box-shadow:0 2px 14px rgba(21,101,192,.4)!important;transition:opacity .15s,transform .1s!important;cursor:pointer!important}
div[data-testid="stFormSubmitButton"]>button:hover{opacity:.92!important;transform:translateY(-1px)!important}

div[data-testid="stAlert"]{border-radius:6px!important;font-size:13px!important;background:#0d1829!important}
hr{border-color:#1a2235!important}
[data-testid="stForm"]{border:none!important;padding:0!important;background:transparent!important}

.lp-footer{display:flex;justify-content:space-between;align-items:center;margin-top:36px;padding-top:20px;border-top:1px solid #1a2235;font-size:11px;color:#283040}
.lp-tab-divider{border:none;border-top:1px solid #1a2235;margin:0 0 24px 0}
</style>"""

# Brand panel HTML — completely flat/minified so the Markdown parser never
# sees 4-space-indented lines (which it would treat as code blocks).
_SVG = '<svg class="lp-logo-icon" viewBox="0 0 38 38" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="38" height="38" rx="7" fill="#0e1e38"/><path d="M19 5 L30 10 L30 20 C30 26 25 31 19 33 C13 31 8 26 8 20 L8 10 Z" fill="none" stroke="#1ec8ff" stroke-width="1.4"/><path d="M19 10 L27 14 L27 20 C27 24 23.5 27.5 19 29 C14.5 27.5 11 24 11 20 L11 14 Z" fill="rgba(30,200,255,0.07)" stroke="#1ec8ff" stroke-width="1" stroke-dasharray="2.5 2"/><circle cx="19" cy="20" r="3" fill="#1ec8ff"/><line x1="19" y1="12" x2="19" y2="16.5" stroke="#1ec8ff" stroke-width="1.4" stroke-linecap="round"/><line x1="13" y1="20" x2="15.5" y2="20" stroke="#1ec8ff" stroke-width="1.4" stroke-linecap="round"/><line x1="22.5" y1="20" x2="25" y2="20" stroke="#1ec8ff" stroke-width="1.4" stroke-linecap="round"/><circle cx="13.5" cy="16.5" r="1.2" fill="rgba(30,200,255,.45)"/><circle cx="24.5" cy="16.5" r="1.2" fill="rgba(30,200,255,.45)"/><circle cx="13.5" cy="23.5" r="1.2" fill="rgba(30,200,255,.45)"/><circle cx="24.5" cy="23.5" r="1.2" fill="rgba(30,200,255,.45)"/></svg>'

BRAND_HTML = (
'<div id="lp-brand">'
'<div id="lp-brand-top">'
'<div class="lp-logo">' + _SVG + '<div class="lp-wordmark">AI<em>-IDS</em></div></div>'
'<div class="lp-headline">Security Operations<br>Command Center</div>'
'<p class="lp-sub">Unified threat detection, real-time log correlation, and AI-assisted incident response for modern security teams.</p>'
'<ul class="lp-features">'
'<li><div class="lp-feat-bar"></div><div><span class="lp-feat-title">Real-time Threat Detection</span><span class="lp-feat-desc">MITRE ATT&amp;CK correlation with sub-second alerting across all ingested event sources</span></div></li>'
'<li><div class="lp-feat-bar"></div><div><span class="lp-feat-title">Network Threat Sensor</span><span class="lp-feat-desc">IDS alert triage, deep traffic inspection, DNS and HTTP behavioral analysis</span></div></li>'
'<li><div class="lp-feat-bar"></div><div><span class="lp-feat-title">Automated Response</span><span class="lp-feat-desc">Playbook-driven containment &#8212; block IPs, snapshot databases, isolate compromised hosts</span></div></li>'
'<li><div class="lp-feat-bar"></div><div><span class="lp-feat-title">Compliance &amp; Reporting</span><span class="lp-feat-desc">PCI-DSS, ISO 27001, SOC 2 control mapping with automated PDF generation</span></div></li>'
'</ul>'
'</div>'
'<div class="lp-strip">'
'<div><span class="lp-stat-val"><span class="lp-pulse"></span>Live</span><span class="lp-stat-lbl">System</span></div>'
'<div><span class="lp-stat-val">TLS 1.3</span><span class="lp-stat-lbl">Encrypted</span></div>'
'<div><span class="lp-stat-val">v2.4.1</span><span class="lp-stat-lbl">Build</span></div>'
'<div><span class="lp-stat-val">SOC 2</span><span class="lp-stat-lbl">Compliant</span></div>'
'</div>'
'</div>'
)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def render_login_page():
    for k, v in [("authenticated", False), ("logged_in", False),
                 ("login_mode", "login"), ("session_checked", False)]:
        if k not in st.session_state:
            st.session_state[k] = v

    # Persistent session restore
    if not st.session_state.authenticated and not st.session_state.session_checked:
        st.session_state.session_checked = True
        session_data = auth_manager.load_persistent_session()
        if session_data:
            session_token, jwt_token = session_data
            payload = auth_manager.verify_jwt_token(jwt_token)
            if payload:
                st.session_state.update(
                    authenticated=True, logged_in=True,
                    session_token=session_token, jwt_token=jwt_token,
                    user_data=payload, username=payload['username']
                )
                st.rerun()

    # URL reset token
    reset_token = st.query_params.get('reset_token', None)
    if isinstance(reset_token, list):
        reset_token = reset_token[0] if reset_token else None
    if reset_token and st.session_state.login_mode != "reset_password":
        st.session_state.login_mode  = "reset_password"
        st.session_state.reset_token = reset_token

    if st.session_state.authenticated:
        return True

    # Inject CSS and brand panel HTML
    st.markdown(LOGIN_CSS,   unsafe_allow_html=True)
    st.markdown(BRAND_HTML,  unsafe_allow_html=True)

    # Form area: three columns [44% offset | form | right margin]
    _, col_form, _ = st.columns([44, 40, 16])

    with col_form:
        st.markdown("<div style='padding-top:72px'></div>", unsafe_allow_html=True)

        if st.session_state.get("pending_2fa"):
            _render_2fa()
        elif st.session_state.login_mode == "login":
            _render_sign_in()
        elif st.session_state.login_mode == "register":
            _render_register()
        elif st.session_state.login_mode == "reset":
            _render_reset_request()
        elif st.session_state.login_mode == "reset_password":
            _render_reset_confirm()

        _render_footer()

    return False


# ---------------------------------------------------------------------------
# Tab switcher
# ---------------------------------------------------------------------------
def _tab_row(current):
    tabs = [("login", "Sign in"), ("register", "New account"), ("reset", "Reset password")]
    cols = st.columns(len(tabs))
    for (key, label), col in zip(tabs, cols):
        with col:
            kind = "primary" if current == key else "secondary"
            if st.button(label, use_container_width=True, type=kind, key=f"tab_{key}"):
                st.session_state.login_mode = key
                st.rerun()
    st.markdown("<hr class='lp-tab-divider'>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------
def _render_sign_in():
    st.markdown("<div class='lp-form-title'>Welcome back</div>", unsafe_allow_html=True)
    st.markdown("<div class='lp-form-hint'>Sign in to your workspace to continue</div>", unsafe_allow_html=True)
    _tab_row("login")

    with st.form("login_form", clear_on_submit=False):
        username  = st.text_input("Username or email", placeholder="you@company.com")
        password  = st.text_input("Password", type="password", placeholder="••••••••••")
        remember  = st.checkbox("Keep me signed in for 30 days")
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        submitted = st.form_submit_button("Sign in →", use_container_width=True, type="primary")

    if submitted:
        if not username or not password:
            st.error("Enter your username and password to continue.")
        else:
            with st.spinner("Verifying…"):
                ok, user_data, msg = auth_manager.authenticate_user(username, password)
            if ok:
                if user_data.get("two_factor_enabled"):
                    st.session_state.update(
                        pending_2fa=True,
                        pending_2fa_user=user_data,
                        pending_2fa_remember=remember
                    )
                    st.rerun()
                else:
                    _complete_login(user_data, remember)
            else:
                st.error(msg or "Incorrect username or password.")


# ---------------------------------------------------------------------------
# 2FA
# ---------------------------------------------------------------------------
def _render_2fa():
    st.markdown("<div class='lp-form-title'>Two-factor authentication</div>", unsafe_allow_html=True)
    st.markdown("<div class='lp-form-hint'>Open your authenticator app and enter the 6-digit code.</div>", unsafe_allow_html=True)

    with st.form("totp_form"):
        code      = st.text_input("Verification code", max_chars=6, placeholder="123 456")
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        submitted = st.form_submit_button("Verify and sign in →", use_container_width=True, type="primary")
        cancel    = st.form_submit_button("Back to sign in")

    if cancel:
        for k in ("pending_2fa", "pending_2fa_user", "pending_2fa_remember"):
            st.session_state.pop(k, None)
        st.rerun()

    if submitted:
        user_data = st.session_state.get("pending_2fa_user", {})
        remember  = st.session_state.get("pending_2fa_remember", False)
        if not code:
            st.error("Enter the code from your authenticator app.")
        elif auth_manager.verify_totp_code(user_data["id"], code):
            for k in ("pending_2fa", "pending_2fa_user", "pending_2fa_remember"):
                st.session_state.pop(k, None)
            _complete_login(user_data, remember)
        else:
            st.error("Incorrect code — check that your device clock is accurate.")


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
def _render_register():
    st.markdown("<div class='lp-form-title'>Create your account</div>", unsafe_allow_html=True)
    st.markdown("<div class='lp-form-hint'>New accounts require administrator approval before first login.</div>", unsafe_allow_html=True)
    _tab_row("register")

    with st.form("register_form", clear_on_submit=False):
        c1, c2   = st.columns(2)
        with c1: first = st.text_input("First name", placeholder="Jane")
        with c2: last  = st.text_input("Last name",  placeholder="Smith")
        username = st.text_input("Username", placeholder="jsmith")
        email    = st.text_input("Work email", placeholder="jane@company.com")
        pwd      = st.text_input("Password", type="password", placeholder="Min. 8 characters")
        pwd2     = st.text_input("Confirm password", type="password", placeholder="Repeat password")

        if pwd:
            ok, issues = is_strong_password(pwd)
            if ok:
                st.success("Password meets all requirements")
            else:
                st.markdown(
                    "<div style='font-size:12px;background:#0d1829;border-left:2px solid #ef4444;"
                    "padding:8px 12px;border-radius:0 4px 4px 0;margin:-4px 0 8px;color:#64748b'>"
                    "Missing: " + " &middot; ".join(f"<span style='color:#ef4444'>{i}</span>" for i in issues)
                    + "</div>", unsafe_allow_html=True)

        terms     = st.checkbox("I agree to the Terms of Service and Privacy Policy")
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        submitted = st.form_submit_button("Create account →", use_container_width=True, type="primary")

    if submitted:
        errors = []
        if not username or len(username) < 3:   errors.append("Username must be at least 3 characters.")
        if not is_valid_email(email):            errors.append("Enter a valid work email address.")
        if not pwd:                              errors.append("Password is required.")
        else:
            ok, issues = is_strong_password(pwd)
            if not ok: errors.extend(issues)
        if pwd != pwd2:  errors.append("Passwords do not match.")
        if not terms:    errors.append("You must accept the Terms of Service.")

        if errors:
            for e in errors: st.error(e)
        else:
            with st.spinner("Creating account…"):
                ok, msg = auth_manager.register_user(username, email, pwd, first, last)
            if ok:
                st.success(msg)
                time.sleep(1.5)
                st.session_state.login_mode = "login"
                st.rerun()
            else:
                st.error(msg)


# ---------------------------------------------------------------------------
# Reset request
# ---------------------------------------------------------------------------
def _render_reset_request():
    st.markdown("<div class='lp-form-title'>Reset your password</div>", unsafe_allow_html=True)
    st.markdown("<div class='lp-form-hint'>We'll send a reset link to your registered email address.</div>", unsafe_allow_html=True)
    _tab_row("reset")

    with st.form("reset_form"):
        email     = st.text_input("Email address", placeholder="jane@company.com")
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        submitted = st.form_submit_button("Send reset link →", use_container_width=True, type="primary")

    if submitted:
        if not email or not is_valid_email(email):
            st.error("Enter a valid email address.")
        else:
            with st.spinner("Sending…"):
                ok, msg = auth_manager.request_password_reset(email)
            if ok:
                st.success(msg)
                st.info("Check your inbox — the link expires in 1 hour.")
            else:
                st.error(msg)


# ---------------------------------------------------------------------------
# Reset confirm
# ---------------------------------------------------------------------------
def _render_reset_confirm():
    st.markdown("<div class='lp-form-title'>Set a new password</div>", unsafe_allow_html=True)
    st.markdown("<div class='lp-form-hint'>Choose a strong password you have not used before.</div>", unsafe_allow_html=True)

    reset_token = st.session_state.get("reset_token", "")

    with st.form("reset_confirm_form"):
        new_pwd  = st.text_input("New password", type="password", placeholder="Min. 8 characters")
        new_pwd2 = st.text_input("Confirm new password", type="password", placeholder="Repeat password")
        if new_pwd:
            ok, _ = is_strong_password(new_pwd)
            if ok:
                st.success("Password meets all requirements")
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        submitted = st.form_submit_button("Update password →", use_container_width=True, type="primary")

    if submitted:
        if not new_pwd:
            st.error("Enter a new password.")
        elif new_pwd != new_pwd2:
            st.error("Passwords do not match.")
        else:
            ok, issues = is_strong_password(new_pwd)
            if not ok:
                for i in issues: st.error(i)
            else:
                with st.spinner("Updating…"):
                    ok, msg = auth_manager.reset_password(reset_token, new_pwd)
                if ok:
                    st.success(msg)
                    time.sleep(1.5)
                    st.session_state.login_mode = "login"
                    st.query_params.clear()
                    st.rerun()
                else:
                    st.error(msg)


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
def _render_footer():
    st.markdown(
        "<div class='lp-footer'>"
        "<span>&copy; 2026 AI-IDS &nbsp;&middot;&nbsp; All rights reserved</span>"
        "<span>v2.4.1 &nbsp;&middot;&nbsp; TLS 1.3</span>"
        "</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------
def _complete_login(user_data, remember):
    session_token, jwt_token = auth_manager.create_user_session(user_data, remember)
    st.session_state.update(
        authenticated=True, logged_in=True,
        session_token=session_token, jwt_token=jwt_token,
        user_data=user_data, username=user_data["username"], remember_me=remember
    )
    st.rerun()


def logout():
    auth_manager.logout_user(st.session_state.get("session_token"))
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    st.rerun()


def get_current_user():
    if st.session_state.get("authenticated") and "user_data" in st.session_state:
        return st.session_state.user_data
    return None


def require_auth(role=None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                st.error("Authentication required.")
                st.stop()
            if role and user.get("role") != role:
                st.error(f"Access denied — {role} role required.")
                st.stop()
            return func(*args, **kwargs)
        return wrapper
    return decorator


def render_notification_badge():
    user = get_current_user()
    if not user:
        return
    n = len(auth_manager.get_user_notifications(user["id"], unread_only=True))
    if n > 0:
        st.sidebar.markdown(
            f"<div style='font-size:13px;color:#94a3b8'>"
            f"<span style='color:#ef4444;font-weight:700'>{n}</span> "
            f"new notification{'s' if n > 1 else ''}</div>",
            unsafe_allow_html=True,
        )
        if st.sidebar.button("View Notifications"):
            st.session_state.view = "notifications"
            st.query_params["view"] = "notifications"
            st.rerun()


def render_notifications_page():
    user = get_current_user()
    if not user:
        return
    st.title("Notifications")
    tab1, tab2 = st.tabs(["Unread", "All"])
    with tab1:
        _render_notif_list(auth_manager.get_user_notifications(user["id"], unread_only=True),  user["id"])
    with tab2:
        _render_notif_list(auth_manager.get_user_notifications(user["id"], unread_only=False), user["id"])


def _render_notif_list(notifications, user_id):
    if not notifications:
        st.info("No notifications.")
        return
    for n in notifications:
        with st.container():
            c1, c2, c3 = st.columns([1, 6, 1])
            with c1: st.markdown("✅" if n["is_read"] else "🔴")
            with c2:
                st.markdown(f"**{n['type']}**")
                st.markdown(n["message"])
                st.caption(f"Sent: {n['sent_at']}")
            with c3:
                if not n["is_read"] and st.button("Mark read", key=f"read_{n['id']}"):
                    auth_manager.mark_notification_read(n["id"], user_id)
                    st.rerun()
            st.divider()


if "auth_manager" not in st.session_state:
    st.session_state.auth_manager = auth_manager
