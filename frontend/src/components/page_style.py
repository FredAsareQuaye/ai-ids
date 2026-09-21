"""
Shared page styling for all SIEM pages.
Import and call inject_page_css() at the top of any render function.
"""
import streamlit as st

# ── Core design tokens ────────────────────────────────────────────────────
BG         = "#0b0f19"
BG2        = "#0f1623"
BG3        = "#131c2e"
BORDER     = "#1a2235"
BORDER2    = "#1e2d3d"
TEXT       = "#e2e8f0"
TEXT_MUTED = "#64748b"
TEXT_DIM   = "#334155"
ACCENT     = "#1ec8ff"
BLUE       = "#1976d2"
RED        = "#ef4444"
ORANGE     = "#f97316"
GREEN      = "#22c55e"
YELLOW     = "#eab308"

PAGE_CSS = """<style>
/* ── Page base ─────────────────────────────────────────────────────────── */
html,body,[data-testid="stApp"]{background:#0b0f19!important;
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif!important}
.main .block-container{padding:2rem 2.5rem 3rem!important;max-width:1280px!important}

/* ── Page title ─────────────────────────────────────────────────────────── */
h1[data-testid="stHeadingWithActionElements"],
h1{color:#e2e8f0!important;font-size:22px!important;font-weight:700!important;
   letter-spacing:-.01em!important;margin-bottom:2px!important}

h2,h3{color:#cbd5e1!important;font-weight:600!important}

/* ── Tabs ────────────────────────────────────────────────────────────────── */
[data-testid="stTabs"] [data-testid="stTab"]{
  font-size:13px!important;font-weight:600!important;
  color:#4a5568!important;padding:8px 18px!important;border:none!important}
[data-testid="stTabs"] [data-testid="stTab"][aria-selected="true"]{
  color:#1ec8ff!important;border-bottom:2px solid #1ec8ff!important;
  background:transparent!important}
[data-testid="stTabs"] [role="tablist"]{
  border-bottom:1px solid #1a2235!important;gap:4px!important}

/* ── Metrics ─────────────────────────────────────────────────────────────── */
[data-testid="stMetric"]{
  background:#131c2e!important;border:1px solid #1a2235!important;
  border-radius:8px!important;padding:16px 18px!important}
[data-testid="stMetricLabel"]{
  font-size:11px!important;font-weight:600!important;
  text-transform:uppercase!important;letter-spacing:.06em!important;
  color:#4a5568!important}
[data-testid="stMetricValue"]{
  font-size:24px!important;font-weight:700!important;color:#e2e8f0!important}
[data-testid="stMetricDelta"]{font-size:12px!important}

/* ── Expanders ───────────────────────────────────────────────────────────── */
[data-testid="stExpander"]{
  background:#0f1623!important;border:1px solid #1a2235!important;
  border-radius:8px!important;margin-bottom:8px!important}
[data-testid="stExpander"] summary{
  font-size:13px!important;font-weight:600!important;
  color:#94a3b8!important;padding:14px 16px!important}
[data-testid="stExpander"] summary:hover{color:#e2e8f0!important}
[data-testid="stExpander"] [data-testid="stExpanderDetails"]{
  padding:0 16px 16px!important}

/* ── Inputs ──────────────────────────────────────────────────────────────── */
div[data-testid="stTextInput"] label,
div[data-testid="stSelectbox"] label,
div[data-testid="stTextArea"] label,
div[data-testid="stNumberInput"] label{
  font-size:11px!important;font-weight:600!important;
  text-transform:uppercase!important;letter-spacing:.05em!important;
  color:#4a5568!important}
div[data-testid="stTextInput"] input,
div[data-testid="stNumberInput"] input{
  background:#131c2e!important;border:1px solid #1e2d3d!important;
  border-radius:6px!important;color:#e2e8f0!important;font-size:14px!important}
div[data-testid="stTextInput"] input:focus,
div[data-testid="stNumberInput"] input:focus{
  border-color:#1ec8ff!important;box-shadow:0 0 0 3px rgba(30,200,255,.1)!important}
div[data-testid="stSelectbox"] [data-baseweb="select"] [data-testid="stMarkdownContainer"],
div[data-testid="stSelectbox"] div[class*="ValueContainer"]{
  background:#131c2e!important;border-color:#1e2d3d!important}
textarea{background:#131c2e!important;border:1px solid #1e2d3d!important;
  border-radius:6px!important;color:#e2e8f0!important;font-size:14px!important}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
div[data-testid="stButton"]>button,
div[data-testid="stFormSubmitButton"]>button{
  background:#131c2e!important;border:1px solid #1e2d3d!important;
  border-radius:6px!important;color:#94a3b8!important;
  font-size:13px!important;font-weight:600!important;
  transition:all .15s!important}
div[data-testid="stButton"]>button:hover,
div[data-testid="stFormSubmitButton"]>button:hover{
  border-color:#1ec8ff!important;color:#1ec8ff!important}
div[data-testid="stButton"]>button[kind="primary"],
div[data-testid="stFormSubmitButton"]>button[kind="primaryFormSubmit"]{
  background:linear-gradient(135deg,#1565c0,#1976d2)!important;
  border:none!important;color:#fff!important;
  box-shadow:0 2px 12px rgba(21,101,192,.35)!important}
div[data-testid="stButton"]>button[kind="primary"]:hover{
  opacity:.9!important;transform:translateY(-1px)!important}

/* ── Alerts ──────────────────────────────────────────────────────────────── */
div[data-testid="stAlert"]{
  border-radius:7px!important;font-size:13px!important;
  padding:10px 14px!important}
div[data-testid="stAlert"][data-baseweb="notification"][kind="info"]{
  background:#0d1829!important;border-left:3px solid #1976d2!important}
div[data-testid="stAlert"][data-baseweb="notification"][kind="success"]{
  background:#051a0d!important;border-left:3px solid #16a34a!important}
div[data-testid="stAlert"][data-baseweb="notification"][kind="error"]{
  background:#1a0505!important;border-left:3px solid #dc2626!important}
div[data-testid="stAlert"][data-baseweb="notification"][kind="warning"]{
  background:#1a1005!important;border-left:3px solid #d97706!important}

/* ── Checkboxes / Toggles ────────────────────────────────────────────────── */
div[data-testid="stCheckbox"] label{font-size:13px!important;color:#64748b!important}
div[data-testid="stCheckbox"] input[type="checkbox"]{accent-color:#1ec8ff!important}
div[data-testid="stToggle"] label{font-size:13px!important;color:#94a3b8!important}

/* ── Sliders ─────────────────────────────────────────────────────────────── */
div[data-testid="stSlider"] [class*="thumb"]{
  background:#1ec8ff!important;border-color:#1ec8ff!important}
div[data-testid="stSlider"] [class*="track"]{background:#1e2d3d!important}

/* ── Code blocks ─────────────────────────────────────────────────────────── */
pre,code{background:#0d1829!important;border:1px solid #1a2235!important;
  border-radius:6px!important;font-size:12px!important}

/* ── Dividers ────────────────────────────────────────────────────────────── */
hr{border-color:#1a2235!important;margin:1.5rem 0!important}

/* ── Tables / DataFrames ─────────────────────────────────────────────────── */
[data-testid="stDataFrame"]{border:1px solid #1a2235!important;border-radius:8px!important}

/* ── Sidebar polishing ───────────────────────────────────────────────────── */
[data-testid="stSidebar"]{background:#0b0f19!important;border-right:1px solid #1a2235!important}
[data-testid="stSidebar"] [data-testid="stButton"]>button{
  background:transparent!important;border:none!important;
  color:#4a5568!important;font-size:13px!important;
  font-weight:500!important;text-align:left!important;
  padding:6px 12px!important;border-radius:6px!important}
[data-testid="stSidebar"] [data-testid="stButton"]>button:hover{
  background:#131c2e!important;color:#e2e8f0!important;border:none!important}
[data-testid="stSidebar"] [data-testid="stButton"]>button[kind="primary"]{
  background:#131c2e!important;color:#1ec8ff!important;border:none!important}

/* ── Spinner ─────────────────────────────────────────────────────────────── */
[data-testid="stSpinner"]>div{border-top-color:#1ec8ff!important}

/* ── Download button ─────────────────────────────────────────────────────── */
[data-testid="stDownloadButton"]>button{
  background:#131c2e!important;border:1px solid #1e2d3d!important;
  border-radius:6px!important;color:#94a3b8!important;
  font-size:13px!important;font-weight:600!important}
[data-testid="stDownloadButton"]>button:hover{
  border-color:#1ec8ff!important;color:#1ec8ff!important}
</style>"""


def inject_page_css():
    """Call this once at the top of each page's render function."""
    st.markdown(PAGE_CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "", badge: str = ""):
    """Render a clean page header without emoji or gradient banners."""
    badge_html = (
        f'<span style="font-size:11px;font-weight:600;text-transform:uppercase;'
        f'letter-spacing:.06em;color:#1ec8ff;background:#0d2040;'
        f'padding:3px 10px;border-radius:20px;border:1px solid #1e3a5f">{badge}</span>'
        if badge else ""
    )
    sub_html = (
        f'<div style="font-size:13px;color:#4a5568;margin-top:4px">{subtitle}</div>'
        if subtitle else ""
    )
    st.markdown(
        f'<div style="margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid #1a2235">'
        f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">'
        f'<span style="font-size:20px;font-weight:700;color:#e2e8f0">{title}</span>'
        f'{badge_html}</div>'
        f'{sub_html}</div>',
        unsafe_allow_html=True,
    )


def stat_card(label: str, value, color: str = "#1ec8ff", note: str = ""):
    """Render a single stat card as HTML (use inside st.columns)."""
    note_html = f'<div style="font-size:11px;color:#334155;margin-top:4px">{note}</div>' if note else ""
    st.markdown(
        f'<div style="background:#131c2e;border:1px solid #1a2235;border-radius:8px;'
        f'padding:16px 18px">'
        f'<div style="font-size:11px;font-weight:600;text-transform:uppercase;'
        f'letter-spacing:.06em;color:#4a5568;margin-bottom:6px">{label}</div>'
        f'<div style="font-size:24px;font-weight:700;color:{color}">{value}</div>'
        f'{note_html}</div>',
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    """Return an HTML severity badge string."""
    colors = {
        "CRITICAL": ("#1a0505", "#ef4444"),
        "HIGH":     ("#1a0d00", "#f97316"),
        "MEDIUM":   ("#1a1500", "#eab308"),
        "LOW":      ("#051a12", "#22c55e"),
        "INFO":     ("#091525", "#1ec8ff"),
    }
    bg, fg = colors.get(severity.upper(), ("#131c2e", "#94a3b8"))
    return (
        f'<span style="font-size:10px;font-weight:700;text-transform:uppercase;'
        f'letter-spacing:.06em;color:{fg};background:{bg};'
        f'padding:2px 8px;border-radius:4px;border:1px solid {fg}40">{severity}</span>'
    )
