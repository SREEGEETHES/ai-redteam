"""
AI Red Team Dashboard  —  Streamlit front-end
=============================================
Drop-in replacement for the original main.py.

* Same API contract (endpoints, payloads, session keys) — nothing in the backend changes.
* Same 13 pages, same actions (launch scan, retest, compare, checklist updates, reports ...).
* New: enterprise security-console look (graphite + signal orange, muted semantic colours),
  custom KPI cards, severity/result badges, HTML tables, syntax-highlighted JSON,
  timeline view for finding lifecycle, donut / bar charts.

Run:   streamlit run main.py
Env:   REDTEAM_API_URL=http://localhost:8080   (optional, default shown)
"""

import html
import json
import os
import re
import time

import altair as alt
import pandas as pd
import requests
import streamlit as st

st.set_page_config(
    page_title="AI Red Team Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE_URL = os.getenv("REDTEAM_API_URL", "http://localhost:8080")


# ─────────────────────────────────────────────────────────────────────────────
# Cached API helpers (massive speedup for tab switching)
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=5)
def api_get(endpoint: str, params: dict | None = None):
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"API Error: {e}")
        return []


@st.cache_data(ttl=5)
def api_get_raw(endpoint: str, params: dict | None = None):
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", params=params, timeout=10)
        response.raise_for_status()
        return response
    except Exception as e:
        st.error(f"API Error: {e}")
        return None


def api_post(endpoint: str, data: dict):
    try:
        response = requests.post(f"{API_BASE_URL}{endpoint}", json=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"API Error: {e}")
        return None


@st.cache_data(ttl=5)
def get_targets():
    return api_get("/targets")


@st.cache_data(ttl=5)
def get_scans():
    return api_get("/scans")


@st.cache_data(ttl=5)
def get_attacks():
    return api_get("/attacks")


@st.cache_data(ttl=5)
def get_checklist():
    return api_get("/checklist")


@st.cache_data(ttl=5)
def get_protections_checks(target_id: int):
    return api_get("/protections/checks", params={"target_id": target_id})


# ─────────────────────────────────────────────────────────────────────────────
# Design tokens
# ─────────────────────────────────────────────────────────────────────────────
BG = "#0E1116"
SURFACE = "#151A21"
SURFACE_2 = "#1B222B"
BORDER = "#263140"
TEXT = "#E6EAF0"
MUTED = "#8B97A7"
ACCENT = "#FA582D"  # signal orange (brand accent)
BLUE = "#4C8DBF"  # steel blue
GREEN = "#3DA57C"  # pass
RED = "#D94F4F"  # fail / critical
AMBER = "#D9A441"  # medium / warning
TEAL = "#4A9BB0"  # low
GREY = "#7C8A9C"  # info / neutral

SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH": "#E8833A",
    "MEDIUM": AMBER,
    "LOW": TEAL,
    "INFO": GREY,
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RESULT_COLORS = {"PASS": GREEN, "FAIL": RED, "INCONCLUSIVE": GREY}
FONT = "Inter, Segoe UI, Helvetica, Arial, sans-serif"

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
:root{
  --bg:#0E1116; --surface:#151A21; --surface2:#1B222B; --border:#263140;
  --text:#E6EAF0; --muted:#8B97A7; --accent:#FA582D; --accent-soft:rgba(250,88,45,.12);
  --green:#3DA57C; --red:#D94F4F; --amber:#D9A441; --blue:#4C8DBF;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
html, body, .stApp, [data-testid="stAppViewContainer"]{
  background:var(--bg)!important; color:var(--text);
  font-family:'Inter','Segoe UI',-apple-system,Roboto,Helvetica,Arial,sans-serif;
}
[data-testid="stHeader"]{background:transparent!important}
#MainMenu, footer, [data-testid="stDecoration"], [data-testid="stToolbar"]{visibility:hidden;height:0}
.block-container{padding-top:1.4rem!important;padding-bottom:4rem;max-width:1440px}

/* text */
[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] p, .stApp label p,
.stApp button, .stApp input, .stApp textarea{font-family:'Inter','Segoe UI',-apple-system,Roboto,Helvetica,Arial,sans-serif}
[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li, [data-testid="stWidgetLabel"] p,
[data-testid="stWidgetLabel"] label, .stApp label{color:var(--text)!important}
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p{color:var(--muted)!important}
h1,h2,h3,h4,h5{color:var(--text)!important;letter-spacing:-.01em}
hr{border-color:var(--border)!important}
a{color:var(--blue)!important}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:#2E3A4A;border-radius:8px}
::-webkit-scrollbar-track{background:transparent}

/* sidebar */
[data-testid="stSidebar"]{background:#0A0D12!important;border-right:1px solid var(--border)}
[data-testid="stSidebar"] > div:first-child{padding-top:1.1rem}
[data-testid="stSidebar"] [role="radiogroup"]{gap:2px}
[data-testid="stSidebar"] [role="radiogroup"] label{
  padding:9px 12px;border-radius:8px;border-left:3px solid transparent;width:100%;display:flex;
  cursor:pointer;transition:background .15s,border-color .15s}
/* hide the radio circle (any Streamlit version): any div inside the label that holds no text */
[data-testid="stSidebar"] [role="radiogroup"] label div:not([data-testid="stMarkdownContainer"]):not(:has([data-testid="stMarkdownContainer"])){display:none!important}
[data-testid="stSidebar"] [role="radiogroup"] label p{
  color:var(--muted)!important;font-size:.9rem;font-weight:500;margin:0}
[data-testid="stSidebar"] [role="radiogroup"] label:hover{background:var(--surface2)}
[data-testid="stSidebar"] [role="radiogroup"] label:hover p{color:var(--text)!important}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked){
  background:var(--accent-soft);border-left-color:var(--accent)}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) p{
  color:var(--text)!important;font-weight:600}

/* brand + top bar */
.rt-brand{display:flex;align-items:center;gap:12px;padding:4px 6px 18px}
.rt-logo{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,#FA582D,#C9401C);
  display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:15px;
  box-shadow:0 4px 14px rgba(250,88,45,.28)}
.rt-brand-name{font-weight:700;font-size:1rem;color:var(--text);line-height:1.1}
.rt-brand-sub{font-size:.7rem;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-top:3px}
.rt-nav-label{font-size:.68rem;letter-spacing:.14em;text-transform:uppercase;color:#5E6B7C;
  padding:6px 8px 8px;font-weight:600}
.rt-side-card{margin-top:14px;padding:12px 14px;border:1px solid var(--border);border-radius:10px;
  background:var(--surface);font-size:.78rem;color:var(--muted)}
.rt-side-card b{color:var(--text);font-weight:600}
.rt-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;vertical-align:middle}

.rt-topbar{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;
  padding:16px 22px;margin-bottom:22px;border:1px solid var(--border);border-radius:14px;
  background:linear-gradient(120deg,#171D26 0%,#12171E 60%,#191512 100%);position:relative;overflow:hidden}
.rt-topbar:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--accent)}
.rt-top-title{font-size:1.25rem;font-weight:700;color:var(--text);letter-spacing:-.01em}
.rt-top-tag{font-size:.86rem;color:var(--muted);margin-top:3px}
.rt-chips{display:flex;gap:8px;flex-wrap:wrap}
.rt-chip{font-size:.72rem;font-weight:600;letter-spacing:.05em;padding:5px 11px;border-radius:999px;
  border:1px solid var(--border);color:var(--muted);background:rgba(255,255,255,.02)}
.rt-chip.hot{color:var(--accent);border-color:rgba(250,88,45,.45);background:var(--accent-soft)}

/* page + section headings */
.rt-page-title{font-size:1.55rem;font-weight:700;letter-spacing:-.02em;color:var(--text);margin:2px 0 2px}
.rt-page-sub{font-size:.9rem;color:var(--muted);margin-bottom:18px}
.rt-section{display:flex;align-items:center;gap:10px;margin:26px 0 12px;font-size:.78rem;font-weight:600;
  letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.rt-section:after{content:"";flex:1;height:1px;background:var(--border)}
.rt-section:before{content:"";width:6px;height:6px;border-radius:2px;background:var(--accent)}

/* KPI */
.rt-kpi{background:var(--surface);border:1px solid var(--border);box-shadow:inset 0 3px 0 var(--kc,var(--accent));
  border-radius:12px;padding:16px 18px;min-height:112px}
.rt-kpi-label{font-size:.7rem;letter-spacing:.11em;text-transform:uppercase;color:var(--muted);font-weight:600}
.rt-kpi-value{font-size:2.05rem;font-weight:700;color:var(--text);line-height:1.15;margin-top:8px;
  font-variant-numeric:tabular-nums}
.rt-kpi-sub{font-size:.78rem;color:var(--muted);margin-top:4px}

/* badges */
.rt-badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;
  font-size:.7rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;
  border:1px solid transparent}
.rt-badge:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.rt-chip-sm{display:inline-block;padding:1px 8px;margin:0 4px 2px 0;border-radius:6px;font-size:.72rem;
  background:var(--surface2);border:1px solid var(--border);color:var(--muted)}

/* table */
.rt-wrap{border:1px solid var(--border);border-radius:12px;overflow:auto;background:var(--surface)}
table.rt-table{width:100%;border-collapse:separate;border-spacing:0;font-size:.84rem}
.rt-table th{position:sticky;top:0;z-index:1;background:#10151B;color:var(--muted);text-align:left;
  font-size:.68rem;letter-spacing:.1em;text-transform:uppercase;font-weight:600;padding:11px 14px;
  border-bottom:1px solid var(--border);white-space:nowrap}
.rt-table td{padding:10px 14px;border-bottom:1px solid #1E2733;color:var(--text);vertical-align:middle}
.rt-table tr:last-child td{border-bottom:none}
.rt-table tbody tr:hover td{background:#1A212B}
.rt-mono{font-family:var(--mono);font-size:.8rem;color:#B9C4D2}
.rt-dim{color:#5E6B7C}
.rt-empty{padding:26px;text-align:center;color:var(--muted);border:1px dashed var(--border);
  border-radius:12px;background:var(--surface)}

/* code / json */
div.rt-json{margin:0;padding:16px 18px;background:#0A0E13;border:1px solid var(--border);border-radius:12px;
  font-family:var(--mono);font-size:.78rem;line-height:1.6;color:#C3CCD8;overflow:auto;white-space:nowrap}
.rt-j-key{color:#7FB2D6}.rt-j-str{color:#8FC7A8}.rt-j-num{color:#E3B15C}.rt-j-kw{color:#E8833A}

/* field cards / rows */
.rt-field{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;
  height:100%;margin-bottom:12px}
.rt-field-l{font-size:.68rem;letter-spacing:.11em;text-transform:uppercase;color:var(--accent);
  font-weight:600;margin-bottom:6px}
.rt-field-v{font-size:.9rem;color:var(--text);line-height:1.55}
.rt-row{display:flex;align-items:center;justify-content:space-between;gap:14px;background:var(--surface);
  border:1px solid var(--border);border-radius:12px;padding:9px 16px;margin-bottom:8px}
.rt-row-main{font-weight:600;color:var(--text)}
.rt-row-sub{font-size:.78rem;color:var(--muted);font-family:var(--mono)}
.rt-bar{height:8px;border-radius:99px;background:#222B37;overflow:hidden}
.rt-bar > div{height:100%;border-radius:99px}
.rt-sprint{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;margin-bottom:12px}
.rt-sprint-h{display:flex;justify-content:space-between;font-size:.85rem;margin-bottom:10px;color:var(--text)}
.rt-sprint-h span{color:var(--muted);font-variant-numeric:tabular-nums}

/* timeline */
.rt-tl{position:relative;margin:6px 0 4px 8px;padding-left:22px;border-left:2px solid var(--border)}
.rt-tl-i{position:relative;margin-bottom:16px}
.rt-tl-i:before{content:"";position:absolute;left:-29px;top:4px;width:12px;height:12px;border-radius:50%;
  background:var(--bg);border:2px solid var(--tc,var(--accent))}
.rt-tl-t{font-size:.9rem;color:var(--text)}
.rt-tl-d{font-size:.75rem;color:var(--muted);font-family:var(--mono);margin-top:2px}

/* native widgets */
/* react-aria widgets (recent Streamlit) */
[data-testid="stSelectbox"] [role="group"], [data-testid="stMultiSelect"] [role="group"],
[data-testid="stTextInput"] [role="group"], [data-testid="stTextArea"] [role="group"],
[data-testid="stNumberInput"] [role="group"]{
  background:var(--surface2)!important;border:1px solid var(--border)!important;border-radius:9px!important;
  box-shadow:none!important}
[data-testid="stSelectbox"] [role="group"]:hover, [data-testid="stSelectbox"] [role="group"]:focus-within,
[data-testid="stMultiSelect"] [role="group"]:focus-within, [data-testid="stTextInput"] [role="group"]:focus-within{
  border-color:var(--accent)!important}
[data-testid="stSelectbox"] input, [data-testid="stMultiSelect"] input, [data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea, [data-testid="stNumberInput"] input{
  background:transparent!important;color:var(--text)!important;-webkit-text-fill-color:var(--text)!important}
[data-testid="stSelectbox"] input::placeholder, [data-testid="stTextInput"] input::placeholder{
  color:#5E6B7C!important;-webkit-text-fill-color:#5E6B7C!important}
[data-testid="stSelectbox"] button, [data-testid="stMultiSelect"] button{background:transparent!important;color:var(--muted)!important}
[role="listbox"], [data-testid="stSelectboxVirtualDropdown"], [data-testid="stSelectboxVirtualDropdown"] > div{
  background:var(--surface2)!important;color:var(--text)!important;border-radius:10px}
[role="option"], [role="option"] *{color:var(--text)!important}
[role="option"]{background:transparent!important}
[role="option"]:hover, [role="option"][aria-selected="true"], [role="option"][data-focused="true"], [role="option"][data-hovered="true"]{
  background:var(--accent-soft)!important}
[data-testid="stPopover"], [data-testid="stSelectboxPopover"], div[data-rac][role="dialog"]{background:var(--surface2)!important}

[data-baseweb="select"] > div, [data-baseweb="input"] > div, [data-baseweb="textarea"] > div,
.stTextInput input, .stTextArea textarea{
  background:var(--surface2)!important;border-color:var(--border)!important;color:var(--text)!important;
  border-radius:9px!important}
[data-baseweb="select"] *, [data-baseweb="input"] input{color:var(--text)!important}
[data-baseweb="select"] svg{fill:var(--muted)!important}
[data-baseweb="input"] input::placeholder{color:#5E6B7C!important}
[data-baseweb="select"] > div:hover, [data-baseweb="input"] > div:focus-within{border-color:var(--accent)!important}
[data-baseweb="popover"], [data-baseweb="popover"] > div, [data-baseweb="menu"], ul[role="listbox"]{
  background:var(--surface2)!important;border:1px solid var(--border);border-radius:10px}
li[role="option"]{color:var(--text)!important;background:transparent!important}
li[role="option"]:hover, li[aria-selected="true"]{background:var(--accent-soft)!important}
[data-baseweb="tag"]{background:var(--accent-soft)!important;border:1px solid rgba(250,88,45,.35)!important}
[data-baseweb="tag"] span{color:var(--text)!important}

.stButton > button, .stFormSubmitButton > button, .stDownloadButton > button{
  background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:9px;
  font-weight:600;font-size:.85rem;padding:.45rem 1rem;transition:all .15s}
.stButton > button:hover, .stFormSubmitButton > button:hover, .stDownloadButton > button:hover{
  border-color:var(--accent);color:var(--text);background:#212A35}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"],
[data-testid="stBaseButton-primary"], [data-testid="stBaseButton-primaryFormSubmit"]{
  background:var(--accent)!important;border-color:var(--accent)!important;color:#fff!important}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primary"]:hover,
[data-testid="stBaseButton-primary"]:hover, [data-testid="stBaseButton-primaryFormSubmit"]:hover{
  background:#E24A20!important;border-color:#E24A20!important}
[data-testid="stBaseButton-primary"] *, [data-testid="stBaseButton-primaryFormSubmit"] *{color:#fff!important}
[data-testid="stBaseButton-secondary"], [data-testid="stBaseButton-secondaryFormSubmit"], [data-testid="stBaseButton-download"]{
  background:var(--surface2)!important;border:1px solid var(--border)!important;color:var(--text)!important;border-radius:9px!important}
[data-testid="stBaseButton-secondary"]:hover, [data-testid="stBaseButton-secondaryFormSubmit"]:hover{border-color:var(--accent)!important}

[data-baseweb="tab-list"]{gap:6px;border-bottom:1px solid var(--border)}
button[data-baseweb="tab"]{background:transparent!important;color:var(--muted)!important;font-weight:600}
button[data-baseweb="tab"][aria-selected="true"]{color:var(--text)!important}
[data-baseweb="tab-highlight"]{background:var(--accent)!important;height:2px!important}
[data-baseweb="tab-border"]{background:transparent!important}

[data-testid="stExpander"], [data-testid="stExpander"] details{background:var(--surface)!important;
  border:1px solid var(--border)!important;border-radius:12px!important}
[data-testid="stExpander"] summary{background:var(--surface)!important;border-radius:12px}
[data-testid="stExpander"] summary:hover{background:var(--surface2)!important}
[data-testid="stExpander"] summary *, [data-testid="stExpander"] summary p{color:var(--text)!important}
[data-testid="stExpander"] svg{fill:var(--muted)}
[data-testid="stForm"]{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px}
[data-testid="stAlert"]{background:var(--surface2)!important;border:1px solid var(--border);
  border-left:3px solid var(--accent);border-radius:10px}
[data-testid="stAlert"] *{color:var(--text)!important}
[data-testid="stArrowVegaLiteChart"], [data-testid="stVegaLiteChart"]{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 10px 6px}
.stSpinner p{color:var(--muted)!important}
</style>
"""


# ─────────────────────────────────────────────────────────────────────────────
# API helpers  (unchanged behaviour)
# ─────────────────────────────────────────────────────────────────────────────
def api_get(endpoint: str, params: dict | None = None):
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"API Error: {e}")
        return []


def api_post(endpoint: str, data: dict):
    try:
        response = requests.post(f"{API_BASE_URL}{endpoint}", json=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"API Error: {e}")
        return None


def api_get_raw(endpoint: str):
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", timeout=10)
        response.raise_for_status()
        return response
    except Exception as e:
        st.error(f"API Error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# UI building blocks
# ─────────────────────────────────────────────────────────────────────────────
def esc(x) -> str:
    """HTML-escape (also neutralises `$` so Streamlit's markdown never treats it as LaTeX)."""
    return html.escape(str(x), quote=True).replace("$", "&#36;")


def md(markup: str):
    st.markdown(markup, unsafe_allow_html=True)


def flash(kind: str, message: str):
    """Queue a message that survives st.rerun()."""
    st.session_state["_flash"] = (kind, message)


def show_flash():
    if "_flash" in st.session_state:
        kind, message = st.session_state.pop("_flash")
        getattr(st, kind, st.info)(message)


def badge(text, color=GREY) -> str:
    return (
        f'<span class="rt-badge" style="color:{color};background:{color}1F;border-color:{color}55">'
        f"{esc(text)}</span>"
    )


def status_color(value) -> str:
    s = str(value).upper().replace(" ", "_")
    if s in RESULT_COLORS:
        return RESULT_COLORS[s]
    if any(k in s for k in ("REGRESS", "FAIL", "BLOCK")):
        return RED
    if any(k in s for k in ("VERIF", "FIXED", "RESOLV", "CLOSED", "COMPLETE", "PASS", "HEALTHY")):
        return GREEN
    if any(k in s for k in ("PROGRESS", "RUNNING")):
        return BLUE
    if any(k in s for k in ("OPEN", "NEW", "STILL", "PENDING")):
        return AMBER
    return GREY


def sev_badge(sev) -> str:
    s = str(sev).upper()
    return badge(s, SEV_COLORS.get(s, GREY))


def page_header(title: str, subtitle: str = ""):
    md(
        f'<div class="rt-page-title">{esc(title)}</div>'
        f'<div class="rt-page-sub">{esc(subtitle)}</div>'
    )


def section(title: str):
    md(f'<div class="rt-section">{esc(title)}</div>')


def kpi(label, value, sub="", color=ACCENT) -> str:
    return (
        f'<div class="rt-kpi" style="--kc:{color}"><div class="rt-kpi-label">{esc(label)}</div>'
        f'<div class="rt-kpi-value">{esc(value)}</div><div class="rt-kpi-sub">{esc(sub) or "&nbsp;"}</div></div>'
    )


def kpi_row(items):
    cols = st.columns(len(items))
    for col, item in zip(cols, items, strict=False):
        with col:
            md(kpi(*item))


def progress_bar(pct: float, color=ACCENT) -> str:
    pct = max(0.0, min(1.0, float(pct)))
    return (
        f'<div class="rt-bar"><div style="width:{pct * 100:.0f}%;background:{color}"></div></div>'
    )


def field_card(label: str, text) -> str:
    body = esc(text if text not in (None, "") else "—").replace("\n", "<br>")
    return f'<div class="rt-field"><div class="rt-field-l">{esc(label)}</div><div class="rt-field-v">{body}</div></div>'


def empty_state(message: str):
    md(f'<div class="rt-empty">{esc(message)}</div>')


_ID_COLS = {
    "id",
    "attack_id",
    "test_id",
    "scan_id",
    "target_id",
    "finding_id",
    "check_id",
    "retest_id",
    "hash",
}


def _fmt_cell(col: str, v) -> str:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return '<span class="rt-dim">—</span>'
    c = col.lower()
    if c == "passed":
        return badge("PASS" if v else "FAIL", GREEN if v else RED)
    if c == "is_authorized":
        return badge("Authorized" if v else "Unauthorized", GREEN if v else RED)
    if isinstance(v, bool):
        return badge("YES" if v else "NO", GREEN if v else GREY)
    if c == "severity":
        return sev_badge(v)
    if c in ("result", "status", "regression_status", "current_status"):
        return badge(str(v).replace("_", " "), status_color(v))
    if isinstance(v, (list, tuple, set)):
        return (
            "".join(f'<span class="rt-chip-sm">{esc(i)}</span>' for i in v)
            or '<span class="rt-dim">—</span>'
        )
    if isinstance(v, dict):
        s = json.dumps(v, default=str)
        return f'<span class="rt-mono" title="{esc(s)}">{esc(s[:70] + ("…" if len(s) > 70 else ""))}</span>'
    if c.endswith("_at"):
        return f'<span class="rt-mono">{esc(str(v).replace("T", " ")[:19])}</span>'
    if isinstance(v, float):
        return f'<span class="rt-mono">{v:.2f}</span>'
    s = str(v).replace("\r", " ").replace("\n", " ")
    short = s if len(s) <= 90 else s[:90] + "…"
    cls = ' class="rt-mono"' if c in _ID_COLS else ""
    return f'<span{cls} title="{esc(s)}">{esc(short)}</span>'


def render_table(data, cols=None, max_height=420, limit=500):
    """Themed HTML table (works identically in any Streamlit theme)."""
    df = data if isinstance(data, pd.DataFrame) else pd.DataFrame(data)
    if df.empty:
        empty_state("No records to display")
        return
    if cols:
        df = df[[c for c in cols if c in df.columns]]
    df = df.head(limit)
    head = "".join(f"<th>{esc(str(c).replace('_', ' '))}</th>" for c in df.columns)
    rows = []
    for rec in df.to_dict("records"):
        rows.append(
            "<tr>" + "".join(f"<td>{_fmt_cell(str(c), rec[c])}</td>" for c in df.columns) + "</tr>"
        )
    md(
        f'<div class="rt-wrap" style="max-height:{max_height}px"><table class="rt-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


_JSON_RE = re.compile(
    r'("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
)


def json_block(obj, max_height=420):
    """Syntax-highlighted JSON viewer with a fixed dark palette."""
    try:
        text = json.dumps(obj, indent=2, default=str, ensure_ascii=False)
    except Exception:
        text = str(obj)
    text = html.escape(text, quote=False).replace("$", "&#36;")

    def repl(m):
        if m.group(1) and m.group(2):
            return f'<span class="rt-j-key">{m.group(1)}</span>{m.group(2)}'
        if m.group(1):
            return f'<span class="rt-j-str">{m.group(1)}</span>'
        if m.group(3):
            return f'<span class="rt-j-kw">{m.group(3)}</span>'
        return f'<span class="rt-j-num">{m.group(4)}</span>'

    lines = []
    for line in text.split("\n"):
        stripped = line.lstrip(" ")
        indent = "&nbsp;" * (len(line) - len(stripped))
        lines.append(indent + _JSON_RE.sub(repl, stripped))
    md(f'<div class="rt-json" style="max-height:{max_height}px">{"<br>".join(lines)}</div>')


# ── charts ───────────────────────────────────────────────────────────────────
def _style_chart(chart, title=None, height=260):
    if title:
        chart = chart.properties(
            title=alt.TitleParams(
                title, color=MUTED, fontSize=11, fontWeight=600, anchor="start", offset=10
            )
        )
    return (
        chart.properties(
            height=height,
            width="container",
            background="transparent",
            autosize=alt.AutoSizeParams(type="fit", contains="padding"),
            padding={"left": 6, "right": 26, "top": 16, "bottom": 6},
        )
        .configure_view(stroke=None)
        .configure_axis(
            labelColor=MUTED,
            titleColor=MUTED,
            gridColor="#202A36",
            domainColor=BORDER,
            tickColor=BORDER,
            labelFontSize=11,
            titleFontSize=11,
            labelFont=FONT,
            titleFont=FONT,
        )
        .configure_legend(
            labelColor=TEXT,
            titleColor=MUTED,
            orient="bottom",
            direction="horizontal",
            labelFontSize=12,
            labelFont=FONT,
            symbolType="circle",
        )
        .configure_title(font=FONT)
    )


def show_chart(chart):
    try:
        st.altair_chart(chart, theme=None, width="stretch")
    except TypeError:
        st.altair_chart(chart, theme=None, use_container_width=True)


def donut_chart(counts: dict, colors: dict, title: str):
    if not counts:
        return
    df = pd.DataFrame({"label": list(counts.keys()), "value": list(counts.values())})
    domain = list(counts.keys())
    rng = [colors.get(k, GREY) for k in domain]
    chart = (
        alt.Chart(df)
        .mark_arc(innerRadius=58, outerRadius=90, stroke=SURFACE, strokeWidth=3)
        .encode(
            theta=alt.Theta("value:Q"),
            color=alt.Color(
                "label:N", scale=alt.Scale(domain=domain, range=rng), legend=alt.Legend(title=None)
            ),
            tooltip=["label:N", "value:Q"],
        )
    )
    show_chart(_style_chart(chart, title, height=250))


def bar_chart(
    counts: dict, title: str, colors: dict | None = None, order=None, horizontal=False, height=240
):
    if not counts:
        return
    df = pd.DataFrame({"label": list(counts.keys()), "value": list(counts.values())})
    sort = order if order else "-x" if horizontal else "-y"
    if colors:
        color = alt.Color(
            "label:N",
            scale=alt.Scale(
                domain=list(counts.keys()), range=[colors.get(k, GREY) for k in counts]
            ),
            legend=None,
        )
    else:
        color = alt.value(ACCENT)
    if horizontal:
        chart = (
            alt.Chart(df)
            .mark_bar(cornerRadiusEnd=4, height=16)
            .encode(
                y=alt.Y("label:N", sort=sort, title=None),
                x=alt.X("value:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                color=color,
                tooltip=["label:N", "value:Q"],
            )
        )
    else:
        chart = (
            alt.Chart(df)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=38)
            .encode(
                x=alt.X("label:N", sort=sort, title=None, axis=alt.Axis(labelAngle=0)),
                y=alt.Y("value:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                color=color,
                tooltip=["label:N", "value:Q"],
            )
        )
    show_chart(_style_chart(chart, title, height=height))


def _by_id(items, key, value):
    return next((i for i in items if i.get(key) == value), {})


# ─────────────────────────────────────────────────────────────────────────────
# Shell
# ─────────────────────────────────────────────────────────────────────────────
def main():
    md(CSS)

    pages = {
        "Overview": show_overview,
        "Targets": show_targets,
        "Scan": show_scan,
        "Findings": show_findings,
        "Evidence": show_evidence,
        "OWASP Coverage": show_owasp_coverage,
        "Remediation": show_remediation,
        "Retest": show_retest,
        "Regression": show_regression,
        "Scan History": show_scan_history,
        "Checklist": show_checklist,
        "Configuration": show_configuration,
        "Attacks": show_attacks,
    }

    with st.sidebar:
        md(
            '<div class="rt-brand"><div class="rt-logo">RT</div><div>'
            '<div class="rt-brand-name">AI Red Team</div>'
            '<div class="rt-brand-sub">Adversarial Testing</div></div></div>'
            '<div class="rt-nav-label">Workspace</div>'
        )
        page = st.radio(
            "Navigation", list(pages.keys()), label_visibility="collapsed", key="nav_page"
        )
        try:
            h = requests.get(f"{API_BASE_URL}/health", timeout=2).json()
            dot, label = GREEN, f"API online {esc(h.get('version', ''))}".strip()
        except Exception:
            dot, label = RED, "API unreachable"
        md(
            f'<div class="rt-side-card"><div><span class="rt-dot" style="background:{dot};'
            f'box-shadow:0 0 0 3px {dot}22"></span><b>{label}</b></div>'
            f'<div style="margin-top:6px;font-family:var(--mono);font-size:.72rem">{esc(API_BASE_URL)}</div></div>'
        )

    md(
        '<div class="rt-topbar"><div>'
        '<div class="rt-top-title">AI Red Team Dashboard</div>'
        '<div class="rt-top-tag">Break the AI. Prove the vulnerability. Verify the fix.</div></div>'
        '<div class="rt-chips"><span class="rt-chip hot">OWASP GenAI LLM Top 10 · 2026</span>'
        '<span class="rt-chip">Deterministic detection</span>'
        '<span class="rt-chip">Reproducible evidence</span></div></div>'
    )
    show_flash()
    pages[page]()


# ─────────────────────────────────────────────────────────────────────────────
# Overview
# ─────────────────────────────────────────────────────────────────────────────
def show_overview():
    page_header("Overview", "Project progress and scan summary across all targets")
    targets = api_get("/targets")
    scans = api_get("/scans")
    findings, tests = [], []
    for scan in scans:
        findings.extend(api_get(f"/scans/{scan['id']}/findings"))
        tests.extend(api_get(f"/scans/{scan['id']}/tests"))

    pass_c = sum(1 for t in tests if t.get("result") == "PASS")
    fail_c = sum(1 for t in tests if t.get("result") == "FAIL")
    decided = pass_c + fail_c
    rate = f"{pass_c / decided * 100:.0f}%" if decided else "—"

    kpi_row(
        [
            ("Targets", len(targets), "Registered systems", BLUE),
            ("Scans", len(scans), "Executed runs", TEAL),
            (
                "Findings (FAIL)",
                len(findings),
                "Confirmed vulnerabilities",
                RED if findings else GREEN,
            ),
            (
                "Pass / Fail",
                f"{pass_c} / {fail_c}",
                f"Pass rate {rate}",
                GREEN if fail_c == 0 else AMBER,
            ),
        ]
    )

    if tests:
        df = pd.DataFrame(tests)
        section("Test outcomes")
        c1, c2 = st.columns(2)
        with c1:
            counts = df["result"].value_counts().to_dict()
            donut_chart(counts, RESULT_COLORS, "PASS / FAIL DISTRIBUTION")
        with c2:
            if findings:
                sev = pd.DataFrame(findings)["severity"].value_counts().to_dict()
                sev = {k: sev[k] for k in SEV_ORDER if k in sev} | {
                    k: v for k, v in sev.items() if k not in SEV_ORDER
                }
                bar_chart(
                    sev, "FINDINGS BY SEVERITY", colors=SEV_COLORS, order=SEV_ORDER, height=250
                )
            else:
                empty_state("No findings recorded — every executed test passed or was inconclusive")
        section("Latest tests")
        render_table(
            df,
            ["id", "attack_id", "category", "name", "result", "severity"],
            max_height=440,
            limit=20,
        )

    if scans:
        section("Recent scans")
        df = pd.DataFrame(scans[:10])
        render_table(
            df, ["id", "target_id", "taxonomy_version", "status", "started_at", "completed_at"]
        )
    elif not tests:
        empty_state("No scan data yet — add a target and launch your first scan")


# ─────────────────────────────────────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────────────────────────────────────
def show_targets():
    page_header("Targets", "Registered systems, health checks and blue-team protection status")
    tab1, tab2, tab3 = st.tabs(["List & Health", "Add Target", "Target Details"])
    with tab1:
        targets = api_get("/targets")
        if targets:
            render_table(
                targets, ["id", "name", "target_type", "base_url", "is_authorized", "created_at"]
            )
            section("Health checks")
            for t in targets:
                col1, col2 = st.columns([5, 1])
                with col1:
                    md(
                        f'<div class="rt-row"><div><div class="rt-row-main">{esc(t["name"])}</div>'
                        f'<div class="rt-row-sub">{esc(t["base_url"])}</div></div>'
                        f"<div>{badge(t['target_type'], BLUE)}</div></div>"
                    )
                with col2:
                    clicked = st.button(
                        "Run check", key=f"health_{t['id']}", use_container_width=True
                    )
                if clicked:
                    try:
                        r = requests.get(f"{t['base_url']}/health", timeout=5)
                        if r.status_code == 200:
                            st.success(f"{t['name']} healthy — {r.json()}")
                        else:
                            st.warning(f"{t['name']} returned status {r.status_code}")
                    except Exception as e:
                        st.error(f"Health check failed: {e}")
        else:
            empty_state("No targets configured yet")

    with tab2, st.form("add_target"):
        name = st.text_input("Name")
        url = st.text_input("URL", placeholder="http://localhost:8000")
        target_type = st.selectbox("Type", ["llm", "rag", "agent"])
        submitted = st.form_submit_button("Add Target", type="primary")
        if submitted:
            result = api_post(
                "/targets",
                {"name": name, "target_type": target_type, "base_url": url, "config": {}},
            )
            if result:
                flash("success", f"Target added with ID {result['id']}")
                st.rerun()

    with tab3:
        targets = api_get("/targets")
        if targets:
            tid = st.selectbox(
                "Select Target for Details",
                options=[t["id"] for t in targets],
                format_func=lambda x: _by_id(targets, "id", x).get("name", x),
                key="target_details",
            )
            if tid:
                t = _by_id(targets, "id", tid)
                json_block(t, max_height=320)
                section("Protection checks (blue team)")
                checks = api_get("/protections/checks", params={"target_id": tid})
                if checks:
                    render_table(
                        [
                            {
                                "check_id": c.get("check_id"),
                                "name": c.get("name"),
                                "passed": c.get("passed"),
                                "reason": c.get("reason"),
                            }
                            for c in checks
                        ]
                    )
                else:
                    empty_state("No protection checks reported for this target")


# ─────────────────────────────────────────────────────────────────────────────
# Scan
# ─────────────────────────────────────────────────────────────────────────────
def show_scan():
    page_header("Scan", "Launch assessments and monitor progress")
    targets = api_get("/targets")
    if not targets:
        st.warning("Add a target first in the Targets page")
        return

    attacks = api_get("/attacks")
    categories = sorted({a["category"] for a in attacks}) if attacks else []

    with st.form("launcher"):
        col1, col2 = st.columns(2)
        with col1:
            target_id = st.selectbox(
                "Target",
                options=[t["id"] for t in targets],
                format_func=lambda x: _by_id(targets, "id", x).get("name", x),
            )
            category = st.multiselect(
                "Categories (empty = auto for target type)", options=categories
            )
        with col2:
            attack_ids = st.multiselect(
                "Specific Attack IDs (optional)",
                options=[a["attack_id"] for a in attacks] if attacks else [],
            )
            st.caption("Leave both empty to auto-select attacks for the target type.")
        submitted = st.form_submit_button("Launch Scan", type="primary")
        if submitted:
            payload = {"target_id": target_id}
            if attack_ids:
                payload["attack_ids"] = attack_ids
            if category:
                payload["categories"] = category
            with st.spinner("Creating scan..."):
                scan = api_post("/scans", payload)
                if not scan:
                    st.error("Failed to create scan")
                    return
                st.session_state["last_scan_id"] = scan["id"]
                st.session_state["polling_scan_id"] = scan["id"]
                st.session_state["polling_start"] = time.time()
                st.success(f"Scan created ID {scan['id']} — running...")
                run_resp = api_post(f"/scans/{scan['id']}/run", {})
                if run_resp:
                    flash("success", f"Scan {run_resp['id']} completed: {run_resp['status']}")
                    st.rerun()
                else:
                    st.info("Run triggered, polling...")
                    st.session_state["polling_scan_id"] = scan["id"]
                    st.session_state["polling_start"] = time.time()
                    st.rerun()

    # ─── Live polling for scan progress (no full reruns) ───
    if "polling_scan_id" in st.session_state:
        sid = st.session_state["polling_scan_id"]
        section(f"Progress — Scan {sid}")

        # Auto-refresh every 2 seconds using session_state
        if "last_poll" not in st.session_state:
            st.session_state["last_poll"] = 0

        now = time.time()
        if now - st.session_state["last_poll"] > 2:
            st.session_state["last_poll"] = now
            scan = api_get(f"/scans/{sid}")
            if isinstance(scan, dict) and scan.get("status") in ["COMPLETED", "FAILED"]:
                st.session_state.pop("polling_scan_id", None)
                st.session_state.pop("polling_start", None)
                st.session_state.pop("last_poll", None)
                flash("success", f"Scan {sid} {scan['status']}")
                st.rerun()
            else:
                st.rerun()

        scan = api_get(f"/scans/{sid}")
        if isinstance(scan, dict) and scan.get("id"):
            c1, c2, c3 = st.columns(3)
            with c1:
                md(
                    kpi(
                        "Status", str(scan.get("status", "—")), "", status_color(scan.get("status"))
                    )
                )
            with c2:
                md(
                    kpi(
                        "Started",
                        str(scan.get("started_at") or "—").replace("T", " ")[:19],
                        "",
                        BLUE,
                    )
                )
            with c3:
                md(
                    kpi(
                        "Completed",
                        str(scan.get("completed_at") or "—").replace("T", " ")[:19],
                        "",
                        TEAL,
                    )
                )
            tests = api_get(f"/scans/{sid}/tests")
            if tests:
                done = sum(1 for t in tests if t.get("result") not in ["INCONCLUSIVE", None])
                md(
                    f'<div style="margin:18px 0 6px;font-size:.8rem;color:{MUTED}">Conclusive tests: '
                    f'<b style="color:{TEXT}">{done}/{len(tests)}</b></div>{progress_bar(done / len(tests))}'
                )
                section("Test results")
                render_table(
                    tests,
                    [
                        "attack_id",
                        "category",
                        "name",
                        "result",
                        "severity",
                        "reproduction_count",
                        "confidence",
                    ],
                )
                counts = pd.Series([t.get("result") for t in tests]).value_counts().to_dict()
                donut_chart(counts, RESULT_COLORS, "RESULT DISTRIBUTION")
            findings = api_get(f"/scans/{sid}/findings")
            if findings:
                section(f"Findings ({len(findings)})")
                for f in findings:
                    md(
                        f'<div class="rt-row"><div><div class="rt-row-main">{esc(f.get("title"))}</div>'
                        f'<div class="rt-row-sub">{esc(f.get("attack_id"))} · {esc(f.get("category"))}</div></div>'
                        f"<div>{sev_badge(f.get('severity'))}</div></div>"
                    )

    section("All scans — run / inspect")
    scans = api_get("/scans")
    if scans:
        render_table(
            scans, ["id", "target_id", "taxonomy_version", "status", "started_at", "completed_at"]
        )
        md('<div style="height:10px"></div>')
        for s in scans[:5]:
            col1, col2, col3 = st.columns([4, 1, 1])
            with col1:
                md(
                    f'<div class="rt-row"><div class="rt-row-main">Scan {esc(s["id"])}</div>'
                    f"<div>{badge(str(s.get('status')).replace('_', ' '), status_color(s.get('status')))}</div></div>"
                )
            with col2:
                if st.button("Run", key=f"run_{s['id']}", use_container_width=True):
                    res = api_post(f"/scans/{s['id']}/run", {})
                    if res:
                        st.success(f"Ran {s['id']} → {res['status']}")
            with col3:
                if st.button("Findings", key=f"find_{s['id']}", use_container_width=True):
                    st.session_state["last_scan_id"] = s["id"]
                    st.rerun()
    else:
        empty_state("No scans yet")


# ─────────────────────────────────────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────────────────────────────────────
def show_findings():
    page_header("Findings", "Confirmed vulnerabilities with severity and remediation guidance")
    scans = api_get("/scans")
    if not scans:
        empty_state("No scans available")
        return
    scan_id = st.selectbox(
        "Select Scan",
        options=[s["id"] for s in scans],
        format_func=lambda x: f"Scan {x}  ·  {_by_id(scans, 'id', x).get('taxonomy_version', '')}",
        key="findings_scan",
    )
    if not scan_id:
        return
    findings = api_get(f"/scans/{scan_id}/findings")
    if not findings:
        empty_state("No findings for this scan — check Evidence for PASS / INCONCLUSIVE results")
        return

    counts = pd.Series([f.get("severity") for f in findings]).value_counts().to_dict()
    kpi_row(
        [(sev.title(), counts.get(sev, 0), "findings", SEV_COLORS[sev]) for sev in SEV_ORDER[:4]]
    )
    section("All findings")
    render_table(
        findings, ["id", "attack_id", "category", "title", "severity", "regression_status"]
    )

    # ─── Quick Wins: Export Findings ───
    col_exp1, col_exp2, col_exp3 = st.columns(3)
    with col_exp1:
        if st.button("📥 Export Findings (JSON)", use_container_width=True):
            data = json.dumps(findings, indent=2, default=str)
            st.download_button(
                "Download JSON", data, file_name=f"findings_{scan_id}.json", mime="application/json"
            )
    with col_exp2:
        if st.button("📥 Export Findings (CSV)", use_container_width=True):
            df = pd.DataFrame(findings)
            csv = df.to_csv(index=False)
            st.download_button(
                "Download CSV", csv, file_name=f"findings_{scan_id}.csv", mime="text/csv"
            )
    with col_exp3:
        if st.button("📋 Copy cURL for all findings", use_container_width=True):
            # Build a cURL command for the findings API
            curl_cmd = f'curl -X GET "{API_BASE_URL}/scans/{scan_id}/findings" -H "Accept: application/json"'
            st.code(curl_cmd, language="bash")
            st.toast("cURL copied to clipboard!")
            st.session_state["clipboard"] = curl_cmd

    section("Finding detail")
    sev = st.selectbox("Filter Severity", options=["ALL", *SEV_ORDER])
    if sev != "ALL":
        findings = [f for f in findings if f.get("severity") == sev]
    selected = st.selectbox(
        "View Details",
        options=[f["id"] for f in findings],
        format_func=lambda x: _by_id(findings, "id", x).get("title", x),
        key="find_sel",
    )
    if selected:
        f = _by_id(findings, "id", selected)
        md(
            f'<div class="rt-row"><div><div class="rt-row-main" style="font-size:1.05rem">{esc(f.get("title"))}</div>'
            f'<div class="rt-row-sub">{esc(f.get("attack_id"))} · {esc(f.get("category"))}</div></div>'
            f'<div style="display:flex;gap:8px">{sev_badge(f.get("severity"))}'
            f"{badge(str(f.get('regression_status', '—')).replace('_', ' '), status_color(f.get('regression_status')))}"
            f"</div></div>"
        )
        c1, c2 = st.columns(2)
        with c1:
            md(field_card("Root cause", f.get("root_cause")))
            md(field_card("Remediation", f.get("remediation")))
            md(field_card("Retest procedure", f.get("retest_procedure")))
        with c2:
            md(field_card("Impact", f.get("impact")))
            md(field_card("Protection control", f.get("protection_control")))
        with st.expander("Raw finding record"):
            json_block(f, max_height=360)

        # Quick Win: Copy cURL for this specific finding
        col_btn1, col_btn2, col_btn3 = st.columns(3)
        with col_btn1:
            if st.button("🔁 Retest this finding", key=f"retest_{f['id']}", type="primary"):
                res = api_post(f"/findings/{f['id']}/retest", {})
                if res:
                    flash(
                        "success",
                        f"Retest {res['retest_id']} → {res['regression_status']} ({res['result']})",
                    )
                    st.rerun()
        with col_btn2:
            # Copy cURL for this finding
            curl_cmd = f'curl -X POST "{API_BASE_URL}/findings/{f["id"]}/retest" -H "Content-Type: application/json" -d \'{{"approval_token": "HUMAN_APPROVED_123"}}\''
            if st.button("📋 Copy cURL for retest", use_container_width=True):
                st.code(curl_cmd, language="bash")
                st.toast("cURL copied!")
        with col_btn3:
            # Export single finding
            if st.button("📥 Export finding (JSON)", use_container_width=True):
                data = json.dumps(f, indent=2, default=str)
                st.download_button(
                    "Download finding JSON",
                    data,
                    file_name=f"finding_{f['id']}.json",
                    mime="application/json",
                )


# ─────────────────────────────────────────────────────────────────────────────
# Evidence
# ─────────────────────────────────────────────────────────────────────────────
def show_evidence():
    page_header(
        "Evidence",
        "Request · response · tool calls · retrieval · detectors · reproduction (immutable)",
    )
    st.caption("Every FAIL is reproducible — deterministic detectors, never an LLM opinion alone.")
    scans = api_get("/scans")
    if not scans:
        empty_state("No scans available")
        return
    scan_id = st.selectbox(
        "Select Scan for Evidence",
        options=[s["id"] for s in scans],
        format_func=lambda x: f"Scan {x}  ·  {_by_id(scans, 'id', x).get('taxonomy_version', '')}",
        key="evidence_scan",
    )
    if not scan_id:
        return
    evidences = api_get(f"/scans/{scan_id}/evidence")
    if not evidences:
        empty_state("No evidence yet — run the scan first")
        return

    rows = []
    for e in evidences:
        req = e.get("request")
        rows.append(
            {
                "test_id": e.get("test_id"),
                "attack_id": req.get("attack_id")
                if isinstance(req, dict) and req.get("attack_id")
                else e.get("test_id"),
                "result": e.get("result"),
                "confidence": e.get("confidence"),
                "reproduction": e.get("reproduction_count"),
                "detectors": ", ".join(e.get("detectors_triggered") or []),
                "http_status": e.get("http_status"),
            }
        )
    render_table(rows)

    section("Evidence inspector")
    test_ids = [e["test_id"] for e in evidences]
    selected = st.selectbox(
        "Select Test for Detailed Evidence",
        options=test_ids,
        format_func=lambda x: f"Test {x}  ·  {_by_id(evidences, 'test_id', x).get('result', '')}",
        key="evidence_test",
    )
    if selected:
        ev = _by_id(evidences, "test_id", selected)
        meta = ev.get("evidence_metadata")
        repro = ev.get("reproduction_count") or 0
        with st.expander("Request capture", expanded=True):
            json_block(ev.get("request"))
        with st.expander("Response capture", expanded=True):
            json_block(
                {
                    "http_status": ev.get("http_status"),
                    "headers": ev.get("headers"),
                    "response": ev.get("response"),
                }
            )
        with st.expander("Tool-call capture"):
            json_block(ev.get("tool_calls") or "No tool calls (LLM/RAG)")
        with st.expander("Retrieval evidence"):
            json_block(ev.get("retrieved_documents") or "No retrieval (Agent/LLM)")
        with st.expander("Deterministic detection"):
            json_block(
                {
                    "detectors_triggered": ev.get("detectors_triggered"),
                    "expected": ev.get("expected_behavior"),
                    "observed": ev.get("observed_behavior"),
                    "confidence": ev.get("confidence"),
                }
            )
        with st.expander("Reproduction tracking"):
            json_block(
                {
                    "reproduction_count": repro,
                    "reproducible": repro > 1,
                    "hash": meta.get("evidence_hash", "n/a") if isinstance(meta, dict) else "n/a",
                }
            )
        st.caption(
            "Evidence is immutable once the scan is COMPLETED. Every FAIL above is reproducible — "
            "request/response and detectors prove the vulnerability."
        )
        findings = api_get(f"/scans/{scan_id}/findings")
        for f in findings:
            if f.get("test_id") == selected:
                if st.button(
                    f"Compare before / after — finding {f['id']}", key=f"compare_{f['id']}"
                ):
                    json_block(api_get(f"/findings/{f['id']}/compare"))


# ─────────────────────────────────────────────────────────────────────────────
# OWASP Coverage
# ─────────────────────────────────────────────────────────────────────────────
def show_owasp_coverage():
    page_header("OWASP Coverage", "Taxonomy version per scan and attack coverage by category")
    scans = api_get("/scans")
    attacks = api_get("/attacks")
    if scans:
        versions = pd.Series([s["taxonomy_version"] for s in scans]).value_counts().to_dict()
        kpi_row(
            [
                ("Current taxonomy", scans[0]["taxonomy_version"], "Latest scan", ACCENT),
                ("Attack definitions", len(attacks) if attacks else 0, "Loaded", BLUE),
                (
                    "Categories",
                    len({a["category"] for a in attacks}) if attacks else 0,
                    "Covered",
                    TEAL,
                ),
            ]
        )
        c1, c2 = st.columns([1, 2])
        with c1:
            bar_chart(versions, "SCANS PER TAXONOMY VERSION", height=260)
        cov_counts = None
        if attacks:
            cov_counts = pd.DataFrame(attacks)["category"].value_counts().sort_index().to_dict()
        with c2:
            if cov_counts:
                bar_chart(
                    cov_counts,
                    "ATTACKS PER OWASP CATEGORY",
                    horizontal=True,
                    order="ascending",
                    height=260,
                )
    if attacks:
        section("Attack catalogue")
        render_table(
            attacks, ["attack_id", "category", "name", "severity", "target_types"], max_height=460
        )
        section("Coverage by category")
        cats = sorted({a["category"] for a in attacks})
        cols = st.columns(2)
        for i, cat in enumerate(cats):
            c_atks = [a for a in attacks if a["category"] == cat]
            chips = "".join(
                f'<span class="rt-chip-sm">{esc(a["attack_id"])}</span>' for a in c_atks
            )
            with cols[i % 2]:
                md(
                    f'<div class="rt-field"><div class="rt-field-l">{esc(cat)} · {len(c_atks)} attack(s)</div>'
                    f'<div class="rt-field-v">{chips}</div></div>'
                )
    elif not scans:
        empty_state("No taxonomy data available")


# ─────────────────────────────────────────────────────────────────────────────
# Remediation
# ─────────────────────────────────────────────────────────────────────────────
def show_remediation():
    page_header("Remediation", "Root cause, protection controls and fix guidance — then retest")
    scans = api_get("/scans")
    if not scans:
        empty_state("No scans available")
        return
    scan_id = st.selectbox(
        "Select Scan for Remediation",
        options=[s["id"] for s in scans],
        format_func=lambda x: f"Scan {x}",
        key="rem_scan",
    )
    if not scan_id:
        return
    findings = api_get(f"/scans/{scan_id}/findings")
    if not findings:
        empty_state("No findings — all tests PASS or INCONCLUSIVE")
        return
    section(f"{len(findings)} finding(s) to remediate")
    for f in findings:
        with st.expander(
            f"{f.get('attack_id')} — {f.get('title')}   [{f.get('severity')}]", expanded=False
        ):
            md(sev_badge(f.get("severity")))
            c1, c2 = st.columns(2)
            with c1:
                md(field_card("Root cause", f.get("root_cause")))
                md(field_card("Protection", f.get("protection_control")))
                md(field_card("Retest procedure", f.get("retest_procedure")))
            with c2:
                md(field_card("Impact", f.get("impact")))
                md(field_card("Remediation", f.get("remediation")))
            rem = api_get(f"/attacks/{f['attack_id']}/remediation")
            if rem:
                st.caption("Attack-level remediation playbook")
                json_block(rem, max_height=320)


# ─────────────────────────────────────────────────────────────────────────────
# Retest
# ─────────────────────────────────────────────────────────────────────────────
def show_retest():
    page_header("Retest", "Fix verification — FAIL → PASS with before / after comparison")
    st.caption(
        "Real retest: a new scan of the same attack, compared against the original and tracked for regression."
    )
    scans = api_get("/scans")
    if not scans:
        empty_state("No scans available")
        return
    scan_id = st.selectbox(
        "Select Original Scan", options=[s["id"] for s in scans], key="retest_scan"
    )
    if not scan_id:
        return
    findings = api_get(f"/scans/{scan_id}/findings")
    if not findings:
        empty_state("No findings to retest")
        return
    fid = st.selectbox(
        "Select Finding to Retest",
        options=[f["id"] for f in findings],
        format_func=lambda x: _by_id(findings, "id", x).get("attack_id", x),
        key="retest_fid",
    )
    if not fid:
        return
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button(
            "Retest finding", key=f"do_retest_{fid}", type="primary", use_container_width=True
        ):
            res = api_post(f"/findings/{fid}/retest", {})
            if res:
                flash(
                    "success",
                    f"Retest {res['retest_id']} → {res['regression_status']} ({res['result']})",
                )
                st.rerun()
    with col2:
        show_hist = st.button("Show history", key=f"hist_{fid}", use_container_width=True)
    with col3:
        show_comp = st.button("Show comparison", key=f"comp_{fid}", use_container_width=True)

    if show_hist:
        section("History (raw)")
        json_block(api_get(f"/findings/{fid}/history"))
    if show_comp:
        section("Comparison (raw)")
        json_block(api_get(f"/findings/{fid}/compare"))

    hist = api_get(f"/findings/{fid}/history")
    if hist:
        section("Retest history")
        render_table(hist, ["id", "scan_id", "result", "notes", "created_at"])
    comp = api_get(f"/findings/{fid}/compare")
    if isinstance(comp, dict) and comp.get("latest_retest"):
        section("Before → After")
        after = comp["latest_retest"].get("result")
        verified = comp.get("verified")
        md(
            f'<div class="rt-row"><div style="display:flex;align-items:center;gap:14px">'
            f"{badge(comp.get('original_result'), status_color(comp.get('original_result')))}"
            f'<span style="color:{MUTED}">→</span>{badge(after, status_color(after))}</div>'
            f"<div>{badge('Verified' if verified else 'Not verified', GREEN if verified else AMBER)}</div></div>"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Regression
# ─────────────────────────────────────────────────────────────────────────────
def show_regression():
    page_header("Regression", "Finding history and lifecycle across scans")
    scans = api_get("/scans")
    if not scans:
        empty_state("No scans available")
        return
    all_findings = []
    for s in scans:
        all_findings.extend(api_get(f"/scans/{s['id']}/findings"))
    if not all_findings:
        empty_state("No findings recorded")
        return
    render_table(
        all_findings, ["id", "attack_id", "category", "title", "severity", "regression_status"]
    )
    section("Lifecycle")
    fid = st.selectbox(
        "Select Finding for Lifecycle",
        options=[f["id"] for f in all_findings],
        format_func=lambda x: _by_id(all_findings, "id", x).get("attack_id", x),
        key="reg_fid",
    )
    if fid:
        lc = api_get(f"/findings/{fid}/lifecycle")
        if isinstance(lc, dict) and lc:
            kpi_row(
                [
                    (
                        "Current status",
                        str(lc.get("current_status", "—")).replace("_", " "),
                        "",
                        status_color(lc.get("current_status")),
                    ),
                    ("Retests", lc.get("retest_count", 0), "Verification runs", BLUE),
                ]
            )
            history = lc.get("history") or []
            if history:
                section("Timeline")
                items = "".join(
                    f'<div class="rt-tl-i" style="--tc:{status_color(h.get("result"))}">'
                    f'<div class="rt-tl-t">Scan {esc(h.get("scan_id"))} &nbsp;{badge(h.get("result"), status_color(h.get("result")))}</div>'
                    f'<div class="rt-tl-d">{esc(str(h.get("created_at", "")).replace("T", " ")[:19])}</div></div>'
                    for h in history
                )
                md(f'<div class="rt-tl">{items}</div>')
            with st.expander("Raw lifecycle record"):
                json_block(lc)


# ─────────────────────────────────────────────────────────────────────────────
# Checklist
# ─────────────────────────────────────────────────────────────────────────────
def show_checklist():
    page_header("Project Checklist", "Sprint progress and task verification")
    items = api_get("/checklist")
    if not items:
        empty_state("No checklist items")
        return
    sprints = {}
    for it in items:
        sprints.setdefault(it["sprint"], {"total": 0, "verified": 0})
        sprints[it["sprint"]]["total"] += 1
        if it["status"] == "VERIFIED":
            sprints[it["sprint"]]["verified"] += 1

    total = sum(c["total"] for c in sprints.values())
    verified = sum(c["verified"] for c in sprints.values())
    kpi_row(
        [
            (
                "Overall progress",
                f"{verified / total * 100:.0f}%" if total else "0%",
                f"{verified} of {total} tasks verified",
                GREEN,
            ),
            ("Sprints", len(sprints), "Tracked", BLUE),
            ("Open tasks", total - verified, "Not yet verified", AMBER),
        ]
    )

    section("Sprint progress")
    cols = st.columns(3)
    for i, (sprint, counts) in enumerate(sorted(sprints.items())):
        pct = counts["verified"] / counts["total"] if counts["total"] else 0
        with cols[i % 3]:
            md(
                f'<div class="rt-sprint"><div class="rt-sprint-h"><b>{esc(sprint)}</b>'
                f"<span>{counts['verified']}/{counts['total']} · {pct * 100:.0f}%</span></div>"
                f"{progress_bar(pct, GREEN if pct >= 1 else ACCENT)}</div>"
            )

    current_sprint = None
    for item in items:
        if item["sprint"] != current_sprint:
            current_sprint = item["sprint"]
            section(str(current_sprint))
        options = ["TODO", "IN_PROGRESS", "VERIFIED", "BLOCKED"]
        col1, col2 = st.columns([4, 1])
        with col1:
            md(
                f'<div class="rt-row"><div class="rt-row-main" style="font-weight:500">{esc(item["task"])}</div>'
                f"<div>{badge(item['status'].replace('_', ' '), status_color(item['status']))}</div></div>"
            )
        with col2:
            new_status = st.selectbox(
                "Status",
                options,
                index=options.index(item["status"]) if item["status"] in options else 0,
                key=f"status_{item['id']}",
                label_visibility="collapsed",
            )
            if new_status != item["status"]:
                api_post(f"/checklist/{item['id']}", {"status": new_status})
                st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# Scan history
# ─────────────────────────────────────────────────────────────────────────────
def show_scan_history():
    page_header("Scan History", "Every scan with tests, findings, evidence and exportable reports")
    scans = api_get("/scans")
    if not scans:
        empty_state("No scans available")
        return
    df = pd.DataFrame(scans)
    render_table(
        df,
        [
            "id",
            "target_id",
            "taxonomy_version",
            "status",
            "started_at",
            "completed_at",
            "created_at",
        ],
    )
    section("Scan detail")
    sid = st.selectbox("Select Scan for Details", options=[s["id"] for s in scans], key="hist_scan")
    if not sid:
        return
    tests = api_get(f"/scans/{sid}/tests")
    if tests:
        st.markdown("**Tests**")
        render_table(
            tests,
            [
                "attack_id",
                "category",
                "name",
                "result",
                "severity",
                "reproduction_count",
                "confidence",
            ],
        )
    findings = api_get(f"/scans/{sid}/findings")
    if findings:
        st.markdown("**Findings**")
        render_table(findings, ["attack_id", "title", "severity", "regression_status"])
    evidences = api_get(f"/scans/{sid}/evidence")
    if evidences:
        st.markdown("**Evidence summary**")
        json_block(
            [
                {
                    "test_id": e.get("test_id"),
                    "result": e.get("result"),
                    "detectors": e.get("detectors_triggered"),
                }
                for e in evidences
            ],
            max_height=300,
        )

    section("Reports")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Generate JSON report", key=f"json_{sid}", use_container_width=True):
            r = api_get_raw(f"/scans/{sid}/report?format=json")
            if r:
                data = r.json()
                json_block(data, max_height=380)
                st.download_button(
                    "Download JSON",
                    json.dumps(data, indent=2, default=str),
                    file_name=f"scan_{sid}_report.json",
                    mime="application/json",
                )
    with col2:
        if st.button("Generate Markdown report", key=f"md_{sid}", use_container_width=True):
            r = api_get_raw(f"/scans/{sid}/report?format=markdown")
            if r:
                st.text(r.text[:3000])
                st.download_button(
                    "Download Markdown",
                    r.text,
                    file_name=f"scan_{sid}_report.md",
                    mime="text/markdown",
                )
    with col3:
        if st.button("Generate HTML report", key=f"html_{sid}", use_container_width=True):
            r = api_get_raw(f"/scans/{sid}/report?format=html")
            if r:
                st.success("HTML report generated")
                md(
                    f'<a href="{esc(API_BASE_URL)}/scans/{esc(sid)}/report?format=html" target="_blank">Open report in new tab ↗</a>'
                )
                st.download_button(
                    "Download HTML", r.text, file_name=f"scan_{sid}_report.html", mime="text/html"
                )


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
def show_configuration():
    page_header("Configuration", "Budgets, taxonomy and target authorization")
    scans = api_get("/scans")
    attacks = api_get("/attacks")
    kpi_row(
        [
            (
                "Current taxonomy",
                scans[0]["taxonomy_version"] if scans else "—",
                "From latest scan",
                ACCENT,
            ),
            ("Total attacks", len(attacks) if attacks else 0, "Definitions loaded", BLUE),
            (
                "API endpoint",
                API_BASE_URL.replace("http://", "").replace("https://", ""),
                "Backend service",
                TEAL,
            ),
        ]
    )
    section("Per-scan budgets")
    b = st.columns(4)
    budgets = [
        ("Max requests", "100"),
        ("Max tokens", "50,000"),
        ("Max runtime", "300 s"),
        ("Max tool calls", "50"),
    ]
    for col, (label, value) in zip(b, budgets, strict=False):
        with col:
            md(kpi(label, value, "per scan", AMBER))
    section("Authorization")
    st.info(
        "Target authorization: localhost by default; an explicit allowlist is required for remote targets "
        "(see app/security/authorization.py:14)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Attacks
# ─────────────────────────────────────────────────────────────────────────────
def show_attacks():
    page_header("Attack Definitions", "OWASP 2026 attack library")
    attacks = api_get("/attacks")
    if not attacks:
        empty_state("No attacks loaded")
        return
    sev_counts = pd.Series([a.get("severity") for a in attacks]).value_counts().to_dict()
    kpi_row(
        [("Total", len(attacks), "Attack definitions", ACCENT)]
        + [(s.title(), sev_counts.get(s, 0), "attacks", SEV_COLORS[s]) for s in SEV_ORDER[:3]]
    )
    section("Library")
    render_table(
        attacks, ["attack_id", "category", "name", "severity", "target_types"], max_height=460
    )
    section("Browse by category")
    cat = st.selectbox(
        "Filter Category", options=["ALL", *sorted({a["category"] for a in attacks})]
    )
    if cat != "ALL":
        attacks = [a for a in attacks if a["category"] == cat]
        render_table(attacks, ["attack_id", "name", "severity"])
        for a in attacks:
            with st.expander(f"{a['attack_id']} — {a['name']}", expanded=False):
                json_block(a, max_height=360)


if __name__ == "__main__":
    main()
