#!/usr/bin/env python3
"""
Detection Rule Validator v6
============================
Platform-aware detection rule validation with:
  - 7 Knowledge Base integrations (Armis, Cribl, Obsidian, Okta, PAN-OS, ProofPoint, SentinelOne)
  - Multi-format rule parsing (Sigma, KQL, S1QL, ASQ, OQL, PAN-OS, Okta EventHook)
  - Synthetic + real log telemetry generation
  - AI-powered recommendations engine (KB-grounded)
  - Full export: HTML, JSON, CSV

Place this file alongside detection_validator.py and the knowledge_bases/ folder:
  knowledge_bases/
    armis_centrix_knowledge_base.json
    cribl_datalake_detection_knowledge_base.json
    obsidian_security_detection_knowledge_base.json
    okta_detection_engineering_knowledge_base.json
    palo_alto_firewall_knowledge_base.json
    proofpoint_email_security_knowledge_base.json
    sentinelone_knowledge_base.json
"""

import base64
import csv
import datetime
import importlib.util
import io
import json
import logging
import re
import sys
from pathlib import Path
from typing import Optional

import streamlit as st
import streamlit.components.v1 as components

# Validate pyyaml is available early so the error message is clear
try:
    import yaml as _yaml_check  # noqa: F401 — existence check only
    del _yaml_check
except ImportError:
    st.error(
        "❌ Missing dependency: **pyyaml** is required for Sigma rule parsing.\n\n"
        "Add `pyyaml` to your `requirements.txt` and redeploy."
    )
    st.stop()

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Detection Rule Validator",
    page_icon="⚔️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ═══════════════════════════════════════════════════════════════════════════════
# THEME / CSS
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ═══════════════════════════════════════════════════════
   Apple HIG Design System — Detection Rule Validator
   Clarity · Deference · Depth · Consistency
   ═══════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ── Design tokens ──────────────────────────────────────────── */
:root{
  --bg:          #07080e;
  --surface-1:   #0d0f18;
  --surface-2:   #111420;
  --surface-3:   #161929;
  --border:      rgba(255,255,255,.07);
  --border-hi:   rgba(255,255,255,.13);
  --text-1:      #eef1f8;
  --text-2:      #8595ae;
  --text-3:      #44546a;
  --accent:      #0ea5e9;
  --accent-dim:  rgba(14,165,233,.1);
  --accent-glow: rgba(14,165,233,.18);
  --green:  #10b981;  --green-dim:  rgba(16,185,129,.1);
  --amber:  #f59e0b;  --amber-dim:  rgba(245,158,11,.08);
  --red:    #ef4444;  --red-dim:    rgba(239,68,68,.08);
  --purple: #8b5cf6;  --purple-dim: rgba(139,92,246,.1);
  --teal:   #14b8a6;  --teal-dim:   rgba(20,184,166,.08);
  --orange: #f97316;
  --r-xs: 6px; --r-sm: 10px; --r-md: 14px; --r-lg: 20px; --r-xl: 28px;
  --ease: cubic-bezier(.4,0,.2,1);
  --spring: cubic-bezier(.34,1.56,.64,1);
  --dur-fast: .14s; --dur-base: .22s; --dur-slow: .36s;
  --shadow-sm: 0 1px 4px rgba(0,0,0,.5);
  --shadow-md: 0 4px 20px rgba(0,0,0,.55);
  --shadow-lg: 0 12px 40px rgba(0,0,0,.65);
  --shadow-accent: 0 0 28px rgba(14,165,233,.2);
}

/* ── Reset ──────────────────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box}
html,body,[class*="css"]{
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;
  background:var(--bg); color:var(--text-1);
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;
}

/* ── App shell ──────────────────────────────────────────────── */
.stApp{
  background:var(--bg);
  background-image:
    radial-gradient(ellipse 90% 55% at 50% -5%, rgba(14,165,233,.055) 0%, transparent 65%),
    radial-gradient(ellipse 50% 40% at 85% 95%, rgba(139,92,246,.04) 0%, transparent 60%);
  min-height:100vh;
}
#MainMenu,footer,header,[data-testid="stDecoration"]{visibility:hidden!important;height:0!important}
.block-container{padding:0 2.2rem 5rem;max-width:1340px;margin:0 auto}

/* ── Sidebar ────────────────────────────────────────────────── */
section[data-testid="stSidebar"]{
  background:var(--surface-1)!important;
  border-right:1px solid var(--border)!important;
  box-shadow:8px 0 40px rgba(0,0,0,.6)!important;
}
section[data-testid="stSidebar"]>div{padding:1.4rem 1.1rem 2rem}

/* Sidebar toggle — pill tab, always visible */
[data-testid="collapsedControl"]{
  background:var(--surface-2)!important;
  border:1px solid var(--border-hi)!important;
  border-left:none!important;
  border-radius:0 var(--r-md) var(--r-md) 0!important;
  width:30px!important; height:72px!important;
  top:calc(50vh - 36px)!important;
  display:flex!important; align-items:center!important; justify-content:center!important;
  box-shadow:4px 0 16px rgba(0,0,0,.5), var(--shadow-accent)!important;
  transition:all var(--dur-base) var(--ease)!important;
  cursor:pointer!important;
}
[data-testid="collapsedControl"]:hover{
  background:var(--accent-dim)!important;
  border-color:var(--accent)!important;
  box-shadow:4px 0 24px var(--accent-glow)!important;
  width:36px!important;
}
[data-testid="collapsedControl"] svg{width:14px!important;color:var(--accent)!important}

/* ── Typography (HIG scale) ─────────────────────────────────── */
h1,h2,h3,h4{font-family:'Inter',sans-serif!important;color:var(--text-1)!important;font-weight:700!important;letter-spacing:-.025em}
.t-display{font-size:clamp(32px,5vw,52px);font-weight:800;line-height:1.05;letter-spacing:-.035em;color:var(--text-1)}
.t-title1{font-size:24px;font-weight:700;line-height:1.2;letter-spacing:-.02em}
.t-title2{font-size:18px;font-weight:600;line-height:1.3}
.t-headline{font-size:14px;font-weight:600;color:var(--text-1)}
.t-body{font-size:13px;line-height:1.65;color:var(--text-2)}
.t-caption{font-size:11px;font-weight:500;letter-spacing:.02em;color:var(--text-3)}
.t-label{font-size:10px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--text-3)}

/* ── Cards ──────────────────────────────────────────────────── */
.card{background:var(--surface-1);border:1px solid var(--border);border-radius:var(--r-md);
  padding:20px 22px;margin-bottom:12px;transition:border-color var(--dur-base) var(--ease)}
.card:hover{border-color:var(--border-hi)}
.card-accent{border-color:rgba(14,165,233,.25);background:rgba(14,165,233,.04)}
.card-green{border-color:rgba(16,185,129,.2);background:var(--green-dim)}
.card-blue{border-color:rgba(14,165,233,.25);background:rgba(14,165,233,.04)}
.card-red{border-color:rgba(239,68,68,.2);background:var(--red-dim)}
.card-amber{border-color:rgba(245,158,11,.2);background:var(--amber-dim)}
.card-purple{border-color:rgba(139,92,246,.2);background:var(--purple-dim)}
.card-teal{border-color:rgba(20,184,166,.2);background:var(--teal-dim)}

/* Hero card for home page */
.card-hero{
  background:linear-gradient(160deg,rgba(14,165,233,.06),rgba(139,92,246,.04) 60%,transparent);
  border:1px solid rgba(14,165,233,.22);
  border-radius:var(--r-xl);
  box-shadow:var(--shadow-lg),var(--shadow-accent);
}

/* Input wrapper — home page centred input */
.hero-input-wrap{
  position:relative;
  border:1.5px solid rgba(14,165,233,.3);
  border-radius:var(--r-lg);
  background:var(--surface-1);
  box-shadow:var(--shadow-md),0 0 40px rgba(14,165,233,.07);
  transition:border-color var(--dur-base) var(--ease), box-shadow var(--dur-base) var(--ease);
  overflow:hidden;
}
.hero-input-wrap:focus-within{
  border-color:rgba(14,165,233,.55);
  box-shadow:var(--shadow-lg),0 0 48px rgba(14,165,233,.15);
}
.hero-input-inner{padding:18px 20px 6px}

/* ── Grade badge ────────────────────────────────────────────── */
.grade-badge{display:inline-flex;align-items:center;justify-content:center;
  width:84px;height:84px;border-radius:50%;font-size:38px;font-weight:800;border:2.5px solid}
.grade-A{color:var(--green);border-color:var(--green);box-shadow:0 0 32px rgba(16,185,129,.25)}
.grade-B{color:var(--accent);border-color:var(--accent);box-shadow:0 0 32px rgba(14,165,233,.25)}
.grade-C{color:var(--amber);border-color:var(--amber);box-shadow:0 0 32px rgba(245,158,11,.25)}
.grade-D{color:var(--orange);border-color:var(--orange);box-shadow:0 0 32px rgba(249,115,22,.25)}
.grade-F{color:var(--red);border-color:var(--red);box-shadow:0 0 32px rgba(239,68,68,.25)}

/* ── Metrics ────────────────────────────────────────────────── */
.metric-num{font-size:30px;font-weight:700;line-height:1;letter-spacing:-.025em}
.metric-label{font-size:10px;font-weight:600;letter-spacing:.09em;text-transform:uppercase;color:var(--text-3);margin-bottom:5px}
.metric-sub{font-size:11px;color:var(--text-3);margin-top:5px}
.section-title{font-size:10px;font-weight:600;letter-spacing:.11em;text-transform:uppercase;
  color:var(--text-3);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border)}

/* ── Progress ───────────────────────────────────────────────── */
.prog-track{background:rgba(255,255,255,.05);border-radius:100px;height:5px;overflow:hidden;margin:8px 0}
.prog-fill{height:100%;border-radius:100px;transition:width .5s var(--ease)}

/* ── Confusion matrix ───────────────────────────────────────── */
.cm-cell{border-radius:var(--r-sm);padding:18px 12px;text-align:center}
.cm-tp{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.2)}
.cm-tn{background:rgba(14,165,233,.06);border:1px solid rgba(14,165,233,.18)}
.cm-fp{background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.18)}
.cm-fn{background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.18)}

/* ── Pills ──────────────────────────────────────────────────── */
.pill{display:inline-block;padding:3px 10px;border-radius:100px;
  font-size:10px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;margin:2px 3px 2px 0}
.pill-blue{background:rgba(14,165,233,.1);color:#38bdf8;border:1px solid rgba(14,165,233,.25)}
.pill-green{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.25)}
.pill-red{background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.25)}
.pill-amber{background:rgba(245,158,11,.09);color:#fbbf24;border:1px solid rgba(245,158,11,.25)}
.pill-purple{background:rgba(139,92,246,.1);color:#a78bfa;border:1px solid rgba(139,92,246,.25)}
.pill-teal{background:rgba(20,184,166,.09);color:#2dd4bf;border:1px solid rgba(20,184,166,.2)}
.pill-gray{background:rgba(148,163,184,.07);color:#64748b;border:1px solid rgba(148,163,184,.14)}

/* ── Findings ───────────────────────────────────────────────── */
.finding{background:rgba(255,255,255,.015);border-left:3px solid;border-radius:0 var(--r-sm) var(--r-sm) 0;padding:14px 18px;margin:8px 0}
.finding-fn{border-left-color:var(--amber)}
.finding-fp{border-left-color:var(--red)}
.finding-ev{border-left-color:var(--purple)}

/* ── Recommendations ────────────────────────────────────────── */
.rec-card{background:rgba(255,255,255,.018);border-left:3px solid;border-radius:0 var(--r-md) var(--r-md) 0;
  padding:16px 20px;margin:10px 0;transition:background var(--dur-fast) var(--ease)}
.rec-card:hover{background:rgba(255,255,255,.03)}

/* ── Model selector chips ───────────────────────────────────── */
.model-chip-row{display:flex;flex-wrap:wrap;gap:7px;padding:2px 0 8px}
.model-chip{
  display:inline-flex;align-items:center;gap:5px;
  padding:5px 13px;border-radius:100px;
  border:1px solid var(--border);background:var(--surface-2);
  font-size:11px;font-weight:500;color:var(--text-2);
  cursor:pointer;transition:all var(--dur-fast) var(--ease);white-space:nowrap;
  user-select:none;
}
.model-chip:hover{border-color:var(--border-hi);color:var(--text-1);background:var(--surface-3)}
.model-chip.chip-default{
  border-color:rgba(14,165,233,.4);color:var(--accent);background:var(--accent-dim);
  box-shadow:0 0 10px rgba(14,165,233,.12);
}
.model-chip.chip-openai{border-color:rgba(16,185,129,.3);color:var(--green)}
.model-chip.chip-anthropic{border-color:rgba(139,92,246,.3);color:#a78bfa}
.model-chip.chip-google{border-color:rgba(14,165,233,.3);color:#60a5fa}

/* ── Generated rule block ───────────────────────────────────── */
.gen-rule-wrap{
  border:1px solid rgba(14,165,233,.22);border-radius:var(--r-md);
  background:rgba(14,165,233,.03);padding:16px;margin-top:14px;
  animation:fadeUp var(--dur-slow) var(--ease) both;
}
.gen-rule-header{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);
}

/* ── Real log badge ─────────────────────────────────────────── */
.real-badge{font-size:9px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  color:var(--teal);background:var(--teal-dim);border:1px solid rgba(20,184,166,.2);
  border-radius:4px;padding:1px 6px;margin-left:6px}

/* ── Motion ─────────────────────────────────────────────────── */
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes popIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}
.anim-fade-up{animation:fadeUp var(--dur-slow) var(--ease) both}
.anim-pop{animation:popIn var(--dur-base) var(--spring) both}

/* ── Streamlit widget overrides ─────────────────────────────── */
/* Transparent textarea for hero wrapper */
.stTextArea>label{display:none!important}
.stTextArea>div{background:transparent!important;border:none!important;padding:0!important}
.stTextArea textarea{
  background:transparent!important;border:none!important;
  color:var(--text-1)!important;
  font-family:'JetBrains Mono',monospace!important;font-size:12px!important;
  line-height:1.65!important;resize:none!important;box-shadow:none!important;
  caret-color:var(--accent)!important;
}
.stTextArea textarea:focus{border:none!important;box-shadow:none!important}
.stTextArea textarea::placeholder{color:var(--text-3)!important}

.stSelectbox>div>div{
  background:var(--surface-2)!important;border:1px solid var(--border)!important;
  color:var(--text-1)!important;border-radius:var(--r-sm)!important;font-size:13px!important}
.stSelectbox>div>div:focus-within{border-color:rgba(14,165,233,.4)!important}

.stNumberInput>div>div>input{
  background:var(--surface-2)!important;border:1px solid var(--border)!important;
  color:var(--text-1)!important;border-radius:var(--r-sm)!important;font-size:13px!important}

.stButton>button{
  background:linear-gradient(135deg,#075985,#0284c7)!important;color:#e0f7ff!important;
  border:1px solid rgba(14,165,233,.5)!important;
  font-family:'Inter',sans-serif!important;font-weight:600!important;
  font-size:13px!important;letter-spacing:.03em!important;
  border-radius:var(--r-sm)!important;padding:10px 22px!important;
  transition:all var(--dur-base) var(--ease)!important;
  box-shadow:0 1px 4px rgba(0,0,0,.4),0 0 18px rgba(14,165,233,.08)!important}
.stButton>button:hover{
  background:linear-gradient(135deg,#0284c7,#0ea5e9)!important;
  box-shadow:0 4px 24px rgba(14,165,233,.38)!important;transform:translateY(-1px)!important}
.stButton>button:active{transform:translateY(0)!important;transition-duration:var(--dur-fast)!important}

.stFileUploader{
  background:var(--surface-2)!important;
  border:1px dashed rgba(255,255,255,.1)!important;border-radius:var(--r-md)!important}

.streamlit-expanderHeader{
  background:var(--surface-2)!important;border:1px solid var(--border)!important;
  border-radius:var(--r-sm)!important;font-size:13px!important;font-weight:500!important;
  color:var(--text-1)!important;padding:10px 16px!important;
  transition:all var(--dur-fast) var(--ease)!important}
.streamlit-expanderHeader:hover{border-color:var(--border-hi)!important;background:var(--surface-3)!important}

.stTabs [data-baseweb="tab-list"]{
  background:transparent!important;border-bottom:1px solid var(--border)!important;gap:3px!important}
.stTabs [data-baseweb="tab"]{
  background:transparent!important;color:var(--text-3)!important;
  border-radius:var(--r-sm) var(--r-sm) 0 0!important;
  font-size:12px!important;font-weight:500!important;padding:9px 15px!important;
  border:1px solid transparent!important;border-bottom:none!important;
  transition:all var(--dur-fast) var(--ease)!important}
.stTabs [aria-selected="true"]{
  background:var(--surface-1)!important;color:var(--text-1)!important;
  border-color:var(--border)!important;border-bottom-color:var(--surface-1)!important}
.stTabs [data-baseweb="tab"]:hover:not([aria-selected="true"]){
  color:var(--text-2)!important;background:rgba(255,255,255,.03)!important}

hr{border-color:var(--border)!important;margin:14px 0!important}
pre,code{font-family:'JetBrains Mono',monospace!important;font-size:12px!important}

::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.09);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.17)}
*:focus-visible{outline:2px solid var(--accent)!important;outline-offset:2px!important}
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# PLATFORM REGISTRY — maps UI name → KB filename
# ═══════════════════════════════════════════════════════════════════════════════
PLATFORM_META = {
    "Armis Centrix": {
        "kb_file": "armis_centrix_knowledge_base.json",
        "icon": "📡", "color": "#06b6d4",
        "lang": "ASQ", "log_source": "IoT/OT Network",
        "desc": "Agentless asset intelligence & IoT/OT device security",
    },
    "Cribl Data Lake": {
        "kb_file": "cribl_datalake_detection_knowledge_base.json",
        "icon": "🗄️", "color": "#8b5cf6",
        "lang": "KQL", "log_source": "Aggregated Pipeline",
        "desc": "Federated search across Cribl pipelines and data lake",
    },
    "Obsidian SaaS Security": {
        "kb_file": "obsidian_security_detection_knowledge_base.json",
        "icon": "☁️", "color": "#10b981",
        "lang": "OQL", "log_source": "SaaS Activity",
        "desc": "SaaS app monitoring, OAuth, shadow IT, posture management",
    },
    "Okta Identity Management": {
        "kb_file": "okta_detection_engineering_knowledge_base.json",
        "icon": "🔑", "color": "#f59e0b",
        "lang": "EventHook / SCIM", "log_source": "Identity Events",
        "desc": "Auth events, MFA fatigue, session anomalies, privilege changes",
    },
    "Palo Alto Firewall": {
        "kb_file": "palo_alto_firewall_knowledge_base.json",
        "icon": "🔥", "color": "#ef4444",
        "lang": "PAN-OS Filter", "log_source": "Firewall/Threat Logs",
        "desc": "NGFW traffic, threat, URL, WildFire, Cortex XDR logs",
    },
    "ProofPoint Email Security": {
        "kb_file": "proofpoint_email_security_knowledge_base.json",
        "icon": "📧", "color": "#f97316",
        "lang": "Smart Search", "log_source": "Email Gateway",
        "desc": "Phishing, BEC, malware delivery, email auth (DMARC/DKIM/SPF)",
    },
    "SentinelOne EDR": {
        "kb_file": "sentinelone_knowledge_base.json",
        "icon": "🛡️", "color": "#22d3ee",
        "lang": "S1QL", "log_source": "Endpoint Events",
        "desc": "Process, file, network, registry, threat telemetry",
    },
}

GRADE_COLORS = {"A": "#10b981", "B": "#06b6d4", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}
GRADE_THRESHOLDS = {"A": 0.90, "B": 0.80, "C": 0.70, "D": 0.60}


# ═══════════════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE LOADER
# ═══════════════════════════════════════════════════════════════════════════════
_KB_CACHE: dict = {}

def _find_kb_path(filename: str) -> Optional[Path]:
    """Search for KB file in multiple locations relative to this script.

    Cheap explicit candidates are checked first.  The recursive glob is a
    last-resort fallback and is skipped entirely when a candidate matches.
    """
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "knowledge_bases" / filename,
        script_dir / filename,
        script_dir / "guides" / filename,
        Path("knowledge_bases") / filename,
        Path(filename),
    ]
    # Fast path — check explicit locations before any filesystem scan.
    for c in candidates:
        if c.exists():
            return c

    # Slow fallback: partial stem match anywhere under the script directory.
    stem = Path(filename).stem
    try:
        for p in script_dir.rglob("*.json"):
            if stem in p.stem:
                return p
    except PermissionError:
        pass

    return None


def _fix_json(text: str, filename: str) -> str:
    """Fix known JSON issues in specific KB files."""
    if "proofpoint" in filename.lower():
        # Fix embedded double-quotes: {"field": ""dmarc.domain"  -> {"field": "dmarc.domain"
        text = re.sub(r'"field":\s*""([\w.]+)"', r'"field": "\1"', text)
    return text


@st.cache_data(show_spinner=False)
def load_kb(platform_name: str) -> dict:
    """Load and cache a knowledge base JSON file for the given platform."""
    meta = PLATFORM_META.get(platform_name, {})
    filename = meta.get("kb_file", "")
    if not filename:
        return {}
    path = _find_kb_path(filename)
    if path is None:
        return {}
    try:
        raw = path.read_bytes().decode("utf-8", errors="replace")
        raw = _fix_json(raw, filename)
        return json.loads(raw)
    except Exception as e:
        st.warning(f"⚠ Could not load KB for {platform_name}: {e}")
        return {}


def get_kb_field_schema(kb: dict, platform: str) -> dict:
    """Extract field schema dict from KB for use in telemetry generation."""
    fields = {}

    if "SentinelOne" in platform:
        ns = kb.get("data_model", {}).get("namespaces", {})
        for ns_name, ns_data in ns.items():
            for field_name, field_desc in ns_data.get("fields", {}).items():
                fields[field_name] = field_desc

    elif "Armis" in platform:
        dm = kb.get("data_models", {})
        for entity, edata in dm.items():
            for group in edata.get("fields", {}).values() if isinstance(edata.get("fields"), dict) else []:
                for f in (group if isinstance(group, list) else []):
                    if isinstance(f, dict):
                        fields[f.get("field", "")] = f.get("description", "")

    elif "Okta" in platform:
        sle = kb.get("data_models", {}).get("system_log_event", {})
        for section_data in sle.values():
            if isinstance(section_data, list):
                for f in section_data:
                    if isinstance(f, dict):
                        fields[f.get("field", "")] = f.get("description", "")
            elif isinstance(section_data, dict):
                for f in section_data.get("fields", []):
                    if isinstance(f, dict):
                        fields[f.get("field", "")] = f.get("description", "")

    elif "Obsidian" in platform:
        uae = kb.get("data_models", {}).get("unified_activity_event", {})
        for ns_data in uae.get("namespaces", {}).values():
            for f in ns_data.get("fields", []):
                if isinstance(f, dict):
                    fields[f.get("field", "")] = f.get("description", "")

    elif "Palo Alto" in platform:
        fbc = kb.get("field_reference", {}).get("fields_by_category", {})
        for cat_fields in fbc.values():
            for f in (cat_fields if isinstance(cat_fields, list) else []):
                if isinstance(f, dict):
                    fields[f.get("field", "")] = f.get("description", "")

    elif "ProofPoint" in platform:
        for model_data in kb.get("data_models", {}).values():
            for f in (model_data.get("fields", []) if isinstance(model_data, dict) else []):
                if isinstance(f, dict):
                    fields[f.get("field", "")] = f.get("description", "")

    elif "Cribl" in platform:
        for schema_data in kb.get("data_models", {}).values():
            for f in (schema_data.get("fields", []) if isinstance(schema_data, dict) else []):
                if isinstance(f, dict):
                    fields[f.get("field", "")] = f.get("description", "")

    return {k: v for k, v in fields.items() if k}


def get_kb_tuning_guidelines(kb: dict) -> dict:
    """Extract tuning guidelines (FPR / FNR) from KB."""
    de = kb.get("detection_engineering", {})
    tg = de.get("tuning_guidelines", {})
    return {
        "fpr": tg.get("false_positive_reduction", []),
        "fnr": tg.get("false_negative_reduction", []),
        "perf": tg.get("performance_optimization", tg.get("kql_performance_optimization", [])),
    }


def get_kb_detection_patterns(kb: dict) -> dict:
    """Extract detection pattern examples from KB."""
    de = kb.get("detection_engineering", {})
    return de.get("detection_patterns", {})


def get_kb_evasion_guidance(kb: dict) -> list:
    """Extract evasion/bypass guidance from KB."""
    de = kb.get("detection_engineering", {})
    tg = de.get("tuning_guidelines", {})
    fnr = tg.get("false_negative_reduction", [])
    # Also check testing_and_validation
    tv = de.get("testing_and_validation", {})
    evasion_tips = tv.get("evasion_testing", tv.get("bypass_scenarios", []))
    if isinstance(evasion_tips, dict):
        evasion_tips = list(evasion_tips.values())
    combined = []
    for item in (fnr + (evasion_tips if isinstance(evasion_tips, list) else [])):
        if isinstance(item, str) and len(item) > 10:
            combined.append(item)
    return combined[:10]


# ═══════════════════════════════════════════════════════════════════════════════
# LOAD DETECTION VALIDATOR FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════════
@st.cache_resource
def load_framework():
    """
    Dynamically load detection_validator.py from multiple candidate locations.

    Raises FileNotFoundError if the module cannot be found, or ImportError if
    the file exists but cannot be loaded (empty, syntax error, missing loader).
    """
    # Candidate locations in priority order: script-relative first,
    # then CWD (Streamlit Cloud default), then one level up.
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "detection_validator.py",
        Path("detection_validator.py").resolve(),
        script_dir.parent / "detection_validator.py",
    ]

    spec = None
    resolved_path: Optional[Path] = None
    for candidate in candidates:
        if candidate.exists():
            _spec = importlib.util.spec_from_file_location(
                "detection_validator", str(candidate)
            )
            if _spec is not None:
                spec = _spec
                resolved_path = candidate
                break

    if spec is None:
        searched = "\n".join(f"  • {p}" for p in candidates)
        raise FileNotFoundError(
            f"detection_validator.py not found. Searched:\n{searched}\n\n"
            "Ensure detection_validator.py is committed to the same directory "
            "as app.py in your GitHub repository."
        )

    if spec.loader is None:
        raise ImportError(
            f"Found detection_validator.py at {resolved_path} but its loader "
            "is None — the file may be empty or have a syntax error."
        )

    mod = importlib.util.module_from_spec(spec)

    # ── CRITICAL FIX ────────────────────────────────────────────────────────
    # Register the module in sys.modules BEFORE calling exec_module().
    #
    # Python's @dataclass decorator resolves type-hint strings by calling
    #   sys.modules[cls.__module__].__dict__
    # during class body execution.  If the module isn't registered yet,
    # sys.modules[cls.__module__] returns None, and .__dict__ raises:
    #   AttributeError: 'NoneType' object has no attribute 'dict'
    # This is the exact error that was surfacing on Streamlit Cloud.
    #
    # The standard importlib idiom is to register first, then execute,
    # and roll back on failure to keep sys.modules clean.
    sys.modules["detection_validator"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        # Clean up the partial module registration so a retry works cleanly.
        sys.modules.pop("detection_validator", None)
        import traceback
        tb = traceback.format_exc()
        raise ImportError(
            f"Failed to execute detection_validator.py ({resolved_path}).\n\n"
            f"Root cause: {exc}\n\n"
            f"Full traceback:\n{tb}"
        ) from exc

    logger.info("Loaded detection_validator v%s from %s",
                getattr(mod, "__version__", "?"), resolved_path)
    return mod


try:
    dv = load_framework()
except (FileNotFoundError, ImportError) as e:
    st.error(f"❌ Cannot load detection_validator.py")
    st.code(str(e), language="text")
    st.info(
        "**Quick fix:** Ensure `detection_validator.py` is in the same directory "
        "as `app.py` and is committed to your GitHub repository. "
        "Also confirm your `runtime.txt` specifies `python-3.11`.",
        icon="💡",
    )
    st.stop()
except Exception as e:
    st.error(f"❌ Unexpected error loading detection_validator.py — {type(e).__name__}")
    st.code(str(e), language="text")
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-PLATFORM RULE PARSER
# ═══════════════════════════════════════════════════════════════════════════════
class RuleParser:
    """Parses detection rules from any supported format into a normalised dict."""

    SIGMA_OP_MAP = {
        "contains": "contains", "contains|all": "contains_all",
        "startswith": "startswith", "endswith": "endswith",
        "equals": "equals", "re": "regex",
        "cidr": "contains", "gt": "gt", "gte": "gte",
        "lt": "lt", "lte": "lte",
        "base64offset|contains": "contains",
        "windash": "contains", "wide": "contains",
    }

    @classmethod
    def parse(cls, text: str, platform: str) -> dict:
        pl = platform.lower()
        if "sigma" in pl or cls._looks_like_sigma(text):
            return cls._sigma(text)
        elif "sentinel" in pl and "sentinelone" not in pl:
            return cls._kql(text, "Cribl KQL" if "cribl" in pl else "Microsoft Sentinel KQL")
        elif "cribl" in pl:
            return cls._kql(text, "Cribl KQL")
        elif "sentinelone" in pl or cls._looks_like_s1ql(text):
            return cls._s1ql(text)
        elif "proofpoint" in pl:
            return cls._proofpoint(text)
        elif "palo alto" in pl or "pan" in pl:
            return cls._panfw(text)
        elif "okta" in pl:
            return cls._okta(text)
        elif "armis" in pl:
            return cls._armis(text)
        elif "obsidian" in pl:
            return cls._obsidian(text)
        else:
            # Auto-detect fallback
            if cls._looks_like_sigma(text):
                return cls._sigma(text)
            if cls._looks_like_s1ql(text):
                return cls._s1ql(text)
            if cls._looks_like_kql(text):
                return cls._kql(text, "KQL")
            return cls._generic(text)

    @staticmethod
    def _looks_like_sigma(text: str) -> bool:
        return bool(re.search(r"^\s*(?:title|detection|logsource)\s*:", text, re.M))

    @staticmethod
    def _looks_like_s1ql(text: str) -> bool:
        return bool(re.search(r"\b(?:ContainsCIS|TgtProc|SrcProc|src\.process|tgt\.process)\b", text, re.I))

    @staticmethod
    def _looks_like_kql(text: str) -> bool:
        return bool(re.search(r"\|\s*where\b", text, re.I))

    @classmethod
    def _sigma(cls, text: str) -> dict:
        try:
            import yaml as _y
            doc = _y.safe_load(text)
            if not isinstance(doc, dict):
                raise ValueError("Not a YAML dict")
        except Exception:
            return cls._generic(text)

        title = doc.get("title", "Sigma Rule")
        det = doc.get("detection", {})
        cond_str = str(det.get("condition", "selection"))
        ls = doc.get("logsource", {})
        log_src = f"{ls.get('category', '')} {ls.get('product', '')}".strip()
        mitre = []
        for tag in doc.get("tags", []):
            if tag.lower().startswith("attack.t"):
                mitre.append(tag.split(".")[-1].upper())

        conditions, filters = [], []
        for key, body in det.items():
            if key == "condition":
                continue
            is_filter = key.startswith("filter")
            if isinstance(body, dict):
                for fop, value in body.items():
                    parts = fop.split("|")
                    field = parts[0]
                    op_raw = "|".join(parts[1:]) if len(parts) > 1 else ""
                    op = cls.SIGMA_OP_MAP.get(op_raw, "equals" if not op_raw else "contains")
                    vals = value if isinstance(value, list) else [value]
                    for v in vals:
                        entry = {"field": field, "op": op, "value": str(v) if v is not None else ""}
                        (filters if is_filter else conditions).append(entry)
            elif isinstance(body, list):
                for v in body:
                    entry = {"field": "_raw", "op": "contains", "value": str(v)}
                    (filters if is_filter else conditions).append(entry)

        logic = "AND_NOT_FILTER" if re.search(r'\bnot\b', cond_str, re.I) and filters else \
                ("OR" if re.search(r'\bor\b', cond_str, re.I) else "AND")

        return {
            "rule_name": title, "format": "Sigma",
            "conditions": conditions, "filters": filters,
            "logic": logic, "log_source": log_src,
            "raw_condition": cond_str, "mitre": mitre,
        }

    @classmethod
    def _kql(cls, text: str, label: str = "KQL") -> dict:
        conditions, filters = [], []
        m0 = re.match(r'^\s*(\w+)', text)
        rule_name = f"KQL — {m0.group(1)}" if m0 else f"{label} Rule"

        for block in re.findall(r'\|\s*where\s+(.+?)(?=\n\s*\||\Z)', text, re.DOTALL | re.I):
            for m in re.finditer(r'(\w[\w.]*)\s*=~\s*["\'](([^"\']+))["\']', block):
                conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
            for m in re.finditer(r'(\w[\w.]*)\s+has_any\s*\(([^)]+)\)', block, re.I):
                for v in re.findall(r'["\'](([^"\']+))["\']', m.group(2)):
                    conditions.append({"field": m.group(1), "op": "contains", "value": v[0]})
            for m in re.finditer(r'(\w[\w.]*)\s+has_all\s*\(([^)]+)\)', block, re.I):
                for v in re.findall(r'["\'](([^"\']+))["\']', m.group(2)):
                    conditions.append({"field": m.group(1), "op": "contains", "value": v[0]})
            for m in re.finditer(r'(\w[\w.]*)\s+has\s+["\'](([^"\']+))["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
            for m in re.finditer(r'(\w[\w.]*)\s+startswith\s+["\'](([^"\']+))["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "startswith", "value": m.group(2)})
            for m in re.finditer(r'(\w[\w.]*)\s+endswith\s+["\'](([^"\']+))["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "endswith", "value": m.group(2)})
            for m in re.finditer(r'(\w[\w.]*)\s+matches\s+regex\s+["\'](([^"\']+))["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "regex", "value": m.group(2)})
            for m in re.finditer(r'(\w[\w.]*)\s+contains\s+["\'](([^"\']+))["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
            for m in re.finditer(r'(\w[\w.]*)\s*==\s*["\'](([^"\']+))["\']', block):
                conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})

        for m in re.finditer(r'(\w[\w.]*)\s+!in~?\s*\(([^)]+)\)', text, re.I):
            for v in re.findall(r'["\'](([^"\']+))["\']', m.group(2)):
                filters.append({"field": m.group(1), "op": "equals", "value": v[0]})

        return {"rule_name": rule_name, "format": label, "conditions": conditions,
                "filters": filters, "logic": "AND", "log_source": "windows", "mitre": []}

    @classmethod
    def _s1ql(cls, text: str) -> dict:
        conditions, filters = [], []
        # S1QL v1 syntax
        for m in re.finditer(r'(\w[\w.]*)\s+ContainsCIS\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
        # S1QL v2 dot-notation
        for m in re.finditer(r'([\w.]+)\s+contains\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s+matches\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "regex", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s+RegExp\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "regex", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s+StartsWith\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "startswith", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s+EndsWith\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "endswith", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s*=\s*["\'](([^"\']+))["\']', text):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'NOT\s+([\w.]+)\s+In\s+Contains\s*\(([^)]+)\)', text, re.I):
            for v in re.findall(r'["\'](([^"\']+))["\']', m.group(2)):
                filters.append({"field": m.group(1), "op": "equals", "value": v[0]})
        mn = re.search(r'event\.type\s*=\s*["\']([^"\']+)["\']', text, re.I)
        return {
            "rule_name": f"S1 — {mn.group(1)}" if mn else "S1QL Rule",
            "format": "S1QL", "conditions": conditions, "filters": filters,
            "logic": "AND", "log_source": "sentinelone", "mitre": [],
        }

    @classmethod
    def _proofpoint(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'([\w.]+)\s+eq\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s+contains\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s+geq\s+(\S+)', text, re.I):
            conditions.append({"field": m.group(1), "op": "gte", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s+leq\s+(\S+)', text, re.I):
            conditions.append({"field": m.group(1), "op": "lte", "value": m.group(2)})
        for m in re.finditer(r'([\w.]+)\s*=\s*["\'](([^"\']+))["\']', text):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        return {"rule_name": "ProofPoint Rule", "format": "Smart Search",
                "conditions": conditions, "filters": [], "logic": "AND",
                "log_source": "email", "mitre": []}

    @classmethod
    def _panfw(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'(\w[\w\-]*)\s+eq\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'(\w[\w\-]*)\s+contains\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
        for m in re.finditer(r'(\w[\w\-]*)\s+geq\s+(\S+)', text, re.I):
            conditions.append({"field": m.group(1), "op": "gte", "value": m.group(2)})
        for m in re.finditer(r'addr\.(src|dst)\s+in\s+([\d./]+)', text, re.I):
            conditions.append({"field": f"addr.{m.group(1)}", "op": "contains", "value": m.group(2)})
        return {"rule_name": "PAN-OS Rule", "format": "PAN-OS Filter",
                "conditions": conditions, "filters": [], "logic": "AND",
                "log_source": "firewall", "mitre": []}

    @classmethod
    def _okta(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'([\w.\[\]]+)\s+eq\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'([\w.\[\]]+)\s+co\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
        for m in re.finditer(r'([\w.\[\]]+)\s+sw\s+["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "startswith", "value": m.group(2)})
        return {"rule_name": "Okta Rule", "format": "EventHook",
                "conditions": conditions, "filters": [], "logic": "AND",
                "log_source": "okta", "mitre": []}

    @classmethod
    def _armis(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'(\w[\w.]*)\s*:\s*["\'](([^"\']+))["\']', text):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'(\w[\w.]*)\s*<\s*(\d+)', text):
            conditions.append({"field": m.group(1), "op": "lt", "value": m.group(2)})
        for m in re.finditer(r'(\w[\w.]*)\s*>\s*(\d+)', text):
            conditions.append({"field": m.group(1), "op": "gt", "value": m.group(2)})
        return {"rule_name": "Armis ASQ Rule", "format": "ASQ",
                "conditions": conditions, "filters": [], "logic": "AND",
                "log_source": "iot", "mitre": []}

    @classmethod
    def _obsidian(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'([\w.]+)\s*:\s*(true|false)', text, re.I):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'event_type\s*:\s*["\'](([^"\']+))["\']', text, re.I):
            conditions.append({"field": "event.type", "op": "equals", "value": m.group(1)})
        for m in re.finditer(r'([\w.]+)\s*=\s*["\'](([^"\']+))["\']', text):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        return {"rule_name": "Obsidian Rule", "format": "OQL",
                "conditions": conditions, "filters": [], "logic": "AND",
                "log_source": "saas", "mitre": []}

    @classmethod
    def _generic(cls, text: str) -> dict:
        skip = {"and", "or", "not", "where", "from", "select", "true", "false",
                "null", "by", "on", "in", "as", "if", "then", "when", "case"}
        conditions = []
        for m in re.finditer(
            r'(\b[A-Za-z_]\w*\b)\s*[=:]\s*["\']?([^\s"\'|&,\)\n]{2,60})["\']?', text
        ):
            f, v = m.group(1), m.group(2)
            if f.lower() not in skip and not f.isdigit():
                conditions.append({"field": f, "op": "contains", "value": v})
        return {"rule_name": "Custom Rule", "format": "Generic",
                "conditions": conditions[:12], "filters": [],
                "logic": "OR", "log_source": "", "mitre": []}


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class DynamicEngine(dv.DetectionEngine):
    """Evaluates any parsed rule against log events at runtime."""

    def __init__(self, parsed: dict):
        super().__init__(rule_name=parsed.get("rule_name", "Custom Rule"))
        self.conditions = parsed.get("conditions", [])
        self.filters    = parsed.get("filters", [])
        self.logic      = parsed.get("logic", "AND")

    def _eval(self, event: dict, cond: dict) -> bool:
        f, op, v = cond["field"], cond["op"], cond["value"]
        try:
            match op:
                case "equals":       return self.field_equals(event, f, v)
                case "contains":     return self.field_contains(event, f, v)
                case "startswith":   return self.field_startswith(event, f, v)
                case "endswith":     return self.field_endswith(event, f, v)
                case "regex":        return self.field_regex(event, f, v)
                case "contains_all": return self.field_all_of(event, f, v.split("|"))
                case "gt":           return self.field_gt(event, f, float(v))
                case "lt":           return self.field_lt(event, f, float(v))
                case "gte":
                    try:
                        return float(self.nested_get(event, f) or 0) >= float(v)
                    except (TypeError, ValueError):
                        return False
                case "lte":
                    try:
                        return float(self.nested_get(event, f) or 0) <= float(v)
                    except (TypeError, ValueError):
                        return False
                case _:              return self.field_contains(event, f, v)
        except Exception:  # noqa: BLE001 — engine must never crash on bad events
            return False

    def evaluate(self, event: dict) -> dv.DetectionResult:
        if not self.conditions:
            return dv.DetectionResult(event_id="", matched=False,
                                       matched_conditions=[], confidence_score=0.0)
        hits, matched = [], []
        for c in self.conditions:
            h = self._eval(event, c)
            hits.append(h)
            if h:
                matched.append(f"{c['field']}:{c['op']}:{str(c['value'])[:30]}")

        filter_hit = any(self._eval(event, f) for f in self.filters)
        result = (all(hits) if self.logic in ("AND", "AND_NOT_FILTER") else any(hits))
        result = result and not filter_hit

        return dv.DetectionResult(
            event_id="",
            matched=result,
            matched_conditions=matched,
            confidence_score=round(sum(hits) / len(hits) if hits else 0, 2),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# PLATFORM-AWARE TELEMETRY GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════
class PlatformGenerator(dv.TelemetryGenerator):
    """
    Generates synthetic events using:
      - Parsed rule conditions to construct true-positive field values
      - KB field schemas for realistic log structure
      - KB evasion guidance for bypass variants
      - Platform-specific base templates
    """

    _EVASION_TRANSFORMS = [
        ("case_manipulation",    lambda v: v.upper() if isinstance(v, str) else v),
        ("env_variable_sub",     lambda v: v.replace(r"C:\Windows", "%SystemRoot%") if isinstance(v, str) else v),
        ("path_traversal",       lambda v: v.replace(r"\System32\\", r"\System32\..\System32\\") if isinstance(v, str) else v),
        ("double_extension",     lambda v: v + ".bak" if isinstance(v, str) and ".exe" in v else v),
        ("syswow64_redirect",    lambda v: v.replace("System32", "SysWow64") if isinstance(v, str) else v),
        ("space_insertion",      lambda v: v.replace(".exe", " .exe") if isinstance(v, str) else v),
        ("b64_encoding",         lambda v: (
            "powershell.exe -enc " +
            base64.b64encode((v + " ").encode("utf-16-le")).decode()
        ) if isinstance(v, str) and len(v) < 80 else v),
        ("unicode_substitution", lambda v: v.replace("a", "\u0061").replace("e", "\u0065")
                                  if isinstance(v, str) and len(v) < 50 else v),
    ]

    def __init__(self, parsed: dict, platform: str, kb: dict):
        super().__init__()
        self.conditions = parsed.get("conditions", [])
        self.platform   = platform.lower()
        self.kb         = kb
        self.kb_fields  = get_kb_field_schema(kb, platform)
        self.evasion_tips = get_kb_evasion_guidance(kb)
        self._pos       = self._build_positive_values()

    def _build_positive_values(self) -> dict:
        """Build a dict of field → trigger-value from parsed conditions."""
        pos = {}
        for c in self.conditions:
            f, op, v = c["field"], c["op"], c["value"]
            match op:
                case "equals":     pos[f] = v
                case "contains":   pos[f] = f"prefix_{v}_suffix"
                case "startswith": pos[f] = f"{v}_continuation"
                case "endswith":   pos[f] = f"C:\\Windows\\System32\\{v}"
                case "regex":
                    lit = re.sub(r'[\\()?+*\[\]^$|{}]', '', v)[:40]
                    pos[f] = lit or v[:20]
                case _:            pos[f] = v
        return pos

    # ── Platform base templates ──────────────────────────────────────────────

    def _base_event(self) -> dict:
        pl = self.platform
        if "sentinelone" in pl:
            return {
                "event.type": "Process Creation",
                "src.process.name": "cmd.exe",
                "src.process.image.path": r"C:\Windows\System32\cmd.exe",
                "src.process.cmdline": "cmd.exe /c normal",
                "src.process.pid": self._random_pid(),
                "src.process.user": f"CORP\\{self._random_username()}",
                "src.process.parent.name": "explorer.exe",
                "tgt.process.name": "benign.exe",
                "tgt.process.cmdline": "benign.exe --help",
                "endpoint.name": self._random_hostname(),
                "endpoint.os": "windows",
                "agent.version": "23.4.1",
                "site.name": "Default",
            }
        elif "proofpoint" in pl:
            return {
                "msg.sender": f"user@{self._random_fqdn()}",
                "msg.sender.domain": self._random_fqdn(),
                "msg.sender.ip": self._random_ip(internal=False),
                "msg.rcpt": f"{self._random_username()}@company.com",
                "msg.subject": "Normal Business Update",
                "msg.parts.filename": "document.pdf",
                "msg.parts.content_type": "application/pdf",
                "msg.urls.domain": "office.com",
                "msg.threat.score": 5,
                "msg.threat.verdict": "CLEAN",
                "msg.dkim": "pass", "msg.spf": "pass", "msg.dmarc": "pass",
                "msg.senderReputation": "known",
                "msg.completelyRewritten": "true",
            }
        elif "armis" in pl:
            return {
                "name": self._random_hostname(),
                "ipAddress": self._random_ip(),
                "macAddress": self._random_mac(),
                "type": "Workstation",
                "manufacturer": "Dell",
                "operatingSystem": "Windows 11",
                "category": "IT",
                "riskLevel": "Low",
                "networkSegment": "Corporate",
                "isManaged": "true",
                "vulnerability.severity": "Low",
                "vulnerability.cvssScore": 2.1,
                "lastSeen": "0days",
                "connectionCount": 12,
            }
        elif "okta" in pl:
            return {
                "eventType": "user.authentication.sso",
                "published": self._random_timestamp(),
                "severity": "INFO",
                "actor.alternateId": f"{self._random_username()}@company.com",
                "actor.type": "User",
                "actor.displayName": self._random_username().replace(".", " ").title(),
                "client.ipAddress": self._random_ip(internal=True),
                "client.geographicalContext.country": "US",
                "client.geographicalContext.city": "New York",
                "client.device": "Computer",
                "client.userAgent.rawUserAgent": self._random_user_agent(),
                "securityContext.isProxy": "false",
                "securityContext.isTor": "false",
                "outcome.result": "SUCCESS",
                "authenticationContext.credentialType": "PASSWORD",
                "debugContext.debugData.threatSuspected": "false",
                "target[0].alternateId": f"{self._random_username()}@company.com",
            }
        elif "palo alto" in pl:
            return {
                "type": "TRAFFIC", "subtype": "end",
                "src": self._random_ip(internal=True),
                "dst": self._random_ip(internal=False),
                "dport": 443, "proto": "tcp", "application": "ssl",
                "from": "trust", "to": "untrust", "action": "allow",
                "bytes": self.rng.randint(1000, 50000),
                "bytes_sent": self.rng.randint(200, 5000),
                "rule": "Default-Allow-Web",
                "srcloc": "US", "dstloc": "US",
                "srcuser": self._random_username(),
                "severity": "low",
            }
        elif "obsidian" in pl:
            return {
                "event.type": "user.login", "event.app": "Salesforce",
                "event.timestamp": self._random_timestamp(),
                "event.outcome": "success",
                "event.location.country": "US",
                "event.location.is_vpn": "false",
                "event.location.is_tor": "false",
                "event.device.is_managed": "true",
                "user.mfa_enabled": "true",
                "user.is_external": "false",
                "user.risk_score": 8,
                "user.email": f"{self._random_username()}@company.com",
                "resource.sensitivity": "Internal",
            }
        elif "cribl" in pl:
            b = self._base_sysmon_event(1)
            b.update({
                "_time": self._random_timestamp(), "index": "endpoint",
                "sourcetype": "windows:sysmon",
                "Image": r"C:\Windows\System32\benign.exe",
                "CommandLine": "benign.exe", "EventID": 1,
                "ParentImage": r"C:\Windows\explorer.exe",
                "User": f"CORP\\{self._random_username()}",
                "Hashes": f"SHA256={self._random_hash()}",
            })
            return b
        else:  # Sigma / generic Windows
            b = self._base_sysmon_event(1)
            b.update({
                "Image": r"C:\Windows\System32\benign.exe",
                "CommandLine": "benign.exe", "OriginalFileName": "benign.EXE",
                "ParentImage": r"C:\Windows\explorer.exe",
                "ParentCommandLine": "explorer.exe",
                "CurrentDirectory": r"C:\Users\user\\",
                "IntegrityLevel": "Medium",
                "Hashes": f"SHA256={self._random_hash()}",
                "User": f"CORP\\{self._random_username()}",
            })
            return b

    def _benign_overrides(self) -> dict:
        pl = self.platform
        if "sentinelone" in pl:
            return {"tgt.process.name": "notepad.exe",
                    "tgt.process.cmdline": "notepad.exe readme.txt",
                    "event.type": "Process Creation"}
        elif "proofpoint" in pl:
            return {"msg.sender.domain": "microsoft.com",
                    "msg.subject": "Monthly Newsletter",
                    "msg.threat.verdict": "CLEAN", "msg.threat.score": 1}
        elif "armis" in pl:
            return {"type": "Workstation", "riskLevel": "Low",
                    "isManaged": "true", "networkSegment": "Corporate"}
        elif "okta" in pl:
            return {"outcome.result": "SUCCESS", "securityContext.isProxy": "false",
                    "client.geographicalContext.country": "US"}
        elif "palo alto" in pl:
            return {"application": "ssl", "dport": 443, "action": "allow", "dstloc": "US"}
        elif "obsidian" in pl:
            return {"event.outcome": "success", "user.mfa_enabled": "true",
                    "event.location.is_vpn": "false"}
        elif "cribl" in pl:
            return {"Image": r"C:\Windows\System32\notepad.exe",
                    "CommandLine": "notepad.exe readme.txt"}
        else:
            return {"Image": r"C:\Windows\System32\notepad.exe",
                    "CommandLine": "notepad.exe readme.txt",
                    "OriginalFileName": "notepad.EXE",
                    "ParentImage": r"C:\Windows\explorer.exe"}

    def generate_true_positives(self, count: int = 10) -> list:
        variations = [
            ("standard",     lambda d: d),
            ("uppercase",    lambda d: {k: v.upper()   if isinstance(v, str) else v for k, v in d.items()}),
            ("lowercase",    lambda d: {k: v.lower()   if isinstance(v, str) else v for k, v in d.items()}),
            ("extra_args",   lambda d: {k: (v + " --extra-flag") if k in
                                ("CommandLine", "tgt.process.cmdline", "msg.subject",
                                 "src.process.cmdline") and isinstance(v, str) else v
                                for k, v in d.items()}),
            ("path_variant", lambda d: {k: v.replace("System32", "SysWOW64") if isinstance(v, str) else v
                                for k, v in d.items()}),
        ]
        events = []
        for i in range(count):
            base = self._base_event()
            base.update(self._pos)
            label, xform = variations[i % len(variations)]
            if i > 0:
                base = xform(base)
            trigger_desc = list(self._pos.values())[0][:50] if self._pos else "trigger condition"
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(),
                category=dv.EventCategory.TRUE_POSITIVE,
                description=f"TP [{label}]: {trigger_desc}",
                log_data=base,
                expected_detection=True,
                tags=["true_positive", label],
                attack_technique="T1059",
            ))
        return events

    def generate_true_negatives(self, count: int = 15) -> list:
        benign_procs = [
            ("notepad.exe",   r"C:\Windows\System32\notepad.exe",   "notepad.exe readme.txt"),
            ("mspaint.exe",   r"C:\Windows\System32\mspaint.exe",   "mspaint.exe"),
            ("calc.exe",      r"C:\Windows\System32\calc.exe",      "calc.exe"),
            ("svchost.exe",   r"C:\Windows\System32\svchost.exe",   "svchost.exe -k netsvcs"),
            ("explorer.exe",  r"C:\Windows\explorer.exe",           "explorer.exe"),
            ("chrome.exe",    r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer"),
            ("Teams.exe",     r"C:\Users\user\AppData\Local\Microsoft\Teams\Teams.exe", "Teams.exe"),
            ("python.exe",    r"C:\Python311\python.exe",            "python.exe -c print('hello')"),
            ("git.exe",       r"C:\Program Files\Git\cmd\git.exe",   "git.exe status"),
            ("code.exe",      r"C:\Program Files\Microsoft VS Code\Code.exe", "code.exe ."),
            ("7zFM.exe",      r"C:\Program Files\7-Zip\7zFM.exe",   "7zFM.exe"),
            ("msiexec.exe",   r"C:\Windows\System32\msiexec.exe",   "msiexec /i setup.msi /quiet"),
        ]
        events = []
        for i in range(count):
            base = self._base_event()
            base.update(self._benign_overrides())
            if "sigma" in self.platform or "cribl" in self.platform or len(self.platform) < 3:
                name, path, cmd = benign_procs[i % len(benign_procs)]
                base["Image"] = path
                base["CommandLine"] = cmd
                base["OriginalFileName"] = name.upper()
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(),
                category=dv.EventCategory.TRUE_NEGATIVE,
                description=f"TN — benign #{i + 1}: normal activity",
                log_data=base,
                expected_detection=False,
                tags=["true_negative", "benign"],
            ))
        return events

    def generate_fp_candidates(self, count: int = 5) -> list:
        events = []
        for i in range(count):
            base = self._base_event()
            base.update(self._benign_overrides())
            partial = dict(list(self._pos.items())[:max(1, len(self._pos) // 2)])
            base.update(partial)
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(),
                category=dv.EventCategory.FALSE_POSITIVE_CANDIDATE,
                description=f"FP candidate #{i + 1}: partial match — legit activity",
                log_data=base,
                expected_detection=False,
                tags=["fp_candidate", "stress_test"],
                notes="Satisfies some but not all conditions. Verifying no false positive.",
            ))
        return events

    def generate_evasion_samples(self, count: int = 5) -> list:
        events = []
        for idx, (name, xform) in enumerate(self._EVASION_TRANSFORMS[:count]):
            base = self._base_event()
            base.update({k: xform(v) for k, v in self._pos.items()})
            note = (self.evasion_tips[idx] if idx < len(self.evasion_tips)
                    else f"Evasion technique: {name.replace('_', ' ')}")
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(),
                category=dv.EventCategory.EVASION,
                description=f"Evasion — {name.replace('_', ' ')}",
                log_data=base,
                expected_detection=True,
                tags=["evasion", name],
                attack_technique="T1036",
                notes=note,
            ))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# LOG IMPORTER  (real log ingestion)
# ═══════════════════════════════════════════════════════════════════════════════
class LogImporter:
    CATEGORY_MAP = {
        "True Positive (attack)":       (dv.EventCategory.TRUE_POSITIVE,            True),
        "True Negative (benign)":       (dv.EventCategory.TRUE_NEGATIVE,            False),
        "FP Candidate (tricky benign)": (dv.EventCategory.FALSE_POSITIVE_CANDIDATE, False),
        "Evasion Variant":              (dv.EventCategory.EVASION,                  True),
    }
    _DESC_CANDIDATES = (
        "CommandLine", "tgt.process.cmdline", "src.process.cmdline",
        "msg.subject", "eventType", "event.type", "description", "name",
    )

    @classmethod
    def parse(cls, raw: bytes, filename: str, label: str, desc_field: str = "") -> tuple:
        ext = Path(filename).suffix.lower()
        warnings = []
        try:
            if ext in (".jsonl", ".ndjson"):
                rows = []
                for i, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        warnings.append(f"Line {i}: skipped — invalid JSON")
            elif ext == ".csv":
                reader = csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace")))
                rows = [dict(r) for r in reader]
            else:
                data = json.loads(raw.decode("utf-8", errors="replace"))
                rows = data if isinstance(data, list) else [data]
        except Exception as e:
            return [], [f"Parse error: {e}"]

        if not rows:
            return [], ["File parsed but contained no rows."]

        is_native = (
            label == "auto" and len(rows) >= 1
            and all("category" in r and "log_data" in r for r in rows[:3])
        )

        events = []
        for i, row in enumerate(rows):
            eid = f"IMP-{i + 1:04d}"
            if is_native:
                try:
                    ev = dv.SyntheticEvent.from_dict({**row, "event_id": eid})
                    events.append(ev)
                    continue
                except Exception as e:
                    warnings.append(f"Row {i + 1}: native parse failed ({e})")

            if label == "auto":
                cr = str(row.get("category", row.get("label", row.get("type", "")))).lower()
                if any(k in cr for k in ("tp", "true_pos", "malicious", "attack")):
                    cat, exp = dv.EventCategory.TRUE_POSITIVE, True
                elif any(k in cr for k in ("evasion", "bypass")):
                    cat, exp = dv.EventCategory.EVASION, True
                elif any(k in cr for k in ("fp", "false_pos", "candidate")):
                    cat, exp = dv.EventCategory.FALSE_POSITIVE_CANDIDATE, False
                else:
                    cat, exp = dv.EventCategory.TRUE_NEGATIVE, False
            else:
                cat, exp = cls.CATEGORY_MAP.get(label, (dv.EventCategory.TRUE_NEGATIVE, False))

            if desc_field and desc_field in row:
                desc = str(row[desc_field])[:80]
            else:
                desc = f"[imported] event {i + 1}"
                for candidate in cls._DESC_CANDIDATES:
                    if candidate in row:
                        desc = f"[imported] {str(row[candidate])[:65]}"
                        break

            clean_row = {k: v for k, v in row.items() if k not in ("category", "label")}
            events.append(dv.SyntheticEvent(
                event_id=eid, category=cat, description=desc,
                log_data=clean_row, expected_detection=exp,
                tags=["imported", "real_log"],
                notes=f"Imported from {filename}",
            ))

        if len(events) > 300:
            warnings.append(
                f"Imported {len(events)} events but capped at 300. "
                "Use the JSON export for the full dataset."
            )
            events = events[:300]
        return events, warnings


# ═══════════════════════════════════════════════════════════════════════════════
# AI RULE GENERATION ENGINE — GitHub Copilot model registry
# ═══════════════════════════════════════════════════════════════════════════════

# Models available via GitHub Copilot (as of 2025)
AI_MODELS = {
    # ── OpenAI — Copilot default stack ──────────────────────────────────────
    "gpt-4o": {
        "label": "GPT-4o", "provider": "openai", "icon": "●",
        "chip_class": "chip-default", "default": True,
        "note": "Copilot default · fastest GPT-4 class · best balance of speed & quality",
    },
    "gpt-4": {
        "label": "GPT-4", "provider": "openai", "icon": "●",
        "chip_class": "chip-openai",
        "note": "OpenAI flagship · maximum reasoning depth for complex rules",
    },
    "o1": {
        "label": "o1", "provider": "openai", "icon": "●",
        "chip_class": "chip-openai",
        "note": "Extended thinking · best for multi-step detection logic",
    },
    "o3-mini": {
        "label": "o3-mini", "provider": "openai", "icon": "●",
        "chip_class": "chip-openai",
        "note": "Fast o3 variant · efficient reasoning for iterative tuning",
    },
    # ── Anthropic ────────────────────────────────────────────────────────────
    "claude-3-5-sonnet": {
        "label": "Claude 3.5 Sonnet", "provider": "anthropic", "icon": "◆",
        "chip_class": "chip-anthropic",
        "note": "Anthropic · structured YAML & code generation · excellent at rule rewrites",
    },
    # ── Google ───────────────────────────────────────────────────────────────
    "gemini-1-5-pro": {
        "label": "Gemini 1.5 Pro", "provider": "google", "icon": "◈",
        "chip_class": "chip-google",
        "note": "Google · long-context · strong multi-platform rule translation",
    },
    "gemini-2-0-flash": {
        "label": "Gemini 2.0 Flash", "provider": "google", "icon": "◈",
        "chip_class": "chip-google",
        "note": "Google · fastest model · ideal for rapid iteration",
    },
}
_DEFAULT_MODEL = "gpt-4o"


def _build_generation_prompt(
    original_rule: str,
    rec: dict,
    parsed_rule: dict,
    platform: str,
    metrics: dict,
) -> str:
    """Construct a rich, self-contained prompt for rule generation."""
    fmt    = parsed_rule.get("format", "Sigma")
    logic  = parsed_rule.get("logic", "AND")
    conds  = parsed_rule.get("conditions", [])
    filts  = parsed_rule.get("filters", [])
    mitre  = ", ".join(parsed_rule.get("mitre", [])) or "unknown"
    cm     = metrics.get("confusion_matrix", {})

    cond_block = "\n".join(
        f"  {i+1}. field={c['field']}  op={c['op']}  value={c['value']!r}"
        for i, c in enumerate(conds[:12])
    ) or "  (none parsed)"
    filt_block = "\n".join(
        f"  NOT  field={f['field']}  op={f['op']}  value={f['value']!r}"
        for f in filts[:6]
    ) or "  (none)"

    return f"""\
You are a senior detection engineer. Your task: generate an improved, \
production-ready detection rule that directly addresses the validation \
finding below.

════════════════════════════════════════
ORIGINAL RULE  ({fmt} · {platform})
════════════════════════════════════════
{original_rule.strip()}

════════════════════════════════════════
VALIDATION SUMMARY
════════════════════════════════════════
Overall grade      : {metrics.get('overall_grade','?')}
Recall             : {metrics.get('recall',0):.1%}
Precision          : {metrics.get('precision',0):.1%}
Evasion resistance : {metrics.get('evasion_resistance',0):.1%}
TP / FP / FN / TN  : {cm.get('TP',0)} / {cm.get('FP',0)} / {cm.get('FN',0)} / {cm.get('TN',0)}
Combinator logic   : {logic}
MITRE ATT&CK       : {mitre}

Parsed conditions:
{cond_block}

Exclusion filters:
{filt_block}

════════════════════════════════════════
FINDING TO ADDRESS  [{rec.get('priority','medium').upper()}]
════════════════════════════════════════
Title  : {rec.get('title','')}
Detail : {rec.get('body','')}
Fix    : {rec.get('fix','')}

════════════════════════════════════════
INSTRUCTIONS
════════════════════════════════════════
1. Output a complete, improved {fmt} rule for {platform}.
2. Directly fix the finding — do not just restate the original.
3. Add / improve exclusion filters to reduce false positives.
4. Broaden detection coverage (OR branches, OriginalFileName,
   encoded variants) if recall or evasion resistance < 80%.
5. Add inline comments on every changed section explaining WHY.
6. After the rule, append a "## Changes Made" section listing
   each modification and its rationale.

Output ONLY the improved rule (with comments) and the ## Changes Made \
section. No preamble.
"""


def _call_anthropic(prompt: str, api_key: str) -> str:
    """Direct Anthropic API call (no SDK required)."""
    import urllib.request, urllib.error
    body = json.dumps({
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=body,
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.loads(r.read())["content"][0]["text"]
    except Exception as exc:
        return f"⚠ API error: {exc}"


def render_model_chips(selected_key: str, widget_key: str) -> str:
    """Render model selector chips; returns chosen model key from session state."""
    # Persist selection across reruns
    ss_key = f"model_sel_{widget_key}"
    if ss_key not in st.session_state:
        st.session_state[ss_key] = selected_key

    provider_groups = [
        ("OpenAI — Copilot Default & Alternatives", ["gpt-4o","gpt-4","o1","o3-mini"]),
        ("Anthropic",                               ["claude-3-5-sonnet"]),
        ("Google",                                  ["gemini-1-5-pro","gemini-2-0-flash"]),
    ]

    for group_label, keys in provider_groups:
        chips_html = ""
        for k in keys:
            m          = AI_MODELS[k]
            is_default = m.get("default", False)
            is_active  = (st.session_state[ss_key] == k)
            extra      = " chip-default" if is_active else " " + m["chip_class"]
            badge      = ' <span style="font-size:9px;opacity:.65">DEFAULT</span>' if is_default else ""
            safe_note  = m["note"].replace('"', "&quot;")
            chips_html += (
                '<span class="model-chip' + extra + '" title="' + safe_note + '">'
                + m["icon"] + " " + m["label"] + badge + "</span>"
            )
        st.markdown(
            f'<div style="font-size:9px;font-weight:600;letter-spacing:.1em;'
            f'text-transform:uppercase;color:var(--text-3);margin:8px 0 4px">{group_label}</div>'
            f'<div class="model-chip-row">{chips_html}</div>',
            unsafe_allow_html=True,
        )

    # Actual selectbox (hidden label) that drives the state
    chosen = st.selectbox(
        "Model",
        list(AI_MODELS.keys()),
        index=list(AI_MODELS.keys()).index(st.session_state[ss_key]),
        format_func=lambda k: f"{AI_MODELS[k]['icon']} {AI_MODELS[k]['label']}",
        key=f"sb_{widget_key}",
        label_visibility="collapsed",
    )
    st.session_state[ss_key] = chosen
    return chosen


def render_rule_generator(
    rec: dict,
    parsed_rule: dict,
    rule_text: str,
    platform: str,
    metrics: dict,
    idx: int,
) -> None:
    """Render the AI rule-generation panel inside a recommendation expander."""
    widget_key = f"rg_{idx}_{abs(hash(rec['title'])) % 99999}"
    gen_key    = f"gen_{widget_key}"

    st.markdown(
        '<div style="height:1px;background:var(--border);margin:14px 0 16px"></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div style="font-size:10px;font-weight:600;letter-spacing:.1em;'
        'text-transform:uppercase;color:var(--text-3);margin-bottom:10px">'
        '⚡ Generate Improved Rule</div>',
        unsafe_allow_html=True,
    )

    chosen_model = render_model_chips(_DEFAULT_MODEL, widget_key)
    model_info   = AI_MODELS[chosen_model]
    prompt       = _build_generation_prompt(rule_text, rec, parsed_rule, platform, metrics)
    prompt_b64   = base64.b64encode(prompt.encode()).decode()

    col_gen, col_copy = st.columns([1, 1])
    with col_gen:
        if st.button(
            f"✨ Generate with {model_info['label']}",
            key=f"btn_{widget_key}",
            use_container_width=True,
        ):
            api_key = (
                st.session_state.get("anthropic_api_key", "")
                or getattr(getattr(st, "secrets", None), "get", lambda k, d: d)("ANTHROPIC_API_KEY", "")
            )
            if model_info["provider"] == "anthropic" and api_key:
                with st.spinner(f"Calling {model_info['label']}…"):
                    st.session_state[gen_key] = _call_anthropic(prompt, api_key)
            else:
                # Return a ready-to-paste Copilot prompt
                st.session_state[gen_key] = (
                    "# ─────────────────────────────────────────────────────\n"
                    "# Copy this entire block into GitHub Copilot Chat,\n"
                    "# VS Code AI panel, or any IDE with Copilot access,\n"
                    f"# then select '{model_info['label']}' in the model dropdown.\n"
                    "# ─────────────────────────────────────────────────────\n\n"
                    + prompt
                )

    with col_copy:
        components.html(
            f"""<button
              onclick="navigator.clipboard.writeText(atob('{prompt_b64}')).then(()=>{{
                this.textContent='✓ Copied!';
                this.style.borderColor='rgba(16,185,129,.5)';
                this.style.color='#34d399';
                setTimeout(()=>{{this.textContent='📋 Copy Prompt';
                  this.style.borderColor='rgba(255,255,255,.1)';
                  this.style.color='#8595ae'}},2000)
              }})"
              style="width:100%;height:42px;background:transparent;
                border:1px solid rgba(255,255,255,.1);border-radius:8px;
                color:#8595ae;font-size:12px;font-family:Inter,sans-serif;
                cursor:pointer;transition:all .18s"
              onmouseover="this.style.borderColor='rgba(14,165,233,.4)';this.style.color='#38bdf8'"
              onmouseout="this.style.borderColor='rgba(255,255,255,.1)';this.style.color='#8595ae'"
            >📋 Copy Prompt</button>""",
            height=50,
        )

    # Display generated output
    if gen_key in st.session_state and st.session_state[gen_key]:
        out   = st.session_state[gen_key]
        label = model_info["label"]
        icon  = model_info["icon"]
        fmt   = parsed_rule.get("format", "Sigma") if parsed_rule else "Sigma"
        lang  = "yaml" if fmt == "Sigma" else "sql"
        st.markdown(
            f'<div class="gen-rule-wrap">'
            f'<div class="gen-rule-header">'
            f'<span style="font-size:10px;font-weight:600;letter-spacing:.09em;'
            f'text-transform:uppercase;color:var(--accent)">'
            f'{icon} Improved Rule — {label}</span>'
            f'<span style="font-size:10px;color:var(--text-3)">{platform} · {fmt}</span>'
            f'</div></div>',
            unsafe_allow_html=True,
        )
        st.code(out, language=lang)


# ═══════════════════════════════════════════════════════════════════════════════
# RECOMMENDATIONS ENGINE  (KB-grounded)
# ═══════════════════════════════════════════════════════════════════════════════
def generate_recommendations(
    results: list,
    metrics: dict,
    parsed_rule: dict,
    platform: str,
    kb: dict,
) -> list:
    """
    Produce a ranked list of actionable recommendations by analysing:
      - Confusion matrix outcomes (FN / FP / evasion misses)
      - Parsed rule structure (conditions, filters, logic)
      - KB tuning guidelines (platform-specific FPR / FNR guidance)
      - Evasion bypass patterns from the KB
    """
    recs = []
    cm = metrics.get("confusion_matrix", {})
    fn_count = cm.get("FN", 0)
    fp_count = cm.get("FP", 0)
    evasion_missed = metrics.get("evasion_total", 0) - metrics.get("evasion_caught", 0)
    precision = metrics.get("precision", 1.0)
    recall    = metrics.get("recall", 1.0)
    evasion_r = metrics.get("evasion_resistance", 1.0)
    conditions = parsed_rule.get("conditions", [])
    filters    = parsed_rule.get("filters", [])
    logic      = parsed_rule.get("logic", "AND")
    fmt        = parsed_rule.get("format", "Generic")

    tg    = get_kb_tuning_guidelines(kb)
    fpr_g = tg.get("fpr", [])
    fnr_g = tg.get("fnr", [])
    perf_g = tg.get("perf", [])
    ev_tips = get_kb_evasion_guidance(kb)

    # Helper
    def add(priority, title, body, fix, source="analysis"):
        recs.append({
            "priority": priority,  # critical / high / medium / low / info
            "title": title,
            "body": body,
            "fix": fix,
            "source": source,
        })

    # ── False Negative analysis ──────────────────────────────────────────────
    if fn_count > 0:
        fn_results = [r for r in results if r.outcome == "FN"]
        fn_descs = [r.event.description[:60] for r in fn_results[:3]]
        add(
            "critical",
            f"⚠ {fn_count} False Negative(s) — Rule misses real attacks",
            f"The rule failed to detect {fn_count} attack event(s).\n"
            f"Examples missed: {', '.join(fn_descs)}.\n"
            f"Recall dropped to {recall:.1%}.",
            "Widen detection logic: add OR branches for missed variants, "
            "lower threshold values, or introduce OriginalFileName checks to catch renamed binaries.",
            "confusion_matrix",
        )

    if recall < 0.8 and len(conditions) < 3:
        add(
            "high",
            "📉 Low Recall — Insufficient condition coverage",
            f"Only {len(conditions)} condition(s) parsed. Rules with very few conditions "
            "tend to be over-specific and miss attack variants.",
            "Add secondary detection conditions covering alternate execution paths "
            "(e.g., different parent processes, alternate field values). "
            "Consider converting to OR logic across variants.",
            "rule_structure",
        )

    # ── Evasion bypass analysis ──────────────────────────────────────────────
    if evasion_missed > 0:
        ev_failed = [r for r in results if r.event.category == dv.EventCategory.EVASION and not r.passed]
        ev_tags = []
        for r in ev_failed:
            ev_tags.extend(r.event.tags or [])
        ev_types = list(set(t for t in ev_tags if t not in ("evasion",)))

        add(
            "critical",
            f"🥷 {evasion_missed} Evasion Bypass(es) Detected",
            f"The rule was evaded by: {', '.join(ev_types[:5]) or 'unknown techniques'}.\n"
            f"Evasion resistance score: {evasion_r:.1%}.",
            "Add OriginalFileName field check (Sysmon) for renamed binary evasion. "
            "Use case-insensitive matching. Add path-normalisation pre-processing. "
            "Consider adding base64 decode enrichment before rule evaluation.",
            "evasion_analysis",
        )

    _failed_tags = {tag for r in results if not r.passed for tag in (r.event.tags or [])}
    if "case_manipulation" in _failed_tags:
        add(
            "high",
            "🔡 Case-Sensitivity Bypass Risk",
            "One or more evasion variants used uppercase/lowercase manipulation to evade the rule.",
            f"Ensure all {fmt} conditions use case-insensitive comparison operators "
            "(e.g., `|contains` in Sigma, `has` in KQL, `ContainsCIS` in S1QL).",
            "evasion_analysis",
        )

    if "b64_encoding" in _failed_tags:
        add(
            "high",
            "🔐 Base64 Encoding Bypass Risk",
            "The rule can be bypassed by base64-encoding the trigger payload.",
            "Add a second detection branch that decodes and inspects encoded command lines. "
            "In Sigma: add `CommandLine|base64offset|contains` modifier. "
            "In KQL/Cribl: use `base64_decode_tostring()` in a `let` statement.",
            "evasion_analysis",
        )

    # ── False Positive analysis ──────────────────────────────────────────────
    if fp_count > 0:
        fp_results = [r for r in results if r.outcome == "FP"]
        fp_descs = [r.event.description[:60] for r in fp_results[:3]]
        add(
            "high",
            f"🚨 {fp_count} False Positive(s) — Rule fires on benign activity",
            f"The rule incorrectly fired on {fp_count} benign event(s).\n"
            f"Examples: {', '.join(fp_descs)}.\nPrecision: {precision:.1%}.",
            "Add exclusion filters for known-good values (allowlisted domains, system accounts, "
            "admin paths). Use NOT conditions or filter blocks.",
            "confusion_matrix",
        )

    if precision < 0.85 and len(filters) == 0:
        add(
            "high",
            "🚫 No Exclusion Filters — High FP risk in production",
            "The rule has no allowlist/filter conditions. Without tuning, "
            "this rule will likely produce significant false positive volume in a real environment.",
            "Add filter conditions excluding: known-good process paths, system service accounts, "
            "scheduled task names, software update paths, and your IT admin hostnames.",
            "rule_structure",
        )

    # ── Rule structure recommendations ───────────────────────────────────────
    if logic == "OR" and len(conditions) > 6:
        add(
            "medium",
            "🔀 OR Logic with Many Conditions — FP risk",
            f"Rule uses OR logic across {len(conditions)} conditions. "
            "This maximises recall but significantly increases false positive risk.",
            "Refactor into AND groups: combine related conditions with AND, "
            "then OR the groups. Example: (process_match AND parent_match) OR (file_match AND hash_match).",
            "rule_structure",
        )

    if len(conditions) == 0:
        add(
            "critical",
            "❌ No Conditions Parsed",
            "The rule parser extracted zero conditions from your input. "
            "This may indicate an unsupported syntax or a parsing error.",
            f"Verify the rule is valid {fmt} syntax and that the platform selection matches the rule format. "
            "Try pasting a minimal test rule to confirm the parser is working.",
            "parsing",
        )

    if len(conditions) > 0 and not any(
        c["field"] in ("OriginalFileName", "src.process.displayName", "tgt.process.displayName")
        for c in conditions
    ) and ("sigma" in platform.lower() or "sentinelone" in platform.lower()):
        add(
            "medium",
            "🔎 No OriginalFileName / DisplayName Check",
            "The rule relies only on the Image/path field to identify the process. "
            "Attackers can rename a binary to any name; the Image field will not catch this.",
            "Add an OriginalFileName (Sigma/Sysmon) or src.process.displayName (SentinelOne) "
            "check as an OR condition to detect renamed binary execution.",
            "rule_structure",
        )

    # ── KB-grounded FPR recommendations ──────────────────────────────────────
    for tip in fpr_g[:3]:
        if isinstance(tip, str) and len(tip) > 15:
            add(
                "medium",
                f"📖 KB Tip — False Positive Reduction ({platform})",
                tip,
                "Apply this KB-recommended tuning technique to reduce false positive noise.",
                f"kb:{platform}",
            )

    # ── KB-grounded FNR recommendations ──────────────────────────────────────
    for tip in fnr_g[:3]:
        if isinstance(tip, str) and len(tip) > 15:
            add(
                "low",
                f"📖 KB Tip — Coverage Improvement ({platform})",
                tip,
                "Apply this KB-recommended technique to improve detection coverage.",
                f"kb:{platform}",
            )

    # ── Evasion guidance from KB ──────────────────────────────────────────────
    for tip in ev_tips[:2]:
        if isinstance(tip, str) and len(tip) > 15:
            add(
                "low",
                f"📖 KB Tip — Evasion Resistance ({platform})",
                tip,
                "Implement this platform-specific technique to harden against evasion.",
                f"kb:{platform}",
            )

    # ── Performance ──────────────────────────────────────────────────────────
    avg_t = metrics.get("avg_execution_time_ms", 0)
    if avg_t > 5:
        add(
            "info",
            "⚡ Performance — Slow average evaluation time",
            f"Average evaluation time: {avg_t:.2f} ms. "
            "This may indicate overly complex regex or excessive field lookups.",
            "Simplify regex patterns, avoid excessive wildcard prefixes, "
            "and consider field indexing in your SIEM.",
            "performance",
        )

    for tip in perf_g[:2]:
        if isinstance(tip, str) and len(tip) > 15:
            add("info", f"⚡ KB Tip — Performance ({platform})", tip,
                "Apply this platform-specific optimisation.", f"kb:{platform}")

    # ── Final: no issues ──────────────────────────────────────────────────────
    grade = metrics.get("overall_grade", "F")
    if grade == "A" and fn_count == 0 and fp_count == 0:
        add(
            "info",
            "✅ Rule passes all tests — Grade A",
            "No false negatives, no false positives, full evasion resistance. "
            "This rule is production-ready based on the tested telemetry set.",
            "Consider scheduling periodic re-validation as attacker TTPs evolve. "
            "Expand evasion test coverage over time.",
            "summary",
        )

    # Sort: critical → high → medium → low → info
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    recs.sort(key=lambda r: priority_order.get(r["priority"], 5))
    return recs


# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT BUILDER  (self-contained, with recommendations)
# ═══════════════════════════════════════════════════════════════════════════════
def build_html_report(
    results: list,
    metrics: dict,
    rule_name: str,
    platform: str,
    parsed_rule: dict,
    recommendations: list,
) -> str:
    m  = metrics
    cm = m["confusion_matrix"]
    grade = m.get("overall_grade", "F")
    gc = {"A": "#10b981", "B": "#06b6d4", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}.get(grade, "#ef4444")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    pmeta = PLATFORM_META.get(platform, {})

    # Build results rows
    rows_html = ""
    for r in results:
        cls_  = "pass" if r.passed else "fail"
        badge = "badge-pass" if r.passed else "badge-fail"
        exp   = "DETECT" if r.event.expected_detection else "IGNORE"
        act   = "DETECT" if r.detection.matched else "IGNORE"
        conf  = f"{r.detection.confidence_score:.2f}" if r.detection.matched else "—"
        real_tag = '<span class="real-badge">REAL</span>' if "imported" in (r.event.tags or []) else ""
        rows_html += f"""<tr class="{cls_}"><td>{r.event.event_id}</td>
          <td>{r.event.category.value}</td>
          <td>{r.event.description[:55]}{'…' if len(r.event.description) > 55 else ''}{real_tag}</td>
          <td>{exp}</td><td>{act}</td><td>{conf}</td>
          <td><span class="{badge}">{r.outcome}</span></td></tr>\n"""

    # Build failures section
    failures_html = ""
    for r in [x for x in results if not x.passed]:
        cstr = ", ".join(r.detection.matched_conditions[:3]) or "no conditions matched"
        preview = json.dumps(r.event.log_data, indent=2)[:800]
        failures_html += f"""<div class="failure-card">
          <h4>[{r.outcome}] {r.event.event_id}: {r.event.description}</h4>
          <p><b>Category:</b> {r.event.category.value} &nbsp;|&nbsp; <b>Notes:</b> {r.event.notes or 'N/A'}</p>
          <p><b>Matched conditions:</b> {cstr}</p>
          <pre>{preview}</pre></div>\n"""

    # Build recommendations section
    pcolors = {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#10b981", "info": "#06b6d4"}
    recs_html = ""
    for r in recommendations:
        c = pcolors.get(r["priority"], "#94a3b8")
        recs_html += f"""<div class="rec-card" style="border-left-color:{c}">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
            <span class="priority-badge" style="background:{c}22;color:{c};border:1px solid {c}44">
              {r['priority'].upper()}</span>
            <strong style="color:#e2e8f0;font-size:.92rem">{r['title']}</strong>
          </div>
          <p style="color:#94a3b8;font-size:.83rem;line-height:1.7;margin:4px 0">{r['body']}</p>
          <div class="rec-fix">
            <span style="font-size:.75rem;font-weight:700;text-transform:uppercase;
              letter-spacing:1px;color:{c};margin-right:6px">FIX →</span>
            <span style="font-size:.83rem;color:#64748b">{r['fix']}</span>
          </div></div>\n"""

    if not recs_html:
        recs_html = '<p style="color:#10b981;padding:1rem 0">✓ No issues found — rule is production-ready.</p>'

    # Conditions list
    conds = parsed_rule.get("conditions", []) if parsed_rule else []
    cond_html = "".join(
        f"<li><code>{c['field']}</code> <em style='color:#8b5cf6'>{c['op']}</em> "
        f"<strong style='color:#fbbf24'>'{c['value'][:40]}'</strong></li>"
        for c in conds
    ) or "<li>No conditions parsed</li>"

    passed_n   = sum(1 for r in results if r.passed)
    imported_n = sum(1 for r in results if "imported" in (r.event.tags or []))
    imported_note = f" · <span style='color:#2dd4bf'>{imported_n} real logs included</span>" if imported_n else ""

    metric_cards = "".join(
        f'<div class="metric-card"><span class="value">{v:.1%}</span>'
        f'<div class="label">{lbl}</div>'
        f'<div class="prog-track"><div class="prog-fill" style="width:{v*100:.0f}%;background:{clr}"></div></div></div>'
        for lbl, v, clr in [
            ("Accuracy",           m.get("accuracy", 0),           "#06b6d4"),
            ("Precision",          m.get("precision", 0),          "#10b981"),
            ("Recall",             m.get("recall", 0),             "#10b981"),
            ("F1 Score",           m.get("f1_score", 0),           "#8b5cf6"),
            ("Evasion Resistance", m.get("evasion_resistance", 0), "#f59e0b"),
            ("Composite Score",    m.get("composite_score", 0),    gc),
        ]
    )

    critical_recs = sum(1 for r in recommendations if r["priority"] in ("critical", "high"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Validation Report — {rule_name}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     max-width:1100px;margin:0 auto;padding:2rem;background:#0f172a;color:#e2e8f0;line-height:1.6}}
h1{{color:#f8fafc;font-size:1.5rem;font-weight:800;margin-bottom:.3rem}}
h2{{color:#94a3b8;font-size:.78rem;letter-spacing:3px;text-transform:uppercase;
    border-bottom:1px solid #1e293b;padding-bottom:.5rem;margin:2rem 0 1rem}}
.meta{{font-size:.83rem;color:#475569;margin-bottom:1.5rem}}
.platform-tag{{display:inline-block;background:rgba(6,182,212,.1);border:1px solid rgba(6,182,212,.3);
    border-radius:6px;padding:3px 10px;font-size:.72rem;color:#22d3ee;font-weight:600;margin-bottom:.75rem}}
.summary-row{{display:flex;align-items:center;gap:2rem;background:#0f1e33;border:1px solid #1e3a5f;
    border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;flex-wrap:wrap}}
.grade{{font-size:5rem;font-weight:900;color:{gc};text-shadow:0 0 30px {gc}44;line-height:1}}
.summary-item .sv{{font-size:1.8rem;font-weight:800;color:{gc}}}
.summary-item .sl{{font-size:.65rem;color:#475569;text-transform:uppercase;letter-spacing:2px;margin-top:2px}}
.metrics-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:.75rem;margin:1rem 0}}
.metric-card{{background:#1e293b;border-radius:8px;padding:1rem;text-align:center;border:1px solid #334155}}
.metric-card .value{{font-size:1.6rem;font-weight:700;color:#f8fafc}}
.metric-card .label{{font-size:.78rem;color:#64748b;margin-top:.25rem}}
.prog-track{{background:#0f172a;border-radius:100px;height:4px;margin-top:.5rem;overflow:hidden}}
.prog-fill{{height:100%;border-radius:100px}}
.cm-grid{{display:grid;grid-template-columns:1fr 1fr;gap:.5rem;max-width:360px;margin:1rem 0}}
.cm-cell{{padding:1.2rem;border-radius:8px;text-align:center;font-weight:800;font-size:1.4rem}}
.cm-tp{{background:#14532d;color:#bbf7d0}}.cm-fp{{background:#7f1d1d;color:#fecaca}}
.cm-fn{{background:#78350f;color:#fed7aa}}.cm-tn{{background:#1e3a5f;color:#bfdbfe}}
.cm-sub{{font-size:.65rem;font-weight:400;opacity:.7;display:block;margin-top:4px;
         letter-spacing:1px;text-transform:uppercase}}
.cond-list{{list-style:none;display:flex;flex-wrap:wrap;gap:6px;margin:.5rem 0 1rem}}
.cond-list li{{background:#1e293b;border:1px solid #334155;border-radius:6px;padding:4px 10px;font-size:.78rem}}
code{{background:#1e293b;padding:1px 6px;border-radius:4px;color:#7dd3fc;font-size:.78rem}}
table{{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.84rem}}
th{{background:#1e293b;color:#94a3b8;padding:.6rem .8rem;text-align:left;
    font-size:.72rem;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #1e293b}}
td{{padding:.5rem .8rem;border-bottom:1px solid #0f172a}}
tr.pass{{background:#060d16}}tr.fail{{background:#110a0a}}
tr:hover{{background:#0f1a2e!important}}
.badge-pass{{background:#14532d;color:#bbf7d0;padding:2px 8px;border-radius:4px;font-weight:700;font-size:.72rem}}
.badge-fail{{background:#7f1d1d;color:#fecaca;padding:2px 8px;border-radius:4px;font-weight:700;font-size:.72rem}}
.real-badge{{font-size:.68rem;font-weight:700;letter-spacing:.5px;text-transform:uppercase;
    color:#2dd4bf;background:rgba(20,184,166,.1);border:1px solid rgba(20,184,166,.25);
    border-radius:3px;padding:1px 5px;margin-left:5px}}
.failure-card{{background:#0f0a12;border-left:3px solid #ef4444;padding:1rem 1.2rem;
    margin:.6rem 0;border-radius:0 8px 8px 0}}
.failure-card h4{{color:#fca5a5;margin-bottom:.4rem;font-size:.88rem}}
.failure-card p{{font-size:.8rem;color:#94a3b8;margin:.2rem 0}}
.rec-card{{background:#0a1628;border-left:3px solid #06b6d4;padding:1rem 1.2rem;
    margin:.6rem 0;border-radius:0 8px 8px 0}}
.priority-badge{{font-size:.68rem;font-weight:800;letter-spacing:1px;text-transform:uppercase;
    padding:2px 8px;border-radius:4px}}
.rec-fix{{margin-top:.5rem;padding:.5rem .75rem;background:#0f172a;border-radius:6px;font-size:.82rem}}
.no-issues{{color:#10b981;padding:1rem 0}}
pre{{background:#06090f;padding:.75rem;border-radius:6px;overflow-x:auto;font-size:.72rem;
     color:#64748b;margin-top:.5rem;border:1px solid #1e293b;max-height:200px;overflow-y:auto}}
.alert-banner{{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:8px;
    padding:.75rem 1rem;margin:.75rem 0;color:#fca5a5;font-size:.85rem}}
</style>
</head>
<body>
<div class="platform-tag">{pmeta.get('icon', '🔍')} {platform} · {pmeta.get('lang', 'Custom')}</div>
<h1>Detection Rule Validation Report</h1>
<div class="meta">Rule: <strong>{rule_name}</strong> &nbsp;·&nbsp; Generated: {now}{imported_note}</div>

{"<div class='alert-banner'>⚠ " + str(critical_recs) + " critical/high priority recommendation(s) require attention before production deployment.</div>" if critical_recs > 0 else ""}

<div class="summary-row">
  <div><div class="grade">{grade}</div></div>
  <div class="summary-item"><div class="sv">{m['composite_score']:.0%}</div><div class="sl">Composite</div></div>
  <div class="summary-item"><div class="sv">{m['precision']:.0%}</div><div class="sl">Precision</div></div>
  <div class="summary-item"><div class="sv">{m['recall']:.0%}</div><div class="sl">Recall</div></div>
  <div class="summary-item"><div class="sv">{m['f1_score']:.0%}</div><div class="sl">F1 Score</div></div>
  <div class="summary-item"><div class="sv">{m['evasion_resistance']:.0%}</div><div class="sl">Evasion Resist.</div></div>
  <div class="summary-item"><div class="sv">{passed_n}/{m['total_events']}</div><div class="sl">Tests Passed</div></div>
</div>

<h2>Metrics</h2>
<div class="metrics-grid">{metric_cards}</div>

<h2>Confusion Matrix</h2>
<div class="cm-grid">
  <div class="cm-cell cm-tp">{cm['TP']}<span class="cm-sub">True Positives</span></div>
  <div class="cm-cell cm-fp">{cm['FP']}<span class="cm-sub">False Positives</span></div>
  <div class="cm-cell cm-fn">{cm['FN']}<span class="cm-sub">False Negatives</span></div>
  <div class="cm-cell cm-tn">{cm['TN']}<span class="cm-sub">True Negatives</span></div>
</div>

<h2>Detection Logic ({parsed_rule.get('format','Generic') if parsed_rule else 'Demo'} — {parsed_rule.get('logic','') if parsed_rule else ''} logic)</h2>
<ul class="cond-list">{cond_html}</ul>

<h2>🔧 Recommendations ({len(recommendations)} items · {critical_recs} critical/high)</h2>
{recs_html}

<h2>All Results &nbsp;<span style="font-weight:400;color:#475569">({passed_n}/{m['total_events']} passed)</span></h2>
<table>
<thead><tr><th>ID</th><th>Category</th><th>Description</th><th>Expected</th><th>Actual</th><th>Conf</th><th>Result</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>

<h2>Failure Details &nbsp;<span style="font-weight:400;color:#475569">({sum(1 for r in results if not r.passed)} events)</span></h2>
{failures_html or '<p class="no-issues">✓ No failures — all events evaluated correctly.</p>'}
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# POPUP REPORT COMPONENT
# ═══════════════════════════════════════════════════════════════════════════════
def show_popup_button(html_content: str, rule_name: str):
    """Render a button that opens the HTML report in a full-screen overlay.

    Uses a base64 data URI instead of embedding the raw HTML in a JS template
    literal, which eliminates all escaping edge-cases (newlines, backticks,
    dollar signs, Unicode surrogates, etc.).
    """
    b64_report = base64.b64encode(html_content.encode("utf-8")).decode("ascii")
    safe_name  = rule_name[:70].replace('"', "'")
    markup = f"""<!DOCTYPE html><html><head><style>
*{{box-sizing:border-box;margin:0;padding:0}}body{{background:transparent}}
.open-btn{{display:inline-flex;align-items:center;gap:8px;background:linear-gradient(135deg,#6d28d9,#7c3aed);
  color:#ede9fe;border:1px solid #7c3aed;border-radius:8px;padding:10px 22px;
  font-family:'Outfit',system-ui,sans-serif;font-size:12px;font-weight:700;letter-spacing:1.5px;
  text-transform:uppercase;cursor:pointer;transition:all .2s;box-shadow:0 0 20px rgba(109,40,217,.4)}}
.open-btn:hover{{background:linear-gradient(135deg,#5b21b6,#6d28d9);box-shadow:0 0 30px rgba(109,40,217,.6);transform:translateY(-1px)}}
#overlay{{display:none;position:fixed;inset:0;background:rgba(3,5,12,.94);z-index:99999;flex-direction:column;animation:fadeIn .2s ease}}
#overlay.show{{display:flex}}@keyframes fadeIn{{from{{opacity:0}}to{{opacity:1}}}}
.topbar{{background:#050810;border-bottom:1px solid #0d1625;padding:10px 18px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-shrink:0}}
.topbar-title{{font-family:'Outfit',system-ui;font-size:13px;font-weight:700;color:#e2e8f0;letter-spacing:.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}}
.action-row{{display:flex;gap:8px;flex-shrink:0}}
.btn{{border-radius:6px;padding:6px 14px;font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;cursor:pointer;font-family:'Outfit',system-ui;border:1px solid;transition:all .15s;text-decoration:none;display:inline-flex;align-items:center;gap:5px}}
.btn-dl{{background:rgba(6,182,212,.1);color:#22d3ee;border-color:rgba(6,182,212,.35)}}.btn-dl:hover{{background:rgba(6,182,212,.2)}}
.btn-pr{{background:rgba(16,185,129,.1);color:#34d399;border-color:rgba(16,185,129,.35)}}.btn-pr:hover{{background:rgba(16,185,129,.2)}}
.btn-cl{{background:rgba(239,68,68,.1);color:#f87171;border-color:rgba(239,68,68,.3)}}.btn-cl:hover{{background:rgba(239,68,68,.2)}}
.frame-wrap{{flex:1;overflow:hidden;background:#0f172a}}
.frame-wrap iframe{{width:100%;height:100%;border:none;display:block}}
.loader{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  background:#0f172a;font-family:system-ui;font-size:14px;color:#4a6080;pointer-events:none;transition:opacity .3s}}
.loader.hidden{{opacity:0}}
</style></head><body>
<button class="open-btn" onclick="openReport()">📄&nbsp; View Full Report</button>
<div id="overlay">
  <div class="topbar">
    <div class="topbar-title">📄 &nbsp;{safe_name}</div>
    <div class="action-row">
      <button class="btn btn-pr" onclick="printFrame()">🖨&nbsp;Print</button>
      <a id="dlLink" class="btn btn-dl" download="validation_report.html">⬇&nbsp;Download</a>
      <button class="btn btn-cl" onclick="closeReport()">✕&nbsp;Close</button>
    </div>
  </div>
  <div class="frame-wrap" style="position:relative">
    <div class="loader" id="loader">Loading report…</div>
    <iframe id="rFrame" onload="document.getElementById('loader').classList.add('hidden')"></iframe>
  </div>
</div>
<script>
const B64="{b64_report}";
function decodeB64(s){{
  const bytes=atob(s);
  const arr=new Uint8Array(bytes.length);
  for(let i=0;i<bytes.length;i++)arr[i]=bytes.charCodeAt(i);
  return new TextDecoder('utf-8').decode(arr);
}}
function openReport(){{
  const html=decodeB64(B64);
  const blob=new Blob([html],{{type:'text/html;charset=utf-8'}});
  const url=URL.createObjectURL(blob);
  document.getElementById('rFrame').src=url;
  document.getElementById('dlLink').href=url;
  document.getElementById('loader').classList.remove('hidden');
  document.getElementById('overlay').classList.add('show');
  document.body.style.overflow='hidden';
}}
function closeReport(){{document.getElementById('overlay').classList.remove('show');document.body.style.overflow='';}}
function printFrame(){{try{{document.getElementById('rFrame').contentWindow.print();}}catch(e){{window.print();}}}}
document.addEventListener('keydown',e=>{{if(e.key==='Escape')closeReport();}});
</script></body></html>"""
    components.html(markup, height=52, scrolling=False)


# ═══════════════════════════════════════════════════════════════════════════════
# CSV EXPORTER
# ═══════════════════════════════════════════════════════════════════════════════
def build_csv_export(results: list, metrics: dict, recommendations: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["=== METRICS ==="])
    for k, v in metrics.items():
        if not isinstance(v, dict):
            w.writerow([k, v])
    w.writerow([])
    w.writerow(["=== CONFUSION MATRIX ==="])
    cm = metrics.get("confusion_matrix", {})
    for k, v in cm.items():
        w.writerow([k, v])
    w.writerow([])
    w.writerow(["=== RECOMMENDATIONS ==="])
    w.writerow(["priority", "title", "body", "fix", "source"])
    for r in recommendations:
        w.writerow([r["priority"], r["title"], r["body"], r["fix"], r["source"]])
    w.writerow([])
    w.writerow(["=== EVENT RESULTS ==="])
    w.writerow(["event_id", "category", "description", "expected_detection",
                "actual_detection", "outcome", "passed", "confidence",
                "matched_conditions", "source", "tags"])
    for r in results:
        is_real = "imported" in (r.event.tags or [])
        w.writerow([
            r.event.event_id,
            r.event.category.value,
            r.event.description,
            r.event.expected_detection,
            r.detection.matched,
            r.outcome, r.passed,
            f"{r.detection.confidence_score:.2f}",
            "; ".join(r.detection.matched_conditions),
            "real" if is_real else "synthetic",
            ", ".join(r.event.tags or []),
        ])
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def pill(text: str, color: str = "blue") -> str:
    return f'<span class="pill pill-{color}">{text}</span>'

def pbar(value: float, color: str = "#06b6d4") -> str:
    pct = max(0, min(100, value * 100))
    return (f'<div class="prog-track"><div class="prog-fill" '
            f'style="width:{pct:.0f}%;background:{color}"></div></div>')

def metric_card(label: str, value: str, color: str, sub: str = "") -> str:
    # Parse the display value back to a 0-1 float for the progress bar.
    # Handles "75.3%" → 0.753 and raw floats like "0.75" → 0.75.
    try:
        if "%" in str(value):
            raw = float(str(value).strip("%")) / 100
        else:
            raw = float(value)
            if raw > 1.0:
                raw /= 100  # treat values > 1 as percentages (e.g. 75 → 0.75)
    except (ValueError, TypeError):
        raw = 0.0
    return f"""<div class="card">
      <div class="metric-label">{label}</div>
      <div class="metric-num" style="color:{color}">{value}</div>
      {f'<div class="metric-sub">{sub}</div>' if sub else ''}
      {pbar(raw, color)}
    </div>"""

def cm_cell(label: str, value: int, cls: str) -> str:
    colors = {
        "cm-tp": ("#10b981", "rgba(16,185,129,.1)"),
        "cm-tn": ("#06b6d4", "rgba(6,182,212,.08)"),
        "cm-fp": ("#ef4444", "rgba(239,68,68,.08)"),
        "cm-fn": ("#f59e0b", "rgba(245,158,11,.08)"),
    }
    c, bg = colors.get(cls, ("#94a3b8", "rgba(255,255,255,.05)"))
    return f"""<div class="{cls} cm-cell" style="background:{bg}">
      <div style="font-size:10px;letter-spacing:2px;color:#4a6080;text-transform:uppercase;margin-bottom:6px">{label}</div>
      <div class="metric-num" style="color:{c};font-size:40px">{value}</div>
    </div>"""


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE INITIALISATION
# ═══════════════════════════════════════════════════════════════════════════════
_SS_DEFAULTS = {
    "results": [],
    "metrics": {},
    "parsed_rule": None,
    "rule_name": "",
    "active_platform": list(PLATFORM_META.keys())[0],
    "html_report": "",
    "recommendations": [],
    "imported_count": 0,
}
for k, v in _SS_DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ═══════════════════════════════════════════════════════════════════════════════
# DEMO RULE CONSTANT
# ═══════════════════════════════════════════════════════════════════════════════
_DEMO_RULE = """\
title: Suspicious Rundll32 Execution
status: experimental
description: Detects suspicious Rundll32 proxy execution with scripting engines
author: DVT Demo
tags:
  - attack.defense_evasion
  - attack.t1218.011
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\rundll32.exe'
    CommandLine|contains:
      - 'javascript:'
      - 'vbscript:'
      - '..\\\\'
      - 'shell32.dll'
      - 'advpack.dll'
  filter_benign:
    CommandLine|contains:
      - 'shell32.dll,Control_RunDLL'
  condition: selection and not filter_benign
falsepositives:
  - Legitimate use of rundll32 for administrative purposes
level: medium"""


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    # ── Brand ─────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="display:flex;align-items:center;gap:10px;padding:4px 0 20px">
      <div style="width:34px;height:34px;border-radius:10px;flex-shrink:0;
        background:linear-gradient(135deg,#075985,#0ea5e9);
        display:flex;align-items:center;justify-content:center;font-size:16px;
        box-shadow:0 2px 12px rgba(14,165,233,.3)">⚔️</div>
      <div>
        <div style="font-size:13px;font-weight:700;color:var(--text-1);letter-spacing:-.01em">DVT v6</div>
        <div style="font-size:10px;color:var(--text-3);letter-spacing:.05em">SETTINGS &amp; CONTROLS</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Nav-back hint when results exist
    if st.session_state.get("results"):
        st.markdown("""
        <div style="background:var(--accent-dim);border:1px solid rgba(14,165,233,.25);
          border-radius:8px;padding:8px 12px;margin-bottom:14px;display:flex;
          align-items:center;gap:8px">
          <span style="font-size:14px">←</span>
          <span style="font-size:11px;color:var(--accent)">Close panel to view results</span>
        </div>
        """, unsafe_allow_html=True)

    # ── Platform ──────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Target Platform</div>', unsafe_allow_html=True)
    platform_options = list(PLATFORM_META.keys())
    _initial_platform = st.session_state.get("_pending_platform",
                         st.session_state.get("active_platform", platform_options[0]))
    if _initial_platform not in platform_options:
        _initial_platform = platform_options[0]

    platform = st.selectbox(
        "Platform",
        platform_options,
        index=platform_options.index(_initial_platform),
        label_visibility="collapsed",
    )
    st.session_state.active_platform = platform
    pmeta = PLATFORM_META[platform]

    kb        = load_kb(platform)
    kb_loaded = bool(kb)

    st.markdown(f"""
    <div class="card" style="padding:10px 14px;margin-top:6px">
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:20px">{pmeta['icon']}</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:12px;font-weight:600;color:{pmeta['color']};
            white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{platform}</div>
          <div style="font-size:10px;color:var(--text-3)">{pmeta['lang']} · {pmeta['log_source']}</div>
        </div>
        {'<span class="pill pill-green">KB ✓</span>' if kb_loaded else '<span class="pill pill-amber">KB —</span>'}
      </div>
      <div style="font-size:10px;color:var(--text-3);margin-top:8px;line-height:1.5">{pmeta['desc']}</div>
    </div>
    """, unsafe_allow_html=True)

    if not kb_loaded:
        st.warning(
            f"KB not found for **{platform}**. Place `{pmeta['kb_file']}` in "
            "`knowledge_bases/` next to app.py to enable KB-grounded recommendations.",
            icon="⚠️",
        )

    st.divider()

    # ── Rule input ────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Detection Rule</div>', unsafe_allow_html=True)

    demo_clicked_sb = st.button("▶  Load Demo Rule", use_container_width=True, key="demo_sidebar")
    if demo_clicked_sb:
        st.session_state["_demo_rule"] = _DEMO_RULE
        st.rerun()

    # Pending rule from home page takes priority
    _pending = st.session_state.pop("_pending_rule", None)
    _demo_default = _pending or st.session_state.get("_demo_rule", "")

    rule_text = st.text_area(
        "Paste your detection rule",
        value=_demo_default,
        height=220,
        placeholder=(
            "Paste any detection rule:\n\n"
            "• Sigma (YAML)\n• S1QL\n• KQL / Cribl KQL\n"
            "• PAN-OS filter\n• ASQ (Armis)\n• OQL (Obsidian)\n• Okta EventHook"
        ),
        label_visibility="collapsed",
    )
    if _demo_default and rule_text != _demo_default:
        st.session_state.pop("_demo_rule", None)

    if rule_text.strip():
        try:
            _preview = RuleParser.parse(rule_text, platform)
            st.markdown(
                f'<div style="font-size:11px;color:var(--green);padding:4px 0">'
                f'✓ {_preview["format"]} · {len(_preview["conditions"])} conditions · '
                f'{len(_preview["filters"])} filters · {_preview["logic"]}</div>',
                unsafe_allow_html=True,
            )
        except Exception:
            pass

    st.divider()

    # ── Test parameters ───────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Test Parameters</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        tp_count = st.number_input("True Pos", min_value=1, max_value=50, value=10)
        fp_count = st.number_input("FP Cand.", min_value=0, max_value=20, value=5)
    with c2:
        tn_count = st.number_input("True Neg", min_value=1, max_value=50, value=15)
        ev_count = st.number_input("Evasion",  min_value=0, max_value=20, value=5)

    st.divider()

    # ── Real log import ───────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Import Real Logs (Optional)</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "Upload logs",
        type=["json", "jsonl", "ndjson", "csv"],
        label_visibility="collapsed",
    )
    import_label = st.selectbox(
        "Label imported events as",
        list(LogImporter.CATEGORY_MAP.keys()) + ["auto-detect"],
        index=4,
        label_visibility="collapsed",
    )
    import_desc_field = st.text_input(
        "Description field (optional)",
        value="",
        placeholder="e.g. CommandLine, msg.subject",
        label_visibility="collapsed",
    )

    st.divider()

    # ── Run button ────────────────────────────────────────────────────────────
    run_disabled = not rule_text.strip()
    run_clicked  = st.button(
        "⚔  Run Validation",
        use_container_width=True,
        disabled=run_disabled,
    )
    if run_disabled:
        st.caption("Paste a detection rule above to begin.")

    # Anthropic API key (optional — enables direct Claude calls)
    with st.expander("🔑 Anthropic API Key (optional)"):
        api_key_input = st.text_input(
            "API Key",
            value=st.session_state.get("anthropic_api_key", ""),
            type="password",
            placeholder="sk-ant-…",
            label_visibility="collapsed",
        )
        if api_key_input:
            st.session_state["anthropic_api_key"] = api_key_input
        st.caption("Enables direct Claude 3.5 Sonnet rule generation. "
                   "Without a key, the prompt is prepared for copy-paste into Copilot.")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN VALIDATION LOGIC
# ═══════════════════════════════════════════════════════════════════════════════
if run_clicked and rule_text.strip():
    # ── Parse rule ────────────────────────────────────────────────────────────
    with st.spinner("Parsing rule..."):
        parsed = RuleParser.parse(rule_text, platform)
    st.session_state.parsed_rule = parsed
    st.session_state.rule_name   = parsed.get("rule_name", "Custom Rule")

    # ── Generate synthetic telemetry ─────────────────────────────────────────
    with st.spinner("Generating test telemetry..."):
        gen = PlatformGenerator(parsed, platform, kb)
        events: list[dv.SyntheticEvent] = gen.generate_all(
            tp=int(tp_count), tn=int(tn_count), fp=int(fp_count), evasion=int(ev_count)
        )

    # ── Import real logs ──────────────────────────────────────────────────────
    imported_count = 0
    if uploaded_file is not None:
        raw_bytes = uploaded_file.read()
        lbl = import_label if import_label != "auto-detect" else "auto"
        imported_events, import_warnings = LogImporter.parse(
            raw_bytes, uploaded_file.name, lbl, import_desc_field
        )
        if import_warnings:
            for w in import_warnings:
                st.warning(w)
        events.extend(imported_events)
        imported_count = len(imported_events)
        if imported_count:
            st.success(f"✅ Imported {imported_count} real log events from {uploaded_file.name}")
    st.session_state.imported_count = imported_count

    # ── Run detection engine ──────────────────────────────────────────────────
    with st.spinner("Evaluating events..."):
        engine = DynamicEngine(parsed)
        runner = dv.TestRunner(engine, events)
        results = runner.run()
        metrics = runner.get_metrics()

    st.session_state.results = results
    st.session_state.metrics = metrics

    # ── Generate recommendations ──────────────────────────────────────────────
    with st.spinner("Generating recommendations..."):
        recommendations = generate_recommendations(results, metrics, parsed, platform, kb)
    st.session_state.recommendations = recommendations

    # ── Build HTML report ────────────────────────────────────────────────────
    st.session_state.html_report = build_html_report(
        results, metrics, parsed["rule_name"], platform, parsed, recommendations
    )


# ═══════════════════════════════════════════════════════════════════════════════
# RESULTS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════
results      = st.session_state.results
metrics      = st.session_state.metrics
parsed_rule  = st.session_state.parsed_rule
recommendations = st.session_state.recommendations
imported_in_results = sum(1 for r in results if "imported" in (r.event.tags or []))

if not results:
    # ── HOME PAGE — centred hero input ───────────────────────────────────────
    st.markdown("<div style='height:3.5rem'></div>", unsafe_allow_html=True)

    # Brand mark
    st.markdown("""
    <div style="text-align:center;margin-bottom:2.5rem" class="anim-fade-up">
      <div style="display:inline-flex;align-items:center;gap:12px;margin-bottom:16px">
        <div style="width:44px;height:44px;border-radius:14px;
          background:linear-gradient(135deg,#075985,#0ea5e9);
          display:flex;align-items:center;justify-content:center;
          font-size:22px;box-shadow:0 4px 20px rgba(14,165,233,.35)">⚔️</div>
        <div style="text-align:left">
          <div style="font-size:13px;font-weight:700;letter-spacing:.06em;
            text-transform:uppercase;color:var(--text-1)">Detection Rule Validator</div>
          <div style="font-size:11px;color:var(--text-3);letter-spacing:.04em">v6 · KB-grounded · AI-powered</div>
        </div>
      </div>
      <div class="t-display" style="margin-bottom:12px">
        Validate any<br>
        <span style="background:linear-gradient(135deg,#0ea5e9,#8b5cf6);
          -webkit-background-clip:text;-webkit-text-fill-color:transparent">
          detection rule</span>
      </div>
      <p style="font-size:15px;color:var(--text-2);max-width:520px;
        margin:0 auto;line-height:1.7">
        Paste a rule below. Get synthetic telemetry, evasion testing, precision &amp;
        recall scoring, and AI-generated improvements — in seconds.
      </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Centred input card ────────────────────────────────────────────────────
    _, col_main, _ = st.columns([1, 3.2, 1])
    with col_main:
        # Platform chips row
        platform_keys = list(PLATFORM_META.keys())
        if "home_platform" not in st.session_state:
            st.session_state.home_platform = platform_keys[0]

        # Build platform chip HTML (visual only — selectbox drives state)
        chips = ""
        for p in platform_keys:
            pm   = PLATFORM_META[p]
            sel  = "selected" if p == st.session_state.home_platform else ""
            desc_safe = PLATFORM_META[p]["desc"].replace('"', "&quot;")
            chips += (
                '<div class="platform-chip ' + sel + '" style="min-width:90px" '
                'title="' + desc_safe + '">'
                '<div style="font-size:18px">' + pm["icon"] + '</div>'
                '<div style="font-size:10px;font-weight:600;color:var(--text-2);margin-top:4px">'
                + p.split()[0] + '</div></div>'
            )
        st.markdown(
            f'<div style="display:flex;flex-wrap:wrap;gap:8px;justify-content:center;'
            f'margin-bottom:14px">{chips}</div>',
            unsafe_allow_html=True,
        )
        platform_home = st.selectbox(
            "Platform",
            platform_keys,
            index=platform_keys.index(st.session_state.home_platform),
            label_visibility="collapsed",
            key="home_platform_sel",
        )
        st.session_state.home_platform   = platform_home
        st.session_state.active_platform = platform_home

        # Rule input wrapped in styled hero card
        st.markdown('<div class="hero-input-wrap">', unsafe_allow_html=True)
        st.markdown(
            '<div style="padding:14px 20px 0;display:flex;align-items:center;'
            'justify-content:space-between;border-bottom:1px solid var(--border);'
            'margin-bottom:8px">'
            '<span style="font-size:11px;font-weight:600;letter-spacing:.06em;'
            'text-transform:uppercase;color:var(--text-3)">Detection Rule</span>'
            '<span style="font-size:10px;color:var(--text-3)">'
            'Sigma · S1QL · KQL · PAN-OS · ASQ · OQL · Okta</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div style="padding:0 20px 4px">', unsafe_allow_html=True)

        _demo_default_home = st.session_state.get("_demo_rule", "")
        rule_text_home = st.text_area(
            "rule_home",
            value=_demo_default_home,
            height=260,
            placeholder=(
                "# Paste any detection rule here…\n\n"
                "# Example — Sigma\n"
                "title: Suspicious Rundll32\n"
                "detection:\n"
                "  selection:\n"
                "    Image|endswith: '\\\\rundll32.exe'\n"
                "    CommandLine|contains: 'javascript:'\n"
                "  condition: selection"
            ),
            label_visibility="collapsed",
            key="rule_home_input",
        )
        st.markdown("</div>", unsafe_allow_html=True)

        # Bottom toolbar of the hero input box
        tb_left, tb_right = st.columns([2, 1])
        with tb_left:
            st.markdown(
                '<div style="padding:10px 20px 14px;display:flex;gap:10px;align-items:center">',
                unsafe_allow_html=True,
            )
            if rule_text_home.strip():
                try:
                    _prev = RuleParser.parse(rule_text_home, platform_home)
                    st.markdown(
                        f'<span style="font-size:11px;color:var(--green)">'
                        f'✓ {_prev["format"]} · {len(_prev["conditions"])} conditions · '
                        f'{len(_prev["filters"])} filters</span>',
                        unsafe_allow_html=True,
                    )
                except Exception:
                    pass
            st.markdown("</div>", unsafe_allow_html=True)
        with tb_right:
            st.markdown('<div style="padding:10px 20px 14px;text-align:right">', unsafe_allow_html=True)
            demo_btn_home = st.button("Load demo rule", key="demo_btn_home", use_container_width=False)
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)  # close hero-input-wrap

        if demo_btn_home:
            st.session_state["_demo_rule"] = _DEMO_RULE
            st.rerun()
        if _demo_default_home and rule_text_home != _demo_default_home:
            st.session_state.pop("_demo_rule", None)

        # Run button — full width, prominent
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        run_home = st.button(
            "⚔  Run Validation",
            use_container_width=True,
            disabled=not rule_text_home.strip(),
            key="run_home_btn",
        )
        if not rule_text_home.strip():
            st.markdown(
                '<div style="text-align:center;font-size:11px;color:var(--text-3);margin-top:8px">'
                'Paste a detection rule to begin</div>',
                unsafe_allow_html=True,
            )

    # Feature badges
    st.markdown("<div style='height:2.5rem'></div>", unsafe_allow_html=True)
    badges = [
        ("🎯", "True Positive Testing",   "Synthetic malicious telemetry matched to rule logic"),
        ("🥷", "Evasion Analysis",         "Adversary bypass variants — renamed binaries, encoding, path tricks"),
        ("⚖️", "Precision & Recall",      "Full confusion matrix, F1, composite grade A–F"),
        ("⚡", "AI Rule Generation",       "GPT-4o, Claude, Gemini improve your rule based on findings"),
    ]
    badge_cols = st.columns(4)
    for col, (icon, title, desc) in zip(badge_cols, badges):
        with col:
            st.markdown(
                f'<div class="card" style="text-align:center;padding:20px 14px">'
                f'<div style="font-size:26px;margin-bottom:10px">{icon}</div>'
                f'<div style="font-size:12px;font-weight:600;color:var(--text-1);margin-bottom:6px">{title}</div>'
                f'<div style="font-size:11px;color:var(--text-3);line-height:1.55">{desc}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # Sidebar call-to-action — draw attention to the panel
    st.markdown("""
    <div style="text-align:center;margin:2rem 0 1rem;
      font-size:12px;color:var(--text-3);letter-spacing:.03em">
      ← Use the <strong style="color:var(--text-2)">Settings panel</strong>
      on the left to configure test parameters, import real logs, and select your platform.
    </div>
    """, unsafe_allow_html=True)

    # If run pressed from home page, push data to sidebar state and re-run through main logic
    if run_home and rule_text_home.strip():
        st.session_state["_pending_rule"]     = rule_text_home
        st.session_state["_pending_platform"] = platform_home
        st.rerun()

    st.stop()

# ── Metrics shorthand ─────────────────────────────────────────────────────────
m     = metrics
cm    = m.get("confusion_matrix", {})
grade = m.get("overall_grade", "F")
gc    = GRADE_COLORS.get(grade, "#94a3b8")
pct   = lambda v: f"{v:.1%}"

critical_recs = sum(1 for r in recommendations if r["priority"] in ("critical", "high"))

# ── Hero strip ────────────────────────────────────────────────────────────────
pmeta = PLATFORM_META.get(platform, {})
st.markdown(f"""<div class="card card-blue" style="display:flex;align-items:center;gap:20px;padding:18px 24px;margin-bottom:16px">
  <div class="grade-badge grade-{grade}">{grade}</div>
  <div style="flex:1;min-width:0">
    <div style="font-size:20px;font-weight:800;color:#e8f0fe;margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
      {st.session_state.rule_name or 'Custom Rule'}
    </div>
    <div style="font-size:11px;color:#3a5070;margin-bottom:8px">
      {pmeta.get('icon','')} {platform} · {parsed_rule.get('format','') if parsed_rule else ''} · 
      {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} · {m.get('total_events',0)} events
      {f' · <span style="color:#2dd4bf">{imported_in_results} real</span>' if imported_in_results else ''}
    </div>
    <div>
      {pill(parsed_rule.get('format','generic'),'blue') if parsed_rule else ''}
      {pill(pmeta.get('lang','custom'),'purple')}
      {pill(platform,'gray')}
      {''.join(pill(t,'amber') for t in (parsed_rule.get('mitre',[]) if parsed_rule else []))}
      {pill(f'{critical_recs} recs need attention','red') if critical_recs > 0 else pill('all checks passed','green')}
    </div>
  </div>
  <div style="display:flex;gap:10px;flex-shrink:0;flex-wrap:wrap">
    {''.join(f'<div style="text-align:center;background:{c}10;border:1px solid {c}30;border-radius:10px;padding:10px 14px"><div style="font-size:26px;font-weight:900;color:{c};line-height:1">{v}</div><div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2a3a50;margin-top:3px">{l}</div></div>' for l,c,v in [("Passed","#10b981",m.get("total_passed",0)),("Failed","#ef4444",m.get("total_failed",0)),("Events","#06b6d4",m.get("total_events",0))])}
  </div>
</div>""", unsafe_allow_html=True)

# ── Tabs ───────────────────────────────────────────────────────────────────────
t_over, t_matrix, t_recs, t_fn, t_fp, t_ev, t_log, t_rule = st.tabs([
    "📊 Overview", "🧪 Test Matrix", "🔧 Recommendations",
    "🔴 False Negatives", "🟡 False Positives",
    "🥷 Evasion", "📋 Event Log", "🔍 Rule",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB: OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
with t_over:
    # Metrics row
    col_m = st.columns(5)
    for col, (label, val, color, sub) in zip(col_m, [
        ("Precision",          m.get("precision",0),          "#10b981", "Alerts that are real threats"),
        ("Recall",             m.get("recall",0),             "#10b981", "Real threats caught"),
        ("F1 Score",           m.get("f1_score",0),           "#8b5cf6", "Harmonic mean"),
        ("Evasion Resistance", m.get("evasion_resistance",0), "#f59e0b", f'{m.get("evasion_caught",0)}/{m.get("evasion_total",0)} variants caught'),
        ("Composite Score",    m.get("composite_score",0),    gc,        f'Grade {grade}'),
    ]):
        with col:
            st.markdown(metric_card(label, pct(val), color, sub), unsafe_allow_html=True)

    st.divider()

    # Confusion matrix + category breakdown
    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown('<div class="section-title">Confusion Matrix</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">'
            f'{cm_cell("True Positives",  cm.get("TP",0), "cm-tp")}'
            f'{cm_cell("True Negatives",  cm.get("TN",0), "cm-tn")}'
            f'{cm_cell("False Positives", cm.get("FP",0), "cm-fp")}'
            f'{cm_cell("False Negatives", cm.get("FN",0), "cm-fn")}'
            f'</div>', unsafe_allow_html=True,
        )

    with c2:
        st.markdown('<div class="section-title">Category Breakdown</div>', unsafe_allow_html=True)
        for cat_name, cat_data in m.get("category_breakdown", {}).items():
            color_map = {
                "true_positive": "#10b981", "true_negative": "#06b6d4",
                "fp_candidate": "#f59e0b", "evasion": "#8b5cf6",
            }
            cc = color_map.get(cat_name, "#94a3b8")
            st.markdown(f"""<div class="card" style="padding:12px 16px;margin-bottom:8px">
              <div style="display:flex;align-items:center;justify-content:space-between">
                <div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:{cc}">{cat_name.replace('_',' ')}</div>
                <div style="font-size:18px;font-weight:800;color:{cc}">{cat_data['passed']}/{cat_data['total']}</div>
              </div>
              {pbar(cat_data['pass_rate'], cc)}
              <div style="font-size:10px;color:#2a3a50;margin-top:4px">{cat_data['pass_rate']:.0%} pass rate</div>
            </div>""", unsafe_allow_html=True)

    # KB status bar
    if kb_loaded:
        dp = get_kb_detection_patterns(kb)
        st.markdown(f"""<div class="card card-teal" style="padding:12px 18px;margin-top:4px">
          <div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#2dd4bf;margin-bottom:6px">
            Knowledge Base Loaded — {platform}</div>
          <div style="font-size:11px;color:#4a6080;line-height:1.7">
            {len(dp)} detection patterns · {len(get_kb_evasion_guidance(kb))} evasion tips · 
            {len(get_kb_field_schema(kb, platform))} schema fields · 
            {len(get_kb_tuning_guidelines(kb).get('fpr',[]))} FP-reduction guidelines
          </div>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: TEST MATRIX
# ══════════════════════════════════════════════════════════════════════════════
with t_matrix:
    phases = [
        (1, "True Positive Generation",     "#10b981", "🎯", "true_positive",
         "Synthetic malicious events that should trigger the rule."),
        (2, "Evasion & False Negative Test", "#8b5cf6", "🥷", "evasion",
         "Adversary-realistic bypass attempts to stress-test detection coverage."),
        (3, "False Positive Stress Test",    "#f59e0b", "⚠️", "fp_candidate",
         "Tricky benign events that partially match rule conditions."),
        (4, "True Negative Baseline",        "#06b6d4", "✅", "true_negative",
         "Normal activity that must not fire the rule."),
    ]
    for ph, title, color, icon, cat, desc in phases:
        cat_results = [r for r in results if r.event.category.value == cat]
        passed = sum(1 for r in cat_results if r.passed)
        rate   = passed / len(cat_results) if cat_results else 0
        st.markdown(f"""<div class="card" style="border-color:{color}30;box-shadow:0 0 16px {color}08;margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:14px;margin-bottom:10px">
            <div style="width:36px;height:36px;border-radius:10px;background:{color}18;border:1px solid {color}30;
              display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0">{icon}</div>
            <div style="flex:1">
              <div style="font-size:9px;color:#2a3a50;letter-spacing:2px;text-transform:uppercase">Phase {ph}</div>
              <div style="font-size:14px;font-weight:700;color:#e2e8f0">{title}</div>
            </div>
            <div style="text-align:right">
              <div style="font-size:22px;font-weight:900;color:{color}">{passed}/{len(cat_results)}</div>
              <div style="font-size:9px;color:#2a3a50">passed</div>
            </div>
          </div>
          {pbar(rate, color)}
          <div style="font-size:11px;color:#4a6080;line-height:1.7;margin-top:10px">{desc}</div>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: RECOMMENDATIONS  (primary new feature)
# ══════════════════════════════════════════════════════════════════════════════
with t_recs:
    if not recommendations:
        st.markdown("""<div class="card card-green" style="text-align:center;padding:40px">
          <div style="font-size:30px;margin-bottom:10px">✅</div>
          <div style="font-size:16px;font-weight:700;color:#10b981">No issues found</div>
          <div style="font-size:12px;color:#3a5070;margin-top:6px">
            Run validation to generate KB-grounded recommendations.</div>
        </div>""", unsafe_allow_html=True)
    else:
        pri_colors = {
            "critical": "#ef4444", "high": "#f97316",
            "medium": "#f59e0b", "low": "#10b981", "info": "#06b6d4",
        }
        # Summary banner
        counts = {}
        for r in recommendations:
            counts[r["priority"]] = counts.get(r["priority"], 0) + 1
        def _pill_for_priority(p, c):
            clr = pri_colors.get(p, "#64748b")
            return f'<span class="pill" style="background:{clr}15;color:{clr};border:1px solid {clr}40">{c} {p}</span>'
        summary_pills = " ".join(_pill_for_priority(p, c) for p, c in counts.items())
        st.markdown(f"""<div class="card card-blue" style="padding:12px 18px;margin-bottom:16px">
          <div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#4a6080;margin-bottom:8px">
            Recommendations Summary — {len(recommendations)} total</div>
          <div>{summary_pills}</div>
          {'<div style="font-size:11px;color:#ef4444;margin-top:8px">⚠ Address critical/high items before production deployment.</div>' if critical_recs > 0 else '<div style="font-size:11px;color:#10b981;margin-top:8px">✓ No critical issues found.</div>'}
        </div>""", unsafe_allow_html=True)

        for idx, rec in enumerate(recommendations):
            c = pri_colors.get(rec["priority"], "#94a3b8")
            src_tag = f'<span style="font-size:9px;color:var(--text-3);float:right">source: {rec["source"]}</span>' \
                      if rec.get("source") else ""
            with st.expander(f"{rec['title']}"):
                st.markdown(f"""<div class="rec-card" style="border-left-color:{c}">
                  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
                    <span style="font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
                      padding:2px 8px;border-radius:4px;background:{c}18;color:{c};border:1px solid {c}35">
                      {rec['priority'].upper()}</span>
                    {src_tag}
                  </div>
                  <div style="font-size:12px;color:var(--text-2);line-height:1.8;margin-bottom:12px">{rec['body']}</div>
                  <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:10px 14px;
                    border-left:2px solid {c}55">
                    <div style="font-size:9px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;
                      color:{c};margin-bottom:4px">RECOMMENDED FIX</div>
                    <div style="font-size:12px;color:var(--text-2);line-height:1.7">{rec['fix']}</div>
                  </div>
                </div>""", unsafe_allow_html=True)
                # AI rule generator — one per recommendation
                render_rule_generator(rec, parsed_rule, rule_text, platform, metrics, idx)


# ══════════════════════════════════════════════════════════════════════════════
# TAB: FALSE NEGATIVES
# ══════════════════════════════════════════════════════════════════════════════
with t_fn:
    fn_list = [r for r in results if r.outcome == "FN"]
    if not fn_list:
        st.markdown("""<div class="card card-green" style="text-align:center;padding:32px">
          <div style="font-size:28px">✅</div>
          <div style="color:#10b981;font-weight:700;margin-top:8px">Zero False Negatives</div>
          <div style="color:#3a5070;font-size:12px;margin-top:4px">
            All attack events were correctly detected.</div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""<div class="card card-amber" style="padding:12px 18px;margin-bottom:12px">
          <span style="color:#f59e0b;font-weight:700">{len(fn_list)} False Negative(s)</span>
          <span style="color:#4a6080;font-size:11px;margin-left:8px">
            — rule missed {len(fn_list)} attack event(s) · Recall: {pct(m.get('recall',0))}</span>
        </div>""", unsafe_allow_html=True)
        for r in fn_list:
            is_real = "imported" in (r.event.tags or [])
            real_tag = " · <span style='color:#2dd4bf;font-size:10px'>REAL LOG</span>" if is_real else ""
            with st.expander(f"🔴  {r.event.event_id} — {r.event.description[:70]}"):
                st.markdown(f"""<div class="finding finding-fn">
                  <div style="font-size:9px;letter-spacing:2px;color:#f59e0b;text-transform:uppercase;margin-bottom:8px">
                    Why it was missed{real_tag}</div>
                  <div style="font-size:12px;color:#94a3b8;line-height:1.7">
                    Matched {len(r.detection.matched_conditions)} of {len(parsed_rule.get('conditions',[]) if parsed_rule else [])} conditions.<br>
                    {f'Matched: {", ".join(r.detection.matched_conditions[:4])}' if r.detection.matched_conditions else 'No conditions matched.'}
                  </div>
                  <div style="font-size:11px;color:#3a5070;margin-top:8px">
                    💡 {r.event.notes or 'Add a broader OR condition or check OriginalFileName for this variant.'}
                  </div>
                </div>""", unsafe_allow_html=True)
                st.code(json.dumps(r.event.log_data, indent=2), language="json")


# ══════════════════════════════════════════════════════════════════════════════
# TAB: FALSE POSITIVES
# ══════════════════════════════════════════════════════════════════════════════
with t_fp:
    fp_list = [r for r in results if r.outcome == "FP"]
    if not fp_list:
        st.markdown("""<div class="card card-green" style="text-align:center;padding:32px">
          <div style="font-size:28px">✅</div>
          <div style="color:#10b981;font-weight:700;margin-top:8px">Zero False Positives</div>
          <div style="color:#3a5070;font-size:12px;margin-top:4px">
            Rule did not fire on any benign activity.</div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""<div class="card card-red" style="padding:12px 18px;margin-bottom:12px">
          <span style="color:#ef4444;font-weight:700">{len(fp_list)} False Positive(s)</span>
          <span style="color:#4a6080;font-size:11px;margin-left:8px">
            — rule misfired on {len(fp_list)} benign event(s) · Precision: {pct(m.get('precision',0))}</span>
        </div>""", unsafe_allow_html=True)
        for r in fp_list:
            is_real = "imported" in (r.event.tags or [])
            real_tag = " · <span style='color:#2dd4bf;font-size:10px'>REAL LOG</span>" if is_real else ""
            with st.expander(f"⚠️  {r.event.event_id} — {r.event.description[:70]}"):
                st.markdown(f"""<div class="finding finding-fp">
                  <div style="font-size:9px;letter-spacing:2px;color:#ef4444;text-transform:uppercase;margin-bottom:8px">
                    Why it fired{real_tag}</div>
                  <div style="font-size:12px;color:#94a3b8;line-height:1.7">
                    Triggered by: {', '.join(r.detection.matched_conditions[:4]) or 'unknown conditions'}
                  </div>
                  <div style="font-size:11px;color:#3a5070;margin-top:8px">
                    💡 Add allowlist filter for this field value or narrow the triggering condition.</div>
                </div>""", unsafe_allow_html=True)
                st.code(json.dumps(r.event.log_data, indent=2), language="json")


# ══════════════════════════════════════════════════════════════════════════════
# TAB: EVASION
# ══════════════════════════════════════════════════════════════════════════════
with t_ev:
    ev_results = [r for r in results if r.event.category == dv.EventCategory.EVASION]
    caught   = sum(1 for r in ev_results if r.passed)
    bypassed = len(ev_results) - caught
    erate    = m.get("evasion_resistance", 0)

    st.markdown(f"""<div class="card card-purple" style="padding:12px 18px;margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:20px">
        <div><div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#8b5cf6">Evasion Resistance</div>
             <div style="font-size:28px;font-weight:900;color:#a78bfa">{pct(erate)}</div></div>
        <div style="flex:1">{pbar(erate, '#8b5cf6')}</div>
        <div style="text-align:right;font-size:11px;color:#4a6080">
          {caught} caught · {bypassed} bypassed · {len(ev_results)} total</div>
      </div>
    </div>""", unsafe_allow_html=True)

    for r in ev_results:
        success = r.passed
        c = "#10b981" if success else "#ef4444"
        icon = "✅" if success else "❌"
        with st.expander(f"{icon}  {r.event.event_id} — {r.event.description}"):
            st.markdown(f"""<div class="finding finding-ev">
              <div style="font-size:9px;letter-spacing:2px;color:#8b5cf6;text-transform:uppercase;margin-bottom:8px">
                {'Detected — evasion caught' if success else 'BYPASSED — rule evaded'}</div>
              <div style="font-size:12px;color:#94a3b8;line-height:1.7">
                {f'Matched: {", ".join(r.detection.matched_conditions[:4])}' if r.detection.matched_conditions else 'No conditions matched this evasion variant.'}
              </div>
              {'<div style="font-size:11px;color:#ef4444;margin-top:8px">⚠ Risk: attacker can evade this rule using this technique. See Recommendations tab for fixes.</div>' if not success else ''}
              {f'<div style="font-size:11px;color:#4a6080;margin-top:6px">KB note: {r.event.notes}</div>' if r.event.notes else ''}
            </div>""", unsafe_allow_html=True)
            st.code(json.dumps(r.event.log_data, indent=2), language="json")


# ══════════════════════════════════════════════════════════════════════════════
# TAB: EVENT LOG
# ══════════════════════════════════════════════════════════════════════════════
with t_log:
    # Filter controls
    fc1, fc2, fc3 = st.columns([2, 2, 1])
    with fc1:
        cat_filter = st.selectbox(
            "Filter by category",
            ["All"] + [c.value for c in dv.EventCategory],
            label_visibility="collapsed",
        )
    with fc2:
        outcome_filter = st.selectbox(
            "Filter by outcome",
            ["All", "TP", "FP", "TN", "FN"],
            label_visibility="collapsed",
        )
    with fc3:
        source_filter = st.selectbox(
            "Source",
            ["All", "Synthetic", "Real"],
            label_visibility="collapsed",
        )

    filtered = results
    if cat_filter != "All":
        filtered = [r for r in filtered if r.event.category.value == cat_filter]
    if outcome_filter != "All":
        filtered = [r for r in filtered if r.outcome == outcome_filter]
    if source_filter == "Synthetic":
        filtered = [r for r in filtered if "imported" not in (r.event.tags or [])]
    elif source_filter == "Real":
        filtered = [r for r in filtered if "imported" in (r.event.tags or [])]

    st.markdown(f'<div style="font-size:11px;color:#2a3a50;margin-bottom:8px">{len(filtered)} events</div>',
                unsafe_allow_html=True)

    # Table header
    st.markdown("""<div style="display:grid;grid-template-columns:70px 90px 1fr 100px 70px 60px;
      gap:8px;padding:8px 14px;border-bottom:1px solid rgba(255,255,255,.06);
      background:rgba(255,255,255,.02);border-radius:8px 8px 0 0">
      <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2a3a50">ID</div>
      <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2a3a50">Category</div>
      <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2a3a50">Description</div>
      <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2a3a50">Conf</div>
      <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2a3a50">Outcome</div>
      <div style="font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#2a3a50">Source</div>
    </div>""", unsafe_allow_html=True)

    outcome_colors = {"TP": "#10b981", "TN": "#06b6d4", "FP": "#ef4444", "FN": "#f59e0b"}
    cat_colors = {
        "true_positive": "green", "true_negative": "blue",
        "fp_candidate": "amber", "evasion": "purple",
    }
    for r in filtered[:200]:
        oc = outcome_colors.get(r.outcome, "#64748b")
        is_real = "imported" in (r.event.tags or [])
        real_html = '<span class="real-badge">REAL</span>' if is_real else ""
        with st.expander(f"{r.event.event_id}  ·  {r.event.description[:65]}"):
            st.markdown(f"""<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">
              {pill(r.event.category.value.replace('_',' '), cat_colors.get(r.event.category.value,'gray'))}
              <span style="font-size:10px;font-weight:800;color:{oc};
                background:{oc}18;border:1px solid {oc}40;padding:2px 8px;border-radius:4px">{r.outcome}</span>
              <span style="font-size:10px;color:#4a6080">conf: {r.detection.confidence_score:.2f}</span>
              {real_html}
            </div>
            <div style="font-size:10px;color:#4a6080;margin-bottom:8px;line-height:1.6">
              Matched: {', '.join(r.detection.matched_conditions[:5]) or 'none'}</div>""",
                unsafe_allow_html=True)
            st.code(json.dumps(r.event.log_data, indent=2), language="json")

    if len(filtered) > 200:
        st.caption(f"Showing 200 of {len(filtered)} — use JSON export for full dataset.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB: RULE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
with t_rule:
    if not parsed_rule:
        st.info("No rule parsed yet.")
    else:
        r1, r2 = st.columns([1, 1])
        with r1:
            st.markdown('<div class="section-title">Parsed Conditions</div>', unsafe_allow_html=True)
            for c in parsed_rule.get("conditions", []):
                st.markdown(f"""<div class="card" style="padding:8px 12px;margin-bottom:6px;font-family:monospace">
                  <span style="color:#22d3ee">{c['field']}</span>
                  <span style="color:#8b5cf6;margin:0 8px">{c['op']}</span>
                  <span style="color:#fbbf24">'{c['value'][:50]}'</span>
                </div>""", unsafe_allow_html=True)
            st.markdown(
                f'<div style="font-size:11px;color:#3a5070;margin-top:8px">'
                f'Logic combinator: <strong style="color:#06b6d4">{parsed_rule.get("logic","AND")}</strong></div>',
                unsafe_allow_html=True,
            )

        with r2:
            st.markdown('<div class="section-title">Filters / Allowlist</div>', unsafe_allow_html=True)
            filters = parsed_rule.get("filters", [])
            if filters:
                for f in filters:
                    st.markdown(f"""<div class="card card-red" style="padding:8px 12px;margin-bottom:6px;font-family:monospace">
                      <span style="color:#f87171">NOT </span>
                      <span style="color:#22d3ee">{f['field']}</span>
                      <span style="color:#8b5cf6;margin:0 8px">{f['op']}</span>
                      <span style="color:#fbbf24">'{f['value'][:50]}'</span>
                    </div>""", unsafe_allow_html=True)
            else:
                st.markdown('<div class="card card-amber" style="padding:10px 14px;font-size:12px;color:#f59e0b">'
                            '⚠ No exclusion filters found — consider adding allowlist conditions.</div>',
                            unsafe_allow_html=True)

            st.markdown('<div class="section-title" style="margin-top:16px">Raw Rule Text</div>',
                        unsafe_allow_html=True)
            st.code(rule_text, language="yaml" if parsed_rule.get("format") == "Sigma" else "sql")

        # KB detection patterns comparison
        if kb_loaded:
            dp = get_kb_detection_patterns(kb)
            if dp:
                st.markdown('<div class="section-title" style="margin-top:16px">KB Detection Pattern Examples</div>',
                            unsafe_allow_html=True)
                for pat_name, pat_data in list(dp.items())[:4]:
                    desc = pat_data.get("description", "") if isinstance(pat_data, dict) else str(pat_data)[:200]
                    mitre = pat_data.get("mitre_attack", {}).get("technique_ids", []) if isinstance(pat_data, dict) else []
                    with st.expander(f"📋  {pat_name.replace('_', ' ').title()}"):
                        st.markdown(f"""<div style="font-size:12px;color:#8096b0;line-height:1.7;margin-bottom:8px">{desc[:400]}</div>
                          <div>{''.join(pill(t,'red') for t in mitre[:4])}</div>""",
                                    unsafe_allow_html=True)
                        # Show example query if available
                        for q_field in ("kql", "query", "asq", "s1ql", "oql"):
                            if isinstance(pat_data, dict) and q_field in pat_data:
                                st.code(str(pat_data[q_field])[:600],
                                        language="sql" if q_field != "kql" else "kusto")
                                break


# ═══════════════════════════════════════════════════════════════════════════════
# BOTTOM BAR — export actions
# ═══════════════════════════════════════════════════════════════════════════════
st.divider()
ba1, ba2, ba3, ba4, ba5 = st.columns([2, 2, 2, 2, 2])

with ba1:
    if st.session_state.html_report:
        show_popup_button(st.session_state.html_report, st.session_state.rule_name or "Rule")

with ba2:
    if st.session_state.html_report:
        st.download_button(
            "⬇  Download HTML Report",
            data=st.session_state.html_report,
            file_name=f"validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            mime="text/html",
            use_container_width=True,
        )

with ba3:
    if results:
        json_payload = json.dumps({
            "rule_name":       st.session_state.rule_name,
            "platform":        platform,
            "generated_at":    datetime.datetime.utcnow().isoformat(),
            "metrics":         metrics,
            "recommendations": recommendations,
            "parsed_rule":     parsed_rule,
            "imported_events": imported_in_results,
            "events": [{
                "event_id":           r.event.event_id,
                "category":           r.event.category.value,
                "description":        r.event.description,
                "outcome":            r.outcome,
                "passed":             r.passed,
                "matched":            r.detection.matched,
                "matched_conditions": r.detection.matched_conditions,
                "confidence":         r.detection.confidence_score,
                "source":             "real" if "imported" in (r.event.tags or []) else "synthetic",
                "log_data":           r.event.log_data,
            } for r in results],
        }, indent=2)
        st.download_button(
            "⬇  Export JSON",
            data=json_payload,
            file_name=f"validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

with ba4:
    if results:
        csv_data = build_csv_export(results, metrics, recommendations)
        st.download_button(
            "⬇  Export CSV",
            data=csv_data,
            file_name=f"validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

with ba5:
    if results:
        st.markdown(
            f"<div style='font-size:11px;color:#2a3a50;padding:12px 4px'>"
            f"Grade <strong style='color:{gc}'>{grade}</strong> &nbsp;·&nbsp; "
            f"Score {m['composite_score']:.0%} &nbsp;·&nbsp; "
            f"{m['total_events']} events"
            f"{f' · <span style=\"color:#2dd4bf\">{imported_in_results} real</span>' if imported_in_results else ''}"
            f" &nbsp;·&nbsp; {len(recommendations)} recs"
            f"</div>",
            unsafe_allow_html=True,
        )
