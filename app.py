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

import csv
import datetime
import importlib.util
import io
import json
import re
import streamlit as st
import streamlit.components.v1 as components
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Detection Rule Validator",
    page_icon="⚔️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════════
# THEME / CSS
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box}
html,body,[class*="css"]{font-family:'Outfit',sans-serif;background:#060810;color:#c4cfe0}
.stApp{
  background-color:#060810;
  background-image:linear-gradient(rgba(6,182,212,.02)1px,transparent 1px),
    linear-gradient(90deg,rgba(6,182,212,.02)1px,transparent 1px);
  background-size:40px 40px;
}
section[data-testid="stSidebar"]{background:#07090f!important;border-right:1px solid #0d1625}
section[data-testid="stSidebar"]>div{padding-top:1rem}
#MainMenu,footer,header{visibility:hidden}
.block-container{padding:1.2rem 1.8rem 3rem;max-width:1480px}
h1,h2,h3,h4{font-family:'Outfit',sans-serif!important;color:#e8f0fe!important}

/* Cards */
.card{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:18px 20px;margin-bottom:10px}
.card-blue{border-color:rgba(6,182,212,.3);box-shadow:0 0 16px rgba(6,182,212,.06)}
.card-green{border-color:rgba(16,185,129,.3);box-shadow:0 0 16px rgba(16,185,129,.06)}
.card-red{border-color:rgba(239,68,68,.3);box-shadow:0 0 16px rgba(239,68,68,.06)}
.card-amber{border-color:rgba(245,158,11,.3);box-shadow:0 0 16px rgba(245,158,11,.06)}
.card-purple{border-color:rgba(139,92,246,.3);box-shadow:0 0 16px rgba(139,92,246,.06)}
.card-teal{border-color:rgba(20,184,166,.3);box-shadow:0 0 16px rgba(20,184,166,.06)}

/* Grade badge */
.grade-badge{display:inline-flex;align-items:center;justify-content:center;width:88px;height:88px;border-radius:50%;font-size:42px;font-weight:900;border:3px solid}
.grade-A{color:#10b981;border-color:#10b981;box-shadow:0 0 28px rgba(16,185,129,.3)}
.grade-B{color:#06b6d4;border-color:#06b6d4;box-shadow:0 0 28px rgba(6,182,212,.3)}
.grade-C{color:#f59e0b;border-color:#f59e0b;box-shadow:0 0 28px rgba(245,158,11,.3)}
.grade-D{color:#f97316;border-color:#f97316;box-shadow:0 0 28px rgba(249,115,22,.3)}
.grade-F{color:#ef4444;border-color:#ef4444;box-shadow:0 0 28px rgba(239,68,68,.3)}

/* Typography */
.metric-num{font-size:32px;font-weight:800;line-height:1}
.metric-label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#4a6080;margin-bottom:4px}
.metric-sub{font-size:11px;color:#3a5070;margin-top:4px}
.section-title{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#4a6080;font-weight:600;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid rgba(255,255,255,.04)}

/* Progress bar */
.prog-track{background:rgba(255,255,255,.05);border-radius:100px;height:6px;overflow:hidden;margin:6px 0}
.prog-fill{height:100%;border-radius:100px}

/* Confusion matrix */
.cm-cell{border-radius:10px;padding:16px 10px;text-align:center}
.cm-tp{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.25)}
.cm-tn{background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.2)}
.cm-fp{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2)}
.cm-fn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2)}

/* Pills */
.pill{display:inline-block;padding:2px 9px;border-radius:100px;font-size:9px;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin:2px 3px 2px 0}
.pill-blue{background:rgba(6,182,212,.12);color:#22d3ee;border:1px solid rgba(6,182,212,.3)}
.pill-green{background:rgba(16,185,129,.12);color:#34d399;border:1px solid rgba(16,185,129,.3)}
.pill-red{background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.pill-amber{background:rgba(245,158,11,.1);color:#fbbf24;border:1px solid rgba(245,158,11,.3)}
.pill-purple{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.3)}
.pill-teal{background:rgba(20,184,166,.1);color:#2dd4bf;border:1px solid rgba(20,184,166,.25)}
.pill-gray{background:rgba(148,163,184,.08);color:#64748b;border:1px solid rgba(148,163,184,.15)}

/* Findings */
.finding{background:rgba(255,255,255,.018);border-left:3px solid;border-radius:0 10px 10px 0;padding:12px 16px;margin:6px 0}
.finding-fn{border-left-color:#f59e0b}
.finding-fp{border-left-color:#ef4444}
.finding-ev{border-left-color:#8b5cf6}

/* Recommendations */
.rec-card{background:rgba(255,255,255,.02);border-left:3px solid;border-radius:0 10px 10px 0;padding:14px 18px;margin:8px 0}
.rec-critical{border-left-color:#ef4444}
.rec-high{border-left-color:#f97316}
.rec-medium{border-left-color:#f59e0b}
.rec-low{border-left-color:#10b981}
.rec-info{border-left-color:#06b6d4}

/* Real log badge */
.real-badge{font-size:9px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#2dd4bf;
            background:rgba(20,184,166,.08);border:1px solid rgba(20,184,166,.2);border-radius:4px;padding:1px 5px;margin-left:6px}

/* Streamlit overrides */
.stTextArea textarea{background:rgba(255,255,255,.03)!important;border:1px solid rgba(255,255,255,.08)!important;
  color:#c4cfe0!important;font-family:'JetBrains Mono',monospace!important;font-size:11.5px!important;border-radius:8px!important}
.stTextArea textarea:focus{border-color:rgba(6,182,212,.4)!important;box-shadow:0 0 0 2px rgba(6,182,212,.1)!important}
.stSelectbox>div>div{background:rgba(255,255,255,.03)!important;border:1px solid rgba(255,255,255,.08)!important;
  color:#c4cfe0!important;border-radius:8px!important}
.stMultiSelect>div>div{background:rgba(255,255,255,.03)!important;border:1px solid rgba(255,255,255,.08)!important;border-radius:8px!important}
.stButton>button{background:linear-gradient(135deg,#0e7490,#0891b2)!important;color:#e0f7fa!important;
  border:1px solid #06b6d4!important;font-family:'Outfit',sans-serif!important;font-weight:600!important;
  font-size:12px!important;letter-spacing:1.5px!important;text-transform:uppercase!important;
  border-radius:8px!important;padding:9px 22px!important;transition:all .2s!important}
.stButton>button:hover{background:linear-gradient(135deg,#0891b2,#06b6d4)!important;
  box-shadow:0 0 22px rgba(6,182,212,.4)!important;transform:translateY(-1px)!important}
.stTabs [data-baseweb="tab-list"]{background:transparent;gap:4px;border-bottom:1px solid rgba(255,255,255,.06)}
.stTabs [data-baseweb="tab"]{font-family:'Outfit',sans-serif;font-size:11px;font-weight:600;letter-spacing:1.5px;
  text-transform:uppercase;color:#4a6080!important;padding:9px 16px;border-radius:8px 8px 0 0}
.stTabs [aria-selected="true"]{color:#22d3ee!important;background:rgba(6,182,212,.08)!important;border-bottom:2px solid #06b6d4!important}
details>summary{background:rgba(255,255,255,.025)!important;border:1px solid rgba(255,255,255,.06)!important;
  border-radius:8px!important;padding:10px 14px!important;color:#94a3b8!important;font-size:12px!important;
  font-family:'Outfit',sans-serif!important;cursor:pointer}
details>summary:hover{border-color:rgba(6,182,212,.3)!important;color:#e2e8f0!important}
pre,code{font-family:'JetBrains Mono',monospace!important;background:rgba(255,255,255,.04)!important;
  color:#7dd3fc!important;font-size:11px!important;border:1px solid rgba(255,255,255,.06)!important}
hr{border-color:rgba(255,255,255,.05)!important}
.stFileUploader{background:rgba(255,255,255,.02)!important;border:1px solid rgba(255,255,255,.08)!important;border-radius:8px!important}
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

def _find_kb_path(filename: str) -> Path | None:
    """Search for KB file in multiple locations relative to this script."""
    candidates = [
        Path(__file__).parent / "knowledge_bases" / filename,
        Path(__file__).parent / filename,
        Path(__file__).parent / "guides" / filename,
        Path("knowledge_bases") / filename,
        Path(filename),
    ]
    # Also try partial filename match (handles timestamp-prefixed files)
    stem = Path(filename).stem  # e.g. "armis_centrix_knowledge_base"
    for p in Path(__file__).parent.rglob("*.json"):
        if stem in p.stem:
            candidates.insert(0, p)
    for c in candidates:
        if c.exists():
            return c
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
    spec = importlib.util.spec_from_file_location(
        "detection_validator",
        Path(__file__).parent / "detection_validator.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


try:
    dv = load_framework()
except Exception as e:
    st.error(f"❌ Cannot load detection_validator.py — {e}")
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
                case "gte":
                    try: return float(event.get(f, 0)) >= float(v)
                    except: return False
                case "lt":           return self.field_lt(event, f, float(v))
                case "lte":
                    try: return float(event.get(f, 0)) <= float(v)
                    except: return False
                case _:              return self.field_contains(event, f, v)
        except Exception:
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
        ("case_manipulation",  lambda v: v.upper()    if isinstance(v, str) else v),
        ("env_variable_sub",   lambda v: v.replace(r"C:\Windows", "%SystemRoot%") if isinstance(v, str) else v),
        ("path_traversal",     lambda v: v.replace(r"\System32\\", r"\System32\..\System32\\") if isinstance(v, str) else v),
        ("double_extension",   lambda v: v + ".bak"  if isinstance(v, str) and ".exe" in v else v),
        ("syswow64_redirect",  lambda v: v.replace("System32", "SysWow64") if isinstance(v, str) else v),
        ("space_insertion",    lambda v: v.replace(".exe", " .exe") if isinstance(v, str) else v),
        ("b64_encoding",       lambda v: (
            "powershell.exe -enc " +
            __import__("base64").b64encode((v + " ").encode("utf-16-le")).decode()
        ) if isinstance(v, str) and len(v) < 80 else v),
        ("unicode_substitution", lambda v: v.replace("a", "\u0061").replace("e", "\u0065") if isinstance(v, str) and len(v) < 50 else v),
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
            warnings.append(f"Capped at 300 events (file had {len(events)}).")
            events = events[:300]
        return events, warnings


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

    if "case_manipulation" in str([r.event.tags for r in results]):
        add(
            "high",
            "🔡 Case-Sensitivity Bypass Risk",
            "One or more evasion variants used uppercase/lowercase manipulation to evade the rule.",
            f"Ensure all {fmt} conditions use case-insensitive comparison operators "
            "(e.g., `|contains` in Sigma, `has` in KQL, `ContainsCIS` in S1QL).",
            "evasion_analysis",
        )

    if "b64_encoding" in str([r.event.tags for r in results]):
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
    ) and any("sigma" in platform.lower() or "sentinelone" in platform.lower() for _ in [1]):
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
            ("Accuracy",           m["accuracy"],           "#06b6d4"),
            ("Precision",          m["precision"],          "#10b981"),
            ("Recall",             m["recall"],             "#10b981"),
            ("F1 Score",           m["f1_score"],           "#8b5cf6"),
            ("Evasion Resistance", m["evasion_resistance"], "#f59e0b"),
            ("Composite Score",    m["composite_score"],    gc),
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
    safe = html_content.replace("\\", "\\\\").replace("`", "\\`").replace("$", "\\$")
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
    <div class="topbar-title">📄 &nbsp;{rule_name[:70]}</div>
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
const HTML=`{safe}`;
function openReport(){{
  const overlay=document.getElementById('overlay');
  const frame=document.getElementById('rFrame');
  document.getElementById('loader').classList.remove('hidden');
  frame.srcdoc=HTML;
  try{{const blob=new Blob([HTML],{{type:'text/html'}});document.getElementById('dlLink').href=URL.createObjectURL(blob);}}catch(e){{}}
  overlay.classList.add('show');document.body.style.overflow='hidden';
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
    raw = float(value.strip("%")) / 100 if "%" in str(value) else 0
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
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""<div style="text-align:center;padding:8px 0 20px">
      <div style="font-size:22px;font-weight:900;letter-spacing:3px;text-transform:uppercase;
        background:linear-gradient(135deg,#06b6d4,#8b5cf6);-webkit-background-clip:text;
        -webkit-text-fill-color:transparent">⚔ DVT v6</div>
      <div style="font-size:9px;color:#2a3a50;letter-spacing:2px;margin-top:2px">DETECTION VALIDATOR</div>
    </div>""", unsafe_allow_html=True)

    # ── Platform selection ────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Target Platform</div>', unsafe_allow_html=True)
    platform_options = list(PLATFORM_META.keys())
    platform = st.selectbox(
        "Platform",
        platform_options,
        index=platform_options.index(st.session_state.active_platform)
              if st.session_state.active_platform in platform_options else 0,
        label_visibility="collapsed",
    )
    st.session_state.active_platform = platform
    pmeta = PLATFORM_META[platform]

    # Load KB for selected platform
    kb = load_kb(platform)
    kb_loaded = bool(kb)

    st.markdown(f"""<div class="card" style="padding:10px 14px;margin-top:6px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:18px">{pmeta['icon']}</span>
        <div>
          <div style="font-size:11px;font-weight:700;color:{pmeta['color']}">{platform}</div>
          <div style="font-size:9px;color:#2a3a50">{pmeta['lang']} · {pmeta['log_source']}</div>
        </div>
        <div style="margin-left:auto">
          {'<span class="pill pill-green">KB ✓</span>' if kb_loaded else '<span class="pill pill-amber">KB ?</span>'}
        </div>
      </div>
      <div style="font-size:10px;color:#3a5070;margin-top:6px;line-height:1.5">{pmeta['desc']}</div>
    </div>""", unsafe_allow_html=True)

    if not kb_loaded:
        st.warning(
            f"KB file not found for {platform}.\n\n"
            f"Place `{pmeta['kb_file']}` in a `knowledge_bases/` subfolder "
            f"next to this script to enable KB-grounded recommendations.",
            icon="⚠️",
        )

    st.divider()

    # ── Rule input ────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Detection Rule</div>', unsafe_allow_html=True)
    rule_text = st.text_area(
        "Paste your detection rule",
        height=220,
        placeholder=(
            "Paste any detection rule:\n\n"
            "• Sigma (YAML)\n• S1QL\n• KQL / Cribl KQL\n"
            "• PAN-OS filter\n• ASQ (Armis)\n• OQL (Obsidian)\n• Okta EventHook\n\n"
            "Example (Sigma):\ntitle: Suspicious Rundll32\ndetection:\n"
            "  selection:\n    Image|endswith: '\\\\rundll32.exe'\n  condition: selection"
        ),
        label_visibility="collapsed",
    )

    # Show live parse preview
    if rule_text.strip():
        try:
            _preview = RuleParser.parse(rule_text, platform)
            st.markdown(
                f'<div style="font-size:10px;color:#10b981;padding:4px 0">'
                f'✓ {_preview["format"]} · {len(_preview["conditions"])} conditions · '
                f'{len(_preview["filters"])} filters · {_preview["logic"]} logic</div>',
                unsafe_allow_html=True,
            )
        except Exception:
            pass

    st.divider()

    # ── Test parameters ───────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Test Parameters</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        tp_count  = st.number_input("True Pos", min_value=1, max_value=50, value=10)
        fp_count  = st.number_input("FP Cand.",  min_value=0, max_value=20, value=5)
    with c2:
        tn_count  = st.number_input("True Neg", min_value=1, max_value=50, value=15)
        ev_count  = st.number_input("Evasion",  min_value=0, max_value=20, value=5)

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
        "⚔  RUN VALIDATION",
        use_container_width=True,
        disabled=run_disabled,
    )
    if run_disabled:
        st.caption("Paste a detection rule above to begin.")

    st.divider()

    # ── Demo ──────────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Demo</div>', unsafe_allow_html=True)
    demo_clicked = st.button("▶  Load Demo Rule", use_container_width=True)
    if demo_clicked:
        st.session_state["_demo_rule"] = """title: Suspicious Rundll32 Execution
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
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains:
      - 'javascript:'
      - 'vbscript:'
      - '..\\'
      - 'shell32.dll'
      - 'advpack.dll'
  filter_benign:
    CommandLine|contains:
      - 'shell32.dll,Control_RunDLL'
  condition: selection and not filter_benign
falsepositives:
  - Legitimate use of rundll32 for administrative purposes
level: medium"""
        st.rerun()

    if "_demo_rule" in st.session_state:
        rule_text = st.session_state["_demo_rule"]


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
    # ── Empty state ──────────────────────────────────────────────────────────
    st.markdown(f"""<div style="text-align:center;padding:80px 20px">
      <div style="font-size:50px;margin-bottom:20px">⚔️</div>
      <div style="font-size:24px;font-weight:800;color:#e8f0fe;margin-bottom:12px">
        Detection Rule Validator v6</div>
      <div style="font-size:14px;color:#3a5070;margin-bottom:24px;line-height:1.8">
        Paste your detection rule in the sidebar and click <strong style="color:#06b6d4">RUN VALIDATION</strong><br>
        Supports: Sigma · S1QL · KQL · PAN-OS · ASQ · OQL · Okta EventHook
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;max-width:700px;margin:0 auto 30px">
        {''.join(f'<div class="card" style="padding:14px;text-align:center"><div style="font-size:22px">{m["icon"]}</div><div style="font-size:11px;color:{m["color"]};font-weight:700;margin-top:6px">{p}</div><div style="font-size:9px;color:#2a3a50;margin-top:3px">{m["lang"]}</div></div>' for p, m in PLATFORM_META.items())}
      </div>
    </div>""", unsafe_allow_html=True)
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
        g1, g2, g3, g4 = st.columns(2), st.columns(2), None, None
        g1, g2 = st.columns(2), st.columns(2)
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

        for rec in recommendations:
            c = pri_colors.get(rec["priority"], "#94a3b8")
            src_tag = f'<span style="font-size:9px;color:#3a5070;float:right">source: {rec["source"]}</span>' \
                      if rec.get("source") else ""
            with st.expander(f"{rec['title']}"):
                st.markdown(f"""<div class="rec-card" style="border-left-color:{c}">
                  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
                    <span style="font-size:9px;font-weight:800;letter-spacing:1px;text-transform:uppercase;
                      padding:2px 8px;border-radius:4px;background:{c}20;color:{c};border:1px solid {c}40">
                      {rec['priority'].upper()}</span>
                    {src_tag}
                  </div>
                  <div style="font-size:12px;color:#8096b0;line-height:1.8;margin-bottom:12px">{rec['body']}</div>
                  <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:10px 14px;
                    border-left:2px solid {c}60">
                    <div style="font-size:9px;font-weight:800;letter-spacing:1px;text-transform:uppercase;
                      color:{c};margin-bottom:4px">RECOMMENDED FIX</div>
                    <div style="font-size:12px;color:#94a3b8;line-height:1.7">{rec['fix']}</div>
                  </div>
                </div>""", unsafe_allow_html=True)


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
