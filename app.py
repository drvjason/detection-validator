#!/usr/bin/env python3
"""
Detection Rule Validator — Streamlit UI v3
Supports: Sigma, KQL, SPL, EQL, Snort/Suricata, YARA-L, Custom
"""

import streamlit as st
import json, re, datetime, time, importlib.util, traceback
from pathlib import Path

# ─── Page config (must be first) ────────────────────────────────────────────
st.set_page_config(
    page_title="Detection Rule Validator",
    page_icon="⚔️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@300;400;500;600&display=swap');

*, *::before, *::after { box-sizing: border-box; }

html, body, [class*="css"] {
  font-family: 'Outfit', sans-serif;
  background: #060810;
  color: #c4cfe0;
}

.stApp {
  background-color: #060810;
  background-image:
    linear-gradient(rgba(6,182,212,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(6,182,212,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
}

section[data-testid="stSidebar"] {
  background: #080b12 !important;
  border-right: 1px solid #0f1a2e;
}
section[data-testid="stSidebar"] > div { padding-top: 1.5rem; }

#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1.5rem 2rem 3rem; max-width: 1400px; }

h1, h2, h3, h4 {
  font-family: 'Outfit', sans-serif !important;
  color: #e8f0fe !important;
}

.card {
  background: rgba(255,255,255,0.025);
  border: 1px solid rgba(255,255,255,0.06);
  border-radius: 12px;
  padding: 20px 22px;
  margin-bottom: 12px;
  backdrop-filter: blur(8px);
}
.card-glow-blue  { border-color: rgba(6,182,212,0.35); box-shadow: 0 0 20px rgba(6,182,212,0.08); }
.card-glow-green { border-color: rgba(16,185,129,0.35); box-shadow: 0 0 20px rgba(16,185,129,0.08); }
.card-glow-red   { border-color: rgba(239,68,68,0.35);  box-shadow: 0 0 20px rgba(239,68,68,0.08); }
.card-glow-amber { border-color: rgba(245,158,11,0.35); box-shadow: 0 0 20px rgba(245,158,11,0.08); }

.grade-badge {
  display: inline-flex; align-items: center; justify-content: center;
  width: 90px; height: 90px; border-radius: 50%;
  font-family: 'Outfit', sans-serif;
  font-size: 42px; font-weight: 900;
  border: 3px solid;
}
.grade-A { color: #10b981; border-color: #10b981; box-shadow: 0 0 30px rgba(16,185,129,0.3); }
.grade-B { color: #06b6d4; border-color: #06b6d4; box-shadow: 0 0 30px rgba(6,182,212,0.3); }
.grade-C { color: #f59e0b; border-color: #f59e0b; box-shadow: 0 0 30px rgba(245,158,11,0.3); }
.grade-D { color: #f97316; border-color: #f97316; box-shadow: 0 0 30px rgba(249,115,22,0.3); }
.grade-F { color: #ef4444; border-color: #ef4444; box-shadow: 0 0 30px rgba(239,68,68,0.3); }

.metric-num {
  font-family: 'Outfit', sans-serif;
  font-size: 36px; font-weight: 800; line-height: 1;
}
.metric-label {
  font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
  color: #4a6080; margin-bottom: 6px;
}
.metric-sub { font-size: 11px; color: #3a5070; margin-top: 6px; }

.prog-track {
  background: rgba(255,255,255,0.05);
  border-radius: 100px; height: 6px; overflow: hidden;
  margin: 8px 0;
}
.prog-fill { height: 100%; border-radius: 100px; }

.cm-cell {
  border-radius: 10px; padding: 18px 12px;
  text-align: center;
}
.cm-tp { background: rgba(16,185,129,0.1);  border: 1px solid rgba(16,185,129,0.25); }
.cm-tn { background: rgba(6,182,212,0.08);  border: 1px solid rgba(6,182,212,0.2); }
.cm-fp { background: rgba(239,68,68,0.08);  border: 1px solid rgba(239,68,68,0.2); }
.cm-fn { background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.2); }

.pill {
  display: inline-block; padding: 2px 10px; border-radius: 100px;
  font-size: 10px; font-weight: 600; letter-spacing: 1px;
  text-transform: uppercase; margin: 2px 3px 2px 0;
}
.pill-blue  { background: rgba(6,182,212,0.12);  color: #22d3ee; border: 1px solid rgba(6,182,212,0.3); }
.pill-green { background: rgba(16,185,129,0.12); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }
.pill-red   { background: rgba(239,68,68,0.12);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
.pill-amber { background: rgba(245,158,11,0.1);  color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }
.pill-gray  { background: rgba(148,163,184,0.08);color: #64748b; border: 1px solid rgba(148,163,184,0.15); }

.finding {
  background: rgba(255,255,255,0.018);
  border-left: 3px solid;
  border-radius: 0 10px 10px 0;
  padding: 14px 18px; margin: 8px 0;
}
.finding-fn { border-left-color: #f59e0b; }
.finding-fp { border-left-color: #ef4444; }
.finding-ev { border-left-color: #8b5cf6; }

.section-title {
  font-size: 10px; letter-spacing: 3px; text-transform: uppercase;
  color: #4a6080; font-weight: 600; margin-bottom: 16px;
  padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.04);
}

.delta-pos { color: #10b981; font-weight: 700; }
.delta-neg { color: #ef4444; font-weight: 700; }
.delta-neu { color: #64748b; }

.stTextArea textarea {
  background: rgba(255,255,255,0.03) !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  color: #c4cfe0 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 12px !important;
  border-radius: 8px !important;
}
.stTextArea textarea:focus {
  border-color: rgba(6,182,212,0.4) !important;
  box-shadow: 0 0 0 2px rgba(6,182,212,0.1) !important;
}
.stSelectbox > div > div {
  background: rgba(255,255,255,0.03) !important;
  border: 1px solid rgba(255,255,255,0.08) !important;
  color: #c4cfe0 !important; border-radius: 8px !important;
}
.stButton > button {
  background: linear-gradient(135deg, #0e7490, #0891b2) !important;
  color: #e0f7fa !important;
  border: 1px solid #06b6d4 !important;
  font-family: 'Outfit', sans-serif !important;
  font-weight: 600 !important; font-size: 13px !important;
  letter-spacing: 1.5px !important; text-transform: uppercase !important;
  border-radius: 8px !important; padding: 10px 24px !important;
  transition: all .2s ease !important;
}
.stButton > button:hover {
  background: linear-gradient(135deg, #0891b2, #06b6d4) !important;
  box-shadow: 0 0 20px rgba(6,182,212,0.35) !important;
  transform: translateY(-1px) !important;
}
.stTabs [data-baseweb="tab-list"] {
  background: transparent; gap: 4px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}
.stTabs [data-baseweb="tab"] {
  font-family: 'Outfit', sans-serif; font-size: 12px; font-weight: 600;
  letter-spacing: 1.5px; text-transform: uppercase;
  color: #4a6080 !important; padding: 10px 18px;
  border-radius: 8px 8px 0 0;
}
.stTabs [aria-selected="true"] {
  color: #22d3ee !important;
  background: rgba(6,182,212,0.08) !important;
  border-bottom: 2px solid #06b6d4 !important;
}
details > summary {
  background: rgba(255,255,255,0.025) !important;
  border: 1px solid rgba(255,255,255,0.06) !important;
  border-radius: 8px !important; padding: 10px 14px !important;
  color: #94a3b8 !important; font-size: 13px !important;
  font-family: 'Outfit', sans-serif !important; cursor: pointer;
}
details > summary:hover { border-color: rgba(6,182,212,0.3) !important; }
pre, code {
  font-family: 'JetBrains Mono', monospace !important;
  background: rgba(255,255,255,0.04) !important;
  color: #7dd3fc !important; font-size: 11px !important;
  border: 1px solid rgba(255,255,255,0.06) !important;
}
hr { border-color: rgba(255,255,255,0.05) !important; }
</style>
""", unsafe_allow_html=True)


# ─── Load framework ───────────────────────────────────────────────────────────
@st.cache_resource
def load_framework():
    spec = importlib.util.spec_from_file_location(
        "detection_validator", Path(__file__).parent / "detection_validator.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

try:
    dv = load_framework()
except Exception as e:
    st.error(f"Cannot load detection_validator.py — {e}")
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC RULE PARSER
# ═══════════════════════════════════════════════════════════════════════════════
class RuleParser:
    SIGMA_OP_MAP = {
        "contains": "contains", "contains|all": "contains_all",
        "startswith": "startswith", "endswith": "endswith",
        "equals": "equals", "re": "regex", "cidr": "cidr",
        "gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte",
    }

    @classmethod
    def parse(cls, text: str, fmt: str) -> dict:
        fmt = fmt.lower()
        if "sigma" in fmt:                     return cls._sigma(text)
        elif "kql" in fmt:                     return cls._kql(text)
        elif "spl" in fmt:                     return cls._spl(text)
        elif "eql" in fmt:                     return cls._eql(text)
        elif "snort" in fmt or "suricata" in fmt: return cls._snort(text)
        else:                                  return cls._generic(text)

    @classmethod
    def _sigma(cls, text: str) -> dict:
        try:
            import yaml as _yaml
            doc = _yaml.safe_load(text)
            if not isinstance(doc, dict):
                raise ValueError("Not a dict")
        except Exception:
            return cls._generic(text)

        title      = doc.get("title", "Sigma Rule")
        detection  = doc.get("detection", {})
        cond_str   = str(detection.get("condition", "selection"))
        logsource  = doc.get("logsource", {})
        log_src    = f"{logsource.get('category','')} {logsource.get('product','')}".strip()

        conditions, filters = [], []
        for sel_key, sel_body in detection.items():
            if sel_key == "condition":
                continue
            is_filter = sel_key.startswith("filter")
            if isinstance(sel_body, dict):
                for field_op, value in sel_body.items():
                    parts  = field_op.split("|")
                    field  = parts[0]
                    op_raw = "|".join(parts[1:]) if len(parts) > 1 else ""
                    op     = cls.SIGMA_OP_MAP.get(op_raw, "equals" if not op_raw else "contains")
                    vals   = value if isinstance(value, list) else [value]
                    for v in vals:
                        entry = {"field": field, "op": op, "value": str(v) if v is not None else ""}
                        (filters if is_filter else conditions).append(entry)
            elif isinstance(sel_body, list):
                for v in sel_body:
                    entry = {"field": "_raw", "op": "contains", "value": str(v)}
                    (filters if is_filter else conditions).append(entry)

        logic = "OR" if re.search(r'\bor\b', cond_str, re.I) else "AND"
        if re.search(r'\bnot\b', cond_str, re.I) and filters:
            logic = "AND_NOT_FILTER"

        return {"rule_name": title, "conditions": conditions, "filters": filters,
                "logic": logic, "log_source": log_src, "raw_condition": cond_str}

    @classmethod
    def _kql(cls, text: str) -> dict:
        conditions = []
        m0 = re.match(r'^\s*(\w+)', text)
        rule_name = f"KQL — {m0.group(1)}" if m0 else "KQL Rule"
        blocks = re.findall(r'\|\s*where\s+(.+?)(?=\n\s*\||\Z)', text, re.DOTALL | re.I)
        for block in blocks:
            for m in re.finditer(r'(\w+)\s*=~\s*["\']([^"\']+)["\']', block):
                conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
            for m in re.finditer(r'(\w+)\s+has_any\s*\(\s*([^)]+)\)', block, re.I):
                for v in re.findall(r'["\']([^"\']+)["\']', m.group(2)):
                    conditions.append({"field": m.group(1), "op": "contains", "value": v})
            for m in re.finditer(r'(\w+)\s+has\s+["\']([^"\']+)["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
            for m in re.finditer(r'(\w+)\s+startswith\s+["\']([^"\']+)["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "startswith", "value": m.group(2)})
            for m in re.finditer(r'(\w+)\s+endswith\s+["\']([^"\']+)["\']', block, re.I):
                conditions.append({"field": m.group(1), "op": "endswith", "value": m.group(2)})
            for m in re.finditer(r'(\w+)\s*==\s*["\']([^"\']+)["\']', block):
                conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        return {"rule_name": rule_name, "conditions": conditions, "filters": [],
                "logic": "AND", "log_source": ""}

    @classmethod
    def _spl(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'match\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)', text, re.I):
            conditions.append({"field": m.group(1), "op": "regex", "value": m.group(2)})
        for m in re.finditer(r'(\w+)\s*=\s*"([^"]+)"', text):
            if m.group(1).lower() not in ("index", "re"):
                conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'\|\s*search\s+"([^"]+)"', text, re.I):
            conditions.append({"field": "_raw", "op": "contains", "value": m.group(1)})
        return {"rule_name": "SPL Rule", "conditions": conditions, "filters": [],
                "logic": "OR", "log_source": ""}

    @classmethod
    def _eql(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'(\w+)\s*(?:==|:)\s*["\']([^"\']+)["\']', text):
            conditions.append({"field": m.group(1), "op": "equals", "value": m.group(2)})
        for m in re.finditer(r'(\w+)\s+like\s*~?\s*["\']([^"\']+)["\']', text, re.I):
            conditions.append({"field": m.group(1), "op": "contains", "value": m.group(2)})
        return {"rule_name": "EQL Rule", "conditions": conditions, "filters": [],
                "logic": "AND", "log_source": ""}

    @classmethod
    def _snort(cls, text: str) -> dict:
        conditions = []
        for m in re.finditer(r'content\s*:\s*"([^"]+)"', text, re.I):
            conditions.append({"field": "_payload", "op": "contains", "value": m.group(1)})
        for m in re.finditer(r'pcre\s*:\s*"/([^/]+)/', text, re.I):
            conditions.append({"field": "_payload", "op": "regex", "value": m.group(1)})
        rule_name = "Snort Rule"
        mn = re.search(r'msg\s*:\s*"([^"]+)"', text, re.I)
        if mn: rule_name = mn.group(1)
        return {"rule_name": rule_name, "conditions": conditions, "filters": [],
                "logic": "AND", "log_source": "network"}

    @classmethod
    def _generic(cls, text: str) -> dict:
        conditions = []
        skip = {"and","or","not","where","from","select","index","true","false",
                "null","by","on","in","as","if","then","else","when","case"}
        for m in re.finditer(r'(\b[A-Za-z_]\w*\b)\s*[=:]\s*["\']?([^\s"\'|&,\)\n]{2,60})["\']?', text):
            f, v = m.group(1), m.group(2)
            if f.lower() in skip or re.match(r'^\d+$', f):
                continue
            conditions.append({"field": f, "op": "contains", "value": v})
        return {"rule_name": "Custom Rule", "conditions": conditions[:12],
                "filters": [], "logic": "OR", "log_source": ""}


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
class DynamicEngine(dv.DetectionEngine):
    def __init__(self, parsed: dict):
        super().__init__(rule_name=parsed.get("rule_name", "Custom Rule"))
        self.conditions = parsed.get("conditions", [])
        self.filters    = parsed.get("filters", [])
        self.logic      = parsed.get("logic", "AND")

    def _eval_cond(self, event: dict, cond: dict) -> bool:
        field, op, value = cond["field"], cond["op"], cond["value"]
        try:
            if op == "equals":         return self.field_equals(event, field, value)
            elif op == "contains":     return self.field_contains(event, field, value)
            elif op == "startswith":   return self.field_startswith(event, field, value)
            elif op == "endswith":     return self.field_endswith(event, field, value)
            elif op == "regex":        return self.field_regex(event, field, value)
            elif op == "contains_all":
                return self.field_all_of(event, field, value.split("|"))
            elif op in ("gt","gte","lt","lte"):
                fv, tv = float(event.get(field, 0)), float(value)
                return {"gt":fv>tv,"gte":fv>=tv,"lt":fv<tv,"lte":fv<=tv}[op]
            else:
                return self.field_contains(event, field, value)
        except Exception:
            return False

    def evaluate(self, event: dict) -> dv.DetectionResult:
        if not self.conditions:
            return dv.DetectionResult(event_id="", matched=False,
                                      matched_conditions=[], confidence_score=0.0)
        hits, matched_conds = [], []
        for cond in self.conditions:
            hit = self._eval_cond(event, cond)
            hits.append(hit)
            if hit:
                matched_conds.append(f"{cond['field']}:{cond['op']}:{cond['value'][:25]}")

        filter_hit = any(self._eval_cond(event, f) for f in self.filters)

        if self.logic in ("AND", "AND_NOT_FILTER"):
            matched = all(hits) and not filter_hit
        else:
            matched = any(hits) and not filter_hit

        confidence = sum(hits) / len(hits) if hits else 0.0
        return dv.DetectionResult(event_id="", matched=matched,
                                  matched_conditions=matched_conds,
                                  confidence_score=round(confidence, 2))


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC TELEMETRY GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════
class DynamicGenerator(dv.TelemetryGenerator):
    _BENIGN = {
        "Image":              r"C:\Windows\System32\notepad.exe",
        "CommandLine":        "notepad.exe readme.txt",
        "OriginalFileName":   "notepad.EXE",
        "ParentImage":        r"C:\Windows\explorer.exe",
        "ProcessCommandLine": "notepad.exe readme.txt",
        "New_Process_Name":   r"C:\Windows\System32\notepad.exe",
        "FileName":           "notepad.exe",
        "QueryName":          "microsoft.com",
        "DestinationPort":    "443",
    }
    _EVASION_TRANSFORMS = [
        ("case_manipulation",  lambda v: v.upper() if isinstance(v,str) else v),
        ("path_traversal",     lambda v: v.replace("\\System32\\","\\System32\\..\\System32\\") if isinstance(v,str) else v),
        ("env_variable",       lambda v: v.replace("C:\\Windows","%SystemRoot%") if isinstance(v,str) else v),
        ("double_extension",   lambda v: v+".bak" if isinstance(v,str) and v.endswith(".exe") else v),
        ("syswow64_path",      lambda v: v.replace("System32","SysWow64") if isinstance(v,str) else v),
        ("space_insertion",    lambda v: v.replace(".exe"," .exe") if isinstance(v,str) else v),
        ("short_name_case",    lambda v: v.replace("C:\\Windows","C:\\WINDOWS") if isinstance(v,str) else v),
    ]

    def __init__(self, parsed: dict, log_source: str = ""):
        super().__init__()
        self.conditions  = parsed.get("conditions", [])
        self.log_source  = (log_source or parsed.get("log_source","")).lower()
        self._pos_fields = self._build_positive_values()

    def _build_positive_values(self) -> dict:
        pos = {}
        for c in self.conditions:
            f, op, v = c["field"], c["op"], c["value"]
            if op == "equals":       pos[f] = v
            elif op == "contains":   pos[f] = f"prefix_{v}_suffix"
            elif op == "startswith": pos[f] = f"{v}_continuation"
            elif op == "endswith":   pos[f] = f"C:\\Windows\\System32\\{v}"
            elif op == "regex":
                lit = re.sub(r'[\\()?+*\[\]^$|{}]','',v)[:40]
                pos[f] = lit or v[:20]
            else:                    pos[f] = v
        return pos

    def _base(self) -> dict:
        ls = self.log_source
        if "3" in ls or "network" in ls:
            return self._base_sysmon_network_event()
        elif "4688" in ls or ("windows" in ls and "process" in ls):
            b = self._base_windows_security_event(4688)
            b.update({"New_Process_Name": r"C:\Windows\System32\benign.exe",
                      "Process_Command_Line": "benign.exe",
                      "Creator_Process_Name": r"C:\Windows\System32\svchost.exe"})
            return b
        elif "4624" in ls or "logon" in ls:
            return self._base_windows_logon_event(3)
        elif "cloudtrail" in ls or "aws" in ls:
            return self._base_cloudtrail_event("DescribeInstances")
        elif "dns" in ls:
            return self._base_sysmon_dns_event()
        else:
            b = self._base_sysmon_event(1)
            b.update({"Image": r"C:\Windows\System32\benign.exe",
                      "CommandLine": "benign.exe", "OriginalFileName": "benign.EXE",
                      "ParentImage": r"C:\Windows\explorer.exe",
                      "CurrentDirectory": r"C:\Users\user\\", "IntegrityLevel": "Medium",
                      "Hashes": f"SHA256={self._random_hash()}"})
            return b

    def generate_true_positives(self, count: int = 10):
        events = []
        variations = [
            ("textbook",   lambda d: d),
            ("upper_case", lambda d: {k: v.upper() if isinstance(v,str) else v for k,v in d.items()}),
            ("lower_case", lambda d: {k: v.lower() if isinstance(v,str) else v for k,v in d.items()}),
            ("extra_args", lambda d: {k:(v+" /extra_arg") if k=="CommandLine" and isinstance(v,str) else v for k,v in d.items()}),
        ]
        for i in range(count):
            base = self._base()
            base.update(self._pos_fields)
            label, xform = variations[i % len(variations)]
            if i > 0:
                base = xform(base)
            desc = list(self._pos_fields.values())[0][:45] if self._pos_fields else "trigger"
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(), category=dv.EventCategory.TRUE_POSITIVE,
                description=f"Attack [{label}]: {desc}",
                log_data=base, expected_detection=True,
                tags=["true_positive", label], attack_technique="T1059",
            ))
        return events

    def generate_true_negatives(self, count: int = 15):
        events = []
        benign = [
            ("svchost.exe",  r"C:\Windows\System32\svchost.exe"),
            ("notepad.exe",  r"C:\Windows\System32\notepad.exe"),
            ("explorer.exe", r"C:\Windows\explorer.exe"),
            ("chrome.exe",   r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            ("Teams.exe",    r"C:\Users\user\AppData\Local\Microsoft\Teams\Teams.exe"),
            ("python.exe",   r"C:\Python311\python.exe"),
            ("git.exe",      r"C:\Program Files\Git\cmd\git.exe"),
            ("code.exe",     r"C:\Program Files\Microsoft VS Code\Code.exe"),
        ]
        for i in range(count):
            base = self._base()
            base.update(self._BENIGN)
            name, path = benign[i % len(benign)]
            base["Image"] = path
            base["OriginalFileName"] = name.upper()
            base["CommandLine"] = f"{name} --normal-arg"
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(), category=dv.EventCategory.TRUE_NEGATIVE,
                description=f"Benign: {name} — normal system activity",
                log_data=base, expected_detection=False, tags=["benign","baseline"],
            ))
        return events

    def generate_fp_candidates(self, count: int = 5):
        events = []
        for i in range(count):
            base = self._base()
            base.update(self._BENIGN)
            # Partial match: only half the conditions
            partial = dict(list(self._pos_fields.items())[:max(1, len(self._pos_fields)//2)])
            base.update(partial)
            base["ParentImage"] = r"C:\Windows\System32\services.exe"
            base["User"] = "NT AUTHORITY\\SYSTEM"
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(), category=dv.EventCategory.FALSE_POSITIVE_CANDIDATE,
                description=f"FP stress-test {i+1}: partial match — legitimate admin activity",
                log_data=base, expected_detection=False,
                tags=["fp_candidate","stress_test"],
                notes="Satisfies some but not all conditions. Should NOT fire.",
            ))
        return events

    def generate_evasion_samples(self, count: int = 5):
        events = []
        for (name, xform) in self._EVASION_TRANSFORMS[:count]:
            base = self._base()
            evaded = {k: xform(v) for k, v in self._pos_fields.items()}
            base.update(evaded)
            events.append(dv.SyntheticEvent(
                event_id=self._next_id(), category=dv.EventCategory.EVASION,
                description=f"Evasion — {name.replace('_',' ')}",
                log_data=base, expected_detection=True,
                tags=["evasion", name], attack_technique="T1036",
                notes=f"Attacker uses {name} to evade detection while achieving same objective.",
            ))
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def grade_color(g):
    return {"A":"#10b981","B":"#06b6d4","C":"#f59e0b","D":"#f97316","F":"#ef4444"}.get(g,"#94a3b8")

def prog_bar(val, color):
    pct = int(min(max(val*100,0),100))
    return f'<div class="prog-track"><div class="prog-fill" style="width:{pct}%;background:{color}"></div></div>'

def pill(text, style="blue"):
    return f'<span class="pill pill-{style}">{text}</span>'

def outcome_color(o):
    return {"TP":"#10b981","TN":"#06b6d4","FP":"#ef4444","FN":"#f59e0b"}.get(o,"#64748b")


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div style="padding:0 4px 20px">
      <div style="font-family:'Outfit',sans-serif;font-size:20px;font-weight:800;
                  color:#e2e8f0;letter-spacing:.5px;">⚔️ Rule Validator</div>
      <div style="font-size:10px;letter-spacing:2px;color:#4a6080;text-transform:uppercase;
                  margin-top:3px;">Detection Engineering</div>
    </div>
    """, unsafe_allow_html=True)

    mode = st.radio("Mode", ["🧪 Demo (built-in)", "📋 Custom Rule"], label_visibility="collapsed")
    demo_mode = mode.startswith("🧪")

    st.divider()

    if demo_mode:
        st.markdown('<div class="metric-label">Demo: Rundll32 Detection Rule</div>',
                    unsafe_allow_html=True)
        st.caption("Validates the built-in Rundll32 execution rule using the example engine.")
    else:
        rule_format = st.selectbox("Rule Format", [
            "Sigma", "KQL", "SPL", "EQL", "Snort/Suricata", "YARA-L", "Generic"
        ])
        platform = st.selectbox("Platform", [
            "Elastic SIEM", "Microsoft Sentinel", "Splunk", "CrowdStrike NG-SIEM",
            "SumoLogic", "Chronicle / SecOps", "Devo", "Other",
        ])
        log_source = st.selectbox("Log Source", [
            "Sysmon EventID 1 (Process Create)",
            "Sysmon EventID 3 (Network Connect)",
            "Sysmon EventID 11 (File Create)",
            "Sysmon EventID 22 (DNS Query)",
            "Windows Security 4688 (Process Create)",
            "Windows Security 4624 (Logon)",
            "AWS CloudTrail",
            "Azure Activity Logs",
            "Network Flow / Firewall",
            "DNS Query Log",
            "Generic / Unknown",
        ])
        rule_content = st.text_area(
            "Detection Rule",
            height=260,
            placeholder="# Paste your Sigma / KQL / SPL / EQL rule here...\n\ntitle: Suspicious Rundll32\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\rundll32.exe'\n    CommandLine|contains:\n      - '.dll,'\n  condition: selection",
        )

    st.divider()
    st.markdown('<div class="metric-label">Test Volume</div>', unsafe_allow_html=True)
    n_tp = st.slider("True Positives",   5, 20, 10)
    n_tn = st.slider("True Negatives",   5, 25, 15)
    n_fp = st.slider("FP Candidates",    2, 10,  5)
    n_ev = st.slider("Evasion Variants", 2, 10,  5)

    st.divider()
    run_btn = st.button("⚡  Run Validation", use_container_width=True)

    st.markdown("""
    <div style="margin-top:24px;text-align:center;font-size:10px;color:#1e3a52;letter-spacing:1px;">
      detection_validator.py v2<br>synthetic telemetry engine
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ═══════════════════════════════════════════════════════════════════════════════
for k in ("results","metrics","runner","runner_v2","metrics_v2","compare_data",
          "rule_name","parsed_rule","events"):
    if k not in st.session_state:
        st.session_state[k] = None


# ═══════════════════════════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════════════════════════
if run_btn:
    with st.spinner("Generating synthetic telemetry & running evaluation…"):
        try:
            if demo_mode:
                gen = dv.ExampleRundll32Generator()
                e1  = dv.ExampleRundll32Engine()
                e2  = dv.ImprovedRundll32Engine()
                events = gen.generate_all(tp=n_tp, tn=n_tn, fp=n_fp, evasion=n_ev)
                runner = dv.TestRunner(e1, events); runner.run()
                runner_v2 = dv.TestRunner(e2, events); runner_v2.run()
                comp = dv.RuleComparator(e1, e2, events).compare()
                st.session_state.update({
                    "runner": runner, "runner_v2": runner_v2,
                    "results": runner.results, "metrics": runner.get_metrics(),
                    "metrics_v2": runner_v2.get_metrics(), "compare_data": comp,
                    "rule_name": e1.rule_name, "events": events, "parsed_rule": None,
                })
            else:
                if not rule_content or not rule_content.strip():
                    st.error("⚠️  Paste a detection rule in the sidebar first.")
                    st.stop()

                parsed = RuleParser.parse(rule_content, rule_format)

                if not parsed.get("conditions"):
                    st.warning(
                        "⚠️  Could not extract specific conditions from this rule. "
                        "Falling back to full-text search. "
                        "Try selecting the correct format in the sidebar for better results."
                    )
                    parsed["conditions"] = [
                        {"field": "_raw", "op": "contains", "value": rule_content[:60]}
                    ]
                    parsed["logic"] = "OR"

                engine = DynamicEngine(parsed)
                gen    = DynamicGenerator(parsed, log_source)
                events = gen.generate_all(tp=n_tp, tn=n_tn, fp=n_fp, evasion=n_ev)
                runner = dv.TestRunner(engine, events); runner.run()
                st.session_state.update({
                    "runner": runner, "runner_v2": None,
                    "results": runner.results, "metrics": runner.get_metrics(),
                    "metrics_v2": None, "compare_data": None,
                    "rule_name": parsed.get("rule_name","Custom Rule"),
                    "events": events, "parsed_rule": parsed,
                })

        except Exception as exc:
            st.error(f"Validation error: {exc}")
            st.code(traceback.format_exc(), language="python")
            st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# LANDING
# ═══════════════════════════════════════════════════════════════════════════════
if st.session_state.metrics is None:
    st.markdown("""
    <div style="text-align:center;padding:70px 20px 40px">
      <div style="font-size:72px;margin-bottom:20px;
                  filter:drop-shadow(0 0 30px rgba(6,182,212,.4))">⚔️</div>
      <div style="font-family:'Outfit',sans-serif;font-size:28px;font-weight:800;
                  color:#e2e8f0;letter-spacing:.5px;">Detection Rule Validator</div>
      <div style="font-size:14px;color:#3a5070;margin:12px auto 0;
                  max-width:520px;line-height:1.8;">
        Paste any Sigma, KQL, SPL or EQL rule in the sidebar — or run the built-in demo —
        then click <strong style="color:#22d3ee">Run Validation</strong> to generate
        synthetic attack telemetry, test evasion bypasses, and score detection quality.
      </div>
    </div>
    """, unsafe_allow_html=True)
    c1,c2,c3,c4 = st.columns(4)
    for col, (icon, title, desc, clr) in zip([c1,c2,c3,c4], [
        ("🧬","Synthetic Telemetry","TP / TN / FP candidates & evasion variants generated automatically","#06b6d4"),
        ("🎭","Evasion Testing","Renamed binaries, path traversal, encoding, LOLBAS substitutions","#8b5cf6"),
        ("🎯","Precision & Recall","Full confusion matrix with F1, composite score and letter grade","#10b981"),
        ("🔧","Remediation","Plain-English explanation of every miss and false positive","#f59e0b"),
    ]):
        with col:
            st.markdown(f"""
            <div class="card" style="text-align:center;padding:28px 16px;">
              <div style="font-size:32px;margin-bottom:10px;">{icon}</div>
              <div style="font-family:'Outfit',sans-serif;font-size:14px;font-weight:700;
                          color:{clr};margin-bottom:8px;">{title}</div>
              <div style="font-size:12px;color:#3a5070;line-height:1.6;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)
    st.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════════════════
m       = st.session_state.metrics
results = st.session_state.results
cm      = m["confusion_matrix"]
grade   = m.get("overall_grade","F")
gc      = grade_color(grade)

# Header
st.markdown(f"""
<div style="display:flex;align-items:center;justify-content:space-between;
            background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.05);
            border-radius:12px;padding:16px 24px;margin-bottom:20px;">
  <div>
    <div style="font-family:'Outfit',sans-serif;font-size:20px;font-weight:800;color:#e2e8f0;">
      {st.session_state.rule_name or "Detection Rule"}
    </div>
    <div style="font-size:11px;color:#4a6080;margin-top:3px;letter-spacing:1px;">
      {len(results)} events evaluated · {datetime.datetime.now().strftime("%H:%M:%S")}
    </div>
  </div>
  <div><div class="grade-badge grade-{grade}">{grade}</div></div>
</div>
""", unsafe_allow_html=True)

# Parsed conditions (custom mode)
if st.session_state.parsed_rule:
    parsed = st.session_state.parsed_rule
    conds  = parsed.get("conditions",[])
    filts  = parsed.get("filters",[])
    with st.expander(f"🔍  Parsed — {len(conds)} condition(s)  ·  logic: {parsed.get('logic','AND')}"):
        if conds:
            cond_html = " ".join(
                f'<span class="pill pill-blue">{c["field"]} '
                f'<span style="color:#4a6080">{c["op"]}</span> '
                f'<span style="color:#fbbf24">{c["value"][:30]}</span></span>'
                for c in conds
            )
            st.markdown(cond_html, unsafe_allow_html=True)
        else:
            st.markdown('<span style="color:#4a6080">no conditions extracted</span>',
                        unsafe_allow_html=True)
        if filts:
            st.markdown(" ".join(
                f'<span class="pill pill-amber">FILTER: {f["field"]} {f["op"]} {f["value"][:20]}</span>'
                for f in filts
            ), unsafe_allow_html=True)

# Tabs
t1, t2, t3, t4, t5 = st.tabs([
    "📊 Overview", "📋 Event Log", "🎭 Evasion",
    "⚠️ Findings", "📈 Regression",
])

# ── OVERVIEW ──────────────────────────────────────────────────────────────────
with t1:
    st.markdown('<div class="section-title">Confusion Matrix</div>', unsafe_allow_html=True)
    c1,c2,c3,c4 = st.columns(4)
    for col, (val,label,sub,css) in zip([c1,c2,c3,c4],[
        (cm["TP"],"True Positives","Attacks caught","cm-tp"),
        (cm["FN"],"False Negatives","Attacks missed","cm-fn"),
        (cm["FP"],"False Positives","Benign flagged","cm-fp"),
        (cm["TN"],"True Negatives","Benign ignored","cm-tn"),
    ]):
        with col:
            st.markdown(f"""
            <div class="cm-cell {css}">
              <div style="font-family:'Outfit',sans-serif;font-size:48px;font-weight:900;line-height:1;">{val}</div>
              <div style="font-size:11px;font-weight:600;margin-top:6px;">{label}</div>
              <div style="font-size:10px;opacity:.6;margin-top:3px;">{sub}</div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()
    st.markdown('<div class="section-title">Quality Metrics</div>', unsafe_allow_html=True)
    mc1,mc2,mc3,mc4,mc5 = st.columns(5)
    for col, (label,val,color,sub) in zip([mc1,mc2,mc3,mc4,mc5],[
        ("Precision",          m["precision"],          "#06b6d4", f"{cm['TP']} of {cm['TP']+cm['FP']} alerts real"),
        ("Recall",             m["recall"],             "#10b981", f"Caught {cm['TP']} of {cm['TP']+cm['FN']} attacks"),
        ("F1 Score",           m["f1_score"],           "#8b5cf6", "Harmonic mean P & R"),
        ("Evasion Resistance", m["evasion_resistance"], "#f59e0b", f"{m['evasion_caught']}/{m['evasion_total']} variants caught"),
        ("Composite Score",    m["composite_score"],    gc,        f"Letter grade: {grade}"),
    ]):
        with col:
            st.markdown(f"""
            <div class="card">
              <div class="metric-label">{label}</div>
              <div class="metric-num" style="color:{color};">{val:.1%}</div>
              {prog_bar(val, color)}
              <div class="metric-sub">{sub}</div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()
    st.markdown('<div class="section-title">Test Coverage</div>', unsafe_allow_html=True)
    bd = m.get("category_breakdown",{})
    bc1,bc2,bc3,bc4,bc5 = st.columns(5)
    for col, (label,val,color) in zip([bc1,bc2,bc3,bc4,bc5],[
        ("Total Events",  m["total_events"],              "#e2e8f0"),
        ("True Positives",bd.get("true_positive",0),     "#10b981"),
        ("True Negatives",bd.get("true_negative",0),     "#06b6d4"),
        ("FP Candidates", bd.get("fp_candidate",0),      "#ef4444"),
        ("Evasion Tests", bd.get("evasion",0),            "#f59e0b"),
    ]):
        with col:
            st.markdown(f"""
            <div class="card" style="text-align:center;padding:18px 12px;">
              <div class="metric-label">{label}</div>
              <div style="font-family:'Outfit',sans-serif;font-size:40px;font-weight:800;color:{color};">{val}</div>
            </div>
            """, unsafe_allow_html=True)

# ── EVENT LOG ─────────────────────────────────────────────────────────────────
with t2:
    f1c,f2c = st.columns([1,3])
    with f1c:
        filt = st.multiselect("Outcome", ["TP","TN","FP","FN"], default=["TP","TN","FP","FN"])
    with f2c:
        cat_filt = st.multiselect("Category",
            ["true_positive","true_negative","fp_candidate","evasion"],
            default=["true_positive","true_negative","fp_candidate","evasion"])

    shown = [r for r in results if r.outcome in filt and r.event.category.value in cat_filt]
    st.markdown(f'<div style="font-size:11px;color:#3a5070;margin:6px 0 14px;">'
                f'Showing {len(shown)} / {len(results)} events</div>', unsafe_allow_html=True)

    for r in shown:
        cat_icon = {"true_positive":"🔴","true_negative":"🟢",
                    "fp_candidate":"🟡","evasion":"🟠"}.get(r.event.category.value,"⚪")
        oc = outcome_color(r.outcome)
        with st.expander(f"{cat_icon}  {r.event.description[:72]}"):
            lc1,lc2 = st.columns([3,1])
            with lc1:
                st.markdown(f'<div style="font-size:16px;font-weight:700;color:{oc};margin-bottom:10px;">{r.outcome}</div>', unsafe_allow_html=True)
                tag_html = " ".join(pill(t,"blue") for t in r.event.tags)
                if r.event.attack_technique:
                    tag_html += " " + pill(r.event.attack_technique,"amber")
                st.markdown(tag_html, unsafe_allow_html=True)
                if r.event.notes:
                    st.markdown(f'<div style="font-size:11px;color:#4a6080;margin-top:8px;font-style:italic;">{r.event.notes}</div>', unsafe_allow_html=True)
                if r.detection.matched_conditions:
                    st.markdown('<div style="font-size:10px;letter-spacing:1px;color:#4a6080;text-transform:uppercase;margin-top:10px;">Matched conditions</div>', unsafe_allow_html=True)
                    st.markdown(" ".join(pill(c[:50],"green") for c in r.detection.matched_conditions), unsafe_allow_html=True)
            with lc2:
                conf_c = "#10b981" if r.detection.confidence_score>.7 else "#f59e0b" if r.detection.confidence_score>.4 else "#ef4444"
                st.markdown(f"""
                <div class="card" style="text-align:center;">
                  <div class="metric-label">Confidence</div>
                  <div style="font-family:'Outfit',sans-serif;font-size:28px;font-weight:800;color:{conf_c};">{r.detection.confidence_score:.0%}</div>
                  {prog_bar(r.detection.confidence_score,conf_c)}
                  <div class="metric-label">Exec time</div>
                  <div style="font-size:13px;color:#4a6080;">{r.detection.execution_time_ms:.3f}ms</div>
                </div>
                """, unsafe_allow_html=True)
            st.code(json.dumps(r.event.log_data, indent=2), language="json")

# ── EVASION ───────────────────────────────────────────────────────────────────
with t3:
    ev_results = [r for r in results if r.event.category.value == "evasion"]
    caught   = sum(1 for r in ev_results if r.outcome == "TP")
    bypassed = len(ev_results) - caught
    resist   = m["evasion_resistance"]
    rc       = grade_color("A" if resist>=.9 else "B" if resist>=.7 else "C" if resist>=.5 else "F")

    ec1,ec2,ec3,ec4 = st.columns(4)
    for col, (label,val,color,fmt) in zip([ec1,ec2,ec3,ec4],[
        ("Resistance Score", resist,        rc,        "pct"),
        ("Variants Tested",  len(ev_results),"#e2e8f0","int"),
        ("Caught",           caught,        "#10b981", "int"),
        ("Bypassed",         bypassed,      "#ef4444", "int"),
    ]):
        with col:
            display = f"{val:.0%}" if fmt=="pct" else str(val)
            bar_val  = val if fmt=="pct" else (val/max(len(ev_results),1))
            st.markdown(f"""
            <div class="card" style="text-align:center;">
              <div class="metric-label">{label}</div>
              <div style="font-family:'Outfit',sans-serif;font-size:44px;font-weight:900;color:{color};">{display}</div>
              {prog_bar(bar_val, color)}
            </div>
            """, unsafe_allow_html=True)

    st.divider()
    st.markdown('<div class="section-title">Evasion Variant Detail</div>', unsafe_allow_html=True)
    for r in ev_results:
        detected = r.outcome == "TP"
        icon  = "✅" if detected else "❌"
        color = "#10b981" if detected else "#ef4444"
        risk  = "BLOCKED" if detected else "BYPASS FOUND"
        st.markdown(f"""
        <div class="finding finding-ev">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
            <div style="font-size:14px;color:#e2e8f0;font-weight:600;">{icon} &nbsp; {r.event.description}</div>
            <span class="pill" style="background:rgba({'16,185,129' if detected else '239,68,68'},.12);color:{color};border:1px solid {color}40;">{risk}</span>
          </div>
          <div>{''.join(pill(t,'blue') for t in r.event.tags)}</div>
          <div style="font-size:11px;color:{'#10b981' if detected else '#ef4444'};margin-top:8px;">
            {'✓ Rule detected this variant despite obfuscation' if detected else '⚠ Rule failed — attacker achieves same objective undetected'}
          </div>
          {('<div style="font-size:11px;color:#4a6080;margin-top:6px;">💡 Add OriginalFileName or hash check to catch this variant.</div>') if not detected else ''}
        </div>
        """, unsafe_allow_html=True)

# ── FINDINGS ──────────────────────────────────────────────────────────────────
with t4:
    fn_list = [r for r in results if r.outcome=="FN"]
    fp_list = [r for r in results if r.outcome=="FP"]
    fc1,fc2 = st.columns(2)

    with fc1:
        st.markdown(f'<div style="font-family:Outfit,sans-serif;font-size:13px;font-weight:700;color:#f59e0b;margin-bottom:12px;">❌ Missed Detections — False Negatives ({len(fn_list)})</div>', unsafe_allow_html=True)
        if not fn_list:
            st.markdown('<div class="card" style="text-align:center;padding:32px;color:#3a5070;">✓ No false negatives — rule caught all expected threats</div>', unsafe_allow_html=True)
        else:
            for r in fn_list:
                with st.expander(f"❌  {r.event.description[:65]}"):
                    st.markdown(f"""
                    <div class="finding finding-fn">
                      <div style="font-size:10px;letter-spacing:2px;color:#f59e0b;text-transform:uppercase;margin-bottom:8px;">Why it missed</div>
                      <div style="font-size:12px;color:#94a3b8;line-height:1.7;">
                        {'No conditions matched.' if not r.detection.matched_conditions else f'Partially matched: {", ".join(r.detection.matched_conditions[:3])}'}
                        The rule conditions did not evaluate to true for this event.
                      </div>
                      <div style="font-size:11px;color:#4a6080;margin-top:8px;">💡 Broaden detection logic or add OriginalFileName / hash check to cover this variant.</div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(json.dumps(r.event.log_data, indent=2), language="json")

    with fc2:
        st.markdown(f'<div style="font-family:Outfit,sans-serif;font-size:13px;font-weight:700;color:#ef4444;margin-bottom:12px;">⚠️ False Positives — Incorrect Alerts ({len(fp_list)})</div>', unsafe_allow_html=True)
        if not fp_list:
            st.markdown('<div class="card" style="text-align:center;padding:32px;color:#3a5070;">✓ No false positives — rule did not fire on benign activity</div>', unsafe_allow_html=True)
        else:
            for r in fp_list:
                with st.expander(f"⚠️  {r.event.description[:65]}"):
                    st.markdown(f"""
                    <div class="finding finding-fp">
                      <div style="font-size:10px;letter-spacing:2px;color:#ef4444;text-transform:uppercase;margin-bottom:8px;">Why it fired</div>
                      <div style="font-size:12px;color:#94a3b8;line-height:1.7;">
                        Matched: {", ".join(r.detection.matched_conditions[:4]) or "unknown conditions"}
                      </div>
                      <div style="font-size:11px;color:#4a6080;margin-top:8px;">💡 Add allowlist filter or tighten condition with additional field checks.</div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(json.dumps(r.event.log_data, indent=2), language="json")

# ── REGRESSION ────────────────────────────────────────────────────────────────
with t5:
    comp = st.session_state.compare_data
    m2   = st.session_state.metrics_v2

    if not comp or not m2:
        st.markdown("""
        <div class="card" style="text-align:center;padding:48px;color:#3a5070;">
          <div style="font-size:28px;margin-bottom:12px;">📊</div>
          <div style="font-size:14px;">Regression comparison is available in demo mode only.<br>
          Switch to <strong style="color:#22d3ee">🧪 Demo</strong> to compare original vs improved Rundll32 rule.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        verdict = comp.get("verdict","NO_CHANGE")
        v_clr = {"SIGNIFICANT_IMPROVEMENT":"#10b981","MARGINAL_IMPROVEMENT":"#06b6d4",
                 "NO_CHANGE":"#f59e0b","MARGINAL_REGRESSION":"#f97316",
                 "SIGNIFICANT_REGRESSION":"#ef4444"}.get(verdict,"#94a3b8")

        st.markdown(f"""
        <div class="card card-glow-blue" style="text-align:center;padding:20px;margin-bottom:20px;">
          <div class="metric-label">Regression Verdict</div>
          <div style="font-family:'Outfit',sans-serif;font-size:22px;font-weight:800;color:{v_clr};letter-spacing:2px;">
            {verdict.replace("_"," ")}
          </div>
        </div>
        """, unsafe_allow_html=True)

        rc1,rc2 = st.columns([3,2])
        v1d    = comp["engine_a"]
        deltas = comp["deltas"]

        with rc1:
            st.markdown('<div class="section-title">Metric Deltas  (V1 → V2)</div>', unsafe_allow_html=True)
            for key,label in [("precision","Precision"),("recall","Recall"),("f1_score","F1 Score"),
                               ("evasion_resistance","Evasion Resistance"),("composite_score","Composite Score")]:
                v1_val = v1d["metrics"].get(key,0)
                v2_val = m2.get(key,0)
                delta  = deltas.get(key,0)
                d_sign = "+" if delta>0 else ""
                d_cls  = "delta-pos" if delta>0 else "delta-neg" if delta<0 else "delta-neu"
                bar_c  = "#10b981" if delta>0 else "#ef4444" if delta<0 else "#64748b"
                st.markdown(f"""
                <div class="card" style="margin-bottom:8px;padding:14px 18px;">
                  <div style="display:flex;align-items:center;justify-content:space-between;">
                    <div>
                      <div class="metric-label">{label}</div>
                      <div style="display:flex;align-items:baseline;gap:12px;margin-top:4px;">
                        <span style="font-size:18px;font-weight:700;color:#4a6080;">{v1_val:.1%}</span>
                        <span style="color:#2a3a50;">→</span>
                        <span style="font-size:18px;font-weight:700;color:#e2e8f0;">{v2_val:.1%}</span>
                      </div>
                    </div>
                    <div class="{d_cls}" style="font-family:'Outfit',sans-serif;font-size:18px;font-weight:800;">
                      {d_sign}{delta:.1%}
                    </div>
                  </div>
                  {prog_bar(v2_val, bar_c)}
                </div>
                """, unsafe_allow_html=True)

        with rc2:
            diffs = comp.get("outcome_diffs",[])
            st.markdown(f'<div class="section-title">Changed Outcomes ({len(diffs)})</div>', unsafe_allow_html=True)
            if not diffs:
                st.markdown('<div class="card" style="text-align:center;color:#3a5070;">No outcome changes between versions</div>', unsafe_allow_html=True)
            else:
                for d in diffs[:15]:
                    improved = d["engine_b_outcome"] in ("TP","TN")
                    clr = "#10b981" if improved else "#ef4444"
                    st.markdown(f"""
                    <div class="finding" style="border-left-color:{clr};margin-bottom:6px;">
                      <div style="font-size:12px;color:#c4cfe0;">{d['description'][:60]}</div>
                      <div style="margin-top:6px;">
                        {pill(d['category'],'gray')}
                        <span style="font-size:12px;color:#4a6080;margin:0 8px;">
                          {d['engine_a_outcome']} → <strong style="color:{clr};">{d['engine_b_outcome']}</strong>
                        </span>
                      </div>
                    </div>
                    """, unsafe_allow_html=True)


# ─── Export ───────────────────────────────────────────────────────────────────
st.divider()
ex1,ex2,_,_ = st.columns(4)
with ex1:
    payload = json.dumps({
        "rule_name": st.session_state.rule_name,
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "metrics": m,
        "parsed_rule": st.session_state.parsed_rule,
        "events": [r.event.to_dict() for r in results],
        "results": [{"event_id":r.event.event_id,"outcome":r.outcome,
                     "matched":r.detection.matched,
                     "matched_conditions":r.detection.matched_conditions,
                     "confidence":r.detection.confidence_score} for r in results],
        "compare": st.session_state.compare_data,
    }, indent=2)
    st.download_button("⬇  Export JSON Report", data=payload,
        file_name=f"validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json", use_container_width=True)
with ex2:
    st.markdown(
        f"<div style='font-size:11px;color:#2a3a50;padding:10px;'>"
        f"Grade <strong style='color:{gc}'>{grade}</strong> · "
        f"Score {m['composite_score']:.0%} · {m['total_events']} events</div>",
        unsafe_allow_html=True)
