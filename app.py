#!/usr/bin/env python3
"""
Detection Rule Validation UI
Streamlit interface for the detection_validator.py framework.
"""

import streamlit as st
import json
import sys
import io
import datetime
import importlib.util
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG  (must be first Streamlit call)
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Detection Rule Validator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# STYLING
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'JetBrains Mono', monospace;
}

/* Background */
.stApp {
    background-color: #0a0d12;
    color: #c8d6e5;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #0f1318;
    border-right: 1px solid #1e2d40;
}

/* Headers */
h1, h2, h3 {
    font-family: 'Syne', sans-serif !important;
    color: #e8f4fd !important;
}

/* Metric cards */
.metric-card {
    background: #0f1318;
    border: 1px solid #1e2d40;
    border-radius: 6px;
    padding: 16px 20px;
    margin: 4px 0;
}

.metric-label {
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #5a7a99;
    margin-bottom: 4px;
}

.metric-value {
    font-family: 'Syne', sans-serif;
    font-size: 32px;
    font-weight: 800;
    line-height: 1;
}

.metric-grade-A { color: #00e676; }
.metric-grade-B { color: #69f0ae; }
.metric-grade-C { color: #ffd740; }
.metric-grade-D { color: #ff9100; }
.metric-grade-F { color: #ff5252; }

/* Confusion matrix */
.cm-cell {
    text-align: center;
    padding: 20px;
    border-radius: 6px;
    font-family: 'Syne', sans-serif;
}

.cm-tp { background: rgba(0,230,118,0.15); border: 1px solid rgba(0,230,118,0.3); color: #00e676; }
.cm-tn { background: rgba(0,176,255,0.10); border: 1px solid rgba(0,176,255,0.2); color: #40c4ff; }
.cm-fp { background: rgba(255,82,82,0.12); border: 1px solid rgba(255,82,82,0.25); color: #ff5252; }
.cm-fn { background: rgba(255,145,0,0.12); border: 1px solid rgba(255,145,0,0.25); color: #ff9100; }

.cm-value { font-size: 40px; font-weight: 800; line-height: 1; }
.cm-label { font-size: 10px; letter-spacing: 2px; text-transform: uppercase; opacity: 0.7; margin-top: 6px; }

/* Score bar */
.score-bar-bg {
    background: #1a2332;
    border-radius: 4px;
    height: 8px;
    margin: 4px 0 12px;
    overflow: hidden;
}
.score-bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s ease;
}

/* Finding cards */
.finding-card {
    background: #0f1318;
    border-left: 3px solid #ff5252;
    padding: 12px 16px;
    margin: 8px 0;
    border-radius: 0 6px 6px 0;
}

.evasion-card {
    border-left-color: #ff9100;
}

.info-tag {
    display: inline-block;
    background: #1a2332;
    border: 1px solid #2a3d52;
    border-radius: 3px;
    padding: 2px 8px;
    font-size: 11px;
    color: #7a9ab8;
    margin: 2px;
}

/* Buttons */
.stButton > button {
    background: #0d3b6b !important;
    color: #7ec8f4 !important;
    border: 1px solid #1a5c99 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    border-radius: 4px !important;
    padding: 8px 20px !important;
    transition: all 0.2s !important;
}

.stButton > button:hover {
    background: #1a5c99 !important;
    border-color: #2a7ec0 !important;
    color: #e8f4fd !important;
}

/* Text area */
.stTextArea textarea {
    background: #0f1318 !important;
    color: #a8c8e8 !important;
    border: 1px solid #1e2d40 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
}

/* Select boxes */
.stSelectbox > div > div {
    background: #0f1318 !important;
    border: 1px solid #1e2d40 !important;
    color: #a8c8e8 !important;
}

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    background: #0f1318;
    border-bottom: 1px solid #1e2d40;
    gap: 0;
}

.stTabs [data-baseweb="tab"] {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 1px;
    color: #5a7a99 !important;
    padding: 12px 20px;
    text-transform: uppercase;
}

.stTabs [aria-selected="true"] {
    color: #7ec8f4 !important;
    border-bottom: 2px solid #2a7ec0 !important;
}

/* Expander */
.streamlit-expanderHeader {
    background: #0f1318 !important;
    border: 1px solid #1e2d40 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
    color: #7a9ab8 !important;
}

/* Code blocks */
code {
    background: #1a2332 !important;
    color: #7ec8f4 !important;
    border: none !important;
    font-size: 11px !important;
}

/* Divider */
hr { border-color: #1e2d40 !important; }

/* Status pill */
.status-pill {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 20px;
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-weight: 600;
}

.pill-pass { background: rgba(0,230,118,0.15); color: #00e676; border: 1px solid rgba(0,230,118,0.3); }
.pill-fail { background: rgba(255,82,82,0.12); color: #ff5252; border: 1px solid rgba(255,82,82,0.25); }
.pill-warn { background: rgba(255,145,0,0.12); color: #ff9100; border: 1px solid rgba(255,145,0,0.25); }

/* Header bar */
.header-bar {
    background: linear-gradient(135deg, #0a1929 0%, #0d2137 100%);
    border: 1px solid #1e3a52;
    border-radius: 8px;
    padding: 24px 28px;
    margin-bottom: 24px;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# LOAD FRAMEWORK
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_resource
def load_framework():
    """Import detection_validator.py dynamically."""
    spec = importlib.util.spec_from_file_location(
        "detection_validator", Path(__file__).parent / "detection_validator.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


try:
    dv = load_framework()
    FRAMEWORK_LOADED = True
except Exception as e:
    FRAMEWORK_LOADED = False
    FRAMEWORK_ERROR = str(e)


# ─────────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="header-bar">
    <div style="font-family:'Syne',sans-serif;font-size:24px;font-weight:800;color:#e8f4fd;letter-spacing:1px;">
        🛡️ Detection Rule Validator
    </div>
    <div style="font-size:11px;color:#5a7a99;margin-top:6px;letter-spacing:1px;">
        SYNTHETIC TELEMETRY · EVASION TESTING · PRECISION/RECALL SCORING · REMEDIATION GUIDANCE
    </div>
</div>
""", unsafe_allow_html=True)

if not FRAMEWORK_LOADED:
    st.error(f"⚠️ Could not load detection_validator.py: {FRAMEWORK_ERROR}")
    st.info("Make sure `detection_validator.py` is in the same directory as `app.py`.")
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR — RULE INPUT
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="font-family:'Syne',sans-serif;font-size:16px;font-weight:700;
                color:#e8f4fd;letter-spacing:1px;margin-bottom:16px;">
        RULE CONFIGURATION
    </div>
    """, unsafe_allow_html=True)

    demo_mode = st.checkbox("▶ Run built-in demo (Rundll32 rule)", value=True)

    if not demo_mode:
        rule_format = st.selectbox(
            "Rule Format",
            ["Sigma", "KQL", "SPL", "EQL", "Snort/Suricata", "YARA", "Custom"],
        )
        platform = st.selectbox(
            "Platform",
            ["Elastic SIEM", "Microsoft Sentinel", "Splunk", "CrowdStrike",
             "SumoLogic", "Chronicle", "Other"],
        )
        log_source = st.selectbox(
            "Log Source",
            ["Sysmon EventID 1 (Process Create)", "Sysmon EventID 3 (Network Connect)",
             "Windows Security 4688", "Windows Security 4624",
             "CloudTrail", "Azure Activity", "Network Flow", "DNS", "Other"],
        )
        rule_content = st.text_area(
            "Paste your detection rule",
            height=280,
            placeholder="# Paste your Sigma / KQL / SPL rule here...\ntitle: Example\nlogsource:\n  ...",
        )

    st.divider()

    # Test volume controls
    st.markdown("""
    <div style="font-family:'Syne',sans-serif;font-size:12px;font-weight:600;
                color:#5a7a99;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">
        Test Volume
    </div>
    """, unsafe_allow_html=True)

    n_tp = st.slider("True Positive samples", 5, 20, 10)
    n_tn = st.slider("True Negative samples", 5, 25, 15)
    n_fp = st.slider("False Positive candidates", 2, 10, 5)
    n_ev = st.slider("Evasion variants", 2, 10, 5)

    st.divider()

    run_btn = st.button("⚡ RUN VALIDATION", use_container_width=True)

    st.divider()
    st.markdown("""
    <div style="font-size:10px;color:#2a3d52;text-align:center;line-height:1.8;">
        Detection Rule Validator<br>
        Powered by detection_validator.py<br>
        v2 Framework
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state.results = None
if "metrics" not in st.session_state:
    st.session_state.metrics = None
if "runner" not in st.session_state:
    st.session_state.runner = None
if "compare_data" not in st.session_state:
    st.session_state.compare_data = None


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def grade_color(grade: str) -> str:
    return {
        "A": "#00e676", "B": "#69f0ae", "C": "#ffd740",
        "D": "#ff9100", "F": "#ff5252"
    }.get(grade, "#c8d6e5")


def pct_bar(value: float, color: str = "#2a7ec0") -> str:
    pct = min(max(int(value * 100), 0), 100)
    return f"""
    <div class="score-bar-bg">
        <div class="score-bar-fill" style="width:{pct}%;background:{color};"></div>
    </div>
    """


def outcome_pill(outcome: str) -> str:
    mapping = {
        "TP": ('<span class="status-pill pill-pass">✓ TP</span>', "Detected correctly"),
        "TN": ('<span class="status-pill pill-pass">✓ TN</span>', "Correctly ignored"),
        "FP": ('<span class="status-pill pill-fail">✗ FP</span>', "False alarm"),
        "FN": ('<span class="status-pill pill-fail">✗ FN</span>', "Missed detection"),
    }
    pill, label = mapping.get(outcome, ("", outcome))
    return f"{pill} <span style='font-size:11px;color:#5a7a99;margin-left:6px;'>{label}</span>"


# ─────────────────────────────────────────────────────────────────────────────
# RUN VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
if run_btn:
    with st.spinner("Generating synthetic telemetry and evaluating rule..."):
        try:
            # ── Demo mode: use the built-in Rundll32 example ────────────────
            if demo_mode:
                gen = dv.ExampleRundll32Generator()
                engine_v1 = dv.ExampleRundll32Engine()
                engine_v2 = dv.ImprovedRundll32Engine()

                events = gen.generate_all(
                    tp=n_tp, tn=n_tn, fp=n_fp, evasion=n_ev
                )
                runner = dv.TestRunner(engine_v1, events)
                runner.run()
                metrics = runner.get_metrics()

                runner_v2 = dv.TestRunner(engine_v2, events)
                runner_v2.run()
                metrics_v2 = runner_v2.get_metrics()

                comparator = dv.RuleComparator(engine_v1, engine_v2, events)
                compare_data = comparator.compare()

                st.session_state.runner = runner
                st.session_state.runner_v2 = runner_v2
                st.session_state.results = runner.results
                st.session_state.metrics = metrics
                st.session_state.metrics_v2 = metrics_v2
                st.session_state.compare_data = compare_data
                st.session_state.rule_name = engine_v1.rule_name
                st.session_state.events = events

            else:
                st.warning(
                    "Custom rule validation requires a DetectionEngine subclass "
                    "generated by the AI workflow. Paste the generated engine code "
                    "into `engines/custom_engine.py` and reload, or run in demo mode "
                    "to explore the UI."
                )
                st.stop()

        except Exception as e:
            st.error(f"Validation failed: {e}")
            import traceback
            st.code(traceback.format_exc(), language="python")
            st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# RESULTS DISPLAY
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.metrics is None:
    # Landing state
    st.markdown("""
    <div style="text-align:center;padding:80px 20px;">
        <div style="font-size:64px;margin-bottom:16px;">🛡️</div>
        <div style="font-family:'Syne',sans-serif;font-size:22px;font-weight:700;color:#e8f4fd;">
            Ready to Validate
        </div>
        <div style="font-size:13px;color:#3a5a78;margin-top:12px;max-width:480px;margin-left:auto;margin-right:auto;line-height:1.8;">
            Configure your rule in the sidebar and click <strong style="color:#7ec8f4;">RUN VALIDATION</strong>
            to generate synthetic attack telemetry, test evasion variants, and score detection quality.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Feature cards
    cols = st.columns(4)
    features = [
        ("⚡", "True Positive\nGeneration", "Attack variants across execution patterns"),
        ("🎭", "Evasion\nTesting", "Renamed binaries, obfuscation, LOLBAS"),
        ("🔬", "False Positive\nStress Test", "Benign noise that resembles attacks"),
        ("📊", "Scored\nReport", "Precision, recall, F1, composite grade"),
    ]
    for col, (icon, title, desc) in zip(cols, features):
        with col:
            st.markdown(f"""
            <div class="metric-card" style="text-align:center;padding:24px 16px;">
                <div style="font-size:28px;margin-bottom:8px;">{icon}</div>
                <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;
                            color:#e8f4fd;white-space:pre-line;margin-bottom:8px;">{title}</div>
                <div style="font-size:11px;color:#3a5a78;line-height:1.6;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)
    st.stop()


# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────
m = st.session_state.metrics
results = st.session_state.results
cm = m["confusion_matrix"]

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 OVERVIEW",
    "🔬 EVENT LOG",
    "🎭 EVASION ANALYSIS",
    "⚠️ FINDINGS",
    "📈 REGRESSION",
])


# ═══════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ═══════════════════════════════════════════════════════
with tab1:
    rule_name = st.session_state.get("rule_name", "Detection Rule")
    grade = m.get("overall_grade", "F")
    grade_c = grade_color(grade)

    # Top row: grade + confusion matrix
    col_grade, col_cm = st.columns([1, 2])

    with col_grade:
        st.markdown(f"""
        <div class="metric-card" style="text-align:center;padding:32px 20px;">
            <div class="metric-label">Composite Grade</div>
            <div style="font-family:'Syne',sans-serif;font-size:96px;font-weight:800;
                        color:{grade_c};line-height:1;margin:8px 0;">{grade}</div>
            <div style="font-size:22px;color:{grade_c};font-weight:600;">
                {m['composite_score']:.0%}
            </div>
            <div style="font-size:11px;color:#3a5a78;margin-top:8px;">
                {rule_name[:40]}
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_cm:
        st.markdown("""
        <div style="font-family:'Syne',sans-serif;font-size:11px;font-weight:600;
                    color:#5a7a99;letter-spacing:2px;text-transform:uppercase;
                    margin-bottom:12px;">Confusion Matrix</div>
        """, unsafe_allow_html=True)

        cm_cols = st.columns(4)
        cm_data = [
            (cm["TP"], "True Positives", "cm-tp", "Attacks caught"),
            (cm["FN"], "False Negatives", "cm-fn", "Attacks missed"),
            (cm["FP"], "False Positives", "cm-fp", "Benign flagged"),
            (cm["TN"], "True Negatives", "cm-tn", "Benign passed"),
        ]
        for col, (val, label, css_class, desc) in zip(cm_cols, cm_data):
            with col:
                st.markdown(f"""
                <div class="cm-cell {css_class}">
                    <div class="cm-value">{val}</div>
                    <div class="cm-label">{label}</div>
                    <div style="font-size:10px;opacity:0.6;margin-top:4px;">{desc}</div>
                </div>
                """, unsafe_allow_html=True)

    st.divider()

    # Metrics row
    metrics_display = [
        ("Precision", m["precision"], "What % of alerts are real threats?",
         "#2a7ec0", m["precision"]),
        ("Recall", m["recall"], "What % of real attacks were caught?",
         "#00c853", m["recall"]),
        ("F1 Score", m["f1_score"], "Harmonic mean of precision & recall",
         "#aa00ff", m["f1_score"]),
        ("Evasion Resistance", m["evasion_resistance"],
         f"Caught {m['evasion_caught']}/{m['evasion_total']} evasion variants",
         "#ff6d00", m["evasion_resistance"]),
        ("Accuracy", m["accuracy"], "Overall correct classifications",
         "#0091ea", m["accuracy"]),
    ]

    m_cols = st.columns(5)
    for col, (label, value, desc, color, bar_val) in zip(m_cols, metrics_display):
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="color:{color};font-size:28px;">
                    {value:.1%}
                </div>
                <div style="margin-top:8px;">
                    {pct_bar(bar_val, color)}
                </div>
                <div style="font-size:10px;color:#3a5a78;line-height:1.5;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.divider()

    # Summary stats
    st.markdown("""
    <div style="font-family:'Syne',sans-serif;font-size:11px;font-weight:600;
                color:#5a7a99;letter-spacing:2px;text-transform:uppercase;
                margin-bottom:12px;">Test Coverage</div>
    """, unsafe_allow_html=True)

    breakdown = m.get("category_breakdown", {})
    cat_cols = st.columns(5)
    cat_data = [
        ("Total Events", m["total_events"], "#7ec8f4"),
        ("True Positives", breakdown.get("true_positive", 0), "#00e676"),
        ("True Negatives", breakdown.get("true_negative", 0), "#40c4ff"),
        ("FP Candidates", breakdown.get("fp_candidate", 0), "#ff5252"),
        ("Evasion Tests", breakdown.get("evasion", 0), "#ff9100"),
    ]
    for col, (label, val, color) in zip(cat_cols, cat_data):
        with col:
            st.markdown(f"""
            <div class="metric-card" style="text-align:center;">
                <div class="metric-label">{label}</div>
                <div style="font-family:'Syne',sans-serif;font-size:36px;
                            font-weight:800;color:{color};">{val}</div>
            </div>
            """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# TAB 2 — EVENT LOG
# ═══════════════════════════════════════════════════════
with tab2:
    st.markdown("""
    <div style="font-family:'Syne',sans-serif;font-size:11px;font-weight:600;
                color:#5a7a99;letter-spacing:2px;text-transform:uppercase;
                margin-bottom:16px;">All Test Events</div>
    """, unsafe_allow_html=True)

    # Filter bar
    filter_col1, filter_col2 = st.columns([1, 3])
    with filter_col1:
        outcome_filter = st.multiselect(
            "Filter by outcome",
            ["TP", "TN", "FP", "FN"],
            default=["TP", "TN", "FP", "FN"],
        )

    filtered = [r for r in results if r.outcome in outcome_filter]
    st.markdown(
        f"<div style='font-size:11px;color:#3a5a78;margin-bottom:12px;'>"
        f"Showing {len(filtered)} of {len(results)} events</div>",
        unsafe_allow_html=True
    )

    for r in filtered:
        cat = r.event.category.value
        icon = {"true_positive": "🔴", "true_negative": "🟢",
                "fp_candidate": "🟡", "evasion": "🟠"}.get(cat, "⚪")

        with st.expander(f"{icon}  {r.event.description}  —  {r.outcome}"):
            ec1, ec2 = st.columns([2, 1])
            with ec1:
                st.markdown(f"""
                <div style="font-size:11px;color:#5a7a99;margin-bottom:8px;">
                    {outcome_pill(r.outcome)}
                </div>
                """, unsafe_allow_html=True)
                if r.event.attack_technique:
                    st.markdown(
                        f'<span class="info-tag">MITRE {r.event.attack_technique}</span>',
                        unsafe_allow_html=True
                    )
                for tag in r.event.tags:
                    st.markdown(f'<span class="info-tag">{tag}</span>', unsafe_allow_html=True)
                if r.event.notes:
                    st.markdown(
                        f"<div style='font-size:11px;color:#5a7a99;margin-top:8px;"
                        f"font-style:italic;'>{r.event.notes}</div>",
                        unsafe_allow_html=True
                    )
            with ec2:
                confidence = r.detection.confidence_score
                conf_color = "#00e676" if confidence > 0.7 else "#ffd740" if confidence > 0.4 else "#ff5252"
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Confidence</div>
                    <div style="font-family:'Syne',sans-serif;font-size:28px;
                                font-weight:800;color:{conf_color};">{confidence:.0%}</div>
                    {pct_bar(confidence, conf_color)}
                    <div class="metric-label" style="margin-top:8px;">Exec Time</div>
                    <div style="font-size:14px;color:#5a7a99;">
                        {r.detection.execution_time_ms:.3f}ms
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.code(json.dumps(r.event.log_data, indent=2), language="json")

            if r.detection.matched_conditions:
                st.markdown(
                    "<div style='font-size:11px;color:#5a7a99;margin-top:8px;'>Matched conditions:</div>",
                    unsafe_allow_html=True
                )
                for cond in r.detection.matched_conditions:
                    st.markdown(f'<span class="info-tag">{cond}</span>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# TAB 3 — EVASION ANALYSIS
# ═══════════════════════════════════════════════════════
with tab3:
    evasion_results = [r for r in results if r.event.category.value == "evasion"]
    caught = sum(1 for r in evasion_results if r.outcome == "TP")
    missed = len(evasion_results) - caught
    resistance = m["evasion_resistance"]
    res_color = grade_color("A" if resistance >= 0.9 else "B" if resistance >= 0.7 else "C" if resistance >= 0.5 else "D")

    ev_col1, ev_col2, ev_col3 = st.columns(3)
    with ev_col1:
        st.markdown(f"""
        <div class="metric-card" style="text-align:center;">
            <div class="metric-label">Evasion Resistance</div>
            <div style="font-family:'Syne',sans-serif;font-size:52px;font-weight:800;
                        color:{res_color};">{resistance:.0%}</div>
            {pct_bar(resistance, res_color)}
        </div>
        """, unsafe_allow_html=True)
    with ev_col2:
        st.markdown(f"""
        <div class="metric-card" style="text-align:center;">
            <div class="metric-label">Variants Caught</div>
            <div style="font-family:'Syne',sans-serif;font-size:52px;font-weight:800;
                        color:#00e676;">{caught}</div>
        </div>
        """, unsafe_allow_html=True)
    with ev_col3:
        st.markdown(f"""
        <div class="metric-card" style="text-align:center;">
            <div class="metric-label">Bypasses Found</div>
            <div style="font-family:'Syne',sans-serif;font-size:52px;font-weight:800;
                        color:#ff5252;">{missed}</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    for r in evasion_results:
        detected = r.outcome == "TP"
        status_icon = "✅" if detected else "❌"
        risk = "LOW" if detected else "HIGH"
        risk_color = "#00e676" if detected else "#ff5252"

        st.markdown(f"""
        <div class="finding-card evasion-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <div style="font-size:13px;color:#e8f4fd;">{status_icon} {r.event.description}</div>
                <div>
                    <span class="status-pill" style="background:rgba(255,145,0,0.12);
                          color:{risk_color};border:1px solid {risk_color}40;">
                        BYPASS RISK: {risk}
                    </span>
                </div>
            </div>
            <div>
                {''.join(f'<span class="info-tag">{t}</span>' for t in r.event.tags)}
            </div>
            {'<div style="font-size:11px;color:#ff9100;margin-top:8px;">⚠ Rule failed to detect this evasion variant</div>' if not detected else '<div style="font-size:11px;color:#00e676;margin-top:8px;">✓ Rule successfully caught this variant</div>'}
        </div>
        """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════
# TAB 4 — FINDINGS
# ═══════════════════════════════════════════════════════
with tab4:
    fn_results = [r for r in results if r.outcome == "FN"]
    fp_results = [r for r in results if r.outcome == "FP"]

    f_col1, f_col2 = st.columns(2)

    with f_col1:
        st.markdown(f"""
        <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;
                    color:#ff5252;letter-spacing:1px;margin-bottom:12px;">
            ✗ MISSED DETECTIONS — False Negatives ({len(fn_results)})
        </div>
        """, unsafe_allow_html=True)

        if not fn_results:
            st.markdown("""
            <div style="text-align:center;padding:32px;color:#3a5a78;font-size:12px;">
                ✓ No missed detections — rule caught all expected threats
            </div>
            """, unsafe_allow_html=True)
        else:
            for r in fn_results:
                with st.expander(f"❌ {r.event.description}"):
                    st.markdown(f"""
                    <div class="finding-card">
                        <div style="font-size:11px;color:#ff9100;margin-bottom:8px;">
                            WHY IT MISSED
                        </div>
                        <div style="font-size:12px;color:#a8c8e8;line-height:1.7;">
                            The rule's matching conditions did not trigger on this event.
                            Check matched conditions list — if empty, no condition evaluated true.
                        </div>
                        {''.join(f'<span class="info-tag">{t}</span>' for t in r.event.tags)}
                        <div style="font-size:11px;color:#5a7a99;margin-top:8px;">
                            💡 Consider broadening the detection to cover this variant or adding an
                            OriginalFileName check to catch renamed binaries.
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(json.dumps(r.event.log_data, indent=2), language="json")

    with f_col2:
        st.markdown(f"""
        <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;
                    color:#ff9100;letter-spacing:1px;margin-bottom:12px;">
            ⚠ FALSE POSITIVES — Incorrect Alerts ({len(fp_results)})
        </div>
        """, unsafe_allow_html=True)

        if not fp_results:
            st.markdown("""
            <div style="text-align:center;padding:32px;color:#3a5a78;font-size:12px;">
                ✓ No false positives — rule did not fire on benign activity
            </div>
            """, unsafe_allow_html=True)
        else:
            for r in fp_results:
                with st.expander(f"⚠️ {r.event.description}"):
                    st.markdown(f"""
                    <div class="finding-card" style="border-left-color:#ff9100;">
                        <div style="font-size:11px;color:#ff9100;margin-bottom:8px;">
                            WHY IT FIRED
                        </div>
                        <div style="font-size:12px;color:#a8c8e8;line-height:1.7;">
                            This benign event matched the rule's detection conditions.
                            Matched on: {", ".join(r.detection.matched_conditions) or "unknown conditions"}
                        </div>
                        <div style="font-size:11px;color:#5a7a99;margin-top:8px;">
                            💡 Add allowlist filters or tighten the condition specificity
                            to exclude this class of benign activity.
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(json.dumps(r.event.log_data, indent=2), language="json")


# ═══════════════════════════════════════════════════════
# TAB 5 — REGRESSION COMPARISON
# ═══════════════════════════════════════════════════════
with tab5:
    compare_data = st.session_state.get("compare_data")
    m2 = st.session_state.get("metrics_v2")

    if compare_data and m2:
        verdict = compare_data.get("verdict", "NO_CHANGE")
        verdict_colors = {
            "SIGNIFICANT_IMPROVEMENT": "#00e676",
            "MARGINAL_IMPROVEMENT": "#69f0ae",
            "NO_CHANGE": "#ffd740",
            "MARGINAL_REGRESSION": "#ff9100",
            "SIGNIFICANT_REGRESSION": "#ff5252",
        }
        verdict_color = verdict_colors.get(verdict, "#c8d6e5")

        st.markdown(f"""
        <div class="metric-card" style="text-align:center;padding:20px;margin-bottom:20px;">
            <div class="metric-label">Regression Verdict</div>
            <div style="font-family:'Syne',sans-serif;font-size:22px;font-weight:800;
                        color:{verdict_color};letter-spacing:2px;">
                {verdict.replace("_", " ")}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Side-by-side comparison
        rc1, rc2 = st.columns(2)
        v1_data = compare_data["engine_a"]
        v2_data = compare_data["engine_b"]
        deltas = compare_data["deltas"]

        def delta_html(key: str, label: str) -> str:
            v1_val = v1_data["metrics"].get(key, 0)
            v2_val = v2_data["metrics"].get(key, 0)
            delta = deltas.get(key, 0)
            delta_sign = "+" if delta > 0 else ""
            delta_c = "#00e676" if delta > 0 else "#ff5252" if delta < 0 else "#5a7a99"
            return f"""
            <div class="metric-card" style="margin-bottom:8px;">
                <div class="metric-label">{label}</div>
                <div style="display:flex;align-items:baseline;gap:16px;">
                    <div>
                        <div style="font-size:9px;color:#3a5a78;text-transform:uppercase;letter-spacing:1px;">V1 Original</div>
                        <div style="font-size:22px;font-weight:700;color:#7a9ab8;">{v1_val:.1%}</div>
                    </div>
                    <div style="color:{delta_c};font-size:18px;font-weight:700;">→</div>
                    <div>
                        <div style="font-size:9px;color:#3a5a78;text-transform:uppercase;letter-spacing:1px;">V2 Improved</div>
                        <div style="font-size:22px;font-weight:700;color:#e8f4fd;">{v2_val:.1%}</div>
                    </div>
                    <div style="margin-left:auto;">
                        <span style="font-family:'Syne',sans-serif;font-size:16px;
                                     font-weight:700;color:{delta_c};">{delta_sign}{delta:.1%}</span>
                    </div>
                </div>
            </div>
            """

        with rc1:
            st.markdown("""
            <div style="font-family:'Syne',sans-serif;font-size:11px;font-weight:600;
                        color:#5a7a99;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;">
                Metric Deltas
            </div>
            """, unsafe_allow_html=True)
            for key, label in [
                ("precision", "Precision"),
                ("recall", "Recall"),
                ("f1_score", "F1 Score"),
                ("evasion_resistance", "Evasion Resistance"),
                ("composite_score", "Composite Score"),
            ]:
                st.markdown(delta_html(key, label), unsafe_allow_html=True)

        with rc2:
            diffs = compare_data.get("outcome_diffs", [])
            st.markdown(f"""
            <div style="font-family:'Syne',sans-serif;font-size:11px;font-weight:600;
                        color:#5a7a99;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;">
                Changed Outcomes ({len(diffs)} events)
            </div>
            """, unsafe_allow_html=True)

            if not diffs:
                st.markdown("""
                <div style="padding:32px;text-align:center;color:#3a5a78;font-size:12px;">
                    No outcome changes between rule versions
                </div>
                """, unsafe_allow_html=True)
            else:
                for diff in diffs:
                    a_out = diff["engine_a_outcome"]
                    b_out = diff["engine_b_outcome"]
                    improved = b_out in ("TP", "TN") and a_out not in ("TP", "TN")
                    card_color = "#00e676" if improved else "#ff5252"
                    st.markdown(f"""
                    <div class="finding-card" style="border-left-color:{card_color};margin-bottom:8px;">
                        <div style="font-size:12px;color:#e8f4fd;">{diff['description']}</div>
                        <div style="margin-top:6px;">
                            <span class="info-tag">{diff['category']}</span>
                            <span style="font-size:12px;color:#5a7a99;margin:0 8px;">
                                {a_out} → <strong style="color:{card_color};">{b_out}</strong>
                            </span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
    else:
        st.info("Regression comparison is only available in demo mode with the built-in Rundll32 example (V1 vs V2).")


# ─────────────────────────────────────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────────────────────────────────────
st.divider()
if st.session_state.metrics:
    ex_col1, ex_col2, _, _ = st.columns(4)
    with ex_col1:
        report_json = json.dumps({
            "rule_name": st.session_state.get("rule_name"),
            "generated_at": datetime.datetime.utcnow().isoformat(),
            "metrics": st.session_state.metrics,
            "events": [r.event.to_dict() for r in results],
            "results": [
                {
                    "event_id": r.event.event_id,
                    "outcome": r.outcome,
                    "matched": r.detection.matched,
                    "matched_conditions": r.detection.matched_conditions,
                    "confidence": r.detection.confidence_score,
                }
                for r in results
            ],
            "compare": st.session_state.get("compare_data"),
        }, indent=2)
        st.download_button(
            "⬇ EXPORT JSON REPORT",
            data=report_json,
            file_name=f"validation_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )
    with ex_col2:
        st.markdown(
            f"<div style='font-size:11px;color:#3a5a78;padding:10px;'>"
            f"Last run: {datetime.datetime.now().strftime('%H:%M:%S')}"
            f"  ·  {len(results)} events evaluated</div>",
            unsafe_allow_html=True
        )
