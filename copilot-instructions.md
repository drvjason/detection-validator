# Detection Rule Validator — Copilot Instructions

> **Scope:** These instructions govern all AI-assisted development on this codebase.
> Every contribution — new feature, bug fix, refactor, or documentation change —
> must follow the conventions below. Read this file in full before making any edit.

---

## 1. Project Overview

This project is a **production-grade detection rule validation platform** built for security engineers. It lets operators paste any detection rule (Sigma, KQL, SPL, S1QL, PAN-OS, OQL, Okta EventHook, ProofPoint Smart Search, ASQ) and get back a scored, graded, platform-aware validation report with full evasion analysis, KB-grounded tuning recommendations, and multi-format exports.

### Core capabilities

- **7 platform knowledge bases** — Armis (ASQ), Cribl (KQL), Obsidian (OQL), Okta (EventHook/SCIM), Palo Alto Networks (PAN-OS Filter), ProofPoint (Smart Search), SentinelOne (S1QL)
- **Multi-format rule parser** — auto-detects format; normalises to a canonical condition list
- **Platform-aware synthetic telemetry** — generates structurally correct log events per KB field schema
- **Dynamic detection engine** — evaluates parsed rule conditions at runtime without human-written engine code
- **8-technique evasion testing** — case manipulation, base64, path traversal, env-var expansion, SysWOW64 redirect, space insertion, double extension, Unicode substitution
- **KB-grounded recommendations** — maps FPR/FNR/perf guidelines from each platform's KB into prioritised fix cards
- **Full export suite** — self-contained HTML report, JSON payload, CSV (metrics + recs + events)
- **Real log import** — JSON / JSONL / CSV upload with category auto-detection
- **Streamlit UI** — 8-tab dark cybersecurity interface with live parse preview and popup report viewer

---

## 2. Repository Layout

```
project-root/
├── app.py                          # Streamlit application (~2,400 lines)
├── detection_validator.py          # Core framework library v3.0.0 (~2,400 lines)
├── detection_rule_validation_prompt.md  # Reusable 4-phase validation prompt
├── knowledge_bases/                # One JSON file per supported platform
│   ├── armis_centrix_knowledge_base.json
│   ├── cribl_datalake_detection_knowledge_base.json
│   ├── obsidian_security_detection_knowledge_base.json
│   ├── okta_detection_engineering_knowledge_base.json
│   ├── palo_alto_firewall_knowledge_base.json
│   ├── proofpoint_email_security_knowledge_base.json
│   └── sentinelone_knowledge_base.json
└── copilot-instructions.md         # ← this file
```

> **KB filenames may have a timestamp prefix** (e.g. `1747301234_sentinelone_knowledge_base.json`).
> The loader in `app.py` handles this via partial-stem matching — never rename KB files
> without updating `_find_kb_path()`.

---

## 3. Architecture Map

### 3.1 `detection_validator.py` — Framework Library

This is the **sole source of truth** for all core data models, matching logic, metrics,
and report generation. `app.py` imports it as `dv`. Never duplicate logic from this
file in `app.py`.

| Class / Symbol | Responsibility |
|----------------|----------------|
| `ValidationError` | Typed exception for all framework validation failures |
| `EventCategory` (Enum) | `TRUE_POSITIVE`, `TRUE_NEGATIVE`, `FALSE_POSITIVE_CANDIDATE`, `EVASION` |
| `SyntheticEvent` | Dataclass: a single test event with label, log data, tags, notes |
| `DetectionResult` | Dataclass: match result with matched conditions and confidence |
| `TestResult` | Dataclass: `SyntheticEvent + DetectionResult → TP/FP/TN/FN + passed` |
| `TelemetryGenerator` | Base class — subclass to generate platform-specific synthetic events |
| `DetectionEngine` | Base class — subclass to implement rule matching; all field matchers live here |
| `GradingConfig` | Configurable composite score weights; `validate_weights()` enforces sum = 1.0 |
| `TestRunner` | Orchestrates run → metrics → reports; `progress_callback` for Streamlit |
| `RuleComparator` | A/B comparison of two engine versions; cached `compare()` result |
| `ExampleRundll32Generator` | Demo telemetry generator (Sigma/Sysmon EventID 1) |
| `ExampleRundll32Engine` | Demo v1 rule — intentionally weak, used for regression demo |
| `ImprovedRundll32Engine` | Demo v2 rule — improved, used as comparison target |

#### Field matching utilities on `DetectionEngine`

All matchers are `@staticmethod` and handle both flat keys (`'src.process.cmdline'`)
and nested dict paths (`{'src': {'process': {'cmdline': '…'}}}`) via `nested_get()`.

| Method | Notes |
|--------|-------|
| `nested_get(event, field)` | Resolves flat or nested dot-path — **always use this, never `event.get(field)` directly** |
| `field_equals` | Case-insensitive by default |
| `field_contains` / `field_not_contains` | Substring check |
| `field_startswith` / `field_endswith` | Prefix/suffix check |
| `field_regex(event, field, pattern)` | Catches `re.error` — never raises on bad patterns |
| `field_wildcard(event, field, pattern)` | Glob (`*`/`?`) via `fnmatch` |
| `field_in` / `field_not_in` | Exact-match membership |
| `field_any_of` / `field_all_of` | Substring membership (ANY/ALL) |
| `field_gt` / `field_gte` / `field_lt` / `field_lte` | Numeric comparisons |
| `field_between(event, field, low, high)` | Inclusive numeric range |
| `field_count` | Count occurrences of pattern in field |
| `field_length_gt` / `field_length_lt` | String length bounds |
| `field_exists` | Non-null, non-empty presence check |
| `check_original_filename` | PE header–based renamed-binary detection |
| `check_process_lineage` | Parent-child chain validation |

#### `TestRunner` result accessors (use these, not list comprehensions)

```python
runner.get_by_outcome("FN")     # → list[TestResult]
runner.get_failures()           # FP + FN
runner.get_true_positives()
runner.get_false_positives()
runner.get_false_negatives()
runner.get_evasion_missed()     # Evasion events the rule failed to catch
runner.iter_results()           # Iterator — avoids materialising full list
```

#### Export methods

```python
runner.print_report(recommendations=[...])   # Console — includes RECOMMENDATIONS section
runner.export_report_json(recommendations)   # dict — JSON-serialisable
runner.export_html_report(path, recommendations)
runner.export_csv(recommendations)           # 4-section CSV string
```

---

### 3.2 `app.py` — Streamlit Application

`app.py` is a single-file Streamlit app. It imports `detection_validator` as `dv`
via `importlib` so it can be resolved from the project root at runtime.

#### Module-level constants

```python
PLATFORM_META = {
    "SentinelOne EDR": {
        "kb_file": "sentinelone_knowledge_base.json",
        "lang": "S1QL",
        "log_source": "Process, Network, File events",
        "icon": "🛡️",
        "color": "#8b5cf6",
    },
    # … 6 more platforms
}
```

> **Adding a new platform:** add an entry to `PLATFORM_META`, add a KB JSON to
> `knowledge_bases/`, implement the corresponding branch in `get_kb_field_schema()`,
> `get_kb_tuning_guidelines()`, `get_kb_evasion_guidance()`, and add a
> `_base_<platform>_event()` helper in `PlatformGenerator`.

#### Key classes in `app.py`

| Class | Responsibility |
|-------|----------------|
| `RuleParser` | Auto-detects format (Sigma/KQL/S1QL/PAN-OS/ASQ/OQL/Okta/ProofPoint/Generic); returns normalised `{rule_name, format, conditions, filters, logic, log_source, mitre}` |
| `DynamicEngine(dv.DetectionEngine)` | Evaluates parsed rule conditions at runtime using `dv.DetectionEngine` matchers; never requires a hand-written `evaluate()` per rule |
| `PlatformGenerator(dv.TelemetryGenerator)` | Extends base generator with KB field schemas; generates platform-correct log events |
| `LogImporter` | Parses JSON/JSONL/CSV uploads; auto-detects or manual-labels categories; merges with synthetic events; caps at 300 events |

#### Key functions in `app.py`

| Function | Signature | Notes |
|----------|-----------|-------|
| `load_kb(platform_name)` | `→ dict` | `@st.cache_data`; auto-searches for timestamp-prefixed filenames |
| `get_kb_field_schema(kb, platform)` | `→ dict` | Returns platform-specific field names for telemetry generation |
| `get_kb_tuning_guidelines(kb)` | `→ {fpr, fnr, perf}` | For recommendation engine |
| `get_kb_evasion_guidance(kb)` | `→ list[str]` | Injected into evasion event notes |
| `generate_recommendations(results, metrics, parsed_rule, kb)` | `→ list[dict]` | Full KB-grounded recommendations; each item: `{priority, title, body, fix, source}` |
| `build_html_report(results, metrics, recommendations, rule_name, platform, parsed_rule)` | `→ str` | Self-contained HTML; never writes a file, returns the string |
| `build_csv_export(results, metrics, recommendations)` | `→ str` | 4-section CSV |
| `show_popup_button(html_content, rule_name)` | `→ None` | Renders inline HTML modal with Print/Download/Close |

#### UI tab layout

```
Tab 0: Overview          — Grade badge, metric cards, confusion matrix, KB status bar
Tab 1: Test Matrix       — 4 phase cards (TP/Evasion/FP/TN) with pass rates
Tab 2: Recommendations   — Priority pills, expandable rec cards with fix boxes
Tab 3: False Negatives   — Per-FN "why missed" + KB notes + expandable JSON
Tab 4: False Positives   — Per-FP "why fired" + fix suggestion
Tab 5: Evasion           — Resistance score card + per-event caught/bypass status
Tab 6: Event Log         — Filterable table (first 200 events) + expandable rows
Tab 7: Rule Analysis     — Parsed conditions, KB detection pattern examples
```

---

## 4. Data Flow

```
User pastes rule
      │
      ▼
RuleParser.parse()
  → {rule_name, format, conditions[], filters[], logic, log_source, mitre[]}
      │
      ├──► DynamicEngine(parsed_rule)          ← evaluates events at runtime
      │
      └──► PlatformGenerator(parsed_rule, kb)
             ├── generate_true_positives(n)    ← uses _build_positive_values()
             ├── generate_evasion_samples(n)   ← 8 evasion transforms
             ├── generate_fp_candidates(n)     ← benign_overrides()
             └── generate_true_negatives(n)
                      │
                      ▼
              LogImporter.merge(uploaded_events)   ← optional real logs
                      │
                      ▼
              dv.TestRunner.run(progress_callback=st.progress)
                      │
                      ▼
              dv.TestRunner.get_metrics()
                      │
                      ├──► generate_recommendations(results, metrics, parsed_rule, kb)
                      │
                      ├──► build_html_report(...)    → st.download_button
                      ├──► export_report_json(...)   → st.download_button
                      └──► build_csv_export(...)     → st.download_button
```

---

## 5. Coding Standards

### 5.1 Python

- **Minimum Python version:** 3.11 (uses `list[T]` generic syntax, `match` statement optional)
- **Type hints:** required on all public functions and class methods; use `Optional[T]` for nullable params
- **`from __future__ import annotations`** must be the first import in both `detection_validator.py` and `app.py`
- **No bare `except:`** — always catch specific exception types
- **`re.error` must always be caught** when calling `re.search` / `re.compile` on user-provided patterns
- **`nested_get()` must be used** instead of `event.get(field)` whenever reading log event fields — it handles both flat-key S1QL exports and nested raw JSON schemas
- **No global mutable state** in `detection_validator.py` — all state lives on class instances
- **`@st.cache_data`** on every function in `app.py` that loads files or performs expensive computation without side effects
- **No `datetime.utcnow()`** — use `datetime.datetime.now(datetime.UTC)` or `datetime.datetime.utcnow()` with a comment that the DeprecationWarning is accepted until Python 3.12 is the minimum

### 5.2 Streamlit

- **Never call `st.rerun()`** inside a function called from a tab — it resets all widget state
- **`st.session_state` key naming:** use `snake_case` with a module prefix, e.g. `dv_results`, `dv_metrics`, `dv_recommendations`
- **All expensive computation** (telemetry generation, rule evaluation, recommendation generation) must happen inside the "RUN VALIDATION" button's `if st.button(...)` block, not on every rerender
- **`st.progress()`** must receive the `progress_callback` from `TestRunner.run()` — do not call `st.progress` from inside the runner itself
- **HTML in `st.markdown()`:** always pass `unsafe_allow_html=True` explicitly — do not rely on defaults

### 5.3 Knowledge Base integration

- **Never hard-code field names** that belong in a KB — always extract from `get_kb_field_schema()`
- **Never hard-code tuning advice** that belongs in a KB — always source from `get_kb_tuning_guidelines()`
- **KB load failures must degrade gracefully** — if a KB file is missing, the UI must show a warning indicator and continue with reduced functionality, not crash
- **ProofPoint KB fix:** `_fix_json()` in `app.py` patches the embedded double-quote bug in `proofpoint_email_security_knowledge_base.json` — do not remove this function even if the file is later corrected, as it is a safety net

### 5.4 Detection engine

- **`DynamicEngine` must never import or reference** a platform-specific class directly — all evaluation goes through the `DetectionEngine` base class matchers
- **Confidence scoring** must always be `round(value, 2)` and clamped to `[0.0, 1.0]`
- **`matched_conditions`** must contain human-readable strings describing *which* condition matched, not raw field/value pairs — they are displayed directly in the UI

### 5.5 Telemetry generator

- **Every event must have a unique `event_id`** from `_next_id(prefix)` — never hardcode IDs
- **All events must have their `tags` list populated** — they drive the Evasion tab's bypass classification
- **Evasion events must set `expected_detection=True`** — they are attack variants, not benign noise
- **FP candidate events must set `expected_detection=False`** — they are benign, not attacks
- **`_random_ip(internal=False)`** must never produce RFC-1918 / loopback / multicast addresses — the blocklist in v3 must be maintained

---

## 6. Recommendation Engine Contract

`generate_recommendations()` in `app.py` returns `list[dict]` where every dict conforms to:

```python
{
    "priority": "critical" | "high" | "medium" | "low" | "info",
    "title":    str,         # Short headline, shown in badge
    "body":     str,         # 1–4 sentence explanation
    "fix":      str,         # Specific actionable fix, 1–2 sentences max
    "source":   str,         # "confusion_matrix" | "evasion" | "rule_structure" | "kb_<platform>" | "performance"
}
```

Priority escalation rules (do not change without security review):

| Condition | Priority |
|-----------|----------|
| Any FN detected | `critical` |
| Recall < 0.8 | `high` |
| Any FP detected | `high` |
| Precision < 0.85 with no filters | `high` |
| Any evasion missed | `critical` |
| Case-manipulation bypass | `high` |
| Base64 bypass | `high` |
| OR logic with > 5 conditions | `medium` |
| No OriginalFileName check (Sigma/S1) | `medium` |
| No conditions parsed | `critical` |
| KB FPR guideline | `medium` |
| KB FNR guideline | `low` |
| Avg eval time > 5 ms | `info` |

---

## 7. Export Format Contracts

### 7.1 JSON report (single-engine)

```json
{
  "framework_version": "3.0.0",
  "rule_name": "...",
  "rule_metadata": {},
  "generated_at": "2026-02-18T22:33:00Z",
  "metrics": {
    "confusion_matrix": {"TP": 0, "FP": 0, "TN": 0, "FN": 0},
    "accuracy": 0.0,
    "precision": 0.0,
    "recall": 0.0,
    "f1_score": 0.0,
    "evasion_resistance": 0.0,
    "evasion_caught": 0,
    "evasion_total": 0,
    "fp_candidates_triggered": 0,
    "fp_candidates_total": 0,
    "overall_grade": "A",
    "composite_score": 0.0,
    "total_events": 0,
    "total_passed": 0,
    "total_failed": 0,
    "category_breakdown": {},
    "avg_execution_time_ms": 0.0
  },
  "recommendations": [{"priority": "...", "title": "...", "body": "...", "fix": "...", "source": "..."}],
  "results": [
    {
      "event_id": "EVT-0001",
      "category": "true_positive",
      "description": "...",
      "attack_technique": "T1218.011",
      "expected_detection": true,
      "actual_detection": true,
      "matched_conditions": ["..."],
      "confidence": 0.95,
      "execution_time_ms": 0.003,
      "outcome": "TP",
      "passed": true,
      "log_data": {},
      "notes": "...",
      "tags": ["..."],
      "source": "synthetic"
    }
  ]
}
```

### 7.2 JSON report (comparison / A/B mode)

```json
{
  "engine_a": {"name": "...", "metrics": {}},
  "engine_b": {"name": "...", "metrics": {}},
  "deltas": {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1_score": 0.0, "evasion_resistance": 0.0, "composite_score": 0.0},
  "outcome_diffs": [{"event_id": "...", "engine_a_outcome": "FN", "engine_b_outcome": "TP", ...}],
  "total_diffs": 0,
  "verdict": "SIGNIFICANT_IMPROVEMENT"
}
```

### 7.3 CSV structure (4 mandatory sections)

```
=== METRICS ===
key,value
...

=== CONFUSION MATRIX ===
TP,<n>
FP,<n>
TN,<n>
FN,<n>

=== RECOMMENDATIONS ===
priority,title,body,fix
...

=== EVENT RESULTS ===
event_id,category,description,expected,actual,outcome,passed,confidence,matched_conditions,source,tags
...
```

> **Do not rename, reorder, or drop** any of these sections — downstream dashboards ingest this format.

---

## 8. Grading Scale

| Grade | Composite Score | Interpretation |
|-------|----------------|----------------|
| A | ≥ 0.90 | Production-ready — deploy with standard monitoring |
| B | ≥ 0.80 | Near-production — address high-priority findings before deploy |
| C | ≥ 0.70 | Significant gaps — fix critical/high issues first |
| D | ≥ 0.60 | High risk — major rework required |
| F | < 0.60 | Do not deploy — rule is unreliable |

**Composite score formula:**

```
composite = (F1 × 0.40) + (evasion_resistance × 0.30) + ((1 − FP_rate) × 0.30)
```

If there are zero evasion events, `evasion_resistance` defaults to `1.0` (no penalty).
Weights must always sum to 1.0 — enforced by `GradingConfig.validate_weights()`.

---

## 9. Supported Rule Formats

| Format | Detection heuristic | Canonical operators used |
|--------|---------------------|--------------------------|
| **Sigma** (YAML) | `title:` or `detection:` key present | `contains`, `contains\|all`, `endswith`, `startswith`, `base64offset\|contains` |
| **KQL** | `has`, `has_any`, `has_all` operators | `has`, `has_any`, `has_all`, `startswith`, `endswith`, `matches regex`, `contains`, `==` |
| **S1QL v1** | `ContainsCIS`, `RegExp`, `StartsWith`, `EndsWith` | S1QL v1 functions |
| **S1QL v2** | Dot-notation fields (`src.process.cmdline`) | `contains`, `matches`, inline |
| **PAN-OS Filter** | `eq`, `contains` in a filter string | `eq`, `contains` |
| **ASQ** (Armis) | `in:`, `type =` device query syntax | Custom ASQ operators |
| **OQL** (Obsidian) | `event.type`, `outcome` activity syntax | OQL equality/membership |
| **Okta EventHook** | `eventType`, `outcome.result` JSON | JSON field equality |
| **ProofPoint Smart Search** | `msg.threat`, `msg.sender` field prefix | Smart Search operators |
| **Generic fallback** | Any unrecognised format | Regex-extracted `field=value` pairs |

When adding a new format:
1. Add a detection branch in `RuleParser._detect_format()`
2. Add a parsing branch in `RuleParser._parse_conditions()`
3. Add a `_base_<format>_event()` helper in `TelemetryGenerator` (if new log schema)
4. Add a KB or at minimum a `PLATFORM_META` entry
5. Update this table

---

## 10. Evasion Test Technique Registry

Every evasion sample generated by `PlatformGenerator.generate_evasion_samples()` must
tag its event with exactly one of these canonical technique labels. These labels drive
the Evasion tab's per-technique risk assessment.

| Tag | What it tests |
|-----|---------------|
| `case_manipulation` | Uppercase/lowercase field values bypassing case-sensitive rules |
| `env_variable_sub` | `%TEMP%`, `$HOME`, `%SYSTEMROOT%` path expansion |
| `path_traversal` | `..\\`, `../` in DLL/binary paths |
| `double_extension` | `payload.dll.exe`, `document.pdf.bat` |
| `syswow64_redirect` | SysWOW64 vs System32 path variants |
| `space_insertion` | Spaces or null-bytes in command-line arguments |
| `b64_encoding` | Base64-encoded payloads in `CommandLine` |
| `unicode_substitution` | Look-alike Unicode characters in binary names |
| `renamed_binary` | Binary renamed on disk; OriginalFileName still correct |
| `filter_bypass` | Abusing an allowlist entry (e.g. shell32.dll + path traversal) |
| `pe_metadata` | PE header metadata discrepancy (OriginalFileName ≠ Image) |
| `unc_path` | UNC share paths (`\\server\share\dll`) |
| `masquerade` | Binary name mimics a legitimate process |
| `parent_spoof` | Parent PID spoofed to a trusted process |

---

## 11. Knowledge Base JSON Schema

Each KB file must conform to this top-level structure. The loader uses duck-typing —
missing sections degrade gracefully, never crash.

```json
{
  "platform_name": "SentinelOne EDR",
  "platform_version": "...",
  "namespaces": {                        // OR "data_models" OR "system_log_event"
    "process_event": {
      "fields": [
        {"name": "src.process.cmdline", "type": "string", "description": "..."},
        ...
      ]
    }
  },
  "detection_engineering": {
    "query_language": "S1QL",
    "tuning_guidelines": {
      "false_positive_reduction": ["Exclude known-good hashes", "..."],
      "false_negative_reduction": ["Add OriginalFileName", "..."],
      "performance":              ["Index high-cardinality fields", "..."]
    },
    "detection_patterns": {
      "process_injection": {
        "description": "...",
        "mitre_attack": ["T1055"],
        "example_query": "..."
      }
    }
  },
  "false_negative_reduction": ["..."],  // top-level fallback
  "testing_and_validation": {
    "evasion_techniques": ["..."]
  }
}
```

---

## 12. Testing Requirements

Before submitting any change:

### Framework library (`detection_validator.py`)

```bash
# 1. Syntax check
python3 -c "import ast; ast.parse(open('detection_validator.py').read()); print('OK')"

# 2. Run built-in demo (must exit 0, must show grade A or B)
python3 detection_validator.py --engine improved --seed 42 --quiet

# 3. Run A/B comparison (verdict must be SIGNIFICANT_IMPROVEMENT)
python3 detection_validator.py --compare --seed 42 --quiet

# 4. Export all formats
python3 detection_validator.py --html /tmp/test.html --json /tmp/test.json --csv /tmp/test.csv --quiet

# 5. Verify specific bug fixes
python3 -c "
from detection_validator import GradingConfig, DetectionEngine, ValidationError
g = GradingConfig()
assert all(g.compute_grade(s) == gr for s, gr in [(0.95,'A'),(0.85,'B'),(0.75,'C'),(0.65,'D'),(0.40,'F')])
assert DetectionEngine.field_regex({'f': 'test'}, 'f', '[invalid(') == False
assert DetectionEngine.nested_get({'src': {'process': {'cmdline': 'evil'}}}, 'src.process.cmdline') == 'evil'
try:
    GradingConfig(f1_weight=0.5, evasion_weight=0.5, fp_weight=0.5).validate_weights()
    raise AssertionError('Should have raised ValidationError')
except ValidationError:
    pass
print('All assertions passed')
"
```

### Streamlit app (`app.py`)

```bash
# 1. Syntax check
python3 -c "import ast; ast.parse(open('app.py').read()); print('OK')"

# 2. Import check (must not raise)
python3 -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('app', 'app.py')
# Don't exec — just parse
import ast; ast.parse(open('app.py').read())
print('Import structure OK')
"

# 3. Run app (manual smoke test)
streamlit run app.py
```

### Checklist before every PR / commit

- [ ] Both files pass `ast.parse()` with zero syntax errors
- [ ] `GradingConfig.compute_grade()` returns the correct grade for all 5 score bands
- [ ] `field_regex()` returns `False` (not exception) on malformed patterns
- [ ] `nested_get()` resolves both flat and nested field paths
- [ ] `validate_weights()` raises `ValidationError` on bad weight sums
- [ ] CLI `--export-events` flag reuses the existing generator instance
- [ ] `RuleComparator.compare()` returns the same dict on repeated calls (cached)
- [ ] All 7 KB platforms load without error when `knowledge_bases/` is present
- [ ] ProofPoint KB loads without JSON parse error (`_fix_json()` applied)
- [ ] `export_csv()` output contains all 4 mandatory section headers
- [ ] HTML report contains: confusion matrix, evasion analysis, category breakdown, recommendations
- [ ] No `datetime.utcnow()` deprecation warnings in Python 3.12+

---

## 13. Adding a New Platform

Follow this exact checklist to add full support for a new platform:

1. **KB file:** Add `<platform>_knowledge_base.json` to `knowledge_bases/` following the schema in §11
2. **`PLATFORM_META`:** Add entry with `kb_file`, `lang`, `log_source`, `icon`, `color`
3. **`get_kb_field_schema()`:** Add `elif platform == "My Platform":` branch extracting field names
4. **`get_kb_tuning_guidelines()`:** Ensure the new KB's `tuning_guidelines` keys are handled
5. **`get_kb_evasion_guidance()`:** Ensure evasion tips are extracted from the new KB
6. **`_base_<platform>_event()` in `TelemetryGenerator`:** Add realistic base event template using fields from the KB schema
7. **`PlatformGenerator._base_event()`:** Add `elif "My Platform" in self.platform_name:` branch
8. **`PlatformGenerator._benign_overrides()`:** Add benign field values for the new platform
9. **`RuleParser._detect_format()`:** Add format auto-detection heuristics if the platform uses a unique query language
10. **`RuleParser._parse_conditions()`:** Add condition parsing branch for the new language
11. **Update `PLATFORM_META` doc string** and this §13 checklist
12. **Run full test suite** (§12) against a sample rule from the new platform

---

## 14. Known Limitations

| Limitation | Workaround |
|------------|------------|
| `evasion_resistance` is `None` when no evasion events are in the test set | Treat `None` as 1.0 (no penalty) in composite score; display "N/A" in UI |
| S1QL v1 and v2 use different field naming conventions | `RuleParser` detects version by presence of dot-notation; `nested_get()` handles both |
| ProofPoint KB has embedded double-quotes in field names | `_fix_json()` patches this with regex before `json.loads()` |
| `LogImporter` caps imports at 300 events | Documented in UI; users are warned via `st.warning()` |
| `RuleComparator` requires events list to be identical for both engines | Always pass the same list; do not re-generate between engine runs |
| Timestamp-prefixed KB filenames (CI/CD may add timestamps) | `_find_kb_path()` uses partial stem matching; do not rely on exact filename |

---

## 15. Versioning

- **`detection_validator.py`** is versioned via `__version__` at the module level (currently `"3.0.0"`)
- **`app.py`** version is in the module docstring (currently `"Detection Rule Validator v6"`)
- When releasing a new major version of `detection_validator.py`, update `__version__`, the module docstring changelog, and the `framework_version` field in JSON exports
- `app.py` does not expose a version number to users in the UI — update the docstring only

---

## 16. Dependency Manifest

### `detection_validator.py` (zero third-party dependencies)

```
csv, datetime, fnmatch, hashlib, io, json, re, string, sys, time, uuid,
random, argparse, collections.Counter, dataclasses, enum, pathlib.Path, typing
```

### `app.py`

```
streamlit >= 1.32.0
```

All other imports in `app.py` (`csv`, `json`, `re`, `io`, `pathlib`, `datetime`, `importlib`) are stdlib.

> `detection_validator.py` **must remain zero-dependency** — it is designed to be
> dropped into any Python 3.11+ environment without a `requirements.txt`.

---

## 17. Security Notes

- **No user input is executed** — `RuleParser` extracts conditions declaratively; `DynamicEngine` calls pre-defined matcher methods with extracted field/value pairs. No `eval()`, `exec()`, or `subprocess` is used on rule content.
- **`field_regex()` sanitisation:** malformed patterns return `False` silently — they do not raise, log errors, or expose the pattern to the user.
- **Uploaded log files** are parsed with `json.loads()` / `csv.reader` only — no pickle, no YAML `load()`, no `eval()`.
- **Knowledge base files** are loaded with `json.loads()` via `_fix_json()` pre-processing — no YAML, no pickle.
- **HTML exports** use Python f-string templating — no Jinja2, no template injection surface. Event data rendered into HTML must be truncated at 700 characters to prevent excessively large inline payloads.
