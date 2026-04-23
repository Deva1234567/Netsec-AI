"""
realtime_pipeline.py — NetSec AI v11.0
========================================
Real-time Wazuh → IOC Extract → Enrich → Score → Narrative → Splunk pipeline.

This file ONLY wires together what already exists in your codebase.
It adds zero duplicate logic — just the glue.

Architecture
────────────
Wazuh alert (webhook / poll)
    │
    ▼
Stage 1 — IOC Extraction       (_extract_iocs_from_alerts  in triage.py)
    │
    ▼
Stage 2 — Threat Intel Enrich  (IOCEnricher.batch_enrich   in ioc_enricher.py)
    │
    ▼
Stage 3 — Score + Correlate    (DynamicRiskScorer + CorrelationEngine)
    │
    ▼
Stage 4 — AI Narrative         (_build_narrative_from_alerts in investigate.py)
    │
    ▼
Stage 5 — Push to Splunk       (send_to_splunk / queue_alert in splunk_handler.py)
    │
    ▼
Stage 6 — Store + Notify       (session state + live dashboard feed)

How to use
──────────
Option A — Automatic (runs every N seconds in background thread):
    from realtime_pipeline import PipelineEngine
    PipelineEngine.start(poll_interval=30)   # polls Wazuh every 30s

Option B — Manual trigger (call from app.py button):
    from realtime_pipeline import PipelineEngine
    result = PipelineEngine.run_once()

Option C — Webhook mode (Wazuh posts alerts directly):
    POST http://localhost:8001/pipeline/ingest
    Body: {"alerts": [...]}   ← Wazuh alert JSON array

Add to app.py sidebar:
    from realtime_pipeline import render_pipeline_dashboard
    render_pipeline_dashboard()
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any

logger = logging.getLogger("netsec.pipeline")

# ── Path setup (works whether file is in root or modules/) ───────────────────
_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in [_HERE, _PARENT,
           os.path.join(_HERE,   "modules"),
           os.path.join(_PARENT, "modules")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Safe streamlit import ────────────────────────────────────────────────────
try:
    import streamlit as st
    _ST = True
except ImportError:
    _ST = False

# ══════════════════════════════════════════════════════════════════════════════
# MODULE IMPORTS  (all graceful — pipeline runs even if some modules missing)
# ══════════════════════════════════════════════════════════════════════════════
def auto_trigger_n8n(alert_result: dict):
    """Automatically trigger n8n SOAR for high-risk alerts"""
    score = alert_result.get("risk_score", alert_result.get("composite_score", 0))
    verdict = alert_result.get("verdict", "").upper()
    severity = alert_result.get("risk_label", alert_result.get("severity", "")).lower()

    # Only trigger for Critical or High risk
    if score >= 80 or severity in ["critical", "high"] or verdict in ["CRITICAL", "CONFIRMED_THREAT"]:
        
        payload = {
            "action": "critical_alert",
            "ip": alert_result.get("raw_alert", {}).get("data", {}).get("srcip") or 
                  alert_result.get("context", {}).get("agent_ip"),
            "domain": alert_result.get("enrichment", [{}])[0].get("ioc") if alert_result.get("enrichment") else None,
            "threat_score": score,
            "severity": severity or "high",
            "mitre": alert_result.get("mitre_id", ""),
            "category": alert_result.get("category", "Unknown"),
            "agent": alert_result.get("raw_alert", {}).get("agent", {}).get("name", ""),
            "timestamp": _ts(),
            "alert_id": alert_result.get("alert_id", "auto"),
            "executive_summary": alert_result.get("executive_summary", "")[:300]
        }

        success, result = _post("/webhook/soc-alert", payload)

        if success:
            logger.info(f"[AUTO-SOAR] ✅ Triggered n8n for alert {alert_result.get('alert_id')} (Score: {score})")
        else:
            logger.error(f"[AUTO-SOAR] ❌ n8n trigger failed: {result.get('error')}")
# Stage 1 — IOC extraction (triage.py)
try:
    from triage import _extract_iocs_from_alerts
    _IOC_EXTRACT = True
except ImportError:
    _IOC_EXTRACT = False
    def _extract_iocs_from_alerts(alerts):
        import re
        seen, iocs = set(), []
        for a in alerts:
            raw = json.dumps(a)
            for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw):
                if ip not in seen and not ip.startswith(("192.168","10.","127.","172.")):
                    seen.add(ip); iocs.append((ip, "ip"))
            for dom in re.findall(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|xyz|tk|cc|ru|cn|in)\b', raw.lower()):
                if dom not in seen and len(dom) > 5:
                    seen.add(dom); iocs.append((dom, "domain"))
        return iocs[:20]

# Stage 2 — Enrichment (ioc_enricher.py)
try:
    from ioc_enricher import IOCEnricher
    _ENRICHER = True
except ImportError:
    _ENRICHER = False
    class IOCEnricher:
        @staticmethod
        def enrich(ioc, ioc_type="auto", session_config=None):
            return {"ioc": ioc, "ioc_type": ioc_type, "unified_score": 50,
                    "verdict": "UNKNOWN", "sources": {}, "error": "ioc_enricher not loaded"}
        @staticmethod
        def batch_enrich(iocs, progress_container=None):
            return [IOCEnricher.enrich(ioc, t) for ioc, t in iocs]

# Stage 3a — Reputation scoring (reputation_engine.py)
try:
    from reputation_engine import ReputationEngine
    _REP = True
except ImportError:
    _REP = False
    class ReputationEngine:
        @staticmethod
        def score(ioc, use_apis=False):
            return {"score": 50, "verdict": "UNKNOWN", "signals": []}

# Stage 3b — Dynamic risk + correlation (enterprise_soc.py)
try:
    from enterprise_soc import DynamicRiskScorer, CorrelationEngine, FalsePositiveKiller
    _ENTERPRISE = True
except ImportError:
    _ENTERPRISE = False
    class DynamicRiskScorer:
        @staticmethod
        def score(ioc, **kw):
            rep = ReputationEngine.score(ioc)
            s = max(0, 100 - rep.get("score", 50))
            return {"composite_score": s, "risk_level": "HIGH" if s > 60 else "MEDIUM" if s > 30 else "LOW",
                    "recommendation": "Investigate", "breakdown": {}}
    class CorrelationEngine:
        @staticmethod
        def correlate(alert):
            return {"verdict": "UNKNOWN", "confidence": 0, "iocs_checked": [],
                    "misp_hits": [], "mitre_tags": [], "threat_actors": [], "reason": "enterprise_soc not loaded"}
    class FalsePositiveKiller:
        @staticmethod
        def is_false_positive(ioc, current_count=1, rep_score=50):
            return rep_score >= 72, f"Rep score {rep_score}/100"

# Stage 4 — Narrative (investigate.py)
try:
    from investigate import _build_narrative_from_alerts, _autonomous_investigate
    _NARRATIVE = True
except ImportError:
    _NARRATIVE = False
    def _build_narrative_from_alerts(alerts, incidents, analyst_name="Pipeline"):
        ips    = [a.get("ip", a.get("domain", "?")) for a in alerts[:3]]
        scores = [a.get("threat_score", a.get("score", 50)) for a in alerts]
        max_s  = max(scores) if scores else 0
        return {
            "executive_summary": (
                f"Pipeline processed {len(alerts)} alert(s). "
                f"IOCs: {', '.join(ips)}. Max threat score: {max_s}/100."
            ),
            "severity_verdict": "HIGH" if max_s > 60 else "MEDIUM" if max_s > 30 else "LOW",
            "confidence": 60,
            "recommended_actions": [
                f"Investigate IOC: {ips[0]}" if ips else "Review alerts",
                "Check Wazuh for lateral movement",
                "Correlate with Splunk logs",
            ],
            "timeline": [],
            "attack_phases_observed": [],
        }
    def _autonomous_investigate(alert):
        return {"summary": f"Auto-investigate: {alert.get('domain', alert.get('ip', '?'))}",
                "severity": "medium", "confidence": 50}

# Stage 5 — Splunk push (splunk_handler.py)
try:
    from splunk_handler import send_to_splunk, build_siem_alert, queue_alert
    _SPLUNK = True
except ImportError:
    _SPLUNK = False
    def send_to_splunk(d):  return False, "splunk_handler not loaded"
    def build_siem_alert(*a, **kw): return {}
    def queue_alert(r): pass

# Wazuh alerts fetch (soc_enhancements.py)
try:
    from soc_enhancements import wazuh_get_alerts, wazuh_health_check
    _WAZUH = True
except ImportError:
    _WAZUH = False
    def wazuh_get_alerts(**kw): return []
    def wazuh_health_check(**kw): return {"status": "error", "message": "soc_enhancements not loaded"}


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE RESULT STORE  (in-memory ring buffer — last 200 results)
# ══════════════════════════════════════════════════════════════════════════════

_RESULTS: deque = deque(maxlen=200)
_STATS = {
    "total_alerts":      0,
    "total_iocs":        0,
    "confirmed_threats": 0,
    "false_positives":   0,
    "last_run":          None,
    "running":           False,
    "errors":            0,
}
_LOCK = threading.Lock()

# ── NEW: Asset intelligence store ─────────────────────────────────────────────
# { agent_name: { ip, os, alert_count, threat_count, last_seen, risk_score } }
_ASSETS: dict = {}

# ── NEW: Trend store — rolling 24h alert counts per hour ──────────────────────
# { "YYYY-MM-DD HH": count }
_TREND: dict = {}

# ── NEW: Category counter ─────────────────────────────────────────────────────
# { category_name: count }
_CATEGORIES: dict = {}


def _store_result(result: dict) -> None:
    with _LOCK:
        _RESULTS.appendleft(result)
        _STATS["total_alerts"]  += 1
        _STATS["total_iocs"]    += result.get("ioc_count", 0)
        _STATS["last_run"]       = datetime.utcnow().isoformat()
        v = result.get("correlation_verdict", "")
        if v == "CONFIRMED_THREAT":
            _STATS["confirmed_threats"] += 1
        elif result.get("is_fp"):
            _STATS["false_positives"] += 1


def get_results(n: int = 50) -> list:
    with _LOCK:
        return list(_RESULTS)[:n]


def get_stats() -> dict:
    with _LOCK:
        return dict(_STATS)


# ══════════════════════════════════════════════════════════════════════════════
# ALERT CLASSIFICATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Wazuh rule groups → SOC category mapping
# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 1: THREAT DETECTION LAYER
# Maps Wazuh rule groups → attack category + MITRE technique + severity + score
# ══════════════════════════════════════════════════════════════════════════════

# rule.group → (category, icon, severity, mitre_technique, tactic, base_score)
_CATEGORY_MAP = {
    # ── Authentication attacks ────────────────────────────────────────────────
    "authentication_failed":   ("Suspicious Login",       "🔐", "medium",  "T1110",    "Credential Access",  20),
    "authentication_failures": ("Brute Force Attack",     "💥", "high",    "T1110.001","Credential Access",  60),
    "invalid_login":           ("Suspicious Login",       "🔐", "medium",  "T1110",    "Credential Access",  20),
    "brute_force":             ("Brute Force Attack",     "💥", "high",    "T1110.001","Credential Access",  70),
    "authentication_success":  ("Login Activity",         "🔑", "low",     "T1078",    "Defense Evasion",    5),
    "multiple_auth_failures":  ("Brute Force Attack",     "💥", "high",    "T1110",    "Credential Access",  65),
    # ── Privilege escalation ──────────────────────────────────────────────────
    "privilege_escalation":    ("Privilege Escalation",   "👑", "critical","T1068",    "Privilege Escalation",85),
    "rootkit":                 ("Rootkit Detected",        "👑", "critical","T1014",    "Defense Evasion",    95),
    "account_changed":         ("Account Manipulation",   "👤", "medium",  "T1098",    "Persistence",        40),
    "adduser":                 ("New User Created",        "👤", "high",    "T1136",    "Persistence",        70),
    "win_account_change":      ("Account Manipulation",   "👤", "medium",  "T1098",    "Persistence",        40),
    # ── Malware & execution ───────────────────────────────────────────────────
    "malware":                 ("Malware Detected",        "🦠", "critical","T1204",    "Execution",          90),
    "virus":                   ("Malware Detected",        "🦠", "critical","T1204",    "Execution",          90),
    "trojan":                  ("Malware Detected",        "🦠", "critical","T1204",    "Execution",          92),
    "exploit":                 ("Exploit Attempt",         "💣", "high",    "T1203",    "Execution",          80),
    "shellshock":              ("Shell Exploit",           "💣", "critical","T1190",    "Initial Access",     88),
    # ── Suspicious execution ──────────────────────────────────────────────────
    "powershell":              ("Suspicious PowerShell",   "⚡", "high",    "T1059.001","Execution",          65),
    "sysmon":                  ("Process Activity",        "⚡", "medium",  "T1059",    "Execution",          30),
    "process":                 ("Process Activity",        "⚡", "low",     "T1059",    "Execution",          15),
    # ── Persistence ───────────────────────────────────────────────────────────
    "win_service":             ("Service Manipulation",    "🔧", "medium",  "T1543.003","Persistence",        45),
    "service_control":         ("Service Manipulation",    "🔧", "medium",  "T1543.003","Persistence",        45),
    "startup":                 ("Startup Persistence",     "🔧", "high",    "T1547.001","Persistence",        60),
    "registry":                ("Registry Modification",   "📋", "medium",  "T1112",    "Defense Evasion",    40),
    "scheduled_task":          ("Scheduled Task",          "📋", "medium",  "T1053.005","Persistence",        45),
    # ── File & integrity ──────────────────────────────────────────────────────
    "syscheck":                ("File Integrity Alert",    "📁", "medium",  "T1565",    "Impact",             35),
    "file_monitoring":         ("File Integrity Alert",    "📁", "medium",  "T1565",    "Impact",             35),
    # ── Network & C2 ─────────────────────────────────────────────────────────
    "ids":                     ("Intrusion Detection",     "🚨", "high",    "T1071",    "Command and Control", 75),
    "firewall":                ("Firewall Event",          "🛡️",  "medium",  "T1562.004","Defense Evasion",    30),
    "network":                 ("Network Activity",        "📡", "low",     "T1071",    "Command and Control", 10),
    "dns":                     ("DNS Activity",            "📡", "low",     "T1071.004","Command and Control", 10),
    # ── Web attacks ───────────────────────────────────────────────────────────
    "web_attack":              ("Web Attack",              "🌐", "high",    "T1190",    "Initial Access",     75),
    "sql_injection":           ("SQL Injection",           "🌐", "high",    "T1190",    "Initial Access",     80),
    "xss":                     ("XSS Attack",              "🌐", "medium",  "T1059.007","Execution",          50),
    # ── Vulnerability ─────────────────────────────────────────────────────────
    "vulnerability_detector":  ("Vulnerability Found",     "🔍", "high",    "T1210",    "Lateral Movement",   60),
    "configuration_assessment":("Misconfiguration",        "⚠️",  "medium",  "T1562",    "Defense Evasion",    30),
    # ── Windows service events (real Wazuh rule 61104) ─────────────────────────
    "win_service_start":       ("Service Started",         "🔧", "low",     "T1543.003","Persistence",        15),
    "win_service_stop":        ("Service Stopped",         "🔧", "low",     "T1543.003","Persistence",        12),
    "win_service_change":      ("Service Config Changed",  "🔧", "medium",  "T1543.003","Persistence",        40),
    "service_start":           ("Service Started",         "🔧", "low",     "T1543.003","Persistence",        15),
    "service_stop":            ("Service Stopped",         "🔧", "low",     "T1543.003","Persistence",        12),
    # ── SCA / CIS Benchmark (real Wazuh rules 19003, 19008, 19009) ───────────
    "sca":                     ("CIS Benchmark Finding",   "📋", "low",     "T1562",    "Defense Evasion",    15),
    "ciscat":                  ("CIS Benchmark Finding",   "📋", "low",     "T1562",    "Defense Evasion",    15),
    # ── Windows event log groups ─────────────────────────────────────────────
    "win_evt_channel_security":("Security Log Event",      "🛡️",  "medium",  "T1562.002","Defense Evasion",    25),
    "win_audit_policy_change": ("Audit Policy Changed",    "📋", "medium",  "T1562.002","Defense Evasion",    40),
    "win_account_logon":       ("Account Logon",           "🔑", "low",     "T1078",    "Defense Evasion",    10),
    "win_logon_event":         ("Windows Logon",           "🔑", "low",     "T1078",    "Defense Evasion",    10),
    "win_local_account":       ("Local Account Activity",  "👤", "medium",  "T1136",    "Persistence",        35),
    "win_object_access":       ("Object Access",           "📁", "low",     "T1565",    "Impact",             10),
    "win_process_execution":   ("Process Execution",       "⚡", "medium",  "T1059",    "Execution",          30),
    "win_security_essential":  ("Windows Security Event",  "🛡️",  "medium",  "T1562",    "Defense Evasion",    25),
    # ── Low noise ─────────────────────────────────────────────────────────────
    "system":                  ("System Event",            "⚙️",  "low",     "",         "Other",              5),
    "windows":                 ("Windows Event",           "🪟", "low",     "",         "Other",              8),
    "ossec":                   ("OSSEC Internal",          "🔧", "low",     "",         "Other",              3),
    "policy_violation":        ("Policy Violation",        "📋", "medium",  "T1562",    "Defense Evasion",    35),
}

# level → (severity, category, icon, base_score)
_LEVEL_MAP = {
    (0,  3):  ("low",           "System Noise",          "⬜",  3),
    (4,  6):  ("low",           "System Info",           "🔵", 10),
    (7,  9):  ("medium",        "Suspicious Activity",   "🟡", 35),
    (10, 11): ("high",          "Security Alert",        "🟠", 60),
    (12, 14): ("high",          "High Risk Event",       "🔴", 75),
    (15, 99): ("critical",      "Critical Threat",       "🚨", 90),
}

# ── FEATURE 2: MITRE ATT&CK full mapping ─────────────────────────────────────
_MITRE_DETAILS = {
    "T1110":     {"name": "Brute Force",                  "tactic": "Credential Access",   "url": "https://attack.mitre.org/techniques/T1110"},
    "T1110.001": {"name": "Password Guessing",            "tactic": "Credential Access",   "url": "https://attack.mitre.org/techniques/T1110/001"},
    "T1078":     {"name": "Valid Accounts",               "tactic": "Defense Evasion",     "url": "https://attack.mitre.org/techniques/T1078"},
    "T1068":     {"name": "Exploitation for Privilege",   "tactic": "Privilege Escalation","url": "https://attack.mitre.org/techniques/T1068"},
    "T1014":     {"name": "Rootkit",                      "tactic": "Defense Evasion",     "url": "https://attack.mitre.org/techniques/T1014"},
    "T1098":     {"name": "Account Manipulation",         "tactic": "Persistence",         "url": "https://attack.mitre.org/techniques/T1098"},
    "T1136":     {"name": "Create Account",               "tactic": "Persistence",         "url": "https://attack.mitre.org/techniques/T1136"},
    "T1204":     {"name": "User Execution",               "tactic": "Execution",           "url": "https://attack.mitre.org/techniques/T1204"},
    "T1059":     {"name": "Command & Scripting",          "tactic": "Execution",           "url": "https://attack.mitre.org/techniques/T1059"},
    "T1059.001": {"name": "PowerShell",                   "tactic": "Execution",           "url": "https://attack.mitre.org/techniques/T1059/001"},
    "T1059.007": {"name": "JavaScript",                   "tactic": "Execution",           "url": "https://attack.mitre.org/techniques/T1059/007"},
    "T1543.003": {"name": "Windows Service",              "tactic": "Persistence",         "url": "https://attack.mitre.org/techniques/T1543/003"},
    "T1547.001": {"name": "Registry Run Keys",            "tactic": "Persistence",         "url": "https://attack.mitre.org/techniques/T1547/001"},
    "T1053.005": {"name": "Scheduled Task",               "tactic": "Persistence",         "url": "https://attack.mitre.org/techniques/T1053/005"},
    "T1112":     {"name": "Modify Registry",              "tactic": "Defense Evasion",     "url": "https://attack.mitre.org/techniques/T1112"},
    "T1562.004": {"name": "Disable Firewall",             "tactic": "Defense Evasion",     "url": "https://attack.mitre.org/techniques/T1562/004"},
    "T1562":     {"name": "Impair Defenses",              "tactic": "Defense Evasion",     "url": "https://attack.mitre.org/techniques/T1562"},
    "T1565":     {"name": "Data Manipulation",            "tactic": "Impact",              "url": "https://attack.mitre.org/techniques/T1565"},
    "T1071":     {"name": "App Layer Protocol",           "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071"},
    "T1071.004": {"name": "DNS",                          "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/004"},
    "T1190":     {"name": "Exploit Public App",           "tactic": "Initial Access",      "url": "https://attack.mitre.org/techniques/T1190"},
    "T1203":     {"name": "Exploitation for Exec",        "tactic": "Execution",           "url": "https://attack.mitre.org/techniques/T1203"},
    "T1210":     {"name": "Exploitation of Remote Svcs",  "tactic": "Lateral Movement",    "url": "https://attack.mitre.org/techniques/T1210"},
}

# ── FEATURE 3: AI RISK SCORING ENGINE ────────────────────────────────────────
# Conditions stack on top of base_score from category map

def calculate_risk_score(alert: dict, base_score: int, category: str) -> tuple[int, str, list]:
    """
    Dynamic risk scoring — stacks conditions on top of base category score.
    Returns (final_score 0-100, risk_label, score_breakdown list)

    Score table:
        Base from category          0-95
        + Failed login              +20
        + Multiple failures (>5)    +40
        + Admin/privilege keyword   +25
        + Suspicious command        +30
        + New user created          +35
        + Service/startup mod       +20
        + Level bonus               +level*2
        Capped at 100
    """
    rule   = alert.get("rule", {})
    data   = alert.get("data", {})
    desc   = rule.get("description", "").lower()
    level  = int(rule.get("level", 0))
    groups = rule.get("groups", [])
    groups_str = " ".join(str(g).lower() for g in (groups if isinstance(groups, list) else [groups]))

    score     = base_score
    breakdown = [f"Base ({category}): +{base_score}"]

    # ── Condition scoring ─────────────────────────────────────────────────────
    if "authentication_failed" in groups_str or "login failed" in desc:
        score += 20; breakdown.append("Failed login: +20")

    if "multiple" in desc or "brute" in desc or "repeated" in desc:
        score += 40; breakdown.append("Multiple/repeated: +40")

    if any(k in desc for k in ["admin", "administrator", "privilege", "root", "sudo"]):
        score += 25; breakdown.append("Admin/privilege keyword: +25")

    if any(k in desc for k in ["powershell", "encoded", "cmd.exe", "wscript", "cscript", "mshta"]):
        score += 30; breakdown.append("Suspicious command: +30")

    if any(k in groups_str for k in ["adduser", "useradd"]) or "user created" in desc or "new user" in desc:
        score += 35; breakdown.append("New user created: +35")

    if any(k in groups_str for k in ["win_service", "service_control", "startup"]):
        score += 20; breakdown.append("Service/startup modification: +20")

    if any(k in desc for k in ["disabled", "stopped", "delete", "removed"]):
        score += 15; breakdown.append("Defense disabled/removed: +15")

    if any(k in desc for k in ["lateral", "remote", "smb", "rdp", "psexec"]):
        score += 25; breakdown.append("Lateral movement indicator: +25")

    # Level bonus
    level_bonus = min(20, level * 2)
    score += level_bonus
    if level_bonus:
        breakdown.append(f"Level {level} bonus: +{level_bonus}")

    # Cap
    score = min(100, score)

    # Risk label
    if score >= 80:
        label = "CRITICAL"
    elif score >= 60:
        label = "HIGH"
    elif score >= 35:
        label = "MEDIUM"
    elif score >= 15:
        label = "LOW"
    else:
        label = "INFORMATIONAL"

    return score, label, breakdown


# ── FEATURE 5: BEHAVIORAL PATTERN DETECTION ───────────────────────────────────
# Detects attack patterns across multiple alerts (not just single events)
_BEHAVIOR_WINDOW: dict = {}   # agent → {event_type: [timestamps]}

def detect_behavioral_pattern(alert: dict, category: str) -> dict:
    """
    Detect behavioral attack patterns across a rolling time window.
    Returns {pattern_detected, pattern_name, confidence, description}
    """
    import datetime as _dt
    agent_name = alert.get("agent", {}).get("name", "") or "Unidentified Host"
    now        = _dt.datetime.utcnow()
    cutoff     = now - _dt.timedelta(minutes=10)
    rule       = alert.get("rule", {})
    level      = int(rule.get("level", 0))

    # Map category to behavior bucket
    bucket_map = {
        "Suspicious Login":    "failed_login",
        "Brute Force Attack":  "failed_login",
        "Account Manipulation":"account_change",
        "New User Created":    "account_change",
        "Service Manipulation":"persistence",
        "Startup Persistence": "persistence",
        "Suspicious PowerShell":"exec_suspicious",
        "Process Activity":    "exec_suspicious",
    }
    bucket = bucket_map.get(category, "other")

    with _LOCK:
        if agent_name not in _BEHAVIOR_WINDOW:
            _BEHAVIOR_WINDOW[agent_name] = {}
        w = _BEHAVIOR_WINDOW[agent_name]
        if bucket not in w:
            w[bucket] = []
        # Prune old events
        w[bucket] = [t for t in w[bucket] if t > cutoff]
        w[bucket].append(now)
        count = len(w[bucket])

    # ── Pattern rules ─────────────────────────────────────────────────────────
    patterns = {
        "failed_login":    (5,  "🚨 Brute Force Pattern",      "T1110",    5  + 30),
        "account_change":  (2,  "👤 Account Takeover Pattern",  "T1098",    10 + 25),
        "persistence":     (2,  "🔧 Persistence Pattern",       "T1543.003",15 + 20),
        "exec_suspicious": (3,  "⚡ Suspicious Execution Pattern","T1059",   10 + 20),
    }

    if bucket in patterns:
        threshold, name, mitre, score_boost = patterns[bucket]
        if count >= threshold:
            return {
                "pattern_detected": True,
                "pattern_name":     name,
                "mitre":            mitre,
                "count":            count,
                "confidence":       min(95, 50 + count * 5),
                "score_boost":      score_boost,
                "description":      f"{count} {bucket.replace('_',' ')} events in 10 minutes on {agent_name}",
            }
    return {"pattern_detected": False}


# ── FEATURE 6: CONTEXT ENRICHMENT ─────────────────────────────────────────────
def enrich_context(alert: dict, category: str, mitre_id: str, risk_score: int) -> dict:
    """
    Adds full human-readable context to every alert:
    what happened, why it matters, MITRE details, recommended action.
    """
    rule        = alert.get("rule", {})
    agent       = alert.get("agent", {})
    data        = alert.get("data", {})
    desc        = rule.get("description", "N/A")
    _raw_agent_name = agent.get("name", "") or ""
    _raw_agent_ip   = agent.get("ip", "") or ""
    try:
        from modules.soc_brain import resolve_asset as _ra_ec
        _ec_asset  = _ra_ec(_raw_agent_name, _raw_agent_ip)
        agent_name = _ec_asset.get("display_name") or _raw_agent_name or "Unidentified Host"
    except Exception:
        agent_name = _raw_agent_name or "Unidentified Host"
    agent_ip = _raw_agent_ip or "N/A"
    src_ip      = data.get("srcip", "")
    src_user    = data.get("srcuser", data.get("dstuser", ""))
    level       = int(rule.get("level", 0))

    # Who
    who_parts = []
    if src_user:
        who_parts.append(f"User `{src_user}`")
    if src_ip:
        who_parts.append(f"from `{src_ip}`")
    who_parts.append(f"on `{agent_name}` ({agent_ip})")
    who_str = " ".join(who_parts)

    # MITRE context
    mitre_info = _MITRE_DETAILS.get(mitre_id, {})
    mitre_name   = mitre_info.get("name", "")
    mitre_tactic = mitre_info.get("tactic", "")

    # Priority → SLA
    sla_map = {"CRITICAL": "Respond NOW (15 min)", "HIGH": "Investigate (1 hr)",
                "MEDIUM": "Review (4 hr)", "LOW": "Monitor (24 hr)", "INFORMATIONAL": "Log only"}
    risk_label = ("CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else
                  "MEDIUM" if risk_score >= 35 else "LOW" if risk_score >= 15 else "INFORMATIONAL")
    sla = sla_map.get(risk_label, "Log only")

    # Playbook steps per category
    playbooks = {
        "Brute Force Attack":    ["Check source IP reputation", "Block IP if external", "Reset targeted account password", "Enable account lockout policy"],
        "Suspicious Login":      ["Verify with user if login was legitimate", "Check login time vs normal pattern", "Review recent account activity"],
        "Privilege Escalation":  ["Immediately isolate host", "Review who granted privilege", "Check for persistence mechanisms", "Audit admin group membership"],
        "New User Created":      ["Verify authorized creation", "Check if user has admin rights", "Audit all accounts on host", "Review creation source"],
        "Service Manipulation":  ["Check if service is legitimate", "Review service binary path", "Compare against baseline", "Scan with AV"],
        "Suspicious PowerShell": ["Capture and decode command", "Check parent process", "Review execution context", "Scan host for malware"],
        "Malware Detected":      ["Isolate host immediately", "Run full AV scan", "Check for lateral movement", "Preserve forensic evidence"],
        "File Integrity Alert":  ["Compare file with known-good hash", "Check who modified the file", "Review recent changes", "Restore from backup if tampered"],
        "Account Manipulation":  ["Verify change was authorized", "Check if MFA still enabled", "Review all recent account changes"],
    }
    steps = playbooks.get(category, ["Investigate alert details", "Check system logs", "Verify with endpoint owner"])

    return {
        "who":           who_str,
        "what":          desc,
        "why_matters":   f"{category} — {mitre_name}" if mitre_name else category,
        "mitre_id":      mitre_id,
        "mitre_name":    mitre_name,
        "mitre_tactic":  mitre_tactic,
        "risk_label":    risk_label,
        "sla":           sla,
        "agent_name":    agent_name,
        "agent_ip":      agent_ip,
        "playbook":      steps,
    }


# ── FEATURE 7: INCIDENT GROUPING ──────────────────────────────────────────────
_INCIDENTS: dict = {}    # incident_id → {title, alerts, opened, severity, status}
_INCIDENT_COUNTER = [0]

def group_into_incident(result: dict) -> str | None:
    """
    Groups related alerts into incidents.
    Returns incident_id if alert was grouped, else None.
    Same agent + same category within 30 minutes → same incident.
    """
    import datetime as _dt
    agent    = result.get("raw_alert", {}).get("agent", {}).get("name", "unknown")
    category = result.get("category", "unknown")
    severity = result.get("risk_label", result.get("severity_class", "low"))
    now      = _dt.datetime.utcnow()
    cutoff   = now - _dt.timedelta(minutes=30)

    with _LOCK:
        # Find existing open incident for this agent+category
        for inc_id, inc in _INCIDENTS.items():
            if (inc["agent"] == agent
                    and inc["category"] == category
                    and inc["status"] == "open"
                    and inc["last_updated"] > cutoff):
                inc["alerts"].append(result.get("alert_id", ""))
                inc["alert_count"] += 1
                inc["last_updated"] = now
                # Escalate severity if new alert is worse
                sev_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                if sev_order.get(severity, 0) > sev_order.get(inc["severity"], 0):
                    inc["severity"] = severity
                return inc_id

        # Create new incident
        _INCIDENT_COUNTER[0] += 1
        inc_id = f"INC-{_INCIDENT_COUNTER[0]:04d}"
        _INCIDENTS[inc_id] = {
            "id":           inc_id,
            "title":        f"{category} on {agent}",
            "agent":        agent,
            "category":     category,
            "severity":     severity,
            "status":       "open",
            "alert_count":  1,
            "alerts":       [result.get("alert_id", "")],
            "opened":       now,
            "last_updated": now,
        }
        return inc_id


def get_incidents(status: str = "all") -> list:
    """Return incidents sorted by severity then time."""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    with _LOCK:
        incs = list(_INCIDENTS.values())
    if status != "all":
        incs = [i for i in incs if i["status"] == status]
    return sorted(incs, key=lambda x: (sev_order.get(x["severity"], 9),
                                        -x["last_updated"].timestamp()))


def classify_alert(alert: dict) -> dict:
    """
    Classify a Wazuh alert.
    Returns category, icon, severity, mitre, tactic, base_score, confidence, explanation.
    """
    rule    = alert.get("rule", {})
    level   = int(rule.get("level", 0))
    groups  = rule.get("groups", [])
    desc    = rule.get("description", "")

    # Extract MITRE from Wazuh rule if present
    mitre_raw   = rule.get("mitre", {})
    wazuh_mitre = ""
    if isinstance(mitre_raw, dict):
        ids = mitre_raw.get("id", [])
        wazuh_mitre = ids[0] if ids else ""

    # ── Group mapping ─────────────────────────────────────────────────────────
    category = icon = severity = mitre_id = tactic = None
    base_score = 5

    for g in (groups if isinstance(groups, list) else [groups]):
        g_lower = str(g).lower()
        for key, (cat, ic, sev, mit, tac, bsc) in _CATEGORY_MAP.items():
            if key in g_lower:
                category, icon, severity = cat, ic, sev
                mitre_id = wazuh_mitre or mit
                tactic   = tac
                base_score = bsc
                break
        if category:
            break

    # ── Also scan description for keywords if no group match ──────────────────
    if not category:
        desc_lower = desc.lower()
        keyword_map = {
            # High severity patterns
            "brute force":         ("Brute Force Attack",      "💥", "high",    "T1110",    "Credential Access",    65),
            "multiple.*failed":    ("Brute Force Attack",      "💥", "high",    "T1110",    "Credential Access",    60),
            "failed login":        ("Suspicious Login",        "🔐", "medium",  "T1110",    "Credential Access",    20),
            "authentication fail": ("Suspicious Login",        "🔐", "medium",  "T1110",    "Credential Access",    20),
            "invalid user":        ("Suspicious Login",        "🔐", "medium",  "T1110",    "Credential Access",    25),
            "user created":        ("New User Created",        "👤", "high",    "T1136",    "Persistence",          70),
            "account created":     ("New User Created",        "👤", "high",    "T1136",    "Persistence",          70),
            "privilege":           ("Privilege Escalation",    "👑", "high",    "T1068",    "Privilege Escalation", 60),
            "elevated":            ("Privilege Escalation",    "👑", "high",    "T1068",    "Privilege Escalation", 55),
            "powershell":          ("Suspicious PowerShell",   "⚡", "high",    "T1059.001","Execution",            65),
            "encoded command":     ("Suspicious PowerShell",   "⚡", "high",    "T1059.001","Execution",            70),
            "malware":             ("Malware Detected",        "🦠", "critical","T1204",    "Execution",            90),
            "virus":               ("Malware Detected",        "🦠", "critical","T1204",    "Execution",            90),
            "ransomware":          ("Malware Detected",        "🦠", "critical","T1486",    "Impact",               95),
            # Medium severity — service & persistence
            "service.*start":      ("Service Started",         "🔧", "low",     "T1543.003","Persistence",          15),
            "service.*stop":       ("Service Stopped",         "🔧", "low",     "T1543.003","Persistence",          12),
            "startup type":        ("Service Config Changed",  "🔧", "medium",  "T1543.003","Persistence",          40),
            "service.*changed":    ("Service Config Changed",  "🔧", "medium",  "T1543.003","Persistence",          40),
            "scheduled task":      ("Scheduled Task",          "📋", "medium",  "T1053.005","Persistence",          45),
            "registry":            ("Registry Modification",   "📋", "medium",  "T1112",    "Defense Evasion",      40),
            "autorun":             ("Startup Persistence",     "🔧", "high",    "T1547.001","Persistence",          60),
            # CIS / SCA benchmarks
            "cis benchmark":       ("CIS Benchmark Finding",   "📋", "low",     "T1562",    "Defense Evasion",      15),
            "cis microsoft":       ("CIS Benchmark Finding",   "📋", "low",     "T1562",    "Defense Evasion",      15),
            "sca summary":         ("Security Config Audit",   "📋", "medium",  "T1562",    "Defense Evasion",      20),
            "ensure.*password":    ("Password Policy Check",   "🔑", "medium",  "T1110",    "Credential Access",    25),
            "ensure.*lockout":     ("Account Lockout Policy",  "🔑", "medium",  "T1110",    "Credential Access",    20),
            "wazuh server":        ("Wazuh Manager Event",     "⚙️",  "low",     "",         "Other",                 3),
            # Suspicious indicators
            "suspicious":          ("Suspicious Activity",     "🟡", "medium",  "",         "Unknown",              30),
            "anomal":              ("Anomalous Activity",      "🟡", "medium",  "",         "Unknown",              35),
        }
        for kw, vals in keyword_map.items():
            if kw in desc_lower:
                category, icon, severity, mitre_id, tactic, base_score = vals
                if wazuh_mitre:
                    mitre_id = wazuh_mitre
                break

    # ── Level fallback ────────────────────────────────────────────────────────
    if not category:
        for (lo, hi), (sev, cat, ic, bsc) in _LEVEL_MAP.items():
            if lo <= level <= hi:
                severity, category, icon, base_score = sev, cat, ic, bsc
                break
        if not category:
            severity, category, icon, base_score = "low", "Unknown Event", "⬜", 3
        mitre_id = wazuh_mitre or ""
        tactic   = ""

    confidence = min(99, 40 + level * 4)

    # ── Human explanation ─────────────────────────────────────────────────────
    _raw_agent = alert.get("agent", {}).get("name", "") or ""
    try:
        from modules.soc_brain import resolve_asset as _ra
        _asset_clf = _ra(_raw_agent, alert.get("agent",{}).get("ip",""))
        agent_name = _asset_clf.get("display_name") or _raw_agent or "Unidentified Host"
    except Exception:
        agent_name = _raw_agent or "Unidentified Host"
    src_ip     = alert.get("data", {}).get("srcip", "")
    src_user   = alert.get("data", {}).get("srcuser", alert.get("data", {}).get("dstuser", ""))
    who  = f"User `{src_user}` on" if src_user else "On"
    frm  = f"from `{src_ip}`"       if src_ip  else ""
    explanation = f"{who} `{agent_name}` {frm}: {desc}".strip()

    fp_hint = ""
    if level <= 3:
        fp_hint = "Likely system noise — low level event"
    elif category in ("System Noise", "System Event", "Windows Event", "OSSEC Internal"):
        fp_hint = "Routine system event — verify before escalating"

    return {
        "category":    category,
        "icon":        icon,
        "severity":    severity,
        "mitre_id":    mitre_id,
        "tactic":      tactic or "",
        "base_score":  base_score,
        "confidence":  confidence,
        "explanation": explanation,
        "fp_hint":     fp_hint,
        "rule_level":  level,
        "rule_groups": groups,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ASSET INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def update_asset(alert: dict, classification: dict) -> None:
    """
    Update the in-memory asset registry from a processed alert.
    Tracks: alert count, threat count, risk score, last seen, OS, IP.
    Handles both Wazuh Manager API format and OpenSearch _source format.
    """
    # OpenSearch _source nests agent data — handle both formats
    raw    = alert.get("_raw", alert)   # _raw = original _source from OpenSearch
    agent  = raw.get("agent", alert.get("agent", {}))

    name   = agent.get("name", "") or alert.get("agent", {}).get("name", "")
    if not name or name == "000" or name.lower() == "unknown":
        name = raw.get("manager", {}).get("name", "") or "wazuh.manager"

    # IP: try agent first, then data.srcip, then manager IP
    ip     = (agent.get("ip", "")
              or raw.get("data", {}).get("srcip", "")
              or alert.get("data", {}).get("srcip", "")
              or "")

    # OS: try agent.os, then infer from Windows/Linux clues
    os_info = agent.get("os", {})
    if isinstance(os_info, dict):
        os_name = (os_info.get("name", "") or os_info.get("platform", ""))[:40]
    else:
        os_name = str(os_info)[:40] if os_info else ""

    if not os_name:
        desc = str(raw.get("rule", {}).get("description", "")).lower()
        os_name = ("Windows" if "windows" in desc
                   else "Linux" if "linux" in desc or "ubuntu" in desc
                   else "")
    ts         = alert.get("timestamp", datetime.utcnow().isoformat())
    severity   = classification.get("severity", "low")
    is_threat  = severity in ("high", "critical")

    with _LOCK:
        if name not in _ASSETS:
            _ASSETS[name] = {
                "name":          name,
                "ip":            ip or "unknown",
                "os":            os_name or "unknown",
                "alert_count":   0,
                "threat_count":  0,
                "risk_score":    0,
                "last_seen":     ts,
                "top_categories": {},
            }
        a = _ASSETS[name]
        a["alert_count"]  += 1
        a["threat_count"] += 1 if is_threat else 0
        a["last_seen"]     = ts
        if ip:
            a["ip"] = ip
        if os_name:
            a["os"] = os_name

        # Rolling risk score: weighted avg favouring recent severe alerts
        sev_weights = {"critical": 90, "high": 70, "medium": 40, "low": 10}
        w = sev_weights.get(severity, 10)
        a["risk_score"] = round(a["risk_score"] * 0.85 + w * 0.15)

        # Track top categories per asset
        cat = classification.get("category", "Unknown")
        a["top_categories"][cat] = a["top_categories"].get(cat, 0) + 1

        # Global category counter
        _CATEGORIES[cat] = _CATEGORIES.get(cat, 0) + 1


def get_assets() -> list:
    """Return assets sorted by risk score descending."""
    with _LOCK:
        return sorted(_ASSETS.values(), key=lambda x: x["risk_score"], reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# TREND ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def update_trend(alert: dict, classification: dict) -> None:
    """Bucket alert into hourly trend counter."""
    ts  = alert.get("timestamp", datetime.utcnow().isoformat())
    try:
        hour_key = ts[:13]   # "YYYY-MM-DDTHH"
    except Exception:
        hour_key = datetime.utcnow().strftime("%Y-%m-%dT%H")

    with _LOCK:
        _TREND[hour_key] = _TREND.get(hour_key, 0) + 1
        # Keep only last 24 hours
        cutoff = (datetime.utcnow() - __import__("datetime").timedelta(hours=24)
                  ).strftime("%Y-%m-%dT%H")
        for k in list(_TREND.keys()):
            if k < cutoff:
                del _TREND[k]


def get_trend() -> dict:
    """Return trend dict sorted by hour."""
    with _LOCK:
        return dict(sorted(_TREND.items()))


def get_categories() -> dict:
    """Return category counts sorted by frequency."""
    with _LOCK:
        return dict(sorted(_CATEGORIES.items(), key=lambda x: x[1], reverse=True))


# ══════════════════════════════════════════════════════════════════════════════
# CORE PIPELINE FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def process_alert(alert: dict, session_config: dict = None) -> dict:
    """
    Run a single Wazuh alert through all 6 pipeline stages.
    Returns a structured result dict with everything needed for display + Splunk.

    This is the heart of the pipeline — all other functions call this.
    """
    t_start   = time.time()
    cfg       = session_config or {}
    ts        = datetime.utcnow().isoformat()
    alert_id  = alert.get("id", f"alert_{int(time.time()*1000)}")

    result = {
        "alert_id":   alert_id,
        "timestamp":  ts,
        "raw_alert":  alert,
        "stage":      "started",
        "error":      None,
    }

    try:
        # ── Stage 1: IOC Extraction ──────────────────────────────────────────
        result["stage"] = "ioc_extraction"
        ioc_tuples = _extract_iocs_from_alerts([alert])

        # Also pull direct fields from Wazuh alert structure
        direct_iocs = []
        for field in ["data.srcip", "data.dstip", "data.srcuser", "agent.ip"]:
            parts = field.split(".")
            val   = alert
            for p in parts:
                val = val.get(p, {}) if isinstance(val, dict) else {}
            if isinstance(val, str) and val and val not in [ioc for ioc, _ in ioc_tuples]:
                import re
                if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', val):
                    direct_iocs.append((val, "ip"))

        all_iocs = list({ioc: t for ioc, t in (ioc_tuples + direct_iocs)}.items())
        result["iocs"]      = [{"value": ioc, "type": t} for ioc, t in all_iocs]
        result["ioc_count"] = len(all_iocs)

        # ── Classification (runs even with no IOCs) ──────────────────────────
        classification = classify_alert(alert)
        result["category"]     = classification["category"]
        result["category_icon"]= classification["icon"]
        result["severity_class"]= classification["severity"]
        result["confidence_class"] = classification["confidence"]
        result["explanation"]  = classification["explanation"]
        result["fp_hint"]      = classification["fp_hint"]

        # ── Risk scoring (works even with no IOCs) ───────────────────────────
        risk_score, risk_label, score_breakdown = calculate_risk_score(
            alert,
            classification["base_score"],
            classification["category"],
        )
        result["risk_score"]      = risk_score
        result["risk_label"]      = risk_label
        result["score_breakdown"] = score_breakdown

        # ── Behavioral pattern detection ──────────────────────────────────────
        behavior = detect_behavioral_pattern(alert, classification["category"])
        result["behavior"] = behavior
        if behavior.get("pattern_detected"):
            result["risk_score"] = min(100, risk_score + behavior.get("score_boost", 0))
            result["risk_label"] = ("CRITICAL" if result["risk_score"] >= 80 else
                                    "HIGH"     if result["risk_score"] >= 60 else
                                    "MEDIUM"   if result["risk_score"] >= 35 else "LOW")
            result["behavior_pattern"] = behavior["pattern_name"]
            result["mitre_tags"] = [behavior["mitre"]]

        # ── Context enrichment ────────────────────────────────────────────────
        mitre_id = classification.get("mitre_id", "")
        context  = enrich_context(alert, classification["category"], mitre_id, result["risk_score"])
        result["context"]       = context
        result["mitre_id"]      = mitre_id
        result["mitre_name"]    = context["mitre_name"]
        result["mitre_tactic"]  = context["mitre_tactic"]
        result["playbook"]      = context["playbook"]
        result["sla"]           = context["sla"]
        result["who"]           = context["who"]

        # ── Asset + Trend update ──────────────────────────────────────────────
        update_asset(alert, classification)
        update_trend(alert, classification)

        # ── Incident grouping ─────────────────────────────────────────────────
        inc_id = group_into_incident(result)
        result["incident_id"] = inc_id

        # ── Handle NO_IOCS: still show full intelligence ──────────────────────
        if not all_iocs:
            result["stage"]   = "complete_no_iocs"
            # NOT "NO_IOCS" anymore — use real verdict based on risk score
            result["verdict"] = result["risk_label"]
            result["composite_score"] = result["risk_score"]
            result["summary"] = (
                f"{classification['icon']} [{result['risk_label']}] "
                f"{classification['category']} — score {result['risk_score']}/100 — "
                f"{classification['explanation'][:100]}"
            )
            result["executive_summary"] = (
                f"{context['who']}: {context['what']}. "
                f"Category: {classification['category']}. "
                f"Risk: {result['risk_label']} ({result['risk_score']}/100). "
                f"SLA: {context['sla']}."
                + (f" Behavioral pattern: {behavior['pattern_name']}." if behavior.get("pattern_detected") else "")
            )
            result["recommended_actions"] = context["playbook"]
            result["elapsed_ms"] = round((time.time() - t_start) * 1000)
            _store_result(result)
            return result

        # ── Stage 2: Threat Intel Enrichment ────────────────────────────────
        result["stage"] = "enrichment"
        enriched = []
        for ioc, ioc_type in all_iocs[:8]:    # cap at 8 IOCs per alert
            try:
                r = IOCEnricher.enrich(ioc, ioc_type, session_config=cfg)
                enriched.append(r)
            except Exception as e:
                enriched.append({"ioc": ioc, "ioc_type": ioc_type,
                                  "unified_score": 50, "verdict": "UNKNOWN",
                                  "error": str(e)})

        result["enrichment"]    = enriched
        result["max_vt_hits"]   = max((e.get("vt_malicious",    0) for e in enriched), default=0)
        result["max_abuse"]     = max((e.get("abuse_score",     0) for e in enriched), default=0)
        result["any_otx_hit"]   = any(e.get("otx_hits",      False) for e in enriched)
        result["min_rep_score"] = min((e.get("unified_score",  50) for e in enriched), default=50)

        # ── Stage 3: Score + Correlate ───────────────────────────────────────
        result["stage"] = "scoring"

        # Primary IOC = the one with the lowest (worst) reputation score
        primary = min(enriched, key=lambda e: e.get("unified_score", 50))
        primary_ioc = primary.get("ioc", all_iocs[0][0])

        drs = DynamicRiskScorer.score(
            ioc               = primary_ioc,
            alert_frequency   = int(alert.get("rule", {}).get("level", 1)) * 3,
            misp_threat_level = "HIGH" if result["max_abuse"] > 70 else
                                "MEDIUM" if result["max_abuse"] > 30 else "LOW",
            mitre_count       = 1 if alert.get("rule", {}).get("mitre") else 0,
        )

        corr  = CorrelationEngine.correlate(alert)
        is_fp, fp_reason = FalsePositiveKiller.is_false_positive(
            primary_ioc,
            current_count = 1,
            rep_score     = result["min_rep_score"],
        )

        # Use the better risk_score from our engine, DRS as fallback
        pipeline_score = result.get("risk_score", drs["composite_score"])
        result["composite_score"]      = max(pipeline_score, drs["composite_score"])
        result["risk_level"]           = result.get("risk_label", drs["risk_level"])
        result["recommendation"]       = drs["recommendation"]
        result["correlation_verdict"]  = corr["verdict"]
        result["correlation_confidence"] = corr["confidence"]
        result["mitre_tags"]           = corr.get("mitre_tags", [])
        result["threat_actors"]        = corr.get("threat_actors", [])
        result["is_fp"]                = is_fp
        result["fp_reason"]            = fp_reason if is_fp else ""

        if is_fp:
            result["stage"]   = "complete_fp"
            result["verdict"] = "FALSE_POSITIVE"
            result["summary"] = f"Suppressed: {fp_reason}"
            result["elapsed_ms"] = round((time.time() - t_start) * 1000)
            _store_result(result)
            return result

        # ── Stage 4: AI Narrative ─────────────────────────────────────────────
        result["stage"] = "narrative"

        # Build enriched alert list for narrative engine
        enriched_alerts = []
        for e in enriched:
            enriched_alerts.append({
                "ip":          e.get("ioc", ""),
                "domain":      e.get("ioc", ""),
                "threat_score":max(0, 100 - e.get("unified_score", 50)),
                "verdict":     e.get("verdict", "UNKNOWN"),
                "mitre":       (result["mitre_tags"][0] if result["mitre_tags"] else
                                alert.get("rule", {}).get("mitre", {}).get("id", [""])[0]
                                if isinstance(alert.get("rule", {}).get("mitre"), dict) else ""),
                "alert_type":  alert.get("rule", {}).get("description", "Wazuh Alert"),
                "severity":    ("high" if drs["composite_score"] > 60 else
                                "medium" if drs["composite_score"] > 30 else "low"),
                "source":      "wazuh_pipeline",
                "timestamp":   ts,
            })

        narrative = _build_narrative_from_alerts(enriched_alerts, [], analyst_name="Pipeline")

        result["narrative"]             = narrative
        result["executive_summary"]     = narrative.get("executive_summary", "")
        result["severity_verdict"]      = narrative.get("severity_verdict", "UNKNOWN")
        result["recommended_actions"]   = narrative.get("recommended_actions", [])
        result["attack_phases"]         = narrative.get("attack_phases_observed", [])

        # Final verdict: correlation overrides narrative if stronger
        if corr["verdict"] == "CONFIRMED_THREAT" and corr["confidence"] >= 70:
            result["verdict"] = "CONFIRMED_THREAT"
        elif corr["verdict"] == "SUSPICIOUS" or drs["composite_score"] >= 55:
            result["verdict"] = "SUSPICIOUS"
        elif drs["composite_score"] >= 35:
            result["verdict"] = "MONITOR"
        else:
            result["verdict"] = "LIKELY_BENIGN"

        # ── Stage 5: Push to Splunk ───────────────────────────────────────────
        result["stage"] = "splunk_push"
        if _SPLUNK:
            try:
                mitre_str = result["mitre_tags"][0] if result["mitre_tags"] else ""
                severity  = ("high"   if drs["composite_score"] > 60 else
                             "medium" if drs["composite_score"] > 30 else "low")
                payload = build_siem_alert(
                    primary_ioc,
                    result["verdict"],
                    result["composite_score"],
                    corr["confidence"],
                    mitre_str,
                    severity,
                )
                # Enrich payload with pipeline extras
                payload.setdefault("event", {}).update({
                    "pipeline_stage":    "auto",
                    "wazuh_rule_id":     alert.get("rule", {}).get("id", ""),
                    "wazuh_rule_level":  alert.get("rule", {}).get("level", 0),
                    "wazuh_agent":       alert.get("agent", {}).get("name", ""),
                    "executive_summary": result["executive_summary"][:500],
                    "ioc_count":         result["ioc_count"],
                    "attack_phases":     ", ".join(result["attack_phases"]),
                })
                ok, msg = send_to_splunk(payload)
                result["splunk_ok"]  = ok
                result["splunk_msg"] = msg
            except Exception as e:
                result["splunk_ok"]  = False
                result["splunk_msg"] = str(e)
        else:
            result["splunk_ok"]  = False
            result["splunk_msg"] = "Splunk not configured"

        # ── Stage 6: Store ────────────────────────────────────────────────────
        result["stage"]      = "complete"
        result["elapsed_ms"] = round((time.time() - t_start) * 1000)

        # Build human-readable summary
        cat_icon = result.get("category_icon", "")
        cat_name = result.get("category", "")
        result["summary"] = (
            f"{cat_icon} [{result['verdict']}] {primary_ioc} — "
            f"score {result['composite_score']}/100 — "
            f"{cat_name}: {result.get('explanation','')[:100]}"
        )

        _store_result(result)
        logger.info(
            "[PIPELINE] %s | %s | score:%d | iocs:%d | %dms",
            result["verdict"], primary_ioc,
            result["composite_score"], result["ioc_count"],
            result["elapsed_ms"]
        )

        # ── NEW: FULLY AUTOMATIC n8n SOAR TRIGGER ─────────────────────────────
        auto_trigger_n8n(result)

        return result

    except Exception as e:
        result["stage"]      = "error"
        result["error"]      = str(e)
        result["verdict"]    = "PIPELINE_ERROR"
        result["summary"]    = f"Pipeline error on alert {alert_id}: {e}"
        result["elapsed_ms"] = round((time.time() - t_start) * 1000)
        with _LOCK:
            _STATS["errors"] += 1
        logger.exception("[PIPELINE] Error processing alert %s", alert_id)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE ENGINE  (polling + background thread)
# ══════════════════════════════════════════════════════════════════════════════

class PipelineEngine:
    """
    Manages the background polling loop.
    Wazuh → fetch alerts → process_alert() → store results.
    """

    _thread:   threading.Thread | None = None
    _stop_evt: threading.Event         = threading.Event()
    _last_alert_ids: set               = set()

    @classmethod
    def start(
        cls,
        poll_interval:  int  = 30,
        wazuh_url:       str  = "",
        wazuh_user:      str  = "",
        wazuh_pass:      str  = "",
        session_config:  dict = None,
        alert_limit:     int  = 20,
    ) -> None:
        """Start background polling thread. Safe to call multiple times."""
        if cls._thread and cls._thread.is_alive():
            logger.info("[PIPELINE] Already running")
            return

        cls._stop_evt.clear()
        _STATS["running"] = True

        def _loop():
            logger.info("[PIPELINE] Started — polling every %ds", poll_interval)
            while not cls._stop_evt.is_set():
                try:
                    cls._poll_once(wazuh_url, wazuh_user, wazuh_pass,
                                   session_config or {}, alert_limit)
                except Exception as e:
                    logger.exception("[PIPELINE] Poll error: %s", e)
                cls._stop_evt.wait(poll_interval)
            _STATS["running"] = False
            logger.info("[PIPELINE] Stopped")

        cls._thread = threading.Thread(target=_loop, daemon=True, name="netsec-pipeline")
        cls._thread.start()

    @classmethod
    def stop(cls) -> None:
        cls._stop_evt.set()
        _STATS["running"] = False

    @classmethod
    def is_running(cls) -> bool:
        return cls._thread is not None and cls._thread.is_alive()

    @classmethod
    def run_once(
        cls,
        wazuh_url:      str  = "",
        wazuh_user:     str  = "",
        wazuh_pass:     str  = "",
        session_config: dict = None,
        alert_limit:    int  = 20,
    ) -> list[dict]:
        """Manually trigger one pipeline run. Clears dedup cache so all alerts process."""
        # Clear dedup cache on manual run so we always process fresh alerts
        cls._last_alert_ids.clear()
        return cls._poll_once(wazuh_url, wazuh_user, wazuh_pass,
                               session_config or {}, alert_limit)

    @classmethod
    def _poll_once(
        cls,
        wazuh_url:      str,
        wazuh_user:     str,
        wazuh_pass:     str,
        session_config: dict,
        limit:          int,
    ) -> list[dict]:
        """Fetch alerts from Wazuh, deduplicate, process each one."""
        # Resolve credentials
        url  = wazuh_url  or os.getenv("WAZUH_URL",  "https://192.168.1.4:9200")
        user = wazuh_user or os.getenv("WAZUH_USER", "admin")
        pwd  = wazuh_pass or os.getenv("WAZUH_PASS", "")

        if not pwd:
            logger.debug("[PIPELINE] WAZUH_PASS not set — skipping poll")
            return []

        alerts = wazuh_get_alerts(url, user, pwd, limit=limit)
        if not alerts:
            logger.debug("[PIPELINE] No new alerts from Wazuh")
            return []

        # Deduplicate by alert ID
        new_alerts = []
        for a in alerts:
            aid = a.get("id", json.dumps(a, sort_keys=True)[:64])
            if aid not in cls._last_alert_ids:
                new_alerts.append(a)
                cls._last_alert_ids.add(aid)

        # Keep ID cache bounded
        if len(cls._last_alert_ids) > 10000:
            cls._last_alert_ids = set(list(cls._last_alert_ids)[-5000:])

        if not new_alerts:
            logger.debug("[PIPELINE] No new (deduplicated) alerts")
            return []

        logger.info("[PIPELINE] Processing %d new alert(s)", len(new_alerts))
        results = []
        for alert in new_alerts:
            r = process_alert(alert, session_config)
            results.append(r)

        return results

    @classmethod
    def inject_alert(cls, alert: dict, session_config: dict = None) -> dict:
        """
        Manually inject a single alert into the pipeline.
        Used by webhook_server.py and test scripts.
        """
        return process_alert(alert, session_config or {})


# ══════════════════════════════════════════════════════════════════════════════
# WEBHOOK SERVER  (lightweight HTTP server — alternative to polling)
# ══════════════════════════════════════════════════════════════════════════════

def run_pipeline_webhook_server(port: int = 8001) -> None:
    """
    Start a lightweight HTTP server that receives Wazuh alerts via POST.
    Run in a separate terminal: python realtime_pipeline.py --server

    Wazuh posts to: http://YOUR_IP:8001/pipeline/ingest
    Payload: {"alerts": [...]}  or single alert dict
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            logger.debug(fmt, *args)

        def _send(self, code, data):
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {
                    "service":  "NetSec AI Pipeline",
                    "status":   "ok",
                    "stats":    get_stats(),
                    "results":  len(get_results()),
                })
            elif self.path == "/results":
                self._send(200, {"results": get_results(20)})
            else:
                self._send(404, {"error": "Not found"})

        def do_POST(self):
            if self.path != "/pipeline/ingest":
                self._send(404, {"error": "Use POST /pipeline/ingest"})
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body   = json.loads(self.rfile.read(length).decode())
            except Exception as e:
                self._send(400, {"error": f"Invalid JSON: {e}"})
                return

            # Accept either {"alerts": [...]} or a single alert dict
            if isinstance(body, list):
                alerts = body
            elif "alerts" in body:
                alerts = body["alerts"]
            else:
                alerts = [body]

            results = [PipelineEngine.inject_alert(a) for a in alerts]
            self._send(200, {
                "processed": len(results),
                "results": [
                    {"verdict": r["verdict"], "summary": r.get("summary", ""),
                     "score": r.get("composite_score", 0), "elapsed_ms": r.get("elapsed_ms", 0)}
                    for r in results
                ]
            })

    server = HTTPServer(("0.0.0.0", port), Handler)
    logger.info("[PIPELINE SERVER] Listening on port %d", port)
    print(f"\n  NetSec AI Pipeline Server running on port {port}")
    print(f"  Health:  http://localhost:{port}/health")
    print(f"  Ingest:  POST http://localhost:{port}/pipeline/ingest")
    print(f"  Results: http://localhost:{port}/results\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")


# ══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# INLINE ALERT EXPLAINER  — renders a full explanation panel for one result
# ══════════════════════════════════════════════════════════════════════════════

def _render_inline_explanation(r: dict, key_suffix: str) -> None:
    """
    Render a full in-place explanation panel for a single pipeline result.
    Called when analyst clicks the Explain button on any alert row.
    Includes: verdict, plain-English, MITRE, playbook, behavioral pattern,
    score breakdown, LLM narrative, and feedback/action buttons.
    """
    risk_lbl  = r.get("risk_label", r.get("verdict", "UNKNOWN"))
    score     = r.get("risk_score", r.get("composite_score", 0))
    cat       = r.get("category", "Unknown")
    cat_icon  = r.get("category_icon", "⬜")
    expl      = r.get("explanation", r.get("summary", ""))
    who       = r.get("who", "")
    mitre_id  = r.get("mitre_id", "")
    mitre_nm  = r.get("mitre_name", "")
    mitre_tac = r.get("mitre_tactic", "")
    mitre_url = f"https://attack.mitre.org/techniques/{mitre_id.replace('.','/')}/" if mitre_id else ""
    playbook  = r.get("playbook", [])
    sla       = r.get("sla", "")
    inc_id    = r.get("incident_id", "")
    breakdown = r.get("score_breakdown", [])
    beh       = r.get("behavior", {})
    exec_sum  = r.get("executive_summary", "")
    agent     = r.get("raw_alert", {}).get("agent", {}).get("name", "?")
    src_ip    = r.get("raw_alert", {}).get("data", {}).get("srcip", "")
    rule_desc = r.get("raw_alert", {}).get("rule", {}).get("description", "")
    rule_lvl  = r.get("raw_alert", {}).get("rule", {}).get("level", "")
    ts        = r.get("timestamp", "")[:19].replace("T", " ")

    sev_colors = {
        "CRITICAL": "#ff0033", "HIGH": "#ff6600",
        "MEDIUM": "#ffcc00", "LOW": "#00aaff", "INFORMATIONAL": "#666688"
    }
    vc = sev_colors.get(risk_lbl, "#7788aa")

    # ── Verdict banner ────────────────────────────────────────────────────────
    st.markdown(
        f"<div style='background:{vc}12;border:1.5px solid {vc}55;"
        f"border-radius:10px;padding:14px 18px;margin:6px 0'>"
        f"<div style='display:flex;align-items:center;gap:12px;flex-wrap:wrap'>"
        f"<span style='font-size:1.4rem'>{cat_icon}</span>"
        f"<div>"
        f"<div style='color:{vc};font-family:Orbitron,monospace;font-size:.82rem;"
        f"font-weight:900;letter-spacing:2px'>{risk_lbl} — {cat}</div>"
        f"<div style='color:#7fb3cc;font-size:.75rem;margin-top:2px'>"
        f"Risk {score}/100 · SLA: <span style='color:#ff9900'>{sla}</span>"
        + (f" · Incident: <span style='color:#00aaff'>{inc_id}</span>" if inc_id else "")
        + f"</div></div>"
        f"<div style='margin-left:auto;text-align:right'>"
        f"<div style='color:#2a4a6a;font-size:.65rem'>{ts}</div>"
        + (f"<div style='color:#446688;font-size:.65rem'>Wazuh level {rule_lvl}</div>" if rule_lvl else "")
        + f"</div></div></div>",
        unsafe_allow_html=True
    )

    # ── Two-column: Plain English + Who/What ──────────────────────────────────
    col_a, col_b = st.columns([3, 2])
    with col_a:
        st.markdown(
            "<div style='color:#00f9ff;font-size:.62rem;font-weight:700;"
            "letter-spacing:1.5px;margin-bottom:4px'>💬 PLAIN ENGLISH — WHAT IS THIS?</div>"
            f"<div style='color:#c8e8ff;font-size:.78rem;line-height:1.6;"
            f"background:#080f1a;border-radius:6px;padding:8px 12px'>{expl}</div>",
            unsafe_allow_html=True
        )
        if exec_sum and exec_sum != expl:
            st.markdown(
                f"<div style='color:#5577aa;font-size:.73rem;margin-top:6px;"
                f"line-height:1.5;padding:0 4px'>{exec_sum[:280]}</div>",
                unsafe_allow_html=True
            )

    with col_b:
        st.markdown(
            "<div style='color:#00f9ff;font-size:.62rem;font-weight:700;"
            "letter-spacing:1.5px;margin-bottom:4px'>🎯 TECHNICAL DETAILS</div>"
            f"<div style='background:#080f1a;border-radius:6px;padding:8px 12px;"
            f"font-size:.73rem'>"
            + (f"<div style='margin-bottom:4px'><span style='color:#446688'>Agent:</span> "
               f"<span style='color:#c8e8ff'>{agent}</span></div>" if agent else "")
            + (f"<div style='margin-bottom:4px'><span style='color:#446688'>Source IP:</span> "
               f"<span style='color:#ff9944;font-family:monospace'>{src_ip}</span></div>" if src_ip else "")
            + (f"<div style='margin-bottom:4px'><span style='color:#446688'>Who:</span> "
               f"<span style='color:#c8e8ff'>{who}</span></div>" if who else "")
            + (f"<div style='margin-bottom:4px'><span style='color:#446688'>Rule:</span> "
               f"<span style='color:#7fb3cc'>{rule_desc[:60]}</span></div>" if rule_desc else "")
            + (f"<div><span style='color:#446688'>MITRE:</span> "
               f"<a href='{mitre_url}' target='_blank' style='color:#c300ff;text-decoration:none'>"
               f"{mitre_id}</a> {mitre_nm} · "
               f"<span style='color:#888'>{mitre_tac}</span></div>" if mitre_id else "")
            + "</div>",
            unsafe_allow_html=True
        )

    # ── Behavioral pattern alert (if detected) ────────────────────────────────
    if beh.get("pattern_detected"):
        st.markdown(
            f"<div style='background:rgba(255,51,102,0.1);border:1px solid #ff336644;"
            f"border-radius:6px;padding:8px 14px;margin:6px 0'>"
            f"<span style='color:#ff3366;font-weight:700;font-size:.78rem'>"
            f"⚡ BEHAVIORAL PATTERN DETECTED</span><br>"
            f"<span style='color:#ff8899;font-size:.73rem'>"
            f"{beh['pattern_name']} — {beh.get('description','')}</span><br>"
            f"<span style='color:#886677;font-size:.68rem'>"
            f"Count: {beh.get('count',0)} events · "
            f"Confidence: {beh.get('confidence',0)}% · "
            f"MITRE: {beh.get('mitre','')}</span>"
            f"</div>",
            unsafe_allow_html=True
        )

    # ── Playbook steps ────────────────────────────────────────────────────────
    if playbook:
        st.markdown(
            "<div style='color:#00f9ff;font-size:.62rem;font-weight:700;"
            "letter-spacing:1.5px;margin:10px 0 6px'>⚡ PLAYBOOK — DO THESE IN ORDER:</div>",
            unsafe_allow_html=True
        )
        for i, step in enumerate(playbook):
            step_color = "#ff4455" if i == 0 else "#ff9900" if i == 1 else "#7fb3cc"
            st.markdown(
                f"<div style='display:flex;align-items:flex-start;gap:10px;"
                f"padding:5px 10px;background:#080f1a;border-left:2px solid {step_color}55;"
                f"margin:2px 0;border-radius:0 5px 5px 0'>"
                f"<span style='color:{step_color};font-weight:900;font-size:.75rem;"
                f"min-width:18px;font-family:monospace'>{i+1}</span>"
                f"<span style='color:#c8e8ff;font-size:.73rem;line-height:1.4'>{step}</span>"
                f"</div>",
                unsafe_allow_html=True
            )

    # ── Score breakdown (collapsible) ─────────────────────────────────────────
    if breakdown:
        with st.expander(f"📊 Score breakdown — how {score}/100 was calculated"):
            for b in breakdown:
                st.markdown(f"- `{b}`")

    # ── LLM narrative (collapsible, needs API key) ────────────────────────────
    if exec_sum:
        with st.expander("🧠 Full AI narrative"):
            st.markdown(
                f"<div style='color:#c8e8ff;font-size:.78rem;line-height:1.7;"
                f"white-space:pre-wrap'>{exec_sum}</div>",
                unsafe_allow_html=True
            )

    # ── Action buttons ────────────────────────────────────────────────────────
    st.markdown("<div style='margin-top:10px'></div>", unsafe_allow_html=True)
    b1, b2, b3, b4 = st.columns(4)

    if b1.button("✅ Confirm Threat", key=f"confirm_{key_suffix}", use_container_width=True):
        st.session_state.setdefault("analyst_feedback_log", []).append(
            {"action": "confirmed", "agent": agent, "category": cat,
             "score": score, "ts": datetime.utcnow().isoformat()}
        )
        with _LOCK:
            _STATS["confirmed_threats"] = _STATS.get("confirmed_threats", 0) + 1
        st.success(f"✅ Threat confirmed — {cat} weight boosted for future alerts")

    if b2.button("❌ False Positive", key=f"fp_{key_suffix}", use_container_width=True):
        st.session_state.setdefault("analyst_feedback_log", []).append(
            {"action": "false_positive", "agent": agent, "category": cat,
             "score": score, "ts": datetime.utcnow().isoformat()}
        )
        with _LOCK:
            _STATS["false_positives"] = _STATS.get("false_positives", 0) + 1
        st.info(f"ℹ️ False positive logged — baseline updated for {agent}")

    if b3.button("⬆️ Escalate to IR", key=f"esc_{key_suffix}", use_container_width=True):
        st.session_state.setdefault("triage_alerts", []).append({
            "alert_type": cat,
            "severity":   risk_lbl.lower(),
            "mitre":      mitre_id,
            "ip":         src_ip,
            "detail":     expl,
            "source":     "pipeline_escalation",
            "timestamp":  datetime.utcnow().isoformat(),
        })
        st.session_state.setdefault("analyst_feedback_log", []).append(
            {"action": "escalated", "agent": agent, "category": cat,
             "score": score, "ts": datetime.utcnow().isoformat()}
        )
        st.warning(f"⬆️ Escalated to IR queue — {cat} on {agent}")

    if b4.button("🚫 Block IOC", key=f"block_{key_suffix}", use_container_width=True):
        ioc_to_block = src_ip or agent
        if ioc_to_block:
            st.session_state.setdefault("global_blocklist", []).append({
                "ioc": ioc_to_block, "methods": ["Firewall", "Splunk"],
                "reason": f"Pipeline: {cat}", "analyst": "pipeline",
                "time": datetime.utcnow().isoformat(), "status": "BLOCKED"
            })
            st.session_state.setdefault("blocked_ips", []).append(ioc_to_block)
            st.error(f"🚫 {ioc_to_block} added to global blocklist")

def render_pipeline_dashboard() -> None:
    """
    Full pipeline dashboard UI.
    Add to app.py:
        from realtime_pipeline import render_pipeline_dashboard
        # in your nav routing:
        elif mode == "Live Pipeline":
            render_pipeline_dashboard()
    """
    if not _ST:
        return

    # ── AUTO-START: launch pipeline on first render if creds are configured ────
    if not PipelineEngine.is_running():
        _auto_url  = st.session_state.get("pl_wazuh_url",  os.getenv("WAZUH_URL",  ""))
        _auto_user = st.session_state.get("pl_wazuh_user", os.getenv("WAZUH_USER", ""))
        _auto_pass = st.session_state.get("pl_wazuh_pass", os.getenv("WAZUH_PASS", ""))
        if _auto_url and _auto_user and _auto_pass:
            PipelineEngine.start(
                poll_interval  = st.session_state.get("pl_interval", 30),
                wazuh_url      = _auto_url,
                wazuh_user     = _auto_user,
                wazuh_pass     = _auto_pass,
                session_config = st.session_state.get("user_api_config", {}),
            )

    st.markdown("""
    <div style='background:linear-gradient(135deg,#0a1628,#001a33);
                border:1px solid #00d4ff33;border-radius:12px;
                padding:18px 24px;margin-bottom:20px'>
        <h2 style='color:#00d4ff;margin:0;font-size:1.3rem'>
            ⚡ Real-Time SOC Pipeline
        </h2>
        <p style='color:#7fb3cc;margin:6px 0 0;font-size:.82rem'>
            Wazuh → Classify → Score → Enrich → Incident → Splunk · Auto-starts when credentials saved
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Stats bar ────────────────────────────────────────────────────────────
    stats = get_stats()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Alerts processed",  stats["total_alerts"])
    c2.metric("IOCs extracted",    stats["total_iocs"])
    c3.metric("Confirmed threats", stats["confirmed_threats"],
              delta=None if not stats["confirmed_threats"] else "🔴")
    c4.metric("FP suppressed",     stats["false_positives"])
    c5.metric("Pipeline errors",   stats["errors"])

    st.divider()

    # ── Controls ─────────────────────────────────────────────────────────────
    tab_live, tab_classify, tab_incidents, tab_assets, tab_trend, tab_manual, tab_test, tab_config = st.tabs([
        "🔴 Live Feed", "🏷️ Classification", "🚨 Incidents",
        "🖥️ Asset Intel", "📈 Trends", "▶ Manual Run", "🧪 Test", "⚙️ Config"
    ])

    # ── TAB: LIVE FEED ────────────────────────────────────────────────────────
    with tab_live:
        running = PipelineEngine.is_running()
        col1, col2 = st.columns([3, 1])
        col1.markdown(
            f"**Status:** {'🟢 Running' if running else '⚪ Stopped'}  |  "
            f"Last run: {stats.get('last_run', 'Never') or 'Never'}"
        )

        if not running:
            if col2.button("▶ Start Pipeline", type="primary", use_container_width=True, key="pl_start"):
                cfg = st.session_state.get("user_api_config", {})
                PipelineEngine.start(
                    poll_interval = st.session_state.get("pl_interval", 30),
                    wazuh_url     = st.session_state.get("pl_wazuh_url", ""),
                    wazuh_user    = st.session_state.get("pl_wazuh_user", ""),
                    wazuh_pass    = st.session_state.get("pl_wazuh_pass", ""),
                    session_config= cfg,
                )
                st.success("Pipeline started — polling Wazuh every "
                           f"{st.session_state.get('pl_interval', 30)}s")
                st.rerun()
        else:
            if col2.button("⏹ Stop Pipeline", use_container_width=True, key="pl_stop"):
                PipelineEngine.stop()
                st.warning("Pipeline stopped")
                st.rerun()

        # Results table
        _noise_col, _filter_col = st.columns([3, 1])
        _show_noise = _noise_col.checkbox(
            "Show System Noise (score < 20)",
            value=False, key="pl_show_noise"
        )
        results = get_results(50)
        if not _show_noise:
            _before = len(results)
            results = [r for r in results if r.get("risk_score", r.get("composite_score", 0)) >= 20
                       or r.get("risk_label","") not in ("INFORMATIONAL","LOW","LIKELY_BENIGN")]
            _suppressed = _before - len(results)
            if _suppressed > 0:
                st.caption(f"🔇 {_suppressed} system noise alert(s) suppressed — enable toggle to show")

        # Track which alert rows are expanded
        if "pl_expanded_alerts" not in st.session_state:
            st.session_state["pl_expanded_alerts"] = set()

        if results:
            col_hdr, col_ref = st.columns([4, 1])
            col_hdr.markdown(f"**Last {min(len(results), 50)} pipeline results — click ⚡ Explain on any row:**")
            if col_ref.button("🔄 Refresh", key="pl_refresh", use_container_width=True):
                st.rerun()

            for idx, r in enumerate(results[:20]):
                risk_lbl = r.get("risk_label", r.get("verdict", "UNKNOWN"))
                score    = r.get("risk_score", r.get("composite_score", 0))
                ts       = r.get("timestamp", "")[:19].replace("T", " ")
                cat_icon = r.get("category_icon", "⬜")
                cat_name = r.get("category", "")
                expl     = r.get("explanation", r.get("summary", ""))[:110]
                _raw_name = r.get("raw_alert", {}).get("agent", {}).get("name", "") or ""
                _raw_ip   = r.get("raw_alert", {}).get("agent", {}).get("ip", "") or ""
                try:
                    from modules.soc_brain import resolve_asset as _ra_lf
                    _lf_asset = _ra_lf(_raw_name, _raw_ip)
                    agent = _lf_asset.get("display_name") or _raw_name or "Unidentified Host"
                except Exception:
                    agent = _raw_name or "Unidentified Host"
                mitre_id = r.get("mitre_id", "")
                mitre_tac= r.get("mitre_tactic", "")
                inc_id   = r.get("incident_id", "")
                sla      = r.get("sla", "")
                pattern  = r.get("behavior_pattern", "")
                playbook = r.get("playbook", [])
                alert_key = f"live_{idx}_{r.get('alert_id', idx)}"
                is_expanded = alert_key in st.session_state["pl_expanded_alerts"]

                color_map = {
                    "CRITICAL": "#ff0033", "HIGH": "#ff6600",
                    "MEDIUM": "#ffcc00",   "LOW": "#00aaff",
                    "INFORMATIONAL": "#666688", "FALSE_POSITIVE": "#00cc88",
                    "LIKELY_BENIGN": "#00cc88", "PIPELINE_ERROR": "#ff6600",
                }
                vc = color_map.get(risk_lbl, "#7788aa")

                # ── Alert row ─────────────────────────────────────────────────
                row_col, btn_col = st.columns([5, 1])
                with row_col:
                    st.markdown(
                        f"<div style='border-left:3px solid {vc};padding:7px 12px;"
                        f"background:#0a1220;border-radius:0 6px 6px 0'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                        f"<span style='font-size:.9rem'>{cat_icon}</span>"
                        f"<span style='color:{vc};font-weight:700;font-size:.8rem;margin:0 6px'>{risk_lbl}</span>"
                        f"<span style='color:#7fb3cc;font-size:.76rem;flex:1'>{cat_name}</span>"
                        + (f"<span style='background:#ff336622;color:#ff6688;font-size:.65rem;"
                           f"padding:1px 5px;border-radius:3px;margin:0 4px'>⚡ {pattern}</span>" if pattern else "")
                        + f"<span style='color:#2a4a6a;font-size:.65rem'>{ts}</span>"
                        f"</div>"
                        f"<div style='color:#c8e8ff;font-size:.74rem;margin:2px 0 3px'>{expl}</div>"
                        f"<div style='display:flex;gap:8px;flex-wrap:wrap'>"
                        f"<span style='color:#446688;font-size:.68rem'>Score: <b style='color:{vc}'>{score}</b>/100</span>"
                        + (f"<span style='color:#556688;font-size:.68rem'>{mitre_id}·{mitre_tac}</span>" if mitre_id else "")
                        + (f"<span style='color:#446688;font-size:.68rem'>📁 {inc_id}</span>" if inc_id else "")
                        + (f"<span style='color:#ff9900;font-size:.68rem'>⏱ {sla}</span>" if sla and risk_lbl in ("HIGH","CRITICAL","MEDIUM") else "")
                        + f"<span style='color:#2a4a6a;font-size:.65rem;margin-left:auto'>{agent}</span>"
                        f"</div>"
                        + (f"<div style='color:#3a5a3a;font-size:.67rem;margin-top:2px'>📋 {playbook[0]}</div>" if playbook else "")
                        + f"</div>",
                        unsafe_allow_html=True
                    )
                with btn_col:
                    btn_label = "🔼 Close" if is_expanded else "⚡ Explain"
                    btn_type  = "secondary" if is_expanded else "primary"
                    if st.button(btn_label, key=f"exbtn_{alert_key}",
                                 use_container_width=True, type=btn_type):
                        if is_expanded:
                            st.session_state["pl_expanded_alerts"].discard(alert_key)
                        else:
                            st.session_state["pl_expanded_alerts"].add(alert_key)
                        st.rerun()

                # ── Inline explanation panel (shown when expanded) ─────────────
                if is_expanded:
                    with st.container():
                        st.markdown(
                            "<div style='border:1px solid #1a3a5a;border-radius:8px;"
                            "padding:14px 16px;background:#060d18;margin:2px 0 8px'>",
                            unsafe_allow_html=True
                        )
                        _render_inline_explanation(r, key_suffix=alert_key)
                        st.markdown("</div>", unsafe_allow_html=True)

        else:
            st.info("No results yet — start the pipeline or run manually.")
            if st.button("🔄 Refresh", key="pl_refresh"):
                st.rerun()

    # ── TAB: CLASSIFICATION ──────────────────────────────────────────────────
    with tab_classify:
        st.markdown("### 🏷️ Alert Classification")
        st.caption("Every Wazuh alert automatically categorised by type · severity · confidence")

        results_c = get_results(100)
        cats      = get_categories()

        if not results_c:
            st.info("No alerts processed yet — run the pipeline first.")
        else:
            # Category breakdown metrics
            top_cats = list(cats.items())[:6]
            if top_cats:
                cols = st.columns(min(len(top_cats), 3))
                for i, (cat, cnt) in enumerate(top_cats):
                    cols[i % 3].metric(cat, cnt)
                st.divider()

            # Severity breakdown
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for r in results_c:
                sev = r.get("severity_class", r.get("severity", "low"))
                if sev in sev_counts:
                    sev_counts[sev] += 1
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("🚨 Critical", sev_counts["critical"])
            c2.metric("🔴 High",     sev_counts["high"])
            c3.metric("🟡 Medium",   sev_counts["medium"])
            c4.metric("🔵 Low",      sev_counts["low"])
            st.divider()

            # Alert list with classification + inline explain
            st.markdown("**Recent classified alerts — click ⚡ Explain on any row:**")

            if "cl_expanded_alerts" not in st.session_state:
                st.session_state["cl_expanded_alerts"] = set()

            for idx, r in enumerate(results_c[:30]):
                icon  = r.get("category_icon", "⬜")
                cat   = r.get("category", "Unknown")
                sev   = r.get("severity_class", "low")
                expl  = r.get("explanation", r.get("summary", ""))[:120]
                ts    = r.get("timestamp", "")[:16].replace("T", " ")
                conf  = r.get("confidence_class", 0)
                fp    = r.get("fp_hint", "")
                alert_key = f"cl_{idx}_{r.get('alert_id', idx)}"
                is_expanded = alert_key in st.session_state["cl_expanded_alerts"]

                sev_colors = {
                    "critical": "#ff0033", "high": "#ff6600",
                    "medium":   "#ffcc00", "low":  "#4488aa",
                }
                sc = sev_colors.get(sev, "#888")

                row_col, btn_col = st.columns([5, 1])
                with row_col:
                    st.markdown(
                        f"<div style='border-left:3px solid {sc};padding:5px 10px;"
                        f"margin:2px 0;background:#0a1220;border-radius:0 5px 5px 0'>"
                        f"<span style='font-size:.82rem'>{icon}</span> "
                        f"<span style='color:{sc};font-size:.76rem;font-weight:600'>{cat}</span> "
                        f"<span style='color:#888;font-size:.7rem'>· {sev.upper()} · {conf}% confidence</span>"
                        f"<br><span style='color:#c8e8ff;font-size:.73rem'>{expl}</span>"
                        + (f"<br><span style='color:#446688;font-size:.68rem'>ℹ️ {fp}</span>" if fp else "")
                        + f"<span style='color:#2a4a6a;font-size:.65rem;float:right'>{ts}</span>"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                with btn_col:
                    btn_label = "🔼 Close" if is_expanded else "⚡ Explain"
                    btn_type  = "secondary" if is_expanded else "primary"
                    if st.button(btn_label, key=f"clbtn_{alert_key}",
                                 use_container_width=True, type=btn_type):
                        if is_expanded:
                            st.session_state["cl_expanded_alerts"].discard(alert_key)
                        else:
                            st.session_state["cl_expanded_alerts"].add(alert_key)
                        st.rerun()

                if is_expanded:
                    with st.container():
                        st.markdown(
                            "<div style='border:1px solid #1a3a5a;border-radius:8px;"
                            "padding:14px 16px;background:#060d18;margin:2px 0 8px'>",
                            unsafe_allow_html=True
                        )
                        _render_inline_explanation(r, key_suffix=alert_key)
                        st.markdown("</div>", unsafe_allow_html=True)

    # ── TAB: INCIDENTS ────────────────────────────────────────────────────────
    with tab_incidents:
        st.markdown("### 🚨 Incident Management")
        st.caption("Related alerts grouped into incidents · Severity · SLA · Playbook")

        incidents = get_incidents()
        open_incs = [i for i in incidents if i["status"] == "open"]

        if not incidents:
            st.info("No incidents yet — run the pipeline to generate incidents from alerts.")
        else:
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Incidents", len(incidents))
            c2.metric("Open",   len(open_incs))
            c3.metric("Critical", sum(1 for i in open_incs if i["severity"] == "critical"))

            st.divider()
            sev_colors = {
                "critical": "#ff0033", "high": "#ff6600",
                "medium":   "#ffcc00", "low":  "#00aaff", "informational": "#888"
            }
            for inc in incidents[:30]:
                sc   = sev_colors.get(inc["severity"], "#888")
                age  = (datetime.utcnow() - inc["opened"]).seconds // 60
                last = (datetime.utcnow() - inc["last_updated"]).seconds // 60

                st.markdown(
                    f"<div style='border:1px solid {sc}44;border-left:4px solid {sc};"
                    f"border-radius:6px;padding:10px 14px;margin:4px 0;background:#0a1220'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                    f"<span style='color:{sc};font-weight:700;font-size:.9rem'>{inc['id']} — {inc['title']}</span>"
                    f"<span style='color:#446688;font-size:.72rem'>{inc['alert_count']} alerts · "
                    f"opened {age}m ago · last update {last}m ago</span>"
                    f"</div>"
                    f"<span style='color:{sc};font-size:.78rem;font-weight:600'>{inc['severity'].upper()}</span>"
                    f"<span style='color:#446688;font-size:.75rem'> · Agent: {inc['agent']} · "
                    f"Status: {inc['status'].upper()}</span>"
                    f"</div>",
                    unsafe_allow_html=True
                )

    # ── TAB: ASSET INTELLIGENCE ───────────────────────────────────────────────
    with tab_assets:
        st.markdown("### 🖥️ Asset Intelligence")
        st.caption("Which endpoints are generating the most alerts? Who is highest risk?")

        assets = get_assets()

        if not assets:
            st.info("No asset data yet — run the pipeline to populate.")
        else:
            # Top asset highlight
            top = assets[0]
            risk_color = (
                "#ff0033" if top["risk_score"] >= 70 else
                "#ff6600" if top["risk_score"] >= 50 else
                "#ffcc00" if top["risk_score"] >= 30 else "#00cc88"
            )
            st.markdown(
                f"<div style='background:#0a1220;border:1px solid {risk_color}44;"
                f"border-radius:8px;padding:12px 16px;margin-bottom:12px'>"
                f"<span style='color:{risk_color};font-size:1rem;font-weight:700'>"
                f"⚠️ Highest Risk: {top['name']}</span>"
                f"<span style='color:#888;font-size:.8rem'> · {top['ip']} · {top['os']}</span>"
                f"<br><span style='color:#c8e8ff;font-size:.85rem'>"
                f"{top['alert_count']} alerts · {top['threat_count']} threats · "
                f"Risk score: {top['risk_score']}/100</span>"
                f"</div>",
                unsafe_allow_html=True
            )

            # All assets table
            for asset in assets:
                rc = (
                    "#ff0033" if asset["risk_score"] >= 70 else
                    "#ff6600" if asset["risk_score"] >= 50 else
                    "#ffcc00" if asset["risk_score"] >= 30 else "#00cc88"
                )
                bar_w = max(4, asset["risk_score"])
                top_cats = sorted(
                    asset.get("top_categories", {}).items(),
                    key=lambda x: x[1], reverse=True
                )[:3]
                cat_str = " · ".join(f"{c}({n})" for c, n in top_cats)

                st.markdown(
                    f"<div style='background:#0d1825;border:1px solid #1a2a3a;"
                    f"border-radius:6px;padding:10px 14px;margin:4px 0'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                    f"<span style='color:#c8e8ff;font-weight:600'>{asset['name']}</span>"
                    f"<span style='color:#446688;font-size:.75rem'>{asset['ip']} · {asset['os'][:30]}</span>"
                    f"</div>"
                    f"<div style='background:#1a2a3a;border-radius:3px;height:6px;margin:6px 0'>"
                    f"<div style='background:{rc};width:{bar_w}%;height:6px;border-radius:3px'></div>"
                    f"</div>"
                    f"<span style='color:{rc};font-size:.78rem;font-weight:600'>"
                    f"Risk {asset['risk_score']}/100</span> "
                    f"<span style='color:#446688;font-size:.75rem'>"
                    f"· {asset['alert_count']} alerts · {asset['threat_count']} threats</span>"
                    + (f"<br><span style='color:#4a6a8a;font-size:.72rem'>{cat_str}</span>" if cat_str else "")
                    + f"<span style='color:#2a4a6a;font-size:.68rem;float:right'>"
                    f"Last: {asset['last_seen'][:16].replace('T',' ')}</span>"
                    f"</div>",
                    unsafe_allow_html=True
                )

            st.divider()
            total_alerts = sum(a["alert_count"] for a in assets)
            if total_alerts > 0 and assets:
                top_pct = round(assets[0]["alert_count"] / total_alerts * 100)
                st.caption(
                    f"📊 `{assets[0]['name']}` generated {top_pct}% of all alerts "
                    f"({assets[0]['alert_count']}/{total_alerts})"
                )

    # ── TAB: TREND ANALYSIS ───────────────────────────────────────────────────
    with tab_trend:
        st.markdown("### 📈 Trend Analysis")
        st.caption("Alert volume per hour · Attack patterns · Top categories")

        trend = get_trend()
        cats  = get_categories()

        if not trend:
            st.info("No trend data yet — run the pipeline to populate.")
        else:
            # Hourly alert chart using st.bar_chart
            import pandas as pd
            hours  = list(trend.keys())
            counts = list(trend.values())

            # Format hours for display
            labels = [h.replace("T", " ") + ":00" for h in hours]
            df_trend = pd.DataFrame({"Hour": labels, "Alerts": counts})
            df_trend = df_trend.set_index("Hour")

            st.markdown("**Alerts per hour (last 24h):**")
            st.bar_chart(df_trend, color="#00d4ff")

            # Peak hour
            if counts:
                peak_idx = counts.index(max(counts))
                st.caption(
                    f"📍 Peak hour: `{labels[peak_idx]}` — {counts[peak_idx]} alerts  |  "
                    f"Total: {sum(counts)} alerts in last 24h"
                )

            st.divider()

            # Top categories bar chart
            if cats:
                st.markdown("**Top alert categories:**")
                df_cats = pd.DataFrame(
                    list(cats.items())[:10],
                    columns=["Category", "Count"]
                ).set_index("Category")
                st.bar_chart(df_cats, color="#ff6600")

            st.divider()

            # Anomaly detection — flag hours with 3x average
            if len(counts) > 2:
                avg = sum(counts) / len(counts)
                spike_threshold = avg * 3
                spikes = [(labels[i], counts[i]) for i, c in enumerate(counts)
                          if c > spike_threshold and spike_threshold > 0]
                if spikes:
                    st.markdown("**⚠️ Anomaly detected — unusual spikes:**")
                    for hour, cnt in spikes:
                        st.error(
                            f"🚨 `{hour}` had {cnt} alerts "
                            f"({round(cnt/avg, 1)}x above average of {avg:.1f})"
                        )
                else:
                    st.success(f"✅ No anomalies — traffic within normal range (avg {avg:.1f} alerts/hr)")

    # ── TAB: MANUAL RUN ───────────────────────────────────────────────────────
    with tab_manual:
        st.markdown("**Run pipeline once — pulls latest Wazuh alerts and processes them now.**")

        col1, col2, col3 = st.columns(3)
        m_url  = col1.text_input("Wazuh URL",  value=os.getenv("WAZUH_URL",  "https://192.168.1.4:9200"), key="m_url")
        m_user = col2.text_input("Username",   value=os.getenv("WAZUH_USER", "admin"),               key="m_user")
        m_pass = col3.text_input("Password",   type="password",                                           key="m_pass")
        m_lim  = st.slider("Max alerts to process", 1, 50, 10, key="m_lim")

        if st.button("▶ Run Pipeline Now", type="primary", key="pl_manual_run"):
            if not m_pass:
                st.error("Enter Wazuh password first")
            else:
                with st.spinner("Running pipeline..."):
                    cfg     = st.session_state.get("user_api_config", {})
                    results = PipelineEngine.run_once(m_url, m_user, m_pass, cfg, m_lim)

                if results:
                    st.success(f"✅ Processed {len(results)} alert(s)")
                    for r in results:
                        if r.get("error"):
                            st.error(f"❌ Pipeline error: {r['error']}")
                            continue

                        risk_lbl  = r.get("risk_label", r.get("verdict", "UNKNOWN"))
                        score     = r.get("risk_score", r.get("composite_score", 0))
                        cat_icon  = r.get("category_icon", "⬜")
                        category  = r.get("category", "Unknown")
                        expl      = r.get("explanation", r.get("summary", ""))[:150]
                        agent     = r.get("raw_alert", {}).get("agent", {}).get("name", "")
                        mitre_id  = r.get("mitre_id", "")
                        mitre_tac = r.get("mitre_tactic", "")
                        mitre_nm  = r.get("mitre_name", "")
                        playbook  = r.get("playbook", [])
                        sla       = r.get("sla", "")
                        inc_id    = r.get("incident_id", "")
                        who       = r.get("who", "")
                        breakdown = r.get("score_breakdown", [])
                        behavior  = r.get("behavior", {})
                        exec_sum  = r.get("executive_summary", "")

                        sev_colors = {
                            "CRITICAL": "#ff0033", "HIGH": "#ff6600",
                            "MEDIUM":   "#ffcc00", "LOW":  "#00aaff",
                            "INFORMATIONAL": "#888888"
                        }
                        vc = sev_colors.get(risk_lbl, "#888888")

                        st.markdown(
                            f"<div style='border:1px solid {vc}44;border-left:5px solid {vc};"
                            f"border-radius:8px;padding:12px 16px;margin:6px 0;background:#0a1220'>"
                            f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                            f"<span style='font-size:1.1rem'>{cat_icon}</span>"
                            f"<span style='color:{vc};font-weight:700;font-size:.95rem;margin:0 8px'>{risk_lbl}</span>"
                            f"<span style='color:#c8e8ff;font-size:.85rem'>{category}</span>"
                            f"<span style='color:#446688;font-size:.75rem;margin-left:auto'>Score: {score}/100</span>"
                            f"</div>"
                            f"<div style='color:#a8c8e8;font-size:.82rem;margin:6px 0'>{expl}</div>"
                            + (f"<div style='color:#7fb3cc;font-size:.78rem'>👤 {who}</div>" if who else "")
                            + (f"<div style='color:#446688;font-size:.75rem;margin-top:4px'>"
                               f"{'🎯 ' + mitre_id + ' · ' + mitre_nm if mitre_id else ''}"
                               f"{'  |  📂 ' + mitre_tac if mitre_tac else ''}"
                               f"{'  |  📁 ' + inc_id if inc_id else ''}"
                               f"{'  |  ⏱ ' + sla if sla else ''}"
                               f"</div>" if any([mitre_id, inc_id, sla]) else "")
                            + (f"<div style='color:#ff9944;font-size:.78rem;margin-top:4px'>⚡ {behavior['pattern_name']} — {behavior['description']}</div>" if behavior.get("pattern_detected") else "")
                            + f"</div>",
                            unsafe_allow_html=True
                        )

                        if exec_sum:
                            st.caption(f"📋 {exec_sum[:200]}")

                        if playbook:
                            with st.expander(f"📖 Playbook — {len(playbook)} steps"):
                                for i, step in enumerate(playbook, 1):
                                    st.markdown(f"{i}. {step}")

                        if breakdown:
                            with st.expander("📊 Risk score breakdown"):
                                for b in breakdown:
                                    st.markdown(f"- {b}")
                else:
                    st.warning("No new alerts from Wazuh (or connection failed)")

    # ── TAB: TEST ─────────────────────────────────────────────────────────────
    with tab_test:
        st.markdown("**Inject a synthetic alert to test the full pipeline — no Wazuh needed.**")

        sample_alerts = {
            "SSH Brute Force (high risk IP)": {
                "id":   "test-001",
                "rule": {"id": "5710", "description": "SSH brute force attempt", "level": 10,
                         "mitre": {"id": ["T1110"], "tactic": ["credential-access"]}},
                "data": {"srcip": "185.220.101.47", "dstip": "10.0.0.5"},
                "agent": {"name": "prod-server-01", "ip": "10.0.0.5"},
                "timestamp": datetime.utcnow().isoformat(),
            },
            "Suspicious DNS (likely C2)": {
                "id":   "test-002",
                "rule": {"id": "23502", "description": "Suspicious DNS query", "level": 8},
                "data": {"srcip": "10.0.0.22", "query": "xk2f9mq3.xyz"},
                "agent": {"name": "workstation-07", "ip": "10.0.0.22"},
                "timestamp": datetime.utcnow().isoformat(),
            },
            "Known malicious domain": {
                "id":   "test-003",
                "rule": {"id": "87001", "description": "Known malicious domain contacted", "level": 12},
                "data": {"srcip": "10.0.0.15", "hostname": "malware-c2.tk"},
                "agent": {"name": "dev-laptop-03", "ip": "10.0.0.15"},
                "timestamp": datetime.utcnow().isoformat(),
            },
        }

        chosen = st.selectbox("Select test alert", list(sample_alerts.keys()), key="test_alert_sel")
        alert_json = st.text_area(
            "Alert JSON (editable)",
            value=json.dumps(sample_alerts[chosen], indent=2),
            height=180,
            key="test_alert_json"
        )

        if st.button("🧪 Run Test Pipeline", type="primary", key="pl_test_run"):
            try:
                alert = json.loads(alert_json)
            except Exception:
                st.error("Invalid JSON")
                st.stop()

            with st.spinner("Running all 6 pipeline stages..."):
                cfg    = st.session_state.get("user_api_config", {})
                result = PipelineEngine.inject_alert(alert, cfg)

            # Show stage-by-stage breakdown
            stage_icons = {
                "ioc_extraction": "1️⃣",
                "enrichment":     "2️⃣",
                "scoring":        "3️⃣",
                "narrative":      "4️⃣",
                "splunk_push":    "5️⃣",
                "complete":       "✅",
                "complete_fp":    "✅",
                "complete_no_iocs": "ℹ️",
                "error":          "❌",
            }

            st.markdown("#### Pipeline result")
            verdict = result.get("verdict", "?")
            score   = result.get("composite_score", 0)

            col1, col2, col3, col4 = st.columns(4)
            risk_lbl = result.get("risk_label", result.get("verdict", "?"))
            score    = result.get("risk_score", result.get("composite_score", 0))
            col1.metric("Risk Level",  risk_lbl)
            col2.metric("Score",       f"{score}/100")
            col3.metric("Category",    result.get("category", "?"))
            col4.metric("Time",        f"{result.get('elapsed_ms', 0)}ms")

            # Executive summary
            exec_sum = result.get("executive_summary", result.get("summary",""))
            if exec_sum:
                st.info(exec_sum[:300])

            # MITRE
            mitre_id  = result.get("mitre_id", "")
            mitre_nm  = result.get("mitre_name", "")
            mitre_tac = result.get("mitre_tactic", "")
            if mitre_id:
                st.markdown(f"**🎯 MITRE:** `{mitre_id}` — {mitre_nm} · Tactic: {mitre_tac}")

            # Behavior pattern
            beh = result.get("behavior", {})
            if beh.get("pattern_detected"):
                st.error(f"⚡ **Behavioral Pattern:** {beh['pattern_name']} — {beh['description']}")

            # SLA + Incident
            col_a, col_b = st.columns(2)
            if result.get("sla"):
                col_a.info(f"⏱ **SLA:** {result['sla']}")
            if result.get("incident_id"):
                col_b.info(f"📁 **Incident:** {result['incident_id']}")

            # Score breakdown
            if result.get("score_breakdown"):
                with st.expander("📊 Risk score breakdown"):
                    for b in result["score_breakdown"]:
                        st.markdown(f"- {b}")

            # Playbook
            if result.get("playbook"):
                with st.expander(f"📖 Playbook — {len(result['playbook'])} steps"):
                    for i, step in enumerate(result["playbook"], 1):
                        st.markdown(f"{i}. {step}")

            if result.get("is_fp"):
                st.success(f"✅ FP suppressed: {result.get('fp_reason')}")

            with st.expander("Full result JSON"):
                # Don't show raw_alert to keep it clean
                display = {k: v for k, v in result.items()
                           if k not in ("raw_alert", "enrichment", "narrative")}
                st.json(display)

    # ── TAB: CONFIG ───────────────────────────────────────────────────────────
    with tab_config:
        st.markdown("**Pipeline configuration**")

        cfg_url  = st.text_input(
            "Wazuh URL (OpenSearch)",
            value=st.session_state.get("pl_wazuh_url", os.getenv("WAZUH_URL", "https://192.168.1.4:9200")),
            key="cfg_wazuh_url"
        )
        cfg_user = st.text_input(
            "Username",
            value=st.session_state.get("pl_wazuh_user", os.getenv("WAZUH_USER", "admin")),
            key="cfg_wazuh_user"
        )
        cfg_pass = st.text_input("Password", type="password", key="cfg_wazuh_pass")
        cfg_int  = st.slider("Poll interval (seconds)", 10, 300, 30, key="cfg_interval")

        if st.button("💾 Save & Auto-Start Pipeline", type="primary", key="cfg_save"):
            st.session_state["pl_wazuh_url"]  = cfg_url
            st.session_state["pl_wazuh_user"] = cfg_user
            st.session_state["pl_wazuh_pass"] = cfg_pass
            st.session_state["pl_interval"]   = cfg_int
            if cfg_pass:
                if PipelineEngine.is_running():
                    PipelineEngine.stop()
                PipelineEngine.start(
                    poll_interval  = cfg_int,
                    wazuh_url      = cfg_url,
                    wazuh_user     = cfg_user,
                    wazuh_pass     = cfg_pass,
                    session_config = st.session_state.get("user_api_config", {}),
                )
                st.success(f"✅ Pipeline started — polling every {cfg_int}s. Switch to Live Feed tab.")
            else:
                st.error("Enter password to start pipeline")

        st.divider()
        st.markdown("**Webhook mode** — alternative to polling")
        st.code("python realtime_pipeline.py --server", language="bash")
        st.caption(
            f"Then configure Wazuh to POST alerts to: "
            f"`http://YOUR_IP:8001/pipeline/ingest`"
        )

        st.divider()
        st.markdown("**Module status**")
        modules = [
            ("IOC Extractor",     _IOC_EXTRACT),
            ("IOC Enricher",      _ENRICHER),
            ("Reputation Engine", _REP),
            ("Enterprise SOC",    _ENTERPRISE),
            ("Narrative Engine",  _NARRATIVE),
            ("Splunk Handler",    _SPLUNK),
            ("Wazuh Connector",   _WAZUH),
        ]
        for name, loaded in modules:
            icon = "✅" if loaded else "❌"
            st.markdown(f"{icon} `{name}`")


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="NetSec AI Real-Time Pipeline")
    parser.add_argument("--server",   action="store_true", help="Run webhook ingest server")
    parser.add_argument("--port",     type=int, default=8001, help="Webhook server port")
    parser.add_argument("--poll",     action="store_true", help="Run Wazuh polling loop")
    parser.add_argument("--interval", type=int, default=30,  help="Poll interval seconds")
    parser.add_argument("--once",     action="store_true", help="Run pipeline once and exit")
    parser.add_argument("--test",     action="store_true", help="Run test alert through pipeline")
    args = parser.parse_args()

    if args.test:
        print("\nRunning test alert through pipeline...\n")
        test_alert = {
            "id": "cli-test-001",
            "rule": {"id": "5710", "description": "SSH brute force attempt", "level": 10},
            "data": {"srcip": "185.220.101.47"},
            "agent": {"name": "test-server"},
            "timestamp": datetime.utcnow().isoformat(),
        }
        r = PipelineEngine.inject_alert(test_alert)
        print(f"Verdict:  {r['verdict']}")
        print(f"Score:    {r.get('composite_score', 0)}/100")
        print(f"Summary:  {r.get('executive_summary', r.get('summary', ''))}")
        print(f"Actions:  {r.get('recommended_actions', [])}")
        print(f"Elapsed:  {r.get('elapsed_ms', 0)}ms")
        print(f"\nModules: IOC={_IOC_EXTRACT} Enrich={_ENRICHER} Rep={_REP} "
              f"Enterprise={_ENTERPRISE} Narrative={_NARRATIVE} Splunk={_SPLUNK} Wazuh={_WAZUH}")

    elif args.server:
        run_pipeline_webhook_server(port=args.port)

    elif args.poll or args.once:
        wazuh_url  = os.getenv("WAZUH_URL",  "https://192.168.1.6:9200")
        wazuh_user = os.getenv("WAZUH_USER", "admin")
        wazuh_pass = os.getenv("WAZUH_PASS", "SecretPassword")
        if not wazuh_pass:
            print("ERROR: Set WAZUH_PASS environment variable")
            sys.exit(1)
        if args.once:
            results = PipelineEngine.run_once(wazuh_url, wazuh_user, wazuh_pass)
            print(f"Processed {len(results)} alert(s)")
            for r in results:
                print(f"  {r['verdict']:20} {r.get('composite_score',0):3}/100  {r.get('summary','')[:80]}")
        else:
            PipelineEngine.start(args.interval, wazuh_url, wazuh_user, wazuh_pass)
            print(f"Pipeline polling every {args.interval}s — Ctrl+C to stop")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                PipelineEngine.stop()
    else:
        parser.print_help()