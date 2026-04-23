"""
enterprise_soc.py — NetSec AI v11.0  (Enterprise SOC Upgrade)
==============================================================
Drop-in additions wired to your existing:
    Wazuh  →  soc_enhancements.wazuh_get_alerts()
    MISP   →  soc_enhancements.misp_search_ioc()
    Splunk →  splunk_handler.send_to_splunk()
    Triage →  reputation_engine.ReputationEngine.score_with_apis()

New engines in this file
────────────────────────
1.  CorrelationEngine       — Wazuh alert ↔ MISP IOC ↔ Splunk log matching
2.  DynamicRiskScorer       — Composite score: IOC + behavior + intel × confidence
3.  FalsePositiveKiller     — Baseline + frequency + reputation gating
4.  DetectionRuleEngine     — MITRE-tagged Sigma-style rules (DNS C2, BruteForce, LateralMove)
5.  AutomatedResponseEngine — Block IP / isolate host / reset credentials via Wazuh active-response
6.  ContinuousLearningStore — Analyst feedback → adjusts scoring weights persistently
7.  SplunkDetectionRules    — Ready-to-paste SPL correlation searches (MITRE-tagged)
8.  render_enterprise_soc() — Full Streamlit UI tab

Usage
─────
    from enterprise_soc import render_enterprise_soc
    render_enterprise_soc()

Environment variables used (same as rest of stack)
────────────────────────────────────────────────────
    MISP_URL · MISP_API_KEY
    WAZUH_URL · WAZUH_USER · WAZUH_PASS
    SPLUNK_HEC_URL · SPLUNK_HEC_TOKEN
    WAZUH_ACTIVE_RESPONSE_URL  (new — e.g. https://wazuh:55000)
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("netsec.enterprise")

# ─── Safe streamlit import ────────────────────────────────────────────────────
try:
    import streamlit as st
    _ST = True
except ImportError:
    _ST = False

# ─── Safe internal imports ────────────────────────────────────────────────────
try:
    from soc_enhancements import misp_search_ioc, misp_push_ioc, wazuh_get_alerts
    _ENHANCEMENTS = True
except ImportError:
    _ENHANCEMENTS = False
    def misp_search_ioc(ioc, **kw):  return {"found": False, "error": "soc_enhancements not loaded"}
    def misp_push_ioc(*a, **kw):     return False, "soc_enhancements not loaded"
    def wazuh_get_alerts(**kw):      return []

try:
    from splunk_handler import send_to_splunk, build_siem_alert
    _SPLUNK = True
except ImportError:
    _SPLUNK = False
    def send_to_splunk(d): return False, "splunk_handler not loaded"
    def build_siem_alert(*a, **kw): return {}

try:
    from reputation_engine import ReputationEngine
    _REP = True
except ImportError:
    _REP = False
    class ReputationEngine:
        @staticmethod
        def score(ioc, **kw): return {"score": 50, "verdict": "UNKNOWN", "signals": []}


# ══════════════════════════════════════════════════════════════════════════════
# 1.  CORRELATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class CorrelationEngine:
    """
    Matches Wazuh alerts → MISP IOCs → reputation scores.
    Returns unified verdict: CONFIRMED_THREAT / SUSPICIOUS / FALSE_POSITIVE.

    Architecture:
        Wazuh alert (domain/IP extracted)
            ↓
        MISP lookup  (threat_level, tags, families)
            ↓
        Reputation check  (score 0-100)
            ↓
        Correlation verdict + confidence
    """

    CONFIRMED_THRESHOLD  = 65   # MISP hit + rep score < 40  → CONFIRMED_THREAT
    SUSPICIOUS_THRESHOLD = 40   # Either MISP hit OR rep < 40 → SUSPICIOUS
    FP_THRESHOLD         = 72   # rep score ≥ 72 + no MISP    → FALSE_POSITIVE

    @staticmethod
    def _extract_iocs(alert: dict) -> list[str]:
        """Pull IPs and domains from a Wazuh alert dict."""
        iocs = []
        raw  = json.dumps(alert)

        # IPs
        iocs += re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw)
        # Domains (rough heuristic)
        iocs += re.findall(
            r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|xyz|tk|cc|ru|cn|in|info|biz|me)\b',
            raw, re.IGNORECASE
        )
        # Remove private IPs
        iocs = [i for i in iocs if not re.match(
            r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)', i
        )]
        return list(set(iocs))[:8]   # cap at 8 IOCs per alert

    @staticmethod
    def correlate(alert: dict) -> dict:
        """
        Main correlation function.
        Input:  Wazuh alert dict
        Output: {
            verdict, confidence, iocs_checked, misp_hits,
            rep_scores, mitre_tags, threat_actors, reason
        }
        """
        iocs = CorrelationEngine._extract_iocs(alert)
        if not iocs:
            return {
                "verdict": "NO_IOCS", "confidence": 0,
                "iocs_checked": [], "reason": "No extractable IOCs in alert"
            }

        misp_hits    = []
        rep_scores   = {}
        mitre_tags   = set()
        threat_actors= set()

        for ioc in iocs:
            # ── MISP lookup ──────────────────────────────────────────────────
            m = misp_search_ioc(ioc)
            if m.get("found"):
                misp_hits.append({
                    "ioc":      ioc,
                    "level":    m.get("threat_level", "UNKNOWN"),
                    "families": m.get("malware_families", []),
                    "tags":     m.get("tags", []),
                })
                for tag in m.get("tags", []):
                    if "mitre-attack" in tag.lower():
                        tech = re.search(r'T\d{4}(?:\.\d{3})?', tag)
                        if tech:
                            mitre_tags.add(tech.group())
                    if "threat-actor" in tag.lower():
                        threat_actors.add(tag.split("=")[-1].strip('"'))

            # ── Reputation check ─────────────────────────────────────────────
            if _REP:
                r = ReputationEngine.score(ioc, use_apis=False)
                rep_scores[ioc] = r.get("score", 50)
            else:
                rep_scores[ioc] = 50

        # ── Build verdict ────────────────────────────────────────────────────
        min_rep    = min(rep_scores.values()) if rep_scores else 50
        avg_rep    = sum(rep_scores.values()) / len(rep_scores) if rep_scores else 50
        misp_count = len(misp_hits)

        if misp_count > 0 and min_rep < CorrelationEngine.CONFIRMED_THRESHOLD:
            verdict    = "CONFIRMED_THREAT"
            confidence = min(95, 50 + misp_count * 10 + max(0, 40 - min_rep))
            reason     = f"MISP hit + low reputation ({min_rep}/100)"
        elif misp_count > 0 or min_rep < CorrelationEngine.SUSPICIOUS_THRESHOLD:
            verdict    = "SUSPICIOUS"
            confidence = min(75, 30 + misp_count * 8 + max(0, 50 - min_rep))
            reason     = "MISP hit OR low reputation score"
        elif avg_rep >= CorrelationEngine.FP_THRESHOLD:
            verdict    = "FALSE_POSITIVE"
            confidence = min(90, int(avg_rep - 10))
            reason     = f"High average reputation ({avg_rep:.0f}/100), no MISP hits"
        else:
            verdict    = "UNKNOWN"
            confidence = 20
            reason     = "Insufficient signals"

        return {
            "verdict":       verdict,
            "confidence":    confidence,
            "iocs_checked":  iocs,
            "misp_hits":     misp_hits,
            "rep_scores":    rep_scores,
            "mitre_tags":    list(mitre_tags),
            "threat_actors": list(threat_actors),
            "reason":        reason,
            "min_rep":       min_rep,
            "avg_rep":       round(avg_rep, 1),
            "timestamp":     datetime.utcnow().isoformat(),
        }

    @staticmethod
    def batch_correlate(alerts: list[dict]) -> list[dict]:
        """Correlate a list of Wazuh alerts. Returns enriched list."""
        results = []
        for alert in alerts:
            corr = CorrelationEngine.correlate(alert)
            alert["_correlation"] = corr
            results.append(alert)
        return results


# ══════════════════════════════════════════════════════════════════════════════
# 2.  DYNAMIC RISK SCORER
# ══════════════════════════════════════════════════════════════════════════════

class DynamicRiskScorer:
    """
    Composite risk score:
        risk = (ioc_score * W_ioc + behavior_score * W_beh + intel_score * W_int)
               * confidence_multiplier

    Replaces static `risk = 50` patterns.
    """

    # Weights — tuned by ContinuousLearningStore feedback
    _DEFAULT_WEIGHTS = {
        "ioc":      0.40,   # reputation / IOC hits
        "behavior": 0.35,   # frequency, entropy, pattern
        "intel":    0.25,   # MISP + MITRE
    }
    _WEIGHTS_FILE = os.path.join(os.path.dirname(__file__), "data", "risk_weights.json")

    @classmethod
    def _load_weights(cls) -> dict:
        try:
            if os.path.exists(cls._WEIGHTS_FILE):
                with open(cls._WEIGHTS_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return dict(cls._DEFAULT_WEIGHTS)

    @classmethod
    def score(
        cls,
        ioc: str,
        alert_frequency: int    = 1,
        domain_entropy: float   = 0.0,
        misp_threat_level: str  = "LOW",
        mitre_count: int        = 0,
        analyst_feedback: str   = "none",   # "confirmed" | "fp" | "none"
    ) -> dict:
        """
        Returns {composite_score, risk_level, breakdown, recommendation}
        composite_score: 0 (safe) → 100 (critical)
        """
        weights = cls._load_weights()

        # ── IOC sub-score (0-100, higher = MORE malicious) ───────────────────
        rep = ReputationEngine.score(ioc, use_apis=False) if _REP else {"score": 50}
        rep_score   = rep.get("score", 50)
        ioc_score   = max(0, 100 - rep_score)   # invert: low rep → high risk

        # ── Behavior sub-score ───────────────────────────────────────────────
        freq_score    = min(100, alert_frequency * 4)           # 25+ alerts → 100
        entropy_score = min(100, int(domain_entropy * 30))      # high entropy = DGA
        behavior_score = int((freq_score * 0.6) + (entropy_score * 0.4))

        # ── Intel sub-score ──────────────────────────────────────────────────
        misp_map   = {"HIGH": 90, "MEDIUM": 55, "LOW": 20, "UNKNOWN": 10}
        misp_score = misp_map.get(misp_threat_level.upper(), 10)
        mitre_bonus= min(30, mitre_count * 10)
        intel_score= min(100, misp_score + mitre_bonus)

        # ── Composite ────────────────────────────────────────────────────────
        raw = (
            ioc_score      * weights["ioc"] +
            behavior_score * weights["behavior"] +
            intel_score    * weights["intel"]
        )

        # Analyst feedback modifier
        if analyst_feedback == "confirmed":
            raw = min(100, raw * 1.25)
        elif analyst_feedback == "fp":
            raw = max(0,   raw * 0.40)

        composite = round(raw)

        # ── Risk level ───────────────────────────────────────────────────────
        if composite >= 75:
            risk_level = "CRITICAL"
            recommendation = "Immediate containment — auto-block candidate"
        elif composite >= 55:
            risk_level = "HIGH"
            recommendation = "Escalate to Tier 2 analyst — investigate now"
        elif composite >= 35:
            risk_level = "MEDIUM"
            recommendation = "Monitor and enrich — 4-hour SLA"
        elif composite >= 15:
            risk_level = "LOW"
            recommendation = "Log and track — 24-hour SLA"
        else:
            risk_level = "INFORMATIONAL"
            recommendation = "Likely benign — log for baseline"

        return {
            "composite_score":  composite,
            "risk_level":       risk_level,
            "recommendation":   recommendation,
            "breakdown": {
                "ioc_score":       ioc_score,
                "behavior_score":  behavior_score,
                "intel_score":     intel_score,
                "weights_used":    weights,
            },
            "ioc":         ioc,
            "timestamp":   datetime.utcnow().isoformat(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# 3.  FALSE POSITIVE KILLER
# ══════════════════════════════════════════════════════════════════════════════

class FalsePositiveKiller:
    """
    Three-gate FP suppression:
      Gate 1 — Reputation:  score ≥ 72 → likely benign
      Gate 2 — Frequency baseline:  alert count is normal for this asset
      Gate 3 — Behavior whitelist:  known-safe pattern (CDN, update server, etc.)

    Learns from analyst feedback via ContinuousLearningStore.
    """

    SAFE_REPUTATION_THRESHOLD = 72
    _BASELINE_FILE = os.path.join(os.path.dirname(__file__), "data", "fp_baseline.json")

    # Known-safe patterns (extend as you learn your environment)
    SAFE_PATTERNS = [
        r"windowsupdate\.com", r"microsoft\.com", r"apple\.com",
        r"googleapis\.com",    r"gstatic\.com",   r"akamaihd\.net",
        r"cloudfront\.net",    r"fastly\.net",    r"cdn\.",
        r"ocsp\.",             r"crl\.",           r"pki\.",
        r"update\.",           r"patch\.",
    ]

    @classmethod
    def _load_baseline(cls) -> dict:
        try:
            if os.path.exists(cls._BASELINE_FILE):
                with open(cls._BASELINE_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    @classmethod
    def _save_baseline(cls, baseline: dict) -> None:
        os.makedirs(os.path.dirname(cls._BASELINE_FILE), exist_ok=True)
        with open(cls._BASELINE_FILE, "w") as f:
            json.dump(baseline, f, indent=2)

    @classmethod
    def update_baseline(cls, ioc: str, count: int) -> None:
        """Call this daily to update normal frequency baseline."""
        baseline = cls._load_baseline()
        entry    = baseline.get(ioc, {"counts": [], "mean": 0, "std": 0})
        entry["counts"].append(count)
        if len(entry["counts"]) > 30:      # rolling 30-day window
            entry["counts"] = entry["counts"][-30:]
        n = len(entry["counts"])
        mu = sum(entry["counts"]) / n
        std = math.sqrt(sum((x - mu) ** 2 for x in entry["counts"]) / n) if n > 1 else mu
        entry.update({"mean": round(mu, 2), "std": round(std, 2)})
        baseline[ioc] = entry
        cls._save_baseline(baseline)

    @classmethod
    def is_false_positive(
        cls,
        ioc: str,
        current_count: int = 1,
        rep_score: int = 50,
    ) -> tuple[bool, str]:
        """
        Returns (is_fp: bool, reason: str)
        """
        # Gate 1 — reputation
        if rep_score >= cls.SAFE_REPUTATION_THRESHOLD:
            return True, f"High reputation ({rep_score}/100) — below alert threshold"

        # Gate 2 — known-safe pattern
        for pattern in cls.SAFE_PATTERNS:
            if re.search(pattern, ioc, re.IGNORECASE):
                return True, f"Matched known-safe pattern: {pattern}"

        # Gate 3 — frequency baseline (only suppress if count is normal)
        baseline = cls._load_baseline()
        if ioc in baseline:
            entry = baseline[ioc]
            mean  = entry.get("mean", 0)
            std   = entry.get("std",  0)
            upper = mean + 2 * std         # 2σ upper bound
            if current_count <= upper and mean > 0:
                return True, (
                    f"Count {current_count} is within normal baseline "
                    f"(mean={mean:.1f}, +2σ={upper:.1f})"
                )

        return False, "Passed all FP gates — treat as real alert"

    @classmethod
    def bulk_filter(cls, alerts: list[dict]) -> tuple[list[dict], list[dict]]:
        """
        Split alerts into (real_alerts, suppressed_fps).
        Each alert dict should have 'ioc', 'count', 'rep_score' keys.
        """
        real = []
        fps  = []
        for alert in alerts:
            ioc   = alert.get("ioc", "")
            count = int(alert.get("count", 1))
            rep   = int(alert.get("rep_score", 50))
            is_fp, reason = cls.is_false_positive(ioc, count, rep)
            alert["_fp_reason"] = reason
            (fps if is_fp else real).append(alert)
        return real, fps


# ══════════════════════════════════════════════════════════════════════════════
# 4.  DETECTION RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class DetectionRuleEngine:
    """
    Sigma-style detection rules in pure Python.
    Each rule: name, mitre, condition_fn, severity, response_action
    """

    RULES: list[dict] = [
        # ── DNS C2 Beaconing (T1071.004) ─────────────────────────────────────
        {
            "id":          "DNS_C2_BEACONING",
            "name":        "DNS C2 Beaconing",
            "description": "High-frequency DNS queries with high-entropy subdomains → likely C2 tunnel",
            "mitre":       "T1071.004",
            "tactic":      "Command and Control",
            "severity":    "HIGH",
            "response":    "block_domain",
            "condition":   lambda a: (
                a.get("query_count", 0) > 50
                and a.get("unique_subdomains", 0) > 20
                and a.get("entropy", 0.0) > 3.5
            ),
        },
        # ── Brute Force (T1110) ───────────────────────────────────────────────
        {
            "id":          "BRUTE_FORCE_LOGIN",
            "name":        "Brute Force Login Attempt",
            "description": ">20 failed auth attempts from same IP in 5 minutes",
            "mitre":       "T1110",
            "tactic":      "Credential Access",
            "severity":    "HIGH",
            "response":    "block_ip",
            "condition":   lambda a: (
                a.get("failed_logins", 0) > 20
                and a.get("unique_users_targeted", 1) >= 1
                and a.get("time_window_minutes", 60) <= 5
            ),
        },
        # ── Lateral Movement SMB (T1021.002) ─────────────────────────────────
        {
            "id":          "LATERAL_MOVEMENT_SMB",
            "name":        "Lateral Movement via SMB",
            "description": "SMB connections from workstation to multiple internal hosts",
            "mitre":       "T1021.002",
            "tactic":      "Lateral Movement",
            "severity":    "HIGH",
            "response":    "isolate_host",
            "condition":   lambda a: (
                a.get("smb_connections", 0) > 0
                and a.get("unique_dest_hosts", 0) > 3
                and a.get("source_type", "") == "workstation"
            ),
        },
        # ── Data Exfiltration DNS (T1048.003) ────────────────────────────────
        {
            "id":          "DATA_EXFIL_DNS",
            "name":        "Data Exfiltration via DNS",
            "description": "Large DNS payload (>100 chars per query) suggesting DNS tunnelling",
            "mitre":       "T1048.003",
            "tactic":      "Exfiltration",
            "severity":    "CRITICAL",
            "response":    "block_domain",
            "condition":   lambda a: (
                a.get("avg_query_length", 0) > 100
                and a.get("query_count", 0) > 10
            ),
        },
        # ── Persistence via Startup (T1547.001) ──────────────────────────────
        {
            "id":          "PERSISTENCE_STARTUP",
            "name":        "Persistence via Startup Folder",
            "description": "File written to Windows Startup or Run registry key",
            "mitre":       "T1547.001",
            "tactic":      "Persistence",
            "severity":    "MEDIUM",
            "response":    "alert_analyst",
            "condition":   lambda a: (
                any(path in a.get("file_path", "").lower() for path in [
                    "\\startup\\", "\\start menu\\", "software\\microsoft\\windows\\currentversion\\run"
                ])
            ),
        },
        # ── Process Injection (T1055) ─────────────────────────────────────────
        {
            "id":          "PROCESS_INJECTION",
            "name":        "Suspicious Process Injection",
            "description": "Unusual parent→child process relationship (e.g. Word spawning PowerShell)",
            "mitre":       "T1055",
            "tactic":      "Defense Evasion",
            "severity":    "HIGH",
            "response":    "alert_analyst",
            "condition":   lambda a: (
                a.get("parent_process", "").lower() in ["winword.exe", "excel.exe", "powerpnt.exe"]
                and a.get("child_process", "").lower() in [
                    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"
                ]
            ),
        },
        # ── Abnormal Outbound Volume (T1030) ─────────────────────────────────
        {
            "id":          "ABNORMAL_OUTBOUND",
            "name":        "Abnormal Outbound Data Volume",
            "description": "Host sending >500MB outbound in short window",
            "mitre":       "T1030",
            "tactic":      "Exfiltration",
            "severity":    "CRITICAL",
            "response":    "isolate_host",
            "condition":   lambda a: (
                a.get("outbound_mb", 0) > 500
                and a.get("dest_is_external", False)
            ),
        },
    ]

    @classmethod
    def evaluate(cls, alert_fields: dict) -> list[dict]:
        """
        Run all rules against an alert_fields dict.
        Returns list of triggered rule dicts (empty = no match).
        """
        triggered = []
        for rule in cls.RULES:
            try:
                if rule["condition"](alert_fields):
                    triggered.append({
                        "rule_id":     rule["id"],
                        "rule_name":   rule["name"],
                        "description": rule["description"],
                        "mitre":       rule["mitre"],
                        "tactic":      rule["tactic"],
                        "severity":    rule["severity"],
                        "response":    rule["response"],
                        "matched_at":  datetime.utcnow().isoformat(),
                    })
            except Exception as e:
                logger.debug(f"Rule {rule['id']} eval error: {e}")
        return triggered

    @classmethod
    def evaluate_wazuh_alert(cls, alert: dict) -> list[dict]:
        """
        Convert a raw Wazuh alert dict into rule-engine fields then evaluate.
        Extracts common Wazuh fields automatically.
        """
        fields: dict[str, Any] = {}

        # Wazuh standard fields
        fields["failed_logins"]         = int(alert.get("data", {}).get("failed_logins", 0))
        fields["unique_users_targeted"] = int(alert.get("data", {}).get("unique_users", 1))
        fields["time_window_minutes"]   = int(alert.get("data", {}).get("time_window", 60))
        fields["smb_connections"]       = int(alert.get("data", {}).get("smb_count", 0))
        fields["unique_dest_hosts"]     = int(alert.get("data", {}).get("dest_hosts", 0))
        fields["source_type"]           = alert.get("agent", {}).get("type", "")
        fields["query_count"]           = int(alert.get("data", {}).get("dns_queries", 0))
        fields["unique_subdomains"]     = int(alert.get("data", {}).get("unique_subdomains", 0))
        fields["entropy"]               = float(alert.get("data", {}).get("entropy", 0.0))
        fields["avg_query_length"]      = int(alert.get("data", {}).get("avg_dns_len", 0))
        fields["outbound_mb"]           = float(alert.get("data", {}).get("outbound_mb", 0))
        fields["dest_is_external"]      = alert.get("data", {}).get("dest_external", False)
        fields["file_path"]             = alert.get("syscheck", {}).get("path", "")
        fields["parent_process"]        = alert.get("data", {}).get("srcproc", "")
        fields["child_process"]         = alert.get("data", {}).get("dstproc", "")

        return cls.evaluate(fields)


# ══════════════════════════════════════════════════════════════════════════════
# 5.  AUTOMATED RESPONSE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class AutomatedResponseEngine:
    """
    Executes response actions via Wazuh active-response API.
    All actions require confidence ≥ threshold (safety gate).

    Actions:
        block_ip      → Wazuh active-response: firewall-drop
        block_domain  → Wazuh active-response: DNS-blackhole (custom script)
        isolate_host  → Wazuh active-response: host-isolation (custom script)
        alert_analyst → Sends Splunk HEC event + logs
        reset_creds   → Logs recommendation (requires human for AD/LDAP)
    """

    CONFIDENCE_GATES = {
        "block_ip":     85,   # Must be ≥85% confident to auto-block an IP
        "block_domain": 80,
        "isolate_host": 90,   # Highest gate — very disruptive
        "alert_analyst": 0,   # Always allowed
        "reset_creds":   0,   # Recommendation only — always allowed
    }

    @staticmethod
    def _wazuh_active_response(
        command: str, target_ip: str, agent_id: str = "000"
    ) -> tuple[bool, str]:
        """Call Wazuh Manager active-response REST API."""
        import urllib.request as _ur, ssl as _ssl, base64

        wazuh_url  = os.getenv("WAZUH_ACTIVE_RESPONSE_URL", "").rstrip("/")
        wazuh_user = os.getenv("WAZUH_USER", "")
        wazuh_pass = os.getenv("WAZUH_PASS", "")

        if not wazuh_url:
            return False, "WAZUH_ACTIVE_RESPONSE_URL not configured"

        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE

        creds   = base64.b64encode(f"{wazuh_user}:{wazuh_pass}".encode()).decode()
        payload = json.dumps({
            "command":    command,
            "arguments":  [target_ip],
            "agents_list": [agent_id],
        }).encode()

        try:
            req = _ur.Request(
                f"{wazuh_url}/active-response",
                data=payload,
                headers={
                    "Authorization": f"Basic {creds}",
                    "Content-Type":  "application/json",
                },
                method="PUT",
            )
            with _ur.urlopen(req, timeout=8, context=ctx) as r:
                resp = json.loads(r.read().decode())
            return True, f"Wazuh active-response executed: {resp}"
        except Exception as e:
            return False, f"Wazuh active-response failed: {e}"

    @classmethod
    def execute(
        cls,
        action: str,
        target: str,
        confidence: int,
        reason: str = "",
        dry_run: bool = False,
    ) -> dict:
        """
        Execute a response action with confidence gate.
        dry_run=True → log only, no actual execution (safe testing mode).

        Returns {executed, action, target, confidence, gate, message, timestamp}
        """
        gate      = cls.CONFIDENCE_GATES.get(action, 100)
        timestamp = datetime.utcnow().isoformat()

        base = {
            "action":     action,
            "target":     target,
            "confidence": confidence,
            "gate":       gate,
            "reason":     reason,
            "timestamp":  timestamp,
            "dry_run":    dry_run,
        }

        if confidence < gate:
            base.update({
                "executed": False,
                "message":  (
                    f"BLOCKED BY GATE: confidence {confidence}% < required {gate}%. "
                    f"Action not executed. Escalating to analyst."
                ),
            })
            logger.warning(f"[RESPONSE GATE] {action} on {target} blocked — conf {confidence}% < {gate}%")
            return base

        if dry_run:
            base.update({
                "executed": False,
                "message":  f"DRY RUN — would execute {action} on {target}",
            })
            logger.info(f"[RESPONSE DRY RUN] {action} → {target}")
            return base

        # ── Execute ──────────────────────────────────────────────────────────
        ok = False
        msg = ""

        if action == "block_ip":
            ok, msg = cls._wazuh_active_response("firewall-drop5", target)

        elif action == "block_domain":
            # Log for manual DNS-blackhole until custom script is deployed
            ok  = True
            msg = f"DNS block queued for {target} — copy to /etc/hosts or Pi-hole blocklist"
            logger.info(f"[DNS BLOCK] {target} — {msg}")

        elif action == "isolate_host":
            ok, msg = cls._wazuh_active_response("host-deny", target)

        elif action == "alert_analyst":
            if _SPLUNK:
                payload = build_siem_alert(
                    target, "AUTO_RESPONSE_ALERT", 20, confidence, "", "high"
                )
                payload["event"]["auto_response_reason"] = reason
                ok, msg = send_to_splunk(payload)
            else:
                ok  = True
                msg = "Analyst alert logged (Splunk not configured)"
            logger.warning(f"[ANALYST ALERT] {target}: {reason}")

        elif action == "reset_creds":
            ok  = True
            msg = (
                f"⚠️ RECOMMENDATION: Reset credentials for {target}. "
                f"Reason: {reason}. Action requires human approval (AD/LDAP)."
            )
            logger.warning(f"[CRED RESET REC] {target}: {reason}")

        else:
            ok  = False
            msg = f"Unknown action: {action}"

        base.update({"executed": ok, "message": msg})
        logger.info(f"[AUTO RESPONSE] {action} → {target}: {msg}")
        return base


# ══════════════════════════════════════════════════════════════════════════════
# 6.  CONTINUOUS LEARNING STORE
# ══════════════════════════════════════════════════════════════════════════════

class ContinuousLearningStore:
    """
    Stores analyst feedback and adjusts risk scoring weights.

    Feedback types:
        confirmed  → real threat (weight IOC/intel higher)
        fp         → false positive (weight reputation/baseline higher)
        escalated  → needed Tier 2 (log for SLA tuning)

    Weights are persisted to data/risk_weights.json and loaded by DynamicRiskScorer.
    """

    _FEEDBACK_FILE = os.path.join(os.path.dirname(__file__), "data", "analyst_feedback.json")
    _WEIGHTS_FILE  = DynamicRiskScorer._WEIGHTS_FILE

    @classmethod
    def _load_feedback(cls) -> list:
        try:
            if os.path.exists(cls._FEEDBACK_FILE):
                with open(cls._FEEDBACK_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    @classmethod
    def record_feedback(
        cls,
        ioc: str,
        original_verdict: str,
        feedback: str,       # "confirmed" | "fp" | "escalated" | "benign"
        analyst: str = "analyst",
        notes: str   = "",
    ) -> None:
        """Log analyst feedback and retune weights."""
        os.makedirs(os.path.dirname(cls._FEEDBACK_FILE), exist_ok=True)

        log = cls._load_feedback()
        log.append({
            "ioc":      ioc,
            "verdict":  original_verdict,
            "feedback": feedback,
            "analyst":  analyst,
            "notes":    notes,
            "ts":       datetime.utcnow().isoformat(),
        })
        with open(cls._FEEDBACK_FILE, "w") as f:
            json.dump(log, f, indent=2)

        # Retune weights every 10 feedback entries
        if len(log) % 10 == 0:
            cls._retune_weights(log)
        logger.info(f"[FEEDBACK] {ioc}: {feedback} by {analyst}")

    @classmethod
    def _retune_weights(cls, log: list) -> None:
        """Adjust IOC/behavior/intel weights based on feedback statistics."""
        recent = log[-100:]   # last 100 entries only

        confirmed = sum(1 for e in recent if e["feedback"] == "confirmed")
        fps       = sum(1 for e in recent if e["feedback"] == "fp")
        total     = confirmed + fps
        if total < 5:
            return   # Not enough data yet

        fp_rate   = fps / total
        conf_rate = confirmed / total

        # High FP rate → trust reputation more, downweight behavior
        # High confirm rate → trust IOC/intel more
        w_ioc  = round(0.35 + conf_rate * 0.15,  2)
        w_beh  = round(0.35 - fp_rate   * 0.10,  2)
        w_int  = round(max(0.05, 1.0 - w_ioc - w_beh), 2)

        weights = {"ioc": w_ioc, "behavior": w_beh, "intel": w_int}
        os.makedirs(os.path.dirname(cls._WEIGHTS_FILE), exist_ok=True)
        with open(cls._WEIGHTS_FILE, "w") as f:
            json.dump(weights, f, indent=2)
        logger.info(f"[LEARNING] Weights updated: {weights} (FP rate={fp_rate:.0%})")

    @classmethod
    def get_stats(cls) -> dict:
        log = cls._load_feedback()
        if not log:
            return {"total": 0, "confirmed": 0, "fp": 0, "fp_rate": 0.0}
        c   = Counter(e["feedback"] for e in log)
        tot = len(log)
        fp  = c.get("fp", 0)
        return {
            "total":       tot,
            "confirmed":   c.get("confirmed", 0),
            "fp":          fp,
            "escalated":   c.get("escalated", 0),
            "benign":      c.get("benign", 0),
            "fp_rate":     round(fp / tot * 100, 1) if tot else 0.0,
            "recent_iocs": [e["ioc"] for e in log[-5:]],
        }


# ══════════════════════════════════════════════════════════════════════════════
# 7.  SPLUNK DETECTION RULES  (Ready-to-paste SPL)
# ══════════════════════════════════════════════════════════════════════════════

SPLUNK_DETECTION_RULES: dict[str, dict] = {

    "misp_correlation": {
        "title": "MISP IOC Correlation [T1071]",
        "description": "Join Wazuh alerts with MISP lookup CSV to find confirmed IOC hits",
        "mitre": "T1071",
        "spl": """\
index=wazuh OR index=main
| rex field=_raw "(?i)(?:https?://)?(?:www\\.)?(?P<domain>[a-z0-9\\-]+(?:\\.[a-z0-9\\-]+)+)"
| rex field=_raw "(?P<src_ip>\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b)"
| eval ioc=coalesce(domain, src_ip)
| lookup misp_iocs.csv ioc OUTPUT threat_level malware_family tags
| where isnotnull(threat_level)
| eval verdict=case(
    threat_level="HIGH",   "CONFIRMED_THREAT",
    threat_level="MEDIUM", "SUSPICIOUS",
    true(),                "MONITOR"
  )
| table _time, host, ioc, threat_level, malware_family, verdict
| sort -_time""",
    },

    "dns_c2_beaconing": {
        "title": "DNS C2 Beaconing Detection [T1071.004]",
        "description": "High-frequency, high-entropy DNS queries → potential DNS tunnel/C2",
        "mitre": "T1071.004",
        "spl": """\
index=dns OR index=wazuh sourcetype=dns
| rex field=query "^(?P<subdomain>[^.]+)\\.(?P<domain>[^.]+\\.[^.]+)$"
| eval query_len=len(subdomain)
| stats
    count              AS query_count,
    dc(subdomain)      AS unique_subdomains,
    avg(query_len)     AS avg_len
    BY src_ip, domain
| where query_count > 50 AND unique_subdomains > 20 AND avg_len > 15
| eval risk="DNS C2 — T1071.004"
| table src_ip, domain, query_count, unique_subdomains, avg_len, risk
| sort -query_count""",
    },

    "brute_force": {
        "title": "Brute Force Login Detection [T1110]",
        "description": "20+ failed logins from same IP within 5 minutes",
        "mitre": "T1110",
        "spl": """\
index=wazuh OR index=auth
| search (action=failed OR EventCode=4625 OR "authentication failed")
| bucket _time span=5m
| stats
    count AS failed_attempts,
    dc(user) AS unique_users
    BY _time, src_ip
| where failed_attempts > 20
| eval severity="HIGH", mitre="T1110", tactic="Credential Access"
| table _time, src_ip, failed_attempts, unique_users, severity, mitre""",
    },

    "lateral_movement_smb": {
        "title": "Lateral Movement via SMB [T1021.002]",
        "description": "Workstation making SMB connections to 3+ internal hosts",
        "mitre": "T1021.002",
        "spl": """\
index=wazuh OR index=network
| search (dest_port=445 OR dest_port=139)
| stats
    dc(dest_ip) AS unique_dest,
    values(dest_ip) AS destinations
    BY src_ip
| where unique_dest > 3
| eval severity="HIGH", mitre="T1021.002", tactic="Lateral Movement"
| table src_ip, unique_dest, destinations, severity, mitre
| sort -unique_dest""",
    },

    "data_exfil_dns": {
        "title": "DNS Data Exfiltration [T1048.003]",
        "description": "Long DNS query names (>100 chars) suggesting DNS tunnelling for exfil",
        "mitre": "T1048.003",
        "spl": """\
index=dns sourcetype=dns
| eval query_len=len(query)
| where query_len > 100
| stats
    count       AS query_count,
    avg(query_len) AS avg_len,
    values(query)  AS sample_queries
    BY src_ip
| where query_count > 10
| eval severity="CRITICAL", mitre="T1048.003", tactic="Exfiltration"
| table src_ip, query_count, avg_len, severity, mitre""",
    },

    "netsec_ai_high_risk": {
        "title": "NetSec AI — High Risk Verdicts",
        "description": "All SUSPICIOUS/MALICIOUS verdicts from NetSec AI triage engine",
        "mitre": "Multiple",
        "spl": """\
index=main sourcetype=netsec_ai
| where verdict IN ("SUSPICIOUS","MALICIOUS","CONFIRMED_THREAT")
| eval risk_color=case(
    verdict="MALICIOUS",        "🔴",
    verdict="CONFIRMED_THREAT", "🚨",
    verdict="SUSPICIOUS",       "🟡",
    true(),                     "⚪"
  )
| table _time, domain, verdict, score, confidence, mitre_tags, threat_actors, risk_color
| sort -score""",
    },

    "combined_soc_dashboard": {
        "title": "Combined SOC Overview Dashboard",
        "description": "Single pane showing all threats from Wazuh + MISP + NetSec AI",
        "mitre": "All tactics",
        "spl": """\
(index=main sourcetype=netsec_ai verdict IN ("SUSPICIOUS","MALICIOUS","CONFIRMED_THREAT"))
OR (index=wazuh rule.level>=10)
| eval source=case(
    sourcetype="netsec_ai", "NetSec AI",
    index="wazuh",          "Wazuh IDS",
    true(),                 "Unknown"
  )
| eval severity_score=case(
    verdict="MALICIOUS" OR verdict="CONFIRMED_THREAT", 3,
    verdict="SUSPICIOUS" OR rule.level>=12,            2,
    true(),                                            1
  )
| table _time, source, host, domain, verdict, score, severity_score
| sort -severity_score, -_time""",
    },
}


def get_splunk_detection_rules() -> dict:
    return SPLUNK_DETECTION_RULES


# ══════════════════════════════════════════════════════════════════════════════
# 8.  STREAMLIT UI  — render_enterprise_soc()
# ══════════════════════════════════════════════════════════════════════════════

def render_enterprise_soc():
    """
    Full enterprise SOC upgrade UI.
    Call this from app.py as a new tab.
    """
    if not _ST:
        print("[enterprise_soc] Streamlit not available")
        return

    # ── Header ───────────────────────────────────────────────────────────────
    st.markdown("""
    <div style='background:linear-gradient(135deg,#0a1628,#001a33);
                border:1px solid #00d4ff33;border-radius:12px;padding:20px 24px;margin-bottom:20px'>
        <h2 style='color:#00d4ff;margin:0;font-size:1.4rem'>
            🏢 Enterprise SOC Platform — v11.0
        </h2>
        <p style='color:#7fb3cc;margin:6px 0 0;font-size:.85rem'>
            Correlation Engine · Dynamic Risk Scoring · FP Killer ·
            MITRE Detection Rules · Auto-Response · Continuous Learning
        </p>
    </div>
    """, unsafe_allow_html=True)

    tabs = st.tabs([
        "🔗 Correlation",
        "⚡ Dynamic Risk",
        "🚫 FP Killer",
        "🎯 Detection Rules",
        "🤖 Auto-Response",
        "🧠 Learning Loop",
        "📋 Splunk SPL",
    ])

    # ── TAB 1: CORRELATION ENGINE ─────────────────────────────────────────────
    with tabs[0]:
        st.markdown("### 🔗 Correlation Engine")
        st.caption("Matches Wazuh alerts → MISP IOCs → Reputation. Returns unified verdict.")

        col1, col2 = st.columns([2, 1])
        with col1:
            sample_alert = {
                "agent": {"name": "prod-server-01", "ip": "10.0.0.45"},
                "rule":  {"id": "5710", "description": "SSH brute force attempt"},
                "data":  {"srcip": "185.220.101.47", "dstip": "10.0.0.45"},
                "_raw":  "185.220.101.47 attempted SSH login to 10.0.0.45 — failed"
            }
            alert_json = st.text_area(
                "Paste Wazuh alert (JSON)",
                value=json.dumps(sample_alert, indent=2),
                height=180,
                key="corr_alert_input"
            )
        with col2:
            st.markdown("**What this does:**")
            st.markdown("""
- Extracts IPs/domains from alert
- Checks each IOC against MISP
- Scores reputation (0–100)
- Returns **CONFIRMED_THREAT / SUSPICIOUS / FALSE_POSITIVE**
            """)

        if st.button("🔗 Correlate Alert", type="primary", key="corr_run"):
            try:
                alert = json.loads(alert_json)
            except Exception:
                st.error("Invalid JSON — fix the alert format")
                return

            with st.spinner("Correlating across Wazuh + MISP + Reputation..."):
                result = CorrelationEngine.correlate(alert)

            verdict = result["verdict"]
            col_a, col_b, col_c = st.columns(3)
            color_map = {
                "CONFIRMED_THREAT": "#ff3366",
                "SUSPICIOUS":       "#ffcc00",
                "FALSE_POSITIVE":   "#00cc88",
                "UNKNOWN":          "#888",
                "NO_IOCS":          "#888",
            }
            vcolor = color_map.get(verdict, "#888")

            col_a.metric("Verdict",     verdict)
            col_b.metric("Confidence",  f"{result['confidence']}%")
            col_c.metric("IOCs Checked",len(result["iocs_checked"]))

            st.markdown(f"**Reason:** {result['reason']}")

            if result.get("misp_hits"):
                st.error(f"🚨 **MISP Hits:** {len(result['misp_hits'])} IOC(s) found in threat intel")
                for hit in result["misp_hits"]:
                    st.markdown(
                        f"- `{hit['ioc']}` → Level: **{hit['level']}** | "
                        f"Families: {', '.join(hit['families']) or 'N/A'}"
                    )
            if result.get("mitre_tags"):
                st.warning(f"📌 MITRE Tags: {', '.join(result['mitre_tags'])}")
            if result.get("threat_actors"):
                st.warning(f"👤 Threat Actors: {', '.join(result['threat_actors'])}")

            with st.expander("Full Reputation Scores"):
                for ioc, score in result.get("rep_scores", {}).items():
                    bar_color = "#00cc88" if score >= 72 else "#ffcc00" if score >= 40 else "#ff3366"
                    st.markdown(
                        f"`{ioc}` — Score: **{score}/100** "
                        f"<span style='color:{bar_color}'>{'█' * (score // 10)}</span>",
                        unsafe_allow_html=True
                    )

    # ── TAB 2: DYNAMIC RISK SCORER ────────────────────────────────────────────
    with tabs[1]:
        st.markdown("### ⚡ Dynamic Risk Scorer")
        st.caption("Composite score: IOC × behavior × intel × confidence. Replaces static risk=50.")

        c1, c2 = st.columns(2)
        with c1:
            ioc_input    = st.text_input("IOC (domain or IP)", "login-paytm-secure.in", key="drs_ioc")
            freq         = st.slider("Alert frequency (last hour)", 1, 200, 35, key="drs_freq")
            entropy      = st.slider("Domain entropy", 0.0, 5.0, 3.8, step=0.1, key="drs_ent")
        with c2:
            misp_level   = st.selectbox("MISP threat level", ["LOW", "MEDIUM", "HIGH", "UNKNOWN"], 1, key="drs_misp")
            mitre_count  = st.number_input("MITRE techniques matched", 0, 10, 2, key="drs_mit")
            feedback     = st.selectbox("Prior analyst feedback", ["none", "confirmed", "fp"], key="drs_fb")

        if st.button("⚡ Calculate Risk", type="primary", key="drs_run"):
            result = DynamicRiskScorer.score(
                ioc_input, int(freq), float(entropy),
                misp_level, int(mitre_count), feedback
            )
            score = result["composite_score"]
            level = result["risk_level"]

            level_colors = {
                "CRITICAL": "#ff0033", "HIGH": "#ff6600",
                "MEDIUM":   "#ffcc00", "LOW":  "#00aaff",
                "INFORMATIONAL": "#00cc88"
            }
            lc = level_colors.get(level, "#888")

            st.markdown(
                f"<div style='background:#0a1628;border:2px solid {lc};"
                f"border-radius:10px;padding:16px;text-align:center'>"
                f"<div style='font-size:2.5rem;font-weight:700;color:{lc}'>{score}</div>"
                f"<div style='color:{lc};font-size:1.1rem'>{level}</div>"
                f"</div>",
                unsafe_allow_html=True
            )
            st.info(f"💡 **Recommendation:** {result['recommendation']}")

            bd = result["breakdown"]
            col_x, col_y, col_z = st.columns(3)
            col_x.metric("IOC Sub-score",      bd["ioc_score"])
            col_y.metric("Behavior Sub-score",  bd["behavior_score"])
            col_z.metric("Intel Sub-score",     bd["intel_score"])

            w = bd["weights_used"]
            st.caption(
                f"Weights used — IOC: {w['ioc']:.0%}  |  "
                f"Behavior: {w['behavior']:.0%}  |  Intel: {w['intel']:.0%}  "
                f"(auto-tuned from analyst feedback)"
            )

    # ── TAB 3: FALSE POSITIVE KILLER ─────────────────────────────────────────
    with tabs[2]:
        st.markdown("### 🚫 False Positive Killer")
        st.caption("Three-gate FP suppression: reputation · known-safe patterns · frequency baseline")

        fp_ioc   = st.text_input("IOC to test", "windowsupdate.com", key="fp_ioc")
        fp_count = st.number_input("Current alert count",  1, 10000, 5,  key="fp_count")
        fp_rep   = st.slider("Reputation score",           0, 100,   85, key="fp_rep")

        if st.button("🚫 Check for FP", type="primary", key="fp_run"):
            is_fp, reason = FalsePositiveKiller.is_false_positive(
                fp_ioc, int(fp_count), int(fp_rep)
            )
            if is_fp:
                st.success(f"✅ **FALSE POSITIVE** — suppressed\n\nReason: {reason}")
            else:
                st.error(f"🚨 **REAL ALERT** — passed all FP gates\n\nReason: {reason}")

        st.divider()
        st.markdown("#### Update Frequency Baseline")
        st.caption("Run daily to teach the system what's 'normal' for each IOC in your environment")
        b_ioc   = st.text_input("IOC", "analytics.company.com", key="base_ioc")
        b_count = st.number_input("Today's alert count", 1, 10000, 12, key="base_count")
        if st.button("📊 Update Baseline", key="base_run"):
            FalsePositiveKiller.update_baseline(b_ioc, int(b_count))
            st.success(f"Baseline updated for `{b_ioc}` (count={b_count})")

    # ── TAB 4: DETECTION RULES ────────────────────────────────────────────────
    with tabs[3]:
        st.markdown("### 🎯 MITRE-Tagged Detection Rules")
        st.caption("Sigma-style rules running in pure Python against Wazuh alert fields")

        rule_names = [f"{r['mitre']} — {r['name']}" for r in DetectionRuleEngine.RULES]
        selected   = st.selectbox("Select rule to inspect", rule_names, key="dr_select")

        rule = next((r for r in DetectionRuleEngine.RULES
                     if r["name"] in selected), None)
        if rule:
            col1, col2, col3 = st.columns(3)
            col1.metric("Severity", rule["severity"])
            col2.metric("MITRE",    rule["mitre"])
            col3.metric("Response", rule["response"])
            st.markdown(f"**Tactic:** {rule['tactic']}")
            st.markdown(f"**Description:** {rule['description']}")

        st.divider()
        st.markdown("#### Test Rules Against Alert Fields")
        sample_fields = {
            "failed_logins":         25,
            "unique_users_targeted": 1,
            "time_window_minutes":   3,
            "query_count":           0,
            "unique_subdomains":     0,
            "entropy":               0.0,
        }
        fields_json = st.text_area(
            "Alert fields (JSON)",
            value=json.dumps(sample_fields, indent=2),
            height=160,
            key="dr_fields"
        )
        if st.button("🎯 Evaluate Rules", type="primary", key="dr_eval"):
            try:
                fields = json.loads(fields_json)
                triggered = DetectionRuleEngine.evaluate(fields)
                if triggered:
                    for t in triggered:
                        st.error(
                            f"🚨 **{t['rule_name']}** | {t['mitre']} | {t['severity']} | "
                            f"Response: `{t['response']}`"
                        )
                else:
                    st.success("✅ No rules triggered — alert does not match any detection pattern")
            except json.JSONDecodeError:
                st.error("Invalid JSON in alert fields")

    # ── TAB 5: AUTO-RESPONSE ──────────────────────────────────────────────────
    with tabs[4]:
        st.markdown("### 🤖 Automated Response Engine")
        st.caption("Safety-gated auto-response via Wazuh active-response. Confidence gates prevent noise.")

        st.info(
            "**Confidence gates:** block_ip ≥85% | block_domain ≥80% | "
            "isolate_host ≥90% | alert_analyst always allowed"
        )

        c1, c2 = st.columns(2)
        with c1:
            ar_action     = st.selectbox(
                "Action", ["block_ip", "block_domain", "isolate_host", "alert_analyst", "reset_creds"],
                key="ar_action"
            )
            ar_target     = st.text_input("Target (IP / domain / hostname)", "185.220.101.47", key="ar_target")
        with c2:
            ar_confidence = st.slider("Confidence %", 0, 100, 87, key="ar_conf")
            ar_reason     = st.text_input("Reason / evidence", "MISP hit + rep score 12/100", key="ar_reason")
            ar_dry        = st.checkbox("🧪 Dry run (safe test — no real action)", value=True, key="ar_dry")

        if st.button("🤖 Execute Response", type="primary", key="ar_run"):
            result = AutomatedResponseEngine.execute(
                ar_action, ar_target, int(ar_confidence), ar_reason, dry_run=ar_dry
            )
            if result["executed"] or result.get("dry_run"):
                st.success(f"✅ {result['message']}")
            elif not result["executed"] and result.get("gate"):
                st.warning(f"🛡️ {result['message']}")
            else:
                st.error(f"❌ {result['message']}")

            with st.expander("Response details"):
                st.json(result)

    # ── TAB 6: LEARNING LOOP ──────────────────────────────────────────────────
    with tabs[5]:
        st.markdown("### 🧠 Continuous Learning Loop")
        st.caption(
            "Every 10 analyst feedbacks auto-retune IOC/behavior/intel weights. "
            "High FP rate → trust reputation more. High confirm rate → trust IOC/intel more."
        )

        stats = ContinuousLearningStore.get_stats()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Feedback",   stats["total"])
        c2.metric("Confirmed Threats",stats["confirmed"])
        c3.metric("False Positives",  stats["fp"])
        c4.metric("FP Rate",          f"{stats['fp_rate']}%")

        if stats.get("recent_iocs"):
            st.caption(f"Recent feedback IOCs: {', '.join(stats['recent_iocs'])}")

        st.divider()
        st.markdown("#### Submit Analyst Feedback")
        fb_ioc     = st.text_input("IOC", "random-new-xyz-987654.xyz", key="fb_ioc")
        fb_verdict = st.text_input("Original verdict", "SUSPICIOUS", key="fb_verdict")
        fb_type    = st.selectbox("Your feedback", ["confirmed", "fp", "escalated", "benign"], key="fb_type")
        fb_analyst = st.text_input("Analyst name", "analyst1", key="fb_analyst")
        fb_notes   = st.text_area("Notes", height=80, key="fb_notes")

        if st.button("🧠 Submit Feedback", type="primary", key="fb_submit"):
            ContinuousLearningStore.record_feedback(
                fb_ioc, fb_verdict, fb_type, fb_analyst, fb_notes
            )
            st.success(
                f"✅ Feedback recorded. "
                f"Weights will auto-retune every 10 entries (currently {stats['total']+1})."
            )
            # Show updated weights
            weights = DynamicRiskScorer._load_weights()
            st.json({"updated_weights": weights})

    # ── TAB 7: SPLUNK SPL ─────────────────────────────────────────────────────
    with tabs[6]:
        st.markdown("### 📋 Splunk Detection Rules — Copy-Paste SPL")
        st.caption("Enterprise-grade MITRE-tagged correlation searches. Paste directly into Splunk.")

        rules = get_splunk_detection_rules()
        rule_choice = st.selectbox(
            "Select rule",
            list(rules.keys()),
            format_func=lambda k: f"{rules[k]['mitre']} — {rules[k]['title']}",
            key="spl_rule_choice"
        )
        rule = rules[rule_choice]
        st.markdown(f"**{rule['title']}**")
        st.markdown(f"*{rule['description']}*")
        st.code(rule["spl"], language="spl")
        st.caption(
            "Copy → Splunk Web → Search → paste → Save As Alert → "
            "Trigger: Number of Results > 0 → Action: Webhook → http://YOUR_PC:8000/webhook/splunk"
        )

        st.divider()
        st.markdown("#### MISP Lookup CSV — create this in Splunk")
        st.markdown(
            "After exporting IOCs from MISP, copy to "
            "`$SPLUNK_HOME/etc/apps/search/lookups/misp_iocs.csv`"
        )
        sample_csv = (
            "ioc,threat_level,malware_family,tags,source\n"
            "185.220.101.47,HIGH,Cobalt Strike,mitre-attack:T1071,MISP\n"
            "login-paytm-secure.in,MEDIUM,Phishing,mitre-attack:T1566,MISP\n"
            "malware-c2.tk,HIGH,AgentTesla,mitre-attack:T1071.004,MISP\n"
        )
        st.code(sample_csv, language="csv")
        st.download_button(
            "⬇️ Download sample misp_iocs.csv",
            data=sample_csv,
            file_name="misp_iocs.csv",
            mime="text/csv",
            key="dl_misp_csv"
        )

        st.divider()
        st.markdown("#### Wazuh → Splunk forwarding (inputs.conf snippet)")
        st.code("""\
[monitor:///var/ossec/logs/alerts/alerts.json]
disabled = false
index    = wazuh
sourcetype = wazuh
""", language="ini")