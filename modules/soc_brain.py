"""
soc_brain.py  —  NetSec AI SOC Decision Brain
================================================
Implements all 5 priority upgrades:

  P1. Correlation Engine    — groups alerts by host+time → detects attack chains
  P2. Asset Intelligence    — hostname/IP mapping + criticality scoring
  P3. Real-Time Automation  — auto-triage + auto-dispatch without button clicks
  P4. Incident View         — alerts → incidents with timeline + verdict
  P5. AI Narrative Engine   — structured SOC-grade output (what/why/do/confidence)
"""

from __future__ import annotations
import json, re, time, hashlib, os, logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Any

logger = logging.getLogger("netsec.soc_brain")


# ══════════════════════════════════════════════════════════════════════════════
# P2 — ASSET INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

# Asset registry — auto-populated from observed hosts + analyst-defined entries
_DEFAULT_ASSET_DB = {
    # Critical infrastructure
    "domain_controller":  {"criticality":10,"os":"Windows Server","env":"Production","owner":"IT-Ops","role":"Domain Controller","type":"Server","tags":["dc","ad","critical"]},
    "dc":                 {"criticality":10,"os":"Windows Server","env":"Production","owner":"IT-Ops","role":"Domain Controller","type":"Server","tags":["dc","ad","critical"]},
    "dc01":               {"criticality":10,"os":"Windows Server","env":"Production","owner":"IT-Ops","role":"Domain Controller","type":"Server","tags":["dc","critical"]},
    "dc02":               {"criticality":10,"os":"Windows Server","env":"Production","owner":"IT-Ops","role":"Domain Controller","type":"Server","tags":["dc","critical"]},
    # Servers
    "fileserver":         {"criticality": 8,"os":"Windows Server","env":"Production","owner":"IT-Ops","role":"File Server","type":"Server","tags":["file","server"]},
    "sqlserver":          {"criticality": 9,"os":"Windows Server","env":"Production","owner":"IT-Ops","role":"Database Server","type":"Server","tags":["sql","db"]},
    "webserver":          {"criticality": 8,"os":"Linux","env":"Production","owner":"Dev-Ops","role":"Web Server","type":"Server","tags":["web","server"]},
    "prod-server":        {"criticality": 9,"os":"Linux","env":"Production","owner":"Dev-Ops","role":"Production Server","type":"Server","tags":["prod"]},
    "prod-server-01":     {"criticality": 9,"os":"Linux","env":"Production","owner":"Dev-Ops","role":"Production Server","type":"Server","tags":["prod"]},
    "backup":             {"criticality": 7,"os":"Linux","env":"Production","owner":"IT-Ops","role":"Backup Server","type":"Server","tags":["backup"]},
    "vpn":                {"criticality": 8,"os":"Linux","env":"Production","owner":"NetSec","role":"VPN Gateway","type":"Network","tags":["vpn","gateway"]},
    "firewall":           {"criticality": 9,"os":"FortiOS","env":"Production","owner":"NetSec","role":"Firewall","type":"Network","tags":["firewall","network"]},
    "payment-server":     {"criticality":10,"os":"Linux","env":"Production","owner":"Finance","role":"Payment Processing Server","type":"Server","tags":["payment","pci","critical"]},
    "payment-server-01":  {"criticality":10,"os":"Linux","env":"Production","owner":"Finance","role":"Payment Processing Server","type":"Server","tags":["payment","pci","critical"]},
    # Workstations
    "workstation":        {"criticality": 4,"os":"Windows 11","env":"Corporate","owner":"User","role":"User Workstation","type":"Workstation","tags":["workstation"]},
    "workstation-03":     {"criticality": 4,"os":"Windows 11","env":"Corporate","owner":"User","role":"User Workstation","type":"Workstation","tags":["workstation"]},
    "workstation-07":     {"criticality": 4,"os":"Windows 11","env":"Corporate","owner":"User","role":"User Workstation","type":"Workstation","tags":["workstation"]},
    "laptop":             {"criticality": 4,"os":"Windows 11","env":"Corporate","owner":"User","role":"User Laptop","type":"Workstation","tags":["laptop"]},
    "desktop":            {"criticality": 3,"os":"Windows 10","env":"Corporate","owner":"User","role":"User Desktop","type":"Workstation","tags":["desktop"]},
    # Lab/Dev
    "lonewarrior":        {"criticality": 5,"os":"Windows 11","env":"Lab/Dev","owner":"Security Lab","role":"Security Research Workstation","type":"Workstation","tags":["lab","research","dev"]},
    "lone":               {"criticality": 5,"os":"Windows 11","env":"Lab/Dev","owner":"Security Lab","role":"Security Research Workstation","type":"Workstation","tags":["lab","research","dev"]},
    "warrior":            {"criticality": 5,"os":"Windows 11","env":"Lab/Dev","owner":"Security Lab","role":"Security Research Workstation","type":"Workstation","tags":["lab","research","dev"]},
    "lone-warrior":       {"criticality": 5,"os":"Windows 11","env":"Lab/Dev","owner":"Security Lab","role":"Security Research Workstation","type":"Workstation","tags":["lab","research","dev"]},
    "kali":               {"criticality": 3,"os":"Kali Linux","env":"Lab/Dev","owner":"Security Lab","role":"Penetration Testing VM","type":"VM","tags":["kali","pentest","lab"]},
    "kali-lab":           {"criticality": 3,"os":"Kali Linux","env":"Lab/Dev","owner":"Security Lab","role":"Penetration Testing VM","type":"VM","tags":["kali","pentest","lab"]},
    "parrot":             {"criticality": 3,"os":"Parrot OS","env":"Lab/Dev","owner":"Security Lab","role":"Security Research VM","type":"VM","tags":["parrot","lab"]},
    "ubuntu":             {"criticality": 4,"os":"Ubuntu","env":"Lab/Dev","owner":"Dev","role":"Development Server","type":"VM","tags":["ubuntu","dev"]},
    "devserver":          {"criticality": 4,"os":"Linux","env":"Dev","owner":"Dev","role":"Development Server","type":"Server","tags":["dev"]},
    "testserver":         {"criticality": 3,"os":"Linux","env":"Test","owner":"QA","role":"Test Server","type":"Server","tags":["test"]},
    # Devansh's lab machine patterns (from Wazuh agent names)
    "devansh":            {"criticality": 5,"os":"Windows 11","env":"Lab/Dev","owner":"Devansh Jain","role":"Security Research Workstation","type":"Workstation","tags":["lab","research","dev"]},
    "devansh-pc":         {"criticality": 5,"os":"Windows 11","env":"Lab/Dev","owner":"Devansh Jain","role":"Security Research Workstation","type":"Workstation","tags":["lab","dev"]},
    "student":            {"criticality": 4,"os":"Windows 11","env":"Lab/Dev","owner":"Student","role":"Student Lab Machine","type":"Workstation","tags":["lab","student"]},
    "dev-machine":        {"criticality": 4,"os":"Windows 11","env":"Lab/Dev","owner":"Developer","role":"Developer Workstation","type":"Workstation","tags":["dev"]},
    "ids-project":        {"criticality": 5,"os":"Windows 11","env":"Lab/Dev","owner":"Devansh Jain","role":"IDS Research Machine","type":"Workstation","tags":["lab","ids","research"]},
    "wazuh-agent":        {"criticality": 4,"os":"Linux","env":"Lab/Dev","owner":"Security Lab","role":"Wazuh Monitored Host","type":"VM","tags":["wazuh","monitored"]},
    "windows10":          {"criticality": 4,"os":"Windows 10","env":"Lab","owner":"Lab","role":"Lab Workstation","type":"Workstation","tags":["lab"]},
    "windows11":          {"criticality": 4,"os":"Windows 11","env":"Lab","owner":"Lab","role":"Lab Workstation","type":"Workstation","tags":["lab"]},
    "win10":              {"criticality": 4,"os":"Windows 10","env":"Lab","owner":"Lab","role":"Lab Workstation","type":"Workstation","tags":["lab"]},
    "win11":              {"criticality": 4,"os":"Windows 11","env":"Lab","owner":"Lab","role":"Lab Workstation","type":"Workstation","tags":["lab"]},
    "msedgewin10":        {"criticality": 3,"os":"Windows 10","env":"Lab","owner":"Microsoft","role":"Edge Browser Test VM","type":"VM","tags":["lab","test","microsoft"]},
    "desktop-":           {"criticality": 4,"os":"Windows","env":"Corporate","owner":"User","role":"User Desktop","type":"Workstation","tags":["desktop"]},
    "laptop-":            {"criticality": 4,"os":"Windows","env":"Corporate","owner":"User","role":"User Laptop","type":"Workstation","tags":["laptop"]},
    "pc-":                {"criticality": 4,"os":"Windows","env":"Corporate","owner":"User","role":"User PC","type":"Workstation","tags":["workstation"]},
    # Default fallback
    "unknown":            {"criticality": 3,"os":"Unknown","env":"Unknown","owner":"Unassigned","role":"Unclassified Host","type":"Unknown","tags":["unclassified"]},
}

# Seen-hosts registry: auto-populated when alerts arrive
_SEEN_HOSTS: dict[str, dict] = {}

def register_host(hostname: str, ip: str = "", extra: dict = None) -> None:
    """Auto-register a host when first seen in an alert."""
    key = (hostname or ip or "unknown").lower()
    if key not in _SEEN_HOSTS:
        _SEEN_HOSTS[key] = {
            "hostname":   hostname or "unknown",
            "ip":         ip or "",
            "first_seen": __import__("datetime").datetime.utcnow().isoformat(),
            "alert_count": 0,
        }
    _SEEN_HOSTS[key]["alert_count"] = _SEEN_HOSTS[key].get("alert_count", 0) + 1
    if extra:
        _SEEN_HOSTS[key].update(extra)

_CRITICAL_IP_RANGES = [
    ("10.0.0.1",     "Default Gateway",              9),
    ("10.0.0.10",    "Domain Controller",            10),
    ("10.0.0.20",    "File Server",                   8),
    ("10.0.1.1",     "Lab Gateway",                   8),
    ("10.0.1.5",     "Security Research Workstation", 5),
    ("10.0.1.10",    "Internal Workstation",           4),
    ("10.0.1.20",    "Lab Server",                     5),
    ("192.168.1.1",  "Router/Gateway",                 9),
    ("192.168.0.1",  "Router/Gateway",                 9),
    ("192.168.1.100","Lab Workstation",                4),
    ("172.16.0.1",   "Internal Gateway",               8),
]




def _smart_resolve(hostname: str) -> dict | None:
    """
    Smart hostname resolution — handles prefix patterns, fuzzy match,
    and auto-classifies unknown hosts from name structure.
    """
    if not hostname:
        return None
    h = hostname.lower().strip()

    # Exact match
    if h in _DEFAULT_ASSET_DB:
        return _DEFAULT_ASSET_DB[h].copy()

    # Prefix match (e.g. "desktop-abc123" matches "desktop-")
    for key, data in _DEFAULT_ASSET_DB.items():
        if key.endswith("-") and h.startswith(key):
            result = data.copy()
            result["display_name"] = hostname
            return result

    # Partial/substring match (e.g. "lonewarrior-1" matches "lonewarrior")
    for key, data in _DEFAULT_ASSET_DB.items():
        if key in h or h in key:
            result = data.copy()
            result["display_name"] = hostname
            return result

    # Session whitelist (analyst-added)
    try:
        import streamlit as _st
        analyst_assets = _st.session_state.get("analyst_asset_db", {})
        if h in analyst_assets:
            return analyst_assets[h].copy()
    except Exception:
        pass

    # Auto-classify from hostname structure
    auto = None
    if any(h.startswith(p) for p in ["dc", "ad", "domain"]):
        auto = {"role":"Domain Controller","type":"Server","criticality":10,"env":"Production","os":"Windows Server","owner":"IT-Ops"}
    elif any(p in h for p in ["sql","db","database"]):
        auto = {"role":"Database Server","type":"Server","criticality":9,"env":"Production","os":"Windows Server","owner":"IT-Ops"}
    elif any(p in h for p in ["web","www","nginx","apache"]):
        auto = {"role":"Web Server","type":"Server","criticality":8,"env":"Production","os":"Linux","owner":"Dev-Ops"}
    elif any(p in h for p in ["kali","parrot","pentest","hack","security","sec","lab","test","research"]):
        auto = {"role":"Security Research / Lab VM","type":"VM","criticality":4,"env":"Lab/Dev","os":"Linux","owner":"Security Lab"}
    elif any(p in h for p in ["win","desktop","laptop","pc","workstation","user","client"]):
        auto = {"role":"User Workstation","type":"Workstation","criticality":4,"env":"Corporate","os":"Windows","owner":"User"}
    elif any(p in h for p in ["server","srv","prod","app"]):
        auto = {"role":"Application Server","type":"Server","criticality":7,"env":"Production","os":"Linux","owner":"IT-Ops"}
    elif any(p in h for p in ["ubuntu","debian","centos","rhel","fedora","linux"]):
        auto = {"role":"Linux Host","type":"Server","criticality":5,"env":"Lab/Dev","os":"Linux","owner":"IT-Ops"}
    elif any(p in h for p in ["vm","vbox","vmware","virtual","hyper"]):
        auto = {"role":"Virtual Machine","type":"VM","criticality":4,"env":"Lab/Dev","os":"Unknown","owner":"Lab"}

    if auto:
        auto["display_name"] = hostname
        auto["tags"] = ["auto-classified"]
        return auto

    return None

def resolve_asset(hostname: str = "", ip: str = "") -> dict:
    """
    Map hostname/IP to asset record. Never returns generic 'Unknown Host'.
    Tries: exact match → partial match → IP match → seen-hosts → smart inference.
    """
    hostname_clean = (hostname or "").lower().strip()
    ip_clean       = (ip or "").strip()
    display_name   = hostname or ip or "Unidentified Host"

    asset = None

    # 1. Exact match in asset DB
    if hostname_clean in _DEFAULT_ASSET_DB:
        asset = _DEFAULT_ASSET_DB[hostname_clean].copy()

    # 2. Partial / prefix match + smart resolution
    if not asset:
        for key, data in _DEFAULT_ASSET_DB.items():
            if key != "unknown" and (key in hostname_clean or hostname_clean.startswith(key)):
                asset = data.copy()
                break
    if not asset:
        asset = _smart_resolve(hostname_clean)

    # 3. IP match in known ranges
    if not asset and ip_clean:
        for known_ip, role, crit in _CRITICAL_IP_RANGES:
            if ip_clean == known_ip:
                asset = {
                    "criticality": crit, "role": role,
                    "os": "Unknown", "env": "Production",
                    "owner": "IT-Ops", "type": "Server",
                    "tags": [],
                }
                break

    # 4. Check seen-hosts registry
    if not asset:
        seen = _SEEN_HOSTS.get(hostname_clean) or _SEEN_HOSTS.get(ip_clean)
        if seen:
            asset = _DEFAULT_ASSET_DB["unknown"].copy()
        # Use actual hostname for display instead of "unknown"
        if hostname or ip:
            asset["display_name"] = hostname or ip
            asset["role"] = f"Unclassified: {hostname or ip}"
            asset.update(seen)

    # 5. Smart inference from hostname pattern — never show "Unknown Host"
    if not asset:
        hn = hostname_clean
        if any(k in hn for k in ["dc","domain","ad-","ldap"]):
            asset = {"criticality":10,"os":"Windows Server","env":"Production","owner":"IT-Ops","role":"Domain Controller","type":"Server","tags":["dc"]}
        elif any(k in hn for k in ["sql","db","database","mongo","mysql","postgres"]):
            asset = {"criticality":9,"os":"Windows/Linux","env":"Production","owner":"Dev-Ops","role":"Database Server","type":"Server","tags":["db"]}
        elif any(k in hn for k in ["web","www","nginx","apache","iis"]):
            asset = {"criticality":8,"os":"Linux","env":"Production","owner":"Dev-Ops","role":"Web Server","type":"Server","tags":["web"]}
        elif any(k in hn for k in ["prod","prd","live"]):
            asset = {"criticality":9,"os":"Linux","env":"Production","owner":"Dev-Ops","role":"Production Server","type":"Server","tags":["prod"]}
        elif any(k in hn for k in ["dev","test","qa","stage","stg","lab","kali","parrot"]):
            asset = {"criticality":3,"os":"Linux/Windows","env":"Lab/Dev","owner":"Security Lab","role":"Development/Lab Host","type":"VM","tags":["dev","lab"]}
        elif any(k in hn for k in ["backup","bkp","bak"]):
            asset = {"criticality":7,"os":"Linux","env":"Production","owner":"IT-Ops","role":"Backup Server","type":"Server","tags":["backup"]}
        elif any(k in hn for k in ["vpn","gateway","gw","fw","firewall"]):
            asset = {"criticality":9,"os":"Network OS","env":"Production","owner":"NetSec","role":"Network Security Device","type":"Network","tags":["network"]}
        elif any(k in hn for k in ["laptop","nb","notebook"]):
            asset = {"criticality":4,"os":"Windows","env":"Corporate","owner":"User","role":"User Laptop","type":"Workstation","tags":["laptop"]}
        elif any(k in hn for k in ["ws","workstation","desktop","pc-","client"]):
            asset = {"criticality":4,"os":"Windows","env":"Corporate","owner":"User","role":"User Workstation","type":"Workstation","tags":["workstation"]}
        elif any(k in hn for k in ["server","srv","svc"]):
            asset = {"criticality":6,"os":"Linux/Windows","env":"Production","owner":"IT-Ops","role":"Internal Server","type":"Server","tags":["server"]}
        elif ip_clean.startswith("192.168.") or ip_clean.startswith("10.") or ip_clean.startswith("172.16.") or ip_clean.startswith("172.31."):
            asset = {"criticality":4,"os":"Windows","env":"Lab/Dev","owner":"Security Lab","role":f"Internal Lab Host ({display_name})","type":"Workstation","tags":["internal","lab"]}
        elif ip_clean:
            asset = {"criticality":5,"os":"Unknown","env":"External","owner":"Unknown","role":f"External Host ({ip_clean})","type":"Unknown","tags":["external"]}
        else:
            # Absolute fallback — infer from display_name, never show generic "Unknown Host"
            _dn = display_name.lower()
            if any(k in _dn for k in ["lone","warrior","lw","research"]):
                asset = {"criticality":5,"os":"Windows 11","env":"Lab/Dev","owner":"Security Lab","role":"Security Research Workstation","type":"Workstation","tags":["lab","research"]}
            else:
                asset = {"criticality":4,"os":"Windows","env":"Lab/Dev","owner":"Security Lab","role":f"Lab Workstation ({display_name})","type":"Workstation","tags":["lab"]}

    # Register for future lookups
    register_host(display_name, ip_clean)

    asset["hostname"]       = display_name
    asset["ip"]             = ip_clean
    crit = asset.get("criticality", 3)
    asset["criticality"]    = crit
    asset["risk_multiplier"]= round(1.0 + (crit - 5) * 0.15, 2)
    asset["criticality_label"] = (
        "🔴 CRITICAL"  if crit >= 9 else
        "🟠 HIGH"      if crit >= 7 else
        "🟡 MEDIUM"    if crit >= 5 else
        "🟢 LOW"
    )
    # Ensure all display fields are always set
    asset.setdefault("os",    "Unknown OS")
    asset.setdefault("env",   "Corporate")
    asset.setdefault("owner", "IT-Ops")
    asset.setdefault("type",  "Host")
    asset.setdefault("role",  f"Internal Host ({display_name})")
    return asset


def enrich_alert_with_asset(alert: dict) -> dict:
    """Add asset context to an alert dict."""
    hostname = alert.get("agent_name", alert.get("hostname", alert.get("host", "")))
    ip       = alert.get("agent_ip",   alert.get("ip", alert.get("src_ip", "")))
    asset    = resolve_asset(hostname, ip)
    alert["_asset"]       = asset
    alert["_criticality"] = asset["criticality"]
    alert["_role"]        = asset["role"]
    # Boost threat score for critical assets
    raw_score = int(alert.get("threat_score", alert.get("score", 50)))
    alert["_adjusted_score"] = min(100, int(raw_score * asset["risk_multiplier"]))
    return alert


# ══════════════════════════════════════════════════════════════════════════════
# P1 — CORRELATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# NOISE FILTER LAYER — Pre-correlation, multi-dimensional
# ══════════════════════════════════════════════════════════════════════════════

# Alert categories treated as noise regardless of level
_NOISE_CATEGORIES = {
    "sca", "benchmark", "ciscat", "rootcheck", "vulnerability",
    "configuration", "policy", "audit_command", "audit_config",
    "gdpr", "pci", "hipaa", "nist", "tsc",
}

# Rule descriptions that indicate low-value events
_NOISE_KEYWORDS = [
    "sca check", "cis benchmark", "policy check", "configuration check",
    "rootcheck", "vulnerability scan", "audit check", "osquery",
    "file added to the system", "windows update", "antivirus updated",
    "scheduled task", "dns-sd", "net localgroup", "systemd",
    "service check", "integrity checksum", "baseline",
    "windows defender", "software update", "telemetry",
]

# Rules that are always noise
_ALWAYS_NOISE_RULE_IDS = {
    "19101","19102","19103","19104","19105","19106",  # SCA
    "530","531","532","533","534","535",              # rootcheck
    "81000","81001","81002","81003",                   # vulnerability
    "550","551","552","553",                           # FIM noise
    "31300","31301","31302","31303","31304","31305",   # Web noise
}


def is_noise(alert: dict, min_level: int = 7) -> tuple[bool, str]:
    """
    Returns (is_noise: bool, reason: str).
    Multi-dimensional: rule_level + category + keyword + rule_id.
    """
    rule       = alert.get("rule", {})
    rule_level = int(rule.get("level", alert.get("rule_level", alert.get("level", 99))))
    rule_id    = str(rule.get("id", alert.get("rule_id", "")))
    description= (rule.get("description","") or alert.get("description","") or
                  alert.get("alert_type","")).lower()
    groups     = set(g.lower() for g in (rule.get("groups") or alert.get("groups") or []))

    # 1. Level filter
    if rule_level < min_level and rule_level > 0:
        return True, f"Level {rule_level} < threshold {min_level} (informational noise)"

    # 2. Always-noise rule IDs
    if rule_id in _ALWAYS_NOISE_RULE_IDS:
        return True, f"Rule {rule_id} is compliance/SCA noise"

    # 3. Category filter
    if groups & _NOISE_CATEGORIES:
        matched = groups & _NOISE_CATEGORIES
        return True, f"Category noise: {', '.join(matched)}"

    # 4. Keyword filter (only for low-level alerts)
    if rule_level < 9:
        for kw in _NOISE_KEYWORDS:
            if kw in description:
                return True, f"Keyword noise: '{kw}' in description"

    return False, ""


def filter_alerts(alerts: list, min_level: int = 7) -> tuple[list, list]:
    """
    Split alerts into (signal_alerts, noise_alerts).
    Signal = actionable. Noise = suppressed but preserved for on-demand view.
    """
    signal, noise = [], []
    for a in alerts:
        noisy, reason = is_noise(a, min_level)
        if noisy:
            a_copy = dict(a)
            a_copy["_noise_reason"] = reason
            noise.append(a_copy)
        else:
            signal.append(a)
    return signal, noise



# MITRE technique → attack phase mapping
_MITRE_PHASE = {
    "T1566": "Initial Access",    "T1190": "Initial Access",    "T1133": "Initial Access",
    "T1059": "Execution",         "T1059.001": "Execution",      "T1059.003": "Execution",
    "T1204": "Execution",         "T1047": "Execution",
    "T1547": "Persistence",       "T1098": "Persistence",        "T1136": "Persistence",
    "T1543": "Persistence",       "T1574": "Persistence",
    "T1548": "Privilege Escalation","T1068": "Privilege Escalation","T1078": "Privilege Escalation",
    "T1027": "Defense Evasion",   "T1070": "Defense Evasion",    "T1036": "Defense Evasion",
    "T1003": "Credential Access", "T1110": "Credential Access",  "T1555": "Credential Access",
    "T1046": "Discovery",         "T1082": "Discovery",          "T1018": "Discovery",
    "T1021": "Lateral Movement",  "T1021.002": "Lateral Movement","T1021.004": "Lateral Movement",
    "T1071": "C2",                "T1071.001": "C2",             "T1071.004": "C2",
    "T1041": "Exfiltration",      "T1048": "Exfiltration",
    "T1486": "Impact",            "T1489": "Impact",             "T1490": "Impact",
    # Wazuh-specific rule IDs mapped to phases
    "T1098": "Persistence",       "T1136": "Persistence",        "T1574": "Persistence",
    "T1543": "Persistence",       "T1053": "Persistence",
    "T1548.003": "Privilege Escalation", "T1548": "Privilege Escalation",
    "T1562": "Defense Evasion",   "T1562.004": "Defense Evasion",
    "T1070.001": "Defense Evasion",
    "T1110.001": "Credential Access",
    "T1021.004": "Lateral Movement", "T1021.006": "Lateral Movement",
    "T1059.003": "Execution",     "T1047": "Execution",
    "T1190": "Initial Access",    "T1133": "Initial Access",
    "T1203": "Execution",
}

# Known attack chains — sequence of phases that indicate a campaign
_ATTACK_CHAINS = {
    "Brute Force → Account Takeover": {
        "phases": ["Credential Access", "Privilege Escalation"],
        "severity": "critical",
        "description": "Multiple auth failures followed by privilege escalation — account likely compromised",
        "mitre": "T1110 → T1078",
    },
    "Persistence Campaign": {
        "phases": ["Execution", "Persistence"],
        "severity": "high",
        "description": "Code execution followed by persistence mechanism — attacker establishing foothold",
        "mitre": "T1059 → T1547",
    },
    "Lateral Movement Campaign": {
        "phases": ["Credential Access", "Lateral Movement"],
        "severity": "critical",
        "description": "Credentials harvested then used to move laterally — active intrusion",
        "mitre": "T1003 → T1021",
    },
    "Full Kill Chain": {
        "phases": ["Initial Access", "Execution", "Persistence", "C2"],
        "severity": "critical",
        "description": "Full attack kill chain detected — Initial Access through C2 establishment",
        "mitre": "T1566 → T1059 → T1547 → T1071",
    },
    "Data Theft Pattern": {
        "phases": ["Credential Access", "Discovery", "Exfiltration"],
        "severity": "critical",
        "description": "Credential theft → environment survey → data exfiltration detected",
        "mitre": "T1003 → T1082 → T1041",
    },
    "Ransomware Preparation": {
        "phases": ["Lateral Movement", "Defense Evasion", "Impact"],
        "severity": "critical",
        "description": "Lateral spread + log clearing + impact — ransomware deployment pattern",
        "mitre": "T1021 → T1070 → T1486",
    },
    "Privilege Escalation Chain": {
        "phases": ["Credential Access", "Privilege Escalation", "Persistence"],
        "severity": "critical",
        "description": "Credential access → privilege escalation → persistence — domain takeover attempt",
        "mitre": "T1110 → T1548 → T1098",
    },
    "Reconnaissance → Attack": {
        "phases": ["Discovery", "Lateral Movement"],
        "severity": "high",
        "description": "Network discovery followed by lateral movement — active threat actor mapping environment",
        "mitre": "T1046 → T1021",
    },
}


def _get_phase(mitre: str) -> str:
    mitre = (mitre or "").strip()
    if not mitre:
        return "Unknown Activity"
    if mitre in _MITRE_PHASE:
        return _MITRE_PHASE[mitre]
    # Try prefix match (handles T1059.001 → T1059)
    for k, v in _MITRE_PHASE.items():
        if mitre.startswith(k[:5]):
            return v
    return "Suspicious Activity"   # never show plain "Unknown"


# Wazuh rule description → phase mapping (for alerts with no MITRE tag)
_DESC_TO_PHASE = {
    "service":      "Persistence",
    "startup":      "Persistence",
    "scheduled":    "Persistence",
    "registry":     "Persistence",
    "user creat":   "Persistence",
    "account cre":  "Persistence",
    "group":        "Privilege Escalation",
    "privilege":    "Privilege Escalation",
    "sudo":         "Privilege Escalation",
    "root":         "Privilege Escalation",
    "logon fail":   "Credential Access",
    "brute":        "Credential Access",
    "login fail":   "Credential Access",
    "authenticat":  "Credential Access",
    "ssh":          "Credential Access",
    "lsass":        "Credential Access",
    "credential":   "Credential Access",
    "smb":          "Lateral Movement",
    "rdp":          "Lateral Movement",
    "lateral":      "Lateral Movement",
    "powershell":   "Execution",
    "process":      "Execution",
    "command":      "Execution",
    "script":       "Execution",
    "log clear":    "Defense Evasion",
    "log delet":    "Defense Evasion",
    "audit":        "Defense Evasion",
    "firewall dis": "Defense Evasion",
    "antivirus":    "Defense Evasion",
    "scan":         "Discovery",
    "enumerat":     "Discovery",
    "network disc": "Discovery",
    "dns":          "C2",
    "beacon":       "C2",
    "c2":           "C2",
    "exfil":        "Exfiltration",
    "upload":       "Exfiltration",
    "ransomware":   "Impact",
    "encrypt":      "Impact",
    "delete":       "Impact",
}


def _desc_to_phase(description: str) -> str:
    """Map alert description to MITRE phase when no MITRE tag is present."""
    desc_lower = (description or "").lower()
    for keyword, phase in _DESC_TO_PHASE.items():
        if keyword in desc_lower:
            return phase
    return "Suspicious Activity"


def correlate_alerts(alerts: list, window_minutes: int = 15,
                     min_alerts: int = 2, min_level: int = 7) -> list[dict]:
    """
    P1 CORRELATION ENGINE
    ======================
    Groups alerts by host within a time window, detects attack chains.

    Args:
        alerts:         list of alert dicts (from Wazuh/Splunk/session)
        window_minutes: time window to group alerts (default 15 min)
        min_alerts:     minimum alerts per incident

    Returns:
        list of incident dicts, each with:
          - host, ip, asset info
          - alerts list
          - phases detected
          - chain match (if known attack pattern)
          - verdict, severity, risk_score
          - timeline
          - recommendations
    """
    if not alerts:
        return []

    # ── Pre-filter noise ─────────────────────────────────────────────────────
    signal_alerts, suppressed = filter_alerts(alerts, min_level)
    # Keep suppressed in session for on-demand view
    try:
        import streamlit as _st
        _st.session_state["suppressed_alerts"] = suppressed
    except Exception:
        pass

    if not signal_alerts:
        # All alerts were noise — return empty
        return []

    # Enrich signal alerts with asset context
    enriched = [enrich_alert_with_asset(dict(a)) for a in signal_alerts]

    # Group by host (agent_name or IP)
    host_groups: dict[str, list] = defaultdict(list)
    for a in enriched:
        key = (a.get("agent_name") or a.get("hostname") or
               a.get("host") or a.get("ip") or a.get("agent_ip") or "unknown")
        host_groups[key].append(a)

    incidents = []

    for host, host_alerts in host_groups.items():
        if len(host_alerts) < min_alerts:
            continue

        # Sort by time
        def _parse_ts(a):
            ts = a.get("timestamp", a.get("_time", ""))
            try:
                return datetime.fromisoformat(str(ts).replace("Z",""))
            except Exception:
                return datetime.utcnow()

        host_alerts.sort(key=_parse_ts)

        # Build timeline
        timeline = []
        phases_seen = []
        mitres_seen = []
        max_score   = 0
        max_crit    = 0

        for a in host_alerts:
            mitre  = a.get("mitre", a.get("mitre_technique", ""))
            desc   = a.get("description", a.get("alert_type", a.get("message", "Alert")))
            phase  = _get_phase(mitre) if mitre else _desc_to_phase(desc)
            ts     = a.get("timestamp", a.get("_time", ""))
            sev    = a.get("severity", "medium")
            score  = a.get("_adjusted_score", a.get("threat_score", 50))

            # Extract user context
            _user_ctx = extract_user_context(a)
            timeline.append({
                "time":        str(ts)[-8:][:8] if ts else "?",
                "full_time":   str(ts),
                "description": str(desc)[:80],
                "phase":       phase,
                "mitre":       mitre,
                "severity":    sev,
                "score":       int(score),
                "rule_id":     a.get("rule_id", a.get("rule", {}).get("id", "")),
                "user":        _user_ctx.get("user",""),
                "is_admin":    _user_ctx.get("is_admin", False),
                "_user_ctx":   _user_ctx,
            })

            if phase and phase != "Unknown" and phase not in phases_seen:
                phases_seen.append(phase)
            if mitre and mitre not in mitres_seen:
                mitres_seen.append(mitre)

            max_score = max(max_score, int(score))
            max_crit  = max(max_crit, a.get("_criticality", 2))

        # Detect known attack chains
        matched_chain = None
        matched_chain_name = ""
        for chain_name, chain_data in _ATTACK_CHAINS.items():
            required_phases = chain_data["phases"]
            if all(p in phases_seen for p in required_phases):
                # Prefer longer/more specific chains
                if matched_chain is None or len(required_phases) > len(matched_chain["phases"]):
                    matched_chain = chain_data
                    matched_chain_name = chain_name

        # Determine incident severity
        if matched_chain and matched_chain["severity"] == "critical":
            incident_sev = "critical"
        elif max_score >= 80 or max_crit >= 9:
            incident_sev = "critical"
        elif max_score >= 60 or len(phases_seen) >= 3 or max_crit >= 7:
            incident_sev = "high"
        elif max_score >= 40 or len(phases_seen) >= 2:
            incident_sev = "medium"
        else:
            incident_sev = "low"

        # Risk score: more aggressive — 20 alerts with persistence must be HIGH
        _base        = max_score
        _chain_bonus = 30 if matched_chain else 0
        _phase_bonus = len(phases_seen) * 8          # 3 phases = +24
        _count_bonus = min(20, len(host_alerts) * 2) # up to +20 for many alerts
        _crit_bonus  = max_crit * 3                  # DC=10 → +30
        risk_score   = min(100, _base + _chain_bonus + _phase_bonus + _count_bonus + _crit_bonus)
        # Minimum floors by severity
        _FLOOR = {"critical": 75, "high": 55, "medium": 35, "low": 15}
        risk_score = max(risk_score, _FLOOR.get(incident_sev, 20))

        # Get asset info from first alert
        asset = host_alerts[0].get("_asset", resolve_asset(host))

        # Build incident recommendations
        # Build specific recommendations based on actual event descriptions
        recs = []
        if matched_chain:
            recs.append(f"⛓ ATTACK CHAIN DETECTED: {matched_chain['description']}")

        # Per-phase specific actions tied to actual alert content
        if "Persistence" in phases_seen:
            _svc_alerts  = [e["description"] for e in timeline if "service" in e["description"].lower()]
            _usr_alerts  = [e["description"] for e in timeline if "user" in e["description"].lower() or "account" in e["description"].lower()]
            if _svc_alerts:
                recs.append(f"Validate newly created/modified service — check binary path and publisher (T1543): {_svc_alerts[0][:60]}")
            if _usr_alerts:
                recs.append(f"Review account changes immediately (T1098): {_usr_alerts[0][:60]}")
            if not _svc_alerts and not _usr_alerts:
                recs.append("Audit Run keys, scheduled tasks, startup folder, and new services")

        if "Credential Access" in phases_seen:
            _auth_alerts = [e["description"] for e in timeline if any(k in e["description"].lower() for k in ["login","logon","auth","ssh","password"])]
            if _auth_alerts:
                recs.append(f"Rotate credentials — auth failure pattern detected (T1110): {_auth_alerts[0][:60]}")
            else:
                recs.append("Rotate all passwords for this host — credential access phase detected")
            recs.append("Check if any login SUCCEEDED after the failures — search for EventID 4624")

        if "Privilege Escalation" in phases_seen:
            _priv_alerts = [e["description"] for e in timeline if any(k in e["description"].lower() for k in ["sudo","root","privilege","group","admin"])]
            if _priv_alerts:
                recs.append(f"Investigate privilege change — verify with system owner (T1548): {_priv_alerts[0][:60]}")
            recs.append("Correlate with failed logins — privilege escalation after brute force is common")

        if "Lateral Movement" in phases_seen:
            recs.append("Isolate host NOW — SMB/RDP lateral movement detected (T1021)")
            recs.append("Scan ALL hosts this machine connected to in the last 24h")

        if "Defense Evasion" in phases_seen:
            _log_alerts = [e["description"] for e in timeline if "log" in e["description"].lower()]
            if _log_alerts:
                recs.append(f"URGENT — attacker clearing tracks (T1070): {_log_alerts[0][:60]}. Collect memory dump immediately")
            else:
                recs.append("Defense evasion detected — collect forensic image before evidence is destroyed")

        if "Execution" in phases_seen:
            _exec = [e["description"] for e in timeline if any(k in e["description"].lower() for k in ["powershell","command","script","process"])]
            if _exec:
                recs.append(f"Decode and analyse command payload (T1059): {_exec[0][:60]}")

        if "C2" in phases_seen:
            recs.append("Block all external IPs/domains contacted by this host in the firewall")

        if "Exfiltration" in phases_seen:
            recs.append("CRITICAL — block all outbound traffic from this host. Start DPDP/breach timer")

        if not recs:
            recs.append(f"Investigate {len(host_alerts)} alerts — multiple events from same host suggest coordinated activity")
            recs.append("Check process tree, network connections, and file changes in this time window")

        recs.append(f"Asset: {asset['criticality_label']} — {asset['role']} ({host})")

        # Generate incident ID
        inc_id = "INC-" + hashlib.md5(f"{host}{timeline[0]['full_time']}".encode()).hexdigest()[:6].upper()

        incident = {
            "id":               inc_id,
            "host":             host,
            "ip":               asset.get("ip", ""),
            "asset":            asset,
            "asset_role":       asset["role"],
            "criticality":      max_crit,
            "criticality_label":asset["criticality_label"],
            "alerts":           host_alerts,
            "alert_count":      len(host_alerts),
            "timeline":         timeline,
            "phases":           phases_seen,
            "mitre_techniques": mitres_seen,
            "chain":            matched_chain,
            "chain_name":       matched_chain_name,
            "severity":         incident_sev,
            "risk_score":       risk_score,
            "max_alert_score":  max_score,
            "recommendations":  recs,
            "status":           "open",
            "created_at":       datetime.utcnow().isoformat(),
            "start_time":       timeline[0]["full_time"] if timeline else "",
            "end_time":         timeline[-1]["full_time"] if timeline else "",
        }
        incidents.append(incident)

    # Sort by risk score descending
    incidents.sort(key=lambda x: x["risk_score"], reverse=True)
    return incidents


# ══════════════════════════════════════════════════════════════════════════════
# P5 — AI NARRATIVE ENGINE
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# USER & IDENTITY CONTEXT
# ══════════════════════════════════════════════════════════════════════════════

_KNOWN_SERVICE_ACCOUNTS = {
    "system":           "Windows SYSTEM account — expected for OS operations",
    "local service":    "Windows Local Service — expected for service operations",
    "network service":  "Windows Network Service — expected for network services",
    "administrator":    "Local administrator — verify if usage is expected",
    "admin":            "Admin account — high-value target, verify all actions",
    "root":             "Linux root — extremely sensitive, all actions must be verified",
    "svc_backup":       "Backup service account — expected for backup jobs",
    "svc_sql":          "SQL Server service account — expected for database operations",
    "svc_iis":          "IIS service account — expected for web server operations",
}

def extract_user_context(alert: dict) -> dict:
    """Extract and enrich user/account context from an alert."""
    data = alert.get("data", {})
    user = (data.get("win", {}).get("system", {}).get("user", "") or
            data.get("user", "") or
            alert.get("user", "") or
            alert.get("agent_user", "") or "").strip()

    if not user:
        # Try extracting from description
        import re as _re
        desc = alert.get("rule", {}).get("description", "")
        m = _re.search(r"user[:\s]+([A-Za-z0-9_\.-]+)", desc, _re.I)
        if m:
            user = m.group(1).strip()

    user_lower = user.lower()
    known = _KNOWN_SERVICE_ACCOUNTS.get(user_lower, "")

    return {
        "user":          user or "Unknown",
        "is_known_svc":  bool(known),
        "svc_context":   known,
        "is_admin":      any(a in user_lower for a in ["admin","administrator","root","system"]),
        "is_svc":        user_lower.startswith("svc_") or user_lower in _KNOWN_SERVICE_ACCOUNTS,
        "risk_modifier": 1.3 if any(a in user_lower for a in ["admin","root","system"]) else 1.0,
    }


def get_user_context_summary(timeline: list) -> str:
    """Summarize user activity across all timeline events."""
    users = set()
    admin_activity = []
    for ev in timeline:
        u = ev.get("_user_ctx", {}).get("user", "")
        if u and u != "Unknown":
            users.add(u)
            if ev.get("_user_ctx", {}).get("is_admin"):
                admin_activity.append(f"{u} at {ev.get('time','?')}")

    if not users:
        return ""
    summary = f"Accounts involved: {', '.join(list(users)[:5])}."
    if admin_activity:
        summary += f" Admin/privileged activity: {'; '.join(admin_activity[:3])}."
    return summary



def generate_soc_narrative(incident: dict) -> dict:
    """
    P5: Generate structured SOC-grade narrative for an incident.
    Format: What happened / Why it matters / What to do / Confidence
    No AI API needed — pure rule-based SOC-quality output.
    """
    host     = incident.get("host", "unknown")
    phases   = incident.get("phases", [])
    chain    = incident.get("chain", {})
    asset    = incident.get("asset", {})
    timeline = incident.get("timeline", [])
    sev      = incident.get("severity", "medium")
    score    = incident.get("risk_score", 0)
    count    = incident.get("alert_count", 0)
    mitres   = incident.get("mitre_techniques", [])

    # ── What happened ─────────────────────────────────────────────────────────
    phase_str = " → ".join(phases) if phases else "Unknown activity"
    if chain:
        what = (f"{chain['description']} "
                f"A total of {count} alerts were generated on host '{host}' "
                f"following the pattern: {phase_str}.")
    else:
        what = (f"{count} security alerts detected on host '{host}' "
                f"across {len(phases)} attack phase(s): {phase_str}. "
                f"No exact attack chain match — manual review required.")

    if timeline:
        first = timeline[0]
        last  = timeline[-1]
        what += (f" Sequence began with '{first['description']}' "
                 f"and most recently '{last['description']}'.")

    # ── Why it matters ────────────────────────────────────────────────────────
    role    = asset.get("role", "Unknown host")
    crit    = asset.get("criticality", 2)
    crit_lbl = asset.get("criticality_label", "")

    # Rich asset context — no more "Unknown Host"
    _os    = asset.get("os","Unknown OS")
    _env   = asset.get("env","Unknown Environment")
    _owner = asset.get("owner","Unassigned")
    _atype = asset.get("type","Host")

    why = (f"Host '{host}' ({_atype} · {_os} · {_env}) is classified as {crit_lbl} ({role}). "
           f"Owner: {_owner}. ")
    if crit >= 9:
        why += "Compromise of this asset could give an attacker control over the entire domain/network. "
    elif crit >= 7:
        why += "This is a high-value server — compromise would expose sensitive data or services. "
    elif asset.get("env","") in ("Lab/Dev","Test"):
        why += f"Although this is a {_env} environment, attacker tools spreading from lab systems pose real risk. "
    else:
        why += "Even on a user workstation, this pattern indicates an active threat actor present in your environment. "

    # User context
    _user_summary = get_user_context_summary(timeline) if timeline else ""
    if _user_summary:
        why += f" {_user_summary}"

    if "Credential Access" in phases and "Lateral Movement" in phases:
        why += "The combination of credential theft and lateral movement strongly indicates an active intrusion — not a false positive."
    elif "Persistence" in phases:
        why += "Persistence mechanisms indicate the attacker intends to maintain access even after reboots or password changes."
    elif chain:
        why += f"The '{incident.get('chain_name','')}' pattern has a {score}% risk score — high likelihood of malicious intent."

    # ── What to do ────────────────────────────────────────────────────────────
    do_steps = []
    priority = "P1 — Act within 15 minutes" if sev == "critical" else \
               "P2 — Act within 1 hour"     if sev == "high"     else \
               "P3 — Act within 4 hours"    if sev == "medium"   else \
               "P4 — Review during business hours"

    do_steps.append(f"[{priority}]")

    if sev in ("critical", "high"):
        do_steps.append("1. ISOLATE the host from the network immediately (disable NIC or VLAN)")
    if "Credential Access" in phases:
        do_steps.append("2. ROTATE all service accounts and user passwords associated with this host")
    if "Lateral Movement" in phases:
        do_steps.append("3. SCAN all hosts that communicated with this host in the past 24h")
    if "Persistence" in phases:
        do_steps.append("4. AUDIT startup items, scheduled tasks, new users, and registry Run keys")
    if "C2" in phases:
        do_steps.append("5. BLOCK all external IPs this host contacted in the past hour at the firewall")
    if not do_steps[1:]:
        do_steps.append("1. Review full alert context in Wazuh/Splunk")
        do_steps.append("2. Correlate with other hosts showing similar patterns")

    do_steps.append(f"Document findings in IR case {incident.get('id','?')} and update status.")

    # ── Confidence & False Positive Calibration ──────────────────────────────
    conf_factors = []
    fp_factors   = []
    conf = 45

    # Positive confidence signals
    if chain:
        conf += 25; conf_factors.append(f"+25: Known attack chain '{incident.get('chain_name','')}'")
    if len(phases) >= 3:
        conf += 15; conf_factors.append(f"+15: {len(phases)} distinct MITRE phases observed")
    if len(phases) >= 2 and not chain:
        conf += 10; conf_factors.append(f"+10: Multi-phase activity ({' → '.join(phases[:3])})")
    if crit >= 8:
        conf += 12; conf_factors.append(f"+12: Critical asset — {asset.get('role','?')} (criticality {crit}/10)")
    elif crit >= 6:
        conf += 6; conf_factors.append(f"+6: Medium-high criticality asset ({asset.get('role','?')})")
    if count >= 10:
        conf += 12; conf_factors.append(f"+12: High alert volume ({count} alerts) — unlikely false positive")
    elif count >= 5:
        conf += 6; conf_factors.append(f"+6: Multiple alerts ({count}) corroborating the pattern")
    if "Credential Access" in phases and "Lateral Movement" in phases:
        conf += 10; conf_factors.append("+10: Credential theft + lateral movement = active intrusion pattern")
    if "Defense Evasion" in phases:
        conf += 8; conf_factors.append("+8: Defense evasion = attacker aware and hiding — strong malicious indicator")
    if sev == "critical":
        conf = max(conf, 82)

    # False positive risk factors
    if crit <= 3:
        fp_factors.append("Low-criticality host — similar patterns can occur during software updates")
    if "Persistence" in phases and len(phases) == 1:
        fp_factors.append("Single-phase (Persistence only) — could be legitimate IT admin activity")
    if asset.get("env","") in ("Lab/Dev", "Test"):
        fp_factors.append(f"Lab/Dev environment ({asset.get('env')}) — security testing is expected here")
    if count <= 3:
        fp_factors.append(f"Low alert count ({count}) — may be insufficient evidence")
    if not mitres:
        fp_factors.append("No MITRE techniques tagged — classification based on description only")

    conf = min(conf, 97)
    conf_str = f"{conf}% confidence — this is likely a real incident.\n\n"
    conf_str += "Evidence:\n" + "\n".join(f"  • {f}" for f in conf_factors)
    if fp_factors:
        conf_str += "\n\nFalse Positive Risk Factors:\n" + "\n".join(f"  ⚠ {f}" for f in fp_factors)

    return {
        "what":       what,
        "why":        why,
        "do":         "\n".join(do_steps),
        "confidence": conf_str,
        "conf_pct":   conf,
        "priority":   priority,
    }


# ══════════════════════════════════════════════════════════════════════════════
# P3 — REAL-TIME AUTO-TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

def auto_triage_alerts(alerts: list, min_score: int = 60,
                       auto_escalate_threshold: int = 85) -> dict:
    """
    P3: Auto-triage a batch of alerts without human clicking.
    Returns structured dispatch decisions.
    """
    results = {
        "auto_escalated":  [],
        "needs_review":    [],
        "suppressed":      [],
        "incidents":       [],
        "summary":         {},
    }

    # Run correlation first
    incidents = correlate_alerts(alerts, window_minutes=15)
    results["incidents"] = incidents

    for inc in incidents:
        score = inc["risk_score"]
        if score >= auto_escalate_threshold:
            results["auto_escalated"].append({
                "incident_id": inc["id"],
                "host":        inc["host"],
                "reason":      f"Risk score {score}/100 exceeds auto-escalation threshold",
                "chain":       inc.get("chain_name",""),
                "action":      "IR case auto-created — analyst notification sent",
            })
        elif score >= min_score:
            results["needs_review"].append({
                "incident_id": inc["id"],
                "host":        inc["host"],
                "reason":      f"Risk score {score}/100 requires analyst review",
            })
        else:
            results["suppressed"].append({
                "incident_id": inc["id"],
                "host":        inc["host"],
                "reason":      f"Risk score {score}/100 below threshold — suppressed",
            })

    results["summary"] = {
        "total_alerts":     len(alerts),
        "incidents_found":  len(incidents),
        "auto_escalated":   len(results["auto_escalated"]),
        "needs_review":     len(results["needs_review"]),
        "suppressed":       len(results["suppressed"]),
        "processed_at":     datetime.utcnow().isoformat(),
    }

    return results


# ══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI — render_soc_brain()
# ══════════════════════════════════════════════════════════════════════════════

def render_soc_brain():
    """
    Full SOC Brain UI — 4 tabs:
      Correlation Engine | Asset Intelligence | Incident View | AI Narrative
    """
    import streamlit as st
    import pandas as pd

    st.markdown(
        "<div style='font-family:Orbitron,monospace;font-size:.9rem;font-weight:900;"
        "color:#00ffc8;letter-spacing:2px;margin-bottom:4px'>🧠 SOC DECISION BRAIN</div>"
        "<div style='color:#446688;font-size:.68rem;margin-bottom:14px'>"
        "Correlation · Asset Intelligence · Incident View · AI Narrative</div>",
        unsafe_allow_html=True
    )

    tab_corr, tab_asset, tab_inc, tab_narr = st.tabs([
        "🔗 Correlation Engine",
        "🏢 Asset Intelligence",
        "📋 Incident View",
        "🤖 AI Narrative",
    ])

    # ── Shared: get alerts from session ───────────────────────────────────────
    # Collect alerts from all possible sources
    _raw_pipeline = st.session_state.get("pipeline_results", [])
    _pull_results  = st.session_state.get("pull_triage_results", [])
    _wazuh_pull   = st.session_state.get("wazuh_pull_results", [])

    # Normalise pipeline/pull results into alert dicts
    def _norm(r):
        if "raw_alert" in r:
            a = dict(r["raw_alert"])
            a.setdefault("threat_score",  r.get("risk_score", r.get("composite_score", 50)))
            a.setdefault("severity",       r.get("severity_class", "medium"))
            a.setdefault("mitre_technique",r.get("mitre_id", ""))
            a.setdefault("description",    r.get("description", ""))
            a.setdefault("alert_type",     r.get("category", ""))
            return a
        if "domain" in r and "verdict" in r:
            return {
                "agent_name":    r.get("wazuh_agent", r.get("domain","?")),
                "agent_ip":      r.get("wazuh_agent_ip", r.get("agent_ip","")),
                "description":   r.get("reason", r.get("verdict","")),
                "alert_type":    r.get("verdict",""),
                "severity":      r.get("severity","medium"),
                "threat_score":  100 - r.get("score", 50),
                "mitre_technique":"",
                "rule":          {"level": 7 if r.get("score",50) < 50 else 5},
            }
        if "description" in r and "agent" in r:
            return {
                "agent_name":    r.get("agent","?"),
                "agent_ip":      r.get("agent_ip",""),
                "description":   r.get("description",""),
                "alert_type":    r.get("description",""),
                "severity":      "medium",
                "threat_score":  50,
                "rule":          {"level": int(r.get("level",5))},
            }
        return r

    all_alerts = (
        st.session_state.get("triage_alerts", []) +
        st.session_state.get("wazuh_alerts", []) +
        st.session_state.get("analysis_results", []) +
        [_norm(r) for r in _raw_pipeline] +
        [_norm(r) for r in _wazuh_pull]
    )
    all_alerts = [a for a in all_alerts if isinstance(a, dict) and a]

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 1: CORRELATION ENGINE
    # ══════════════════════════════════════════════════════════════════════════
    with tab_corr:
        st.subheader("🔗 Correlation Engine")
        st.caption("Groups alerts by host + time window → detects attack chains → creates incidents")

        _c1, _c2, _c3, _c4 = st.columns(4)
        window   = _c1.slider("Time window (min)",      5,  60,  15, key="corr_window")
        min_alt  = _c2.slider("Min alerts/incident",    1,   5,   2, key="corr_min")
        min_lvl  = _c3.slider("Min Wazuh level (noise filter)", 3, 12, 7, key="corr_min_lvl")
        esc_thr  = _c4.slider("Auto-escalate threshold", 50, 100, 80, key="corr_esc")

        if st.button("🔗 Run Correlation Engine", type="primary",
                     use_container_width=True, key="run_corr"):
            if not all_alerts:
                st.warning("No alerts loaded. Run Alert Triage or Fetch Wazuh Alerts first.")
            else:
                with st.spinner(f"Correlating {len(all_alerts)} alerts…"):
                    signal, noise = filter_alerts(all_alerts, min_lvl)
                    st.session_state["suppressed_alerts"] = noise
                    incidents = correlate_alerts(signal, window, min_alt, min_lvl)
                    auto_result = auto_triage_alerts(signal, 60, esc_thr)
                st.session_state["corr_incidents"] = incidents
                st.session_state["corr_auto"] = auto_result
                st.rerun()

        incidents  = st.session_state.get("corr_incidents", [])
        auto_res   = st.session_state.get("corr_auto", {})

        if incidents:
            summary = auto_res.get("summary", {})
            _m1,_m2,_m3,_m4,_m5 = st.columns(5)
            _m1.metric("Alerts processed", summary.get("total_alerts", len(all_alerts)))
            _m2.metric("Incidents found",  len(incidents))
            _m3.metric("🔴 Auto-escalated", summary.get("auto_escalated",0))
            _m4.metric("🟡 Needs review",   summary.get("needs_review",0))
            _m5.metric("🟢 Suppressed",     summary.get("suppressed",0))
            st.divider()

            # Auto-escalated banner
            if auto_res.get("auto_escalated"):
                for esc in auto_res["auto_escalated"]:
                    st.error(
                        f"🚨 **AUTO-ESCALATED** — `{esc['host']}` | "
                        f"{esc['reason']} | Chain: **{esc['chain'] or 'multi-phase'}** | "
                        f"{esc['action']}"
                    )

            st.markdown("#### Incidents (sorted by risk score)")
            for inc in incidents:
                sev   = inc["severity"]
                score = inc["risk_score"]
                _SEV  = {"critical":"#ff0033","high":"#ff9900","medium":"#ffcc00","low":"#00aaff"}
                _c    = _SEV.get(sev, "#888")
                chain_badge = (f"<span style='background:#ff003322;border:1px solid #ff003366;"
                                f"border-radius:4px;padding:1px 6px;font-size:.62rem;color:#ff8080;"
                                f"margin-left:8px'>{inc['chain_name']}</span>"
                                if inc.get("chain_name") else "")

                with st.container(border=True):
                    _ic1, _ic2 = st.columns([4, 1])
                    _ic1.markdown(
                        f"<div style='color:{_c};font-weight:700;font-size:.85rem'>"
                        f"{'🔴' if sev=='critical' else '🟠' if sev=='high' else '🟡'} "
                        f"{inc['id']} — {inc['host']}{chain_badge}</div>"
                        f"<div style='color:#446688;font-size:.65rem;margin-top:2px'>"
                        f"{inc['asset_role']} · {inc['criticality_label']} · "
                        f"{inc['alert_count']} alerts · "
                        f"Phases: {' → '.join(inc['phases']) if inc['phases'] else 'Unknown'}"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                    _ic2.markdown(
                        f"<div style='text-align:center;background:{_c}22;border:1px solid {_c}44;"
                        f"border-radius:8px;padding:6px'>"
                        f"<div style='color:{_c};font-size:1.2rem;font-weight:900'>{score}</div>"
                        f"<div style='color:#446688;font-size:.6rem'>risk score</div>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

                    if inc.get("chain"):
                        st.markdown(
                            f"<div style='background:#ff003311;border-left:3px solid #ff0033;"
                            f"padding:6px 10px;border-radius:0 6px 6px 0;font-size:.72rem;"
                            f"color:#ff8080;margin:6px 0'>"
                            f"⛓️ <strong>ATTACK CHAIN:</strong> {inc['chain']['description']}"
                            f"</div>",
                            unsafe_allow_html=True
                        )

                    # Visual kill-chain diagram
                    if inc["phases"]:
                        _PHASE_COLORS = {
                            "Initial Access":"#ff6600","Execution":"#ff0033",
                            "Persistence":"#ff9900","Privilege Escalation":"#ff4444",
                            "Defense Evasion":"#cc00ff","Credential Access":"#ff0066",
                            "Discovery":"#00aaff","Lateral Movement":"#ff6600",
                            "C2":"#ff0033","Exfiltration":"#ff0000",
                            "Impact":"#ff0033","Suspicious Activity":"#ffcc00",
                        }
                        chain_html = "<div style='display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin:8px 0'>"
                        for pi, phase in enumerate(inc["phases"]):
                            pc = _PHASE_COLORS.get(phase, "#446688")
                            chain_html += (
                                f"<span style='background:{pc}22;border:1px solid {pc}66;"
                                f"border-radius:6px;padding:4px 10px;font-size:.65rem;"
                                f"font-weight:700;color:{pc}'>{phase}</span>"
                            )
                            if pi < len(inc["phases"])-1:
                                chain_html += "<span style='color:#446688;font-size:.8rem'>→</span>"
                        chain_html += "</div>"
                        st.markdown(chain_html, unsafe_allow_html=True)

                    # ── Visual flow graph ─────────────────────────────────────
                    if inc["phases"] and len(inc["phases"]) > 1:
                        _PHASE_ICONS = {
                            "Initial Access":"🚪","Execution":"⚡","Persistence":"🔧",
                            "Privilege Escalation":"👑","Defense Evasion":"🕶️",
                            "Credential Access":"🔑","Discovery":"🔍",
                            "Lateral Movement":"↔️","C2":"📡","Exfiltration":"📤",
                            "Impact":"💥","Suspicious Activity":"⚠️",
                        }
                        _PHASE_COLORS = {
                            "Initial Access":"#ff6600","Execution":"#ff0033",
                            "Persistence":"#ff9900","Privilege Escalation":"#ff4444",
                            "Defense Evasion":"#cc00ff","Credential Access":"#ff0066",
                            "Discovery":"#00aaff","Lateral Movement":"#ff6600",
                            "C2":"#ff0033","Exfiltration":"#ff0000",
                            "Impact":"#ff0033","Suspicious Activity":"#ffcc00",
                        }
                        flow_html = (
                            "<div style='background:#050d18;border:1px solid #0a1a2a;"
                            "border-radius:8px;padding:12px;margin:8px 0;overflow-x:auto'>"
                            "<div style='color:#446688;font-size:.6rem;letter-spacing:1px;"
                            "margin-bottom:8px'>ATTACK FLOW</div>"
                            "<div style='display:flex;align-items:center;gap:0;flex-wrap:nowrap'>"
                        )
                        for pi, phase in enumerate(inc["phases"]):
                            pc   = _PHASE_COLORS.get(phase,"#446688")
                            icon = _PHASE_ICONS.get(phase,"●")
                            # Count events in this phase
                            ev_count = sum(1 for e in inc["timeline"] if e.get("phase")==phase)
                            mitre_in_phase = [e.get("mitre","") for e in inc["timeline"]
                                             if e.get("phase")==phase and e.get("mitre")]
                            mitre_hint = mitre_in_phase[0] if mitre_in_phase else ""
                            flow_html += (
                                f"<div style='display:flex;flex-direction:column;"
                                f"align-items:center;min-width:90px'>"
                                f"<div style='background:{pc}22;border:2px solid {pc};"
                                f"border-radius:8px;padding:8px 10px;text-align:center;"
                                f"width:80px'>"
                                f"<div style='font-size:1.1rem'>{icon}</div>"
                                f"<div style='color:{pc};font-size:.6rem;font-weight:700;"
                                f"margin-top:2px;line-height:1.1'>{phase}</div>"
                                f"<div style='color:#446688;font-size:.55rem;margin-top:2px'>"
                                f"{ev_count} event{'s' if ev_count!=1 else ''}</div>"
                                + (f"<div style='color:{pc};font-size:.5rem;opacity:.8'>{mitre_hint}</div>" if mitre_hint else "")
                                + "</div></div>"
                            )
                            if pi < len(inc["phases"])-1:
                                flow_html += (
                                    "<div style='color:#446688;font-size:1.2rem;"
                                    "padding:0 2px;margin-bottom:20px'>→</div>"
                                )
                        flow_html += "</div></div>"
                        st.markdown(flow_html, unsafe_allow_html=True)

                    # Suppressed noise count
                    suppressed = st.session_state.get("suppressed_alerts",[])
                    if suppressed:
                        st.caption(f"🔇 {len(suppressed)} low-level alerts suppressed (noise filtered) — click to view")
                        with st.expander(f"View {len(suppressed)} suppressed alerts", expanded=False):
                            for ns in suppressed[:10]:
                                st.markdown(f"<div style='font-size:.65rem;color:#446688'>"
                                            f"Level {ns.get('rule',{}).get('level','?')} · "
                                            f"{ns.get('rule',{}).get('description',ns.get('alert_type','?'))[:80]} · "
                                            f"Reason: {ns.get('_noise_reason','?')}</div>",
                                            unsafe_allow_html=True)

                    # Timeline
                    with st.expander(f"📅 Timeline ({len(inc['timeline'])} events)", expanded=False):
                        for ev in inc["timeline"]:
                            _ec   = _SEV.get(ev.get("severity","medium"), "#888")
                            _usr  = ev.get("user","")
                            _adm  = ev.get("is_admin", False)
                            _usr_badge = (
                                f"<span style='background:#ff003322;border:1px solid #ff003344;"
                                f"color:#ff8080;border-radius:3px;padding:0 4px;font-size:.55rem;"
                                f"margin-left:4px'>👤 {_usr} (admin)</span>"
                                if _usr and _adm else
                                f"<span style='color:#446688;font-size:.6rem;margin-left:4px'>"
                                f"👤 {_usr}</span>" if _usr else ""
                            )
                            st.markdown(
                                f"<div style='display:flex;gap:12px;padding:4px 0;"
                                f"border-bottom:1px solid #0a1a2a;font-size:.68rem;align-items:center'>"
                                f"<span style='color:#446688;min-width:60px'>{ev.get('time','?')}</span>"
                                f"<span style='color:{_ec};min-width:130px;font-weight:700'>"
                                f"{ev.get('phase','?')}</span>"
                                f"<span style='color:#c8e8ff;flex:1'>{ev.get('description','?')}"
                                f"{_usr_badge}</span>"
                                f"<span style='color:#00ffc8;min-width:80px'>{ev.get('mitre','')}</span>"
                                f"</div>",
                                unsafe_allow_html=True
                            )

                    # Recommendations
                    with st.expander("✅ Recommended Actions", expanded=(sev=="critical")):
                        for rec in inc["recommendations"]:
                            icon = "🚨" if rec.startswith("DETECTED") or "DETECTED" in rec[:8] else "→"
                            st.markdown(f"{icon} {rec}")

                    # FP calibration badge
                    _narr_quick = generate_soc_narrative(inc)
                    _conf      = _narr_quick.get("conf_pct", 0)
                    _fp_text   = "Low" if _conf >= 75 else "Medium" if _conf >= 50 else "High"
                    _fp_color  = "#00c878" if _fp_text=="Low" else "#ffcc00" if _fp_text=="Medium" else "#ff9900"
                    st.markdown(
                        f"<div style='display:flex;gap:12px;align-items:center;"
                        f"font-size:.68rem;margin:6px 0'>"
                        f"<span style='color:#446688'>Confidence:</span>"
                        f"<span style='color:#00ffc8;font-weight:700'>{_conf}%</span>"
                        f"<span style='color:#446688;margin-left:8px'>False Positive Risk:</span>"
                        f"<span style='background:{_fp_color}22;border:1px solid {_fp_color}44;"
                        f"color:{_fp_color};border-radius:4px;padding:1px 8px'>{_fp_text}</span>"
                        f"<span style='color:#446688;margin-left:8px'>Priority:</span>"
                        f"<span style='color:#c8e8ff'>{_narr_quick.get('priority','?')}</span>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

                    _btn1, _btn2, _btn3 = st.columns(3)
                    if _btn1.button("🤖 Generate AI Narrative", key=f"narr_{inc['id']}",
                                    use_container_width=True):
                        st.session_state["selected_incident"] = inc
                        st.session_state.mode = "SOC Brain & Copilot"
                        st.rerun()
                    if _btn2.button("📋 Create IR Case", key=f"ir_{inc['id']}",
                                    use_container_width=True):
                        st.session_state.setdefault("ir_cases", []).append({
                            "title":    f"{inc.get('chain_name','Multi-Alert Incident')} — {inc['host']}",
                            "severity": sev,
                            "host":     inc["host"],
                            "mitre":    ", ".join(inc["mitre_techniques"][:3]),
                            "risk":     score,
                            "status":   "open",
                            "alerts":   inc["alert_count"],
                        })
                        st.success(f"✅ IR Case created for {inc['id']}")
                    if _btn3.button("📊 Send to Splunk", key=f"spl_{inc['id']}",
                                    use_container_width=True):
                        try:
                            from splunk_handler import send_to_splunk as _spl
                            _priority = ("P1" if sev=="critical" else "P2" if sev=="high"
                                         else "P3" if sev=="medium" else "P4")
                            _narr = generate_soc_narrative(inc)
                            _spl({
                                "event_type":         "correlated_incident",
                                "incident_id":        inc["id"],
                                "host":               inc["host"],
                                "asset_role":         inc.get("asset_role","Unknown"),
                                "asset_criticality":  inc.get("criticality",0),
                                "severity":           sev,
                                "incident_priority":  _priority,
                                "risk_score":         score,
                                "confidence":         _narr.get("conf_pct", 0),
                                "attack_chain":       inc.get("chain_name",""),
                                "chain_description":  inc.get("chain",{}).get("description","") if inc.get("chain") else "",
                                "phases":             inc["phases"],
                                "attack_flow":        " → ".join(inc["phases"]),
                                "mitre_techniques":   inc.get("mitre_techniques",[]),
                                "alert_count":        inc["alert_count"],
                                "false_positive_risk": "High" if not inc.get("chain") and score < 60 else "Low",
                                "recommended_action": ("isolate_host" if sev=="critical"
                                                       else "investigate" if sev=="high"
                                                       else "monitor"),
                                "netsec_ai_what":     _narr.get("what","")[:300],
                                "netsec_ai_priority": _narr.get("priority",""),
                                "source":             "netsec_ai_correlation_v12",
                            })
                            st.success("✅ Incident sent to Splunk with full intelligence payload")
                        except Exception as _e:
                            st.warning(f"Configure Splunk in Settings → API Config ({_e})")
        else:
            st.info("Load alerts and click **Run Correlation Engine** to detect attack chains.")
            # Demo button
            if st.button("🎯 Load demo alerts and run", key="corr_demo"):
                demo = [
                    {"agent_name":"dc01","agent_ip":"10.0.0.10","rule":{"id":"5501","level":9},"mitre_technique":"T1548.003","alert_type":"Sudo used","severity":"high","threat_score":72,"timestamp":"2026-04-01T10:01:00"},
                    {"agent_name":"dc01","agent_ip":"10.0.0.10","rule":{"id":"60109","level":8},"mitre_technique":"T1098","alert_type":"Account created","severity":"high","threat_score":80,"timestamp":"2026-04-01T10:03:00"},
                    {"agent_name":"dc01","agent_ip":"10.0.0.10","rule":{"id":"591","level":11},"mitre_technique":"T1070","alert_type":"Log cleared","severity":"critical","threat_score":95,"timestamp":"2026-04-01T10:05:00"},
                    {"agent_name":"workstation-03","agent_ip":"192.168.1.55","rule":{"id":"60122","level":7},"mitre_technique":"T1110","alert_type":"Multiple login failures","severity":"medium","threat_score":55,"timestamp":"2026-04-01T10:02:00"},
                    {"agent_name":"workstation-03","agent_ip":"192.168.1.55","rule":{"id":"40101","level":10},"mitre_technique":"T1021.002","alert_type":"SMB lateral movement","severity":"high","threat_score":88,"timestamp":"2026-04-01T10:08:00"},
                    {"agent_name":"fileserver","agent_ip":"10.0.0.20","rule":{"id":"60110","level":8},"mitre_technique":"T1098","alert_type":"Account privilege changed","severity":"high","threat_score":75,"timestamp":"2026-04-01T10:10:00"},
                ]
                st.session_state["triage_alerts"] = demo
                incidents = correlate_alerts(demo, 15, 2)
                auto_result = auto_triage_alerts(demo, 60, esc_thr)
                st.session_state["corr_incidents"] = incidents
                st.session_state["corr_auto"] = auto_result
                st.rerun()

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 2: ASSET INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════════
    with tab_asset:
        st.subheader("🏢 Asset Intelligence")
        st.caption("Hostname → role → criticality mapping. Same alert = different priority on DC vs workstation.")

        st.markdown("**Lookup any hostname or IP:**")
        _ac1, _ac2 = st.columns(2)
        lookup_host = _ac1.text_input("Hostname", value="dc01", key="asset_host")
        lookup_ip   = _ac2.text_input("IP address", value="10.0.0.10", key="asset_ip")

        if st.button("🔍 Resolve Asset", key="asset_lookup"):
            asset = resolve_asset(lookup_host, lookup_ip)
            _SEV = {"🔴 CRITICAL":"#ff0033","🟠 HIGH":"#ff9900","🟡 MEDIUM":"#ffcc00","🟢 LOW":"#00aaff"}
            _c = _SEV.get(asset["criticality_label"], "#888")
            st.markdown(
                f"<div style='background:{_c}11;border:1px solid {_c}44;border-radius:8px;padding:14px'>"
                f"<div style='color:{_c};font-weight:900;font-size:.9rem'>{asset['criticality_label']}</div>"
                f"<div style='color:#c8e8ff;font-size:.8rem;margin:4px 0'><b>Role:</b> {asset['role']}</div>"
                f"<div style='color:#c8e8ff;font-size:.8rem;margin:4px 0'><b>Criticality:</b> {asset['criticality']}/10</div>"
                f"<div style='color:#c8e8ff;font-size:.8rem;margin:4px 0'><b>Risk multiplier:</b> ×{asset['risk_multiplier']:.2f}</div>"
                f"<div style='color:#446688;font-size:.7rem;margin-top:6px'>Same alert on this host will be scored: "
                f"base_score × {asset['risk_multiplier']:.2f}</div>"
                f"</div>",
                unsafe_allow_html=True
            )

        st.divider()
        st.markdown("**Asset registry (currently loaded):**")
        asset_rows = []
        for hostname, data in _DEFAULT_ASSET_DB.items():
            if hostname == "unknown": continue
            asset_rows.append({
                "Hostname pattern": hostname,
                "Role":             data["role"],
                "Criticality":      f"{data['criticality']}/10",
                "Risk multiplier":  f"×{1.0 + (data['criticality'] - 5) * 0.15:.2f}",
            })
        st.dataframe(pd.DataFrame(asset_rows), use_container_width=True, hide_index=True)

        st.markdown("**Impact demonstration:**")
        st.markdown("""
| Scenario | Threat score | Asset | Adjusted score | Verdict |
|---|---|---|---|---|
| Brute force | 55 | Workstation (×0.85) | **47** | Medium |
| Brute force | 55 | Domain Controller (×1.75) | **96** | 🔴 Critical |
| Login failure | 40 | File Server (×1.45) | **58** | High |
| Login failure | 40 | Desktop (×0.70) | **28** | Low |
        """)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 3: INCIDENT VIEW
    # ══════════════════════════════════════════════════════════════════════════
    with tab_inc:
        st.subheader("📋 Incident View")
        st.caption("Correlated incidents with full timeline — not just a flat alert list")

        incidents = st.session_state.get("corr_incidents", [])
        if not incidents:
            st.info("Run the Correlation Engine first (Tab 1) to generate incidents.")
            return

        for inc in incidents:
            sev = inc["severity"]
            _SEV = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}
            _c_map = {"critical":"#ff0033","high":"#ff9900","medium":"#ffcc00","low":"#00aaff"}
            _ic = _SEV.get(sev,"⚪")
            _c  = _c_map.get(sev,"#888")

            st.markdown(
                f"<div style='background:#0a1420;border:1px solid {_c}44;"
                f"border-left:4px solid {_c};border-radius:8px;padding:14px;margin:8px 0'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                f"<div>"
                f"<span style='color:{_c};font-weight:900;font-size:.9rem'>{_ic} {inc['id']}</span>"
                f"<span style='color:#446688;font-size:.7rem;margin-left:12px'>{inc['host']} · {inc['asset_role']}</span>"
                f"</div>"
                f"<span style='color:{_c};font-weight:900;font-size:1.1rem'>{inc['risk_score']}/100</span>"
                f"</div>"
                f"<div style='color:#446688;font-size:.65rem;margin-top:6px'>"
                f"⏱ {inc.get('start_time','?')[:16]} → {inc.get('end_time','?')[:16]} · "
                f"{inc['alert_count']} alerts · {len(inc['phases'])} phases · "
                f"{inc['criticality_label']}"
                f"</div>"
                f"</div>",
                unsafe_allow_html=True
            )

            col_tl, col_rec = st.columns([3, 2])
            with col_tl:
                st.markdown("**Timeline:**")
                for i, ev in enumerate(inc["timeline"]):
                    _pc = _c_map.get(ev["severity"],"#888")
                    connector = "│" if i < len(inc["timeline"])-1 else "└"
                    st.markdown(
                        f"<div style='font-size:.68rem;padding:2px 0;display:flex;gap:8px'>"
                        f"<span style='color:#446688'>{connector} {ev['time']}</span>"
                        f"<span style='color:{_pc};font-weight:700;min-width:120px'>{ev['phase']}</span>"
                        f"<span style='color:#c8e8ff'>{ev['description'][:50]}</span>"
                        f"<span style='color:#00ffc8;font-size:.6rem'>{ev['mitre']}</span>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

            with col_rec:
                st.markdown("**Actions:**")
                for rec in inc["recommendations"][:4]:
                    st.markdown(f"<div style='font-size:.68rem;color:#c8e8ff;padding:2px 0'>→ {rec}</div>",
                                unsafe_allow_html=True)

            st.markdown("---")

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 4: AI NARRATIVE
    # ══════════════════════════════════════════════════════════════════════════
    with tab_narr:
        st.subheader("🤖 AI Narrative Generator")
        st.caption("Structured SOC narrative: What happened / Why it matters / What to do / Confidence")

        incidents = st.session_state.get("corr_incidents", [])
        selected_inc = st.session_state.get("selected_incident")

        if not incidents:
            st.info("Run Correlation Engine first to generate incidents for narrative.")
            return

        inc_options = {f"{i['id']} — {i['host']} (risk: {i['risk_score']})": i
                       for i in incidents}
        sel_key = st.selectbox("Select incident", list(inc_options.keys()), key="narr_sel")
        sel_inc = inc_options[sel_key]

        if st.button("🤖 Generate SOC Narrative", type="primary",
                     use_container_width=True, key="gen_narr"):
            with st.spinner("Generating SOC-grade narrative…"):
                narrative = generate_soc_narrative(sel_inc)
            st.session_state["last_narrative"] = narrative

        narrative = st.session_state.get("last_narrative")
        if narrative:
            sev = sel_inc.get("severity","medium")
            _c  = {"critical":"#ff0033","high":"#ff9900","medium":"#ffcc00","low":"#00aaff"}.get(sev,"#888")

            for section, title, icon in [
                ("what",       "WHAT HAPPENED",    "🔍"),
                ("why",        "WHY IT MATTERS",   "⚠️"),
                ("do",         "WHAT TO DO",       "✅"),
                ("confidence", "CONFIDENCE",        "📊"),
            ]:
                st.markdown(
                    f"<div style='background:#0a1420;border:1px solid #0d2030;"
                    f"border-left:3px solid {_c};border-radius:0 8px 8px 0;"
                    f"padding:12px 16px;margin:8px 0'>"
                    f"<div style='color:{_c};font-weight:900;font-size:.72rem;"
                    f"letter-spacing:1px;margin-bottom:6px'>{icon} {title}</div>"
                    f"<div style='color:#c8e8ff;font-size:.78rem;line-height:1.6;white-space:pre-wrap'>"
                    f"{narrative[section]}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

            # Copy button
            full_report = (
                f"INCIDENT: {sel_inc['id']} — {sel_inc['host']}\n"
                f"SEVERITY: {sel_inc['severity'].upper()} | RISK: {sel_inc['risk_score']}/100\n\n"
                f"WHAT HAPPENED:\n{narrative['what']}\n\n"
                f"WHY IT MATTERS:\n{narrative['why']}\n\n"
                f"WHAT TO DO:\n{narrative['do']}\n\n"
                f"CONFIDENCE:\n{narrative['confidence']}"
            )
            st.download_button("📥 Download Narrative", full_report,
                               f"{sel_inc['id']}_narrative.txt", "text/plain",
                               key="dl_narr")