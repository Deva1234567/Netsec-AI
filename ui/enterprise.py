# enterprise.py
# Enterprise Security Framework Module for NetSec AI IDS
# Covers: Threat Modeling, Vulnerability Assessment (CVSS), 
#         Incident Response, NIST/ISO/CIS/OWASP Framework Mapping

import os
import json
import socket
import logging
import subprocess
import platform
from datetime import datetime, timezone
from typing import Optional

import requests
import pandas as pd

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# 1. THREAT MODELING
# ══════════════════════════════════════════════════════════════════════════════

ASSET_TYPES = {
    "web_server":    {"label": "Web Server",        "value": 9},
    "database":      {"label": "Database",           "value": 10},
    "auth_service":  {"label": "Auth Service",       "value": 10},
    "api_gateway":   {"label": "API Gateway",        "value": 8},
    "cdn":           {"label": "CDN / Load Balancer","value": 6},
    "mail_server":   {"label": "Mail Server",        "value": 7},
    "dns":           {"label": "DNS Server",         "value": 8},
    "file_server":   {"label": "File Server",        "value": 7},
    "monitoring":    {"label": "Monitoring System",  "value": 5},
    "endpoint":      {"label": "User Endpoint",      "value": 6},
}

ATTACK_SURFACES = {
    "public_http":   {"label": "Public HTTP/S endpoints",   "risk": 9},
    "open_ports":    {"label": "Exposed network ports",     "risk": 8},
    "weak_ssl":      {"label": "Weak/expired SSL cert",     "risk": 7},
    "no_auth":       {"label": "Unauthenticated endpoints", "risk": 10},
    "xss_vectors":   {"label": "XSS attack vectors",        "risk": 8},
    "sqli_vectors":  {"label": "SQL injection vectors",     "risk": 9},
    "misconf":       {"label": "Security misconfigurations","risk": 7},
    "third_party":   {"label": "Third-party dependencies",  "risk": 6},
    "dns_exposure":  {"label": "DNS information exposure",  "risk": 5},
    "old_software":  {"label": "Outdated software/headers", "risk": 7},
}

ATTACK_PATHS = [
    {
        "id": "AP-001",
        "name": "SQL Injection → DB Exfiltration",
        "steps": ["Reconnaissance", "SQLi via web form", "DB dump", "Data exfiltration"],
        "mitre": "T1190 → T1005",
        "likelihood": 8, "impact": 10,
        "framework_refs": {"OWASP": "A03:2021", "NIST": "SI-10", "CIS": "Control 16"},
    },
    {
        "id": "AP-002",
        "name": "XSS → Session Hijack",
        "steps": ["Phishing link", "XSS payload injection", "Cookie theft", "Account takeover"],
        "mitre": "T1189 → T1539",
        "likelihood": 7, "impact": 8,
        "framework_refs": {"OWASP": "A03:2021", "NIST": "SC-8", "CIS": "Control 16"},
    },
    {
        "id": "AP-003",
        "name": "Port Scan → Service Exploit",
        "steps": ["Nmap scan", "Identify vulnerable service", "Exploit CVE", "Privilege escalation"],
        "mitre": "T1046 → T1068",
        "likelihood": 6, "impact": 9,
        "framework_refs": {"OWASP": "A06:2021", "NIST": "SI-2", "CIS": "Control 7"},
    },
    {
        "id": "AP-004",
        "name": "Malware → Lateral Movement",
        "steps": ["Phishing email", "Malware execution", "C2 connection", "Lateral movement"],
        "mitre": "T1204 → T1021",
        "likelihood": 7, "impact": 10,
        "framework_refs": {"OWASP": "A08:2021", "NIST": "SI-3", "CIS": "Control 10"},
    },
    {
        "id": "AP-005",
        "name": "SSL Weakness → MITM",
        "steps": ["Cert expiry/mismatch detected", "Traffic interception", "Credential harvest"],
        "mitre": "T1557",
        "likelihood": 5, "impact": 9,
        "framework_refs": {"OWASP": "A02:2021", "NIST": "SC-17", "CIS": "Control 16"},
    },
    {
        "id": "AP-006",
        "name": "DDoS → Service Outage",
        "steps": ["Botnet assembly", "Volumetric attack", "Service degradation", "Outage"],
        "mitre": "T1498",
        "likelihood": 6, "impact": 8,
        "framework_refs": {"OWASP": "A05:2021", "NIST": "CP-10", "CIS": "Control 13"},
    },
]


def build_threat_model(domain: str, analysis_result: dict) -> dict:
    """
    Build a structured threat model from an analysis result.
    Returns assets, attack surfaces, attack paths, and risk matrix.
    """
    prediction   = analysis_result.get("prediction",   "Unknown")
    threat_score = int(analysis_result.get("threat_score", 0))
    ssl_result   = analysis_result.get("ssl",  {})
    scan_result  = analysis_result.get("scan", {})
    flaws        = analysis_result.get("security_audit", [])
    vt_result    = analysis_result.get("virustotal", "")

    # ── Infer active assets ──
    active_assets = ["web_server"]
    if isinstance(scan_result, dict):
        ports = [p["port"] for p in scan_result.get("ports", [])]
        if any(p in ports for p in [3306, 5432, 1433]):
            active_assets.append("database")
        if 25 in ports or 587 in ports:
            active_assets.append("mail_server")
        if 53 in ports:
            active_assets.append("dns")
        if any(p in ports for p in [8080, 8443, 8000]):
            active_assets.append("api_gateway")

    # ── Infer active attack surfaces ──
    active_surfaces = ["public_http"]
    if isinstance(ssl_result, dict):
        if ssl_result.get("expired") or not ssl_result.get("hostname_match", True):
            active_surfaces.append("weak_ssl")
    if isinstance(flaws, list):
        for f in flaws:
            fl = f.lower()
            if "xss" in fl:             active_surfaces.append("xss_vectors")
            if "sql" in fl:             active_surfaces.append("sqli_vectors")
            if "missing" in fl:         active_surfaces.append("misconf")
    if isinstance(scan_result, dict) and scan_result.get("ports"):
        active_surfaces.append("open_ports")

    # ── Infer relevant attack paths ──
    active_paths = []
    for path in ATTACK_PATHS:
        if "SQL" in path["name"] and "sqli_vectors" in active_surfaces:
            active_paths.append(path)
        elif "XSS" in path["name"] and "xss_vectors" in active_surfaces:
            active_paths.append(path)
        elif "Port" in path["name"] and "open_ports" in active_surfaces:
            active_paths.append(path)
        elif "Malware" in path["name"] and prediction in ("Malware", "Suspicious"):
            active_paths.append(path)
        elif "SSL" in path["name"] and "weak_ssl" in active_surfaces:
            active_paths.append(path)

    if not active_paths:
        active_paths = ATTACK_PATHS[:2]  # always show at least 2

    # ── Risk matrix ──
    def _risk(likelihood, impact):
        r = (likelihood * impact) / 10
        if r >= 8:   return "Critical"
        if r >= 6:   return "High"
        if r >= 4:   return "Medium"
        return "Low"

    risk_matrix = [
        {
            "Attack Path":  p["name"],
            "ID":           p["id"],
            "Likelihood":   p["likelihood"],
            "Impact":       p["impact"],
            "Risk Score":   round((p["likelihood"] * p["impact"]) / 10, 1),
            "Risk Level":   _risk(p["likelihood"], p["impact"]),
            "MITRE":        p["mitre"],
            "OWASP":        p["framework_refs"]["OWASP"],
            "NIST":         p["framework_refs"]["NIST"],
            "CIS":          p["framework_refs"]["CIS"],
        }
        for p in active_paths
    ]

    # ── Business impact score ──
    asset_value  = max((ASSET_TYPES[a]["value"] for a in active_assets), default=5)
    surface_risk = max((ATTACK_SURFACES[s]["risk"] for s in active_surfaces), default=5)
    biz_impact   = round((asset_value * surface_risk * threat_score) / 1000 * 10, 1)

    return {
        "domain":          domain,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "active_assets":   [ASSET_TYPES[a] for a in active_assets],
        "attack_surfaces": [ATTACK_SURFACES[s] for s in active_surfaces],
        "attack_paths":    active_paths,
        "risk_matrix":     risk_matrix,
        "business_impact": min(biz_impact, 10.0),
        "threat_score":    threat_score,
        "overall_risk":    _risk(surface_risk, threat_score // 10 or 1),
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. VULNERABILITY ASSESSMENT  (CVSS + CVE + NIST alignment)
# ══════════════════════════════════════════════════════════════════════════════

# Static CVE/CVSS knowledge base mapped to common findings
CVE_KNOWLEDGE_BASE = [
    {
        "id": "CVE-2021-44228", "name": "Log4Shell",
        "cvss": 10.0, "severity": "Critical",
        "trigger": ["java", "log4j", "8080"],
        "description": "Remote code execution via JNDI injection in Log4j.",
        "remediation": "Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true.",
        "nist": "SI-2", "cis": "Control 7", "owasp": "A06:2021",
    },
    {
        "id": "CVE-2021-26855", "name": "ProxyLogon (Exchange)",
        "cvss": 9.8, "severity": "Critical",
        "trigger": ["exchange", "smtp", "25", "443"],
        "description": "SSRF leading to pre-auth RCE on Microsoft Exchange.",
        "remediation": "Apply KB5001779 patch. Block external access to ECP/OWA.",
        "nist": "SI-2", "cis": "Control 7", "owasp": "A06:2021",
    },
    {
        "id": "CVE-2017-5638", "name": "Apache Struts RCE",
        "cvss": 10.0, "severity": "Critical",
        "trigger": ["struts", "8080", "java"],
        "description": "RCE via Content-Type header in Struts 2.",
        "remediation": "Upgrade Apache Struts to 2.3.32+ or 2.5.10.1+.",
        "nist": "SI-2", "cis": "Control 7", "owasp": "A06:2021",
    },
    {
        "id": "CVE-2019-0708", "name": "BlueKeep (RDP)",
        "cvss": 9.8, "severity": "Critical",
        "trigger": ["3389", "rdp"],
        "description": "Pre-auth RCE in Windows Remote Desktop Services.",
        "remediation": "Apply MS19-0708 patch. Disable RDP if not needed.",
        "nist": "CM-7", "cis": "Control 4", "owasp": "A05:2021",
    },
    {
        "id": "CVE-2020-1472", "name": "Zerologon",
        "cvss": 10.0, "severity": "Critical",
        "trigger": ["445", "smb", "netlogon"],
        "description": "Privilege escalation in Netlogon allowing domain takeover.",
        "remediation": "Apply August 2020 Windows security updates.",
        "nist": "AC-6", "cis": "Control 5", "owasp": "A01:2021",
    },
    {
        "id": "OWASP-XSS", "name": "Cross-Site Scripting (XSS)",
        "cvss": 6.1, "severity": "Medium",
        "trigger": ["xss", "script"],
        "description": "Reflected/stored XSS allowing session hijacking.",
        "remediation": "Implement output encoding, CSP headers, input validation.",
        "nist": "SI-10", "cis": "Control 16", "owasp": "A03:2021",
    },
    {
        "id": "OWASP-SQLI", "name": "SQL Injection",
        "cvss": 9.8, "severity": "Critical",
        "trigger": ["sql", "sqli", "mysql", "database"],
        "description": "SQL injection enabling data extraction and auth bypass.",
        "remediation": "Use parameterised queries, ORM, WAF rules.",
        "nist": "SI-10", "cis": "Control 16", "owasp": "A03:2021",
    },
    {
        "id": "OWASP-MISCONFIG", "name": "Security Misconfiguration",
        "cvss": 5.3, "severity": "Medium",
        "trigger": ["missing", "header", "misconfiguration"],
        "description": "Missing security headers expose users to attack vectors.",
        "remediation": "Add X-Frame-Options, HSTS, CSP, X-Content-Type-Options.",
        "nist": "CM-6", "cis": "Control 4", "owasp": "A05:2021",
    },
    {
        "id": "SSL-EXPIRED", "name": "Expired SSL Certificate",
        "cvss": 5.9, "severity": "Medium",
        "trigger": ["expired", "ssl"],
        "description": "Expired certificate allows MITM and breaks trust.",
        "remediation": "Renew certificate immediately. Enable auto-renewal (Let's Encrypt).",
        "nist": "SC-17", "cis": "Control 16", "owasp": "A02:2021",
    },
    {
        "id": "SSL-MISMATCH", "name": "SSL Hostname Mismatch",
        "cvss": 5.4, "severity": "Medium",
        "trigger": ["hostname_match", "mismatch"],
        "description": "Certificate hostname mismatch allows impersonation.",
        "remediation": "Reissue certificate with correct SAN/CN entries.",
        "nist": "SC-17", "cis": "Control 16", "owasp": "A02:2021",
    },
]


def _cvss_rating(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score >= 0.1: return "Low"
    return "None"


def run_vulnerability_assessment(domain: str, analysis_result: dict) -> dict:
    """
    Map findings from analysis_result to CVEs/CVSS scores.
    Returns structured VA report aligned to NIST, CIS, OWASP.
    """
    flaws       = analysis_result.get("security_audit", [])
    ssl_result  = analysis_result.get("ssl",  {})
    scan_result = analysis_result.get("scan", {})
    vt_result   = analysis_result.get("virustotal", "")
    prediction  = analysis_result.get("prediction", "")

    # Build search corpus from all findings
    corpus = " ".join([
        " ".join(flaws),
        str(ssl_result),
        str([p.get("service","") for p in scan_result.get("ports", [])]),
        str([p.get("port",0) for p in scan_result.get("ports", [])]),
        vt_result,
        prediction,
    ]).lower()

    matched_vulns = []
    for cve in CVE_KNOWLEDGE_BASE:
        if any(t in corpus for t in cve["trigger"]):
            matched_vulns.append(cve)

    # Always include generic findings based on flaws
    flaw_text = " ".join(flaws).lower()
    if "xss" in flaw_text and not any(v["id"] == "OWASP-XSS" for v in matched_vulns):
        matched_vulns.append(next(v for v in CVE_KNOWLEDGE_BASE if v["id"] == "OWASP-XSS"))
    if "sql" in flaw_text and not any(v["id"] == "OWASP-SQLI" for v in matched_vulns):
        matched_vulns.append(next(v for v in CVE_KNOWLEDGE_BASE if v["id"] == "OWASP-SQLI"))
    if "missing" in flaw_text and not any(v["id"] == "OWASP-MISCONFIG" for v in matched_vulns):
        matched_vulns.append(next(v for v in CVE_KNOWLEDGE_BASE if v["id"] == "OWASP-MISCONFIG"))
    if isinstance(ssl_result, dict) and ssl_result.get("expired"):
        if not any(v["id"] == "SSL-EXPIRED" for v in matched_vulns):
            matched_vulns.append(next(v for v in CVE_KNOWLEDGE_BASE if v["id"] == "SSL-EXPIRED"))

    if not matched_vulns:
        matched_vulns = []

    # Build CVSS summary
    cvss_scores  = [v["cvss"] for v in matched_vulns]
    max_cvss     = max(cvss_scores) if cvss_scores else 0.0
    avg_cvss     = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0
    critical_cnt = sum(1 for s in cvss_scores if s >= 9.0)
    high_cnt     = sum(1 for s in cvss_scores if 7.0 <= s < 9.0)

    return {
        "domain":           domain,
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "vulnerabilities":  matched_vulns,
        "total_vulns":      len(matched_vulns),
        "max_cvss":         max_cvss,
        "avg_cvss":         avg_cvss,
        "critical_count":   critical_cnt,
        "high_count":       high_cnt,
        "overall_rating":   _cvss_rating(max_cvss),
        "scan_basis":       {
            "flaws_checked":  len(flaws),
            "ports_scanned":  len(scan_result.get("ports", [])),
            "ssl_checked":    "error" not in ssl_result,
            "vt_checked":     bool(vt_result),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3. INCIDENT RESPONSE
# ══════════════════════════════════════════════════════════════════════════════

IR_PLAYBOOKS = {
    "Malware": [
        "🔴 ISOLATE: Identify and quarantine affected host",
        "🔍 IDENTIFY: Collect IOCs (IPs, hashes, domains)",
        "📋 CONTAIN: Block C2 IP at firewall/EDR",
        "🧹 ERADICATE: Remove malware, patch entry point",
        "🔄 RECOVER: Restore from clean backup",
        "📝 LESSONS: Update detection rules and IOC feeds",
    ],
    "SQLi": [
        "🔴 CONTAIN: WAF rule to block SQLi patterns immediately",
        "🔍 IDENTIFY: Review DB query logs for exfiltration",
        "🔒 PATCH: Parameterise all DB queries",
        "🔄 RECOVER: Audit and restore affected DB records",
        "📝 LESSONS: Implement SAST/DAST in CI pipeline",
    ],
    "XSS": [
        "🔴 CONTAIN: Deploy CSP header to block inline scripts",
        "🔍 IDENTIFY: Check session logs for stolen tokens",
        "🔒 PATCH: Encode all user-controlled output",
        "🔄 RECOVER: Invalidate all active sessions",
        "📝 LESSONS: Add XSS scanning to CI/CD pipeline",
    ],
    "Suspicious": [
        "🔍 INVESTIGATE: Correlate with Splunk for full timeline",
        "📋 MONITOR: Increase logging verbosity on affected host",
        "🔒 HARDEN: Apply principle of least privilege",
        "📝 DOCUMENT: Log all findings for chain-of-custody",
    ],
    "Port Scan": [
        "🔴 BLOCK: Add source IP to firewall deny list",
        "🔍 IDENTIFY: Check if scan preceded any access attempts",
        "📋 MONITOR: Enable IDS alerts on this IP range",
        "📝 REPORT: Log for threat intelligence feed",
    ],
    "DDoS": [
        "🔴 MITIGATE: Enable rate limiting / scrubbing service",
        "📋 CONTACT: Notify upstream ISP and CDN provider",
        "🔍 IDENTIFY: Capture botnet source IPs",
        "🔄 RECOVER: Restore service after mitigation",
    ],
}

IR_PHASES = ["Preparation", "Identification", "Containment",
             "Eradication", "Recovery", "Lessons Learned"]


def generate_ir_report(domain: str, analysis_result: dict,
                        blocked_ips: list = None) -> dict:
    """
    Generate a structured Incident Response report with:
    - Playbook steps for the detected threat
    - Chain-of-custody timeline
    - Containment actions taken
    - NIST IR framework alignment
    """
    prediction   = analysis_result.get("prediction",   "Unknown")
    threat_score = int(analysis_result.get("threat_score", 0))
    ip           = analysis_result.get("ip",     "unknown")
    vt_result    = analysis_result.get("virustotal", "")
    flaws        = analysis_result.get("security_audit", [])
    ssl_result   = analysis_result.get("ssl",   {})
    ts           = datetime.now(timezone.utc).isoformat()

    playbook = IR_PLAYBOOKS.get(prediction, IR_PLAYBOOKS["Suspicious"])

    # Severity / priority
    if threat_score >= 70:   priority = "P1 — Critical"
    elif threat_score >= 40: priority = "P2 — High"
    elif threat_score >= 20: priority = "P3 — Medium"
    else:                    priority = "P4 — Low"

    # Chain-of-custody timeline
    timeline = [
        {"time": ts, "event": f"Alert generated by NetSec AI IDS",
         "actor": "Automated", "phase": "Identification"},
        {"time": ts, "event": f"Threat classified: {prediction} (score {threat_score}/100)",
         "actor": "ML Model", "phase": "Identification"},
        {"time": ts, "event": f"Domain resolved to IP: {ip}",
         "actor": "DNS Resolver", "phase": "Identification"},
    ]

    if vt_result and "threats detected" in vt_result.lower():
        timeline.append({
            "time": ts, "event": f"VirusTotal confirmed: {vt_result}",
            "actor": "VirusTotal API", "phase": "Identification"
        })

    if isinstance(ssl_result, dict) and (ssl_result.get("expired") or
                                          not ssl_result.get("hostname_match", True)):
        timeline.append({
            "time": ts, "event": "SSL certificate issue detected",
            "actor": "SSL Inspector", "phase": "Identification"
        })

    containment_actions = []
    if blocked_ips:
        for bip in blocked_ips:
            timeline.append({
                "time": ts, "event": f"IP blocked: {bip}",
                "actor": "Analyst", "phase": "Containment"
            })
            containment_actions.append(f"Blocked IP: {bip}")

    # NIST IR framework mapping
    nist_mapping = {
        "Preparation":   "NIST SP 800-61 §3.1 — IR Policy, Team, Tools",
        "Identification":"NIST SP 800-61 §3.2 — Detection & Analysis",
        "Containment":   "NIST SP 800-61 §3.3 — Short/Long-term containment",
        "Eradication":   "NIST SP 800-61 §3.3 — Remove threat, patch systems",
        "Recovery":      "NIST SP 800-61 §3.4 — Restore & validate systems",
        "Lessons Learned":"NIST SP 800-61 §3.5 — Post-incident activity",
    }

    return {
        "ir_id":              f"IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "domain":             domain,
        "ip":                 ip,
        "timestamp":          ts,
        "priority":           priority,
        "threat_type":        prediction,
        "threat_score":       threat_score,
        "playbook":           playbook,
        "timeline":           timeline,
        "containment_actions": containment_actions,
        "nist_ir_mapping":    nist_mapping,
        "status":             "Open",
        "assigned_to":        "SOC Analyst",
        "escalation_required": threat_score >= 60,
    }


def block_ip_windows(ip: str) -> tuple[bool, str]:
    """
    Block an IP using Windows Firewall (netsh) — requires admin privileges.
    Returns (success, message).
    """
    if platform.system() != "Windows":
        return False, "IP blocking via netsh only supported on Windows"
    try:
        rule_name = f"NetSecAI_Block_{ip.replace('.','_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}",
            "protocol=any", "enable=yes",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.info(f"Blocked IP {ip} via Windows Firewall")
            return True, f"IP {ip} blocked via Windows Firewall rule '{rule_name}'"
        else:
            return False, f"netsh failed: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "netsh command timed out — run Streamlit as Administrator"
    except Exception as e:
        return False, str(e)


def unblock_ip_windows(ip: str) -> tuple[bool, str]:
    """Remove a previously added block rule."""
    if platform.system() != "Windows":
        return False, "Only supported on Windows"
    try:
        rule_name = f"NetSecAI_Block_{ip.replace('.','_')}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
               f"name={rule_name}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, f"Unblocked IP {ip}"
        return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)


# ══════════════════════════════════════════════════════════════════════════════
# 4. ENTERPRISE FRAMEWORK MAPPING
# ══════════════════════════════════════════════════════════════════════════════

FRAMEWORK_CONTROLS = {
    "NIST_CSF": {
        "label": "NIST Cybersecurity Framework",
        "functions": {
            "Identify":  ["Asset Management", "Risk Assessment", "Governance"],
            "Protect":   ["Access Control", "Data Security", "Protective Technology"],
            "Detect":    ["Anomaly Detection", "Security Monitoring", "Detection Process"],
            "Respond":   ["Response Planning", "Mitigation", "Communication"],
            "Recover":   ["Recovery Planning", "Improvements", "Communications"],
        },
    },
    "ISO_27001": {
        "label": "ISO/IEC 27001:2022",
        "domains": {
            "A.5":  "Information Security Policies",
            "A.6":  "Organisation of Information Security",
            "A.8":  "Asset Management",
            "A.12": "Operations Security",
            "A.13": "Communications Security",
            "A.14": "System Acquisition & Development",
            "A.16": "Incident Management",
            "A.18": "Compliance",
        },
    },
    "CIS_Controls": {
        "label": "CIS Controls v8",
        "controls": {
            "1":  "Inventory of Enterprise Assets",
            "2":  "Inventory of Software Assets",
            "4":  "Secure Configuration",
            "7":  "Continuous Vulnerability Management",
            "10": "Malware Defenses",
            "12": "Network Infrastructure Management",
            "13": "Network Monitoring and Defense",
            "16": "Application Software Security",
            "17": "Incident Response Management",
        },
    },
    "OWASP_TOP10": {
        "label": "OWASP Top 10 (2021)",
        "items": {
            "A01:2021": "Broken Access Control",
            "A02:2021": "Cryptographic Failures",
            "A03:2021": "Injection (SQLi/XSS)",
            "A04:2021": "Insecure Design",
            "A05:2021": "Security Misconfiguration",
            "A06:2021": "Vulnerable & Outdated Components",
            "A07:2021": "Identification & Authentication Failures",
            "A08:2021": "Software & Data Integrity Failures",
            "A09:2021": "Security Logging & Monitoring Failures",
            "A10:2021": "Server-Side Request Forgery",
        },
    },
    "SOC2": {
        "label": "SOC 2 Trust Services Criteria",
        "criteria": {
            "CC1": "Control Environment",
            "CC2": "Communication & Information",
            "CC3": "Risk Assessment",
            "CC4": "Monitoring Controls",
            "CC6": "Logical & Physical Access",
            "CC7": "System Operations",
            "CC8": "Change Management",
            "CC9": "Risk Mitigation",
        },
    },
}


def map_to_frameworks(analysis_result: dict, va_report: dict) -> dict:
    """
    Map detected findings to all enterprise framework controls.
    Returns a compliance gap report.
    """
    prediction   = analysis_result.get("prediction",   "")
    threat_score = int(analysis_result.get("threat_score", 0))
    flaws        = analysis_result.get("security_audit", [])
    ssl_result   = analysis_result.get("ssl", {})
    vulns        = va_report.get("vulnerabilities", [])

    flaw_text = " ".join(flaws).lower()

    gaps = []

    # NIST CSF gaps
    if threat_score > 0:
        gaps.append({"Framework": "NIST CSF", "Control": "Detect — Anomaly Detection",
                     "Status": "⚠️ Partial", "Finding": f"Threat detected: {prediction}",
                     "Recommendation": "Implement continuous SIEM monitoring"})
    if not any("hsts" in f.lower() for f in flaws):
        gaps.append({"Framework": "NIST CSF", "Control": "Protect — Data Security",
                     "Status": "❌ Gap", "Finding": "HSTS not enforced",
                     "Recommendation": "Add Strict-Transport-Security header"})

    # ISO 27001 gaps
    if isinstance(ssl_result, dict) and ssl_result.get("expired"):
        gaps.append({"Framework": "ISO 27001", "Control": "A.13 — Communications Security",
                     "Status": "❌ Gap", "Finding": "Expired SSL certificate",
                     "Recommendation": "Renew certificate, enable auto-renewal"})
    if "missing content-security-policy" in flaw_text:
        gaps.append({"Framework": "ISO 27001", "Control": "A.14 — System Development",
                     "Status": "❌ Gap", "Finding": "No CSP header",
                     "Recommendation": "Implement Content-Security-Policy"})

    # CIS Controls gaps
    if any(v["cvss"] >= 7.0 for v in vulns):
        gaps.append({"Framework": "CIS Controls", "Control": "Control 7 — Vulnerability Management",
                     "Status": "❌ Gap", "Finding": f"{va_report['high_count']} high/critical CVEs found",
                     "Recommendation": "Patch within 30 days (critical: 7 days)"})
    if prediction in ("Malware", "Suspicious"):
        gaps.append({"Framework": "CIS Controls", "Control": "Control 10 — Malware Defenses",
                     "Status": "❌ Gap", "Finding": f"Malware/suspicious activity: {prediction}",
                     "Recommendation": "Deploy EDR, enable real-time scanning"})

    # OWASP gaps
    if "xss" in flaw_text:
        gaps.append({"Framework": "OWASP Top 10", "Control": "A03:2021 — Injection",
                     "Status": "❌ Gap", "Finding": "XSS vulnerability detected",
                     "Recommendation": "Implement output encoding and CSP"})
    if "sql" in flaw_text:
        gaps.append({"Framework": "OWASP Top 10", "Control": "A03:2021 — Injection",
                     "Status": "❌ Gap", "Finding": "SQL injection risk detected",
                     "Recommendation": "Use parameterised queries throughout"})
    if "missing" in flaw_text:
        gaps.append({"Framework": "OWASP Top 10", "Control": "A05:2021 — Misconfiguration",
                     "Status": "⚠️ Partial", "Finding": "Security headers missing",
                     "Recommendation": "Add all recommended security headers"})

    # SOC 2 gaps
    if threat_score >= 40:
        gaps.append({"Framework": "SOC 2", "Control": "CC3 — Risk Assessment",
                     "Status": "❌ Gap", "Finding": f"High risk score: {threat_score}/100",
                     "Recommendation": "Conduct formal risk assessment and treatment"})
    if threat_score >= 20:
        gaps.append({"Framework": "SOC 2", "Control": "CC7 — System Operations",
                     "Status": "⚠️ Partial", "Finding": "Threats detected during operation",
                     "Recommendation": "Implement continuous monitoring and alerting"})

    # Compliance score
    total_controls = 20
    gap_count      = len([g for g in gaps if "❌" in g["Status"]])
    partial_count  = len([g for g in gaps if "⚠️" in g["Status"]])
    compliance_pct = round(((total_controls - gap_count - partial_count * 0.5)
                             / total_controls) * 100, 1)

    return {
        "domain":           analysis_result.get("domain", "unknown"),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "gaps":             gaps,
        "gap_count":        gap_count,
        "partial_count":    partial_count,
        "compliance_score": max(0.0, compliance_pct),
        "frameworks_covered": list(FRAMEWORK_CONTROLS.keys()),
    }


# ══════════════════════════════════════════════════════════════════════════════
# 5. PDF REPORT GENERATION  (ReportLab)
# ══════════════════════════════════════════════════════════════════════════════

def generate_pdf_report(domain: str, threat_model: dict, va_report: dict,
                         ir_report: dict, framework_map: dict) -> bytes:
    """
    Generate a professional PDF security report combining all four modules.
    Returns PDF as bytes for Streamlit download.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle, HRFlowable)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                             rightMargin=0.75*inch, leftMargin=0.75*inch,
                             topMargin=0.75*inch, bottomMargin=0.75*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"],
                                  fontSize=18, spaceAfter=6, textColor=colors.HexColor("#1a1a2e"))
    h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                          fontSize=14, spaceBefore=14, spaceAfter=6,
                          textColor=colors.HexColor("#16213e"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                          fontSize=11, spaceBefore=8, spaceAfter=4,
                          textColor=colors.HexColor("#0f3460"))
    body = styles["Normal"]

    RED  = colors.HexColor("#c0392b")
    ORG  = colors.HexColor("#e67e22")
    GRN  = colors.HexColor("#27ae60")
    BLUE = colors.HexColor("#2980b9")
    HDR  = colors.HexColor("#2c3e50")
    LGRY = colors.HexColor("#ecf0f1")

    def _tbl(data, col_widths=None):
        t = Table(data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), HDR),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [LGRY, colors.white]),
            ("FONTSIZE",    (0, 1), (-1, -1), 8),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        return t

    story = []
    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    # ── Cover ──
    story += [
        Paragraph("NetSec AI — Enterprise Security Report", title_style),
        Paragraph(f"Target: <b>{domain}</b>", body),
        Paragraph(f"Generated: {ts_str}", body),
        Paragraph(f"IR Reference: {ir_report.get('ir_id','N/A')}  |  "
                  f"Priority: {ir_report.get('priority','N/A')}", body),
        HRFlowable(width="100%", thickness=1, color=HDR, spaceAfter=10),
    ]

    # ── Executive Summary ──
    story.append(Paragraph("Executive Summary", h1))
    ts_val = threat_model.get("threat_score", 0)
    va_max = va_report.get("max_cvss", 0)
    cmp    = framework_map.get("compliance_score", 0)
    story += [
        Paragraph(f"Threat Score: <b>{ts_val}/100</b> | "
                  f"Max CVSS: <b>{va_max}</b> | "
                  f"Overall Risk: <b>{threat_model.get('overall_risk','N/A')}</b> | "
                  f"Compliance: <b>{cmp}%</b>", body),
        Spacer(1, 8),
    ]

    # ── 1. Threat Model ──
    story.append(Paragraph("1. Threat Model", h1))
    story.append(Paragraph("Risk Matrix", h2))
    rm = threat_model.get("risk_matrix", [])
    if rm:
        tbl_data = [["ID", "Attack Path", "Likelihood", "Impact", "Risk", "MITRE", "OWASP"]]
        for r in rm:
            tbl_data.append([r["ID"], r["Attack Path"], r["Likelihood"],
                              r["Impact"], f"{r['Risk Score']} ({r['Risk Level']})",
                              r["MITRE"], r["OWASP"]])
        story.append(_tbl(tbl_data, [0.6*inch, 2.2*inch, 0.8*inch, 0.7*inch,
                                      1.1*inch, 1.0*inch, 0.8*inch]))

    story.append(Paragraph(
        f"Business Impact Score: <b>{threat_model.get('business_impact',0)}/10</b>", body))

    # ── 2. Vulnerability Assessment ──
    story.append(Paragraph("2. Vulnerability Assessment (CVSS)", h1))
    story.append(Paragraph(
        f"Total Vulns: <b>{va_report['total_vulns']}</b> | "
        f"Critical: <b>{va_report['critical_count']}</b> | "
        f"High: <b>{va_report['high_count']}</b> | "
        f"Max CVSS: <b>{va_report['max_cvss']}</b> | "
        f"Rating: <b>{va_report['overall_rating']}</b>", body))
    vulns = va_report.get("vulnerabilities", [])
    if vulns:
        tbl_data = [["CVE/ID", "Name", "CVSS", "Severity", "OWASP", "Remediation"]]
        for v in vulns:
            tbl_data.append([v["id"], v["name"], v["cvss"], v["severity"],
                              v["owasp"], Paragraph(v["remediation"], body)])
        story.append(_tbl(tbl_data, [1.0*inch, 1.3*inch, 0.5*inch, 0.7*inch,
                                      0.8*inch, 2.4*inch]))

    # ── 3. Incident Response ──
    story.append(Paragraph("3. Incident Response", h1))
    story.append(Paragraph(f"Priority: <b>{ir_report.get('priority')}</b> | "
                            f"Status: <b>{ir_report.get('status')}</b> | "
                            f"Escalation Required: <b>"
                            f"{'Yes' if ir_report.get('escalation_required') else 'No'}</b>",
                            body))
    story.append(Paragraph("Playbook Steps", h2))
    for step in ir_report.get("playbook", []):
        story.append(Paragraph(f"• {step}", body))

    story.append(Paragraph("Chain-of-Custody Timeline", h2))
    tl = ir_report.get("timeline", [])
    if tl:
        tbl_data = [["Time", "Event", "Actor", "Phase"]]
        for t in tl:
            tbl_data.append([t["time"][-8:], t["event"], t["actor"], t["phase"]])
        story.append(_tbl(tbl_data, [0.8*inch, 3.0*inch, 1.2*inch, 1.2*inch]))

    # ── 4. Framework Compliance ──
    story.append(Paragraph("4. Enterprise Framework Compliance", h1))
    story.append(Paragraph(f"Compliance Score: <b>{cmp}%</b> | "
                            f"Gaps: <b>{framework_map.get('gap_count',0)}</b> | "
                            f"Partial: <b>{framework_map.get('partial_count',0)}</b>", body))
    gaps = framework_map.get("gaps", [])
    if gaps:
        tbl_data = [["Framework", "Control", "Status", "Finding", "Recommendation"]]
        for g in gaps:
            tbl_data.append([g["Framework"], g["Control"], g["Status"],
                              Paragraph(g["Finding"], body),
                              Paragraph(g["Recommendation"], body)])
        story.append(_tbl(tbl_data, [0.9*inch, 1.5*inch, 0.7*inch, 1.5*inch, 2.1*inch]))

    doc.build(story)
    return buf.getvalue()