# ─────────────────────────────────────────────────────────────────────────────
# NetSec AI v10.0 — Triage Module
# Alert Explainer · Bulk Processor · IOC Blast Enrichment · IOC Lookup · Alert Triage
# ─────────────────────────────────────────────────────────────────────────────
"""
Import order: core → triage → detect → respond → investigate → report → advanced
Every module does: from modules.core import *
"""

import os, sys
# Ensure modules/ directory is on path
_this = os.path.dirname(os.path.abspath(__file__))
if _this not in sys.path:
    sys.path.insert(0, _this)
_parent = os.path.dirname(_this)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

try:
    from modules.core import *  # noqa
except Exception as _core_err:
    import os, sys, logging, random, hashlib, json, re, math, io
    import streamlit as st
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    from datetime import datetime
    from collections import Counter, defaultdict


_EXPLAINER_DEMO = {
    "T1059.001": {
        "verdict": "⚠️ REAL THREAT — HIGH CONFIDENCE", "verdict_color": "#ff0033",
        "false_positive_chance": "12% — encoded PowerShell is almost always malicious",
        "plain_english": "An attacker ran a hidden PowerShell command scrambled (Base64-encoded) to avoid detection. Classic first step in ransomware, C2 beaconing, and credential theft.",
        "is_it_real": "✅ Very likely real — 88% of encoded PS commands in production are malicious",
        "what_happened": "Attacker → PowerShell launcher → encoded payload → executes in memory",
        "urgency": "🔴 CRITICAL — Act within 5 minutes. Memory-only malware can vanish on reboot.",
        "actions": ["Isolate the host from network immediately", "Capture memory dump BEFORE rebooting", "Decode the Base64 command and inspect payload", "Check for child processes spawned by PowerShell", "Search all hosts for same encoded string"],
    },
    "T1071": {
        "verdict": "⚠️ REAL THREAT — C2 BEACONING", "verdict_color": "#ff6600",
        "false_positive_chance": "8%",
        "plain_english": "A host is regularly calling home to an external server controlled by an attacker. The attacker is already inside and waiting to send instructions.",
        "is_it_real": "✅ Very likely real",
        "what_happened": "Malware installed → beacons every 60s → waits for attacker commands",
        "urgency": "🔴 HIGH — isolate before attacker issues destructive commands",
        "actions": ["Block the C2 domain at DNS and firewall", "Isolate the beaconing host", "Check outbound connections: netstat -an", "Identify the process making the calls", "Open IR case and check other hosts"],
    },
    "T1071.004": {
        "verdict": "⚠️ DNS TUNNEL OR C2", "verdict_color": "#ff6600",
        "false_positive_chance": "15%",
        "plain_english": "Unusually high DNS queries or long/random subdomains — attackers use DNS to sneak data out because it is rarely blocked.",
        "is_it_real": "⚠️ Likely real if subdomains are long/random",
        "what_happened": "Malware encodes data in DNS queries → exfiltrates or receives commands",
        "urgency": "🟠 HIGH — data may already be leaving",
        "actions": ["Check for >50 char random subdomains", "Block the parent domain at DNS resolver", "Normal hosts do <100 DNS queries/hour", "Run IOC enrichment on the domain", "If confirmed: isolate host, preserve DNS logs"],
    },
    "T1110": {
        "verdict": "⚠️ BRUTE FORCE IN PROGRESS", "verdict_color": "#ff9900",
        "false_positive_chance": "5%",
        "plain_english": "Someone is systematically trying thousands of passwords. The source IP is the attacker.",
        "is_it_real": "✅ Almost certainly real",
        "what_happened": "Attacker IP → automated tool → hammering SSH/RDP/web login",
        "urgency": "🟠 HIGH — block the IP now",
        "actions": ["Block source IP at firewall immediately", "Check if any login SUCCEEDED", "Enable account lockout after 5 failures", "Check for distributed brute force (multiple IPs)", "If login succeeded: treat as full compromise"],
    },
    "T1003": {
        "verdict": "🚨 CRITICAL — CREDENTIAL THEFT", "verdict_color": "#ff0033",
        "false_positive_chance": "3%",
        "plain_english": "An attacker is stealing password hashes from Windows memory (LSASS). With these they can log into any system without knowing passwords.",
        "is_it_real": "✅ Critical — treat as confirmed compromise",
        "what_happened": "Attacker → LSASS memory access → extracts NTLM hashes → lateral movement",
        "urgency": "🔴 CRITICAL — isolate NOW",
        "actions": ["Immediately isolate the host", "Force password reset for ALL accounts on this machine", "Check for Mimikatz/ProcDump/WCE", "Enable Windows Credential Guard", "Assume all credentials compromised — rotate service accounts"],
    },
    "T1003.001": {
        "verdict": "🚨 CRITICAL — LSASS MEMORY ACCESS", "verdict_color": "#ff0033",
        "false_positive_chance": "3%",
        "plain_english": "An attacker is dumping LSASS memory to extract Windows credentials — one of the most serious alerts in a Windows environment.",
        "is_it_real": "✅ Critical",
        "what_happened": "Attacker → LSASS dump → extracts all domain hashes",
        "urgency": "🔴 CRITICAL — isolate NOW",
        "actions": ["Immediately isolate the host", "Force password reset for ALL domain accounts", "Check for Mimikatz or ProcDump", "Enable Windows Credential Guard", "Rotate all service accounts"],
    },
    "T1041": {
        "verdict": "🚨 CRITICAL — DATA EXFILTRATION", "verdict_color": "#ff0033",
        "false_positive_chance": "10%",
        "plain_english": "Data is being sent from your network to an external IP. The attacker is stealing information.",
        "is_it_real": "⚠️ Likely real — check destination IP reputation",
        "what_happened": "Attacker inside → collects data → transfers to external server",
        "urgency": "🔴 CRITICAL — start DPDP breach notification timer",
        "actions": ["Block outbound to destination IP immediately", "Identify what data was transferred", "Start DPDP 72h breach notification timer if PII involved", "Preserve network logs as evidence (hash immediately)", "Notify legal/compliance team"],
    },
    "T1566": {
        "verdict": "⚠️ PHISHING ATTEMPT", "verdict_color": "#ff9900",
        "false_positive_chance": "20%",
        "plain_english": "A suspicious email designed to trick an employee into clicking a malicious link or opening an infected attachment.",
        "is_it_real": "⚠️ Check if user clicked the link",
        "what_happened": "Attacker email → employee inbox → click → credential theft or malware",
        "urgency": "🟠 HIGH — find out if user interacted",
        "actions": ["Contact the recipient — did they click any link?", "Analyze email headers and links", "Check proxy/DNS logs for email domains", "If clicked: reset password, check inbox rules", "Block sender domain at email gateway"],
    },
    "T1486": {
        "verdict": "🚨 RANSOMWARE — MAXIMUM SEVERITY", "verdict_color": "#ff0033",
        "false_positive_chance": "2%",
        "plain_english": "Ransomware is encrypting files RIGHT NOW. Every second more files are destroyed.",
        "is_it_real": "✅ Treat as confirmed. Do not wait.",
        "what_happened": "Ransomware executing → encrypting files → spreading to network shares",
        "urgency": "🔴 MAXIMUM — pull the network cable NOW",
        "actions": ["PHYSICAL network disconnect immediately", "Do NOT reboot — evidence is in memory", "Alert CISO and legal team", "Identify patient zero", "Activate DR/BCP — restore from backup"],
    },
    "T1046": {
        "verdict": "⚠️ NETWORK RECONNAISSANCE", "verdict_color": "#ffcc00",
        "false_positive_chance": "35% — IT teams run legitimate scans",
        "plain_english": "Something on your network is scanning other systems — mapping open ports. Often the first step after initial access.",
        "is_it_real": "⚠️ Check if source IP is an authorised scanner",
        "what_happened": "Host → port scan → maps network topology → feeds lateral movement",
        "urgency": "🟡 MEDIUM — verify source first",
        "actions": ["Is the source IP a known IT scanner?", "Was this scheduled (maintenance window)?", "If unknown: isolate and investigate", "Review what was discovered", "If confirmed attacker: escalate immediately"],
    },
    "DEFAULT": {
        "verdict": "⚠️ SUSPICIOUS ACTIVITY — REVIEW REQUIRED", "verdict_color": "#ff9900",
        "false_positive_chance": "25-40%",
        "plain_english": "An anomalous security event that doesn't match normal patterns. Could be a real attack, misconfigured system, or false positive.",
        "is_it_real": "⚠️ Unknown — check baseline behaviour for this host/user",
        "what_happened": "Anomalous event → context needed to determine attack stage",
        "urgency": "🟡 MEDIUM — review within the hour",
        "actions": ["Check the host's normal behaviour", "Look at events 10 min before and after", "Cross-reference IOC against threat intel", "Determine if legitimate user/process could cause this", "If no benign explanation in 15 min: escalate"],
    },
}


def render_one_click_alert_explainer():
    """
    ONE-CLICK ALERT EXPLAINER
    Solves the #1 SOC analyst pain: understanding what an alert means.
    45 minutes of manual investigation → 10 seconds.
    Shows: plain English, is it real, urgency, exact steps.
    """
    st.markdown(
        "<h2 style='margin:0 0 2px'>🧠 One-Click Alert Explainer</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 14px'>"
        "Select any alert → instant plain-English verdict · Is it real? · "
        "What happened? · Exactly what to do next · "
        "<b style='color:#00f9ff'>45 minutes → 10 seconds</b>"
        "</p>",
        unsafe_allow_html=True
    )

    config        = get_api_config()
    groq_key      = config.get("groq_key", "") or os.getenv("GROQ_API_KEY", "")
    anthropic_key = config.get("anthropic_key", "") or os.getenv("ANTHROPIC_API_KEY", "")
    has_llm       = bool(groq_key or anthropic_key)

    # ── Alert selector ────────────────────────────────────────────────────────
    _all_alerts = (
        st.session_state.get("triage_alerts", []) +
        st.session_state.get("analysis_results", []) +
        [a for a in st.session_state.get("sysmon_results", {}).get("alerts", [])]
    )

    # Inline demo alerts if none loaded
    if not _all_alerts:
        _all_alerts = [
            {"id": "DEMO-001", "alert_type": "PowerShell Encoded Command",
             "mitre": "T1059.001", "severity": "critical", "threat_score": 94,
             "domain": "WORKSTATION-07", "ip": "192.168.1.55",
             "detail": "powershell.exe -nop -w hidden -enc JABjAD0AbgBlAHcA…",
             "timestamp": "10:02:33"},
            {"id": "DEMO-002", "alert_type": "C2 Beaconing Detected",
             "mitre": "T1071", "severity": "high", "threat_score": 87,
             "domain": "c2panel.tk", "ip": "185.220.101.45",
             "detail": "Regular DNS queries every 60s to c2panel.tk",
             "timestamp": "10:08:14"},
            {"id": "DEMO-003", "alert_type": "SSH Brute Force",
             "mitre": "T1110", "severity": "high", "threat_score": 78,
             "domain": "10.0.0.5", "ip": "94.102.49.8",
             "detail": "320 failed SSH logins in 45 seconds from single source IP",
             "timestamp": "10:15:22"},
            {"id": "DEMO-004", "alert_type": "Data Exfiltration",
             "mitre": "T1041", "severity": "critical", "threat_score": 96,
             "domain": "185.220.101.45", "ip": "185.220.101.45",
             "detail": "7.8MB transferred to external IP via HTTPS",
             "timestamp": "10:22:07"},
        ]

    # Build alert labels
    _labels = []
    for a in _all_alerts:
        sev  = a.get("severity", "?").upper()
        name = a.get("alert_type", a.get("type", "Unknown"))[:35]
        host = a.get("domain", a.get("ip", "?"))[:20]
        _labels.append(f"[{sev}] {name} — {host}")

    col_sel, col_btn = st.columns([4, 1])
    with col_sel:
        selected_idx = st.selectbox(
            "Select alert to explain", range(len(_labels)),
            format_func=lambda i: _labels[i],
            key="explainer_alert_sel"
        )
    with col_btn:
        st.write("")
        explain_clicked = st.button(
            "🧠 EXPLAIN", type="primary",
            use_container_width=True, key="explainer_btn"
        )

    alert = _all_alerts[selected_idx]

    # ── Alert raw data strip ──────────────────────────────────────────────────
    sev_color = {"critical": "#ff0033", "high": "#ff6600", "medium": "#f39c12", "low": "#00c878"}.get(
        alert.get("severity", "medium"), "#446688"
    )
    st.markdown(
        f"<div style='background:rgba(0,0,0,0.3);border:1px solid {sev_color}33;"
        f"border-left:3px solid {sev_color};border-radius:0 8px 8px 0;"
        f"padding:8px 14px;margin-bottom:8px;display:flex;gap:20px;align-items:center;flex-wrap:wrap'>"
        f"<span style='color:{sev_color};font-size:.68rem;font-weight:700'>"
        f"{alert.get('severity','?').upper()}</span>"
        f"<span style='color:#c8e8ff;font-size:.72rem'>{alert.get('alert_type', alert.get('type','?'))}</span>"
        f"<span style='color:#446688;font-size:.65rem;font-family:monospace'>"
        f"MITRE: {alert.get('mitre','—')}</span>"
        f"<span style='color:#446688;font-size:.65rem;font-family:monospace'>"
        f"Score: {alert.get('threat_score', alert.get('score','—'))}</span>"
        f"<span style='color:#446688;font-size:.65rem;font-family:monospace'>"
        f"IOC: {alert.get('domain', alert.get('ip','—'))}</span>"
        f"<span style='color:#336677;font-size:.62rem'>{alert.get('timestamp','')}</span>"
        f"</div>",
        unsafe_allow_html=True
    )

    if explain_clicked or st.session_state.get("_explainer_last") == selected_idx:
        st.session_state["_explainer_last"] = selected_idx

        mitre_key = alert.get("mitre", "").split(",")[0].strip()
        demo_exp  = _EXPLAINER_DEMO.get(mitre_key, _EXPLAINER_DEMO["DEFAULT"])

        # ── If LLM available, generate live explanation ───────────────────────
        if has_llm:
            _sys = (
                "You are a senior SOC analyst explaining an alert to a junior analyst. "
                "Be direct, clear, and use plain English — no jargon without explanation. "
                "Structure your response in exactly these sections:\n"
                "VERDICT: (one line — is this real or FP?)\n"
                "PLAIN ENGLISH: (2-3 sentences — what actually happened, explained simply)\n"
                "IS IT REAL?: (one line with confidence %)\n"
                "WHAT HAPPENED: (one sentence attack chain)\n"
                "URGENCY: (one line — how fast must analyst act)\n"
                "ACTIONS: (numbered list — exactly 5 specific steps)\n"
                "Be specific to the exact alert details provided."
            )
            _prompt = (
                f"Explain this security alert in plain English:\n\n"
                f"Alert Type: {alert.get('alert_type', alert.get('type','?'))}\n"
                f"MITRE Technique: {alert.get('mitre','?')}\n"
                f"Severity: {alert.get('severity','?')}\n"
                f"Threat Score: {alert.get('threat_score', alert.get('score','?'))}/100\n"
                f"IOC: {alert.get('domain','?')} / {alert.get('ip','?')}\n"
                f"Detail: {alert.get('detail', alert.get('event','No detail'))}\n"
                f"Source: {alert.get('source','?')}\n\n"
                f"Is this real or a false positive? What should I do in the next 5 minutes?"
            )
            with st.spinner("🧠 AI analyst reviewing alert…"):
                resp = _call_llm(_prompt, _sys, groq_key, anthropic_key)

            if resp.get("ok"):
                # Parse structured response
                st.markdown(
                    f"<div style='background:rgba(0,0,0,0.35);border:1.5px solid "
                    f"{sev_color}55;border-radius:12px;padding:16px 20px;margin:8px 0'>"
                    f"<div style='color:{sev_color};font-family:Orbitron,monospace;"
                    f"font-size:.7rem;font-weight:900;letter-spacing:2px;margin-bottom:10px'>"
                    f"🧠 AI ANALYST EXPLANATION — {alert.get('alert_type','?')[:40].upper()}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )
                st.markdown(resp["text"])
                st.caption(f"Powered by {resp.get('model','AI')} · {datetime.now().strftime('%H:%M:%S')}")
                st.divider()

        # ── Always show structured demo panel (LLM supplements, not replaces) ──
        vc = demo_exp["verdict_color"]
        st.markdown(
            f"<div style='background:rgba(0,0,0,0.4);border:2px solid {vc}44;"
            f"border-radius:14px;padding:16px 20px;margin:8px 0'>"

            # Verdict banner
            f"<div style='background:{vc}15;border:1px solid {vc}55;border-radius:8px;"
            f"padding:10px 16px;margin-bottom:14px;text-align:center'>"
            f"<div style='color:{vc};font-family:Orbitron,monospace;font-size:.85rem;"
            f"font-weight:900;letter-spacing:2px'>{demo_exp['verdict']}</div>"
            f"<div style='color:#556677;font-size:.62rem;margin-top:3px'>"
            f"False Positive Chance: {demo_exp['false_positive_chance']}</div>"
            f"</div>"

            # Plain English block
            f"<div style='margin-bottom:12px'>"
            f"<div style='color:#00f9ff;font-size:.65rem;font-weight:700;"
            f"letter-spacing:1px;margin-bottom:4px'>💬 PLAIN ENGLISH — WHAT IS THIS?</div>"
            f"<div style='color:#c8e8ff;font-size:.78rem;line-height:1.6'>{demo_exp['plain_english']}</div>"
            f"</div>"

            # Is it real
            f"<div style='display:flex;gap:16px;margin-bottom:12px;flex-wrap:wrap'>"
            f"<div style='flex:1;min-width:200px'>"
            f"<div style='color:#00f9ff;font-size:.65rem;font-weight:700;letter-spacing:1px;margin-bottom:4px'>"
            f"🎯 IS IT REAL?</div>"
            f"<div style='color:#a0c8e8;font-size:.73rem;line-height:1.5'>{demo_exp['is_it_real']}</div>"
            f"</div>"
            f"<div style='flex:1;min-width:200px'>"
            f"<div style='color:#00f9ff;font-size:.65rem;font-weight:700;letter-spacing:1px;margin-bottom:4px'>"
            f"⛓ WHAT HAPPENED?</div>"
            f"<div style='color:#a0c8e8;font-size:.73rem;line-height:1.5;font-family:monospace'>"
            f"{demo_exp['what_happened']}</div>"
            f"</div>"
            f"</div>"

            # Urgency
            f"<div style='background:rgba(0,0,0,0.3);border:1px solid {vc}33;border-radius:8px;"
            f"padding:8px 14px;margin-bottom:12px'>"
            f"<div style='color:{vc};font-size:.75rem;font-weight:700'>{demo_exp['urgency']}</div>"
            f"</div>"

            f"</div>",
            unsafe_allow_html=True
        )

        # Actions list
        st.markdown(
            "<div style='color:#00f9ff;font-size:.65rem;font-weight:700;"
            "letter-spacing:1px;margin:10px 0 6px'>⚡ EXACT STEPS — DO THESE IN ORDER:</div>",
            unsafe_allow_html=True
        )
        for i, action in enumerate(demo_exp["actions"]):
            _ac = "#ff0033" if i == 0 else "#ff9900" if i == 1 else "#c8e8ff"
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:12px;"
                f"padding:7px 10px;background:rgba(0,0,0,0.2);"
                f"border-left:2px solid {_ac}55;margin:2px 0;border-radius:0 6px 6px 0'>"
                f"<span style='color:{_ac};font-weight:900;font-size:.78rem;"
                f"font-family:monospace;min-width:20px'>{i+1}</span>"
                f"<span style='color:#c8e8ff;font-size:.73rem'>{action}</span>"
                f"</div>",
                unsafe_allow_html=True
            )

        # Quick action buttons
        st.markdown("<div style='margin-top:12px'>", unsafe_allow_html=True)
        qb1, qb2, qb3, qb4 = st.columns(4)
        if qb1.button("🤖 Autonomous Investigate", key="exp_auto_inv", use_container_width=True):
            st.session_state.mode = "Autonomous Investigator"
            st.rerun()
        if qb2.button("🚫 Block IOC", key="exp_block", use_container_width=True):
            ioc = alert.get("ip") or alert.get("domain", "")
            if ioc:
                st.session_state.setdefault("global_blocklist", []).append(ioc)
                st.success(f"✅ Blocked {ioc}")
        if qb3.button("📋 Create IR Case", key="exp_ir", use_container_width=True):
            st.session_state.mode = "Incident Response"
            st.rerun()
        if qb4.button("🔗 Correlate Alerts", key="exp_corr", use_container_width=True):
            st.session_state.mode = "Attack Correlation"
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: BULK ALERT PROCESSOR
# SOC pain: 400 alerts in queue, analyst doesn't know where to start.
# Manual priority ranking: 2-3 hours. This does it in under 2 minutes.
# AI scores + groups + ranks every alert by: severity, MITRE, IOC reputation,
# correlation, analyst load — outputs an ordered work queue.
# ══════════════════════════════════════════════════════════════════════════════

_BULK_PRIORITY_WEIGHTS = {
    # Severity score
    "critical": 40, "high": 25, "medium": 10, "low": 2,
    # MITRE tactic urgency bonus
    "Impact": 30, "Exfiltration": 28, "Command & Control": 20,
    "Credential Access": 18, "Lateral Movement": 16,
    "Execution": 12, "Initial Access": 10,
    "Persistence": 8, "Defense Evasion": 6,
    "Discovery": 4, "Reconnaissance": 2,
    # Threat score bonus (0-100 → 0-20)
}

_BULK_GROUP_RULES = [
    # (group_name, color, matching_mitre_prefixes)
    ("🔴 CRITICAL — Act Now",    "#ff0033", ["T1486","T1041","T1003","T1059.001"]),
    ("🟠 C2 & Exfiltration",     "#ff6600", ["T1071","T1102","T1041","T1048","T1572"]),
    ("🟡 Credential & Access",   "#ff9900", ["T1110","T1078","T1556","T1566"]),
    ("🔵 Recon & Lateral Move",  "#00aaff", ["T1046","T1018","T1021","T1595"]),
    ("🟢 Review & Close",        "#00c878", ["T1592","T1590","T1498"]),
    ("⚪ Low Priority Queue",    "#446688", []),
]


def _bulk_score_alert(alert: dict) -> int:
    score = 0
    sev   = alert.get("severity", "low")
    score += _BULK_PRIORITY_WEIGHTS.get(sev, 2)

    mitre = alert.get("mitre", "").split(",")[0].strip()
    tactic = _MITRE_FULL_DB.get(mitre, {}).get("tactic", "")
    score += _BULK_PRIORITY_WEIGHTS.get(tactic, 0)

    ts = int(alert.get("threat_score", alert.get("score", 0)))
    score += round(ts / 5)  # 0-20 bonus

    # FP penalty
    ioc = alert.get("ip") or alert.get("domain", "")
    _ioc_type = ("ip" if __import__("re").match(r"\d+\.\d+\.\d+\.\d+", str(ioc))
                  else "hash" if len(str(ioc)) in (32,40,64)
                  else "domain")
    if ioc and _safe_is_fp(ioc, _ioc_type):
        score = max(0, score - 30)

    return min(score, 100)


def _bulk_assign_group(alert: dict) -> tuple:
    mitre = alert.get("mitre", "").split(",")[0].strip()
    for gname, gcolor, gprefixes in _BULK_GROUP_RULES:
        for prefix in gprefixes:
            if mitre.startswith(prefix):
                return gname, gcolor
    sev = alert.get("severity", "low")
    if sev == "critical":
        return _BULK_GROUP_RULES[0][0], _BULK_GROUP_RULES[0][1]
    if sev == "high":
        return _BULK_GROUP_RULES[1][0], _BULK_GROUP_RULES[1][1]
    return _BULK_GROUP_RULES[-1][0], _BULK_GROUP_RULES[-1][1]


def render_bulk_alert_processor():
    """
    BULK ALERT PROCESSOR
    Solves: analyst staring at 400 alerts, no idea where to start.
    2-3 hours of manual triage → under 2 minutes.
    AI scores, groups, and produces a prioritised work queue.
    """
    st.markdown(
        "<h2 style='margin:0 0 2px'>⚡ Bulk Alert Processor</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 14px'>"
        "Load 400 alerts → AI scores + groups + ranks every one → "
        "ordered work queue in under 2 minutes · "
        "<b style='color:#00f9ff'>2-3 hours → 2 minutes</b>"
        "</p>",
        unsafe_allow_html=True
    )

    import random as _brnd
    _brnd.seed(42)

    # ── Simulate large alert batch if none loaded ─────────────────────────────
    _BULK_DEMO_TYPES = [
        ("PowerShell Encoded Command", "T1059.001", "critical", 94),
        ("C2 Beaconing",               "T1071",     "high",     87),
        ("Data Exfiltration",          "T1041",     "critical", 96),
        ("SSH Brute Force",            "T1110",     "high",     78),
        ("Port Scan",                  "T1046",     "medium",   45),
        ("Phishing Email",             "T1566",     "high",     72),
        ("LSASS Access",               "T1003.001", "critical", 91),
        ("DNS Tunneling",              "T1071.004", "high",     83),
        ("SMB Lateral Move",           "T1021.002", "high",     80),
        ("Dead-Drop C2",               "T1102",     "high",     85),
        ("Low Risk Scan",              "T1592",     "low",      22),
        ("SSL Certificate Mismatch",   "T1557",     "medium",   58),
        ("Registry Persistence",       "T1547.001", "medium",   61),
        ("Suspicious DNS Query",       "T1071.004", "medium",   49),
        ("Failed Auth",                "T1110",     "low",      31),
    ]

    if st.button("📥 Load 400-Alert Batch (Demo)", key="bulk_load_demo", use_container_width=False):
        _batch = []
        for i in range(400):
            _t = _BULK_DEMO_TYPES[i % len(_BULK_DEMO_TYPES)]
            _batch.append({
                "id":           f"ALT-{i+1:04d}",
                "alert_type":   _t[0],
                "mitre":        _t[1],
                "severity":     _t[2],
                "threat_score": min(100, _t[3] + _brnd.randint(-8, 8)),
                "ip":           f"185.{_brnd.randint(1,250)}.{_brnd.randint(1,250)}.{_brnd.randint(1,250)}",
                "domain":       f"host-{i+1:04d}.internal",
                "timestamp":    f"{_brnd.randint(8,17):02d}:{_brnd.randint(0,59):02d}:{_brnd.randint(0,59):02d}",
                "source":       _brnd.choice(["Splunk", "Zeek", "Sysmon", "EDR"]),
            })
        st.session_state["bulk_batch"] = _batch
        st.rerun()

    # Use existing triage alerts or bulk batch
    _batch = (
        st.session_state.get("bulk_batch") or
        st.session_state.get("triage_alerts") or
        st.session_state.get("analysis_results") or
        []
    )

    if not _batch:
        st.info("Click **Load 400-Alert Batch** above, or load alerts from Domain Analysis / Live Capture first.")
        return

    # ── Process batch ─────────────────────────────────────────────────────────
    if st.button(f"⚡ PROCESS ALL {len(_batch)} ALERTS NOW",
                 type="primary", use_container_width=True, key="bulk_run"):
        with st.spinner(f"AI scoring {len(_batch)} alerts…"):
            import time as _t
            _t.sleep(0.8)  # realistic pause
        st.session_state["bulk_processed"] = True
        st.rerun()

    if not st.session_state.get("bulk_processed") and len(_batch) > 5:
        st.info(f"**{len(_batch)} alerts loaded.** Click PROCESS to rank and group them.")
        return

    # Score all alerts
    for a in _batch:
        a["_priority_score"] = _bulk_score_alert(a)
        a["_group"], a["_group_color"] = _bulk_assign_group(a)

    _sorted = sorted(_batch, key=lambda x: x["_priority_score"], reverse=True)

    # ── Summary metrics ───────────────────────────────────────────────────────
    _crits   = sum(1 for a in _batch if a.get("severity") == "critical")
    _highs   = sum(1 for a in _batch if a.get("severity") == "high")
    _p90_cut = _sorted[max(0, len(_sorted)//10)]["_priority_score"]
    _act_now = [a for a in _sorted if a["_priority_score"] >= _p90_cut][:20]
    _auto_close_candidates = [a for a in _sorted if a["_priority_score"] <= 8]

    st.markdown(
        f"<div style='background:rgba(0,0,0,0.3);border:1px solid #00f9ff22;"
        f"border-radius:12px;padding:14px 20px;margin:10px 0'>"
        f"<div style='color:#00f9ff;font-size:.65rem;font-weight:700;"
        f"letter-spacing:2px;margin-bottom:10px'>📊 BATCH PROCESSING COMPLETE — {len(_batch)} ALERTS</div>"
        f"<div style='display:flex;gap:24px;flex-wrap:wrap'>"
        f"<div style='text-align:center'><div style='color:#ff0033;font-size:1.6rem;font-weight:900'>{_crits}</div>"
        f"<div style='color:#446688;font-size:.6rem'>CRITICAL</div></div>"
        f"<div style='text-align:center'><div style='color:#ff9900;font-size:1.6rem;font-weight:900'>{_highs}</div>"
        f"<div style='color:#446688;font-size:.6rem'>HIGH</div></div>"
        f"<div style='text-align:center'><div style='color:#ff0033;font-size:1.6rem;font-weight:900'>{len(_act_now)}</div>"
        f"<div style='color:#446688;font-size:.6rem'>ACT NOW</div></div>"
        f"<div style='text-align:center'><div style='color:#00c878;font-size:1.6rem;font-weight:900'>{len(_auto_close_candidates)}</div>"
        f"<div style='color:#446688;font-size:.6rem'>AUTO-CLOSE</div></div>"
        f"<div style='text-align:center'><div style='color:#c300ff;font-size:1.6rem;font-weight:900'>"
        f"{round(len(_auto_close_candidates)/max(len(_batch),1)*100)}%</div>"
        f"<div style='color:#446688;font-size:.6rem'>NOISE REDUCED</div></div>"
        f"</div></div>",
        unsafe_allow_html=True
    )

    # ── Tabs: Priority Queue | Groups | Auto-Close ────────────────────────────
    tab_q, tab_grp, tab_auto = st.tabs([
        f"🔴 Priority Work Queue ({len(_act_now)})",
        "🧩 Alert Groups",
        f"✅ Auto-Close Candidates ({len(_auto_close_candidates)})",
    ])

    with tab_q:
        st.markdown(
            "<div style='color:#c8e8ff;font-size:.65rem;font-weight:700;"
            "letter-spacing:1.5px;margin-bottom:8px'>"
            "⚡ THESE ARE YOUR TOP PRIORITY ALERTS — work through them in this order:</div>",
            unsafe_allow_html=True
        )
        for rank, alert in enumerate(_act_now, 1):
            _sc  = alert["_priority_score"]
            _sc_c = "#ff0033" if _sc >= 75 else "#ff9900" if _sc >= 50 else "#ffcc00"
            _sev_c = {"critical": "#ff0033", "high": "#ff6600",
                      "medium": "#f39c12", "low": "#00c878"}.get(alert.get("severity","low"), "#446688")
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:10px;"
                f"background:rgba(0,0,0,0.25);border:1px solid {_sc_c}22;"
                f"border-left:3px solid {_sc_c};border-radius:0 8px 8px 0;"
                f"padding:7px 12px;margin:2px 0'>"
                f"<span style='color:{_sc_c};font-weight:900;font-family:monospace;"
                f"font-size:.75rem;min-width:24px'>#{rank}</span>"
                f"<span style='background:{_sev_c}22;border:1px solid {_sev_c}44;"
                f"border-radius:4px;padding:1px 6px;font-size:.6rem;color:{_sev_c};"
                f"font-weight:700;min-width:56px;text-align:center'>"
                f"{alert.get('severity','?').upper()}</span>"
                f"<span style='color:#c8e8ff;font-size:.72rem;flex:1'>"
                f"{alert.get('alert_type','?')[:40]}</span>"
                f"<span style='color:#446688;font-size:.62rem;font-family:monospace'>"
                f"{alert.get('mitre','—')}</span>"
                f"<span style='color:{_sc_c};font-weight:700;font-size:.72rem;"
                f"font-family:monospace;min-width:36px;text-align:right'>{_sc}</span>"
                f"</div>",
                unsafe_allow_html=True
            )

    with tab_grp:
        st.markdown(
            "<div style='color:#c8e8ff;font-size:.65rem;font-weight:700;"
            "letter-spacing:1.5px;margin-bottom:8px'>🧩 ALERTS GROUPED BY ATTACK TYPE:</div>",
            unsafe_allow_html=True
        )
        from collections import Counter
        _group_counts = Counter(a["_group"] for a in _sorted)
        for gname, gcolor, _ in _BULK_GROUP_RULES:
            cnt = _group_counts.get(gname, 0)
            if cnt == 0:
                continue
            grp_alerts = [a for a in _sorted if a["_group"] == gname]
            with st.expander(f"{gname}  —  {cnt} alerts", expanded=(gname == _BULK_GROUP_RULES[0][0])):
                for a in grp_alerts[:15]:
                    st.markdown(
                        f"<div style='font-size:.68rem;color:#c8e8ff;font-family:monospace;"
                        f"padding:2px 0;border-bottom:1px solid #0a1a2a'>"
                        f"<span style='color:{gcolor}'>{a.get('alert_type','?')[:30]}</span>"
                        f"  {a.get('mitre','—')}  ·  Score:{a['_priority_score']}  ·  "
                        f"{a.get('ip',a.get('domain','?'))}</div>",
                        unsafe_allow_html=True
                    )
                if cnt > 15:
                    st.caption(f"… and {cnt-15} more in this group")

    with tab_auto:
        st.markdown(
            "<div style='color:#00c878;font-size:.65rem;font-weight:700;"
            "letter-spacing:1.5px;margin-bottom:6px'>"
            f"✅ {len(_auto_close_candidates)} alerts are safe to auto-close (score ≤ 8 = confirmed low risk):</div>",
            unsafe_allow_html=True
        )
        if st.button(f"✅ Auto-Close All {len(_auto_close_candidates)} Low-Risk Alerts",
                     type="primary", key="bulk_autoclose", use_container_width=True):
            import datetime as _bdt
            for a in _auto_close_candidates:
                a["status"] = "auto_closed"
            _time_saved = len(_auto_close_candidates) * 3
            # ── Record run in history ────────────────────────────────────────
            st.session_state.setdefault("bulk_run_history", []).insert(0, {
                "timestamp":     _bdt.datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
                "batch_size":    len(_batch),
                "auto_closed":   len(_auto_close_candidates),
                "escalated":     len([a for a in _sorted if a["_priority_score"] >= 75]),
                "ac_pct":        round(len(_auto_close_candidates)/max(len(_batch),1)*100, 1),
                "time_saved_min":_time_saved,
            })
            st.session_state["bulk_run_history"] = st.session_state["bulk_run_history"][:50]
            # ── Update global metrics ────────────────────────────────────────
            st.session_state["alerts_processed"] =                 st.session_state.get("alerts_processed", 0) + len(_batch)
            st.session_state["alerts_auto_closed"] =                 st.session_state.get("alerts_auto_closed", 0) + len(_auto_close_candidates)
            st.success(
                f"✅ **{len(_auto_close_candidates)} low-risk alerts closed** — "
                f"analyst queue reduced by {round(len(_auto_close_candidates)/len(_batch)*100)}% · "
                f"**~{_time_saved} minutes saved**"
            )
            # ── Closed-loop: flag patterns seen 5+ times ─────────────────────
            from collections import Counter as _Ctr
            _fp_types = Counter(_Ctr(a.get("alert_type","?") for a in _auto_close_candidates))
            # _fp_types is now a Counter of alert_type → count
            _fp_counts = _Ctr(a.get("alert_type","?") for a in _auto_close_candidates)
            _sugg = [t for t, c in _fp_counts.items() if c >= 5]
            if _sugg:
                st.session_state.setdefault("auto_suppress_suggestions", [])
                _existing = [s.get("pattern") for s in st.session_state.auto_suppress_suggestions]
                for _t in _sugg:
                    if _t not in _existing:
                        st.session_state.auto_suppress_suggestions.append({
                            "pattern": _t, "count": _fp_counts[_t],
                            "suggested_at": _bdt.datetime.utcnow().strftime("%H:%M"),
                            "status": "pending",
                        })
                st.info(f"🤖 **Closed-loop:** {len(_sugg)} alert type(s) appeared 5+ times — "
                        f"check the Run History tab for suppression suggestions.")
        for a in _auto_close_candidates[:20]:
            st.markdown(
                f"<div style='font-size:.67rem;color:#446688;font-family:monospace;padding:2px 0'>"
                f"✅ {a.get('alert_type','?')[:35]}  ·  {a.get('mitre','—')}  ·  Score:{a['_priority_score']}</div>",
                unsafe_allow_html=True
            )

    # ── NEW TAB: Run History + Suppression Suggestions ────────────────────────
    history_data = st.session_state.get("bulk_run_history", [])
    sugg_data    = [s for s in st.session_state.get("auto_suppress_suggestions", [])
                    if s.get("status") == "pending"]

    with st.expander(
        f"📊 Run History ({len(history_data)} runs) · "
        f"🤖 Suppression Suggestions ({len(sugg_data)})",
        expanded=bool(sugg_data),
    ):
        if history_data:
            import pandas as _hpd
            _hdf = _hpd.DataFrame(history_data)
            _hdf.columns = [c.replace("_"," ").title() for c in _hdf.columns]
            st.dataframe(_hdf, use_container_width=True, hide_index=True)

            # ── Aggregate metrics ─────────────────────────────────────────────
            _total_processed = sum(r.get("batch_size",0) for r in history_data)
            _total_closed    = sum(r.get("auto_closed",0) for r in history_data)
            _total_saved     = sum(r.get("time_saved_min",0) for r in history_data)
            _avg_ac_pct      = round(_total_closed / max(_total_processed,1) * 100, 1)
            m1, m2, m3, m4  = st.columns(4)
            m1.metric("Total Processed",    f"{_total_processed:,}")
            m2.metric("Total Auto-Closed",  f"{_total_closed:,}")
            m3.metric("Avg Auto-Close %",   f"{_avg_ac_pct}%")
            m4.metric("Total Time Saved",   f"~{_total_saved} min")
        else:
            st.info("Run the processor and auto-close alerts to build run history.")

        if sugg_data:
            st.markdown("#### 🤖 Closed-Loop: Suppression Suggestions")
            st.caption("These alert types appeared 5+ times as auto-closed. "
                       "Approve to add as permanent suppression rules.")
            import datetime as _sdt
            for _si, _s in enumerate(sugg_data):
                _sa, _sb, _sc2 = st.columns([5, 1, 1])
                _sa.markdown(
                    f"**{_s['pattern']}** — seen {_s['count']}× "
                    f"(since {_s.get('suggested_at','?')})"
                )
                if _sb.button("✅ Suppress", key=f"bulk_supp_{_si}",
                              use_container_width=True, type="primary"):
                    _s["status"] = "approved"
                    _ATP_FP_PATTERNS.append({
                        "id":             f"BULK-LEARNED-{len(_ATP_FP_PATTERNS)+1:03d}",
                        "name":           f"Auto-learned: {_s['pattern'][:35]}",
                        "condition":      f"alert_type contains '{_s['pattern'][:30]}'",
                        "action":         "AUTO_CLOSE",
                        "confidence":     80,
                        "keywords":       _s["pattern"].split()[:4],
                        "count":          _s["count"],
                        "last_triggered": _sdt.datetime.utcnow().strftime("%H:%M:%S"),
                    })
                    st.success(f"✅ Suppression rule added for '{_s['pattern'][:35]}'")
                    st.rerun()
                if _sc2.button("❌ Ignore", key=f"bulk_ign_{_si}",
                               use_container_width=True):
                    _s["status"] = "ignored"
                    st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: REAL-TIME SLA BREACH WARNING BAR
# SOC pain: queue blows past SLA, you find out AFTER it happened.
# This shows: queue will breach in N minutes → call backup NOW.
# Persistent bar shown across all modes when breach is imminent.
# ══════════════════════════════════════════════════════════════════════════════

def render_sla_breach_warning():
    """
    Persistent SLA Breach Warning Bar.
    Shows at top of every page when queue depth + arrival rate will breach SLA.
    Call this from main() before mode routing.
    Eliminates the #1 shift management failure: discovering SLA breach after it happens.
    """
    import math as _math

    _queue = st.session_state.get("triage_alerts", [])
    _arrival_rate  = st.session_state.get("sla_arrival_rate", 0)
    _analysts      = st.session_state.get("sla_analysts_active", 1)
    _queue_len     = len(_queue)
    _SLA_LIMIT     = 30     # queue > 30 alerts = SLA breach
    _THROUGHPUT    = 6.5    # alerts/min per analyst
    _throughput    = _THROUGHPUT * max(_analysts, 1)
    _net_rate      = _arrival_rate - _throughput
    _breach_eta    = None

    if _queue_len > _SLA_LIMIT:
        _breach_eta = 0  # already breached
    elif _net_rate > 0 and _arrival_rate > 0:
        _breach_eta = (_SLA_LIMIT - _queue_len) / _net_rate
    elif _queue_len >= _SLA_LIMIT * 0.8:
        _breach_eta = 15  # approaching limit

    if _breach_eta is None:
        return  # No warning needed

    if _breach_eta == 0:
        _bar_color  = "#ff0033"
        _bar_bg     = "rgba(255,0,51,0.12)"
        _msg        = "🚨 SLA BREACH ACTIVE — Queue depth exceeded. Escalate immediately."
        _eta_text   = "NOW"
    elif _breach_eta < 10:
        _bar_color  = "#ff0033"
        _bar_bg     = "rgba(255,0,51,0.08)"
        _msg        = f"⚠️ SLA BREACH IN {int(_breach_eta)} MINUTES — Call backup analyst now."
        _eta_text   = f"{int(_breach_eta)}min"
    elif _breach_eta < 20:
        _bar_color  = "#ff9900"
        _bar_bg     = "rgba(255,153,0,0.08)"
        _msg        = f"⚠️ SLA BREACH IN {int(_breach_eta)} MINUTES — Monitor queue closely."
        _eta_text   = f"{int(_breach_eta)}min"
    else:
        _bar_color  = "#ffcc00"
        _bar_bg     = "rgba(255,204,0,0.05)"
        _msg        = f"⏱ Queue approaching SLA limit — breach projected in {int(_breach_eta)} min."
        _eta_text   = f"~{int(_breach_eta)}min"

    _open_crits  = sum(1 for a in _queue if a.get("severity") == "critical")
    _open_highs  = sum(1 for a in _queue if a.get("severity") == "high")

    st.markdown(
        f"<div style='background:{_bar_bg};border:1.5px solid {_bar_color}55;"
        f"border-left:4px solid {_bar_color};border-radius:0 10px 10px 0;"
        f"padding:10px 18px;margin:0 0 8px;display:flex;"
        f"justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px'>"
        f"<div>"
        f"<div style='color:{_bar_color};font-size:.72rem;font-weight:700'>{_msg}</div>"
        f"<div style='color:#446688;font-size:.62rem;margin-top:2px'>"
        f"Queue: <b style='color:#c8e8ff'>{_queue_len}</b> alerts  ·  "
        f"Critical: <b style='color:#ff0033'>{_open_crits}</b>  ·  "
        f"High: <b style='color:#ff9900'>{_open_highs}</b>  ·  "
        f"Analysts online: <b style='color:#00c878'>{_analysts}</b>  ·  "
        f"Arrival: <b style='color:#c8e8ff'>{_arrival_rate:.1f} alerts/min</b>"
        f"</div>"
        f"</div>"
        f"<div style='display:flex;gap:10px;align-items:center'>"
        f"<div style='text-align:center'>"
        f"<div style='color:{_bar_color};font-family:Orbitron,monospace;"
        f"font-size:1.1rem;font-weight:900'>{_eta_text}</div>"
        f"<div style='color:#446688;font-size:.55rem'>TO BREACH</div>"
        f"</div>"
        f"</div>"
        f"</div>",
        unsafe_allow_html=True
    )


# ══════════════════════════════════════════════════════════════════════════════
# ALERT TRIAGE CENTER
# ══════════════════════════════════════════════════════════════════════════════
def render_alert_triage():
    if not THREAT_INTEL_ENABLED:
        st.error("threat_intel.py not found. Place it in project root.")
        return

    st.header("Alert Triage Center")
    st.caption("Live alert queue from Splunk · Enrich · Classify · Escalate · False-positive tune")

    # ── Controls bar ─────────────────────────────────────────────────────────
    col_time, col_sev, col_ref = st.columns([2,2,1])
    with col_time:
        time_range = st.selectbox("Time Range", ["-1h","-4h","-24h","-7d"], index=2, key="triage_time")
    with col_sev:
        sev_filter = st.multiselect("Severity", ["critical","high","medium","low"],
                                     default=["critical","high"], key="triage_sev")
    with col_ref:
        st.write("")
        st.write("")
        refresh = st.button("🔄 Refresh", use_container_width=True)

    if refresh or not st.session_state.get("triage_alerts"):
        with st.spinner("Querying Splunk…"):
            sev_str = " OR ".join([f'severity="{s}"' for s in sev_filter]) if sev_filter else "severity=*"
            spl = f'index=ids_alerts earliest={time_range} ({sev_str}) | sort -_time | head 50'
            result = query_splunk_alerts(spl, max_results=50, earliest=time_range)
            if result.get("error"):
                st.warning(f"Splunk not reachable: {result['error']}  \n\n**Demo mode** — loading sample alerts")
                # Demo alerts when Splunk not connected
                from datetime import datetime as _dt
                import random
                demo = []
                domains = ["suspicious-domain.tk","malware-c2.ml","legit-corp.com",
                           "phishing-site.ga","update-server.net","normal-site.com"]
                preds   = ["Malware","SQLi","XSS","Suspicious","Port Scan","Low Risk"]
                sevs    = ["critical","critical","high","high","medium","low"]
                for i, (d,p,s) in enumerate(zip(domains,preds,sevs)):
                    demo.append({"domain":d,"alert_type":p,"severity":s,
                                 "threat_score":str(random.randint(20,95)),
                                 "ip_address":f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                                 "mitre_technique":f"T{1000+i*50}",
                                 "_time":_dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                                 "status":"open","id":f"DEMO-{i+1:04d}"})
                st.session_state.triage_alerts = demo
            else:
                events = result.get("events", [])
                for e in events:
                    e.setdefault("status","open")
                    e.setdefault("id", e.get("_cd","") or f"ALT-{hash(str(e))%10000:04d}")
                st.session_state.triage_alerts = events

    alerts = st.session_state.get("triage_alerts", [])
    if not alerts:
        st.info("No alerts found in Splunk for the selected time range.")
        return

    # ── Summary metrics ───────────────────────────────────────────────────────
    total = len(alerts)
    crits = sum(1 for a in alerts if a.get("severity") == "critical")
    highs = sum(1 for a in alerts if a.get("severity") == "high")
    fps   = sum(1 for a in alerts if a.get("status") == "false_positive")
    m1,m2,m3,m4,m5 = st.columns(5)
    m1.metric("Total Alerts",   total)
    m2.metric("Critical",       crits)
    m3.metric("High",           highs)
    m4.metric("False Positives",fps)
    m5.metric("Open",           sum(1 for a in alerts if a.get("status")=="open"))
    st.divider()

    # ── Alert cards ───────────────────────────────────────────────────────────
    st.markdown("#### 🚨 Alert Queue")
    for i, alert in enumerate(alerts):
        sev   = alert.get("severity","medium")
        score = alert.get("threat_score", alert.get("score","?"))
        dom   = alert.get("domain","unknown")
        ip    = alert.get("ip_address", alert.get("ip","unknown"))
        pred  = _generate_alert_name(alert)
        mitre = alert.get("mitre_technique","")
        ts    = alert.get("_time","")
        aid   = alert.get("id",f"ALT-{i:04d}")
        status = alert.get("status","open")
        is_fp  = is_false_positive(dom,"domain") or is_false_positive(ip,"ip")

        sev_icon = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(sev,"⚪")
        status_badge = "✅ FP" if status=="false_positive" else "🔒 Escalated" if status=="escalated" else "🔓 Open"

        with st.container(border=True):
            col_info, col_actions = st.columns([3,2])

            with col_info:
                st.write(f"**IP:** {ip}  |  **MITRE:** {mitre}  |  **Time:** {ts}")
                if is_fp:
                    st.warning("⚠️ This IOC is in your False Positive store")

                # Quick enrich button
                if st.button(f"🔍 Enrich IOC ({ip})", key=f"enrich_{aid}"):
                    with st.spinner("Running threat intel lookup…"):
                        result = unified_ioc_lookup(ip, "ip")
                        st.session_state.ioc_results[ip] = result
                    r = st.session_state.ioc_results[ip]
                    risk_color = {"HIGH":"🔴","MEDIUM":"🟠","LOW":"🟢"}.get(r.get("risk",""),"⚪")
                    st.write(f"**Overall verdict:** {risk_color} {r.get('overall','').upper()} ({r.get('risk','')})")
                    for src_name, src_data in r.get("results",{}).items():
                        verdict = src_data.get("verdict","unknown")
                        vc = "🔴" if verdict=="malicious" else "🟡" if verdict=="suspicious" else "🟢"
                        st.write(f"  {vc} **{src_name}**: {verdict}"
                                 + (f" | Confidence: {src_data.get('confidence','')}%" if "confidence" in src_data else "")
                                 + (f" | Pulses: {src_data.get('pulse_count','')}" if "pulse_count" in src_data else ""))

                # Show cached result
                elif ip in st.session_state.get("ioc_results",{}):
                    r = st.session_state.ioc_results[ip]
                    st.info(f"Cached verdict: {r.get('overall','').upper()} | Risk: {r.get('risk','')}")

            with col_actions:
                c1,c2 = st.columns(2)
                with c1:
                    if st.button("✅ Mark Safe", key=f"safe_{aid}_{i}"):
                        alerts[i]["status"] = "false_positive"
                        mark_false_positive(dom,"domain","Marked safe from triage")
                        st.session_state.triage_alerts = alerts
                        st.success("Marked as false positive")
                with c2:
                    if st.button("🚨 Escalate", key=f"esc_{aid}_{i}"):
                        alerts[i]["status"] = "escalated"
                        st.session_state.triage_alerts = alerts
                        if N8N_ENABLED:
                            trigger_slack_notify(
                                f"🚨 Escalated: {pred} on {dom} | Score: {score}",
                                severity=sev)
                        st.error("Escalated + n8n notified")

                if st.button("🔒 Block IP", key=f"blk_{aid}_{i}"):
                    from enterprise import block_ip_windows
                    ok, msg = block_ip_windows(ip)
                    if ok:
                        st.success(msg)
                        if ip not in st.session_state.blocked_ips:
                            st.session_state.blocked_ips.append(ip)
                    else:
                        st.error(f"Block failed: {msg}")

    # ── False Positive Tuning panel ───────────────────────────────────────────
    st.divider()
    st.subheader("🎯 False Positive Tuning")
    fp_list = get_fp_list()
    recs    = get_tuning_recommendations()

    col_fps, col_recs = st.columns(2)
    with col_fps:
        st.markdown("**Stored False Positives**")
        all_fps = {**fp_list.get("ips",{}), **fp_list.get("domains",{}),
                   **fp_list.get("hashes",{})}
        if all_fps:
            for ioc, data in list(all_fps.items())[:15]:
                st.write(f"• `{ioc}` — _{data.get('reason','no reason')}_ "
                         f"(seen {data.get('count',1)}x)")
        else:
            st.info("No false positives recorded yet.")

    with col_recs:
        st.markdown("**Suppression Recommendations**")
        if recs:
            for rec in recs:
                st.warning(f"🔕 {rec['suggestion']}")
                st.write(f"  Reason: {rec.get('reason','')} | Count: {rec.get('count',0)}")
        else:
            st.info("No suppression rules recommended yet (need 3+ FP hits).")


# ══════════════════════════════════════════════════════════════════════════════
# IOC LOOKUP  —  all sources in one search
# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: IOC BLAST ENRICHMENT
# SOC pain: analyst gets an alert with 5 IOCs (2 IPs, 2 domains, 1 hash).
# They have to manually look up each one in AbuseIPDB, VirusTotal, GreyNoise,
# OTX — that's 5 IOCs × 4 sources = 20 lookups, 30-45 minutes.
# This does all of them in parallel in under 10 seconds.
# ══════════════════════════════════════════════════════════════════════════════

# Deterministic enrichment scores (no API keys needed — realistic demo data)
_BLAST_DEMO_DB = {
    # Known malicious IPs
    "185.220.101.45": {"abuse_confidence": 97, "reports": 1847, "country": "DE",
                       "org": "Tor Exit Node", "verdict": "MALICIOUS",
                       "greynoise": "Malicious", "otx_pulses": 23,
                       "tags": ["Tor", "C2", "Brute Force"], "threat_score": 98},
    "91.108.4.200":   {"abuse_confidence": 45, "reports": 12, "country": "RU",
                       "org": "Selectel LLC", "verdict": "SUSPICIOUS",
                       "greynoise": "Suspicious", "otx_pulses": 3,
                       "tags": ["Scanner"], "threat_score": 62},
    "94.102.49.8":    {"abuse_confidence": 89, "reports": 234, "country": "NL",
                       "org": "Bredbandsfiberf", "verdict": "MALICIOUS",
                       "greynoise": "Malicious", "otx_pulses": 11,
                       "tags": ["Brute Force", "SSH"], "threat_score": 91},
    # Known malicious domains
    "c2panel.tk":     {"vt_malicious": 52, "vt_total": 72, "age_days": 14,
                       "registrar": "Freenom", "verdict": "MALICIOUS",
                       "otx_pulses": 8, "tags": ["C2", "Phishing"], "threat_score": 95},
    "suspicious-domain.tk": {"vt_malicious": 31, "vt_total": 70, "age_days": 7,
                       "registrar": "Freenom", "verdict": "MALICIOUS",
                       "otx_pulses": 5, "tags": ["Malware", "DGA"], "threat_score": 87},
    "malware-c2.ml":  {"vt_malicious": 44, "vt_total": 72, "age_days": 3,
                       "registrar": "Freenom", "verdict": "MALICIOUS",
                       "otx_pulses": 12, "tags": ["C2", "RAT"], "threat_score": 96},
    "update-server.net": {"vt_malicious": 8, "vt_total": 72, "age_days": 180,
                       "registrar": "GoDaddy", "verdict": "SUSPICIOUS",
                       "otx_pulses": 2, "tags": ["Suspicious"], "threat_score": 45},
    # Hashes
    "5f4dcc3b5aa765d61d8327deb882cf99": {
        "name": "password", "type": "Not malware (MD5 of 'password')",
        "verdict": "CLEAN", "threat_score": 0},
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR Test File", "type": "Test signature",
        "verdict": "CLEAN", "threat_score": 5},
}

_BLAST_DEFAULT_CLEAN = {"verdict": "CLEAN", "threat_score": 5, "tags": [],
                         "otx_pulses": 0, "greynoise": "Not seen"}
_BLAST_DEFAULT_UNKNOWN = {"verdict": "UNKNOWN", "threat_score": 35, "tags": ["Not in database"],
                           "otx_pulses": 0, "greynoise": "Not seen"}


def _blast_enrich_ioc(ioc: str, ioc_type: str) -> dict:
    """Real enrichment using IOCEnricher — AbuseIPDB·VT·GreyNoise·OTX·URLhaus·IPinfo."""
    try:
        from modules.ioc_enricher import IOCEnricher as _IE
        result = _IE.enrich(ioc, ioc_type)
        if result:
            # Map to legacy format expected by the UI
            return {
                "ioc":          ioc,
                "type":         ioc_type,
                "verdict":      result.get("verdict","UNKNOWN").upper(),
                "threat_score": result.get("threat_score", 50),
                "tags":         [result.get("verdict","")],
                "country":      result.get("sources",{}).get("ipinfo",{}).get("country",""),
                "org":          result.get("sources",{}).get("ipinfo",{}).get("org",""),
                "abuse_confidence": result.get("sources",{}).get("abuseipdb",{}).get("confidence",0),
                "vt_malicious": result.get("sources",{}).get("virustotal",{}).get("malicious",0),
                "greynoise":    result.get("sources",{}).get("greynoise",{}).get("classification","Not seen"),
                "otx_pulses":   result.get("sources",{}).get("otx",{}).get("pulse_count",0),
                "unified_score":result.get("unified_score",50),
                "sources_used": result.get("sources_used",[]),
                "is_test_domain":result.get("is_test_domain",False),
                # Keep full result for detailed rendering
                "_full": result,
            }
    except Exception as _e:
        pass
    # Fallback to original demo logic
    return _blast_enrich_ioc_demo(ioc, ioc_type)


def _blast_enrich_ioc_demo(ioc: str, ioc_type: str) -> dict:
    """Fallback demo enrichment when API unavailable."""
    import re as _re
    ioc_lower = ioc.lower().strip()

    # Direct match
    if ioc_lower in _BLAST_DEMO_DB:
        result = dict(_BLAST_DEMO_DB[ioc_lower])
        result["ioc"]  = ioc
        result["type"] = ioc_type
        return result

    # Heuristic scoring for unknown IOCs
    score = 30
    tags  = []
    verdict = "UNKNOWN"

    if ioc_type == "ip":
        # Check if it's in known suspicious ranges (Tor exit nodes, bulletproof hosters)
        if any(ioc.startswith(pfx) for pfx in
               ["185.220","185.130","194.165","45.148","5.188","91.108"]):
            score, tags, verdict = 75, ["Known Suspicious Range"], "SUSPICIOUS"
        elif any(ioc.startswith(pfx) for pfx in
                 ["192.168","10.","172.16","127."]):
            score, tags, verdict = 5, ["Internal IP"], "CLEAN"
        else:
            score, tags, verdict = 35, ["No prior intelligence"], "UNKNOWN"

    elif ioc_type == "domain":
        # High-risk TLDs
        if _re.search(r'\.(tk|ml|ga|cf|gq|cc|top|xyz|bit)$', ioc_lower):
            score += 30
            tags.append("High-risk TLD")
            verdict = "SUSPICIOUS"
        # Short domain name = DGA indicator
        parts = ioc_lower.split(".")
        if len(parts[0]) > 12 and not parts[0].replace("-","").isalpha():
            score += 20
            tags.append("Possible DGA")
            verdict = "SUSPICIOUS"
        # Known C2 patterns
        if any(kw in ioc_lower for kw in ["c2","beacon","panel","gate","payload","update-srv","cdn-cache"]):
            score += 25
            tags.append("C2 naming pattern")
            verdict = "SUSPICIOUS"
        if score >= 60:
            verdict = "SUSPICIOUS"
        elif score < 30:
            verdict = "CLEAN"

    elif ioc_type == "hash":
        # Random hash = unknown
        score, tags, verdict = 40, ["Unknown hash"], "UNKNOWN"

    result = {
        "ioc":     ioc,
        "type":    ioc_type,
        "verdict": verdict,
        "threat_score": min(score, 99),
        "tags":    tags,
        "otx_pulses": 0,
        "greynoise": "Not seen" if verdict == "CLEAN" else "Suspicious" if verdict == "SUSPICIOUS" else "Not seen",
    }
    return result


def _extract_iocs_from_alerts(alerts: list) -> list:
    """Extract all unique IOCs from a list of alerts."""
    import re as _re
    seen  = set()
    iocs  = []

    ip_pat     = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pat = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:tk|ml|ga|cc|xyz|top|com|net|org|io|ru|cn|uk|de|fr)\b'
    hash_pat   = r'\b[0-9a-f]{32,64}\b'

    for a in alerts:
        # Direct fields
        for field in ["ip", "domain", "hash"]:
            val = str(a.get(field, "")).strip()
            if val and val not in seen and val != "—":
                t = "ip" if field == "ip" else "domain" if field == "domain" else "hash"
                # Validate
                if t == "ip" and _re.match(ip_pat, val):
                    seen.add(val); iocs.append((val, t))
                elif t == "domain" and "." in val and len(val) > 4:
                    seen.add(val); iocs.append((val, t))
                elif t == "hash" and len(val) in (32, 40, 64):
                    seen.add(val); iocs.append((val, t))

        # Extract from detail/event text
        detail = str(a.get("detail", a.get("event", "")))
        for ip in _re.findall(ip_pat, detail):
            if ip not in seen and not ip.startswith(("192.168","10.","127.","172.")):
                seen.add(ip); iocs.append((ip, "ip"))
        for dom in _re.findall(domain_pat, detail.lower()):
            if dom not in seen and len(dom) > 5:
                seen.add(dom); iocs.append((dom, "domain"))
        for h in _re.findall(hash_pat, detail.lower()):
            if h not in seen:
                seen.add(h); iocs.append((h, "hash"))

    return iocs[:30]  # cap at 30 IOCs per blast


"""
IOC Blast Enrichment — Updated Functions
Covers: extraction, scoring, enrichment, and Streamlit UI
"""

import re
import time
import hashlib
import streamlit as st
import pandas as pd
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS & CONFIG
# ─────────────────────────────────────────────────────────────────────────────

VERDICT_COLORS = {
    "CONFIRMED MALICIOUS": "#ff0033",
    "MALICIOUS":           "#ff0033",
    "SUSPICIOUS":          "#ff9900",
    "CLEAN":               "#00c878",
    "UNKNOWN":             "#ffcc00",
}

# Threat score thresholds
SCORE_MALICIOUS  = 75
SCORE_SUSPICIOUS = 40


# ─────────────────────────────────────────────────────────────────────────────
# IOC TYPE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

_RE_IPV4   = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_RE_HASH   = re.compile(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$')
_RE_URL    = re.compile(r'^https?://', re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def detect_ioc_type(value: str) -> str:
    """Return one of: ip, hash, url, domain, unknown."""
    v = value.strip()
    if _RE_IPV4.match(v):
        return "ip"
    if _RE_HASH.match(v):
        return "hash"
    if _RE_URL.match(v):
        return "url"
    if _RE_DOMAIN.match(v):
        return "domain"
    return "unknown"


def parse_manual_iocs(raw_text: str) -> list[tuple[str, str]]:
    """
    Parse a newline-delimited block of IOC values.
    Returns list of (value, type) tuples, skipping blanks and unknowns.
    """
    results = []
    for line in raw_text.strip().splitlines():
        v = line.strip()
        if not v:
            continue
        t = detect_ioc_type(v)
        if t != "unknown":
            results.append((v, t))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# IOC EXTRACTION FROM ALERT OBJECTS
# ─────────────────────────────────────────────────────────────────────────────

_ALERT_IP_FIELDS     = ("ip", "src_ip", "dest_ip", "source_ip", "destination_ip",
                         "remote_ip", "peer_ip", "client_ip", "server_ip")
_ALERT_DOMAIN_FIELDS = ("domain", "hostname", "fqdn", "dns_query", "host",
                         "dest_domain", "src_domain")
_ALERT_HASH_FIELDS   = ("hash", "md5", "sha1", "sha256", "file_hash",
                         "process_hash", "parent_hash")
_ALERT_URL_FIELDS    = ("url", "uri", "request_url", "http_url", "full_url")


def _extract_iocs_from_alerts(alerts: list[dict]) -> list[tuple[str, str]]:
    """
    Walk a list of alert dicts and pull out all recognisable IOC values.
    Returns deduplicated list of (value, type) tuples.
    """
    seen    = set()
    results = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        candidates: list[tuple[str, str]] = []

        for field in _ALERT_IP_FIELDS:
            if v := alert.get(field):
                candidates.append((str(v).strip(), "ip"))

        for field in _ALERT_DOMAIN_FIELDS:
            if v := alert.get(field):
                candidates.append((str(v).strip(), "domain"))

        for field in _ALERT_HASH_FIELDS:
            if v := alert.get(field):
                candidates.append((str(v).strip(), "hash"))

        for field in _ALERT_URL_FIELDS:
            if v := alert.get(field):
                candidates.append((str(v).strip(), "url"))

        # Also do a generic pass: detect any string value that looks like an IOC
        for key, val in alert.items():
            if not isinstance(val, str):
                continue
            t = detect_ioc_type(val.strip())
            if t != "unknown":
                candidates.append((val.strip(), t))

        for value, ioc_type in candidates:
            if value and value not in seen:
                seen.add(value)
                results.append((value, ioc_type))

    return results


def deduplicate_iocs(ioc_list: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen = set()
    out  = []
    for ioc, t in ioc_list:
        if ioc not in seen:
            seen.add(ioc)
            out.append((ioc, t))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# MOCK THREAT INTEL SOURCES  (replace with real API calls)
# ─────────────────────────────────────────────────────────────────────────────

def _query_abuseipdb(ioc: str, ioc_type: str) -> dict:
    """AbuseIPDB — IP reputation (stub)."""
    if ioc_type != "ip":
        return {}
    # TODO: replace with requests.get("https://api.abuseipdb.com/api/v2/check", ...)
    score = int(hashlib.md5(ioc.encode()).hexdigest(), 16) % 101
    return {"source": "AbuseIPDB", "score": score,
            "detail": f"Abuse confidence {score}%",
            "malicious": score > 50}


def _query_shodan(ioc: str, ioc_type: str) -> dict:
    """Shodan — open port / banner data (stub)."""
    if ioc_type != "ip":
        return {}
    ports = [22, 80, 443, 8080, 3389]
    seed  = int(hashlib.md5(ioc.encode()).hexdigest()[:4], 16)
    open_ports = [p for i, p in enumerate(ports) if (seed >> i) & 1]
    return {"source": "Shodan", "score": min(len(open_ports) * 10, 60),
            "detail": f"Open ports: {open_ports or 'none'}",
            "malicious": 3389 in open_ports or 8080 in open_ports}


def _query_greynoise(ioc: str, ioc_type: str) -> dict:
    """GreyNoise — mass-scan / noise classification (stub)."""
    if ioc_type != "ip":
        return {}
    seed = int(hashlib.md5(ioc.encode()).hexdigest()[:2], 16)
    classification = ["benign", "malicious", "unknown"][seed % 3]
    score_map = {"malicious": 80, "unknown": 40, "benign": 5}
    return {"source": "GreyNoise", "score": score_map[classification],
            "detail": f"Classification: {classification}",
            "malicious": classification == "malicious"}


def _query_otx(ioc: str, ioc_type: str) -> dict:
    """OTX AlienVault — pulse count (stub)."""
    seed   = int(hashlib.md5(ioc.encode()).hexdigest()[:4], 16)
    pulses = seed % 12
    score  = min(pulses * 8, 90)
    return {"source": "OTX", "score": score,
            "detail": f"Found in {pulses} threat pulses",
            "malicious": pulses >= 3}


def _query_malwarebazaar(ioc: str, ioc_type: str) -> dict:
    """MalwareBazaar — hash lookup (stub)."""
    if ioc_type != "hash":
        return {}
    seed  = int(hashlib.md5(ioc.encode()).hexdigest()[:2], 16)
    found = (seed % 4) == 0
    return {"source": "MalwareBazaar", "score": 95 if found else 0,
            "detail": "Hash found in malware database" if found else "Not found",
            "malicious": found}


def _query_urlscan(ioc: str, ioc_type: str) -> dict:
    """URLScan.io — domain/URL scan (stub)."""
    if ioc_type not in ("domain", "url"):
        return {}
    seed    = int(hashlib.md5(ioc.encode()).hexdigest()[:2], 16)
    malicious = (seed % 3) == 0
    score   = 85 if malicious else 20
    return {"source": "URLScan", "score": score,
            "detail": "Flagged as malicious" if malicious else "No threats found",
            "malicious": malicious}


def _query_ipinfo(ioc: str, ioc_type: str) -> dict:
    """IPInfo — geo / ASN enrichment (stub)."""
    if ioc_type != "ip":
        return {}
    countries = ["RU", "CN", "KP", "IR", "US", "DE", "NL"]
    seed      = int(hashlib.md5(ioc.encode()).hexdigest()[:2], 16)
    country   = countries[seed % len(countries)]
    high_risk = country in ("RU", "CN", "KP", "IR")
    return {"source": "IPInfo", "score": 60 if high_risk else 10,
            "detail": f"Country: {country}",
            "malicious": False,
            "country": country}


_SOURCE_FNS = [
    _query_abuseipdb,
    _query_shodan,
    _query_greynoise,
    _query_otx,
    _query_malwarebazaar,
    _query_urlscan,
    _query_ipinfo,
]


# ─────────────────────────────────────────────────────────────────────────────
# CORE ENRICHMENT FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def _blast_enrich_ioc(ioc: str, ioc_type: str) -> dict:
    """
    Query all sources for a single IOC, aggregate scores, and return a
    unified enrichment result dict.
    """
    source_results = []
    strong_signals = []
    sources_used   = []

    for fn in _SOURCE_FNS:
        try:
            result = fn(ioc, ioc_type)
            if result:
                source_results.append(result)
                sources_used.append(result["source"])
                if result.get("malicious") and result.get("score", 0) >= 70:
                    strong_signals.append(f"{result['source']}: {result['detail']}")
        except Exception as e:
            pass  # Individual source failures should not abort the whole enrichment

    # ── Aggregate score ───────────────────────────────────────────────────────
    if source_results:
        scores       = [r.get("score", 0) for r in source_results]
        threat_score = int(
            max(scores) * 0.5 + (sum(scores) / len(scores)) * 0.5
        )
    else:
        threat_score = 0

    malicious_hits = sum(1 for r in source_results if r.get("malicious"))
    confidence     = min(95, 40 + len(source_results) * 8)

    # ── Verdict ───────────────────────────────────────────────────────────────
    if strong_signals and malicious_hits >= 2:
        verdict = "CONFIRMED MALICIOUS"
    elif threat_score >= SCORE_MALICIOUS or malicious_hits >= 2:
        verdict = "MALICIOUS"
    elif threat_score >= SCORE_SUSPICIOUS or malicious_hits == 1:
        verdict = "SUSPICIOUS"
    elif source_results:
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    # ── Reason summary ────────────────────────────────────────────────────────
    why_parts = [r["detail"] for r in source_results if r.get("detail")]
    why       = " | ".join(why_parts[:3]) if why_parts else "No signal data"

    return {
        "ioc":           ioc,
        "ioc_type":      ioc_type,
        "verdict":       verdict,
        "threat_score":  threat_score,
        "confidence":    confidence,
        "why":           why,
        "strong_signals": strong_signals,
        "sources_used":  sources_used,
        "source_details": source_results,
    }


def unified_ioc_score(ioc: str, ioc_type: Optional[str] = None) -> dict:
    """
    Public wrapper — auto-detects type if not supplied, then enriches.
    """
    if not ioc_type:
        ioc_type = detect_ioc_type(ioc)
    return _blast_enrich_ioc(ioc, ioc_type)


# ─────────────────────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────────────────────

def render_ioc_blast_enrichment():
    """
    IOC Blast Enrichment — Full Streamlit component.
    Single IOC + Batch Lookup tabs, results cards, CSV export.
    """

    st.caption(
        "Every IOC from your session → Unified Engine in parallel · "
        "30-45 min → 10 seconds"
    )

    # ── Source status pills ───────────────────────────────────────────────────
    sources = [
        ("AbuseIPDB",    True),
        ("Shodan",       True),
        ("GreyNoise",    True),
        ("OTX",          True),
        ("MalwareBazaar",True),
        ("URLScan",      False),   # toggle based on real API key availability
        ("IPInfo",       True),
    ]
    pills_html = " ".join(
        f"<span style='display:inline-block;padding:2px 10px;border-radius:12px;"
        f"font-size:.72rem;margin:0 3px 6px 0;"
        f"border:1px solid {'#00c878' if ok else '#ff4444'};"
        f"color:{'#00c878' if ok else '#ff4444'}'>"
        f"{'●' if ok else '○'} {name}</span>"
        for name, ok in sources
    )
    st.markdown(pills_html, unsafe_allow_html=True)

    # ── Tabs ─────────────────────────────────────────────────────────────────
    tab_single, tab_batch = st.tabs(["🔍 Single IOC Lookup", "📋 Batch Lookup"])

    # ── TAB 1: Single IOC ─────────────────────────────────────────────────────
    with tab_single:
        col1, col2 = st.columns([4, 1])
        with col1:
            single_ioc = st.text_input(
                "Enter IOC",
                placeholder="IP, domain, URL, or hash...",
                key="single_ioc_input",
                label_visibility="collapsed",
            )
        with col2:
            run_single = st.button(
                "🔍 Lookup", type="primary",
                use_container_width=True, key="single_run"
            )

        if run_single and single_ioc.strip():
            with st.spinner("Enriching..."):
                result = unified_ioc_score(single_ioc.strip())
            st.session_state["single_result"] = result

        if r := st.session_state.get("single_result"):
            _render_result_card(r, expanded=True)

    # ── TAB 2: Batch Lookup ───────────────────────────────────────────────────
    with tab_batch:
        st.markdown("#### 📋 Batch IOC Lookup")

        # ── FIX 1: persist manual text across reruns via session_state ────────
        if "blast_manual_text" not in st.session_state:
            st.session_state["blast_manual_text"] = ""

        manual_raw = st.text_area(
            "Enter IOCs (one per line)",
            value=st.session_state["blast_manual_text"],
            placeholder="185.220.101.45\nmalware-c2.tk\nabc123def456...",
            height=140,
            key="blast_manual",
            label_visibility="visible",
        )
        # Sync typed value back to persistent state immediately
        st.session_state["blast_manual_text"] = manual_raw

        # ── FIX 2: only use demo fallback when user has typed nothing AND
        #           no real session alerts exist — never mix with manual input ──
        manual_iocs = parse_manual_iocs(manual_raw) if manual_raw.strip() else []

        session_alerts = (
            st.session_state.get("triage_alerts", [])
            + st.session_state.get("analysis_results", [])
            + list(st.session_state.get("sysmon_results", {}).get("alerts", []))
        )

        # Only inject demo IOCs when the user has supplied nothing at all
        if not manual_iocs and not session_alerts:
            session_alerts = [
                {"ip": "185.220.101.45", "domain": "c2panel.tk",        "detail": "C2 beacon"},
                {"ip": "94.102.49.8",    "domain": "malware-c2.ml",     "detail": "Brute force"},
                {"ip": "91.108.4.200",   "domain": "update-server.net", "detail": "Suspicious"},
            ]

        auto_iocs = _extract_iocs_from_alerts(session_alerts) if not manual_iocs else []
        all_iocs  = deduplicate_iocs(manual_iocs + auto_iocs)

        if all_iocs:
            type_counts = {}
            for _, t in all_iocs:
                type_counts[t] = type_counts.get(t, 0) + 1
            breakdown = " · ".join(f"{v} {k}{'s' if v>1 else ''}" for k, v in type_counts.items())
            st.info(f"**{len(all_iocs)} unique IOCs** ready — {breakdown}")
        else:
            st.info("No IOCs found. Add them above or load session alerts.")

        # ── Blast button ──────────────────────────────────────────────────────
        if st.button(
            "🔍 Run Batch Lookup" if not all_iocs
            else f"🔥 BLAST ENRICH ALL {len(all_iocs)} IOCs NOW",
            type="primary",
            use_container_width=True,
            key="blast_run",
            disabled=not all_iocs,
        ):
            results  = []
            prog     = st.progress(0, text="Starting enrichment...")
            total    = len(all_iocs)

            for idx, (ioc, ioc_type) in enumerate(all_iocs):
                prog.progress(
                    (idx + 1) / total,
                    text=f"[{idx+1}/{total}] Checking {ioc_type}: {ioc[:50]}...",
                )
                # ── FIX 3: use unified engine, not the old internal function ──
                results.append(unified_ioc_score(ioc, ioc_type))

            prog.empty()
            st.session_state["blast_results"] = results
            # ── FIX 4: NO st.rerun() — results render in same pass ────────────
            st.success(f"✅ Blast completed — {len(results)} IOCs processed.")

        # ── Results ───────────────────────────────────────────────────────────
        results = st.session_state.get("blast_results", [])
        if not results:
            return

        _render_summary_bar(results)
        st.divider()

        for r in results:
            _render_result_card(r)

        # ── CSV export ────────────────────────────────────────────────────────
        df = pd.DataFrame([
            {
                "IOC":          r.get("ioc"),
                "Type":         r.get("ioc_type"),
                "Verdict":      r.get("verdict"),
                "Threat Score": r.get("threat_score"),
                "Confidence":   r.get("confidence"),
                "Reason":       r.get("why", ""),
                "Sources":      ", ".join(r.get("sources_used", [])),
            }
            for r in results
        ])
        st.download_button(
            "⬇️ Export Results (CSV)",
            df.to_csv(index=False),
            f"ioc_blast_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
            "text/csv",
            key="blast_export",
        )


# ─────────────────────────────────────────────────────────────────────────────
# UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _render_summary_bar(results: list[dict]) -> None:
    """Malicious / Suspicious / Clean count row."""
    _MAL   = {"MALICIOUS", "CONFIRMED MALICIOUS"}
    _SUS   = {"SUSPICIOUS", "HIGH SUSPICION"}
    _CLEAN = {"CLEAN", "BENIGN"}
    mal   = sum(1 for r in results if r.get("verdict") in _MAL)
    sus   = sum(1 for r in results if r.get("verdict") in _SUS)
    clean = sum(1 for r in results if r.get("verdict") in _CLEAN)

    cols = st.columns(3)
    cols[0].metric("🔴 Malicious",  mal)
    cols[1].metric("🟠 Suspicious", sus)
    cols[2].metric("🟢 Clean",      clean)


def _render_result_card(r: dict, expanded: bool = False) -> None:
    """Render a single enrichment result as a styled card."""
    verdict = r.get("verdict", "UNKNOWN")
    color   = VERDICT_COLORS.get(verdict, "#ffcc00")
    ioc     = r.get("ioc", "—")
    score   = r.get("threat_score", 0)

    st.markdown(
        f"<div style='background:rgba(0,0,0,0.22);border-left:4px solid {color};"
        f"padding:12px 16px;margin:8px 0;border-radius:8px'>"
        f"<b style='color:{color}'>{verdict}</b>"
        f"&nbsp;&nbsp;<span style='font-family:monospace;font-size:.85rem'>{ioc}</span>"
        f"<span style='float:right;font-family:monospace;font-size:.85rem'>"
        f"Score: <b>{score}</b></span>"
        f"</div>",
        unsafe_allow_html=True,
    )

    if r.get("strong_signals"):
        st.error("🚨 " + " · ".join(r["strong_signals"]))

    if r.get("why"):
        st.caption(f"🧠 {r['why']}")

    c1, c2, c3 = st.columns(3)
    c1.caption(f"Type: **{r.get('ioc_type','—')}**")
    c2.caption(f"Confidence: **{r.get('confidence', 0)}%**")
    c3.caption(f"Sources: **{len(r.get('sources_used', []))}/7**")

    if expanded and r.get("source_details"):
        with st.expander("Source breakdown"):
            for src in r["source_details"]:
                src_color = "#ff4444" if src.get("malicious") else "#00c878"
                st.markdown(
                    f"<span style='color:{src_color}'>●</span> "
                    f"**{src['source']}** — {src.get('detail','—')} "
                    f"*(score: {src.get('score',0)})*",
                    unsafe_allow_html=True,
                )

    st.divider()

def render_ioc_lookup():
    if not THREAT_INTEL_ENABLED:
        st.error("threat_intel.py not found.")
        return

    st.header("🔎 IOC Intelligence — Multi-Source Lookup + Malware Behavior Analyzer")
    st.caption("One search → AbuseIPDB · Shodan · GreyNoise · OTX · MalwareBazaar · URLScan · AI Malware Behavior Explainer")

    # ── MALWARE BEHAVIOR ANALYZER ────────────────────────────────────────────
    # Only show when user clicks the tab — injected as expander at top
    with st.expander("🦠 AI Malware Behavior Analyzer — Upload Hash / File", expanded=False):
        st.caption("Upload a file or paste a hash → AI explains: malware type, capabilities, MITRE techniques, IOCs, kill-chain position")
        _mb_c1, _mb_c2 = st.columns([3, 2])
        with _mb_c1:
            _hash_input = st.text_input(
                "Paste MD5 / SHA256 / SHA1 hash:",
                placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99",
                key="mba_hash"
            )
            _file_upload = st.file_uploader(
                "Or upload file for hash extraction:",
                type=["exe","dll","ps1","js","vbs","bat","zip","doc","docx","xls","xlsx","pdf"],
                key="mba_file"
            )
        with _mb_c2:
            _mb_groq = get_api_config().get("groq_key","") or os.getenv("GROQ_API_KEY","")
            st.markdown(
                "<div style='background:#0a1020;border:1px solid #1a3a5a;"
                "border-radius:8px;padding:10px 14px;margin-top:4px'>"
                "<div style='color:#5577aa;font-size:.7rem;letter-spacing:1px'>HOW IT WORKS</div>"
                "<div style='color:#aaccee;font-size:.75rem;margin-top:6px'>"
                "1. Hash lookup → MalwareBazaar + VirusTotal<br>"
                "2. Behavioral analysis → sandbox detonation results<br>"
                "3. AI explains in plain English: what it does, how it hides, how to kill it<br>"
                "4. MITRE ATT&CK mapping auto-generated</div>"
                "</div>",
                unsafe_allow_html=True
            )

        if st.button("🦠 Analyze Malware", type="primary", use_container_width=True, key="mba_btn"):
            import hashlib as _mhash, datetime as _mdt

            # Extract hash
            _target_hash = _hash_input.strip()
            if _file_upload and not _target_hash:
                _raw = _file_upload.read()
                _target_hash = _mhash.sha256(_raw).hexdigest()
                st.info(f"SHA256: `{_target_hash}`")

            if not _target_hash:
                st.warning("Paste a hash or upload a file first.")
            else:
                _MALWARE_SYSTEM = (
                    "You are a malware reverse-engineering expert and SOC analyst. "
                    "Given a file hash or malware name, provide: "
                    "(1) Malware family and type (Trojan/Ransomware/RAT/Stealer/Loader/etc), "
                    "(2) Capabilities in plain English (keylogging, C2, persistence, exfil, lateral movement), "
                    "(3) MITRE ATT&CK techniques used (list T-codes), "
                    "(4) IOCs the analyst should hunt for (registry keys, mutex, network indicators, filenames), "
                    "(5) Kill-chain position (initial access/execution/persistence/C2/exfil), "
                    "(6) How to detect it in Splunk/Zeek/Sysmon (one SPL query), "
                    "(7) How to kill it: kill process, remove persistence, clean registry. "
                    "Be specific, structured, use markdown. No fluff."
                )
                _MALWARE_DEMO = {
                    "guloader": (
                        "## \U0001f9a0 Malware Analysis: GuLoader (CloudEyE)\n\n"
                        "**Type:** Shellcode-based downloader / packer\n"
                        "**Family:** GuLoader (aka CloudEyE, NSIS Dropper)\n\n"
                        "### \U0001f4a3 Capabilities\n"
                        "- Downloads and executes secondary payload (AgentTesla, FormBook, Remcos)\n"
                        "- **Anti-analysis:** CPUID checks, VirtualAlloc shellcode injection, NTFS ADS hiding\n"
                        "- **Process injection:** Shellcode injected into legitimate process (explorer.exe, RegSvr32)\n"
                        "- **Cloud-hosted payload:** Fetches from Google Drive / OneDrive / Dropbox URLs\n"
                        "- **Anti-sandbox:** Checks screen resolution, mouse movement, CPU core count\n\n"
                        "### \U0001f3af MITRE ATT&CK\n"
                        "| Technique | ID | Tactic |\n"
                        "|-----------|-----|--------|\n"
                        "| Phishing attachment | T1566.001 | Initial Access |\n"
                        "| PowerShell / VBScript | T1059.001/.005 | Execution |\n"
                        "| Process injection | T1055 | Defense Evasion |\n"
                        "| Obfuscated files | T1027 | Defense Evasion |\n"
                        "| Cloud storage C2 | T1102.002 | C2 |\n"
                        "| Sandbox evasion | T1497 | Defense Evasion |\n\n"
                        "### \U0001f50d Hunt IOCs\n"
                        "- **Registry:** HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*\n"
                        "- **Mutex:** random GUID-style mutex\n"
                        "- **Network:** drive.google.com GET requests with encoded path\n"
                        "- **Process:** RegSvr32.exe /s /n /u /i:http://... (living-off-the-land)\n"
                        "- **File:** Temp dir .exe with random 8-char name\n\n"
                        "### \U0001f50e Detect in Splunk\n"
                        "```splunk\n"
                        "index=sysmon EventCode=1\n"
                        "| where (ParentImage LIKE \"%WINWORD%\" OR ParentImage LIKE \"%EXCEL%\")\n"
                        "    AND (Image LIKE \"%regsvr32%\" OR Image LIKE \"%powershell%\")\n"
                        "| table _time, host, Image, CommandLine, ParentImage\n"
                        "```\n\n"
                        "### \U0001f48a Kill It\n"
                        "1. Kill: taskkill /IM regsvr32.exe /F\n"
                        "2. Remove persistence: Delete registry run key\n"
                        "3. Block: drive.google.com outbound at proxy\n"
                        "4. Hunt: Check all hosts for same parent-child process pattern"
                    ),
                }
                # Match demo keyword
                _kw = _target_hash.lower()
                _demo_key = next((k for k in _MALWARE_DEMO if k in _kw), None)

                with st.spinner("🦠 Analyzing malware behavior…"):
                    if _mb_groq:
                        _prompt = f"Analyze this malware hash/name: {_target_hash}. Provide full behavioral breakdown."
                        _resp = _groq_call(_prompt, _MALWARE_SYSTEM, _mb_groq, max_tokens=900)
                    elif _demo_key:
                        _resp = _MALWARE_DEMO[_demo_key]
                    else:
                        _resp = (
                            f"## \U0001f9a0 Malware Analysis: `{_target_hash[:20]}`\n\n"
                            "**Type:** Unknown / Not in offline database\n\n"
                            "**Submit for analysis:**\n"
                            "- MalwareBazaar: https://bazaar.abuse.ch/\n"
                            "- VirusTotal: https://virustotal.com\n"
                            "- Hybrid Analysis: https://hybrid-analysis.com\n\n"
                            "**Behavioral IOCs to hunt (Sysmon):**\n"
                            "- EID 1: Unusual parent-child process chain\n"
                            "- EID 3: Outbound connection from unexpected process\n"
                            "- EID 7: DLL loaded from TEMP directory\n"
                            "- EID 11: File created in %APPDATA% or %TEMP%\n\n"
                            "**Tip:** Type `guloader` as hash to see a full demo analysis."
                        )

                if _resp:
                    st.markdown(_resp)
                    # Store in session state for later reference
                    st.session_state.setdefault("mba_history", []).append({
                        "hash": _target_hash[:32],
                        "time": _mdt.datetime.utcnow().strftime("%H:%M UTC"),
                        "analysis": _resp[:200] + "…"
                    })
                    st.download_button(
                        "⬇️ Download Analysis Report",
                        _resp.encode(),
                        file_name=f"malware_analysis_{_target_hash[:12]}.md",
                        mime="text/markdown",
                        key="mba_dl"
                    )

        # Show history
        _mba_hist = st.session_state.get("mba_history", [])
        if _mba_hist:
            st.divider()
            st.markdown("**Recent analyses:**")
            for _h in _mba_hist[-3:]:
                st.markdown(
                    f"<div style='color:#446688;font-size:.72rem;font-family:monospace'>"
                    f"`{_h['hash']}` · {_h['time']} · {_h['analysis'][:80]}…</div>",
                    unsafe_allow_html=True
                )
    st.divider()

    # ── Source availability badges ─────────────────────────────────────────────
    import os as _os
    sources = {
        "AbuseIPDB":     bool(_os.getenv("ABUSEIPDB_API_KEY")),
        "Shodan":        bool(_os.getenv("SHODAN_API_KEY")),
        "GreyNoise":     True,
        "OTX":           bool(_os.getenv("OTX_API_KEY")),
        "MalwareBazaar": True,
        "URLScan":       bool(_os.getenv("URLSCAN_API_KEY")),
        "IPInfo":        True,
    }
    badge_html = " &nbsp; ".join(
        f"<span style='background:{'rgba(0,255,200,0.12)' if ok else 'rgba(255,0,50,0.12)'};"
        f"border:1px solid {'#00ffc844' if ok else '#ff003344'};"
        f"border-radius:12px;padding:2px 10px;font-size:0.72rem;"
        f"color:{'#00ffc8' if ok else '#ff6666'}'>"
        f"{'●' if ok else '○'} {name}</span>"
        for name, ok in sources.items()
    )
    st.markdown(f"<div style='margin-bottom:12px'>{badge_html}</div>",
                unsafe_allow_html=True)

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tab_single, tab_batch = st.tabs(["🔍 Single IOC", "📋 Batch Lookup"])

    with tab_single:
        col_ioc, col_type, col_btn = st.columns([3, 1, 1])
        with col_ioc:
            ioc_input = st.text_input("Enter IOC",
                                       placeholder="IP, domain, URL, or file hash",
                                       key="ioc_input")
        with col_type:
            ioc_type = st.selectbox("Type", ["auto", "ip", "domain", "url", "hash"],
                                     key="ioc_type")
        with col_btn:
            st.write(""); st.write("")
            search_btn = st.button("🔍 Search", use_container_width=True, type="primary")

        # Quick demo presets
        st.markdown(
            "<div style='color:#446688;font-size:0.75rem;margin-bottom:4px'>Quick demo:</div>",
            unsafe_allow_html=True)
        qc = st.columns(4)
        if qc[0].button("185.220.101.45", key="q1"): ioc_input, ioc_type, search_btn = "185.220.101.45", "ip", True
        if qc[1].button("91.108.4.200",   key="q2"): ioc_input, ioc_type, search_btn = "91.108.4.200",   "ip", True
        if qc[2].button("malware-c2.tk",  key="q3"): ioc_input, ioc_type, search_btn = "malware-c2.tk",  "domain", True
        if qc[3].button("8.8.8.8 (safe)", key="q4"): ioc_input, ioc_type, search_btn = "8.8.8.8",        "ip", True

        if search_btn and ioc_input:
            with st.spinner(f"Querying 7 intel sources for {ioc_input}…"):
                result = unified_ioc_lookup(ioc_input.strip(), ioc_type)
            st.session_state.ioc_results[ioc_input] = result

        if ioc_input and ioc_input in st.session_state.get("ioc_results", {}):
            r = st.session_state.ioc_results[ioc_input]

            # ── Composite threat score gauge ──────────────────────────────────
            risk     = r.get("risk", "UNKNOWN")
            overall  = r.get("overall", "unknown")
            sources_hit = r.get("sources_hit", 0)
            sources_total = r.get("sources_total", 1)
            elapsed  = r.get("elapsed_s", 0)
            risk_colors = {
                "HIGH":    ("#ff0033", "#ff003322"),
                "MEDIUM":  ("#ff9900", "#ff990022"),
                "LOW":     ("#00ffc8", "#00ffc822"),
                "UNKNOWN": ("#888888", "#88888822"),
            }
            rc, rbg = risk_colors.get(risk, risk_colors["UNKNOWN"])

            # Score derived from sources reporting suspicious/malicious
            score_pct = 0
            for _, sd in r.get("results", {}).items():
                v = sd.get("verdict", "")
                if v == "malicious":   score_pct += 30
                elif v == "suspicious": score_pct += 15
                elif v == "noise":     score_pct += 5
            score_pct = min(100, score_pct)

            st.markdown(
                f"<div style='background:rgba(0,0,0,0.4);border:2px solid {rc}44;"
                f"border-left:6px solid {rc};border-radius:10px;padding:14px 20px;"
                f"margin:8px 0 16px;display:flex;align-items:center;gap:24px'>"
                f"<div style='text-align:center;min-width:70px'>"
                f"<div style='font-size:2rem;font-weight:900;color:{rc};"
                f"font-family:Orbitron,sans-serif'>{score_pct}</div>"
                f"<div style='color:#888;font-size:0.6rem;letter-spacing:2px'>THREAT SCORE</div>"
                f"</div>"
                f"<div style='border-left:1px solid #1a2a3a;padding-left:20px;flex:1'>"
                f"<div style='font-size:1.1rem;font-weight:bold;color:{rc}'>"
                f"{overall.upper()} — Risk: {risk}</div>"
                f"<div style='color:#a0b8d0;font-size:0.78rem;margin-top:4px'>"
                f"Sources: {sources_hit}/{sources_total} responded &nbsp;|&nbsp; "
                f"Elapsed: {elapsed}s &nbsp;|&nbsp; IOC: {ioc_input}"
                f"</div></div></div>",
                unsafe_allow_html=True)

            # ── Tags ──────────────────────────────────────────────────────────
            if r.get("all_tags"):
                tags_html = " &nbsp; ".join(
                    f"<span style='background:rgba(0,200,255,0.08);"
                    f"border:1px solid #00ccff33;border-radius:10px;"
                    f"padding:1px 8px;font-size:0.72rem;color:#00ccff'>{t}</span>"
                    for t in r["all_tags"][:15]
                )
                st.markdown(
                    f"<div style='margin-bottom:12px'>"
                    f"<span style='color:#446688;font-size:0.72rem'>TAGS: </span>{tags_html}</div>",
                    unsafe_allow_html=True)

            # ── Per-source result cards ───────────────────────────────────────
            st.markdown(
                "<div style='color:#00f9ff;font-size:0.75rem;letter-spacing:2px;"
                "text-transform:uppercase;margin:12px 0 8px'>📡 Source Results</div>",
                unsafe_allow_html=True)

            _verdict_icon  = {"malicious":"🔴","suspicious":"🟠","clean":"🟢",
                              "noise":"🔵","unknown":"⚪","error":"❌"}
            _verdict_color = {"malicious":"#ff0033","suspicious":"#ff9900","clean":"#00ffc8",
                              "noise":"#00aaff","unknown":"#666666","error":"#aa4444"}

            source_cols = st.columns(3)
            for idx, (src_name, sd) in enumerate(r.get("results", {}).items()):
                col = source_cols[idx % 3]
                verdict = sd.get("verdict", "unknown")
                vc  = _verdict_color.get(verdict, "#666666")
                vic = _verdict_icon.get(verdict, "⚪")
                display_name = sd.get("source", src_name).upper()

                # Build key-value rows specific to each source
                rows = []
                if sd.get("error"):
                    rows = [("⚠️ Error", (sd.get("error") or "")[:60])]
                elif src_name == "abuseipdb":
                    rows = [
                        ("Confidence",  f"{sd.get('confidence', 0)}%"),
                        ("Reports",     str(sd.get("total_reports", 0))),
                        ("ISP",         (sd.get("isp") or "")[:28]),
                        ("Tor Exit",    "Yes ⚠️" if sd.get("is_tor") else "No"),
                    ]
                elif src_name == "shodan":
                    ports = sd.get("open_ports", [])
                    vulns = sd.get("vulns", [])
                    rows = [
                        ("Open ports",  str(len(ports))),
                        ("Org",         (sd.get("org") or "")[:28]),
                    ]
                    if vulns:
                        rows.append(("CVEs", ", ".join(vulns[:2])))
                elif src_name == "greynoise":
                    rows = [
                        ("Noise",   "Yes (scanner)" if sd.get("noise") else "No"),
                        ("RIOT",    "Yes (benign)" if sd.get("riot") else "No"),
                        ("Class",   sd.get("classification", "—")),
                    ]
                elif src_name == "otx":
                    rows = [
                        ("Pulses",  str(sd.get("pulse_count", 0))),
                    ]
                    if sd.get("malware_families"):
                        rows.append(("Malware", ", ".join((sd.get("malware_families") or [])[:2])))
                elif src_name == "ipinfo":
                    rows = [
                        ("Org",        (sd.get("org") or "")[:28]),
                        ("Country",    f"{sd.get('country','')} / {sd.get('city','')}"),
                        ("Datacenter", "Yes ⚠️" if sd.get("is_datacenter") else "No"),
                    ]
                elif src_name == "malwarebazaar":
                    if sd.get("found"):
                        rows = [
                            ("Family", sd.get("malware_family", "—")),
                            ("File",   (sd.get("file_name") or "—")[:28]),
                        ]
                    else:
                        rows = [("Status", "Not in MalwareBazaar")]
                elif src_name == "urlscan":
                    rows = [
                        ("Malicious", "Yes 🔴" if sd.get("malicious") else "No"),
                        ("Score",     str(sd.get("score", 0))),
                    ]
                else:
                    rows = [(k, str(v)[:30]) for k, v in sd.items()
                            if k not in ("source","verdict","error") and v][:4]

                rows_html = "".join(
                    f"<div style='display:flex;justify-content:space-between;"
                    f"padding:3px 0;border-bottom:1px solid #0d1a2a'>"
                    f"<span style='color:#446688;font-size:0.75rem'>{k}</span>"
                    f"<span style='color:#c8e8ff;font-size:0.75rem'>{v}</span></div>"
                    for k, v in rows
                )
                col.markdown(
                    f"<div style='background:rgba(0,10,25,0.8);"
                    f"border:1px solid {vc}33;border-top:3px solid {vc};"
                    f"border-radius:8px;padding:10px 12px;margin-bottom:10px;min-height:90px'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:center;"
                    f"margin-bottom:8px'>"
                    f"<span style='color:{vc};font-weight:bold;font-size:0.8rem'>{display_name}</span>"
                    f"<span style='font-size:1rem'>{vic}</span></div>"
                    f"{rows_html}"
                    f"</div>",
                    unsafe_allow_html=True)

            # ── Actions row ───────────────────────────────────────────────────
            st.divider()
            col_fp, col_blk, col_spl = st.columns(3)
            with col_fp:
                fp_reason = st.text_input("FP reason", key="fp_reason_ioc",
                                           placeholder="Why is this a false positive?")
            with col_blk:
                st.write("")
                if st.button("🔒 Block IP", key="blk_btn_ioc", use_container_width=True):
                    if ENTERPRISE_ENABLED:
                        ok, msg = block_ip_windows(ioc_input)
                        (st.success if ok else st.error)(msg)
                    else:
                        st.warning("enterprise.py not loaded")
            with col_spl:
                st.write("")
                if SPLUNK_ENABLED and st.button("📤 Send to Splunk", key="spl_btn_ioc",
                                                 use_container_width=True):
                    ok, msg = send_to_splunk({
                        "event_type":  "ioc_lookup_manual",
                        "ioc":         ioc_input,
                        "verdict":     str(r.get("verdict", r.get("overall","UNKNOWN"))),
                        "risk_score":  score_pct,
                        "severity":    "high" if score_pct < 30 else "medium" if score_pct < 60 else "low",
                        "sources":     list(r.get("results", {}).keys()),
                        "source":      "netsec_ai_ioc_lookup",
                        "timestamp":   __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    })
                    (st.success if ok else st.error)("✅ Sent to Splunk!" if ok else msg)

            # FP button separated so it has the reason text
            if fp_reason and st.button("✅ Confirm False Positive", key="fp_btn_ioc"):
                ioc_t = r.get("ioc_type", "domain")
                mark_false_positive(ioc_input, ioc_t, fp_reason)
                st.success(f"Marked {ioc_input} as false positive")

    with tab_batch:
        st.subheader("📋 Batch IOC Lookup")
        batch_input = st.text_area(
            "Enter IOCs (one per line)",
            placeholder="185.220.101.45\nmalware-c2.tk\nabc123def456...",
            height=150, key="batch_ioc_input")
        if st.button("🔍 Run Batch Lookup", use_container_width=True, type="primary"):
            iocs = [i.strip() for i in batch_input.strip().splitlines() if i.strip()]
            if not iocs:
                st.warning("Enter at least one IOC")
            else:
                # ── Unified via IOCEnricher — same engine as Batch Domain Analysis ──
                prog = st.progress(0, text="Starting enrichment…")
                results_raw = []
                try:
                    from ioc_enricher import IOCEnricher as _IOCe
                    _use_ioc_enricher = True
                except ImportError:
                    try:
                        from modules.ioc_enricher import IOCEnricher as _IOCe
                        _use_ioc_enricher = True
                    except ImportError:
                        _use_ioc_enricher = False

                for idx_i, ioc_item in enumerate(iocs):
                    prog.progress((idx_i+1)/len(iocs),
                                  text=f"Enriching {ioc_item[:40]}… ({idx_i+1}/{len(iocs)})")
                    try:
                        if _use_ioc_enricher:
                            r = _IOCe.enrich(ioc_item.strip(), ioc_type="auto")
                        else:
                            r = unified_ioc_lookup(ioc_item.strip(), "auto")
                        results_raw.append(r)
                    except Exception as ex:
                        results_raw.append({
                            "ioc": ioc_item, "type": "unknown",
                            "verdict": "ERROR", "overall": "error",
                            "sources_hit": 0, "sources_total": 7,
                            "all_tags": [str(ex)[:40]],
                        })
                prog.empty()

                # ── Build display table ────────────────────────────────────────
                rows = []
                for res in results_raw:
                    verdict_raw = res.get("verdict", res.get("overall","UNKNOWN"))
                    verdict_str = str(verdict_raw).upper()
                    score       = res.get("unified_score", res.get("threat_score", 50))
                    # Normalise score direction (ioc_enricher: lower=worse, rep: higher=better)
                    if score <= 100 and res.get("unified_score") is not None:
                        risk_pct = 100 - score   # ioc_enricher: 0=malicious
                    else:
                        risk_pct = score
                    sources_used = res.get("sources_used", [])
                    sources_hit  = res.get("sources_hit", 0)
                    sources_tot  = res.get("sources_total", 7)
                    all_tags     = res.get("all_tags", [])
                    typo_tag     = res.get("typosquat_tag","")
                    if typo_tag and typo_tag not in all_tags:
                        all_tags = [typo_tag] + all_tags

                    rows.append({
                        "IOC":       res.get("ioc", "?"),
                        "Type":      res.get("type", res.get("ioc_type","?")),
                        "Verdict":   verdict_str,
                        "Score":     f"{risk_pct}/100",
                        "Sources":   f"{sources_hit}/{sources_tot} ({', '.join(sources_used[:4])})",
                        "Tags":      " · ".join(all_tags[:3]) or "—",
                    })

                import pandas as _pd_b
                summary_df = _pd_b.DataFrame(rows)

                def _colour_risk(val):
                    v = str(val).upper()
                    if any(k in v for k in ["MALICIOUS","HIGH","CONFIRMED"]):
                        return "color:#ff0033;font-weight:bold"
                    if any(k in v for k in ["SUSPICIOUS","MEDIUM"]):
                        return "color:#ff9900;font-weight:bold"
                    if any(k in v for k in ["SAFE","CLEAN","BENIGN","LOW"]):
                        return "color:#00ffc8"
                    return ""

                st.dataframe(
                    summary_df.style.map(_colour_risk, subset=["Verdict","Score"]),
                    use_container_width=True, hide_index=True)

                # ── Detail expanders ──────────────────────────────────────────
                st.markdown("**Per-IOC details:**")
                for res in results_raw:
                    v  = str(res.get("verdict","?")).upper()
                    vc = ("#ff0033" if "MALICIOUS" in v or "HIGH" in v
                          else "#ff9900" if "SUSPICIOUS" in v
                          else "#00ffc8")
                    with st.expander(
                        f"{res.get('ioc','?')} — {v}  |  "
                        f"Sources: {res.get('sources_hit',0)}/{res.get('sources_total',7)}"
                    ):
                        st.markdown(f"**Why:** {res.get('why', res.get('explanation',{}).get('summary',''))[:300]}")
                        used = res.get("sources_used",[])
                        if used:
                            st.markdown(f"**Sources queried:** {' · '.join(used)}")
                        tags = res.get("all_tags",[])
                        if tags:
                            pills = " ".join(
                                f"<span style='background:#1a2a3a;border:1px solid #446688;"
                                f"color:#c8e8ff;border-radius:4px;padding:1px 7px;"
                                f"font-size:.75rem;margin:2px;display:inline-block'>{t}</span>"
                                for t in tags
                            )
                            st.markdown(pills, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# THREAT HUNTING LAB
# ══════════════════════════════════════════════════════════════════════════════
HUNT_QUERIES = {
    "🔴 Malware Execution: Office → PowerShell (Sysmon)":
        'index=sysmon_logs EventCode=1 ParentImage="*WINWORD*" OR ParentImage="*EXCEL*" Image="*powershell*" OR Image="*cmd*" | table _time Computer User ParentImage Image CommandLine',

    "🔴 PowerShell Encoded Command":
        'index=sysmon_logs EventCode=1 Image="*powershell*" CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" | table _time Computer User CommandLine',

    "🔴 LSASS Credential Dumping":
        'index=sysmon_logs EventCode=10 TargetImage="*lsass*" | table _time Computer SourceImage TargetImage GrantedAccess',

    "🔴 Process Injection (CreateRemoteThread)":
        'index=sysmon_logs EventCode=8 | table _time Computer SourceImage TargetImage StartAddress',

    "🟠 Suspicious C2 Port Connections":
        'index=ids_alerts alert_type="Port Scan" OR alert_type="Suspicious" | stats count by ip_address domain | sort -count',

    "🟠 DNS Beaconing (Regular Intervals)":
        'index=zeek_dns query="*.tk" OR query="*.ml" OR query="*.ga" | timechart span=5m count by query',

    "🟠 Large Data Transfers (Exfil Detection)":
        'index=ids_alerts | where threat_score > 60 | stats sum(bytes) as total_bytes by domain ip_address | sort -total_bytes',

    "🟠 Lateral Movement via SMB":
        'index=sysmon_logs EventCode=3 DestinationPort=445 | stats count by SourceIp DestinationIp | where count > 5',

    "🟡 Executable Dropped in Temp":
        'index=sysmon_logs EventCode=11 TargetFilename="*\\Temp\\*.exe" OR TargetFilename="*AppData*\\*.exe" | table _time Computer Image TargetFilename',

    "🟡 LOLBin Abuse (certutil, bitsadmin, mshta)":
        'index=sysmon_logs EventCode=1 Image="*certutil*" OR Image="*bitsadmin*" OR Image="*mshta*" OR Image="*regsvr32*" | table _time Computer User Image CommandLine',

    "🟡 SQL Injection Attempts":
        'index=ids_alerts alert_type=SQLi | stats count by domain ip_address | sort -count',

    "🟢 Top Alert Sources (Last 24h)":
        'index=ids_alerts earliest=-24h | top limit=20 domain',

    "🟢 Alert Volume by Hour":
        'index=ids_alerts earliest=-24h | timechart span=1h count by severity',

    "🟢 MITRE ATT&CK Coverage":
        'index=ids_alerts | stats count by mitre_technique | sort -count',
}

def render_threat_hunting():
    if not THREAT_INTEL_ENABLED:
        st.error("threat_intel.py not found.")
        return

    st.header("Threat Hunting Lab")
    st.caption("Pre-built hunt queries · Custom SPL · Live Splunk execution · Results enrichment")

    tab_prebuilt, tab_custom, tab_results = st.tabs(
        ["🎯 Pre-built Hunts", "🔧 Custom SPL", "📊 Hunt Results"])

    # ── Pre-built hunts ───────────────────────────────────────────────────────
    with tab_prebuilt:
        st.subheader("SOC Hunt Query Library")
        selected_hunt = st.selectbox("Select Hunt", list(HUNT_QUERIES.keys()),
                                      key="hunt_select")
        hunt_spl = HUNT_QUERIES[selected_hunt]
        st.code(hunt_spl, language="python")

        col_run, col_time = st.columns([1,2])
        with col_time:
            hunt_range = st.selectbox("Time Range",
                                       ["-1h","-4h","-24h","-7d","-30d"],
                                       index=2, key="hunt_range")
        with col_run:
            st.write("")
            run_btn = st.button("▶ Run Hunt", use_container_width=True)

        if run_btn:
            with st.spinner("Hunting…"):
                result = query_splunk_alerts(hunt_spl, max_results=100,
                                              earliest=hunt_range)
            if result.get("error"):
                st.warning(f"Splunk unavailable: {result['error']}")
                st.info("💡 In production: connect Splunk REST API (port 8089)")
            else:
                events = result.get("events",[])
                if events:
                    st.success(f"Found {len(events)} results")
                    hunt_df = pd.DataFrame(events)
                    st.dataframe(hunt_df, use_container_width=True)
                    st.session_state.hunt_results = events
                else:
                    st.info("No results — environment is clean or Splunk has no data yet")

        # Hunt categories breakdown
        st.divider()
        st.markdown("#### Hunt Coverage by MITRE Phase")
        mitre_hunts = {
            "Initial Access":    ["Office → PowerShell","Encoded Command"],
            "Execution":         ["PowerShell Encoded","LOLBin Abuse"],
            "Credential Access": ["LSASS Dumping"],
            "Defense Evasion":   ["Process Injection","LOLBin"],
            "Discovery":         ["SMB Lateral","DNS Beaconing"],
            "C2":                ["C2 Port Connections","DNS Beaconing"],
            "Exfiltration":      ["Large Data Transfers","DNS Tunneling"],
        }
        cov_df = pd.DataFrame([{"Phase":k,"Hunts":len(v),"Coverage":f"{min(len(v)*25,100)}%"}
                                for k,v in mitre_hunts.items()])
        fig = px.bar(cov_df, x="Phase", y="Hunts",
                     title="Hunt Coverage by MITRE Phase",
                     color="Hunts", color_continuous_scale="Reds")
        st.plotly_chart(fig, use_container_width=True, key="hunt_mitre_bar")

    # ── Custom SPL ────────────────────────────────────────────────────────────
    with tab_custom:
        st.subheader("Custom SPL Query")
        custom_spl = st.text_area(
            "SPL Query",
            value='index=ids_alerts earliest=-24h | stats count by domain, severity | sort -count',
            height=120, key="custom_spl")
        custom_range = st.selectbox("Earliest", ["-1h","-4h","-24h","-7d"], index=2,
                                     key="custom_range")

        col_run2, col_export = st.columns([1,1])
        with col_run2:
            if st.button("▶ Run Query", use_container_width=True):
                with st.spinner("Running SPL…"):
                    result = query_splunk_alerts(custom_spl, earliest=custom_range)
                if result.get("error"):
                    st.error(f"Error: {result['error']}")
                else:
                    events = result.get("events",[])
                    if events:
                        st.success(f"{len(events)} results")
                        df = pd.DataFrame(events)
                        st.dataframe(df, use_container_width=True)
                        st.session_state.hunt_results = events
                    else:
                        st.info("No results")

        # SPL quick reference
        st.markdown("#### SPL Quick Reference")
        spl_refs = {
            "Filter by field":     'index=ids_alerts severity="critical"',
            "Stats count":         '| stats count by domain',
            "Top values":          '| top limit=10 ip_address',
            "Time chart":          '| timechart span=1h count',
            "Where filter":        '| where threat_score > 70',
            "Rex extract":         r'| rex field=_raw "domain=(?<domain>[\w.-]+)"',
            "Join":                '| join ip_address [search index=blocked_ips]',
            "Dedup":               '| dedup domain',
        }
        for cmd, example in spl_refs.items():
            st.code(f"# {cmd}\n{example}", language="python")

    # ── Results ───────────────────────────────────────────────────────────────
    with tab_results:
        hunt_results = st.session_state.get("hunt_results",[])
        if not hunt_results:
            st.info("Run a hunt query to see results here.")
        else:
            st.success(f"{len(hunt_results)} results from last hunt")
            df = pd.DataFrame(hunt_results)
            st.dataframe(df, use_container_width=True)

            col_dl, col_splunk = st.columns(2)
            with col_dl:
                csv = df.to_csv(index=False)
                st.download_button("⬇️ Download CSV", csv,
                                    f"hunt_results_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                                    "text/csv")
            with col_splunk:
                if SPLUNK_ENABLED and st.button("📤 Send Results to Splunk"):
                    from splunk_handler import send_batch_to_splunk
                    ok, fail = send_batch_to_splunk(hunt_results)
                    st.success(f"Sent {ok} | Failed {fail}")


# ══════════════════════════════════════════════════════════════════════════════
# SOC METRICS DASHBOARD  —  MTTD/MTTR + Daily Report
# ══════════════════════════════════════════════════════════════════════════════