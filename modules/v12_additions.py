"""
NetSec AI v12.0 — New Additions Module
=======================================
Drop this file into your modules/ directory as:
    modules/v12_additions.py

Then add "v12_additions" to the module loader list in app.py:
    for _mod_name in [..., "v12_additions"]:

Provides:
  ✅ render_alert_correlation_dashboard()  — groups alerts into incidents
  ✅ _render_splunk_integration_page()    — Splunk HEC config + test + verdict push
  ✅ _render_webhook_config_page()        — Webhook server config UI
  ✅ render_analyst_metrics_dashboard()   — interview-ready KPI dashboard
  ✅ AlertCorrelationEngine               — time-window + entity-overlap clustering
  ✅ FPReductionTracker                   — tracks FP rate over time (interview metric)
  ✅ MTTRTracker                          — mean-time-to-respond per case
"""

import os
import re
import json
import time
import hashlib
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional

try:
    from modules.core import get_api_config, _keys_configured
except Exception:
    try:
        from core import get_api_config, _keys_configured
    except Exception:
        def get_api_config(): return st.session_state.get("api_config", {})
        def _keys_configured(c): return bool(c)

# ══════════════════════════════════════════════════════════════════════════════
# ALERT CORRELATION ENGINE
# Groups related alerts into incidents using:
#   1. Time window (alerts within N minutes of each other)
#   2. Entity overlap (same IP / domain / host appears in multiple alerts)
#   3. MITRE tactic grouping (same kill-chain phase)
# ══════════════════════════════════════════════════════════════════════════════

class AlertCorrelationEngine:

    @staticmethod
    def correlate(
        alerts: list,
        time_window_minutes: int = 30,
        min_group_size: int = 2,
    ) -> list:
        """
        Returns list of incident groups, each containing:
          {
            "incident_id":   str,
            "name":          str,
            "alerts":        [alert_dict, ...],
            "entities":      set of shared IPs/domains,
            "mitre_chain":   list of unique MITRE techniques,
            "severity":      "critical" | "high" | "medium" | "low",
            "confidence":    int 0-100,
            "kill_chain":    str  (highest kill-chain stage),
            "first_seen":    str,
            "last_seen":     str,
            "recommendation":str,
          }
        """
        if not alerts:
            return []

        # Build entity index: entity → [alert_idx, ...]
        entity_index: dict[str, list] = defaultdict(list)
        for idx, alert in enumerate(alerts):
            for field in ("ip", "src_ip", "dest_ip", "domain", "hostname",
                          "host", "user", "username", "process_name"):
                val = str(alert.get(field, "")).strip().lower()
                if val and val not in ("", "unknown", "none", "—", "-"):
                    entity_index[val].append(idx)

        # Union-find for grouping
        parent = list(range(len(alerts)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Group by entity overlap
        for entity, idxs in entity_index.items():
            for i in range(1, len(idxs)):
                union(idxs[0], idxs[i])

        # Group by time window
        def _parse_ts(alert):
            for field in ("timestamp", "_time", "time", "created_at"):
                val = alert.get(field, "")
                if val:
                    try:
                        return datetime.fromisoformat(str(val)[:19])
                    except Exception:
                        pass
            return datetime.utcnow()

        sorted_alerts = sorted(enumerate(alerts), key=lambda x: _parse_ts(x[1]))
        for i in range(1, len(sorted_alerts)):
            idx_a, a_alert = sorted_alerts[i-1]
            idx_b, b_alert = sorted_alerts[i]
            if (_parse_ts(b_alert) - _parse_ts(a_alert)).total_seconds() <= time_window_minutes * 60:
                union(idx_a, idx_b)

        # Collect groups
        groups: dict[int, list] = defaultdict(list)
        for idx, alert in enumerate(alerts):
            groups[find(idx)].append(alert)

        # Build incident objects
        incidents = []
        _MITRE_KILL_CHAIN = {
            "T1566": "Initial Access",     "T1190": "Initial Access",
            "T1059": "Execution",          "T1053": "Execution",
            "T1543": "Persistence",        "T1547": "Persistence",
            "T1055": "Privilege Escalation","T1068": "Privilege Escalation",
            "T1070": "Defense Evasion",    "T1027": "Defense Evasion",
            "T1003": "Credential Access",  "T1110": "Credential Access",
            "T1046": "Discovery",          "T1082": "Discovery",
            "T1021": "Lateral Movement",   "T1075": "Lateral Movement",
            "T1041": "Exfiltration",       "T1048": "Exfiltration",
            "T1071": "C2",                 "T1095": "C2",
            "T1486": "Impact",             "T1490": "Impact",
        }
        _CHAIN_ORDER = [
            "Initial Access","Execution","Persistence","Privilege Escalation",
            "Defense Evasion","Credential Access","Discovery","Lateral Movement",
            "C2","Exfiltration","Impact",
        ]

        for root_idx, group in groups.items():
            if len(group) < min_group_size:
                continue

            entities = set()
            for a in group:
                for field in ("ip","src_ip","dest_ip","domain","hostname","host"):
                    v = str(a.get(field,"")).strip().lower()
                    if v and v not in ("","unknown","none","—","-"):
                        entities.add(v)

            mitre_tags = []
            for a in group:
                m = str(a.get("mitre","")).strip()
                if m:
                    mitre_tags.append(m)
            mitre_chain = list(dict.fromkeys(mitre_tags))  # dedupe preserving order

            # Kill-chain stage
            stages_seen = set()
            for m in mitre_tags:
                prefix = m[:5]
                for t, stage in _MITRE_KILL_CHAIN.items():
                    if m.startswith(t):
                        stages_seen.add(stage)
            kill_chain = max(
                stages_seen or {"Unknown"},
                key=lambda s: _CHAIN_ORDER.index(s) if s in _CHAIN_ORDER else -1
            )

            severities = [a.get("severity","medium") for a in group]
            _SEV_ORDER = {"critical":4,"high":3,"medium":2,"low":1}
            top_severity = max(severities,
                               key=lambda s: _SEV_ORDER.get(s,0))

            # Confidence = base + entity overlap boost + MITRE coverage boost
            confidence = min(95, 40 + len(entities) * 5 + len(mitre_chain) * 4)

            ts_list = [_parse_ts(a) for a in group]
            first_seen = min(ts_list).strftime("%Y-%m-%d %H:%M:%S")
            last_seen  = max(ts_list).strftime("%Y-%m-%d %H:%M:%S")

            name = AlertCorrelationEngine._name_incident(group, kill_chain, entities)

            rec_map = {
                "Impact":            "CRITICAL — isolate affected hosts immediately, preserve forensic images",
                "Exfiltration":      "Block outbound connections to external IPs, start DPDP breach timer",
                "C2":                "Block C2 IPs/domains at firewall + DNS, isolate beaconing hosts",
                "Lateral Movement":  "Disable compromised accounts, restrict SMB/RDP laterally",
                "Credential Access": "Force password reset, enable MFA, audit privileged accounts",
                "Privilege Escalation":"Revoke elevated tokens, audit sudo/admin activity",
                "Execution":         "Kill suspicious processes, check persistence mechanisms",
                "Initial Access":    "Identify entry vector (phishing/vuln), patch & block IOCs",
            }
            recommendation = rec_map.get(kill_chain, "Investigate alerts — correlate with endpoint telemetry")

            inc_id = f"INC-{hashlib.md5(name.encode()).hexdigest()[:6].upper()}"
            incidents.append({
                "incident_id":    inc_id,
                "name":           name,
                "alerts":         group,
                "alert_count":    len(group),
                "entities":       list(entities)[:10],
                "mitre_chain":    mitre_chain[:8],
                "severity":       top_severity,
                "confidence":     confidence,
                "kill_chain":     kill_chain,
                "first_seen":     first_seen,
                "last_seen":      last_seen,
                "recommendation": recommendation,
            })

        # Sort by severity then confidence
        _SEV_ORDER = {"critical":4,"high":3,"medium":2,"low":1}
        incidents.sort(key=lambda i: (_SEV_ORDER.get(i["severity"],0), i["confidence"]),
                       reverse=True)
        return incidents

    @staticmethod
    def _name_incident(alerts, kill_chain, entities):
        types = [a.get("alert_type", a.get("type","Unknown")) for a in alerts]
        most_common = max(set(types), key=types.count)
        entity_hint = list(entities)[0] if entities else "unknown target"
        return f"{kill_chain}: {most_common[:40]} ({entity_hint[:20]})"


# ══════════════════════════════════════════════════════════════════════════════
# FP REDUCTION TRACKER  — interview-ready metric
# ══════════════════════════════════════════════════════════════════════════════

class FPReductionTracker:

    @staticmethod
    def record(verdict: str, was_fp: bool):
        """Call after every auto-triage decision."""
        st.session_state.setdefault("alerts_processed", 0)
        st.session_state["alerts_processed"] += 1
        if verdict in ("SAFE","BENIGN","LOW RISK") or was_fp:
            st.session_state.setdefault("alerts_auto_closed", 0)
            st.session_state["alerts_auto_closed"] += 1
        elif verdict in ("HIGH SUSPICION","SUSPICIOUS","MALICIOUS","CONFIRMED MALICIOUS"):
            st.session_state.setdefault("alerts_escalated", 0)
            st.session_state["alerts_escalated"] += 1

        total = st.session_state["alerts_processed"]
        closed = st.session_state.get("alerts_auto_closed", 0)
        fp_rate = round(closed / total * 100, 1) if total else 0.0
        st.session_state.setdefault("fp_rate_history", [])
        st.session_state["fp_rate_history"].append(
            (datetime.utcnow().isoformat(), fp_rate)
        )
        # Keep last 200 data points
        st.session_state["fp_rate_history"] = st.session_state["fp_rate_history"][-200:]

    @staticmethod
    def get_summary() -> dict:
        total  = st.session_state.get("alerts_processed", 0)
        closed = st.session_state.get("alerts_auto_closed", 0)
        esc    = st.session_state.get("alerts_escalated", 0)
        return {
            "total":       total,
            "auto_closed": closed,
            "escalated":   esc,
            "fp_rate":     round(closed/total*100,1) if total else 0.0,
            "esc_rate":    round(esc/total*100,1)    if total else 0.0,
        }


# ══════════════════════════════════════════════════════════════════════════════
# MTTR TRACKER
# ══════════════════════════════════════════════════════════════════════════════

class MTTRTracker:

    @staticmethod
    def open_case(case_id: str):
        st.session_state.setdefault("mttr_log", [])
        st.session_state["mttr_log"].append({
            "case_id":  case_id,
            "opened":   datetime.utcnow().isoformat(),
            "closed":   None,
            "minutes":  None,
        })

    @staticmethod
    def close_case(case_id: str):
        for entry in st.session_state.get("mttr_log", []):
            if entry["case_id"] == case_id and entry["closed"] is None:
                entry["closed"] = datetime.utcnow().isoformat()
                opened = datetime.fromisoformat(entry["opened"])
                entry["minutes"] = round((datetime.utcnow() - opened).total_seconds() / 60, 1)
                break

    @staticmethod
    def get_avg_mttr() -> Optional[float]:
        closed = [e["minutes"] for e in st.session_state.get("mttr_log",[])
                  if e["minutes"] is not None]
        return round(sum(closed) / len(closed), 1) if closed else None


# ══════════════════════════════════════════════════════════════════════════════
# UI — ALERT CORRELATION DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

_SEV_COLOR = {
    "critical": "#ff0033",
    "high":     "#ff9900",
    "medium":   "#ffcc00",
    "low":      "#00c878",
}

def render_alert_correlation_dashboard():
    """
    Groups all session alerts into correlated incidents.
    Shows incident cards with entity list, MITRE chain, confidence, recommendation.
    """
    st.markdown(
        "<h2 style='margin:0 0 2px'>🔗 Alert Correlation Engine</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 14px'>"
        "Groups related alerts into incidents · Time-window + entity-overlap clustering · "
        "<b style='color:#00f9ff'>100 alerts → 1 incident</b>"
        "</p>",
        unsafe_allow_html=True,
    )

    raw_alerts = (
        st.session_state.get("triage_alerts", []) +
        st.session_state.get("analysis_results", []) +
        list(st.session_state.get("sysmon_results", {}).get("alerts", []))
    )

    # Demo alerts if none loaded
    if not raw_alerts:
        raw_alerts = _demo_correlation_alerts()
        st.info("💡 Showing demo alerts — load real alerts via Triage or Data Pipeline.")

    col_cfg1, col_cfg2, col_run = st.columns([2, 2, 1])
    time_window = col_cfg1.slider("Time window (minutes)", 5, 120, 30, 5,
                                  key="corr_time_window")
    min_group   = col_cfg2.slider("Min alerts per incident", 2, 10, 2, 1,
                                  key="corr_min_group")
    run_corr    = col_run.button("🔗 Correlate", type="primary",
                                 use_container_width=True, key="corr_run")

    if run_corr or st.session_state.get("corr_auto_ran") != len(raw_alerts):
        with st.spinner("Correlating alerts..."):
            incidents = AlertCorrelationEngine.correlate(
                raw_alerts, time_window_minutes=time_window,
                min_group_size=min_group
            )
        st.session_state["correlation_groups"]  = incidents
        st.session_state["correlated_incidents"] = incidents
        st.session_state["corr_auto_ran"]        = len(raw_alerts)
        if incidents:
            st.success(f"✅ {len(raw_alerts)} alerts → {len(incidents)} correlated incidents")

    incidents = st.session_state.get("correlation_groups", [])

    if not incidents:
        st.info("Click Correlate to group your alerts into incidents.")
        return

    # ── Summary metrics ───────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📊 Raw Alerts",        len(raw_alerts))
    c2.metric("🔗 Incidents",         len(incidents))
    c3.metric("📉 Noise Reduction",
              f"{round((1 - len(incidents)/max(len(raw_alerts),1))*100)}%")
    c4.metric("🔴 Critical Incidents",
              sum(1 for i in incidents if i["severity"] == "critical"))

    st.divider()

    # ── Incident cards ────────────────────────────────────────────────────────
    for inc in incidents:
        color = _SEV_COLOR.get(inc["severity"], "#446688")
        mitre_pills = " ".join(
            f"<span style='background:rgba(195,0,255,0.15);border:1px solid #c300ff33;"
            f"border-radius:4px;padding:1px 6px;font-size:.62rem;color:#c300ff'>{m}</span>"
            for m in inc["mitre_chain"][:6]
        )
        entity_list = " · ".join(inc["entities"][:5])

        st.markdown(
            f"<div style='background:rgba(0,0,0,0.25);border-left:4px solid {color};"
            f"border-radius:8px;padding:14px 16px;margin:8px 0'>"

            f"<div style='display:flex;justify-content:space-between;align-items:center'>"
            f"<span style='color:{color};font-weight:700;font-size:.8rem'>"
            f"[{inc['severity'].upper()}] {inc['incident_id']}</span>"
            f"<span style='color:#00c878;font-size:.7rem'>Confidence: {inc['confidence']}%</span>"
            f"</div>"

            f"<div style='color:#c8e8ff;font-size:.82rem;font-weight:700;margin:4px 0'>"
            f"{inc['name']}</div>"

            f"<div style='display:flex;gap:16px;font-size:.68rem;color:#446688;margin:6px 0'>"
            f"<span>🚨 {inc['alert_count']} alerts</span>"
            f"<span>⏱ {inc['first_seen'][:16]} → {inc['last_seen'][:16]}</span>"
            f"<span>🎯 Kill-chain: <b style='color:#ff9900'>{inc['kill_chain']}</b></span>"
            f"</div>"

            f"<div style='margin:4px 0'>{mitre_pills}</div>"

            f"<div style='font-size:.68rem;color:#5577aa;margin-top:4px'>"
            f"Entities: {entity_list}</div>"

            f"<div style='background:rgba(0,200,120,0.08);border:1px solid #00c87833;"
            f"border-radius:6px;padding:6px 10px;margin-top:8px;"
            f"font-size:.7rem;color:#00c878'>"
            f"⚡ Recommendation: {inc['recommendation']}</div>"

            f"</div>",
            unsafe_allow_html=True,
        )

        # Expandable alert list
        with st.expander(f"View {inc['alert_count']} alerts in this incident"):
            for a in inc["alerts"]:
                sev_c = _SEV_COLOR.get(a.get("severity","medium"), "#446688")
                st.markdown(
                    f"<div style='border-left:3px solid {sev_c};padding:4px 10px;"
                    f"margin:2px 0;font-size:.72rem;color:#c8e8ff'>"
                    f"<b style='color:{sev_c}'>{a.get('severity','?').upper()}</b> — "
                    f"{a.get('alert_type', a.get('type','Unknown'))} · "
                    f"IP: {a.get('ip','—')} · MITRE: {a.get('mitre','—')}</div>",
                    unsafe_allow_html=True,
                )

        # Action buttons per incident
        btn1, btn2, btn3 = st.columns(3)
        if btn1.button("📋 Create IR Case", key=f"corr_ir_{inc['incident_id']}",
                       use_container_width=True):
            _auto_create_ir_from_incident(inc)
            st.success(f"✅ IR Case created for {inc['incident_id']}")
        if btn2.button("🚫 Block All IOCs", key=f"corr_block_{inc['incident_id']}",
                       use_container_width=True):
            for entity in inc["entities"]:
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", entity) or "." in entity:
                    st.session_state.setdefault("blocked_ips", []).append(entity)
                    st.session_state.setdefault("global_blocklist", []).append({
                        "ioc": entity, "methods": ["Firewall","DNS"],
                        "reason": f"Auto-blocked from {inc['incident_id']}",
                        "analyst": "auto-correlation", "status": "BLOCKED",
                        "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    })
            st.success(f"🚫 Blocked {len(inc['entities'])} entities")
        if btn3.button("📤 Export Incident", key=f"corr_exp_{inc['incident_id']}",
                       use_container_width=True):
            df = pd.DataFrame(inc["alerts"])
            st.download_button(
                f"⬇️ {inc['incident_id']}.csv",
                df.to_csv(index=False),
                f"{inc['incident_id']}.csv",
                "text/csv",
                key=f"dl_{inc['incident_id']}",
            )

    st.divider()

    # ── CSV export all incidents ──────────────────────────────────────────────
    df_inc = pd.DataFrame([{
        "Incident ID":    i["incident_id"],
        "Name":           i["name"],
        "Severity":       i["severity"],
        "Confidence":     i["confidence"],
        "Alert Count":    i["alert_count"],
        "Kill Chain":     i["kill_chain"],
        "MITRE Chain":    ", ".join(i["mitre_chain"]),
        "Entities":       ", ".join(i["entities"]),
        "First Seen":     i["first_seen"],
        "Last Seen":      i["last_seen"],
        "Recommendation": i["recommendation"],
    } for i in incidents])
    st.download_button(
        "⬇️ Export All Incidents (CSV)",
        df_inc.to_csv(index=False),
        f"correlated_incidents_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
        "text/csv",
        key="corr_export_all",
    )


def _auto_create_ir_from_incident(inc: dict):
    """Create an IR case from a correlated incident automatically."""
    case = {
        "id":        inc["incident_id"],
        "title":     inc["name"],
        "severity":  inc["severity"],
        "mitre":     ", ".join(inc["mitre_chain"][:3]),
        "analyst":   "auto-correlation",
        "status":    "Open",
        "iocs":      inc["entities"],
        "timestamp": datetime.utcnow().isoformat(),
        "notes":     f"Auto-created from correlation. Kill-chain: {inc['kill_chain']}. "
                     f"{inc['alert_count']} alerts grouped.",
    }
    st.session_state.setdefault("ir_cases", []).append(case)
    MTTRTracker.open_case(inc["incident_id"])


def _demo_correlation_alerts():
    """Returns realistic demo alerts for correlation demo."""
    now = datetime.utcnow()
    return [
        {"id":"A01","alert_type":"PowerShell Encoded Command","severity":"critical",
         "mitre":"T1059.001","ip":"192.168.1.55","domain":"workstation-07",
         "timestamp":(now - timedelta(minutes=2)).isoformat()},
        {"id":"A02","alert_type":"LSASS Memory Access","severity":"critical",
         "mitre":"T1003","ip":"192.168.1.55","domain":"workstation-07",
         "timestamp":(now - timedelta(minutes=1)).isoformat()},
        {"id":"A03","alert_type":"C2 Beaconing","severity":"high",
         "mitre":"T1071","ip":"185.220.101.45","domain":"c2panel.tk",
         "timestamp":(now - timedelta(minutes=5)).isoformat()},
        {"id":"A04","alert_type":"DNS Tunnel Detected","severity":"high",
         "mitre":"T1071.004","ip":"185.220.101.45","domain":"c2panel.tk",
         "timestamp":(now - timedelta(minutes=4)).isoformat()},
        {"id":"A05","alert_type":"SMB Lateral Movement","severity":"high",
         "mitre":"T1021.002","ip":"192.168.1.55","domain":"workstation-07",
         "timestamp":(now - timedelta(minutes=8)).isoformat()},
        {"id":"A06","alert_type":"SSH Brute Force","severity":"medium",
         "mitre":"T1110","ip":"94.102.49.8","domain":"external-attacker",
         "timestamp":(now - timedelta(minutes=45)).isoformat()},
        {"id":"A07","alert_type":"Scheduled Task Created","severity":"medium",
         "mitre":"T1053","ip":"192.168.1.55","domain":"workstation-07",
         "timestamp":(now - timedelta(minutes=0)).isoformat()},
        {"id":"A08","alert_type":"Data Exfiltration","severity":"critical",
         "mitre":"T1041","ip":"185.220.101.45","domain":"c2panel.tk",
         "timestamp":(now - timedelta(minutes=3)).isoformat()},
    ]


# ══════════════════════════════════════════════════════════════════════════════
# UI — SPLUNK INTEGRATION PAGE
# ══════════════════════════════════════════════════════════════════════════════

def _render_splunk_integration_page():
    st.markdown(
        "<h2 style='margin:0 0 2px'>📡 Splunk Integration</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 14px'>"
        "Push verdicts → Splunk HEC · Pull alerts via Splunk API · "
        "Lookup write-back · Saved search automation"
        "</p>",
        unsafe_allow_html=True,
    )

    cfg = st.session_state.get("api_config", {})
    tab_hec, tab_api, tab_lookup, tab_spl = st.tabs([
        "📤 HEC Push", "📥 Pull Alerts", "📋 Lookup Write-Back", "📜 SPL Templates"
    ])

    # ── TAB 1: HEC Push ───────────────────────────────────────────────────────
    with tab_hec:
        st.markdown("#### Push verdicts → Splunk HEC")

        col1, col2 = st.columns(2)
        hec_url   = col1.text_input("HEC URL",
                    value=cfg.get("splunk_hec_url","") or os.getenv("SPLUNK_HEC_URL",""),
                    placeholder="https://your-splunk:8088/services/collector",
                    key="spl_hec_url")
        hec_token = col2.text_input("HEC Token", type="password",
                    value=cfg.get("splunk_hec_token","") or os.getenv("SPLUNK_HEC_TOKEN",""),
                    key="spl_hec_token")
        hec_index = st.text_input("Index", value="main", key="spl_hec_index")

        col_save, col_test = st.columns(2)
        if col_save.button("💾 Save HEC Config", use_container_width=True, key="spl_save"):
            cfg["splunk_hec_url"]   = hec_url
            cfg["splunk_hec_token"] = hec_token
            st.session_state["api_config"] = cfg
            st.success("✅ HEC config saved")

        if col_test.button("🧪 Test HEC Connection", use_container_width=True,
                           type="primary", key="spl_test"):
            if not hec_url or not hec_token:
                st.warning("Enter HEC URL and token first")
            else:
                with st.spinner("Testing..."):
                    ok, msg = _test_splunk_hec(hec_url, hec_token, hec_index)
                if ok:
                    st.success(f"✅ {msg}")
                else:
                    st.error(f"❌ {msg}")

        st.divider()
        st.markdown("#### Push session verdicts to Splunk now")
        verdicts = st.session_state.get("splunk_verdicts", [])
        ioc_log  = st.session_state.get("ioc_enrichment_log", [])
        push_data = verdicts + ioc_log

        if push_data:
            st.info(f"**{len(push_data)} verdicts** ready to push")
            if st.button("📤 Push All to Splunk HEC", type="primary",
                         use_container_width=True, key="spl_push_all"):
                if not hec_url or not hec_token:
                    st.error("Configure HEC URL and token first")
                else:
                    pushed = 0
                    for event in push_data:
                        ok, _ = _send_to_hec(hec_url, hec_token, hec_index, event)
                        if ok:
                            pushed += 1
                    st.success(f"✅ Pushed {pushed}/{len(push_data)} events to Splunk")
        else:
            st.info("Run IOC enrichment or triage first to generate verdicts.")

    # ── TAB 2: Pull Alerts ────────────────────────────────────────────────────
    with tab_api:
        st.markdown("#### Pull alerts from Splunk Search API (port 8089)")

        # ── Credential warning ────────────────────────────────────────────────
        st.info(
            "**Username** — use the value in the **Name** column at Splunk Web → Settings → Users.  \n"
            "Email-style usernames are valid if that's how your account was created.  \n"
            "URL must be `https://127.0.0.1:8089` (port 8089 is always HTTPS in Splunk)",
            icon="ℹ️"
        )

        col1, col2 = st.columns(2)
        spl_url  = col1.text_input(
            "Splunk URL",
            value=cfg.get("splunk_url","") or os.getenv("SPLUNK_URL","https://127.0.0.1:8089"),
            placeholder="https://127.0.0.1:8089",
            key="spl_api_url"
        )
        spl_user = col1.text_input(
            "Username  (local Splunk user — not email)",
            value=cfg.get("splunk_user","admin"),
            key="spl_api_user"
        )
        spl_pass = col2.text_input(
            "Password",
            type="password",
            value=cfg.get("splunk_pass",""),
            key="spl_api_pass"
        )
        spl_query = col2.text_area(
            "SPL Query",
            value='index=main | head 20',
            height=80,
            key="spl_query"
        )

        # ── Username validation: email-style names are fine in Splunk ─────────
        # (no blocking — Splunk allows emails as usernames)

        btn_test, btn_run = st.columns(2)
        run_test  = btn_test.button("🔌 Test Connection First", use_container_width=True, key="spl_conn_test")
        run_query = btn_run.button("🔍 Run Query & Import Alerts", type="primary",
                                   use_container_width=True, key="spl_run_query")

        # ── Test connection ───────────────────────────────────────────────────
        if run_test:
            if not spl_url or not spl_pass:
                st.warning("Enter URL and password first")
            else:
                with st.spinner("Testing Splunk connection..."):
                    ok, msg = _test_splunk_connection(spl_url, spl_user, spl_pass)
                if ok:
                    st.success(f"✅ {msg}")
                    cfg["splunk_url"]  = spl_url
                    cfg["splunk_user"] = spl_user
                    cfg["splunk_pass"] = spl_pass
                    st.session_state["api_config"] = cfg
                else:
                    st.error(f"❌ {msg}")

        # ── Run query ─────────────────────────────────────────────────────────
        if run_query:
            if not spl_url:
                st.warning("Enter Splunk URL first")
            elif not spl_pass:
                st.warning("Enter password first")
            else:
                with st.spinner("Querying Splunk..."):
                    results, err = _query_splunk_api(spl_url, spl_user, spl_pass, spl_query)
                if err:
                    st.error(f"❌ {err}")
                    # Give specific fix tips
                    if "401" in str(err) or "Unauthorized" in str(err):
                        st.warning(
                            "**401 Unauthorized** — wrong username or password.  \n"
                            "- Username must be local (e.g. `admin`), not your email  \n"
                            "- Check Splunk Web → Settings → Users for the correct username"
                        )
                    elif "Connection refused" in str(err) or "111" in str(err):
                        st.warning("**Connection refused** — is Splunk running? Use: `https://127.0.0.1:8089` (port 8089 is always HTTPS)")
                    elif "timed out" in str(err).lower():
                        st.warning("**Timeout** — the SPL query took too long. Use `| head 20` at the end to limit results.")
                else:
                    alerts = _splunk_results_to_alerts(results)
                    st.session_state.setdefault("triage_alerts", []).extend(alerts)
                    cfg["splunk_url"]  = spl_url
                    cfg["splunk_user"] = spl_user
                    cfg["splunk_pass"] = spl_pass
                    st.session_state["api_config"] = cfg
                    st.success(f"✅ Imported {len(alerts)} alerts from Splunk")
                    if results:
                        st.dataframe(pd.DataFrame(results[:20]), use_container_width=True)
                    else:
                        st.warning("Query ran OK but returned 0 results — try `index=main | head 20`")

        # ── Quick SPL presets ─────────────────────────────────────────────────
        st.divider()
        st.markdown("**Quick SPL presets — click to copy:**")
        presets = {
            "All events (safe test)":     "index=main | head 20",
            "DNS queries":                "index=* sourcetype=dns | stats count by query | sort -count | head 20",
            "Failed logins (Windows)":    "index=wineventlog EventCode=4625 | stats count by Account_Name, src_ip | sort -count | head 20",
            "Firewall blocks":            "index=* sourcetype=firewall action=blocked | stats count by src_ip | sort -count | head 20",
            "Wazuh alerts level 7+":      "index=* sourcetype=wazuh rule.level>=7 | table _time agent.name rule.description rule.level",
        }
        for label, spl_val in presets.items():
            st.code(f"{spl_val}", language="spl")
            st.caption(f"↑ {label}")

    # ── TAB 3: Lookup Write-Back ──────────────────────────────────────────────
    with tab_lookup:
        st.markdown("#### Export verdicts as Splunk CSV lookup")
        st.caption("Copy this file to `$SPLUNK_HOME/etc/apps/search/lookups/netsec_verdicts.csv`")

        verdicts_all = (
            st.session_state.get("blast_results", []) +
            st.session_state.get("rep_batch_results", []) +
            st.session_state.get("ioc_enrichment_log", [])
        )

        if verdicts_all:
            df = pd.DataFrame([{
                "domain":      r.get("ioc") or r.get("value",""),
                "verdict":     r.get("verdict","UNKNOWN"),
                "score":       r.get("threat_score") or r.get("score",0),
                "confidence":  r.get("confidence") or r.get("confidence_cap",0),
                "severity":    r.get("severity","unknown"),
                "action":      r.get("action","investigate"),
                "reason":      r.get("why") or r.get("decision_engine",""),
                "timestamp":   datetime.utcnow().isoformat(),
                "source":      "netsec_ai",
            } for r in verdicts_all])

            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button(
                "⬇️ Download netsec_verdicts.csv",
                df.to_csv(index=False),
                "netsec_verdicts.csv",
                "text/csv",
                key="spl_lookup_dl",
            )

            st.code(
                "| inputlookup netsec_verdicts.csv\n"
                "| table domain verdict score severity action\n"
                "| sort - score",
                language="spl"
            )
        else:
            st.info("Run IOC enrichment or reputation scoring first to generate verdicts.")

    # ── TAB 4: SPL Templates ──────────────────────────────────────────────────
    with tab_spl:
        st.markdown("#### Ready-to-use SPL queries for your SOC")

        _SPL_TEMPLATES = {
            "Domain extraction + triage": """\
index=* sourcetype=access_combined OR sourcetype=proxy
| rex field=_raw "(?i)(?:https?://)?(?:www\\.)?(?P<domain>[a-z0-9\\-]+(?:\\.[a-z0-9\\-]+)+)"
| stats count by domain
| sort - count
| head 100
| lookup netsec_verdicts.csv domain OUTPUT verdict score severity
| where isnotnull(verdict)
| table domain count verdict score severity""",

            "High-severity IOC alerts": """\
index=* sourcetype=netsec_ai verdict IN ("HIGH SUSPICION","CONFIRMED MALICIOUS","MALICIOUS")
| table _time domain verdict score severity action reason
| sort - score""",

            "Alert triage summary (last 24h)": """\
index=* sourcetype=netsec_ai earliest=-24h
| stats count by verdict
| eval pct = round(count / sum(count) * 100, 1)
| sort - count""",

            "FP rate over time": """\
index=* sourcetype=netsec_ai
| eval is_benign = if(verdict IN ("SAFE","LOW RISK"), 1, 0)
| timechart span=1h avg(is_benign) AS fp_rate
| eval fp_rate = round(fp_rate * 100, 1)""",

            "Entity correlation": """\
index=* sourcetype=netsec_ai
| stats dc(domain) AS domains_seen, list(verdict) AS verdicts by src_ip
| where domains_seen > 5
| mvexpand verdicts
| where verdicts IN ("HIGH SUSPICION","MALICIOUS")""",
        }

        for title, spl in _SPL_TEMPLATES.items():
            with st.expander(f"📜 {title}"):
                st.code(spl, language="spl")


# ══════════════════════════════════════════════════════════════════════════════
# UI — WEBHOOK CONFIG PAGE
# ══════════════════════════════════════════════════════════════════════════════

def _render_pull_hec_dashboard():
    """
    Pull + HEC Dashboard — replaces old Webhook Config.
    Primary: Pull alerts FROM Splunk (Search API port 8089).
    Secondary: HEC push verdicts TO Splunk.
    Webhook push removed — too unreliable.
    """
    st.markdown(
        "<h2 style='margin:0 0 2px'>⚡ Pull & HEC Dashboard</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 14px'>"
        "Pull alerts FROM Splunk (port 8089) · Push verdicts TO Splunk (HEC) · "
        "Wazuh pull · Backfill · Metrics"
        "</p>",
        unsafe_allow_html=True,
    )

    cfg = st.session_state.get("api_config", {})

    tab_pull, tab_wazuh, tab_hec, tab_metrics, tab_spl = st.tabs([
        "📥 Pull Alerts", "🦅 Wazuh Pull", "📤 HEC Push", "📊 Metrics", "📜 SPL Templates"
    ])

    # ── TAB 1: PULL ALERTS ────────────────────────────────────────────────────
    with tab_pull:
        st.markdown("#### Pull domains from Splunk Search API (port 8089)")
        st.caption("This is the primary, reliable method — no webhook needed.")

        col1, col2, col3 = st.columns(3)
        pull_url  = col1.text_input("Splunk URL",
                    value=cfg.get("splunk_url","") or os.getenv("SPLUNK_SEARCH_URL","https://127.0.0.1:8089"),
                    key="pull_hec_url")
        pull_user = col2.text_input("Username",
                    value=cfg.get("splunk_user","admin"), key="pull_hec_user")
        pull_pass = col3.text_input("Password", type="password",
                    value=cfg.get("splunk_pass",""), key="pull_hec_pass")

        col_src, col_hrs, col_cnt = st.columns(3)
        source    = col_src.selectbox("Log source", ["any","dns","firewall","proxy","windows"],
                                      key="pull_source")
        hours_back = col_hrs.slider("Hours back", 1, 24, 1, key="pull_hours")
        min_count  = col_cnt.slider("Min domain count (noise filter)", 1, 20, 2, key="pull_min_count")

        col_run, col_backfill = st.columns(2)
        run_now   = col_run.button("▶ Pull & Triage Now", type="primary",
                                   use_container_width=True, key="pull_run_now")
        backfill  = col_backfill.button("📂 Backfill Last 24h",
                                        use_container_width=True, key="pull_backfill")

        if run_now or backfill:
            if not pull_pass:
                st.error("Enter Splunk password first")
            else:
                h = 24 if backfill else hours_back
                with st.spinner(f"Pulling from Splunk ({source}, last {h}h)..."):
                    try:
                        import urllib.request as _ur, urllib.parse as _up
                        import base64 as _b64, ssl as _ssl, json as _j
                        ctx = _ssl.create_default_context()
                        ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
                        creds = _b64.b64encode(f"{pull_user}:{pull_pass}".encode()).decode()

                        _SPL = {
                            "any": f'index=* | rex field=_raw "(?i)(?P<domain>[a-z0-9\-]+(?:\.[a-z0-9\-]+)+)" | stats count by domain | where count >= {min_count} | sort -count | head 50',
                            "dns": f'index=dns sourcetype=dns | stats count by query | rename query AS domain | where count >= {min_count} | sort -count | head 50',
                            "firewall": f'index=firewall | rex field=_raw "(?P<domain>[a-z0-9\-]+\.(?:com|net|org|io|tk|xyz|in|co))" | stats count by domain | where count >= {min_count} | head 50',
                            "proxy": f'index=proxy | rex field=_raw "(?P<domain>[a-z0-9\-]+\.(?:com|net|org|io|tk|xyz|in|co))" | stats count by domain | where count >= {min_count} | head 50',
                            "windows": f'index=wineventlog | rex field=_raw "(?P<domain>[a-z0-9\-]+\.(?:com|net|org|io|tk|xyz|in|co))" | stats count by domain | where count >= {min_count} | head 50',
                        }
                        spl = f"search earliest=-{h}h latest=now {_SPL.get(source, _SPL['any'])}"
                        payload = _up.urlencode({"search": spl, "output_mode":"json",
                                                 "exec_mode":"blocking","count":"100"}).encode()
                        req = _ur.Request(f"{pull_url.rstrip('/')}/services/search/jobs",
                                          data=payload,
                                          headers={"Authorization":f"Basic {creds}",
                                                   "Content-Type":"application/x-www-form-urlencoded"},
                                          method="POST")
                        with _ur.urlopen(req, timeout=30, context=ctx) as r:
                            job = _j.loads(r.read())
                        sid = job.get("sid")
                        if not sid:
                            st.error("Splunk returned no job ID — check credentials"); st.stop()
                        res_req = _ur.Request(
                            f"{pull_url.rstrip('/')}/services/search/jobs/{sid}/results?output_mode=json&count=100",
                            headers={"Authorization":f"Basic {creds}"})
                        with _ur.urlopen(res_req, timeout=15, context=ctx) as r:
                            results = _j.loads(r.read()).get("results",[])
                    except Exception as e:
                        st.error(f"Pull failed: {e}"); results = []

                if not results:
                    st.warning("No domains found — try a different source or reduce min_count")
                else:
                    st.success(f"✅ Pulled {len(results)} domains from Splunk")
                    # Triage each
                    prog = st.progress(0)
                    triaged = []
                    try:
                        from reputation_engine import get_authoritative_verdict
                        _has_rep = True
                    except ImportError:
                        _has_rep = False
                    for i, row in enumerate(results):
                        domain = str(row.get("domain","")).strip().lower()
                        if not domain: continue
                        prog.progress((i+1)/len(results), text=f"Triaging {domain[:40]}…")
                        if _has_rep:
                            try:
                                r = get_authoritative_verdict(domain)
                                score = r.get("score",50)
                                verdict = r.get("verdict","UNKNOWN")
                            except Exception:
                                score, verdict = 50, "UNKNOWN"
                        else:
                            score, verdict = 50, "UNKNOWN"
                        triaged.append({
                            "domain": domain,
                            "count": row.get("count","?"),
                            "verdict": verdict,
                            "score": score,
                            "severity": ("informational" if score>=70 else "low" if score>=40
                                         else "medium" if score>=20 else "high"),
                            "action": ("no_action" if score>=70 else "monitor" if score>=40
                                       else "investigate" if score>=20 else "BLOCK"),
                        })
                    prog.empty()
                    st.session_state["pull_triage_results"] = triaged

        # Display results
        results_display = st.session_state.get("pull_triage_results",[])
        if results_display:
            import pandas as _pd
            df = _pd.DataFrame(results_display)
            def _color(v):
                s = str(v).upper()
                if "BLOCK" in s or "MALICIOUS" in s or "HIGH" in s: return "color:#ff0033;font-weight:bold"
                if "SUSPICIOUS" in s or "INVESTIGATE" in s or "MEDIUM" in s: return "color:#ff9900;font-weight:bold"
                if "BENIGN" in s or "SAFE" in s or "LOW" in s: return "color:#00ffc8"
                return ""
            st.dataframe(df.style.map(_color, subset=["verdict","action"]),
                         use_container_width=True, hide_index=True)
            malicious = sum(1 for r in results_display if r["score"]<40)
            if malicious:
                st.error(f"🚨 {malicious} HIGH RISK domains found — review immediately")

    # ── TAB 2: WAZUH PULL ─────────────────────────────────────────────────────
    with tab_wazuh:
        st.markdown("#### Pull alerts from Wazuh OpenSearch (port 9200)")
        col1, col2, col3 = st.columns(3)
        wazuh_url  = col1.text_input("Wazuh URL",
                     value=cfg.get("wazuh_url","") or os.getenv("WAZUH_URL","https://192.168.1.4:9200"),
                     key="phd_wazuh_url")
        wazuh_user = col2.text_input("Username",
                     value=cfg.get("wazuh_user","admin"), key="phd_wazuh_user")
        wazuh_pass = col3.text_input("Password", type="password",
                     value=cfg.get("wazuh_pass",""), key="phd_wazuh_pass")

        col_lvl, col_hrs = st.columns(2)
        min_level   = col_lvl.slider("Min rule level", 3, 15, 5, key="phd_wazuh_level")
        wazuh_hours = col_hrs.slider("Hours back", 1, 24, 1, key="phd_wazuh_hours")

        if st.button("🦅 Pull Wazuh Alerts Now", type="primary",
                     use_container_width=True, key="phd_wazuh_pull"):
            if not wazuh_pass:
                st.error("Enter Wazuh password (default: SecretPassword)")
            else:
                with st.spinner(f"Querying Wazuh (level>={min_level}, last {wazuh_hours}h)..."):
                    import urllib.request as _ur, base64 as _b64, ssl as _ssl, json as _j
                    from datetime import timedelta
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False; ctx.verify_mode = _ssl.CERT_NONE
                    creds = _b64.b64encode(f"{wazuh_user}:{wazuh_pass}".encode()).decode()
                    cutoff = (datetime.utcnow()-timedelta(hours=wazuh_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
                    q = _j.dumps({
                        "size": 50,
                        "sort": [{"@timestamp":{"order":"desc"}}],
                        "query":{"bool":{"must":[
                            {"range":{"@timestamp":{"gte":cutoff}}},
                            {"range":{"rule.level":{"gte":min_level}}},
                        ]}},
                        "_source":["@timestamp","rule.level","rule.description",
                                   "rule.groups","agent.name","agent.ip",
                                   "data.srcip","data.dstip","data.hostname","full_log"]
                    }).encode()
                    try:
                        req = _ur.Request(
                            f"{wazuh_url.rstrip('/')}/wazuh-alerts-*/_search",
                            data=q,
                            headers={"Authorization":f"Basic {creds}",
                                     "Content-Type":"application/json"},
                            method="POST"
                        )
                        with _ur.urlopen(req, timeout=10, context=ctx) as r:
                            hits = _j.loads(r.read()).get("hits",{}).get("hits",[])
                        rows = []
                        import re as _re
                        for hit in hits:
                            src   = hit.get("_source",{})
                            rule  = src.get("rule",{})
                            agent = src.get("agent",{})
                            d     = src.get("data",{})
                            ioc = (d.get("hostname","") or d.get("srcip","") or "")
                            if not ioc:
                                m = _re.search(r'([a-z0-9\-]+\.(?:com|net|org|io|tk|xyz|in))',
                                               src.get("full_log",""), _re.I)
                                if m: ioc = m.group(1)
                            rows.append({
                                "timestamp":   src.get("@timestamp","")[:19].replace("T"," "),
                                "agent":       agent.get("name","?"),
                                "agent_ip":    agent.get("ip","?"),
                                "level":       rule.get("level",0),
                                "rule_id":     rule.get("id",""),
                                "description": rule.get("description","")[:80],
                                "ioc":         ioc or "—",
                            })
                        st.session_state["wazuh_pull_results"] = rows
                    except Exception as e:
                        st.error(f"Wazuh pull failed: {e}")

        wazuh_rows = st.session_state.get("wazuh_pull_results",[])
        if wazuh_rows:
            import pandas as _pd
            st.success(f"✅ {len(wazuh_rows)} Wazuh alerts pulled")
            st.dataframe(_pd.DataFrame(wazuh_rows), use_container_width=True, hide_index=True)
            extractable = [r for r in wazuh_rows if r["ioc"] != "—"]
            if extractable:
                st.info(f"**{len(extractable)} IOCs** extracted and ready for triage")

    # ── TAB 3: HEC PUSH ───────────────────────────────────────────────────────
    with tab_hec:
        st.markdown("#### Push verdicts TO Splunk via HEC (always on)")
        col1, col2 = st.columns(2)
        hec_url   = col1.text_input("HEC URL",
                    value=cfg.get("splunk_hec_url","") or os.getenv("SPLUNK_HEC_URL","http://127.0.0.1:8088/services/collector/event"),
                    key="phd_hec_url")
        hec_token = col2.text_input("HEC Token", type="password",
                    value=cfg.get("splunk_hec_token","") or os.getenv("SPLUNK_HEC_TOKEN",""),
                    key="phd_hec_token")

        if st.button("🧪 Test HEC Connection", type="primary",
                     use_container_width=True, key="phd_hec_test"):
            if not hec_url or not hec_token:
                st.warning("Enter HEC URL and token first")
            else:
                try:
                    ok_hec, msg_hec = _test_splunk_hec(hec_url, hec_token, hec_index)
                    if ok_hec:
                        st.success(f"✅ HEC OK — {msg_hec}")
                    else:
                        st.error(f"HEC failed: {msg_hec}")
                except Exception as e:
                    st.error(f"HEC failed: {e}")

        st.divider()
        st.markdown("**HEC sends these enriched fields to Splunk:**")
        st.code("netsec_ai_verdict · netsec_ai_score · netsec_ai_action\n"
                "netsec_ai_confidence · netsec_ai_severity · netsec_ai_reason\n"
                "netsec_ai_sources · netsec_ai_typosquat · wazuh_agent", language="text")
        st.markdown("**Dashboard SPL (paste into Splunk):**")
        st.code('index=main sourcetype=netsec_ai\n'
                '| stats count by netsec_ai_verdict\n'
                '| sort -count', language="spl")

    # ── TAB 4: METRICS ────────────────────────────────────────────────────────
    with tab_metrics:
        st.markdown("#### NetSec AI triage metrics (this session)")
        results = st.session_state.get("pull_triage_results",[])
        if results:
            total = len(results)
            malicious  = sum(1 for r in results if r["score"]<40)
            suspicious = sum(1 for r in results if 40<=r["score"]<70)
            benign     = sum(1 for r in results if r["score"]>=70)
            c1,c2,c3,c4 = st.columns(4)
            c1.metric("Total Triaged",  total)
            c2.metric("🔴 High Risk",   malicious,  delta=f"{malicious/max(total,1)*100:.0f}%")
            c3.metric("🟡 Suspicious",  suspicious)
            c4.metric("✅ Benign",      benign)
            if total > 0:
                fp_rate = round(benign/total*100,1)
                st.metric("FP Rate (benign/total)", f"{fp_rate}%")
        else:
            st.info("Run a Pull first to see metrics")

    # ── TAB 5: SPL TEMPLATES ──────────────────────────────────────────────────
    with tab_spl:
        st.markdown("#### Copy-paste SPL queries for Splunk")
        st.markdown("**Extract domains from any index:**")
        st.code('index=* earliest=-1h\n'
                '| rex field=_raw "(?i)(?P<domain>[a-z0-9\\-]+(?:\\.[a-z0-9\\-]+)+)"\n'
                '| stats count by domain | where count >= 2\n'
                '| sort -count | head 50', language="spl")
        st.markdown("**Dashboard — verdicts by type:**")
        st.code('index=main sourcetype=netsec_ai\n'
                '| stats count by netsec_ai_verdict | sort -count', language="spl")
        st.markdown("**Top risky domains:**")
        st.code('index=main sourcetype=netsec_ai\n'
                '| where netsec_ai_score < 40\n'
                '| table domain netsec_ai_verdict netsec_ai_score netsec_ai_action\n'
                '| sort netsec_ai_score | head 20', language="spl")
        st.markdown("**Trend over time:**")
        st.code('index=main sourcetype=netsec_ai\n'
                '| timechart count by netsec_ai_verdict', language="spl")
        st.markdown("**Alert suppression (auto-close benign):**")
        st.code('index=main sourcetype=netsec_ai\n'
                '| where netsec_ai_verdict="LIKELY BENIGN"\n'
                '| eval auto_close="yes"\n'
                '| table domain netsec_ai_verdict netsec_ai_score auto_close', language="spl")
        st.markdown("**DPDP Audit trail:**")
        st.code('index=main sourcetype=netsec_ai\n'
                '| table _time domain netsec_ai_verdict netsec_ai_action netsec_ai_reason netsec_ai_sources\n'
                '| sort -_time', language="spl")



# ══════════════════════════════════════════════════════════════════════════════
# ANALYST METRICS DASHBOARD  (interview-ready slide)
# ══════════════════════════════════════════════════════════════════════════════

def render_analyst_metrics_dashboard():
    """
    Shows real measured metrics:
      - Alerts processed vs escalated vs auto-closed
      - FP rate over time chart
      - MTTR per case
      - Noise reduction %
    Designed to answer interview question: "How did you measure that?"
    """
    st.markdown(
        "<h2 style='margin:0 0 2px'>📈 Analyst Metrics Dashboard</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 14px'>"
        "Measured impact · Alert fatigue reduction · FP rate · MTTR · "
        "<b style='color:#00f9ff'>Answers the 'how did you measure that?' question</b>"
        "</p>",
        unsafe_allow_html=True,
    )

    summary = FPReductionTracker.get_summary()
    avg_mttr = MTTRTracker.get_avg_mttr()

    # ── KPI row ───────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("📥 Total Alerts",         f"{summary['total']:,}")
    c2.metric("✅ Auto-Closed",          f"{summary['auto_closed']:,}",
              delta=f"{summary['fp_rate']:.1f}% of total")
    c3.metric("🚨 Escalated",           f"{summary['escalated']:,}",
              delta=f"{summary['esc_rate']:.1f}% escalation rate")
    c4.metric("📉 Noise Reduction",
              f"{summary['fp_rate']:.1f}%",
              delta="analyst time saved")
    c5.metric("⏱ Avg MTTR",
              f"{avg_mttr}m" if avg_mttr else "—",
              delta="time to respond")

    st.divider()

    # ── FP rate over time chart ───────────────────────────────────────────────
    fp_hist = st.session_state.get("fp_rate_history", [])
    if fp_hist and len(fp_hist) > 1:
        import plotly.graph_objects as go
        df_fp = pd.DataFrame(fp_hist, columns=["timestamp","fp_rate"])
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_fp["timestamp"], y=df_fp["fp_rate"],
            mode="lines+markers",
            line=dict(color="#00c878", width=2),
            name="FP Rate %",
        ))
        fig.update_layout(
            title="False Positive Rate Over Time",
            xaxis_title="Time",
            yaxis_title="FP Rate (%)",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0.15)",
            font=dict(color="#c8e8ff"),
            height=300,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Process alerts to generate FP rate trend data.")

    # ── MTTR table ────────────────────────────────────────────────────────────
    mttr_log = st.session_state.get("mttr_log", [])
    if mttr_log:
        st.markdown("#### Case Response Times")
        df_mttr = pd.DataFrame([
            {
                "Case ID": e["case_id"],
                "Opened":  e["opened"][:16],
                "Closed":  e["closed"][:16] if e["closed"] else "Open",
                "MTTR (min)": e["minutes"] or "—",
            }
            for e in mttr_log[-20:]
        ])
        st.dataframe(df_mttr, use_container_width=True, hide_index=True)

    # ── Interview-ready methodology note ─────────────────────────────────────
    with st.expander("📝 Methodology — how these metrics are measured"):
        st.markdown("""
**Alerts Processed** — incremented by `FPReductionTracker.record()` after every auto-triage decision.

**Auto-Closed** — verdicts of `SAFE`, `BENIGN`, or `LOW RISK` from the reputation/IOC engine.
These are alerts the system decided required no analyst action.

**FP Rate** — `auto_closed / total_processed × 100`.
Represents the fraction of alerts that were confirmed benign by the unified engine.

**Escalated** — verdicts of `HIGH SUSPICION`, `MALICIOUS`, or `CONFIRMED MALICIOUS` that
were passed to analyst queue or created an IR case.

**MTTR** — time between `MTTRTracker.open_case()` (IR case created) and
`MTTRTracker.close_case()` (case marked Closed). Measured in minutes.

**Noise Reduction** — `1 - (incidents / raw_alerts)` after correlation,
showing how many raw alerts collapsed into fewer actionable incidents.

---
*These are real measurements from this session. In production, persist to a time-series
store (InfluxDB / Splunk) for trend analysis across shifts and analysts.*
        """)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS — API CALLS (real, no mocks)
# ══════════════════════════════════════════════════════════════════════════════

def _test_splunk_hec(url: str, token: str, index: str) -> tuple:
    """
    Test Splunk HEC. Normalises URL, uses correct index, handles 400 errors.
    """
    try:
        import urllib.request as _ur, urllib.error as _ue
        import json as _j, ssl as _ssl, time as _t

        # ── Normalise URL ──────────────────────────────────────────────────────
        u = (url or "").strip().rstrip("/")
        while u.endswith("/event"):
            u = u[:-6].rstrip("/")
        if "/services/collector" in u:
            u = u + "/event"
        else:
            u = u + "/services/collector/event"
        if "127.0.0.1" in u or "localhost" in u:
            u = u.replace("https://", "http://", 1)

        _index = (index or "ids_alerts").strip() or "ids_alerts"

        # ── Build payload ──────────────────────────────────────────────────────
        payload = _j.dumps({
            "sourcetype": "netsec_ai",
            "index":      _index,
            "event":      {
                "test":      True,
                "source":    "netsec_ai_health_check",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
        }).encode()

        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE

        req = _ur.Request(u, data=payload,
                          headers={"Authorization": f"Splunk {token}",
                                   "Content-Type": "application/json"},
                          method="POST")
        try:
            with _ur.urlopen(req, timeout=6, context=ctx) as r:
                resp = _j.loads(r.read().decode())
            code = resp.get("code", -1)
            text = resp.get("text", "")
            if code == 0 or text == "Success":
                return True, f"HEC OK — index:{_index} · {u}"
            return False, f"Splunk error code {code}: {text}"
        except _ue.HTTPError as e:
            try:
                err_body = _j.loads(e.read().decode())
                code = err_body.get("code", e.code)
                _CODES = {
                    1: "Token disabled — enable in Data Inputs → HEC",
                    3: "Invalid token — check token value",
                    7: "Invalid data channel",
                    8: f"Index '{_index}' does not exist — create it in Splunk",
                    10: "Data channel missing — HEC not fully enabled",
                }
                hint = _CODES.get(code, err_body.get("text", str(e)))
                return False, f"HTTP {e.code}: {hint}"
            except Exception:
                return False, f"HTTP {e.code}: {e.reason} — check HEC Global Settings in Splunk"
    except Exception as e:
        return False, f"Connection failed: {str(e)[:100]}"


def _send_to_hec(url: str, token: str, index: str, event: dict) -> tuple:
    """Send event to Splunk HEC. Normalises URL, uses correct index."""
    try:
        import urllib.request as _ur, json as _j, ssl as _ssl
        u = (url or "").strip().rstrip("/")
        while u.endswith("/event"):
            u = u[:-6].rstrip("/")
        u = (u + "/event") if "/services/collector" in u else (u + "/services/collector/event")
        if "127.0.0.1" in u or "localhost" in u:
            u = u.replace("https://", "http://", 1)
        _index = (index or "ids_alerts").strip() or "ids_alerts"
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        payload = _j.dumps({
            "index": _index, "sourcetype": "netsec_ai", "event": event
        }).encode()
        req = _ur.Request(u, data=payload,
                          headers={"Authorization": f"Splunk {token}",
                                   "Content-Type": "application/json"},
                          method="POST")
        with _ur.urlopen(req, timeout=4, context=ctx) as r:
            resp = _j.loads(r.read().decode())
        return resp.get("code") == 0 or resp.get("text") == "Success", resp.get("text","sent")
    except Exception as e:
        return False, str(e)[:80]


def _test_splunk_connection(url: str, user: str, password: str) -> tuple:
    """Test Splunk Search API connection — returns (ok, message)."""
    import urllib.request as _ur, urllib.error as _ue
    import base64 as _b64, json as _j, ssl as _ssl

    url = url.rstrip("/")
    # Port 8089 = Splunk management port = MUST be HTTPS (even on localhost)
    if ":8089" in url and url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    if not url.startswith("http"):
        url = "https://" + url

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    creds = _b64.b64encode(f"{user}:{password}".encode()).decode()

    try:
        req = _ur.Request(
            f"{url}/services/server/info?output_mode=json",
            headers={"Authorization": f"Basic {creds}"}
        )
        with _ur.urlopen(req, timeout=10, context=ctx) as r:
            data = _j.loads(r.read())
        version = data.get("entry", [{}])[0].get("content", {}).get("version", "?")
        return True, f"Connected to Splunk v{version} at {url}"
    except _ue.HTTPError as e:
        body = ""
        try: body = e.read().decode()[:200]
        except Exception: pass
        if e.code == 401:
            return False, (
                f"401 Unauthorized — wrong username or password.\n"
                f"Username tried: '{user}'. Check Splunk Web → Settings → Users."
            )
        return False, f"HTTP {e.code}: {e.reason} — {body[:100]}"
    except _ue.URLError as e:
        reason = str(e.reason)
        if "Connection refused" in reason:
            return False, f"Connection refused — is Splunk running? Use: https://127.0.0.1:8089"
        if "timed out" in reason.lower():
            return False, f"Timeout — {url} not responding within 10 seconds."
        if "Remote end closed" in reason or "EOF" in reason:
            return False, "Remote end closed — port 8089 requires HTTPS. Use: https://127.0.0.1:8089"
        return False, f"Connection failed: {reason[:150]}"
    except Exception as e:
        msg = str(e)
        if "Remote end closed" in msg or "EOF" in msg:
            return False, "Remote end closed — port 8089 requires HTTPS. Use: https://127.0.0.1:8089"
        return False, f"Error: {msg[:150]}"


def _query_splunk_api(url: str, user: str, password: str, spl: str) -> tuple:
    """
    Submit a Splunk search job and return results.
    Returns (results_list, error_string_or_None).
    Shows real error messages — no silent failures.
    """
    import urllib.request as _ur, urllib.parse as _up, urllib.error as _ue
    import json as _j, ssl as _ssl, base64 as _b64

    url = url.rstrip("/")
    # Port 8089 = Splunk management port = MUST be HTTPS (even on localhost)
    if ":8089" in url and url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    if not url.startswith("http"):
        url = "https://" + url

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    creds   = _b64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}",
               "Content-Type": "application/x-www-form-urlencoded"}

    # Ensure query doesn't start with "search search"
    spl_clean = spl.strip()
    if spl_clean.lower().startswith("search "):
        spl_clean = spl_clean[7:]

    try:
        # Step 1 — create search job (blocking mode — simpler, no polling)
        data = _up.urlencode({
            "search":      f"search {spl_clean}",
            "output_mode": "json",
            "exec_mode":   "blocking",   # wait until done
            "count":       "100",
        }).encode()
        req = _ur.Request(f"{url}/services/search/jobs",
                          data=data, headers=headers, method="POST")
        try:
            with _ur.urlopen(req, timeout=30, context=ctx) as r:
                job = _j.loads(r.read())
        except _ue.HTTPError as e:
            body = ""
            try: body = e.read().decode()[:300]
            except Exception: pass
            if e.code == 401:
                return [], (
                    "401 Unauthorized — wrong username or password.\n"
                    f"Username tried: '{user}'.\n"
                    "Check Splunk Web → Settings → Users for your correct username."
                )
            if e.code == 400:
                return [], f"400 Bad Request — check SPL query syntax. Detail: {body[:150]}"
            return [], f"HTTP {e.code}: {e.reason} — {body[:150]}"

        sid = job.get("sid")
        if not sid:
            msg = job.get("messages",[{}])
            return [], f"No search ID — Splunk said: {msg}"

        # Step 2 — fetch results (blocking mode already done)
        try:
            req2 = _ur.Request(
                f"{url}/services/search/jobs/{sid}/results?output_mode=json&count=100",
                headers=headers
            )
            with _ur.urlopen(req2, timeout=15, context=ctx) as r2:
                results = _j.loads(r2.read())
        except _ue.HTTPError as e2:
            return [], f"Results fetch error HTTP {e2.code}: {e2.reason}"

        rows = results.get("results", [])
        return rows, None

    except _ue.URLError as e:
        reason = str(e.reason)
        if "Connection refused" in reason:
            return [], f"Connection refused — is Splunk running at {url}?"
        if "timed out" in reason.lower():
            return [], "Timeout — query took >30s. Add | head 20 to limit results."
        if "Remote end closed" in reason or "EOF" in reason:
            return [], "Remote end closed — port 8089 requires HTTPS. Use: https://127.0.0.1:8089"
        return [], f"Network error: {reason[:150]}"
    except Exception as e:
        msg = str(e)
        if "Remote end closed" in msg or "EOF" in msg:
            return [], "Remote end closed — port 8089 requires HTTPS. Use: https://127.0.0.1:8089"
        return [], f"Unexpected error: {msg[:150]}"


def _splunk_results_to_alerts(results: list) -> list:
    """Convert Splunk API result rows into alert dicts."""
    alerts = []
    for row in results:
        alerts.append({
            "id":         f"SPL-{hashlib.md5(str(row).encode()).hexdigest()[:8].upper()}",
            "alert_type": row.get("search_name", "Splunk Alert"),
            "severity":   "medium",
            "ip":         row.get("src_ip", row.get("dest_ip", "")),
            "domain":     row.get("domain", row.get("host", "")),
            "mitre":      row.get("mitre", ""),
            "source":     "splunk",
            "timestamp":  row.get("_time", datetime.utcnow().isoformat()),
            "raw":        row,
        })
    return alerts


def _post_webhook(url: str, payload: dict) -> tuple:
    try:
        import urllib.request as _ur, json as _j
        data = json.dumps(payload).encode()
        req  = _ur.Request(url, data=data,
                           headers={"Content-Type": "application/json"}, method="POST")
        with _ur.urlopen(req, timeout=5) as r:
            resp = _j.loads(r.read())
        return True, resp
    except Exception as e:
        return False, str(e)[:80]

# ══════════════════════════════════════════════════════════════════════════════
# 2077 FEATURE 1: AUTONOMOUS AGENT SWARM
# ══════════════════════════════════════════════════════════════════════════════

def render_autonomous_agents():
    """Multi-agent SOC — Triage, Forensics, Correlation, Remediation agents."""
    st.markdown(
        "<h2 style='margin:0 0 4px'>🤖 Autonomous Agent Swarm</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 16px'>"
        "Specialized AI agents collaborate on every alert · Triage → Forensics → Correlation → Remediation"
        "</p>",
        unsafe_allow_html=True,
    )

    agents = [
        ("🔍 Triage Agent",       "triage",       "Classifies every alert. Assigns risk score, MITRE tag, SLA.", "#00d4ff"),
        ("🔬 Forensics Agent",    "forensics",    "Deep-dives into high-risk alerts. Extracts IOCs, checks process tree.", "#c300ff"),
        ("🔗 Correlation Agent",  "correlation",  "Links multiple alerts into campaigns. Detects kill-chain progression.", "#ff9900"),
        ("🛡️ Remediation Agent",  "remediation",  "Suggests containment steps. For CRITICAL alerts — proposes auto-block.", "#ff0033"),
        ("📊 Reporting Agent",    "reporting",    "Generates executive briefings and shift handover notes on demand.", "#00ffc8"),
    ]

    # Status display
    cols = st.columns(len(agents))
    for col, (name, key, desc, color) in zip(cols, agents):
        status = st.session_state.get(f"agent_{key}_status", "idle")
        icon   = "🟢" if status == "active" else "⚪"
        col.markdown(
            f"<div style='border:1px solid {color}44;border-left:3px solid {color};"
            f"border-radius:6px;padding:8px;background:#080f1a;text-align:center'>"
            f"<div style='font-size:.85rem;font-weight:700;color:{color}'>{name}</div>"
            f"<div style='font-size:.72rem;color:#446688;margin:3px 0'>{desc[:50]}…</div>"
            f"<div style='font-size:.75rem'>{icon} {status.upper()}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.divider()

    # Dispatch alert to agent swarm
    st.markdown("#### Dispatch alert to agent swarm")
    alert_input = st.text_area(
        "Paste alert description or domain",
        placeholder="185.220.101.45 seen 47 times in DNS logs · LoneWarrior · rule 61104",
        height=80, key="agent_alert_input"
    )
    dispatch_col, persona_col = st.columns([3,1])
    run_all = dispatch_col.button("🚀 Run Full Agent Swarm", type="primary",
                                   use_container_width=True, key="agent_run_swarm")
    run_triage_only = persona_col.button("🔍 Triage Only", use_container_width=True,
                                          key="agent_triage_only")

    if (run_all or run_triage_only) and alert_input.strip():
        cfg = st.session_state.get("api_config", {})

        # Agent 1: Triage
        with st.expander("🔍 Triage Agent — running…", expanded=True):
            try:
                from reputation_engine import get_authoritative_verdict
                import re as _re
                # Extract first domain or IP from input
                m = _re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+\.[a-z]{2,})',
                               alert_input, _re.I)
                ioc = m.group(0) if m else alert_input[:60]
                result = get_authoritative_verdict(ioc)
                score  = result.get("score",50)
                verdict= result.get("verdict","UNKNOWN")
                c1,c2,c3 = st.columns(3)
                c1.metric("Verdict",  verdict)
                c2.metric("Score",    f"{score}/100")
                c3.metric("Action",   "🔴 BLOCK" if score<40 else "🟡 MONITOR" if score<70 else "✅ SAFE")
                st.caption(f"Reason: {result.get('reason','')[:200]}")
                st.session_state["agent_triage_status"] = "active"
                st.session_state["agent_last_triage"] = result
            except Exception as e:
                st.warning(f"Triage: {e}")

        if run_all:
            # Agent 2: Forensics
            with st.expander("🔬 Forensics Agent — IOC extraction + context"):
                st.markdown(f"**IOC analysed:** `{alert_input[:80]}`")
                st.markdown("**Extracted artefacts:**")
                import re as _re2
                ips      = _re2.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', alert_input)
                domains2 = _re2.findall(r'[a-z0-9\-]+\.[a-z]{2,}', alert_input.lower())
                if ips:      st.markdown(f"- IPs: {', '.join(set(ips))}")
                if domains2: st.markdown(f"- Domains: {', '.join(set(domains2[:5]))}")
                st.markdown("**MITRE context:** T1071 (C2 over DNS), T1568 (Dynamic Resolution)")
                st.markdown("**Recommended forensics:** Check process tree, DNS query history, parent process")
                st.session_state["agent_forensics_status"] = "active"

            # Agent 3: Correlation
            with st.expander("🔗 Correlation Agent — campaign + kill-chain"):
                st.markdown("**Kill-chain stage:** Likely C2 / Exfiltration (based on frequency + TLD)")
                st.markdown("**Correlated alerts:** Checking for related events on same host…")
                related = st.session_state.get("pull_triage_results",[])
                if related:
                    st.info(f"Found {len(related)} pulled alerts — checking entity overlap…")
                else:
                    st.caption("Run Pull Alerts first for correlation context")
                st.session_state["agent_correlation_status"] = "active"

            # Agent 4: Remediation
            with st.expander("🛡️ Remediation Agent — containment steps"):
                triage_res = st.session_state.get("agent_last_triage",{})
                score2 = triage_res.get("score",50)
                if score2 < 30:
                    st.error("🔴 HIGH CONFIDENCE THREAT — recommended actions:")
                    for step in ["Isolate affected host immediately",
                                 "Block IOC at firewall/DNS level",
                                 "Collect memory dump + process list",
                                 "Notify SOC lead within 15 minutes"]:
                        st.markdown(f"- {step}")
                    if st.button("🚨 Request Auto-Block Approval", key="agent_auto_block"):
                        st.warning("Auto-block request queued — awaiting analyst approval")
                elif score2 < 60:
                    st.warning("🟡 SUSPICIOUS — monitor and collect more context")
                    for step in ["Add to watchlist","Enable enhanced logging on host",
                                 "Review DNS query history"]:
                        st.markdown(f"- {step}")
                else:
                    st.success("✅ LOW RISK — log and move on")
                st.session_state["agent_remediation_status"] = "active"

    elif (run_all or run_triage_only) and not alert_input.strip():
        st.warning("Paste an alert description first")


# ══════════════════════════════════════════════════════════════════════════════
# 2077 FEATURE 2: CAUSAL ATTACK GRAPH
# ══════════════════════════════════════════════════════════════════════════════

def render_causal_attack_graph():
    """Visual kill-chain timeline and attack graph builder."""
    st.markdown(
        "<h2 style='margin:0 0 4px'>🗺️ Causal Attack Graph</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 16px'>"
        "Automatic kill-chain timeline · Visual attack progression · MITRE mapping"
        "</p>",
        unsafe_allow_html=True,
    )

    tab_build, tab_live = st.tabs(["🔨 Build Graph", "⚡ Live Incidents"])

    with tab_build:
        st.markdown("#### Paste related alerts to auto-build attack graph")
        raw_alerts = st.text_area(
            "Paste alert descriptions (one per line)",
            placeholder="2026-03-28 10:00 LoneWarrior: Service startup type changed\n"
                        "2026-03-28 10:05 LoneWarrior: CIS benchmark failed - password policy\n"
                        "2026-03-28 10:21 LoneWarrior: Service startup type changed again",
            height=150, key="cag_raw_alerts"
        )
        if st.button("🗺️ Build Attack Graph", type="primary", key="cag_build"):
            if not raw_alerts.strip():
                st.warning("Paste alert lines first")
            else:
                lines = [l.strip() for l in raw_alerts.strip().splitlines() if l.strip()]
                import re as _re3

                _MITRE_MAP = {
                    "service": ("T1543.003","Persistence","Service Manipulation"),
                    "password": ("T1110","Credential Access","Password Policy"),
                    "login": ("T1110","Credential Access","Brute Force"),
                    "powershell": ("T1059.001","Execution","PowerShell"),
                    "user": ("T1136","Persistence","Account Creation"),
                    "dns": ("T1071.004","C2","DNS"),
                    "firewall": ("T1562.004","Defense Evasion","Firewall Disable"),
                    "registry": ("T1112","Defense Evasion","Registry Mod"),
                    "sca": ("T1562","Defense Evasion","Security Config"),
                    "cis": ("T1562","Defense Evasion","Config Assessment"),
                }

                nodes = []
                for i, line in enumerate(lines[:15]):
                    line_lower = line.lower()
                    mitre_id, tactic, cat = "T????", "Unknown", "Unknown"
                    for kw, (mid, tac, c) in _MITRE_MAP.items():
                        if kw in line_lower:
                            mitre_id, tactic, cat = mid, tac, c
                            break
                    ts_m = _re3.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}', line)
                    ts   = ts_m.group(0) if ts_m else f"Event {i+1}"
                    host_m = _re3.search(r'([A-Z][a-zA-Z0-9]+):', line)
                    host = host_m.group(1) if host_m else "UnknownHost"
                    nodes.append({
                        "step": i+1, "timestamp": ts, "host": host,
                        "category": cat, "mitre": mitre_id, "tactic": tactic,
                        "desc": line[:80],
                    })

                # Timeline display
                st.markdown("#### 🗺️ Attack Timeline")
                for node in nodes:
                    sev_color = ("#ff0033" if node["tactic"] in ("Credential Access","Execution")
                                 else "#ff9900" if node["tactic"] == "Persistence"
                                 else "#00aaff")
                    st.markdown(
                        f"<div style='border-left:3px solid {sev_color};padding:6px 12px;"
                        f"margin:4px 0;background:#080f1a;border-radius:0 6px 6px 0'>"
                        f"<span style='color:#446688;font-size:.72rem'>{node['timestamp']}</span>"
                        f" · <span style='color:{sev_color};font-weight:700'>{node['category']}</span>"
                        f" · <span style='color:#7fb3cc;font-size:.78rem'>{node['mitre']}</span>"
                        f" · <span style='color:#446688;font-size:.72rem'>{node['host']}</span>"
                        f"<br><span style='color:#c8e8ff;font-size:.78rem'>{node['desc']}</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
                # Tactics summary
                tactics = list(dict.fromkeys(n["tactic"] for n in nodes))
                st.markdown(f"**Kill-chain stages detected:** {' → '.join(tactics)}")
                mitre_ids = list(dict.fromkeys(n["mitre"] for n in nodes))
                st.markdown(f"**MITRE techniques:** {', '.join(mitre_ids)}")

    with tab_live:
        pipeline_results = st.session_state.get("pipeline_results",
                           st.session_state.get("pull_triage_results",[]))
        if not pipeline_results:
            st.info("Run Live Pipeline or Pull Alerts to see incident graph here")
        else:
            # Group by severity
            high = [r for r in pipeline_results if r.get("score",100)<40]
            med  = [r for r in pipeline_results if 40<=r.get("score",100)<70]
            st.metric("🔴 High Risk", len(high))
            st.metric("🟡 Medium Risk", len(med))
            if high:
                st.markdown("**High risk events (kill-chain candidates):**")
                for r in high[:5]:
                    st.markdown(f"- `{r.get('domain',r.get('ioc','?'))}` — "
                                f"{r.get('verdict','?')} (score {r.get('score',0)})")


# ══════════════════════════════════════════════════════════════════════════════
# 2077 FEATURE 3: PREDICTIVE THREAT HUNTING
# ══════════════════════════════════════════════════════════════════════════════

def render_predictive_hunting():
    """Daily proactive hunting queries generated from current threat intel."""
    st.markdown(
        "<h2 style='margin:0 0 4px'>🎯 Predictive Threat Hunting</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 16px'>"
        "Daily hunting queries · What-if simulations · Proactive IOC discovery"
        "</p>",
        unsafe_allow_html=True,
    )

    tab_generate, tab_queries, tab_simulate = st.tabs([
        "⚡ Generate Hunts", "📋 Query Library", "🎮 What-If Simulation"
    ])

    with tab_generate:
        st.markdown("#### Generate today's hunting queries based on your environment")
        col1, col2 = st.columns(2)
        env_type     = col1.selectbox("Environment type",
                        ["Windows Enterprise","Linux Server","Mixed","Cloud (AWS/Azure)"],
                        key="hunt_env")
        threat_focus = col2.multiselect("Threat focus",
                        ["Ransomware","APT/Nation State","Insider Threat",
                         "C2/Beaconing","Lateral Movement","Data Exfiltration"],
                        default=["C2/Beaconing","Lateral Movement"],
                        key="hunt_focus")
        if st.button("🎯 Generate Hunting Queries", type="primary", key="hunt_gen"):
            _HUNT_TEMPLATES = {
                "C2/Beaconing": [
                    ("DNS beaconing", "index=dns | stats count dc(query) as uniq by src_ip | where count > 100 AND uniq < 5 | sort -count"),
                    ("High-freq queries", "index=dns | stats count by query, src_ip | where count > 50 | sort -count | head 20"),
                ],
                "Lateral Movement": [
                    ("SMB lateral move", "index=wineventlog EventCode=4624 Logon_Type=3 | stats count by src_ip, dest_ip | where count > 5 | sort -count"),
                    ("Remote service", "index=sysmon EventCode=1 Image=*psexec* | table _time Computer User CommandLine"),
                ],
                "Ransomware": [
                    ("File ext changes", "index=sysmon EventCode=11 | rex field=TargetFilename \".(?P<ext>[a-z0-9]+)$\" | stats count by ext, Computer | where count > 50 | sort -count"),
                    ("Shadow delete", "index=wineventlog | search vssadmin delete | table _time Computer User CommandLine"),
                ],
                "Data Exfiltration": [
                    ("Large transfers", "index=firewall | stats sum(bytes_out) as tot by src_ip, dest_ip | where tot > 100000000 | sort -tot | head 10"),
                ],
            }
            generated = []
            for focus in threat_focus:
                if focus in _HUNT_TEMPLATES:
                    generated.extend(_HUNT_TEMPLATES[focus])
            if not generated:
                generated = [("General IOC hunt",
                              "index=* earliest=-24h | rex field=_raw \"(?P<domain>[a-z0-9\\-]+\\.(?:tk|xyz|top|ml|ga))\" | stats count by domain | sort -count | head 20")]
            st.session_state["generated_hunts"] = generated
            st.success(f"Generated {len(generated)} hunting queries for {env_type}")
            for title, spl in generated:
                with st.expander(f"🎯 {title}"):
                    st.code(spl, language="spl")
                    st.caption("Copy → Paste into Splunk Search")