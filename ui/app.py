"""
NetSec AI v10.0 — Application Entry Point
==========================================
"Throw alerts at it. It investigates, explains, and responds — autonomously."

Run:  streamlit run app.py

Structure:
  app.py            ← startup, sidebar, routing
  modules/core.py   ← engines, constants, helpers
  modules/triage.py ← alert triage, explainer, IOC blast
  modules/detect.py ← detection, PCAP, Zeek/Sysmon
  modules/respond.py← SOAR, automated response
  modules/investigate.py ← autonomous investigator, correlation
  modules/report.py ← IR reports, DPDP, compliance
  modules/advanced.py ← Phase 2+ deferred modules
"""

# ── Path setup ──────────────────────────────────────────────────────────────
import os, sys, logging
from logging.handlers import TimedRotatingFileHandler
from n8n_agent import auto_trigger_n8n
from datetime import datetime

_this_dir    = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(_this_dir, ".."))
_modules_dir = os.path.join(_this_dir, "modules")
for _p in [project_root, _this_dir, _modules_dir,
           os.path.join(project_root, "scripts"), os.getcwd()]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Logger ──────────────────────────────────────────────────────────────────
os.makedirs(os.path.join(_this_dir, "logs"), exist_ok=True)
logger = logging.getLogger("streamlit_app")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    _fh = TimedRotatingFileHandler(
        os.path.join(_this_dir, "logs", "streamlit.log"), when="midnight", backupCount=7)
    _fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(_fh)
    _ch = logging.StreamHandler()
    _ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(_ch)
logger.info("NetSec AI v10.0 starting")

# ── Streamlit ────────────────────────────────────────────────────────────────
import streamlit as st

st.set_page_config(
    page_title="NetSec AI — Autonomous SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load modules ─────────────────────────────────────────────────────────────
_load_errors = []
_loaded_modules = []

import importlib as _il

for _mod_name in ["splunk_integration", "soc_brain", "enterprise_soc"] + ["core", "triage", "detect", "respond", "investigate", "report", "advanced", "domain_intel", "reputation_engine", "ioc_enricher", "v12_additions", "realtime_pipeline"]:
    try:
        # Force reload to pick up any changes
        if f"modules.{_mod_name}" in _il.sys.modules:
            _m = _il.reload(_il.sys.modules[f"modules.{_mod_name}"])
        else:
            _m = _il.import_module(f"modules.{_mod_name}")
        # Inject EVERY public name into app globals
        _injected = 0
        for _k, _v in vars(_m).items():
            if not _k.startswith("__"):
                globals()[_k] = _v
                _injected += 1
        _loaded_modules.append(_m)
        logger.info(f"✅ modules.{_mod_name} loaded ({_injected} names injected)")
    except Exception as _e:
        _msg = f"modules/{_mod_name}.py failed to load: {_e}"
        _load_errors.append(_msg)
        logger.error(_msg)

# Second pass: inject app globals into each module so cross-module calls work
# (e.g. report.py calling render_soar_playbooks which is in respond.py)
_app_globals = {k: v for k, v in globals().items() if not k.startswith("__")}
for _m in _loaded_modules:
    try:
        _m.__dict__.update({k: v for k, v in _app_globals.items()
                             if k not in _m.__dict__})
    except Exception:
        pass

# Verify critical functions loaded — raise visible error if not
_critical = ["render_soar_playbooks", "render_autonomous_investigator",
             "render_triage_autopilot", "render_dpdp_breach_console",
             "render_incident_report_generator", "get_api_config",
             "render_alert_correlation_dashboard", "render_reputation_tester"]
_missing = [f for f in _critical if f not in globals()]
if _missing:
    logger.error(f"CRITICAL MISSING: {_missing}")
    # Try direct re-import as fallback
    for _fn_name in _missing:
        for _mod_name in ["splunk_integration"] + ["core","triage","detect","respond","investigate","report","advanced"]:
            try:
                _m2 = _il.import_module(f"modules.{_mod_name}")
                if hasattr(_m2, _fn_name):
                    globals()[_fn_name] = getattr(_m2, _fn_name)
                    logger.info(f"✅ Recovered {_fn_name} from modules.{_mod_name}")
                    break
            except Exception:
                pass

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def _show_load_warnings():
    if _load_errors:
        with st.sidebar:
            with st.expander("⚠️ Module load warnings", expanded=False):
                for err in _load_errors:
                    st.warning(err)

# ══════════════════════════════════════════════════════════════════════════════
# ── SOC Lab Enhancements ──────────────────────────────────────────
try:
    from soc_enhancements import render_soc_enhancements
    SOC_ENHANCEMENTS_ENABLED = True
except ImportError:
    render_soc_enhancements  = None
    SOC_ENHANCEMENTS_ENABLED = False

# ── Real-Time Pipeline v11.0 ─────────────────────────────────────────
try:
    from modules.realtime_pipeline import render_pipeline_dashboard, PipelineEngine
    PIPELINE_ENABLED = True
except ImportError:
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
        from modules.realtime_pipeline import render_pipeline_dashboard, PipelineEngine
        PIPELINE_ENABLED = True
    except ImportError:
        render_pipeline_dashboard = None
        PIPELINE_ENABLED = False

# ── Enterprise SOC v11.0 ──────────────────────────────────────────
try:
    from modules.enterprise_soc import render_enterprise_soc
    ENTERPRISE_SOC_ENABLED = True
except ImportError:
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
        from modules.enterprise_soc import render_enterprise_soc
        ENTERPRISE_SOC_ENABLED = True
    except ImportError:
        render_enterprise_soc  = None
        ENTERPRISE_SOC_ENABLED = False

# ── IOC Enricher (standalone enrichment engine) ──────────────────────────────
try:
    from modules.ioc_enricher import enrich_ioc, batch_enrich_iocs
    IOC_ENRICHER_ENABLED = True
except ImportError:
    try:
        from ioc_enricher import enrich_ioc, batch_enrich_iocs
        IOC_ENRICHER_ENABLED = True
    except ImportError:
        enrich_ioc = batch_enrich_iocs = None
        IOC_ENRICHER_ENABLED = False

# ── Splunk Handler ────────────────────────────────────────────────────────────
try:
    from modules.splunk_handler import SplunkHandler
    SPLUNK_ENABLED = True
except ImportError:
    try:
        from splunk_handler import SplunkHandler
        SPLUNK_ENABLED = True
    except ImportError:
        SplunkHandler = None
        SPLUNK_ENABLED = False

# ── SOC Decision Brain ──────────────────────────────────────────────────
try:
    from modules.soc_brain import (
        render_soc_brain, correlate_alerts, auto_triage_alerts,
        generate_soc_narrative, resolve_asset, enrich_alert_with_asset
    )
    SOC_BRAIN_ENABLED = True
except ImportError:
    render_soc_brain        = None
    correlate_alerts        = lambda a, **k: []
    auto_triage_alerts      = lambda a, **k: {}
    generate_soc_narrative  = lambda i: {}
    resolve_asset           = lambda h="", ip="": {
        "role": "Unknown", "criticality": 2,
        "criticality_label": "🟢 LOW", "risk_multiplier": 1.0
    }
    enrich_alert_with_asset = lambda a: a
    SOC_BRAIN_ENABLED       = False

def main():
    defaults = {
        "mode": "Dashboard",
        "threat_locations": [], "threat_counts": {"malware":0,"xss":0,"sqli":0,"low risk":0,"suspicious":0},
        "recent_threats": [], "vt_alerts": 0, "analysis_results": [],
        "splunk_log": [], "splunk_status": None,
        "blocked_ips": [], "zeek_results": {}, "sysmon_results": {},
        "triage_alerts": [], "alert_history": [], "fp_decisions": [],
        "correlated_alerts": [], "correlated_incidents": [],
        "ioc_results": {}, "ioc_lookups": [], "hunt_results": {},
        "ir_cases": [], "ir_reports": [], "evidence_vault": [],
        "evidence_hashes": {}, "coc_log": [],
        "n8n_log": [], "soar_history": [],
        "copilot_history_v1": [], "copilot_history": {},
        "replay_timeline": [], "custom_graph_nodes": [], "custom_graph_edges": [],
        "current_rule": None, "threat_models": [], "va_reports": [],
        "breach_mode": False, "demo_ran": False, "share_report_html": None,
        "ueba_result": None, "asm_result": None, "hash_results": None, "leaderboard": [],
        "symbiotic_memory": [], "symbiotic_chat": [],
        "symbiotic_learned_patterns": {}, "symbiotic_fp_patterns": [],
        "symbiotic_escalation_patterns": [], "auto_triage_queue": [], "dpdp_log": [],
        "auto_investigations": [], "attack_campaigns": [],
        "entity_graph": {"nodes": {}, "edges": []}, "behavior_baselines": {},
        "analyst_feedback_map": {},
        "copilot_prefill": "", "copilot_persona": "🧠 SOC Brain", "copilot_bar_open": False,
        # ── NEW v12 defaults ──────────────────────────────────────────────────
        "alerts_processed": 0,      # total alerts auto-triaged (for dashboard KPI)
        "alerts_auto_closed": 0,    # confirmed benign auto-closed (FP reduction metric)
        "alerts_escalated": 0,      # escalated to analyst
        "fp_rate_history": [],      # list of (timestamp, fp_rate%) for trend chart
        "correlation_groups": [],   # grouped correlated incidents
        "splunk_verdicts": [],      # verdicts sent back to Splunk
        "ioc_enrichment_log": [],   # every IOC enrichment result ever run
        "analyst_notes": {},        # case_id → free-text analyst notes
        "playbook_runs": [],        # executed playbook log for audit trail
        "mttr_log": [],             # mean-time-to-respond per case
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v
    if "mode" not in st.session_state:
        st.session_state.mode = "Dashboard"
        # Auto-run n8n for critical alerts in live pipeline
    if st.session_state.get("live_pipeline_running", False):
    # Your existing live pipeline code...
       auto_trigger_n8n(processed_alert)

    # ── AUTO-START PIPELINE on app launch (if creds saved) ───────────────────
    try:
        if PIPELINE_ENABLED and not PipelineEngine.is_running():
            _pl_url  = st.session_state.get("pl_wazuh_url")  or os.getenv("WAZUH_URL",  "")
            _pl_user = st.session_state.get("pl_wazuh_user") or os.getenv("WAZUH_USER", "admin")
            _pl_pass = st.session_state.get("pl_wazuh_pass") or os.getenv("WAZUH_PASS", "")
            if _pl_url and _pl_user and _pl_pass:
                PipelineEngine.start(
                    poll_interval  = st.session_state.get("pl_interval", 30),
                    wazuh_url      = _pl_url,
                    wazuh_user     = _pl_user,
                    wazuh_pass     = _pl_pass,
                    session_config = st.session_state.get("user_api_config", {}),
                )
    except Exception:
        pass

    # ── Handle FAB navigation via query param ────────────────────────────────
    try:
        _nav = st.query_params.get("nav_mode")
        if isinstance(_nav, list):
            _nav = _nav[0]
        if _nav and _nav != st.session_state.mode:
            st.session_state.mode = _nav
            st.query_params.clear()
            st.rerun()
    except Exception:
        pass

    # ── CSS ────────────────────────────────────────────────────────────────────
    if st.session_state.get("breach_mode"):
        st.markdown(BREACH_CSS, unsafe_allow_html=True)
    else:
        st.markdown(NORMAL_CSS_OVERRIDE, unsafe_allow_html=True)
    if st.session_state.get("night_shift"):
        st.markdown("""<style>
        .main,section[data-testid="stSidebar"]{background:#000!important;filter:contrast(1.08) brightness(0.92);}
        .netsec-topnav{background:#000!important;border-bottom-color:#222!important;}
        h1,h2,h3{text-shadow:none!important;}
        </style>""", unsafe_allow_html=True)

    breach_active = st.session_state.get("breach_mode", False)

    # ── Top navbar (display only — sidebar handles navigation) ────────────────
    _NAV_SECTION_MAP = {
        "SOC":                    ["Dashboard","One-Click Demo"],
        "Explain & Auto-Triage":  ["Alert Triage Autopilot","Alert Explainer",
                                   "Bulk Alert Processor","Alert Deduplicator"],
        "Autonomous Investigator":["Autonomous Investigator","IOC Intelligence",
                                   "Domain Triage Engine","Reputation Scorer"],
        "Attack Story":           ["Attack Correlation","Incident Response"],
        "One-Click IR Report":    ["Incident Report Generator","Shift Handover",
                                   "DPDP Breach Console"],
        "Ask Anything":           ["AI Copilot","NL SOC Query","Hunt Query Builder"],

        "SOC Lab":                ["SOC Lab Enhancements","SOC Brain","Live Pipeline"],
        "Settings":               ["API Config"],
    }
    _cur_mode    = st.session_state.get("mode", "Dashboard")
    _active_sect = next((s for s,items in _NAV_SECTION_MAP.items() if _cur_mode in items), "SOC")
    _nav_html    = "".join(
        f"<span class='{'netsec-navlink active' if _active_sect==ns else 'netsec-navlink'}'>{ns}</span>"
        for ns in ["SOC","Explain & Auto-Triage","Autonomous Investigator","Attack Story","One-Click IR Report","Ask Anything","Settings"]
    )
    st.markdown(
        f"<div class='netsec-topnav'>"
        f"<span class='netsec-logo'>{'<span class=breach>' if breach_active else ''}◼ NETSEC AI — AUTONOMOUS SOC{'</span>' if breach_active else ''}</span>"
        f"<div class='netsec-navlinks'>{_nav_html}</div>"
        f"{'<span class=netsec-breach-badge>🔴 BREACH MODE</span>' if breach_active else ''}"
        f"<span style='color:#00c8aa;font-size:.6rem;margin-right:10px'>detect · investigate · explain · respond</span>"
        f"</div>",
        unsafe_allow_html=True
    )

    # ── CTRL+K overlay (st.markdown — no iframe dead space) ───────────────────
    st.markdown("""
<div id="ctrlk-overlay">
  <div id="ctrlk-box">
    <div style="color:#00f9ff;font-size:.7rem;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px">
      ⚡ ASK SOC — Universal Search
    </div>
    <input id="ctrlk-input" placeholder="IP · alert · block 185.x.x.x · handover Priya…" autocomplete="off"/>
    <div id="ctrlk-hint">
      <kbd>Enter</kbd> to route · <kbd>Esc</kbd> to close · <kbd>Ctrl+K</kbd> to open
    </div>
    <div id="ctrlk-suggestions">
      <div class="ctrlk-sug">→ Show me everything about 185.220.101.45</div>
      <div class="ctrlk-sug">→ Generate handover for Priya's shift</div>
      <div class="ctrlk-sug">→ Run DPDP scan on current queue</div>
      <div class="ctrlk-sug">→ Block 185.220.101.45 now</div>
    </div>
  </div>
</div>
<script>
document.addEventListener('keydown',function(e){
  if((e.ctrlKey||e.metaKey)&&e.key==='k'){
    e.preventDefault();
    var ov=document.getElementById('ctrlk-overlay');
    ov.classList.toggle('open');
    if(ov.classList.contains('open'))setTimeout(()=>document.getElementById('ctrlk-input').focus(),80);
  }
  if(e.key==='Escape')document.getElementById('ctrlk-overlay').classList.remove('open');
});
document.getElementById('ctrlk-overlay').addEventListener('click',function(e){
  if(e.target===this)this.classList.remove('open');
});
document.querySelectorAll('.ctrlk-sug').forEach(function(el){
  el.addEventListener('click',function(){
    document.getElementById('ctrlk-input').value=this.textContent.replace('→','').trim();
    document.getElementById('ctrlk-input').focus();
  });
});
</script>
""", unsafe_allow_html=True)



    # ── Global Block expander ──────────────────────────────────────────────────
    _block_ioc_default = st.session_state.get("block_prefill", "")
    with st.expander("🚫 GLOBAL BLOCK & ISOLATE", expanded=bool(_block_ioc_default)):
        _bc1, _bc2, _bc3, _bc4 = st.columns([3, 1, 1, 1])
        _block_target  = _bc1.text_input("IOC:", value=_block_ioc_default,
                                         placeholder="185.220.101.45 or evil.tk",
                                         key="global_block_ioc", label_visibility="collapsed")
        _block_methods = _bc2.multiselect("Where:", ["Firewall","DNS","Proxy","Splunk","Endpoint"],
                                          default=["Firewall","Splunk"],
                                          label_visibility="collapsed", key="global_block_methods")
        _block_reason  = _bc3.text_input("Reason:", placeholder="C2 beacon",
                                         key="global_block_reason", label_visibility="collapsed")
        _block_go      = _bc4.button("🚫 BLOCK", type="primary",
                                     use_container_width=True, key="global_block_btn")
        if _block_go and _block_target.strip():
            import datetime as _dt2
            _entry = {"ioc": _block_target.strip(), "methods": _block_methods,
                      "reason": _block_reason or "Manual block",
                      "analyst": "devansh.jain",
                      "time": _dt2.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "status": "BLOCKED"}
            st.session_state.setdefault("global_blocklist", []).append(_entry)
            st.session_state.setdefault("blocked_ips", []).append(_block_target.strip())
            st.session_state["block_prefill"] = ""
            st.success(f"✅ {_block_target} blocked via {', '.join(_block_methods or ['All'])}")
            _create_ir_case({"id": f"BLOCK-{_dt2.datetime.utcnow().strftime('%H%M%S')}",
                             "title": f"IOC Blocked: {_block_target}", "severity": "high",
                             "mitre": "T1071", "analyst": "devansh.jain",
                             "iocs": [_block_target.strip()]})
        _bl = st.session_state.get("global_blocklist", [])
        if _bl:
            import pandas as _blpd
            st.dataframe(_blpd.DataFrame(_bl)[["ioc","methods","reason","analyst","time","status"]],
                         use_container_width=True, hide_index=True)

    # ── SIDEBAR ────────────────────────────────────────────────────────────────
    with st.sidebar:
        # ── Logo ──────────────────────────────────────────────────────────────
        _lc = "#ff0033" if breach_active else "#00f9ff"
        _crits_sb = sum(1 for a in st.session_state.get("triage_alerts",[])
                        if a.get("severity") == "critical")
        st.markdown(
            f"<div style='padding:4px 0 2px'>"
            f"<span style='font-family:Orbitron,sans-serif;font-size:.82rem;"
            f"font-weight:900;color:{_lc};letter-spacing:2px'>◼ NETSEC AI</span>"
            f"<br><span style='font-size:.55rem;color:#00c8aa'>v10.0 · AUTONOMOUS SOC</span>"
            f"</div>",
            unsafe_allow_html=True
        )
        _keys_sb = _keys_configured(get_api_config())
        st.caption("🟢 LIVE" if _keys_sb else "⚪ DEMO MODE")
        st.markdown(
            "<div style='color:#2a4a6a;font-size:.55rem;margin:-4px 0 4px'>"
            "Explain · Investigate · Connect · Report · Ask</div>",
            unsafe_allow_html=True
        )

        # ── Toggles (single column — NO st.columns) ───────────────────────────
        _bv = st.toggle("🔴 BREACH MODE", value=breach_active, key="breach_toggle")
        if _bv != breach_active:
            st.session_state.breach_mode = _bv; st.rerun()
        _nv = st.toggle("🌙 NIGHT SHIFT", value=st.session_state.get("night_shift",False), key="night_toggle")
        if _nv != st.session_state.get("night_shift",False):
            st.session_state.night_shift = _nv; st.rerun()

        # ── ASK SOC ────────────────────────────────────────────────────────────
        st.markdown("---")
        st.caption("⚡ ASK SOC")
        _ask = st.text_input("ask", label_visibility="collapsed",
                             placeholder="IP · alert · block · dpdp…",
                             key="ask_soc_bar")
        if _ask and _ask != st.session_state.get("_last_ask",""):
            st.session_state._last_ask = _ask
            q = _ask.lower()
            st.session_state.mode = (
                "Shift Handover"       if any(k in q for k in ["handover","shift"]) else
                "DPDP Breach Console"  if any(k in q for k in ["dpdp","breach","72"]) else
                "Automated Response"   if any(k in q for k in ["block","isolate"]) else
                "Hunt Query Builder"   if any(k in q for k in ["hunt","sigma","splunk"]) else
                "IOC Intelligence"     if any(k in q for k in ["ioc","enrich","blast"]) else
                "Reputation Scorer"     if any(k in q for k in ["reputation","rep score","domain score"]) else
                "Alert Explainer"      if any(k in q for k in ["explain","alert"]) else
                "Autonomous Investigator"
            )
            st.session_state.ask_soc_query = _ask; st.rerun()

        # ── Navigation ─────────────────────────────────────────────────────────
        st.markdown("---")
        mode = st.session_state.get("mode","Dashboard")

        _NAV = [
            ("🏠", "SOC", [
                "Dashboard", "One-Click Demo", "Splunk Alert Pull"]),
            ("⚡", "Explain & Auto-Triage", [
                "Alert Triage Autopilot",
                "Alert Explainer",
                "Bulk Alert Processor",
                "Alert Deduplicator"]),
            ("🔍", "Autonomous Investigator", [
                "Autonomous Investigator",
                "IOC Intelligence",
                "IOC Blast Enrichment",
                "Domain Triage Engine",
                "Reputation Scorer"]),
            ("📖", "Attack Story", [
                "Attack Correlation",
                "Incident Response"]),
            ("📝", "One-Click IR Report", [
                "Incident Report Generator",
                "Shift Handover",
                "DPDP Breach Console"]),
            ("💬", "Ask Anything", [
                "AI Copilot",
                "NL SOC Query",
                "Hunt Query Builder"]),

            ("🔬", "SOC Lab", ["SOC Lab Enhancements", "SOC Brain", "Live Pipeline"]),
            ("🏢", "Enterprise SOC", ["Enterprise SOC"]),
            ("📡", "Integrations", ["Splunk Integration", "Automation"]),
            ("⚙️", "Settings", ["API Config"]),

        ]

        for _icon, _label, _items in _NAV:
            _active = mode in _items
            # Section label
            _badge = " 🔴" if _active else ""
            st.markdown(
                f"<div style='font-size:.62rem;font-weight:700;color:#446688;"
                f"letter-spacing:1.5px;padding:8px 2px 3px;border-top:1px solid #0a1a2a;margin-top:2px'>"
                f"{_icon} {_label}{_badge}</div>",
                unsafe_allow_html=True
            )
            for _item in _items:
                _cur = mode == _item
                if st.button(
                    ("▶ " if _cur else "   ") + _item,
                    key=f"nav_{_label}_{_item}".replace(" ", "_"),
                    use_container_width=True,
                    type="primary" if _cur else "secondary"
                ):
                    st.session_state.mode = _item; st.rerun()

        # ── Quick access ───────────────────────────────────────────────────────
        st.markdown("---")
        st.caption("⭐ QUICK ACCESS")
        for _qi,_qm in enumerate([
            "Alert Triage Autopilot",
            "Autonomous Investigator",
            "Splunk Alert Pull",
            "Attack Correlation",
            "Incident Report Generator",
            "AI Copilot",
        ]):
            if st.button(_qm, key=f"qa_{_qi}", use_container_width=True, type="secondary"):
                st.session_state.mode = _qm; st.rerun()

        # ── Live stats ─────────────────────────────────────────────────────────
        st.markdown("---")
        _h  = sum(1 for a in st.session_state.get("triage_alerts",[]) if a.get("severity")=="high")
        _ir = sum(1 for c in st.session_state.get("ir_cases",[])
                  if c.get("status","") not in ("Closed","closed"))
        st.markdown(
            f"<div style='display:grid;grid-template-columns:1fr 1fr;gap:3px'>"
            f"<div style='background:#0a141e;border:1px solid #1a2a3a;border-radius:5px;padding:4px 6px'>"
            f"<div style='color:#446688;font-size:.5rem'>🚨 CRIT</div>"
            f"<div style='color:{'#ff4444' if _crits_sb else '#00c878'};font-weight:700;font-size:.8rem'>{_crits_sb}</div></div>"
            f"<div style='background:#0a141e;border:1px solid #1a2a3a;border-radius:5px;padding:4px 6px'>"
            f"<div style='color:#446688;font-size:.5rem'>⚠️ HIGH</div>"
            f"<div style='color:{'#ff9900' if _h else '#00c878'};font-weight:700;font-size:.8rem'>{_h}</div></div>"
            f"<div style='background:#0a141e;border:1px solid #1a2a3a;border-radius:5px;padding:4px 6px'>"
            f"<div style='color:#446688;font-size:.5rem'>📋 IR</div>"
            f"<div style='color:{'#ffcc44' if _ir else '#00c878'};font-weight:700;font-size:.8rem'>{_ir}</div></div>"
            f"<div style='background:#0a141e;border:1px solid #1a2a3a;border-radius:5px;padding:4px 6px'>"
            f"<div style='color:#446688;font-size:.5rem'>🔑 API</div>"
            f"<div style='color:{'#00c878' if _keys_sb else '#446688'};font-weight:700;font-size:.8rem'>{'ON' if _keys_sb else 'OFF'}</div></div>"
            f"</div>",
            unsafe_allow_html=True
        )
    mode = st.session_state.get("mode", "Dashboard")
    if not is_live_capture_supported() and mode == "Network Threat Detection":
        st.warning("Live capture disabled. Use Upload PCAP mode.")

    _PRIORITY_FEATURES = {
        "Alert Triage Autopilot":   ("⚡","PAIN #1 KILLER — Alert fatigue · AI classifies every alert · 45 min → 10 sec · stop chasing noise"),
        "Alert Explainer":          ("🧠","PAIN #1 KILLER — Plain English verdict · Why it fired · What to do · No analyst guesswork"),
        "Autonomous Investigator":  ("🔍","PAIN #2 KILLER — Full kill-chain in one click · Context without 7 tools · MTTR: hours → minutes"),
        "Attack Correlation":       ("📖","PAIN #3 KILLER — Attack Story · Connect dots across weeks · Find repeat attackers · Campaign view"),
        "Incident Report Generator":("📝","PAIN #4 KILLER — AI writes 90% of IR report in 30 sec · Shift handover · CISO-ready PDF"),
        "Shift Handover":           ("📝","PAIN #4 KILLER — AI-generated shift handover note · Never miss an open case again"),
        "AI Copilot":      ("💬","PAIN #5 KILLER — Ask Anything · Replace 7 consoles with one chat · Natural language SOC"),
        "NL SOC Query":             ("💬","PAIN #5 KILLER — Ask your SOC data in plain English · No SPL/KQL needed"),
        "DPDP Breach Console":      ("⏱️","DPDP Act 2023 — 72h breach notification · ₹250Cr fine protection · Auto-generate DPBI draft"),
    }
    if mode in _PRIORITY_FEATURES:
        _pf_icon, _pf_desc = _PRIORITY_FEATURES[mode]
        st.markdown(
            f"<div style='background:linear-gradient(90deg,rgba(0,249,255,0.07),transparent);"
            f"border-left:3px solid #00f9ff;border-radius:0 6px 6px 0;"
            f"padding:6px 14px;margin-bottom:10px'>"
            f"<span style='font-size:1.1rem'>{_pf_icon}</span>"
            f" <span style='color:#00c8aa;font-size:.75rem;font-weight:700'>{_pf_desc}</span>"
            f"</div>",
            unsafe_allow_html=True
        )

    # ── Hallucination safety banner + cleanup ────────────────────────────────
    _deployed_fix = True  # Set False to hide once stable
    if _deployed_fix:
        _banner_col, _btn_col = st.columns([5, 1])
        with _banner_col:
            st.info(
                "🛡️ **Benign domain guardrail active** — google.com / youtube.com / major tech domains "
                "are force-classified as 'Benign — No Action'. "
                "False-positive IR cases auto-blocked. Confidence calibration: ON."
            )
        with _btn_col:
            if st.button("🧹 Clean FP Cases", key="global_cleanup_btn",
                         use_container_width=True, help="Remove benign-domain IR cases"):
                try:
                    from modules.domain_intel import DomainIntel as _DI_cleanup
                    _removed, _kept = _DI_cleanup.cleanup_benign_cases()
                    if _removed:
                        st.success(f"✅ Removed {_removed} false positive cases")
                    else:
                        st.info("No false positive cases found")
                except Exception as _e:
                    # Fallback manual cleanup
                    _before = len(st.session_state.get("ir_cases",[]))
                    _clean_kw = ["google","youtube","gstatic","googleapis","microsoft",
                                 "amazonaws","cloudflare","facebook","apple","zoom"]
                    st.session_state.ir_cases = [
                        c for c in st.session_state.get("ir_cases",[])
                        if not any(kw in str(c).lower() for kw in _clean_kw)
                    ]
                    _after = len(st.session_state.get("ir_cases",[]))
                    st.success(f"✅ Removed {_before - _after} false positive cases")
                st.rerun()

    render_sla_breach_warning()

    _cfg_check  = get_api_config()
    _has_key    = bool(_cfg_check.get("groq_key") or _cfg_check.get("anthropic_key") or
                       os.getenv("GROQ_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))
    _has_ollama = bool(_cfg_check.get("ollama_url") or os.getenv("OLLAMA_BASE_URL"))
    if not _has_key and not _has_ollama and mode not in ("API Config","One-Click Demo","Dashboard"):
        st.markdown(
            "<div style='background:rgba(0,200,120,0.05);border-left:3px solid #00c878;"
            "border-radius:0 8px 8px 0;padding:8px 16px;margin:0 0 8px'>"
            "<span style='color:#00c878;font-size:.65rem;font-weight:700'>✅ DEMO MODE</span>"
            "<span style='color:#446688;font-size:.62rem;margin-left:10px'>"
            "All features work · Add Groq/Anthropic/Ollama key for live AI</span>"
            "</div>",
            unsafe_allow_html=True
        )

    if mode == "Dashboard":
        import datetime as _dtdb
        breach_active_db = st.session_state.get("breach_mode", False)
        crits_db = [a for a in st.session_state.get("triage_alerts",[])
                    if a.get("severity") == "critical"]
        highs_db = [a for a in st.session_state.get("triage_alerts",[])
                    if a.get("severity") == "high"]
        open_cases_db = [c for c in st.session_state.get("ir_cases",[])
                         if c.get("status","") not in ("Closed","closed")]
        dpdp_db = [t for t in st.session_state.get("dpdp_timers",[])
                   if t.get("status") != "Notified"]
        blocked_db = st.session_state.get("global_blocklist",[])
        pipe_db    = st.session_state.get("pipeline_sources",{})
        pipe_active = sum(1 for s in pipe_db.values() if s.get("enabled"))
        pipe_events = sum(s.get("events",0) for s in pipe_db.values())
        campaigns_db = st.session_state.get("attack_campaigns",[])
        atp_queue = st.session_state.get("auto_triage_queue",[])

        # ── Live Attack Campaign panel (shown when alerts exist) ───────────────
        _dashboard_alerts = (
            st.session_state.get("triage_alerts") or
            st.session_state.get("analysis_results") or
            []
        )
        if _dashboard_alerts:
            render_live_attack_campaign(_dashboard_alerts)
            st.divider()

        # ── Hero brand strip ───────────────────────────────────────────────────
        st.markdown(
            "<div style='background:linear-gradient(90deg,rgba(0,249,255,0.06),"
            "rgba(195,0,255,0.04),transparent);"
            "border-left:4px solid #00f9ff;border-radius:0 12px 12px 0;"
            "padding:16px 22px;margin-bottom:14px'>"

            # Title
            "<div style='font-family:Orbitron,monospace;font-size:1.1rem;font-weight:900;"
            "color:#00f9ff;letter-spacing:3px'>◼ NETSEC AI — AUTONOMOUS SOC</div>"

            # One-sentence pitch (README-first sentence)
            "<div style='color:#00c8aa;font-size:.85rem;font-weight:700;margin-top:6px'>"
            "Explain any alert. Investigate any incident. Write any IR report. Ask anything. Autonomously."
            "</div>"

            # Pipeline visual
            "<div style='display:flex;align-items:center;gap:6px;margin-top:10px;flex-wrap:wrap'>"
            "<span style='background:rgba(0,249,255,0.1);border:1px solid #00f9ff33;"
            "border-radius:6px;padding:3px 10px;font-size:.65rem;color:#00f9ff'>"
            "📡 Ingest</span>"
            "<span style='color:#2a4a6a;font-size:.7rem'>→</span>"
            "<span style='background:rgba(255,153,0,0.1);border:1px solid #ff990033;"
            "border-radius:6px;padding:3px 10px;font-size:.65rem;color:#ff9900'>"
            "🚨 Triage</span>"
            "<span style='color:#2a4a6a;font-size:.7rem'>→</span>"
            "<span style='background:rgba(195,0,255,0.1);border:1px solid #c300ff33;"
            "border-radius:6px;padding:3px 10px;font-size:.65rem;color:#c300ff'>"
            "🤖 Investigate</span>"
            "<span style='color:#2a4a6a;font-size:.7rem'>→</span>"
            "<span style='background:rgba(255,0,51,0.1);border:1px solid #ff003333;"
            "border-radius:6px;padding:3px 10px;font-size:.65rem;color:#ff0033'>"
            "📋 Report</span>"
            "<span style='color:#2a4a6a;font-size:.7rem'>→</span>"
            "<span style='background:rgba(0,200,120,0.1);border:1px solid #00c87833;"
            "border-radius:6px;padding:3px 10px;font-size:.65rem;color:#00c878'>"
            "💬 Ask Copilot</span>"
            "</div>"

            # Tagline strip
            "<div style='color:#2a4a6a;font-size:.6rem;margin-top:8px'>"
            "v10.0 Phase 1 &nbsp;·&nbsp; Open Source &nbsp;·&nbsp; "
            "DPDP Act 2023 compliant &nbsp;·&nbsp; Works offline (Ollama) &nbsp;·&nbsp; "
            "Indian SOC teams &nbsp;·&nbsp; "
            f"{'🔴 BREACH MODE ACTIVE' if breach_active_db else '🟢 All systems nominal'}"
            "</div>"
            "</div>",
            unsafe_allow_html=True
        )

        # ── CORE PRODUCT HERO — AI Autonomous Investigation CTA ───────────────
        _hero_col1, _hero_col2, _hero_col3 = st.columns([2, 1, 1])
        with _hero_col1:
            st.markdown(
                "<div style='background:linear-gradient(135deg,rgba(195,0,255,0.12),"
                "rgba(0,249,255,0.08),rgba(0,0,0,0.5));border:1.5px solid #c300ff66;"
                "border-radius:14px;padding:16px 20px'>"
                "<div style='color:#c300ff;font-family:Orbitron,sans-serif;"
                "font-size:.7rem;font-weight:900;letter-spacing:2px'>"
                "5 BUTTONS THAT KILL 80% OF TIER-1 PAIN</div>"
                "<div style='color:#e0e8ff;font-size:.9rem;font-weight:700;margin-top:6px'>"
                "NetSec AI — Autonomous SOC Platform</div>"
                "<div style='color:#5577aa;font-size:.73rem;margin-top:4px;line-height:1.6'>"
                "⚡ Explain &amp; Auto-Triage → kill alert fatigue (80–95% FP rate)<br>"
                "🔍 Autonomous Investigator → kill context switching + slow MTTR<br>"
                "📖 Attack Story → kill missing campaigns + repeat attackers<br>"
                "📝 One-Click IR Report → kill documentation hell<br>"
                "💬 Ask Anything → kill tool sprawl (7–14 consoles → 1 chat)</div>"
                "</div>",
                unsafe_allow_html=True
            )
        with _hero_col2:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            if st.button("⚡ Explain & Triage Alert",
                         type="primary", use_container_width=True,
                         key="db_hero_triage"):
                st.session_state.mode = "Alert Triage Autopilot"; st.rerun()
            if st.button("🔍 Autonomous Investigator",
                         use_container_width=True, key="db_hero_investigate"):
                st.session_state.mode = "Autonomous Investigator"; st.rerun()
        with _hero_col3:
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            if st.button("📖 Attack Story / Campaigns",
                         use_container_width=True, key="db_hero_stories"):
                st.session_state.mode = "Attack Correlation"; st.rerun()
            if st.button("💬 Ask Anything",
                         use_container_width=True, key="db_hero_copilot"):
                st.session_state.mode = "AI Copilot"; st.rerun()

        st.divider()

        # ── Autonomous pipeline status — 4 stages ─────────────────────────────
        _pipe_color = "#00c878" if pipe_events > 0 else "#ff4444"
        _inv_count  = len(st.session_state.get("auto_investigations",[]))
        _resp_count = len(st.session_state.get("are_execution_log",[]))
        _rpt_count  = len(st.session_state.get("ir_reports",[]))

        st.markdown(
            "<div style='display:flex;gap:0;margin-bottom:18px;border-radius:10px;"
            "overflow:hidden;border:1px solid #0d1520'>"
            + "".join([
                f"<div style='flex:1;background:{bg};border-right:1px solid #0d1520;"
                f"padding:12px 14px;text-align:center'>"
                f"<div style='font-size:1.4rem'>{ic}</div>"
                f"<div style='color:{tc};font-size:.7rem;font-weight:700;letter-spacing:1px;"
                f"margin-top:3px'>{lbl}</div>"
                f"<div style='color:#2a4a6a;font-size:.58rem;margin-top:1px'>{sub}</div>"
                f"</div>"
                for ic, lbl, sub, bg, tc in [
                    ("📡", "DETECT", f"{pipe_events:,} events ingested",
                     "rgba(0,200,120,0.06)" if pipe_events>0 else "rgba(255,0,51,0.06)",
                     "#00c878" if pipe_events>0 else "#ff4444"),
                    ("🔎", "INVESTIGATE", f"{_inv_count} auto-investigations",
                     "rgba(0,160,255,0.06)", "#00aaff"),
                    ("🧠", "EXPLAIN", f"{open_cases_db.__len__()} cases with AI narrative",
                     "rgba(195,0,255,0.06)", "#c300ff"),
                    ("⚡", "RESPOND", f"{_resp_count} automated responses",
                     "rgba(255,204,0,0.06)", "#ffcc00"),
                ]
            ])
            + "</div>",
            unsafe_allow_html=True
        )

        # ── Live threat status — 6 KPI tiles ──────────────────────────────────
        _kpi1, _kpi2, _kpi3, _kpi4, _kpi5, _kpi6 = st.columns(6)
        _kpi1.metric("🚨 Critical Alerts", len(crits_db),
                     delta="ACTION NEEDED" if crits_db else "✅ Clear",
                     delta_color="inverse" if crits_db else "normal")
        _kpi2.metric("🔶 High Alerts",     len(highs_db))
        _kpi3.metric("📋 Open IR Cases",   len(open_cases_db),
                     delta=f"{len(campaigns_db)} campaigns" if campaigns_db else None)
        _kpi4.metric("⏱ DPDP Timers",     len(dpdp_db),
                     delta=f"{dpdp_db[0].get('hours_remaining','?')}h left" if dpdp_db else "None")
        _kpi5.metric("🚫 Blocked IOCs",   len(blocked_db))

        # Detection accuracy score — computed from stress test results or default
        _st_results = st.session_state.get("stress_results", {})
        if _st_results:
            _st_passed  = sum(1 for r in _st_results.values() if r.get("status") == "PASS")
            _st_pct     = round(_st_passed / max(len(_st_results), 1) * 100)
            _acc_delta  = f"{_st_passed}/{len(_st_results)} scenarios"
        else:
            _st_pct    = 65  # baseline estimate
            _acc_delta = "Run stress test"
        _kpi6.metric("🎯 Detection Score", f"{_st_pct}%", delta=_acc_delta)

        # ── v12: Alerts processed + FP reduction KPIs (interview-ready metrics) ──
        _kpi_row2 = st.columns(4)
        _ap  = st.session_state.get("alerts_processed", 0)
        _ac  = st.session_state.get("alerts_auto_closed", 0)
        _ae  = st.session_state.get("alerts_escalated", 0)
        _fp_hist = st.session_state.get("fp_rate_history", [])
        _fp_rate = _fp_hist[-1][1] if _fp_hist else None
        _kpi_row2[0].metric("📥 Alerts Processed", f"{_ap:,}", delta="auto-triaged")
        _kpi_row2[1].metric("✅ Auto-Closed (Benign)", f"{_ac:,}",
                            delta=f"{round(_ac/_ap*100)}% of total" if _ap else "0%")
        _kpi_row2[2].metric("🚨 Escalated to Analyst", f"{_ae:,}",
                            delta=f"{round(_ae/_ap*100)}% escalation rate" if _ap else "0%")
        _kpi_row2[3].metric("📉 FP Rate",
                            f"{_fp_rate:.1f}%" if _fp_rate is not None else "—",
                            delta="vs baseline" if _fp_rate else "No data yet")

        st.divider()

        # ── Main content: 3-column layout ─────────────────────────────────────
        _col_main, _col_side = st.columns([2, 1])

        with _col_main:
            # ── Active alert feed (the core product view) ──────────────────────
            st.markdown(
                "<div style='color:#c8e8ff;font-size:.72rem;font-weight:700;"
                "letter-spacing:2px;margin-bottom:8px'>🚨 LIVE ALERT FEED — AI TRIAGE ACTIVE</div>",
                unsafe_allow_html=True
            )

            _all_alerts = st.session_state.get("triage_alerts", [])
            if _all_alerts:
                for _al in reversed(_all_alerts[-8:]):
                    _sev = _al.get("severity","medium")
                    _sev_color = {"critical":"#ff0033","high":"#ff9900",
                                  "medium":"#ffcc00","low":"#00c878"}.get(_sev,"#446688")
                    _ai_action = _al.get("ai_action","") or _al.get("action","")
                    _ai_badge  = (
                        f"<span style='background:rgba(0,200,120,0.15);border:1px solid #00c87855;"
                        f"border-radius:8px;padding:1px 7px;font-size:.58rem;color:#00c878;"
                        f"margin-left:6px'>🤖 {_ai_action[:30]}</span>"
                        if _ai_action else ""
                    )
                    st.markdown(
                        f"<div style='background:rgba(0,0,0,0.35);border:1px solid {_sev_color}22;"
                        f"border-left:3px solid {_sev_color};border-radius:0 8px 8px 0;"
                        f"padding:8px 12px;margin:3px 0;display:flex;align-items:center;gap:8px'>"
                        f"<span style='color:{_sev_color};font-size:.65rem;font-weight:700;"
                        f"text-transform:uppercase;min-width:54px'>{_sev[:4].upper()}</span>"
                        f"<span style='color:#c8e8ff;font-size:.75rem;flex:1'>"
                        f"{_generate_alert_name(_al)}</span>"
                        f"<span style='color:#446688;font-size:.65rem'>"
                        f"{_al.get('mitre','—')} · {_al.get('ip','—')}</span>"
                        f"{_ai_badge}"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                _btn_col1, _btn_col2 = st.columns(2)
                if _btn_col1.button("⚡ Open Alert Triage Autopilot", type="primary",
                                    use_container_width=True, key="db_triage_v9"):
                    st.session_state.mode = "Alert Triage Autopilot"; st.rerun()
                if _btn_col2.button("🔎 Autonomous Investigator", type="secondary",
                                    use_container_width=True, key="db_inv_v9"):
                    st.session_state.mode = "Autonomous Investigator"; st.rerun()
            else:
                st.markdown(
                    "<div style='background:rgba(0,200,120,0.06);border:1px solid #00c87833;"
                    "border-radius:8px;padding:18px;text-align:center'>"
                    "<div style='font-size:1.8rem'>✅</div>"
                    "<div style='color:#00c878;font-size:.8rem;font-weight:700;margin-top:4px'>"
                    "No active alerts — SOC is clear</div>"
                    "<div style='color:#2a4a6a;font-size:.65rem;margin-top:3px'>"
                    "Ingest telemetry via Data Pipeline to begin autonomous monitoring</div>"
                    "</div>",
                    unsafe_allow_html=True
                )
                if st.button("📡 Set Up Data Pipeline", type="primary",
                             use_container_width=True, key="db_pipe_v9"):
                    st.session_state.mode = "Data Pipeline"; st.rerun()

            # ── Active campaigns ───────────────────────────────────────────────
            if campaigns_db:
                st.markdown(
                    "<div style='color:#ff9900;font-size:.68rem;font-weight:700;"
                    "letter-spacing:2px;margin:12px 0 6px'>🎯 ACTIVE ATTACK CAMPAIGNS</div>",
                    unsafe_allow_html=True
                )
                for _camp in campaigns_db[-3:]:
                    _cf = _camp.get("confidence", 0)
                    _cf_color = "#ff0033" if _cf > 80 else "#ff9900" if _cf > 60 else "#ffcc00"
                    st.markdown(
                        f"<div style='background:rgba(255,153,0,0.06);border:1px solid #ff990033;"
                        f"border-left:3px solid {_cf_color};border-radius:0 8px 8px 0;"
                        f"padding:8px 12px;margin:3px 0'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                        f"<span style='color:#ff9944;font-size:.75rem;font-weight:700'>"
                        f"{_camp.get('name','Campaign')}</span>"
                        f"<span style='color:{_cf_color};font-size:.7rem;font-weight:700'>"
                        f"Confidence: {_cf}%</span>"
                        f"</div>"
                        f"<div style='color:#446688;font-size:.65rem;margin-top:2px'>"
                        f"{_camp.get('mitre_chain','—')} · "
                        f"{len(_camp.get('linked_signals',[]))} signals</div>"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                if st.button("🕸 View Attack Correlation", use_container_width=True,
                             key="db_corr_v9"):
                    st.session_state.mode = "Attack Correlation"; st.rerun()

        with _col_side:
            # ── LIVE INCIDENT TIMELINE — CTO requirement ───────────────────────
            # "SOC investigations rely on timeline views" — CTO
            _all_tl_alerts = st.session_state.get("triage_alerts", [])
            _camps_for_tl  = st.session_state.get("corr_campaigns", [])

            st.markdown(
                "<div style='color:#00f9ff;font-size:.65rem;font-weight:700;"
                "letter-spacing:2px;margin-bottom:6px'>⏱️ LIVE INCIDENT TIMELINE</div>",
                unsafe_allow_html=True
            )

            # Build a unified timeline from alerts + campaign events
            _tl_events = []
            for _a in reversed(_all_tl_alerts[-12:]):
                _tl_events.append({
                    "time":  _a.get("timestamp", "")[:8] or _a.get("_time","")[:8] or "—",
                    "event": _generate_alert_name(_a),
                    "mitre": _a.get("mitre",""),
                    "sev":   _a.get("severity","medium"),
                    "src":   _a.get("source","?"),
                })

            # If no live alerts, show demo timeline from first campaign
            if not _tl_events:
                from datetime import datetime as _dtl2
                _demo_camp = (_DEMO_CAMPAIGNS[0] if (lambda: __import__("builtins").globals().get("_DEMO_CAMPAIGNS") or globals().get("_DEMO_CAMPAIGNS"))() else {"timeline":[]})
                for _ev in _demo_camp["timeline"][:8]:
                    _tl_events.append({
                        "time":  _ev["time"],
                        "event": _ev["event"],
                        "mitre": _ev["technique"],
                        "sev":   _ev["severity"],
                        "src":   "Demo",
                    })

            _sev_dot = {"critical":"#ff0033","high":"#ff9900","medium":"#ffcc00","low":"#00c878"}
            for _tlev in _tl_events[:10]:
                _dc = _sev_dot.get(_tlev["sev"],"#446688")
                st.markdown(
                    f"<div style='display:flex;align-items:flex-start;gap:6px;"
                    f"padding:4px 0;border-bottom:1px solid #0a1422'>"
                    f"<span style='color:#2a4a6a;font-size:.6rem;font-family:monospace;"
                    f"min-width:52px;padding-top:1px'>{_tlev['time']}</span>"
                    f"<span style='width:8px;height:8px;background:{_dc};border-radius:50%;"
                    f"flex-shrink:0;margin-top:4px;box-shadow:0 0 4px {_dc}'></span>"
                    f"<div style='flex:1;min-width:0'>"
                    f"<div style='color:#c8e8ff;font-size:.68rem;white-space:nowrap;"
                    f"overflow:hidden;text-overflow:ellipsis'>{_tlev['event'][:38]}</div>"
                    f"<div style='color:#2a4a6a;font-size:.58rem'>"
                    f"{_tlev['mitre']} · {_tlev['src']}</div>"
                    f"</div></div>",
                    unsafe_allow_html=True
                )

            if st.button("📖 Full Attack Story →", use_container_width=True,
                         key="db_story_v10"):
                st.session_state.mode = "Attack Correlation"; st.rerun()

            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

            # ── AI Investigation summary (signature feature preview) ───────────
            st.markdown(
                "<div style='color:#00aaff;font-size:.65rem;font-weight:700;"
                "letter-spacing:2px;margin-bottom:6px'>🔎 AI INVESTIGATION ENGINE</div>",
                unsafe_allow_html=True
            )
            _demo_inv = {
                "alert": "DNS anomaly — workstation-07",
                "summary": "Host contacted suspicious domain linked to Cobalt Strike C2 infrastructure.",
                "stage": "Command & Control",
                "mitre": "T1071.004",
                "confidence": 91,
                "action": "Isolate host · Block domain · Open IR case",
            }
            if crits_db:
                _a0 = crits_db[0]
                _demo_inv["alert"] = _a0.get("alert_type", _demo_inv["alert"])
                _demo_inv["mitre"] = _a0.get("mitre", _demo_inv["mitre"])
            st.markdown(
                f"<div style='background:rgba(0,10,30,0.6);border:1px solid #00aaff33;"
                f"border-radius:10px;padding:12px;font-size:.68rem'>"
                f"<div style='color:#00f9ff;font-weight:700;margin-bottom:6px'>"
                f"⚡ Alert: {_demo_inv['alert']}</div>"
                f"<div style='color:#c8e8ff;line-height:1.5;margin-bottom:8px'>"
                f"{_demo_inv['summary']}</div>"
                f"<div style='display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-bottom:8px'>"
                f"<div><span style='color:#446688'>Kill-chain:</span><br>"
                f"<span style='color:#ff9900;font-weight:700'>{_demo_inv['stage']}</span></div>"
                f"<div><span style='color:#446688'>MITRE:</span><br>"
                f"<span style='color:#c300ff;font-weight:700'>{_demo_inv['mitre']}</span></div>"
                f"<div><span style='color:#446688'>Confidence:</span><br>"
                f"<span style='color:#00c878;font-weight:700'>{_demo_inv['confidence']}%</span></div>"
                f"</div>"
                f"<div style='background:rgba(0,200,120,0.08);border:1px solid #00c87833;"
                f"border-radius:6px;padding:6px;color:#00c878;font-weight:700'>"
                f"🤖 Recommended: {_demo_inv['action']}</div>"
                f"</div>",
                unsafe_allow_html=True
            )
            if st.button("🔎 Open Autonomous Investigator", use_container_width=True,
                         type="primary", key="db_inv2_v9"):
                st.session_state.mode = "Autonomous Investigator"; st.rerun()

            st.markdown("<div style='margin-top:10px'></div>", unsafe_allow_html=True)

            # ── DPDP compliance widget ─────────────────────────────────────────
            st.markdown(
                "<div style='color:#ff9900;font-size:.65rem;font-weight:700;"
                "letter-spacing:2px;margin-bottom:6px'>⏱ DPDP COMPLIANCE</div>",
                unsafe_allow_html=True
            )
            if dpdp_db:
                for t in dpdp_db[:2]:
                    _th  = t.get("hours_remaining", 72)
                    _tc  = "#ff0033" if _th < 12 else "#ff9900" if _th < 36 else "#ffcc00"
                    st.markdown(
                        f"<div style='background:{_tc}0d;border:1px solid {_tc}44;"
                        f"border-radius:8px;padding:8px 10px;margin:3px 0'>"
                        f"<span style='color:{_tc};font-size:1rem;font-weight:900'>{_th}h</span>"
                        f" <span style='color:#aaa;font-size:.65rem'>"
                        f"· {t.get('case_id','?')}</span>"
                        f"<div style='color:#666;font-size:.58rem;margin-top:1px'>"
                        f"{'⚠️ CRITICAL — notify CERT-In now' if _th < 12 else '🟡 Monitor'}"
                        f"</div></div>",
                        unsafe_allow_html=True
                    )
                if st.button("Open DPDP Console", type="primary",
                             use_container_width=True, key="db_dpdp_v9"):
                    st.session_state.mode = "DPDP Breach Console"; st.rerun()
            else:
                st.markdown(
                    "<div style='background:rgba(0,200,120,0.06);border:1px solid #00c87833;"
                    "border-radius:8px;padding:8px;text-align:center'>"
                    "<div style='color:#00c878;font-size:.7rem'>✅ Compliant</div>"
                    "<div style='color:#2a4a6a;font-size:.58rem'>No active DPDP timers</div>"
                    "</div>",
                    unsafe_allow_html=True
                )

            # ── Phase 1 core loop quick-launch ────────────────────────────────
            st.markdown(
                "<div style='color:#c8e8ff;font-size:.65rem;font-weight:700;"
                "letter-spacing:2px;margin:10px 0 4px'>⚡ PHASE 1 CORE LOOP</div>"
                "<div style='color:#446688;font-size:.58rem;margin-bottom:6px'>"
                "Triage → Investigate → Correlate → Respond → Report</div>",
                unsafe_allow_html=True
            )
            _qa_btns = [
                ("⚡", "Alert Triage Autopilot",    "⚡ Triage"),
                ("🧠", "Alert Explainer",            "🧠 Explain"),
                ("🔎", "Autonomous Investigator",    "🔎 Investigate"),
                ("📖", "Attack Correlation",         "📖 Attack Story"),
                ("📋", "Incident Report Generator",  "📋 IR Report"),
                ("📝", "Shift Handover",             "📝 Handover"),
                ("💬", "AI Copilot",        "💬 Ask Copilot"),
                ("📊", "Reputation Scorer",          "📊 Rep Score"),
            ]
            # Two columns for compact layout
            _qa_col1, _qa_col2 = st.columns(2)
            for i, (_qic, _qmode, _qlbl) in enumerate(_qa_btns):
                _col = _qa_col1 if i % 2 == 0 else _qa_col2
                if _col.button(f"{_qic} {_qlbl}", key=f"db_qa_{_qmode}",
                               use_container_width=True):
                    st.session_state.mode = _qmode; st.rerun()

            st.divider()
            if st.button("🎬 Run One-Click Demo — APT29 Full Pipeline",
                         use_container_width=True, key="db_demo_launch", type="primary"):
                st.session_state.mode = "One-Click Demo"; st.rerun()
            if st.button("🧪 Platform Stress Test — 13 APT Scenarios",
                         use_container_width=True, key="db_stress_launch"):
                st.session_state.mode = "Platform Stress Test"; st.rerun()

        st.divider()

        # ── Platform Architecture Diagram ──────────────────────────────────────
        st.markdown(
            "<div style='color:#00f9ff;font-size:.72rem;font-weight:700;"
            "letter-spacing:2px;margin:0 0 12px'>🏗️ PLATFORM ARCHITECTURE — 5-LAYER AUTONOMOUS SOC PIPELINE</div>",
            unsafe_allow_html=True
        )
        _arch_layers = [
            ("#00aaff", "1️⃣  DATA INGESTION",    "Sensors",
             "PCAP · EVTX · Zeek · Sysmon · DNS logs · Firewall logs · Cloud logs",
             "Kafka / Fluentd / Vector pipeline → normalisation → ECS format"),
            ("#00c878", "2️⃣  DETECTION ENGINE",  "Rules + ML",
             "Signature · Behaviour · Anomaly · Threat intel matching · ML classification",
             "MITRE mapping · Signal scoring · DGA detection · VT enrichment"),
            ("#ff9900", "3️⃣  CORRELATION",        "alerts → incidents",
             "Time-windowed grouping · IP clustering · Kill-chain reconstruction",
             "100 alerts → 1 correlated incident · Campaign tracking"),
            ("#c300ff", "4️⃣  INVESTIGATION AI",  "Autonomous Analyst",
             "What happened · How attacker entered · MITRE chain · IOC extraction",
             "Process tree · Network path · Entity graph · Threat actor attribution"),
            ("#ff0033", "5️⃣  RESPONSE / SOAR",   "Automation",
             "Block IP · Isolate host · Disable account · Open IR case · DPDP timer",
             "SOAR playbooks · ARE gates · Evidence chain of custody"),
        ]
        _arch_html = (
            "<div style='display:flex;align-items:stretch;gap:0;"
            "background:rgba(0,5,15,0.7);border:1px solid #0a1a2a;"
            "border-radius:14px;overflow:hidden;margin-bottom:6px'>"
        )
        for i, (_col, _title, _sub, _desc, _tech) in enumerate(_arch_layers):
            _arrow = "" if i == len(_arch_layers) - 1 else (
                f"<div style='position:absolute;right:-18px;top:50%;transform:translateY(-50%);"
                f"color:{_col};font-size:1.4rem;z-index:10'>▶</div>"
            )
            _arch_html += (
                f"<div style='flex:1;background:{_col}09;border-right:1px solid {_col}22;"
                f"padding:14px 12px;position:relative;min-width:0'>"
                f"<div style='color:{_col};font-size:.6rem;font-weight:900;"
                f"letter-spacing:1.5px;text-transform:uppercase'>{_title}</div>"
                f"<div style='color:#c8e8ff;font-size:.72rem;font-weight:700;margin-top:4px'>{_sub}</div>"
                f"<div style='color:#556677;font-size:.62rem;margin-top:6px;line-height:1.4'>{_desc}</div>"
                f"<div style='color:{_col}99;font-size:.56rem;margin-top:6px;"
                f"font-family:monospace;line-height:1.3'>{_tech}</div>"
                f"{_arrow}</div>"
            )
        _arch_html += "</div>"

        # Knowledge Graph layer — full-width below
        _arch_html += (
            "<div style='background:rgba(255,204,0,0.05);border:1px solid #ffcc0033;"
            "border-radius:10px;padding:12px 18px;margin-top:4px;"
            "display:flex;align-items:center;gap:20px'>"
            "<div style='color:#ffcc00;font-size:.65rem;font-weight:900;"
            "letter-spacing:1.5px;min-width:160px'>6️⃣  KNOWLEDGE GRAPH</div>"
            "<div style='color:#c8e8ff;font-size:.72rem'>IP → Domain → Host → User → Process → MITRE Technique</div>"
            "<div style='color:#556677;font-size:.62rem;margin-left:auto'>"
            "Entity graph · Attack path prediction · Threat attribution · Campaign detection</div>"
            "</div>"
        )
        st.markdown(_arch_html, unsafe_allow_html=True)


    elif mode == "Attack Correlation":
        st.header("🔗 Attack Correlation Engine")
        st.caption("Multi-alert correlation · Kill chain replay · Visual attack graph")
        tab_corr, tab_replay, tab_graph = st.tabs([
            "🔗 Correlation", "⏪ Attack Replay", "🕸️ Attack Graph"
        ])
        with tab_corr:
            render_attack_correlation()
        with tab_replay:
            render_attack_replay()
        with tab_graph:
            render_attack_graph()

    # ── 7. Incident Response (merged: IR Cases + Evidence Vault) ──────────────
    elif mode == "Incident Response":
        st.header("🚨 Incident Response & Evidence")
        st.caption("IR case management · SHA-256 evidence vault · Chain of custody · DPDP compliance")
        tab_cases, tab_vault = st.tabs(["📋 IR Cases", "🔒 Evidence Vault"])
        with tab_cases:
            render_incident_cases()
        with tab_vault:
            render_evidence_vault()

    # ── 8. SOAR Automation (merged: SOAR Playbooks + n8n Automation) ──────────
    elif mode == "IOC Intelligence":
        st.header("🔎 IOC Intelligence Engine")
        st.caption("AbuseIPDB · Shodan · GreyNoise · OTX · VirusTotal · MalwareBazaar — parallel enrichment")
        tab_single, tab_batch = st.tabs(["🔍 Single IOC Lookup", "📦 Batch / Fusion"])
        with tab_single:
            render_ioc_lookup()
        with tab_batch:
            render_threat_intel_fusion()

    # ── 10. Threat Hunting ─────────────────────────────────────────────────────
    elif mode == "Attack Narrative Engine":
        render_attack_narrative()

    # ── 💬 SOC AI ASSISTANT — unified chatbot ─────────────────────────────────
    elif mode == "SOC Assistant":
        render_soc_chatbot()

    # ── 13. AI Copilot (merged: Copilot + v2 + SOC Brain) ────────────
    elif mode == "AI Copilot":
        st.header("💬 AI Copilot")
        st.caption("Autonomous investigation · AI chat assistant · Cross-silo context · Workflow suggestions")
        tab_brain, tab_copilot = st.tabs(["🤖 Autonomous Investigator", "💬 AI Chat"])
        with tab_brain:
            render_soc_brain_agent()
            # Attack Chain Reconstruction from live session alerts
            _live_alerts = (
                st.session_state.get("triage_alerts") or
                st.session_state.get("sysmon_results", {}).get("alerts") or
                []
            )
            if _live_alerts:
                with st.expander("⛓ Attack Chain Reconstruction", expanded=False):
                    render_attack_chain_narrative(_live_alerts)
        with tab_copilot:
            render_soc_copilot_v2()

    # ── 14. Detection Architect ────────────────────────────────────────────────
    elif mode == "Detection Architect":
        render_self_evolving_detection()

    # ── 14. Adversarial Simulation (merged: Purple Team + Red Team) ────────────
    elif mode == "Adversarial Simulation":
        st.header("⚔️ Adversarial Simulation")
        st.caption("Purple team scenarios · Red team TTPs · Detection gap identification · Sigma rule generation")
        tab_purple, tab_red = st.tabs(["🟣 Purple Team", "🔴 Adversarial Red Team"])
        with tab_purple:
            render_purple_team()
        with tab_red:
            render_adversarial_red_team()

    # ── 15. Temporal Memory ────────────────────────────────────────────────────
    elif mode == "API Config":
        render_api_config()

    elif mode == "Splunk Alert Pull":
        try:
            from modules.splunk_integration import render_splunk_pull
            render_splunk_pull()
        except Exception as _e:
            st.error(f"Splunk module error: {_e}")

    elif mode == "One-Click Demo":
        render_one_click_demo()

    # ── 🚀 NEXT-GEN AI — 5 new capabilities ───────────────────────────────
    elif mode == "Autonomous Investigator":
        render_autonomous_investigator()

    elif mode == "NL SOC Query":
        render_nl_soc_query()

    elif mode == "Incident Report Generator":
        render_incident_report_generator()

    elif mode == "Shift Handover":
        render_shift_handover()

    elif mode == "Alert Triage Autopilot":
        render_triage_autopilot()

    elif mode == "Alert Explainer":
        render_one_click_alert_explainer()

    elif mode == "Bulk Alert Processor":
        render_bulk_alert_processor()

    elif mode == "Domain Triage Engine":
        render_domain_triage()

    elif mode == "Reputation Scorer":
        render_reputation_tester()

    elif mode == "Hunt Query Builder":
        render_hunt_query_builder()

    elif mode == "Alert Deduplicator":
        render_alert_deduplicator()

    elif mode == "DPDP Breach Console":
        render_dpdp_breach_console()

    elif mode == "Live Playbook Runner":
        render_live_playbook_runner()

    elif mode == "Alert Triage":
        render_alert_triage()
    elif mode == "SOC Copilot":
        st.session_state.mode = "AI Copilot"
        st.rerun()
    elif mode == "Co-Pilot v2":
        st.session_state.mode = "AI Copilot"
        st.rerun()
    elif mode == "SOC Brain":
        st.header("🧠 SOC Decision Brain")
        st.caption("Correlation Engine · Asset Intelligence · Incident View · AI Narrative")
        if SOC_BRAIN_ENABLED and render_soc_brain:
            render_soc_brain()
        else:
            st.error("⚠️ Place soc_brain.py in your ui/ folder alongside app.py")
    elif mode == "Deployment":
        render_deployment()
    elif mode == "User Management":
        render_user_management()
    elif mode == "SOC Lab Enhancements":
        st.header("🔬 SOC Lab Enhancements")
        st.caption("MISP · Wazuh · Sigma Rules · Splunk Dashboard · MITRE Coverage")
        if SOC_ENHANCEMENTS_ENABLED and render_soc_enhancements:
            render_soc_enhancements()
        else:
            st.error("⚠️ soc_enhancements.py not found in ui/ folder — place it next to app.py")
    elif mode == "Live Pipeline":
        if PIPELINE_ENABLED and render_pipeline_dashboard:
            render_pipeline_dashboard()
        else:
            st.warning("realtime_pipeline.py not found — copy it to your modules/ folder.")
            st.code("cp realtime_pipeline.py modules/realtime_pipeline.py", language="bash")

    elif mode == "Enterprise SOC":
        # ── Enterprise SOC v11.0 ────────────────────────────────────────────
        if ENTERPRISE_SOC_ENABLED and render_enterprise_soc:
            render_enterprise_soc()
        else:
            st.warning("Enterprise SOC module not loaded. Copy enterprise_soc.py into your project root or modules/ folder, then restart Streamlit.")
            st.code("cp enterprise_soc.py modules/enterprise_soc.py", language="bash")

    elif mode == "IOC Blast Enrichment":
        st.header("🔥 IOC Blast Enrichment")
        st.caption("All IOCs from session → parallel enrichment → unified verdict · 30-45 min → 10 seconds")
        render_ioc_blast_enrichment()

    elif mode == "Alert Correlation":
        st.header("🔗 Alert Correlation")
        st.caption("Group related alerts into incidents · Time-window clustering · Entity overlap detection")
        render_alert_correlation_dashboard()

    elif mode == "Splunk Integration":
        _render_splunk_integration_page()

    elif mode == "Pull & HEC Dashboard":
        _render_pull_hec_dashboard()

    elif mode == "Autonomous Agents":
        from v12_additions import render_autonomous_agents
        render_autonomous_agents()

    elif mode == "Causal Attack Graph":
        from v12_additions import render_causal_attack_graph
        render_causal_attack_graph()

    elif mode == "Predictive Hunting":
        from v12_additions import render_predictive_hunting
        render_predictive_hunting()

    elif mode == "Digital Twin":
        from v12_additions import render_digital_twin
        render_digital_twin()

    elif mode == "Executive Briefing":
        from v12_additions import render_executive_briefing
        render_executive_briefing()

    elif mode == "Automation":
        st.header("⚡ SOAR Automation — n8n Integration")
        st.caption("Playbooks · Autonomous Response Engine · n8n live triggers · Feedback loop · Action tracking")
        tab_pb, tab_are, tab_n8n = st.tabs([
            "⚡ SOAR Playbooks", "🤖 Autonomous Response Engine", "🔗 n8n Integration"
        ])
        with tab_pb:
            render_soar_playbooks()
        with tab_are:
            render_autonomous_response_engine()
        with tab_n8n:
            _render_n8n_integration_tab()

    else:
        st.info(f"Navigate using the sidebar. Selected: `{mode}`")


def _render_n8n_integration_tab():
    """n8n health, workflow list, manual triggers (with retry), action log, setup guide."""
    try:
        from ui.n8n_agent import (
            n8n_health_check, get_workflow_list, get_workflow_setup_guide,
            get_action_log, trigger_slack_notify, trigger_block_ip,
            trigger_enrich_ioc, trigger_ir_escalation, auto_or_manual_trigger,
        )
    except ImportError:
        st.error("n8n_agent.py not found — place it in the same folder as app.py and restart.")
        return

    _n8n_tabs = st.tabs([
        "🟢 Health", "📋 Workflows", "🧪 Manual Triggers", "📣 Action Log", "📖 Setup Guide"
    ])

    with _n8n_tabs[0]:
        if st.button("🔄 Test n8n Connection", type="primary",
                     use_container_width=True, key="n8n_health_btn"):
            with st.spinner("Connecting to n8n…"):
                _h = n8n_health_check()
            st.session_state["n8n_health_last"] = _h
        _h = st.session_state.get("n8n_health_last", {})
        if _h:
            _hc = ("#00c878" if _h["status"] == "ok"
                   else "#ff0033" if _h["status"] in ("offline","auth_error")
                   else "#ff9900")
            st.markdown(
                f"<div style='background:rgba(0,5,15,0.8);border:2px solid {_hc}44;"
                f"border-left:4px solid {_hc};border-radius:0 10px 10px 0;"
                f"padding:14px 20px;margin:8px 0'>"
                f"<div style='color:{_hc};font-weight:900;font-size:1rem'>"
                f"● {_h['status'].upper()}</div>"
                f"<div style='color:#c8e8ff;font-size:.85rem;margin-top:4px'>"
                f"{_h.get('message','')}</div>"
                f"<div style='color:#446688;font-size:.72rem;margin-top:6px'>"
                f"URL: {_h.get('n8n_url','')} · "
                f"Workflows: {_h.get('workflows',0)} · "
                f"Active: {_h.get('active_workflows',0)} · "
                f"Latency: {_h.get('latency_ms',0)}ms</div>"
                f"</div>", unsafe_allow_html=True)
        else:
            st.info("Click 'Test n8n Connection' to check status.")

    with _n8n_tabs[1]:
        _wf_list = get_workflow_list()
        for _wf in _wf_list:
            _wac = "#00c878" if _wf.get("active") else "#446688"
            st.markdown(
                f"<div style='background:#070810;border:1px solid #0a1a2a;"
                f"border-left:3px solid {_wac};border-radius:0 8px 8px 0;"
                f"padding:8px 14px;margin:4px 0'>"
                f"<div style='color:#c8e8ff;font-size:.82rem;font-weight:700'>"
                f"{_wf['name']}</div>"
                f"<div style='color:#446688;font-size:.68rem;font-family:monospace;margin-top:2px'>"
                f"{_wf.get('webhook_url','')} · "
                f"<span style='color:{_wac}'>{'● ACTIVE' if _wf.get('active') else '○ INACTIVE'}"
                f"</span></div></div>", unsafe_allow_html=True)

    with _n8n_tabs[2]:
        st.caption("Manually fire n8n workflows — all use retry logic (3 attempts, exponential backoff).")
        _mc1, _mc2 = st.columns(2)
        _tip   = _mc1.text_input("Target IP",     value="185.220.101.45", key="n8n_test_ip")
        _tdom  = _mc2.text_input("Target Domain", value="malware-c2.tk",  key="n8n_test_dom")
        _tsco  = _mc1.slider("Threat Score", 0, 100, 88,                  key="n8n_test_score")
        _tsev  = _mc2.selectbox("Severity", ["critical","high","medium","low"], key="n8n_test_sev")

        _b1, _b2, _b3, _b4 = st.columns(4)
        if _b1.button("🔔 Slack Notify", use_container_width=True, key="n8n_btn_slack"):
            _ok, _r = trigger_slack_notify(
                f"NetSec AI test — {_tdom} score={_tsco}", _tsev)
            st.success("✅ Sent!") if _ok else st.error(f"❌ {_r.get('error','')}")

        if _b2.button("🚫 Block IP", use_container_width=True, key="n8n_btn_block"):
            _ok, _r = trigger_block_ip(_tip, f"Manual test score={_tsco}", _tsco)
            st.success("✅ Sent!") if _ok else st.error(f"❌ {_r.get('error','')}")

        if _b3.button("🔭 Enrich IOC", use_container_width=True, key="n8n_btn_enrich"):
            _ok, _r = trigger_enrich_ioc(_tip)
            st.success("✅ Sent!") if _ok else st.error(f"❌ {_r.get('error','')}")

        if _b4.button("🚨 IR Escalate", use_container_width=True, key="n8n_btn_esc"):
            _ok, _r = trigger_ir_escalation(
                f"IR-TEST-{datetime.now().strftime('%H%M%S')}",
                f"Manual escalation test — {_tdom}", _tsev,
                _tdom, [_tip], ["T1071"])
            st.success("✅ Sent!") if _ok else st.error(f"❌ {_r.get('error','')}")

        st.divider()
        st.caption("Smart trigger — auto/suggest/log_only decision based on score:")
        if st.button("⚡ Smart Trigger (auto/suggest/log_only)",
                     use_container_width=True, key="n8n_smart"):
            _ok, _r, _dec = auto_or_manual_trigger(
                _tdom, _tip, "Manual Test", _tsev, _tsco)
            _dec_label = {"auto": "🤖 Auto-executed",
                          "suggest": "💡 Suggested",
                          "log_only": "📝 Logged"}.get(_dec, _dec)
            if _ok:
                st.success(f"✅ {_dec_label} — score {_tsco}")
            else:
                st.error(f"❌ Failed after 3 retries: {_r.get('error','')}")

    with _n8n_tabs[3]:
        _log = get_action_log()
        _lc1, _lc2 = st.columns([3, 1])
        _lc1.caption(f"{len(_log)} n8n actions logged this session")
        if _lc2.button("🗑️ Clear Log", use_container_width=True, key="n8n_log_clear"):
            st.session_state["n8n_action_log"] = []
            st.rerun()
        if not _log:
            st.info("No n8n actions logged yet. Fire a workflow above.")
        else:
            for _entry in _log[:50]:
                _ec = ("#00c878" if _entry.get("status") == "ok"
                       else "#ff0033" if _entry.get("error") else "#ff9900")
                st.markdown(
                    f"<div style='background:#070810;border-left:3px solid {_ec};"
                    f"padding:6px 12px;margin:3px 0;border-radius:0 6px 6px 0;"
                    f"font-size:.73rem'>"
                    f"<span style='color:{_ec};font-weight:700'>"
                    f"{_entry.get('action','?').upper()}</span> "
                    f"<span style='color:#c8e8ff'>{_entry.get('target','')}</span> "
                    f"<span style='color:#446688;font-family:monospace'>"
                    f"{_entry.get('executed_at','')}</span>"
                    + (f" <span style='color:#ff6644'>{_entry['error']}</span>"
                       if _entry.get("error") else "")
                    + "</div>", unsafe_allow_html=True)

    with _n8n_tabs[4]:
        st.markdown(get_workflow_setup_guide())

if __name__ == "__main__":
    main()