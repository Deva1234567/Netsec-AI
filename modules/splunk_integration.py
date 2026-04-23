"""
NetSec AI — Splunk Integration
================================
Pulls real alerts from Splunk via REST API (port 8089).
Connects using username/password or HEC token from .env.

Your Splunk setup (from screenshot):
  User: devanshjain209@gmail.com
  Role: admin
  Auth: Splunk native
  Default app: launcher

Usage:
    from modules.splunk_integration import SplunkClient, render_splunk_pull
"""

import os
import re
import json
import time
import base64
import ssl
import urllib.request
import urllib.parse
import urllib.error
import streamlit as st
from datetime import datetime, timedelta

# ── Splunk connection defaults ─────────────────────────────────────────────────
_DEFAULT_PORT    = 8089   # Splunk REST API / management port
_DEFAULT_APP     = "search"
_SEARCH_TIMEOUT  = 30     # seconds to wait for search job


class SplunkClient:
    """
    Splunk REST API client.
    Handles: auth, job creation, result polling, alert parsing.
    """

    def __init__(self, host: str, port: int, username: str, password: str,
                 verify_ssl: bool = False):
        self.host       = host.rstrip("/")
        self.port       = port
        self.username   = username
        self.password   = password
        self.verify_ssl = verify_ssl
        self.base_url   = f"https://{self.host}:{self.port}"
        self._session_key = None

    # ── Auth ───────────────────────────────────────────────────────────────────
    def authenticate(self) -> tuple:
        """Login and get session key. Returns (success: bool, message: str)."""
        try:
            url  = f"{self.base_url}/services/auth/login"
            body = urllib.parse.urlencode({
                "username": self.username,
                "password": self.password,
                "output_mode": "json",
            }).encode()
            req = urllib.request.Request(url, data=body, method="POST")
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
                data = json.loads(r.read().decode("utf-8"))
            self._session_key = data.get("sessionKey", "")
            if self._session_key:
                return True, f"Authenticated as {self.username}"
            return False, "No session key returned"
        except urllib.error.HTTPError as e:
            return False, f"HTTP {e.code}: Wrong username/password"
        except Exception as e:
            return False, f"Connection failed: {str(e)[:80]}"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Splunk {self._session_key}",
            "Content-Type":  "application/x-www-form-urlencoded",
        }

    def _get(self, path: str, params: dict = None) -> dict:
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self._headers())
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))

    def _post(self, path: str, body: dict) -> dict:
        url  = f"{self.base_url}{path}"
        data = urllib.parse.urlencode(body).encode()
        req  = urllib.request.Request(url, data=data,
                                       headers=self._headers(), method="POST")
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))

    # ── Search ─────────────────────────────────────────────────────────────────
    def run_search(self, spl_query: str, earliest: str = "-24h",
                   latest: str = "now", max_results: int = 100) -> tuple:
        """
        Run a Splunk search and return results.
        Returns (results: list[dict], error: str | None)
        """
        if not self._session_key:
            ok, msg = self.authenticate()
            if not ok:
                return [], msg

        # Ensure query starts with "search"
        query = spl_query.strip()
        if not query.startswith("search ") and not query.startswith("|"):
            query = "search " + query

        # Create search job
        try:
            job_resp = self._post("/services/search/jobs", {
                "search":        query,
                "earliest_time": earliest,
                "latest_time":   latest,
                "output_mode":   "json",
                "max_count":     str(max_results),
            })
        except Exception as e:
            return [], f"Failed to create search job: {e}"

        sid = job_resp.get("sid", "")
        if not sid:
            return [], f"No SID returned: {job_resp}"

        # Poll for completion
        deadline = time.time() + _SEARCH_TIMEOUT
        while time.time() < deadline:
            try:
                status = self._get(f"/services/search/jobs/{sid}",
                                   {"output_mode": "json"})
                state = (status.get("entry", [{}])[0]
                         .get("content", {}).get("dispatchState", ""))
                if state in ("DONE", "FINALIZED"):
                    break
                if state == "FAILED":
                    return [], "Search job failed"
                time.sleep(0.8)
            except Exception as e:
                return [], f"Poll error: {e}"
        else:
            return [], f"Search timed out after {_SEARCH_TIMEOUT}s"

        # Fetch results
        try:
            results_resp = self._get(f"/services/search/jobs/{sid}/results", {
                "output_mode": "json",
                "count":       str(max_results),
            })
            results = results_resp.get("results", [])
            return results, None
        except Exception as e:
            return [], f"Failed to fetch results: {e}"

    # ── Alert parsing ──────────────────────────────────────────────────────────
    @staticmethod
    def parse_alerts(raw_results: list) -> list:
        """
        Convert raw Splunk results into NetSec AI triage_alerts format.
        Handles common Splunk alert field names automatically.
        """
        alerts = []
        for r in raw_results:
            if not isinstance(r, dict):
                continue

            # Extract time
            ts = (r.get("_time") or r.get("timestamp") or
                  datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))

            # Extract source IP
            src_ip = (r.get("src_ip") or r.get("src") or r.get("source_ip") or
                      r.get("Source_IP") or r.get("src_host") or "")

            # Extract destination
            dest_ip = (r.get("dest_ip") or r.get("dest") or r.get("dst_ip") or
                       r.get("destination_ip") or r.get("dest_host") or "")

            # Extract signature/rule name
            signature = (r.get("signature") or r.get("rule_name") or
                         r.get("alert_name") or r.get("name") or
                         r.get("event_type") or r.get("EventCode") or
                         r.get("source") or "Splunk Alert")

            # Severity mapping
            raw_sev = str(r.get("severity") or r.get("priority") or
                          r.get("urgency") or "medium").lower()
            sev_map = {
                "0":"informational","1":"low","2":"medium","3":"high","4":"critical",
                "info":"informational","low":"low","medium":"medium",
                "high":"high","critical":"critical",
                "5":"critical","informational":"informational",
            }
            severity = sev_map.get(raw_sev, "medium")

            # Extract domain
            domain = (r.get("domain") or r.get("dest_domain") or
                      r.get("query") or r.get("url_domain") or "")

            # Build raw detail from all fields
            detail_parts = []
            for k, v in r.items():
                if k.startswith("_") or not v or v == "unknown":
                    continue
                detail_parts.append(f"{k}={v}")
            detail = " · ".join(detail_parts[:12])

            alert = {
                "alert_type":  str(signature)[:80],
                "ip":          str(src_ip),
                "domain":      str(domain),
                "dest_ip":     str(dest_ip),
                "severity":    severity,
                "timestamp":   str(ts),
                "detail":      detail,
                "source":      "Splunk",
                "_raw":        r,  # Keep full raw event
            }
            alerts.append(alert)

        return alerts

    # ── Pre-built queries ──────────────────────────────────────────────────────
    @staticmethod
    def get_preset_queries() -> list:
        """Pre-built SPL queries for common SOC use cases."""
        return [
            {
                "name":     "🚨 Recent IDS/IPS Alerts",
                "query":    'index=* (sourcetype=suricata OR sourcetype=snort OR sourcetype=ids) | head 100 | table _time src_ip dest_ip signature severity',
                "earliest": "-24h",
            },
            {
                "name":     "🔴 High Severity Events",
                "query":    'index=* severity=high OR severity=critical | head 100 | table _time src_ip dest_ip signature severity',
                "earliest": "-24h",
            },
            {
                "name":     "🌐 DNS Queries (Suspicious TLDs)",
                "query":    'index=* sourcetype=stream:dns OR sourcetype=bro:dns | search query=*.xyz OR query=*.top OR query=*.tk | head 100 | table _time src_ip query answer',
                "earliest": "-24h",
            },
            {
                "name":     "🔒 Failed Logins / Brute Force",
                "query":    'index=* (EventCode=4625 OR "failed login" OR "authentication failure") | stats count by src_ip user | where count > 5 | sort -count',
                "earliest": "-24h",
            },
            {
                "name":     "📡 Outbound Network Connections",
                "query":    'index=* sourcetype=stream:tcp OR sourcetype=bro:conn | stats count by src_ip dest_ip dest_port | where count > 10 | sort -count | head 50',
                "earliest": "-1h",
            },
            {
                "name":     "⚡ All Recent Events (last 100)",
                "query":    'index=* | head 100 | table _time src_ip dest_ip signature severity',
                "earliest": "-1h",
            },
            {
                "name":     "🎯 Custom SPL Query",
                "query":    "",
                "earliest": "-24h",
            },
        ]


# ── Streamlit UI ───────────────────────────────────────────────────────────────
def render_splunk_pull():
    """
    Full Splunk alert pull UI.
    Connect → Query → Pull → Load into triage_alerts session state.
    """
    st.markdown(
        "<div style='font-family:Orbitron,monospace;font-size:.9rem;font-weight:900;"
        "color:#00f9ff;letter-spacing:2px;margin-bottom:4px'>"
        "⚡ SPLUNK ALERT PULL</div>"
        "<div style='color:#446688;font-size:.68rem;margin-bottom:12px'>"
        "Connect to your Splunk instance → run SPL search → load real alerts into NetSec AI triage pipeline</div>",
        unsafe_allow_html=True
    )

    tab_connect, tab_pull, tab_live = st.tabs([
        "🔌 Connect", "🔍 Pull Alerts", "📊 Live Status"
    ])

    # ══ TAB 1: CONNECT ═══════════════════════════════════════════════════════
    with tab_connect:
        st.markdown("**Step 1 — Configure your Splunk connection**")

        # Load from .env defaults
        _default_host  = os.getenv("SPLUNK_HOST", "localhost")
        _default_port  = int(os.getenv("SPLUNK_PORT", "8089"))
        _default_user  = os.getenv("SPLUNK_USERNAME", "devanshjain209@gmail.com")
        _default_pass  = os.getenv("SPLUNK_PASSWORD", "")

        _c1, _c2 = st.columns(2)
        _host = _c1.text_input("Splunk Host / IP",
                                value=st.session_state.get("splunk_host", _default_host),
                                placeholder="localhost or 192.168.x.x",
                                key="sp_host_input")
        _port = _c2.number_input("Management Port (REST API)",
                                  value=st.session_state.get("splunk_port", _default_port),
                                  min_value=1, max_value=65535,
                                  key="sp_port_input")
        _user = _c1.text_input("Username",
                                value=st.session_state.get("splunk_user", _default_user),
                                key="sp_user_input")
        _pass = _c2.text_input("Password", type="password",
                                value=st.session_state.get("splunk_pass", _default_pass),
                                key="sp_pass_input")
        _ssl  = st.checkbox("Verify SSL certificate", value=False, key="sp_ssl")

        st.markdown(
            "<div style='background:rgba(0,200,120,0.06);border:1px solid #00c87833;"
            "border-radius:8px;padding:8px 14px;margin:8px 0;color:#446688;font-size:.65rem'>"
            "💡 <b style='color:#c8e8ff'>Auto-loaded from .env:</b> "
            "Set SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USERNAME, SPLUNK_PASSWORD in your .env file. "
            "Management port is 8089 (not 8000). "
            "Your admin user: devanshjain209@gmail.com</div>",
            unsafe_allow_html=True
        )

        # .env format reminder
        with st.expander("📄 .env format for Splunk"):
            st.code("""SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=devanshjain209@gmail.com
SPLUNK_PASSWORD=your_splunk_password_here
SPLUNK_HEC_URL=http://localhost:8088/services/collector
SPLUNK_HEC_TOKEN=your_hec_token_here""", language="bash")

        if st.button("🔌 Test Connection", type="primary",
                     use_container_width=True, key="sp_test"):
            with st.spinner(f"Connecting to {_host}:{_port}…"):
                client = SplunkClient(_host, int(_port), _user, _pass, _ssl)
                ok, msg = client.authenticate()
                if ok:
                    st.success(f"✅ {msg}")
                    st.session_state["splunk_connected"] = True
                    st.session_state["splunk_host"]      = _host
                    st.session_state["splunk_port"]      = int(_port)
                    st.session_state["splunk_user"]      = _user
                    st.session_state["splunk_pass"]      = _pass
                    st.session_state["splunk_ssl"]       = _ssl
                    # Test a quick search
                    results, err = client.run_search(
                        "search index=* | head 1 | table _time index sourcetype",
                        earliest="-5m")
                    if err:
                        st.warning(f"⚠️ Connected but test search failed: {err}")
                    else:
                        st.info(f"✅ Search API working — found {len(results)} result(s)")
                else:
                    st.error(f"❌ {msg}")
                    st.session_state["splunk_connected"] = False

        # Connection status badge
        if st.session_state.get("splunk_connected"):
            st.markdown(
                f"<div style='background:rgba(0,200,120,0.08);border:1px solid #00c87844;"
                f"border-radius:8px;padding:8px 14px;margin-top:8px'>"
                f"<span style='color:#00c878;font-weight:700'>🟢 Connected</span> "
                f"<span style='color:#446688;font-size:.68rem'>"
                f"→ {st.session_state.get('splunk_host')}:"
                f"{st.session_state.get('splunk_port')} "
                f"as {st.session_state.get('splunk_user')}</span>"
                f"</div>",
                unsafe_allow_html=True
            )

    # ══ TAB 2: PULL ALERTS ═══════════════════════════════════════════════════
    with tab_pull:
        if not st.session_state.get("splunk_connected"):
            st.warning("⚠️ Connect to Splunk first (Tab: Connect)")
        else:
            st.markdown("**Step 2 — Choose a query and pull alerts**")

            presets = SplunkClient.get_preset_queries()
            preset_names = [p["name"] for p in presets]
            _sel = st.selectbox("Query preset:", preset_names,
                                key="sp_preset_sel")
            preset = presets[preset_names.index(_sel)]

            # Show/edit the SPL query
            _query = st.text_area(
                "SPL Query (editable):",
                value=preset["query"],
                height=80,
                key="sp_query_input",
                placeholder="search index=* | head 100 | table _time src_ip dest_ip signature severity"
            )

            _c1p, _c2p, _c3p = st.columns(3)
            _earliest = _c1p.selectbox("Time range", [
                "-15m", "-1h", "-4h", "-24h", "-7d", "-30d"
            ], index=3, key="sp_earliest")
            _maxres   = _c2p.number_input("Max results", 10, 1000, 100, step=10,
                                           key="sp_maxres")
            _autotriage = _c3p.checkbox("Auto-load into Triage", value=True,
                                         key="sp_autotriage")

            if st.button("🔍 Pull Alerts from Splunk", type="primary",
                         use_container_width=True, key="sp_pull"):
                if not _query.strip():
                    st.error("Enter an SPL query")
                else:
                    _prog = st.progress(0, "Creating search job…")
                    client = SplunkClient(
                        st.session_state["splunk_host"],
                        st.session_state["splunk_port"],
                        st.session_state["splunk_user"],
                        st.session_state["splunk_pass"],
                        st.session_state.get("splunk_ssl", False),
                    )
                    _prog.progress(20, "Authenticating…")
                    ok, msg = client.authenticate()
                    if not ok:
                        st.error(f"❌ Auth failed: {msg}")
                        _prog.empty()
                    else:
                        _prog.progress(40, "Running SPL query…")
                        results, err = client.run_search(
                            _query, _earliest, "now", int(_maxres))
                        _prog.progress(80, "Parsing results…")
                        if err:
                            st.error(f"❌ Search error: {err}")
                            _prog.empty()
                        else:
                            alerts = SplunkClient.parse_alerts(results)
                            _prog.progress(100, f"Done — {len(alerts)} alerts")
                            _prog.empty()

                            st.session_state["splunk_raw_results"] = results
                            st.session_state["splunk_alerts"]      = alerts
                            st.session_state["splunk_pull_time"]   = datetime.now().strftime("%H:%M:%S")

                            if _autotriage and alerts:
                                existing = st.session_state.get("triage_alerts", [])
                                # Deduplicate by alert_type+ip
                                existing_keys = {
                                    (a.get("alert_type",""), a.get("ip",""))
                                    for a in existing
                                }
                                new_alerts = [
                                    a for a in alerts
                                    if (a.get("alert_type",""), a.get("ip",""))
                                    not in existing_keys
                                ]
                                st.session_state["triage_alerts"] = new_alerts + existing
                                st.success(
                                    f"✅ Pulled {len(results)} events → "
                                    f"{len(alerts)} alerts parsed → "
                                    f"{len(new_alerts)} new alerts added to Triage queue"
                                )
                            else:
                                st.success(f"✅ {len(results)} events → {len(alerts)} alerts parsed")

            # ── Show pulled results ───────────────────────────────────────────
            alerts = st.session_state.get("splunk_alerts", [])
            if alerts:
                pull_time = st.session_state.get("splunk_pull_time","")
                st.markdown(
                    f"<div style='color:#446688;font-size:.65rem;margin:8px 0'>"
                    f"📋 {len(alerts)} alerts pulled at {pull_time} — "
                    f"{'✅ loaded into Triage queue' if _autotriage else 'preview only'}"
                    f"</div>",
                    unsafe_allow_html=True
                )

                _SEV_C = {"critical":"#ff0033","high":"#ff9900",
                          "medium":"#ffcc00","low":"#00aaff","informational":"#446688"}
                for a in alerts[:50]:
                    _sc = _SEV_C.get(a.get("severity","medium"),"#888")
                    st.markdown(
                        f"<div style='display:flex;align-items:center;gap:10px;"
                        f"padding:5px 8px;border-bottom:1px solid #0a1420;"
                        f"background:rgba(0,0,0,0.2)'>"
                        f"<span style='color:{_sc};font-size:.65rem;font-weight:700;"
                        f"min-width:70px'>{a.get('severity','?').upper()}</span>"
                        f"<span style='color:#c8e8ff;font-size:.72rem;flex:1'>"
                        f"{a.get('alert_type','?')[:50]}</span>"
                        f"<span style='color:#446688;font-size:.62rem;min-width:100px'>"
                        f"{a.get('ip','')}</span>"
                        f"<span style='color:#446688;font-size:.58rem'>"
                        f"{str(a.get('timestamp',''))[:16]}</span>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

                _b1, _b2 = st.columns(2)
                if _b1.button("⚡ Send All to Triage Autopilot",
                               use_container_width=True, key="sp_to_triage"):
                    existing = st.session_state.get("triage_alerts", [])
                    st.session_state["triage_alerts"] = alerts + existing
                    st.success(f"✅ {len(alerts)} alerts → Triage queue")

                if _b2.button("🔍 Send All to Autonomous Investigator",
                               use_container_width=True, key="sp_to_invest"):
                    st.session_state["investigation_queue"] = alerts[:10]
                    st.success(f"✅ Top {min(10,len(alerts))} alerts → Investigator")

    # ══ TAB 3: LIVE STATUS ════════════════════════════════════════════════════
    with tab_live:
        st.markdown("**Splunk Session Status**")

        _s1, _s2, _s3, _s4 = st.columns(4)
        _s1.metric("Connection",
                   "🟢 Live" if st.session_state.get("splunk_connected") else "🔴 Not connected")
        _s2.metric("Alerts Pulled",
                   len(st.session_state.get("splunk_alerts", [])))
        _s3.metric("In Triage Queue",
                   len(st.session_state.get("triage_alerts", [])))
        _s4.metric("Last Pull",
                   st.session_state.get("splunk_pull_time", "—"))

        if st.button("🗑️ Clear Splunk session", key="sp_clear"):
            for k in ["splunk_connected","splunk_alerts","splunk_raw_results",
                      "splunk_pull_time"]:
                st.session_state.pop(k, None)
            st.success("✅ Session cleared")
            st.rerun()

        # Show triage queue summary
        triage = st.session_state.get("triage_alerts", [])
        if triage:
            from_splunk = [a for a in triage if a.get("source") == "Splunk"]
            st.markdown(f"**Triage queue: {len(triage)} total, {len(from_splunk)} from Splunk**")
            _SEV_C2 = {"critical":"#ff0033","high":"#ff9900",
                       "medium":"#ffcc00","low":"#00aaff"}
            for sev in ["critical","high","medium","low"]:
                cnt = sum(1 for a in triage if a.get("severity") == sev)
                if cnt:
                    _c = _SEV_C2.get(sev,"#888")
                    st.markdown(
                        f"<span style='color:{_c};font-size:.72rem'>"
                        f"● {sev.upper()}: {cnt}</span>  ",
                        unsafe_allow_html=True
                    )