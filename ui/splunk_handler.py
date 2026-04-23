"""
splunk_handler.py — NetSec AI v10.1
=====================================
Full Splunk integration:
  Step 1 — Receive domains FROM Splunk (webhook endpoint + SPL query builder)
  Step 2 — Write NetSec AI verdicts BACK to Splunk (HEC + KV Store + lookup CSV)
  Step 3 — Dashboard SPL generator + saved search creator

Exports: send_to_splunk, queue_alert, build_siem_alert, splunk_health_check
"""

from __future__ import annotations
import json
import logging
import os
import time
import csv
import io
from datetime import datetime
from typing import Any

logger = logging.getLogger("netsec.splunk")

# ── Config from env / session ──────────────────────────────────────────────────
def _fix_hec_url(raw: str) -> str:
    """Always return the correct /services/collector/event URL regardless of what user typed."""
    u = raw.strip().rstrip("/")
    if not u:
        return u
    # Remove any duplicate /event suffixes
    while u.endswith("/event"):
        u = u[:-6].rstrip("/")
    # Add correct path
    if "/services/collector" in u:
        u = u + "/event"
    else:
        u = u + "/services/collector/event"
    # Local Splunk: use http not https
    if "127.0.0.1" in u or "localhost" in u:
        u = u.replace("https://", "http://", 1)
    return u


def _cfg() -> dict:
    try:
        import streamlit as st
        c = st.session_state.get("user_api_config", {})
    except Exception:
        c = {}
    raw_url = c.get("splunk_hec_url","") or os.getenv("SPLUNK_HEC_URL","")
    return {
        "hec_url":   _fix_hec_url(raw_url),
        "hec_url_raw": raw_url,
        "hec_token": c.get("splunk_hec_token","") or os.getenv("SPLUNK_HEC_TOKEN",""),
        "hec_index": c.get("splunk_index","")     or os.getenv("SPLUNK_INDEX","ids_alerts"),
        "rest_url":  c.get("splunk_rest_url","")  or os.getenv("SPLUNK_REST_URL","https://127.0.0.1:8089"),
        "username":  c.get("splunk_username","")  or os.getenv("SPLUNK_USERNAME","admin"),
        "password":  c.get("splunk_password","")  or os.getenv("SPLUNK_PASSWORD",""),
    }

def _http_post(url: str, payload: dict, headers: dict, timeout: int = 8) -> tuple[bool, dict]:
    """HTTP POST using urllib (no requests dependency). Handles Splunk HEC 400 errors."""
    import urllib.request as _ur
    import urllib.error as _ue
    import json as _jj
    import ssl as _ssl

    data = _jj.dumps(payload).encode()
    req  = _ur.Request(url, data=data, headers=headers, method="POST")
    ctx  = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    try:
        with _ur.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode()
            try:
                return True, _jj.loads(body)
            except Exception:
                return True, {"raw": body[:200], "code": 0}
    except _ue.HTTPError as e:
        # Read Splunk's error body — it tells you exactly what's wrong
        try:
            err_body = e.read().decode()
            err_json = _jj.loads(err_body)
            code     = err_json.get("code", e.code)
            msg      = err_json.get("text", str(e))
            # Splunk HEC error codes
            _HEC_ERRORS = {
                0:  "Success",
                1:  "Token disabled — enable it in Data Inputs → HTTP Event Collector",
                2:  "Token is required — check Authorization header",
                3:  "Invalid authorisation token",
                4:  "Invalid event — check JSON format",
                5:  "No data — empty request body",
                6:  "Invalid content-type — must be application/json",
                7:  "Invalid data channel",
                8:  "Invalid index — check SPLUNK_INDEX or use 'main'",
                9:  "Server error",
                10: "Data channel missing",
                11: "Invalid query string",
                12: "Invalid event data — nested 'event' field required",
                13: "Queue full — Splunk is overloaded",
            }
            friendly = _HEC_ERRORS.get(code, msg)
            return False, {"error": f"HTTP {e.code}: {friendly}", "splunk_code": code,
                           "splunk_text": msg, "_http_error": e.code}
        except Exception:
            return False, {"error": f"HTTP {e.code}: {e.reason}", "_http_error": e.code}
    except Exception as e:
        return False, {"error": str(e)[:150]}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — SEND VERDICT TO SPLUNK (HEC)
# ══════════════════════════════════════════════════════════════════════════════

def _rest_post_event(data: dict, cfg: dict) -> tuple[bool, str]:
    """
    Send event to Splunk via REST API (port 8089).
    Uses /services/receivers/simple — no HEC needed, no port 8088.
    """
    import urllib.request as _ur, urllib.error as _ue
    import base64 as _b64, ssl as _ssl, json as _jj

    rest_url  = cfg["rest_url"].rstrip("/")
    index     = cfg.get("hec_index", "ids_alerts") or "ids_alerts"
    sourcetype= "netsec_ai"
    username  = cfg.get("username", "admin")
    password  = cfg.get("password", "")

    if not rest_url or not password:
        return False, "REST API not configured — add Splunk username + password in Settings → API Config"

    # /services/receivers/simple?index=X&sourcetype=Y  ← posts raw JSON event
    url   = f"{rest_url}/services/receivers/simple?index={index}&sourcetype={sourcetype}&source=netsec_ai"
    creds = _b64.b64encode(f"{username}:{password}".encode()).decode()
    body  = _jj.dumps(data).encode()

    req = _ur.Request(url, data=body,
                      headers={"Authorization": f"Basic {creds}",
                               "Content-Type": "application/json"},
                      method="POST")
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    try:
        with _ur.urlopen(req, timeout=10, context=ctx) as r:
            resp_body = r.read().decode()
            # Splunk REST returns 200 with XML or JSON on success
            logger.info("Splunk REST ✅ → index=%s status=%s", index, r.status)
            return True, f"✅ Sent to Splunk (REST API · index: {index})"
    except _ue.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode()[:150]
        except Exception:
            pass
        hint = ""
        if e.code == 401:
            hint = " — wrong username/password"
        elif e.code == 403:
            hint = " — user lacks write permission to index"
        elif e.code == 404:
            hint = f" — index '{index}' does not exist in Splunk"
        logger.warning("Splunk REST HTTP %s: %s%s", e.code, err_body, hint)
        return False, f"❌ REST error HTTP {e.code}{hint}"
    except Exception as e:
        return False, f"❌ REST connection failed: {str(e)[:80]}"


def send_to_splunk(data: dict) -> tuple[bool, str]:
    """
    Send any dict to Splunk.
    PRIMARY:  REST API on port 8089 (always available, no HEC config needed)
    FALLBACK: HEC on port 8088 (if REST fails and HEC is configured)
    Returns (success: bool, message: str)
    """
    cfg = _cfg()
    rest_ready = bool(cfg.get("rest_url") and cfg.get("username") and cfg.get("password"))
    hec_ready  = bool(cfg.get("hec_url")  and cfg.get("hec_token"))

    if not rest_ready and not hec_ready:
        return False, ("Splunk not configured — add credentials in Settings → API Config:\n"
                       "  • REST: username + password (uses port 8089 — already open)\n"
                       "  • HEC:  token + URL (uses port 8088 — needs enabling)")

    # ── Try REST API first (port 8089 — your REST is already working) ─────────
    if rest_ready:
        ok, msg = _rest_post_event(data, cfg)
        if ok:
            return True, msg
        logger.warning("REST send failed (%s) — trying HEC fallback", msg)

    # ── HEC fallback (port 8088) ───────────────────────────────────────────────
    if hec_ready:
        hec_url = cfg["hec_url"]
        _index  = cfg.get("hec_index", "ids_alerts") or "ids_alerts"
        payload = {
            "event":      data,
            "sourcetype": "netsec_ai",
            "index":      _index,
            "time":       time.time(),
            "source":     "netsec_ai_ids",
            "host":       "netsec-ai-dashboard",
        }
        ok, resp = _http_post(
            hec_url, payload,
            {"Authorization": f"Splunk {cfg['hec_token']}",
             "Content-Type":  "application/json"}
        )
        if ok and (resp.get("code") == 0 or resp.get("text") == "Success"):
            return True, f"✅ Sent to Splunk (HEC · index: {_index})"
        err = resp.get("error", str(resp))
        return False, f"❌ Both REST and HEC failed. REST: see log. HEC: {err}"

    return False, "❌ No working Splunk connection — check Settings → API Config"



def queue_alert(result: dict) -> None:
    """
    Background-safe wrapper around send_to_splunk.
    Called automatically after every domain analysis.
    Enriches the payload with NetSec AI fields before sending.
    """
    payload = {
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "source_tool":  "netsec_ai",
        "event_type":   "domain_triage",
        # Core verdict fields
        "domain":       str(result.get("domain", result.get("host", ""))),
        "ip":           str(result.get("ip", "")),
        "verdict":      str(result.get("verdict", result.get("overall", "UNKNOWN"))),
        "risk_score":   result.get("risk_score", result.get("threat_score", 0)),
        "confidence":   result.get("confidence", 0),
        "severity":     str(result.get("severity", "unknown")),
        "mitre":        str(result.get("mitre", "")),
        "alert_type":   str(result.get("alert_type", result.get("type", ""))),
        # DPDP
        "dpdp_relevant": bool(result.get("dpdp_relevant", False)),
    }
    ok, msg = send_to_splunk(payload)
    if not ok:
        logger.warning("queue_alert failed: %s", msg)
    try:
        import streamlit as st
        st.session_state.setdefault("splunk_log", []).append({
            "ts":      datetime.now().strftime("%H:%M:%S"),
            "domain":  payload["domain"],
            "verdict": payload["verdict"],
            "score":   payload["risk_score"],
            "ok":      ok,
            "msg":     msg,
        })
        st.session_state["splunk_log"] = st.session_state["splunk_log"][-50:]
    except Exception:
        pass


def build_siem_alert(domain: str, verdict: str, risk_score: int,
                     confidence: int, mitre: str = "", severity: str = "medium") -> dict:
    """Build a structured SIEM alert dict ready for send_to_splunk."""
    return {
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "source_tool": "netsec_ai",
        "event_type":  "siem_alert",
        "domain":      domain,
        "verdict":     verdict,
        "risk_score":  risk_score,
        "confidence":  confidence,
        "severity":    severity,
        "mitre":       mitre,
        "action":      ("block_recommended" if risk_score < 30
                        else "investigate" if risk_score < 60
                        else "no_action"),
    }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2b — WRITE VERDICT TO SPLUNK KV STORE / LOOKUP CSV
# ══════════════════════════════════════════════════════════════════════════════

def write_verdict_to_kv_store(domain: str, verdict: str,
                               risk_score: int, confidence: int) -> tuple[bool, str]:
    """
    Write NetSec AI verdict into Splunk KV Store (requires REST API).
    Creates a persistent lookup that Splunk searches can join on.
    """
    cfg = _cfg()
    if not cfg["rest_url"]:
        return False, "Splunk REST URL not configured"

    import base64 as _b64
    creds  = _b64.b64encode(f"{cfg['username']}:{cfg['password']}".encode()).decode()
    url    = f"{cfg['rest_url'].rstrip('/')}/servicesNS/nobody/search/storage/collections/data/netsec_ai_verdicts"
    record = {
        "domain":     domain,
        "verdict":    verdict,
        "risk_score": str(risk_score),
        "confidence": str(confidence),
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "source":     "netsec_ai",
    }
    ok, resp = _http_post(url, record, {"Authorization": f"Basic {creds}",
                                         "Content-Type": "application/json"})
    return ok, str(resp)


def write_verdict_to_csv_lookup(domain: str, verdict: str,
                                 risk_score: int, confidence: int,
                                 csv_path: str = "domains_lookup.csv") -> bool:
    """
    Append verdict to a CSV lookup file that Splunk can read.
    Simpler than KV store — works without REST API.
    File goes in: $SPLUNK_HOME/etc/apps/search/lookups/domains_lookup.csv
    """
    try:
        fieldnames = ["domain","verdict","risk_score","confidence","updated_at","source"]
        row = {
            "domain":     domain,
            "verdict":    verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "updated_at": datetime.utcnow().isoformat(),
            "source":     "netsec_ai",
        }
        write_header = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                w.writeheader()
            w.writerow(row)
        return True
    except Exception as e:
        logger.error("CSV lookup write failed: %s", e)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — SPL QUERIES (copy-paste into Splunk)
# ══════════════════════════════════════════════════════════════════════════════

SPL_QUERIES = {
    "find_domains": """
index=* sourcetype=access_combined OR sourcetype=firewall OR sourcetype=proxy OR sourcetype=dns
| rex field=_raw "(?P<domain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,})"
| where isnotnull(domain) AND len(domain) > 4
| stats count, latest(_time) as last_seen by domain
| where count > 0
| eval alert_type="domain_observed"
| sort -count
| head 100
""".strip(),

    "find_malicious_ips": """
index=* sourcetype=firewall OR sourcetype=ids OR sourcetype=netflow
| rex field=_raw "(?P<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"
| where isnotnull(src_ip) AND NOT cidrmatch("10.0.0.0/8", src_ip)
    AND NOT cidrmatch("192.168.0.0/16", src_ip)
    AND NOT cidrmatch("172.16.0.0/12", src_ip)
| stats count by src_ip
| where count > 10
| sort -count
""".strip(),

    "dns_beaconing": """
index=dns OR index=* sourcetype=dns
| stats count, dc(answer) as unique_answers,
    range(_time) as time_span by src_ip, query
| where count > 100 AND unique_answers < 5
| eval beacon_ratio = round(count / (time_span / 60), 2)
| where beacon_ratio > 1
| sort -count
| eval alert_type="dns_beaconing"
""".strip(),

    "netsec_ai_verdicts_dashboard": """
| inputlookup domains_lookup.csv
| eval verdict_color = case(
    verdict=="TRUSTED INFRASTRUCTURE",   "#00c878",
    verdict=="LIKELY BENIGN",            "#00aaff",
    verdict=="SUSPICIOUS",               "#ffcc00",
    verdict=="MALICIOUS",                "#ff0033",
    verdict=="KNOWN TEST DOMAIN",        "#ff9900",
    1=1,                                 "#888888"
  )
| eval risk_band = case(
    risk_score >= 70, "SAFE",
    risk_score >= 40, "LOW RISK",
    risk_score >= 20, "SUSPICIOUS",
    1=1,              "MALICIOUS"
  )
| table domain verdict risk_score confidence updated_at verdict_color risk_band
| sort -updated_at
""".strip(),

    "netsec_ai_alerts": """
index=main sourcetype=netsec_ai
| eval risk_band = case(
    risk_score >= 70, "SAFE",
    risk_score >= 40, "LOW RISK",
    risk_score >= 20, "SUSPICIOUS",
    1=1,              "MALICIOUS"
  )
| table _time domain verdict risk_score confidence severity mitre alert_type risk_band
| sort -_time
""".strip(),

    "high_risk_domains": """
index=main sourcetype=netsec_ai risk_score<40
| table _time domain verdict risk_score confidence mitre
| sort -risk_score
| head 20
""".strip(),

    "dpdp_breach_candidates": """
index=main sourcetype=netsec_ai dpdp_relevant=true
| table _time domain verdict risk_score severity
| sort -_time
""".strip(),

    # ── Enterprise v11.0 additions ─────────────────────────────────────────
    "misp_correlation": """
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
| sort -_time
""".strip(),

    "brute_force_detection": """
index=wazuh OR index=auth
| search (action=failed OR EventCode=4625 OR "authentication failed")
| bucket _time span=5m
| stats count AS failed_attempts, dc(user) AS unique_users BY _time, src_ip
| where failed_attempts > 20
| eval severity="HIGH", mitre="T1110", tactic="Credential Access"
| table _time, src_ip, failed_attempts, unique_users, severity, mitre
""".strip(),

    "lateral_movement_smb": """
index=wazuh OR index=network
| search (dest_port=445 OR dest_port=139)
| stats dc(dest_ip) AS unique_dest, values(dest_ip) AS destinations BY src_ip
| where unique_dest > 3
| eval severity="HIGH", mitre="T1021.002", tactic="Lateral Movement"
| table src_ip, unique_dest, destinations, severity, mitre
| sort -unique_dest
""".strip(),

    "data_exfil_dns": """
index=dns sourcetype=dns
| eval query_len=len(query)
| where query_len > 100
| stats count AS query_count, avg(query_len) AS avg_len, values(query) AS sample_queries BY src_ip
| where query_count > 10
| eval severity="CRITICAL", mitre="T1048.003", tactic="Exfiltration"
| table src_ip, query_count, avg_len, severity, mitre
""".strip(),

    "combined_soc_dashboard": """
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
| sort -severity_score, -_time
""".strip(),
}

SPLUNK_ALERT_SPL = """
index=* sourcetype=access_combined OR sourcetype=firewall OR sourcetype=dns
| rex field=_raw "(?P<domain>(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,})"
| where isnotnull(domain) AND len(domain) > 4
| stats count by domain
| where count > 0
| eval alert_type="domain_observed"
| table domain alert_type count
""".strip()

SPLUNK_WEBHOOK_PAYLOAD = """{
  "domain":      "$result.domain$",
  "alert_type":  "$result.alert_type$",
  "count":       "$result.count$",
  "search_name": "$name$",
  "trigger_time":"$trigger.time$"
}"""


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

def splunk_health_check() -> dict:
    """Test HEC connectivity. Returns dict with both 'status' and 'hec_status' keys."""
    cfg = _cfg()
    result = {
        "hec_configured":  bool(cfg["hec_url"] and cfg["hec_token"]),
        "rest_configured": bool(cfg["rest_url"] and cfg["username"]),
        "hec_status":      "not_configured",
        "status":          "not_configured",   # alias so both key names work
        "rest_status":     "not_configured",
        "hec_url":         cfg["hec_url"] or "(not set)",
        "hec_url_raw":     cfg.get("hec_url_raw","") or cfg["hec_url"],
        "rest_url":        cfg["rest_url"],
        "latency_ms":      0,
        "message":         "",
    }

    # Test REST API first (primary path — port 8089)
    rest_ready = bool(cfg.get("rest_url") and cfg.get("username") and cfg.get("password"))
    if rest_ready:
        t0 = time.time()
        ok, msg = _rest_post_event({
            "event_type": "health_check",
            "source":     "netsec_ai",
            "timestamp":  datetime.utcnow().isoformat(),
        }, cfg)
        result["latency_ms"]  = round((time.time() - t0) * 1000)
        result["rest_status"] = "ok" if ok else "error"
        result["status"]      = "ok" if ok else "error"
        result["hec_status"]  = "ok" if ok else "error"  # keep aliases in sync
        if not ok:
            result["hec_error"] = msg
        else:
            result["message"] = f"✅ Splunk REST connected ({result['latency_ms']}ms) — port 8089 · Splunk {result.get('splunk_version','?')}"

    # Test HEC only if REST not configured (fallback)
    elif result["hec_configured"]:
        t0 = time.time()
        ok, msg = send_to_splunk({
            "event_type": "health_check",
            "source":     "netsec_ai",
            "timestamp":  datetime.utcnow().isoformat(),
        })
        result["latency_ms"] = round((time.time() - t0) * 1000)
        result["hec_status"] = "ok" if ok else "error"
        result["status"]     = "ok" if ok else "error"
        result["hec_error"]  = "" if ok else str(msg)

    # Test REST API
    if result["rest_configured"]:
        try:
            import urllib.request as _ur, base64 as _b64, ssl as _ssl
            creds = _b64.b64encode(f"{cfg['username']}:{cfg['password']}".encode()).decode()
            url   = f"{cfg['rest_url'].rstrip('/')}/services/server/info?output_mode=json"
            req   = _ur.Request(url, headers={"Authorization": f"Basic {creds}"})
            ctx   = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            with _ur.urlopen(req, timeout=6, context=ctx) as r:
                info = json.loads(r.read().decode())
            version = info.get("entry",[{}])[0].get("content",{}).get("version","?")
            result["rest_status"]  = "ok"
            result["splunk_version"] = version
        except Exception as e:
            result["rest_status"] = "error"
            result["rest_error"]  = str(e)[:80]

    # Summary message (only set if not already set by REST test above)
    if not result.get("message"):
        if result["status"] == "ok":
            result["message"] = f"✅ Splunk connected ({result['latency_ms']}ms) · Splunk {result.get('splunk_version','?')}"
        elif result.get("hec_configured") or result.get("rest_configured"):
            err = result.get("hec_error", result.get("rest_error","unknown"))
            result["message"] = f"❌ Connection error: {err}"
        else:
            result["message"] = "⚠️ Not configured — add Splunk REST credentials in Settings → API Config"

    return result


# ══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI — render_splunk_integration()
# ══════════════════════════════════════════════════════════════════════════════

def render_splunk_integration():
    """Full Splunk integration UI — all 3 steps in one panel."""
    try:
        import streamlit as st
    except ImportError:
        return

    st.markdown(
        "<div style='font-family:Orbitron,monospace;font-size:.9rem;font-weight:900;"
        "color:#ff6600;letter-spacing:2px;margin-bottom:4px'>"
        "📊 SPLUNK INTEGRATION</div>"
        "<div style='color:#446688;font-size:.68rem;margin-bottom:12px'>"
        "Step 1: Splunk → NetSec AI &nbsp;·&nbsp; Step 2: NetSec AI → Splunk &nbsp;·&nbsp; "
        "Step 3: Dashboard SPL</div>",
        unsafe_allow_html=True
    )

    tab_status, tab_step1, tab_step2, tab_step3, tab_log = st.tabs([
        "🔌 Status", "📥 Step 1 — Receive", "📤 Step 2 — Send", "📊 Step 3 — Dashboard", "📋 Log"
    ])

    # ── STATUS ──────────────────────────────────────────────────────────────
    with tab_status:
        cfg = _cfg()
        _hec_ok  = bool(cfg["hec_url"] and cfg["hec_token"])
        _rest_ok = bool(cfg["rest_url"] and cfg["username"])

        c1, c2, c3 = st.columns(3)
        c1.metric("HEC",      "✅ Configured" if _hec_ok  else "⚠️ Not set",
                  delta="URL + Token" if _hec_ok else "Add in API Config")
        c2.metric("REST API", "✅ Configured" if _rest_ok else "⚠️ Not set",
                  delta="URL + creds"  if _rest_ok else "Optional")
        c3.metric("Events sent", len(st.session_state.get("splunk_log",[])))

        if st.button("🔌 Test Splunk Connection", key="splunk_health_btn",
                     type="primary", use_container_width=True):
            with st.spinner("Testing…"):
                result = splunk_health_check()
            if "ok" in result.get("hec_status",""):
                st.success(result["message"])
            else:
                st.warning(result["message"])
            with st.expander("Full result"):
                st.json(result)

        if not _hec_ok:
            st.info(
                "**To enable:** Settings → API Config → Splunk section\n\n"
                "- **Splunk HEC URL:** `http://localhost:8088/services/collector/event`\n"
                "- **Splunk HEC Token:** from Splunk → Settings → Data Inputs → HTTP Event Collector\n\n"
                "Get token: Splunk Web → **Settings → Data Inputs → HTTP Event Collector → New Token** "
                "→ Name: netsec-ai, Source type: _json, Index: main → Save → copy token"
            )

        # Manual send test
        st.divider()
        st.markdown("**📤 Manual test — send a test event to Splunk:**")
        _tc, _tb = st.columns([3, 1])
        _test_domain = _tc.text_input("Domain to test", value="185.220.101.45", key="spl_test_domain")
        if _tb.button("Send", key="spl_test_send", use_container_width=True):
            ok, msg = send_to_splunk({
                "event_type": "manual_test", "domain": _test_domain,
                "verdict": "MALICIOUS", "risk_score": 15, "confidence": 85,
                "source": "netsec_ai_manual_test",
                "timestamp": datetime.utcnow().isoformat()
            })
            (st.success if ok else st.error)(msg)

    # ── STEP 1: RECEIVE FROM SPLUNK ──────────────────────────────────────────
    with tab_step1:
        st.markdown("**Goal:** Splunk finds domains in your logs → sends them to NetSec AI for triage")
        st.markdown("#### 1. Create this Saved Search in Splunk")
        st.markdown("Go to **Splunk Web → Search → Save As Alert** → paste this SPL:")
        st.code(SPLUNK_ALERT_SPL, language="spl")

        st.markdown("#### 2. Alert settings")
        _s1, _s2 = st.columns(2)
        with _s1:
            st.markdown("""
- **Title:** NetSec AI — Domain Triage
- **Alert type:** Scheduled (every 15 min)
- **Trigger when:** Number of results > 0
- **Trigger for:** Each result
            """)
        with _s2:
            st.markdown("""
- **Action:** Webhook
- **URL:** `http://localhost:8501/` *(your app)*
- **Method:** POST
- **Content-Type:** application/json
            """)

        st.markdown("#### 3. Webhook payload (paste into Splunk)")
        st.code(SPLUNK_WEBHOOK_PAYLOAD, language="json")

        st.info(
            "💡 NetSec AI doesn't need a separate endpoint — "
            "the data flows through the **n8n webhook** you already set up, "
            "which then calls NetSec AI's reputation engine automatically."
        )

    # ── STEP 2: SEND TO SPLUNK ───────────────────────────────────────────────
    with tab_step2:
        st.markdown("**Goal:** After every domain triage → verdict automatically appears in Splunk")

        st.markdown("#### Automatic (already wired in)")
        st.markdown(
            "Every time you run a domain lookup or triage, `queue_alert()` fires automatically "
            "and sends the verdict to Splunk HEC. Just make sure HEC is configured in **Settings → API Config**."
        )

        st.markdown("#### Manual send from this panel")
        with st.form("manual_splunk_send"):
            _md = st.text_input("Domain", value="testphp.vulnweb.com")
            _v  = st.selectbox("Verdict", ["TRUSTED INFRASTRUCTURE","LIKELY BENIGN",
                                             "SUSPICIOUS","MALICIOUS","KNOWN TEST DOMAIN"])
            _rs = st.slider("Risk score (0=malicious, 100=safe)", 0, 100, 75)
            _cf = st.slider("Confidence %", 0, 100, 80)
            _mi = st.text_input("MITRE", value="T1071")
            if st.form_submit_button("📤 Send to Splunk", type="primary", use_container_width=True):
                payload = build_siem_alert(_md, _v, _rs, _cf, _mi,
                                           "high" if _rs < 30 else "medium" if _rs < 60 else "low")
                ok, msg = send_to_splunk(payload)
                (st.success if ok else st.error)(msg)
                # Also write to CSV lookup
                write_verdict_to_csv_lookup(_md, _v, _rs, _cf)
                st.caption("Also written to domains_lookup.csv for Splunk lookup joins")

        st.markdown("#### CSV Lookup file (copy to Splunk)")
        st.markdown(
            "After sending verdicts, copy `domains_lookup.csv` from your project root to:\n\n"
            "`$SPLUNK_HOME/etc/apps/search/lookups/domains_lookup.csv`\n\n"
            "Then Splunk searches can do: `| inputlookup domains_lookup.csv`"
        )

    # ── STEP 3: DASHBOARD SPL ────────────────────────────────────────────────
    with tab_step3:
        st.markdown("**Goal:** Splunk dashboard showing all NetSec AI verdicts in one screen")

        _q_choice = st.selectbox("Select query", [
            "netsec_ai_alerts             — all events from NetSec AI",
            "netsec_ai_verdicts_dashboard — lookup-based verdict table",
            "high_risk_domains            — only score < 40 (malicious/suspicious)",
            "dpdp_breach_candidates       — DPDP relevant events",
            "find_domains                 — extract domains from raw logs",
            "dns_beaconing                — detect C2-like DNS patterns",
            "find_malicious_ips           — extract external IPs",
            "misp_correlation             — Wazuh alerts x MISP IOC lookup [T1071]",
            "brute_force_detection        — 20+ failed logins/5min [T1110]",
            "lateral_movement_smb         — SMB to 3+ hosts [T1021.002]",
            "data_exfil_dns               — DNS query length >100 chars [T1048.003]",
            "combined_soc_dashboard       — All threats: Wazuh + MISP + NetSec AI",
        ], key="spl_q_choice")

        _key = _q_choice.split()[0].strip()
        _spl = SPL_QUERIES.get(_key, "")
        if _spl:
            st.code(_spl, language="spl")
            st.caption("Copy this → Splunk Web → Search → paste → run → Save As → Dashboard Panel")

        st.markdown("#### Dashboard creation steps")
        st.markdown("""
1. Splunk Web → **Dashboards → Create New Dashboard**
2. Title: **NetSec AI Verdicts** → Classic Dashboards → Create
3. Click **+ Add Panel** → New from Search
4. Paste the `netsec_ai_alerts` query above
5. Visualization: **Table** (or Statistics)
6. **+ Add Panel** again → paste `high_risk_domains`
7. Visualization: **Single value** (shows count of malicious)
8. Save → share with your team
        """)

    # ── LOG ─────────────────────────────────────────────────────────────────
    with tab_log:
        st.markdown("**Recent Splunk events sent from NetSec AI:**")
        log = st.session_state.get("splunk_log", [])
        if not log:
            st.info("No events sent yet. Run a domain triage or click 'Send' above.")
        else:
            for entry in reversed(log[-20:]):
                _ic = "✅" if entry.get("ok") else "❌"
                _vc = {"MALICIOUS":"#ff0033","SUSPICIOUS":"#ffcc00",
                       "LIKELY BENIGN":"#00aaff","TRUSTED INFRASTRUCTURE":"#00c878"
                       }.get(entry.get("verdict",""), "#888")
                st.markdown(
                    f"<div style='display:flex;gap:12px;align-items:center;padding:4px 0;"
                    f"border-bottom:1px solid #0d1a2a;font-size:.72rem'>"
                    f"<span style='color:#446688'>{entry.get('ts','')}</span>"
                    f"<span>{_ic}</span>"
                    f"<span style='color:#c8e8ff;min-width:160px'>{entry.get('domain','')}</span>"
                    f"<span style='color:{_vc}'>{entry.get('verdict','')}</span>"
                    f"<span style='color:#446688'>{entry.get('score','')}/100</span>"
                    f"</div>",
                    unsafe_allow_html=True
                )
        if log and st.button("Clear log", key="spl_clear_log"):
            st.session_state["splunk_log"] = []
            st.rerun()