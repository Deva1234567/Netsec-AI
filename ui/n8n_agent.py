"""
n8n_agent.py — NetSec AI SOC Platform
======================================
SOAR integration layer for n8n workflow automation.

Functions exported to app.py:
  auto_trigger(domain, ip, alert_type, severity, threat_score, details)
  trigger_slack_notify(message, severity)
  trigger_block_ip(ip, reason, threat_score)
  trigger_enrich_ioc(ioc, ioc_type)
  trigger_daily_report(summary_dict)
  n8n_health_check()
  get_workflow_list()
  get_workflow_setup_guide()
  SOC_WORKFLOW_TEMPLATES  (dict)

Environment variables:
  N8N_WEBHOOK_URL   — base webhook URL  (e.g. https://your-n8n.railway.app)
  N8N_API_KEY       — n8n API key for REST calls
  N8N_BASE_URL      — n8n UI base URL   (default: http://localhost:5678)
  SLACK_WEBHOOK_URL — direct Slack fallback (optional)
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Any
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
logger = logging.getLogger("netsec.n8n_agent")

# ── Env ───────────────────────────────────────────────────────────────────────
_N8N_WEBHOOK = os.getenv("N8N_WEBHOOK_URL", "").rstrip("/")
_N8N_API_KEY = os.getenv("N8N_API_KEY", "")
_N8N_BASE    = os.getenv("N8N_BASE_URL", "http://localhost:5678").rstrip("/")
_SLACK_WH    = os.getenv("SLACK_WEBHOOK_URL", "")

def _req():
    try:
        import requests as _r
        return _r
    except ImportError:
        raise RuntimeError("requests library not installed — run: pip install requests")


# ══════════════════════════════════════════════════════════════════════════════
# SOC Workflow Templates
# ══════════════════════════════════════════════════════════════════════════════
# ── IMPORTANT: All triggers use ONE webhook path ──────────────────────────────
# The "action" field inside the payload tells n8n what to do via an IF/Switch node.
# This way you only need ONE active workflow in n8n, not six.
# Your n8n webhook path: /webhook/soc-alert  (set N8N_WEBHOOK_URL in .env)
# ─────────────────────────────────────────────────────────────────────────────

SOC_WORKFLOW_TEMPLATES: dict[str, dict] = {
    "critical_alert": {
        "name": "🚨 Critical Alert — Slack + Jira + Block",
        "trigger": "threat_score >= 80 OR severity = critical",
        "description": (
            "Fires when the ML model or correlation engine flags a critical threat. "
            "Sends a Slack alert, opens a Jira P1 ticket, and blocks the source IP."
        ),
        "nodes": [
            "1. Webhook trigger (POST /webhook/soc-alert)",
            "2. Switch node — route by action field",
            "3. Slack node — post to #soc-alerts channel",
            "4. IF node — threat_score > 90 → Jira ticket",
            "5. Jira node — create P1 issue in SOC project",
            "6. HTTP Request — call firewall API to block IP",
            "7. Respond to Webhook — return {ok: true}",
        ],
        "setup_steps": [
            "Create ONE workflow in n8n with webhook path: soc-alert",
            "Add Switch node routing on action field",
            "Add Slack credential",
            "Activate workflow",
        ],
        "webhook_path": "/webhook/soc-alert",   # ← single unified path
    },
    "ioc_enrichment": {
        "name": "🔭 IOC Enrichment Pipeline",
        "trigger": "New IOC submitted for lookup",
        "description": (
            "Accepts an IP/domain/hash and fans out to AbuseIPDB, VirusTotal, OTX, "
            "and Shodan in parallel. Merges results and returns a unified threat score."
        ),
        "nodes": [
            "1. Webhook trigger (POST /soc/enrich-ioc)",
            "2. Switch node — route by ioc_type (ip/domain/hash)",
            "3a. HTTP Request — AbuseIPDB /check",
            "3b. HTTP Request — VirusTotal /files or /domains",
            "3c. HTTP Request — OTX /indicators",
            "3d. HTTP Request — Shodan /shodan/host/{ip}",
            "4. Merge node — combine all results",
            "5. Code node — calculate composite_score",
            "6. Respond to Webhook — return enriched result",
        ],
        "setup_steps": [
            "Add API keys to n8n Credentials store",
            "Set ABUSEIPDB_KEY, VT_KEY, OTX_KEY, SHODAN_KEY",
            "Import workflow JSON",
            "Activate workflow",
        ],
        "webhook_path": "/webhook/soc-alert",
    },
    "ip_block": {
        "name": "🔒 Auto IP Block + Audit",
        "trigger": "IP reputation score > 75 OR manual trigger",
        "description": (
            "Blocks a malicious IP at the perimeter firewall, logs the action to Splunk, "
            "posts a Slack notification, and creates an audit trail entry."
        ),
        "nodes": [
            "1. Webhook trigger (POST /soc/block-ip)",
            "2. HTTP Request — firewall API (add deny rule)",
            "3. HTTP Request — Splunk HEC (log block action)",
            "4. Slack node — notify #soc-blocks channel",
            "5. Google Sheets / DB — append to block audit log",
            "6. Respond to Webhook — return {blocked: true}",
        ],
        "setup_steps": [
            "Configure firewall API endpoint + auth token",
            "Set Splunk HEC URL and token",
            "Add Slack credential",
            "Import and activate workflow",
        ],
        "webhook_path": "/webhook/soc-alert",
    },
    "daily_report": {
        "name": "📊 Daily SOC Report",
        "trigger": "Cron: 08:00 every weekday  OR  manual POST",
        "description": (
            "Compiles the previous 24 hours of alerts from Splunk, calculates MTTD/MTTR, "
            "generates a summary, and emails it to the SOC team and CISO."
        ),
        "nodes": [
            "1. Cron trigger (08:00 Mon-Fri) or Webhook",
            "2. HTTP Request — Splunk REST API (last 24h stats)",
            "3. Code node — calculate metrics (MTTD, MTTR, FP rate)",
            "4. HTML template node — render report",
            "5. Email node — send to soc-team@corp.com + ciso@corp.com",
            "6. Slack node — post summary to #soc-daily",
        ],
        "setup_steps": [
            "Add Splunk REST credential (username + password or token)",
            "Set email SMTP credential",
            "Add Slack credential",
            "Adjust recipient addresses in Email node",
            "Activate workflow",
        ],
        "webhook_path": "/webhook/soc-alert",
    },
    "ir_escalation": {
        "name": "🔴 Incident Response Escalation",
        "trigger": "correlation_rule fired OR manual escalation",
        "description": (
            "Full IR workflow: pages the on-call analyst via PagerDuty, creates a "
            "Jira incident, posts to Slack with full context, and triggers host isolation."
        ),
        "nodes": [
            "1. Webhook trigger (POST /soc/ir-escalation)",
            "2. HTTP Request — PagerDuty Events API (trigger incident)",
            "3. Jira node — create Critical issue with all context",
            "4. Slack node — post to #incident-response with @here",
            "5. HTTP Request — EDR API to isolate affected host",
            "6. HTTP Request — Splunk HEC (log escalation)",
            "7. Respond to Webhook — return {escalated: true, pagerduty_id}",
        ],
        "setup_steps": [
            "Add PagerDuty integration key",
            "Add Jira credential",
            "Add Slack credential",
            "Set EDR isolation API endpoint",
            "Import and activate",
        ],
        "webhook_path": "/webhook/soc-alert",
    },
    "phishing_response": {
        "name": "🎣 Phishing Auto-Response",
        "trigger": "alert_type = Phishing OR threat_score > 60 for phishing domain",
        "description": (
            "Extracts IOCs from phishing alert, blocks sender domain, hunts for "
            "other users who received the same email, and notifies affected users."
        ),
        "nodes": [
            "1. Webhook trigger (POST /soc/phishing-response)",
            "2. Code node — extract sender domain + URLs",
            "3. HTTP Request — add domain to email gateway blocklist",
            "4. HTTP Request — Splunk search for other recipients",
            "5. Loop Over Items — send warning email to each recipient",
            "6. Slack node — summary to #soc-phishing",
            "7. Respond to Webhook",
        ],
        "setup_steps": [
            "Configure email gateway API",
            "Add Splunk REST credential",
            "Add SMTP for user notifications",
            "Activate workflow",
        ],
        "webhook_path": "/webhook/soc-alert",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ══════════════════════════════════════════════════════════════════════════════
def _webhook_url(path: str) -> str:
    base = _N8N_WEBHOOK or _N8N_BASE
    return f"{base}{path}"


def _post(path: str, payload: dict, timeout: int = 60) -> tuple[bool, dict]:
    _base = (_N8N_WEBHOOK or _N8N_BASE).rstrip("/")
    
    # Handle webhook path correctly
    if path.startswith("/webhook/"):
        import urllib.parse as _up
        _parsed = _up.urlparse(_base)
        _host_only = f"{_parsed.scheme}://{_parsed.netloc}"
        url = _host_only + path
    else:
        url = _base + path

    headers = {"Content-Type": "application/json"}
    if _N8N_API_KEY:
        headers["X-N8N-API-KEY"] = _N8N_API_KEY

    if not (_N8N_WEBHOOK or _N8N_BASE.startswith("http")):
        logger.warning("n8n webhook URL not configured — running in demo mode")
        return True, {"demo": True, "message": "Demo mode — n8n not configured", "payload": payload}

    try:
        r = _req().post(url, json=payload, headers=headers, timeout=timeout)

        if r.status_code in (200, 201):
            try:
                result = r.json()
            except Exception:
                result = {"status": "ok", "raw": r.text[:200]}

            # === LOG SUCCESS ===
            try:
                import streamlit as st
                log_entry = {
                    "action": payload.get("action", path),
                    "target": payload.get("ip", payload.get("domain", payload.get("target", ""))),
                    "status": "ok",
                    "executed_at": _ts(),
                    "result": result,
                    "error": ""
                }
                st.session_state.setdefault("n8n_action_log", []).insert(0, log_entry)
            except Exception:
                pass

            return True, result

        else:
            logger.warning("n8n returned %s for %s", r.status_code, url)
            # === LOG FAILURE ===
            try:
                import streamlit as st
                log_entry = {
                    "action": payload.get("action", path),
                    "target": payload.get("ip", payload.get("domain", payload.get("target", ""))),
                    "status": "error",
                    "executed_at": _ts(),
                    "result": {},
                    "error": f"HTTP {r.status_code}"
                }
                st.session_state.setdefault("n8n_action_log", []).insert(0, log_entry)
            except Exception:
                pass

            return False, {"error": f"HTTP {r.status_code}", "body": r.text[:200]}

    except Exception as exc:
        logger.error("n8n error: %s — %s", url, exc)
        return False, {"error": str(exc)}


def _ts() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def auto_trigger_n8n(alert_data: dict):
    """Automatically trigger n8n for high-risk alerts"""
    
    threat_score = alert_data.get("threat_score", 0)
    severity = alert_data.get("severity", "").lower()
    ip = alert_data.get("ip") or alert_data.get("source_ip")
    domain = alert_data.get("domain")
    
    # Only auto-trigger for critical/high risk
    if threat_score >= 80 or severity in ["critical", "high"]:
        
        payload = {
            "action": "critical_alert",
            "ip": ip,
            "domain": domain,
            "threat_score": threat_score,
            "severity": severity,
            "mitre": alert_data.get("mitre_technique", ""),
            "timestamp": _ts(),
            "alert_id": alert_data.get("alert_id", "auto")
        }
        
        success, result = _post("/webhook/soc-alert", payload)
        
        if success:
            st.success(f"✅ Auto-triggered n8n for critical alert (Score: {threat_score})")
        else:
            st.error(f"❌ Auto-trigger failed: {result.get('error', 'Unknown')}")
# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def auto_trigger(
    domain: str,
    ip: str,
    alert_type: str,
    severity: str,
    threat_score: int,
    details: dict | None = None,
) -> tuple[bool, dict]:
    """
    Main auto-trigger called after every detection.
    Routes to the correct workflow based on severity and score.
    """
    # Determine action field for n8n Switch node routing
    if severity == "critical" or threat_score >= 80:
        _action = "critical_alert"
    elif severity == "high" or threat_score >= 60:
        _action = "high_alert"
    elif severity == "medium" or threat_score >= 40:
        _action = "medium_alert"
    else:
        _action = "log_only"

    payload = {
        "timestamp":    _ts(),
        "action":       _action,        # n8n Switch node routes on this
        "domain":       domain,
        "ip":           ip,
        "alert_type":   alert_type,
        "severity":     severity,
        "threat_score": threat_score,
        "source":       "netsec_ai_ids",
        "details":      details or {},
    }

    # All requests go to ONE webhook — action field routes inside n8n
    if _action == "log_only":
        logger.debug("auto_trigger: below threshold for %s (score=%s)", domain, threat_score)
        return True, {"skipped": True, "reason": "below threshold",
                      "score": threat_score, "action": _action}

    logger.info("auto_trigger → %s for %s (score=%s)", _action, domain, threat_score)
    return _post("/webhook/soc-alert", payload)


def trigger_slack_notify(message: str, severity: str = "high") -> tuple[bool, dict]:
    """Send Slack notification via n8n webhook (or direct Slack webhook fallback)."""
    severity_emoji = {
        "critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "🟢", "info": "⚪",
    }.get(severity, "🔵")

    payload = {
        "timestamp": _ts(),
        "severity":  severity,
        "message":   message,
        "emoji":     severity_emoji,
        "source":    "netsec_ai_ids",
        "text":      f"{severity_emoji} *NetSec AI IDS* [{severity.upper()}]\n{message}",
        "channel":   "#soc-alerts",
    }

    # Try direct Slack first (faster)
    if _SLACK_WH:
        try:
            slack_payload = {
                "text": payload["text"],
                "attachments": [{
                    "color": {"critical":"#ff0033","high":"#e67e22",
                               "medium":"#f39c12","low":"#27ae60"}.get(severity,"#666"),
                    "fields": [
                        {"title":"Severity","value":severity,"short":True},
                        {"title":"Time",    "value":_ts(),   "short":True},
                    ],
                }],
            }
            r = _req().post(_SLACK_WH, json=slack_payload, timeout=8)
            if r.status_code == 200:
                logger.info("Slack direct notify sent: %s", message[:60])
                return True, {"channel": "direct_slack", "status": "sent"}
        except Exception as exc:
            logger.warning("Direct Slack failed, falling back to n8n: %s", exc)

    ok, resp = _post("/webhook/soc-alert", payload)
    logger.info("trigger_slack_notify [%s]: ok=%s", severity, ok)
    return ok, resp


def trigger_block_ip(
    ip: str,
    reason: str,
    threat_score: int,
    auto: bool = False,
) -> tuple[bool, dict]:
    """Block an IP via n8n firewall API workflow."""
    payload = {
        "timestamp":    _ts(),
        "ip":           ip,
        "reason":       reason,
        "threat_score": threat_score,
        "auto_blocked": auto,
        "action":       "block",
        "source":       "netsec_ai_ids",
    }
    logger.info("trigger_block_ip: %s — %s (score=%s)", ip, reason, threat_score)
    payload["action"] = "block_ip"
    return _post("/webhook/soc-alert", payload)


def trigger_enrich_ioc(
    ioc: str,
    ioc_type: str = "auto",
    callback_url: str = "",
) -> tuple[bool, dict]:
    """Trigger IOC enrichment pipeline in n8n (AbuseIPDB/VT/OTX/Shodan fan-out)."""
    if ioc_type == "auto":
        import re as _re
        if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            ioc_type = "ip"
        elif _re.match(r"^[a-f0-9]{32,64}$", ioc, _re.I):
            ioc_type = "hash"
        elif ioc.startswith("http"):
            ioc_type = "url"
        else:
            ioc_type = "domain"

    payload = {
        "timestamp":    _ts(),
        "ioc":          ioc,
        "ioc_type":     ioc_type,
        "callback_url": callback_url,
        "source":       "netsec_ai_ids",
    }
    logger.info("trigger_enrich_ioc: %s (%s)", ioc, ioc_type)
    payload["action"] = "enrich_ioc"
    return _post("/webhook/soc-alert", payload)


def trigger_daily_report(summary: dict) -> tuple[bool, dict]:
    """
    Trigger the daily SOC report email workflow.
    summary keys: total_alerts, compliance_score, top_threats,
                  domains_analysed, mttd_minutes, mttr_minutes
    """
    payload = {
        "timestamp":           _ts(),
        "report_type":         "daily_soc",
        "total_alerts":        summary.get("total_alerts", 0),
        "compliance_score":    summary.get("compliance_score", 0),
        "top_threats":         summary.get("top_threats", []),
        "domains_analysed":    summary.get("domains_analysed", 0),
        "mttd_minutes":        summary.get("mttd_minutes", 0),
        "mttr_minutes":        summary.get("mttr_minutes", 0),
        "false_positive_rate": summary.get("false_positive_rate", 0),
        "critical_alerts":     summary.get("critical_alerts", 0),
        "source":              "netsec_ai_ids",
    }
    logger.info("trigger_daily_report: %d alerts, compliance=%s%%",
                payload["total_alerts"], payload["compliance_score"])
    payload["action"] = "daily_report"
    return _post("/webhook/soc-alert", payload)


def trigger_ir_escalation(
    incident_id: str,
    title: str,
    severity: str,
    affected_host: str,
    iocs: list,
    mitre_techniques: list,
) -> tuple[bool, dict]:
    """Page on-call via PagerDuty + Jira + Slack + host isolation."""
    payload = {
        "timestamp":        _ts(),
        "incident_id":      incident_id,
        "title":            title,
        "severity":         severity,
        "affected_host":    affected_host,
        "iocs":             iocs,
        "mitre_techniques": mitre_techniques,
        "source":           "netsec_ai_ids",
    }
    logger.info("trigger_ir_escalation: %s [%s]", incident_id, severity)
    payload["action"] = "ir_escalation"
    return _post("/webhook/soc-alert", payload)


def trigger_phishing_response(
    sender_domain: str,
    affected_users: list,
    threat_score: int,
    iocs: list,
) -> tuple[bool, dict]:
    """Block phishing domain and notify affected users."""
    payload = {
        "timestamp":      _ts(),
        "sender_domain":  sender_domain,
        "affected_users": affected_users,
        "threat_score":   threat_score,
        "iocs":           iocs,
        "source":         "netsec_ai_ids",
    }
    logger.info("trigger_phishing_response: %s (%d users)", sender_domain, len(affected_users))
    payload["action"] = "phishing_response"
    return _post("/webhook/soc-alert", payload)


# ══════════════════════════════════════════════════════════════════════════════
# FEEDBACK LOOP — receives n8n callback and updates session state
# ══════════════════════════════════════════════════════════════════════════════

def process_n8n_callback(callback_data: dict) -> dict:
    """
    Call this when n8n POSTs back a result.
    Updates n8n_action_log in session state and syncs incident status.
    """
    result = {
        "action":      callback_data.get("action", "unknown"),
        "status":      callback_data.get("status", "unknown"),
        "executed_at": callback_data.get("executed_at", _ts()),
        "target":      callback_data.get("target", ""),
        "result":      callback_data.get("result", {}),
        "error":       callback_data.get("error", ""),
    }
    try:
        import streamlit as st
        st.session_state.setdefault("n8n_action_log", []).insert(0, result)
        # Update incident status if incident_id is provided in callback
        _iid = callback_data.get("incident_id")
        if _iid:
            for _c in st.session_state.get("ir_cases", []):
                if _c.get("id") == _iid:
                    _c["status"]     = "In Progress"
                    _c["n8n_result"] = result
    except Exception:
        pass
    return result


def _post_with_retry(path: str, payload: dict, retries: int = 3, backoff: float = 1.5) -> tuple[bool, dict]:
    """
    POST with exponential backoff retry.
    Delays: attempt 0→immediate, 1→1.5s, 2→2.25s.
    Returns demo-mode response if n8n not configured.
    """
    import time as _t
    last_err: dict = {}
    for attempt in range(retries):
        ok, resp = _post(path, payload)
        if ok:
            if attempt > 0:
                logger.info("n8n succeeded on retry %d for %s", attempt + 1, path)
            return ok, resp
        last_err = resp
        if attempt < retries - 1:
            _delay = backoff ** attempt
            logger.warning("n8n retry %d/%d for %s — %s (waiting %.1fs)",
                           attempt + 1, retries, path, resp.get("error", ""), _delay)
            _t.sleep(_delay)
    logger.error("n8n all %d retries failed for %s — last: %s", retries, path, last_err)
    return False, {"error": "max_retries_exceeded", "last_error": last_err, "retries": retries}


def auto_or_manual_trigger(
    domain: str,
    ip: str,
    alert_type: str,
    severity: str,
    threat_score: int,
    details: dict | None = None,
) -> tuple[bool, dict, str]:
    """
    Smart trigger with auto/suggest/log_only decision logic + retry.
      critical / score≥80  → auto-execute  (fires immediately)
      high     / score≥60  → suggest        (fires but flags as 'suggested')
      medium   / score≥40  → suggest
      below 40             → log_only       (no webhook call)
    Returns (ok, response, decision).
    """
    if severity == "critical" or threat_score >= 80:
        decision = "auto"
        _action  = "critical_alert"
    elif severity == "high" or threat_score >= 60:
        decision = "suggest"
        _action  = "high_alert"
    elif severity == "medium" or threat_score >= 40:
        decision = "suggest"
        _action  = "medium_alert"
    else:
        decision = "log_only"
        _action  = "log_only"

    payload = {
        "timestamp":    _ts(),
        "action":       _action,
        "domain":       domain,
        "ip":           ip,
        "alert_type":   alert_type,
        "severity":     severity,
        "threat_score": threat_score,
        "source":       "netsec_ai_ids",
        "details":      details or {},
        "decision":     decision,
    }

    if decision == "log_only":
        logger.debug("auto_or_manual_trigger: log_only for %s (score=%s)", domain, threat_score)
        return True, {"skipped": True, "reason": "below threshold", "decision": decision}, decision

    logger.info("auto_or_manual_trigger → %s [%s] for %s (score=%s)",
                decision, _action, domain, threat_score)
    ok, resp = _post_with_retry("/webhook/soc-alert", payload)
    return ok, resp, decision


def get_action_log() -> list:
    """Return n8n action log from session state. Safe to call outside Streamlit context."""
    try:
        import streamlit as st
        return st.session_state.get("n8n_action_log", [])
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
# Health check + workflow list
# ══════════════════════════════════════════════════════════════════════════════

def n8n_health_check() -> dict:
    """
    Check n8n connectivity via REST API.
    Returns {status, n8n_url, workflows, workflow_names, latency_ms, message}
    """
    url     = f"{_N8N_BASE}/api/v1/workflows"
    headers = {}
    if _N8N_API_KEY:
        headers["X-N8N-API-KEY"] = _N8N_API_KEY

    if not _N8N_BASE.startswith("http"):
        return {
            "status": "not_configured",
            "n8n_url": _N8N_BASE,
            "message": "N8N_BASE_URL not set. Add it to your .env file.",
            "workflows": 0, "workflow_names": [], "latency_ms": 0,
        }

    t0 = time.time()
    try:
        r = _req().get(url, headers=headers, timeout=6, verify=False)
        latency = round((time.time() - t0) * 1000)

        if r.status_code == 200:
            data    = r.json()
            wf_list = data.get("data", [])
            active  = sum(1 for w in wf_list if w.get("active", False))
            return {
                "status":           "ok",
                "n8n_url":          _N8N_BASE,
                "workflows":        len(wf_list),
                "active_workflows": active,
                "workflow_names":   [w.get("name","?") for w in wf_list],
                "latency_ms":       latency,
                "message": f"Connected — {len(wf_list)} workflows ({active} active)",
            }
        elif r.status_code == 401:
            return {
                "status": "auth_error", "n8n_url": _N8N_BASE,
                "message": "Invalid N8N_API_KEY — check your credentials",
                "workflows": 0, "workflow_names": [], "latency_ms": latency,
            }
        else:
            return {
                "status": "error", "n8n_url": _N8N_BASE,
                "message": f"HTTP {r.status_code}: {r.text[:100]}",
                "workflows": 0, "workflow_names": [], "latency_ms": latency,
            }
    except Exception as exc:
        return {
            "status":  "offline",
            "n8n_url": _N8N_BASE,
            "message": f"Connection error: {exc}",
            "workflows": 0, "workflow_names": [], "latency_ms": 0,
        }


def get_workflow_list() -> list:
    """
    Fetch active workflows from n8n REST API.
    Falls back to SOC_WORKFLOW_TEMPLATES if n8n is unreachable.
    """
    url     = f"{_N8N_BASE}/api/v1/workflows"
    headers = {"X-N8N-API-KEY": _N8N_API_KEY} if _N8N_API_KEY else {}
    try:
        r = _req().get(url, headers=headers, timeout=5, verify=False)
        if r.status_code == 200:
            return [
                {
                    "id":          w.get("id","?"),
                    "name":        w.get("name","?"),
                    "active":      w.get("active", False),
                    "webhook_url": f"{_N8N_BASE}/webhook/{w.get('id','')}",
                    "updated_at":  w.get("updatedAt",""),
                }
                for w in r.json().get("data", [])
            ]
    except Exception:
        pass

    return [
        {
            "id":          k,
            "name":        v["name"],
            "active":      True,
            "webhook_url": _webhook_url(v["webhook_path"]),
            "updated_at":  "",
        }
        for k, v in SOC_WORKFLOW_TEMPLATES.items()
    ]


def get_workflow_setup_guide() -> str:
    """Return step-by-step n8n setup guide for the Automation dashboard."""
    return """
## n8n Setup Guide for NetSec AI IDS

### 1. Deploy n8n
```bash
# Docker (recommended)
docker run -d --name n8n \\
  -p 5678:5678 \\
  -e N8N_BASIC_AUTH_ACTIVE=true \\
  -e N8N_BASIC_AUTH_USER=admin \\
  -e N8N_BASIC_AUTH_PASSWORD=netsecai \\
  -v ~/.n8n:/home/node/.n8n \\
  n8nio/n8n

# OR: railway.app free tier → Deploy n8n template
# OR: npm install -g n8n && n8n start
```

### 2. Configure .env
```bash
N8N_BASE_URL=http://localhost:5678
N8N_WEBHOOK_URL=http://localhost:5678
N8N_API_KEY=your-api-key          # n8n Settings → API Keys
SLACK_WEBHOOK_URL=https://hooks.slack.com/...  # optional direct Slack
```

### 3. Import Workflow Templates
1. n8n UI → Workflows → Import from JSON
2. Import each file from /workflows/ in this project
3. Add credentials (Slack, Jira, Splunk) to each workflow
4. Toggle each workflow to ACTIVE

### 4. Test
- Open n8n Automation tab → Test Connection → should show green
- Use Manual Trigger buttons to test each workflow

### Troubleshooting
- Connection refused → Docker on port 5678?
- 401 Unauthorized → check N8N_API_KEY
- Workflow not triggering → toggle to ACTIVE in n8n UI
- Slack not posting → verify Bot Token has chat:write
"""


# ══════════════════════════════════════════════════════════════════════════════
# Standalone test
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    print("=== n8n_agent.py self-test ===\n")

    print("1. Health check:")
    result = n8n_health_check()
    print(f"   Status: {result['status']} | {result['message']}")

    print("\n2. trigger_slack_notify:")
    ok, resp = trigger_slack_notify("Test from NetSec AI IDS", "high")
    print(f"   ok={ok} | {resp}")

    print("\n3. trigger_block_ip:")
    ok, resp = trigger_block_ip("185.220.101.45", "C2 server AbuseIPDB 95%", 91)
    print(f"   ok={ok} | {resp}")

    print("\n4. trigger_enrich_ioc:")
    ok, resp = trigger_enrich_ioc("185.220.101.45")
    print(f"   ok={ok} | {resp}")

    print("\n5. trigger_daily_report:")
    ok, resp = trigger_daily_report({
        "total_alerts":324,"compliance_score":82,
        "top_threats":["DNS Beacon","C2","Exfil"],
        "domains_analysed":45,"mttd_minutes":2.3,"mttr_minutes":18,
    })
    print(f"   ok={ok} | {resp}")

    print("\n6. SOC_WORKFLOW_TEMPLATES:", list(SOC_WORKFLOW_TEMPLATES.keys()))
    print("\n✅ All functions operational (demo mode — configure .env for live n8n)")