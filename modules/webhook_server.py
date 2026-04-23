"""
webhook_server.py — NetSec AI v12.0
=====================================
Recommended architecture (stable + reliable):

  PULL  → NetSec AI pulls domains/alerts FROM Splunk (Search API port 8089)
  HEC   → NetSec AI pushes verdicts back TO Splunk (HEC port 8088)
  WAZUH → NetSec AI pulls alerts from Wazuh (OpenSearch port 9200)

Webhook push (Splunk → NetSec AI) kept for compatibility but Pull is primary.

Run:
  python webhook_server.py                        # basic
  python webhook_server.py --auto-pull            # auto-pull every 5 min
  python webhook_server.py --auto-pull --interval 300 --wazuh-pull

Endpoints:
  GET  /health           — server status
  GET  /status           — full diagnostics
  GET  /pull             — trigger one Splunk pull now
  GET  /pull/wazuh       — trigger one Wazuh pull now
  GET  /pull/backfill    — pull last 24h (historical backfill)
  GET  /verdicts         — last 200 triage results
  GET  /metrics          — FP rate, verdict breakdown
  GET  /csv              — download the verdict CSV
  GET  /splunk-spl       — recommended SPL queries + dashboard SPL
  POST /webhook/splunk   — Splunk pushes alert here (push mode)
  POST /webhook/batch    — batch domain triage
  POST /feedback         — mark alert as FP or confirmed
"""

import sys, os, json, csv, time, logging, threading, re
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ── Path setup ────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in [_HERE, os.path.join(_HERE, "modules"), os.path.join(_HERE, "ui"),
           os.path.join(_HERE, "ui", "modules")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("netsec.webhook")

# ── Enterprise SOC (optional) ─────────────────────────────────────────────────
try:
    from enterprise_soc import (
        CorrelationEngine, FalsePositiveKiller, ContinuousLearningStore,
    )
    _ENTERPRISE = True
except ImportError:
    _ENTERPRISE = False

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

WEBHOOK_PORT      = int(os.getenv("WEBHOOK_PORT",     "8000"))
SPLUNK_HEC_URL    = os.getenv("SPLUNK_HEC_URL",   "http://127.0.0.1:8088/services/collector/event")
SPLUNK_HEC_TOKEN  = os.getenv("SPLUNK_HEC_TOKEN", "be9a022a-014d-47a8-86df-4a1cde8c17e6")
SPLUNK_SEARCH_URL  = os.getenv("SPLUNK_SEARCH_URL",  "https://127.0.0.1:8089")
SPLUNK_SEARCH_USER = os.getenv("SPLUNK_SEARCH_USER", "devanshjain209@gmail.com")
SPLUNK_SEARCH_PASS = os.getenv("SPLUNK_SEARCH_PASS", "Abc@1234")
WAZUH_URL   = os.getenv("WAZUH_URL",  "https://192.168.1.7:9200")
WAZUH_USER  = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS  = os.getenv("WAZUH_PASS", "")
MIN_COUNT   = int(os.getenv("MIN_COUNT_THRESHOLD", "2"))

CSV_PATH = os.path.join(_HERE, "data", "netsec_verdicts.csv")
FP_PATH  = os.path.join(_HERE, "data", "false_positives.json")
os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)

VERDICT_LOG: list = []
MAX_LOG           = 500
_PULL_CACHE: set  = set()
_FP_SET: set      = set()
_METRICS          = defaultdict(int)
_LOCK             = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# TRIAGE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def run_triage(domain: str) -> dict:
    domain = domain.strip().lower()
    if not domain:
        return {"domain": domain, "verdict": "UNKNOWN", "score": 50, "confidence": 0}

    if domain in _FP_SET:
        return {"domain": domain, "verdict": "FALSE_POSITIVE", "score": 90,
                "risk_score": 90, "confidence": 99, "severity": "informational",
                "action": "suppressed_fp", "should_investigate": False,
                "reason": "Marked as FP by analyst", "signals": [],
                "from_cache": True, "source": "fp_list",
                "timestamp": datetime.utcnow().isoformat() + "Z"}

    try:
        from reputation_engine import get_authoritative_verdict
        result  = get_authoritative_verdict(domain)
        score   = result.get("score", 50)
        verdict = result.get("verdict", "UNKNOWN")
        conf    = max(0, min(100, 100 - result.get("confidence_cap", 75)))
        if score >= 70:   action, severity = "no_action",         "informational"
        elif score >= 40: action, severity = "monitor",           "low"
        elif score >= 20: action, severity = "investigate",       "medium"
        else:             action, severity = "block_recommended", "high"
        return {
            "domain": domain, "verdict": verdict, "score": score,
            "risk_score": score, "confidence": conf, "severity": severity,
            "action": action,
            "should_investigate": result.get("should_investigate", True),
            "reason": result.get("reason", ""),
            "signals": [s[1] for s in result.get("signals", [])[:3]
                        if isinstance(s, (list, tuple)) and len(s) > 1],
            "typosquat_tag": result.get("typosquat_tag", ""),
            "sources_used":  result.get("sources_used", []),
            "from_cache": result.get("from_cache", False),
            "source": "reputation_engine",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except ImportError:
        pass
    except Exception as e:
        log.warning("ReputationEngine failed %s: %s", domain, e)

    try:
        from domain_intel import DomainIntel
        result = DomainIntel.analyse(domain)
        score  = 100 - min(100, result.get("risk_score", 50))
        return {"domain": domain, "verdict": result.get("verdict","UNKNOWN"),
                "score": score, "risk_score": score,
                "confidence": result.get("confidence", 50),
                "severity": result.get("severity","medium"),
                "action": "investigate" if score < 50 else "no_action",
                "should_investigate": not result.get("safe", False),
                "reason": result.get("summary",""), "signals": [],
                "from_cache": False, "source": "domain_intel",
                "timestamp": datetime.utcnow().isoformat() + "Z"}
    except Exception:
        pass

    _SAFE = {"google.com","youtube.com","microsoft.com","apple.com","amazon.com",
             "cloudflare.com","whatsapp.com","facebook.com","instagram.com",
             "swiggy.com","zomato.com","flipkart.com","github.com","airtel.in"}
    _BAD_TLD = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".win",
                ".loan",".stream",".pw",".cc",".su"}
    _BAD_KW  = ["login","secure","verify","account","update","bank",
                "paypal","password","credential","malware","c2","beacon"]
    if any(domain == s or domain.endswith("."+s) for s in _SAFE):
        return {"domain":domain,"verdict":"LIKELY BENIGN","score":85,"risk_score":85,
                "confidence":75,"severity":"informational","action":"no_action",
                "should_investigate":False,"reason":"Known safe (fallback)","signals":[],
                "from_cache":False,"source":"heuristic",
                "timestamp":datetime.utcnow().isoformat()+"Z"}
    bad_tld = any(domain.endswith(t) for t in _BAD_TLD)
    bad_kw  = any(k in domain for k in _BAD_KW)
    score   = 30 if (bad_tld and bad_kw) else 35 if bad_tld else 40 if bad_kw else 55
    return {"domain":domain,"verdict":"SUSPICIOUS" if score<50 else "LOW RISK",
            "score":score,"risk_score":score,"confidence":60,
            "severity":"medium" if score<50 else "low",
            "action":"investigate" if score<50 else "monitor",
            "should_investigate":score<50,
            "reason":f"Heuristic: tld={bad_tld} kw={bad_kw}",
            "signals":["suspicious_tld"] if bad_tld else [],
            "from_cache":False,"source":"heuristic",
            "timestamp":datetime.utcnow().isoformat()+"Z"}


# ══════════════════════════════════════════════════════════════════════════════
# STORAGE
# ══════════════════════════════════════════════════════════════════════════════

def save_verdict_csv(verdict: dict) -> None:
    try:
        fields = ["domain","verdict","score","confidence","severity",
                  "action","reason","timestamp","source","typosquat_tag","sources_used"]
        write_header = not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0
        with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            if write_header:
                w.writeheader()
            row = dict(verdict)
            if isinstance(row.get("sources_used"), list):
                row["sources_used"] = ",".join(row["sources_used"])
            w.writerow(row)
    except Exception as e:
        log.warning("CSV write failed: %s", e)


def _load_fp_list() -> None:
    global _FP_SET
    try:
        if os.path.exists(FP_PATH):
            with open(FP_PATH) as f:
                _FP_SET = set(json.load(f))
    except Exception:
        pass


def _save_fp_list() -> None:
    try:
        with open(FP_PATH, "w") as f:
            json.dump(list(_FP_SET), f)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# HEC — push verdicts TO Splunk
# ══════════════════════════════════════════════════════════════════════════════

def send_verdict_to_splunk_hec(verdict: dict) -> tuple:
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return False, "HEC not configured"
    try:
        import urllib.request as _ur, ssl as _ssl
        sources_str = ",".join(verdict.get("sources_used", [])) \
                      if isinstance(verdict.get("sources_used"), list) \
                      else str(verdict.get("sources_used",""))
        payload = json.dumps({
            "event": {
                **{k: v for k, v in verdict.items()
                   if k not in ("signals","sources_used")},
                "netsec_ai_verdict":    verdict.get("verdict",""),
                "netsec_ai_score":      verdict.get("score", 0),
                "netsec_ai_action":     verdict.get("action",""),
                "netsec_ai_confidence": verdict.get("confidence", 0),
                "netsec_ai_severity":   verdict.get("severity",""),
                "netsec_ai_reason":     str(verdict.get("reason",""))[:200],
                "netsec_ai_sources":    sources_str,
                "netsec_ai_typosquat":  verdict.get("typosquat_tag",""),
            },
            "sourcetype": "netsec_ai",
            "index": "main",
            "source": "netsec_ai_v12",
            "time": time.time(),
        }).encode()
        url = SPLUNK_HEC_URL.rstrip("/")
        if not url.endswith("/event"):
            url += "/event"
        req = _ur.Request(url, data=payload,
                          headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
                                   "Content-Type": "application/json"},
                          method="POST")
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        with _ur.urlopen(req, timeout=6, context=ctx) as r:
            body = json.loads(r.read().decode())
        if body.get("code") == 0 or body.get("text") == "Success":
            return True, "✅ Written to Splunk"
        return False, f"HEC: {body}"
    except Exception as e:
        return False, f"HEC error: {str(e)[:80]}"


# ══════════════════════════════════════════════════════════════════════════════
# SPL QUERIES — one per log source
# ══════════════════════════════════════════════════════════════════════════════

_SPL_QUERIES = {
    "any": (
        'index=* '
        '| rex field=_raw "(?i)(?:https?://)?(?:www\\.)?'
        '(?P<domain>[a-z0-9\\-]+(?:\\.[a-z0-9\\-]+)+)" '
        f'| stats count by domain | where count >= {MIN_COUNT} '
        '| sort -count | head 50'
    ),
    "dns": (
        'index=dns OR sourcetype=dns '
        '| stats count by query | rename query AS domain '
        f'| where count >= {MIN_COUNT} | sort -count | head 50'
    ),
    "firewall": (
        'index=firewall OR sourcetype=firewall '
        '| rex field=_raw "(?P<domain>[a-z0-9\\-]+\\.(?:com|net|org|io|tk|xyz|in|co))" '
        f'| stats count by domain | where count >= {MIN_COUNT} | sort -count | head 50'
    ),
    "proxy": (
        'index=proxy OR sourcetype=access_combined '
        '| rex field=_raw "(?P<domain>[a-z0-9\\-]+\\.(?:com|net|org|io|tk|xyz|in|co))" '
        f'| stats count by domain | where count >= {MIN_COUNT} | sort -count | head 50'
    ),
    "windows": (
        'index=wineventlog OR sourcetype=WinEventLog '
        '| rex field=_raw "(?P<domain>[a-z0-9\\-]+\\.(?:com|net|org|io|tk|xyz|in|co))" '
        f'| stats count by domain | where count >= {MIN_COUNT} | sort -count | head 50'
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# PULL — fetch domains FROM Splunk Search API (port 8089)
# ══════════════════════════════════════════════════════════════════════════════

def pull_from_splunk(source: str = "any", hours_back: int = 1,
                     max_results: int = 50) -> list:
    if not SPLUNK_SEARCH_PASS:
        log.warning("SPLUNK_SEARCH_PASS not set — cannot pull from Splunk")
        return []
    import urllib.request as _ur, urllib.parse as _up, base64 as _b64, ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    creds = _b64.b64encode(f"{SPLUNK_SEARCH_USER}:{SPLUNK_SEARCH_PASS}".encode()).decode()
    spl = _SPL_QUERIES.get(source, _SPL_QUERIES["any"])
    spl_timed = f'search earliest=-{hours_back}h latest=now {spl}'
    try:
        payload = _up.urlencode({
            "search": spl_timed, "output_mode": "json",
            "exec_mode": "blocking", "count": max_results,
        }).encode()
        req = _ur.Request(
            f"{SPLUNK_SEARCH_URL}/services/search/jobs",
            data=payload,
            headers={"Authorization": f"Basic {creds}",
                     "Content-Type": "application/x-www-form-urlencoded"},
            method="POST"
        )
        with _ur.urlopen(req, timeout=30, context=ctx) as r:
            job = json.loads(r.read())
        sid = job.get("sid")
        if not sid:
            return []
        res_req = _ur.Request(
            f"{SPLUNK_SEARCH_URL}/services/search/jobs/{sid}/results"
            f"?output_mode=json&count={max_results}",
            headers={"Authorization": f"Basic {creds}"}
        )
        with _ur.urlopen(res_req, timeout=15, context=ctx) as r:
            data = json.loads(r.read())
        rows = data.get("results", [])
        log.info("Splunk pull (%s, -%dh): %d rows", source, hours_back, len(rows))
        return rows
    except Exception as e:
        log.warning("Splunk pull failed: %s", e)
        return []


def pull_and_triage(source: str = "any", hours_back: int = 1,
                    max_results: int = 50, skip_cache: bool = False) -> list:
    rows = pull_from_splunk(source=source, hours_back=hours_back, max_results=max_results)
    processed = []
    for row in rows:
        domain = str(row.get("domain", row.get("query",""))).strip().lower()
        count  = int(row.get("count","1") or 1)
        if not domain or len(domain) < 4:
            continue
        if not skip_cache and domain in _PULL_CACHE:
            continue
        with _LOCK:
            _PULL_CACHE.add(domain)
            if len(_PULL_CACHE) > 10000:
                _PULL_CACHE.clear()
        verdict = run_triage(domain)
        verdict["pull_source"]  = f"splunk_{source}"
        verdict["splunk_count"] = count
        save_verdict_csv(verdict)
        hec_ok, hec_msg = send_verdict_to_splunk_hec(verdict)
        verdict["hec_status"] = hec_msg
        with _LOCK:
            VERDICT_LOG.append(verdict)
            if len(VERDICT_LOG) > MAX_LOG:
                del VERDICT_LOG[:len(VERDICT_LOG)-MAX_LOG]
            _METRICS["total"] += 1
            _METRICS[verdict["verdict"].lower().replace(" ","_")] += 1
        log.info("PULL %s → %s (score:%d) HEC:%s",
                 domain, verdict["verdict"], verdict["score"], hec_msg[:25])
        processed.append(verdict)
    return processed


# ══════════════════════════════════════════════════════════════════════════════
# WAZUH PULL — fetch alerts from Wazuh OpenSearch (port 9200)
# ══════════════════════════════════════════════════════════════════════════════

def pull_from_wazuh(hours_back: int = 1, min_level: int = 5,
                    max_results: int = 30) -> list:
    if not WAZUH_PASS:
        log.warning("WAZUH_PASS not set — skipping Wazuh pull")
        return []
    import urllib.request as _ur, base64 as _b64, ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    creds = _b64.b64encode(f"{WAZUH_USER}:{WAZUH_PASS}".encode()).decode()
    cutoff = (datetime.utcnow() - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = json.dumps({
        "size": max_results,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": cutoff}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
        "_source": ["@timestamp","rule.level","rule.description","rule.groups",
                    "agent.name","agent.ip","data.srcip","data.dstip",
                    "data.hostname","data.url","full_log"]
    }).encode()
    try:
        req = _ur.Request(
            f"{WAZUH_URL.rstrip('/')}/wazuh-alerts-*/_search",
            data=query,
            headers={"Authorization": f"Basic {creds}", "Content-Type": "application/json"},
            method="POST"
        )
        with _ur.urlopen(req, timeout=10, context=ctx) as r:
            data = json.loads(r.read())
        hits = data.get("hits",{}).get("hits",[])
        alerts = []
        for hit in hits:
            src   = hit.get("_source",{})
            rule  = src.get("rule",{})
            agent = src.get("agent",{})
            d     = src.get("data",{})
            ioc = (d.get("hostname","") or d.get("url","") or
                   d.get("srcip","") or d.get("dstip","") or "")
            if not ioc:
                raw = src.get("full_log","")
                m   = re.search(r'\b([a-z0-9\-]+\.(?:com|net|org|io|tk|xyz|in|co))\b',
                                raw, re.IGNORECASE)
                if m:
                    ioc = m.group(1)
            if ioc:
                alerts.append({
                    "domain":      ioc,
                    "agent_name":  agent.get("name","?"),
                    "agent_ip":    agent.get("ip","?"),
                    "rule_level":  rule.get("level",0),
                    "rule_id":     rule.get("id",""),
                    "description": rule.get("description",""),
                    "timestamp":   src.get("@timestamp",""),
                })
        log.info("Wazuh pull: %d IOCs from %d alerts", len(alerts), len(hits))
        return alerts
    except Exception as e:
        log.warning("Wazuh pull failed: %s", e)
        return []


def wazuh_pull_and_triage(hours_back: int = 1, min_level: int = 5) -> list:
    alerts = pull_from_wazuh(hours_back=hours_back, min_level=min_level)
    processed = []
    for alert in alerts:
        ioc = alert["domain"].strip().lower()
        if not ioc or ioc in _PULL_CACHE:
            continue
        with _LOCK:
            _PULL_CACHE.add(ioc)
        verdict = run_triage(ioc)
        verdict.update({
            "wazuh_agent":   alert.get("agent_name",""),
            "wazuh_agent_ip":alert.get("agent_ip",""),
            "wazuh_rule_id": alert.get("rule_id",""),
            "wazuh_level":   alert.get("rule_level",0),
            "wazuh_desc":    alert.get("description",""),
            "pull_source":   "wazuh",
        })
        save_verdict_csv(verdict)
        hec_ok, hec_msg = send_verdict_to_splunk_hec(verdict)
        verdict["hec_status"] = hec_msg
        with _LOCK:
            VERDICT_LOG.append(verdict)
            _METRICS["total"] += 1
            _METRICS[verdict["verdict"].lower().replace(" ","_")] += 1
        log.info("WAZUH %s → %s (score:%d, agent:%s)",
                 ioc, verdict["verdict"], verdict["score"], alert.get("agent_name","?"))
        processed.append(verdict)
    return processed


# ══════════════════════════════════════════════════════════════════════════════
# AUTO-PULL BACKGROUND THREAD
# ══════════════════════════════════════════════════════════════════════════════

def _auto_pull_loop(interval: int = 300, wazuh: bool = False):
    log.info("[AUTO-PULL] Started — every %ds wazuh=%s", interval, wazuh)
    while True:
        try:
            r = pull_and_triage(source="any", hours_back=1)
            if r:
                log.info("[AUTO-PULL] Splunk: %d processed", len(r))
        except Exception as e:
            log.warning("[AUTO-PULL] Splunk error: %s", e)
        if wazuh:
            try:
                r2 = wazuh_pull_and_triage(hours_back=1, min_level=5)
                if r2:
                    log.info("[AUTO-PULL] Wazuh: %d processed", len(r2))
            except Exception as e:
                log.warning("[AUTO-PULL] Wazuh error: %s", e)
        time.sleep(interval)


# ══════════════════════════════════════════════════════════════════════════════
# HTTP HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class WebhookHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        path   = urlparse(self.path).path
        params = parse_qs(urlparse(self.path).query)

        if path == "/health":
            self._send_json(200, {
                "status": "ok", "service": "NetSec AI Webhook v12",
                "port":   WEBHOOK_PORT, "verdicts_logged": len(VERDICT_LOG),
                "hec_configured":   bool(SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN),
                "pull_configured":  bool(SPLUNK_SEARCH_PASS),
                "wazuh_configured": bool(WAZUH_PASS),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })

        elif path == "/status":
            self._send_json(200, {
                "webhook_server":    "running",
                "port":              WEBHOOK_PORT,
                "hec_url":           SPLUNK_HEC_URL,
                "hec_configured":    bool(SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN),
                "pull_configured":   bool(SPLUNK_SEARCH_PASS),
                "wazuh_configured":  bool(WAZUH_PASS),
                "min_count_filter":  MIN_COUNT,
                "verdicts_in_memory":len(VERDICT_LOG),
                "fp_domains":        len(_FP_SET),
                "metrics":           dict(_METRICS),
                "csv_exists":        os.path.exists(CSV_PATH),
                "csv_size_bytes":    os.path.getsize(CSV_PATH) if os.path.exists(CSV_PATH) else 0,
                "enterprise_soc":    _ENTERPRISE,
                "endpoints": [
                    "GET /health  GET /status  GET /pull  GET /pull/wazuh",
                    "GET /pull/backfill  GET /verdicts  GET /metrics",
                    "GET /csv  GET /splunk-spl  GET /test-domains",
                    "POST /webhook/splunk  POST /webhook/batch  POST /feedback",
                ],
                "tip": (
                    "Primary = GET /pull (needs SPLUNK_SEARCH_PASS). "
                    "If webhook fails use machine IP not 127.0.0.1 in Splunk."
                ),
            })

        elif path == "/pull":
            source     = params.get("source",["any"])[0]
            hours_back = int(params.get("hours",["1"])[0])
            results    = pull_and_triage(source=source, hours_back=hours_back)
            self._send_json(200, {
                "status":    "ok", "processed": len(results),
                "source":    source, "hours_back": hours_back,
                "verdicts": [{"domain": v["domain"], "verdict": v["verdict"],
                              "score": v["score"], "action": v["action"],
                              "hec": v.get("hec_status","")} for v in results],
                "message": (f"Pulled and triaged {len(results)} domains from Splunk"
                            if results else
                            "No new domains — check SPLUNK_SEARCH_PASS or try ?source=dns"),
            })

        elif path == "/pull/wazuh":
            hours_back = int(params.get("hours",["1"])[0])
            min_level  = int(params.get("level",["5"])[0])
            results    = wazuh_pull_and_triage(hours_back=hours_back, min_level=min_level)
            self._send_json(200, {
                "status": "ok", "processed": len(results),
                "verdicts": [{"domain": v["domain"], "verdict": v["verdict"],
                              "score": v["score"],
                              "agent": v.get("wazuh_agent","")} for v in results],
                "message": (f"Wazuh: {len(results)} IOCs triaged" if results
                            else "No alerts from Wazuh — check WAZUH_PASS"),
            })

        elif path == "/pull/backfill":
            hours    = int(params.get("hours",["24"])[0])
            log.info("[BACKFILL] Pulling last %dh...", hours)
            rows     = pull_from_splunk(source="any", hours_back=hours, max_results=200)
            processed = []
            for row in rows:
                domain = str(row.get("domain","")).strip().lower()
                if not domain:
                    continue
                verdict = run_triage(domain)
                verdict["pull_source"]  = "backfill"
                verdict["splunk_count"] = row.get("count","1")
                save_verdict_csv(verdict)
                send_verdict_to_splunk_hec(verdict)
                with _LOCK:
                    VERDICT_LOG.append(verdict)
                    _METRICS["total"] += 1
                processed.append(verdict)
            self._send_json(200, {
                "status": "ok", "hours_back": hours, "processed": len(processed),
                "breakdown": {
                    "malicious":  sum(1 for v in processed if "MALICIOUS"  in v["verdict"].upper()),
                    "suspicious": sum(1 for v in processed if "SUSPICIOUS" in v["verdict"].upper()),
                    "benign":     sum(1 for v in processed if v["score"] >= 70),
                },
            })

        elif path == "/verdicts":
            n = int(params.get("n",["50"])[0])
            with _LOCK:
                verdicts = list(reversed(VERDICT_LOG[-n:]))
            self._send_json(200, {"count": len(verdicts), "verdicts": verdicts})

        elif path == "/metrics":
            with _LOCK:
                m = dict(_METRICS)
            total = max(m.get("total",1), 1)
            self._send_json(200, {
                "total_triaged":   m.get("total",0),
                "malicious":       m.get("malicious",0),
                "suspicious":      m.get("suspicious",0),
                "false_positives": m.get("false_positive",0),
                "fp_rate_pct":     round(m.get("false_positive",0)/total*100, 1),
                "fp_domains":      list(_FP_SET)[:20],
                "confirmed":       m.get("confirmed",0),
            })

        elif path == "/csv":
            if os.path.exists(CSV_PATH):
                with open(CSV_PATH, encoding="utf-8") as f:
                    body = f.read().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition",
                                 "attachment; filename=netsec_verdicts.csv")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._send_json(404, {"error": "CSV not found — run a pull first"})

        elif path == "/splunk-spl":
            self._send_json(200, {
                "description": "Paste these SPL queries into Splunk Search",
                "pull_queries": _SPL_QUERIES,
                "dashboard_spl": {
                    "verdicts_by_type": (
                        'index=main sourcetype=netsec_ai '
                        '| stats count by netsec_ai_verdict | sort -count'
                    ),
                    "top_risky_domains": (
                        'index=main sourcetype=netsec_ai '
                        '| where netsec_ai_score < 40 '
                        '| table domain netsec_ai_verdict netsec_ai_score '
                        '  netsec_ai_action netsec_ai_sources '
                        '| sort netsec_ai_score | head 20'
                    ),
                    "trend_over_time": (
                        'index=main sourcetype=netsec_ai '
                        '| timechart count by netsec_ai_verdict'
                    ),
                    "top_risky_agents": (
                        'index=main sourcetype=netsec_ai wazuh_agent!="" '
                        '| where netsec_ai_score < 40 '
                        '| stats count by wazuh_agent | sort -count | head 10'
                    ),
                    "alert_suppression": (
                        'index=main sourcetype=netsec_ai '
                        '| where netsec_ai_verdict="LIKELY BENIGN" '
                        '| eval auto_close="yes" '
                        '| table domain netsec_ai_verdict netsec_ai_score auto_close'
                    ),
                    "audit_trail_dpdp": (
                        'index=main sourcetype=netsec_ai '
                        '| table _time domain netsec_ai_verdict netsec_ai_action '
                        '  netsec_ai_reason netsec_ai_sources '
                        '| sort -_time'
                    ),
                },
                "lookup_spl": (
                    "| inputlookup netsec_verdicts.csv "
                    "| table domain verdict score severity action"
                ),
                "copy_csv_cmd": (
                    "copy netsec_verdicts.csv "
                    "%SPLUNK_HOME%\\etc\\apps\\search\\lookups\\netsec_verdicts.csv"
                ),
            })

        elif path == "/test-domains":
            test_domains = ["google.com","malware-c2.tk","amaz0n.co",
                            "login-paytm-secure.in","espncricinfo.com"]
            results = [run_triage(d) for d in test_domains]
            self._send_json(200, {"test_results": [
                {"domain":v["domain"],"verdict":v["verdict"],
                 "score":v["score"],"action":v["action"]} for v in results
            ]})

        else:
            self._send_json(404, {"error": "Not found", "see": "/status"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length) if length else b"{}"
            data   = json.loads(body.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON: {e}"}); return

        # ── POST /webhook/splunk ──────────────────────────────────────────────
        if path in ("/webhook/splunk", "/api/triage/splunk", "/webhook/soc-alert"):
            domain = (data.get("domain") or data.get("ioc") or "").strip()
            if not domain:
                self._send_json(400, {
                    "error": "No domain in payload",
                    "received": list(data.keys()),
                    "tip": "Use GET /pull instead — more reliable than webhook push",
                }); return

            log.info("PUSH: %s (from %s)", domain, data.get("search_name","?"))
            verdict = run_triage(domain)

            if _ENTERPRISE:
                try:
                    synth = {"_raw": domain,
                             "data": {"srcip": domain,
                                      "dns_queries": int(data.get("count",0))},
                             "agent": {}}
                    corr = CorrelationEngine.correlate(synth)
                    verdict.update({
                        "correlation":     corr.get("verdict","UNKNOWN"),
                        "corr_confidence": corr.get("confidence",0),
                        "mitre_tags":      corr.get("mitre_tags",[]),
                    })
                    is_fp, fp_reason = FalsePositiveKiller.is_false_positive(
                        domain, int(data.get("count",1)), verdict.get("score",50))
                    if is_fp:
                        verdict["action"] = "suppressed_fp"
                        verdict["should_investigate"] = False
                except Exception:
                    pass

            verdict.update({
                "splunk_search_name":  data.get("search_name",""),
                "splunk_count":        data.get("count",""),
                "splunk_trigger_time": data.get("trigger_time",""),
            })
            save_verdict_csv(verdict)
            hec_ok, hec_msg = send_verdict_to_splunk_hec(verdict)
            verdict["hec_status"] = hec_msg
            with _LOCK:
                VERDICT_LOG.append(verdict)
                if len(VERDICT_LOG) > MAX_LOG:
                    del VERDICT_LOG[:len(VERDICT_LOG)-MAX_LOG]
                _METRICS["total"] += 1

            _ico = {"informational":"✅","low":"🔵","medium":"🟡","high":"🔴"}.get(
                verdict.get("severity",""),"⚪")
            log.info("%s %-35s %-25s score:%3d %s",
                     _ico, domain, verdict["verdict"], verdict["score"], hec_msg[:30])
            self._send_json(200, {
                "status": "processed", "domain": domain,
                "verdict": verdict["verdict"], "score": verdict["score"],
                "severity": verdict["severity"], "action": verdict["action"],
                "hec": hec_msg,
            })

        # ── POST /webhook/batch ───────────────────────────────────────────────
        elif path == "/webhook/batch":
            domains = data.get("domains",[])
            if not domains:
                self._send_json(400, {"error": "No domains list"}); return
            results = []
            for d in domains[:100]:
                v = run_triage(d)
                save_verdict_csv(v)
                send_verdict_to_splunk_hec(v)
                with _LOCK:
                    VERDICT_LOG.append(v)
                results.append(v)
            self._send_json(200, {
                "processed": len(results),
                "results": [{"domain":v["domain"],"verdict":v["verdict"],
                             "score":v["score"],"action":v["action"]} for v in results],
            })

        # ── POST /feedback ────────────────────────────────────────────────────
        elif path == "/feedback":
            domain   = data.get("domain","").strip().lower()
            feedback = data.get("feedback","").lower()
            analyst  = data.get("analyst","analyst")
            if not domain:
                self._send_json(400, {"error": "domain required"}); return
            if feedback == "fp":
                with _LOCK:
                    _FP_SET.add(domain)
                    _METRICS["false_positive"] += 1
                _save_fp_list()
                if _ENTERPRISE:
                    try:
                        ContinuousLearningStore.record_feedback(
                            domain, "UNKNOWN", "fp", analyst, "webhook feedback")
                    except Exception:
                        pass
                log.info("FP marked: %s by %s", domain, analyst)
                self._send_json(200, {"status":"fp_marked","domain":domain,
                                      "total_fps":len(_FP_SET)})
            elif feedback == "confirmed":
                with _LOCK:
                    _METRICS["confirmed"] += 1
                if _ENTERPRISE:
                    try:
                        ContinuousLearningStore.record_feedback(
                            domain, "UNKNOWN", "confirmed", analyst, "")
                    except Exception:
                        pass
                log.info("CONFIRMED: %s by %s", domain, analyst)
                self._send_json(200, {"status":"confirmed","domain":domain})
            else:
                self._send_json(400, {"error":"feedback must be 'fp' or 'confirmed'"})

        else:
            self._send_json(404, {"error":"Unknown endpoint","see":"/status"})


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║       NetSec AI — Webhook + Pull Server  v12.0                  ║
╠══════════════════════════════════════════════════════════════════╣
║  PRIMARY — Pull from Splunk (reliable, no push config needed):  ║
║    GET /pull                  — pull any index, last 1h         ║
║    GET /pull?source=dns       — DNS logs only                   ║
║    GET /pull?source=firewall  — firewall logs                   ║
║    GET /pull?source=windows   — Windows event logs              ║
║    GET /pull/wazuh            — Wazuh alerts                    ║
║    GET /pull/backfill?hours=24— last 24h historical             ║
╠══════════════════════════════════════════════════════════════════╣
║  HEC push (verdicts → Splunk): {hec}
║  Splunk pull:                  {pull}
║  Wazuh pull:                   {wazuh}
║  Smart filter:                 min_count >= {min_count}
╠══════════════════════════════════════════════════════════════════╣
║  SECONDARY — Webhook push (Splunk → NetSec AI):                 ║
║    POST http://YOUR_MACHINE_IP:{port}/webhook/splunk             ║
║    (use machine IP, not 127.0.0.1, in Splunk alert config)     ║
╠══════════════════════════════════════════════════════════════════╣
║  SPL queries: http://127.0.0.1:{port}/splunk-spl                ║
║  Dashboard:   copy from /splunk-spl → paste in Splunk           ║
║  Metrics:     http://127.0.0.1:{port}/metrics                   ║
║  CSV:         http://127.0.0.1:{port}/csv                       ║
║  Status:      http://127.0.0.1:{port}/status                    ║
╚══════════════════════════════════════════════════════════════════╝
"""


def run_server(auto_pull: bool = False, pull_interval: int = 300,
               wazuh_pull: bool = False):
    _load_fp_list()
    server = HTTPServer(("0.0.0.0", WEBHOOK_PORT), WebhookHandler)
    print(BANNER.format(
        port      = WEBHOOK_PORT,
        hec       = "✅ Ready" if (SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN) else "⚠️  Set SPLUNK_HEC_TOKEN",
        pull      = "✅ Ready" if SPLUNK_SEARCH_PASS else "⚠️  Set SPLUNK_SEARCH_PASS",
        wazuh     = "✅ Ready" if WAZUH_PASS         else "⚠️  Set WAZUH_PASS",
        min_count = MIN_COUNT,
    ))
    log.info("Server port=%d auto_pull=%s interval=%ds wazuh=%s",
             WEBHOOK_PORT, auto_pull, pull_interval, wazuh_pull)
    if auto_pull:
        t = threading.Thread(target=_auto_pull_loop,
                             args=(pull_interval, wazuh_pull), daemon=True)
        t.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Server stopped.")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="NetSec AI Webhook + Pull Server v12")
    p.add_argument("--port",        type=int,  default=WEBHOOK_PORT)
    p.add_argument("--auto-pull",   action="store_true", help="Auto-pull from Splunk every N sec")
    p.add_argument("--wazuh-pull",  action="store_true", help="Also pull from Wazuh")
    p.add_argument("--interval",    type=int,  default=300, help="Pull interval in seconds")
    p.add_argument("--min-count",   type=int,  default=MIN_COUNT, help="Min domain count filter")
    args = p.parse_args()
    WEBHOOK_PORT = args.port
    MIN_COUNT    = args.min_count
    run_server(auto_pull=args.auto_pull,
               pull_interval=args.interval,
               wazuh_pull=args.wazuh_pull)