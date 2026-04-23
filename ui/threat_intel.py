# threat_intel.py
# Multi-source Threat Intelligence for SOC Proof AI
# AbuseIPDB · Shodan · GreyNoise · OTX AlienVault · MalwareBazaar · URLScan · IPInfo
# Splunk REST API · False Positive Tracker · MTTD/MTTR Calculator

import os, json, time, logging, requests
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY",  "")
SHODAN_KEY     = os.getenv("SHODAN_API_KEY",      "")
GREYNOISE_KEY  = os.getenv("GREYNOISE_API_KEY",   "")
OTX_KEY        = os.getenv("OTX_API_KEY",         "")
IPINFO_KEY     = os.getenv("IPINFO_TOKEN",        "")
URLSCAN_KEY    = os.getenv("URLSCAN_API_KEY",     "")
SPLUNK_REST    = os.getenv("SPLUNK_REST_URL",     "https://127.0.0.1:8089")
SPLUNK_USER    = os.getenv("SPLUNK_USERNAME",     "admin")
SPLUNK_PASS    = os.getenv("SPLUNK_PASSWORD",     "")
TIMEOUT        = 8

# ─── AbuseIPDB ────────────────────────────────────────────────────────────────
def query_abuseipdb(ip: str) -> dict:
    """IP confidence score 0-100. Free: 1000/day. key: abuseipdb.com/account/api"""
    r = {"source":"AbuseIPDB","ip":ip,"confidence":0,"total_reports":0,
         "country":"","isp":"","usage_type":"","is_tor":False,
         "last_reported":"","verdict":"clean","error":None}
    if not ABUSEIPDB_KEY:
        r["error"] = "ABUSEIPDB_API_KEY not set"; return r
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT)
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            c = d.get("abuseConfidenceScore", 0)
            r.update({"confidence":c,"total_reports":d.get("totalReports",0),
                      "country":d.get("countryCode",""),"isp":d.get("isp",""),
                      "usage_type":d.get("usageType",""),"is_tor":d.get("isTor",False),
                      "last_reported":d.get("lastReportedAt",""),
                      "verdict":"malicious" if c>=75 else "suspicious" if c>=25 else "clean"})
        elif resp.status_code == 429: r["error"] = "Rate limit (1000/day)"
        else: r["error"] = f"HTTP {resp.status_code}"
    except Exception as e: r["error"] = str(e)
    return r

# ─── Shodan ───────────────────────────────────────────────────────────────────
def query_shodan(ip: str) -> dict:
    """Open ports, services, CVEs. Free: 100/month. key: account.shodan.io"""
    r = {"source":"Shodan","ip":ip,"open_ports":[],"hostnames":[],
         "org":"","country":"","city":"","os":"","vulns":[],
         "tags":[],"services":[],"last_update":"","verdict":"unknown","error":None}
    if not SHODAN_KEY:
        r["error"] = "SHODAN_API_KEY not set"; return r
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": SHODAN_KEY}, timeout=TIMEOUT)
        if resp.status_code == 200:
            d = resp.json()
            vulns = list(d.get("vulns", {}).keys())
            services = [{"port":i.get("port"),"proto":i.get("transport","tcp"),
                         "product":i.get("product",""),"version":i.get("version",""),
                         "banner":(i.get("data") or "")[:100]}
                        for i in d.get("data",[])[:8]]
            r.update({"open_ports":d.get("ports",[]),"hostnames":d.get("hostnames",[]),
                      "org":d.get("org",""),"country":d.get("country_name",""),
                      "city":d.get("city",""),"os":d.get("os",""),"vulns":vulns,
                      "tags":d.get("tags",[]),"services":services,
                      "last_update":d.get("last_update",""),
                      "verdict":"malicious" if vulns else "suspicious" if len(d.get("ports",[]))>10 else "clean"})
        elif resp.status_code == 404: r["error"] = "No data for this IP"
        elif resp.status_code == 401: r["error"] = "Invalid API key"
        else: r["error"] = f"HTTP {resp.status_code}"
    except Exception as e: r["error"] = str(e)
    return r

# ─── GreyNoise ────────────────────────────────────────────────────────────────
def query_greynoise(ip: str) -> dict:
    """Noise vs targeted classification. Free: 50/day. key: viz.greynoise.io"""
    r = {"source":"GreyNoise","ip":ip,"noise":False,"riot":False,
         "classification":"","name":"","last_seen":"","tags":[],
         "verdict":"unknown","error":None}
    try:
        headers = {"Accept": "application/json"}
        if GREYNOISE_KEY: headers["key"] = GREYNOISE_KEY
        resp = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                            headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            d = resp.json(); cls = d.get("classification","unknown")
            r.update({"noise":d.get("noise",False),"riot":d.get("riot",False),
                      "classification":cls,"name":d.get("name",""),
                      "last_seen":d.get("last_seen",""),
                      "verdict":"clean" if d.get("riot") else
                                "malicious" if cls=="malicious" else
                                "noise" if d.get("noise") else "unknown"})
        elif resp.status_code == 404: r["error"] = "IP not in GreyNoise"
        elif resp.status_code == 429: r["error"] = "Rate limit (50/day)"
        else: r["error"] = f"HTTP {resp.status_code}"
    except Exception as e: r["error"] = str(e)
    return r

# ─── OTX AlienVault ───────────────────────────────────────────────────────────
def query_otx(ioc: str, ioc_type: str = "ip") -> dict:
    """Threat pulses, malware families. Free unlimited. key: otx.alienvault.com"""
    r = {"source":"OTX AlienVault","ioc":ioc,"ioc_type":ioc_type,
         "pulse_count":0,"malware_families":[],"threat_types":[],
         "tags":[],"country":"","asn":"","verdict":"clean","error":None}
    if not OTX_KEY:
        r["error"] = "OTX_API_KEY not set"; return r
    ep = {"ip":f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
          "domain":f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general",
          "url":f"https://otx.alienvault.com/api/v1/indicators/url/{ioc}/general",
          "hash":f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general"}
    try:
        resp = requests.get(ep.get(ioc_type,ep["ip"]),
                            headers={"X-OTX-API-KEY": OTX_KEY}, timeout=TIMEOUT)
        if resp.status_code == 200:
            d = resp.json(); pi = d.get("pulse_info",{}); pc = pi.get("count",0)
            pulses = pi.get("pulses",[])
            r.update({"pulse_count":pc,
                      "malware_families":list({t for p in pulses for t in p.get("malware_families",[])})[:8],
                      "tags":list({t for p in pulses for t in p.get("tags",[])})[:12],
                      "country":d.get("country_name",""),"asn":d.get("asn",""),
                      "verdict":"malicious" if pc>=3 else "suspicious" if pc>=1 else "clean"})
        elif resp.status_code == 403: r["error"] = "Invalid OTX key"
        else: r["error"] = f"HTTP {resp.status_code}"
    except Exception as e: r["error"] = str(e)
    return r

# ─── MalwareBazaar ────────────────────────────────────────────────────────────
def query_malwarebazaar(file_hash: str) -> dict:
    """Hash lookup — no API key needed. abuse.ch/projects/malware-bazaar"""
    r = {"source":"MalwareBazaar","hash":file_hash,"found":False,
         "file_name":"","file_type":"","malware_family":"",
         "tags":[],"first_seen":"","verdict":"unknown","error":None}
    try:
        resp = requests.post("https://mb-api.abuse.ch/api/v1/",
                             data={"query":"get_info","hash":file_hash}, timeout=TIMEOUT)
        if resp.status_code == 200:
            d = resp.json()
            if d.get("query_status") == "ok":
                info = d.get("data",[{}])[0]
                r.update({"found":True,"file_name":info.get("file_name",""),
                          "file_type":info.get("file_type",""),
                          "malware_family":info.get("signature",""),
                          "tags":info.get("tags",[]) or [],
                          "first_seen":info.get("first_seen",""),
                          "verdict":"malicious"})
            else: r["error"] = "Hash not found"; r["verdict"] = "clean"
        else: r["error"] = f"HTTP {resp.status_code}"
    except Exception as e: r["error"] = str(e)
    return r

# ─── URLScan.io ───────────────────────────────────────────────────────────────
def query_urlscan(url_or_domain: str) -> dict:
    """URL/domain scan results. Free search. key: urlscan.io/user/signup"""
    r = {"source":"URLScan.io","url":url_or_domain,"found":False,
         "malicious":False,"score":0,"categories":[],"tags":[],
         "ip":"","country":"","verdict":"unknown","error":None}
    try:
        resp = requests.get("https://urlscan.io/api/v1/search/",
                            params={"q":f"domain:{url_or_domain}","size":1},
                            headers={"API-Key":URLSCAN_KEY} if URLSCAN_KEY else {},
                            timeout=TIMEOUT)
        if resp.status_code == 200:
            results = resp.json().get("results",[])
            if results:
                res = results[0]; v = res.get("verdicts",{}).get("overall",{})
                r.update({"found":True,"malicious":v.get("malicious",False),
                          "score":v.get("score",0),"categories":v.get("categories",[]),
                          "tags":res.get("tags",[]),"ip":res.get("page",{}).get("ip",""),
                          "country":res.get("page",{}).get("country",""),
                          "verdict":"malicious" if v.get("malicious") else "clean"})
        else: r["error"] = f"HTTP {resp.status_code}"
    except Exception as e: r["error"] = str(e)
    return r

# ─── IPInfo ───────────────────────────────────────────────────────────────────
def query_ipinfo(ip: str) -> dict:
    """ASN, org, datacenter detection. Free: 50k/month. key: ipinfo.io/signup"""
    r = {"source":"IPInfo","ip":ip,"hostname":"","org":"","asn":"",
         "country":"","city":"","is_datacenter":False,"verdict":"unknown","error":None}
    try:
        token = f"?token={IPINFO_KEY}" if IPINFO_KEY else ""
        resp  = requests.get(f"https://ipinfo.io/{ip}/json{token}", timeout=TIMEOUT)
        if resp.status_code == 200:
            d = resp.json(); org = d.get("org","")
            dc_orgs = ["amazon","google","microsoft","digitalocean","linode",
                       "vultr","ovh","hetzner","cloudflare","choopa","psychz"]
            is_dc = any(p in org.lower() for p in dc_orgs)
            r.update({"hostname":d.get("hostname",""),"org":org,
                      "asn":org.split(" ")[0] if org else "",
                      "country":d.get("country",""),"city":d.get("city",""),
                      "is_datacenter":is_dc,
                      "verdict":"suspicious" if is_dc else "clean"})
        else: r["error"] = f"HTTP {resp.status_code}"
    except Exception as e: r["error"] = str(e)
    return r

# ─── Unified IOC Lookup ───────────────────────────────────────────────────────
def unified_ioc_lookup(ioc: str, ioc_type: str = "auto") -> dict:
    """
    Run all relevant threat intel sources in parallel.
    Returns combined verdict + all source results + elapsed time.
    """
    import re
    if ioc_type == "auto":
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):          ioc_type = "ip"
        elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):            ioc_type = "hash"
        elif ioc.startswith("http://") or ioc.startswith("https://"): ioc_type = "url"
        else:                                                     ioc_type = "domain"

    start = time.time()
    task_map = {
        "ip":     {"abuseipdb":lambda:query_abuseipdb(ioc),
                   "shodan":   lambda:query_shodan(ioc),
                   "greynoise":lambda:query_greynoise(ioc),
                   "otx":      lambda:query_otx(ioc,"ip"),
                   "ipinfo":   lambda:query_ipinfo(ioc)},
        "domain": {"otx":     lambda:query_otx(ioc,"domain"),
                   "urlscan": lambda:query_urlscan(ioc)},
        "hash":   {"malwarebazaar":lambda:query_malwarebazaar(ioc),
                   "otx":          lambda:query_otx(ioc,"hash")},
        "url":    {"urlscan":lambda:query_urlscan(ioc),
                   "otx":    lambda:query_otx(ioc,"url")},
    }
    tasks   = task_map.get(ioc_type, task_map["ip"])
    results = {}

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for f in as_completed(futures, timeout=15):
            name = futures[f]
            try:    results[name] = f.result()
            except Exception as e: results[name] = {"source":name,"error":str(e),"verdict":"error"}

    verdicts = [r.get("verdict","unknown") for r in results.values()]
    overall  = ("malicious"  if "malicious"  in verdicts else
                "suspicious" if "suspicious" in verdicts else
                "clean"      if all(v in ("clean","noise") for v in verdicts
                                    if v not in ("unknown","error","")) else "unknown")
    risk     = {"malicious":"HIGH","suspicious":"MEDIUM","clean":"LOW"}.get(overall,"UNKNOWN")
    all_tags = list({t for r in results.values() for t in r.get("tags",[])})[:20]

    return {"ioc":ioc,"ioc_type":ioc_type,"timestamp":datetime.now(timezone.utc).isoformat(),
            "elapsed_s":round(time.time()-start,2),"overall":overall,"risk":risk,
            "sources_hit":len([r for r in results.values() if not r.get("error")]),
            "sources_total":len(results),"all_tags":all_tags,"results":results}


def batch_ioc_lookup(iocs: list) -> list:
    results = []
    for ioc in iocs[:20]:
        results.append(unified_ioc_lookup(ioc.strip()))
        time.sleep(0.3)
    return results


# ─── Splunk REST API ──────────────────────────────────────────────────────────
def query_splunk_alerts(spl: str, max_results: int = 100,
                         earliest: str = "-24h") -> dict:
    """Query Splunk via REST API (port 8089). Requires SPLUNK_PASSWORD in .env."""
    if not SPLUNK_PASS:
        return {"error":"SPLUNK_PASSWORD not set","events":[]}
    try:
        import urllib3; urllib3.disable_warnings()
        # Create job
        r = requests.post(f"{SPLUNK_REST}/services/search/jobs",
                          auth=(SPLUNK_USER,SPLUNK_PASS),
                          data={"search":f"search {spl}","earliest_time":earliest,
                                "latest_time":"now","output_mode":"json"},
                          verify=False, timeout=15)
        if r.status_code not in (200,201):
            return {"error":f"Job creation failed: HTTP {r.status_code}","events":[]}
        sid = r.json().get("sid")
        if not sid: return {"error":"No SID","events":[]}
        # Poll
        for _ in range(30):
            s = requests.get(f"{SPLUNK_REST}/services/search/jobs/{sid}",
                             auth=(SPLUNK_USER,SPLUNK_PASS),
                             params={"output_mode":"json"},
                             verify=False, timeout=10)
            if s.status_code==200:
                state = s.json()["entry"][0]["content"]["dispatchState"]
                if state in ("DONE","FAILED"): break
            time.sleep(1)
        # Fetch
        res = requests.get(f"{SPLUNK_REST}/services/search/jobs/{sid}/results",
                           auth=(SPLUNK_USER,SPLUNK_PASS),
                           params={"output_mode":"json","count":max_results},
                           verify=False, timeout=15)
        if res.status_code == 200:
            events = res.json().get("results",[])
            return {"events":events,"count":len(events),"sid":sid}
        return {"error":f"Results failed: HTTP {res.status_code}","events":[]}
    except requests.exceptions.ConnectionError:
        return {"error":"Cannot reach Splunk REST (port 8089)","events":[]}
    except Exception as e:
        return {"error":str(e),"events":[]}


def get_splunk_stats(earliest: str = "-24h") -> dict:
    """Fetch summary stats from Splunk for dashboard and daily reports."""
    queries = {
        "total_alerts": f"index=ids_alerts earliest={earliest} | stats count",
        "by_severity":  f"index=ids_alerts earliest={earliest} | stats count by severity",
        "top_domains":  f"index=ids_alerts earliest={earliest} | top limit=10 domain",
        "top_threats":  f"index=ids_alerts earliest={earliest} | top limit=10 alert_type",
        "avg_score":    f"index=ids_alerts earliest={earliest} | stats avg(threat_score) as avg_score",
        "hourly":       f"index=ids_alerts earliest={earliest} | timechart span=1h count",
    }
    stats = {}
    for k, spl in queries.items():
        stats[k] = query_splunk_alerts(spl, max_results=50, earliest=earliest).get("events",[])
    return stats

def fp_tracker(*args, **kwargs):
    return {"status": "not_implemented"}

def full_ioc_lookup(*args, **kwargs):
    return {"status": "not_implemented"}


def calculate_soc_metrics(*args, **kwargs):
    return {
        "mttr": 0,
        "mttd": 0,
        "false_positive_rate": 0
    }

def lookup_abuseipdb(ip: str):
    return {
        "ip": ip,
        "confidence_score": 0,
        "country": "Unknown",
        "usage_type": "Unknown"
    }


# ─── Backward Compatibility Wrappers ─────────────────────────────────────────

def lookup_shodan(ip: str):
    return query_shodan(ip)

def lookup_abuseipdb(ip: str):
    return query_abuseipdb(ip)

# ─── False Positive Tracker ───────────────────────────────────────────────────
FP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fp_tracker.json")

def load_fp_store() -> dict:
    try:
        if os.path.exists(FP_FILE):
            with open(FP_FILE) as f: return json.load(f)
    except Exception: pass
    return {"ips":{},"domains":{},"hashes":{},"tuning_rules":[]}

def save_fp_store(store: dict):
    try:
        with open(FP_FILE,"w") as f: json.dump(store, f, indent=2)
    except Exception as e: logger.error(f"FP save error: {e}")

def mark_false_positive(ioc: str, ioc_type: str, reason: str,
                         analyst: str = "analyst") -> bool:
    store = load_fp_store()
    key   = f"{ioc_type}s"
    store.setdefault(key, {})
    existing = store[key].get(ioc, {})
    store[key][ioc] = {"reason":reason,"analyst":analyst,
                        "ts":datetime.now(timezone.utc).isoformat(),
                        "count":existing.get("count",0)+1}
    save_fp_store(store)
    return True

def is_false_positive(ioc: str, ioc_type: str) -> bool:
    return ioc in load_fp_store().get(f"{ioc_type}s", {})

def get_fp_list() -> dict:
    return load_fp_store()

def remove_false_positive(ioc: str, ioc_type: str) -> bool:
    store = load_fp_store(); key = f"{ioc_type}s"
    if ioc in store.get(key,{}):
        del store[key][ioc]; save_fp_store(store); return True
    return False

def get_tuning_recommendations() -> list:
    """Suggest suppression rules based on repeated false positives."""
    store = load_fp_store(); recs = []
    for itype in ["ips","domains","hashes"]:
        for ioc, data in store.get(itype,{}).items():
            if data.get("count",0) >= 3:
                recs.append({"ioc":ioc,"type":itype[:-1],"count":data["count"],
                              "reason":data.get("reason",""),
                              "suggestion":f"Add suppression rule: {itype[:-1]}={ioc}"})
    return recs


# ─── MTTD / MTTR ─────────────────────────────────────────────────────────────
def calculate_mttd_mttr(alert_history: list) -> dict:
    """
    Calculate MTTD and MTTR from alert history list.
    Each alert needs: created_at, detected_at, resolved_at (ISO strings), status.
    """
    if not alert_history:
        return {"mttd_minutes":0,"mttr_minutes":0,"total_alerts":0,
                "resolved":0,"open":0,"false_positives":0,"fp_rate":0}
    mttd, mttr = [], []; resolved = fp = 0
    for a in alert_history:
        if a.get("status") == "false_positive": fp += 1; continue
        try:
            c = datetime.fromisoformat(a["created_at"])
            d = datetime.fromisoformat(a["detected_at"])
            mttd.append((d-c).total_seconds()/60)
        except Exception: pass
        if a.get("status") == "resolved":
            resolved += 1
            try:
                c  = datetime.fromisoformat(a["created_at"])
                r2 = datetime.fromisoformat(a["resolved_at"])
                mttr.append((r2-c).total_seconds()/60)
            except Exception: pass
    total = len(alert_history)
    return {"mttd_minutes": round(sum(mttd)/len(mttd),1) if mttd else 0,
            "mttr_minutes": round(sum(mttr)/len(mttr),1) if mttr else 0,
            "total_alerts": total,"resolved": resolved,
            "open": total-resolved-fp,"false_positives": fp,
            "fp_rate": round(fp/total*100,1) if total else 0}