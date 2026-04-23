"""
soc_enhancements.py — NetSec AI v10.1
========================================
5 high-value SOC lab enhancements:
  1. MISP Integration   — consume & push threat intel IOCs
  2. Wazuh Integration  — receive host-based alerts
  3. Sigma Rule Engine  — convert/test Sigma rules against your alerts
  4. Splunk Dashboard   — rich auto-built SPL dashboard panels
  5. MITRE Coverage Map — visual heatmap of detected vs missing techniques
"""
from __future__ import annotations
import json, os, re, time, logging
from datetime import datetime
from typing import Any

logger = logging.getLogger("netsec.enhancements")


# ══════════════════════════════════════════════════════════════════════════════
# 1. MISP INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

def misp_search_ioc(ioc: str, misp_url: str = "", misp_key: str = "") -> dict:
    """
    Search MISP for an IOC (IP, domain, hash, URL).
    Returns {found, events, threat_level, tags, malware_families}
    """
    misp_url = misp_url or os.getenv("MISP_URL", "")
    misp_key = misp_key or os.getenv("MISP_API_KEY", "")

    if not misp_url or not misp_key:
        return {"found": False, "error": "MISP not configured", "events": []}

    import urllib.request as _ur, ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE

    try:
        payload = json.dumps({
            "returnFormat": "json",
            "value":        ioc,
            "quickFilter":  True,
            "limit":        10,
        }).encode()

        req = _ur.Request(
            f"{misp_url.rstrip('/')}/attributes/restSearch",
            data=payload,
            headers={"Authorization": misp_key,
                     "Content-Type":  "application/json",
                     "Accept":        "application/json"},
            method="POST"
        )
        with _ur.urlopen(req, timeout=8, context=ctx) as r:
            data = json.loads(r.read().decode())

        attrs = data.get("response", {}).get("Attribute", [])
        if not attrs:
            return {"found": False, "events": [], "ioc": ioc}

        events   = list({a.get("event_id") for a in attrs})
        tags     = list({t.get("name","") for a in attrs for t in a.get("Tag",[])})
        families = [t.replace("misp-galaxy:malpedia=","")
                    for t in tags if "malpedia" in t.lower()]

        threat_level = "HIGH" if any("tlp:red" in t.lower() for t in tags) else \
                       "MEDIUM" if any("tlp:amber" in t.lower() for t in tags) else "LOW"

        return {
            "found":            True,
            "ioc":              ioc,
            "event_count":      len(events),
            "event_ids":        events[:5],
            "tags":             tags[:10],
            "malware_families": families[:5],
            "threat_level":     threat_level,
            "attribute_count":  len(attrs),
            "source":           "MISP",
        }
    except Exception as e:
        return {"found": False, "error": str(e)[:80], "ioc": ioc}


def misp_push_ioc(ioc: str, ioc_type: str, verdict: str, risk_score: int,
                   misp_url: str = "", misp_key: str = "") -> tuple[bool, str]:
    """Push a NetSec AI verdict back to MISP as a new event."""
    misp_url = misp_url or os.getenv("MISP_URL","")
    misp_key = misp_key or os.getenv("MISP_API_KEY","")
    if not misp_url or not misp_key:
        return False, "MISP not configured"

    import urllib.request as _ur, ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE

    _type_map = {"ip":"ip-dst","domain":"domain","hash":"md5","url":"url"}
    misp_attr_type = _type_map.get(ioc_type, "other")
    threat_level   = 1 if risk_score < 30 else 2 if risk_score < 50 else 3

    event = {
        "Event": {
            "info":           f"NetSec AI: {verdict} — {ioc}",
            "threat_level_id": str(threat_level),
            "distribution":   "0",
            "analysis":       "2",
            "Attribute": [{
                "type":        misp_attr_type,
                "value":       ioc,
                "to_ids":      risk_score < 40,
                "comment":     f"NetSec AI verdict: {verdict} (score {risk_score}/100)",
            }]
        }
    }
    try:
        req = _ur.Request(
            f"{misp_url.rstrip('/')}/events/add",
            data=json.dumps(event).encode(),
            headers={"Authorization": misp_key,
                     "Content-Type": "application/json",
                     "Accept": "application/json"},
            method="POST"
        )
        with _ur.urlopen(req, timeout=8, context=ctx) as r:
            resp = json.loads(r.read().decode())
        eid = resp.get("Event",{}).get("id","?")
        return True, f"✅ MISP event created (ID: {eid})"
    except Exception as e:
        return False, f"MISP push failed: {str(e)[:80]}"


# ══════════════════════════════════════════════════════════════════════════════
# 2. WAZUH INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

def wazuh_get_alerts(wazuh_url: str = "",
                     wazuh_user: str = "",
                     wazuh_pass: str = "", limit: int = 20) -> list[dict]:
    """
    Fetch alerts from OpenSearch/Wazuh Indexer (port 9200).
    Endpoint : POST /wazuh-alerts-*/_search
    Auth     : HTTP Basic (admin / SecretPassword)
    Parses   : hits.hits[i]._source  — NOT data.affected_items
    """
    wazuh_url  = wazuh_url  or os.getenv("WAZUH_URL",  "https://192.168.1.5:9200")
    wazuh_user = wazuh_user or os.getenv("WAZUH_USER", "admin")
    wazuh_pass = wazuh_pass or os.getenv("WAZUH_PASS", "SecretPassword")

    if not wazuh_pass:
        return []

    import urllib.request as _ur, base64 as _b64, ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    creds = _b64.b64encode(f"{wazuh_user}:{wazuh_pass}".encode()).decode()

    try:
        query = json.dumps({
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp","rule.level","rule.description",
                "rule.id","rule.groups","rule.mitre",
                "agent.name","agent.ip","agent.id",
                "data.srcip","data.dstip","data.srcuser",
                "location","full_log"
            ]
        }).encode()

        req = _ur.Request(
            f"{wazuh_url.rstrip('/')}/wazuh-alerts-*/_search",
            data=query,
            headers={
                "Authorization": f"Basic {creds}",
                "Content-Type":  "application/json",
            },
            method="POST"
        )
        with _ur.urlopen(req, timeout=10, context=ctx) as r:
            raw = r.read().decode()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("OpenSearch non-JSON: %s", raw[:200])
            return []

        # Parse hits.hits[i]._source  (NOT data.affected_items)
        hits = data.get("hits", {}).get("hits", [])
        alerts = []
        for hit in hits:
            src   = hit.get("_source", {})
            rule  = src.get("rule",  {})
            agent = src.get("agent", {})
            sdata = src.get("data",  {})
            level = int(rule.get("level", 0))

            mitre_raw = rule.get("mitre", {})
            if isinstance(mitre_raw, dict):
                mitre_id = (mitre_raw.get("id") or [""])[0]
            else:
                mitre_id = ""

            alerts.append({
                "id":          hit.get("_id", ""),
                "timestamp":   src.get("@timestamp", ""),
                "agent_name":  agent.get("name", "?"),
                "agent_ip":    agent.get("ip", agent.get("id", "?")),
                "rule_id":     str(rule.get("id", "")),
                "rule_level":  level,
                "description": rule.get("description", ""),
                "groups":      rule.get("groups", []),
                "mitre":       mitre_id,
                "srcip":       sdata.get("srcip", ""),
                "dstip":       sdata.get("dstip", ""),
                "srcuser":     sdata.get("srcuser", ""),
                "location":    src.get("location", ""),
                "severity":    (
                    "critical" if level >= 12 else
                    "high"     if level >= 8  else
                    "medium"   if level >= 5  else
                    "low"
                ),
                "source": "wazuh_indexer",
                "_raw":   src,
            })
        logger.info("OpenSearch: %d alerts fetched", len(alerts))
        return alerts

    except Exception as e:
        logger.warning("OpenSearch fetch failed: %s", e)
        return []


def wazuh_health_check(wazuh_url: str = "", wazuh_user: str = "",
                        wazuh_pass: str = "") -> dict:
    """
    Health check against OpenSearch indexer (port 9200).
    GET / with Basic auth — returns cluster name + version.
    """
    wazuh_url  = wazuh_url  or os.getenv("WAZUH_URL",  "https://192.168.1.4:9200")
    wazuh_user = wazuh_user or os.getenv("WAZUH_USER", "admin")
    wazuh_pass = wazuh_pass or os.getenv("WAZUH_PASS", "")

    if not wazuh_pass:
        return {
            "status":  "not_configured",
            "message": "Enter password — default is SecretPassword"
        }

    import urllib.request as _ur, base64 as _b64, ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    creds = _b64.b64encode(f"{wazuh_user}:{wazuh_pass}".encode()).decode()
    t0 = time.time()

    try:
        req = _ur.Request(
            f"{wazuh_url.rstrip('/')}/",
            headers={"Authorization": f"Basic {creds}"}
        )
        with _ur.urlopen(req, timeout=8, context=ctx) as r:
            raw = r.read().decode()

        try:
            resp = json.loads(raw)
        except json.JSONDecodeError:
            preview = raw[:120].replace("\n", " ")
            return {"status": "error",
                    "message": f"Non-JSON response — wrong URL/port. Got: {preview}"}

        latency = round((time.time() - t0) * 1000)
        version = resp.get("version", {}).get("number", "?")
        cluster = resp.get("cluster_name", "?")
        node    = resp.get("name", "?")
        return {
            "status":     "ok",
            "message":    f"OpenSearch connected — v{version} cluster:{cluster} ({latency}ms)",
            "version":    version,
            "cluster":    cluster,
            "node":       node,
            "latency_ms": latency,
        }

    except _ur.HTTPError as e:
        body = ""
        try: body = e.read().decode()[:120]
        except Exception: pass
        if e.code == 401:
            return {"status": "error",
                    "message": "401 Unauthorized — use username=admin password=SecretPassword"}
        return {"status": "error", "message": f"HTTP {e.code}: {e.reason} — {body}"}

    except _ur.URLError as e:
        reason = str(e.reason)
        if "Connection refused" in reason:
            hint = f"Connection refused — is OpenSearch running at {wazuh_url}?"
        elif "timed out" in reason.lower():
            hint = "Timeout — check IP and port 9200 is reachable"
        else:
            hint = reason[:100]
        return {"status": "error", "message": f"{hint}"}

    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}


# ══════════════════════════════════════════════════════════════════════════════
# 3. SIGMA RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

SIGMA_TEMPLATES = {
    "DNS C2 Beaconing": {
        "title": "DNS C2 Beaconing Pattern",
        "id":    "a1b2c3d4-0001",
        "status": "experimental",
        "description": "Detects high-frequency DNS queries to low-reputation domains (C2 pattern)",
        "author": "NetSec AI",
        "date":   datetime.now().strftime("%Y/%m/%d"),
        "tags":   ["attack.command-and-control", "attack.t1071.004"],
        "logsource": {"category": "dns"},
        "detection": {
            "selection": {
                "query|contains": [".tk", ".ml", ".ga", ".cf", ".xyz", ".top"]
            },
            "filter_trusted": {
                "query|contains": ["google.com","microsoft.com","amazon.com"]
            },
            "condition": "selection and not filter_trusted",
            "timeframe": "1m",
            "count": {"field": "query", "condition": ">50"}
        },
        "falsepositives": ["Legitimate apps using free TLDs (rare)"],
        "level": "high",
        "splunk_spl": (
            'index=dns | stats count by src_ip, query '
            '| where count>50 AND (match(query,"\\.tk$") OR match(query,"\\.xyz$") '
            'OR match(query,"\\.ml$")) | sort -count'
        ),
    },
    "LSASS Memory Access": {
        "title": "LSASS Memory Read — Credential Dumping",
        "id":    "a1b2c3d4-0002",
        "status": "stable",
        "description": "Detects non-system process reading LSASS memory (Mimikatz / credential dumping)",
        "author": "NetSec AI",
        "date":   datetime.now().strftime("%Y/%m/%d"),
        "tags":   ["attack.credential-access", "attack.t1003.001"],
        "logsource": {"product":"windows","category":"process_access"},
        "detection": {
            "selection": {
                "TargetImage|endswith": ["\\lsass.exe"],
                "GrantedAccess|contains": ["0x1010","0x1410","0x1438","0x143a","0x1fffff"]
            },
            "filter": {
                "SourceImage|startswith": ["C:\\Windows\\System32\\",
                                           "C:\\Windows\\SysWOW64\\",
                                           "C:\\Program Files\\Windows Defender\\"]
            },
            "condition": "selection and not filter"
        },
        "falsepositives": ["AV software","EDR agents"],
        "level": "critical",
        "splunk_spl": (
            'index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe" '
            'NOT (SourceImage="*\\\\System32\\\\*" OR SourceImage="*\\\\SysWOW64\\\\*") '
            '| table _time, host, SourceImage, GrantedAccess'
        ),
    },
    "PowerShell Encoded Command": {
        "title": "PowerShell Encoded Command from Office App",
        "id":    "a1b2c3d4-0003",
        "status": "stable",
        "description": "PowerShell launched with -enc from Word/Excel (malicious macro indicator)",
        "author": "NetSec AI",
        "date":   datetime.now().strftime("%Y/%m/%d"),
        "tags":   ["attack.execution", "attack.t1059.001"],
        "logsource": {"product":"windows","category":"process_creation"},
        "detection": {
            "selection_cmd": {
                "Image|endswith": ["\\powershell.exe","\\pwsh.exe"],
                "CommandLine|contains|all": ["-enc","-EncodedCommand"]
            },
            "selection_parent": {
                "ParentImage|endswith": ["\\WINWORD.EXE","\\EXCEL.EXE",
                                         "\\POWERPNT.EXE","\\OUTLOOK.EXE"]
            },
            "condition": "selection_cmd and selection_parent"
        },
        "falsepositives": ["Legitimate admin scripts run from Office (very rare)"],
        "level": "high",
        "splunk_spl": (
            'index=sysmon EventCode=1 Image="*\\\\powershell.exe" '
            '(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*") '
            '(ParentImage="*\\\\WINWORD.EXE" OR ParentImage="*\\\\EXCEL.EXE") '
            '| table _time, host, User, CommandLine, ParentImage'
        ),
    },
    "Lateral Movement SMB": {
        "title": "Lateral Movement via SMB",
        "id":    "a1b2c3d4-0004",
        "status": "experimental",
        "description": "Detects SMB connections to multiple internal hosts (lateral movement pattern)",
        "author": "NetSec AI",
        "date":   datetime.now().strftime("%Y/%m/%d"),
        "tags":   ["attack.lateral-movement", "attack.t1021.002"],
        "logsource": {"product":"windows","category":"network_connection"},
        "detection": {
            "selection": {
                "DestinationPort": 445,
                "Initiated": "true"
            },
            "filter": {"SourceIp|startswith": ["127.","::1"]},
            "condition": "selection and not filter",
            "timeframe": "5m",
            "count": {"field":"DestinationIp","condition":">3"}
        },
        "falsepositives": ["Domain controller","File server access","Backup jobs"],
        "level": "medium",
        "splunk_spl": (
            'index=sysmon EventCode=3 DestinationPort=445 '
            'NOT (SourceIp="127.*" OR SourceIp="::1") '
            '| stats dc(DestinationIp) as unique_dests by SourceIp '
            '| where unique_dests>3 | sort -unique_dests'
        ),
    },
    "Data Exfiltration Large Upload": {
        "title": "Large Outbound Data Transfer (Exfiltration)",
        "id":    "a1b2c3d4-0005",
        "status": "experimental",
        "description": "Detects unusually large outbound data transfer to external IPs",
        "author": "NetSec AI",
        "date":   datetime.now().strftime("%Y/%m/%d"),
        "tags":   ["attack.exfiltration", "attack.t1041"],
        "logsource": {"category":"firewall"},
        "detection": {
            "selection": {
                "bytes_out|gt": 100000000,
                "direction": "outbound"
            },
            "filter_internal": {
                "dst_ip|cidr": ["10.0.0.0/8","192.168.0.0/16","172.16.0.0/12"]
            },
            "condition": "selection and not filter_internal"
        },
        "falsepositives": ["Cloud backup","Software updates","Video conferencing"],
        "level": "high",
        "splunk_spl": (
            'index=firewall action=allow '
            'NOT (dest_ip="10.*" OR dest_ip="192.168.*" OR dest_ip="172.16.*") '
            '| stats sum(bytes_out) as total_bytes by src_ip, dest_ip '
            '| where total_bytes>100000000 '
            '| eval gb=round(total_bytes/1073741824,2) | sort -total_bytes'
        ),
    },
}


def sigma_to_splunk_spl(rule_name: str) -> str:
    """Get the Splunk SPL for a Sigma rule template."""
    rule = SIGMA_TEMPLATES.get(rule_name, {})
    return rule.get("splunk_spl", f"| search rule=\"{rule_name}\"")


def sigma_match_alert(alert: dict) -> list[str]:
    """
    Quick check: which Sigma rule templates match this alert?
    Returns list of matching rule names.
    """
    matches = []
    alert_str = json.dumps(alert).lower()
    mitre = alert.get("mitre","").upper()

    _MITRE_MAP = {
        "T1071": ["DNS C2 Beaconing"],
        "T1003": ["LSASS Memory Access"],
        "T1059": ["PowerShell Encoded Command"],
        "T1021": ["Lateral Movement SMB"],
        "T1041": ["Data Exfiltration Large Upload"],
    }
    for tech, rules in _MITRE_MAP.items():
        if tech in mitre:
            matches.extend(rules)

    # keyword matching
    if any(k in alert_str for k in ["lsass","credential","mimikatz"]):
        if "LSASS Memory Access" not in matches:
            matches.append("LSASS Memory Access")
    if any(k in alert_str for k in ["-enc","-encodedcommand","powershell"]):
        if "PowerShell Encoded Command" not in matches:
            matches.append("PowerShell Encoded Command")
    if any(k in alert_str for k in ["smb","lateral","445"]):
        if "Lateral Movement SMB" not in matches:
            matches.append("Lateral Movement SMB")

    return list(set(matches))


# ══════════════════════════════════════════════════════════════════════════════
# 4. SPLUNK DASHBOARD BUILDER
# ══════════════════════════════════════════════════════════════════════════════

SPLUNK_DASHBOARD_PANELS = {
    "verdict_summary": {
        "title": "NetSec AI Verdict Distribution",
        "spl": (
            'index=ids_alerts sourcetype=netsec_ai '
            '| stats count by verdict '
            '| sort -count'
        ),
        "viz": "pie",
    },
    "top_malicious": {
        "title": "Top Malicious Domains/IPs (last 24h)",
        "spl": (
            'index=ids_alerts sourcetype=netsec_ai risk_score<40 '
            '| stats count, min(risk_score) as score by domain '
            '| sort -count | head 10'
        ),
        "viz": "table",
    },
    "alert_timeline": {
        "title": "Alert Timeline",
        "spl": (
            'index=ids_alerts sourcetype=netsec_ai '
            '| timechart span=1h count by severity'
        ),
        "viz": "line",
    },
    "mitre_heatmap": {
        "title": "MITRE ATT&CK Techniques Seen",
        "spl": (
            'index=ids_alerts sourcetype=netsec_ai mitre!="" '
            '| stats count by mitre '
            '| sort -count'
        ),
        "viz": "bar",
    },
    "risk_score_dist": {
        "title": "Risk Score Distribution",
        "spl": (
            'index=ids_alerts sourcetype=netsec_ai '
            '| eval band=case(risk_score>=70,"SAFE",risk_score>=40,"LOW RISK",'
            'risk_score>=20,"SUSPICIOUS",1=1,"MALICIOUS") '
            '| stats count by band'
        ),
        "viz": "bar",
    },
    "wazuh_top_rules": {
        "title": "Top Wazuh Alert Rules",
        "spl": (
            'index=wazuh sourcetype=wazuh '
            '| stats count by rule.description '
            '| sort -count | head 10'
        ),
        "viz": "table",
    },
    "high_risk_sources": {
        "title": "Source IPs Generating Most High-Risk Alerts",
        "spl": (
            'index=ids_alerts sourcetype=netsec_ai '
            '(severity=high OR severity=critical) '
            '| stats count by ip '
            '| sort -count | head 10'
        ),
        "viz": "table",
    },
}


def generate_splunk_dashboard_xml() -> str:
    """Generate importable Splunk Simple XML dashboard."""
    panels_xml = ""
    for key, panel in SPLUNK_DASHBOARD_PANELS.items():
        viz_type = {"pie":"chart","bar":"chart","line":"chart","table":"table"}.get(panel["viz"],"table")
        chart_type = panel["viz"] if panel["viz"] in ("pie","bar","line") else ""
        panels_xml += f"""
  <row>
    <panel>
      <title>{panel['title']}</title>
      <{viz_type}>
        <search><query>{panel['spl']}</query><earliest>-24h</earliest><latest>now</latest></search>
        {"<option name='charting.chart'>" + chart_type + "</option>" if chart_type else ""}
      </{viz_type}>
    </panel>
  </row>"""

    return f"""<?xml version="1.0"?>
<dashboard version="1.1">
  <label>NetSec AI — SOC Operations Dashboard</label>
  <description>Auto-generated by NetSec AI v10.1 — shows verdicts, MITRE coverage, Wazuh alerts</description>
  {panels_xml}
</dashboard>"""


# ══════════════════════════════════════════════════════════════════════════════
# 5. MITRE COVERAGE MAP
# ══════════════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES = {
    "Initial Access":     ["T1566","T1190","T1133","T1078","T1091","T1195","T1200"],
    "Execution":          ["T1059","T1059.001","T1059.003","T1204","T1047","T1053","T1569"],
    "Persistence":        ["T1547","T1547.001","T1053","T1078","T1136","T1543","T1574"],
    "Privilege Escalation":["T1548","T1055","T1068","T1078","T1134","T1543"],
    "Defense Evasion":    ["T1027","T1036","T1055","T1070","T1112","T1140","T1562"],
    "Credential Access":  ["T1003","T1003.001","T1110","T1187","T1552","T1555","T1558"],
    "Discovery":          ["T1018","T1033","T1046","T1057","T1069","T1082","T1135"],
    "Lateral Movement":   ["T1021","T1021.002","T1021.006","T1534","T1550","T1563"],
    "Collection":         ["T1005","T1025","T1039","T1074","T1114","T1115","T1119"],
    "C2":                 ["T1071","T1071.001","T1071.004","T1095","T1105","T1571","T1572"],
    "Exfiltration":       ["T1020","T1030","T1041","T1048","T1052","T1567"],
    "Impact":             ["T1485","T1486","T1489","T1490","T1491","T1498","T1529"],
}

def compute_mitre_coverage(session_alerts: list) -> dict:
    """
    Compute which MITRE techniques have been detected vs missing.
    Returns coverage dict per tactic.
    """
    detected = set()
    for a in session_alerts:
        mitre = str(a.get("mitre",""))
        for t in re.findall(r'T\d{4}(?:\.\d{3})?', mitre.upper()):
            detected.add(t)

    coverage = {}
    total_detected = 0
    total_techniques = 0

    for tactic, techniques in MITRE_TECHNIQUES.items():
        covered = [t for t in techniques if t in detected]
        missing  = [t for t in techniques if t not in detected]
        pct      = round(len(covered)/len(techniques)*100) if techniques else 0
        coverage[tactic] = {
            "covered":    covered,
            "missing":    missing,
            "total":      len(techniques),
            "detected":   len(covered),
            "pct":        pct,
            "color":      ("#ff0033" if pct==0 else "#ff9900" if pct<40
                           else "#ffcc00" if pct<70 else "#00c878"),
        }
        total_detected   += len(covered)
        total_techniques += len(techniques)

    overall_pct = round(total_detected/total_techniques*100) if total_techniques else 0
    return {
        "tactics":       coverage,
        "total_detected":total_detected,
        "total_techs":   total_techniques,
        "overall_pct":   overall_pct,
        "detected_set":  list(detected),
    }


# ══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI — render_soc_enhancements()
# ══════════════════════════════════════════════════════════════════════════════

def render_soc_enhancements():
    import streamlit as st

    st.markdown(
        "<div style='font-family:Orbitron,monospace;font-size:.9rem;font-weight:900;"
        "color:#00ffc8;letter-spacing:2px;margin-bottom:4px'>🔬 SOC LAB ENHANCEMENTS</div>"
        "<div style='color:#446688;font-size:.68rem;margin-bottom:14px'>"
        "Wazuh · Sigma Rules · Splunk Dashboard · MITRE Coverage</div>",
        unsafe_allow_html=True
    )

    tab_wazuh, tab_sigma, tab_mitre = st.tabs([
        "🛡️ Wazuh", "⚔️ Sigma Rules", "🗺️ MITRE Coverage"
    ])

    # ── WAZUH ─────────────────────────────────────────────────────────────────
    with tab_wazuh:
        st.subheader("🛡️ Wazuh Host-Based IDS")
        st.caption("Receive Wazuh alerts · Enrich with NetSec AI reputation · Push to Splunk")

        _wc1, _wc2, _wc3 = st.columns(3)
        wazuh_url  = _wc1.text_input("Wazuh URL", value=os.getenv("WAZUH_URL","https://192.168.1.4:9200"), key="wazuh_url")
        wazuh_user = _wc2.text_input("Username",  value=os.getenv("WAZUH_USER","admin"), key="wazuh_user")
        wazuh_pass = _wc3.text_input("Password",  type="password", key="wazuh_pass")

        _wb1, _wb2 = st.columns(2)
        if _wb1.button("🔌 Test Wazuh Connection", key="wazuh_test", use_container_width=True):
            with st.spinner("Connecting…"):
                h = wazuh_health_check(wazuh_url, wazuh_user, wazuh_pass)
            if h["status"] == "ok":
                st.success(h["message"])
            elif h["status"] == "not_configured":
                st.info(h["message"])
            else:
                msg = h["message"]
                if "401" in msg or "Unauthorized" in msg or "Invalid credentials" in msg:
                    st.error(msg)
                    st.markdown("**Fix — get the correct password from your docker-compose.yml:**")
                    st.code('cd wazuh-docker/single-node\ntype docker-compose.yml | findstr /i API_PASSWORD', language="bash")
                    st.markdown("**Then verify it works:**")
                    st.code('curl -k -u admin:SecretPassword https://192.168.1.4:9200/', language="bash")
                    st.warning("Make sure port 9200 is accessible — use https://192.168.1.4:9200")
                elif "Connection refused" in msg:
                    st.error(msg)
                    st.code("docker ps | grep wazuh\ncd wazuh-docker/single-node && docker compose up -d", language="bash")
                elif "timed out" in msg.lower():
                    st.error(msg)
                    st.markdown("URL must be `https://192.168.1.4:9200` — this is the OpenSearch/Indexer port")
                elif "non-JSON" in msg or "Expecting value" in msg:
                    st.error(msg)
                    st.markdown("Wrong URL — port 9200 is OpenSearch, port 55000 is Wazuh Manager API (not used here)")
                elif "403" in msg or "Forbidden" in msg:
                    st.error(msg)
                    st.markdown("403 Forbidden — your admin user lacks permission. Try username=admin password=SecretPassword")
                else:
                    st.error(msg)

        if _wb2.button("📥 Fetch Recent Alerts", key="wazuh_fetch", use_container_width=True):
            with st.spinner("Fetching alerts…"):
                alerts = wazuh_get_alerts(wazuh_url, wazuh_user, wazuh_pass)
            if alerts:
                st.session_state["wazuh_alerts"] = alerts
                st.success(f"✅ Fetched {len(alerts)} Wazuh alerts")
            else:
                st.info("No alerts fetched (check credentials or Wazuh not running)")

        wazuh_alerts = st.session_state.get("wazuh_alerts",[])
        if wazuh_alerts:
            import pandas as pd
            df = pd.DataFrame(wazuh_alerts)[["timestamp","agent_name","agent_ip","rule_id","rule_level","description","mitre","severity"]]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No Wazuh alerts loaded yet.")

        with st.expander("💡 Wazuh Setup (Docker — 3 minutes)"):
            st.code("""# Start Wazuh all-in-one (manager + indexer + dashboard)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Or Docker:
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker-compose up -d

# Dashboard: https://localhost  user: admin / pass from install output
# API:       https://192.168.1.4:55000  user: wazuh""", language="bash")

    # ── SIGMA ─────────────────────────────────────────────────────────────────
    with tab_sigma:
        st.subheader("⚔️ Sigma Rule Engine")
        st.caption("Pre-built Sigma rules mapped to your alerts · Auto-convert to Splunk SPL")

        rule_choice = st.selectbox("Select Sigma rule template", list(SIGMA_TEMPLATES.keys()), key="sigma_rule_sel")
        rule = SIGMA_TEMPLATES[rule_choice]

        _s1, _s2, _s3 = st.columns(3)
        _s1.metric("Level",  rule["level"].upper())
        _s2.metric("Status", rule["status"])
        _s3.metric("MITRE",  rule["tags"][-1].replace("attack.","").upper() if rule["tags"] else "?")

        st.markdown(f"**Description:** {rule['description']}")
        st.markdown(f"**False positives:** {', '.join(rule['falsepositives'])}")

        tab_yaml, tab_spl = st.tabs(["📄 Sigma YAML", "🔍 Splunk SPL"])
        with tab_yaml:
            # No yaml dependency — build clean YAML string manually
            def _to_yaml(d, indent=0):
                lines = []
                pad = "  " * indent
                for k, v in d.items():
                    if isinstance(v, dict):
                        lines.append(f"{pad}{k}:")
                        lines.append(_to_yaml(v, indent+1))
                    elif isinstance(v, list):
                        lines.append(f"{pad}{k}:")
                        for item in v:
                            if isinstance(item, dict):
                                sub = _to_yaml(item, indent+2).lstrip()
                                lines.append(f"{pad}  - {sub}")
                            else:
                                lines.append(f"{pad}  - {item}")
                    else:
                        lines.append(f"{pad}{k}: {json.dumps(v) if isinstance(v, bool) else v}")
                return "\n".join(lines)
            rule_display = {k:v for k,v in rule.items() if k != "splunk_spl"}
            st.code(_to_yaml(rule_display), language="yaml")
        with tab_spl:
            st.code(rule["splunk_spl"], language="spl")
            st.caption("Copy → paste into Splunk Search → Save As Alert → Webhook → NetSec AI")

        st.divider()
        st.markdown("**Match against current session alerts:**")
        alerts = st.session_state.get("triage_alerts",[])
        if alerts:
            matched_count = 0
            for a in alerts[:20]:
                matches = sigma_match_alert(a)
                if matches:
                    matched_count += 1
                    st.markdown(f"- `{a.get('alert_type','?')}` on `{a.get('domain',a.get('ip','?'))}` → **{', '.join(matches)}**")
            if matched_count == 0:
                st.info("No current session alerts match these Sigma rules.")
        else:
            st.info("No session alerts loaded yet — run Threat Triage first.")

    # ── SPLUNK DASHBOARD ──────────────────────────────────────────────────────
    with tab_mitre:
        st.subheader("🗺️ MITRE ATT&CK Coverage Map")
        st.caption("Which techniques have you detected? Where are the gaps?")

        alerts = st.session_state.get("triage_alerts", [])
        coverage = compute_mitre_coverage(alerts)

        _m1, _m2, _m3 = st.columns(3)
        _m1.metric("Overall Coverage", f"{coverage['overall_pct']}%")
        _m2.metric("Techniques Detected", coverage['total_detected'])
        _m3.metric("Total Mapped", coverage['total_techs'])

        st.markdown("---")

        for tactic, data in coverage["tactics"].items():
            _col_l, _col_r = st.columns([1, 4])
            _col_l.markdown(
                f"<div style='font-size:.72rem;font-weight:700;color:{data['color']};margin-top:4px'>"
                f"{tactic}<br><span style='font-size:1.1rem'>{data['pct']}%</span></div>",
                unsafe_allow_html=True
            )
            with _col_r:
                # Render technique pills
                pills_html = ""
                for t in data["covered"]:
                    pills_html += (f"<span style='background:#00c87822;border:1px solid #00c87844;"
                                   f"color:#00c878;border-radius:4px;padding:1px 7px;"
                                   f"font-size:.68rem;margin:2px;display:inline-block'>{t}</span>")
                for t in data["missing"]:
                    pills_html += (f"<span style='background:#ff003311;border:1px solid #ff003333;"
                                   f"color:#ff4444;border-radius:4px;padding:1px 7px;"
                                   f"font-size:.68rem;margin:2px;display:inline-block'>{t}</span>")
                st.markdown(f"<div style='padding:4px 0'>{pills_html}</div>", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown(
            "<div style='font-size:.7rem;color:#446688'>"
            "<span style='color:#00c878'>■</span> Detected &nbsp;&nbsp;"
            "<span style='color:#ff4444'>■</span> Not yet detected (detection gap)</div>",
            unsafe_allow_html=True
        )

        if coverage["detected_set"]:
            st.markdown(f"**Detected techniques:** `{'` · `'.join(sorted(coverage['detected_set']))}`")
        else:
            st.info("No MITRE techniques detected yet in this session. Run Threat Triage to populate.")