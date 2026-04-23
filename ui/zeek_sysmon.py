# zeek_sysmon.py
# Zeek + Sysmon log ingestion, parsing, and correlation
# Place in project root

import os
import json
import re
import logging
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# ZEEK LOG PARSER
# ══════════════════════════════════════════════════════════════════════════════

ZEEK_LOG_TYPES = {
    "conn":  "Network connections",
    "dns":   "DNS queries",
    "http":  "HTTP requests",
    "ssl":   "SSL/TLS sessions",
    "files": "File transfers",
    "weird": "Unusual activity",
}

# Suspicious indicators per log type
ZEEK_SUSPICIOUS = {
    "conn": {
        "high_bytes":    5_000_000,   # >5MB single connection
        "many_ports":    50,          # single src hitting >50 dst ports
        "long_duration": 3600,        # connection >1hr
    },
    "dns": {
        "suspicious_tlds":  [".tk", ".ml", ".ga", ".cf", ".gq", ".onion"],
        "long_domain":      50,       # domain label > 50 chars (DGA indicator)
        "high_query_rate":  100,      # >100 queries/min from one src
    },
    "http": {
        "bad_user_agents": ["sqlmap", "nikto", "nmap", "masscan", "zgrab",
                             "python-requests/2.1", "curl/7.1"],
        "suspicious_uri":  ["../", "etc/passwd", "cmd.exe", "eval(",
                             "base64", "union+select", "<script"],
    },
}


def parse_zeek_conn_log(filepath: str) -> list[dict]:
    """Parse Zeek conn.log (TSV or JSON format)."""
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        headers = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#close") or line.startswith("#open"):
                continue
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue

            # Try JSON first
            if line.startswith("{"):
                try:
                    results.append(json.loads(line))
                    continue
                except json.JSONDecodeError:
                    pass

            # TSV
            if headers:
                parts = line.split("\t")
                record = dict(zip(headers, parts))
                results.append(record)

    except Exception as e:
        logger.error(f"Zeek conn.log parse error: {e}")

    return results


def parse_zeek_dns_log(filepath: str) -> list[dict]:
    """Parse Zeek dns.log."""
    return parse_zeek_conn_log(filepath)  # same TSV/JSON structure


def parse_zeek_http_log(filepath: str) -> list[dict]:
    """Parse Zeek http.log."""
    return parse_zeek_conn_log(filepath)


def analyze_zeek_conn(records: list[dict]) -> dict:
    """Analyse conn.log records for suspicious patterns."""
    alerts = []
    src_port_map   = {}   # src_ip → set of dst_ports
    src_byte_map   = {}   # src_ip → total bytes
    total = len(records)

    for r in records:
        src = r.get("id.orig_h") or r.get("orig_h", "")
        dst = r.get("id.resp_h") or r.get("resp_h", "")
        dport = r.get("id.resp_p") or r.get("resp_p", "")
        duration = float(r.get("duration", 0) or 0)
        orig_bytes = int(r.get("orig_bytes", 0) or 0)
        resp_bytes = int(r.get("resp_bytes", 0) or 0)
        total_bytes = orig_bytes + resp_bytes

        if src:
            src_port_map.setdefault(src, set()).add(dport)
            src_byte_map[src] = src_byte_map.get(src, 0) + total_bytes

        # Long connection
        if duration > ZEEK_SUSPICIOUS["conn"]["long_duration"]:
            alerts.append({
                "type": "Long Connection", "severity": "medium",
                "src": src, "dst": dst,
                "detail": f"Connection lasted {duration:.0f}s (>{ZEEK_SUSPICIOUS['conn']['long_duration']}s)",
                "mitre": "T1071", "source": "zeek:conn",
            })

        # High data transfer (potential exfil)
        if total_bytes > ZEEK_SUSPICIOUS["conn"]["high_bytes"]:
            alerts.append({
                "type": "Large Data Transfer", "severity": "high",
                "src": src, "dst": dst,
                "detail": f"{total_bytes/1_000_000:.1f}MB transferred",
                "mitre": "T1041", "source": "zeek:conn",
            })

    # Port scan detection
    for src, ports in src_port_map.items():
        if len(ports) > ZEEK_SUSPICIOUS["conn"]["many_ports"]:
            alerts.append({
                "type": "Port Scan", "severity": "high",
                "src": src, "dst": "multiple",
                "detail": f"{len(ports)} distinct ports probed",
                "mitre": "T1046", "source": "zeek:conn",
            })

    # Top talkers
    top_talkers = sorted(src_byte_map.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_connections": total,
        "alerts": alerts,
        "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
        "unique_sources": len(src_port_map),
    }


def analyze_zeek_dns(records: list[dict]) -> dict:
    """Analyse dns.log for DGA, tunneling, beaconing."""
    alerts = []
    query_counts = {}   # src → count
    suspicious_domains = []

    for r in records:
        query  = (r.get("query") or "").lower()
        src    = r.get("id.orig_h") or r.get("orig_h", "")
        rcode  = r.get("rcode_name") or r.get("rcode", "")

        if not query:
            continue

        query_counts[src] = query_counts.get(src, 0) + 1

        # Suspicious TLD
        for tld in ZEEK_SUSPICIOUS["dns"]["suspicious_tlds"]:
            if query.endswith(tld):
                suspicious_domains.append(query)
                alerts.append({
                    "type": "Suspicious TLD", "severity": "medium",
                    "src": src, "dst": query,
                    "detail": f"Query to suspicious TLD: {query}",
                    "mitre": "T1568", "source": "zeek:dns",
                })
                break

        # DGA indicator: very long random-looking subdomain
        parts = query.split(".")
        if parts and len(parts[0]) > ZEEK_SUSPICIOUS["dns"]["long_domain"]:
            alerts.append({
                "type": "Possible DGA Domain", "severity": "high",
                "src": src, "dst": query,
                "detail": f"Unusually long subdomain ({len(parts[0])} chars) — possible DGA",
                "mitre": "T1568.002", "source": "zeek:dns",
            })

        # DNS tunneling: high entropy label
        if parts and _entropy(parts[0]) > 3.8 and len(parts[0]) > 20:
            alerts.append({
                "type": "DNS Tunneling Indicator", "severity": "high",
                "src": src, "dst": query,
                "detail": f"High-entropy DNS label — possible DNS tunneling",
                "mitre": "T1071.004", "source": "zeek:dns",
            })

    # Beaconing: high query rate from single src
    for src, count in query_counts.items():
        if count > ZEEK_SUSPICIOUS["dns"]["high_query_rate"]:
            alerts.append({
                "type": "DNS Beaconing", "severity": "high",
                "src": src, "dst": "multiple",
                "detail": f"{count} DNS queries — possible C2 beaconing",
                "mitre": "T1071.004", "source": "zeek:dns",
            })

    return {
        "total_queries": len(records),
        "alerts": alerts,
        "suspicious_domains": list(set(suspicious_domains))[:20],
        "top_queriers": sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:10],
    }


def analyze_zeek_http(records: list[dict]) -> dict:
    """Analyse http.log for web attacks, suspicious user-agents."""
    alerts = []
    uri_counts = {}

    for r in records:
        ua    = (r.get("user_agent") or "").lower()
        uri   = (r.get("uri") or "").lower()
        src   = r.get("id.orig_h") or r.get("orig_h", "")
        host  = r.get("host") or ""
        meth  = r.get("method") or ""
        status= r.get("status_code") or ""

        # Bad user agent
        for bad_ua in ZEEK_SUSPICIOUS["http"]["bad_user_agents"]:
            if bad_ua in ua:
                alerts.append({
                    "type": "Suspicious User-Agent", "severity": "high",
                    "src": src, "dst": host,
                    "detail": f"Attack tool detected: {ua[:80]}",
                    "mitre": "T1595", "source": "zeek:http",
                })
                break

        # Suspicious URI patterns
        for pattern in ZEEK_SUSPICIOUS["http"]["suspicious_uri"]:
            if pattern in uri:
                attack_type = "Path Traversal" if "../" in pattern else \
                              "SQLi" if "select" in pattern else \
                              "XSS" if "script" in pattern else \
                              "Command Injection"
                alerts.append({
                    "type": attack_type, "severity": "critical",
                    "src": src, "dst": f"{host}{uri[:60]}",
                    "detail": f"Suspicious URI pattern '{pattern}' detected",
                    "mitre": "T1190", "source": "zeek:http",
                })
                break

        uri_counts[uri[:60]] = uri_counts.get(uri[:60], 0) + 1

    return {
        "total_requests": len(records),
        "alerts": alerts,
        "top_uris": sorted(uri_counts.items(), key=lambda x: x[1], reverse=True)[:10],
    }


def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    import math
    from collections import Counter
    if not s:
        return 0.0
    freq = Counter(s)
    return -sum((c/len(s)) * math.log2(c/len(s)) for c in freq.values())


def ingest_zeek_directory(directory: str) -> dict:
    """
    Auto-detect and parse all Zeek log files in a directory.
    Returns combined analysis.
    """
    results = {"conn": {}, "dns": {}, "http": {}, "all_alerts": [], "summary": {}}
    dir_path = Path(directory)

    if not dir_path.exists():
        return {"error": f"Directory not found: {directory}"}

    for log_type, description in ZEEK_LOG_TYPES.items():
        # Check for .log and .log.gz
        for pattern in [f"{log_type}.log", f"{log_type}.*.log"]:
            matches = list(dir_path.glob(pattern))
            if matches:
                filepath = str(matches[0])
                records  = parse_zeek_conn_log(filepath)
                logger.info(f"Zeek {log_type}.log: {len(records)} records from {filepath}")

                if log_type == "conn":
                    results["conn"] = analyze_zeek_conn(records)
                    results["all_alerts"].extend(results["conn"].get("alerts", []))
                elif log_type == "dns":
                    results["dns"] = analyze_zeek_dns(records)
                    results["all_alerts"].extend(results["dns"].get("alerts", []))
                elif log_type == "http":
                    results["http"] = analyze_zeek_http(records)
                    results["all_alerts"].extend(results["http"].get("alerts", []))
                break

    results["summary"] = {
        "total_alerts":    len(results["all_alerts"]),
        "critical_alerts": sum(1 for a in results["all_alerts"] if a.get("severity") == "critical"),
        "high_alerts":     sum(1 for a in results["all_alerts"] if a.get("severity") == "high"),
        "log_types_found": [k for k in ["conn","dns","http"] if results.get(k)],
    }

    return results


# ══════════════════════════════════════════════════════════════════════════════
# SYSMON PARSER (Windows XML event logs)
# ══════════════════════════════════════════════════════════════════════════════

SYSMON_EVENT_IDS = {
    1:  "Process Creation",
    3:  "Network Connection",
    7:  "Image Loaded",
    8:  "CreateRemoteThread",
    10: "Process Access",
    11: "File Created",
    12: "Registry Event (Create/Delete)",
    13: "Registry Event (Set Value)",
    22: "DNS Query",
    23: "File Delete",
}

# Suspicious patterns per event
SYSMON_RULES = {
    1: {  # Process Creation
        "suspicious_parents": ["winword.exe", "excel.exe", "powerpnt.exe",
                                "outlook.exe", "iexplore.exe", "chrome.exe"],
        "suspicious_children": ["cmd.exe", "powershell.exe", "wscript.exe",
                                  "cscript.exe", "mshta.exe", "regsvr32.exe",
                                  "rundll32.exe", "certutil.exe", "bitsadmin.exe"],
        "suspicious_cmdline":  ["base64", "-enc", "iex(", "downloadstring",
                                  "invoke-expression", "bypass", "-nop", "hidden"],
    },
    3: {  # Network Connection
        "suspicious_ports": [4444, 5555, 6666, 6667, 8888, 1337, 31337],
    },
    11: {  # File Created
        "suspicious_dirs":  ["\\temp\\", "\\tmp\\", "\\appdata\\roaming\\",
                              "\\programdata\\", "\\windows\\temp\\"],
        "suspicious_exts":  [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"],
    },
}


def parse_sysmon_xml(filepath: str) -> list[dict]:
    """
    Parse Sysmon XML event log file.
    Supports .evtx exported to XML via wevtutil or PowerShell.
    """
    events = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(filepath)
        root = tree.getroot()

        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        for event_elem in root.findall(".//e:Event", ns):
            try:
                sys_elem  = event_elem.find("e:System", ns)
                data_elem = event_elem.find("e:EventData", ns)

                if sys_elem is None:
                    continue

                event_id_elem = sys_elem.find("e:EventID", ns)
                time_elem     = sys_elem.find("e:TimeCreated", ns)

                event_id  = int(event_id_elem.text) if event_id_elem is not None else 0
                timestamp = time_elem.get("SystemTime", "") if time_elem is not None else ""

                # Parse EventData fields
                data = {}
                if data_elem is not None:
                    for item in data_elem:
                        name = item.get("Name", "")
                        if name:
                            data[name] = item.text or ""

                events.append({
                    "EventID":   event_id,
                    "EventName": SYSMON_EVENT_IDS.get(event_id, f"Event {event_id}"),
                    "TimeCreated": timestamp,
                    **data,
                })
            except Exception:
                continue

    except Exception as e:
        logger.error(f"Sysmon XML parse error: {e}")

    return events


def parse_sysmon_json(filepath: str) -> list[dict]:
    """Parse Sysmon logs exported as JSON (e.g. via winlogbeat)."""
    events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Winlogbeat format
                    if "winlog" in obj:
                        wl = obj["winlog"]
                        events.append({
                            "EventID":    wl.get("event_id", 0),
                            "EventName":  SYSMON_EVENT_IDS.get(wl.get("event_id",0), ""),
                            "TimeCreated": obj.get("@timestamp", ""),
                            **wl.get("event_data", {}),
                        })
                    else:
                        events.append(obj)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error(f"Sysmon JSON parse error: {e}")
    return events


def analyze_sysmon_events(events: list[dict]) -> dict:
    """
    Analyse Sysmon events for TTPs.
    Returns structured alerts with MITRE mapping.
    """
    alerts = []
    process_tree = {}   # pid → {name, parent, cmdline}

    for ev in events:
        eid      = int(ev.get("EventID", 0))
        ts       = ev.get("TimeCreated", "")

        # ── Event ID 1: Process Creation ──────────────────────────────────
        if eid == 1:
            image       = (ev.get("Image") or "").lower()
            parent      = (ev.get("ParentImage") or "").lower()
            cmdline     = (ev.get("CommandLine") or "").lower()
            pid         = ev.get("ProcessId", "")
            parent_pid  = ev.get("ParentProcessId", "")

            process_tree[pid] = {
                "name": image, "parent": parent,
                "cmdline": cmdline, "ts": ts
            }

            # Suspicious parent → child chain (Living off the Land)
            parent_name = os.path.basename(parent)
            child_name  = os.path.basename(image)

            if any(p in parent for p in SYSMON_RULES[1]["suspicious_parents"]) and \
               any(c in image for c in SYSMON_RULES[1]["suspicious_children"]):
                alerts.append({
                    "type":     "Suspicious Process Spawn",
                    "severity": "critical",
                    "src":      parent_name,
                    "dst":      child_name,
                    "detail":   f"{parent_name} spawned {child_name}: {cmdline[:100]}",
                    "mitre":    "T1059",
                    "source":   "sysmon:event1",
                    "ts":       ts,
                })

            # Suspicious commandline indicators
            for indicator in SYSMON_RULES[1]["suspicious_cmdline"]:
                if indicator in cmdline:
                    alerts.append({
                        "type":     "Suspicious CommandLine",
                        "severity": "high",
                        "src":      child_name,
                        "dst":      "system",
                        "detail":   f"Indicator '{indicator}' in cmdline: {cmdline[:120]}",
                        "mitre":    "T1059.001" if "powershell" in image else "T1059",
                        "source":   "sysmon:event1",
                        "ts":       ts,
                    })
                    break

        # ── Event ID 3: Network Connection ────────────────────────────────
        elif eid == 3:
            image    = (ev.get("Image") or "").lower()
            dst_ip   = ev.get("DestinationIp", "")
            dst_port = int(ev.get("DestinationPort", 0) or 0)
            src_ip   = ev.get("SourceIp", "")

            if dst_port in SYSMON_RULES[3]["suspicious_ports"]:
                alerts.append({
                    "type":     "C2 Port Connection",
                    "severity": "critical",
                    "src":      f"{src_ip} ({os.path.basename(image)})",
                    "dst":      f"{dst_ip}:{dst_port}",
                    "detail":   f"Process {os.path.basename(image)} connected to known C2 port {dst_port}",
                    "mitre":    "T1071",
                    "source":   "sysmon:event3",
                    "ts":       ts,
                })

            # Process that shouldn't make network connections
            suspicious_net_procs = ["word", "excel", "powerpnt", "notepad", "calc"]
            if any(p in image for p in suspicious_net_procs):
                alerts.append({
                    "type":     "Unexpected Network Connection",
                    "severity": "high",
                    "src":      os.path.basename(image),
                    "dst":      f"{dst_ip}:{dst_port}",
                    "detail":   f"Office/system process making network connection",
                    "mitre":    "T1071",
                    "source":   "sysmon:event3",
                    "ts":       ts,
                })

        # ── Event ID 8: CreateRemoteThread (injection) ────────────────────
        elif eid == 8:
            source_img = ev.get("SourceImage", "")
            target_img = ev.get("TargetImage", "")
            alerts.append({
                "type":     "Process Injection",
                "severity": "critical",
                "src":      os.path.basename(source_img),
                "dst":      os.path.basename(target_img),
                "detail":   f"CreateRemoteThread: {source_img} → {target_img}",
                "mitre":    "T1055",
                "source":   "sysmon:event8",
                "ts":       ts,
            })

        # ── Event ID 11: File Created ──────────────────────────────────────
        elif eid == 11:
            target_fn = (ev.get("TargetFilename") or "").lower()
            image     = (ev.get("Image") or "").lower()

            in_sus_dir = any(d in target_fn for d in SYSMON_RULES[11]["suspicious_dirs"])
            has_sus_ext = any(target_fn.endswith(e) for e in SYSMON_RULES[11]["suspicious_exts"])

            if in_sus_dir and has_sus_ext:
                alerts.append({
                    "type":     "Suspicious File Drop",
                    "severity": "high",
                    "src":      os.path.basename(image),
                    "dst":      target_fn[-80:],
                    "detail":   f"Executable dropped in suspicious location: {target_fn[-80:]}",
                    "mitre":    "T1105",
                    "source":   "sysmon:event11",
                    "ts":       ts,
                })

    return {
        "total_events": len(events),
        "alerts":       alerts,
        "event_summary": {
            SYSMON_EVENT_IDS.get(eid, f"Event {eid}"): sum(
                1 for e in events if int(e.get("EventID",0)) == eid
            )
            for eid in SYSMON_EVENT_IDS
            if any(int(e.get("EventID",0)) == eid for e in events)
        },
        "process_tree": process_tree,
    }


def ingest_sysmon_file(filepath: str) -> dict:
    """Auto-detect format (XML or JSON) and parse Sysmon log file."""
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}

    ext = Path(filepath).suffix.lower()
    if ext in (".xml", ".evtx"):
        events = parse_sysmon_xml(filepath)
    else:
        events = parse_sysmon_json(filepath)

    if not events:
        return {"error": "No events parsed — check file format"}

    return analyze_sysmon_events(events)


# ══════════════════════════════════════════════════════════════════════════════
# CORRELATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

CORRELATION_RULES = [
    {
        "id":       "CORR-001",
        "name":     "C2 Beacon: DNS + Network",
        "sources":  ["zeek:dns", "sysmon:event3"],
        "pattern":  lambda alerts: (
            any(a["type"] in ("DNS Tunneling Indicator","DNS Beaconing") for a in alerts) and
            any(a["type"] == "C2 Port Connection" for a in alerts)
        ),
        "severity": "critical",
        "mitre":    "T1071.004",
        "description": "DNS beaconing + C2 port connection — likely active C2 communication",
    },
    {
        "id":       "CORR-002",
        "name":     "Lateral Movement: Process Spawn + Network",
        "sources":  ["sysmon:event1", "sysmon:event3"],
        "pattern":  lambda alerts: (
            any(a["type"] == "Suspicious Process Spawn" for a in alerts) and
            any(a["type"] == "Unexpected Network Connection" for a in alerts)
        ),
        "severity": "critical",
        "mitre":    "T1021",
        "description": "Suspicious process spawned and made network connection — lateral movement",
    },
    {
        "id":       "CORR-003",
        "name":     "Web Attack: HTTP Scan + Port Scan",
        "sources":  ["zeek:http", "zeek:conn"],
        "pattern":  lambda alerts: (
            any(a["type"] == "Suspicious User-Agent" for a in alerts) and
            any(a["type"] == "Port Scan" for a in alerts)
        ),
        "severity": "high",
        "mitre":    "T1595",
        "description": "Attack tool user-agent combined with port scanning — active recon",
    },
    {
        "id":       "CORR-004",
        "name":     "Malware Drop + Execution",
        "sources":  ["sysmon:event11", "sysmon:event1"],
        "pattern":  lambda alerts: (
            any(a["type"] == "Suspicious File Drop" for a in alerts) and
            any(a["type"] in ("Suspicious Process Spawn", "Suspicious CommandLine") for a in alerts)
        ),
        "severity": "critical",
        "mitre":    "T1204",
        "description": "File dropped in suspicious location and executed — malware execution",
    },
    {
        "id":       "CORR-005",
        "name":     "Data Exfiltration: Large Transfer + DNS Tunnel",
        "sources":  ["zeek:conn", "zeek:dns"],
        "pattern":  lambda alerts: (
            any(a["type"] == "Large Data Transfer" for a in alerts) and
            any(a["type"] in ("DNS Tunneling Indicator","Suspicious TLD") for a in alerts)
        ),
        "severity": "critical",
        "mitre":    "T1041",
        "description": "Large data transfer with DNS tunneling — data exfiltration likely",
    },
]


def run_correlation(zeek_results: dict, sysmon_results: dict) -> list[dict]:
    """
    Run correlation rules across Zeek and Sysmon alerts.
    Returns list of correlated high-confidence alerts.
    """
    all_alerts = (
        zeek_results.get("all_alerts", []) +
        sysmon_results.get("alerts", [])
    )

    correlated = []
    for rule in CORRELATION_RULES:
        try:
            if rule["pattern"](all_alerts):
                correlated.append({
                    "id":          rule["id"],
                    "name":        rule["name"],
                    "severity":    rule["severity"],
                    "mitre":       rule["mitre"],
                    "description": rule["description"],
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                    "supporting_alerts": [
                        a for a in all_alerts
                        if a.get("source") in rule["sources"]
                    ][:5],
                })
        except Exception as e:
            logger.error(f"Correlation rule {rule['id']} error: {e}")

    return correlated