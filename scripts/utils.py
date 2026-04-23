# scripts/utils.py

import logging
import socket
import ssl
import requests
from collections import Counter, defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, Raw, sniff

logger = logging.getLogger(__name__)

# ─── Nmap (optional) ──────────────────────────────────────────────────────────
import os, sys

_NMAP_WIN_PATHS = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
for _np in _NMAP_WIN_PATHS:
    if os.path.isdir(_np) and _np not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _np + os.pathsep + os.environ.get("PATH", "")

try:
    import nmap as _nmap_module
    _nmap_module.PortScanner()          # confirm binary reachable
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False
    logger.warning("Nmap binary not found – scans disabled.")

# ─── WHOIS (robust) ───────────────────────────────────────────────────────────
_whois_fn = None
try:
    import whois as _whois_mod
    for _attr in ("whois", "query", "lookup"):
        if hasattr(_whois_mod, _attr):
            _whois_fn = getattr(_whois_mod, _attr)
            break
    if _whois_fn is None:
        logger.warning("whois package installed but no usable function. "
                       "Fix: pip uninstall whois && pip install python-whois")
except ImportError:
    logger.warning("whois not installed. Run: pip install python-whois")

# ─── API KEY ──────────────────────────────────────────────────────────────────
try:
    from scripts.config import VIRUSTOTAL_API_KEY
except ImportError:
    try:
        from config import VIRUSTOTAL_API_KEY
    except ImportError:
        VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
        logger.warning("VIRUSTOTAL_API_KEY not found in config – using env var.")


# ══════════════════════════════════════════════════════════════════════════════
# SSL CHECK
# ══════════════════════════════════════════════════════════════════════════════

def ssl_check(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        ip = socket.gethostbyname(domain)

        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter", "")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        expired = not_after < datetime.utcnow()

        return {
            "expired": expired,
            "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S"),
            "hostname_match": True,
            "ip": ip,
        }

    except ssl.SSLCertVerificationError as e:
        return {"expired": False, "hostname_match": False,
                "error": f"Certificate verification failed: {e}"}
    except ConnectionRefusedError:
        return {"error": f"SSL check failed: port 443 refused on {domain}"}
    except Exception as e:
        logger.error(f"SSL check failed for {domain}: {e}")
        return {"error": f"SSL check failed: {e}"}


# ══════════════════════════════════════════════════════════════════════════════
# NMAP SCAN
# ══════════════════════════════════════════════════════════════════════════════

def nmap_scan(ip):
    if not NMAP_AVAILABLE:
        return {"error": ("Nmap binary not found. "
                          "Install from https://nmap.org/download.html "
                          "and add to system PATH, then restart.")}
    try:
        nm = _nmap_module.PortScanner()
        # -sT works without root/admin on Windows; -sS requires elevated privileges
        nm.scan(ip, arguments="-sT --open -p 1-1024")
        ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    if nm[host][proto][port]["state"] == "open":
                        ports.append({
                            "port": port,
                            "service": nm[host][proto][port].get("name", "unknown"),
                        })
        return {"ports": ports}
    except Exception as e:
        logger.error(f"Nmap scan failed for {ip}: {e}")
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL  (v2 domain report)
# ══════════════════════════════════════════════════════════════════════════════

def virustotal_lookup(domain, api_key=None):
    key = api_key or VIRUSTOTAL_API_KEY
    if not key or key == "YOUR_API_KEY_HERE":
        return "VirusTotal API key not configured"
    try:
        url = "https://www.virustotal.com/vtapi/v2/domain/report"
        resp = requests.get(url, params={"apikey": key, "domain": domain}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if data.get("response_code") == 1:
            detected = data.get("detected_urls", [])
            if detected:
                return f"Threats detected: {len(detected)} malicious URLs"
            return "No threats detected"
        return "VirusTotal lookup failed (no data)"
    except Exception as e:
        logger.error(f"VirusTotal error for {domain}: {e}")
        return f"VirusTotal error: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# WHOIS
# ══════════════════════════════════════════════════════════════════════════════

def whois_lookup(domain):
    if _whois_fn is None:
        return {"error": ("WHOIS unavailable. "
                          "Fix: pip uninstall whois && pip install python-whois")}
    try:
        w = _whois_fn(domain)
        if w is None:
            return {"error": "WHOIS returned no data"}

        def _val(v):
            if isinstance(v, list):
                return ", ".join(str(i) for i in v)
            return str(v) if v else "N/A"

        raw = w.__dict__ if hasattr(w, "__dict__") else dict(w)
        return {k: _val(v) for k, v in raw.items()
                if not k.startswith("_") and v not in (None, [], "")}
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# PARALLEL DOMAIN ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def parallel_domain_analysis(domain):
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            "SSL":        ex.submit(ssl_check,         domain),
            "VirusTotal": ex.submit(virustotal_lookup,  domain),
            "WHOIS":      ex.submit(whois_lookup,       domain),
        }
        return {k: f.result() for k, f in futures.items()}


# ══════════════════════════════════════════════════════════════════════════════
# PACKET ANALYSIS  ← fully rewritten to include all required fields
# ══════════════════════════════════════════════════════════════════════════════

# Suspicious payload signatures
_PAYLOAD_SIGS = {
    "sqlmap":       "SQLmap signature detected",
    "union select": "SQL Injection attempt detected",
    "<script":      "XSS payload detected",
    "malware":      "Malware signature detected",
    "/etc/passwd":  "Path traversal attempt detected",
    "cmd.exe":      "Command injection attempt detected",
    "powershell":   "PowerShell execution attempt detected",
}

# Well-known service ports for labelling
_SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def analyze_packets(packets):
    """
    Analyse a list of Scapy packets and return a comprehensive dict with:
      - protocol_distribution
      - traffic_direction  (inbound / outbound relative to RFC-1918 src)
      - packet_sizes
      - connection_states  (SYN / ACK / FIN / RST counts)
      - top_talkers        (sources / destinations, top 10 each)
      - port_usage         (source_ports / dest_ports, top 10 each)
      - suspicious / details / payload_suspicion
    """
    try:
        proto_dist   = {"TCP": 0, "UDP": 0, "Other": 0}
        pkt_sizes    = []
        direction    = {"inbound": 0, "outbound": 0}
        tcp_states   = {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0}
        src_ips      = Counter()
        dst_ips      = Counter()
        src_ports    = Counter()
        dst_ports    = Counter()
        suspicious   = False
        details      = []
        payload_sus  = []

        import ipaddress

        def _is_private(ip_str):
            try:
                return ipaddress.ip_address(ip_str).is_private
            except ValueError:
                return False

        for pkt in packets:
            if IP not in pkt:
                continue

            src = pkt[IP].src
            dst = pkt[IP].dst
            size = len(pkt)
            pkt_sizes.append(size)

            # Protocol
            if TCP in pkt:
                proto_dist["TCP"] += 1
                flags = pkt[TCP].flags
                if flags & 0x02:  tcp_states["SYN"] += 1
                if flags & 0x10:  tcp_states["ACK"] += 1
                if flags & 0x01:  tcp_states["FIN"] += 1
                if flags & 0x04:  tcp_states["RST"] += 1
                src_ports[pkt[TCP].sport] += 1
                dst_ports[pkt[TCP].dport] += 1
            elif UDP in pkt:
                proto_dist["UDP"] += 1
                src_ports[pkt[UDP].sport] += 1
                dst_ports[pkt[UDP].dport] += 1
            else:
                proto_dist["Other"] += 1

            # Direction: outbound = private src, inbound = public src
            if _is_private(src):
                direction["outbound"] += 1
            else:
                direction["inbound"] += 1

            src_ips[src] += 1
            dst_ips[dst] += 1

            # Payload inspection
            if Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore").lower()
                    for sig, msg in _PAYLOAD_SIGS.items():
                        if sig in payload and msg not in payload_sus:
                            suspicious = True
                            payload_sus.append(msg)
                except Exception:
                    pass

        # Port scan heuristic: single source hitting many distinct dst ports
        if len(dst_ports) > 50:
            suspicious = True
            details.append(f"Possible port scan: {len(dst_ports)} distinct destination ports")

        # High packet rate to single dest
        if dst_ips and dst_ips.most_common(1)[0][1] > 500:
            top_dst, top_count = dst_ips.most_common(1)[0]
            suspicious = True
            details.append(f"High packet rate to {top_dst}: {top_count} packets")

        # Build top-10 dicts with service labels for ports
        def _top10(counter):
            return dict(counter.most_common(10))

        def _top10_ports(counter):
            return {
                f"{p} ({_SERVICE_PORTS.get(p, 'unknown')})": c
                for p, c in counter.most_common(10)
            }

        return {
            "suspicious":           suspicious,
            "details":              details,
            "payload_suspicion":    payload_sus,
            "protocol_distribution": proto_dist,
            "traffic_direction":    direction,
            "packet_sizes":         pkt_sizes,
            "connection_states":    tcp_states,
            "top_talkers": {
                "sources":      _top10(src_ips),
                "destinations": _top10(dst_ips),
            },
            "port_usage": {
                "source_ports": _top10_ports(src_ports),
                "dest_ports":   _top10_ports(dst_ports),
            },
        }

    except Exception as e:
        logger.error(f"Packet analysis failed: {e}")
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# LIVE CAPTURE
# ══════════════════════════════════════════════════════════════════════════════

def _detect_best_interface():
    """
    Find the interface that actually has live traffic by doing a 1-second
    probe on each candidate. Returns the name of the best interface.
    Priority: VPN > Wi-Fi > Ethernet > first with packets > first non-junk.
    """
    from scapy.all import get_working_ifaces
    try:
        ifaces = get_working_ifaces()
        descs  = {i.name: (i.description or "").lower() for i in ifaces}
        skip   = ("wan miniport", "loopback", "bluetooth", "pseudo")

        # Build priority-ordered candidate list
        vpn, wifi, eth, other = [], [], [], []
        for name, desc in descs.items():
            if any(k in desc for k in skip):
                continue
            if any(k in desc for k in ("protonvpn", "wireguard", "vpn",
                                        "nordvpn", "openvpn")):
                vpn.append(name)
            elif "wi-fi" in desc or "wireless" in desc or "wifi" in name.lower():
                wifi.append(name)
            elif "ethernet" in desc and "vmware" not in desc and "virtual" not in desc:
                eth.append(name)
            else:
                other.append(name)

        candidates = vpn + wifi + eth + other

        # Quick 1-second probe — return first interface that yields packets
        for iface in candidates:
            try:
                test = sniff(iface=iface, timeout=1, count=5)
                if test:
                    logger.info(f"Interface probe: {iface} yielded {len(test)} packets")
                    return iface
            except Exception as e:
                logger.debug(f"Interface probe failed for {iface}: {e}")

        # No probe succeeded — return highest priority candidate anyway
        return candidates[0] if candidates else "Wi-Fi"

    except Exception as e:
        logger.error(f"Interface detection failed: {e}")
        return "Wi-Fi"


def capture_and_analyze_packets(duration=10, interface=None, target_ip=None):
    """
    Capture packets for `duration` seconds on the best available interface.
    If interface is not specified, auto-detects via _detect_best_interface().
    BPF filter: 'host <ip> and tcp' when target_ip is given.
    """
    try:
        # Auto-detect interface if not provided
        iface = interface or _detect_best_interface()
        logger.info(f"Capturing on interface: {iface}")

        kwargs = {"timeout": duration, "iface": iface}
        if target_ip:
            kwargs["filter"] = f"host {target_ip} and tcp"

        packets = sniff(**kwargs)
        logger.info(f"Captured {len(packets)} packets "
                    f"(iface={iface}, target={target_ip})")
        return analyze_packets(packets)
    except Exception as e:
        logger.error(f"Live capture failed: {e}")
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# WEB FLAW CHECK
# ══════════════════════════════════════════════════════════════════════════════

def check_flaws(domain):
    """
    Light HTTP probe for common web vulnerabilities in response headers/body.
    Returns a list of finding strings, or ["No major flaws detected"].
    """
    flaws = []
    try:
        resp = requests.get(f"https://{domain}", timeout=8,
                            headers={"User-Agent": "Mozilla/5.0"})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        text = resp.text.lower()

        # Header checks
        if "x-frame-options" not in headers:
            flaws.append("Missing X-Frame-Options header (clickjacking risk)")
        if "x-content-type-options" not in headers:
            flaws.append("Missing X-Content-Type-Options header")
        if "strict-transport-security" not in headers:
            flaws.append("Missing HSTS header")
        if "content-security-policy" not in headers:
            flaws.append("Missing Content-Security-Policy header")

        # Body checks (crude heuristics — not a real scanner)
        if "xss" in text or "<script" in resp.text[:5000].lower():
            flaws.append("Potential XSS indicators in response body")
        if any(s in text for s in ("sql syntax", "mysql error", "ora-", "sqlite")):
            flaws.append("Potential SQL error disclosure")

    except requests.exceptions.SSLError:
        flaws.append("SSL/TLS error on HTTPS connection")
    except Exception as e:
        logger.warning(f"Flaw check failed for {domain}: {e}")
        return [f"Flaw check failed: {e}"]

    return flaws if flaws else ["No major flaws detected"]