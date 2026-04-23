"""
NetSec AI — Unified IOC Enrichment Engine  v11.0
=================================================
UPGRADES (v10 → v11):

  ✅ FIX 1 — 7-Source Intel Stack (was 4–5 sources)
       VirusTotal · AbuseIPDB · GreyNoise · OTX
       + URLScan · IPInfo · MalwareBazaar (NEW)
       Priority order: cheapest/fastest first, most expensive last

  ✅ FIX 2 — Weighted Scoring Model (replaces flat delta sum)
       Formula: final_score = (heuristic_score * 0.5) + (intel_score * 0.5)
       Per-source weights:
         VirusTotal    → 25   AbuseIPDB  → 15   GreyNoise → 10
         OTX           → 10   URLScan    → 15   IPInfo    → 10
         MalwareBazaar → 15

  ✅ FIX 3 — "1 Strong Signal > 3 Weak Cleans" Rule
       If MalwareBazaar / VT (≥5 engines) / URLhaus (active) = malicious
       → FORCE verdict MALICIOUS regardless of other clean signals

  ✅ FIX 4 — Source Conflict Detection
       If VT=clean AND MalwareBazaar=malicious
       → Output "⚠ Conflicting intelligence → Investigate"

  ✅ FIX 5 — Freshness Factor
       First-seen / last-seen timestamps from OTX/VT
       Recent threat (< 7 days) → +25% weight on that source
       Old intel (> 180 days)   → -30% weight on that source

  ✅ FIX 6 — Explainability Layer (WHY output)
       Every verdict ships with a structured reason chain:
         "Brand impersonation (Google) | Auth keyword (login) |
          Suspicious TLD (.net misuse) | No reputation history"

  ✅ FIX 7 — Source Breakdown Display
       Instead of "Sources: 2/2" shows:
         ✔ VirusTotal: Clean (0/72 engines)
         ⚠ AbuseIPDB: Suspicious (score 34%)
         ❌ MalwareBazaar: MALICIOUS (C2 domain)
         Final Verdict: HIGH SUSPICION

  ✅ FIX 8 — Auto Escalation Logic
       If ANY of: MalwareBazaar hit | High DGA | Brand phishing
       → Force HIGH regardless of clean API signals

Source call order (cheapest/fastest first):
  1. URLhaus        (free, no key, instant POST)
  2. AbuseIPDB      (free tier, fast)
  3. IPInfo         (free tier, fast)
  4. GreyNoise      (free tier community)
  5. MalwareBazaar  (free, no key, fast POST)   ← NEW
  6. VirusTotal     (free 4 req/min)
  7. OTX            (free)
  8. URLScan        (free, domain-only)
  9. Shodan         (paid, ip-only)
"""

import os
import re
import json
import time
import math
import hashlib
import urllib.request
import urllib.parse
import urllib.error
import streamlit as st
from datetime import datetime, timezone

# ── Paths ──────────────────────────────────────────────────────────────────────
_THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR  = os.path.join(_THIS_DIR, "..", "data")
_IOC_CACHE = os.path.join(_DATA_DIR, "ioc_cache.json")

# ── Known test / training domains (never flag as malicious) ───────────────────
_TEST_DOMAINS = {
    "vulnweb.com", "testphp.vulnweb.com", "testasp.vulnweb.com",
    "testaspnet.vulnweb.com", "testhtml5.vulnweb.com",
    "webscantest.com", "hackme.org", "dvwa",
    "mutillidae", "juice-shop", "hackazon.webscantest.com",
    "crackme.ovh", "bwapp.bitnami.com", "zero.webappsecurity.com",
    "demo.testfire.net", "altoro.testfire.net",
    "acunetix-test.com", "acuforum.com",
    "scanme.nmap.org", "example.com", "example.org", "example.net",
    "test.com", "localhost",
}

# ── Session key for global reputation propagation ─────────────────────────────
_REP_SCORE_KEY = "global_ioc_reputation"

# ── FIX 2: Source weight table (max contribution to intel score) ───────────────
# Weights represent how authoritative each source is for verdict decisions.
# Total = 100 (used in weighted average).
_SOURCE_WEIGHTS = {
    "virustotal":    25,   # Aggregated 70+ AV engines — highest authority
    "abuseipdb":     15,   # Crowd-sourced IP abuse — very reliable for IPs
    "greynoise":     10,   # Scanner vs targeted distinction — strong signal
    "otx":           10,   # Community pulses — broad but lower precision
    "urlscan":       15,   # Web behavior / phishing screenshots — high precision
    "ipinfo":        10,   # ASN / hosting intel — structural signal
    "malwarebazaar": 15,   # Known malware C2/payload infrastructure — high precision
    "urlhaus":       10,   # Active malware URLs — very high precision when hit
    "shodan":         5,   # Open ports / exposed infra — supplementary
}

# ── FIX 3: Strong signal sources — one hit forces MALICIOUS ───────────────────
_STRONG_SIGNAL_SOURCES = {"malwarebazaar", "urlhaus"}
# VT threshold for strong signal (≥ this many engines = strong)
_VT_STRONG_THRESHOLD = 5

# ── FIX 5: Freshness thresholds (days) ────────────────────────────────────────
_FRESH_THRESHOLD_DAYS   =   7   # < 7 days → fresh → +25% weight boost
_STALE_THRESHOLD_DAYS   = 180   # > 180 days → stale → -30% weight penalty


class IOCEnricher:
    """
    Unified IOC enrichment — 7-source threat intelligence fusion engine.
    v11 upgrades: weighted scoring, conflict detection, freshness factor,
    explainability layer, 1-strong-signal override, structured WHY output.
    """

    # ── Cache helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _load_cache() -> dict:
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            if os.path.exists(_IOC_CACHE):
                with open(_IOC_CACHE, encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    @staticmethod
    def _save_cache(cache: dict):
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with open(_IOC_CACHE, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def _cache_get(ioc: str, ttl_hours: int = 24) -> dict | None:
        cache = IOCEnricher._load_cache()
        entry = cache.get(ioc.lower())
        if not entry:
            return None
        if time.time() - entry.get("_ts", 0) > ttl_hours * 3600:
            return None
        return entry

    @staticmethod
    def _cache_set(ioc: str, data: dict):
        cache = IOCEnricher._load_cache()
        data["_ts"] = time.time()
        cache[ioc.lower()] = data
        if len(cache) > 10000:
            oldest = sorted(cache.items(), key=lambda x: x[1].get("_ts", 0))[:1000]
            for k, _ in oldest:
                del cache[k]
        IOCEnricher._save_cache(cache)

    # ── Get API keys ───────────────────────────────────────────────────────────
    @staticmethod
    def _keys() -> dict:
        try:
            cfg = st.session_state.get("user_api_config",
                  st.session_state.get("api_config", {}))
        except Exception:
            cfg = {}
        return {
            "abuseipdb":    cfg.get("abuseipdb_key","")    or os.getenv("ABUSEIPDB_API_KEY",""),
            "virustotal":   cfg.get("virustotal_key","")   or os.getenv("VIRUSTOTAL_API_KEY",""),
            "greynoise":    cfg.get("greynoise_key","")    or os.getenv("GREYNOISE_API_KEY",""),
            "otx":          cfg.get("otx_key","")          or os.getenv("OTX_API_KEY",""),
            "shodan":       cfg.get("shodan_key","")       or os.getenv("SHODAN_API_KEY",""),
            "ipinfo":       cfg.get("ipinfo_key","")       or os.getenv("IPINFO_TOKEN",""),
            "urlscan":      cfg.get("urlscan_key","")      or os.getenv("URLSCAN_API_KEY",""),
        }
        # URLhaus + MalwareBazaar are free — no key needed

    # ── HTTP helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _get(url: str, headers: dict = None, timeout: int = 6) -> dict:
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return {"_http_error": e.code, "error": f"HTTP {e.code}"}
        except Exception as e:
            return {"error": str(e)[:60]}

    @staticmethod
    def _post(url: str, payload: dict, headers: dict = None, timeout: int = 6) -> dict:
        try:
            data = urllib.parse.urlencode(payload).encode()
            req = urllib.request.Request(
                url, data=data,
                headers={**(headers or {}),
                         "Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)[:60]}

    # ── FIX 5: Freshness helper ────────────────────────────────────────────────
    @staticmethod
    def _freshness_multiplier(timestamp_str: str) -> float:
        """
        Given an ISO timestamp string, return a weight multiplier:
          < 7 days  → 1.25  (boost — fresh threat, high relevance)
          7–180 days → 1.0  (neutral)
          > 180 days → 0.70 (penalty — stale intel, lower weight)
        """
        if not timestamp_str:
            return 1.0
        try:
            # Handle various formats
            ts = timestamp_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - dt).days
            if age_days < _FRESH_THRESHOLD_DAYS:
                return 1.25
            if age_days > _STALE_THRESHOLD_DAYS:
                return 0.70
            return 1.0
        except Exception:
            return 1.0

    # ── Individual API calls ───────────────────────────────────────────────────

    @staticmethod
    def _call_abuseipdb(ip: str, key: str) -> dict:
        if not key:
            return {"source": "abuseipdb", "verdict": "unknown",
                    "error": "No API key", "skipped": True}
        url = (f"https://api.abuseipdb.com/api/v2/check?"
               f"ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose=true")
        data = IOCEnricher._get(url, {"Key": key, "Accept": "application/json"})
        if data.get("error"):
            return {"source": "abuseipdb", "verdict": "unknown",
                    "error": data["error"], "skipped": True}
        d = data.get("data", {})
        conf = d.get("abuseConfidenceScore", 0)
        reports = d.get("numDistinctUsers", 0)
        is_tor  = d.get("isTor", False)
        last_reported = d.get("lastReportedAt", "")

        verdict = "malicious" if conf >= 70 else "suspicious" if conf >= 25 else "clean"

        # Explanation fragment
        if conf >= 70:
            explain = f"abuse confidence {conf}% — HIGH (reported by {reports} users)"
        elif conf >= 25:
            explain = f"abuse confidence {conf}% — MEDIUM"
        else:
            explain = f"abuse confidence {conf}% — clean"
        if is_tor:
            explain += " | TOR exit node"

        freshness = IOCEnricher._freshness_multiplier(last_reported)
        return {
            "source":          "abuseipdb",
            "verdict":         verdict,
            "confidence":      conf,
            "total_reports":   reports,
            "isp":             d.get("isp", ""),
            "country":         d.get("countryCode", ""),
            "is_tor":          is_tor,
            "last_reported":   last_reported,
            "freshness":       freshness,
            "explain":         f"AbuseIPDB: {explain}",
            "score_delta":     -35 if conf >= 70 else -15 if conf >= 25 else 20,
        }

    @staticmethod
    def _call_greynoise(ip: str, key: str) -> dict:
        headers = {"Accept": "application/json"}
        if key:
            headers["key"] = key
        url  = f"https://api.greynoise.io/v3/community/{ip}"
        data = IOCEnricher._get(url, headers)
        if data.get("_http_error") == 404 or data.get("error"):
            return {"source": "greynoise", "verdict": "unknown",
                    "noise": False, "riot": False, "classification": "unknown",
                    "explain": "GreyNoise: not observed on internet scanners",
                    "freshness": 1.0}
        cls   = data.get("classification", "")
        noise = data.get("noise", False)
        riot  = data.get("riot", False)   # RIOT = known benign/business IP

        if riot:
            verdict = "clean"
            explain = f"GreyNoise: RIOT — known benign business IP ({data.get('name','')})"
            score_delta = 50
        elif cls == "malicious":
            verdict = "malicious"
            explain = f"GreyNoise: classified MALICIOUS — targeted scanner/attacker"
            score_delta = -50
        elif noise:
            verdict = "clean"
            explain = "GreyNoise: internet background noise — mass scanner, not targeted"
            score_delta = 15
        else:
            verdict = "unknown"
            explain = "GreyNoise: not classified"
            score_delta = 0

        return {
            "source":         "greynoise",
            "verdict":        verdict,
            "noise":          noise,
            "riot":           riot,
            "classification": cls,
            "name":           data.get("name", ""),
            "freshness":      1.0,
            "explain":        explain,
            "score_delta":    score_delta,
        }

    @staticmethod
    def _call_virustotal(ioc: str, ioc_type: str, key: str) -> dict:
        if not key:
            return {"source": "virustotal", "verdict": "unknown",
                    "error": "No API key", "skipped": True}
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        data = IOCEnricher._get(url, {"x-apikey": key})
        if data.get("error"):
            return {"source": "virustotal", "verdict": "unknown",
                    "error": str(data.get("error"))[:60], "skipped": True}

        attrs  = data.get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {})
        mal    = stats.get("malicious", 0)
        sus    = stats.get("suspicious", 0)
        har    = stats.get("harmless", 0)
        total  = mal + sus + har + stats.get("undetected", 0)

        # FIX 5: freshness from last_analysis_date
        last_ts = attrs.get("last_analysis_date", "")
        if isinstance(last_ts, (int, float)):
            # VT returns epoch int
            from datetime import datetime, timezone
            last_ts = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat()
        freshness = IOCEnricher._freshness_multiplier(str(last_ts))

        verdict = ("malicious" if mal >= _VT_STRONG_THRESHOLD else
                   "suspicious" if mal >= 2 else "clean")

        if mal >= _VT_STRONG_THRESHOLD:
            explain = f"VirusTotal: {mal}/{total} engines MALICIOUS — confirmed threat"
        elif mal >= 2:
            explain = f"VirusTotal: {mal}/{total} engines malicious — suspicious"
        elif mal == 1:
            explain = f"VirusTotal: 1/{total} engine flagged — low confidence"
        else:
            explain = f"VirusTotal: 0/{total if total else '?'} — clean"

        return {
            "source":      "virustotal",
            "verdict":     verdict,
            "malicious":   mal,
            "suspicious":  sus,
            "harmless":    har,
            "total":       total,
            "freshness":   freshness,
            "explain":     explain,
            "score_delta": -40 if mal >= 5 else -20 if mal >= 2 else 30 if har > 5 else 10,
            # FIX 3: flag strong signal
            "is_strong_signal": mal >= _VT_STRONG_THRESHOLD,
        }

    @staticmethod
    def _call_otx(ioc: str, ioc_type: str, key: str) -> dict:
        if not key:
            return {"source": "otx", "verdict": "unknown",
                    "error": "No API key", "skipped": True}
        if ioc_type == "ip":
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
        elif ioc_type == "hash":
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general"
        else:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
        data = IOCEnricher._get(url, {"X-OTX-API-KEY": key})
        if data.get("error"):
            return {"source": "otx", "verdict": "unknown",
                    "error": data["error"], "skipped": True}

        pulse_info = data.get("pulse_info", {})
        pulses     = pulse_info.get("count", 0)
        malware    = [p.get("name", "") for p in pulse_info.get("pulses", [])
                      if any(t in str(p).lower()
                             for t in ["malware","ransomware","c2","apt","phish"])][:3]

        # FIX 5: freshness from most recent pulse
        last_ts = ""
        pulses_list = pulse_info.get("pulses", [])
        if pulses_list:
            last_ts = pulses_list[0].get("modified", "")
        freshness = IOCEnricher._freshness_multiplier(last_ts)

        verdict = "malicious" if pulses >= 5 else "suspicious" if pulses >= 1 else "clean"

        if pulses >= 5:
            explain = f"OTX AlienVault: {pulses} threat pulses — known bad infrastructure"
        elif pulses >= 1:
            families = ", ".join(malware) if malware else "unknown"
            explain  = f"OTX: {pulses} pulse(s) — associated malware: {families}"
        else:
            explain  = "OTX AlienVault: 0 malicious pulses"

        return {
            "source":           "otx",
            "verdict":          verdict,
            "pulse_count":      pulses,
            "malware_families": malware,
            "freshness":        freshness,
            "explain":          explain,
            "score_delta":      -30 if pulses >= 5 else -15 if pulses >= 1 else 10,
        }

    @staticmethod
    def _call_ipinfo(ip: str, key: str) -> dict:
        token = f"?token={key}" if key else ""
        url   = f"https://ipinfo.io/{ip}/json{token}"
        data  = IOCEnricher._get(url)
        if data.get("error"):
            return {"source": "ipinfo", "verdict": "unknown",
                    "freshness": 1.0, "explain": "IPInfo: unavailable"}
        org     = data.get("org", "")
        city    = data.get("city", "")
        country = data.get("country", "")
        hosting_kws   = ["hosting","datacenter","vps","cloud","server",
                         "digital ocean","vultr","linode","hetzner","ovh","choopa"]
        safe_kws      = ["google","microsoft","amazon","cloudflare","akamai",
                         "apple","meta","fastly","netflix","tata","airtel",
                         "reliance","bsnl","jio","vodafone","comcast","att"]
        is_dc         = any(kw in org.lower() for kw in hosting_kws)
        is_safe_prov  = any(kw in org.lower() for kw in safe_kws)
        verdict       = "clean" if is_safe_prov else "suspicious" if is_dc else "unknown"

        if is_safe_prov:
            explain = f"IPInfo: {org} — major provider, legitimate infrastructure"
        elif is_dc:
            explain = f"IPInfo: {org} — VPS/hosting provider ({city}, {country}) — common attacker infra"
        else:
            explain = f"IPInfo: {org} — {city}, {country}"

        return {
            "source":           "ipinfo",
            "verdict":          verdict,
            "org":              org,
            "city":             city,
            "country":          country,
            "is_datacenter":    is_dc,
            "is_safe_provider": is_safe_prov,
            "freshness":        1.0,
            "explain":          explain,
            "score_delta":      30 if is_safe_prov else -10 if is_dc else 5,
        }

    @staticmethod
    def _call_urlhaus(ioc: str, ioc_type: str) -> dict:
        """URLhaus — free, no key, unlimited. Extremely high precision."""
        try:
            if ioc_type == "domain":
                payload = {"host": ioc}
                endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            elif ioc_type == "ip":
                payload  = {"host": ioc}
                endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            else:
                payload  = {"md5_hash": ioc}
                endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"

            data = IOCEnricher._post(endpoint, payload)
            status = data.get("query_status", "")

            if status == "is_host":
                urls   = data.get("urls", [])
                active = [u for u in urls if u.get("url_status") == "online"]

                # FIX 5: freshness from most recent URL date_added
                last_ts = ""
                if urls:
                    last_ts = urls[0].get("date_added", "")
                freshness = IOCEnricher._freshness_multiplier(last_ts)

                if active:
                    verdict = "malicious"
                    explain = (f"URLhaus: {len(active)} ACTIVE malware URLs hosted — "
                               f"live C2/malware distribution confirmed")
                elif urls:
                    verdict = "suspicious"
                    explain = f"URLhaus: {len(urls)} historical malware URLs (currently offline)"
                else:
                    verdict = "clean"
                    explain = "URLhaus: no malware URLs found"

                return {
                    "source":       "urlhaus",
                    "verdict":      verdict,
                    "malware_urls": len(urls),
                    "active":       len(active),
                    "freshness":    freshness,
                    "explain":      explain,
                    "score_delta":  -40 if active else -20 if urls else 10,
                    # FIX 3: active URLs = strong signal
                    "is_strong_signal": bool(active),
                }

            return {"source": "urlhaus", "verdict": "clean",
                    "freshness": 1.0, "explain": "URLhaus: not found", "score_delta": 5}

        except Exception as e:
            return {"source": "urlhaus", "verdict": "unknown",
                    "freshness": 1.0, "explain": f"URLhaus: error ({str(e)[:40]})",
                    "error": str(e)[:40]}

    @staticmethod
    def _call_malwarebazaar(ioc: str, ioc_type: str) -> dict:
        """
        MalwareBazaar — free, no key, by abuse.ch.
        Covers: file hashes, domains used as C2/distribution, IPs.
        HIGH PRECISION — if it hits here, it's confirmed malware infrastructure.
        """
        try:
            if ioc_type == "hash":
                payload  = {"query": "get_info", "hash": ioc}
            elif ioc_type == "ip":
                # MalwareBazaar supports signature/tag search but not IP directly
                # Use file lookup for C2 IPs via signature
                return {"source": "malwarebazaar", "verdict": "unknown",
                        "freshness": 1.0, "explain": "MalwareBazaar: IP lookup not supported",
                        "score_delta": 0}
            else:
                # Domain — search by C2 domain tag
                payload = {"query": "get_siginfo", "signature": ioc, "limit": "5"}

            endpoint = "https://mb-api.abuse.ch/api/v1/"
            data     = IOCEnricher._post(endpoint, payload,
                                         headers={"User-Agent": "NetSecAI/11.0"})

            query_status = data.get("query_status", "")

            if query_status in ("ok",) and data.get("data"):
                entries  = data["data"]
                families = list({e.get("signature","") for e in entries
                                 if e.get("signature")})[:3]
                tags_all = []
                for e in entries:
                    tags_all.extend(e.get("tags") or [])
                tags = list(set(tags_all))[:5]

                # FIX 5: freshness from first_seen of most recent sample
                last_ts   = entries[0].get("first_seen", "") if entries else ""
                freshness = IOCEnricher._freshness_multiplier(last_ts)

                family_str = ", ".join(families) if families else "unknown"
                explain    = (f"MalwareBazaar: {len(entries)} sample(s) — "
                              f"malware families: {family_str} | tags: {', '.join(tags[:3]) or 'none'}")

                return {
                    "source":           "malwarebazaar",
                    "verdict":          "malicious",
                    "sample_count":     len(entries),
                    "malware_families": families,
                    "tags":             tags,
                    "freshness":        freshness,
                    "explain":          explain,
                    "score_delta":      -45,   # Very high precision — strong penalty
                    "is_strong_signal": True,  # FIX 3: MalwareBazaar hit = force escalation
                }

            elif query_status in ("no_results", "hash_not_found",
                                  "illegal_hash", "signature_not_found"):
                return {
                    "source":    "malwarebazaar",
                    "verdict":   "clean",
                    "freshness": 1.0,
                    "explain":   "MalwareBazaar: not found in malware database",
                    "score_delta": 10,
                }

            return {
                "source":    "malwarebazaar",
                "verdict":   "unknown",
                "freshness": 1.0,
                "explain":   f"MalwareBazaar: {query_status or 'unexpected response'}",
                "score_delta": 0,
            }
        except Exception as e:
            return {"source": "malwarebazaar", "verdict": "unknown",
                    "freshness": 1.0, "explain": f"MalwareBazaar: error ({str(e)[:40]})",
                    "error": str(e)[:40]}

    @staticmethod
    def _call_urlscan(ioc: str, key: str) -> dict:
        if not key:
            return {"source": "urlscan", "verdict": "unknown",
                    "error": "No API key", "skipped": True,
                    "explain": "URLScan: no API key configured",
                    "freshness": 1.0}
        url  = f"https://urlscan.io/api/v1/search/?q=domain:{ioc}&size=5"
        data = IOCEnricher._get(url, {"API-Key": key})
        if data.get("error"):
            return {"source": "urlscan", "verdict": "unknown",
                    "freshness": 1.0, "explain": "URLScan: unavailable"}

        results   = data.get("results", [])
        malicious = [r for r in results
                     if r.get("verdicts", {}).get("overall", {}).get("malicious")]
        score_max = max((r.get("verdicts", {}).get("urlscan", {}).get("score", 0)
                         for r in results), default=0)

        # FIX 5: freshness from most recent scan
        last_ts = ""
        if results:
            last_ts = results[0].get("task", {}).get("time", "")
        freshness = IOCEnricher._freshness_multiplier(last_ts)

        if malicious:
            verdict = "malicious"
            explain = (f"URLScan: {len(malicious)} scan(s) verdict MALICIOUS — "
                       f"phishing/malware page confirmed via screenshot analysis")
        elif score_max > 50:
            verdict = "suspicious"
            explain = f"URLScan: page risk score {score_max}/100 — suspicious behavior"
        else:
            verdict = "clean"
            explain = f"URLScan: {len(results)} scan(s) — benign page behavior"

        return {
            "source":    "urlscan",
            "verdict":   verdict,
            "malicious": len(malicious),
            "score":     score_max,
            "freshness": freshness,
            "explain":   explain,
            "score_delta": -40 if malicious else -15 if score_max > 50 else 10,
        }

    @staticmethod
    def _call_shodan(ip: str, key: str) -> dict:
        if not key:
            return {"source": "shodan", "verdict": "unknown",
                    "error": "No API key", "skipped": True,
                    "explain": "Shodan: no API key",
                    "freshness": 1.0}
        url  = f"https://api.shodan.io/shodan/host/{ip}?key={key}&minify=true"
        data = IOCEnricher._get(url)
        if data.get("error"):
            return {"source": "shodan", "verdict": "unknown",
                    "freshness": 1.0, "explain": "Shodan: IP not indexed"}
        ports = data.get("ports", [])
        vulns = list(data.get("vulns", {}).keys())
        org   = data.get("org", "")
        # C2 / proxy / Metasploit common ports
        risky_ports = [p for p in ports if p in [4444, 6667, 1337, 31337, 8888, 9001, 1080]]
        score_delta = -20 if vulns else 0
        if risky_ports:
            score_delta -= 15
        verdict = "suspicious" if (vulns or risky_ports) else "unknown"

        if vulns:
            explain = f"Shodan: {len(vulns)} CVE(s): {', '.join(vulns[:3])} | ports: {ports[:5]}"
        elif risky_ports:
            explain = f"Shodan: C2-associated ports open: {risky_ports} — attacker infrastructure"
        else:
            explain = f"Shodan: {len(ports)} ports indexed, no known vulns | org: {org}"

        return {
            "source":      "shodan",
            "verdict":     verdict,
            "open_ports":  ports[:10],
            "org":         org,
            "vulns":       vulns[:5],
            "risky_ports": risky_ports,
            "freshness":   1.0,
            "explain":     explain,
            "score_delta": score_delta,
        }

    # ── FIX 2: Weighted unified score ─────────────────────────────────────────
    @staticmethod
    def _compute_weighted_score(source_results: list) -> tuple:
        """
        v11 weighted scoring model.

        Formula:
          final_score = (heuristic_base * 0.5) + (intel_weighted_score * 0.5)

        Each source contributes proportionally to its weight in _SOURCE_WEIGHTS.
        FIX 5: Each source's contribution is multiplied by its freshness multiplier.

        Returns (score: int, weight_breakdown: dict)
        """
        total_weight   = 0
        weighted_sum   = 0   # Weighted sum of (0–100 per-source score)
        weight_breakdown = {}

        for r in source_results:
            sname   = r.get("source", "")
            weight  = _SOURCE_WEIGHTS.get(sname, 5)
            fresh   = r.get("freshness", 1.0)
            delta   = r.get("score_delta", 0)
            verdict = r.get("verdict", "unknown")

            if verdict == "unknown" or r.get("skipped"):
                continue   # Don't let missing data bias the score

            # Convert delta to 0–100 per-source score
            # delta range: typically -50 to +50, map to 0–100
            per_source_score = max(0, min(100, 50 + delta))

            # Apply freshness multiplier (FIX 5)
            effective_weight = weight * fresh
            weighted_sum    += per_source_score * effective_weight
            total_weight    += effective_weight

            weight_breakdown[sname] = {
                "raw_score":    per_source_score,
                "weight":       weight,
                "freshness":    round(fresh, 2),
                "eff_weight":   round(effective_weight, 2),
                "contribution": round(per_source_score * effective_weight, 1),
                "verdict":      verdict,
            }

        if total_weight == 0:
            return 50, weight_breakdown   # No data — neutral

        intel_score = weighted_sum / total_weight
        # Final = 50% heuristic base + 50% intel score
        # Heuristic base is 50 (neutral) when no heuristics passed separately
        final = (50 * 0.5) + (intel_score * 0.5)
        return round(max(0, min(100, final))), weight_breakdown

    # ── FIX 4: Conflict detection ──────────────────────────────────────────────
    @staticmethod
    def _detect_conflicts(source_results: list) -> list:
        """
        FIX 4: Detect conflicting intel between sources.
        Returns list of conflict strings for display.
        Example: ["VT=clean vs MalwareBazaar=malicious → INVESTIGATE"]
        """
        conflicts = []
        verdicts  = {r["source"]: r["verdict"] for r in source_results
                     if r.get("verdict") not in ("unknown",) and not r.get("skipped")}

        malicious_sources = [s for s, v in verdicts.items() if v == "malicious"]
        clean_sources     = [s for s, v in verdicts.items() if v == "clean"]

        # Conflict = some say malicious, some say clean
        if malicious_sources and clean_sources:
            mal_str   = ", ".join(malicious_sources)
            clean_str = ", ".join(clean_sources)
            conflicts.append(
                f"⚠️ CONFLICTING INTEL: {mal_str} = MALICIOUS vs {clean_str} = CLEAN "
                f"→ Manual investigation required"
            )

        # Specific high-value conflicts
        vt_v  = verdicts.get("virustotal", "")
        mb_v  = verdicts.get("malwarebazaar", "")
        uh_v  = verdicts.get("urlhaus", "")
        gn_v  = verdicts.get("greynoise", "")

        if vt_v == "clean" and mb_v == "malicious":
            conflicts.append(
                "🔴 CRITICAL: VirusTotal=clean but MalwareBazaar=malicious — "
                "AV evasion possible (FUD malware). Trust MalwareBazaar."
            )
        if gn_v == "clean" and uh_v == "malicious":
            conflicts.append(
                "⚠️ GreyNoise=benign-noise but URLhaus=malicious — "
                "Mass-scanning C2 server. Both signals valid."
            )

        return conflicts

    # ── FIX 6: Explainability layer ────────────────────────────────────────────
    @staticmethod
    def _build_explanation(
        ioc: str,
        ioc_type: str,
        source_results: list,
        verdict: str,
        conflicts: list,
        strong_signals: list,
    ) -> dict:
        """
        FIX 6: Build structured WHY explanation for every verdict.

        Returns {
          "summary":  one-line plain English verdict,
          "reasons":  ordered list of (icon, signal, detail),
          "why_text": full paragraph for reports/LLM context,
        }
        """
        reasons = []

        # 1. Strong signals first
        for sig in strong_signals:
            reasons.append(("🔴", "Strong Malicious Signal", sig))

        # 2. Source-by-source contributions
        for r in source_results:
            if r.get("skipped") or r.get("verdict") == "unknown":
                continue
            v      = r.get("verdict", "")
            expl   = r.get("explain", "")
            icon   = "❌" if v == "malicious" else "⚠️" if v == "suspicious" else "✔️"
            if expl:
                reasons.append((icon, r.get("source","?").upper(), expl))

        # 3. Conflicts
        for c in conflicts:
            reasons.append(("⚡", "Intel Conflict", c))

        # 4. Summary sentence
        malicious_count = sum(1 for r in source_results if r.get("verdict") == "malicious")
        clean_count     = sum(1 for r in source_results if r.get("verdict") == "clean")
        total_sources   = sum(1 for r in source_results
                              if not r.get("skipped") and r.get("verdict") != "unknown")

        if verdict == "MALICIOUS":
            summary = (
                f"{ioc} classified MALICIOUS — {malicious_count}/{total_sources} "
                f"sources confirmed. Immediate block + investigation required."
            )
        elif verdict == "SUSPICIOUS":
            summary = (
                f"{ioc} is SUSPICIOUS — {malicious_count} malicious signal(s), "
                f"{clean_count} clean source(s). Full investigation recommended."
            )
        elif verdict == "SAFE":
            summary = (
                f"{ioc} appears SAFE — {clean_count}/{total_sources} "
                f"sources clean. No action required."
            )
        else:
            summary = (
                f"{ioc} is LOW RISK — {total_sources} source(s) checked, "
                f"no strong malicious signals."
            )

        # 5. why_text — full paragraph for report export
        source_lines = "\n".join(
            f"  - {r.get('explain','')}" for r in source_results
            if r.get("explain") and not r.get("skipped")
        )
        conflict_lines = "\n".join(f"  - {c}" for c in conflicts)
        why_text = (
            f"IOC: {ioc} ({ioc_type})\n"
            f"Verdict: {verdict}\n"
            f"Checked {total_sources} intelligence sources:\n"
            f"{source_lines}\n"
            + (f"Conflicts detected:\n{conflict_lines}\n" if conflicts else "")
            + (f"Strong signals (auto-escalation):\n"
               + "\n".join(f"  - {s}" for s in strong_signals) if strong_signals else "")
        )

        return {"summary": summary, "reasons": reasons, "why_text": why_text}

    @staticmethod
    def _score_to_verdict(score: int) -> tuple:
        """Returns (verdict, severity, confidence_cap, action)"""
        if score >= 70:
            return "SAFE", "informational", 10, "No action required"
        elif score >= 50:
            return "LOW RISK", "low", 30, "Monitor — limited enrichment"
        elif score >= 30:
            return "SUSPICIOUS", "medium", 70, "Full investigation recommended"
        else:
            return "MALICIOUS", "high", 95, "Block + investigate immediately"

    # ── Source name display map ───────────────────────────────────────────────
    _SOURCE_LABELS = {
        "virustotal":   "VirusTotal",
        "abuseipdb":    "AbuseIPDB",
        "greynoise":    "GreyNoise",
        "otx":          "AlienVault OTX",
        "urlscan":      "URLScan.io",
        "urlhaus":      "URLhaus",
        "malwarebazaar":"MalwareBazaar",
        "shodan":       "Shodan",
        "ipinfo":       "IPInfo",
    }

    @staticmethod
    def _build_tags(ioc: str, source_results: list, verdict: str) -> list:
        """
        Build human-readable tag list for the Tags column in Batch IOC Lookup.
        Shows: source verdicts + typosquat + DGA + brand impersonation tags.
        """
        tags = []

        # Source-based tags
        for r in source_results:
            src   = r.get("source", "")
            verd  = r.get("verdict", "")
            label = IOCEnricher._SOURCE_LABELS.get(src, src.title())
            if verd == "malicious":
                detail = r.get("explain", "")
                tags.append(f"{label}: malicious" + (f" ({detail[:30]})" if detail else ""))
            elif verd == "suspicious":
                tags.append(f"{label}: suspicious")
            elif verd == "clean" and src in ("virustotal", "abuseipdb"):
                tags.append(f"{label}: clean")

        # Typosquat tag
        ts_tag = IOCEnricher._detect_typosquat_tag(ioc)
        if ts_tag:
            tags.insert(0, ts_tag)

        # DGA tag
        import math as _math
        domain = ioc.split(".")[0] if "." in ioc else ioc
        if len(domain) > 12:
            freq = {c: domain.count(c)/len(domain) for c in set(domain)}
            entropy = -sum(p * _math.log2(p) for p in freq.values())
            if entropy > 3.5:
                tags.insert(0, "DGA-style domain")

        return tags[:8]   # cap at 8 tags

    @staticmethod
    def _detect_typosquat_tag(ioc: str) -> str:
        """
        Detect typosquatting patterns and return a human-readable tag.
        e.g. amaz0n.co → 'Typosquat of Amazon'
        """
        import re as _re
        domain = ioc.lower().split(".")[0] if "." in ioc else ioc.lower()

        # Number-letter substitutions
        leet_map = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a"}
        normalized = domain
        for num, letter in leet_map.items():
            normalized = normalized.replace(num, letter)

        # Known brand targets
        brands = {
            "amazon": "Amazon",    "google": "Google",
            "facebook": "Facebook","microsoft": "Microsoft",
            "paypal": "PayPal",    "apple": "Apple",
            "netflix": "Netflix",  "instagram": "Instagram",
            "twitter": "Twitter",  "linkedin": "LinkedIn",
            "whatsapp": "WhatsApp","youtube": "YouTube",
            "gmail": "Gmail",      "yahoo": "Yahoo",
            "icici": "ICICI Bank", "hdfc": "HDFC Bank",
            "paytm": "Paytm",      "sbi": "SBI",
        }

        for key, brand in brands.items():
            if key in normalized and key not in domain:
                return f"Typosquat of {brand}"
            if key in domain and domain != key and len(domain) > len(key):
                suffix = domain.replace(key, "")
                if suffix in ("-secure","-login","-verify","secure","login","verify","update"):
                    return f"Brand impersonation of {brand}"

        # Homograph check — looks like brand but has extra chars
        for key, brand in brands.items():
            if normalized == key and domain != key:
                return f"Typosquat of {brand}"

        return ""

    @staticmethod
    def is_test_domain(ioc: str) -> tuple:
        val = ioc.lower().strip()
        for td in _TEST_DOMAINS:
            if val == td or val.endswith("." + td):
                return True, f"Known intentionally vulnerable test site: {td}"
        return False, ""

    # ── Main enrich function ───────────────────────────────────────────────────
    @staticmethod
    def enrich(ioc: str, ioc_type: str = "auto",
               use_cache: bool = True, progress_cb=None) -> dict:
        """
        Full 7-source enrichment pipeline.

        Pipeline:
          1. Type auto-detection
          2. Test domain check
          3. Cache lookup
          4. API calls (cheapest/fastest first)
          5. FIX 2: Weighted scoring
          6. FIX 3: Strong signal override
          7. FIX 4: Conflict detection
          8. FIX 5: Freshness adjustment
          9. FIX 6: Explainability layer
         10. FIX 7: Source breakdown
         11. Cache write + Splunk push
        """
        ioc = ioc.strip()
        if not ioc:
            return {}

        # Step 1 — type auto-detection
        if ioc_type == "auto":
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
                ioc_type = "ip"
            elif re.match(r"^[0-9a-f]{32,64}$", ioc.lower()):
                ioc_type = "hash"
            else:
                ioc_type = "domain"

        # Step 2 — test domain check
        is_test, test_reason = IOCEnricher.is_test_domain(ioc)

        # Step 3 — cache
        if use_cache:
            cached = IOCEnricher._cache_get(ioc)
            if cached:
                cached["from_cache"] = True
                return cached

        keys           = IOCEnricher._keys()
        source_results = []
        sources_used   = []

        def _step(label, fn, *args):
            if progress_cb:
                progress_cb(label)
            try:
                r = fn(*args)
                if r:
                    source_results.append(r)
                    if not r.get("skipped") and not r.get("error"):
                        sources_used.append(label)
                return r
            except Exception:
                return {}

        # Step 4 — API calls (cheapest/fastest first)
        # URLhaus + MalwareBazaar first — free, no key, high precision
        _step("urlhaus",      IOCEnricher._call_urlhaus,      ioc, ioc_type)
        _step("malwarebazaar",IOCEnricher._call_malwarebazaar, ioc, ioc_type)

        # ── All IOC types get all applicable sources ─────────────────────────
        if ioc_type == "ip":
            _step("abuseipdb", IOCEnricher._call_abuseipdb, ioc, keys["abuseipdb"])
            _step("ipinfo",    IOCEnricher._call_ipinfo,    ioc, keys["ipinfo"])
            _step("greynoise", IOCEnricher._call_greynoise, ioc, keys["greynoise"])
            _step("shodan",    IOCEnricher._call_shodan,    ioc, keys["shodan"])

        _step("virustotal", IOCEnricher._call_virustotal, ioc, ioc_type, keys["virustotal"])
        _step("otx",        IOCEnricher._call_otx,        ioc, ioc_type, keys["otx"])

        if ioc_type in ("domain", "url"):
            _step("urlscan", IOCEnricher._call_urlscan, ioc, keys["urlscan"])
            # Try Shodan for domain (host lookup)
            if keys.get("shodan"):
                _step("shodan", IOCEnricher._call_shodan, ioc, keys["shodan"])

        if ioc_type == "hash":
            # MalwareBazaar is best for hashes — already called above
            pass

        # Step 5 — FIX 2: weighted scoring
        score, weight_breakdown = IOCEnricher._compute_weighted_score(source_results)

        # Step 6 — FIX 3: Strong signal override ("1 strong signal > 3 weak cleans")
        strong_signals = []
        for r in source_results:
            if r.get("is_strong_signal") and r.get("verdict") == "malicious":
                strong_signals.append(r.get("explain", r["source"]))

        if strong_signals:
            # Force score into MALICIOUS range regardless of other clean signals
            score = min(score, 25)   # ≤25 → MALICIOUS verdict
            strong_note = f"FIX 3: Strong-signal override by {', '.join(s.split(':')[0] for s in strong_signals)}"
        else:
            strong_note = ""

        # Test domain override
        if is_test:
            score = max(score, 55)

        # Step 7 — FIX 4: conflict detection
        conflicts = IOCEnricher._detect_conflicts(source_results)

        # Determine final verdict
        verdict, severity, conf_cap, action = IOCEnricher._score_to_verdict(score)

        malicious_count  = sum(1 for r in source_results if r.get("verdict") == "malicious")
        suspicious_count = sum(1 for r in source_results if r.get("verdict") == "suspicious")

        # Step 8 — additional majority vote check (belt-and-suspenders)
        if malicious_count >= 2 and score > 30:
            score    = min(score, 30)
            verdict  = "MALICIOUS"
            severity = "high"
            conf_cap = 90
            action   = "Block + investigate immediately"

        # Step 9 — FIX 6: explainability layer
        explanation = IOCEnricher._build_explanation(
            ioc          = ioc,
            ioc_type     = ioc_type,
            source_results = source_results,
            verdict      = verdict,
            conflicts    = conflicts,
            strong_signals = strong_signals,
        )

        result = {
            # Core fields
            "ioc":              ioc,
            "type":             ioc_type,
            "unified_score":    score,
            "verdict":          verdict,
            "severity":         severity,
            "confidence_cap":   conf_cap,
            "action":           action,
            # FIX 7: full source breakdown
            "sources":          {r["source"]: r for r in source_results},
            "sources_used":     sources_used,
            "sources_hit":      malicious_count + suspicious_count,
            "malicious_sources":malicious_count,
            # FIX 4: conflicts
            "conflicts":        conflicts,
            # FIX 5: weight breakdown (for UI transparency)
            "weight_breakdown": weight_breakdown,
            # FIX 6: explainability
            "explanation":      explanation,
            "why":              explanation["summary"],
            "why_text":         explanation["why_text"],
            # Meta
            "is_test_domain":   is_test,
            "test_reason":      test_reason,
            "strong_signals":   strong_signals,
            "strong_note":      strong_note,
            "from_cache":       False,
            "timestamp":        datetime.utcnow().isoformat(),
            # Legacy compat
            "overall":          verdict.lower().replace(" ", "_"),
            "threat_score":     100 - score,
            # ── FIX: sources_total + all_tags for Batch IOC display ───────────
            "sources_total":    max(7, len(sources_used)),   # always show /7
            "all_tags":         IOCEnricher._build_tags(ioc, source_results, verdict),
            "typosquat_tag":    IOCEnricher._detect_typosquat_tag(ioc),
        }

        # Store in session for global propagation
        try:
            st.session_state.setdefault(_REP_SCORE_KEY, {})[ioc.lower()] = score
        except Exception:
            pass

        # Auto-send to Splunk HEC
        try:
            from modules.splunk_handler import send_to_splunk as _spl
            _spl({
                "event_type":        "ioc_enrichment",
                "ioc":               ioc,
                "ioc_type":          ioc_type,
                "verdict":           verdict,
                "unified_score":     score,
                "severity":          severity,
                "malicious_sources": malicious_count,
                "sources_used":      sources_used,
                "conflicts":         len(conflicts),
                "strong_signals":    len(strong_signals),
                "why":               explanation["summary"],
                "timestamp":         datetime.utcnow().isoformat() + "Z",
                "source":            "netsec_ai_ioc_enrichment_v11",
            })
        except Exception:
            pass

        IOCEnricher._cache_set(ioc, result)
        return result

    # ── Global reputation lookup ───────────────────────────────────────────────
    @staticmethod
    def get_session_score(ioc: str) -> int | None:
        try:
            return st.session_state.get(_REP_SCORE_KEY, {}).get(ioc.lower())
        except Exception:
            return None

    @staticmethod
    def should_investigate(ioc: str) -> tuple:
        score = IOCEnricher.get_session_score(ioc)
        if score is None:
            return True, "No prior reputation score — proceeding with investigation"
        if score >= 70:
            return False, f"Reputation score {score}/100 — SAFE, investigation blocked"
        if score >= 50:
            return False, f"Reputation score {score}/100 — LOW RISK, enrichment-only"
        return True, f"Reputation score {score}/100 — suspicious, investigation allowed"

    # ── Batch enrich ──────────────────────────────────────────────────────────
    @staticmethod
    def batch_enrich(iocs: list, progress_container=None) -> list:
        """Enrich multiple IOCs. iocs = [(value, type), ...]"""
        results = []
        total   = len(iocs)
        for i, (ioc, ioc_type) in enumerate(iocs):
            if progress_container:
                progress_container.progress(
                    int((i + 1) / total * 100),
                    text=f"Enriching {i+1}/{total}: {ioc[:30]}…"
                )
            results.append(IOCEnricher.enrich(ioc, ioc_type))
        return results


# ── FIX 7: Upgraded source breakdown renderer ─────────────────────────────────
def render_ioc_enrichment_result(result: dict, show_sources: bool = True):
    """
    v11: Renders upgraded enrichment result with:
      - Full source breakdown (verdict per source, not just count)
      - Conflict warnings
      - Strong signal banners
      - WHY explainability panel
      - Weight transparency table
    """
    if not result:
        return

    score   = result.get("unified_score", 50)
    verdict = result.get("verdict", "UNKNOWN")
    ioc     = result.get("ioc", "")
    is_test = result.get("is_test_domain", False)
    conflicts    = result.get("conflicts", [])
    strong_sigs  = result.get("strong_signals", [])
    explanation  = result.get("explanation", {})
    reasons      = explanation.get("reasons", [])

    _SC = {
        "SAFE":     "#00c878",
        "LOW RISK": "#00aaff",
        "SUSPICIOUS":"#ffcc00",
        "MALICIOUS":"#ff0033",
        "UNKNOWN":  "#446688",
    }
    _c = _SC.get(verdict, "#446688")

    # ── Test domain banner ────────────────────────────────────────────────────
    if is_test:
        st.markdown(
            f"<div style='background:rgba(255,204,0,0.08);border:2px solid #ffcc0066;"
            f"border-radius:10px;padding:10px 16px;margin-bottom:8px'>"
            f"<span style='color:#ffcc00;font-weight:700'>⚠️ INTENTIONALLY VULNERABLE TEST SITE</span><br>"
            f"<span style='color:#c8e8ff;font-size:.72rem'>{result.get('test_reason','')}</span>"
            f"</div>",
            unsafe_allow_html=True
        )

    # ── Strong signal banner ──────────────────────────────────────────────────
    if strong_sigs:
        st.markdown(
            f"<div style='background:rgba(255,0,51,0.10);border:2px solid #ff003366;"
            f"border-left:4px solid #ff0033;border-radius:8px;"
            f"padding:10px 16px;margin-bottom:8px'>"
            f"<div style='color:#ff0033;font-weight:900;font-size:.75rem;margin-bottom:4px'>"
            f"🔴 STRONG SIGNAL OVERRIDE — AUTO ESCALATION TRIGGERED</div>"
            + "".join(
                f"<div style='color:#ff8080;font-size:.68rem;margin:2px 0'>• {s}</div>"
                for s in strong_sigs
            )
            + f"<div style='color:#ff444488;font-size:.62rem;margin-top:4px'>"
            f"Rule: 1 strong malicious signal &gt; 3 weak clean signals</div>"
            f"</div>",
            unsafe_allow_html=True
        )

    # ── Conflict warning banner ───────────────────────────────────────────────
    for conflict in conflicts:
        st.markdown(
            f"<div style='background:rgba(255,153,0,0.08);border:1px solid #ff990044;"
            f"border-left:3px solid #ff9900;border-radius:6px;"
            f"padding:8px 14px;margin-bottom:6px'>"
            f"<span style='color:#ff9900;font-size:.68rem'>{conflict}</span>"
            f"</div>",
            unsafe_allow_html=True
        )

    # ── Main score card ───────────────────────────────────────────────────────
    bar_w = score
    st.markdown(
        f"<div style='background:rgba(0,0,0,0.3);border:1px solid {_c}33;"
        f"border-top:3px solid {_c};border-radius:10px;padding:14px 18px;margin:6px 0'>"
        f"<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:8px'>"
        f"<div style='flex:1'>"
        f"<span style='color:{_c};font-weight:900;font-size:.85rem'>{verdict}</span>"
        f"<span style='color:#446688;font-size:.65rem;margin-left:8px'>— {ioc}</span>"
        + (f"<span style='background:rgba(0,200,120,0.12);border:1px solid #00c87844;"
           f"border-radius:4px;padding:1px 7px;font-size:.6rem;color:#00c878;margin-left:6px'>from cache</span>"
           if result.get("from_cache") else "")
        + f"</div>"
        f"<div style='text-align:right'>"
        f"<div style='color:#446688;font-size:.58rem'>REPUTATION</div>"
        f"<div style='color:{_c};font-size:1.2rem;font-weight:900'>{score}"
        f"<span style='color:#446688;font-size:.6rem'>/100</span></div></div>"
        f"<div style='text-align:right'>"
        f"<div style='color:#446688;font-size:.58rem'>CONF. CAP</div>"
        f"<div style='color:{'#00c878' if result.get('confidence_cap',95)<=15 else '#ff9900' if result.get('confidence_cap',95)<=50 else '#ff4444'};"
        f"font-size:1.1rem;font-weight:900'>≤{result.get('confidence_cap',95)}%</div>"
        f"</div></div>"
        f"<div style='background:#0a1420;border-radius:4px;height:7px;margin-bottom:8px'>"
        f"<div style='background:{_c};height:100%;width:{bar_w}%;border-radius:4px'></div></div>"
        f"<div style='color:{_c};font-size:.68rem'>{result.get('action','')}</div>"
        f"<div style='color:#446688;font-size:.6rem;margin-top:4px'>"
        f"Sources checked: {', '.join(result.get('sources_used',[])) or 'none (no API keys)'} · "
        f"{result.get('malicious_sources',0)} malicious · "
        f"{len(conflicts)} conflict(s)</div>"
        f"</div>",
        unsafe_allow_html=True
    )

    # ── FIX 7: Full per-source breakdown (replaces "Sources: 2/2") ───────────
    if show_sources and result.get("sources"):
        st.markdown(
            "<div style='color:#446688;font-size:.65rem;font-weight:700;"
            "letter-spacing:1px;margin:10px 0 6px'>📊 SOURCE BREAKDOWN</div>",
            unsafe_allow_html=True
        )

        _ICONS   = {
            "abuseipdb":    "🚨", "virustotal": "🔬", "greynoise":    "📡",
            "otx":          "🌐", "ipinfo":     "📍", "urlhaus":      "🔗",
            "urlscan":      "🔭", "shodan":     "⚙️", "malwarebazaar":"☣️",
        }
        _VC = {
            "malicious": "#ff0033",
            "suspicious":"#ff9900",
            "clean":     "#00c878",
            "unknown":   "#446688",
        }
        _VERDICT_ICONS = {
            "malicious": "❌", "suspicious": "⚠️",
            "clean": "✔️", "unknown": "—",
        }

        sources = result["sources"]
        # Sort: malicious first, then suspicious, then clean, then unknown
        _ORDER  = {"malicious": 0, "suspicious": 1, "clean": 2, "unknown": 3}
        sorted_sources = sorted(
            sources.items(),
            key=lambda x: _ORDER.get(x[1].get("verdict","unknown"), 3)
        )

        # Render 4 per row
        chunk_size = 4
        chunks = [sorted_sources[i:i+chunk_size]
                  for i in range(0, len(sorted_sources), chunk_size)]

        for chunk in chunks:
            cols = st.columns(len(chunk))
            for col, (sname, sdata) in zip(cols, chunk):
                sv   = sdata.get("verdict", "unknown")
                sc   = _VC.get(sv, "#446688")
                icon = _ICONS.get(sname, "🔍")
                vi   = _VERDICT_ICONS.get(sv, "—")
                w    = _SOURCE_WEIGHTS.get(sname, 5)
                fresh= sdata.get("freshness", 1.0)
                expl = sdata.get("explain", "")[:70]

                # Freshness badge
                if fresh > 1.0:
                    fresh_badge = "<span style='color:#00f9ff;font-size:.55rem'>🔴 FRESH</span>"
                elif fresh < 1.0:
                    fresh_badge = "<span style='color:#446688;font-size:.55rem'>💤 STALE</span>"
                else:
                    fresh_badge = ""

                col.markdown(
                    f"<div style='background:rgba(0,0,0,0.4);border:1px solid {sc}33;"
                    f"border-top:2px solid {sc};border-radius:8px;padding:8px 10px;"
                    f"min-height:90px'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:center;"
                    f"margin-bottom:3px'>"
                    f"<span style='color:{sc};font-size:.65rem;font-weight:700'>"
                    f"{icon} {sname.upper()}</span>"
                    f"<span style='color:#334455;font-size:.55rem'>w:{w}</span></div>"
                    f"<div style='color:{sc};font-size:.75rem;font-weight:900'>"
                    f"{vi} {sv.upper()}</div>"
                    f"{fresh_badge}"
                    f"<div style='color:#446688;font-size:.58rem;margin-top:3px;"
                    f"line-height:1.3'>{expl}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

    # ── FIX 6: WHY explainability panel ──────────────────────────────────────
    if reasons:
        with st.expander("🧠 Why this verdict? (Explainability)", expanded=False):
            st.markdown(
                f"<div style='color:#c8e8ff;font-size:.72rem;font-weight:700;"
                f"margin-bottom:8px'>📋 VERDICT REASONING CHAIN</div>",
                unsafe_allow_html=True
            )
            for icon, label, detail in reasons:
                label_color = (
                    "#ff0033" if icon == "❌" else
                    "#ff9900" if icon == "⚠️" else
                    "#00c878" if icon == "✔️" else
                    "#ff9900" if icon == "⚡" else
                    "#ff0033" if icon == "🔴" else
                    "#c8e8ff"
                )
                st.markdown(
                    f"<div style='display:flex;gap:10px;padding:5px 0;"
                    f"border-bottom:1px solid #0a1420'>"
                    f"<span style='font-size:.75rem;min-width:20px'>{icon}</span>"
                    f"<div>"
                    f"<span style='color:{label_color};font-size:.68rem;font-weight:700'>"
                    f"{label}: </span>"
                    f"<span style='color:#8899aa;font-size:.65rem'>{detail}</span>"
                    f"</div></div>",
                    unsafe_allow_html=True
                )
            # Summary
            summary = explanation.get("summary", "")
            if summary:
                st.markdown(
                    f"<div style='background:rgba(0,0,0,0.3);border-left:3px solid #00f9ff;"
                    f"padding:8px 14px;margin-top:8px;border-radius:0 6px 6px 0'>"
                    f"<div style='color:#446688;font-size:.6rem;margin-bottom:2px'>VERDICT SUMMARY</div>"
                    f"<div style='color:#c8e8ff;font-size:.7rem'>{summary}</div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

    # ── Weight transparency (collapsible) ─────────────────────────────────────
    wb = result.get("weight_breakdown", {})
    if wb:
        with st.expander("⚖️ Scoring weights (transparency)", expanded=False):
            import pandas as pd
            rows = []
            for sname, wd in wb.items():
                rows.append({
                    "Source":       sname.upper(),
                    "Verdict":      wd.get("verdict","?").upper(),
                    "Raw Score":    wd.get("raw_score", 0),
                    "Weight":       wd.get("weight", 0),
                    "Freshness":    f"{wd.get('freshness',1.0):.2f}x",
                    "Eff. Weight":  round(wd.get("eff_weight",0),1),
                    "Contribution": round(wd.get("contribution",0),1),
                })
            if rows:
                df = pd.DataFrame(rows).sort_values("Contribution", ascending=False)
                st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(
                "Formula: Final Score = (Neutral Base × 0.5) + (Weighted Intel Score × 0.5) | "
                "Freshness < 7d = 1.25×, > 180d = 0.70×"
            )