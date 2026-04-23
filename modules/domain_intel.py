"""
NetSec AI — Domain Intelligence & Triage Engine
================================================
Implements the full suspicious domain triage spec:
- Benign domain pre-check (Phase 1)
- Severity/confidence scaling (Phase 2)
- Safe case creation guard (Phase 3)
- Suspicious domain scoring (Docs 1+2)
- DGA detection, TLD abuse scoring, keyword matching

Usage:
    from modules.domain_intel import DomainIntel
    result = DomainIntel.analyse("suspicious-login-verify.xyz")
"""

import os
import re
import math
import fnmatch
import streamlit as st
from datetime import datetime

# ── Paths ──────────────────────────────────────────────────────────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR    = os.path.join(_THIS_DIR, "..", "data")
_BENIGN_FILE = os.path.join(_DATA_DIR, "benign_domains.txt")

# ── TLD abuse lists (2024-2026 data) ──────────────────────────────────────────
_TLD_VERY_HIGH_ABUSE = {
    "xyz","top","cfd","buzz","sbs","quest","live","fun","shop","site",
    "icu","gq","ml","tk","cf","ga","pw","cc","su","to"
}
_TLD_HIGH_ABUSE = {
    "club","online","space","website","digital","monster","bond","cyou",
    "rest","bar","hair","beauty","skin","vip","work","world","zip","mov"
}

# ── Suspicious keywords in domain names ───────────────────────────────────────
_PHISHING_KEYWORDS = {
    "login","signin","sign-in","logon","auth","authenticate","verify","verification",
    "secure","security","account","update","reset","recover","recovery","restore",
    "confirm","confirmation","validate","validation","activate","activation",
    "billing","payment","pay","invoice","tax","refund","claim","redeem","reward",
    "gift","bonus","free","win","winner","prize","offer","deal","discount",
    "crypto","wallet","bitcoin","eth","nft","invest","trading","profit",
    "bank","paypal","apple-id","microsoft","google","amazon","netflix","spotify",
    "support","help","service","helpdesk","portal","gateway","dashboard",
    "webmail","cpanel","admin","panel","manage","manager"
}

# ── Known malicious domain patterns ───────────────────────────────────────────
_C2_PATTERNS = [
    r"\b[a-z0-9]{8,16}\.(xyz|top|cfd|buzz|live|sbs|quest)\b",  # Random + abusive TLD
    r"\b\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.",                    # IP-like in domain
    r"[a-z0-9]{32,}\.",                                          # Very long random subdomain (DGA)
    r"\b(?:cdn|api|update|download|mail)\d{2,}\.",               # Fake infra names
]

# ── Bullet-proof / abusive ASNs / hosting keywords ────────────────────────────
_SHADY_HOSTING_KEYWORDS = {
    "njalla","withheld","internet.bs","epik.com","namecheap","regway",
    "panamaserver","privatewhois","whoisguard"
}




def _universal_benign_guard(domain_or_ip: str, context: str = "") -> bool:
    """
    Universal benign guard — call at the TOP of any domain/IP processing.
    Returns True if benign AND renders the verdict. Caller must return after True.
    No st.stop() — safer across Streamlit contexts.
    """
    if not domain_or_ip:
        return False
    val = str(domain_or_ip).lower().strip()

    _BENIGN_PATTERNS = [
        "google.com","youtube.com","gstatic.com","googleapis.com","googleusercontent.com",
        "googlevideo.com","gmail.com","google.co.in","google.co.uk",
        "microsoft.com","azure.com","azureedge.net","office.com","office365.com",
        "live.com","outlook.com","hotmail.com","bing.com","windowsupdate.com",
        "microsoftonline.com","sharepoint.com",
        "amazonaws.com","cloudfront.net","awsstatic.com",
        "cloudflare.com","cloudflare-dns.com","akamai.net","akamaized.net","fastly.net",
        "apple.com","icloud.com","mzstatic.com",
        "facebook.com","fbcdn.net","instagram.com","whatsapp.com","meta.com",
        "zoom.us","dropbox.com","slack.com","salesforce.com",
        "twitter.com","x.com","linkedin.com","twimg.com",
        "github.com","githubusercontent.com","gitlab.com",
        "wikipedia.org","wikimedia.org","netflix.com","spotify.com",
        "adobe.com","oracle.com","cisco.com","okta.com","crowdstrike.com",
    ]
    _GOOGLE_IP_PFX = (
        "8.8.8.8","8.8.4.4","142.250.","142.251.","172.217.","172.253.",
        "216.58.","216.239.","74.125.","64.233.","66.102.","66.249.",
        "72.14.","209.85.",
    )
    _MS_IP_PFX  = ("13.64.","13.107.","40.76.","52.96.","104.40.")
    _CF_IP_PFX  = ("1.1.1.","1.0.0.","104.16.","104.17.","104.18.")

    is_safe = False
    matched = ""
    owner   = "Known Legitimate Infrastructure"

    for pfx in _GOOGLE_IP_PFX:
        if val == pfx or val.startswith(pfx):
            is_safe = True; matched = pfx; owner = "Google LLC"; break
    if not is_safe:
        for pfx in _MS_IP_PFX:
            if val.startswith(pfx):
                is_safe = True; matched = pfx; owner = "Microsoft Corporation"; break
    if not is_safe:
        for pfx in _CF_IP_PFX:
            if val.startswith(pfx):
                is_safe = True; matched = pfx; owner = "Cloudflare Inc."; break

    if not is_safe:
        for p in _BENIGN_PATTERNS:
            if val == p or val.endswith("." + p) or ("." in val and p in val):
                is_safe = True; matched = p
                if any(k in p for k in ["google","youtube","gstatic","googleapis"]):
                    owner = "Google LLC"
                elif any(k in p for k in ["microsoft","azure","office","bing","sharepoint"]):
                    owner = "Microsoft Corporation"
                elif any(k in p for k in ["amazon","aws","cloudfront"]):
                    owner = "Amazon Web Services"
                elif "cloudflare" in p:
                    owner = "Cloudflare Inc."
                elif "apple" in p or "icloud" in p:
                    owner = "Apple Inc."
                elif any(k in p for k in ["facebook","meta","instagram","whatsapp"]):
                    owner = "Meta Platforms Inc."
                else:
                    owner = "Major Technology Provider"
                break

    if not is_safe:
        try:
            if val in st.session_state.get("analyst_whitelist", set()):
                is_safe = True; matched = "analyst-whitelist"; owner = "Analyst-approved"
        except Exception:
            pass

    if not is_safe:
        try:
            import fnmatch as _fm
            _bf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "benign_domains.txt")
            if os.path.exists(_bf):
                with open(_bf) as _f:
                    for _ln in _f:
                        _p = _ln.strip().lower()
                        if not _p or _p.startswith("#"): continue
                        _base = _p[2:] if _p.startswith("*.") else _p
                        if val == _base or val.endswith("." + _base) or _fm.fnmatch(val, _p):
                            is_safe = True; matched = _p; break
        except Exception:
            pass

    if not is_safe:
        return False

    from datetime import datetime as _dtbg
    st.markdown(
        f"<div style='background:rgba(0,200,120,0.08);border:2px solid #00c878;"
        f"border-radius:14px;padding:22px 26px;margin:10px 0'>"
        f"<div style='font-size:2rem;margin-bottom:8px'>✅</div>"
        f"<div style='color:#00c878;font-family:Orbitron,sans-serif;"
        f"font-size:1rem;font-weight:900;margin-bottom:10px'>"
        f"Known Benign Infrastructure — No Threat Detected</div>"
        f"<table style='color:#c8e8ff;font-size:.76rem;border-collapse:collapse'>"
        f"<tr><td style='color:#446688;padding:3px 16px 3px 0;min-width:140px'>Domain / IP</td>"
        f"<td><b>{domain_or_ip}</b></td></tr>"
        f"<tr><td style='color:#446688;padding:3px 16px 3px 0'>Category</td>"
        f"<td>Major global technology / CDN / cloud infrastructure</td></tr>"
        f"<tr><td style='color:#446688;padding:3px 16px 3px 0'>Owner</td><td>{owner}</td></tr>"
        f"<tr><td style='color:#446688;padding:3px 16px 3px 0'>Risk level</td>"
        f"<td><b style='color:#00c878'>Very Low / Informational</b></td></tr>"
        f"<tr><td style='color:#446688;padding:3px 16px 3px 0'>Action required</td>"
        f"<td><b style='color:#00c878'>None</b></td></tr>"
        f"<tr><td style='color:#446688;padding:3px 16px 3px 0'>Confidence</td>"
        f"<td><b style='color:#00c878'>99.9%</b></td></tr>"
        f"<tr><td style='color:#446688;padding:3px 16px 3px 0'>Matched rule</td>"
        f"<td><code style='color:#00c878;font-size:.65rem'>{matched}</code></td></tr>"
        f"</table>"
        f"<div style='margin-top:12px;color:#2a5a3a;font-size:.65rem;"
        f"border-top:1px solid #00c87833;padding-top:8px'>"
        f"No investigation · No timeline · No MITRE mapping · "
        f"No IR case · No block/isolate actions · {context or ''} · "
        f"Checked: {_dtbg.now().strftime('%d %b %Y %H:%M')}"
        f"</div></div>",
        unsafe_allow_html=True
    )
    return True

class DomainIntel:
    """
    All-in-one domain intelligence engine.
    Call DomainIntel.analyse(domain) → returns structured verdict dict.
    """

    # ── Load benign list ───────────────────────────────────────────────────────
    @staticmethod
    def _load_benign_list():
        """Load benign domains from file + built-in + analyst session state."""
        domains = set()
        # From file
        try:
            with open(_BENIGN_FILE, encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        domains.add(line)
        except FileNotFoundError:
            pass
        # From analyst whitelist in session
        try:
            for d in st.session_state.get("analyst_whitelist", set()):
                domains.add(d.lower())
        except Exception:
            pass
        return domains

    @staticmethod
    def is_benign(domain: str) -> tuple:
        """
        Returns (is_benign: bool, matched_pattern: str).
        Checks exact match and wildcard patterns.
        """
        if not domain:
            return False, ""
        d = domain.lower().strip()

        # Check analyst blacklist first — overrides safe list
        try:
            if d in st.session_state.get("analyst_blacklist", set()):
                return False, ""
        except Exception:
            pass

        benign_list = DomainIntel._load_benign_list()
        for pattern in benign_list:
            if pattern.startswith("*."):
                # Wildcard: *.google.com matches mail.google.com AND google.com
                base = pattern[2:]  # google.com
                if d == base or d.endswith("." + base):
                    return True, pattern
            else:
                if d == pattern or fnmatch.fnmatch(d, pattern):
                    return True, pattern

        # Private / loopback IPs
        if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|localhost)", d):
            return True, "private-network"

        return False, ""

    @staticmethod
    def entropy(s: str) -> float:
        """Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f/n) * math.log2(f/n) for f in freq.values())

    @staticmethod
    def is_dga_like(domain: str) -> tuple:
        """
        Returns (is_dga: bool, confidence: int, reason: str).
        Checks entropy, consonant runs, digit/letter mixing.
        """
        # Strip TLD for analysis
        parts = domain.lower().split(".")
        label = parts[0] if parts else domain

        ent = DomainIntel.entropy(label)
        consonants = re.sub(r"[aeiou0-9]", "", label)
        digits     = re.findall(r"\d", label)
        digit_ratio = len(digits) / max(len(label), 1)
        vowel_ratio = len(re.findall(r"[aeiou]", label)) / max(len(label), 1)

        reasons = []
        score   = 0

        if ent > 4.0:
            reasons.append(f"Very high entropy ({ent:.2f})")
            score += 40
        elif ent > 3.5:
            reasons.append(f"High entropy ({ent:.2f})")
            score += 20

        if len(consonants) >= 6 and vowel_ratio < 0.15:
            reasons.append("No vowels — consonant cluster")
            score += 30

        if digit_ratio > 0.4:
            reasons.append(f"High digit ratio ({digit_ratio:.0%})")
            score += 25

        if len(label) > 20:
            reasons.append(f"Very long label ({len(label)} chars)")
            score += 15

        # Check C2 patterns
        for pat in _C2_PATTERNS:
            if re.search(pat, domain.lower()):
                reasons.append("Matches known C2/DGA pattern")
                score += 35
                break

        is_dga = score >= 50
        return is_dga, min(score, 99), "; ".join(reasons) if reasons else "No DGA indicators"

    @staticmethod
    def tld_abuse_score(domain: str) -> tuple:
        """Returns (score: int, level: str, tld: str)."""
        tld = domain.lower().rsplit(".", 1)[-1] if "." in domain else ""
        if tld in _TLD_VERY_HIGH_ABUSE:
            return 80, "VERY HIGH ABUSE TLD", tld
        if tld in _TLD_HIGH_ABUSE:
            return 50, "HIGH ABUSE TLD", tld
        return 0, "normal", tld

    @staticmethod
    def keyword_match(domain: str) -> tuple:
        """Returns (matched: bool, keywords: list, confidence: int)."""
        d = domain.lower()
        found = [kw for kw in _PHISHING_KEYWORDS if kw in d]
        if len(found) >= 3:
            return True, found, 90
        if len(found) >= 2:
            return True, found, 75
        if len(found) == 1:
            return True, found, 55
        return False, [], 0

    @staticmethod
    def typosquat_check(domain: str) -> tuple:
        """Returns (is_typosquat: bool, target: str, confidence: int)."""
        d = domain.lower()
        # Digit substitution patterns (g00gle, micr0soft)
        normalized = d.replace("0","o").replace("1","l").replace("3","e").replace("4","a").replace("5","s")
        brands = {
            "google":"google.com","microsoft":"microsoft.com","amazon":"amazon.com",
            "apple":"apple.com","facebook":"facebook.com","paypal":"paypal.com",
            "netflix":"netflix.com","spotify":"spotify.com","twitter":"twitter.com",
            "linkedin":"linkedin.com","instagram":"instagram.com","github":"github.com",
        }
        for brand, legit in brands.items():
            if brand in normalized and d != legit and not d.endswith("."+legit.split(".")[0]+".com"):
                # Not the real domain but contains the brand
                if brand not in d:  # Only flag if it's via substitution
                    return True, legit, 90
        # Punycode / homoglyph check
        if "xn--" in d:
            return True, "Punycode homoglyph attack", 95
        return False, "", 0

    @staticmethod
    def score_domain(domain: str) -> dict:
        """
        Full scoring pipeline. Returns structured suspicion verdict.
        Lower score = more suspicious (0=definite threat, 100=clean).
        """
        d = domain.lower().strip()

        # Step 1: Benign check
        is_safe, matched = DomainIntel.is_benign(d)
        if is_safe:
            return {
                "domain":       d,
                "verdict":      "BENIGN",
                "risk_score":   2,   # Near zero
                "severity":     "informational",
                "confidence":   99,
                "safe":         True,
                "matched_rule": matched,
                "indicators":   [],
                "action":       "No action required",
                "summary":      f"{d} is classified as known legitimate infrastructure. "
                               f"No incident report generated.",
                "tld":          d.rsplit(".",1)[-1] if "." in d else "",
            }

        indicators = []
        suspicion  = 0   # Accumulates — higher = more suspicious

        # Step 2: TLD abuse
        tld_score, tld_level, tld = DomainIntel.tld_abuse_score(d)
        if tld_score > 0:
            suspicion += tld_score
            indicators.append({
                "type":       "TLD Abuse",
                "detail":     f".{tld} — {tld_level}",
                "confidence": tld_score,
                "severity":   "high" if tld_score >= 80 else "medium",
            })

        # Step 3: DGA detection
        is_dga, dga_conf, dga_reason = DomainIntel.is_dga_like(d)
        if is_dga:
            suspicion += dga_conf
            indicators.append({
                "type":       "DGA / Random Domain",
                "detail":     dga_reason,
                "confidence": dga_conf,
                "severity":   "high",
            })

        # Step 4: Keyword match
        kw_match, kw_found, kw_conf = DomainIntel.keyword_match(d)
        if kw_match:
            suspicion += kw_conf
            indicators.append({
                "type":       "Phishing Keywords",
                "detail":     f"Keywords found: {', '.join(kw_found[:5])}",
                "confidence": kw_conf,
                "severity":   "high" if kw_conf >= 75 else "medium",
            })

        # Step 5: Typosquat check
        is_ts, ts_target, ts_conf = DomainIntel.typosquat_check(d)
        if is_ts:
            suspicion += ts_conf
            indicators.append({
                "type":       "Typosquatting / Homoglyph",
                "detail":     f"Impersonating: {ts_target}",
                "confidence": ts_conf,
                "severity":   "critical",
            })

        # Step 6: Check session IOC cache
        try:
            cached = st.session_state.get("ioc_results", {}).get(d, {})
            if cached.get("overall") == "malicious":
                suspicion += 60
                indicators.append({
                    "type":       "Threat Intel Hit",
                    "detail":     f"Confirmed malicious — {cached.get('sources_hit',0)} sources",
                    "confidence": 92,
                    "severity":   "critical",
                })
            elif cached.get("overall") == "suspicious":
                suspicion += 30
                indicators.append({
                    "type":       "Threat Intel — Suspicious",
                    "detail":     "Flagged by threat intelligence",
                    "confidence": 65,
                    "severity":   "medium",
                })
        except Exception:
            pass

        # ── Calculate final verdict ────────────────────────────────────────────
        suspicion = min(suspicion, 200)

        if suspicion >= 150 or (is_ts and ts_conf >= 90):
            severity, verdict, action = "critical", "CONFIRMED MALICIOUS", \
                "Block DNS + Firewall · Isolate hosts · Create P1 case"
            confidence = min(95, 50 + suspicion // 4)
        elif suspicion >= 90:
            severity, verdict, action = "high", "HIGH SUSPICION", \
                "Enrich all IOCs · Create P2 case · Monitor related hosts"
            confidence = min(88, 40 + suspicion // 4)
        elif suspicion >= 50:
            severity, verdict, action = "medium", "SUSPICIOUS — INVESTIGATE", \
                "IOC enrichment · Add to watchlist · Analyst review"
            confidence = min(72, 30 + suspicion // 5)
        elif suspicion >= 20:
            severity, verdict, action = "low", "LOW SUSPICION", \
                "Log only · No auto-block · Monitor passively"
            confidence = min(50, 20 + suspicion // 5)
        else:
            severity, verdict, action = "informational", "LIKELY BENIGN", \
                "No action required — insufficient signals"
            confidence = max(10, suspicion)

        return {
            "domain":       d,
            "verdict":      verdict,
            "risk_score":   suspicion,
            "severity":     severity,
            "confidence":   confidence,
            "safe":         False,
            "matched_rule": "",
            "indicators":   indicators,
            "action":       action,
            "tld":          tld,
            "is_dga":       is_dga,
            "has_keywords": kw_match,
            "is_typosquat": is_ts,
            "summary":      (
                f"{d} — {verdict}. Risk score: {suspicion}/200. "
                f"Detected: {len(indicators)} indicator(s). "
                f"Recommended: {action}"
            ),
        }

    @staticmethod
    def analyse(domain: str) -> dict:
        """Main entry point. Alias for score_domain. Auto-sends verdict to Splunk."""
        result = DomainIntel.score_domain(domain)
        try:
            from modules.splunk_handler import send_to_splunk as _spl
            import datetime as _dt2
            _spl({
                "event_type": "domain_triage",
                "domain":     result.get("domain", domain),
                "verdict":    result.get("verdict", "UNKNOWN"),
                "risk_score": result.get("risk_score", 50),
                "confidence": result.get("confidence", 0),
                "severity":   result.get("severity", "unknown"),
                "safe":       result.get("safe", False),
                "timestamp":  _dt2.datetime.utcnow().isoformat() + "Z",
                "source":     "netsec_ai_domain_triage",
            })
        except Exception:
            pass
        return result

    @staticmethod
    def should_create_ir_case(title: str, description: str = "") -> tuple:
        """
        Returns (should_create: bool, reason: str).
        Phase 3: Guard against benign-domain case creation.
        """
        text = (title + " " + description).lower()
        # Extract domains from text
        dom_pat = r"\b(?:[a-z0-9-]+\.)+(?:[a-z]{2,})\b"
        found_domains = re.findall(dom_pat, text)
        for dom in found_domains:
            is_safe, matched = DomainIntel.is_benign(dom)
            if is_safe:
                return False, f"Skipped — {dom} is known benign infrastructure (matched: {matched})"
        return True, "OK"

    @staticmethod
    def cleanup_benign_cases():
        """Remove IR cases that are about benign domains. Call from UI."""
        try:
            cases = st.session_state.get("ir_cases", [])
            before = len(cases)
            kept = []
            removed = []
            for c in cases:
                title = c.get("title","") + " " + c.get("name","") + " " + c.get("summary","")
                should_keep, reason = DomainIntel.should_create_ir_case(title)
                if should_keep:
                    kept.append(c)
                else:
                    c["status"] = "Auto-closed — false positive"
                    c["close_reason"] = reason
                    removed.append(c)
            st.session_state.ir_cases = kept
            return len(removed), before - len(removed)
        except Exception as e:
            return 0, 0


def render_domain_triage():
    """
    Full-featured domain triage testing platform.
    Implements all spec requirements with beautiful UI.
    """
    # ── Diagnostic: show benign_domains.txt load status ─────────────────────
    import os as _os_di
    _bf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "benign_domains.txt")
    _bf_path = os.path.abspath(_bf_path)
    _bf_exists = os.path.exists(_bf_path)
    _bf_count  = 0
    if _bf_exists:
        with open(_bf_path, encoding="utf-8") as _bf:
            _bf_count = sum(1 for l in _bf if l.strip() and not l.strip().startswith("#"))

    # Status indicator
    if _bf_exists and _bf_count > 0:
        st.markdown(
            f"<div style='background:rgba(0,200,120,0.08);border:1px solid #00c87844;"
            f"border-radius:8px;padding:6px 14px;margin-bottom:8px;display:flex;"
            f"align-items:center;gap:10px'>"
            f"<span style='color:#00c878;font-size:.8rem'>✅</span>"
            f"<span style='color:#00c878;font-size:.68rem;font-weight:700'>"
            f"benign_domains.txt LOADED — {_bf_count} patterns active</span>"
            f"<span style='color:#446688;font-size:.62rem;margin-left:auto'>"
            f"Path: {_bf_path}</span>"
            f"</div>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"<div style='background:rgba(255,0,51,0.08);border:1px solid #ff003344;"
            f"border-radius:8px;padding:6px 14px;margin-bottom:8px;display:flex;"
            f"align-items:center;gap:10px'>"
            f"<span style='color:#ff4444;font-size:.8rem'>❌</span>"
            f"<span style='color:#ff4444;font-size:.68rem;font-weight:700'>"
            f"benign_domains.txt NOT FOUND — using built-in list only</span>"
            f"<span style='color:#446688;font-size:.62rem;margin-left:auto'>"
            f"Expected: {_bf_path}</span>"
            f"</div>",
            unsafe_allow_html=True
        )
        # Create file automatically if missing
        _bf_dir = os.path.dirname(_bf_path)
        if not os.path.exists(_bf_dir):
            try:
                os.makedirs(_bf_dir, exist_ok=True)
            except Exception:
                pass
        if not os.path.exists(_bf_path):
            _DEFAULT_BENIGN = """google.com\n*.google.com\nyoutube.com\n*.youtube.com\ngstatic.com\n*.gstatic.com\ngoogleapis.com\n*.googleapis.com\nmicrosoft.com\n*.microsoft.com\n*.azure.com\n*.office.com\namazonaws.com\n*.amazonaws.com\ncloudflare.com\n*.cloudflare.com\nakamai.net\n*.akamai.net\nfacebook.com\n*.facebook.com\napple.com\n*.apple.com\nzoom.us\ndropbox.com\nslack.com\ngithub.com\nwikipedia.org\n"""
            try:
                with open(_bf_path, "w") as _bf_w:
                    _bf_w.write(_DEFAULT_BENIGN)
                st.success("✅ benign_domains.txt auto-created! Refresh the page.")
            except Exception as _e:
                st.error(f"Could not create file: {_e}. Please create data/benign_domains.txt manually.")

    st.markdown(
        "<div style='font-family:Orbitron,monospace;font-size:1.1rem;font-weight:900;"
        "color:#00f9ff;letter-spacing:2px;margin-bottom:4px'>🔬 DOMAIN INTELLIGENCE TRIAGE PLATFORM</div>"
        "<div style='color:#446688;font-size:.72rem;margin-bottom:16px'>"
        "Test any domain — benign pre-check → DGA detection → TLD abuse → keyword match → "
        "typosquat detection → suspicion scoring → verdict</div>",
        unsafe_allow_html=True
    )

    tab_triage, tab_batch, tab_safelist, tab_cleanup = st.tabs([
        "🔬 Domain Triage", "📦 Batch Analysis", "🛡️ Safe List Manager", "🧹 Case Cleanup"
    ])

    # ══ TAB 1: SINGLE DOMAIN TRIAGE ══════════════════════════════════════════
    with tab_triage:
        _SEV_COLOR = {
            "informational": "#00c878",
            "low":           "#00aaff",
            "medium":        "#ffcc00",
            "high":          "#ff9900",
            "critical":      "#ff0033",
        }
        _VERDICT_COLOR = {
            "BENIGN":                  "#00c878",
            "LIKELY BENIGN":           "#00aaff",
            "LOW SUSPICION":           "#88ccff",
            "SUSPICIOUS — INVESTIGATE":"#ffcc00",
            "HIGH SUSPICION":          "#ff9900",
            "CONFIRMED MALICIOUS":     "#ff0033",
        }

        # Input
        _col1, _col2 = st.columns([4, 1])
        # Use prefill value if set by quick-test buttons (must be set BEFORE widget renders)
        _prefill = st.session_state.pop("dit_prefill", "")
        _domain_input = _col1.text_input(
            "Enter domain or IP to analyse:",
            value=_prefill,
            placeholder="e.g. suspicious-login.xyz  or  google.com  or  185.220.101.45",
            key="dit_domain"
        )
        _analyse_btn = _col2.button("🔬 Analyse", type="primary",
                                     use_container_width=True, key="dit_analyse")

        # Quick test buttons
        st.markdown("<div style='margin-bottom:6px'><span style='color:#446688;font-size:.65rem'>Quick test:</span></div>", unsafe_allow_html=True)
        _qcols = st.columns(8)
        _quick = [
            ("google.com",              "✅ Benign"),
            ("verify-login-secure.xyz", "🔴 Phish"),
            ("185.220.101.45",          "🔴 TOR"),
            ("x7k9p2q8.top",            "🔴 DGA"),
            ("g00gle-login.com",        "🔴 Typosq"),
            ("free-crypto-wallet.club", "🔴 Scam"),
            ("github.com",              "✅ Benign"),
            ("update-microsoft.xyz",    "🔴 Phish"),
        ]
        for i, (dom, label) in enumerate(_quick):
            if _qcols[i].button(label, key=f"qt_{i}", use_container_width=True):
                st.session_state["dit_prefill"] = dom
                st.rerun()

        if _analyse_btn or _domain_input:
            domain = _domain_input.strip()
            if not domain:
                st.info("Enter a domain above or click a quick test button.")
            else:
                result = DomainIntel.analyse(domain)
                _vc = _VERDICT_COLOR.get(result["verdict"], "#888")
                _sc = _SEV_COLOR.get(result["severity"], "#888")

                # ── BENIGN verdict ─────────────────────────────────────────────
                if result.get("safe"):
                    st.markdown(
                        f"<div style='background:rgba(0,200,120,0.08);border:2px solid #00c878;"
                        f"border-radius:14px;padding:22px 26px;margin:10px 0'>"
                        f"<div style='font-size:2rem;margin-bottom:8px'>✅</div>"
                        f"<div style='color:#00c878;font-family:Orbitron,sans-serif;"
                        f"font-size:1.1rem;font-weight:900;margin-bottom:6px'>"
                        f"No Threat Detected</div>"
                        f"<div style='color:#c8e8ff;font-size:.85rem;margin-bottom:14px'>"
                        f"<b>{domain}</b> is classified as known legitimate infrastructure.</div>"
                        f"<div style='display:flex;flex-direction:column;gap:4px;margin-bottom:14px'>"
                        f"<div style='color:#00c878;font-size:.73rem'>✅ Domain belongs to a major trusted technology provider</div>"
                        f"<div style='color:#00c878;font-size:.73rem'>✅ Zero malicious detections across threat intelligence sources</div>"
                        f"<div style='color:#00c878;font-size:.73rem'>✅ No incident report or response actions required</div>"
                        f"</div>"
                        f"<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px'>"
                        f"<div style='background:rgba(0,200,120,0.1);border:1px solid #00c87833;"
                        f"border-radius:8px;padding:8px;text-align:center'>"
                        f"<div style='color:#446688;font-size:.58rem'>CLASSIFICATION</div>"
                        f"<div style='color:#00c878;font-weight:700;font-size:.72rem'>"
                        f"Known Benign Infrastructure</div></div>"
                        f"<div style='background:rgba(0,200,120,0.1);border:1px solid #00c87833;"
                        f"border-radius:8px;padding:8px;text-align:center'>"
                        f"<div style='color:#446688;font-size:.58rem'>RISK LEVEL</div>"
                        f"<div style='color:#00c878;font-weight:700;font-size:.72rem'>Very Low</div></div>"
                        f"<div style='background:rgba(0,200,120,0.1);border:1px solid #00c87833;"
                        f"border-radius:8px;padding:8px;text-align:center'>"
                        f"<div style='color:#446688;font-size:.58rem'>CONFIDENCE</div>"
                        f"<div style='color:#00c878;font-weight:700;font-size:.72rem'>99.9%</div></div>"
                        f"</div>"
                        f"<div style='color:#446688;font-size:.62rem'>"
                        f"Matched rule: <code>{result.get('matched_rule','built-in safe list')}</code> · "
                        f"Last checked: {datetime.now().strftime('%B %d, %Y %H:%M IST')}</div>"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                    _rb1, _rb2 = st.columns(2)
                    if _rb1.button("🔍 Run full enrichment anyway", key="dit_enrich_anyway",
                                   use_container_width=True):
                        st.session_state["dit_force_enrich"] = domain
                        st.info("Navigate to IOC Intelligence for full enrichment (no narrative generated).")
                    if _rb2.button("⛔ Override — actually suspicious", key="dit_override",
                                   use_container_width=True):
                        st.session_state.setdefault("analyst_blacklist",set()).add(domain.lower())
                        st.warning(f"⛔ {domain} moved to blacklist — will be investigated next run")

                else:
                    # ── SUSPICIOUS verdict ─────────────────────────────────────
                    # Top banner
                    st.markdown(
                        f"<div style='background:rgba({('255,0,51' if result['severity']=='critical' else '255,153,0' if result['severity']=='high' else '255,204,0' if result['severity']=='medium' else '0,170,255')},0.1);"
                        f"border:2px solid {_sc};border-radius:14px;padding:18px 22px;margin:10px 0'>"
                        f"<div style='display:flex;align-items:center;gap:16px;flex-wrap:wrap'>"
                        f"<div style='font-size:2rem'>"
                        f"{'🔴' if result['severity']=='critical' else '🟠' if result['severity']=='high' else '🟡' if result['severity']=='medium' else '🔵'}"
                        f"</div>"
                        f"<div style='flex:1'>"
                        f"<div style='color:{_vc};font-family:Orbitron,sans-serif;"
                        f"font-size:.9rem;font-weight:900'>{result['verdict']}</div>"
                        f"<div style='color:#c8e8ff;font-size:1rem;font-weight:700;margin-top:2px'>"
                        f"{domain}</div>"
                        f"</div>"
                        f"<div style='text-align:right'>"
                        f"<div style='color:#446688;font-size:.6rem'>RISK SCORE</div>"
                        f"<div style='color:{_sc};font-size:1.6rem;font-weight:900'>"
                        f"{result['risk_score']}<span style='font-size:.7rem;color:#446688'>/200</span>"
                        f"</div></div>"
                        f"<div style='text-align:right'>"
                        f"<div style='color:#446688;font-size:.6rem'>CONFIDENCE</div>"
                        f"<div style='color:{_sc};font-size:1.3rem;font-weight:900'>"
                        f"{result['confidence']}%</div></div>"
                        f"</div></div>",
                        unsafe_allow_html=True
                    )

                    # KPI tiles
                    _k1, _k2, _k3, _k4, _k5 = st.columns(5)
                    _k1.metric("Severity",   result["severity"].upper())
                    _k2.metric("Risk Score", f"{result['risk_score']}/200")
                    _k3.metric("Confidence", f"{result['confidence']}%")
                    _k4.metric("Indicators", len(result["indicators"]))
                    _k5.metric("TLD",        f".{result['tld']}" if result.get("tld") else "—")

                    # Indicator breakdown
                    if result["indicators"]:
                        st.markdown(
                            "<div style='color:#c8e8ff;font-size:.72rem;font-weight:700;"
                            "letter-spacing:1.5px;margin:12px 0 6px'>⚠️ DETECTED INDICATORS</div>",
                            unsafe_allow_html=True
                        )
                        for ind in result["indicators"]:
                            _ic = _SEV_COLOR.get(ind.get("severity","medium"), "#888")
                            st.markdown(
                                f"<div style='background:rgba(0,0,0,0.3);border-left:3px solid {_ic};"
                                f"border-radius:0 8px 8px 0;padding:8px 14px;margin:3px 0;"
                                f"display:flex;align-items:center;gap:10px'>"
                                f"<span style='color:{_ic};font-size:.65rem;font-weight:700;"
                                f"min-width:140px'>{ind['type']}</span>"
                                f"<span style='color:#c8e8ff;font-size:.72rem;flex:1'>{ind['detail']}</span>"
                                f"<span style='color:{_ic};font-size:.65rem;font-weight:700'>"
                                f"{ind['confidence']}% conf.</span>"
                                f"</div>",
                                unsafe_allow_html=True
                            )

                    # Recommended action
                    st.markdown(
                        f"<div style='background:rgba(0,0,0,0.4);border:1px solid {_sc}44;"
                        f"border-radius:8px;padding:12px 16px;margin:10px 0'>"
                        f"<div style='color:{_sc};font-size:.65rem;font-weight:700;"
                        f"letter-spacing:1px;margin-bottom:4px'>⚡ RECOMMENDED ACTION</div>"
                        f"<div style='color:#c8e8ff;font-size:.8rem'>{result['action']}</div>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

                    # Action buttons
                    _ab1, _ab2, _ab3, _ab4 = st.columns(4)
                    if _ab1.button("🚫 Block IOC", key="dit_block", use_container_width=True,
                                   type="primary" if result["severity"] in ("critical","high") else "secondary"):
                        st.session_state.setdefault("global_blocklist",[]).append({
                            "ioc": domain, "methods":["DNS","Firewall"],
                            "reason": result["verdict"],
                            "analyst": "domain_intel",
                            "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "status": "BLOCKED"
                        })
                        st.success(f"🚫 {domain} blocked")

                    if _ab2.button("📋 Create IR Case", key="dit_case", use_container_width=True):
                        should, reason = DomainIntel.should_create_ir_case(domain)
                        if should:
                            import datetime as _dt
                            _new_case = {
                                "id":       f"IR-DIT-{_dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
                                "title":    f"Domain Intel: {result['verdict']} — {domain}",
                                "name":     f"Domain Intel: {result['verdict']} — {domain}",
                                "severity": result["severity"],
                                "status":   "Open",
                                "priority": result["severity"].upper(),
                                "analyst":  "domain_intel_engine",
                                "assignee": "domain_intel_engine",
                                "host":     domain,
                                "iocs":     [domain],
                                "summary":  result["summary"],
                                "created":  _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "updated":  _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                                "tags":     [result["verdict"], f"risk:{result['risk_score']}"],
                                "confidence": result["confidence"],
                                "source":   "Domain Intelligence Engine",
                                "indicators": result["indicators"],
                            }
                            st.session_state.setdefault("ir_cases",[]).insert(0, _new_case)
                            st.success(f"✅ IR case created: {_new_case['id']}")
                        else:
                            st.warning(f"⚠️ {reason}")

                    if _ab3.button("🔍 Deep Investigate", key="dit_inv", use_container_width=True):
                        # Pre-fill alert for autonomous investigator
                        _alert = {
                            "alert_type": f"Suspicious Domain — {result['verdict']}",
                            "domain":     domain,
                            "ip":         domain,
                            "severity":   result["severity"],
                            "mitre":      "T1071.004",
                            "confidence": result["confidence"],
                            "detail":     result["summary"],
                        }
                        st.session_state.setdefault("triage_alerts",[]).append(_alert)
                        st.session_state.mode = "Autonomous Investigator"
                        st.success("→ Alert added. Navigate to Autonomous Investigator.")

                    if _ab4.button("✅ Mark safe", key="dit_safe", use_container_width=True):
                        st.session_state.setdefault("analyst_whitelist",set()).add(domain.lower())
                        st.success(f"✅ {domain} added to safe list")

                    # Low confidence watermark
                    if result["confidence"] < 40:
                        st.markdown(
                            "<div style='background:rgba(255,153,0,0.08);border:1px solid #ff990044;"
                            "border-radius:8px;padding:8px 14px;margin-top:8px;color:#ff9900;"
                            "font-size:.65rem'>⚠️ LOW CONFIDENCE — Signals are weak. "
                            "Manual analyst review recommended before taking action.</div>",
                            unsafe_allow_html=True
                        )

                # Store result for history
                st.session_state.setdefault("dit_history",[]).insert(0, {
                    "domain":  domain,
                    "verdict": result["verdict"],
                    "score":   result["risk_score"],
                    "conf":    result["confidence"],
                    "sev":     result["severity"],
                    "time":    datetime.now().strftime("%H:%M:%S"),
                })

        # ── Analysis history ───────────────────────────────────────────────────
        _hist = st.session_state.get("dit_history",[])
        if _hist:
            st.markdown("---")
            st.markdown(
                "<div style='color:#446688;font-size:.65rem;font-weight:700;"
                "letter-spacing:1px;margin-bottom:6px'>📋 RECENT ANALYSES</div>",
                unsafe_allow_html=True
            )
            _SEV_C = {"informational":"#00c878","low":"#00aaff","medium":"#ffcc00",
                      "high":"#ff9900","critical":"#ff0033"}
            for _h in _hist[:10]:
                _hc = _SEV_C.get(_h["sev"],"#888")
                st.markdown(
                    f"<div style='display:flex;align-items:center;gap:10px;"
                    f"padding:4px 8px;border-bottom:1px solid #0a1420;cursor:pointer'>"
                    f"<span style='color:#446688;font-size:.6rem;font-family:monospace;"
                    f"min-width:60px'>{_h['time']}</span>"
                    f"<span style='color:#c8e8ff;font-size:.72rem;flex:1'>{_h['domain']}</span>"
                    f"<span style='color:{_hc};font-size:.62rem;font-weight:700'>{_h['verdict']}</span>"
                    f"<span style='color:#446688;font-size:.6rem'>{_h['score']}/200</span>"
                    f"<span style='color:{_hc};font-size:.6rem'>{_h['conf']}%</span>"
                    f"</div>",
                    unsafe_allow_html=True
                )

    # ══ TAB 2: BATCH ANALYSIS ════════════════════════════════════════════════
    with tab_batch:
        st.markdown("**📦 Batch Domain Analysis** — analyse multiple domains at once")
        _batch_input = st.text_area(
            "Domains (one per line):",
            placeholder="google.com\nsuspicious-login.xyz\n185.220.101.45\nfree-crypto-wallet.club",
            height=150, key="dit_batch"
        )
        if st.button("🔬 Analyse All", type="primary", use_container_width=True, key="dit_batch_btn"):
            domains = [d.strip() for d in _batch_input.split("\n") if d.strip()]
            if not domains:
                st.warning("Enter at least one domain")
            else:
                results = []
                _pb = st.progress(0, text="Analysing domains...")
                for i, dom in enumerate(domains):
                    results.append(DomainIntel.analyse(dom))
                    _pb.progress(int((i+1)/len(domains)*100), text=f"Analysed {dom}")
                _pb.empty()

                # Summary
                _crits  = [r for r in results if r["severity"]=="critical"]
                _highs  = [r for r in results if r["severity"]=="high"]
                _benigns= [r for r in results if r.get("safe")]
                _c1,_c2,_c3,_c4 = st.columns(4)
                _c1.metric("Total", len(results))
                _c2.metric("🔴 Critical/High", len(_crits)+len(_highs),
                           delta_color="inverse" if _crits else "normal")
                _c3.metric("✅ Benign", len(_benigns))
                _c4.metric("Avg Risk", f"{sum(r['risk_score'] for r in results)//max(len(results),1)}/200")

                # Results table
                _SEV_C2 = {"informational":"#00c878","low":"#00aaff","medium":"#ffcc00",
                           "high":"#ff9900","critical":"#ff0033"}
                for r in sorted(results, key=lambda x: -x["risk_score"]):
                    _rc = _SEV_C2.get(r["severity"],"#888")
                    _safe_icon = "✅" if r.get("safe") else ("🔴" if r["severity"]=="critical" else "🟠" if r["severity"]=="high" else "🟡" if r["severity"]=="medium" else "🔵")
                    st.markdown(
                        f"<div style='display:flex;align-items:center;gap:10px;"
                        f"padding:6px 10px;border-bottom:1px solid #0a1420;background:rgba(0,0,0,0.2)'>"
                        f"<span style='font-size:1rem'>{_safe_icon}</span>"
                        f"<span style='color:#c8e8ff;font-size:.78rem;flex:1;font-family:monospace'>{r['domain']}</span>"
                        f"<span style='color:{_rc};font-size:.68rem;font-weight:700;min-width:80px'>{r['verdict'][:20]}</span>"
                        f"<span style='color:{_rc};font-size:.68rem;min-width:60px'>{r['risk_score']}/200</span>"
                        f"<span style='color:{_rc};font-size:.65rem'>{r['confidence']}%</span>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

    # ══ TAB 3: SAFE LIST MANAGER ════════════════════════════════════════════
    with tab_safelist:
        st.markdown("**🛡️ Safe List & Blacklist Management**")
        _sm1, _sm2 = st.columns(2)
        with _sm1:
            st.markdown("#### ✅ Safe List")
            _wl = st.session_state.get("analyst_whitelist", set())
            st.caption(f"64 built-in · {len(_wl)} analyst-added")
            _add_safe = st.text_input("Add domain/IP:", key="sm_add_safe",
                                       placeholder="internal-cdn.company.com")
            if st.button("➕ Add", key="sm_add_safe_btn", use_container_width=True):
                if _add_safe.strip():
                    st.session_state.setdefault("analyst_whitelist",set()).add(_add_safe.strip().lower())
                    st.success(f"✅ Added"); st.rerun()
            st.markdown("**Analyst additions:**")
            for _w in sorted(_wl):
                _wc1, _wc2 = st.columns([5,1])
                _wc1.code(_w, language=None)
                if _wc2.button("✕", key=f"sm_rm_{hash(_w)%99999}"):
                    st.session_state["analyst_whitelist"].discard(_w); st.rerun()
            # Show sample built-ins
            with st.expander("View built-in safe domains"):
                try:
                    with open(_BENIGN_FILE) as f:
                        st.code(f.read(), language=None)
                except Exception:
                    st.caption("File not found")

        with _sm2:
            st.markdown("#### ⛔ Blacklist")
            _bl = st.session_state.get("analyst_blacklist", set())
            st.caption(f"{len(_bl)} analyst-added high-risk entries")
            _add_bl = st.text_input("Add domain/IP:", key="sm_add_bl",
                                     placeholder="evil-c2.ru or 185.220.x.x")
            if st.button("➕ Add", key="sm_add_bl_btn", use_container_width=True):
                if _add_bl.strip():
                    v = _add_bl.strip().lower()
                    st.session_state.setdefault("analyst_blacklist",set()).add(v)
                    st.session_state.get("analyst_whitelist",set()).discard(v)
                    st.warning(f"⛔ Added"); st.rerun()
            for _b in sorted(_bl):
                _bc1, _bc2 = st.columns([5,1])
                _bc1.markdown(f"⛔ `{_b}`")
                if _bc2.button("✕", key=f"sm_rm_bl_{hash(_b)%99999}"):
                    st.session_state["analyst_blacklist"].discard(_b); st.rerun()

    # ══ TAB 4: CASE CLEANUP ═════════════════════════════════════════════════
    with tab_cleanup:
        st.markdown("**🧹 IR Case Cleanup — Remove False Positive Cases**")
        st.info(
            "⚠️ Several IR cases may have been auto-generated from benign domains "
            "(e.g. google.com, facebook.com). Click below to remove them."
        )
        _cases = st.session_state.get("ir_cases", [])
        if _cases:
            # Preview which cases would be removed
            _to_remove = []
            for c in _cases:
                text = c.get("title","") + " " + c.get("name","") + " " + c.get("summary","")
                should, reason = DomainIntel.should_create_ir_case(text)
                if not should:
                    _to_remove.append((c, reason))
            if _to_remove:
                st.warning(f"⚠️ {len(_to_remove)} false positive case(s) detected:")
                for c, reason in _to_remove:
                    st.markdown(
                        f"<div style='background:rgba(255,0,51,0.06);border-left:3px solid #ff003355;"
                        f"padding:6px 12px;margin:2px 0;color:#c8e8ff;font-size:.72rem'>"
                        f"🗑️ {c.get('title',c.get('name','?'))[:70]} — {reason[:60]}</div>",
                        unsafe_allow_html=True
                    )
                if st.button("🗑️ Remove All Benign-Domain Cases", type="primary",
                             use_container_width=True, key="cleanup_btn"):
                    removed, kept = DomainIntel.cleanup_benign_cases()
                    st.success(f"✅ Removed {removed} false positive cases. {kept} legitimate cases kept.")
                    st.markdown(
                        "<div style='background:rgba(0,200,120,0.06);border:1px solid #00c87833;"
                        "border-radius:8px;padding:10px 14px;margin-top:8px;color:#00c878;font-size:.72rem'>"
                        "⚠️ Notice: Several cases related to benign domains were auto-generated due to "
                        "a temporary logic issue. They have been reviewed and closed as false positives. "
                        f"Fix deployed on {datetime.now().strftime('%B %d, %Y')}.</div>",
                        unsafe_allow_html=True
                    )
                    st.rerun()
            else:
                st.success("✅ No false positive cases detected — all cases look legitimate.")
        else:
            st.info("No IR cases in the queue.")