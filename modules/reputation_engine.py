"""
NetSec AI — Reputation Scoring Engine  v12.0
=============================================
v12 FIXES (on top of v11):
  ✅ FIX 1 — sources_used tracks every API that returns data → no more 0/7
  ✅ FIX 2 — keyword_score >= 2 + tld_risk >= 30 → force -60 (escalate LOW RISK → SUSPICIOUS)
  ✅ FIX 3 — comment stripper: "amaz0n.co  # tricky" → "amaz0n.co" before processing
  ✅ FIX 4 — confidence boost: convergence of 3+ signals → +20 confidence (capped 99)
  ✅ FIX 5 — benign score floor: established domains always score >= 90 (not flat 10)
  ✅ FIX 6 — ASN intelligence stub (real call when ipinfo key present)
  ✅ FIX 7 — Passive DNS resolution check (NXDOMAIN → suspicious signal)
  ✅ FIX 8 — Domain age API stub (whoisxml / ipinfo — plugs into age heuristic)
"""

import os
import re
import math
import json
import time
import socket
import hashlib
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR    = os.path.join(_THIS_DIR, "..", "data")
_CACHE_FILE  = os.path.join(_DATA_DIR, "reputation_cache.json")
_TRANCO_FILE = os.path.join(_DATA_DIR, "tranco_top100k.txt")

# ── TLD tables ─────────────────────────────────────────────────────────────────
_TLD_SAFE = {
    "com","net","org","edu","gov","mil","int",
    "in","uk","co.uk","io","ai","de","fr","jp",
    "au","ca","eu","nz","sg","ie","nl","se","no",
}

_TLD_RISK_WEIGHTS = {
    "tk":50,"ml":50,"ga":50,"cf":50,"gq":50,
    "su":45,"ru":40,"zip":40,"mov":40,
    "cn":35,"pw":35,
    "xyz":30,"top":30,"icu":30,"cc":30,
    "club":25,"site":25,"online":25,
    "live":20,"fun":20,"shop":20,"space":20,
    "info":15,"biz":15,"name":10,"mobi":10,
}

_PHISHING_KEYWORDS = {
    "login","signin","sign-in","logon","auth","authenticate",
    "verify","verification","secure","security","account",
    "update","reset","recover","recovery","confirm","validate",
    "activate","billing","payment","pay","invoice","refund",
    "claim","redeem","reward","gift","bonus","free","win",
    "crypto","wallet","bitcoin","invest","bank","paypal",
    "support","helpdesk","portal","gateway","webmail","cpanel",
}

_AUTH_ACTION_KEYWORDS = {
    "login","signin","sign-in","auth","authenticate","verify",
    "verification","secure","security","account","update","reset",
    "confirm","validate","activate","password","credential",
    "support","helpdesk","portal","2fa","mfa","recover",
}

_BRAND_OFFICIAL_DOMAINS = {
    "google":       {"google.com","google.co.","googleapis.com","gstatic.com","googlevideo.com"},
    "microsoft":    {"microsoft.com","microsoftonline.com","office.com","office365.com",
                     "live.com","outlook.com","azure.com","bing.com","msn.com"},
    "paypal":       {"paypal.com","paypal.me","paypalobjects.com"},
    "apple":        {"apple.com","icloud.com","itunes.com","mzstatic.com"},
    "amazon":       {"amazon.com","amazon.co.","amazonaws.com","amazon.in",
                     "amazon.de","amazon.fr","amazon.co.uk"},
    "facebook":     {"facebook.com","fb.com","fbcdn.net","meta.com"},
    "instagram":    {"instagram.com"},
    "twitter":      {"twitter.com","x.com","twimg.com"},
    "linkedin":     {"linkedin.com"},
    "netflix":      {"netflix.com","nflxvideo.net"},
    "spotify":      {"spotify.com","scdn.co"},
    "github":       {"github.com","github.io","githubusercontent.com"},
    "dropbox":      {"dropbox.com","dropboxusercontent.com"},
    "adobe":        {"adobe.com","adobelogin.com"},
    "steam":        {"steampowered.com","steamcommunity.com"},
    "discord":      {"discord.com","discord.gg","discordapp.com"},
    "zoom":         {"zoom.us","zoom.com"},
    "whatsapp":     {"whatsapp.com","whatsapp.net"},
    "telegram":     {"telegram.org","t.me"},
    "ebay":         {"ebay.com","ebay.co.uk"},
    "chase":        {"chase.com"},
    "wellsfargo":   {"wellsfargo.com"},
    "bankofamerica":{"bankofamerica.com"},
    "sbi":          {"sbi.co.in","onlinesbi.com"},
    "hdfc":         {"hdfc.com","hdfcbank.com"},
    "icici":        {"icicibank.com","icicidirect.com","icici.com","icicibank.co.in"},
    "paytm":        {"paytm.com"},
    "zomato":       {"zomato.com"},
    "swiggy":       {"swiggy.com"},
}

# ✅ FIX 5 — Established domains get a score FLOOR of 90
_KNOWN_OLD_DOMAINS = {
    "google.com","youtube.com","facebook.com","twitter.com","amazon.com",
    "microsoft.com","apple.com","netflix.com","linkedin.com","instagram.com",
    "wikipedia.org","github.com","reddit.com","stackoverflow.com",
    "yahoo.com","bing.com","live.com","outlook.com","office.com",
    "azure.com","amazonaws.com","cloudflare.com","akamai.com",
    "zoom.us","slack.com","dropbox.com","box.com","salesforce.com",
    "adobe.com","oracle.com","ibm.com","cisco.com","intel.com",
    "samsung.com","sony.com","lg.com","hp.com","dell.com",
    "paypal.com","stripe.com","visa.com","mastercard.com",
    "hsbc.com","citi.com","barclays.com","sbi.co.in","hdfc.com",
    "icicibank.com","rbi.org.in","gov.in","nic.in","cert-in.org.in",
    "gov.uk","gov.au","gc.ca","europa.eu",
    "nytimes.com","bbc.com","cnn.com","reuters.com","bloomberg.com",
    "wsj.com","theguardian.com","economist.com","forbes.com",
    "twitch.tv","discord.com","telegram.org","whatsapp.com",
    "spotify.com","soundcloud.com","tiktok.com","snapchat.com",
    "pinterest.com","tumblr.com","medium.com","substack.com",
    "cloudfront.net","fastly.net","gstatic.com","googleapis.com",
    "fbcdn.net","akamaized.net","twimg.com","cdnjs.cloudflare.com",
    "wordpress.com","wix.com","squarespace.com","shopify.com",
    "espncricinfo.com","cricbuzz.com","ndtv.com","timesofindia.com",
    "indiatimes.com","rediff.com","moneycontrol.com","livemint.com",
    "economictimes.com","zomato.com","swiggy.com","flipkart.com",
    "myntra.com","paytm.com","phonepe.com","razorpay.com",
}

# Known malicious ASNs (stub — extend as needed)
_MALICIOUS_ASN_KEYWORDS = {
    "bulletproof","offshore","sharktech","serverius","combahton",
    "frantech","buyvm","alexhost","aez network","datacamp",
}

SCORE_MALICIOUS  = 75
SCORE_SUSPICIOUS = 40


# ══════════════════════════════════════════════════════════════════════════════
class ReputationEngine:
# ══════════════════════════════════════════════════════════════════════════════

    # ── Cache ──────────────────────────────────────────────────────────────────
    @staticmethod
    def _load_cache() -> dict:
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            if os.path.exists(_CACHE_FILE):
                with open(_CACHE_FILE, encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    @staticmethod
    def _save_cache(cache: dict):
        try:
            os.makedirs(_DATA_DIR, exist_ok=True)
            with open(_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def _cache_get(key: str):
        cache = ReputationEngine._load_cache()
        entry = cache.get(key)
        if not entry:
            return None
        ttl = 86400 * 7 if entry.get("safe") else 86400
        if time.time() - entry.get("ts", 0) > ttl:
            return None
        return entry

    @staticmethod
    def _cache_set(key: str, data: dict):
        cache = ReputationEngine._load_cache()
        data["ts"] = time.time()
        cache[key] = data
        if len(cache) > 5000:
            oldest = sorted(cache.items(), key=lambda x: x[1].get("ts", 0))[:500]
            for k, _ in oldest:
                del cache[k]
        ReputationEngine._save_cache(cache)

    # ── ✅ FIX 3: Comment stripper ─────────────────────────────────────────────
    @staticmethod
    def _clean_input(raw: str) -> str:
        """Strip inline comments and whitespace. 'amaz0n.co  # tricky' → 'amaz0n.co'"""
        return raw.split("#")[0].strip().lower()

    # ── Tranco / established domain check ─────────────────────────────────────
    @staticmethod
    def _is_in_top_list(domain: str) -> tuple:
        d = domain.lower()
        if d in _KNOWN_OLD_DOMAINS:
            return True, "known-established-domain"
        for known in _KNOWN_OLD_DOMAINS:
            if d.endswith("." + known):
                return True, f"subdomain-of-{known}"
        try:
            if os.path.exists(_TRANCO_FILE):
                with open(_TRANCO_FILE, encoding="utf-8") as f:
                    for line in f:
                        td = line.strip().lower()
                        if td and (d == td or d.endswith("." + td)):
                            return True, "tranco-top-100k"
        except Exception:
            pass
        return False, ""

    # ── Entropy ────────────────────────────────────────────────────────────────
    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f/n) * math.log2(f/n) for f in freq.values())

    # ── Brand Impersonation ────────────────────────────────────────────────────
    @staticmethod
    def _detect_brand_impersonation(domain: str) -> tuple:
        d = domain.lower()
        for brand, official_patterns in _BRAND_OFFICIAL_DOMAINS.items():
            if brand not in d:
                continue
            is_official = any(
                d == pat or d.endswith("." + pat) or pat in d
                for pat in official_patterns
            )
            if is_official:
                continue
            auth_kws = [kw for kw in _AUTH_ACTION_KEYWORDS if kw in d]
            if auth_kws:
                detail = (
                    f"🚨 PHISHING LIKELY: '{brand}' impersonation + "
                    f"auth keywords [{', '.join(auth_kws[:3])}] — NOT official domain."
                )
                return 70, "🚨 Brand Impersonation + Auth Keywords", detail, True
            else:
                detail = (
                    f"⚠️ Brand squatting: '{brand}' in domain but NOT "
                    f"an official {brand} domain."
                )
                return 50, "⚠️ Brand Impersonation", detail, False
        return 0, "", "", False

    # ── Age heuristic ──────────────────────────────────────────────────────────
    @staticmethod
    def _estimate_age_score(domain: str) -> tuple:
        d    = domain.lower()
        in_top, why = ReputationEngine._is_in_top_list(d)
        if in_top:
            return 40, f"Established domain ({why}) — age > 5 years estimated"
        tld   = d.rsplit(".", 1)[-1] if "." in d else ""
        label = d.split(".")[0] if "." in d else d
        if len(label) <= 8 and tld in _TLD_SAFE and label.isalpha():
            return 20, f"Short clean label on trusted TLD (.{tld})"
        digits = sum(c.isdigit() for c in label)
        if digits >= 3 or len(label) > 18:
            return -15, "Long/numeric label — possibly newly registered"
        if tld in _TLD_RISK_WEIGHTS:
            return -35, f"High-abuse TLD (.{tld}) — commonly new/malicious"
        return 0, "Age unknown"

    # ── TLD scoring ────────────────────────────────────────────────────────────
    @staticmethod
    def _score_tld(domain: str) -> tuple:
        d   = domain.lower()
        tld = d.rsplit(".", 1)[-1] if "." in d else ""
        if tld in _TLD_SAFE:
            return +15, f".{tld} — trusted TLD"
        if tld in _TLD_RISK_WEIGHTS:
            penalty = _TLD_RISK_WEIGHTS[tld]
            tier = ("EXTREME" if penalty >= 45 else "HIGH" if penalty >= 35 else "MEDIUM")
            return -penalty, f".{tld} — {tier} abuse TLD (risk weight: -{penalty})"
        return 0, f".{tld} — TLD reputation unknown"

    # ── DGA Detection ─────────────────────────────────────────────────────────
    @staticmethod
    def _detect_dga(domain: str) -> tuple:
        d     = domain.lower()
        label = d.split(".")[0] if "." in d else d
        if len(label) < 6:
            return 0, "", 0.0
        ent           = ReputationEngine._entropy(label)
        vowels        = sum(1 for c in label if c in "aeiou")
        vowel_ratio   = vowels / max(len(label), 1)
        cons_clusters = len(re.findall(r"[bcdfghjklmnpqrstvwxyz]{4,}", label))
        digit_ratio   = sum(c.isdigit() for c in label) / max(len(label), 1)
        dga_score = 0
        reasons   = []
        if ent > 4.0:
            dga_score += 3
            reasons.append(f"entropy={ent:.2f} (very high)")
        elif ent > 3.5:
            dga_score += 2
            reasons.append(f"entropy={ent:.2f} (high)")
        if vowel_ratio < 0.15 and len(label) > 8:
            dga_score += 2
            reasons.append(f"vowel_ratio={vowel_ratio:.0%}")
        if cons_clusters >= 2:
            dga_score += 1
            reasons.append(f"consonant_clusters={cons_clusters}")
        if digit_ratio > 0.3 and len(label) > 10:
            dga_score += 2
            reasons.append(f"digit_ratio={digit_ratio:.0%}")
        if len(label) > 20:
            dga_score += 1
            reasons.append(f"label_length={len(label)}")
        if dga_score >= 5:
            return -50, f"🤖 DGA High Confidence — {' | '.join(reasons)}", ent
        elif dga_score >= 3:
            return -30, f"🤖 DGA Likely — {' | '.join(reasons)}", ent
        elif dga_score >= 2:
            return -15, f"🤖 DGA Possible — {' | '.join(reasons)}", ent
        return 0, "", ent

    # ── ✅ FIX 7: Passive DNS resolution check ────────────────────────────────
    @staticmethod
    def _check_dns_resolution(domain: str) -> tuple:
        """
        Resolves domain. NXDOMAIN = slightly suspicious (dead/never-existed).
        Fast fail: 1s timeout via socket.
        """
        is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain))
        if is_ip:
            return 0, ""
        try:
            socket.setdefaulttimeout(1.5)
            socket.gethostbyname(domain)
            return +5, "DNS: resolves — domain exists"
        except socket.gaierror:
            return -15, "DNS: NXDOMAIN — domain does not resolve (dead/newly registered)"
        except Exception:
            return 0, "DNS: check inconclusive"

    # ── ✅ FIX 6: ASN intelligence ────────────────────────────────────────────
    @staticmethod
    def _check_asn(ip: str, ipinfo_key: str = "") -> tuple:
        """
        Looks up ASN for an IP via ipinfo.io.
        Flags known bulletproof/malicious hosting providers.
        """
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            return 0, ""
        try:
            import urllib.request as _ur, json as _j
            _url = f"https://ipinfo.io/{ip}/json"
            _headers = {}
            if ipinfo_key:
                _headers["Authorization"] = f"Bearer {ipinfo_key}"
            _req = _ur.Request(_url, headers=_headers)
            with _ur.urlopen(_req, timeout=3) as r:
                data = _j.loads(r.read())
            org = data.get("org", "").lower()
            asn = data.get("asn", {}).get("asn", "") if isinstance(data.get("asn"), dict) else ""
            country = data.get("country", "")

            for kw in _MALICIOUS_ASN_KEYWORDS:
                if kw in org:
                    return -30, f"ASN: '{org}' — known bulletproof/malicious hosting"

            high_risk_countries = {"RU", "KP", "IR", "BY"}
            if country in high_risk_countries:
                return -15, f"ASN: Hosted in {country} — elevated risk country"

            if any(k in org for k in ("google","cloudflare","amazon","microsoft","akamai","fastly")):
                return +10, f"ASN: {org} — major trusted provider"

            return 0, f"ASN: {org or 'unknown'}"
        except Exception as e:
            return 0, f"ASN: lookup unavailable ({str(e)[:30]})"

    # ── ✅ FIX 8: Domain age via WhoisXML (stub) ───────────────────────────────
    @staticmethod
    def _check_domain_age(domain: str, whoisxml_key: str = "") -> tuple:
        """
        Real domain age check via WhoisXML API.
        Falls back to heuristic if key not set.
        """
        is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain))
        if is_ip or not whoisxml_key:
            return 0, "Domain age: API key not configured (using heuristic)"
        try:
            import urllib.request as _ur, json as _j, urllib.parse as _up
            _url = (f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
                    f"?apiKey={whoisxml_key}&domainName={_up.quote(domain)}"
                    f"&outputFormat=JSON")
            with _ur.urlopen(_url, timeout=4) as r:
                data = _j.loads(r.read())
            created = data.get("WhoisRecord", {}).get("createdDate", "")
            if created:
                try:
                    from datetime import datetime as _dt
                    age_days = (_dt.utcnow() - _dt.fromisoformat(created[:10])).days
                    if age_days < 30:
                        return -25, f"Domain age: {age_days} days — VERY NEW (high risk)"
                    elif age_days < 180:
                        return -10, f"Domain age: {age_days} days — recently registered"
                    elif age_days > 365 * 3:
                        return +20, f"Domain age: {age_days // 365}y — established"
                    return 0, f"Domain age: {age_days} days"
                except Exception:
                    pass
        except Exception:
            pass
        return 0, "Domain age: lookup failed"

    # ── Final Decision Engine ──────────────────────────────────────────────────
    @staticmethod
    def _final_decision(
        heuristic_score: int,
        brand_critical: bool,
        phishing_kw_count: int,
        dga_penalty: int,
        tld_penalty: int,
        api_signals: list,
    ) -> tuple:
        forced_verdict   = None
        confidence_boost = 0
        reasons          = []

        if brand_critical:
            forced_verdict   = "HIGH SUSPICION"
            confidence_boost = 40
            reasons.append("Brand impersonation + auth keywords")

        # ✅ FIX 2 — keyword convergence with bad TLD → escalate
        if phishing_kw_count >= 2 and tld_penalty >= 30:
            if forced_verdict is None:
                forced_verdict = "SUSPICIOUS"
            confidence_boost += 25
            reasons.append(f"{phishing_kw_count} phishing kws + risky TLD → force SUSPICIOUS")

        if phishing_kw_count >= 3:
            if forced_verdict is None:
                forced_verdict = "SUSPICIOUS"
            confidence_boost += 20
            reasons.append(f"{phishing_kw_count} phishing keywords")

        if dga_penalty >= 50:
            if forced_verdict is None:
                forced_verdict = "SUSPICIOUS"
            confidence_boost += 15
            reasons.append("High-confidence DGA")

        if dga_penalty >= 50 and tld_penalty >= 45:
            forced_verdict = "HIGH SUSPICION"
            confidence_boost += 20
            reasons.append("DGA + extreme-abuse TLD")

        if tld_penalty >= 40 and phishing_kw_count >= 1:
            if forced_verdict is None:
                forced_verdict = "SUSPICIOUS"
            confidence_boost += 10
            reasons.append("Abused TLD + phishing keyword")

        api_bad = sum(1 for s in api_signals
                      if "malicious" in s.lower() or "high" in s.lower())
        if api_bad >= 2:
            confidence_boost += 15
            reasons.append(f"{api_bad} API sources flagging bad")

        # ✅ FIX 4 — signal convergence boost
        total_signals = (
            (1 if brand_critical else 0)
            + (1 if phishing_kw_count >= 2 else 0)
            + (1 if dga_penalty >= 30 else 0)
            + (1 if tld_penalty >= 30 else 0)
            + api_bad
        )
        if total_signals >= 3:
            confidence_boost = min(confidence_boost + 20, 99)
            reasons.append(f"{total_signals} converging signals → confidence boost")

        decision_reason = " | ".join(reasons) if reasons else "Standard heuristic scoring"
        return heuristic_score, forced_verdict, confidence_boost, decision_reason

    # ── Main score() — heuristics only ────────────────────────────────────────
    @staticmethod
    def score(domain_or_ip: str, use_apis: bool = True) -> dict:
        """Heuristic-only scoring pipeline."""
        # ✅ FIX 3: strip comments before anything else
        val = ReputationEngine._clean_input(str(domain_or_ip))
        if not val:
            return {"score": 50, "verdict": "UNKNOWN", "signals": [], "sources_used": []}

        cached = ReputationEngine._cache_get(val)
        if cached:
            cached["from_cache"] = True
            return cached

        signals      = []
        total        = 50
        sources_used = []   # ✅ FIX 1: tracked throughout
        is_ip        = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val))

        _brand_critical      = False
        _brand_penalty       = 0
        _dga_penalty_applied = 0
        _tld_penalty_applied = 0
        _kw_count            = 0

        # Signal 1: Known benign list ─────────────────────────────────────────
        in_top, top_reason = ReputationEngine._is_in_top_list(val)
        if in_top:
            # ✅ FIX 5: floor at 90, not whatever 50+80 lands at
            total = max(90, min(100, total + 80))
            signals.append((total - 50, "✅ Established Domain", top_reason))
            sources_used.append("KnownList")
            result = {
                "value":          val,
                "score":          total,
                "verdict":        "SAFE",
                "severity":       "informational",
                "confidence_cap": 5,
                "signals":        signals,
                "sources_used":   sources_used,
                "summary":        f"{val} is a well-established, trusted domain.",
                "safe":           True,
                "from_cache":     False,
                "action":         "No action required",
                "decision_engine":"Known-established list — fast-path SAFE",
            }
            ReputationEngine._cache_set(val, result)
            return result

        # Signal 2: Brand impersonation ───────────────────────────────────────
        brand_penalty, brand_label, brand_detail, brand_critical = \
            ReputationEngine._detect_brand_impersonation(val)
        if brand_penalty > 0:
            signals.append((-brand_penalty, brand_label, brand_detail))
            total -= brand_penalty
            _brand_critical = brand_critical
            _brand_penalty  = brand_penalty
            sources_used.append("BrandEngine")

        # Signal 3: Age heuristic ─────────────────────────────────────────────
        age_delta, age_reason = ReputationEngine._estimate_age_score(val)
        signals.append((age_delta, "📅 Domain Age Estimate", age_reason))
        total += age_delta
        sources_used.append("AgeHeuristic")

        # Signal 4: TLD scoring ───────────────────────────────────────────────
        tld_delta, tld_reason = ReputationEngine._score_tld(val)
        signals.append((tld_delta, "🌐 TLD Reputation", tld_reason))
        total += tld_delta
        if tld_delta < 0:
            _tld_penalty_applied = abs(tld_delta)
        sources_used.append("TLDEngine")

        # Signal 5: DGA detection ─────────────────────────────────────────────
        dga_delta, dga_reason, ent_val = ReputationEngine._detect_dga(val)
        if dga_delta != 0:
            signals.append((dga_delta, "🎲 DGA Detection", dga_reason))
            total += dga_delta
            _dga_penalty_applied = abs(dga_delta)
            sources_used.append("DGAEngine")
        elif ent_val > 0 and ent_val < 2.5 and len(val.split(".")[0]) > 3:
            signals.append((5, "📝 Natural Name", f"Low entropy {ent_val:.2f}"))
            total += 5

        # Signal 6: Phishing keywords ─────────────────────────────────────────
        kw_found  = [kw for kw in _PHISHING_KEYWORDS if kw in val]
        _kw_count = len(kw_found)
        if _kw_count >= 3:
            signals.append((-35, "🎣 Phishing Keywords",
                            f"Multiple phishing keywords: {', '.join(kw_found[:4])}"))
            total -= 35
            sources_used.append("PhishingKW")
        elif _kw_count >= 2:
            signals.append((-20, "🎣 Suspicious Keywords",
                            f"Keywords: {', '.join(kw_found[:3])}"))
            total -= 20
            sources_used.append("PhishingKW")
        elif _kw_count == 1:
            signals.append((-10, "🎣 Keyword Match", f"Keyword: {kw_found[0]}"))
            total -= 10

        # Signal 7: Label length / digit ratio ────────────────────────────────
        label = val.split(".")[0] if "." in val else val
        if len(label) <= 6 and label.isalpha():
            signals.append((10, "📏 Short Clean Name", f"{len(label)} chars"))
            total += 10
        elif len(label) > 25:
            signals.append((-15, "📏 Very Long Domain", f"{len(label)} chars"))
            total -= 15
        digit_ratio = sum(c.isdigit() for c in label) / max(len(label), 1)
        if digit_ratio > 0.4:
            signals.append((-15, "🔢 High Digit Ratio", f"{digit_ratio:.0%}"))
            total -= 15

        # Signal 8: Typosquatting ─────────────────────────────────────────────
        if not _brand_penalty:
            _BRANDS = ["google","microsoft","amazon","apple","facebook","paypal",
                       "netflix","spotify","twitter","linkedin","instagram","github"]
            normalized = val.replace("0","o").replace("1","l").replace("3","e").replace("5","s")
            for brand in _BRANDS:
                if brand in normalized and brand not in val and f"{brand}.com" not in val:
                    signals.append((-40, "⚠️ Typosquatting",
                                   f"Leet-speak impersonation of {brand}"))
                    total -= 40
                    sources_used.append("TyposquatEngine")
                    break

        # Signal 9: Punycode ──────────────────────────────────────────────────
        if "xn--" in val:
            signals.append((-30, "⚠️ Punycode", "IDN homograph attack"))
            total -= 30

        # Signal 10: IP signals ───────────────────────────────────────────────
        if is_ip:
            if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", val):
                signals.append((60, "🏠 Private IP", "Internal/private network"))
                total += 60
            _SAFE_IP_PREFIXES = (
                "8.8.","8.34.","8.35.","142.250.","142.251.","172.217.","216.58.",
                "13.64.","13.107.","20.190.","40.76.","52.84.","52.85.",
                "13.224.","13.225.","104.16.","104.17.","104.18.","1.1.1.","1.0.",
            )
            for pfx in _SAFE_IP_PREFIXES:
                if val.startswith(pfx):
                    signals.append((50, "☁️ Cloud Provider IP", f"Range {pfx}*"))
                    total += 50
                    break

        # Signal 11: DNS resolution check (✅ FIX 7) ──────────────────────────
        dns_delta, dns_reason = ReputationEngine._check_dns_resolution(val)
        if dns_delta != 0:
            signals.append((dns_delta, "🌐 DNS Resolution", dns_reason))
            total += dns_delta
            sources_used.append("PassiveDNS")

        total = max(0, min(100, total))

        # Final Decision Engine ───────────────────────────────────────────────
        _, forced_verdict, confidence_boost, decision_reason = \
            ReputationEngine._final_decision(
                heuristic_score   = total,
                brand_critical    = _brand_critical,
                phishing_kw_count = _kw_count,
                dga_penalty       = _dga_penalty_applied,
                tld_penalty       = _tld_penalty_applied,
                api_signals       = [],
            )

        if forced_verdict == "HIGH SUSPICION":
            total = min(total, 19)
        elif forced_verdict == "SUSPICIOUS":
            total = min(total, 39)

        verdict, severity, conf_cap, action = ReputationEngine._classify(
            total, confidence_boost, forced_verdict
        )

        result = {
            "value":           val,
            "score":           total,
            "verdict":         verdict,
            "severity":        severity,
            "confidence_cap":  conf_cap,
            "signals":         signals,
            "sources_used":    list(set(sources_used)),   # ✅ FIX 1
            "api_used":        [],
            "summary":         f"{val} — {total}/100 ({verdict}). {action}.",
            "safe":            total >= 70,
            "from_cache":      False,
            "action":          action,
            "decision_engine": decision_reason,
            "_brand_critical": _brand_critical,
        }
        ReputationEngine._cache_set(val, result)
        return result

    # ── score_with_apis() — heuristics + real API calls ───────────────────────
    @staticmethod
    def score_with_apis(domain_or_ip: str, session_config: dict = None) -> dict:
        """Full pipeline: heuristics + AbuseIPDB + GreyNoise + VT + OTX + URLScan + ASN."""
        # ✅ FIX 3: strip comments
        val = ReputationEngine._clean_input(str(domain_or_ip))
        cfg = session_config or {}
        try:
            cfg = cfg or st.session_state.get("api_config", {})
        except Exception:
            pass

        base     = ReputationEngine.score(val, use_apis=False)
        total    = base["score"]
        signals  = list(base.get("signals", []))
        api_used = list(base.get("api_used", []))
        sources_used     = list(base.get("sources_used", []))   # ✅ FIX 1
        api_results_text = []
        is_ip            = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val))

        import urllib.request as _ur, urllib.parse as _up, json as _j

        def _get(url, headers=None, timeout=4):
            try:
                req = _ur.Request(url, headers=headers or {})
                with _ur.urlopen(req, timeout=timeout) as r:
                    return _j.loads(r.read())
            except Exception:
                return None

        # 1. AbuseIPDB ─────────────────────────────────────────────────────────
        _abuse_key = cfg.get("abuseipdb_key","") or os.getenv("ABUSEIPDB_API_KEY","")
        if _abuse_key and is_ip:
            d = _get(f"https://api.abuseipdb.com/api/v2/check"
                     f"?ipAddress={_up.quote(val)}&maxAgeInDays=90",
                     {"Key": _abuse_key, "Accept": "application/json"})
            if d:                                                # ✅ FIX 1
                score = d.get("data",{}).get("abuseConfidenceScore",-1)
                if score >= 70:
                    total -= 35
                    signals.append((-35,"🚨 AbuseIPDB",f"Abuse score {score}% — HIGH"))
                    api_results_text.append(f"AbuseIPDB high-abuse {score}%")
                elif score >= 30:
                    total -= 15
                    signals.append((-15,"⚠️ AbuseIPDB",f"Abuse score {score}% — MEDIUM"))
                    api_results_text.append(f"AbuseIPDB medium {score}%")
                elif score >= 0:
                    total += 25
                    signals.append((+25,"✅ AbuseIPDB",f"Abuse score {score}% — CLEAN"))
                    api_results_text.append(f"AbuseIPDB clean {score}%")
                api_used.append("AbuseIPDB")
                sources_used.append("AbuseIPDB")              # ✅ FIX 1

        # 2. GreyNoise ─────────────────────────────────────────────────────────
        _gn_key = cfg.get("greynoise_key","") or os.getenv("GREYNOISE_API_KEY","")
        if _gn_key and is_ip:
            d = _get(f"https://api.greynoise.io/v3/community/{val}",
                     {"key": _gn_key, "Accept": "application/json"})
            if d:                                                # ✅ FIX 1
                cls = d.get("classification","")
                if cls == "malicious":
                    total -= 50
                    signals.append((-50,"🔴 GreyNoise","MALICIOUS — targeted scanner"))
                    api_results_text.append("GreyNoise malicious")
                elif cls == "benign":
                    total += 20
                    signals.append((+20,"✅ GreyNoise","BENIGN — known safe scanner"))
                elif d.get("noise"):
                    total += 20
                    signals.append((+20,"📡 GreyNoise","Internet noise — mass scanner"))
                api_used.append("GreyNoise")
                sources_used.append("GreyNoise")              # ✅ FIX 1

        # 3. VirusTotal ────────────────────────────────────────────────────────
        _vt_key = cfg.get("virustotal_key","") or os.getenv("VIRUSTOTAL_API_KEY","")
        if _vt_key:
            _vt_type = "ip_addresses" if is_ip else "domains"
            d = _get(f"https://www.virustotal.com/api/v3/{_vt_type}/{val}",
                     {"x-apikey": _vt_key})
            if d:                                                # ✅ FIX 1
                stats = d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                mal   = stats.get("malicious",0)
                harm  = stats.get("harmless",0)
                if mal >= 5:
                    total -= 40
                    signals.append((-40,"🔴 VirusTotal",f"{mal} malicious detections"))
                    api_results_text.append(f"VirusTotal {mal} malicious")
                elif mal >= 1:
                    total -= 20
                    signals.append((-20,"⚠️ VirusTotal",f"{mal} detections"))
                    api_results_text.append(f"VirusTotal {mal} suspicious")
                elif harm > 0:
                    total += 30
                    signals.append((+30,"✅ VirusTotal",f"0 malicious / {harm} harmless"))
                    api_results_text.append("VirusTotal clean")
                api_used.append("VirusTotal")
                sources_used.append("VirusTotal")             # ✅ FIX 1

        # 4. OTX AlienVault ───────────────────────────────────────────────────
        _otx_key = cfg.get("otx_key","") or os.getenv("OTX_API_KEY","")
        if _otx_key:
            _otx_type = "IPv4" if is_ip else "domain"
            d = _get(f"https://otx.alienvault.com/api/v1/indicators/{_otx_type}/{val}/general",
                     {"X-OTX-API-KEY": _otx_key})
            if d:                                                # ✅ FIX 1
                pulses = d.get("pulse_info",{}).get("count",0)
                if pulses >= 3:
                    total -= 30
                    signals.append((-30,"🔴 OTX AlienVault",f"{pulses} malicious pulses"))
                    api_results_text.append(f"OTX {pulses} pulses")
                elif pulses >= 1:
                    total -= 15
                    signals.append((-15,"⚠️ OTX AlienVault",f"{pulses} pulse(s)"))
                    api_results_text.append(f"OTX {pulses} pulse(s)")
                else:
                    total += 10
                    signals.append((+10,"✅ OTX AlienVault","0 malicious pulses"))
                api_used.append("OTX")
                sources_used.append("OTX")                    # ✅ FIX 1

        # 5. URLScan.io ────────────────────────────────────────────────────────
        _urlscan_key = cfg.get("urlscan_key","") or os.getenv("URLSCAN_API_KEY","")
        if _urlscan_key:
            d = _get(f"https://urlscan.io/api/v1/search/?q=domain:{val}&size=5",
                     {"API-Key": _urlscan_key})
            if d and d.get("results"):                           # ✅ FIX 1
                mal_scores = [r.get("verdicts",{}).get("overall",{}).get("score",0)
                              for r in d["results"]]
                avg = sum(mal_scores) / len(mal_scores)
                if avg > 50:
                    total -= 40
                    signals.append((-40,"🔴 URLScan.io",f"Avg score {avg:.0f}"))
                    api_results_text.append(f"URLScan malicious avg {avg:.0f}")
                elif avg > 20:
                    total -= 15
                    signals.append((-15,"⚠️ URLScan.io",f"Avg score {avg:.0f}"))
                else:
                    total += 15
                    signals.append((+15,"✅ URLScan.io",f"Low malicious score ({avg:.0f})"))
                api_used.append("URLScan.io")
                sources_used.append("URLScan.io")             # ✅ FIX 1

        # 6. ASN intelligence (✅ FIX 6) ───────────────────────────────────────
        _ipinfo_key = cfg.get("ipinfo_key","") or os.getenv("IPINFO_API_KEY","")
        if is_ip:
            asn_delta, asn_reason = ReputationEngine._check_asn(val, _ipinfo_key)
            if asn_delta != 0:
                signals.append((asn_delta, "🏢 ASN Intelligence", asn_reason))
                total += asn_delta
                sources_used.append("ASN")                    # ✅ FIX 1
                if asn_delta < 0:
                    api_results_text.append(asn_reason)

        # 7. Domain age API (✅ FIX 8) ──────────────────────────────────────────
        _whois_key = cfg.get("whoisxml_key","") or os.getenv("WHOISXML_API_KEY","")
        if not is_ip and _whois_key:
            age_delta, age_reason = ReputationEngine._check_domain_age(val, _whois_key)
            if age_delta != 0:
                signals.append((age_delta, "📅 Domain Age (API)", age_reason))
                total += age_delta
                sources_used.append("WhoisXML")              # ✅ FIX 1
                if age_delta < 0:
                    api_results_text.append(age_reason)

        total = max(0, min(100, total))

        # Re-run Final Decision Engine with API signals ────────────────────────
        _brand_crit = base.get("_brand_critical", False)
        _kw_ct      = len([s for s in base.get("signals",[])
                           if "keyword" in s[1].lower()])
        _dga_pen    = abs(next((s[0] for s in base.get("signals",[])
                                if "DGA" in s[1]), 0))
        _tld_pen    = abs(next((s[0] for s in base.get("signals",[])
                                if "TLD" in s[1]), 0))

        _, forced_v, conf_boost, decision_reason = ReputationEngine._final_decision(
            heuristic_score   = total,
            brand_critical    = _brand_crit,
            phishing_kw_count = _kw_ct,
            dga_penalty       = _dga_pen,
            tld_penalty       = _tld_pen,
            api_signals       = api_results_text,
        )

        if forced_v == "HIGH SUSPICION":
            total = min(total, 19)
        elif forced_v == "SUSPICIOUS":
            total = min(total, 39)

        verdict, severity, conf_cap, action = ReputationEngine._classify(
            total, conf_boost, forced_v
        )

        base.update({
            "score":          total,
            "signals":        signals,
            "api_used":       api_used,
            "sources_used":   list(set(sources_used)),   # ✅ FIX 1
            "safe":           total >= 70,
            "verdict":        verdict,
            "severity":       severity,
            "confidence_cap": conf_cap,
            "action":         action,
            "decision_engine":decision_reason,
        })
        ReputationEngine._cache_set(val, base)
        return base

    # ── Shared verdict classifier ─────────────────────────────────────────────
    @staticmethod
    def _classify(score: int, confidence_boost: int, forced_verdict):
        if score >= 70:
            v, sev, cap = "SAFE",           "informational", 10
            act = "No action required — strong reputation signals"
        elif score >= 40:
            v, sev, cap = "LOW RISK",       "low",           30
            act = "Monitor passively — limited enrichment"
        elif score >= 20:
            v, sev, cap = "SUSPICIOUS",     "medium",        min(95, 75 + confidence_boost)
            act = "Full investigation recommended"
        else:
            v, sev, cap = "HIGH SUSPICION", "high",          min(99, 90 + confidence_boost)
            act = "Immediate investigation — strong malicious signals"
        if forced_verdict:
            v = forced_verdict
        return v, sev, cap, act

    @staticmethod
    def should_generate_narrative(rep_result: dict) -> tuple:
        score = rep_result.get("score", 50)
        if score >= 70:
            return False, f"Score {score}/100 — SAFE, narrative suppressed"
        if score >= 40:
            return False, f"Score {score}/100 — LOW RISK, enrichment-only"
        return True, f"Score {score}/100 — suspicious, full narrative allowed"


# ══════════════════════════════════════════════════════════════════════════════
# STREAMLIT UI
# ══════════════════════════════════════════════════════════════════════════════

_VERDICT_COLORS = {
    "HIGH SUSPICION": "#ff0033",
    "SUSPICIOUS":     "#ff9900",
    "LOW RISK":       "#ffcc00",
    "SAFE":           "#00c878",
    "UNKNOWN":        "#446688",
}
_VERDICT_BG = {
    "HIGH SUSPICION": "rgba(255,0,51,0.07)",
    "SUSPICIOUS":     "rgba(255,153,0,0.07)",
    "LOW RISK":       "rgba(255,204,0,0.07)",
    "SAFE":           "rgba(0,200,120,0.07)",
    "UNKNOWN":        "rgba(68,102,136,0.07)",
}

# Total possible sources for the "X / N" display
_ALL_SOURCES = [
    "KnownList","BrandEngine","AgeHeuristic","TLDEngine","DGAEngine",
    "PhishingKW","TyposquatEngine","PassiveDNS",
    "AbuseIPDB","GreyNoise","VirusTotal","OTX","URLScan.io","ASN","WhoisXML",
]
_SOURCE_TOTAL = 7   # displayed as X/7 (the 7 external/API sources)
_API_SOURCES  = {"AbuseIPDB","GreyNoise","VirusTotal","OTX","URLScan.io","ASN","WhoisXML"}


def render_reputation_tester():
    """
    Streamlit UI for the Reputation Scoring Engine v12.
    Wired in app.py:  elif mode == "Reputation Scorer": render_reputation_tester()
    """
    st.markdown(
        "<h2 style='margin:0 0 2px'>📊 Reputation Scorer v12</h2>"
        "<p style='color:#5577aa;font-size:.78rem;margin:0 0 14px'>"
        "Brand impersonation · DGA · TLD risk · Phishing intelligence · ASN · DNS · "
        "<b style='color:#00f9ff'>Unified confidence engine</b>"
        "</p>",
        unsafe_allow_html=True,
    )

    cfg = st.session_state.get("api_config", {})

    # ── Source status pills ───────────────────────────────────────────────────
    _pill_sources = [
        ("VirusTotal",   bool(cfg.get("virustotal_key")  or os.getenv("VIRUSTOTAL_API_KEY"))),
        ("AbuseIPDB",    bool(cfg.get("abuseipdb_key")   or os.getenv("ABUSEIPDB_API_KEY"))),
        ("GreyNoise",    bool(cfg.get("greynoise_key")   or os.getenv("GREYNOISE_API_KEY"))),
        ("OTX",          bool(cfg.get("otx_key")         or os.getenv("OTX_API_KEY"))),
        ("URLScan.io",   bool(cfg.get("urlscan_key")     or os.getenv("URLSCAN_API_KEY"))),
        ("ASN/IPInfo",   bool(cfg.get("ipinfo_key")      or os.getenv("IPINFO_API_KEY"))),
        ("WhoisXML",     bool(cfg.get("whoisxml_key")    or os.getenv("WHOISXML_API_KEY"))),
        ("Heuristics",   True),
        ("Brand Engine", True),
        ("DGA Engine",   True),
        ("PassiveDNS",   True),
    ]
    pills = " ".join(
        f"<span style='display:inline-block;padding:2px 10px;border-radius:12px;"
        f"font-size:.72rem;margin:0 3px 6px 0;"
        f"border:1px solid {'#00c878' if ok else '#334455'};"
        f"color:{'#00c878' if ok else '#334455'}'>"
        f"{'●' if ok else '○'} {name}</span>"
        for name, ok in _pill_sources
    )
    st.markdown(pills, unsafe_allow_html=True)

    tab_single, tab_batch, tab_history = st.tabs([
        "🔍 Single Lookup", "📋 Batch Lookup", "📜 History"
    ])

    # ── TAB 1: Single ─────────────────────────────────────────────────────────
    with tab_single:
        col_in, col_btn = st.columns([5, 1])
        with col_in:
            target = st.text_input(
                "Domain or IP",
                placeholder="login-google-auth.net · free-gift-card.tk · 185.220.101.45",
                key="rep_single_input",
                label_visibility="collapsed",
            )
        with col_btn:
            run_single = st.button("🔍 Score", type="primary",
                                   use_container_width=True, key="rep_single_run")

        use_apis = st.toggle(
            "Use live API sources (requires keys in API Config)",
            value=True, key="rep_use_apis"
        )

        if run_single and target.strip():
            clean_target = ReputationEngine._clean_input(target)
            with st.spinner(f"Scoring {clean_target} ..."):
                result = (ReputationEngine.score_with_apis(clean_target, cfg)
                          if use_apis else
                          ReputationEngine.score(clean_target, use_apis=False))
            st.session_state["rep_single_result"] = result
            history = st.session_state.setdefault("rep_history", [])
            history.insert(0, result)
            st.session_state["rep_history"] = history[:200]

        result = st.session_state.get("rep_single_result")
        if result:
            _render_rep_card(result, expanded=True)

    # ── TAB 2: Batch ──────────────────────────────────────────────────────────
    with tab_batch:
        st.markdown("#### 📋 Batch Reputation Lookup")

        if "rep_batch_text" not in st.session_state:
            st.session_state["rep_batch_text"] = ""

        raw = st.text_area(
            "Enter domains/IPs (one per line, comments with # are stripped)",
            value=st.session_state["rep_batch_text"],
            placeholder="login-google-auth.net\nfree-gift-card.tk  # phishing\n185.220.101.45\najd92jd92jd92j.com",
            height=150,
            key="rep_batch_area",
        )
        st.session_state["rep_batch_text"] = raw

        # ✅ FIX 3: strip comments when parsing batch input
        raw_targets = [ReputationEngine._clean_input(line)
                       for line in raw.strip().splitlines()
                       if ReputationEngine._clean_input(line)]
        seen_t, targets_dedup = set(), []
        for t in raw_targets:
            if t not in seen_t:
                seen_t.add(t)
                targets_dedup.append(t)

        if targets_dedup:
            st.info(f"**{len(targets_dedup)} unique targets** ready for scoring")
        else:
            st.info("Enter one domain or IP per line above.")

        batch_use_apis = st.toggle(
            "Use live API sources", value=False, key="rep_batch_apis",
            help="Slower but more accurate — requires API keys"
        )

        if st.button(
            f"📊 Score All {len(targets_dedup)} Targets" if targets_dedup
            else "📊 Run Batch Score",
            type="primary",
            use_container_width=True,
            key="rep_batch_run",
            disabled=not targets_dedup,
        ):
            batch_results = []
            prog = st.progress(0, text="Starting...")
            for idx, t in enumerate(targets_dedup):
                prog.progress(
                    (idx + 1) / len(targets_dedup),
                    text=f"[{idx+1}/{len(targets_dedup)}] Scoring: {t[:60]}...",
                )
                r = (ReputationEngine.score_with_apis(t, cfg)
                     if batch_use_apis else
                     ReputationEngine.score(t, use_apis=False))
                batch_results.append(r)

            prog.empty()
            st.session_state["rep_batch_results"] = batch_results
            history = st.session_state.setdefault("rep_history", [])
            st.session_state["rep_history"] = (batch_results + history)[:200]
            st.success(f"✅ Scored {len(batch_results)} targets.")

        batch_results = st.session_state.get("rep_batch_results", [])
        if batch_results:
            _render_batch_summary(batch_results)
            st.divider()
            for r in batch_results:
                _render_rep_card(r, expanded=False)

            df = pd.DataFrame([{
                "Target":          r.get("value",""),
                "Score":           r.get("score"),
                "Verdict":         r.get("verdict"),
                "Severity":        r.get("severity"),
                "Confidence Cap":  r.get("confidence_cap"),
                "Sources Used":    f"{len([s for s in r.get('sources_used',[]) if s in _API_SOURCES])}/{_SOURCE_TOTAL}",
                "Action":          r.get("action",""),
                "Decision Engine": r.get("decision_engine",""),
                "API Sources":     ", ".join(r.get("api_used",[])),
            } for r in batch_results])
            st.download_button(
                "⬇️ Export Results (CSV)",
                df.to_csv(index=False),
                f"reputation_scan_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                "text/csv",
                key="rep_batch_export",
            )

    # ── TAB 3: History ────────────────────────────────────────────────────────
    with tab_history:
        history = st.session_state.get("rep_history", [])
        if not history:
            st.info("No lookups yet.")
            return

        col_h1, col_h2 = st.columns([4, 1])
        col_h1.markdown(f"**{len(history)} lookups** in session history")
        if col_h2.button("🗑️ Clear History", key="rep_clear_hist"):
            st.session_state["rep_history"] = []
            st.rerun()

        _render_batch_summary(history)
        st.divider()
        for r in history[:50]:
            _render_rep_card(r, expanded=False)


# ── Card renderer ─────────────────────────────────────────────────────────────

def _render_rep_card(r: dict, expanded: bool = False):
    verdict   = r.get("verdict", "UNKNOWN")
    score     = r.get("score", 0)
    color     = _VERDICT_COLORS.get(verdict, "#446688")
    bg        = _VERDICT_BG.get(verdict, "transparent")
    target    = r.get("value") or r.get("ioc") or "—"
    action    = r.get("action", "")
    decision  = r.get("decision_engine", "")
    conf_cap  = r.get("confidence_cap", 0)
    cached    = r.get("from_cache", False)

    # ✅ FIX 1: show real source count
    api_hits  = len([s for s in r.get("sources_used", []) if s in _API_SOURCES])
    src_label = f"{api_hits}/{_SOURCE_TOTAL}"

    st.markdown(
        f"<div style='background:{bg};border-left:4px solid {color};"
        f"padding:12px 16px;margin:6px 0;border-radius:8px'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center'>"
        f"<span style='font-family:monospace;font-size:.9rem;color:#c8e8ff'>{target}</span>"
        f"<span style='color:{color};font-weight:700;font-size:.85rem'>{verdict}</span>"
        f"</div>"
        f"<div style='margin:8px 0 4px;background:rgba(0,0,0,0.3);border-radius:4px;height:6px'>"
        f"<div style='width:{score}%;background:{color};height:6px;border-radius:4px'></div></div>"
        f"<div style='display:flex;gap:16px;font-size:.68rem;color:#446688;margin-top:4px'>"
        f"<span>Safety: <b style='color:{color}'>{score}/100</b></span>"
        f"<span>Confidence Cap: <b style='color:#c8e8ff'>{conf_cap}%</b></span>"
        f"<span>Sources: <b style='color:#c8e8ff'>{src_label}</b></span>"
        f"{'<span style=\"color:#334455\">💾 cached</span>' if cached else ''}"
        f"</div></div>",
        unsafe_allow_html=True,
    )

    if action:
        st.caption(f"⚡ **Action:** {action}")
    if decision and verdict not in ("SAFE", "LOW RISK"):
        st.caption(f"🧠 **Why:** {decision}")

    signals = r.get("signals", [])
    if signals:
        with st.expander(f"📡 Signal breakdown ({len(signals)} signals)", expanded=expanded):
            for delta, label, detail in signals:
                sig_color = "#00c878" if delta > 0 else "#ff4444" if delta < 0 else "#446688"
                sign      = "+" if delta > 0 else ""
                st.markdown(
                    f"<div style='display:flex;gap:10px;padding:3px 0;"
                    f"border-bottom:1px solid #0a1422;font-size:.72rem'>"
                    f"<span style='color:{sig_color};font-family:monospace;"
                    f"min-width:38px;text-align:right'>{sign}{delta}</span>"
                    f"<span style='color:#c8e8ff;min-width:200px'>{label}</span>"
                    f"<span style='color:#446688'>{detail}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
    st.divider()


def _render_batch_summary(results: list):
    high = sum(1 for r in results if r.get("verdict") == "HIGH SUSPICION")
    sus  = sum(1 for r in results if r.get("verdict") == "SUSPICIOUS")
    low  = sum(1 for r in results if r.get("verdict") == "LOW RISK")
    safe = sum(1 for r in results if r.get("verdict") == "SAFE")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("🔴 High Suspicion", high)
    c2.metric("🟠 Suspicious",     sus)
    c3.metric("🟡 Low Risk",       low)
    c4.metric("🟢 Safe",           safe)


# ── Standalone test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    TEST_CASES = [
        ("update-microsoft-security.com",  "HIGH SUSPICION"),
        ("login-google-auth.net",          "HIGH SUSPICION"),
        ("secure-paypal-verification.xyz", "HIGH SUSPICION"),
        ("free-gift-card.tk",              "SUSPICIOUS"),    # ✅ FIX 2
        ("crypto-airdrop.ml",              "SUSPICIOUS"),    # ✅ FIX 2
        ("ajd92jd92jd92j.com",             "HIGH SUSPICION"),
        ("xvk3m9p2q8r5t7y.tk",            "HIGH SUSPICION"),
        ("amaz0n.co  # tricky typo",       "HIGH SUSPICION"),# ✅ FIX 3
        ("espncricinfo.com",               "SAFE"),
        ("google.com",                     "SAFE"),
        ("random-new-xyz-987654.xyz",      "SUSPICIOUS"),
        ("malware-c2.tk",                  "HIGH SUSPICION"),
    ]

    print("\n" + "=" * 80)
    print(f"{'NetSec AI v12 — Reputation Engine Test':^80}")
    print("=" * 80)
    print(f"{'Domain':<44} {'Expected':<18} {'Got':<18} {'Score':>5}  {'Pass?'}")
    print("-" * 80)

    passed = failed = 0
    for domain, expected in TEST_CASES:
        r       = ReputationEngine.score(domain, use_apis=False)
        verdict = r["verdict"]
        score   = r["score"]
        ok      = verdict == expected
        status  = "✅ PASS" if ok else "❌ FAIL"
        if ok: passed += 1
        else:  failed += 1
        clean   = ReputationEngine._clean_input(domain)
        print(f"{clean:<44} {expected:<18} {verdict:<18} {score:>5}  {status}")
        if not ok:
            print(f"  └─ Engine: {r.get('decision_engine','?')}")

    print("-" * 80)
    print(f"Results: {passed} passed / {failed} failed / {len(TEST_CASES)} total")
    print("=" * 80)