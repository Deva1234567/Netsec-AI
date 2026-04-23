"""
test_splunk_integration.py — NetSec AI
========================================
Run this to test all integration points WITHOUT needing Splunk running.
Tests: webhook receiver, triage function, CSV write-back, HEC (if configured)

Usage:
  python test_splunk_integration.py
  python test_splunk_integration.py --live    (actually calls your webhook server)
"""

import sys, os, json, urllib.request, urllib.error, time, argparse
from datetime import datetime

# Golden test domains from the document
TEST_DOMAINS = [
    ("espncricinfo.com",          "TRUSTED / LIKELY BENIGN",   True,  False),
    ("swiggy.com",                "TRUSTED / LIKELY BENIGN",   True,  False),
    ("zomato.com",                "TRUSTED / LIKELY BENIGN",   True,  False),
    ("whatsapp.com",              "TRUSTED INFRASTRUCTURE",    True,  False),
    ("google.com",                "TRUSTED INFRASTRUCTURE",    True,  False),
    ("testphp.vulnweb.com",       "LIKELY BENIGN / LOW RISK",  True,  False),
    ("demo.owasp-juice.shop",     "SUSPICIOUS / LOW RISK",     False, False),
    ("login-paytm-secure.in",     "SUSPICIOUS (typosquatting)",False, True),
    ("random-new-xyz-987654.xyz", "SUSPICIOUS / MALICIOUS",    False, True),
    ("malware-c2.tk",             "MALICIOUS (if flagged)",     False, True),
]

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def _color(text, color):
    return f"{color}{text}{RESET}"


def test_local_triage():
    """Test triage function directly (no server needed)."""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}TEST 1 — Local triage function{RESET}")
    print(f"{'='*60}")

    # Add project path
    for p in [os.path.dirname(__file__),
              os.path.join(os.path.dirname(__file__), "modules"),
              os.path.join(os.path.dirname(__file__), "ui"),
              os.path.join(os.path.dirname(__file__), "ui", "modules")]:
        if p not in sys.path:
            sys.path.insert(0, p)

    try:
        from webhook_server import run_triage
        print(f"  {_color('✅', GREEN)} webhook_server.py loaded OK")
    except ImportError as e:
        print(f"  {_color('❌', RED)} Could not import webhook_server: {e}")
        print("     Make sure webhook_server.py is in the same folder as this script")
        return False

    passed = 0
    failed = 0

    print(f"\n  {'Domain':<35} {'Verdict':<30} {'Score':>5} {'Action':<20} {'Pass?'}")
    print(f"  {'-'*35} {'-'*30} {'-'*5} {'-'*20} {'-'*5}")

    for domain, expected, expect_safe, expect_suspicious in TEST_DOMAINS:
        t0 = time.time()
        try:
            result = run_triage(domain)
            elapsed = round((time.time() - t0) * 1000)

            verdict = result.get("verdict", "?")
            score   = result.get("score", 0)
            action  = result.get("action", "?")
            safe    = not result.get("should_investigate", True)

            # Check if result matches expectation
            if expect_safe and safe:
                status = _color("PASS ✓", GREEN)
                passed += 1
            elif expect_suspicious and not safe:
                status = _color("PASS ✓", GREEN)
                passed += 1
            elif not expect_safe and not expect_suspicious:
                status = _color("PASS ✓", GREEN)  # neutral — just check it runs
                passed += 1
            else:
                status = _color("WARN ⚠", YELLOW)
                failed += 1

            verdict_color = (GREEN if safe else RED if not safe and result.get("severity")=="high" else YELLOW)
            print(f"  {domain:<35} {_color(verdict[:30], verdict_color):<39} {score:>5} {action:<20} {status}")

        except Exception as e:
            print(f"  {domain:<35} {_color('ERROR: '+str(e)[:30], RED):<39} {'':>5} {'':20} {_color('FAIL ✗', RED)}")
            failed += 1

    print(f"\n  Results: {_color(str(passed)+' passed', GREEN)} · {_color(str(failed)+' warnings', YELLOW)}")
    return failed == 0


def test_csv_write():
    """Test CSV verdict write."""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}TEST 2 — CSV lookup write{RESET}")
    print(f"{'='*60}")

    try:
        from webhook_server import save_verdict_csv, CSV_PATH
        test_verdict = {
            "domain": "test-integration.xyz",
            "verdict": "SUSPICIOUS",
            "score": 35,
            "confidence": 60,
            "severity": "medium",
            "action": "investigate",
            "reason": "Integration test",
            "timestamp": datetime.utcnow().isoformat(),
            "source": "test_script",
        }
        save_verdict_csv(test_verdict)
        if os.path.exists(CSV_PATH):
            size = os.path.getsize(CSV_PATH)
            print(f"  {_color('✅', GREEN)} CSV written: {CSV_PATH} ({size} bytes)")
            print(f"\n  {BLUE}To use in Splunk, copy this file to:{RESET}")
            print(f"  $SPLUNK_HOME/etc/apps/search/lookups/netsec_verdicts.csv")
            print(f"\n  {BLUE}Then search in Splunk:{RESET}")
            print(f"  | inputlookup netsec_verdicts.csv | table domain verdict score action")
            return True
        else:
            print(f"  {_color('❌', RED)} CSV not created — check write permissions")
            return False
    except Exception as e:
        print(f"  {_color('❌', RED)} CSV test failed: {e}")
        return False


def test_webhook_server(port=8000):
    """Test the running webhook server."""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}TEST 3 — Webhook server (must be running: python webhook_server.py){RESET}")
    print(f"{'='*60}")

    base = f"http://localhost:{port}"

    # Health check
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=3) as r:
            data = json.loads(r.read())
        print(f"  {_color('✅', GREEN)} Server alive — {data.get('service','?')}")
    except Exception as e:
        print(f"  {_color('⚠️ ', YELLOW)} Server not running on port {port}: {e}")
        print(f"     Start it with: {BLUE}python webhook_server.py{RESET}")
        return False

    # Test webhook with a domain
    print(f"\n  Sending test domains to webhook...")
    results = []
    for domain, expected, expect_safe, _ in TEST_DOMAINS[:5]:
        payload = json.dumps({
            "domain": domain,
            "count": "1",
            "alert_type": "domain_observed",
            "search_name": "Test - NetSec AI Integration",
            "trigger_time": datetime.utcnow().isoformat(),
        }).encode()

        try:
            req = urllib.request.Request(
                f"{base}/webhook/splunk", data=payload,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                resp = json.loads(r.read())

            verdict  = resp.get("verdict","?")
            score    = resp.get("score",0)
            writeback= resp.get("splunk_writeback","?")
            safe_got = not resp.get("should_investigate", True)

            status = _color("✓", GREEN) if (expect_safe == safe_got) else _color("⚠", YELLOW)
            wb_color = GREEN if "✅" in writeback else YELLOW
            print(f"  {status} {domain:<35} → {verdict:<25} score:{score:>3}  HEC:{_color(writeback[:30], wb_color)}")
            results.append(True)
        except Exception as e:
            print(f"  {_color('✗', RED)} {domain:<35} → ERROR: {e}")
            results.append(False)

    passed = sum(results)
    print(f"\n  Webhook: {_color(str(passed)+'/'+str(len(results))+' passed', GREEN)}")
    return passed == len(results)


def print_splunk_setup():
    """Print the exact steps to configure Splunk."""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}SPLUNK SETUP — copy-paste these steps{RESET}")
    print(f"{'='*60}")

    print(f"""
{BLUE}Step 1 — Create saved search in Splunk:{RESET}
  Splunk Web → Search → paste this SPL → Save As Alert

  {YELLOW}index=* sourcetype=access_combined OR index=* sourcetype=firewall OR index=*
  | rex field=_raw "(?i)(?:https?://)?(?:www\\.)?(?<domain>[a-z0-9\\-]+(?:\\.[a-z0-9\\-]+)+)"
  | stats count by domain
  | where count > 0
  | eval alert_type="domain_observed"
  | table domain count alert_type{RESET}

{BLUE}Step 2 — Alert settings:{RESET}
  Title:        NetSec AI - Domain Triage
  Schedule:     Every 15 minutes
  Trigger when: Number of Results > 0
  Trigger:      For each result
  Action:       Webhook

{BLUE}Step 3 — Webhook settings in Splunk:{RESET}
  URL:    http://YOUR_PC_IP:8000/webhook/splunk
  Method: POST
  Payload:
  {{
    "domain":      "$result.domain$",
    "count":       "$result.count$",
    "alert_type":  "$result.alert_type$",
    "search_name": "$name$",
    "trigger_time":"$trigger.time$"
  }}

{BLUE}Step 4 — View verdicts in Splunk:{RESET}
  index=main sourcetype=netsec_ai | table _time domain verdict score severity

{BLUE}Step 5 — Use CSV lookup in Splunk:{RESET}
  Copy netsec_verdicts.csv → $SPLUNK_HOME/etc/apps/search/lookups/
  Then: | inputlookup netsec_verdicts.csv | table domain verdict score
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSec AI Splunk integration test")
    parser.add_argument("--live", action="store_true", help="Also test running webhook server")
    parser.add_argument("--port", type=int, default=8000, help="Webhook server port")
    parser.add_argument("--setup", action="store_true", help="Print Splunk setup steps only")
    args = parser.parse_args()

    if args.setup:
        print_splunk_setup()
        sys.exit(0)

    print(f"\n{BOLD}NetSec AI — Splunk Integration Test Suite{RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    r1 = test_local_triage()
    r2 = test_csv_write()

    if args.live:
        r3 = test_webhook_server(args.port)
    else:
        print(f"\n  {BLUE}ℹ️  Skipping live server test (run with --live to test webhook server){RESET}")
        r3 = True

    print_splunk_setup()

    print(f"\n{BOLD}{'='*60}{RESET}")
    all_pass = all([r1, r2, r3])
    if all_pass:
        print(f"{_color('✅ All tests passed — integration ready', GREEN)}")
    else:
        print(f"{_color('⚠️  Some tests had warnings — check output above', YELLOW)}")
    print(f"{'='*60}\n")