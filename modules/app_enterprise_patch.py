"""
app_enterprise_patch.py — NetSec AI v11.0
==========================================
PATCH INSTRUCTIONS for app.py
Add the Enterprise SOC tab to your existing Streamlit app.

1. Copy enterprise_soc.py to your modules/ directory
2. Apply the patches below to app.py

HOW TO APPLY
─────────────
Option A — Manual (recommended):
  Find the section in app.py where your main tabs are defined,
  then follow the patches below.

Option B — Run this file directly to preview the patch locations:
  python3 app_enterprise_patch.py
"""

PATCH_1_DESCRIPTION = """
PATCH 1 — Import enterprise_soc in app.py
──────────────────────────────────────────
Find this block near the top of app.py (after other module imports):

    try:
        from modules.report import ...
    except ImportError:
        ...

Add AFTER it:
"""

PATCH_1_CODE = """\
try:
    from modules.enterprise_soc import render_enterprise_soc
    ENTERPRISE_ENABLED = True
except ImportError:
    try:
        from enterprise_soc import render_enterprise_soc
        ENTERPRISE_ENABLED = True
    except ImportError:
        render_enterprise_soc = None
        ENTERPRISE_ENABLED = False
"""

PATCH_2_DESCRIPTION = """
PATCH 2 — Add tab to main navigation
──────────────────────────────────────
Find in app.py where the main st.tabs() call is — something like:

    tabs = st.tabs(["🏠 Home", "🔍 Triage", "🎯 Detect", ...])

Add  "🏢 Enterprise SOC"  to the list, e.g.:

    tabs = st.tabs([
        "🏠 Home",
        "🔍 Triage",
        "🎯 Detect",
        "🛡️ Respond",
        "🔬 Investigate",
        "📊 Report",
        "⚙️ Advanced",
        "🏢 Enterprise SOC",    # ← ADD THIS
    ])
"""

PATCH_3_DESCRIPTION = """
PATCH 3 — Render the tab content
──────────────────────────────────
In the section that routes each tab (with tabs[0], tabs[1] etc.),
add a new block for the Enterprise SOC tab:

    with tabs[7]:   # adjust index to match your tab order
        if ENTERPRISE_ENABLED and render_enterprise_soc:
            render_enterprise_soc()
        else:
            st.warning(
                "Enterprise SOC module not loaded. "
                "Copy enterprise_soc.py to your modules/ directory."
            )
"""

PATCH_4_DESCRIPTION = """
PATCH 4 — Wire feedback into existing triage results (optional)
────────────────────────────────────────────────────────────────
In your existing triage/verdict display code, after showing a verdict,
add analyst feedback buttons:

    from enterprise_soc import ContinuousLearningStore

    col1, col2, col3 = st.columns(3)
    if col1.button("✅ Confirmed Threat", key=f"fb_conf_{domain}"):
        ContinuousLearningStore.record_feedback(domain, verdict, "confirmed")
        st.success("Feedback recorded — scoring weights will auto-update")
    if col2.button("❌ False Positive", key=f"fb_fp_{domain}"):
        ContinuousLearningStore.record_feedback(domain, verdict, "fp")
        st.success("FP recorded — baseline updated")
    if col3.button("⬆️ Escalate", key=f"fb_esc_{domain}"):
        ContinuousLearningStore.record_feedback(domain, verdict, "escalated")
        st.info("Escalation logged")
"""

PATCH_5_DESCRIPTION = """
PATCH 5 — Wire DynamicRiskScorer into existing reputation flow (optional)
──────────────────────────────────────────────────────────────────────────
In triage.py or wherever you currently compute risk_score, replace:

    risk = 50   # or whatever static value

With:

    from enterprise_soc import DynamicRiskScorer
    drs = DynamicRiskScorer.score(
        ioc           = domain,
        alert_frequency = alert_count,
        domain_entropy  = entropy_value,
        misp_threat_level = misp_result.get("threat_level", "LOW"),
        mitre_count     = len(mitre_tags),
    )
    risk            = drs["composite_score"]
    risk_level      = drs["risk_level"]
    recommendation  = drs["recommendation"]
"""

if __name__ == "__main__":
    print("=" * 65)
    print("NetSec AI v11.0 — Enterprise SOC app.py Patch Guide")
    print("=" * 65)
    for desc, code in [
        (PATCH_1_DESCRIPTION, PATCH_1_CODE),
        (PATCH_2_DESCRIPTION, ""),
        (PATCH_3_DESCRIPTION, ""),
        (PATCH_4_DESCRIPTION, ""),
        (PATCH_5_DESCRIPTION, ""),
    ]:
        print(desc)
        if code:
            print("  Code to add:")
            for line in code.split("\n"):
                print(f"    {line}")
        print()
    print("=" * 65)
    print("After applying patches, run:  streamlit run app.py")
    print("Enterprise SOC tab will appear in the main navigation.")