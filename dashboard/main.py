import time
import pandas as pd
import requests
import streamlit as st

st.set_page_config(
    page_title="AI Red Team Dashboard",
    page_icon="🔴",
    layout="wide",
)

API_BASE_URL = "http://localhost:8080"


def api_get(endpoint: str, params: dict = None):
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"API Error: {e}")
        return []

def api_post(endpoint: str, data: dict):
    try:
        response = requests.post(f"{API_BASE_URL}{endpoint}", json=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"API Error: {e}")
        return None

def api_get_raw(endpoint: str):
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", timeout=10)
        response.raise_for_status()
        return response
    except Exception as e:
        st.error(f"API Error: {e}")
        return None

def main():
    st.title("🔴 AI Red Team Dashboard")
    st.caption("Break the AI. Prove the vulnerability. Verify the fix. — OWASP GenAI LLM Top 10 2026")

    pages = {
        "Overview": show_overview,
        "Targets": show_targets,
        "Scan": show_scan,
        "Findings": show_findings,
        "Evidence": show_evidence,
        "OWASP Coverage": show_owasp_coverage,
        "Remediation": show_remediation,
        "Retest": show_retest,
        "Regression": show_regression,
        "Scan History": show_scan_history,
        "Checklist": show_checklist,
        "Configuration": show_configuration,
        "Attacks": show_attacks,
    }

    # Sidebar with scan launcher quick access
    with st.sidebar:
        st.header("Navigation")
        page = st.selectbox("Go to", list(pages.keys()))
        st.divider()
        st.caption(f"API: {API_BASE_URL}")
        # Quick health
        try:
            h = requests.get(f"{API_BASE_URL}/health", timeout=2).json()
            st.success(f"API {h.get('version','')} ✓")
        except:
            st.error("API unreachable")

    pages[page]()

# --- Overview ---
def show_overview():
    st.header("Overview — Project Progress & Scan Summary")
    col1, col2, col3, col4 = st.columns(4)
    targets = api_get("/targets")
    scans = api_get("/scans")
    findings = []
    tests = []
    for scan in scans:
        findings.extend(api_get(f"/scans/{scan['id']}/findings"))
        tests.extend(api_get(f"/scans/{scan['id']}/tests"))
    with col1:
        st.metric("Targets", len(targets))
    with col2:
        st.metric("Scans", len(scans))
    with col3:
        st.metric("Findings (FAIL)", len(findings))
    with col4:
        # PASS/FAIL counts from latest scan
        if tests:
            pass_c = sum(1 for t in tests if t.get("result") == "PASS")
            fail_c = sum(1 for t in tests if t.get("result") == "FAIL")
            st.metric("Latest PASS/FAIL", f"{pass_c}/{fail_c}")
        else:
            st.metric("Latest PASS/FAIL", "0/0")

    # PASS/FAIL dashboard
    if tests:
        st.subheader("PASS/FAIL Dashboard")
        df = pd.DataFrame(tests)
        counts = df["result"].value_counts()
        st.bar_chart(counts)
        st.dataframe(df[["id","attack_id","category","name","result","severity"]].head(20))

    # Severity dashboard
    if findings:
        st.subheader("Severity Dashboard")
        df = pd.DataFrame(findings)
        sev_counts = df["severity"].value_counts()
        st.bar_chart(sev_counts)

    if scans:
        st.subheader("Recent Scans")
        df = pd.DataFrame(scans[:10])
        cols = [c for c in ["id","target_id","taxonomy_version","status","started_at","completed_at"] if c in df.columns]
        st.dataframe(df[cols])

# --- Targets ---
def show_targets():
    st.header("Targets — Selector & Health Checks")
    tab1, tab2, tab3 = st.tabs(["List & Health", "Add Target", "Target Details"])
    with tab1:
        targets = api_get("/targets")
        if targets:
            df = pd.DataFrame(targets)
            st.dataframe(df[["id","name","target_type","base_url","is_authorized","created_at"]])
            # Health check button per target
            for t in targets:
                col1, col2 = st.columns([3,1])
                with col1:
                    st.write(f"{t['name']} ({t['base_url']}) [{t['target_type']}]")
                with col2:
                    if st.button(f"Health Check {t['id']}", key=f"health_{t['id']}"):
                        try:
                            r = requests.get(f"{t['base_url']}/health", timeout=5)
                            if r.status_code == 200:
                                st.success(f"{t['name']} ✓ {r.json()}")
                            else:
                                st.warning(f"{t['name']} status {r.status_code}")
                        except Exception as e:
                            st.error(f"Health failed: {e}")
        else:
            st.info("No targets configured")

    with tab2, st.form("add_target"):
        name = st.text_input("Name")
        url = st.text_input("URL", placeholder="http://localhost:8000")
        target_type = st.selectbox("Type", ["llm","rag","agent"])
        submitted = st.form_submit_button("Add Target")
        if submitted:
            result = api_post("/targets", {"name": name, "target_type": target_type, "base_url": url, "config": {}})
            if result:
                st.success(f"Target added with ID {result['id']}")
                st.rerun()

    with tab3:
        targets = api_get("/targets")
        if targets:
            tid = st.selectbox("Select Target for Details", options=[t["id"] for t in targets], format_func=lambda x: next(t["name"] for t in targets if t["id"]==x), key="target_details")
            if tid:
                t = next(t for t in targets if t["id"]==tid)
                st.json(t)
                # Show protection checks for this target
                st.subheader("Protection Checks (Blue-Team)")
                checks = api_get("/protections/checks", params={"target_id": tid})
                if checks:
                    df = pd.DataFrame([{"check_id": c["check_id"], "name": c["name"], "passed": c["passed"], "reason": c["reason"]} for c in checks])
                    st.dataframe(df)

# --- Scan (launcher + progress) ---
def show_scan():
    st.header("Scan — Launcher & Progress")
    targets = api_get("/targets")
    if not targets:
        st.warning("Add a target first in Targets page")
        return

    attacks = api_get("/attacks")
    categories = sorted(list(set(a["category"] for a in attacks))) if attacks else []

    with st.form("launcher"):
        col1, col2 = st.columns(2)
        with col1:
            target_id = st.selectbox("Target", options=[t["id"] for t in targets], format_func=lambda x: next(t["name"] for t in targets if t["id"]==x))
            category = st.multiselect("Categories (empty = auto for target type)", options=categories)
        with col2:
            attack_ids = st.multiselect("Specific Attack IDs (optional)", options=[a["attack_id"] for a in attacks] if attacks else [])
            st.caption("Leave both empty to auto-select for target type (per Sprint 2-3).")
        submitted = st.form_submit_button("🚀 Launch Scan")
        if submitted:
            payload = {"target_id": target_id}
            if attack_ids: payload["attack_ids"] = attack_ids
            if category: payload["categories"] = category
            with st.spinner("Creating scan..."):
                scan = api_post("/scans", payload)
                if not scan:
                    st.error("Failed to create scan")
                    return
                st.session_state["last_scan_id"] = scan["id"]
                st.success(f"Scan created ID {scan['id']} — running...")
                # Trigger run
                run_resp = api_post(f"/scans/{scan['id']}/run", {})
                if run_resp:
                    st.success(f"Scan {run_resp['id']} completed: {run_resp['status']}")
                    st.rerun()
                else:
                    # Fallback: poll status
                    st.info("Run triggered, polling...")
                    for _ in range(20):
                        time.sleep(1)
                        s = api_get(f"/scans/{scan['id']}")
                        if s and isinstance(s, dict) and s.get("status") in ["COMPLETED","FAILED"]:
                            st.success(f"Scan {s['id']} {s['status']}")
                            st.rerun()
                            break
                    st.warning("Still running... check Scan History")

    # Progress for last scan
    if "last_scan_id" in st.session_state:
        sid = st.session_state["last_scan_id"]
        st.divider()
        st.subheader(f"Progress — Scan {sid}")
        scan = api_get(f"/scans/{sid}")
        if isinstance(scan, dict) and scan.get("id"):
            st.json({"status": scan.get("status"), "started_at": scan.get("started_at"), "completed_at": scan.get("completed_at")})
            tests = api_get(f"/scans/{sid}/tests")
            if tests:
                df = pd.DataFrame(tests)
                st.dataframe(df[["attack_id","category","name","result","severity","reproduction_count","confidence"]])
                # Progress bar
                done = sum(1 for t in tests if t.get("result") not in ["INCONCLUSIVE", None])
                st.progress(done / len(tests) if tests else 0)
                # PASS/FAIL pie via bar
                counts = pd.Series([t.get("result") for t in tests]).value_counts()
                st.bar_chart(counts)
            # Findings quick
            findings = api_get(f"/scans/{sid}/findings")
            if findings:
                st.warning(f"Findings: {len(findings)}")
                for f in findings:
                    st.write(f"- **{f['attack_id']}** {f['title']} [{f['severity']}] {f['category']}")

    # Also show all scans with run button
    st.divider()
    st.subheader("All Scans — Run / Inspect")
    scans = api_get("/scans")
    if scans:
        df = pd.DataFrame(scans)
        st.dataframe(df[["id","target_id","taxonomy_version","status","started_at","completed_at"]])
        for s in scans[:5]:
            col1, col2, col3 = st.columns([2,1,1])
            with col1:
                st.write(f"Scan {s['id']} [{s['status']}]")
            with col2:
                if st.button(f"Run {s['id']}", key=f"run_{s['id']}"):
                    res = api_post(f"/scans/{s['id']}/run", {})
                    if res: st.success(f"Ran {s['id']} -> {res['status']}")
            with col3:
                if st.button(f"Findings {s['id']}", key=f"find_{s['id']}"):
                    st.session_state["last_scan_id"] = s["id"]
                    st.rerun()

# --- Findings ---
def show_findings():
    st.header("Findings — Severity & Remediation")
    scans = api_get("/scans")
    if not scans:
        st.info("No scans")
        return
    scan_id = st.selectbox("Select Scan", options=[s["id"] for s in scans], format_func=lambda x: f"Scan {x} ({next(s['taxonomy_version'] for s in scans if s['id']==x)})", key="findings_scan")
    if scan_id:
        findings = api_get(f"/scans/{scan_id}/findings")
        if findings:
            df = pd.DataFrame(findings)
            st.dataframe(df[["id","attack_id","category","title","severity","regression_status"]])
            # Severity filter
            sev = st.selectbox("Filter Severity", options=["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"])
            if sev != "ALL":
                findings = [f for f in findings if f["severity"]==sev]
            selected = st.selectbox("View Details", options=[f["id"] for f in findings], format_func=lambda x: next(f["title"] for f in findings if f["id"]==x), key="find_sel")
            if selected:
                f = next(f for f in findings if f["id"]==selected)
                with st.expander("Finding Details", expanded=True):
                    st.json(f)
                with st.expander("Remediation & Retest", expanded=True):
                    st.write(f"**Remediation:** {f['remediation']}")
                    st.write(f"**Protection:** {f['protection_control']}")
                    st.write(f"**Retest:** {f['retest_procedure']}")
                    st.write(f"**Root Cause:** {f['root_cause']}")
                    st.write(f"**Impact:** {f['impact']}")
                # Retest button per finding
                if st.button(f"🔁 Retest Finding {f['id']}", key=f"retest_{f['id']}"):
                    res = api_post(f"/findings/{f['id']}/retest", {})
                    if res:
                        st.success(f"Retest {res['retest_id']} -> {res['regression_status']} ({res['result']})")
                        st.rerun()
        else:
            st.info("No findings for this scan — check Evidence for PASS/INCONCLUSIVE")

# --- Evidence ---
def show_evidence():
    st.header("Evidence — Request/Response/Tool/Retrieval/Detectors/Reproduction (Immutable)")
    st.caption("Every FAIL is reproducible — deterministic detectors, no LLM opinion alone.")
    scans = api_get("/scans")
    if not scans:
        st.info("No scans")
        return
    scan_id = st.selectbox("Select Scan for Evidence", options=[s["id"] for s in scans], format_func=lambda x: f"Scan {x} ({next(s['taxonomy_version'] for s in scans if s['id']==x)})", key="evidence_scan")
    if scan_id:
        evidences = api_get(f"/scans/{scan_id}/evidence")
        if not evidences:
            st.info("No evidence (run scan first)")
            return
        df = pd.DataFrame([{"test_id": e["test_id"], "attack_id": e.get("request",{}).get("attack_id") if isinstance(e.get("request"),dict) else e["test_id"], "result": e["result"], "confidence": e["confidence"], "reproduction": e["reproduction_count"], "detectors": ", ".join(e["detectors_triggered"] or []), "http_status": e["http_status"]} for e in evidences])
        st.dataframe(df)
        test_ids = [e["test_id"] for e in evidences]
        selected = st.selectbox("Select Test for Detailed Evidence", options=test_ids, format_func=lambda x: f"Test {x} - {next(e['result'] for e in evidences if e['test_id']==x)}", key="evidence_test")
        if selected:
            ev = next(e for e in evidences if e["test_id"]==selected)
            with st.expander("Request Capture", expanded=True):
                st.json(ev["request"])
            with st.expander("Response Capture", expanded=True):
                st.json({"http_status": ev["http_status"], "headers": ev["headers"], "response": ev["response"]})
            with st.expander("Tool-Call Capture", expanded=False):
                st.json(ev["tool_calls"] or "No tool calls (LLM/RAG)")
            with st.expander("Retrieval Evidence", expanded=False):
                st.json(ev["retrieved_documents"] or "No retrieval (Agent/LLM)")
            with st.expander("Deterministic Detection", expanded=False):
                st.json({"detectors_triggered": ev["detectors_triggered"], "expected": ev["expected_behavior"], "observed": ev["observed_behavior"], "confidence": ev["confidence"]})
            with st.expander("Reproduction Tracking", expanded=False):
                st.json({"reproduction_count": ev["reproduction_count"], "reproducible": ev["reproduction_count"]>1, "hash": ev.get("evidence_metadata",{}).get("evidence_hash","n/a") if isinstance(ev.get("evidence_metadata"),dict) else "n/a"})
            st.caption("Evidence is immutable once scan is COMPLETED (spec 22). Every FAIL above is reproducible — request/response + detectors prove vulnerability.")
            # Also show comparison via compare endpoint if finding exists
            findings = api_get(f"/scans/{scan_id}/findings")
            for f in findings:
                if f["test_id"]==selected:
                    if st.button(f"Compare Before/After for Finding {f['id']}", key=f"compare_{f['id']}"):
                        comp = api_get(f"/findings/{f['id']}/compare")
                        st.json(comp)

# --- OWASP Coverage ---
def show_owasp_coverage():
    st.header("OWASP Coverage — Taxonomy Version per Scan")
    scans = api_get("/scans")
    if scans:
        versions = pd.Series([s["taxonomy_version"] for s in scans]).value_counts()
        st.bar_chart(versions)
        st.write(f"Current taxonomy: {scans[0]['taxonomy_version']}")
    attacks = api_get("/attacks")
    if attacks:
        df = pd.DataFrame(attacks)
        cov = df["category"].value_counts().sort_index()
        st.subheader("Attacks per OWASP Category")
        st.bar_chart(cov)
        st.dataframe(df[["attack_id","category","name","severity","target_types"]])
        # Checklist-style coverage
        for cat in sorted(set(a["category"] for a in attacks)):
            c_atks = [a for a in attacks if a["category"]==cat]
            st.write(f"**{cat}** — {len(c_atks)} attack(s): {', '.join(a['attack_id'] for a in c_atks)}")

# --- Remediation ---
def show_remediation():
    st.header("Remediation Viewer — Fix & Retest")
    scans = api_get("/scans")
    if not scans:
        st.info("No scans")
        return
    scan_id = st.selectbox("Select Scan for Remediation", options=[s["id"] for s in scans], format_func=lambda x: f"Scan {x}", key="rem_scan")
    if scan_id:
        findings = api_get(f"/scans/{scan_id}/findings")
        if not findings:
            st.info("No findings — all PASS/INCONCLUSIVE")
            return
        for f in findings:
            with st.expander(f"{f['attack_id']} — {f['title']} [{f['severity']}]", expanded=False):
                st.write(f"**Root Cause:** {f['root_cause']}")
                st.write(f"**Impact:** {f['impact']}")
                st.write(f"**Protection:** {f['protection_control']}")
                st.write(f"**Remediation:** {f['remediation']}")
                st.write(f"**Retest Procedure:** {f['retest_procedure']}")
                rem = api_get(f"/attacks/{f['attack_id']}/remediation")
                if rem:
                    st.json(rem)

# --- Retest ---
def show_retest():
    st.header("Retest — Fix Verification (FAIL→PASS)")
    st.caption("Real retest: new scan for same attack, before/after comparison, regression status.")
    scans = api_get("/scans")
    if not scans:
        st.info("No scans")
        return
    scan_id = st.selectbox("Select Original Scan", options=[s["id"] for s in scans], key="retest_scan")
    if scan_id:
        findings = api_get(f"/scans/{scan_id}/findings")
        if not findings:
            st.info("No findings to retest")
            return
        fid = st.selectbox("Select Finding to Retest", options=[f["id"] for f in findings], format_func=lambda x: next(f["attack_id"] for f in findings if f["id"]==x), key="retest_fid")
        if fid:
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button(f"🔁 Retest Finding {fid}", key=f"do_retest_{fid}"):
                    res = api_post(f"/findings/{fid}/retest", {})
                    if res:
                        st.success(f"Retest {res['retest_id']} → {res['regression_status']} ({res['result']})")
                        st.rerun()
            with col2:
                if st.button(f"History {fid}", key=f"hist_{fid}"):
                    hist = api_get(f"/findings/{fid}/history")
                    st.json(hist)
            with col3:
                if st.button(f"Compare {fid}", key=f"comp_{fid}"):
                    comp = api_get(f"/findings/{fid}/compare")
                    st.json(comp)
            # Show history table
            hist = api_get(f"/findings/{fid}/history")
            if hist:
                df = pd.DataFrame(hist)
                st.dataframe(df[["id","scan_id","result","notes","created_at"]])
            comp = api_get(f"/findings/{fid}/compare")
            if comp and comp.get("latest_retest"):
                st.write(f"**Before:** {comp['original_result']} → **After:** {comp['latest_retest']['result']} — Verified: {comp['verified']}")

# --- Regression ---
def show_regression():
    st.header("Regression — History & Lifecycle")
    scans = api_get("/scans")
    if not scans:
        st.info("No scans")
        return
    # Collect all findings across scans
    all_findings = []
    for s in scans:
        all_findings.extend(api_get(f"/scans/{s['id']}/findings"))
    if not all_findings:
        st.info("No findings")
        return
    df = pd.DataFrame(all_findings)
    st.dataframe(df[["id","attack_id","category","title","severity","regression_status"]])
    fid = st.selectbox("Select Finding for Lifecycle", options=[f["id"] for f in all_findings], format_func=lambda x: next(f["attack_id"] for f in all_findings if f["id"]==x), key="reg_fid")
    if fid:
        lc = api_get(f"/findings/{fid}/lifecycle")
        if lc:
            st.json(lc)
            st.write(f"**Current:** {lc['current_status']} — {lc['retest_count']} retests")
            if lc["history"]:
                st.write("**Timeline:**")
                for h in lc["history"]:
                    st.write(f"- Scan {h['scan_id']}: {h['result']} at {h['created_at']}")

# --- Checklist ---
def show_checklist():
    st.header("Project Checklist — Sprint Progress")
    items = api_get("/checklist")
    if not items:
        st.info("No checklist items")
        return
    # Progress per sprint
    sprints = {}
    for it in items:
        sprints.setdefault(it["sprint"], {"total":0, "verified":0})
        sprints[it["sprint"]]["total"] += 1
        if it["status"]=="VERIFIED":
            sprints[it["sprint"]]["verified"] += 1
    for sprint, counts in sorted(sprints.items()):
        pct = counts["verified"]/counts["total"]*100 if counts["total"] else 0
        st.write(f"**{sprint}** — {counts['verified']}/{counts['total']} ({pct:.0f}%)")
        st.progress(pct/100)
    # Detailed
    current_sprint = None
    for item in items:
        if item["sprint"] != current_sprint:
            current_sprint = item["sprint"]
            st.subheader(current_sprint)
        status_icon = {"TODO":"☐","IN_PROGRESS":"◐","VERIFIED":"☑","BLOCKED":"⚠"}.get(item["status"],"?")
        col1, col2 = st.columns([4,1])
        with col1:
            st.write(f"{status_icon} {item['task']}")
        with col2:
            new_status = st.selectbox("Status", ["TODO","IN_PROGRESS","VERIFIED","BLOCKED"], index=["TODO","IN_PROGRESS","VERIFIED","BLOCKED"].index(item["status"]), key=f"status_{item['id']}")
            if new_status != item["status"]:
                api_post(f"/checklist/{item['id']}", {"status": new_status})
                st.rerun()

# --- Scan History ---
def show_scan_history():
    st.header("Scan History — All Scans")
    scans = api_get("/scans")
    if not scans:
        st.info("No scans")
        return
    df = pd.DataFrame(scans)
    cols = [c for c in ["id","target_id","taxonomy_version","status","started_at","completed_at","created_at"] if c in df.columns]
    st.dataframe(df[cols])
    # Per-scan detail
    sid = st.selectbox("Select Scan for Details", options=[s["id"] for s in scans], key="hist_scan")
    if sid:
        tests = api_get(f"/scans/{sid}/tests")
        if tests:
            st.subheader("Tests")
            st.dataframe(pd.DataFrame(tests)[["attack_id","category","name","result","severity","reproduction_count","confidence"]])
        findings = api_get(f"/scans/{sid}/findings")
        if findings:
            st.subheader("Findings")
            st.dataframe(pd.DataFrame(findings)[["attack_id","title","severity","regression_status"]])
        evidences = api_get(f"/scans/{sid}/evidence")
        if evidences:
            st.subheader("Evidence Summary")
            st.json([{"test_id": e["test_id"], "result": e["result"], "detectors": e["detectors_triggered"]} for e in evidences])
        # Report buttons
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button(f"JSON Report {sid}", key=f"json_{sid}"):
                r = api_get_raw(f"/scans/{sid}/report?format=json")
                if r: st.json(r.json())
        with col2:
            if st.button(f"Markdown {sid}", key=f"md_{sid}"):
                r = api_get_raw(f"/scans/{sid}/report?format=markdown")
                if r: st.text(r.text[:3000])
        with col3:
            if st.button(f"HTML {sid}", key=f"html_{sid}"):
                r = api_get_raw(f"/scans/{sid}/report?format=html")
                if r: st.write("HTML generated (open via API)")

# --- Configuration ---
def show_configuration():
    st.header("Configuration — Budgets, Taxonomy, Targets")
    # Show settings via health or config endpoint? For now show taxonomy
    scans = api_get("/scans")
    if scans:
        st.write(f"**Current Taxonomy:** {scans[0]['taxonomy_version']}")
    attacks = api_get("/attacks")
    if attacks:
        st.write(f"**Total Attacks:** {len(attacks)}")
    # Show allowed targets hint
    st.info("Target authorization: localhost by default, explicit allowlist required for remote (see app/security/authorization.py:14)")
    st.write("**Budgets (per scan):** max_requests 100, max_tokens 50000, max_runtime 300s, max_tool_calls 50")

def show_attacks():
    st.header("Attack Definitions — OWASP 2026")
    attacks = api_get("/attacks")
    if attacks:
        df = pd.DataFrame(attacks)
        st.dataframe(df[["attack_id","category","name","severity","target_types"]])
        # Filter
        cat = st.selectbox("Filter Category", options=["ALL"]+sorted(set(a["category"] for a in attacks)))
        if cat != "ALL":
            attacks = [a for a in attacks if a["category"]==cat]
            st.dataframe(pd.DataFrame(attacks)[["attack_id","name","severity"]])
            for a in attacks:
                with st.expander(f"{a['attack_id']} — {a['name']}", expanded=False):
                    st.json(a)
    else:
        st.info("No attacks loaded")

if __name__ == "__main__":
    main()
