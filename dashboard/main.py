
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


def main():
    st.title("🔴 AI Red Team Dashboard")
    st.caption("Security Testing Platform for AI Applications")

    pages = {
        "Overview": show_overview,
        "Targets": show_targets,
        "Scans": show_scans,
        "Findings": show_findings,
        "Evidence": show_evidence,
        "Attacks": show_attacks,
        "Checklist": show_checklist,
    }

    page = st.sidebar.selectbox("Navigation", list(pages.keys()))
    pages[page]()


def show_overview():
    st.header("Overview")

    col1, col2, col3 = st.columns(3)

    targets = api_get("/targets")
    scans = api_get("/scans")
    findings = []
    for scan in scans:
        f = api_get(f"/scans/{scan['id']}/findings")
        findings.extend(f)

    with col1:
        st.metric("Targets", len(targets))
    with col2:
        st.metric("Scans", len(scans))
    with col3:
        st.metric("Total Findings", len(findings))

    if scans:
        st.subheader("Recent Scans")
        df = pd.DataFrame(scans[:10])
        st.dataframe(df[["id", "target_id", "taxonomy_version", "status", "started_at", "completed_at"]])


def show_targets():
    st.header("Targets")

    tab1, tab2 = st.tabs(["List Targets", "Add Target"])

    with tab1:
        targets = api_get("/targets")
        if targets:
            df = pd.DataFrame(targets)
            st.dataframe(df[["id", "name", "target_type", "base_url", "is_authorized", "created_at"]])
        else:
            st.info("No targets configured")

    with tab2, st.form("add_target"):
        name = st.text_input("Name")
        url = st.text_input("URL")
        target_type = st.selectbox("Type", ["llm", "rag", "agent"])
        submitted = st.form_submit_button("Add Target")

        if submitted:
            result = api_post("/targets", {
                "name": name,
                "target_type": target_type,
                "base_url": url,
                "config": {},
            })
            if result:
                st.success(f"Target added with ID {result['id']}")


def show_scans():
    st.header("Scans")

    tab1, tab2 = st.tabs(["List Scans", "Start Scan"])

    with tab1:
        scans = api_get("/scans")
        if scans:
            df = pd.DataFrame(scans)
            st.dataframe(df[["id", "target_id", "taxonomy_version", "status", "started_at", "completed_at"]])
        else:
            st.info("No scans yet")

    with tab2:
        targets = api_get("/targets")
        if not targets:
            st.warning("Add a target first")
            return

        with st.form("start_scan"):
            target_id = st.selectbox("Target", options=[t["id"] for t in targets],
                                   format_func=lambda x: next(t["name"] for t in targets if t["id"] == x))
            submitted = st.form_submit_button("Start Scan")

            if submitted:
                result = api_post("/scans", {"target_id": target_id})
                if result:
                    st.success(f"Scan started with ID {result['id']}")


def show_findings():
    st.header("Findings")

    scans = api_get("/scans")
    if not scans:
        st.info("No scans available")
        return

    scan_id = st.selectbox("Select Scan", options=[s["id"] for s in scans],
                          format_func=lambda x: f"Scan {x} ({next(s['taxonomy_version'] for s in scans if s['id'] == x)})")

    if scan_id:
        findings = api_get(f"/scans/{scan_id}/findings")
        if findings:
            df = pd.DataFrame(findings)
            st.dataframe(df[["id", "attack_id", "category", "title", "severity", "regression_status"]])

            selected = st.selectbox("View Details", options=[f["id"] for f in findings],
                                  format_func=lambda x: next(f["title"] for f in findings if f["id"] == x))

            if selected:
                finding = next(f for f in findings if f["id"] == selected)
                with st.expander("Finding Details", expanded=True):
                    st.json(finding)
        else:
            st.info("No findings for this scan")


def show_evidence():
    st.header("Evidence Viewer — Sprint 6 (Reproducible, Immutable)")
    st.caption("Every FAIL has request/response/headers/tool_calls/retrieved_docs/detectors/reproduction. Deterministic detectors, no LLM opinion alone.")

    scans = api_get("/scans")
    if not scans:
        st.info("No scans available")
        return

    scan_id = st.selectbox("Select Scan for Evidence", options=[s["id"] for s in scans],
                           format_func=lambda x: f"Scan {x} ({next(s['taxonomy_version'] for s in scans if s['id'] == x)})", key="evidence_scan")

    if scan_id:
        evidences = api_get(f"/scans/{scan_id}/evidence")
        if not evidences:
            st.info("No evidence for this scan (maybe no tests yet, run scan).")
            return

        # Summary table
        df = pd.DataFrame([{
            "test_id": e["test_id"],
            "result": e["result"],
            "confidence": e["confidence"],
            "reproduction": e["reproduction_count"],
            "detectors": ", ".join(e["detectors_triggered"] or []),
            "http_status": e["http_status"],
        } for e in evidences])
        st.dataframe(df)

        # Detail viewer
        test_ids = [e["test_id"] for e in evidences]
        selected = st.selectbox("Select Test for Detailed Evidence", options=test_ids, format_func=lambda x: f"Test {x} - {next(e['result'] for e in evidences if e['test_id']==x)}", key="evidence_test")

        if selected:
            ev = next(e for e in evidences if e["test_id"] == selected)
            with st.expander("Request Capture (attack_id, target, payload, auth, timestamp)", expanded=True):
                st.json(ev["request"])
            with st.expander("Response Capture (status, headers, body)", expanded=True):
                st.json({"http_status": ev["http_status"], "headers": ev["headers"], "response": ev["response"]})
            with st.expander("Tool-Call Capture (tool, args, auth, result, side effect, sequence)", expanded=False):
                st.json(ev["tool_calls"] or "No tool calls (LLM/RAG)")
            with st.expander("Retrieval Evidence (doc IDs, metadata, similarity, context)", expanded=False):
                st.json(ev["retrieved_documents"] or "No retrieval (Agent/LLM)")
            with st.expander("Deterministic Detection", expanded=False):
                st.json({"detectors_triggered": ev["detectors_triggered"], "expected": ev["expected_behavior"], "observed": ev["observed_behavior"], "confidence": ev["confidence"]})
            with st.expander("Reproduction Tracking", expanded=False):
                st.json({"reproduction_count": ev["reproduction_count"], "reproducible": ev["reproduction_count"] > 1, "confidence": ev["confidence"], "hash": ev.get("evidence_metadata", {}).get("evidence_hash", "n/a") if isinstance(ev.get("evidence_metadata"), dict) else "n/a"})
            st.caption("Evidence is immutable once scan is COMPLETED (spec 22). Every FAIL above is reproducible — request/response + detectors prove vulnerability.")


def show_attacks():
    st.header("Attack Definitions")

    attacks = api_get("/attacks")
    if attacks:
        df = pd.DataFrame(attacks)
        st.dataframe(df[["attack_id", "category", "name", "severity", "target_types"]])
    else:
        st.info("No attacks loaded")


def show_checklist():
    st.header("Project Checklist")

    items = api_get("/checklist")
    if not items:
        st.info("No checklist items")
        return

    current_sprint = None
    for item in items:
        if item["sprint"] != current_sprint:
            current_sprint = item["sprint"]
            st.subheader(current_sprint)

        status_icon = {
            "TODO": "☐",
            "IN_PROGRESS": "◐",
            "VERIFIED": "☑",
            "BLOCKED": "⚠",
        }.get(item["status"], "?")

        col1, col2 = st.columns([4, 1])
        with col1:
            st.write(f"{status_icon} {item['task']}")
        with col2:
            new_status = st.selectbox(
                "Status",
                ["TODO", "IN_PROGRESS", "VERIFIED", "BLOCKED"],
                index=["TODO", "IN_PROGRESS", "VERIFIED", "BLOCKED"].index(item["status"]),
                key=f"status_{item['id']}",
            )
            if new_status != item["status"]:
                api_post(f"/checklist/{item['id']}", {"status": new_status})
                st.rerun()


if __name__ == "__main__":
    main()
