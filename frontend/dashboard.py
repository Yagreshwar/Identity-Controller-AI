"""
Identity Commander console (Streamlit).

One file with the five pages in the requirements document, section 15.

Sign-in uses Microsoft Entra ID through the Identity Commander Frontend app
registration. The access token for the Identity Commander API
(scope `access_as_user`) is sent as `Authorization: Bearer <token>`.

Run from the project root:
    streamlit run frontend/dashboard.py
"""

import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path

import msal
import requests
import streamlit as st
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from app.audit.audit_logger import read_audit_events

API_BASE_URL = os.getenv(
    "IDENTITY_COMMANDER_API_URL", "http://localhost:8000"
).rstrip("/")
TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
FRONTEND_CLIENT_ID = os.getenv("FRONTEND_CLIENT_ID", "")
FRONTEND_CLIENT_SECRET = os.getenv("FRONTEND_CLIENT_SECRET", "")
API_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "")
REDIRECT_URI = os.getenv("FRONTEND_REDIRECT_URI", "http://localhost:8501")
API_SCOPES = [f"api://{API_CLIENT_ID}/access_as_user"]

REQUIRED_SETTINGS = {
    "AZURE_TENANT_ID": TENANT_ID,
    "FRONTEND_CLIENT_ID": FRONTEND_CLIENT_ID,
    "FRONTEND_CLIENT_SECRET": FRONTEND_CLIENT_SECRET,
    "ENTRA_CLIENT_ID": API_CLIENT_ID,
}


class ApiError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------

@st.cache_resource
def _auth_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        FRONTEND_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=FRONTEND_CLIENT_SECRET,
    )


@st.cache_resource
def _pending_sign_ins() -> dict:
    """
    Sign-in flows waiting for the Entra redirect, keyed by MSAL state.

    The redirect opens a new Streamlit session, so the flow cannot be kept
    in session_state. This process-level store is shared by all sessions.
    """
    return {}


def _require_sign_in() -> None:
    """Show the sign-in link and stop the page until a token is held."""

    if (
        st.session_state.get("access_token")
        and st.session_state.get("token_expires_at", 0) - 60 > time.time()
    ):
        return

    st.session_state.pop("access_token", None)
    params = dict(st.query_params)

    if "error" in params:
        st.error(
            "Sign-in was not completed: "
            f"{params.get('error_description', params['error'])}"
        )
        st.query_params.clear()

    elif "code" in params:
        flow = _pending_sign_ins().pop(params.get("state", ""), None)
        st.query_params.clear()

        if flow is None:
            st.error("This sign-in link has expired. Start sign-in again.")
        else:
            result = _auth_app().acquire_token_by_auth_code_flow(
                flow,
                auth_response=params,
            )

            if "access_token" in result:
                claims = result.get("id_token_claims", {})
                st.session_state["access_token"] = result["access_token"]
                st.session_state["token_expires_at"] = time.time() + int(
                    result.get("expires_in", 3600)
                )
                st.session_state["username"] = (
                    claims.get("preferred_username")
                    or claims.get("name")
                    or "Signed in"
                )
                st.rerun()

            st.error("Sign-in failed. Start sign-in again.")

    flow = _auth_app().initiate_auth_code_flow(
        scopes=API_SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    _pending_sign_ins()[flow["state"]] = flow

    st.title("Identity Commander")
    st.markdown(f"[Sign in with Microsoft]({flow['auth_uri']})")
    st.stop()


# ---------------------------------------------------------------------
# Backend API
# ---------------------------------------------------------------------

def _error_text(response: requests.Response) -> str:
    try:
        detail = response.json().get("detail", response.text)
    except ValueError:
        detail = response.text

    if isinstance(detail, dict):
        return str(
            detail.get("reason")
            or detail.get("message")
            or json.dumps(detail)
        )

    return str(detail)


def api(method: str, path: str, **kwargs):
    token = st.session_state.get("access_token")

    if not token:
        raise ApiError("Sign in again to continue.")

    try:
        response = requests.request(
            method,
            f"{API_BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=300,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise ApiError(
            "The Identity Commander API is not reachable. "
            "Start the backend and try again."
        ) from exc

    if response.status_code == 401:
        st.session_state.pop("access_token", None)
        raise ApiError("Your session expired. Sign in again.")

    if not response.ok:
        raise ApiError(_error_text(response))

    return response.json()


def _page(render):
    """Show API errors inside the page instead of a stack trace."""

    @wraps(render)
    def wrapper():
        try:
            render()
        except ApiError as exc:
            st.error(exc.message)

    return wrapper


# ---------------------------------------------------------------------
# Audit log helpers (the backend writes the audit trail on this machine)
# ---------------------------------------------------------------------

def _latest_investigations() -> dict[str, dict]:
    latest: dict[str, dict] = {}

    for event in read_audit_events():
        if (
            event.get("event_type") == "INVESTIGATION"
            and event.get("status") == "COMPLETED"
        ):
            latest[event.get("identity_id")] = event

    return latest


def _events(event_type: str, status: str | None = None) -> list[dict]:
    return [
        event for event in read_audit_events()
        if event.get("event_type") == event_type
        and (status is None or event.get("status") == status)
    ]


def _normalize(value) -> str:
    return str(value or "").rstrip("/").casefold()


# ---------------------------------------------------------------------
# Page 1: Overview
# ---------------------------------------------------------------------

@_page
def overview():
    st.title("Identity Risk Dashboard")

    latest = _latest_investigations()
    findings_rows = []

    for event in latest.values():
        for finding in event.get("findings", []):
            findings_rows.append({
                "Identity": event.get("identity_name"),
                "Role": finding.get("role"),
                "Resource": finding.get("resource"),
                "Project": finding.get("project_id"),
                "Risk": finding.get("risk_level"),
                "Finding": finding.get("finding_type"),
                "Approval": finding.get("approval_status"),
            })

    high_risk = [row for row in findings_rows if row["Risk"] == "HIGH"]
    pending = [
        item for item in api("GET", "/approvals")
        if item.get("status") == "PENDING"
    ]
    remediations = _events("REMEDIATION", "SIMULATED")

    cols = st.columns(4)
    cols[0].metric("Identities scanned", len(latest))
    cols[1].metric("High-risk findings", len(high_risk))
    cols[2].metric("Pending approvals (yours)", len(pending))
    cols[3].metric("Remediations completed (simulated)", len(remediations))

    st.subheader("Risk findings")

    if findings_rows:
        st.dataframe(findings_rows)
    else:
        st.info("No investigations yet. Use Investigate Identity to start one.")


# ---------------------------------------------------------------------
# Page 2: Investigate Identity
# ---------------------------------------------------------------------

def _show_profile(result: dict) -> None:
    evidence = result.get("evidence", {})
    identity = evidence.get("identity") or {}

    st.subheader(identity.get("display_name") or result.get("identity"))

    cols = st.columns(3)
    cols[0].metric("Identity type", identity.get("identity_type") or "-")
    cols[1].metric("Account enabled", str(identity.get("account_enabled")))
    cols[2].metric(
        "Department / UPN",
        identity.get("department")
        or identity.get("user_principal_name")
        or "-",
    )

    projects = evidence.get("projects", [])

    st.markdown("**Current project**")
    st.dataframe([
        {
            "Project": item.get("project", {}).get("project_id"),
            "Status": item.get("project", {}).get("status"),
            "Start": item.get("project", {}).get("start_date"),
            "End": item.get("project", {}).get("end_date"),
        }
        for item in projects
    ] or [{"Project": "No project assignment found"}])

    permission_rows = []
    scope_rows = []

    for project in projects:
        for resource in project.get("resources", []):
            resource_id = resource.get("resource_record", {}).get("resource_id")
            details = resource.get("resource_details") or {}
            scope_rows.append({
                "Resource scope": resource_id,
                "Name": details.get("name") if isinstance(details, dict) else None,
                "Project activity": (
                    resource.get("project_activity") or {}
                ).get("status"),
                "Post-project activity": (
                    resource.get("post_project_activity") or {}
                ).get("status"),
                "Activity events": len(
                    (resource.get("post_project_activity") or {})
                    .get("activities", [])
                ),
            })

            for item in resource.get("role_assignments", []):
                assignment = item.get("assignment", {})
                permission_rows.append({
                    "Role": assignment.get("role_name"),
                    "Assignment": assignment.get("id"),
                    "Scope": assignment.get("scope"),
                    "Source": assignment.get("assignment_source"),
                })

    st.markdown("**Assigned permissions**")
    st.dataframe(permission_rows or [{"Role": "No direct role assignment found"}])

    st.markdown("**Resource scopes and activity evidence**")
    st.dataframe(scope_rows or [{"Resource scope": "No resources found"}])

    summary_rows = [
        {
            "Risk": finding.get("risk_level"),
            "Finding": finding.get("finding_type"),
            "Recommendation": finding.get("recommended_action"),
            "Approval status": finding.get("approval_status"),
        }
        for finding in result.get("findings", [])
    ]

    st.markdown("**Risk findings**")
    st.dataframe(summary_rows or [{"Risk": "No findings"}])
    st.caption(
        "Open Investigation Report for the full explanation and evidence."
    )


@_page
def investigate():
    st.title("Investigate Identity")

    query = st.text_input("Search by email or display name").strip()

    if query:
        matches = api("GET", "/identities/search", params={"q": query})

        if not matches:
            st.info("No matching identity was found.")
        else:
            options = {
                (
                    f"{item.get('display_name') or item['object_id']} "
                    f"({item.get('identity_type')}) - {item['object_id']}"
                ): item
                for item in matches
            }
            choice = st.selectbox("Matching identities", list(options))

            if st.button("Investigate with AI", type="primary"):
                with st.spinner("Collecting evidence and running the AI investigation..."):
                    st.session_state["investigation"] = api(
                        "POST",
                        "/investigate",
                        json={"identity_id": options[choice]["object_id"]},
                    )

    result = st.session_state.get("investigation")

    if result:
        _show_profile(result)


# ---------------------------------------------------------------------
# Page 3: Investigation Report
# ---------------------------------------------------------------------

def _request_approval_form(finding: dict, identity_id: str, key: str) -> None:
    with st.form(key=key):
        hours = st.number_input(
            "Approval valid for (hours)",
            min_value=1,
            max_value=168,
            value=24,
        )
        submitted = st.form_submit_button("Request resource-owner approval")

    if submitted:
        created = api("POST", "/approvals", json={
            "approval_id": f"APP-{uuid.uuid4().hex[:8].upper()}",
            "incident_id": f"IC-{uuid.uuid4().hex[:8].upper()}",
            "project_id": finding.get("project_id"),
            "role_assignment_id": finding.get("role_assignment_id"),
            "identity_id": identity_id,
            "resource_scope": finding.get("resource_scope"),
            "expires_at": (
                datetime.now(UTC) + timedelta(hours=int(hours))
            ).isoformat(),
        })
        st.success(
            f"Approval {created['approval_id']} was sent to the resource "
            f"owner ({created.get('approver_name') or 'registered owner'})."
        )


@_page
def report():
    st.title("Investigation Report")

    latest = _latest_investigations()

    if not latest:
        st.info("No completed investigations yet. Run one first.")
        return

    labels = {
        f"{event.get('identity_name')} ({identity_id})": identity_id
        for identity_id, event in latest.items()
    }
    choice = st.selectbox("Investigated identity", list(labels))
    identity_id = labels[choice]
    event = latest[identity_id]

    summary = event.get("investigation_summary", {})
    evidence_by_id = {
        item.get("evidence_id"): item
        for item in event.get("evidence_records", [])
    }

    st.subheader("Explanation")
    st.write(summary.get("summary") or "No explanation was produced.")

    st.subheader("Findings and recommendations")

    for index, finding in enumerate(event.get("findings", [])):
        with st.container(border=True):
            st.markdown(
                f"**{finding.get('finding_type')}** - "
                f"risk level **{finding.get('risk_level')}**"
            )
            st.write(
                f"Role: {finding.get('role')}  \n"
                f"Resource: {finding.get('resource')}  \n"
                f"Project: {finding.get('project_id')} "
                f"({finding.get('project_status')})"
            )
            st.write(f"Recommendation: {finding.get('recommended_action')}")

            st.markdown("**Evidence references**")
            refs = [
                evidence_by_id.get(evidence_id, {"evidence_id": evidence_id})
                for evidence_id in finding.get("evidence_ids", [])
            ]
            st.dataframe(refs or [{"evidence_id": "None"}])

            if (
                finding.get("approval_eligible")
                and finding.get("approval_status") == "PENDING_APPROVAL"
            ):
                _request_approval_form(
                    finding,
                    identity_id,
                    key=f"request-{identity_id}-{index}",
                )

    st.subheader("Alternative explanations")
    for item in summary.get("alternative_explanations", []) or ["None recorded."]:
        st.write(f"- {item}")

    st.subheader("Evidence gaps")
    for item in summary.get("evidence_gaps", []) or ["None recorded."]:
        st.write(f"- {item}")

    st.subheader("All evidence")
    st.dataframe(event.get("evidence_records", []) or [{"evidence_id": "None"}])


# ---------------------------------------------------------------------
# Page 4: Approvals
# ---------------------------------------------------------------------

def _show_remediation_result(result: dict) -> None:
    execution = result.get("execution", {})
    verification = result.get("verification", {})
    access_test = verification.get("controlled_access_test", {})
    legitimate = verification.get("legitimate_access", {})

    st.success(
        f"Execution: {execution.get('status')}. "
        f"{execution.get('message', '')}"
    )
    st.write(
        f"Verification: **{verification.get('status')}**. "
        f"{verification.get('message', '')}"
    )
    st.write(
        f"Controlled access test: {access_test.get('status')}. "
        f"Legitimate access: {legitimate.get('status')}."
    )


@_page
def approvals():
    st.title("Approvals")
    st.caption(
        "Only the registered resource owner sees and decides these requests."
    )

    items = api("GET", "/approvals")
    pending = [item for item in items if item.get("status") == "PENDING"]
    approved = [item for item in items if item.get("status") == "APPROVED"]

    st.subheader("Pending remediation requests")

    if not pending:
        st.info("No pending requests.")

    for item in pending:
        approval_id = item["approval_id"]

        with st.container(border=True):
            st.markdown(f"**{approval_id}** - {item.get('proposed_action')} (simulated)")
            st.write(
                f"Role assignment: `{item.get('role_assignment_id')}`  \n"
                f"Resource scope: `{item.get('resource_scope')}`  \n"
                f"Identity: `{item.get('identity_id')}`  \n"
                f"Incident: {item.get('incident_id')}  \n"
                f"Expires: {item.get('expires_at')}"
            )

            approve_col, reject_col = st.columns(2)

            if approve_col.button("Approve", key=f"approve-{approval_id}"):
                api(
                    "POST",
                    f"/approvals/{approval_id}/decision",
                    json={"status": "APPROVED"},
                )
                st.rerun()

            if reject_col.button("Reject", key=f"reject-{approval_id}"):
                api(
                    "POST",
                    f"/approvals/{approval_id}/decision",
                    json={"status": "REJECTED"},
                )
                st.rerun()

    st.subheader("Approved - ready for simulated remediation")

    if not approved:
        st.info("No approved requests waiting to run.")

    for item in approved:
        approval_id = item["approval_id"]

        with st.container(border=True):
            st.markdown(f"**{approval_id}** - {item.get('proposed_action')} (simulated)")
            st.write(
                f"Role assignment: `{item.get('role_assignment_id')}`  \n"
                f"Resource scope: `{item.get('resource_scope')}`"
            )
            st.caption(
                "Simulation only: no Azure role assignment is deleted in this POC."
            )

            if st.button(
                "Run simulated remediation",
                key=f"remediate-{approval_id}",
            ):
                st.session_state[f"result-{approval_id}"] = api(
                    "POST",
                    "/remediate",
                    json={"approval_id": approval_id},
                )

            result = st.session_state.get(f"result-{approval_id}")

            if result:
                _show_remediation_result(result)


# ---------------------------------------------------------------------
# Page 5: Remediation History
# ---------------------------------------------------------------------

def _before_after(verification: dict) -> None:
    st.markdown("**Before and after: identity's role assignments at the approved scope**")

    before = verification.get("role_assignments_before", [])
    after = verification.get("role_assignments_after", [])
    cols = st.columns(2)

    cols[0].markdown("Before")
    cols[0].dataframe(before or [{"id": "No assignments"}])

    cols[1].markdown("After")
    cols[1].dataframe(after or [{"id": "No assignments"}])

    target = _normalize(verification.get("role_assignment_id"))
    still_present = any(_normalize(item.get("id")) == target for item in after)

    if before == after and still_present:
        st.info(
            "No change. Simulation mode: the target role assignment still exists."
        )
    elif not still_present:
        st.success("The target role assignment is no longer present.")
    else:
        st.warning("The role assignments changed during this run.")


@_page
def history():
    st.title("Remediation History")

    events = read_audit_events()
    remediations = [
        event for event in events
        if event.get("event_type") == "REMEDIATION"
        and event.get("action") == "ROLE_ASSIGNMENT_REMOVAL"
    ]

    verifications: dict[str, dict] = {}

    for event in events:
        if (
            event.get("event_type") == "VERIFICATION"
            and event.get("action") == "REMEDIATION_VERIFICATION"
        ):
            verifications[event.get("approval_id")] = event

    if not remediations:
        st.info("No remediation has been run yet.")
        return

    st.dataframe([
        {
            "Approval": event.get("approval_id"),
            "Approved action": "Delete role assignment (simulated)",
            "Executed at": event.get("recorded_at"),
            "Execution status": event.get("status"),
            "Verification": verifications.get(
                event.get("approval_id"), {}
            ).get("status", "-"),
            "Reason": event.get("reason", ""),
        }
        for event in remediations
    ])

    for event in remediations:
        approval_id = event.get("approval_id")
        verification = verifications.get(approval_id)

        with st.expander(
            f"{approval_id} - {event.get('status')} - {event.get('recorded_at')}"
        ):
            if verification:
                _before_after(verification)

            st.markdown("**Audit record**")
            st.json([
                item for item in events
                if item.get("approval_id") == approval_id
            ])


# ---------------------------------------------------------------------
# App
# ---------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="Identity Commander", layout="wide")

    missing = [name for name, value in REQUIRED_SETTINGS.items() if not value]

    if missing:
        st.error(
            "Missing settings in .env: " + ", ".join(missing)
        )
        st.stop()

    _require_sign_in()

    with st.sidebar:
        st.caption(f"Signed in as {st.session_state.get('username')}")

        if st.button("Sign out"):
            st.session_state.clear()
            st.rerun()

    pages = [
        st.Page(overview, title="Overview", default=True),
        st.Page(investigate, title="Investigate Identity"),
        st.Page(report, title="Investigation Report"),
        st.Page(approvals, title="Approvals"),
        st.Page(history, title="Remediation History"),
    ]

    st.navigation(pages).run()


if __name__ == "__main__":
    main()
