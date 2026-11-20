import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest

from app.audit import audit_logger

FRONTEND_PATH = (
    Path(__file__).resolve().parents[1] / "frontend" / "dashboard.py"
)

HARNESS = """
import importlib.util
import os

import streamlit as st

spec = importlib.util.spec_from_file_location("dashboard", {path!r})
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)

getattr(dashboard, os.environ["PAGE"])()
"""

APPROVAL = {
    "approval_id": "APP-1",
    "incident_id": "IC-1",
    "project_id": "APOLLO-001",
    "role_assignment_id": "/subscriptions/s/roleAssignments/alex",
    "identity_id": "alex-id",
    "resource_scope": "/subscriptions/s/resourceGroups/rg/providers/x/apollo",
    "proposed_action": "DELETE_ROLE_ASSIGNMENT",
    "approver": "owner-id",
    "approver_name": "Owner",
    "status": "PENDING",
    "created_at": None,
    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
}


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = str(payload)

    def json(self):
        return self._payload


class FakeBackend:
    """Stands in for the Identity Commander API; records every call."""

    def __init__(self):
        self.calls = []
        self.approvals = [dict(APPROVAL)]

    def __call__(self, method, url, headers=None, timeout=None, **kwargs):
        path = url.replace("http://localhost:8000", "")
        self.calls.append({
            "method": method,
            "path": path,
            "headers": headers or {},
            "params": kwargs.get("params"),
            "json": kwargs.get("json"),
        })

        if method == "GET" and path == "/approvals":
            return FakeResponse(self.approvals)

        if method == "GET" and path == "/identities/search":
            return FakeResponse([{
                "object_id": "alex-id",
                "display_name": "Alex Morgan",
                "identity_type": "USER",
            }])

        if method == "POST" and path.endswith("/decision"):
            approval_id = path.split("/")[2]
            status = kwargs["json"]["status"]
            for item in self.approvals:
                if item["approval_id"] == approval_id:
                    item["status"] = status
            return FakeResponse(self.approvals[0])

        return FakeResponse({"detail": "Unexpected call"}, status_code=404)


@pytest.fixture
def backend(monkeypatch):
    fake = FakeBackend()
    monkeypatch.setattr(requests, "request", fake)
    return fake


@pytest.fixture
def signed_in(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("FRONTEND_CLIENT_ID", "frontend")
    monkeypatch.setenv("FRONTEND_CLIENT_SECRET", "secret")
    monkeypatch.setenv("ENTRA_CLIENT_ID", "api-app")


def run_page(page, monkeypatch):
    monkeypatch.setenv("PAGE", page)
    at = AppTest.from_string(HARNESS.format(path=str(FRONTEND_PATH)))
    at.session_state["access_token"] = "token-for-tests"
    at.session_state["token_expires_at"] = time.time() + 3600
    at.run(timeout=20)
    return at


def write_audit(*events):
    for event_type, event in events:
        audit_logger._write_audit_event(event, event_type)


def test_every_api_call_carries_the_bearer_token(backend, signed_in, monkeypatch):
    run_page("overview", monkeypatch)

    assert backend.calls
    for call in backend.calls:
        assert call["headers"] == {"Authorization": "Bearer token-for-tests"}


def test_overview_shows_the_four_kpis(backend, signed_in, monkeypatch):
    write_audit(
        ("INVESTIGATION", {
            "action": "IDENTITY_INVESTIGATION",
            "status": "COMPLETED",
            "identity_id": "alex-id",
            "identity_name": "Alex Morgan",
            "findings": [{
                "role": "Storage Blob Data Contributor",
                "resource": "apollo",
                "project_id": "APOLLO-001",
                "risk_level": "HIGH",
                "finding_type": "STALE_PRODUCTION_ACCESS",
                "approval_status": "PENDING_APPROVAL",
            }],
        }),
        ("REMEDIATION", {
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "approval_id": "APP-0",
            "status": "SIMULATED",
        }),
    )

    at = run_page("overview", monkeypatch)

    labels = [metric.label for metric in at.metric]
    values = [metric.value for metric in at.metric]
    assert labels == [
        "Identities scanned",
        "High-risk findings",
        "Pending approvals (yours)",
        "Remediations completed (simulated)",
    ]
    assert values == ["1", "1", "1", "1"]
    assert not at.exception


def test_search_sends_the_typed_term_to_the_backend(backend, signed_in, monkeypatch):
    monkeypatch.setenv("PAGE", "investigate")
    at = AppTest.from_string(HARNESS.format(path=str(FRONTEND_PATH)))
    at.session_state["access_token"] = "token-for-tests"
    at.session_state["token_expires_at"] = time.time() + 3600
    at.run(timeout=20)

    at.text_input[0].input("Alex Morgan").run(timeout=20)

    searches = [c for c in backend.calls if c["path"] == "/identities/search"]
    assert searches[-1]["params"] == {"q": "Alex Morgan"}
    assert not at.exception


def test_approve_sends_decision_to_the_backend(backend, signed_in, monkeypatch):
    at = run_page("approvals", monkeypatch)

    approve = next(b for b in at.button if b.key == "approve-APP-1")
    approve.click().run(timeout=20)

    decisions = [c for c in backend.calls if c["path"].endswith("/decision")]
    assert decisions[-1]["json"] == {"status": "APPROVED"}
    assert decisions[-1]["path"] == "/approvals/APP-1/decision"
    assert not at.exception


def test_remediation_history_shows_before_and_after(backend, signed_in, monkeypatch):
    assignment = {
        "id": "/subscriptions/s/roleAssignments/alex",
        "principal_id": "alex-id",
        "role_definition_id": "role",
        "scope": "/subscriptions/s/resourceGroups/rg/providers/x/apollo",
        "assignment_source": "DIRECT",
    }
    write_audit(
        ("REMEDIATION", {
            "action": "ROLE_ASSIGNMENT_REMOVAL",
            "approval_id": "APP-1",
            "role_assignment_id": assignment["id"],
            "status": "SIMULATED",
        }),
        ("VERIFICATION", {
            "action": "REMEDIATION_VERIFICATION",
            "approval_id": "APP-1",
            "role_assignment_id": assignment["id"],
            "status": "ACCESS_STILL_PRESENT",
            "role_assignments_before": [assignment],
            "role_assignments_after": [assignment],
        }),
    )

    at = run_page("history", monkeypatch)

    assert not at.exception
    assert at.dataframe[0].value.iloc[0]["Verification"] == "ACCESS_STILL_PRESENT"
    assert any(
        "No change. Simulation mode" in info.value for info in at.info
    )


def test_report_shows_explanation_and_alternatives(backend, signed_in, monkeypatch):
    write_audit(
        ("INVESTIGATION", {
            "action": "IDENTITY_INVESTIGATION",
            "status": "COMPLETED",
            "identity_id": "alex-id",
            "identity_name": "Alex Morgan",
            "findings": [],
            "investigation_summary": {
                "summary": "Alex retains access after the project ended.",
                "alternative_explanations": ["Access may be a forgotten grant."],
                "evidence_gaps": ["Diagnostic logs are incomplete."],
                "evidence_ids": [],
            },
            "evidence_records": [{
                "evidence_id": "EVID-001",
                "source": "Microsoft Entra ID",
                "description": "Identity Alex Morgan.",
            }],
        }),
    )

    at = run_page("report", monkeypatch)

    assert not at.exception
    rendered = " ".join(markdown.value for markdown in at.markdown)
    assert "Alex retains access after the project ended." in rendered
    assert "Access may be a forgotten grant." in rendered
    assert "Diagnostic logs are incomplete." in rendered
