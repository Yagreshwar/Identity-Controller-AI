from app.connectors.entra_client import search_identity
from app.investigation.identity_discovery import analyze_identity


def test_analyze_identity():
    identity_data = {
        "id": "identity-001",
        "displayName": "Alex Morgan",
        "userPrincipalName": "alex@example.com",
        "accountEnabled": True,
        "identity_type": "User",
        "department": "Engineering"
    }

    result = analyze_identity(identity_data)

    assert result["object_id"] == "identity-001"
    assert result["display_name"] == "Alex Morgan"
    assert result["user_principal_name"] == "alex@example.com"
    assert result["account_enabled"] is True
    assert result["identity_type"] == "User"
    assert result["department"] == "Engineering"


def test_analyze_identity_without_optional_fields():
    identity_data = {
        "id": "identity-001",
        "displayName": "Alex Morgan"
    }

    result = analyze_identity(identity_data)

    assert result["object_id"] == "identity-001"
    assert result["user_principal_name"] is None
    assert result["department"] is None


def _capture_search(monkeypatch, users):
    filters = []

    def fake_pages(url, headers, params=None):
        filters.append((url, params["$filter"]))
        if url.endswith("/users"):
            return users
        return []

    monkeypatch.setattr(
        "app.connectors.entra_client._get_headers",
        lambda: {},
    )
    monkeypatch.setattr(
        "app.connectors.entra_client._get_all_pages",
        fake_pages,
    )
    return filters


def _service_principal_filter(filters):
    return next(
        query for url, query in filters if url.endswith("/servicePrincipals")
    )


def test_search_alex_morgan_by_display_name(monkeypatch):
    filters = _capture_search(monkeypatch, [{
        "id": "alex-id",
        "displayName": "Alex Morgan",
        "userPrincipalName": "alex.morgan@contoso-demo.com",
        "accountEnabled": True,
        "department": None,
    }])

    results = search_identity("Alex Morgan")

    assert results[0]["display_name"] == "Alex Morgan"
    assert results[0]["identity_type"] == "USER"
    assert _service_principal_filter(filters) == "displayName eq 'Alex Morgan'"


def test_search_by_email_keeps_mail_filter_and_skips_app_id(monkeypatch):
    email = "alex.morgan@contoso-demo.com"
    filters = _capture_search(monkeypatch, [])

    assert search_identity(email) == []

    user_filter = next(query for url, query in filters if url.endswith("/users"))
    assert f"mail eq '{email}'" in user_filter
    assert "appId" not in _service_principal_filter(filters)


def test_search_by_application_id_includes_app_id_filter(monkeypatch):
    app_id = "11111111-1111-1111-1111-111111111111"
    filters = _capture_search(monkeypatch, [])

    search_identity(app_id)

    assert _service_principal_filter(filters) == (
        f"displayName eq '{app_id}' or appId eq '{app_id}'"
    )