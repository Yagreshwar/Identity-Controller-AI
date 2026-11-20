from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app import authentication

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def local_signing_key(monkeypatch):
    monkeypatch.setattr(
        authentication,
        "jwks_client",
        SimpleNamespace(
            get_signing_key_from_jwt=lambda token: SimpleNamespace(
                key=PRIVATE_KEY.public_key()
            )
        ),
    )


def make_token(**overrides) -> str:
    claims = {
        "aud": authentication.ENTRA_CLIENT_ID,
        "iss": authentication.ISSUER,
        "tid": authentication.ENTRA_TENANT_ID,
        "oid": "owner-object-id",
        "preferred_username": "owner@contoso-demo.com",
        "name": "Resource Owner",
        "scp": "access_as_user",
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }
    claims.update(overrides)
    claims = {key: value for key, value in claims.items() if value is not None}

    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256")


def authenticate(token: str) -> dict:
    return authentication.get_current_user(
        HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    )


def test_valid_token_returns_user():
    user = authenticate(make_token())

    assert user["user_id"] == "owner-object-id"
    assert user["username"] == "owner@contoso-demo.com"
    assert user["tenant_id"] == authentication.ENTRA_TENANT_ID


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": datetime.now(UTC) - timedelta(minutes=5)},
        {"aud": "api://another-application"},
        {"iss": "https://login.microsoftonline.com/other-tenant/v2.0"},
        {"oid": None},
    ],
    ids=["expired", "wrong-audience", "wrong-issuer", "missing-oid"],
)
def test_invalid_token_is_rejected(overrides):
    with pytest.raises(HTTPException) as error:
        authenticate(make_token(**overrides))

    assert error.value.status_code == 401


def test_token_from_another_tenant_is_rejected():
    with pytest.raises(HTTPException) as error:
        authenticate(make_token(tid="another-tenant"))

    assert error.value.status_code == 401


def test_token_without_api_scope_is_forbidden():
    with pytest.raises(HTTPException) as error:
        authenticate(make_token(scp="User.Read"))

    assert error.value.status_code == 403


def test_token_signed_by_unknown_key_is_rejected():
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "aud": authentication.ENTRA_CLIENT_ID,
            "iss": authentication.ISSUER,
            "tid": authentication.ENTRA_TENANT_ID,
            "oid": "attacker",
            "scp": "access_as_user",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        other_key,
        algorithm="RS256",
    )

    with pytest.raises(HTTPException) as error:
        authenticate(token)

    assert error.value.status_code == 401


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/investigate", {"identity_id": "alex"}),
        ("post", "/approvals", {}),
        ("get", "/approvals/APP-001", None),
        ("post", "/approvals/APP-001/decision", {"status": "APPROVED"}),
        ("post", "/remediate", {"approval_id": "APP-001"}),
    ],
)
def test_endpoints_require_bearer_token(api_client, method, path, body):
    response = getattr(api_client, method)(
        path,
        **({"json": body} if body is not None else {}),
    )

    assert response.status_code in (401, 403)


def test_endpoint_accepts_valid_bearer_token(api_client, fake_azure, fake_ai):
    from fakes import ALEX_ID

    response = api_client.post(
        "/investigate",
        json={"identity_id": ALEX_ID},
        headers={"Authorization": f"Bearer {make_token()}"},
    )

    assert response.status_code == 200
