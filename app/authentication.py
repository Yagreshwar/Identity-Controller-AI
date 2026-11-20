
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

from app.config import ENTRA_CLIENT_ID, ENTRA_TENANT_ID

security = HTTPBearer()

JWKS_URL = (
    f"https://login.microsoftonline.com/"
    f"{ENTRA_TENANT_ID}/discovery/v2.0/keys"
)

ISSUER = (
    f"https://login.microsoftonline.com/"
    f"{ENTRA_TENANT_ID}/v2.0"
)

jwks_client = PyJWKClient(JWKS_URL)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    if not ENTRA_CLIENT_ID or not ENTRA_TENANT_ID:
        raise HTTPException(
            status_code=500,
            detail="Entra authentication configuration is missing.",
        )

    token = credentials.credentials

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=ENTRA_CLIENT_ID,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud", "tid", "oid"]},
        )

        if claims.get("tid") != ENTRA_TENANT_ID:
            raise HTTPException(
                status_code=401,
                detail="Token belongs to an unauthorized tenant.",
            )

        scopes = claims.get("scp", "").split()

        if "access_as_user" not in scopes:
            raise HTTPException(
                status_code=403,
                detail="Required API scope is missing.",
            )

        return {
            "user_id": claims.get("oid"),
            "username": claims.get("preferred_username"),
            "name": claims.get("name"),
            "tenant_id": claims.get("tid"),
        }

    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token.",
        ) from exc
