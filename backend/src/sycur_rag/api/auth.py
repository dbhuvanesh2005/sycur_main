from __future__ import annotations

from functools import lru_cache
from typing import Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel

from sycur_rag.core.config import Settings, get_settings


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["authentication"],
)

bearer_scheme = HTTPBearer(auto_error=False)

ALLOWED_SUPABASE_JWT_ALGORITHMS = {
    "ES256",
    "RS256",
}


class AuthenticatedUser(BaseModel):
    user_id: str
    email: str | None = None
    organization_name: str | None = None


@lru_cache(maxsize=4)
def _get_jwk_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(
        jwks_url,
        cache_keys=True,
    )


def verify_supabase_token(
    token: str,
    settings: Settings,
) -> AuthenticatedUser:
    """Verify a Supabase access token using its public signing keys."""

    if settings.SUPABASE_URL is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase authentication is not configured.",
        )

    try:
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")

        if algorithm not in ALLOWED_SUPABASE_JWT_ALGORITHMS:
            raise jwt.InvalidAlgorithmError(
                "Unsupported Supabase JWT algorithm."
            )

        signing_key = _get_jwk_client(
            settings.supabase_jwks_url
        ).get_signing_key_from_jwt(token)

        claims: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=[algorithm],
            audience=settings.SUPABASE_JWT_AUDIENCE,
            issuer=settings.supabase_issuer,
            leeway=30,
            options={
                "require": ["exp", "iat", "sub"],
            },
        )

    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = claims.get("sub")

    if not isinstance(user_id, str) or not user_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has no valid subject.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = claims.get("email")
    metadata = claims.get("user_metadata")
    organization_name = None

    if isinstance(metadata, dict):
        raw_organization_name = metadata.get("organization_name")

        if isinstance(raw_organization_name, str):
            organization_name = raw_organization_name.strip() or None

    return AuthenticatedUser(
        user_id=user_id,
        email=email if isinstance(email, str) else None,
        organization_name=organization_name,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    settings: Settings = Depends(get_settings),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return verify_supabase_token(
        credentials.credentials,
        settings,
    )


@router.get(
    "/me",
    response_model=AuthenticatedUser,
)
def get_authenticated_user(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Return the authenticated Supabase user for demo API validation."""

    return current_user
