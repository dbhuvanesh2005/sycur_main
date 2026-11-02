from types import SimpleNamespace
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import HTTPException
from starlette.middleware.cors import CORSMiddleware

from sycur_rag.api import auth as auth_module
from sycur_rag.api.main import app


ISSUER = "https://example.supabase.co/auth/v1"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"


def create_settings():
    return SimpleNamespace(
        SUPABASE_URL="https://example.supabase.co",
        SUPABASE_JWT_AUDIENCE="authenticated",
        supabase_issuer=ISSUER,
        supabase_jwks_url=JWKS_URL,
    )


def create_token(*, audience="authenticated", algorithm="RS256"):
    if algorithm == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    now = int(time.time())

    token = jwt.encode(
        {
            "sub": "11111111-2222-3333-4444-555555555555",
            "email": "admin@example.com",
            "aud": audience,
            "iss": ISSUER,
            "iat": now - 60,
            "exp": now + 3_600,
            "user_metadata": {
                "organization_name": "Example Engineering",
            },
        },
        private_key,
        algorithm=algorithm,
        headers={"kid": "test-key"},
    )

    return token, private_key.public_key()


@pytest.mark.parametrize("algorithm", ["ES256", "RS256"])
def test_valid_supabase_token_is_verified(monkeypatch, algorithm):
    token, public_key = create_token(algorithm=algorithm)

    fake_client = SimpleNamespace(
        get_signing_key_from_jwt=lambda _token: SimpleNamespace(
            key=public_key
        )
    )

    monkeypatch.setattr(
        auth_module,
        "_get_jwk_client",
        lambda _url: fake_client,
    )

    user = auth_module.verify_supabase_token(
        token,
        create_settings(),
    )

    assert user.email == "admin@example.com"
    assert user.organization_name == "Example Engineering"


def test_wrong_supabase_audience_is_rejected(monkeypatch):
    token, public_key = create_token(audience="unexpected")

    fake_client = SimpleNamespace(
        get_signing_key_from_jwt=lambda _token: SimpleNamespace(
            key=public_key
        )
    )

    monkeypatch.setattr(
        auth_module,
        "_get_jwk_client",
        lambda _url: fake_client,
    )

    with pytest.raises(HTTPException) as error:
        auth_module.verify_supabase_token(
            token,
            create_settings(),
        )

    assert error.value.status_code == 401


def test_protected_endpoint_requires_bearer_token():
    with pytest.raises(HTTPException) as error:
        auth_module.get_current_user(
            credentials=None,
            settings=create_settings(),
        )

    assert error.value.status_code == 401
    assert error.value.headers == {"WWW-Authenticate": "Bearer"}


def test_cors_allows_only_configured_frontend_origin():
    cors_middleware = next(
        middleware
        for middleware in app.user_middleware
        if middleware.cls is CORSMiddleware
    )

    assert cors_middleware.kwargs["allow_origins"] == [
        "http://localhost:5173"
    ]
    assert cors_middleware.kwargs["allow_credentials"] is False
    assert "*" not in cors_middleware.kwargs["allow_origins"]
