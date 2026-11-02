from __future__ import annotations

import time
from pathlib import Path

import jwt
import requests

from sycur_rag.core.config import get_settings


def create_app_jwt() -> str:
    """Create a short-lived GitHub App JWT."""
    settings = get_settings()
    app_id = settings.GITHUB_APP_ID
    key_location = settings.GITHUB_APP_PRIVATE_KEY_PATH

    if app_id is None or app_id <= 0:
        raise ValueError("GitHub App ID is not configured.")

    if not key_location:
        raise ValueError("GitHub App private key path is not configured.")

    key_path = Path(key_location).expanduser()

    try:
        private_key = key_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(
            "Unable to read GitHub App private key."
        ) from exc

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": str(app_id),
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )


def create_installation_access_token(
    installation_id: int,
    repository_full_name: str,
) -> str:
    """Create a repository-scoped GitHub installation token."""
    if (
        not isinstance(installation_id, int)
        or isinstance(installation_id, bool)
        or installation_id <= 0
    ):
        raise ValueError("Invalid GitHub installation ID.")

    if not isinstance(repository_full_name, str):
        raise ValueError("Invalid GitHub repository name.")

    parts = repository_full_name.split("/")

    if (
        len(parts) != 2
        or not all(parts)
        or repository_full_name.strip() != repository_full_name
    ):
        raise ValueError("Invalid GitHub repository name.")

    repository_name = parts[1]

    try:
        response = requests.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {create_app_jwt()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={
                "repositories": [repository_name],
                "permissions": {
                    "contents": "read",
                    "pull_requests": "read",
                    "checks": "write",
                },
            },
            timeout=15,
        )
    except requests.RequestException as exc:
        raise RuntimeError(
            "Unable to create GitHub installation access token."
        ) from exc

    if response.status_code != 201:
        raise RuntimeError(
            "GitHub installation token request failed."
        )

    try:
        token_response = response.json()
    except ValueError as exc:
        raise RuntimeError(
            "GitHub installation token response is invalid."
        ) from exc

    if not isinstance(token_response, dict):
        raise RuntimeError(
            "GitHub installation token response is invalid."
        )

    token = token_response.get("token")
    repositories = token_response.get("repositories")
    permissions = token_response.get("permissions")

    if (
        not isinstance(token, str)
        or not token.strip()
        or token_response.get("repository_selection") != "selected"
        or not isinstance(repositories, list)
        or len(repositories) != 1
        or not isinstance(repositories[0], dict)
        or not isinstance(repositories[0].get("full_name"), str)
        or repositories[0]["full_name"].casefold()
        != repository_full_name.casefold()
        or not isinstance(permissions, dict)
        or permissions.get("contents") != "read"
        or permissions.get("pull_requests") != "read"
        or permissions.get("checks") != "write"
        or any(
            name not in {
                "contents",
                "pull_requests",
                "metadata",
                "checks",
            }
            or level != ("write" if name == "checks" else "read")
            for name, level in permissions.items()
        )
    ):
        raise RuntimeError(
            "GitHub installation token response has unexpected scope."
        )

    return token
