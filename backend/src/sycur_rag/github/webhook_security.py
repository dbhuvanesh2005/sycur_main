import hashlib
import hmac


def verify_github_signature(
    payload: bytes,
    signature: str | None,
    secret: str,
) -> bool:
    """Verify a GitHub webhook HMAC-SHA256 signature."""

    if not signature or not secret:
        return False

    prefix = "sha256="

    if not signature.startswith(prefix):
        return False

    expected_signature = prefix + hmac.new(
        key=secret.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected_signature,
        signature,
    )
