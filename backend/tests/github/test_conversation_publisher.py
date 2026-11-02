import pytest

from sycur_rag.github import conversation_publisher as module


REPO = "test-owner/test-repo"
SHA = "a" * 40
MARKER = f"<!-- sycur:pr-review:{SHA} -->"


def test_scanning_comment_contains_live_scanner_details():
    body = module.build_conversation_comment(
        repository=REPO,
        pr_number=17,
        head_sha=SHA,
        stage="CODE_SCAN",
        scanner_events=[
            {
                "scanner": "gitleaks",
                "status": "completed",
                "duration_ms": 1250,
                "findings_count": 1,
                "targeted_files": ["src/auth.py"],
                "targeted_file_count": 1,
            },
            {
                "scanner": "semgrep",
                "status": "running",
                "duration_ms": 600,
                "findings_count": 0,
            },
        ],
    )

    assert body.startswith(MARKER)
    assert "**Review state:** SCANNING" in body
    assert "Gitleaks" in body
    assert "Semgrep" in body
    assert "`src/auth.py`" in body
    assert "1.25 s" in body
    assert "/pull/17/checks" in body


def test_execution_failure_comment_hides_raw_diagnostics():
    body = module.build_conversation_comment(
        repository=REPO,
        pr_number=17,
        head_sha=SHA,
        failure_type="RuntimeError",
        scanner_events=[
            {
                "scanner": "semgrep",
                "status": "failed",
                "duration_ms": 250,
                "findings_count": 0,
                "error_type": "ScannerExecutionError",
                "error_message": "private-api-key-123",
            },
        ],
    )

    assert "**Review state:** EXECUTION FAILED" in body
    assert "NOT ISSUED" in body
    assert "ScannerExecutionError" in body
    assert "private-api-key-123" not in body


def test_conversation_comment_post_patch_and_noop(monkeypatch):
    monkeypatch.setattr(
        module,
        "create_installation_access_token",
        lambda **kwargs: "fake-token",
    )

    calls = []
    saved = []

    def fake_request(url, token, *, method="GET", payload=None):
        calls.append((method, url, payload))

        if method == "GET":
            return list(saved)

        if method == "POST":
            comment = {
                "id": 123,
                "body": payload["body"],
                "user": {"type": "Bot"},
                "html_url": "https://github.com/example/comment/123",
            }
            saved.append(comment)
            return dict(comment)

        if method == "PATCH":
            saved[0]["body"] = payload["body"]
            return dict(saved[0])

        raise AssertionError(f"Unexpected HTTP method: {method}")

    monkeypatch.setattr(
        module,
        "_request_json",
        fake_request,
    )

    arguments = {
        "repository": REPO,
        "installation_id": 1,
        "pr_number": 17,
        "head_sha": SHA,
    }

    first = MARKER + "\nScanning..."
    second = MARKER + "\nReview completed."

    module.upsert_conversation_comment(
        **arguments,
        body=first,
    )

    assert len([
        item for item in calls if item[0] == "POST"
    ]) == 1

    module.upsert_conversation_comment(
        **arguments,
        body=second,
    )

    assert len([
        item for item in calls if item[0] == "PATCH"
    ]) == 1

    module.upsert_conversation_comment(
        **arguments,
        body=second,
    )

    # Identical updates do not create another notification.
    assert len([
        item for item in calls if item[0] == "POST"
    ]) == 1

    assert len([
        item for item in calls if item[0] == "PATCH"
    ]) == 1


def test_never_overwrite_a_developer_comment(monkeypatch):
    monkeypatch.setattr(
        module,
        "create_installation_access_token",
        lambda **kwargs: "fake-token",
    )

    methods = []

    def fake_request(url, token, *, method="GET", payload=None):
        methods.append(method)

        if method == "GET":
            return [{
                "id": 10,
                "body": MARKER + "\nDeveloper-written text",
                "user": {"type": "User"},
            }]

        if method == "POST":
            return {"id": 20, "body": payload["body"]}

        raise AssertionError("Developer comment was overwritten.")

    monkeypatch.setattr(
        module,
        "_request_json",
        fake_request,
    )

    module.upsert_conversation_comment(
        repository=REPO,
        installation_id=1,
        pr_number=17,
        head_sha=SHA,
        body=MARKER + "\nSYCUR scanning",
    )

    assert methods == ["GET", "POST"]
