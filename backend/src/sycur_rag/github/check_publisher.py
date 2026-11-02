from __future__ import annotations

import json
import re

from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from sycur_rag.core.config import get_settings
from sycur_rag.github.app_auth import (
    create_installation_access_token,
)
from sycur_rag.models.review import ReviewResult


CHECK_NAME = "TMT | SYCUR Security Review"

CONCLUSIONS = {
    "PASS": "success",
    "WARNING": "neutral",
    "FAIL": "failure",
    "INSUFFICIENT_EVIDENCE": "action_required",
}

PROGRESS_STAGES = {
    "CODE_SCAN": (
        "Code Security Analysis",
        "Inspecting changed code for potential security issues.",
    ),
    "FINDING_ANALYSIS": (
        "Finding Analysis",
        "Correlating and validating detected security findings.",
    ),
    "RAG_EVALUATION": (
        "Security Evidence Evaluation",
        "Retrieving relevant security requirements and evidence.",
    ),
    "AI_EXPLANATION": (
        "Security Explanation",
        "Preparing explanations and remediation guidance.",
    ),
    "POLICY_EVALUATION": (
        "Policy Evaluation",
        "Applying SYCUR's deterministic security policies.",
    ),
}


SCANNER_DISPLAY_NAMES = {
    "gitleaks": "Gitleaks",
    "semgrep": "Semgrep",
    "bandit": "Bandit",
    "trivy": "Trivy",
    "osv": "OSV-Scanner",
    "checkov": "Checkov",
}

SCANNER_STATUS_LABELS = {
    "queued": "⏳ Queued",
    "running": "🔄 Running",
    "completed": "✅ Completed",
    "failed": "❌ Failed",
}


def _format_scanner_duration(
    duration_ms: int | None,
) -> str:
    if duration_ms is None:
        return "In progress"

    if duration_ms < 1000:
        return f"{duration_ms} ms"

    return f"{duration_ms / 1000:.2f} s"


def _sanitize_scanner_diagnostic(value: str) -> str:
    """Remove common credentials from scanner diagnostics."""

    if not isinstance(value, str):
        raise ValueError("Invalid scanner diagnostic.")

    message = " ".join(value.split())

    patterns = [
        (
            r"(?i)\bBearer\s+[^\s,;]+",
            "Bearer [REDACTED]",
        ),
        (
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,})\b",
            "[REDACTED]",
        ),
        (
            r"\bAKIA[0-9A-Z]{16}\b",
            "[REDACTED]",
        ),
        (
            r"(?i)\b(authorization)\s*[:=]\s*"
            r"[^\s,;]+",
            r"\1=[REDACTED]",
        ),
        (
            r"(?i)\b(api[_-]?key|access[_-]?token|"
            r"refresh[_-]?token|password|passwd|"
            r"secret|token|client[_-]?secret)"
            r"\b(\s*[:=]\s*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
            r"\1\2[REDACTED]",
        ),
        (
            r"(?i)\b(https?://)[^/\s:@]+:[^@\s/]+@",
            r"\1[REDACTED]@",
        ),
    ]

    for pattern, replacement in patterns:
        message = re.sub(
            pattern,
            replacement,
            message,
        )

    return message[:500]


def _build_scanner_progress_section(
    scanner_events: list[dict] | None,
) -> str:
    """Build detailed scanner execution intelligence."""

    if scanner_events is None:
        return ""

    if not isinstance(scanner_events, list):
        raise ValueError(
            "scanner_events must be a list."
        )

    completed = 0
    failed = 0
    running = 0
    queued = 0
    total_findings = 0

    rows = []
    file_sections = []
    diagnostic_sections = []

    for event in scanner_events:

        if not isinstance(event, dict):
            raise ValueError(
                "Scanner event must be an object."
            )

        scanner = event.get("scanner")
        status = event.get("status")
        duration_ms = event.get("duration_ms")

        findings_count = event.get(
            "findings_count",
            0,
        )

        if scanner not in SCANNER_DISPLAY_NAMES:
            raise ValueError(
                "Unsupported scanner event."
            )

        if status not in SCANNER_STATUS_LABELS:
            raise ValueError(
                "Invalid scanner status."
            )

        if (
            duration_ms is not None
            and (
                not isinstance(duration_ms, int)
                or isinstance(duration_ms, bool)
                or duration_ms < 0
            )
        ):
            raise ValueError(
                "Invalid scanner duration."
            )

        if (
            not isinstance(findings_count, int)
            or isinstance(findings_count, bool)
            or findings_count < 0
        ):
            raise ValueError(
                "Invalid scanner findings count."
            )

        display_name = SCANNER_DISPLAY_NAMES[scanner]

        if status == "completed":
            completed += 1
        elif status == "failed":
            failed += 1
        elif status == "running":
            running += 1
        else:
            queued += 1

        total_findings += findings_count

        duration = _format_scanner_duration(
            duration_ms
        )

        rows.append(
            f"| {display_name} "
            f"| {SCANNER_STATUS_LABELS[status]} "
            f"| {duration} "
            f"| {findings_count} |"
        )

        # File target validation.
        targeted_files = event.get("targeted_files")
        supplied_file_count = event.get(
            "targeted_file_count"
        )

        if targeted_files is not None:

            if (
                not isinstance(targeted_files, list)
                or any(
                    not isinstance(path, str)
                    or not path.strip()
                    for path in targeted_files
                )
            ):
                raise ValueError(
                    "Invalid scanner file targets."
                )

            file_count = len(targeted_files)

            if supplied_file_count is not None:
                if (
                    type(supplied_file_count) is not int
                    or supplied_file_count != file_count
                ):
                    raise ValueError(
                        "Scanner file count mismatch."
                    )

            if targeted_files:

                visible_paths = []

                for path in targeted_files[:10]:
                    safe_path = (
                        " ".join(path.split())
                        .replace("`", "ˋ")
                    )

                    visible_paths.append(
                        f"- `{safe_path[:500]}`"
                    )

                remaining = file_count - len(visible_paths)

                if remaining:
                    visible_paths.append(
                        f"- ... and {remaining} more files"
                    )

                file_sections.append(
                    f"**{display_name} — "
                    f"Files targeted ({file_count}):**\n"
                    + "\n".join(visible_paths)
                )

            else:
                file_sections.append(
                    f"**{display_name}:** "
                    "No target files recorded."
                )

        elif supplied_file_count is not None:

            if (
                type(supplied_file_count) is not int
                or supplied_file_count < 0
            ):
                raise ValueError(
                    "Invalid scanner file count."
                )

            file_sections.append(
                f"**{display_name}:** "
                f"{supplied_file_count} target files; "
                "paths unavailable."
            )

        # Failure diagnostics.
        if status == "failed":

            error_type = event.get("error_type")
            error_message = event.get("error_message")

            if error_type is not None:
                if (
                    not isinstance(error_type, str)
                    or not re.fullmatch(
                        r"[A-Za-z][A-Za-z0-9_.]{0,127}",
                        error_type,
                    )
                ):
                    raise ValueError(
                        "Invalid scanner error type."
                    )

            if error_message is not None:
                if not isinstance(error_message, str):
                    raise ValueError(
                        "Invalid scanner error message."
                    )

                error_message = (
                    _sanitize_scanner_diagnostic(
                        error_message
                    )
                )

            diagnostic_parts = []

            if error_type:
                diagnostic_parts.append(
                    f"`{error_type}`"
                )

            if error_message:
                safe_message = error_message.replace(
                    "`", "ˋ"
                )

                diagnostic_parts.append(
                    f"`{safe_message}`"
                )

            explanation = (
                " — ".join(diagnostic_parts)
                if diagnostic_parts
                else "No diagnostic details were recorded."
            )

            diagnostic_sections.append(
                f"**{display_name} failure:** "
                f"{explanation}"
            )

    total = len(scanner_events)
    finished = completed + failed

    summary = (
        "### 🔍 Scanner Execution\n\n"
        f"**Progress:** {finished}/{total} finished "
        f"· {completed} completed "
        f"· {failed} failed "
        f"· {running} running "
        f"· {queued} queued\n\n"
        f"**Total findings detected:** {total_findings}\n\n"
        "| Security Scanner | Status | Duration | Findings |\n"
        "|---|---|---:|---:|\n"
        + "\n".join(rows)
    )

    if file_sections:
        summary += (
            "\n\n### 📁 Scanner File Targets\n\n"
            + "\n\n".join(file_sections)
            + "\n\n_File paths represent assigned scanner "
            "targets, not independently verified file reads._"
        )

    if diagnostic_sections:
        summary += (
            "\n\n### ⚠️ Scanner Diagnostics\n\n"
            + "\n\n".join(diagnostic_sections)
        )

    return summary


def _build_review_stage_progress_section(
    stage_events: list[dict] | None,
    total_duration_ms: int | None,
) -> str:

    if (
        stage_events is None
        and total_duration_ms is None
    ):
        return ""

    if not isinstance(stage_events, (list, type(None))):
        raise ValueError(
            "stage_events must be a list."
        )

    if (
        total_duration_ms is not None
        and (
            not isinstance(total_duration_ms, int)
            or isinstance(total_duration_ms, bool)
            or total_duration_ms < 0
        )
    ):
        raise ValueError(
            "Invalid total review duration."
        )

    recorded = {}

    for event in stage_events or []:

        if not isinstance(event, dict):
            raise ValueError(
                "Review stage event must be an object."
            )

        stage = event.get("stage")
        status = event.get("status")
        duration_ms = event.get("duration_ms")

        if (
            not isinstance(stage, str)
            or stage not in PROGRESS_STAGES
        ):
            raise ValueError(
                "Unsupported review stage event."
            )

        if stage in recorded:
            raise ValueError(
                "Duplicate review stage event."
            )

        if status not in {
            "in_progress",
            "completed",
            "failed",
        }:
            raise ValueError(
                "Invalid review stage status."
            )

        if (
            duration_ms is not None
            and (
                not isinstance(duration_ms, int)
                or isinstance(duration_ms, bool)
                or duration_ms < 0
            )
        ):
            raise ValueError(
                "Invalid review stage duration."
            )

        recorded[stage] = event

    labels = {
        "in_progress": "🔄 Running",
        "completed": "✅ Completed",
        "failed": "❌ Failed",
    }

    completed = 0
    failed = 0
    running = 0
    pending = 0

    rows = []

    for stage, (title, _) in PROGRESS_STAGES.items():

        event = recorded.get(stage)

        if event is None:
            status = "pending"
            duration = "—"
            pending += 1

        else:
            status = event["status"]

            duration_ms = event["duration_ms"]

            duration = (
                _format_scanner_duration(duration_ms)
                if duration_ms is not None
                else "—"
            )

            if status == "completed":
                completed += 1

            elif status == "failed":
                failed += 1

            else:
                running += 1

        status_label = (
            "⏳ Pending"
            if status == "pending"
            else labels[status]
        )

        rows.append(
            f"| {title} | {status_label} | {duration} |"
        )

    total = len(PROGRESS_STAGES)

    elapsed = (
        _format_scanner_duration(total_duration_ms)
        if total_duration_ms is not None
        else "Not available"
    )

    return (
        "### 🧭 SYCUR Review Pipeline\n\n"
        f"**Progress:** {completed}/{total} completed "
        f"· {failed} failed "
        f"· {running} running "
        f"· {pending} pending\n\n"
        f"**Total execution time:** {elapsed}\n\n"
        "| Review Stage | Status | Duration |\n"
        "|---|---|---:|\n"
        + "\n".join(rows)
    )


def validate_report_details_url(
    details_url: str | None,
) -> str | None:
    """Validate a public HTTPS SYCUR report URL."""

    if details_url is None:
        return None

    if (
        not isinstance(details_url, str)
        or not details_url
        or details_url != details_url.strip()
    ):
        raise ValueError("Invalid report details URL.")

    try:
        parsed = urlsplit(details_url)
    except ValueError as exc:
        raise ValueError(
            "Invalid report details URL."
        ) from exc

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(
            "Report details URL must be a valid HTTPS URL."
        )

    return details_url


def build_review_external_id(
    *,
    repository: str,
    pr_number: int,
    head_sha: str,
) -> str:
    """Stable identity for one PR at one commit."""

    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
        repository,
    ):
        raise ValueError("Invalid repository.")

    if type(pr_number) is not int or pr_number <= 0:
        raise ValueError("Invalid PR number.")

    if not isinstance(head_sha, str) or not re.fullmatch(
        r"[0-9a-fA-F]{40}", head_sha
    ):
        raise ValueError("Invalid commit SHA.")

    return (
        f"sycur:pr:{repository.casefold()}:"
        f"{pr_number}:{head_sha.lower()}"
    )


def build_check_run_payload(
    *,
    head_sha: str,
    review: ReviewResult,
    repository: str | None = None,
    pr_number: int | None = None,
    details_url: str | None = None,
    scanner_events: list[dict] | None = None,
    stage_events: list[dict] | None = None,
    total_duration_ms: int | None = None,
) -> dict:
    """Build a GitHub Check Run from a SYCUR policy review."""

    if not isinstance(review, ReviewResult):
        raise TypeError("review must be ReviewResult.")

    if not isinstance(head_sha, str) or not re.fullmatch(
        r"[0-9a-fA-F]{40}", head_sha
    ):
        raise ValueError("Invalid Git commit SHA.")

    status = getattr(review.status, "value", review.status)
    action = getattr(review.action, "value", review.action)

    if status not in CONCLUSIONS:
        raise ValueError("Unsupported SYCUR review status.")

    details_url = validate_report_details_url(
        details_url
    )

    summary = (
        f"**Review status:** {status}\n\n"
        f"**Policy action:** {action}\n\n"
        f"**Findings:** {review.finding_count}\n\n"
        f"**Warnings:** {review.warning_count}\n\n"
        f"**Blocking findings:** {review.blocking_count}\n\n"
        f"**Reason:** {review.reason}\n\n"
        "---\n"
        "Scope: Configured security checks for changed PR files. "
        "This result does not certify full regulatory compliance."
    )

    # Include the complete review execution timeline.
    stage_section = _build_review_stage_progress_section(
        stage_events,
        total_duration_ms,
    )
    scanner_section = _build_scanner_progress_section(
        scanner_events
    )

    if stage_section or scanner_section:

        sections = []

        if stage_section:
            sections.append(stage_section)

        if scanner_section:
            sections.append(scanner_section)

        summary = (
            "## TMT | SYCUR\n\n"
            "**Security Intelligence · PR Assessment**\n\n"
            + "\n\n".join(sections)
            + "\n\n---\n\n"
            + summary
        )

    annotations = []

    for reviewed in review.findings:
        finding = reviewed.finding

        if finding.line_start is None:
            continue

        path = finding.file_path.replace("\\", "/")

        if (
            path.startswith("/")
            or any(
                part in ("", ".", "..")
                for part in path.split("/")
            )
        ):
            continue

        finding_status = getattr(
            reviewed.status,
            "value",
            reviewed.status,
        )

        level = {
            "FAIL": "failure",
            "WARNING": "warning",
        }.get(finding_status, "notice")

        message = f"{finding.rule_id}: {finding.message}"

        if reviewed.finding_summary:
            message += (
                f"\n\nAI Summary: "
                f"{reviewed.finding_summary}"
            )

        if reviewed.risk_explanation:
            message += (
                f"\n\nSecurity Risk: "
                f"{reviewed.risk_explanation}"
            )

        if reviewed.required_action:
            message += (
                f"\n\nSuggested Fix: "
                f"{reviewed.required_action}"
            )

        if reviewed.evidence_references:
            evidence_lines = []

            for reference in reviewed.evidence_references:
                evidence_lines.append(
                    f"Source ID: {reference.source_id}\n"
                    f"Document: {reference.document_name}\n"
                    f"Title: {reference.title}"
                    + (
                        f"\nControl: {reference.control_id}"
                        if reference.control_id
                        else ""
                    )
                )

            message += (
                "\n\nSupporting Evidence:\n"
                + "\n\n".join(evidence_lines)
            )

        elif reviewed.source_ids:
            # Backward compatibility for older reviews.
            source_refs = ", ".join(
                str(source_id)
                for source_id in reviewed.source_ids
            )

            message += (
                f"\n\nEvidence IDs (current review): "
                f"{source_refs}"
            )

        annotations.append({
            "path": path,
            "start_line": finding.line_start,
            "end_line": max(
                finding.line_start,
                finding.line_end or finding.line_start,
            ),
            "annotation_level": level,
            "title": f"TMT | SYCUR: {finding.title}"[:255],
            "message": message[:65535],
        })

        if len(annotations) == 50:
            break

    payload = {
        "name": CHECK_NAME,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": CONCLUSIONS[status],
        "output": {
            "title": f"TMT | SYCUR Security Review — {status}",
            "summary": summary,
            "annotations": annotations,
        },
    }

    if details_url is not None:
        payload["details_url"] = details_url

    if (repository is None) != (pr_number is None):
        raise ValueError(
            "Repository and PR number must be supplied together."
        )
    if repository is not None:
        payload["external_id"] = build_review_external_id(
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
        )
    return payload


def build_check_run_progress_payload(
    *,
    repository: str,
    pr_number: int,
    head_sha: str,
    stage: str,
    scanner_events: list[dict] | None = None,
    stage_events: list[dict] | None = None,
    total_duration_ms: int | None = None,
) -> dict:
    """Build an in-progress SYCUR Check Run payload."""

    if not isinstance(head_sha, str) or not re.fullmatch(
        r"[0-9a-fA-F]{40}",
        head_sha,
    ):
        raise ValueError("Invalid Git commit SHA.")

    if stage not in PROGRESS_STAGES:
        raise ValueError("Unsupported review progress stage.")

    stage_title, description = PROGRESS_STAGES[stage]

    scanner_section = _build_scanner_progress_section(
        scanner_events
    )
    stage_section = _build_review_stage_progress_section(
        stage_events,
        total_duration_ms,
    )

    summary = (
        "## TMT | SYCUR\n\n"
        "**Security Intelligence · Automated PR Assessment**\n\n"
        f"**Current stage:** {stage_title}\n\n"
        f"{description}\n\n"
    )

    if stage_section:
        summary += stage_section + "\n\n"

    if scanner_section:
        summary += scanner_section + "\n\n"

    summary += (
        "---\n\n"
        "The security assessment is running. "
        "Final findings, remediation guidance, and the "
        "policy decision will appear here when complete."
    )

    return {
        "name": CHECK_NAME,
        "head_sha": head_sha,
        "status": "in_progress",
        "external_id": build_review_external_id(
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
        ),
        "output": {
            "title": f"TMT | SYCUR — {stage_title}",
            "summary": summary,
        },
    }


def build_check_run_failure_payload(
    *,
    repository: str,
    pr_number: int,
    head_sha: str,
    error_type: str,
    scanner_events: list[dict] | None = None,
    stage_events: list[dict] | None = None,
    total_duration_ms: int | None = None,
) -> dict:
    """Build a terminal GitHub Check Run for an execution failure."""

    if (
        not isinstance(repository, str)
        or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
            repository,
        )
    ):
        raise ValueError("Invalid repository.")

    if type(pr_number) is not int or pr_number < 1:
        raise ValueError("Invalid PR number.")

    if (
        not isinstance(head_sha, str)
        or not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha)
    ):
        raise ValueError("Invalid commit SHA.")

    if (
        not isinstance(error_type, str)
        or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.]{0,127}",
            error_type,
        )
    ):
        raise ValueError("Invalid execution error type.")

    # Scanner diagnostics can contain sensitive subprocess output.
    # Keep error types, statuses and targets, but do not publish
    # raw exception messages to GitHub.
    safe_scanner_events = None
    if scanner_events is not None:
        safe_scanner_events = [
            {**event, "error_message": None}
            for event in scanner_events
        ]

    sections = [
        "## TMT | SYCUR",
        "**Security Intelligence · Execution Failure**",
        "### ❌ Security Assessment Incomplete",
        (
            "SYCUR could not complete this security review. "
            "The PR has **not** received a clean security verdict."
        ),
        f"**Failure type:** `{error_type}`",
    ]

    stage_section = _build_review_stage_progress_section(
        stage_events,
        total_duration_ms,
    )
    scanner_section = _build_scanner_progress_section(
        safe_scanner_events
    )

    if stage_section:
        sections.append(stage_section)

    if scanner_section:
        sections.append(scanner_section)

    sections.extend([
        "---",
        "**Execution status:** FAILED",
        "**Security verdict:** NOT ISSUED",
        "**Required action:** Retry the SYCUR review "
        "or investigate the scanner/worker failure.",
        (
            "A scanner execution failure is not the same as "
            "a confirmed security-policy violation."
        ),
    ])

    return {
        "name": CHECK_NAME,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": "failure",
        "external_id": build_review_external_id(
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
        ),
        "output": {
            "title": "TMT | SYCUR — Security Assessment Incomplete",
            "summary": "\n\n".join(sections),
            "annotations": [],
        },
    }


def publish_github_check_failure(
    *,
    repository: str,
    installation_id: int,
    head_sha: str,
    pr_number: int,
    error_type: str,
    scanner_events: list[dict] | None = None,
    stage_events: list[dict] | None = None,
    total_duration_ms: int | None = None,
) -> dict:
    """Create or close the Check Run after review execution fails."""

    if type(installation_id) is not int or installation_id < 1:
        raise ValueError("Invalid installation ID.")

    payload = build_check_run_failure_payload(
        repository=repository,
        pr_number=pr_number,
        head_sha=head_sha,
        error_type=error_type,
        scanner_events=scanner_events,
        stage_events=stage_events,
        total_duration_ms=total_duration_ms,
    )

    app_id = get_settings().GITHUB_APP_ID
    if app_id is None or app_id <= 0:
        raise ValueError("GitHub App ID is not configured.")

    token = create_installation_access_token(
        installation_id=installation_id,
        repository_full_name=repository,
    )

    existing = find_existing_github_check_run(
        repository=repository,
        head_sha=head_sha,
        token=token,
        app_id=app_id,
        external_id=payload["external_id"],
    )

    endpoint = (
        f"https://api.github.com/repos/{repository}/check-runs"
    )

    if existing is not None:
        endpoint += f"/{existing['id']}"
        method = "PATCH"

        # GitHub PATCH requests must not change the commit SHA.
        payload.pop("head_sha")
    else:
        method = "POST"

    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "Content-Type": "application/json",
        },
        method=method,
    )

    with urlopen(request, timeout=20) as response:
        return json.load(response)


def publish_github_check_run(
    *,
    repository: str,
    installation_id: int,
    head_sha: str,
    review: ReviewResult,
    pr_number: int | None = None,
    details_url: str | None = None,
    scanner_events: list[dict] | None = None,
    stage_events: list[dict] | None = None,
    total_duration_ms: int | None = None,
) -> dict:
    """Publish a completed security review to GitHub."""

    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
        repository,
    ):
        raise ValueError("Invalid repository.")

    if type(installation_id) is not int or installation_id < 1:
        raise ValueError("Invalid installation ID.")

    app_id = get_settings().GITHUB_APP_ID
    if app_id is None or app_id <= 0:
        raise ValueError("GitHub App ID is not configured.")

    payload = build_check_run_payload(
        head_sha=head_sha,
        review=review,
        repository=repository if pr_number is not None else None,
        pr_number=pr_number,
        details_url=details_url,
        scanner_events=scanner_events,
        stage_events=stage_events,
        total_duration_ms=total_duration_ms,
    )

    token = create_installation_access_token(
        installation_id=installation_id,
        repository_full_name=repository,
    )

    external_id = (
        build_review_external_id(
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
        )
        if pr_number is not None
        else None
    )

    existing = find_existing_github_check_run(
        repository=repository,
        head_sha=head_sha,
        token=token,
        app_id=app_id,
        external_id=external_id,
    )
    if existing is not None:
        # Read existing annotations to avoid duplicate findings.
        existing_keys = set()
        page = 1

        def annotation_key(item):
            return (
                item.get("path"),
                item.get("start_line"),
                item.get("end_line"),
                item.get("annotation_level"),
                item.get("title"),
                item.get("message"),
            )

        while True:
            annotations_url = (
                f"https://api.github.com/repos/{repository}"
                f"/check-runs/{existing['id']}/annotations"
                f"?per_page=100&page={page}"
            )

            annotations_request = Request(
                annotations_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                },
            )

            with urlopen(annotations_request, timeout=20) as response:
                saved_annotations = json.load(response)

            if not isinstance(saved_annotations, list):
                raise RuntimeError("Invalid annotations response.")

            existing_keys.update(
                annotation_key(item)
                for item in saved_annotations
            )

            if len(saved_annotations) < 100:
                break

            page += 1

        payload["output"]["annotations"] = [
            annotation
            for annotation in payload["output"].get("annotations", [])
            if annotation_key(annotation) not in existing_keys
        ]

        url = (
            f"https://api.github.com/repos/{repository}"
            f"/check-runs/{existing['id']}"
        )
        method = "PATCH"
        expected_status = 200
        # head_sha belongs to creation, not update.
        payload.pop("head_sha")
    else:
        url = (
            f"https://api.github.com/repos/{repository}"
            "/check-runs"
        )
        method = "POST"
        expected_status = 201

    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method=method,
    )

    with urlopen(request, timeout=20) as response:
        if response.status != expected_status:
            raise RuntimeError("GitHub Check Run publishing failed.")

        result = json.load(response)

    return {
        "id": result["id"],
        "html_url": result["html_url"],
    }


def find_existing_github_check_run(
    *,
    repository: str,
    head_sha: str,
    token: str,
    app_id: int,
    external_id: str | None = None,
) -> dict | None:
    """Find our existing Check Run for an exact commit."""
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
        repository,
    ):
        raise ValueError("Invalid repository.")
    if not isinstance(head_sha, str) or not re.fullmatch(
        r"[0-9a-fA-F]{40}",
        head_sha,
    ):
        raise ValueError("Invalid Git commit SHA.")
    if not isinstance(token, str) or not token:
        raise ValueError("Invalid installation token.")
    if type(app_id) is not int or app_id <= 0:
        raise ValueError("Invalid GitHub App ID.")

    query = urlencode({
        "check_name": CHECK_NAME,
        "app_id": app_id,
        "filter": "all" if external_id is not None else "latest",
        "per_page": 100,
    })
    request = Request(
        f"https://api.github.com/repos/{repository}"
        f"/commits/{head_sha}/check-runs?{query}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method="GET",
    )

    with urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError("GitHub Check Run lookup failed.")
        result = json.load(response)

    if not isinstance(result, dict) or not isinstance(result.get("check_runs"), list):
        raise RuntimeError("Invalid GitHub Check Run lookup response.")

    for check_run in result["check_runs"]:
        if not isinstance(check_run, dict):
            raise RuntimeError("Invalid GitHub Check Run lookup response.")
        app = check_run.get("app")
        if (
            check_run.get("name") == CHECK_NAME
            and isinstance(check_run.get("head_sha"), str)
            and check_run["head_sha"].lower() == head_sha.lower()
            and isinstance(app, dict)
            and app.get("id") == app_id
            and (
                external_id is None
                or check_run.get("external_id") == external_id
            )
        ):
            return {
                "id": check_run["id"],
                "html_url": check_run["html_url"],
            }

    return None


def publish_github_check_progress(
    *,
    repository: str,
    installation_id: int,
    head_sha: str,
    pr_number: int,
    stage: str,
    scanner_events: list[dict] | None = None,
    stage_events: list[dict] | None = None,
    total_duration_ms: int | None = None,
) -> dict:
    """Create or update the existing PR security Check Run."""

    settings = get_settings()
    app_id = settings.GITHUB_APP_ID

    if app_id is None or app_id <= 0:
        raise ValueError("GitHub App ID is not configured.")

    if type(installation_id) is not int or installation_id <= 0:
        raise ValueError("Invalid installation ID.")

    payload = build_check_run_progress_payload(
        repository=repository,
        pr_number=pr_number,
        head_sha=head_sha,
        stage=stage,
        scanner_events=scanner_events,
        stage_events=stage_events,
        total_duration_ms=total_duration_ms,
    )

    token = create_installation_access_token(
        installation_id=installation_id,
        repository_full_name=repository,
    )

    existing = find_existing_github_check_run(
        repository=repository,
        head_sha=head_sha,
        token=token,
        app_id=app_id,
        external_id=payload["external_id"],
    )

    if existing is not None:
        payload.pop("head_sha")

        url = (
            f"https://api.github.com/repos/{repository}"
            f"/check-runs/{existing['id']}"
        )
        method = "PATCH"
        expected_status = 200

    else:
        url = (
            f"https://api.github.com/repos/{repository}"
            "/check-runs"
        )
        method = "POST"
        expected_status = 201

    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method=method,
    )

    with urlopen(request, timeout=20) as response:
        if response.status != expected_status:
            raise RuntimeError(
                "GitHub progress Check Run publishing failed."
            )

        result = json.load(response)

    if (
        not isinstance(result, dict)
        or "id" not in result
        or "html_url" not in result
    ):
        raise RuntimeError(
            "Invalid GitHub Check Run response."
        )

    return {
        "id": result["id"],
        "html_url": result["html_url"],
    }
