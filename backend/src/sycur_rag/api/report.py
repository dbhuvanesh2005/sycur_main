
from __future__ import annotations

import html
import logging
import os
import sqlite3

from pathlib import Path
from string import Template

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from sycur_rag.github.review_queue import (
    get_review_report_by_token,
)


logger = logging.getLogger(__name__)

router = APIRouter()

REPORT_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
    "Expires": "0",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "style-src 'unsafe-inline'; "
        "img-src data:; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    ),
}


def get_report_database_path() -> Path:
    """Use the same database as the GitHub webhook and worker."""

    return Path(
        os.environ.get(
            "SYCUR_REVIEW_QUEUE_DB",
            str(
                Path.home()
                / ".local"
                / "share"
                / "sycur"
                / "review_jobs.db"
            ),
        )
    ).expanduser()


def escape(value: object) -> str:
    """Escape all dynamic report content before HTML rendering."""

    if value is None:
        return ""

    return html.escape(str(value), quote=True)


def enum_value(value) -> str:
    return str(getattr(value, "value", value))


def status_class(status: str) -> str:
    return {
        "PASS": "pass",
        "WARNING": "warning",
        "FAIL": "fail",
        "INSUFFICIENT_EVIDENCE": "review",
    }.get(status, "neutral")


def render_finding(item) -> str:
    finding = item.finding

    status = enum_value(item.status)
    severity = enum_value(finding.severity)

    if finding.line_start is not None:
        location = f"{finding.file_path}:{finding.line_start}"

        if (
            finding.line_end is not None
            and finding.line_end != finding.line_start
        ):
            location += f"-{finding.line_end}"
    else:
        location = finding.file_path

    snippet_html = ""

    if finding.code_snippet:
        snippet_html = f"""
        <div class="detail-block">
            <h4>Code Evidence</h4>
            <pre><code>{escape(finding.code_snippet)}</code></pre>
        </div>
        """

    if item.explanation_available:
        explanation_html = f"""
        <div class="detail-block">
            <h4>Security Explanation</h4>
            <p>{escape(item.finding_summary)}</p>
        </div>

        <div class="detail-block risk">
            <h4>Security Risk</h4>
            <p>{escape(item.risk_explanation)}</p>
        </div>

        <div class="detail-block remediation">
            <h4>Recommended Remediation</h4>
            <p>{escape(item.required_action)}</p>
        </div>
        """
    else:
        explanation_html = """
        <div class="detail-block">
            <h4>Security Explanation</h4>
            <p>Detailed explanation is unavailable for this finding.</p>
        </div>
        """

    evidence_items = ""

    for reference in item.evidence_references:
        control = ""

        if reference.control_id:
            control = (
                f"<span>Control: "
                f"{escape(reference.control_id)}</span>"
            )

        evidence_items += f"""
        <li>
            <strong>{escape(reference.document_name)}</strong>
            <span>{escape(reference.title)}</span>
            {control}
            <small>Source ID: {escape(reference.source_id)}</small>
        </li>
        """

    if not evidence_items and item.source_ids:
        source_ids = ", ".join(
            str(source_id)
            for source_id in item.source_ids
        )

        evidence_items = (
            f"<li>Evidence source IDs: {escape(source_ids)}</li>"
        )

    evidence_html = ""

    if evidence_items:
        evidence_html = f"""
        <div class="detail-block">
            <h4>Supporting Compliance Evidence</h4>
            <ul class="evidence-list">
                {evidence_items}
            </ul>
        </div>
        """

    cwe_text = ", ".join(finding.cwe_ids) or "Not mapped"

    return f"""
    <article class="finding-card">

        <div class="finding-heading">
            <div>
                <span class="eyebrow">
                    {escape(finding.scanner)}
                    / {escape(finding.rule_id)}
                </span>

                <h3>{escape(finding.title)}</h3>
            </div>

            <div class="badges">
                <span class="badge {status_class(status)}">
                    {escape(status)}
                </span>

                <span class="badge severity">
                    {escape(severity)}
                </span>
            </div>
        </div>

        <div class="file-location">
            <span>FILE LOCATION</span>
            <code>{escape(location)}</code>
        </div>

        <p class="finding-message">
            {escape(finding.message)}
        </p>

        {snippet_html}

        <div class="detail-block">
            <h4>Policy Assessment</h4>
            <p>{escape(item.policy_reason)}</p>
        </div>

        {explanation_html}

        <div class="detail-block">
            <h4>Weakness Classification</h4>
            <p>{escape(cwe_text)}</p>
        </div>

        {evidence_html}

    </article>
    """


def format_execution_duration(duration_ms: int | None) -> str:
    """Format execution duration for the report UI."""

    if type(duration_ms) is not int or duration_ms < 0:
        return "Not recorded"

    if duration_ms < 1000:
        return f"{duration_ms} ms"

    seconds = duration_ms / 1000

    if seconds < 60:
        return f"{seconds:.2f} s"

    minutes, remaining_seconds = divmod(seconds, 60)

    return f"{int(minutes)}m {remaining_seconds:.1f}s"


def execution_status_class(status: str) -> str:
    """Map execution states to existing report badge styles."""

    return {
        "completed": "pass",
        "failed": "fail",
        "running": "warning",
        "in_progress": "warning",
    }.get(str(status).lower(), "neutral")


def render_execution_history(history: list[dict]) -> str:
    """Render immutable review attempts and stage timings."""

    if not history:
        return """
        <div class="empty-state">
            <h3>Execution history unavailable</h3>
            <p>
                No execution history was recorded for this review.
            </p>
        </div>
        """

    attempts_html = []

    for run in reversed(history):

        attempt_number = escape(run.get("attempt_number", "—"))

        status = str(run.get("status") or "unknown")
        status_label = escape(status.replace("_", " ").upper())

        commit_sha = str(run.get("head_sha") or "")
        short_sha = escape(commit_sha[:12] or "Not recorded")

        total_duration = format_execution_duration(
            run.get("duration_ms")
        )

        started_at = escape(run.get("started_at") or "—")
        completed_at = escape(run.get("completed_at") or "—")

        stage_items = []

        for stage in run.get("stages") or []:

            stage_name = escape(
                str(stage.get("stage") or "Unknown stage")
                .replace("_", " ")
            )

            stage_status = str(
                stage.get("status") or "unknown"
            )

            stage_status_label = escape(
                stage_status.replace("_", " ").upper()
            )

            stage_duration = format_execution_duration(
                stage.get("duration_ms")
            )

            stage_started = escape(
                stage.get("started_at") or "—"
            )

            stage_completed = escape(
                stage.get("completed_at") or "—"
            )

            stage_items.append(
                f"""
                <li class="stage-row">

                    <div class="stage-main">
                        <strong>{stage_name}</strong>

                        <div class="stage-times">
                            <span>Started: {stage_started}</span>
                            <span>Finished: {stage_completed}</span>
                        </div>
                    </div>

                    <span class="badge {
                        execution_status_class(stage_status)
                    }">
                        {stage_status_label}
                    </span>

                    <strong class="stage-duration">
                        {escape(stage_duration)}
                    </strong>

                </li>
                """
            )

        if stage_items:
            stages_html = (
                '<ol class="stage-timeline">'
                + "".join(stage_items)
                + "</ol>"
            )
        else:
            stages_html = """
            <p class="muted">
                No individual stage timings recorded.
            </p>
            """

        failure_html = ""

        if run.get("failure_stage") or run.get("error_type"):

            failure_html = f"""
            <div class="execution-failure">
                <strong>Execution Failure Details</strong>

                <p>
                    Failure stage:
                    {escape(run.get("failure_stage") or "Unknown")}
                </p>

                <p>
                    Error type:
                    {escape(run.get("error_type") or "Unknown")}
                </p>
            </div>
            """

        attempts_html.append(
            f"""
            <article class="execution-attempt">

                <div class="execution-header">

                    <div>
                        <div class="eyebrow">
                            ATTEMPT #{attempt_number}
                        </div>

                        <div class="execution-commit">
                            Commit: <code>{short_sha}</code>
                        </div>
                    </div>

                    <span class="badge {
                        execution_status_class(status)
                    }">
                        {status_label}
                    </span>

                </div>

                <div class="execution-summary">

                    <div>
                        <span>Total Duration</span>
                        <strong>{escape(total_duration)}</strong>
                    </div>

                    <div>
                        <span>Started At</span>
                        <strong>{started_at}</strong>
                    </div>

                    <div>
                        <span>Completed At</span>
                        <strong>{completed_at}</strong>
                    </div>

                </div>

                <h4>Stage Breakdown</h4>

                {stages_html}

                {failure_html}

            </article>
            """
        )

    return "".join(attempts_html)


def render_report(report: dict) -> str:
    review = report["review"]

    status = enum_value(review.status)
    action = enum_value(review.action)
    severity = enum_value(review.severity)

    findings_html = "".join(
        render_finding(item)
        for item in review.findings
    )

    if not findings_html:
        findings_html = """
        <div class="empty-state">
            <div class="empty-icon">✓</div>
            <h3>No security findings recorded</h3>
            <p>
                No findings were recorded in this review.
                This result applies only to the configured
                checks and reviewed PR files.
            </p>
        </div>
        """

    page = Template("""
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <meta name="robots"
              content="noindex,nofollow,noarchive">

        <title>SYCUR Security Review</title>

        <style>
            :root {
                --bg: #0b1020;
                --surface: #111b2e;
                --surface2: #18243a;
                --border: #28364e;
                --text: #edf2ff;
                --muted: #9baac0;
                --brand: #a78bfa;
                --green: #22c55e;
                --yellow: #eab308;
                --red: #ef4444;
                --orange: #f97316;
            }

            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                background: var(--bg);
                color: var(--text);
                font-family: -apple-system, BlinkMacSystemFont,
                    "Segoe UI", sans-serif;
                line-height: 1.6;
            }

            .shell {
                max-width: 1100px;
                margin: auto;
                padding: 30px 22px;
            }

            header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 15px;
                padding-bottom: 25px;
                border-bottom: 1px solid var(--border);
            }

            .brand {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .brand-mark {
                width: 42px;
                height: 42px;
                display: grid;
                place-items: center;
                border-radius: 12px;
                background: var(--brand);
                color: #171329;
                font-weight: 900;
                font-size: 20px;
            }

            .brand-name {
                font-size: 20px;
                font-weight: 800;
                letter-spacing: 1px;
            }

            .brand-subtitle,
            .eyebrow,
            .muted {
                color: var(--muted);
            }

            .brand-subtitle {
                font-size: 10px;
                letter-spacing: 2px;
            }

            .report-label {
                font-size: 11px;
                letter-spacing: 1.5px;
                color: var(--muted);
            }

            .hero {
                padding: 35px 0;
            }

            h1 {
                font-size: clamp(28px, 5vw, 42px);
                margin: 8px 0;
            }

            h2 {
                font-size: 23px;
            }

            h3 {
                font-size: 18px;
                margin: 8px 0;
            }

            h4 {
                font-size: 13px;
                margin: 0 0 8px;
                color: var(--brand);
            }

            p {
                color: #c7d2e5;
                overflow-wrap: anywhere;
            }

            .eyebrow {
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1.5px;
                text-transform: uppercase;
            }

            .hero-meta {
                display: flex;
                flex-wrap: wrap;
                gap: 12px;
                margin-top: 15px;
                color: var(--muted);
                font-size: 13px;
            }

            .status-pill,
            .badge {
                display: inline-flex;
                padding: 7px 13px;
                border-radius: 7px;
                font-size: 12px;
                font-weight: 800;
            }

            .pass {
                background: #14532d;
                color: #86efac;
            }

            .warning {
                background: #713f12;
                color: #fde047;
            }

            .fail {
                background: #7f1d1d;
                color: #fca5a5;
            }

            .review {
                background: #7c2d12;
                color: #fdba74;
            }

            .severity,
            .neutral {
                background: var(--surface2);
                color: var(--muted);
            }

            .metrics {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 14px;
                margin-bottom: 35px;
            }

            .metric,
            .panel,
            .finding-card {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 13px;
            }

            .metric {
                padding: 20px;
            }

            .metric strong {
                display: block;
                font-size: 30px;
            }

            .metric span {
                font-size: 12px;
                color: var(--muted);
            }

            .panel {
                padding: 24px;
                margin-bottom: 24px;
            }

            .summary-grid {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 15px;
            }

            .summary-item {
                background: var(--surface2);
                padding: 15px;
                border-radius: 9px;
            }

            .summary-item span {
                display: block;
                color: var(--muted);
                font-size: 11px;
                margin-bottom: 5px;
            }

            .finding-card {
                padding: 22px;
                margin-bottom: 17px;
            }

            .finding-heading {
                display: flex;
                align-items: flex-start;
                justify-content: space-between;
                gap: 15px;
            }

            .badges {
                display: flex;
                flex-wrap: wrap;
                gap: 7px;
            }

            .file-location {
                display: flex;
                flex-wrap: wrap;
                gap: 12px;
                padding: 12px;
                margin: 18px 0;
                background: var(--surface2);
                border-radius: 8px;
                font-size: 12px;
            }

            .file-location span {
                color: var(--muted);
                font-weight: 700;
            }

            .finding-message {
                font-size: 14px;
            }

            .detail-block {
                padding: 15px;
                margin-top: 13px;
                background: var(--surface2);
                border-radius: 9px;
            }

            .risk {
                border-left: 3px solid var(--red);
            }

            .remediation {
                border-left: 3px solid var(--green);
            }

            pre {
                white-space: pre-wrap;
                overflow-wrap: anywhere;
                padding: 13px;
                border-radius: 7px;
                background: #080d18;
                color: #d1fae5;
                overflow-x: auto;
            }

            code {
                overflow-wrap: anywhere;
            }

            .evidence-list {
                padding-left: 20px;
            }

            .evidence-list li {
                margin: 10px 0;
            }

            .evidence-list span,
            .evidence-list small {
                display: block;
                color: var(--muted);
            }

            .empty-state {
                text-align: center;
                padding: 45px 20px;
                border: 1px dashed var(--border);
                border-radius: 12px;
            }

            .empty-icon {
                font-size: 38px;
                color: var(--green);
            }

            .roadmap {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
                padding: 0;
                list-style: none;
            }

            .roadmap li {
                padding: 13px;
                background: var(--surface2);
                border-radius: 8px;
                font-size: 13px;
            }

            .execution-attempt {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 13px;
                padding: 22px;
                margin-bottom: 16px;
            }

            .execution-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 15px;
            }

            .execution-commit {
                margin-top: 8px;
                color: var(--muted);
                font-size: 12px;
            }

            .execution-summary {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                margin: 20px 0;
            }

            .execution-summary > div {
                background: var(--surface2);
                padding: 14px;
                border-radius: 9px;
                min-width: 0;
            }

            .execution-summary span {
                display: block;
                color: var(--muted);
                font-size: 11px;
                margin-bottom: 6px;
            }

            .execution-summary strong {
                display: block;
                font-size: 13px;
                overflow-wrap: anywhere;
            }

            .stage-timeline {
                list-style: none;
                padding: 0;
                margin: 15px 0 0;
            }

            .stage-row {
                display: grid;
                grid-template-columns: minmax(0, 1fr) auto auto;
                align-items: center;
                gap: 12px;
                padding: 13px;
                margin-bottom: 9px;
                background: var(--surface2);
                border-radius: 9px;
            }

            .stage-main {
                min-width: 0;
            }

            .stage-main strong {
                font-size: 13px;
            }

            .stage-times {
                display: flex;
                flex-wrap: wrap;
                gap: 5px 12px;
                margin-top: 5px;
                color: var(--muted);
                font-size: 10px;
            }

            .stage-duration {
                font-size: 12px;
                white-space: nowrap;
            }

            .execution-failure {
                margin-top: 18px;
                padding: 14px;
                border-left: 3px solid var(--red);
                background: var(--surface2);
                border-radius: 5px;
            }

            .execution-failure p {
                font-size: 12px;
                margin-bottom: 4px;
            }

            @media (max-width: 650px) {
                .execution-summary {
                    grid-template-columns: 1fr;
                }

                .stage-row {
                    grid-template-columns: minmax(0, 1fr) auto;
                }

                .stage-duration {
                    grid-column: 1 / -1;
                }

                .execution-header {
                    align-items: flex-start;
                }
            }

            footer {
                padding: 25px 0;
                margin-top: 35px;
                border-top: 1px solid var(--border);
                text-align: center;
                color: var(--muted);
                font-size: 12px;
            }

            @media (max-width: 650px) {
                .metrics {
                    grid-template-columns: repeat(2, 1fr);
                }

                .summary-grid {
                    grid-template-columns: 1fr;
                }

                .finding-heading {
                    flex-direction: column;
                }

                .roadmap {
                    grid-template-columns: 1fr;
                }

                .shell {
                    padding: 18px 14px;
                }
            }
        </style>
    </head>

    <body>
        <div class="shell">

            <header>
                <div class="brand">
                    <div class="brand-mark">S</div>

                    <div>
                        <div class="brand-name">SYCUR</div>
                        <div class="brand-subtitle">
                            SECURITY INTELLIGENCE
                        </div>
                    </div>
                </div>

                <div class="report-label">
                    PR SECURITY REPORT
                </div>
            </header>

            <section class="hero">
                <div class="eyebrow">
                    Automated Pull Request Assessment
                </div>

                <h1>Security Review</h1>

                <p>$repository · Pull Request #$pr_number</p>

                <span class="status-pill $status_class">
                    $status
                </span>

                <div class="hero-meta">
                    <span>Commit: $head_sha</span>
                    <span>Reviewed: $created_at</span>
                </div>
            </section>

            <section class="metrics">
                <div class="metric">
                    <strong>$finding_count</strong>
                    <span>Total Findings</span>
                </div>

                <div class="metric">
                    <strong>$blocking_count</strong>
                    <span>Blocking Findings</span>
                </div>

                <div class="metric">
                    <strong>$warning_count</strong>
                    <span>Warnings</span>
                </div>

                <div class="metric">
                    <strong>$explained_count</strong>
                    <span>Explained Findings</span>
                </div>
            </section>

            <section class="panel">
                <div class="eyebrow">01 / Executive Summary</div>

                <h2>Review Overview</h2>

                <p>$reason</p>

                <div class="summary-grid">
                    <div class="summary-item">
                        <span>Policy Action</span>
                        <strong>$action</strong>
                    </div>

                    <div class="summary-item">
                        <span>Overall Severity</span>
                        <strong>$severity</strong>
                    </div>

                    <div class="summary-item">
                        <span>Review Status</span>
                        <strong>$status</strong>
                    </div>
                </div>
            </section>

            <section>
                <div class="eyebrow">02 / Detailed Assessment</div>

                <h2>Security Findings</h2>

                $findings_html
            </section>

            <section>
                <div class="eyebrow">03 / Execution Diagnostics</div>

                <h2>Review Execution History</h2>

                $execution_history_html
            </section>

            <section class="panel">
                <div class="eyebrow">04 / Product Roadmap</div>

                <h2>Coming Soon</h2>

                <ul class="roadmap">
                    <li>Live PR scanning progress</li>
                    <li>Parallel security review workers</li>
                    <li>Expanded compliance control mapping</li>
                    <li>Guided remediation and re-review</li>
                </ul>
            </section>

            <footer>
                <strong>SYCUR</strong> · Security Intelligence

                <p>
                    This report represents the configured
                    checks performed on the specified PR commit.
                    It does not certify complete regulatory compliance.
                </p>

                © SYCUR · Confidential Security Report
            </footer>

        </div>
    </body>
    </html>
    """)

    return page.substitute(
        repository=escape(report["repository"]),
        pr_number=escape(report["pr_number"]),
        head_sha=escape(report["head_sha"][:12]),
        created_at=escape(report["created_at"]),
        status=escape(status),
        status_class=status_class(status),
        action=escape(action),
        severity=escape(severity),
        reason=escape(review.reason),
        finding_count=review.finding_count,
        blocking_count=review.blocking_count,
        warning_count=review.warning_count,
        explained_count=review.explained_count,
        findings_html=findings_html,
        execution_history_html=render_execution_history(
            report.get("execution_history", [])
        ),
    )


@router.get(
    "/reports/{report_token}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def view_security_report(
    report_token: str,
) -> HTMLResponse:
    """Display a private SYCUR security report."""

    try:
        report = get_review_report_by_token(
            report_token=report_token,
            db_path=get_report_database_path(),
        )

    except ValueError:
        raise HTTPException(
            status_code=404,
            detail="Security report not found.",
            headers=REPORT_HEADERS,
        )

    except (OSError, sqlite3.Error):
        logger.exception(
            "Unable to retrieve SYCUR security report."
        )

        raise HTTPException(
            status_code=503,
            detail="Security report temporarily unavailable.",
            headers=REPORT_HEADERS,
        )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Security report not found.",
            headers=REPORT_HEADERS,
        )

    return HTMLResponse(
        content=render_report(report),
        status_code=200,
        headers=REPORT_HEADERS,
    )
