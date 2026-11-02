from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sycur_rag.github.pr_event import ValidatedPREvent
from sycur_rag.models.review import ReviewResult


def _ensure_review_job_lease_columns(
    connection: sqlite3.Connection,
) -> None:
    """Add lease and diagnostic columns to an existing review queue."""

    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(review_jobs)"
        )
    }

    if "lease_token" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN lease_token TEXT"
        )

    if "lease_expires_at" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN lease_expires_at INTEGER"
        )

    if "retry_after" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN retry_after INTEGER"
        )

    # Review lifecycle diagnostics.

    if "last_stage" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN last_stage TEXT"
        )

    if "failure_stage" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN failure_stage TEXT"
        )

    if "error_type" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN error_type TEXT"
        )

    if "error_message" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN error_message TEXT"
        )

    if "failed_at" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN failed_at TEXT"
        )

    if "active_run_id" not in columns:
        connection.execute(
            "ALTER TABLE review_jobs "
            "ADD COLUMN active_run_id TEXT"
        )

    # Permanent review execution history.

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS review_runs (
            run_id TEXT PRIMARY KEY,
            delivery_id TEXT NOT NULL,
            attempt_number INTEGER NOT NULL
                CHECK (attempt_number > 0),
            repository TEXT NOT NULL,
            pr_number INTEGER NOT NULL,
            head_sha TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN (
                    'running',
                    'completed',
                    'failed'
                )),
            started_at TEXT NOT NULL,
            started_at_epoch_ms INTEGER NOT NULL,
            completed_at TEXT,
            duration_ms INTEGER,
            failure_stage TEXT,
            error_type TEXT,
            error_message TEXT,
            UNIQUE (delivery_id, attempt_number)
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS review_stage_events (
            event_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            stage TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN (
                    'in_progress',
                    'completed',
                    'failed'
                )),
            started_at TEXT NOT NULL,
            started_at_epoch_ms INTEGER NOT NULL,
            completed_at TEXT,
            duration_ms INTEGER,
            UNIQUE (run_id, stage),
            FOREIGN KEY (run_id)
                REFERENCES review_runs(run_id)
        )
        """
    )

    # Independent scanner execution history.
    # Unlike review stages, scanner events can run concurrently.

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS review_scanner_events (
            event_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,

            scanner TEXT NOT NULL
                CHECK (scanner IN (
                    'gitleaks',
                    'semgrep',
                    'bandit',
                    'trivy',
                    'osv',
                    'checkov'
                )),

            file_paths_json TEXT NOT NULL,

            status TEXT NOT NULL
                CHECK (status IN (
                    'queued',
                    'running',
                    'completed',
                    'failed'
                )),

            queued_at TEXT NOT NULL,
            started_at TEXT,
            started_at_epoch_ms INTEGER,
            completed_at TEXT,
            duration_ms INTEGER,

            findings_count INTEGER NOT NULL DEFAULT 0
                CHECK (findings_count >= 0),

            error_type TEXT,
            error_message TEXT,

            UNIQUE (run_id, scanner),

            FOREIGN KEY (run_id)
                REFERENCES review_runs(run_id)
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_review_scanner_events_run
        ON review_scanner_events(run_id, queued_at)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_review_runs_delivery
        ON review_runs(delivery_id, attempt_number)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_review_stage_events_run
        ON review_stage_events(run_id)
        """
    )


def _utc_timestamp_from_epoch_ms(epoch_ms: int) -> str:
    """Convert epoch milliseconds into an ISO-8601 UTC timestamp."""

    return (
        datetime.fromtimestamp(
            epoch_ms / 1000,
            tz=timezone.utc,
        )
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _get_active_review_run_id_with_lease(
    connection: sqlite3.Connection,
    *,
    delivery_id: str,
    lease_token: str,
) -> str | None:
    """Return the active run ID only for a valid worker lease."""

    job = connection.execute(
        """
        SELECT active_run_id
        FROM review_jobs
        WHERE delivery_id = ?
          AND status = 'running'
          AND lease_token = ?
          AND lease_expires_at >
              CAST(strftime('%s', 'now') AS INTEGER)
        """,
        (delivery_id, lease_token),
    ).fetchone()

    if job is None:
        return None

    run_id = job["active_run_id"]

    if not run_id:
        raise RuntimeError(
            "Review job has no active execution run."
        )

    run = connection.execute(
        """
        SELECT status
        FROM review_runs
        WHERE run_id = ?
          AND delivery_id = ?
        """,
        (run_id, delivery_id),
    ).fetchone()

    if run is None or run["status"] != "running":
        raise RuntimeError(
            "Active review execution is not running."
        )

    return run_id


def queue_review_scanner_events_with_lease(
    *,
    delivery_id: str,
    lease_token: str,
    scanner_plan: list[tuple[str, list[str] | tuple[str, ...]]],
    db_path: str | Path,
) -> bool:
    """Create scanner execution records for an active review."""

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    if not isinstance(lease_token, str) or not lease_token.strip():
        raise ValueError("Invalid lease token.")

    if not isinstance(scanner_plan, list):
        raise TypeError("scanner_plan must be a list.")

    allowed_scanners = {
        "gitleaks",
        "semgrep",
        "bandit",
        "trivy",
        "osv",
        "checkov",
    }

    normalized_plan = []
    seen_scanners = set()

    for item in scanner_plan:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("Invalid scanner plan item.")

        scanner, file_paths = item

        if scanner not in allowed_scanners:
            raise ValueError("Unsupported scanner.")

        if scanner in seen_scanners:
            raise ValueError("Duplicate scanner in plan.")

        if not isinstance(file_paths, (list, tuple)):
            raise TypeError("Invalid scanner file paths.")

        if not file_paths or any(
            not isinstance(path, str) or not path.strip()
            for path in file_paths
        ):
            raise ValueError("Invalid scanner file paths.")

        seen_scanners.add(scanner)

        normalized_plan.append(
            (
                scanner,
                json.dumps(
                    list(file_paths),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        )

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        connection.row_factory = sqlite3.Row

        with connection:
            connection.execute("BEGIN IMMEDIATE")

            run_id = _get_active_review_run_id_with_lease(
                connection,
                delivery_id=delivery_id,
                lease_token=lease_token,
            )

            if run_id is None:
                return False

            now_epoch_ms = time.time_ns() // 1_000_000
            now_timestamp = _utc_timestamp_from_epoch_ms(
                now_epoch_ms
            )

            for scanner, file_paths_json in normalized_plan:

                existing = connection.execute(
                    """
                    SELECT file_paths_json
                    FROM review_scanner_events
                    WHERE run_id = ?
                      AND scanner = ?
                    """,
                    (run_id, scanner),
                ).fetchone()

                if existing is not None:
                    if existing["file_paths_json"] != file_paths_json:
                        raise RuntimeError(
                            "Scanner execution plan changed "
                            f"for {scanner}."
                        )

                    continue

                connection.execute(
                    """
                    INSERT INTO review_scanner_events (
                        event_id,
                        run_id,
                        scanner,
                        file_paths_json,
                        status,
                        queued_at
                    )
                    VALUES (?, ?, ?, ?, 'queued', ?)
                    """,
                    (
                        str(uuid4()),
                        run_id,
                        scanner,
                        file_paths_json,
                        now_timestamp,
                    ),
                )

            return True


def update_review_scanner_event_with_lease(
    *,
    delivery_id: str,
    lease_token: str,
    scanner: str,
    status: str,
    db_path: str | Path,
    findings_count: int = 0,
    error_type: str | None = None,
    error_message: str | None = None,
) -> bool:
    """Persist an individual scanner lifecycle transition."""

    allowed_scanners = {
        "gitleaks",
        "semgrep",
        "bandit",
        "trivy",
        "osv",
        "checkov",
    }

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    if not isinstance(lease_token, str) or not lease_token.strip():
        raise ValueError("Invalid lease token.")

    if scanner not in allowed_scanners:
        raise ValueError("Unsupported scanner.")

    if status not in {"running", "completed", "failed"}:
        raise ValueError("Invalid scanner status.")

    if (
        not isinstance(findings_count, int)
        or isinstance(findings_count, bool)
        or findings_count < 0
    ):
        raise ValueError("Invalid findings count.")

    if status == "failed":
        if not isinstance(error_type, str) or not error_type.strip():
            raise ValueError("Failed scanner requires an error type.")

    elif error_type is not None or error_message is not None:
        raise ValueError(
            "Error details are only valid for failed scanners."
        )

    if (
        error_message is not None
        and not isinstance(error_message, str)
    ):
        raise ValueError("Invalid scanner error message.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        connection.row_factory = sqlite3.Row

        with connection:
            connection.execute("BEGIN IMMEDIATE")

            run_id = _get_active_review_run_id_with_lease(
                connection,
                delivery_id=delivery_id,
                lease_token=lease_token,
            )

            if run_id is None:
                return False

            event = connection.execute(
                """
                SELECT *
                FROM review_scanner_events
                WHERE run_id = ?
                  AND scanner = ?
                """,
                (run_id, scanner),
            ).fetchone()

            if event is None:
                raise RuntimeError(
                    f"Scanner event not queued: {scanner}"
                )

            current_status = event["status"]

            if status == "running":

                if current_status == "running":
                    return True

                if current_status != "queued":
                    raise RuntimeError(
                        f"Invalid scanner transition: "
                        f"{current_status} -> running"
                    )

                now_epoch_ms = time.time_ns() // 1_000_000
                now_timestamp = _utc_timestamp_from_epoch_ms(
                    now_epoch_ms
                )

                cursor = connection.execute(
                    """
                    UPDATE review_scanner_events
                    SET status = 'running',
                        started_at = ?,
                        started_at_epoch_ms = ?
                    WHERE event_id = ?
                      AND status = 'queued'
                    """,
                    (
                        now_timestamp,
                        now_epoch_ms,
                        event["event_id"],
                    ),
                )

            else:

                if current_status == status:
                    if (
                        event["findings_count"] != findings_count
                        or event["error_type"] != error_type
                        or event["error_message"] != error_message
                    ):
                        raise RuntimeError(
                            "Conflicting scanner completion event."
                        )

                    return True

                if current_status != "running":
                    raise RuntimeError(
                        f"Invalid scanner transition: "
                        f"{current_status} -> {status}"
                    )

                now_epoch_ms = time.time_ns() // 1_000_000
                now_timestamp = _utc_timestamp_from_epoch_ms(
                    now_epoch_ms
                )

                duration_ms = max(
                    0,
                    now_epoch_ms - event["started_at_epoch_ms"],
                )

                cursor = connection.execute(
                    """
                    UPDATE review_scanner_events
                    SET status = ?,
                        completed_at = ?,
                        duration_ms = ?,
                        findings_count = ?,
                        error_type = ?,
                        error_message = ?
                    WHERE event_id = ?
                      AND status = 'running'
                    """,
                    (
                        status,
                        now_timestamp,
                        duration_ms,
                        findings_count,
                        error_type,
                        error_message,
                        event["event_id"],
                    ),
                )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    "Unable to persist scanner execution event."
                )

            return True


def _finalize_interrupted_review_run(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    completed_at: str,
    completed_at_epoch_ms: int,
) -> None:
    """Record an execution abandoned after its worker lease expired."""

    run = connection.execute(
        """
        SELECT started_at_epoch_ms
        FROM review_runs
        WHERE run_id = ?
          AND status = 'running'
        """,
        (run_id,),
    ).fetchone()

    if run is None:
        return

    active_stage = connection.execute(
        """
        SELECT event_id, stage, started_at_epoch_ms
        FROM review_stage_events
        WHERE run_id = ?
          AND status = 'in_progress'
        ORDER BY started_at_epoch_ms DESC
        LIMIT 1
        """,
        (run_id,),
    ).fetchone()

    failure_stage = None

    if active_stage is not None:
        failure_stage = active_stage[1]

        connection.execute(
            """
            UPDATE review_stage_events
            SET status = 'failed',
                completed_at = ?,
                duration_ms = ?
            WHERE event_id = ?
              AND status = 'in_progress'
            """,
            (
                completed_at,
                max(
                    0,
                    completed_at_epoch_ms
                    - active_stage[2],
                ),
                active_stage[0],
            ),
        )

    connection.execute(
        """
        UPDATE review_runs
        SET status = 'failed',
            completed_at = ?,
            duration_ms = ?,
            failure_stage = ?,
            error_type = 'WorkerLeaseExpired',
            error_message = ?
        WHERE run_id = ?
          AND status = 'running'
        """,
        (
            completed_at,
            max(
                0,
                completed_at_epoch_ms - run[0],
            ),
            failure_stage,
            "Previous worker lease expired before review completion.",
            run_id,
        ),
    )


def _ensure_review_result_json_column(
    connection: sqlite3.Connection,
) -> None:
    """Add complete review JSON to existing results."""

    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(review_results)"
        )
    }

    if "review_json" not in columns:
        connection.execute(
            "ALTER TABLE review_results "
            "ADD COLUMN review_json TEXT"
        )


def _ensure_report_token_hash_column(
    connection: sqlite3.Connection,
) -> None:
    """Add secure report token storage."""

    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(review_results)"
        )
    }

    if "report_token_hash" not in columns:
        connection.execute(
            "ALTER TABLE review_results "
            "ADD COLUMN report_token_hash TEXT"
        )

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_review_results_report_token_hash
        ON review_results(report_token_hash)
        WHERE report_token_hash IS NOT NULL
        """
    )


def enqueue_review_job(
    *,
    event: ValidatedPREvent,
    db_path: str | Path,
) -> bool:
    """
    Persist a validated GitHub PR event.

    Returns True for a newly queued job.
    Returns False for an already recorded
    delivery or PR head commit.
    """

    if not isinstance(event, ValidatedPREvent):
        raise TypeError(
            "event must be ValidatedPREvent."
        )

    database_path = Path(db_path).expanduser()
    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with closing(
        sqlite3.connect(
            database_path,
            timeout=10,
        )
    ) as connection:

        with connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS review_jobs (
                    delivery_id TEXT PRIMARY KEY,
                    installation_id INTEGER NOT NULL,
                    repository TEXT NOT NULL,
                    pr_number INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                        DEFAULT CURRENT_TIMESTAMP,

                    UNIQUE (
                        installation_id,
                        repository,
                        pr_number,
                        head_sha
                    )
                )
                """
            )

            _ensure_review_job_lease_columns(connection)

            cursor = connection.execute(
                """
                INSERT INTO review_jobs (
                    delivery_id,
                    installation_id,
                    repository,
                    pr_number,
                    head_sha,
                    action
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    str(event.delivery_id),
                    event.installation_id,
                    event.repository,
                    event.pr_number,
                    event.head_sha,
                    event.action,
                ),
            )

            inserted = cursor.rowcount == 1

    return inserted


def claim_next_review_job(
    *,
    db_path: str | Path,
    lease_seconds: int = 900,
) -> dict | None:
    """
    Atomically claim a review job and create
    a unique execution-history record.
    """

    if type(lease_seconds) is not int or lease_seconds < 1:
        raise ValueError("lease_seconds must be a positive integer.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(
            database_path,
            timeout=10,
        )
    ) as connection:

        connection.row_factory = sqlite3.Row

        with connection:
            connection.execute("BEGIN IMMEDIATE")

            _ensure_review_job_lease_columns(connection)

            row = connection.execute(
                """
                SELECT *
                FROM review_jobs
                WHERE status = 'queued'
                ORDER BY created_at, rowid
                LIMIT 1
                """
            ).fetchone()

            if row is None:
                return None

            now_epoch_ms = time.time_ns() // 1_000_000
            now_timestamp = _utc_timestamp_from_epoch_ms(
                now_epoch_ms
            )

            # Recover an unfinished execution before
            # starting another attempt.
            previous_run_id = row["active_run_id"]

            if previous_run_id:
                _finalize_interrupted_review_run(
                    connection,
                    run_id=previous_run_id,
                    completed_at=now_timestamp,
                    completed_at_epoch_ms=now_epoch_ms,
                )

            run_id = str(uuid4())

            lease_token = uuid4().hex
            lease_expires_at = int(time.time()) + lease_seconds

            cursor = connection.execute(
                """
                UPDATE review_jobs
                SET status = 'running',
                    attempts = attempts + 1,
                    lease_token = ?,
                    lease_expires_at = ?,
                    active_run_id = ?,
                    last_stage = NULL,
                    failure_stage = NULL,
                    error_type = NULL,
                    error_message = NULL,
                    failed_at = NULL,
                    retry_after = NULL
                WHERE delivery_id = ?
                  AND status = 'queued'
                """,
                (
                    lease_token,
                    lease_expires_at,
                    run_id,
                    row["delivery_id"],
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    "Unable to claim review job."
                )

            claimed = connection.execute(
                """
                SELECT *
                FROM review_jobs
                WHERE delivery_id = ?
                """,
                (row["delivery_id"],),
            ).fetchone()

            # Create the permanent execution record.
            connection.execute(
                """
                INSERT INTO review_runs (
                    run_id,
                    delivery_id,
                    attempt_number,
                    repository,
                    pr_number,
                    head_sha,
                    status,
                    started_at,
                    started_at_epoch_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    run_id,
                    claimed["delivery_id"],
                    claimed["attempts"],
                    claimed["repository"],
                    claimed["pr_number"],
                    claimed["head_sha"],
                    now_timestamp,
                    now_epoch_ms,
                ),
            )

            claimed_job = dict(claimed)
            claimed_job["run_id"] = run_id

            return claimed_job


def finish_review_job(
    *,
    delivery_id: str,
    final_status: str,
    db_path: str | Path,
) -> None:
    """Mark a running review job as completed or failed."""

    if final_status not in {"completed", "failed"}:
        raise ValueError(
            "final_status must be completed or failed."
        )

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:
        with connection:
            cursor = connection.execute(
                """
                UPDATE review_jobs
                SET status = ?
                WHERE delivery_id = ?
                  AND status = 'running'
                  AND lease_token IS NULL
                  AND lease_expires_at IS NULL
                """,
                (final_status, delivery_id),
            )

            if cursor.rowcount != 1:
                raise ValueError(
                    "Review job does not exist or is not running."
                )


def save_review_result_with_lease(
    *,
    delivery_id: str,
    lease_token: str,
    review: ReviewResult,
    report_token: str,
    db_path: str | Path,
) -> None:
    """
    Save a complete review while retaining
    the worker's active job lease.
    """

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    if not isinstance(lease_token, str) or not lease_token.strip():
        raise ValueError("Invalid lease token.")

    if not isinstance(review, ReviewResult):
        raise TypeError("review must be ReviewResult.")

    if (
        not isinstance(report_token, str)
        or not 32 <= len(report_token) <= 256
        or not report_token.isascii()
        or not report_token.replace("_", "").replace("-", "").isalnum()
    ):
        raise ValueError("Invalid report token.")

    report_token_hash = hashlib.sha256(
        report_token.encode("utf-8")
    ).hexdigest()

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:
        connection.execute("PRAGMA foreign_keys = ON")

        with connection:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT 1
                FROM review_jobs
                WHERE delivery_id = ?
                  AND status = 'running'
                  AND lease_token = ?
                  AND lease_expires_at >
                      CAST(strftime('%s', 'now') AS INTEGER)
                """,
                (delivery_id, lease_token),
            ).fetchone()

            if row is None:
                raise ValueError(
                    "Review job is not running, "
                    "or lease is invalid or expired."
                )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS review_results (
                    delivery_id TEXT PRIMARY KEY,
                    review_status TEXT NOT NULL,
                    review_action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    finding_count INTEGER NOT NULL,
                    blocking_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    insufficient_evidence_count INTEGER NOT NULL,
                    explained_count INTEGER NOT NULL,
                    review_json TEXT,
                    report_token_hash TEXT,
                    created_at TEXT NOT NULL
                        DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (delivery_id)
                        REFERENCES review_jobs(delivery_id)
                )
                """
            )

            _ensure_review_result_json_column(connection)
            _ensure_report_token_hash_column(connection)

            connection.execute(
                """
                INSERT INTO review_results (
                    delivery_id,
                    review_status,
                    review_action,
                    severity,
                    reason,
                    finding_count,
                    blocking_count,
                    warning_count,
                    insufficient_evidence_count,
                    explained_count,
                    review_json,
                    report_token_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(delivery_id) DO UPDATE SET
                    review_status = excluded.review_status,
                    review_action = excluded.review_action,
                    severity = excluded.severity,
                    reason = excluded.reason,
                    finding_count = excluded.finding_count,
                    blocking_count = excluded.blocking_count,
                    warning_count = excluded.warning_count,
                    insufficient_evidence_count =
                        excluded.insufficient_evidence_count,
                    explained_count = excluded.explained_count,
                    review_json = excluded.review_json,
                    report_token_hash = excluded.report_token_hash,
                    created_at = CURRENT_TIMESTAMP
                """,
                (
                    delivery_id,
                    review.status.value,
                    review.action.value,
                    review.severity.value,
                    review.reason,
                    review.finding_count,
                    review.blocking_count,
                    review.warning_count,
                    review.insufficient_evidence_count,
                    review.explained_count,
                    review.model_dump_json(
                        exclude={
                            "finding_count": True,
                            "blocking_count": True,
                            "warning_count": True,
                            "insufficient_evidence_count": True,
                            "explained_count": True,
                            "findings": {
                                "__all__": {
                                    "finding_id": True,
                                    "finding": {
                                        "finding_id": True,
                                    },
                                },
                            },
                        },
                    ),
                    report_token_hash,
                ),
            )


def retry_failed_review_job(
    *,
    delivery_id: str,
    db_path: str | Path,
    max_attempts: int = 3,
) -> bool:
    """
    Requeue a failed job when its retry limit
    has not been reached.

    Returns True if requeued, otherwise False.
    """

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:
        with connection:
            cursor = connection.execute(
                """
                UPDATE review_jobs
                SET status = 'queued',
                    retry_after = NULL
                WHERE delivery_id = ?
                  AND status = 'failed'
                  AND attempts < ?
                """,
                (delivery_id, max_attempts),
            )

            return cursor.rowcount == 1


def update_review_job_progress_with_lease(
    *,
    delivery_id: str,
    lease_token: str,
    stage: str,
    db_path: str | Path,
) -> bool:
    """
    Persist a review stage transition using the
    active execution run and worker lease.

    The previous stage is completed automatically.
    The new stage receives its own timing record.
    """

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    if not isinstance(lease_token, str) or not lease_token.strip():
        raise ValueError("Invalid lease token.")

    allowed_stages = {
        "CODE_SCAN",
        "FINDING_ANALYSIS",
        "RAG_EVALUATION",
        "AI_EXPLANATION",
        "POLICY_EVALUATION",
    }

    if not isinstance(stage, str) or stage not in allowed_stages:
        raise ValueError("Invalid review progress stage.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        connection.row_factory = sqlite3.Row

        with connection:
            connection.execute("BEGIN IMMEDIATE")

            now_epoch_ms = time.time_ns() // 1_000_000
            now_timestamp = _utc_timestamp_from_epoch_ms(
                now_epoch_ms
            )

            # 1. Verify the active worker lease.
            job = connection.execute(
                """
                SELECT active_run_id, last_stage
                FROM review_jobs
                WHERE delivery_id = ?
                  AND status = 'running'
                  AND lease_token = ?
                  AND lease_expires_at >
                      CAST(strftime('%s', 'now') AS INTEGER)
                """,
                (
                    delivery_id,
                    lease_token,
                ),
            ).fetchone()

            if job is None:
                return False

            run_id = job["active_run_id"]

            if not run_id:
                raise RuntimeError(
                    "Review job has no active execution run."
                )

            # 2. Verify that this execution is still running.
            run = connection.execute(
                """
                SELECT status
                FROM review_runs
                WHERE run_id = ?
                  AND delivery_id = ?
                """,
                (
                    run_id,
                    delivery_id,
                ),
            ).fetchone()

            if run is None or run["status"] != "running":
                raise RuntimeError(
                    "Active review execution is not running."
                )

            # 3. Prevent duplicate stage events.
            existing = connection.execute(
                """
                SELECT status
                FROM review_stage_events
                WHERE run_id = ?
                  AND stage = ?
                """,
                (
                    run_id,
                    stage,
                ),
            ).fetchone()

            if existing is not None:
                if (
                    existing["status"] == "in_progress"
                    and job["last_stage"] == stage
                ):
                    return True

                raise RuntimeError(
                    f"Review stage already recorded: {stage}"
                )

            # 4. Complete the previous active stage.
            previous_stage = connection.execute(
                """
                SELECT event_id, started_at_epoch_ms
                FROM review_stage_events
                WHERE run_id = ?
                  AND status = 'in_progress'
                ORDER BY started_at_epoch_ms DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()

            if previous_stage is not None:
                connection.execute(
                    """
                    UPDATE review_stage_events
                    SET status = 'completed',
                        completed_at = ?,
                        duration_ms = ?
                    WHERE event_id = ?
                      AND status = 'in_progress'
                    """,
                    (
                        now_timestamp,
                        max(
                            0,
                            now_epoch_ms
                            - previous_stage["started_at_epoch_ms"],
                        ),
                        previous_stage["event_id"],
                    ),
                )

            # 5. Create the new stage execution event.
            connection.execute(
                """
                INSERT INTO review_stage_events (
                    event_id,
                    run_id,
                    stage,
                    status,
                    started_at,
                    started_at_epoch_ms
                )
                VALUES (?, ?, ?, 'in_progress', ?, ?)
                """,
                (
                    str(uuid4()),
                    run_id,
                    stage,
                    now_timestamp,
                    now_epoch_ms,
                ),
            )

            # 6. Update the current job lifecycle stage.
            cursor = connection.execute(
                """
                UPDATE review_jobs
                SET last_stage = ?
                WHERE delivery_id = ?
                  AND active_run_id = ?
                  AND status = 'running'
                  AND lease_token = ?
                """,
                (
                    stage,
                    delivery_id,
                    run_id,
                    lease_token,
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    "Unable to persist review stage."
                )

            return True


def finish_review_job_with_lease(
    *,
    delivery_id: str,
    lease_token: str,
    final_status: str,
    db_path: str | Path,
    retry_delay_seconds: int = 30,
    failure_stage: str | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
) -> None:
    """
    Finalize a review execution and its active stage.

    All lifecycle updates are atomic and protected
    by the current, unexpired worker lease.
    """

    if final_status not in {"completed", "failed"}:
        raise ValueError("Invalid final job status.")

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    if not isinstance(lease_token, str) or not lease_token.strip():
        raise ValueError("Invalid lease token.")

    if (
        type(retry_delay_seconds) is not int
        or not 1 <= retry_delay_seconds <= 3600
    ):
        raise ValueError(
            "retry_delay_seconds must be between 1 and 3600."
        )

    if failure_stage is not None:
        if (
            not isinstance(failure_stage, str)
            or not failure_stage.strip()
            or len(failure_stage) > 64
        ):
            raise ValueError("Invalid failure stage.")

        failure_stage = failure_stage.strip()

    if error_type is not None:
        if (
            not isinstance(error_type, str)
            or not error_type.strip()
            or len(error_type) > 128
        ):
            raise ValueError("Invalid error type.")

        error_type = error_type.strip()

    if error_message is not None:
        if not isinstance(error_message, str):
            raise ValueError("Invalid error message.")

        error_message = error_message.strip()[:2000] or None

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        connection.row_factory = sqlite3.Row

        with connection:

            connection.execute("BEGIN IMMEDIATE")

            now_epoch_ms = time.time_ns() // 1_000_000

            now_timestamp = _utc_timestamp_from_epoch_ms(
                now_epoch_ms
            )

            # 1. Verify current worker lease.

            job = connection.execute(
                """
                SELECT active_run_id, last_stage
                FROM review_jobs
                WHERE delivery_id = ?
                  AND status = 'running'
                  AND lease_token = ?
                  AND lease_expires_at >
                      CAST(strftime('%s', 'now') AS INTEGER)
                """,
                (
                    delivery_id,
                    lease_token,
                ),
            ).fetchone()

            if job is None:
                raise ValueError(
                    "Review job is not running, "
                    "or lease is invalid or expired."
                )

            run_id = job["active_run_id"]

            if not run_id:
                raise RuntimeError(
                    "Review job has no active execution run."
                )

            # 2. Verify execution record.

            run = connection.execute(
                """
                SELECT started_at_epoch_ms
                FROM review_runs
                WHERE run_id = ?
                  AND delivery_id = ?
                  AND status = 'running'
                """,
                (
                    run_id,
                    delivery_id,
                ),
            ).fetchone()

            if run is None:
                raise RuntimeError(
                    "Active review execution is not running."
                )

            # 3. Find the final active stage.

            active_stage = connection.execute(
                """
                SELECT event_id, stage, started_at_epoch_ms
                FROM review_stage_events
                WHERE run_id = ?
                  AND status = 'in_progress'
                ORDER BY started_at_epoch_ms DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()

            resolved_failure_stage = failure_stage

            if (
                final_status == "failed"
                and resolved_failure_stage is None
            ):
                resolved_failure_stage = (
                    active_stage["stage"]
                    if active_stage is not None
                    else job["last_stage"]
                )

            # 4. Finalize the active stage.

            if active_stage is not None:

                stage_duration_ms = max(
                    0,
                    now_epoch_ms
                    - active_stage["started_at_epoch_ms"],
                )

                connection.execute(
                    """
                    UPDATE review_stage_events
                    SET status = ?,
                        completed_at = ?,
                        duration_ms = ?
                    WHERE event_id = ?
                      AND status = 'in_progress'
                    """,
                    (
                        final_status,
                        now_timestamp,
                        stage_duration_ms,
                        active_stage["event_id"],
                    ),
                )

            # 5. Finalize the complete execution.

            total_duration_ms = max(
                0,
                now_epoch_ms
                - run["started_at_epoch_ms"],
            )

            cursor = connection.execute(
                """
                UPDATE review_runs
                SET status = ?,
                    completed_at = ?,
                    duration_ms = ?,
                    failure_stage = ?,
                    error_type = ?,
                    error_message = ?
                WHERE run_id = ?
                  AND status = 'running'
                """,
                (
                    final_status,
                    now_timestamp,
                    total_duration_ms,
                    (
                        resolved_failure_stage
                        if final_status == "failed"
                        else None
                    ),
                    error_type if final_status == "failed" else None,
                    error_message if final_status == "failed" else None,
                    run_id,
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    "Unable to finalize review execution."
                )

            # 6. Finalize the queue job and release its lease.

            cursor = connection.execute(
                """
                UPDATE review_jobs
                SET status = ?,
                    lease_token = NULL,
                    lease_expires_at = NULL,
                    active_run_id = NULL,

                    retry_after = CASE
                        WHEN ? = 'failed'
                        THEN CAST(strftime('%s', 'now') AS INTEGER) + ?
                        ELSE NULL
                    END,

                    failure_stage = CASE
                        WHEN ? = 'failed' THEN ?
                        ELSE NULL
                    END,

                    error_type = CASE
                        WHEN ? = 'failed' THEN ?
                        ELSE NULL
                    END,

                    error_message = CASE
                        WHEN ? = 'failed' THEN ?
                        ELSE NULL
                    END,

                    failed_at = CASE
                        WHEN ? = 'failed' THEN CURRENT_TIMESTAMP
                        ELSE NULL
                    END

                WHERE delivery_id = ?
                  AND active_run_id = ?
                  AND status = 'running'
                  AND lease_token = ?

                  AND lease_expires_at >
                      CAST(strftime('%s', 'now') AS INTEGER)
                """,
                (
                    final_status,
                    final_status,
                    retry_delay_seconds,
                    final_status,
                    resolved_failure_stage,
                    final_status,
                    error_type,
                    final_status,
                    error_message,
                    final_status,
                    delivery_id,
                    run_id,
                    lease_token,
                ),
            )

            if cursor.rowcount != 1:
                raise ValueError(
                    "Review job is not running, "
                    "or lease is invalid or expired."
                )


def renew_review_job_lease(
    *,
    delivery_id: str,
    lease_token: str,
    db_path: str | Path,
    lease_seconds: int = 900,
) -> bool:
    """
    Extend an active job lease.

    Only the current worker can renew.
    Expired or completed leases cannot be renewed.

    Returns True if renewed, otherwise False.
    """

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    if not isinstance(lease_token, str) or not lease_token.strip():
        raise ValueError("Invalid lease token.")

    if type(lease_seconds) is not int or lease_seconds < 1:
        raise ValueError("lease_seconds must be a positive integer.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:
        with connection:
            cursor = connection.execute(
                """
                UPDATE review_jobs
                SET lease_expires_at = MAX(
                    lease_expires_at,
                    CAST(strftime('%s', 'now') AS INTEGER) + ?
                )
                WHERE delivery_id = ?
                  AND status = 'running'
                  AND lease_token = ?
                  AND lease_expires_at >
                      CAST(strftime('%s', 'now') AS INTEGER)
                """,
                (
                    lease_seconds,
                    delivery_id,
                    lease_token,
                ),
            )

            return cursor.rowcount == 1


def recover_expired_review_jobs(
    *,
    db_path: str | Path,
    max_attempts: int = 3,
) -> dict[str, int]:
    """
    Recover expired leased jobs.

    Requeue jobs below the attempt limit.
    Mark exhausted jobs failed.

    Returns counts of requeued and exhausted jobs.
    """

    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError(
            "max_attempts must be a positive integer."
        )

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")

            requeued = connection.execute(
                """
                UPDATE review_jobs
                SET status = 'queued',
                    lease_token = NULL,
                    lease_expires_at = NULL
                WHERE status = 'running'
                  AND lease_token IS NOT NULL
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <=
                      CAST(strftime('%s', 'now') AS INTEGER)
                  AND attempts < ?
                """,
                (max_attempts,),
            ).rowcount

            exhausted = connection.execute(
                """
                UPDATE review_jobs
                SET status = 'failed',
                    lease_token = NULL,
                    lease_expires_at = NULL
                WHERE status = 'running'
                  AND lease_token IS NOT NULL
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <=
                      CAST(strftime('%s', 'now') AS INTEGER)
                  AND attempts >= ?
                """,
                (max_attempts,),
            ).rowcount

    return {
        "requeued": requeued,
        "exhausted": exhausted,
    }


def requeue_due_failed_review_jobs(
    *,
    db_path: str | Path,
    max_attempts: int = 3,
) -> dict[str, int]:
    """
    Requeue failed jobs whose retry delay has elapsed.

    Jobs below the attempt limit become queued.
    Exhausted jobs remain failed and have their
    retry schedule cleared.

    Returns counts of requeued and exhausted jobs.
    """

    if type(max_attempts) is not int or max_attempts < 1:
        raise ValueError(
            "max_attempts must be a positive integer."
        )

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")

            _ensure_review_job_lease_columns(connection)

            requeued = connection.execute(
                """
                UPDATE review_jobs
                SET status = 'queued',
                    retry_after = NULL
                WHERE status = 'failed'
                  AND retry_after IS NOT NULL
                  AND retry_after <=
                      CAST(strftime('%s', 'now') AS INTEGER)
                  AND attempts < ?
                """,
                (max_attempts,),
            ).rowcount

            exhausted = connection.execute(
                """
                UPDATE review_jobs
                SET retry_after = NULL
                WHERE status = 'failed'
                  AND retry_after IS NOT NULL
                  AND retry_after <=
                      CAST(strftime('%s', 'now') AS INTEGER)
                  AND attempts >= ?
                """,
                (max_attempts,),
            ).rowcount

    return {
        "requeued": requeued,
        "exhausted": exhausted,
    }


def get_review_result(
    *,
    delivery_id: str,
    db_path: str | Path,
) -> ReviewResult | None:
    """Retrieve a complete saved security review."""

    if not isinstance(delivery_id, str) or not delivery_id.strip():
        raise ValueError("Invalid delivery ID.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(review_results)"
            )
        }

        if "review_json" not in columns:
            return None

        row = connection.execute(
            """
            SELECT review_json
            FROM review_results
            WHERE delivery_id = ?
            """,
            (delivery_id,),
        ).fetchone()

    if row is None or row[0] is None:
        return None

    return ReviewResult.model_validate_json(row[0])


def _build_scanner_progress_events(
    rows: list[sqlite3.Row],
    *,
    now_epoch_ms: int,
) -> list[dict] | None:
    """Build complete scanner progress snapshots."""

    events = []

    for row in rows:

        try:
            targeted_files = json.loads(
                row["file_paths_json"]
            )
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Invalid file targets for scanner "
                f"{row['scanner']}."
            ) from exc

        if (
            not isinstance(targeted_files, list)
            or any(
                not isinstance(path, str) or not path.strip()
                for path in targeted_files
            )
        ):
            raise RuntimeError(
                f"Invalid file targets for scanner "
                f"{row['scanner']}."
            )

        duration_ms = row["duration_ms"]

        if row["status"] == "running":

            started_at_epoch_ms = (
                row["started_at_epoch_ms"]
            )

            if type(started_at_epoch_ms) is not int:
                raise RuntimeError(
                    f"Missing scanner start time: "
                    f"{row['scanner']}."
                )

            duration_ms = max(
                0,
                now_epoch_ms - started_at_epoch_ms,
            )

        events.append({
            "scanner": row["scanner"],
            "status": row["status"],
            "targeted_files": targeted_files,
            "targeted_file_count": len(targeted_files),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "duration_ms": duration_ms,
            "findings_count": row["findings_count"],
            "error_type": row["error_type"],
            "error_message": row["error_message"],
        })

    return events or None


def get_review_scanner_events_for_run(
    *,
    run_id: str,
    db_path: str | Path,
) -> list[dict] | None:
    """Retrieve current scanner progress for one review run."""

    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("Invalid review run ID.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                scanner,
                status,
                file_paths_json,
                started_at,
                started_at_epoch_ms,
                completed_at,
                duration_ms,
                findings_count,
                error_type,
                error_message
            FROM review_scanner_events
            WHERE run_id = ?
            ORDER BY queued_at ASC, rowid ASC
            """,
            (run_id,),
        ).fetchall()

    now_epoch_ms = time.time_ns() // 1_000_000

    return _build_scanner_progress_events(
        rows,
        now_epoch_ms=now_epoch_ms,
    )


def get_review_progress_snapshot_for_run(
    *,
    run_id: str,
    db_path: str | Path,
) -> dict:
    """Retrieve live scanner, stage and review timing data."""

    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("Invalid review run ID.")

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        connection.row_factory = sqlite3.Row

        run = connection.execute(
            """
            SELECT status, started_at_epoch_ms
            FROM review_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        if run is None:
            raise ValueError("Review execution does not exist.")

        if run["status"] != "running":
            raise RuntimeError(
                "Review execution is not running."
            )

        now_epoch_ms = time.time_ns() // 1_000_000

        total_duration_ms = max(
            0,
            now_epoch_ms - run["started_at_epoch_ms"],
        )

        scanner_rows = connection.execute(
            """
            SELECT
                scanner,
                status,
                file_paths_json,
                started_at,
                started_at_epoch_ms,
                completed_at,
                duration_ms,
                findings_count,
                error_type,
                error_message
            FROM review_scanner_events
            WHERE run_id = ?
            ORDER BY queued_at ASC, rowid ASC
            """,
            (run_id,),
        ).fetchall()

        stage_rows = connection.execute(
            """
            SELECT
                stage,
                status,
                started_at,
                started_at_epoch_ms,
                completed_at,
                duration_ms
            FROM review_stage_events
            WHERE run_id = ?
            ORDER BY started_at_epoch_ms ASC
            """,
            (run_id,),
        ).fetchall()

    scanner_events = (
        _build_scanner_progress_events(
            scanner_rows,
            now_epoch_ms=now_epoch_ms,
        )
    )

    stage_events = []

    for row in stage_rows:

        duration_ms = row["duration_ms"]

        if row["status"] == "in_progress":
            duration_ms = max(
                0,
                now_epoch_ms - row["started_at_epoch_ms"],
            )

        stage_events.append({
            "stage": row["stage"],
            "status": row["status"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "duration_ms": duration_ms,
        })

    return {
        "scanner_events": scanner_events or None,
        "stage_events": stage_events,
        "total_duration_ms": total_duration_ms,
    }


def _get_review_execution_history(
    connection: sqlite3.Connection,
    *,
    delivery_id: str,
) -> list[dict]:
    """Retrieve immutable execution and stage history."""

    tables = {
        row[0]
        for row in connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        )
    }

    if "review_runs" not in tables:
        return []

    runs = connection.execute(
        """
        SELECT
            attempt_number,
            head_sha,
            status,
            started_at,
            completed_at,
            duration_ms,
            failure_stage,
            error_type,
            run_id
        FROM review_runs
        WHERE delivery_id = ?
        ORDER BY attempt_number ASC
        """,
        (delivery_id,),
    ).fetchall()

    history = []

    for run in runs:
        stages = []

        if "review_stage_events" in tables:
            stage_rows = connection.execute(
                """
                SELECT
                    stage,
                    status,
                    started_at,
                    completed_at,
                    duration_ms
                FROM review_stage_events
                WHERE run_id = ?
                ORDER BY started_at_epoch_ms ASC
                """,
                (run["run_id"],),
            ).fetchall()

            stages = [
                {
                    "stage": stage["stage"],
                    "status": stage["status"],
                    "started_at": stage["started_at"],
                    "completed_at": stage["completed_at"],
                    "duration_ms": stage["duration_ms"],
                }
                for stage in stage_rows
            ]

        scanners = []

        if "review_scanner_events" in tables:
            scanner_rows = connection.execute(
                """
                SELECT
                    scanner,
                    file_paths_json,
                    status,
                    queued_at,
                    started_at,
                    completed_at,
                    duration_ms,
                    findings_count,
                    error_type
                FROM review_scanner_events
                WHERE run_id = ?
                ORDER BY queued_at ASC, rowid ASC
                """,
                (run["run_id"],),
            ).fetchall()

            for scanner_row in scanner_rows:
                file_paths = json.loads(
                    scanner_row["file_paths_json"]
                )

                if (
                    not isinstance(file_paths, list)
                    or any(
                        not isinstance(path, str)
                        for path in file_paths
                    )
                ):
                    raise RuntimeError(
                        "Invalid stored scanner file paths."
                    )

                scanners.append({
                    "scanner": scanner_row["scanner"],
                    "file_paths": file_paths,
                    "status": scanner_row["status"],
                    "queued_at": scanner_row["queued_at"],
                    "started_at": scanner_row["started_at"],
                    "completed_at": scanner_row["completed_at"],
                    "duration_ms": scanner_row["duration_ms"],
                    "findings_count": scanner_row["findings_count"],
                    "error_type": scanner_row["error_type"],
                })

        history.append(
            {
                "run_id": run["run_id"],
                "attempt_number": run["attempt_number"],
                "head_sha": run["head_sha"],
                "status": run["status"],
                "started_at": run["started_at"],
                "completed_at": run["completed_at"],
                "duration_ms": run["duration_ms"],
                "failure_stage": run["failure_stage"],
                "error_type": run["error_type"],
                "stages": stages,
                "scanners": scanners,
            }
        )

    return history


def get_review_report_by_token(
    *,
    report_token: str,
    db_path: str | Path,
) -> dict | None:
    """Retrieve a report and its execution history."""

    if (
        not isinstance(report_token, str)
        or not 32 <= len(report_token) <= 256
        or not report_token.isascii()
        or not report_token.replace("_", "").replace("-", "").isalnum()
    ):
        raise ValueError("Invalid report token.")

    token_hash = hashlib.sha256(
        report_token.encode("utf-8")
    ).hexdigest()

    database_path = Path(db_path).expanduser()

    if not database_path.is_file():
        raise FileNotFoundError(
            "Review queue database does not exist."
        )

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as connection:

        connection.row_factory = sqlite3.Row

        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(review_results)"
            )
        }

        if not {
            "review_json",
            "report_token_hash",
        }.issubset(columns):
            return None

        row = connection.execute(
            """
            SELECT
                rr.delivery_id,
                rr.review_json,
                rr.review_status,
                rr.review_action,
                rr.severity,
                rr.reason,
                rr.created_at,
                rj.repository,
                rj.pr_number,
                rj.head_sha
            FROM review_results rr
            JOIN review_jobs rj
                ON rj.delivery_id = rr.delivery_id
            WHERE rr.report_token_hash = ?
            """,
            (token_hash,),
        ).fetchone()

        if row is None or row["review_json"] is None:
            return None

        execution_history = _get_review_execution_history(
            connection,
            delivery_id=row["delivery_id"],
        )

    return {
        "review": ReviewResult.model_validate_json(
            row["review_json"]
        ),
        "repository": row["repository"],
        "pr_number": row["pr_number"],
        "head_sha": row["head_sha"],
        "status": row["review_status"],
        "action": row["review_action"],
        "severity": row["severity"],
        "reason": row["reason"],
        "created_at": row["created_at"],
        "execution_history": execution_history,
    }
