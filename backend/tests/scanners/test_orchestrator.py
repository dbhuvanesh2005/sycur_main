from threading import Event, Lock, Thread
from pathlib import Path

import pytest

from sycur_rag.core.enums import Severity
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.base import ScannerAdapter
from sycur_rag.scanners.orchestrator import (
    SUPPORTED_SCANNERS,
    ScannerOrchestrator,
    ScannerPlanItem,
    ScannerProgressCallbackError,
)


class FakeScannerAdapter(ScannerAdapter):

    def __init__(self, name, scan_callback=None):
        self._name = name
        self._scan_callback = scan_callback

    @property
    def scanner_name(self):
        return self._name

    def scan(self, target_path):
        if self._scan_callback is not None:
            return self._scan_callback(target_path)

        return []


def create_repository(root, files):
    for relative_path in files:
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("test content\n", encoding="utf-8")

    return root


def create_orchestrator(
    repository_root,
    callbacks=None,
    max_workers=3,
):
    callbacks = callbacks or {}

    adapters = {
        name: FakeScannerAdapter(
            name,
            callbacks.get(name),
        )
        for name in SUPPORTED_SCANNERS
    }

    return ScannerOrchestrator(
        repository_root=repository_root,
        adapters=adapters,
        max_workers=max_workers,
    )


def create_finding():
    return ScannerFinding(
        scanner="semgrep",
        rule_id="TEST-001",
        title="Test security finding",
        message="Simulated security issue.",
        severity=Severity.MEDIUM,
        file_path="src/app.py",
        line_start=10,
        line_end=10,
    )


def test_python_file_uses_selective_scanner_routing(tmp_path):
    create_repository(
        tmp_path,
        ["src/app.py"],
    )

    orchestrator = create_orchestrator(tmp_path)

    plan = orchestrator.build_plan(["src/app.py"])

    actual = {
        item.scanner: item.file_paths
        for item in plan
    }

    assert actual == {
        "gitleaks": ("src/app.py",),
        "semgrep": ("src/app.py",),
        "bandit": ("src/app.py",),
    }


def test_scanner_filter_selects_only_requested_scanner(tmp_path):
    create_repository(
        tmp_path,
        ["src/app.py"],
    )

    orchestrator = create_orchestrator(tmp_path)

    plan = orchestrator.build_plan(
        ["src/app.py"],
        scanner_filter="bandit",
    )

    assert len(plan) == 1
    assert plan[0].scanner == "bandit"
    assert plan[0].file_paths == ("src/app.py",)


def test_scanner_failure_preserves_other_findings(tmp_path):
    create_repository(
        tmp_path,
        ["src/app.py"],
    )

    def return_finding(_):
        return [create_finding()]

    def fail_scanner(_):
        raise RuntimeError("Simulated scanner failure.")

    orchestrator = create_orchestrator(
        tmp_path,
        callbacks={
            "semgrep": return_finding,
            "bandit": fail_scanner,
        },
    )

    result = orchestrator.run(["src/app.py"])

    assert result.attempted_runs == 3
    assert result.successful_runs == 2
    assert result.failed_runs == 1

    assert len(result.findings) == 1
    assert result.findings[0].scanner == "semgrep"

    assert result.failures[0].scanner == "bandit"
    assert result.failures[0].error_type == "RuntimeError"


def test_parallel_execution_never_exceeds_three(
    tmp_path,
    monkeypatch,
):
    create_repository(
        tmp_path,
        ["src/app.py"],
    )

    lock = Lock()
    release = Event()
    three_active = Event()

    active = 0
    peak = 0

    def blocking_scan(_):
        nonlocal active, peak

        with lock:
            active += 1
            peak = max(peak, active)

            if active >= 3:
                three_active.set()

        try:
            if not release.wait(timeout=5):
                raise TimeoutError(
                    "Scanner test release timed out."
                )

            return []

        finally:
            with lock:
                active -= 1

    callbacks = {
        name: blocking_scan
        for name in SUPPORTED_SCANNERS
    }

    orchestrator = create_orchestrator(
        tmp_path,
        callbacks=callbacks,
        max_workers=3,
    )

    # Isolate concurrency from file-routing behaviour.
    plan = [
        ScannerPlanItem(
            scanner=name,
            file_paths=("src/app.py",),
        )
        for name in SUPPORTED_SCANNERS
    ]

    def fixed_plan(_changed_files, *, scanner_filter=None):
        return plan

    monkeypatch.setattr(
        orchestrator,
        "build_plan",
        fixed_plan,
    )

    results = []
    errors = []

    def execute():
        try:
            results.append(
                orchestrator.run(["src/app.py"])
            )
        except Exception as exc:
            errors.append(exc)

    worker = Thread(
        target=execute,
        daemon=True,
    )

    worker.start()

    try:
        assert three_active.wait(timeout=3), (
            "Three scanners did not execute concurrently."
        )

        with lock:
            assert active == 3
            assert peak == 3

    finally:
        release.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert not errors, str(errors)

    assert peak <= 3
    assert len(results) == 1
    assert results[0].attempted_runs == 6
    assert results[0].successful_runs == 6
    assert results[0].failed_runs == 0


def test_scanner_progress_callbacks_report_actual_lifecycle(
    tmp_path,
):
    create_repository(
        tmp_path,
        ["src/app.py"],
    )

    def return_finding(_):
        return [create_finding()]

    def fail_scanner(_):
        raise RuntimeError("Simulated scanner failure.")

    orchestrator = create_orchestrator(
        tmp_path,
        callbacks={
            "semgrep": return_finding,
            "bandit": fail_scanner,
        },
    )

    plans = []
    started = []
    completed = []
    failed = []

    lock = Lock()

    def record_start(item):
        with lock:
            started.append(item.scanner)

    def record_complete(item, findings_count):
        with lock:
            completed.append(
                (item.scanner, findings_count)
            )

    def record_failure(item, error):
        with lock:
            failed.append(
                (
                    item.scanner,
                    type(error).__name__,
                    str(error),
                )
            )

    result = orchestrator.run(
        ["src/app.py"],
        on_plan=lambda plan: plans.append(plan),
        on_scanner_start=record_start,
        on_scanner_complete=record_complete,
        on_scanner_failure=record_failure,
    )

    assert len(plans) == 1

    assert {
        item.scanner
        for item in plans[0]
    } == {
        "gitleaks",
        "semgrep",
        "bandit",
    }

    assert set(started) == {
        "gitleaks",
        "semgrep",
        "bandit",
    }

    assert set(completed) == {
        ("gitleaks", 0),
        ("semgrep", 1),
    }

    assert failed == [
        (
            "bandit",
            "RuntimeError",
            "Simulated scanner failure.",
        )
    ]

    assert result.successful_runs == 2
    assert result.failed_runs == 1
    assert len(result.findings) == 1


def test_progress_callback_failure_aborts_scanner_execution(
    tmp_path,
):
    create_repository(
        tmp_path,
        ["notes.txt"],
    )

    scan_called = Event()

    def scanner(_):
        scan_called.set()
        return []

    orchestrator = create_orchestrator(
        tmp_path,
        callbacks={
            "gitleaks": scanner,
        },
    )

    def fail_start(_):
        raise RuntimeError("Simulated database failure.")

    with pytest.raises(
        ScannerProgressCallbackError,
    ):
        orchestrator.run(
            ["notes.txt"],
            on_scanner_start=fail_start,
        )

    assert not scan_called.is_set()
