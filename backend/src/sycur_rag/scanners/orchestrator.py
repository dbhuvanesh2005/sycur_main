from __future__ import annotations

import os
import shutil
import tempfile
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sycur_rag.models.finding import ScannerFinding
from sycur_rag.scanners.base import (
    ScannerAdapter,
    deduplicate_scanner_findings,
)


SUPPORTED_SCANNERS = (
    "gitleaks",
    "semgrep",
    "bandit",
    "trivy",
    "osv",
    "checkov",
)


class ScannerProgressCallbackError(RuntimeError):
    """Raised when scanner lifecycle persistence fails."""


SOURCE_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".dart",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".rs",
    ".kt",
    ".kts",
    ".swift",
}


DEPENDENCY_FILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "cargo.lock",
    "gemfile.lock",
    "composer.lock",
    "go.mod",
    "gradle.lockfile",
    "packages.lock.json",
    "pom.xml",
}


IAC_FILE_NAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}


@dataclass(
    frozen=True,
    slots=True,
)
class ScannerPlanItem:
    scanner: str
    file_paths: tuple[str, ...]


@dataclass(
    frozen=True,
    slots=True,
)
class ScannerRunFailure:
    scanner: str
    file_paths: tuple[str, ...]
    error_type: str
    message: str


@dataclass(
    frozen=True,
    slots=True,
)
class ScannerOrchestrationResult:
    findings: tuple[
        ScannerFinding,
        ...,
    ]

    failures: tuple[
        ScannerRunFailure,
        ...,
    ]

    plan: tuple[
        ScannerPlanItem,
        ...,
    ]

    successful_runs: int
    diagnostic_only: bool = False

    @property
    def attempted_runs(
        self,
    ) -> int:
        return len(
            self.plan
        )

    @property
    def failed_runs(
        self,
    ) -> int:
        return len(
            self.failures
        )

    @property
    def planned_file_checks(
        self,
    ) -> int:
        return sum(
            len(item.file_paths)
            for item in self.plan
        )

    @property
    def is_complete(
        self,
    ) -> bool:
        return (
            not self.failures
            and not self.diagnostic_only
        )


def _is_dependency_file(
    path: Path,
) -> bool:
    name = path.name.lower()

    if name in DEPENDENCY_FILE_NAMES:
        return True

    if (
        name.startswith(
            "requirements"
        )
        and name.endswith(
            ".txt"
        )
    ):
        return True

    return False


def _is_iac_file(
    path: Path,
) -> bool:
    name = path.name.lower()

    if name in IAC_FILE_NAMES:
        return True

    if (
        name.endswith(".tf")
        or name.endswith(".tf.json")
    ):
        return True

    if path.suffix.lower() in {
        ".yaml",
        ".yml",
    }:
        normalized = (
            "/"
            + path.as_posix()
            .lower()
            .strip("/")
            + "/"
        )

        markers = (
            "/k8s/",
            "/kubernetes/",
            "/helm/",
            "/cloudformation/",
            "/cfn/",
            "/infrastructure/",
            "/infra/",
        )

        return any(
            marker in normalized
            for marker in markers
        )

    return False


def _scanner_names_for_file(
    path: Path,
) -> tuple[str, ...]:
    scanners: list[str] = [
        "gitleaks",
    ]

    suffix = path.suffix.lower()

    if (
        suffix
        in SOURCE_CODE_EXTENSIONS
    ):
        scanners.append(
            "semgrep"
        )

    if suffix == ".py":
        scanners.append(
            "bandit"
        )

    if _is_dependency_file(
        path
    ):
        scanners.extend(
            [
                "trivy",
                "osv",
            ]
        )

    if _is_iac_file(
        path
    ):
        scanners.append(
            "checkov"
        )

    return tuple(
        scanners
    )


def _resolve_repository_file(
    repository_root: Path,
    raw_path: str | Path,
) -> tuple[Path, str]:
    if not isinstance(
        raw_path,
        (str, Path),
    ):
        raise TypeError(
            "Changed file path must be "
            "a string or Path."
        )

    raw = str(
        raw_path
    ).strip()

    if not raw:
        raise ValueError(
            "Changed file path cannot "
            "be empty."
        )

    path = Path(
        raw
    ).expanduser()

    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (
            repository_root
            / path
        ).resolve()

    try:
        relative = (
            resolved.relative_to(
                repository_root
            )
        )

    except ValueError as exc:
        raise ValueError(
            "Changed file escapes "
            "repository root: "
            f"{raw}"
        ) from exc

    if not resolved.exists():
        raise FileNotFoundError(
            "Changed file does not exist: "
            f"{relative.as_posix()}"
        )

    if not resolved.is_file():
        raise ValueError(
            "Changed path must be a file: "
            f"{relative.as_posix()}"
        )

    return (
        resolved,
        relative.as_posix(),
    )


def _stage_changed_files(
    *,
    repository_root: Path,
    workspace: Path,
    relative_paths: set[str],
) -> None:
    for relative in sorted(
        relative_paths
    ):
        source = (
            repository_root
            / relative
        )

        destination = (
            workspace
            / relative
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            source,
            destination,
        )


def _remove_dot_slash_prefix(
    value: str,
) -> str:
    result = value

    while result.startswith(
        "./"
    ):
        result = result[2:]

    return result


def _resolve_finding_path(
    raw_path: str,
    *,
    workspace: Path,
) -> str:
    if not isinstance(
        raw_path,
        str,
    ):
        raise TypeError(
            "Scanner finding file path "
            "must be a string."
        )

    cleaned = (
        raw_path
        .replace("\\", "/")
        .strip()
    )

    if not cleaned:
        raise ValueError(
            "Scanner finding has "
            "an empty file path."
        )

    candidate = Path(
        cleaned
    )

    if candidate.is_absolute():
        resolved = candidate.resolve()

        try:
            return (
                resolved.relative_to(
                    workspace.resolve()
                )
                .as_posix()
            )

        except ValueError as exc:
            raise ValueError(
                "Scanner finding escaped "
                "the staged workspace: "
                f"{raw_path}"
            ) from exc

    return _remove_dot_slash_prefix(
        candidate.as_posix()
    )


def _remap_finding(
    finding: ScannerFinding,
    *,
    file_path: str,
) -> ScannerFinding:
    return ScannerFinding(
        scanner=finding.scanner,
        rule_id=finding.rule_id,
        title=finding.title,
        message=finding.message,
        severity=finding.severity,
        file_path=file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        code_snippet=finding.code_snippet,
        cwe_ids=finding.cwe_ids,
        requires_evidence=(
            finding.requires_evidence
        ),
    )


class ScannerOrchestrator:
    def __init__(
        self,
        *,
        repository_root: str | Path,
        adapters: dict[
            str,
            ScannerAdapter,
        ],
        max_workers: int = 3,
    ) -> None:
        if not isinstance(
            repository_root,
            (str, Path),
        ):
            raise TypeError(
                "repository_root must be "
                "a string or Path."
            )

        root = Path(
            repository_root
        ).expanduser().resolve()

        if not root.exists():
            raise FileNotFoundError(
                "Repository root does "
                f"not exist: {root}"
            )

        if not root.is_dir():
            raise ValueError(
                "repository_root must "
                "be a directory."
            )

        if not isinstance(
            adapters,
            dict,
        ):
            raise TypeError(
                "adapters must be a dict."
            )

        if (
            not isinstance(
                max_workers,
                int,
            )
            or isinstance(
                max_workers,
                bool,
            )
            or max_workers <= 0
        ):
            raise ValueError(
                "max_workers must be "
                "a positive integer."
            )

        missing = [
            scanner
            for scanner
            in SUPPORTED_SCANNERS
            if scanner
            not in adapters
        ]

        if missing:
            raise ValueError(
                "Missing scanner adapters: "
                + ", ".join(
                    missing
                )
            )

        unknown = [
            scanner
            for scanner
            in adapters
            if scanner
            not in SUPPORTED_SCANNERS
        ]

        if unknown:
            raise ValueError(
                "Unsupported scanner adapters: "
                + ", ".join(
                    unknown
                )
            )

        for scanner_name in (
            SUPPORTED_SCANNERS
        ):
            adapter = adapters[
                scanner_name
            ]

            if not isinstance(
                adapter,
                ScannerAdapter,
            ):
                raise TypeError(
                    f"{scanner_name} adapter "
                    "must implement "
                    "ScannerAdapter."
                )

            if (
                adapter.scanner_name
                != scanner_name
            ):
                raise ValueError(
                    "Scanner adapter name "
                    "mismatch: expected "
                    f"{scanner_name}, got "
                    f"{adapter.scanner_name}."
                )

        self._repository_root = root
        self._adapters = dict(
            adapters
        )
        self._max_workers = (
            max_workers
        )

    def build_plan(
        self,
        changed_files: list[
            str | Path
        ],
        *,
        scanner_filter: str | None = None,
    ) -> list[
        ScannerPlanItem
    ]:
        if not isinstance(
            changed_files,
            list,
        ):
            raise TypeError(
                "changed_files must "
                "be a list."
            )

        if (
            scanner_filter is not None
            and scanner_filter not in SUPPORTED_SCANNERS
        ):
            raise ValueError(
                "Unsupported scanner filter."
            )

        resolved_files: dict[
            str,
            Path,
        ] = {}

        for raw_path in changed_files:
            resolved, relative = (
                _resolve_repository_file(
                    self._repository_root,
                    raw_path,
                )
            )

            resolved_files[
                relative
            ] = resolved

        routed: dict[
            str,
            list[str],
        ] = {
            scanner: []
            for scanner
            in SUPPORTED_SCANNERS
        }

        for relative in sorted(
            resolved_files
        ):
            scanner_names = (
                _scanner_names_for_file(
                    Path(relative)
                )
            )

            for scanner_name in (
                scanner_names
            ):
                if (
                    scanner_filter is not None
                    and scanner_name != scanner_filter
                ):
                    continue
                routed[
                    scanner_name
                ].append(
                    relative
                )

        plan: list[
            ScannerPlanItem
        ] = []

        for scanner_name in (
            SUPPORTED_SCANNERS
        ):
            file_paths = routed[
                scanner_name
            ]

            if not file_paths:
                continue

            plan.append(
                ScannerPlanItem(
                    scanner=scanner_name,
                    file_paths=tuple(
                        file_paths
                    ),
                )
            )

        return plan

    def _execute_batch(
        self,
        *,
        item: ScannerPlanItem,
        workspace: Path,
        all_changed_paths: set[str],
    ) -> list[ScannerFinding]:
        adapter = self._adapters[
            item.scanner
        ]

        raw_findings = adapter.scan(
            workspace
        )

        if not isinstance(
            raw_findings,
            list,
        ):
            raise TypeError(
                "Scanner adapter "
                f"{item.scanner} "
                "must return a list."
            )

        allowed_paths = set(
            item.file_paths
        )

        findings: list[
            ScannerFinding
        ] = []

        for index, finding in enumerate(
            raw_findings
        ):
            if not isinstance(
                finding,
                ScannerFinding,
            ):
                raise TypeError(
                    "Scanner adapter "
                    f"{item.scanner} "
                    "returned invalid finding "
                    f"at index {index}."
                )

            if (
                finding.scanner
                != item.scanner
            ):
                raise ValueError(
                    "Scanner finding provenance "
                    "does not match adapter: "
                    f"{finding.scanner} != "
                    f"{item.scanner}"
                )

            relative = (
                _resolve_finding_path(
                    finding.file_path,
                    workspace=workspace,
                )
            )

            if (
                relative
                not in all_changed_paths
            ):
                raise ValueError(
                    "Scanner returned a finding "
                    "for a file that was not "
                    "part of the changed-files "
                    "workspace: "
                    f"{relative}"
                )

            # Scanner inspected a valid changed
            # file, but routing says that file
            # belongs to another scanner.
            if relative not in allowed_paths:
                continue

            findings.append(
                _remap_finding(
                    finding,
                    file_path=relative,
                )
            )

        return findings

    def _execute_batch_with_progress(
        self,
        *,
        item: ScannerPlanItem,
        workspace: Path,
        all_changed_paths: set[str],
        on_scanner_start: Callable[
            [ScannerPlanItem], None
        ] | None = None,
        on_scanner_complete: Callable[
            [ScannerPlanItem, int], None
        ] | None = None,
        on_scanner_failure: Callable[
            [ScannerPlanItem, Exception], None
        ] | None = None,
    ) -> list[ScannerFinding]:

        if on_scanner_start is not None:
            try:
                on_scanner_start(item)
            except Exception as exc:
                raise ScannerProgressCallbackError(
                    f"Unable to record {item.scanner} start."
                ) from exc

        try:
            findings = self._execute_batch(
                item=item,
                workspace=workspace,
                all_changed_paths=all_changed_paths,
            )

        except Exception as scanner_error:

            if on_scanner_failure is not None:
                try:
                    on_scanner_failure(
                        item,
                        scanner_error,
                    )
                except Exception as callback_error:
                    raise ScannerProgressCallbackError(
                        f"Unable to record {item.scanner} failure."
                    ) from callback_error

            raise

        if on_scanner_complete is not None:
            try:
                on_scanner_complete(
                    item,
                    len(findings),
                )
            except Exception as exc:
                raise ScannerProgressCallbackError(
                    f"Unable to record {item.scanner} completion."
                ) from exc

        return findings

    def discover_repository_files(
        self,
        *,
        max_files: int = 5000,
    ) -> list[str]:
        """Discover source files for an explicit repository audit."""

        if type(max_files) is not int or max_files <= 0:
            raise ValueError("max_files must be positive.")

        excluded_dirs = {
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "dist",
            "build",
        }

        files = []

        for directory, dirs, names in os.walk(
            self._repository_root,
            topdown=True,
            followlinks=False,
        ):
            dirs[:] = sorted(
                name
                for name in dirs
                if name not in excluded_dirs
                and not (Path(directory) / name).is_symlink()
            )

            for name in sorted(names):
                path = Path(directory) / name

                if path.is_symlink() or not path.is_file():
                    continue

                files.append(
                    path.relative_to(
                        self._repository_root
                    ).as_posix()
                )

                if len(files) > max_files:
                    raise RuntimeError(
                        "Repository audit file limit exceeded."
                    )

        if not files:
            raise RuntimeError(
                "No eligible repository files found."
            )

        return sorted(files)

    def run_repository(
        self,
        *,
        fail_fast: bool = False,
        max_files: int = 5000,
    ) -> ScannerOrchestrationResult:
        """Run applicable scanners across repository source files."""

        files = self.discover_repository_files(
            max_files=max_files,
        )

        return self.run(
            files,
            fail_fast=fail_fast,
        )

    def run(
        self,
        changed_files: list[
            str | Path
        ],
        *,
        fail_fast: bool = False,
        scanner_filter: str | None = None,
        on_plan: Callable[
            [tuple[ScannerPlanItem, ...]], None
        ] | None = None,
        on_scanner_start: Callable[
            [ScannerPlanItem], None
        ] | None = None,
        on_scanner_complete: Callable[
            [ScannerPlanItem, int], None
        ] | None = None,
        on_scanner_failure: Callable[
            [ScannerPlanItem, Exception], None
        ] | None = None,
    ) -> ScannerOrchestrationResult:
        if not isinstance(
            fail_fast,
            bool,
        ):
            raise TypeError(
                "fail_fast must be bool."
            )

        plan = self.build_plan(
            changed_files,
            scanner_filter=scanner_filter,
        )

        callbacks = {
            "on_plan": on_plan,
            "on_scanner_start": on_scanner_start,
            "on_scanner_complete": on_scanner_complete,
            "on_scanner_failure": on_scanner_failure,
        }

        for name, callback in callbacks.items():
            if callback is not None and not callable(callback):
                raise TypeError(
                    f"{name} must be callable."
                )

        if on_plan is not None:
            on_plan(tuple(plan))

        if not plan:
            return ScannerOrchestrationResult(
                findings=(),
                failures=(),
                plan=(),
                successful_runs=0,
                diagnostic_only=scanner_filter is not None,
            )

        all_changed_paths = {
            file_path
            for item in plan
            for file_path
            in item.file_paths
        }

        findings: list[
            ScannerFinding
        ] = []

        failures: list[
            ScannerRunFailure
        ] = []

        successful_runs = 0

        with tempfile.TemporaryDirectory(
            prefix="sycur-pr-scan-"
        ) as temp:
            workspace = Path(
                temp
            )

            _stage_changed_files(
                repository_root=(
                    self._repository_root
                ),
                workspace=workspace,
                relative_paths=(
                    all_changed_paths
                ),
            )

            if fail_fast:
                for item in plan:
                    batch_findings = (
                        self._execute_batch_with_progress(
                            item=item,
                            workspace=workspace,
                            all_changed_paths=(
                                all_changed_paths
                            ),
                            on_scanner_start=on_scanner_start,
                            on_scanner_complete=on_scanner_complete,
                            on_scanner_failure=on_scanner_failure,
                        )
                    )

                    findings.extend(
                        batch_findings
                    )

                    successful_runs += 1

            else:
                workers = min(
                    self._max_workers,
                    len(plan),
                )

                with ThreadPoolExecutor(
                    max_workers=workers
                ) as executor:
                    future_to_index = {
                        executor.submit(
                            self._execute_batch_with_progress,
                            item=item,
                            workspace=workspace,
                            all_changed_paths=(
                                all_changed_paths
                            ),
                            on_scanner_start=on_scanner_start,
                            on_scanner_complete=on_scanner_complete,
                            on_scanner_failure=on_scanner_failure,
                        ): index
                        for index, item
                        in enumerate(plan)
                    }

                    results: dict[
                        int,
                        list[ScannerFinding],
                    ] = {}

                    errors: dict[
                        int,
                        Exception,
                    ] = {}

                    callback_errors: dict[
                        int,
                        ScannerProgressCallbackError,
                    ] = {}

                    for future in as_completed(
                        future_to_index
                    ):
                        index = (
                            future_to_index[
                                future
                            ]
                        )

                        try:
                            results[
                                index
                            ] = future.result()

                        except ScannerProgressCallbackError as exc:
                            callback_errors[index] = exc

                        except Exception as exc:
                            errors[
                                index
                            ] = exc

                if callback_errors:
                    first_error = min(callback_errors)
                    raise callback_errors[first_error]

                # Reassemble in deterministic
                # scanner-plan order.
                for index, item in enumerate(
                    plan
                ):
                    error = errors.get(
                        index
                    )

                    if error is not None:
                        failures.append(
                            ScannerRunFailure(
                                scanner=(
                                    item.scanner
                                ),
                                file_paths=(
                                    item.file_paths
                                ),
                                error_type=(
                                    type(
                                        error
                                    ).__name__
                                ),
                                message=str(
                                    error
                                ),
                            )
                        )

                        continue

                    findings.extend(
                        results.get(
                            index,
                            [],
                        )
                    )

                    successful_runs += 1

        deduplicated = (
            deduplicate_scanner_findings(
                findings
            )
        )

        return ScannerOrchestrationResult(
            findings=tuple(
                deduplicated
            ),
            failures=tuple(
                failures
            ),
            plan=tuple(
                plan
            ),
            successful_runs=(
                successful_runs
            ),
            diagnostic_only=scanner_filter is not None,
        )
