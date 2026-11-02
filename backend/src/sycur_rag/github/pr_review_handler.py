from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from hashlib import sha256

from sycur_rag.github.app_auth import create_installation_access_token
from sycur_rag.github.client import GitHubClient
from sycur_rag.github.pull_request import (
    parse_github_rest_pull_request_metadata,
)
from sycur_rag.github.assembler import assemble_github_pull_request_changeset
from sycur_rag.github.workspace import github_pull_request_workspace
from sycur_rag.github.review_pipeline import evaluate_completed_scan

from sycur_rag.models.review import ReviewResult
from sycur_rag.scanners.orchestrator import ScannerOrchestrator
from sycur_rag.scanners.semgrep import SemgrepAdapter
from sycur_rag.scanners.bandit import BanditAdapter
from sycur_rag.scanners.gitleaks import GitleaksAdapter
from sycur_rag.scanners.trivy import TrivyAdapter
from sycur_rag.scanners.osv import OSVScannerAdapter
from sycur_rag.scanners.checkov import CheckovAdapter
from sycur_rag.models.finding import ScannerFinding
from sycur_rag.models.finding import EvidenceReference
from sycur_rag.retrieval.hybrid import search_hybrid
from sycur_rag.evidence.knapsack import (
    EvidenceCandidate,
    select_evidence,
)
from sycur_rag.evidence.pack import build_evidence_pack
from sycur_rag.llm import (
    GroundedExplanation,
    generate_grounded_explanation,
)


def explain_pr_finding_with_rag(
    finding: ScannerFinding,
    *,
    progress_callback: Callable[[str], None] | None = None,
) -> GroundedExplanation | None:
    """Retrieve security evidence and ask local AI for a grounded fix."""

    query = (
        f"{finding.title} "
        f"{finding.rule_id} "
        f"{' '.join(finding.cwe_ids)} "
        f"{finding.message[:300]}"
    )

    if progress_callback is not None:
        progress_callback("RAG_EVALUATION")

    results = search_hybrid(
        query_text=query,
        cwe_ids=list(finding.cwe_ids),
        scanner=finding.scanner,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        final_top_k=5,
    )

    if not results:
        return None

    candidates = []

    for rank, item in enumerate(results, start=1):
        if not item.content.strip():
            continue

        content_hash = (
            item.content_hash
            or sha256(item.content.encode("utf-8")).hexdigest()
        )

        signals = tuple(
            name
            for name, value in (
                ("keyword", item.keyword_rank),
                ("vector", item.vector_rank),
                ("graph", item.graph_rank),
            )
            if value is not None
        )

        candidates.append(
            EvidenceCandidate(
                evidence_key=(
                    f"{item.document_name}:"
                    f"{item.chunk_index}:"
                    f"{content_hash}"
                ),
                title=item.title,
                content=item.content,
                document_name=item.document_name,
                retrieval_rank=rank,
                rrf_score=item.rrf_score,
                layer=item.layer,
                framework=item.framework,
                language=item.language,
                topic=item.topic,
                subtopic=item.subtopic,
                control_id=item.control_id,
                cwe_ids=tuple(item.cwe_ids or ()),
                source_path=item.source_path,
                chunk_index=item.chunk_index,
                content_hash=content_hash,
                retrieval_signals=signals,
                keyword_rank=item.keyword_rank,
                vector_rank=item.vector_rank,
                graph_rank=item.graph_rank,
                graph_depth=item.graph_depth,
                graph_matched_seeds=tuple(
                    item.graph_matched_seeds or ()
                ),
            )
        )

    if not candidates:
        return None

    selection = select_evidence(candidates)

    question = (
        f"Explain security finding {finding.rule_id}: "
        f"{finding.title}. "
        f"Risk: {finding.message[:500]}. "
        "Using only the supplied evidence, explain the "
        "vulnerability, its risk, and the required fix."
    )

    evidence = build_evidence_pack(
        question,
        selection,
    )

    if not evidence.has_evidence:
        return None

    if progress_callback is not None:
        progress_callback("AI_EXPLANATION")

    explanation = generate_grounded_explanation(
        question=question,
        evidence=evidence,
        trusted_cwe_ids=tuple(finding.cwe_ids),
    )

    # Match AI citations against actual retrieved sources.
    sources_by_id = {
        source.source_id: source
        for source in evidence.sources
    }

    references = []

    for source_id in explanation.source_ids:
        source = sources_by_id.get(source_id)

        if source is None:
            raise RuntimeError(
                f"Unknown evidence source ID: {source_id}"
            )

        references.append(
            EvidenceReference(
                source_id=source.source_id,
                document_name=source.document_name,
                title=source.title,
                control_id=source.control_id,
            )
        )

    # Attach only verified, AI-cited sources.
    explanation.attach_evidence_references(
        tuple(references)
    )

    return explanation


def review_github_pr_job(job: dict) -> ReviewResult:
    """
    Review the exact GitHub PR revision recorded
    in a claimed queue job.

    Returns a ReviewResult for worker persistence.
    """

    repository = job["repository"]
    pr_number = job["pr_number"]
    installation_id = job["installation_id"]
    expected_sha = job["head_sha"]

    token = create_installation_access_token(
        installation_id=installation_id,
        repository_full_name=repository,
    )

    client = GitHubClient(token=token)

    def fetch_metadata():
        response = client.get_pull_request(
            repository=repository,
            pull_request_number=pr_number,
        )
        return parse_github_rest_pull_request_metadata(response)

    metadata = fetch_metadata()

    if metadata.head_sha.lower() != expected_sha.lower():
        raise RuntimeError("Stale PR commit; review rejected.")

    pages = client.list_pull_request_file_pages(
        repository=repository,
        pull_request_number=pr_number,
    )

    # Validate the complete changed-file response.
    assemble_github_pull_request_changeset(
        metadata=metadata,
        file_pages=pages,
    )

    # Detect a PR update while fetching file metadata.
    if fetch_metadata().head_sha.lower() != expected_sha.lower():
        raise RuntimeError("PR changed during file discovery.")

    changed_files = [
        item["filename"]
        for page in pages
        for item in page
        if item["status"] != "removed"
    ]

    if not changed_files:
        raise RuntimeError("No scannable changed files.")

    rules = (
        Path(__file__).resolve().parents[1]
        / "scanners"
        / "rules"
        / "web_security.yml"
    )

    if not rules.is_file():
        raise FileNotFoundError("Semgrep rules file missing.")

    scanner_event_callback = job.get(
        "_scanner_event_callback"
    )

    if (
        scanner_event_callback is not None
        and not callable(scanner_event_callback)
    ):
        raise TypeError(
            "Invalid scanner event callback."
        )

    def report_scanner_plan(plan):
        if scanner_event_callback is None:
            return

        scanner_event_callback(
            "plan",
            scanner_plan=[
                (item.scanner, item.file_paths)
                for item in plan
            ],
        )

    def report_scanner_start(item):
        if scanner_event_callback is None:
            return

        scanner_event_callback(
            "start",
            scanner=item.scanner,
        )

    def report_scanner_complete(item, findings_count):
        if scanner_event_callback is None:
            return

        scanner_event_callback(
            "complete",
            scanner=item.scanner,
            findings_count=findings_count,
        )

    def report_scanner_failure(item, error):
        if scanner_event_callback is None:
            return

        scanner_event_callback(
            "failure",
            scanner=item.scanner,
            error_type=type(error).__name__,
            error_message=str(error),
        )

    with github_pull_request_workspace(
        metadata=metadata,
        token=token,
    ) as workspace:

        adapters = {
            "gitleaks": GitleaksAdapter(),
            "semgrep": SemgrepAdapter(config=str(rules)),
            "bandit": BanditAdapter(),
            "trivy": TrivyAdapter(),
            "osv": OSVScannerAdapter(),
            "checkov": CheckovAdapter(),
        }

        scanner = ScannerOrchestrator(
            repository_root=workspace,
            adapters=adapters,
            max_workers=3,
        )

        scan_result = scanner.run(
            changed_files,
            fail_fast=False,
            on_plan=(
                report_scanner_plan
                if scanner_event_callback is not None
                else None
            ),
            on_scanner_start=(
                report_scanner_start
                if scanner_event_callback is not None
                else None
            ),
            on_scanner_complete=(
                report_scanner_complete
                if scanner_event_callback is not None
                else None
            ),
            on_scanner_failure=(
                report_scanner_failure
                if scanner_event_callback is not None
                else None
            ),
        )

    progress_callback = job.get(
        "_progress_callback"
    )

    if (
        progress_callback is not None
        and not callable(progress_callback)
    ):
        raise TypeError(
            "Invalid review progress callback."
        )

    if progress_callback is not None:
        progress_callback("FINDING_ANALYSIS")

    reported_stages: set[str] = set()

    def report_stage(stage: str) -> None:
        if (
            progress_callback is None
            or stage in reported_stages
        ):
            return

        reported_stages.add(stage)

        progress_callback(stage)

    def explain_finding(
        finding: ScannerFinding,
    ) -> GroundedExplanation | None:

        return explain_pr_finding_with_rag(
            finding,
            progress_callback=report_stage,
        )

    return evaluate_completed_scan(
        scan_result,
        explain_finding=explain_finding,
        progress_callback=report_stage,
    )
