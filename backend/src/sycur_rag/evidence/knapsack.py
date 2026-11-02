from __future__ import annotations

import logging
from dataclasses import dataclass
from math import ceil, isfinite
from typing import Callable

from sycur_rag.core.config import get_settings
from sycur_rag.evidence.builder import (
    EvidenceCandidate,
)


logger = logging.getLogger(__name__)


# Conservative heuristic.
#
# This is an ESTIMATE, not an exact Qwen tokenizer
# count. Security/code text can tokenize densely,
# so 3 characters/token is intentionally safer
# than the common ~4 chars/token approximation.
CHARS_PER_TOKEN = 3

EVIDENCE_OVERHEAD_TOKENS = 24


TokenEstimator = Callable[
    [EvidenceCandidate],
    int,
]


@dataclass(frozen=True)
class SelectedEvidence:
    candidate: EvidenceCandidate
    estimated_tokens: int
    value: float


@dataclass(frozen=True)
class EvidenceSelection:
    selected: tuple[
        SelectedEvidence,
        ...
    ]

    estimated_tokens: int
    token_budget: int
    total_value: float

    strategy: str
    excluded_count: int

    @property
    def candidates(
        self,
    ) -> tuple[
        EvidenceCandidate,
        ...
    ]:
        return tuple(
            item.candidate
            for item in self.selected
        )


@dataclass(frozen=True)
class _PreparedEvidence:
    index: int
    candidate: EvidenceCandidate

    estimated_tokens: int
    bucket_cost: int

    value: float


@dataclass(frozen=True)
class _KnapsackState:
    value: float
    actual_tokens: int
    indexes: tuple[int, ...]


def estimate_evidence_tokens(
    candidate: EvidenceCandidate,
) -> int:
    if not isinstance(
        candidate,
        EvidenceCandidate,
    ):
        raise TypeError(
            "candidate must be an "
            "EvidenceCandidate."
        )

    parts = [
        candidate.title,
        candidate.content,
        candidate.document_name,
        candidate.layer or "",
        candidate.framework or "",
        candidate.language or "",
        candidate.topic or "",
        candidate.subtopic or "",
        candidate.control_id or "",
        " ".join(
            candidate.cwe_ids
        ),
        candidate.source_path or "",
    ]

    text = "\n".join(
        parts
    )

    character_count = len(
        text
    )

    estimated = ceil(
        character_count
        / CHARS_PER_TOKEN
    )

    estimated += (
        EVIDENCE_OVERHEAD_TOKENS
    )

    return max(
        1,
        estimated,
    )


def _evidence_value(
    candidate: EvidenceCandidate,
) -> float:
    value = float(
        candidate.rrf_score
    )

    if not isfinite(
        value
    ):
        raise ValueError(
            "Evidence rrf_score must be finite."
        )

    if value < 0:
        raise ValueError(
            "Evidence rrf_score cannot be negative."
        )

    return value


def _validate_inputs(
    candidates: list[EvidenceCandidate],
    *,
    token_budget: int,
    bucket_size: int,
    token_estimator: TokenEstimator,
) -> list[_PreparedEvidence]:
    if not isinstance(
        candidates,
        list,
    ):
        raise TypeError(
            "candidates must be a list."
        )

    if not isinstance(
        token_budget,
        int,
    ):
        raise TypeError(
            "token_budget must be an integer."
        )

    if token_budget <= 0:
        raise ValueError(
            "token_budget must be greater "
            "than zero."
        )

    if not isinstance(
        bucket_size,
        int,
    ):
        raise TypeError(
            "bucket_size must be an integer."
        )

    if bucket_size <= 0:
        raise ValueError(
            "bucket_size must be greater "
            "than zero."
        )

    if not callable(
        token_estimator
    ):
        raise TypeError(
            "token_estimator must be callable."
        )

    prepared: list[
        _PreparedEvidence
    ] = []

    seen: set[str] = set()

    for index, candidate in enumerate(
        candidates
    ):
        if not isinstance(
            candidate,
            EvidenceCandidate,
        ):
            raise TypeError(
                "Candidate at index "
                f"{index} must be an "
                "EvidenceCandidate."
            )

        # Defensive dedup.
        if (
            candidate.evidence_key
            in seen
        ):
            continue

        seen.add(
            candidate.evidence_key
        )

        estimated_tokens = (
            token_estimator(
                candidate
            )
        )

        if not isinstance(
            estimated_tokens,
            int,
        ):
            raise TypeError(
                "token_estimator must "
                "return an integer."
            )

        if estimated_tokens <= 0:
            raise ValueError(
                "Estimated token cost "
                "must be greater than zero."
            )

        # Round UP.
        #
        # Example:
        # 61 tokens with bucket 50
        # becomes 2 buckets, not 1.
        #
        # This keeps the approximation
        # conservative.
        bucket_cost = ceil(
            estimated_tokens
            / bucket_size
        )

        prepared.append(
            _PreparedEvidence(
                index=index,
                candidate=candidate,
                estimated_tokens=(
                    estimated_tokens
                ),
                bucket_cost=(
                    bucket_cost
                ),
                value=(
                    _evidence_value(
                        candidate
                    )
                ),
            )
        )

    return prepared


def _state_is_better(
    candidate: _KnapsackState,
    current: _KnapsackState | None,
) -> bool:
    if current is None:
        return True

    epsilon = 1e-12

    if (
        candidate.value
        > current.value + epsilon
    ):
        return True

    if (
        abs(
            candidate.value
            - current.value
        )
        <= epsilon
    ):
        if (
            candidate.actual_tokens
            < current.actual_tokens
        ):
            return True

        if (
            candidate.actual_tokens
            == current.actual_tokens
            and candidate.indexes
            < current.indexes
        ):
            return True

    return False


def _solve_knapsack(
    prepared: list[_PreparedEvidence],
    *,
    token_budget: int,
    bucket_size: int,
) -> list[_PreparedEvidence]:
    if not prepared:
        return []

    capacity = (
        token_budget
        // bucket_size
    )

    if capacity <= 0:
        return []

    states: list[
        _KnapsackState | None
    ] = [
        None
        for _ in range(
            capacity + 1
        )
    ]

    states[0] = (
        _KnapsackState(
            value=0.0,
            actual_tokens=0,
            indexes=(),
        )
    )

    for prepared_index, item in enumerate(
        prepared
    ):
        if (
            item.estimated_tokens
            > token_budget
        ):
            continue

        if (
            item.bucket_cost
            > capacity
        ):
            continue

        for current_capacity in range(
            capacity,
            item.bucket_cost - 1,
            -1,
        ):
            previous = states[
                current_capacity
                - item.bucket_cost
            ]

            if previous is None:
                continue

            next_state = (
                _KnapsackState(
                    value=(
                        previous.value
                        + item.value
                    ),
                    actual_tokens=(
                        previous.actual_tokens
                        + item.estimated_tokens
                    ),
                    indexes=(
                        previous.indexes
                        + (
                            prepared_index,
                        )
                    ),
                )
            )

            if (
                next_state.actual_tokens
                > token_budget
            ):
                continue

            if _state_is_better(
                next_state,
                states[
                    current_capacity
                ],
            ):
                states[
                    current_capacity
                ] = next_state

    best: _KnapsackState | None = None

    for state in states:
        if state is None:
            continue

        if _state_is_better(
            state,
            best,
        ):
            best = state

    if (
        best is None
        or not best.indexes
    ):
        return []

    selected = [
        prepared[index]
        for index in best.indexes
    ]

    # Preserve incoming evidence order for
    # downstream prompt/audit stability.
    selected.sort(
        key=lambda item: item.index
    )

    return selected


def _solve_greedy(
    prepared: list[_PreparedEvidence],
    *,
    token_budget: int,
) -> list[_PreparedEvidence]:
    if not prepared:
        return []

    ranked = sorted(
        prepared,
        key=lambda item: (
            -(
                item.value
                / item.estimated_tokens
            ),
            -item.value,
            item.estimated_tokens,
            item.index,
        ),
    )

    selected: list[
        _PreparedEvidence
    ] = []

    used_tokens = 0

    for item in ranked:
        if (
            item.estimated_tokens
            > token_budget
        ):
            continue

        if (
            used_tokens
            + item.estimated_tokens
            > token_budget
        ):
            continue

        selected.append(
            item
        )

        used_tokens += (
            item.estimated_tokens
        )

    selected.sort(
        key=lambda item: item.index
    )

    return selected


def _build_selection(
    prepared: list[_PreparedEvidence],
    selected: list[_PreparedEvidence],
    *,
    token_budget: int,
    strategy: str,
) -> EvidenceSelection:
    selected_items = tuple(
        SelectedEvidence(
            candidate=item.candidate,
            estimated_tokens=(
                item.estimated_tokens
            ),
            value=item.value,
        )
        for item in selected
    )

    return EvidenceSelection(
        selected=selected_items,

        estimated_tokens=sum(
            item.estimated_tokens
            for item in selected
        ),

        token_budget=token_budget,

        total_value=sum(
            item.value
            for item in selected
        ),

        strategy=strategy,

        excluded_count=(
            len(prepared)
            - len(selected)
        ),
    )


def select_evidence(
    candidates: list[EvidenceCandidate],
    *,
    token_budget: int | None = None,
    bucket_size: int | None = None,
    token_estimator: TokenEstimator | None = None,
) -> EvidenceSelection:
    settings = get_settings()

    final_token_budget = (
        token_budget
        if token_budget is not None
        else settings.EVIDENCE_TOKEN_BUDGET
    )

    final_bucket_size = (
        bucket_size
        if bucket_size is not None
        else settings.TOKEN_BUCKET_SIZE
    )

    final_estimator = (
        token_estimator
        if token_estimator is not None
        else estimate_evidence_tokens
    )

    prepared = _validate_inputs(
        candidates,
        token_budget=(
            final_token_budget
        ),
        bucket_size=(
            final_bucket_size
        ),
        token_estimator=(
            final_estimator
        ),
    )

    if not prepared:
        return EvidenceSelection(
            selected=(),
            estimated_tokens=0,
            token_budget=(
                final_token_budget
            ),
            total_value=0.0,
            strategy="knapsack",
            excluded_count=0,
        )

    try:
        selected = _solve_knapsack(
            prepared,
            token_budget=(
                final_token_budget
            ),
            bucket_size=(
                final_bucket_size
            ),
        )

        strategy = "knapsack"

    except Exception:
        logger.exception(
            "Evidence knapsack failed. "
            "Falling back to greedy selection."
        )

        selected = _solve_greedy(
            prepared,
            token_budget=(
                final_token_budget
            ),
        )

        strategy = "greedy_fallback"

    return _build_selection(
        prepared,
        selected,
        token_budget=(
            final_token_budget
        ),
        strategy=strategy,
    )