from __future__ import annotations

from collections import defaultdict, deque

from sycur_rag.evidence.builder import (
    EvidenceCandidate,
)


UNKNOWN_LAYER = "__unknown__"


def _validate_preferred_layers(
    preferred_layers: list[str] | None,
) -> list[str]:
    if preferred_layers is None:
        return []

    if not isinstance(
        preferred_layers,
        list,
    ):
        raise TypeError(
            "preferred_layers must be a list "
            "or None."
        )

    normalized: list[str] = []

    for index, layer in enumerate(
        preferred_layers
    ):
        if not isinstance(
            layer,
            str,
        ):
            raise TypeError(
                "preferred_layers item at "
                f"index {index} must be a string."
            )

        value = layer.strip()

        if not value:
            raise ValueError(
                "preferred_layers cannot contain "
                "blank values."
            )

        if value not in normalized:
            normalized.append(
                value
            )

    return normalized


def balance_evidence_layers(
    candidates: list[EvidenceCandidate],
    *,
    max_candidates: int,
    preferred_layers: list[str] | None = None,
) -> list[EvidenceCandidate]:
    if not isinstance(
        candidates,
        list,
    ):
        raise TypeError(
            "candidates must be a list."
        )

    if not isinstance(
        max_candidates,
        int,
    ):
        raise TypeError(
            "max_candidates must be an integer."
        )

    if max_candidates <= 0:
        raise ValueError(
            "max_candidates must be greater "
            "than zero."
        )

    if not candidates:
        return []

    preferred = _validate_preferred_layers(
        preferred_layers
    )

    # ==========================================
    # Defensive validation + dedup
    # ==========================================

    unique_candidates: list[
        EvidenceCandidate
    ] = []

    seen_keys: set[str] = set()

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

        if candidate.evidence_key in seen_keys:
            continue

        seen_keys.add(
            candidate.evidence_key
        )

        unique_candidates.append(
            candidate
        )

    # ==========================================
    # Build layer buckets.
    #
    # Candidates already arrive in retrieval
    # order, so deque preserves ranking inside
    # every layer.
    # ==========================================

    buckets: dict[
        str,
        deque[EvidenceCandidate],
    ] = defaultdict(
        deque
    )

    discovered_layers: list[str] = []

    for candidate in unique_candidates:
        layer = (
            candidate.layer.strip()
            if candidate.layer
            else UNKNOWN_LAYER
        )

        if layer not in discovered_layers:
            discovered_layers.append(
                layer
            )

        buckets[
            layer
        ].append(
            candidate
        )

    # ==========================================
    # Determine deterministic layer order.
    #
    # 1. preferred layers that actually exist
    # 2. remaining layers in first-seen order
    # ==========================================

    layer_order: list[str] = []

    for layer in preferred:
        if (
            layer in buckets
            and layer not in layer_order
        ):
            layer_order.append(
                layer
            )

    for layer in discovered_layers:
        if layer not in layer_order:
            layer_order.append(
                layer
            )

    # ==========================================
    # Round-robin balancing
    # ==========================================

    output: list[
        EvidenceCandidate
    ] = []

    while (
        len(output) < max_candidates
    ):
        added_this_round = False

        for layer in layer_order:
            bucket = buckets[
                layer
            ]

            if not bucket:
                continue

            output.append(
                bucket.popleft()
            )

            added_this_round = True

            if (
                len(output)
                >= max_candidates
            ):
                break

        if not added_this_round:
            break

    return output
