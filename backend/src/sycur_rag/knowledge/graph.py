from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from math import isfinite


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    label: str

    metadata: dict[str, str] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        node_id = self.node_id.strip()
        node_type = self.node_type.strip()
        label = self.label.strip()

        if not node_id:
            raise ValueError(
                "node_id cannot be empty."
            )

        if not node_type:
            raise ValueError(
                "node_type cannot be empty."
            )

        if not label:
            raise ValueError(
                "label cannot be empty."
            )

        object.__setattr__(
            self,
            "node_id",
            node_id,
        )

        object.__setattr__(
            self,
            "node_type",
            node_type,
        )

        object.__setattr__(
            self,
            "label",
            label,
        )


@dataclass(frozen=True)
class GraphEdge:
    source_id: str
    target_id: str
    relation: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        source_id = self.source_id.strip()
        target_id = self.target_id.strip()
        relation = self.relation.strip()

        if not source_id:
            raise ValueError(
                "source_id cannot be empty."
            )

        if not target_id:
            raise ValueError(
                "target_id cannot be empty."
            )

        if source_id == target_id:
            raise ValueError(
                "Self-referencing graph edges "
                "are not allowed."
            )

        if not relation:
            raise ValueError(
                "relation cannot be empty."
            )

        if (
            not isfinite(self.weight)
            or self.weight <= 0
        ):
            raise ValueError(
                "weight must be a positive "
                "finite number."
            )

        object.__setattr__(
            self,
            "source_id",
            source_id,
        )

        object.__setattr__(
            self,
            "target_id",
            target_id,
        )

        object.__setattr__(
            self,
            "relation",
            relation,
        )


@dataclass(frozen=True)
class TraversalResult:
    node: GraphNode
    depth: int

    parent_id: str | None = None
    relation: str | None = None


class SecurityGraph:
    def __init__(self) -> None:
        self._nodes: dict[
            str,
            GraphNode,
        ] = {}

        self._adjacency: dict[
            str,
            list[GraphEdge],
        ] = {}

        self._edge_keys: set[
            tuple[str, str, str]
        ] = set()

    @property
    def node_count(self) -> int:
        return len(
            self._nodes
        )

    @property
    def edge_count(self) -> int:
        return len(
            self._edge_keys
        )

    def add_node(
        self,
        node: GraphNode,
    ) -> None:
        if not isinstance(
            node,
            GraphNode,
        ):
            raise TypeError(
                "node must be a GraphNode."
            )

        existing = self._nodes.get(
            node.node_id
        )

        if existing is not None:
            if existing != node:
                raise ValueError(
                    "A different node already "
                    f"exists with id {node.node_id}."
                )

            return

        self._nodes[
            node.node_id
        ] = node

        self._adjacency.setdefault(
            node.node_id,
            [],
        )

    def add_edge(
        self,
        edge: GraphEdge,
    ) -> None:
        if not isinstance(
            edge,
            GraphEdge,
        ):
            raise TypeError(
                "edge must be a GraphEdge."
            )

        if (
            edge.source_id
            not in self._nodes
        ):
            raise ValueError(
                "Unknown source node: "
                f"{edge.source_id}"
            )

        if (
            edge.target_id
            not in self._nodes
        ):
            raise ValueError(
                "Unknown target node: "
                f"{edge.target_id}"
            )

        key = (
            edge.source_id,
            edge.target_id,
            edge.relation,
        )

        if key in self._edge_keys:
            return

        self._edge_keys.add(
            key
        )

        self._adjacency[
            edge.source_id
        ].append(
            edge
        )

    def get_node(
        self,
        node_id: str,
    ) -> GraphNode | None:
        if not isinstance(
            node_id,
            str,
        ):
            raise TypeError(
                "node_id must be a string."
            )

        return self._nodes.get(
            node_id.strip()
        )

    def bfs(
        self,
        start_ids: list[str],
        *,
        max_depth: int = 2,
        allowed_relations: set[str] | None = None,
        max_results: int = 50,
    ) -> list[TraversalResult]:
        if not start_ids:
            raise ValueError(
                "start_ids cannot be empty."
            )

        if max_depth < 0:
            raise ValueError(
                "max_depth cannot be negative."
            )

        if max_results <= 0:
            raise ValueError(
                "max_results must be greater "
                "than zero."
            )

        normalized_starts = [
            value.strip()
            for value in start_ids
            if isinstance(
                value,
                str,
            )
            and value.strip()
        ]

        if (
            len(normalized_starts)
            != len(start_ids)
        ):
            raise ValueError(
                "start_ids contains an "
                "invalid node id."
            )

        missing = [
            node_id
            for node_id
            in normalized_starts
            if node_id not in self._nodes
        ]

        if missing:
            raise ValueError(
                "Unknown start node(s): "
                + ", ".join(
                    missing
                )
            )

        normalized_relations = None

        if allowed_relations is not None:
            normalized_relations = {
                relation.strip()
                for relation
                in allowed_relations
                if isinstance(
                    relation,
                    str,
                )
                and relation.strip()
            }

            if (
                len(normalized_relations)
                != len(allowed_relations)
            ):
                raise ValueError(
                    "allowed_relations contains "
                    "an invalid value."
                )

        queue: deque[
            tuple[
                str,
                int,
                str | None,
                str | None,
            ]
        ] = deque()

        visited: set[str] = set()

        for node_id in normalized_starts:
            if node_id in visited:
                continue

            visited.add(
                node_id
            )

            queue.append(
                (
                    node_id,
                    0,
                    None,
                    None,
                )
            )

        results: list[
            TraversalResult
        ] = []

        while queue:
            (
                node_id,
                depth,
                parent_id,
                relation,
            ) = queue.popleft()

            results.append(
                TraversalResult(
                    node=self._nodes[
                        node_id
                    ],
                    depth=depth,
                    parent_id=parent_id,
                    relation=relation,
                )
            )

            if (
                len(results)
                >= max_results
            ):
                break

            if depth >= max_depth:
                continue

            for edge in self._adjacency.get(
                node_id,
                [],
            ):
                if (
                    normalized_relations
                    is not None
                    and edge.relation
                    not in normalized_relations
                ):
                    continue

                if (
                    edge.target_id
                    in visited
                ):
                    continue

                visited.add(
                    edge.target_id
                )

                queue.append(
                    (
                        edge.target_id,
                        depth + 1,
                        node_id,
                        edge.relation,
                    )
                )

        return results

    def validate(self) -> None:
        """
        Validate graph integrity using DFS.

        Security graphs may legitimately contain
        cycles, so cycles themselves are not treated
        as corruption.
        """

        for source_id, edges in (
            self._adjacency.items()
        ):
            if source_id not in self._nodes:
                raise RuntimeError(
                    "Graph contains an unknown "
                    f"adjacency source: {source_id}"
                )

            for edge in edges:
                if (
                    edge.target_id
                    not in self._nodes
                ):
                    raise RuntimeError(
                        "Graph contains dangling "
                        "edge target: "
                        f"{edge.target_id}"
                    )

        visited: set[str] = set()

        for start_id in self._nodes:
            if start_id in visited:
                continue

            stack = [
                start_id
            ]

            while stack:
                node_id = stack.pop()

                if node_id in visited:
                    continue

                visited.add(
                    node_id
                )

                for edge in (
                    self._adjacency.get(
                        node_id,
                        [],
                    )
                ):
                    if (
                        edge.target_id
                        not in visited
                    ):
                        stack.append(
                            edge.target_id
                        )

        if len(visited) != len(
            self._nodes
        ):
            raise RuntimeError(
                "Graph validation did not visit "
                "all nodes."
            )