"""Retrieval configurations under benchmark.

Only ``ungated`` trusts request filters as an authorization mechanism. Every
other configuration evaluates a separate server-derived :class:`ServerScope`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Type

from .authorization import is_authorized, matches_client_filters
from .models import AttackCase, Document, RetrievalHit, RetrievalResult, ServerScope
from .scorer import DeterministicVectorScorer


CONFIGURATION_NAMES = (
    "ungated",
    "post_retrieval_gating",
    "pre_filtered_partition",
    "per_scope_index",
)


class BaseRetriever(ABC):
    name = "base"

    def __init__(
        self,
        documents: Sequence[Document],
        scorer: Optional[DeterministicVectorScorer] = None,
    ) -> None:
        self.documents = tuple(documents)
        self.by_id = {document.doc_id: document for document in self.documents}
        self.scorer = scorer or DeterministicVectorScorer()

    @abstractmethod
    def _vector_hits(
        self, case: AttackCase
    ) -> Tuple[List[RetrievalHit], int, int]:
        """Return hits, documents scored, and candidate count."""

    @abstractmethod
    def _allow_graph_document(self, document: Document, case: AttackCase) -> bool:
        """Apply the configuration's policy to graph expansion."""

    def _expand_graph(
        self, hits: List[RetrievalHit], case: AttackCase
    ) -> List[RetrievalHit]:
        if case.graph_depth <= 0 or not hits:
            return hits
        best: Dict[str, RetrievalHit] = {hit.doc_id: hit for hit in hits}
        frontier = list(hits)
        for depth in range(1, case.graph_depth + 1):
            next_frontier: List[RetrievalHit] = []
            for parent_hit in sorted(frontier, key=lambda hit: (-hit.score, hit.doc_id)):
                parent = self.by_id.get(parent_hit.doc_id)
                if parent is None:
                    continue
                for reference_index, target_id in enumerate(parent.references):
                    target = self.by_id.get(target_id)
                    if target is None or not self._allow_graph_document(target, case):
                        continue
                    graph_score = round(
                        max(0.0, parent_hit.score * (0.95 ** depth))
                        - reference_index * 0.000001,
                        12,
                    )
                    candidate = RetrievalHit(target.doc_id, graph_score, "graph")
                    existing = best.get(target.doc_id)
                    if existing is None or candidate.score > existing.score:
                        best[target.doc_id] = candidate
                        next_frontier.append(candidate)
            frontier = next_frontier
            if not frontier:
                break
        return sorted(best.values(), key=lambda hit: (-hit.score, hit.doc_id))[: case.k]

    def retrieve(self, case: AttackCase) -> RetrievalResult:
        hits, scored_count, candidate_count = self._vector_hits(case)
        hits = self._expand_graph(hits, case)
        documents = [self.by_id[hit.doc_id] for hit in hits]
        answer = " ".join(document.fact_token for document in documents)
        return RetrievalResult(
            case_id=case.case_id,
            configuration=self.name,
            hits=tuple(hits),
            answer=answer,
            scored_count=scored_count,
            candidate_count=candidate_count,
        )

    def _rank(self, query: str, documents: Iterable[Document], k: int) -> List[RetrievalHit]:
        return [
            RetrievalHit(document.doc_id, score, "vector")
            for document, score in self.scorer.rank(query, documents, limit=k)
        ]


class UngatedRetriever(BaseRetriever):
    """Vulnerable baseline: client filters are the only boundary."""

    name = "ungated"

    def _vector_hits(
        self, case: AttackCase
    ) -> Tuple[List[RetrievalHit], int, int]:
        candidates = [
            document
            for document in self.documents
            if matches_client_filters(document, case.client_filters)
        ]
        return self._rank(case.query, candidates, case.k), len(candidates), len(candidates)

    def _allow_graph_document(self, document: Document, case: AttackCase) -> bool:
        return matches_client_filters(document, case.client_filters)


class PostRetrievalGatingRetriever(BaseRetriever):
    """Rank globally, then intersect top-k with trusted and client constraints."""

    name = "post_retrieval_gating"

    def _vector_hits(
        self, case: AttackCase
    ) -> Tuple[List[RetrievalHit], int, int]:
        global_hits = self._rank(case.query, self.documents, case.k)
        permitted = [
            hit
            for hit in global_hits
            if is_authorized(self.by_id[hit.doc_id], case.server_scope)
            and matches_client_filters(self.by_id[hit.doc_id], case.client_filters)
        ]
        return permitted, len(self.documents), len(self.documents)

    def _allow_graph_document(self, document: Document, case: AttackCase) -> bool:
        return is_authorized(document, case.server_scope) and matches_client_filters(
            document, case.client_filters
        )


class PreFilteredPartitionRetriever(BaseRetriever):
    """Intersect trusted and request constraints before scoring."""

    name = "pre_filtered_partition"

    def _candidates(self, case: AttackCase) -> Tuple[Document, ...]:
        return tuple(
            document
            for document in self.documents
            if is_authorized(document, case.server_scope)
            and matches_client_filters(document, case.client_filters)
        )

    def _vector_hits(
        self, case: AttackCase
    ) -> Tuple[List[RetrievalHit], int, int]:
        candidates = self._candidates(case)
        return self._rank(case.query, candidates, case.k), len(candidates), len(candidates)

    def _allow_graph_document(self, document: Document, case: AttackCase) -> bool:
        return is_authorized(document, case.server_scope) and matches_client_filters(
            document, case.client_filters
        )


class PerScopeIndexRetriever(BaseRetriever):
    """Build immutable in-memory indexes keyed only by trusted server scope."""

    name = "per_scope_index"

    def __init__(
        self,
        documents: Sequence[Document],
        scorer: Optional[DeterministicVectorScorer] = None,
    ) -> None:
        super().__init__(documents, scorer)
        self._scope_indexes: Dict[Tuple[object, ...], Tuple[Document, ...]] = {}

    def scope_index(self, scope: ServerScope) -> Tuple[Document, ...]:
        key = scope.cache_key()
        if key not in self._scope_indexes:
            self._scope_indexes[key] = tuple(
                document for document in self.documents if is_authorized(document, scope)
            )
        return self._scope_indexes[key]

    @property
    def index_count(self) -> int:
        return len(self._scope_indexes)

    def _vector_hits(
        self, case: AttackCase
    ) -> Tuple[List[RetrievalHit], int, int]:
        scope_documents = self.scope_index(case.server_scope)
        candidates = tuple(
            document
            for document in scope_documents
            if matches_client_filters(document, case.client_filters)
        )
        return self._rank(case.query, candidates, case.k), len(candidates), len(scope_documents)

    def _allow_graph_document(self, document: Document, case: AttackCase) -> bool:
        scope_ids = {
            candidate.doc_id for candidate in self.scope_index(case.server_scope)
        }
        return document.doc_id in scope_ids and matches_client_filters(
            document, case.client_filters
        )


RETRIEVER_TYPES: Mapping[str, Type[BaseRetriever]] = {
    "ungated": UngatedRetriever,
    "post_retrieval_gating": PostRetrievalGatingRetriever,
    "pre_filtered_partition": PreFilteredPartitionRetriever,
    "per_scope_index": PerScopeIndexRetriever,
}


def make_retriever(
    name: str,
    documents: Sequence[Document],
    scorer: Optional[DeterministicVectorScorer] = None,
) -> BaseRetriever:
    try:
        retriever_type = RETRIEVER_TYPES[name]
    except KeyError as error:
        raise ValueError("unknown configuration: " + name) from error
    return retriever_type(documents, scorer)
