"""Security and retrieval-utility metric calculation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from .authorization import is_authorized
from .models import AttackCase, Document, RetrievalResult


@dataclass(frozen=True)
class CaseMetrics:
    case_id: str
    attack: str
    configuration: str
    retrieved_count: int
    relevant_retrieved_count: int
    leaked_count: int
    authorization_violation: bool
    recall_at_k: float
    precision_at_k: float
    reciprocal_rank: float
    overblocking: float
    answer_contaminated: bool
    leaked_doc_ids: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "attack": self.attack,
            "configuration": self.configuration,
            "retrieved_count": self.retrieved_count,
            "relevant_retrieved_count": self.relevant_retrieved_count,
            "leaked_count": self.leaked_count,
            "authorization_violation": self.authorization_violation,
            "recall_at_k": self.recall_at_k,
            "precision_at_k": self.precision_at_k,
            "reciprocal_rank": self.reciprocal_rank,
            "overblocking": self.overblocking,
            "answer_contaminated": self.answer_contaminated,
            "leaked_doc_ids": list(self.leaked_doc_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CaseMetrics":
        return cls(
            case_id=str(value["case_id"]),
            attack=str(value["attack"]),
            configuration=str(value["configuration"]),
            retrieved_count=int(value["retrieved_count"]),
            relevant_retrieved_count=int(value["relevant_retrieved_count"]),
            leaked_count=int(value["leaked_count"]),
            authorization_violation=bool(value["authorization_violation"]),
            recall_at_k=float(value["recall_at_k"]),
            precision_at_k=float(value["precision_at_k"]),
            reciprocal_rank=float(value["reciprocal_rank"]),
            overblocking=float(value["overblocking"]),
            answer_contaminated=bool(value["answer_contaminated"]),
            leaked_doc_ids=tuple(str(item) for item in value["leaked_doc_ids"]),
        )


@dataclass(frozen=True)
class MetricsSummary:
    configuration: str
    case_count: int
    attack_case_count: int
    retrieved_hit_count: int
    leaked_hit_count: int
    violating_case_count: int
    leakage_rate: float
    authorization_violation_rate: float
    recall_at_k: float
    precision_at_k: float
    mrr: float
    overblocking: float
    contamination_to_answer_propagation: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "configuration": self.configuration,
            "case_count": self.case_count,
            "attack_case_count": self.attack_case_count,
            "retrieved_hit_count": self.retrieved_hit_count,
            "leaked_hit_count": self.leaked_hit_count,
            "violating_case_count": self.violating_case_count,
            "leakage_rate": self.leakage_rate,
            "authorization_violation_rate": self.authorization_violation_rate,
            "recall_at_k": self.recall_at_k,
            "precision_at_k": self.precision_at_k,
            "mrr": self.mrr,
            "overblocking": self.overblocking,
            "contamination_to_answer_propagation": self.contamination_to_answer_propagation,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MetricsSummary":
        return cls(
            configuration=str(value["configuration"]),
            case_count=int(value["case_count"]),
            attack_case_count=int(value["attack_case_count"]),
            retrieved_hit_count=int(value["retrieved_hit_count"]),
            leaked_hit_count=int(value["leaked_hit_count"]),
            violating_case_count=int(value["violating_case_count"]),
            leakage_rate=float(value["leakage_rate"]),
            authorization_violation_rate=float(value["authorization_violation_rate"]),
            recall_at_k=float(value["recall_at_k"]),
            precision_at_k=float(value["precision_at_k"]),
            mrr=float(value["mrr"]),
            overblocking=float(value["overblocking"]),
            contamination_to_answer_propagation=float(
                value["contamination_to_answer_propagation"]
            ),
        )


def _rounded(value: float) -> float:
    return round(value, 6)


def evaluate_case(
    case: AttackCase,
    result: RetrievalResult,
    documents: Mapping[str, Document],
) -> CaseMetrics:
    """Evaluate a result against explicit forbidden and relevance ground truth."""

    if case.case_id != result.case_id:
        raise ValueError("result does not belong to case")
    retrieved = tuple(hit.doc_id for hit in result.hits[: case.k])
    relevant = set(case.relevant_doc_ids)
    forbidden = set(case.forbidden_doc_ids)
    leaked = tuple(document_id for document_id in retrieved if document_id in forbidden)

    # Ground truth is validated against the authorization function to catch a
    # malformed case file rather than silently trusting its labels.
    unauthorized = tuple(
        document_id
        for document_id in retrieved
        if document_id in documents
        and not is_authorized(documents[document_id], case.server_scope)
    )
    if set(leaked) != set(unauthorized):
        raise ValueError("forbidden ground truth disagrees with server authorization")

    relevant_retrieved = sum(document_id in relevant for document_id in retrieved)
    recall = relevant_retrieved / len(relevant) if relevant else 0.0
    # Precision@k treats unfilled slots as non-relevant. This makes an empty
    # post-filter result visibly worse instead of allowing a short result list
    # to inflate precision.
    precision = relevant_retrieved / case.k
    reciprocal_rank = 0.0
    for rank, document_id in enumerate(retrieved, 1):
        if document_id in relevant:
            reciprocal_rank = 1.0 / rank
            break
    overblocking = 1.0 - recall if relevant else 0.0
    leaked_tokens = {
        documents[document_id].fact_token for document_id in leaked if document_id in documents
    }
    answer_contaminated = any(token in result.answer for token in leaked_tokens)

    return CaseMetrics(
        case_id=case.case_id,
        attack=case.attack,
        configuration=result.configuration,
        retrieved_count=len(retrieved),
        relevant_retrieved_count=relevant_retrieved,
        leaked_count=len(leaked),
        authorization_violation=bool(leaked),
        recall_at_k=_rounded(recall),
        precision_at_k=_rounded(precision),
        reciprocal_rank=_rounded(reciprocal_rank),
        overblocking=_rounded(overblocking),
        answer_contaminated=answer_contaminated,
        leaked_doc_ids=leaked,
    )


def summarize_metrics(metrics: Sequence[CaseMetrics]) -> MetricsSummary:
    if not metrics:
        raise ValueError("cannot summarize an empty metric set")
    configurations = {metric.configuration for metric in metrics}
    if len(configurations) != 1:
        raise ValueError("metrics must have one configuration")
    attacks = [metric for metric in metrics if metric.attack != "benign_control"]
    controls = [metric for metric in metrics if metric.attack == "benign_control"]
    utility = controls if controls else list(metrics)
    retrieved_hits = sum(metric.retrieved_count for metric in attacks)
    leaked_hits = sum(metric.leaked_count for metric in attacks)
    violating = [metric for metric in attacks if metric.authorization_violation]
    contaminated = sum(metric.answer_contaminated for metric in violating)

    def mean(attribute: str, values: Sequence[CaseMetrics]) -> float:
        if not values:
            return 0.0
        return sum(float(getattr(metric, attribute)) for metric in values) / len(values)

    return MetricsSummary(
        configuration=next(iter(configurations)),
        case_count=len(metrics),
        attack_case_count=len(attacks),
        retrieved_hit_count=retrieved_hits,
        leaked_hit_count=leaked_hits,
        violating_case_count=len(violating),
        leakage_rate=_rounded(leaked_hits / retrieved_hits if retrieved_hits else 0.0),
        authorization_violation_rate=_rounded(
            len(violating) / len(attacks) if attacks else 0.0
        ),
        recall_at_k=_rounded(mean("recall_at_k", utility)),
        precision_at_k=_rounded(mean("precision_at_k", utility)),
        mrr=_rounded(mean("reciprocal_rank", utility)),
        overblocking=_rounded(mean("overblocking", utility)),
        contamination_to_answer_propagation=_rounded(
            contaminated / len(violating) if violating else 0.0
        ),
    )
