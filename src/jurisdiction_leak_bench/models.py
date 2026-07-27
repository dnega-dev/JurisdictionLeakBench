"""Core immutable data models for JurisdictionLeakBench."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


PRIVILEGE_ORDER = {
    "public": 0,
    "internal": 1,
    "attorney_work_product": 2,
}

AUTHORITY_LABELS = {
    1: "persuasive",
    2: "controlling",
    3: "supreme",
}


@dataclass(frozen=True)
class Document:
    """A synthetic record with all authorization-relevant metadata."""

    doc_id: str
    title: str
    text: str
    tenant_id: str
    matter_id: str
    jurisdiction: str
    privilege_class: str
    effective_from: date
    effective_to: Optional[date]
    authority_level: int
    version: int
    concept_id: str
    fact_token: str
    references: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "text": self.text,
            "tenant_id": self.tenant_id,
            "matter_id": self.matter_id,
            "jurisdiction": self.jurisdiction,
            "privilege_class": self.privilege_class,
            "effective_from": self.effective_from.isoformat(),
            "effective_to": self.effective_to.isoformat() if self.effective_to else None,
            "authority_level": self.authority_level,
            "version": self.version,
            "concept_id": self.concept_id,
            "fact_token": self.fact_token,
            "references": list(self.references),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Document":
        return cls(
            doc_id=str(value["doc_id"]),
            title=str(value["title"]),
            text=str(value["text"]),
            tenant_id=str(value["tenant_id"]),
            matter_id=str(value["matter_id"]),
            jurisdiction=str(value["jurisdiction"]),
            privilege_class=str(value["privilege_class"]),
            effective_from=date.fromisoformat(str(value["effective_from"])),
            effective_to=(
                date.fromisoformat(str(value["effective_to"]))
                if value.get("effective_to")
                else None
            ),
            authority_level=int(value["authority_level"]),
            version=int(value["version"]),
            concept_id=str(value["concept_id"]),
            fact_token=str(value["fact_token"]),
            references=tuple(str(item) for item in value.get("references", ())),
        )


@dataclass(frozen=True)
class ServerScope:
    """Trusted, server-derived authorization scope.

    This object is deliberately separate from :class:`ClientFilters`. Callers
    must never construct a ServerScope from request filters without an
    independent authentication/authorization step.
    """

    tenant_id: str
    matter_id: str
    jurisdiction: str
    privilege_classes: Tuple[str, ...]
    as_of_date: date
    max_authority_level: int
    principal_id: str = "benchmark-principal"

    def cache_key(self) -> Tuple[Any, ...]:
        return (
            self.principal_id,
            self.tenant_id,
            self.matter_id,
            self.jurisdiction,
            tuple(sorted(self.privilege_classes)),
            self.as_of_date.isoformat(),
            self.max_authority_level,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "matter_id": self.matter_id,
            "jurisdiction": self.jurisdiction,
            "privilege_classes": list(self.privilege_classes),
            "as_of_date": self.as_of_date.isoformat(),
            "max_authority_level": self.max_authority_level,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ServerScope":
        return cls(
            principal_id=str(value.get("principal_id", "benchmark-principal")),
            tenant_id=str(value["tenant_id"]),
            matter_id=str(value["matter_id"]),
            jurisdiction=str(value["jurisdiction"]),
            privilege_classes=tuple(str(item) for item in value["privilege_classes"]),
            as_of_date=date.fromisoformat(str(value["as_of_date"])),
            max_authority_level=int(value["max_authority_level"]),
        )


@dataclass(frozen=True)
class ClientFilters:
    """Untrusted request metadata filters.

    ``combine_with_or`` intentionally models a common client-controlled OR
    bypass. Secure retrievers still intersect these values with ServerScope.
    """

    tenant_ids: Tuple[str, ...] = field(default_factory=tuple)
    matter_ids: Tuple[str, ...] = field(default_factory=tuple)
    jurisdictions: Tuple[str, ...] = field(default_factory=tuple)
    privilege_classes: Tuple[str, ...] = field(default_factory=tuple)
    max_authority_level: Optional[int] = None
    combine_with_or: bool = False

    def is_empty(self) -> bool:
        return not any(
            (
                self.tenant_ids,
                self.matter_ids,
                self.jurisdictions,
                self.privilege_classes,
                self.max_authority_level is not None,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_ids": list(self.tenant_ids),
            "matter_ids": list(self.matter_ids),
            "jurisdictions": list(self.jurisdictions),
            "privilege_classes": list(self.privilege_classes),
            "max_authority_level": self.max_authority_level,
            "combine_with_or": self.combine_with_or,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ClientFilters":
        return cls(
            tenant_ids=tuple(str(item) for item in value.get("tenant_ids", ())),
            matter_ids=tuple(str(item) for item in value.get("matter_ids", ())),
            jurisdictions=tuple(str(item) for item in value.get("jurisdictions", ())),
            privilege_classes=tuple(
                str(item) for item in value.get("privilege_classes", ())
            ),
            max_authority_level=(
                int(value["max_authority_level"])
                if value.get("max_authority_level") is not None
                else None
            ),
            combine_with_or=bool(value.get("combine_with_or", False)),
        )


@dataclass(frozen=True)
class AttackCase:
    """A benchmark query and its security/utility ground truth."""

    case_id: str
    attack: str
    query: str
    server_scope: ServerScope
    client_filters: ClientFilters
    relevant_doc_ids: Tuple[str, ...]
    forbidden_doc_ids: Tuple[str, ...]
    k: int = 5
    graph_depth: int = 0
    description: str = ""

    @property
    def is_attack(self) -> bool:
        return self.attack != "benign_control"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "attack": self.attack,
            "query": self.query,
            "server_scope": self.server_scope.to_dict(),
            "client_filters": self.client_filters.to_dict(),
            "relevant_doc_ids": list(self.relevant_doc_ids),
            "forbidden_doc_ids": list(self.forbidden_doc_ids),
            "k": self.k,
            "graph_depth": self.graph_depth,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttackCase":
        return cls(
            case_id=str(value["case_id"]),
            attack=str(value["attack"]),
            query=str(value["query"]),
            server_scope=ServerScope.from_dict(value["server_scope"]),
            client_filters=ClientFilters.from_dict(value["client_filters"]),
            relevant_doc_ids=tuple(
                str(item) for item in value.get("relevant_doc_ids", ())
            ),
            forbidden_doc_ids=tuple(
                str(item) for item in value.get("forbidden_doc_ids", ())
            ),
            k=int(value.get("k", 5)),
            graph_depth=int(value.get("graph_depth", 0)),
            description=str(value.get("description", "")),
        )


@dataclass(frozen=True)
class RetrievalHit:
    doc_id: str
    score: float
    source: str = "vector"

    def to_dict(self) -> Dict[str, Any]:
        return {"doc_id": self.doc_id, "score": self.score, "source": self.source}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RetrievalHit":
        return cls(
            doc_id=str(value["doc_id"]),
            score=float(value["score"]),
            source=str(value.get("source", "vector")),
        )


@dataclass(frozen=True)
class RetrievalResult:
    case_id: str
    configuration: str
    hits: Tuple[RetrievalHit, ...]
    answer: str
    scored_count: int
    candidate_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "configuration": self.configuration,
            "hits": [hit.to_dict() for hit in self.hits],
            "answer": self.answer,
            "scored_count": self.scored_count,
            "candidate_count": self.candidate_count,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RetrievalResult":
        return cls(
            case_id=str(value["case_id"]),
            configuration=str(value["configuration"]),
            hits=tuple(RetrievalHit.from_dict(item) for item in value["hits"]),
            answer=str(value["answer"]),
            scored_count=int(value["scored_count"]),
            candidate_count=int(value["candidate_count"]),
        )


def honest_client_filters(scope: ServerScope) -> ClientFilters:
    """Return request filters matching a trusted scope without conflating them."""

    return ClientFilters(
        tenant_ids=(scope.tenant_id,),
        matter_ids=(scope.matter_id,),
        jurisdictions=(scope.jurisdiction,),
        privilege_classes=scope.privilege_classes,
        max_authority_level=scope.max_authority_level,
    )
