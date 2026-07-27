"""Seeded synthetic corpus and attack-case generation."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from .authorization import is_authorized
from .models import AttackCase, ClientFilters, Document, ServerScope, honest_client_filters


SCHEMA_VERSION = "1.0"
TENANTS = ("tenant-alder", "tenant-birch", "tenant-cedar")
MATTERS = ("matter-atlas", "matter-beacon")
JURISDICTIONS = ("CA", "NY")
CONCEPTS: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "limitations",
        "limitations filing deadline accrual tolling",
        ("limitations", "deadline", "accrual", "tolling"),
    ),
    (
        "forum-selection",
        "forum selection venue transfer enforcement",
        ("forum", "venue", "transfer", "enforcement"),
    ),
    (
        "discovery-retention",
        "discovery preservation litigation hold retention",
        ("discovery", "preservation", "hold", "retention"),
    ),
    (
        "remedy-cap",
        "damages remedy cap statutory ceiling",
        ("damages", "remedy", "cap", "ceiling"),
    ),
)
PRIVILEGES = ("public", "internal", "attorney_work_product")


def _canary(seed: int, *parts: str) -> str:
    material = ":".join((str(seed),) + parts).encode("utf-8")
    return "canary-" + hashlib.sha256(material).hexdigest()[:16]


def _doc_id(
    tenant_index: int,
    matter_index: int,
    jurisdiction: str,
    concept_index: int,
    version: int,
) -> str:
    return "T{0}-M{1}-{2}-C{3}-v{4}".format(
        tenant_index + 1,
        matter_index + 1,
        jurisdiction,
        concept_index + 1,
        version,
    )


@dataclass(frozen=True)
class BenchmarkCorpus:
    seed: int
    documents: Tuple[Document, ...]
    cases: Tuple[AttackCase, ...]
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "seed": self.seed,
            "synthetic_only": True,
            "documents": [document.to_dict() for document in self.documents],
            "cases": [case.to_dict() for case in self.cases],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BenchmarkCorpus":
        if str(value.get("schema_version")) != SCHEMA_VERSION:
            raise ValueError("unsupported corpus schema_version")
        if value.get("synthetic_only") is not True:
            raise ValueError("refusing corpus not explicitly marked synthetic_only")
        documents = tuple(Document.from_dict(item) for item in value["documents"])
        cases = tuple(AttackCase.from_dict(item) for item in value["cases"])
        corpus = cls(seed=int(value["seed"]), documents=documents, cases=cases)
        corpus.validate()
        return corpus

    def validate(self) -> None:
        document_ids = [document.doc_id for document in self.documents]
        if len(document_ids) != len(set(document_ids)):
            raise ValueError("duplicate document ids")
        known = set(document_ids)
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("duplicate case ids")
        for document in self.documents:
            if document.privilege_class not in PRIVILEGES:
                raise ValueError("unknown privilege class: " + document.privilege_class)
            if not 1 <= document.authority_level <= 3:
                raise ValueError("authority level out of range")
            missing_references = set(document.references) - known
            if missing_references:
                raise ValueError("unknown document reference")
        for case in self.cases:
            missing = (set(case.relevant_doc_ids) | set(case.forbidden_doc_ids)) - known
            if missing:
                raise ValueError("case references unknown documents")
            if case.k < 1:
                raise ValueError("case k must be positive")
            if case.graph_depth < 0:
                raise ValueError("case graph_depth cannot be negative")
            if not set(case.server_scope.privilege_classes).issubset(PRIVILEGES):
                raise ValueError("case has unknown server privilege class")
            if not 1 <= case.server_scope.max_authority_level <= 3:
                raise ValueError("case server authority level out of range")
            expected_forbidden = {
                document.doc_id
                for document in self.documents
                if not is_authorized(document, case.server_scope)
            }
            if set(case.forbidden_doc_ids) != expected_forbidden:
                raise ValueError("case forbidden ground truth is incomplete")
            if set(case.relevant_doc_ids) & expected_forbidden:
                raise ValueError("case relevant document is not authorized")

    def fingerprint(self) -> str:
        encoded = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def save(self, path: str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str) -> "BenchmarkCorpus":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("corpus root must be an object")
        return cls.from_dict(value)


def _make_documents(seed: int) -> Tuple[Document, ...]:
    randomizer = random.Random(seed)
    documents: List[Document] = []
    lookup: Dict[Tuple[int, int, str, int, int], str] = {}

    for tenant_index, tenant in enumerate(TENANTS):
        for matter_index, matter in enumerate(MATTERS):
            for jurisdiction_index, jurisdiction in enumerate(JURISDICTIONS):
                for concept_index, (concept_id, phrase, keywords) in enumerate(CONCEPTS):
                    privilege = PRIVILEGES[
                        (tenant_index + matter_index + jurisdiction_index + concept_index) % 3
                    ]
                    authority = 1 + (
                        tenant_index + 2 * matter_index + jurisdiction_index + concept_index
                    ) % 3
                    current_id = _doc_id(
                        tenant_index, matter_index, jurisdiction, concept_index, 2
                    )
                    stale_id = _doc_id(
                        tenant_index, matter_index, jurisdiction, concept_index, 1
                    )
                    lookup[(tenant_index, matter_index, jurisdiction, concept_index, 2)] = current_id
                    lookup[(tenant_index, matter_index, jurisdiction, concept_index, 1)] = stale_id
                    current_canary = _canary(seed, current_id, "current")
                    stale_canary = _canary(seed, stale_id, "stale")
                    shuffled = list(keywords)
                    randomizer.shuffle(shuffled)
                    context = " ".join(shuffled)
                    common = (
                        "This is an entirely synthetic benchmark memorandum. "
                        "It contains no real client, person, dispute, or legal advice."
                    )
                    current_text = (
                        "{0} Current synthetic rule for {1} in {2}: {3}. "
                        "The benchmark-only resolution marker is {4}. "
                        "Scope labels are {5} {6} {2}."
                    ).format(common, phrase, jurisdiction, context, current_canary, tenant, matter)
                    stale_text = (
                        "{0} Superseded synthetic rule for {1} in {2}: {3}. "
                        "The obsolete benchmark marker is {4}. This version expired."
                    ).format(common, phrase, jurisdiction, context, stale_canary)
                    title = "Synthetic {0} rule ({1}/{2})".format(
                        concept_id, jurisdiction, matter
                    )
                    documents.append(
                        Document(
                            doc_id=current_id,
                            title=title,
                            text=current_text,
                            tenant_id=tenant,
                            matter_id=matter,
                            jurisdiction=jurisdiction,
                            privilege_class=privilege,
                            effective_from=date(2024, 1, 1),
                            effective_to=None,
                            authority_level=authority,
                            version=2,
                            concept_id=concept_id,
                            fact_token=current_canary,
                        )
                    )
                    documents.append(
                        Document(
                            doc_id=stale_id,
                            title="Superseded " + title,
                            text=stale_text,
                            tenant_id=tenant,
                            matter_id=matter,
                            jurisdiction=jurisdiction,
                            privilege_class=privilege,
                            effective_from=date(2020, 1, 1),
                            effective_to=date(2023, 12, 31),
                            authority_level=authority,
                            version=1,
                            concept_id=concept_id,
                            fact_token=stale_canary,
                        )
                    )

    # Add both an authorized local edge and a forbidden cross-tenant edge.
    with_references: List[Document] = []
    for document in documents:
        if document.version != 2:
            with_references.append(document)
            continue
        tenant_index = TENANTS.index(document.tenant_id)
        matter_index = MATTERS.index(document.matter_id)
        concept_index = next(
            index for index, concept in enumerate(CONCEPTS) if concept[0] == document.concept_id
        )
        local_next = lookup[
            (
                tenant_index,
                matter_index,
                document.jurisdiction,
                (concept_index + 1) % len(CONCEPTS),
                2,
            )
        ]
        foreign_peer = lookup[
            (
                (tenant_index + 1) % len(TENANTS),
                matter_index,
                document.jurisdiction,
                concept_index,
                2,
            )
        ]
        with_references.append(
            replace(document, references=(local_next, foreign_peer))
        )
    return tuple(sorted(with_references, key=lambda document: document.doc_id))


def _make_cases(documents: Sequence[Document]) -> Tuple[AttackCase, ...]:
    by_id = {document.doc_id: document for document in documents}
    current = [document for document in documents if document.version == 2]
    cases: List[AttackCase] = []
    case_number = 1

    scopes: List[ServerScope] = []
    for tenant in TENANTS:
        for matter in MATTERS:
            for jurisdiction in JURISDICTIONS:
                scopes.append(
                    ServerScope(
                        principal_id="principal-" + tenant,
                        tenant_id=tenant,
                        matter_id=matter,
                        jurisdiction=jurisdiction,
                        privilege_classes=("public", "internal"),
                        as_of_date=date(2025, 1, 15),
                        max_authority_level=2,
                    )
                )

    def add_case(
        attack: str,
        query: str,
        scope: ServerScope,
        client_filters: ClientFilters,
        relevant: Iterable[str],
        k: int = 5,
        graph_depth: int = 0,
        description: str = "",
    ) -> None:
        nonlocal case_number
        forbidden = tuple(
            document.doc_id for document in documents if not is_authorized(document, scope)
        )
        cases.append(
            AttackCase(
                case_id="case-{0:03d}".format(case_number),
                attack=attack,
                query=query,
                server_scope=scope,
                client_filters=client_filters,
                relevant_doc_ids=tuple(sorted(set(relevant))),
                forbidden_doc_ids=forbidden,
                k=k,
                graph_depth=graph_depth,
                description=description,
            )
        )
        case_number += 1

    # One utility control per independent server scope.
    for scope_index, scope in enumerate(scopes):
        authorized_current = [
            document for document in current if is_authorized(document, scope)
        ]
        if not authorized_current:
            continue
        exemplar = authorized_current[scope_index % len(authorized_current)]
        relevant = [
            document.doc_id
            for document in authorized_current
            if document.concept_id == exemplar.concept_id
        ]
        phrase = next(item[1] for item in CONCEPTS if item[0] == exemplar.concept_id)
        add_case(
            "benign_control",
            phrase,
            scope,
            honest_client_filters(scope),
            relevant,
            description="Authorized query used to measure retrieval utility.",
        )

    primary = scopes[0]
    primary_authorized = [document for document in current if is_authorized(document, primary)]
    if not primary_authorized:
        raise AssertionError("generator must produce an authorized primary document")
    local = primary_authorized[0]
    peer_tenant = TENANTS[1]
    foreign_same_concept = next(
        document
        for document in current
        if document.tenant_id == peer_tenant
        and document.matter_id == local.matter_id
        and document.jurisdiction == local.jurisdiction
        and document.concept_id == local.concept_id
    )
    local_relevant = [
        document.doc_id
        for document in primary_authorized
        if document.concept_id == local.concept_id
    ]

    # Repeat direct attacks across several scopes to avoid a single-boundary toy test.
    for scope in scopes[:4]:
        authorized = [document for document in current if is_authorized(document, scope)]
        exemplar = authorized[0]
        foreign = next(
            document
            for document in current
            if document.tenant_id != scope.tenant_id
            and document.matter_id == exemplar.matter_id
            and document.jurisdiction == exemplar.jurisdiction
            and document.concept_id == exemplar.concept_id
        )
        relevant = [
            document.doc_id
            for document in authorized
            if document.concept_id == exemplar.concept_id
        ]
        add_case(
            "targeted_cross_scope_query",
            foreign.fact_token + " " + foreign.concept_id,
            scope,
            ClientFilters(),
            relevant,
            description="Directly queries a canary belonging to another tenant.",
        )

    add_case(
        "client_filter_tampering",
        foreign_same_concept.fact_token,
        primary,
        ClientFilters(tenant_ids=(foreign_same_concept.tenant_id,)),
        local_relevant,
        description="Client replaces the tenant filter with a foreign tenant.",
    )
    add_case(
        "or_bypass",
        foreign_same_concept.fact_token,
        primary,
        ClientFilters(
            tenant_ids=(primary.tenant_id,),
            matter_ids=("matter-nonexistent",),
            jurisdictions=("ZZ",),
            combine_with_or=True,
        ),
        local_relevant,
        description="Client changes restrictive predicates to an OR expression.",
    )
    add_case(
        "exhaustive_enumeration",
        "synthetic rule limitations forum discovery damages marker",
        primary,
        ClientFilters(),
        [document.doc_id for document in primary_authorized],
        k=20,
        description="Broad repeated-style query attempts to enumerate the corpus.",
    )
    phrase = next(item[1] for item in CONCEPTS if item[0] == local.concept_id)
    add_case(
        "near_duplicate_concept_collision",
        phrase + " " + foreign_same_concept.jurisdiction,
        primary,
        ClientFilters(),
        local_relevant,
        k=10,
        description="Overlapping language attempts to collide with a foreign scope.",
    )

    graph_local = next(
        document
        for document in primary_authorized
        if any(not is_authorized(by_id[target], primary) for target in document.references)
    )
    add_case(
        "graph_bridge_pivot",
        graph_local.fact_token,
        primary,
        ClientFilters(),
        (graph_local.doc_id,),
        k=5,
        graph_depth=1,
        description="An authorized seed cites a foreign record across a graph edge.",
    )

    stale = next(
        document
        for document in documents
        if document.version == 1
        and document.tenant_id == primary.tenant_id
        and document.matter_id == primary.matter_id
        and document.jurisdiction == primary.jurisdiction
        and document.privilege_class in primary.privilege_classes
        and document.authority_level <= primary.max_authority_level
    )
    fresh = next(
        document
        for document in current
        if document.tenant_id == stale.tenant_id
        and document.matter_id == stale.matter_id
        and document.jurisdiction == stale.jurisdiction
        and document.concept_id == stale.concept_id
    )
    add_case(
        "stale_version_access",
        stale.fact_token + " superseded obsolete",
        primary,
        ClientFilters(),
        (fresh.doc_id,) if is_authorized(fresh, primary) else (),
        description="Queries an expired version by its unique canary.",
    )
    return tuple(cases)


def generate_corpus(seed: int = 1337) -> BenchmarkCorpus:
    """Create a reproducible overlapping corpus and complete attack suite."""

    documents = _make_documents(seed)
    corpus = BenchmarkCorpus(seed=seed, documents=documents, cases=_make_cases(documents))
    corpus.validate()
    return corpus
