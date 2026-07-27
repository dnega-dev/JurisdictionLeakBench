"""Attack taxonomy used by the generated benchmark suite."""

from __future__ import annotations

from enum import Enum
from typing import Dict, Iterable, Tuple

from .models import AttackCase


class AttackKind(str, Enum):
    BENIGN_CONTROL = "benign_control"
    TARGETED_CROSS_SCOPE_QUERY = "targeted_cross_scope_query"
    CLIENT_FILTER_TAMPERING = "client_filter_tampering"
    OR_BYPASS = "or_bypass"
    EXHAUSTIVE_ENUMERATION = "exhaustive_enumeration"
    NEAR_DUPLICATE_CONCEPT_COLLISION = "near_duplicate_concept_collision"
    GRAPH_BRIDGE_PIVOT = "graph_bridge_pivot"
    STALE_VERSION_ACCESS = "stale_version_access"


ATTACK_DESCRIPTIONS: Dict[str, str] = {
    AttackKind.TARGETED_CROSS_SCOPE_QUERY.value: "Query a unique foreign-scope marker.",
    AttackKind.CLIENT_FILTER_TAMPERING.value: "Replace client metadata with a foreign scope.",
    AttackKind.OR_BYPASS.value: "Turn filter conjunction into a permissive disjunction.",
    AttackKind.EXHAUSTIVE_ENUMERATION.value: "Use broad queries and large k to enumerate records.",
    AttackKind.NEAR_DUPLICATE_CONCEPT_COLLISION.value: "Exploit semantically overlapping scoped text.",
    AttackKind.GRAPH_BRIDGE_PIVOT.value: "Traverse an authorized citation into a forbidden record.",
    AttackKind.STALE_VERSION_ACCESS.value: "Retrieve an expired or superseded version.",
}

REQUIRED_ATTACKS = tuple(ATTACK_DESCRIPTIONS)


def present_attack_kinds(cases: Iterable[AttackCase]) -> Tuple[str, ...]:
    return tuple(sorted({case.attack for case in cases if case.is_attack}))


def missing_required_attacks(cases: Iterable[AttackCase]) -> Tuple[str, ...]:
    present = set(present_attack_kinds(cases))
    return tuple(attack for attack in REQUIRED_ATTACKS if attack not in present)
