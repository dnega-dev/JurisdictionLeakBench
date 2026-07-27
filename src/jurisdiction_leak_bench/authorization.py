"""Trusted authorization and untrusted client-filter evaluation."""

from __future__ import annotations

from typing import Iterable, Tuple

from .models import ClientFilters, Document, PRIVILEGE_ORDER, ServerScope


def is_authorized(document: Document, scope: ServerScope) -> bool:
    """Evaluate every security boundary against a server-enforced scope."""

    if document.tenant_id != scope.tenant_id:
        return False
    if document.matter_id != scope.matter_id:
        return False
    if document.jurisdiction != scope.jurisdiction:
        return False
    if document.privilege_class not in scope.privilege_classes:
        return False
    if document.authority_level > scope.max_authority_level:
        return False
    if document.effective_from > scope.as_of_date:
        return False
    if document.effective_to is not None and document.effective_to < scope.as_of_date:
        return False
    return True


def matches_client_filters(document: Document, filters: ClientFilters) -> bool:
    """Evaluate request filters without treating them as authorization.

    Empty filters match everything. With ``combine_with_or`` set, a match on any
    supplied field is accepted; this intentionally models the OR-bypass attack.
    Secure retrievers still separately require :func:`is_authorized`.
    """

    checks = []
    if filters.tenant_ids:
        checks.append(document.tenant_id in filters.tenant_ids)
    if filters.matter_ids:
        checks.append(document.matter_id in filters.matter_ids)
    if filters.jurisdictions:
        checks.append(document.jurisdiction in filters.jurisdictions)
    if filters.privilege_classes:
        checks.append(document.privilege_class in filters.privilege_classes)
    if filters.max_authority_level is not None:
        checks.append(document.authority_level <= filters.max_authority_level)

    if not checks:
        return True
    return any(checks) if filters.combine_with_or else all(checks)


def authorization_failures(document: Document, scope: ServerScope) -> Tuple[str, ...]:
    """Return deterministic explanations for all failed authorization dimensions."""

    failures = []
    if document.tenant_id != scope.tenant_id:
        failures.append("tenant")
    if document.matter_id != scope.matter_id:
        failures.append("matter")
    if document.jurisdiction != scope.jurisdiction:
        failures.append("jurisdiction")
    if document.privilege_class not in scope.privilege_classes:
        failures.append("privilege")
    if document.authority_level > scope.max_authority_level:
        failures.append("authority")
    if document.effective_from > scope.as_of_date:
        failures.append("not_yet_effective")
    if document.effective_to is not None and document.effective_to < scope.as_of_date:
        failures.append("stale")
    return tuple(failures)


def authorized_ids(documents: Iterable[Document], scope: ServerScope) -> Tuple[str, ...]:
    return tuple(document.doc_id for document in documents if is_authorized(document, scope))
