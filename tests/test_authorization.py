from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import date

from jurisdiction_leak_bench.authorization import (
    authorization_failures,
    is_authorized,
    matches_client_filters,
)
from jurisdiction_leak_bench.corpus import generate_corpus
from jurisdiction_leak_bench.models import ClientFilters, ServerScope, honest_client_filters


class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = generate_corpus()
        cls.case = next(case for case in cls.corpus.cases if case.attack == "benign_control")
        cls.scope = cls.case.server_scope
        cls.document = next(
            document
            for document in cls.corpus.documents
            if document.doc_id in cls.case.relevant_doc_ids
        )

    def test_known_relevant_document_is_authorized(self) -> None:
        self.assertTrue(is_authorized(self.document, self.scope))
        self.assertEqual((), authorization_failures(self.document, self.scope))

    def test_wrong_tenant_is_denied(self) -> None:
        document = replace(self.document, tenant_id="tenant-foreign")
        self.assertFalse(is_authorized(document, self.scope))
        self.assertIn("tenant", authorization_failures(document, self.scope))

    def test_wrong_matter_is_denied(self) -> None:
        document = replace(self.document, matter_id="matter-foreign")
        self.assertFalse(is_authorized(document, self.scope))
        self.assertIn("matter", authorization_failures(document, self.scope))

    def test_wrong_jurisdiction_is_denied(self) -> None:
        document = replace(self.document, jurisdiction="ZZ")
        self.assertFalse(is_authorized(document, self.scope))
        self.assertIn("jurisdiction", authorization_failures(document, self.scope))

    def test_disallowed_privilege_is_denied(self) -> None:
        document = replace(self.document, privilege_class="attorney_work_product")
        scope = replace(self.scope, privilege_classes=("public", "internal"))
        self.assertFalse(is_authorized(document, scope))
        self.assertIn("privilege", authorization_failures(document, scope))

    def test_excess_authority_is_denied(self) -> None:
        document = replace(self.document, authority_level=3)
        scope = replace(self.scope, max_authority_level=2)
        self.assertFalse(is_authorized(document, scope))
        self.assertIn("authority", authorization_failures(document, scope))

    def test_future_document_is_denied(self) -> None:
        document = replace(self.document, effective_from=date(2030, 1, 1))
        self.assertFalse(is_authorized(document, self.scope))
        self.assertIn("not_yet_effective", authorization_failures(document, self.scope))

    def test_stale_document_is_denied(self) -> None:
        document = replace(self.document, effective_to=date(2024, 1, 1))
        self.assertFalse(is_authorized(document, self.scope))
        self.assertIn("stale", authorization_failures(document, self.scope))

    def test_empty_client_filters_match_everything(self) -> None:
        self.assertTrue(matches_client_filters(self.document, ClientFilters()))

    def test_client_filter_conjunction_rejects_one_wrong_field(self) -> None:
        filters = ClientFilters(
            tenant_ids=(self.document.tenant_id,),
            matter_ids=("wrong-matter",),
        )
        self.assertFalse(matches_client_filters(self.document, filters))

    def test_client_or_filter_accepts_one_matching_field(self) -> None:
        filters = ClientFilters(
            tenant_ids=(self.document.tenant_id,),
            matter_ids=("wrong-matter",),
            combine_with_or=True,
        )
        self.assertTrue(matches_client_filters(self.document, filters))

    def test_server_scope_and_client_filters_are_distinct_types(self) -> None:
        filters = honest_client_filters(self.scope)
        self.assertIsInstance(self.scope, ServerScope)
        self.assertIsInstance(filters, ClientFilters)
        self.assertNotIsInstance(filters, ServerScope)
        self.assertEqual((self.scope.tenant_id,), filters.tenant_ids)

    def test_scope_cache_key_changes_for_every_security_dimension(self) -> None:
        baseline = self.scope.cache_key()
        variants = (
            replace(self.scope, principal_id="other"),
            replace(self.scope, tenant_id="other"),
            replace(self.scope, matter_id="other"),
            replace(self.scope, jurisdiction="TX"),
            replace(self.scope, privilege_classes=("public",)),
            replace(self.scope, as_of_date=date(2026, 1, 1)),
            replace(self.scope, max_authority_level=1),
        )
        self.assertTrue(all(variant.cache_key() != baseline for variant in variants))


if __name__ == "__main__":
    unittest.main()
