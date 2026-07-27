from __future__ import annotations

import unittest

from jurisdiction_leak_bench.attacks import REQUIRED_ATTACKS
from jurisdiction_leak_bench.authorization import authorization_failures
from jurisdiction_leak_bench.corpus import generate_corpus
from jurisdiction_leak_bench.retrieval import CONFIGURATION_NAMES, make_retriever
from jurisdiction_leak_bench.runner import run_benchmark


class EndToEndSecurityBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = generate_corpus(1337)
        cls.by_id = {document.doc_id: document for document in cls.corpus.documents}

    def cases_for(self, attack: str):
        return [case for case in self.corpus.cases if case.attack == attack]

    def test_every_attack_kind_exercises_ungated_baseline(self) -> None:
        retriever = make_retriever("ungated", self.corpus.documents)
        for attack in REQUIRED_ATTACKS:
            cases = self.cases_for(attack)
            self.assertTrue(cases, attack)
            self.assertTrue(
                any(
                    set(case.forbidden_doc_ids)
                    & {hit.doc_id for hit in retriever.retrieve(case).hits}
                    for case in cases
                ),
                attack,
            )

    def test_every_secure_configuration_resists_every_attack_case(self) -> None:
        attacks = [case for case in self.corpus.cases if case.is_attack]
        for configuration in CONFIGURATION_NAMES[1:]:
            retriever = make_retriever(configuration, self.corpus.documents)
            for case in attacks:
                result = retriever.retrieve(case)
                self.assertFalse(
                    set(case.forbidden_doc_ids) & {hit.doc_id for hit in result.hits},
                    configuration + "/" + case.case_id,
                )

    def test_forbidden_ground_truth_spans_all_policy_dimensions(self) -> None:
        dimensions = set()
        for case in self.corpus.cases:
            for document_id in case.forbidden_doc_ids:
                dimensions.update(
                    authorization_failures(self.by_id[document_id], case.server_scope)
                )
        self.assertTrue(
            {
                "tenant",
                "matter",
                "jurisdiction",
                "privilege",
                "authority",
                "stale",
            }.issubset(dimensions)
        )

    def test_client_tampering_case_supplies_foreign_tenant(self) -> None:
        case = self.cases_for("client_filter_tampering")[0]
        self.assertNotIn(case.server_scope.tenant_id, case.client_filters.tenant_ids)
        self.assertTrue(case.client_filters.tenant_ids)

    def test_or_bypass_case_is_explicitly_disjunctive(self) -> None:
        case = self.cases_for("or_bypass")[0]
        self.assertTrue(case.client_filters.combine_with_or)
        self.assertGreaterEqual(
            len(case.client_filters.tenant_ids)
            + len(case.client_filters.matter_ids)
            + len(case.client_filters.jurisdictions),
            3,
        )

    def test_exhaustive_enumeration_uses_large_k(self) -> None:
        case = self.cases_for("exhaustive_enumeration")[0]
        self.assertGreaterEqual(case.k, 20)
        self.assertGreater(len(case.relevant_doc_ids), 1)

    def test_near_duplicate_query_uses_shared_concept_language(self) -> None:
        case = self.cases_for("near_duplicate_concept_collision")[0]
        self.assertNotIn("canary-", case.query)
        self.assertTrue(any(word in case.query for word in ("limitations", "forum", "discovery", "damages")))

    def test_graph_attack_requests_expansion(self) -> None:
        case = self.cases_for("graph_bridge_pivot")[0]
        self.assertGreaterEqual(case.graph_depth, 1)
        self.assertTrue(any(self.by_id[item].references for item in case.relevant_doc_ids))

    def test_stale_attack_queries_expired_canary(self) -> None:
        case = self.cases_for("stale_version_access")[0]
        stale_canaries = {
            document.fact_token
            for document in self.corpus.documents
            if document.effective_to is not None
        }
        self.assertTrue(any(canary in case.query for canary in stale_canaries))

    def test_seeded_benchmark_has_expected_security_shape(self) -> None:
        run = run_benchmark(self.corpus)
        ungated = run.summary_for("ungated")
        self.assertEqual(1.0, ungated.authorization_violation_rate)
        for configuration in CONFIGURATION_NAMES[1:]:
            summary = run.summary_for(configuration)
            self.assertEqual(0.0, summary.authorization_violation_rate)
            self.assertEqual(0.0, summary.leakage_rate)


if __name__ == "__main__":
    unittest.main()
