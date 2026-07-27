from __future__ import annotations

import unittest
from dataclasses import replace

from jurisdiction_leak_bench.authorization import is_authorized
from jurisdiction_leak_bench.corpus import generate_corpus
from jurisdiction_leak_bench.retrieval import (
    CONFIGURATION_NAMES,
    PerScopeIndexRetriever,
    make_retriever,
)


class RetrievalConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = generate_corpus()
        cls.documents = {document.doc_id: document for document in cls.corpus.documents}

    def case_for(self, attack: str):
        return next(case for case in self.corpus.cases if case.attack == attack)

    def test_all_four_configurations_are_registered(self) -> None:
        self.assertEqual(
            (
                "ungated",
                "post_retrieval_gating",
                "pre_filtered_partition",
                "per_scope_index",
            ),
            CONFIGURATION_NAMES,
        )

    def test_unknown_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown configuration"):
            make_retriever("missing", self.corpus.documents)

    def test_ungated_targeted_query_returns_forbidden_record(self) -> None:
        case = self.case_for("targeted_cross_scope_query")
        result = make_retriever("ungated", self.corpus.documents).retrieve(case)
        forbidden = set(case.forbidden_doc_ids)
        self.assertTrue(any(hit.doc_id in forbidden for hit in result.hits))

    def test_post_retrieval_gating_never_returns_unauthorized_record(self) -> None:
        retriever = make_retriever("post_retrieval_gating", self.corpus.documents)
        for case in self.corpus.cases:
            result = retriever.retrieve(case)
            self.assertTrue(
                all(is_authorized(self.documents[hit.doc_id], case.server_scope) for hit in result.hits),
                case.case_id,
            )

    def test_pre_filtered_partition_never_returns_unauthorized_record(self) -> None:
        retriever = make_retriever("pre_filtered_partition", self.corpus.documents)
        for case in self.corpus.cases:
            result = retriever.retrieve(case)
            self.assertTrue(
                all(is_authorized(self.documents[hit.doc_id], case.server_scope) for hit in result.hits),
                case.case_id,
            )

    def test_per_scope_index_never_returns_unauthorized_record(self) -> None:
        retriever = make_retriever("per_scope_index", self.corpus.documents)
        for case in self.corpus.cases:
            result = retriever.retrieve(case)
            self.assertTrue(
                all(is_authorized(self.documents[hit.doc_id], case.server_scope) for hit in result.hits),
                case.case_id,
            )

    def test_post_gating_scores_global_corpus(self) -> None:
        case = self.case_for("targeted_cross_scope_query")
        result = make_retriever("post_retrieval_gating", self.corpus.documents).retrieve(case)
        self.assertEqual(len(self.corpus.documents), result.scored_count)
        self.assertEqual(len(self.corpus.documents), result.candidate_count)

    def test_pre_filter_scores_strict_subset(self) -> None:
        case = self.case_for("benign_control")
        result = make_retriever("pre_filtered_partition", self.corpus.documents).retrieve(case)
        self.assertGreater(result.scored_count, 0)
        self.assertLess(result.scored_count, len(self.corpus.documents))
        self.assertEqual(result.scored_count, result.candidate_count)

    def test_per_scope_index_is_cached_by_trusted_scope(self) -> None:
        case = self.case_for("benign_control")
        retriever = PerScopeIndexRetriever(self.corpus.documents)
        first = retriever.scope_index(case.server_scope)
        second = retriever.scope_index(case.server_scope)
        self.assertIs(first, second)
        self.assertEqual(1, retriever.index_count)
        retriever.scope_index(replace(case.server_scope, max_authority_level=1))
        self.assertEqual(2, retriever.index_count)

    def test_client_filter_tampering_cannot_expand_pre_filtered_scope(self) -> None:
        case = self.case_for("client_filter_tampering")
        result = make_retriever("pre_filtered_partition", self.corpus.documents).retrieve(case)
        self.assertEqual((), result.hits)

    def test_graph_bridge_leaks_in_ungated_configuration(self) -> None:
        case = self.case_for("graph_bridge_pivot")
        result = make_retriever("ungated", self.corpus.documents).retrieve(case)
        graph_hits = [hit for hit in result.hits if hit.source == "graph"]
        self.assertTrue(graph_hits)
        self.assertTrue(
            any(hit.doc_id in set(case.forbidden_doc_ids) for hit in graph_hits)
        )

    def test_graph_bridge_is_gated_in_secure_configurations(self) -> None:
        case = self.case_for("graph_bridge_pivot")
        for configuration in CONFIGURATION_NAMES[1:]:
            result = make_retriever(configuration, self.corpus.documents).retrieve(case)
            self.assertFalse(
                set(case.forbidden_doc_ids) & {hit.doc_id for hit in result.hits},
                configuration,
            )

    def test_stale_version_is_blocked_by_secure_configurations(self) -> None:
        case = self.case_for("stale_version_access")
        stale_ids = {
            document.doc_id
            for document in self.corpus.documents
            if document.version == 1
        }
        for configuration in CONFIGURATION_NAMES[1:]:
            result = make_retriever(configuration, self.corpus.documents).retrieve(case)
            self.assertFalse(stale_ids & {hit.doc_id for hit in result.hits})

    def test_ungated_stale_query_retrieves_stale_record(self) -> None:
        case = self.case_for("stale_version_access")
        result = make_retriever("ungated", self.corpus.documents).retrieve(case)
        self.assertTrue(
            any(self.documents[hit.doc_id].version == 1 for hit in result.hits)
        )

    def test_answer_is_derived_from_retrieved_canaries(self) -> None:
        case = self.case_for("benign_control")
        result = make_retriever("pre_filtered_partition", self.corpus.documents).retrieve(case)
        for hit in result.hits:
            self.assertIn(self.documents[hit.doc_id].fact_token, result.answer)

    def test_pre_filter_and_per_scope_return_same_control_hits(self) -> None:
        case = self.case_for("benign_control")
        pre = make_retriever("pre_filtered_partition", self.corpus.documents).retrieve(case)
        per_scope = make_retriever("per_scope_index", self.corpus.documents).retrieve(case)
        self.assertEqual(
            [hit.doc_id for hit in pre.hits], [hit.doc_id for hit in per_scope.hits]
        )


if __name__ == "__main__":
    unittest.main()
