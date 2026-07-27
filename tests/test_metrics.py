from __future__ import annotations

import unittest
from dataclasses import replace

from jurisdiction_leak_bench.corpus import generate_corpus
from jurisdiction_leak_bench.metrics import evaluate_case, summarize_metrics
from jurisdiction_leak_bench.models import RetrievalResult
from jurisdiction_leak_bench.retrieval import make_retriever
from jurisdiction_leak_bench.runner import run_benchmark


class MetricsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = generate_corpus()
        cls.documents = {document.doc_id: document for document in cls.corpus.documents}
        cls.benchmark_run = run_benchmark(cls.corpus)

    def case_for(self, attack: str):
        return next(case for case in self.corpus.cases if case.attack == attack)

    def test_ungated_targeted_case_records_leak(self) -> None:
        case = self.case_for("targeted_cross_scope_query")
        result = make_retriever("ungated", self.corpus.documents).retrieve(case)
        metric = evaluate_case(case, result, self.documents)
        self.assertTrue(metric.authorization_violation)
        self.assertGreater(metric.leaked_count, 0)

    def test_secure_targeted_case_has_zero_leak(self) -> None:
        case = self.case_for("targeted_cross_scope_query")
        result = make_retriever("pre_filtered_partition", self.corpus.documents).retrieve(case)
        metric = evaluate_case(case, result, self.documents)
        self.assertFalse(metric.authorization_violation)
        self.assertEqual(0, metric.leaked_count)

    def test_forbidden_canary_propagates_to_ungated_answer(self) -> None:
        case = self.case_for("targeted_cross_scope_query")
        result = make_retriever("ungated", self.corpus.documents).retrieve(case)
        metric = evaluate_case(case, result, self.documents)
        self.assertTrue(metric.answer_contaminated)

    def test_all_secure_summaries_have_zero_security_rates(self) -> None:
        for summary in self.benchmark_run.summaries[1:]:
            self.assertEqual(0.0, summary.leakage_rate)
            self.assertEqual(0.0, summary.authorization_violation_rate)

    def test_ungated_summary_proves_attack_signal(self) -> None:
        summary = self.benchmark_run.summary_for("ungated")
        self.assertGreater(summary.leakage_rate, 0.0)
        self.assertGreater(summary.authorization_violation_rate, 0.0)

    def test_pre_filter_has_perfect_control_recall(self) -> None:
        summary = self.benchmark_run.summary_for("pre_filtered_partition")
        self.assertEqual(1.0, summary.recall_at_k)
        self.assertEqual(0.0, summary.overblocking)

    def test_post_filter_overblocks_more_than_pre_filter(self) -> None:
        post = self.benchmark_run.summary_for("post_retrieval_gating")
        pre = self.benchmark_run.summary_for("pre_filtered_partition")
        self.assertGreater(post.overblocking, pre.overblocking)
        self.assertLess(post.recall_at_k, pre.recall_at_k)

    def test_precision_at_k_counts_unfilled_slots(self) -> None:
        case = self.case_for("benign_control")
        result = make_retriever("pre_filtered_partition", self.corpus.documents).retrieve(case)
        metric = evaluate_case(case, result, self.documents)
        self.assertEqual(
            round(metric.relevant_retrieved_count / case.k, 6), metric.precision_at_k
        )

    def test_metrics_are_bounded(self) -> None:
        names = (
            "leakage_rate",
            "authorization_violation_rate",
            "recall_at_k",
            "precision_at_k",
            "mrr",
            "overblocking",
            "contamination_to_answer_propagation",
        )
        for summary in self.benchmark_run.summaries:
            for name in names:
                self.assertGreaterEqual(getattr(summary, name), 0.0)
                self.assertLessEqual(getattr(summary, name), 1.0)

    def test_case_and_result_ids_must_match(self) -> None:
        case = self.case_for("benign_control")
        result = make_retriever("pre_filtered_partition", self.corpus.documents).retrieve(case)
        wrong = replace(result, case_id="wrong")
        with self.assertRaisesRegex(ValueError, "does not belong"):
            evaluate_case(case, wrong, self.documents)

    def test_evaluator_rejects_inconsistent_forbidden_ground_truth(self) -> None:
        case = self.case_for("targeted_cross_scope_query")
        result = make_retriever("ungated", self.corpus.documents).retrieve(case)
        malformed = replace(case, forbidden_doc_ids=())
        with self.assertRaisesRegex(ValueError, "disagrees"):
            evaluate_case(malformed, result, self.documents)

    def test_empty_summary_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty"):
            summarize_metrics(())

    def test_mixed_configuration_summary_is_rejected(self) -> None:
        metrics = self.benchmark_run.case_metrics
        first = next(metric for metric in metrics if metric.configuration == "ungated")
        second = next(
            metric for metric in metrics if metric.configuration == "pre_filtered_partition"
        )
        with self.assertRaisesRegex(ValueError, "one configuration"):
            summarize_metrics((first, second))

    def test_ungated_answer_propagation_is_nonzero(self) -> None:
        summary = self.benchmark_run.summary_for("ungated")
        self.assertGreater(summary.contamination_to_answer_propagation, 0.0)


if __name__ == "__main__":
    unittest.main()
