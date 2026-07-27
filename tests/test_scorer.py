from __future__ import annotations

import unittest
from dataclasses import replace

from jurisdiction_leak_bench.corpus import generate_corpus
from jurisdiction_leak_bench.scorer import DeterministicVectorScorer, tokenize


class DeterministicScorerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = generate_corpus()
        cls.scorer = DeterministicVectorScorer()

    def test_tokenization_is_case_insensitive(self) -> None:
        self.assertEqual(tokenize("Forum Selection"), tokenize("FORUM selection"))

    def test_tokenization_adds_trigram_features(self) -> None:
        features = tokenize("limitations")
        self.assertIn("limitations", features)
        self.assertTrue(any(feature.startswith("tri:") for feature in features))

    def test_vector_has_requested_dimensions(self) -> None:
        vector = self.scorer.vectorize("filing deadline and tolling")
        self.assertEqual(96, len(vector))

    def test_nonempty_vector_is_unit_normalized(self) -> None:
        vector = self.scorer.vectorize("filing deadline and tolling")
        magnitude = sum(value * value for value in vector) ** 0.5
        self.assertAlmostEqual(1.0, magnitude)

    def test_empty_text_has_zero_similarity(self) -> None:
        self.assertEqual(0.0, self.scorer.score_text("", ""))
        self.assertEqual(0.0, self.scorer.score_text("query", ""))

    def test_same_input_has_exact_same_score(self) -> None:
        first = self.scorer.score_text("forum venue", "forum venue transfer")
        second = self.scorer.score_text("forum venue", "forum venue transfer")
        self.assertEqual(first, second)

    def test_exact_canary_ranks_its_document_first(self) -> None:
        target = self.corpus.documents[7]
        ranked = self.scorer.rank(target.fact_token, self.corpus.documents, limit=1)
        self.assertEqual(target.doc_id, ranked[0][0].doc_id)

    def test_semantically_overlapping_text_scores_higher(self) -> None:
        query = "limitations filing deadline tolling"
        related = "limitations deadline accrual and tolling rule"
        unrelated = "pineapple astronomy orchestra"
        self.assertGreater(
            self.scorer.score_text(query, related),
            self.scorer.score_text(query, unrelated),
        )

    def test_ties_are_broken_by_document_id(self) -> None:
        source = self.corpus.documents[0]
        left = replace(source, doc_id="A")
        right = replace(source, doc_id="B")
        ranked = self.scorer.rank("synthetic rule", (right, left))
        self.assertEqual(["A", "B"], [item[0].doc_id for item in ranked])

    def test_small_dimension_count_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            DeterministicVectorScorer(dimensions=7)


if __name__ == "__main__":
    unittest.main()
