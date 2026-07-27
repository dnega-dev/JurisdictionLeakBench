from __future__ import annotations

import json
import unittest
from pathlib import Path

from jurisdiction_leak_bench.attacks import REQUIRED_ATTACKS, missing_required_attacks
from jurisdiction_leak_bench.corpus import BenchmarkCorpus, generate_corpus

from .helpers import temporary_directory


class CorpusGenerationTests(unittest.TestCase):
    def test_default_corpus_has_expected_scale(self) -> None:
        corpus = generate_corpus()
        self.assertEqual(96, len(corpus.documents))
        self.assertGreaterEqual(len(corpus.cases), 20)

    def test_same_seed_is_byte_reproducible(self) -> None:
        first = generate_corpus(1337)
        second = generate_corpus(1337)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.fingerprint(), second.fingerprint())

    def test_different_seed_changes_fingerprint_and_canaries(self) -> None:
        first = generate_corpus(1)
        second = generate_corpus(2)
        self.assertNotEqual(first.fingerprint(), second.fingerprint())
        self.assertNotEqual(first.documents[0].fact_token, second.documents[0].fact_token)

    def test_all_required_attacks_are_present(self) -> None:
        corpus = generate_corpus()
        self.assertEqual((), missing_required_attacks(corpus.cases))
        present = {case.attack for case in corpus.cases}
        self.assertTrue(set(REQUIRED_ATTACKS).issubset(present))

    def test_corpus_is_explicitly_synthetic(self) -> None:
        value = generate_corpus().to_dict()
        self.assertIs(value["synthetic_only"], True)
        self.assertEqual("1.0", value["schema_version"])
        all_text = " ".join(item["text"] for item in value["documents"])
        self.assertIn("entirely synthetic", all_text)

    def test_document_ids_are_unique(self) -> None:
        corpus = generate_corpus()
        ids = [document.doc_id for document in corpus.documents]
        self.assertEqual(len(ids), len(set(ids)))

    def test_each_scope_dimension_varies(self) -> None:
        corpus = generate_corpus()
        self.assertEqual(3, len({document.tenant_id for document in corpus.documents}))
        self.assertEqual(2, len({document.matter_id for document in corpus.documents}))
        self.assertEqual(2, len({document.jurisdiction for document in corpus.documents}))
        self.assertEqual(3, len({document.privilege_class for document in corpus.documents}))
        self.assertEqual({1, 2, 3}, {document.authority_level for document in corpus.documents})
        self.assertEqual({1, 2}, {document.version for document in corpus.documents})

    def test_save_and_load_round_trip(self) -> None:
        corpus = generate_corpus(44)
        with temporary_directory() as directory:
            path = str(Path(directory) / "corpus.json")
            corpus.save(path)
            loaded = BenchmarkCorpus.load(path)
        self.assertEqual(corpus, loaded)
        self.assertEqual(corpus.fingerprint(), loaded.fingerprint())

    def test_loader_rejects_unmarked_corpus(self) -> None:
        value = generate_corpus().to_dict()
        value["synthetic_only"] = False
        with self.assertRaisesRegex(ValueError, "synthetic_only"):
            BenchmarkCorpus.from_dict(value)

    def test_loader_rejects_unknown_reference(self) -> None:
        value = generate_corpus().to_dict()
        value["documents"][0]["references"] = ["missing-record"]
        with self.assertRaisesRegex(ValueError, "reference"):
            BenchmarkCorpus.from_dict(value)

    def test_loader_rejects_incomplete_forbidden_ground_truth(self) -> None:
        value = generate_corpus().to_dict()
        value["cases"][0]["forbidden_doc_ids"].pop()
        with self.assertRaisesRegex(ValueError, "forbidden ground truth"):
            BenchmarkCorpus.from_dict(value)

    def test_stale_and_current_versions_share_concepts(self) -> None:
        corpus = generate_corpus()
        groups = {}
        for document in corpus.documents:
            key = (
                document.tenant_id,
                document.matter_id,
                document.jurisdiction,
                document.concept_id,
            )
            groups.setdefault(key, set()).add(document.version)
        self.assertTrue(groups)
        self.assertTrue(all(versions == {1, 2} for versions in groups.values()))

    def test_current_records_have_cross_tenant_graph_edges(self) -> None:
        corpus = generate_corpus()
        by_id = {document.doc_id: document for document in corpus.documents}
        current = [document for document in corpus.documents if document.version == 2]
        self.assertTrue(
            all(
                any(by_id[target].tenant_id != document.tenant_id for target in document.references)
                for document in current
            )
        )


if __name__ == "__main__":
    unittest.main()
