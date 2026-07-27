from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from jurisdiction_leak_bench.comparison import compare_runs
from jurisdiction_leak_bench.corpus import generate_corpus
from jurisdiction_leak_bench.runner import BenchmarkRun, run_benchmark

from .helpers import temporary_directory


class RunnerAndComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = generate_corpus()
        cls.benchmark_run = run_benchmark(cls.corpus)

    def test_repeat_run_has_same_id_and_payload(self) -> None:
        second = run_benchmark(self.corpus)
        self.assertEqual(self.benchmark_run.run_id, second.run_id)
        self.assertEqual(self.benchmark_run.to_dict(), second.to_dict())

    def test_run_selection_limits_configurations_and_attacks(self) -> None:
        selected = run_benchmark(
            self.corpus,
            configurations=("pre_filtered_partition",),
            attacks=("benign_control", "stale_version_access"),
        )
        expected_cases = sum(
            case.attack in {"benign_control", "stale_version_access"}
            for case in self.corpus.cases
        )
        self.assertEqual(("pre_filtered_partition",), selected.configurations)
        self.assertEqual(expected_cases, len(selected.results))
        self.assertEqual(1, len(selected.summaries))

    def test_empty_configuration_selection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least one configuration"):
            run_benchmark(self.corpus, configurations=())

    def test_duplicate_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            run_benchmark(self.corpus, configurations=("ungated", "ungated"))

    def test_unknown_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown configuration"):
            run_benchmark(self.corpus, configurations=("unknown",))

    def test_unknown_attack_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown attack"):
            run_benchmark(self.corpus, attacks=("unknown",))

    def test_duplicate_attack_selection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate attack"):
            run_benchmark(
                self.corpus, attacks=("benign_control", "benign_control")
            )

    def test_run_save_and_load_round_trip(self) -> None:
        with temporary_directory() as directory:
            path = str(Path(directory) / "run.json")
            self.benchmark_run.save(path)
            loaded = BenchmarkRun.load(path)
        self.assertEqual(self.benchmark_run, loaded)

    def test_run_loader_detects_tampering(self) -> None:
        value = self.benchmark_run.to_dict()
        value["summaries"][0]["leakage_rate"] = 0.0
        with self.assertRaisesRegex(ValueError, "run_id"):
            BenchmarkRun.from_dict(value)

    def test_summary_lookup_rejects_missing_configuration(self) -> None:
        with self.assertRaises(KeyError):
            self.benchmark_run.summary_for("missing")

    def test_identical_runs_compare_without_regression(self) -> None:
        comparison = compare_runs(self.benchmark_run, self.benchmark_run)
        self.assertFalse(comparison.regressed)
        self.assertTrue(all(not delta.regressed for delta in comparison.deltas))

    def test_comparison_detects_security_regression(self) -> None:
        summaries = list(self.benchmark_run.summaries)
        index = next(
            index
            for index, summary in enumerate(summaries)
            if summary.configuration == "pre_filtered_partition"
        )
        summaries[index] = replace(
            summaries[index], leakage_rate=0.1, authorization_violation_rate=0.1
        )
        candidate = replace(self.benchmark_run, run_id="candidate", summaries=tuple(summaries))
        comparison = compare_runs(self.benchmark_run, candidate)
        delta = next(
            item
            for item in comparison.deltas
            if item.configuration == "pre_filtered_partition"
        )
        self.assertTrue(delta.regressed)
        self.assertEqual(0.1, delta.leakage_rate)

    def test_comparison_tolerance_can_absorb_small_change(self) -> None:
        summaries = list(self.benchmark_run.summaries)
        summaries[0] = replace(
            summaries[0], leakage_rate=summaries[0].leakage_rate + 0.001
        )
        candidate = replace(self.benchmark_run, run_id="candidate", summaries=tuple(summaries))
        comparison = compare_runs(self.benchmark_run, candidate, tolerance=0.002)
        self.assertFalse(comparison.deltas[0].regressed)

    def test_comparison_rejects_different_corpus(self) -> None:
        other = run_benchmark(generate_corpus(999))
        with self.assertRaisesRegex(ValueError, "different corpus"):
            compare_runs(self.benchmark_run, other)

    def test_comparison_rejects_negative_tolerance(self) -> None:
        with self.assertRaisesRegex(ValueError, "negative"):
            compare_runs(self.benchmark_run, self.benchmark_run, tolerance=-0.1)

    def test_comparison_requires_common_configuration(self) -> None:
        left = run_benchmark(self.corpus, configurations=("ungated",))
        right = run_benchmark(
            self.corpus, configurations=("pre_filtered_partition",)
        )
        with self.assertRaisesRegex(ValueError, "no configurations"):
            compare_runs(left, right)

    def test_comparison_requires_same_attack_selection(self) -> None:
        candidate = run_benchmark(
            self.corpus,
            configurations=self.benchmark_run.configurations,
            attacks=("benign_control",),
        )
        with self.assertRaisesRegex(ValueError, "attack selections"):
            compare_runs(self.benchmark_run, candidate)


if __name__ == "__main__":
    unittest.main()
