from __future__ import annotations

import json
import unittest
import xml.etree.ElementTree as ET

from jurisdiction_leak_bench.comparison import compare_runs
from jurisdiction_leak_bench.corpus import generate_corpus
from jurisdiction_leak_bench.reporting import (
    render_comparison,
    render_junit,
    render_report,
    render_sarif,
    render_text,
)
from jurisdiction_leak_bench.runner import run_benchmark


class ReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark_run = run_benchmark(generate_corpus())

    def test_text_report_contains_all_metrics(self) -> None:
        text = render_text(self.benchmark_run)
        for label in (
            "leak rate",
            "auth violations",
            "recall@k",
            "precision@k",
            "MRR",
            "overblocking",
            "answer propagation",
        ):
            self.assertIn(label, text)

    def test_text_report_lists_all_configurations(self) -> None:
        text = render_text(self.benchmark_run)
        for configuration in self.benchmark_run.configurations:
            self.assertIn(configuration, text)

    def test_json_report_is_complete_run_payload(self) -> None:
        value = json.loads(render_report(self.benchmark_run, "json"))
        self.assertEqual(self.benchmark_run.run_id, value["run_id"])
        self.assertEqual(len(self.benchmark_run.summaries), len(value["summaries"]))
        self.assertEqual(len(self.benchmark_run.results), len(value["results"]))

    def test_junit_report_is_valid_xml(self) -> None:
        root = ET.fromstring(render_junit(self.benchmark_run))
        self.assertEqual("testsuite", root.tag)
        self.assertEqual(str(len(self.benchmark_run.case_metrics)), root.attrib["tests"])

    def test_junit_failures_match_violating_cases(self) -> None:
        root = ET.fromstring(render_junit(self.benchmark_run))
        expected = sum(
            metric.authorization_violation for metric in self.benchmark_run.case_metrics
        )
        self.assertEqual(str(expected), root.attrib["failures"])
        self.assertEqual(expected, len(root.findall("./testcase/failure")))

    def test_junit_includes_utility_output_for_every_case(self) -> None:
        root = ET.fromstring(render_junit(self.benchmark_run))
        outputs = root.findall("./testcase/system-out")
        self.assertEqual(len(self.benchmark_run.case_metrics), len(outputs))
        self.assertTrue(all("recall@k=" in (output.text or "") for output in outputs))

    def test_sarif_report_is_version_2_1(self) -> None:
        value = json.loads(render_sarif(self.benchmark_run))
        self.assertEqual("2.1.0", value["version"])
        self.assertEqual("JurisdictionLeakBench", value["runs"][0]["tool"]["driver"]["name"])

    def test_sarif_result_count_matches_leaked_hits(self) -> None:
        value = json.loads(render_sarif(self.benchmark_run))
        expected = sum(metric.leaked_count for metric in self.benchmark_run.case_metrics)
        self.assertEqual(expected, len(value["runs"][0]["results"]))
        self.assertTrue(
            all(result["ruleId"] == "JLB001" for result in value["runs"][0]["results"])
        )

    def test_unknown_report_format_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown report"):
            render_report(self.benchmark_run, "csv")

    def test_comparison_text_and_json_render(self) -> None:
        comparison = compare_runs(self.benchmark_run, self.benchmark_run)
        text = render_comparison(comparison, "text")
        value = json.loads(render_comparison(comparison, "json"))
        self.assertIn("baseline=", text)
        self.assertEqual(self.benchmark_run.run_id, value["baseline_run_id"])
        self.assertFalse(value["regressed"])

    def test_comparison_rejects_other_format(self) -> None:
        comparison = compare_runs(self.benchmark_run, self.benchmark_run)
        with self.assertRaisesRegex(ValueError, "text or json"):
            render_comparison(comparison, "sarif")


if __name__ == "__main__":
    unittest.main()
