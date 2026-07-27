from __future__ import annotations

import contextlib
import io
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from jurisdiction_leak_bench.cli import main
from jurisdiction_leak_bench.corpus import BenchmarkCorpus, generate_corpus
from jurisdiction_leak_bench.runner import BenchmarkRun, run_benchmark

from .helpers import temporary_directory


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = temporary_directory()
        cls.directory = Path(cls.temporary.name)
        cls.corpus = generate_corpus()
        cls.corpus_path = cls.directory / "corpus.json"
        cls.run_path = cls.directory / "run.json"
        cls.corpus.save(str(cls.corpus_path))
        run_benchmark(cls.corpus).save(str(cls.run_path))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def invoke(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(arguments)
        return status, output.getvalue()

    def test_generate_to_stdout(self) -> None:
        status, output = self.invoke(["generate", "--seed", "77", "--output", "-"])
        value = json.loads(output)
        self.assertEqual(0, status)
        self.assertEqual(77, value["seed"])
        self.assertIs(value["synthetic_only"], True)

    def test_generate_to_file(self) -> None:
        path = self.directory / "generated" / "corpus-88.json"
        status, output = self.invoke(
            ["generate", "--seed", "88", "--output", str(path)]
        )
        self.assertEqual(0, status)
        self.assertEqual("", output)
        self.assertEqual(88, BenchmarkCorpus.load(str(path)).seed)

    def test_run_to_stdout_is_json(self) -> None:
        status, output = self.invoke(
            [
                "run",
                "--corpus",
                str(self.corpus_path),
                "--configuration",
                "pre_filtered_partition",
                "--output",
                "-",
            ]
        )
        value = json.loads(output)
        self.assertEqual(0, status)
        self.assertEqual(["pre_filtered_partition"], value["configurations"])

    def test_run_to_file_can_be_loaded(self) -> None:
        path = self.directory / "nested" / "secure-run.json"
        status, output = self.invoke(
            [
                "run",
                "--seed",
                "1337",
                "--configuration",
                "per_scope_index",
                "--output",
                str(path),
                "--quiet",
            ]
        )
        self.assertEqual(0, status)
        self.assertEqual("", output)
        loaded = BenchmarkRun.load(str(path))
        self.assertEqual(("per_scope_index",), loaded.configurations)

    def test_run_attack_selection_is_honored(self) -> None:
        status, output = self.invoke(
            [
                "run",
                "--seed",
                "1337",
                "--configuration",
                "ungated",
                "--attack",
                "stale_version_access",
                "--output",
                "-",
            ]
        )
        value = json.loads(output)
        self.assertEqual(0, status)
        self.assertEqual(["stale_version_access"], value["selected_attacks"])
        self.assertEqual(1, len(value["results"]))

    def test_report_text_to_stdout(self) -> None:
        status, output = self.invoke(
            ["report", str(self.run_path), "--format", "text", "--output", "-"]
        )
        self.assertEqual(0, status)
        self.assertIn("JurisdictionLeakBench run", output)

    def test_report_writes_all_machine_formats(self) -> None:
        for report_format, suffix in (("json", "json"), ("junit", "xml"), ("sarif", "sarif")):
            path = self.directory / ("report-" + report_format + "." + suffix)
            status, _ = self.invoke(
                [
                    "report",
                    str(self.run_path),
                    "--format",
                    report_format,
                    "--output",
                    str(path),
                ]
            )
            self.assertEqual(0, status)
            self.assertTrue(path.is_file())
        json.loads((self.directory / "report-json.json").read_text(encoding="utf-8"))
        ET.parse(str(self.directory / "report-junit.xml"))
        json.loads((self.directory / "report-sarif.sarif").read_text(encoding="utf-8"))

    def test_fail_on_leak_returns_two(self) -> None:
        status, _ = self.invoke(
            [
                "report",
                str(self.run_path),
                "--format",
                "text",
                "--output",
                "-",
                "--fail-on-leak",
            ]
        )
        self.assertEqual(2, status)

    def test_fail_on_leak_accepts_secure_only_run(self) -> None:
        secure_path = self.directory / "secure-only.json"
        run_benchmark(
            self.corpus,
            configurations=("pre_filtered_partition", "per_scope_index"),
        ).save(str(secure_path))
        status, _ = self.invoke(
            [
                "report",
                str(secure_path),
                "--format",
                "json",
                "--output",
                "-",
                "--fail-on-leak",
            ]
        )
        self.assertEqual(0, status)

    def test_compare_identical_runs_as_json(self) -> None:
        status, output = self.invoke(
            [
                "compare",
                str(self.run_path),
                str(self.run_path),
                "--format",
                "json",
                "--output",
                "-",
                "--fail-on-regression",
            ]
        )
        value = json.loads(output)
        self.assertEqual(0, status)
        self.assertFalse(value["regressed"])

    def test_version_flag_exits_successfully(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(0, raised.exception.code)
        self.assertIn("0.1.0", output.getvalue())

    def test_unknown_command_exits_with_usage_error(self) -> None:
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as raised:
            main(["unknown"])
        self.assertEqual(2, raised.exception.code)
        self.assertIn("invalid choice", error.getvalue())


if __name__ == "__main__":
    unittest.main()
