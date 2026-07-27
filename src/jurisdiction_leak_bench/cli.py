"""Command-line interface for corpus generation, execution, comparison, and reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .attacks import AttackKind
from .comparison import compare_runs
from .corpus import BenchmarkCorpus, generate_corpus
from .reporting import REPORT_FORMATS, render_comparison, render_report, render_text
from .retrieval import CONFIGURATION_NAMES
from .runner import BenchmarkRun, run_benchmark


def _write_output(content: str, destination: str) -> None:
    if destination == "-":
        sys.stdout.write(content)
        return
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jurisdiction-leak-bench",
        description="Benchmark retrieval-scope isolation with synthetic data.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="generate a seeded corpus")
    generate.add_argument("--seed", type=int, default=1337)
    generate.add_argument("--output", "-o", default="corpus.json")

    run = subparsers.add_parser("run", help="execute benchmark configurations")
    source = run.add_mutually_exclusive_group()
    source.add_argument("--corpus", help="generated corpus JSON")
    source.add_argument("--seed", type=int, default=1337, help="inline corpus seed")
    run.add_argument(
        "--configuration",
        "-c",
        action="append",
        choices=CONFIGURATION_NAMES,
        help="configuration to run; repeat to select multiple (default: all)",
    )
    run.add_argument(
        "--attack",
        action="append",
        choices=tuple(kind.value for kind in AttackKind),
        help="attack/control to run; repeat to select multiple (default: all)",
    )
    run.add_argument("--output", "-o", default="benchmark-run.json")
    run.add_argument(
        "--quiet", action="store_true", help="do not print a text summary after saving"
    )

    compare = subparsers.add_parser("compare", help="compare two run JSON files")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    compare.add_argument("--format", choices=("text", "json"), default="text")
    compare.add_argument("--output", "-o", default="-")
    compare.add_argument("--tolerance", type=float, default=0.0)
    compare.add_argument("--fail-on-regression", action="store_true")

    report = subparsers.add_parser("report", help="render a saved run")
    report.add_argument("run_file")
    report.add_argument("--format", choices=REPORT_FORMATS, default="text")
    report.add_argument("--output", "-o", default="-")
    report.add_argument("--fail-on-leak", action="store_true")

    return parser


def _command_generate(arguments: argparse.Namespace) -> int:
    corpus = generate_corpus(arguments.seed)
    content = json.dumps(corpus.to_dict(), indent=2, sort_keys=True) + "\n"
    _write_output(content, arguments.output)
    return 0


def _command_run(arguments: argparse.Namespace) -> int:
    corpus = (
        BenchmarkCorpus.load(arguments.corpus)
        if arguments.corpus
        else generate_corpus(arguments.seed)
    )
    run = run_benchmark(corpus, arguments.configuration, arguments.attack)
    content = render_report(run, "json")
    _write_output(content, arguments.output)
    if not arguments.quiet and arguments.output != "-":
        sys.stdout.write(render_text(run))
    return 0


def _command_compare(arguments: argparse.Namespace) -> int:
    comparison = compare_runs(
        BenchmarkRun.load(arguments.baseline),
        BenchmarkRun.load(arguments.candidate),
        tolerance=arguments.tolerance,
    )
    _write_output(render_comparison(comparison, arguments.format), arguments.output)
    return 2 if arguments.fail_on_regression and comparison.regressed else 0


def _command_report(arguments: argparse.Namespace) -> int:
    run = BenchmarkRun.load(arguments.run_file)
    _write_output(render_report(run, arguments.format), arguments.output)
    has_leak = any(metric.authorization_violation for metric in run.case_metrics)
    return 2 if arguments.fail_on_leak and has_leak else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "generate":
            return _command_generate(arguments)
        if arguments.command == "run":
            return _command_run(arguments)
        if arguments.command == "compare":
            return _command_compare(arguments)
        if arguments.command == "report":
            return _command_report(arguments)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    parser.error("unknown command")
    return 2
