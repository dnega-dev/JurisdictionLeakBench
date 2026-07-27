"""Render benchmark results as text, JSON, JUnit XML, or SARIF."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List

from .comparison import RunComparison
from .runner import BenchmarkRun


REPORT_FORMATS = ("text", "json", "junit", "sarif")


def _percent(value: float) -> str:
    return "{0:.2f}%".format(value * 100.0)


def render_text(run: BenchmarkRun) -> str:
    lines = [
        "JurisdictionLeakBench run " + run.run_id,
        "seed={0} corpus={1}".format(run.seed, run.corpus_fingerprint[:16]),
        "",
        (
            "configuration               leak rate  auth violations  recall@k  "
            "precision@k  MRR      overblocking  answer propagation"
        ),
        "-" * 124,
    ]
    for summary in run.summaries:
        lines.append(
            "{0:<27} {1:>9}  {2:>15}  {3:>8}  {4:>11}  {5:>7}  {6:>12}  {7:>18}".format(
                summary.configuration,
                _percent(summary.leakage_rate),
                _percent(summary.authorization_violation_rate),
                _percent(summary.recall_at_k),
                _percent(summary.precision_at_k),
                "{0:.3f}".format(summary.mrr),
                _percent(summary.overblocking),
                _percent(summary.contamination_to_answer_propagation),
            )
        )
    violations = [metric for metric in run.case_metrics if metric.authorization_violation]
    lines.extend(("", "violating cases: {0}".format(len(violations))))
    for metric in violations:
        lines.append(
            "  {0}/{1}: {2}".format(
                metric.configuration, metric.case_id, ", ".join(metric.leaked_doc_ids)
            )
        )
    return "\n".join(lines) + "\n"


def render_junit(run: BenchmarkRun) -> str:
    failures = sum(metric.authorization_violation for metric in run.case_metrics)
    suite = ET.Element(
        "testsuite",
        {
            "name": "JurisdictionLeakBench",
            "tests": str(len(run.case_metrics)),
            "failures": str(failures),
            "errors": "0",
            "skipped": "0",
        },
    )
    properties = ET.SubElement(suite, "properties")
    ET.SubElement(properties, "property", {"name": "run_id", "value": run.run_id})
    ET.SubElement(
        properties,
        "property",
        {"name": "corpus_fingerprint", "value": run.corpus_fingerprint},
    )
    for metric in run.case_metrics:
        testcase = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": "jurisdiction_leak_bench." + metric.configuration,
                "name": metric.case_id + "." + metric.attack,
            },
        )
        if metric.authorization_violation:
            failure = ET.SubElement(
                testcase,
                "failure",
                {
                    "type": "AuthorizationViolation",
                    "message": "forbidden records retrieved",
                },
            )
            failure.text = "Leaked synthetic document ids: " + ", ".join(
                metric.leaked_doc_ids
            )
        output = ET.SubElement(testcase, "system-out")
        output.text = (
            "recall@k={0} precision@k={1} reciprocal_rank={2} overblocking={3}"
        ).format(
            metric.recall_at_k,
            metric.precision_at_k,
            metric.reciprocal_rank,
            metric.overblocking,
        )
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def render_sarif(run: BenchmarkRun) -> str:
    results: List[Dict[str, object]] = []
    for metric in run.case_metrics:
        if not metric.authorization_violation:
            continue
        for document_id in metric.leaked_doc_ids:
            results.append(
                {
                    "ruleId": "JLB001",
                    "level": "error",
                    "message": {
                        "text": (
                            "Authorization boundary violation in {0}/{1}: "
                            "retrieved forbidden synthetic record {2}."
                        ).format(metric.configuration, metric.case_id, document_id)
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "synthetic-corpus/" + document_id
                                }
                            }
                        }
                    ],
                    "properties": {
                        "attack": metric.attack,
                        "caseId": metric.case_id,
                        "configuration": metric.configuration,
                        "answerContaminated": metric.answer_contaminated,
                    },
                }
            )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "JurisdictionLeakBench",
                        "version": "0.1.0",
                        "rules": [
                            {
                                "id": "JLB001",
                                "name": "RetrievalScopeAuthorizationViolation",
                                "shortDescription": {
                                    "text": "A forbidden record crossed the retrieval scope."
                                },
                                "help": {
                                    "text": (
                                        "Enforce tenant, matter, jurisdiction, privilege, "
                                        "effective-date, and authority constraints using a "
                                        "trusted server scope before retrieval or before use."
                                    )
                                },
                            }
                        ],
                    }
                },
                "automationDetails": {"id": run.run_id},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True) + "\n"


def render_report(run: BenchmarkRun, report_format: str) -> str:
    if report_format == "text":
        return render_text(run)
    if report_format == "json":
        return json.dumps(run.to_dict(), indent=2, sort_keys=True) + "\n"
    if report_format == "junit":
        return render_junit(run)
    if report_format == "sarif":
        return render_sarif(run)
    raise ValueError("unknown report format: " + report_format)


def render_comparison(comparison: RunComparison, report_format: str) -> str:
    if report_format == "json":
        return json.dumps(comparison.to_dict(), indent=2, sort_keys=True) + "\n"
    if report_format != "text":
        raise ValueError("comparison format must be text or json")
    lines = [
        "JurisdictionLeakBench comparison",
        "baseline={0} candidate={1}".format(
            comparison.baseline_run_id, comparison.candidate_run_id
        ),
        "",
        "configuration               leak Δ    auth Δ    recall Δ  precision Δ  MRR Δ     overblock Δ  status",
        "-" * 111,
    ]
    for delta in comparison.deltas:
        lines.append(
            "{0:<27} {1:>9.6f} {2:>9.6f} {3:>10.6f} {4:>12.6f} {5:>9.6f} {6:>12.6f}  {7}".format(
                delta.configuration,
                delta.leakage_rate,
                delta.authorization_violation_rate,
                delta.recall_at_k,
                delta.precision_at_k,
                delta.mrr,
                delta.overblocking,
                "REGRESSION" if delta.regressed else "OK",
            )
        )
    return "\n".join(lines) + "\n"
