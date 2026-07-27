"""Deterministic benchmark orchestration and result persistence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .attacks import REQUIRED_ATTACKS, missing_required_attacks
from .corpus import BenchmarkCorpus
from .metrics import CaseMetrics, MetricsSummary, evaluate_case, summarize_metrics
from .models import RetrievalResult
from .retrieval import CONFIGURATION_NAMES, make_retriever


RUN_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class BenchmarkRun:
    run_id: str
    seed: int
    corpus_fingerprint: str
    configurations: Tuple[str, ...]
    selected_attacks: Tuple[str, ...]
    summaries: Tuple[MetricsSummary, ...]
    case_metrics: Tuple[CaseMetrics, ...]
    results: Tuple[RetrievalResult, ...]
    schema_version: str = RUN_SCHEMA_VERSION

    def _payload(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "seed": self.seed,
            "corpus_fingerprint": self.corpus_fingerprint,
            "configurations": list(self.configurations),
            "selected_attacks": list(self.selected_attacks),
            "summaries": [summary.to_dict() for summary in self.summaries],
            "case_metrics": [metric.to_dict() for metric in self.case_metrics],
            "results": [result.to_dict() for result in self.results],
        }

    def to_dict(self) -> Dict[str, Any]:
        value = self._payload()
        value["run_id"] = self.run_id
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BenchmarkRun":
        if str(value.get("schema_version")) != RUN_SCHEMA_VERSION:
            raise ValueError("unsupported run schema_version")
        run = cls(
            run_id=str(value["run_id"]),
            seed=int(value["seed"]),
            corpus_fingerprint=str(value["corpus_fingerprint"]),
            configurations=tuple(str(item) for item in value["configurations"]),
            selected_attacks=tuple(str(item) for item in value["selected_attacks"]),
            summaries=tuple(
                MetricsSummary.from_dict(item) for item in value["summaries"]
            ),
            case_metrics=tuple(
                CaseMetrics.from_dict(item) for item in value["case_metrics"]
            ),
            results=tuple(RetrievalResult.from_dict(item) for item in value["results"]),
        )
        expected = _run_id(run._payload())
        if run.run_id != expected:
            raise ValueError("run_id does not match run contents")
        return run

    def save(self, path: str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str) -> "BenchmarkRun":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("run root must be an object")
        return cls.from_dict(value)

    def summary_for(self, configuration: str) -> MetricsSummary:
        for summary in self.summaries:
            if summary.configuration == configuration:
                return summary
        raise KeyError(configuration)


def _run_id(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]


def run_benchmark(
    corpus: BenchmarkCorpus,
    configurations: Optional[Sequence[str]] = None,
    attacks: Optional[Sequence[str]] = None,
) -> BenchmarkRun:
    """Execute selected configurations and cases with deterministic ordering."""

    selected_configurations = tuple(
        CONFIGURATION_NAMES if configurations is None else configurations
    )
    if not selected_configurations:
        raise ValueError("at least one configuration is required")
    if len(selected_configurations) != len(set(selected_configurations)):
        raise ValueError("duplicate configuration")
    unknown_configurations = set(selected_configurations) - set(CONFIGURATION_NAMES)
    if unknown_configurations:
        raise ValueError("unknown configuration: " + sorted(unknown_configurations)[0])

    available_attacks = {case.attack for case in corpus.cases}
    selected_attacks = tuple(
        sorted(available_attacks) if attacks is None else attacks
    )
    if not selected_attacks:
        raise ValueError("at least one attack or control is required")
    if len(selected_attacks) != len(set(selected_attacks)):
        raise ValueError("duplicate attack selection")
    unknown_attacks = set(selected_attacks) - available_attacks
    if unknown_attacks:
        raise ValueError("unknown attack: " + sorted(unknown_attacks)[0])
    selected_cases = tuple(
        case for case in corpus.cases if case.attack in set(selected_attacks)
    )

    documents = {document.doc_id: document for document in corpus.documents}
    all_results: List[RetrievalResult] = []
    all_metrics: List[CaseMetrics] = []
    summaries: List[MetricsSummary] = []
    for configuration in selected_configurations:
        retriever = make_retriever(configuration, corpus.documents)
        configuration_metrics: List[CaseMetrics] = []
        for case in selected_cases:
            result = retriever.retrieve(case)
            metric = evaluate_case(case, result, documents)
            all_results.append(result)
            all_metrics.append(metric)
            configuration_metrics.append(metric)
        summaries.append(summarize_metrics(configuration_metrics))

    provisional = BenchmarkRun(
        run_id="",
        seed=corpus.seed,
        corpus_fingerprint=corpus.fingerprint(),
        configurations=selected_configurations,
        selected_attacks=selected_attacks,
        summaries=tuple(summaries),
        case_metrics=tuple(all_metrics),
        results=tuple(all_results),
    )
    return BenchmarkRun(
        run_id=_run_id(provisional._payload()),
        seed=provisional.seed,
        corpus_fingerprint=provisional.corpus_fingerprint,
        configurations=provisional.configurations,
        selected_attacks=provisional.selected_attacks,
        summaries=provisional.summaries,
        case_metrics=provisional.case_metrics,
        results=provisional.results,
    )
