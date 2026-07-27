"""Compare two benchmark runs without third-party tooling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .runner import BenchmarkRun


@dataclass(frozen=True)
class ConfigurationDelta:
    configuration: str
    leakage_rate: float
    authorization_violation_rate: float
    recall_at_k: float
    precision_at_k: float
    mrr: float
    overblocking: float
    contamination_to_answer_propagation: float
    regressed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "configuration": self.configuration,
            "leakage_rate": self.leakage_rate,
            "authorization_violation_rate": self.authorization_violation_rate,
            "recall_at_k": self.recall_at_k,
            "precision_at_k": self.precision_at_k,
            "mrr": self.mrr,
            "overblocking": self.overblocking,
            "contamination_to_answer_propagation": self.contamination_to_answer_propagation,
            "regressed": self.regressed,
        }


@dataclass(frozen=True)
class RunComparison:
    baseline_run_id: str
    candidate_run_id: str
    corpus_fingerprint: str
    deltas: Tuple[ConfigurationDelta, ...]

    @property
    def regressed(self) -> bool:
        return any(delta.regressed for delta in self.deltas)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_run_id": self.baseline_run_id,
            "candidate_run_id": self.candidate_run_id,
            "corpus_fingerprint": self.corpus_fingerprint,
            "regressed": self.regressed,
            "deltas": [delta.to_dict() for delta in self.deltas],
        }


def compare_runs(
    baseline: BenchmarkRun, candidate: BenchmarkRun, tolerance: float = 0.0
) -> RunComparison:
    if tolerance < 0.0:
        raise ValueError("tolerance cannot be negative")
    if baseline.corpus_fingerprint != candidate.corpus_fingerprint:
        raise ValueError("cannot compare runs from different corpus fingerprints")
    if set(baseline.selected_attacks) != set(candidate.selected_attacks):
        raise ValueError("cannot compare runs with different attack selections")
    configurations = tuple(
        configuration
        for configuration in baseline.configurations
        if configuration in set(candidate.configurations)
    )
    if not configurations:
        raise ValueError("runs have no configurations in common")

    def difference(candidate_value: float, baseline_value: float) -> float:
        return round(candidate_value - baseline_value, 6)

    deltas: List[ConfigurationDelta] = []
    for configuration in configurations:
        before = baseline.summary_for(configuration)
        after = candidate.summary_for(configuration)
        leakage = difference(after.leakage_rate, before.leakage_rate)
        violations = difference(
            after.authorization_violation_rate, before.authorization_violation_rate
        )
        recall = difference(after.recall_at_k, before.recall_at_k)
        precision = difference(after.precision_at_k, before.precision_at_k)
        mrr = difference(after.mrr, before.mrr)
        overblocking = difference(after.overblocking, before.overblocking)
        propagation = difference(
            after.contamination_to_answer_propagation,
            before.contamination_to_answer_propagation,
        )
        regressed = (
            leakage > tolerance
            or violations > tolerance
            or overblocking > tolerance
            or recall < -tolerance
            or precision < -tolerance
            or mrr < -tolerance
            or propagation > tolerance
        )
        deltas.append(
            ConfigurationDelta(
                configuration=configuration,
                leakage_rate=leakage,
                authorization_violation_rate=violations,
                recall_at_k=recall,
                precision_at_k=precision,
                mrr=mrr,
                overblocking=overblocking,
                contamination_to_answer_propagation=propagation,
                regressed=regressed,
            )
        )
    return RunComparison(
        baseline_run_id=baseline.run_id,
        candidate_run_id=candidate.run_id,
        corpus_fingerprint=baseline.corpus_fingerprint,
        deltas=tuple(deltas),
    )
