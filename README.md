# JurisdictionLeakBench

JurisdictionLeakBench is a **zero-runtime-dependency, reproducible Python 3.9+ security benchmark** for retrieval-scope isolation. It asks a narrow question: when semantically overlapping records share one retrieval system, can a query cross a boundary that the authenticated principal is not allowed to cross?

The benchmark uses only generated text and deterministic synthetic canaries. It contains **no real client data, confidential material, people, cases, or legal advice**.

## What it covers

Every generated record carries independent metadata for:

- tenant;
- matter;
- jurisdiction;
- privilege class (`public`, `internal`, or `attorney_work_product`);
- effective date interval and version;
- authority level; and
- graph references to local and cross-tenant records.

The corpus intentionally repeats legal-like concepts and phrasing across scopes. A stable signed-feature-hashing scorer supplies vector-like ranking without NumPy, a model download, network access, or any non-standard-library runtime package.

### Retrieval configurations

| Configuration | Candidate selection | Security property |
| --- | --- | --- |
| `ungated` | Client filters only | Deliberately vulnerable baseline |
| `post_retrieval_gating` | Global top-k, then trusted metadata gate | No returned leak, but global top-k may overblock |
| `pre_filtered_partition` | Trusted scope + client narrowing before scoring | Isolation and useful in-scope ranking |
| `per_scope_index` | Index cached by trusted server scope | Physical/logical index separation per complete scope key |

`ServerScope` and `ClientFilters` are different types. Secure retrievers always evaluate the authenticated, server-derived scope. Client filters can only narrow that set; they never grant access.

### Attack suite

The seeded suite includes:

1. targeted cross-scope canary queries;
2. client filter tampering;
3. OR-filter bypass;
4. exhaustive enumeration;
5. near-duplicate concept collision;
6. graph bridge/pivot traversal; and
7. stale-version access.

Benign controls run in every tenant/matter/jurisdiction combination to measure utility separately from attack efficacy.

### Metrics

- **Leakage rate**: forbidden retrieved hits / all retrieved hits on attack cases.
- **Authorization violation rate**: attack cases returning at least one forbidden hit / attack cases.
- **Recall@k**: relevant retrieved hits / relevant ground-truth records, macro-averaged on benign controls.
- **Precision@k**: relevant retrieved hits / `k`, macro-averaged on benign controls; unfilled slots count as non-relevant.
- **MRR**: mean reciprocal rank of the first relevant hit on benign controls.
- **Overblocking**: `1 - recall@k` on benign controls.
- **Contamination-to-answer propagation**: violating cases whose synthesized answer contains a forbidden synthetic canary / violating cases.

The answer stage is intentionally simple: it concatenates retrieved canaries. This makes retrieval-to-answer propagation observable and deterministic; it is not an LLM evaluation.

## Quick start

No installation is required:

```sh
cd /path/to/JurisdictionLeakBench
PYTHONPATH=src python3 -m jurisdiction_leak_bench generate \
  --seed 1337 --output corpus.json
PYTHONPATH=src python3 -m jurisdiction_leak_bench run \
  --corpus corpus.json --output run.json
PYTHONPATH=src python3 -m jurisdiction_leak_bench report \
  run.json --format text
```

Or install the local project (the installed package still has no runtime dependencies):

```sh
python3 -m pip install .
jurisdiction-leak-bench run --seed 1337 --output run.json
```

The default seed generates 96 documents, 12 benign controls, and 10 attack cases. Expected high-level behavior is a leaking `ungated` baseline, zero authorization violations in all three server-enforced configurations, and higher overblocking for post-retrieval gating than pre-filtering.

## CLI

```text
jurisdiction-leak-bench generate [--seed N] [--output corpus.json|-]
jurisdiction-leak-bench run [--corpus corpus.json | --seed N]
                            [-c CONFIG ...] [--attack ATTACK ...]
                            [--output run.json|-] [--quiet]
jurisdiction-leak-bench compare BASELINE.json CANDIDATE.json
                            [--format text|json] [--tolerance N]
                            [--fail-on-regression] [--output PATH|-]
jurisdiction-leak-bench report RUN.json
                            [--format text|json|junit|sarif]
                            [--fail-on-leak] [--output PATH|-]
```

Examples:

```sh
# Run only the secure pre-filtered configurations.
PYTHONPATH=src python3 -m jurisdiction_leak_bench run --seed 1337 \
  -c pre_filtered_partition -c per_scope_index -o secure.json

# Produce CI formats.
PYTHONPATH=src python3 -m jurisdiction_leak_bench report run.json \
  --format junit -o results.xml
PYTHONPATH=src python3 -m jurisdiction_leak_bench report run.json \
  --format sarif -o results.sarif

# Fail with status 2 if any candidate metric regresses beyond 0.5 percentage points.
PYTHONPATH=src python3 -m jurisdiction_leak_bench compare baseline.json candidate.json \
  --tolerance 0.005 --fail-on-regression
```

A saved corpus has a schema version, `synthetic_only: true`, and a SHA-256 fingerprint. A saved run embeds that fingerprint and has a deterministic content-derived run ID. Loading rejects altered run content whose ID no longer matches.

## Python API

```python
from jurisdiction_leak_bench import generate_corpus, run_benchmark

corpus = generate_corpus(seed=1337)
run = run_benchmark(
    corpus,
    configurations=("pre_filtered_partition", "per_scope_index"),
)
for summary in run.summaries:
    print(summary.configuration, summary.authorization_violation_rate)
```

## Reproducibility

For a fixed Python implementation and project version, the seed controls all corpus variation. Stable BLAKE2/SHA-256 hashes replace Python's randomized `hash()`, document and tie ordering are explicit, floating values are rounded, and result files contain no wall-clock timestamps. Running the same seed and selection twice yields the same corpus fingerprint and run ID.

## Testing

```sh
./ci/check.sh
```

The check runs the standard-library `unittest` suite and compiles all Python sources. See [docs/threat-model.md](docs/threat-model.md) for trust assumptions and limitations.

## Non-goals

This MVP does not claim to model production embedding quality, ANN implementation defects, inference-time prompt attacks, side-channel timing, cryptographic isolation, or the correctness of any legal proposition. Passing it is evidence about the modeled retrieval boundary, not a security certification. Add system-specific adapters and adversarial cases before using it as a release gate.

## License

Apache License 2.0. See [LICENSE](LICENSE).
