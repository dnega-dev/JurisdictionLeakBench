# Contributing

Thank you for improving JurisdictionLeakBench. Contributions should preserve its small, auditable, offline design.

## Development setup

Requirements:

- Python 3.9 or newer;
- a POSIX shell for `ci/check.sh`; and
- no network services or credentials.

Run directly from the source tree:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests examples
```

Or run both checks with:

```sh
./ci/check.sh
```

## Design rules

- Keep runtime dependencies at zero; use the Python standard library.
- Support Python 3.9 syntax. In particular, do not use `match`, `str | None`, or `list[str]` without considering the minimum version.
- Keep `ServerScope` distinct from `ClientFilters`. Client input must never grant access.
- Use deterministic hashing and explicit ordering; never use Python's randomized `hash()` for generated or ranked data.
- Keep fixtures entirely synthetic and visibly marked as such.
- Avoid dates, organizations, names, or prose copied from real legal matters.
- Apply authorization at every retrieval path, including graph traversal and answer synthesis.
- Do not weaken corpus/run schema validation merely to accept an ambiguous fixture.

## Adding an attack

1. Add the taxonomy entry and short description in `attacks.py`.
2. Generate at least one deterministic case in `corpus.py`.
3. Define both relevant and forbidden document IDs.
4. Demonstrate that the `ungated` baseline is meaningfully exercised.
5. Demonstrate that secure configurations do not return forbidden documents.
6. Add focused unit tests plus any metric/report expectations.
7. Document threat assumptions in `docs/threat-model.md`.

## Adding a retriever

A retriever must declare where server authorization is enforced, how client filters narrow the result, how graph references are gated, what its candidate count means, and which complete server-scope fields participate in cache/index keys. Add it to `CONFIGURATION_NAMES`, CLI choices, documentation, and tests.

## Tests and compatibility

New behavior needs tests. Prefer small explicit `unittest` cases over snapshots. Security tests should assert IDs and authorization state, not just aggregate percentages. Re-run a seed twice and compare fingerprints/run IDs when changing generation or ranking. Changes to deterministic output are allowed, but must be called out in `CHANGELOG.md`.

## Change submissions

A change description should explain the threat modeled, trust boundary, expected secure behavior, tests, and any compatibility impact. Never include confidential examples, customer names, internal endpoints, credentials, or generated output derived from production data.

By contributing, you agree that your contribution is licensed under Apache-2.0.
