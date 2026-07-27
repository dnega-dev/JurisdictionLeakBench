# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning follows semantic-versioning intent while the project is pre-1.0.

## [Unreleased]

### Planned

- Adapter protocol examples for external retrieval systems.
- Larger seeded scenario profiles and configurable policy matrices.

## [0.1.0] - 2025-01-15

### Added

- Seeded, synthetic, overlapping 96-document corpus across tenants, matters, jurisdictions, privilege classes, effective dates, authority levels, versions, and graph links.
- Explicit, separate `ServerScope` and untrusted `ClientFilters` models.
- Deterministic signed-feature-hashing vector-like scorer.
- Ungated, post-retrieval-gated, pre-filtered-partition, and per-scope-index retrieval configurations.
- Targeted cross-scope, client-filter tampering, OR-bypass, exhaustive-enumeration, near-duplicate collision, graph-pivot, and stale-version attacks.
- Leakage rate, authorization violation rate, recall@k, precision@k, MRR, overblocking, and contamination-to-answer propagation metrics.
- `generate`, `run`, `compare`, and `report` CLI commands.
- Text, JSON, JUnit XML, and SARIF reports.
- Standard-library unit tests and offline CI check script.

