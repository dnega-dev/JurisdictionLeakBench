# Security policy

## Supported versions

This is an MVP. Security fixes are applied to the latest release on the `0.1.x` line; older snapshots are not supported.

## Reporting a vulnerability

Do not place exploit details, secrets, or confidential corpora in a public issue. Contact the project maintainers through the private security-reporting channel published by the distribution location from which you obtained this project. Include:

- affected version and Python version;
- minimal reproduction using synthetic data;
- expected and observed authorization result;
- configuration and attack case;
- whether a forbidden canary reached retrieval or answer output; and
- a proposed fix, if known.

If no private channel is available, report only that a private security contact is needed. Do not attach production indexes or client records.

## Data handling

JurisdictionLeakBench is designed for generated synthetic data. Its built-in loader requires `synthetic_only: true`, but that marker is not a data-loss-prevention control. Do not substitute real privileged, personal, regulated, or confidential text into a corpus. Generated JSON and reports may reveal benchmark canaries and scope layouts; treat outputs according to your environment's normal test-artifact policy.

The project performs no network calls, has no runtime dependencies, and does not require credentials. A request for API keys, client documents, or network access is unexpected and should be treated as suspicious.

## Security invariants

A secure adapter should preserve these invariants:

1. Authenticate the principal before constructing a server scope.
2. Derive tenant, matter, jurisdiction, privilege, date, and authority constraints from trusted server state.
3. Never copy client filter values into `ServerScope` as an authorization decision.
4. Apply all dimensions conjunctively.
5. Re-check graph edges and post-retrieval data before use in an answer.
6. Include the complete trusted scope in index and cache keys.
7. Fail closed on unknown metadata, stale records, malformed scope, and policy-service failure.
8. Avoid logging record content or canaries in production integrations.

## Scope of security claims

The included secure configurations prevent returned-document authorization violations under the benchmark's deterministic in-process model. They do not establish isolation for an external vector database, cache, model, graph store, API gateway, or answer generator. Passing results are not a penetration test or certification. See `docs/threat-model.md`.
