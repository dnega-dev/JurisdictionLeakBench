# Threat model

## 1. Purpose

JurisdictionLeakBench models a retrieval service that stores highly overlapping text for several authorization scopes. It tests whether forbidden records can become retrieval hits or contaminate a downstream answer when an authenticated user controls the query and request-level filters.

This document describes the MVP's model, not every threat to retrieval-augmented generation. The corpus is synthetic and legal-like only to create realistic overlap among dimensions often found in document systems.

## 2. Assets and security objectives

The protected assets are individual synthetic records and their unique canary facts. Each record is labeled on six authorization axes:

1. `tenant_id` — organization-level isolation;
2. `matter_id` — workstream or case-level need-to-know;
3. `jurisdiction` — policy/geographic boundary;
4. `privilege_class` — public, internal, or attorney work product;
5. `effective_from`/`effective_to` — temporal validity and stale-version exclusion; and
6. `authority_level` — the maximum authority available to a principal.

Graph references form an additional path to those assets. Version and concept IDs support utility ground truth but do not independently authorize access.

The principal security objective is **complete mediation**: every record exposed by vector retrieval or graph expansion must satisfy every trusted constraint for the authenticated principal at the benchmark's as-of date. Secondary objectives are useful retrieval (recall, precision, MRR), low overblocking, and no forbidden content in answer text.

## 3. Trust boundaries

### Trusted

- Authentication has produced a principal ID.
- A server-side policy decision has produced `ServerScope`.
- Corpus metadata is integrity-protected after ingestion.
- The benchmark process and its authorization code are trusted.
- The as-of date in `ServerScope` comes from trusted server policy, not the request.

### Untrusted

- Query text;
- all fields in `ClientFilters`;
- requested `k` in a production adaptation;
- vector similarity and rank order;
- document graph edges as an authorization signal;
- cached results not keyed by the complete trusted scope; and
- any retrieved text before a final authorization check.

`ServerScope` and `ClientFilters` are separate immutable data classes. A secure retriever conjunctively checks server scope and then lets client filters narrow the already-authorized set. Matching a client filter is never proof of authorization.

```text
untrusted request                    trusted service
+------------------+                +------------------------------+
| query            |--------------->| deterministic scorer         |
| client filters   |--- narrowing -->| AND ServerScope policy gate |
| OR/tampering     |                | retrieval / graph / answer   |
+------------------+                +------------------------------+
                                               |
                                               v
                                     authorized synthetic records
```

## 4. Adversary

The adversary is an authenticated principal with a legitimate narrow scope. The adversary can:

- submit arbitrary and repeated queries;
- know or guess a foreign concept or synthetic canary;
- omit filters, replace scope labels, submit multiple labels, or request OR semantics;
- use broad queries and a large result count;
- exploit semantic overlap among scopes;
- follow references from a permitted seed; and
- ask for an obsolete version.

The adversary cannot modify trusted corpus metadata, forge `ServerScope`, alter benchmark code, read process memory, or exploit the host operating system. These exclusions keep the benchmark focused on retrieval authorization.

## 5. Attack-to-control mapping

| Attack | Mechanism | Secure expectation |
| --- | --- | --- |
| Targeted cross-scope query | Query a foreign record's unique canary | Foreign record is absent regardless of score |
| Client filter tampering | Replace tenant with a foreign tenant | Client filter cannot expand server scope; result may be empty |
| OR bypass | Make one permissive predicate satisfy an OR | Server constraints remain conjunctive |
| Exhaustive enumeration | Broad terms and high `k` | Every returned record remains authorized |
| Near-duplicate collision | Use shared legal-like language | Similarity cannot override metadata authorization |
| Graph bridge/pivot | Follow a citation from an allowed seed to a forbidden peer | Every graph node is independently authorized |
| Stale-version access | Query an expired record's canary | `effective_to < as_of_date` is denied; current version may be returned only if relevant |

The generated suite also exercises matter, jurisdiction, privilege, and authority differences in every forbidden set even where an attack name emphasizes one dimension.

## 6. Configuration semantics

### Ungated

The baseline applies only `ClientFilters`. Empty filters search globally, tampered filters select foreign records, and OR semantics accept any matching field. It is expected to leak and exists to prove that attacks and canaries have signal.

### Post-retrieval metadata gating

The scorer ranks the global corpus to top-k, after which both `ServerScope` and client narrowing are applied. Graph expansion rechecks the same policy. The implementation returns no forbidden hit, but authorized records displaced before the gate are not backfilled. This models post-filter overblocking and demonstrates why “safe” is not equivalent to “useful.”

A real system must also ensure forbidden candidate content is not sent to an external model, logger, trace, cache, or reranker before the post-gate. This in-process benchmark measures returned-hit and answer exposure, not internal processor exposure.

### Pre-filtered partition

Trusted server policy and client narrowing form the candidate set before scoring. This avoids global top-k displacement and should preserve utility when the policy index is complete. Graph targets receive the same authorization check.

### Per-scope index

The retriever materializes an immutable in-memory document tuple keyed by every field in `ServerScope.cache_key()`, including principal, tenant, matter, jurisdiction, sorted privilege set, as-of date, and authority ceiling. Client filters apply only within that index. Omitting any security-relevant dimension from a production cache key is a cross-scope risk.

## 7. Metrics and interpretation

Security metrics use attack cases only. Utility metrics prefer benign controls so a deliberately malicious query does not redefine relevance.

- A **leaked hit** belongs to the case's forbidden set and also fails the executable server authorization function. The evaluator rejects ground truth that disagrees with that function.
- An **authorization violation** is any case with at least one leaked hit.
- **Answer contamination** requires a leaked document's exact synthetic canary to appear in the synthesized answer.
- **Overblocking** is one minus recall on controls; it is not itself a data leak.

A secure result should have zero leakage and authorization-violation rates. Nonzero answer propagation indicates that a retrieval failure was not contained downstream. High overblocking can make an otherwise isolated system unusable and may encourage operators to disable controls.

## 8. Temporal model

Date intervals are inclusive: a record is eligible when `effective_from <= as_of_date` and `effective_to` is absent or `effective_to >= as_of_date`. The stale fixtures end on 2023-12-31; default scopes use 2025-01-15. The model does not cover time zones, retroactive policy changes, litigation-hold exceptions, or bitemporal ingestion history.

## 9. Reproducibility and integrity

The seed controls token shuffling and canary values. SHA-256 derives canaries and corpus fingerprints; BLAKE2 derives feature-hash positions. Explicit ordering breaks ties. No timestamps enter a run. Run IDs hash complete canonical run content, and the loader rejects a mismatch. These mechanisms detect accidental mutation; they are not digital signatures against a malicious file author.

## 10. Out of scope

- Real legal correctness or advice;
- production embedding, ANN, quantization, reranker, or model behavior;
- prompt injection and tool-use attacks;
- side channels such as timing, counts, errors, or vector distances;
- membership inference without a returned record;
- denial of service, rate limits, authentication, and session fixation;
- encryption, key management, host/process isolation, and transport security;
- metadata integrity attacks and policy-administration compromise;
- inference providers receiving globally retrieved candidates before a gate;
- log, telemetry, backup, or operator-console exposure; and
- data deletion guarantees.

## 11. Applying the benchmark to another system

An adapter should map each synthetic document into the target index without dropping metadata, construct trusted scope from test harness state, keep request filters untrusted, retrieve stable document IDs, and return answer text separately. Preserve the generated relevant/forbidden ground truth. Record the target's version and configuration outside sensitive logs.

Before treating results as a release gate, add system-specific tests for cache keys, index aliases, policy outages, missing metadata, partial ingestion, pagination, batch queries, graph/reranker paths, retries, and concurrent principals. A pass means only that the tested adapter resisted the tested cases under the stated assumptions.
