"""Minimal library API example; all data is generated and synthetic."""

from jurisdiction_leak_bench import generate_corpus, run_benchmark


def main() -> None:
    corpus = generate_corpus(seed=1337)
    result = run_benchmark(
        corpus,
        configurations=(
            "post_retrieval_gating",
            "pre_filtered_partition",
            "per_scope_index",
        ),
    )
    print("corpus", corpus.fingerprint())
    print("run", result.run_id)
    for summary in result.summaries:
        print(
            summary.configuration,
            "violations=", summary.authorization_violation_rate,
            "recall=", summary.recall_at_k,
            "overblocking=", summary.overblocking,
        )


if __name__ == "__main__":
    main()
