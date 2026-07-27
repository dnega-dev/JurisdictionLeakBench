"""JurisdictionLeakBench: retrieval-scope isolation benchmarking."""

from .corpus import BenchmarkCorpus, generate_corpus
from .runner import BenchmarkRun, run_benchmark

__all__ = ("BenchmarkCorpus", "BenchmarkRun", "generate_corpus", "run_benchmark")
__version__ = "0.1.0"
