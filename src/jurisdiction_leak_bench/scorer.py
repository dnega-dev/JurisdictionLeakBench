"""A deterministic, dependency-free vector-like similarity scorer."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Iterable, List, Optional, Tuple

from .models import Document


_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-_][a-z0-9]+)*")


def tokenize(text: str) -> Tuple[str, ...]:
    """Normalize words and add lightweight character trigrams.

    Trigrams make near-duplicate phrases collide in a predictable way while the
    stable hashing below approximates a small signed feature projection.
    """

    words = _TOKEN_RE.findall(text.lower())
    features: List[str] = list(words)
    for word in words:
        if len(word) >= 5:
            padded = "^" + word + "$"
            features.extend("tri:" + padded[i : i + 3] for i in range(len(padded) - 2))
    return tuple(features)


class DeterministicVectorScorer:
    """Signed feature hashing with cosine similarity and deterministic ties."""

    def __init__(self, dimensions: int = 96) -> None:
        if dimensions < 8:
            raise ValueError("dimensions must be at least 8")
        self.dimensions = dimensions

    def _projection(self, token: str) -> Tuple[int, float]:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        raw = int.from_bytes(digest, "big")
        index = raw % self.dimensions
        sign = -1.0 if raw & (1 << 63) else 1.0
        return index, sign

    def vectorize(self, text: str) -> Tuple[float, ...]:
        counts = Counter(tokenize(text))
        vector = [0.0] * self.dimensions
        for token, count in sorted(counts.items()):
            index, sign = self._projection(token)
            # Sublinear term frequency keeps repeated boilerplate from dominating.
            vector[index] += sign * (1.0 + math.log(float(count)))
        magnitude = math.sqrt(sum(value * value for value in vector))
        if magnitude:
            vector = [value / magnitude for value in vector]
        return tuple(vector)

    def score_text(self, query: str, text: str) -> float:
        query_vector = self.vectorize(query)
        text_vector = self.vectorize(text)
        cosine = sum(left * right for left, right in zip(query_vector, text_vector))
        # A small exact-token term makes unique synthetic canaries reliably rank.
        query_words = set(_TOKEN_RE.findall(query.lower()))
        text_words = set(_TOKEN_RE.findall(text.lower()))
        overlap = len(query_words & text_words) / max(1, len(query_words))
        return round(0.85 * cosine + 0.15 * overlap, 12)

    def score_document(self, query: str, document: Document) -> float:
        searchable = " ".join((document.title, document.text, document.fact_token))
        return self.score_text(query, searchable)

    def rank(
        self, query: str, documents: Iterable[Document], limit: Optional[int] = None
    ) -> Tuple[Tuple[Document, float], ...]:
        ranked = sorted(
            ((document, self.score_document(query, document)) for document in documents),
            key=lambda item: (-item[1], item[0].doc_id),
        )
        if limit is not None:
            ranked = ranked[: max(0, limit)]
        return tuple(ranked)
