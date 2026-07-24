"""Deterministic retrieval metrics with explicit eligible denominators."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass

from cti_provenance.retrieval.protocol import RetrievalHit


@dataclass(frozen=True)
class RecallAtK:
    """Recall over queries that have at least one relevant document."""

    k: int
    retrieved_relevant_queries: int
    denominator: int

    @property
    def value(self) -> float:
        return (
            self.retrieved_relevant_queries / self.denominator
            if self.denominator
            else 0.0
        )


def recall_at_k(
    results: Mapping[str, Sequence[RetrievalHit]],
    relevant_document_ids: Mapping[str, Collection[str]],
    *,
    k: int,
) -> RecallAtK:
    """Compute document-level recall@K; unanswerable queries are not counted."""

    if k <= 0:
        raise ValueError("k must be greater than zero")
    unexpected_result_ids = set(results).difference(relevant_document_ids)
    if unexpected_result_ids:
        raise ValueError("results contain query IDs absent from relevance judgments")
    denominator = 0
    retrieved_relevant_queries = 0
    for query_id, relevant_ids in relevant_document_ids.items():
        relevant = set(relevant_ids)
        if not relevant:
            continue
        denominator += 1
        retrieved = {hit.document_id for hit in results.get(query_id, ())[:k]}
        if relevant.intersection(retrieved):
            retrieved_relevant_queries += 1
    return RecallAtK(k, retrieved_relevant_queries, denominator)
