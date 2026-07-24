"""Small deterministic, dependency-free lexical retriever."""

from __future__ import annotations

import re
from collections import Counter
from math import log

from cti_provenance.retrieval.protocol import CorpusView, RetrievalHit

_TOKEN_RE = re.compile(r"[^\W_]+", flags=re.UNICODE)
_K1 = 1.2
_B = 0.75


def tokenize(text: str) -> tuple[str, ...]:
    """Return a stable Unicode word-token sequence for local ranking."""

    return tuple(match.group(0).casefold() for match in _TOKEN_RE.finditer(text))


class LexicalRetriever:
    """A deterministic BM25-style ranker over one already-filtered corpus view."""

    version = "lexical-bm25-v1"

    def __init__(self, corpus: CorpusView) -> None:
        self._corpus = corpus
        self._document_tokens = {
            document.document_id: tokenize(document.normalized_text)
            for document in corpus.documents
        }
        self._term_document_frequency: Counter[str] = Counter()
        for tokens in self._document_tokens.values():
            self._term_document_frequency.update(set(tokens))
        count = len(corpus.documents)
        self._average_document_length = (
            sum(len(tokens) for tokens in self._document_tokens.values()) / count
            if count
            else 0.0
        )

    @property
    def corpus(self) -> CorpusView:
        """The immutable cutoff-filtered corpus used for ranking."""

        return self._corpus

    def search(self, query: str, *, limit: int = 10) -> tuple[RetrievalHit, ...]:
        """Rank lexical matches with stable document-ID tie-breaking."""

        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        query_terms = tokenize(query)
        if not query_terms or not self._corpus.documents:
            return ()
        query_counts = Counter(query_terms)
        hits: list[RetrievalHit] = []
        document_count = len(self._corpus.documents)
        for document in self._corpus.documents:
            term_counts = Counter(self._document_tokens[document.document_id])
            length = len(self._document_tokens[document.document_id])
            score = 0.0
            for term, query_frequency in query_counts.items():
                term_frequency = term_counts[term]
                if term_frequency == 0:
                    continue
                document_frequency = self._term_document_frequency[term]
                inverse_frequency = log(
                    1.0
                    + (document_count - document_frequency + 0.5)
                    / (document_frequency + 0.5)
                )
                normalization = _K1 * (
                    1.0 - _B + _B * length / self._average_document_length
                )
                score += (
                    query_frequency
                    * inverse_frequency
                    * (term_frequency * (_K1 + 1.0) / (term_frequency + normalization))
                )
            if score > 0.0:
                hits.append(
                    RetrievalHit(
                        document_id=document.document_id,
                        snapshot_id=document.snapshot_id,
                        span_ids=tuple(span.span_id for span in document.spans),
                        score=score,
                    )
                )
        ordered = sorted(hits, key=lambda hit: (-hit.score, hit.document_id))
        return tuple(ordered[:limit])
