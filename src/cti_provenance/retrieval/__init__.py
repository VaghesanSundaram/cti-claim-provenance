"""Offline, cutoff-aware lexical retrieval."""

from cti_provenance.retrieval.lexical import LexicalRetriever, tokenize
from cti_provenance.retrieval.metrics import RecallAtK, recall_at_k
from cti_provenance.retrieval.protocol import (
    CorpusView,
    RetrievalError,
    RetrievalHit,
    build_cutoff_corpus,
)

__all__ = [
    "CorpusView",
    "LexicalRetriever",
    "RecallAtK",
    "RetrievalError",
    "RetrievalHit",
    "build_cutoff_corpus",
    "recall_at_k",
    "tokenize",
]
