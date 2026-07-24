"""Contracts for deterministic retrieval over a cutoff-filtered corpus."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cti_provenance.normalize import NormalizedDocument
from cti_provenance.snapshot import SnapshotState, select_admissible_by_entity


class RetrievalError(ValueError):
    """A retrieval corpus or request violates the offline retrieval contract."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise RetrievalError("cutoff must be timezone-aware UTC")
    return value.astimezone(UTC)


@dataclass(frozen=True)
class CorpusView:
    """The only document view accepted by retrievers.

    The selected snapshot identifiers are retained with the documents so callers
    can audit the temporal boundary used for every retrieval result.
    """

    documents: tuple[NormalizedDocument, ...]
    selected_snapshot_ids: frozenset[str]
    cutoff: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "cutoff", _utc(self.cutoff))
        document_ids = [document.document_id for document in self.documents]
        if len(document_ids) != len(set(document_ids)):
            raise RetrievalError("corpus documents must have unique document_id values")
        document_snapshot_ids = {document.snapshot_id for document in self.documents}
        if not document_snapshot_ids.issubset(self.selected_snapshot_ids):
            raise RetrievalError(
                "corpus contains a document outside selected snapshots"
            )


@dataclass(frozen=True)
class RetrievalHit:
    """A ranked document plus its addressable evidence spans."""

    document_id: str
    snapshot_id: str
    span_ids: tuple[str, ...]
    score: float


def build_cutoff_corpus(
    documents: list[NormalizedDocument] | tuple[NormalizedDocument, ...],
    states: list[SnapshotState] | tuple[SnapshotState, ...],
    cutoff: datetime,
) -> CorpusView:
    """Select one admissible source state per entity before exposing documents.

    Documents physically present for newer or unselected snapshots are excluded
    here, before a retriever receives any searchable text.
    """

    cutoff = _utc(cutoff)
    selected = select_admissible_by_entity(list(states), cutoff)
    selected_snapshot_ids = frozenset(
        manifest.snapshot_id for manifest in selected.values()
    )
    all_documents = tuple(documents)
    document_ids = [document.document_id for document in all_documents]
    if len(document_ids) != len(set(document_ids)):
        raise RetrievalError("corpus documents must have unique document_id values")
    return CorpusView(
        documents=tuple(
            document
            for document in all_documents
            if document.snapshot_id in selected_snapshot_ids
        ),
        selected_snapshot_ids=selected_snapshot_ids,
        cutoff=cutoff,
    )
