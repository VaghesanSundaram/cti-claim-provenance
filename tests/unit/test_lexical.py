from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from cti_provenance.normalize import EvidenceSpan, NormalizedDocument
from cti_provenance.retrieval import (
    LexicalRetriever,
    RetrievalError,
    RetrievalHit,
    build_cutoff_corpus,
    recall_at_k,
)
from cti_provenance.snapshot import SnapshotManifest, SnapshotState

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _state(snapshot_id: str, observed_at: datetime) -> SnapshotState:
    return SnapshotState(
        SnapshotManifest(
            snapshot_id=snapshot_id,
            source_name="nvd",
            source_class="government",
            source_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            retrieved_at_utc=observed_at,
            http_status=200,
            http_etag=None,
            http_last_modified=None,
            effective_date_if_known=None,
            effective_date_basis="unknown",
            available_by_utc=observed_at,
            available_by_basis="observed_retrieval",
            upstream_identifier="CVE-TEST-1",
            upstream_version=None,
            media_type="application/json",
            byte_length=1,
            sha256=("a" if snapshot_id == "old" else "b") * 64,
            raw_blob_path=f"fixtures/{snapshot_id}.json",
            fetcher_version="fixture-v1",
            normalization_version="fixture-v1",
            license_or_terms_note="fixture",
        )
    )


def _document(document_id: str, snapshot_id: str, text: str) -> NormalizedDocument:
    return NormalizedDocument(
        document_id=document_id,
        snapshot_id=snapshot_id,
        upstream_entity_id="CVE-TEST-1",
        title="fixture",
        canonical_url=f"urn:cti-provenance:test:{document_id}",
        published_at=None,
        modified_at=None,
        source_name="nvd",
        source_class="government",
        normalization_version="fixture-v1",
        normalized_text=text,
        normalized_text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        fields={},
        spans=[
            EvidenceSpan(
                span_id=f"{document_id}-span",
                field_path="description",
                start_char=0,
                end_char=len(text),
                text_sha256=hashlib.sha256(text.encode()).hexdigest(),
                raw_locator="/description",
                raw_locator_unavailable_reason=None,
                raw_snapshot_id=snapshot_id,
                raw_snapshot_sha256="c" * 64,
                normalization_version="fixture-v1",
            )
        ],
    )


def test_later_physical_document_cannot_enter_cutoff_corpus() -> None:
    old = _state("old", NOW)
    later = _state("later", NOW + timedelta(days=1))
    corpus = build_cutoff_corpus(
        [
            _document("old-doc", "old", "legacy patched"),
            _document("later-doc", "later", "secret future"),
        ],
        [old, later],
        NOW,
    )

    assert corpus.selected_snapshot_ids == frozenset({"old"})
    hits = LexicalRetriever(corpus).search("secret future")
    assert [hit.document_id for hit in hits] == []


def test_same_entity_later_snapshot_distractor_is_excluded_before_ranking() -> None:
    corpus = build_cutoff_corpus(
        [
            _document("correct", "old", "Apache Log4j version"),
            _document("wrong-date", "later", "Apache Log4j version future correction"),
        ],
        [_state("old", NOW), _state("later", NOW + timedelta(seconds=1))],
        NOW,
    )

    hits = LexicalRetriever(corpus).search("Apache Log4j version")
    assert [hit.document_id for hit in hits] == ["correct"]


def test_ties_are_deterministic_and_hits_expose_spans() -> None:
    corpus = build_cutoff_corpus(
        [
            _document("z-doc", "old", "same terms"),
            _document("a-doc", "old", "same terms"),
        ],
        [_state("old", NOW)],
        NOW,
    )

    hits = LexicalRetriever(corpus).search("same terms")

    assert [hit.document_id for hit in hits] == ["a-doc", "z-doc"]
    assert hits[0].span_ids == ("a-doc-span",)


def test_empty_query_and_empty_corpus_return_no_hits() -> None:
    populated = build_cutoff_corpus(
        [_document("doc", "old", "text")], [_state("old", NOW)], NOW
    )
    empty = build_cutoff_corpus([], [], NOW)

    assert LexicalRetriever(populated).search("   ") == ()
    assert LexicalRetriever(empty).search("text") == ()


def test_duplicate_document_ids_are_rejected() -> None:
    document = _document("duplicate", "old", "text")
    with pytest.raises(RetrievalError, match="unique document_id"):
        build_cutoff_corpus([document, document], [_state("old", NOW)], NOW)


def test_ambiguous_snapshot_state_is_rejected() -> None:
    with pytest.raises(ValueError, match="incomparable or collide"):
        build_cutoff_corpus(
            [_document("first", "old", "text"), _document("second", "later", "text")],
            [_state("old", NOW), _state("later", NOW)],
            NOW,
        )


def test_recall_at_k_reports_an_explicit_eligible_denominator() -> None:
    hit = RetrievalHit("support", "old", ("support-span",), 1.0)
    metric = recall_at_k(
        {"answered": [hit], "abstain": []},
        {"answered": {"support"}, "miss": {"other"}, "abstain": set()},
        k=1,
    )

    assert (metric.retrieved_relevant_queries, metric.denominator, metric.value) == (
        1,
        2,
        0.5,
    )


@pytest.mark.parametrize("k", [0, -1])
def test_recall_at_k_rejects_invalid_k(k: int) -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        recall_at_k({}, {}, k=k)
