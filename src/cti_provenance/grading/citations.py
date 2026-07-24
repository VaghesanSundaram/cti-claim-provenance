"""Exact evidence-index construction and citation assessment."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from cti_provenance.claims.schema import AtomicClaim, GoldAtomicClaim
from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.grading.authority import (
    AUTHORITY_POLICY_VERSION,
    assess_authority,
)
from cti_provenance.grading.schema import EvidenceAssessment
from cti_provenance.grading.temporal import TemporalSnapshotView
from cti_provenance.normalize.common import EvidenceSpan, NormalizedDocument


@dataclass(frozen=True)
class IndexedEvidence:
    """One globally unique ``document_id:span_id`` address."""

    document: NormalizedDocument
    span: EvidenceSpan
    integrity_valid: bool


@dataclass(frozen=True)
class EvidenceIndex:
    """Validated deterministic indexes used by the grader."""

    documents: dict[str, NormalizedDocument]
    evidence: dict[str, IndexedEvidence]


def _document_hashes_are_valid(
    document: NormalizedDocument,
    span: EvidenceSpan,
    temporal_view: TemporalSnapshotView,
) -> bool:
    text_hash = hashlib.sha256(document.normalized_text.encode("utf-8")).hexdigest()
    if text_hash != document.normalized_text_sha256:
        return False
    if span.start_char < 0 or span.end_char <= span.start_char:
        return False
    if span.end_char > len(document.normalized_text):
        return False
    text = document.normalized_text[span.start_char : span.end_char]
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != span.text_sha256:
        return False
    if span.raw_snapshot_id != document.snapshot_id:
        return False
    if span.normalization_version != document.normalization_version:
        return False
    state = temporal_view.states_by_snapshot_id.get(document.snapshot_id)
    if state is None:
        return False
    manifest = state.manifest
    return (
        span.raw_snapshot_sha256 == manifest.sha256
        and document.source_name == manifest.source_name
        and document.source_class == manifest.source_class
        and document.normalization_version == manifest.normalization_version
    )


def build_evidence_index(
    documents: list[NormalizedDocument],
    temporal_view: TemporalSnapshotView,
) -> EvidenceIndex:
    """Build unique document/span/evidence indexes and recompute integrity."""

    document_index: dict[str, NormalizedDocument] = {}
    evidence_index: dict[str, IndexedEvidence] = {}
    for document in documents:
        if document.document_id in document_index:
            raise ValueError(f"duplicate document_id {document.document_id!r}")
        document_index[document.document_id] = document

        local_span_ids: set[str] = set()
        for span in document.spans:
            if span.span_id in local_span_ids:
                raise ValueError(
                    f"duplicate span_id {span.span_id!r} in "
                    f"document {document.document_id!r}"
                )
            local_span_ids.add(span.span_id)
            evidence_id = f"{document.document_id}:{span.span_id}"
            if evidence_id in evidence_index:
                raise ValueError(f"duplicate evidence_id {evidence_id!r}")
            evidence_index[evidence_id] = IndexedEvidence(
                document=document,
                span=span,
                integrity_valid=_document_hashes_are_valid(
                    document, span, temporal_view
                ),
            )
    return EvidenceIndex(document_index, evidence_index)


def assess_citations(
    *,
    case: BenchmarkCase,
    claim: AtomicClaim,
    expected: GoldAtomicClaim | None,
    value_exact: bool,
    evidence_index: EvidenceIndex,
    temporal_view: TemporalSnapshotView,
    authority_policy_version: str = AUTHORITY_POLICY_VERSION,
) -> list[EvidenceAssessment]:
    """Assess generated citations without fuzzy or model entailment."""

    expected_evidence = set(expected.evidence_ids) if expected is not None else set()
    assessments: list[EvidenceAssessment] = []
    for evidence_id in sorted(claim.evidence_ids):
        indexed = evidence_index.evidence.get(evidence_id)
        if indexed is None:
            assessments.append(
                EvidenceAssessment(
                    evidence_id=evidence_id,
                    resolution="missing",
                    entailment="unsupported",
                    temporality="not_applicable",
                    authority="not_applicable",
                    span_hash_match=None,
                )
            )
            continue

        document = indexed.document
        snapshot_id = document.snapshot_id
        eligible = snapshot_id in temporal_view.eligible_snapshot_ids
        resolution: Literal["resolved", "wrong_snapshot"] = (
            "resolved" if eligible else "wrong_snapshot"
        )

        if snapshot_id in temporal_view.invalid_basis_snapshot_ids:
            temporality: Literal[
                "admissible", "post_cutoff", "invalid_basis", "not_applicable"
            ] = "invalid_basis"
        elif snapshot_id in temporal_view.post_cutoff_snapshot_ids:
            temporality = "post_cutoff"
        elif snapshot_id in temporal_view.states_by_snapshot_id:
            temporality = "admissible"
        else:
            temporality = "not_applicable"

        supports_generated = (
            expected is not None
            and value_exact
            and evidence_id in expected_evidence
            and indexed.integrity_valid
        )
        assessments.append(
            EvidenceAssessment(
                evidence_id=evidence_id,
                resolution=resolution,
                entailment="supported" if supports_generated else "unsupported",
                temporality=temporality,
                authority=assess_authority(
                    case,
                    claim,
                    document,
                    authority_policy_version=authority_policy_version,
                ),
                span_hash_match=indexed.integrity_valid if eligible else None,
            )
        )
    return assessments
