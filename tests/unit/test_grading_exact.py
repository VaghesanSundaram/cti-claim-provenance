from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from cti_provenance.claims.schema import (
    AtomicClaim,
    ClaimAnswer,
    ClaimObject,
    ClaimQualifiers,
    ClaimSubject,
    GoldAtomicClaim,
)
from cti_provenance.dataset.cases import AttackTreatment, BenchmarkCase
from cti_provenance.grading import grade_answer
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.normalize.spans import create_span
from cti_provenance.snapshot.admissibility import SnapshotState, SyntheticEvidence
from cti_provenance.snapshot.manifest import SnapshotManifest

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def _manifest(
    snapshot_id: str,
    *,
    source_name: str = "nvd",
    available_by: datetime = BASE_TIME,
) -> SnapshotManifest:
    source_class = "government" if source_name == "nvd" else "synthetic"
    return SnapshotManifest.model_validate(
        {
            "snapshot_id": snapshot_id,
            "source_name": source_name,
            "source_class": source_class,
            "source_url": (
                "https://services.nvd.nist.gov/rest/json/cves/2.0"
                if source_name == "nvd"
                else "urn:cti-provenance:test:grading"
            ),
            "retrieved_at_utc": available_by,
            "http_status": 200,
            "http_etag": None,
            "http_last_modified": None,
            "effective_date_if_known": None,
            "effective_date_basis": "unknown",
            "available_by_utc": available_by,
            "available_by_basis": (
                "observed_retrieval" if source_name == "nvd" else "synthetic_fixture"
            ),
            "upstream_identifier": "CVE-SYNTHETIC-0001",
            "upstream_version": None if source_name == "nvd" else "1",
            "media_type": "application/json",
            "byte_length": 10,
            "sha256": hashlib.sha256(snapshot_id.encode()).hexdigest(),
            "raw_blob_path": f"fixtures/{snapshot_id}.json",
            "fetcher_version": "fixture-v1",
            "normalization_version": "normalize-v1",
            "license_or_terms_note": "synthetic grading fixture",
        }
    )


def _state(manifest: SnapshotManifest) -> SnapshotState:
    if manifest.source_name == "synthetic_control":
        return SnapshotState(
            manifest,
            synthetic_evidence=SyntheticEvidence("fixture-generator-v1", 1),
        )
    return SnapshotState(manifest)


def _document(
    manifest: SnapshotManifest,
    *,
    document_id: str = "doc-1",
    represented_source_name: str | None = None,
) -> NormalizedDocument:
    text = "2025-12-31"
    span = create_span(
        span_id="published",
        field_path="/published",
        normalized_text=text,
        start_char=0,
        end_char=len(text),
        raw_locator="/published",
        raw_locator_unavailable_reason=None,
        raw_snapshot_id=manifest.snapshot_id,
        raw_snapshot_sha256=manifest.sha256,
        normalization_version=manifest.normalization_version,
    )
    fields: dict[str, str] = {}
    if represented_source_name is not None:
        fields["represented_source_name"] = represented_source_name
    return NormalizedDocument.model_validate(
        {
            "document_id": document_id,
            "snapshot_id": manifest.snapshot_id,
            "upstream_entity_id": "CVE-SYNTHETIC-0001",
            "title": "fixture",
            "canonical_url": "urn:cti-provenance:test:document",
            "published_at": None,
            "modified_at": None,
            "source_name": manifest.source_name,
            "source_class": manifest.source_class,
            "normalization_version": manifest.normalization_version,
            "normalized_text": text,
            "normalized_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "fields": fields,
            "spans": [span],
        }
    )


def _claim(
    claim_id: str,
    *,
    evidence_id: str = "doc-1:published",
    gold: bool,
    authority: str = "nvd",
    value: str = "2025-12-31",
) -> AtomicClaim:
    claim_type = GoldAtomicClaim if gold else AtomicClaim
    return claim_type(
        claim_id=claim_id,
        subject=ClaimSubject(type="cve", id="CVE-SYNTHETIC-0001"),
        predicate="cve.published_at",
        object=ClaimObject(value=value, datatype="date"),
        qualifiers=ClaimQualifiers(
            authority=authority,
            cvss_version=None,
            product=None,
            ecosystem=None,
        ),
        evidence_ids=[evidence_id],
        confidence=1.0,
    )


def _case(
    *,
    expected: list[GoldAtomicClaim],
    should_abstain: bool = False,
    temporal_truth_mode: str = "observed_snapshot",
    allowed_snapshot_ids: list[str] | None = None,
    as_of: datetime = BASE_TIME,
    template_family_id: str = "nvd-published-at",
) -> BenchmarkCase:
    return BenchmarkCase.model_validate(
        {
            "case_id": "case-1",
            "case_family_id": "family-1",
            "entity_family_id": "entity-1",
            "template_family_id": template_family_id,
            "split": "dev",
            "as_of": as_of,
            "temporal_truth_mode": temporal_truth_mode,
            "question": "When was the record published?",
            "allowed_snapshot_ids": allowed_snapshot_ids or ["snapshot-1"],
            "expected_claims": expected,
            "required_authority_policy_ids": ["nvd-publication-time"],
            "should_abstain": should_abstain,
            "abstention_reason": "insufficient evidence" if should_abstain else None,
            "paired_case_id": None,
            "attack": AttackTreatment(
                family="none",
                treatment_document_ids=[],
                generation_version=None,
            ),
        }
    )


def _answer(
    *,
    claims: list[AtomicClaim],
    abstained: bool = False,
    case_id: str = "case-1",
    as_of: datetime = BASE_TIME,
) -> ClaimAnswer:
    return ClaimAnswer(
        answer_id="answer-1",
        run_id="run-1",
        case_id=case_id,
        as_of=as_of,
        claims=claims,
        abstained=abstained,
        abstention_reason="insufficient evidence" if abstained else None,
        narrative=None,
    )


def test_supported_exact_claim_has_resolved_eligible_authoritative_evidence() -> None:
    manifest = _manifest("snapshot-1")
    document = _document(manifest)
    case = _case(expected=[_claim("expected", gold=True)])
    grades = grade_answer(
        case,
        _answer(claims=[_claim("generated", gold=False)]),
        [document],
        [_state(manifest)],
    )

    assert len(grades) == 1
    assert grades[0].claim_support == "supported"
    assert grades[0].value_match == "exact"
    assert grades[0].evidence_assessments[0].model_dump() == {
        "evidence_id": "doc-1:published",
        "resolution": "resolved",
        "entailment": "supported",
        "temporality": "admissible",
        "authority": "accepted",
        "span_hash_match": True,
    }
    assert grades == grade_answer(
        case,
        _answer(claims=[_claim("generated", gold=False)]),
        [document],
        [_state(manifest)],
    )


def test_post_cutoff_snapshot_cannot_support_a_claim() -> None:
    later = _manifest("snapshot-later", available_by=BASE_TIME + timedelta(days=1))
    document = _document(later)
    evidence_id = "doc-1:published"
    case = _case(
        expected=[_claim("expected", gold=True, evidence_id=evidence_id)],
        allowed_snapshot_ids=["snapshot-later"],
    )
    grade = grade_answer(
        case,
        _answer(claims=[_claim("generated", gold=False, evidence_id=evidence_id)]),
        [document],
        [_state(later)],
    )[0]

    assert grade.claim_support == "unsupported"
    assessment = grade.evidence_assessments[0]
    assert assessment.resolution == "wrong_snapshot"
    assert assessment.temporality == "post_cutoff"


def test_wrong_authority_and_unresolved_span_are_unsupported() -> None:
    manifest = _manifest("snapshot-1")
    document = _document(manifest)
    wrong_authority = _claim("generated", gold=False, authority="cisa_kev")
    wrong_authority_expected = _claim("expected", gold=True, authority="cisa_kev")
    grade = grade_answer(
        _case(expected=[wrong_authority_expected]),
        _answer(claims=[wrong_authority]),
        [document],
        [_state(manifest)],
    )[0]
    assert grade.evidence_assessments[0].authority == "wrong"
    assert grade.claim_support == "unsupported"

    corrupted = document.model_copy(update={"normalized_text": "2025-12-30"})
    corrupted_grade = grade_answer(
        _case(expected=[_claim("expected", gold=True)]),
        _answer(claims=[_claim("generated", gold=False)]),
        [corrupted],
        [_state(manifest)],
    )[0]
    assert corrupted_grade.evidence_assessments[0].span_hash_match is False
    assert corrupted_grade.evidence_assessments[0].entailment == "unsupported"
    assert corrupted_grade.claim_support == "unsupported"


def test_generated_false_positive_and_expected_false_negative_are_typed() -> None:
    manifest = _manifest("snapshot-1")
    document = _document(manifest)
    false_positive = grade_answer(
        _case(expected=[], should_abstain=True),
        _answer(claims=[_claim("generated", gold=False)]),
        [document],
        [_state(manifest)],
    )[0]
    assert false_positive.expected_claim_id is None
    assert false_positive.abstention_outcome == "missed"
    assert false_positive.claim_support == "unsupported"

    false_negative = grade_answer(
        _case(expected=[_claim("expected", gold=True)]),
        _answer(claims=[], abstained=True),
        [document],
        [_state(manifest)],
    )[0]
    assert false_negative.generated_claim_id is None
    assert false_negative.abstention_outcome == "unnecessary"
    assert false_negative.claim_support == "unsupported"


def test_correct_abstention_uses_only_explicit_template_mapping() -> None:
    case = _case(expected=[], should_abstain=True)
    grade = grade_answer(case, _answer(claims=[], abstained=True), [], [])[0]
    assert grade.predicate == "cve.published_at"
    assert grade.abstention_outcome == "correct"
    assert grade.claim_support == "ungradable"

    unknown = _case(
        expected=[],
        should_abstain=True,
        template_family_id="unknown-template",
    )
    with pytest.raises(ValueError, match="unknown template_family_id"):
        grade_answer(unknown, _answer(claims=[], abstained=True), [], [])


def test_case_identity_and_cutoff_must_match_answer() -> None:
    case = _case(expected=[_claim("expected", gold=True)])
    with pytest.raises(ValueError, match="case_id"):
        grade_answer(case, _answer(claims=[], case_id="other"), [], [])
    with pytest.raises(ValueError, match="as_of"):
        grade_answer(
            case,
            _answer(claims=[], as_of=BASE_TIME + timedelta(seconds=1)),
            [],
            [],
        )


def test_duplicate_document_snapshot_and_span_indexes_are_rejected() -> None:
    manifest = _manifest("snapshot-1")
    state = _state(manifest)
    document = _document(manifest)
    case = _case(expected=[_claim("expected", gold=True)])
    answer = _answer(claims=[_claim("generated", gold=False)])

    with pytest.raises(ValueError, match="duplicate document_id"):
        grade_answer(case, answer, [document, document], [state])
    with pytest.raises(ValueError, match="duplicate snapshot_id"):
        grade_answer(case, answer, [document], [state, state])

    duplicate_spans = document.model_copy(
        update={"spans": [document.spans[0], document.spans[0]]}
    )
    with pytest.raises(ValueError, match="duplicate span_id"):
        grade_answer(case, answer, [duplicate_spans], [state])


def test_represented_source_is_accepted_only_for_synthetic_control_case() -> None:
    manifest = _manifest("snapshot-1", source_name="synthetic_control")
    document = _document(manifest, represented_source_name="nvd")
    expected = _claim("expected", gold=True)
    answer = _answer(claims=[_claim("generated", gold=False)])
    synthetic_case = _case(
        expected=[expected],
        temporal_truth_mode="synthetic_control",
    )
    synthetic_grade = grade_answer(
        synthetic_case, answer, [document], [_state(manifest)]
    )[0]
    assert synthetic_grade.evidence_assessments[0].authority == "accepted"
    assert synthetic_grade.claim_support == "supported"

    real_mode_case = _case(expected=[expected])
    real_mode_grade = grade_answer(
        real_mode_case, answer, [document], [_state(manifest)]
    )[0]
    assert real_mode_grade.evidence_assessments[0].authority == "wrong"
    assert real_mode_grade.claim_support == "unsupported"
