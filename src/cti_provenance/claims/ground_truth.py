"""Fail-closed loading and cross-validation for Phase 2 development cases."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cti_provenance.dataset import BenchmarkCase
from cti_provenance.normalize import NormalizedDocument, resolve_span
from cti_provenance.snapshot import SnapshotState, select_admissible_by_entity

PHASE2_CASES_PATH = Path("data/benchmark/dev/phase2-cases.jsonl")
PHASE2_REVIEWS_PATH = Path("annotations/phase2-plumbing-review.jsonl")


class GroundTruthError(ValueError):
    """The development cases do not bind to the frozen offline corpus."""


ReviewNotesCode = Literal[
    "plumbing_only",
    "publisher_declared_version_evidence_only",
    "synthetic_contradiction_pair",
    "cutoff_abstention",
]


class CaseReview(BaseModel):
    """Manager review evidence for one development question and its spans."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case_id: str
    reviewer_role: Literal["manager"]
    reviewed_at_utc: datetime
    question_status: Literal["pass"]
    claim_status: Literal["pass", "not_applicable"]
    evidence_status: Literal["pass", "not_applicable"]
    evidence_ids: list[str]
    notes_code: ReviewNotesCode


def _expected_review_code(case: BenchmarkCase) -> ReviewNotesCode:
    if case.should_abstain:
        return "cutoff_abstention"
    if case.attack.family == "contradiction":
        return "synthetic_contradiction_pair"
    if any(
        claim.predicate in {"vendor.affected_versions", "vendor.fixed_versions"}
        for claim in case.expected_claims
    ):
        return "publisher_declared_version_evidence_only"
    return "plumbing_only"


def _load_cases(path: Path) -> list[BenchmarkCase]:
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise GroundTruthError("cannot read the Phase 2 case file") from exc
    cases: list[BenchmarkCase] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            cases.append(BenchmarkCase.model_validate_json(line))
        except ValueError as exc:
            raise GroundTruthError(
                f"invalid Phase 2 benchmark case on line {line_number}"
            ) from exc
    return cases


def _load_reviews(path: Path) -> list[CaseReview]:
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise GroundTruthError("cannot read the Phase 2 review file") from exc
    reviews: list[CaseReview] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            reviews.append(CaseReview.model_validate_json(line))
        except ValueError as exc:
            raise GroundTruthError(
                f"invalid Phase 2 case review on line {line_number}"
            ) from exc
    return reviews


def load_phase2_cases(
    root: Path,
    *,
    states: list[SnapshotState],
    documents: list[NormalizedDocument],
) -> list[BenchmarkCase]:
    """Load 12-20 reviewed development cases and prove every corpus binding."""
    cases = _load_cases(root / PHASE2_CASES_PATH)
    if not 12 <= len(cases) <= 20:
        raise GroundTruthError("Phase 2 requires 12-20 development cases")
    case_by_id = {case.case_id: case for case in cases}
    if len(case_by_id) != len(cases) or any(case.split != "dev" for case in cases):
        raise GroundTruthError("Phase 2 cases must have unique IDs and split=dev")
    if any(
        case.entity_family_id != "log4shell-plumbing-only"
        or case.temporal_truth_mode != "synthetic_control"
        for case in cases
    ):
        raise GroundTruthError("Phase 2 cases must retain the plumbing-only label")
    predicates = {claim.predicate for case in cases for claim in case.expected_claims}
    if len(predicates) < 3:
        raise GroundTruthError("Phase 2 cases must cover at least three predicates")
    reviews = _load_reviews(root / PHASE2_REVIEWS_PATH)
    review_by_case = {review.case_id: review for review in reviews}
    if len(review_by_case) != len(reviews) or set(review_by_case) != set(case_by_id):
        raise GroundTruthError("every Phase 2 case requires exactly one review")
    for case in cases:
        review = review_by_case[case.case_id]
        expected_evidence = sorted(
            {
                evidence_id
                for claim in case.expected_claims
                for evidence_id in claim.evidence_ids
            }
        )
        if (
            review.reviewed_at_utc.utcoffset() != UTC.utcoffset(review.reviewed_at_utc)
            or review.evidence_ids != expected_evidence
            or review.notes_code != _expected_review_code(case)
            or (
                case.should_abstain
                and (
                    review.claim_status != "not_applicable"
                    or review.evidence_status != "not_applicable"
                )
            )
            or (
                not case.should_abstain
                and (review.claim_status != "pass" or review.evidence_status != "pass")
            )
        ):
            raise GroundTruthError(f"case {case.case_id} review is inconsistent")

    state_ids = {state.manifest.snapshot_id for state in states}
    document_by_id = {document.document_id: document for document in documents}
    if len(document_by_id) != len(documents):
        raise GroundTruthError("normalized document IDs must be unique")
    evidence_index: dict[str, tuple[NormalizedDocument, str]] = {}
    for document in documents:
        if document.snapshot_id not in state_ids:
            raise GroundTruthError("normalized document references an unknown snapshot")
        for span in document.spans:
            evidence_id = f"{document.document_id}:{span.span_id}"
            if evidence_id in evidence_index:
                raise GroundTruthError("evidence IDs must be globally unique")
            resolve_span(span, document.normalized_text)
            evidence_index[evidence_id] = (document, span.span_id)

    for case in cases:
        selected_ids = {
            manifest.snapshot_id
            for manifest in select_admissible_by_entity(states, case.as_of).values()
        }
        if not set(case.allowed_snapshot_ids) <= selected_ids:
            raise GroundTruthError(
                f"case {case.case_id} allows a post-cutoff or invalid snapshot"
            )
        if case.should_abstain and case.allowed_snapshot_ids:
            raise GroundTruthError(
                f"plumbing abstention case {case.case_id} must have an empty corpus"
            )
        for claim in case.expected_claims:
            for evidence_id in claim.evidence_ids:
                evidence = evidence_index.get(evidence_id)
                if evidence is None:
                    raise GroundTruthError(
                        f"case {case.case_id} references missing evidence"
                    )
                document, _span_id = evidence
                if document.snapshot_id not in case.allowed_snapshot_ids:
                    raise GroundTruthError(
                        f"case {case.case_id} evidence is outside its corpus"
                    )
        for treatment_document_id in case.attack.treatment_document_ids:
            treatment = document_by_id.get(treatment_document_id)
            if (
                treatment is None
                or treatment.snapshot_id not in case.allowed_snapshot_ids
            ):
                raise GroundTruthError(
                    f"case {case.case_id} treatment is outside its corpus"
                )

    paired = [case for case in cases if case.paired_case_id is not None]
    if (
        len(paired) != 2
        or sum(case.attack.family == "contradiction" for case in paired) != 1
        or sum(case.attack.family == "none" for case in paired) != 1
    ):
        raise GroundTruthError(
            "Phase 2 requires exactly one clean/contradiction reciprocal pair"
        )
    for case in paired:
        assert case.paired_case_id is not None
        other = case_by_id.get(case.paired_case_id)
        if (
            other is None
            or other.paired_case_id != case.case_id
            or other.case_family_id != case.case_family_id
            or other.entity_family_id != case.entity_family_id
            or other.template_family_id != case.template_family_id
            or other.as_of != case.as_of
            or other.question != case.question
            or [
                claim.model_dump(exclude={"claim_id"})
                for claim in other.expected_claims
            ]
            != [
                claim.model_dump(exclude={"claim_id"}) for claim in case.expected_claims
            ]
            or {case.attack.family, other.attack.family} != {"none", "contradiction"}
        ):
            raise GroundTruthError("Phase 2 attack pair is not reciprocal and matched")
        attacked = case if case.attack.family != "none" else other
        clean = other if attacked is case else case
        treatment_snapshots = {
            document_by_id[document_id].snapshot_id
            for document_id in attacked.attack.treatment_document_ids
        }
        if set(attacked.allowed_snapshot_ids) - set(
            clean.allowed_snapshot_ids
        ) != treatment_snapshots or set(clean.allowed_snapshot_ids) - set(
            attacked.allowed_snapshot_ids
        ):
            raise GroundTruthError(
                "Phase 2 attack pair corpus delta is not exactly its treatment"
            )
    return sorted(cases, key=lambda case: case.case_id)
