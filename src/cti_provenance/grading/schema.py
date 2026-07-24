"""Frozen grader records and deterministic one-to-one claim matching."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from cti_provenance.claims.schema import (
    AtomicClaim,
    GoldAtomicClaim,
    PredicateName,
    canonical_typed_value,
    claim_match_key,
)

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class EvidenceAssessment(BaseModel):
    """Deterministic and human-linked decisions for one cited span."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evidence_id: NonEmptyString
    resolution: Literal["resolved", "missing", "wrong_snapshot"]
    entailment: Literal["supported", "partial", "unsupported", "not_applicable"]
    temporality: Literal["admissible", "post_cutoff", "invalid_basis", "not_applicable"]
    authority: Literal["accepted", "weak", "wrong", "unresolved", "not_applicable"]
    span_hash_match: bool | None

    @model_validator(mode="after")
    def validate_resolution_hash_relationship(self) -> Self:
        if self.resolution == "resolved" and self.span_hash_match is None:
            raise ValueError("resolved evidence requires a span_hash_match decision")
        if self.resolution != "resolved" and self.span_hash_match is not None:
            raise ValueError("unresolved evidence cannot declare span_hash_match")
        return self


class ClaimGrade(BaseModel):
    """Grader-owned claim assessment, separate from generated output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    claim_grade_id: NonEmptyString
    run_id: NonEmptyString
    case_id: NonEmptyString
    generated_claim_id: NonEmptyString | None
    expected_claim_id: NonEmptyString | None
    predicate: PredicateName
    value_match: Literal["exact", "partial", "mismatch", "not_applicable"]
    evidence_assessments: list[EvidenceAssessment]
    contradiction: Literal[
        "none", "lower_authority", "peer_authority", "primary_authority"
    ]
    claim_support: Literal["supported", "unsupported", "contradictory", "ungradable"]
    abstention_outcome: Literal["correct", "unnecessary", "missed", "not_applicable"]
    generated_confidence: float | None = Field(ge=0.0, le=1.0)
    deterministic_grader_version: NonEmptyString
    authority_policy_version: NonEmptyString
    normalization_version: NonEmptyString
    human_judgment_id: str | None
    notes_code: str | None

    @field_validator("evidence_assessments")
    @classmethod
    def unique_evidence_assessments(
        cls, assessments: list[EvidenceAssessment]
    ) -> list[EvidenceAssessment]:
        ids = [assessment.evidence_id for assessment in assessments]
        if len(ids) != len(set(ids)):
            raise ValueError("evidence assessments must have unique evidence_id values")
        return assessments

    @model_validator(mode="after")
    def validate_grade_relationships(self) -> Self:
        has_generated = self.generated_claim_id is not None
        has_expected = self.expected_claim_id is not None
        if has_generated != (self.generated_confidence is not None):
            raise ValueError(
                "generated_confidence must be present if and only if "
                "generated_claim_id is present"
            )
        if self.evidence_assessments and not has_generated:
            raise ValueError("evidence assessments require a generated claim")

        matched = has_generated and has_expected
        if matched and self.value_match == "not_applicable":
            raise ValueError("matched claims require a value comparison")
        if not matched and self.value_match != "not_applicable":
            raise ValueError("unmatched claims require value_match=not_applicable")
        if self.value_match == "exact" and not matched:
            raise ValueError("exact value match requires both claim IDs")

        is_contradictory = self.contradiction != "none"
        if is_contradictory != (self.claim_support == "contradictory"):
            raise ValueError(
                "claim_support must be contradictory if and only if "
                "contradiction is not none"
            )

        if not has_generated and not has_expected:
            if self.abstention_outcome != "correct":
                raise ValueError(
                    "a grade with no generated or expected claim represents "
                    "only a correct abstention"
                )
            if (
                self.claim_support != "ungradable"
                or self.contradiction != "none"
                or self.evidence_assessments
            ):
                raise ValueError(
                    "correct abstention requires ungradable support, no "
                    "contradiction, and no evidence assessments"
                )
        elif not matched and self.claim_support != "unsupported":
            raise ValueError("unmatched false positives/negatives are unsupported")

        if self.abstention_outcome == "correct" and (has_generated or has_expected):
            raise ValueError(
                "correct abstention requires no generated or expected claim"
            )
        if self.abstention_outcome == "unnecessary" and not (
            has_expected and not has_generated
        ):
            raise ValueError(
                "unnecessary abstention requires an expected claim and no "
                "generated claim"
            )
        if self.abstention_outcome == "missed" and not (
            has_generated and not has_expected
        ):
            raise ValueError(
                "missed abstention requires a generated claim and no expected claim"
            )

        if self.claim_support == "supported":
            fully_supporting = any(
                assessment.resolution == "resolved"
                and assessment.entailment == "supported"
                and assessment.temporality == "admissible"
                and assessment.authority == "accepted"
                and assessment.span_hash_match is True
                for assessment in self.evidence_assessments
            )
            if (
                not matched
                or self.value_match != "exact"
                or self.contradiction != "none"
                or not fully_supporting
            ):
                raise ValueError(
                    "supported claims require matched exact values, no "
                    "contradiction, and fully valid evidence"
                )
        return self


class ClaimMatch(BaseModel):
    """One deterministic expected/generated diagnostic pairing."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    expected_claim_id: NonEmptyString
    generated_claim_id: NonEmptyString
    exact: bool


class ClaimMatchingResult(BaseModel):
    """Complete one-to-one partition used by downstream deterministic graders."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    matches: list[ClaimMatch]
    unmatched_expected_claim_ids: list[str]
    unmatched_generated_claim_ids: list[str]


def match_claims(
    expected_claims: list[GoldAtomicClaim],
    generated_claims: list[AtomicClaim],
) -> ClaimMatchingResult:
    """Apply the frozen exact one-to-one matching algorithm.

    Expected keys and all claim IDs must be unique. Generated claims are
    partitioned by the expected matching key and sorted by stable ``claim_id``.
    The first exact typed-value candidate wins; otherwise the first candidate is
    paired for mismatch diagnostics. Every other candidate remains an unmatched
    false positive. There is no fuzzy or model-selected tie-breaking.
    """

    expected_ids = [claim.claim_id for claim in expected_claims]
    if len(expected_ids) != len(set(expected_ids)):
        raise ValueError("expected claim_id values must be unique")
    generated_ids = [claim.claim_id for claim in generated_claims]
    if len(generated_ids) != len(set(generated_ids)):
        raise ValueError("generated claim_id values must be unique")

    expected_keys = [claim_match_key(claim) for claim in expected_claims]
    if len(expected_keys) != len(set(expected_keys)):
        raise ValueError("expected claims must be unique by the frozen matching key")

    available: dict[tuple[object, ...], list[AtomicClaim]] = {}
    for claim in sorted(generated_claims, key=lambda item: item.claim_id):
        available.setdefault(claim_match_key(claim), []).append(claim)

    matches: list[ClaimMatch] = []
    unmatched_expected: list[str] = []
    used_generated_ids: set[str] = set()

    for expected in sorted(expected_claims, key=lambda item: item.claim_id):
        candidates = available.get(claim_match_key(expected), [])
        if not candidates:
            unmatched_expected.append(expected.claim_id)
            continue
        expected_value = canonical_typed_value(expected)
        exact_candidate = next(
            (
                candidate
                for candidate in candidates
                if canonical_typed_value(candidate) == expected_value
            ),
            None,
        )
        selected = exact_candidate if exact_candidate is not None else candidates[0]
        used_generated_ids.add(selected.claim_id)
        matches.append(
            ClaimMatch(
                expected_claim_id=expected.claim_id,
                generated_claim_id=selected.claim_id,
                exact=exact_candidate is not None,
            )
        )

    unmatched_generated = sorted(set(generated_ids) - used_generated_ids)
    return ClaimMatchingResult(
        matches=matches,
        unmatched_expected_claim_ids=unmatched_expected,
        unmatched_generated_claim_ids=unmatched_generated,
    )
