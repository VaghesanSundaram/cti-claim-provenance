"""Frozen benchmark-case contract."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from cti_provenance.claims.schema import GoldAtomicClaim, claim_match_key


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use the UTC offset")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc_datetime)]
NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class AttackTreatment(BaseModel):
    """Declared clean/adversarial case treatment."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    family: Literal[
        "none",
        "injection",
        "stale",
        "contradiction",
        "laundering",
        "later_data_leak",
    ]
    treatment_document_ids: list[str]
    generation_version: str | None

    @field_validator("treatment_document_ids")
    @classmethod
    def unique_document_ids(cls, ids: list[str]) -> list[str]:
        if len(ids) != len(set(ids)):
            raise ValueError("treatment_document_ids must be unique")
        return ids

    @model_validator(mode="after")
    def validate_attack_fields(self) -> Self:
        if self.family == "none":
            if self.treatment_document_ids or self.generation_version is not None:
                raise ValueError("clean cases cannot declare treatment artifacts")
        elif not self.treatment_document_ids or not self.generation_version:
            raise ValueError(
                "adversarial cases require treatment documents and a version"
            )
        return self


class BenchmarkCase(BaseModel):
    """One point-in-time question with frozen expected claims."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case_id: NonEmptyString
    case_family_id: NonEmptyString
    entity_family_id: NonEmptyString
    template_family_id: NonEmptyString
    split: Literal["dev", "validation", "holdout"]
    as_of: UtcDateTime
    temporal_truth_mode: Literal[
        "observed_snapshot",
        "upstream_versioned",
        "reconstructed_history",
        "synthetic_control",
    ]
    question: NonEmptyString
    allowed_snapshot_ids: list[NonEmptyString]
    expected_claims: list[GoldAtomicClaim]
    required_authority_policy_ids: list[NonEmptyString] = Field(min_length=1)
    should_abstain: bool
    abstention_reason: str | None
    paired_case_id: str | None
    attack: AttackTreatment

    @model_validator(mode="after")
    def validate_case(self) -> Self:
        if len(self.allowed_snapshot_ids) != len(set(self.allowed_snapshot_ids)):
            raise ValueError("allowed_snapshot_ids must be unique")
        if len(self.required_authority_policy_ids) != len(
            set(self.required_authority_policy_ids)
        ):
            raise ValueError("required_authority_policy_ids must be unique")

        claim_ids = [claim.claim_id for claim in self.expected_claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("expected claim_id values must be unique")
        keys = [claim_match_key(claim) for claim in self.expected_claims]
        if len(keys) != len(set(keys)):
            raise ValueError(
                "expected claims must be unique by the frozen matching key; "
                "represent multiple values as one typed set/list"
            )

        if self.should_abstain:
            if self.expected_claims:
                raise ValueError("abstention cases cannot contain expected claims")
            if not self.abstention_reason:
                raise ValueError("abstention cases require abstention_reason")
        else:
            if not self.expected_claims:
                raise ValueError(
                    "answerable cases require at least one expected material claim"
                )
            if self.abstention_reason is not None:
                raise ValueError("answerable cases cannot set abstention_reason")
        if self.paired_case_id == self.case_id:
            raise ValueError("paired_case_id cannot refer to the same case")
        return self
