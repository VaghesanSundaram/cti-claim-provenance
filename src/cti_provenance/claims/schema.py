"""Atomic claims and provider-facing generated answer envelopes."""

from __future__ import annotations

import json
from collections.abc import Hashable, Sequence
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use the UTC offset")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc_datetime)]
NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
EvidenceId = Annotated[
    str, StringConstraints(strip_whitespace=True, pattern=r"^[^:\s]+:[^:\s]+$")
]
type ClaimScalar = StrictBool | StrictStr | Decimal
type ClaimValue = ClaimScalar | list[str] | dict[str, JsonValue]
PredicateName = Literal[
    "cve.affected_versions",
    "directive.required_action",
    "cve.published_at",
    "cve.modified_at",
    "cve.cvss.score",
    "kev.is_member",
    "kev.date_added",
    "kev.due_date",
    "kev.ransomware_campaign_use",
    "nvd.cpe_applicability",
    "vendor.affected_versions",
    "vendor.fixed_versions",
    "vendor.recommended_action",
    "vendor.release_affected_versions",
    "vendor.security_release_versions",
    "vendor.cve_fixed_release",
    "attack.relationship_present",
    "attack.platforms",
    "source.temporal_change",
    "source.authority_divergence",
    "source.multi_source_synthesis",
]


class ClaimSubject(BaseModel):
    """Typed claim subject."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["cve", "product", "advisory", "attack_object"]
    id: NonEmptyString


class ClaimObject(BaseModel):
    """Typed claim value.

    Datatype/value consistency is enforced locally because JSON Schema cannot
    safely infer a discriminator from two sibling properties.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    value: ClaimValue
    datatype: Literal[
        "boolean",
        "string",
        "date",
        "decimal",
        "version_set",
        "identifier_set",
    ]

    @model_validator(mode="after")
    def validate_datatype(self) -> Self:
        value = self.value
        if self.datatype == "boolean":
            valid = isinstance(value, bool)
        elif self.datatype in {"string", "date"}:
            valid = isinstance(value, str)
            if isinstance(value, str) and self.datatype == "date":
                try:
                    date.fromisoformat(value)
                except ValueError as exc:
                    raise ValueError(
                        "date values must use ISO 8601 YYYY-MM-DD"
                    ) from exc
        elif self.datatype == "decimal":
            valid = isinstance(value, Decimal) and not isinstance(value, bool)
        elif self.datatype == "identifier_set":
            valid = (
                isinstance(value, list)
                and all(isinstance(item, str) and item for item in value)
                and len(value) == len(set(value))
            )
        else:
            valid = (
                isinstance(value, list)
                and all(isinstance(item, str) and item for item in value)
                and len(value) == len(set(value))
            ) or (isinstance(value, dict) and bool(value))
        if not valid:
            raise ValueError(f"value is inconsistent with datatype {self.datatype!r}")
        return self


class ClaimQualifiers(BaseModel):
    """Frozen qualifier vocabulary used by the first benchmark version."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    authority: NonEmptyString | None
    cvss_version: NonEmptyString | None
    product: NonEmptyString | None
    ecosystem: NonEmptyString | None


class AtomicClaim(BaseModel):
    """Generated atomic claim; it contains no grader-owned decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    claim_id: NonEmptyString
    subject: ClaimSubject
    predicate: PredicateName
    object: ClaimObject
    qualifiers: ClaimQualifiers
    evidence_ids: list[EvidenceId]
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, evidence_ids: list[str]) -> list[str]:
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence_ids must be unique within a claim")
        return evidence_ids


class GoldAtomicClaim(AtomicClaim):
    """Expected claim; gold material claims always cite frozen evidence."""

    evidence_ids: list[EvidenceId] = Field(min_length=1)


class ClaimEvidenceAtomicClaim(AtomicClaim):
    """Generated claim for the constrained claim-evidence condition."""

    evidence_ids: list[EvidenceId] = Field(min_length=1)


class ClaimAnswer(BaseModel):
    """Provider-facing answer shared by direct and citation-prompted conditions.

    Empty evidence lists are valid here. The direct condition treats citation
    metrics as not applicable; citation-prompted grading treats an empty list as
    unsupported without invalidating the rest of an otherwise valid envelope.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    answer_id: NonEmptyString
    run_id: NonEmptyString
    case_id: NonEmptyString
    as_of: UtcDateTime
    claims: Sequence[AtomicClaim]
    abstained: bool
    abstention_reason: str | None
    narrative: str | None

    @field_validator("claims")
    @classmethod
    def unique_claim_ids(cls, claims: Sequence[AtomicClaim]) -> Sequence[AtomicClaim]:
        claim_ids = [claim.claim_id for claim in claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("generated claim_id values must be unique")
        return claims

    @model_validator(mode="after")
    def validate_abstention(self) -> Self:
        if self.abstained:
            if self.claims:
                raise ValueError("a fully abstained answer cannot emit claims")
            if not self.abstention_reason:
                raise ValueError("abstained answers require abstention_reason")
        elif self.abstention_reason is not None:
            raise ValueError("non-abstained answers cannot set abstention_reason")
        return self


class ClaimEvidenceAnswer(ClaimAnswer):
    """Explicit constrained-condition schema path (`minItems: 1`)."""

    claims: list[ClaimEvidenceAtomicClaim]


def claim_match_key(claim: AtomicClaim) -> tuple[Hashable, ...]:
    """Return the frozen expected-claim uniqueness/matching key."""

    qualifiers = (
        claim.qualifiers.authority,
        claim.qualifiers.cvss_version,
        claim.qualifiers.product,
        claim.qualifiers.ecosystem,
    )
    return (
        claim.subject.type,
        claim.subject.id,
        claim.predicate,
        qualifiers,
        claim.object.datatype,
    )


def canonical_typed_value(claim: AtomicClaim) -> Hashable:
    """Canonicalize a validated typed value for deterministic exact matching."""

    value = claim.object.value
    if claim.object.datatype in {"version_set", "identifier_set"}:
        if isinstance(value, list):
            return tuple(sorted(value))
        assert isinstance(value, dict)
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if claim.object.datatype == "decimal":
        assert isinstance(value, Decimal)
        return value.normalize()
    assert isinstance(value, (bool, str, Decimal))
    return value
