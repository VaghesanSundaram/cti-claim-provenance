"""Immutable run-record contract for experiment accounting."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
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
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class RunRecord(BaseModel):
    """Non-secret, append-only summary for one scheduled experiment slot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: NonEmptyString
    recorded_at_utc: UtcDateTime
    project_version: NonEmptyString
    dataset_version: NonEmptyString
    case_id: NonEmptyString
    case_seed: int = Field(ge=0)
    condition: Literal[
        "lexical_direct_answer",
        "lexical_citation_prompted",
        "lexical_claim_evidence_constrained",
        "claim_evidence_with_verifier",
    ]
    provider: Literal["none", "openai", "anthropic", "google"]
    model_id: str | None
    model_snapshot_or_version: str | None
    prompt_version: NonEmptyString
    retriever_version: NonEmptyString
    corpus_manifest_hash: Sha256
    authority_policy_version: NonEmptyString
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    latency_ms: int = Field(ge=0)
    retry_count: int = Field(ge=0)
    provider_status: Literal[
        "not_called", "allowed", "refused", "additional_check", "blocked", "error"
    ]
    parse_status: Literal["valid", "invalid", "not_applicable"]
    retrieval_outcome: Literal["success", "empty", "error", "not_applicable"]
    deterministic_outcome: Literal[
        "graded", "unusable_slot", "not_graded", "not_applicable"
    ]
    security_outcome: Literal[
        "allowed",
        "refused",
        "additional_check",
        "blocked",
        "unknown",
        "not_applicable",
    ]
    utility_outcome: Literal[
        "claims_emitted", "abstained", "empty", "unusable", "not_applicable"
    ]
    error_category: Literal[
        "none",
        "local_safety_block",
        "provider_refusal",
        "transport",
        "timeout",
        "parse",
        "schema",
        "retrieval",
        "grader",
        "infrastructure",
    ]
    estimated_cost_usd: Decimal = Field(ge=0)

    @model_validator(mode="after")
    def validate_run_relationships(self) -> Self:
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached_input_tokens cannot exceed input_tokens")

        if self.provider == "none":
            if self.model_id is not None or self.model_snapshot_or_version is not None:
                raise ValueError("provider=none cannot identify a model")
            if self.provider_status != "not_called":
                raise ValueError("provider=none requires provider_status=not_called")
            if self.security_outcome != "not_applicable":
                raise ValueError(
                    "provider=none requires security_outcome=not_applicable"
                )
            if any((self.input_tokens, self.cached_input_tokens, self.output_tokens)):
                raise ValueError("provider=none cannot record provider tokens")
            if self.estimated_cost_usd != 0:
                raise ValueError("provider=none cannot record provider cost")
        else:
            if not self.model_id or not self.model_snapshot_or_version:
                raise ValueError("model providers require model identity and version")
            if self.provider_status == "not_called":
                raise ValueError(
                    "model providers cannot use provider_status=not_called"
                )

        expected_security = {
            "not_called": "not_applicable",
            "allowed": "allowed",
            "refused": "refused",
            "additional_check": "additional_check",
            "blocked": "blocked",
            "error": "unknown",
        }
        if self.security_outcome != expected_security[self.provider_status]:
            raise ValueError("provider_status and security_outcome are inconsistent")

        expected_deterministic = {
            "valid": "graded",
            "invalid": "unusable_slot",
        }
        if (
            self.parse_status in expected_deterministic
            and self.deterministic_outcome != expected_deterministic[self.parse_status]
        ):
            raise ValueError("parse_status and deterministic_outcome are inconsistent")
        if (
            self.parse_status == "not_applicable"
            and self.deterministic_outcome == "graded"
        ):
            raise ValueError("an unparsed run cannot be graded")
        if self.provider_status in {
            "refused",
            "additional_check",
            "blocked",
            "error",
        }:
            if (
                self.parse_status != "not_applicable"
                or self.deterministic_outcome != "unusable_slot"
            ):
                raise ValueError(
                    "provider non-results require an unusable, unparsed slot"
                )
            if self.error_category == "none":
                raise ValueError("provider non-results require an error category")
        return self
