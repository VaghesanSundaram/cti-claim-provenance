"""Provider-free validation of a future pilot schedule and cost reservation."""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

_NON_EMPTY = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_ONE_MILLION = Decimal(1_000_000)
PHASE7_COST_CAP_USD = Decimal("6.00")
PHASE7_CONDITIONS = (
    "lexical_direct_answer",
    "lexical_citation_prompted",
    "lexical_claim_evidence_constrained",
)
PHASE7_REPETITIONS = 3
PHASE7_MINIMUM_ATTACKED_PAIRS = 40
PHASE7_MAXIMUM_BASE_CASES = 100


class PilotScheduleError(ValueError):
    """The realized schedule does not match its frozen execution plan."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PilotPricing(BaseModel):
    """Frozen rate evidence used for local upper-bound arithmetic only."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
    )

    pricing_version: _NON_EMPTY
    evidence_url: _NON_EMPTY
    evidence_accessed_at_utc: AwareDatetime
    input_per_million_usd: Decimal = Field(gt=0, max_digits=12, decimal_places=8)
    output_per_million_usd: Decimal = Field(gt=0, max_digits=12, decimal_places=8)

    @field_validator("evidence_accessed_at_utc")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("pricing evidence timestamp must be UTC")
        return value.astimezone(UTC)


class PilotExecutionPlan(BaseModel):
    """Exact design inputs from which every execution total is derived."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
    )

    plan_version: Literal["pilot-execution-plan-v1"]
    candidate_manifest_sha256: _SHA256
    provider: _NON_EMPTY
    model: _NON_EMPTY
    api: _NON_EMPTY
    service_tier: _NON_EMPTY
    reasoning_effort: _NON_EMPTY
    prompt_version: _NON_EMPTY
    provider_schema_version: _NON_EMPTY
    parser_version: _NON_EMPTY
    grader_version: _NON_EMPTY
    authority_policy_version: _NON_EMPTY
    normalization_versions: tuple[_NON_EMPTY, ...] = Field(min_length=1)
    retrieval_version: _NON_EMPTY
    case_form_ids: tuple[_NON_EMPTY, ...] = Field(min_length=1)
    conditions: tuple[_NON_EMPTY, ...] = Field(min_length=1)
    repetitions: int = Field(ge=1)
    schedule_seed: int
    maximum_transient_retries: int = Field(ge=0)
    input_token_reservation_per_attempt: int = Field(ge=1)
    output_token_reservation_per_attempt: int = Field(ge=1)
    retry_inclusive_cost_cap_usd: Decimal = Field(gt=0, max_digits=12, decimal_places=8)
    pricing: PilotPricing

    @field_validator(
        "case_form_ids",
        "conditions",
        "normalization_versions",
        mode="before",
    )
    @classmethod
    def freeze_arrays(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("pilot plan collections must be arrays")
        return tuple(value)

    @model_validator(mode="after")
    def validate_design(self) -> Self:
        if len(set(self.case_form_ids)) != len(self.case_form_ids):
            raise ValueError("case-form identities must be unique")
        if len(set(self.conditions)) != len(self.conditions):
            raise ValueError("condition identities must be unique")
        if len(set(self.normalization_versions)) != len(
            self.normalization_versions
        ) or self.normalization_versions != tuple(sorted(self.normalization_versions)):
            raise ValueError("normalization versions must be unique and sorted")
        if self.calculated_retry_inclusive_cost_usd > self.retry_inclusive_cost_cap_usd:
            raise ValueError(
                "retry-inclusive calculated cost exceeds the declared hard cap"
            )
        return self

    @property
    def planned_calls(self) -> int:
        return len(self.case_form_ids) * len(self.conditions) * self.repetitions

    @property
    def maximum_attempts(self) -> int:
        return self.planned_calls * (self.maximum_transient_retries + 1)

    @property
    def input_token_ceiling(self) -> int:
        return self.maximum_attempts * self.input_token_reservation_per_attempt

    @property
    def output_token_ceiling(self) -> int:
        return self.maximum_attempts * self.output_token_reservation_per_attempt

    @property
    def calculated_retry_inclusive_cost_usd(self) -> Decimal:
        input_cost = (
            Decimal(self.input_token_ceiling)
            * self.pricing.input_per_million_usd
            / _ONE_MILLION
        )
        output_cost = (
            Decimal(self.output_token_ceiling)
            * self.pricing.output_per_million_usd
            / _ONE_MILLION
        )
        return input_cost + output_cost

    def canonical_json(self) -> str:
        return _canonical_json(self.model_dump(mode="json"))

    def sha256(self) -> str:
        return _sha256_text(self.canonical_json())


class PilotScheduleSlot(BaseModel):
    """One immutable call position in the deterministic pilot schedule."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ordinal: int = Field(ge=0)
    slot_id: _NON_EMPTY
    case_form_id: _NON_EMPTY
    condition: _NON_EMPTY
    repetition_index: int = Field(ge=0)


class PilotExecutionEvidence(BaseModel):
    """Derived, hash-bound evidence that schedule and arithmetic validate."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    validation_version: Literal["pilot-execution-validation-v1"]
    plan_sha256: _SHA256
    candidate_manifest_sha256: _SHA256
    schedule_sha256: _SHA256
    case_form_count: int = Field(ge=1)
    condition_count: int = Field(ge=1)
    repetitions: int = Field(ge=1)
    planned_calls: int = Field(ge=1)
    maximum_attempts: int = Field(ge=1)
    input_token_ceiling: int = Field(ge=1)
    output_token_ceiling: int = Field(ge=1)
    calculated_retry_inclusive_cost_usd: Decimal = Field(gt=0)
    retry_inclusive_cost_cap_usd: Decimal = Field(gt=0)
    pricing_version: _NON_EMPTY
    frozen_rate_arithmetic_valid: Literal[True]
    current_pricing_status: Literal["unverified"]
    phase7_cost_cap_usd: Decimal = Field(gt=0)
    phase7_budget_compliant: bool


def build_pilot_schedule(
    plan: PilotExecutionPlan,
) -> tuple[PilotScheduleSlot, ...]:
    """Build a seeded block-interleaved complete Cartesian schedule."""

    randomizer = random.Random(plan.schedule_seed)
    blocks = [
        (case_form_id, repetition_index)
        for case_form_id in plan.case_form_ids
        for repetition_index in range(plan.repetitions)
    ]
    randomizer.shuffle(blocks)
    slots: list[PilotScheduleSlot] = []
    for case_form_id, repetition_index in blocks:
        conditions = list(plan.conditions)
        randomizer.shuffle(conditions)
        for condition in conditions:
            ordinal = len(slots)
            identity = _canonical_json(
                {
                    "plan_sha256": plan.sha256(),
                    "ordinal": ordinal,
                    "case_form_id": case_form_id,
                    "condition": condition,
                    "repetition_index": repetition_index,
                }
            )
            slots.append(
                PilotScheduleSlot(
                    ordinal=ordinal,
                    slot_id=f"pilot-slot-{_sha256_text(identity)[:24]}",
                    case_form_id=case_form_id,
                    condition=condition,
                    repetition_index=repetition_index,
                )
            )
    return tuple(slots)


def _revalidate_plan(plan: PilotExecutionPlan) -> PilotExecutionPlan:
    try:
        return PilotExecutionPlan.model_validate(plan.model_dump(mode="python"))
    except ValueError as exc:
        raise PilotScheduleError("pilot execution plan failed revalidation") from exc


def validate_pilot_schedule(
    plan: PilotExecutionPlan,
    schedule: Sequence[PilotScheduleSlot],
) -> None:
    """Fail closed unless a schedule exactly matches the frozen design."""

    validated_plan = _revalidate_plan(plan)
    if len(schedule) != validated_plan.planned_calls:
        raise PilotScheduleError("schedule differs from the planned call count")
    supplied = tuple(schedule)
    expected = build_pilot_schedule(validated_plan)
    if supplied != expected:
        raise PilotScheduleError(
            "schedule differs from the exact deterministic schedule"
        )


def _schedule_sha256(schedule: Sequence[PilotScheduleSlot]) -> str:
    payload = [slot.model_dump(mode="json") for slot in schedule]
    return _sha256_text(_canonical_json(payload))


def build_pilot_execution_evidence(
    plan: PilotExecutionPlan,
    schedule: Sequence[PilotScheduleSlot],
) -> PilotExecutionEvidence:
    """Validate exact coverage and return only derived execution evidence."""

    validate_pilot_schedule(plan, schedule)
    plan = _revalidate_plan(plan)
    return PilotExecutionEvidence(
        validation_version="pilot-execution-validation-v1",
        plan_sha256=plan.sha256(),
        candidate_manifest_sha256=plan.candidate_manifest_sha256,
        schedule_sha256=_schedule_sha256(schedule),
        case_form_count=len(plan.case_form_ids),
        condition_count=len(plan.conditions),
        repetitions=plan.repetitions,
        planned_calls=plan.planned_calls,
        maximum_attempts=plan.maximum_attempts,
        input_token_ceiling=plan.input_token_ceiling,
        output_token_ceiling=plan.output_token_ceiling,
        calculated_retry_inclusive_cost_usd=(plan.calculated_retry_inclusive_cost_usd),
        retry_inclusive_cost_cap_usd=plan.retry_inclusive_cost_cap_usd,
        pricing_version=plan.pricing.pricing_version,
        frozen_rate_arithmetic_valid=True,
        current_pricing_status="unverified",
        phase7_cost_cap_usd=PHASE7_COST_CAP_USD,
        phase7_budget_compliant=(
            plan.calculated_retry_inclusive_cost_usd
            <= plan.retry_inclusive_cost_cap_usd
            <= PHASE7_COST_CAP_USD
        ),
    )
