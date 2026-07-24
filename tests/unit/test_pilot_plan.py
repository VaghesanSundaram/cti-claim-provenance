from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from cti_provenance.experiments.pilot_plan import (
    PilotExecutionPlan,
    PilotPricing,
    PilotScheduleError,
    build_pilot_execution_evidence,
    build_pilot_schedule,
    validate_pilot_schedule,
)


def _plan(
    *,
    case_form_count: int = 40,
    cap: str = "5.50",
    retries: int = 1,
) -> PilotExecutionPlan:
    return PilotExecutionPlan(
        plan_version="pilot-execution-plan-v1",
        candidate_manifest_sha256="a" * 64,
        provider="openai",
        model="gpt-5.6-luna",
        api="responses",
        service_tier="default",
        reasoning_effort="medium",
        prompt_version="future-pilot-prompt-v1",
        provider_schema_version="future-pilot-schema-v1",
        parser_version="future-pilot-parser-v1",
        grader_version="future-pilot-grader-v1",
        authority_policy_version="future-pilot-authority-v1",
        normalization_versions=("future-pilot-normalization-v1",),
        retrieval_version="future-pilot-retrieval-v1",
        case_form_ids=tuple(
            f"synthetic-test-case-{index:03d}" for index in range(case_form_count)
        ),
        conditions=(
            "lexical_direct_answer",
            "lexical_citation_prompted",
            "lexical_claim_evidence_constrained",
        ),
        repetitions=3,
        schedule_seed=20260719,
        maximum_transient_retries=retries,
        input_token_reservation_per_attempt=4000,
        output_token_reservation_per_attempt=600,
        retry_inclusive_cost_cap_usd=Decimal(cap),
        pricing=PilotPricing(
            pricing_version="local-planning-rates-2026-07-19-v1",
            evidence_url=("https://developers.openai.com/api/docs/models/gpt-5.6-luna"),
            evidence_accessed_at_utc=datetime(2026, 7, 19, tzinfo=UTC),
            input_per_million_usd=Decimal("1.00"),
            output_per_million_usd=Decimal("6.00"),
        ),
    )


def test_exact_retry_inclusive_arithmetic_is_derived_not_caller_supplied() -> None:
    plan = _plan()
    schedule = build_pilot_schedule(plan)
    evidence = build_pilot_execution_evidence(plan, schedule)

    assert evidence.case_form_count == 40
    assert evidence.condition_count == 3
    assert evidence.repetitions == 3
    assert evidence.planned_calls == 360
    assert evidence.maximum_attempts == 720
    assert evidence.input_token_ceiling == 2_880_000
    assert evidence.output_token_ceiling == 432_000
    assert evidence.calculated_retry_inclusive_cost_usd == Decimal("5.472")
    assert evidence.retry_inclusive_cost_cap_usd == Decimal("5.50")
    assert evidence.frozen_rate_arithmetic_valid is True
    assert evidence.current_pricing_status == "unverified"
    assert evidence.phase7_budget_compliant is True
    assert evidence.plan_sha256 == plan.sha256()
    assert len(evidence.schedule_sha256) == 64

    forged = plan.model_dump(mode="python")
    forged["planned_calls"] = 999
    with pytest.raises(ValidationError, match="Extra inputs"):
        PilotExecutionPlan.model_validate(forged)

    bypassed = plan.model_copy(update={"retry_inclusive_cost_cap_usd": Decimal("0.01")})
    with pytest.raises(PilotScheduleError, match="revalidation"):
        build_pilot_execution_evidence(
            bypassed,
            build_pilot_schedule(bypassed),
        )


def test_phase7_pair_minimum_exposes_current_six_dollar_conflict() -> None:
    with pytest.raises(
        ValidationError,
        match="retry-inclusive calculated cost exceeds the declared hard cap",
    ):
        _plan(case_form_count=80, cap="6.00")

    plan = _plan(case_form_count=80, cap="10.944")
    assert plan.planned_calls == 720
    assert plan.maximum_attempts == 1440
    assert plan.calculated_retry_inclusive_cost_usd == Decimal("10.944")
    evidence = build_pilot_execution_evidence(plan, build_pilot_schedule(plan))
    assert evidence.phase7_budget_compliant is False

    no_retry = _plan(case_form_count=80, cap="5.50", retries=0)
    assert no_retry.planned_calls == 720
    assert no_retry.maximum_attempts == 720
    assert no_retry.calculated_retry_inclusive_cost_usd == Decimal("5.472")
    no_retry_evidence = build_pilot_execution_evidence(
        no_retry,
        build_pilot_schedule(no_retry),
    )
    assert no_retry_evidence.phase7_budget_compliant is True


def test_schedule_is_deterministic_unique_and_complete() -> None:
    plan = _plan(case_form_count=4, cap="0.5472")
    first = build_pilot_schedule(plan)
    second = build_pilot_schedule(plan)

    assert first == second
    assert [slot.ordinal for slot in first] == list(range(36))
    assert len({slot.slot_id for slot in first}) == 36
    assert {
        (slot.case_form_id, slot.condition, slot.repetition_index) for slot in first
    } == {
        (case_form_id, condition, repetition_index)
        for case_form_id in plan.case_form_ids
        for condition in plan.conditions
        for repetition_index in range(plan.repetitions)
    }
    validate_pilot_schedule(plan, first)


def test_schedule_rejects_reordering_missing_slots_and_identity_forgery() -> None:
    plan = _plan(case_form_count=4, cap="0.5472")
    schedule = build_pilot_schedule(plan)

    with pytest.raises(PilotScheduleError, match="exact deterministic schedule"):
        validate_pilot_schedule(plan, (schedule[1], schedule[0], *schedule[2:]))
    with pytest.raises(PilotScheduleError, match="planned call count"):
        validate_pilot_schedule(plan, schedule[:-1])
    forged = schedule[0].model_copy(update={"slot_id": "forged-slot"})
    with pytest.raises(PilotScheduleError, match="exact deterministic schedule"):
        validate_pilot_schedule(plan, (forged, *schedule[1:]))


def test_plan_rejects_duplicate_dimensions_and_invalid_cost_inputs() -> None:
    source = _plan().model_dump(mode="python")
    for key, value, match in (
        (
            "case_form_ids",
            ("duplicate", "duplicate"),
            "case-form identities must be unique",
        ),
        (
            "conditions",
            ("same", "same"),
            "condition identities must be unique",
        ),
        (
            "retry_inclusive_cost_cap_usd",
            Decimal("5.471"),
            "calculated cost exceeds",
        ),
    ):
        mutated = dict(source)
        mutated[key] = value
        with pytest.raises(ValidationError, match=match):
            PilotExecutionPlan.model_validate(mutated)
    coerced = dict(source)
    coerced["repetitions"] = True
    with pytest.raises(ValidationError):
        PilotExecutionPlan.model_validate(coerced)


def test_plan_and_schedule_hashes_change_on_semantic_mutation() -> None:
    plan = _plan(case_form_count=4, cap="0.5472")
    changed = plan.model_copy(update={"schedule_seed": plan.schedule_seed + 1})
    assert changed.sha256() != plan.sha256()

    original = build_pilot_execution_evidence(plan, build_pilot_schedule(plan))
    mutated = build_pilot_execution_evidence(
        changed,
        build_pilot_schedule(changed),
    )
    assert mutated.plan_sha256 != original.plan_sha256
    assert mutated.schedule_sha256 != original.schedule_sha256
