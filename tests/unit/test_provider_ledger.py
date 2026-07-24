from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from cti_provenance.experiments.provider_ledger import (
    AttemptReservation,
    AttemptTerminal,
    CostReconciliation,
    PlannedSlot,
    SafetyEvent,
    append_jsonl_record,
    canonical_json,
    canonical_sha256,
    load_jsonl_records,
    validate_provider_ledger,
)

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
SHA = "a" * 64


def _slot() -> PlannedSlot:
    return PlannedSlot(
        run_id="run-1",
        schedule_ordinal=1,
        case_id="case-1",
        repeat=1,
        condition="lexical_direct_answer",
        execution_mode="fake",
        authorization_id="auth-1",
        authorization_ids=("auth-1",),
        authorization_hash=SHA,
        approval_id="approval-1",
        approved_at_utc=NOW,
        approval_hash=SHA,
        config_hash=SHA,
        prompt_hash=SHA,
        request_hash=SHA,
        retrieval_hash=SHA,
        semantic_request_hash=SHA,
    )


def _reservation(index: int = 1) -> AttemptReservation:
    return AttemptReservation(
        run_id="run-1",
        schedule_ordinal=1,
        attempt_id=f"attempt-{index}",
        attempt_index=index,
        reserved_at_utc=NOW + timedelta(seconds=index),
        execution_mode="fake",
        authorization_hash=SHA,
        approval_id="approval-1",
        approved_at_utc=NOW,
        approval_hash=SHA,
        config_hash=SHA,
        prompt_hash=SHA,
        request_hash=SHA,
        retrieval_hash=SHA,
        semantic_request_hash=SHA,
        reserved_cost_usd=Decimal("0.50"),
    )


def _terminal(index: int = 1, result: str = "completed") -> AttemptTerminal:
    return AttemptTerminal(
        run_id="run-1",
        schedule_ordinal=1,
        attempt_id=f"attempt-{index}",
        attempt_index=index,
        completed_at_utc=NOW + timedelta(seconds=index + 1),
        result_class=result,
        input_tokens=3,
        cached_input_tokens=0,
        output_tokens=2,
        reasoning_tokens=1,
        latency_ms=10,
        provider_http_status=200,
        provider_model="gpt-5.6-luna" if result == "completed" else None,
        provider_service_tier="default" if result == "completed" else None,
        request_body_sha256=SHA,
        response_body_sha256=SHA,
        response_headers_sha256=SHA,
    )


def _event(index: int = 1) -> SafetyEvent:
    return SafetyEvent(
        run_id="run-1",
        scenario_id="case-1",
        schedule_ordinal=1,
        attempt_id=f"attempt-{index}",
        attempt_index=index,
        recorded_at_utc=NOW + timedelta(seconds=index + 1),
        authorization_id="auth-1",
        authorization_ids=("auth-1",),
        authorization_hash=SHA,
        approval_id="approval-1",
        approved_at_utc=NOW,
        approval_hash=SHA,
        provider="openai",
        model="gpt-5.6-luna",
        request_template_version="prompt-v1",
        request_template_hash=SHA,
        safety_outcome="allowed",
        retry_count=index - 1,
        response_used_for_scoring=True,
    )


def _cost(index: int = 1) -> CostReconciliation:
    return CostReconciliation(
        run_id="run-1",
        schedule_ordinal=1,
        attempt_id=f"attempt-{index}",
        attempt_index=index,
        reconciled_at_utc=NOW + timedelta(seconds=index + 2),
        actual_cost_usd=Decimal("0.01"),
        cost_basis="provider_usage_estimate",
        pricing_hash=SHA,
    )


def test_canonical_append_and_reload(tmp_path) -> None:
    path = tmp_path / "ledger.jsonl"
    item = _slot()
    append_jsonl_record(path, item)
    assert path.read_text(encoding="utf-8") == canonical_json(item) + "\n"
    assert load_jsonl_records(path, PlannedSlot) == (item,)
    assert canonical_sha256(item) == canonical_sha256(item.model_dump(mode="json"))


def test_load_rejects_noncanonical_or_partial_line(tmp_path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text('{ "run_id": "wrong" }\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid ledger line"):
        load_jsonl_records(path, PlannedSlot)
    path.write_bytes(canonical_json(_slot()).encode())
    with pytest.raises(ValueError, match="newline"):
        load_jsonl_records(path, PlannedSlot)


def test_resume_blocks_ambiguous_start_and_finalizes_complete_slot() -> None:
    ambiguous = validate_provider_ledger((_slot(),), (_reservation(),), (), (), ())
    assert ambiguous.ambiguous_attempt_ids == ("attempt-1",)
    assert not ambiguous.can_send_next_attempt("run-1")

    state = validate_provider_ledger(
        (_slot(),), (_reservation(),), (_terminal(),), (_event(),), (_cost(),)
    )
    state.finalize((_slot(),))


def test_retry_requires_transient_exact_request_and_safety_event() -> None:
    retryable_terminal = _terminal(result="server_error")
    with pytest.raises(ValidationError, match="one safety event"):
        validate_provider_ledger(
            (_slot(),),
            (_reservation(), _reservation(2)),
            (retryable_terminal, _terminal(2)),
            (_event(),),
            (),
        )
    state = validate_provider_ledger(
        (_slot(),),
        (_reservation(), _reservation(2)),
        (retryable_terminal, _terminal(2)),
        (_event(), _event(2)),
        (_cost(), _cost(2)),
    )
    state.finalize((_slot(),))


def test_non_retryable_and_cap_violations_fail() -> None:
    with pytest.raises(ValidationError, match="cannot be retried"):
        validate_provider_ledger(
            (_slot(),),
            (_reservation(), _reservation(2)),
            (_terminal(result="refusal"), _terminal(2)),
            (_event(), _event(2)),
            (),
        )
    reservation = _reservation().model_copy(
        update={"reserved_cost_usd": Decimal("2.00")}
    )
    second = _reservation(2).model_copy(update={"reserved_cost_usd": Decimal("0.01")})
    with pytest.raises(ValidationError, match="exceed \\$2 cap"):
        validate_provider_ledger(
            (_slot(),),
            (reservation, second),
            (_terminal(result="server_error"),),
            (_event(), _event(2)),
            (),
        )
