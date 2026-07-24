"""Strict, append-only provider-evaluation accounting records.

This module deliberately has no provider or filesystem discovery dependency:
callers construct a frozen schedule, append lifecycle events before/after an
attempt, and reload the ledger to decide whether it is safe to resume.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    model_validator,
)

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Usd = Annotated[Decimal, Field(ge=Decimal("0"), max_digits=12, decimal_places=8)]
MAX_COST_USD = Decimal("2.00")
MAX_ATTEMPTS = 2


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use the UTC offset")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc_datetime)]


def canonical_json(value: BaseModel | object) -> str:
    """Produce stable compact JSON for hashes and one-record JSONL lines."""

    payload: object = (
        value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    )
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def canonical_sha256(value: BaseModel | object) -> str:
    """Return the SHA-256 of :func:`canonical_json`."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class PlannedSlot(BaseModel):
    """One immutable slot in the planned provider schedule."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: NonEmptyString
    schedule_ordinal: int = Field(ge=1)
    case_id: NonEmptyString
    repeat: int = Field(ge=1, le=3)
    condition: Literal[
        "lexical_direct_answer",
        "lexical_citation_prompted",
        "lexical_claim_evidence_constrained",
    ]
    execution_mode: Literal["fake", "live"]
    authorization_id: NonEmptyString
    authorization_ids: tuple[NonEmptyString, ...] = Field(min_length=1)
    authorization_hash: Sha256
    approval_id: NonEmptyString
    approved_at_utc: UtcDateTime
    approval_hash: Sha256
    config_hash: Sha256
    prompt_hash: Sha256
    request_hash: Sha256
    retrieval_hash: Sha256
    semantic_request_hash: Sha256


class AttemptReservation(BaseModel):
    """Durable pre-egress reservation; its existence means an attempt occurred."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: NonEmptyString
    schedule_ordinal: int = Field(ge=1)
    attempt_id: NonEmptyString
    attempt_index: int = Field(ge=1, le=MAX_ATTEMPTS)
    reserved_at_utc: UtcDateTime
    execution_mode: Literal["fake", "live"]
    authorization_hash: Sha256
    approval_id: NonEmptyString
    approved_at_utc: UtcDateTime
    approval_hash: Sha256
    config_hash: Sha256
    prompt_hash: Sha256
    request_hash: Sha256
    retrieval_hash: Sha256
    semantic_request_hash: Sha256
    reserved_cost_usd: Usd = Field(le=MAX_COST_USD)


class AttemptTerminal(BaseModel):
    """A terminal observation for a reserved attempt (never a retry decision)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: NonEmptyString
    schedule_ordinal: int = Field(ge=1)
    attempt_id: NonEmptyString
    attempt_index: int = Field(ge=1, le=MAX_ATTEMPTS)
    completed_at_utc: UtcDateTime
    result_class: Literal[
        "completed",
        "refusal",
        "schema_error",
        "parse_error",
        "incomplete",
        "auth_error",
        "transport_error",
        "rate_limited",
        "server_error",
        "timeout_ambiguous",
        "local_block",
    ]
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    latency_ms: int = Field(ge=0)
    provider_http_status: int | None = Field(default=None, ge=100, le=599)
    provider_model: NonEmptyString | None = None
    provider_service_tier: NonEmptyString | None = None
    provider_request_id_hash: Sha256 | None = None
    request_body_sha256: Sha256
    response_body_sha256: Sha256 | None = None
    response_headers_sha256: Sha256 | None = None
    redacted_error_code: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_usage(self) -> AttemptTerminal:
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached_input_tokens cannot exceed input_tokens")
        if self.reasoning_tokens > self.output_tokens:
            raise ValueError("reasoning_tokens cannot exceed output_tokens")
        if self.result_class == "completed" and (
            self.provider_model is None or self.provider_service_tier is None
        ):
            raise ValueError(
                "completed attempts require provider model and service tier"
            )
        if (self.response_body_sha256 is None) != (
            self.response_headers_sha256 is None
        ):
            raise ValueError(
                "response body and selected-header hashes must be present together"
            )
        if (self.response_body_sha256 is None) != (self.provider_http_status is None):
            raise ValueError("response body and HTTP status must be present together")
        return self


class SafetyEvent(BaseModel):
    """One redacted safety classification for every actual provider attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: NonEmptyString
    scenario_id: NonEmptyString
    schedule_ordinal: int = Field(ge=1)
    attempt_id: NonEmptyString
    attempt_index: int = Field(ge=1, le=MAX_ATTEMPTS)
    recorded_at_utc: UtcDateTime
    authorization_id: NonEmptyString
    authorization_ids: tuple[NonEmptyString, ...] = Field(min_length=1)
    authorization_hash: Sha256
    approval_id: NonEmptyString
    approved_at_utc: UtcDateTime
    approval_hash: Sha256
    provider: Literal["openai"]
    model: NonEmptyString
    request_template_version: NonEmptyString
    request_template_hash: Sha256
    safety_outcome: Literal[
        "allowed", "refused", "additional_check", "blocked", "unknown"
    ]
    provider_request_id_hash: Sha256 | None = None
    retry_count: int = Field(ge=0, le=1)
    response_used_for_scoring: bool
    notes: NonEmptyString | None = None


class CostReconciliation(BaseModel):
    """Actual known cost for a terminal attempt, bounded by its reservation."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    run_id: NonEmptyString
    schedule_ordinal: int = Field(ge=1)
    attempt_id: NonEmptyString
    attempt_index: int = Field(ge=1, le=MAX_ATTEMPTS)
    reconciled_at_utc: UtcDateTime
    actual_cost_usd: Usd = Field(le=MAX_COST_USD)
    cost_basis: Literal[
        "provider_usage_estimate",
        "known_zero",
        "ambiguous_reserved_max",
    ]
    pricing_hash: Sha256


def append_jsonl_record(path: Path, record: BaseModel) -> None:
    """Append one canonical line, flushing it to stable local storage."""

    path.parent.mkdir(parents=True, exist_ok=True)
    line = (canonical_json(record) + "\n").encode("utf-8")
    with path.open("ab") as stream:
        stream.write(line)
        stream.flush()
        os.fsync(stream.fileno())


def load_jsonl_records[T: BaseModel](path: Path, model: type[T]) -> tuple[T, ...]:
    """Load a ledger strictly, rejecting blank, malformed, or noncanonical lines."""

    if not path.exists():
        return ()
    records: list[T] = []
    adapter = TypeAdapter(model)
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, start=1):
            if not raw.endswith(b"\n"):
                raise ValueError(f"ledger line {number} lacks newline terminator")
            try:
                text = raw[:-1].decode("utf-8")
                record = adapter.validate_json(text)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError(f"invalid ledger line {number}") from exc
            if canonical_json(record) != text:
                raise ValueError(f"ledger line {number} is not canonical JSON")
            records.append(record)
    return tuple(records)


def _key(
    record: AttemptReservation | AttemptTerminal | SafetyEvent | CostReconciliation,
) -> tuple[str, str]:
    return record.run_id, record.attempt_id


def _slot_key(
    slot: PlannedSlot
    | AttemptReservation
    | AttemptTerminal
    | SafetyEvent
    | CostReconciliation,
) -> tuple[str, int]:
    return slot.run_id, slot.schedule_ordinal


_RETRYABLE = frozenset({"transport_error", "rate_limited", "server_error"})


class ProviderLedgerState(BaseModel):
    """Validated append-only lifecycle state, safe to use for resume decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    planned_slots: tuple[PlannedSlot, ...]
    reservations: tuple[AttemptReservation, ...]
    terminals: tuple[AttemptTerminal, ...]
    safety_events: tuple[SafetyEvent, ...]
    reconciliations: tuple[CostReconciliation, ...]

    @model_validator(mode="after")
    def validate_invariants(self) -> ProviderLedgerState:
        slot_keys = [_slot_key(slot) for slot in self.planned_slots]
        if len(slot_keys) != len(set(slot_keys)):
            raise ValueError("planned schedule has duplicate run/ordinal")
        if len({slot.run_id for slot in self.planned_slots}) != len(self.planned_slots):
            raise ValueError("planned schedule has duplicate run_id")
        if len({slot.schedule_ordinal for slot in self.planned_slots}) != len(
            self.planned_slots
        ):
            raise ValueError("planned schedule has duplicate schedule_ordinal")
        if tuple(sorted(slot.schedule_ordinal for slot in self.planned_slots)) != tuple(
            range(1, len(self.planned_slots) + 1)
        ):
            raise ValueError("planned schedule ordinals must be contiguous from one")
        if any(
            len(slot.authorization_ids) != len(set(slot.authorization_ids))
            for slot in self.planned_slots
        ):
            raise ValueError("planned authorization IDs must be unique")

        slots = {_slot_key(slot): slot for slot in self.planned_slots}
        reservation_keys = [_key(item) for item in self.reservations]
        if len(reservation_keys) != len(set(reservation_keys)):
            raise ValueError("duplicate attempt reservation")
        reservations = {_key(item): item for item in self.reservations}
        for reservation in self.reservations:
            slot = slots.get(_slot_key(reservation))
            if slot is None:
                raise ValueError("reservation is not in planned schedule")
            if any(
                getattr(reservation, name) != getattr(slot, name)
                for name in (
                    "execution_mode",
                    "authorization_hash",
                    "approval_id",
                    "approved_at_utc",
                    "approval_hash",
                    "config_hash",
                    "prompt_hash",
                    "request_hash",
                    "retrieval_hash",
                    "semantic_request_hash",
                )
            ):
                raise ValueError("reservation hashes must match planned slot")

        by_slot: dict[tuple[str, int], list[AttemptReservation]] = {}
        for reservation in self.reservations:
            by_slot.setdefault(_slot_key(reservation), []).append(reservation)
        for values in by_slot.values():
            values.sort(key=lambda item: item.attempt_index)
            if [item.attempt_index for item in values] != list(
                range(1, len(values) + 1)
            ):
                raise ValueError("attempt indexes must be contiguous from one")
            if (
                len(values) == 2
                and values[0].semantic_request_hash != values[1].semantic_request_hash
            ):
                raise ValueError("retry must use exact semantic request hash")

        terminal_keys = [_key(item) for item in self.terminals]
        if len(terminal_keys) != len(set(terminal_keys)):
            raise ValueError("duplicate attempt terminal")
        terminals = {_key(item): item for item in self.terminals}
        for terminal in self.terminals:
            terminal_reservation = reservations.get(_key(terminal))
            if terminal_reservation is None:
                raise ValueError("terminal lacks attempt reservation")
            if (
                terminal.attempt_index != terminal_reservation.attempt_index
                or _slot_key(terminal) != _slot_key(terminal_reservation)
            ):
                raise ValueError("terminal does not match reservation")
            if terminal.completed_at_utc < terminal_reservation.reserved_at_utc:
                raise ValueError("terminal precedes reservation")

        event_keys = [_key(item) for item in self.safety_events]
        if len(event_keys) != len(set(event_keys)):
            raise ValueError("one safety event is required per actual attempt")
        events = {_key(item): item for item in self.safety_events}
        if not set(events) <= set(reservations):
            raise ValueError("safety event lacks an attempt reservation")
        if not set(terminals) <= set(events):
            raise ValueError("every terminal attempt requires one safety event")
        for event in self.safety_events:
            event_reservation = reservations[_key(event)]
            slot = slots[_slot_key(event)]
            if event.attempt_index != event_reservation.attempt_index or _slot_key(
                event
            ) != _slot_key(event_reservation):
                raise ValueError("safety event does not match reservation")
            if (
                event.scenario_id != slot.case_id
                or event.authorization_id != slot.authorization_id
                or event.authorization_ids != slot.authorization_ids
                or event.authorization_hash != slot.authorization_hash
                or event.approval_id != slot.approval_id
                or event.approved_at_utc != slot.approved_at_utc
                or event.approval_hash != slot.approval_hash
                or event.retry_count != event.attempt_index - 1
            ):
                raise ValueError("safety event scope does not match planned slot")
            if event.recorded_at_utc < event_reservation.reserved_at_utc:
                raise ValueError("safety event precedes reservation")

        reconciliation_keys = [_key(item) for item in self.reconciliations]
        if len(reconciliation_keys) != len(set(reconciliation_keys)):
            raise ValueError("duplicate cost reconciliation")
        for reconciliation in self.reconciliations:
            reconciliation_reservation = reservations.get(_key(reconciliation))
            reconciliation_terminal = terminals.get(_key(reconciliation))
            if reconciliation_reservation is None or reconciliation_terminal is None:
                raise ValueError("cost reconciliation requires terminal reservation")
            if reconciliation.attempt_index != reconciliation_reservation.attempt_index:
                raise ValueError("cost reconciliation does not match reservation")
            if (
                reconciliation.reconciled_at_utc
                < reconciliation_terminal.completed_at_utc
            ):
                raise ValueError("cost reconciliation precedes terminal")
            if (
                reconciliation.actual_cost_usd
                > reconciliation_reservation.reserved_cost_usd
            ):
                raise ValueError("actual cost cannot exceed reservation")

        if (
            sum((item.reserved_cost_usd for item in self.reservations), Decimal("0"))
            > MAX_COST_USD
        ):
            raise ValueError("total reservations exceed $2 cap")
        if (
            sum((item.actual_cost_usd for item in self.reconciliations), Decimal("0"))
            > MAX_COST_USD
        ):
            raise ValueError("total reconciled cost exceeds $2 cap")

        for values in by_slot.values():
            if len(values) == 2:
                first_terminal = terminals.get(_key(values[0]))
                if first_terminal is None:
                    raise ValueError("ambiguous unfinished attempt blocks resend")
                if first_terminal.result_class not in _RETRYABLE:
                    raise ValueError("terminal result class cannot be retried")
                if values[1].reserved_at_utc < first_terminal.completed_at_utc:
                    raise ValueError("retry reservation precedes first terminal")
        return self

    @property
    def ambiguous_attempt_ids(self) -> tuple[str, ...]:
        """Started attempts without terminal observations; never resend these slots."""

        terminal_ids = {item.attempt_id for item in self.terminals}
        return tuple(
            item.attempt_id
            for item in self.reservations
            if item.attempt_id not in terminal_ids
        )

    def can_send_next_attempt(self, run_id: str) -> bool:
        """Return whether the slot has no unresolved start and may be attempted."""

        if run_id not in {slot.run_id for slot in self.planned_slots}:
            raise ValueError("unknown run_id")
        if any(
            item.run_id == run_id
            for item in self.reservations
            if item.attempt_id in self.ambiguous_attempt_ids
        ):
            return False
        items = sorted(
            (item for item in self.reservations if item.run_id == run_id),
            key=lambda item: item.attempt_index,
        )
        if not items:
            return True
        if len(items) >= MAX_ATTEMPTS:
            return False
        terminal = next(
            item for item in self.terminals if item.attempt_id == items[-1].attempt_id
        )
        return terminal.result_class in _RETRYABLE

    def finalize(self, expected_slots: tuple[PlannedSlot, ...]) -> None:
        """Prove a complete, unique, terminal schedule before derived scoring."""

        if self.planned_slots != expected_slots:
            raise ValueError("ledger schedule differs from frozen expected schedule")
        if self.ambiguous_attempt_ids:
            raise ValueError("cannot finalize with ambiguous unfinished attempts")
        terminal_run_ids = {item.run_id for item in self.terminals}
        if terminal_run_ids != {item.run_id for item in expected_slots}:
            raise ValueError(
                "finalization requires terminal completeness for every slot"
            )
        if any(
            not any(item.run_id == slot.run_id for item in self.reconciliations)
            for slot in expected_slots
        ):
            raise ValueError("finalization requires cost reconciliation for every slot")


def validate_provider_ledger(
    planned_slots: tuple[PlannedSlot, ...],
    reservations: tuple[AttemptReservation, ...],
    terminals: tuple[AttemptTerminal, ...],
    safety_events: tuple[SafetyEvent, ...],
    reconciliations: tuple[CostReconciliation, ...],
) -> ProviderLedgerState:
    """Construct and validate a provider ledger state from append-only streams."""

    return ProviderLedgerState(
        planned_slots=planned_slots,
        reservations=reservations,
        terminals=terminals,
        safety_events=safety_events,
        reconciliations=reconciliations,
    )
