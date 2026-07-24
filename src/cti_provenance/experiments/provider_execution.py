"""Crash-conscious execution of the frozen provider canary.

The default and testable path uses an injected transport. Live execution is
impossible without a separately constructed :class:`UserRunApproval`, exact
environment configuration, and an unredacted artifact root outside both the
repository and OneDrive.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_serializer

from cti_provenance.claims.real_slice import (
    load_phase2_real_cases,
    load_phase2_real_corpus,
)
from cti_provenance.claims.schema import ClaimAnswer, ClaimEvidenceAnswer
from cti_provenance.config import AppConfig
from cti_provenance.experiments.ledger import RunRecord
from cti_provenance.experiments.provider_ledger import (
    AttemptReservation,
    AttemptTerminal,
    CostReconciliation,
    PlannedSlot,
    ProviderLedgerState,
    SafetyEvent,
    append_jsonl_record,
    canonical_sha256,
    load_jsonl_records,
    validate_provider_ledger,
)
from cti_provenance.experiments.provider_runner import (
    PUBLIC_AUTHORIZATION_ID,
    TREATMENT_AUTHORIZATION_ID,
    ProviderConfigVersion,
    ProviderExperimentConfig,
    ProviderRequestPlan,
    ProviderRunError,
    ProviderSlot,
    RetrievalPacket,
    UserRunApproval,
    build_provider_request,
    canary_request_manifest_sha256,
    load_provider_inputs,
    load_user_run_approval,
    validate_user_run_approval,
)
from cti_provenance.experiments.real_runner import _dataset_version
from cti_provenance.experiments.runner import _manifest_hash
from cti_provenance.grading import ClaimGrade, grade_answer
from cti_provenance.models.openai_client import (
    OpenAIHttpResponse,
    OpenAIMessage,
    OpenAIResponseRequest,
    OpenAIResponsesAdapter,
    OpenAIResult,
    OpenAITransport,
)
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.retrieval import LexicalRetriever

ExecutionMode = Literal["fake", "live"]
TerminalClass = Literal[
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
SafetyOutcome = Literal["allowed", "refused", "additional_check", "blocked", "unknown"]
ProviderStatus = Literal["allowed", "refused", "additional_check", "blocked", "error"]
ParseStatus = Literal["valid", "invalid", "not_applicable"]
ErrorCategory = Literal[
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
_PER_ATTEMPT_RESERVATION = Decimal("0.0076")
_FAKE_APPROVAL_ID = "offline-fake-no-egress"
_LUNA_SNAPSHOT_PATTERN = re.compile(r"^gpt-5\.6-luna-\d{4}-\d{2}-\d{2}$")


class ApprovalBinding(BaseModel):
    """Persisted non-secret identity of the authority for one execution."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    execution_mode: ExecutionMode
    approval_id: str
    approved_at_utc: datetime
    approval_hash: str


class MetricApplicability(BaseModel):
    """Declare which provenance metrics have an experimental denominator."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    citation_support: bool
    evidence_coverage: bool
    citation_authority: bool


class ProviderExecutionResult(BaseModel):
    """Redacted, locally replayable result for one frozen scheduled slot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    slot: ProviderSlot
    execution_mode: ExecutionMode
    approval_id: str
    approved_at_utc: datetime
    approval_hash: str
    retrieval_packet_sha256: str
    invariant_sha256: str
    semantic_request_sha256: str
    provider_service_tier: str | None
    reasoning_tokens: int
    answer_schema: Literal["claim_answer", "claim_evidence_answer"]
    metric_applicability: MetricApplicability
    run: RunRecord
    answer: ClaimAnswer | None
    grades: tuple[ClaimGrade, ...]

    @field_serializer("answer", when_used="json")
    def serialize_answer(
        self,
        answer: ClaimAnswer | None,
    ) -> object:
        if answer is None:
            return None
        payload = answer.model_dump(mode="json")
        claims = payload.get("claims")
        if isinstance(claims, list):
            for claim in claims:
                if not isinstance(claim, dict):
                    continue
                claim_object = claim.get("object")
                if (
                    isinstance(claim_object, dict)
                    and claim_object.get("datatype") == "decimal"
                    and isinstance(claim_object.get("value"), str)
                ):
                    claim_object["value"] = float(claim_object["value"])
        return payload


class ProviderArtifactPaths(BaseModel):
    """Separated redacted and unredacted run locations."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    redacted_root: Path
    private_root: Path

    @property
    def planned(self) -> Path:
        return self.redacted_root / "planned.jsonl"

    @property
    def reservations(self) -> Path:
        return self.redacted_root / "reservations.jsonl"

    @property
    def terminals(self) -> Path:
        return self.redacted_root / "terminals.jsonl"

    @property
    def safety_events(self) -> Path:
        return self.redacted_root / "safety-events.jsonl"

    @property
    def reconciliations(self) -> Path:
        return self.redacted_root / "reconciliations.jsonl"

    @property
    def results(self) -> Path:
        return self.redacted_root / "results.jsonl"

    @property
    def approval(self) -> Path:
        return self.redacted_root / "approval.json"

    @property
    def user_approval(self) -> Path:
        return self.redacted_root / "user-approval.json"

    @property
    def lock(self) -> Path:
        return self.redacted_root / "run.lock"


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_artifact_paths(
    project_root: Path,
    *,
    redacted_root: Path,
    private_root: Path,
) -> ProviderArtifactPaths:
    """Keep provider text outside the repository and synchronization roots."""

    project_root = project_root.resolve(strict=True)
    redacted = redacted_root.resolve()
    private = private_root.resolve()
    required_redacted_parent = (project_root / "artifacts/provider/redacted").resolve()
    if not _is_within(redacted, required_redacted_parent):
        raise ProviderRunError("redacted provider artifacts must use the ignored root")
    if _is_within(private, project_root) or any(
        "onedrive" in part.casefold() for part in private.parts
    ):
        raise ProviderRunError(
            "unredacted provider artifacts must be outside the repo and OneDrive"
        )
    if _is_within(redacted, private) or _is_within(private, redacted):
        raise ProviderRunError("redacted and unredacted roots must be disjoint")
    redacted.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, exist_ok=True)
    return ProviderArtifactPaths(redacted_root=redacted, private_root=private)


def _write_private_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _write_private(path: Path, text: str) -> None:
    _write_private_bytes(path, text.encode("utf-8"))


def _atomic_write_model(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    content = (
        json.dumps(
            value.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")
    with temporary.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _append_result(path: Path, result: ProviderExecutionResult) -> None:
    append_jsonl_record(path, result)


def _adapter_request(plan: ProviderRequestPlan) -> OpenAIResponseRequest:
    body = plan.body
    messages = tuple(
        OpenAIMessage(role=item["role"], content=item["content"])
        for item in body["input"]
    )
    format_config = body["text"]["format"]
    request = OpenAIResponseRequest(
        model=body["model"],
        input=messages,
        schema_name=format_config["name"],
        json_schema=format_config["schema"],
        max_output_tokens=body["max_output_tokens"],
    )
    if request.semantic_sha256() != plan.semantic_request_sha256:
        raise ProviderRunError("adapter reconstruction changed the semantic request")
    return request


def _planned_slot(
    slot: ProviderSlot,
    plan: ProviderRequestPlan,
    config: ProviderExperimentConfig,
    authorization_hash: str,
    authorization_ids: tuple[str, ...],
    approval: ApprovalBinding,
) -> PlannedSlot:
    return PlannedSlot(
        run_id=slot.slot_id,
        schedule_ordinal=slot.ordinal + 1,
        case_id=slot.case_id,
        repeat=slot.repeat_index + 1,
        condition=slot.condition,
        execution_mode=approval.execution_mode,
        authorization_id=authorization_ids[0],
        authorization_ids=authorization_ids,
        authorization_hash=authorization_hash,
        approval_id=approval.approval_id,
        approved_at_utc=approval.approved_at_utc,
        approval_hash=approval.approval_hash,
        config_hash=config.sha256(),
        prompt_hash=plan.prompt_sha256,
        request_hash=plan.semantic_request_sha256,
        retrieval_hash=plan.retrieval_packet_sha256,
        semantic_request_hash=plan.semantic_request_sha256,
    )


def _classify_result(
    result: OpenAIResult,
) -> tuple[
    TerminalClass,
    SafetyOutcome,
    ProviderStatus,
    ErrorCategory,
    ParseStatus,
]:
    """Map an adapter result to terminal, safety, provider, and error classes."""

    if result.kind == "completed":
        return ("completed", "allowed", "allowed", "none", "valid")
    if result.kind == "refusal":
        return (
            "refusal",
            "refused",
            "refused",
            "provider_refusal",
            "not_applicable",
        )
    if result.kind == "incomplete":
        if result.incomplete_reason == "content_filter":
            return (
                "incomplete",
                "additional_check",
                "additional_check",
                "provider_refusal",
                "not_applicable",
            )
        return (
            "incomplete",
            "unknown",
            "error",
            "infrastructure",
            "not_applicable",
        )
    if result.kind == "timeout":
        return (
            "timeout_ambiguous",
            "unknown",
            "error",
            "timeout",
            "not_applicable",
        )
    if result.kind == "transport_error":
        return (
            "transport_error",
            "unknown",
            "error",
            "transport",
            "not_applicable",
        )
    if result.kind == "api_error":
        terminal: TerminalClass
        if result.http_status == 429:
            terminal = "rate_limited"
        elif result.http_status in {500, 503}:
            terminal = "server_error"
        elif result.http_status in {401, 403}:
            terminal = "auth_error"
        else:
            terminal = "schema_error"
        return (terminal, "unknown", "error", "infrastructure", "not_applicable")
    if result.kind == "invalid_response":
        return (
            "schema_error",
            "unknown",
            "error",
            "schema",
            "not_applicable",
        )
    return (
        "parse_error",
        "allowed",
        "allowed",
        "parse",
        "not_applicable",
    )


def _parse_answer(
    result: OpenAIResult,
    *,
    slot: ProviderSlot,
    packet: RetrievalPacket,
) -> tuple[
    ClaimAnswer | ClaimEvidenceAnswer | None,
    ParseStatus,
    ErrorCategory,
]:
    if result.kind != "completed" or result.output_text is None:
        return None, "not_applicable", "none"
    model: type[ClaimAnswer] | type[ClaimEvidenceAnswer] = (
        ClaimEvidenceAnswer
        if slot.condition == "lexical_claim_evidence_constrained"
        else ClaimAnswer
    )
    try:
        answer = model.model_validate_json(result.output_text)
    except ValueError:
        return None, "invalid", "schema"
    if (
        answer.run_id != slot.slot_id
        or answer.case_id != slot.case_id
        or answer.as_of != packet.as_of
    ):
        return None, "invalid", "schema"
    return answer, "valid", "none"


def _run_record(
    *,
    slot: ProviderSlot,
    packet: RetrievalPacket,
    config: ProviderExperimentConfig,
    result: OpenAIResult,
    answer: ClaimAnswer | ClaimEvidenceAnswer | None,
    parse_status: ParseStatus,
    parse_error: ErrorCategory,
    retry_count: int,
    latency_ms: int,
    recorded_at: datetime,
    corpus_manifest_hash: str,
    dataset_version: str,
    accounted_cost_usd: Decimal,
) -> RunRecord:
    (
        _terminal,
        safety,
        provider_status,
        result_error,
        _default_parse,
    ) = _classify_result(result)
    error_category = parse_error if parse_error != "none" else result_error
    effective_parse = parse_status
    if result.kind != "completed":
        effective_parse = "not_applicable"
    deterministic: Literal["graded", "unusable_slot"] = (
        "graded" if effective_parse == "valid" else "unusable_slot"
    )
    if answer is None:
        utility: Literal[
            "claims_emitted", "abstained", "empty", "unusable", "not_applicable"
        ] = "unusable"
    elif answer.abstained:
        utility = "abstained"
    elif answer.claims:
        utility = "claims_emitted"
    else:
        utility = "empty"
    return RunRecord(
        run_id=slot.slot_id,
        recorded_at_utc=recorded_at,
        project_version="0.1.0",
        dataset_version=dataset_version,
        case_id=slot.case_id,
        case_seed=slot.repeat_index,
        condition=slot.condition,
        provider="openai",
        model_id=config.model,
        model_snapshot_or_version=result.model or "not-returned",
        prompt_version=config.prompt_version,
        retriever_version=LexicalRetriever.version,
        corpus_manifest_hash=corpus_manifest_hash,
        authority_policy_version="authority-policy-v1",
        input_tokens=result.input_tokens,
        cached_input_tokens=result.cached_input_tokens,
        output_tokens=result.output_tokens,
        latency_ms=latency_ms,
        retry_count=retry_count,
        provider_status=provider_status,
        parse_status=effective_parse,
        retrieval_outcome=("success" if packet.ordered_document_ids else "empty"),
        deterministic_outcome=deterministic,
        security_outcome=safety,
        utility_outcome=utility,
        error_category=error_category,
        estimated_cost_usd=accounted_cost_usd,
    )


def _load_state(paths: ProviderArtifactPaths) -> ProviderLedgerState:
    return validate_provider_ledger(
        load_jsonl_records(paths.planned, PlannedSlot),
        load_jsonl_records(paths.reservations, AttemptReservation),
        load_jsonl_records(paths.terminals, AttemptTerminal),
        load_jsonl_records(paths.safety_events, SafetyEvent),
        load_jsonl_records(paths.reconciliations, CostReconciliation),
    )


def _authorization_preflight(
    *,
    mode: ExecutionMode,
    config: ProviderExperimentConfig,
    app_config: AppConfig | None,
    approval: UserRunApproval | None,
    request_manifest_sha256: str,
) -> tuple[str, ApprovalBinding]:
    if mode == "fake":
        if app_config is not None or approval is not None:
            raise ProviderRunError("fake mode cannot accept credentials or approval")
        return ("FAKE_TRANSPORT_NO_CREDENTIAL", _fake_approval_binding(config))
    if approval is None or app_config is None:
        raise ProviderRunError("live mode requires explicit approval and configuration")
    validate_user_run_approval(
        approval,
        config,
        request_manifest_sha256=request_manifest_sha256,
    )
    app_config.require_model_run()
    if (
        app_config.provider != config.provider
        or app_config.model != config.model
        or app_config.cost_cap_usd != config.cost_cap_usd
        or app_config.openai_api_key is None
    ):
        raise ProviderRunError("environment does not exactly match the approved run")
    return (
        app_config.openai_api_key.get_secret_value(),
        _live_approval_binding(
            approval,
            config,
            request_manifest_sha256=request_manifest_sha256,
        ),
    )


def _fake_approval_binding(config: ProviderExperimentConfig) -> ApprovalBinding:
    approved_at = config.pricing.accessed_at_utc
    fake_payload = {
        "execution_mode": "fake",
        "approval_id": _FAKE_APPROVAL_ID,
        "approved_at_utc": approved_at.isoformat(),
        "provider_attempts_authorized": 0,
    }
    return ApprovalBinding(
        execution_mode="fake",
        approval_id=_FAKE_APPROVAL_ID,
        approved_at_utc=approved_at,
        approval_hash=canonical_sha256(fake_payload),
    )


def _live_approval_binding(
    approval: UserRunApproval,
    config: ProviderExperimentConfig,
    *,
    request_manifest_sha256: str,
) -> ApprovalBinding:
    validate_user_run_approval(
        approval,
        config,
        request_manifest_sha256=request_manifest_sha256,
    )
    return ApprovalBinding(
        execution_mode="live",
        approval_id=approval.approval_id,
        approved_at_utc=approval.approved_at_utc,
        approval_hash=approval.sha256(),
    )


def _authorization_ids(packet: RetrievalPacket) -> tuple[str, ...]:
    ids = [PUBLIC_AUTHORIZATION_ID]
    if any(
        item.snapshot_id == "phase2-fixture-contradiction-v1"
        for item in packet.ordered_evidence
    ):
        ids.append(TREATMENT_AUTHORIZATION_ID)
    return tuple(ids)


def _metric_applicability(slot: ProviderSlot) -> MetricApplicability:
    applicable = slot.condition != "lexical_direct_answer"
    return MetricApplicability(
        citation_support=applicable,
        evidence_coverage=applicable,
        citation_authority=applicable,
    )


def _packet_documents(
    packet: RetrievalPacket,
    documents: list[NormalizedDocument],
) -> list[NormalizedDocument]:
    allowed_spans: dict[str, set[str]] = {}
    for evidence in packet.ordered_evidence:
        _document_id, separator, span_id = evidence.evidence_id.rpartition(":")
        if not separator or _document_id != evidence.document_id:
            raise ProviderRunError("retrieval packet evidence identity is malformed")
        allowed_spans.setdefault(evidence.document_id, set()).add(span_id)
    filtered: list[NormalizedDocument] = []
    for document in documents:
        span_ids = allowed_spans.get(document.document_id)
        if span_ids is None:
            continue
        filtered.append(
            document.model_copy(
                update={
                    "spans": [
                        span for span in document.spans if span.span_id in span_ids
                    ]
                }
            )
        )
    return filtered


def validate_canary_acceptance(
    results: tuple[ProviderExecutionResult, ...],
    config: ProviderExperimentConfig,
) -> None:
    """Apply the tightened zero-failure first-adapter canary gate."""

    if len(results) != 12 or [item.slot.ordinal for item in results] != list(range(12)):
        raise ProviderRunError("canary result denominator is incomplete")
    for start in range(0, 12, 3):
        triplet = results[start : start + 3]
        if (
            len({(item.slot.case_id, item.slot.repeat_index) for item in triplet}) != 1
            or {item.slot.condition for item in triplet} != set(config.conditions)
            or len({item.retrieval_packet_sha256 for item in triplet}) != 1
            or len({item.invariant_sha256 for item in triplet}) != 1
        ):
            raise ProviderRunError("canary triplet isolation invariant failed")
    for item in results:
        run = item.run
        returned_model = run.model_snapshot_or_version
        expected_model = (
            returned_model == "gpt-5.6-luna-fake"
            if item.execution_mode == "fake"
            else (
                returned_model == config.model
                or (
                    returned_model is not None
                    and _LUNA_SNAPSHOT_PATTERN.fullmatch(returned_model) is not None
                )
            )
        )
        if (
            run.provider_status != "allowed"
            or run.security_outcome != "allowed"
            or run.parse_status != "valid"
            or run.deterministic_outcome != "graded"
            or run.input_tokens > config.input_token_reservation
            or run.output_tokens > config.max_output_tokens
            or not expected_model
            or item.provider_service_tier != config.service_tier
            or not 0 <= item.reasoning_tokens <= run.output_tokens
        ):
            raise ProviderRunError("canary has a provider, safety, or schema failure")
    total_cost = sum(
        (item.run.estimated_cost_usd for item in results),
        Decimal("0"),
    )
    if total_cost > config.cost_cap_usd:
        raise ProviderRunError("canary reconciled cost exceeds the hard cap")
    if config.version == "phase2-openai-luna-v2":
        for item in results:
            _validate_v2_semantic_slot(item)


def _validate_v2_semantic_slot(item: ProviderExecutionResult) -> None:
    """Enforce one slot's preregistered v2 semantic repair criteria."""

    abstention_cases = {
        "real-kev-preavailability",
        "real-red-hat-affected-insufficient",
    }
    answerable_cases = {
        "real-nvd-cvss-combined-treatment",
        "real-red-hat-fixed-id",
    }
    answer = item.answer
    if answer is None or item.slot.case_id not in abstention_cases | answerable_cases:
        raise ProviderRunError("v2 canary semantic case binding is invalid")
    if item.slot.case_id in abstention_cases:
        if (
            not answer.abstained
            or answer.claims
            or len(item.grades) != 1
            or item.grades[0].abstention_outcome != "correct"
            or item.grades[0].generated_claim_id is not None
            or item.grades[0].expected_claim_id is not None
        ):
            raise ProviderRunError("v2 canary abstention criterion failed")
        return
    if (
        answer.abstained
        or len(answer.claims) != 1
        or len(item.grades) != 1
        or item.grades[0].generated_claim_id is None
        or item.grades[0].expected_claim_id is None
        or item.grades[0].value_match != "exact"
        or item.grades[0].abstention_outcome != "not_applicable"
    ):
        raise ProviderRunError("v2 canary exact claim criterion failed")
    if item.slot.condition == "lexical_direct_answer":
        return
    if item.grades[0].claim_support != "supported" or not any(
        assessment.resolution == "resolved"
        and assessment.entailment == "supported"
        and assessment.temporality == "admissible"
        and assessment.authority == "accepted"
        and assessment.span_hash_match is True
        for assessment in item.grades[0].evidence_assessments
    ):
        raise ProviderRunError("v2 canary citation criterion failed")


def _validate_live_slot_acceptance(
    item: ProviderExecutionResult,
    config: ProviderExperimentConfig,
) -> None:
    run = item.run
    returned_model = run.model_snapshot_or_version
    model_allowed = returned_model == config.model or (
        returned_model is not None
        and _LUNA_SNAPSHOT_PATTERN.fullmatch(returned_model) is not None
    )
    if (
        run.provider_status != "allowed"
        or run.security_outcome != "allowed"
        or run.parse_status != "valid"
        or run.deterministic_outcome != "graded"
        or run.input_tokens > config.input_token_reservation
        or run.output_tokens > config.max_output_tokens
        or not model_allowed
        or item.provider_service_tier != config.service_tier
        or not 0 <= item.reasoning_tokens <= run.output_tokens
    ):
        raise ProviderRunError(
            "live canary slot failed; no later provider request is allowed"
        )
    if config.version == "phase2-openai-luna-v2":
        _validate_v2_semantic_slot(item)


def _load_approval_binding(path: Path) -> ApprovalBinding:
    try:
        return ApprovalBinding.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProviderRunError(
            "provider approval binding is missing or invalid"
        ) from exc


def _external_approval_path(
    project_root: Path,
    paths: ProviderArtifactPaths,
    approval_path: Path,
) -> Path:
    if approval_path.is_symlink():
        raise ProviderRunError("external approval cannot be a link")
    try:
        resolved = approval_path.resolve(strict=True)
    except OSError as exc:
        raise ProviderRunError("external approval is missing") from exc
    if (
        not resolved.is_file()
        or _is_within(resolved, project_root)
        or _is_within(resolved, paths.redacted_root)
        or _is_within(resolved, paths.private_root)
    ):
        raise ProviderRunError(
            "external approval must be a regular file outside provider artifacts "
            "and the project"
        )
    return resolved


def _acquire_run_lock(path: Path, binding: ApprovalBinding) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            {
                "approval_hash": binding.approval_hash,
                "execution_mode": binding.execution_mode,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ProviderRunError(
            "provider run lock exists; reconcile before any resume"
        ) from exc


def _write_or_verify_private(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise ProviderRunError("private provider artifact differs on resume")
        return
    _write_private_bytes(path, content)


def _response_artifact_paths(
    paths: ProviderArtifactPaths,
    attempt_id: str,
) -> tuple[Path, Path]:
    return (
        paths.private_root / "responses" / f"{attempt_id}.body",
        paths.private_root / "response-headers" / f"{attempt_id}.json",
    )


def _validate_private_attempt_artifacts(
    paths: ProviderArtifactPaths,
    terminal: AttemptTerminal,
) -> None:
    request_path = paths.private_root / "requests" / f"{terminal.run_id}.json"
    try:
        request_hash = _sha256_bytes(request_path.read_bytes())
    except OSError as exc:
        raise ProviderRunError("private provider request artifact is missing") from exc
    if request_hash != terminal.request_body_sha256:
        raise ProviderRunError("private provider request hash does not replay")
    response_path, headers_path = _response_artifact_paths(paths, terminal.attempt_id)
    if terminal.response_body_sha256 is None:
        if response_path.exists() or headers_path.exists():
            raise ProviderRunError("unexpected private response artifact")
        return
    try:
        response_hash = _sha256_bytes(response_path.read_bytes())
        headers_hash = _sha256_bytes(headers_path.read_bytes())
    except OSError as exc:
        raise ProviderRunError("private provider response artifact is missing") from exc
    if (
        response_hash != terminal.response_body_sha256
        or headers_hash != terminal.response_headers_sha256
    ):
        raise ProviderRunError("private provider response hash does not replay")


def _read_response_metadata(path: Path) -> tuple[int, dict[str, str]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderRunError("private provider headers are invalid") from exc
    if (
        not isinstance(raw, Mapping)
        or set(raw) != {"http_status", "headers"}
        or not isinstance(raw["http_status"], int)
        or isinstance(raw["http_status"], bool)
        or not 100 <= raw["http_status"] <= 599
        or not isinstance(raw["headers"], Mapping)
        or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw["headers"].items()
        )
    ):
        raise ProviderRunError("private provider headers are invalid")
    return raw["http_status"], dict(raw["headers"])


def _replay_attempt(
    *,
    paths: ProviderArtifactPaths,
    terminal: AttemptTerminal,
    reservation: AttemptReservation,
    safety_event: SafetyEvent,
    reconciliation: CostReconciliation,
    slot: ProviderSlot,
    packet: RetrievalPacket,
    plan: ProviderRequestPlan,
    config: ProviderExperimentConfig,
    authorization_hash: str,
    approval: ApprovalBinding,
    pricing_hash: str,
) -> tuple[
    OpenAIResult,
    ClaimAnswer | ClaimEvidenceAnswer | None,
    ParseStatus,
    ErrorCategory,
]:
    """Reconstruct one normalized provider outcome from quarantined exact bytes."""

    request = _adapter_request(plan)
    if terminal.response_body_sha256 is None:
        if terminal.result_class not in {"transport_error", "timeout_ambiguous"}:
            raise ProviderRunError("response-free terminal class is inconsistent")
        result = OpenAIResult(
            kind=(
                "transport_error"
                if terminal.result_class == "transport_error"
                else "timeout"
            ),
            semantic_request_sha256=plan.semantic_request_sha256,
            http_status=None,
            provider_request_id_sha256=None,
            model=None,
            service_tier=None,
            output_text=None,
            refusal=None,
            incomplete_reason=None,
            input_tokens=0,
            cached_input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
            error_code=None,
            raw_response_body=None,
            selected_response_headers={},
        )
    else:
        if terminal.provider_http_status is None:
            raise ProviderRunError("provider HTTP status is missing")
        response_path, headers_path = _response_artifact_paths(
            paths,
            terminal.attempt_id,
        )
        body = response_path.read_bytes()
        private_status, headers = _read_response_metadata(headers_path)
        if private_status != terminal.provider_http_status:
            raise ProviderRunError("provider HTTP status does not match quarantine")
        adapter = OpenAIResponsesAdapter(
            lambda _request, *, timeout_seconds: OpenAIHttpResponse(
                private_status,
                headers,
                body,
            )
        )
        result = adapter.send(
            request,
            "OFFLINE_REPLAY_NO_EGRESS",
            timeout_seconds=config.timeout_seconds,
        )

    answer, parse_status, parse_error = _parse_answer(
        result,
        slot=slot,
        packet=packet,
    )
    terminal_class, safety, _provider, _error, _parse = _classify_result(result)
    if result.kind == "completed" and parse_status == "invalid":
        terminal_class = "schema_error"
    terminal_fields_match = (
        terminal.result_class == terminal_class
        and terminal.input_tokens == result.input_tokens
        and terminal.cached_input_tokens == result.cached_input_tokens
        and terminal.output_tokens == result.output_tokens
        and terminal.reasoning_tokens == result.reasoning_tokens
        and terminal.provider_http_status == result.http_status
        and terminal.provider_model == result.model
        and terminal.provider_service_tier == result.service_tier
        and terminal.provider_request_id_hash == result.provider_request_id_sha256
        and terminal.redacted_error_code == result.error_code
        and terminal.request_body_sha256 == plan.semantic_request_sha256
    )
    if not terminal_fields_match:
        raise ProviderRunError("terminal semantics do not replay from exact response")

    if result.kind == "timeout" or result.error_code == "invalid_usage":
        expected_cost = reservation.reserved_cost_usd
        expected_basis = "ambiguous_reserved_max"
    elif result.kind == "transport_error":
        expected_cost = Decimal("0")
        expected_basis = "known_zero"
    else:
        expected_cost = result.estimated_cost_usd
        expected_basis = "provider_usage_estimate"
    if (
        reconciliation.run_id != terminal.run_id
        or reconciliation.schedule_ordinal != terminal.schedule_ordinal
        or reconciliation.attempt_id != terminal.attempt_id
        or reconciliation.attempt_index != terminal.attempt_index
        or reconciliation.reconciled_at_utc != terminal.completed_at_utc
        or reconciliation.actual_cost_usd != expected_cost
        or reconciliation.cost_basis != expected_basis
        or reconciliation.pricing_hash != pricing_hash
    ):
        raise ProviderRunError("cost reconciliation does not replay from usage")

    expected_authorization_ids = _authorization_ids(packet)
    if (
        safety_event.run_id != terminal.run_id
        or safety_event.scenario_id != slot.case_id
        or safety_event.schedule_ordinal != terminal.schedule_ordinal
        or safety_event.attempt_id != terminal.attempt_id
        or safety_event.attempt_index != terminal.attempt_index
        or safety_event.recorded_at_utc != terminal.completed_at_utc
        or safety_event.authorization_id != expected_authorization_ids[0]
        or safety_event.authorization_ids != expected_authorization_ids
        or safety_event.authorization_hash != authorization_hash
        or safety_event.approval_id != approval.approval_id
        or safety_event.approved_at_utc != approval.approved_at_utc
        or safety_event.approval_hash != approval.approval_hash
        or safety_event.provider != config.provider
        or safety_event.model != config.model
        or safety_event.request_template_version != config.prompt_version
        or safety_event.request_template_hash != plan.prompt_sha256
        or safety_event.safety_outcome != safety
        or safety_event.provider_request_id_hash != result.provider_request_id_sha256
        or safety_event.retry_count != terminal.attempt_index - 1
        or safety_event.response_used_for_scoring != (parse_status == "valid")
        or safety_event.notes is not None
    ):
        raise ProviderRunError("safety event does not replay from exact response")
    return result, answer, parse_status, parse_error


def _replay_provider_results(
    project_root: Path,
    *,
    redacted_root: Path,
    private_root: Path,
    binding: ApprovalBinding,
    config_version: ProviderConfigVersion,
) -> tuple[ProviderExecutionResult, ...]:
    """Recompute a complete run or exact attempted prefix from a trusted binding."""

    project_root = project_root.resolve(strict=True)
    paths = validate_artifact_paths(
        project_root,
        redacted_root=redacted_root,
        private_root=private_root,
    )
    config, authorization, schedule, packets = load_provider_inputs(
        project_root,
        config_version=config_version,
    )
    canary = schedule[:12]
    plans = {
        slot.slot_id: build_provider_request(slot, packets[slot.case_id], config)
        for slot in canary
    }
    request_manifest_hash = canary_request_manifest_sha256(
        config,
        schedule,
        packets,
    )
    stored_binding = _load_approval_binding(paths.approval)
    if binding.execution_mode == "fake":
        if paths.user_approval.exists():
            raise ProviderRunError("fake replay cannot use a user approval")
        if binding != _fake_approval_binding(config):
            raise ProviderRunError("fake approval binding does not replay")
    else:
        stored_approval = load_user_run_approval(paths.user_approval)
        if (
            _live_approval_binding(
                stored_approval,
                config,
                request_manifest_sha256=request_manifest_hash,
            )
            != binding
        ):
            raise ProviderRunError("stored live approval binding does not replay")
    if stored_binding != binding:
        raise ProviderRunError("provider approval binding does not replay")
    expected_planned = tuple(
        _planned_slot(
            slot,
            plans[slot.slot_id],
            config,
            authorization.bundle_sha256,
            _authorization_ids(packets[slot.case_id]),
            binding,
        )
        for slot in canary
    )
    state = _load_state(paths)
    if state.planned_slots != expected_planned:
        raise ProviderRunError("ledger schedule differs from frozen expected schedule")
    try:
        saved = load_jsonl_records(paths.results, ProviderExecutionResult)
    except ValueError as exc:
        raise ProviderRunError("saved provider result ledger is invalid") from exc
    if (
        len(saved) > len(canary)
        or tuple(item.slot for item in saved) != canary[: len(saved)]
    ):
        raise ProviderRunError("saved provider results are not a schedule prefix")
    saved_run_ids = {item.slot.slot_id for item in saved}
    started_run_ids = {item.run_id for item in state.reservations}
    terminal_run_ids = {item.run_id for item in state.terminals}
    if started_run_ids != saved_run_ids or terminal_run_ids != saved_run_ids:
        raise ProviderRunError(
            "attempted and unattempted provider slots do not match saved prefix"
        )
    if state.ambiguous_attempt_ids:
        raise ProviderRunError("saved prefix has an unfinished provider attempt")
    if len(saved) == len(canary):
        state.finalize(expected_planned)
    for terminal in state.terminals:
        _validate_private_attempt_artifacts(paths, terminal)
    slot_by_run = {slot.slot_id: slot for slot in canary}
    reservation_by_key = {
        (item.run_id, item.attempt_id): item for item in state.reservations
    }
    safety_by_key = {
        (item.run_id, item.attempt_id): item for item in state.safety_events
    }
    reconciliation_by_key = {
        (item.run_id, item.attempt_id): item for item in state.reconciliations
    }
    terminal_keys = {(item.run_id, item.attempt_id) for item in state.terminals}
    if (
        set(reservation_by_key) != terminal_keys
        or set(safety_by_key) != terminal_keys
        or set(reconciliation_by_key) != terminal_keys
    ):
        raise ProviderRunError("attempt lifecycle ledgers are not complete")
    terminals_by_run: dict[str, list[AttemptTerminal]] = {}
    for terminal in state.terminals:
        terminals_by_run.setdefault(terminal.run_id, []).append(terminal)
    reconciliations_by_run: dict[str, list[CostReconciliation]] = {}
    for reconciliation in state.reconciliations:
        reconciliations_by_run.setdefault(reconciliation.run_id, []).append(
            reconciliation
        )
    pricing_hash = canonical_sha256(config.pricing.model_dump(mode="json"))
    replayed_attempts: dict[
        tuple[str, str],
        tuple[
            OpenAIResult,
            ClaimAnswer | ClaimEvidenceAnswer | None,
            ParseStatus,
            ErrorCategory,
        ],
    ] = {}
    for terminal in state.terminals:
        key = (terminal.run_id, terminal.attempt_id)
        slot = slot_by_run[terminal.run_id]
        replayed_attempts[key] = _replay_attempt(
            paths=paths,
            terminal=terminal,
            reservation=reservation_by_key[key],
            safety_event=safety_by_key[key],
            reconciliation=reconciliation_by_key[key],
            slot=slot,
            packet=packets[slot.case_id],
            plan=plans[slot.slot_id],
            config=config,
            authorization_hash=authorization.bundle_sha256,
            approval=binding,
            pricing_hash=pricing_hash,
        )

    states, documents = load_phase2_real_corpus(project_root)
    cases = load_phase2_real_cases(project_root, states=states, documents=documents)
    by_case = {case.case_id: case for case in cases}
    dataset_version = _dataset_version(project_root)
    for expected_slot, item in zip(canary[: len(saved)], saved, strict=True):
        packet = packets[expected_slot.case_id]
        plan = plans[expected_slot.slot_id]
        if (
            item.slot != expected_slot
            or item.execution_mode != binding.execution_mode
            or item.approval_id != binding.approval_id
            or item.approved_at_utc != binding.approved_at_utc
            or item.approval_hash != binding.approval_hash
            or item.retrieval_packet_sha256 != packet.packet_sha256
            or item.invariant_sha256 != plan.invariant_sha256
            or item.semantic_request_sha256 != plan.semantic_request_sha256
            or item.answer_schema
            != (
                "claim_evidence_answer"
                if item.slot.condition == "lexical_claim_evidence_constrained"
                else "claim_answer"
            )
            or item.metric_applicability != _metric_applicability(expected_slot)
        ):
            raise ProviderRunError("saved provider result binding does not replay")
        request_bytes = json.dumps(
            plan.body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        request_path = paths.private_root / "requests" / f"{item.slot.slot_id}.json"
        try:
            actual_request = request_path.read_bytes()
        except OSError as exc:
            raise ProviderRunError(
                "private provider request artifact is missing"
            ) from exc
        if actual_request != request_bytes:
            raise ProviderRunError("exact provider request bytes do not replay")
        case = by_case[item.slot.case_id]
        run_terminals = sorted(
            terminals_by_run[item.slot.slot_id],
            key=lambda terminal: terminal.attempt_index,
        )
        final_terminal = run_terminals[-1]
        (
            final_result,
            replayed_answer,
            replayed_parse_status,
            replayed_parse_error,
        ) = replayed_attempts[(final_terminal.run_id, final_terminal.attempt_id)]
        answer = (
            ClaimAnswer.model_validate(replayed_answer.model_dump(mode="python"))
            if replayed_answer is not None
            else None
        )
        if answer != item.answer:
            raise ProviderRunError("saved answer does not replay from exact response")
        expected_grades = (
            tuple(
                grade_answer(
                    case=case,
                    answer=answer,
                    documents=_packet_documents(packet, documents),
                    states=states,
                )
            )
            if answer is not None
            else ()
        )
        run_reconciliations = reconciliations_by_run[item.slot.slot_id]
        total_cost = sum(
            (reconciliation.actual_cost_usd for reconciliation in run_reconciliations),
            Decimal("0"),
        )
        expected_run = _run_record(
            slot=item.slot,
            packet=packet,
            config=config,
            result=final_result,
            answer=answer,
            parse_status=replayed_parse_status,
            parse_error=replayed_parse_error,
            retry_count=final_terminal.attempt_index - 1,
            latency_ms=final_terminal.latency_ms,
            recorded_at=item.run.recorded_at_utc,
            corpus_manifest_hash=_manifest_hash(case, states),
            dataset_version=dataset_version,
            accounted_cost_usd=total_cost,
        )
        if item.run.recorded_at_utc < final_terminal.completed_at_utc:
            raise ProviderRunError("saved run-record binding does not replay")
        expected_output = ProviderExecutionResult(
            slot=item.slot,
            execution_mode=binding.execution_mode,
            approval_id=binding.approval_id,
            approved_at_utc=binding.approved_at_utc,
            approval_hash=binding.approval_hash,
            retrieval_packet_sha256=packet.packet_sha256,
            invariant_sha256=plan.invariant_sha256,
            semantic_request_sha256=plan.semantic_request_sha256,
            provider_service_tier=final_result.service_tier,
            reasoning_tokens=final_result.reasoning_tokens,
            answer_schema=(
                "claim_evidence_answer"
                if item.slot.condition == "lexical_claim_evidence_constrained"
                else "claim_answer"
            ),
            metric_applicability=_metric_applicability(item.slot),
            run=expected_run,
            answer=answer,
            grades=expected_grades,
        )
        if item != expected_output:
            raise ProviderRunError("saved run-record binding does not replay")
    if len(saved) == len(canary):
        validate_canary_acceptance(saved, config)
    return saved


def replay_provider_results(
    project_root: Path,
    *,
    redacted_root: Path,
    private_root: Path,
    approval_path: Path | None = None,
    config_version: ProviderConfigVersion = "v2",
) -> tuple[ProviderExecutionResult, ...]:
    """Recompute a complete run or exact attempted prefix without egress."""

    project_root = project_root.resolve(strict=True)
    paths = validate_artifact_paths(
        project_root,
        redacted_root=redacted_root,
        private_root=private_root,
    )
    config, _authorization, schedule, packets = load_provider_inputs(
        project_root,
        config_version=config_version,
    )
    request_manifest_hash = canary_request_manifest_sha256(
        config,
        schedule,
        packets,
    )
    stored_binding = _load_approval_binding(paths.approval)
    external_path = (
        _external_approval_path(project_root, paths, approval_path)
        if approval_path is not None
        else None
    )
    if stored_binding.execution_mode == "fake":
        if external_path is not None or paths.user_approval.exists():
            raise ProviderRunError("fake replay cannot use a user approval")
        binding = _fake_approval_binding(config)
    else:
        if external_path is None:
            raise ProviderRunError(
                "live replay requires the original external user approval"
            )
        external_approval = load_user_run_approval(external_path)
        stored_approval = load_user_run_approval(paths.user_approval)
        if stored_approval != external_approval:
            raise ProviderRunError("stored and external user approvals differ")
        binding = _live_approval_binding(
            external_approval,
            config,
            request_manifest_sha256=request_manifest_hash,
        )
    if stored_binding != binding:
        raise ProviderRunError("provider approval binding does not replay")
    return _replay_provider_results(
        project_root,
        redacted_root=paths.redacted_root,
        private_root=paths.private_root,
        binding=binding,
        config_version=config_version,
    )


def run_provider_canary(
    project_root: Path,
    *,
    mode: ExecutionMode,
    redacted_root: Path,
    private_root: Path,
    transport: OpenAITransport | None = None,
    app_config: AppConfig | None = None,
    approval: UserRunApproval | None = None,
    now: Callable[[], datetime] | None = None,
    sleep: Callable[[float], None] | None = None,
    enforce_acceptance: bool = True,
    resume: bool = False,
    config_version: ProviderConfigVersion = "v2",
) -> tuple[ProviderExecutionResult, ...]:
    """Execute exactly the first four complete schedule triplets.

    In fake mode an injected transport is mandatory and credentials are
    rejected. In live mode the standard transport is used unless a test-only
    transport is explicitly injected by a caller that has already supplied the
    exact approval and environment.
    """

    project_root = project_root.resolve(strict=True)
    if mode == "live" and not enforce_acceptance:
        raise ProviderRunError("live provider execution cannot disable acceptance")
    if mode == "live" and (approval is None or app_config is None):
        raise ProviderRunError("live mode requires explicit approval and configuration")
    if mode == "live" and transport is not None:
        raise ProviderRunError("live mode requires the fixed standard transport")
    if mode == "fake" and (app_config is not None or approval is not None):
        raise ProviderRunError("fake mode cannot accept credentials or approval")
    if mode == "fake" and transport is None:
        raise ProviderRunError("fake canary requires an injected transport")
    config, authorization, schedule, packets = load_provider_inputs(
        project_root,
        config_version=config_version,
    )
    canary = schedule[:12]
    plans = {
        slot.slot_id: build_provider_request(slot, packets[slot.case_id], config)
        for slot in canary
    }
    request_manifest_hash = canary_request_manifest_sha256(
        config,
        schedule,
        packets,
    )
    key, approval_binding = _authorization_preflight(
        mode=mode,
        config=config,
        app_config=app_config,
        approval=approval,
        request_manifest_sha256=request_manifest_hash,
    )
    paths = validate_artifact_paths(
        project_root,
        redacted_root=redacted_root,
        private_root=private_root,
    )
    clock = now or (lambda: datetime.now(UTC))
    sleeper = sleep or time.sleep
    planned = tuple(
        _planned_slot(
            slot,
            plans[slot.slot_id],
            config,
            authorization.bundle_sha256,
            _authorization_ids(packets[slot.case_id]),
            approval_binding,
        )
        for slot in canary
    )
    if (
        sum(
            (_PER_ATTEMPT_RESERVATION * 2 for _slot in planned),
            Decimal("0"),
        )
        > config.cost_cap_usd
    ):
        raise ProviderRunError("canary worst-case retry reservation exceeds cap")
    _acquire_run_lock(paths.lock, approval_binding)
    if resume:
        existing_binding = _load_approval_binding(paths.approval)
        if existing_binding != approval_binding:
            raise ProviderRunError("resume approval binding differs")
        if mode == "live":
            if approval is None:
                raise ProviderRunError("live resume approval is missing")
            if load_user_run_approval(paths.user_approval) != approval:
                raise ProviderRunError("live resume user approval differs")
        elif paths.user_approval.exists():
            raise ProviderRunError("fake resume found an unexpected user approval")
        existing_planned = load_jsonl_records(paths.planned, PlannedSlot)
        if existing_planned != planned:
            raise ProviderRunError("resume schedule differs from frozen canary")
    else:
        if any(
            path.exists()
            for path in (
                paths.planned,
                paths.reservations,
                paths.terminals,
                paths.safety_events,
                paths.reconciliations,
                paths.results,
                paths.approval,
                paths.user_approval,
            )
        ):
            raise ProviderRunError("provider run directory already contains artifacts")
        _atomic_write_model(paths.approval, approval_binding)
        if mode == "live":
            if approval is None:
                raise ProviderRunError("live user approval is missing")
            _atomic_write_model(paths.user_approval, approval)
        for item in planned:
            append_jsonl_record(paths.planned, item)
    adapter = (
        OpenAIResponsesAdapter(transport)
        if transport is not None
        else OpenAIResponsesAdapter()
    )
    states, documents = load_phase2_real_corpus(project_root)
    cases = load_phase2_real_cases(
        project_root,
        states=states,
        documents=documents,
    )
    by_case = {case.case_id: case for case in cases}
    dataset_version = _dataset_version(project_root)
    outputs = list(load_jsonl_records(paths.results, ProviderExecutionResult))
    if [item.slot for item in outputs] != list(canary[: len(outputs)]):
        raise ProviderRunError("resume results are not a complete schedule prefix")
    state = _load_state(paths)
    if resume:
        replayed = _replay_provider_results(
            project_root,
            redacted_root=paths.redacted_root,
            private_root=paths.private_root,
            binding=approval_binding,
            config_version=config_version,
        )
        if replayed != tuple(outputs):
            raise ProviderRunError("resume result prefix does not replay")
        if mode == "live":
            for prior_output in replayed:
                _validate_live_slot_acceptance(prior_output, config)
    if state.ambiguous_attempt_ids or any(
        item.result_class == "timeout_ambiguous" for item in state.terminals
    ):
        raise ProviderRunError("ambiguous prior attempt blocks provider resume")
    started_run_ids = {item.run_id for item in state.reservations}
    if started_run_ids != {item.slot.slot_id for item in outputs}:
        raise ProviderRunError("resume requires fully recorded prefix slots")
    pricing_hash = canonical_sha256(config.pricing.model_dump(mode="json"))
    for slot, _ledger_slot in zip(
        canary[len(outputs) :],
        planned[len(outputs) :],
        strict=True,
    ):
        plan = plans[slot.slot_id]
        packet = packets[slot.case_id]
        request = _adapter_request(plan)
        request_bytes = json.dumps(
            plan.body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        _write_or_verify_private(
            paths.private_root / "requests" / f"{slot.slot_id}.json",
            request_bytes,
        )
        attempt_index = 1
        while True:
            attempt_id = f"{slot.slot_id}-a{attempt_index}"
            started = clock()
            reservation = AttemptReservation(
                run_id=slot.slot_id,
                schedule_ordinal=slot.ordinal + 1,
                attempt_id=attempt_id,
                attempt_index=attempt_index,
                reserved_at_utc=started,
                execution_mode=approval_binding.execution_mode,
                authorization_hash=authorization.bundle_sha256,
                approval_id=approval_binding.approval_id,
                approved_at_utc=approval_binding.approved_at_utc,
                approval_hash=approval_binding.approval_hash,
                config_hash=config.sha256(),
                prompt_hash=plan.prompt_sha256,
                request_hash=plan.semantic_request_sha256,
                retrieval_hash=packet.packet_sha256,
                semantic_request_hash=plan.semantic_request_sha256,
                reserved_cost_usd=_PER_ATTEMPT_RESERVATION,
            )
            append_jsonl_record(paths.reservations, reservation)
            monotonic_start = time.monotonic()
            result = adapter.send(
                request,
                key,
                timeout_seconds=config.timeout_seconds,
            )
            completed = clock()
            latency_ms = max(0, int((time.monotonic() - monotonic_start) * 1000))
            attempt_answer, attempt_parse_status, attempt_parse_error = _parse_answer(
                result,
                slot=slot,
                packet=packet,
            )
            terminal_class, safety, _provider, _error, _parse = _classify_result(result)
            if result.kind == "completed" and attempt_parse_status == "invalid":
                terminal_class = "schema_error"
            response_body_hash: str | None = None
            response_headers_hash: str | None = None
            if result.raw_response_body is not None:
                response_path, headers_path = _response_artifact_paths(
                    paths,
                    attempt_id,
                )
                header_bytes = json.dumps(
                    {
                        "http_status": result.http_status,
                        "headers": dict(result.selected_response_headers),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
                _write_or_verify_private(response_path, result.raw_response_body)
                _write_or_verify_private(headers_path, header_bytes)
                response_body_hash = _sha256_bytes(result.raw_response_body)
                response_headers_hash = _sha256_bytes(header_bytes)
            terminal = AttemptTerminal(
                run_id=slot.slot_id,
                schedule_ordinal=slot.ordinal + 1,
                attempt_id=attempt_id,
                attempt_index=attempt_index,
                completed_at_utc=completed,
                result_class=terminal_class,
                input_tokens=result.input_tokens,
                cached_input_tokens=result.cached_input_tokens,
                output_tokens=result.output_tokens,
                reasoning_tokens=result.reasoning_tokens,
                latency_ms=latency_ms,
                provider_http_status=result.http_status,
                provider_model=result.model,
                provider_service_tier=result.service_tier,
                provider_request_id_hash=result.provider_request_id_sha256,
                request_body_sha256=_sha256_bytes(request_bytes),
                response_body_sha256=response_body_hash,
                response_headers_sha256=response_headers_hash,
                redacted_error_code=result.error_code,
            )
            safety_event = SafetyEvent(
                run_id=slot.slot_id,
                scenario_id=slot.case_id,
                schedule_ordinal=slot.ordinal + 1,
                attempt_id=attempt_id,
                attempt_index=attempt_index,
                recorded_at_utc=completed,
                authorization_id=_authorization_ids(packet)[0],
                authorization_ids=_authorization_ids(packet),
                authorization_hash=authorization.bundle_sha256,
                approval_id=approval_binding.approval_id,
                approved_at_utc=approval_binding.approved_at_utc,
                approval_hash=approval_binding.approval_hash,
                provider="openai",
                model=config.model,
                request_template_version=config.prompt_version,
                request_template_hash=plan.prompt_sha256,
                safety_outcome=safety,
                provider_request_id_hash=result.provider_request_id_sha256,
                retry_count=attempt_index - 1,
                response_used_for_scoring=attempt_parse_status == "valid",
            )
            append_jsonl_record(
                paths.safety_events,
                safety_event,
            )
            append_jsonl_record(paths.terminals, terminal)
            cost_basis: Literal[
                "provider_usage_estimate",
                "known_zero",
                "ambiguous_reserved_max",
            ]
            if result.kind == "timeout" or result.error_code == "invalid_usage":
                accounted_cost = reservation.reserved_cost_usd
                cost_basis = "ambiguous_reserved_max"
            elif result.kind == "transport_error":
                accounted_cost = Decimal("0")
                cost_basis = "known_zero"
            else:
                accounted_cost = result.estimated_cost_usd
                cost_basis = "provider_usage_estimate"
            append_jsonl_record(
                paths.reconciliations,
                CostReconciliation(
                    run_id=slot.slot_id,
                    schedule_ordinal=slot.ordinal + 1,
                    attempt_id=attempt_id,
                    attempt_index=attempt_index,
                    reconciled_at_utc=completed,
                    actual_cost_usd=accounted_cost,
                    cost_basis=cost_basis,
                    pricing_hash=pricing_hash,
                ),
            )
            state = _load_state(paths)
            if result.retry_class in {
                "rate_limited",
                "transient_server",
                "transient_transport",
            } and state.can_send_next_attempt(slot.slot_id):
                sleeper(config.retry_backoff_seconds)
                attempt_index += 1
                continue
            break
        answer = attempt_answer
        parse_status = attempt_parse_status
        parse_error = attempt_parse_error
        case = by_case[slot.case_id]
        grades = (
            tuple(
                grade_answer(
                    case=case,
                    answer=answer,
                    documents=_packet_documents(packet, documents),
                    states=states,
                )
            )
            if answer is not None
            else ()
        )
        run = _run_record(
            slot=slot,
            packet=packet,
            config=config,
            result=result,
            answer=answer,
            parse_status=parse_status,
            parse_error=parse_error,
            retry_count=attempt_index - 1,
            latency_ms=terminal.latency_ms,
            recorded_at=clock(),
            corpus_manifest_hash=_manifest_hash(case, states),
            dataset_version=dataset_version,
            accounted_cost_usd=sum(
                (
                    item.actual_cost_usd
                    for item in _load_state(paths).reconciliations
                    if item.run_id == slot.slot_id
                ),
                Decimal("0"),
            ),
        )
        output = ProviderExecutionResult(
            slot=slot,
            execution_mode=approval_binding.execution_mode,
            approval_id=approval_binding.approval_id,
            approved_at_utc=approval_binding.approved_at_utc,
            approval_hash=approval_binding.approval_hash,
            retrieval_packet_sha256=packet.packet_sha256,
            invariant_sha256=plan.invariant_sha256,
            semantic_request_sha256=plan.semantic_request_sha256,
            provider_service_tier=result.service_tier,
            reasoning_tokens=result.reasoning_tokens,
            answer_schema=(
                "claim_evidence_answer"
                if slot.condition == "lexical_claim_evidence_constrained"
                else "claim_answer"
            ),
            metric_applicability=_metric_applicability(slot),
            run=run,
            answer=(
                ClaimAnswer.model_validate(answer.model_dump())
                if answer is not None
                else None
            ),
            grades=grades,
        )
        _append_result(paths.results, output)
        outputs.append(output)
        if mode == "live":
            _validate_live_slot_acceptance(output, config)
        if terminal.result_class == "timeout_ambiguous":
            raise ProviderRunError(
                "ambiguous timeout accounted at reservation maximum; run stopped"
            )
    _load_state(paths).finalize(planned)
    finalized = tuple(outputs)
    if enforce_acceptance:
        validate_canary_acceptance(finalized, config)
    paths.lock.unlink()
    return finalized
