"""Narrow execution and deterministic reporting for the frozen V6 Luna run."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cti_provenance.claims.diverse_portfolio_v4 import (
    DiverseQuestionV4,
    canonical_sha256,
)
from cti_provenance.claims.diverse_portfolio_v6 import DiverseCorpusV6
from cti_provenance.experiments.portfolio_diverse_provider import (
    PortfolioProviderPlan,
    PortfolioProviderResponse,
    PortfolioProviderSlot,
    build_portfolio_request,
    candidate_alias_map,
)
from cti_provenance.grading import (
    grade_portfolio_diverse_outcome,
    grade_portfolio_diverse_provenance_outcome,
)
from cti_provenance.models.openai_client import OpenAIResponsesAdapter, OpenAIResult

PER_ATTEMPT_RESERVATION_USD = Decimal("0.052")
RUN_ID: Literal["portfolio-diverse-v6-luna-single-sample"] = (
    "portfolio-diverse-v6-luna-single-sample"
)


class PortfolioProviderResult(BaseModel):
    """One redacted terminal result; provider text remains private and ignored."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-provider-result-v1"]
    run_id: Literal["portfolio-diverse-v6-luna-single-sample"]
    slot_id: str
    ordinal: int = Field(ge=0, lt=192)
    case_id: str
    dependency_id: str
    case_slice: str
    split: Literal["dev", "validation"]
    variant: Literal["clean", "control", "challenge"]
    condition: Literal["citation_prompted", "claim_evidence_constrained"]
    attempt_count: int = Field(ge=1, le=3)
    result_kind: str
    provider_model: str | None
    provider_service_tier: str | None
    http_status: int | None
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    latency_ms: int = Field(ge=0)
    accounted_cost_usd: Decimal = Field(ge=0)
    parse_status: Literal["valid", "invalid", "not_applicable"]
    provenance_outcome_correct: bool
    exact_outcome_correct: bool
    component_tp: int = Field(ge=0)
    component_fp: int = Field(ge=0)
    component_fn: int = Field(ge=0)
    expected_abstention: bool
    correct_abstention: bool
    emitted_claim_count: int = Field(ge=0)
    output_text_sha256: str | None
    response_body_sha256: str | None
    request_semantic_sha256: str
    completed_at_utc: datetime


def _append_jsonl(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    line = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    with path.open("ab") as stream:
        stream.write(line)
        stream.flush()
        os.fsync(stream.fileno())


def load_provider_results(path: Path) -> tuple[PortfolioProviderResult, ...]:
    if not path.exists():
        return ()
    return tuple(
        PortfolioProviderResult.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    )


def _value_hash(datatype: str, value: Any) -> str:
    if datatype == "string_set" and isinstance(value, list):
        value = sorted(value)
    return canonical_sha256(value)


def _component_counts(
    question: DiverseQuestionV4,
    response: PortfolioProviderResponse,
    alias_map: dict[str, str],
) -> tuple[int, int, int]:
    if question.outcome_type == "abstain":
        return (0, len(response.components), 0)
    expected: Counter[tuple[object, ...]] = Counter(
        (
            item.kind,
            item.predicate,
            item.datatype,
            _value_hash(item.datatype, item.value),
            tuple(sorted(item.required_evidence_ids)),
        )
        for item in question.expected_components
    )
    actual: Counter[tuple[object, ...]] = Counter()
    for item in response.components:
        citations = tuple(
            sorted(
                alias_map.get(alias, f"invalid:{alias}")
                for alias in item.cited_span_aliases
            )
        )
        actual[
            (
                item.kind,
                item.predicate,
                item.datatype,
                _value_hash(item.datatype, item.value),
                citations,
            )
        ] += 1
    tp = sum((expected & actual).values())
    return tp, sum(actual.values()) - tp, sum(expected.values()) - tp


def score_provider_result(
    *,
    root: Path,
    slot: PortfolioProviderSlot,
    result: OpenAIResult,
    attempt_count: int,
    latency_ms: int,
    accounted_cost_usd: Decimal,
) -> PortfolioProviderResult:
    corpus = DiverseCorpusV6.model_validate_json(
        (root / "data/benchmark/portfolio-diverse-draft-v6.json").read_text(
            encoding="utf-8"
        )
    )
    question = next(item for item in corpus.questions if item.case_id == slot.case_id)
    response: PortfolioProviderResponse | None = None
    parse_status: Literal["valid", "invalid", "not_applicable"] = "not_applicable"
    if result.kind == "completed" and result.output_text is not None:
        try:
            response = PortfolioProviderResponse.model_validate_json(result.output_text)
            if response.case_id != slot.case_id:
                raise ValueError("response case_id does not match scheduled case")
            parse_status = "valid"
        except ValueError:
            parse_status = "invalid"
    alias_map = candidate_alias_map(root=root, case_id=slot.case_id)
    exact = False
    provenance = False
    tp = fp = 0
    fn = len(question.expected_components) if question.outcome_type != "abstain" else 0
    if response is not None and parse_status == "valid":
        provenance = grade_portfolio_diverse_provenance_outcome(
            question,
            components=response.components,
            abstained=response.abstained,
            abstention_reason_code=response.abstention_reason_code,
            span_alias_to_evidence_id=alias_map,
        )
        exact = grade_portfolio_diverse_outcome(
            question,
            components=response.components,
            abstained=response.abstained,
            abstention_reason_code=response.abstention_reason_code,
            span_alias_to_evidence_id=alias_map,
        )
        tp, fp, fn = _component_counts(question, response, alias_map)
    expected_abstention = question.outcome_type == "abstain"
    correct_abstention = bool(
        expected_abstention
        and response is not None
        and parse_status == "valid"
        and response.abstained
        and exact
    )
    return PortfolioProviderResult(
        schema_version="portfolio-diverse-provider-result-v1",
        run_id=RUN_ID,
        slot_id=slot.slot_id,
        ordinal=slot.ordinal,
        case_id=slot.case_id,
        dependency_id=slot.dependency_id,
        case_slice=question.slice,
        split=question.split,
        variant=slot.variant,
        condition=slot.condition,
        attempt_count=attempt_count,
        result_kind=result.kind,
        provider_model=result.model,
        provider_service_tier=result.service_tier,
        http_status=result.http_status,
        input_tokens=result.input_tokens,
        cached_input_tokens=result.cached_input_tokens,
        output_tokens=result.output_tokens,
        reasoning_tokens=result.reasoning_tokens,
        latency_ms=latency_ms,
        accounted_cost_usd=accounted_cost_usd,
        parse_status=parse_status,
        provenance_outcome_correct=provenance,
        exact_outcome_correct=exact,
        component_tp=tp,
        component_fp=fp,
        component_fn=fn,
        expected_abstention=expected_abstention,
        correct_abstention=correct_abstention,
        emitted_claim_count=len(response.components) if response is not None else 0,
        output_text_sha256=(
            hashlib.sha256(result.output_text.encode()).hexdigest()
            if result.output_text is not None
            else None
        ),
        response_body_sha256=(
            hashlib.sha256(result.raw_response_body).hexdigest()
            if result.raw_response_body is not None
            else None
        ),
        request_semantic_sha256=result.semantic_request_sha256,
        completed_at_utc=datetime.now(UTC),
    )


def _write_private_result(
    private_root: Path,
    slot: PortfolioProviderSlot,
    attempt: int,
    result: OpenAIResult,
) -> None:
    directory = private_root / slot.slot_id
    directory.mkdir(parents=True, exist_ok=True)
    if result.raw_response_body is not None:
        (directory / f"attempt-{attempt}-response.json").write_bytes(
            result.raw_response_body
        )
    if result.output_text is not None:
        (directory / f"attempt-{attempt}-output.txt").write_text(
            result.output_text, encoding="utf-8"
        )


def _provider_result_requires_run_stop(result_kind: str) -> bool:
    """Stop on transport/API-envelope failures, not scientific model outcomes."""

    return result_kind in {
        "api_error",
        "invalid_response",
        "timeout",
        "transport_error",
    }


def run_frozen_portfolio_experiment(
    *,
    root: Path,
    api_key: str,
    redacted_root: Path,
    private_root: Path,
    timeout_seconds: float = 90.0,
) -> tuple[PortfolioProviderResult, ...]:
    """Execute or safely resume the exact frozen schedule."""

    root = root.resolve(strict=True)
    redacted_root = redacted_root.resolve()
    private_root = private_root.resolve()
    if root in private_root.parents or "onedrive" in str(private_root).casefold():
        raise ValueError("private provider artifacts must be outside repo and OneDrive")
    plan = PortfolioProviderPlan.model_validate_json(
        (root / "configs/experiments/portfolio-diverse-v6-openai-luna.json").read_text(
            encoding="utf-8"
        )
    )
    if plan.status != "ready_for_execution" or plan.egress_blocked_case_ids:
        raise ValueError("provider plan is not fully reviewed and egress eligible")
    schedule_payload = json.loads(
        (root / "data/benchmark/portfolio-diverse-provider-schedule-v1.json").read_text(
            encoding="utf-8"
        )
    )
    if (
        canonical_sha256(
            {
                "schema_version": schedule_payload["schema_version"],
                "created_at_utc": schedule_payload["created_at_utc"],
                "slots": schedule_payload["slots"],
            }
        )
        != schedule_payload["schedule_sha256"]
    ):
        raise ValueError("provider schedule hash changed")
    slots = tuple(
        PortfolioProviderSlot.model_validate(item) for item in schedule_payload["slots"]
    )
    results_path = redacted_root / "results.jsonl"
    existing = {item.slot_id: item for item in load_provider_results(results_path)}
    if len(existing) != len(load_provider_results(results_path)):
        raise ValueError("duplicate provider results prevent safe resume")
    adapter = OpenAIResponsesAdapter()
    attempts_path = redacted_root / "attempt-events.jsonl"
    attempt_events = (
        [
            json.loads(line)
            for line in attempts_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        if attempts_path.exists()
        else []
    )
    reservations = [item for item in attempt_events if item["event"] == "reserved"]
    terminals = {
        (item["slot_id"], item["attempt_index"])
        for item in attempt_events
        if item["event"] == "terminal"
    }
    dangling = [
        item
        for item in reservations
        if (item["slot_id"], item["attempt_index"]) not in terminals
    ]
    if dangling:
        raise ValueError("ambiguous reserved attempt prevents automatic resume")
    accounted = sum(
        (item.accounted_cost_usd for item in existing.values()), Decimal("0")
    )
    for slot in slots:
        if slot.slot_id in existing:
            continue
        request, packet = build_portfolio_request(root=root, slot=slot)
        if request.semantic_sha256() != slot.request_semantic_sha256:
            raise ValueError("scheduled request semantic hash changed")
        if packet["packet_sha256"] != slot.input_binding_sha256:
            raise ValueError("scheduled candidate packet hash changed")
        final_result: OpenAIResult | None = None
        total_latency = 0
        attempt_cost = Decimal("0")
        for attempt_index in range(1, plan.max_transient_retries + 2):
            if (
                accounted + attempt_cost + PER_ATTEMPT_RESERVATION_USD
                > plan.cost_cap_usd
            ):
                raise ValueError("next provider attempt would exceed the USD 30 cap")
            _append_jsonl(
                attempts_path,
                {
                    "event": "reserved",
                    "run_id": RUN_ID,
                    "slot_id": slot.slot_id,
                    "attempt_index": attempt_index,
                    "reserved_at_utc": datetime.now(UTC).isoformat(),
                    "request_semantic_sha256": request.semantic_sha256(),
                    "reservation_usd": str(PER_ATTEMPT_RESERVATION_USD),
                },
            )
            started = time.monotonic()
            result = adapter.send(request, api_key, timeout_seconds=timeout_seconds)
            elapsed = round((time.monotonic() - started) * 1000)
            total_latency += elapsed
            _write_private_result(private_root, slot, attempt_index, result)
            ambiguous = result.kind == "timeout"
            this_cost = (
                PER_ATTEMPT_RESERVATION_USD if ambiguous else result.estimated_cost_usd
            )
            attempt_cost += this_cost
            _append_jsonl(
                attempts_path,
                {
                    "event": "terminal",
                    "run_id": RUN_ID,
                    "slot_id": slot.slot_id,
                    "attempt_index": attempt_index,
                    "completed_at_utc": datetime.now(UTC).isoformat(),
                    "result_kind": result.kind,
                    "http_status": result.http_status,
                    "provider_model": result.model,
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "accounted_cost_usd": str(this_cost),
                    "response_body_sha256": (
                        hashlib.sha256(result.raw_response_body).hexdigest()
                        if result.raw_response_body is not None
                        else None
                    ),
                },
            )
            final_result = result
            if (
                result.retry_class
                not in {"rate_limited", "transient_server", "transient_transport"}
                or attempt_index == plan.max_transient_retries + 1
            ):
                break
            time.sleep(plan.transient_retry_backoff_seconds[attempt_index - 1])
        assert final_result is not None
        scored = score_provider_result(
            root=root,
            slot=slot,
            result=final_result,
            attempt_count=attempt_index,
            latency_ms=total_latency,
            accounted_cost_usd=attempt_cost,
        )
        if scored.provider_model is not None and not scored.provider_model.startswith(
            "gpt-5.6-luna"
        ):
            raise ValueError(
                "provider returned an unexpected model; no fallback allowed"
            )
        _append_jsonl(results_path, scored)
        existing[slot.slot_id] = scored
        accounted += attempt_cost
        if _provider_result_requires_run_stop(scored.result_kind):
            raise RuntimeError(
                "provider transport, API, or response-envelope failure recorded; "
                "stop before the remaining schedule"
            )
    return tuple(sorted(existing.values(), key=lambda item: item.ordinal))


def summarize_provider_results(
    results: tuple[PortfolioProviderResult, ...],
) -> dict[str, Any]:
    """Aggregate single-sample outcomes without inferential claims."""

    if len(results) != 192 or len({item.slot_id for item in results}) != 192:
        raise ValueError("complete result report requires all 192 scheduled cells")

    def metrics(rows: list[PortfolioProviderResult]) -> dict[str, Any]:
        tp = sum(item.component_tp for item in rows)
        fp = sum(item.component_fp for item in rows)
        fn = sum(item.component_fn for item in rows)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        return {
            "n": len(rows),
            "provenance_correct": sum(item.provenance_outcome_correct for item in rows),
            "provenance_rate": sum(item.provenance_outcome_correct for item in rows)
            / len(rows),
            "exact_correct": sum(item.exact_outcome_correct for item in rows),
            "exact_rate": sum(item.exact_outcome_correct for item in rows) / len(rows),
            "component_tp": tp,
            "component_fp": fp,
            "component_fn": fn,
            "component_precision": precision,
            "component_recall": recall,
            "parse_failures": sum(item.parse_status != "valid" for item in rows),
            "refusals": sum(item.result_kind == "refusal" for item in rows),
            "correct_abstentions": sum(item.correct_abstention for item in rows),
            "expected_abstentions": sum(item.expected_abstention for item in rows),
        }

    by_condition = {
        condition: metrics([item for item in results if item.condition == condition])
        for condition in ("citation_prompted", "claim_evidence_constrained")
    }
    paired: dict[tuple[str, str], dict[str, PortfolioProviderResult]] = defaultdict(
        dict
    )
    for item in results:
        paired[(item.case_id, item.variant)][item.condition] = item
    provenance_deltas = {
        key: int(value["claim_evidence_constrained"].provenance_outcome_correct)
        - int(value["citation_prompted"].provenance_outcome_correct)
        for key, value in paired.items()
    }
    exact_deltas = {
        key: int(value["claim_evidence_constrained"].exact_outcome_correct)
        - int(value["citation_prompted"].exact_outcome_correct)
        for key, value in paired.items()
    }
    dependency_deltas: dict[str, list[int]] = defaultdict(list)
    dependency_by_case = {item.case_id: item.dependency_id for item in results}
    for (case_id, _variant), delta in provenance_deltas.items():
        dependency_deltas[dependency_by_case[case_id]].append(delta)
    family_macro_delta = sum(
        sum(values) / len(values) for values in dependency_deltas.values()
    ) / len(dependency_deltas)
    by_variant = {
        variant: {
            condition: metrics(
                [
                    item
                    for item in results
                    if item.variant == variant and item.condition == condition
                ]
            )
            for condition in ("citation_prompted", "claim_evidence_constrained")
        }
        for variant in ("clean", "control", "challenge")
    }
    by_slice = {
        case_slice: {
            condition: metrics(
                [
                    item
                    for item in results
                    if item.case_slice == case_slice and item.condition == condition
                ]
            )
            for condition in ("citation_prompted", "claim_evidence_constrained")
        }
        for case_slice in sorted({item.case_slice for item in results})
    }
    return {
        "schema_version": "portfolio-diverse-provider-summary-v1",
        "run_id": RUN_ID,
        "scheduled_cells": 192,
        "completed_result_cells": len(results),
        "unique_semantic_questions": 64,
        "dependency_clusters": len({item.dependency_id for item in results}),
        "comparison_scope": (
            "bundled pipeline variants: prompt plus API schema enforcement"
        ),
        "causal_attribution": "not_estimated",
        "single_sample_no_repeats": True,
        "by_condition": by_condition,
        "by_variant": by_variant,
        "by_slice": by_slice,
        "primary_metric": "provenance_outcome_correct",
        "paired_provenance_delta_mean": (
            sum(provenance_deltas.values()) / len(provenance_deltas)
        ),
        "paired_exact_delta_mean": sum(exact_deltas.values()) / len(exact_deltas),
        "dependency_family_macro_delta": family_macro_delta,
        "paired_wins": sum(value > 0 for value in provenance_deltas.values()),
        "paired_ties": sum(value == 0 for value in provenance_deltas.values()),
        "paired_losses": sum(value < 0 for value in provenance_deltas.values()),
        "result_kinds": dict(
            sorted(Counter(item.result_kind for item in results).items())
        ),
        "returned_models": dict(
            sorted(Counter(item.provider_model or "none" for item in results).items())
        ),
        "input_tokens": sum(item.input_tokens for item in results),
        "cached_input_tokens": sum(item.cached_input_tokens for item in results),
        "output_tokens": sum(item.output_tokens for item in results),
        "reasoning_tokens": sum(item.reasoning_tokens for item in results),
        "total_latency_ms": sum(item.latency_ms for item in results),
        "accounted_cost_usd": str(
            sum((item.accounted_cost_usd for item in results), Decimal("0"))
        ),
        "limitations": [
            "One generation per cell; no run-to-run variance or stability estimate.",
            (
                "Exactly 64 answer contracts span 51 semantic-pair groups and 24 "
                "dependency clusters; they are not 64 independent factual phenomena."
            ),
            (
                "The 8 abstention questions test enumerated benchmark insufficiency "
                "causes only."
            ),
            (
                "Control/challenge packets cover the 16 retained extraction "
                "questions, not all 64 questions."
            ),
            (
                "The comparison bundles prompt wording with API schema enforcement "
                "and does not isolate either mechanism causally."
            ),
            (
                "The preregistered primary provenance metric grades predicate, "
                "component role, exact evidence bindings, and abstention; the "
                "stricter semantic metric additionally requires canonical typed "
                "values. Natural-language authority_scope wording is descriptive "
                "because authority is enforced by predicate and evidence binding."
            ),
        ],
    }
