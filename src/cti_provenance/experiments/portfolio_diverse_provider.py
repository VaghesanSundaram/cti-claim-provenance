"""Offline-only freeze contracts for the V6 diverse portfolio provider run."""

from __future__ import annotations

import hashlib
import json
import random
import re
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from cti_provenance.claims.diverse_portfolio_v4 import (
    AbstentionReasonCode,
    CandidateComponent,
    canonical_sha256,
)
from cti_provenance.models.openai_client import (
    OpenAIMessage,
    OpenAIResponseRequest,
)

Condition = Literal["citation_prompted", "claim_evidence_constrained"]
Variant = Literal["clean", "control", "challenge"]

_SUPPORTED_COMPONENT_KINDS_BY_SLICE: dict[str, tuple[str, ...]] = {
    "single_source_extraction": ("answer_value",),
    "temporal_comparison": ("old_value", "new_value", "delta_kind"),
    "cutoff_or_insufficiency_abstention": ("answer_value",),
    "authority_divergence": ("authority_fact", "authority_fact"),
    "multi_source_synthesis": ("synthesis_fact", "synthesis_fact"),
}


class PortfolioProviderResponse(BaseModel):
    """Provider-facing response envelope shared across both conditions."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-provider-response-v1"]
    case_id: str = Field(min_length=1)
    abstained: bool
    abstention_reason_code: AbstentionReasonCode | None
    components: list[CandidateComponent]

    @model_validator(mode="after")
    def validate_abstention_shape(self) -> Self:
        if self.abstained:
            if self.abstention_reason_code is None or self.components:
                raise ValueError(
                    "abstention needs one reason code and no answer components"
                )
        elif self.abstention_reason_code is not None:
            raise ValueError("non-abstention cannot carry an abstention reason")
        return self


def portfolio_provider_response_schema() -> dict[str, Any]:
    """Return the strict provider wire schema for the typed component values.

    Pydantic renders ``JsonValue`` as an empty schema.  That is appropriate for
    local validation but is not accepted by the Responses API's strict
    Structured Outputs subset.  The benchmark needs only four concrete value
    shapes plus five closed mapping shapes, so bind those shapes explicitly
    without changing the locally parsed response model.
    """

    schema = PortfolioProviderResponse.model_json_schema(mode="serialization")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict) or "JsonValue" not in definitions:
        raise ValueError("provider response schema no longer exposes JsonValue")

    def closed_object(properties: dict[str, dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }

    definitions["JsonValue"] = {
        "anyOf": [
            {"type": "string"},
            {"type": "number"},
            {"type": "boolean"},
            {"type": "array", "items": {"type": "string"}},
            closed_object(
                {
                    "affected": {"type": "string"},
                    "unaffected": {"type": "string"},
                }
            ),
            closed_object({"cvss_v31": {"type": "number"}}),
            closed_object(
                {
                    "default_status": {"type": "string"},
                    "explicit_versions": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                }
            ),
            closed_object(
                {
                    "status": {"type": "string"},
                    "target_date": {"type": "string"},
                }
            ),
            closed_object(
                {
                    "status": {"type": "string"},
                    "versions": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                }
            ),
        ]
    }
    return schema


class PortfolioProviderSlot(BaseModel):
    """One immutable provider call position; retries do not create new cells."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ordinal: int = Field(ge=0, lt=192)
    slot_id: str = Field(pattern=r"^portfolio-v6-[0-9a-f]{24}$")
    case_id: str = Field(min_length=1)
    dependency_id: str = Field(min_length=1)
    variant: Variant
    variant_case_id: str = Field(min_length=1)
    condition: Condition
    input_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_semantic_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    egress_eligible: bool
    egress_block_reason: str | None

    @model_validator(mode="after")
    def validate_egress(self) -> Self:
        if self.egress_eligible == (self.egress_block_reason is not None):
            raise ValueError("egress eligibility and blocker disagree")
        return self


class PortfolioProviderPlan(BaseModel):
    """Frozen design, cost, and safety descriptor for manager audit."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-provider-plan-v1"]
    status: Literal["blocked_pending_replacement_human_review", "ready_for_execution"]
    created_at_utc: datetime
    corpus_path: str
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_index_path: str
    packet_index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_log_path: str
    review_log_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lineage_path: str
    lineage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replacement_review_packet_path: str
    replacement_review_packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replacement_review_decision_log_path: str
    replacement_review_decision_log_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replacement_user_approval_path: str
    replacement_user_approval_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authority_policy_version: Literal["authority-policy-portfolio-diverse-v6"]
    provider: Literal["openai"]
    model_route: Literal["gpt-5.6-luna"]
    returned_model_policy: Literal["record_exact_no_fallback"]
    api: Literal["responses"]
    endpoint: Literal["https://api.openai.com/v1/responses"]
    service_tier: Literal["default"]
    reasoning_effort: Literal["medium"]
    store: Literal[False]
    background: Literal[False]
    tools: tuple[()]
    live_search: Literal[False]
    conditions: tuple[
        Literal["citation_prompted"], Literal["claim_evidence_constrained"]
    ]
    comparison_scope: Literal[
        "bundled_pipeline_variants_prompt_plus_api_schema_enforcement"
    ]
    causal_attribution: Literal["not_estimated"]
    primary_metric: Literal["provenance_outcome_correct"]
    secondary_metric: Literal["canonical_typed_value_exact"]
    authority_scope_treatment: Literal[
        "descriptive_unscored_authority_from_predicate_and_citations"
    ]
    repeats: Literal[1]
    schedule_seed: Literal[20260724]
    unique_question_count: Literal[64]
    clean_question_count: Literal[64]
    challenge_subset_question_count: Literal[16]
    planned_calls: Literal[192]
    max_transient_retries: Literal[2]
    maximum_attempts: Literal[576]
    transient_retry_backoff_seconds: tuple[Literal[2], Literal[8]]
    input_token_reservation: Literal[32000]
    max_output_tokens: Literal[2000]
    cost_cap_usd: Decimal
    input_per_million_usd: Decimal
    cache_write_multiplier: Decimal
    output_per_million_usd: Decimal
    retry_inclusive_upper_bound_usd: Decimal
    pricing_accessed_at_utc: datetime
    pricing_source_url: str
    data_controls_source_url: str
    egress_disposition_path: str
    egress_blocked_case_ids: tuple[str, ...]
    egress_blocked_call_count: int = Field(ge=0)
    schedule_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantic_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_design(self) -> Self:
        if self.cost_cap_usd != Decimal("30.00"):
            raise ValueError("cost cap drifted")
        expected = (
            Decimal(self.maximum_attempts)
            * (
                Decimal(self.input_token_reservation)
                * self.input_per_million_usd
                * self.cache_write_multiplier
                + Decimal(self.max_output_tokens) * self.output_per_million_usd
            )
            / Decimal(1_000_000)
        )
        if expected != self.retry_inclusive_upper_bound_usd:
            raise ValueError("retry-inclusive cost arithmetic drifted")
        if expected > self.cost_cap_usd:
            raise ValueError("provider reservation exceeds the user cap")
        return self


def _sha_bytes(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _legacy_variant_base(case_id: str) -> tuple[str, Variant]:
    match = re.fullmatch(r"(.+)-(clean|control|challenge)-v2", case_id)
    if not match:
        raise ValueError(f"unexpected challenge case ID: {case_id}")
    return match.group(1), match.group(2)  # type: ignore[return-value]


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _opaque(prefix: str, identity: str) -> str:
    return f"{prefix}-{hashlib.sha256(identity.encode()).hexdigest()[:12]}"


def build_portfolio_candidate_packet(
    *, root: Path, case_id: str, variant: Variant
) -> dict[str, JsonValue]:
    """Build the exact candidate-visible packet for one scheduled cell."""

    corpus = json.loads(
        (root / "data/benchmark/portfolio-diverse-draft-v6.json").read_text(
            encoding="utf-8"
        )
    )
    index = json.loads(
        (root / "data/benchmark/portfolio-diverse-packets-v6.json").read_text(
            encoding="utf-8"
        )
    )
    question = next(item for item in corpus["questions"] if item["case_id"] == case_id)
    clean = next(item for item in index["packets"] if item["case_id"] == case_id)
    retained = question["review_status"] == "approved_v2"
    if not retained and variant != "clean":
        raise ValueError("control/challenge packets exist only for retained V2 cases")
    documents = list(clean["documents"])
    if retained:
        result = next(
            item
            for item in _jsonl(root / "reports/portfolio-challenge-slice-v2.jsonl")
            if item["base_case_id"] == case_id
        )
        selected = next(
            item for item in result["variants"] if item["variant"] == variant
        )["top_document_ids"]
        fixtures = {
            item["document_id"]: item
            for item in _jsonl(
                root / "data/fixtures/portfolio-challenge-documents-v1.jsonl"
            )
        }
        additions: list[dict[str, JsonValue]] = []
        for document_id in selected:
            fixture = fixtures.get(document_id)
            if fixture is None:
                continue
            additions.append(
                {
                    "document_alias": _opaque("doc", document_id),
                    "neutral_title": "Supplemental evidence document",
                    "state_label": f"Supplemental {len(additions) + 1:02d}",
                    "available_by_utc": clean["cutoff_utc"],
                    "temporal_basis": "safe_synthetic_control",
                    "publisher_identity": "Synthetic benchmark fixture",
                    "source_class": "synthetic",
                    "evidence": [
                        {
                            "span_alias": _opaque("span", document_id),
                            "text": fixture["normalized_text"],
                        }
                    ],
                }
            )
        documents.extend(additions)
    packet: dict[str, JsonValue] = {
        "packet_id": clean["packet_id"]
        if variant == "clean"
        else (f"{case_id}-{variant}-v6"),
        "case_id": case_id,
        "question": clean["question"],
        "target_predicate": question["predicate"],
        "supported_component_kinds": list(
            _SUPPORTED_COMPONENT_KINDS_BY_SLICE[str(question["slice"])]
        ),
        "cutoff_utc": clean["cutoff_utc"],
        "documents": documents,
        "variant": variant,
    }
    packet["packet_sha256"] = canonical_sha256(packet)
    return packet


def candidate_alias_map(*, root: Path, case_id: str) -> dict[str, str]:
    """Return evaluator-only opaque-alias to evidence-ID bindings."""

    index = json.loads(
        (root / "data/benchmark/portfolio-diverse-packets-v6.json").read_text(
            encoding="utf-8"
        )
    )
    packet = next(item for item in index["packets"] if item["case_id"] == case_id)
    bindings = index["evaluator_bindings"][packet["packet_id"]]
    return {
        evidence["span_alias"]: evidence["evidence_id"]
        for document in bindings
        for evidence in document["evidence"]
    }


def _make_request(
    *, root: Path, condition: Condition, packet: dict[str, JsonValue]
) -> OpenAIResponseRequest:
    condition_path = (
        root
        / "configs/prompts"
        / {
            "citation_prompted": "portfolio-diverse-v6-citation-prompted.txt",
            "claim_evidence_constrained": "portfolio-diverse-v6-constrained.txt",
        }[condition]
    )
    shared = (root / "configs/prompts/portfolio-diverse-v6-shared.txt").read_text(
        encoding="utf-8"
    )
    user_prompt = shared.format(
        condition_contract=condition_path.read_text(encoding="utf-8"),
        candidate_packet_json=json.dumps(
            packet, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ),
    )
    return OpenAIResponseRequest(
        model="gpt-5.6-luna",
        input=(
            OpenAIMessage(
                "developer",
                "Follow the frozen evidence-selection contract exactly.",
            ),
            OpenAIMessage("user", user_prompt),
        ),
        schema_name="portfolio_diverse_provider_response",
        json_schema=portfolio_provider_response_schema(),
        max_output_tokens=2000,
        schema_enforced=condition == "claim_evidence_constrained",
    )


def build_portfolio_request(
    *, root: Path, slot: PortfolioProviderSlot
) -> tuple[OpenAIResponseRequest, dict[str, JsonValue]]:
    """Construct one frozen request without credentials or provider access."""

    packet = build_portfolio_candidate_packet(
        root=root, case_id=slot.case_id, variant=slot.variant
    )
    request = _make_request(root=root, condition=slot.condition, packet=packet)
    return request, packet


def build_portfolio_provider_schedule(
    *,
    root: Path,
    egress_blocked_case_ids: set[str],
) -> tuple[tuple[PortfolioProviderSlot, ...], dict[str, Any]]:
    """Build the complete seeded 192-cell schedule without any provider call."""

    corpus = json.loads(
        (root / "data/benchmark/portfolio-diverse-draft-v6.json").read_text(
            encoding="utf-8"
        )
    )
    index = json.loads(
        (root / "data/benchmark/portfolio-diverse-packets-v6.json").read_text(
            encoding="utf-8"
        )
    )
    packet_by_case = {item["case_id"]: item for item in index["packets"]}
    question_by_case = {item["case_id"]: item for item in corpus["questions"]}
    retained = {
        item["case_id"]
        for item in corpus["questions"]
        if item["review_status"] == "approved_v2"
    }
    if len(question_by_case) != 64 or len(retained) != 16:
        raise ValueError("V6 case denominator drifted")
    legacy_rows = [
        json.loads(line)
        for line in (
            root / "data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl"
        )
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    legacy: dict[tuple[str, Variant], dict[str, JsonValue]] = {}
    for row in legacy_rows:
        base, variant = _legacy_variant_base(str(row["case_id"]))
        legacy[(base, variant)] = row
    if {
        base for base, variant in legacy if variant in {"control", "challenge"}
    } != retained:
        raise ValueError("legacy challenge subset differs from retained V2 cases")

    prompt_paths = {
        "citation_prompted": root
        / "configs/prompts/portfolio-diverse-v6-citation-prompted.txt",
        "claim_evidence_constrained": root
        / "configs/prompts/portfolio-diverse-v6-constrained.txt",
    }
    shared_prompt = root / "configs/prompts/portfolio-diverse-v6-shared.txt"
    response_schema = portfolio_provider_response_schema()
    response_schema_sha256 = canonical_sha256(response_schema)
    prompt_hashes = {
        condition: canonical_sha256(
            {
                "shared": shared_prompt.read_text(encoding="utf-8"),
                "contract": path.read_text(encoding="utf-8"),
            }
        )
        for condition, path in prompt_paths.items()
    }
    challenge_artifacts = {
        "cases_file_sha256": _sha_bytes(
            root / "data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl"
        ),
        "documents_file_sha256": _sha_bytes(
            root / "data/fixtures/portfolio-challenge-documents-v1.jsonl"
        ),
    }
    blocks: list[tuple[str, Variant]] = [
        (case_id, "clean") for case_id in sorted(question_by_case)
    ]
    extra_variants: tuple[Variant, ...] = ("control", "challenge")
    blocks.extend(
        (case_id, variant) for case_id in sorted(retained) for variant in extra_variants
    )
    randomizer = random.Random(20260724)
    randomizer.shuffle(blocks)
    slots: list[PortfolioProviderSlot] = []
    for case_id, variant in blocks:
        question = question_by_case[case_id]
        if variant == "clean":
            variant_case_id = str(packet_by_case[case_id]["packet_id"])
        else:
            legacy_case = legacy[(case_id, variant)]
            variant_case_id = str(legacy_case["case_id"])
        candidate_packet = build_portfolio_candidate_packet(
            root=root, case_id=case_id, variant=variant
        )
        input_binding_sha256 = str(candidate_packet["packet_sha256"])
        conditions: list[Condition] = [
            "citation_prompted",
            "claim_evidence_constrained",
        ]
        randomizer.shuffle(conditions)
        for condition in conditions:
            scheduled_request = _make_request(
                root=root,
                condition=condition,
                packet=candidate_packet,
            )
            request_semantic_sha256 = scheduled_request.semantic_sha256()
            slot_digest = hashlib.sha256(request_semantic_sha256.encode()).hexdigest()[
                :24
            ]
            slot_id = f"portfolio-v6-{slot_digest}"
            blocked = case_id in egress_blocked_case_ids
            slots.append(
                PortfolioProviderSlot(
                    ordinal=len(slots),
                    slot_id=slot_id,
                    case_id=case_id,
                    dependency_id=str(question["dependency_id"]),
                    variant=variant,
                    variant_case_id=variant_case_id,
                    condition=condition,
                    input_binding_sha256=input_binding_sha256,
                    prompt_sha256=prompt_hashes[condition],
                    response_schema_sha256=response_schema_sha256,
                    request_semantic_sha256=request_semantic_sha256,
                    egress_eligible=not blocked,
                    egress_block_reason=(
                        None
                        if not blocked
                        else "source_terms_do_not_authorize_provider_egress"
                    ),
                )
            )
    if len(slots) != 192 or len({item.slot_id for item in slots}) != 192:
        raise ValueError("provider schedule denominator or uniqueness drifted")
    return tuple(slots), {
        "response_schema_sha256": response_schema_sha256,
        "prompt_hashes": prompt_hashes,
        "challenge_artifacts": challenge_artifacts,
    }
