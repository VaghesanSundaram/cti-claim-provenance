"""Additive V5 contracts for the manager-repaired diverse CTI corpus."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from cti_provenance.claims.diverse_portfolio_v4 import (
    DiverseCorpusV4,
    DiverseQuestionV4,
    PacketIndexV4,
    ReviewPacketV4,
)


def reference_component_marker(component_id: str, value: object) -> str:
    """Return the exact reviewer-visible marker for one structured component."""

    rendered = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return f"[{component_id}={rendered}]"


def validate_reference_answer(question: DiverseQuestionV4) -> None:
    """Require each answerable structured component in the readable answer."""

    if question.outcome_type == "abstain":
        return
    if not isinstance(question.readable_reference_answer, str):
        raise ValueError("V5 answerable questions need a textual reference answer")
    for component in question.expected_components:
        marker = reference_component_marker(component.component_id, component.value)
        if marker not in question.readable_reference_answer:
            raise ValueError(
                f"reference answer omits structured component: {component.component_id}"
            )


class DiverseCorpusV5(DiverseCorpusV4):
    """Truthfully timed V5 successor with ordered temporal-state guarantees."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-draft-v5"]  # type: ignore[assignment]
    corpus_id: Literal["portfolio-diverse-v5-manager-audit-candidate"]  # type: ignore[assignment]
    questions: list[DiverseQuestionV4] = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def validate_v5_contract(self) -> Self:
        now = datetime.now(UTC)
        if self.created_at_utc > now:
            raise ValueError("corpus creation time is in the future")
        if any(
            question.cutoff_utc > self.created_at_utc for question in self.questions
        ):
            raise ValueError("question cutoff is later than corpus creation")
        if any(
            evidence.source_available_by_utc > self.created_at_utc
            for question in self.questions
            for evidence in question.evidence
        ):
            raise ValueError("source state is later than corpus creation")
        for question in self.questions:
            if question.review_status != "approved_v2":
                validate_reference_answer(question)
            if question.slice != "temporal_comparison":
                continue
            evidence_by_id = {
                evidence.evidence_id: evidence for evidence in question.evidence
            }
            old_component = next(
                item
                for item in question.expected_components
                if item.kind == "old_value"
            )
            new_component = next(
                item
                for item in question.expected_components
                if item.kind == "new_value"
            )
            old_states = {
                evidence_by_id[evidence_id].source_id
                for evidence_id in old_component.required_evidence_ids
            }
            new_states = {
                evidence_by_id[evidence_id].source_id
                for evidence_id in new_component.required_evidence_ids
            }
            if not old_states or not new_states or old_states & new_states:
                raise ValueError("temporal old/new states are not distinguishable")
            old_times = [
                evidence_by_id[evidence_id].source_available_by_utc
                for evidence_id in old_component.required_evidence_ids
            ]
            new_times = [
                evidence_by_id[evidence_id].source_available_by_utc
                for evidence_id in new_component.required_evidence_ids
            ]
            if max(old_times) >= min(new_times):
                raise ValueError("temporal old/new states are not truthfully ordered")
        return self


class PacketIndexV5(PacketIndexV4):
    """V5 candidate packets with evaluator-only provenance bindings."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-packets-v5"]  # type: ignore[assignment]


class ReviewPacketV5(ReviewPacketV4):
    """Manager-audit-only V5 packet; human review is not open."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["review-packet-v3"]  # type: ignore[assignment]
    packet_id: Literal["portfolio-diverse-review-v5-manager-audit-candidate"]  # type: ignore[assignment]
