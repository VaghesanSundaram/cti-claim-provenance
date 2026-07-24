"""Single-reviewer portfolio packet with blinded resurfacing and repeatability."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cti_provenance.claims.portfolio_minimum import (
    load_portfolio_minimum_authority_policy,
)
from cti_provenance.claims.portfolio_proof import (
    load_portfolio_proof_authority_policy,
)
from cti_provenance.claims.portfolio_scale import (
    load_portfolio_scale_authority_policy,
)
from cti_provenance.claims.portfolio_yield import (
    load_portfolio_yield_authority_policy,
)
from cti_provenance.claims.three_family import load_three_family_authority_policy
from cti_provenance.experiments.portfolio_challenge_runner import (
    load_portfolio_public_inputs,
)
from cti_provenance.grading.review_workflow import (
    OriginalLabel,
    ReviewDecision,
    ReviewEvidence,
    ReviewItem,
    ReviewPacket,
    ReviewSource,
    _authority_category,
    _category,
    _display_claim,
    _review_evidence,
    _source_temporal_description,
    canonical_sha256,
    validate_review_log,
)

PACKET_PATH = Path("annotations/packets/portfolio-dev-validation-review-v1.json")
V2_PACKET_PATH = Path("annotations/packets/portfolio-dev-validation-review-v2.json")
RESURFACING_PATH = Path(
    "artifacts/private/portfolio-review/portfolio-dev-validation-resurfacing-v1.json"
)
V2_RESURFACING_PATH = Path(
    "artifacts/private/portfolio-review/portfolio-dev-validation-resurfacing-v2.json"
)


class ResurfacingRecord(BaseModel):
    """Manager-only linkage omitted from the reviewer-facing interface."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    group_id: str = Field(pattern=r"^resurface-[0-9a-f]{16}$")
    base_case_id: str = Field(min_length=1)
    base_case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    item_id: str = Field(pattern=r"^portfolio-item-[0-9a-f]{16}$")
    review_case_id: str = Field(pattern=r"^portfolio-case-[0-9a-f]{16}$")
    occurrence: Literal[0, 1]


class ResurfacingManifest(BaseModel):
    """Exact hidden-linkage manifest for the 25% repeatability sample."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-resurfacing-v1", "portfolio-resurfacing-v2"]
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_id: Literal[
        "portfolio-dev-validation-review-v1",
        "portfolio-dev-validation-review-v2",
    ]
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_family_count: Literal[16]
    resurfaced_family_count: Literal[4]
    resurfacing_fraction: float
    reviewer_instruction: Literal[
        "Do not inspect this linkage manifest until all packet decisions are exported."
    ]
    records: tuple[ResurfacingRecord, ...]

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        item_ids = [record.item_id for record in self.records]
        review_case_ids = [record.review_case_id for record in self.records]
        grouped: dict[str, list[ResurfacingRecord]] = defaultdict(list)
        base_groups: dict[str, set[str]] = defaultdict(set)
        for record in self.records:
            grouped[record.base_case_id].append(record)
            base_groups[record.base_case_id].add(record.group_id)
        repeated = [values for values in grouped.values() if len(values) == 2]
        if (
            len(self.records) != 20
            or len(item_ids) != len(set(item_ids))
            or len(review_case_ids) != len(set(review_case_ids))
            or len(grouped) != self.base_family_count
            or len(repeated) != self.resurfaced_family_count
            or self.resurfacing_fraction != 0.25
            or any(
                sorted(record.occurrence for record in values) != [0, 1]
                for values in repeated
            )
            or any(len(values) not in {1, 2} for values in grouped.values())
            or any(len(group_ids) != 1 for group_ids in base_groups.values())
            or any(
                record.group_id != _group_id(record.base_case_id)
                for record in self.records
            )
        ):
            raise ValueError("portfolio resurfacing inventory is inconsistent")
        body = self.model_dump(mode="json", exclude={"manifest_sha256"})
        if canonical_sha256(body) != self.manifest_sha256:
            raise ValueError("portfolio resurfacing manifest hash is invalid")
        return self


class RepeatabilitySummary(BaseModel):
    """Single-reviewer repeatability and correction queue."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    packet_id: str
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_log_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_ids: tuple[str, ...]
    packet_item_count: Literal[20]
    completed_item_count: int = Field(ge=0, le=20)
    resurfaced_pair_count: Literal[4]
    completed_resurfaced_pair_count: int = Field(ge=0, le=4)
    agreement_count: int = Field(ge=0, le=4)
    agreement_denominator: int = Field(ge=0, le=4)
    agreement_rate: float | None
    disagreement_group_ids: tuple[str, ...]
    correction_queue_base_case_ids: tuple[str, ...]
    unresolved_item_ids: tuple[str, ...]
    limitation: Literal[
        "Intra-rater consistency measures repeatability, not correctness of "
        "gold labels."
    ]


def _alias(case_id: str, occurrence: int, kind: Literal["item", "case"]) -> str:
    digest = hashlib.sha256(
        f"portfolio-review-alias-v1|{kind}|{case_id}|{occurrence}".encode()
    ).hexdigest()[:16]
    return f"portfolio-{kind}-{digest}"


def _group_id(case_id: str) -> str:
    digest = hashlib.sha256(f"portfolio-review-group-v1|{case_id}".encode()).hexdigest()
    return f"resurface-{digest[:16]}"


def _sample_resurface_case_ids(case_ids: list[str]) -> frozenset[str]:
    """Select exactly 25% using the frozen deterministic pseudorandom seed."""

    if len(case_ids) != 16 or len(set(case_ids)) != 16:
        raise ValueError("portfolio review requires 16 unique base cases")
    ordered = sorted(
        case_ids,
        key=lambda case_id: hashlib.sha256(
            f"portfolio-review-resurface-sample-v1|{case_id}".encode()
        ).hexdigest(),
    )
    return frozenset(ordered[:4])


def _schedule_occurrences(
    case_ids: list[str], resurface_case_ids: frozenset[str]
) -> list[tuple[str, Literal[0, 1]]]:
    """Pseudorandomize while forcing every repeat later and five items apart."""

    occurrences: list[tuple[str, Literal[0, 1]]] = [
        (case_id, 0) for case_id in case_ids
    ]
    occurrences.extend((case_id, 1) for case_id in resurface_case_ids)
    if len(occurrences) != 20 or len(resurface_case_ids) != 4:
        raise ValueError("portfolio review resurfacing selection is invalid")
    for nonce in range(10_000):
        ordered = sorted(
            occurrences,
            key=lambda occurrence: hashlib.sha256(
                (
                    f"portfolio-review-order-v2|{nonce}|{occurrence[0]}|{occurrence[1]}"
                ).encode()
            ).hexdigest(),
        )
        positions = {occurrence: index for index, occurrence in enumerate(ordered)}
        if all(
            positions[(case_id, 1)] - positions[(case_id, 0)] >= 5
            for case_id in resurface_case_ids
        ):
            return ordered
    raise ValueError("could not construct a separated resurfacing schedule")


def _review_source(document: Any, state: Any) -> ReviewSource:
    manifest = state.manifest
    return ReviewSource(
        snapshot_id=document.snapshot_id,
        source_name=document.source_name,
        source_class=document.source_class,
        title=document.title,
        canonical_url=str(document.canonical_url),
        local_reference=manifest.raw_blob_path,
        published_at_utc=document.published_at,
        modified_at_utc=document.modified_at,
        retrieved_at_utc=manifest.retrieved_at_utc,
        available_by_utc=manifest.available_by_utc,
        available_by_basis=manifest.available_by_basis,
        temporal_evidence_description=_source_temporal_description(state),
        raw_snapshot_sha256=manifest.sha256,
        normalized_text_sha256=document.normalized_text_sha256,
    )


def build_portfolio_review_packet(
    root: Path,
    *,
    correction_version: Literal["v1", "v2"] = "v1",
) -> tuple[ReviewPacket, ResurfacingManifest]:
    """Build the blinded 16-family packet plus four resurfaced items."""

    resolved = root.resolve(strict=True)
    states, documents, cases = load_portfolio_public_inputs(
        resolved, correction_version=correction_version
    )
    state_by_id = {state.manifest.snapshot_id: state for state in states}
    document_by_id = {document.document_id: document for document in documents}
    authority_configs = (
        load_three_family_authority_policy(resolved),
        load_portfolio_proof_authority_policy(resolved),
        load_portfolio_yield_authority_policy(resolved),
        load_portfolio_scale_authority_policy(resolved),
        load_portfolio_minimum_authority_policy(resolved),
    )
    policies_by_id: dict[str, Any] = {}
    for config in authority_configs:
        for policy in config.policies:
            existing = policies_by_id.get(policy.policy_id)
            if existing is not None and existing != policy:
                raise ValueError("portfolio review authority policy IDs collide")
            policies_by_id[policy.policy_id] = policy

    case_by_id = {case.case_id: case for case in cases}
    resurface_case_ids = _sample_resurface_case_ids(list(case_by_id))
    occurrences = [
        (case_by_id[case_id], occurrence)
        for case_id, occurrence in _schedule_occurrences(
            list(case_by_id), resurface_case_ids
        )
    ]

    items: list[ReviewItem] = []
    records: list[ResurfacingRecord] = []
    for case, occurrence in occurrences:
        claim = case.expected_claims[0]
        policies = [
            policies_by_id[policy_id]
            for policy_id in case.required_authority_policy_ids
        ]
        expected_ids = set(claim.evidence_ids)
        evidence_document_ids = {
            evidence_id.split(":", 1)[0] for evidence_id in expected_ids
        }
        evidence_documents = [
            document_by_id[document_id] for document_id in evidence_document_ids
        ]
        entity_id = evidence_documents[0].upstream_entity_id
        candidate_documents = [
            document
            for document in documents
            if document.upstream_entity_id == entity_id
            and state_by_id[document.snapshot_id].manifest.available_by_utc
            <= case.as_of
        ]
        candidate_documents.sort(
            key=lambda document: (
                document.document_id not in evidence_document_ids,
                document.snapshot_id,
                document.document_id,
            )
        )
        selected_by_snapshot: dict[str, Any] = {}
        for document in candidate_documents:
            selected_by_snapshot.setdefault(document.snapshot_id, document)
        selected_documents = list(selected_by_snapshot.values())
        if not evidence_document_ids <= {
            document.document_id for document in selected_documents
        }:
            raise ValueError("portfolio review omitted expected evidence document")

        sources = [
            _review_source(document, state_by_id[document.snapshot_id])
            for document in selected_documents
        ]
        all_evidence: list[ReviewEvidence] = []
        for document in selected_documents:
            state = state_by_id[document.snapshot_id]
            category = _authority_category(
                source_name=document.source_name,
                claim=claim,
                policies=policies,
            )
            all_evidence.extend(
                _review_evidence(
                    document,
                    state,
                    span.span_id,
                    cutoff=case.as_of,
                    category=category,
                    context_policy="same_line_redacted_v1",
                )
                for span in document.spans
            )
        evidence = sorted(
            [value for value in all_evidence if value.evidence_id in expected_ids],
            key=lambda value: value.evidence_id,
        )
        alternates = sorted(
            [value for value in all_evidence if value.evidence_id not in expected_ids],
            key=lambda value: value.evidence_id,
        )[:4]
        case_hash = canonical_sha256(case)
        binding = {
            "case_sha256": case_hash,
            "sources": [
                {
                    "snapshot_id": source.snapshot_id,
                    "raw_snapshot_sha256": source.raw_snapshot_sha256,
                    "normalized_text_sha256": source.normalized_text_sha256,
                }
                for source in sources
            ],
            "evidence": [
                {
                    "evidence_id": value.evidence_id,
                    "raw_snapshot_sha256": value.raw_snapshot_sha256,
                    "normalized_text_sha256": value.normalized_text_sha256,
                    "span_text_sha256": value.span_text_sha256,
                }
                for value in [*evidence, *alternates]
            ],
        }
        item_id = _alias(case.case_id, occurrence, "item")
        review_case_id = _alias(case.case_id, occurrence, "case")
        item_data: dict[str, Any] = {
            "item_id": item_id,
            "item_sha256": "0" * 64,
            "case_id": review_case_id,
            "case_sha256": case_hash,
            "question": case.question,
            "cutoff_utc": case.as_of,
            "case_category": _category(case),
            "scope_label": "portfolio-scale pilot development/validation",
            "original_label": OriginalLabel(
                expected_answer="answer",
                abstention_reason=None,
                expected_claim=_display_claim(claim),
            ),
            "required_authority_policy_ids": case.required_authority_policy_ids,
            "sources": sources,
            "evidence": evidence,
            "alternate_evidence": alternates,
            "evidence_binding_sha256": canonical_sha256(binding),
        }
        item_data["item_sha256"] = canonical_sha256(
            {key: value for key, value in item_data.items() if key != "item_sha256"}
        )
        items.append(ReviewItem.model_validate(item_data))
        records.append(
            ResurfacingRecord(
                group_id=_group_id(case.case_id),
                base_case_id=case.case_id,
                base_case_sha256=case_hash,
                item_id=item_id,
                review_case_id=review_case_id,
                occurrence=occurrence,
            )
        )

    packet_data: dict[str, Any] = {
        "schema_version": "review-packet-v1",
        "packet_id": f"portfolio-dev-validation-review-{correction_version}",
        "packet_sha256": "0" * 64,
        "created_at_utc": max(state.manifest.retrieved_at_utc for state in states),
        "benchmark_scope": "portfolio-scale pilot development/validation",
        "blinding_statement": (
            "No model outputs, conditions, pass/fail fields, aggregates, "
            "or preferences."
        ),
        "case_file_sha256": canonical_sha256(
            [case.model_dump(mode="json") for case in cases]
        ),
        "authority_policy_sha256": canonical_sha256(
            [config.model_dump(mode="json") for config in authority_configs]
        ),
        "source_license_or_terms": {
            snapshot_id: state_by_id[snapshot_id].manifest.license_or_terms_note
            for snapshot_id in sorted(
                {source.snapshot_id for item in items for source in item.sources}
            )
        },
        "items": items,
    }
    packet_data["packet_sha256"] = canonical_sha256(
        {key: value for key, value in packet_data.items() if key != "packet_sha256"}
    )
    packet = ReviewPacket.model_validate(packet_data)
    manifest_data: dict[str, Any] = {
        "schema_version": f"portfolio-resurfacing-{correction_version}",
        "manifest_sha256": "0" * 64,
        "packet_id": packet.packet_id,
        "packet_sha256": packet.packet_sha256,
        "base_family_count": 16,
        "resurfaced_family_count": 4,
        "resurfacing_fraction": 0.25,
        "reviewer_instruction": (
            "Do not inspect this linkage manifest until all packet decisions are "
            "exported."
        ),
        "records": tuple(sorted(records, key=lambda record: record.item_id)),
    }
    manifest_data["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in manifest_data.items() if key != "manifest_sha256"}
    )
    return packet, ResurfacingManifest.model_validate(manifest_data)


def render_resurfacing_manifest(manifest: ResurfacingManifest) -> str:
    """Render the post-review linkage manifest deterministically."""

    return json.dumps(manifest.model_dump(mode="json"), indent=2) + "\n"


def evaluate_repeatability(
    packet: ReviewPacket,
    manifest: ResurfacingManifest,
    decisions: list[ReviewDecision],
    *,
    decision_log_sha256: str,
) -> RepeatabilitySummary:
    """Compute intra-rater repeatability after single-review completion."""

    validation = validate_review_log(
        packet, decisions, [], review_mode="single_reviewer"
    )
    if (
        len(validation.completed_item_ids) != 20
        or validation.unresolved_item_ids
        or len(validation.reviewer_ids) != 1
    ):
        raise ValueError("repeatability requires one reviewer to complete all 20 items")
    if manifest.packet_sha256 != packet.packet_sha256 or {
        record.item_id for record in manifest.records
    } != {item.item_id for item in packet.items}:
        raise ValueError("resurfacing manifest does not bind the review packet")
    item_by_id = {item.item_id: item for item in packet.items}
    for record in manifest.records:
        item = item_by_id[record.item_id]
        if (
            record.review_case_id != item.case_id
            or record.base_case_sha256 != item.case_sha256
        ):
            raise ValueError("resurfacing record does not bind its review item")
    superseded = {
        decision.supersedes_decision_id
        for decision in decisions
        if decision.supersedes_decision_id is not None
    }
    active = {
        decision.item_id: decision
        for decision in decisions
        if decision.decision_id not in superseded
    }
    records_by_group: dict[str, list[ResurfacingRecord]] = defaultdict(list)
    for record in manifest.records:
        records_by_group[record.group_id].append(record)
    repeated = {
        group_id: records
        for group_id, records in records_by_group.items()
        if len(records) == 2
    }
    for records in repeated.values():
        left_item, right_item = (item_by_id[record.item_id] for record in records)
        excluded = {"item_id", "item_sha256", "case_id"}
        if canonical_sha256(left_item.model_dump(exclude=excluded)) != canonical_sha256(
            right_item.model_dump(exclude=excluded)
        ):
            raise ValueError("resurfaced review items do not have identical content")
    completed_pairs = {
        group_id: records
        for group_id, records in repeated.items()
        if all(record.item_id in active for record in records)
    }

    def decision_key(decision: ReviewDecision) -> tuple[object, ...]:
        verdict = decision.verdict
        return (
            verdict.factual_correctness,
            verdict.evidence_support,
            verdict.authority,
            verdict.cutoff,
            verdict.answerability,
            verdict.alternate_evidence_exists,
            verdict.question_quality,
            decision.label_changed,
        )

    disagreements: list[str] = []
    agreements = 0
    for group_id, records in completed_pairs.items():
        left_decision, right_decision = (active[record.item_id] for record in records)
        if decision_key(left_decision) == decision_key(right_decision):
            agreements += 1
        else:
            disagreements.append(group_id)
    item_to_base = {record.item_id: record.base_case_id for record in manifest.records}
    correction_queue = {
        item_to_base[decision.item_id]
        for decision in decisions
        if decision.label_changed or decision.supersedes_decision_id is not None
    }
    correction_queue.update(
        record.base_case_id
        for group_id in disagreements
        for record in repeated[group_id]
    )
    denominator = len(completed_pairs)
    if denominator != 4:
        raise ValueError("repeatability requires all four resurfaced pairs")
    return RepeatabilitySummary(
        packet_id=packet.packet_id,
        packet_sha256=packet.packet_sha256,
        decision_log_sha256=decision_log_sha256,
        reviewer_ids=tuple(validation.reviewer_ids),
        packet_item_count=20,
        completed_item_count=len(validation.completed_item_ids),
        resurfaced_pair_count=4,
        completed_resurfaced_pair_count=denominator,
        agreement_count=agreements,
        agreement_denominator=denominator,
        agreement_rate=(agreements / denominator if denominator else None),
        disagreement_group_ids=tuple(sorted(disagreements)),
        correction_queue_base_case_ids=tuple(sorted(correction_queue)),
        unresolved_item_ids=tuple(validation.unresolved_item_ids),
        limitation=(
            "Intra-rater consistency measures repeatability, not correctness of "
            "gold labels."
        ),
    )


def render_repeatability_summary(summary: RepeatabilitySummary) -> str:
    """Render the single-reviewer status without overstating label validity."""

    rate = "not yet available"
    if summary.agreement_rate is not None:
        rate = (
            f"{summary.agreement_count}/{summary.agreement_denominator} "
            f"({summary.agreement_rate:.1%})"
        )
    disagreements = ", ".join(summary.disagreement_group_ids) or "none"
    corrections = ", ".join(summary.correction_queue_base_case_ids) or "none"
    unresolved = ", ".join(summary.unresolved_item_ids) or "none"
    return (
        "# Portfolio single-reviewer repeatability\n\n"
        f"- Decision log SHA-256: `{summary.decision_log_sha256}`.\n"
        f"- Packet items completed: {summary.completed_item_count}/20.\n"
        "- Resurfaced pairs completed: "
        f"{summary.completed_resurfaced_pair_count}/4.\n"
        f"- Exact intra-rater agreement: {rate}.\n"
        f"- Repeat disagreements: {disagreements}.\n"
        f"- Correction queue: {corrections}.\n"
        f"- Unresolved review items: {unresolved}.\n"
        f"- Limitation: {summary.limitation}\n"
    )
