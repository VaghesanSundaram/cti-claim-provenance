"""Blinded, append-only human review packets for frozen benchmark cases."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

from cti_provenance.claims.real_slice import (
    load_phase2_real_cases,
    load_phase2_real_corpus,
)
from cti_provenance.claims.schema import (
    ClaimQualifiers,
    ClaimSubject,
    GoldAtomicClaim,
    PredicateName,
)
from cti_provenance.config import load_authority_policy_config
from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.snapshot.admissibility import SnapshotState


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use UTC")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc)]
NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ReviewerId = Annotated[
    str, StringConstraints(strip_whitespace=True, pattern=r"^reviewer-[a-z0-9-]{3,32}$")
]
OptionalReason = (
    Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)] | None
)

CaseCategory = Literal[
    "answerable",
    "insufficient_evidence",
    "contradiction",
    "wrong_date",
    "weak_authority",
    "poison",
    "distractor",
]
ReviewMode = Literal["single_reviewer", "double_reviewer"]
FactualDecision = Literal["correct", "incorrect", "ambiguous"]
EvidenceDecision = Literal[
    "fully_supported",
    "partially_supported",
    "relevant_but_unsupported",
    "contradicts",
    "unclear",
]
AuthorityDecision = Literal["acceptable", "unacceptable", "unclear"]
CutoffDecision = Literal["eligible", "ineligible", "unclear"]
AnswerabilityDecision = Literal["answer", "abstain", "ambiguous"]
QuestionDecision = Literal["clear", "needs_revision", "exclude"]


def _canonical_bytes(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    else:
        value = to_jsonable_python(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Hash JSON-compatible data with the workflow's canonical encoding."""

    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


class ReviewSource(BaseModel):
    """One frozen source state visible to a reviewer."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    snapshot_id: NonEmpty
    source_name: NonEmpty
    source_class: Literal["government", "standards_body", "vendor", "synthetic"]
    title: str | None
    canonical_url: NonEmpty
    local_reference: NonEmpty
    published_at_utc: UtcDateTime | None
    modified_at_utc: UtcDateTime | None
    retrieved_at_utc: UtcDateTime
    available_by_utc: UtcDateTime
    available_by_basis: NonEmpty
    temporal_evidence_description: NonEmpty
    raw_snapshot_sha256: Sha256
    normalized_text_sha256: Sha256


class ReviewEvidence(BaseModel):
    """Exact evidence plus bounded context and immutable source bindings."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evidence_id: NonEmpty
    snapshot_id: NonEmpty
    document_id: NonEmpty
    span_id: NonEmpty
    field_path: NonEmpty
    exact_text: str
    context_before: str
    context_after: str
    raw_locator: str | None
    source_url: NonEmpty
    local_reference: NonEmpty
    source_name: NonEmpty
    document_date_utc: UtcDateTime | None
    available_by_utc: UtcDateTime
    authority_category: Literal[
        "primary", "acceptable_corroboration", "unacceptable", "synthetic_control"
    ]
    cutoff_eligibility: Literal["eligible", "ineligible"]
    raw_snapshot_sha256: Sha256
    normalized_text_sha256: Sha256
    span_text_sha256: Sha256

    @model_validator(mode="after")
    def verify_exact_text_hash(self) -> Self:
        if hashlib.sha256(self.exact_text.encode("utf-8")).hexdigest() != (
            self.span_text_sha256
        ):
            raise ValueError("exact evidence text does not match its span hash")
        return self


class ReviewClaim(BaseModel):
    """JSON-stable display form of one typed gold claim."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    claim_id: NonEmpty
    subject: ClaimSubject
    predicate: PredicateName
    value: JsonValue
    datatype: Literal[
        "boolean",
        "string",
        "date",
        "decimal",
        "version_set",
        "identifier_set",
    ]
    qualifiers: ClaimQualifiers
    evidence_ids: list[NonEmpty]


class OriginalLabel(BaseModel):
    """The pre-review benchmark label, separate from later decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    expected_answer: Literal["answer", "abstain"]
    abstention_reason: str | None
    expected_claim: ReviewClaim | None

    @model_validator(mode="after")
    def validate_label(self) -> Self:
        if (self.expected_answer == "answer") != (self.expected_claim is not None):
            raise ValueError("answer labels require exactly one expected claim")
        if (self.expected_answer == "abstain") != (self.abstention_reason is not None):
            raise ValueError("abstention labels require a reason")
        return self


class ReviewItem(BaseModel):
    """One complete, blinded human-review unit."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    item_id: NonEmpty
    item_sha256: Sha256
    case_id: NonEmpty
    case_sha256: Sha256
    question: NonEmpty
    cutoff_utc: UtcDateTime
    case_category: CaseCategory
    scope_label: Literal[
        "Log4Shell plumbing-only",
        "portfolio-scale pilot development/validation",
    ]
    original_label: OriginalLabel
    required_authority_policy_ids: list[NonEmpty] = Field(min_length=1)
    sources: list[ReviewSource]
    evidence: list[ReviewEvidence]
    alternate_evidence: list[ReviewEvidence]
    evidence_binding_sha256: Sha256

    @field_validator("required_authority_policy_ids")
    @classmethod
    def unique_policy_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("authority policy IDs must be unique")
        return values

    @model_validator(mode="after")
    def validate_item_hashes(self) -> Self:
        evidence_ids = [
            evidence.evidence_id
            for evidence in [*self.evidence, *self.alternate_evidence]
        ]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence and alternate evidence must be disjoint")
        sources = {source.snapshot_id: source for source in self.sources}
        if len(sources) != len(self.sources):
            raise ValueError("review sources must have unique snapshot IDs")
        for evidence in [*self.evidence, *self.alternate_evidence]:
            source = sources.get(evidence.snapshot_id)
            if (
                source is None
                or evidence.source_name != source.source_name
                or evidence.raw_snapshot_sha256 != source.raw_snapshot_sha256
                or evidence.normalized_text_sha256 != source.normalized_text_sha256
                or evidence.available_by_utc != source.available_by_utc
            ):
                raise ValueError("evidence does not match its declared source")
            expected_eligibility = (
                "eligible"
                if evidence.available_by_utc <= self.cutoff_utc
                else "ineligible"
            )
            if evidence.cutoff_eligibility != expected_eligibility:
                raise ValueError("cutoff eligibility does not match source timing")
        if self.original_label.expected_answer == "answer":
            if (
                self.case_category not in {"answerable", "contradiction"}
                or not self.evidence
                or any(
                    value.cutoff_eligibility != "eligible"
                    or value.authority_category != "primary"
                    for value in self.evidence
                )
            ):
                raise ValueError(
                    "answer labels require eligible primary expected evidence"
                )
        elif self.case_category == "wrong_date":
            if self.evidence or any(
                source.available_by_utc <= self.cutoff_utc for source in self.sources
            ):
                raise ValueError(
                    "wrong-date abstentions require only post-cutoff sources"
                )
        elif self.case_category == "insufficient_evidence" and (
            self.evidence
            or not any(
                source.available_by_utc <= self.cutoff_utc for source in self.sources
            )
        ):
            raise ValueError(
                "insufficient-evidence abstentions require an eligible source"
            )
        binding = {
            "case_sha256": self.case_sha256,
            "sources": [
                {
                    "snapshot_id": source.snapshot_id,
                    "raw_snapshot_sha256": source.raw_snapshot_sha256,
                    "normalized_text_sha256": source.normalized_text_sha256,
                }
                for source in self.sources
            ],
            "evidence": [
                {
                    "evidence_id": evidence.evidence_id,
                    "raw_snapshot_sha256": evidence.raw_snapshot_sha256,
                    "normalized_text_sha256": evidence.normalized_text_sha256,
                    "span_text_sha256": evidence.span_text_sha256,
                }
                for evidence in [*self.evidence, *self.alternate_evidence]
            ],
        }
        if canonical_sha256(binding) != self.evidence_binding_sha256:
            raise ValueError("evidence binding hash does not match item content")
        body = self.model_dump(mode="json", exclude={"item_sha256"})
        if canonical_sha256(body) != self.item_sha256:
            raise ValueError("item hash does not match item content")
        return self


class ReviewPacket(BaseModel):
    """Versioned packet containing labels but no system result fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["review-packet-v1"]
    packet_id: NonEmpty
    packet_sha256: Sha256
    created_at_utc: UtcDateTime
    benchmark_scope: Literal[
        "Log4Shell plumbing-only",
        "portfolio-scale pilot development/validation",
    ]
    blinding_statement: Literal[
        "No model outputs, conditions, pass/fail fields, aggregates, or preferences."
    ]
    case_file_sha256: Sha256
    authority_policy_sha256: Sha256
    source_license_or_terms: dict[NonEmpty, NonEmpty] | None = None
    items: list[ReviewItem] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_packet(self) -> Self:
        ids = [item.item_id for item in self.items]
        cases = [item.case_id for item in self.items]
        if len(ids) != len(set(ids)) or len(cases) != len(set(cases)):
            raise ValueError("packet item and case IDs must be unique")
        source_ids = {
            source.snapshot_id for item in self.items for source in item.sources
        }
        if (
            self.benchmark_scope == "portfolio-scale pilot development/validation"
            and self.source_license_or_terms is None
        ):
            raise ValueError("portfolio packets require source license/terms bindings")
        if self.source_license_or_terms is not None and (
            set(self.source_license_or_terms) != source_ids
        ):
            raise ValueError("source license/terms map must cover every packet source")
        body = self.model_dump(
            mode="json", exclude={"packet_sha256"}, exclude_unset=True
        )
        if canonical_sha256(body) != self.packet_sha256:
            raise ValueError("packet hash does not match packet content")
        return self


class ReviewVerdict(BaseModel):
    """A complete reviewer or adjudicator decision."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    factual_correctness: FactualDecision
    evidence_support: EvidenceDecision
    authority: AuthorityDecision
    cutoff: CutoffDecision
    answerability: AnswerabilityDecision
    alternate_evidence_exists: bool
    alternate_evidence_notes: OptionalReason
    question_quality: QuestionDecision
    confidence: float = Field(ge=0.0, le=1.0)
    notes: OptionalReason
    reason: OptionalReason

    @model_validator(mode="after")
    def require_reasons(self) -> Self:
        needs_reason = (
            self.factual_correctness == "ambiguous"
            or self.evidence_support in {"contradicts", "unclear"}
            or self.authority == "unclear"
            or self.cutoff == "unclear"
            or self.answerability == "ambiguous"
            or self.question_quality == "exclude"
        )
        if needs_reason and not self.reason:
            raise ValueError(
                "ambiguous, contradictory, unclear, or excluded decisions "
                "require a reason"
            )
        if self.alternate_evidence_exists and not self.alternate_evidence_notes:
            raise ValueError("alternate evidence requires notes")
        return self


class ReviewDecision(BaseModel):
    """One immutable reviewer decision; corrections append a superseding record."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["review-decision-v1"]
    decision_id: NonEmpty
    packet_sha256: Sha256
    item_id: NonEmpty
    item_sha256: Sha256
    case_id: NonEmpty
    case_sha256: Sha256
    evidence_binding_sha256: Sha256
    reviewer_id: ReviewerId
    decided_at_utc: UtcDateTime
    supersedes_decision_id: str | None
    original_label_sha256: Sha256
    verdict: ReviewVerdict
    label_changed: bool
    label_change_reason: OptionalReason

    @model_validator(mode="after")
    def require_label_change_reason(self) -> Self:
        if self.label_changed != (self.label_change_reason is not None):
            raise ValueError("label changes require exactly one reason")
        return self


class ReviewAdjudication(BaseModel):
    """Immutable final label linked to two disagreeing reviewer decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["review-adjudication-v1"]
    adjudication_id: NonEmpty
    packet_sha256: Sha256
    item_id: NonEmpty
    item_sha256: Sha256
    case_id: NonEmpty
    reviewer_decision_ids: list[NonEmpty] = Field(min_length=2, max_length=2)
    adjudicator_id: ReviewerId
    adjudicated_at_utc: UtcDateTime
    final_verdict: ReviewVerdict
    final_label_changed: bool
    adjudication_reason: NonEmpty

    @field_validator("reviewer_decision_ids")
    @classmethod
    def distinct_decisions(cls, values: list[str]) -> list[str]:
        if len(set(values)) != 2:
            raise ValueError("adjudication requires two distinct decisions")
        return values


class ReviewValidationSummary(BaseModel):
    """Deterministic validation result safe to include in reports."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    packet_id: NonEmpty
    packet_sha256: Sha256
    review_mode: ReviewMode
    required_reviews_per_item: Literal[1, 2]
    item_count: int = Field(ge=1)
    decision_count: int = Field(ge=0)
    active_decision_count: int = Field(ge=0)
    adjudication_count: int = Field(ge=0)
    reviewer_ids: list[ReviewerId]
    completed_item_ids: list[str]
    disagreement_item_ids: list[str]
    unresolved_item_ids: list[str]


def _source_temporal_description(state: SnapshotState) -> str:
    manifest = state.manifest
    if manifest.source_name == "red_hat_rhsa":
        return (
            "Publisher-declared version evidence observed in this frozen advisory; "
            "not independently observed historical availability."
        )
    if manifest.source_name == "synthetic_control":
        return "Project-generated control; never source authority."
    return f"Frozen {manifest.available_by_basis.replace('_', ' ')} evidence."


def _authority_category(
    *,
    source_name: str,
    claim: GoldAtomicClaim | None,
    policies: list[Any],
) -> Literal[
    "primary", "acceptable_corroboration", "unacceptable", "synthetic_control"
]:
    if source_name == "synthetic_control":
        return "synthetic_control"
    primary = {value for policy in policies for value in policy.primary_sources}
    corroboration = {
        value for policy in policies for value in policy.acceptable_corroboration
    }
    if source_name in primary:
        return "primary"
    if (
        claim is not None
        and claim.predicate == "cve.cvss.score"
        and source_name == "nvd"
        and claim.qualifiers.authority == "nvd@nist.gov"
    ):
        return "primary"
    if source_name in corroboration:
        return "acceptable_corroboration"
    return "unacceptable"


def _review_evidence(
    document: NormalizedDocument,
    state: SnapshotState,
    span_id: str,
    *,
    cutoff: datetime,
    category: Literal[
        "primary", "acceptable_corroboration", "unacceptable", "synthetic_control"
    ],
    context_policy: Literal["legacy_v1", "same_line_redacted_v1"] = "legacy_v1",
) -> ReviewEvidence:
    span = next(span for span in document.spans if span.span_id == span_id)
    text = document.normalized_text[span.start_char : span.end_char]
    context_start = max(0, span.start_char - 160)
    context_end = min(len(document.normalized_text), span.end_char + 160)
    if context_policy == "same_line_redacted_v1":
        previous_newline = document.normalized_text.rfind("\n", 0, span.start_char)
        next_newline = document.normalized_text.find("\n", span.end_char)
        context_start = max(context_start, previous_newline + 1)
        if next_newline >= 0:
            context_end = min(context_end, next_newline)
    context_before = document.normalized_text[context_start : span.start_char]
    context_after = document.normalized_text[span.end_char : context_end]
    if context_policy == "same_line_redacted_v1":
        email_pattern = re.compile(
            r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])"
        )
        context_before = email_pattern.sub("[email removed]", context_before)
        context_after = email_pattern.sub("[email removed]", context_after)
    manifest = state.manifest
    return ReviewEvidence(
        evidence_id=f"{document.document_id}:{span.span_id}",
        snapshot_id=document.snapshot_id,
        document_id=document.document_id,
        span_id=span.span_id,
        field_path=span.field_path,
        exact_text=text,
        context_before=context_before,
        context_after=context_after,
        raw_locator=span.raw_locator,
        source_url=str(document.canonical_url),
        local_reference=(
            f"{manifest.raw_blob_path}#{span.raw_locator or span.field_path}"
        ),
        source_name=document.source_name,
        document_date_utc=document.published_at or manifest.effective_date_if_known,
        available_by_utc=manifest.available_by_utc,
        authority_category=category,
        cutoff_eligibility=(
            "eligible" if manifest.available_by_utc <= cutoff else "ineligible"
        ),
        raw_snapshot_sha256=manifest.sha256,
        normalized_text_sha256=document.normalized_text_sha256,
        span_text_sha256=span.text_sha256,
    )


def _category(case: BenchmarkCase) -> CaseCategory:
    if case.should_abstain:
        return "insufficient_evidence" if case.allowed_snapshot_ids else "wrong_date"
    if case.attack.family == "contradiction":
        return "contradiction"
    return "answerable"


def _display_claim(claim: GoldAtomicClaim | None) -> ReviewClaim | None:
    if claim is None:
        return None
    value: JsonValue = claim.object.value  # type: ignore[assignment]
    if claim.object.datatype == "decimal":
        value = float(claim.object.value)  # type: ignore[arg-type]
    return ReviewClaim(
        claim_id=claim.claim_id,
        subject=claim.subject,
        predicate=claim.predicate,
        value=value,
        datatype=claim.object.datatype,
        qualifiers=claim.qualifiers,
        evidence_ids=claim.evidence_ids,
    )


def build_phase2_real_review_packet(root: Path) -> ReviewPacket:
    """Build the deterministic 12-item real-source review packet offline."""

    root = root.resolve(strict=True)
    states, documents = load_phase2_real_corpus(root)
    cases = load_phase2_real_cases(root, states=states, documents=documents)
    authority = load_authority_policy_config(root / "configs/authority-policy.yaml")
    state_by_id = {state.manifest.snapshot_id: state for state in states}
    document_by_snapshot = {document.snapshot_id: document for document in documents}
    policies_by_id = {policy.policy_id: policy for policy in authority.policies}

    items: list[ReviewItem] = []
    for case in cases:
        claim = case.expected_claims[0] if case.expected_claims else None
        policies = [
            policies_by_id[value] for value in case.required_authority_policy_ids
        ]
        target_snapshot_ids = list(case.allowed_snapshot_ids)
        if not target_snapshot_ids:
            target_by_template = {
                "nvd-published-at": "nvd-ec21319bd698",
                "nvd-modified-at": "nvd-ec21319bd698",
                "nvd-cvss-score": "nvd-ec21319bd698",
                "kev-membership": "kev-41d27023a591",
                "kev-date-added": "kev-41d27023a591",
                "kev-due-date": "kev-41d27023a591",
                "red-hat-affected-versions": "rhsa-da43faeafb5b",
                "red-hat-fixed-versions": "rhsa-da43faeafb5b",
            }
            target_snapshot_ids = [target_by_template[case.template_family_id]]
        sources: list[ReviewSource] = []
        all_evidence: list[ReviewEvidence] = []
        expected_ids = set(claim.evidence_ids if claim is not None else [])
        for snapshot_id in target_snapshot_ids:
            state = state_by_id[snapshot_id]
            document = document_by_snapshot[snapshot_id]
            manifest = state.manifest
            sources.append(
                ReviewSource(
                    snapshot_id=snapshot_id,
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
            )
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
        )
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
        item_data: dict[str, Any] = {
            "item_id": f"review-{case.case_id}",
            "item_sha256": "0" * 64,
            "case_id": case.case_id,
            "case_sha256": case_hash,
            "question": case.question,
            "cutoff_utc": case.as_of,
            "case_category": _category(case),
            "scope_label": "Log4Shell plumbing-only",
            "original_label": OriginalLabel(
                expected_answer="abstain" if case.should_abstain else "answer",
                abstention_reason=case.abstention_reason,
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

    packet_data: dict[str, Any] = {
        "schema_version": "review-packet-v1",
        "packet_id": "phase2-real-gold-review-v1",
        "packet_sha256": "0" * 64,
        "created_at_utc": max(state.manifest.retrieved_at_utc for state in states),
        "benchmark_scope": "Log4Shell plumbing-only",
        "blinding_statement": (
            "No model outputs, conditions, pass/fail fields, aggregates, "
            "or preferences."
        ),
        "case_file_sha256": hashlib.sha256(
            (root / "data/benchmark/dev/phase2-real-cases.jsonl").read_bytes()
        ).hexdigest(),
        "authority_policy_sha256": hashlib.sha256(
            (root / "configs/authority-policy.yaml").read_bytes()
        ).hexdigest(),
        "items": sorted(items, key=lambda item: item.case_id),
    }
    packet_data["packet_sha256"] = canonical_sha256(
        {key: value for key, value in packet_data.items() if key != "packet_sha256"}
    )
    return ReviewPacket.model_validate(packet_data)


def render_review_packet(packet: ReviewPacket) -> str:
    """Render a stable, human-readable packet file."""

    return (
        json.dumps(
            packet.model_dump(mode="json", exclude_unset=True),
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )


def render_canonical_jsonl(records: list[BaseModel]) -> str:
    """Render records in stable identity order without changing their content."""

    def identity(record: BaseModel) -> tuple[datetime, str]:
        if isinstance(record, ReviewDecision):
            return record.decided_at_utc, record.decision_id
        if isinstance(record, ReviewAdjudication):
            return record.adjudicated_at_utc, record.adjudication_id
        raise TypeError("canonical review JSONL accepts review records only")

    return "".join(
        json.dumps(
            record.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for record in sorted(records, key=identity)
    )


def load_jsonl_records[ModelT: BaseModel](
    path: Path,
    model: type[ModelT],
) -> list[ModelT]:
    """Load strict JSONL records without accepting blank or malformed lines."""

    records: list[ModelT] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            records.append(model.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"invalid review record at line {line_number}") from exc
    return records


def validate_review_log(
    packet: ReviewPacket,
    decisions: list[ReviewDecision],
    adjudications: list[ReviewAdjudication],
    *,
    review_mode: ReviewMode = "single_reviewer",
) -> ReviewValidationSummary:
    """Validate packet bindings, append-only corrections, and adjudications."""

    item_by_id = {item.item_id: item for item in packet.items}
    decision_by_id: dict[str, ReviewDecision] = {}
    superseded: set[str] = set()
    active_by_key: dict[tuple[str, str], ReviewDecision] = {}
    for decision in decisions:
        if decision.decision_id in decision_by_id:
            raise ValueError("duplicate decision_id")
        item = item_by_id.get(decision.item_id)
        if item is None or decision.case_id != (item.case_id if item else None):
            raise ValueError(
                "decision references a nonexistent item or mismatched case"
            )
        if (
            decision.packet_sha256 != packet.packet_sha256
            or decision.item_sha256 != item.item_sha256
            or decision.case_sha256 != item.case_sha256
            or decision.evidence_binding_sha256 != item.evidence_binding_sha256
            or decision.original_label_sha256 != canonical_sha256(item.original_label)
        ):
            raise ValueError(
                "decision packet, case, evidence, or label binding changed"
            )
        if decision.decided_at_utc <= packet.created_at_utc:
            raise ValueError("decision must be recorded after packet creation")
        key = (decision.item_id, decision.reviewer_id)
        prior_id = decision.supersedes_decision_id
        if prior_id is None:
            if key in active_by_key:
                raise ValueError(
                    "reviewer decision overwrite requires supersedes_decision_id"
                )
        else:
            prior = decision_by_id.get(prior_id)
            if prior is None or (prior.item_id, prior.reviewer_id) != key:
                raise ValueError(
                    "superseded decision must be an earlier matching record"
                )
            if prior_id in superseded or active_by_key.get(key) is not prior:
                raise ValueError("only the active decision may be superseded")
            if decision.decided_at_utc <= prior.decided_at_utc:
                raise ValueError("superseding decision must be later")
            superseded.add(prior_id)
        decision_by_id[decision.decision_id] = decision
        active_by_key[key] = decision

    active_by_item: dict[str, list[ReviewDecision]] = defaultdict(list)
    for decision in active_by_key.values():
        active_by_item[decision.item_id].append(decision)
    active_reviewer_ids = {decision.reviewer_id for decision in active_by_key.values()}
    required_reviews: Literal[1, 2] = 1 if review_mode == "single_reviewer" else 2
    if review_mode == "single_reviewer" and adjudications:
        raise ValueError("single-reviewer mode cannot contain adjudications")
    if len(active_reviewer_ids) > required_reviews:
        raise ValueError("a packet may use only its declared fixed reviewer cohort")
    if any(len(values) > required_reviews for values in active_by_item.values()):
        raise ValueError(
            "an item has more active decisions than its review mode permits"
        )

    def disagreement_key(decision: ReviewDecision) -> tuple[object, ...]:
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

    disagreements = (
        []
        if review_mode == "single_reviewer"
        else sorted(
            item_id
            for item_id, values in active_by_item.items()
            if len(values) >= 2
            and len({disagreement_key(value) for value in values}) > 1
        )
    )

    adjudication_ids: set[str] = set()
    adjudicated_items: set[str] = set()
    for adjudication in adjudications:
        if adjudication.adjudication_id in adjudication_ids:
            raise ValueError("duplicate adjudication_id")
        item = item_by_id.get(adjudication.item_id)
        linked = [
            decision_by_id.get(value) for value in adjudication.reviewer_decision_ids
        ]
        if (
            item is None
            or adjudication.packet_sha256 != packet.packet_sha256
            or adjudication.item_sha256 != item.item_sha256
            or adjudication.case_id != item.case_id
            or any(value is None for value in linked)
        ):
            raise ValueError("adjudication has a missing or mismatched binding")
        linked_decisions = [value for value in linked if value is not None]
        if (
            len({value.reviewer_id for value in linked_decisions}) != 2
            or any(value.item_id != item.item_id for value in linked_decisions)
            or any(value.decision_id in superseded for value in linked_decisions)
            or {value.decision_id for value in linked_decisions}
            != {value.decision_id for value in active_by_item[item.item_id]}
            or item.item_id not in disagreements
            or adjudication.adjudicator_id
            in {value.reviewer_id for value in linked_decisions}
            or adjudication.adjudicated_at_utc
            <= max(value.decided_at_utc for value in linked_decisions)
        ):
            raise ValueError("adjudication requires two prior disagreeing reviewers")
        if item.item_id in adjudicated_items:
            raise ValueError("item already has an adjudication")
        adjudication_ids.add(adjudication.adjudication_id)
        adjudicated_items.add(item.item_id)

    completed = sorted(
        item.item_id
        for item in packet.items
        if len(active_by_item[item.item_id]) >= required_reviews
        and (
            review_mode == "single_reviewer"
            or item.item_id not in disagreements
            or item.item_id in adjudicated_items
        )
    )
    unresolved = sorted(
        item.item_id
        for item in packet.items
        if len(active_by_item[item.item_id]) < required_reviews
        or (
            review_mode == "double_reviewer"
            and item.item_id in disagreements
            and item.item_id not in adjudicated_items
        )
    )
    return ReviewValidationSummary(
        packet_id=packet.packet_id,
        packet_sha256=packet.packet_sha256,
        review_mode=review_mode,
        required_reviews_per_item=required_reviews,
        item_count=len(packet.items),
        decision_count=len(decisions),
        active_decision_count=len(active_by_key),
        adjudication_count=len(adjudications),
        reviewer_ids=sorted(active_reviewer_ids),
        completed_item_ids=completed,
        disagreement_item_ids=disagreements,
        unresolved_item_ids=unresolved,
    )


def render_review_summary(summary: ReviewValidationSummary) -> str:
    """Render a stable Markdown status summary without model-result fields."""

    disagreements = ", ".join(summary.disagreement_item_ids) or "none"
    unresolved = ", ".join(summary.unresolved_item_ids) or "none"
    return (
        "# Human review status\n\n"
        f"- Packet: `{summary.packet_id}` (`{summary.packet_sha256}`)\n"
        f"- Review mode: `{summary.review_mode}` "
        f"({summary.required_reviews_per_item} required per item)\n"
        f"- Items: {summary.item_count}\n"
        f"- Completed items: {len(summary.completed_item_ids)}\n"
        f"- Reviewer IDs: {', '.join(summary.reviewer_ids) or 'none'}\n"
        f"- Decisions: {summary.decision_count} "
        f"({summary.active_decision_count} active)\n"
        f"- Adjudications: {summary.adjudication_count}\n"
        f"- Disagreements: {disagreements}\n"
        f"- Unresolved: {unresolved}\n"
    )
