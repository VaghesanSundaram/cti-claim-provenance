"""Additive, human-auditable question draft for the diverse portfolio v3."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

from cti_provenance.claims.schema import PredicateName


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must be UTC")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc)]
NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
QuestionSlice = Literal[
    "single_source_extraction",
    "temporal_comparison",
    "cutoff_or_insufficiency_abstention",
    "authority_divergence",
    "multi_source_synthesis",
]


def canonical_sha256(value: object) -> str:
    """Hash JSON-compatible data using the repository's canonical encoding."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    else:
        value = to_jsonable_python(value)
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


class DiverseEvidence(BaseModel):
    """One minimal evidence item bound to an authentic frozen source."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evidence_id: NonEmpty
    source_id: NonEmpty
    source_name: NonEmpty
    source_class: Literal["government", "standards_body", "vendor"]
    title: NonEmpty
    url: NonEmpty
    local_reference: NonEmpty
    source_sha256: Sha256
    source_available_by_utc: UtcDateTime
    temporal_basis: Literal[
        "publisher_declared_version",
        "observed_retrieval",
        "publisher_timestamp_with_observation",
    ]
    authority_scope: NonEmpty
    locator: NonEmpty
    exact_text: NonEmpty
    text_sha256: Sha256
    extraction_method: Literal[
        "literal_raw_span",
        "normalized_span",
        "deterministic_derivation",
    ]
    role: Literal[
        "required_support",
        "eligible_but_insufficient",
        "excluded_post_cutoff",
        "authority_boundary",
    ]
    terms_disposition: NonEmpty

    @model_validator(mode="after")
    def validate_text_hash(self) -> Self:
        if hashlib.sha256(self.exact_text.encode()).hexdigest() != self.text_sha256:
            raise ValueError("evidence text hash mismatch")
        return self


class DiverseQuestion(BaseModel):
    """One unique semantic question proposed for manager and human review."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case_id: NonEmpty
    slice: QuestionSlice
    source_family_id: NonEmpty
    dependency_id: NonEmpty
    split: Literal["dev", "validation"]
    predicate: PredicateName
    answer_type: Literal["boolean", "string", "set", "qualified_statement"]
    outcome_type: Literal["positive", "negative", "no_change", "abstain"]
    cutoff_utc: UtcDateTime
    question: NonEmpty
    expected_answer: str | bool | list[str] | None
    abstention_reason: str | None
    evidence: list[DiverseEvidence]
    required_evidence_ids: list[NonEmpty]
    authority_rationale: NonEmpty
    temporal_rationale: NonEmpty
    ambiguity_notes: NonEmpty
    leakage_audit: NonEmpty
    retained_v2_case_id: str | None = None
    retained_v2_case_sha256: Sha256 | None = None
    review_status: Literal["approved_v2", "manager_audit_pending"]
    question_sha256: Sha256

    @field_validator("required_evidence_ids")
    @classmethod
    def unique_required_evidence(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("required evidence IDs must be unique")
        return values

    @model_validator(mode="after")
    def validate_question(self) -> Self:
        evidence_ids = [value.evidence_id for value in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence IDs must be unique within a question")
        if not set(self.required_evidence_ids).issubset(evidence_ids):
            raise ValueError("required evidence is not present")
        if self.outcome_type == "abstain":
            if self.expected_answer is not None or not self.abstention_reason:
                raise ValueError("abstention requires a reason and no answer")
        elif self.expected_answer is None or self.abstention_reason is not None:
            raise ValueError("answerable questions require an answer and no reason")
        if self.slice == "single_source_extraction":
            if self.review_status != "approved_v2" or not self.retained_v2_case_id:
                raise ValueError("extraction questions must bind an approved v2 case")
        else:
            if self.review_status != "manager_audit_pending":
                raise ValueError("new questions must remain pending manager audit")
            if (
                self.slice != "cutoff_or_insufficiency_abstention"
                and len(self.required_evidence_ids) < 2
            ):
                raise ValueError("multi-state/source questions require all spans")
        body = self.model_dump(mode="json", exclude={"question_sha256"})
        if canonical_sha256(body) != self.question_sha256:
            raise ValueError("question hash mismatch")
        return self


class DiverseCorpusDraft(BaseModel):
    """Frozen manager-audit candidate; not yet human-approved benchmark gold."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-draft-v3"]
    corpus_id: Literal["portfolio-diverse-v3-manager-audit-candidate"]
    created_at_utc: UtcDateTime
    temporal_boundary: Literal[
        "publisher-declared version evidence is not independently observed history"
    ]
    questions: list[DiverseQuestion] = Field(min_length=48)
    corpus_sha256: Sha256

    @model_validator(mode="after")
    def validate_corpus(self) -> Self:
        ids = [question.case_id for question in self.questions]
        if len(ids) != len(set(ids)):
            raise ValueError("case IDs must be unique")
        counts = Counter(question.slice for question in self.questions)
        required_minimum: dict[QuestionSlice, int] = {
            "single_source_extraction": 16,
            "temporal_comparison": 8,
            "cutoff_or_insufficiency_abstention": 8,
            "authority_divergence": 8,
            "multi_source_synthesis": 8,
        }
        if counts["single_source_extraction"] != 16 or any(
            counts[slice_name] < minimum
            for slice_name, minimum in required_minimum.items()
            if slice_name != "single_source_extraction"
        ):
            raise ValueError(f"draft slice counts do not satisfy {required_minimum!r}")
        if sum(question.outcome_type == "abstain" for question in self.questions) != 8:
            raise ValueError("draft must contain exactly eight explicit abstentions")
        body = self.model_dump(mode="json", exclude={"corpus_sha256"})
        if canonical_sha256(body) != self.corpus_sha256:
            raise ValueError("corpus hash mismatch")
        return self


def load_diverse_corpus_draft(path: Path) -> DiverseCorpusDraft:
    """Load the strict canonical manager-audit candidate."""

    return DiverseCorpusDraft.model_validate_json(path.read_text(encoding="utf-8"))


def grade_diverse_outcome(
    question: DiverseQuestion,
    *,
    answer: str | bool | list[str] | None,
    abstained: bool,
    cited_evidence_ids: list[str],
) -> bool:
    """Exact draft oracle requiring every necessary span and explicit abstention."""

    if question.outcome_type == "abstain":
        return abstained and answer is None and not cited_evidence_ids
    return (
        not abstained
        and answer == question.expected_answer
        and set(question.required_evidence_ids).issubset(cited_evidence_ids)
        and len(cited_evidence_ids) == len(set(cited_evidence_ids))
    )
