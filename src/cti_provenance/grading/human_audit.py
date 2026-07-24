"""Fail-closed validation for blinded human entailment calibration artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from cti_provenance.grading.schema import ClaimGrade

NonEmptyString = Annotated[
    StrictStr,
    StringConstraints(strip_whitespace=True, min_length=1, pattern=r".*\S.*"),
]
Sha256 = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
EntailmentLabel = Literal["supported", "partial", "unsupported", "not_applicable"]
_SAFE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_LABELS: tuple[EntailmentLabel, ...] = (
    "supported",
    "partial",
    "unsupported",
    "not_applicable",
)


class HumanAuditError(ValueError):
    """A calibration artifact is malformed, unsafe, or internally inconsistent."""


class ArtifactBinding(BaseModel):
    """Exact-byte binding for one calibration artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: NonEmptyString
    sha256: Sha256
    byte_length: StrictInt = Field(ge=1)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        relative = PurePosixPath(value)
        if (
            not _SAFE_PATH.fullmatch(value)
            or relative.is_absolute()
            or ".." in relative.parts
            or "." in relative.parts
        ):
            raise ValueError("artifact path must be a canonical safe relative path")
        return value


class CalibrationManifest(BaseModel):
    """Exact inputs and upstream identities for one calibration cohort."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    manifest_version: Literal["human-calibration-manifest-v1"]
    protocol_spec: ArtifactBinding
    protocol_document: ArtifactBinding
    grade_records: ArtifactBinding
    reviewer_contexts: ArtifactBinding
    items: ArtifactBinding
    judgments: ArtifactBinding
    adjudications: ArtifactBinding
    candidate_manifest_sha256: Sha256
    source_bundle_sha256: Sha256
    grade_schema_sha256: Sha256
    deterministic_grader_version: NonEmptyString
    authority_policy_version: NonEmptyString
    normalization_versions: tuple[NonEmptyString, ...]
    item_universe_sha256: Sha256

    def sha256(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CalibrationProtocol(BaseModel):
    """Machine-checkable process rules bound to the human-readable protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    protocol_version: Literal["human-calibration-v1"]
    judgments_per_item: Literal[2]
    reviewers_blind_to_conditions: Literal[True]
    adjudicator_blind_to_conditions: Literal[True]
    agreement_method: Literal["cohen_kappa_v1"]
    label_set: tuple[EntailmentLabel, ...]

    @field_validator("label_set", mode="before")
    @classmethod
    def freeze_label_set(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("label_set must be an array")
        return tuple(value)

    @model_validator(mode="after")
    def validate_labels(self) -> Self:
        if self.label_set != _LABELS:
            raise ValueError("v1 label_set differs from the frozen vocabulary")
        return self


class CalibrationItem(BaseModel):
    """One content-hash-bound item without model or condition metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    item_id: NonEmptyString
    case_id: NonEmptyString
    claim_grade_id: NonEmptyString
    evidence_id: NonEmptyString
    predicate: NonEmptyString
    split: Literal["dev", "validation"]
    source_name: NonEmptyString
    context_sha256: Sha256


class CalibrationContextRecord(BaseModel):
    """Exact condition-blind content shown for one entailment judgment."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    item_id: NonEmptyString
    case_id: NonEmptyString
    evidence_id: NonEmptyString
    predicate: NonEmptyString
    source_name: NonEmptyString
    question: NonEmptyString
    evidence_text: NonEmptyString
    evidence_text_sha256: Sha256

    @model_validator(mode="after")
    def validate_evidence_text_hash(self) -> Self:
        actual = hashlib.sha256(self.evidence_text.encode("utf-8")).hexdigest()
        if actual != self.evidence_text_sha256:
            raise ValueError("reviewer context evidence text hash does not match")
        return self

    def sha256(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CalibrationJudgment(BaseModel):
    """One blinded reviewer label for an item."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    judgment_id: NonEmptyString
    item_id: NonEmptyString
    reviewer_id: NonEmptyString
    judged_at_utc: AwareDatetime
    label: EntailmentLabel

    @field_validator("judged_at_utc")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("judgment timestamp must use UTC")
        return value.astimezone(UTC)


class CalibrationAdjudication(BaseModel):
    """One blinded resolution for exactly one disagreeing pair."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    adjudication_id: NonEmptyString
    item_id: NonEmptyString
    judgment_ids: tuple[NonEmptyString, NonEmptyString]
    adjudicator_id: NonEmptyString
    adjudicated_at_utc: AwareDatetime
    final_label: EntailmentLabel
    rationale_code: Literal["evidence_support_resolution", "ambiguous_stratum_removed"]

    @field_validator("adjudicated_at_utc")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("adjudication timestamp must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        if self.judgment_ids[0] == self.judgment_ids[1]:
            raise ValueError("adjudication must reference two distinct judgments")
        return self


class HumanCalibrationFinding(BaseModel):
    """Deterministic structural/calculation result."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    code: Literal[
        "evidence_span_provenance_unbound",
        "insufficient_cohort",
        "kappa_undefined",
    ]
    detail: NonEmptyString


class HumanCalibrationAudit(BaseModel):
    """Derived evidence; no caller-supplied counts or statistics are accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    audit_version: Literal["human-calibration-audit-v1"]
    manifest_sha256: Sha256
    protocol_version: Literal["human-calibration-v1"]
    candidate_manifest_sha256: Sha256
    source_bundle_sha256: Sha256
    grade_schema_sha256: Sha256
    deterministic_grader_version: NonEmptyString
    authority_policy_version: NonEmptyString
    normalization_versions: tuple[NonEmptyString, ...]
    item_universe_sha256: Sha256
    items: tuple[CalibrationItem, ...]
    reviewer_contexts: tuple[CalibrationContextRecord, ...]
    item_count: StrictInt = Field(ge=1)
    judgment_count: StrictInt = Field(ge=2)
    disagreement_count: StrictInt = Field(ge=0)
    adjudication_count: StrictInt = Field(ge=0)
    raw_agreement_numerator: StrictInt = Field(ge=0)
    raw_agreement_denominator: StrictInt = Field(ge=1)
    raw_agreement: Decimal
    cohens_kappa: Decimal | None
    evidence_span_binding_status: Literal["bound", "unbound"]
    structural_gate_complete: bool
    acceptance_threshold_status: Literal["not_declared"]
    findings: tuple[HumanCalibrationFinding, ...]


def _safe_file(root: Path, binding: ArtifactBinding) -> bytes:
    root_resolved = root.resolve(strict=True)
    relative = PurePosixPath(binding.path)
    candidate = root_resolved.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise HumanAuditError(
            "calibration artifact is unavailable or escapes root"
        ) from exc
    current = candidate
    while current != root_resolved:
        is_junction = getattr(current, "is_junction", None)
        if current.is_symlink() or (callable(is_junction) and is_junction()):
            raise HumanAuditError("calibration artifact traverses a link or junction")
        current = current.parent
    if not resolved.is_file():
        raise HumanAuditError("calibration artifact is not a regular file")
    body = resolved.read_bytes()
    if (
        len(body) != binding.byte_length
        or hashlib.sha256(body).hexdigest() != binding.sha256
    ):
        raise HumanAuditError(
            "calibration artifact bytes do not match manifest binding"
        )
    return body


def _load_json(body: bytes, model: type[BaseModel], label: str) -> BaseModel:
    try:
        return model.model_validate_json(body)
    except ValueError as exc:
        raise HumanAuditError(f"invalid {label} JSON") from exc


def _load_jsonl(
    body: bytes, model: type[BaseModel], label: str, *, require_nonempty: bool = True
) -> tuple[BaseModel, ...]:
    records: list[BaseModel] = []
    for line_number, line in enumerate(body.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(model.model_validate_json(line))
        except ValueError as exc:
            raise HumanAuditError(f"invalid {label} JSONL line {line_number}") from exc
    if require_nonempty and not records:
        raise HumanAuditError(f"{label} must not be empty")
    return tuple(records)


def _unique_ids(values: tuple[BaseModel, ...], attribute: str, label: str) -> None:
    identifiers = [getattr(value, attribute) for value in values]
    if len(identifiers) != len(set(identifiers)):
        raise HumanAuditError(f"{label} identifiers must be unique")


def _canonical_records_sha256(records: tuple[CalibrationItem, ...]) -> str:
    body = "\n".join(
        json.dumps(
            item.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        for item in sorted(records, key=lambda item: item.item_id)
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def audit_human_calibration(
    root: Path,
    manifest: CalibrationManifest,
    *,
    expected_candidate_manifest_sha256: str,
    expected_source_bundle_sha256: str,
    expected_grade_schema_sha256: str,
    expected_evidence_text_sha256_by_id: Mapping[str, str] | None = None,
) -> HumanCalibrationAudit:
    """Derive agreement only after exact bytes and upstream identities validate."""

    try:
        manifest = CalibrationManifest.model_validate(
            manifest.model_dump(mode="python")
        )
    except ValueError as exc:
        raise HumanAuditError("calibration manifest failed revalidation") from exc
    expected_bindings = (
        (manifest.candidate_manifest_sha256, expected_candidate_manifest_sha256),
        (manifest.source_bundle_sha256, expected_source_bundle_sha256),
        (manifest.grade_schema_sha256, expected_grade_schema_sha256),
    )
    if any(actual != expected for actual, expected in expected_bindings):
        raise HumanAuditError("calibration upstream hash binding does not match")

    protocol = _load_json(
        _safe_file(root, manifest.protocol_spec),
        CalibrationProtocol,
        "protocol specification",
    )
    assert isinstance(protocol, CalibrationProtocol)
    _safe_file(root, manifest.protocol_document)
    grade_records = tuple(
        grade
        for record in _load_jsonl(
            _safe_file(root, manifest.grade_records),
            ClaimGrade,
            "grade records",
        )
        if isinstance((grade := record), ClaimGrade)
    )
    contexts = tuple(
        context
        for record in _load_jsonl(
            _safe_file(root, manifest.reviewer_contexts),
            CalibrationContextRecord,
            "reviewer contexts",
        )
        if isinstance((context := record), CalibrationContextRecord)
    )
    items = tuple(
        item
        for item in _load_jsonl(
            _safe_file(root, manifest.items), CalibrationItem, "items"
        )
        if isinstance(item, CalibrationItem)
    )
    judgments = tuple(
        judgment
        for judgment in _load_jsonl(
            _safe_file(root, manifest.judgments),
            CalibrationJudgment,
            "judgments",
        )
        if isinstance(judgment, CalibrationJudgment)
    )
    adjudications = tuple(
        adjudication
        for adjudication in _load_jsonl(
            _safe_file(root, manifest.adjudications),
            CalibrationAdjudication,
            "adjudications",
            require_nonempty=False,
        )
        if isinstance(adjudication, CalibrationAdjudication)
    )
    if _canonical_records_sha256(items) != manifest.item_universe_sha256:
        raise HumanAuditError("item universe hash does not match parsed items")
    _unique_ids(items, "item_id", "item")
    _unique_ids(grade_records, "claim_grade_id", "grade record")
    grader_versions = {grade.deterministic_grader_version for grade in grade_records}
    authority_versions = {grade.authority_policy_version for grade in grade_records}
    if len(grader_versions) != 1 or len(authority_versions) != 1:
        raise HumanAuditError(
            "calibration grader and authority versions must be uniform"
        )
    grader_version = next(iter(grader_versions))
    authority_policy_version = next(iter(authority_versions))
    normalization_versions = tuple(
        sorted({grade.normalization_version for grade in grade_records})
    )
    if (
        grader_version != manifest.deterministic_grader_version
        or authority_policy_version != manifest.authority_policy_version
        or normalization_versions != manifest.normalization_versions
    ):
        raise HumanAuditError("calibration grade versions differ from the manifest")
    _unique_ids(contexts, "item_id", "reviewer context")
    grade_by_id = {record.claim_grade_id: record for record in grade_records}
    context_by_item = {context.item_id: context for context in contexts}
    if set(context_by_item) != {item.item_id for item in items}:
        raise HumanAuditError("reviewer contexts and blinded items differ")
    for item in items:
        grade_record = grade_by_id.get(item.claim_grade_id)
        if (
            grade_record is None
            or grade_record.case_id != item.case_id
            or str(grade_record.predicate) != item.predicate
            or item.evidence_id
            not in {
                assessment.evidence_id
                for assessment in grade_record.evidence_assessments
            }
        ):
            raise HumanAuditError("blinded item differs from its grade record")
        context = context_by_item[item.item_id]
        if (
            context.case_id != item.case_id
            or context.evidence_id != item.evidence_id
            or context.predicate != item.predicate
            or context.source_name != item.source_name
            or context.sha256() != item.context_sha256
        ):
            raise HumanAuditError("blinded item differs from reviewer-visible context")
    semantic_item_ids = {
        (item.case_id, item.claim_grade_id, item.evidence_id) for item in items
    }
    if len(semantic_item_ids) != len(items):
        raise HumanAuditError("calibration item semantic identities must be unique")
    _unique_ids(judgments, "judgment_id", "judgment")
    _unique_ids(adjudications, "adjudication_id", "adjudication")

    item_ids = {item.item_id for item in items}
    by_item: dict[str, dict[str, CalibrationJudgment]] = {
        item_id: {} for item_id in item_ids
    }
    reviewer_ids: set[str] = set()
    for judgment in judgments:
        if judgment.item_id not in by_item:
            raise HumanAuditError("judgment references unknown item")
        if judgment.reviewer_id in by_item[judgment.item_id]:
            raise HumanAuditError("reviewer may judge an item only once")
        by_item[judgment.item_id][judgment.reviewer_id] = judgment
        reviewer_ids.add(judgment.reviewer_id)
    if len(reviewer_ids) != 2:
        raise HumanAuditError("v1 calibration requires exactly two reviewers")
    ordered_reviewers = tuple(sorted(reviewer_ids))

    disagreements: dict[str, tuple[CalibrationJudgment, CalibrationJudgment]] = {}
    agreements = 0
    ordered_pairs: list[tuple[CalibrationJudgment, CalibrationJudgment]] = []
    for item_id in sorted(by_item):
        reviewer_map = by_item[item_id]
        if set(reviewer_map) != set(ordered_reviewers):
            raise HumanAuditError("each item requires both independent reviewers")
        pair = (reviewer_map[ordered_reviewers[0]], reviewer_map[ordered_reviewers[1]])
        ordered_pairs.append(pair)
        if pair[0].label == pair[1].label:
            agreements += 1
        else:
            disagreements[item_id] = pair

    judgment_by_id = {judgment.judgment_id: judgment for judgment in judgments}
    adjudication_by_item: dict[str, CalibrationAdjudication] = {}
    for adjudication in adjudications:
        if adjudication.adjudicator_id in reviewer_ids:
            raise HumanAuditError("adjudicator must be independent of both reviewers")
        if adjudication.item_id not in disagreements:
            raise HumanAuditError("adjudication exists only for a disagreement")
        if adjudication.item_id in adjudication_by_item:
            raise HumanAuditError("each disagreement requires exactly one adjudication")
        try:
            referenced = tuple(
                judgment_by_id[judgment_id] for judgment_id in adjudication.judgment_ids
            )
        except KeyError as exc:
            raise HumanAuditError("adjudication references unknown judgment") from exc
        expected_ids = {
            judgment.judgment_id for judgment in disagreements[adjudication.item_id]
        }
        if {judgment.item_id for judgment in referenced} != {
            adjudication.item_id
        } or set(adjudication.judgment_ids) != expected_ids:
            raise HumanAuditError(
                "adjudication must reference the complete item disagreement"
            )
        if adjudication.adjudicated_at_utc <= max(
            judgment.judged_at_utc for judgment in referenced
        ):
            raise HumanAuditError("adjudication timestamp must follow both judgments")
        adjudication_by_item[adjudication.item_id] = adjudication
    if set(adjudication_by_item) != set(disagreements):
        raise HumanAuditError("every disagreement requires exactly one adjudication")

    item_count = len(items)
    raw_agreement = Decimal(agreements) / Decimal(item_count)
    reviewer_counts: dict[EntailmentLabel, list[int]] = {
        label: [0, 0] for label in _LABELS
    }
    for pair in ordered_pairs:
        reviewer_counts[pair[0].label][0] += 1
        reviewer_counts[pair[1].label][1] += 1
    expected_agreement = sum(
        (
            (Decimal(counts[0]) / Decimal(item_count))
            * (Decimal(counts[1]) / Decimal(item_count))
            for counts in reviewer_counts.values()
        ),
        Decimal(0),
    )
    findings: list[HumanCalibrationFinding] = []
    evidence_spans_bound = expected_evidence_text_sha256_by_id is not None
    if expected_evidence_text_sha256_by_id is None:
        findings.append(
            HumanCalibrationFinding(
                code="evidence_span_provenance_unbound",
                detail=(
                    "Reviewer-visible text lacks an independently derived "
                    "candidate evidence-span hash binding."
                ),
            )
        )
    else:
        for item in items:
            expected_text_sha256 = expected_evidence_text_sha256_by_id.get(
                item.evidence_id
            )
            if (
                expected_text_sha256 is None
                or context_by_item[item.item_id].evidence_text_sha256
                != expected_text_sha256
            ):
                raise HumanAuditError(
                    "reviewer-visible text differs from candidate evidence span"
                )
    kappa = None
    if expected_agreement == Decimal(1):
        findings.append(
            HumanCalibrationFinding(
                code="kappa_undefined",
                detail="Cohen kappa is undefined when expected agreement is one.",
            )
        )
    else:
        kappa = (raw_agreement - expected_agreement) / (Decimal(1) - expected_agreement)
    if item_count < 50:
        findings.append(
            HumanCalibrationFinding(
                code="insufficient_cohort",
                detail="A complete v1 structural gate requires at least 50 items.",
            )
        )
    return HumanCalibrationAudit(
        audit_version="human-calibration-audit-v1",
        manifest_sha256=manifest.sha256(),
        protocol_version=protocol.protocol_version,
        candidate_manifest_sha256=manifest.candidate_manifest_sha256,
        source_bundle_sha256=manifest.source_bundle_sha256,
        grade_schema_sha256=manifest.grade_schema_sha256,
        deterministic_grader_version=grader_version,
        authority_policy_version=authority_policy_version,
        normalization_versions=normalization_versions,
        item_universe_sha256=manifest.item_universe_sha256,
        items=tuple(sorted(items, key=lambda item: item.item_id)),
        reviewer_contexts=tuple(sorted(contexts, key=lambda context: context.item_id)),
        item_count=item_count,
        judgment_count=len(judgments),
        disagreement_count=len(disagreements),
        adjudication_count=len(adjudications),
        raw_agreement_numerator=agreements,
        raw_agreement_denominator=item_count,
        raw_agreement=raw_agreement,
        cohens_kappa=kappa,
        evidence_span_binding_status="bound" if evidence_spans_bound else "unbound",
        structural_gate_complete=(
            item_count >= 50 and kappa is not None and evidence_spans_bound
        ),
        acceptance_threshold_status="not_declared",
        findings=tuple(findings),
    )
