"""Deterministic dataset-wide leakage, pairing, and pilot-readiness audits."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Callable, Hashable, Mapping, Sequence
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from cti_provenance.claims.schema import PredicateName
from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.experiments.pilot_plan import (
    PHASE7_CONDITIONS,
    PHASE7_MAXIMUM_BASE_CASES,
    PHASE7_MINIMUM_ATTACKED_PAIRS,
    PHASE7_REPETITIONS,
    PilotExecutionEvidence,
    PilotExecutionPlan,
    PilotScheduleError,
    PilotScheduleSlot,
    build_pilot_execution_evidence,
)
from cti_provenance.grading.human_audit import (
    CalibrationManifest,
    HumanAuditError,
    audit_human_calibration,
)
from cti_provenance.snapshot.manifest import SnapshotManifest

DATASET_AUDIT_VERSION: Literal["dataset-audit-v1"] = "dataset-audit-v1"
NEAR_DUPLICATE_JACCARD_THRESHOLD = 0.90
_SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_NON_EMPTY = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_QUESTION_TOKEN = re.compile(r"[a-z0-9]+")
_SOURCE_BY_PREDICATE: dict[PredicateName, str] = {
    "cve.affected_versions": "cve_program",
    "directive.required_action": "cisa_directive",
    "cve.published_at": "nvd",
    "cve.modified_at": "nvd",
    "cve.cvss.score": "nvd",
    "kev.is_member": "cisa_kev",
    "kev.date_added": "cisa_kev",
    "kev.due_date": "cisa_kev",
    "vendor.affected_versions": "red_hat_rhsa",
    "vendor.fixed_versions": "red_hat_rhsa",
    "vendor.recommended_action": "netscaler_advisory",
    "attack.relationship_present": "mitre_attack",
    "vendor.release_affected_versions": "vendor_advisory",
    "kev.ransomware_campaign_use": "cisa_kev",
    "attack.platforms": "mitre_attack",
    "vendor.security_release_versions": "vendor_advisory",
    "vendor.cve_fixed_release": "vendor_advisory",
    "nvd.cpe_applicability": "nvd",
}
_CONFIRMATORY_CELLS = {
    ("nvd", "cve.published_at"),
    ("cisa_kev", "kev.is_member"),
    ("mitre_attack", "attack.relationship_present"),
    ("red_hat_rhsa", "vendor.fixed_versions"),
}
_DOCUMENT_EVIDENCE_BY_MANIFEST_BASIS = {
    "observed_retrieval": "observed_retrieval",
    "upstream_version": "upstream_version",
    "signed_release": "signed_release",
    "publisher_timestamp_with_observation": "publisher_version",
    "synthetic_fixture": "synthetic_fixture",
}


class DatasetReadinessError(ValueError):
    """Dataset audit inputs are unavailable, unsafe, or structurally invalid."""


class DatasetDocumentIdentity(BaseModel):
    """Non-content identity fields needed for cross-split document leakage checks."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    document_id: _NON_EMPTY
    snapshot_id: _NON_EMPTY
    upstream_entity_id: _NON_EMPTY
    canonical_url: _NON_EMPTY
    normalized_text_sha256: _SHA256
    available_by_utc: AwareDatetime
    availability_evidence: Literal[
        "observed_retrieval",
        "upstream_version",
        "signed_release",
        "publisher_version",
        "synthetic_fixture",
    ]
    source_name: Literal[
        "cisa_directive",
        "cve_program",
        "nvd",
        "cisa_kev",
        "mitre_attack",
        "netscaler_advisory",
        "red_hat_rhsa",
        "vendor_advisory",
        "synthetic_control",
    ]


class CaseFileBinding(BaseModel):
    """Exact byte binding for one candidate benchmark case file."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: _NON_EMPTY
    sha256: _SHA256
    byte_length: int = Field(ge=1)
    case_count: int = Field(ge=1)
    splits: tuple[Literal["dev", "validation", "holdout"], ...]

    @field_validator("splits")
    @classmethod
    def unique_ordered_splits(
        cls,
        value: tuple[Literal["dev", "validation", "holdout"], ...],
    ) -> tuple[Literal["dev", "validation", "holdout"], ...]:
        if not value or tuple(sorted(set(value))) != value:
            raise ValueError("case-file splits must be unique and sorted")
        return value


class SourceManifestBinding(BaseModel):
    """Exact byte and snapshot-ID binding for one source manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: _NON_EMPTY
    sha256: _SHA256
    byte_length: int = Field(ge=1)
    record_count: int = Field(ge=1)
    snapshot_ids: tuple[str, ...]
    source_names: tuple[str, ...]
    snapshot_sources: tuple[tuple[str, str], ...]
    snapshot_availability: tuple[
        tuple[
            str,
            AwareDatetime,
            Literal[
                "observed_retrieval",
                "upstream_version",
                "signed_release",
                "publisher_timestamp_with_observation",
                "publisher_declared_version",
                "synthetic_fixture",
            ],
        ],
        ...,
    ]

    @field_validator("snapshot_ids", "source_names")
    @classmethod
    def unique_ordered_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)) or list(value) != sorted(value):
            raise ValueError("manifest identity values must be unique and sorted")
        return value

    @field_validator("snapshot_sources")
    @classmethod
    def unique_snapshot_sources(
        cls,
        value: tuple[tuple[str, str], ...],
    ) -> tuple[tuple[str, str], ...]:
        if not value or len(value) != len(set(value)) or list(value) != sorted(value):
            raise ValueError("snapshot/source bindings must be unique and sorted")
        return value

    @field_validator("snapshot_availability")
    @classmethod
    def unique_snapshot_availability(
        cls,
        value: tuple[tuple[str, AwareDatetime, str], ...],
    ) -> tuple[tuple[str, AwareDatetime, str], ...]:
        snapshot_ids = [item[0] for item in value]
        if (
            not value
            or len(snapshot_ids) != len(set(snapshot_ids))
            or snapshot_ids != sorted(snapshot_ids)
        ):
            raise ValueError("snapshot availability bindings must be unique and sorted")
        return value

    @model_validator(mode="after")
    def consistent_snapshot_inventory(self) -> SourceManifestBinding:
        source_ids = [item[0] for item in self.snapshot_sources]
        availability_ids = [item[0] for item in self.snapshot_availability]
        if (
            self.record_count != len(self.snapshot_ids)
            or source_ids != list(self.snapshot_ids)
            or availability_ids != list(self.snapshot_ids)
            or tuple(sorted({item[1] for item in self.snapshot_sources}))
            != self.source_names
        ):
            raise ValueError("source manifest binding inventories are inconsistent")
        return self


class DocumentIdentityFileBinding(BaseModel):
    """Exact byte and document-ID binding for one identity inventory."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: _NON_EMPTY
    sha256: _SHA256
    byte_length: int = Field(ge=1)
    record_count: int = Field(ge=1)
    document_ids: tuple[str, ...]

    @field_validator("document_ids")
    @classmethod
    def unique_document_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)) or list(value) != sorted(value):
            raise ValueError("document IDs must be unique and sorted")
        return value

    @model_validator(mode="after")
    def consistent_document_count(self) -> DocumentIdentityFileBinding:
        if self.record_count != len(self.document_ids):
            raise ValueError("document identity count is inconsistent")
        return self


class DatasetCandidateManifest(BaseModel):
    """Hash-bound candidate inputs; this is not a frozen benchmark declaration."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    dataset_version: _NON_EMPTY
    audit_version: Literal["dataset-audit-v1"]
    case_files: tuple[CaseFileBinding, ...]
    case_record_count: int = Field(ge=1)
    case_records_sha256: _SHA256
    source_manifests: tuple[SourceManifestBinding, ...]
    document_identity_files: tuple[DocumentIdentityFileBinding, ...]
    document_identity_count: int = Field(ge=0)
    document_identities_sha256: _SHA256
    authority_policy_path: _NON_EMPTY
    authority_policy_sha256: _SHA256

    @field_validator("case_files")
    @classmethod
    def unique_case_file_paths(
        cls,
        value: tuple[CaseFileBinding, ...],
    ) -> tuple[CaseFileBinding, ...]:
        paths = [item.path for item in value]
        if not value or len(paths) != len(set(paths)) or paths != sorted(paths):
            raise ValueError("case-file bindings must have unique sorted paths")
        return value

    @field_validator("source_manifests")
    @classmethod
    def unique_source_manifest_paths(
        cls,
        value: tuple[SourceManifestBinding, ...],
    ) -> tuple[SourceManifestBinding, ...]:
        paths = [item.path for item in value]
        if not value or len(paths) != len(set(paths)) or paths != sorted(paths):
            raise ValueError("source-manifest bindings must have unique sorted paths")
        return value

    @field_validator("document_identity_files")
    @classmethod
    def unique_document_identity_paths(
        cls,
        value: tuple[DocumentIdentityFileBinding, ...],
    ) -> tuple[DocumentIdentityFileBinding, ...]:
        paths = [item.path for item in value]
        if len(paths) != len(set(paths)) or paths != sorted(paths):
            raise ValueError("document-identity bindings must have unique sorted paths")
        return value

    @model_validator(mode="after")
    def consistent_record_counts(self) -> DatasetCandidateManifest:
        if self.case_record_count != sum(item.case_count for item in self.case_files):
            raise ValueError("candidate case count is inconsistent")
        if self.document_identity_count != sum(
            item.record_count for item in self.document_identity_files
        ):
            raise ValueError("candidate document identity count is inconsistent")
        return self

    def canonical_json(self) -> str:
        """Serialize the candidate binding deterministically."""

        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )

    def sha256(self) -> str:
        """Hash the complete candidate binding."""

        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class DatasetAuditFinding(BaseModel):
    """One fail-closed structural or scientific-readiness finding."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    code: _NON_EMPTY
    severity: Literal["blocker", "limitation"]
    case_ids: tuple[str, ...]
    detail: _NON_EMPTY


class DatasetIntegrityAudit(BaseModel):
    """Dataset-wide split and pair integrity result."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    audit_version: Literal["dataset-audit-v1"]
    case_count: int = Field(ge=0)
    dev_case_count: int = Field(ge=0)
    validation_case_count: int = Field(ge=0)
    holdout_case_count: int = Field(ge=0)
    document_identity_count: int = Field(ge=0)
    findings: tuple[DatasetAuditFinding, ...]

    @property
    def passed(self) -> bool:
        """Whether no structural blocker was found."""

        return not any(item.severity == "blocker" for item in self.findings)

    @property
    def split_case_counts(self) -> dict[str, int]:
        """Expose explicit denominators for reports and tests."""

        return {
            "dev": self.dev_case_count,
            "validation": self.validation_case_count,
            "holdout": self.holdout_case_count,
        }


class CalibrationEvidence(BaseModel):
    """Derived non-secret status of the human entailment-calibration gate."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["not_started", "structurally_unbound", "structurally_valid"]
    audit_version: Literal["human-calibration-audit-v1"] | None
    manifest_sha256: _SHA256 | None
    protocol_version: Literal["human-calibration-v1"] | None
    deterministic_grader_version: str | None
    authority_policy_version: str | None
    normalization_versions: tuple[str, ...] | None
    evidence_span_binding_status: Literal["not_started", "bound", "unbound"]
    double_annotated_judgments: int = Field(ge=0)
    raw_agreement: Decimal | None
    cohens_kappa: Decimal | None
    adjudication_status: Literal["not_started", "complete"]
    acceptance_threshold_status: Literal["not_declared"]


class DatasetCoverage(BaseModel):
    """Prospective pilot denominators from candidate case metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    split_case_counts: tuple[tuple[str, int], ...]
    real_case_count: int = Field(ge=0)
    synthetic_case_count: int = Field(ge=0)
    entity_family_count: int = Field(ge=0)
    case_family_count: int = Field(ge=0)
    paired_attack_case_count: int = Field(ge=0)
    bound_real_sources: tuple[str, ...]
    scored_real_sources: tuple[str, ...]
    predicates: tuple[str, ...]
    confirmatory_cells: tuple[str, ...]
    confirmatory_cells_by_split: tuple[tuple[str, tuple[str, ...]], ...]
    truth_modes: tuple[tuple[str, int], ...]
    attack_families: tuple[tuple[str, int], ...]
    abstention_cases: int = Field(ge=0)


class PilotReadinessReport(BaseModel):
    """Machine-readable provider-free entry audit for a future pilot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    report_version: Literal["pilot-readiness-v1"]
    status: Literal["not_ready"]
    candidate_manifest: DatasetCandidateManifest
    candidate_manifest_sha256: _SHA256
    integrity: DatasetIntegrityAudit
    coverage: DatasetCoverage
    calibration: CalibrationEvidence
    execution: PilotExecutionEvidence | None
    findings: tuple[DatasetAuditFinding, ...]


def _safe_file(root: Path, relative_path: Path) -> tuple[Path, bytes]:
    root = root.resolve(strict=True)
    relative = PurePosixPath(relative_path.as_posix())
    if relative.is_absolute() or ".." in relative.parts:
        raise DatasetReadinessError("manifest input path is not repository-relative")
    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise DatasetReadinessError(
            "manifest input is unavailable or escapes root"
        ) from exc
    current = candidate
    while current != root:
        is_junction = getattr(current, "is_junction", None)
        if current.is_symlink() or (callable(is_junction) and is_junction()):
            raise DatasetReadinessError("manifest input traverses a link") from None
        current = current.parent
    if not resolved.is_file():
        raise DatasetReadinessError("manifest input is not a regular file")
    return resolved, resolved.read_bytes()


def _load_case_bytes(body: bytes, path: str) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    for line_number, line in enumerate(body.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            cases.append(BenchmarkCase.model_validate_json(line))
        except ValueError as exc:
            raise DatasetReadinessError(
                f"invalid candidate case record in {path} line {line_number}"
            ) from exc
    if not cases:
        raise DatasetReadinessError("candidate case file is empty")
    return cases


def _load_source_manifest_bytes(
    body: bytes,
    path: str,
) -> list[SnapshotManifest]:
    manifests: list[SnapshotManifest] = []
    for line_number, line in enumerate(body.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            manifests.append(SnapshotManifest.model_validate_json(line))
        except ValueError as exc:
            raise DatasetReadinessError(
                f"invalid source manifest record in {path} line {line_number}"
            ) from exc
    if not manifests:
        raise DatasetReadinessError("candidate source manifest is empty")
    return manifests


def _load_document_identity_bytes(
    body: bytes,
    path: str,
) -> list[DatasetDocumentIdentity]:
    documents: list[DatasetDocumentIdentity] = []
    for line_number, line in enumerate(body.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            documents.append(DatasetDocumentIdentity.model_validate_json(line))
        except ValueError as exc:
            raise DatasetReadinessError(
                f"invalid document identity in {path} line {line_number}"
            ) from exc
    if not documents:
        raise DatasetReadinessError("candidate document identity file is empty")
    return documents


def _canonical_model_records_sha256[ModelT: BaseModel](
    records: Sequence[ModelT],
    *,
    identity: Callable[[ModelT], str],
) -> str:
    ordered = sorted(records, key=identity)
    body = json.dumps(
        [record.model_dump(mode="json") for record in ordered],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _source_bundle_sha256(manifest: DatasetCandidateManifest) -> str:
    payload = [
        binding.model_dump(mode="json")
        for binding in sorted(
            manifest.source_manifests,
            key=lambda binding: binding.path,
        )
    ]
    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def build_candidate_manifest(
    root: Path,
    *,
    dataset_version: str,
    case_paths: tuple[Path, ...],
    source_manifest_paths: tuple[Path, ...],
    authority_policy_path: Path,
    document_identity_paths: tuple[Path, ...] = (),
) -> tuple[
    DatasetCandidateManifest,
    list[BenchmarkCase],
    list[DatasetDocumentIdentity],
]:
    """Bind exact candidate case/config bytes and return validated cases."""

    if not dataset_version.strip() or not case_paths or not source_manifest_paths:
        raise DatasetReadinessError("candidate manifest identity is incomplete")
    normalized_paths = tuple(sorted(path.as_posix() for path in case_paths))
    if len(normalized_paths) != len(set(normalized_paths)):
        raise DatasetReadinessError("candidate case paths must be unique")
    all_cases: list[BenchmarkCase] = []
    bindings: list[CaseFileBinding] = []
    for path_text in normalized_paths:
        relative = Path(path_text)
        _resolved, body = _safe_file(root, relative)
        cases = _load_case_bytes(body, path_text)
        all_cases.extend(cases)
        bindings.append(
            CaseFileBinding(
                path=path_text,
                sha256=hashlib.sha256(body).hexdigest(),
                byte_length=len(body),
                case_count=len(cases),
                splits=tuple(sorted({case.split for case in cases})),
            )
        )
    normalized_source_paths = tuple(
        sorted(path.as_posix() for path in source_manifest_paths)
    )
    if len(normalized_source_paths) != len(set(normalized_source_paths)):
        raise DatasetReadinessError("candidate source manifest paths must be unique")
    source_manifests: list[SourceManifestBinding] = []
    all_snapshot_ids: set[str] = set()
    for path_text in normalized_source_paths:
        _source_path, source_body = _safe_file(root, Path(path_text))
        manifests = _load_source_manifest_bytes(source_body, path_text)
        snapshot_ids = tuple(sorted(item.snapshot_id for item in manifests))
        if len(snapshot_ids) != len(set(snapshot_ids)):
            raise DatasetReadinessError(
                "source manifest contains duplicate snapshot IDs"
            )
        duplicate_snapshot_ids = all_snapshot_ids & set(snapshot_ids)
        if duplicate_snapshot_ids:
            raise DatasetReadinessError(
                "snapshot IDs must be unique across source manifests"
            )
        all_snapshot_ids.update(snapshot_ids)
        source_manifests.append(
            SourceManifestBinding(
                path=path_text,
                sha256=hashlib.sha256(source_body).hexdigest(),
                byte_length=len(source_body),
                record_count=len(manifests),
                snapshot_ids=snapshot_ids,
                source_names=tuple(
                    sorted({str(item.source_name) for item in manifests})
                ),
                snapshot_sources=tuple(
                    sorted(
                        (item.snapshot_id, str(item.source_name)) for item in manifests
                    )
                ),
                snapshot_availability=tuple(
                    sorted(
                        (
                            item.snapshot_id,
                            item.available_by_utc,
                            item.available_by_basis,
                        )
                        for item in manifests
                    )
                ),
            )
        )
    normalized_document_paths = tuple(
        sorted(path.as_posix() for path in document_identity_paths)
    )
    if len(normalized_document_paths) != len(set(normalized_document_paths)):
        raise DatasetReadinessError("candidate document identity paths must be unique")
    all_documents: list[DatasetDocumentIdentity] = []
    document_identity_files: list[DocumentIdentityFileBinding] = []
    all_document_ids: set[str] = set()
    for path_text in normalized_document_paths:
        _document_path, document_body = _safe_file(root, Path(path_text))
        documents = _load_document_identity_bytes(document_body, path_text)
        document_ids = tuple(sorted(item.document_id for item in documents))
        if len(document_ids) != len(set(document_ids)):
            raise DatasetReadinessError("identity file contains duplicate document IDs")
        if all_document_ids & set(document_ids):
            raise DatasetReadinessError(
                "document IDs must be unique across identity files"
            )
        all_document_ids.update(document_ids)
        all_documents.extend(documents)
        document_identity_files.append(
            DocumentIdentityFileBinding(
                path=path_text,
                sha256=hashlib.sha256(document_body).hexdigest(),
                byte_length=len(document_body),
                record_count=len(documents),
                document_ids=document_ids,
            )
        )
    _authority_path, authority_body = _safe_file(root, authority_policy_path)
    manifest = DatasetCandidateManifest(
        dataset_version=dataset_version,
        audit_version=DATASET_AUDIT_VERSION,
        case_files=tuple(bindings),
        case_record_count=len(all_cases),
        case_records_sha256=_canonical_model_records_sha256(
            all_cases,
            identity=lambda item: str(item.case_id),
        ),
        source_manifests=tuple(source_manifests),
        document_identity_files=tuple(document_identity_files),
        document_identity_count=len(all_documents),
        document_identities_sha256=_canonical_model_records_sha256(
            all_documents,
            identity=lambda item: str(item.document_id),
        ),
        authority_policy_path=authority_policy_path.as_posix(),
        authority_policy_sha256=hashlib.sha256(authority_body).hexdigest(),
    )
    return manifest, all_cases, all_documents


def _finding(
    code: str,
    case_ids: Sequence[str],
    detail: str,
    *,
    severity: Literal["blocker", "limitation"] = "blocker",
) -> DatasetAuditFinding:
    return DatasetAuditFinding(
        code=code,
        severity=severity,
        case_ids=tuple(sorted(set(case_ids))),
        detail=detail,
    )


def _group_cross_split(
    cases: Sequence[BenchmarkCase],
    *,
    key: Callable[[BenchmarkCase], Hashable],
    code: str,
    detail: str,
) -> list[DatasetAuditFinding]:
    grouped: dict[Hashable, list[BenchmarkCase]] = defaultdict(list)
    for case in cases:
        grouped[key(case)].append(case)
    return [
        _finding(code, [case.case_id for case in matching], detail)
        for matching in grouped.values()
        if len({case.split for case in matching}) > 1
    ]


def _question_tokens(question: str) -> tuple[str, ...]:
    return tuple(_QUESTION_TOKEN.findall(question.casefold()))


def _evidence_document_ids(case: BenchmarkCase) -> set[str]:
    return {
        evidence_id.split(":", 1)[0]
        for claim in case.expected_claims
        for evidence_id in claim.evidence_ids
    }


def _claim_payloads(case: BenchmarkCase) -> list[dict[str, object]]:
    return [
        claim.model_dump(mode="python", exclude={"claim_id"})
        for claim in case.expected_claims
    ]


def _audit_pairs(
    cases: Sequence[BenchmarkCase],
    documents: Mapping[str, DatasetDocumentIdentity],
) -> list[DatasetAuditFinding]:
    findings: list[DatasetAuditFinding] = []
    by_id = {case.case_id: case for case in cases}
    visited: set[str] = set()
    for case in cases:
        if case.attack.family != "none" and case.paired_case_id is None:
            findings.append(
                _finding(
                    "attack_without_pair",
                    [case.case_id],
                    "Every adversarial case must identify its reciprocal clean pair.",
                )
            )
            continue
        if case.paired_case_id is None or case.case_id in visited:
            continue
        other = by_id.get(case.paired_case_id)
        if other is None or other.paired_case_id != case.case_id:
            findings.append(
                _finding(
                    "pair_not_reciprocal",
                    [case.case_id, case.paired_case_id],
                    "Paired case IDs must resolve reciprocally.",
                )
            )
            continue
        visited.update({case.case_id, other.case_id})
        pair_ids = [case.case_id, other.case_id]
        if case.split != other.split:
            findings.append(
                _finding(
                    "pair_cross_split",
                    pair_ids,
                    "Clean and adversarial forms must remain in the same split.",
                )
            )
        clean_candidates = [
            item for item in (case, other) if item.attack.family == "none"
        ]
        attacked_candidates = [
            item for item in (case, other) if item.attack.family != "none"
        ]
        if len(clean_candidates) != 1 or len(attacked_candidates) != 1:
            findings.append(
                _finding(
                    "pair_attack_shape_invalid",
                    pair_ids,
                    "A pair must contain exactly one clean and one treated case.",
                )
            )
            continue
        clean = clean_candidates[0]
        attacked = attacked_candidates[0]
        stable_equal = (
            clean.case_family_id == attacked.case_family_id
            and clean.entity_family_id == attacked.entity_family_id
            and clean.template_family_id == attacked.template_family_id
            and clean.as_of == attacked.as_of
            and clean.temporal_truth_mode == attacked.temporal_truth_mode
            and clean.question == attacked.question
            and clean.required_authority_policy_ids
            == attacked.required_authority_policy_ids
            and clean.should_abstain == attacked.should_abstain
            and clean.abstention_reason == attacked.abstention_reason
        )
        if not stable_equal:
            findings.append(
                _finding(
                    "pair_metadata_mismatch",
                    pair_ids,
                    "Paired cases change metadata outside the declared treatment.",
                )
            )
        if _claim_payloads(clean) != _claim_payloads(attacked):
            findings.append(
                _finding(
                    "pair_claim_mismatch",
                    pair_ids,
                    "Paired cases must retain identical expected material claims.",
                )
            )
        treatment_snapshots = {
            documents[document_id].snapshot_id
            for document_id in attacked.attack.treatment_document_ids
            if document_id in documents
        }
        treatment_metadata_complete = len(treatment_snapshots) == len(
            attacked.attack.treatment_document_ids
        )
        added = set(attacked.allowed_snapshot_ids) - set(clean.allowed_snapshot_ids)
        removed = set(clean.allowed_snapshot_ids) - set(attacked.allowed_snapshot_ids)
        if not treatment_metadata_complete:
            findings.append(
                _finding(
                    "pair_treatment_metadata_missing",
                    pair_ids,
                    (
                        "Declared treatment documents lack the identities needed "
                        "to verify the paired corpus delta."
                    ),
                )
            )
        elif added != treatment_snapshots or removed:
            findings.append(
                _finding(
                    "pair_treatment_delta_invalid",
                    pair_ids,
                    (
                        "The corpus delta must equal only the declared "
                        "treatment snapshots."
                    ),
                )
            )
    return findings


def audit_dataset_integrity(
    cases: Sequence[BenchmarkCase],
    *,
    documents: Sequence[DatasetDocumentIdentity] = (),
) -> DatasetIntegrityAudit:
    """Audit cross-split isolation and reciprocal treatment-pair structure."""

    findings: list[DatasetAuditFinding] = []
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        findings.append(
            _finding(
                "duplicate_case_id",
                case_ids,
                "Case IDs must be globally unique.",
            )
        )
    document_by_id = {document.document_id: document for document in documents}
    if len(document_by_id) != len(documents):
        findings.append(
            _finding(
                "duplicate_document_id",
                (),
                "Document identities must be globally unique.",
            )
        )

    group_specs = (
        (
            lambda item: item.entity_family_id,
            "entity_family_cross_split",
            "Entity/advisory lineages cannot cross splits.",
        ),
        (
            lambda item: item.case_family_id,
            "case_family_cross_split",
            "Case families cannot cross splits.",
        ),
        (
            lambda item: item.template_family_id,
            "template_family_cross_split",
            "Question-template families cannot cross splits.",
        ),
    )
    for key, code, detail in group_specs:
        findings.extend(_group_cross_split(cases, key=key, code=code, detail=detail))

    subject_cases: dict[tuple[str, str], list[BenchmarkCase]] = defaultdict(list)
    evidence_cases: dict[str, list[BenchmarkCase]] = defaultdict(list)
    snapshot_cases: dict[str, list[BenchmarkCase]] = defaultdict(list)
    referenced_documents: dict[str, list[BenchmarkCase]] = defaultdict(list)
    question_groups: dict[str, list[BenchmarkCase]] = defaultdict(list)
    for case in cases:
        for claim in case.expected_claims:
            subject_cases[(claim.subject.type, claim.subject.id)].append(case)
        for document_id in _evidence_document_ids(case):
            evidence_cases[document_id].append(case)
            referenced_documents[document_id].append(case)
        for document_id in case.attack.treatment_document_ids:
            referenced_documents[document_id].append(case)
        for snapshot_id in case.allowed_snapshot_ids:
            snapshot_cases[snapshot_id].append(case)
        question_groups[" ".join(_question_tokens(case.question))].append(case)
    for matching in subject_cases.values():
        if len({case.split for case in matching}) > 1:
            findings.append(
                _finding(
                    "claim_subject_cross_split",
                    [case.case_id for case in matching],
                    "A scored subject identity cannot cross splits.",
                )
            )
    for matching in evidence_cases.values():
        if len({case.split for case in matching}) > 1:
            findings.append(
                _finding(
                    "evidence_document_cross_split",
                    [case.case_id for case in matching],
                    "A gold evidence document cannot cross splits.",
                )
            )
    for matching in snapshot_cases.values():
        if len({case.split for case in matching}) > 1:
            findings.append(
                _finding(
                    "allowed_snapshot_cross_split",
                    [case.case_id for case in matching],
                    "An exact allowed source snapshot cannot cross splits.",
                )
            )
    for matching in question_groups.values():
        if len({case.split for case in matching}) > 1:
            findings.append(
                _finding(
                    "exact_question_cross_split",
                    [case.case_id for case in matching],
                    "Canonicalized exact question text cannot cross splits.",
                )
            )

    ordered = sorted(cases, key=lambda item: item.case_id)
    for left_index, left in enumerate(ordered):
        left_tokens = set(_question_tokens(left.question))
        for right in ordered[left_index + 1 :]:
            if left.split == right.split:
                continue
            right_tokens = set(_question_tokens(right.question))
            if not left_tokens or not right_tokens:
                continue
            if " ".join(_question_tokens(left.question)) == " ".join(
                _question_tokens(right.question)
            ):
                continue
            similarity = len(left_tokens & right_tokens) / len(
                left_tokens | right_tokens
            )
            if similarity >= NEAR_DUPLICATE_JACCARD_THRESHOLD:
                findings.append(
                    _finding(
                        "near_duplicate_question_cross_split",
                        [left.case_id, right.case_id],
                        (
                            "Cross-split question-token Jaccard similarity "
                            f"{similarity:.3f} meets the frozen "
                            f"{NEAR_DUPLICATE_JACCARD_THRESHOLD:.2f} threshold."
                        ),
                    )
                )

    missing_document_cases = [
        case.case_id
        for document_id, matching in referenced_documents.items()
        if document_id not in document_by_id
        for case in matching
    ]
    if missing_document_cases:
        findings.append(
            _finding(
                "document_metadata_missing",
                missing_document_cases,
                "Referenced evidence/treatment documents lack audit identities.",
            )
        )

    for case in cases:
        allowed_snapshot_ids = set(case.allowed_snapshot_ids)
        for claim in case.expected_claims:
            resolved_evidence = [
                document_by_id[document_id]
                for document_id in (
                    evidence_id.split(":", 1)[0] for evidence_id in claim.evidence_ids
                )
                if document_id in document_by_id
            ]
            if any(
                document.snapshot_id not in allowed_snapshot_ids
                for document in resolved_evidence
            ):
                findings.append(
                    _finding(
                        "evidence_snapshot_not_allowed",
                        [case.case_id],
                        "Gold evidence resolves outside the case snapshot allowlist.",
                    )
                )
            expected_source = _SOURCE_BY_PREDICATE[claim.predicate]
            if resolved_evidence and not any(
                document.source_name == expected_source
                for document in resolved_evidence
            ):
                findings.append(
                    _finding(
                        "evidence_source_mismatch",
                        [case.case_id],
                        (
                            f"Predicate {claim.predicate} lacks evidence from "
                            f"required source {expected_source}."
                        ),
                    )
                )
            if any(
                document.available_by_utc > case.as_of for document in resolved_evidence
            ):
                findings.append(
                    _finding(
                        "evidence_document_post_cutoff",
                        [case.case_id],
                        "Gold evidence document is unavailable at the case cutoff.",
                    )
                )
        resolved_treatments = [
            document_by_id[document_id]
            for document_id in case.attack.treatment_document_ids
            if document_id in document_by_id
        ]
        if any(
            document.snapshot_id not in allowed_snapshot_ids
            for document in resolved_treatments
        ):
            findings.append(
                _finding(
                    "treatment_snapshot_not_allowed",
                    [case.case_id],
                    "Declared treatment resolves outside the case snapshot allowlist.",
                )
            )
        if any(
            document.available_by_utc > case.as_of for document in resolved_treatments
        ):
            findings.append(
                _finding(
                    "treatment_document_post_cutoff",
                    [case.case_id],
                    "Declared treatment document is unavailable at the case cutoff.",
                )
            )

    for attribute, code, detail in (
        (
            "upstream_entity_id",
            "document_entity_cross_split",
            "Document upstream entity identities cannot cross splits.",
        ),
        (
            "canonical_url",
            "canonical_url_cross_split",
            "Canonical document URLs cannot cross splits.",
        ),
        (
            "normalized_text_sha256",
            "normalized_content_cross_split",
            "Normalized document bytes cannot cross splits.",
        ),
    ):
        grouped: dict[str, list[BenchmarkCase]] = defaultdict(list)
        for document_id, matching in referenced_documents.items():
            document = document_by_id.get(document_id)
            if document is not None:
                grouped[str(getattr(document, attribute))].extend(matching)
        for matching in grouped.values():
            if len({case.split for case in matching}) > 1:
                findings.append(
                    _finding(
                        code,
                        [case.case_id for case in matching],
                        detail,
                    )
                )
    findings.extend(_audit_pairs(cases, document_by_id))
    findings = sorted(
        findings,
        key=lambda item: (item.severity, item.code, item.case_ids),
    )
    return DatasetIntegrityAudit(
        audit_version=DATASET_AUDIT_VERSION,
        case_count=len(cases),
        dev_case_count=sum(case.split == "dev" for case in cases),
        validation_case_count=sum(case.split == "validation" for case in cases),
        holdout_case_count=sum(case.split == "holdout" for case in cases),
        document_identity_count=len(documents),
        findings=tuple(findings),
    )


def _coverage(
    cases: Sequence[BenchmarkCase],
    *,
    documents: Sequence[DatasetDocumentIdentity],
    manifest: DatasetCandidateManifest,
) -> DatasetCoverage:
    real_cases = [
        case for case in cases if case.temporal_truth_mode != "synthetic_control"
    ]
    document_by_id = {document.document_id: document for document in documents}
    predicates = {
        claim.predicate for case in real_cases for claim in case.expected_claims
    }
    bound_sources = {
        source
        for binding in manifest.source_manifests
        for source in binding.source_names
        if source != "synthetic_control"
    }
    scored_sources: set[str] = set()
    cells: set[tuple[str, str]] = set()
    cells_by_split: dict[str, set[str]] = {
        "dev": set(),
        "validation": set(),
        "holdout": set(),
    }
    for case in real_cases:
        for claim in case.expected_claims:
            evidence_documents = [
                document_by_id[document_id]
                for document_id in (
                    evidence_id.split(":", 1)[0] for evidence_id in claim.evidence_ids
                )
                if document_id in document_by_id
            ]
            scored_sources.update(
                document.source_name
                for document in evidence_documents
                if document.source_name != "synthetic_control"
            )
            candidate_cell = (
                str(claim.qualifiers.authority),
                claim.predicate,
            )
            required_source = _SOURCE_BY_PREDICATE[claim.predicate]
            if candidate_cell in _CONFIRMATORY_CELLS and any(
                document.source_name == required_source
                and document.snapshot_id in case.allowed_snapshot_ids
                and document.available_by_utc <= case.as_of
                for document in evidence_documents
            ):
                cells.add(candidate_cell)
                cells_by_split[case.split].add(
                    f"{candidate_cell[0]}:{candidate_cell[1]}"
                )
    truth_modes: dict[str, int] = defaultdict(int)
    attack_families: dict[str, int] = defaultdict(int)
    split_counts: dict[str, int] = {"dev": 0, "validation": 0, "holdout": 0}
    for case in cases:
        truth_modes[case.temporal_truth_mode] += 1
        attack_families[case.attack.family] += 1
        split_counts[case.split] += 1
    return DatasetCoverage(
        split_case_counts=tuple(sorted(split_counts.items())),
        real_case_count=len(real_cases),
        synthetic_case_count=len(cases) - len(real_cases),
        entity_family_count=len({case.entity_family_id for case in real_cases}),
        case_family_count=len({case.case_family_id for case in real_cases}),
        paired_attack_case_count=sum(
            case.attack.family != "none" and case.paired_case_id is not None
            for case in real_cases
        ),
        bound_real_sources=tuple(sorted(bound_sources)),
        scored_real_sources=tuple(sorted(scored_sources)),
        predicates=tuple(sorted(predicates)),
        confirmatory_cells=tuple(
            sorted(f"{source}:{predicate}" for source, predicate in cells)
        ),
        confirmatory_cells_by_split=tuple(
            (split, tuple(sorted(split_cells)))
            for split, split_cells in sorted(cells_by_split.items())
        ),
        truth_modes=tuple(sorted(truth_modes.items())),
        attack_families=tuple(sorted(attack_families.items())),
        abstention_cases=sum(case.should_abstain for case in cases),
    )


def _has_observed_real_change(
    cases: Sequence[BenchmarkCase],
    documents: Sequence[DatasetDocumentIdentity],
) -> bool:
    document_by_id = {document.document_id: document for document in documents}
    grouped: dict[tuple[str, str], list[BenchmarkCase]] = defaultdict(list)
    for case in cases:
        if (
            case.temporal_truth_mode != "synthetic_control"
            and case.attack.family == "none"
            and not case.should_abstain
        ):
            grouped[(case.entity_family_id, case.template_family_id)].append(case)
    accepted_evidence = {
        "observed_retrieval",
        "upstream_version",
        "signed_release",
    }
    for matching in grouped.values():
        ordered = sorted(matching, key=lambda item: (item.as_of, item.case_id))
        for left_index, left in enumerate(ordered):
            left_documents = [
                document_by_id[document_id]
                for document_id in _evidence_document_ids(left)
                if document_id in document_by_id
            ]
            for right in ordered[left_index + 1 :]:
                if left.as_of >= right.as_of:
                    continue
                right_documents = [
                    document_by_id[document_id]
                    for document_id in _evidence_document_ids(right)
                    if document_id in document_by_id
                ]
                for left_document in left_documents:
                    for right_document in right_documents:
                        if (
                            left_document.source_name == right_document.source_name
                            and left_document.upstream_entity_id
                            == right_document.upstream_entity_id
                            and left_document.snapshot_id != right_document.snapshot_id
                            and left_document.normalized_text_sha256
                            != right_document.normalized_text_sha256
                            and left_document.availability_evidence in accepted_evidence
                            and right_document.availability_evidence
                            in accepted_evidence
                            and left_document.available_by_utc
                            < right_document.available_by_utc
                            and left_document.available_by_utc <= left.as_of
                            and right_document.available_by_utc <= right.as_of
                            and left_document.snapshot_id in left.allowed_snapshot_ids
                            and right_document.snapshot_id in right.allowed_snapshot_ids
                        ):
                            return True
    return False


def _phase7_selection_counts(
    cases_by_id: Mapping[str, BenchmarkCase],
    selected_ids: set[str],
) -> tuple[int, int]:
    selected_attacked_pairs = sum(
        1
        for case_id in selected_ids
        if cases_by_id[case_id].attack.family != "none"
        and cases_by_id[case_id].paired_case_id in selected_ids
    )
    selected_base_cases = sum(
        1 for case_id in selected_ids if cases_by_id[case_id].attack.family == "none"
    )
    return selected_attacked_pairs, selected_base_cases


def build_pilot_readiness_report(
    *,
    manifest: DatasetCandidateManifest | None,
    cases: Sequence[BenchmarkCase],
    documents: Sequence[DatasetDocumentIdentity],
    project_root: Path,
    calibration_manifest: CalibrationManifest | None = None,
    execution_plan: PilotExecutionPlan | None = None,
    execution_schedule: Sequence[PilotScheduleSlot] | None = None,
) -> PilotReadinessReport:
    """Combine structural audit and frozen Phase 3-7 pilot-entry evidence."""

    if manifest is None:
        raise DatasetReadinessError("candidate manifest is required")
    project_root.resolve(strict=True)
    integrity = audit_dataset_integrity(cases, documents=documents)
    coverage = _coverage(cases, documents=documents, manifest=manifest)
    findings = list(integrity.findings)
    case_binding_hash = _canonical_model_records_sha256(
        cases,
        identity=lambda item: str(item.case_id),
    )
    if (
        manifest.case_record_count != len(cases)
        or manifest.case_records_sha256 != case_binding_hash
    ):
        findings.append(
            _finding(
                "candidate_case_binding_mismatch",
                [case.case_id for case in cases],
                "Supplied cases do not match the candidate manifest binding.",
            )
        )
    document_binding_hash = _canonical_model_records_sha256(
        documents,
        identity=lambda item: str(item.document_id),
    )
    if (
        manifest.document_identity_count != len(documents)
        or manifest.document_identities_sha256 != document_binding_hash
    ):
        findings.append(
            _finding(
                "document_identity_binding_mismatch",
                (),
                (
                    "Supplied document identities do not match the candidate "
                    "manifest binding."
                ),
            )
        )
    bound_snapshot_ids = {
        snapshot_id
        for binding in manifest.source_manifests
        for snapshot_id in binding.snapshot_ids
    }
    unbound_snapshot_cases = [
        case.case_id
        for case in cases
        if not set(case.allowed_snapshot_ids) <= bound_snapshot_ids
    ]
    if unbound_snapshot_cases:
        findings.append(
            _finding(
                "allowed_snapshot_unbound",
                unbound_snapshot_cases,
                "Case allowlists reference snapshots outside the bound manifests.",
            )
        )
    source_by_snapshot = {
        snapshot_id: source_name
        for binding in manifest.source_manifests
        for snapshot_id, source_name in binding.snapshot_sources
    }
    availability_by_snapshot = {
        snapshot_id: (available_by_utc, available_by_basis)
        for binding in manifest.source_manifests
        for snapshot_id, available_by_utc, available_by_basis in (
            binding.snapshot_availability
        )
    }
    mismatched_document_ids = [
        document.document_id
        for document in documents
        if source_by_snapshot.get(document.snapshot_id) != document.source_name
    ]
    if mismatched_document_ids:
        findings.append(
            _finding(
                "document_snapshot_source_mismatch",
                (),
                (
                    "Document identities do not match the bound source for "
                    "their snapshot: " + ", ".join(sorted(mismatched_document_ids))
                ),
            )
        )
    mismatched_document_availability = []
    for document in documents:
        bound_availability = availability_by_snapshot.get(document.snapshot_id)
        if bound_availability is None:
            mismatched_document_availability.append(document.document_id)
            continue
        available_by_utc, available_by_basis = bound_availability
        if (
            document.available_by_utc != available_by_utc
            or document.availability_evidence
            != _DOCUMENT_EVIDENCE_BY_MANIFEST_BASIS[available_by_basis]
        ):
            mismatched_document_availability.append(document.document_id)
    if mismatched_document_availability:
        findings.append(
            _finding(
                "document_snapshot_availability_mismatch",
                (),
                (
                    "Document cutoff metadata does not match its bound snapshot "
                    "manifest: " + ", ".join(sorted(mismatched_document_availability))
                ),
            )
        )
    split_counts = dict(coverage.split_case_counts)
    if split_counts["dev"] == 0:
        findings.append(
            _finding("development_split_missing", (), "Development split is empty.")
        )
    if split_counts["validation"] == 0:
        findings.append(
            _finding("validation_split_missing", (), "Validation split is empty.")
        )
    required_sources = {source for source, _predicate in _CONFIRMATORY_CELLS}
    missing_bound_sources = sorted(required_sources - set(coverage.bound_real_sources))
    if missing_bound_sources:
        findings.append(
            _finding(
                "bound_source_missing",
                (),
                "Missing bound source manifests: " + ", ".join(missing_bound_sources),
            )
        )
    missing_sources = sorted(required_sources - set(coverage.scored_real_sources))
    if missing_sources:
        findings.append(
            _finding(
                "confirmatory_source_missing",
                (),
                "Missing real confirmatory sources: " + ", ".join(missing_sources),
            )
        )
    required_predicates = {predicate for _source, predicate in _CONFIRMATORY_CELLS}
    missing_predicates = sorted(required_predicates - set(coverage.predicates))
    if missing_predicates:
        findings.append(
            _finding(
                "confirmatory_predicate_missing",
                (),
                "Missing real confirmatory predicates: "
                + ", ".join(missing_predicates),
            )
        )
    missing_cells = sorted(
        f"{source}:{predicate}"
        for source, predicate in _CONFIRMATORY_CELLS
        if f"{source}:{predicate}" not in coverage.confirmatory_cells
    )
    if missing_cells:
        findings.append(
            _finding(
                "confirmatory_cell_missing",
                (),
                "Missing authority/predicate cells: " + ", ".join(missing_cells),
            )
        )
    split_cells = dict(coverage.confirmatory_cells_by_split)
    required_cell_names = {
        f"{source}:{predicate}" for source, predicate in _CONFIRMATORY_CELLS
    }
    for split in ("dev", "validation"):
        missing_split_cells = sorted(
            required_cell_names - set(split_cells.get(split, ()))
        )
        if missing_split_cells:
            findings.append(
                _finding(
                    "confirmatory_cell_missing_by_split",
                    (),
                    (
                        f"{split} is missing authority/predicate cells: "
                        + ", ".join(missing_split_cells)
                    ),
                )
            )
    if coverage.entity_family_count <= 1:
        findings.append(
            _finding(
                "single_entity_corpus",
                [case.case_id for case in cases],
                "A one-entity corpus cannot support a broader pilot.",
            )
        )
    if coverage.paired_attack_case_count < 40:
        findings.append(
            _finding(
                "paired_attack_minimum_unmet",
                (),
                (
                    "Phase 7 requires at least 40 paired attack cases; "
                    f"candidate has {coverage.paired_attack_case_count}."
                ),
            )
        )
    if not _has_observed_real_change(cases, documents):
        findings.append(
            _finding(
                "observed_change_case_missing",
                (),
                "No clean real entity/template family contains distinct source states.",
            )
        )
    if calibration_manifest is None:
        calibration_audit = None
        calibration = CalibrationEvidence(
            status="not_started",
            audit_version=None,
            manifest_sha256=None,
            protocol_version=None,
            deterministic_grader_version=None,
            authority_policy_version=None,
            normalization_versions=None,
            evidence_span_binding_status="not_started",
            double_annotated_judgments=0,
            raw_agreement=None,
            cohens_kappa=None,
            adjudication_status="not_started",
            acceptance_threshold_status="not_declared",
        )
    else:
        _grade_schema_path, grade_schema_body = _safe_file(
            project_root,
            Path("schemas/claim-grade.schema.json"),
        )
        try:
            calibration_audit = audit_human_calibration(
                project_root,
                calibration_manifest,
                expected_candidate_manifest_sha256=manifest.sha256(),
                expected_source_bundle_sha256=_source_bundle_sha256(manifest),
                expected_grade_schema_sha256=hashlib.sha256(
                    grade_schema_body
                ).hexdigest(),
            )
        except HumanAuditError as exc:
            raise DatasetReadinessError(
                "human calibration artifact validation failed"
            ) from exc
        calibration_cases = {str(case.case_id): case for case in cases}
        context_by_item = {
            context.item_id: context for context in calibration_audit.reviewer_contexts
        }
        for item in calibration_audit.items:
            case = calibration_cases.get(item.case_id)
            if case is None or case.split != item.split:
                raise DatasetReadinessError(
                    "human calibration item does not match its candidate case split"
                )
            matching_claims = [
                claim
                for claim in case.expected_claims
                if str(claim.predicate) == item.predicate
                and item.evidence_id in claim.evidence_ids
            ]
            if not matching_claims:
                raise DatasetReadinessError(
                    "human calibration item is not bound to candidate gold evidence"
                )
            expected_source = _SOURCE_BY_PREDICATE.get(matching_claims[0].predicate)
            if item.source_name != expected_source:
                raise DatasetReadinessError(
                    "human calibration item source does not match its predicate"
                )
            if context_by_item[item.item_id].question != case.question:
                raise DatasetReadinessError(
                    "human calibration context question differs from the candidate"
                )
        calibration = CalibrationEvidence(
            status=(
                "structurally_valid"
                if calibration_audit.structural_gate_complete
                else "structurally_unbound"
            ),
            audit_version=calibration_audit.audit_version,
            manifest_sha256=calibration_audit.manifest_sha256,
            protocol_version=calibration_audit.protocol_version,
            deterministic_grader_version=(
                calibration_audit.deterministic_grader_version
            ),
            authority_policy_version=calibration_audit.authority_policy_version,
            normalization_versions=calibration_audit.normalization_versions,
            evidence_span_binding_status=(
                calibration_audit.evidence_span_binding_status
            ),
            double_annotated_judgments=calibration_audit.item_count,
            raw_agreement=calibration_audit.raw_agreement,
            cohens_kappa=calibration_audit.cohens_kappa,
            adjudication_status=(
                "complete"
                if calibration_audit.adjudication_count
                == calibration_audit.disagreement_count
                else "not_started"
            ),
            acceptance_threshold_status=(calibration_audit.acceptance_threshold_status),
        )
        if calibration_audit.evidence_span_binding_status == "unbound":
            findings.append(
                _finding(
                    "calibration_evidence_span_provenance_unbound",
                    (),
                    (
                        "Reviewer-visible evidence text is not independently "
                        "bound to candidate evidence-span hashes."
                    ),
                )
            )
    if calibration.protocol_version is None:
        findings.append(
            _finding(
                "annotation_protocol_missing",
                (),
                "A versioned blinded annotation protocol is required.",
            )
        )
    if calibration.double_annotated_judgments < 50:
        findings.append(
            _finding(
                "double_annotation_minimum_unmet",
                (),
                (
                    "Phase 6 requires 50 double-annotated entailment judgments; "
                    f"candidate records {calibration.double_annotated_judgments}."
                ),
            )
        )
    if calibration.cohens_kappa is None:
        findings.append(
            _finding(
                "agreement_statistic_missing",
                (),
                "Human-review agreement has not been calculated.",
            )
        )
    if calibration.adjudication_status == "not_started":
        findings.append(
            _finding(
                "adjudication_incomplete",
                (),
                "Blinded disagreement adjudication is not complete.",
            )
        )
    if (execution_plan is None) != (execution_schedule is None):
        raise DatasetReadinessError(
            "pilot execution plan and schedule must be supplied together"
        )
    execution_evidence = None
    if execution_plan is None or execution_schedule is None:
        findings.append(
            _finding(
                "pilot_schedule_budget_unfrozen",
                (),
                (
                    "Exact case forms, schedule hashes, retries, and cost "
                    "ceiling are not frozen."
                ),
            )
        )
    else:
        if execution_plan.candidate_manifest_sha256 != manifest.sha256():
            raise DatasetReadinessError(
                "pilot execution plan is not bound to the candidate manifest"
            )
        cases_by_id = {str(case.case_id): case for case in cases}
        selected_ids = set(execution_plan.case_form_ids)
        if not selected_ids <= set(cases_by_id):
            raise DatasetReadinessError(
                "pilot execution plan selects a case outside the candidate"
            )
        if any(cases_by_id[case_id].split == "holdout" for case_id in selected_ids):
            raise DatasetReadinessError("pilot execution plan selects a holdout case")
        incomplete_pairs = [
            case.case_id
            for case_id in selected_ids
            if (case := cases_by_id[case_id]).paired_case_id is not None
            and case.paired_case_id not in selected_ids
        ]
        if incomplete_pairs:
            raise DatasetReadinessError(
                "pilot execution plan selects an incomplete reciprocal pair"
            )
        selected_attacked_pairs, selected_base_cases = _phase7_selection_counts(
            cases_by_id,
            selected_ids,
        )
        if (
            execution_plan.conditions != PHASE7_CONDITIONS
            or execution_plan.repetitions != PHASE7_REPETITIONS
            or selected_attacked_pairs < PHASE7_MINIMUM_ATTACKED_PAIRS
            or selected_base_cases > PHASE7_MAXIMUM_BASE_CASES
        ):
            findings.append(
                _finding(
                    "pilot_schedule_phase7_design_noncompliant",
                    tuple(sorted(selected_ids)),
                    (
                        "A Phase 7 schedule requires the three frozen "
                        "conditions, three repetitions, and at least 40 "
                        "selected attacked cases with complete clean pairs, "
                        "with no more than 100 clean/base cases; this plan "
                        f"selects {selected_attacked_pairs} attacked and "
                        f"{selected_base_cases} clean/base cases."
                    ),
                )
            )
        try:
            execution_evidence = build_pilot_execution_evidence(
                execution_plan,
                execution_schedule,
            )
        except PilotScheduleError as exc:
            raise DatasetReadinessError("pilot schedule validation failed") from exc
        findings.append(
            _finding(
                "pilot_pricing_currentness_unverified",
                (),
                (
                    "Frozen local rates validate arithmetic only; official "
                    "pricing must be reverified before approval."
                ),
            )
        )
        if not execution_evidence.phase7_budget_compliant:
            findings.append(
                _finding(
                    "phase7_budget_cap_exceeded",
                    (),
                    (
                        "The validated retry-inclusive hard cap exceeds the "
                        "frozen Phase 7 $6 ceiling."
                    ),
                )
            )
    if calibration_audit is not None and execution_plan is not None:
        calibrated_versions = (
            calibration_audit.deterministic_grader_version,
            calibration_audit.authority_policy_version,
            calibration_audit.normalization_versions,
        )
        planned_versions = (
            execution_plan.grader_version,
            execution_plan.authority_policy_version,
            execution_plan.normalization_versions,
        )
        if calibrated_versions != planned_versions:
            raise DatasetReadinessError(
                "pilot execution versions differ from calibrated grade versions"
            )
    if calibration.acceptance_threshold_status == "not_declared":
        findings.append(
            _finding(
                "calibration_acceptance_threshold_undeclared",
                (),
                (
                    "Agreement can be calculated, but an acceptable threshold "
                    "or excluded-stratum policy has not been preregistered."
                ),
            )
        )
    findings.append(
        _finding(
            "positive_readiness_gate_unimplemented",
            (),
            (
                "Positive readiness is fail-closed until calibration evidence-"
                "span binding and acceptance policy, per-split strata, and "
                "pricing-currentness evidence have dedicated validators."
            ),
        )
    )
    findings = sorted(
        findings,
        key=lambda item: (item.severity, item.code, item.case_ids),
    )
    return PilotReadinessReport(
        report_version="pilot-readiness-v1",
        status="not_ready",
        candidate_manifest=manifest,
        candidate_manifest_sha256=manifest.sha256(),
        integrity=integrity,
        coverage=coverage,
        calibration=calibration,
        execution=execution_evidence,
        findings=tuple(findings),
    )
