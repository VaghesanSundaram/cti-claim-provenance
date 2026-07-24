"""Fail-closed orchestration for the five-resource Phase 2 capture."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from cti_provenance.ingest.base import (
    AttemptEvidence,
    CapturedResponse,
    CaptureError,
    FetchSpec,
    SourceStateEvidenceRecord,
    fetch_https,
    request_fingerprint,
    validate_attempt_sequence,
    validate_fetch_spec,
)
from cti_provenance.ingest.kev import (
    KEV_COMPARE_FETCH_SPEC,
    KEV_FETCH_SPEC,
    parse_kev_bytes,
    parse_kev_lineage_bytes,
)
from cti_provenance.ingest.nvd import NVD_FETCH_SPEC, parse_nvd_bytes
from cti_provenance.ingest.vendor import (
    RHSA_CHECKSUM_FETCH_SPEC,
    RHSA_FETCH_SPEC,
    RedHatAdvisoryValidationError,
    parse_red_hat_bytes,
    parse_red_hat_checksum,
)

type Phase2ResourceId = Literal[
    "nvd_primary",
    "kev_catalog",
    "kev_lineage",
    "red_hat_primary",
    "red_hat_checksum",
]
type EvidenceSourceName = Literal["nvd", "cisa_kev", "red_hat_rhsa"]
type ArtifactRole = Literal[
    "primary_body",
    "commit_lineage",
    "published_checksum",
]
type FailureStage = Literal[
    "transport",
    "http",
    "redirect",
    "response",
    "validation",
]
type FailureCode = Literal[
    "transport_exhausted",
    "http_429_exhausted",
    "http_5xx_exhausted",
    "http_other",
    "redirect_rejected",
    "response_rejected",
    "nvd_validation",
    "kev_catalog_validation",
    "kev_lineage_validation",
    "red_hat_checksum_validation",
    "red_hat_advisory_validation",
    "red_hat_json_validation",
    "red_hat_csaf_identity_validation",
    "red_hat_revision_metadata_validation",
    "red_hat_revision_history_validation",
    "red_hat_selected_cve_validation",
]
_DETAILED_RED_HAT_FAILURE_CODES = frozenset(
    {
        "red_hat_json_validation",
        "red_hat_csaf_identity_validation",
        "red_hat_revision_metadata_validation",
        "red_hat_revision_history_validation",
        "red_hat_selected_cve_validation",
    }
)

_SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_NON_EMPTY = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


@dataclass(frozen=True)
class CaptureResourceDefinition:
    """One immutable member of the frozen capture plan."""

    resource_id: Phase2ResourceId
    spec: FetchSpec


PHASE2_CAPTURE_RESOURCES = (
    CaptureResourceDefinition("nvd_primary", NVD_FETCH_SPEC),
    CaptureResourceDefinition("kev_catalog", KEV_FETCH_SPEC),
    CaptureResourceDefinition("kev_lineage", KEV_COMPARE_FETCH_SPEC),
    CaptureResourceDefinition("red_hat_primary", RHSA_FETCH_SPEC),
    CaptureResourceDefinition("red_hat_checksum", RHSA_CHECKSUM_FETCH_SPEC),
)
PHASE2_RESOURCE_IDS = tuple(
    resource.resource_id for resource in PHASE2_CAPTURE_RESOURCES
)
_RESOURCE_BY_ID = {
    resource.resource_id: resource for resource in PHASE2_CAPTURE_RESOURCES
}
_ARTIFACT_BINDINGS: dict[Phase2ResourceId, tuple[EvidenceSourceName, ArtifactRole]] = {
    "nvd_primary": ("nvd", "primary_body"),
    "kev_catalog": ("cisa_kev", "primary_body"),
    "kev_lineage": ("cisa_kev", "commit_lineage"),
    "red_hat_primary": ("red_hat_rhsa", "primary_body"),
    "red_hat_checksum": ("red_hat_rhsa", "published_checksum"),
}
_OUTCOME_FAILURE: dict[str, tuple[FailureStage, FailureCode]] = {
    "transport_error": ("transport", "transport_exhausted"),
    "http_429": ("http", "http_429_exhausted"),
    "http_5xx": ("http", "http_5xx_exhausted"),
    "http_other": ("http", "http_other"),
    "redirect": ("redirect", "redirect_rejected"),
    "response_rejected": ("response", "response_rejected"),
}
_FAILURE_STAGE_BY_CODE: dict[FailureCode, FailureStage] = {
    "transport_exhausted": "transport",
    "http_429_exhausted": "http",
    "http_5xx_exhausted": "http",
    "http_other": "http",
    "redirect_rejected": "redirect",
    "response_rejected": "response",
    "nvd_validation": "validation",
    "kev_catalog_validation": "validation",
    "kev_lineage_validation": "validation",
    "red_hat_checksum_validation": "validation",
    "red_hat_advisory_validation": "validation",
    "red_hat_json_validation": "validation",
    "red_hat_csaf_identity_validation": "validation",
    "red_hat_revision_metadata_validation": "validation",
    "red_hat_revision_history_validation": "validation",
    "red_hat_selected_cve_validation": "validation",
}
_VALIDATION_RESOURCE_BY_CODE: dict[FailureCode, Phase2ResourceId] = {
    "nvd_validation": "nvd_primary",
    "kev_catalog_validation": "kev_catalog",
    "kev_lineage_validation": "kev_lineage",
    "red_hat_checksum_validation": "red_hat_checksum",
    "red_hat_advisory_validation": "red_hat_checksum",
    "red_hat_json_validation": "red_hat_checksum",
    "red_hat_csaf_identity_validation": "red_hat_checksum",
    "red_hat_revision_metadata_validation": "red_hat_checksum",
    "red_hat_revision_history_validation": "red_hat_checksum",
    "red_hat_selected_cve_validation": "red_hat_checksum",
}
_VALIDATION_CODES = frozenset(
    {
        "nvd_validation",
        "kev_catalog_validation",
        "kev_lineage_validation",
        "red_hat_checksum_validation",
        "red_hat_advisory_validation",
        "red_hat_json_validation",
        "red_hat_csaf_identity_validation",
        "red_hat_revision_metadata_validation",
        "red_hat_revision_history_validation",
        "red_hat_selected_cve_validation",
    }
)
_VALIDATION_FAILURE_BY_RESOURCE: dict[Phase2ResourceId, FailureCode] = {
    "nvd_primary": "nvd_validation",
    "kev_catalog": "kev_catalog_validation",
    "kev_lineage": "kev_lineage_validation",
    "red_hat_checksum": "red_hat_advisory_validation",
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("capture session timestamps must use UTC")
    return value.astimezone(UTC)


def _attempts(response: CapturedResponse) -> list[AttemptEvidence]:
    return [
        AttemptEvidence(
            attempt_number=attempt.attempt_number,
            started_at_utc=attempt.started_at_utc,
            finished_at_utc=attempt.finished_at_utc,
            outcome=attempt.outcome,
            status=attempt.status,
            retry_delay_seconds=attempt.retry_delay_seconds,
        )
        for attempt in response.attempts
    ]


def _session_id(started_at_utc: datetime) -> str:
    payload = json.dumps(
        {
            "started_at_utc": _utc(started_at_utc).isoformat(),
            "resources": [
                {
                    "resource_id": resource.resource_id,
                    "request_fingerprint": request_fingerprint(resource.spec.url),
                }
                for resource in PHASE2_CAPTURE_RESOURCES
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"phase2-capture-{hashlib.sha256(payload).hexdigest()[:20]}"


class CaptureFailure(BaseModel):
    """Redacted terminal reason for one failed capture session."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    resource_id: Phase2ResourceId
    stage: FailureStage
    code: FailureCode

    @model_validator(mode="after")
    def validate_stage_code(self) -> Self:
        if self.stage != _FAILURE_STAGE_BY_CODE[self.code]:
            raise ValueError("capture failure stage and code are inconsistent")
        if (
            self.code in _VALIDATION_CODES
            and self.resource_id != _VALIDATION_RESOURCE_BY_CODE[self.code]
        ):
            raise ValueError(
                "capture validation failure code does not match its resource"
            )
        return self


class ResourceCaptureLedger(BaseModel):
    """Attempt-only evidence for one exact resource, including terminal failure."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    resource_id: Phase2ResourceId
    request_url: _NON_EMPTY
    request_fingerprint: _SHA256
    attempts: list[AttemptEvidence] = Field(min_length=1, max_length=2)
    transport_status: Literal["success", "failed"]
    response_sha256: _SHA256 | None
    response_byte_length: int | None = Field(default=None, gt=0)
    retrieved_at_utc: datetime | None

    @model_validator(mode="after")
    def validate_resource(self) -> Self:
        definition = _RESOURCE_BY_ID[self.resource_id]
        if (
            self.request_url != definition.spec.url
            or self.request_fingerprint != request_fingerprint(definition.spec.url)
        ):
            raise ValueError("resource ledger does not match the frozen request")
        validate_attempt_sequence(
            self.attempts,
            terminal_success=self.transport_status == "success",
            minimum_retry_delay_seconds=definition.spec.retry_delay_seconds,
        )
        response_fields = (
            self.response_sha256,
            self.response_byte_length,
            self.retrieved_at_utc,
        )
        if any(value is not None for value in response_fields) != all(
            value is not None for value in response_fields
        ):
            raise ValueError("response metadata must be entirely present or absent")
        has_response = all(value is not None for value in response_fields)
        if has_response != (self.transport_status == "success"):
            raise ValueError("only successful transport may bind response metadata")
        if self.retrieved_at_utc is not None:
            _utc(self.retrieved_at_utc)
            if self.retrieved_at_utc != self.attempts[-1].finished_at_utc:
                raise ValueError("retrieval time must equal the successful attempt")
        return self


class Phase2CaptureSessionEvidence(BaseModel):
    """Durable aggregate proof of the fixed five-resource request budget."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[
        "phase2-capture-session-v1",
        "phase2-capture-session-v2",
    ]
    capture_policy_version: Literal["phase2-capture-policy-v1"]
    session_id: _NON_EMPTY
    started_at_utc: datetime
    finished_at_utc: datetime
    status: Literal["complete", "failed"]
    resources: list[ResourceCaptureLedger] = Field(min_length=1, max_length=6)
    failure: CaptureFailure | None

    @model_validator(mode="after")
    def validate_session(self) -> Self:
        started = _utc(self.started_at_utc)
        finished = _utc(self.finished_at_utc)
        if finished < started:
            raise ValueError("capture session cannot finish before it starts")
        total_attempts = sum(len(resource.attempts) for resource in self.resources)
        if total_attempts > 10:
            raise ValueError("capture session exceeds the ten-attempt ceiling")
        resource_ids = [resource.resource_id for resource in self.resources]
        if resource_ids != list(PHASE2_RESOURCE_IDS[: len(resource_ids)]):
            raise ValueError(
                "capture resources must be a unique ordered prefix of the frozen plan"
            )
        if self.resources[0].attempts[0].started_at_utc != started:
            raise ValueError("session start must equal the first attempt start")
        if self.resources[-1].attempts[-1].finished_at_utc != finished:
            raise ValueError("session finish must equal the final attempt finish")
        if any(
            later.attempts[0].started_at_utc < earlier.attempts[-1].finished_at_utc
            for earlier, later in pairwise(self.resources)
        ):
            raise ValueError("capture resources overlap or run out of order")
        if self.session_id != _session_id(started):
            raise ValueError("capture session identity does not match its plan")
        if self.status == "complete":
            if (
                tuple(resource_ids) != PHASE2_RESOURCE_IDS
                or any(
                    resource.transport_status != "success"
                    for resource in self.resources
                )
                or self.failure is not None
            ):
                raise ValueError(
                    "complete capture requires all five successful resources"
                )
        elif (
            self.failure is None
            or self.failure.resource_id != resource_ids[-1]
            or any(
                resource.transport_status != "success"
                for resource in self.resources[:-1]
            )
            or (
                self.failure.stage == "validation"
                and self.resources[-1].transport_status != "success"
            )
            or (
                self.failure.stage != "validation"
                and self.resources[-1].transport_status != "failed"
            )
        ):
            raise ValueError("failed capture does not bind its terminal resource")
        if (
            self.status == "failed"
            and self.failure is not None
            and self.failure.stage != "validation"
            and _OUTCOME_FAILURE[self.resources[-1].attempts[-1].outcome]
            != (self.failure.stage, self.failure.code)
        ):
            raise ValueError(
                "terminal failure code does not match the final attempt outcome"
            )
        if (
            self.version == "phase2-capture-session-v1"
            and self.failure is not None
            and self.failure.code in _DETAILED_RED_HAT_FAILURE_CODES
        ):
            raise ValueError("detailed Red Hat failures require capture-session v2")
        return self


@dataclass(frozen=True)
class Phase2CaptureBundle:
    """In-memory successful responses plus their aggregate evidence."""

    nvd_primary: CapturedResponse
    kev_catalog: CapturedResponse
    kev_lineage: CapturedResponse
    red_hat_primary: CapturedResponse
    red_hat_checksum: CapturedResponse
    evidence: Phase2CaptureSessionEvidence


class Phase2CaptureSessionError(CaptureError):
    """The fixed capture stopped and retained a serializable redacted ledger."""

    def __init__(self, evidence: Phase2CaptureSessionEvidence) -> None:
        super().__init__("Phase 2 capture session failed")
        self.evidence = evidence


def validate_phase2_capture_plan() -> None:
    """Prove the immutable plan contains exactly five safe logical GETs."""
    expected = (
        CaptureResourceDefinition("nvd_primary", NVD_FETCH_SPEC),
        CaptureResourceDefinition("kev_catalog", KEV_FETCH_SPEC),
        CaptureResourceDefinition("kev_lineage", KEV_COMPARE_FETCH_SPEC),
        CaptureResourceDefinition("red_hat_primary", RHSA_FETCH_SPEC),
        CaptureResourceDefinition("red_hat_checksum", RHSA_CHECKSUM_FETCH_SPEC),
    )
    expected_ids = tuple(resource.resource_id for resource in expected)
    if (
        expected != PHASE2_CAPTURE_RESOURCES
        or tuple(resource.resource_id for resource in PHASE2_CAPTURE_RESOURCES)
        != PHASE2_RESOURCE_IDS
        or expected_ids != PHASE2_RESOURCE_IDS
        or len(set(PHASE2_RESOURCE_IDS)) != 5
        or len(PHASE2_CAPTURE_RESOURCES) * 2 != 10
    ):
        raise CaptureError("Phase 2 capture plan is not the frozen five/ten plan")
    for resource in PHASE2_CAPTURE_RESOURCES:
        validate_fetch_spec(resource.spec)


def _success_ledger(
    definition: CaptureResourceDefinition,
    response: CapturedResponse,
) -> ResourceCaptureLedger:
    if response.request_url != definition.spec.url or not response.attempts:
        raise CaptureError("captured response does not match the session resource")
    return ResourceCaptureLedger(
        resource_id=definition.resource_id,
        request_url=response.request_url,
        request_fingerprint=response.request_fingerprint,
        attempts=_attempts(response),
        transport_status="success",
        response_sha256=hashlib.sha256(response.body).hexdigest(),
        response_byte_length=len(response.body),
        retrieved_at_utc=response.retrieved_at_utc,
    )


def _failed_ledger(
    definition: CaptureResourceDefinition,
    error: CaptureError,
) -> ResourceCaptureLedger:
    if not error.attempts:
        raise error
    attempts = [
        AttemptEvidence(
            attempt_number=attempt.attempt_number,
            started_at_utc=attempt.started_at_utc,
            finished_at_utc=attempt.finished_at_utc,
            outcome=attempt.outcome,
            status=attempt.status,
            retry_delay_seconds=attempt.retry_delay_seconds,
        )
        for attempt in error.attempts
    ]
    return ResourceCaptureLedger(
        resource_id=definition.resource_id,
        request_url=definition.spec.url,
        request_fingerprint=request_fingerprint(definition.spec.url),
        attempts=attempts,
        transport_status="failed",
        response_sha256=None,
        response_byte_length=None,
        retrieved_at_utc=None,
    )


def _evidence(
    resources: list[ResourceCaptureLedger],
    *,
    status: Literal["complete", "failed"],
    failure: CaptureFailure | None,
) -> Phase2CaptureSessionEvidence:
    started = resources[0].attempts[0].started_at_utc
    finished = resources[-1].attempts[-1].finished_at_utc
    return Phase2CaptureSessionEvidence(
        version="phase2-capture-session-v2",
        capture_policy_version="phase2-capture-policy-v1",
        session_id=_session_id(started),
        started_at_utc=started,
        finished_at_utc=finished,
        status=status,
        resources=resources,
        failure=failure,
    )


def _transport_failure(
    definition: CaptureResourceDefinition,
    error: CaptureError,
    resources: list[ResourceCaptureLedger],
) -> Phase2CaptureSessionError:
    ledger = _failed_ledger(definition, error)
    resources.append(ledger)
    outcome = ledger.attempts[-1].outcome
    stage, code = _OUTCOME_FAILURE[outcome]
    return Phase2CaptureSessionError(
        _evidence(
            resources,
            status="failed",
            failure=CaptureFailure(
                resource_id=definition.resource_id,
                stage=stage,
                code=code,
            ),
        )
    )


def _validation_failure(
    resources: list[ResourceCaptureLedger],
    *,
    code: FailureCode,
) -> Phase2CaptureSessionError:
    return Phase2CaptureSessionError(
        _evidence(
            resources,
            status="failed",
            failure=CaptureFailure(
                resource_id=resources[-1].resource_id,
                stage="validation",
                code=code,
            ),
        )
    )


def _validate_resource(
    resource_id: Phase2ResourceId,
    responses: dict[Phase2ResourceId, CapturedResponse],
) -> FailureCode | None:
    if resource_id == "red_hat_checksum":
        try:
            checksum = parse_red_hat_checksum(responses[resource_id].body)
        except CaptureError:
            return "red_hat_checksum_validation"
        primary = responses["red_hat_primary"].body
        if checksum != hashlib.sha256(primary).hexdigest():
            return "red_hat_checksum_validation"
        try:
            parse_red_hat_bytes(primary, responses[resource_id].body)
        except RedHatAdvisoryValidationError as error:
            return error.code
        except CaptureError:
            return "red_hat_advisory_validation"
        return None
    try:
        if resource_id == "nvd_primary":
            parse_nvd_bytes(responses[resource_id].body)
        elif resource_id == "kev_catalog":
            parse_kev_bytes(responses[resource_id].body)
        elif resource_id == "kev_lineage":
            parse_kev_lineage_bytes(responses[resource_id].body)
    except CaptureError:
        return _VALIDATION_FAILURE_BY_RESOURCE[resource_id]
    return None


def run_phase2_capture_session() -> Phase2CaptureBundle:
    """Run exactly the five frozen credential-free GETs, once each."""
    validate_phase2_capture_plan()
    resources: list[ResourceCaptureLedger] = []
    responses: dict[Phase2ResourceId, CapturedResponse] = {}
    for definition in PHASE2_CAPTURE_RESOURCES:
        try:
            response = fetch_https(definition.spec)
        except CaptureError as error:
            raise _transport_failure(definition, error, resources) from error
        resources.append(_success_ledger(definition, response))
        responses[definition.resource_id] = response
        failure_code = _validate_resource(definition.resource_id, responses)
        if failure_code is not None:
            raise _validation_failure(resources, code=failure_code)
    evidence = _evidence(resources, status="complete", failure=None)
    return Phase2CaptureBundle(
        nvd_primary=responses["nvd_primary"],
        kev_catalog=responses["kev_catalog"],
        kev_lineage=responses["kev_lineage"],
        red_hat_primary=responses["red_hat_primary"],
        red_hat_checksum=responses["red_hat_checksum"],
        evidence=evidence,
    )


def bind_phase2_capture_artifacts(
    session: Phase2CaptureSessionEvidence,
    records: list[SourceStateEvidenceRecord],
) -> None:
    """Cross-bind the aggregate session to all three source evidence records."""
    try:
        session = Phase2CaptureSessionEvidence.model_validate(
            session.model_dump(mode="python")
        )
    except ValidationError as exc:
        raise CaptureError("capture session failed final revalidation") from exc
    if session.status != "complete":
        raise CaptureError("failed capture session cannot bind accepted artifacts")
    by_source = {record.source_name: record for record in records}
    if (
        len(records) != 3
        or len(by_source) != 3
        or set(by_source) != {"nvd", "cisa_kev", "red_hat_rhsa"}
    ):
        raise CaptureError("capture binding requires exactly three source records")
    resource_by_id = {resource.resource_id: resource for resource in session.resources}
    for resource_id, (source_name, role) in _ARTIFACT_BINDINGS.items():
        artifacts = [
            artifact
            for artifact in by_source[source_name].artifacts
            if artifact.role == role
        ]
        resource = resource_by_id[resource_id]
        if len(artifacts) != 1:
            raise CaptureError("capture artifact role is missing or duplicated")
        artifact = artifacts[0]
        if (
            artifact.request_url != resource.request_url
            or artifact.request_fingerprint != resource.request_fingerprint
            or artifact.attempts != resource.attempts
            or artifact.sha256 != resource.response_sha256
            or artifact.byte_length != resource.response_byte_length
            or artifact.retrieved_at_utc != resource.retrieved_at_utc
        ):
            raise CaptureError("capture session and source artifact do not cross-bind")


def render_capture_session_json(session: Phase2CaptureSessionEvidence) -> str:
    """Render stable, redacted session metadata with no raw response bytes."""
    return (
        json.dumps(
            session.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
