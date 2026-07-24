"""Red Hat CSAF publisher-declared version evidence and replay."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any, Literal, cast

from cti_provenance.ingest.base import (
    CapturedResponse,
    CaptureError,
    FetchSpec,
    RedHatDerivation,
    SourceStateEvidenceRecord,
    artifact_evidence,
    replay_response,
)
from cti_provenance.ingest.nvd import SELECTED_CVE
from cti_provenance.snapshot import RedHatEvidence, SnapshotManifest, SnapshotState

type RedHatAdvisoryFailureCode = Literal[
    "red_hat_json_validation",
    "red_hat_csaf_identity_validation",
    "red_hat_revision_metadata_validation",
    "red_hat_revision_history_validation",
    "red_hat_selected_cve_validation",
]

RHSA_URL = (
    "https://security.access.redhat.com/data/csaf/v2/advisories/2021/"
    "rhsa-2021_5133.json"
)
RHSA_ID: Literal["RHSA-2021:5133"] = "RHSA-2021:5133"
RHSA_FILENAME = "rhsa-2021_5133.json"
RHSA_CHECKSUM_URL = f"{RHSA_URL}.sha256"
RHSA_FETCH_SPEC = FetchSpec(
    url=RHSA_URL,
    allowed_host="security.access.redhat.com",
    allowed_path="/data/csaf/v2/advisories/2021/rhsa-2021_5133.json",
    max_bytes=10_000_000,
    timeout_seconds=30.0,
)
RHSA_CHECKSUM_FETCH_SPEC = FetchSpec(
    url=RHSA_CHECKSUM_URL,
    allowed_host="security.access.redhat.com",
    allowed_path="/data/csaf/v2/advisories/2021/rhsa-2021_5133.json.sha256",
    max_bytes=512,
    timeout_seconds=30.0,
)
RED_HAT_LICENSE_NOTE = (
    "Red Hat security data is CC BY 4.0; retain attribution, source link, "
    "license link, and modification notice. current_release_date is "
    "publisher-declared version evidence, not observed historical availability."
)
_CHECKSUM_RE = re.compile(
    rb"\A([0-9A-Fa-f]{64})[ \t]+\*?rhsa-2021_5133\.json(?:\r?\n)?\Z"
)
_MAX_REVISION_NUMBER_DIGITS = 18


class RedHatAdvisoryValidationError(CaptureError):
    """A stable redacted semantic domain for checksum-matched CSAF bytes."""

    def __init__(self, code: RedHatAdvisoryFailureCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_red_hat_checksum(checksum_raw: bytes) -> str:
    """Parse one exact ASCII checksum record for the selected advisory."""
    match = _CHECKSUM_RE.fullmatch(checksum_raw)
    if match is None:
        raise CaptureError("Red Hat checksum companion has an invalid exact format")
    return match.group(1).decode("ascii").lower()


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise CaptureError(f"Red Hat {field} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaptureError(f"Red Hat {field} is invalid") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise CaptureError(f"Red Hat {field} must use UTC")
    return parsed.astimezone(UTC)


def _parse_advisory_utc(
    value: Any,
    *,
    field: str,
    code: RedHatAdvisoryFailureCode,
) -> datetime:
    try:
        return _parse_utc(value, field=field)
    except CaptureError as exc:
        raise RedHatAdvisoryValidationError(code, str(exc)) from exc


def parse_red_hat_bytes(raw: bytes, checksum_raw: bytes) -> dict[str, Any]:
    expected = parse_red_hat_checksum(checksum_raw)
    if expected != hashlib.sha256(raw).hexdigest():
        raise CaptureError("Red Hat companion checksum mismatch")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RedHatAdvisoryValidationError(
            "red_hat_json_validation",
            "Red Hat response is not JSON",
        ) from exc
    document = payload.get("document") if isinstance(payload, dict) else None
    tracking = document.get("tracking") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or document.get("category") != "csaf_security_advisory"
        or not isinstance(tracking, dict)
        or tracking.get("id") != RHSA_ID
        or tracking.get("status") != "final"
    ):
        raise RedHatAdvisoryValidationError(
            "red_hat_csaf_identity_validation",
            "Red Hat CSAF identity/status invalid",
        )
    version = tracking.get("version")
    current_raw = tracking.get("current_release_date")
    history = tracking.get("revision_history")
    version_text = str(version)
    if (
        not isinstance(version, (str, int))
        or not version_text.isascii()
        or not version_text.isdecimal()
        or len(version_text) > _MAX_REVISION_NUMBER_DIGITS
        or (len(version_text) > 1 and version_text.startswith("0"))
        or version_text == "0"
    ):
        raise RedHatAdvisoryValidationError(
            "red_hat_revision_metadata_validation",
            "Red Hat revision version is invalid",
        )
    current = _parse_advisory_utc(
        current_raw,
        field="current release date",
        code="red_hat_revision_metadata_validation",
    )
    if not isinstance(history, list) or not history:
        raise RedHatAdvisoryValidationError(
            "red_hat_revision_history_validation",
            "Red Hat revision history is missing",
        )
    history_dates: list[datetime] = []
    history_numbers: list[str] = []
    for entry in history:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("number"), (str, int))
            or not str(entry["number"]).isascii()
            or not str(entry["number"]).isdecimal()
            or len(str(entry["number"])) > _MAX_REVISION_NUMBER_DIGITS
            or (len(str(entry["number"])) > 1 and str(entry["number"]).startswith("0"))
            or not isinstance(entry.get("summary"), str)
            or not entry["summary"].strip()
        ):
            raise RedHatAdvisoryValidationError(
                "red_hat_revision_history_validation",
                "Red Hat revision history entry is incomplete",
            )
        history_dates.append(
            _parse_advisory_utc(
                entry.get("date"),
                field="revision date",
                code="red_hat_revision_history_validation",
            )
        )
        history_numbers.append(str(entry["number"]))
    if (
        any(later < earlier for earlier, later in pairwise(history_dates))
        or history_dates[-1] != current
        or version_text != str(len(history_numbers))
        or any(
            number != str(index)
            for index, number in enumerate(history_numbers, start=1)
        )
    ):
        raise RedHatAdvisoryValidationError(
            "red_hat_revision_history_validation",
            "Red Hat current revision history is inconsistent",
        )
    vulnerabilities = payload.get("vulnerabilities")
    if (
        not isinstance(vulnerabilities, list)
        or sum(
            isinstance(vulnerability, dict) and vulnerability.get("cve") == SELECTED_CVE
            for vulnerability in vulnerabilities
        )
        != 1
    ):
        raise RedHatAdvisoryValidationError(
            "red_hat_selected_cve_validation",
            "Red Hat advisory lacks exact selected CVE",
        )
    return cast(dict[str, Any], payload)


def _primary_path(digest: str) -> str:
    return f"data/raw/red-hat/{digest}.json"


def _checksum_path(digest: str) -> str:
    return f"data/raw/red-hat-checksum/{digest}.sha256"


def red_hat_state(
    response: CapturedResponse, checksum_response: CapturedResponse
) -> SnapshotState:
    """Use checksum-matched publisher-declared, not observed-history, evidence."""
    if (
        response.request_url != RHSA_URL
        or checksum_response.request_url != RHSA_CHECKSUM_URL
    ):
        raise CaptureError("Red Hat capture requires exact advisory and checksum URLs")
    payload = parse_red_hat_bytes(response.body, checksum_response.body)
    tracking = payload["document"]["tracking"]
    current = _parse_utc(tracking["current_release_date"], field="current release date")
    if (
        response.retrieved_at_utc < current
        or checksum_response.retrieved_at_utc < current
    ):
        raise CaptureError(
            "observation predates the publisher-declared current release date"
        )
    digest = hashlib.sha256(response.body).hexdigest()
    published = parse_red_hat_checksum(checksum_response.body)
    manifest = SnapshotManifest(
        snapshot_id=f"rhsa-{digest[:12]}",
        source_name="red_hat_rhsa",
        source_class="vendor",
        source_url=RHSA_URL,
        retrieved_at_utc=response.retrieved_at_utc,
        http_status=200,
        http_etag=response.headers.get("etag"),
        http_last_modified=response.headers.get("last-modified"),
        effective_date_if_known=current,
        effective_date_basis="publisher_version",
        available_by_utc=current,
        available_by_basis="publisher_timestamp_with_observation",
        upstream_identifier=RHSA_ID,
        upstream_version=str(tracking["version"]),
        media_type=response.headers.get("content-type", "application/octet-stream"),
        byte_length=len(response.body),
        sha256=digest,
        raw_blob_path=_primary_path(digest),
        fetcher_version="phase2-capture-v1",
        normalization_version="phase2-red-hat-v1",
        license_or_terms_note=RED_HAT_LICENSE_NOTE,
    )
    return SnapshotState(
        manifest=manifest,
        red_hat_evidence=RedHatEvidence(
            final_status=True,
            tracking_id=RHSA_ID,
            revision_version=str(tracking["version"]),
            complete_revision_history=True,
            final_revision_date_utc=current,
            current_release_date_utc=current,
            published_sha256=published,
        ),
    )


def red_hat_evidence_record(
    response: CapturedResponse,
    checksum_response: CapturedResponse,
    state: SnapshotState,
) -> SourceStateEvidenceRecord:
    """Serialize both artifacts needed to recompute Red Hat availability."""
    expected = red_hat_state(response, checksum_response)
    if state != expected:
        raise CaptureError("Red Hat state does not match captured evidence")
    checksum_digest = hashlib.sha256(checksum_response.body).hexdigest()
    tracking = parse_red_hat_bytes(response.body, checksum_response.body)["document"][
        "tracking"
    ]
    current = _parse_utc(tracking["current_release_date"], field="current release date")
    return SourceStateEvidenceRecord(
        version="phase2-source-evidence-v1",
        snapshot_id=state.manifest.snapshot_id,
        source_name="red_hat_rhsa",
        verifier_version="phase2-source-verifier-v1",
        artifacts=[
            artifact_evidence(
                response,
                role="primary_body",
                raw_blob_path=state.manifest.raw_blob_path,
            ),
            artifact_evidence(
                checksum_response,
                role="published_checksum",
                raw_blob_path=_checksum_path(checksum_digest),
            ),
        ],
        derivation=RedHatDerivation(
            kind="red_hat_published_checksum",
            tracking_id=RHSA_ID,
            revision_version=str(tracking["version"]),
            current_release_date_utc=current,
            published_sha256=parse_red_hat_checksum(checksum_response.body),
        ),
        license_or_terms_note=RED_HAT_LICENSE_NOTE,
    )


def replay_red_hat_state(
    record: SourceStateEvidenceRecord,
    *,
    primary_body: bytes,
    checksum_body: bytes,
) -> SnapshotState:
    """Recompute Red Hat state from hash-bound offline evidence."""
    if record.source_name != "red_hat_rhsa" or not isinstance(
        record.derivation, RedHatDerivation
    ):
        raise CaptureError("source evidence is not a Red Hat record")
    by_role = {artifact.role: artifact for artifact in record.artifacts}
    response = replay_response(by_role["primary_body"], primary_body)
    checksum_response = replay_response(by_role["published_checksum"], checksum_body)
    state = red_hat_state(response, checksum_response)
    evidence = state.red_hat_evidence
    if (
        evidence is None
        or state.manifest.snapshot_id != record.snapshot_id
        or record.derivation.tracking_id != evidence.tracking_id
        or record.derivation.revision_version != evidence.revision_version
        or record.derivation.current_release_date_utc
        != evidence.current_release_date_utc
        or record.derivation.published_sha256 != evidence.published_sha256
    ):
        raise CaptureError("replayed Red Hat derivation does not match evidence")
    return state
