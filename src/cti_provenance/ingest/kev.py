"""Pinned CISA KEV Phase 2 capture, provenance proof, and replay."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from cti_provenance.ingest.base import (
    CapturedResponse,
    CaptureError,
    FetchSpec,
    KevDerivation,
    SourceStateEvidenceRecord,
    artifact_evidence,
    replay_response,
)
from cti_provenance.ingest.nvd import SELECTED_CVE
from cti_provenance.snapshot import CisaEvidence, SnapshotManifest, SnapshotState

KEV_COMMIT = "87ba74fc7c502adcf482fc7b06e65ce9ea4d9ef2"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/"
    f"{KEV_COMMIT}/known_exploited_vulnerabilities.json"
)
KEV_COMPARE_URL = (
    f"https://api.github.com/repos/cisagov/kev-data/compare/{KEV_COMMIT}...develop"
)
KEV_COMMIT_TIME = datetime.fromisoformat("2026-07-16T19:11:42+00:00")
KEV_FETCH_SPEC = FetchSpec(
    url=KEV_URL,
    allowed_host="raw.githubusercontent.com",
    allowed_path=(
        f"/cisagov/kev-data/{KEV_COMMIT}/known_exploited_vulnerabilities.json"
    ),
    max_bytes=10_000_000,
    timeout_seconds=30.0,
)
KEV_COMPARE_FETCH_SPEC = FetchSpec(
    url=KEV_COMPARE_URL,
    allowed_host="api.github.com",
    allowed_path=(f"/repos/cisagov/kev-data/compare/{KEV_COMMIT}...develop"),
    max_bytes=2_000_000,
    timeout_seconds=30.0,
)
KEV_LICENSE_NOTE = (
    "CISA KEV catalog is released under CC0; retain source and no-endorsement note."
)


def parse_kev_bytes(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError("KEV response is not JSON") from exc
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("catalogVersion"), str)
        or not isinstance(payload.get("dateReleased"), str)
    ):
        raise CaptureError("KEV catalog metadata is incomplete")
    entries = payload.get("vulnerabilities")
    found = (
        [x for x in entries if isinstance(x, dict) and x.get("cveID") == SELECTED_CVE]
        if isinstance(entries, list)
        else []
    )
    if len(found) != 1:
        raise CaptureError("KEV must contain exactly one selected CVE")
    return payload


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise CaptureError(f"KEV lineage {field} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaptureError(f"KEV lineage {field} is invalid") from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise CaptureError(f"KEV lineage {field} must use UTC")
    return parsed.astimezone(UTC)


type LiteralStatus = Literal["ahead", "identical"]


def parse_kev_lineage_bytes(raw: bytes) -> tuple[LiteralStatus, datetime]:
    """Verify the pinned commit is the official comparison base and ancestor."""
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError("KEV lineage response is not JSON") from exc
    if not isinstance(payload, dict):
        raise CaptureError("KEV lineage response has an invalid envelope")
    status = payload.get("status")
    if status not in {"ahead", "identical"}:
        raise CaptureError("KEV pinned commit is not proven in develop lineage")
    base = payload.get("base_commit")
    merge_base = payload.get("merge_base_commit")
    if (
        not isinstance(base, dict)
        or base.get("sha") != KEV_COMMIT
        or not isinstance(merge_base, dict)
        or merge_base.get("sha") != KEV_COMMIT
    ):
        raise CaptureError("KEV lineage does not bind the pinned commit")
    commit = base.get("commit")
    committer = commit.get("committer") if isinstance(commit, dict) else None
    commit_time = _parse_utc(
        committer.get("date") if isinstance(committer, dict) else None,
        field="commit time",
    )
    if commit_time != KEV_COMMIT_TIME:
        raise CaptureError("KEV official commit time changed from the frozen value")
    return status, commit_time


def _raw_path(digest: str) -> str:
    return f"data/raw/cisa-kev/{digest}.json"


def _lineage_path(digest: str) -> str:
    return f"data/raw/cisa-kev-lineage/{digest}.json"


def kev_state(
    response: CapturedResponse, lineage_response: CapturedResponse
) -> SnapshotState:
    """Construct state only after replayable official lineage verification."""
    if (
        response.request_url != KEV_URL
        or lineage_response.request_url != KEV_COMPARE_URL
    ):
        raise CaptureError("KEV capture requires exact catalog and lineage URLs")
    if (
        response.retrieved_at_utc < KEV_COMMIT_TIME
        or lineage_response.retrieved_at_utc < KEV_COMMIT_TIME
    ):
        raise CaptureError("KEV evidence observation predates the pinned commit")
    parse_kev_bytes(response.body)
    _, commit_time = parse_kev_lineage_bytes(lineage_response.body)
    digest = hashlib.sha256(response.body).hexdigest()
    manifest = SnapshotManifest(
        snapshot_id=f"kev-{digest[:12]}",
        source_name="cisa_kev",
        source_class="government",
        source_url=KEV_URL,
        retrieved_at_utc=response.retrieved_at_utc,
        http_status=200,
        http_etag=response.headers.get("etag"),
        http_last_modified=response.headers.get("last-modified"),
        effective_date_if_known=commit_time,
        effective_date_basis="publisher_version",
        available_by_utc=commit_time,
        available_by_basis="upstream_version",
        upstream_identifier="cisa-kev-catalog",
        upstream_version=KEV_COMMIT,
        media_type=response.headers.get("content-type", "application/octet-stream"),
        byte_length=len(response.body),
        sha256=digest,
        raw_blob_path=_raw_path(digest),
        fetcher_version="phase2-capture-v1",
        normalization_version="phase2-kev-v1",
        license_or_terms_note=KEV_LICENSE_NOTE,
    )
    return SnapshotState(
        manifest=manifest,
        cisa_evidence=CisaEvidence(
            commit_sha=KEV_COMMIT,
            official_commit_time_utc=commit_time,
            mirror_relationship_verified=True,
            ancestry_verified=True,
        ),
    )


def kev_evidence_record(
    response: CapturedResponse,
    lineage_response: CapturedResponse,
    state: SnapshotState,
) -> SourceStateEvidenceRecord:
    """Serialize the two artifacts needed to recompute KEV state."""
    expected = kev_state(response, lineage_response)
    if state != expected:
        raise CaptureError("KEV state does not match captured evidence")
    status, commit_time = parse_kev_lineage_bytes(lineage_response.body)
    lineage_digest = hashlib.sha256(lineage_response.body).hexdigest()
    return SourceStateEvidenceRecord(
        version="phase2-source-evidence-v1",
        snapshot_id=state.manifest.snapshot_id,
        source_name="cisa_kev",
        verifier_version="phase2-source-verifier-v1",
        artifacts=[
            artifact_evidence(
                response,
                role="primary_body",
                raw_blob_path=state.manifest.raw_blob_path,
            ),
            artifact_evidence(
                lineage_response,
                role="commit_lineage",
                raw_blob_path=_lineage_path(lineage_digest),
            ),
        ],
        derivation=KevDerivation(
            kind="cisa_kev_commit",
            stable_entity_id="cisa-kev-catalog",
            commit_sha=KEV_COMMIT,
            commit_time_utc=commit_time,
            compare_status=status,
        ),
        license_or_terms_note=KEV_LICENSE_NOTE,
    )


def replay_kev_state(
    record: SourceStateEvidenceRecord,
    *,
    primary_body: bytes,
    lineage_body: bytes,
) -> SnapshotState:
    """Recompute KEV state and verification booleans from offline artifacts."""
    if record.source_name != "cisa_kev" or not isinstance(
        record.derivation, KevDerivation
    ):
        raise CaptureError("source evidence is not a KEV record")
    by_role = {artifact.role: artifact for artifact in record.artifacts}
    response = replay_response(by_role["primary_body"], primary_body)
    lineage_response = replay_response(by_role["commit_lineage"], lineage_body)
    state = kev_state(response, lineage_response)
    status, commit_time = parse_kev_lineage_bytes(lineage_body)
    if (
        state.manifest.snapshot_id != record.snapshot_id
        or record.derivation.commit_sha != KEV_COMMIT
        or record.derivation.commit_time_utc != commit_time
        or record.derivation.compare_status != status
    ):
        raise CaptureError("replayed KEV derivation does not match evidence")
    return state
