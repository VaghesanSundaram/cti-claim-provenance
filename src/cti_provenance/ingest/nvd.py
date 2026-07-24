"""Exact NVD CVE 2.0 Phase 2 capture and replay contract."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from cti_provenance.ingest.base import (
    CapturedResponse,
    CaptureError,
    FetchSpec,
    NvdDerivation,
    SourceStateEvidenceRecord,
    artifact_evidence,
    replay_response,
)
from cti_provenance.snapshot import SnapshotManifest, SnapshotState

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SELECTED_CVE: Literal["CVE-2021-44228"] = "CVE-2021-44228"
NVD_URL = f"{NVD_BASE_URL}?cveId={SELECTED_CVE}"
NVD_FETCH_SPEC = FetchSpec(
    url=NVD_URL,
    allowed_host="services.nvd.nist.gov",
    allowed_path="/rest/json/cves/2.0",
    allowed_query=(("cveId", SELECTED_CVE),),
    max_bytes=2_000_000,
    timeout_seconds=30.0,
    retry_delay_seconds=6.0,
)
NVD_LICENSE_NOTE = (
    "NVD public-data source; retain metadata, hash, and reproducible fetch recipe."
)


def parse_nvd_bytes(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError("NVD response is not JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("format") != "NVD_CVE"
        or payload.get("version") != "2.0"
        or payload.get("totalResults") != 1
    ):
        raise CaptureError("NVD response has unexpected envelope")
    vulnerabilities = payload.get("vulnerabilities")
    if (
        not isinstance(vulnerabilities, list)
        or len(vulnerabilities) != 1
        or not isinstance(vulnerabilities[0], dict)
    ):
        raise CaptureError("NVD response must contain exactly one record")
    cve = vulnerabilities[0].get("cve")
    if not isinstance(cve, dict) or cve.get("id") != SELECTED_CVE:
        raise CaptureError("NVD response does not identify selected CVE")
    return payload


def _raw_path(digest: str) -> str:
    return f"data/raw/nvd/{digest}.json"


def nvd_state(response: CapturedResponse) -> SnapshotState:
    """Create a query-free manifest with observed-retrieval availability."""
    if response.request_url != NVD_URL:
        raise CaptureError("NVD request must use the exact selected-CVE query")
    parse_nvd_bytes(response.body)
    digest = hashlib.sha256(response.body).hexdigest()
    manifest = SnapshotManifest(
        snapshot_id=f"nvd-{digest[:12]}",
        source_name="nvd",
        source_class="government",
        source_url=NVD_BASE_URL,
        retrieved_at_utc=response.retrieved_at_utc,
        http_status=200,
        http_etag=response.headers.get("etag"),
        http_last_modified=response.headers.get("last-modified"),
        effective_date_if_known=None,
        effective_date_basis="unknown",
        available_by_utc=response.retrieved_at_utc,
        available_by_basis="observed_retrieval",
        upstream_identifier=SELECTED_CVE,
        upstream_version=None,
        media_type=response.headers.get("content-type", "application/octet-stream"),
        byte_length=len(response.body),
        sha256=digest,
        raw_blob_path=_raw_path(digest),
        fetcher_version="phase2-capture-v1",
        normalization_version="phase2-nvd-v1",
        license_or_terms_note=NVD_LICENSE_NOTE,
    )
    return SnapshotState(manifest=manifest)


def nvd_evidence_record(
    response: CapturedResponse, state: SnapshotState
) -> SourceStateEvidenceRecord:
    """Serialize replayable evidence for one accepted NVD observation."""
    expected = nvd_state(response)
    if state != expected:
        raise CaptureError("NVD state does not match the captured response")
    manifest = state.manifest
    return SourceStateEvidenceRecord(
        version="phase2-source-evidence-v1",
        snapshot_id=manifest.snapshot_id,
        source_name="nvd",
        verifier_version="phase2-source-verifier-v1",
        artifacts=[
            artifact_evidence(
                response,
                role="primary_body",
                raw_blob_path=manifest.raw_blob_path,
            )
        ],
        derivation=NvdDerivation(kind="nvd_observed", cve_id=SELECTED_CVE),
        license_or_terms_note=NVD_LICENSE_NOTE,
    )


def replay_nvd_state(
    record: SourceStateEvidenceRecord, primary_body: bytes
) -> SnapshotState:
    """Recompute NVD state from hash-bound offline evidence."""
    if record.source_name != "nvd" or not isinstance(record.derivation, NvdDerivation):
        raise CaptureError("source evidence is not an NVD record")
    response = replay_response(record.artifacts[0], primary_body)
    state = nvd_state(response)
    if state.manifest.snapshot_id != record.snapshot_id:
        raise CaptureError("replayed NVD snapshot identity does not match evidence")
    return state
