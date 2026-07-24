from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.ingest.base import (
    AttemptRecord,
    CapturedResponse,
    CaptureError,
    store_capture,
)
from cti_provenance.ingest.nvd import (
    NVD_URL,
    SELECTED_CVE,
    nvd_evidence_record,
    nvd_state,
    parse_nvd_bytes,
    replay_nvd_state,
)
from cti_provenance.snapshot import ImmutableBlobStore, select_admissible_snapshot

NOW = datetime(2026, 7, 18, tzinfo=UTC)


def _raw() -> bytes:
    return json.dumps(
        {
            "format": "NVD_CVE",
            "version": "2.0",
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": SELECTED_CVE}}],
        }
    ).encode()


def _response(raw: bytes | None = None, *, url: str = NVD_URL) -> CapturedResponse:
    attempt = AttemptRecord(1, NOW, NOW + timedelta(seconds=1), "success", 200, None)
    return CapturedResponse(
        url,
        200,
        raw or _raw(),
        {"content-type": "application/json"},
        attempt.finished_at_utc,
        (attempt,),
    )


def test_nvd_parser_requires_exact_single_selected_record() -> None:
    payload = json.loads(_raw())
    assert parse_nvd_bytes(_raw())["totalResults"] == 1
    payload["vulnerabilities"][0]["cve"]["id"] = "CVE-2024-0001"
    with pytest.raises(CaptureError, match="selected CVE"):
        parse_nvd_bytes(json.dumps(payload).encode())


def test_nvd_state_requires_exact_query_and_uses_observation_cutoff() -> None:
    state = nvd_state(_response())
    assert str(state.manifest.source_url).endswith("/rest/json/cves/2.0")
    assert state.manifest.available_by_utc == state.manifest.retrieved_at_utc
    assert select_admissible_snapshot([state], NOW) is None
    assert (
        select_admissible_snapshot([state], NOW + timedelta(seconds=1))
        == state.manifest
    )
    with pytest.raises(CaptureError, match="exact selected-CVE query"):
        nvd_state(_response(url=NVD_URL + "&extra=true"))


def test_nvd_source_evidence_replays_and_detects_tampering() -> None:
    response = _response()
    state = nvd_state(response)
    record = nvd_evidence_record(response, state)
    assert replay_nvd_state(record, response.body) == state
    with pytest.raises(CaptureError, match="do not match"):
        replay_nvd_state(record, response.body + b" ")


def test_nvd_serialized_evidence_rejects_retry_below_six_seconds() -> None:
    attempts = (
        AttemptRecord(
            1,
            NOW,
            NOW + timedelta(seconds=1),
            "transport_error",
            None,
            1,
        ),
        AttemptRecord(
            2,
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            "success",
            200,
            None,
        ),
    )
    response = CapturedResponse(
        NVD_URL,
        200,
        _raw(),
        {"content-type": "application/json"},
        attempts[-1].finished_at_utc,
        attempts,
    )
    with pytest.raises(ValidationError, match="six seconds"):
        nvd_evidence_record(response, nvd_state(response))


def test_nvd_storage_cross_binds_primary_request_evidence(tmp_path: Path) -> None:
    response = _response()
    state = nvd_state(response)
    record = nvd_evidence_record(response, state)
    store_capture(
        response,
        store=ImmutableBlobStore(tmp_path),
        raw_blob_path=state.manifest.raw_blob_path,
        manifest=state.manifest,
        state=state,
        source_evidence=record,
    )
    stored = tmp_path / Path(state.manifest.raw_blob_path)
    assert stored.read_bytes() == response.body

    changed_artifact = record.artifacts[0].model_copy(
        update={"request_url": NVD_URL + "&extra=true"}
    )
    changed_record = record.model_copy(update={"artifacts": [changed_artifact]})
    with pytest.raises(CaptureError, match="cross-bind"):
        store_capture(
            response,
            store=ImmutableBlobStore(tmp_path),
            raw_blob_path=state.manifest.raw_blob_path,
            manifest=state.manifest,
            state=state,
            source_evidence=changed_record,
        )
