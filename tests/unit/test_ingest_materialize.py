from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import cti_provenance.ingest.materialize as materialize_module
import cti_provenance.ingest.session as session_module
from cti_provenance.ingest.base import AttemptRecord, CapturedResponse, CaptureError
from cti_provenance.ingest.kev import KEV_COMMIT, KEV_COMMIT_TIME
from cti_provenance.ingest.materialize import (
    PHASE2_METADATA_ENVELOPE_PATH,
    PHASE2_REAL_SLICE_SESSION_ID,
    PHASE2_SNAPSHOT_MANIFEST_PATH,
    PHASE2_SOURCE_EVIDENCE_PATH,
    capture_and_materialize_phase2,
    load_phase2_materialized_corpus,
    materialize_phase2_capture,
    recover_phase2_metadata_views,
)
from cti_provenance.ingest.nvd import SELECTED_CVE
from cti_provenance.ingest.session import (
    PHASE2_CAPTURE_RESOURCES,
    Phase2CaptureSessionError,
    run_phase2_capture_session,
)

NOW = datetime(2026, 7, 18, 12, tzinfo=UTC)


def _nvd_raw() -> bytes:
    return json.dumps(
        {
            "format": "NVD_CVE",
            "version": "2.0",
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": SELECTED_CVE,
                        "published": "2021-12-10T10:00:00Z",
                        "lastModified": "2021-12-11T10:00:00Z",
                        "descriptions": [
                            {"lang": "en", "value": "Selected NVD description"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                    "cvssData": {"baseScore": 10.0},
                                }
                            ]
                        },
                    }
                }
            ],
        }
    ).encode()


def _kev_raw() -> bytes:
    return json.dumps(
        {
            "catalogVersion": "2026.07.16",
            "dateReleased": "2026-07-16T19:11:42Z",
            "vulnerabilities": [
                {
                    "cveID": SELECTED_CVE,
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                }
            ],
        }
    ).encode()


def _kev_lineage_raw() -> bytes:
    return json.dumps(
        {
            "status": "ahead",
            "base_commit": {
                "sha": KEV_COMMIT,
                "commit": {
                    "committer": {
                        "date": KEV_COMMIT_TIME.isoformat().replace("+00:00", "Z")
                    }
                },
            },
            "merge_base_commit": {"sha": KEV_COMMIT},
        }
    ).encode()


def _red_hat_raw() -> bytes:
    return json.dumps(
        {
            "document": {
                "category": "csaf_security_advisory",
                "title": "Selected advisory",
                "tracking": {
                    "id": "RHSA-2021:5133",
                    "status": "final",
                    "version": "3",
                    "current_release_date": "2026-06-28T12:35:37Z",
                    "revision_history": [
                        {
                            "number": "1",
                            "date": "2021-12-15T00:00:00Z",
                            "summary": "Initial",
                        },
                        {
                            "number": "2",
                            "date": "2022-01-01T00:00:00Z",
                            "summary": "Second",
                        },
                        {
                            "number": "3",
                            "date": "2026-06-28T12:35:37Z",
                            "summary": "Current",
                        },
                    ],
                },
            },
            "product_tree": {
                "branches": [
                    {
                        "product": {
                            "product_id": "affected-id",
                            "name": "Example affected product",
                        }
                    },
                    {
                        "product": {
                            "product_id": "fixed-id",
                            "name": "Example fixed product",
                        }
                    },
                ]
            },
            "vulnerabilities": [
                {
                    "cve": SELECTED_CVE,
                    "product_status": {
                        "known_affected": ["affected-id"],
                        "fixed": ["fixed-id"],
                    },
                }
            ],
        }
    ).encode()


def _checksum(raw: bytes) -> bytes:
    return f"{hashlib.sha256(raw).hexdigest()}  rhsa-2021_5133.json\n".encode()


def _response(resource_index: int, body: bytes) -> CapturedResponse:
    definition = PHASE2_CAPTURE_RESOURCES[resource_index]
    started = NOW + timedelta(seconds=resource_index * 2)
    finished = started + timedelta(seconds=1)
    return CapturedResponse(
        definition.spec.url,
        200,
        body,
        {"content-type": "application/json"},
        finished,
        (
            AttemptRecord(
                1,
                started,
                finished,
                "success",
                200,
                None,
            ),
        ),
    )


def _bundle(monkeypatch: pytest.MonkeyPatch) -> Any:
    red_hat = _red_hat_raw()
    responses = iter(
        (
            _response(0, _nvd_raw()),
            _response(1, _kev_raw()),
            _response(2, _kev_lineage_raw()),
            _response(3, red_hat),
            _response(4, _checksum(red_hat)),
        )
    )
    monkeypatch.setattr(session_module, "fetch_https", lambda _spec: next(responses))
    return run_phase2_capture_session()


def _bind_real_session(
    tmp_path: Path,
    result: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_path = tmp_path / result.session_path
    monkeypatch.setattr(
        materialize_module,
        "PHASE2_REAL_SLICE_SESSION_ID",
        session_path.stem,
    )
    monkeypatch.setattr(
        materialize_module,
        "PHASE2_REAL_SLICE_SESSION_SHA256",
        hashlib.sha256(session_path.read_bytes()).hexdigest(),
    )


def test_materialization_stores_replays_and_normalizes_exact_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    result = materialize_phase2_capture(tmp_path, bundle)

    assert len(result.states) == 3
    assert len(result.source_evidence) == 3
    assert len(result.normalized_documents) == 3
    assert (tmp_path / result.session_path).is_file()
    assert (tmp_path / PHASE2_SNAPSHOT_MANIFEST_PATH).read_text().count("\n") == 3
    assert (tmp_path / PHASE2_SOURCE_EVIDENCE_PATH).read_text().count("\n") == 3
    for state in result.states:
        raw = tmp_path / state.manifest.raw_blob_path
        assert raw.is_file()
        assert hashlib.sha256(raw.read_bytes()).hexdigest() == state.manifest.sha256
    for document in result.normalized_documents:
        normalized = (
            tmp_path
            / "data"
            / "normalized"
            / "phase2"
            / document.snapshot_id
            / f"{document.document_id}.json"
        )
        assert normalized.is_file()
        assert json.loads(normalized.read_text())["snapshot_id"] == document.snapshot_id

    assert materialize_phase2_capture(tmp_path, bundle) == result
    tracked_metadata = (
        (tmp_path / result.session_path).read_text()
        + (tmp_path / PHASE2_SNAPSHOT_MANIFEST_PATH).read_text()
        + (tmp_path / PHASE2_SOURCE_EVIDENCE_PATH).read_text()
    )
    assert "Selected NVD description" not in tracked_metadata
    assert "Example affected product" not in tracked_metadata


def test_real_slice_loader_replays_exact_materialized_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    _bind_real_session(tmp_path, result, monkeypatch)

    states, documents = load_phase2_materialized_corpus(tmp_path)

    assert states == result.states
    assert documents == result.normalized_documents


def test_real_slice_loader_requires_the_frozen_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))

    assert Path(result.session_path).stem != PHASE2_REAL_SLICE_SESSION_ID
    with pytest.raises(CaptureError, match="complete session"):
        load_phase2_materialized_corpus(tmp_path)


def test_real_slice_loader_rejects_missing_raw_or_normalized_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    _bind_real_session(tmp_path, result, monkeypatch)
    (tmp_path / result.states[0].manifest.raw_blob_path).unlink()

    with pytest.raises(CaptureError, match="unavailable for replay"):
        load_phase2_materialized_corpus(tmp_path)

    materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    document = result.normalized_documents[0]
    normalized = (
        tmp_path
        / "data"
        / "normalized"
        / "phase2"
        / document.snapshot_id
        / f"{document.document_id}.json"
    )
    normalized.unlink()
    with pytest.raises(CaptureError, match="normalized document is unavailable"):
        load_phase2_materialized_corpus(tmp_path)


def test_real_slice_loader_rejects_noncanonical_normalized_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    _bind_real_session(tmp_path, result, monkeypatch)
    document = result.normalized_documents[0]
    normalized = (
        tmp_path
        / "data"
        / "normalized"
        / "phase2"
        / document.snapshot_id
        / f"{document.document_id}.json"
    )
    normalized.write_bytes(normalized.read_bytes() + b" ")

    with pytest.raises(CaptureError, match="does not replay exactly"):
        load_phase2_materialized_corpus(tmp_path)


@pytest.mark.parametrize(
    "relative_path",
    [
        PHASE2_SNAPSHOT_MANIFEST_PATH,
        PHASE2_SOURCE_EVIDENCE_PATH,
    ],
)
def test_real_slice_loader_cross_binds_redundant_metadata_views(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    _bind_real_session(tmp_path, result, monkeypatch)
    path = tmp_path / relative_path
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(CaptureError, match="views do not match"):
        load_phase2_materialized_corpus(tmp_path)


def test_real_slice_loader_pins_session_ledger_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    _bind_real_session(tmp_path, result, monkeypatch)
    session_path = tmp_path / result.session_path
    session_path.write_bytes(session_path.read_bytes() + b" ")

    with pytest.raises(CaptureError, match="complete session"):
        load_phase2_materialized_corpus(tmp_path)


def test_real_slice_loader_rejects_linked_source_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    _bind_real_session(tmp_path, result, monkeypatch)
    raw_path = tmp_path / result.states[0].manifest.raw_blob_path
    outside = tmp_path / "outside.json"
    outside.write_bytes(raw_path.read_bytes())
    raw_path.unlink()
    try:
        raw_path.symlink_to(outside)
    except OSError:
        pytest.skip("this Windows environment cannot create a file symlink")

    with pytest.raises(CaptureError, match="traverses a link"):
        load_phase2_materialized_corpus(tmp_path)


def test_materialization_revalidates_post_construction_session_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    bundle.evidence.resources.append(bundle.evidence.resources[0])

    with pytest.raises(CaptureError, match="final session revalidation"):
        materialize_phase2_capture(tmp_path, bundle)

    assert not (tmp_path / "data").exists()


def test_capture_failure_persists_only_redacted_terminal_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempt = AttemptRecord(
        1,
        NOW,
        NOW + timedelta(seconds=1),
        "http_other",
        404,
        None,
    )

    def fail_fetch(_spec: Any) -> CapturedResponse:
        raise CaptureError("untrusted exception text", attempts=(attempt,))

    monkeypatch.setattr(session_module, "fetch_https", fail_fetch)
    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()
    failure = exc_info.value

    def fail_session() -> Any:
        raise failure

    monkeypatch.setattr(
        materialize_module,
        "run_phase2_capture_session",
        fail_session,
    )
    with pytest.raises(Phase2CaptureSessionError):
        capture_and_materialize_phase2(tmp_path)

    session_files = list(
        (tmp_path / "data" / "manifests" / "phase2-capture-sessions").glob("*.json")
    )
    assert len(session_files) == 1
    rendered = session_files[0].read_text()
    assert '"status":"failed"' in rendered
    assert "untrusted exception text" not in rendered
    assert not (tmp_path / "data" / "raw").exists()
    assert not (tmp_path / PHASE2_SNAPSHOT_MANIFEST_PATH).exists()
    assert not (tmp_path / PHASE2_SOURCE_EVIDENCE_PATH).exists()


def test_red_hat_semantic_failure_persists_stable_code_without_raw_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(_red_hat_raw())
    payload["document"]["tracking"]["version"] = "9" * 5_000
    invalid = json.dumps(payload).encode()
    responses = iter(
        (
            _response(0, _nvd_raw()),
            _response(1, _kev_raw()),
            _response(2, _kev_lineage_raw()),
            _response(3, invalid),
            _response(4, _checksum(invalid)),
        )
    )
    monkeypatch.setattr(session_module, "fetch_https", lambda _spec: next(responses))
    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()
    failure = exc_info.value

    def fail_session() -> Any:
        raise failure

    monkeypatch.setattr(
        materialize_module,
        "run_phase2_capture_session",
        fail_session,
    )

    with pytest.raises(Phase2CaptureSessionError):
        capture_and_materialize_phase2(tmp_path)

    session_files = list(
        (tmp_path / "data" / "manifests" / "phase2-capture-sessions").glob("*.json")
    )
    assert len(session_files) == 1
    persisted_text = session_files[0].read_text()
    persisted = json.loads(persisted_text)
    assert persisted["version"] == "phase2-capture-session-v2"
    assert persisted["failure"]["code"] == "red_hat_revision_metadata_validation"
    assert "9" * 64 not in persisted_text
    assert not (tmp_path / "data" / "raw").exists()
    assert not (tmp_path / "data" / "normalized").exists()


def test_complete_transport_session_survives_materialization_validation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)

    def fail_records(_bundle: Any) -> Any:
        raise CaptureError("validation stopped")

    monkeypatch.setattr(
        materialize_module,
        "_source_records",
        fail_records,
    )

    with pytest.raises(CaptureError, match="validation stopped"):
        materialize_phase2_capture(tmp_path, bundle)

    session_path = (
        tmp_path
        / "data"
        / "manifests"
        / "phase2-capture-sessions"
        / f"{bundle.evidence.session_id}.json"
    )
    assert '"status":"complete"' in session_path.read_text()
    assert not (tmp_path / "data" / "raw").exists()


def test_metadata_views_recover_from_envelope_after_second_view_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    original_put = materialize_module.ImmutableBlobStore.put_bytes
    injected = False

    def fail_second_view(
        self: Any,
        relative_path: str,
        data: bytes,
        *,
        expected_sha256: str | None = None,
    ) -> Any:
        nonlocal injected
        if relative_path == PHASE2_SOURCE_EVIDENCE_PATH and not injected:
            injected = True
            raise OSError("simulated interrupted metadata view")
        return original_put(
            self,
            relative_path,
            data,
            expected_sha256=expected_sha256,
        )

    monkeypatch.setattr(
        materialize_module.ImmutableBlobStore,
        "put_bytes",
        fail_second_view,
    )
    with pytest.raises(OSError, match="simulated interrupted"):
        materialize_phase2_capture(tmp_path, bundle)

    assert (tmp_path / PHASE2_METADATA_ENVELOPE_PATH).is_file()
    assert (tmp_path / PHASE2_SNAPSHOT_MANIFEST_PATH).is_file()
    assert not (tmp_path / PHASE2_SOURCE_EVIDENCE_PATH).exists()

    monkeypatch.setattr(
        materialize_module.ImmutableBlobStore,
        "put_bytes",
        original_put,
    )
    recover_phase2_metadata_views(tmp_path)
    assert (tmp_path / PHASE2_SNAPSHOT_MANIFEST_PATH).read_text().count("\n") == 3
    assert (tmp_path / PHASE2_SOURCE_EVIDENCE_PATH).read_text().count("\n") == 3


@pytest.mark.parametrize(
    "session_id",
    [
        "../outside",
        "C:/outside",
        r"..\outside",
        "phase2-capture-not-hex",
    ],
)
def test_metadata_recovery_rejects_unsafe_or_malformed_session_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_id: str,
) -> None:
    result = materialize_phase2_capture(tmp_path, _bundle(monkeypatch))
    envelope_path = tmp_path / PHASE2_METADATA_ENVELOPE_PATH
    payload = json.loads(envelope_path.read_text())
    payload["session_id"] = session_id
    envelope_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CaptureError, match="recovery source"):
        recover_phase2_metadata_views(tmp_path)

    assert (tmp_path / result.session_path).is_file()
