from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import cti_provenance.ingest.session as session_module
from cti_provenance.ingest.base import (
    AttemptEvidence,
    AttemptRecord,
    CapturedResponse,
    CaptureError,
    FetchSpec,
    request_fingerprint,
)
from cti_provenance.ingest.kev import (
    KEV_COMMIT,
    KEV_COMMIT_TIME,
    kev_evidence_record,
    kev_state,
)
from cti_provenance.ingest.nvd import (
    SELECTED_CVE,
    nvd_evidence_record,
    nvd_state,
)
from cti_provenance.ingest.session import (
    PHASE2_CAPTURE_RESOURCES,
    PHASE2_RESOURCE_IDS,
    CaptureFailure,
    Phase2CaptureSessionError,
    Phase2CaptureSessionEvidence,
    ResourceCaptureLedger,
    bind_phase2_capture_artifacts,
    render_capture_session_json,
    run_phase2_capture_session,
    validate_phase2_capture_plan,
)
from cti_provenance.ingest.vendor import red_hat_evidence_record, red_hat_state

NOW = datetime(2026, 7, 18, 12, tzinfo=UTC)


def _nvd_raw() -> bytes:
    return json.dumps(
        {
            "format": "NVD_CVE",
            "version": "2.0",
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": SELECTED_CVE}}],
        }
    ).encode()


def _kev_raw() -> bytes:
    return json.dumps(
        {
            "catalogVersion": "2026.07.16",
            "dateReleased": "2026-07-16T19:11:42Z",
            "vulnerabilities": [{"cveID": SELECTED_CVE}],
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


def _red_hat_raw(*, tracking_id: str = "RHSA-2021:5133") -> bytes:
    return json.dumps(
        {
            "document": {
                "category": "csaf_security_advisory",
                "tracking": {
                    "id": tracking_id,
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
            "vulnerabilities": [{"cve": SELECTED_CVE}],
        }
    ).encode()


def _checksum(raw: bytes) -> bytes:
    return f"{hashlib.sha256(raw).hexdigest()}  rhsa-2021_5133.json\n".encode()


def _response(
    resource_index: int,
    body: bytes,
    *,
    retry: bool = False,
) -> CapturedResponse:
    definition = PHASE2_CAPTURE_RESOURCES[resource_index]
    start = NOW + timedelta(seconds=resource_index * 20)
    if retry:
        attempts = (
            AttemptRecord(
                1,
                start,
                start + timedelta(seconds=1),
                "transport_error",
                None,
                definition.spec.retry_delay_seconds,
            ),
            AttemptRecord(
                2,
                start + timedelta(seconds=7),
                start + timedelta(seconds=8),
                "success",
                200,
                None,
            ),
        )
    else:
        attempts = (
            AttemptRecord(
                1,
                start,
                start + timedelta(seconds=1),
                "success",
                200,
                None,
            ),
        )
    return CapturedResponse(
        definition.spec.url,
        200,
        body,
        {"content-type": "application/json"},
        attempts[-1].finished_at_utc,
        attempts,
    )


def _valid_responses(
    *,
    red_hat_raw: bytes | None = None,
    checksum_raw: bytes | None = None,
) -> list[CapturedResponse]:
    vendor_raw = red_hat_raw or _red_hat_raw()
    return [
        _response(0, _nvd_raw(), retry=True),
        _response(1, _kev_raw()),
        _response(2, _kev_lineage_raw()),
        _response(3, vendor_raw),
        _response(4, checksum_raw or _checksum(vendor_raw)),
    ]


def _install_fake_fetcher(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[CapturedResponse | CaptureError],
) -> list[str]:
    calls: list[str] = []
    outcomes = iter(responses)

    def fake_fetch(spec: Any) -> CapturedResponse:
        calls.append(spec.url)
        outcome = next(outcomes)
        if isinstance(outcome, CaptureError):
            raise outcome
        return outcome

    monkeypatch.setattr(session_module, "fetch_https", fake_fetch)
    return calls


def test_fixed_capture_session_succeeds_and_cross_binds_source_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validate_phase2_capture_plan()
    responses = _valid_responses()
    calls = _install_fake_fetcher(monkeypatch, responses)
    bundle = run_phase2_capture_session()

    assert calls == [resource.spec.url for resource in PHASE2_CAPTURE_RESOURCES]
    assert bundle.evidence.status == "complete"
    assert [resource.resource_id for resource in bundle.evidence.resources] == list(
        PHASE2_RESOURCE_IDS
    )
    assert sum(len(resource.attempts) for resource in bundle.evidence.resources) == 6

    nvd_snapshot = nvd_state(bundle.nvd_primary)
    kev_snapshot = kev_state(bundle.kev_catalog, bundle.kev_lineage)
    vendor_snapshot = red_hat_state(bundle.red_hat_primary, bundle.red_hat_checksum)
    records = [
        nvd_evidence_record(bundle.nvd_primary, nvd_snapshot),
        kev_evidence_record(bundle.kev_catalog, bundle.kev_lineage, kev_snapshot),
        red_hat_evidence_record(
            bundle.red_hat_primary,
            bundle.red_hat_checksum,
            vendor_snapshot,
        ),
    ]
    bind_phase2_capture_artifacts(bundle.evidence, records)

    rendered = render_capture_session_json(bundle.evidence)
    assert "response_sha256" in rendered
    assert "body" not in rendered
    assert Phase2CaptureSessionEvidence.model_validate_json(rendered) == bundle.evidence
    assert rendered == render_capture_session_json(bundle.evidence)

    changed_artifact = (
        records[0].artifacts[0].model_copy(update={"request_fingerprint": "0" * 64})
    )
    changed_record = records[0].model_copy(update={"artifacts": [changed_artifact]})
    with pytest.raises(CaptureError, match="cross-bind"):
        bind_phase2_capture_artifacts(
            bundle.evidence,
            [changed_record, records[1], records[2]],
        )
    with pytest.raises(CaptureError, match="exactly three"):
        bind_phase2_capture_artifacts(bundle.evidence, [*records, records[0]])


@pytest.mark.parametrize(
    ("outcome", "status", "expected_stage", "expected_code"),
    [
        ("transport_error", None, "transport", "transport_exhausted"),
        ("http_429", 429, "http", "http_429_exhausted"),
        ("http_5xx", 503, "http", "http_5xx_exhausted"),
        ("http_other", 404, "http", "http_other"),
        ("redirect", 302, "redirect", "redirect_rejected"),
        ("response_rejected", 200, "response", "response_rejected"),
    ],
)
def test_terminal_fetch_failures_serialize_without_raw_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    status: int | None,
    expected_stage: str,
    expected_code: str,
) -> None:
    attempt = AttemptRecord(
        1,
        NOW,
        NOW + timedelta(seconds=1),
        outcome,  # type: ignore[arg-type]
        status,
        None,
    )
    calls = _install_fake_fetcher(
        monkeypatch,
        [CaptureError("redacted failure", attempts=(attempt,))],
    )
    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()

    evidence = exc_info.value.evidence
    assert len(calls) == 1
    assert evidence.status == "failed"
    assert evidence.failure is not None
    assert evidence.failure.stage == expected_stage
    assert evidence.failure.code == expected_code
    assert evidence.resources[-1].response_sha256 is None
    assert "data/raw" not in render_capture_session_json(evidence)


@pytest.mark.parametrize(
    ("resource_index", "body", "expected_code"),
    [
        (0, b"{}", "nvd_validation"),
        (1, b"{}", "kev_catalog_validation"),
        (2, b"{}", "kev_lineage_validation"),
        (4, b"invalid checksum", "red_hat_checksum_validation"),
    ],
)
def test_semantic_failures_stop_the_fixed_plan_and_remain_serializable(
    monkeypatch: pytest.MonkeyPatch,
    resource_index: int,
    body: bytes,
    expected_code: str,
) -> None:
    responses = _valid_responses()
    responses[resource_index] = _response(resource_index, body)
    calls = _install_fake_fetcher(monkeypatch, responses)
    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()

    evidence = exc_info.value.evidence
    assert len(calls) == resource_index + 1
    assert evidence.failure is not None
    assert evidence.failure.stage == "validation"
    assert evidence.failure.code == expected_code
    assert evidence.resources[-1].transport_status == "success"
    assert Phase2CaptureSessionEvidence.model_validate_json(
        render_capture_session_json(evidence)
    )


def test_red_hat_identity_failure_is_distinct_from_checksum_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = _red_hat_raw(tracking_id="RHSA-2099:0001")
    calls = _install_fake_fetcher(monkeypatch, _valid_responses(red_hat_raw=invalid))
    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()
    assert len(calls) == 5
    assert exc_info.value.evidence.failure == CaptureFailure(
        resource_id="red_hat_checksum",
        stage="validation",
        code="red_hat_csaf_identity_validation",
    )


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("json", "red_hat_json_validation"),
        ("identity", "red_hat_csaf_identity_validation"),
        ("revision_metadata", "red_hat_revision_metadata_validation"),
        ("revision_history", "red_hat_revision_history_validation"),
        ("selected_cve", "red_hat_selected_cve_validation"),
    ],
)
def test_red_hat_semantic_failures_persist_only_stable_redacted_domains(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_code: str,
) -> None:
    if mutation == "json":
        invalid = b"{"
    else:
        payload = json.loads(_red_hat_raw())
        tracking = payload["document"]["tracking"]
        if mutation == "identity":
            tracking["status"] = "RAW-SEMANTIC-SENTINEL"
        elif mutation == "revision_metadata":
            tracking["version"] = "03"
        elif mutation == "revision_history":
            tracking["revision_history"] = []
        else:
            payload["vulnerabilities"][0]["cve"] = "CVE-2099-0001"
        invalid = json.dumps(payload).encode()
    calls = _install_fake_fetcher(
        monkeypatch,
        _valid_responses(red_hat_raw=invalid),
    )

    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()

    evidence = exc_info.value.evidence
    assert len(calls) == 5
    assert evidence.version == "phase2-capture-session-v2"
    assert evidence.failure == CaptureFailure(
        resource_id="red_hat_checksum",
        stage="validation",
        code=expected_code,  # type: ignore[arg-type]
    )
    assert evidence.resources[-1].transport_status == "success"
    rendered = render_capture_session_json(evidence)
    assert "Red Hat " not in rendered
    assert "RAW-SEMANTIC-SENTINEL" not in rendered
    assert Phase2CaptureSessionEvidence.model_validate_json(rendered) == evidence


def test_detailed_red_hat_failure_requires_v2_evidence_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = _red_hat_raw(tracking_id="RHSA-2099:0001")
    _install_fake_fetcher(monkeypatch, _valid_responses(red_hat_raw=invalid))
    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()
    payload = exc_info.value.evidence.model_dump()
    payload["version"] = "phase2-capture-session-v1"

    with pytest.raises(ValidationError, match="require capture-session v2"):
        Phase2CaptureSessionEvidence.model_validate(payload)


def test_typed_red_hat_exception_message_never_enters_session_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = _valid_responses()
    _install_fake_fetcher(monkeypatch, responses)

    def fail_with_sentinel(_raw: bytes, _checksum: bytes) -> dict[str, Any]:
        raise session_module.RedHatAdvisoryValidationError(
            "red_hat_revision_history_validation",
            "EXCEPTION-MESSAGE-SENTINEL",
        )

    monkeypatch.setattr(session_module, "parse_red_hat_bytes", fail_with_sentinel)
    with pytest.raises(Phase2CaptureSessionError) as exc_info:
        run_phase2_capture_session()

    rendered = render_capture_session_json(exc_info.value.evidence)
    assert "EXCEPTION-MESSAGE-SENTINEL" not in rendered
    assert '"code":"red_hat_revision_history_validation"' in rendered


def test_tracked_legacy_red_hat_failure_ledger_remains_byte_stable() -> None:
    root = Path(__file__).resolve().parents[2]
    path = (
        root
        / "data"
        / "manifests"
        / "phase2-capture-sessions"
        / "phase2-capture-5741247aa56985af2664.json"
    )
    rendered = path.read_text(encoding="utf-8")
    assert (
        hashlib.sha256(rendered.encode()).hexdigest()
        == "6734e774616ff8561adfb7c8c0abdb52d5bd8d71d006a48dde8d2e0d6e973166"
    )
    evidence = Phase2CaptureSessionEvidence.model_validate_json(rendered)
    assert evidence.failure == CaptureFailure(
        resource_id="red_hat_checksum",
        stage="validation",
        code="red_hat_advisory_validation",
    )
    assert render_capture_session_json(evidence) == rendered


def _two_attempt_ledger(
    resource_index: int,
    *,
    start: datetime,
) -> ResourceCaptureLedger:
    definition = PHASE2_CAPTURE_RESOURCES[resource_index]
    retry_finished = start + timedelta(seconds=1)
    success_started = retry_finished + timedelta(
        seconds=definition.spec.retry_delay_seconds
    )
    attempts = [
        AttemptEvidence(
            attempt_number=1,
            started_at_utc=start,
            finished_at_utc=retry_finished,
            outcome="transport_error",
            status=None,
            retry_delay_seconds=definition.spec.retry_delay_seconds,
        ),
        AttemptEvidence(
            attempt_number=2,
            started_at_utc=success_started,
            finished_at_utc=success_started + timedelta(seconds=1),
            outcome="success",
            status=200,
            retry_delay_seconds=None,
        ),
    ]
    return ResourceCaptureLedger(
        resource_id=definition.resource_id,
        request_url=definition.spec.url,
        request_fingerprint=request_fingerprint(definition.spec.url),
        attempts=attempts,
        transport_status="success",
        response_sha256="a" * 64,
        response_byte_length=1,
        retrieved_at_utc=attempts[-1].finished_at_utc,
    )


def test_session_contract_rejects_missing_duplicate_unknown_and_eleventh_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_fetcher(monkeypatch, _valid_responses())
    evidence = run_phase2_capture_session().evidence
    payload = evidence.model_dump()
    payload["resources"] = payload["resources"][:-1]
    payload["finished_at_utc"] = payload["resources"][-1]["attempts"][-1][
        "finished_at_utc"
    ]
    with pytest.raises(ValidationError, match="all five"):
        Phase2CaptureSessionEvidence.model_validate(payload)

    payload = evidence.model_dump()
    payload["resources"][1]["resource_id"] = "nvd_primary"
    with pytest.raises(ValidationError):
        Phase2CaptureSessionEvidence.model_validate(payload)

    payload = evidence.model_dump()
    payload["resources"][0]["resource_id"] = "unknown"
    with pytest.raises(ValidationError):
        Phase2CaptureSessionEvidence.model_validate(payload)

    ledgers = [
        _two_attempt_ledger(
            index,
            start=NOW + timedelta(seconds=index * 10),
        )
        for index in range(5)
    ]
    ledgers.append(_two_attempt_ledger(4, start=NOW + timedelta(seconds=50)))
    with pytest.raises(ValidationError, match="ten-attempt"):
        Phase2CaptureSessionEvidence(
            version="phase2-capture-session-v1",
            capture_policy_version="phase2-capture-policy-v1",
            session_id=session_module._session_id(NOW),
            started_at_utc=NOW,
            finished_at_utc=ledgers[-1].attempts[-1].finished_at_utc,
            status="failed",
            resources=ledgers,
            failure=CaptureFailure(
                resource_id="red_hat_checksum",
                stage="validation",
                code="red_hat_advisory_validation",
            ),
        )


def test_failed_resource_rejects_response_metadata_and_nvd_short_retry() -> None:
    definition = PHASE2_CAPTURE_RESOURCES[0]
    failed_attempt = AttemptEvidence(
        attempt_number=1,
        started_at_utc=NOW,
        finished_at_utc=NOW + timedelta(seconds=1),
        outcome="http_other",
        status=404,
        retry_delay_seconds=None,
    )
    with pytest.raises(ValidationError, match="only successful"):
        ResourceCaptureLedger(
            resource_id="nvd_primary",
            request_url=definition.spec.url,
            request_fingerprint=request_fingerprint(definition.spec.url),
            attempts=[failed_attempt],
            transport_status="failed",
            response_sha256="a" * 64,
            response_byte_length=1,
            retrieved_at_utc=failed_attempt.finished_at_utc,
        )
    with pytest.raises(ValidationError, match="entirely present or absent"):
        ResourceCaptureLedger(
            resource_id="nvd_primary",
            request_url=definition.spec.url,
            request_fingerprint=request_fingerprint(definition.spec.url),
            attempts=[failed_attempt],
            transport_status="failed",
            response_sha256=None,
            response_byte_length=1,
            retrieved_at_utc=None,
        )

    first = AttemptEvidence(
        attempt_number=1,
        started_at_utc=NOW,
        finished_at_utc=NOW + timedelta(seconds=1),
        outcome="transport_error",
        status=None,
        retry_delay_seconds=1,
    )
    second = AttemptEvidence(
        attempt_number=2,
        started_at_utc=NOW + timedelta(seconds=2),
        finished_at_utc=NOW + timedelta(seconds=3),
        outcome="success",
        status=200,
        retry_delay_seconds=None,
    )
    with pytest.raises(ValidationError, match="required minimum"):
        ResourceCaptureLedger(
            resource_id="nvd_primary",
            request_url=definition.spec.url,
            request_fingerprint=request_fingerprint(definition.spec.url),
            attempts=[first, second],
            transport_status="success",
            response_sha256="a" * 64,
            response_byte_length=1,
            retrieved_at_utc=second.finished_at_utc,
        )


def test_attempt_history_rejects_retry_before_declared_delay_elapsed() -> None:
    definition = PHASE2_CAPTURE_RESOURCES[0]
    first = AttemptEvidence(
        attempt_number=1,
        started_at_utc=NOW,
        finished_at_utc=NOW + timedelta(seconds=1),
        outcome="transport_error",
        status=None,
        retry_delay_seconds=6,
    )
    early_second = AttemptEvidence(
        attempt_number=2,
        started_at_utc=NOW + timedelta(seconds=2),
        finished_at_utc=NOW + timedelta(seconds=3),
        outcome="success",
        status=200,
        retry_delay_seconds=None,
    )
    with pytest.raises(ValidationError, match="declared delay"):
        ResourceCaptureLedger(
            resource_id="nvd_primary",
            request_url=definition.spec.url,
            request_fingerprint=request_fingerprint(definition.spec.url),
            attempts=[first, early_second],
            transport_status="success",
            response_sha256="a" * 64,
            response_byte_length=1,
            retrieved_at_utc=early_second.finished_at_utc,
        )


def test_preflight_rejects_spec_substitution_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = PHASE2_CAPTURE_RESOURCES[0]
    substituted = session_module.CaptureResourceDefinition(
        original.resource_id,
        FetchSpec(
            url="https://example.test/not-nvd",
            allowed_host="example.test",
            allowed_path="/not-nvd",
        ),
    )
    monkeypatch.setattr(
        session_module,
        "PHASE2_CAPTURE_RESOURCES",
        (substituted, *PHASE2_CAPTURE_RESOURCES[1:]),
    )
    monkeypatch.setattr(
        session_module,
        "fetch_https",
        lambda _spec: pytest.fail("substituted plan must fail before fetch"),
    )
    with pytest.raises(CaptureError, match="frozen five/ten plan"):
        run_phase2_capture_session()


def test_failure_code_is_bound_to_exact_stage_and_validation_resource() -> None:
    with pytest.raises(ValidationError, match="stage and code"):
        CaptureFailure(
            resource_id="nvd_primary",
            stage="http",
            code="redirect_rejected",
        )
    with pytest.raises(ValidationError, match="does not match"):
        CaptureFailure(
            resource_id="red_hat_checksum",
            stage="validation",
            code="nvd_validation",
        )


@pytest.mark.parametrize(
    "code",
    [
        "red_hat_json_validation",
        "red_hat_csaf_identity_validation",
        "red_hat_revision_metadata_validation",
        "red_hat_revision_history_validation",
        "red_hat_selected_cve_validation",
    ],
)
def test_red_hat_semantic_codes_bind_to_terminal_validation_resource(
    code: str,
) -> None:
    with pytest.raises(ValidationError, match="stage and code"):
        CaptureFailure(
            resource_id="red_hat_checksum",
            stage="http",
            code=code,  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="does not match"):
        CaptureFailure(
            resource_id="nvd_primary",
            stage="validation",
            code=code,  # type: ignore[arg-type]
        )


def test_failed_session_rejects_prior_failure_and_false_terminal_code() -> None:
    definition = PHASE2_CAPTURE_RESOURCES[0]
    failed_attempt = AttemptEvidence(
        attempt_number=1,
        started_at_utc=NOW,
        finished_at_utc=NOW + timedelta(seconds=1),
        outcome="http_other",
        status=404,
        retry_delay_seconds=None,
    )
    failed = ResourceCaptureLedger(
        resource_id="nvd_primary",
        request_url=definition.spec.url,
        request_fingerprint=request_fingerprint(definition.spec.url),
        attempts=[failed_attempt],
        transport_status="failed",
        response_sha256=None,
        response_byte_length=None,
        retrieved_at_utc=None,
    )
    later_success = _two_attempt_ledger(
        1,
        start=NOW + timedelta(seconds=10),
    )
    with pytest.raises(ValidationError, match="terminal resource"):
        Phase2CaptureSessionEvidence(
            version="phase2-capture-session-v1",
            capture_policy_version="phase2-capture-policy-v1",
            session_id=session_module._session_id(NOW),
            started_at_utc=NOW,
            finished_at_utc=later_success.attempts[-1].finished_at_utc,
            status="failed",
            resources=[failed, later_success],
            failure=CaptureFailure(
                resource_id="kev_catalog",
                stage="validation",
                code="kev_catalog_validation",
            ),
        )

    with pytest.raises(ValidationError, match="final attempt outcome"):
        Phase2CaptureSessionEvidence(
            version="phase2-capture-session-v1",
            capture_policy_version="phase2-capture-policy-v1",
            session_id=session_module._session_id(NOW),
            started_at_utc=NOW,
            finished_at_utc=failed_attempt.finished_at_utc,
            status="failed",
            resources=[failed],
            failure=CaptureFailure(
                resource_id="nvd_primary",
                stage="redirect",
                code="redirect_rejected",
            ),
        )
