from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from cti_provenance.ingest.base import AttemptRecord, CapturedResponse, CaptureError
from cti_provenance.ingest.vendor import (
    RHSA_CHECKSUM_URL,
    RHSA_URL,
    RedHatAdvisoryValidationError,
    parse_red_hat_bytes,
    parse_red_hat_checksum,
    red_hat_evidence_record,
    red_hat_state,
    replay_red_hat_state,
)
from cti_provenance.snapshot import select_admissible_snapshot

NOW = datetime(2026, 7, 18, tzinfo=UTC)
RELEASE = datetime(2026, 6, 28, 12, 35, 37, tzinfo=UTC)


def _raw() -> bytes:
    return json.dumps(
        {
            "document": {
                "category": "csaf_security_advisory",
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
            "vulnerabilities": [{"cve": "CVE-2021-44228"}],
        }
    ).encode()


def _checksum(raw: bytes) -> bytes:
    return f"{hashlib.sha256(raw).hexdigest()}  rhsa-2021_5133.json\n".encode()


def _response(url: str, body: bytes, *, seconds: int) -> CapturedResponse:
    finished = NOW + timedelta(seconds=seconds)
    attempt = AttemptRecord(
        1, finished - timedelta(seconds=1), finished, "success", 200, None
    )
    return CapturedResponse(
        url,
        200,
        body,
        {"content-type": "application/json"},
        finished,
        (attempt,),
    )


@pytest.mark.parametrize(
    "checksum",
    [
        b"",
        b"0" * 64,
        b"0" * 64 + b"  other.json\n",
        b"0" * 64 + b"  rhsa-2021_5133.json\nextra",
        b"not-ascii-\xff",
    ],
)
def test_red_hat_checksum_parser_requires_one_exact_named_record(
    checksum: bytes,
) -> None:
    with pytest.raises(CaptureError, match="exact format"):
        parse_red_hat_checksum(checksum)


def test_red_hat_parser_rejects_bad_checksum_and_incomplete_history() -> None:
    raw = _raw()
    with pytest.raises(CaptureError, match="mismatch"):
        parse_red_hat_bytes(raw, f"{'0' * 64}  rhsa-2021_5133.json\n".encode())
    payload = json.loads(raw)
    del payload["document"]["tracking"]["revision_history"][-1]["summary"]
    changed = json.dumps(payload).encode()
    with pytest.raises(RedHatAdvisoryValidationError, match="incomplete") as exc_info:
        parse_red_hat_bytes(changed, _checksum(changed))
    assert exc_info.value.code == "red_hat_revision_history_validation"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("json", "red_hat_json_validation"),
        ("identity", "red_hat_csaf_identity_validation"),
        ("version", "red_hat_revision_metadata_validation"),
        ("current_date_missing", "red_hat_revision_metadata_validation"),
        ("current_date_non_utc", "red_hat_revision_metadata_validation"),
        ("history_missing", "red_hat_revision_history_validation"),
        ("history_date_invalid", "red_hat_revision_history_validation"),
        ("selected_cve_missing", "red_hat_selected_cve_validation"),
        ("selected_cve_duplicate", "red_hat_selected_cve_validation"),
    ],
)
def test_red_hat_parser_exposes_stable_redacted_semantic_domains(
    mutation: str,
    expected_code: str,
) -> None:
    if mutation == "json":
        raw = b"{"
    else:
        payload = json.loads(_raw())
        tracking = payload["document"]["tracking"]
        if mutation == "identity":
            tracking["status"] = "draft"
        elif mutation == "version":
            tracking["version"] = "03"
        elif mutation == "current_date_missing":
            del tracking["current_release_date"]
        elif mutation == "current_date_non_utc":
            tracking["current_release_date"] = "2026-06-28T12:35:37+01:00"
        elif mutation == "history_missing":
            tracking["revision_history"] = []
        elif mutation == "history_date_invalid":
            tracking["revision_history"][0]["date"] = "not-a-date"
        elif mutation == "selected_cve_missing":
            payload["vulnerabilities"][0]["cve"] = "CVE-2099-0001"
        else:
            payload["vulnerabilities"].append({"cve": "CVE-2021-44228"})
        raw = json.dumps(payload).encode()

    with pytest.raises(RedHatAdvisoryValidationError) as exc_info:
        parse_red_hat_bytes(raw, _checksum(raw))
    assert exc_info.value.code == expected_code


@pytest.mark.parametrize(
    "numbers",
    [
        ["1", "3"],
        ["1", "2", "2"],
        ["1", "3", "2"],
        ["99", "2", "3"],
    ],
)
def test_red_hat_parser_rejects_incomplete_or_invalid_revision_sequence(
    numbers: list[str],
) -> None:
    payload = json.loads(_raw())
    history = payload["document"]["tracking"]["revision_history"]
    if len(numbers) == 2:
        history.pop(1)
    for entry, number in zip(history, numbers, strict=True):
        entry["number"] = number
    raw = json.dumps(payload).encode()
    with pytest.raises(RedHatAdvisoryValidationError, match="inconsistent") as exc_info:
        parse_red_hat_bytes(raw, _checksum(raw))
    assert exc_info.value.code == "red_hat_revision_history_validation"


def test_red_hat_parser_allows_equal_adjacent_revision_dates() -> None:
    payload = json.loads(_raw())
    history = payload["document"]["tracking"]["revision_history"]
    history[1]["date"] = history[0]["date"]
    raw = json.dumps(payload).encode()

    parsed = parse_red_hat_bytes(raw, _checksum(raw))

    assert parsed["document"]["tracking"]["revision_history"] == history


def test_red_hat_parser_rejects_decreasing_revision_dates() -> None:
    payload = json.loads(_raw())
    history = payload["document"]["tracking"]["revision_history"]
    history[1]["date"] = "2021-12-14T00:00:00Z"
    raw = json.dumps(payload).encode()

    with pytest.raises(RedHatAdvisoryValidationError, match="inconsistent") as exc_info:
        parse_red_hat_bytes(raw, _checksum(raw))

    assert exc_info.value.code == "red_hat_revision_history_validation"


@pytest.mark.parametrize(
    ("field", "expected_code"),
    [
        ("version", "red_hat_revision_metadata_validation"),
        ("history_number", "red_hat_revision_history_validation"),
    ],
)
def test_red_hat_parser_contains_oversized_decimal_fields(
    field: str,
    expected_code: str,
) -> None:
    payload = json.loads(_raw())
    if field == "version":
        payload["document"]["tracking"]["version"] = "9" * 5_000
    else:
        payload["document"]["tracking"]["revision_history"][0]["number"] = "9" * 5_000
    raw = json.dumps(payload).encode()

    with pytest.raises(RedHatAdvisoryValidationError) as exc_info:
        parse_red_hat_bytes(raw, _checksum(raw))
    assert exc_info.value.code == expected_code


def test_red_hat_parser_contains_json_integer_conversion_limit() -> None:
    raw = _raw().replace(b'"version": "3"', b'"version": ' + b"9" * 5_000)
    with pytest.raises(RedHatAdvisoryValidationError) as exc_info:
        parse_red_hat_bytes(raw, _checksum(raw))
    assert exc_info.value.code == "red_hat_json_validation"


def test_red_hat_state_uses_final_revision_and_rejects_2021_cutoff() -> None:
    raw = _raw()
    primary = _response(RHSA_URL, raw, seconds=1)
    checksum = _response(RHSA_CHECKSUM_URL, _checksum(raw), seconds=2)
    state = red_hat_state(primary, checksum)
    assert state.manifest.available_by_utc == RELEASE
    assert (
        select_admissible_snapshot([state], datetime(2021, 12, 31, tzinfo=UTC)) is None
    )
    assert select_admissible_snapshot([state], RELEASE) == state.manifest


def test_red_hat_evidence_replays_checksum_and_revision_proof() -> None:
    raw = _raw()
    primary = _response(RHSA_URL, raw, seconds=1)
    checksum = _response(RHSA_CHECKSUM_URL, _checksum(raw), seconds=2)
    state = red_hat_state(primary, checksum)
    record = red_hat_evidence_record(primary, checksum, state)
    replayed = replay_red_hat_state(
        record,
        primary_body=raw,
        checksum_body=checksum.body,
    )
    assert replayed == state
    with pytest.raises(CaptureError, match="do not match"):
        replay_red_hat_state(
            record,
            primary_body=raw,
            checksum_body=checksum.body + b" ",
        )
