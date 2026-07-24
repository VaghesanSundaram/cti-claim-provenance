from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from cti_provenance.ingest.base import AttemptRecord, CapturedResponse, CaptureError
from cti_provenance.ingest.kev import (
    KEV_COMMIT,
    KEV_COMMIT_TIME,
    KEV_COMPARE_URL,
    KEV_URL,
    kev_evidence_record,
    kev_state,
    parse_kev_bytes,
    parse_kev_lineage_bytes,
    replay_kev_state,
)
from cti_provenance.snapshot import select_admissible_snapshot

NOW = datetime(2026, 7, 18, tzinfo=UTC)


def _kev_raw() -> bytes:
    return json.dumps(
        {
            "catalogVersion": "2026.07.16",
            "dateReleased": "2026-07-16T19:11:42Z",
            "vulnerabilities": [{"cveID": "CVE-2021-44228"}],
        }
    ).encode()


def _lineage_raw(*, status: str = "ahead", sha: str = KEV_COMMIT) -> bytes:
    return json.dumps(
        {
            "status": status,
            "base_commit": {
                "sha": sha,
                "commit": {"committer": {"date": "2026-07-16T19:11:42Z"}},
            },
            "merge_base_commit": {"sha": sha},
        }
    ).encode()


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


def test_kev_parser_rejects_duplicate_selected_cve() -> None:
    payload = json.loads(_kev_raw())
    payload["vulnerabilities"].append({"cveID": "CVE-2021-44228"})
    with pytest.raises(CaptureError, match="exactly one"):
        parse_kev_bytes(json.dumps(payload).encode())


@pytest.mark.parametrize(
    ("status", "sha", "message"),
    [
        ("diverged", KEV_COMMIT, "not proven"),
        ("ahead", "0" * 40, "bind"),
    ],
)
def test_kev_lineage_requires_official_base_and_ancestry(
    status: str, sha: str, message: str
) -> None:
    with pytest.raises(CaptureError, match=message):
        parse_kev_lineage_bytes(_lineage_raw(status=status, sha=sha))


def test_kev_state_uses_stable_identity_and_commit_time_cutoff() -> None:
    primary = _response(KEV_URL, _kev_raw(), seconds=1)
    lineage = _response(KEV_COMPARE_URL, _lineage_raw(), seconds=2)
    state = kev_state(primary, lineage)
    assert state.manifest.upstream_identifier == "cisa-kev-catalog"
    assert state.manifest.available_by_utc == KEV_COMMIT_TIME
    assert (
        select_admissible_snapshot([state], datetime(2021, 12, 31, tzinfo=UTC)) is None
    )
    assert select_admissible_snapshot([state], KEV_COMMIT_TIME) == state.manifest


def test_kev_source_evidence_recomputes_verification_offline() -> None:
    primary = _response(KEV_URL, _kev_raw(), seconds=1)
    lineage = _response(KEV_COMPARE_URL, _lineage_raw(), seconds=2)
    state = kev_state(primary, lineage)
    record = kev_evidence_record(primary, lineage, state)
    replayed = replay_kev_state(
        record,
        primary_body=primary.body,
        lineage_body=lineage.body,
    )
    assert replayed == state
    assert replayed.cisa_evidence is not None
    assert replayed.cisa_evidence.ancestry_verified
    with pytest.raises(CaptureError, match="do not match"):
        replay_kev_state(
            record,
            primary_body=primary.body,
            lineage_body=lineage.body + b" ",
        )
