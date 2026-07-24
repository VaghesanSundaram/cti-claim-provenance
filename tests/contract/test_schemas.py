from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.claims.schema import (
    AtomicClaim,
    ClaimAnswer,
    ClaimEvidenceAnswer,
    ClaimObject,
    ClaimQualifiers,
    ClaimSubject,
)
from cti_provenance.cli import SCHEMA_MODELS, check_schemas
from cti_provenance.normalize.common import EvidenceSpan, NormalizedDocument
from cti_provenance.snapshot.manifest import SnapshotManifest

ROOT = Path(__file__).resolve().parents[2]
UTC_NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
SHA_A = "a" * 64


def _claim(**overrides: object) -> AtomicClaim:
    data: dict[str, object] = {
        "claim_id": "generated-1",
        "subject": ClaimSubject(type="cve", id="CVE-SYNTHETIC-0001"),
        "predicate": "kev.is_member",
        "object": ClaimObject(value=True, datatype="boolean"),
        "qualifiers": ClaimQualifiers(
            authority="cisa_kev",
            cvss_version=None,
            product=None,
            ecosystem=None,
        ),
        "evidence_ids": [],
        "confidence": 0.9,
    }
    data.update(overrides)
    return AtomicClaim.model_validate(data)


def test_all_six_checked_in_schemas_are_current_and_valid_json() -> None:
    assert set(path.name for path in (ROOT / "schemas").glob("*.schema.json")) == set(
        SCHEMA_MODELS
    )
    assert check_schemas(ROOT / "schemas") == []
    for filename in SCHEMA_MODELS:
        schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def test_claim_answer_round_trip_and_condition_cardinality() -> None:
    answer = ClaimAnswer(
        answer_id="answer-1",
        run_id="run-1",
        case_id="case-1",
        as_of=UTC_NOW,
        claims=[_claim()],
        abstained=False,
        abstention_reason=None,
        narrative=None,
    )
    assert ClaimAnswer.model_validate_json(answer.model_dump_json()) == answer

    constrained = answer.model_dump(mode="python")
    with pytest.raises(ValidationError):
        ClaimEvidenceAnswer.model_validate(constrained)
    constrained["claims"][0]["evidence_ids"] = ["doc-1:span-1"]
    assert ClaimEvidenceAnswer.model_validate(constrained).claims[0].evidence_ids


def test_unknown_fields_duplicate_claim_ids_and_non_utc_dates_are_rejected() -> None:
    answer_data = {
        "answer_id": "answer-1",
        "run_id": "run-1",
        "case_id": "case-1",
        "as_of": "2026-07-18T08:00:00-04:00",
        "claims": [],
        "abstained": False,
        "abstention_reason": None,
        "narrative": None,
        "unexpected": True,
    }
    with pytest.raises(ValidationError):
        ClaimAnswer.model_validate(answer_data)

    answer_data.pop("unexpected")
    with pytest.raises(ValidationError):
        ClaimAnswer.model_validate(answer_data)

    answer_data["as_of"] = UTC_NOW
    answer_data["claims"] = [_claim(), _claim()]
    with pytest.raises(ValidationError, match="claim_id"):
        ClaimAnswer.model_validate(answer_data)


def test_provider_scalar_types_are_not_coerced() -> None:
    answer_data = {
        "answer_id": "answer-1",
        "run_id": "run-1",
        "case_id": "case-1",
        "as_of": UTC_NOW,
        "claims": [],
        "abstained": "false",
        "abstention_reason": None,
        "narrative": None,
    }
    with pytest.raises(ValidationError):
        ClaimAnswer.model_validate(answer_data)

    claim_data = _claim().model_dump(mode="python")
    claim_data["confidence"] = "0.9"
    with pytest.raises(ValidationError):
        AtomicClaim.model_validate(claim_data)

    claim_data = _claim().model_dump(mode="python")
    claim_data["predicate"] = "cve.has_reference"
    with pytest.raises(ValidationError):
        AtomicClaim.model_validate(claim_data)

    claim_data = _claim().model_dump(mode="python")
    claim_data["qualifiers"]["authority"] = "   "
    with pytest.raises(ValidationError):
        AtomicClaim.model_validate(claim_data)


def test_snapshot_manifest_rejects_bad_hash_path_and_observed_time_mismatch() -> None:
    base: dict[str, object] = {
        "snapshot_id": "snapshot-1",
        "source_name": "nvd",
        "source_class": "government",
        "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "retrieved_at_utc": UTC_NOW,
        "http_status": 200,
        "http_etag": None,
        "http_last_modified": None,
        "effective_date_if_known": None,
        "effective_date_basis": "unknown",
        "available_by_utc": UTC_NOW,
        "available_by_basis": "observed_retrieval",
        "upstream_identifier": "CVE-SYNTHETIC-0001",
        "upstream_version": None,
        "media_type": "application/json",
        "byte_length": 10,
        "sha256": SHA_A,
        "raw_blob_path": "data/raw/aa/blob",
        "fetcher_version": "fetcher-v1",
        "normalization_version": "normalize-v1",
        "license_or_terms_note": "metadata-only release default",
    }
    manifest = SnapshotManifest.model_validate(base)
    assert SnapshotManifest.model_validate_json(manifest.model_dump_json()) == manifest

    for key, value in (
        ("sha256", "A" * 64),
        ("raw_blob_path", "../outside"),
        (
            "available_by_utc",
            datetime(2026, 7, 18, 12, 1, tzinfo=UTC),
        ),
    ):
        invalid = {**base, key: value}
        with pytest.raises(ValidationError):
            SnapshotManifest.model_validate(invalid)


def test_normalized_document_validates_span_bounds_and_hashes() -> None:
    text = "Known exploited vulnerability"
    span_text = "exploited"
    start = text.index(span_text)
    span = EvidenceSpan(
        span_id="span-1",
        field_path="/description",
        start_char=start,
        end_char=start + len(span_text),
        text_sha256=hashlib.sha256(span_text.encode()).hexdigest(),
        raw_locator="/descriptions/0/value",
        raw_locator_unavailable_reason=None,
        raw_snapshot_id="snapshot-1",
        raw_snapshot_sha256=SHA_A,
        normalization_version="normalize-v1",
    )
    document = NormalizedDocument(
        document_id="doc-1",
        snapshot_id="snapshot-1",
        upstream_entity_id="CVE-SYNTHETIC-0001",
        title=None,
        canonical_url="https://example.invalid/CVE-SYNTHETIC-0001",
        published_at=UTC_NOW,
        modified_at=None,
        source_name="nvd",
        source_class="government",
        normalization_version="normalize-v1",
        normalized_text=text,
        normalized_text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        fields={"published": "2026-07-18T12:00:00Z"},
        spans=[span],
    )
    assert (
        NormalizedDocument.model_validate_json(document.model_dump_json()) == document
    )

    invalid = document.model_dump(mode="python")
    invalid["spans"][0]["end_char"] = len(text) + 1
    with pytest.raises(ValidationError, match="bounds"):
        NormalizedDocument.model_validate(invalid)

    invalid = document.model_dump(mode="python")
    invalid["source_class"] = "vendor"
    with pytest.raises(ValidationError, match="configured source_class"):
        NormalizedDocument.model_validate(invalid)


def test_decimal_claim_does_not_accept_a_string_value() -> None:
    with pytest.raises(ValidationError):
        ClaimObject(value="9.8", datatype="decimal")
    assert ClaimObject(value=Decimal("9.8"), datatype="decimal").value == Decimal("9.8")
