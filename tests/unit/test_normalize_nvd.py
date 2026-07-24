from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from cti_provenance.ingest.nvd import NVD_BASE_URL
from cti_provenance.normalize.nvd import normalize_nvd
from cti_provenance.normalize.spans import (
    resolve_json_pointer,
    resolve_span,
)
from cti_provenance.snapshot import SnapshotManifest


def _raw() -> bytes:
    return json.dumps(
        {
            "format": "NVD_CVE",
            "version": "2.0",
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "published": "2021-12-10T10:00:00Z",
                        "lastModified": "2021-12-11T10:00:00Z",
                        "descriptions": [
                            {"lang": "es", "value": "señuelo"},
                            {
                                "lang": "en",
                                "value": (
                                    "Repeated 2021-12-10T10:00:00Z and score 10.0"
                                ),
                            },
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {"baseScore": 1.0},
                                    "source": "vendor@example.test",
                                    "type": "Secondary",
                                },
                                {
                                    "cvssData": {"baseScore": 10.0},
                                    "source": "nvd@nist.gov",
                                    "type": "Primary",
                                },
                            ]
                        },
                    }
                }
            ],
        }
    ).encode()


def _manifest(raw: bytes) -> SnapshotManifest:
    observed = datetime(2026, 7, 18, tzinfo=UTC)
    return SnapshotManifest(
        snapshot_id="nvd-1",
        source_name="nvd",
        source_class="government",
        source_url=NVD_BASE_URL,
        retrieved_at_utc=observed,
        http_status=200,
        http_etag=None,
        http_last_modified=None,
        effective_date_if_known=None,
        effective_date_basis="unknown",
        available_by_utc=observed,
        available_by_basis="observed_retrieval",
        upstream_identifier="CVE-2021-44228",
        upstream_version=None,
        media_type="application/json",
        byte_length=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        raw_blob_path="data/raw/nvd/test.json",
        fetcher_version="phase2-capture-v1",
        normalization_version="phase2-nvd-v1",
        license_or_terms_note="test",
    )


def test_normalize_nvd_selects_named_metric_and_round_trips_every_span() -> None:
    raw = _raw()
    document = normalize_nvd(raw, _manifest(raw))[0]
    assert document.fields["cvss_v31_named_source"] == "nvd@nist.gov"
    assert document.fields["cvss_v31_base_score"] == 10.0
    cvss_span = next(span for span in document.spans if span.span_id == "nvd-cvss-v31")
    assert cvss_span.raw_locator is not None
    assert "/cvssMetricV31/1/" in cvss_span.raw_locator
    assert cvss_span.start_char == document.normalized_text.index(
        "10.0", document.normalized_text.index("CVSS v3.1 (NVD):")
    )
    published_span = next(
        span for span in document.spans if span.span_id == "nvd-published"
    )
    assert published_span.start_char == document.normalized_text.index(
        "2021-12-10T10:00:00Z",
        document.normalized_text.index("Published:"),
    )
    for span in document.spans:
        assert span.raw_locator is not None
        assert str(resolve_json_pointer(raw, span.raw_locator)) == resolve_span(
            span, document.normalized_text
        )


def test_normalize_nvd_rejects_manifest_hash_mismatch() -> None:
    raw = _raw()
    with pytest.raises(ValueError, match="capture"):
        normalize_nvd(raw + b" ", _manifest(raw))


def test_normalize_nvd_interprets_suffixless_api_times_as_utc() -> None:
    payload = json.loads(_raw())
    cve = payload["vulnerabilities"][0]["cve"]
    cve["published"] = "2021-12-10T10:00:00.143"
    cve["lastModified"] = "2026-06-17T04:12:05.460"
    raw = json.dumps(payload).encode()

    document = normalize_nvd(raw, _manifest(raw))[0]

    assert document.published_at == datetime(2021, 12, 10, 10, 0, 0, 143000, tzinfo=UTC)
    assert document.modified_at == datetime(2026, 6, 17, 4, 12, 5, 460000, tzinfo=UTC)


def test_normalize_nvd_rejects_nonzero_api_time_offset() -> None:
    payload = json.loads(_raw())
    payload["vulnerabilities"][0]["cve"]["published"] = "2021-12-10T10:00:00.143+01:00"
    raw = json.dumps(payload).encode()

    with pytest.raises(ValueError, match="zero UTC offset"):
        normalize_nvd(raw, _manifest(raw))


@pytest.mark.parametrize(
    "published",
    [
        "2021-12-10",
        "20211210",
        "2021-W49-5T10:00:00Z",
        "2021-12-10 10:00:00Z",
        "2021-12-10T10:00Z",
        "2021-12-10T10:00:00.1234567Z",
    ],
)
def test_normalize_nvd_rejects_timestamp_forms_outside_api_contract(
    published: str,
) -> None:
    payload = json.loads(_raw())
    payload["vulnerabilities"][0]["cve"]["published"] = published
    raw = json.dumps(payload).encode()

    with pytest.raises(ValueError, match="NVD API timestamp is invalid"):
        normalize_nvd(raw, _manifest(raw))
