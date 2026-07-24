from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cti_provenance.claims.three_family import (
    ThreeFamilyError,
    _validate_evidence_snapshot_boundary,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.normalize import NormalizedDocument
from cti_provenance.normalize.versioned import (
    NORMALIZATION_VERSION,
    normalize_versioned_source,
)
from cti_provenance.snapshot import (
    PublisherVersionEvidence,
    SnapshotManifest,
    SnapshotState,
    select_admissible_snapshot,
)


def _manifest(
    *,
    source_name: str,
    source_class: str,
    source_url: str,
    snapshot_id: str,
    identifier: str,
    version: str,
    raw: bytes,
    available: datetime,
    media_type: str = "application/json",
) -> SnapshotManifest:
    return SnapshotManifest.model_validate(
        {
            "snapshot_id": snapshot_id,
            "source_name": source_name,
            "source_class": source_class,
            "source_url": source_url,
            "retrieved_at_utc": available + timedelta(days=1),
            "http_status": 200,
            "http_etag": None,
            "http_last_modified": None,
            "effective_date_if_known": available,
            "effective_date_basis": "publisher_version",
            "available_by_utc": available,
            "available_by_basis": "publisher_declared_version",
            "upstream_identifier": identifier,
            "upstream_version": version,
            "media_type": media_type,
            "byte_length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_blob_path": f"data/raw/test/{snapshot_id}.json",
            "fetcher_version": "test-v1",
            "normalization_version": NORMALIZATION_VERSION,
            "license_or_terms_note": "test fixture",
        }
    )


def test_cve_normalizer_extracts_exact_versions_and_rejects_hash_drift() -> None:
    payload = {
        "cveMetadata": {"dateUpdated": "2024-04-18T17:29:57.790Z"},
        "containers": {
            "cna": {
                "descriptions": [{"value": "xz affected versions"}],
                "affected": [
                    {
                        "defaultStatus": "unaffected",
                        "versions": [
                            {"status": "affected", "version": "5.6.0"},
                            {"status": "affected", "version": "5.6.1"},
                        ],
                    }
                ],
            }
        },
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    manifest = _manifest(
        source_name="cve_program",
        source_class="standards_body",
        source_url=(
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/"
            "f839db1bd8348c17381dbc47e8e08143c10dd756/cves/2024/3xxx/"
            "CVE-2024-3094.json"
        ),
        snapshot_id="test-cve",
        identifier="CVE-2024-3094",
        version="f839db1bd8348c17381dbc47e8e08143c10dd756",
        raw=raw,
        available=datetime(2024, 4, 18, 17, 33, 58, tzinfo=UTC),
    )
    document = normalize_versioned_source(manifest, raw)
    assert document.fields["affected_versions"] == ["5.6.0", "5.6.1"]
    assert [span.raw_locator for span in document.spans] == [
        "/containers/cna/affected/0/versions/0",
        "/containers/cna/affected/0/versions/1",
    ]
    assert [
        document.normalized_text[span.start_char : span.end_char]
        for span in document.spans
    ] == [
        '{"status":"affected","version":"5.6.0"}',
        '{"status":"affected","version":"5.6.1"}',
    ]
    with pytest.raises(ValueError, match=r"length|hash"):
        normalize_versioned_source(manifest, raw + b" ")


def test_publisher_version_state_is_cutoff_selected_and_fail_closed() -> None:
    raw = b"{}"
    available = datetime(2024, 4, 18, 17, 33, 58, tzinfo=UTC)
    manifest = _manifest(
        source_name="cve_program",
        source_class="standards_body",
        source_url=(
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/"
            "f839db1bd8348c17381dbc47e8e08143c10dd756/cves/2024/3xxx/"
            "CVE-2024-3094.json"
        ),
        snapshot_id="test-state",
        identifier="CVE-2024-3094",
        version="f839db1bd8348c17381dbc47e8e08143c10dd756",
        raw=raw,
        available=available,
    )
    evidence = PublisherVersionEvidence(
        version_identifier=manifest.upstream_version or "",
        publisher_declared_time_utc=available,
        independently_addressable=True,
    )
    state = SnapshotState(
        manifest=manifest,
        publisher_version_evidence=evidence,
    )
    assert select_admissible_snapshot([state], available - timedelta(seconds=1)) is None
    assert select_admissible_snapshot([state], available) == manifest

    invalid = SnapshotState(
        manifest=manifest,
        publisher_version_evidence=PublisherVersionEvidence(
            version_identifier=manifest.upstream_version or "",
            publisher_declared_time_utc=available,
            independently_addressable=False,
        ),
    )
    with pytest.raises(ValueError, match="invalid cve_program"):
        select_admissible_snapshot([invalid], available)


def test_cisa_and_netscaler_html_normalizers_extract_exact_targets() -> None:
    cisa_action = (
        "As soon as possible and no later than 11:59PM on Friday February 2, "
        "2024, disconnect all instances of Ivanti Connect Secure and Ivanti "
        "Policy Secure solution products from agency networks."
    )
    cisa_raw = f"<html><body><p>{cisa_action}</p></body></html>".encode()
    cisa_manifest = _manifest(
        source_name="cisa_directive",
        source_class="government",
        source_url=(
            "https://www.cisa.gov/news-events/directives/"
            "supplemental-direction-v1-ed-24-01"
        ),
        snapshot_id="test-cisa",
        identifier="ED-24-01",
        version="supplemental-v1",
        raw=cisa_raw,
        available=datetime(2024, 2, 5, 23, 59, 59, tzinfo=UTC),
        media_type="text/html",
    )
    cisa = normalize_versioned_source(cisa_manifest, cisa_raw)
    assert cisa.fields["required_disconnect_action"] == cisa_action
    assert len(cisa.spans) == 1
    cisa_span = cisa.spans[0]
    assert (
        cisa.normalized_text[cisa_span.start_char : cisa_span.end_char] == cisa_action
    )

    netscaler_action = (
        "Review the \u2018SSLVPN TCPCONNSTAT\u2019 logs for the same "
        "\u2018Source\u2019 IP address accessing the sessions of multiple users "
        "(you can refer to the \u2018User\u2019 "
        "field in the log)."
    )
    old_raw = b"<html><body><p>Initial mitigation only.</p></body></html>"
    new_raw = f"<html><body><p>{netscaler_action}</p></body></html>".encode()
    old_manifest = _manifest(
        source_name="netscaler_advisory",
        source_class="vendor",
        source_url=(
            "https://www.netscaler.com/blog/news/"
            "cve-2023-4966-critical-security-update-now-available/"
        ),
        snapshot_id="test-netscaler-old",
        identifier="CVE-2023-4966",
        version="2023-10-23",
        raw=old_raw,
        available=datetime(2023, 10, 23, 12, tzinfo=UTC),
        media_type="text/html",
    )
    new_manifest = _manifest(
        source_name="netscaler_advisory",
        source_class="vendor",
        source_url=str(old_manifest.source_url),
        snapshot_id="test-netscaler-new",
        identifier="CVE-2023-4966",
        version="2023-11-20",
        raw=new_raw,
        available=datetime(2023, 11, 20, 17, 30, 16, tzinfo=UTC),
        media_type="text/html",
    )
    old = normalize_versioned_source(old_manifest, old_raw)
    new = normalize_versioned_source(new_manifest, new_raw)
    assert old.fields["ssl_vpn_source_ip_pattern"] is None
    assert new.fields["ssl_vpn_source_ip_pattern"] == (
        "the same Source IP address accessing sessions of multiple users"
    )
    assert len(new.spans) == 1
    span = new.spans[0]
    assert new.normalized_text[span.start_char : span.end_char] == netscaler_action


def test_gold_evidence_must_belong_to_the_allowed_selected_snapshot() -> None:
    case = BenchmarkCase.model_validate_json(
        (
            Path(__file__).resolve().parents[2]
            / "data/benchmark/dev/three-family-cases.jsonl"
        )
        .read_text()
        .splitlines()[0]
    )
    evidence_ids = case.expected_claims[0].evidence_ids
    evidence_id = evidence_ids[0]
    foreign = NormalizedDocument.model_validate(
        {
            "document_id": evidence_id.split(":", 1)[0],
            "snapshot_id": "foreign-post-cutoff-snapshot",
            "upstream_entity_id": "CVE-2024-3094",
            "title": "foreign",
            "canonical_url": "https://example.invalid/foreign",
            "published_at": None,
            "modified_at": None,
            "source_name": "cve_program",
            "source_class": "standards_body",
            "normalization_version": NORMALIZATION_VERSION,
            "normalized_text": "foreign",
            "normalized_text_sha256": hashlib.sha256(b"foreign").hexdigest(),
            "fields": {},
            "spans": [],
        }
    )
    with pytest.raises(ThreeFamilyError, match="outside the case snapshot"):
        _validate_evidence_snapshot_boundary(
            case,
            evidence_documents={item: foreign for item in evidence_ids},
            selected_snapshot_ids=set(case.allowed_snapshot_ids),
        )
