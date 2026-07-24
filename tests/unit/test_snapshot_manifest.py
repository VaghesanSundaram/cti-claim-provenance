from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cti_provenance.snapshot.manifest import SnapshotManifest, _approved_source_url


def _manifest(**changes: object) -> SnapshotManifest:
    timestamp = datetime(2026, 7, 18, tzinfo=UTC)
    data: dict[str, object] = {
        "snapshot_id": "snapshot-1",
        "source_name": "nvd",
        "source_class": "government",
        "source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "retrieved_at_utc": timestamp,
        "http_status": 200,
        "http_etag": None,
        "http_last_modified": None,
        "effective_date_if_known": None,
        "effective_date_basis": "unknown",
        "available_by_utc": timestamp,
        "available_by_basis": "observed_retrieval",
        "upstream_identifier": "SYNTHETIC-CVE-ALPHA",
        "upstream_version": None,
        "media_type": "application/json",
        "byte_length": 1,
        "sha256": "a" * 64,
        "raw_blob_path": "data/raw/blob.json",
        "fetcher_version": "fixture-v1",
        "normalization_version": "fixture-v1",
        "license_or_terms_note": "project-generated test fixture",
    }
    data.update(changes)
    return SnapshotManifest.model_validate(data)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("source_class", "vendor"),
        ("http_status", 204),
        ("http_status", 206),
        ("source_url", "http://services.nvd.nist.gov/rest/json/cves/2.0"),
        ("source_url", "https://example.invalid/rest/json/cves/2.0"),
        ("source_url", "https://security.access.redhat.com/data/csaf/v2/advisories/"),
        (
            "source_url",
            "https://services.nvd.nist.gov/rest/json/cves/2.0?apiKey=secret",
        ),
        (
            "source_url",
            "https://services.nvd.nist.gov/rest/json/cves/2.0#fragment",
        ),
        ("raw_blob_path", "C:/escape"),
        ("raw_blob_path", "folder//blob"),
        ("raw_blob_path", "folder/./blob"),
        ("raw_blob_path", "folder/CON"),
        ("raw_blob_path", "folder/blob. "),
    ],
)
def test_manifest_rejects_unapproved_source_or_windows_unsafe_path(
    key: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        _manifest(**{key: value})


def test_synthetic_manifest_requires_project_urn_prefix() -> None:
    with pytest.raises(ValidationError):
        _manifest(
            source_name="synthetic_control",
            source_class="synthetic",
            source_url="urn:outside-project:fixture",
            available_by_basis="synthetic_fixture",
            upstream_version="1",
        )


def test_repository_source_url_requires_a_path_boundary() -> None:
    with pytest.raises(ValidationError):
        _manifest(
            source_name="cisa_kev",
            source_url="https://github.com/cisagov/kev-data-evil",
            available_by_basis="upstream_version",
            upstream_version="c" * 40,
        )


@pytest.mark.parametrize(
    ("source_name", "url"),
    [
        (
            "cisa_directive",
            "https://www.cisa.gov/news-events/directives/example",
        ),
        (
            "cve_program",
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/abc/record.json",
        ),
        ("cisa_kev", "https://github.com/cisagov/kev-data/commit/abc"),
        (
            "mitre_attack",
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/abc/file.json",
        ),
        (
            "netscaler_advisory",
            "https://www.netscaler.com/blog/news/example",
        ),
        (
            "red_hat_rhsa",
            "https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa.json",
        ),
        (
            "vendor_advisory",
            "https://archive.apache.org/dist/httpd/CHANGES_2.4.51",
        ),
    ],
)
def test_non_nvd_sources_reject_every_query_string(source_name: str, url: str) -> None:
    assert _approved_source_url(source_name, f"{url}?apiKey=secret") is False


def test_postgresql_release_source_allowlist_is_exact() -> None:
    valid = (
        "https://raw.githubusercontent.com/postgres/postgres/REL_15_5/"
        "doc/src/sgml/release-15.sgml"
    )
    assert _approved_source_url("vendor_advisory", valid) is True
    assert _approved_source_url("vendor_advisory", f"{valid}?ref=other") is False
    assert (
        _approved_source_url(
            "vendor_advisory",
            valid.replace("REL_15_5", "REL_16_1"),
        )
        is False
    )


@pytest.mark.parametrize(
    "query",
    [
        "",
        "?changeRecordedOn=",
        "?changeRecordedOn=a&changeRecordedOn=b",
        "?changeRecordedOn=a&apiKey=secret",
        "?apiKey=secret",
    ],
)
def test_nvd_change_record_allows_only_one_nonempty_timestamp_query(
    query: str,
) -> None:
    base = "https://nvd.nist.gov/vuln/detail/CVE-2024-3400/change-record"
    assert _approved_source_url("nvd", f"{base}{query}") is False

    valid = f"{base}?changeRecordedOn=05%2F29%2F2024T12%3A00%3A24.110-0400"
    assert _approved_source_url("nvd", valid) is True
