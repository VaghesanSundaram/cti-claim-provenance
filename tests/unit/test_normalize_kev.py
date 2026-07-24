from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from cti_provenance.ingest.kev import KEV_COMMIT, KEV_COMMIT_TIME, KEV_URL
from cti_provenance.normalize.kev import normalize_kev
from cti_provenance.normalize.spans import resolve_json_pointer, resolve_span
from cti_provenance.snapshot import SnapshotManifest


def _raw() -> bytes:
    return json.dumps(
        {
            "catalogVersion": "2026.07.16",
            "dateReleased": "2026-07-16T19:11:42Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                }
            ],
        }
    ).encode()


def _manifest(raw: bytes) -> SnapshotManifest:
    return SnapshotManifest(
        snapshot_id="kev-1",
        source_name="cisa_kev",
        source_class="government",
        source_url=KEV_URL,
        retrieved_at_utc=datetime(2026, 7, 18, tzinfo=UTC),
        http_status=200,
        http_etag=None,
        http_last_modified=None,
        effective_date_if_known=KEV_COMMIT_TIME,
        effective_date_basis="publisher_version",
        available_by_utc=KEV_COMMIT_TIME,
        available_by_basis="upstream_version",
        upstream_identifier="cisa-kev-catalog",
        upstream_version=KEV_COMMIT,
        media_type="application/json",
        byte_length=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        raw_blob_path="data/raw/cisa-kev/test.json",
        fetcher_version="phase2-capture-v1",
        normalization_version="phase2-kev-v1",
        license_or_terms_note="test",
    )


def test_normalize_kev_membership_cites_cve_id_and_round_trips() -> None:
    raw = _raw()
    document = normalize_kev(raw, _manifest(raw))[0]
    assert document.fields["is_member"] is True
    membership = next(
        span for span in document.spans if span.span_id == "kev-membership"
    )
    assert resolve_span(membership, document.normalized_text) == "CVE-2021-44228"
    for span in document.spans:
        assert span.raw_locator is not None
        assert str(resolve_json_pointer(raw, span.raw_locator)) == resolve_span(
            span, document.normalized_text
        )
