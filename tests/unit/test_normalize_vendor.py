from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from cti_provenance.ingest.vendor import RHSA_URL
from cti_provenance.normalize.spans import resolve_json_pointer, resolve_span
from cti_provenance.normalize.vendor import normalize_red_hat
from cti_provenance.snapshot import SnapshotManifest

RELEASE = datetime(2026, 6, 28, 12, 35, 37, tzinfo=UTC)


def _payload() -> dict[str, Any]:
    return {
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
                    "category": "vendor",
                    "name": "Red Hat",
                    "branches": [
                        {
                            "category": "product_version",
                            "name": "affected",
                            "product": {
                                "product_id": "affected-id",
                                "name": "Example product 1.0",
                            },
                        },
                        {
                            "category": "product_version",
                            "name": "not affected",
                            "product": {
                                "product_id": "not-affected-id",
                                "name": "Example product 3.0",
                            },
                        },
                        {
                            "category": "component",
                            "name": "component",
                            "product": {
                                "product_id": "component",
                                "name": "Example component",
                            },
                        },
                        {
                            "category": "product_name",
                            "name": "fixed parent",
                            "product": {
                                "product_id": "fixed-parent",
                                "name": "Example fixed parent",
                            },
                        },
                    ],
                }
            ],
            "relationships": [
                {
                    "category": "default_component_of",
                    "product_reference": "component",
                    "relates_to_product_reference": "fixed-parent",
                    "full_product_name": {
                        "product_id": "fixed-id",
                        "name": "Example product 2.0",
                    },
                }
            ],
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2021-44228",
                "product_status": {
                    "known_affected": ["affected-id"],
                    "fixed": ["fixed-id"],
                    "known_not_affected": ["not-affected-id"],
                },
                "remediations": [
                    {
                        "category": "mitigation",
                        "details": "Not a fixed-status assertion",
                        "product_ids": ["affected-id"],
                    }
                ],
            }
        ],
    }


def _bytes(payload: dict[str, Any] | None = None) -> tuple[bytes, bytes]:
    raw = json.dumps(payload or _payload()).encode()
    checksum = f"{hashlib.sha256(raw).hexdigest()}  rhsa-2021_5133.json\n".encode()
    return raw, checksum


def _manifest(raw: bytes) -> SnapshotManifest:
    return SnapshotManifest(
        snapshot_id="rhsa-1",
        source_name="red_hat_rhsa",
        source_class="vendor",
        source_url=RHSA_URL,
        retrieved_at_utc=datetime(2026, 7, 18, tzinfo=UTC),
        http_status=200,
        http_etag=None,
        http_last_modified=None,
        effective_date_if_known=RELEASE,
        effective_date_basis="publisher_version",
        available_by_utc=RELEASE,
        available_by_basis="publisher_timestamp_with_observation",
        upstream_identifier="RHSA-2021:5133",
        upstream_version="3",
        media_type="application/json",
        byte_length=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        raw_blob_path="data/raw/red-hat/test.json",
        fetcher_version="phase2-capture-v1",
        normalization_version="phase2-red-hat-v1",
        license_or_terms_note="test",
    )


def test_red_hat_preserves_status_categories_and_ignores_remediation_as_fixed() -> None:
    raw, checksum = _bytes()
    document = normalize_red_hat(raw, checksum, _manifest(raw))[0]
    assert document.fields["fixed_products"] == [
        {"product_id": "fixed-id", "product": "Example product 2.0"}
    ]
    assert document.fields["known_affected_products"] == [
        {"product_id": "affected-id", "product": "Example product 1.0"}
    ]
    status = document.fields["product_status_by_category"]
    assert isinstance(status, dict)
    assert set(status) == {"fixed", "known_affected", "known_not_affected"}
    for span in document.spans:
        assert span.raw_locator is not None
        assert str(resolve_json_pointer(raw, span.raw_locator)) == resolve_span(
            span, document.normalized_text
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "overlap",
        "duplicate_product",
        "dangling_relationship",
        "unknown_remediation",
    ],
)
def test_red_hat_rejects_ambiguous_product_mappings(mutation: str) -> None:
    payload = _payload()
    status = payload["vulnerabilities"][0]["product_status"]
    if mutation == "unknown":
        status["fixed"] = ["missing-id"]
    elif mutation == "overlap":
        status["fixed"] = ["affected-id"]
    elif mutation == "duplicate_product":
        duplicate = {
            "category": "product_version",
            "name": "duplicate",
            "product": {
                "product_id": "affected-id",
                "name": "Duplicate",
            },
        }
        payload["product_tree"]["branches"][0]["branches"].append(duplicate)
    elif mutation == "dangling_relationship":
        payload["product_tree"]["relationships"][0]["product_reference"] = "missing"
    else:
        payload["vulnerabilities"][0]["remediations"][0]["product_ids"] = ["missing"]
    raw, checksum = _bytes(payload)
    with pytest.raises(
        ValueError,
        match=r"unknown|contradictory|duplicate|dangling",
    ):
        normalize_red_hat(raw, checksum, _manifest(raw))
