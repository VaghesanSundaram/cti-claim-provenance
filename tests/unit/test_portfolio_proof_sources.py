from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from cti_provenance.normalize import (
    load_portfolio_family_config,
    normalize_portfolio_source,
)
from cti_provenance.normalize.spans import resolve_span
from cti_provenance.snapshot import SnapshotManifest

ROOT = Path(__file__).resolve().parents[2]
SPECS = load_portfolio_family_config(
    ROOT / "configs" / "portfolio-proof-families-v1.yaml"
).families


def _manifest(
    raw: bytes,
    *,
    snapshot_id: str,
    source_name: str,
    source_class: str,
    source_url: str,
    upstream_identifier: str,
    upstream_version: str,
) -> SnapshotManifest:
    now = datetime(2026, 7, 21, 23, 0, tzinfo=UTC)
    return SnapshotManifest.model_validate(
        {
            "snapshot_id": snapshot_id,
            "source_name": source_name,
            "source_class": source_class,
            "source_url": source_url,
            "retrieved_at_utc": now,
            "http_status": 200,
            "http_etag": None,
            "http_last_modified": None,
            "effective_date_if_known": now,
            "effective_date_basis": "publisher_version",
            "available_by_utc": now,
            "available_by_basis": (
                "publisher_declared_version"
                if source_name == "vendor_advisory"
                else "upstream_version"
            ),
            "upstream_identifier": upstream_identifier,
            "upstream_version": upstream_version,
            "media_type": "application/json",
            "byte_length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_blob_path": f"data/raw/test/{snapshot_id}.bin",
            "fetcher_version": "test",
            "normalization_version": "portfolio-proof-source-v1",
            "license_or_terms_note": "test fixture only",
        }
    )


def test_declarative_normalizers_extract_three_distinct_semantic_deltas() -> None:
    apache = SPECS[0]
    old_apache = b"Changes with Apache 2.4.50\nCVE-2021-41773 only."
    new_apache = (
        b"Changes with Apache 2.4.51\nCVE-2021-42013\n"
        b"This issue only affects Apache 2.4.49 and Apache 2.4.50 and not\n"
        b"earlier versions."
    )
    apache_documents = []
    for raw, snapshot_id, version in zip(
        (old_apache, new_apache),
        apache.source_state_ids,
        ("2.4.50", "2.4.51"),
        strict=True,
    ):
        apache_documents.append(
            normalize_portfolio_source(
                _manifest(
                    raw,
                    snapshot_id=snapshot_id,
                    source_name="vendor_advisory",
                    source_class="vendor",
                    source_url=f"https://archive.apache.org/dist/httpd/CHANGES_{version}",
                    upstream_identifier=apache.family_id,
                    upstream_version=version,
                ),
                raw,
                apache,
            )
        )
    assert [item.fields["claim_value"] for item in apache_documents] == [
        [],
        ["2.4.49", "2.4.50"],
    ]
    assert resolve_span(
        apache_documents[1].spans[0], apache_documents[1].normalized_text
    ).endswith("not earlier versions.")

    kev = SPECS[1]
    kev_documents = []
    for value, snapshot_id, commit in zip(
        ("Unknown", "Known"),
        kev.source_state_ids,
        ("a" * 40, "b" * 40),
        strict=True,
    ):
        raw = json.dumps(
            {
                "catalogVersion": "test",
                "dateReleased": "2026-07-21T00:00:00Z",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0257",
                        "knownRansomwareCampaignUse": value,
                    }
                ],
            }
        ).encode()
        kev_documents.append(
            normalize_portfolio_source(
                _manifest(
                    raw,
                    snapshot_id=snapshot_id,
                    source_name="cisa_kev",
                    source_class="government",
                    source_url=(
                        "https://raw.githubusercontent.com/cisagov/kev-data/"
                        f"{commit}/known_exploited_vulnerabilities.json"
                    ),
                    upstream_identifier="cisa-kev-catalog",
                    upstream_version=commit,
                ),
                raw,
                kev,
            )
        )
    assert [item.fields["claim_value"] for item in kev_documents] == [
        "Unknown",
        "Known",
    ]
    assert kev_documents[1].spans[0].raw_locator.endswith("/knownRansomwareCampaignUse")

    attack = SPECS[2]
    attack_documents = []
    for platforms, snapshot_id, commit, version in zip(
        (["Windows"], ["Windows", "Linux"]),
        attack.source_state_ids,
        ("c" * 40, "d" * 40),
        ("15.1", "16.0"),
        strict=True,
    ):
        raw = json.dumps(
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--test",
                        "name": "Fileless Storage",
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": "T1027.011",
                            }
                        ],
                        "x_mitre_version": "test",
                        "x_mitre_platforms": platforms,
                    }
                ]
            }
        ).encode()
        attack_documents.append(
            normalize_portfolio_source(
                _manifest(
                    raw,
                    snapshot_id=snapshot_id,
                    source_name="mitre_attack",
                    source_class="standards_body",
                    source_url=(
                        "https://raw.githubusercontent.com/mitre-attack/"
                        f"attack-stix-data/{commit}/enterprise-attack/"
                        f"enterprise-attack-{version}.json"
                    ),
                    upstream_identifier="enterprise-attack",
                    upstream_version=version,
                ),
                raw,
                attack,
            )
        )
    assert [item.fields["claim_value"] for item in attack_documents] == [
        ["Windows"],
        ["Windows", "Linux"],
    ]
    assert attack_documents[1].spans[0].raw_locator == "/objects/0/x_mitre_platforms"


def test_portfolio_normalizer_rejects_hash_mismatch() -> None:
    spec = SPECS[0]
    raw = b"Changes with Apache 2.4.50"
    manifest = _manifest(
        raw,
        snapshot_id=spec.source_state_ids[0],
        source_name="vendor_advisory",
        source_class="vendor",
        source_url="https://archive.apache.org/dist/httpd/CHANGES_2.4.50",
        upstream_identifier=spec.family_id,
        upstream_version="2.4.50",
    )
    with pytest.raises(ValueError, match="manifest and family spec"):
        normalize_portfolio_source(manifest, raw + b"tampered", spec)


@pytest.mark.parametrize(
    "dependency_field",
    [
        "incident_campaign_lineage",
        "vendor_product_lineage",
        "source_release_lineage",
        "template_family_id",
        "challenge_generator_family",
        "coarsest_shared_dependency",
    ],
)
def test_family_spec_rejects_shared_dependency_across_splits(
    tmp_path: Path,
    dependency_field: str,
) -> None:
    payload = {
        "version": "portfolio-family-spec-v1",
        "families": [spec.model_dump(mode="python") for spec in SPECS[:2]],
    }
    payload["families"][1][dependency_field] = payload["families"][0][dependency_field]
    payload["families"][1]["prospective_split"] = "validation"

    path = tmp_path / "families.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="cannot cross prospective splits"):
        load_portfolio_family_config(path)
