from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path

from cti_provenance.snapshot.manifest import SnapshotManifest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parents[2] / "data" / "fixtures"
MANIFESTS = ROOT / "data" / "manifests" / "synthetic-fixture-snapshots.jsonl"
EXPECTED = {
    "nvd-synthetic.json": "nvd",
    "cisa-kev-synthetic.json": "cisa_kev",
    "mitre-attack-synthetic.json": "mitre_attack",
    "red-hat-rhsa-synthetic.json": "red_hat_rhsa",
}


def test_phase1_fixtures_are_tiny_synthetic_and_source_distinct() -> None:
    assert {path.name for path in FIXTURES.glob("*-synthetic.json")} == set(EXPECTED)
    for filename, source_name in EXPECTED.items():
        path = FIXTURES / filename
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert path.stat().st_size < 1024
        assert payload["source_name"] == source_name
        assert "synthetic" in payload["fixture_notice"].lower()
        assert "non-authoritative" in payload["fixture_notice"].lower()
        fixture_text = path.read_text(encoding="utf-8")
        assert re.search(r"\bCVE-\d{4}-\d{4,}\b", fixture_text) is None
        assert re.search(r"\bRHSA-\d{4}:\d+\b", fixture_text) is None


def test_synthetic_fixture_manifests_bind_exact_project_authored_bytes() -> None:
    manifests = [
        SnapshotManifest.model_validate_json(line)
        for line in MANIFESTS.read_text(encoding="utf-8").splitlines()
        if line
    ]
    fixture_paths = {
        f"data/fixtures/{path.name}" for path in FIXTURES.glob("*-synthetic.json")
    }
    manifest_paths = {manifest.raw_blob_path for manifest in manifests}
    assert manifest_paths == fixture_paths
    assert len(manifests) == len(manifest_paths)

    for manifest in manifests:
        assert manifest.source_name == "synthetic_control"
        assert manifest.source_class == "synthetic"
        assert str(manifest.source_url).startswith("urn:cti-provenance:fixture:")
        assert manifest.available_by_basis == "synthetic_fixture"
        assert manifest.effective_date_if_known is None
        assert manifest.effective_date_basis == "unknown"
        assert manifest.raw_blob_path.startswith("data/fixtures/")
        assert manifest.upstream_identifier.startswith("synthetic-representation:")
        assert manifest.upstream_version.isdigit()
        assert "project-generated" in manifest.license_or_terms_note.lower()

        raw_bytes = (ROOT / manifest.raw_blob_path).read_bytes()
        assert manifest.byte_length == len(raw_bytes)
        assert manifest.sha256 == sha256(raw_bytes).hexdigest()
