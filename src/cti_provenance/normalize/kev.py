"""Deterministic Phase 2 KEV normalization."""

from __future__ import annotations

import hashlib
from datetime import datetime

from cti_provenance.ingest.kev import KEV_URL, parse_kev_bytes
from cti_provenance.ingest.nvd import SELECTED_CVE
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.normalize.spans import create_span, verify_raw_round_trip
from cti_provenance.snapshot import SnapshotManifest

NORMALIZATION_VERSION = "phase2-kev-v1"


def _time(v: str) -> datetime:
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def normalize_kev(raw: bytes, manifest: SnapshotManifest) -> list[NormalizedDocument]:
    if (
        manifest.source_name != "cisa_kev"
        or manifest.source_class != "government"
        or str(manifest.source_url) != KEV_URL
        or manifest.normalization_version != NORMALIZATION_VERSION
        or manifest.upstream_identifier != "cisa-kev-catalog"
        or manifest.byte_length != len(raw)
        or manifest.sha256 != hashlib.sha256(raw).hexdigest()
    ):
        raise ValueError("manifest is not the pinned Phase 2 KEV capture")
    payload = parse_kev_bytes(raw)
    entry_index = next(
        i
        for i, x in enumerate(payload["vulnerabilities"])
        if x.get("cveID") == SELECTED_CVE
    )
    entry = payload["vulnerabilities"][entry_index]
    for field in ("dateAdded", "dueDate"):
        if not isinstance(entry.get(field), str):
            raise ValueError(f"KEV entry lacks {field}")
    text = (
        f"{SELECTED_CVE}\nKEV selected cveID: {SELECTED_CVE}\n"
        f"Date added: {entry['dateAdded']}\nDue date: {entry['dueDate']}"
    )
    spans = []
    for name, value, locator in (
        ("membership", SELECTED_CVE, f"/vulnerabilities/{entry_index}/cveID"),
        ("date-added", entry["dateAdded"], f"/vulnerabilities/{entry_index}/dateAdded"),
        ("due-date", entry["dueDate"], f"/vulnerabilities/{entry_index}/dueDate"),
    ):
        start = (
            text.index(str(value), len(SELECTED_CVE))
            if name == "membership"
            else text.index(str(value))
        )
        spans.append(
            create_span(
                span_id=f"kev-{name}",
                field_path=f"/{name}",
                normalized_text=text,
                start_char=start,
                end_char=start + len(str(value)),
                raw_locator=locator,
                raw_locator_unavailable_reason=None,
                raw_snapshot_id=manifest.snapshot_id,
                raw_snapshot_sha256=manifest.sha256,
                normalization_version=NORMALIZATION_VERSION,
            )
        )
    document = NormalizedDocument(
        document_id=f"kev-{SELECTED_CVE.lower()}",
        snapshot_id=manifest.snapshot_id,
        upstream_entity_id=SELECTED_CVE,
        title=f"CISA KEV {SELECTED_CVE}",
        canonical_url=KEV_URL,
        published_at=_time(payload["dateReleased"]),
        modified_at=None,
        source_name="cisa_kev",
        source_class="government",
        normalization_version=NORMALIZATION_VERSION,
        normalized_text=text,
        normalized_text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        fields={
            "cve_id": SELECTED_CVE,
            "is_member": True,
            "date_added": entry["dateAdded"],
            "due_date": entry["dueDate"],
            "catalog_version": payload["catalogVersion"],
        },
        spans=spans,
    )
    for span in document.spans:
        verify_raw_round_trip(span, normalized_text=text, raw=raw)
    return [document]
