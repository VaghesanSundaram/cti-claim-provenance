"""Deterministic Phase 2 NVD normalization."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from cti_provenance.ingest.nvd import NVD_BASE_URL, SELECTED_CVE, parse_nvd_bytes
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.normalize.spans import create_span, verify_raw_round_trip
from cti_provenance.snapshot import SnapshotManifest

NORMALIZATION_VERSION = "phase2-nvd-v1"
_NVD_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?P<offset>Z|[+-]\d{2}:\d{2})?$"
)


def _time(value: str) -> datetime:
    match = _NVD_TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError("NVD API timestamp is invalid")
    if match.group("offset") not in (None, "Z", "+00:00"):
        raise ValueError("NVD API timestamp must use a zero UTC offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("NVD API timestamp is invalid") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_nvd(raw: bytes, manifest: SnapshotManifest) -> list[NormalizedDocument]:
    if (
        manifest.source_name != "nvd"
        or manifest.source_class != "government"
        or str(manifest.source_url) != NVD_BASE_URL
        or manifest.normalization_version != NORMALIZATION_VERSION
        or manifest.upstream_identifier != SELECTED_CVE
        or manifest.byte_length != len(raw)
        or manifest.sha256 != hashlib.sha256(raw).hexdigest()
    ):
        raise ValueError("manifest is not the Phase 2 NVD capture")
    payload = parse_nvd_bytes(raw)
    cve = payload["vulnerabilities"][0]["cve"]
    descriptions = cve.get("descriptions", [])
    description_index = next(
        (
            index
            for index, x in enumerate(descriptions)
            if isinstance(x, dict)
            and x.get("lang") == "en"
            and isinstance(x.get("value"), str)
        ),
        None,
    )
    if description_index is None:
        raise ValueError("NVD selected record lacks English description")
    description = descriptions[description_index]["value"]
    metrics: dict[str, Any] = (
        cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
    )
    cvss = metrics.get("cvssMetricV31", [])
    named_cvss_match = next(
        (
            (index, x)
            for index, x in enumerate(cvss)
            if isinstance(x, dict)
            and x.get("source") == "nvd@nist.gov"
            and x.get("type") == "Primary"
            and isinstance(x.get("cvssData"), dict)
        ),
        None,
    )
    if named_cvss_match is None:
        raise ValueError("NVD selected record lacks CVSS v3.1")
    cvss_index, named_cvss = named_cvss_match
    cvss_data = named_cvss["cvssData"]
    if not isinstance(cvss_data.get("baseScore"), (int, float)):
        raise ValueError("NVD selected CVSS metric lacks a numeric base score")
    for field in ("published", "lastModified"):
        if not isinstance(cve.get(field), str):
            raise ValueError(f"NVD selected record lacks {field}")
    chunks = [f"{SELECTED_CVE}\n"]
    specs: list[tuple[str, str, int, int, str]] = []
    for label, name, value, locator in (
        (
            "Published",
            "published",
            cve["published"],
            "/vulnerabilities/0/cve/published",
        ),
        (
            "Modified",
            "modified",
            cve["lastModified"],
            "/vulnerabilities/0/cve/lastModified",
        ),
        (
            "Description",
            "description",
            description,
            f"/vulnerabilities/0/cve/descriptions/{description_index}/value",
        ),
        (
            "CVSS v3.1 (NVD)",
            "cvss-v31",
            str(cvss_data.get("baseScore")),
            (
                "/vulnerabilities/0/cve/metrics/"
                f"cvssMetricV31/{cvss_index}/cvssData/baseScore"
            ),
        ),
    ):
        value_text = str(value)
        prefix = f"{label}: "
        start = sum(len(chunk) for chunk in chunks) + len(prefix)
        chunks.append(f"{prefix}{value_text}\n")
        specs.append((name, value_text, start, start + len(value_text), locator))
    text = "".join(chunks).rstrip("\n")
    spans = []
    for name, _value, start, end, locator in specs:
        spans.append(
            create_span(
                span_id=f"nvd-{name}",
                field_path=f"/{name}",
                normalized_text=text,
                start_char=start,
                end_char=end,
                raw_locator=locator,
                raw_locator_unavailable_reason=None,
                raw_snapshot_id=manifest.snapshot_id,
                raw_snapshot_sha256=manifest.sha256,
                normalization_version=NORMALIZATION_VERSION,
            )
        )
    document = NormalizedDocument(
        document_id=f"nvd-{SELECTED_CVE.lower()}",
        snapshot_id=manifest.snapshot_id,
        upstream_entity_id=SELECTED_CVE,
        title=SELECTED_CVE,
        canonical_url=NVD_BASE_URL,
        published_at=_time(cve["published"]),
        modified_at=_time(cve["lastModified"]),
        source_name="nvd",
        source_class="government",
        normalization_version=NORMALIZATION_VERSION,
        normalized_text=text,
        normalized_text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        fields={
            "cve_id": SELECTED_CVE,
            "published": cve["published"],
            "modified": cve["lastModified"],
            "description": description,
            "cvss_v31_named_source": named_cvss.get("source"),
            "cvss_v31_base_score": cvss_data.get("baseScore"),
        },
        spans=spans,
    )
    for span in document.spans:
        verify_raw_round_trip(span, normalized_text=text, raw=raw)
    return [document]
