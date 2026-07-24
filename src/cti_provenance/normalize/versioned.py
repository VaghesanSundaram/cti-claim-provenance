"""Narrow normalizers for the three-family provider-free corpus."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from html.parser import HTMLParser
from typing import Any

from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.normalize.spans import create_span, verify_raw_json_round_trip
from cti_provenance.snapshot import SnapshotManifest

NORMALIZATION_VERSION = "three-family-source-specific-v2"

_IVANTI_ACTION = (
    "As soon as possible and no later than 11:59PM on Friday February 2, 2024, "
    "disconnect all instances of Ivanti Connect Secure and Ivanti Policy Secure "
    "solution products from agency networks."
)
_IVANTI_V2_ACTION = (
    "apply the February 8 update from Ivanti to address CVE-2024-22024 by "
    "11:59PM Monday February 12, 2024."
)
_NETSCALER_INVESTIGATION = (
    "Review the \u2018SSLVPN TCPCONNSTAT\u2019 logs for the same "
    "\u2018Source\u2019 IP address accessing the sessions of multiple users "
    "(you can refer to the \u2018User\u2019 field "
    "in the log)."
)


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in {"script", "style", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


def _visible_text(raw: bytes) -> str:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("versioned HTML source is not UTF-8") from exc
    parser = _VisibleTextParser()
    parser.feed(decoded)
    parser.close()
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()


def _document(
    manifest: SnapshotManifest,
    *,
    document_id: str,
    title: str,
    normalized_text: str,
    fields: dict[str, Any],
    spans: Sequence[tuple[str, str, str, str | None]],
) -> NormalizedDocument:
    evidence = []
    for span_id, field_path, target, raw_locator in spans:
        if target not in normalized_text:
            raise ValueError(f"expected exact evidence span for {span_id}")
        start = normalized_text.index(target)
        evidence.append(
            create_span(
                span_id=span_id,
                field_path=field_path,
                normalized_text=normalized_text,
                start_char=start,
                end_char=start + len(target),
                raw_locator=raw_locator,
                raw_locator_unavailable_reason=(
                    None
                    if raw_locator is not None
                    else "HTML visible-text normalization has no stable DOM locator"
                ),
                raw_snapshot_id=manifest.snapshot_id,
                raw_snapshot_sha256=manifest.sha256,
                normalization_version=NORMALIZATION_VERSION,
            )
        )
    return NormalizedDocument(
        document_id=document_id,
        snapshot_id=manifest.snapshot_id,
        upstream_entity_id=manifest.upstream_identifier or "",
        title=title,
        canonical_url=manifest.source_url,
        published_at=manifest.effective_date_if_known,
        modified_at=manifest.effective_date_if_known,
        source_name=manifest.source_name,
        source_class=manifest.source_class,
        normalization_version=NORMALIZATION_VERSION,
        normalized_text=normalized_text,
        normalized_text_sha256=hashlib.sha256(normalized_text.encode()).hexdigest(),
        fields=fields,
        spans=evidence,
    )


def _normalize_cve(manifest: SnapshotManifest, raw: bytes) -> NormalizedDocument:
    try:
        payload = json.loads(raw)
        cna = payload["containers"]["cna"]
        affected = cna["affected"][0]
        description = cna["descriptions"][0]["value"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("CVE Program record has an unexpected shape") from exc
    affected_records = [
        item
        for item in affected.get("versions", [])
        if item.get("status") == "affected"
    ]
    versions = [item["version"] for item in affected_records]
    version_lines = [
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in affected_records
    ]
    normalized_text = "\n".join(
        [
            "CVE-2024-3094",
            *version_lines,
            f"Default status: {affected.get('defaultStatus', 'unspecified')}",
            f"Description: {description}",
        ]
    )
    spans = [
        (
            f"affected-version-{index}",
            f"/containers/cna/affected/0/versions/{index}",
            version_lines[index],
            f"/containers/cna/affected/0/versions/{index}",
        )
        for index in range(len(versions))
    ]
    document = _document(
        manifest,
        document_id=f"cve-program-cve-2024-3094-{manifest.snapshot_id}",
        title="CVE Program record for CVE-2024-3094",
        normalized_text=normalized_text,
        fields={
            "affected_versions": versions,
            "default_status": affected.get("defaultStatus"),
            "date_updated": payload["cveMetadata"]["dateUpdated"],
        },
        spans=spans,
    )
    for span in document.spans:
        verify_raw_json_round_trip(span, normalized_text=normalized_text, raw=raw)
    return document


def _normalize_cisa(manifest: SnapshotManifest, raw: bytes) -> NormalizedDocument:
    text = _visible_text(raw)
    is_v1 = "supplemental-v1" in (manifest.upstream_version or "")
    target = _IVANTI_ACTION if is_v1 else _IVANTI_V2_ACTION
    span_id = "required-disconnect" if is_v1 else "required-february-8-update"
    spans = [(span_id, "required_actions[0]", target, None)]
    return _document(
        manifest,
        document_id=f"cisa-ed-24-01-{manifest.snapshot_id}",
        title="CISA ED 24-01 supplemental direction",
        normalized_text=text,
        fields={
            "required_disconnect_action": _IVANTI_ACTION if is_v1 else None,
            "required_february_8_update": None if is_v1 else _IVANTI_V2_ACTION,
            "publisher_version": manifest.upstream_version,
        },
        spans=spans,
    )


def _normalize_netscaler(manifest: SnapshotManifest, raw: bytes) -> NormalizedDocument:
    text = _visible_text(raw)
    has_investigation = _NETSCALER_INVESTIGATION in text
    spans = (
        [
            (
                "ssl-vpn-source-ip-pattern",
                "investigation_recommendations.sslvpn_tcpconnstat",
                _NETSCALER_INVESTIGATION,
                None,
            )
        ]
        if has_investigation
        else []
    )
    return _document(
        manifest,
        document_id=f"netscaler-cve-2023-4966-{manifest.snapshot_id}",
        title="NetScaler guidance for CVE-2023-4966",
        normalized_text=text,
        fields={
            "ssl_vpn_source_ip_pattern": (
                "the same Source IP address accessing sessions of multiple users"
                if has_investigation
                else None
            ),
            "publisher_version": manifest.upstream_version,
        },
        spans=spans,
    )


def normalize_versioned_source(
    manifest: SnapshotManifest, raw: bytes
) -> NormalizedDocument:
    """Normalize only one of the six frozen, manifest-bound source versions."""
    if len(raw) != manifest.byte_length:
        raise ValueError("versioned source byte length does not match manifest")
    if hashlib.sha256(raw).hexdigest() != manifest.sha256:
        raise ValueError("versioned source hash does not match manifest")
    if manifest.normalization_version != NORMALIZATION_VERSION:
        raise ValueError("versioned source normalization version is not supported")
    if manifest.source_name == "cve_program":
        return _normalize_cve(manifest, raw)
    if manifest.source_name == "cisa_directive":
        return _normalize_cisa(manifest, raw)
    if manifest.source_name == "netscaler_advisory":
        return _normalize_netscaler(manifest, raw)
    raise ValueError("unsupported three-family source")
