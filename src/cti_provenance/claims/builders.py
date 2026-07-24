"""Deterministic builders for the Phase 2 plumbing-only offline corpus."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from pydantic import JsonValue

from cti_provenance.normalize import (
    NormalizedDocument,
    create_span,
    verify_raw_round_trip,
)
from cti_provenance.snapshot import SnapshotManifest, SnapshotState, SyntheticEvidence

FIXTURE_NORMALIZATION_VERSION = "phase2-plumbing-fixture-v1"
FIXTURE_GENERATOR_VERSION = "phase2-plumbing-v1"
SCOPE_LABEL = "log4shell-plumbing-only"
FIXTURE_MANIFEST_PATH = Path("data/manifests/phase2-offline-fixtures.jsonl")
_FIELD_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
type RepresentedSource = Literal[
    "nvd",
    "cisa_kev",
    "red_hat_rhsa",
    "untrusted_secondary",
]


class FixtureBuildError(ValueError):
    """A tracked synthetic fixture does not satisfy the offline-slice contract."""


def _safe_read(root: Path, relative_path: str) -> bytes:
    relative = PurePosixPath(relative_path)
    candidate = root.joinpath(*relative.parts)
    root_resolved = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise FixtureBuildError("fixture path escapes the repository root") from exc
    current = candidate
    while current != root:
        is_junction = getattr(current, "is_junction", None)
        if current.is_symlink() or (callable(is_junction) and is_junction()):
            raise FixtureBuildError("fixture path traverses a link or junction")
        current = current.parent
    return resolved.read_bytes()


def _object(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise FixtureBuildError(f"fixture {key} must be an object")
    return value


def normalize_plumbing_fixture(
    raw: bytes, manifest: SnapshotManifest
) -> NormalizedDocument:
    """Normalize one project-authored fixture without implying source authority."""
    if (
        manifest.source_name != "synthetic_control"
        or manifest.source_class != "synthetic"
        or manifest.normalization_version != FIXTURE_NORMALIZATION_VERSION
        or manifest.byte_length != len(raw)
        or manifest.sha256 != hashlib.sha256(raw).hexdigest()
    ):
        raise FixtureBuildError("manifest does not bind the Phase 2 fixture bytes")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureBuildError("Phase 2 fixture is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise FixtureBuildError("Phase 2 fixture root must be an object")
    notice = payload.get("fixture_notice")
    represented = payload.get("represented_source_name")
    if (
        not isinstance(notice, str)
        or "synthetic" not in notice.lower()
        or "plumbing-only" not in notice.lower()
        or payload.get("fixture_version") != FIXTURE_GENERATOR_VERSION
        or payload.get("scope_label") != SCOPE_LABEL
        or represented not in {"nvd", "cisa_kev", "red_hat_rhsa", "untrusted_secondary"}
    ):
        raise FixtureBuildError("fixture lacks the explicit plumbing-only boundary")
    if represented == "red_hat_rhsa" and payload.get("timing_basis") != (
        "publisher-declared-version-evidence"
    ):
        raise FixtureBuildError(
            "Red Hat fixture must label publisher-declared version evidence"
        )
    document = _object(payload, "document")
    document_id = document.get("document_id")
    upstream_entity_id = document.get("upstream_entity_id")
    title = document.get("title")
    fields = document.get("fields")
    if (
        not isinstance(document_id, str)
        or not document_id
        or ":" in document_id
        or any(character.isspace() for character in document_id)
        or not isinstance(upstream_entity_id, str)
        or not upstream_entity_id
        or not isinstance(title, str)
        or not title
        or not isinstance(fields, list)
        or not fields
    ):
        raise FixtureBuildError("fixture document identity or fields are invalid")

    chunks = [
        f"{title}\n",
        "Scope: Log4Shell plumbing-only synthetic control\n",
    ]
    span_specs: list[tuple[str, str, int, int, str]] = []
    normalized_fields: dict[str, JsonValue] = {
        "scope_label": SCOPE_LABEL,
        "represented_source_name": cast(RepresentedSource, represented),
    }
    if represented == "red_hat_rhsa":
        normalized_fields["timing_basis"] = "publisher-declared-version-evidence"
    field_ids: set[str] = set()
    for field_index, field in enumerate(fields):
        if not isinstance(field, dict):
            raise FixtureBuildError("fixture field must be an object")
        field_id = field.get("field_id")
        label = field.get("label")
        value = field.get("value")
        if (
            not isinstance(field_id, str)
            or _FIELD_ID_RE.fullmatch(field_id) is None
            or field_id in field_ids
            or not isinstance(label, str)
            or not label
        ):
            raise FixtureBuildError("fixture field identity is invalid or duplicate")
        field_ids.add(field_id)
        if isinstance(value, str) and value:
            values = [value]
            normalized_fields[field_id] = value
            locator_base = f"/document/fields/{field_index}/value"
        elif (
            isinstance(value, list)
            and value
            and all(isinstance(item, str) and item for item in value)
            and len(value) == len(set(value))
        ):
            values = value
            normalized_fields[field_id] = cast(JsonValue, value)
            locator_base = f"/document/fields/{field_index}/value"
        else:
            raise FixtureBuildError(
                "fixture field value must be a string or string set"
            )
        for value_index, item in enumerate(values):
            suffix = f"-{value_index}" if len(values) > 1 else ""
            line_label = f"{label}[{value_index}]" if len(values) > 1 else label
            prefix = f"{line_label}: "
            start = sum(len(chunk) for chunk in chunks) + len(prefix)
            chunks.append(f"{prefix}{item}\n")
            locator = (
                f"{locator_base}/{value_index}"
                if isinstance(value, list)
                else locator_base
            )
            span_specs.append(
                (
                    f"{field_id}{suffix}",
                    (
                        f"/fields/{field_id}/{value_index}"
                        if isinstance(value, list)
                        else f"/fields/{field_id}"
                    ),
                    start,
                    start + len(item),
                    locator,
                )
            )
    normalized_text = "".join(chunks).rstrip("\n")
    spans = [
        create_span(
            span_id=span_id,
            field_path=field_path,
            normalized_text=normalized_text,
            start_char=start,
            end_char=end,
            raw_locator=raw_locator,
            raw_locator_unavailable_reason=None,
            raw_snapshot_id=manifest.snapshot_id,
            raw_snapshot_sha256=manifest.sha256,
            normalization_version=FIXTURE_NORMALIZATION_VERSION,
        )
        for span_id, field_path, start, end, raw_locator in span_specs
    ]
    normalized = NormalizedDocument(
        document_id=document_id,
        snapshot_id=manifest.snapshot_id,
        upstream_entity_id=upstream_entity_id,
        title=title,
        canonical_url=str(manifest.source_url),
        published_at=None,
        modified_at=None,
        source_name="synthetic_control",
        source_class="synthetic",
        normalization_version=FIXTURE_NORMALIZATION_VERSION,
        normalized_text=normalized_text,
        normalized_text_sha256=hashlib.sha256(
            normalized_text.encode("utf-8")
        ).hexdigest(),
        fields=normalized_fields,
        spans=spans,
    )
    for span in normalized.spans:
        verify_raw_round_trip(span, normalized_text=normalized_text, raw=raw)
    return normalized


def load_phase2_plumbing_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument]]:
    """Load, hash-check, and normalize the tracked offline fixture corpus."""
    manifest_bytes = _safe_read(root, FIXTURE_MANIFEST_PATH.as_posix())
    manifests: list[SnapshotManifest] = []
    for line_number, line in enumerate(manifest_bytes.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            manifests.append(SnapshotManifest.model_validate_json(line))
        except ValueError as exc:
            raise FixtureBuildError(
                f"invalid Phase 2 fixture manifest line {line_number}"
            ) from exc
    if len(manifests) != 4 or len(
        {manifest.snapshot_id for manifest in manifests}
    ) != len(manifests):
        raise FixtureBuildError("Phase 2 fixture manifest set must contain four IDs")
    states: list[SnapshotState] = []
    documents: list[NormalizedDocument] = []
    for manifest in sorted(manifests, key=lambda item: item.snapshot_id):
        if (
            manifest.upstream_version is None
            or not manifest.upstream_version.isdecimal()
        ):
            raise FixtureBuildError("synthetic fixture sequence is invalid")
        raw = _safe_read(root, manifest.raw_blob_path)
        documents.append(normalize_plumbing_fixture(raw, manifest))
        states.append(
            SnapshotState(
                manifest=manifest,
                synthetic_evidence=SyntheticEvidence(
                    generator_version=FIXTURE_GENERATOR_VERSION,
                    fixture_sequence=int(manifest.upstream_version),
                ),
            )
        )
    return states, documents
