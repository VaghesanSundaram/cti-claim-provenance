"""Declarative normalizers for the portfolio proof-family batch."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    model_validator,
)

from cti_provenance.claims.schema import PredicateName
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.normalize.spans import (
    create_span,
    verify_raw_json_round_trip,
    verify_raw_round_trip,
)
from cti_provenance.snapshot import SnapshotManifest

NORMALIZATION_VERSION = "portfolio-proof-source-v1"
_NON_EMPTY = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_APACHE_SCOPE = (
    "This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions."
)


class ExtractionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: Literal[
        "security_release_text",
        "json_scalar",
        "stix_object_array",
        "json_membership",
        "markdown_release_versions",
        "html_contains",
    ]
    selector: _NON_EMPTY
    field: _NON_EMPTY
    span_id: _NON_EMPTY
    value_pattern: str | None = None

    @model_validator(mode="after")
    def validate_pattern_use(self) -> ExtractionSpec:
        if (self.kind == "markdown_release_versions") != (
            self.value_pattern is not None
        ):
            raise ValueError(
                "value_pattern is required only for markdown_release_versions"
            )
        return self


class ClaimSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    subject_type: Literal["cve", "product", "advisory", "attack_object"]
    subject_id: _NON_EMPTY
    predicate: PredicateName
    datatype: Literal[
        "boolean",
        "string",
        "date",
        "decimal",
        "version_set",
        "identifier_set",
    ]
    authority: _NON_EMPTY
    product: str | None
    ecosystem: str | None


class FamilySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    family_id: _NON_EMPTY
    template_family_id: _NON_EMPTY
    title: _NON_EMPTY
    dominant_stratum: Literal[
        "vendor_project",
        "public_coordination_exploitation",
        "structured_cti_vulnerability",
    ]
    prospective_split: Literal["dev", "validation", "holdout_candidate"]
    incident_campaign_lineage: _NON_EMPTY
    vendor_product_lineage: _NON_EMPTY
    source_release_lineage: _NON_EMPTY
    challenge_generator_family: _NON_EMPTY
    coarsest_shared_dependency: _NON_EMPTY
    source_name: Literal["vendor_advisory", "cisa_kev", "mitre_attack", "nvd"]
    source_state_ids: list[_NON_EMPTY] = Field(min_length=2, max_length=2)
    extraction: ExtractionSpec
    expected_values: list[JsonValue] = Field(min_length=2, max_length=2)
    claim: ClaimSpec


class PortfolioFamilyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["portfolio-family-spec-v1"]
    families: list[FamilySpec] = Field(min_length=1)


class FamilyLineageRecord(BaseModel):
    """Split-unit identity shared by legacy and declarative portfolio families."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    family_id: _NON_EMPTY
    dominant_stratum: Literal[
        "vendor_project",
        "public_coordination_exploitation",
        "structured_cti_vulnerability",
    ]
    prospective_split: Literal["dev", "validation", "holdout_candidate"]
    incident_campaign_lineage: _NON_EMPTY
    vendor_product_lineage: _NON_EMPTY
    source_release_lineage: _NON_EMPTY
    template_family_id: _NON_EMPTY
    challenge_generator_family: _NON_EMPTY
    coarsest_shared_dependency: _NON_EMPTY


class PortfolioLineageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["portfolio-family-lineage-v1"]
    families: list[FamilyLineageRecord] = Field(min_length=1)


def validate_portfolio_dependency_splits(
    families: Sequence[FamilySpec | FamilyLineageRecord],
) -> None:
    """Keep every recorded dependency lineage in exactly one split."""

    dependency_fields = (
        "incident_campaign_lineage",
        "vendor_product_lineage",
        "source_release_lineage",
        "template_family_id",
        "challenge_generator_family",
        "coarsest_shared_dependency",
    )
    for field_name in dependency_fields:
        dependency_splits: dict[str, str] = {}
        for family in families:
            dependency = str(getattr(family, field_name))
            previous = dependency_splits.setdefault(
                dependency, family.prospective_split
            )
            if previous != family.prospective_split:
                raise ValueError(f"shared {field_name} cannot cross prospective splits")


def load_portfolio_lineage_config(path: Path) -> PortfolioLineageConfig:
    """Load and audit the complete eligible-family dependency registry."""

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    config = PortfolioLineageConfig.model_validate(payload)
    ids = [family.family_id for family in config.families]
    if len(ids) != len(set(ids)):
        raise ValueError("portfolio lineage family identities must be unique")
    validate_portfolio_dependency_splits(config.families)
    return config


def load_portfolio_family_config(path: Path) -> PortfolioFamilyConfig:
    """Load a fixed family spec without interpolation or executable hooks."""

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    config = PortfolioFamilyConfig.model_validate(payload)
    ids = [family.family_id for family in config.families]
    snapshots = [item for family in config.families for item in family.source_state_ids]
    if len(ids) != len(set(ids)) or len(snapshots) != len(set(snapshots)):
        raise ValueError("portfolio family identities must be unique")
    validate_portfolio_dependency_splits(config.families)
    return config


def _base_document(
    manifest: SnapshotManifest,
    spec: FamilySpec,
    *,
    normalized_text: str,
    fields: dict[str, JsonValue],
    target: str | None,
    raw_locator: str | None,
) -> NormalizedDocument:
    spans = []
    if target is not None:
        start = normalized_text.index(target)
        spans.append(
            create_span(
                span_id=spec.extraction.span_id,
                field_path=spec.extraction.field,
                normalized_text=normalized_text,
                start_char=start,
                end_char=start + len(target),
                raw_locator=raw_locator,
                raw_locator_unavailable_reason=(
                    None
                    if raw_locator is not None
                    else "plain-text release note has no structured raw locator"
                ),
                raw_snapshot_id=manifest.snapshot_id,
                raw_snapshot_sha256=manifest.sha256,
                normalization_version=NORMALIZATION_VERSION,
            )
        )
    return NormalizedDocument(
        document_id=f"{spec.family_id}-{manifest.snapshot_id}",
        snapshot_id=manifest.snapshot_id,
        upstream_entity_id=manifest.upstream_identifier or spec.family_id,
        title=spec.title,
        canonical_url=manifest.source_url,
        published_at=manifest.effective_date_if_known,
        modified_at=manifest.effective_date_if_known,
        source_name=manifest.source_name,
        source_class=manifest.source_class,
        normalization_version=NORMALIZATION_VERSION,
        normalized_text=normalized_text,
        normalized_text_sha256=hashlib.sha256(normalized_text.encode()).hexdigest(),
        fields={**fields, "publisher_authority": spec.claim.authority},
        spans=spans,
    )


def _apache(
    manifest: SnapshotManifest, raw: bytes, spec: FamilySpec
) -> NormalizedDocument:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Apache release note is not UTF-8") from exc
    normalized_text = re.sub(r"\s+", " ", text).strip()
    has_correction = spec.extraction.selector in normalized_text
    if has_correction and _APACHE_SCOPE not in normalized_text:
        raise ValueError("Apache correction lacks the exact affected-version scope")
    versions = (
        re.findall(r"Apache (2\.4\.\d+)", _APACHE_SCOPE) if has_correction else []
    )
    return _base_document(
        manifest,
        spec,
        normalized_text=normalized_text,
        fields={
            "claim_value": versions,
            "publisher_version": manifest.upstream_version,
        },
        target=_APACHE_SCOPE if has_correction else None,
        raw_locator=None,
    )


def _kev(
    manifest: SnapshotManifest, raw: bytes, spec: FamilySpec
) -> NormalizedDocument:
    try:
        payload = json.loads(raw)
        index, entry = next(
            (index, entry)
            for index, entry in enumerate(payload["vulnerabilities"])
            if entry.get("cveID") == spec.extraction.selector
        )
        value = entry[spec.extraction.field]
        released = datetime.fromisoformat(
            payload["dateReleased"].replace("Z", "+00:00")
        )
    except (KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("CISA KEV proof entry has an unexpected shape") from exc
    if not isinstance(value, str):
        raise ValueError("CISA KEV proof field must be a string")
    text = f"{spec.extraction.selector}\n{spec.extraction.field}: {value}"
    locator = f"/vulnerabilities/{index}/{spec.extraction.field}"
    document = _base_document(
        manifest,
        spec,
        normalized_text=text,
        fields={
            "claim_value": value,
            "catalog_version": payload["catalogVersion"],
            "catalog_date_released": released.isoformat(),
        },
        target=value,
        raw_locator=locator,
    )
    verify_raw_round_trip(document.spans[0], normalized_text=text, raw=raw)
    return document


def _external_id(item: dict[str, Any]) -> str | None:
    return next(
        (
            reference.get("external_id")
            for reference in item.get("external_references", [])
            if reference.get("source_name") == "mitre-attack"
        ),
        None,
    )


def _attack(
    manifest: SnapshotManifest, raw: bytes, spec: FamilySpec
) -> NormalizedDocument:
    try:
        payload = json.loads(raw)
        index, item = next(
            (index, item)
            for index, item in enumerate(payload["objects"])
            if item.get("type") == "attack-pattern"
            and _external_id(item) == spec.extraction.selector
        )
        value = item[spec.extraction.field]
    except (KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("ATT&CK proof object has an unexpected shape") from exc
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(platform, str) and platform for platform in value)
    ):
        raise ValueError("ATT&CK platform field must be a non-empty string list")
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
    text = f"{spec.extraction.selector} {item.get('name', '')}\nPlatforms: {rendered}"
    locator = f"/objects/{index}/{spec.extraction.field}"
    document = _base_document(
        manifest,
        spec,
        normalized_text=text,
        fields={
            "claim_value": value,
            "object_id": item.get("id"),
            "object_version": item.get("x_mitre_version"),
        },
        target=rendered,
        raw_locator=locator,
    )
    verify_raw_json_round_trip(document.spans[0], normalized_text=text, raw=raw)
    return document


def _kev_membership(
    manifest: SnapshotManifest, raw: bytes, spec: FamilySpec
) -> NormalizedDocument:
    try:
        payload = json.loads(raw)
        entries = payload["vulnerabilities"]
        match = next(
            (
                (index, entry)
                for index, entry in enumerate(entries)
                if entry.get("cveID") == spec.extraction.selector
            ),
            None,
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("CISA KEV catalog has an unexpected shape") from exc
    value = match is not None
    text = f"{spec.extraction.selector}\nKEV member: {str(value).lower()}"
    locator = f"/vulnerabilities/{match[0]}/cveID" if match is not None else None
    document = _base_document(
        manifest,
        spec,
        normalized_text=text,
        fields={"claim_value": value, "catalog_version": payload["catalogVersion"]},
        target=spec.extraction.selector if match is not None else None,
        raw_locator=locator,
    )
    if match is not None:
        verify_raw_round_trip(document.spans[0], normalized_text=text, raw=raw)
    return document


def _markdown_release_versions(
    manifest: SnapshotManifest, raw: bytes, spec: FamilySpec
) -> NormalizedDocument:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("project release document is not UTF-8") from exc
    if spec.extraction.value_pattern is None:
        raise ValueError("project release extraction pattern is missing")
    versions = re.findall(spec.extraction.value_pattern, text)
    if not all(isinstance(value, str) for value in versions):
        raise ValueError("project release extraction must produce one capture group")
    versions = list(dict.fromkeys(versions))
    target = None
    if versions:
        lines = [line for line in text.splitlines() if spec.extraction.selector in line]
        target = "\n".join(lines[: len(versions)])
    return _base_document(
        manifest,
        spec,
        normalized_text=text,
        fields={"claim_value": versions},
        target=target,
        raw_locator=None,
    )


def _html_contains(
    manifest: SnapshotManifest, raw: bytes, spec: FamilySpec
) -> NormalizedDocument:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("publisher change record is not UTF-8") from exc
    value = spec.extraction.selector in text
    return _base_document(
        manifest,
        spec,
        normalized_text=text,
        fields={"claim_value": value},
        target=spec.extraction.selector if value else None,
        raw_locator=None,
    )


def normalize_portfolio_source(
    manifest: SnapshotManifest, raw: bytes, spec: FamilySpec
) -> NormalizedDocument:
    """Normalize one manifest-bound source using a closed extraction kind."""

    if (
        manifest.snapshot_id not in spec.source_state_ids
        or manifest.source_name != spec.source_name
        or manifest.normalization_version != NORMALIZATION_VERSION
        or len(raw) != manifest.byte_length
        or hashlib.sha256(raw).hexdigest() != manifest.sha256
    ):
        raise ValueError("portfolio source does not match its manifest and family spec")
    if spec.extraction.kind == "security_release_text":
        return _apache(manifest, raw, spec)
    if spec.extraction.kind == "json_scalar":
        return _kev(manifest, raw, spec)
    if spec.extraction.kind == "stix_object_array":
        return _attack(manifest, raw, spec)
    if spec.extraction.kind == "json_membership":
        return _kev_membership(manifest, raw, spec)
    if spec.extraction.kind == "markdown_release_versions":
        return _markdown_release_versions(manifest, raw, spec)
    if spec.extraction.kind == "html_contains":
        return _html_contains(manifest, raw, spec)
    raise ValueError("unsupported portfolio extraction kind")
