"""Fail-closed, source-specific cutoff selection for frozen snapshots."""

from __future__ import annotations

import re
from dataclasses import field
from datetime import UTC, datetime
from itertools import groupby

from pydantic import ConfigDict
from pydantic.dataclasses import dataclass

from cti_provenance.snapshot.manifest import SnapshotManifest


class AdmissibilityError(ValueError):
    """A manifest cannot be admitted under the frozen source rules."""


class AmbiguousSnapshotState(AdmissibilityError):
    """Distinct maximum-time states have no validated total choice."""


_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$")
_INTEGER_RE = re.compile(r"^(0|[1-9]\d*)$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
_ATTACK_TAG_RE = re.compile(r"^v(\d+(?:\.\d+)*)$")


@dataclass(frozen=True, config=ConfigDict(strict=True))
class CisaEvidence:
    """Validated CISA mirror/commit provenance for an upstream state."""

    commit_sha: str
    official_commit_time_utc: datetime
    mirror_relationship_verified: bool
    ancestry_verified: bool


@dataclass(frozen=True, config=ConfigDict(strict=True))
class AttackEvidence:
    """Validated release metadata for a release-specific ATT&CK bundle."""

    release_tag: str
    release_semantic_version: str
    commit_sha: str
    release_metadata_verified: bool
    publisher_release_time_utc: datetime
    bundle_sha256: str


@dataclass(frozen=True, config=ConfigDict(strict=True))
class RedHatEvidence:
    """Validated final CSAF state and checksum evidence for one RHSA."""

    final_status: bool
    tracking_id: str
    revision_version: str
    complete_revision_history: bool
    final_revision_date_utc: datetime
    current_release_date_utc: datetime
    published_sha256: str


@dataclass(frozen=True, config=ConfigDict(strict=True))
class SyntheticEvidence:
    """Deterministic generator metadata for a synthetic control."""

    generator_version: str
    fixture_sequence: int


@dataclass(frozen=True, config=ConfigDict(strict=True))
class PublisherVersionEvidence:
    """Publisher-declared ordering for one independently addressable version."""

    version_identifier: str
    publisher_declared_time_utc: datetime
    independently_addressable: bool


@dataclass(frozen=True, config=ConfigDict(strict=True))
class SnapshotState:
    """A manifest plus validated ordering evidence not represented in its bytes."""

    manifest: SnapshotManifest
    cisa_ancestor_snapshot_ids: frozenset[str] = field(default_factory=frozenset)
    cisa_evidence: CisaEvidence | None = None
    attack_evidence: AttackEvidence | None = None
    red_hat_evidence: RedHatEvidence | None = None
    synthetic_evidence: SyntheticEvidence | None = None
    publisher_version_evidence: PublisherVersionEvidence | None = None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AdmissibilityError("cutoff must be timezone-aware UTC")
    if value.utcoffset() != UTC.utcoffset(value):
        raise AdmissibilityError("cutoff must use UTC offset")
    return value.astimezone(UTC)


def _version(value: str | None) -> tuple[int, ...]:
    match = _VERSION_RE.fullmatch(value or "")
    if match is None:
        raise AdmissibilityError("source state requires a validated semantic version")
    return tuple(int(part) for part in match.group(1).split("."))


def _utc_equal(left: datetime, right: datetime) -> bool:
    return _utc(left) == _utc(right)


def _valid_commit(value: str) -> bool:
    return _COMMIT_RE.fullmatch(value) is not None


def _attack_tag_matches(tag: str, version: str) -> bool:
    match = _ATTACK_TAG_RE.fullmatch(tag)
    return match is not None and _version(match.group(1)) == _version(version)


def _has_exact_evidence_shape(state: SnapshotState) -> bool:
    """Reject metadata from another source instead of ignoring it."""
    source = state.manifest.source_name
    only_cisa = (
        state.cisa_evidence is not None
        and state.attack_evidence is None
        and state.red_hat_evidence is None
        and state.synthetic_evidence is None
        and state.publisher_version_evidence is None
    )
    none = (
        state.cisa_evidence is None
        and state.attack_evidence is None
        and state.red_hat_evidence is None
        and state.synthetic_evidence is None
        and state.publisher_version_evidence is None
        and not state.cisa_ancestor_snapshot_ids
    )
    if source == "nvd":
        publisher_only = (
            state.cisa_evidence is None
            and state.attack_evidence is None
            and state.red_hat_evidence is None
            and state.synthetic_evidence is None
            and state.publisher_version_evidence is not None
            and not state.cisa_ancestor_snapshot_ids
        )
        return none or publisher_only
    if source == "cisa_kev":
        return only_cisa or none
    if source == "mitre_attack":
        return (
            state.cisa_evidence is None
            and state.attack_evidence is not None
            and state.red_hat_evidence is None
            and state.synthetic_evidence is None
            and state.publisher_version_evidence is None
            and not state.cisa_ancestor_snapshot_ids
        )
    if source == "red_hat_rhsa":
        return (
            state.cisa_evidence is None
            and state.attack_evidence is None
            and state.red_hat_evidence is not None
            and state.synthetic_evidence is None
            and state.publisher_version_evidence is None
            and not state.cisa_ancestor_snapshot_ids
        )
    if source == "synthetic_control":
        return (
            state.cisa_evidence is None
            and state.attack_evidence is None
            and state.red_hat_evidence is None
            and state.synthetic_evidence is not None
            and state.publisher_version_evidence is None
            and not state.cisa_ancestor_snapshot_ids
        )
    if source in {
        "cisa_directive",
        "cve_program",
        "netscaler_advisory",
        "vendor_advisory",
    }:
        return (
            state.cisa_evidence is None
            and state.attack_evidence is None
            and state.red_hat_evidence is None
            and state.synthetic_evidence is None
            and state.publisher_version_evidence is not None
            and not state.cisa_ancestor_snapshot_ids
        )
    return none


def _validate_basis(state: SnapshotState) -> None:
    manifest = state.manifest
    source = manifest.source_name
    shape_valid = _has_exact_evidence_shape(state)
    if source == "nvd":
        evidence = state.publisher_version_evidence
        if manifest.available_by_basis == "observed_retrieval":
            valid = shape_valid and evidence is None
        else:
            valid = (
                shape_valid
                and manifest.available_by_basis == "publisher_declared_version"
                and bool(manifest.upstream_identifier)
                and bool(manifest.upstream_version)
                and evidence is not None
                and evidence.independently_addressable
                and evidence.version_identifier == manifest.upstream_version
                and _utc_equal(
                    evidence.publisher_declared_time_utc, manifest.available_by_utc
                )
                and manifest.effective_date_basis == "publisher_version"
                and manifest.effective_date_if_known is not None
                and _utc_equal(
                    manifest.effective_date_if_known, manifest.available_by_utc
                )
                and manifest.retrieved_at_utc >= manifest.available_by_utc
            )
    elif source in {
        "cisa_directive",
        "cve_program",
        "netscaler_advisory",
        "vendor_advisory",
    }:
        evidence = state.publisher_version_evidence
        valid = (
            shape_valid
            and manifest.available_by_basis == "publisher_declared_version"
            and bool(manifest.upstream_identifier)
            and bool(manifest.upstream_version)
            and evidence is not None
            and evidence.independently_addressable
            and evidence.version_identifier == manifest.upstream_version
            and _utc_equal(
                evidence.publisher_declared_time_utc, manifest.available_by_utc
            )
            and manifest.effective_date_basis == "publisher_version"
            and manifest.effective_date_if_known is not None
            and _utc_equal(manifest.effective_date_if_known, manifest.available_by_utc)
            and manifest.retrieved_at_utc >= manifest.available_by_utc
        )
    elif source == "cisa_kev":
        if manifest.available_by_basis == "observed_retrieval":
            valid = (
                shape_valid
                and manifest.available_by_utc == manifest.retrieved_at_utc
                and state.cisa_evidence is None
                and state.cisa_ancestor_snapshot_ids == frozenset()
                and manifest.upstream_version is None
            )
        else:
            cisa_evidence = state.cisa_evidence
            valid = (
                shape_valid
                and manifest.available_by_basis == "upstream_version"
                and bool(manifest.upstream_identifier)
                and bool(manifest.upstream_version)
                and cisa_evidence is not None
                and _valid_commit(cisa_evidence.commit_sha)
                and cisa_evidence.commit_sha == manifest.upstream_version
                and _utc_equal(
                    cisa_evidence.official_commit_time_utc, manifest.available_by_utc
                )
                and cisa_evidence.mirror_relationship_verified
                and cisa_evidence.ancestry_verified
                and manifest.effective_date_basis == "publisher_version"
                and manifest.effective_date_if_known is not None
                and _utc_equal(
                    manifest.effective_date_if_known, manifest.available_by_utc
                )
                and manifest.retrieved_at_utc >= manifest.available_by_utc
            )
    elif source == "mitre_attack":
        attack_evidence = state.attack_evidence
        valid = (
            shape_valid
            and manifest.available_by_basis == "upstream_version"
            and bool(manifest.upstream_identifier)
            and bool(manifest.upstream_version)
            and attack_evidence is not None
            and _attack_tag_matches(
                attack_evidence.release_tag, attack_evidence.release_semantic_version
            )
            and _version(attack_evidence.release_semantic_version)
            == _version(manifest.upstream_version)
            and _valid_commit(attack_evidence.commit_sha)
            and attack_evidence.release_metadata_verified
            and _utc_equal(
                attack_evidence.publisher_release_time_utc, manifest.available_by_utc
            )
            and attack_evidence.bundle_sha256 == manifest.sha256
            and manifest.effective_date_basis == "publisher_version"
            and manifest.effective_date_if_known is not None
            and _utc_equal(manifest.effective_date_if_known, manifest.available_by_utc)
            and manifest.retrieved_at_utc >= manifest.available_by_utc
        )
    elif source == "red_hat_rhsa":
        red_hat_evidence = state.red_hat_evidence
        valid = (
            shape_valid
            and manifest.available_by_basis == "publisher_timestamp_with_observation"
            and bool(manifest.upstream_identifier)
            and bool(manifest.upstream_version)
            and red_hat_evidence is not None
            and red_hat_evidence.final_status
            and red_hat_evidence.tracking_id == manifest.upstream_identifier
            and _version(red_hat_evidence.revision_version)
            == _version(manifest.upstream_version)
            and red_hat_evidence.complete_revision_history
            and _utc_equal(
                red_hat_evidence.final_revision_date_utc, manifest.available_by_utc
            )
            and _utc_equal(
                red_hat_evidence.current_release_date_utc, manifest.available_by_utc
            )
            and red_hat_evidence.published_sha256 == manifest.sha256
            and manifest.effective_date_basis == "publisher_version"
            and manifest.effective_date_if_known is not None
            and _utc_equal(manifest.effective_date_if_known, manifest.available_by_utc)
            and manifest.retrieved_at_utc >= manifest.available_by_utc
        )
    elif source == "synthetic_control":
        synthetic_evidence = state.synthetic_evidence
        valid = (
            shape_valid
            and manifest.available_by_basis == "synthetic_fixture"
            and synthetic_evidence is not None
            and bool(synthetic_evidence.generator_version)
            and synthetic_evidence.fixture_sequence >= 0
            and _INTEGER_RE.fullmatch(manifest.upstream_version or "") is not None
            and int(manifest.upstream_version or "-1")
            == synthetic_evidence.fixture_sequence
        )
    else:  # SnapshotManifest keeps this exhaustive, but selection stays fail-closed.
        valid = False
    if not valid:
        raise AdmissibilityError(f"invalid {source} available_by basis evidence")


def _validate_synthetic_sequence(states: list[SnapshotState]) -> None:
    if states[0].manifest.source_name != "synthetic_control":
        return
    states_by_time: dict[datetime, list[SnapshotState]] = {}
    for state in states:
        states_by_time.setdefault(state.manifest.available_by_utc, []).append(state)
    maxima_by_time: dict[datetime, int] = {}
    for time, time_states in states_by_time.items():
        distinct_at_time = _collapse_identical(time_states)
        sequences: list[int] = []
        for state in distinct_at_time:
            evidence = state.synthetic_evidence
            if evidence is None:  # _validate_basis keeps this unreachable.
                raise AdmissibilityError("synthetic evidence is required")
            sequences.append(evidence.fixture_sequence)
        maxima_by_time[time] = max(sequences)
    previous_sequence: int | None = None
    for sequence in (maxima_by_time[time] for time in sorted(maxima_by_time)):
        if previous_sequence is not None and sequence <= previous_sequence:
            raise AdmissibilityError(
                "synthetic fixture sequence must increase over time"
            )
        previous_sequence = sequence


def _collapse_identical(states: list[SnapshotState]) -> list[SnapshotState]:
    distinct: dict[tuple[str, int], list[SnapshotState]] = {}
    for state in states:
        key = (state.manifest.sha256, state.manifest.byte_length)
        distinct.setdefault(key, []).append(state)
    representatives: list[SnapshotState] = []
    for duplicates in distinct.values():
        reference = duplicates[0]
        reference_manifest = reference.manifest.model_dump(
            mode="json", exclude={"snapshot_id"}
        )
        equivalent = all(
            candidate.manifest.model_dump(mode="json", exclude={"snapshot_id"})
            == reference_manifest
            and candidate.cisa_ancestor_snapshot_ids
            == reference.cisa_ancestor_snapshot_ids
            and candidate.cisa_evidence == reference.cisa_evidence
            and candidate.attack_evidence == reference.attack_evidence
            and candidate.red_hat_evidence == reference.red_hat_evidence
            and candidate.synthetic_evidence == reference.synthetic_evidence
            and candidate.publisher_version_evidence
            == reference.publisher_version_evidence
            for candidate in duplicates[1:]
        )
        if not equivalent:
            raise AmbiguousSnapshotState(
                "equal-byte states have conflicting provenance metadata"
            )
        representatives.append(
            min(duplicates, key=lambda state: state.manifest.snapshot_id)
        )
    return representatives


def _select_equal_time(states: list[SnapshotState]) -> SnapshotState:
    states = _collapse_identical(states)
    if len(states) == 1:
        return states[0]
    source = states[0].manifest.source_name
    if source == "cisa_kev":
        descendants = [
            state
            for state in states
            if all(
                other.manifest.snapshot_id == state.manifest.snapshot_id
                or other.manifest.snapshot_id in state.cisa_ancestor_snapshot_ids
                for other in states
            )
        ]
        if len(descendants) == 1:
            return descendants[0]
    elif source in {"mitre_attack", "red_hat_rhsa"}:
        keys = [_version(state.manifest.upstream_version) for state in states]
        maximum = max(keys)
        selected = [
            state for state, key in zip(states, keys, strict=True) if key == maximum
        ]
        if len(selected) == 1:
            return selected[0]
    elif source == "synthetic_control":
        sequence_keys: list[int] = []
        for state in states:
            evidence = state.synthetic_evidence
            if evidence is None:  # _validate_basis keeps this unreachable.
                raise AdmissibilityError("synthetic evidence is required")
            sequence_keys.append(evidence.fixture_sequence)
        sequence_maximum = max(sequence_keys)
        selected = [
            state
            for state, key in zip(states, sequence_keys, strict=True)
            if key == sequence_maximum
        ]
        if len(selected) == 1:
            return selected[0]
    raise AmbiguousSnapshotState(
        f"distinct equal-time {source} states are incomparable or collide"
    )


def select_admissible_snapshot(
    states: list[SnapshotState], cutoff: datetime
) -> SnapshotManifest | None:
    """Select one source state, or fail closed for an invalid/ambiguous group."""
    if not states:
        return None
    cutoff = _utc(cutoff)
    key = (states[0].manifest.source_name, states[0].manifest.upstream_identifier)
    if any(
        (state.manifest.source_name, state.manifest.upstream_identifier) != key
        for state in states
    ):
        raise AdmissibilityError(
            "states must share source_name and upstream_identifier"
        )
    for state in states:
        _validate_basis(state)
    _validate_synthetic_sequence(states)
    eligible = [state for state in states if state.manifest.available_by_utc <= cutoff]
    if not eligible:
        return None
    maximum_time = max(state.manifest.available_by_utc for state in eligible)
    return _select_equal_time(
        [state for state in eligible if state.manifest.available_by_utc == maximum_time]
    ).manifest


def select_admissible_by_entity(
    states: list[SnapshotState], cutoff: datetime
) -> dict[tuple[str, str | None], SnapshotManifest]:
    """Select a local offline corpus view for every source/entity group."""
    ordered = sorted(
        states,
        key=lambda state: (
            state.manifest.source_name,
            state.manifest.upstream_identifier or "",
        ),
    )
    selected: dict[tuple[str, str | None], SnapshotManifest] = {}
    for key, group in groupby(
        ordered,
        key=lambda state: (
            state.manifest.source_name,
            state.manifest.upstream_identifier,
        ),
    ):
        result = select_admissible_snapshot(list(group), cutoff)
        if result is not None:
            selected[key] = result
    return selected
