"""Cutoff-first snapshot selection for deterministic grading."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import groupby

from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.snapshot.admissibility import (
    AdmissibilityError,
    SnapshotState,
    select_admissible_snapshot,
)
from cti_provenance.snapshot.manifest import SnapshotManifest


@dataclass(frozen=True)
class TemporalSnapshotView:
    """A cutoff-selected view plus typed reasons excluded states cannot support."""

    states_by_snapshot_id: dict[str, SnapshotState]
    eligible_manifests: dict[str, SnapshotManifest]
    invalid_basis_snapshot_ids: frozenset[str]
    post_cutoff_snapshot_ids: frozenset[str]

    @property
    def eligible_snapshot_ids(self) -> frozenset[str]:
        return frozenset(self.eligible_manifests)


def build_temporal_view(
    case: BenchmarkCase, states: list[SnapshotState]
) -> TemporalSnapshotView:
    """Select admissible source states before inspecting any cited evidence.

    Invalid or incomparable groups are retained only as typed invalid-basis
    outcomes. They can never enter the eligible view.
    """

    by_snapshot_id: dict[str, SnapshotState] = {}
    for state in states:
        snapshot_id = state.manifest.snapshot_id
        if snapshot_id in by_snapshot_id:
            raise ValueError(f"duplicate snapshot_id {snapshot_id!r}")
        by_snapshot_id[snapshot_id] = state

    ordered = sorted(
        states,
        key=lambda state: (
            state.manifest.source_name,
            state.manifest.upstream_identifier or "",
            state.manifest.snapshot_id,
        ),
    )
    selected: dict[str, SnapshotManifest] = {}
    invalid: set[str] = set()
    post_cutoff: set[str] = set()
    for _, grouped in groupby(
        ordered,
        key=lambda state: (
            state.manifest.source_name,
            state.manifest.upstream_identifier,
        ),
    ):
        group = list(grouped)
        try:
            manifest = select_admissible_snapshot(group, case.as_of)
        except AdmissibilityError:
            invalid.update(state.manifest.snapshot_id for state in group)
            continue
        post_cutoff.update(
            state.manifest.snapshot_id
            for state in group
            if state.manifest.available_by_utc > case.as_of
        )
        if manifest is not None and manifest.snapshot_id in case.allowed_snapshot_ids:
            selected[manifest.snapshot_id] = manifest

    return TemporalSnapshotView(
        states_by_snapshot_id=by_snapshot_id,
        eligible_manifests=selected,
        invalid_basis_snapshot_ids=frozenset(invalid),
        post_cutoff_snapshot_ids=frozenset(post_cutoff),
    )
