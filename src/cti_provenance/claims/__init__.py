"""Atomic claim contracts and lazily loaded development builders."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cti_provenance.claims.schema import (
    AtomicClaim,
    ClaimAnswer,
    ClaimEvidenceAnswer,
    GoldAtomicClaim,
    PredicateName,
)

if TYPE_CHECKING:
    from cti_provenance.claims.builders import (
        FIXTURE_GENERATOR_VERSION,
        FIXTURE_NORMALIZATION_VERSION,
        SCOPE_LABEL,
        FixtureBuildError,
        load_phase2_plumbing_corpus,
        normalize_plumbing_fixture,
    )
    from cti_provenance.claims.ground_truth import GroundTruthError, load_phase2_cases
    from cti_provenance.claims.real_slice import (
        RealSliceError,
        load_phase2_real_cases,
        load_phase2_real_corpus,
    )
    from cti_provenance.claims.three_family import (
        load_three_family_cases,
        load_three_family_corpus,
    )

_BUILDER_EXPORTS = {
    "FIXTURE_GENERATOR_VERSION",
    "FIXTURE_NORMALIZATION_VERSION",
    "SCOPE_LABEL",
    "FixtureBuildError",
    "load_phase2_plumbing_corpus",
    "normalize_plumbing_fixture",
}
_GROUND_TRUTH_EXPORTS = {"GroundTruthError", "load_phase2_cases"}
_REAL_SLICE_EXPORTS = {
    "RealSliceError",
    "load_phase2_real_cases",
    "load_phase2_real_corpus",
}
_THREE_FAMILY_EXPORTS = {"load_three_family_cases", "load_three_family_corpus"}


def __getattr__(name: str) -> object:
    """Load modules that depend on dataset contracts only when requested."""

    if name in _BUILDER_EXPORTS:
        from cti_provenance.claims import builders

        return getattr(builders, name)
    if name in _GROUND_TRUTH_EXPORTS:
        from cti_provenance.claims import ground_truth

        return getattr(ground_truth, name)
    if name in _REAL_SLICE_EXPORTS:
        from cti_provenance.claims import real_slice

        return getattr(real_slice, name)
    if name in _THREE_FAMILY_EXPORTS:
        from cti_provenance.claims import three_family

        return getattr(three_family, name)
    raise AttributeError(name)


__all__ = [
    "FIXTURE_GENERATOR_VERSION",
    "FIXTURE_NORMALIZATION_VERSION",
    "SCOPE_LABEL",
    "AtomicClaim",
    "ClaimAnswer",
    "ClaimEvidenceAnswer",
    "FixtureBuildError",
    "GoldAtomicClaim",
    "GroundTruthError",
    "PredicateName",
    "RealSliceError",
    "load_phase2_cases",
    "load_phase2_plumbing_corpus",
    "load_phase2_real_cases",
    "load_phase2_real_corpus",
    "load_three_family_cases",
    "load_three_family_corpus",
    "normalize_plumbing_fixture",
]
