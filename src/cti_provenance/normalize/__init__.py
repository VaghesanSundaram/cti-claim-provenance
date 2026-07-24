"""Normalized-document contracts and source-specific normalizers."""

from cti_provenance.normalize.common import EvidenceSpan, NormalizedDocument
from cti_provenance.normalize.kev import normalize_kev
from cti_provenance.normalize.nvd import normalize_nvd
from cti_provenance.normalize.portfolio import (
    FamilyLineageRecord,
    FamilySpec,
    PortfolioFamilyConfig,
    PortfolioLineageConfig,
    load_portfolio_family_config,
    load_portfolio_lineage_config,
    normalize_portfolio_source,
    validate_portfolio_dependency_splits,
)
from cti_provenance.normalize.spans import (
    SpanResolutionError,
    create_span,
    resolve_json_pointer,
    resolve_span,
    verify_raw_round_trip,
)
from cti_provenance.normalize.vendor import normalize_red_hat
from cti_provenance.normalize.versioned import normalize_versioned_source

__all__ = [
    "EvidenceSpan",
    "FamilyLineageRecord",
    "FamilySpec",
    "NormalizedDocument",
    "PortfolioFamilyConfig",
    "PortfolioLineageConfig",
    "SpanResolutionError",
    "create_span",
    "load_portfolio_family_config",
    "load_portfolio_lineage_config",
    "normalize_kev",
    "normalize_nvd",
    "normalize_portfolio_source",
    "normalize_red_hat",
    "normalize_versioned_source",
    "resolve_json_pointer",
    "resolve_span",
    "validate_portfolio_dependency_splits",
    "verify_raw_round_trip",
]
