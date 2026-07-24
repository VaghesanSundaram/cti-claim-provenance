from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.cli import main
from cti_provenance.config import (
    AuthorityPolicyConfig,
    MinimumSourcesConfig,
    PortfolioSourcesConfig,
    ScaleSourcesConfig,
    SourcesConfig,
    YieldSourcesConfig,
    load_authority_policy_config,
    load_minimum_project_config_files,
    load_minimum_sources_config,
    load_portfolio_project_config_files,
    load_portfolio_sources_config,
    load_project_config_files,
    load_scale_project_config_files,
    load_scale_sources_config,
    load_sources_config,
    load_yield_project_config_files,
    load_yield_sources_config,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCES_PATH = ROOT / "configs" / "sources.yaml"
AUTHORITY_PATH = ROOT / "configs" / "authority-policy.yaml"
THREE_FAMILY_AUTHORITY_PATH = ROOT / "configs" / "authority-policy-three-family-v1.yaml"
PORTFOLIO_PROOF_AUTHORITY_PATH = (
    ROOT / "configs" / "authority-policy-portfolio-proof-v1.yaml"
)
PORTFOLIO_PROOF_SOURCES_PATH = ROOT / "configs" / "sources-portfolio-proof-v1.yaml"
PORTFOLIO_YIELD_AUTHORITY_PATH = (
    ROOT / "configs" / "authority-policy-portfolio-yield-v1.yaml"
)
PORTFOLIO_YIELD_SOURCES_PATH = ROOT / "configs" / "sources-portfolio-yield-v1.yaml"
PORTFOLIO_SCALE_AUTHORITY_PATH = (
    ROOT / "configs" / "authority-policy-portfolio-scale-v1.yaml"
)
PORTFOLIO_SCALE_SOURCES_PATH = ROOT / "configs" / "sources-portfolio-scale-v1.yaml"
PORTFOLIO_MINIMUM_AUTHORITY_PATH = (
    ROOT / "configs" / "authority-policy-portfolio-minimum-v1.yaml"
)
PORTFOLIO_MINIMUM_SOURCES_PATH = ROOT / "configs" / "sources-portfolio-minimum-v1.yaml"

VALID_SOURCE = {
    "source_name": "nvd",
    "source_class": "government",
    "canonical_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "temporal_truth_mode": "observed_snapshot",
    "available_by_basis": "observed_retrieval",
    "redistribution_default": "metadata_hash_and_fetch_recipe",
}
VALID_POLICY = {
    "policy_id": "nvd-publication-time",
    "predicates": ["cve.published_at"],
    "primary_sources": ["nvd"],
    "acceptable_corroboration": ["cve_program"],
    "conflict_action": "preserve_named_source_values",
}


def test_checked_in_config_files_load_and_cross_validate() -> None:
    sources, authority = load_project_config_files(SOURCES_PATH, AUTHORITY_PATH)
    assert sources.version == "sources-v1"
    assert authority.version == "authority-policy-v1"
    assert len(sources.sources) == 5
    assert len(authority.policies) == 5
    assert main(["config", "check"]) == 0
    assert main(["config", "provider-check"]) == 0

    three_family = load_authority_policy_config(THREE_FAMILY_AUTHORITY_PATH)
    assert three_family.version == "authority-policy-three-family-v1"
    assert {policy.policy_id for policy in three_family.policies} == {
        "cve-program-affected-versions",
        "cisa-directive-required-action",
        "vendor-recommended-action",
    }

    portfolio_proof = load_authority_policy_config(PORTFOLIO_PROOF_AUTHORITY_PATH)
    assert portfolio_proof.version == "authority-policy-portfolio-proof-v1"
    assert {policy.policy_id for policy in portfolio_proof.policies} == {
        "apache-release-affected-versions",
        "cisa-kev-ransomware-use",
        "mitre-attack-platforms",
    }
    portfolio_sources, portfolio_authority = load_portfolio_project_config_files(
        PORTFOLIO_PROOF_SOURCES_PATH,
        PORTFOLIO_PROOF_AUTHORITY_PATH,
    )
    assert portfolio_sources.version == "sources-portfolio-proof-v1"
    assert portfolio_authority.version == "authority-policy-portfolio-proof-v1"
    assert {source.source_name for source in portfolio_sources.sources} == {
        "vendor_advisory",
        "cisa_kev",
        "mitre_attack",
    }
    yield_sources, yield_authority = load_yield_project_config_files(
        PORTFOLIO_YIELD_SOURCES_PATH,
        PORTFOLIO_YIELD_AUTHORITY_PATH,
    )
    assert yield_sources.version == "sources-portfolio-yield-v1"
    assert yield_authority.version == "authority-policy-portfolio-yield-v1"
    assert {source.source_id for source in yield_sources.sources} == {
        "cisa_kev_catalog",
        "django_project",
        "nodejs_project",
        "nvd_change_history",
    }
    scale_sources, scale_authority = load_scale_project_config_files(
        PORTFOLIO_SCALE_SOURCES_PATH,
        PORTFOLIO_SCALE_AUTHORITY_PATH,
    )
    assert scale_sources.version == "sources-portfolio-scale-v1"
    assert scale_authority.version == "authority-policy-portfolio-scale-v1"
    assert {source.source_id for source in scale_sources.sources} == {
        "cisa_kev_catalog",
        "django_project",
        "jenkins_project",
        "nodejs_project",
        "nvd_change_history",
        "python_project",
        "rust_project",
    }
    minimum_sources, minimum_authority = load_minimum_project_config_files(
        PORTFOLIO_MINIMUM_SOURCES_PATH,
        PORTFOLIO_MINIMUM_AUTHORITY_PATH,
    )
    assert minimum_sources.version == "sources-portfolio-minimum-v1"
    assert minimum_authority.version == "authority-policy-portfolio-minimum-v1"
    assert [source.source_id for source in minimum_sources.sources] == [
        "postgresql_project"
    ]


def test_portfolio_source_catalog_is_closed() -> None:
    checked_in = load_portfolio_sources_config(PORTFOLIO_PROOF_SOURCES_PATH).model_dump(
        mode="python"
    )
    checked_in["sources"].pop()
    with pytest.raises(ValidationError, match="three sources"):
        PortfolioSourcesConfig.model_validate(checked_in)

    yield_checked_in = load_yield_sources_config(
        PORTFOLIO_YIELD_SOURCES_PATH
    ).model_dump(mode="python")
    yield_checked_in["sources"].pop()
    with pytest.raises(ValidationError, match="four sources"):
        YieldSourcesConfig.model_validate(yield_checked_in)

    scale_checked_in = load_scale_sources_config(
        PORTFOLIO_SCALE_SOURCES_PATH
    ).model_dump(mode="python")
    scale_checked_in["sources"].pop()
    with pytest.raises(ValidationError, match="seven sources"):
        ScaleSourcesConfig.model_validate(scale_checked_in)

    minimum_checked_in = load_minimum_sources_config(
        PORTFOLIO_MINIMUM_SOURCES_PATH
    ).model_dump(mode="python")
    minimum_checked_in["sources"][0]["source_id"] = "other_project"
    with pytest.raises(ValidationError):
        MinimumSourcesConfig.model_validate(minimum_checked_in)


def test_unknown_fields_and_malformed_enumerations_are_rejected() -> None:
    with pytest.raises(ValidationError):
        SourcesConfig.model_validate(
            {
                "version": "sources-v1",
                "sources": [{**VALID_SOURCE, "unexpected": True}],
            }
        )
    with pytest.raises(ValidationError):
        SourcesConfig.model_validate({"version": "sources-v1", "sources": []})
    with pytest.raises(ValidationError):
        AuthorityPolicyConfig.model_validate(
            {
                "version": "authority-policy-v1",
                "policies": [{**VALID_POLICY, "predicates": []}],
            }
        )
    with pytest.raises(ValidationError):
        SourcesConfig.model_validate(
            {
                "version": "sources-v1",
                "sources": [{**VALID_SOURCE, "temporal_truth_mode": "live_web"}],
            }
        )


def test_duplicate_sources_policy_ids_and_predicates_are_rejected() -> None:
    with pytest.raises(ValidationError, match="source_name"):
        SourcesConfig.model_validate(
            {
                "version": "sources-v1",
                "sources": [VALID_SOURCE, VALID_SOURCE],
            }
        )
    with pytest.raises(ValidationError, match="policy_id"):
        AuthorityPolicyConfig.model_validate(
            {
                "version": "authority-policy-v1",
                "policies": [VALID_POLICY, VALID_POLICY],
            }
        )
    second_policy = {
        **VALID_POLICY,
        "policy_id": "duplicate-predicate-policy",
    }
    with pytest.raises(ValidationError, match="predicate"):
        AuthorityPolicyConfig.model_validate(
            {
                "version": "authority-policy-v1",
                "policies": [VALID_POLICY, second_policy],
            }
        )


def test_safe_yaml_loading_rejects_unknown_python_tags(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text(
        "!!python/object/apply:os.system ['not executed']\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid YAML"):
        load_sources_config(path)


def test_frozen_config_versions_reject_missing_sources_and_predicates() -> None:
    checked_in_sources = load_sources_config(SOURCES_PATH)
    missing_source = checked_in_sources.model_dump(mode="python")
    missing_source["sources"].pop()
    with pytest.raises(ValidationError, match="every frozen source"):
        SourcesConfig.model_validate(missing_source)

    checked_in_authority = load_authority_policy_config(AUTHORITY_PATH)
    missing_policy = checked_in_authority.model_dump(mode="python")
    missing_policy["policies"].pop()
    with pytest.raises(ValidationError, match="every frozen predicate"):
        AuthorityPolicyConfig.model_validate(missing_policy)


def test_documented_external_authorities_do_not_require_source_entries() -> None:
    sources, authority = load_project_config_files(SOURCES_PATH, AUTHORITY_PATH)
    configured = {source.source_name for source in sources.sources}
    references = {
        source
        for policy in authority.policies
        for source in (*policy.primary_sources, *policy.acceptable_corroboration)
    }
    assert {"cve_program", "named_scoring_authority"} <= references
    assert {"cve_program", "named_scoring_authority"}.isdisjoint(configured)


def test_frozen_source_urls_and_policy_id_groupings_are_exact() -> None:
    sources = load_sources_config(SOURCES_PATH).model_dump(mode="python")
    sources["sources"][0]["canonical_url"] = "https://example.invalid/nvd"
    with pytest.raises(ValidationError, match="canonical_url"):
        SourcesConfig.model_validate(sources)

    authority = load_authority_policy_config(AUTHORITY_PATH).model_dump(mode="python")
    authority["policies"][0]["policy_id"] = "renamed-publication-policy"
    with pytest.raises(ValidationError, match="policy IDs"):
        AuthorityPolicyConfig.model_validate(authority)
