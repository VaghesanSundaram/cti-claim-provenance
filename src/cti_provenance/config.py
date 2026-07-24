"""Safe environment configuration with allowlist-only serialization."""

from __future__ import annotations

import os
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Annotated, ClassVar, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    SecretStr,
    StringConstraints,
    model_validator,
)

from cti_provenance.claims.schema import PredicateName

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
SourceName = Literal[
    "nvd",
    "cisa_kev",
    "mitre_attack",
    "red_hat_rhsa",
    "synthetic_control",
    "vendor_advisory",
]
SourceReference = Literal[
    "cisa_directive",
    "cve_program",
    "nvd",
    "cisa_kev",
    "mitre_attack",
    "netscaler_advisory",
    "red_hat_rhsa",
    "synthetic_control",
    "named_scoring_authority",
    "vendor_advisory",
]


class SourceDefinition(BaseModel):
    """One documented source and its temporal/release posture."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_name: SourceName
    source_class: Literal["government", "standards_body", "vendor", "synthetic"]
    canonical_url: HttpUrl | Annotated[str, StringConstraints(pattern=r"^urn:")]
    temporal_truth_mode: Literal[
        "observed_snapshot",
        "upstream_versioned",
        "reconstructed_history",
        "synthetic_control",
    ]
    available_by_basis: Literal[
        "observed_retrieval",
        "upstream_version",
        "signed_release",
        "publisher_timestamp_with_observation",
        "publisher_declared_version",
        "synthetic_fixture",
    ]
    redistribution_default: Literal[
        "metadata_hash_and_fetch_recipe",
        "pinned_raw_and_derived_with_cc0_notice",
        "preserve_required_license_designation",
        "attribution_link_and_modification_notice",
        "project_generated",
    ]

    @model_validator(mode="after")
    def validate_temporal_basis(self) -> Self:
        expected = {
            "nvd": (
                "government",
                "observed_snapshot",
                "observed_retrieval",
                "metadata_hash_and_fetch_recipe",
            ),
            "cisa_kev": (
                "government",
                "upstream_versioned",
                "upstream_version",
                "pinned_raw_and_derived_with_cc0_notice",
            ),
            "mitre_attack": (
                "standards_body",
                "upstream_versioned",
                "upstream_version",
                "preserve_required_license_designation",
            ),
            "red_hat_rhsa": (
                "vendor",
                "upstream_versioned",
                "publisher_timestamp_with_observation",
                "attribution_link_and_modification_notice",
            ),
            "synthetic_control": (
                "synthetic",
                "synthetic_control",
                "synthetic_fixture",
                "project_generated",
            ),
            "vendor_advisory": (
                "vendor",
                "upstream_versioned",
                "publisher_declared_version",
                "metadata_hash_and_fetch_recipe",
            ),
        }
        actual = (
            self.source_class,
            self.temporal_truth_mode,
            self.available_by_basis,
            self.redistribution_default,
        )
        if actual != expected[self.source_name]:
            raise ValueError(
                "source class, truth mode, and availability basis do not match "
                "the frozen source policy"
            )
        expected_urls = {
            "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "cisa_kev": "https://github.com/cisagov/kev-data",
            "mitre_attack": "https://github.com/mitre-attack/attack-stix-data",
            "red_hat_rhsa": (
                "https://security.access.redhat.com/data/csaf/v2/advisories/"
            ),
            "synthetic_control": "urn:cti-provenance:synthetic-control",
            "vendor_advisory": "https://archive.apache.org/dist/httpd/",
        }
        if str(self.canonical_url) != expected_urls[self.source_name]:
            raise ValueError("canonical_url does not match the frozen source")
        return self


class SourcesConfig(BaseModel):
    """Versioned source catalog."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["sources-v1"]
    sources: list[SourceDefinition] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_source_names(self) -> Self:
        names = [source.source_name for source in self.sources]
        if len(names) != len(set(names)):
            raise ValueError("source_name values must be unique")
        expected = {
            "nvd",
            "cisa_kev",
            "mitre_attack",
            "red_hat_rhsa",
            "synthetic_control",
        }
        if set(names) != expected:
            raise ValueError("sources-v1 must contain every frozen source exactly once")
        return self


class PortfolioSourcesConfig(BaseModel):
    """Versioned source catalog for the bounded portfolio proof batch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["sources-portfolio-proof-v1"]
    sources: list[SourceDefinition] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_exact_sources(self) -> Self:
        names = [source.source_name for source in self.sources]
        expected = {"vendor_advisory", "cisa_kev", "mitre_attack"}
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValueError(
                "sources-portfolio-proof-v1 must contain its three sources exactly once"
            )
        return self


class YieldSourceDefinition(BaseModel):
    """One exact source posture used by the portfolio yield-gate batch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_id: Literal[
        "cisa_kev_catalog",
        "django_project",
        "nodejs_project",
        "nvd_change_history",
    ]
    source_name: Literal["cisa_kev", "vendor_advisory", "nvd"]
    canonical_url: HttpUrl
    available_by_basis: Literal["upstream_version", "publisher_declared_version"]
    redistribution_default: Literal[
        "metadata_hash_and_fetch_recipe",
        "pinned_raw_and_derived_with_cc0_notice",
        "preserve_required_license_designation",
    ]

    @model_validator(mode="after")
    def validate_exact_posture(self) -> Self:
        expected = {
            "cisa_kev_catalog": (
                "cisa_kev",
                "https://github.com/cisagov/kev-data",
                "upstream_version",
                "pinned_raw_and_derived_with_cc0_notice",
            ),
            "nodejs_project": (
                "vendor_advisory",
                "https://github.com/nodejs/nodejs.org",
                "publisher_declared_version",
                "preserve_required_license_designation",
            ),
            "django_project": (
                "vendor_advisory",
                "https://github.com/django/django",
                "publisher_declared_version",
                "preserve_required_license_designation",
            ),
            "nvd_change_history": (
                "nvd",
                "https://nvd.nist.gov/vuln/detail/",
                "publisher_declared_version",
                "metadata_hash_and_fetch_recipe",
            ),
        }
        actual = (
            self.source_name,
            str(self.canonical_url),
            self.available_by_basis,
            self.redistribution_default,
        )
        if actual != expected[self.source_id]:
            raise ValueError("yield source posture does not match the frozen policy")
        return self


class YieldSourcesConfig(BaseModel):
    """Closed source catalog for the portfolio yield-gate batch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["sources-portfolio-yield-v1"]
    sources: list[YieldSourceDefinition] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_exact_sources(self) -> Self:
        ids = [source.source_id for source in self.sources]
        expected = {
            "cisa_kev_catalog",
            "django_project",
            "nodejs_project",
            "nvd_change_history",
        }
        if len(ids) != len(set(ids)) or set(ids) != expected:
            raise ValueError(
                "sources-portfolio-yield-v1 must contain its four sources exactly once"
            )
        return self


class ScaleSourceDefinition(BaseModel):
    """One exact source posture used by the first portfolio scale batch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_id: Literal[
        "cisa_kev_catalog",
        "django_project",
        "jenkins_project",
        "nodejs_project",
        "nvd_change_history",
        "python_project",
        "rust_project",
    ]
    source_name: Literal["cisa_kev", "vendor_advisory", "nvd"]
    canonical_url: HttpUrl
    claim_bearing_url: HttpUrl
    available_by_basis: Literal["upstream_version", "publisher_declared_version"]
    redistribution_default: Literal[
        "metadata_hash_and_fetch_recipe",
        "pinned_raw_and_derived_with_cc0_notice",
        "preserve_required_license_designation",
    ]

    @model_validator(mode="after")
    def validate_exact_posture(self) -> Self:
        expected = {
            "cisa_kev_catalog": (
                "cisa_kev",
                "https://github.com/cisagov/kev-data",
                "https://github.com/cisagov/kev-data",
                "upstream_version",
                "pinned_raw_and_derived_with_cc0_notice",
            ),
            "nodejs_project": (
                "vendor_advisory",
                "https://github.com/nodejs/nodejs.org",
                "https://github.com/nodejs/nodejs.org",
                "publisher_declared_version",
                "preserve_required_license_designation",
            ),
            "django_project": (
                "vendor_advisory",
                "https://github.com/django/django",
                "https://github.com/django/django",
                "publisher_declared_version",
                "preserve_required_license_designation",
            ),
            "rust_project": (
                "vendor_advisory",
                "https://github.com/rust-lang/rust",
                "https://github.com/rust-lang/blog.rust-lang.org",
                "publisher_declared_version",
                "preserve_required_license_designation",
            ),
            "python_project": (
                "vendor_advisory",
                "https://github.com/python/cpython",
                "https://github.com/python/cpython",
                "publisher_declared_version",
                "preserve_required_license_designation",
            ),
            "jenkins_project": (
                "vendor_advisory",
                "https://github.com/jenkinsci/jenkins",
                "https://github.com/jenkins-infra/jenkins.io",
                "publisher_declared_version",
                "preserve_required_license_designation",
            ),
            "nvd_change_history": (
                "nvd",
                "https://nvd.nist.gov/vuln/detail/",
                "https://nvd.nist.gov/vuln/detail/",
                "publisher_declared_version",
                "metadata_hash_and_fetch_recipe",
            ),
        }
        actual = (
            self.source_name,
            str(self.canonical_url),
            str(self.claim_bearing_url),
            self.available_by_basis,
            self.redistribution_default,
        )
        if actual != expected[self.source_id]:
            raise ValueError("scale source posture does not match the frozen policy")
        return self


class ScaleSourcesConfig(BaseModel):
    """Closed source catalog for the first portfolio scale batch."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["sources-portfolio-scale-v1"]
    sources: list[ScaleSourceDefinition] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_exact_sources(self) -> Self:
        ids = [source.source_id for source in self.sources]
        expected = {
            "cisa_kev_catalog",
            "django_project",
            "jenkins_project",
            "nodejs_project",
            "nvd_change_history",
            "python_project",
            "rust_project",
        }
        if len(ids) != len(set(ids)) or set(ids) != expected:
            raise ValueError(
                "sources-portfolio-scale-v1 must contain its seven sources exactly once"
            )
        return self


class MinimumSourceDefinition(BaseModel):
    """Closed source posture for the minimum-completion validation case."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_id: Literal["postgresql_project"]
    source_name: Literal["vendor_advisory"]
    canonical_url: HttpUrl
    claim_bearing_url: HttpUrl
    available_by_basis: Literal["publisher_declared_version"]
    redistribution_default: Literal["preserve_required_license_designation"]

    @model_validator(mode="after")
    def validate_exact_posture(self) -> Self:
        actual = (
            str(self.canonical_url),
            str(self.claim_bearing_url),
        )
        expected = (
            "https://github.com/postgres/postgres",
            "https://github.com/postgres/postgres",
        )
        if actual != expected:
            raise ValueError("minimum source posture does not match the frozen policy")
        return self


class MinimumSourcesConfig(BaseModel):
    """Closed source catalog for the minimum-completion validation case."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["sources-portfolio-minimum-v1"]
    sources: list[MinimumSourceDefinition] = Field(min_length=1, max_length=1)

    @model_validator(mode="after")
    def validate_exact_sources(self) -> Self:
        if [source.source_id for source in self.sources] != ["postgresql_project"]:
            raise ValueError(
                "minimum source catalog must contain PostgreSQL exactly once"
            )
        return self


class AuthorityPolicy(BaseModel):
    """Predicate-specific source authority rule."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    policy_id: NonEmptyString
    predicates: list[PredicateName] = Field(min_length=1)
    primary_sources: list[SourceReference] = Field(min_length=1)
    acceptable_corroboration: list[SourceReference]
    conflict_action: Literal[
        "preserve_named_source_values",
        "reject_wrong_authority_and_never_blend",
        "cisa_governs_and_conflicts_remain_visible",
        "abstain_on_ambiguous_product_mapping",
        "score_only_the_pinned_release",
        "score_only_the_named_publisher_version",
        "publisher_directive_governs",
        "vendor_advisory_governs",
        "cisa_status_governs",
    ]

    @model_validator(mode="after")
    def validate_policy_members(self) -> Self:
        if len(self.predicates) != len(set(self.predicates)):
            raise ValueError("predicates must be unique within a policy")
        if len(self.primary_sources) != len(set(self.primary_sources)):
            raise ValueError("primary_sources must be unique")
        if len(self.acceptable_corroboration) != len(
            set(self.acceptable_corroboration)
        ):
            raise ValueError("acceptable_corroboration must be unique")
        if set(self.primary_sources) & set(self.acceptable_corroboration):
            raise ValueError(
                "primary_sources and acceptable_corroboration must be disjoint"
            )
        frozen_rules = {
            "cve.published_at": (
                {"nvd"},
                {"cve_program"},
                "preserve_named_source_values",
            ),
            "cve.modified_at": (
                {"nvd"},
                {"cve_program"},
                "preserve_named_source_values",
            ),
            "cve.cvss.score": (
                {"named_scoring_authority"},
                set(),
                "reject_wrong_authority_and_never_blend",
            ),
            "kev.is_member": (
                {"cisa_kev"},
                set(),
                "cisa_governs_and_conflicts_remain_visible",
            ),
            "kev.date_added": (
                {"cisa_kev"},
                set(),
                "cisa_governs_and_conflicts_remain_visible",
            ),
            "kev.due_date": (
                {"cisa_kev"},
                set(),
                "cisa_governs_and_conflicts_remain_visible",
            ),
            "vendor.affected_versions": (
                {"red_hat_rhsa"},
                {"nvd", "cisa_kev"},
                "abstain_on_ambiguous_product_mapping",
            ),
            "vendor.fixed_versions": (
                {"red_hat_rhsa"},
                {"nvd", "cisa_kev"},
                "abstain_on_ambiguous_product_mapping",
            ),
            "attack.relationship_present": (
                {"mitre_attack"},
                set(),
                "score_only_the_pinned_release",
            ),
            "cve.affected_versions": (
                {"cve_program"},
                set(),
                "score_only_the_named_publisher_version",
            ),
            "directive.required_action": (
                {"cisa_directive"},
                set(),
                "publisher_directive_governs",
            ),
            "vendor.recommended_action": (
                {"netscaler_advisory"},
                set(),
                "vendor_advisory_governs",
            ),
            "vendor.release_affected_versions": (
                {"vendor_advisory"},
                set(),
                "vendor_advisory_governs",
            ),
            "kev.ransomware_campaign_use": (
                {"cisa_kev"},
                set(),
                "cisa_status_governs",
            ),
            "attack.platforms": (
                {"mitre_attack"},
                set(),
                "score_only_the_pinned_release",
            ),
            "vendor.security_release_versions": (
                {"vendor_advisory"},
                set(),
                "vendor_advisory_governs",
            ),
            "vendor.cve_fixed_release": (
                {"vendor_advisory"},
                set(),
                "vendor_advisory_governs",
            ),
            "nvd.cpe_applicability": (
                {"nvd"},
                set(),
                "preserve_named_source_values",
            ),
        }
        for predicate in self.predicates:
            rule = frozen_rules.get(predicate)
            if rule is None:
                raise ValueError(
                    f"predicate {predicate!r} has no frozen authority rule"
                )
            expected_primary, expected_corroboration, expected_action = rule
            if (
                set(self.primary_sources) != expected_primary
                or set(self.acceptable_corroboration) != expected_corroboration
                or self.conflict_action != expected_action
            ):
                raise ValueError(
                    f"policy fields do not match the frozen rule for {predicate}"
                )
        return self


class AuthorityPolicyConfig(BaseModel):
    """Versioned predicate-authority catalog."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[
        "authority-policy-v1",
        "authority-policy-three-family-v1",
        "authority-policy-portfolio-proof-v1",
        "authority-policy-portfolio-yield-v1",
        "authority-policy-portfolio-scale-v1",
        "authority-policy-portfolio-minimum-v1",
    ]
    policies: list[AuthorityPolicy] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_policies_and_predicates(self) -> Self:
        policy_ids = [policy.policy_id for policy in self.policies]
        if len(policy_ids) != len(set(policy_ids)):
            raise ValueError("policy_id values must be unique")
        predicates = [
            predicate for policy in self.policies for predicate in policy.predicates
        ]
        if len(predicates) != len(set(predicates)):
            raise ValueError("each predicate may appear in only one policy")
        expected_by_version = {
            "authority-policy-v1": {
                "cve.published_at",
                "cve.modified_at",
                "cve.cvss.score",
                "kev.is_member",
                "kev.date_added",
                "kev.due_date",
                "vendor.affected_versions",
                "vendor.fixed_versions",
                "attack.relationship_present",
            },
            "authority-policy-three-family-v1": {
                "cve.affected_versions",
                "directive.required_action",
                "vendor.recommended_action",
            },
            "authority-policy-portfolio-proof-v1": {
                "vendor.release_affected_versions",
                "kev.ransomware_campaign_use",
                "attack.platforms",
            },
            "authority-policy-portfolio-yield-v1": {
                "kev.is_member",
                "vendor.security_release_versions",
                "vendor.cve_fixed_release",
                "nvd.cpe_applicability",
            },
            "authority-policy-portfolio-scale-v1": {
                "kev.is_member",
                "vendor.security_release_versions",
                "vendor.cve_fixed_release",
                "nvd.cpe_applicability",
            },
            "authority-policy-portfolio-minimum-v1": {
                "vendor.cve_fixed_release",
            },
        }
        expected = expected_by_version[self.version]
        if set(predicates) != expected:
            raise ValueError(
                f"{self.version} must cover every frozen predicate exactly once"
            )
        expected_groups_by_version = {
            "authority-policy-v1": {
                "nvd-publication-time": {"cve.published_at", "cve.modified_at"},
                "named-cvss-authority": {"cve.cvss.score"},
                "cisa-kev-status": {
                    "kev.is_member",
                    "kev.date_added",
                    "kev.due_date",
                },
                "red-hat-product-state": {
                    "vendor.affected_versions",
                    "vendor.fixed_versions",
                },
                "mitre-attack-relationship": {"attack.relationship_present"},
            },
            "authority-policy-three-family-v1": {
                "cve-program-affected-versions": {"cve.affected_versions"},
                "cisa-directive-required-action": {"directive.required_action"},
                "vendor-recommended-action": {"vendor.recommended_action"},
            },
            "authority-policy-portfolio-proof-v1": {
                "apache-release-affected-versions": {
                    "vendor.release_affected_versions"
                },
                "cisa-kev-ransomware-use": {"kev.ransomware_campaign_use"},
                "mitre-attack-platforms": {"attack.platforms"},
            },
            "authority-policy-portfolio-yield-v1": {
                "cisa-kev-membership-yield": {"kev.is_member"},
                "node-security-release-versions": {"vendor.security_release_versions"},
                "django-cve-fixed-release": {"vendor.cve_fixed_release"},
                "nvd-cpe-applicability": {"nvd.cpe_applicability"},
            },
            "authority-policy-portfolio-scale-v1": {
                "cisa-kev-membership-yield": {"kev.is_member"},
                "vendor-security-release-versions": {
                    "vendor.security_release_versions"
                },
                "vendor-cve-fixed-release": {"vendor.cve_fixed_release"},
                "nvd-cpe-applicability": {"nvd.cpe_applicability"},
            },
            "authority-policy-portfolio-minimum-v1": {
                "postgresql-cve-fixed-release": {"vendor.cve_fixed_release"},
            },
        }
        expected_groups = expected_groups_by_version[self.version]
        actual_groups = {
            policy.policy_id: set(policy.predicates) for policy in self.policies
        }
        if actual_groups != expected_groups:
            raise ValueError(
                f"{self.version} requires exact frozen policy IDs and groupings"
            )
        return self


def _load_yaml(path: Path) -> object:
    """Safely parse one explicit YAML file without environment interpolation."""

    try:
        with path.open("r", encoding="utf-8") as stream:
            return yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        raise ValueError("invalid YAML configuration") from exc


def load_sources_config(path: Path) -> SourcesConfig:
    """Load and validate a source catalog from an explicit path."""

    return SourcesConfig.model_validate(_load_yaml(path))


def load_portfolio_sources_config(path: Path) -> PortfolioSourcesConfig:
    """Load and validate the bounded portfolio proof source catalog."""

    return PortfolioSourcesConfig.model_validate(_load_yaml(path))


def load_yield_sources_config(path: Path) -> YieldSourcesConfig:
    """Load the closed portfolio yield-gate source catalog."""

    return YieldSourcesConfig.model_validate(_load_yaml(path))


def load_scale_sources_config(path: Path) -> ScaleSourcesConfig:
    """Load the closed source catalog for the first scale batch."""

    return ScaleSourcesConfig.model_validate(_load_yaml(path))


def load_minimum_sources_config(path: Path) -> MinimumSourcesConfig:
    """Load the closed source catalog for the minimum-completion case."""

    return MinimumSourcesConfig.model_validate(_load_yaml(path))


def load_authority_policy_config(path: Path) -> AuthorityPolicyConfig:
    """Load and validate an authority-policy catalog from an explicit path."""

    return AuthorityPolicyConfig.model_validate(_load_yaml(path))


def load_project_config_files(
    sources_path: Path, authority_policy_path: Path
) -> tuple[SourcesConfig, AuthorityPolicyConfig]:
    """Load both catalogs and enforce their source-reference relationship."""

    sources = load_sources_config(sources_path)
    authority = load_authority_policy_config(authority_policy_path)
    configured_sources = {source.source_name for source in sources.sources}
    external_authorities = {"cve_program", "named_scoring_authority"}
    for policy in authority.policies:
        references = set(policy.primary_sources) | set(policy.acceptable_corroboration)
        missing = references - configured_sources - external_authorities
        if missing:
            raise ValueError(
                f"authority policy {policy.policy_id!r} references "
                "an unconfigured source"
            )
    return sources, authority


def load_portfolio_project_config_files(
    sources_path: Path, authority_policy_path: Path
) -> tuple[PortfolioSourcesConfig, AuthorityPolicyConfig]:
    """Load and cross-validate the bounded portfolio proof catalogs."""

    sources = load_portfolio_sources_config(sources_path)
    authority = load_authority_policy_config(authority_policy_path)
    if authority.version != "authority-policy-portfolio-proof-v1":
        raise ValueError(
            "portfolio sources require the portfolio proof authority policy"
        )
    configured_sources = {source.source_name for source in sources.sources}
    for policy in authority.policies:
        references = set(policy.primary_sources) | set(policy.acceptable_corroboration)
        if references - configured_sources:
            raise ValueError(
                f"authority policy {policy.policy_id!r} references "
                "an unconfigured portfolio source"
            )
    return sources, authority


def load_yield_project_config_files(
    sources_path: Path, authority_policy_path: Path
) -> tuple[YieldSourcesConfig, AuthorityPolicyConfig]:
    """Load and cross-validate the portfolio yield-gate catalogs."""

    sources = load_yield_sources_config(sources_path)
    authority = load_authority_policy_config(authority_policy_path)
    if authority.version != "authority-policy-portfolio-yield-v1":
        raise ValueError("yield sources require the yield authority policy")
    configured_sources = {source.source_name for source in sources.sources}
    for policy in authority.policies:
        references = set(policy.primary_sources) | set(policy.acceptable_corroboration)
        if references - configured_sources:
            raise ValueError(
                f"authority policy {policy.policy_id!r} references "
                "an unconfigured yield source"
            )
    return sources, authority


def load_scale_project_config_files(
    sources_path: Path, authority_policy_path: Path
) -> tuple[ScaleSourcesConfig, AuthorityPolicyConfig]:
    """Load and cross-validate the first portfolio scale catalogs."""

    sources = load_scale_sources_config(sources_path)
    authority = load_authority_policy_config(authority_policy_path)
    if authority.version != "authority-policy-portfolio-scale-v1":
        raise ValueError("scale sources require the scale authority policy")
    configured_sources = {source.source_name for source in sources.sources}
    for policy in authority.policies:
        references = set(policy.primary_sources) | set(policy.acceptable_corroboration)
        if references - configured_sources:
            raise ValueError(
                f"authority policy {policy.policy_id!r} references "
                "an unconfigured scale source"
            )
    return sources, authority


def load_minimum_project_config_files(
    sources_path: Path, authority_policy_path: Path
) -> tuple[MinimumSourcesConfig, AuthorityPolicyConfig]:
    """Load and cross-validate the minimum-completion catalogs."""

    sources = load_minimum_sources_config(sources_path)
    authority = load_authority_policy_config(authority_policy_path)
    if authority.version != "authority-policy-portfolio-minimum-v1":
        raise ValueError("minimum sources require the minimum authority policy")
    configured_sources = {source.source_name for source in sources.sources}
    for policy in authority.policies:
        references = set(policy.primary_sources) | set(policy.acceptable_corroboration)
        if references - configured_sources:
            raise ValueError(
                f"authority policy {policy.policy_id!r} references "
                "an unconfigured minimum source"
            )
    return sources, authority


class AppConfig(BaseModel):
    """Documented configuration surface.

    Environment loading copies only explicitly documented variable names.
    Secret values remain ``SecretStr`` instances and are never included in
    either safe serialization path.
    """

    # Environment variables are strings by definition; numeric conversion is
    # intentional here. Provider/data contracts above remain strict.
    model_config = ConfigDict(extra="forbid", frozen=True)

    nvd_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    gemini_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    cost_cap_usd: Decimal = Field(default=Decimal("5"), gt=0)
    provider: Literal["openai", "anthropic", "google"] | None = None
    model: str | None = None

    ENV_TO_FIELD: ClassVar[dict[str, str]] = {
        "NVD_API_KEY": "nvd_api_key",
        "OPENAI_API_KEY": "openai_api_key",
        "ANTHROPIC_API_KEY": "anthropic_api_key",
        "GEMINI_API_KEY": "gemini_api_key",
        "GITHUB_TOKEN": "github_token",
        "CTI_EVAL_COST_CAP_USD": "cost_cap_usd",
        "CTI_EVAL_PROVIDER": "provider",
        "CTI_EVAL_MODEL": "model",
    }
    SECRET_ENV_NAMES: ClassVar[tuple[str, ...]] = (
        "NVD_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GITHUB_TOKEN",
    )
    SAFE_ENV_NAMES: ClassVar[tuple[str, ...]] = (
        "CTI_EVAL_COST_CAP_USD",
        "CTI_EVAL_PROVIDER",
        "CTI_EVAL_MODEL",
    )

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> AppConfig:
        """Load only allowlisted names from an environment mapping."""

        source = os.environ if environ is None else environ
        values = {
            field_name: source[env_name]
            for env_name, field_name in cls.ENV_TO_FIELD.items()
            if source.get(env_name) not in {None, ""}
        }
        return cls.model_validate(values)

    def require_model_run(self) -> Self:
        """Validate provider/model/key selection immediately before a model run."""

        if self.provider is None:
            raise ValueError("CTI_EVAL_PROVIDER is required for a model run")
        if not self.model:
            raise ValueError("CTI_EVAL_MODEL is required for a model run")
        provider_key_fields = {
            "openai": "openai_api_key",
            "anthropic": "anthropic_api_key",
            "google": "gemini_api_key",
        }
        present = {
            provider
            for provider, field_name in provider_key_fields.items()
            if getattr(self, field_name) is not None
        }
        if present != {self.provider}:
            raise ValueError("a model run requires exactly the selected provider's key")
        return self

    def safe_environment(self) -> dict[str, str]:
        """Serialize only non-secret, documented configuration variables."""

        result: dict[str, str] = {}
        if self.provider is not None:
            result["CTI_EVAL_PROVIDER"] = self.provider
        if self.model is not None:
            result["CTI_EVAL_MODEL"] = self.model
        result["CTI_EVAL_COST_CAP_USD"] = str(self.cost_cap_usd)
        return result

    def redacted_environment(self) -> dict[str, str]:
        """Return an allowlisted diagnostic view with secret values redacted."""

        result = self.safe_environment()
        for env_name in self.SECRET_ENV_NAMES:
            field_name = self.ENV_TO_FIELD[env_name]
            if getattr(self, field_name) is not None:
                result[env_name] = "[REDACTED]"
        return result


def load_config(*, require_model_run: bool = False) -> AppConfig:
    """Load process configuration, optionally enforcing model-run requirements."""

    config = AppConfig.from_environment()
    return config.require_model_run() if require_model_run else config


def redact_known_secrets(text: str, config: AppConfig) -> str:
    """Redact configured secret values before text reaches logs or diagnostics."""

    redacted = text
    for field_name in (
        "nvd_api_key",
        "openai_api_key",
        "anthropic_api_key",
        "gemini_api_key",
        "github_token",
    ):
        secret = getattr(config, field_name)
        if secret is None:
            continue
        value = secret.get_secret_value()
        if value:
            redacted = redacted.replace(value, "[REDACTED]")
    return redacted
