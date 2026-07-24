"""Frozen predicate-specific authority decisions."""

from __future__ import annotations

from typing import Literal

from cti_provenance.claims.schema import AtomicClaim, PredicateName
from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.normalize.common import NormalizedDocument

AuthorityDecision = Literal["accepted", "weak", "wrong", "unresolved"]

AUTHORITY_POLICY_VERSION = "authority-policy-v1"
THREE_FAMILY_AUTHORITY_POLICY_VERSION = "authority-policy-three-family-v1"
PORTFOLIO_PROOF_AUTHORITY_POLICY_VERSION = "authority-policy-portfolio-proof-v1"
PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION = "authority-policy-portfolio-yield-v1"
PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION = "authority-policy-portfolio-scale-v1"
PORTFOLIO_MINIMUM_AUTHORITY_POLICY_VERSION = "authority-policy-portfolio-minimum-v1"
PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION = "authority-policy-portfolio-diverse-v6"

_PREDICATES_BY_POLICY_VERSION: dict[str, frozenset[PredicateName]] = {
    AUTHORITY_POLICY_VERSION: frozenset(
        {
            "cve.published_at",
            "cve.modified_at",
            "cve.cvss.score",
            "kev.is_member",
            "kev.date_added",
            "kev.due_date",
            "vendor.affected_versions",
            "vendor.fixed_versions",
            "attack.relationship_present",
        }
    ),
    THREE_FAMILY_AUTHORITY_POLICY_VERSION: frozenset(
        {
            "cve.affected_versions",
            "directive.required_action",
            "vendor.recommended_action",
        }
    ),
    PORTFOLIO_PROOF_AUTHORITY_POLICY_VERSION: frozenset(
        {
            "vendor.release_affected_versions",
            "kev.ransomware_campaign_use",
            "attack.platforms",
        }
    ),
    PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION: frozenset(
        {
            "kev.is_member",
            "vendor.security_release_versions",
            "vendor.cve_fixed_release",
            "nvd.cpe_applicability",
        }
    ),
    PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION: frozenset(
        {
            "kev.is_member",
            "vendor.security_release_versions",
            "vendor.cve_fixed_release",
            "nvd.cpe_applicability",
        }
    ),
    PORTFOLIO_MINIMUM_AUTHORITY_POLICY_VERSION: frozenset({"vendor.cve_fixed_release"}),
    PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION: frozenset(
        {
            "attack.platforms",
            "cve.affected_versions",
            "directive.required_action",
            "kev.is_member",
            "kev.ransomware_campaign_use",
            "nvd.cpe_applicability",
            "source.temporal_change",
            "source.authority_divergence",
            "source.multi_source_synthesis",
            "vendor.cve_fixed_release",
            "vendor.fixed_versions",
            "vendor.recommended_action",
            "vendor.release_affected_versions",
            "vendor.security_release_versions",
        }
    ),
}

_PRIMARY_SOURCE: dict[PredicateName, str] = {
    "cve.affected_versions": "cve_program",
    "directive.required_action": "cisa_directive",
    "cve.published_at": "nvd",
    "cve.modified_at": "nvd",
    "cve.cvss.score": "nvd",
    "kev.is_member": "cisa_kev",
    "kev.date_added": "cisa_kev",
    "kev.due_date": "cisa_kev",
    "vendor.affected_versions": "red_hat_rhsa",
    "vendor.fixed_versions": "red_hat_rhsa",
    "vendor.recommended_action": "netscaler_advisory",
    "attack.relationship_present": "mitre_attack",
    "vendor.release_affected_versions": "vendor_advisory",
    "kev.ransomware_campaign_use": "cisa_kev",
    "attack.platforms": "mitre_attack",
    "vendor.security_release_versions": "vendor_advisory",
    "vendor.cve_fixed_release": "vendor_advisory",
    "nvd.cpe_applicability": "nvd",
}

_REQUIRED_QUALIFIER: dict[PredicateName, str] = {
    "cve.affected_versions": "cve_program",
    "directive.required_action": "cisa",
    "cve.published_at": "nvd",
    "cve.modified_at": "nvd",
    "cve.cvss.score": "nvd@nist.gov",
    "kev.is_member": "cisa_kev",
    "kev.date_added": "cisa_kev",
    "kev.due_date": "cisa_kev",
    "vendor.affected_versions": "red_hat_rhsa",
    "vendor.fixed_versions": "red_hat_rhsa",
    "vendor.recommended_action": "netscaler",
    "attack.relationship_present": "mitre_attack",
    "vendor.release_affected_versions": "apache_httpd",
    "kev.ransomware_campaign_use": "cisa_kev",
    "attack.platforms": "mitre_attack",
    "vendor.security_release_versions": "nodejs_project",
    "vendor.cve_fixed_release": "django_project",
    "nvd.cpe_applicability": "nvd",
}

_ALLOWED_PUBLISHER_AUTHORITIES: dict[tuple[str, PredicateName], frozenset[str]] = {
    (
        PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
        "vendor.security_release_versions",
    ): frozenset({"nodejs_project"}),
    (
        PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
        "vendor.cve_fixed_release",
    ): frozenset({"django_project"}),
    (
        PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION,
        "vendor.security_release_versions",
    ): frozenset({"jenkins_project", "nodejs_project"}),
    (
        PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION,
        "vendor.cve_fixed_release",
    ): frozenset({"django_project", "python_project", "rust_project"}),
    (
        PORTFOLIO_MINIMUM_AUTHORITY_POLICY_VERSION,
        "vendor.cve_fixed_release",
    ): frozenset({"postgresql_project"}),
}

_WEAK_SOURCES: dict[PredicateName, frozenset[str]] = {
    "vendor.affected_versions": frozenset({"nvd", "cisa_kev"}),
    "vendor.fixed_versions": frozenset({"nvd", "cisa_kev"}),
}

_SYNTHETIC_REPRESENTATIONS = frozenset({"nvd", "cisa_kev", "red_hat_rhsa"})


def validate_authority_policy_predicate(
    authority_policy_version: str, predicate: PredicateName
) -> None:
    """Require the named immutable policy catalog to cover the predicate."""

    if predicate not in _PREDICATES_BY_POLICY_VERSION.get(
        authority_policy_version, frozenset()
    ):
        raise ValueError(
            f"authority policy {authority_policy_version!r} does not cover "
            f"predicate {predicate!r}"
        )


def represented_source_name(case: BenchmarkCase, document: NormalizedDocument) -> str:
    """Return the authority identity without laundering real-source content."""

    if document.source_name != "synthetic_control":
        return document.source_name
    if case.temporal_truth_mode != "synthetic_control":
        return "synthetic_control"
    represented = document.fields.get("represented_source_name")
    if isinstance(represented, str) and represented in _SYNTHETIC_REPRESENTATIONS:
        return represented
    return "synthetic_control"


def assess_authority(
    case: BenchmarkCase,
    claim: AtomicClaim,
    document: NormalizedDocument,
    *,
    authority_policy_version: str = AUTHORITY_POLICY_VERSION,
) -> AuthorityDecision:
    """Assess one cited document under the frozen predicate policy."""

    validate_authority_policy_predicate(authority_policy_version, claim.predicate)

    source = represented_source_name(case, document)
    required_source = _PRIMARY_SOURCE[claim.predicate]
    required_qualifier = _REQUIRED_QUALIFIER[claim.predicate]
    if claim.predicate in {
        "vendor.cve_fixed_release",
        "vendor.security_release_versions",
    }:
        declared_authority = document.fields.get("publisher_authority")
        if not isinstance(declared_authority, str) or not declared_authority:
            return "unresolved"
        allowed_publishers = _ALLOWED_PUBLISHER_AUTHORITIES.get(
            (authority_policy_version, claim.predicate), frozenset()
        )
        if declared_authority not in allowed_publishers:
            return "wrong"
        required_qualifier = declared_authority
    qualifier = claim.qualifiers.authority

    if qualifier is None:
        return "unresolved"
    if source == required_source and qualifier == required_qualifier:
        return "accepted"
    if source in _WEAK_SOURCES.get(claim.predicate, frozenset()):
        return "weak"
    return "wrong"
