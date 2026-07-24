"""Explicit abstention-template handling."""

from __future__ import annotations

from cti_provenance.claims.schema import PredicateName

_TEMPLATE_PREDICATES: dict[str, PredicateName] = {
    "cve-program-affected-versions": "cve.affected_versions",
    "cisa-directive-required-action": "directive.required_action",
    "nvd-published-at": "cve.published_at",
    "nvd-modified-at": "cve.modified_at",
    "nvd-cvss-score": "cve.cvss.score",
    "kev-membership": "kev.is_member",
    "kev-date-added": "kev.date_added",
    "kev-due-date": "kev.due_date",
    "red-hat-affected-versions": "vendor.affected_versions",
    "red-hat-fixed-versions": "vendor.fixed_versions",
    "netscaler-investigation-recommendation": "vendor.recommended_action",
    "attack-relationship-present": "attack.relationship_present",
    "apache-release-affected-versions": "vendor.release_affected_versions",
    "cisa-kev-ransomware-use": "kev.ransomware_campaign_use",
    "mitre-attack-platforms": "attack.platforms",
    "cisa-kev-membership-yield": "kev.is_member",
    "node-security-release-versions": "vendor.security_release_versions",
    "django-cve-fixed-release": "vendor.cve_fixed_release",
    "nvd-cpe-applicability": "nvd.cpe_applicability",
}


def infer_abstention_predicate(template_family_id: str) -> PredicateName:
    """Resolve only frozen template identities; never guess from question text."""

    try:
        return _TEMPLATE_PREDICATES[template_family_id]
    except KeyError as exc:
        raise ValueError(
            "cannot infer abstention predicate from unknown template_family_id "
            f"{template_family_id!r}"
        ) from exc
