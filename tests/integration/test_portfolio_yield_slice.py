from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from cti_provenance.claims.portfolio_yield import (
    LINEAGE_PATH,
    load_portfolio_yield_cases,
    load_portfolio_yield_corpus,
)
from cti_provenance.dataset.audit import (
    DatasetDocumentIdentity,
    audit_dataset_integrity,
)
from cti_provenance.experiments.portfolio_yield_runner import (
    render_portfolio_yield_jsonl,
    render_portfolio_yield_report,
    run_portfolio_yield_slice,
)
from cti_provenance.grading.authority import (
    PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
    assess_authority,
)
from cti_provenance.normalize import (
    load_portfolio_lineage_config,
    validate_portfolio_dependency_splits,
)
from cti_provenance.snapshot import select_admissible_by_entity

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw" / "portfolio-pilot-v1"
REQUIRED = [
    RAW / "cisa-kev-2026-07-16.json",
    RAW / "cisa-kev-2026-07-21.json",
    RAW / "nodejs-may-2025-prerelease.md",
    RAW / "nodejs-may-2025-released.md",
    RAW / "nvd-cve-2024-3400-event-2024-04-23.html",
    RAW / "nvd-cve-2024-3400-event-2024-05-29.html",
    RAW / "django-release-5.0.2.txt",
    RAW / "django-release-5.0.3.txt",
]


def _require_raw() -> None:
    if not all(path.is_file() for path in REQUIRED):
        pytest.skip("gitignored portfolio yield raw bytes are unavailable")


def test_portfolio_yield_replay_matches_tracked_results() -> None:
    _require_raw()
    results = run_portfolio_yield_slice(ROOT)
    assert len(results) == 4
    assert all(not result.answer.abstained for result in results)
    assert all(
        grade.claim_support == "supported"
        for result in results
        for grade in result.grades
    )
    assert render_portfolio_yield_jsonl(results) == (
        ROOT / "reports" / "portfolio-yield-slice.jsonl"
    ).read_text(encoding="utf-8")
    assert render_portfolio_yield_report(results) == (
        ROOT / "reports" / "portfolio-yield-slice.md"
    ).read_text(encoding="utf-8")


def test_yield_families_select_before_between_and_after_cutoffs() -> None:
    _require_raw()
    states, _, specs = load_portfolio_yield_corpus(ROOT)
    for spec in specs:
        family_states = [
            state
            for state in states
            if state.manifest.snapshot_id in spec.source_state_ids
        ]
        family_states.sort(key=lambda state: state.manifest.available_by_utc)
        first, second = family_states
        key = (
            first.manifest.source_name,
            first.manifest.upstream_identifier,
        )
        before = first.manifest.available_by_utc - timedelta(microseconds=1)
        between = (
            first.manifest.available_by_utc
            + (second.manifest.available_by_utc - first.manifest.available_by_utc) / 2
        )
        after = second.manifest.available_by_utc + timedelta(microseconds=1)
        assert select_admissible_by_entity(family_states, before) == {}
        assert select_admissible_by_entity(family_states, between)[key] == (
            first.manifest
        )
        assert select_admissible_by_entity(family_states, after)[key] == (
            second.manifest
        )


def test_yield_authority_and_dataset_integrity() -> None:
    _require_raw()
    states, documents, specs = load_portfolio_yield_corpus(ROOT)
    cases = load_portfolio_yield_cases(
        ROOT, states=states, documents=documents, specs=specs
    )
    specs_by_template = {spec.template_family_id: spec for spec in specs}
    docs_by_snapshot = {document.snapshot_id: document for document in documents}
    manifests = {state.manifest.snapshot_id: state.manifest for state in states}
    for case in cases:
        spec = specs_by_template[case.template_family_id]
        document = docs_by_snapshot[spec.source_state_ids[-1]]
        claim = case.expected_claims[0]
        assert (
            assess_authority(
                case,
                claim,
                document,
                authority_policy_version=PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
            )
            == "accepted"
        )
        wrong_source = (
            "cisa_kev" if document.source_name != "cisa_kev" else "mitre_attack"
        )
        assert (
            assess_authority(
                case,
                claim,
                document.model_copy(update={"source_name": wrong_source}),
                authority_policy_version=PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
            )
            == "wrong"
        )
        wrong_claim = claim.model_copy(
            update={
                "qualifiers": claim.qualifiers.model_copy(
                    update={"authority": "wrong_publisher"}
                )
            }
        )
        assert (
            assess_authority(
                case,
                wrong_claim,
                document,
                authority_policy_version=PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
            )
            == "wrong"
        )

    identities = [
        DatasetDocumentIdentity(
            document_id=document.document_id,
            snapshot_id=document.snapshot_id,
            upstream_entity_id=document.upstream_entity_id,
            canonical_url=str(manifests[document.snapshot_id].source_url),
            normalized_text_sha256=hashlib.sha256(
                document.normalized_text.encode("utf-8")
            ).hexdigest(),
            available_by_utc=manifests[document.snapshot_id].available_by_utc,
            availability_evidence="publisher_version",
            source_name=document.source_name,
        )
        for document in documents
    ]
    audit = audit_dataset_integrity(cases, documents=identities)
    assert audit.passed
    assert audit.findings == ()
    assert audit.split_case_counts == {"dev": 1, "validation": 3, "holdout": 0}


def test_yield_authority_does_not_inherit_later_scale_publishers() -> None:
    _require_raw()
    states, documents, specs = load_portfolio_yield_corpus(ROOT)
    cases = load_portfolio_yield_cases(
        ROOT, states=states, documents=documents, specs=specs
    )
    case = next(
        item for item in cases if item.entity_family_id == "django-cve-2024-27351"
    )
    document = next(
        item for item in documents if item.snapshot_id == case.allowed_snapshot_ids[0]
    )
    claim = case.expected_claims[0]
    forged_document = document.model_copy(
        update={
            "fields": {
                **document.fields,
                "publisher_authority": "rust_project",
            }
        }
    )
    forged_claim = claim.model_copy(
        update={
            "qualifiers": claim.qualifiers.model_copy(
                update={"authority": "rust_project"}
            )
        }
    )
    assert (
        assess_authority(
            case,
            forged_claim,
            forged_document,
            authority_policy_version=PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
        )
        == "wrong"
    )


def test_shared_dependency_lineage_cannot_cross_proof_and_yield_splits() -> None:
    lineage = load_portfolio_lineage_config(ROOT / LINEAGE_PATH)
    assert len(lineage.families) == 24
    assert "log4shell-plumbing-only" not in {
        family.family_id for family in lineage.families
    }
    validate_portfolio_dependency_splits(lineage.families)

    cisa_yield = next(
        family
        for family in lineage.families
        if family.family_id == "cisa-kev-cve-2021-27137"
    )
    conflicting = cisa_yield.model_copy(update={"prospective_split": "validation"})
    with pytest.raises(ValueError, match="cannot cross prospective splits"):
        validate_portfolio_dependency_splits(
            [
                family
                for family in lineage.families
                if family.family_id != conflicting.family_id
            ]
            + [conflicting]
        )
