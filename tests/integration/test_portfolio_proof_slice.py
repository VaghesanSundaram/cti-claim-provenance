from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from cti_provenance.claims.portfolio_proof import (
    PortfolioProofError,
    load_portfolio_proof_cases,
    load_portfolio_proof_corpus,
)
from cti_provenance.dataset.audit import (
    DatasetDocumentIdentity,
    audit_dataset_integrity,
)
from cti_provenance.experiments.portfolio_proof_runner import (
    build_portfolio_proof_answer,
    render_portfolio_proof_jsonl,
    render_portfolio_proof_report,
    run_portfolio_proof_slice,
)
from cti_provenance.grading.authority import (
    PORTFOLIO_PROOF_AUTHORITY_POLICY_VERSION,
    assess_authority,
)
from cti_provenance.snapshot import select_admissible_by_entity

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw" / "portfolio-pilot-v1"
REQUIRED = [
    RAW / "apache-archive-CHANGES_2.4.50.txt",
    RAW / "apache-archive-CHANGES_2.4.51.txt",
    RAW / "cisa-kev-2026-07-16.json",
    RAW / "cisa-kev-2026-07-21.json",
    RAW / "enterprise-attack-15.1.json",
    RAW / "enterprise-attack-16.0.json",
]


def _require_raw() -> None:
    if not all(path.is_file() for path in REQUIRED):
        pytest.skip("gitignored portfolio proof raw bytes are unavailable")


def test_portfolio_proof_replay_matches_tracked_results() -> None:
    _require_raw()
    results = run_portfolio_proof_slice(ROOT)
    assert len(results) == 3
    assert all(not result.answer.abstained for result in results)
    assert all(
        grade.claim_support == "supported"
        for result in results
        for grade in result.grades
    )
    assert render_portfolio_proof_jsonl(results) == (
        ROOT / "reports" / "portfolio-proof-slice.jsonl"
    ).read_text(encoding="utf-8")
    assert render_portfolio_proof_report(results) == (
        ROOT / "reports" / "portfolio-proof-slice.md"
    ).read_text(encoding="utf-8")


def test_each_proof_family_abstains_before_its_first_version() -> None:
    _require_raw()
    states, documents, specs = load_portfolio_proof_corpus(ROOT)
    cases = load_portfolio_proof_cases(
        ROOT, states=states, documents=documents, specs=specs
    )
    spec_by_template = {spec.template_family_id: spec for spec in specs}
    first_by_family = {
        spec.family_id: next(
            state
            for state in states
            if state.manifest.snapshot_id == spec.source_state_ids[0]
        )
        for spec in specs
    }
    for case in cases:
        pre_case = case.model_copy(
            update={
                "as_of": (
                    first_by_family[case.entity_family_id].manifest.available_by_utc
                    - timedelta(microseconds=1)
                )
            }
        )
        answer = build_portfolio_proof_answer(
            pre_case,
            run_id=f"pre-{case.case_id}",
            hits=(),
            documents=documents,
            spec=spec_by_template[case.template_family_id],
        )
        assert answer.abstained
        assert answer.claims == []


def test_each_proof_family_selects_before_between_and_after_cutoffs() -> None:
    _require_raw()
    states, _, specs = load_portfolio_proof_corpus(ROOT)
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


def test_missing_portfolio_raw_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PortfolioProofError, match="manifest/spec is invalid"):
        load_portfolio_proof_corpus(tmp_path)


def test_portfolio_authority_accepts_primary_and_rejects_wrong_source() -> None:
    _require_raw()
    states, documents, specs = load_portfolio_proof_corpus(ROOT)
    cases = load_portfolio_proof_cases(
        ROOT, states=states, documents=documents, specs=specs
    )
    documents_by_snapshot = {document.snapshot_id: document for document in documents}
    specs_by_template = {spec.template_family_id: spec for spec in specs}

    for case in cases:
        spec = specs_by_template[case.template_family_id]
        document = documents_by_snapshot[spec.source_state_ids[-1]]
        claim = case.expected_claims[0]
        assert (
            assess_authority(
                case,
                claim,
                document,
                authority_policy_version=PORTFOLIO_PROOF_AUTHORITY_POLICY_VERSION,
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
                authority_policy_version=PORTFOLIO_PROOF_AUTHORITY_POLICY_VERSION,
            )
            == "wrong"
        )


def test_portfolio_proof_cases_pass_dataset_integrity_audit() -> None:
    _require_raw()
    states, documents, specs = load_portfolio_proof_corpus(ROOT)
    cases = load_portfolio_proof_cases(
        ROOT, states=states, documents=documents, specs=specs
    )
    manifests = {state.manifest.snapshot_id: state.manifest for state in states}
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
    assert audit.split_case_counts == {"dev": 3, "validation": 0, "holdout": 0}
