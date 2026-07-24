from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Literal

import pytest

from cti_provenance.claims.schema import (
    ClaimObject,
    ClaimQualifiers,
    ClaimSubject,
    GoldAtomicClaim,
)
from cti_provenance.dataset.audit import (
    _SOURCE_BY_PREDICATE,
    DatasetDocumentIdentity,
    DatasetReadinessError,
    _has_observed_real_change,
    _phase7_selection_counts,
    _source_bundle_sha256,
    audit_dataset_integrity,
    build_candidate_manifest,
    build_pilot_readiness_report,
)
from cti_provenance.dataset.cases import AttackTreatment, BenchmarkCase
from cti_provenance.experiments.pilot_plan import (
    PilotExecutionPlan,
    PilotPricing,
    build_pilot_schedule,
)
from cti_provenance.grading.human_audit import (
    ArtifactBinding,
    CalibrationManifest,
)
from cti_provenance.snapshot.manifest import SnapshotManifest

NOW = datetime(2026, 7, 19, 20, 0, tzinfo=UTC)


def _artifact_binding(root: Path, path: str, body: bytes) -> ArtifactBinding:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    return ArtifactBinding(
        path=path,
        sha256=hashlib.sha256(body).hexdigest(),
        byte_length=len(body),
    )


def _claim(
    name: str,
    *,
    subject_id: str,
    evidence_document_id: str,
) -> GoldAtomicClaim:
    return GoldAtomicClaim(
        claim_id=f"gold-{name}",
        subject=ClaimSubject(type="cve", id=subject_id),
        predicate="kev.is_member",
        object=ClaimObject(value=True, datatype="boolean"),
        qualifiers=ClaimQualifiers(
            authority="cisa_kev",
            cvss_version=None,
            product=None,
            ecosystem=None,
        ),
        evidence_ids=[f"{evidence_document_id}:membership"],
        confidence=1.0,
    )


def _case(
    name: str,
    *,
    split: str,
    entity: str | None = None,
    family: str | None = None,
    template: str | None = None,
    subject_id: str | None = None,
    evidence_document_id: str | None = None,
    question: str | None = None,
    paired_case_id: str | None = None,
    attack_family: str = "none",
    treatment_document_ids: list[str] | None = None,
    allowed_snapshot_ids: list[str] | None = None,
    as_of: datetime = NOW,
) -> BenchmarkCase:
    document_id = evidence_document_id or f"doc-{name}"
    treatment_ids = treatment_document_ids or []
    return BenchmarkCase.model_validate(
        {
            "case_id": name,
            "case_family_id": family or f"family-{name}",
            "entity_family_id": entity or f"entity-{name}",
            "template_family_id": template or f"template-{name}",
            "split": split,
            "as_of": as_of,
            "temporal_truth_mode": "upstream_versioned",
            "question": question
            or (f"Does the frozen defensive catalog record mark {name} as a member?"),
            "allowed_snapshot_ids": allowed_snapshot_ids or [f"snapshot-{document_id}"],
            "expected_claims": [
                _claim(
                    name,
                    subject_id=subject_id or f"SYNTHETIC-CVE-{name.upper()}",
                    evidence_document_id=document_id,
                )
            ],
            "required_authority_policy_ids": ["cisa-kev-status"],
            "should_abstain": False,
            "abstention_reason": None,
            "paired_case_id": paired_case_id,
            "attack": AttackTreatment(
                family=attack_family,
                treatment_document_ids=treatment_ids,
                generation_version=(
                    "synthetic-audit-attack-v1" if attack_family != "none" else None
                ),
            ),
        }
    )


def _document(
    document_id: str,
    *,
    snapshot_id: str | None = None,
    entity: str | None = None,
    canonical_url: str | None = None,
    text_hash: str | None = None,
    available_by: datetime = NOW,
    availability_evidence: Literal[
        "observed_retrieval",
        "upstream_version",
        "signed_release",
        "publisher_version",
        "synthetic_fixture",
    ] = "upstream_version",
    source_name: Literal[
        "nvd",
        "cisa_kev",
        "mitre_attack",
        "red_hat_rhsa",
        "synthetic_control",
    ] = "cisa_kev",
) -> DatasetDocumentIdentity:
    return DatasetDocumentIdentity(
        document_id=document_id,
        snapshot_id=snapshot_id or f"snapshot-{document_id}",
        upstream_entity_id=entity or f"upstream-{document_id}",
        canonical_url=canonical_url or f"urn:cti-provenance:audit:{document_id}",
        normalized_text_sha256=(
            text_hash or hashlib.sha256(document_id.encode()).hexdigest()
        ),
        available_by_utc=available_by,
        availability_evidence=availability_evidence,
        source_name=source_name,
    )


def _snapshot_manifest_json(
    snapshot_id: str,
    *,
    source_name: Literal["cisa_kev", "synthetic_control"] = "synthetic_control",
) -> str:
    if source_name == "cisa_kev":
        source_class = "government"
        source_url = (
            "https://raw.githubusercontent.com/cisagov/kev-data/"
            + "a" * 40
            + "/known_exploited_vulnerabilities.json"
        )
        available_by_basis = "upstream_version"
        upstream_version = "a" * 40
    else:
        source_class = "synthetic"
        source_url = f"urn:cti-provenance:audit:{snapshot_id}"
        available_by_basis = "synthetic_fixture"
        upstream_version = "1"
    return SnapshotManifest.model_validate(
        {
            "snapshot_id": snapshot_id,
            "source_name": source_name,
            "source_class": source_class,
            "source_url": source_url,
            "retrieved_at_utc": NOW,
            "http_status": 200,
            "http_etag": None,
            "http_last_modified": None,
            "effective_date_if_known": None,
            "effective_date_basis": "unknown",
            "available_by_utc": NOW,
            "available_by_basis": available_by_basis,
            "upstream_identifier": f"audit:{snapshot_id}",
            "upstream_version": upstream_version,
            "media_type": "application/json",
            "byte_length": 1,
            "sha256": "a" * 64,
            "raw_blob_path": f"data/fixtures/{snapshot_id}.json",
            "fetcher_version": "audit-fixture-v1",
            "normalization_version": "audit-fixture-v1",
            "license_or_terms_note": "project-authored audit fixture",
        }
    ).model_dump_json()


def _finding_codes(
    cases: list[BenchmarkCase],
    documents: list[DatasetDocumentIdentity],
) -> set[str]:
    return {
        finding.code
        for finding in audit_dataset_integrity(cases, documents=documents).findings
    }


def test_phase7_base_case_limit_counts_100_vs_101() -> None:
    cases = {
        f"clean-{index}": _case(f"clean-{index}", split="dev") for index in range(101)
    }
    assert _phase7_selection_counts(cases, set(list(cases)[:100])) == (0, 100)
    assert _phase7_selection_counts(cases, set(cases)) == (0, 101)


def test_isolated_dev_validation_cases_pass_integrity_audit() -> None:
    cases = [
        _case("dev-clean", split="dev"),
        _case("validation-clean", split="validation"),
    ]
    documents = [_document("doc-dev-clean"), _document("doc-validation-clean")]

    audit = audit_dataset_integrity(cases, documents=documents)

    assert audit.passed
    assert audit.findings == ()
    assert audit.split_case_counts == {"dev": 1, "validation": 1, "holdout": 0}


@pytest.mark.parametrize(
    ("field", "expected_code"),
    [
        ("entity", "entity_family_cross_split"),
        ("family", "case_family_cross_split"),
        ("template", "template_family_cross_split"),
        ("subject", "claim_subject_cross_split"),
        ("evidence", "evidence_document_cross_split"),
        ("question", "exact_question_cross_split"),
    ],
)
def test_cross_split_identity_leakage_is_rejected(
    field: str,
    expected_code: str,
) -> None:
    dev = _case("dev", split="dev")
    changes: dict[str, object] = {}
    if field == "entity":
        changes["entity"] = dev.entity_family_id
    elif field == "family":
        changes["family"] = dev.case_family_id
    elif field == "template":
        changes["template"] = dev.template_family_id
    elif field == "subject":
        changes["subject_id"] = dev.expected_claims[0].subject.id
    elif field == "evidence":
        changes["evidence_document_id"] = "doc-dev"
    else:
        changes["question"] = dev.question
    validation = _case("validation", split="validation", **changes)
    document_ids = {
        evidence_id.split(":", 1)[0]
        for case in (dev, validation)
        for claim in case.expected_claims
        for evidence_id in claim.evidence_ids
    }
    documents = [_document(document_id) for document_id in sorted(document_ids)]

    assert expected_code in _finding_codes([dev, validation], documents)


def test_near_duplicate_question_cross_split_is_rejected() -> None:
    dev = _case(
        "dev",
        split="dev",
        question=(
            "Does the frozen defensive catalog entry identify the synthetic "
            "record as a known exploited vulnerability member?"
        ),
    )
    validation = _case(
        "validation",
        split="validation",
        question=(
            "Does the frozen defensive catalog entry identify this synthetic "
            "record as a known exploited vulnerability member?"
        ),
    )

    codes = _finding_codes(
        [dev, validation],
        [_document("doc-dev"), _document("doc-validation")],
    )

    assert "near_duplicate_question_cross_split" in codes


def test_exact_allowed_snapshot_cannot_cross_splits_with_distinct_documents() -> None:
    dev = _case(
        "dev",
        split="dev",
        allowed_snapshot_ids=["shared-snapshot"],
    )
    validation = _case(
        "validation",
        split="validation",
        allowed_snapshot_ids=["shared-snapshot"],
    )
    documents = [
        _document("doc-dev", snapshot_id="shared-snapshot"),
        _document("doc-validation", snapshot_id="shared-snapshot"),
    ]

    codes = _finding_codes([dev, validation], documents)

    assert "allowed_snapshot_cross_split" in codes


def test_document_lineage_url_and_hash_leakage_are_rejected() -> None:
    dev = _case("dev", split="dev")
    validation = _case("validation", split="validation")
    common_hash = hashlib.sha256(b"same normalized bytes").hexdigest()
    documents = [
        _document(
            "doc-dev",
            entity="shared-upstream",
            canonical_url="urn:cti-provenance:audit:shared",
            text_hash=common_hash,
        ),
        _document(
            "doc-validation",
            entity="shared-upstream",
            canonical_url="urn:cti-provenance:audit:shared",
            text_hash=common_hash,
        ),
    ]

    codes = _finding_codes([dev, validation], documents)

    assert {
        "document_entity_cross_split",
        "canonical_url_cross_split",
        "normalized_content_cross_split",
    } <= codes


def test_evidence_must_resolve_to_allowed_cutoff_eligible_required_source() -> None:
    case = _case(
        "dev",
        split="dev",
        allowed_snapshot_ids=["snapshot-allowed"],
    )
    document = _document(
        "doc-dev",
        snapshot_id="snapshot-other",
        available_by=NOW.replace(hour=21),
        source_name="nvd",
    )

    codes = _finding_codes([case], [document])

    assert {
        "evidence_snapshot_not_allowed",
        "evidence_source_mismatch",
        "evidence_document_post_cutoff",
    } <= codes


def test_observed_change_requires_ordered_same_lineage_distinct_content() -> None:
    old_case = _case(
        "old",
        split="dev",
        family="changed-old",
        entity="changed-entity",
        template="changed-template",
        subject_id="SYNTHETIC-CVE-CHANGED",
        evidence_document_id="old-document",
        allowed_snapshot_ids=["old-snapshot"],
        as_of=NOW,
    )
    new_case = _case(
        "new",
        split="dev",
        family="changed-new",
        entity="changed-entity",
        template="changed-template",
        subject_id="SYNTHETIC-CVE-CHANGED",
        evidence_document_id="new-document",
        allowed_snapshot_ids=["new-snapshot"],
        as_of=NOW + timedelta(hours=2),
    )
    old_document = _document(
        "old-document",
        snapshot_id="old-snapshot",
        entity="same-upstream-lineage",
        text_hash="a" * 64,
        available_by=NOW - timedelta(hours=1),
    )
    new_document = _document(
        "new-document",
        snapshot_id="new-snapshot",
        entity="same-upstream-lineage",
        text_hash="b" * 64,
        available_by=NOW + timedelta(hours=1),
    )

    assert _has_observed_real_change(
        [old_case, new_case],
        [old_document, new_document],
    )
    assert not _has_observed_real_change(
        [old_case, new_case],
        [
            old_document,
            new_document.model_copy(
                update={"availability_evidence": "publisher_version"}
            ),
        ],
    )
    assert not _has_observed_real_change(
        [old_case, new_case],
        [
            old_document,
            new_document.model_copy(
                update={"normalized_text_sha256": old_document.normalized_text_sha256}
            ),
        ],
    )


def test_reciprocal_pair_requires_exact_declared_treatment_delta() -> None:
    clean = _case(
        "clean",
        split="dev",
        family="paired-family",
        entity="paired-entity",
        template="paired-template",
        subject_id="SYNTHETIC-CVE-PAIR",
        evidence_document_id="authoritative",
        question="What membership is supported for the paired synthetic record?",
        paired_case_id="attacked",
        allowed_snapshot_ids=["snapshot-authoritative"],
    )
    attacked_payload = clean.model_dump(mode="python")
    attacked_payload.update(
        case_id="attacked",
        paired_case_id="clean",
        allowed_snapshot_ids=[
            "snapshot-authoritative",
            "snapshot-treatment",
        ],
        attack={
            "family": "contradiction",
            "treatment_document_ids": ["treatment"],
            "generation_version": "synthetic-audit-attack-v1",
        },
    )
    attacked_payload["expected_claims"][0]["claim_id"] = "gold-attacked"
    attacked = BenchmarkCase.model_validate(attacked_payload)
    documents = [
        _document("authoritative"),
        _document("treatment", snapshot_id="snapshot-treatment"),
    ]

    assert audit_dataset_integrity([clean, attacked], documents=documents).passed

    invalid_payload = attacked.model_dump(mode="python")
    invalid_payload["allowed_snapshot_ids"] = ["snapshot-authoritative"]
    invalid = BenchmarkCase.model_validate(invalid_payload)
    codes = _finding_codes([clean, invalid], documents)
    assert "pair_treatment_delta_invalid" in codes


def test_reciprocal_pair_reports_unverifiable_delta_when_metadata_is_missing() -> None:
    clean = _case(
        "clean",
        split="dev",
        family="paired-family",
        entity="paired-entity",
        template="paired-template",
        subject_id="SYNTHETIC-CVE-PAIR",
        evidence_document_id="authoritative",
        paired_case_id="attacked",
        allowed_snapshot_ids=["snapshot-authoritative"],
    )
    attacked_payload = clean.model_dump(mode="python")
    attacked_payload.update(
        case_id="attacked",
        paired_case_id="clean",
        allowed_snapshot_ids=["snapshot-authoritative", "snapshot-treatment"],
        attack={
            "family": "contradiction",
            "treatment_document_ids": ["treatment"],
            "generation_version": "synthetic-audit-attack-v1",
        },
    )
    attacked_payload["expected_claims"][0]["claim_id"] = "gold-attacked"
    attacked = BenchmarkCase.model_validate(attacked_payload)

    codes = _finding_codes(
        [clean, attacked],
        [_document("authoritative")],
    )

    assert "pair_treatment_metadata_missing" in codes
    assert "pair_treatment_delta_invalid" not in codes


@pytest.mark.legacy
def test_candidate_manifest_hash_is_deterministic_and_binds_exact_files(
    tmp_path: Path,
) -> None:
    cases = [_case("dev", split="dev")]
    case_path = tmp_path / "data/benchmark/dev/cases.jsonl"
    source_path = tmp_path / "data/manifests/snapshots.jsonl"
    treatment_path = tmp_path / "data/manifests/treatments.jsonl"
    identity_path = tmp_path / "data/identities/documents.jsonl"
    authority_path = tmp_path / "configs/authority-policy.yaml"
    case_path.parent.mkdir(parents=True)
    source_path.parent.mkdir(parents=True)
    identity_path.parent.mkdir(parents=True)
    authority_path.parent.mkdir(parents=True)
    case_path.write_text(
        "".join(
            json.dumps(
                case.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for case in cases
        ),
        encoding="utf-8",
    )
    source_path.write_text(
        _snapshot_manifest_json(
            "snapshot-doc-dev",
            source_name="cisa_kev",
        )
        + "\n",
        encoding="utf-8",
    )
    treatment_path.write_text(
        _snapshot_manifest_json("snapshot-treatment") + "\n",
        encoding="utf-8",
    )
    expected_documents = [_document("doc-dev")]
    identity_path.write_text(
        expected_documents[0].model_dump_json() + "\n",
        encoding="utf-8",
    )
    authority_path.write_text("version: one\n", encoding="utf-8")

    first, loaded, documents = build_candidate_manifest(
        tmp_path,
        dataset_version="audit-fixture-v1",
        case_paths=(Path("data/benchmark/dev/cases.jsonl"),),
        source_manifest_paths=(
            Path("data/manifests/snapshots.jsonl"),
            Path("data/manifests/treatments.jsonl"),
        ),
        authority_policy_path=Path("configs/authority-policy.yaml"),
        document_identity_paths=(Path("data/identities/documents.jsonl"),),
    )
    second, loaded_again, documents_again = build_candidate_manifest(
        tmp_path,
        dataset_version="audit-fixture-v1",
        case_paths=(Path("data/benchmark/dev/cases.jsonl"),),
        source_manifest_paths=(
            Path("data/manifests/snapshots.jsonl"),
            Path("data/manifests/treatments.jsonl"),
        ),
        authority_policy_path=Path("configs/authority-policy.yaml"),
        document_identity_paths=(Path("data/identities/documents.jsonl"),),
    )

    assert loaded == loaded_again == cases
    assert documents == documents_again == expected_documents
    assert first == second
    assert first.sha256() == second.sha256()
    assert [binding.path for binding in first.source_manifests] == [
        "data/manifests/snapshots.jsonl",
        "data/manifests/treatments.jsonl",
    ]

    case_path.write_text(
        case_path.read_text(encoding="utf-8").replace(
            "Does the frozen defensive catalog",
            "Does this immutable defensive catalog",
        ),
        encoding="utf-8",
    )
    changed, _, _ = build_candidate_manifest(
        tmp_path,
        dataset_version="audit-fixture-v1",
        case_paths=(Path("data/benchmark/dev/cases.jsonl"),),
        source_manifest_paths=(
            Path("data/manifests/snapshots.jsonl"),
            Path("data/manifests/treatments.jsonl"),
        ),
        authority_policy_path=Path("configs/authority-policy.yaml"),
        document_identity_paths=(Path("data/identities/documents.jsonl"),),
    )
    assert changed.sha256() != first.sha256()

    selected_case_ids = tuple(str(case.case_id) for case in loaded)
    calculated_cap = Decimal(len(selected_case_ids) * 200) / Decimal(1_000_000)
    execution_plan = PilotExecutionPlan(
        plan_version="pilot-execution-plan-v1",
        candidate_manifest_sha256=first.sha256(),
        provider="synthetic-test-provider",
        model="synthetic-test-model",
        api="offline-test-api",
        service_tier="offline",
        reasoning_effort="none",
        prompt_version="synthetic-test-prompt-v1",
        provider_schema_version="synthetic-test-schema-v1",
        parser_version="synthetic-test-parser-v1",
        grader_version="synthetic-test-grader-v1",
        authority_policy_version="synthetic-test-authority-v1",
        normalization_versions=("synthetic-test-normalization-v1",),
        retrieval_version="synthetic-test-retrieval-v1",
        case_form_ids=selected_case_ids,
        conditions=("synthetic-test-condition",),
        repetitions=1,
        schedule_seed=1,
        maximum_transient_retries=0,
        input_token_reservation_per_attempt=100,
        output_token_reservation_per_attempt=100,
        retry_inclusive_cost_cap_usd=calculated_cap,
        pricing=PilotPricing(
            pricing_version="synthetic-test-pricing-v1",
            evidence_url="urn:synthetic:test:pricing",
            evidence_accessed_at_utc=datetime(2026, 7, 19, tzinfo=UTC),
            input_per_million_usd=Decimal(1),
            output_per_million_usd=Decimal(1),
        ),
    )
    execution_report = build_pilot_readiness_report(
        manifest=first,
        cases=loaded,
        documents=documents,
        project_root=tmp_path,
        execution_plan=execution_plan,
        execution_schedule=build_pilot_schedule(execution_plan),
    )
    execution_codes = {finding.code for finding in execution_report.findings}
    assert "pilot_schedule_budget_unfrozen" not in execution_codes
    assert "pilot_schedule_phase7_design_noncompliant" in execution_codes
    assert "pilot_pricing_currentness_unverified" in execution_codes
    assert execution_report.execution is not None
    assert execution_report.execution.planned_calls == len(selected_case_ids)

    grade_schema_body = b'{"synthetic_test_only":true}\n'
    _artifact_binding(
        tmp_path,
        "schemas/claim-grade.schema.json",
        grade_schema_body,
    )
    protocol_body = json.dumps(
        {
            "protocol_version": "human-calibration-v1",
            "judgments_per_item": 2,
            "reviewers_blind_to_conditions": True,
            "adjudicator_blind_to_conditions": True,
            "agreement_method": "cohen_kappa_v1",
            "label_set": [
                "supported",
                "partial",
                "unsupported",
                "not_applicable",
            ],
        },
        separators=(",", ":"),
    ).encode()
    calibration_claims = [
        (case, claim)
        for case in loaded
        for claim in case.expected_claims
        if claim.evidence_ids
    ]
    assert calibration_claims
    calibration_items = []
    calibration_contexts = []
    calibration_grades = []
    for index in range(50):
        case, claim = calibration_claims[index % len(calibration_claims)]
        source_name = _SOURCE_BY_PREDICATE[claim.predicate]
        evidence_text = f"Synthetic integration evidence {index}."
        context = {
            "item_id": f"synthetic-item-{index}",
            "case_id": str(case.case_id),
            "evidence_id": claim.evidence_ids[0],
            "predicate": str(claim.predicate),
            "source_name": source_name,
            "question": case.question,
            "evidence_text": evidence_text,
            "evidence_text_sha256": hashlib.sha256(evidence_text.encode()).hexdigest(),
        }
        calibration_contexts.append(context)
        context_body = json.dumps(
            context,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        calibration_items.append(
            {
                "item_id": context["item_id"],
                "case_id": str(case.case_id),
                "claim_grade_id": f"synthetic-grade-{index}",
                "evidence_id": context["evidence_id"],
                "predicate": str(claim.predicate),
                "split": case.split,
                "source_name": source_name,
                "context_sha256": hashlib.sha256(context_body).hexdigest(),
            }
        )
        calibration_grades.append(
            {
                "claim_grade_id": f"synthetic-grade-{index}",
                "run_id": "synthetic-test-run",
                "case_id": str(case.case_id),
                "generated_claim_id": f"synthetic-generated-{index}",
                "expected_claim_id": claim.claim_id,
                "predicate": str(claim.predicate),
                "value_match": "exact",
                "evidence_assessments": [
                    {
                        "evidence_id": claim.evidence_ids[0],
                        "resolution": "resolved",
                        "entailment": "supported",
                        "temporality": "admissible",
                        "authority": "accepted",
                        "span_hash_match": True,
                    }
                ],
                "contradiction": "none",
                "claim_support": "supported",
                "abstention_outcome": "not_applicable",
                "generated_confidence": 1.0,
                "deterministic_grader_version": "synthetic-grader-v1",
                "authority_policy_version": "synthetic-authority-v1",
                "normalization_version": "synthetic-normalization-v1",
                "human_judgment_id": None,
                "notes_code": None,
            }
        )
    item_universe_body = "\n".join(
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in sorted(calibration_items, key=lambda item: item["item_id"])
    ).encode()
    item_file_body = b"\n".join(
        json.dumps(item, separators=(",", ":")).encode() for item in calibration_items
    )
    grade_records_body = b"\n".join(
        json.dumps(grade, separators=(",", ":")).encode()
        for grade in calibration_grades
    )
    reviewer_contexts_body = b"\n".join(
        json.dumps(context, separators=(",", ":")).encode()
        for context in calibration_contexts
    )
    judgments: list[bytes] = []
    adjudications: list[bytes] = []
    for index in range(50):
        first_label = "supported" if index % 2 else "partial"
        second_label = "unsupported" if index % 5 == 0 else first_label
        for reviewer_id, label in (
            ("synthetic-reviewer-a", first_label),
            ("synthetic-reviewer-b", second_label),
        ):
            judgments.append(
                json.dumps(
                    {
                        "judgment_id": f"synthetic-j-{index}-{reviewer_id}",
                        "item_id": f"synthetic-item-{index}",
                        "reviewer_id": reviewer_id,
                        "judged_at_utc": "2026-07-19T00:00:00Z",
                        "label": label,
                    },
                    separators=(",", ":"),
                ).encode()
            )
        if first_label != second_label:
            adjudications.append(
                json.dumps(
                    {
                        "adjudication_id": f"synthetic-a-{index}",
                        "item_id": f"synthetic-item-{index}",
                        "judgment_ids": [
                            f"synthetic-j-{index}-synthetic-reviewer-a",
                            f"synthetic-j-{index}-synthetic-reviewer-b",
                        ],
                        "adjudicator_id": "synthetic-adjudicator",
                        "adjudicated_at_utc": "2026-07-19T01:00:00Z",
                        "final_label": first_label,
                        "rationale_code": "evidence_support_resolution",
                    },
                    separators=(",", ":"),
                ).encode()
            )
    calibration_manifest = CalibrationManifest(
        manifest_version="human-calibration-manifest-v1",
        protocol_spec=_artifact_binding(
            tmp_path,
            "annotations/test/protocol.json",
            protocol_body,
        ),
        protocol_document=_artifact_binding(
            tmp_path,
            "annotations/test/protocol.md",
            b"# Synthetic integration fixture\n",
        ),
        grade_records=_artifact_binding(
            tmp_path,
            "annotations/test/grades.jsonl",
            grade_records_body,
        ),
        reviewer_contexts=_artifact_binding(
            tmp_path,
            "annotations/test/contexts.jsonl",
            reviewer_contexts_body,
        ),
        items=_artifact_binding(
            tmp_path,
            "annotations/test/items.jsonl",
            item_file_body,
        ),
        judgments=_artifact_binding(
            tmp_path,
            "annotations/test/judgments.jsonl",
            b"\n".join(judgments),
        ),
        adjudications=_artifact_binding(
            tmp_path,
            "annotations/test/adjudications.jsonl",
            b"\n".join(adjudications),
        ),
        candidate_manifest_sha256=first.sha256(),
        source_bundle_sha256=_source_bundle_sha256(first),
        grade_schema_sha256=hashlib.sha256(grade_schema_body).hexdigest(),
        deterministic_grader_version="synthetic-grader-v1",
        authority_policy_version="synthetic-authority-v1",
        normalization_versions=("synthetic-normalization-v1",),
        item_universe_sha256=hashlib.sha256(item_universe_body).hexdigest(),
    )
    calibration_report = build_pilot_readiness_report(
        manifest=first,
        cases=loaded,
        documents=documents,
        project_root=tmp_path,
        calibration_manifest=calibration_manifest,
    )
    calibration_codes = {finding.code for finding in calibration_report.findings}
    assert "annotation_protocol_missing" not in calibration_codes
    assert "double_annotation_minimum_unmet" not in calibration_codes
    assert "agreement_statistic_missing" not in calibration_codes
    assert "adjudication_incomplete" not in calibration_codes
    assert "calibration_evidence_span_provenance_unbound" in calibration_codes
    assert "calibration_acceptance_threshold_undeclared" in calibration_codes
    assert calibration_report.calibration.status == "structurally_unbound"
    with pytest.raises(DatasetReadinessError, match="calibrated grade versions"):
        build_pilot_readiness_report(
            manifest=first,
            cases=loaded,
            documents=documents,
            project_root=tmp_path,
            calibration_manifest=calibration_manifest,
            execution_plan=execution_plan,
            execution_schedule=build_pilot_schedule(execution_plan),
        )
    matching_plan = execution_plan.model_copy(
        update={
            "grader_version": "synthetic-grader-v1",
            "authority_policy_version": "synthetic-authority-v1",
            "normalization_versions": ("synthetic-normalization-v1",),
        }
    )
    combined_report = build_pilot_readiness_report(
        manifest=first,
        cases=loaded,
        documents=documents,
        project_root=tmp_path,
        calibration_manifest=calibration_manifest,
        execution_plan=matching_plan,
        execution_schedule=build_pilot_schedule(matching_plan),
    )
    assert combined_report.calibration.status == "structurally_unbound"

    mismatched_case = loaded[0].model_copy(
        update={"question": "A manifest-mismatched question?"}
    )
    mismatch_report = build_pilot_readiness_report(
        manifest=first,
        cases=[mismatched_case],
        documents=documents,
        project_root=tmp_path,
    )
    mismatch_codes = {finding.code for finding in mismatch_report.findings}
    assert "candidate_case_binding_mismatch" in mismatch_codes
    assert "document_snapshot_source_mismatch" not in mismatch_codes
    assert "document_snapshot_availability_mismatch" not in mismatch_codes
    assert mismatch_report.status == "not_ready"
    assert "positive_readiness_gate_unimplemented" in mismatch_codes

    unbound_case = loaded[0].model_copy(
        update={"allowed_snapshot_ids": ["snapshot-not-in-manifest"]}
    )
    unbound_report = build_pilot_readiness_report(
        manifest=first,
        cases=[unbound_case],
        documents=documents,
        project_root=tmp_path,
    )
    assert "allowed_snapshot_unbound" in {
        finding.code for finding in unbound_report.findings
    }

    identity_mismatch_report = build_pilot_readiness_report(
        manifest=first,
        cases=loaded,
        documents=[],
        project_root=tmp_path,
    )
    assert "document_identity_binding_mismatch" in {
        finding.code for finding in identity_mismatch_report.findings
    }

    forged_document = documents[0].model_copy(
        update={
            "available_by_utc": NOW - timedelta(days=1),
            "availability_evidence": "observed_retrieval",
        }
    )
    forged_availability_report = build_pilot_readiness_report(
        manifest=first,
        cases=loaded,
        documents=[forged_document],
        project_root=tmp_path,
    )
    forged_codes = {finding.code for finding in forged_availability_report.findings}
    assert "document_identity_binding_mismatch" in forged_codes
    assert "document_snapshot_availability_mismatch" in forged_codes


@pytest.mark.legacy
def test_pilot_readiness_keeps_missing_scientific_evidence_explicit() -> None:
    cases = [_case("dev", split="dev")]
    manifest_root = Path(".")
    with pytest.raises(DatasetReadinessError, match="manifest"):
        build_pilot_readiness_report(
            manifest=None,
            cases=cases,
            documents=[_document("doc-dev")],
            project_root=manifest_root,
        )
