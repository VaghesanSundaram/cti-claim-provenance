from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from cti_provenance.claims.schema import (
    ClaimObject,
    ClaimQualifiers,
    ClaimSubject,
    GoldAtomicClaim,
)
from cti_provenance.dataset.cases import AttackTreatment, BenchmarkCase
from cti_provenance.experiments.ledger import RunRecord

NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
SHA = "a" * 64


def _benchmark_case() -> BenchmarkCase:
    claim = GoldAtomicClaim(
        claim_id="expected-1",
        subject=ClaimSubject(type="cve", id="CVE-SYNTHETIC-0001"),
        predicate="kev.is_member",
        object=ClaimObject(value=True, datatype="boolean"),
        qualifiers=ClaimQualifiers(
            authority="cisa_kev",
            cvss_version=None,
            product=None,
            ecosystem=None,
        ),
        evidence_ids=["doc-1:span-1"],
        confidence=1.0,
    )
    return BenchmarkCase(
        case_id="case-1",
        case_family_id="case-family-1",
        entity_family_id="entity-family-1",
        template_family_id="template-family-1",
        split="dev",
        as_of=NOW,
        temporal_truth_mode="observed_snapshot",
        question="Was the synthetic record a KEV member?",
        allowed_snapshot_ids=["snapshot-1"],
        expected_claims=[claim],
        required_authority_policy_ids=["cisa-kev-status"],
        should_abstain=False,
        abstention_reason=None,
        paired_case_id=None,
        attack=AttackTreatment(
            family="none",
            treatment_document_ids=[],
            generation_version=None,
        ),
    )


def _run_record() -> RunRecord:
    return RunRecord(
        run_id="run-1",
        recorded_at_utc=NOW,
        project_version="0.1.0",
        dataset_version="dataset-v1",
        case_id="case-1",
        case_seed=7,
        condition="lexical_claim_evidence_constrained",
        provider="openai",
        model_id="example-model",
        model_snapshot_or_version="example-snapshot",
        prompt_version="prompt-v1",
        retriever_version="retriever-v1",
        corpus_manifest_hash=SHA,
        authority_policy_version="authority-policy-v1",
        input_tokens=100,
        cached_input_tokens=20,
        output_tokens=10,
        latency_ms=250,
        retry_count=0,
        provider_status="allowed",
        parse_status="valid",
        retrieval_outcome="success",
        deterministic_outcome="graded",
        security_outcome="allowed",
        utility_outcome="claims_emitted",
        error_category="none",
        estimated_cost_usd=Decimal("0.001"),
    )


def test_benchmark_case_roundtrip_and_cross_invariants() -> None:
    case = _benchmark_case()
    assert BenchmarkCase.model_validate_json(case.model_dump_json()) == case

    invalid = case.model_dump(mode="python")
    invalid["should_abstain"] = True
    invalid["abstention_reason"] = "insufficient_evidence"
    with pytest.raises(ValidationError, match="cannot contain expected"):
        BenchmarkCase.model_validate(invalid)

    invalid = case.model_dump(mode="python")
    invalid["abstention_reason"] = "unexpected"
    with pytest.raises(ValidationError, match="answerable"):
        BenchmarkCase.model_validate(invalid)

    invalid = case.model_dump(mode="python")
    invalid["expected_claims"] = []
    with pytest.raises(ValidationError, match="at least one expected"):
        BenchmarkCase.model_validate(invalid)

    invalid = case.model_dump(mode="python")
    invalid["should_abstain"] = 0
    with pytest.raises(ValidationError):
        BenchmarkCase.model_validate(invalid)


def test_run_record_roundtrip_strict_scalars_and_cross_invariants() -> None:
    record = _run_record()
    assert RunRecord.model_validate_json(record.model_dump_json()) == record

    invalid = record.model_dump(mode="python")
    invalid["case_seed"] = True
    with pytest.raises(ValidationError):
        RunRecord.model_validate(invalid)

    invalid = record.model_dump(mode="python")
    invalid["cached_input_tokens"] = 101
    with pytest.raises(ValidationError, match="cannot exceed"):
        RunRecord.model_validate(invalid)

    invalid = record.model_dump(mode="python")
    invalid.update(
        provider="none",
        provider_status="not_called",
        security_outcome="not_applicable",
    )
    with pytest.raises(ValidationError, match="cannot identify a model"):
        RunRecord.model_validate(invalid)

    invalid = record.model_dump(mode="python")
    invalid["parse_status"] = "invalid"
    with pytest.raises(ValidationError, match="deterministic_outcome"):
        RunRecord.model_validate(invalid)
