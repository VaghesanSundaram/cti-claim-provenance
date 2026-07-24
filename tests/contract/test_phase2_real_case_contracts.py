from __future__ import annotations

from pathlib import Path

from cti_provenance.claims.real_slice import RealCaseReview
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.runner import OfflineCaseResult

ROOT = Path(__file__).resolve().parents[2]


def _jsonl(path: Path, model: type[BenchmarkCase] | type[RealCaseReview]) -> list:
    return [
        model.model_validate_json(line)
        for line in path.read_bytes().splitlines()
        if line.strip()
    ]


def test_real_development_cases_and_reviews_retain_scope_boundaries() -> None:
    cases = _jsonl(
        ROOT / "data" / "benchmark" / "dev" / "phase2-real-cases.jsonl",
        BenchmarkCase,
    )
    reviews = _jsonl(
        ROOT / "annotations" / "phase2-real-review.jsonl",
        RealCaseReview,
    )
    assert len(cases) == len(reviews) == 12
    assert {case.case_id for case in cases} == {review.case_id for review in reviews}
    for case in cases:
        assert case.split == "dev"
        assert case.entity_family_id == "log4shell-plumbing-only"
        assert "plumbing-only" in case.question.casefold()
        for claim in case.expected_claims:
            assert all(
                not evidence_id.startswith("phase2-contradictory-log4shell:")
                for evidence_id in claim.evidence_ids
            )
            expected_mode = (
                "observed_snapshot"
                if claim.predicate.startswith("cve.")
                else "upstream_versioned"
            )
            assert case.temporal_truth_mode == expected_mode
        if case.template_family_id.startswith("red-hat-"):
            assert case.temporal_truth_mode == "upstream_versioned"
            assert "publisher-declared version evidence" in case.question.casefold()

    attacked = next(case for case in cases if case.attack.family == "contradiction")
    assert attacked.attack.treatment_document_ids == ["phase2-contradictory-log4shell"]
    assert attacked.temporal_truth_mode == "observed_snapshot"
    insufficient = next(
        review
        for review in reviews
        if review.notes_code == "real_insufficient_evidence"
    )
    assert insufficient.target_predicate == "vendor.affected_versions"
    assert insufficient.required_authority == "red_hat_rhsa"
    assert insufficient.insufficiency_code == "no_explicit_known_affected_span"


def test_tracked_real_results_are_redacted_provider_free_outputs() -> None:
    result_path = ROOT / "reports" / "phase2-real-slice.jsonl"
    raw = result_path.read_text(encoding="utf-8")
    forbidden = (
        "data/raw/",
        "data/normalized/",
        "raw_locator",
        "response_headers",
        "normalized_text",
        str(ROOT),
    )
    assert all(value not in raw for value in forbidden)
    results = [
        OfflineCaseResult.model_validate_json(line)
        for line in raw.splitlines()
        if line.strip()
    ]
    assert len(results) == 12
    assert all(result.run.provider == "none" for result in results)
    assert all(result.run.input_tokens == 0 for result in results)
    assert all(result.run.output_tokens == 0 for result in results)
    assert all(result.run.estimated_cost_usd == 0 for result in results)
    assert len({result.run.dataset_version for result in results}) == 1
    assert results[0].run.dataset_version.startswith("phase2-real-local-replay-v1-")
    for result in results:
        if result.case.should_abstain:
            assert result.answer.abstained
            assert result.grades[0].abstention_outcome == "correct"
        else:
            assert not result.answer.abstained
            assert all(grade.claim_support == "supported" for grade in result.grades)

    report = (ROOT / "reports" / "phase2-real-slice.md").read_text(encoding="utf-8")
    assert "not a model evaluation" in report
    assert "not a model evaluation, baseline" in report
    assert "clean checkout must fail closed" in report
    assert "publisher-declared version evidence only" in report
    assert "CC BY 4.0" in report
    assert "CC0" in report
