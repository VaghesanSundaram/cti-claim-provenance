from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from cti_provenance.claims.portfolio_correction import (
    load_portfolio_gold_correction,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.portfolio_challenge_runner import (
    PortfolioChallengeResult,
    run_portfolio_challenge_slice,
)
from cti_provenance.experiments.portfolio_yield_runner import (
    run_portfolio_yield_slice,
)
from cti_provenance.grading.review_workflow import (
    ReviewDecision,
    ReviewPacket,
    load_jsonl_records,
    validate_review_log,
)

ROOT = Path(__file__).resolve().parents[2]
DECISIONS = ROOT / (
    "annotations/decisions/portfolio-dev-validation-review-v1-reviewer-a17.jsonl"
)
ACTIVE_MANIFEST = ROOT / "data/manifests/portfolio-active-corpus-v2.json"
RAW = ROOT / "data/raw/portfolio-pilot-v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _jsonl[ModelT: BaseModel](path: Path, model: type[ModelT]) -> list[ModelT]:
    return [model.model_validate_json(line) for line in path.read_text().splitlines()]


def test_corrected_append_only_review_log_is_exact_and_complete() -> None:
    assert _sha256(DECISIONS) == (
        "9064e11c415052441daa0eecaf8181b6b20775324b9cef90d3e327b2f1eb643b"
    )
    packet = ReviewPacket.model_validate_json(
        (
            ROOT / "annotations/packets/portfolio-dev-validation-review-v1.json"
        ).read_text(encoding="utf-8")
    )
    decisions = load_jsonl_records(DECISIONS, ReviewDecision)
    summary = validate_review_log(packet, decisions, [], review_mode="single_reviewer")
    assert len(decisions) == 21
    assert summary.active_decision_count == 20
    assert summary.unresolved_item_ids == []
    correction = next(
        item
        for item in decisions
        if item.decision_id == "66dae977-b2eb-4cdc-a305-cfc90630a7ef"
    )
    assert correction.supersedes_decision_id == ("a91b0891-d337-4bbe-a1ce-83fde45ee8e7")
    assert correction.case_id == "portfolio-case-84fa2dcb3d58982b"
    assert correction.verdict.factual_correctness == "incorrect"
    assert correction.verdict.evidence_support == "partially_supported"
    assert correction.verdict.authority == "acceptable"
    assert correction.verdict.cutoff == "eligible"
    assert correction.label_changed is True


def test_overlay_locks_v1_and_active_v2_artifacts() -> None:
    overlay = load_portfolio_gold_correction(ROOT)
    for relative, expected in overlay.frozen_v1_artifacts.items():
        assert _sha256(ROOT / relative) == expected

    manifest = json.loads(ACTIVE_MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "portfolio-active-corpus-v2"
    for artifact in [
        manifest["overlay"],
        manifest["review_decisions"],
        *manifest["successors"],
        *manifest["reused_artifacts"],
    ]:
        assert _sha256(ROOT / artifact["path"]) == artifact["sha256"]


def test_v2_cases_and_packet_contain_only_the_dd_wrt_successor() -> None:
    public_cases = _jsonl(
        ROOT / "data/benchmark/portfolio-public-cases-v2.jsonl", BenchmarkCase
    )
    challenge_cases = _jsonl(
        ROOT / "data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl",
        BenchmarkCase,
    )
    assert len(public_cases) == 16
    assert len(challenge_cases) == 48
    target_public = [
        case
        for case in public_cases
        if case.case_id == "portfolio-yield-cisa-kev-cve-2021-27137"
    ]
    assert len(target_public) == 1
    assert target_public[0].expected_claims[0].qualifiers.product == "DD-WRT"
    target_challenges = [
        case
        for case in challenge_cases
        if case.case_id.startswith("portfolio-yield-cisa-kev-cve-2021-27137-")
    ]
    assert len(target_challenges) == 3
    assert all(
        case.expected_claims[0].qualifiers.product == "DD-WRT"
        for case in target_challenges
    )
    assert (
        "Accellion FTA"
        not in (ROOT / "data/benchmark/portfolio-public-cases-v2.jsonl").read_text()
    )
    assert (
        "Accellion FTA"
        not in (
            ROOT / "data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl"
        ).read_text()
    )

    packet = ReviewPacket.model_validate_json(
        (
            ROOT / "annotations/packets/portfolio-dev-validation-review-v2.json"
        ).read_text(encoding="utf-8")
    )
    targets = [
        item
        for item in packet.items
        if item.original_label.expected_claim is not None
        and item.original_label.expected_claim.subject.id == "CVE-2021-27137"
    ]
    assert packet.packet_id == "portfolio-dev-validation-review-v2"
    assert len(packet.items) == 20
    assert len(targets) == 1
    claim = targets[0].original_label.expected_claim
    assert claim is not None and claim.qualifiers.product == "DD-WRT"


def test_tracked_v2_challenge_metrics_remain_provider_free() -> None:
    results = _jsonl(
        ROOT / "reports/portfolio-challenge-slice-v2.jsonl",
        PortfolioChallengeResult,
    )
    assert len(results) == 16
    assert all(result.provider_calls == 0 for result in results)
    for variant in ("clean", "control", "challenge"):
        selected = [
            item
            for result in results
            for item in result.variants
            if item.variant == variant
        ]
        assert len(selected) == 16
        assert all(item.relevant_at_k for item in selected)
    repeatability = (
        ROOT / "reports/portfolio-dev-validation-review-v1-repeatability.md"
    ).read_text(encoding="utf-8")
    assert "4/4 (100.0%)" in repeatability
    assert "portfolio-yield-cisa-kev-cve-2021-27137" in repeatability
    assert "not correctness of gold labels" in repeatability


@pytest.mark.skipif(not RAW.is_dir(), reason="gitignored source cache unavailable")
def test_v2_rebuild_has_no_deterministic_metric_change() -> None:
    yield_v1 = run_portfolio_yield_slice(ROOT, correction_version="v1")
    yield_v2 = run_portfolio_yield_slice(ROOT, correction_version="v2")

    def grade_shape(rows):
        return [
            [
                (
                    grade.value_match,
                    grade.claim_support,
                    [
                        (
                            evidence.entailment,
                            evidence.temporality,
                            evidence.authority,
                            evidence.span_hash_match,
                        )
                        for evidence in grade.evidence_assessments
                    ],
                )
                for grade in row.grades
            ]
            for row in rows
        ]

    assert grade_shape(yield_v1) == grade_shape(yield_v2)

    challenge_v1 = run_portfolio_challenge_slice(ROOT, correction_version="v1")
    challenge_v2 = run_portfolio_challenge_slice(ROOT, correction_version="v2")

    def metric_shape(bundle):
        return [
            [
                (variant.variant, variant.relevant_rank, variant.relevant_at_k)
                for variant in result.variants
            ]
            for result in bundle.results
        ]

    assert challenge_v2.integrity.passed
    assert metric_shape(challenge_v1) == metric_shape(challenge_v2)
