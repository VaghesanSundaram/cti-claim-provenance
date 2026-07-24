from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest
from pydantic import BaseModel

from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.portfolio_challenge_runner import (
    CASE_OUTPUT_PATH,
    DOCUMENT_OUTPUT_PATH,
    PLAN_PATH,
    REPORT_OUTPUT_PATH,
    RESULT_OUTPUT_PATH,
    ChallengePlan,
    PortfolioChallengeResult,
    render_portfolio_challenge_cases,
    render_portfolio_challenge_documents,
    render_portfolio_challenge_jsonl,
    render_portfolio_challenge_report,
    run_portfolio_challenge_slice,
)
from cti_provenance.normalize import NormalizedDocument

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw" / "portfolio-pilot-v1"


def _jsonl[ModelT: BaseModel](path: Path, model: type[ModelT]) -> list[ModelT]:
    return [
        model.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _require_raw() -> None:
    if not RAW.is_dir():
        pytest.skip("gitignored portfolio source captures are unavailable")


def test_tracked_challenge_artifacts_are_closed_safe_and_holdout_free() -> None:
    plan = ChallengePlan.model_validate_json(
        ROOT.joinpath(*PLAN_PATH.parts).read_text(encoding="utf-8")
    )
    cases = _jsonl(ROOT.joinpath(*CASE_OUTPUT_PATH.parts), BenchmarkCase)
    documents = _jsonl(ROOT.joinpath(*DOCUMENT_OUTPUT_PATH.parts), NormalizedDocument)
    results = _jsonl(ROOT.joinpath(*RESULT_OUTPUT_PATH.parts), PortfolioChallengeResult)

    assert len(plan.families) == 16
    assert Counter(item.challenge_type for item in plan.families) == {
        "stale": 4,
        "lower_authority_contradiction": 4,
        "instruction_like_poison": 4,
        "unsupported_assertion": 4,
    }
    assert len(cases) == 48
    assert Counter(case.split for case in cases) == {"dev": 24, "validation": 24}
    assert all(case.split != "holdout" for case in cases)
    paired = [case for case in cases if "-control-" not in case.case_id]
    controls = [case for case in cases if "-control-" in case.case_id]
    assert len(paired) == 32 and all(case.paired_case_id for case in paired)
    assert len(controls) == 16 and all(case.paired_case_id is None for case in controls)
    by_id = {case.case_id: case for case in cases}
    assert all(
        by_id[case.paired_case_id].paired_case_id == case.case_id for case in paired
    )

    assert len(documents) == 128
    assert len({document.document_id for document in documents}) == 128
    assert all(document.source_name == "synthetic_control" for document in documents)
    assert all(
        document.fields["operational_content"] is False for document in documents
    )
    rendered_documents = "\n".join(document.normalized_text for document in documents)
    assert "payload" not in rendered_documents.casefold()
    assert "exploit code" not in rendered_documents.casefold()

    assert len(results) == 16
    assert Counter(result.split for result in results) == {"dev": 8, "validation": 8}
    assert all(len(result.variants) == 3 for result in results)
    assert all(result.provider_calls == 0 for result in results)
    assert all(
        variant.packet_document_count > variant.retrieval_depth
        for result in results
        for variant in result.variants
    )
    assert all(
        variant.relevant_at_k for result in results for variant in result.variants
    )
    for result in results:
        case_ids = {
            "clean": result.clean_case_id,
            "control": result.control_case_id,
            "challenge": result.challenge_case_id,
        }
        for variant in result.variants:
            assert set(by_id[case_ids[variant.variant]].allowed_snapshot_ids) == set(
                variant.packet_snapshot_ids
            )

    report = ROOT.joinpath(*REPORT_OUTPUT_PATH.parts).read_text(encoding="utf-8")
    assert "48/48" in report
    assert "16/16" in report
    assert "0/8" in report
    assert "not a provider/model evaluation" in report


def test_challenge_slice_replays_exactly_when_frozen_sources_exist() -> None:
    _require_raw()
    bundle = run_portfolio_challenge_slice(ROOT)

    assert bundle.integrity.passed
    assert len(bundle.results) == 16
    assert len(bundle.cases) == 48
    assert len(bundle.synthetic_documents) == 128
    assert render_portfolio_challenge_cases(bundle) == ROOT.joinpath(
        *CASE_OUTPUT_PATH.parts
    ).read_text(encoding="utf-8")
    assert render_portfolio_challenge_documents(bundle) == ROOT.joinpath(
        *DOCUMENT_OUTPUT_PATH.parts
    ).read_text(encoding="utf-8")
    assert render_portfolio_challenge_jsonl(bundle) == ROOT.joinpath(
        *RESULT_OUTPUT_PATH.parts
    ).read_text(encoding="utf-8")
    assert render_portfolio_challenge_report(bundle) == ROOT.joinpath(
        *REPORT_OUTPUT_PATH.parts
    ).read_text(encoding="utf-8")

    matched_control_ranks = 0
    for result in bundle.results:
        ranks = {variant.variant: variant.relevant_rank for variant in result.variants}
        if ranks["challenge"] == ranks["control"]:
            matched_control_ranks += 1
    assert matched_control_ranks == 16


def test_tracked_results_are_canonical_jsonl() -> None:
    path = ROOT.joinpath(*RESULT_OUTPUT_PATH.parts)
    for line in path.read_text(encoding="utf-8").splitlines():
        assert (
            json.dumps(json.loads(line), sort_keys=True, separators=(",", ":")) == line
        )
