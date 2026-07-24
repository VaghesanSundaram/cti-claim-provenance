from __future__ import annotations

import socket
from datetime import timedelta
from pathlib import Path

import pytest

from cti_provenance.claims.three_family import (
    load_three_family_cases,
    load_three_family_corpus,
)
from cti_provenance.cli import main
from cti_provenance.experiments.three_family_runner import (
    build_three_family_answer,
    render_three_family_jsonl,
    render_three_family_report,
    run_three_family_slice,
)
from cti_provenance.grading import grade_answer
from cti_provenance.grading.authority import THREE_FAMILY_AUTHORITY_POLICY_VERSION
from cti_provenance.retrieval import LexicalRetriever, build_cutoff_corpus

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.legacy
RAW_PATHS = (
    ROOT / "data/raw/corpus-replacement-v1/cve-2024-3094-initial.json",
    ROOT / "data/raw/corpus-replacement-v1/cve-2024-3094-apr18.json",
    ROOT
    / "data/raw/corpus-feasibility-seven-url-v1/04-ivanti-ed-24-01-supplement-v1.html",
    ROOT
    / "data/raw/corpus-feasibility-seven-url-v1/05-ivanti-ed-24-01-supplement-v2.html",
    ROOT
    / (
        "data/raw/corpus-feasibility-seven-url-v1/"
        "06-netscaler-cve-2023-4966-2023-10-23.html"
    ),
    ROOT
    / (
        "data/raw/corpus-feasibility-seven-url-v1/"
        "07-netscaler-cve-2023-4966-2023-11-20.html"
    ),
)
requires_three_family_raw = pytest.mark.skipif(
    not all(path.is_file() for path in RAW_PATHS),
    reason="exact three-family source bytes are intentionally gitignored",
)


@requires_three_family_raw
def test_three_family_slice_is_offline_deterministic_and_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("three-family slice attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    first = run_three_family_slice(ROOT)
    second = run_three_family_slice(ROOT)

    jsonl = render_three_family_jsonl(first)
    report = render_three_family_report(first)
    assert jsonl == render_three_family_jsonl(second)
    assert report == render_three_family_report(second)
    assert jsonl == (ROOT / "reports/three-family-slice.jsonl").read_text()
    assert report == (ROOT / "reports/three-family-slice.md").read_text()
    assert len(first) == 3
    assert {result.case.entity_family_id for result in first} == {
        "cve-2024-3094",
        "ivanti-ed-24-01",
        "netscaler-cve-2023-4966",
    }
    assert all(not result.answer.abstained for result in first)
    assert all(
        grade.claim_support == "supported"
        for result in first
        for grade in result.grades
    )
    assert all(result.run.provider == "none" for result in first)
    assert all(result.run.estimated_cost_usd == 0 for result in first)


@requires_three_family_raw
def test_each_family_abstains_before_its_answer_bearing_publisher_version() -> None:
    states, documents = load_three_family_corpus(ROOT)
    cases = load_three_family_cases(ROOT, states=states, documents=documents)
    states_by_snapshot = {state.manifest.snapshot_id: state for state in states}
    for case in cases:
        cutoff = states_by_snapshot[
            case.allowed_snapshot_ids[0]
        ].manifest.available_by_utc - timedelta(seconds=1)
        abstention_case = case.model_copy(
            update={
                "as_of": cutoff,
                "allowed_snapshot_ids": [],
                "expected_claims": [],
                "should_abstain": True,
                "abstention_reason": "No publisher version is eligible by cutoff.",
            }
        )
        corpus = build_cutoff_corpus(documents, states, cutoff)
        hits = LexicalRetriever(corpus).search(case.question, limit=4)
        answer = build_three_family_answer(
            abstention_case,
            run_id=f"pre-cutoff-{case.case_id}",
            hits=hits,
            documents=documents,
        )
        assert answer.abstained
        grades = grade_answer(
            abstention_case,
            answer,
            documents=documents,
            states=states,
            authority_policy_version=THREE_FAMILY_AUTHORITY_POLICY_VERSION,
        )
        assert len(grades) == 1
        assert grades[0].abstention_outcome == "correct"


def test_three_family_cli_fails_closed_without_local_raw(tmp_path: Path) -> None:
    jsonl = tmp_path / "result.jsonl"
    report = tmp_path / "report.md"
    assert (
        main(
            [
                "three-family-slice",
                "--root",
                str(tmp_path),
                "--jsonl",
                str(jsonl),
                "--report",
                str(report),
            ]
        )
        == 1
    )
    assert not jsonl.exists()
    assert not report.exists()
