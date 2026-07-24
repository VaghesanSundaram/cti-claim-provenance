from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest

from cti_provenance.claims.real_slice import (
    RealSliceError,
    load_phase2_real_cases,
    load_phase2_real_corpus,
)
from cti_provenance.claims.schema import (
    ClaimEvidenceAnswer,
    ClaimEvidenceAtomicClaim,
)
from cti_provenance.cli import main
from cti_provenance.experiments.real_reports import render_real_offline_report
from cti_provenance.experiments.real_runner import (
    render_real_results_jsonl,
    run_real_offline_slice,
)
from cti_provenance.grading import grade_answer

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.legacy
REAL_CAPTURE_PATHS = (
    ROOT
    / "data/raw/nvd"
    / "ec21319bd69851e928c7eb34eded19bc049a71b092999f9d4930eba2f57c6db3.json",
    ROOT
    / "data/raw/cisa-kev"
    / "41d27023a5912a49ca2b06370550fa6da50e35794c269766a6332618d82f243e.json",
    ROOT
    / "data/raw/cisa-kev-lineage"
    / "a3a42da5e46e283ed0cc615e73b9e330cc518e9bcc8075dcb71bb626fdc8fc3a.json",
    ROOT
    / "data/raw/red-hat"
    / "da43faeafb5b8f5f0896572936959c3106f10c3ad13e66c34957a4f3e6c64f19.json",
    ROOT
    / "data/raw/red-hat-checksum"
    / "c6ed900b09a9bf71bf6d63b7049f537b0b461f91f4e621988f6fee692168b62e.sha256",
)
requires_real_capture = pytest.mark.skipif(
    not all(path.is_file() for path in REAL_CAPTURE_PATHS),
    reason="exact local real-source capture is intentionally gitignored",
)


@requires_real_capture
def test_real_slice_is_network_denied_deterministic_and_document_derived(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("real offline slice attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    first = run_real_offline_slice(ROOT)
    second = run_real_offline_slice(ROOT)

    first_jsonl = render_real_results_jsonl(first)
    first_report = render_real_offline_report(first)
    assert first_jsonl == render_real_results_jsonl(second)
    assert first_report == render_real_offline_report(second)
    assert first_jsonl == (ROOT / "reports" / "phase2-real-slice.jsonl").read_text()
    assert first_report == (ROOT / "reports" / "phase2-real-slice.md").read_text()
    assert len(first) == 12
    assert sum(result.answer.abstained for result in first) == 4
    assert all(result.run.provider == "none" for result in first)
    assert all(result.run.estimated_cost_usd == 0 for result in first)


@requires_real_capture
def test_synthetic_treatment_cannot_be_accepted_as_real_nvd_authority() -> None:
    results = run_real_offline_slice(ROOT)
    states, documents = load_phase2_real_corpus(ROOT)
    attacked = next(
        result
        for result in results
        if result.case.case_id == "real-nvd-cvss-combined-treatment"
    )
    expected = attacked.case.expected_claims[0]
    wrong_claim = ClaimEvidenceAtomicClaim.model_validate(
        {
            **expected.model_dump(),
            "claim_id": "generated-synthetic-cited",
            "evidence_ids": [
                "phase2-contradictory-log4shell:cvss_score",
            ],
        }
    )
    wrong_answer = ClaimEvidenceAnswer(
        answer_id="answer-synthetic-cited",
        run_id="run-synthetic-cited",
        case_id=attacked.case.case_id,
        as_of=attacked.case.as_of,
        claims=[wrong_claim],
        abstained=False,
        abstention_reason=None,
        narrative=None,
    )
    grades = grade_answer(
        attacked.case,
        wrong_answer,
        documents=documents,
        states=states,
    )
    assert len(grades) == 1
    assessment = grades[0].evidence_assessments[0]
    assert assessment.authority == "wrong"
    assert assessment.entailment == "unsupported"
    assert grades[0].claim_support == "unsupported"


def _copy_reviewed_cases(tmp_path: Path) -> None:
    case_path = tmp_path / "data" / "benchmark" / "dev" / "phase2-real-cases.jsonl"
    review_path = tmp_path / "annotations" / "phase2-real-review.jsonl"
    case_path.parent.mkdir(parents=True)
    review_path.parent.mkdir(parents=True)
    shutil.copyfile(
        ROOT / "data" / "benchmark" / "dev" / "phase2-real-cases.jsonl",
        case_path,
    )
    shutil.copyfile(
        ROOT / "annotations" / "phase2-real-review.jsonl",
        review_path,
    )


@requires_real_capture
@pytest.mark.parametrize(
    ("case_id", "field", "value", "message"),
    [
        (
            "real-red-hat-fixed-id",
            "temporal_truth_mode",
            "observed_snapshot",
            "temporal mode",
        ),
        (
            "real-nvd-published",
            "expected_value",
            "2099-01-01T00:00:00.000",
            "answer key",
        ),
        (
            "real-nvd-preavailability",
            "allowed_snapshot_ids",
            ["nvd-ec21319bd698"],
            "post-cutoff",
        ),
        (
            "real-kev-preavailability",
            "as_of",
            "2026-07-16T19:11:42Z",
            "cutoff admits",
        ),
    ],
)
def test_real_gold_rejects_mode_value_and_cutoff_mutations(
    tmp_path: Path,
    case_id: str,
    field: str,
    value: object,
    message: str,
) -> None:
    _copy_reviewed_cases(tmp_path)
    path = tmp_path / "data" / "benchmark" / "dev" / "phase2-real-cases.jsonl"
    cases = [json.loads(line) for line in path.read_text().splitlines()]
    target = next(case for case in cases if case["case_id"] == case_id)
    if field == "expected_value":
        target["expected_claims"][0]["object"]["value"] = value
    else:
        target[field] = value
    path.write_text(
        "".join(json.dumps(case, separators=(",", ":")) + "\n" for case in cases),
        encoding="utf-8",
    )
    states, documents = load_phase2_real_corpus(ROOT)

    with pytest.raises(RealSliceError, match=message):
        load_phase2_real_cases(tmp_path, states=states, documents=documents)


@requires_real_capture
@pytest.mark.parametrize(
    ("case_id", "field", "value", "message"),
    [
        (
            "real-red-hat-affected-insufficient",
            "insufficiency_code",
            None,
            "wrong corpus",
        ),
        (
            "real-nvd-published",
            "evidence_ids",
            [],
            "review",
        ),
    ],
)
def test_real_gold_rejects_review_binding_mutations(
    tmp_path: Path,
    case_id: str,
    field: str,
    value: object,
    message: str,
) -> None:
    _copy_reviewed_cases(tmp_path)
    path = tmp_path / "annotations" / "phase2-real-review.jsonl"
    reviews = [json.loads(line) for line in path.read_text().splitlines()]
    next(review for review in reviews if review["case_id"] == case_id)[field] = value
    path.write_text(
        "".join(json.dumps(review, separators=(",", ":")) + "\n" for review in reviews),
        encoding="utf-8",
    )
    states, documents = load_phase2_real_corpus(ROOT)

    with pytest.raises(RealSliceError, match=message):
        load_phase2_real_cases(tmp_path, states=states, documents=documents)


def test_real_cli_fails_closed_without_local_capture(tmp_path: Path) -> None:
    jsonl = tmp_path / "result.jsonl"
    report = tmp_path / "report.md"

    assert (
        main(
            [
                "real-offline-slice",
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
