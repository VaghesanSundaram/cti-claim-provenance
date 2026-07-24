from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.grading.schema import ClaimGrade

ROOT = Path(__file__).resolve().parents[2]
GRADE_FIXTURES = ROOT / "tests" / "fixtures" / "claim-grades"


def test_valid_claim_grade_fixture_round_trips() -> None:
    payload = (GRADE_FIXTURES / "valid" / "supported.json").read_text(encoding="utf-8")
    grade = ClaimGrade.model_validate_json(payload)
    assert grade.claim_support == "supported"
    assert ClaimGrade.model_validate_json(grade.model_dump_json()) == grade


@pytest.mark.parametrize(
    "path",
    sorted((GRADE_FIXTURES / "invalid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_deliberately_invalid_claim_grade_fixtures_fail(path: Path) -> None:
    with pytest.raises(ValidationError):
        ClaimGrade.model_validate_json(path.read_text(encoding="utf-8"))


def test_coherent_unmatched_false_positive_and_false_negative() -> None:
    base = ClaimGrade.model_validate_json(
        (GRADE_FIXTURES / "valid" / "supported.json").read_text(encoding="utf-8")
    ).model_dump(mode="python")

    false_positive = {
        **base,
        "claim_grade_id": "false-positive-1",
        "expected_claim_id": None,
        "value_match": "not_applicable",
        "evidence_assessments": [],
        "claim_support": "unsupported",
    }
    assert ClaimGrade.model_validate(false_positive).expected_claim_id is None

    false_negative = {
        **base,
        "claim_grade_id": "false-negative-1",
        "generated_claim_id": None,
        "value_match": "not_applicable",
        "evidence_assessments": [],
        "claim_support": "unsupported",
        "abstention_outcome": "not_applicable",
        "generated_confidence": None,
    }
    assert ClaimGrade.model_validate(false_negative).generated_claim_id is None


def test_abstention_outcomes_follow_case_answerability_semantics() -> None:
    base = ClaimGrade.model_validate_json(
        (GRADE_FIXTURES / "valid" / "supported.json").read_text(encoding="utf-8")
    ).model_dump(mode="python")

    correct = {
        **base,
        "claim_grade_id": "correct-abstention-1",
        "generated_claim_id": None,
        "expected_claim_id": None,
        "value_match": "not_applicable",
        "evidence_assessments": [],
        "claim_support": "ungradable",
        "abstention_outcome": "correct",
        "generated_confidence": None,
    }
    assert ClaimGrade.model_validate(correct).abstention_outcome == "correct"

    unnecessary = {
        **base,
        "claim_grade_id": "unnecessary-abstention-1",
        "generated_claim_id": None,
        "value_match": "not_applicable",
        "evidence_assessments": [],
        "claim_support": "unsupported",
        "abstention_outcome": "unnecessary",
        "generated_confidence": None,
    }
    assert ClaimGrade.model_validate(unnecessary).abstention_outcome == "unnecessary"

    missed = {
        **base,
        "claim_grade_id": "missed-abstention-1",
        "expected_claim_id": None,
        "value_match": "not_applicable",
        "evidence_assessments": [],
        "claim_support": "unsupported",
        "abstention_outcome": "missed",
    }
    assert ClaimGrade.model_validate(missed).abstention_outcome == "missed"


@pytest.mark.parametrize(
    ("generated_claim_id", "expected_claim_id", "outcome"),
    [
        (None, None, "not_applicable"),
        ("generated-1", None, "correct"),
        (None, "expected-1", "correct"),
        ("generated-1", "expected-1", "correct"),
        ("generated-1", None, "unnecessary"),
        (None, "expected-1", "missed"),
    ],
)
def test_incoherent_abstention_relationships_fail(
    generated_claim_id: str | None,
    expected_claim_id: str | None,
    outcome: str,
) -> None:
    base = ClaimGrade.model_validate_json(
        (GRADE_FIXTURES / "valid" / "supported.json").read_text(encoding="utf-8")
    ).model_dump(mode="python")
    payload = {
        **base,
        "generated_claim_id": generated_claim_id,
        "expected_claim_id": expected_claim_id,
        "value_match": (
            "exact"
            if generated_claim_id is not None and expected_claim_id is not None
            else "not_applicable"
        ),
        "evidence_assessments": [],
        "claim_support": (
            "unsupported"
            if generated_claim_id is not None or expected_claim_id is not None
            else "ungradable"
        ),
        "abstention_outcome": outcome,
        "generated_confidence": 0.9 if generated_claim_id is not None else None,
    }
    with pytest.raises(ValidationError):
        ClaimGrade.model_validate(payload)
