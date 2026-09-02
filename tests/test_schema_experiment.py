from __future__ import annotations

import json
from pathlib import Path

import pytest

from cti_provenance.evaluation import load_json
from cti_provenance.experiment import RunStopped
from cti_provenance.schema_experiment import (
    answer_schema,
    build_request,
    build_schedule,
    grade,
    publish_results,
    response_schema,
    run,
)

ROOT = Path(__file__).resolve().parents[1]


def _case(
    case_id: str,
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    questions = load_json(ROOT / "data/benchmark/questions.json")
    packets = load_json(ROOT / "data/benchmark/evidence-packets.json")
    question = next(
        item for item in questions["questions"] if item["case_id"] == case_id
    )
    packet = next(item for item in packets["packets"] if item["case_id"] == case_id)
    return question, packet, packets["evaluator_bindings"][packet["packet_id"]]


def test_answer_schema_rejects_unneeded_union() -> None:
    assert answer_schema("boolean") == {"type": "boolean"}
    assert answer_schema("string_set")["type"] == "array"
    with pytest.raises(RunStopped):
        answer_schema("mapping")


def test_schema_is_question_specific_without_gold_value() -> None:
    question, _, _ = _case("extraction-09")
    public_metadata = {**question, "expected_components": []}
    schema = response_schema(public_metadata)
    serialized = json.dumps(schema)
    assert schema["properties"]["answer"]["anyOf"][0] == {"type": "boolean"}
    assert "Rust 1.77.2" not in serialized
    assert "true" not in serialized.casefold()


def test_conditions_share_prompt_and_differ_only_in_api_format() -> None:
    question, packet, _ = _case("extraction-09")
    baseline = build_request(ROOT, "citation_prompted", question, packet)
    candidate = build_request(ROOT, "question_specific_schema", question, packet)
    assert baseline["input"] == candidate["input"]
    assert baseline["text"]["format"] == {"type": "json_object"}
    assert candidate["text"]["format"]["schema"]["properties"]["answer"]["anyOf"][
        0
    ] == {"type": "boolean"}


def test_schedule_has_three_matched_trials_and_baseline_first() -> None:
    cells, requests = build_schedule(ROOT)
    assert len(cells) == len(requests) == 144
    assert len({cell["cell_id"] for cell in cells}) == 144
    for trial in (1, 2, 3):
        rows = [cell for cell in cells if cell["trial"] == trial]
        assert {cell["condition"] for cell in rows[:24]} == {"citation_prompted"}
        assert {cell["condition"] for cell in rows[24:]} == {"question_specific_schema"}
        assert [cell["case_id"] for cell in rows[:24]] == [
            cell["case_id"] for cell in rows[24:]
        ]


def test_grader_separates_semantics_type_and_evidence() -> None:
    question, _, bindings = _case("extraction-09")
    alias = bindings[0]["evidence"][0]["span_alias"]
    correct = {
        "schema_version": "cti-schema-v1.1-response",
        "case_id": "extraction-09",
        "answer": True,
        "abstention_reason": None,
        "citations": [alias],
    }
    assert grade(question, bindings, correct) == {
        "parse_status": "valid",
        "typed_contract_valid": True,
        "semantic_answer_correct": True,
        "evidence_binding_correct": True,
        "abstention_reason_correct": False,
    }
    wrong_type = {**correct, "answer": "Rust 1.77.2"}
    result = grade(question, bindings, wrong_type)
    assert result["typed_contract_valid"] is False
    assert result["semantic_answer_correct"] is None
    assert result["evidence_binding_correct"] is True


def test_singleton_set_gold_is_graded_as_a_set() -> None:
    question, _, bindings = _case("extraction-05")
    alias = bindings[0]["evidence"][0]["span_alias"]
    response = {
        "schema_version": "cti-schema-v1.1-response",
        "case_id": "extraction-05",
        "answer": ["2.95"],
        "abstention_reason": None,
        "citations": [alias],
    }
    result = grade(question, bindings, response)
    assert result["typed_contract_valid"] is True
    assert result["semantic_answer_correct"] is True


def test_correct_abstention_requires_the_expected_reason() -> None:
    question, _, bindings = _case("abstention-05")
    alias = bindings[0]["evidence"][0]["span_alias"]
    response = {
        "schema_version": "cti-schema-v1.1-response",
        "case_id": "abstention-05",
        "answer": None,
        "abstention_reason": "predicate_absent",
        "citations": [alias],
    }
    result = grade(question, bindings, response)
    assert result["semantic_answer_correct"] is True
    assert result["abstention_reason_correct"] is True


def test_results_require_a_complete_ledger(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text('{"record_type":"run_header"}\n', encoding="utf-8")
    with pytest.raises(RunStopped, match="header does not match"):
        publish_results(ROOT, ledger)


def test_provider_ledger_must_stay_outside_repository(tmp_path: Path) -> None:
    with pytest.raises(RunStopped, match="ledger must be outside"):
        run(ROOT, ROOT / "provider-ledger.jsonl", tmp_path / "raw", 0)
