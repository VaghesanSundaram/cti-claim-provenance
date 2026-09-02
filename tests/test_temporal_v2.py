from __future__ import annotations

import json
from pathlib import Path

import pytest

from cti_provenance.evaluation import (
    IntegrityError,
    analyze_factorial,
    build_temporal_rubric,
    grade_temporal,
    grade_temporal_text,
    load_json,
    load_jsonl,
)
from cti_provenance.experiment import (
    RetryableProviderError,
    RunStopped,
    UncertainProviderError,
    build_schedule,
    compact,
    make_openai_provider,
    request_set_hash,
    run_schedule,
    schedule_bytes,
    sha256,
)

ROOT = Path(__file__).resolve().parents[1]
MODEL = "gpt-5.6-luna"


def _provider_result(request: dict[str, object]) -> dict[str, object]:
    return {
        "model": request["model"],
        "output": {"final_answer": "test", "citations": []},
        "usage": {"input_tokens": 10, "output_tokens": 2},
    }


def test_schedule_is_complete_deterministic_and_factor_paired() -> None:
    cells, requests = build_schedule(ROOT)
    repeated_cells, repeated_requests = build_schedule(ROOT)
    assert schedule_bytes(cells) == schedule_bytes(repeated_cells)
    assert request_set_hash(requests) == request_set_hash(repeated_requests)
    assert len(cells) == len(requests) == 520
    assert len({cell["cell_id"] for cell in cells}) == 520
    assert sum(cell["kind"] == "factorial" for cell in cells) == 480
    assert sum(cell["kind"] == "oracle" for cell in cells) == 40
    assert {cell["dependency_id"] for cell in cells if cell["kind"] == "factorial"} == {
        question["dependency_id"]
        for question in load_json(ROOT / "data/benchmark/questions.json")["questions"]
        if question["slice"] == "temporal_comparison"
    }

    indexed = {
        (cell["case_id"], cell["trial"], cell["condition"]): request
        for cell, request in zip(cells, requests, strict=True)
        if cell["kind"] == "factorial"
    }
    for case_id in {cell["case_id"] for cell in cells}:
        for trial in range(1, 6):
            assert (
                indexed[(case_id, trial, "A")]["input"]
                == indexed[(case_id, trial, "B")]["input"]
            )
            assert (
                indexed[(case_id, trial, "C")]["input"]
                == indexed[(case_id, trial, "D")]["input"]
            )
            assert "text" not in indexed[(case_id, trial, "A")]
            assert "text" in indexed[(case_id, trial, "B")]


def test_requests_exclude_final_gold_and_record_supplied_absence_states() -> None:
    cells, requests = build_schedule(ROOT)
    corpus = load_json(ROOT / "data/benchmark/questions.json")
    questions = {question["case_id"]: question for question in corpus["questions"]}
    assertion_cases: set[str] = set()
    for cell, request in zip(cells, requests, strict=True):
        question = questions[cell["case_id"]]
        reference = question["readable_reference_answer"].split(
            " Structured component coverage:", 1
        )[0]
        delta = next(
            component["value"]
            for component in question["expected_components"]
            if component["kind"] == "delta_kind"
        )
        serialized = compact(request)
        assert reference not in serialized
        assert delta not in serialized
        if (
            cell["kind"] == "factorial"
            and "assertion" in serialized
            and "absent" in serialized
        ):
            assertion_cases.add(cell["case_id"])
    assert len(assertion_cases) == 13


def test_runner_retries_resumes_and_rejects_manifest_drift(tmp_path: Path) -> None:
    cells, requests = build_schedule(ROOT)
    subset_cells, subset_requests = cells[:3], requests[:3]
    ledger = tmp_path / "ledger.jsonl"
    calls = 0

    def retry_once(request: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RetryableProviderError("rate limit")
        return _provider_result(request)

    run_schedule(subset_cells, subset_requests, retry_once, ledger, "a" * 64, MODEL)
    assert calls == 4
    assert sum(row.get("status") == "completed" for row in load_jsonl(ledger)) == 3
    run_schedule(subset_cells, subset_requests, retry_once, ledger, "a" * 64, MODEL)
    assert calls == 4
    with pytest.raises(RunStopped, match="manifest"):
        run_schedule(subset_cells, subset_requests, retry_once, ledger, "b" * 64, MODEL)

    clean_stop = tmp_path / "clean-stop.jsonl"
    clean_calls = 0

    def clean_provider(request: dict[str, object]) -> dict[str, object]:
        nonlocal clean_calls
        clean_calls += 1
        return _provider_result(request)

    run_schedule(
        subset_cells,
        subset_requests,
        clean_provider,
        clean_stop,
        "c" * 64,
        MODEL,
        maximum_cells=1,
    )
    assert clean_calls == 1
    run_schedule(
        subset_cells, subset_requests, clean_provider, clean_stop, "c" * 64, MODEL
    )
    assert clean_calls == 3

    interrupted = tmp_path / "interrupted.jsonl"

    def interrupt(_: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError, match="interruption"):
        run_schedule(
            subset_cells, subset_requests, interrupt, interrupted, "e" * 64, MODEL
        )
    resumed_calls = 0

    def resume(request: dict[str, object]) -> dict[str, object]:
        nonlocal resumed_calls
        resumed_calls += 1
        return _provider_result(request)

    with pytest.raises(RunStopped, match="unclosed"):
        run_schedule(
            subset_cells, subset_requests, resume, interrupted, "e" * 64, MODEL
        )
    assert resumed_calls == 0

    uncertain = tmp_path / "uncertain.jsonl"

    def uncertain_provider(_: dict[str, object]) -> dict[str, object]:
        raise UncertainProviderError("raw persistence failed")

    with pytest.raises(RunStopped, match="uncertain"):
        run_schedule(
            subset_cells,
            subset_requests,
            uncertain_provider,
            uncertain,
            "f" * 64,
            MODEL,
        )
    with pytest.raises(RunStopped, match="non-resumable"):
        run_schedule(subset_cells, subset_requests, resume, uncertain, "f" * 64, MODEL)
    failed = tmp_path / "failed.jsonl"
    failed_calls = 0

    def exhaust(_: dict[str, object]) -> dict[str, object]:
        nonlocal failed_calls
        failed_calls += 1
        raise RetryableProviderError("server error")

    run_schedule(
        subset_cells[:1], subset_requests[:1], exhaust, failed, "d" * 64, MODEL
    )
    run_schedule(
        subset_cells[:1], subset_requests[:1], exhaust, failed, "d" * 64, MODEL
    )
    assert failed_calls == 2
    assert (
        sum(row.get("status") == "provider_failure" for row in load_jsonl(failed)) == 1
    )
    with pytest.raises(RunStopped, match="outside the repository"):
        make_openai_provider(ROOT / "raw", ROOT)


def test_typed_grader_separates_semantic_canonical_components_and_evidence() -> None:
    corpus = load_json(ROOT / "data/benchmark/questions.json")
    packets = load_json(ROOT / "data/benchmark/evidence-packets.json")
    question = next(q for q in corpus["questions"] if q["case_id"] == "temporal-01")
    documents = packets["evaluator_bindings"]["packet-temporal-01"]
    aliases = [
        evidence["span_alias"] for doc in documents for evidence in doc["evidence"]
    ]
    components = {item["kind"]: item for item in question["expected_components"]}
    accepted = build_temporal_rubric(ROOT)["cases"]["temporal-01"]
    response = {
        "final_answer": accepted["accepted_final_answers"][0],
        "citations": aliases,
        "old_state": components["old_value"]["value"],
        "old_state_citations": aliases[:1],
        "new_state": components["new_value"]["value"],
        "new_state_citations": aliases[1:],
        "change": components["delta_kind"]["value"],
        "change_citations": aliases,
    }
    grade = grade_temporal(question, documents, response, "state_first", accepted)
    assert grade["semantic_correct"] is True
    assert grade["canonical_correct"] is True
    assert grade["old_state_correct"] is True
    assert grade["new_state_correct"] is True
    assert grade["change_correct"] is True
    assert grade["evidence_correct"] is True

    response["final_answer"] = response["final_answer"].upper() + "!!!"
    grade = grade_temporal(question, documents, response, "state_first", accepted)
    assert grade["semantic_correct"] is True
    assert grade["canonical_correct"] is False
    response["final_answer"] = "A faithful but differently worded answer."
    assert grade_temporal(question, documents, response, "state_first", accepted)[
        "review_required"
    ]
    assert grade_temporal(
        question, documents, response, "state_first", accepted, review_decision=True
    )["semantic_correct"]
    response["old_state"], response["new_state"] = (
        response["new_state"],
        response["old_state"],
    )
    assert not grade_temporal(
        question, documents, response, "state_first", accepted, review_decision=True
    )["old_state_correct"]
    assert (
        grade_temporal_text(question, documents, "not json", "state_first", accepted)[
            "parse_status"
        ]
        == "invalid_shape"
    )


def test_set_normalization_and_cluster_effects() -> None:
    corpus = load_json(ROOT / "data/benchmark/questions.json")
    packets = load_json(ROOT / "data/benchmark/evidence-packets.json")
    question = next(q for q in corpus["questions"] if q["case_id"] == "temporal-03")
    documents = packets["evaluator_bindings"]["packet-temporal-03"]
    aliases = [
        evidence["span_alias"] for doc in documents for evidence in doc["evidence"]
    ]
    rubric = build_temporal_rubric(ROOT)["cases"]["temporal-03"]
    response = {
        "final_answer": rubric["accepted_final_answers"][0],
        "citations": aliases,
        "old_state": '["Windows"]',
        "old_state_citations": aliases[:1],
        "new_state": '["Windows","Linux","Linux"]',
        "new_state_citations": aliases[1:],
        "change": "Linux_added",
        "change_citations": aliases,
    }
    assert grade_temporal(question, documents, response, "state_first", rubric)[
        "new_state_correct"
    ]
    response["change"] = "Linux was added"
    paraphrase = grade_temporal(
        question,
        documents,
        response,
        "state_first",
        rubric,
        component_reviews={"delta_kind": True},
    )
    assert paraphrase["change_semantic_correct"] is True
    assert paraphrase["change_canonical_correct"] is False
    response["change"] = "Linux was removed"
    assert not grade_temporal(
        question,
        documents,
        response,
        "state_first",
        rubric,
        component_reviews={"delta_kind": False},
    )["change_semantic_correct"]

    oracle_response = {
        "final_answer": rubric["accepted_final_answers"][0],
        "citations": aliases,
        "change": "Linux was added",
        "change_citations": aliases,
    }
    oracle_grade = grade_temporal(
        question,
        documents,
        oracle_response,
        "direct",
        rubric,
        component_reviews={"delta_kind": True},
        oracle=True,
    )
    assert oracle_grade["change_semantic_correct"] is True

    mapping_case = next(q for q in corpus["questions"] if q["case_id"] == "temporal-04")
    mapping_documents = packets["evaluator_bindings"]["packet-temporal-04"]
    mapping_aliases = [
        evidence["span_alias"]
        for doc in mapping_documents
        for evidence in doc["evidence"]
    ]
    mapping_components = {
        item["kind"]: item for item in mapping_case["expected_components"]
    }
    mapping_rubric = build_temporal_rubric(ROOT)["cases"]["temporal-04"]
    mapping_response = {
        "final_answer": mapping_rubric["accepted_final_answers"][0],
        "citations": mapping_aliases,
        "old_state": json.dumps(
            mapping_components["old_value"]["value"], sort_keys=True
        ),
        "old_state_citations": mapping_aliases,
        "new_state": json.dumps(
            mapping_components["new_value"]["value"], sort_keys=True
        ),
        "new_state_citations": mapping_aliases,
        "change": mapping_components["delta_kind"]["value"],
        "change_citations": mapping_aliases,
    }
    mapping_grade = grade_temporal(
        mapping_case,
        mapping_documents,
        mapping_response,
        "state_first",
        mapping_rubric,
    )
    assert mapping_grade["old_state_semantic_correct"] is True
    assert mapping_grade["new_state_semantic_correct"] is True

    for case_id, field, wrong_value in (
        ("temporal-05", "old_state", "disconnect by 2024-02-03 23:59"),
        ("temporal-18", "new_state", '["X1S PRO"]'),
    ):
        case = next(q for q in corpus["questions"] if q["case_id"] == case_id)
        case_documents = packets["evaluator_bindings"][f"packet-{case_id}"]
        case_aliases = [
            evidence["span_alias"]
            for doc in case_documents
            for evidence in doc["evidence"]
        ]
        case_components = {item["kind"]: item for item in case["expected_components"]}
        case_rubric = build_temporal_rubric(ROOT)["cases"][case_id]
        case_response = {
            "final_answer": case_rubric["accepted_final_answers"][0],
            "citations": case_aliases,
            "old_state": json.dumps(case_components["old_value"]["value"]),
            "old_state_citations": case_aliases,
            "new_state": json.dumps(case_components["new_value"]["value"]),
            "new_state_citations": case_aliases,
            "change": case_components["delta_kind"]["value"],
            "change_citations": case_aliases,
        }
        case_response[field] = wrong_value
        kind = "old_value" if field == "old_state" else "new_value"
        assert not grade_temporal(
            case,
            case_documents,
            case_response,
            "state_first",
            case_rubric,
            component_reviews={kind: False},
        )[f"{field}_semantic_correct"]

    no_change = next(q for q in corpus["questions"] if q["case_id"] == "temporal-20")
    no_change_documents = packets["evaluator_bindings"]["packet-temporal-20"]
    no_change_aliases = [
        evidence["span_alias"]
        for doc in no_change_documents
        for evidence in doc["evidence"]
    ]
    no_change_rubric = build_temporal_rubric(ROOT)["cases"]["temporal-20"]
    no_change_response = {
        "final_answer": no_change_rubric["accepted_final_answers"][0],
        "citations": no_change_aliases,
        "change": "There was no material change",
        "change_citations": no_change_aliases,
    }
    assert grade_temporal(
        no_change,
        no_change_documents,
        no_change_response,
        "direct",
        no_change_rubric,
        component_reviews={"delta_kind": True},
        oracle=True,
    )["change_semantic_correct"]

    schedule, _ = build_schedule(ROOT)
    outcomes = [
        {
            "cell_id": cell["cell_id"],
            "semantic_correct": cell["condition"] in {"C", "D"},
        }
        for cell in schedule
        if cell["kind"] == "factorial"
    ]
    analysis = analyze_factorial(schedule, outcomes, draws=100)
    assert analysis["effects"] == {
        "decomposition": 1.0,
        "schema": 0.0,
        "interaction": 0.0,
    }
    assert analysis["cluster_count"] == 19
    assert all(
        row["pass^5"]
        for key, row in analysis["reliability"].items()
        if key.endswith(":C")
    )

    missing_and_failed = [
        outcome for outcome in outcomes if outcome["cell_id"] != schedule[0]["cell_id"]
    ]
    missing_and_failed[0] = {
        "cell_id": missing_and_failed[0]["cell_id"],
        "status": "provider_failure",
    }
    conservative = analyze_factorial(schedule, missing_and_failed, draws=10)
    assert conservative["condition_rates"]["A"] == 0.0
    with pytest.raises(IntegrityError, match="duplicate"):
        analyze_factorial(schedule, outcomes + outcomes[:1], draws=10)
    with pytest.raises(IntegrityError, match="520"):
        analyze_factorial(schedule[:-1], outcomes, draws=10)
    assert sha256(schedule_bytes(build_schedule(ROOT)[0]))
