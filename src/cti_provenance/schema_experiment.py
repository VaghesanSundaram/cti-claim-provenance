"""Question-specific schema replication for the V1 extraction and abstention slices."""

from __future__ import annotations

import random
from collections import defaultdict
from pathlib import Path

from cti_provenance.evaluation import JSON, canonical_json, load_json, load_jsonl
from cti_provenance.experiment import (
    RunStopped,
    artifact_hash,
    compact,
    make_openai_provider,
    request_set_hash,
    run_schedule,
    schedule_bytes,
    sha256,
)

REASONS = [
    "no_cutoff_eligible_state",
    "insufficient_product_version_specificity",
    "predicate_absent",
    "wrong_authority_for_predicate",
    "unresolved_authoritative_evidence",
]
RESPONSE_KEYS = {
    "schema_version",
    "case_id",
    "answer",
    "abstention_reason",
    "citations",
}


def question_datatype(question: JSON) -> str:
    """Translate public task metadata into the response datatype."""

    datatypes = {"boolean": "boolean", "string": "string", "set": "string_set"}
    try:
        return datatypes[str(question["answer_type"])]
    except KeyError as error:
        raise RunStopped("unsupported V1.1 answer type") from error


def answer_schema(datatype: str) -> JSON:
    """Map benchmark datatypes to the narrow provider value shape."""

    schemas: dict[str, JSON] = {
        "boolean": {"type": "boolean"},
        "string": {"type": "string"},
        "string_set": {"type": "array", "items": {"type": "string"}},
    }
    try:
        return schemas[datatype]
    except KeyError as error:
        raise RunStopped(f"unsupported V1.1 datatype: {datatype}") from error


def response_schema(question: JSON) -> JSON:
    """Build a strict schema from public task metadata, never the gold answer."""

    datatype = question_datatype(question)
    return {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string", "const": "cti-schema-v1.1-response"},
            "case_id": {"type": "string", "const": question["case_id"]},
            "answer": {"anyOf": [answer_schema(datatype), {"type": "null"}]},
            "abstention_reason": {
                "anyOf": [{"type": "string", "enum": REASONS}, {"type": "null"}]
            },
            "citations": {"type": "array", "items": {"type": "string"}},
        },
        "required": sorted(RESPONSE_KEYS),
        "additionalProperties": False,
    }


def _packet(question: JSON, packet: JSON) -> JSON:
    return {
        "case_id": packet["case_id"],
        "question": packet["question"],
        "target_predicate": question["predicate"],
        "answer_datatype": question_datatype(question),
        "allowed_abstention_reasons": REASONS,
        "cutoff_utc": packet["cutoff_utc"],
        "documents": packet["documents"],
    }


def build_request(root: Path, condition: str, question: JSON, packet: JSON) -> JSON:
    design = load_json(root / "configs/experiments/schema-v1.1.json")
    provider = design["provider_intent"]
    prompt = (root / "prompts/schema-v1.1.txt").read_text(encoding="utf-8")
    prompt = prompt.format(packet=compact(_packet(question, packet)))
    request: JSON = {
        "model": provider["model"],
        "input": prompt,
        "max_output_tokens": provider["max_output_tokens"],
        "reasoning": {"effort": provider["reasoning_effort"]},
        "service_tier": provider["service_tier"],
        "store": provider["store"],
        "background": provider["background"],
        "tools": provider["tools"],
        "tool_choice": provider["tool_choice"],
        "text": {"format": {"type": "json_object"}},
    }
    if design["conditions"][condition]["schema_enforced"]:
        request["text"] = {
            "format": {
                "type": "json_schema",
                "name": "cti_question_specific_answer",
                "strict": True,
                "schema": response_schema(question),
            }
        }
    return request


def build_schedule(root: Path) -> tuple[list[JSON], list[JSON]]:
    design = load_json(root / "configs/experiments/schema-v1.1.json")
    corpus = load_json(root / design["source_artifacts"]["questions"])
    packets = load_json(root / design["source_artifacts"]["packets"])
    questions = [
        item for item in corpus["questions"] if item["slice"] in design["slices"]
    ]
    if len(questions) != design["question_count"]:
        raise RunStopped("V1.1 question count drifted")
    packet_by_case = {item["case_id"]: item for item in packets["packets"]}
    cells: list[JSON] = []
    requests: list[JSON] = []
    randomizer = random.Random(design["schedule"]["seed"])
    for trial in range(1, design["trials"] + 1):
        ordered = sorted(questions, key=lambda item: item["case_id"])
        randomizer.shuffle(ordered)
        for condition in design["conditions"]:
            for question in ordered:
                identity = compact(
                    [
                        design["experiment_version"],
                        question["case_id"],
                        condition,
                        trial,
                    ]
                )
                request = build_request(
                    root, condition, question, packet_by_case[question["case_id"]]
                )
                cells.append(
                    {
                        "ordinal": len(cells),
                        "cell_id": sha256(identity),
                        "case_id": question["case_id"],
                        "dependency_id": question["dependency_id"],
                        "slice": question["slice"],
                        "answer_datatype": question_datatype(question),
                        "condition": condition,
                        "trial": trial,
                        "request_sha256": sha256(compact(request)),
                    }
                )
                requests.append(request)
    if len(cells) != design["schedule"]["total_cells"]:
        raise RunStopped("V1.1 schedule size drifted")
    return cells, requests


def freeze(root: Path) -> JSON:
    """Write the deterministic schedule and a compact preflight manifest."""

    cells, requests = build_schedule(root)
    schedule = root / "data/experiments/schema-v1.1-schedule.jsonl"
    schedule.write_bytes(schedule_bytes(cells))
    design = load_json(root / "configs/experiments/schema-v1.1.json")
    tracked = {
        "design": root / "configs/experiments/schema-v1.1.json",
        "prompt": root / "prompts/schema-v1.1.txt",
        "questions": root / design["source_artifacts"]["questions"],
        "packets": root / design["source_artifacts"]["packets"],
    }
    maximum_request_bytes = max(len(compact(item).encode()) for item in requests)
    maximum_attempts = (
        len(requests) * design["retry_policy"]["maximum_attempts_per_cell"]
    )
    pricing = design["provider_intent"]["pricing"]
    cost_ceiling = (
        maximum_attempts
        * (
            maximum_request_bytes * pricing["input_per_million_usd"]
            + design["provider_intent"]["max_output_tokens"]
            * pricing["output_per_million_usd"]
        )
        / 1_000_000
    )
    if cost_ceiling > design["cost_cap_usd"]:
        raise RunStopped("V1.1 retry-inclusive reservation exceeds the cost cap")
    manifest: JSON = {
        "schema_version": "cti-schema-manifest-v1",
        "experiment_version": design["experiment_version"],
        "artifact_sha256": {
            name: artifact_hash(path) for name, path in tracked.items()
        },
        "schedule_sha256": sha256(schedule_bytes(cells)),
        "request_set_sha256": request_set_hash(requests),
        "request_count": len(requests),
        "maximum_request_utf8_bytes": maximum_request_bytes,
        "maximum_attempts": maximum_attempts,
        "retry_inclusive_cost_ceiling_usd": round(cost_ceiling, 6),
        "cost_cap_usd": design["cost_cap_usd"],
    }
    (root / "configs/experiments/schema-v1.1-manifest.json").write_text(
        canonical_json(manifest), encoding="utf-8", newline="\n"
    )
    return manifest


def validate_frozen(root: Path) -> JSON:
    cells, requests = build_schedule(root)
    schedule = load_jsonl(root / "data/experiments/schema-v1.1-schedule.jsonl")
    manifest = load_json(root / "configs/experiments/schema-v1.1-manifest.json")
    design = load_json(root / "configs/experiments/schema-v1.1.json")
    tracked = {
        "design": root / "configs/experiments/schema-v1.1.json",
        "prompt": root / "prompts/schema-v1.1.txt",
        "questions": root / design["source_artifacts"]["questions"],
        "packets": root / design["source_artifacts"]["packets"],
    }
    if {name: artifact_hash(path) for name, path in tracked.items()} != manifest[
        "artifact_sha256"
    ]:
        raise RunStopped("V1.1 source artifact hash drifted")
    if manifest["retry_inclusive_cost_ceiling_usd"] > design["cost_cap_usd"]:
        raise RunStopped("V1.1 cost ceiling exceeds the approved cap")
    if schedule_bytes(cells) != schedule_bytes(schedule):
        raise RunStopped("V1.1 schedule drifted")
    if sha256(schedule_bytes(cells)) != manifest["schedule_sha256"]:
        raise RunStopped("V1.1 schedule hash drifted")
    if request_set_hash(requests) != manifest["request_set_sha256"]:
        raise RunStopped("V1.1 request set drifted")
    return {"cells": len(cells), "request_set_sha256": request_set_hash(requests)}


def run(
    root: Path, ledger: Path, raw_directory: Path, maximum_cells: int | None = None
) -> None:
    """Run or resume the frozen schedule after explicit provider approval."""

    root = root.resolve()
    ledger = ledger.resolve()
    if ledger.is_relative_to(root) or any(
        "onedrive" in part.casefold() for part in ledger.parts
    ):
        raise RunStopped("provider ledger must be outside the repository and OneDrive")
    status = validate_frozen(root)
    design = load_json(root / "configs/experiments/schema-v1.1.json")
    cells, requests = build_schedule(root)
    run_schedule(
        cells,
        requests,
        make_openai_provider(raw_directory, root),
        ledger,
        artifact_hash(root / "configs/experiments/schema-v1.1-manifest.json"),
        design["provider_intent"]["model"],
        design["retry_policy"]["maximum_attempts_per_cell"],
        maximum_cells,
    )
    if status["cells"] != len(cells):
        raise RunStopped("validated cell count changed")


def _answer_type_valid(answer: object, datatype: str) -> bool:
    if answer is None:
        return True
    if datatype == "boolean":
        return isinstance(answer, bool)
    if datatype == "string":
        return isinstance(answer, str)
    if datatype == "string_set":
        return isinstance(answer, list) and all(
            isinstance(item, str) for item in answer
        )
    return False


def _same_answer(actual: object, expected: object, datatype: str) -> bool:
    if datatype == "string_set":
        left = [actual] if isinstance(actual, str) else actual
        right = [expected] if isinstance(expected, str) else expected
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and set(left) == set(right)
        )
    return type(actual) is type(expected) and actual == expected


def grade(question: JSON, bindings: list[JSON], response: object) -> JSON:
    """Grade contract, exact semantics, evidence, and abstention separately."""

    if not isinstance(response, dict) or set(response) != RESPONSE_KEYS:
        return {
            "parse_status": "invalid_shape",
            "typed_contract_valid": False,
            "semantic_answer_correct": False,
            "evidence_binding_correct": False,
            "abstention_reason_correct": False,
        }
    component = question["expected_components"][0]
    answer = response["answer"]
    reason = response["abstention_reason"]
    citations = response["citations"]
    typed = (
        response["schema_version"] == "cti-schema-v1.1-response"
        and response["case_id"] == question["case_id"]
        and _answer_type_valid(answer, component["datatype"])
        and (reason is None or reason in REASONS)
        and isinstance(citations, list)
        and all(isinstance(item, str) for item in citations)
        and ((answer is None) != (reason is None))
    )
    aliases = {
        evidence["evidence_id"]: evidence["span_alias"]
        for document in bindings
        for evidence in document["evidence"]
    }
    required = {aliases[item] for item in question["required_evidence_ids"]}
    allowed = set(aliases.values())
    evidence_correct = (
        isinstance(citations, list)
        and set(citations) <= allowed
        and required <= set(citations)
    )
    expected_abstention = question["outcome_type"] == "abstain"
    if expected_abstention:
        semantic: bool | None = answer is None
    elif _same_answer(answer, component["value"], component["datatype"]):
        semantic = True
    elif _answer_type_valid(answer, component["datatype"]):
        semantic = False
    else:
        semantic = None
    return {
        "parse_status": "valid" if typed else "invalid_type_or_relationship",
        "typed_contract_valid": typed,
        "semantic_answer_correct": semantic,
        "evidence_binding_correct": evidence_correct,
        "abstention_reason_correct": expected_abstention
        and reason == question["abstention_reason_code"],
    }


def publish_results(root: Path, ledger: Path) -> JSON:
    """Grade a complete ledger and write public outputs and metrics."""

    cells = load_jsonl(root / "data/experiments/schema-v1.1-schedule.jsonl")
    history = load_jsonl(ledger)
    header = {
        "record_type": "run_header",
        "manifest_sha256": artifact_hash(
            root / "configs/experiments/schema-v1.1-manifest.json"
        ),
    }
    if not history or history[0] != header:
        raise RunStopped("V1.1 ledger header does not match the frozen manifest")
    completed_rows = [row for row in history if row.get("status") == "completed"]
    completed = {row["cell_id"]: row["result"] for row in completed_rows}
    expected_ids = {cell["cell_id"] for cell in cells}
    if (
        len(completed_rows) != len(completed)
        or set(completed) != expected_ids
        or len(completed) != len(cells)
    ):
        raise RunStopped(
            f"V1.1 needs {len(cells)} completed cells; ledger has {len(completed)}"
        )
    questions_file = load_json(root / "data/benchmark/questions.json")
    packets_file = load_json(root / "data/benchmark/evidence-packets.json")
    questions = {item["case_id"]: item for item in questions_file["questions"]}
    packet_ids = {
        item["case_id"]: item["packet_id"] for item in packets_file["packets"]
    }
    decisions_path = root / "annotations/schema-v1.1-semantic-review.json"
    decisions = (
        load_json(decisions_path).get("decisions", {})
        if decisions_path.exists()
        else {}
    )
    if (
        not isinstance(decisions, dict)
        or not set(decisions) <= expected_ids
        or not all(isinstance(value, bool) for value in decisions.values())
    ):
        raise RunStopped("V1.1 semantic-review decisions are invalid")
    rows: list[JSON] = []
    for cell in cells:
        result = completed[cell["cell_id"]]
        if result.get("model") != "gpt-5.6-luna":
            raise RunStopped("V1.1 ledger contains an unexpected model")
        question = questions[cell["case_id"]]
        bindings = packets_file["evaluator_bindings"][packet_ids[cell["case_id"]]]
        scores = grade(question, bindings, result["output"])
        if scores["semantic_answer_correct"] is None:
            scores["semantic_answer_correct"] = decisions.get(cell["cell_id"])
        rows.append(
            {
                **cell,
                "model": result["model"],
                "latency_ms": result["latency_ms"],
                "usage": result["usage"],
                "output": result["output"],
                **scores,
            }
        )

    def metrics(items: list[JSON]) -> JSON:
        abstentions = [
            item
            for item in items
            if questions[item["case_id"]]["outcome_type"] == "abstain"
        ]
        total = len(items)
        correct = sum(item["semantic_answer_correct"] is True for item in items)
        return {
            "n": total,
            "semantic_correct": correct,
            "semantic_rate": correct / total,
            "semantic_unresolved": sum(
                item["semantic_answer_correct"] is None for item in items
            ),
            "typed_contract_valid": sum(
                item["typed_contract_valid"] is True for item in items
            ),
            "evidence_binding_correct": sum(
                item["evidence_binding_correct"] is True for item in items
            ),
            "abstention_reason_correct": sum(
                item["abstention_reason_correct"] is True for item in abstentions
            ),
            "expected_abstentions": len(abstentions),
        }

    grouped: dict[str, list[JSON]] = defaultdict(list)
    for row in rows:
        grouped[row["condition"]].append(row)
    design = load_json(root / "configs/experiments/schema-v1.1.json")
    pricing = design["provider_intent"]["pricing"]
    input_tokens = sum(row["usage"]["input_tokens"] for row in rows)
    cached_tokens = sum(row["usage"]["cached_input_tokens"] for row in rows)
    output_tokens = sum(row["usage"]["output_tokens"] for row in rows)
    estimated_cost = (
        (input_tokens - cached_tokens) * pricing["input_per_million_usd"]
        + cached_tokens * pricing["cached_input_per_million_usd"]
        + output_tokens * pricing["output_per_million_usd"]
    ) / 1_000_000
    summary: JSON = {
        "schema_version": "cti-schema-results-v1",
        "experiment_version": "schema-v1.1",
        "completed_cells": len(rows),
        "trials": len({row["trial"] for row in rows}),
        "by_condition": {
            name: metrics(items) for name, items in sorted(grouped.items())
        },
        "unresolved_semantic_reviews": sum(
            row["semantic_answer_correct"] is None for row in rows
        ),
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_tokens,
        "output_tokens": output_tokens,
        "estimated_cost_usd": round(estimated_cost, 6),
        "total_latency_ms": sum(row["latency_ms"] for row in rows),
    }
    (root / "reports/schema-v1.1-outputs.jsonl").write_text(
        "".join(f"{compact(row)}\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )
    (root / "reports/schema-v1.1-summary.json").write_text(
        canonical_json(summary), encoding="utf-8", newline="\n"
    )
    return summary
