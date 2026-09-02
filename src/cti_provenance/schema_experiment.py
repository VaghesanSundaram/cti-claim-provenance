"""Question-specific schema replication for the V1 extraction and abstention slices."""

from __future__ import annotations

import random
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
DESIGN = Path("configs/experiments/schema-v1.1.json")
MANIFEST = Path("configs/experiments/schema-v1.1-manifest.json")
SCHEDULE = Path("data/experiments/schema-v1.1-schedule.jsonl")
PROMPT = Path("prompts/schema-v1.1.txt")
DATATYPES: dict[str, tuple[str, JSON]] = {
    "boolean": ("boolean", {"type": "boolean"}),
    "string": ("string", {"type": "string"}),
    "set": ("string_set", {"type": "array", "items": {"type": "string"}}),
}


def _datatype(question: JSON) -> tuple[str, JSON]:
    try:
        return DATATYPES[str(question["answer_type"])]
    except KeyError as error:
        raise RunStopped("unsupported V1.1 answer type") from error


def response_schema(question: JSON) -> JSON:
    """Build a strict schema from public task metadata, never the gold answer."""

    _, answer_schema = _datatype(question)
    return {
        "type": "object",
        "properties": {
            "schema_version": {"type": "string", "const": "cti-schema-v1.1-response"},
            "case_id": {"type": "string", "const": question["case_id"]},
            "answer": {"anyOf": [answer_schema, {"type": "null"}]},
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
        "answer_datatype": _datatype(question)[0],
        "allowed_abstention_reasons": REASONS,
        "cutoff_utc": packet["cutoff_utc"],
        "documents": packet["documents"],
    }


def build_request(root: Path, condition: str, question: JSON, packet: JSON) -> JSON:
    design = load_json(root / DESIGN)
    provider = design["provider_intent"]
    prompt = (root / PROMPT).read_text(encoding="utf-8")
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
    design = load_json(root / DESIGN)
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
                        "answer_datatype": _datatype(question)[0],
                        "condition": condition,
                        "trial": trial,
                        "request_sha256": sha256(compact(request)),
                    }
                )
                requests.append(request)
    if len(cells) != design["schedule"]["total_cells"]:
        raise RunStopped("V1.1 schedule size drifted")
    return cells, requests


def _frozen(root: Path) -> tuple[list[JSON], list[JSON], JSON]:
    cells, requests = build_schedule(root)
    design = load_json(root / DESIGN)
    tracked = {
        "design": root / DESIGN,
        "prompt": root / PROMPT,
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
    if cost_ceiling > design["cost_cap_usd"]:
        raise RunStopped("V1.1 retry-inclusive reservation exceeds the cost cap")
    return cells, requests, manifest


def freeze(root: Path) -> JSON:
    """Write the deterministic schedule and compact preflight manifest."""

    cells, _, manifest = _frozen(root)
    (root / SCHEDULE).write_bytes(schedule_bytes(cells))
    (root / MANIFEST).write_text(
        canonical_json(manifest), encoding="utf-8", newline="\n"
    )
    return manifest


def validate_frozen(root: Path) -> JSON:
    cells, requests, expected_manifest = _frozen(root)
    schedule = load_jsonl(root / SCHEDULE)
    if load_json(root / MANIFEST) != expected_manifest:
        raise RunStopped("V1.1 manifest drifted")
    if schedule_bytes(cells) != schedule_bytes(schedule):
        raise RunStopped("V1.1 schedule drifted")
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
    validate_frozen(root)
    design = load_json(root / DESIGN)
    cells, requests = build_schedule(root)
    run_schedule(
        cells,
        requests,
        make_openai_provider(raw_directory, root),
        ledger,
        artifact_hash(root / MANIFEST),
        design["provider_intent"]["model"],
        design["retry_policy"]["maximum_attempts_per_cell"],
        maximum_cells,
    )


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
