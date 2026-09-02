"""Dataset integrity and deterministic metric recomputation."""

from __future__ import annotations

import json
import random
import re
import unicodedata
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any

JSON = dict[str, Any]
HEX64 = re.compile(r"[0-9a-f]{64}")


class IntegrityError(ValueError):
    """The checked artifact violates a frozen experiment invariant."""


def load_json(path: Path) -> JSON:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise IntegrityError(f"{path} must contain one JSON object")
    return value


def load_jsonl(path: Path) -> list[JSON]:
    records: list[JSON] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise IntegrityError(f"{path}:{number} must contain one JSON object")
        records.append(value)
    return records


def _utc(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise IntegrityError(f"{label} must be an ISO UTC timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise IntegrityError(f"{label} must be an ISO UTC timestamp") from error


def validate_benchmark(root: Path) -> JSON:
    corpus = load_json(root / "data/benchmark/questions.json")
    packets = load_json(root / "data/benchmark/evidence-packets.json")
    questions = corpus.get("questions")
    packet_rows = packets.get("packets")
    if corpus.get("schema_version") != "cti-question-corpus-v1":
        raise IntegrityError("unexpected question corpus schema")
    if packets.get("schema_version") != "cti-evidence-packets-v1":
        raise IntegrityError("unexpected evidence packet schema")
    if not isinstance(questions, list) or not isinstance(packet_rows, list):
        raise IntegrityError("questions and packets must be lists")

    case_ids: set[str] = set()
    evidence_ids: set[str] = set()
    dependencies: dict[str, set[str]] = defaultdict(set)
    temporal_dependencies: set[str] = set()
    for question in questions:
        if not isinstance(question, dict):
            raise IntegrityError("each question must be an object")
        case_id = question.get("case_id")
        split = question.get("split")
        dependency = question.get("dependency_id")
        if not isinstance(case_id, str) or case_id in case_ids:
            raise IntegrityError("case IDs must be present and unique")
        if split not in {"dev", "validation"} or not isinstance(dependency, str):
            raise IntegrityError(f"{case_id} has invalid split metadata")
        _utc(question.get("cutoff_utc"), f"{case_id}.cutoff_utc")
        case_ids.add(case_id)
        dependencies[split].add(dependency)
        if question.get("slice") == "temporal_comparison":
            temporal_dependencies.add(dependency)
        question_evidence: set[str] = set()
        for evidence in question.get("evidence", []):
            if not isinstance(evidence, dict):
                raise IntegrityError(f"{case_id} has invalid evidence")
            evidence_id = evidence.get("evidence_id")
            if not isinstance(evidence_id, str) or evidence_id in evidence_ids:
                raise IntegrityError("evidence IDs must be present and unique")
            for key in ("source_sha256", "text_sha256"):
                value = evidence.get(key)
                if not isinstance(value, str) or HEX64.fullmatch(value) is None:
                    raise IntegrityError(f"{evidence_id}.{key} must be SHA-256")
            _utc(evidence.get("source_available_by_utc"), evidence_id)
            evidence_ids.add(evidence_id)
            question_evidence.add(evidence_id)
        referenced = set(question.get("required_evidence_ids", []))
        for component in question.get("expected_components", []):
            if not isinstance(component, dict):
                raise IntegrityError(f"{case_id} has an invalid expected component")
            referenced.update(component.get("required_evidence_ids", []))
        if not referenced <= question_evidence:
            raise IntegrityError(f"{case_id} references unknown evidence")
    if dependencies["dev"] & dependencies["validation"]:
        raise IntegrityError("dependency clusters cross dataset splits")

    packet_cases = {row.get("case_id") for row in packet_rows if isinstance(row, dict)}
    packet_ids = {row.get("packet_id") for row in packet_rows if isinstance(row, dict)}
    if packet_cases != case_ids:
        raise IntegrityError("packet cases do not match question cases")
    if packet_ids != {f"packet-{case_id}" for case_id in case_ids}:
        raise IntegrityError("packet IDs do not match case IDs")
    return {
        "questions": len(case_ids),
        "dependencies": len(dependencies["dev"] | dependencies["validation"]),
        "temporal_questions": sum(
            question.get("slice") == "temporal_comparison" for question in questions
        ),
        "temporal_dependencies": len(temporal_dependencies),
    }


def _metric_row(records: list[JSON]) -> JSON:
    def count_true(key: str) -> int:
        return sum(record.get(key) is True for record in records)

    total = len(records)
    provenance = count_true("evidence_binding_correct")
    exact = count_true("exact_answer_correct")
    component_tp = sum(int(record.get("component_tp", 0)) for record in records)
    component_fp = sum(int(record.get("component_fp", 0)) for record in records)
    component_fn = sum(int(record.get("component_fn", 0)) for record in records)
    precision_denominator = component_tp + component_fp
    recall_denominator = component_tp + component_fn
    return {
        "component_fn": component_fn,
        "component_fp": component_fp,
        "component_precision": (
            component_tp / precision_denominator if precision_denominator else None
        ),
        "component_recall": (
            component_tp / recall_denominator if recall_denominator else None
        ),
        "component_tp": component_tp,
        "correct_abstentions": count_true("correct_abstention"),
        "exact_correct": exact,
        "exact_rate": exact / total if total else None,
        "expected_abstentions": count_true("expected_abstention"),
        "n": total,
        "parse_failures": sum(
            record.get("parse_status") != "valid" for record in records
        ),
        "provenance_correct": provenance,
        "provenance_rate": provenance / total if total else None,
        "refusals": sum(record.get("result_kind") == "refusal" for record in records),
    }


def _grouped(cells: list[JSON], primary: str, secondary: str | None = None) -> JSON:
    groups: dict[str, list[JSON]] = defaultdict(list)
    if secondary is None:
        for cell in cells:
            groups[str(cell[primary])].append(cell)
        return {name: _metric_row(records) for name, records in sorted(groups.items())}
    nested: dict[str, dict[str, list[JSON]]] = defaultdict(lambda: defaultdict(list))
    for cell in cells:
        nested[str(cell[primary])][str(cell[secondary])].append(cell)
    return {
        name: {
            child: _metric_row(records) for child, records in sorted(children.items())
        }
        for name, children in sorted(nested.items())
    }


def recompute_v1(root: Path) -> JSON:
    cells = load_jsonl(root / "reports/evaluation-cells.jsonl")
    summary = load_json(root / "reports/evaluation-summary.json")
    corpus = load_json(root / "data/benchmark/questions.json")
    case_ids = {question.get("case_id") for question in corpus["questions"]}
    ordinals = [cell.get("ordinal") for cell in cells]
    if ordinals != list(range(len(cells))):
        raise IntegrityError("v1 result ordinals must be ordered and complete")
    if len({cell.get("cell_id") for cell in cells}) != len(cells):
        raise IntegrityError("v1 result cell IDs must be unique")
    if not {cell.get("case_id") for cell in cells} <= case_ids:
        raise IntegrityError("v1 results reference an unknown case")
    computed = {
        "by_condition": _grouped(cells, "condition"),
        "by_slice": _grouped(cells, "slice", "condition"),
        "by_variant": _grouped(cells, "variant", "condition"),
        "dependency_clusters": len({cell.get("dependency_id") for cell in cells}),
    }
    for key, value in computed.items():
        if summary.get(key) != value:
            raise IntegrityError(f"v1 {key} does not recompute from public cells")
    if summary.get("scheduled_cells") != len(cells):
        raise IntegrityError("v1 scheduled cell count does not match public cells")
    return computed


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def build_temporal_rubric(root: Path) -> JSON:
    corpus = load_json(root / "data/benchmark/questions.json")
    cases: JSON = {}
    for question in corpus["questions"]:
        if question["slice"] != "temporal_comparison":
            continue
        reference = question["readable_reference_answer"].split(
            " Structured component coverage:", 1
        )[0]
        cases[question["case_id"]] = {
            "accepted_final_answers": [reference],
            "required_components": [
                {
                    "kind": component["kind"],
                    "datatype": component["datatype"],
                    "value": component["value"],
                }
                for component in question["expected_components"]
            ],
            "forbidden_contradictions": [
                "old/new swap",
                "wrong change direction",
                "missing required identifier, version, member, or boundary",
                "unsupported material claim",
            ],
        }
    return {
        "schema_version": "cti-temporal-semantic-rubric-v2",
        "automatic_rule": (
            "Full-answer equality after Unicode, case, punctuation, and whitespace "
            "normalization against an accepted answer; no substring or fuzzy match."
        ),
        "review_rule": (
            "A blinded reviewer checks all required components and rejects any "
            "listed material contradiction."
        ),
        "cases": cases,
    }


def _text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(re.findall(r"[\w]+", normalized))


def _typed(value: object, datatype: str) -> object:
    if datatype == "string":
        return _text(value) if isinstance(value, str) else None
    if datatype == "string_set":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = [value]
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            return None
        return tuple(sorted({_text(item) for item in value}))
    if datatype == "mapping":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return None
        if not isinstance(value, dict):
            return None
        return tuple(
            sorted(
                (str(key), _typed(child, "string") if isinstance(child, str) else child)
                for key, child in value.items()
            )
        )
    return None


def _canonical_component(value: object, expected: object, datatype: str) -> bool:
    if datatype == "string":
        return isinstance(value, str) and value == expected
    if datatype == "string_set":
        return value == expected
    if datatype == "mapping":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return False
        return value == expected
    return False


def _aliases(evaluator_documents: list[JSON]) -> dict[str, str]:
    return {
        evidence["evidence_id"]: evidence["span_alias"]
        for document in evaluator_documents
        for evidence in document["evidence"]
    }


def grade_temporal(
    question: JSON,
    evaluator_documents: list[JSON],
    response: object,
    method: str,
    rubric_case: JSON,
    review_decision: bool | None = None,
    component_reviews: dict[str, bool] | None = None,
    oracle: bool = False,
) -> JSON:
    common = {"final_answer", "citations"}
    state_fields = {
        "old_state",
        "old_state_citations",
        "new_state",
        "new_state_citations",
        "change",
        "change_citations",
    }
    required = common | (
        state_fields if method == "state_first" and not oracle else set()
    )
    if oracle:
        required |= {"change", "change_citations"}
    if not isinstance(response, dict) or set(response) != required:
        return {
            "parse_status": "invalid_shape",
            "semantic_correct": False,
            "review_required": False,
            "canonical_correct": False,
            "evidence_correct": False,
        }
    list_fields = {name for name in required if "citations" in name}
    if not all(
        isinstance(response[name], list)
        and all(isinstance(item, str) for item in response[name])
        for name in list_fields
    ) or not all(isinstance(response[name], str) for name in required - list_fields):
        return {
            "parse_status": "invalid_type",
            "semantic_correct": False,
            "review_required": False,
            "canonical_correct": False,
            "evidence_correct": False,
        }

    alias_by_evidence = _aliases(evaluator_documents)
    allowed_aliases = set(alias_by_evidence.values())
    required_aliases = {
        alias_by_evidence[evidence_id]
        for evidence_id in question["required_evidence_ids"]
    }
    citations = set(response["citations"])
    evidence_correct = citations <= allowed_aliases and required_aliases <= citations
    accepted = rubric_case["accepted_final_answers"]
    final_answer = response["final_answer"]
    automatic = any(_text(final_answer) == _text(candidate) for candidate in accepted)
    semantic = True if automatic else review_decision
    result: JSON = {
        "parse_status": "valid",
        "semantic_correct": semantic,
        "review_required": semantic is None,
        "canonical_correct": final_answer == accepted[0],
        "evidence_correct": evidence_correct,
        "old_state_correct": None,
        "new_state_correct": None,
        "change_correct": None,
    }
    component_reviews = component_reviews or {}
    components = {item["kind"]: item for item in question["expected_components"]}

    def grade_component(field: str, kind: str) -> None:
        component = components[kind]
        canonical = _canonical_component(
            response[field], component["value"], component["datatype"]
        )
        automatic_component = _typed(response[field], component["datatype"]) == _typed(
            component["value"], component["datatype"]
        )
        semantic_component = (
            True if automatic_component else component_reviews.get(kind)
        )
        result[f"{field}_canonical_correct"] = canonical
        result[f"{field}_semantic_correct"] = semantic_component
        result[f"{field}_review_required"] = semantic_component is None
        result[f"{field}_correct"] = semantic_component

    if method == "state_first" and not oracle:
        for field, kind in (("old_state", "old_value"), ("new_state", "new_value")):
            component = components[kind]
            grade_component(field, kind)
            aliases = {
                alias_by_evidence[evidence_id]
                for evidence_id in component["required_evidence_ids"]
            }
            field_citations = set(response[f"{field}_citations"])
            evidence_correct &= (
                field_citations <= allowed_aliases and aliases <= field_citations
            )
    if method == "state_first" or oracle:
        delta = components["delta_kind"]
        grade_component("change", "delta_kind")
        delta_aliases = {
            alias_by_evidence[evidence_id]
            for evidence_id in delta["required_evidence_ids"]
        }
        change_citations = set(response["change_citations"])
        evidence_correct &= (
            change_citations <= allowed_aliases and delta_aliases <= change_citations
        )
    result["evidence_correct"] = evidence_correct
    return result


def grade_temporal_text(*args: object, **kwargs: object) -> JSON:
    raw = args[2] if len(args) > 2 else kwargs.get("response")
    if not isinstance(raw, str):
        return grade_temporal(*args, **kwargs)  # type: ignore[arg-type]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    positional = list(args)
    if len(positional) > 2:
        positional[2] = parsed
        return grade_temporal(*positional, **kwargs)  # type: ignore[arg-type]
    kwargs["response"] = parsed
    return grade_temporal(**kwargs)  # type: ignore[arg-type]


def analyze_factorial(
    schedule: list[JSON],
    outcomes: list[JSON],
    draws: int = 10_000,
    seed: int = 20260901,
) -> JSON:
    schedule_ids = [row.get("cell_id") for row in schedule]
    if len(schedule) != 520 or len(set(schedule_ids)) != len(schedule_ids):
        raise IntegrityError("the frozen schedule must contain 520 unique cells")
    factorial = [row for row in schedule if row.get("kind") == "factorial"]
    oracle = [row for row in schedule if row.get("kind") == "oracle"]
    if len(factorial) != 480 or len(oracle) != 40:
        raise IntegrityError("the frozen schedule must contain 480 factorial cells")
    if {row.get("condition") for row in factorial} != set("ABCD"):
        raise IntegrityError("factorial conditions must be A through D")
    if {row.get("trial") for row in factorial} != set(range(1, 6)):
        raise IntegrityError("factorial trials must be 1 through 5")
    if len({row.get("case_id") for row in factorial}) != 24:
        raise IntegrityError("factorial schedule must contain 24 cases")
    if len({row.get("dependency_id") for row in factorial}) != 19:
        raise IntegrityError("factorial schedule must contain 19 clusters")
    expected_keys = {
        (row["case_id"], row["condition"], row["trial"]) for row in factorial
    }
    if len(expected_keys) != 480:
        raise IntegrityError("factorial case-condition-trial keys must be unique")

    known_ids = set(schedule_ids)
    outcome_ids = [row.get("cell_id") for row in outcomes]
    if len(set(outcome_ids)) != len(outcome_ids):
        raise IntegrityError("outcomes contain duplicate cell IDs")
    if not set(outcome_ids) <= known_ids:
        raise IntegrityError("outcomes reference cells outside the frozen schedule")
    outcome_by_id = {row["cell_id"]: row for row in outcomes}
    by_case: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    reliability: JSON = {}
    for cell in factorial:
        record = outcome_by_id.get(cell["cell_id"], {})
        key = (cell["dependency_id"], cell["case_id"], cell["condition"])
        by_case[key].append(int(record.get("semantic_correct") is True))
    cluster_values: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for (dependency, case_id, condition), values in by_case.items():
        scores = [int(value) for value in values]
        cluster_values[dependency][condition].append(mean(scores))
        reliability[f"{case_id}:{condition}"] = {
            "trials": scores,
            "pass_count": sum(scores),
            "pass^5": len(scores) == 5 and all(scores),
        }
    clusters = {
        dependency: {
            condition: mean(values) for condition, values in conditions.items()
        }
        for dependency, conditions in cluster_values.items()
    }
    dependencies = sorted(clusters)

    def rates(sample: list[str]) -> dict[str, float]:
        return {
            condition: mean(clusters[dependency][condition] for dependency in sample)
            for condition in "ABCD"
        }

    def effects(values: dict[str, float]) -> dict[str, float]:
        return {
            "decomposition": 0.5
            * ((values["C"] - values["A"]) + (values["D"] - values["B"])),
            "schema": 0.5 * ((values["B"] - values["A"]) + (values["D"] - values["C"])),
            "interaction": (values["D"] - values["C"]) - (values["B"] - values["A"]),
        }

    observed_rates = rates(dependencies)
    observed_effects = effects(observed_rates)
    rng = random.Random(seed)
    samples: dict[str, list[float]] = {name: [] for name in observed_effects}
    for _ in range(draws):
        sampled = rng.choices(dependencies, k=len(dependencies))
        for name, value in effects(rates(sampled)).items():
            samples[name].append(value)
    intervals = {
        name: [sorted(values)[int((draws - 1) * point)] for point in (0.025, 0.975)]
        for name, values in samples.items()
    }
    return {
        "cluster_count": len(dependencies),
        "condition_rates": observed_rates,
        "effects": observed_effects,
        "bootstrap_intervals": intervals,
        "reliability": reliability,
    }
