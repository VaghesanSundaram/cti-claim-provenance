"""Dataset integrity and deterministic metric recomputation."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
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
