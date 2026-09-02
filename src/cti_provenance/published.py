"""Recomputation of published result artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cti_provenance.evaluation import (
    HEX64,
    JSON,
    IntegrityError,
    analyze_factorial,
    load_json,
    load_jsonl,
)


def validate_v1_outputs(root: Path) -> JSON:
    """Validate sanitized V1 outputs against the published result cells."""
    cells = load_jsonl(root / "reports/evaluation-cells.jsonl")
    outputs = load_jsonl(root / "reports/evaluation-outputs.jsonl")
    if len(outputs) != len(cells):
        raise IntegrityError("v1 output count does not match public cells")
    outputs_by_cell = {row.get("cell_id"): row for row in outputs}
    if len(outputs_by_cell) != len(outputs):
        raise IntegrityError("v1 output cell IDs must be unique")
    for cell in cells:
        output = outputs_by_cell.get(cell["cell_id"])
        if output is None or any(
            output.get(field) != cell.get(field)
            for field in ("ordinal", "case_id", "condition", "variant")
        ):
            raise IntegrityError("v1 output metadata does not match public cells")
        provider_output = output.get("output")
        if not isinstance(provider_output, dict) or (
            provider_output.get("case_id") != cell.get("case_id")
        ):
            raise IntegrityError("v1 output payload does not match its public case")
        source_hash = output.get("source_output_sha256")
        if not isinstance(source_hash, str) or HEX64.fullmatch(source_hash) is None:
            raise IntegrityError("v1 output source hash must be SHA-256")
    return {"outputs": len(outputs)}


def recompute_v2(root: Path) -> JSON:
    """Recompute the temporal-v2 result from public cell outcomes."""
    schedule = load_jsonl(root / "data/experiments/temporal-v2-schedule.jsonl")
    cells_path = root / "reports/temporal-v2-cells.jsonl"
    cell_text = cells_path.read_text(encoding="utf-8")
    cells = load_jsonl(cells_path)
    summary = load_json(root / "reports/temporal-v2-summary.json")
    schedule_ids = {row["cell_id"] for row in schedule}
    cell_ids = {row["cell_id"] for row in cells}
    if len(cells) != 520 or cell_ids != schedule_ids:
        raise IntegrityError("published v2 outcomes must cover every frozen cell once")
    digest = hashlib.sha256(cell_text.encode("utf-8")).hexdigest()
    if summary.get("result_set_sha256") != digest:
        raise IntegrityError("published v2 result-set hash does not match")
    analysis = analyze_factorial(schedule, cells)
    if summary.get("factorial_analysis") != analysis:
        raise IntegrityError("published v2 factorial analysis does not recompute")
    return {
        "cells": len(cells),
        "result_set_sha256": digest,
        "semantic_correct": sum(row.get("semantic_correct") is True for row in cells),
        "parse_failures": sum(row.get("parse_status") != "valid" for row in cells),
        "oracle_semantic_correct": sum(
            row.get("kind") == "oracle" and row.get("semantic_correct") is True
            for row in cells
        ),
        "factorial_analysis": analysis,
    }
