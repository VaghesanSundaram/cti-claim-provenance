"""Safe public projection and verifier for the completed V6 evaluation."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path

from .portfolio_diverse_execution import (
    PortfolioProviderResult,
    summarize_provider_results,
)

PUBLIC_RESULTS_PATH = Path("reports/portfolio-diverse-model-evaluation-v1-cells.jsonl")
_FIELDS = (
    "schema_version",
    "run_id",
    "slot_id",
    "ordinal",
    "case_id",
    "dependency_id",
    "case_slice",
    "split",
    "variant",
    "condition",
    "attempt_count",
    "result_kind",
    "provider_model",
    "provider_service_tier",
    "http_status",
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_tokens",
    "latency_ms",
    "accounted_cost_usd",
    "parse_status",
    "provenance_outcome_correct",
    "exact_outcome_correct",
    "component_tp",
    "component_fp",
    "component_fn",
    "expected_abstention",
    "correct_abstention",
    "emitted_claim_count",
    "output_text_sha256",
    "response_body_sha256",
    "request_semantic_sha256",
    "completed_at_utc",
)


def render_public_results(results: tuple[PortfolioProviderResult, ...]) -> str:
    """Render IDs, grades, accounting, and integrity hashes without provider text."""
    if len(results) != 192 or {row.ordinal for row in results} != set(range(192)):
        raise ValueError("public results require exactly the 192 scheduled ordinals")
    lines = []
    for row in sorted(results, key=lambda item: item.ordinal):
        payload = row.model_dump(mode="json")
        lines.append(
            json.dumps(
                {name: payload[name] for name in _FIELDS},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    return "\n".join(lines) + "\n"


def verify_public_results(root: Path) -> dict[str, object]:
    """Recompute the aggregate without requiring provider output or source bodies."""
    path = root / PUBLIC_RESULTS_PATH
    rows = tuple(
        PortfolioProviderResult.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    )
    if path.read_text(encoding="utf-8") != render_public_results(rows):
        raise ValueError("public result projection is not canonical")
    aggregate = json.loads(
        (root / "reports/portfolio-diverse-model-evaluation-v1.json").read_text(
            encoding="utf-8"
        )
    )
    aggregate_without_digest = dict(aggregate)
    aggregate_without_digest.pop("summary_sha256", None)
    if summarize_provider_results(rows) != aggregate_without_digest:
        raise ValueError("public result projection does not reproduce aggregate report")
    return {
        "cell_count": len(rows),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "accounted_cost_usd": str(
            sum((row.accounted_cost_usd for row in rows), Decimal("0"))
        ),
    }
