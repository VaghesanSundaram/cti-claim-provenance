"""Run and report the exact reviewed V6 Luna schedule."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cti_provenance.claims.diverse_portfolio_v4 import canonical_sha256
from cti_provenance.experiments.portfolio_diverse_execution import (
    run_frozen_portfolio_experiment,
    summarize_provider_results,
)

ROOT = Path(__file__).resolve().parents[1]
REPORT_JSON = ROOT / "reports/portfolio-diverse-model-evaluation-v1.json"
REPORT_MD = ROOT / "reports/portfolio-diverse-model-evaluation-v1.md"


def _api_key() -> str:
    value = os.environ.get("OPENAI_API_KEY")
    if value:
        return value
    env_path = ROOT / ".env"
    if not env_path.exists():
        raise ValueError("OPENAI_API_KEY is unavailable")
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, candidate = line.split("=", 1)
        if name.strip() == "OPENAI_API_KEY":
            value = candidate.strip().strip("\"'")
            if value:
                return value
    raise ValueError("OPENAI_API_KEY is unavailable")


def _render(summary: dict[str, object]) -> str:
    conditions = summary["by_condition"]
    assert isinstance(conditions, dict)
    citation = conditions["citation_prompted"]
    constrained = conditions["claim_evidence_constrained"]
    assert isinstance(citation, dict) and isinstance(constrained, dict)
    variants = summary["by_variant"]
    assert isinstance(variants, dict)
    return "\n".join(
        [
            "# CTI diverse portfolio model evaluation v1",
            "",
            "- Model: "
            + ", ".join(
                f"`{name}` ({count} cells)"
                for name, count in dict(summary["returned_models"]).items()
            ),
            "- Design: 64 semantic questions, 24 dependency clusters, 192 "
            "single-sample cells; citation-prompted versus claim-evidence-"
            "constrained bundled pipeline variants.",
            f"- Citation-prompted provenance outcomes: "
            f"{citation['provenance_correct']}/{citation['n']} "
            f"({citation['provenance_rate']:.3f}); strict semantic exact "
            f"{citation['exact_correct']}/{citation['n']} "
            f"({citation['exact_rate']:.3f}).",
            f"- Constrained provenance outcomes: "
            f"{constrained['provenance_correct']}/{constrained['n']} "
            f"({constrained['provenance_rate']:.3f}); strict semantic exact "
            f"{constrained['exact_correct']}/{constrained['n']} "
            f"({constrained['exact_rate']:.3f}).",
            f"- Paired provenance delta (constrained minus citation): "
            f"{summary['paired_provenance_delta_mean']:.3f}; "
            f"dependency-family macro "
            f"delta: {summary['dependency_family_macro_delta']:.3f}.",
            f"- Paired outcomes: {summary['paired_wins']} wins / "
            f"{summary['paired_ties']} ties / {summary['paired_losses']} losses.",
            f"- Accounted provider cost: `${summary['accounted_cost_usd']}`; "
            f"tokens: {summary['input_tokens']} input, "
            f"{summary['output_tokens']} output.",
            "",
            "## Packet variants",
            "",
            *[
                f"- {variant}: citation provenance "
                f"{values['citation_prompted']['provenance_correct']}/"
                f"{values['citation_prompted']['n']}; constrained "
                f"{values['claim_evidence_constrained']['provenance_correct']}/"
                f"{values['claim_evidence_constrained']['n']}."
                for variant, values in variants.items()
            ],
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in summary["limitations"]],
            "",
            "These are descriptive, single-sample results. They do not establish "
            "statistical significance, run-to-run stability, broad CTI "
            "generalization, or causal attribution to schema enforcement alone.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--redacted-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    args = parser.parse_args()
    results = run_frozen_portfolio_experiment(
        root=ROOT,
        api_key=_api_key(),
        redacted_root=args.redacted_root,
        private_root=args.private_root,
    )
    summary = summarize_provider_results(results)
    summary["summary_sha256"] = canonical_sha256(summary)
    REPORT_JSON.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    REPORT_MD.write_text(_render(summary), encoding="utf-8", newline="\n")
    print(
        f"{len(results)} cells; ${summary['accounted_cost_usd']}; "
        f"summary {summary['summary_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
