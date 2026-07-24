from pathlib import Path

from cti_provenance.experiments.portfolio_diverse_public_results import (
    verify_public_results,
)

ROOT = Path(__file__).resolve().parents[2]


def test_tracked_public_result_projection_reproduces_aggregate() -> None:
    result = verify_public_results(ROOT)
    assert result["cell_count"] == 192
    assert result["accounted_cost_usd"] == "0.660676"
