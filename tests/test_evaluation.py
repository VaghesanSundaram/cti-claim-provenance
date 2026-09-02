from __future__ import annotations

import json
from pathlib import Path

import pytest

from cti_provenance.cli import main
from cti_provenance.evaluation import (
    IntegrityError,
    recompute_v1,
    validate_benchmark,
)
from cti_provenance.published import recompute_v2

ROOT = Path(__file__).resolve().parents[1]


def test_public_benchmark_and_v1_metrics_recompute() -> None:
    counts = validate_benchmark(ROOT)
    assert counts == {
        "questions": 64,
        "dependencies": 24,
        "temporal_questions": 24,
        "temporal_dependencies": 19,
    }
    assert (
        recompute_v1(ROOT)["by_condition"]
        == json.loads(
            (ROOT / "reports/evaluation-summary.json").read_text(encoding="utf-8")
        )["by_condition"]
    )
    assert main(["validate", "--root", str(ROOT)]) == 0


def test_public_v2_metrics_recompute() -> None:
    result = recompute_v2(ROOT)
    assert result["cells"] == 520
    assert result["semantic_correct"] == 484
    assert result["parse_failures"] == 4
    assert result["oracle_semantic_correct"] == 40
    assert result["factorial_analysis"]["effects"]["decomposition"] == pytest.approx(
        -0.010526315789473717
    )


def test_duplicate_case_id_fails_closed(tmp_path: Path) -> None:
    target = tmp_path / "data/benchmark"
    target.mkdir(parents=True)
    for name in ("questions.json", "evidence-packets.json"):
        source = ROOT / "data/benchmark" / name
        (target / name).write_bytes(source.read_bytes())
    corpus_path = target / "questions.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    corpus["questions"][1]["case_id"] = corpus["questions"][0]["case_id"]
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    with pytest.raises(IntegrityError, match="case IDs"):
        validate_benchmark(tmp_path)
