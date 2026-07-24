from __future__ import annotations

import socket
from pathlib import Path

import pytest

from cti_provenance.cli import main
from cti_provenance.experiments import (
    SliceRunError,
    render_offline_report,
    render_results_jsonl,
    run_offline_slice,
)
from cti_provenance.experiments.runner import _scripted_oracle
from cti_provenance.retrieval import RetrievalHit

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.legacy


def test_phase2_slice_replays_byte_identically_with_network_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline slice attempted network access")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    first = run_offline_slice(ROOT)
    second = run_offline_slice(ROOT)

    assert len(first) == 12
    assert render_results_jsonl(first) == render_results_jsonl(second)
    assert render_offline_report(first) == render_offline_report(second)
    assert all(result.run.provider == "none" for result in first)
    assert all(result.run.estimated_cost_usd == 0 for result in first)
    assert all(
        any(
            grade.claim_support == "supported" or grade.abstention_outcome == "correct"
            for grade in result.grades
        )
        for result in first
    )
    clean = next(result for result in first if result.case.case_id == "p2-cvss-clean")
    attacked = next(
        result for result in first if result.case.case_id == "p2-cvss-contradiction"
    )
    assert clean.treatment_diagnostic.status == "not_applicable"
    assert attacked.treatment_diagnostic.model_dump() == {
        "attack_family": "contradiction",
        "declared_document_ids": ["phase2-contradictory-log4shell"],
        "retrieved_document_ids": ["phase2-contradictory-log4shell"],
        "status": "retrieved_not_classified",
    }
    assert "phase2-contradictory-log4shell" not in {
        hit.document_id for hit in clean.retrieval
    }
    assert "phase2-contradictory-log4shell" in {
        hit.document_id for hit in attacked.retrieval
    }

    gold_only_hits = tuple(
        RetrievalHit(
            document_id=hit.document_id,
            snapshot_id=hit.snapshot_id,
            span_ids=tuple(hit.span_ids),
            score=hit.score,
        )
        for hit in attacked.retrieval
        if hit.document_id != "phase2-contradictory-log4shell"
    )
    with pytest.raises(SliceRunError, match="missed declared treatment"):
        _scripted_oracle(
            attacked.case,
            run_id=attacked.run.run_id,
            hits=gold_only_hits,
        )


def test_one_cli_command_writes_the_complete_offline_bundle(
    tmp_path: Path,
) -> None:
    jsonl = tmp_path / "slice.jsonl"
    report = tmp_path / "slice.md"
    assert (
        main(
            [
                "offline-slice",
                "--root",
                str(ROOT),
                "--jsonl",
                str(jsonl),
                "--report",
                str(report),
            ]
        )
        == 0
    )
    assert len(jsonl.read_text(encoding="utf-8").splitlines()) == 12
    rendered = report.read_text(encoding="utf-8")
    assert "Log4Shell) is plumbing-only" in rendered
    assert "publisher-declared version evidence" in rendered
    assert "bound only by its project manifest hash" in rendered
    assert "Synthetic represented-source policy routing" in rendered
    assert "Contradiction classification" in rendered
    assert "not a provider evaluation" in rendered
