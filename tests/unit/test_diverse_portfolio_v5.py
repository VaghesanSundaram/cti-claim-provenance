"""Fail-first contracts for the additive diverse portfolio V5 repair."""

# Frozen hashes and reviewer-visible strings are intentionally kept whole.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from cti_provenance.claims.diverse_portfolio_v5 import (
    DiverseCorpusV5,
    PacketIndexV5,
    ReviewPacketV5,
    reference_component_marker,
    validate_reference_answer,
)
from cti_provenance.cli import main

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "data/benchmark/portfolio-diverse-draft-v5.json"
REVIEW = ROOT / "annotations/packets/portfolio-diverse-review-v5.json"
ACCEPTANCE = (
    ROOT / "annotations/packets/portfolio-diverse-review-v5-manager-acceptance.json"
)
INDEX = ROOT / "data/benchmark/portfolio-diverse-packets-v5.json"
LINEAGE = ROOT / "data/benchmark/portfolio-diverse-v4-to-v5.json"
REPORT = ROOT / "reports/portfolio-diverse-corpus-audit-v5.json"
V4_HASHES = {
    "data/benchmark/portfolio-diverse-draft-v4.json": "5a9ff2d5482c11ff2c6fcffe6c9a4fd4f8cfc365452f4f0d3b17721fde673b14",
    "annotations/packets/portfolio-diverse-review-v4.json": "5f4e68071e8a0ebf3185722a081fac735c6496abac97e4406537ccdec28994b9",
    "data/benchmark/portfolio-diverse-packets-v4.json": "12bf268e7bc00975ed715b5614bd36af2dcd8c37b54da3c49a3f7581ad8108a1",
    "data/benchmark/portfolio-diverse-v3-to-v4.json": "9a1f73e5f76b59ea3e7534a252be7ca9a3363389f2151f4743685e314e249d94",
    "reports/portfolio-diverse-corpus-audit-v4.json": "696e7220c97c82e81d78218fef8d65d17c5c29117329757b25dbf9fcb32349b3",
    "reports/portfolio-diverse-corpus-audit-v4.md": "12a871be941a601606fadf46c2606198f3a53d980c56946b54870a730c1e49fb",
}


def _corpus() -> DiverseCorpusV5:
    return DiverseCorpusV5.model_validate_json(V5.read_text(encoding="utf-8"))


def _rehash_question(question: dict[str, Any]) -> None:
    from cti_provenance.claims.diverse_portfolio_v4 import canonical_sha256

    body = {key: value for key, value in question.items() if key != "question_sha256"}
    question["question_sha256"] = canonical_sha256(body)


def _rehash_corpus(payload: dict[str, Any]) -> None:
    from cti_provenance.claims.diverse_portfolio_v4 import canonical_sha256

    body = {key: value for key, value in payload.items() if key != "corpus_sha256"}
    payload["corpus_sha256"] = canonical_sha256(body)


def test_v4_candidate_is_immutable() -> None:
    for relative, expected in V4_HASHES.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected


def test_v5_counts_lineage_and_gate() -> None:
    corpus = _corpus()
    review = ReviewPacketV5.model_validate_json(REVIEW.read_text(encoding="utf-8"))
    index = PacketIndexV5.model_validate_json(INDEX.read_text(encoding="utf-8"))
    lineage = json.loads(LINEAGE.read_text(encoding="utf-8"))
    assert len(corpus.questions) == 64
    assert len(review.items) == 48
    assert len(index.packets) == 64
    assert review.status == "manager_audit_pending"
    assert len(lineage["rows"]) == 64
    assert len({row["v4_case_id"] for row in lineage["rows"]}) == 64
    assert sum(row["disposition"] == "replaced" for row in lineage["rows"]) == 3
    assert {
        row["v4_case_id"] for row in lineage["rows"] if row["disposition"] == "replaced"
    } == {
        "portfolio-diverse-temporal-10",
        "portfolio-diverse-temporal-11",
        "portfolio-diverse-temporal-12",
    }
    v4 = json.loads(
        (ROOT / "data/benchmark/portfolio-diverse-draft-v4.json").read_text(
            encoding="utf-8"
        )
    )
    v5_by_id = {item.case_id: item for item in corpus.questions}
    retained = [
        item for item in v4["questions"] if item["review_status"] == "approved_v2"
    ]
    assert len(retained) == 16
    assert all(
        v5_by_id[item["case_id"]].question_sha256 == item["question_sha256"]
        for item in retained
    )


def test_creation_and_cutoffs_are_truthful_and_future_values_fail() -> None:
    corpus = _corpus()
    assert corpus.created_at_utc == datetime(2026, 7, 22, 21, 55, tzinfo=UTC)
    assert max(item.cutoff_utc for item in corpus.questions) <= corpus.created_at_utc
    assert (
        max(
            evidence.source_available_by_utc
            for question in corpus.questions
            for evidence in question.evidence
        )
        <= corpus.created_at_utc
    )
    assert corpus.created_at_utc <= datetime.now(UTC)

    payload = corpus.model_dump(mode="json")
    payload["created_at_utc"] = "2099-01-01T00:00:00Z"
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="creation time is in the future"):
        DiverseCorpusV5.model_validate_json(json.dumps(payload))

    payload = corpus.model_dump(mode="json")
    question = payload["questions"][0]
    question["cutoff_utc"] = "2026-07-22T21:55:01Z"
    _rehash_question(question)
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="cutoff is later"):
        DiverseCorpusV5.model_validate_json(json.dumps(payload))


def test_every_temporal_packet_exposes_ordered_distinct_states() -> None:
    corpus = _corpus()
    index = PacketIndexV5.model_validate_json(INDEX.read_text(encoding="utf-8"))
    packet_by_case = {item.case_id: item for item in index.packets}
    for question in corpus.questions:
        if question.slice != "temporal_comparison":
            continue
        packet = packet_by_case[question.case_id]
        assert len(packet.documents) >= 2
        assert [item.state_label for item in packet.documents] == [
            f"State {number:02d}" for number in range(1, len(packet.documents) + 1)
        ]
        assert [item.available_by_utc for item in packet.documents] == sorted(
            item.available_by_utc for item in packet.documents
        )

    question = next(
        item
        for item in corpus.questions
        if item.case_id == "portfolio-diverse-temporal-23"
    )
    assert len(question.source_states) == 2
    assert len({item.source_id for item in question.source_states}) == 2
    assert len({item.source_sha256 for item in question.source_states}) == 1
    assert [item.source_available_by_utc for item in question.evidence] == [
        datetime(2024, 7, 1, 13, 15, 6, 467000, tzinfo=UTC),
        datetime(2024, 7, 2, 23, 15, 11, 140000, tzinfo=UTC),
    ]
    assert all(
        item.temporal_basis == "publisher_declared_version"
        for item in question.evidence
    )


def test_temporal_state_removal_or_swap_fails_closed() -> None:
    corpus = _corpus()
    payload = corpus.model_dump(mode="json")
    question = next(
        item
        for item in payload["questions"]
        if item["case_id"] == "portfolio-diverse-temporal-23"
    )
    question["source_states"].pop()
    _rehash_question(question)
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="evidence source missing"):
        DiverseCorpusV5.model_validate_json(json.dumps(payload))

    payload = corpus.model_dump(mode="json")
    question = next(
        item
        for item in payload["questions"]
        if item["case_id"] == "portfolio-diverse-temporal-23"
    )
    old_time = question["evidence"][0]["source_available_by_utc"]
    question["evidence"][0]["source_available_by_utc"] = question["evidence"][1][
        "source_available_by_utc"
    ]
    question["evidence"][1]["source_available_by_utc"] = old_time
    _rehash_question(question)
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="not truthfully ordered"):
        DiverseCorpusV5.model_validate_json(json.dumps(payload))


def test_rejected_release_linkages_are_replaced_by_real_temporal_cases() -> None:
    corpus = _corpus()
    ids = {item.case_id for item in corpus.questions}
    assert (
        not {
            "portfolio-diverse-temporal-10",
            "portfolio-diverse-temporal-11",
            "portfolio-diverse-temporal-12",
        }
        & ids
    )
    replacements = {
        item.case_id: item
        for item in corpus.questions
        if item.case_id
        in {
            "portfolio-diverse-temporal-node-release-v5",
            "portfolio-diverse-temporal-kev-due-date-v5",
            "portfolio-diverse-temporal-kev-action-v5",
        }
    }
    assert len(replacements) == 3
    assert all(item.slice == "temporal_comparison" for item in replacements.values())
    assert (
        replacements["portfolio-diverse-temporal-kev-due-date-v5"].outcome_type
        == "no_change"
    )
    assert (
        replacements["portfolio-diverse-temporal-kev-action-v5"].outcome_type
        == "no_change"
    )


def test_abstention_and_reference_answers_match_structured_gold() -> None:
    corpus = _corpus()
    abstention = next(
        item
        for item in corpus.questions
        if item.case_id == "portfolio-diverse-abstain-08"
    )
    assert abstention.abstention_reason_code == "predicate_absent"
    assert abstention.expected_components[0].value == "predicate_absent"
    for question in corpus.questions:
        if question.review_status == "approved_v2":
            continue
        validate_reference_answer(question)
        if question.outcome_type == "abstain":
            continue
        assert isinstance(question.readable_reference_answer, str)
        for component in question.expected_components:
            assert (
                reference_component_marker(component.component_id, component.value)
                in question.readable_reference_answer
            )

    synthesis = next(
        item
        for item in corpus.questions
        if item.case_id == "portfolio-diverse-synthesis-06"
    )
    assert isinstance(synthesis.readable_reference_answer, str)
    for product, version in synthesis.expected_components[0].value.items():
        assert product in synthesis.readable_reference_answer
        assert str(version) in synthesis.readable_reference_answer
    temporal = next(
        item
        for item in corpus.questions
        if item.case_id == "portfolio-diverse-temporal-23"
    )
    assert "CVE-2006-5051" in str(temporal.readable_reference_answer)
    assert "unauthenticated remote-trigger" in str(temporal.readable_reference_answer)


def test_derivations_and_independence_boundary_are_explicit() -> None:
    corpus = _corpus()
    derived = sum(
        evidence.extraction_method == "deterministic_derivation"
        for question in corpus.questions
        for evidence in question.evidence
    )
    records = sum(len(item.derivation_records) for item in corpus.questions)
    assert (derived, records) == (34, 34)
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["new_capture_count"] == 0
    assert report["cutoff_correction_count"] == 19
    assert all(not findings for findings in report["cross_split_findings"].values())
    assert report["candidate_visible_leakage_findings"] == []
    assert report["semantic_duplicate_pairs"] == []
    assert report["question_independence_note"] == (
        "The 64 unique questions are distinct answer contracts, not 64 independent "
        "factual phenomena; dependency/source family is the clustering unit."
    )


def test_review_cli_accepts_v5_packet_with_empty_log(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    summary = tmp_path / "summary.md"
    decisions.write_text("", encoding="utf-8")
    assert (
        main(
            [
                "review",
                "validate",
                "--packet",
                str(REVIEW),
                "--decisions",
                str(decisions),
                "--summary",
                str(summary),
            ]
        )
        == 0
    )
    assert "- Items: 48" in summary.read_text(encoding="utf-8")


def test_manager_acceptance_opens_only_the_bound_human_review_gate() -> None:
    acceptance = json.loads(ACCEPTANCE.read_text(encoding="utf-8"))
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    review = ReviewPacketV5.model_validate_json(REVIEW.read_text(encoding="utf-8"))
    corpus = _corpus()
    assert acceptance["status"] == "manager_accepted_human_review_open"
    assert acceptance["accepted_commit"] == ("45d89daabb56fd83ae690d431617453fb0c3e24b")
    assert acceptance["corpus_semantic_sha256"] == corpus.corpus_sha256
    assert acceptance["review_packet_semantic_sha256"] == review.packet_sha256
    assert (
        acceptance["review_packet_file_sha256"] == report["review_packet_file_sha256"]
    )
    assert acceptance["new_human_review_item_count"] == len(review.items) == 48
    assert acceptance["unique_answer_contract_count"] == len(corpus.questions) == 64
    assert acceptance["semantic_pair_group_count"] == 51
    assert acceptance["dependency_cluster_count"] == 24
    assert acceptance["provider_execution_status"] == "blocked"
