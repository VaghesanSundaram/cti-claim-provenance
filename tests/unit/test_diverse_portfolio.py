"""Contract tests for the additive diverse-portfolio manager-audit draft."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from cti_provenance.claims.diverse_portfolio import (
    grade_diverse_outcome,
    load_diverse_corpus_draft,
)
from cti_provenance.grading.review_workflow import ReviewPacket

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "data/benchmark/portfolio-diverse-draft-v3.json"
REVIEW_PATH = ROOT / "annotations/packets/portfolio-diverse-review-v3.json"
PACKET_PATH = ROOT / "data/benchmark/portfolio-diverse-packets-v3.json"
V2_PATH = ROOT / "data/benchmark/portfolio-public-cases-v2.jsonl"
CAPTURE_MANIFESTS = (
    ROOT / "data/manifests/portfolio-diverse-capture-batch1.json",
    ROOT / "data/manifests/portfolio-diverse-capture-batch2.json",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_diverse_draft_has_substantive_slice_and_outcome_counts() -> None:
    corpus = load_diverse_corpus_draft(CORPUS_PATH)

    assert len(corpus.questions) == 65
    assert Counter(question.slice for question in corpus.questions) == {
        "single_source_extraction": 16,
        "temporal_comparison": 25,
        "cutoff_or_insufficiency_abstention": 8,
        "authority_divergence": 8,
        "multi_source_synthesis": 8,
    }
    assert Counter(question.outcome_type for question in corpus.questions) == {
        "positive": 55,
        "abstain": 8,
        "no_change": 2,
    }
    assert len({question.question for question in corpus.questions}) == 65
    assert len({question.source_family_id for question in corpus.questions}) == 24


def test_retained_cases_bind_unchanged_reviewed_v2_records() -> None:
    corpus = load_diverse_corpus_draft(CORPUS_PATH)
    v2_hashes = {
        record["case_id"]: hashlib.sha256(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        for record in (
            json.loads(line)
            for line in V2_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    }
    retained = [
        question
        for question in corpus.questions
        if question.review_status == "approved_v2"
    ]

    assert len(retained) == 16
    for question in retained:
        assert question.retained_v2_case_id is not None
        assert (
            question.retained_v2_case_sha256 == v2_hashes[question.retained_v2_case_id]
        )


def test_draft_oracle_requires_all_spans_and_explicit_abstention() -> None:
    corpus = load_diverse_corpus_draft(CORPUS_PATH)
    synthesis = next(
        question
        for question in corpus.questions
        if question.slice == "multi_source_synthesis"
    )
    assert grade_diverse_outcome(
        synthesis,
        answer=synthesis.expected_answer,
        abstained=False,
        cited_evidence_ids=synthesis.required_evidence_ids,
    )
    assert not grade_diverse_outcome(
        synthesis,
        answer=synthesis.expected_answer,
        abstained=False,
        cited_evidence_ids=synthesis.required_evidence_ids[:-1],
    )

    abstention = next(
        question for question in corpus.questions if question.outcome_type == "abstain"
    )
    assert grade_diverse_outcome(
        abstention,
        answer=None,
        abstained=True,
        cited_evidence_ids=[],
    )
    assert not grade_diverse_outcome(
        abstention,
        answer=None,
        abstained=False,
        cited_evidence_ids=[],
    )


def test_review_packet_and_packet_index_cover_only_intended_labels() -> None:
    review = ReviewPacket.model_validate_json(REVIEW_PATH.read_text(encoding="utf-8"))
    packet_index = json.loads(PACKET_PATH.read_text(encoding="utf-8"))

    assert len(review.items) == 49
    assert len({item.case_id for item in review.items}) == 49
    assert Counter(packet["variant"] for packet in packet_index["packets"]) == {
        "clean": 65,
        "benign_control": 16,
        "challenge": 16,
    }
    assert len({packet["packet_id"] for packet in packet_index["packets"]}) == 97


def test_review_sources_use_consistent_hashes_and_evidence_forms() -> None:
    review = ReviewPacket.model_validate_json(REVIEW_PATH.read_text(encoding="utf-8"))
    corpus = load_diverse_corpus_draft(CORPUS_PATH)
    source_hashes: dict[str, tuple[str, str]] = {}

    for item in review.items:
        for source in item.sources:
            pair = (source.raw_snapshot_sha256, source.normalized_text_sha256)
            assert source_hashes.setdefault(source.snapshot_id, pair) == pair

    evidence_methods = {
        evidence.extraction_method
        for question in corpus.questions
        for evidence in question.evidence
    }
    assert evidence_methods == {
        "literal_raw_span",
        "normalized_span",
        "deterministic_derivation",
    }


def test_tracked_artifact_bytes_are_nonempty_and_distinct() -> None:
    hashes = {_sha256(CORPUS_PATH), _sha256(REVIEW_PATH), _sha256(PACKET_PATH)}
    assert len(hashes) == 3
    assert all(
        path.stat().st_size > 0 for path in (CORPUS_PATH, REVIEW_PATH, PACKET_PATH)
    )


def test_new_capture_manifests_bind_seven_unique_raw_inputs() -> None:
    records = [
        record
        for manifest_path in CAPTURE_MANIFESTS
        for record in json.loads(manifest_path.read_text(encoding="utf-8"))["records"]
    ]

    assert len(records) == 7
    assert len({record["url"] for record in records}) == 7
    assert len({record["request_fingerprint"] for record in records}) == 7
    assert sum(len(record["attempts"]) for record in records) == 7
    for record in records:
        assert record["outcome"] == "success"
        assert record["attempts"] == [
            {
                **record["attempts"][0],
                "attempt_number": 1,
                "outcome": "success",
                "retry_delay_seconds": None,
                "status": 200,
            }
        ]
        raw_path = ROOT / record["raw_blob_path"]
        assert record["raw_blob_path"].startswith("data/raw/portfolio-diverse-v1/")
        if raw_path.is_file():
            assert raw_path.stat().st_size == record["byte_length"]
            assert _sha256(raw_path) == record["sha256"]
