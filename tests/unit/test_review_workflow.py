from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.cli import main
from cti_provenance.grading.review_workflow import (
    ReviewAdjudication,
    ReviewDecision,
    ReviewPacket,
    ReviewVerdict,
    build_phase2_real_review_packet,
    canonical_sha256,
    load_jsonl_records,
    render_canonical_jsonl,
    render_review_packet,
    validate_review_log,
)

ROOT = Path(__file__).resolve().parents[2]
PACKET_PATH = ROOT / "annotations" / "packets" / "phase2-real-gold-review-v1.json"
DECISIONS_PATH = (
    ROOT / "annotations" / "decisions" / "phase2-real-gold-review-v1-reviewer-a17.jsonl"
)


def _packet() -> ReviewPacket:
    return ReviewPacket.model_validate_json(PACKET_PATH.read_text(encoding="utf-8"))


def _verdict(*, factual: str = "correct") -> ReviewVerdict:
    return ReviewVerdict.model_validate(
        {
            "factual_correctness": factual,
            "evidence_support": "fully_supported",
            "authority": "acceptable",
            "cutoff": "eligible",
            "answerability": "answer",
            "alternate_evidence_exists": False,
            "alternate_evidence_notes": None,
            "question_quality": "clear",
            "confidence": 0.9,
            "notes": None,
            "reason": "reviewer found a genuine ambiguity"
            if factual == "ambiguous"
            else None,
        }
    )


def _decision(
    packet: ReviewPacket,
    reviewer: str,
    *,
    decision_id: str,
    verdict: ReviewVerdict | None = None,
    when: datetime | None = None,
    supersedes: str | None = None,
    item_index: int = 0,
) -> ReviewDecision:
    item = packet.items[item_index]
    return ReviewDecision(
        schema_version="review-decision-v1",
        decision_id=decision_id,
        packet_sha256=packet.packet_sha256,
        item_id=item.item_id,
        item_sha256=item.item_sha256,
        case_id=item.case_id,
        case_sha256=item.case_sha256,
        evidence_binding_sha256=item.evidence_binding_sha256,
        reviewer_id=reviewer,
        decided_at_utc=when or datetime(2026, 7, 20, 1, tzinfo=UTC),
        supersedes_decision_id=supersedes,
        original_label_sha256=canonical_sha256(item.original_label),
        verdict=verdict or _verdict(),
        label_changed=False,
        label_change_reason=None,
    )


def test_tracked_packet_is_strict_blinded_and_has_requested_fields() -> None:
    packet = _packet()

    assert len(packet.items) == 12
    assert packet.benchmark_scope == "Log4Shell plumbing-only"
    serialized = packet.model_dump_json()
    for forbidden in (
        "model_output",
        '"condition"',
        '"passed"',
        '"aggregate"',
        "preferred_answer",
        "grader_result",
        "run_id",
    ):
        assert forbidden not in serialized
    assert {item.case_category for item in packet.items} >= {
        "answerable",
        "insufficient_evidence",
        "contradiction",
        "wrong_date",
    }
    red_hat = [
        source
        for item in packet.items
        for source in item.sources
        if source.source_name == "red_hat_rhsa"
    ]
    assert red_hat
    assert all(
        "Publisher-declared version evidence" in source.temporal_evidence_description
        for source in red_hat
    )
    assert all(item.sources for item in packet.items)
    assert all(item.alternate_evidence for item in packet.items)


def test_tracked_single_reviewer_decisions_are_complete_and_append_only() -> None:
    packet = _packet()
    decisions = load_jsonl_records(DECISIONS_PATH, ReviewDecision)
    summary = validate_review_log(
        packet,
        decisions,
        [],
        review_mode="single_reviewer",
    )

    assert hashlib.sha256(DECISIONS_PATH.read_bytes()).hexdigest() == (
        "5069a900838e7d9928be003b84dc3eddf73817ecbc55340df937c07f46435f13"
    )
    assert len(decisions) == 16
    assert sum(value.supersedes_decision_id is not None for value in decisions) == 4
    assert summary.active_decision_count == 12
    assert summary.reviewer_ids == ["reviewer-a17"]
    assert len(summary.completed_item_ids) == 12
    assert summary.unresolved_item_ids == []

    superseded = {
        value.supersedes_decision_id
        for value in decisions
        if value.supersedes_decision_id is not None
    }
    active = [value for value in decisions if value.decision_id not in superseded]
    assert all(value.verdict.factual_correctness == "correct" for value in active)
    assert all(value.verdict.authority == "acceptable" for value in active)
    assert all(value.verdict.question_quality == "clear" for value in active)
    assert sum(value.verdict.answerability == "answer" for value in active) == 8
    assert sum(value.verdict.answerability == "abstain" for value in active) == 4
    assert sum(value.label_changed for value in active) == 0


def test_tracked_packet_rebuild_is_byte_deterministic_when_sources_present() -> None:
    try:
        rebuilt = build_phase2_real_review_packet(ROOT)
    except (OSError, ValueError):
        pytest.skip("ignored frozen source bytes are unavailable in this checkout")

    assert render_review_packet(rebuilt) == PACKET_PATH.read_text(encoding="utf-8")


def test_changed_span_or_unknown_field_is_rejected() -> None:
    body = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
    body["items"][0]["evidence"][0]["exact_text"] += " changed"
    with pytest.raises(ValidationError, match="span hash"):
        ReviewPacket.model_validate_json(json.dumps(body))

    leakage = json.loads(
        (
            ROOT / "tests" / "fixtures" / "review-workflow" / "model-leakage.json"
        ).read_text(encoding="utf-8")
    )
    with pytest.raises(ValidationError):
        ReviewPacket.model_validate(leakage)

    cutoff = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
    cutoff["items"][0]["evidence"][0]["cutoff_eligibility"] = "ineligible"
    with pytest.raises(ValidationError, match="cutoff eligibility"):
        ReviewPacket.model_validate_json(json.dumps(cutoff))

    authority = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
    authority["items"][0]["evidence"][0]["authority_category"] = "unacceptable"
    with pytest.raises(ValidationError, match="eligible primary"):
        ReviewPacket.model_validate_json(json.dumps(authority))


def test_decision_reasons_are_required_for_ambiguity_and_label_changes() -> None:
    with pytest.raises(ValidationError, match="require a reason"):
        ReviewVerdict(
            factual_correctness="ambiguous",
            evidence_support="unclear",
            authority="unclear",
            cutoff="unclear",
            answerability="ambiguous",
            alternate_evidence_exists=False,
            alternate_evidence_notes=None,
            question_quality="exclude",
            confidence=0.5,
            notes=None,
            reason=None,
        )
    with pytest.raises(ValidationError, match="at least 1 character"):
        ReviewVerdict(
            factual_correctness="ambiguous",
            evidence_support="fully_supported",
            authority="acceptable",
            cutoff="eligible",
            answerability="answer",
            alternate_evidence_exists=False,
            alternate_evidence_notes=None,
            question_quality="clear",
            confidence=0.5,
            notes=None,
            reason="   ",
        )

    data = _decision(_packet(), "reviewer-one", decision_id="d1").model_dump()
    data["label_changed"] = True
    with pytest.raises(ValidationError, match="label changes require"):
        ReviewDecision.model_validate(data)


def test_append_only_supersession_preserves_prior_decision() -> None:
    packet = _packet()
    first = _decision(packet, "reviewer-one", decision_id="d1")
    corrected = _decision(
        packet,
        "reviewer-one",
        decision_id="d2",
        when=first.decided_at_utc + timedelta(minutes=1),
        supersedes="d1",
    )

    summary = validate_review_log(packet, [first, corrected], [])
    assert summary.decision_count == 2
    assert summary.active_decision_count == 1

    overwrite = _decision(
        packet,
        "reviewer-one",
        decision_id="d3",
        when=first.decided_at_utc + timedelta(minutes=2),
    )
    with pytest.raises(ValueError, match="overwrite"):
        validate_review_log(packet, [first, overwrite], [])


def test_mismatched_bindings_duplicates_and_nonexistent_items_fail() -> None:
    packet = _packet()
    decision = _decision(packet, "reviewer-one", decision_id="d1")
    with pytest.raises(ValueError, match="duplicate"):
        validate_review_log(packet, [decision, decision], [])

    wrong = decision.model_copy(update={"case_sha256": "a" * 64})
    with pytest.raises(ValueError, match="binding changed"):
        validate_review_log(packet, [wrong], [])

    missing = decision.model_copy(update={"item_id": "missing"})
    with pytest.raises(ValueError, match="nonexistent"):
        validate_review_log(packet, [missing], [])


@pytest.mark.legacy
def test_disagreement_requires_two_reviewers_before_adjudication() -> None:
    packet = _packet()
    first = _decision(packet, "reviewer-one", decision_id="d1")
    second = _decision(
        packet,
        "reviewer-two",
        decision_id="d2",
        verdict=_verdict(factual="ambiguous"),
        when=first.decided_at_utc + timedelta(minutes=1),
    )
    item = packet.items[0]
    adjudication = ReviewAdjudication(
        schema_version="review-adjudication-v1",
        adjudication_id="a1",
        packet_sha256=packet.packet_sha256,
        item_id=item.item_id,
        item_sha256=item.item_sha256,
        case_id=item.case_id,
        reviewer_decision_ids=["d1", "d2"],
        adjudicator_id="reviewer-three",
        adjudicated_at_utc=second.decided_at_utc + timedelta(minutes=1),
        final_verdict=_verdict(),
        final_label_changed=False,
        adjudication_reason="The exact span entails the original label.",
    )

    with pytest.raises(ValueError, match="missing or mismatched"):
        validate_review_log(
            packet, [first], [adjudication], review_mode="double_reviewer"
        )
    summary = validate_review_log(
        packet, [first, second], [], review_mode="double_reviewer"
    )
    assert summary.disagreement_item_ids == [item.item_id]
    assert item.item_id in summary.unresolved_item_ids
    resolved = validate_review_log(
        packet,
        [first, second],
        [adjudication],
        review_mode="double_reviewer",
    )
    assert item.item_id not in resolved.unresolved_item_ids


@pytest.mark.legacy
def test_confidence_and_notes_do_not_create_label_disagreement() -> None:
    packet = _packet()
    first = _decision(packet, "reviewer-one", decision_id="d1")
    changed = _verdict().model_copy(
        update={"confidence": 0.85, "notes": "Independent rationale."}
    )
    second = _decision(
        packet,
        "reviewer-two",
        decision_id="d2",
        verdict=changed,
        when=first.decided_at_utc + timedelta(minutes=1),
    )
    summary = validate_review_log(
        packet, [first, second], [], review_mode="double_reviewer"
    )
    assert summary.disagreement_item_ids == []


@pytest.mark.legacy
def test_packet_uses_one_fixed_reviewer_pair() -> None:
    packet = _packet()
    decisions = [
        _decision(
            packet,
            f"reviewer-{name}",
            decision_id=f"d{index}",
            item_index=index,
            when=datetime(2026, 7, 20, 2, index, tzinfo=UTC),
        )
        for index, name in enumerate(("one", "two", "three"))
    ]
    with pytest.raises(ValueError, match="fixed reviewer cohort"):
        validate_review_log(packet, decisions, [], review_mode="double_reviewer")


def test_single_reviewer_mode_completes_with_one_fixed_reviewer() -> None:
    packet = _packet()
    decisions = [
        _decision(
            packet,
            "reviewer-one",
            decision_id=f"single-{index}",
            item_index=index,
            when=datetime(2026, 7, 20, 3, index, tzinfo=UTC),
        )
        for index in range(len(packet.items))
    ]

    summary = validate_review_log(
        packet,
        decisions,
        [],
        review_mode="single_reviewer",
    )
    assert summary.review_mode == "single_reviewer"
    assert summary.required_reviews_per_item == 1
    assert summary.reviewer_ids == ["reviewer-one"]
    assert len(summary.completed_item_ids) == len(packet.items)
    assert summary.unresolved_item_ids == []

    second_reviewer = _decision(
        packet,
        "reviewer-two",
        decision_id="single-extra-reviewer",
        item_index=0,
        when=datetime(2026, 7, 20, 4, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="fixed reviewer cohort"):
        validate_review_log(
            packet,
            [*decisions, second_reviewer],
            [],
            review_mode="single_reviewer",
        )


def test_canonical_export_is_order_independent() -> None:
    packet = _packet()
    first = _decision(packet, "reviewer-one", decision_id="d1")
    second = _decision(packet, "reviewer-two", decision_id="d2")
    assert render_canonical_jsonl([second, first]) == render_canonical_jsonl(
        [first, second]
    )


def test_canonical_export_orders_supersession_by_parsed_timestamp() -> None:
    packet = _packet()
    first = _decision(
        packet,
        "reviewer-one",
        decision_id="d1",
        when=datetime(2026, 7, 20, 2, 0, 0, tzinfo=UTC),
    )
    second = _decision(
        packet,
        "reviewer-one",
        decision_id="d2",
        when=datetime(2026, 7, 20, 2, 0, 0, 500000, tzinfo=UTC),
        supersedes="d1",
    )
    rendered = render_canonical_jsonl([second, first])
    assert rendered.splitlines()[0].find('"decision_id":"d1"') >= 0
    validate_review_log(packet, [first, second], [])


def test_static_app_has_no_network_or_model_result_import_path() -> None:
    html = (ROOT / "annotations" / "review-app" / "index.html").read_text(
        encoding="utf-8"
    )
    lowered = html.casefold()
    assert "fetch(" not in lowered
    assert "xmlhttprequest" not in lowered
    assert "websocket" not in lowered
    assert ".innerhtml" not in lowered
    assert "content-security-policy" in lowered
    assert "verifypacket" in lowered
    assert "date.parse" not in lowered
    assert "current reviewer completed all filtered items" in lowered
    assert 'reviewmode="single_reviewer"' in lowered
    assert "model/result" in lowered
    assert "next unresolved" in lowered
    assert "export decisions" in lowered


def test_review_validate_cli_accepts_empty_append_only_logs(
    tmp_path: Path,
) -> None:
    decisions = tmp_path / "decisions.jsonl"
    summary = tmp_path / "summary.md"
    decisions.write_text("", encoding="utf-8")

    assert (
        main(
            [
                "review",
                "validate",
                "--packet",
                str(PACKET_PATH),
                "--decisions",
                str(decisions),
                "--summary",
                str(summary),
            ]
        )
        == 0
    )
    assert "- Items: 12" in summary.read_text(encoding="utf-8")
    assert "- Review mode: `single_reviewer`" in summary.read_text(encoding="utf-8")


@pytest.mark.legacy
def test_review_packet_cli_never_overwrites_a_changed_version(
    tmp_path: Path,
) -> None:
    output = tmp_path / "phase2-real-gold-review-v1.json"
    output.write_text("existing reviewed bytes\n", encoding="utf-8")

    assert (
        main(
            [
                "review",
                "packet",
                "--root",
                str(ROOT),
                "--output",
                str(output),
            ]
        )
        == 1
    )
    assert output.read_text(encoding="utf-8") == "existing reviewed bytes\n"
