from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from cti_provenance.cli import _write_versioned_outputs
from cti_provenance.grading.portfolio_review import (
    PACKET_PATH,
    RESURFACING_PATH,
    ResurfacingManifest,
    ResurfacingRecord,
    _group_id,
    build_portfolio_review_packet,
    evaluate_repeatability,
    render_repeatability_summary,
    render_resurfacing_manifest,
)
from cti_provenance.grading.review_workflow import (
    ReviewDecision,
    ReviewItem,
    ReviewPacket,
    ReviewVerdict,
    canonical_sha256,
    render_review_packet,
)

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw" / "portfolio-pilot-v1"


def _tracked() -> ReviewPacket:
    return ReviewPacket.model_validate_json(
        (ROOT / PACKET_PATH).read_text(encoding="utf-8")
    )


def _synthetic_manifest(packet: ReviewPacket) -> ResurfacingManifest:
    grouped: dict[str, list[ReviewItem]] = {}
    for item in packet.items:
        grouped.setdefault(item.case_sha256, []).append(item)
    records: list[ResurfacingRecord] = []
    positions = {item.item_id: index for index, item in enumerate(packet.items)}
    for index, (_case_sha256, values) in enumerate(sorted(grouped.items())):
        base_case_id = f"synthetic-base-{index:02d}"
        ordered = sorted(values, key=lambda item: positions[item.item_id])
        for occurrence, item in enumerate(ordered):
            records.append(
                ResurfacingRecord(
                    group_id=_group_id(base_case_id),
                    base_case_id=base_case_id,
                    base_case_sha256=item.case_sha256,
                    item_id=item.item_id,
                    review_case_id=item.case_id,
                    occurrence=occurrence,
                )
            )
    data = {
        "schema_version": "portfolio-resurfacing-v1",
        "manifest_sha256": "0" * 64,
        "packet_id": packet.packet_id,
        "packet_sha256": packet.packet_sha256,
        "base_family_count": 16,
        "resurfaced_family_count": 4,
        "resurfacing_fraction": 0.25,
        "reviewer_instruction": (
            "Do not inspect this linkage manifest until all packet decisions are "
            "exported."
        ),
        "records": tuple(sorted(records, key=lambda record: record.item_id)),
    }
    data["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in data.items() if key != "manifest_sha256"}
    )
    return ResurfacingManifest.model_validate(data)


def _decisions(
    packet: ReviewPacket,
    *,
    disagree_item_id: str | None = None,
) -> list[ReviewDecision]:
    decisions: list[ReviewDecision] = []
    for index, item in enumerate(packet.items):
        factual = "incorrect" if item.item_id == disagree_item_id else "correct"
        decisions.append(
            ReviewDecision(
                schema_version="review-decision-v1",
                decision_id=f"decision-{index:02d}",
                packet_sha256=packet.packet_sha256,
                item_id=item.item_id,
                item_sha256=item.item_sha256,
                case_id=item.case_id,
                case_sha256=item.case_sha256,
                evidence_binding_sha256=item.evidence_binding_sha256,
                reviewer_id="reviewer-test",
                decided_at_utc=packet.created_at_utc + timedelta(days=1, seconds=index),
                supersedes_decision_id=None,
                original_label_sha256=canonical_sha256(item.original_label),
                verdict=ReviewVerdict(
                    factual_correctness=factual,
                    evidence_support="fully_supported",
                    authority="acceptable",
                    cutoff="eligible",
                    answerability="answer",
                    alternate_evidence_exists=False,
                    alternate_evidence_notes=None,
                    question_quality="clear",
                    confidence=0.9,
                    notes=None,
                    reason=None,
                ),
                label_changed=False,
                label_change_reason=None,
            )
        )
    return decisions


def test_tracked_portfolio_packet_is_blinded_and_resurfacing_is_exact() -> None:
    packet = _tracked()
    manifest = _synthetic_manifest(packet)

    assert packet.packet_id == "portfolio-dev-validation-review-v1"
    assert packet.benchmark_scope == "portfolio-scale pilot development/validation"
    assert len(packet.items) == 20
    assert len({item.item_id for item in packet.items}) == 20
    assert len({item.case_id for item in packet.items}) == 20
    assert all(item.case_id.startswith("portfolio-case-") for item in packet.items)
    assert all(item.evidence for item in packet.items)
    assert packet.source_license_or_terms is not None
    assert set(packet.source_license_or_terms) == {
        source.snapshot_id for item in packet.items for source in item.sources
    }
    assert all(
        "@" not in evidence.context_before and "@" not in evidence.context_after
        for item in packet.items
        for evidence in [*item.evidence, *item.alternate_evidence]
    )
    assert all(
        evidence.cutoff_eligibility == "eligible"
        and evidence.authority_category == "primary"
        for item in packet.items
        for evidence in item.evidence
    )
    packet_text = (ROOT / PACKET_PATH).read_text(encoding="utf-8")
    assert "resurface_group" not in packet_text
    packet_payload = json.loads(packet_text)

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {key for child in value.values() for key in keys(child)}
        if isinstance(value, list):
            return {key for child in value for key in keys(child)}
        return set()

    assert not {"model_output", "condition", "passed", "grader_result"} & keys(
        packet_payload
    )

    assert manifest.packet_sha256 == packet.packet_sha256
    assert len(manifest.records) == 20
    grouped: dict[str, list[int]] = {}
    for record in manifest.records:
        grouped.setdefault(record.group_id, []).append(record.occurrence)
    assert sorted(sorted(values) for values in grouped.values()).count([0, 1]) == 4
    assert sum(values == [0] for values in map(sorted, grouped.values())) == 12
    assert {record.item_id for record in manifest.records} == {
        item.item_id for item in packet.items
    }
    positions = {item.item_id: index for index, item in enumerate(packet.items)}
    for group_id in grouped:
        values = [record for record in manifest.records if record.group_id == group_id]
        if len(values) == 2:
            base, repeat = sorted(values, key=lambda record: record.occurrence)
            assert positions[repeat.item_id] - positions[base.item_id] >= 5


def test_repeatability_reports_repeatability_not_gold_correctness() -> None:
    packet = _tracked()
    manifest = _synthetic_manifest(packet)
    repeated = [
        records
        for group_id in {record.group_id for record in manifest.records}
        if len(
            records := [
                record for record in manifest.records if record.group_id == group_id
            ]
        )
        == 2
    ]
    disagree_item_id = repeated[0][1].item_id
    summary = evaluate_repeatability(
        packet,
        manifest,
        _decisions(packet, disagree_item_id=disagree_item_id),
        decision_log_sha256="0" * 64,
    )

    assert summary.completed_item_count == 20
    assert summary.completed_resurfaced_pair_count == 4
    assert (summary.agreement_count, summary.agreement_denominator) == (3, 4)
    assert summary.agreement_rate == 0.75
    assert len(summary.disagreement_group_ids) == 1
    assert len(summary.correction_queue_base_case_ids) == 1
    assert summary.unresolved_item_ids == ()
    assert "not correctness" in summary.limitation
    assert summary.decision_log_sha256 == "0" * 64
    assert f"`{summary.decision_log_sha256}`" in render_repeatability_summary(summary)


def test_repeatability_rejects_incomplete_decisions() -> None:
    packet = _tracked()
    manifest = _synthetic_manifest(packet)

    with pytest.raises(ValueError, match="complete all 20"):
        evaluate_repeatability(
            packet,
            manifest,
            [],
            decision_log_sha256="0" * 64,
        )


def test_portfolio_packet_rejects_missing_license_terms_map() -> None:
    packet = _tracked()
    tampered = packet.model_dump(
        mode="python", exclude={"packet_sha256", "source_license_or_terms"}
    )
    tampered["packet_sha256"] = canonical_sha256(tampered)

    with pytest.raises(ValueError, match="require source license"):
        ReviewPacket.model_validate(tampered)


def test_resurfacing_manifest_rejects_rotated_pairing() -> None:
    packet = _tracked()
    manifest = _synthetic_manifest(packet)
    records = list(manifest.records)
    repeated = [record for record in records if record.occurrence == 1]
    rotated_group_ids = [record.group_id for record in repeated[1:]] + [
        repeated[0].group_id
    ]
    replacements = {
        record.item_id: record.model_copy(update={"group_id": group_id})
        for record, group_id in zip(repeated, rotated_group_ids, strict=True)
    }
    tampered = manifest.model_dump(mode="python", exclude={"manifest_sha256"})
    tampered["records"] = tuple(
        replacements.get(record.item_id, record) for record in records
    )
    tampered["manifest_sha256"] = canonical_sha256(tampered)

    with pytest.raises(ValueError, match="resurfacing inventory"):
        ResurfacingManifest.model_validate(tampered)


def test_portfolio_packet_replays_when_public_source_bytes_exist() -> None:
    if not RAW.is_dir():
        pytest.skip("gitignored portfolio source captures are unavailable")
    packet, manifest = build_portfolio_review_packet(ROOT)
    assert render_review_packet(packet) == (ROOT / PACKET_PATH).read_text(
        encoding="utf-8"
    )
    assert render_resurfacing_manifest(manifest) == (ROOT / RESURFACING_PATH).read_text(
        encoding="utf-8"
    )


def test_versioned_outputs_refuse_partial_overwrite(tmp_path: Path) -> None:
    packet_path = tmp_path / "packet.json"
    resurfacing_path = tmp_path / "resurfacing.json"
    packet_path.write_text("different\n", encoding="utf-8")

    with pytest.raises(ValueError, match="existing packet differs"):
        _write_versioned_outputs(
            (
                (packet_path, "expected\n", "packet"),
                (resurfacing_path, "expected\n", "resurfacing manifest"),
            )
        )

    assert packet_path.read_text(encoding="utf-8") == "different\n"
    assert not resurfacing_path.exists()
