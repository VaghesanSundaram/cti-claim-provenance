"""Append-only single-reviewer validation for diverse review-packet v2."""

from __future__ import annotations

from cti_provenance.claims.diverse_portfolio_v4 import ReviewPacketV4
from cti_provenance.grading.review_workflow import ReviewDecision


def validate_diverse_review_log(
    packet: ReviewPacketV4, decisions: list[ReviewDecision]
) -> tuple[int, list[str]]:
    """Validate immutable bindings and append-only supersession for one reviewer."""

    items = {item.item_id: item for item in packet.items}
    by_id: dict[str, ReviewDecision] = {}
    active: dict[tuple[str, str], ReviewDecision] = {}
    superseded: set[str] = set()
    for decision in decisions:
        if decision.decision_id in by_id:
            raise ValueError("duplicate decision_id")
        item = items.get(decision.item_id)
        if item is None or decision.case_id != (item.case_id if item else None):
            raise ValueError("decision references a nonexistent item or case")
        if (
            decision.packet_sha256 != packet.packet_sha256
            or decision.item_sha256 != item.item_sha256
            or decision.case_sha256 != item.question_sha256
            or decision.evidence_binding_sha256 != item.evidence_binding_sha256
            or decision.original_label_sha256 != item.original_label_sha256
        ):
            raise ValueError(
                "decision packet, case, evidence, or label binding changed"
            )
        if decision.decided_at_utc <= packet.created_at_utc:
            raise ValueError("decision must be recorded after packet creation")
        key = (decision.item_id, decision.reviewer_id)
        prior_id = decision.supersedes_decision_id
        if prior_id is None:
            if key in active:
                raise ValueError("decision overwrite requires supersedes_decision_id")
        else:
            prior = by_id.get(prior_id)
            if (
                prior is None
                or (prior.item_id, prior.reviewer_id) != key
                or prior_id in superseded
                or active.get(key) is not prior
                or decision.decided_at_utc <= prior.decided_at_utc
            ):
                raise ValueError("invalid append-only supersession")
            superseded.add(prior_id)
        by_id[decision.decision_id] = decision
        active[key] = decision
    reviewer_ids = {decision.reviewer_id for decision in active.values()}
    if len(reviewer_ids) > 1:
        raise ValueError("review-packet v2 uses one fixed human reviewer")
    active_items = {decision.item_id for decision in active.values()}
    if len(active_items) != len(active):
        raise ValueError("an item has more than one active decision")
    unresolved = sorted(set(items) - active_items)
    return len(active), unresolved
