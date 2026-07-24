"""Record the user's five-item V6 approval as immutable reviewer-a17 decisions."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic_core import to_jsonable_python

from cti_provenance.claims.diverse_portfolio_v4 import canonical_sha256
from cti_provenance.claims.diverse_portfolio_v6 import ReviewPacketV6
from cti_provenance.grading.diverse_review import validate_diverse_review_log
from cti_provenance.grading.review_workflow import ReviewDecision, ReviewVerdict

ROOT = Path(__file__).resolve().parents[1]
PACKET = (
    ROOT / "annotations/packets/portfolio-diverse-egress-replacements-review-v6.json"
)
DECISIONS = (
    ROOT / "annotations/decisions/"
    "portfolio-diverse-egress-replacements-review-v6-reviewer-a17.jsonl"
)
APPROVAL = (
    ROOT / "annotations/decisions/"
    "portfolio-diverse-egress-replacements-review-v6-user-approval.json"
)
APPROVED_PACKET_SHA256 = (
    "ec991987a8c87d6928436773ef27cd9a30ca6c4a61d3a3c3b9d2f99d46a89d98"
)
APPROVED_AT = datetime(2026, 7, 24, 18, 51, tzinfo=UTC)
REVIEWER_ID = "reviewer-a17"


def _json(value: object) -> str:
    return json.dumps(
        to_jsonable_python(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def main() -> int:
    packet = ReviewPacketV6.model_validate_json(PACKET.read_text(encoding="utf-8"))
    if packet.packet_sha256 != APPROVED_PACKET_SHA256:
        raise ValueError("approved review packet hash changed")
    decisions: list[ReviewDecision] = []
    for offset, item in enumerate(packet.items):
        is_abstention = item.abstention_reason_code is not None
        decision = ReviewDecision(
            schema_version="review-decision-v1",
            decision_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"{APPROVED_PACKET_SHA256}:{REVIEWER_ID}:{item.item_id}",
                )
            ),
            packet_sha256=packet.packet_sha256,
            item_id=item.item_id,
            item_sha256=item.item_sha256,
            case_id=item.case_id,
            case_sha256=item.question_sha256,
            evidence_binding_sha256=item.evidence_binding_sha256,
            reviewer_id=REVIEWER_ID,
            decided_at_utc=APPROVED_AT + timedelta(microseconds=offset),
            supersedes_decision_id=None,
            original_label_sha256=item.original_label_sha256,
            verdict=ReviewVerdict(
                factual_correctness="correct",
                evidence_support="fully_supported",
                authority="acceptable",
                cutoff="eligible",
                answerability="abstain" if is_abstention else "answer",
                alternate_evidence_exists=False,
                alternate_evidence_notes=None,
                question_quality="clear",
                confidence=1.0,
                notes=(
                    "The user explicitly approved this prepared replacement label "
                    "unchanged under reviewer ID reviewer-a17."
                ),
                reason=None,
            ),
            label_changed=False,
            label_change_reason=None,
        )
        decisions.append(decision)
    active, unresolved = validate_diverse_review_log(packet, decisions)
    if active != 5 or unresolved:
        raise ValueError("replacement review log is incomplete")
    DECISIONS.parent.mkdir(parents=True, exist_ok=True)
    DECISIONS.write_text(
        "".join(f"{_json(item.model_dump(mode='json'))}\n" for item in decisions),
        encoding="utf-8",
        newline="\n",
    )
    decision_sha256 = hashlib.sha256(DECISIONS.read_bytes()).hexdigest()
    approval = {
        "schema_version": "portfolio-diverse-v6-user-approval-v1",
        "status": "human_approved",
        "approved_at_utc": APPROVED_AT,
        "reviewer_id": REVIEWER_ID,
        "approval_basis": (
            "Explicit user approval of all five prepared replacement labels "
            "unchanged; agent preparation alone is not human validation."
        ),
        "packet_path": PACKET.relative_to(ROOT).as_posix(),
        "packet_sha256": packet.packet_sha256,
        "decision_log_path": DECISIONS.relative_to(ROOT).as_posix(),
        "decision_log_file_sha256": decision_sha256,
        "active_decision_count": active,
        "unresolved_item_count": len(unresolved),
        "approved_case_ids": sorted(item.case_id for item in packet.items),
    }
    approval["approval_sha256"] = canonical_sha256(approval)
    APPROVAL.write_text(
        json.dumps(
            to_jsonable_python(approval),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"{DECISIONS.relative_to(ROOT)} {decision_sha256}")
    print(f"{APPROVAL.relative_to(ROOT)} {approval['approval_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
