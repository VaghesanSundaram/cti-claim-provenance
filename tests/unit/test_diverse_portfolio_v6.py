"""Contracts for the two approved corrections and five V6 replacements."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cti_provenance.claims.diverse_portfolio_v4 import (
    CandidateComponent,
    canonical_sha256,
    grade_v4_outcome,
)
from cti_provenance.claims.diverse_portfolio_v5 import (
    DiverseCorpusV5,
    ReviewPacketV5,
)
from cti_provenance.claims.diverse_portfolio_v6 import (
    DiverseCorpusV6,
    PacketIndexV6,
    ReviewPacketV6,
)
from cti_provenance.grading import grade_portfolio_diverse_outcome
from cti_provenance.grading.authority import (
    PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION,
    validate_authority_policy_predicate,
)
from cti_provenance.grading.diverse_review import validate_diverse_review_log
from cti_provenance.grading.review_workflow import ReviewDecision, load_jsonl_records

ROOT = Path(__file__).resolve().parents[2]
V5 = ROOT / "data/benchmark/portfolio-diverse-draft-v5.json"
V6 = ROOT / "data/benchmark/portfolio-diverse-draft-v6.json"
V6_INDEX = ROOT / "data/benchmark/portfolio-diverse-packets-v6.json"
LINEAGE = ROOT / "data/benchmark/portfolio-diverse-v5-to-v6.json"
V5_REVIEW = ROOT / "annotations/packets/portfolio-diverse-review-v5.json"
DECISIONS = (
    ROOT / "annotations/decisions/portfolio-diverse-review-v5-reviewer-a17.jsonl"
)
APPROVAL = ROOT / "annotations/decisions/portfolio-diverse-review-v5-user-approval.json"
REPLACEMENT_REVIEW = (
    ROOT / "annotations/packets/portfolio-diverse-egress-replacements-review-v6.json"
)
REPLACEMENT_DECISIONS = (
    ROOT / "annotations/decisions/"
    "portfolio-diverse-egress-replacements-review-v6-reviewer-a17.jsonl"
)
REPLACEMENT_APPROVAL = (
    ROOT / "annotations/decisions/"
    "portfolio-diverse-egress-replacements-review-v6-user-approval.json"
)
V5_COMMITTED_LF_FILE_SHA256 = (
    "03802eaf51465163e05b301e2f1693d6ee0bb04191a00d04495eee797406090c"
)
V5_SEMANTIC_SHA256 = "ea14d41d242672df1734808c5b0327219fc1eaee7b8fa1109d5131bf1346be20"
DECISION_FILE_SHA256 = (
    "c81b62e16961688208b5348501fd577849e1826039723e493ba1838f84752577"
)
APPROVED_CORRECTIONS = {
    "portfolio-diverse-authority-06",
    "portfolio-diverse-temporal-19",
}
EGRESS_REPLACEMENTS = {
    "portfolio-diverse-abstain-08",
    "portfolio-diverse-authority-07-v4",
    "portfolio-diverse-authority-08",
    "portfolio-diverse-synthesis-06",
    "portfolio-diverse-synthesis-07",
}


def _v5() -> DiverseCorpusV5:
    return DiverseCorpusV5.model_validate_json(V5.read_text(encoding="utf-8"))


def _v6() -> DiverseCorpusV6:
    return DiverseCorpusV6.model_validate_json(V6.read_text(encoding="utf-8"))


def _committed_text_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_exact_approved_decision_log_is_canonical_and_complete() -> None:
    # 84a826... was the Windows CRLF checkout rendering, not the Git blob.
    assert _committed_text_sha(V5) == V5_COMMITTED_LF_FILE_SHA256
    assert _v5().corpus_sha256 == V5_SEMANTIC_SHA256
    assert hashlib.sha256(DECISIONS.read_bytes()).hexdigest() == DECISION_FILE_SHA256
    packet = ReviewPacketV5.model_validate_json(V5_REVIEW.read_text(encoding="utf-8"))
    decisions = load_jsonl_records(DECISIONS, ReviewDecision)
    active, unresolved = validate_diverse_review_log(packet, decisions)
    assert active == 48
    assert unresolved == []
    assert {item.reviewer_id for item in decisions} == {"reviewer-a17"}
    changed = {item.case_id for item in decisions if item.label_changed}
    assert changed == {
        "portfolio-diverse-authority-06",
        "portfolio-diverse-temporal-19",
    }
    approval = json.loads(APPROVAL.read_text(encoding="utf-8"))
    assert approval["status"] == "human_approved"
    assert approval["canonical_decision_log_file_sha256"] == DECISION_FILE_SHA256


def test_v6_changes_only_the_two_approved_corrections_and_five_replacements() -> None:
    old = {item.case_id: item for item in _v5().questions}
    new = {item.case_id: item for item in _v6().questions}
    changed = {
        case_id
        for case_id in old
        if old[case_id].question_sha256 != new[case_id].question_sha256
    }
    assert changed == APPROVED_CORRECTIONS | EGRESS_REPLACEMENTS
    lineage = json.loads(LINEAGE.read_text(encoding="utf-8"))
    assert len(lineage["rows"]) == 7
    assert {row["v5_case_id"] for row in lineage["rows"]} == changed
    by_disposition = {row["v5_case_id"]: row["disposition"] for row in lineage["rows"]}
    assert {
        case_id
        for case_id, disposition in by_disposition.items()
        if disposition == "revised"
    } == APPROVED_CORRECTIONS
    assert {
        case_id
        for case_id, disposition in by_disposition.items()
        if disposition == "replaced_pending_five_item_review"
    } == EGRESS_REPLACEMENTS


def test_compact_replacement_review_packet_covers_exactly_five_cases() -> None:
    packet = ReviewPacketV6.model_validate_json(
        REPLACEMENT_REVIEW.read_text(encoding="utf-8")
    )
    assert len(packet.items) == 5
    assert {item.case_id for item in packet.items} == EGRESS_REPLACEMENTS
    body = packet.model_dump(mode="json", exclude={"packet_sha256"})
    assert canonical_sha256(body) == packet.packet_sha256
    decisions = load_jsonl_records(REPLACEMENT_DECISIONS, ReviewDecision)
    active, unresolved = validate_diverse_review_log(packet, decisions)
    assert active == 5
    assert unresolved == []
    assert {item.reviewer_id for item in decisions} == {"reviewer-a17"}
    assert all(not item.label_changed for item in decisions)
    approval = json.loads(REPLACEMENT_APPROVAL.read_text(encoding="utf-8"))
    assert approval["status"] == "human_approved"
    assert approval["packet_sha256"] == packet.packet_sha256
    assert (
        approval["decision_log_file_sha256"]
        == hashlib.sha256(REPLACEMENT_DECISIONS.read_bytes()).hexdigest()
    )


def test_replacements_remove_restricted_vendor_inputs_without_changing_balance() -> (
    None
):
    old = {item.case_id: item for item in _v5().questions}
    new = {item.case_id: item for item in _v6().questions}
    restricted_prefixes = ("ecovacs-", "guralp-", "kunbus-")
    for case_id in EGRESS_REPLACEMENTS:
        replacement = new[case_id]
        assert replacement.source_family_id == old[case_id].source_family_id
        assert replacement.dependency_id == old[case_id].dependency_id
        assert replacement.split == old[case_id].split
        assert replacement.slice == old[case_id].slice
        assert all(
            not evidence.source_id.startswith(restricted_prefixes)
            for evidence in replacement.evidence
        )
        assert {evidence.source_name for evidence in replacement.evidence} == {
            "cisa_csaf"
        }


def test_authority_correction_includes_the_kev_fallback() -> None:
    question = next(
        item
        for item in _v6().questions
        if item.case_id == "portfolio-diverse-authority-06"
    )
    action = next(
        item
        for item in question.expected_components
        if item.kind == "authority_fact"
        and item.authority_scope == "CISA KEV required-action authority"
    )
    assert action.value == (
        "apply mitigations and kill all active and persistent sessions, "
        "or discontinue use if mitigations are unavailable"
    )
    assert "discontinuing use if mitigations are unavailable" in str(
        question.readable_reference_answer
    )
    assert "discontinue use of the product if mitigations are unavailable" in next(
        item.exact_text
        for item in question.evidence
        if item.evidence_id == "kev-cve-2023-4966:requiredAction"
    )


def test_temporal_correction_requires_exact_fmus_and_min_spans() -> None:
    question = next(
        item
        for item in _v6().questions
        if item.case_id == "portfolio-diverse-temporal-19"
    )
    evidence = {item.evidence_id: item for item in question.evidence}
    assert evidence["temporal-guralp:update-a-fmus"].exact_text == (
        "Güralp FMUS Series Seismic Monitoring Devices"
    )
    assert evidence["temporal-guralp:update-a-min"].exact_text == (
        "Güralp MIN Series Digitizing Devices"
    )
    new_value = next(
        item for item in question.expected_components if item.kind == "new_value"
    )
    assert set(new_value.required_evidence_ids) == {
        "temporal-guralp:update-a-fmus",
        "temporal-guralp:update-a-min",
    }
    index = PacketIndexV6.model_validate_json(V6_INDEX.read_text(encoding="utf-8"))
    packet = next(item for item in index.packets if item.case_id == question.case_id)
    aliases = {
        binding.evidence_id: binding.span_alias
        for binding in index.evaluator_bindings[packet.packet_id]
        for binding in binding.evidence
    }
    components = [
        CandidateComponent(
            kind=item.kind,
            predicate=item.predicate,
            datatype=item.datatype,
            value=item.value,
            authority_scope=item.authority_scope,
            cited_span_aliases=[aliases[value] for value in item.required_evidence_ids],
        )
        for item in question.expected_components
    ]
    alias_map = {alias: evidence_id for evidence_id, alias in aliases.items()}
    assert grade_v4_outcome(
        question,
        components=components,
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )
    missing_fmus = [
        component.model_copy(
            update={
                "cited_span_aliases": [
                    alias
                    for alias in component.cited_span_aliases
                    if alias != aliases["temporal-guralp:update-a-fmus"]
                ]
            }
        )
        for component in components
    ]
    assert not grade_v4_outcome(
        question,
        components=missing_fmus,
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )


def test_v6_hashes_and_clean_packets_are_self_consistent() -> None:
    corpus = _v6()
    index = PacketIndexV6.model_validate_json(V6_INDEX.read_text(encoding="utf-8"))
    assert len(corpus.questions) == 64
    assert len(index.packets) == 64
    assert index.corpus_sha256 == corpus.corpus_sha256
    corpus_body = corpus.model_dump(mode="json", exclude={"corpus_sha256"})
    assert canonical_sha256(corpus_body) == corpus.corpus_sha256


def test_central_diverse_policy_and_exact_grader_fail_closed() -> None:
    corpus = _v6()
    index = PacketIndexV6.model_validate_json(V6_INDEX.read_text(encoding="utf-8"))
    predicates = {
        "source.temporal_change",
        "source.authority_divergence",
        "source.multi_source_synthesis",
    }
    for predicate in predicates:
        validate_authority_policy_predicate(
            PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION, predicate
        )
        question = next(
            item
            for item in corpus.questions
            if item.predicate == predicate and item.outcome_type != "abstain"
        )
        packet = next(
            item for item in index.packets if item.case_id == question.case_id
        )
        aliases = {
            binding.evidence_id: binding.span_alias
            for binding in index.evaluator_bindings[packet.packet_id]
            for binding in binding.evidence
        }
        alias_map = {alias: evidence_id for evidence_id, alias in aliases.items()}
        components = [
            CandidateComponent(
                kind=item.kind,
                predicate=item.predicate,
                datatype=item.datatype,
                value=item.value,
                authority_scope=item.authority_scope,
                cited_span_aliases=[
                    aliases[value] for value in item.required_evidence_ids
                ],
            )
            for item in question.expected_components
        ]
        assert grade_portfolio_diverse_outcome(
            question,
            components=components,
            abstained=False,
            abstention_reason_code=None,
            span_alias_to_evidence_id=alias_map,
        )
        alternate_authority_wording = components[0].model_copy(
            update={"authority_scope": "natural-language source description"}
        )
        assert grade_portfolio_diverse_outcome(
            question,
            components=[alternate_authority_wording, *components[1:]],
            abstained=False,
            abstention_reason_code=None,
            span_alias_to_evidence_id=alias_map,
        )
        assert not grade_portfolio_diverse_outcome(
            question,
            components=[*components, components[0]],
            abstained=False,
            abstention_reason_code=None,
            span_alias_to_evidence_id=alias_map,
        )
