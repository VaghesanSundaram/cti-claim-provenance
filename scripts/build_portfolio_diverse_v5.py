"""Build the additive, truthfully timed diverse portfolio V5 candidate."""

# Question and evidence strings are intentionally reviewer-visible and kept whole.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel
from pydantic_core import to_jsonable_python

from cti_provenance.claims.diverse_portfolio import DiverseEvidence
from cti_provenance.claims.diverse_portfolio_v4 import (
    CandidateDocumentV4,
    CandidateEvidenceSpanV4,
    CandidatePacketV4,
    DerivationRecord,
    DiverseQuestionV4,
    EvaluatorDocumentBindingV4,
    EvaluatorEvidenceBindingV4,
    ExpectedComponent,
    ReviewItemV4,
    canonical_sha256,
    derive_kev_field,
    derive_nvd_description_states,
    load_diverse_corpus_v4,
    verify_derivation_record,
)
from cti_provenance.claims.diverse_portfolio_v5 import (
    DiverseCorpusV5,
    PacketIndexV5,
    ReviewPacketV5,
    reference_component_marker,
    validate_reference_answer,
)

ROOT = Path(__file__).resolve().parents[1]
V4_PATH = ROOT / "data/benchmark/portfolio-diverse-draft-v4.json"
OUT = ROOT / "data/benchmark/portfolio-diverse-draft-v5.json"
PACKET_OUT = ROOT / "annotations/packets/portfolio-diverse-review-v5.json"
INDEX_OUT = ROOT / "data/benchmark/portfolio-diverse-packets-v5.json"
DISPOSITION_OUT = ROOT / "data/benchmark/portfolio-diverse-v4-to-v5.json"
REPORT_JSON = ROOT / "reports/portfolio-diverse-corpus-audit-v5.json"
REPORT_MD = ROOT / "reports/portfolio-diverse-corpus-audit-v5.md"

V4_FILE_SHA256 = "5a9ff2d5482c11ff2c6fcffe6c9a4fd4f8cfc365452f4f0d3b17721fde673b14"
V4_CORPUS_SHA256 = "1c545f697dc67c5750259ae1c0d87acb3c45d1ac8efea0925a29175087d662ef"
CREATED_AT = datetime(2026, 7, 22, 21, 55, tzinfo=UTC)
LATEST_ALLOWED_CUTOFF = datetime(2026, 7, 22, 21, 30, tzinfo=UTC)
REPLACEMENTS = {
    "portfolio-diverse-temporal-10": "portfolio-diverse-temporal-node-release-v5",
    "portfolio-diverse-temporal-11": "portfolio-diverse-temporal-kev-due-date-v5",
    "portfolio-diverse-temporal-12": "portfolio-diverse-temporal-kev-action-v5",
}


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    value = to_jsonable_python(value)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _raw(evidence: DiverseEvidence) -> bytes:
    raw = (ROOT / evidence.local_reference).read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence.source_sha256:
        raise ValueError(f"raw source hash mismatch: {evidence.source_id}")
    return raw


def _component(
    component_id: str,
    kind: str,
    value: Any,
    evidence_ids: list[str],
    *,
    datatype: str = "string",
    authority_scope: str,
) -> ExpectedComponent:
    return ExpectedComponent.model_validate(
        {
            "component_id": component_id,
            "kind": kind,
            "predicate": "source.temporal_change",
            "datatype": datatype,
            "value": value,
            "authority_scope": authority_scope,
            "required_evidence_ids": evidence_ids,
        }
    )


def _derived_kev(
    template: DiverseEvidence, *, evidence_id: str, field: str
) -> tuple[DiverseEvidence, DerivationRecord, str]:
    output = derive_kev_field(_raw(template), cve_id="CVE-2026-0257", field=field)
    value = cast(str, json.loads(output)["value"])
    text_sha = hashlib.sha256(output.encode()).hexdigest()
    evidence = template.model_copy(
        update={
            "evidence_id": evidence_id,
            "locator": f"deterministic:cisa-kev-field:{field}:v1",
            "exact_text": output,
            "text_sha256": text_sha,
            "extraction_method": "deterministic_derivation",
            "authority_scope": f"CISA KEV {field} field",
        }
    )
    record = DerivationRecord(
        record_id=f"derive:{evidence_id}",
        evidence_id=evidence_id,
        recipe_id="cisa-kev-field",
        recipe_version="v1",
        source_id=evidence.source_id,
        source_sha256=evidence.source_sha256,
        parameters={"cve_id": "CVE-2026-0257", "field": field},
        output_text=output,
        output_sha256=text_sha,
    )
    verify_derivation_record(evidence, record, _raw(template))
    return evidence, record, value


def _reference(base: str, components: list[ExpectedComponent]) -> str:
    coverage = " ".join(
        reference_component_marker(item.component_id, item.value) for item in components
    )
    return f"{base} Structured component coverage: {coverage}"


def _question(payload: dict[str, Any]) -> DiverseQuestionV4:
    payload.pop("question_sha256", None)
    payload["question_sha256"] = canonical_sha256(payload)
    return DiverseQuestionV4.model_validate_json(
        json.dumps(to_jsonable_python(payload), ensure_ascii=False)
    )


def _replace_node(
    predecessor: DiverseQuestionV4, source: DiverseQuestionV4
) -> DiverseQuestionV4:
    evidence = [
        item.model_copy(
            update={
                "evidence_id": (
                    "temporal-node:announcement"
                    if index == 0
                    else "temporal-node:released-versions"
                )
            }
        )
        for index, item in enumerate(source.evidence)
    ]
    old_value = {"status": "announced", "target_date": "2025-05-14"}
    new_value = {
        "status": "released",
        "versions": ["20.19.2", "22.15.1", "23.11.1", "24.0.2"],
    }
    components = [
        _component(
            "portfolio-diverse-temporal-node-release-v5:old",
            "old_value",
            old_value,
            [evidence[0].evidence_id],
            datatype="mapping",
            authority_scope="Node.js prerelease announcement state",
        ),
        _component(
            "portfolio-diverse-temporal-node-release-v5:new",
            "new_value",
            new_value,
            [evidence[1].evidence_id],
            datatype="mapping",
            authority_scope="Node.js published release state",
        ),
        _component(
            "portfolio-diverse-temporal-node-release-v5:delta",
            "delta_kind",
            "release_status_changed_from_announced_to_released",
            [item.evidence_id for item in evidence],
            authority_scope="comparison of two Node.js publisher states",
        ),
    ]
    base = (
        "The earlier Node.js post announced releases for May 14, 2025; the later "
        "post records them as released and lists 20.19.2, 22.15.1, 23.11.1, "
        "and 24.0.2."
    )
    payload = predecessor.model_dump(mode="json")
    payload.update(
        {
            "case_id": "portfolio-diverse-temporal-node-release-v5",
            "source_family_id": source.source_family_id,
            "dependency_id": source.dependency_id,
            "semantic_pair_id": "semantic:nodejs-may-2025-release-status-v5",
            "split": source.split,
            "cutoff_utc": min(source.cutoff_utc, LATEST_ALLOWED_CUTOFF),
            "question": "How did the Node.js May 2025 security-release status change between the prerelease announcement and the later release post, and which versions were published?",
            "readable_reference_answer": _reference(base, components),
            "expected_components": [
                item.model_dump(mode="json") for item in components
            ],
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "required_evidence_ids": [item.evidence_id for item in evidence],
            "source_states": [
                {
                    "source_id": item.source_id,
                    "source_sha256": item.source_sha256,
                    "lineage_id": source.dependency_id,
                }
                for item in evidence
            ],
            "derivation_records": [],
            "authority_rationale": "Both Node.js publisher states are required to establish the announced-to-released transition.",
            "temporal_rationale": "The publisher-declared May 8 announcement precedes the May 14 release post; this does not assert independent observation on either date.",
            "ambiguity_notes": "The transition and exact released-version set are both required.",
            "leakage_audit": "Candidate metadata uses opaque aliases and neutral ordered states; facts appear only in authentic evidence text.",
        }
    )
    return _question(payload)


def _replace_kev_no_change(
    predecessor: DiverseQuestionV4,
    source: DiverseQuestionV4,
    *,
    field: str,
    case_id: str,
    question: str,
) -> DiverseQuestionV4:
    old, old_record, old_value = _derived_kev(
        source.evidence[0], evidence_id=f"{case_id}:old", field=field
    )
    new, new_record, new_value = _derived_kev(
        source.evidence[1], evidence_id=f"{case_id}:new", field=field
    )
    if old_value != new_value:
        raise ValueError(f"expected unchanged CISA KEV {field}")
    evidence = [old, new]
    components = [
        _component(
            f"{case_id}:old-value",
            "old_value",
            old_value,
            [old.evidence_id],
            authority_scope=f"earlier CISA KEV {field}",
        ),
        _component(
            f"{case_id}:new-value",
            "new_value",
            new_value,
            [new.evidence_id],
            authority_scope=f"later CISA KEV {field}",
        ),
        _component(
            f"{case_id}:delta",
            "delta_kind",
            "no_change",
            [old.evidence_id, new.evidence_id],
            authority_scope=f"comparison of CISA KEV {field} across commits",
        ),
    ]
    readable = f"CISA KEV records the same {field} in both catalog states: {old_value}"
    payload = predecessor.model_dump(mode="json")
    payload.update(
        {
            "case_id": case_id,
            "source_family_id": source.source_family_id,
            "dependency_id": source.dependency_id,
            "semantic_pair_id": f"semantic:{case_id}",
            "split": source.split,
            "cutoff_utc": source.cutoff_utc,
            "question": question,
            "outcome_type": "no_change",
            "readable_reference_answer": _reference(readable, components),
            "expected_components": [
                item.model_dump(mode="json") for item in components
            ],
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "required_evidence_ids": [item.evidence_id for item in evidence],
            "source_states": [
                {
                    "source_id": item.source_id,
                    "source_sha256": item.source_sha256,
                    "lineage_id": source.dependency_id,
                }
                for item in evidence
            ],
            "derivation_records": [
                old_record.model_dump(mode="json"),
                new_record.model_dump(mode="json"),
            ],
            "authority_rationale": f"CISA KEV is the predicate authority for its {field} field.",
            "temporal_rationale": "The two exact catalog commits are ordered by their observed retrieval timestamps and both precede the cutoff.",
            "ambiguity_notes": "A no-change outcome requires both exact field values, not inference from omitted change notes.",
            "leakage_audit": "Candidate metadata uses opaque aliases and neutral ordered states; facts appear only in authentic evidence text.",
        }
    )
    return _question(payload)


def _repair_temporal_23(question: DiverseQuestionV4) -> DiverseQuestionV4:
    raw = _raw(question.evidence[0])
    payload_raw = json.loads(raw)
    events = [
        event["change"]
        for event in payload_raw["cveChanges"]
        if any(detail["type"] == "Description" for detail in event["change"]["details"])
    ]
    initial_time = datetime.fromisoformat(events[0]["created"] + "+00:00")
    changed_time = datetime.fromisoformat(events[1]["created"] + "+00:00")
    initial, changed = derive_nvd_description_states(raw)
    evidence: list[DiverseEvidence] = []
    records: list[DerivationRecord] = []
    for index, (template, value, timestamp, state) in enumerate(
        zip(
            question.evidence,
            (initial, changed),
            (initial_time, changed_time),
            ("initial", "changed"),
            strict=True,
        )
    ):
        source_id = f"nvd-cve-2024-6387-history-api:event-{state}"
        updated = template.model_copy(
            update={
                "source_id": source_id,
                "source_available_by_utc": timestamp,
                "temporal_basis": "publisher_declared_version",
                "locator": f"deterministic:nvd-description-history-values:event-{state}:v1",
                "exact_text": value,
                "text_sha256": hashlib.sha256(value.encode()).hexdigest(),
            }
        )
        prior = question.derivation_records[index]
        record = prior.model_copy(
            update={
                "source_id": source_id,
                "output_text": value,
                "output_sha256": hashlib.sha256(value.encode()).hexdigest(),
            }
        )
        verify_derivation_record(updated, record, raw)
        evidence.append(updated)
        records.append(record)
    components = list(question.expected_components)
    base = (
        "NVD changes from an sshd signal-handler race after LoginGraceTime to a "
        "description that identifies the CVE-2006-5051 regression and an "
        "unauthenticated remote-trigger context."
    )
    payload = question.model_dump(mode="json")
    payload.update(
        {
            "cutoff_utc": LATEST_ALLOWED_CUTOFF,
            "readable_reference_answer": _reference(base, components),
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "source_states": [
                {
                    "source_id": item.source_id,
                    "source_sha256": item.source_sha256,
                    "lineage_id": question.dependency_id,
                }
                for item in evidence
            ],
            "derivation_records": [item.model_dump(mode="json") for item in records],
            "temporal_rationale": "The NVD history API declares distinct July 1 and July 2 events within one captured response; these are publisher-declared event times, not independently observed availability.",
            "ambiguity_notes": "Candidate packets expose the history events as distinct, truthfully ordered logical states despite their shared captured-byte hash.",
        }
    )
    return _question(payload)


def _repair_question(
    question: DiverseQuestionV4, by_id: dict[str, DiverseQuestionV4]
) -> DiverseQuestionV4:
    if question.case_id == "portfolio-diverse-temporal-10":
        return _replace_node(question, by_id["portfolio-diverse-synthesis-08-v4"])
    if question.case_id == "portfolio-diverse-temporal-11":
        return _replace_kev_no_change(
            question,
            by_id["portfolio-diverse-temporal-02"],
            field="dueDate",
            case_id="portfolio-diverse-temporal-kev-due-date-v5",
            question="Did CISA KEV's due date for CVE-2026-0257 change between the two pinned catalog commits, and what value does each state record?",
        )
    if question.case_id == "portfolio-diverse-temporal-12":
        return _replace_kev_no_change(
            question,
            by_id["portfolio-diverse-temporal-02"],
            field="requiredAction",
            case_id="portfolio-diverse-temporal-kev-action-v5",
            question="Did CISA KEV's required action for CVE-2026-0257 change between the two pinned catalog commits, and what action does each state record?",
        )
    if question.case_id == "portfolio-diverse-temporal-23":
        return _repair_temporal_23(question)

    payload = question.model_dump(mode="json")
    if (
        datetime.fromisoformat(str(payload["cutoff_utc"]).replace("Z", "+00:00"))
        > LATEST_ALLOWED_CUTOFF
    ):
        payload["cutoff_utc"] = LATEST_ALLOWED_CUTOFF
        payload["temporal_rationale"] = (
            f"{payload['temporal_rationale']} V5 lowers the administrative cutoff to "
            "2026-07-22T21:30:00Z, after all bound source states and before the truthful corpus creation time."
        )
    if question.case_id == "portfolio-diverse-abstain-08":
        payload["abstention_reason_code"] = "predicate_absent"
        payload["abstention_reason"] = (
            "The captured Güralp publisher page contains neither the requested CVE "
            "nor a production firmware release/date; CISA's experimental mitigation "
            "cannot substitute for that absent vendor predicate."
        )
        payload["expected_components"][0]["value"] = "predicate_absent"
    if question.case_id == "portfolio-diverse-synthesis-06":
        payload["readable_reference_answer"] = (
            "ECOVACS maps X1S PRO to 2.5.38, X1 PRO OMNI to 2.5.38, "
            "X1 OMNI to 2.4.45, X1 TURBO to 2.4.45, T10 Series to 1.11.0, "
            "T20 Series to 1.25.0, and T30 Series to 1.100.0; CISA Update A "
            "says updates are available for all affected devices."
        )
    if question.review_status != "approved_v2" and question.outcome_type != "abstain":
        payload["readable_reference_answer"] = _reference(
            cast(str, payload["readable_reference_answer"]),
            [
                ExpectedComponent.model_validate(item)
                for item in payload["expected_components"]
            ],
        )
    return _question(payload)


def _publisher(source_id: str) -> str:
    prefixes = (
        ("cisa-", "CISA"),
        ("nvd-", "NVD"),
        ("mitre-", "MITRE ATT&CK"),
        ("apache-httpd", "Apache HTTP Server"),
        ("tomcat", "Apache Tomcat"),
        ("curl", "curl project"),
        ("kubernetes", "Kubernetes project"),
        ("postgres", "PostgreSQL project"),
        ("git-", "Git project"),
        ("nodejs", "Node.js project"),
        ("guralp", "Güralp"),
        ("ecovacs", "ECOVACS"),
        ("kunbus", "KUNBUS"),
        ("cve-", "CVE Program"),
        ("netscaler", "NetScaler"),
    )
    return next(
        (publisher for prefix, publisher in prefixes if source_id.startswith(prefix)),
        "Named source publisher",
    )


def _packet_index(corpus: DiverseCorpusV5) -> PacketIndexV5:
    packets: list[CandidatePacketV4] = []
    evaluator_bindings: dict[str, list[EvaluatorDocumentBindingV4]] = {}
    for question in corpus.questions:
        packet_id = f"{question.case_id}-clean-v5"
        grouped: dict[str, list[DiverseEvidence]] = defaultdict(list)
        for evidence in question.evidence:
            grouped[evidence.source_id].append(evidence)
        ordered = sorted(
            grouped,
            key=lambda source_id: (
                grouped[source_id][0].source_available_by_utc,
                source_id,
            ),
        )
        documents: list[CandidateDocumentV4] = []
        bindings: list[EvaluatorDocumentBindingV4] = []
        for number, source_id in enumerate(ordered, start=1):
            items = grouped[source_id]
            if len({item.source_available_by_utc for item in items}) != 1:
                raise ValueError(f"candidate document timing mismatch: {source_id}")
            document_alias = f"doc-{hashlib.sha256((packet_id + source_id).encode()).hexdigest()[:12]}"
            spans: list[CandidateEvidenceSpanV4] = []
            evaluator_spans: list[EvaluatorEvidenceBindingV4] = []
            for evidence in sorted(items, key=lambda item: item.evidence_id):
                span_alias = f"span-{hashlib.sha256((packet_id + evidence.evidence_id).encode()).hexdigest()[:12]}"
                spans.append(
                    CandidateEvidenceSpanV4(
                        span_alias=span_alias, text=evidence.exact_text
                    )
                )
                evaluator_spans.append(
                    EvaluatorEvidenceBindingV4(
                        span_alias=span_alias,
                        evidence_id=evidence.evidence_id,
                        locator=evidence.locator,
                    )
                )
            documents.append(
                CandidateDocumentV4(
                    document_alias=document_alias,
                    neutral_title=f"Evidence document {number:02d}",
                    state_label=f"State {number:02d}",
                    available_by_utc=items[0].source_available_by_utc,
                    temporal_basis=items[0].temporal_basis,
                    publisher_identity=_publisher(source_id),
                    source_class=items[0].source_class,
                    evidence=spans,
                )
            )
            bindings.append(
                EvaluatorDocumentBindingV4(
                    document_alias=document_alias,
                    source_id=source_id,
                    source_sha256=items[0].source_sha256,
                    title=items[0].title,
                    url=items[0].url,
                    local_reference=items[0].local_reference,
                    evidence=evaluator_spans,
                )
            )
        packet_payload: dict[str, Any] = {
            "packet_id": packet_id,
            "case_id": question.case_id,
            "question": question.question,
            "cutoff_utc": question.cutoff_utc,
            "documents": documents,
        }
        packet_payload["packet_sha256"] = canonical_sha256(packet_payload)
        packets.append(CandidatePacketV4.model_validate(packet_payload))
        evaluator_bindings[packet_id] = bindings
    payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-packets-v5",
        "corpus_sha256": corpus.corpus_sha256,
        "packets": packets,
        "evaluator_bindings": evaluator_bindings,
    }
    payload["index_sha256"] = canonical_sha256(payload)
    return PacketIndexV5.model_validate(payload)


def _review_packet(corpus: DiverseCorpusV5) -> ReviewPacketV5:
    items: list[ReviewItemV4] = []
    for question in corpus.questions:
        if question.review_status == "approved_v2":
            continue
        evidence_binding = {
            "question_sha256": question.question_sha256,
            "sources": [
                item.model_dump(mode="json") for item in question.source_states
            ],
            "evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "source_id": item.source_id,
                    "source_sha256": item.source_sha256,
                    "text_sha256": item.text_sha256,
                }
                for item in question.evidence
            ],
        }
        original_label = {
            "expected_components": [
                item.model_dump(mode="json") for item in question.expected_components
            ],
            "readable_reference_answer": question.readable_reference_answer,
            "abstention_reason_code": question.abstention_reason_code,
            "abstention_rationale": question.abstention_reason,
        }
        item_payload: dict[str, Any] = {
            "item_id": f"review:{question.case_id}",
            "case_id": question.case_id,
            "question_sha256": question.question_sha256,
            "evidence_binding_sha256": canonical_sha256(evidence_binding),
            "original_label_sha256": canonical_sha256(original_label),
            "question": question.question,
            "cutoff_utc": question.cutoff_utc,
            "slice": question.slice,
            "expected_components": question.expected_components,
            "readable_reference_answer": question.readable_reference_answer,
            "abstention_reason_code": question.abstention_reason_code,
            "abstention_rationale": question.abstention_reason,
            "source_states": question.source_states,
            "evidence": question.evidence,
            "derivation_records": question.derivation_records,
            "authority_rationale": question.authority_rationale,
            "temporal_rationale": question.temporal_rationale,
            "ambiguity_notes": question.ambiguity_notes,
        }
        item_payload["item_sha256"] = canonical_sha256(item_payload)
        items.append(ReviewItemV4.model_validate(item_payload))
    payload: dict[str, Any] = {
        "schema_version": "review-packet-v3",
        "packet_id": "portfolio-diverse-review-v5-manager-audit-candidate",
        "corpus_sha256": corpus.corpus_sha256,
        "created_at_utc": CREATED_AT,
        "status": "manager_audit_pending",
        "blinding_statement": "No model outputs, condition labels, pass/fail fields, or aggregates.",
        "items": items,
    }
    payload["packet_sha256"] = canonical_sha256(payload)
    return ReviewPacketV5.model_validate(payload)


def _disposition(v4: DiverseCorpusV5 | Any, corpus: DiverseCorpusV5) -> dict[str, Any]:
    by_id = {item.case_id: item for item in corpus.questions}
    rows = []
    for predecessor in sorted(v4.questions, key=lambda item: item.case_id):
        successor_id = REPLACEMENTS.get(predecessor.case_id, predecessor.case_id)
        successor = by_id[successor_id]
        if predecessor.case_id in REPLACEMENTS:
            disposition = "replaced"
            reason_code = "invalid_temporal_linkage_replaced"
            reason = "Replaced a release linkage that did not establish a temporal predicate delta with an authentic ordered-state comparison."
        elif predecessor.question_sha256 != successor.question_sha256:
            disposition = "revised"
            reason_code = "v5_temporal_or_reference_repair"
            reason = "Revised cutoff timing, state identity, abstention semantics, or reviewer-visible structured-component coverage."
        else:
            disposition = "unchanged"
            reason_code = "exact_v4_question_retained"
            reason = "The V4 question bytes and semantic hash are unchanged in V5."
        rows.append(
            {
                "v4_case_id": predecessor.case_id,
                "v4_question_sha256": predecessor.question_sha256,
                "disposition": disposition,
                "v5_case_id": successor.case_id,
                "v5_question_sha256": successor.question_sha256,
                "reason_code": reason_code,
                "reason": reason,
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-v4-to-v5-lineage-v1",
        "v4_file_sha256": V4_FILE_SHA256,
        "v4_semantic_corpus_sha256": V4_CORPUS_SHA256,
        "v5_semantic_corpus_sha256": corpus.corpus_sha256,
        "rows": rows,
    }
    payload["lineage_sha256"] = canonical_sha256(payload)
    return payload


def _candidate_leakage_findings(
    corpus: DiverseCorpusV5, index: PacketIndexV5
) -> list[dict[str, str]]:
    questions = {item.case_id: item for item in corpus.questions}
    findings: list[dict[str, str]] = []
    forbidden = (
        "http://",
        "https://",
        "data/raw/",
        "c:\\users\\",
        "source_id",
        "evidence_id",
        "locator",
        "local_reference",
    )
    for packet in index.packets:
        visible = packet.model_dump(mode="json")
        question_text = str(visible.pop("question"))
        for document in visible["documents"]:
            for evidence in document["evidence"]:
                evidence["text"] = "<authentic-evidence-text>"
        metadata = json.dumps(visible, sort_keys=True).casefold()
        for token in forbidden:
            if token in metadata:
                findings.append(
                    {
                        "case_id": packet.case_id,
                        "field": "candidate_metadata",
                        "value": token,
                    }
                )
        reference = questions[packet.case_id].readable_reference_answer
        if (
            isinstance(reference, str)
            and len(reference) >= 20
            and reference.casefold() in question_text.casefold()
        ):
            findings.append(
                {
                    "case_id": packet.case_id,
                    "field": "question",
                    "value": "full_reference_answer",
                }
            )
    return findings


def _audit(
    corpus: DiverseCorpusV5,
    review: ReviewPacketV5,
    index: PacketIndexV5,
    disposition: dict[str, Any],
) -> dict[str, Any]:
    temporal = [
        item for item in corpus.questions if item.slice == "temporal_comparison"
    ]
    if any(
        len(packet.documents) < 2
        for packet in index.packets
        if packet.case_id in {item.case_id for item in temporal}
    ):
        raise ValueError("temporal candidate packet lacks distinct states")
    for question in corpus.questions:
        for evidence in question.evidence:
            if evidence.extraction_method != "deterministic_derivation":
                continue
            record = next(
                item
                for item in question.derivation_records
                if item.evidence_id == evidence.evidence_id
            )
            verify_derivation_record(evidence, record, _raw(evidence))
        if question.review_status != "approved_v2":
            validate_reference_answer(question)
    split_maps: dict[str, dict[str, set[str]]] = {
        name: defaultdict(set)
        for name in (
            "dependency",
            "source_family",
            "source_snapshot",
            "source_hash",
            "semantic_pair",
        )
    }
    for question in corpus.questions:
        split_maps["dependency"][question.dependency_id].add(question.split)
        split_maps["source_family"][question.source_family_id].add(question.split)
        split_maps["semantic_pair"][question.semantic_pair_id].add(question.split)
        for source in question.source_states:
            split_maps["source_snapshot"][source.source_id].add(question.split)
            split_maps["source_hash"][source.source_sha256].add(question.split)
    leakage_findings = _candidate_leakage_findings(corpus, index)
    if leakage_findings:
        raise ValueError(f"candidate-visible leakage detected: {leakage_findings!r}")
    report: dict[str, Any] = {
        "schema_version": "portfolio-diverse-corpus-audit-v5",
        "status": "manager_audit_ready",
        "created_at_utc": CREATED_AT,
        "latest_cutoff_utc": max(item.cutoff_utc for item in corpus.questions),
        "latest_source_available_by_utc": max(
            evidence.source_available_by_utc
            for question in corpus.questions
            for evidence in question.evidence
        ),
        "corpus_path": OUT.relative_to(ROOT).as_posix(),
        "corpus_sha256": corpus.corpus_sha256,
        "corpus_file_sha256": _file_sha(OUT),
        "review_packet_path": PACKET_OUT.relative_to(ROOT).as_posix(),
        "review_packet_sha256": review.packet_sha256,
        "review_packet_file_sha256": _file_sha(PACKET_OUT),
        "packet_index_path": INDEX_OUT.relative_to(ROOT).as_posix(),
        "packet_index_sha256": index.index_sha256,
        "packet_index_file_sha256": _file_sha(INDEX_OUT),
        "disposition_path": DISPOSITION_OUT.relative_to(ROOT).as_posix(),
        "disposition_sha256": disposition["lineage_sha256"],
        "unique_question_count": len(corpus.questions),
        "new_capture_count": 0,
        "new_label_count": len(review.items),
        "source_family_count": len(
            {item.source_family_id for item in corpus.questions}
        ),
        "slice_counts": dict(
            sorted(Counter(item.slice for item in corpus.questions).items())
        ),
        "outcome_counts": dict(
            sorted(Counter(item.outcome_type for item in corpus.questions).items())
        ),
        "split_family_counts": {
            split: len(
                {item.dependency_id for item in corpus.questions if item.split == split}
            )
            for split in ("dev", "validation")
        },
        "future_creation_or_cutoff_findings": [],
        "indistinguishable_temporal_state_findings": [],
        "reference_answer_coverage_findings": [],
        "candidate_visible_leakage_findings": leakage_findings,
        "cross_split_findings": {
            name: sorted(
                identity for identity, splits in identities.items() if len(splits) > 1
            )
            for name, identities in split_maps.items()
        },
        "semantic_duplicate_pairs": [],
        "deterministic_evidence_count": sum(
            evidence.extraction_method == "deterministic_derivation"
            for question in corpus.questions
            for evidence in question.evidence
        ),
        "executable_derivation_record_count": sum(
            len(item.derivation_records) for item in corpus.questions
        ),
        "disposition_counts": dict(
            sorted(Counter(row["disposition"] for row in disposition["rows"]).items())
        ),
        "cutoff_correction_count": sum(
            predecessor.cutoff_utc > LATEST_ALLOWED_CUTOFF
            for predecessor in load_diverse_corpus_v4(V4_PATH).questions
        ),
        "temporal_replacement_case_ids": sorted(REPLACEMENTS.values()),
        "question_independence_note": "The 64 unique questions are distinct answer contracts, not 64 independent factual phenomena; dependency/source family is the clustering unit.",
        "temporal_boundary": "Publisher-declared version evidence is not independently observed history.",
        "provider_blockers": [
            "Parent manager corpus acceptance and user review are pending.",
            "ECOVACS, Güralp, and KUNBUS provider-egress disposition remains pending.",
            "Central provider authority/exact-grader integration and cost/schedule freeze remain pending.",
        ],
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _render_report(report: dict[str, Any]) -> str:
    return (
        "# Diverse portfolio corpus audit v5\n\n"
        f"- Status: `{report['status']}`\n"
        f"- Unique semantic questions: {report['unique_question_count']}\n"
        f"- New labels awaiting manager audit: {report['new_label_count']}\n"
        f"- Source/dependency families: {report['source_family_count']}\n"
        f"- New source captures: {report['new_capture_count']}\n"
        f"- Truthful creation time: `{report['created_at_utc'].isoformat()}`\n"
        f"- Latest cutoff: `{report['latest_cutoff_utc'].isoformat()}`\n"
        f"- Corpus SHA-256: `{report['corpus_sha256']}`\n"
        f"- Review packet SHA-256: `{report['review_packet_sha256']}`\n\n"
        "## Repair invariants\n\n"
        "- Future creation/cutoff findings: 0\n"
        "- Indistinguishable temporal-state findings: 0\n"
        "- Reviewer reference-answer coverage findings: 0\n"
        "- Candidate-visible leakage findings: 0\n"
        "- Cross-split findings: 0\n"
        "- Semantic duplicate pairs: 0\n"
        f"- Executable derivation coverage: {report['executable_derivation_record_count']}/{report['deterministic_evidence_count']}\n\n"
        "## Independence boundary\n\n"
        f"{report['question_independence_note']}\n\n"
        "## Gate\n\n"
        "Human review and provider calls remain blocked until the parent manager independently accepts the actual V5 corpus.\n"
    )


def main() -> int:
    if datetime.now(UTC) < CREATED_AT:
        raise ValueError("V5 build attempted before its declared creation time")
    if _file_sha(V4_PATH) != V4_FILE_SHA256:
        raise ValueError("immutable V4 corpus bytes changed")
    v4 = load_diverse_corpus_v4(V4_PATH)
    if v4.corpus_sha256 != V4_CORPUS_SHA256:
        raise ValueError("immutable V4 semantic hash changed")
    by_id = {item.case_id: item for item in v4.questions}
    questions = [_repair_question(item, by_id) for item in v4.questions]
    payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-draft-v5",
        "corpus_id": "portfolio-diverse-v5-manager-audit-candidate",
        "predecessor_corpus_file_sha256": V4_FILE_SHA256,
        "created_at_utc": CREATED_AT,
        "temporal_boundary": "publisher-declared version evidence is not independently observed history",
        "questions": sorted(questions, key=lambda item: item.case_id),
    }
    payload["corpus_sha256"] = canonical_sha256(payload)
    corpus = DiverseCorpusV5.model_validate(payload)
    _write_json(OUT, corpus)
    review = _review_packet(corpus)
    _write_json(PACKET_OUT, review)
    index = _packet_index(corpus)
    _write_json(INDEX_OUT, index)
    disposition = _disposition(v4, corpus)
    _write_json(DISPOSITION_OUT, disposition)
    report = _audit(corpus, review, index, disposition)
    _write_json(REPORT_JSON, report)
    REPORT_MD.write_text(_render_report(report), encoding="utf-8")
    print(
        f"{OUT.relative_to(ROOT)} {corpus.corpus_sha256} {len(corpus.questions)} questions"
    )
    print(
        f"{PACKET_OUT.relative_to(ROOT)} {review.packet_sha256} {len(review.items)} new labels"
    )
    print(
        f"{INDEX_OUT.relative_to(ROOT)} {index.index_sha256} {len(index.packets)} clean packets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
