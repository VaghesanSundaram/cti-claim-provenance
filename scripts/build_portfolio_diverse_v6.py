"""Build the narrow, additive V6 successor approved by the single reviewer."""

# Reviewer-visible evidence strings are intentionally kept whole.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic_core import to_jsonable_python

from cti_provenance.claims.diverse_portfolio import DiverseEvidence
from cti_provenance.claims.diverse_portfolio_v4 import (
    CandidateDocumentV4,
    CandidateEvidenceSpanV4,
    CandidatePacketV4,
    DiverseQuestionV4,
    EvaluatorDocumentBindingV4,
    EvaluatorEvidenceBindingV4,
    ExpectedComponent,
    ReviewItemV4,
    SourceStateBinding,
    canonical_sha256,
    verify_derivation_record,
)
from cti_provenance.claims.diverse_portfolio_v5 import (
    DiverseCorpusV5,
    reference_component_marker,
    validate_reference_answer,
)
from cti_provenance.claims.diverse_portfolio_v6 import (
    DiverseCorpusV6,
    PacketIndexV6,
    ReviewPacketV6,
)

ROOT = Path(__file__).resolve().parents[1]
V5_PATH = ROOT / "data/benchmark/portfolio-diverse-draft-v5.json"
V5_PACKET_PATH = ROOT / "data/benchmark/portfolio-diverse-packets-v5.json"
V5_REVIEW_PATH = ROOT / "annotations/packets/portfolio-diverse-review-v5.json"
DECISIONS_PATH = (
    ROOT / "annotations/decisions/portfolio-diverse-review-v5-reviewer-a17.jsonl"
)
OUT = ROOT / "data/benchmark/portfolio-diverse-draft-v6.json"
INDEX_OUT = ROOT / "data/benchmark/portfolio-diverse-packets-v6.json"
DISPOSITION_OUT = ROOT / "data/benchmark/portfolio-diverse-v5-to-v6.json"
REPORT_JSON = ROOT / "reports/portfolio-diverse-corpus-audit-v6.json"
REPORT_MD = ROOT / "reports/portfolio-diverse-corpus-audit-v6.md"
REPLACEMENT_REVIEW_OUT = (
    ROOT / "annotations/packets/portfolio-diverse-egress-replacements-review-v6.json"
)
REPLACEMENT_REVIEW_MD = (
    ROOT / "annotations/packets/portfolio-diverse-egress-replacements-review-v6.md"
)

V5_COMMITTED_LF_FILE_SHA256 = (
    "03802eaf51465163e05b301e2f1693d6ee0bb04191a00d04495eee797406090c"
)
V5_CORPUS_SHA256 = "ea14d41d242672df1734808c5b0327219fc1eaee7b8fa1109d5131bf1346be20"
V5_PACKET_COMMITTED_LF_FILE_SHA256 = (
    "a926c2cce493de3e620ba08158f00a812d3db017d27507c27ff12d38134b2edb"
)
V5_REVIEW_COMMITTED_LF_FILE_SHA256 = (
    "8af976927b24f7327f4937a341431cee3916d91a1476709083f0603ebd4a03ae"
)
DECISIONS_FILE_SHA256 = (
    "c81b62e16961688208b5348501fd577849e1826039723e493ba1838f84752577"
)
CREATED_AT = datetime(2026, 7, 24, 18, 8, tzinfo=UTC)
APPROVED_CORRECTION_CASE_IDS = frozenset(
    {"portfolio-diverse-authority-06", "portfolio-diverse-temporal-19"}
)
EGRESS_REPLACEMENT_CASE_IDS = frozenset(
    {
        "portfolio-diverse-abstain-08",
        "portfolio-diverse-authority-07-v4",
        "portfolio-diverse-authority-08",
        "portfolio-diverse-synthesis-06",
        "portfolio-diverse-synthesis-07",
    }
)
V5_CHANGED_CASE_IDS = APPROVED_CORRECTION_CASE_IDS | EGRESS_REPLACEMENT_CASE_IDS


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


def _committed_text_sha(path: Path) -> str:
    """Hash the LF-normalized text bytes stored in Git, not checkout rendering."""

    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _raw(evidence: DiverseEvidence) -> bytes:
    raw = (ROOT / evidence.local_reference).read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence.source_sha256:
        raise ValueError(f"raw source hash mismatch: {evidence.source_id}")
    return raw


def _rehash_question(payload: dict[str, Any]) -> DiverseQuestionV4:
    payload.pop("question_sha256", None)
    payload["question_sha256"] = canonical_sha256(payload)
    return DiverseQuestionV4.model_validate_json(
        json.dumps(payload, ensure_ascii=False)
    )


def _authority_correction(question: DiverseQuestionV4) -> DiverseQuestionV4:
    payload = question.model_dump(mode="json")
    full_action = (
        "apply mitigations and kill all active and persistent sessions, "
        "or discontinue use if mitigations are unavailable"
    )
    for component in payload["expected_components"]:
        if component["component_id"] == "portfolio-diverse-authority-06:fact-2":
            component["value"] = full_action
    payload["readable_reference_answer"] = (
        "NetScaler recommends reviewing SSLVPN TCPCONNSTAT for one source IP "
        "accessing multiple users' sessions; CISA KEV requires applying "
        "mitigations and killing all active and persistent sessions, or "
        "discontinuing use if mitigations are unavailable. Structured component "
        'coverage: [portfolio-diverse-authority-06:fact-1="review TCPCONNSTAT '
        'for one source IP across multiple users"] '
        '[portfolio-diverse-authority-06:fact-2="apply mitigations and kill all '
        "active and persistent sessions, or discontinue use if mitigations are "
        'unavailable"]'
    )
    corrected = _rehash_question(payload)
    validate_reference_answer(corrected)
    return corrected


def _temporal_correction(question: DiverseQuestionV4) -> DiverseQuestionV4:
    payload = question.model_dump(mode="json")
    update_min = next(
        evidence
        for evidence in payload["evidence"]
        if evidence["evidence_id"] == "temporal-guralp:update-a-min"
    )
    update_fmus = dict(update_min)
    update_fmus.update(
        {
            "evidence_id": "temporal-guralp:update-a-fmus",
            "locator": "/product_tree/branches/0/branches/0/name",
            "exact_text": "Güralp FMUS Series Seismic Monitoring Devices",
            "text_sha256": hashlib.sha256(
                "Güralp FMUS Series Seismic Monitoring Devices".encode()
            ).hexdigest(),
        }
    )
    raw_payload = json.loads(
        (ROOT / update_fmus["local_reference"]).read_text(encoding="utf-8")
    )
    actual = raw_payload["product_tree"]["branches"][0]["branches"][0]["name"]
    if actual != update_fmus["exact_text"]:
        raise ValueError("Update A FMUS product span changed")
    payload["evidence"].append(update_fmus)
    required = [
        "temporal-guralp:update-a-fmus",
        "temporal-guralp:update-a-min",
    ]
    for component in payload["expected_components"]:
        if component["kind"] == "new_value":
            component["required_evidence_ids"] = required
        elif component["kind"] == "delta_kind":
            component["required_evidence_ids"] = [
                "temporal-guralp:initial-fmus",
                *required,
            ]
    payload["required_evidence_ids"] = [
        "temporal-guralp:initial-fmus",
        *required,
    ]
    corrected = _rehash_question(payload)
    validate_reference_answer(corrected)
    return corrected


def _evidence_for_source(
    questions: dict[str, DiverseQuestionV4], case_id: str, source_id: str
) -> DiverseEvidence:
    return next(
        item for item in questions[case_id].evidence if item.source_id == source_id
    )


def _csaf_remediation_span(
    template: DiverseEvidence, *, evidence_id: str, index: int
) -> DiverseEvidence:
    raw_payload = json.loads(
        (ROOT / template.local_reference).read_text(encoding="utf-8")
    )
    exact_text = raw_payload["vulnerabilities"][0]["remediations"][index]["details"]
    payload = template.model_dump(mode="json")
    payload.update(
        {
            "evidence_id": evidence_id,
            "locator": f"/vulnerabilities/0/remediations/{index}/details",
            "exact_text": exact_text,
            "text_sha256": hashlib.sha256(exact_text.encode()).hexdigest(),
        }
    )
    return DiverseEvidence.model_validate_json(json.dumps(payload, ensure_ascii=False))


def _component(
    *,
    component_id: str,
    kind: str,
    value: object,
    datatype: str,
    authority_scope: str,
    evidence_ids: list[str],
) -> ExpectedComponent:
    return ExpectedComponent.model_validate(
        {
            "component_id": component_id,
            "kind": kind,
            "predicate": (
                "source.multi_source_synthesis"
                if kind == "synthesis_fact"
                else "source.authority_divergence"
            ),
            "datatype": datatype,
            "value": value,
            "authority_scope": authority_scope,
            "required_evidence_ids": evidence_ids,
        }
    )


def _replacement_question(
    base: DiverseQuestionV4,
    *,
    question: str,
    readable_reference_answer: str | None,
    evidence: list[DiverseEvidence],
    expected_components: list[ExpectedComponent],
    required_evidence_ids: list[str],
    authority_rationale: str,
    temporal_rationale: str,
    ambiguity_notes: str,
    abstention_reason: str | None = None,
    abstention_reason_code: str | None = None,
) -> DiverseQuestionV4:
    payload = base.model_dump(mode="json")
    payload.update(
        {
            "question": question,
            "readable_reference_answer": readable_reference_answer,
            "evidence": [item.model_dump(mode="json") for item in evidence],
            "expected_components": [
                item.model_dump(mode="json") for item in expected_components
            ],
            "required_evidence_ids": required_evidence_ids,
            "source_states": [
                SourceStateBinding(
                    source_id=item.source_id,
                    source_sha256=item.source_sha256,
                    lineage_id=base.dependency_id,
                ).model_dump(mode="json")
                for item in evidence
            ],
            "derivation_records": [],
            "authority_rationale": authority_rationale,
            "temporal_rationale": temporal_rationale,
            "ambiguity_notes": ambiguity_notes,
            "leakage_audit": (
                "Candidate-visible aliases and titles are neutral; source roles, "
                "gold values, and replacement disposition remain evaluator-only."
            ),
            "abstention_reason": abstention_reason,
            "abstention_reason_code": abstention_reason_code,
        }
    )
    unique_states: dict[str, dict[str, Any]] = {}
    for item in payload["source_states"]:
        unique_states[item["source_id"]] = item
    payload["source_states"] = list(unique_states.values())
    updated = _rehash_question(payload)
    validate_reference_answer(updated)
    return updated


def _egress_safe_replacements(
    questions: dict[str, DiverseQuestionV4],
) -> dict[str, DiverseQuestionV4]:
    replacements: dict[str, DiverseQuestionV4] = {}

    guralp_update_b = _evidence_for_source(
        questions, "portfolio-diverse-temporal-20", "cisa-icsa-25-212-01-update-b"
    )
    guralp_experimental = _csaf_remediation_span(
        guralp_update_b,
        evidence_id="abstain-guralp:cisa-experimental-firmware",
        index=1,
    )
    guralp_qualification = _csaf_remediation_span(
        guralp_update_b,
        evidence_id="abstain-guralp:cisa-experimental-qualification",
        index=2,
    )
    abstain_base = questions["portfolio-diverse-abstain-08"]
    abstain_component = ExpectedComponent.model_validate(
        {
            "component_id": "portfolio-diverse-abstain-08:reason",
            "kind": "abstention_reason",
            "predicate": "vendor.fixed_versions",
            "datatype": "string",
            "value": "predicate_absent",
            "authority_scope": "cutoff-eligible CISA coordinator evidence",
            "required_evidence_ids": [
                guralp_experimental.evidence_id,
                guralp_qualification.evidence_id,
            ],
        }
    )
    replacements[abstain_base.case_id] = _replacement_question(
        abstain_base,
        question=(
            "Which production-ready firmware release and generally available "
            "release date does CISA Update B establish for remediating "
            "CVE-2025-8286?"
        ),
        readable_reference_answer=None,
        evidence=[guralp_experimental, guralp_qualification],
        expected_components=[abstain_component],
        required_evidence_ids=[
            guralp_experimental.evidence_id,
            guralp_qualification.evidence_id,
        ],
        authority_rationale=(
            "CISA is authoritative for its coordinator record. It records only "
            "an experimental firmware identifier and explicitly requires local "
            "evaluation; it does not establish a production-ready release date."
        ),
        temporal_rationale=(
            "Both exact Update B spans are cutoff-eligible publisher-declared "
            "version evidence; no later source is used to fill the absent predicate."
        ),
        ambiguity_notes=(
            "The experimental identifier must not be upgraded into a generally "
            "available production release or assigned an unstated release date."
        ),
        abstention_reason=(
            "The eligible coordinator record identifies experimental firmware "
            "but establishes neither production-ready status nor a release date."
        ),
        abstention_reason_code="predicate_absent",
    )

    kunbus_initial = _evidence_for_source(
        questions,
        "portfolio-diverse-temporal-24",
        "cisa-icsa-25-121-01-initial",
    )
    kunbus_update = _evidence_for_source(
        questions,
        "portfolio-diverse-temporal-21",
        "cisa-icsa-25-121-01-update-a",
    )
    kunbus_pictory = _csaf_remediation_span(
        kunbus_initial,
        evidence_id="authority-kunbus:cisa-pictory-212",
        index=1,
    )
    kunbus_image = _csaf_remediation_span(
        kunbus_update,
        evidence_id="authority-kunbus:vendor-qualified-image",
        index=3,
    )
    authority7_base = questions["portfolio-diverse-authority-07-v4"]
    authority7_components = [
        _component(
            component_id="portfolio-diverse-authority-07-v4:cisa",
            kind="authority_fact",
            value="update PiCtory to 2.12",
            datatype="string",
            authority_scope="CISA coordinator recommendation authority",
            evidence_ids=[kunbus_pictory.evidence_id],
        ),
        _component(
            component_id="portfolio-diverse-authority-07-v4:vendor-qualified",
            kind="authority_fact",
            value="KUNBUS released a Revolution Pi OS Bookworm image on 2025-04-30",
            datatype="string",
            authority_scope="CISA coordinator record of a KUNBUS-qualified release",
            evidence_ids=[kunbus_image.evidence_id],
        ),
    ]
    authority7_answer = (
        "CISA's coordinator recommendation is to update PiCtory to 2.12; "
        "the later coordinator state records the vendor-qualified fact that "
        "KUNBUS released a Revolution Pi OS Bookworm image on 2025-04-30. "
        "Structured component coverage: "
        + " ".join(
            reference_component_marker(item.component_id, item.value)
            for item in authority7_components
        )
    )
    replacements[authority7_base.case_id] = _replacement_question(
        authority7_base,
        question=(
            "Which PiCtory action is CISA's coordinator recommendation, and "
            "which separate Bookworm release fact does its Update A record as "
            "KUNBUS-qualified?"
        ),
        readable_reference_answer=authority7_answer,
        evidence=[kunbus_pictory, kunbus_image],
        expected_components=authority7_components,
        required_evidence_ids=[
            kunbus_pictory.evidence_id,
            kunbus_image.evidence_id,
        ],
        authority_rationale=(
            "The first component is CISA's recommendation; the second is a "
            "vendor-qualified release fact recorded by CISA, not independent "
            "proof from a KUNBUS source."
        ),
        temporal_rationale=(
            "The initial and Update A coordinator states are both eligible and "
            "are used only for what each named state says."
        ),
        ambiguity_notes=(
            "Do not describe the CISA-hosted vendor-qualified release statement "
            "as independently verified vendor evidence."
        ),
    )

    kunbus_method = _csaf_remediation_span(
        kunbus_initial,
        evidence_id="synthesis-kunbus:pictory-cockpit-method",
        index=2,
    )
    kunbus_image_synthesis = _csaf_remediation_span(
        kunbus_update,
        evidence_id="synthesis-kunbus:bookworm-image",
        index=3,
    )
    synthesis7_base = questions["portfolio-diverse-synthesis-07"]
    synthesis7_components = [
        _component(
            component_id="portfolio-diverse-synthesis-07:fact-1",
            kind="synthesis_fact",
            value="update PiCtory to 2.12 through the Cockpit management UI",
            datatype="string",
            authority_scope="CISA initial-state PiCtory update method",
            evidence_ids=[kunbus_method.evidence_id],
        ),
        _component(
            component_id="portfolio-diverse-synthesis-07:fact-2",
            kind="synthesis_fact",
            value="new Revolution Pi OS Bookworm image released 2025-04-30",
            datatype="string",
            authority_scope="CISA Update A vendor-fix record",
            evidence_ids=[kunbus_image_synthesis.evidence_id],
        ),
    ]
    synthesis7_answer = (
        "The initial state says to update PiCtory to 2.12 through the Cockpit "
        "management UI; Update A records a new Revolution Pi OS Bookworm image "
        "released on 2025-04-30. Structured component coverage: "
        + " ".join(
            reference_component_marker(item.component_id, item.value)
            for item in synthesis7_components
        )
    )
    replacements[synthesis7_base.case_id] = _replacement_question(
        synthesis7_base,
        question=(
            "What PiCtory update method does the initial CISA state establish, "
            "and what separate Bookworm image release does Update A add?"
        ),
        readable_reference_answer=synthesis7_answer,
        evidence=[kunbus_method, kunbus_image_synthesis],
        expected_components=synthesis7_components,
        required_evidence_ids=[
            kunbus_method.evidence_id,
            kunbus_image_synthesis.evidence_id,
        ],
        authority_rationale=(
            "CISA is authoritative for the contents of each coordinator state; "
            "the Bookworm release remains explicitly KUNBUS-qualified."
        ),
        temporal_rationale=(
            "The exact initial and Update A states are both required: one binds "
            "the PiCtory delivery method and the other binds the later image release."
        ),
        ambiguity_notes=(
            "This is source-state synthesis from one public coordinator, not "
            "independent cross-publisher corroboration."
        ),
    )

    ecovacs_initial = _evidence_for_source(
        questions,
        "portfolio-diverse-temporal-22",
        "cisa-icsa-25-135-19-initial",
    )
    ecovacs_update = _evidence_for_source(
        questions,
        "portfolio-diverse-temporal-22",
        "cisa-icsa-25-135-19-update-a",
    )
    ecovacs_initial_scope = _csaf_remediation_span(
        ecovacs_initial,
        evidence_id="authority-ecovacs:initial-vendor-fix",
        index=0,
    )
    ecovacs_update_scope = _csaf_remediation_span(
        ecovacs_update,
        evidence_id="authority-ecovacs:update-user-action",
        index=0,
    )
    authority8_base = questions["portfolio-diverse-authority-08"]
    authority8_components = [
        _component(
            component_id="portfolio-diverse-authority-08:fact-1",
            kind="authority_fact",
            value="updates released for X1S PRO and X1 PRO OMNI",
            datatype="string",
            authority_scope="CISA initial coordinator record of ECOVACS vendor-fix scope",
            evidence_ids=[ecovacs_initial_scope.evidence_id],
        ),
        _component(
            component_id="portfolio-diverse-authority-08:fact-2",
            kind="authority_fact",
            value="users complete the fix by performing the system update",
            datatype="string",
            authority_scope="CISA Update A remediation instruction",
            evidence_ids=[ecovacs_update_scope.evidence_id],
        ),
    ]
    authority8_answer = (
        "The initial coordinator state records ECOVACS updates for X1S PRO and "
        "X1 PRO OMNI; Update A instructs users to complete the fix by performing "
        "the system update. Structured component coverage: "
        + " ".join(
            reference_component_marker(item.component_id, item.value)
            for item in authority8_components
        )
    )
    replacements[authority8_base.case_id] = _replacement_question(
        authority8_base,
        question=(
            "Which limited vendor-fix scope does CISA's initial ECOVACS state "
            "record, and which separate user action does Update A prescribe?"
        ),
        readable_reference_answer=authority8_answer,
        evidence=[ecovacs_initial_scope, ecovacs_update_scope],
        expected_components=authority8_components,
        required_evidence_ids=[
            ecovacs_initial_scope.evidence_id,
            ecovacs_update_scope.evidence_id,
        ],
        authority_rationale=(
            "The initial scope is a vendor-fix statement reported in CISA's "
            "coordinator record; the completion action is remediation guidance "
            "stated in Update A."
        ),
        temporal_rationale=(
            "Both named CISA states are eligible publisher-declared versions; "
            "the question does not claim independent observation."
        ),
        ambiguity_notes=(
            "Keep the vendor-qualified update availability distinct from the "
            "coordinator document's user-facing remediation instruction."
        ),
    )

    ecovacs_initial_synthesis = _csaf_remediation_span(
        ecovacs_initial,
        evidence_id="synthesis-ecovacs:initial-deadline",
        index=0,
    )
    ecovacs_update_synthesis = _csaf_remediation_span(
        ecovacs_update,
        evidence_id="synthesis-ecovacs:update-complete-coverage",
        index=0,
    )
    synthesis6_base = questions["portfolio-diverse-synthesis-06"]
    synthesis6_components = [
        _component(
            component_id="portfolio-diverse-synthesis-06:fact-1",
            kind="synthesis_fact",
            value="remaining affected products were scheduled for updates by 2025-05-31",
            datatype="string",
            authority_scope="CISA initial-state vendor-fix schedule",
            evidence_ids=[ecovacs_initial_synthesis.evidence_id],
        ),
        _component(
            component_id="portfolio-diverse-synthesis-06:fact-2",
            kind="synthesis_fact",
            value="software updates available for all affected devices",
            datatype="string",
            authority_scope="CISA Update A remediation coverage",
            evidence_ids=[ecovacs_update_synthesis.evidence_id],
        ),
    ]
    synthesis6_answer = (
        "The initial state scheduled the remaining affected products for updates "
        "by 2025-05-31; Update A records software updates as available for all "
        "affected devices. Structured component coverage: "
        + " ".join(
            reference_component_marker(item.component_id, item.value)
            for item in synthesis6_components
        )
    )
    replacements[synthesis6_base.case_id] = _replacement_question(
        synthesis6_base,
        question=(
            "What update deadline did the initial CISA ECOVACS state give for "
            "the remaining affected products, and what complete coverage does "
            "Update A establish?"
        ),
        readable_reference_answer=synthesis6_answer,
        evidence=[ecovacs_initial_synthesis, ecovacs_update_synthesis],
        expected_components=synthesis6_components,
        required_evidence_ids=[
            ecovacs_initial_synthesis.evidence_id,
            ecovacs_update_synthesis.evidence_id,
        ],
        authority_rationale=(
            "CISA is authoritative for the contents of both coordinator states; "
            "the update schedule and coverage remain ECOVACS-qualified."
        ),
        temporal_rationale=(
            "The initial schedule and Update A completion statement are bound to "
            "separate ordered source states and both are required."
        ),
        ambiguity_notes=(
            "This is source-state synthesis and is correlated with, but not the "
            "same answer contract as, the separate coverage-change question."
        ),
    )
    return replacements


def _publisher(source_id: str) -> str:
    prefixes = {
        "cisa-": "CISA",
        "netscaler-": "NetScaler",
        "nvd-": "NVD",
        "ecovacs-": "ECOVACS",
        "guralp-": "Güralp",
        "kunbus-": "KUNBUS",
    }
    for prefix, publisher in prefixes.items():
        if source_id.startswith(prefix):
            return publisher
    return "Official publisher"


def _packet_index(corpus: DiverseCorpusV6) -> PacketIndexV6:
    packets: list[CandidatePacketV4] = []
    evaluator_bindings: dict[str, list[EvaluatorDocumentBindingV4]] = {}
    for question in corpus.questions:
        packet_id = f"{question.case_id}-clean-v6"
        grouped: dict[str, list[DiverseEvidence]] = defaultdict(list)
        for evidence in question.evidence:
            grouped[evidence.source_id].append(evidence)
        ordered = sorted(
            grouped.items(),
            key=lambda item: (
                item[1][0].source_available_by_utc,
                item[0],
            ),
        )
        documents: list[CandidateDocumentV4] = []
        bindings: list[EvaluatorDocumentBindingV4] = []
        for number, (source_id, items) in enumerate(ordered, start=1):
            document_alias = f"doc-{hashlib.sha256(f'{packet_id}:{number}'.encode()).hexdigest()[:12]}"
            spans: list[CandidateEvidenceSpanV4] = []
            evaluator_spans: list[EvaluatorEvidenceBindingV4] = []
            for span_number, evidence in enumerate(
                sorted(items, key=lambda item: item.evidence_id), start=1
            ):
                span_alias = f"span-{hashlib.sha256(f'{packet_id}:{number}:{span_number}'.encode()).hexdigest()[:12]}"
                spans.append(
                    CandidateEvidenceSpanV4(
                        span_alias=span_alias,
                        text=evidence.exact_text,
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
        "schema_version": "portfolio-diverse-packets-v6",
        "corpus_sha256": corpus.corpus_sha256,
        "packets": packets,
        "evaluator_bindings": evaluator_bindings,
    }
    payload["index_sha256"] = canonical_sha256(payload)
    return PacketIndexV6.model_validate(payload)


def _replacement_review_packet(corpus: DiverseCorpusV6) -> ReviewPacketV6:
    items: list[ReviewItemV4] = []
    by_id = {item.case_id: item for item in corpus.questions}
    for case_id in sorted(EGRESS_REPLACEMENT_CASE_IDS):
        question = by_id[case_id]
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
            "item_id": f"review:{question.case_id}:egress-replacement-v6",
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
        items.append(
            ReviewItemV4.model_validate_json(
                json.dumps(
                    to_jsonable_python(item_payload),
                    ensure_ascii=False,
                )
            )
        )
    payload: dict[str, Any] = {
        "schema_version": "review-packet-v4",
        "packet_id": "portfolio-diverse-v6-egress-replacements-review",
        "corpus_sha256": corpus.corpus_sha256,
        "created_at_utc": CREATED_AT,
        "status": "human_review_open",
        "blinding_statement": (
            "No model outputs, condition labels, pass/fail fields, or aggregates."
        ),
        "items": items,
    }
    payload["packet_sha256"] = canonical_sha256(payload)
    return ReviewPacketV6.model_validate_json(
        json.dumps(to_jsonable_python(payload), ensure_ascii=False)
    )


def _render_replacement_review(packet: ReviewPacketV6) -> str:
    sections = [
        "# Five egress-safe replacement labels for reviewer-a17",
        "",
        f"- Packet SHA-256: `{packet.packet_sha256}`",
        f"- Items: {len(packet.items)}",
        "- Scope: only the five restrictive-source replacements; the other 59 "
        "active contracts are unchanged.",
        "- Human action: approve or correct each proposed label. No model output "
        "is present.",
        "",
    ]
    for number, item in enumerate(packet.items, start=1):
        evidence = "\n".join(
            f"  - `{span.evidence_id}` ({span.source_id}): {span.exact_text}"
            for span in item.evidence
        )
        components = "\n".join(
            f"  - `{component.component_id}`: "
            f"`{json.dumps(component.value, ensure_ascii=False, sort_keys=True)}` "
            f"({component.authority_scope})"
            for component in item.expected_components
        )
        sections.extend(
            [
                f"## {number}. `{item.case_id}`",
                "",
                f"**Question:** {item.question}",
                "",
                f"**Cutoff:** `{item.cutoff_utc.isoformat()}`",
                "",
                f"**Slice:** `{item.slice}`",
                "",
                "**Authentic evidence:**",
                "",
                evidence,
                "",
                "**Proposed structured label:**",
                "",
                components,
                "",
                f"**Reference answer:** {item.readable_reference_answer}",
                "",
                f"**Abstention:** `{item.abstention_reason_code}` — "
                f"{item.abstention_rationale}",
                "",
                f"**Authority rationale:** {item.authority_rationale}",
                "",
                f"**Ambiguity note:** {item.ambiguity_notes}",
                "",
            ]
        )
    return "\n".join(sections).rstrip() + "\n"


def _disposition(v5: DiverseCorpusV5, corpus: DiverseCorpusV6) -> dict[str, Any]:
    old = {item.case_id: item for item in v5.questions}
    new = {item.case_id: item for item in corpus.questions}
    reasons = {
        "portfolio-diverse-authority-06": (
            "cisa_required_action_fallback_completed",
            "Completed the reviewed CISA KEV action with the discontinue-use fallback already present in the bound exact evidence.",
        ),
        "portfolio-diverse-temporal-19": (
            "update_a_fmus_span_bound",
            "Added the exact Update A FMUS span so the reviewed alongside-FMUS statement requires both FMUS and MIN evidence.",
        ),
        "portfolio-diverse-abstain-08": (
            "restricted_vendor_evidence_replaced",
            "Removed the Güralp website dependency and retained only egress-safe CISA Update B evidence for a production-release insufficiency question.",
        ),
        "portfolio-diverse-authority-07-v4": (
            "restricted_vendor_evidence_replaced",
            "Removed the KUNBUS PDF dependency and replaced it with distinct authority-scoped facts from the CISA initial and Update A states.",
        ),
        "portfolio-diverse-authority-08": (
            "restricted_vendor_evidence_replaced",
            "Removed the ECOVACS website dependency and replaced it with authority-scoped facts from the CISA initial and Update A states.",
        ),
        "portfolio-diverse-synthesis-06": (
            "restricted_vendor_evidence_replaced",
            "Removed the ECOVACS website dependency and now requires the initial update deadline plus Update A complete-coverage state.",
        ),
        "portfolio-diverse-synthesis-07": (
            "restricted_vendor_evidence_replaced",
            "Removed the KUNBUS PDF dependency and now requires the initial PiCtory delivery method plus the Update A Bookworm image state.",
        ),
    }
    rows = []
    for case_id in sorted(V5_CHANGED_CASE_IDS):
        reason_code, reason = reasons[case_id]
        rows.append(
            {
                "v5_case_id": case_id,
                "v5_question_sha256": old[case_id].question_sha256,
                "disposition": (
                    "revised"
                    if case_id in APPROVED_CORRECTION_CASE_IDS
                    else "replaced_pending_five_item_review"
                ),
                "v6_case_id": case_id,
                "v6_question_sha256": new[case_id].question_sha256,
                "reason_code": reason_code,
                "reason": reason,
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-v5-to-v6-lineage-v1",
        "v5_file_sha256": V5_COMMITTED_LF_FILE_SHA256,
        "v5_semantic_corpus_sha256": V5_CORPUS_SHA256,
        "v5_review_packet_file_sha256": V5_REVIEW_COMMITTED_LF_FILE_SHA256,
        "v5_decision_log_file_sha256": DECISIONS_FILE_SHA256,
        "v6_semantic_corpus_sha256": corpus.corpus_sha256,
        "rows": rows,
    }
    payload["lineage_sha256"] = canonical_sha256(payload)
    return payload


def _audit(
    v5: DiverseCorpusV5,
    corpus: DiverseCorpusV6,
    index: PacketIndexV6,
    disposition: dict[str, Any],
) -> dict[str, Any]:
    old = {item.case_id: item for item in v5.questions}
    new = {item.case_id: item for item in corpus.questions}
    unchanged = sorted(set(old) - V5_CHANGED_CASE_IDS)
    if any(
        old[case_id].question_sha256 != new[case_id].question_sha256
        for case_id in unchanged
    ):
        raise ValueError("unapproved V5 question changed")
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
    report: dict[str, Any] = {
        "schema_version": "portfolio-diverse-corpus-audit-v6",
        "status": "five_egress_safe_replacements_pending_human_review",
        "created_at_utc": CREATED_AT,
        "corpus_path": OUT.relative_to(ROOT).as_posix(),
        "corpus_sha256": corpus.corpus_sha256,
        "corpus_file_sha256": _file_sha(OUT),
        "packet_index_path": INDEX_OUT.relative_to(ROOT).as_posix(),
        "packet_index_sha256": index.index_sha256,
        "packet_index_file_sha256": _file_sha(INDEX_OUT),
        "disposition_path": DISPOSITION_OUT.relative_to(ROOT).as_posix(),
        "disposition_sha256": disposition["lineage_sha256"],
        "review_decision_log_path": DECISIONS_PATH.relative_to(ROOT).as_posix(),
        "review_decision_log_file_sha256": _file_sha(DECISIONS_PATH),
        "unique_question_count": len(corpus.questions),
        "human_reviewed_new_label_count": 48,
        "unresolved_review_item_count": 0,
        "approved_correction_count": len(APPROVED_CORRECTION_CASE_IDS),
        "pending_replacement_review_count": len(EGRESS_REPLACEMENT_CASE_IDS),
        "unchanged_question_hash_count": len(unchanged),
        "slice_counts": dict(
            sorted(Counter(item.slice for item in corpus.questions).items())
        ),
        "question_independence_note": "The 64 unique questions are distinct answer contracts grouped into 51 semantic pairs and 24 dependency clusters; they are not 64 independent factual phenomena.",
        "temporal_boundary": "Publisher-declared version evidence is not independently observed history.",
        "provider_execution_status": "blocked_pending_five_item_human_review",
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _render_report(report: dict[str, Any]) -> str:
    return (
        "# Diverse portfolio corpus audit v6\n\n"
        f"- Status: `{report['status']}`\n"
        f"- Unique answer contracts: {report['unique_question_count']}\n"
        f"- Human-reviewed new labels: {report['human_reviewed_new_label_count']}\n"
        f"- Unresolved review items: {report['unresolved_review_item_count']}\n"
        f"- Approved V5→V6 corrections: {report['approved_correction_count']}\n"
        f"- Replacement labels pending review: "
        f"{report['pending_replacement_review_count']}\n"
        f"- Unchanged V5 question hashes: {report['unchanged_question_hash_count']}\n"
        f"- Corpus SHA-256: `{report['corpus_sha256']}`\n"
        f"- Packet index SHA-256: `{report['packet_index_sha256']}`\n"
        f"- Decision-log SHA-256: `{report['review_decision_log_file_sha256']}`\n\n"
        "The agent prepared the decision entries; the user's explicit approval is "
        "the human-review act. V5 remains immutable. Provider execution remains "
        "blocked pending the compact five-item replacement review.\n"
    )


def main() -> int:
    if datetime.now(UTC) < CREATED_AT:
        raise ValueError("V6 build attempted before its declared creation time")
    committed_text_inputs = {
        V5_PATH: V5_COMMITTED_LF_FILE_SHA256,
        V5_PACKET_PATH: V5_PACKET_COMMITTED_LF_FILE_SHA256,
        V5_REVIEW_PATH: V5_REVIEW_COMMITTED_LF_FILE_SHA256,
    }
    for path, expected in committed_text_inputs.items():
        if _committed_text_sha(path) != expected:
            raise ValueError(f"immutable input changed: {path.relative_to(ROOT)}")
    if _file_sha(DECISIONS_PATH) != DECISIONS_FILE_SHA256:
        raise ValueError(f"immutable input changed: {DECISIONS_PATH.relative_to(ROOT)}")
    v5 = DiverseCorpusV5.model_validate_json(V5_PATH.read_text(encoding="utf-8"))
    if v5.corpus_sha256 != V5_CORPUS_SHA256:
        raise ValueError("immutable V5 semantic hash changed")
    original = {question.case_id: question for question in v5.questions}
    replacements = _egress_safe_replacements(original)
    if set(replacements) != EGRESS_REPLACEMENT_CASE_IDS:
        raise ValueError("egress replacement set drifted")
    questions = []
    for question in v5.questions:
        if question.case_id == "portfolio-diverse-authority-06":
            question = _authority_correction(question)
        elif question.case_id == "portfolio-diverse-temporal-19":
            question = _temporal_correction(question)
        elif question.case_id in replacements:
            question = replacements[question.case_id]
        questions.append(question)
    payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-draft-v6",
        "corpus_id": "portfolio-diverse-v6-human-reviewed-candidate",
        "predecessor_corpus_file_sha256": V5_COMMITTED_LF_FILE_SHA256,
        "created_at_utc": CREATED_AT,
        "temporal_boundary": "publisher-declared version evidence is not independently observed history",
        "questions": sorted(questions, key=lambda item: item.case_id),
    }
    payload["corpus_sha256"] = canonical_sha256(payload)
    corpus = DiverseCorpusV6.model_validate(payload)
    _write_json(OUT, corpus)
    index = _packet_index(corpus)
    _write_json(INDEX_OUT, index)
    review = _replacement_review_packet(corpus)
    _write_json(REPLACEMENT_REVIEW_OUT, review)
    REPLACEMENT_REVIEW_MD.write_text(
        _render_replacement_review(review), encoding="utf-8"
    )
    disposition = _disposition(v5, corpus)
    _write_json(DISPOSITION_OUT, disposition)
    report = _audit(v5, corpus, index, disposition)
    _write_json(REPORT_JSON, report)
    REPORT_MD.write_text(_render_report(report), encoding="utf-8")
    print(
        f"{OUT.relative_to(ROOT)} {corpus.corpus_sha256} {len(corpus.questions)} questions"
    )
    print(
        f"{INDEX_OUT.relative_to(ROOT)} {index.index_sha256} {len(index.packets)} clean packets"
    )
    print(
        f"{DISPOSITION_OUT.relative_to(ROOT)} {disposition['lineage_sha256']} "
        "two corrections and five review replacements"
    )
    print(
        f"{REPLACEMENT_REVIEW_OUT.relative_to(ROOT)} {review.packet_sha256} "
        "five review items"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
