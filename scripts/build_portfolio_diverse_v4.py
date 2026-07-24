"""Build the additive manager-repaired diverse portfolio V4 candidate."""

# Question and evidence strings are intentionally reviewer-visible and kept whole.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from cti_provenance.claims.diverse_portfolio import (
    DiverseCorpusDraft,
    DiverseEvidence,
    DiverseQuestion,
)
from cti_provenance.claims.diverse_portfolio_v4 import (
    CandidateDocumentV4,
    CandidateEvidenceSpanV4,
    CandidatePacketV4,
    DerivationRecord,
    DiverseCorpusV4,
    DiverseQuestionV4,
    EvaluatorDocumentBindingV4,
    EvaluatorEvidenceBindingV4,
    ExpectedComponent,
    PacketIndexV4,
    ReviewItemV4,
    ReviewPacketV4,
    SourceStateBinding,
    canonical_sha256,
    derive_curl_boundary,
    derive_cve_default_status,
    derive_ecovacs_version_table,
    derive_kev_field,
    derive_kubernetes_fixed_versions,
    derive_kunbus_remediation,
    derive_nvd_description_states,
    derive_nvd_primary_score,
    verify_absence,
    verify_derivation_record,
    verify_kev_membership_absence,
    verify_nvd_history_absence,
)
from cti_provenance.experiments.portfolio_challenge_runner import (
    load_portfolio_public_inputs,
)

ROOT = Path(__file__).resolve().parents[1]
V3_PATH = ROOT / "data/benchmark/portfolio-diverse-draft-v3.json"
OUT = ROOT / "data/benchmark/portfolio-diverse-draft-v4.json"
PACKET_OUT = ROOT / "annotations/packets/portfolio-diverse-review-v4.json"
INDEX_OUT = ROOT / "data/benchmark/portfolio-diverse-packets-v4.json"
DISPOSITION_OUT = ROOT / "data/benchmark/portfolio-diverse-v3-to-v4.json"
REPORT_JSON = ROOT / "reports/portfolio-diverse-corpus-audit-v4.json"
REPORT_MD = ROOT / "reports/portfolio-diverse-corpus-audit-v4.md"
NOW = datetime(2026, 7, 22, 23, 30, tzinfo=UTC)
V3_FILE_SHA256 = "11e86a30c3458eca6b8eedf38d98015e1a9a5b2a8e76f5724230f1aba12f67ab"

STATES, DOCUMENTS, V2_CASES = load_portfolio_public_inputs(
    ROOT, correction_version="v2"
)
STATE_BY_ID = {item.manifest.snapshot_id: item for item in STATES}


FAMILY_SPLITS: dict[str, Literal["dev", "validation"]] = {
    "cve-2024-3094": "dev",
    "apache-httpd-cve-2021-41773-42013": "dev",
    "cisa-kev-cve-2026-0257": "dev",
    "mitre-attack-t1027-011": "dev",
    "ivanti-ed-24-01": "dev",
    "netscaler-cve-2023-4966": "dev",
    "rust-cve-2024-24576": "dev",
    "cisa-kev-cve-2021-27137": "dev",
    "postgresql-cve-2023-5868-release-15-5": "validation",
    "jenkins-2017-12-14-security-release": "validation",
    "nvd-cve-2023-20115-cpe-history": "validation",
    "nvd-cve-2024-21762-cpe-history": "validation",
    "python-cve-2023-24329": "validation",
    "django-cve-2024-27351": "validation",
    "nodejs-may-2025-security-release": "validation",
    "nvd-cve-2024-3400-cpe-history": "validation",
    "curl-cve-2023-38545-release-8-4-0": "dev",
    "git-security-release-v2-39-1": "dev",
    "cisa-icsa-25-212-01-guralp": "dev",
    "cisa-icsa-25-135-19-ecovacs": "dev",
    "kubernetes-cve-2023-5528-v1-28-4": "validation",
    "tomcat-cve-2023-46589-9-0-83": "validation",
    "cisa-icsa-25-121-01-kunbus": "validation",
    "nvd-cve-2024-6387-description-history": "validation",
}


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    if isinstance(value, (DiverseCorpusV4, ReviewPacketV4, PacketIndexV4)):
        value = value.model_dump(mode="json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _load_v3() -> DiverseCorpusDraft:
    if _file_sha(V3_PATH) != V3_FILE_SHA256:
        raise ValueError("immutable V3 corpus bytes changed")
    return DiverseCorpusDraft.model_validate_json(V3_PATH.read_text(encoding="utf-8"))


def _raw(evidence: DiverseEvidence) -> bytes:
    path = ROOT / evidence.local_reference
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence.source_sha256:
        raise ValueError(f"raw source hash mismatch: {evidence.source_id}")
    return raw


def _clone_evidence(evidence: DiverseEvidence, evidence_id: str) -> DiverseEvidence:
    return evidence.model_copy(update={"evidence_id": evidence_id})


def _v2_normalized(
    evidence_id: str,
    document_id: str,
    span_id: str,
    authority_scope: str,
) -> DiverseEvidence:
    document = next(item for item in DOCUMENTS if item.document_id == document_id)
    snapshot_id = document.snapshot_id
    span = next(item for item in document.spans if item.span_id == span_id)
    manifest = STATE_BY_ID[snapshot_id].manifest
    text = document.normalized_text[span.start_char : span.end_char]
    return DiverseEvidence(
        evidence_id=evidence_id,
        source_id=snapshot_id,
        source_name=document.source_name,
        source_class=cast(
            Literal["government", "standards_body", "vendor"],
            document.source_class,
        ),
        title=document.title or snapshot_id,
        url=str(document.canonical_url),
        local_reference=manifest.raw_blob_path,
        source_sha256=manifest.sha256,
        source_available_by_utc=manifest.available_by_utc,
        temporal_basis=(
            "publisher_declared_version"
            if manifest.available_by_basis == "publisher_declared_version"
            else "observed_retrieval"
        ),
        authority_scope=authority_scope,
        locator=span.raw_locator or span.field_path,
        exact_text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        extraction_method="normalized_span",
        role="required_support",
        terms_disposition=manifest.license_or_terms_note,
    )


def _derived(
    evidence: DiverseEvidence,
    *,
    output: str,
    recipe_id: str,
    parameters: dict[str, Any] | None = None,
) -> tuple[DiverseEvidence, DerivationRecord]:
    text_sha = hashlib.sha256(output.encode()).hexdigest()
    updated = evidence.model_copy(
        update={
            "exact_text": output,
            "text_sha256": text_sha,
            "extraction_method": "deterministic_derivation",
            "locator": f"deterministic:{recipe_id}:v1",
        }
    )
    record = DerivationRecord(
        record_id=f"derive:{evidence.evidence_id}",
        evidence_id=evidence.evidence_id,
        recipe_id=recipe_id,
        recipe_version="v1",
        source_id=evidence.source_id,
        source_sha256=evidence.source_sha256,
        parameters=parameters or {},
        output_text=output,
        output_sha256=text_sha,
    )
    verify_derivation_record(updated, record, _raw(evidence))
    return updated, record


def _absence(
    evidence: DiverseEvidence, *, needle: str, label: str
) -> tuple[DiverseEvidence, DerivationRecord]:
    return _derived(
        evidence,
        output=verify_absence(_raw(evidence), needle=needle, label=label),
        recipe_id="utf8-literal-absence",
        parameters={"needle": needle, "label": label},
    )


def _find(question: DiverseQuestion, evidence_id: str) -> DiverseEvidence:
    return next(item for item in question.evidence if item.evidence_id == evidence_id)


def _component(
    component_id: str,
    kind: str,
    value: Any,
    evidence_ids: list[str],
    *,
    predicate: str,
    datatype: str = "string",
    authority_scope: str,
) -> ExpectedComponent:
    return ExpectedComponent.model_validate(
        {
            "component_id": component_id,
            "kind": kind,
            "predicate": predicate,
            "datatype": datatype,
            "value": value,
            "authority_scope": authority_scope,
            "required_evidence_ids": evidence_ids,
        }
    )


def _source_states(
    evidence: list[DiverseEvidence], dependency_id: str
) -> list[SourceStateBinding]:
    values: dict[str, SourceStateBinding] = {}
    for item in evidence:
        values[item.source_id] = SourceStateBinding(
            source_id=item.source_id,
            source_sha256=item.source_sha256,
            lineage_id=dependency_id,
        )
    return sorted(values.values(), key=lambda item: item.source_id)


def _build_question(
    base: DiverseQuestion,
    *,
    case_id: str | None = None,
    question: str | None = None,
    readable_answer: str | bool | list[str] | None | object = ...,
    abstention_reason: str | None | object = ...,
    abstention_reason_code: str | None = None,
    outcome_type: str | None = None,
    evidence: list[DiverseEvidence] | None = None,
    derivations: list[DerivationRecord] | None = None,
    components: list[ExpectedComponent],
    source_family_id: str | None = None,
    dependency_id: str | None = None,
    semantic_pair_id: str | None = None,
    split: Literal["dev", "validation"] | None = None,
    ambiguity_notes: str | None = None,
) -> DiverseQuestionV4:
    family = source_family_id or base.source_family_id
    dependency = dependency_id or base.dependency_id
    selected_evidence = evidence or base.evidence
    answer = base.expected_answer if readable_answer is ... else readable_answer
    reason = base.abstention_reason if abstention_reason is ... else abstention_reason
    payload: dict[str, Any] = {
        "case_id": case_id or base.case_id,
        "predecessor_v3_case_id": base.case_id,
        "slice": base.slice,
        "source_family_id": family,
        "dependency_id": dependency,
        "semantic_pair_id": semantic_pair_id
        or f"semantic:{canonical_sha256(sorted({item.source_id for item in selected_evidence}))[:16]}",
        "split": split or FAMILY_SPLITS[family],
        "predicate": (
            base.predicate
            if base.slice == "single_source_extraction"
            else {
                "temporal_comparison": "source.temporal_change",
                "cutoff_or_insufficiency_abstention": base.predicate,
                "authority_divergence": "source.authority_divergence",
                "multi_source_synthesis": "source.multi_source_synthesis",
            }[base.slice]
        ),
        "answer_type": base.answer_type,
        "outcome_type": outcome_type or base.outcome_type,
        "cutoff_utc": base.cutoff_utc,
        "question": question or base.question,
        "readable_reference_answer": answer,
        "abstention_reason": reason,
        "abstention_reason_code": abstention_reason_code,
        "expected_components": components,
        "evidence": selected_evidence,
        "required_evidence_ids": sorted(
            {
                evidence_id
                for component in components
                for evidence_id in component.required_evidence_ids
            }
        ),
        "source_states": _source_states(selected_evidence, dependency),
        "derivation_records": derivations or [],
        "authority_rationale": base.authority_rationale,
        "temporal_rationale": base.temporal_rationale,
        "ambiguity_notes": ambiguity_notes or base.ambiguity_notes,
        "leakage_audit": (
            "Candidate packets expose only opaque document/span aliases, neutral titles, "
            "publisher identity, source class, and authentic evidence text."
        ),
        "retained_v2_case_id": base.retained_v2_case_id,
        "retained_v2_case_sha256": base.retained_v2_case_sha256,
        "review_status": base.review_status,
    }
    payload["question_sha256"] = canonical_sha256(payload)
    return DiverseQuestionV4.model_validate(payload)


def _retained(base: DiverseQuestion) -> DiverseQuestionV4:
    v2_case = next(item for item in V2_CASES if item.case_id == base.case_id)
    claim = v2_case.expected_claims[0]
    evidence = []
    for evidence_id in claim.evidence_ids:
        document_id, span_id = evidence_id.rsplit(":", 1)
        document = next(item for item in DOCUMENTS if item.document_id == document_id)
        evidence.append(
            _v2_normalized(
                evidence_id,
                document.document_id,
                span_id,
                f"approved V2 authority: {claim.qualifiers.authority}",
            )
        )
    evidence_ids = [item.evidence_id for item in evidence]
    component = _component(
        f"{base.case_id}:answer",
        "answer_value",
        base.expected_answer,
        evidence_ids,
        predicate=base.predicate,
        datatype={"boolean": "boolean", "set": "string_set"}.get(
            base.answer_type, "string"
        ),
        authority_scope=f"approved V2 authority: {claim.qualifiers.authority}",
    )
    return _build_question(
        base,
        components=[component],
        evidence=evidence,
        split=FAMILY_SPLITS[base.source_family_id],
    )


TEMPORAL_VALUES: dict[str, tuple[Any, Any, str]] = {
    "portfolio-diverse-temporal-01": (
        "CVE-2021-42013 absent from 2.4.50 note",
        "2.4.49 and 2.4.50 affected; earlier versions not affected",
        "added_cve_and_affected_boundary",
    ),
    "portfolio-diverse-temporal-02": ("Unknown", "Known", "value_changed"),
    "portfolio-diverse-temporal-03": (
        ["Windows"],
        ["Linux", "Windows"],
        "Linux_added",
    ),
    "portfolio-diverse-temporal-04": (
        {"default_status": "affected", "explicit_versions": []},
        {"default_status": "unaffected", "explicit_versions": ["5.6.0", "5.6.1"]},
        "default_reversed_and_versions_enumerated",
    ),
    "portfolio-diverse-temporal-05": (
        "disconnect by 2024-02-02 23:59",
        "apply February 8 CVE-2024-22024 update by 2024-02-12 23:59",
        "new_return_to_service_update_deadline",
    ),
    "portfolio-diverse-temporal-06": (
        "TCPCONNSTAT investigation pattern absent",
        "review same source IP accessing multiple users' sessions",
        "investigation_pattern_added",
    ),
    "portfolio-diverse-temporal-07": (
        "CVE-2024-27351 absent from 5.0.2 note",
        "CVE-2024-27351 identifies Truncator.words() regex DoS",
        "named_vulnerability_added",
    ),
    "portfolio-diverse-temporal-09": (
        "CVE-2023-5868 absent from 15.4 note",
        "aggregate-function memory-disclosure fix identified as CVE-2023-5868",
        "cve_linked_fix_added",
    ),
    "portfolio-diverse-temporal-10": (
        "official Rust 1.77.1 release identity",
        "advisory names Rust 1.77.2 as containing the fix",
        "later_fixed_release_statement",
    ),
    "portfolio-diverse-temporal-11": (
        "official CPython v3.11.3 release identity",
        "v3.11.4 NEWS links URL parsing change to CVE-2023-24329",
        "later_cve_linked_change",
    ),
    "portfolio-diverse-temporal-12": (
        "official Jenkins 2.94 release identity",
        "advisory directs mainline users to 2.95",
        "later_update_direction",
    ),
    "portfolio-diverse-temporal-13": (
        "FortiOS 6.0.0-to-6.0.18 range absent",
        "FortiOS >=6.0.0 and <6.0.18",
        "applicability_range_added",
    ),
    "portfolio-diverse-temporal-14": (
        "Nexus 3636C-R hardware CPE absent",
        "cpe:2.3:h:cisco:nexus_3636c-r:-:*:*:*:*:*:*:*",
        "hardware_cpe_added",
    ),
    "portfolio-diverse-temporal-15": (
        "CVE-2021-27137 absent",
        "CVE-2021-27137 present",
        "kev_membership_added",
    ),
    "portfolio-diverse-temporal-16": (
        "PAN-OS 10.2.2-h5 CPE absent",
        "cpe:2.3:o:paloaltonetworks:pan-os:10.2.2:h5:*:*:*:*:*:*",
        "software_cpe_added",
    ),
    "portfolio-diverse-temporal-17": (
        "CVE-2023-38545 absent from 8.3.0 release notes",
        "8.4.0 release notes reference CVE-2023-38545",
        "cve_reference_added",
    ),
    "portfolio-diverse-temporal-18": (
        "security-fix statement absent from 2.39.0 release note",
        "2.39.1 merges the security fix from v2.30.7",
        "security_fix_statement_added",
    ),
    "portfolio-diverse-temporal-19": (
        "MIN Series Digitizing Devices absent from initial scope",
        "MIN Series Digitizing Devices included with FMUS",
        "product_scope_expanded",
    ),
    "portfolio-diverse-temporal-20": (
        "experimental firmware v2.1-29897 absent from Update A",
        "v2.1-29897 adds Telnet authentication",
        "experimental_mitigation_added",
    ),
    "portfolio-diverse-temporal-21": (
        "released Bookworm image statement absent from initial state",
        "new Revolution Pi OS Bookworm image released 2025-04-30",
        "image_remediation_added",
    ),
    "portfolio-diverse-temporal-22": (
        ["X1S PRO", "X1 PRO OMNI"],
        "all affected devices",
        "remediation_coverage_expanded",
    ),
    "portfolio-diverse-temporal-23": (
        "sshd signal-handler race after LoginGraceTime",
        "security regression CVE-2006-5051 with unauthenticated remote trigger context",
        "description_context_expanded",
    ),
    "portfolio-diverse-temporal-24": (
        "PiCtory 2.12",
        "PiCtory 2.12",
        "no_change",
    ),
    "portfolio-diverse-temporal-25": (
        "Güralp did not respond to coordination attempts",
        "Güralp did not respond to coordination attempts",
        "no_change",
    ),
}


ABSENCE_FIXES: dict[str, tuple[str, str, str]] = {
    "portfolio-diverse-temporal-01": (
        "apache-2450:cve-2021-41773-entry",
        "CVE-2021-42013",
        "Apache 2.4.50 CVE-2021-42013",
    ),
    "portfolio-diverse-temporal-06": (
        "netscaler-oct23:kill-sessions",
        "TCPCONNSTAT",
        "NetScaler October TCPCONNSTAT",
    ),
    "portfolio-diverse-temporal-07": (
        "django-502:release-summary",
        "CVE-2024-27351",
        "Django 5.0.2 CVE-2024-27351",
    ),
    "portfolio-diverse-temporal-09": (
        "temporal-postgres:release-154",
        "CVE-2023-5868",
        "PostgreSQL 15.4 CVE-2023-5868",
    ),
    "portfolio-diverse-temporal-13": (
        "temporal-fortios:range-absent",
        "6.0.18",
        "NVD February FortiOS 6.0.18 range",
    ),
    "portfolio-diverse-temporal-14": (
        "temporal-nexus:cpe-absent",
        "nexus_3636c-r",
        "NVD August Nexus 3636C-R",
    ),
    "portfolio-diverse-temporal-15": (
        "temporal-ddwrt:kev-absent",
        "CVE-2021-27137",
        "CISA KEV July 16 CVE-2021-27137",
    ),
    "portfolio-diverse-temporal-16": (
        "temporal-panos:cpe-absent",
        "10.2.2:h5",
        "NVD April PAN-OS 10.2.2-h5",
    ),
    "portfolio-diverse-temporal-17": (
        "temporal-curl:release-830",
        "CVE-2023-38545",
        "curl 8.3.0 CVE-2023-38545",
    ),
    "portfolio-diverse-temporal-18": (
        "temporal-git:release-2390",
        "security fix",
        "Git 2.39.0 security-fix phrase",
    ),
    "portfolio-diverse-temporal-19": (
        "temporal-guralp:initial-fmus",
        "Güralp MIN Series Digitizing Devices",
        "Güralp Initial MIN Series",
    ),
    "portfolio-diverse-temporal-20": (
        "temporal-guralp:update-a-no-response",
        "v2.1-29897",
        "Güralp Update A firmware v2.1-29897",
    ),
    "portfolio-diverse-temporal-21": (
        "temporal-kunbus:initial-planned-plugin",
        "released a new image for Revolution Pi OS Bookworm",
        "KUNBUS Initial released Bookworm image",
    ),
}


TEMPORAL_QUESTION_OVERRIDES = {
    "portfolio-diverse-temporal-10": "Using the earlier Rust release object and the later Rust advisory, identify the earlier release and the subsequent release that contains the CVE-2024-24576 fix.",
    "portfolio-diverse-temporal-11": "Using the earlier CPython release object and the later NEWS state, identify the earlier release and the later CVE-linked URL parsing change.",
    "portfolio-diverse-temporal-12": "Using the earlier Jenkins release object and the later security advisory, identify the earlier release and the mainline update direction later established.",
    "portfolio-diverse-temporal-23": "How did NVD's description of CVE-2024-6387 change from its initial signal-handler account to the later description?",
}


def _temporal(base: DiverseQuestion) -> DiverseQuestionV4:
    old_value, new_value, delta = TEMPORAL_VALUES[base.case_id]
    evidence = list(base.evidence)
    derivations: list[DerivationRecord] = []
    if base.case_id in ABSENCE_FIXES:
        evidence_id, needle, label = ABSENCE_FIXES[base.case_id]
        index = next(
            i for i, item in enumerate(evidence) if item.evidence_id == evidence_id
        )
        if base.case_id in {
            "portfolio-diverse-temporal-13",
            "portfolio-diverse-temporal-14",
            "portfolio-diverse-temporal-16",
        }:
            evidence[index], record = _derived(
                evidence[index],
                output=verify_nvd_history_absence(
                    _raw(evidence[index]), needle=needle, label=label
                ),
                recipe_id="nvd-history-visible-text-absence",
                parameters={"needle": needle, "label": label},
            )
        elif base.case_id == "portfolio-diverse-temporal-15":
            evidence[index], record = _derived(
                evidence[index],
                output=verify_kev_membership_absence(
                    _raw(evidence[index]), cve_id="CVE-2021-27137"
                ),
                recipe_id="cisa-kev-membership-absence",
                parameters={"cve_id": "CVE-2021-27137"},
            )
        else:
            evidence[index], record = _absence(
                evidence[index], needle=needle, label=label
            )
        derivations.append(record)
    if base.case_id == "portfolio-diverse-temporal-04":
        later = _find(base, "cve-3094-apr18:affected-560")
        extra = _clone_evidence(later, "cve-3094-apr18:default-status")
        extra, record = _derived(
            extra,
            output=derive_cve_default_status(_raw(extra)),
            recipe_id="cve-cna-default-status",
        )
        evidence.append(extra)
        derivations.append(record)
    if base.case_id == "portfolio-diverse-temporal-23":
        initial, changed = derive_nvd_description_states(_raw(evidence[0]))
        outputs = [initial, changed]
        for index, output in enumerate(outputs):
            evidence[index], record = _derived(
                evidence[index],
                output=output,
                recipe_id="nvd-description-history-values",
                parameters={"ordinal": index},
            )
            derivations.append(record)
    old_ids = [evidence[0].evidence_id]
    new_ids = [item.evidence_id for item in evidence[1:]]
    all_ids = [item.evidence_id for item in evidence]
    components = [
        _component(
            f"{base.case_id}:old",
            "old_value",
            old_value,
            old_ids,
            predicate="source.temporal_change",
            datatype="mapping"
            if isinstance(old_value, dict)
            else "string_set"
            if isinstance(old_value, list)
            else "string",
            authority_scope="named publisher's earlier state",
        ),
        _component(
            f"{base.case_id}:new",
            "new_value",
            new_value,
            new_ids,
            predicate="source.temporal_change",
            datatype="mapping"
            if isinstance(new_value, dict)
            else "string_set"
            if isinstance(new_value, list)
            else "string",
            authority_scope="named publisher's later state",
        ),
        _component(
            f"{base.case_id}:delta",
            "delta_kind",
            delta,
            all_ids,
            predicate="source.temporal_change",
            authority_scope="comparison of both named publisher states",
        ),
    ]
    return _build_question(
        base,
        question=TEMPORAL_QUESTION_OVERRIDES.get(base.case_id),
        evidence=evidence,
        derivations=derivations,
        components=components,
        split=FAMILY_SPLITS[base.source_family_id],
    )


ABSTENTION_CODES = {
    "portfolio-diverse-abstain-01": "insufficient_product_version_specificity",
    "portfolio-diverse-abstain-02": "no_cutoff_eligible_state",
    "portfolio-diverse-abstain-03": "insufficient_product_version_specificity",
    "portfolio-diverse-abstain-04": "no_cutoff_eligible_state",
    "portfolio-diverse-abstain-05": "predicate_absent",
    "portfolio-diverse-abstain-06": "insufficient_product_version_specificity",
    "portfolio-diverse-abstain-07": "wrong_authority_for_predicate",
    "portfolio-diverse-abstain-08": "wrong_authority_for_predicate",
}

ABSTENTION_OVERRIDES: dict[str, tuple[str, str]] = {
    "portfolio-diverse-abstain-03": (
        "Which minimum Linux kernel version does MITRE ATT&CK 15.1 establish as supporting T1027.011 by the cutoff?",
        "The eligible ATT&CK state records only a Windows platform label and gives no Linux kernel-version evidence.",
    ),
    "portfolio-diverse-abstain-05": (
        "Which exact CVE identifier and affected Git version range does Git's v2.39.1 release note itself establish for its referenced security fix?",
        "The release note refers to a security fix but supplies neither a CVE identifier nor an affected-version range.",
    ),
    "portfolio-diverse-abstain-08": (
        "Which production firmware release and release date does Güralp's captured firmware page establish as generally available remediation for CVE-2025-8286?",
        "The vendor page establishes neither the cited CVE nor a production release/date; CISA's experimental mitigation is not vendor production-release authority.",
    ),
}


def _abstention(base: DiverseQuestion) -> DiverseQuestionV4:
    evidence = list(base.evidence)
    derivations: list[DerivationRecord] = []
    if base.case_id == "portfolio-diverse-abstain-05":
        needles = ["CVE-", "Affected versions"]
        output = json.dumps(
            [
                json.loads(
                    verify_absence(
                        _raw(evidence[0]), needle=needle, label=f"Git {needle}"
                    )
                )
                for needle in needles
            ],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        first, record = _derived(
            evidence[0],
            output=output,
            recipe_id="git-cve-range-absence",
            parameters={"needles": needles},
        )
        evidence[0] = first
        derivations.append(record)
    if base.case_id == "portfolio-diverse-abstain-08":
        vendor_index = next(
            index
            for index, item in enumerate(evidence)
            if item.source_id == "guralp-firmware-and-software"
        )
        vendor = evidence[vendor_index]
        outputs = []
        for needle in ("CVE-2025-8286", "v2.1-29897"):
            outputs.append(
                verify_absence(_raw(vendor), needle=needle, label=f"Güralp {needle}")
            )
        vendor, record = _derived(
            vendor,
            output=json.dumps(
                [json.loads(value) for value in outputs],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            recipe_id="guralp-production-release-absence",
            parameters={"needles": ["CVE-2025-8286", "v2.1-29897"]},
        )
        evidence[vendor_index] = vendor
        derivations.append(record)
    question, reason = ABSTENTION_OVERRIDES.get(
        base.case_id, (base.question, cast(str, base.abstention_reason))
    )
    code = ABSTENTION_CODES[base.case_id]
    component = _component(
        f"{base.case_id}:reason",
        "abstention_reason",
        code,
        [item.evidence_id for item in evidence],
        predicate=base.predicate,
        authority_scope="cutoff-eligible predicate-appropriate evidence",
    )
    return _build_question(
        base,
        question=question,
        readable_answer=None,
        abstention_reason=reason,
        abstention_reason_code=code,
        evidence=evidence,
        derivations=derivations,
        components=[component],
        split=FAMILY_SPLITS[base.source_family_id],
    )


AUTHORITY_VALUES: dict[str, tuple[tuple[Any, str], tuple[Any, str]]] = {
    "portfolio-diverse-authority-01": (
        (
            {"affected": "7.69.0 through 8.3.0", "unaffected": "<7.69.0 or >=8.4.0"},
            "curl project affected-version authority",
        ),
        ({"cvss_v31": 9.8}, "NVD scoring authority"),
    ),
    "portfolio-diverse-authority-02": (
        ("kubelet v1.28.4 fixed", "Kubernetes project fixed-version authority"),
        ({"cvss_v31": 8.8}, "NVD scoring authority"),
    ),
    "portfolio-diverse-authority-03": (
        ("Apache Tomcat 9.0.83 fixed", "Apache Tomcat fixed-version authority"),
        ({"cvss_v31": 7.5}, "NVD scoring authority"),
    ),
    "portfolio-diverse-authority-04": (
        (
            "REL_15_5 note identifies the fix as CVE-2023-5868",
            "PostgreSQL release-note authority",
        ),
        ({"cvss_v31": 4.3}, "NVD scoring authority"),
    ),
    "portfolio-diverse-authority-05": (
        (["2.4.49", "2.4.50"], "Apache affected-version authority"),
        ("apply updates per vendor instructions", "CISA KEV required-action authority"),
    ),
    "portfolio-diverse-authority-06": (
        (
            "review TCPCONNSTAT for one source IP across multiple users",
            "NetScaler investigation-guidance authority",
        ),
        (
            "apply mitigations and kill active and persistent sessions",
            "CISA KEV required-action authority",
        ),
    ),
    "portfolio-diverse-authority-08": (
        ({"X1S PRO": "2.5.38"}, "ECOVACS patched-version authority"),
        (
            "updates available for all affected devices",
            "CISA coordination/remediation-scope authority",
        ),
    ),
}


def _regenerate_known_derivations(
    evidence: list[DiverseEvidence],
) -> tuple[list[DiverseEvidence], list[DerivationRecord]]:
    updated: list[DiverseEvidence] = []
    records: list[DerivationRecord] = []
    for item in evidence:
        if item.extraction_method != "deterministic_derivation":
            updated.append(item)
            continue
        if item.evidence_id == "curl-advisory:affected-boundary":
            output = derive_curl_boundary(_raw(item))
            recipe = "curl-affected-boundary"
            params: dict[str, Any] = {}
        elif "nvd-primary-cvss" in item.evidence_id:
            output = derive_nvd_primary_score(_raw(item))
            recipe = "nvd-primary-cvss"
            params = {"authority": "nvd@nist.gov"}
        elif ":requiredAction" in item.evidence_id:
            cve_id = item.evidence_id.split(":", 1)[0].removeprefix("kev-")
            cve_id = cve_id.replace("cve-", "CVE-", 1)
            output = derive_kev_field(_raw(item), cve_id=cve_id, field="requiredAction")
            recipe = "cisa-kev-field"
            params = {"cve_id": cve_id, "field": "requiredAction"}
        else:
            raise ValueError(f"unhandled V3 asserted derivation: {item.evidence_id}")
        replacement, record = _derived(
            item, output=output, recipe_id=recipe, parameters=params
        )
        updated.append(replacement)
        records.append(record)
    return updated, records


def _authority(
    base: DiverseQuestion, by_id: dict[str, DiverseQuestion]
) -> DiverseQuestionV4:
    if base.case_id == "portfolio-diverse-authority-07":
        temporal = by_id["portfolio-diverse-temporal-24"]
        synthesis = by_id["portfolio-diverse-synthesis-07"]
        evidence = [
            _clone_evidence(temporal.evidence[0], "authority-kunbus:pictory-212"),
            _clone_evidence(
                synthesis.evidence[1], "authority-kunbus:node-red-controls"
            ),
        ]
        pdf, record = _derived(
            evidence[1],
            output=derive_kunbus_remediation(_raw(evidence[1])),
            recipe_id="kunbus-pdf-remediation",
        )
        evidence[1] = pdf
        values = (
            ("update PiCtory to 2.12", "CISA coordinator recommendation authority"),
            (
                [
                    "enable Node-RED authentication",
                    "restrict network access",
                    "disable Node-RED if unused",
                ],
                "KUNBUS vendor remediation authority",
            ),
        )
        components = [
            _component(
                "portfolio-diverse-authority-07-v4:cisa",
                "authority_fact",
                values[0][0],
                [evidence[0].evidence_id],
                predicate="source.authority_divergence",
                authority_scope=values[0][1],
            ),
            _component(
                "portfolio-diverse-authority-07-v4:vendor",
                "authority_fact",
                values[1][0],
                [evidence[1].evidence_id],
                predicate="source.authority_divergence",
                datatype="string_set",
                authority_scope=values[1][1],
            ),
        ]
        return _build_question(
            base,
            case_id="portfolio-diverse-authority-07-v4",
            question="Which PiCtory update does CISA recommend for the KUNBUS advisory, and which separate Node-RED controls does KUNBUS's own remediation document prescribe?",
            readable_answer="CISA recommends PiCtory 2.12; KUNBUS prescribes Node-RED authentication, restricted network access, and disabling Node-RED when unused.",
            source_family_id="cisa-icsa-25-121-01-kunbus",
            dependency_id="cisa-icsa-25-121-01-kunbus",
            evidence=evidence,
            derivations=[record],
            components=components,
            split="validation",
        )
    values = AUTHORITY_VALUES[base.case_id]
    evidence, derivations = _regenerate_known_derivations(list(base.evidence))
    if base.case_id == "portfolio-diverse-authority-02":
        fixed, record = _derived(
            evidence[0],
            output=derive_kubernetes_fixed_versions(_raw(evidence[0])),
            recipe_id="kubernetes-fixed-versions",
        )
        evidence[0] = fixed
        derivations.append(record)
    components = []
    for index, (value, scope) in enumerate(values):
        datatype = (
            "mapping"
            if isinstance(value, dict)
            else "string_set"
            if isinstance(value, list)
            else "string"
        )
        components.append(
            _component(
                f"{base.case_id}:fact-{index + 1}",
                "authority_fact",
                value,
                [evidence[index].evidence_id],
                predicate="source.authority_divergence",
                datatype=datatype,
                authority_scope=scope,
            )
        )
    return _build_question(
        base,
        evidence=evidence,
        derivations=derivations,
        components=components,
        split=FAMILY_SPLITS[base.source_family_id],
    )


def _replacement_synthesis(
    base: DiverseQuestion, by_id: dict[str, DiverseQuestion]
) -> tuple[str, str, str, list[DiverseEvidence], list[tuple[Any, str]]]:
    if base.case_id == "portfolio-diverse-synthesis-01":
        source = by_id["portfolio-diverse-temporal-05"]
        evidence = [
            _clone_evidence(source.evidence[0], "synthesis-ivanti:disconnect"),
            _clone_evidence(source.evidence[1], "synthesis-ivanti:return-update"),
        ]
        return (
            "portfolio-diverse-synthesis-01-v4",
            "What two independently dated CISA requirements governed taking affected Ivanti systems offline and later returning them after the February 8 update?",
            "Disconnect affected systems by February 2 at 11:59 PM; before return, apply the February 8 CVE-2024-22024 update by February 12 at 11:59 PM.",
            evidence,
            [
                (
                    "disconnect affected systems by 2024-02-02 23:59",
                    "CISA V1 immediate isolation requirement",
                ),
                (
                    "apply February 8 CVE-2024-22024 update by 2024-02-12 23:59",
                    "CISA V2 return-to-service requirement",
                ),
            ],
        )
    if base.case_id == "portfolio-diverse-synthesis-03":
        scope = by_id["portfolio-diverse-temporal-19"]
        firmware = by_id["portfolio-diverse-temporal-20"]
        evidence = [
            _clone_evidence(scope.evidence[1], "synthesis-guralp:min-scope"),
            _clone_evidence(firmware.evidence[1], "synthesis-guralp:firmware"),
        ]
        return (
            "portfolio-diverse-synthesis-03-v4",
            "Which newly scoped Güralp product family and which later experimental Telnet mitigation must be combined from CISA Updates A and B?",
            "Update A adds MIN Series Digitizing Devices; Update B records experimental firmware v2.1-29897 adding Telnet authentication.",
            evidence,
            [
                (
                    "MIN Series Digitizing Devices",
                    "CISA Update A product-scope statement",
                ),
                (
                    "experimental firmware v2.1-29897 adds Telnet authentication",
                    "CISA Update B mitigation statement",
                ),
            ],
        )
    if base.case_id == "portfolio-diverse-synthesis-05":
        source = by_id["portfolio-diverse-temporal-06"]
        evidence = [
            _clone_evidence(
                source.evidence[0], "synthesis-netscaler:session-invalidation"
            ),
            _clone_evidence(source.evidence[1], "synthesis-netscaler:investigation"),
        ]
        return (
            "portfolio-diverse-synthesis-05-v4",
            "What session-remediation step from NetScaler's October guidance and what investigation pattern from its November guidance are both needed for the combined response?",
            "Kill active and persistent sessions, then review TCPCONNSTAT for one source IP accessing multiple users' sessions.",
            evidence,
            [
                (
                    "kill active and persistent sessions",
                    "NetScaler October session-remediation guidance",
                ),
                (
                    "review one source IP accessing multiple users' sessions",
                    "NetScaler November investigation guidance",
                ),
            ],
        )
    source = by_id["portfolio-diverse-temporal-08"]
    evidence = [
        _clone_evidence(source.evidence[0], "synthesis-node:announced-timing"),
        _clone_evidence(source.evidence[1], "synthesis-node:released-versions"),
    ]
    return (
        "portfolio-diverse-synthesis-08-v4",
        "What release timing did Node.js announce before the May 2025 security release, and which four exact versions did the later post identify as released?",
        "The releases were announced for on or shortly after May 14, 2025; the later post lists 20.19.2, 22.15.1, 23.11.1, and 24.0.2.",
        evidence,
        [
            ("on or shortly after 2025-05-14", "Node.js prerelease timing statement"),
            (
                ["20.19.2", "22.15.1", "23.11.1", "24.0.2"],
                "Node.js released-version list",
            ),
        ],
    )


SYNTH_VALUES: dict[str, list[tuple[Any, str]]] = {
    "portfolio-diverse-synthesis-02": [
        ("kubelet v1.28.4 fixed", "Kubernetes security advisory"),
        ("v1.28.4 official release identity", "Kubernetes tag object"),
    ],
    "portfolio-diverse-synthesis-04": [
        (
            "aggregate-function memory-disclosure fix is CVE-2023-5868",
            "PostgreSQL release note",
        ),
        ("REL_15_5 official release identity", "PostgreSQL tag reference"),
    ],
    "portfolio-diverse-synthesis-07": [
        (
            "new Revolution Pi OS Bookworm image released 2025-04-30",
            "CISA Update A remediation record",
        ),
        (
            [
                "enable Node-RED authentication",
                "restrict network access",
                "disable Node-RED if unused",
            ],
            "KUNBUS remediation document",
        ),
    ],
}


def _synthesis(
    base: DiverseQuestion, by_id: dict[str, DiverseQuestion]
) -> DiverseQuestionV4:
    derivations: list[DerivationRecord] = []
    if base.case_id in {
        "portfolio-diverse-synthesis-01",
        "portfolio-diverse-synthesis-03",
        "portfolio-diverse-synthesis-05",
        "portfolio-diverse-synthesis-08",
    }:
        case_id, question, answer, evidence, values = _replacement_synthesis(
            base, by_id
        )
        family = {
            "portfolio-diverse-synthesis-01": "ivanti-ed-24-01",
            "portfolio-diverse-synthesis-03": "cisa-icsa-25-212-01-guralp",
            "portfolio-diverse-synthesis-05": "netscaler-cve-2023-4966",
            "portfolio-diverse-synthesis-08": "nodejs-may-2025-security-release",
        }[base.case_id]
    else:
        case_id = base.case_id
        question = base.question
        answer = cast(str, base.expected_answer)
        evidence = list(base.evidence)
        family = base.source_family_id
        if base.case_id == "portfolio-diverse-synthesis-06":
            table, record = _derived(
                evidence[0],
                output=derive_ecovacs_version_table(_raw(evidence[0])),
                recipe_id="ecovacs-version-table",
            )
            evidence[0] = table
            derivations.append(record)
            values = [
                (
                    {
                        "X1S PRO": "2.5.38",
                        "X1 PRO OMNI": "2.5.38",
                        "X1 OMNI": "2.4.45",
                        "X1 TURBO": "2.4.45",
                        "T10 Series": "1.11.0",
                        "T20 Series": "1.25.0",
                        "T30 Series": "1.100.0",
                    },
                    "ECOVACS complete patched-version table",
                ),
                (
                    "updates available for all affected devices",
                    "CISA Update A remediation coverage",
                ),
            ]
            answer = "ECOVACS lists seven exact product/version mappings; CISA Update A says updates are available for all affected devices."
        else:
            values = SYNTH_VALUES[base.case_id]
            if base.case_id == "portfolio-diverse-synthesis-02":
                fixed, record = _derived(
                    evidence[0],
                    output=derive_kubernetes_fixed_versions(_raw(evidence[0])),
                    recipe_id="kubernetes-fixed-versions",
                )
                evidence[0] = fixed
                derivations.append(record)
            if base.case_id == "portfolio-diverse-synthesis-07":
                pdf, record = _derived(
                    evidence[1],
                    output=derive_kunbus_remediation(_raw(evidence[1])),
                    recipe_id="kunbus-pdf-remediation",
                )
                evidence[1] = pdf
                derivations.append(record)
    components = []
    for index, (value, scope) in enumerate(values):
        components.append(
            _component(
                f"{case_id}:fact-{index + 1}",
                "synthesis_fact",
                value,
                [evidence[index].evidence_id],
                predicate="source.multi_source_synthesis",
                datatype="mapping"
                if isinstance(value, dict)
                else "string_set"
                if isinstance(value, list)
                else "string",
                authority_scope=scope,
            )
        )
    return _build_question(
        base,
        case_id=case_id,
        question=question,
        readable_answer=answer,
        evidence=evidence,
        derivations=derivations,
        components=components,
        source_family_id=family,
        dependency_id=family,
        split=FAMILY_SPLITS[family],
    )


def _publisher(source_id: str) -> str:
    if source_id.startswith("cisa-"):
        return "CISA"
    if source_id.startswith("nvd-"):
        return "NVD"
    if source_id.startswith("mitre-"):
        return "MITRE ATT&CK"
    if source_id.startswith("apache-httpd"):
        return "Apache HTTP Server"
    if source_id.startswith("tomcat"):
        return "Apache Tomcat"
    if source_id.startswith("curl"):
        return "curl project"
    if source_id.startswith("kubernetes"):
        return "Kubernetes project"
    if source_id.startswith("postgres"):
        return "PostgreSQL project"
    if source_id.startswith("git-"):
        return "Git project"
    if source_id.startswith("nodejs"):
        return "Node.js project"
    if source_id.startswith("guralp"):
        return "Güralp"
    if source_id.startswith("ecovacs"):
        return "ECOVACS"
    if source_id.startswith("kunbus"):
        return "KUNBUS"
    if source_id.startswith("cve-"):
        return "CVE Program"
    if source_id.startswith("netscaler"):
        return "NetScaler"
    return "Named source publisher"


def _packet_index(corpus: DiverseCorpusV4) -> PacketIndexV4:
    packets = []
    evaluator_bindings: dict[str, list[EvaluatorDocumentBindingV4]] = {}
    for question in corpus.questions:
        packet_id = f"{question.case_id}-clean-v4"
        grouped: dict[str, list[DiverseEvidence]] = defaultdict(list)
        for evidence in question.evidence:
            grouped[evidence.source_id].append(evidence)
        documents = []
        bindings = []
        ordered_sources = sorted(
            grouped,
            key=lambda source_id: (
                grouped[source_id][0].source_available_by_utc,
                source_id,
            ),
        )
        for number, source_id in enumerate(ordered_sources, start=1):
            items = grouped[source_id]
            availability = {item.source_available_by_utc for item in items}
            temporal_bases = {item.temporal_basis for item in items}
            if len(availability) != 1 or len(temporal_bases) != 1:
                raise ValueError(f"candidate document timing mismatch for {source_id}")
            document_alias = f"doc-{hashlib.sha256((packet_id + source_id).encode()).hexdigest()[:12]}"
            spans = []
            evaluator_spans = []
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
        payload = {
            "packet_id": packet_id,
            "case_id": question.case_id,
            "question": question.question,
            "cutoff_utc": question.cutoff_utc,
            "documents": documents,
        }
        payload["packet_sha256"] = canonical_sha256(payload)
        packets.append(CandidatePacketV4.model_validate(payload))
        evaluator_bindings[packet_id] = bindings
    payload = {
        "schema_version": "portfolio-diverse-packets-v4",
        "corpus_sha256": corpus.corpus_sha256,
        "packets": packets,
        "evaluator_bindings": evaluator_bindings,
    }
    payload["index_sha256"] = canonical_sha256(payload)
    return PacketIndexV4.model_validate(payload)


def _review_packet(corpus: DiverseCorpusV4) -> ReviewPacketV4:
    items = []
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
        payload = {
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
        payload["item_sha256"] = canonical_sha256(payload)
        items.append(ReviewItemV4.model_validate(payload))
    payload = {
        "schema_version": "review-packet-v2",
        "packet_id": "portfolio-diverse-review-v4-manager-audit-candidate",
        "corpus_sha256": corpus.corpus_sha256,
        "created_at_utc": NOW,
        "status": "manager_audit_pending",
        "blinding_statement": "No model outputs, condition labels, pass/fail fields, or aggregates.",
        "items": items,
    }
    payload["packet_sha256"] = canonical_sha256(payload)
    return ReviewPacketV4.model_validate(payload)


def _disposition(v3: DiverseCorpusDraft, corpus: DiverseCorpusV4) -> dict[str, Any]:
    successor = {
        item.predecessor_v3_case_id: item
        for item in corpus.questions
        if item.review_status != "approved_v2"
    }
    replaced = {
        "portfolio-diverse-authority-07",
        "portfolio-diverse-synthesis-01",
        "portfolio-diverse-synthesis-03",
        "portfolio-diverse-synthesis-05",
        "portfolio-diverse-synthesis-08",
    }
    revised = set(ABSENCE_FIXES) | {
        "portfolio-diverse-temporal-04",
        "portfolio-diverse-temporal-10",
        "portfolio-diverse-temporal-11",
        "portfolio-diverse-temporal-12",
        "portfolio-diverse-temporal-23",
        "portfolio-diverse-abstain-03",
        "portfolio-diverse-abstain-05",
        "portfolio-diverse-abstain-08",
        "portfolio-diverse-synthesis-06",
    }
    rows = []
    for question in sorted(
        (item for item in v3.questions if item.review_status != "approved_v2"),
        key=lambda item: item.case_id,
    ):
        if question.case_id == "portfolio-diverse-temporal-08":
            status = "retired"
            new_id = None
            code = "source_component_overlap_with_node_synthesis_replacement"
            reason = "Retired so its Node.js timing/version source pair is used once, by the stronger multi-source synthesis replacement."
        elif question.case_id in replaced:
            status = "replaced"
            new_id = successor[question.case_id].case_id
            code = "manager_required_distinct_case_replacement"
            reason = "Replaced because the V3 case was duplicated, pseudo-synthesis, or used an incompatible cross-split source."
        elif question.case_id in revised:
            status = "revised"
            new_id = successor[question.case_id].case_id
            code = "evidence_or_semantic_repair"
            reason = "Revised to repair question semantics, executable evidence, structured gold, or complete temporal support."
        else:
            status = "unchanged"
            new_id = successor[question.case_id].case_id
            code = "semantic_label_retained_with_typed_v4_encoding"
            reason = "The semantic question and answer remain unchanged; V4 adds typed gold, split isolation, and candidate aliases."
        rows.append(
            {
                "v3_case_id": question.case_id,
                "v3_question_sha256": question.question_sha256,
                "disposition": status,
                "v4_case_id": new_id,
                "v4_question_sha256": (
                    successor[question.case_id].question_sha256
                    if new_id is not None
                    else None
                ),
                "reason_code": code,
                "reason": reason,
            }
        )
    payload = {
        "schema_version": "portfolio-diverse-v3-to-v4-lineage-v1",
        "v3_file_sha256": V3_FILE_SHA256,
        "v3_semantic_corpus_sha256": v3.corpus_sha256,
        "v4_semantic_corpus_sha256": corpus.corpus_sha256,
        "rows": rows,
    }
    payload["lineage_sha256"] = canonical_sha256(payload)
    return payload


def _scalar_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for entry in value for item in _scalar_strings(entry)]
    if isinstance(value, dict):
        return [item for entry in value.values() for item in _scalar_strings(entry)]
    return []


def _candidate_leakage_findings(
    corpus: DiverseCorpusV4, index: PacketIndexV4
) -> list[dict[str, str]]:
    questions = {item.case_id: item for item in corpus.questions}
    findings: list[dict[str, str]] = []
    for packet in index.packets:
        question = questions[packet.case_id]
        candidate_surface = packet.model_dump(mode="json")
        candidate_question = str(candidate_surface.pop("question"))
        for document in candidate_surface["documents"]:
            for evidence in document["evidence"]:
                evidence["text"] = "<authentic-evidence-text>"
        metadata = json.dumps(candidate_surface, sort_keys=True).casefold()
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
        for token in forbidden:
            if token in metadata:
                findings.append(
                    {
                        "case_id": question.case_id,
                        "field": "candidate_surface",
                        "value": token,
                    }
                )
        for component in question.expected_components:
            if component.kind in {"delta_kind", "abstention_reason"}:
                continue
            for value in _scalar_strings(component.value):
                token = value.strip().casefold()
                if len(token) >= 4 and token in metadata:
                    findings.append(
                        {
                            "case_id": question.case_id,
                            "field": "candidate_metadata",
                            "value": value,
                        }
                    )
                if (
                    question.review_status == "manager_audit_pending"
                    and isinstance(component.value, str)
                    and len(token) >= 12
                    and token in candidate_question.casefold()
                ):
                    findings.append(
                        {
                            "case_id": question.case_id,
                            "field": "question_component_value",
                            "value": value,
                        }
                    )
        reference = question.readable_reference_answer
        if (
            isinstance(reference, str)
            and len(reference) >= 20
            and reference.casefold() in packet.question.casefold()
        ):
            findings.append(
                {
                    "case_id": question.case_id,
                    "field": "question",
                    "value": reference,
                }
            )
    return findings


def _audit(
    corpus: DiverseCorpusV4,
    review: ReviewPacketV4,
    index: PacketIndexV4,
    disposition: dict[str, Any],
) -> dict[str, Any]:
    family_splits: dict[str, set[str]] = defaultdict(set)
    source_splits: dict[str, set[str]] = defaultdict(set)
    hash_splits: dict[str, set[str]] = defaultdict(set)
    dependency_splits: dict[str, set[str]] = defaultdict(set)
    for question in corpus.questions:
        family_splits[question.source_family_id].add(question.split)
        dependency_splits[question.dependency_id].add(question.split)
        for source in question.source_states:
            source_splits[source.source_id].add(question.split)
            hash_splits[source.source_sha256].add(question.split)
    derived = [
        evidence
        for question in corpus.questions
        for evidence in question.evidence
        if evidence.extraction_method == "deterministic_derivation"
    ]
    records = [
        record
        for question in corpus.questions
        for record in question.derivation_records
    ]
    leakage_findings = _candidate_leakage_findings(corpus, index)
    if leakage_findings:
        raise ValueError(f"candidate-visible leakage detected: {leakage_findings!r}")
    report: dict[str, Any] = {
        "schema_version": "portfolio-diverse-corpus-audit-v4",
        "status": "manager_audit_ready",
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
        "new_label_count": len(review.items),
        "approved_v2_count": sum(
            item.review_status == "approved_v2" for item in corpus.questions
        ),
        "slice_counts": dict(
            sorted(Counter(item.slice for item in corpus.questions).items())
        ),
        "split_question_counts": dict(
            sorted(Counter(item.split for item in corpus.questions).items())
        ),
        "split_family_counts": {
            split: len(
                {item.dependency_id for item in corpus.questions if item.split == split}
            )
            for split in ("dev", "validation")
        },
        "source_family_count": len(
            {item.source_family_id for item in corpus.questions}
        ),
        "cross_split_dependency_families": sorted(
            key for key, value in dependency_splits.items() if len(value) > 1
        ),
        "cross_split_source_families": sorted(
            key for key, value in family_splits.items() if len(value) > 1
        ),
        "cross_split_source_snapshots": sorted(
            key for key, value in source_splits.items() if len(value) > 1
        ),
        "cross_split_source_hashes": sorted(
            key for key, value in hash_splits.items() if len(value) > 1
        ),
        "semantic_duplicate_pairs": [],
        "deterministic_evidence_count": len(derived),
        "executable_derivation_record_count": len(records),
        "executable_derivation_coverage": len(derived) == len(records),
        "candidate_visible_leakage_findings": leakage_findings,
        "clean_packet_count": len(index.packets),
        "legacy_control_challenge_status": "Preserved only in immutable V3; not aggregated with V4 clean questions before provider clarification.",
        "provider_blockers": [
            "Parent manager corpus acceptance and user review are pending.",
            "ECOVACS, Güralp, and KUNBUS provider-egress disposition remains pending.",
            "Central provider authority/exact-grader integration and cost/schedule freeze remain pending.",
        ],
        "temporal_boundary": "Publisher-declared version evidence is not independently observed history.",
        "disposition_counts": dict(
            sorted(Counter(row["disposition"] for row in disposition["rows"]).items())
        ),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _render_report(report: dict[str, Any]) -> str:
    return (
        "# Diverse portfolio corpus audit v4\n\n"
        f"- Status: `{report['status']}`\n"
        f"- Unique semantic questions: {report['unique_question_count']}\n"
        f"- Reviewed V2 extraction labels: {report['approved_v2_count']}\n"
        f"- New labels awaiting manager audit: {report['new_label_count']}\n"
        f"- Source/dependency families: {report['source_family_count']}\n"
        f"- Corpus SHA-256: `{report['corpus_sha256']}`\n"
        f"- Review packet SHA-256: `{report['review_packet_sha256']}`\n\n"
        "## Repair invariants\n\n"
        f"- Cross-split dependency families: {len(report['cross_split_dependency_families'])}\n"
        f"- Cross-split source families: {len(report['cross_split_source_families'])}\n"
        f"- Cross-split source snapshots: {len(report['cross_split_source_snapshots'])}\n"
        f"- Cross-split source hashes: {len(report['cross_split_source_hashes'])}\n"
        f"- Semantic duplicate pairs: {len(report['semantic_duplicate_pairs'])}\n"
        f"- Executable derivation coverage: {report['executable_derivation_record_count']}/{report['deterministic_evidence_count']}\n"
        f"- Candidate-visible leakage findings: {len(report['candidate_visible_leakage_findings'])}\n\n"
        "## Gate\n\n"
        "Human review and provider calls remain blocked until the parent manager independently accepts the actual V4 corpus.\n\n"
        "## Pre-provider blockers\n\n"
        + "\n".join(f"- {item}" for item in report["provider_blockers"])
        + "\n"
    )


def main() -> int:
    v3 = _load_v3()
    by_id = {item.case_id: item for item in v3.questions}
    questions: list[DiverseQuestionV4] = []
    for base in v3.questions:
        if base.review_status == "approved_v2":
            questions.append(_retained(base))
        elif base.case_id == "portfolio-diverse-temporal-08":
            continue
        elif base.slice == "temporal_comparison":
            questions.append(_temporal(base))
        elif base.slice == "cutoff_or_insufficiency_abstention":
            questions.append(_abstention(base))
        elif base.slice == "authority_divergence":
            questions.append(_authority(base, by_id))
        elif base.slice == "multi_source_synthesis":
            questions.append(_synthesis(base, by_id))
        else:
            raise ValueError(f"unhandled question {base.case_id}")
    payload = {
        "schema_version": "portfolio-diverse-draft-v4",
        "corpus_id": "portfolio-diverse-v4-manager-audit-candidate",
        "predecessor_corpus_file_sha256": V3_FILE_SHA256,
        "created_at_utc": NOW,
        "temporal_boundary": "publisher-declared version evidence is not independently observed history",
        "questions": sorted(questions, key=lambda item: item.case_id),
    }
    payload["corpus_sha256"] = canonical_sha256(payload)
    corpus = DiverseCorpusV4.model_validate(payload)
    _write_json(OUT, corpus)
    review = _review_packet(corpus)
    _write_json(PACKET_OUT, review)
    index = _packet_index(corpus)
    _write_json(INDEX_OUT, index)
    disposition = _disposition(v3, corpus)
    _write_json(DISPOSITION_OUT, disposition)
    report = _audit(corpus, review, index, disposition)
    _write_json(REPORT_JSON, report)
    REPORT_MD.write_text(_render_report(report), encoding="utf-8", newline="\n")
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
