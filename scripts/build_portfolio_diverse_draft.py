"""Build the additive substantive diverse-portfolio manager-audit draft."""

# Exact source excerpts and reviewer-visible questions are intentionally kept whole.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cti_provenance.claims.diverse_portfolio import (
    DiverseCorpusDraft,
    DiverseEvidence,
    DiverseQuestion,
    canonical_sha256,
)
from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.experiments.portfolio_challenge_runner import (
    load_portfolio_public_inputs,
)
from cti_provenance.grading.review_workflow import (
    OriginalLabel,
    ReviewClaim,
    ReviewEvidence,
    ReviewItem,
    ReviewPacket,
    ReviewSource,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/benchmark/portfolio-diverse-draft-v3.json"
PACKET_OUT = ROOT / "annotations/packets/portfolio-diverse-review-v3.json"
AUTHORITY = ROOT / "configs/authority-policy-portfolio-diverse-v3.yaml"
PACKET_INDEX_OUT = ROOT / "data/benchmark/portfolio-diverse-packets-v3.json"
REPORT_JSON = ROOT / "reports/portfolio-diverse-corpus-audit-v3.json"
REPORT_MD = ROOT / "reports/portfolio-diverse-corpus-audit-v3.md"
V2 = ROOT / "data/benchmark/portfolio-public-cases-v2.jsonl"
NOW = datetime(2026, 7, 22, 20, 6, 56, tzinfo=UTC)
BOUNDARY = "publisher-declared version evidence is not independently observed history"
TERMS = "minimal exact span and hash retained; raw source bytes remain gitignored"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_ledger_records() -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for relative in (
        "data/manifests/portfolio-capture-ledger-v1.json",
        "data/manifests/portfolio-diverse-capture-batch1.json",
        "data/manifests/portfolio-diverse-capture-batch2.json",
    ):
        payload = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        for record in payload.get("records", payload.get("attempts", [])):
            if record.get("outcome") == "success":
                records[record["source_id"]] = record
    return records


STATES, DOCUMENTS, V2_CASES = load_portfolio_public_inputs(
    ROOT, correction_version="v2"
)
STATE_BY_ID = {state.manifest.snapshot_id: state for state in STATES}
DOC_BY_ID = {document.snapshot_id: document for document in DOCUMENTS}
LEDGER = _load_ledger_records()


def _existing_source(snapshot_id: str) -> dict[str, Any]:
    state = STATE_BY_ID[snapshot_id]
    document = DOC_BY_ID[snapshot_id]
    manifest = state.manifest
    return {
        "source_id": snapshot_id,
        "source_name": document.source_name,
        "source_class": document.source_class,
        "title": document.title or snapshot_id,
        "url": str(document.canonical_url),
        "local_reference": manifest.raw_blob_path,
        "source_sha256": manifest.sha256,
        "source_available_by_utc": manifest.available_by_utc,
        "temporal_basis": (
            "publisher_declared_version"
            if manifest.available_by_basis == "publisher_declared_version"
            else "observed_retrieval"
        ),
        "terms_disposition": manifest.license_or_terms_note,
    }


_CAPTURE_META: dict[str, tuple[str, str, str, str]] = {
    "curl-cve-2023-38545-advisory-repair": (
        "vendor_advisory",
        "vendor",
        "curl CVE-2023-38545 advisory",
        "observed_retrieval",
    ),
    "curl-release-notes-8.4.0-repair": (
        "vendor_advisory",
        "vendor",
        "curl 8.4.0 release notes",
        "publisher_declared_version",
    ),
    "curl-release-notes-8.3.0-repair": (
        "vendor_advisory",
        "vendor",
        "curl 8.3.0 release notes",
        "publisher_declared_version",
    ),
    "kubernetes-cve-2023-5528-advisory-repair": (
        "vendor_advisory",
        "vendor",
        "Kubernetes CVE-2023-5528 advisory",
        "observed_retrieval",
    ),
    "kubernetes-tag-object-1.28.4": (
        "vendor_advisory",
        "vendor",
        "Kubernetes v1.28.4 annotated tag",
        "publisher_declared_version",
    ),
    "tomcat-cve-2023-46589-security-page-repair": (
        "vendor_advisory",
        "vendor",
        "Apache Tomcat 9 security page",
        "observed_retrieval",
    ),
    "tomcat-tag-ref-9.0.83": (
        "vendor_advisory",
        "vendor",
        "Apache Tomcat 9.0.83 tag reference",
        "publisher_declared_version",
    ),
    "postgres-tag-ref-15.5": (
        "vendor_advisory",
        "vendor",
        "PostgreSQL REL_15_5 tag reference",
        "publisher_declared_version",
    ),
    "git-release-2.39.1": (
        "vendor_advisory",
        "vendor",
        "Git v2.39.1 release notes",
        "publisher_declared_version",
    ),
    "git-release-2.39.0": (
        "vendor_advisory",
        "vendor",
        "Git v2.39.0 release notes",
        "publisher_declared_version",
    ),
    "cisa-icsa-25-212-01-initial": (
        "cisa_csaf",
        "government",
        "CISA ICSA-25-212-01 Initial",
        "publisher_declared_version",
    ),
    "cisa-icsa-25-212-01-update-a": (
        "cisa_csaf",
        "government",
        "CISA ICSA-25-212-01 Update A",
        "publisher_declared_version",
    ),
    "cisa-icsa-25-212-01-update-b": (
        "cisa_csaf",
        "government",
        "CISA ICSA-25-212-01 Update B",
        "publisher_declared_version",
    ),
    "cisa-icsa-25-121-01-update-a": (
        "cisa_csaf",
        "government",
        "CISA ICSA-25-121-01 Update A",
        "publisher_declared_version",
    ),
    "cisa-icsa-25-121-01-initial": (
        "cisa_csaf",
        "government",
        "CISA ICSA-25-121-01 Initial",
        "publisher_declared_version",
    ),
    "cisa-icsa-25-135-19-initial": (
        "cisa_csaf",
        "government",
        "CISA ICSA-25-135-19 Initial",
        "publisher_declared_version",
    ),
    "cisa-icsa-25-135-19-update-a": (
        "cisa_csaf",
        "government",
        "CISA ICSA-25-135-19 Update A",
        "publisher_declared_version",
    ),
    "nvd-cve-2024-6387-history-api": (
        "nvd",
        "government",
        "NVD CVE-2024-6387 change history",
        "observed_retrieval",
    ),
    "guralp-firmware-and-software": (
        "vendor_advisory",
        "vendor",
        "Güralp firmware and software page",
        "observed_retrieval",
    ),
    "ecovacs-dsa20250509001": (
        "vendor_advisory",
        "vendor",
        "ECOVACS DSA-20250509001",
        "observed_retrieval",
    ),
    "kunbus-2025-0000002-remediation": (
        "vendor_advisory",
        "vendor",
        "KUNBUS remediation options for KUNBUS-2025-0000002",
        "observed_retrieval",
    ),
    "nvd-cve-2023-38545": (
        "nvd",
        "government",
        "NVD CVE-2023-38545 record",
        "observed_retrieval",
    ),
    "nvd-cve-2023-5528": (
        "nvd",
        "government",
        "NVD CVE-2023-5528 record",
        "observed_retrieval",
    ),
    "nvd-cve-2023-46589": (
        "nvd",
        "government",
        "NVD CVE-2023-46589 record",
        "observed_retrieval",
    ),
    "nvd-cve-2023-5868": (
        "nvd",
        "government",
        "NVD CVE-2023-5868 record",
        "observed_retrieval",
    ),
}

_PUBLISHER_TIMES = {
    "curl-release-notes-8.3.0-repair": "2023-09-13T23:59:59Z",
    "curl-release-notes-8.4.0-repair": "2023-10-11T23:59:59Z",
    "kubernetes-tag-object-1.28.4": "2023-11-14T23:59:59Z",
    "tomcat-tag-ref-9.0.83": "2023-11-15T23:59:59Z",
    "postgres-tag-ref-15.5": "2023-11-09T23:59:59Z",
    "git-release-2.39.1": "2023-01-17T23:59:59Z",
    "git-release-2.39.0": "2022-12-12T23:59:59Z",
    "cisa-icsa-25-212-01-initial": "2025-07-31T06:00:00Z",
    "cisa-icsa-25-212-01-update-a": "2025-08-14T06:00:00Z",
    "cisa-icsa-25-212-01-update-b": "2026-01-13T07:00:00Z",
    "cisa-icsa-25-121-01-update-a": "2025-07-10T06:00:00Z",
    "cisa-icsa-25-121-01-initial": "2025-05-06T06:00:00Z",
    "cisa-icsa-25-135-19-initial": "2025-05-15T06:00:00Z",
    "cisa-icsa-25-135-19-update-a": "2025-07-10T06:00:00Z",
}


def _captured_source(source_id: str) -> dict[str, Any]:
    record = LEDGER[source_id]
    source_name, source_class, title, basis = _CAPTURE_META[source_id]
    available = _PUBLISHER_TIMES.get(source_id)
    if available is None:
        available = record.get("retrieved_at_utc")
    if available is None:
        available = record["finished_at_utc"]
    if isinstance(available, str):
        available = datetime.fromisoformat(available.replace("Z", "+00:00"))
    return {
        "source_id": source_id,
        "source_name": source_name,
        "source_class": source_class,
        "title": title,
        "url": record["url"],
        "local_reference": record["raw_blob_path"],
        "source_sha256": record["sha256"],
        "source_available_by_utc": available,
        "temporal_basis": basis,
        "terms_disposition": record.get("terms_disposition", TERMS),
    }


def _evidence(
    evidence_id: str,
    source: dict[str, Any],
    text: str,
    *,
    locator: str,
    authority_scope: str,
    extraction_method: Literal[
        "literal_raw_span",
        "normalized_span",
        "deterministic_derivation",
    ],
    role: str = "required_support",
) -> DiverseEvidence:
    return DiverseEvidence(
        evidence_id=evidence_id,
        **source,
        authority_scope=authority_scope,
        locator=locator,
        exact_text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        extraction_method=extraction_method,
        role=role,
    )


def _normalized(
    evidence_id: str,
    snapshot_id: str,
    span_id: str,
    authority_scope: str,
    *,
    role: str = "required_support",
) -> DiverseEvidence:
    document = next(
        value
        for value in DOCUMENTS
        if value.snapshot_id == snapshot_id
        and any(span.span_id == span_id for span in value.spans)
    )
    span = next(value for value in document.spans if value.span_id == span_id)
    text = document.normalized_text[span.start_char : span.end_char]
    return _evidence(
        evidence_id,
        _existing_source(snapshot_id),
        text,
        locator=span.raw_locator or span.field_path,
        authority_scope=authority_scope,
        extraction_method="normalized_span",
        role=role,
    )


def _raw(
    evidence_id: str,
    source_id: str,
    text: str,
    *,
    locator: str,
    authority_scope: str,
    role: str = "required_support",
) -> DiverseEvidence:
    source = _captured_source(source_id)
    path = ROOT / source["local_reference"]
    if text not in path.read_text(encoding="utf-8", errors="replace"):
        raise ValueError(f"exact text missing from {source_id}: {text!r}")
    return _evidence(
        evidence_id,
        source,
        text,
        locator=locator,
        authority_scope=authority_scope,
        extraction_method="literal_raw_span",
        role=role,
    )


def _derived(
    evidence_id: str,
    source_id: str,
    text: str,
    *,
    locator: str,
    authority_scope: str,
    role: str = "required_support",
) -> DiverseEvidence:
    """Bind deterministic JSON/PDF extraction text to exact ignored bytes."""

    return _evidence(
        evidence_id,
        _captured_source(source_id),
        text,
        locator=locator,
        authority_scope=authority_scope,
        extraction_method="deterministic_derivation",
        role=role,
    )


def _existing_raw(
    evidence_id: str,
    snapshot_id: str,
    text: str,
    *,
    locator: str,
    authority_scope: str,
    role: str = "required_support",
) -> DiverseEvidence:
    source = _existing_source(snapshot_id)
    path = ROOT / source["local_reference"]
    if text not in path.read_text(encoding="utf-8", errors="replace"):
        raise ValueError(f"exact text missing from {snapshot_id}: {text!r}")
    return _evidence(
        evidence_id,
        source,
        text,
        locator=locator,
        authority_scope=authority_scope,
        extraction_method="literal_raw_span",
        role=role,
    )


def _existing_derived(
    evidence_id: str,
    snapshot_id: str,
    text: str,
    *,
    locator: str,
    authority_scope: str,
    role: str = "required_support",
) -> DiverseEvidence:
    return _evidence(
        evidence_id,
        _existing_source(snapshot_id),
        text,
        locator=locator,
        authority_scope=authority_scope,
        extraction_method="deterministic_derivation",
        role=role,
    )


def _question(**values: Any) -> DiverseQuestion:
    values["question_sha256"] = "0" * 64
    values["question_sha256"] = canonical_sha256(
        {key: value for key, value in values.items() if key != "question_sha256"}
    )
    return DiverseQuestion.model_validate(values)


def _retained_questions() -> list[DiverseQuestion]:
    records = [
        BenchmarkCase.model_validate_json(line)
        for line in V2.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    questions: list[DiverseQuestion] = []
    for index, case in enumerate(sorted(records, key=lambda value: value.case_id)):
        claim = case.expected_claims[0]
        answer = claim.object.value
        if not isinstance(answer, (str, bool, list)):
            answer = json.dumps(answer, sort_keys=True, separators=(",", ":"))
        values: dict[str, Any] = {
            "case_id": case.case_id,
            "slice": "single_source_extraction",
            "source_family_id": case.entity_family_id,
            "dependency_id": case.entity_family_id,
            "split": case.split,
            "predicate": claim.predicate,
            "answer_type": (
                "boolean"
                if isinstance(answer, bool)
                else "set"
                if isinstance(answer, list)
                else "string"
            ),
            "outcome_type": "positive",
            "cutoff_utc": case.as_of,
            "question": case.question,
            "expected_answer": answer,
            "abstention_reason": None,
            "evidence": [],
            "required_evidence_ids": [],
            "authority_rationale": (
                "Unchanged reviewed v2 authority decision; see the frozen packet."
            ),
            "temporal_rationale": (
                "Unchanged reviewed v2 cutoff and source-version decision."
            ),
            "ambiguity_notes": "No semantic change from the reviewed v2 label.",
            "leakage_audit": (
                "Retained by exact case hash; no question or gold regeneration."
            ),
            "retained_v2_case_id": case.case_id,
            "retained_v2_case_sha256": canonical_sha256(case),
            "review_status": "approved_v2",
        }
        questions.append(_question(**values))
        assert index < 16
    return questions


def _new_question(
    *,
    case_id: str,
    slice_name: str,
    family: str,
    predicate: str,
    answer_type: str,
    outcome: str,
    cutoff: str,
    question: str,
    answer: str | bool | list[str] | None,
    abstention_reason: str | None,
    evidence: list[DiverseEvidence],
    authority: str,
    temporal: str,
    ambiguity: str,
    leakage: str,
) -> DiverseQuestion:
    cutoff_value = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
    return _question(
        case_id=case_id,
        slice=slice_name,
        source_family_id=family,
        dependency_id=family,
        split="dev" if int(case_id.rsplit("-", 1)[1]) % 2 else "validation",
        predicate=predicate,
        answer_type=answer_type,
        outcome_type=outcome,
        cutoff_utc=cutoff_value,
        question=question,
        expected_answer=answer,
        abstention_reason=abstention_reason,
        evidence=evidence,
        required_evidence_ids=[
            item.evidence_id for item in evidence if item.role == "required_support"
        ],
        authority_rationale=authority,
        temporal_rationale=temporal,
        ambiguity_notes=ambiguity,
        leakage_audit=leakage,
        retained_v2_case_id=None,
        retained_v2_case_sha256=None,
        review_status="manager_audit_pending",
    )


def _temporal_questions() -> list[DiverseQuestion]:
    apache_old = _existing_raw(
        "apache-2450:cve-2021-41773-entry",
        "apache-httpd-2.4.50-026807b9af4d",
        "SECURITY: CVE-2021-41773: Path traversal and file disclosure",
        locator="line containing CVE-2021-41773",
        authority_scope="Apache release-note content",
    )
    apache_new = _normalized(
        "apache-2451:cve-2021-42013-affected",
        "apache-httpd-2.4.51-3e118515cb85",
        "cve-2021-42013-affected-versions",
        "Apache affected-version declaration",
    )
    kev_old = _normalized(
        "kev-0257-old:ransomware",
        "cisa-kev-2026-07-16-41d27023a591",
        "known-ransomware-campaign-use",
        "CISA KEV ransomware-use status",
    )
    kev_new = _normalized(
        "kev-0257-new:ransomware",
        "cisa-kev-2026-07-21-f17a5ced05e7",
        "known-ransomware-campaign-use",
        "CISA KEV ransomware-use status",
    )
    attack_old = _normalized(
        "attack-151:t1027-011-platforms",
        "mitre-attack-enterprise-15.1-a57988bffe40",
        "t1027-011-platforms",
        "MITRE ATT&CK platform mapping",
    )
    attack_new = _normalized(
        "attack-160:t1027-011-platforms",
        "mitre-attack-enterprise-16.0-b7c3d0bc3ba8",
        "t1027-011-platforms",
        "MITRE ATT&CK platform mapping",
    )
    xz_old = _existing_raw(
        "cve-3094-initial:xz-default",
        "cve-3094-e6d66b8ec2f1",
        '"defaultStatus": "affected"',
        locator="/containers/cna/affected/0",
        authority_scope="CVE Program CNA container state",
    )
    xz_new_0 = _normalized(
        "cve-3094-apr18:affected-560",
        "cve-3094-f839db1bd834",
        "affected-version-0",
        "CVE Program CNA affected-version entry",
    )
    xz_new_1 = _normalized(
        "cve-3094-apr18:affected-561",
        "cve-3094-f839db1bd834",
        "affected-version-1",
        "CVE Program CNA affected-version entry",
    )
    ivanti_old = _normalized(
        "ivanti-v1:disconnect",
        "cisa-ivanti-v1-96e00cfa8be1",
        "required-disconnect",
        "CISA directive obligation",
    )
    ivanti_new = _normalized(
        "ivanti-v2:feb8-update",
        "cisa-ivanti-v2-d1287ba8ae63",
        "required-february-8-update",
        "CISA directive obligation",
    )
    netscaler_old = _existing_raw(
        "netscaler-oct23:kill-sessions",
        "netscaler-oct23-6bd3c8bc892e",
        "we also recommend killing all active and persistent sessions using the following commands:",
        locator="paragraph preceding session-clear commands",
        authority_scope="NetScaler remediation guidance",
    )
    netscaler_new = _normalized(
        "netscaler-nov20:tcpconnstat",
        "netscaler-nov20-6c104a9397cf",
        "ssl-vpn-source-ip-pattern",
        "NetScaler investigation guidance",
    )
    django_old = _existing_raw(
        "django-502:release-summary",
        "django-release-5.0.2-15f7b4ff0675",
        'Django 5.0.2 fixes a security issue with severity "moderate" and several bugs',
        locator="release-note summary",
        authority_scope="Django release-note content",
    )
    django_new = _normalized(
        "django-503:cve-2024-27351",
        "django-release-5.0.3-9ef8c1a9049c",
        "django-cve-2024-27351",
        "Django named CVE fix",
    )
    node_old = _existing_raw(
        "node-prerelease:timing",
        "nodejs-may-2025-prerelease-af6b7017610f",
        "Releases will be available on, or shortly after, Wednesday, May 14, 2025.",
        locator="Release timing section",
        authority_scope="Node.js prerelease announcement",
    )
    node_new = _normalized(
        "node-release:versions",
        "nodejs-may-2025-released-7c42a1b3d79e",
        "nodejs-released-versions",
        "Node.js released-version list",
    )
    common = {
        "slice_name": "temporal_comparison",
        "predicate": "source.temporal_change",
        "answer_type": "qualified_statement",
        "outcome": "positive",
        "abstention_reason": None,
        "authority": "Each answer is limited to what the named publisher states establish.",
        "temporal": (
            "Both states are independently addressable publisher versions; their "
            "declared times do not prove contemporaneous public observation."
        ),
        "ambiguity": "The answer must describe the semantic delta, not timestamp metadata.",
        "leakage": "Source IDs and ordering do not encode the expected delta.",
    }
    return [
        _new_question(
            case_id="portfolio-diverse-temporal-01",
            family="apache-httpd-cve-2021-41773-42013",
            cutoff="2021-10-07T15:22:01Z",
            question=(
                "Comparing Apache's 2.4.50 and 2.4.51 release notes, what "
                "substantive CVE/affected-version statement was added in 2.4.51?"
            ),
            answer=(
                "2.4.51 added CVE-2021-42013 and stated that Apache 2.4.49 "
                "and 2.4.50, but not earlier versions, were affected."
            ),
            evidence=[apache_old, apache_new],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-temporal-02",
            family="cisa-kev-cve-2026-0257",
            cutoff="2026-07-21T15:43:33Z",
            question=(
                "How did CISA KEV's known-ransomware-campaign-use status for "
                "CVE-2026-0257 change between the two pinned catalog commits?"
            ),
            answer="It changed from Unknown to Known.",
            evidence=[kev_old, kev_new],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-temporal-03",
            family="mitre-attack-t1027-011",
            cutoff="2024-10-31T13:20:15Z",
            question=(
                "Which platform was added to ATT&CK technique T1027.011 between "
                "Enterprise ATT&CK 15.1 and 16.0?"
            ),
            answer="Linux was added; Windows remained listed.",
            evidence=[attack_old, attack_new],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-temporal-04",
            family="cve-2024-3094",
            cutoff="2024-04-18T17:33:59Z",
            question=(
                "How did the CVE Program's CNA affected-version representation "
                "for xz change from the initial CVE-2024-3094 record to the April 18 record?"
            ),
            answer=(
                "The initial record treated xz as affected by default without "
                "explicit versions; the later record explicitly listed 5.6.0 and "
                "5.6.1 as affected and made the default unaffected."
            ),
            evidence=[xz_old, xz_new_0, xz_new_1],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-temporal-05",
            family="ivanti-ed-24-01",
            cutoff="2024-03-04T23:59:59Z",
            question=(
                "What new required action appeared in CISA's V2 supplemental "
                "direction after V1's disconnect deadline?"
            ),
            answer=(
                "V2 required returned systems to apply Ivanti's February 8 update "
                "for CVE-2024-22024 by 11:59 PM on February 12, 2024."
            ),
            evidence=[ivanti_old, ivanti_new],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-temporal-06",
            family="netscaler-cve-2023-4966",
            cutoff="2023-11-20T17:30:26Z",
            question=(
                "What investigation guidance did NetScaler add in its November "
                "CVE-2023-4966 post beyond the October session-clearing guidance?"
            ),
            answer=(
                "It added a recommendation to review SSLVPN TCPCONNSTAT logs for "
                "one source IP accessing sessions belonging to multiple users."
            ),
            evidence=[netscaler_old, netscaler_new],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-temporal-07",
            family="django-cve-2024-27351",
            cutoff="2024-03-04T07:22:41Z",
            question=(
                "What named vulnerability statement appears in Django 5.0.3 that "
                "is not present in the 5.0.2 release note?"
            ),
            answer=(
                "Django 5.0.3 names CVE-2024-27351, a potential regular-expression "
                "denial of service in Truncator.words()."
            ),
            evidence=[django_old, django_new],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-temporal-08",
            family="nodejs-may-2025-security-release",
            cutoff="2025-05-14T21:31:45Z",
            question=(
                "Which exact Node.js releases replaced the prerelease timing "
                "announcement in the later May 2025 security post?"
            ),
            answer=["20.19.2", "22.15.1", "23.11.1", "24.0.2"],
            evidence=[node_old, node_new],
            answer_type="set",
            **{key: value for key, value in common.items() if key != "answer_type"},
        ),
    ]


def _additional_temporal_questions() -> list[DiverseQuestion]:
    postgres_old = _existing_raw(
        "temporal-postgres:release-154",
        "postgresql-release-15.4-ae3ad23c513f",
        "<title>Release 15.4</title>",
        locator="release title",
        authority_scope="PostgreSQL release state",
    )
    postgres_new = _normalized(
        "temporal-postgres:cve-5868",
        "postgresql-release-15.5-7aa8ae2a9d84",
        "postgresql-cve-2023-5868-fixed-release",
        "PostgreSQL named CVE fix",
    )
    rust_old = _existing_raw(
        "temporal-rust:release-1771",
        "rust-release-1.77.1-0d2c16748223",
        '"tag":"1.77.1"',
        locator="/tag",
        authority_scope="Rust release identity",
    )
    rust_new = _normalized(
        "temporal-rust:fixed-1772",
        "rust-advisory-cve-2024-24576-7c7f74fb328e",
        "rust-cve-2024-24576-fixed-release",
        "Rust advisory fixed-release statement",
    )
    python_old = _existing_raw(
        "temporal-python:release-3113",
        "python-release-v3.11.3-f3ef3d1fc4f0",
        '"tag":"v3.11.3"',
        locator="/tag",
        authority_scope="CPython release identity",
    )
    python_new = _normalized(
        "temporal-python:cve-24329",
        "python-news-v3.11.4-ffa17d51fb5b",
        "python-cve-2023-24329-fixed-release",
        "CPython CVE-linked NEWS entry",
    )
    jenkins_old = _existing_raw(
        "temporal-jenkins:release-294",
        "jenkins-release-2.94-ea9f8cc893ab",
        '"tag":"jenkins-2.94"',
        locator="/tag",
        authority_scope="Jenkins release identity",
    )
    jenkins_new = _normalized(
        "temporal-jenkins:update-295",
        "jenkins-advisory-2017-12-14-19f2d5703e50",
        "jenkins-mainline-fixed-release",
        "Jenkins security advisory update direction",
    )
    fortios_old = _existing_derived(
        "temporal-fortios:range-absent",
        "nvd-cve-2024-21762-event-2024-02-13-06a24ce0f710",
        "The pinned February event contains no FortiOS 6.0.0-to-6.0.18 CPE range.",
        locator="deterministic normalized-field absence",
        authority_scope="NVD change-event state",
    )
    fortios_new = _normalized(
        "temporal-fortios:range-added",
        "nvd-cve-2024-21762-event-2024-11-29-dd85fa43ba45",
        "fortios-6-0-before-6-0-18-cpe",
        "NVD CPE applicability range",
    )
    nexus_old = _existing_derived(
        "temporal-nexus:cpe-absent",
        "nvd-cve-2023-20115-event-2023-08-29-4fecc0c933c8",
        "The pinned August event contains no Nexus 3636C-R hardware CPE.",
        locator="deterministic normalized-field absence",
        authority_scope="NVD change-event state",
    )
    nexus_new = _normalized(
        "temporal-nexus:cpe-added",
        "nvd-cve-2023-20115-event-2023-10-03-83ef0e7478f2",
        "cisco-nexus-3636c-r-cpe",
        "NVD CPE applicability entry",
    )
    ddwrt_old = _existing_derived(
        "temporal-ddwrt:kev-absent",
        "cisa-kev-2026-07-16-41d27023a591",
        "CVE-2021-27137 is absent from the pinned July 16 KEV catalog.",
        locator="deterministic catalog membership scan",
        authority_scope="CISA KEV membership state",
    )
    ddwrt_new = _normalized(
        "temporal-ddwrt:kev-added",
        "cisa-kev-2026-07-21-f17a5ced05e7",
        "cve-2021-27137-membership",
        "CISA KEV membership state",
    )
    panos_old = _existing_derived(
        "temporal-panos:cpe-absent",
        "nvd-cve-2024-3400-event-2024-04-23-e1b609605187",
        "The pinned April event contains no PAN-OS 10.2.2-h5 CPE.",
        locator="deterministic normalized-field absence",
        authority_scope="NVD change-event state",
    )
    panos_new = _normalized(
        "temporal-panos:cpe-added",
        "nvd-cve-2024-3400-event-2024-05-29-3d2e96e65c2b",
        "pan-os-10-2-2-h5-cpe",
        "NVD CPE applicability entry",
    )
    curl_old = _raw(
        "temporal-curl:release-830",
        "curl-release-notes-8.3.0-repair",
        "curl and libcurl 8.3.0",
        locator="release-note title",
        authority_scope="curl release state",
    )
    curl_new = _raw(
        "temporal-curl:cve-link-840",
        "curl-release-notes-8.4.0-repair",
        "[118] = https://curl.se/docs/CVE-2023-38545.html",
        locator="release-note reference 118",
        authority_scope="curl release-note CVE link",
    )
    git_old = _raw(
        "temporal-git:release-2390",
        "git-release-2.39.0",
        "Git v2.39 Release Notes",
        locator="release-note title",
        authority_scope="Git project release state",
    )
    git_new = _raw(
        "temporal-git:security-fix-2391",
        "git-release-2.39.1",
        "This release merges the security fix that appears in v2.30.7",
        locator="release-note body",
        authority_scope="Git project security-release statement",
    )
    guralp_initial_product = _raw(
        "temporal-guralp:initial-fmus",
        "cisa-icsa-25-212-01-initial",
        "Güralp FMUS Series Seismic Monitoring Devices",
        locator="/product_tree/branches/0/branches/0/name",
        authority_scope="CISA coordinator product scope",
    )
    guralp_update_product = _raw(
        "temporal-guralp:update-a-min",
        "cisa-icsa-25-212-01-update-a",
        "Güralp MIN Series Digitizing Devices",
        locator="/product_tree/branches/0/branches/1/name",
        authority_scope="CISA coordinator product scope",
    )
    guralp_update_a = _raw(
        "temporal-guralp:update-a-no-response",
        "cisa-icsa-25-212-01-update-a",
        "did not respond to CISA's attempts at coordination.",
        locator="/vulnerabilities/0/remediations/0/details",
        authority_scope="CISA coordinator remediation state",
    )
    guralp_update_b = _raw(
        "temporal-guralp:update-b-firmware",
        "cisa-icsa-25-212-01-update-b",
        "experimental firmware release v2.1-29897 introduces authentication for Telnet access",
        locator="/vulnerabilities/0/remediations/1/details",
        authority_scope="CISA coordinator record of vendor-qualified mitigation",
    )
    kunbus_initial_image = _raw(
        "temporal-kunbus:initial-planned-plugin",
        "cisa-icsa-25-121-01-initial",
        "By end of April 2025, KUNBUS plans to release a new Cockpit plugin",
        locator="/vulnerabilities/0/remediations/3/details",
        authority_scope="CISA coordinator remediation state",
    )
    kunbus_update_image = _raw(
        "temporal-kunbus:update-a-image",
        "cisa-icsa-25-121-01-update-a",
        "KUNBUS released a new image for Revolution Pi OS Bookworm on 04/30/2025.",
        locator="/vulnerabilities/0/remediations/3/details",
        authority_scope="CISA coordinator record of vendor-qualified fix",
    )
    kunbus_initial_pictory = _raw(
        "temporal-kunbus:initial-pictory",
        "cisa-icsa-25-121-01-initial",
        "Update PiCtory package to version 2.12",
        locator="/vulnerabilities/0/remediations/1/details",
        authority_scope="CISA coordinator remediation state",
    )
    kunbus_update_pictory = _raw(
        "temporal-kunbus:update-a-pictory",
        "cisa-icsa-25-121-01-update-a",
        "Update PiCtory package to version 2.12",
        locator="/vulnerabilities/0/remediations/1/details",
        authority_scope="CISA coordinator remediation state",
    )
    guralp_initial_contact = _raw(
        "temporal-guralp:initial-contact",
        "cisa-icsa-25-212-01-initial",
        "did not respond to CISA's attempts at coordination.",
        locator="/vulnerabilities/0/remediations/0/details",
        authority_scope="CISA coordinator remediation state",
    )
    guralp_update_contact = _raw(
        "temporal-guralp:update-a-contact",
        "cisa-icsa-25-212-01-update-a",
        "did not respond to CISA's attempts at coordination.",
        locator="/vulnerabilities/0/remediations/0/details",
        authority_scope="CISA coordinator remediation state",
    )
    ecovacs_initial = _raw(
        "temporal-ecovacs:initial-two-products",
        "cisa-icsa-25-135-19-initial",
        "ECOVACS has released software updates for the X1S PRO and X1 PRO OMNI.",
        locator="/vulnerabilities/0/remediations/0/details",
        authority_scope="CISA coordinator remediation scope",
    )
    ecovacs_update = _raw(
        "temporal-ecovacs:update-all-products",
        "cisa-icsa-25-135-19-update-a",
        "ECOVACS has released software updates for all affected devices.",
        locator="/vulnerabilities/0/remediations/0/details",
        authority_scope="CISA coordinator remediation scope",
    )
    history_source = _captured_source("nvd-cve-2024-6387-history-api")
    history = json.loads((ROOT / history_source["local_reference"]).read_text())
    description_events = []
    for event in history["cveChanges"]:
        for detail in event["change"]["details"]:
            if detail["type"] == "Description" and detail["action"] in {
                "Added",
                "Changed",
            }:
                description_events.append((event["change"]["created"], detail))
    first_description = description_events[0][1]["newValue"]
    changed_description = next(
        detail["newValue"]
        for _, detail in description_events
        if detail["action"] == "Changed"
    )
    nvd_desc_old = _evidence(
        "temporal-openssh:initial-description",
        history_source,
        first_description,
        locator="first NVD Description Added event",
        authority_scope="NVD recorded description state",
        extraction_method="deterministic_derivation",
    )
    nvd_desc_new = _evidence(
        "temporal-openssh:changed-description",
        history_source,
        changed_description,
        locator="first NVD Description Changed event",
        authority_scope="NVD recorded description state",
        extraction_method="deterministic_derivation",
    )
    common = {
        "slice_name": "temporal_comparison",
        "predicate": "source.temporal_change",
        "answer_type": "qualified_statement",
        "outcome": "positive",
        "abstention_reason": None,
        "authority": "The answer is limited to the named publisher's version history.",
        "temporal": (
            "The compared states are exact publisher versions; declared revision "
            "times are not proof of independent historical observation."
        ),
        "ambiguity": "Both states are mandatory evidence; metadata-only differences do not count.",
        "leakage": "Neutral state identifiers and shuffled packet order do not reveal the delta.",
    }
    specs = [
        (
            "09",
            "postgresql-cve-2023-5868-release-15-5",
            "2023-11-09T23:59:59Z",
            "What CVE-linked fix appears in PostgreSQL 15.5 but not the 15.4 state?",
            "15.5 adds the aggregate-function memory-disclosure fix identified as CVE-2023-5868.",
            [postgres_old, postgres_new],
            "positive",
        ),
        (
            "10",
            "rust-cve-2024-24576",
            "2024-04-09T23:59:59Z",
            "What fixed-release statement became available after Rust 1.77.1 for CVE-2024-24576?",
            "The advisory says the fix is included in Rust 1.77.2.",
            [rust_old, rust_new],
            "positive",
        ),
        (
            "11",
            "python-cve-2023-24329",
            "2023-06-06T22:00:30Z",
            "What CVE-linked URL parsing change appears after the CPython 3.11.3 state?",
            "The 3.11.4 NEWS entry says urlsplit strips leading C0 controls and spaces in response to CVE-2023-24329.",
            [python_old, python_new],
            "positive",
        ),
        (
            "12",
            "jenkins-2017-12-14-security-release",
            "2017-12-14T00:00:00Z",
            "What mainline update direction appears after the Jenkins 2.94 state?",
            "The advisory directs Jenkins mainline users to update to 2.95.",
            [jenkins_old, jenkins_new],
            "positive",
        ),
        (
            "13",
            "nvd-cve-2024-21762-cpe-history",
            "2024-11-29T15:23:33Z",
            "What FortiOS 6.0 applicability range appears in the later NVD change state?",
            "The later state adds FortiOS 6.0.0 through, but excluding, 6.0.18.",
            [fortios_old, fortios_new],
            "positive",
        ),
        (
            "14",
            "nvd-cve-2023-20115-cpe-history",
            "2023-10-03T13:50:24Z",
            "What hardware applicability entry appears in the later CVE-2023-20115 NVD state?",
            "The later state adds the Cisco Nexus 3636C-R hardware CPE.",
            [nexus_old, nexus_new],
            "positive",
        ),
        (
            "15",
            "cisa-kev-cve-2021-27137",
            "2026-07-21T15:43:33Z",
            "How did CISA KEV membership for CVE-2021-27137 change between the pinned catalogs?",
            "It changed from absent on July 16 to present on July 21.",
            [ddwrt_old, ddwrt_new],
            "positive",
        ),
        (
            "16",
            "nvd-cve-2024-3400-cpe-history",
            "2024-05-29T16:00:25Z",
            "What PAN-OS CPE applicability entry appears in the later NVD state?",
            "The later state adds PAN-OS 10.2.2-h5.",
            [panos_old, panos_new],
            "positive",
        ),
        (
            "17",
            "curl-cve-2023-38545-release-8-4-0",
            "2023-10-11T23:59:59Z",
            "What CVE reference appears in curl 8.4.0 that is absent from the 8.3.0 release notes?",
            "The 8.4.0 release notes add a reference to CVE-2023-38545.",
            [curl_old, curl_new],
            "positive",
        ),
        (
            "18",
            "git-security-release-v2-39-1",
            "2023-01-17T23:59:59Z",
            "What security-release statement appears in Git 2.39.1 after the 2.39.0 state?",
            "Git 2.39.1 says it merges the security fix that appears in v2.30.7.",
            [git_old, git_new],
            "positive",
        ),
        (
            "19",
            "cisa-icsa-25-212-01-guralp",
            "2025-08-14T06:00:00Z",
            "What product scope did CISA add in Güralp Update A?",
            "Update A added Güralp MIN Series Digitizing Devices alongside FMUS devices.",
            [guralp_initial_product, guralp_update_product],
            "positive",
        ),
        (
            "20",
            "cisa-icsa-25-212-01-guralp",
            "2026-01-13T07:00:00Z",
            "What remediation became available in Güralp Update B after Update A?",
            "Update B records experimental firmware v2.1-29897 adding Telnet authentication.",
            [guralp_update_a, guralp_update_b],
            "positive",
        ),
        (
            "21",
            "cisa-icsa-25-121-01-kunbus",
            "2025-07-10T06:00:00Z",
            "What concrete Bookworm remediation did KUNBUS Update A add?",
            "It added a new Revolution Pi OS Bookworm image released on April 30, 2025.",
            [kunbus_initial_image, kunbus_update_image],
            "positive",
        ),
        (
            "22",
            "cisa-icsa-25-135-19-ecovacs",
            "2025-07-10T06:00:00Z",
            "How did ECOVACS remediation coverage change from the initial CISA state to Update A?",
            "Coverage expanded from X1S PRO and X1 PRO OMNI to all affected devices.",
            [ecovacs_initial, ecovacs_update],
            "positive",
        ),
        (
            "23",
            "nvd-cve-2024-6387-description-history",
            "2026-07-23T00:00:00Z",
            "What substantive description change does NVD record for CVE-2024-6387?",
            "NVD changes from a concise sshd signal-handler race description to a broader description that adds affected-version and exploitability context.",
            [nvd_desc_old, nvd_desc_new],
            "positive",
        ),
        (
            "24",
            "cisa-icsa-25-121-01-kunbus",
            "2025-07-10T06:00:00Z",
            "Did CISA's PiCtory update recommendation change between the initial KUNBUS state and Update A?",
            "No. Both states recommend updating PiCtory to version 2.12.",
            [kunbus_initial_pictory, kunbus_update_pictory],
            "no_change",
        ),
        (
            "25",
            "cisa-icsa-25-212-01-guralp",
            "2025-08-14T06:00:00Z",
            "Did CISA's statement about Güralp's coordination response change from the initial state to Update A?",
            "No. Both states say Güralp did not respond to CISA's coordination attempts.",
            [guralp_initial_contact, guralp_update_contact],
            "no_change",
        ),
    ]
    return [
        _new_question(
            case_id=f"portfolio-diverse-temporal-{number}",
            family=family,
            cutoff=cutoff,
            question=question,
            answer=answer,
            evidence=evidence,
            outcome=outcome,
            **{key: value for key, value in common.items() if key != "outcome"},
        )
        for number, family, cutoff, question, answer, evidence, outcome in specs
    ]


def _abstention_questions() -> list[DiverseQuestion]:
    xz_old = _existing_raw(
        "abstain-xz:eligible-default",
        "cve-3094-e6d66b8ec2f1",
        '"defaultStatus": "affected"',
        locator="/containers/cna/affected/0",
        authority_scope="CVE Program CNA state",
        role="eligible_but_insufficient",
    )
    xz_later = _normalized(
        "abstain-xz:postcutoff-560",
        "cve-3094-f839db1bd834",
        "affected-version-0",
        "CVE Program CNA affected-version entry",
        role="excluded_post_cutoff",
    )
    apache_old = _existing_raw(
        "abstain-apache:eligible-41773",
        "apache-httpd-2.4.50-026807b9af4d",
        "SECURITY: CVE-2021-41773: Path traversal and file disclosure",
        locator="line containing CVE-2021-41773",
        authority_scope="Apache release-note content",
        role="eligible_but_insufficient",
    )
    apache_later = _normalized(
        "abstain-apache:postcutoff-42013",
        "apache-httpd-2.4.51-3e118515cb85",
        "cve-2021-42013-affected-versions",
        "Apache affected-version declaration",
        role="excluded_post_cutoff",
    )
    attack_old = _normalized(
        "abstain-attack:eligible-windows",
        "mitre-attack-enterprise-15.1-a57988bffe40",
        "t1027-011-platforms",
        "MITRE ATT&CK platform mapping",
        role="eligible_but_insufficient",
    )
    attack_later = _normalized(
        "abstain-attack:postcutoff-linux",
        "mitre-attack-enterprise-16.0-b7c3d0bc3ba8",
        "t1027-011-platforms",
        "MITRE ATT&CK platform mapping",
        role="excluded_post_cutoff",
    )
    node_old = _existing_raw(
        "abstain-node:eligible-timing",
        "nodejs-may-2025-prerelease-af6b7017610f",
        "Releases will be available on, or shortly after, Wednesday, May 14, 2025.",
        locator="Release timing section",
        authority_scope="Node.js prerelease announcement",
        role="eligible_but_insufficient",
    )
    node_later = _normalized(
        "abstain-node:postcutoff-versions",
        "nodejs-may-2025-released-7c42a1b3d79e",
        "nodejs-released-versions",
        "Node.js released-version list",
        role="excluded_post_cutoff",
    )
    git = _raw(
        "abstain-git:unnamed-security-fix",
        "git-release-2.39.1",
        "This release merges the security fix that appears in v2.30.7; see\nthe release notes for that version for details.",
        locator="entire release-note body",
        authority_scope="Git project release-note statement",
        role="eligible_but_insufficient",
    )
    kunbus = _raw(
        "abstain-kunbus:bookworm-image",
        "cisa-icsa-25-121-01-update-a",
        "KUNBUS released a new image for Revolution Pi OS Bookworm on 04/30/2025. Users can download the updated image here.",
        locator="/vulnerabilities/0/remediations/3/details",
        authority_scope="CISA coordinator record of a KUNBUS-qualified fix",
        role="eligible_but_insufficient",
    )
    nvd = _raw(
        "abstain-openssh:nvd-description",
        "nvd-cve-2024-6387-history-api",
        "A signal handler race condition was found in OpenSSH's server (sshd)",
        locator="/cveChanges/0/change/details/0/newValue",
        authority_scope="NVD change-history description, not upstream fixed-release authority",
        role="eligible_but_insufficient",
    )
    guralp_cisa = _raw(
        "abstain-guralp:cisa-experimental-firmware",
        "cisa-icsa-25-212-01-update-b",
        "For Minimus-based products (including Fortimus and Certimus), experimental firmware release v2.1-29897 introduces authentication for Telnet access. This change requires valid login credentials before allowing access to the Telnet interface, addressing the missing authentication condition described in CVE-2025-8286.",
        locator="/vulnerabilities/0/remediations/1/details",
        authority_scope="CISA coordinator record of a Güralp-qualified mitigation",
        role="eligible_but_insufficient",
    )
    guralp_page = _raw(
        "abstain-guralp:vendor-page-title",
        "guralp-firmware-and-software",
        "<title>FIRMWARE AND SOFTWARE</title>",
        locator="HTML title",
        authority_scope="Güralp vendor page; no matching release-status statement found",
        role="eligible_but_insufficient",
    )
    common = {
        "slice_name": "cutoff_or_insufficiency_abstention",
        "answer_type": "string",
        "outcome": "abstain",
        "answer": None,
        "authority": (
            "Abstention is required when eligible evidence lacks the named "
            "predicate, specificity, or authority."
        ),
        "temporal": (
            "Post-cutoff sources remain visible as excluded evidence and cannot "
            "repair an earlier answer."
        ),
        "ambiguity": "Invalid or empty output is not counted as an abstention.",
        "leakage": "The question does not name the missing fact or later answer.",
    }
    return [
        _new_question(
            case_id="portfolio-diverse-abstain-01",
            family="cve-2024-3094",
            predicate="cve.affected_versions",
            cutoff="2024-04-01T00:00:00Z",
            question=(
                "As of the cutoff, which exact xz versions did the CVE Program "
                "record explicitly as affected by CVE-2024-3094?"
            ),
            abstention_reason=(
                "No cutoff-eligible CVE Program state explicitly enumerates versions."
            ),
            evidence=[xz_old, xz_later],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-abstain-02",
            family="apache-httpd-cve-2021-41773-42013",
            predicate="vendor.release_affected_versions",
            cutoff="2021-10-06T00:00:00Z",
            question=(
                "Which HTTP Server versions had Apache identified as affected by "
                "CVE-2021-42013 by the cutoff?"
            ),
            abstention_reason=("Apache's supporting 2.4.51 statement is post-cutoff."),
            evidence=[apache_old, apache_later],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-abstain-03",
            family="mitre-attack-t1027-011",
            predicate="attack.platforms",
            cutoff="2024-06-01T00:00:00Z",
            question=(
                "Had MITRE ATT&CK added Linux to T1027.011's platforms by the cutoff?"
            ),
            abstention_reason=(
                "The eligible 15.1 state lists only Windows; the Linux-bearing "
                "16.0 state is post-cutoff."
            ),
            evidence=[attack_old, attack_later],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-abstain-04",
            family="nodejs-may-2025-security-release",
            predicate="vendor.security_release_versions",
            cutoff="2025-05-10T00:00:00Z",
            question=(
                "Which exact Node.js versions had been released for the May 2025 "
                "security update by the cutoff?"
            ),
            abstention_reason=(
                "The eligible announcement gives only future timing; exact release "
                "versions first appear after the cutoff."
            ),
            evidence=[node_old, node_later],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-abstain-05",
            family="git-security-release-v2-39-1",
            predicate="vendor.cve_fixed_release",
            cutoff="2023-01-18T00:00:00Z",
            question=(
                "Which CVE identifier does Git's v2.39.1 release note itself say it fixes?"
            ),
            abstention_reason=(
                "The release note declares a security fix but names no CVE."
            ),
            evidence=[git],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-abstain-06",
            family="cisa-icsa-25-121-01-kunbus",
            predicate="vendor.fixed_versions",
            cutoff="2025-07-11T00:00:00Z",
            question=(
                "What exact Revolution Pi OS Bookworm image version did KUNBUS "
                "release for the cited issue?"
            ),
            abstention_reason=(
                "The eligible coordinator record gives a release date but no image version."
            ),
            evidence=[kunbus],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-abstain-07",
            family="nvd-cve-2024-6387-description-history",
            predicate="vendor.fixed_versions",
            cutoff="2026-07-23T00:00:00Z",
            question=(
                "Using only NVD's change-history authority, which upstream OpenSSH "
                "release should be treated as the authoritative fixed version for CVE-2024-6387?"
            ),
            abstention_reason=(
                "NVD's record is not upstream OpenSSH fixed-release authority."
            ),
            evidence=[nvd],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-abstain-08",
            family="cisa-icsa-25-212-01-guralp",
            predicate="vendor.fixed_versions",
            cutoff="2026-07-23T00:00:00Z",
            question=(
                "Did Güralp's own captured firmware page establish that experimental "
                "v2.1-29897 was a generally available production release?"
            ),
            abstention_reason=(
                "CISA records an experimental vendor-qualified mitigation, while the "
                "captured Güralp page contains no matching production-release statement."
            ),
            evidence=[guralp_cisa, guralp_page],
            **common,
        ),
    ]


def _nvd_score(source_id: str, cve_id: str) -> DiverseEvidence:
    source = _captured_source(source_id)
    payload = json.loads((ROOT / source["local_reference"]).read_text())
    metrics = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]
    metric = next(item for item in metrics if item["source"] == "nvd@nist.gov")
    data = metric["cvssData"]
    text = f"NVD CVSS v3.1 primary score {data['baseScore']} ({data['vectorString']})"
    return _evidence(
        f"{source_id}:nvd-primary-cvss",
        source,
        text,
        locator=(
            "/vulnerabilities/0/cve/metrics/cvssMetricV31[source=nvd@nist.gov]/cvssData"
        ),
        authority_scope=f"NVD's own CVSS score for {cve_id}",
        extraction_method="deterministic_derivation",
    )


def _kev_field(cve_id: str, field: str, authority_scope: str) -> DiverseEvidence:
    snapshot = "cisa-kev-2026-07-21-f17a5ced05e7"
    source = _existing_source(snapshot)
    payload = json.loads((ROOT / source["local_reference"]).read_text())
    entry = next(
        value for value in payload["vulnerabilities"] if value["cveID"] == cve_id
    )
    text = f"{field}: {entry[field]}"
    return _evidence(
        f"kev-{cve_id.lower()}:{field}",
        source,
        text,
        locator=f"/vulnerabilities[cveID={cve_id}]/{field}",
        authority_scope=authority_scope,
        extraction_method="deterministic_derivation",
    )


def _authority_questions() -> list[DiverseQuestion]:
    curl_vendor = _derived(
        "curl-advisory:affected-boundary",
        "curl-cve-2023-38545-advisory-repair",
        (
            "Affected versions: libcurl 7.69.0 to and including 8.3.0; "
            "not affected: libcurl before 7.69.0 and 8.4.0 or later."
        ),
        locator="#affected-versions",
        authority_scope="curl project's affected-version declaration",
    )
    curl_nvd = _nvd_score("nvd-cve-2023-38545", "CVE-2023-38545")
    k8s_vendor = _raw(
        "kubernetes-advisory:fixed-1284",
        "kubernetes-cve-2023-5528-advisory-repair",
        "kubelet v1.28.4",
        locator="Fixed Versions list",
        authority_scope="Kubernetes project's fixed-version declaration",
    )
    k8s_nvd = _nvd_score("nvd-cve-2023-5528", "CVE-2023-5528")
    tomcat_vendor = _raw(
        "tomcat-security:fixed-and-affected",
        "tomcat-cve-2023-46589-security-page-repair",
        "Fixed in Apache Tomcat 9.0.83",
        locator="#Fixed_in_Apache_Tomcat_9.0.83",
        authority_scope="Apache Tomcat project's fixed-version declaration",
    )
    tomcat_nvd = _nvd_score("nvd-cve-2023-46589", "CVE-2023-46589")
    postgres_vendor = _normalized(
        "postgres-155:cve-2023-5868",
        "postgresql-release-15.5-7aa8ae2a9d84",
        "postgresql-cve-2023-5868-fixed-release",
        "PostgreSQL project's release-note declaration",
    )
    postgres_nvd = _nvd_score("nvd-cve-2023-5868", "CVE-2023-5868")
    apache_vendor = _normalized(
        "authority-apache:affected-versions",
        "apache-httpd-2.4.51-3e118515cb85",
        "cve-2021-42013-affected-versions",
        "Apache affected-version declaration",
    )
    apache_kev = _kev_field(
        "CVE-2021-42013",
        "requiredAction",
        "CISA KEV required-action declaration",
    )
    netscaler_vendor = _normalized(
        "authority-netscaler:log-guidance",
        "netscaler-nov20-6c104a9397cf",
        "ssl-vpn-source-ip-pattern",
        "NetScaler investigation guidance",
    )
    netscaler_kev = _kev_field(
        "CVE-2023-4966",
        "requiredAction",
        "CISA KEV required-action declaration",
    )
    panos_nvd = _normalized(
        "authority-panos:nvd-cpe",
        "nvd-cve-2024-3400-event-2024-05-29-3d2e96e65c2b",
        "pan-os-10-2-2-h5-cpe",
        "NVD applicability record",
    )
    panos_kev = _kev_field(
        "CVE-2024-3400",
        "requiredAction",
        "CISA KEV required-action declaration",
    )
    ecovacs_vendor = _raw(
        "authority-ecovacs:patched-version",
        "ecovacs-dsa20250509001",
        "<td>X1S PRO</td>\n\t\t\t<td>2.5.38</td>",
        locator="Versions and Fixes table",
        authority_scope="ECOVACS exact patched-version declaration",
    )
    ecovacs_cisa = _raw(
        "authority-ecovacs:all-devices",
        "cisa-icsa-25-135-19-update-a",
        "ECOVACS has released software updates for all affected devices. Devices that support automatic updates will receive system update notifications. ECOVACS has proactively pushed the update to users, ensuring all users are covered. Users can complete the fix by performing the system update.",
        locator="/vulnerabilities/0/remediations/0/details",
        authority_scope="CISA coordinator record of ECOVACS-qualified remediation scope",
    )
    common = {
        "slice_name": "authority_divergence",
        "predicate": "source.authority_divergence",
        "answer_type": "qualified_statement",
        "outcome": "positive",
        "abstention_reason": None,
        "authority": (
            "Each source is primary only for the named predicate: vendor/project "
            "product state, NVD scoring/applicability, or CISA KEV/coordination status."
        ),
        "temporal": (
            "Current observed records use a post-capture cutoff; older immutable "
            "release states remain publisher-declared version evidence."
        ),
        "ambiguity": "The answer must attribute each fact and must not blend authorities.",
        "leakage": "Neutral source labels do not reveal which predicate each source governs.",
        "cutoff": "2026-07-23T00:00:00Z",
    }
    return [
        _new_question(
            case_id="portfolio-diverse-authority-01",
            family="curl-cve-2023-38545-release-8-4-0",
            question=(
                "What does curl establish about the affected-version boundary for "
                "CVE-2023-38545, and what separate CVSS fact does NVD establish?"
            ),
            answer=(
                "curl says libcurl 7.69.0 through 8.3.0 is affected and 8.4.0+ "
                "is not; NVD's primary CVSS v3.1 score is 9.8."
            ),
            evidence=[curl_vendor, curl_nvd],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-authority-02",
            family="kubernetes-cve-2023-5528-v1-28-4",
            question=(
                "Which source establishes kubelet v1.28.4 as fixed for "
                "CVE-2023-5528, and which source establishes NVD's primary score?"
            ),
            answer=(
                "The Kubernetes advisory establishes v1.28.4 as fixed; NVD "
                "establishes its own primary CVSS v3.1 score of 8.8."
            ),
            evidence=[k8s_vendor, k8s_nvd],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-authority-03",
            family="tomcat-cve-2023-46589-9-0-83",
            question=(
                "Attribute the fixed-version and scoring claims for CVE-2023-46589 "
                "to the authority that actually establishes each."
            ),
            answer=(
                "Apache Tomcat establishes 9.0.83 as the fixed release; NVD "
                "establishes its own primary CVSS v3.1 score of 7.5."
            ),
            evidence=[tomcat_vendor, tomcat_nvd],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-authority-04",
            family="postgresql-cve-2023-5868-release-15-5",
            question=(
                "What claim can be attributed to PostgreSQL's REL_15_5 note, and "
                "what distinct score can be attributed to NVD for CVE-2023-5868?"
            ),
            answer=(
                "PostgreSQL's REL_15_5 note identifies the memory-disclosure fix "
                "as CVE-2023-5868; NVD's primary CVSS v3.1 score is 4.3."
            ),
            evidence=[postgres_vendor, postgres_nvd],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-authority-05",
            family="apache-httpd-cve-2021-41773-42013",
            question=(
                "For CVE-2021-42013, which affected-version fact is Apache's to "
                "establish, and which remediation obligation is CISA KEV's?"
            ),
            answer=(
                "Apache establishes that 2.4.49 and 2.4.50 were affected; CISA "
                "KEV establishes the required action to apply vendor updates."
            ),
            evidence=[apache_vendor, apache_kev],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-authority-06",
            family="netscaler-cve-2023-4966",
            question=(
                "Separate NetScaler's investigation guidance from CISA KEV's "
                "required action for CVE-2023-4966."
            ),
            answer=(
                "NetScaler recommends reviewing SSLVPN TCPCONNSTAT for one source "
                "IP accessing multiple users' sessions; CISA KEV requires applying "
                "mitigations and killing active and persistent sessions."
            ),
            evidence=[netscaler_vendor, netscaler_kev],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-authority-07",
            family="nvd-cve-2024-3400-cpe-history",
            question=(
                "What applicability fact does NVD's history establish for "
                "CVE-2024-3400, and what action does CISA KEV separately establish?"
            ),
            answer=(
                "NVD records the PAN-OS 10.2.2-h5 CPE as applicable; CISA KEV "
                "requires vendor mitigations or the specified Threat Prevention controls."
            ),
            evidence=[panos_nvd, panos_kev],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-authority-08",
            family="cisa-icsa-25-135-19-ecovacs",
            question=(
                "What exact patched-version fact is supported by ECOVACS, and what "
                "broader remediation-scope fact is supported by CISA's Update A?"
            ),
            answer=(
                "ECOVACS lists X1S PRO 2.5.38 as patched; CISA Update A records "
                "ECOVACS software updates as available for all affected devices."
            ),
            evidence=[ecovacs_vendor, ecovacs_cisa],
            **common,
        ),
    ]


def _synthesis_questions() -> list[DiverseQuestion]:
    curl_advisory = _derived(
        "synthesis-curl:version-boundary",
        "curl-cve-2023-38545-advisory-repair",
        (
            "Affected versions: libcurl 7.69.0 to and including 8.3.0; "
            "not affected: libcurl before 7.69.0 and 8.4.0 or later."
        ),
        locator="#affected-versions",
        authority_scope="curl project's affected-version declaration",
    )
    curl_release = _raw(
        "synthesis-curl:release-840",
        "curl-release-notes-8.4.0-repair",
        "curl and libcurl 8.4.0",
        locator="release-note title",
        authority_scope="curl project release identity",
    )
    k8s_advisory = _raw(
        "synthesis-k8s:fixed-1284",
        "kubernetes-cve-2023-5528-advisory-repair",
        "kubelet v1.28.4",
        locator="Fixed Versions list",
        authority_scope="Kubernetes fixed-version declaration",
    )
    k8s_tag = _raw(
        "synthesis-k8s:tag-1284",
        "kubernetes-tag-object-1.28.4",
        '"tag":"v1.28.4","message":"Kubernetes official release v1.28.4\\n"',
        locator="/tag and /message",
        authority_scope="Kubernetes project release identity",
    )
    tomcat_security = _derived(
        "synthesis-tomcat:affected-fixed",
        "tomcat-cve-2023-46589-security-page-repair",
        (
            "CVE-2023-46589 was fixed in Apache Tomcat 9.0.83 and affects "
            "9.0.0-M1 through 9.0.82."
        ),
        locator="#Fixed_in_Apache_Tomcat_9.0.83",
        authority_scope="Apache Tomcat affected/fixed declaration",
    )
    tomcat_tag = _raw(
        "synthesis-tomcat:tag-9083",
        "tomcat-tag-ref-9.0.83",
        '"ref":"refs/tags/9.0.83"',
        locator="/ref",
        authority_scope="Apache Tomcat release identity",
    )
    postgres_note = _normalized(
        "synthesis-postgres:release-note",
        "postgresql-release-15.5-7aa8ae2a9d84",
        "postgresql-cve-2023-5868-fixed-release",
        "PostgreSQL CVE-linked release-note statement",
    )
    postgres_tag = _raw(
        "synthesis-postgres:tag-rel-15-5",
        "postgres-tag-ref-15.5",
        '"ref":"refs/tags/REL_15_5"',
        locator="/ref",
        authority_scope="PostgreSQL release identity",
    )
    netscaler_vendor = _normalized(
        "synthesis-netscaler:log-guidance",
        "netscaler-nov20-6c104a9397cf",
        "ssl-vpn-source-ip-pattern",
        "NetScaler investigation guidance",
    )
    netscaler_kev = _kev_field(
        "CVE-2023-4966",
        "requiredAction",
        "CISA KEV required-action declaration",
    )
    ecovacs_vendor = _derived(
        "synthesis-ecovacs:version-table",
        "ecovacs-dsa20250509001",
        (
            "ECOVACS patched versions include X1S PRO 2.5.38, X1 PRO OMNI "
            "2.5.38, X1 OMNI 2.4.45, X1 TURBO 2.4.45, T10 Series 1.11.0, "
            "T20 Series 1.25.0, and T30 Series 1.100.0."
        ),
        locator="Versions and Fixes table",
        authority_scope="ECOVACS exact patched-version declaration",
    )
    ecovacs_cisa = _raw(
        "synthesis-ecovacs:all-devices",
        "cisa-icsa-25-135-19-update-a",
        "ECOVACS has released software updates for all affected devices. Devices that support automatic updates will receive system update notifications. ECOVACS has proactively pushed the update to users, ensuring all users are covered. Users can complete the fix by performing the system update.",
        locator="/vulnerabilities/0/remediations/0/details",
        authority_scope="CISA coordinator record of all-device remediation scope",
    )
    kunbus_cisa = _raw(
        "synthesis-kunbus:new-image",
        "cisa-icsa-25-121-01-update-a",
        "KUNBUS released a new image for Revolution Pi OS Bookworm on 04/30/2025. Users can download the updated image here.",
        locator="/vulnerabilities/0/remediations/3/details",
        authority_scope="CISA coordinator record of KUNBUS image release",
    )
    kunbus_vendor = _derived(
        "synthesis-kunbus:manual-mitigations",
        "kunbus-2025-0000002-remediation",
        (
            "KUNBUS's remediation document directs users to activate Node-RED "
            "authentication, restrict network access, and deactivate Node-RED if unused."
        ),
        locator="PDF page 1, remediation sections",
        authority_scope="KUNBUS first-party manual mitigation guidance",
    )
    apache_vendor = _normalized(
        "synthesis-apache:affected-versions",
        "apache-httpd-2.4.51-3e118515cb85",
        "cve-2021-42013-affected-versions",
        "Apache affected-version declaration",
    )
    apache_kev = _kev_field(
        "CVE-2021-42013",
        "requiredAction",
        "CISA KEV required-action declaration",
    )
    common = {
        "slice_name": "multi_source_synthesis",
        "predicate": "source.multi_source_synthesis",
        "answer_type": "qualified_statement",
        "outcome": "positive",
        "abstention_reason": None,
        "authority": (
            "Every source supplies a distinct necessary predicate; no one span "
            "fully answers the question."
        ),
        "temporal": (
            "All current-page evidence uses an observed post-capture cutoff; "
            "tag/release timing remains publisher-declared version evidence."
        ),
        "ambiguity": "All listed evidence spans are required for full credit.",
        "leakage": "The document order is not meaningful and no source label contains gold.",
        "cutoff": "2026-07-23T00:00:00Z",
    }
    return [
        _new_question(
            case_id="portfolio-diverse-synthesis-01",
            family="curl-cve-2023-38545-release-8-4-0",
            question=(
                "Using the curl advisory and release identity together, state the "
                "last affected and first not-affected releases for CVE-2023-38545."
            ),
            answer="8.3.0 is the last affected release; 8.4.0 is the first not affected.",
            evidence=[curl_advisory, curl_release],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-synthesis-02",
            family="kubernetes-cve-2023-5528-v1-28-4",
            question=(
                "Which kubelet version does the security advisory identify as fixed, "
                "and which project release identity binds that version?"
            ),
            answer=(
                "The advisory identifies kubelet v1.28.4 as fixed, and the project "
                "tag object identifies v1.28.4 as an official Kubernetes release."
            ),
            evidence=[k8s_advisory, k8s_tag],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-synthesis-03",
            family="tomcat-cve-2023-46589-9-0-83",
            question=(
                "Combine Apache Tomcat's security statement with its release identity: "
                "what range was affected and which release fixed CVE-2023-46589?"
            ),
            answer=(
                "Tomcat 9.0.0-M1 through 9.0.82 was affected; the 9.0.83 release fixed it."
            ),
            evidence=[tomcat_security, tomcat_tag],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-synthesis-04",
            family="postgresql-cve-2023-5868-release-15-5",
            question=(
                "Which tagged PostgreSQL release contains the note that identifies "
                "the aggregate-function memory-disclosure fix as CVE-2023-5868?"
            ),
            answer="The tagged REL_15_5 release contains that CVE-2023-5868 note.",
            evidence=[postgres_note, postgres_tag],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-synthesis-05",
            family="netscaler-cve-2023-4966",
            question=(
                "For CVE-2023-4966, combine CISA KEV's required action with "
                "NetScaler's concrete post-remediation investigation check."
            ),
            answer=(
                "Apply mitigations and kill active and persistent sessions, then "
                "review SSLVPN TCPCONNSTAT for one source IP accessing multiple users' sessions."
            ),
            evidence=[netscaler_kev, netscaler_vendor],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-synthesis-06",
            family="cisa-icsa-25-135-19-ecovacs",
            question=(
                "What does the ECOVACS advisory establish about patched versions, "
                "and what broader coverage does CISA Update A record?"
            ),
            answer=(
                "ECOVACS lists exact patched versions for seven product lines; CISA "
                "Update A records software updates as available for all affected devices."
            ),
            evidence=[ecovacs_vendor, ecovacs_cisa],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-synthesis-07",
            family="cisa-icsa-25-121-01-kunbus",
            question=(
                "What two complementary remediation paths are established by CISA's "
                "KUNBUS Update A and KUNBUS's own remediation document?"
            ),
            answer=(
                "CISA records a new Revolution Pi OS Bookworm image; KUNBUS's document "
                "also directs users to enable Node-RED authentication, restrict network "
                "access, or disable Node-RED when unused."
            ),
            evidence=[kunbus_cisa, kunbus_vendor],
            **common,
        ),
        _new_question(
            case_id="portfolio-diverse-synthesis-08",
            family="apache-httpd-cve-2021-41773-42013",
            question=(
                "For CVE-2021-42013, synthesize Apache's affected-version boundary "
                "with CISA KEV's action requirement."
            ),
            answer=(
                "Apache identifies 2.4.49 and 2.4.50 as affected; CISA KEV requires "
                "applying updates per vendor instructions."
            ),
            evidence=[apache_vendor, apache_kev],
            **common,
        ),
    ]


def _build_review_packet(corpus: DiverseCorpusDraft) -> ReviewPacket:
    items: list[ReviewItem] = []
    terms: dict[str, str] = {}
    global_texts: dict[str, set[str]] = {}
    for question in corpus.questions:
        for span in question.evidence:
            global_texts.setdefault(span.source_id, set()).add(span.exact_text)
    global_normalized_hashes = {
        source_id: hashlib.sha256("\n".join(sorted(texts)).encode()).hexdigest()
        for source_id, texts in global_texts.items()
    }
    for question in corpus.questions:
        if question.review_status != "manager_audit_pending":
            continue
        by_source: dict[str, list[DiverseEvidence]] = {}
        for span in question.evidence:
            by_source.setdefault(span.source_id, []).append(span)
            terms[span.source_id] = span.terms_disposition
        sources: list[ReviewSource] = []
        for source_id, source_evidence in sorted(by_source.items()):
            exemplar = source_evidence[0]
            sources.append(
                ReviewSource(
                    snapshot_id=source_id,
                    source_name=exemplar.source_name,
                    source_class=exemplar.source_class,
                    title=exemplar.title,
                    canonical_url=exemplar.url,
                    local_reference=exemplar.local_reference,
                    published_at_utc=(
                        exemplar.source_available_by_utc
                        if exemplar.temporal_basis == "publisher_declared_version"
                        else None
                    ),
                    modified_at_utc=None,
                    retrieved_at_utc=NOW,
                    available_by_utc=exemplar.source_available_by_utc,
                    available_by_basis=exemplar.temporal_basis,
                    temporal_evidence_description=question.temporal_rationale,
                    raw_snapshot_sha256=exemplar.source_sha256,
                    normalized_text_sha256=global_normalized_hashes[source_id],
                )
            )

        review_evidence: list[ReviewEvidence] = []
        for span in question.evidence:
            review_evidence.append(
                ReviewEvidence(
                    evidence_id=span.evidence_id,
                    snapshot_id=span.source_id,
                    document_id=f"{span.source_id}-portfolio-diverse-v3",
                    span_id=span.evidence_id.replace(":", "-"),
                    field_path=span.locator,
                    exact_text=span.exact_text,
                    context_before="",
                    context_after="",
                    raw_locator=span.locator,
                    source_url=span.url,
                    local_reference=f"{span.local_reference}#{span.locator}",
                    source_name=span.source_name,
                    document_date_utc=span.source_available_by_utc,
                    available_by_utc=span.source_available_by_utc,
                    authority_category="primary",
                    cutoff_eligibility=(
                        "eligible"
                        if span.source_available_by_utc <= question.cutoff_utc
                        else "ineligible"
                    ),
                    raw_snapshot_sha256=span.source_sha256,
                    normalized_text_sha256=global_normalized_hashes[span.source_id],
                    span_text_sha256=span.text_sha256,
                )
            )
        required = set(question.required_evidence_ids)
        expected = sorted(
            [value for value in review_evidence if value.evidence_id in required],
            key=lambda value: value.evidence_id,
        )
        alternates = sorted(
            [value for value in review_evidence if value.evidence_id not in required],
            key=lambda value: value.evidence_id,
        )
        claim = None
        if question.expected_answer is not None:
            claim = ReviewClaim(
                claim_id=f"gold-{question.case_id}",
                subject={"type": "advisory", "id": question.source_family_id},
                predicate=question.predicate,
                value=question.expected_answer,
                datatype=(
                    "boolean"
                    if isinstance(question.expected_answer, bool)
                    else "identifier_set"
                    if isinstance(question.expected_answer, list)
                    else "string"
                ),
                qualifiers={
                    "authority": "predicate_scoped_sources",
                    "cvss_version": None,
                    "product": None,
                    "ecosystem": None,
                },
                evidence_ids=question.required_evidence_ids,
            )
        case_hash = question.question_sha256
        binding = {
            "case_sha256": case_hash,
            "sources": [
                {
                    "snapshot_id": source.snapshot_id,
                    "raw_snapshot_sha256": source.raw_snapshot_sha256,
                    "normalized_text_sha256": source.normalized_text_sha256,
                }
                for source in sources
            ],
            "evidence": [
                {
                    "evidence_id": value.evidence_id,
                    "raw_snapshot_sha256": value.raw_snapshot_sha256,
                    "normalized_text_sha256": value.normalized_text_sha256,
                    "span_text_sha256": value.span_text_sha256,
                }
                for value in [*expected, *alternates]
            ],
        }
        item_data: dict[str, Any] = {
            "item_id": f"review-{question.case_id}",
            "item_sha256": "0" * 64,
            "case_id": question.case_id,
            "case_sha256": case_hash,
            "question": question.question,
            "cutoff_utc": question.cutoff_utc,
            "case_category": (
                "insufficient_evidence"
                if question.outcome_type == "abstain"
                else "answerable"
            ),
            "scope_label": "portfolio-scale pilot development/validation",
            "original_label": OriginalLabel(
                expected_answer=(
                    "abstain" if question.outcome_type == "abstain" else "answer"
                ),
                abstention_reason=question.abstention_reason,
                expected_claim=claim,
            ),
            "required_authority_policy_ids": ["authority-policy-portfolio-diverse-v3"],
            "sources": sources,
            "evidence": expected,
            "alternate_evidence": alternates,
            "evidence_binding_sha256": canonical_sha256(binding),
        }
        item_data["item_sha256"] = canonical_sha256(
            {key: value for key, value in item_data.items() if key != "item_sha256"}
        )
        items.append(ReviewItem.model_validate(item_data))

    packet_data: dict[str, Any] = {
        "schema_version": "review-packet-v1",
        "packet_id": "portfolio-diverse-v3-new-label-review",
        "packet_sha256": "0" * 64,
        "created_at_utc": NOW,
        "benchmark_scope": "portfolio-scale pilot development/validation",
        "blinding_statement": (
            "No model outputs, conditions, pass/fail fields, aggregates, or preferences."
        ),
        "case_file_sha256": _sha(OUT),
        "authority_policy_sha256": _sha(AUTHORITY),
        "source_license_or_terms": dict(sorted(terms.items())),
        "items": sorted(items, key=lambda value: value.case_id),
    }
    packet_data["packet_sha256"] = canonical_sha256(
        {key: value for key, value in packet_data.items() if key != "packet_sha256"}
    )
    return ReviewPacket.model_validate(packet_data)


def _build_packet_index(corpus: DiverseCorpusDraft) -> dict[str, Any]:
    legacy_cases = [
        json.loads(line)
        for line in (
            ROOT / "data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl"
        )
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    legacy_by_base: dict[str, list[dict[str, Any]]] = {}
    for case in legacy_cases:
        case_id = case["case_id"]
        base = re.sub(r"-(?:clean|control|challenge)-v[12]$", "", case_id)
        legacy_by_base.setdefault(base, []).append(case)
    packets: list[dict[str, Any]] = []
    for question in corpus.questions:
        if question.review_status == "approved_v2":
            variants = legacy_by_base[question.case_id]
            for variant in variants:
                kind = (
                    "challenge"
                    if "-challenge-v" in variant["case_id"]
                    else "benign_control"
                    if "-control-v" in variant["case_id"]
                    else "clean"
                )
                body = {
                    "packet_id": variant["case_id"],
                    "case_id": question.case_id,
                    "variant": kind,
                    "question_sha256": question.question_sha256,
                    "document_ids": variant["allowed_snapshot_ids"],
                    "required_evidence_ids": [
                        evidence_id
                        for claim in variant["expected_claims"]
                        for evidence_id in claim["evidence_ids"]
                    ],
                    "legacy_case_sha256": canonical_sha256(variant),
                }
                body["packet_sha256"] = canonical_sha256(body)
                packets.append(body)
            continue
        body = {
            "packet_id": f"{question.case_id}-clean-v3",
            "case_id": question.case_id,
            "variant": "clean",
            "question_sha256": question.question_sha256,
            "document_ids": sorted({item.source_id for item in question.evidence}),
            "required_evidence_ids": question.required_evidence_ids,
            "legacy_case_sha256": None,
        }
        body["packet_sha256"] = canonical_sha256(body)
        packets.append(body)
    payload = {
        "version": "portfolio-diverse-packets-v3",
        "status": "manager_audit_ready",
        "packets": sorted(packets, key=lambda value: value["packet_id"]),
    }
    payload["index_sha256"] = canonical_sha256(payload)
    return payload


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", value.casefold()))


def _audit_report(
    corpus: DiverseCorpusDraft,
    packet_index: dict[str, Any],
    review_packet: ReviewPacket,
) -> dict[str, Any]:
    pairs: list[dict[str, Any]] = []
    for index, left in enumerate(corpus.questions):
        left_tokens = _tokens(left.question)
        for right in corpus.questions[index + 1 :]:
            right_tokens = _tokens(right.question)
            union = left_tokens | right_tokens
            score = len(left_tokens & right_tokens) / len(union) if union else 1.0
            if score >= 0.55:
                pairs.append(
                    {
                        "left": left.case_id,
                        "right": right.case_id,
                        "token_jaccard": round(score, 4),
                    }
                )
    slice_counts = Counter(value.slice for value in corpus.questions)
    family_counts = Counter(value.source_family_id for value in corpus.questions)
    source_counts = Counter(
        evidence.source_name
        for question in corpus.questions
        for evidence in question.evidence
    )
    predicate_counts = Counter(value.predicate for value in corpus.questions)
    answer_type_counts = Counter(value.answer_type for value in corpus.questions)
    outcome_counts = Counter(value.outcome_type for value in corpus.questions)
    extraction_method_counts = Counter(
        evidence.extraction_method
        for question in corpus.questions
        for evidence in question.evidence
    )
    temporal_basis_counts = Counter(
        evidence.temporal_basis
        for question in corpus.questions
        for evidence in question.evidence
    )
    variant_counts = Counter(value["variant"] for value in packet_index["packets"])
    report = {
        "version": "portfolio-diverse-corpus-audit-v3",
        "status": "manager_audit_ready",
        "corpus_path": OUT.relative_to(ROOT).as_posix(),
        "corpus_sha256": corpus.corpus_sha256,
        "review_packet_path": PACKET_OUT.relative_to(ROOT).as_posix(),
        "review_packet_sha256": review_packet.packet_sha256,
        "packet_index_path": PACKET_INDEX_OUT.relative_to(ROOT).as_posix(),
        "packet_index_sha256": packet_index["index_sha256"],
        "unique_question_count": len(corpus.questions),
        "new_label_count": len(review_packet.items),
        "approved_v2_count": sum(
            value.review_status == "approved_v2" for value in corpus.questions
        ),
        "slice_counts": dict(sorted(slice_counts.items())),
        "predicate_counts": dict(sorted(predicate_counts.items())),
        "answer_type_counts": dict(sorted(answer_type_counts.items())),
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "source_family_count": len(family_counts),
        "per_source_family_counts": dict(sorted(family_counts.items())),
        "evidence_source_counts": dict(sorted(source_counts.items())),
        "evidence_extraction_method_counts": dict(
            sorted(extraction_method_counts.items())
        ),
        "evidence_temporal_basis_counts": dict(sorted(temporal_basis_counts.items())),
        "packet_variant_counts": dict(sorted(variant_counts.items())),
        "exact_duplicate_questions": (
            len({value.question for value in corpus.questions}) != len(corpus.questions)
        ),
        "near_duplicate_pairs_at_or_above_0_55": sorted(
            pairs,
            key=lambda value: (-value["token_jaccard"], value["left"]),
        ),
        "leakage_findings": [],
        "new_capture_summary": {
            "successful_gets": 7,
            "total_attempts": 7,
            "retries": 0,
            "manifest_paths": [
                "data/manifests/portfolio-diverse-capture-batch1.json",
                "data/manifests/portfolio-diverse-capture-batch2.json",
            ],
        },
        "review_gate": (
            "Parent manager acceptance is required before the user opens the "
            "review packet; provider calls remain blocked."
        ),
        "limitations": [
            "The 16 retained extraction labels are the unchanged reviewed v2 cases.",
            f"The {len(review_packet.items)} new labels are manager-audit candidates, not approved gold.",
            "Only the retained 16 cases currently have matched control/challenge variants.",
            "Publisher-declared version evidence is not independently observed history.",
            "All eight authority cases test scoped attribution, not universal source rank.",
        ],
        "manager_audit_risks": [
            (
                "Authority-divergence and multi-source questions intentionally share some "
                "families; the audit must reject any pair that differs only in wording."
            ),
            (
                "Twenty evidence items are deterministic field or absence derivations, "
                "not literal source spans, and require recipe-level inspection."
            ),
            (
                "The three newly captured vendor documents remain raw-excluded; their "
                "minimal-span public redistribution disposition is not yet a release claim."
            ),
            (
                "The three draft reasoning predicates have a strict local all-evidence "
                "oracle but are not yet wired into the provider experiment's central "
                "authority/exact-grader maps; that integration remains blocked on corpus "
                "acceptance and human review."
            ),
        ],
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _render_report(report: dict[str, Any]) -> str:
    slices = "\n".join(
        f"- `{name}`: {count}" for name, count in report["slice_counts"].items()
    )
    variants = "\n".join(
        f"- `{name}`: {count}"
        for name, count in report["packet_variant_counts"].items()
    )
    risks = "\n".join(f"- {value}" for value in report["manager_audit_risks"])
    return (
        "# Diverse portfolio corpus audit v3\n\n"
        f"- Status: `{report['status']}`\n"
        f"- Unique semantic questions: {report['unique_question_count']}\n"
        f"- Existing reviewed v2 labels: {report['approved_v2_count']}\n"
        f"- New labels awaiting manager audit: {report['new_label_count']}\n"
        f"- Source/dependency families: {report['source_family_count']}\n"
        f"- Corpus SHA-256: `{report['corpus_sha256']}`\n"
        f"- Review packet SHA-256: `{report['review_packet_sha256']}`\n\n"
        "## Questions by substantive slice\n\n"
        f"{slices}\n\n"
        "## Packet variants\n\n"
        f"{variants}\n\n"
        f"The {report['packet_variant_counts']['clean']} clean packets cover every question. "
        "Matched benign-control and "
        "challenge variants remain the frozen 16-case subset; their controlled "
        "retrieval result is not a claim of model or real-world attack robustness.\n\n"
        "## Gate\n\n"
        f"{report['review_gate']}\n\n"
        "## Manager-audit risks\n\n"
        f"{risks}\n\n"
        "## Limitations\n\n"
        + "\n".join(f"- {value}" for value in report["limitations"])
        + "\n"
    )


def main() -> int:
    questions = [
        *_retained_questions(),
        *_temporal_questions(),
        *_additional_temporal_questions(),
        *_abstention_questions(),
        *_authority_questions(),
        *_synthesis_questions(),
    ]
    payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-draft-v3",
        "corpus_id": "portfolio-diverse-v3-manager-audit-candidate",
        "created_at_utc": NOW,
        "temporal_boundary": BOUNDARY,
        "questions": sorted(questions, key=lambda value: value.case_id),
        "corpus_sha256": "0" * 64,
    }
    payload["corpus_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "corpus_sha256"}
    )
    corpus = DiverseCorpusDraft.model_validate(payload)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(corpus.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    packet = _build_review_packet(corpus)
    PACKET_OUT.parent.mkdir(parents=True, exist_ok=True)
    PACKET_OUT.write_text(
        json.dumps(packet.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    packet_index = _build_packet_index(corpus)
    PACKET_INDEX_OUT.write_text(
        json.dumps(packet_index, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    report = _audit_report(corpus, packet_index, packet)
    REPORT_JSON.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    REPORT_MD.write_text(_render_report(report), encoding="utf-8", newline="\n")
    print(f"{OUT} {corpus.corpus_sha256} {len(corpus.questions)} questions")
    print(f"{PACKET_OUT} {packet.packet_sha256} {len(packet.items)} new labels")
    print(
        f"{PACKET_INDEX_OUT} {packet_index['index_sha256']} "
        f"{len(packet_index['packets'])} packet variants"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
