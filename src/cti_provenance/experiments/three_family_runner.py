"""Provider-free scripted oracle for the smallest three-family corpus."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from cti_provenance.claims.schema import (
    ClaimEvidenceAnswer,
    ClaimEvidenceAtomicClaim,
)
from cti_provenance.claims.three_family import (
    AUTHORITY_POLICY_PATH,
    CASES_PATH,
    MANIFEST_PATH,
    REVIEWS_PATH,
    load_three_family_authority_policy,
    load_three_family_cases,
    load_three_family_corpus,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.ledger import RunRecord
from cti_provenance.experiments.runner import (
    OfflineCaseResult,
    RetrievedDocument,
    TreatmentDiagnostic,
)
from cti_provenance.grading import grade_answer
from cti_provenance.normalize import NormalizedDocument
from cti_provenance.retrieval import CorpusView, LexicalRetriever, RetrievalHit
from cti_provenance.retrieval.protocol import build_cutoff_corpus
from cti_provenance.snapshot import SnapshotState

ORACLE_VERSION = "three-family-scripted-oracle-v2"
RECORDED_AT = datetime(2026, 7, 21, 22, 45, tzinfo=UTC)

_SOURCE_BY_TEMPLATE = {
    "cve-program-affected-versions": "cve_program",
    "cisa-directive-required-action": "cisa_directive",
    "netscaler-investigation-recommendation": "netscaler_advisory",
}


def _dataset_version(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in (
        MANIFEST_PATH,
        CASES_PATH,
        REVIEWS_PATH,
        Path(*AUTHORITY_POLICY_PATH.parts),
    ):
        path = root.joinpath(*relative.parts)
        digest.update(Path(*relative.parts).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"three-family-corpus-v1-{digest.hexdigest()[:12]}"


def _manifest_hash(case: BenchmarkCase, states: list[SnapshotState]) -> str:
    manifests = [
        state.manifest.model_dump(mode="json")
        for state in states
        if state.manifest.snapshot_id in case.allowed_snapshot_ids
    ]
    rendered = json.dumps(manifests, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(rendered).hexdigest()


def _authoritative_document(
    case: BenchmarkCase,
    hits: tuple[RetrievalHit, ...],
    documents: list[NormalizedDocument],
) -> NormalizedDocument | None:
    source = _SOURCE_BY_TEMPLATE[case.template_family_id]
    hit_ids = {hit.document_id for hit in hits}
    candidates = [
        document
        for document in documents
        if document.document_id in hit_ids
        and document.source_name == source
        and document.snapshot_id in case.allowed_snapshot_ids
    ]
    if len(candidates) > 1:
        raise ValueError("three-family oracle retrieved ambiguous authority")
    return candidates[0] if candidates else None


def _claim_payload(
    case: BenchmarkCase, document: NormalizedDocument
) -> dict[str, Any] | None:
    if case.template_family_id == "cve-program-affected-versions":
        versions = document.fields.get("affected_versions")
        if not isinstance(versions, list) or not versions:
            return None
        return {
            "subject": {"type": "cve", "id": "CVE-2024-3094"},
            "predicate": "cve.affected_versions",
            "object": {"value": versions, "datatype": "version_set"},
            "qualifiers": {
                "authority": "cve_program",
                "cvss_version": None,
                "product": "xz",
                "ecosystem": None,
            },
            "evidence_ids": [
                f"{document.document_id}:{span.span_id}" for span in document.spans
            ],
            "confidence": 1.0,
        }
    if case.template_family_id == "cisa-directive-required-action":
        if document.fields.get("required_disconnect_action") is None:
            return None
        return {
            "subject": {"type": "advisory", "id": "ED-24-01"},
            "predicate": "directive.required_action",
            "object": {
                "value": (
                    "disconnect all instances of Ivanti Connect Secure and Ivanti "
                    "Policy Secure solution products from agency networks by "
                    "February 2, 2024"
                ),
                "datatype": "string",
            },
            "qualifiers": {
                "authority": "cisa",
                "cvss_version": None,
                "product": "Ivanti Connect Secure and Ivanti Policy Secure",
                "ecosystem": None,
            },
            "evidence_ids": [f"{document.document_id}:required-disconnect"],
            "confidence": 1.0,
        }
    if case.template_family_id == "netscaler-investigation-recommendation":
        value = document.fields.get("ssl_vpn_source_ip_pattern")
        if not isinstance(value, str):
            return None
        return {
            "subject": {"type": "advisory", "id": "CVE-2023-4966"},
            "predicate": "vendor.recommended_action",
            "object": {"value": value, "datatype": "string"},
            "qualifiers": {
                "authority": "netscaler",
                "cvss_version": None,
                "product": "NetScaler ADC and NetScaler Gateway",
                "ecosystem": None,
            },
            "evidence_ids": [f"{document.document_id}:ssl-vpn-source-ip-pattern"],
            "confidence": 1.0,
        }
    raise ValueError("three-family oracle received an unsupported template")


def build_three_family_answer(
    case: BenchmarkCase,
    *,
    run_id: str,
    hits: tuple[RetrievalHit, ...],
    documents: list[NormalizedDocument],
) -> ClaimEvidenceAnswer:
    """Build an answer from the selected document, or abstain when it is absent."""
    document = _authoritative_document(case, hits, documents)
    payload = _claim_payload(case, document) if document is not None else None
    if payload is None:
        return ClaimEvidenceAnswer(
            answer_id=f"answer-{case.case_id}",
            run_id=run_id,
            case_id=case.case_id,
            as_of=case.as_of,
            claims=[],
            abstained=True,
            abstention_reason=(
                "No cutoff-eligible authoritative version supports the answer."
            ),
            narrative="Provider-free source-derived oracle abstained.",
        )
    claim = ClaimEvidenceAtomicClaim.model_validate(
        {**payload, "claim_id": f"generated-{case.case_id}-1"}
    )
    return ClaimEvidenceAnswer(
        answer_id=f"answer-{case.case_id}",
        run_id=run_id,
        case_id=case.case_id,
        as_of=case.as_of,
        claims=[claim],
        abstained=False,
        abstention_reason=None,
        narrative=(
            "Provider-free source-derived oracle using publisher-declared version "
            "evidence only."
        ),
    )


def run_three_family_slice(root: Path) -> list[OfflineCaseResult]:
    """Run exactly three reviewed real-source questions without network access."""
    root = root.resolve(strict=True)
    states, documents = load_three_family_corpus(root)
    cases = load_three_family_cases(root, states=states, documents=documents)
    authority_policy = load_three_family_authority_policy(root)
    dataset_version = _dataset_version(root)
    results: list[OfflineCaseResult] = []
    for case in cases:
        selected = build_cutoff_corpus(documents, states, case.as_of)
        allowed = frozenset(case.allowed_snapshot_ids)
        corpus = CorpusView(
            documents=tuple(
                document
                for document in selected.documents
                if document.snapshot_id in allowed
            ),
            selected_snapshot_ids=selected.selected_snapshot_ids.intersection(allowed),
            cutoff=case.as_of,
        )
        hits = LexicalRetriever(corpus).search(case.question, limit=4)
        run_id = f"three-family-{case.case_id}"
        answer = build_three_family_answer(
            case, run_id=run_id, hits=hits, documents=documents
        )
        grades = grade_answer(
            case,
            answer,
            documents=documents,
            states=states,
            authority_policy_version=authority_policy.version,
        )
        run = RunRecord(
            run_id=run_id,
            recorded_at_utc=RECORDED_AT,
            project_version="0.1.0",
            dataset_version=dataset_version,
            case_id=case.case_id,
            case_seed=0,
            condition="lexical_claim_evidence_constrained",
            provider="none",
            model_id=None,
            model_snapshot_or_version=None,
            prompt_version=ORACLE_VERSION,
            retriever_version=LexicalRetriever.version,
            corpus_manifest_hash=_manifest_hash(case, states),
            authority_policy_version=authority_policy.version,
            input_tokens=0,
            cached_input_tokens=0,
            output_tokens=0,
            latency_ms=0,
            retry_count=0,
            provider_status="not_called",
            parse_status="valid",
            retrieval_outcome="success" if hits else "empty",
            deterministic_outcome="graded",
            security_outcome="not_applicable",
            utility_outcome="abstained" if answer.abstained else "claims_emitted",
            error_category="none",
            estimated_cost_usd=Decimal(0),
        )
        results.append(
            OfflineCaseResult(
                case=case,
                run=run,
                retrieval=[
                    RetrievedDocument(
                        document_id=hit.document_id,
                        snapshot_id=hit.snapshot_id,
                        span_ids=list(hit.span_ids),
                        score=round(hit.score, 12),
                    )
                    for hit in hits
                ],
                treatment_diagnostic=TreatmentDiagnostic(
                    attack_family="none",
                    declared_document_ids=[],
                    retrieved_document_ids=[],
                    status="not_applicable",
                ),
                answer=answer,
                grades=grades,
            )
        )
    return results


def _strict_numbers(value: Any) -> Any:
    if isinstance(value, list):
        return [_strict_numbers(item) for item in value]
    if not isinstance(value, dict):
        return value
    converted = {key: _strict_numbers(item) for key, item in value.items()}
    if isinstance(converted.get("estimated_cost_usd"), str):
        converted["estimated_cost_usd"] = float(converted["estimated_cost_usd"])
    return converted


def render_three_family_jsonl(results: list[OfflineCaseResult]) -> str:
    return "".join(
        json.dumps(
            _strict_numbers(result.model_dump(mode="json")),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for result in sorted(results, key=lambda item: item.case.case_id)
    )


def render_three_family_report(results: list[OfflineCaseResult]) -> str:
    ordered = sorted(results, key=lambda item: item.case.case_id)
    grades = [grade for result in ordered for grade in result.grades]
    assessments = [
        assessment for grade in grades for assessment in grade.evidence_assessments
    ]
    supported = sum(grade.claim_support == "supported" for grade in grades)
    citations = sum(item.entailment == "supported" for item in assessments)
    temporal = sum(item.temporality == "admissible" for item in assessments)
    authority = sum(item.authority == "accepted" for item in assessments)
    lines = [
        "# Three-family provider-free corpus slice",
        "",
        "Status: **smoke-tested; scope=three_family_scripted_oracle**. This is a "
        "deterministic real-source development slice, not a model evaluation or "
        "historical-availability proof.",
        "",
        "## Results",
        "",
        f"- Questions: {len(ordered)}/3 completed, exactly one per family.",
        f"- Supported atomic claims: {supported}/{len(grades)}.",
        f"- Citation support: {citations}/{len(assessments)}.",
        f"- Temporal admissibility: {temporal}/{len(assessments)}.",
        f"- Accepted predicate authority: {authority}/{len(assessments)}.",
        "- Provider calls/tokens/cost: 0 / 0 / $0.00.",
        "- Deterministic replay: the tracked JSONL and this report are compared "
        "byte-for-byte in integration tests.",
        "",
        "## Answer keys",
        "",
        "- CVE-2024-3094: xz versions `5.6.0` and `5.6.1`.",
        "- Ivanti ED 24-01 V1: disconnect all instances of the named solution "
        "products from agency networks by February 2, 2024.",
        "- NetScaler CVE-2023-4966: review the same source IP accessing sessions "
        "of multiple users.",
        "",
        "## Temporal boundary",
        "",
        "All historical times are publisher-declared version evidence. The exact "
        "bytes were observed only during the 2026 captures; the slice does not "
        "claim independent observation of those bytes at the historical dates. "
        "Pre-version cutoffs fail closed and produce no eligible document.",
        "",
        "Exact raw bodies remain gitignored. The repository tracks only hashes, "
        "metadata, questions, short evidence mappings, and derived results.",
        "",
    ]
    return "\n".join(lines)
