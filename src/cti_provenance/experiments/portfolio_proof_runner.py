"""Provider-free scripted oracle for the portfolio proof-family batch."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from cti_provenance.claims.portfolio_proof import (
    AUTHORITY_POLICY_PATH,
    CASES_PATH,
    FAMILY_SPEC_PATH,
    MANIFEST_PATH,
    REVIEWS_PATH,
    load_portfolio_proof_authority_policy,
    load_portfolio_proof_cases,
    load_portfolio_proof_corpus,
)
from cti_provenance.claims.schema import ClaimEvidenceAnswer, ClaimEvidenceAtomicClaim
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.ledger import RunRecord
from cti_provenance.experiments.runner import (
    OfflineCaseResult,
    RetrievedDocument,
    TreatmentDiagnostic,
)
from cti_provenance.grading import grade_answer
from cti_provenance.normalize import FamilySpec, NormalizedDocument
from cti_provenance.retrieval import CorpusView, LexicalRetriever, RetrievalHit
from cti_provenance.retrieval.protocol import build_cutoff_corpus
from cti_provenance.snapshot import SnapshotState

ORACLE_VERSION = "portfolio-proof-scripted-oracle-v1"
RECORDED_AT = datetime(2026, 7, 21, 23, 0, tzinfo=UTC)


def _dataset_version(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in (
        MANIFEST_PATH,
        FAMILY_SPEC_PATH,
        CASES_PATH,
        REVIEWS_PATH,
        AUTHORITY_POLICY_PATH,
    ):
        path = root.joinpath(*relative.parts)
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"portfolio-proof-corpus-v1-{digest.hexdigest()[:12]}"


def _manifest_hash(case: BenchmarkCase, states: list[SnapshotState]) -> str:
    manifests = [
        state.manifest.model_dump(mode="json")
        for state in states
        if state.manifest.snapshot_id in case.allowed_snapshot_ids
    ]
    return hashlib.sha256(
        json.dumps(manifests, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _authoritative_document(
    case: BenchmarkCase,
    hits: tuple[RetrievalHit, ...],
    documents: list[NormalizedDocument],
    spec: FamilySpec,
) -> NormalizedDocument | None:
    hit_ids = {hit.document_id for hit in hits}
    candidates = [
        document
        for document in documents
        if document.document_id in hit_ids
        and document.source_name == spec.source_name
        and document.snapshot_id in case.allowed_snapshot_ids
    ]
    if len(candidates) > 1:
        raise ValueError("portfolio proof oracle retrieved ambiguous authority")
    return candidates[0] if candidates else None


def _claim_payload(
    spec: FamilySpec, document: NormalizedDocument
) -> dict[str, Any] | None:
    value = document.fields.get("claim_value")
    if value in (None, []) or not document.spans:
        return None
    return {
        "subject": {
            "type": spec.claim.subject_type,
            "id": spec.claim.subject_id,
        },
        "predicate": spec.claim.predicate,
        "object": {"value": value, "datatype": spec.claim.datatype},
        "qualifiers": {
            "authority": spec.claim.authority,
            "cvss_version": None,
            "product": spec.claim.product,
            "ecosystem": spec.claim.ecosystem,
        },
        "evidence_ids": [
            f"{document.document_id}:{span.span_id}" for span in document.spans
        ],
        "confidence": 1.0,
    }


def build_portfolio_proof_answer(
    case: BenchmarkCase,
    *,
    run_id: str,
    hits: tuple[RetrievalHit, ...],
    documents: list[NormalizedDocument],
    spec: FamilySpec,
) -> ClaimEvidenceAnswer:
    document = _authoritative_document(case, hits, documents, spec)
    payload = _claim_payload(spec, document) if document is not None else None
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


def run_portfolio_proof_slice(root: Path) -> list[OfflineCaseResult]:
    """Run three proof-family questions without network or provider access."""

    root = root.resolve(strict=True)
    states, documents, specs = load_portfolio_proof_corpus(root)
    cases = load_portfolio_proof_cases(
        root, states=states, documents=documents, specs=specs
    )
    authority = load_portfolio_proof_authority_policy(root)
    spec_by_template = {spec.template_family_id: spec for spec in specs}
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
        run_id = f"portfolio-proof-{case.case_id}"
        answer = build_portfolio_proof_answer(
            case,
            run_id=run_id,
            hits=hits,
            documents=documents,
            spec=spec_by_template[case.template_family_id],
        )
        grades = grade_answer(
            case,
            answer,
            documents=documents,
            states=states,
            authority_policy_version=authority.version,
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
            authority_policy_version=authority.version,
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


def render_portfolio_proof_jsonl(results: list[OfflineCaseResult]) -> str:
    return "".join(
        json.dumps(
            _strict_numbers(result.model_dump(mode="json")),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for result in sorted(results, key=lambda item: item.case.case_id)
    )


def render_portfolio_proof_report(results: list[OfflineCaseResult]) -> str:
    ordered = sorted(results, key=lambda item: item.case.case_id)
    grades = [grade for result in ordered for grade in result.grades]
    assessments = [item for grade in grades for item in grade.evidence_assessments]
    supported = sum(grade.claim_support == "supported" for grade in grades)
    citations = sum(item.entailment == "supported" for item in assessments)
    temporal = sum(item.temporality == "admissible" for item in assessments)
    authority = sum(item.authority == "accepted" for item in assessments)
    lines = [
        "# Portfolio proof-family provider-free slice",
        "",
        "Status: **smoke-tested; scope=portfolio_proof_scripted_oracle**. This is "
        "a deterministic three-family development proof, not a model evaluation.",
        "",
        "## Results",
        "",
        f"- Questions completed: {len(ordered)}/3.",
        f"- Supported atomic claims: {supported}/{len(grades)}.",
        f"- Citation support: {citations}/{len(assessments)}.",
        f"- Temporal admissibility: {temporal}/{len(assessments)}.",
        f"- Accepted predicate authority: {authority}/{len(assessments)}.",
        "- Provider calls/tokens/cost: 0 / 0 / $0.00.",
        "",
        "## Answer keys",
        "",
        "- Apache CVE-2021-42013 affected releases: `2.4.49`, `2.4.50`.",
        "- CISA KEV CVE-2026-0257 ransomware campaign use: `Known`.",
        "- ATT&CK T1027.011 platforms in Enterprise v16.0: `Windows`, `Linux`.",
        "",
        "## Boundary",
        "",
        "All historical times are publisher-declared version evidence. Exact "
        "bytes were observed only during the 2026 capture session; this does not "
        "prove those bytes were independently observed at the declared dates. "
        "Manager review is a corpus audit, not human calibration.",
        "",
    ]
    return "\n".join(lines)
