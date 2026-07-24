"""Deterministic provider-free runner for the complete Phase 2 offline slice."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cti_provenance.claims import (
    ClaimEvidenceAnswer,
    load_phase2_cases,
    load_phase2_plumbing_corpus,
)
from cti_provenance.claims.schema import ClaimEvidenceAtomicClaim
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.ledger import RunRecord
from cti_provenance.grading import ClaimGrade, grade_answer
from cti_provenance.retrieval import (
    CorpusView,
    LexicalRetriever,
    RetrievalHit,
    build_cutoff_corpus,
)
from cti_provenance.snapshot import SnapshotState

OFFLINE_DATASET_VERSION = "phase2-plumbing-offline-v1"
OFFLINE_PROMPT_VERSION = "scripted-oracle-v1"
OFFLINE_RECORDED_AT = datetime(2026, 7, 18, 12, tzinfo=UTC)


class SliceRunError(ValueError):
    """The deterministic oracle cannot complete the declared offline slice."""


class RetrievedDocument(BaseModel):
    """Stable JSON representation of one lexical result."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    document_id: str
    snapshot_id: str
    span_ids: list[str]
    score: float


class TreatmentDiagnostic(BaseModel):
    """Stable proof that a declared adversarial treatment reached retrieval."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    attack_family: str
    declared_document_ids: list[str]
    retrieved_document_ids: list[str]
    status: Literal["not_applicable", "retrieved_not_classified"]


class OfflineCaseResult(BaseModel):
    """Complete auditable result for one provider-free development case."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case: BenchmarkCase
    run: RunRecord
    retrieval: list[RetrievedDocument]
    treatment_diagnostic: TreatmentDiagnostic
    answer: ClaimEvidenceAnswer
    grades: list[ClaimGrade]


def _manifest_hash(case: BenchmarkCase, states: list[SnapshotState]) -> str:
    manifests = [
        state.manifest.model_dump(mode="json")
        for state in states
        if state.manifest.snapshot_id in case.allowed_snapshot_ids
    ]
    payload = json.dumps(
        sorted(manifests, key=lambda manifest: manifest["snapshot_id"]),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _evidence_document_ids(case: BenchmarkCase) -> set[str]:
    return {
        evidence_id.split(":", 1)[0]
        for claim in case.expected_claims
        for evidence_id in claim.evidence_ids
    }


def _scripted_oracle(
    case: BenchmarkCase,
    *,
    run_id: str,
    hits: tuple[RetrievalHit, ...],
) -> ClaimEvidenceAnswer:
    retrieved_ids = {hit.document_id for hit in hits}
    required_ids = _evidence_document_ids(case)
    if not required_ids <= retrieved_ids:
        raise SliceRunError(
            f"scripted oracle retrieval missed evidence for {case.case_id}"
        )
    treatment_ids = set(case.attack.treatment_document_ids)
    if not treatment_ids <= retrieved_ids:
        raise SliceRunError(
            f"scripted oracle retrieval missed declared treatment for {case.case_id}"
        )
    if case.should_abstain:
        return ClaimEvidenceAnswer(
            answer_id=f"answer-{case.case_id}",
            run_id=run_id,
            case_id=case.case_id,
            as_of=case.as_of,
            claims=[],
            abstained=True,
            abstention_reason=case.abstention_reason,
            narrative="Provider-free scripted oracle abstained.",
        )
    generated = [
        ClaimEvidenceAtomicClaim.model_validate(
            {
                **claim.model_dump(),
                "claim_id": f"generated-{case.case_id}-{index}",
            }
        )
        for index, claim in enumerate(case.expected_claims, start=1)
    ]
    return ClaimEvidenceAnswer(
        answer_id=f"answer-{case.case_id}",
        run_id=run_id,
        case_id=case.case_id,
        as_of=case.as_of,
        claims=generated,
        abstained=False,
        abstention_reason=None,
        narrative=(
            "Provider-free scripted oracle; Log4Shell is plumbing-only and "
            "supports no substantive research conclusion."
        ),
    )


def _treatment_diagnostic(
    case: BenchmarkCase, hits: tuple[RetrievalHit, ...]
) -> TreatmentDiagnostic:
    declared = sorted(case.attack.treatment_document_ids)
    retrieved_ids = {hit.document_id for hit in hits}
    retrieved = sorted(set(declared).intersection(retrieved_ids))
    return TreatmentDiagnostic(
        attack_family=case.attack.family,
        declared_document_ids=declared,
        retrieved_document_ids=retrieved,
        status=(
            "not_applicable"
            if case.attack.family == "none"
            else "retrieved_not_classified"
        ),
    )


def _validate_attack_pair_results(results: list[OfflineCaseResult]) -> None:
    by_case = {result.case.case_id: result for result in results}
    for attacked in (
        result for result in results if result.case.attack.family != "none"
    ):
        if attacked.case.paired_case_id is None:
            raise SliceRunError("adversarial case lacks a reciprocal clean case")
        clean = by_case[attacked.case.paired_case_id]
        clean_ids = {hit.document_id for hit in clean.retrieval}
        attacked_ids = {hit.document_id for hit in attacked.retrieval}
        treatment_ids = set(attacked.case.attack.treatment_document_ids)
        if treatment_ids & clean_ids or not treatment_ids <= attacked_ids - clean_ids:
            raise SliceRunError(
                f"retrieval delta does not expose treatment for {attacked.case.case_id}"
            )


def run_offline_slice(root: Path) -> list[OfflineCaseResult]:
    """Execute every tracked development case with no network or provider call."""
    states, documents = load_phase2_plumbing_corpus(root)
    cases = load_phase2_cases(root, states=states, documents=documents)
    results: list[OfflineCaseResult] = []
    for case in cases:
        cutoff_corpus = build_cutoff_corpus(documents, states, case.as_of)
        allowed_ids = frozenset(case.allowed_snapshot_ids)
        corpus = CorpusView(
            documents=tuple(
                document
                for document in cutoff_corpus.documents
                if document.snapshot_id in allowed_ids
            ),
            selected_snapshot_ids=(
                cutoff_corpus.selected_snapshot_ids.intersection(allowed_ids)
            ),
            cutoff=case.as_of,
        )
        retriever = LexicalRetriever(corpus)
        hits = retriever.search(case.question, limit=4)
        run_id = f"offline-{case.case_id}"
        answer = _scripted_oracle(case, run_id=run_id, hits=hits)
        grades = grade_answer(
            case=case,
            answer=answer,
            documents=documents,
            states=states,
        )
        run = RunRecord(
            run_id=run_id,
            recorded_at_utc=OFFLINE_RECORDED_AT,
            project_version="0.1.0",
            dataset_version=OFFLINE_DATASET_VERSION,
            case_id=case.case_id,
            case_seed=0,
            condition="lexical_claim_evidence_constrained",
            provider="none",
            model_id=None,
            model_snapshot_or_version=None,
            prompt_version=OFFLINE_PROMPT_VERSION,
            retriever_version=LexicalRetriever.version,
            corpus_manifest_hash=_manifest_hash(case, states),
            authority_policy_version="authority-policy-v1",
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
                        score=hit.score,
                    )
                    for hit in hits
                ],
                treatment_diagnostic=_treatment_diagnostic(case, hits),
                answer=answer,
                grades=grades,
            )
        )
    _validate_attack_pair_results(results)
    return results


def render_results_jsonl(results: list[OfflineCaseResult]) -> str:
    """Serialize results in stable order with one canonical JSON object per line."""
    return "".join(
        json.dumps(
            result.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for result in sorted(results, key=lambda item: item.case.case_id)
    )
