"""Provider-free scripted oracle for the portfolio yield-gate batch."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from cti_provenance.claims.portfolio_correction import (
    OVERLAY_PATH,
    apply_correction_to_cases,
    apply_correction_to_specs,
    load_portfolio_gold_correction,
    verify_corrected_source,
)
from cti_provenance.claims.portfolio_yield import (
    AUTHORITY_POLICY_PATH,
    CASE_PATHS,
    FAMILY_SPEC_PATH,
    MANIFEST_PATH,
    REVIEWS_PATH,
    SOURCE_POLICY_PATH,
    load_portfolio_yield_authority_policy,
    load_portfolio_yield_cases,
    load_portfolio_yield_corpus,
)
from cti_provenance.experiments.ledger import RunRecord
from cti_provenance.experiments.portfolio_proof_runner import (
    build_portfolio_proof_answer,
)
from cti_provenance.experiments.runner import (
    OfflineCaseResult,
    RetrievedDocument,
    TreatmentDiagnostic,
)
from cti_provenance.grading import grade_answer
from cti_provenance.retrieval import CorpusView, LexicalRetriever
from cti_provenance.retrieval.protocol import build_cutoff_corpus

ORACLE_VERSION = "portfolio-yield-scripted-oracle-v1"
RECORDED_AT = datetime(2026, 7, 21, 23, 30, tzinfo=UTC)
_FROZEN_COMPONENT_DIGEST = (
    "d6d5aa14f6b58eba5ecd5af5e6b9b82ac844518e02b86bc6e34554e367961d50"
)
_FROZEN_DATASET_VERSION = "portfolio-yield-corpus-v1-ebca6f95891a"


def _dataset_version(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in (
        MANIFEST_PATH,
        FAMILY_SPEC_PATH,
        SOURCE_POLICY_PATH,
        AUTHORITY_POLICY_PATH,
        *CASE_PATHS,
        REVIEWS_PATH,
    ):
        body = root.joinpath(*relative.parts).read_bytes()
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(body)
        digest.update(b"\0")
    component_digest = digest.hexdigest()
    if component_digest == _FROZEN_COMPONENT_DIGEST:
        return _FROZEN_DATASET_VERSION
    return f"portfolio-yield-corpus-v1-{component_digest[:12]}"


def run_portfolio_yield_slice(
    root: Path, *, correction_version: Literal["v1", "v2"] = "v1"
) -> list[OfflineCaseResult]:
    """Run the four yield-gate questions without network or provider access."""

    root = root.resolve(strict=True)
    states, documents, specs = load_portfolio_yield_corpus(root)
    cases = load_portfolio_yield_cases(
        root, states=states, documents=documents, specs=specs
    )
    if correction_version == "v2":
        overlay = load_portfolio_gold_correction(root)
        verify_corrected_source(root, states, overlay)
        specs = apply_correction_to_specs(specs, overlay)
        cases = apply_correction_to_cases(cases, overlay)
    authority = load_portfolio_yield_authority_policy(root)
    spec_by_template = {spec.template_family_id: spec for spec in specs}
    dataset_version = _dataset_version(root)
    prompt_version = ORACLE_VERSION
    if correction_version == "v2":
        digest = hashlib.sha256()
        digest.update(dataset_version.encode("utf-8"))
        digest.update(root.joinpath(*OVERLAY_PATH.parts).read_bytes())
        dataset_version = f"portfolio-yield-corpus-v2-{digest.hexdigest()[:12]}"
        prompt_version = "portfolio-yield-scripted-oracle-v2"
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
        run_id = (
            f"portfolio-yield-{case.case_id}"
            if correction_version == "v1"
            else f"portfolio-yield-v2-{case.case_id}"
        )
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
        manifests = [
            state.manifest.model_dump(mode="json")
            for state in states
            if state.manifest.snapshot_id in allowed
        ]
        manifest_hash = hashlib.sha256(
            json.dumps(manifests, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
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
            prompt_version=prompt_version,
            retriever_version=LexicalRetriever.version,
            corpus_manifest_hash=manifest_hash,
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


def render_portfolio_yield_jsonl(results: list[OfflineCaseResult]) -> str:
    """Render stable result records."""

    return "".join(
        json.dumps(
            _strict_numbers(result.model_dump(mode="json")),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for result in sorted(results, key=lambda item: item.case.case_id)
    )


def render_portfolio_yield_report(results: list[OfflineCaseResult]) -> str:
    """Render exact provider-free denominators and claim boundaries."""

    ordered = sorted(results, key=lambda item: item.case.case_id)
    grades = [grade for result in ordered for grade in result.grades]
    assessments = [item for grade in grades for item in grade.evidence_assessments]
    lines = [
        "# Portfolio yield-gate provider-free slice",
        "",
        "Status: **smoke-tested; scope=portfolio_yield_scripted_oracle**. This is "
        "a deterministic three-family corpus check, not a model evaluation.",
        "",
        "## Results",
        "",
        f"- Questions completed: {len(ordered)}/3.",
        "- Supported atomic claims: "
        f"{sum(item.claim_support == 'supported' for item in grades)}/{len(grades)}.",
        "- Citation support: "
        f"{sum(item.entailment == 'supported' for item in assessments)}/"
        f"{len(assessments)}.",
        "- Temporal admissibility: "
        f"{sum(item.temporality == 'admissible' for item in assessments)}/"
        f"{len(assessments)}.",
        "- Accepted predicate authority: "
        f"{sum(item.authority == 'accepted' for item in assessments)}/"
        f"{len(assessments)}.",
        "- Provider calls/tokens/cost: 0 / 0 / $0.00.",
        "",
        "## Answer keys",
        "",
        "- CISA KEV CVE-2021-27137 membership: `true`.",
        "- Node.js May 2025 available security releases: `20.19.2`, `22.15.1`, "
        "`23.11.1`, `24.0.2`.",
        "- NVD PAN-OS 10.2.2-h5 CPE applicability: `true`.",
        "",
        "## Boundary",
        "",
        "All historical times are publisher-declared version evidence. Exact "
        "bytes were observed only during the 2026 capture session; this does not "
        "prove independent historical availability. Manager review is a corpus "
        "audit, not human calibration.",
        "",
    ]
    return "\n".join(lines)
