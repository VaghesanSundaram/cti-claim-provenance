"""Provider-free oracle derived from the frozen local real-source documents."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from cti_provenance.claims.real_slice import (
    REAL_CASES_PATH,
    REAL_REVIEWS_PATH,
    load_phase2_real_cases,
    load_phase2_real_corpus,
)
from cti_provenance.claims.schema import (
    ClaimEvidenceAnswer,
    ClaimEvidenceAtomicClaim,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.ledger import RunRecord
from cti_provenance.experiments.runner import (
    OfflineCaseResult,
    RetrievedDocument,
    _manifest_hash,
    _treatment_diagnostic,
    _validate_attack_pair_results,
)
from cti_provenance.grading import grade_answer
from cti_provenance.normalize import NormalizedDocument
from cti_provenance.retrieval import CorpusView, LexicalRetriever, RetrievalHit
from cti_provenance.retrieval.protocol import build_cutoff_corpus

REAL_DATASET_VERSION_PREFIX = "phase2-real-local-replay-v1"
REAL_ORACLE_VERSION = "real-source-field-oracle-v1"
REAL_RECORDED_AT = datetime(2026, 7, 19, 4, 40, tzinfo=UTC)
_SOURCE_BY_TEMPLATE = {
    "nvd-published-at": "nvd",
    "nvd-modified-at": "nvd",
    "nvd-cvss-score": "nvd",
    "kev-membership": "cisa_kev",
    "kev-date-added": "cisa_kev",
    "kev-due-date": "cisa_kev",
    "red-hat-affected-versions": "red_hat_rhsa",
    "red-hat-fixed-versions": "red_hat_rhsa",
}


def _dataset_version(root: Path) -> str:
    paths = (
        Path("data/manifests/phase2-capture-metadata.json"),
        Path("data/manifests/phase2-capture-sessions")
        / "phase2-capture-b093c6c2e2bce1953d5f.json",
        Path(*REAL_CASES_PATH.parts),
        Path(*REAL_REVIEWS_PATH.parts),
        Path("configs/authority-policy.yaml"),
    )
    digest = hashlib.sha256()
    for path in paths:
        body = (root / path).read_bytes()
        digest.update(path.as_posix().encode())
        digest.update(b"\0")
        digest.update(body)
        digest.update(b"\0")
    return f"{REAL_DATASET_VERSION_PREFIX}-{digest.hexdigest()[:12]}"


def _retrieved_authoritative_document(
    case: BenchmarkCase,
    hits: tuple[RetrievalHit, ...],
    documents: list[NormalizedDocument],
) -> NormalizedDocument | None:
    required_source = _SOURCE_BY_TEMPLATE.get(case.template_family_id)
    if required_source is None:
        raise ValueError("real oracle received an unsupported template")
    hit_ids = {hit.document_id for hit in hits}
    candidates = [
        document
        for document in documents
        if document.document_id in hit_ids and document.source_name == required_source
    ]
    if len(candidates) > 1:
        raise ValueError("real oracle retrieved ambiguous authoritative documents")
    return candidates[0] if candidates else None


def _span_id(document: NormalizedDocument, span_id: str) -> str:
    if sum(span.span_id == span_id for span in document.spans) != 1:
        raise ValueError("real oracle required evidence span is unavailable")
    return f"{document.document_id}:{span_id}"


def _claim_payload(
    case: BenchmarkCase,
    document: NormalizedDocument,
) -> dict[str, Any] | None:
    fields = document.fields
    template = case.template_family_id
    if template == "nvd-published-at":
        return {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "cve.published_at",
            "object": {"value": str(fields["published"]), "datatype": "string"},
            "qualifiers": {
                "authority": "nvd",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": [_span_id(document, "nvd-published")],
            "confidence": 1.0,
        }
    if template == "nvd-modified-at":
        return {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "cve.modified_at",
            "object": {"value": str(fields["modified"]), "datatype": "string"},
            "qualifiers": {
                "authority": "nvd",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": [_span_id(document, "nvd-modified")],
            "confidence": 1.0,
        }
    if template == "nvd-cvss-score":
        return {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "cve.cvss.score",
            "object": {
                "value": Decimal(str(fields["cvss_v31_base_score"])),
                "datatype": "decimal",
            },
            "qualifiers": {
                "authority": str(fields["cvss_v31_named_source"]),
                "cvss_version": "3.1",
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": [_span_id(document, "nvd-cvss-v31")],
            "confidence": 1.0,
        }
    if template == "kev-membership":
        if fields.get("cve_id") != "CVE-2021-44228":
            return None
        return {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "kev.is_member",
            "object": {"value": True, "datatype": "boolean"},
            "qualifiers": {
                "authority": "cisa_kev",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": [_span_id(document, "kev-membership")],
            "confidence": 1.0,
        }
    if template in {"kev-date-added", "kev-due-date"}:
        field_name, predicate, span = {
            "kev-date-added": ("date_added", "kev.date_added", "kev-date-added"),
            "kev-due-date": ("due_date", "kev.due_date", "kev-due-date"),
        }[template]
        return {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": predicate,
            "object": {"value": str(fields[field_name]), "datatype": "date"},
            "qualifiers": {
                "authority": "cisa_kev",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": [_span_id(document, span)],
            "confidence": 1.0,
        }
    if template == "red-hat-affected-versions":
        affected = fields.get("known_affected_products")
        if affected == []:
            return None
        raise ValueError("real oracle cannot interpret ambiguous affected products")
    if template == "red-hat-fixed-versions":
        fixed = fields.get("fixed_products")
        if (
            not isinstance(fixed, list)
            or len(fixed) != 1
            or not isinstance(fixed[0], dict)
            or not isinstance(fixed[0].get("product"), str)
        ):
            raise ValueError("real oracle cannot interpret fixed product state")
        product = fixed[0]["product"]
        return {
            "subject": {"type": "advisory", "id": "RHSA-2021:5133"},
            "predicate": "vendor.fixed_versions",
            "object": {"value": [product], "datatype": "version_set"},
            "qualifiers": {
                "authority": "red_hat_rhsa",
                "cvss_version": None,
                "product": product,
                "ecosystem": None,
            },
            "evidence_ids": [_span_id(document, "rhsa-fixed-0-id")],
            "confidence": 1.0,
        }
    raise ValueError("real oracle received an unsupported template")


def _real_oracle(
    case: BenchmarkCase,
    *,
    run_id: str,
    hits: tuple[RetrievalHit, ...],
    documents: list[NormalizedDocument],
) -> ClaimEvidenceAnswer:
    document = _retrieved_authoritative_document(case, hits, documents)
    payload = _claim_payload(case, document) if document is not None else None
    if payload is None:
        reason = (
            "No cutoff-eligible authoritative document was retrieved."
            if document is None
            else "The authoritative document has no explicit supported target value."
        )
        return ClaimEvidenceAnswer(
            answer_id=f"answer-{case.case_id}",
            run_id=run_id,
            case_id=case.case_id,
            as_of=case.as_of,
            claims=[],
            abstained=True,
            abstention_reason=reason,
            narrative="Provider-free real-source field oracle abstained.",
        )
    claim = ClaimEvidenceAtomicClaim.model_validate(
        {
            **payload,
            "claim_id": f"generated-{case.case_id}-1",
        }
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
            "Provider-free document-derived oracle over a frozen local capture; "
            "Log4Shell is plumbing-only."
        ),
    )


def run_real_offline_slice(root: Path) -> list[OfflineCaseResult]:
    """Run the reviewed real-source slice with no provider or network fallback."""
    root = root.resolve(strict=True)
    states, documents = load_phase2_real_corpus(root)
    cases = load_phase2_real_cases(root, states=states, documents=documents)
    dataset_version = _dataset_version(root)
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
        hits = LexicalRetriever(corpus).search(case.question, limit=4)
        run_id = f"real-offline-{case.case_id}"
        answer = _real_oracle(
            case,
            run_id=run_id,
            hits=hits,
            documents=documents,
        )
        grades = grade_answer(
            case=case,
            answer=answer,
            documents=documents,
            states=states,
        )
        run = RunRecord(
            run_id=run_id,
            recorded_at_utc=REAL_RECORDED_AT,
            project_version="0.1.0",
            dataset_version=dataset_version,
            case_id=case.case_id,
            case_seed=0,
            condition="lexical_claim_evidence_constrained",
            provider="none",
            model_id=None,
            model_snapshot_or_version=None,
            prompt_version=REAL_ORACLE_VERSION,
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
                        score=round(hit.score, 12),
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


def _strict_json_numbers(value: Any) -> Any:
    if isinstance(value, list):
        return [_strict_json_numbers(item) for item in value]
    if not isinstance(value, dict):
        return value
    converted = {key: _strict_json_numbers(item) for key, item in value.items()}
    if converted.get("datatype") == "decimal" and isinstance(
        converted.get("value"),
        str,
    ):
        converted["value"] = float(converted["value"])
    if isinstance(converted.get("estimated_cost_usd"), str):
        converted["estimated_cost_usd"] = float(converted["estimated_cost_usd"])
    return converted


def render_real_results_jsonl(results: list[OfflineCaseResult]) -> str:
    """Serialize strict-schema round-trippable real results in stable order."""
    return "".join(
        json.dumps(
            _strict_json_numbers(result.model_dump(mode="json")),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for result in sorted(results, key=lambda item: item.case.case_id)
    )
