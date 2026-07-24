"""Fail-closed corpus and gold loading for the local real-source slice."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from cti_provenance.claims.builders import (
    SCOPE_LABEL,
    load_phase2_plumbing_corpus,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.ingest.materialize import load_phase2_materialized_corpus
from cti_provenance.normalize import NormalizedDocument, resolve_span
from cti_provenance.snapshot import SnapshotState, select_admissible_by_entity

REAL_CASES_PATH = PurePosixPath("data/benchmark/dev/phase2-real-cases.jsonl")
REAL_REVIEWS_PATH = PurePosixPath("annotations/phase2-real-review.jsonl")
REAL_SOURCE_SNAPSHOT_IDS = (
    "nvd-ec21319bd698",
    "kev-41d27023a591",
    "rhsa-da43faeafb5b",
)
REAL_SOURCE_DOCUMENT_IDS = (
    "nvd-cve-2021-44228",
    "kev-cve-2021-44228",
    "red-hat-rhsa-2021-5133",
)
CONTRADICTION_SNAPSHOT_ID = "phase2-fixture-contradiction-v1"
CONTRADICTION_DOCUMENT_ID = "phase2-contradictory-log4shell"

_POLICY_BY_PREDICATE = {
    "cve.published_at": "nvd-publication-time",
    "cve.modified_at": "nvd-publication-time",
    "cve.cvss.score": "named-cvss-authority",
    "kev.is_member": "cisa-kev-status",
    "kev.date_added": "cisa-kev-status",
    "kev.due_date": "cisa-kev-status",
    "vendor.affected_versions": "red-hat-product-state",
    "vendor.fixed_versions": "red-hat-product-state",
}
_PREDICATE_BY_TEMPLATE = {
    "nvd-published-at": "cve.published_at",
    "nvd-modified-at": "cve.modified_at",
    "nvd-cvss-score": "cve.cvss.score",
    "kev-membership": "kev.is_member",
    "kev-date-added": "kev.date_added",
    "kev-due-date": "kev.due_date",
    "red-hat-affected-versions": "vendor.affected_versions",
    "red-hat-fixed-versions": "vendor.fixed_versions",
}
_MODE_BY_PREDICATE = {
    "cve.published_at": "observed_snapshot",
    "cve.modified_at": "observed_snapshot",
    "cve.cvss.score": "observed_snapshot",
    "kev.is_member": "upstream_versioned",
    "kev.date_added": "upstream_versioned",
    "kev.due_date": "upstream_versioned",
    "vendor.affected_versions": "upstream_versioned",
    "vendor.fixed_versions": "upstream_versioned",
}
_SNAPSHOT_BY_PREDICATE = {
    "cve.published_at": "nvd-ec21319bd698",
    "cve.modified_at": "nvd-ec21319bd698",
    "cve.cvss.score": "nvd-ec21319bd698",
    "kev.is_member": "kev-41d27023a591",
    "kev.date_added": "kev-41d27023a591",
    "kev.due_date": "kev-41d27023a591",
    "vendor.affected_versions": "rhsa-da43faeafb5b",
    "vendor.fixed_versions": "rhsa-da43faeafb5b",
}


class RealSliceError(ValueError):
    """Local real-source inputs or reviewed gold violate the frozen slice."""


RealReviewCode = Literal[
    "real_source_plumbing_only",
    "real_publisher_declared_version_evidence_only",
    "real_cutoff_abstention",
    "real_insufficient_evidence",
    "real_with_synthetic_combined_treatment",
]
InsufficiencyCode = Literal["no_explicit_known_affected_span"]


class RealCaseReview(BaseModel):
    """Manager review evidence for one real-source development case."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case_id: str
    reviewer_role: Literal["manager"]
    reviewed_at_utc: datetime
    question_status: Literal["pass"]
    claim_status: Literal["pass", "not_applicable"]
    evidence_status: Literal["pass", "not_applicable"]
    evidence_ids: list[str]
    notes_code: RealReviewCode
    target_subject_type: Literal["cve", "product", "advisory", "attack_object"] | None
    target_subject_id: str | None
    target_predicate: str | None
    required_authority: str | None
    insufficiency_code: InsufficiencyCode | None


def _safe_read(root: Path, relative: PurePosixPath) -> bytes:
    root = root.resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        current = candidate
        while current != root:
            is_junction = getattr(current, "is_junction", None)
            if current.is_symlink() or (callable(is_junction) and is_junction()):
                raise RealSliceError("real-slice input traverses a link")
            current = current.parent
        return resolved.read_bytes()
    except (OSError, ValueError) as exc:
        raise RealSliceError("real-slice tracked input is unavailable") from exc


def _load_jsonl[ModelT: BaseModel](
    root: Path,
    relative: PurePosixPath,
    model: type[ModelT],
) -> list[ModelT]:
    records: list[ModelT] = []
    for line_number, line in enumerate(
        _safe_read(root, relative).splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            records.append(model.model_validate_json(line))
        except ValueError as exc:
            raise RealSliceError(
                f"invalid real-slice record on line {line_number}"
            ) from exc
    return records


def load_phase2_real_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument]]:
    """Replay the exact real capture plus its one declared synthetic treatment."""
    real_states, real_documents = load_phase2_materialized_corpus(root)
    if (
        tuple(state.manifest.snapshot_id for state in real_states)
        != REAL_SOURCE_SNAPSHOT_IDS
        or tuple(document.document_id for document in real_documents)
        != REAL_SOURCE_DOCUMENT_IDS
    ):
        raise RealSliceError("real-slice corpus identity does not match the freeze")
    synthetic_states, synthetic_documents = load_phase2_plumbing_corpus(root)
    treatment_states = [
        state
        for state in synthetic_states
        if state.manifest.snapshot_id == CONTRADICTION_SNAPSHOT_ID
    ]
    treatment_documents = [
        document
        for document in synthetic_documents
        if document.document_id == CONTRADICTION_DOCUMENT_ID
    ]
    if len(treatment_states) != 1 or len(treatment_documents) != 1:
        raise RealSliceError("real-slice contradiction treatment is unavailable")
    return [*real_states, *treatment_states], [
        *real_documents,
        *treatment_documents,
    ]


def _real_claim_contracts(
    documents: list[NormalizedDocument],
) -> dict[str, dict[str, Any]]:
    by_id = {document.document_id: document for document in documents}
    try:
        nvd = by_id["nvd-cve-2021-44228"]
        kev = by_id["kev-cve-2021-44228"]
        red_hat = by_id["red-hat-rhsa-2021-5133"]
        fixed = red_hat.fields["fixed_products"]
        if (
            not isinstance(fixed, list)
            or not fixed
            or not all(
                isinstance(item, dict) and isinstance(item.get("product"), str)
                for item in fixed
            )
        ):
            raise RealSliceError("real Red Hat fixed-product mapping is unavailable")
        fixed_products: list[str] = []
        for item in fixed:
            if not isinstance(item, dict):
                raise RealSliceError(
                    "real Red Hat fixed-product mapping is unavailable"
                )
            product = item.get("product")
            if not isinstance(product, str):
                raise RealSliceError(
                    "real Red Hat fixed-product mapping is unavailable"
                )
            fixed_products.append(product)
        fixed_products = sorted(set(fixed_products))
        cvss = Decimal(str(nvd.fields["cvss_v31_base_score"]))
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, RealSliceError):
            raise
        raise RealSliceError("real-slice normalized fields are incomplete") from exc
    return {
        "cve.published_at": {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "cve.published_at",
            "object": {
                "value": str(nvd.fields["published"]),
                "datatype": "string",
            },
            "qualifiers": {
                "authority": "nvd",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": ["nvd-cve-2021-44228:nvd-published"],
            "confidence": 1.0,
        },
        "cve.modified_at": {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "cve.modified_at",
            "object": {
                "value": str(nvd.fields["modified"]),
                "datatype": "string",
            },
            "qualifiers": {
                "authority": "nvd",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": ["nvd-cve-2021-44228:nvd-modified"],
            "confidence": 1.0,
        },
        "cve.cvss.score": {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "cve.cvss.score",
            "object": {"value": cvss, "datatype": "decimal"},
            "qualifiers": {
                "authority": "nvd@nist.gov",
                "cvss_version": "3.1",
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": ["nvd-cve-2021-44228:nvd-cvss-v31"],
            "confidence": 1.0,
        },
        "kev.is_member": {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "kev.is_member",
            "object": {"value": True, "datatype": "boolean"},
            "qualifiers": {
                "authority": "cisa_kev",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": ["kev-cve-2021-44228:kev-membership"],
            "confidence": 1.0,
        },
        "kev.date_added": {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "kev.date_added",
            "object": {"value": str(kev.fields["date_added"]), "datatype": "date"},
            "qualifiers": {
                "authority": "cisa_kev",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": ["kev-cve-2021-44228:kev-date-added"],
            "confidence": 1.0,
        },
        "kev.due_date": {
            "subject": {"type": "cve", "id": "CVE-2021-44228"},
            "predicate": "kev.due_date",
            "object": {"value": str(kev.fields["due_date"]), "datatype": "date"},
            "qualifiers": {
                "authority": "cisa_kev",
                "cvss_version": None,
                "product": None,
                "ecosystem": None,
            },
            "evidence_ids": ["kev-cve-2021-44228:kev-due-date"],
            "confidence": 1.0,
        },
        "vendor.fixed_versions": {
            "subject": {"type": "advisory", "id": "RHSA-2021:5133"},
            "predicate": "vendor.fixed_versions",
            "object": {"value": fixed_products, "datatype": "version_set"},
            "qualifiers": {
                "authority": "red_hat_rhsa",
                "cvss_version": None,
                "product": fixed_products[0],
                "ecosystem": None,
            },
            "evidence_ids": ["red-hat-rhsa-2021-5133:rhsa-fixed-0-id"],
            "confidence": 1.0,
        },
    }


def _expected_review_code(case: BenchmarkCase) -> RealReviewCode:
    if case.should_abstain:
        return (
            "real_insufficient_evidence"
            if case.allowed_snapshot_ids
            else "real_cutoff_abstention"
        )
    if case.attack.family == "contradiction":
        return "real_with_synthetic_combined_treatment"
    if any(claim.predicate.startswith("vendor.") for claim in case.expected_claims):
        return "real_publisher_declared_version_evidence_only"
    return "real_source_plumbing_only"


def load_phase2_real_cases(
    root: Path,
    *,
    states: list[SnapshotState],
    documents: list[NormalizedDocument],
) -> list[BenchmarkCase]:
    """Load and independently cross-check the 12-case reviewed real slice."""
    cases = _load_jsonl(root, REAL_CASES_PATH, BenchmarkCase)
    reviews = _load_jsonl(root, REAL_REVIEWS_PATH, RealCaseReview)
    if len(cases) != 12 or len({case.case_id for case in cases}) != len(cases):
        raise RealSliceError("real slice requires exactly 12 unique cases")
    if any(
        case.split != "dev"
        or case.entity_family_id != SCOPE_LABEL
        or "plumbing-only" not in case.question.casefold()
        for case in cases
    ):
        raise RealSliceError("real cases must retain development scope labels")

    case_by_id = {case.case_id: case for case in cases}
    review_by_id = {review.case_id: review for review in reviews}
    if len(review_by_id) != len(reviews) or set(review_by_id) != set(case_by_id):
        raise RealSliceError("every real case requires exactly one review")

    state_ids = {state.manifest.snapshot_id for state in states}
    document_by_id = {document.document_id: document for document in documents}
    if len(document_by_id) != len(documents):
        raise RealSliceError("real-slice document identities are not unique")
    evidence_ids: set[str] = set()
    for document in documents:
        if document.snapshot_id not in state_ids:
            raise RealSliceError("real-slice document references an unknown snapshot")
        for span in document.spans:
            evidence_id = f"{document.document_id}:{span.span_id}"
            if evidence_id in evidence_ids:
                raise RealSliceError("real-slice evidence identities are not unique")
            resolve_span(span, document.normalized_text)
            evidence_ids.add(evidence_id)

    contracts = _real_claim_contracts(documents)
    for case in cases:
        review = review_by_id[case.case_id]
        predicate = _PREDICATE_BY_TEMPLATE.get(case.template_family_id)
        if predicate is None:
            raise RealSliceError("real case uses an unsupported template")
        if case.temporal_truth_mode != _MODE_BY_PREDICATE[
            predicate
        ] or case.required_authority_policy_ids != [_POLICY_BY_PREDICATE[predicate]]:
            raise RealSliceError("real case temporal mode or authority policy is wrong")
        selected_ids = {
            manifest.snapshot_id
            for manifest in select_admissible_by_entity(states, case.as_of).values()
        }
        if not set(case.allowed_snapshot_ids) <= selected_ids:
            raise RealSliceError("real case includes post-cutoff source state")

        expected_evidence = sorted(
            {
                evidence_id
                for claim in case.expected_claims
                for evidence_id in claim.evidence_ids
            }
        )
        if (
            review.reviewed_at_utc.tzinfo is None
            or review.reviewed_at_utc.utcoffset()
            != UTC.utcoffset(review.reviewed_at_utc)
            or review.evidence_ids != expected_evidence
            or review.notes_code != _expected_review_code(case)
            or (
                case.should_abstain
                and (
                    review.claim_status != "not_applicable"
                    or review.evidence_status != "not_applicable"
                )
            )
            or (
                not case.should_abstain
                and (review.claim_status != "pass" or review.evidence_status != "pass")
            )
        ):
            raise RealSliceError("real case review does not match its gold")
        structured_insufficiency = (
            review.target_subject_type,
            review.target_subject_id,
            review.target_predicate,
            review.required_authority,
            review.insufficiency_code,
        )

        if case.should_abstain:
            if case.expected_claims:
                raise RealSliceError("real abstention cannot contain expected claims")
            if (
                review.notes_code == "real_cutoff_abstention"
                and case.allowed_snapshot_ids
            ):
                raise RealSliceError("pre-availability case must expose no snapshot")
            if (
                review.notes_code == "real_cutoff_abstention"
                and _SNAPSHOT_BY_PREDICATE[predicate] in selected_ids
            ):
                raise RealSliceError(
                    "pre-availability case cutoff admits its target snapshot"
                )
            if review.notes_code == "real_insufficient_evidence" and (
                case.allowed_snapshot_ids != ["rhsa-da43faeafb5b"]
                or predicate != "vendor.affected_versions"
                or structured_insufficiency
                != (
                    "advisory",
                    "RHSA-2021:5133",
                    "vendor.affected_versions",
                    "red_hat_rhsa",
                    "no_explicit_known_affected_span",
                )
                or any(
                    span.field_path.startswith("/product_status/known_affected")
                    for span in document_by_id["red-hat-rhsa-2021-5133"].spans
                )
                or document_by_id["red-hat-rhsa-2021-5133"].fields.get(
                    "known_affected_products"
                )
                != []
            ):
                raise RealSliceError("insufficient-evidence case has the wrong corpus")
            if review.notes_code != "real_insufficient_evidence" and any(
                value is not None for value in structured_insufficiency
            ):
                raise RealSliceError(
                    "only insufficient-evidence review may declare a target"
                )
            continue
        if any(value is not None for value in structured_insufficiency):
            raise RealSliceError("answerable review cannot declare insufficiency")

        if len(case.expected_claims) != 1 or predicate not in contracts:
            raise RealSliceError("real answerable case has the wrong claim count")
        expected_allowed = {_SNAPSHOT_BY_PREDICATE[predicate]}
        if case.attack.family == "contradiction":
            expected_allowed.add(CONTRADICTION_SNAPSHOT_ID)
        if set(case.allowed_snapshot_ids) != expected_allowed:
            raise RealSliceError("real answerable case exposes extra source state")
        claim = case.expected_claims[0]
        if claim.model_dump(exclude={"claim_id"}) != contracts[predicate]:
            raise RealSliceError(
                "real answer key does not match normalized source data"
            )
        if not set(claim.evidence_ids) <= evidence_ids:
            raise RealSliceError("real answer key references missing evidence")
        cited_documents = {
            evidence_id.split(":", 1)[0] for evidence_id in claim.evidence_ids
        }
        if any(
            document_by_id[document_id].snapshot_id not in case.allowed_snapshot_ids
            for document_id in cited_documents
        ):
            raise RealSliceError("real answer evidence is outside the case corpus")
        if predicate.startswith("vendor.") and (
            "publisher-declared version evidence" not in case.question.casefold()
        ):
            raise RealSliceError("Red Hat question lacks its temporal qualification")

    paired = [case for case in cases if case.paired_case_id is not None]
    if len(paired) != 2:
        raise RealSliceError("real slice requires one reciprocal treatment pair")
    for case in paired:
        assert case.paired_case_id is not None
        other = case_by_id.get(case.paired_case_id)
        if (
            other is None
            or other.paired_case_id != case.case_id
            or other.question != case.question
            or other.as_of != case.as_of
            or other.template_family_id != case.template_family_id
            or {
                case.attack.family,
                other.attack.family,
            }
            != {"none", "contradiction"}
        ):
            raise RealSliceError("real treatment pair is not reciprocal")
        attacked = case if case.attack.family == "contradiction" else other
        clean = other if attacked is case else case
        if (
            attacked.attack.treatment_document_ids != [CONTRADICTION_DOCUMENT_ID]
            or set(attacked.allowed_snapshot_ids) - set(clean.allowed_snapshot_ids)
            != {CONTRADICTION_SNAPSHOT_ID}
            or [
                claim.model_dump(exclude={"claim_id"})
                for claim in attacked.expected_claims
            ]
            != [
                claim.model_dump(exclude={"claim_id"})
                for claim in clean.expected_claims
            ]
        ):
            raise RealSliceError("real treatment pair changes more than treatment")
    return sorted(cases, key=lambda case: case.case_id)
