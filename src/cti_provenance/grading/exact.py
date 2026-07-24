"""Fail-closed deterministic claim grading."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable
from typing import Literal

from cti_provenance.claims.diverse_portfolio_v4 import (
    CandidateComponent,
    DiverseQuestionV4,
    grade_v4_outcome,
)
from cti_provenance.claims.schema import (
    AtomicClaim,
    ClaimAnswer,
    GoldAtomicClaim,
    PredicateName,
)
from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.grading.abstention import infer_abstention_predicate
from cti_provenance.grading.authority import (
    AUTHORITY_POLICY_VERSION,
    PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION,
    PORTFOLIO_MINIMUM_AUTHORITY_POLICY_VERSION,
    PORTFOLIO_PROOF_AUTHORITY_POLICY_VERSION,
    PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION,
    PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
    THREE_FAMILY_AUTHORITY_POLICY_VERSION,
    validate_authority_policy_predicate,
)
from cti_provenance.grading.citations import (
    EvidenceIndex,
    assess_citations,
    build_evidence_index,
)
from cti_provenance.grading.schema import ClaimGrade, EvidenceAssessment, match_claims
from cti_provenance.grading.temporal import TemporalSnapshotView, build_temporal_view
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.snapshot.admissibility import SnapshotState

DETERMINISTIC_GRADER_VERSION = "deterministic-exact-v1"
_NO_NORMALIZATION_VERSION = "not-applicable"

_PREDICATE_POLICY_ID = {
    "cve.affected_versions": "cve-program-affected-versions",
    "directive.required_action": "cisa-directive-required-action",
    "cve.published_at": "nvd-publication-time",
    "cve.modified_at": "nvd-publication-time",
    "cve.cvss.score": "named-cvss-authority",
    "kev.is_member": "cisa-kev-status",
    "kev.date_added": "cisa-kev-status",
    "kev.due_date": "cisa-kev-status",
    "vendor.affected_versions": "red-hat-product-state",
    "vendor.fixed_versions": "red-hat-product-state",
    "vendor.recommended_action": "vendor-recommended-action",
    "attack.relationship_present": "mitre-attack-relationship",
    "vendor.release_affected_versions": "apache-release-affected-versions",
    "kev.ransomware_campaign_use": "cisa-kev-ransomware-use",
    "attack.platforms": "mitre-attack-platforms",
    "vendor.security_release_versions": "node-security-release-versions",
    "vendor.cve_fixed_release": "django-cve-fixed-release",
    "nvd.cpe_applicability": "nvd-cpe-applicability",
    "source.temporal_change": "publisher-version-state-comparison",
    "source.authority_divergence": "predicate-specific-source-authority",
    "source.multi_source_synthesis": "independently-required-source-state-components",
}
_POLICY_ID_BY_VERSION: dict[tuple[str, PredicateName], str] = {
    (
        PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
        "kev.is_member",
    ): "cisa-kev-membership-yield",
    (
        PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION,
        "kev.is_member",
    ): "cisa-kev-membership-yield",
    (
        PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION,
        "vendor.security_release_versions",
    ): "vendor-security-release-versions",
    (
        PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION,
        "vendor.cve_fixed_release",
    ): "vendor-cve-fixed-release",
    (
        PORTFOLIO_MINIMUM_AUTHORITY_POLICY_VERSION,
        "vendor.cve_fixed_release",
    ): "postgresql-cve-fixed-release",
}


def _grade_id(
    *,
    run_id: str,
    case_id: str,
    generated_claim_id: str | None,
    expected_claim_id: str | None,
    predicate: str,
) -> str:
    identity = "\x1f".join(
        (
            run_id,
            case_id,
            generated_claim_id or "",
            expected_claim_id or "",
            predicate,
            DETERMINISTIC_GRADER_VERSION,
        )
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return f"claim-grade-{digest}"


def _normalization_version(
    evidence_ids: Iterable[str], evidence_index: EvidenceIndex
) -> str:
    versions = sorted(
        {
            indexed.document.normalization_version
            for evidence_id in evidence_ids
            if (indexed := evidence_index.evidence.get(evidence_id)) is not None
        }
    )
    return "+".join(versions) if versions else _NO_NORMALIZATION_VERSION


def _has_full_support(assessments: list[EvidenceAssessment]) -> bool:
    return any(
        assessment.resolution == "resolved"
        and assessment.entailment == "supported"
        and assessment.temporality == "admissible"
        and assessment.authority == "accepted"
        and assessment.span_hash_match is True
        for assessment in assessments
    )


def _validate_case_policy(
    case: BenchmarkCase,
    predicate: PredicateName,
    authority_policy_version: str,
) -> None:
    validate_authority_policy_predicate(authority_policy_version, predicate)
    policy_id = _POLICY_ID_BY_VERSION.get(
        (authority_policy_version, predicate), _PREDICATE_POLICY_ID[predicate]
    )
    if policy_id not in case.required_authority_policy_ids:
        raise ValueError(
            f"case does not require authority policy {policy_id!r} "
            f"for predicate {predicate!r}"
        )


def _matched_grade(
    *,
    case: BenchmarkCase,
    answer: ClaimAnswer,
    generated: AtomicClaim,
    expected: GoldAtomicClaim,
    exact: bool,
    evidence_index: EvidenceIndex,
    temporal_view: TemporalSnapshotView,
    authority_policy_version: str,
) -> ClaimGrade:
    assessments = assess_citations(
        case=case,
        claim=generated,
        expected=expected,
        value_exact=exact,
        evidence_index=evidence_index,
        temporal_view=temporal_view,
        authority_policy_version=authority_policy_version,
    )
    supported = exact and _has_full_support(assessments)
    return ClaimGrade(
        claim_grade_id=_grade_id(
            run_id=answer.run_id,
            case_id=case.case_id,
            generated_claim_id=generated.claim_id,
            expected_claim_id=expected.claim_id,
            predicate=expected.predicate,
        ),
        run_id=answer.run_id,
        case_id=case.case_id,
        generated_claim_id=generated.claim_id,
        expected_claim_id=expected.claim_id,
        predicate=expected.predicate,
        value_match="exact" if exact else "mismatch",
        evidence_assessments=assessments,
        contradiction="none",
        claim_support="supported" if supported else "unsupported",
        abstention_outcome="not_applicable",
        generated_confidence=generated.confidence,
        deterministic_grader_version=DETERMINISTIC_GRADER_VERSION,
        authority_policy_version=authority_policy_version,
        normalization_version=_normalization_version(
            generated.evidence_ids, evidence_index
        ),
        human_judgment_id=None,
        notes_code=None if supported else "deterministic_support_failed",
    )


def _unmatched_grade(
    *,
    case: BenchmarkCase,
    answer: ClaimAnswer,
    generated: AtomicClaim | None,
    expected: GoldAtomicClaim | None,
    evidence_index: EvidenceIndex,
    temporal_view: TemporalSnapshotView,
    authority_policy_version: str,
) -> ClaimGrade:
    if generated is not None:
        assessments = assess_citations(
            case=case,
            claim=generated,
            expected=None,
            value_exact=False,
            evidence_index=evidence_index,
            temporal_view=temporal_view,
            authority_policy_version=authority_policy_version,
        )
        predicate = generated.predicate
        evidence_ids = generated.evidence_ids
        abstention_outcome: Literal["missed", "unnecessary"] = "missed"
        notes_code = "unmatched_generated_false_positive"
    else:
        assert expected is not None
        assessments = []
        predicate = expected.predicate
        evidence_ids = expected.evidence_ids
        abstention_outcome = "unnecessary"
        notes_code = "unmatched_expected_false_negative"
    return ClaimGrade(
        claim_grade_id=_grade_id(
            run_id=answer.run_id,
            case_id=case.case_id,
            generated_claim_id=generated.claim_id if generated is not None else None,
            expected_claim_id=expected.claim_id if expected is not None else None,
            predicate=predicate,
        ),
        run_id=answer.run_id,
        case_id=case.case_id,
        generated_claim_id=generated.claim_id if generated is not None else None,
        expected_claim_id=expected.claim_id if expected is not None else None,
        predicate=predicate,
        value_match="not_applicable",
        evidence_assessments=assessments,
        contradiction="none",
        claim_support="unsupported",
        abstention_outcome=abstention_outcome,
        generated_confidence=(generated.confidence if generated is not None else None),
        deterministic_grader_version=DETERMINISTIC_GRADER_VERSION,
        authority_policy_version=authority_policy_version,
        normalization_version=_normalization_version(evidence_ids, evidence_index),
        human_judgment_id=None,
        notes_code=notes_code,
    )


def _correct_abstention_grade(
    *,
    case: BenchmarkCase,
    answer: ClaimAnswer,
    authority_policy_version: str,
) -> ClaimGrade:
    predicate = infer_abstention_predicate(case.template_family_id)
    _validate_case_policy(case, predicate, authority_policy_version)
    return ClaimGrade(
        claim_grade_id=_grade_id(
            run_id=answer.run_id,
            case_id=case.case_id,
            generated_claim_id=None,
            expected_claim_id=None,
            predicate=predicate,
        ),
        run_id=answer.run_id,
        case_id=case.case_id,
        generated_claim_id=None,
        expected_claim_id=None,
        predicate=predicate,
        value_match="not_applicable",
        evidence_assessments=[],
        contradiction="none",
        claim_support="ungradable",
        abstention_outcome="correct",
        generated_confidence=None,
        deterministic_grader_version=DETERMINISTIC_GRADER_VERSION,
        authority_policy_version=authority_policy_version,
        normalization_version=_NO_NORMALIZATION_VERSION,
        human_judgment_id=None,
        notes_code="correct_abstention",
    )


def grade_answer(
    case: BenchmarkCase,
    answer: ClaimAnswer,
    documents: list[NormalizedDocument],
    states: list[SnapshotState],
    authority_policy_version: str = AUTHORITY_POLICY_VERSION,
) -> list[ClaimGrade]:
    """Grade one valid answer envelope against one frozen benchmark case."""

    if answer.case_id != case.case_id:
        raise ValueError("answer case_id does not match benchmark case")
    if answer.as_of != case.as_of:
        raise ValueError("answer as_of does not match benchmark case")
    if authority_policy_version not in {
        AUTHORITY_POLICY_VERSION,
        THREE_FAMILY_AUTHORITY_POLICY_VERSION,
        PORTFOLIO_PROOF_AUTHORITY_POLICY_VERSION,
        PORTFOLIO_SCALE_AUTHORITY_POLICY_VERSION,
        PORTFOLIO_MINIMUM_AUTHORITY_POLICY_VERSION,
        PORTFOLIO_YIELD_AUTHORITY_POLICY_VERSION,
    }:
        raise ValueError(
            f"unsupported authority_policy_version {authority_policy_version!r}"
        )

    expected_by_id = {claim.claim_id: claim for claim in case.expected_claims}
    generated_by_id = {claim.claim_id: claim for claim in answer.claims}
    for claim in case.expected_claims:
        _validate_case_policy(case, claim.predicate, authority_policy_version)
    if case.should_abstain:
        _validate_case_policy(
            case,
            infer_abstention_predicate(case.template_family_id),
            authority_policy_version,
        )

    temporal_view = build_temporal_view(case, states)
    evidence_index = build_evidence_index(documents, temporal_view)

    if not case.expected_claims and not answer.claims:
        if not (case.should_abstain and answer.abstained):
            raise ValueError(
                "an empty non-abstained answer has no schema-valid abstention grade"
            )
        return [
            _correct_abstention_grade(
                case=case,
                answer=answer,
                authority_policy_version=authority_policy_version,
            )
        ]

    matching = match_claims(case.expected_claims, list(answer.claims))
    grades: list[ClaimGrade] = []
    for match in matching.matches:
        expected = expected_by_id[match.expected_claim_id]
        generated = generated_by_id[match.generated_claim_id]
        grades.append(
            _matched_grade(
                case=case,
                answer=answer,
                generated=generated,
                expected=expected,
                exact=match.exact,
                evidence_index=evidence_index,
                temporal_view=temporal_view,
                authority_policy_version=authority_policy_version,
            )
        )
    for expected_id in matching.unmatched_expected_claim_ids:
        grades.append(
            _unmatched_grade(
                case=case,
                answer=answer,
                generated=None,
                expected=expected_by_id[expected_id],
                evidence_index=evidence_index,
                temporal_view=temporal_view,
                authority_policy_version=authority_policy_version,
            )
        )
    for generated_id in matching.unmatched_generated_claim_ids:
        generated = generated_by_id[generated_id]
        grades.append(
            _unmatched_grade(
                case=case,
                answer=answer,
                generated=generated,
                expected=None,
                evidence_index=evidence_index,
                temporal_view=temporal_view,
                authority_policy_version=authority_policy_version,
            )
        )
    return grades


def grade_portfolio_diverse_outcome(
    question: DiverseQuestionV4,
    *,
    components: list[CandidateComponent],
    abstained: bool,
    abstention_reason_code: str | None,
    span_alias_to_evidence_id: dict[str, str],
    authority_policy_version: str = PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION,
) -> bool:
    """Grade a structured diverse-corpus answer under the central policy map."""

    if authority_policy_version != PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION:
        raise ValueError(
            f"unsupported diverse authority policy {authority_policy_version!r}"
        )
    validate_authority_policy_predicate(authority_policy_version, question.predicate)
    for component in components:
        try:
            validate_authority_policy_predicate(
                authority_policy_version, component.predicate
            )
        except ValueError:
            return False
    return grade_v4_outcome(
        question,
        components=components,
        abstained=abstained,
        abstention_reason_code=abstention_reason_code,
        span_alias_to_evidence_id=span_alias_to_evidence_id,
        compare_authority_scope=False,
    )


def grade_portfolio_diverse_provenance_outcome(
    question: DiverseQuestionV4,
    *,
    components: list[CandidateComponent],
    abstained: bool,
    abstention_reason_code: str | None,
    span_alias_to_evidence_id: dict[str, str],
    authority_policy_version: str = PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION,
) -> bool:
    """Grade the provenance decision independently of free-form value wording."""

    if authority_policy_version != PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION:
        raise ValueError(
            f"unsupported diverse authority policy {authority_policy_version!r}"
        )
    validate_authority_policy_predicate(authority_policy_version, question.predicate)
    for component in components:
        try:
            validate_authority_policy_predicate(
                authority_policy_version, component.predicate
            )
        except ValueError:
            return False
    if question.outcome_type == "abstain":
        return (
            abstained
            and abstention_reason_code == question.abstention_reason_code
            and not components
        )
    if abstained or abstention_reason_code is not None:
        return False
    expected = Counter(
        (
            item.kind,
            item.predicate,
            frozenset(item.required_evidence_ids),
        )
        for item in question.expected_components
    )
    try:
        actual = Counter(
            (
                item.kind,
                item.predicate,
                frozenset(
                    span_alias_to_evidence_id[alias]
                    for alias in item.cited_span_aliases
                ),
            )
            for item in components
        )
    except KeyError:
        return False
    return actual == expected
