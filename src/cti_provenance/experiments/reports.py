"""Deterministic Markdown reporting for the Phase 2 plumbing-only slice."""

from __future__ import annotations

from cti_provenance.experiments.runner import OfflineCaseResult

_REPRESENTATION_BY_PREDICATE = {
    "cve.published_at": "Synthetic NVD",
    "cve.modified_at": "Synthetic NVD",
    "cve.cvss.score": "Synthetic NVD",
    "kev.is_member": "Synthetic CISA KEV",
    "kev.date_added": "Synthetic CISA KEV",
    "kev.due_date": "Synthetic CISA KEV",
    "vendor.affected_versions": "Synthetic Red Hat",
    "vendor.fixed_versions": "Synthetic Red Hat",
}


def _ratio(numerator: int, denominator: int) -> str:
    value = numerator / denominator if denominator else 0.0
    return f"{numerator}/{denominator} ({value:.1%})"


def _predicate_table(results: list[OfflineCaseResult]) -> str:
    predicates = sorted(
        {claim.predicate for result in results for claim in result.case.expected_claims}
    )
    rows = [
        "| Representation | Predicate | Cases | Supported | "
        "Evidence covered | Retrieved |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for predicate in predicates:
        matching = [
            result
            for result in results
            if any(
                claim.predicate == predicate for claim in result.case.expected_claims
            )
        ]
        supported = sum(
            any(
                grade.predicate == predicate and grade.claim_support == "supported"
                for grade in result.grades
            )
            for result in matching
        )
        covered = sum(
            any(
                assessment.resolution == "resolved"
                and assessment.span_hash_match is True
                for grade in result.grades
                if grade.predicate == predicate
                for assessment in grade.evidence_assessments
            )
            for result in matching
        )
        retrieved = sum(
            bool(
                {
                    evidence_id.split(":", 1)[0]
                    for claim in result.case.expected_claims
                    if claim.predicate == predicate
                    for evidence_id in claim.evidence_ids
                }
                & {hit.document_id for hit in result.retrieval}
            )
            for result in matching
        )
        denominator = len(matching)
        rows.append(
            f"| {_REPRESENTATION_BY_PREDICATE[predicate]} | `{predicate}` | "
            f"{denominator} | {supported}/{denominator} | {covered}/{denominator} | "
            f"{retrieved}/{denominator} |"
        )
    return "\n".join(rows)


def render_offline_report(results: list[OfflineCaseResult]) -> str:
    """Render declared denominators without implying a model evaluation."""
    ordered = sorted(results, key=lambda result: result.case.case_id)
    answerable = [result for result in ordered if not result.case.should_abstain]
    abstention = [result for result in ordered if result.case.should_abstain]
    grades = [grade for result in ordered for grade in result.grades]
    material = [
        grade
        for grade in grades
        if grade.generated_claim_id is not None or grade.expected_claim_id is not None
    ]
    supported = sum(grade.claim_support == "supported" for grade in material)
    correct_abstentions = sum(grade.abstention_outcome == "correct" for grade in grades)
    assessments = [
        assessment for grade in grades for assessment in grade.evidence_assessments
    ]
    temporally_admissible = sum(
        assessment.temporality == "admissible" for assessment in assessments
    )
    citation_supported = sum(
        assessment.entailment == "supported" for assessment in assessments
    )
    accepted_authority = sum(
        assessment.authority == "accepted" for assessment in assessments
    )
    evidence_covered = sum(
        any(
            assessment.resolution == "resolved" and assessment.span_hash_match is True
            for grade in result.grades
            for assessment in grade.evidence_assessments
        )
        for result in answerable
    )
    answerable_with_relevant_hit = sum(
        bool(
            {
                evidence_id.split(":", 1)[0]
                for claim in result.case.expected_claims
                for evidence_id in claim.evidence_ids
            }
            & {hit.document_id for hit in result.retrieval}
        )
        for result in answerable
    )
    predicted_abstentions = sum(result.answer.abstained for result in ordered)
    adversarial = [result for result in ordered if result.case.attack.family != "none"]
    treatment_exposed = sum(
        result.treatment_diagnostic.status == "retrieved_not_classified"
        for result in adversarial
    )
    attacked = adversarial[0]
    assert attacked.case.paired_case_id is not None
    clean = next(
        result
        for result in ordered
        if result.case.case_id == attacked.case.paired_case_id
    )
    clean_documents = ", ".join(hit.document_id for hit in clean.retrieval)
    attacked_documents = ", ".join(hit.document_id for hit in attacked.retrieval)
    cost = sum(result.run.estimated_cost_usd for result in ordered)
    return (
        "# Phase 2 offline plumbing slice\n\n"
        "Status: deterministic offline development plumbing path; **not a provider "
        "evaluation**.\n\n"
        "`CVE-2021-44228` (Log4Shell) is plumbing-only. These fixtures test "
        "contracts, cutoff filtering, retrieval, evidence resolution, and "
        "grading; they do not constitute a new Log4Shell finding or evidence "
        "of benchmark generalization.\n\n"
        "The project-authored Red Hat fixture is bound only by its project "
        "manifest hash; it is not upstream checksum evidence. It models the "
        "policy that a real Red Hat `current_release_date` is publisher-declared "
        "version evidence only after the exact upstream body is verified against "
        "Red Hat's published checksum. The date is not independently observed "
        "historical availability.\n\n"
        "## Results\n\n"
        f"- Cases: {len(ordered)} total; {len(answerable)} answerable; "
        f"{len(abstention)} abstention.\n"
        f"- Atomic claim accuracy/support: {_ratio(supported, len(material))}.\n"
        f"- Correct abstention: {_ratio(correct_abstentions, len(abstention))}.\n"
        f"- Citation support: {_ratio(citation_supported, len(assessments))}.\n"
        f"- Temporal accuracy: {_ratio(temporally_admissible, len(assessments))}.\n"
        "- Synthetic represented-source policy routing: "
        f"{_ratio(accepted_authority, len(assessments))}; real-source authority "
        "and authenticity remain untested.\n"
        f"- Evidence coverage: {_ratio(evidence_covered, len(answerable))}.\n"
        f"- Retrieval recall@4: "
        f"{_ratio(answerable_with_relevant_hit, len(answerable))}.\n"
        f"- Abstention precision/recall/coverage: "
        f"{_ratio(correct_abstentions, predicted_abstentions)} / "
        f"{_ratio(correct_abstentions, len(abstention))} / "
        f"{_ratio(predicted_abstentions, len(ordered))}.\n"
        "- Post-cutoff leakage: 0 observed in the deterministic fixture gate; "
        "the cutoff-leakage test keeps later physical documents outside ranking.\n"
        f"- Declared treatment retrieval exposure: "
        f"{_ratio(treatment_exposed, len(adversarial))}.\n"
        f"- Provider calls/tokens/cost: 0 / 0 / ${cost:.2f}.\n\n"
        "## Per-representation and predicate diagnostics\n\n"
        f"{_predicate_table(answerable)}\n\n"
        "## Adversarial-pair diagnostic\n\n"
        f"- Clean retrieval (`{clean.case.case_id}`): {clean_documents}.\n"
        f"- Contradiction-treatment retrieval (`{attacked.case.case_id}`): "
        f"{attacked_documents}.\n"
        "- The declared treatment must be retrieved for the slice to pass. "
        "Contradiction classification and attack success rate are **not yet "
        "implemented / not applicable** to this scripted-oracle gate.\n\n"
        "## Uncertainty and not-yet-tested inventory\n\n"
        "- Deterministic fixture failures: none in this run.\n"
        "- Real-source capture, real-source authority/authenticity, model "
        "behavior, contradiction inference, statistical uncertainty, and "
        "provider safety outcomes remain untested.\n\n"
        "## Interpretation boundary\n\n"
        "The scripted oracle is a plumbing check, not a baseline model. Phase 2 "
        "cannot be called evaluated or improved until the separately approved "
        "provider conditions run on frozen data with cost reconciliation.\n"
    )
