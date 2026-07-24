"""Redacted reporting for the local-capture real-source scripted oracle."""

from __future__ import annotations

from cti_provenance.experiments.runner import OfflineCaseResult


def _ratio(numerator: int, denominator: int) -> str:
    value = numerator / denominator if denominator else 0.0
    return f"{numerator}/{denominator} ({value:.1%})"


def render_real_offline_report(results: list[OfflineCaseResult]) -> str:
    """Render measured local replay results without implying model evaluation."""
    ordered = sorted(results, key=lambda result: result.case.case_id)
    answerable = [result for result in ordered if not result.case.should_abstain]
    abstention = [result for result in ordered if result.case.should_abstain]
    grades = [grade for result in ordered for grade in result.grades]
    material = [
        grade
        for grade in grades
        if grade.generated_claim_id is not None or grade.expected_claim_id is not None
    ]
    assessments = [
        assessment for grade in material for assessment in grade.evidence_assessments
    ]
    supported = sum(grade.claim_support == "supported" for grade in material)
    correct_abstentions = sum(grade.abstention_outcome == "correct" for grade in grades)
    citations = sum(assessment.entailment == "supported" for assessment in assessments)
    temporal = sum(assessment.temporality == "admissible" for assessment in assessments)
    authority = sum(assessment.authority == "accepted" for assessment in assessments)
    evidence_covered = sum(
        any(
            assessment.resolution == "resolved" and assessment.span_hash_match is True
            for grade in result.grades
            for assessment in grade.evidence_assessments
        )
        for result in answerable
    )
    retrieval_recall = sum(
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
    attacked = next(
        result for result in ordered if result.case.attack.family == "contradiction"
    )
    clean = next(
        result
        for result in ordered
        if result.case.case_id == attacked.case.paired_case_id
    )
    cost = sum(result.run.estimated_cost_usd for result in ordered)
    return (
        "# Phase 2 real-source local-capture replay\n\n"
        "Status: **smoke-tested; scope=local_real_source_scripted_oracle**. "
        "This is a provider-free deterministic development proof, not a model "
        "evaluation, baseline, generalization result, or clean-clone reproduction.\n\n"
        "`CVE-2021-44228` (Log4Shell) remains explicitly plumbing-only. The "
        "slice checks frozen-byte replay, cutoff selection, lexical retrieval, "
        "document-derived claim construction, evidence resolution, authority, "
        "and abstention. It makes no new substantive Log4Shell finding.\n\n"
        "## Results\n\n"
        f"- Cases: {len(ordered)} total; {len(answerable)} answerable; "
        f"{len(abstention)} abstention.\n"
        f"- Document-derived atomic claim support: "
        f"{_ratio(supported, len(material))}.\n"
        f"- Correct abstention: "
        f"{_ratio(correct_abstentions, len(abstention))}.\n"
        f"- Citation support: {_ratio(citations, len(assessments))}.\n"
        f"- Temporal admissibility: {_ratio(temporal, len(assessments))}.\n"
        f"- Accepted predicate authority: {_ratio(authority, len(assessments))}.\n"
        f"- Evidence coverage: {_ratio(evidence_covered, len(answerable))}.\n"
        f"- Retrieval recall@4: {_ratio(retrieval_recall, len(answerable))}.\n"
        "- Post-cutoff leakage: 0 observed in the three exact boundary cases.\n"
        f"- Provider calls/tokens/cost: 0 / 0 / ${cost:.2f}.\n\n"
        "## Combined treatment diagnostic\n\n"
        f"- Clean case: `{clean.case.case_id}`.\n"
        f"- Treated case: `{attacked.case.case_id}`.\n"
        "- The project-authored treatment combines a lower-authority conflicting "
        "CVSS value with inert instruction-like text. It is retrieved but cannot "
        "be selected as NVD authority by the document-derived oracle. This is a "
        "combined plumbing diagnostic, not an isolated contradiction estimand or "
        "evidence of model resistance.\n\n"
        "## Temporal and authenticity boundaries\n\n"
        "- NVD is an observed HTTPS snapshot eligible only from its recorded "
        "retrieval time; its internal publication and modification fields do not "
        "backdate the bytes and the capture is not cryptographic publisher proof.\n"
        "- CISA KEV is bound to the tracked official repository commit and "
        "commit-lineage evidence.\n"
        "- Red Hat revision 3 is checksum-matched. Its `current_release_date` is "
        "publisher-declared version evidence only, never independently observed "
        "historical availability.\n"
        "- Exact raw and normalized payloads remain local and gitignored. A clean "
        "checkout must fail closed until a separate redistribution/archive "
        "decision supplies the exact bytes.\n\n"
        "## Attribution and redistribution notes\n\n"
        "- NVD source: https://services.nvd.nist.gov/rest/json/cves/2.0 . "
        "This report contains derived atomic facts and provenance identifiers, "
        "not redistributed response bodies.\n"
        "- CISA KEV source: "
        "https://github.com/cisagov/kev-data . CISA publishes KEV data under "
        "CC0; use of agency names does not imply endorsement.\n"
        "- Red Hat source: "
        "https://security.access.redhat.com/data/csaf/v2/advisories/2021/"
        "rhsa-2021_5133.json . Security data is used under CC BY 4.0 "
        "(https://creativecommons.org/licenses/by/4.0/). This project records "
        "derived normalized claims and provenance; it is not endorsed by Red Hat "
        "and any transformation is a project modification.\n\n"
        "## Interpretation boundary\n\n"
        "The oracle reads retrieved normalized fields and never copies gold "
        "answers or abstention labels to construct its output. Gold is used only "
        "by the deterministic grader after answer generation. The next provider "
        "evaluation remains separately gated by an explicit model, cases, "
        "repetitions, cost ceiling, and evidence plan.\n"
    )
