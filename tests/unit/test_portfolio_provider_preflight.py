"""Offline contracts for the frozen V6 Luna plan and human-review stop."""

from __future__ import annotations

import json
from collections import Counter
from decimal import Decimal
from pathlib import Path

from cti_provenance.claims.diverse_portfolio_v4 import CandidateComponent
from cti_provenance.claims.diverse_portfolio_v6 import (
    DiverseCorpusV6,
    PacketIndexV6,
)
from cti_provenance.experiments.portfolio_diverse_execution import (
    _provider_result_requires_run_stop,
    score_provider_result,
)
from cti_provenance.experiments.portfolio_diverse_provider import (
    PortfolioProviderPlan,
    PortfolioProviderResponse,
    PortfolioProviderSlot,
    build_portfolio_candidate_packet,
    build_portfolio_provider_schedule,
    build_portfolio_request,
    candidate_alias_map,
    portfolio_provider_response_schema,
)
from cti_provenance.grading import (
    grade_portfolio_diverse_outcome,
    grade_portfolio_diverse_provenance_outcome,
)
from cti_provenance.grading.authority import (
    PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION,
    validate_authority_policy_predicate,
)
from cti_provenance.models.openai_client import OpenAIResult

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "data/benchmark/portfolio-diverse-draft-v6.json"
INDEX = ROOT / "data/benchmark/portfolio-diverse-packets-v6.json"
PLAN = ROOT / "configs/experiments/portfolio-diverse-v6-openai-luna.json"
SCHEDULE = ROOT / "data/benchmark/portfolio-diverse-provider-schedule-v1.json"
EGRESS = ROOT / "reports/portfolio-provider-egress-v1.json"
CITATION_PROMPT = ROOT / "configs/prompts/portfolio-diverse-v6-citation-prompted.txt"
CONSTRAINED_PROMPT = ROOT / "configs/prompts/portfolio-diverse-v6-constrained.txt"


def _plan() -> PortfolioProviderPlan:
    return PortfolioProviderPlan.model_validate_json(PLAN.read_text(encoding="utf-8"))


def test_frozen_plan_has_complete_single_sample_design_and_cost_stop() -> None:
    plan = _plan()
    schedule_payload = json.loads(SCHEDULE.read_text(encoding="utf-8"))
    slots = [
        PortfolioProviderSlot.model_validate_json(json.dumps(item))
        for item in schedule_payload["slots"]
    ]
    assert plan.model_route == "gpt-5.6-luna"
    assert plan.returned_model_policy == "record_exact_no_fallback"
    assert plan.conditions == (
        "citation_prompted",
        "claim_evidence_constrained",
    )
    assert (
        plan.comparison_scope
        == "bundled_pipeline_variants_prompt_plus_api_schema_enforcement"
    )
    assert plan.causal_attribution == "not_estimated"
    assert plan.primary_metric == "provenance_outcome_correct"
    assert plan.secondary_metric == "canonical_typed_value_exact"
    assert (
        plan.authority_scope_treatment
        == "descriptive_unscored_authority_from_predicate_and_citations"
    )
    assert plan.repeats == 1
    assert len(slots) == plan.planned_calls == 192
    assert len({item.slot_id for item in slots}) == 192
    assert Counter(item.variant for item in slots) == {
        "clean": 128,
        "control": 32,
        "challenge": 32,
    }
    assert Counter(item.condition for item in slots) == {
        "citation_prompted": 96,
        "claim_evidence_constrained": 96,
    }
    assert plan.max_transient_retries == 2
    assert plan.maximum_attempts == 576
    assert plan.transient_retry_backoff_seconds == (2, 8)
    assert plan.retry_inclusive_upper_bound_usd == Decimal("29.952")
    assert plan.retry_inclusive_upper_bound_usd < plan.cost_cap_usd
    assert plan.status == "ready_for_execution"
    assert sum(not item.egress_eligible for item in slots) == 0
    assert plan.egress_blocked_case_ids == ()
    assert plan.egress_blocked_call_count == 0


def test_both_conditions_receive_the_complete_response_contract() -> None:
    required_fields = {
        "schema_version",
        "case_id",
        "abstained",
        "abstention_reason_code",
        "components",
        "kind",
        "predicate",
        "datatype",
        "value",
        "authority_scope",
        "cited_span_aliases",
    }
    reason_codes = {
        "no_cutoff_eligible_state",
        "insufficient_product_version_specificity",
        "predicate_absent",
        "wrong_authority_for_predicate",
        "unresolved_authoritative_evidence",
    }
    for path in (CITATION_PROMPT, CONSTRAINED_PROMPT):
        prompt = path.read_text(encoding="utf-8")
        assert all(f'"{field}"' in prompt for field in required_fields)
        assert all(code in prompt for code in reason_codes)
        assert 'There is no top-level "answer" field.' in prompt
    assert "will not enforce" in CITATION_PROMPT.read_text(encoding="utf-8")
    assert "will enforce" in CONSTRAINED_PROMPT.read_text(encoding="utf-8")


def test_strict_response_schema_contains_no_untyped_json_value() -> None:
    schema = portfolio_provider_response_schema()
    json_value = schema["$defs"]["JsonValue"]
    assert json_value != {}
    assert len(json_value["anyOf"]) == 9

    def inspect(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                inspect(item)
            return
        if not isinstance(node, dict):
            return
        assert node, "strict schema must not contain an unconstrained node"
        if node.get("type") == "object":
            properties = node.get("properties")
            assert isinstance(properties, dict)
            assert node.get("additionalProperties") is False
            assert set(node.get("required", [])) == set(properties)
        if "anyOf" in node:
            assert all(
                isinstance(branch, dict)
                and branch
                and ("type" in branch or "$ref" in branch)
                for branch in node["anyOf"]
            )
        for value in node.values():
            inspect(value)

    inspect(schema)


def test_provider_runner_stops_on_all_non_scientific_failures() -> None:
    for result_kind in ("api_error", "invalid_response", "timeout", "transport_error"):
        assert _provider_result_requires_run_stop(result_kind)
    for result_kind in ("completed", "incomplete", "refusal"):
        assert not _provider_result_requires_run_stop(result_kind)


def test_schedule_rebuild_is_deterministic_and_complete() -> None:
    plan = _plan()
    rebuilt, _ = build_portfolio_provider_schedule(
        root=ROOT, egress_blocked_case_ids=set(plan.egress_blocked_case_ids)
    )
    tracked = json.loads(SCHEDULE.read_text(encoding="utf-8"))["slots"]
    assert [item.model_dump(mode="json") for item in rebuilt] == tracked
    by_case_variant = Counter((item.case_id, item.variant) for item in rebuilt)
    assert all(count == 2 for count in by_case_variant.values())
    assert sum(variant == "clean" for _, variant in by_case_variant) == 64
    assert sum(variant == "control" for _, variant in by_case_variant) == 16
    assert sum(variant == "challenge" for _, variant in by_case_variant) == 16
    for slot in rebuilt:
        request, packet = build_portfolio_request(root=ROOT, slot=slot)
        assert request.semantic_sha256() == slot.request_semantic_sha256
        assert packet["packet_sha256"] == slot.input_binding_sha256
        assert request.schema_enforced == (
            slot.condition == "claim_evidence_constrained"
        )


def test_matched_retained_packets_differ_only_by_frozen_synthetic_context() -> None:
    corpus = DiverseCorpusV6.model_validate_json(CORPUS.read_text(encoding="utf-8"))
    retained = next(
        item for item in corpus.questions if item.review_status == "approved_v2"
    )
    packets = {
        variant: build_portfolio_candidate_packet(
            root=ROOT, case_id=retained.case_id, variant=variant
        )
        for variant in ("clean", "control", "challenge")
    }
    for packet in packets.values():
        assert packet["question"] == retained.question
        assert packet["case_id"] == retained.case_id
        assert packet["target_predicate"] == retained.predicate
        assert packet["supported_component_kinds"] == ["answer_value"]
    clean_aliases = {
        evidence["span_alias"]
        for document in packets["clean"]["documents"]
        if document["source_class"] != "synthetic"
        for evidence in document["evidence"]
    }
    for variant in ("control", "challenge"):
        assert clean_aliases <= {
            evidence["span_alias"]
            for document in packets[variant]["documents"]
            if document["source_class"] != "synthetic"
            for evidence in document["evidence"]
        }


def test_local_oracle_scores_a_complete_structured_response() -> None:
    corpus = DiverseCorpusV6.model_validate_json(CORPUS.read_text(encoding="utf-8"))
    question = next(item for item in corpus.questions if item.outcome_type != "abstain")
    schedule = [
        PortfolioProviderSlot.model_validate(item)
        for item in json.loads(SCHEDULE.read_text(encoding="utf-8"))["slots"]
    ]
    slot = next(
        item
        for item in schedule
        if item.case_id == question.case_id and item.variant == "clean"
    )
    alias_map = candidate_alias_map(root=ROOT, case_id=question.case_id)
    evidence_to_alias = {value: key for key, value in alias_map.items()}
    response = PortfolioProviderResponse(
        schema_version="portfolio-diverse-provider-response-v1",
        case_id=question.case_id,
        abstained=False,
        abstention_reason_code=None,
        components=[
            CandidateComponent(
                kind=item.kind,
                predicate=item.predicate,
                datatype=item.datatype,
                value=item.value,
                authority_scope=item.authority_scope,
                cited_span_aliases=[
                    evidence_to_alias[value] for value in item.required_evidence_ids
                ],
            )
            for item in question.expected_components
        ],
    )
    result = OpenAIResult(
        kind="completed",
        semantic_request_sha256=slot.request_semantic_sha256,
        http_status=200,
        provider_request_id_sha256="0" * 64,
        model="gpt-5.6-luna-2026-07-01",
        service_tier="default",
        output_text=response.model_dump_json(),
        refusal=None,
        incomplete_reason=None,
        input_tokens=100,
        cached_input_tokens=0,
        output_tokens=100,
        reasoning_tokens=10,
        error_code=None,
        raw_response_body=b"{}",
        selected_response_headers={},
    )
    scored = score_provider_result(
        root=ROOT,
        slot=slot,
        result=result,
        attempt_count=1,
        latency_ms=1,
        accounted_cost_usd=Decimal("0.001"),
    )
    assert scored.exact_outcome_correct
    assert scored.component_fp == scored.component_fn == 0
    assert scored.component_tp == len(question.expected_components)


def test_v6_grading_separates_provenance_from_canonical_value_wording() -> None:
    corpus = DiverseCorpusV6.model_validate_json(CORPUS.read_text(encoding="utf-8"))
    question = next(
        item
        for item in corpus.questions
        if item.outcome_type != "abstain"
        and len(item.expected_components) == 1
        and item.expected_components[0].datatype == "boolean"
    )
    alias_map = candidate_alias_map(root=ROOT, case_id=question.case_id)
    evidence_to_alias = {value: key for key, value in alias_map.items()}
    expected = question.expected_components[0]
    wrong_value = CandidateComponent(
        kind=expected.kind,
        predicate=expected.predicate,
        datatype=expected.datatype,
        value=not expected.value,
        authority_scope="Natural-language publisher description",
        cited_span_aliases=[
            evidence_to_alias[value] for value in expected.required_evidence_ids
        ],
    )
    assert grade_portfolio_diverse_provenance_outcome(
        question,
        components=[wrong_value],
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )
    assert not grade_portfolio_diverse_outcome(
        question,
        components=[wrong_value],
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )

    correct_value = wrong_value.model_copy(update={"value": expected.value})
    assert grade_portfolio_diverse_outcome(
        question,
        components=[correct_value],
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )


def test_unexpected_but_known_predicate_is_scored_wrong_instead_of_crashing() -> None:
    corpus = DiverseCorpusV6.model_validate_json(CORPUS.read_text(encoding="utf-8"))
    question = next(
        item
        for item in corpus.questions
        if item.outcome_type != "abstain" and len(item.expected_components) == 1
    )
    alias_map = candidate_alias_map(root=ROOT, case_id=question.case_id)
    evidence_to_alias = {value: key for key, value in alias_map.items()}
    expected = question.expected_components[0]
    candidate = CandidateComponent(
        kind=expected.kind,
        predicate="cve.cvss.score",
        datatype=expected.datatype,
        value=expected.value,
        authority_scope="Natural-language publisher description",
        cited_span_aliases=[
            evidence_to_alias[value] for value in expected.required_evidence_ids
        ],
    )
    assert not grade_portfolio_diverse_outcome(
        question,
        components=[candidate],
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )


def test_retired_restricted_sources_are_absent_from_active_provider_inputs() -> None:
    report = json.loads(EGRESS.read_text(encoding="utf-8"))
    assert report["status"] == "eligible"
    assert {
        item["source"].split()[0] for item in report["retired_source_decisions"]
    } == {
        "ECOVACS",
        "Güralp",
        "KUNBUS",
    }
    assert all(
        item["disposition"] == "retired_from_active_provider_inputs"
        for item in report["retired_source_decisions"]
    )
    assert report["blocked_case_ids"] == []
    assert set(report["active_replacement_basis"]["case_ids"]) == {
        "portfolio-diverse-abstain-08",
        "portfolio-diverse-authority-07-v4",
        "portfolio-diverse-authority-08",
        "portfolio-diverse-synthesis-06",
        "portfolio-diverse-synthesis-07",
    }
    corpus = DiverseCorpusV6.model_validate_json(CORPUS.read_text(encoding="utf-8"))
    by_case = {item.case_id: item for item in corpus.questions}
    for case_id in report["active_replacement_basis"]["case_ids"]:
        assert {item.source_name for item in by_case[case_id].evidence} == {"cisa_csaf"}


def test_central_policy_and_component_grader_cover_all_64_questions() -> None:
    corpus = DiverseCorpusV6.model_validate_json(CORPUS.read_text(encoding="utf-8"))
    index = PacketIndexV6.model_validate_json(INDEX.read_text(encoding="utf-8"))
    packets = {item.case_id: item for item in index.packets}
    for question in corpus.questions:
        validate_authority_policy_predicate(
            PORTFOLIO_DIVERSE_AUTHORITY_POLICY_VERSION, question.predicate
        )
        packet = packets[question.case_id]
        aliases = {
            item.evidence_id: item.span_alias
            for document in index.evaluator_bindings[packet.packet_id]
            for item in document.evidence
        }
        alias_map = {alias: evidence_id for evidence_id, alias in aliases.items()}
        components = (
            []
            if question.outcome_type == "abstain"
            else [
                CandidateComponent(
                    kind=item.kind,
                    predicate=item.predicate,
                    datatype=item.datatype,
                    value=item.value,
                    authority_scope=item.authority_scope,
                    cited_span_aliases=[
                        aliases[value] for value in item.required_evidence_ids
                    ],
                )
                for item in question.expected_components
            ]
        )
        assert grade_portfolio_diverse_outcome(
            question,
            components=components,
            abstained=question.outcome_type == "abstain",
            abstention_reason_code=question.abstention_reason_code,
            span_alias_to_evidence_id=alias_map,
        )
