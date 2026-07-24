"""Freeze the V6 Luna schedule, cost, and conservative provider-egress gate."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic_core import to_jsonable_python

from cti_provenance.claims.diverse_portfolio_v4 import canonical_sha256
from cti_provenance.claims.diverse_portfolio_v6 import ReviewPacketV6
from cti_provenance.experiments.portfolio_diverse_execution import (
    PortfolioProviderResult,
)
from cti_provenance.experiments.portfolio_diverse_provider import (
    PortfolioProviderPlan,
    build_portfolio_provider_schedule,
    portfolio_provider_response_schema,
)
from cti_provenance.grading.diverse_review import validate_diverse_review_log
from cti_provenance.grading.review_workflow import ReviewDecision, load_jsonl_records

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data/benchmark/portfolio-diverse-draft-v6.json"
INDEX = ROOT / "data/benchmark/portfolio-diverse-packets-v6.json"
DECISIONS = (
    ROOT / "annotations/decisions/portfolio-diverse-review-v5-reviewer-a17.jsonl"
)
LINEAGE = ROOT / "data/benchmark/portfolio-diverse-v5-to-v6.json"
AUTHORITY = ROOT / "configs/authority-policy-portfolio-diverse-v6.yaml"
EGRESS_JSON = ROOT / "reports/portfolio-provider-egress-v1.json"
EGRESS_MD = ROOT / "reports/portfolio-provider-egress-v1.md"
SCHEDULE_OUT = ROOT / "data/benchmark/portfolio-diverse-provider-schedule-v1.json"
PLAN_OUT = ROOT / "configs/experiments/portfolio-diverse-v6-openai-luna.json"
REPORT_MD = ROOT / "reports/portfolio-diverse-provider-preflight-v1.md"
RESPONSE_SCHEMA = ROOT / "schemas/portfolio-diverse-provider-response-v1.schema.json"
RESULT_SCHEMA = ROOT / "schemas/portfolio-diverse-provider-result-v1.schema.json"
REPLACEMENT_REVIEW = (
    ROOT / "annotations/packets/portfolio-diverse-egress-replacements-review-v6.json"
)
REPLACEMENT_DECISIONS = (
    ROOT / "annotations/decisions/"
    "portfolio-diverse-egress-replacements-review-v6-reviewer-a17.jsonl"
)
REPLACEMENT_APPROVAL = (
    ROOT / "annotations/decisions/"
    "portfolio-diverse-egress-replacements-review-v6-user-approval.json"
)
CREATED_AT = datetime(2026, 7, 24, 18, 14, tzinfo=UTC)

BLOCKED_CASE_IDS: set[str] = set()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    path.write_text(
        json.dumps(
            to_jsonable_python(value),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _egress_report() -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "portfolio-provider-egress-v1",
        "status": "eligible",
        "assessed_at_utc": CREATED_AT,
        "decision_standard": (
            "Fail closed when official source terms do not affirmatively support "
            "transmitting the retained evidence to a third-party provider. This is "
            "a conservative project policy decision, not legal advice."
        ),
        "provider_data_controls": {
            "provider": "OpenAI API",
            "request_controls": {
                "store": False,
                "tools": [],
                "search": False,
                "connectors": False,
            },
            "training_default": (
                "API inputs and outputs are not used for training unless the "
                "organization explicitly opts in."
            ),
            "retention_boundary": (
                "Default API abuse-monitoring logs may contain prompts and "
                "responses and may be retained for up to 30 days; store=false is "
                "not Zero Data Retention."
            ),
            "official_sources": [
                "https://developers.openai.com/api/docs/guides/your-data#default-usage-policies-by-endpoint",
                "https://openai.com/policies/how-your-data-is-used-to-improve-model-performance/",
            ],
        },
        "retired_source_decisions": [
            {
                "source": "ECOVACS DSA-20250509001",
                "source_sha256": (
                    "ead2b5335c31f213c95213d73dba5c2de13ba7da5bcf85472f614181d0308d79"
                ),
                "source_url": "https://www.ecovacs.com/global/userhelp/dsa20250509001",
                "terms_url": "https://www.ecovacs.com/us/terms-of-use",
                "disposition": "retired_from_active_provider_inputs",
                "reason": (
                    "The official terms limit downloads to personal use and "
                    "prohibit copying, transmitting, publishing, or otherwise "
                    "exploiting website content without express permission."
                ),
                "affected_case_ids": [
                    "portfolio-diverse-authority-08",
                    "portfolio-diverse-synthesis-06",
                ],
            },
            {
                "source": "Güralp firmware and software page",
                "source_sha256": (
                    "bc726b772018be052454bda1c285ebcfdd7d85b98bc8c4fa4845b3e68c0d7dac"
                ),
                "source_url": (
                    "https://www.guralp.com/customer-support/firmware-and-software"
                ),
                "terms_url": "https://www.guralp.com/privacy-notice",
                "disposition": "retired_from_active_provider_inputs",
                "reason": (
                    "The official site asserts all rights reserved and no "
                    "source-specific license authorizing third-party provider "
                    "transmission was found. The packet contains a project-derived "
                    "absence assertion, but the project does not infer permission "
                    "from that transformation."
                ),
                "affected_case_ids": ["portfolio-diverse-abstain-08"],
            },
            {
                "source": "KUNBUS remediation options for KUNBUS-2025-0000002",
                "source_sha256": (
                    "eb2d1c0f97e1f6391a4345b55bb5761a5785dc99347f9cb74d03225cc944f71b"
                ),
                "source_url": (
                    "https://www.kunbus.com/files/media/misc/"
                    "kunbus-2025-0000002-remediation.pdf"
                ),
                "terms_url": "https://www.kunbus.com/en/agb",
                "disposition": "retired_from_active_provider_inputs",
                "reason": (
                    "No permission authorizing third-party provider transmission "
                    "was found; KUNBUS manuals state that reproduction or use is "
                    "limited to internal use and other use needs express written "
                    "consent."
                ),
                "affected_case_ids": [
                    "portfolio-diverse-authority-07-v4",
                    "portfolio-diverse-synthesis-07",
                ],
            },
        ],
        "active_replacement_basis": {
            "publisher": "CISA",
            "source_class": "US government CSAF coordinator records",
            "provider_egress_disposition": "eligible",
            "case_ids": [
                "portfolio-diverse-abstain-08",
                "portfolio-diverse-authority-07-v4",
                "portfolio-diverse-authority-08",
                "portfolio-diverse-synthesis-06",
                "portfolio-diverse-synthesis-07",
            ],
            "boundary": (
                "Only bounded exact CISA spans enter the candidate packets. "
                "Vendor website/PDF text is absent from all active replacements."
            ),
        },
        "blocked_case_ids": [],
        "resolution": (
            "Provider egress is eligible for all active evidence. The five "
            "replacement labels are explicitly user-approved and hash-bound."
        ),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def _render_egress(report: dict[str, Any]) -> str:
    rows = "\n".join(
        f"- {item['source']}: `{item['disposition']}` — {item['reason']}"
        for item in report["retired_source_decisions"]
    )
    return (
        "# Portfolio provider-egress disposition v1\n\n"
        f"- Status: `{report['status']}`\n"
        "- Egress-blocked semantic questions: 0/64\n"
        "- This is a conservative project-policy decision, not legal advice.\n\n"
        f"{rows}\n\n"
        "OpenAI API data is not used for training by default, but default abuse-"
        "monitoring logs may retain prompt/response content for up to 30 days. "
        "`store=false` is not Zero Data Retention. All active evidence is "
        "egress-eligible and the five-item human-review decision is complete.\n"
    )


def main() -> int:
    if datetime.now(UTC) < CREATED_AT:
        raise ValueError("provider preflight build predates its declared timestamp")
    response_schema = portfolio_provider_response_schema()
    review_packet = ReviewPacketV6.model_validate_json(
        REPLACEMENT_REVIEW.read_text(encoding="utf-8")
    )
    review_decisions = load_jsonl_records(REPLACEMENT_DECISIONS, ReviewDecision)
    active, unresolved = validate_diverse_review_log(review_packet, review_decisions)
    approval = json.loads(REPLACEMENT_APPROVAL.read_text(encoding="utf-8"))
    if (
        active != 5
        or unresolved
        or approval["status"] != "human_approved"
        or approval["packet_sha256"] != review_packet.packet_sha256
        or approval["decision_log_file_sha256"] != _file_sha(REPLACEMENT_DECISIONS)
    ):
        raise ValueError("replacement human-review approval is incomplete")
    _write_json(RESPONSE_SCHEMA, response_schema)
    _write_json(
        RESULT_SCHEMA,
        PortfolioProviderResult.model_json_schema(mode="serialization"),
    )
    egress = _egress_report()
    _write_json(EGRESS_JSON, egress)
    EGRESS_MD.write_text(_render_egress(egress), encoding="utf-8")
    schedule, inputs = build_portfolio_provider_schedule(
        root=ROOT, egress_blocked_case_ids=BLOCKED_CASE_IDS
    )
    schedule_payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-provider-schedule-v1",
        "created_at_utc": CREATED_AT,
        "slots": schedule,
    }
    schedule_payload["schedule_sha256"] = canonical_sha256(schedule_payload)
    _write_json(SCHEDULE_OUT, schedule_payload)

    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    lineage = json.loads(LINEAGE.read_text(encoding="utf-8"))
    blocked_calls = sum(not item.egress_eligible for item in schedule)
    plan_payload: dict[str, Any] = {
        "schema_version": "portfolio-diverse-provider-plan-v1",
        "status": "ready_for_execution",
        "created_at_utc": CREATED_AT,
        "corpus_path": CORPUS.relative_to(ROOT).as_posix(),
        "corpus_sha256": corpus["corpus_sha256"],
        "packet_index_path": INDEX.relative_to(ROOT).as_posix(),
        "packet_index_sha256": index["index_sha256"],
        "review_log_path": DECISIONS.relative_to(ROOT).as_posix(),
        "review_log_file_sha256": _file_sha(DECISIONS),
        "lineage_path": LINEAGE.relative_to(ROOT).as_posix(),
        "lineage_sha256": lineage["lineage_sha256"],
        "replacement_review_packet_path": REPLACEMENT_REVIEW.relative_to(
            ROOT
        ).as_posix(),
        "replacement_review_packet_sha256": json.loads(
            REPLACEMENT_REVIEW.read_text(encoding="utf-8")
        )["packet_sha256"],
        "replacement_review_decision_log_path": REPLACEMENT_DECISIONS.relative_to(
            ROOT
        ).as_posix(),
        "replacement_review_decision_log_file_sha256": _file_sha(REPLACEMENT_DECISIONS),
        "replacement_user_approval_path": REPLACEMENT_APPROVAL.relative_to(
            ROOT
        ).as_posix(),
        "replacement_user_approval_sha256": approval["approval_sha256"],
        "authority_policy_version": "authority-policy-portfolio-diverse-v6",
        "provider": "openai",
        "model_route": "gpt-5.6-luna",
        "returned_model_policy": "record_exact_no_fallback",
        "api": "responses",
        "endpoint": "https://api.openai.com/v1/responses",
        "service_tier": "default",
        "reasoning_effort": "medium",
        "store": False,
        "background": False,
        "tools": [],
        "live_search": False,
        "conditions": [
            "citation_prompted",
            "claim_evidence_constrained",
        ],
        "comparison_scope": (
            "bundled_pipeline_variants_prompt_plus_api_schema_enforcement"
        ),
        "causal_attribution": "not_estimated",
        "primary_metric": "provenance_outcome_correct",
        "secondary_metric": "canonical_typed_value_exact",
        "authority_scope_treatment": (
            "descriptive_unscored_authority_from_predicate_and_citations"
        ),
        "repeats": 1,
        "schedule_seed": 20260724,
        "unique_question_count": 64,
        "clean_question_count": 64,
        "challenge_subset_question_count": 16,
        "planned_calls": 192,
        "max_transient_retries": 2,
        "maximum_attempts": 576,
        "transient_retry_backoff_seconds": [2, 8],
        "input_token_reservation": 32000,
        "max_output_tokens": 2000,
        "cost_cap_usd": "30.00",
        "input_per_million_usd": "1.00",
        "cache_write_multiplier": "1.25",
        "output_per_million_usd": "6.00",
        "retry_inclusive_upper_bound_usd": "29.952",
        "pricing_accessed_at_utc": "2026-07-24T18:00:00Z",
        "pricing_source_url": "https://developers.openai.com/api/docs/models/gpt-5.6-luna",
        "data_controls_source_url": "https://developers.openai.com/api/docs/guides/your-data#default-usage-policies-by-endpoint",
        "egress_disposition_path": EGRESS_JSON.relative_to(ROOT).as_posix(),
        "egress_blocked_case_ids": sorted(BLOCKED_CASE_IDS),
        "egress_blocked_call_count": blocked_calls,
        "schedule_sha256": schedule_payload["schedule_sha256"],
    }
    semantic_inputs = {
        **plan_payload,
        "authority_policy_file_sha256": _file_sha(AUTHORITY),
        "response_schema_sha256": inputs["response_schema_sha256"],
        "prompt_hashes": inputs["prompt_hashes"],
        "challenge_artifacts": inputs["challenge_artifacts"],
        "egress_report_sha256": egress["report_sha256"],
    }
    plan_payload["semantic_digest"] = canonical_sha256(semantic_inputs)
    plan = PortfolioProviderPlan.model_validate_json(
        json.dumps(to_jsonable_python(plan_payload), ensure_ascii=False)
    )
    _write_json(PLAN_OUT, plan)
    variant_counts = Counter(item.variant for item in schedule)
    condition_counts = Counter(item.condition for item in schedule)
    REPORT_MD.write_text(
        "# Diverse portfolio provider preflight v1\n\n"
        f"- Status: `{plan.status}`\n"
        f"- Model route: `{plan.model_route}`; no fallback\n"
        f"- Unique semantic questions: {plan.unique_question_count}\n"
        f"- Scheduled cells: {plan.planned_calls} "
        f"({dict(sorted(variant_counts.items()))}; "
        f"{dict(sorted(condition_counts.items()))})\n"
        "- Comparison scope: bundled pipeline variants (prompt plus API schema "
        "enforcement); no isolated schema-enforcement causal effect is estimated.\n"
        "- Primary metric: exact predicate/component-role/evidence provenance or "
        "correct abstention. Secondary metric: canonical typed-value exactness. "
        "Natural-language authority wording is descriptive; predicate and exact "
        "evidence bindings enforce authority.\n"
        f"- Maximum attempts: {plan.maximum_attempts}\n"
        f"- Retry-inclusive reservation: `${plan.retry_inclusive_upper_bound_usd}` "
        f"of `${plan.cost_cap_usd}`\n"
        f"- Egress-blocked questions: {len(plan.egress_blocked_case_ids)}/64 "
        f"({plan.egress_blocked_call_count} scheduled cells)\n"
        f"- Schedule SHA-256: `{plan.schedule_sha256}`\n"
        f"- Semantic digest: `{plan.semantic_digest}`\n\n"
        "All active evidence is egress-eligible and all 64 labels are human-"
        "approved. This frozen descriptor is ready for the exact authorized run; "
        "it does not authorize any expanded scope, fallback model, or publication.\n",
        encoding="utf-8",
    )
    print(
        f"{PLAN_OUT.relative_to(ROOT)} {plan.semantic_digest} "
        f"{plan.planned_calls} calls ${plan.retry_inclusive_upper_bound_usd}"
    )
    print(
        f"{SCHEDULE_OUT.relative_to(ROOT)} {plan.schedule_sha256} "
        f"{blocked_calls} blocked cells"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
