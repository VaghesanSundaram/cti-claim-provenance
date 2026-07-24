from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.claims.real_slice import (
    load_phase2_real_cases,
    load_phase2_real_corpus,
)
from cti_provenance.experiments import provider_runner
from cti_provenance.experiments.provider_runner import (
    EXPECTED_CASE_IDS,
    ONTOLOGY_CONTRACT_CATALOG_SHA256,
    ProviderExperimentConfig,
    ProviderRunError,
    UserRunApproval,
    build_provider_request,
    build_provider_schedule,
    build_retrieval_packet,
    canary_request_manifest_sha256,
    load_provider_authorization_bundle,
    load_provider_experiment_config,
    load_provider_inputs,
    load_user_run_approval,
    ontology_contract_catalog_sha256,
    provider_config_path,
    provider_output_schema,
    validate_user_run_approval,
)

ROOT = Path(__file__).resolve().parents[2]
V1_CONFIG_PATH = ROOT / "configs/experiments/phase2-openai-luna-v1.yaml"
V2_CONFIG_PATH = ROOT / "configs/experiments/phase2-openai-luna.yaml"
REAL_CAPTURE_PATHS = (
    ROOT
    / "data/raw/nvd"
    / "ec21319bd69851e928c7eb34eded19bc049a71b092999f9d4930eba2f57c6db3.json",
    ROOT
    / "data/raw/cisa-kev"
    / "41d27023a5912a49ca2b06370550fa6da50e35794c269766a6332618d82f243e.json",
    ROOT
    / "data/raw/cisa-kev-lineage"
    / "a3a42da5e46e283ed0cc615e73b9e330cc518e9bcc8075dcb71bb626fdc8fc3a.json",
    ROOT
    / "data/raw/red-hat"
    / "da43faeafb5b8f5f0896572936959c3106f10c3ad13e66c34957a4f3e6c64f19.json",
    ROOT
    / "data/raw/red-hat-checksum"
    / "c6ed900b09a9bf71bf6d63b7049f537b0b461f91f4e621988f6fee692168b62e.sha256",
)
requires_real_capture = pytest.mark.skipif(
    not all(path.is_file() for path in REAL_CAPTURE_PATHS),
    reason="exact local real-source capture is intentionally gitignored",
)


def _config(version: str = "v2") -> ProviderExperimentConfig:
    path = V1_CONFIG_PATH if version == "v1" else V2_CONFIG_PATH
    return load_provider_experiment_config(path)


def test_checked_in_config_freezes_exact_provider_budget_and_schedule() -> None:
    config = _config()
    assert config.version == "phase2-openai-luna-v2"
    assert config.prompt_version == "phase2-real-cti-v2"
    assert config.provider == "openai"
    assert config.model == "gpt-5.6-luna"
    assert config.planned_slots == 108
    assert config.maximum_attempts == 216
    assert config.cost_cap_usd == Decimal("0.1824")
    assert config.pricing.retry_inclusive_upper_bound_usd == Decimal("0.1824")
    assert config.ontology_contract_sha256 == ONTOLOGY_CONTRACT_CATALOG_SHA256
    assert ontology_contract_catalog_sha256() == ONTOLOGY_CONTRACT_CATALOG_SHA256
    assert config.sha256() == _config().sha256()


def test_v1_config_remains_frozen_and_separately_selectable() -> None:
    config = _config("v1")
    assert config.version == "phase2-openai-luna-v1"
    assert config.prompt_version == "phase2-real-cti-v1"
    assert (
        config.sha256()
        == "08917a676d0e69b8d7d4cfdd34fbde8ee28aec185638439b6d53ffaa3f4e48e9"
    )
    approval = UserRunApproval(
        approval_id="user-authorized-phase2-luna-20260719t173615z",
        approved_at_utc=datetime(2026, 7, 19, 17, 36, 15, tzinfo=UTC),
        provider="openai",
        model="gpt-5.6-luna",
        api="responses",
        service_tier="default",
        reasoning_effort="medium",
        tools=(),
        live_search=False,
        case_ids=config.case_ids,
        conditions=config.conditions,
        repeats=3,
        planned_slots=108,
        maximum_attempts=216,
        input_token_ceiling=864000,
        output_token_ceiling=129600,
        cost_cap_usd=Decimal("2.00"),
        canary_slots=12,
        config_sha256=config.sha256(),
    )
    assert (
        approval.sha256()
        == "e3549b006d5a10ab80e604c7976594ccec703ec55e513483be8f338ff8244b62"
    )


def test_config_rejects_model_cap_schedule_and_remote_state_drift() -> None:
    source = _config().model_dump(mode="python")
    for key, value in (
        ("model", "another-model"),
        ("cost_cap_usd", "5"),
        ("planned_slots", 107),
        ("conversation_state", True),
        ("max_output_tokens", 601),
    ):
        mutated = copy.deepcopy(source)
        mutated[key] = value
        with pytest.raises(ValidationError):
            ProviderExperimentConfig.model_validate(mutated)
    for version, prompt_version in (
        ("phase2-openai-luna-v1", "phase2-real-cti-v2"),
        ("phase2-openai-luna-v2", "phase2-real-cti-v1"),
    ):
        mutated = copy.deepcopy(source)
        mutated["version"] = version
        mutated["prompt_version"] = prompt_version
        with pytest.raises(ValidationError, match="versions are incoherent"):
            ProviderExperimentConfig.model_validate(mutated)
    mutated = copy.deepcopy(source)
    mutated["ontology_contract_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="ontology contract hash"):
        ProviderExperimentConfig.model_validate(mutated)


def test_provider_config_selector_fails_closed() -> None:
    assert provider_config_path("v1") == Path(
        "configs/experiments/phase2-openai-luna-v1.yaml"
    )
    assert provider_config_path("v2") == Path(
        "configs/experiments/phase2-openai-luna.yaml"
    )
    with pytest.raises(ProviderRunError, match="unsupported provider config"):
        provider_config_path("typo")  # type: ignore[arg-type]


def test_exported_provider_schemas_encode_versioned_identity_and_scope_pairs() -> None:
    config_schema = ProviderExperimentConfig.model_json_schema()
    config_pairs = config_schema["oneOf"]
    assert config_pairs[0]["properties"]["version"]["const"].endswith("-v1")
    assert config_pairs[0]["properties"]["prompt_version"]["const"].endswith("-v1")
    assert config_pairs[1]["properties"]["version"]["const"].endswith("-v2")
    assert config_pairs[1]["properties"]["prompt_version"]["const"].endswith("-v2")
    assert (
        config_pairs[1]["properties"]["ontology_contract_sha256"]["const"]
        == ONTOLOGY_CONTRACT_CATALOG_SHA256
    )
    approval_pairs = UserRunApproval.model_json_schema()["oneOf"]
    assert approval_pairs[0]["properties"]["planned_slots"]["const"] == 108
    assert approval_pairs[0]["properties"]["maximum_attempts"]["const"] == 216
    assert approval_pairs[1]["properties"]["planned_slots"]["const"] == 12
    assert approval_pairs[1]["properties"]["maximum_attempts"]["const"] == 24
    assert "request_manifest_sha256" in approval_pairs[1]["required"]
    assert "canary_blocks" in approval_pairs[1]["required"]
    assert approval_pairs[0]["properties"]["repeats"]["const"] == 3
    assert approval_pairs[1]["properties"]["repeats"]["const"] == 1


def test_authorization_bundle_truthfully_covers_public_and_synthetic_states() -> None:
    config = _config()
    bundle = load_provider_authorization_bundle(ROOT, config)
    by_kind = {manifest.target_kind: manifest for manifest in bundle.manifests}
    assert set(by_kind["frozen_public_document"].target_ids) == {
        "nvd-ec21319bd698",
        "kev-41d27023a591",
        "rhsa-da43faeafb5b",
    }
    assert by_kind["synthetic_fixture"].target_ids == (
        "phase2-fixture-contradiction-v1",
    )
    assert len(bundle.bundle_sha256) == 64


def test_schedule_has_108_unique_slots_and_complete_contiguous_triplets() -> None:
    schedule = build_provider_schedule(_config())
    assert len(schedule) == 108
    assert len({slot.slot_id for slot in schedule}) == 108
    assert [slot.ordinal for slot in schedule] == list(range(108))
    assert Counter(slot.condition for slot in schedule) == {
        "lexical_direct_answer": 36,
        "lexical_citation_prompted": 36,
        "lexical_claim_evidence_constrained": 36,
    }
    by_case: dict[str, Counter[int]] = defaultdict(Counter)
    for slot in schedule:
        by_case[slot.case_id][slot.repeat_index] += 1
    assert set(by_case) == set(EXPECTED_CASE_IDS)
    assert all(counts == Counter({0: 3, 1: 3, 2: 3}) for counts in by_case.values())
    for start in range(0, 108, 3):
        triplet = schedule[start : start + 3]
        assert len({(slot.case_id, slot.repeat_index) for slot in triplet}) == 1
        assert {slot.condition for slot in triplet} == {
            "lexical_direct_answer",
            "lexical_citation_prompted",
            "lexical_claim_evidence_constrained",
        }


def test_canary_is_four_frozen_triplets_with_required_case_coverage() -> None:
    canary = build_provider_schedule(_config())[:12]
    assert all(slot.canary for slot in canary)
    blocks = [
        (canary[index].case_id, canary[index].repeat_index) for index in range(0, 12, 3)
    ]
    assert blocks == [
        ("real-nvd-cvss-combined-treatment", 0),
        ("real-kev-preavailability", 1),
        ("real-red-hat-affected-insufficient", 2),
        ("real-red-hat-fixed-id", 0),
    ]


def test_provider_schemas_have_only_the_preregistered_constraint_delta() -> None:
    direct = provider_output_schema("lexical_direct_answer")
    citation = provider_output_schema("lexical_citation_prompted")
    constrained = provider_output_schema("lexical_claim_evidence_constrained")
    assert direct == citation
    expected = copy.deepcopy(direct)
    evidence = expected["properties"]["claims"]["items"]["properties"]["evidence_ids"]
    evidence["minItems"] = 1
    assert constrained == expected
    for schema in (direct, constrained):
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
        serialized = json.dumps(schema, sort_keys=True)
        assert "$ref" not in serialized
        assert 'additionalProperties": true' not in serialized

        def check_objects(node: object) -> None:
            if isinstance(node, list):
                for item in node:
                    check_objects(item)
                return
            if not isinstance(node, dict):
                return
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
                assert set(node["required"]) == set(node["properties"])
            for value in node.values():
                check_objects(value)

        check_objects(schema)


@requires_real_capture
def test_v2_request_exposes_generic_ontology_contract_without_gold() -> None:
    config, _authorization, schedule, packets = load_provider_inputs(
        ROOT,
        config_version="v2",
    )
    contracts: dict[str, dict[str, object]] = {}
    for slot in schedule:
        if slot.case_id in contracts:
            continue
        packet = packets[slot.case_id]
        plan = build_provider_request(slot, packet, config)
        prompt = json.loads(plan.body["input"][1]["content"])
        contract = prompt["ontology_contract"]
        contracts[slot.case_id] = contract
        serialized = json.dumps(contract, sort_keys=True)
        assert set(contract) == {
            "subject",
            "predicate",
            "object",
            "qualifiers",
        }
        assert set(contract["subject"]) == {"type", "id_rule"}
        assert set(contract["object"]) == {"datatype", "value_rule"}
        assert set(contract["qualifiers"]) == {
            "authority",
            "cvss_version",
            "product",
            "ecosystem",
        }
        assert "expected_claims" not in serialized
        assert "should_abstain" not in serialized
        assert "abstention_reason" not in serialized
        assert '"object_value"' not in serialized
        assert all(
            evidence.evidence_id not in serialized
            for evidence in packet.ordered_evidence
        )
        assert contract["subject"]["id_rule"] == (
            "copy exact CVE/RHSA from question/evidence text; evidence_id is opaque"
        )

    cvss = contracts["real-nvd-cvss-combined-treatment"]
    assert cvss["subject"]["type"] == "cve"
    assert cvss["predicate"] == "cve.cvss.score"
    assert cvss["object"]["datatype"] == "decimal"
    assert cvss["qualifiers"] == {
        "authority": "nvd@nist.gov",
        "cvss_version": "3.1",
        "product": None,
        "ecosystem": None,
    }
    red_hat = contracts["real-red-hat-fixed-id"]
    assert red_hat["subject"]["type"] == "advisory"
    assert red_hat["predicate"] == "vendor.fixed_versions"
    assert red_hat["object"]["datatype"] == "version_set"
    assert red_hat["qualifiers"]["authority"] == "red_hat_rhsa"
    assert red_hat["qualifiers"]["product"] == {"output_rule": "copy array item"}
    assert "Red Hat AMQ Streams 1.6.5" not in json.dumps(red_hat, sort_keys=True)
    for case_id, public_subject_id in (
        ("real-nvd-cvss-combined-treatment", "CVE-2021-44228"),
        ("real-red-hat-fixed-id", "RHSA-2021:5133"),
    ):
        packet = packets[case_id]
        assert public_subject_id in packet.question or any(
            public_subject_id in evidence.text for evidence in packet.ordered_evidence
        )
        assert public_subject_id not in json.dumps(contracts[case_id], sort_keys=True)


def test_ontology_catalog_hash_binds_template_family_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_payload = _config().model_dump(mode="python")
    original = provider_runner._ONTOLOGY_TEMPLATES
    renamed = (("renamed-family", original[0][1]), *original[1:])
    monkeypatch.setattr(provider_runner, "_ONTOLOGY_TEMPLATES", renamed)
    assert ontology_contract_catalog_sha256() != ONTOLOGY_CONTRACT_CATALOG_SHA256
    with pytest.raises(ValidationError, match="ontology contract code"):
        ProviderExperimentConfig.model_validate(config_payload)


@requires_real_capture
def test_v2_retrieval_packet_is_independent_of_gold_and_abstention_fields() -> None:
    states, documents = load_phase2_real_corpus(ROOT)
    case = next(
        item
        for item in load_phase2_real_cases(
            ROOT,
            states=states,
            documents=documents,
        )
        if item.case_id == "real-red-hat-fixed-id"
    )
    baseline = build_retrieval_packet(
        case,
        states=states,
        documents=documents,
        prompt_version="phase2-real-cti-v2",
    )
    mutated = case.model_copy(
        update={
            "expected_claims": [],
            "should_abstain": True,
            "abstention_reason": "grader-owned mutation",
        }
    )
    assert (
        build_retrieval_packet(
            mutated,
            states=states,
            documents=documents,
            prompt_version="phase2-real-cti-v2",
        )
        == baseline
    )


@requires_real_capture
def test_v1_request_hashes_and_prompt_remain_frozen() -> None:
    config, _authorization, schedule, packets = load_provider_inputs(
        ROOT,
        config_version="v1",
    )
    plans = [
        build_provider_request(slot, packets[slot.case_id], config)
        for slot in schedule[:3]
    ]
    assert [plan.prompt_sha256 for plan in plans] == [
        "4b3b513fa6c4cb5255193f930f47fccc98ceb5c9aac7e6ecc42a6f4ed5386175",
        "2f72d072116e8d093acfac220e1c86438e6e09aa34413f6642dd6528d5a7cdb6",
        "71f0ec4d1d610cc9722ce322322506411db6f70f09f13c3038ef8be30f659ae5",
    ]
    assert [plan.semantic_request_sha256 for plan in plans] == [
        "4c388c0ffeda6fea5acae3321a3705d0483fee37d52bc5c069e7fa29a8b5ddef",
        "adc67413163add80c9d5ea3d1360d80bde6821fa0a9ac4e9593689b70898791d",
        "f204cbd2e6a440b86dc1b915537989a3d514e73bb0a133f36f856d2a62e7eb94",
    ]
    for plan in plans:
        prompt = json.loads(plan.body["input"][1]["content"])
        assert "ontology_contract" not in prompt


@requires_real_capture
def test_offline_input_replay_builds_condition_invariant_triplets_without_gold() -> (
    None
):
    config, _authorization, schedule, packets = load_provider_inputs(ROOT)
    assert set(packets) == set(EXPECTED_CASE_IDS)
    assert all(
        "description" not in item.evidence_id
        for packet in packets.values()
        for item in packet.ordered_evidence
    )
    first_triplet = schedule[:3]
    plans = [
        build_provider_request(slot, packets[slot.case_id], config)
        for slot in first_triplet
    ]
    assert len({plan.retrieval_packet_sha256 for plan in plans}) == 1
    assert len({plan.invariant_sha256 for plan in plans}) == 1
    direct = next(
        plan for plan in plans if plan.slot.condition == "lexical_direct_answer"
    )
    citation = next(
        plan for plan in plans if plan.slot.condition == "lexical_citation_prompted"
    )
    assert direct.schema_sha256 == citation.schema_sha256
    serialized = json.dumps(
        [plan.body["input"] for plan in plans],
        sort_keys=True,
    )
    assert "expected_claims" not in serialized
    assert "should_abstain" not in serialized
    assert "abstention_reason" not in serialized
    assert "raw_locator" not in serialized
    assert "https://" not in serialized
    assert "arbitrary code" not in serialized


@requires_real_capture
def test_every_frozen_request_fits_byte_ceiling_and_preserves_triplet_invariant() -> (
    None
):
    config, _authorization, schedule, packets = load_provider_inputs(ROOT)
    plans = [
        build_provider_request(slot, packets[slot.case_id], config) for slot in schedule
    ]
    assert len(plans) == 108
    for plan in plans:
        body = json.dumps(
            plan.body,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        assert len(body) <= config.input_token_reservation
    for start in range(0, 108, 3):
        triplet = plans[start : start + 3]
        assert len({plan.invariant_sha256 for plan in triplet}) == 1
        assert len({plan.retrieval_packet_sha256 for plan in triplet}) == 1


@requires_real_capture
def test_condition_requests_differ_only_by_registered_identity_and_treatment() -> None:
    config, _authorization, schedule, packets = load_provider_inputs(ROOT)
    triplet = [
        build_provider_request(slot, packets[slot.case_id], config)
        for slot in schedule[:3]
    ]
    normalized: list[dict[str, object]] = []
    for plan in triplet:
        body = copy.deepcopy(plan.body)
        prompt = json.loads(body["input"][1]["content"])
        prompt["run_id"] = "[SLOT]"
        prompt["condition_instruction"] = "[TREATMENT]"
        body["input"][1]["content"] = json.dumps(
            prompt,
            sort_keys=True,
            separators=(",", ":"),
        )
        format_config = body["text"]["format"]
        format_config["name"] = "[SCHEMA]"
        format_config["schema"] = "[TREATMENT]"
        normalized.append(body)
    assert normalized[0] == normalized[1] == normalized[2]


@pytest.mark.parametrize(
    "marker",
    [
        "https://live-target.example/path",
        "192.0.2.10",
        "sk-" + "x" * 24,
        "-----BEGIN " + "PRIVATE KEY-----",
    ],
)
@requires_real_capture
def test_outbound_live_target_and_credential_markers_fail_locally(
    marker: str,
) -> None:
    states, documents = load_phase2_real_corpus(ROOT)
    case = load_phase2_real_cases(
        ROOT,
        states=states,
        documents=documents,
    )[0]
    mutated = case.model_copy(update={"question": f"{case.question} {marker}"})
    with pytest.raises(ProviderRunError, match="prohibited outbound"):
        build_retrieval_packet(
            mutated,
            states=states,
            documents=documents,
        )


def test_manifest_substitution_fails_before_any_transport(tmp_path: Path) -> None:
    config = _config()
    mutated = config.model_dump(mode="python")
    mutated["authorization_manifests"] = [
        "configs/experiments/phase2-plumbing-authorization.yaml",
        "configs/experiments/phase2-treatment-openai-authorization.yaml",
    ]
    with pytest.raises(ValidationError):
        ProviderExperimentConfig.model_validate(mutated)


def test_duplicate_provider_yaml_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("version: one\nversion: two\n", encoding="utf-8")
    with pytest.raises(ProviderRunError, match="invalid provider experiment YAML"):
        load_provider_experiment_config(path)


@requires_real_capture
def test_user_approval_must_bind_every_frozen_paid_run_dimension() -> None:
    config, _authorization, schedule, packets = load_provider_inputs(
        ROOT,
        config_version="v2",
    )
    request_manifest_hash = canary_request_manifest_sha256(
        config,
        schedule,
        packets,
    )
    approval = UserRunApproval(
        approval_id="user-approved-phase2-luna-v2",
        approved_at_utc=datetime(2026, 7, 19, 7, tzinfo=UTC),
        provider="openai",
        model="gpt-5.6-luna",
        api="responses",
        service_tier="default",
        reasoning_effort="medium",
        tools=(),
        live_search=False,
        case_ids=tuple(block.case_id for block in config.canary_blocks),
        conditions=config.conditions,
        repeats=1,
        planned_slots=12,
        maximum_attempts=24,
        input_token_ceiling=96000,
        output_token_ceiling=14400,
        cost_cap_usd=Decimal("0.1824"),
        canary_slots=12,
        config_sha256=config.sha256(),
        request_manifest_sha256=request_manifest_hash,
        canary_blocks=config.canary_blocks,
    )
    validate_user_run_approval(
        approval,
        config,
        request_manifest_sha256=request_manifest_hash,
    )
    wrong = approval.model_copy(update={"cost_cap_usd": Decimal("0.1825")})
    with pytest.raises(ProviderRunError, match="does not exactly bind"):
        validate_user_run_approval(
            wrong,
            config,
            request_manifest_sha256=request_manifest_hash,
        )
    with pytest.raises(ProviderRunError, match="exact request manifest"):
        validate_user_run_approval(approval, config)
    plans = [
        build_provider_request(slot, packets[slot.case_id], config)
        for slot in schedule[:12]
    ]
    reordered_hashes = [plan.semantic_request_sha256 for plan in plans]
    reordered_hashes[0], reordered_hashes[1] = (
        reordered_hashes[1],
        reordered_hashes[0],
    )
    reordered_manifest_hash = hashlib.sha256(
        json.dumps(
            reordered_hashes,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert reordered_manifest_hash != request_manifest_hash
    with pytest.raises(ProviderRunError, match="does not exactly bind"):
        validate_user_run_approval(
            approval,
            config,
            request_manifest_sha256=reordered_manifest_hash,
        )


def test_user_approval_json_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "approval.json"
    path.write_text(
        '{"approval_id":"one","approval_id":"two"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ProviderRunError, match="invalid provider run approval JSON"):
        load_user_run_approval(path)
