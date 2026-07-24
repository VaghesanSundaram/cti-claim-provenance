from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from cti_provenance.config import AppConfig
from cti_provenance.experiments import provider_execution
from cti_provenance.experiments.provider_execution import (
    ProviderExecutionResult,
    replay_provider_results,
    run_provider_canary,
)
from cti_provenance.experiments.provider_ledger import (
    AttemptReservation,
    AttemptTerminal,
    CostReconciliation,
    SafetyEvent,
    canonical_json,
    load_jsonl_records,
)
from cti_provenance.experiments.provider_runner import (
    ProviderRunError,
    UserRunApproval,
    canary_request_manifest_sha256,
    load_provider_inputs,
)
from cti_provenance.experiments.real_runner import run_real_offline_slice
from cti_provenance.models.openai_client import (
    OpenAIHttpRequest,
    OpenAIHttpResponse,
    OpenAIResponsesAdapter,
    OpenAITransport,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 19, 6, 0, tzinfo=UTC)
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


def _fake_transport() -> tuple[OpenAITransport, list[OpenAIHttpRequest]]:
    oracle = {
        result.case.case_id: result.answer.model_dump(mode="json")
        for result in run_real_offline_slice(ROOT)
    }
    seen: list[OpenAIHttpRequest] = []

    def transport(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        assert timeout_seconds == 60
        seen.append(request)
        body = json.loads(request.body)
        prompt = json.loads(body["input"][1]["content"])
        answer = dict(oracle[prompt["case_id"]])
        answer["run_id"] = prompt["run_id"]
        answer["answer_id"] = f"answer-{prompt['run_id']}"
        for claim in answer["claims"]:
            if claim["object"]["datatype"] == "decimal":
                claim["object"]["value"] = float(claim["object"]["value"])
        response = {
            "status": "completed",
            "model": "gpt-5.6-luna-fake",
            "service_tier": "default",
            "usage": {
                "input_tokens": 500,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 150,
                "output_tokens_details": {"reasoning_tokens": 40},
                "total_tokens": 650,
            },
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps(answer, separators=(",", ":")),
                        }
                    ],
                }
            ],
        }
        return OpenAIHttpResponse(
            200,
            {"x-request-id": f"fake-{len(seen)}"},
            json.dumps(response).encode(),
        )

    return transport, seen


def _live_approval() -> UserRunApproval:
    config, _authorization, schedule, packets = load_provider_inputs(ROOT)
    return UserRunApproval(
        approval_id="test-user-approved-phase2-luna",
        approved_at_utc=NOW,
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
        request_manifest_sha256=canary_request_manifest_sha256(
            config,
            schedule,
            packets,
        ),
        canary_blocks=config.canary_blocks,
    )


def _live_app_config() -> AppConfig:
    return AppConfig(
        provider="openai",
        model="gpt-5.6-luna",
        openai_api_key="test-key-never-egresses",
        cost_cap_usd="0.1824",
    )


def _patch_live_transport(
    monkeypatch: pytest.MonkeyPatch,
    transport: OpenAITransport,
) -> None:
    adapter_class = provider_execution.OpenAIResponsesAdapter

    def adapter_factory(
        replay_transport: OpenAITransport | None = None,
    ) -> OpenAIResponsesAdapter:
        return adapter_class(
            transport if replay_transport is None else replay_transport
        )

    monkeypatch.setattr(
        provider_execution,
        "OpenAIResponsesAdapter",
        adapter_factory,
    )


def _semantic_failure_transport(
    failure: str,
) -> tuple[OpenAITransport, list[OpenAIHttpRequest], list[int]]:
    base_transport, seen = _fake_transport()
    mutated_at: list[int] = []

    def transport(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        response = base_transport(request, timeout_seconds=timeout_seconds)
        body = json.loads(request.body)
        prompt = json.loads(body["input"][1]["content"])
        provider_body = json.loads(response.body)
        provider_body["model"] = "gpt-5.6-luna-2026-07-01"
        answer = json.loads(provider_body["output"][0]["content"][0]["text"])
        should_mutate = False
        if failure == "ontology":
            should_mutate = (
                prompt["case_id"] == "real-nvd-cvss-combined-treatment"
                and not mutated_at
            )
            if should_mutate:
                answer["claims"][0]["qualifiers"]["authority"] = "nvd"
        elif failure == "citation":
            should_mutate = (
                prompt["case_id"] == "real-nvd-cvss-combined-treatment"
                and "cite supporting allowed evidence IDs when possible"
                in prompt["condition_instruction"]
                and not mutated_at
            )
            if should_mutate:
                answer["claims"][0]["evidence_ids"] = []
        elif failure == "abstention":
            should_mutate = (
                prompt["case_id"] == "real-kev-preavailability"
                and prompt["condition_instruction"]
                == "Answer only from the supplied evidence. Citations are not required."
                and not mutated_at
            )
            if should_mutate:
                answer["abstained"] = False
                answer["abstention_reason"] = None
                answer["claims"] = [
                    {
                        "claim_id": "unsupported-membership",
                        "subject": {"type": "cve", "id": "CVE-2021-44228"},
                        "predicate": "kev.is_member",
                        "object": {"value": True, "datatype": "boolean"},
                        "qualifiers": {
                            "authority": "cisa_kev",
                            "cvss_version": None,
                            "product": None,
                            "ecosystem": None,
                        },
                        "evidence_ids": [],
                        "confidence": 1.0,
                    }
                ]
        else:
            raise AssertionError("unsupported semantic failure fixture")
        if should_mutate:
            mutated_at.append(len(seen))
            provider_body["output"][0]["content"][0]["text"] = json.dumps(
                answer,
                separators=(",", ":"),
            )
        return OpenAIHttpResponse(
            response.status_code,
            response.headers,
            json.dumps(provider_body).encode(),
        )

    return transport, seen, mutated_at


def _write_external_approval(path: Path, approval: UserRunApproval) -> None:
    path.write_text(approval.canonical_json() + "\n", encoding="utf-8", newline="\n")


def _remove_run_directory(path: Path) -> None:
    if not path.exists():
        return
    for child in sorted(path.rglob("*"), reverse=True):
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            child.rmdir()
    path.rmdir()


def _redacted_path(tmp_path: Path, name: str) -> Path:
    suffix = hashlib.sha256(str(tmp_path.resolve()).encode("utf-8")).hexdigest()[:12]
    return ROOT / "artifacts/provider/redacted" / f"{name}-{suffix}"


def _rewrite_first_jsonl_record(
    path: Path,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    mutate(first)
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _rewrite_all_jsonl_records(
    path: Path,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    records = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    ]
    for record in records:
        mutate(record)
    path.write_text(
        "".join(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
        newline="\n",
    )


@requires_real_capture
def test_fake_canary_completes_all_triplets_and_redacted_ledgers(
    tmp_path: Path,
) -> None:
    transport, seen = _fake_transport()
    redacted = _redacted_path(tmp_path, "test-fake-canary")
    if redacted.exists():
        pytest.fail("fake canary test directory must begin absent")
    private = tmp_path / "private"
    try:
        results = run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=private,
            transport=transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
        )
        assert len(results) == len(seen) == 12
        assert all(result.run.parse_status == "valid" for result in results)
        assert all(result.run.deterministic_outcome == "graded" for result in results)
        assert (
            len(load_jsonl_records(redacted / "reservations.jsonl", AttemptReservation))
            == 12
        )
        assert (
            len(load_jsonl_records(redacted / "terminals.jsonl", AttemptTerminal)) == 12
        )
        assert (
            len(load_jsonl_records(redacted / "safety-events.jsonl", SafetyEvent)) == 12
        )
        redacted_text = "".join(
            path.read_text(encoding="utf-8") for path in redacted.glob("*.jsonl")
        )
        assert "fake-1" not in redacted_text
        assert "OPENAI_API_KEY" not in redacted_text
        assert "Apache Log4j2" not in redacted_text
        assert len(list((private / "requests").glob("*.json"))) == 12
        assert len(list((private / "responses").glob("*.body"))) == 12
        assert len(list((private / "response-headers").glob("*.json"))) == 12
        terminals = load_jsonl_records(redacted / "terminals.jsonl", AttemptTerminal)
        for terminal in terminals:
            assert terminal.provider_http_status == 200
            response_body = (
                private / "responses" / f"{terminal.attempt_id}.body"
            ).read_bytes()
            response_headers = (
                private / "response-headers" / f"{terminal.attempt_id}.json"
            ).read_bytes()
            assert (
                hashlib.sha256(response_body).hexdigest()
                == terminal.response_body_sha256
            )
            assert (
                hashlib.sha256(response_headers).hexdigest()
                == terminal.response_headers_sha256
            )
        direct = next(
            result
            for result in results
            if result.slot.condition == "lexical_direct_answer"
        )
        assert direct.metric_applicability.model_dump() == {
            "citation_support": False,
            "evidence_coverage": False,
            "citation_authority": False,
        }
        assert (
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
            == results
        )
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_explicit_v1_fake_canary_remains_replayable(tmp_path: Path) -> None:
    transport, seen = _fake_transport()
    redacted = _redacted_path(tmp_path, "test-fake-canary-v1")
    private = tmp_path / "private-v1"
    try:
        results = run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=private,
            transport=transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
            config_version="v1",
        )
        assert len(results) == len(seen) == 12
        assert (
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
                config_version="v1",
            )
            == results
        )
        with pytest.raises(ProviderRunError):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
                config_version="v2",
            )
    finally:
        _remove_run_directory(redacted)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("ontology", "exact claim criterion"),
        ("citation", "citation criterion"),
        ("abstention", "abstention criterion"),
    ],
)
@requires_real_capture
def test_live_v2_semantic_failure_stops_before_any_later_request(
    failure: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport, seen, mutated_at = _semantic_failure_transport(failure)
    _patch_live_transport(monkeypatch, transport)
    redacted = _redacted_path(tmp_path, f"test-live-v2-{failure}")
    try:
        with pytest.raises(ProviderRunError, match=message):
            run_provider_canary(
                ROOT,
                mode="live",
                redacted_root=redacted,
                private_root=tmp_path / f"private-{failure}",
                app_config=_live_app_config(),
                approval=_live_approval(),
                now=lambda: NOW,
                sleep=lambda _seconds: None,
            )
        assert mutated_at
        assert len(seen) == mutated_at[0]
    finally:
        _remove_run_directory(redacted)


def test_invalid_config_version_fails_before_transport(tmp_path: Path) -> None:
    calls = 0

    def transport(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("transport must not be reached")

    with pytest.raises(ProviderRunError, match="unsupported provider config"):
        run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=ROOT / "artifacts/provider/redacted/blocked-version",
            private_root=tmp_path / "private",
            transport=transport,
            config_version="typo",  # type: ignore[arg-type]
        )
    assert calls == 0


@requires_real_capture
def test_transient_server_retry_is_identical_and_retains_both_attempts(
    tmp_path: Path,
) -> None:
    success_transport, _seen_success = _fake_transport()
    calls: list[OpenAIHttpRequest] = []
    delays: list[float] = []

    def transient_once(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        calls.append(request)
        if len(calls) == 1:
            return OpenAIHttpResponse(
                503,
                {},
                b'{"error":{"code":"server_error"}}',
            )
        return success_transport(request, timeout_seconds=timeout_seconds)

    redacted = _redacted_path(tmp_path, "test-fake-retry")
    try:
        results = run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=tmp_path / "private",
            transport=transient_once,
            now=lambda: NOW,
            sleep=delays.append,
        )
        assert len(results) == 12
        assert len(calls) == 13
        assert delays == [2]
        assert results[0].run.retry_count == 1
        reservations = load_jsonl_records(
            redacted / "reservations.jsonl",
            AttemptReservation,
        )
        assert len(reservations) == 13
        assert (
            reservations[0].semantic_request_hash
            == reservations[1].semantic_request_hash
        )
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_refusal_is_terminal_preserves_slot_and_receives_no_retry(
    tmp_path: Path,
) -> None:
    success_transport, _seen_success = _fake_transport()
    calls: list[OpenAIHttpRequest] = []

    def refuse_once(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        calls.append(request)
        if len(calls) == 1:
            response = {
                "status": "completed",
                "model": "gpt-5.6-luna-fake",
                "service_tier": "default",
                "usage": {
                    "input_tokens": 10,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens": 2,
                    "output_tokens_details": {"reasoning_tokens": 1},
                    "total_tokens": 12,
                },
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "refusal", "refusal": "declined"}],
                    }
                ],
            }
            return OpenAIHttpResponse(200, {}, json.dumps(response).encode())
        return success_transport(request, timeout_seconds=timeout_seconds)

    redacted = _redacted_path(tmp_path, "test-fake-refusal")
    try:
        results = run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=tmp_path / "private",
            transport=refuse_once,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
            enforce_acceptance=False,
        )
        assert len(results) == 12
        assert len(calls) == 12
        refused = results[0]
        assert refused.run.provider_status == "refused"
        assert refused.run.security_outcome == "refused"
        assert refused.run.deterministic_outcome == "unusable_slot"
        assert refused.answer is None
        assert refused.grades == ()
        events = load_jsonl_records(
            redacted / "safety-events.jsonl",
            SafetyEvent,
        )
        assert events[0].safety_outcome == "refused"
        assert events[0].response_used_for_scoring is False
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_live_resume_replays_failed_saved_prefix_before_any_later_egress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval = _live_approval()
    redacted = _redacted_path(tmp_path, "test-live-failed-resume")
    private = tmp_path / "private-live-failed-resume"
    calls: list[OpenAIHttpRequest] = []

    def refusal(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        calls.append(request)
        body = {
            "status": "completed",
            "model": "gpt-5.6-luna-2026-07-01",
            "service_tier": "default",
            "usage": {
                "input_tokens": 10,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 2,
                "output_tokens_details": {"reasoning_tokens": 1},
                "total_tokens": 12,
            },
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "refusal", "refusal": "declined"}],
                }
            ],
        }
        return OpenAIHttpResponse(200, {}, json.dumps(body).encode())

    _patch_live_transport(monkeypatch, refusal)
    try:
        with pytest.raises(ProviderRunError, match="no later provider request"):
            run_provider_canary(
                ROOT,
                mode="live",
                redacted_root=redacted,
                private_root=private,
                app_config=_live_app_config(),
                approval=approval,
                now=lambda: NOW,
                sleep=lambda _seconds: None,
            )
        assert len(calls) == 1
        with pytest.raises(
            ProviderRunError,
            match="outside provider artifacts and the project",
        ):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
                approval_path=redacted / "user-approval.json",
            )
        (redacted / "run.lock").unlink()
        calls.clear()

        with pytest.raises(ProviderRunError, match="no later provider request"):
            run_provider_canary(
                ROOT,
                mode="live",
                redacted_root=redacted,
                private_root=private,
                app_config=_live_app_config(),
                approval=approval,
                now=lambda: NOW,
                sleep=lambda _seconds: None,
                resume=True,
            )
        assert calls == []
    finally:
        _remove_run_directory(redacted)


@pytest.mark.parametrize("failure", ["refusal", "schema", "timeout", "usage"])
@requires_real_capture
def test_live_failed_prefix_replays_without_requiring_unattempted_slots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    approval = _live_approval()
    redacted = _redacted_path(tmp_path, f"test-live-prefix-{failure}")
    private = tmp_path / f"private-live-prefix-{failure}"
    approval_path = tmp_path / f"approval-{failure}.json"
    _write_external_approval(approval_path, approval)
    calls = 0

    def fail_once(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        nonlocal calls
        calls += 1
        if failure == "timeout":
            raise TimeoutError
        output = (
            [{"type": "message", "content": [{"type": "refusal", "refusal": "no"}]}]
            if failure == "refusal"
            else [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "{}"}],
                }
            ]
        )
        body: dict[str, object] = {
            "status": "completed",
            "model": "gpt-5.6-luna-2026-07-01",
            "service_tier": "default",
            "usage": {
                "input_tokens": 10,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 2,
                "output_tokens_details": {"reasoning_tokens": 1},
                "total_tokens": 12,
            },
            "output": output,
        }
        if failure == "usage":
            body.pop("usage")
        return OpenAIHttpResponse(200, {}, json.dumps(body).encode())

    _patch_live_transport(monkeypatch, fail_once)
    try:
        with pytest.raises(ProviderRunError, match="no later provider request"):
            run_provider_canary(
                ROOT,
                mode="live",
                redacted_root=redacted,
                private_root=private,
                app_config=_live_app_config(),
                approval=approval,
                now=lambda: NOW,
                sleep=lambda _seconds: None,
            )
        assert calls == 1

        replayed = replay_provider_results(
            ROOT,
            redacted_root=redacted,
            private_root=private,
            approval_path=approval_path,
        )

        assert len(replayed) == 1
        assert replayed[0].run.provider_status != "allowed" or (
            replayed[0].run.parse_status != "valid"
        )
        if failure == "usage":
            assert replayed[0].run.error_category == "schema"
            assert replayed[0].run.provider_status == "error"
            assert replayed[0].run.security_outcome == "unknown"
            assert replayed[0].run.estimated_cost_usd == Decimal("0.0076")
        assert (
            len(load_jsonl_records(redacted / "reservations.jsonl", AttemptReservation))
            == 1
        )
    finally:
        _remove_run_directory(redacted)


def test_live_mode_rejects_missing_approval_before_transport(tmp_path: Path) -> None:
    calls = 0

    def transport(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("transport must not be reached")

    with pytest.raises(ProviderRunError, match="explicit approval"):
        run_provider_canary(
            ROOT,
            mode="live",
            redacted_root=ROOT / "artifacts/provider/redacted/blocked",
            private_root=tmp_path / "private",
            transport=transport,
            app_config=AppConfig(
                provider="openai",
                model="gpt-5.6-luna",
                openai_api_key="not-a-real-key",
                cost_cap_usd="2.00",
            ),
            approval=None,
        )
    assert calls == 0


def test_live_mode_cannot_disable_acceptance_before_transport(tmp_path: Path) -> None:
    calls = 0

    def transport(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("transport must not be reached")

    with pytest.raises(ProviderRunError, match="cannot disable acceptance"):
        run_provider_canary(
            ROOT,
            mode="live",
            redacted_root=ROOT / "artifacts/provider/redacted/blocked",
            private_root=tmp_path / "private",
            transport=transport,
            enforce_acceptance=False,
        )
    assert calls == 0


def test_fake_mode_rejects_credentials_and_missing_injected_transport(
    tmp_path: Path,
) -> None:
    with pytest.raises(ProviderRunError, match="cannot accept credentials"):
        run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=ROOT / "artifacts/provider/redacted/blocked",
            private_root=tmp_path / "private",
            transport=lambda _request, *, timeout_seconds: OpenAIHttpResponse(
                500, {}, b""
            ),
            app_config=AppConfig(),
        )
    with pytest.raises(ProviderRunError, match="injected transport"):
        run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=ROOT / "artifacts/provider/redacted/blocked",
            private_root=tmp_path / "private",
        )


def _mutating_transport(
    *,
    condition: str,
    evidence_id: str | None = None,
    model: str | None = None,
) -> tuple[OpenAITransport, list[OpenAIHttpRequest]]:
    base, seen = _fake_transport()

    def transport(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        response = base(request, timeout_seconds=timeout_seconds)
        request_body = json.loads(request.body)
        prompt = json.loads(request_body["input"][1]["content"])
        if prompt["run_id"].endswith(condition):
            payload = json.loads(response.body)
            if evidence_id is not None:
                answer = json.loads(payload["output"][0]["content"][0]["text"])
                for claim in answer["claims"]:
                    claim["evidence_ids"] = [evidence_id]
                payload["output"][0]["content"][0]["text"] = json.dumps(
                    answer,
                    separators=(",", ":"),
                )
            if model is not None:
                payload["model"] = model
            return OpenAIHttpResponse(
                response.status_code,
                response.headers,
                json.dumps(payload).encode(),
            )
        return response

    return transport, seen


@requires_real_capture
def test_nonempty_foreign_evidence_remains_claim_level_for_both_citation_conditions(
    tmp_path: Path,
) -> None:
    _config, _authorization, _schedule, packets = load_provider_inputs(ROOT)
    packet = packets["real-nvd-cvss-combined-treatment"]
    allowed = {item.evidence_id for item in packet.ordered_evidence}
    foreign = next(
        evidence_id
        for other in packets.values()
        for evidence_id in (item.evidence_id for item in other.ordered_evidence)
        if evidence_id not in allowed
    )

    constrained_transport, _seen = _mutating_transport(
        condition="lexical_claim_evidence_constrained",
        evidence_id=foreign,
    )
    constrained_redacted = _redacted_path(
        tmp_path,
        "test-constrained-foreign-key",
    )
    try:
        constrained = run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=constrained_redacted,
            private_root=tmp_path / "private-constrained",
            transport=constrained_transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
            enforce_acceptance=False,
        )
        target = next(
            item
            for item in constrained
            if item.slot.condition == "lexical_claim_evidence_constrained"
        )
        assert target.run.parse_status == "valid"
        assert target.answer is not None
        assert target.run.utility_outcome == "claims_emitted"
        assert any(
            assessment.resolution == "missing"
            and assessment.entailment == "unsupported"
            for grade in target.grades
            for assessment in grade.evidence_assessments
        )
    finally:
        _remove_run_directory(constrained_redacted)

    citation_transport, _seen = _mutating_transport(
        condition="lexical_citation_prompted",
        evidence_id=foreign,
    )
    citation_redacted = _redacted_path(tmp_path, "test-citation-foreign-key")
    try:
        citation = run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=citation_redacted,
            private_root=tmp_path / "private-citation",
            transport=citation_transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
            enforce_acceptance=False,
        )
        target = next(
            item
            for item in citation
            if item.slot.condition == "lexical_citation_prompted"
        )
        assert target.run.parse_status == "valid"
        assert target.answer is not None
        assert target.run.utility_outcome == "claims_emitted"
        assert any(
            assessment.resolution == "missing"
            and assessment.entailment == "unsupported"
            for grade in target.grades
            for assessment in grade.evidence_assessments
        )
    finally:
        _remove_run_directory(citation_redacted)


@requires_real_capture
def test_ambiguous_timeout_reserves_upper_bound_and_stops_every_later_slot(
    tmp_path: Path,
) -> None:
    calls = 0

    def timeout(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        nonlocal calls
        calls += 1
        raise TimeoutError

    redacted = _redacted_path(tmp_path, "test-timeout-stop")
    try:
        with pytest.raises(ProviderRunError, match="ambiguous timeout accounted"):
            run_provider_canary(
                ROOT,
                mode="fake",
                redacted_root=redacted,
                private_root=tmp_path / "private-timeout",
                transport=timeout,
                now=lambda: NOW,
                sleep=lambda _seconds: None,
                enforce_acceptance=False,
            )
        assert calls == 1
        reconciliations = load_jsonl_records(
            redacted / "reconciliations.jsonl",
            CostReconciliation,
        )
        assert reconciliations[0].actual_cost_usd == Decimal("0.0076")
        assert reconciliations[0].cost_basis == "ambiguous_reserved_max"
        saved = load_jsonl_records(redacted / "results.jsonl", ProviderExecutionResult)
        assert len(saved) == 1
        assert saved[0].run.estimated_cost_usd == Decimal("0.0076")
        assert (redacted / "run.lock").exists()
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_wrong_returned_model_fails_canary_acceptance(tmp_path: Path) -> None:
    transport, seen = _mutating_transport(
        condition="lexical_direct_answer",
        model="gpt-5.6-other",
    )
    redacted = _redacted_path(tmp_path, "test-wrong-returned-model")
    try:
        with pytest.raises(ProviderRunError, match="provider, safety, or schema"):
            run_provider_canary(
                ROOT,
                mode="fake",
                redacted_root=redacted,
                private_root=tmp_path / "private-wrong-model",
                transport=transport,
                now=lambda: NOW,
                sleep=lambda _seconds: None,
            )
        assert len(seen) == 12
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_lock_blocks_egress_and_reconciled_prefix_resumes_without_duplicate(
    tmp_path: Path,
) -> None:
    redacted = _redacted_path(tmp_path, "test-lock-and-resume")
    private = tmp_path / "private-resume"
    redacted.mkdir(parents=True)
    (redacted / "run.lock").write_text("{}\n", encoding="utf-8")
    transport, seen = _fake_transport()
    try:
        with pytest.raises(ProviderRunError, match="run lock exists"):
            run_provider_canary(
                ROOT,
                mode="fake",
                redacted_root=redacted,
                private_root=private,
                transport=transport,
            )
        assert seen == []
    finally:
        _remove_run_directory(redacted)

    transport, first_seen = _fake_transport()
    clock_calls = 0

    def interrupted_clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        if clock_calls == 4:
            raise RuntimeError("simulated local interruption")
        return NOW

    redacted.mkdir(parents=True)
    _remove_run_directory(redacted)
    try:
        with pytest.raises(RuntimeError, match="simulated local interruption"):
            run_provider_canary(
                ROOT,
                mode="fake",
                redacted_root=redacted,
                private_root=private,
                transport=transport,
                now=interrupted_clock,
                sleep=lambda _seconds: None,
            )
        assert len(first_seen) == 1
        assert (redacted / "run.lock").exists()
        (redacted / "run.lock").unlink()
        resumed_transport, resumed_seen = _fake_transport()
        results = run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=private,
            transport=resumed_transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
            resume=True,
        )
        assert len(results) == 12
        assert len(resumed_seen) == 11
        assert (
            len(load_jsonl_records(redacted / "reservations.jsonl", AttemptReservation))
            == 12
        )
        assert not (redacted / "run.lock").exists()
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_replay_detects_request_response_and_result_binding_mutation(
    tmp_path: Path,
) -> None:
    transport, _seen = _fake_transport()
    redacted = _redacted_path(tmp_path, "test-replay-tamper")
    private = tmp_path / "private-replay"
    try:
        run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=private,
            transport=transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
        )
        request_path = next((private / "requests").glob("*.json"))
        original_request = request_path.read_bytes()
        request_path.write_bytes(original_request + b" ")
        with pytest.raises(ProviderRunError, match="request hash"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
        request_path.write_bytes(original_request)

        response_path = next((private / "responses").glob("*.body"))
        original_response = response_path.read_bytes()
        response_path.write_bytes(original_response + b" ")
        with pytest.raises(ProviderRunError, match="response hash"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
        response_path.write_bytes(original_response)

        results_path = redacted / "results.jsonl"
        original_results = results_path.read_text(encoding="utf-8")
        lines = original_results.splitlines()
        first = ProviderExecutionResult.model_validate_json(lines[0])
        lines[0] = canonical_json(
            first.model_copy(update={"invariant_sha256": "0" * 64})
        )
        results_path.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        with pytest.raises(ProviderRunError, match="saved provider result"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_replay_cross_links_result_usage_retry_latency_reasoning_service_and_cost(
    tmp_path: Path,
) -> None:
    transport, _seen = _fake_transport()
    redacted = _redacted_path(tmp_path, "test-replay-cross-ledger")
    private = tmp_path / "private-cross-ledger"
    try:
        run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=private,
            transport=transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
        )
        results_path = redacted / "results.jsonl"
        original = results_path.read_text(encoding="utf-8")
        first = json.loads(original.splitlines()[0])
        run_mutations = (
            ("input_tokens", first["run"]["input_tokens"] + 1),
            ("latency_ms", first["run"]["latency_ms"] + 1),
            ("retry_count", first["run"]["retry_count"] + 1),
            ("estimated_cost_usd", "0.001401"),
            ("provider", "anthropic"),
            ("project_version", "tampered"),
            ("retriever_version", "tampered"),
            ("authority_policy_version", "tampered"),
            ("retrieval_outcome", "empty"),
            ("utility_outcome", "empty"),
            ("error_category", "schema"),
        )
        for key, value in run_mutations:

            def mutate_run(
                record: dict[str, object],
                *,
                field: str = key,
                replacement: object = value,
            ) -> None:
                run = record["run"]
                assert isinstance(run, dict)
                run[field] = replacement

            _rewrite_first_jsonl_record(results_path, mutate_run)
            with pytest.raises(
                ProviderRunError,
                match="run-record binding does not replay",
            ):
                replay_provider_results(
                    ROOT,
                    redacted_root=redacted,
                    private_root=private,
                )
            results_path.write_text(original, encoding="utf-8", newline="\n")
        top_level_mutations = (
            ("reasoning_tokens", first["reasoning_tokens"] + 1),
            ("provider_service_tier", "unexpected"),
        )
        for key, value in top_level_mutations:

            def mutate_top_level(
                record: dict[str, object],
                *,
                field: str = key,
                replacement: object = value,
            ) -> None:
                record[field] = replacement

            _rewrite_first_jsonl_record(
                results_path,
                mutate_top_level,
            )
            with pytest.raises(
                ProviderRunError,
                match="run-record binding does not replay",
            ):
                replay_provider_results(
                    ROOT,
                    redacted_root=redacted,
                    private_root=private,
                )
            results_path.write_text(original, encoding="utf-8", newline="\n")
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_replay_rederives_terminal_cost_and_safety_from_exact_response(
    tmp_path: Path,
) -> None:
    transport, _seen = _fake_transport()
    redacted = _redacted_path(tmp_path, "test-replay-lifecycle")
    private = tmp_path / "private-lifecycle"
    try:
        run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=private,
            transport=transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
        )
        results_path = redacted / "results.jsonl"
        terminals_path = redacted / "terminals.jsonl"
        reconciliations_path = redacted / "reconciliations.jsonl"
        safety_path = redacted / "safety-events.jsonl"
        originals = {
            path: path.read_text(encoding="utf-8")
            for path in (
                results_path,
                terminals_path,
                reconciliations_path,
                safety_path,
            )
        }

        def increment_terminal_input(record: dict[str, object]) -> None:
            value = record["input_tokens"]
            assert isinstance(value, int)
            record["input_tokens"] = value + 1

        def increment_result_input(record: dict[str, object]) -> None:
            run = record["run"]
            assert isinstance(run, dict)
            value = run["input_tokens"]
            assert isinstance(value, int)
            run["input_tokens"] = value + 1

        _rewrite_first_jsonl_record(terminals_path, increment_terminal_input)
        _rewrite_first_jsonl_record(results_path, increment_result_input)
        with pytest.raises(ProviderRunError, match="terminal semantics"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
        terminals_path.write_text(
            originals[terminals_path],
            encoding="utf-8",
            newline="\n",
        )
        results_path.write_text(
            originals[results_path],
            encoding="utf-8",
            newline="\n",
        )

        def zero_reconciliation(record: dict[str, object]) -> None:
            record["actual_cost_usd"] = "0"
            record["cost_basis"] = "known_zero"

        def zero_result_cost(record: dict[str, object]) -> None:
            run = record["run"]
            assert isinstance(run, dict)
            run["estimated_cost_usd"] = "0"

        _rewrite_first_jsonl_record(reconciliations_path, zero_reconciliation)
        _rewrite_first_jsonl_record(results_path, zero_result_cost)
        with pytest.raises(ProviderRunError, match="cost reconciliation"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
        reconciliations_path.write_text(
            originals[reconciliations_path],
            encoding="utf-8",
            newline="\n",
        )
        results_path.write_text(
            originals[results_path],
            encoding="utf-8",
            newline="\n",
        )

        _rewrite_first_jsonl_record(
            terminals_path,
            lambda record: record.__setitem__("result_class", "parse_error"),
        )
        with pytest.raises(ProviderRunError, match="terminal semantics"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
        terminals_path.write_text(
            originals[terminals_path],
            encoding="utf-8",
            newline="\n",
        )

        def mutate_safety(record: dict[str, object]) -> None:
            record["model"] = "unexpected"
            record["request_template_version"] = "unexpected"
            record["request_template_hash"] = "0" * 64
            record["response_used_for_scoring"] = False

        _rewrite_first_jsonl_record(safety_path, mutate_safety)
        with pytest.raises(ProviderRunError, match="safety event"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
    finally:
        _remove_run_directory(redacted)


@requires_real_capture
def test_replay_rederives_fake_approval_root_instead_of_trusting_run_directory(
    tmp_path: Path,
) -> None:
    transport, _seen = _fake_transport()
    redacted = _redacted_path(tmp_path, "test-replay-approval-root")
    private = tmp_path / "private-approval-root"
    try:
        run_provider_canary(
            ROOT,
            mode="fake",
            redacted_root=redacted,
            private_root=private,
            transport=transport,
            now=lambda: NOW,
            sleep=lambda _seconds: None,
        )
        with pytest.raises(
            ProviderRunError,
            match="outside provider artifacts and the project",
        ):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
                approval_path=redacted / "approval.json",
            )
        fabricated_id = "fabricated-approval"
        fabricated_hash = "f" * 64

        def mutate_approval(record: dict[str, object]) -> None:
            record["approval_id"] = fabricated_id
            record["approval_hash"] = fabricated_hash

        approval_path = redacted / "approval.json"
        approval_record = json.loads(approval_path.read_text(encoding="utf-8"))
        mutate_approval(approval_record)
        approval_path.write_text(
            json.dumps(approval_record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        for name in (
            "planned.jsonl",
            "reservations.jsonl",
            "safety-events.jsonl",
            "results.jsonl",
        ):
            _rewrite_all_jsonl_records(redacted / name, mutate_approval)
        with pytest.raises(ProviderRunError, match="approval binding does not replay"):
            replay_provider_results(
                ROOT,
                redacted_root=redacted,
                private_root=private,
            )
    finally:
        _remove_run_directory(redacted)
